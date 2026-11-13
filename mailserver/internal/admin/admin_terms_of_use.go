// Admin ToU editor + risk dashboard.
//
// Routes (registered in main.go):
//
//	GET    /admin/terms-of-use               — List ToU docs (access.policy_read)
//	POST   /admin/terms-of-use               — Create a ToU doc (access.policy_write, audited)
//	PUT    /admin/terms-of-use/{id}          — Update a ToU doc (access.policy_write, audited)
//	DELETE /admin/terms-of-use/{id}          — Delete a ToU doc (access.policy_write, audited)
//	GET    /admin/user-risk                  — List user_risk rows (access.policy_read)
//	POST   /admin/user-risk/{id}/reset       — Reset a user's risk score (access.policy_write, audited)
package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
)

// touCreateValid is the pure request-shape gate for ToU create/update.
func touCreateValid(name, body string, version int) bool {
	return name != "" && body != "" && version >= 1
}

// ── ToUHandler ──

// ToUHandler provides admin CRUD access to terms_of_use.
// terms_of_use has no per-user RLS (same as conditional_access_policies — gated at app layer).
type ToUHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewToUHandler creates a ToU editor admin handler.
func NewToUHandler(pool *pgxpool.Pool, logger *slog.Logger) *ToUHandler {
	return &ToUHandler{pool: pool, logger: logger}
}

// touRequest is the create/update request body.
type touRequest struct {
	Name          string `json:"name"`
	Version       int    `json:"version"`
	BodyMD        string `json:"body_md"`
	Lang          string `json:"lang,omitempty"`
	RequireScroll bool   `json:"require_scroll,omitempty"`
	Enabled       bool   `json:"enabled,omitempty"`
}

// touRow is the List response shape.
type touRow struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Version       int    `json:"version"`
	BodyMD        string `json:"body_md"`
	Lang          string `json:"lang"`
	RequireScroll bool   `json:"require_scroll"`
	Enabled       bool   `json:"enabled"`
	CreatedAt     string `json:"created_at"`
}

// parseTouLimit clamps the ?limit= query param to [1, 500], defaulting to 100.
// Mirrors the pattern in parseThreatParams (admin_threat.go).
func parseTouLimit(r *http.Request) int {
	const defaultLimit = 100
	const maxLimit = 500
	limit := defaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	return limit
}

// List returns terms_of_use docs ordered by name, clamped to at most 500 rows
// (default 100) to bound the response payload — matches the threat-log pagination
// pattern in admin_threat.go.
func (h *ToUHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, name, version, body_md, lang, require_scroll, enabled, created_at::text
		   FROM terms_of_use ORDER BY name ASC LIMIT $1`, parseTouLimit(r))
	if err != nil {
		h.logger.Error("tou list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	out := []touRow{}
	for rows.Next() {
		var row touRow
		if err := rows.Scan(&row.ID, &row.Name, &row.Version, &row.BodyMD,
			&row.Lang, &row.RequireScroll, &row.Enabled, &row.CreatedAt); err != nil {
			h.logger.Warn("tou list scan failed", "error", err)
			continue
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("tou list rows error", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// Create inserts a new terms_of_use doc and writes an admin_audit_log row in-txn (CA-0b).
func (h *ToUHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req touRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !touCreateValid(req.Name, req.BodyMD, req.Version) {
		httputil.WriteError(w, http.StatusBadRequest, "name, body_md, and version >= 1 are required")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	lang := req.Lang
	if lang == "" {
		lang = "en"
	}

	tx, err := h.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		h.logger.Error("tou create: begin tx failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "transaction failed")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var id int64
	err = tx.QueryRow(ctx,
		`INSERT INTO terms_of_use (name, version, body_md, lang, require_scroll, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		req.Name, req.Version, req.BodyMD, lang, req.RequireScroll, req.Enabled,
	).Scan(&id)
	if err != nil {
		h.logger.Error("tou create failed", "error", err)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	// CA-0b: audit in-txn — sensitive write must be logged atomically.
	after, _ := json.Marshal(map[string]any{"name": req.Name, "version": req.Version})
	if err := audit.Write(ctx, tx, audit.Entry{
		Actor: claims.UserID, Action: "tou.create", TargetType: "terms_of_use", TargetID: &id,
		After: after, IP: httputil.ClientIP(r), Tier: "core",
	}); err != nil {
		h.logger.Error("tou create audit failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "audit write failed")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("tou create: commit failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "commit failed")
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]any{"id": id})
}

// Update modifies an existing terms_of_use doc and audits in-txn (CA-0b).
func (h *ToUHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	id, err := parsePathID(r, "id")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid ToU ID")
		return
	}

	var req touRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !touCreateValid(req.Name, req.BodyMD, req.Version) {
		httputil.WriteError(w, http.StatusBadRequest, "name, body_md, and version >= 1 are required")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	lang := req.Lang
	if lang == "" {
		lang = "en"
	}

	tx, err := h.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		h.logger.Error("tou update: begin tx failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "transaction failed")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tag, err := tx.Exec(ctx,
		`UPDATE terms_of_use SET name=$2, version=$3, body_md=$4, lang=$5,
		     require_scroll=$6, enabled=$7
		 WHERE id=$1`,
		id, req.Name, req.Version, req.BodyMD, lang, req.RequireScroll, req.Enabled,
	)
	if err != nil {
		h.logger.Error("tou update failed", "error", err, "id", id)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteError(w, http.StatusNotFound, "terms_of_use not found")
		return
	}

	// CA-0b: audit in-txn.
	after, _ := json.Marshal(map[string]any{"name": req.Name, "version": req.Version})
	if err := audit.Write(ctx, tx, audit.Entry{
		Actor: claims.UserID, Action: "tou.update", TargetType: "terms_of_use", TargetID: &id,
		After: after, IP: httputil.ClientIP(r), Tier: "core",
	}); err != nil {
		h.logger.Error("tou update audit failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "audit write failed")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("tou update: commit failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "commit failed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Delete removes a terms_of_use doc and audits in-txn (CA-0b).
// FK CASCADE on terms_of_use_acceptance means accepted rows are also removed.
func (h *ToUHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := parsePathID(r, "id")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid ToU ID")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	tx, err := h.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		h.logger.Error("tou delete: begin tx failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "transaction failed")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Capture before_state for the audit row.
	var name string
	var version int
	if err := tx.QueryRow(ctx, `SELECT name, version FROM terms_of_use WHERE id=$1`, id).Scan(&name, &version); err != nil {
		httputil.WriteError(w, http.StatusNotFound, "terms_of_use not found")
		return
	}

	tag, err := tx.Exec(ctx, `DELETE FROM terms_of_use WHERE id=$1`, id)
	if err != nil {
		h.logger.Error("tou delete failed", "error", err, "id", id)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteError(w, http.StatusNotFound, "terms_of_use not found")
		return
	}

	// CA-0b: audit in-txn.
	before, _ := json.Marshal(map[string]any{"name": name, "version": version})
	if err := audit.Write(ctx, tx, audit.Entry{
		Actor: claims.UserID, Action: "tou.delete", TargetType: "terms_of_use", TargetID: &id,
		Before: before, IP: httputil.ClientIP(r), Tier: "core",
	}); err != nil {
		h.logger.Error("tou delete audit failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "audit write failed")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("tou delete: commit failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "commit failed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ── RiskHandler ──

// RiskHandler provides admin read/reset access to user_risk.
// user_risk has FORCE RLS with a self-read-only SELECT policy; cross-user admin
// reads and writes require workerPool (BYPASSRLS).
type RiskHandler struct {
	pool       *pgxpool.Pool
	workerPool *pgxpool.Pool // BYPASSRLS — user_risk FORCE RLS hides all rows otherwise
	logger     *slog.Logger
}

// NewRiskHandler creates a risk dashboard admin handler.
// workerPool is the BYPASSRLS pool; user_risk has FORCE RLS so cross-user access needs it.
// ponytail: workerPool aliases pool until DB_WORKER_DSN is set (W1b) — INERT until the flip.
func NewRiskHandler(pool *pgxpool.Pool, workerPool pgxutil.WorkerPool, logger *slog.Logger) *RiskHandler {
	return &RiskHandler{pool: pool, workerPool: workerPool.Pool, logger: logger}
}

// riskRow is the List response shape.
type riskRow struct {
	UserID    int64           `json:"user_id"`
	Email     string          `json:"email"`
	Score     int             `json:"score"`
	Level     string          `json:"level"`
	Signals   json.RawMessage `json:"signals"`
	UpdatedAt string          `json:"updated_at"`
}

// List returns elevated user_risk rows (level != 'none') joined with email, ordered by score desc.
// Excludes remediated rows (score=0/level='none') — Reset leaves rows in place; showing them
// would bloat the dashboard O(users) after years of compute+remediate cycles.
// Uses workerPool (BYPASSRLS) since user_risk has FORCE RLS.
func (h *RiskHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.workerPool.Query(ctx,
		`SELECT r.user_id, COALESCE(u.email, ''), r.score, r.level, r.signals, r.updated_at::text
		   FROM user_risk r JOIN users u ON u.id = r.user_id
		  WHERE r.level != 'none'
		  ORDER BY r.score DESC LIMIT $1`, parseTouLimit(r))
	if err != nil {
		h.logger.Error("user-risk list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	out := []riskRow{}
	for rows.Next() {
		var row riskRow
		var signals []byte
		if err := rows.Scan(&row.UserID, &row.Email, &row.Score, &row.Level, &signals, &row.UpdatedAt); err != nil {
			h.logger.Warn("user-risk list scan failed", "error", err)
			continue
		}
		row.Signals = json.RawMessage(signals)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("user-risk list rows error", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// Reset clears a user's risk level/score/signals and sets remediated_at (CA-0b audited).
// Uses workerPool (BYPASSRLS) — user_risk FORCE RLS blocks UPDATE on the app pool.
func (h *RiskHandler) Reset(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := parsePathID(r, "id")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	tx, err := h.workerPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		h.logger.Error("risk reset: begin tx failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "transaction failed")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tag, err := tx.Exec(ctx,
		`UPDATE user_risk SET score=0, level='none', signals='[]'::jsonb,
		     remediated_at=now(), updated_at=now()
		 WHERE user_id=$1`, userID)
	if err != nil {
		h.logger.Error("risk reset failed", "error", err, "user_id", userID)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteError(w, http.StatusNotFound, "user_risk not found")
		return
	}

	// CA-0b: audit in-txn — sensitive remediation write must be logged atomically.
	after, _ := json.Marshal(map[string]any{"user_id": userID, "action": "risk_reset"})
	if err := audit.Write(ctx, tx, audit.Entry{
		Actor: claims.UserID, Action: "user_risk.reset", TargetType: "user_risk", TargetID: &userID,
		After: after, IP: httputil.ClientIP(r), Tier: "core",
	}); err != nil {
		h.logger.Error("risk reset audit failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "audit write failed")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("risk reset: commit failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "commit failed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
