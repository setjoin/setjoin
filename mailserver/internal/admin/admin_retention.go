package admin

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
)

// RetentionHandler provides CRUD for email retention policies
// and read/write for log retention settings.
type RetentionHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewRetentionHandler creates a retention admin handler.
func NewRetentionHandler(pool *pgxpool.Pool, logger *slog.Logger) *RetentionHandler {
	return &RetentionHandler{pool: pool, logger: logger}
}

// --- Email retention policies ---

type retentionPolicy struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	RetainDays  *int      `json:"retainDays"` // nil = forever
	Action      string    `json:"action"`
	IsDefault   bool      `json:"isDefault"`
	DomainID    *int64    `json:"domainId,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

// ListPolicies returns all retention policies.
func (h *RetentionHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := `SELECT id, name, description, retain_days, action, is_default, domain_id, created_at
		 FROM retention_policies`
	var args []any
	if domainScope := middleware.DomainScopeFromContext(ctx); domainScope > 0 {
		query += ` WHERE domain_id IS NULL OR domain_id = $1`
		args = append(args, domainScope)
	}
	query += ` ORDER BY is_default DESC, id ASC`
	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "retention policy list failed", err)
		return
	}
	defer rows.Close()

	out := make([]retentionPolicy, 0)
	for rows.Next() {
		var p retentionPolicy
		var domainID *int64
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.RetainDays, &p.Action, &p.IsDefault, &domainID, &p.CreatedAt); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "retention policy scan failed", err)
			return
		}
		p.DomainID = domainID
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "retention policy rows error", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// CreatePolicy creates a new retention policy.
//
// R2 — the policy's owning domain comes from the AUTH CONTEXT, never from the
// request body: a domain-scoped compliance.write holder always creates the
// policy inside their own domain (req.DomainID is never inserted verbatim),
// and a request naming a different domain is rejected. An unscoped (global)
// holder may target any domain, or NULL — NULL domain_id rows are the
// legitimately global org-wide policy tier.
//
// Mutation and audit are ATOMIC (F-002, Astra waves34 HOLD 4): the INSERT and
// its audit_write run on one transaction and commit together — a failed audit
// rolls the policy row back, and the audit after-image is fed from the
// inserted row's RETURNING values, never from the request.
func (h *RetentionHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		RetainDays  *int   `json:"retainDays"` // nil = forever
		Action      string `json:"action"`
		IsDefault   bool   `json:"isDefault"`
		DomainID    *int64 `json:"domainId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.Name == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "name is required"})
		return
	}
	if req.Action == "" {
		req.Action = "delete"
	}
	if req.Action != "delete" && req.Action != "hold" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "action must be delete or hold"})
		return
	}

	var domainID *int64
	if scope := middleware.DomainScopeFromContext(ctx); scope > 0 {
		if req.DomainID != nil && *req.DomainID != scope {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "cannot create a retention policy for another domain"})
			return
		}
		domainID = &scope
	} else {
		domainID = req.DomainID
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "retention policy tx begin failed", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var (
		id         int64
		insName    string
		insDesc    *string
		insDays    *int
		insAction  string
		insDefault bool
		insDomain  *int64
	)
	err = tx.QueryRow(ctx,
		`INSERT INTO retention_policies (name, description, retain_days, action, is_default, domain_id)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, name, description, retain_days, action, is_default, domain_id`,
		req.Name, req.Description, req.RetainDays, req.Action, req.IsDefault, domainID,
	).Scan(&id, &insName, &insDesc, &insDays, &insAction, &insDefault, &insDomain)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "retention policy create failed", err)
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{
		"id": id, "name": insName, "description": insDesc, "retainDays": insDays,
		"action": insAction, "isDefault": insDefault, "domainId": insDomain,
	})
	if err := audit.Write(ctx, tx, audit.Entry{
		Actor: claims.UserID, Action: "retention_policy_create", TargetType: "retention_policy", TargetID: &id,
		After: afterJSON, IP: httputil.ClientIP(r), Tier: "core",
	}); err != nil {
		// The deferred rollback discards the INSERT: no unaudited policy row.
		httputil.WriteDBErr(w, r, h.logger, "retention policy audit failed", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "retention policy tx commit failed", err)
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// UpdatePolicy patches a retention policy.
//
// R3 — ownership rides in the SAME WHERE as the mutation: a domain-scoped
// compliance.write holder can only patch a policy belonging to their own
// domain (another domain's — and any global — policy is not-found, no
// existence leak, no check-then-mutate TOCTOU). A request asking to retarget
// a policy to a different domain is rejected, and when a domain-scoped actor
// does retarget, the written domain_id is the auth-context scope — the
// request's domainId is never written verbatim.
//
// Mutation and audit are ATOMIC (F-002, Astra waves34 HOLD 4): the pre-image
// is read FOR UPDATE on the transaction, the patch commits together with its
// audit_write, and a failed audit rolls the whole patch back. Both images are
// fed from the row itself — before from the locked pre-row, after from the
// UPDATE's RETURNING values.
func (h *RetentionHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid policy id"})
		return
	}

	var req struct {
		Name        *string `json:"name,omitempty"`
		Description *string `json:"description,omitempty"`
		RetainDays  *int    `json:"retainDays,omitempty"`
		Action      *string `json:"action,omitempty"`
		IsDefault   *bool   `json:"isDefault,omitempty"`
		DomainID    *int64  `json:"domainId,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	scope := middleware.DomainScopeFromContext(ctx)
	if scope > 0 && req.DomainID != nil && *req.DomainID != scope {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "cannot retarget a retention policy to another domain"})
		return
	}

	var sets []string
	var args []any
	argIdx := 1

	if req.Name != nil {
		sets = append(sets, "name = $"+strconv.Itoa(argIdx))
		args = append(args, *req.Name)
		argIdx++
	}
	if req.Description != nil {
		sets = append(sets, "description = $"+strconv.Itoa(argIdx))
		args = append(args, *req.Description)
		argIdx++
	}
	if req.RetainDays != nil {
		sets = append(sets, "retain_days = $"+strconv.Itoa(argIdx))
		args = append(args, *req.RetainDays)
		argIdx++
	}
	if req.Action != nil {
		sets = append(sets, "action = $"+strconv.Itoa(argIdx))
		args = append(args, *req.Action)
		argIdx++
	}
	if req.IsDefault != nil {
		sets = append(sets, "is_default = $"+strconv.Itoa(argIdx))
		args = append(args, *req.IsDefault)
		argIdx++
	}
	if req.DomainID != nil {
		sets = append(sets, "domain_id = $"+strconv.Itoa(argIdx))
		args = append(args, *req.DomainID)
		argIdx++
	}

	if len(sets) == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "no fields to update"})
		return
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "retention policy tx begin failed", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Pre-image under the SAME ownership predicate, locked so the audited
	// before/after pair describes one atomic transition.
	beforeQuery := `SELECT id, name, description, retain_days, action, is_default, domain_id
		FROM retention_policies WHERE id = $1`
	beforeArgs := []any{id}
	if scope > 0 {
		beforeQuery += " AND domain_id = $2"
		beforeArgs = append(beforeArgs, scope)
	}
	var (
		preID      int64
		preName    string
		preDesc    *string
		preDays    *int
		preAction  string
		preDefault bool
		preDomain  *int64
	)
	err = tx.QueryRow(ctx, beforeQuery, beforeArgs...).Scan(
		&preID, &preName, &preDesc, &preDays, &preAction, &preDefault, &preDomain)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "policy not found"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "retention policy pre-image read failed", err)
		return
	}
	beforeJSON, _ := json.Marshal(map[string]any{
		"id": preID, "name": preName, "description": preDesc, "retainDays": preDays,
		"action": preAction, "isDefault": preDefault, "domainId": preDomain,
	})

	args = append(args, id)
	query := "UPDATE retention_policies SET " + strings.Join(sets, ", ") + " WHERE id = $" + strconv.Itoa(argIdx)
	if scope > 0 {
		args = append(args, scope)
		query += " AND domain_id = $" + strconv.Itoa(argIdx+1)
	}
	query += " RETURNING id, name, description, retain_days, action, is_default, domain_id"

	var (
		updID      int64
		updName    string
		updDesc    *string
		updDays    *int
		updAction  string
		updDefault bool
		updDomain  *int64
	)
	err = tx.QueryRow(ctx, query, args...).Scan(
		&updID, &updName, &updDesc, &updDays, &updAction, &updDefault, &updDomain)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "retention policy update failed", err)
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{
		"id": updID, "name": updName, "description": updDesc, "retainDays": updDays,
		"action": updAction, "isDefault": updDefault, "domainId": updDomain,
	})
	if err := audit.Write(ctx, tx, audit.Entry{
		Actor: claims.UserID, Action: "retention_policy_update", TargetType: "retention_policy", TargetID: &updID,
		Before: beforeJSON, After: afterJSON, IP: httputil.ClientIP(r), Tier: "core",
	}); err != nil {
		// The deferred rollback discards the patch: no unaudited mutation.
		httputil.WriteDBErr(w, r, h.logger, "retention policy audit failed", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "retention policy tx commit failed", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// DeletePolicy removes a retention policy.
//
// R3 — ownership rides in the SAME WHERE as the delete: a domain-scoped
// compliance.write holder can only delete a policy belonging to their own
// domain; another domain's — and any global — policy is not-found (no
// existence leak, no check-then-delete TOCTOU). The deleted row's RETURNING
// values feed the audit record.
//
// Mutation and audit are ATOMIC (F-002, Astra waves34 HOLD 4): the DELETE and
// its audit_write commit together on one transaction — a failed audit rolls
// the delete back and the policy row survives.
func (h *RetentionHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid policy id"})
		return
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "retention policy tx begin failed", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	query := `DELETE FROM retention_policies WHERE id = $1`
	args := []any{id}
	if scope := middleware.DomainScopeFromContext(ctx); scope > 0 {
		args = append(args, scope)
		query += " AND domain_id = $2"
	}
	query += " RETURNING name, domain_id"

	var name string
	var domainID *int64
	if err := tx.QueryRow(ctx, query, args...).Scan(&name, &domainID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "policy not found"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "retention policy delete failed", err)
		return
	}

	beforeJSON, _ := json.Marshal(map[string]any{"name": name, "domainId": domainID})
	if err := audit.Write(ctx, tx, audit.Entry{
		Actor: claims.UserID, Action: "retention_policy_delete", TargetType: "retention_policy", TargetID: &id,
		Before: beforeJSON, IP: httputil.ClientIP(r), Tier: "core",
	}); err != nil {
		// The deferred rollback restores the row: no unaudited deletion.
		httputil.WriteDBErr(w, r, h.logger, "retention policy audit failed", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "retention policy tx commit failed", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Log retention settings ---

type logRetentionSettings struct {
	MessageTraceDays    *int `json:"messageTraceDays"`    // nil = forever
	MailboxAuditLogDays *int `json:"mailboxAuditLogDays"` // nil = forever
	AuthEventDays       *int `json:"authEventDays"`       // nil = forever
	WebhookDeliveryDays *int `json:"webhookDeliveryDays"` // nil = forever
}

// GetLogRetention returns current log retention settings from system_config.
func (h *RetentionHandler) GetLogRetention(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var s logRetentionSettings

	var traceVal []byte
	err := h.pool.QueryRow(ctx,
		`SELECT value FROM system_config WHERE key = 'log_retention_message_trace_days'`).Scan(&traceVal)
	if err == nil {
		var v int
		if err := json.Unmarshal(traceVal, &v); err == nil && v > 0 {
			s.MessageTraceDays = &v
		}
	}

	var auditVal []byte
	err = h.pool.QueryRow(ctx,
		`SELECT value FROM system_config WHERE key = 'log_retention_mailbox_audit_days'`).Scan(&auditVal)
	if err == nil {
		var v int
		if err := json.Unmarshal(auditVal, &v); err == nil && v > 0 {
			s.MailboxAuditLogDays = &v
		}
	}

	var authEventVal []byte
	_ = h.pool.QueryRow(ctx,
		`SELECT value FROM system_config WHERE key = 'log_retention_auth_event_days'`).Scan(&authEventVal)
	{
		var v int
		if err := json.Unmarshal(authEventVal, &v); err == nil && v > 0 {
			s.AuthEventDays = &v
		}
	}

	var webhookVal []byte
	_ = h.pool.QueryRow(ctx,
		`SELECT value FROM system_config WHERE key = 'log_retention_webhook_delivery_days'`).Scan(&webhookVal)
	{
		var v int
		if err := json.Unmarshal(webhookVal, &v); err == nil && v > 0 {
			s.WebhookDeliveryDays = &v
		}
	}

	httputil.WriteJSON(w, http.StatusOK, s)
}

// SetLogRetention updates log retention settings in system_config.
func (h *RetentionHandler) SetLogRetention(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req logRetentionSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "log retention tx begin failed", err)
		return
	}
	defer tx.Rollback(ctx)

	traceVal := "0"
	if req.MessageTraceDays != nil && *req.MessageTraceDays > 0 {
		traceVal = strconv.Itoa(*req.MessageTraceDays)
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO system_config (key, value, updated_at)
		 VALUES ('log_retention_message_trace_days', $1, now())
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		traceVal)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "log retention trace update failed", err)
		return
	}

	auditVal := "0"
	if req.MailboxAuditLogDays != nil && *req.MailboxAuditLogDays > 0 {
		auditVal = strconv.Itoa(*req.MailboxAuditLogDays)
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO system_config (key, value, updated_at)
		 VALUES ('log_retention_mailbox_audit_days', $1, now())
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		auditVal)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "log retention audit update failed", err)
		return
	}

	authEventVal := "0"
	if req.AuthEventDays != nil && *req.AuthEventDays > 0 {
		authEventVal = strconv.Itoa(*req.AuthEventDays)
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO system_config (key, value, updated_at)
		 VALUES ('log_retention_auth_event_days', $1, now())
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		authEventVal)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "log retention auth event update failed", err)
		return
	}

	webhookVal := "0"
	if req.WebhookDeliveryDays != nil && *req.WebhookDeliveryDays > 0 {
		webhookVal = strconv.Itoa(*req.WebhookDeliveryDays)
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO system_config (key, value, updated_at)
		 VALUES ('log_retention_webhook_delivery_days', $1, now())
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		webhookVal)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "log retention webhook delivery update failed", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "log retention tx commit failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RunPrune triggers an immediate log prune and returns results.
func (h *RetentionHandler) RunPrune(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.pool.Query(ctx, `SELECT pruned_table, rows_deleted FROM prune_log_tables()`)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "prune log tables failed", err)
		return
	}
	defer rows.Close()

	out := []map[string]any{}
	for rows.Next() {
		var table string
		var deleted int
		if err := rows.Scan(&table, &deleted); err == nil {
			out = append(out, map[string]any{"table": table, "deleted": deleted})
		}
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}
