// Admin CRUD + Reorder API for conditional access policies.
//
// Routes (registered in main.go):
//
//	GET    /admin/conditional-access/policies                          — List policies (?include_deleted=1 includes tombstoned)
//	POST   /admin/conditional-access/policies                          — Create a policy (F6 pre-validate)
//	PUT    /admin/conditional-access/policies/{id}                     — Update a policy (F6 pre-validate)
//	DELETE /admin/conditional-access/policies/{id}                     — Soft-delete a policy
//	POST   /admin/conditional-access/policies/{id}/restore             — Restore a soft-deleted policy
//	POST   /admin/conditional-access/policies/restore-from-audit       — Rebuild a hard-deleted policy from audit
//	POST   /admin/conditional-access/policies/reorder                  — Reorder (accepts ID array)
//	GET    /admin/conditional-access/resolve-principals                — Batch id→name for exclude picker
//	GET    /admin/conditional-access/break-glass                       — Read the break-glass set (resolved admins)
//	PUT    /admin/conditional-access/break-glass                       — Set the break-glass user-id list
//	POST   /admin/conditional-access/sessions/{userId}/revoke          — Kill every live session for a user (CA-3a)
//	GET    /admin/conditional-access/sessions/log                      — Recent session_revocations for the audit view (CA-3a)
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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/threat"
)

// ConditionalAccessHandler provides CRUD access to conditional access policies.
type ConditionalAccessHandler struct {
	pool       *pgxpool.Pool
	workerPool *pgxpool.Pool // BYPASSRLS pool for cross-user admin reads (session_revocations log)
	logger     *slog.Logger
}

// NewConditionalAccessHandler creates a conditional access admin handler.
// workerPool is the BYPASSRLS pool for admin cross-user reads; pass the same as pool until
// DB_WORKER_DSN is set (INERT — workerPool aliases pool in that case).
func NewConditionalAccessHandler(pool *pgxpool.Pool, workerPool pgxutil.WorkerPool, logger *slog.Logger) *ConditionalAccessHandler {
	return &ConditionalAccessHandler{pool: pool, workerPool: workerPool.Pool, logger: logger}
}

// caPolicyResponse is the JSON shape for a policy returned by the API.
// DeletedAt is non-nil only when ?include_deleted=1 and the row is a tombstone;
// live rows emit deleted_at:null so the UI can distinguish without a second signal.
type caPolicyResponse struct {
	ID             int64           `json:"id"`
	Priority       int             `json:"priority"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	State          string          `json:"state"`
	ScopeType      string          `json:"scope_type"`
	ScopeTarget    string          `json:"scope_target"`
	Conditions     json.RawMessage `json:"conditions"`
	Actions        json.RawMessage `json:"actions"`
	ExcludeUsers   json.RawMessage `json:"exclude_users"`
	ExcludeGroups  json.RawMessage `json:"exclude_groups"`
	SessionControl json.RawMessage `json:"session_control"`
	CreatedAt      string          `json:"created_at"`
	UpdatedAt      string          `json:"updated_at"`
	DeletedAt      *string         `json:"deleted_at"`
}

// caPolicyCreate is the request body for creating/updating a policy.
type caPolicyCreate struct {
	Priority       *int            `json:"priority,omitempty"`
	Name           string          `json:"name"`
	Description    string          `json:"description,omitempty"`
	State          string          `json:"state,omitempty"`
	ScopeType      string          `json:"scope_type,omitempty"`
	ScopeTarget    string          `json:"scope_target,omitempty"`
	Conditions     json.RawMessage `json:"conditions"`
	Actions        json.RawMessage `json:"actions"`
	ExcludeUsers   json.RawMessage `json:"exclude_users,omitempty"`
	ExcludeGroups  json.RawMessage `json:"exclude_groups,omitempty"`
	SessionControl json.RawMessage `json:"session_control,omitempty"`
}

// ── Error mapping ──

// caErrorStatus maps a reducer/DB error to an HTTP status via the shared
// reducererr classification (c6) — the per-code table (BZ080→409, BZ081→404,
// BZ082/BZ085/BZ094/BZ097/BZ098→400, BZ086→404, BZ087/BZ093→409,
// BZ088/BZ090/BZ092→422, BZ091→404, BZ095→409) lives in reducererr.codeClass
// now, not here. Only the SQLSTATE constraint code stays local:
//   - 23514 CHECK violation → 400 Bad Request (array CHECKs, ca_policy_doc_valid)
//   - unclassified          → 500
func caErrorStatus(err error) int {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23514" { // check_violation — SQLSTATE, kept out of reducererr
		return http.StatusBadRequest
	}
	if class := reducererr.Classify(err); class != reducererr.ClassUnknown {
		return class.HTTPStatus()
	}
	return http.StatusInternalServerError
}

// caErrorDetail returns the reducer HINT (or message) for the client, via the
// shared reducererr.Detail allowlist. The CA-family codes pass the HINT
// through (actionable remediation text the SPA surfaces verbatim); an
// UNCLASSIFIED error now yields the fixed "request failed" instead of leaking
// raw SQLERRM on the 500 path (deliberate c6 hardening). 23514 keeps its local
// HINT passthrough (SQLSTATE, outside reducererr).
func caErrorDetail(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23514" {
		if pgErr.Hint != "" {
			return pgErr.Hint
		}
		return pgErr.Message
	}
	return reducererr.Detail(err)
}

// caSchemaErrorStatus returns 400 for a *threat.PolicySchemaError (F6 pre-reducer
// validation); returns 0 for nil (no error — caller proceeds to the reducer).
func caSchemaErrorStatus(err error) int {
	if err == nil {
		return 0
	}
	var schemaErr *threat.PolicySchemaError
	if errors.As(err, &schemaErr) {
		return http.StatusBadRequest
	}
	return 0
}

// ── Handler methods ──

// List returns policies ordered by priority.
// Default: live only (deleted_at IS NULL). ?include_deleted=1: all rows including tombstones.
func (h *ConditionalAccessHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ponytail: build the WHERE clause inline — one query path, one variable.
	where := " WHERE deleted_at IS NULL"
	if r.URL.Query().Get("include_deleted") == "1" {
		where = ""
	}
	// Cast timestamps to text so pgx binary mode can scan into *string (timestamptz OID → *string panics).
	rows, err := h.pool.Query(ctx,
		`SELECT id, priority, name, description, state, scope_type, scope_target,
		        conditions, actions, exclude_users, exclude_groups, session_control,
		        created_at::text, updated_at::text, deleted_at::text
		 FROM conditional_access_policies`+where+`
		 ORDER BY priority ASC`)
	if err != nil {
		h.logger.Error("conditional access list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var out []caPolicyResponse
	for rows.Next() {
		var p caPolicyResponse
		var condBytes, actBytes, exUBytes, exGBytes, scBytes []byte
		if err := rows.Scan(&p.ID, &p.Priority, &p.Name, &p.Description, &p.State,
			&p.ScopeType, &p.ScopeTarget, &condBytes, &actBytes, &exUBytes, &exGBytes, &scBytes,
			&p.CreatedAt, &p.UpdatedAt, &p.DeletedAt); err != nil {
			h.logger.Warn("conditional access list scan failed", "error", err)
			continue
		}
		p.Conditions = json.RawMessage(condBytes)
		p.Actions = json.RawMessage(actBytes)
		p.ExcludeUsers = json.RawMessage(exUBytes)
		p.ExcludeGroups = json.RawMessage(exGBytes)
		p.SessionControl = json.RawMessage(scBytes)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("conditional access list rows error", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if out == nil {
		out = []caPolicyResponse{}
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// Create inserts a new conditional access policy via ca_policy_upsert.
// F6: ValidatePolicyDocument is called BEFORE the reducer (handler-first
// defence-in-depth; the V026 ca_policy_doc_valid CHECK is the un-bypassable floor).
func (h *ConditionalAccessHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req caPolicyCreate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Name == "" {
		httputil.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}

	// F6: pre-validate the policy document shape before calling the reducer.
	if err := h.validatePolicyDoc(w, req.Conditions, req.Actions); err != nil {
		return // response already written
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	policy := h.buildPolicyJSON(req)

	// ponytail: single tx wraps upsert + set_session_control so a BZ098 (bad
	// session_control) rolls back the policy row — no phantom row on 400.
	tx, txErr := h.pool.BeginTx(ctx, pgx.TxOptions{})
	if txErr != nil {
		h.logger.Error("ca create: begin tx failed", "error", txErr)
		httputil.WriteError(w, http.StatusInternalServerError, "transaction failed")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on any early return; commit below

	var out []byte
	err := tx.QueryRow(ctx,
		`SELECT ca_policy_upsert($1, $2::inet, NULL, $3::jsonb)`,
		claims.UserID, httputil.ClientIP(r), string(policy),
	).Scan(&out)
	if err != nil {
		h.logger.Error("ca create failed", "error", err)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	// CA-3a: route session_control through set_session_control so the §6.1
	// validator runs (BZ098 surfaces as 400). Same tx — rollback on failure so
	// the upsert row never lands without its session_control (data integrity).
	if req.SessionControl != nil {
		var idResp struct {
			ID int64 `json:"id"`
		}
		if jsonErr := json.Unmarshal(out, &idResp); jsonErr == nil && idResp.ID > 0 {
			if _, scErr := tx.Exec(ctx,
				`SELECT set_session_control($1, $2::jsonb, $3::jsonb, $4, $5::inet)`,
				idResp.ID, rawOrObject(req.Actions, `{"action":"allow"}`),
				req.SessionControl, claims.UserID, httputil.ClientIP(r)); scErr != nil {
				h.logger.Error("set_session_control failed on create", "error", scErr, "id", idResp.ID)
				httputil.WriteError(w, caErrorStatus(scErr), caErrorDetail(scErr))
				return
			}
		}
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		h.logger.Error("ca create: commit failed", "error", commitErr)
		httputil.WriteError(w, http.StatusInternalServerError, "commit failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(out)
}

// Update modifies an existing conditional access policy via ca_policy_upsert.
// F6: ValidatePolicyDocument is called BEFORE the reducer.
func (h *ConditionalAccessHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	idStr := r.PathValue("id")
	policyID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	var req caPolicyCreate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Name == "" {
		httputil.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}

	// F6: pre-validate the policy document shape before calling the reducer.
	if err := h.validatePolicyDoc(w, req.Conditions, req.Actions); err != nil {
		return // response already written
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	policy := h.buildPolicyJSON(req)

	// Keep policy upsert and optional session-control validation atomic. A BZ098
	// from set_session_control must not leave the preceding policy update committed.
	tx, txErr := h.pool.BeginTx(ctx, pgx.TxOptions{})
	if txErr != nil {
		h.logger.Error("ca update: begin tx failed", "error", txErr, "id", policyID)
		httputil.WriteError(w, http.StatusInternalServerError, "transaction failed")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on any early return; commit below

	var out []byte
	err = tx.QueryRow(ctx,
		`SELECT ca_policy_upsert($1, $2::inet, $3, $4::jsonb)`,
		claims.UserID, httputil.ClientIP(r), policyID, string(policy),
	).Scan(&out)
	if err != nil {
		h.logger.Error("ca update failed", "error", err, "id", policyID)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	// CA-3a: route session_control through set_session_control (§6.1 validator; BZ098 → 400).
	if req.SessionControl != nil {
		if _, scErr := tx.Exec(ctx,
			`SELECT set_session_control($1, $2::jsonb, $3::jsonb, $4, $5::inet)`,
			policyID, rawOrObject(req.Actions, `{"action":"allow"}`),
			req.SessionControl, claims.UserID, httputil.ClientIP(r)); scErr != nil {
			h.logger.Error("set_session_control failed on update", "error", scErr, "id", policyID)
			httputil.WriteError(w, caErrorStatus(scErr), caErrorDetail(scErr))
			return
		}
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		h.logger.Error("ca update: commit failed", "error", commitErr, "id", policyID)
		httputil.WriteError(w, http.StatusInternalServerError, "commit failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// Delete soft-deletes a conditional access policy via ca_policy_soft_delete.
// The row is tombstoned (deleted_at set) and hidden from the default List view.
// Use POST /{id}/restore to un-delete; hard-delete is a separate admin operation.
func (h *ConditionalAccessHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := parsePathID(r, "id")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	_, err = h.pool.Exec(ctx,
		`SELECT ca_policy_soft_delete($1, $2)`,
		policyID, claims.UserID,
	)
	if err != nil {
		h.logger.Error("ca soft-delete failed", "error", err, "id", policyID)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Restore un-deletes a soft-deleted policy via ca_policy_restore.
// BZ087 (priority conflict) → 409; BZ081 (not found) → 404.
func (h *ConditionalAccessHandler) Restore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := parsePathID(r, "id")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	_, err = h.pool.Exec(ctx,
		`SELECT ca_policy_restore($1, $2)`,
		policyID, claims.UserID,
	)
	if err != nil {
		h.logger.Error("ca restore failed", "error", err, "id", policyID)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RestoreFromAudit rebuilds a hard-deleted policy from an audit snapshot via
// ca_policy_restore_from_audit. Body: {"audit_id": <int64>}.
// Returns {"id": <new_id>} on success.
// BZ086 (audit row missing) → 404; BZ087 (priority conflict) → 409.
func (h *ConditionalAccessHandler) RestoreFromAudit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)

	var req struct {
		AuditID int64 `json:"audit_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.AuditID == 0 {
		httputil.WriteError(w, http.StatusBadRequest, "audit_id is required")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var newID int64
	err := h.pool.QueryRow(ctx,
		`SELECT ca_policy_restore_from_audit($1, $2)`,
		req.AuditID, claims.UserID,
	).Scan(&newID)
	if err != nil {
		h.logger.Error("ca restore-from-audit failed", "error", err, "audit_id", req.AuditID)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"id": newID})
}

// Reorder accepts an array of policy IDs and delegates to ca_policy_reorder.
func (h *ConditionalAccessHandler) Reorder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var ids []int64
	if err := json.NewDecoder(r.Body).Decode(&ids); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON: expected array of policy IDs")
		return
	}
	if len(ids) == 0 {
		httputil.WriteError(w, http.StatusBadRequest, "at least one policy ID required")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	_, err := h.pool.Exec(ctx,
		`SELECT ca_policy_reorder($1, $2::inet, $3::bigint[])`,
		claims.UserID, httputil.ClientIP(r), ids,
	)
	if err != nil {
		h.logger.Error("ca reorder failed", "error", err)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ResolvePrincipals batch-resolves exclude user/group ids to display names so the
// admin UI renders chips (not raw ids). Cross-user read on the admin pool, gated
// access.policy_read at the route; ids are bound params (R-rules), never concatenated.
func (h *ConditionalAccessHandler) ResolvePrincipals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userIDs := parseIDQuery(r.URL.Query().Get("users"))
	groupIDs := parseIDQuery(r.URL.Query().Get("groups"))

	out := map[string]any{
		"users":  []any{},
		"groups": []any{},
	}

	if len(userIDs) > 0 {
		rows, err := h.pool.Query(ctx,
			`SELECT id, COALESCE(email,''), COALESCE(display_name,'') FROM users WHERE id = ANY($1)`,
			userIDs)
		if err != nil {
			h.logger.Error("resolve-principals user query failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "database error")
			return
		}
		defer rows.Close()
		var users []any
		for rows.Next() {
			var id int64
			var email, displayName string
			if scanErr := rows.Scan(&id, &email, &displayName); scanErr == nil {
				users = append(users, map[string]any{
					"id":           id,
					"email":        email,
					"display_name": displayName,
				})
			}
		}
		if rows.Err() != nil {
			h.logger.Error("resolve-principals user rows error", "error", rows.Err())
			httputil.WriteError(w, http.StatusInternalServerError, "database error")
			return
		}
		if users != nil {
			out["users"] = users
		}
	}

	if len(groupIDs) > 0 {
		rows, err := h.pool.Query(ctx,
			`SELECT id, COALESCE(name,'') FROM user_groups WHERE id = ANY($1)`,
			groupIDs)
		if err != nil {
			h.logger.Error("resolve-principals group query failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "database error")
			return
		}
		defer rows.Close()
		var groups []any
		for rows.Next() {
			var id int64
			var name string
			if scanErr := rows.Scan(&id, &name); scanErr == nil {
				groups = append(groups, map[string]any{
					"id":   id,
					"name": name,
				})
			}
		}
		if rows.Err() != nil {
			h.logger.Error("resolve-principals group rows error", "error", rows.Err())
			httputil.WriteError(w, http.StatusInternalServerError, "database error")
			return
		}
		if groups != nil {
			out["groups"] = groups
		}
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// ── Break-glass endpoints ──

// GetBreakGlass reads the system break-glass set from system_config and resolves
// each user ID to display data for the BreakGlassBanner component (Task 8).
//
// Response: { admins: [{id, email, display_name}] }
// An absent key (no break-glass set yet) returns { admins: [] }.
// Gated: access.policy_read.
func (h *ConditionalAccessHandler) GetBreakGlass(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Read the raw break-glass ID array from system_config.
	var raw []byte
	err := h.pool.QueryRow(ctx,
		`SELECT value FROM system_config WHERE key = 'ca_break_glass_user_ids'`,
	).Scan(&raw)
	if err != nil {
		// Key absent — return an empty set (not an error).
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"admins": []any{}})
		return
	}
	var ids []int64
	if jsonErr := json.Unmarshal(raw, &ids); jsonErr != nil || len(ids) == 0 {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"admins": []any{}})
		return
	}

	// Resolve each ID to {id, email, display_name}.
	rows, err := h.pool.Query(ctx,
		`SELECT id, COALESCE(email,''), COALESCE(display_name,'') FROM users WHERE id = ANY($1)`,
		ids,
	)
	if err != nil {
		h.logger.Error("break-glass resolve users failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	admins := make([]any, 0, len(ids))
	for rows.Next() {
		var id int64
		var email, displayName string
		if scanErr := rows.Scan(&id, &email, &displayName); scanErr == nil {
			admins = append(admins, map[string]any{
				"id":           id,
				"email":        email,
				"display_name": displayName,
			})
		}
	}
	if rows.Err() != nil {
		h.logger.Error("break-glass resolve users rows error", "error", rows.Err())
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"admins": admins})
}

// SetBreakGlass writes the break-glass user-id list via ca_break_glass_set.
//
// Request body: [id, id, …]  (JSON array of int64 user IDs)
// Response 204 on success.
// 400 on empty/invalid input; 500 on DB error.
// Gated: access.policy_write.
func (h *ConditionalAccessHandler) SetBreakGlass(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KiB

	var ids []int64
	if err := json.NewDecoder(r.Body).Decode(&ids); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON: expected array of user IDs")
		return
	}
	if len(ids) == 0 {
		httputil.WriteError(w, http.StatusBadRequest, "at least one user ID required")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	_, err := h.pool.Exec(ctx,
		`SELECT ca_break_glass_set($1, $2::inet, $3::bigint[])`,
		claims.UserID, httputil.ClientIP(r), ids,
	)
	if err != nil {
		h.logger.Error("ca break-glass set failed", "error", err)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ── Promote handler ──

// promotePreviewResponse is the 409 body the PromoteDialog (F1) renders.
// Shape mirrors ca_policy_impact('blocked_users') + the summary fields.
type promotePreviewResponse struct {
	WouldBlockUsers  int64           `json:"would_block_users"`
	WouldBlockAdmins int64           `json:"would_block_admins"`
	SelfLockedOut    bool            `json:"self_locked_out"`
	BlockedUsers     []caBlockedUser `json:"blocked_users"`
	AdminUsers       []caAdminUser   `json:"admin_users"`
	Shown            int64           `json:"shown"`
	Total            int64           `json:"total"`
	Window           string          `json:"window"`
}

// caBlockedUser is one row from the blocked_users list (from ca_policy_impact).
type caBlockedUser struct {
	ID      int64  `json:"id"`
	Address string `json:"address"`
	IsAdmin bool   `json:"is_admin"`
}

// caAdminUser is one row from the uncapped admin_users list.
type caAdminUser struct {
	ID      int64  `json:"id"`
	Address string `json:"address"`
}

// Promote handles POST /admin/conditional-access/policies/{id}/promote.
//
// Body: {"confirm": bool}
//
// Without confirm (or confirm:false) the call is a pure preview and NEVER
// mutates: would_block>0 → 409 with the PromoteDialog blast-radius shape;
// would_block==0 → 200 with the zeroed preview shape. The UI must be able to
// open the dialog and read the impact with zero chance of flipping the policy
// — the historical behavior of promoting on confirm:false at would_block==0
// let merely opening the dialog enforce a report_only policy.
//
// With confirm:true → calls ca_policy_promote; maps BZ080 (lockout guard) → 409.
// Already-on policy → 200 no-op (idempotent; ca_policy_promote returns current shape).
//
// Gated: requireCAPolicyWrite at the route (main.go).
func (h *ConditionalAccessHandler) Promote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)

	policyID, err := parsePathID(r, "id")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	var req struct {
		Confirm bool `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// ── Step 1: read impact summary (would_block + would_block_admins) ──
	var summaryRaw []byte
	err = h.pool.QueryRow(ctx,
		`SELECT ca_policy_impact($1, '7d', NULL)`, policyID,
	).Scan(&summaryRaw)
	if err != nil {
		h.logger.Error("ca_policy_impact(summary) failed", "error", err, "id", policyID)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}
	var summary struct {
		WouldBlock       int64  `json:"would_block"`
		WouldBlockAdmins int64  `json:"would_block_admins"`
		Window           string `json:"window"`
	}
	if err := json.Unmarshal(summaryRaw, &summary); err != nil {
		h.logger.Error("ca_policy_impact summary unmarshal failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "impact read failed")
		return
	}

	// ── Step 2: preview — confirm:false NEVER reaches ca_policy_promote ──
	// would_block>0 → 409 with the blast-radius body; would_block==0 → 200 with
	// the zeroed preview shape. Both arms are read-only so the dialog can load
	// its impact without any mutation the Cancel button cannot undo.
	if !req.Confirm {
		if summary.WouldBlock > 0 {
			// Read the blocked-user list for the blast-radius body.
			var listRaw []byte
			err = h.pool.QueryRow(ctx,
				`SELECT ca_policy_impact($1, '7d', 'blocked_users')`, policyID,
			).Scan(&listRaw)
			if err != nil {
				h.logger.Error("ca_policy_impact(blocked_users) failed", "error", err, "id", policyID)
				httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
				return
			}
			var listResult struct {
				Users      []caBlockedUser `json:"users"`
				Shown      int64           `json:"shown"`
				Total      int64           `json:"total"`
				AdminUsers []caAdminUser   `json:"admin_users"`
			}
			if err := json.Unmarshal(listRaw, &listResult); err != nil {
				h.logger.Error("ca_policy_impact list unmarshal failed", "error", err)
				httputil.WriteError(w, http.StatusInternalServerError, "impact read failed")
				return
			}

			// self_locked_out: the acting admin's user_id appears in the would-block set.
			// ponytail: linear scan over the capped list (≤200 entries) — sufficient for this check.
			selfLockedOut := false
			for _, u := range listResult.Users {
				if u.ID == claims.UserID {
					selfLockedOut = true
					break
				}
			}
			// Also check admin_users (uncapped) for the self-lock case (admin may be >200 in list).
			if !selfLockedOut {
				for _, au := range listResult.AdminUsers {
					if au.ID == claims.UserID {
						selfLockedOut = true
						break
					}
				}
			}

			if listResult.Users == nil {
				listResult.Users = []caBlockedUser{}
			}
			if listResult.AdminUsers == nil {
				listResult.AdminUsers = []caAdminUser{}
			}

			httputil.WriteJSON(w, http.StatusConflict, promotePreviewResponse{
				WouldBlockUsers:  summary.WouldBlock,
				WouldBlockAdmins: summary.WouldBlockAdmins,
				SelfLockedOut:    selfLockedOut,
				BlockedUsers:     listResult.Users,
				AdminUsers:       listResult.AdminUsers,
				Shown:            listResult.Shown,
				Total:            listResult.Total,
				Window:           summary.Window,
			})
			return
		}

		// would_block==0: still a preview — 200 with the zeroed shape, no mutation.
		httputil.WriteJSON(w, http.StatusOK, promotePreviewResponse{
			WouldBlockUsers:  0,
			WouldBlockAdmins: 0,
			SelfLockedOut:    false,
			BlockedUsers:     []caBlockedUser{},
			AdminUsers:       []caAdminUser{},
			Shown:            0,
			Total:            0,
			Window:           summary.Window,
		})
		return
	}

	// ── Step 3: promote — only an explicit confirm:true reaches ca_policy_promote ──
	var out []byte
	err = h.pool.QueryRow(ctx,
		`SELECT ca_policy_promote($1, $2)`,
		policyID, claims.UserID,
	).Scan(&out)
	if err != nil {
		h.logger.Error("ca_policy_promote failed", "error", err, "id", policyID)
		// BZ080 (lockout guard inside promote) → 409; BZ081 (not found) → 404.
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// ── Sign-in log ──

// caSignInLogSelect is the shared column list for both SignInLog query branches.
// source_ip is inet — cast to text via host() so pgx v5 binary mode can scan it
// into *string (binary inet→*string panics; this matches admin_auth_log.go L36).
// ponytail: T7 — one const instead of the duplicated 14-column list.
const caSignInLogSelect = `SELECT id, occurred_at, user_id, COALESCE(host(source_ip), ''),
       protocol, client_type, device_fp, country, matched_policy_id, decision,
       would_decision, report_only, correlation_id, evaluated
FROM ca_signin_log`

// scanCASignInLogRow scans one caSignInLogSelect row into a map[string]any.
// ponytail: shared helper — caSignInLogSelect const was already extracted (T7); this closes
// the matching scan step so SignInLog and Why both stay in sync on the 14-column shape.
func scanCASignInLogRow(rows pgx.Rows) (map[string]any, error) {
	var id int64
	var uid, matched *int64
	var occurredAt time.Time
	var sip, proto, ct, dfp, country, dec, would, corrID *string
	var ro bool
	var evaluated json.RawMessage
	if err := rows.Scan(&id, &occurredAt, &uid, &sip, &proto, &ct, &dfp, &country,
		&matched, &dec, &would, &ro, &corrID, &evaluated); err != nil {
		return nil, err
	}
	return map[string]any{
		"id": id, "occurred_at": occurredAt, "user_id": uid, "source_ip": sip,
		"protocol": proto, "client_type": ct, "device_fp": dfp, "country": country,
		"matched_policy_id": matched, "decision": dec, "would_decision": would,
		"report_only": ro, "correlation_id": corrID, "evaluated": evaluated,
	}, nil
}

// SignInLog returns recent ca_signin_log rows for an admin trace.
// Gated on access.policy_read at the route. Accepts user_id OR correlation_id query params.
// ponytail: direct SELECT on ca_signin_log — no reducer needed for a read-only telemetry query.
func (h *ConditionalAccessHandler) SignInLog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit, _ := httputil.ParseLimitOffset(r, 50, 500)
	corr := r.URL.Query().Get("correlation_id")
	var rows pgx.Rows
	var err error
	if corr != "" {
		rows, err = h.pool.Query(ctx,
			caSignInLogSelect+` WHERE correlation_id = $1 ORDER BY occurred_at DESC LIMIT $2`,
			corr, limit)
	} else if uid, perr := strconv.ParseInt(r.URL.Query().Get("user_id"), 10, 64); perr == nil {
		rows, err = h.pool.Query(ctx,
			caSignInLogSelect+` WHERE user_id = $1 ORDER BY occurred_at DESC LIMIT $2`,
			uid, limit)
	} else {
		httputil.WriteError(w, http.StatusBadRequest, "user_id or correlation_id required")
		return
	}
	if err != nil {
		h.logger.Error("signin-log query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		row, scanErr := scanCASignInLogRow(rows)
		if scanErr != nil {
			h.logger.Warn("signin-log scan failed", "error", scanErr)
			continue
		}
		out = append(out, row)
	}
	if rows.Err() != nil {
		h.logger.Error("signin-log rows error", "error", rows.Err())
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"rows": out})
}

// ── Session enforcement (CA-3a) ──

// RevokeSessions kills every live session for a user (CAE critical event).
//
// Inserts a session_revocations row via revoke_user_sessions (scope='all'), which
// fires app_notify('session_revoke') so the gateway denylist cuts the session in
// near-real-time, and writes an admin_audit_log entry in-txn (CA-0b).
// The oauth_tokens.revoked_at flip (authserver-side) happens on the next token
// refresh against the revoked denylist — the gateway button issues the denylist
// row + push; full RevokeAndNotifyTx is the authserver path for originating revokes.
//
// Response: {"revocation_id": <id>}
// Gated: access.policy_write at the route (main.go); CA-0b audit is in the reducer.
func (h *ConditionalAccessHandler) RevokeSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := strconv.ParseInt(r.PathValue("userId"), 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Rule B reach check (same as suspend/delete/password-reset): revoking every
	// session of a target user is a target-user mutation — an OU/domain-confined
	// admin must not be able to kill sessions of users outside their reach (e.g.
	// lock a super-admin out of the console).
	var canReach bool
	if err := h.pool.QueryRow(ctx, `SELECT admin_can_reach($1, $2)`, claims.UserID, userID).Scan(&canReach); err != nil {
		h.logger.Error("revoke sessions reach check failed", "error", err, "user_id", userID)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if !canReach {
		httputil.WriteError(w, http.StatusForbidden, "target user is outside your administrative scope")
		return
	}

	var id int64
	if err := h.pool.QueryRow(ctx,
		`SELECT revoke_user_sessions($1, 'all', 'admin_revoke_all', $2, NULL, NULL)`,
		userID, claims.UserID).Scan(&id); err != nil {
		h.logger.Error("revoke sessions failed", "error", err, "user_id", userID)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"revocation_id": id})
}

// SessionEnforcementLog returns recent session_revocations rows for the admin audit view.
//
// ponytail: direct SELECT — no reducer needed for a read-only admin telemetry query.
// Uses h.workerPool (BYPASSRLS) so FORCE RLS on session_revocations does not filter
// to the current_user_id GUC (which is unset on admin calls → empty result).
// The admin route gate (access.policy_read) is the auth backstop.
// Gated: access.policy_read at the route (main.go).
func (h *ConditionalAccessHandler) SessionEnforcementLog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rows, err := h.workerPool.Query(ctx,
		`SELECT id, user_id, scope, reason, created_by, created_at::text
		   FROM session_revocations ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		h.logger.Error("session enforcement log query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type entry struct {
		ID        int64  `json:"id"`
		UserID    int64  `json:"user_id"`
		Scope     string `json:"scope"`
		Reason    string `json:"reason"`
		CreatedBy *int64 `json:"created_by"`
		CreatedAt string `json:"created_at"`
	}
	out := []entry{}
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Scope, &e.Reason, &e.CreatedBy, &e.CreatedAt); err != nil {
			h.logger.Warn("session enforcement log scan failed", "error", err)
			continue
		}
		out = append(out, e)
	}
	if rows.Err() != nil {
		h.logger.Error("session enforcement log rows error", "error", rows.Err())
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// ── Internal helpers ──

// validatePolicyDoc unmarshals conditions and actions from raw JSON and runs
// ValidatePolicyDocument (F6 pre-reducer gate). Writes a 400 and returns a
// non-nil error if validation fails; returns nil on success.
func (h *ConditionalAccessHandler) validatePolicyDoc(w http.ResponseWriter, condRaw, actRaw json.RawMessage) error {
	var conditions, actions map[string]interface{}
	if len(condRaw) > 0 {
		if err := json.Unmarshal(condRaw, &conditions); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "conditions: invalid JSON object")
			return err
		}
	}
	if len(actRaw) > 0 {
		if err := json.Unmarshal(actRaw, &actions); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "actions: invalid JSON object")
			return err
		}
	}
	if err := threat.ValidatePolicyDocument(conditions, actions); err != nil {
		status := caSchemaErrorStatus(err)
		if status == 0 {
			status = http.StatusBadRequest
		}
		httputil.WriteError(w, status, err.Error())
		return err
	}
	return nil
}

// buildPolicyJSON assembles the reducer's p_policy argument from the request.
// State defaults to "off" (safe). Never sends `enabled` (trigger-derived, V026 L2).
func (h *ConditionalAccessHandler) buildPolicyJSON(req caPolicyCreate) []byte {
	state := firstNonEmpty(req.State, "off")
	m := map[string]any{
		"name":           req.Name,
		"description":    req.Description,
		"state":          state,
		"scope_type":     firstNonEmpty(req.ScopeType, "global"),
		"scope_target":   req.ScopeTarget,
		"conditions":     rawOrObject(req.Conditions, "{}"),
		"actions":        rawOrObject(req.Actions, `{"action":"allow"}`),
		"exclude_users":  rawOrObject(req.ExcludeUsers, "[]"),
		"exclude_groups": rawOrObject(req.ExcludeGroups, "[]"),
	}
	if req.Priority != nil {
		m["priority"] = *req.Priority
	}
	b, _ := json.Marshal(m)
	return b
}

// firstNonEmpty returns the first non-empty string from the arguments.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// rawOrObject returns r if non-nil, otherwise a json.RawMessage of def.
func rawOrObject(r json.RawMessage, def string) json.RawMessage {
	if r != nil {
		return r
	}
	return json.RawMessage(def)
}

// parseIDQuery parses a comma-separated list of int64 IDs from a query parameter.
// e.g. "1,2,3" → []int64{1,2,3}. Invalid entries are silently skipped.
func parseIDQuery(s string) []int64 {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]int64, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		id, err := strconv.ParseInt(p, 10, 64)
		if err != nil {
			continue
		}
		out = append(out, id)
	}
	return out
}
