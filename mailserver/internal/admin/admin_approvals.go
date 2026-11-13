package admin

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"
)

// ApprovalsHandler serves admin CRUD for approval_policies and audit read of approval_requests.
// All DB queries run inside dbscope.RunUserScoped — approval_policies + approval_requests
// have FORCE RLS keyed on app.current_user_id; without the GUC the query returns 0 rows.
type ApprovalsHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewApprovalsHandler creates an ApprovalsHandler.
func NewApprovalsHandler(pool *pgxpool.Pool, logger *slog.Logger) *ApprovalsHandler {
	return &ApprovalsHandler{pool: pool, logger: logger}
}

// validConsumerTypes is the whitelist from the approval_policies CHECK constraint
// (V110 added hr.leave/hr.expense; V116 added drive.export/drive.share — the
// 6th/7th consumers, Drive P5).
var validConsumerTypes = map[string]bool{
	"rbac.jit_activation":   true,
	"mail.external_send":    true,
	"mail.group_moderation": true,
	"hr.leave":              true,
	"hr.expense":            true,
	"drive.export":          true,
	"drive.share":           true,
}

// requireManageClaims returns claims if caller has approvals.manage; writes 401/403 on failure.
func (h *ApprovalsHandler) requireManageClaims(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return nil, false
	}
	if !claims.HasPermission(permissions.PermApprovalsManage) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "approvals.manage required"})
		return nil, false
	}
	return claims, true
}

// requireViewClaims returns claims if caller has approvals.view or approvals.manage.
func (h *ApprovalsHandler) requireViewClaims(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return nil, false
	}
	if !claims.HasPermission(permissions.PermApprovalsView) && !claims.HasPermission(permissions.PermApprovalsManage) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "approvals.view or approvals.manage required"})
		return nil, false
	}
	return claims, true
}

// approvalPolicyResponse is the JSON shape for an approval_policies row.
type approvalPolicyResponse struct {
	ID               int64           `json:"id"`
	ConsumerType     string          `json:"consumerType"`
	Name             string          `json:"name"`
	Enabled          bool            `json:"enabled"`
	Priority         int             `json:"priority"`
	Conditions       json.RawMessage `json:"conditions"`
	RequiresApproval bool            `json:"requiresApproval"`
	ApproverSpec     json.RawMessage `json:"approverSpec"`
	CreatedAt        string          `json:"createdAt"`
	UpdatedAt        string          `json:"updatedAt"`
}

// approvalRequestAuditRow is the JSON shape for an approval_requests audit row.
type approvalRequestAuditRow struct {
	ID              int64   `json:"id"`
	ConsumerType    string  `json:"consumerType"`
	RequesterUserID *int64  `json:"requesterUserId,omitempty"`
	Subject         string  `json:"subject"`
	Status          string  `json:"status"`
	ApproverKind    string  `json:"approverKind"`
	ApproverRef     int64   `json:"approverRef"`
	DecidedByUserID *int64  `json:"decidedByUserId,omitempty"`
	DecidedAt       *string `json:"decidedAt,omitempty"`
	DecisionComment *string `json:"decisionComment,omitempty"`
	CreatedAt       string  `json:"createdAt"`
	ExpiresAt       string  `json:"expiresAt"`
}

// ListPolicies implements GET /admin/approval-policies?consumer_type={ct}.
// Requires approvals.view or approvals.manage.
func (h *ApprovalsHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireViewClaims(w, r)
	if !ok {
		return
	}
	ct := r.URL.Query().Get("consumer_type")
	if ct != "" && !validConsumerTypes[ct] {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid consumer_type"})
		return
	}
	ctx := r.Context()

	var out []approvalPolicyResponse
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		var q string
		var args []any
		if ct != "" {
			q = `SELECT id, consumer_type, name, enabled, priority, conditions, requires_approval,
			            approver_spec, created_at::TEXT, updated_at::TEXT
			     FROM approval_policies WHERE consumer_type = $1
			     ORDER BY consumer_type, priority`
			args = []any{ct}
		} else {
			q = `SELECT id, consumer_type, name, enabled, priority, conditions, requires_approval,
			            approver_spec, created_at::TEXT, updated_at::TEXT
			     FROM approval_policies
			     ORDER BY consumer_type, priority`
		}
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p approvalPolicyResponse
			if err := rows.Scan(&p.ID, &p.ConsumerType, &p.Name, &p.Enabled, &p.Priority,
				&p.Conditions, &p.RequiresApproval, &p.ApproverSpec, &p.CreatedAt, &p.UpdatedAt); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list approval policies failed", err)
		return
	}
	if out == nil {
		out = []approvalPolicyResponse{}
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// createPolicyRequest is the JSON body for POST /admin/approval-policies.
type createPolicyRequest struct {
	ConsumerType     string          `json:"consumerType"`
	Name             string          `json:"name"`
	Enabled          bool            `json:"enabled"`
	Conditions       json.RawMessage `json:"conditions"`
	RequiresApproval bool            `json:"requiresApproval"`
	ApproverSpec     json.RawMessage `json:"approverSpec"`
}

// CreatePolicy implements POST /admin/approval-policies. Requires approvals.manage.
func (h *ApprovalsHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req createPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if !validConsumerTypes[req.ConsumerType] {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid consumerType"})
		return
	}
	if req.Name == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "name is required"})
		return
	}
	if !isJSONObject(req.Conditions) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "conditions must be a JSON object"})
		return
	}
	if !isJSONObject(req.ApproverSpec) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "approverSpec must be a JSON object"})
		return
	}

	var id int64
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		// priority = max(priority for this consumer_type) + 1, or 1 if none.
		var maxPri int
		_ = tx.QueryRow(ctx,
			`SELECT COALESCE(MAX(priority), 0) FROM approval_policies WHERE consumer_type = $1`,
			req.ConsumerType).Scan(&maxPri)
		return tx.QueryRow(ctx, `
			INSERT INTO approval_policies
			  (consumer_type, name, enabled, priority, conditions, requires_approval, approver_spec)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
			req.ConsumerType, req.Name, req.Enabled, maxPri+1,
			[]byte(req.Conditions), req.RequiresApproval, []byte(req.ApproverSpec)).Scan(&id)
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			httputil.WriteProblem(w, r, httputil.NewConflictProblem("priority conflict — try again"))
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "create approval policy failed", err)
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{"id": id, "consumerType": req.ConsumerType, "name": req.Name})
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "approval_policy_create", TargetType: "approval_policy", TargetID: &id,
		After: afterJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// updatePolicyRequest is the JSON body for PUT /admin/approval-policies/{id}.
type updatePolicyRequest struct {
	Name             *string         `json:"name,omitempty"`
	Enabled          *bool           `json:"enabled,omitempty"`
	Conditions       json.RawMessage `json:"conditions,omitempty"`
	RequiresApproval *bool           `json:"requiresApproval,omitempty"`
	ApproverSpec     json.RawMessage `json:"approverSpec,omitempty"`
}

// UpdatePolicy implements PUT /admin/approval-policies/{id}. Requires approvals.manage.
func (h *ApprovalsHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	id, ok := httputil.ParseIDPath(w, r, "id", "invalid policy id")
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req updatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if len(req.Conditions) > 0 && !isJSONObject(req.Conditions) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "conditions must be a JSON object"})
		return
	}
	if len(req.ApproverSpec) > 0 && !isJSONObject(req.ApproverSpec) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "approverSpec must be a JSON object"})
		return
	}

	var condArg, specArg *[]byte
	if len(req.Conditions) > 0 {
		b := []byte(req.Conditions)
		condArg = &b
	}
	if len(req.ApproverSpec) > 0 {
		b := []byte(req.ApproverSpec)
		specArg = &b
	}

	var rowsAffected int64
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE approval_policies SET
			  name              = COALESCE($2, name),
			  enabled           = COALESCE($3, enabled),
			  conditions        = COALESCE($4, conditions),
			  requires_approval = COALESCE($5, requires_approval),
			  approver_spec     = COALESCE($6, approver_spec),
			  updated_at        = now()
			WHERE id = $1`,
			id, req.Name, req.Enabled, condArg, req.RequiresApproval, specArg)
		rowsAffected = tag.RowsAffected()
		return err
	})
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "update approval policy failed", err)
		return
	}
	if rowsAffected == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "policy not found"})
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{"id": id, "name": req.Name})
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "approval_policy_update", TargetType: "approval_policy", TargetID: &id,
		After: afterJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	w.WriteHeader(http.StatusNoContent)
}

// DeletePolicy implements DELETE /admin/approval-policies/{id}. Requires approvals.manage.
func (h *ApprovalsHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	id, ok := httputil.ParseIDPath(w, r, "id", "invalid policy id")
	if !ok {
		return
	}

	var rowsAffected int64
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM approval_policies WHERE id = $1`, id)
		rowsAffected = tag.RowsAffected()
		return err
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "P0001") {
			httputil.WriteProblem(w, r, httputil.NewConflictProblem("policy is referenced by existing approval requests"))
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "delete approval policy failed", err)
		return
	}
	if rowsAffected == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "policy not found"})
		return
	}

	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "approval_policy_delete", TargetType: "approval_policy", TargetID: &id,
		IP: httputil.ClientIP(r), Tier: "core",
	})

	w.WriteHeader(http.StatusNoContent)
}

// reorderRequest is the JSON body for POST /admin/approval-policies/reorder.
type reorderRequest struct {
	ConsumerType string  `json:"consumerType"`
	OrderedIDs   []int64 `json:"orderedIds"`
}

// ReorderPolicies implements POST /admin/approval-policies/reorder.
// Renumbers policies 1..N in the given order within the consumer_type.
// Uses two passes (negative then positive) to avoid UNIQUE constraint conflicts mid-renumber.
// Requires approvals.manage.
func (h *ApprovalsHandler) ReorderPolicies(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req reorderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if !validConsumerTypes[req.ConsumerType] {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid consumerType"})
		return
	}

	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		// Pass 1: set to negative to vacate the 1..N range (avoids UNIQUE violations).
		for i, pid := range req.OrderedIDs {
			if _, err := tx.Exec(ctx,
				`UPDATE approval_policies SET priority = $1 WHERE id = $2 AND consumer_type = $3`,
				-(i + 1), pid, req.ConsumerType); err != nil {
				return err
			}
		}
		// Pass 2: set to final positive values.
		for i, pid := range req.OrderedIDs {
			if _, err := tx.Exec(ctx,
				`UPDATE approval_policies SET priority = $1, updated_at = now() WHERE id = $2 AND consumer_type = $3`,
				i+1, pid, req.ConsumerType); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			httputil.WriteProblem(w, r, httputil.NewConflictProblem("priority conflict during reorder"))
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "reorder approval policies failed", err)
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{"consumerType": req.ConsumerType, "orderedIds": req.OrderedIDs})
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "approval_policy_reorder", TargetType: "approval_policy",
		After: afterJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	w.WriteHeader(http.StatusNoContent)
}

// ListAudit implements GET /admin/approval-requests/audit?limit=&offset=.
// Requires approvals.view or approvals.manage.
func (h *ApprovalsHandler) ListAudit(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireViewClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	limit, offset := httputil.ParseLimitOffset(r, 50, 500)

	// Domain-scoped admins (middleware.DomainScopeFromContext) see only their
	// domain's requests — mirrors admin_users.go's ListUsers domain scoping.
	// domainScope == 0 means a global (unscoped) admin → no extra predicate.
	// RLS is unchanged (an admin with approvals.view already passes row
	// visibility for every domain); this is an additional app-layer filter.
	domainScope := middleware.DomainScopeFromContext(ctx)
	query := `SELECT id, consumer_type, requester_user_id, subject, status,
			       approver_kind, approver_ref,
			       decided_by_user_id, decided_at::TEXT, decision_comment,
			       created_at::TEXT, expires_at::TEXT
			FROM approval_requests`
	args := []any{limit, offset}
	if domainScope > 0 {
		query += ` WHERE domain_id = $3`
		args = append(args, domainScope)
	}
	query += ` ORDER BY created_at DESC LIMIT $1 OFFSET $2`

	var out []approvalRequestAuditRow
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row approvalRequestAuditRow
			if err := rows.Scan(
				&row.ID, &row.ConsumerType, &row.RequesterUserID, &row.Subject, &row.Status,
				&row.ApproverKind, &row.ApproverRef,
				&row.DecidedByUserID, &row.DecidedAt, &row.DecisionComment,
				&row.CreatedAt, &row.ExpiresAt,
			); err != nil {
				return err
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list approval audit failed", err)
		return
	}
	if out == nil {
		out = []approvalRequestAuditRow{}
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// isJSONObject returns true when b is a non-null JSON object (starts with '{').
// ponytail: cheap whitespace-tolerant check, avoids full json.Unmarshal allocation.
func isJSONObject(b json.RawMessage) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		return c == '{'
	}
	return false
}
