package admin

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// IPRulesHandler serves the CRUD API for admin-managed IP allow/block rules.
// Routes:
//
//	GET    /admin/threat/ip-rules        — List (audit.read)
//	POST   /admin/threat/ip-rules        — Create (security.write)
//	DELETE /admin/threat/ip-rules/{id}   — Delete (security.write)
type IPRulesHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewIPRulesHandler constructs an IPRulesHandler backed by the provided pool.
// pool may be nil in unit tests.
func NewIPRulesHandler(pool *pgxpool.Pool, logger *slog.Logger) *IPRulesHandler {
	return &IPRulesHandler{pool: pool, logger: logger}
}

// ipRuleRow is the JSON shape returned for each ip_rules row.
type ipRuleRow struct {
	ID          int64   `json:"id"`
	CIDR        string  `json:"cidr"`
	Action      string  `json:"action"`
	Description string  `json:"description"`
	ExpiresAt   *string `json:"expiresAt"`
	CreatedAt   string  `json:"createdAt"`
	CreatedBy   *int64  `json:"createdBy"`
}

// ipRuleCreateRequest is the JSON body for POST /admin/threat/ip-rules.
// created_by is intentionally absent — it is always taken from the auth context.
type ipRuleCreateRequest struct {
	CIDR        string  `json:"cidr"`
	Action      string  `json:"action"`
	Description string  `json:"description"`
	ExpiresAt   *string `json:"expiresAt"`
}

// List handles GET /admin/threat/ip-rules.
// Returns {rows:[...], total, limit, offset} matching the M1 Table contract.
// Pagination: limit (default 100, max 500), offset (default 0).
func (h *IPRulesHandler) List(w http.ResponseWriter, r *http.Request) {
	const defaultLimit = 100
	const maxLimit = 500

	q := r.URL.Query()
	limit, err := strconv.Atoi(q.Get("limit"))
	if err != nil || limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	offset, err := strconv.Atoi(q.Get("offset"))
	if err != nil || offset < 0 {
		offset = 0
	}

	if h.pool == nil {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"rows":   []ipRuleRow{},
			"total":  0,
			"limit":  limit,
			"offset": offset,
		})
		return
	}

	ctx := r.Context()

	var total int
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ip_rules`).Scan(&total); err != nil {
		h.logError("ip_rules count", err)
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT id, cidr::text, action, description,
		        to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		        to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		        created_by
		 FROM ip_rules
		 ORDER BY created_at DESC
		 LIMIT $1 OFFSET $2`,
		limit, offset)
	if err != nil {
		h.logError("ip_rules list query", err)
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}
	defer rows.Close()

	out := make([]ipRuleRow, 0)
	for rows.Next() {
		var row ipRuleRow
		if err := rows.Scan(&row.ID, &row.CIDR, &row.Action, &row.Description,
			&row.ExpiresAt, &row.CreatedAt, &row.CreatedBy); err != nil {
			h.logError("ip_rules scan", err)
			continue
		}
		out = append(out, row)
	}
	if rows.Err() != nil {
		h.logError("ip_rules rows iteration", rows.Err())
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"rows":   out,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// Create handles POST /admin/threat/ip-rules.
// Validates CIDR (net/netip) and action ∈ {allow,block}; takes created_by from
// the auth context (never the request body — R2).
// Writes an admin_audit_log row on success.
func (h *IPRulesHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req ipRuleCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest,
			Detail: "request body must be JSON with cidr, action, and description fields",
		})
		return
	}

	// Validate CIDR using net/netip — rejects any malformed input.
	if _, err := netip.ParsePrefix(req.CIDR); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest,
			Detail: fmt.Sprintf("invalid CIDR %q: %v", req.CIDR, err),
		})
		return
	}

	// Validate action — only allow and block are permitted.
	if req.Action != "allow" && req.Action != "block" {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest,
			Detail: fmt.Sprintf("action must be 'allow' or 'block', got %q", req.Action),
		})
		return
	}

	if req.Description == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest,
			Detail: "description is required",
		})
		return
	}

	// R2: created_by always comes from the auth context, never the request body.
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}
	createdBy := claims.UserID

	if h.pool == nil {
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}

	ctx := r.Context()

	var id int64
	err := h.pool.QueryRow(ctx,
		`INSERT INTO ip_rules (cidr, action, description, expires_at, created_by)
		 VALUES ($1::inet, $2, $3, $4, $5)
		 RETURNING id`,
		req.CIDR, req.Action, req.Description, req.ExpiresAt, createdBy,
	).Scan(&id)
	if err != nil {
		h.logError("ip_rules insert", err)
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}

	// Write audit log — best-effort, never fail the request.
	ipCreateJSON, _ := json.Marshal(map[string]string{"cidr": req.CIDR, "action_value": req.Action, "description": req.Description})
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: createdBy, Action: "ip_rule_create", TargetType: "ip_rule", TargetID: &id,
		Before: ipCreateJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	httputil.WriteJSON(w, http.StatusCreated, map[string]any{
		"id": id,
	})
}

// Delete handles DELETE /admin/threat/ip-rules/{id}.
// Requires a numeric {id}; writes an admin_audit_log row on successful deletion.
func (h *IPRulesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest,
			Detail: "id must be a positive integer",
		})
		return
	}

	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	if h.pool == nil {
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}

	ctx := r.Context()

	// Capture existing row data for audit before deletion.
	var cidr, action string
	_ = h.pool.QueryRow(ctx,
		`SELECT cidr::text, action FROM ip_rules WHERE id = $1`, id).
		Scan(&cidr, &action)

	tag, err := h.pool.Exec(ctx, `DELETE FROM ip_rules WHERE id = $1`, id)
	if err != nil {
		h.logError("ip_rules delete", err)
		httputil.WriteProblem(w, r, httputil.NewInternalProblem())
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteProblem(w, r, httputil.NewNotFoundProblem(
			fmt.Sprintf("ip_rule %d not found", id)))
		return
	}

	// Write audit log — best-effort.
	ipDeleteJSON, _ := json.Marshal(map[string]string{"cidr": cidr, "action_value": action})
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "ip_rule_delete", TargetType: "ip_rule", TargetID: &id,
		Before: ipDeleteJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	w.WriteHeader(http.StatusNoContent)
}

// logError logs an error; silently ignores a nil logger.
func (h *IPRulesHandler) logError(msg string, err error) {
	if h.logger != nil {
		h.logger.Error(msg, "error", err)
	}
}
