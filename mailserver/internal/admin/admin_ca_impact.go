// Admin API: Policy impact read endpoint.
//
// Routes (registered in main.go):
//
//	GET /admin/conditional-access/policies/{id}/impact?window=<24h|7d|30d>[&list=blocked_users]
//
// Calls the ca_policy_impact reducer (C4) and passes through its JSONB result.
// Read-only — no audit / no notify. Gated: requireCAPolicyRead at the route.
package admin

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/httputil"
)

// CAImpactHandler provides the policy impact read endpoint.
type CAImpactHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewCAImpactHandler creates a CAImpactHandler.
func NewCAImpactHandler(pool *pgxpool.Pool, logger *slog.Logger) *CAImpactHandler {
	return &CAImpactHandler{pool: pool, logger: logger}
}

// Impact calls ca_policy_impact(p_policy_id, p_window, p_list) and passes the JSONB result through.
//
// Query params:
//   - window=<24h|7d|30d>  — required; 22023 from reducer → 400
//   - list=blocked_users   — optional; absent → summary shape
//
// Response shapes (from reducer):
//   - summary:       {window, window_has_data, matched, would_block, would_step_up, would_notify, distinct_users, would_block_admins}
//   - blocked_users: {users:[{id,address,is_admin}], shown, total, admin_users:[{id,address}]}
//
// Gated: requireCAPolicyRead at the route.
func (h *CAImpactHandler) Impact(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policyID, err := parsePathID(r, "id")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	q := r.URL.Query()
	window := q.Get("window")
	if window == "" {
		window = "7d" // ponytail: sensible default matching the Promote handler.
	}
	listParam := q.Get("list") // empty → NULL → summary; 'blocked_users' → user list.
	var listArg *string
	if listParam != "" {
		listArg = &listParam
	}

	// Call the C4 reducer; it owns all logic (window parsing, no-data detection, admin flagging).
	var out []byte
	err = h.pool.QueryRow(ctx,
		`SELECT ca_policy_impact($1, $2, $3)`,
		policyID, window, listArg,
	).Scan(&out)
	if err != nil {
		h.logger.Error("ca_policy_impact failed", "error", err, "id", policyID, "window", window)
		httputil.WriteError(w, caImpactErrorStatus(err), caErrorDetail(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// caImpactErrorStatus maps ca_policy_impact errors to HTTP status codes.
// Extends caErrorStatus with 22023 (invalid_parameter_value) → 400 for bad window/list params
// (ca_policy_impact is read-only and uses standard PG error codes, not BZ codes).
func caImpactErrorStatus(err error) int {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "22023" {
		return http.StatusBadRequest
	}
	return caErrorStatus(err)
}
