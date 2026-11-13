// Admin API: CA coverage report endpoint (CA-1 D7).
//
// Routes (registered in main.go):
//
//	GET /admin/conditional-access/coverage
//
// Calls ca_coverage_report() (C7) and passes the JSONB result through.
// Returns {gaps:[{kind,detail,severity}], shadowed:[{...}]} — always arrays (never null).
// Read-only — no audit / no notify. Gated: requireCAPolicyRead at the route.
package admin

import (
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/httputil"
)

// CACoverageHandler provides the CA coverage report endpoint.
type CACoverageHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewCACoverageHandler creates a CACoverageHandler.
func NewCACoverageHandler(pool *pgxpool.Pool, logger *slog.Logger) *CACoverageHandler {
	return &CACoverageHandler{pool: pool, logger: logger}
}

// Coverage calls ca_coverage_report() and passes the JSONB result through.
// Returns {gaps:[{kind,detail,severity}], shadowed:[{...}]}.
// Gated: requireCAPolicyRead at the route.
func (h *CACoverageHandler) Coverage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ponytail: ca_coverage_report() owns all logic (gap check + shadow detector);
	// reducer guarantees COALESCE([]::jsonb) so result is never null.
	var out []byte
	if err := h.pool.QueryRow(ctx, `SELECT ca_coverage_report()`).Scan(&out); err != nil {
		h.logger.Error("ca_coverage_report failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}
