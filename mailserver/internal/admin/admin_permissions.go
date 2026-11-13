package admin

import (
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
)

// PermissionsHandler serves the static catalog of admin permissions so the UI
// can render the role permission picker without re-typing the 21 keys.
type PermissionsHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewPermissionsHandler creates a permissions catalog handler.
func NewPermissionsHandler(pool *pgxpool.Pool, logger *slog.Logger) *PermissionsHandler {
	return &PermissionsHandler{pool: pool, logger: logger}
}

type permissionCatalogEntry struct {
	Key         string `json:"key"`
	Category    string `json:"category"`
	Description string `json:"description"`
	IsSensitive bool   `json:"isSensitive"`
}

// List returns every row of admin_permissions, ordered by category then key.
func (h *PermissionsHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT permission_key, category, description, is_sensitive
		 FROM admin_permissions ORDER BY category COLLATE "C", permission_key COLLATE "C"`)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list permissions failed", err)
		return
	}
	defer rows.Close()

	out := []permissionCatalogEntry{}
	for rows.Next() {
		var e permissionCatalogEntry
		if err := rows.Scan(&e.Key, &e.Category, &e.Description, &e.IsSensitive); err != nil {
			h.logger.Warn("list permissions scan error", "error", err)
			continue
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list permissions rows error", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}
