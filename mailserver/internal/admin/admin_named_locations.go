// Admin CRUD + Restore API for CA named locations.
//
// Routes (registered in main.go):
//
//	GET    /admin/conditional-access/named-locations                 — List (active; ?include_deleted=1 for all)
//	POST   /admin/conditional-access/named-locations                 — Create
//	PUT    /admin/conditional-access/named-locations/{id}            — Update
//	DELETE /admin/conditional-access/named-locations/{id}            — Soft-delete
//	POST   /admin/conditional-access/named-locations/{id}/restore    — Un-delete
//
// All mutating routes: requireCAPolicyWrite (access.policy_write).
// Read routes: requireCAPolicyRead (access.policy_read).
package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// NamedLocationsHandler provides CRUD access to named_locations.
type NamedLocationsHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewNamedLocationsHandler creates a named-locations admin handler.
func NewNamedLocationsHandler(pool *pgxpool.Pool, logger *slog.Logger) *NamedLocationsHandler {
	return &NamedLocationsHandler{pool: pool, logger: logger}
}

// namedLocationRequest is the create/update request body.
type namedLocationRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	CIDRs       []string `json:"cidrs,omitempty"`
	Countries   []string `json:"countries,omitempty"`
	IsTrusted   bool     `json:"is_trusted,omitempty"`
}

// List returns all named_locations (active by default; ?include_deleted=1 includes tombstoned rows).
func (h *NamedLocationsHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	includeDel := r.URL.Query().Get("include_deleted") == "1"

	query := `SELECT id, name, description, ip_ranges, countries, is_trusted,
		created_at, updated_at, deleted_at FROM named_locations`
	if !includeDel {
		query += ` WHERE deleted_at IS NULL`
	}
	query += ` ORDER BY name ASC`

	rows, err := h.pool.Query(ctx, query)
	if err != nil {
		h.logger.Error("named-locations list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	out := make([]map[string]any, 0)
	for rows.Next() {
		var id int64
		var isTrusted bool
		var name, desc string
		var ipRanges, countries []byte
		var createdAt, updatedAt interface{}
		var deletedAt interface{}
		if err := rows.Scan(&id, &name, &desc, &ipRanges, &countries, &isTrusted,
			&createdAt, &updatedAt, &deletedAt); err != nil {
			h.logger.Warn("named-locations list scan failed", "error", err)
			continue
		}
		out = append(out, map[string]any{
			"id":          id,
			"name":        name,
			"description": desc,
			"ip_ranges":   json.RawMessage(ipRanges),
			"countries":   json.RawMessage(countries),
			"is_trusted":  isTrusted,
			"created_at":  createdAt,
			"updated_at":  updatedAt,
			"deleted_at":  deletedAt,
		})
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("named-locations list rows error", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// Create inserts a new named_location via ca_named_location_set.
func (h *NamedLocationsHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)

	var req namedLocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Name == "" {
		httputil.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	cidrs := nilSliceIfEmpty(req.CIDRs)
	countries := nilSliceIfEmpty(req.Countries)

	var id int64
	err := h.pool.QueryRow(ctx,
		`SELECT ca_named_location_set($1, $2, $3, $4::cidr[], $5::text[], $6, false, $7, $8::inet)`,
		int64(0), req.Name, req.Description, cidrs, countries, req.IsTrusted,
		claims.UserID, httputil.ClientIP(r),
	).Scan(&id)
	if err != nil {
		h.logger.Error("named-location create failed", "error", err)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"id": id})
}

// Update modifies an existing named_location via ca_named_location_set.
func (h *NamedLocationsHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)

	id, err := parsePathID(r, "id")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid location ID")
		return
	}

	var req namedLocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Name == "" {
		httputil.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	cidrs := nilSliceIfEmpty(req.CIDRs)
	countries := nilSliceIfEmpty(req.Countries)

	var out int64
	err = h.pool.QueryRow(ctx,
		`SELECT ca_named_location_set($1, $2, $3, $4::cidr[], $5::text[], $6, false, $7, $8::inet)`,
		id, req.Name, req.Description, cidrs, countries, req.IsTrusted,
		claims.UserID, httputil.ClientIP(r),
	).Scan(&out)
	if err != nil {
		h.logger.Error("named-location update failed", "error", err, "id", id)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"id": out})
}

// Delete soft-deletes a named_location via ca_named_location_set(p_deleted=true).
func (h *NamedLocationsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := parsePathID(r, "id")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid location ID")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// p_deleted=true; name/cidrs/countries/trusted are ignored on the delete path.
	_, err = h.pool.Exec(ctx,
		`SELECT ca_named_location_set($1, NULL, NULL, NULL, NULL, NULL, true, $2, $3::inet)`,
		id, claims.UserID, httputil.ClientIP(r),
	)
	if err != nil {
		h.logger.Error("named-location delete failed", "error", err, "id", id)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Restore un-deletes a named_location via ca_named_location_restore.
// The reducer does a single UPDATE ... WHERE deleted_at IS NOT NULL (R3, no TOCTOU),
// writes the audit log in-txn (finding 4 fix), and maps 23505 → BZ093 → 409 (finding 3 fix).
func (h *NamedLocationsHandler) Restore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := parsePathID(r, "id")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid location ID")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var out int64
	err = h.pool.QueryRow(ctx,
		`SELECT ca_named_location_restore($1, $2, $3::inet)`,
		id, claims.UserID, httputil.ClientIP(r),
	).Scan(&out)
	if err != nil {
		h.logger.Error("named-location restore failed", "error", err, "id", id)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"id": out})
}

// parsePathID extracts and parses an int64 path variable.
func parsePathID(r *http.Request, key string) (int64, error) {
	return strconv.ParseInt(r.PathValue(key), 10, 64)
}

// nilSliceIfEmpty returns nil for an empty slice so pgx sends NULL to the reducer.
// The reducer treats NULL arrays as empty (COALESCE in ca_named_location_set).
// ponytail: named differently from the string-nilIfEmpty in admin_email_address_policy.go
// to avoid a redeclaration in the same package.
func nilSliceIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
