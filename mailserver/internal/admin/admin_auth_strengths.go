// Admin CRUD API for CA auth strengths.
//
// Routes (registered in main.go):
//
//	GET    /admin/conditional-access/auth-strengths       — List all (built-in + custom)
//	POST   /admin/conditional-access/auth-strengths       — Create custom strength
//	PUT    /admin/conditional-access/auth-strengths/{id}  — Update custom strength
//	DELETE /admin/conditional-access/auth-strengths/{id}  — Delete custom (built-in → 400)
//
// All mutating routes: requireCAPolicyWrite (access.policy_write).
// Read routes: requireCAPolicyRead (access.policy_read).
package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// AuthStrengthsHandler provides CRUD access to auth_strengths.
type AuthStrengthsHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewAuthStrengthsHandler creates an auth-strengths admin handler.
func NewAuthStrengthsHandler(pool *pgxpool.Pool, logger *slog.Logger) *AuthStrengthsHandler {
	return &AuthStrengthsHandler{pool: pool, logger: logger}
}

// authStrengthRequest is the create/update request body.
type authStrengthRequest struct {
	Slug         string          `json:"slug"`
	Name         string          `json:"name"`
	Combinations json.RawMessage `json:"combinations,omitempty"` // jsonb array of arrays
	MinACR       string          `json:"min_acr,omitempty"`
}

// List returns all auth_strengths (built-in + custom), ordered by name.
func (h *AuthStrengthsHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rows, err := h.pool.Query(ctx,
		`SELECT id, slug, name, description, requirement, min_acr, builtin, created_at, updated_at
		 FROM auth_strengths ORDER BY builtin DESC, name ASC`)
	if err != nil {
		h.logger.Error("auth-strengths list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	out := make([]map[string]any, 0)
	for rows.Next() {
		var id int64
		var builtin bool
		var slug, name, desc, minACR string
		var requirement []byte
		var createdAt, updatedAt interface{}
		if err := rows.Scan(&id, &slug, &name, &desc, &requirement, &minACR, &builtin,
			&createdAt, &updatedAt); err != nil {
			h.logger.Warn("auth-strengths list scan failed", "error", err)
			continue
		}
		out = append(out, map[string]any{
			"id":          id,
			"slug":        slug,
			"name":        name,
			"description": desc,
			"requirement": json.RawMessage(requirement),
			"min_acr":     minACR,
			"builtin":     builtin,
			"created_at":  createdAt,
			"updated_at":  updatedAt,
		})
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("auth-strengths list rows error", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// Create inserts a new custom auth_strength via ca_auth_strength_set.
func (h *AuthStrengthsHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)

	var req authStrengthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Slug == "" {
		httputil.WriteError(w, http.StatusBadRequest, "slug is required")
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

	var combinations json.RawMessage
	if len(req.Combinations) > 0 {
		combinations = req.Combinations
	}

	var id int64
	err := h.pool.QueryRow(ctx,
		`SELECT ca_auth_strength_set($1, $2, $3, $4::jsonb, $5, false, $6, $7::inet)`,
		int64(0), req.Slug, req.Name, combinations, req.MinACR,
		claims.UserID, httputil.ClientIP(r),
	).Scan(&id)
	if err != nil {
		h.logger.Error("auth-strength create failed", "error", err)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"id": id})
}

// Update modifies an existing custom auth_strength via ca_auth_strength_set.
func (h *AuthStrengthsHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)

	id, err := parsePathID(r, "id")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid strength ID")
		return
	}

	var req authStrengthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var combinations json.RawMessage
	if len(req.Combinations) > 0 {
		combinations = req.Combinations
	}

	var out int64
	err = h.pool.QueryRow(ctx,
		`SELECT ca_auth_strength_set($1, $2, $3, $4::jsonb, $5, false, $6, $7::inet)`,
		id, req.Slug, req.Name, combinations, req.MinACR,
		claims.UserID, httputil.ClientIP(r),
	).Scan(&out)
	if err != nil {
		h.logger.Error("auth-strength update failed", "error", err, "id", id)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"id": out})
}

// Delete calls ca_auth_strength_set(p_deleted=true). The reducer raises a plain
// EXCEPTION (no BZ code) for built-in rows; caAuthStrengthErrorStatus maps that → 400.
func (h *AuthStrengthsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := parsePathID(r, "id")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid strength ID")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	_, err = h.pool.Exec(ctx,
		`SELECT ca_auth_strength_set($1, NULL, NULL, NULL, NULL, true, $2, $3::inet)`,
		id, claims.UserID, httputil.ClientIP(r),
	)
	if err != nil {
		h.logger.Error("auth-strength delete failed", "error", err, "id", id)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
