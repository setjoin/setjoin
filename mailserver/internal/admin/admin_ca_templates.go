// Admin API for CA policy templates.
//
// Routes (registered in main.go):
//
//	GET  /admin/conditional-access/templates                    — List all templates
//	POST /admin/conditional-access/templates/{slug}/instantiate — Instantiate a template
//
// List: requireCAPolicyRead. Instantiate: requireCAPolicyWrite.
package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// CATemplatesHandler provides the templates catalog and instantiate endpoint.
type CATemplatesHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewCATemplatesHandler creates a CA templates admin handler.
func NewCATemplatesHandler(pool *pgxpool.Pool, logger *slog.Logger) *CATemplatesHandler {
	return &CATemplatesHandler{pool: pool, logger: logger}
}

// List returns all rows from ca_templates ordered by suggested_priority.
// Gated: requireCAPolicyRead at the route.
func (h *CATemplatesHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rows, err := h.pool.Query(ctx,
		`SELECT id, slug, name, description, scope_type, scope_target,
		        conditions, actions, suggested_priority, created_at::text
		 FROM ca_templates ORDER BY suggested_priority ASC`)
	if err != nil {
		h.logger.Error("ca_templates list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	out := make([]map[string]any, 0)
	for rows.Next() {
		var id int64
		var slug, name, desc, scopeType, scopeTarget, createdAt string
		var suggestedPriority int
		var conditions, actions []byte
		if err := rows.Scan(&id, &slug, &name, &desc, &scopeType, &scopeTarget,
			&conditions, &actions, &suggestedPriority, &createdAt); err != nil {
			h.logger.Warn("ca_templates list scan failed", "error", err)
			continue
		}
		out = append(out, map[string]any{
			"id":                 id,
			"slug":               slug,
			"name":               name,
			"description":        desc,
			"scope_type":         scopeType,
			"scope_target":       scopeTarget,
			"conditions":         json.RawMessage(conditions),
			"actions":            json.RawMessage(actions),
			"suggested_priority": suggestedPriority,
			"created_at":         createdAt,
		})
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("ca_templates list rows error", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// Instantiate calls ca_template_instantiate(p_slug, p_admin_id) and returns
// the newly-created policy row (born in report_only with the admin auto-excluded).
// BZ085 (unknown slug) → 400. Gated: requireCAPolicyWrite at the route.
func (h *CATemplatesHandler) Instantiate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	slug := r.PathValue("slug")
	if slug == "" {
		httputil.WriteError(w, http.StatusBadRequest, "slug is required")
		return
	}

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Call the reducer; it owns the atomic write + audit + ca_notify_policy_change.
	var newID int64
	err := h.pool.QueryRow(ctx,
		`SELECT ca_template_instantiate($1, $2)`,
		slug, claims.UserID,
	).Scan(&newID)
	if err != nil {
		h.logger.Error("ca_template_instantiate failed", "error", err, "slug", slug)
		// ponytail: BZ085 is "unknown slug" — bad input → 400; delegate all others to caErrorStatus.
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	// Read back the new policy row so the response includes state + exclude_users
	// (the UI needs them immediately without a second round-trip).
	var out []byte
	err = h.pool.QueryRow(ctx,
		`SELECT to_jsonb(c) - 'enabled'
		 FROM conditional_access_policies c WHERE id = $1`, newID,
	).Scan(&out)
	if err != nil {
		h.logger.Error("ca_template_instantiate readback failed", "error", err, "id", newID)
		httputil.WriteError(w, http.StatusInternalServerError, "policy created but read failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(out)
}
