package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

type TemplatesHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

func NewTemplatesHandler(pool *pgxpool.Pool, logger *slog.Logger) *TemplatesHandler {
	return &TemplatesHandler{pool: pool, logger: logger}
}

// List returns all visible templates for the caller.
// Admins see all; users see only enabled templates not hidden for them.
func (h *TemplatesHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.UserFromContext(ctx)
	var rows interface {
		Next() bool
		Scan(dest ...any) error
		Close()
		Err() error
	}
	var err error
	if claims != nil && !claims.IsAdmin {
		rows, err = h.pool.Query(ctx,
			`SELECT t.id, t.name, t.description, t.category, t.conditions, t.actions,
			        t.parameters, t.is_system, t.sort_order
			 FROM rule_templates t
			 WHERE t.enabled = TRUE
			   AND NOT EXISTS (
			     SELECT 1 FROM rule_template_visibility v
			     WHERE v.template_id = t.id AND v.user_id = $1 AND v.hidden = TRUE
			   )
			 ORDER BY t.category, t.sort_order`, claims.UserID)
	} else {
		rows, err = h.pool.Query(ctx,
			`SELECT t.id, t.name, t.description, t.category, t.conditions, t.actions,
			        t.parameters, t.is_system, t.sort_order
			 FROM rule_templates t
			 WHERE t.enabled = TRUE
			 ORDER BY t.category, t.sort_order`)
	}
	if err != nil {
		h.logger.Error("templates list query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	out := []map[string]interface{}{}
	for rows.Next() {
		var id int64
		var name, desc, category string
		var conditions, actions, parameters []byte
		var isSystem bool
		var sortOrder int
		if err := rows.Scan(&id, &name, &desc, &category, &conditions, &actions, &parameters, &isSystem, &sortOrder); err != nil {
			continue
		}
		out = append(out, map[string]interface{}{
			"id":          id,
			"name":        name,
			"description": desc,
			"category":    category,
			"conditions":  json.RawMessage(conditions),
			"actions":     json.RawMessage(actions),
			"parameters":  json.RawMessage(parameters),
			"isSystem":    isSystem,
			"sortOrder":   sortOrder,
		})
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

type templateRequest struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Category    string          `json:"category"`
	Conditions  json.RawMessage `json:"conditions"`
	Actions     json.RawMessage `json:"actions"`
	Parameters  json.RawMessage `json:"parameters"`
	Enabled     *bool           `json:"enabled"`
	SortOrder   *int            `json:"sortOrder"`
}

// Create adds a new template (admin only).
func (h *TemplatesHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req templateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var id int64
	err := h.pool.QueryRow(ctx,
		`INSERT INTO rule_templates (name, description, category, conditions, actions, parameters, sort_order)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		req.Name, req.Description, req.Category, req.Conditions, req.Actions, req.Parameters,
		coalesceInt(req.SortOrder, 0),
	).Scan(&id)
	if err != nil {
		h.logger.Error("template create failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// Get returns a single template.
func (h *TemplatesHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := strings.TrimPrefix(r.URL.Path, "/admin/rule-templates/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid template id")
		return
	}

	var name, desc, category string
	var conditions, actions, parameters []byte
	var isSystem, enabled bool
	var sortOrder int
	err = h.pool.QueryRow(ctx,
		`SELECT name, description, category, conditions, actions, parameters, is_system, enabled, sort_order
		 FROM rule_templates WHERE id = $1`, id,
	).Scan(&name, &desc, &category, &conditions, &actions, &parameters, &isSystem, &enabled, &sortOrder)
	if err != nil {
		httputil.WriteError(w, http.StatusNotFound, "template not found")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"id":          id,
		"name":        name,
		"description": desc,
		"category":    category,
		"conditions":  json.RawMessage(conditions),
		"actions":     json.RawMessage(actions),
		"parameters":  json.RawMessage(parameters),
		"isSystem":    isSystem,
		"enabled":     enabled,
		"sortOrder":   sortOrder,
	})
}

// Update modifies a template (admin only, system templates can only change enabled/sortOrder).
func (h *TemplatesHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := strings.TrimPrefix(r.URL.Path, "/admin/rule-templates/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid template id")
		return
	}

	var req templateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	ct, err := h.pool.Exec(ctx,
		`UPDATE rule_templates SET
			name = COALESCE(NULLIF($1,''), name),
			description = COALESCE($2, description),
			category = COALESCE(NULLIF($3,''), category),
			conditions = COALESCE($4, conditions),
			actions = COALESCE($5, actions),
			parameters = COALESCE($6, parameters),
			enabled = COALESCE($7, enabled),
			sort_order = COALESCE($8, sort_order),
			updated_at = now()
		 WHERE id = $9`,
		req.Name, req.Description, req.Category, req.Conditions, req.Actions, req.Parameters,
		req.Enabled, req.SortOrder, id,
	)
	if err != nil {
		h.logger.Error("template update failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if ct.RowsAffected() == 0 {
		httputil.WriteError(w, http.StatusNotFound, "template not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Delete removes a template (admin only, system templates cannot be deleted).
func (h *TemplatesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := strings.TrimPrefix(r.URL.Path, "/admin/rule-templates/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid template id")
		return
	}

	ct, err := h.pool.Exec(ctx,
		`DELETE FROM rule_templates WHERE id = $1 AND NOT is_system`, id,
	)
	if err != nil {
		h.logger.Error("template delete failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if ct.RowsAffected() == 0 {
		httputil.WriteError(w, http.StatusForbidden, "cannot delete system template or template not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SetVisibility controls per-user template visibility (admin only).
// POST /admin/rule-templates/{id}/visibility
// Body: {"userId": 42, "hidden": true}  — userId=null for global override
func (h *TemplatesHandler) SetVisibility(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := strings.TrimPrefix(r.URL.Path, "/admin/rule-templates/")
	idStr = strings.TrimSuffix(idStr, "/visibility")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid template id")
		return
	}

	var body struct {
		UserID *int64 `json:"userId"`
		Hidden bool   `json:"hidden"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if body.Hidden {
		_, err = h.pool.Exec(ctx,
			`INSERT INTO rule_template_visibility (template_id, user_id, hidden)
			 VALUES ($1, $2, TRUE)
			 ON CONFLICT (template_id, COALESCE(user_id, -1)) DO UPDATE SET hidden = TRUE`,
			id, body.UserID,
		)
	} else {
		if body.UserID != nil {
			_, err = h.pool.Exec(ctx,
				`DELETE FROM rule_template_visibility WHERE template_id = $1 AND user_id = $2`,
				id, *body.UserID,
			)
		} else {
			_, err = h.pool.Exec(ctx,
				`DELETE FROM rule_template_visibility WHERE template_id = $1 AND user_id IS NULL`,
				id,
			)
		}
	}
	if err != nil {
		h.logger.Error("template visibility update failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetVisibility returns visibility overrides for a template.
func (h *TemplatesHandler) GetVisibility(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := strings.TrimPrefix(r.URL.Path, "/admin/rule-templates/")
	idStr = strings.TrimSuffix(idStr, "/visibility")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid template id")
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT user_id, hidden FROM rule_template_visibility WHERE template_id = $1`, id,
	)
	if err != nil {
		h.logger.Error("template visibility query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	out := []map[string]interface{}{}
	for rows.Next() {
		var uid *int64
		var hidden bool
		if err := rows.Scan(&uid, &hidden); err != nil {
			continue
		}
		out = append(out, map[string]interface{}{
			"userId": uid,
			"hidden": hidden,
		})
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// TemplateFromID resolves a template and its parameters for rule creation.
// GET /admin/rule-templates/{id}/resolve
func (h *TemplatesHandler) Resolve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := strings.TrimPrefix(r.URL.Path, "/admin/rule-templates/")
	idStr = strings.TrimSuffix(idStr, "/resolve")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid template id")
		return
	}

	var name, category string
	var conditions, actions, parameters []byte
	err = h.pool.QueryRow(ctx,
		`SELECT name, category, conditions, actions, parameters FROM rule_templates WHERE id = $1 AND enabled = TRUE`,
		id,
	).Scan(&name, &category, &conditions, &actions, &parameters)
	if err != nil {
		httputil.WriteError(w, http.StatusNotFound, "template not found")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"id":         id,
		"name":       name,
		"category":   category,
		"conditions": json.RawMessage(conditions),
		"actions":    json.RawMessage(actions),
		"parameters": json.RawMessage(parameters),
	})
}

func coalesceInt(p *int, defaultVal int) int {
	if p == nil {
		return defaultVal
	}
	return *p
}
