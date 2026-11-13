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

// AuthMethodsHandler provides read/write access to auth_methods configuration.
type AuthMethodsHandler struct {
	pool   *pgxpool.Pool
	chain  *auth.Chain
	logger *slog.Logger
}

// NewAuthMethodsHandler creates an auth methods admin handler.
func NewAuthMethodsHandler(pool *pgxpool.Pool, chain *auth.Chain, logger *slog.Logger) *AuthMethodsHandler {
	return &AuthMethodsHandler{pool: pool, chain: chain, logger: logger}
}

type authMethodResponse struct {
	Slug       string          `json:"slug"`
	Name       string          `json:"name"`
	Enabled    bool            `json:"enabled"`
	Priority   int             `json:"priority"`
	ConfigJSON json.RawMessage `json:"config,omitempty"`
}

// List returns all auth methods ordered by priority.
func (h *AuthMethodsHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rows, err := h.pool.Query(ctx,
		`SELECT slug, name, enabled, priority, config_json FROM auth_methods ORDER BY priority ASC`)
	if err != nil {
		h.logger.Error("admin auth methods list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	out := []authMethodResponse{}
	for rows.Next() {
		var m authMethodResponse
		if err := rows.Scan(&m.Slug, &m.Name, &m.Enabled, &m.Priority, &m.ConfigJSON); err != nil {
			continue
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("admin auth methods list rows error", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// Update patches an auth method's enabled flag, priority, and config.
func (h *AuthMethodsHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	slug := r.PathValue("slug")
	var req struct {
		Enabled    *bool           `json:"enabled,omitempty"`
		Priority   *int            `json:"priority,omitempty"`
		ConfigJSON json.RawMessage `json:"config,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var sets []string
	var args []any
	argIdx := 1

	if req.Enabled != nil {
		sets = append(sets, "enabled = $"+strconv.Itoa(argIdx))
		args = append(args, *req.Enabled)
		argIdx++
	}
	if req.Priority != nil {
		sets = append(sets, "priority = $"+strconv.Itoa(argIdx))
		args = append(args, *req.Priority)
		argIdx++
	}
	if len(req.ConfigJSON) > 0 {
		sets = append(sets, "config_json = $"+strconv.Itoa(argIdx))
		args = append(args, req.ConfigJSON)
		argIdx++
	}

	if len(sets) == 0 {
		httputil.WriteError(w, http.StatusBadRequest, "no fields to update")
		return
	}

	args = append(args, slug)
	query := "UPDATE auth_methods SET " + strings.Join(sets, ", ") + " WHERE slug = $" + strconv.Itoa(argIdx)
	tag, err := h.pool.Exec(ctx, query, args...)
	if err != nil {
		h.logger.Error("admin auth method update failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteError(w, http.StatusNotFound, "auth method not found")
		return
	}

	if err := h.chain.ReloadMethods(ctx); err != nil {
		h.logger.Error("auth chain reload failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "auth reload failed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
