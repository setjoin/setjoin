package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

// JITHandler serves the self-service JIT activation endpoints and the admin
// activation-policy CRUD.  Self-service routes are gated requireAuth only
// (the actor is always the authenticated user); policy CRUD is gated
// requireRolesManage.
type JITHandler struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	toggles *toggle.FeatureFlags
}

// NewJITHandler creates a JITHandler.
func NewJITHandler(pool *pgxpool.Pool, logger *slog.Logger, toggles *toggle.FeatureFlags) *JITHandler {
	return &JITHandler{pool: pool, logger: logger, toggles: toggles}
}

// mapJITErr maps reducer business errors from admin_role_activate to HTTP
// problems via the shared reducererr.WriteClassified (arch #A1): BZ104/BZ105
// classify to ClassInvalidArguments → 400 with the reducer message passed
// through (the Detail allowlist). Returns true if the error was handled;
// false if the caller must handle it (unclassified → its 500 fallback).
func (h *JITHandler) mapJITErr(w http.ResponseWriter, r *http.Request, err error) bool {
	return reducererr.WriteClassified(w, r, err)
}

// Activate implements POST /admin/me/roles/{id}/activate
// Actor is always the authenticated caller (claims.UserID — never the request body).
// On success returns {activatedUntil, tokenRefreshRequired?}.
// D6 cold-start: if the live token carries IsAdmin=false (minted before the
// eligible assignment existed), include tokenRefreshRequired:true so the webmail
// refreshes the token and re-derives is_admin=true.
func (h *JITHandler) Activate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	roleID, ok := httputil.ParseIDPath(w, r, "id", "invalid role id")
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req struct {
		DurationMinutes int     `json:"durationMinutes"`
		Justification   *string `json:"justification,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.DurationMinutes <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "durationMinutes must be positive"})
		return
	}

	// Pass nil justification when absent/empty; the reducer checks require_justification.
	var justification *string
	if req.Justification != nil && *req.Justification != "" {
		justification = req.Justification
	}

	// actor is always claims.UserID (self-service — DATABASE_SECURITY R2/R3).
	var activatedUntil time.Time
	err := h.pool.QueryRow(ctx,
		`SELECT admin_role_activate($1, $2, $3, $4)`,
		claims.UserID, roleID, req.DurationMinutes, justification,
	).Scan(&activatedUntil)
	if err != nil {
		if h.mapJITErr(w, r, err) {
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "admin_role_activate failed", err)
		return
	}

	resp := map[string]any{"activatedUntil": activatedUntil}
	// D6 cold-start: the token predates the eligible assignment; webmail must refresh.
	if !claims.IsAdmin {
		resp["tokenRefreshRequired"] = true
	}
	httputil.WriteJSON(w, http.StatusOK, resp)
}

// Deactivate implements POST /admin/me/roles/{id}/deactivate
// Ends the caller's active window early (NULLs activated_until).
func (h *JITHandler) Deactivate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	roleID, ok := httputil.ParseIDPath(w, r, "id", "invalid role id")
	if !ok {
		return
	}

	if _, err := h.pool.Exec(ctx,
		`SELECT admin_role_deactivate($1, $2)`, claims.UserID, roleID); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "admin_role_deactivate failed", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{})
}

// jitMyRole is the per-row shape returned by ListMyRoles.
type jitMyRole struct {
	RoleGroupID    int64      `json:"roleGroupId"`
	Name           string     `json:"name"`
	Eligible       bool       `json:"eligible"`
	ActivatedUntil *time.Time `json:"activatedUntil,omitempty"`
	ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
	Policy         struct {
		MaxDurationMinutes   int  `json:"maxDurationMinutes"`
		RequireJustification bool `json:"requireJustification"`
	} `json:"policy"`
}

// ListMyRoles implements GET /admin/me/roles
// Returns all the caller's admin_role_assignments with their eligible/activated_until
// state and the resolved per-role policy (override else global default).
//
// ponytail: no expires_at active-filter — self-service list shows ALL the caller's
// assignments (eligible+dormant+expired). The JIT coverage guard only fires on the
// "expires_at IS NULL OR expires_at > now()" active-filter pattern; omitting it here
// is deliberate (this is the activation UI, not an enforcement gate).
func (h *JITHandler) ListMyRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT
			ara.role_group_id,
			rg.name,
			ara.eligible,
			ara.activated_until,
			ara.expires_at,
			COALESCE(arp.max_duration_minutes,
			         (SELECT (value ->> 0)::int  FROM system_config WHERE key = 'jit.default_max_minutes'),
			         480)     AS max_duration_minutes,
			COALESCE(arp.require_justification,
			         (SELECT (value ->> 0)::bool FROM system_config WHERE key = 'jit.default_require_justification'),
			         false)   AS require_justification
		FROM   admin_role_assignments   ara
		JOIN   admin_role_groups        rg  ON rg.id = ara.role_group_id
		LEFT JOIN admin_role_activation_policy arp ON arp.role_group_id = ara.role_group_id
		WHERE  ara.user_id = $1
		ORDER  BY rg.name`, claims.UserID)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "ListMyRoles query failed", err)
		return
	}
	defer rows.Close()

	result := []jitMyRole{}
	for rows.Next() {
		var mr jitMyRole
		if err := rows.Scan(
			&mr.RoleGroupID, &mr.Name, &mr.Eligible,
			&mr.ActivatedUntil, &mr.ExpiresAt,
			&mr.Policy.MaxDurationMinutes, &mr.Policy.RequireJustification,
		); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "ListMyRoles scan failed", err)
			return
		}
		result = append(result, mr)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "ListMyRoles rows.Err", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, result)
}

// jitPolicy is the shape for activation policy read/write.
type jitPolicy struct {
	RoleGroupID          int64 `json:"roleGroupId"`
	MaxDurationMinutes   int   `json:"maxDurationMinutes"`
	RequireJustification bool  `json:"requireJustification"`
}

// GetActivationPolicy implements GET /admin/roles/{id}/activation-policy
// Returns the per-role override if one exists, else the resolved global defaults.
func (h *JITHandler) GetActivationPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	roleID, ok := httputil.ParseIDPath(w, r, "id", "invalid role id")
	if !ok {
		return
	}

	var p jitPolicy
	p.RoleGroupID = roleID
	err := h.pool.QueryRow(ctx,
		`SELECT max_duration_minutes, require_justification
		 FROM admin_role_activation_policy WHERE role_group_id = $1`, roleID,
	).Scan(&p.MaxDurationMinutes, &p.RequireJustification)
	if err == pgx.ErrNoRows {
		// Return resolved global defaults.
		if err2 := h.pool.QueryRow(ctx,
			`SELECT COALESCE((SELECT (value->>0)::int  FROM system_config WHERE key='jit.default_max_minutes'), 480),
			        COALESCE((SELECT (value->>0)::bool FROM system_config WHERE key='jit.default_require_justification'), false)`,
		).Scan(&p.MaxDurationMinutes, &p.RequireJustification); err2 != nil {
			httputil.WriteDBErr(w, r, h.logger, "GetActivationPolicy defaults query failed", err2)
			return
		}
		httputil.WriteJSON(w, http.StatusOK, p)
		return
	}
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "GetActivationPolicy query failed", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, p)
}

// PutActivationPolicy implements PUT /admin/roles/{id}/activation-policy
// Upserts the per-role activation policy (max duration + justification requirement).
func (h *JITHandler) PutActivationPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	roleID, ok := httputil.ParseIDPath(w, r, "id", "invalid role id")
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req struct {
		MaxDurationMinutes   int  `json:"maxDurationMinutes"`
		RequireJustification bool `json:"requireJustification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.MaxDurationMinutes <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "maxDurationMinutes must be positive"})
		return
	}

	if _, err := h.pool.Exec(ctx,
		`INSERT INTO admin_role_activation_policy (role_group_id, max_duration_minutes, require_justification)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (role_group_id) DO UPDATE
		   SET max_duration_minutes   = EXCLUDED.max_duration_minutes,
		       require_justification  = EXCLUDED.require_justification`,
		roleID, req.MaxDurationMinutes, req.RequireJustification,
	); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "PutActivationPolicy upsert failed", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, jitPolicy{
		RoleGroupID: roleID, MaxDurationMinutes: req.MaxDurationMinutes, RequireJustification: req.RequireJustification,
	})
}

// jitDefaults is the shape for the global JIT defaults read/write.
type jitDefaults struct {
	DefaultMaxDurationMinutes   int  `json:"defaultMaxDurationMinutes"`
	DefaultRequireJustification bool `json:"defaultRequireJustification"`
}

// GetJITDefaults implements GET /admin/system/jit-defaults
func (h *JITHandler) GetJITDefaults(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var d jitDefaults
	if err := h.pool.QueryRow(ctx,
		`SELECT COALESCE((SELECT (value->>0)::int  FROM system_config WHERE key='jit.default_max_minutes'), 480),
		        COALESCE((SELECT (value->>0)::bool FROM system_config WHERE key='jit.default_require_justification'), false)`,
	).Scan(&d.DefaultMaxDurationMinutes, &d.DefaultRequireJustification); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "GetJITDefaults query failed", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, d)
}

// PutJITDefaults implements PUT /admin/system/jit-defaults
// Updates the global JIT defaults in system_config.
func (h *JITHandler) PutJITDefaults(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req jitDefaults
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.DefaultMaxDurationMinutes <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "defaultMaxDurationMinutes must be positive"})
		return
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "PutJITDefaults begin tx failed", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx,
		`SELECT set_system_config('jit.default_max_minutes', to_jsonb($1::int))`,
		req.DefaultMaxDurationMinutes); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "PutJITDefaults set max failed", err)
		return
	}
	if _, err := tx.Exec(ctx,
		`SELECT set_system_config('jit.default_require_justification', to_jsonb($1::bool))`,
		req.DefaultRequireJustification); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "PutJITDefaults set require_justification failed", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "PutJITDefaults commit failed", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, req)
}
