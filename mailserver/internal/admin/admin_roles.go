package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/toggle"
	"setjoin.com/shared/validate"
)

// RolesHandler provides admin CRUD for RBAC role groups and member assignments.
type RolesHandler struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	toggles *toggle.FeatureFlags // nil = SoD pre-check inactive (unit-test / fresh deploy)
}

// NewRolesHandler creates a roles admin handler.
func NewRolesHandler(pool *pgxpool.Pool, logger *slog.Logger) *RolesHandler {
	return &RolesHandler{pool: pool, logger: logger}
}

// acquireAdminAuthorityFence establishes the V172 universal lock order before
// a handler transaction takes any role, principal, or scope row lock.
func acquireAdminAuthorityFence(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT admin_authority_fence()`)
	return err
}

// SetFeatureFlags injects the live feature-toggle set. Called from main.go after
// construction — matches the same wiring pattern used by JMAPHandler.
func (h *RolesHandler) SetFeatureFlags(f *toggle.FeatureFlags) { h.toggles = f }

// sodClassConflict is the pure decision helper for the 等保三级 SoD pre-check.
// It returns true only when SodMode is ON AND the new role's sod_class is
// non-empty AND the principal's existing class union would span ≥2 distinct
// classes after adding newClass. It short-circuits to false (allow) when
// SodMode is OFF — strict no-op.
//
// existingClasses is the distinct set of non-null sod_class values the
// principal currently holds (from unexpired assignments); newClass is the
// sod_class of the role being assigned.
func sodClassConflict(flags *toggle.FeatureFlags, existingClasses []string, newClass string) bool {
	if flags == nil || !SodMode(flags) {
		return false // OFF — strict no-op
	}
	if newClass == "" {
		return false // role has no class — no conflict possible
	}
	for _, c := range existingClasses {
		if c != "" && c != newClass {
			return true // adding newClass would create a second distinct class
		}
	}
	return false
}

type roleResponse struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	DomainScope *int64   `json:"domainScope,omitempty"`
	IsBuiltin   bool     `json:"isBuiltin"`
	MemberCount int      `json:"memberCount"`
	CreatedAt   string   `json:"createdAt"`
	UpdatedAt   string   `json:"updatedAt"`
}

type roleMember struct {
	UserID         int64   `json:"userId"`
	UserEmail      string  `json:"userEmail"`
	DisplayName    string  `json:"displayName"`
	DomainOverride *int64  `json:"domainOverride,omitempty"`
	GrantedBy      int64   `json:"grantedBy"`
	GrantedAt      string  `json:"grantedAt"`
	ExpiresAt      *string `json:"expiresAt,omitempty"`
	// Manageable indicates whether the caller has sufficient authority to manage
	// (remove/reassign) this member. Uses the same admin_effective_authority
	// computation as admin_protection_check so the hint matches enforcement.
	Manageable bool    `json:"manageable"`
	ScopeType  *string `json:"scopeType,omitempty"`
	ScopeID    *int64  `json:"scopeId,omitempty"`
	SetName    *string `json:"setName,omitempty"`
}

// ListRoles returns role groups with member counts, scoped like every other
// read path (D-MAILSERVER-INTERNAL-ADMIN-F-008): a domain-scoped roles.manage
// holder sees only roles whose domain_scope matches their grant ($1 <= 0 means
// unconfined — same predicate access_reviews.go uses), so organization-wide
// role catalogs are no longer enumerable from a domain grant.
func (h *RolesHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	scope := middleware.DomainScopeFromContext(ctx)

	rows, err := h.pool.Query(ctx, `
		SELECT rg.id, rg.name, rg.description, rg.permissions,
		       rg.domain_scope, rg.is_builtin,
		       COALESCE((SELECT COUNT(*) FROM admin_role_assignments WHERE role_group_id = rg.id), 0),
		       rg.created_at::TEXT, rg.updated_at::TEXT
		FROM admin_role_groups rg
		WHERE ($1 <= 0 OR rg.domain_scope = $1)
		ORDER BY rg.is_builtin DESC, rg.name ASC`, scope)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list roles failed", err)
		return
	}
	defer rows.Close()

	out := []roleResponse{}
	for rows.Next() {
		var ro roleResponse
		var domainScope *int64
		if err := rows.Scan(&ro.ID, &ro.Name, &ro.Description, &ro.Permissions,
			&domainScope, &ro.IsBuiltin, &ro.MemberCount, &ro.CreatedAt, &ro.UpdatedAt); err != nil {
			continue
		}
		ro.DomainScope = domainScope
		out = append(out, ro)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list roles rows error", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// GetRole returns a single role group with its members. Out-of-scope ids are
// treated as not-found (404, no existence leak) — matching the mutation-path
// comment below and making the read path truthful
// (D-MAILSERVER-INTERNAL-ADMIN-F-008).
func (h *RolesHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid role id"})
		return
	}
	scope := middleware.DomainScopeFromContext(ctx)

	var ro roleResponse
	var domainScope *int64
	err = h.pool.QueryRow(ctx, `
		SELECT rg.id, rg.name, rg.description, rg.permissions,
		       rg.domain_scope, rg.is_builtin,
		       COALESCE((SELECT COUNT(*) FROM admin_role_assignments WHERE role_group_id = rg.id), 0),
		       rg.created_at::TEXT, rg.updated_at::TEXT
		FROM admin_role_groups rg
		WHERE rg.id = $1 AND ($2 <= 0 OR rg.domain_scope = $2)`, id, scope).Scan(
		&ro.ID, &ro.Name, &ro.Description, &ro.Permissions,
		&domainScope, &ro.IsBuiltin, &ro.MemberCount, &ro.CreatedAt, &ro.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "role not found"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "get role failed", err)
		return
	}
	ro.DomainScope = domainScope

	// Resolve caller for per-member manageable flags.
	var callerID int64
	if claims := auth.UserFromContext(ctx); claims != nil {
		callerID = claims.UserID
	}

	// Fetch members with per-member manageable flags keyed on the caller.
	members, err := h.fetchMembers(ctx, id, callerID)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "get role members failed", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"role":    ro,
		"members": members,
	})
}

// fetchMembers returns the list of users assigned to a role group, annotated
// with a per-member manageable flag computed from the caller's effective
// authority via the same admin_effective_authority helper used by the
// admin_protection_check reducer — so the pre-disable hint matches enforcement.
// callerID == 0 (unauthenticated) yields manageable=false for every member.
// The role's own domain_scope is re-checked (defense in depth — GetRole gates
// it already; this keeps the member identities unreachable even if a future
// caller skips that gate) via the same $n <= 0 OR predicate as access_reviews.
func (h *RolesHandler) fetchMembers(ctx context.Context, roleID, callerID int64) ([]roleMember, error) {
	scope := middleware.DomainScopeFromContext(ctx)
	rows, err := h.pool.Query(ctx, `
WITH actor AS (
  SELECT EXISTS(SELECT 1 FROM admin_role_assignments
                 WHERE user_id=$2 AND role_group_id=1
                   AND (expires_at IS NULL OR expires_at > now())) AS is_super,
         a.perms, a.scope
    FROM admin_effective_authority($2) AS a
)
SELECT ra.user_id, u.email, u.display_name,
       ra.domain_override, ra.granted_by, ra.granted_at::TEXT,
       ra.expires_at::TEXT,
       CASE WHEN act.is_super THEN true
            ELSE ea.perms <@ act.perms
                 AND NOT (cardinality(ea.perms) > 0 AND act.scope IS NOT NULL AND ea.scope IS NULL)
                 AND (cardinality(act.perms) = 0 OR admin_can_reach($2, ra.user_id))
       END AS manageable,
       ra.scope_type, ra.scope_id, ss.name
FROM admin_role_assignments ra
JOIN users u ON u.id = ra.user_id
CROSS JOIN LATERAL admin_effective_authority(ra.user_id) AS ea
CROSS JOIN actor act
LEFT JOIN admin_scope_sets ss ON ra.scope_type='set' AND ss.id = ra.scope_id
WHERE ra.role_group_id = $1
  AND ($3 <= 0 OR EXISTS (SELECT 1 FROM admin_role_groups rg
                          WHERE rg.id = ra.role_group_id
                            AND rg.domain_scope = $3))
ORDER BY u.email`, roleID, callerID, scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []roleMember{}
	for rows.Next() {
		var m roleMember
		var domainOverride *int64
		var expiresAt *string
		var scopeType *string
		var scopeID *int64
		var setName *string
		if err := rows.Scan(&m.UserID, &m.UserEmail, &m.DisplayName,
			&domainOverride, &m.GrantedBy, &m.GrantedAt, &expiresAt, &m.Manageable,
			&scopeType, &scopeID, &setName); err != nil {
			continue
		}
		m.DomainOverride = domainOverride
		m.ExpiresAt = expiresAt
		m.ScopeType = scopeType
		m.ScopeID = scopeID
		m.SetName = setName
		out = append(out, m)
	}
	return out, rows.Err()
}

// CreateRole creates a new role group.
func (h *RolesHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
		DomainScope *int64   `json:"domainScope,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.Name == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "role name is required"})
		return
	}
	if err := validate.ValidateResourceName(req.Name); err != nil {
		if ve, ok := err.(*validate.ValidationError); ok {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: ve.ToFieldError().Message})
		} else {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: err.Error()})
		}
		return
	}
	if len(req.Permissions) == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "at least one permission is required"})
		return
	}
	// Validate all permissions are known.
	for _, p := range req.Permissions {
		if !permissions.IsValid(p) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "unknown permission: " + p})
			return
		}
	}

	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}
	actor := claims.UserID

	// Rule A — grant-only-what-you-hold: a role may not embed a permission the
	// acting admin does not themselves hold (a super-admin holds AllPermissions
	// via a governed assignment, so this is vacuous for them).
	for _, p := range req.Permissions {
		if !claims.HasPermission(p) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "cannot grant a permission you do not hold: " + p})
			return
		}
	}

	// Rule B — mutation-scope-confinement: a scoped admin (scope > 0) may only
	// create a role confined to their own domain — never a global/NULL-scope
	// role nor a role for another domain.
	if scope := middleware.DomainScopeFromContext(ctx); scope > 0 {
		if req.DomainScope == nil || *req.DomainScope != scope {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "scoped admin cannot create a role outside their domain"})
			return
		}
	}

	var id int64
	err := h.pool.QueryRow(ctx, `
		INSERT INTO admin_role_groups (name, description, permissions, domain_scope)
		VALUES ($1, $2, $3, $4)
		RETURNING id`,
		req.Name, req.Description, req.Permissions, req.DomainScope).Scan(&id)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "create role failed", err)
		return
	}
	permsJSON, _ := json.Marshal(req.Permissions)
	afterJSON, _ := json.Marshal(map[string]any{"name": req.Name, "permissions": json.RawMessage(permsJSON)})
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: actor, Action: "role_create", TargetType: "role_group", TargetID: &id,
		After: afterJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// UpdateRole updates a role group's name, description, permissions, or domain scope.
func (h *RolesHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid role id"})
		return
	}

	// Atomic check+write: lock the role row FOR UPDATE so its is_builtin /
	// domain_scope / permissions cannot change between this check and the UPDATE
	// below (closes the TOCTOU race a concurrent privileged writer could drive).
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "update role tx begin failed", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := acquireAdminAuthorityFence(ctx, tx); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "update role authority fence failed", err)
		return
	}

	// Read SodMode ONCE at handler entry so a mid-request hot-reload flip has no
	// effect on the rest of this request.
	sodOn := h.toggles != nil && SodMode(h.toggles)

	var isBuiltin bool
	var existingScope *int64
	var existingSodClass *string
	var existingPermissions []string
	if err := tx.QueryRow(ctx, `SELECT is_builtin, domain_scope, sod_class, permissions FROM admin_role_groups WHERE id = $1 FOR UPDATE`, id).Scan(&isBuiltin, &existingScope, &existingSodClass, &existingPermissions); err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "role not found"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "update role check failed", err)
		return
	}

	// Rule B — mutation-scope-confinement: a scoped admin may only edit a role
	// already confined to their domain. A global/other-domain role is treated as
	// not-found (no existence leak), matching the read path.
	scope := middleware.DomainScopeFromContext(ctx)
	if scope > 0 {
		if existingScope == nil || *existingScope != scope {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "role not found"})
			return
		}
	}

	if isBuiltin {
		httputil.WriteProblem(w, r, httputil.NewConflictProblem("cannot modify a built-in role"))
		return
	}

	var req struct {
		Name        *string  `json:"name,omitempty"`
		Description *string  `json:"description,omitempty"`
		Permissions []string `json:"permissions,omitempty"`
		DomainScope *int64   `json:"domainScope,omitempty"`
		SodClass    *string  `json:"sodClass,omitempty"` // 等保三级 SoD class (system/security/audit/null)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.Name != nil {
		if *req.Name == "" {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "role name must not be empty"})
			return
		}
		if err := validate.ValidateResourceName(*req.Name); err != nil {
			if ve, ok := err.(*validate.ValidationError); ok {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: ve.ToFieldError().Message})
			} else {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: err.Error()})
			}
			return
		}
	}
	if len(req.Permissions) > 0 {
		for _, p := range req.Permissions {
			if !permissions.IsValid(p) {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "unknown permission: " + p})
				return
			}
		}
		// Rule A — grant-only-what-you-hold: the new permission set may not
		// introduce a permission the acting admin does not hold.
		for _, p := range req.Permissions {
			if !claims.HasPermission(p) {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "cannot grant a permission you do not hold: " + p})
				return
			}
		}
	}

	// Rule B — a scoped admin may not re-target the role to a different domain
	// (nor make it global).
	if scope > 0 && req.DomainScope != nil && *req.DomainScope != scope {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "scoped admin cannot move a role outside their domain"})
		return
	}

	// ── 等保三级 SoD checks (UpdateRole) ──────────────────────────────────────
	// Performed BEFORE the DB write (inside the tx holding the role lock).
	if sodOn {
		// Determine the effective sod_class after this update.
		effectiveSodClass := existingSodClass
		if req.SodClass != nil {
			effectiveSodClass = req.SodClass
		}
		// Determine the effective permissions after this update.  When the
		// request omits permissions, fall back to the role's STORED permissions
		// (already fetched via the FOR UPDATE lock) so that a class-only change
		// is still validated against the permissions the role actually holds.
		var effectivePerms []string
		if len(req.Permissions) > 0 {
			effectivePerms = req.Permissions
		} else {
			effectivePerms = existingPermissions
		}

		// SoD check A — ValidateRoleClass: when both a class and permissions are
		// present (either from the DB or from the request), every permission must
		// be allowed in that class.
		if effectiveSodClass != nil && *effectiveSodClass != "" && len(effectivePerms) > 0 {
			if bad := permissions.ValidateRoleClass(*effectiveSodClass, effectivePerms); len(bad) > 0 {
				httputil.WriteProblem(w, r, httputil.NewConflictProblem(
					"SoD class violation: permissions not allowed in class '"+*effectiveSodClass+"': "+strings.Join(bad, ", ")))
				return
			}
		}

		// SoD check B — assignee collision: when the sod_class is changing (either
		// because req.SodClass is provided or permissions changed the effective
		// class), reject if any current assignee would end up spanning ≥2 classes.
		//
		// Single set-based EXISTS query (NOT a per-assignee loop):
		//   Does there exist a principal who holds BOTH an unexpired assignment for
		//   THIS role AND at least one unexpired assignment to a DIFFERENT classed
		//   role in a DIFFERENT class?
		if effectiveSodClass != nil && *effectiveSodClass != "" {
			// Only run if the class is actually changing — a no-op class update
			// cannot introduce new conflicts.
			classChanging := existingSodClass == nil || *existingSodClass != *effectiveSodClass
			if classChanging {
				newClass := *effectiveSodClass
				var collides bool
				err := tx.QueryRow(ctx, `
					SELECT EXISTS (
					  SELECT 1
					  FROM admin_role_assignments ara_this
					  WHERE ara_this.role_group_id = $1
					    AND (ara_this.expires_at IS NULL OR ara_this.expires_at > now())
					    AND EXISTS (
					      SELECT 1
					      FROM admin_role_assignments ara_other
					      JOIN admin_role_groups rg_other
					        ON rg_other.id = ara_other.role_group_id
					      WHERE ara_other.user_id = ara_this.user_id
					        AND ara_other.role_group_id <> $1
					        AND (ara_other.expires_at IS NULL OR ara_other.expires_at > now())
					        AND rg_other.sod_class IS NOT NULL
					        AND rg_other.sod_class <> $2
					    )
					)`, id, newClass).Scan(&collides)
				if err != nil {
					httputil.WriteDBErr(w, r, h.logger, "sod update role collision check failed", err)
					return
				}
				if collides {
					httputil.WriteProblem(w, r, httputil.NewConflictProblem(
						"SoD class conflict: changing this role's class would cause existing assignees to span multiple 等保 classes"))
					return
				}
			}
		}
	}

	// Build SET clauses dynamically.
	var sets []string
	var args []any
	argIdx := 1

	if req.Name != nil {
		sets = append(sets, "name = $"+strconv.Itoa(argIdx))
		args = append(args, *req.Name)
		argIdx++
	}
	if req.Description != nil {
		sets = append(sets, "description = $"+strconv.Itoa(argIdx))
		args = append(args, *req.Description)
		argIdx++
	}
	if len(req.Permissions) > 0 {
		sets = append(sets, "permissions = $"+strconv.Itoa(argIdx))
		args = append(args, req.Permissions)
		argIdx++
	}
	if req.DomainScope != nil {
		// Allow setting domain_scope to NULL by passing -1 as sentinel.
		if *req.DomainScope <= 0 {
			sets = append(sets, "domain_scope = NULL")
		} else {
			sets = append(sets, "domain_scope = $"+strconv.Itoa(argIdx))
			args = append(args, *req.DomainScope)
			argIdx++
		}
	}
	if req.SodClass != nil {
		if *req.SodClass == "" {
			sets = append(sets, "sod_class = NULL")
		} else {
			sets = append(sets, "sod_class = $"+strconv.Itoa(argIdx))
			args = append(args, *req.SodClass)
			argIdx++
		}
	}

	if len(sets) == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "no fields to update"})
		return
	}

	query := "UPDATE admin_role_groups SET " + strings.Join(sets, ", ") + ", updated_at = now() WHERE id = $" + strconv.Itoa(argIdx)
	args = append(args, id)

	tag, err := tx.Exec(ctx, query, args...)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "update role failed", err)
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "role not found"})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "update role tx commit failed", err)
		return
	}

	updateActor := claims.UserID
	// Build a minimal after_state from whatever fields were supplied.
	afterFields := map[string]any{}
	if req.Name != nil {
		afterFields["name"] = *req.Name
	}
	if len(req.Permissions) > 0 {
		afterFields["permissions"] = req.Permissions
	}
	if req.SodClass != nil {
		afterFields["sodClass"] = *req.SodClass
	}
	afterJSON, _ := json.Marshal(afterFields)
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: updateActor, Action: "role_update", TargetType: "role_group", TargetID: &id,
		After: afterJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	w.WriteHeader(http.StatusNoContent)
}

// DeleteRole removes a role group. Built-in roles cannot be deleted.
func (h *RolesHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid role id"})
		return
	}

	// Atomic check+delete: open the tx and lock the role row FOR UPDATE before
	// the is_builtin / domain_scope checks, so it can't change before the DELETE.
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "delete role tx begin failed", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := acquireAdminAuthorityFence(ctx, tx); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "delete role authority fence failed", err)
		return
	}

	var isBuiltin bool
	var deletedName string
	var deletedPerms []string
	var deletedScope *int64
	if err := tx.QueryRow(ctx, `SELECT is_builtin, name, permissions, domain_scope FROM admin_role_groups WHERE id = $1 FOR UPDATE`, id).Scan(&isBuiltin, &deletedName, &deletedPerms, &deletedScope); err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "role not found"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "delete role check failed", err)
		return
	}

	// Rule B — mutation-scope-confinement: a scoped admin may only delete a role
	// confined to their domain. A global/other-domain role is treated as
	// not-found (no existence leak).
	if scope := middleware.DomainScopeFromContext(ctx); scope > 0 {
		if deletedScope == nil || *deletedScope != scope {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "role not found"})
			return
		}
	}

	if isBuiltin {
		httputil.WriteProblem(w, r, httputil.NewConflictProblem("cannot delete a built-in role"))
		return
	}

	// Delete assignments first, then the role (in the tx opened above).
	if _, err := tx.Exec(ctx, `DELETE FROM admin_role_assignments WHERE role_group_id = $1`, id); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "delete role assignments failed", err)
		return
	}
	if _, err := tx.Exec(ctx, `DELETE FROM admin_role_groups WHERE id = $1`, id); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "delete role failed", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "delete role tx commit failed", err)
		return
	}

	deleteActor := claims.UserID
	deletePermsJSON, _ := json.Marshal(deletedPerms)
	beforeJSON, _ := json.Marshal(map[string]any{"name": deletedName, "permissions": json.RawMessage(deletePermsJSON)})
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: deleteActor, Action: "role_delete", TargetType: "role_group", TargetID: &id,
		Before: beforeJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	w.WriteHeader(http.StatusNoContent)
}

// AssignMember assigns a user to a role group.
func (h *RolesHandler) AssignMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	roleIDStr := r.PathValue("id")
	roleID, err := strconv.ParseInt(roleIDStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid role id"})
		return
	}

	// Verify role exists and fetch its permissions + scope (assigning a role
	// effectively grants its permissions — needed for Rules A and B below).
	// Atomic check+write: lock the role row FOR UPDATE so its permissions / scope
	// cannot change between the Rule A/B checks below and the assignment INSERT.
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "assign member tx begin failed", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := acquireAdminAuthorityFence(ctx, tx); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "assign member authority fence failed", err)
		return
	}

	// Read SodMode ONCE at handler entry so a mid-request hot-reload flip has no
	// effect on the rest of this request.
	sodOn := h.toggles != nil && SodMode(h.toggles)

	var rolePerms []string
	var roleScope *int64
	var roleSodClass *string
	if err := tx.QueryRow(ctx, `SELECT permissions, domain_scope, sod_class FROM admin_role_groups WHERE id = $1 FOR UPDATE`, roleID).Scan(&rolePerms, &roleScope, &roleSodClass); err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "role not found"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "assign member role lookup failed", err)
		return
	}

	// Rule A — grant-only-what-you-hold: assigning a role hands the target every
	// permission the role grants; the acting admin must hold each of them.
	for _, p := range rolePerms {
		if !claims.HasPermission(p) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "cannot assign a role granting a permission you do not hold: " + p})
			return
		}
	}

	var req struct {
		UserID         int64   `json:"userId"`
		DomainOverride *int64  `json:"domainOverride,omitempty"`
		ExpiresAt      *string `json:"expiresAt,omitempty"`
		ScopeType      *string `json:"scopeType,omitempty"`
		ScopeID        *int64  `json:"scopeId,omitempty"`
		Eligible       *bool   `json:"eligible,omitempty"` // decision 14: eligible flag, default false
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.UserID <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "userId is required"})
		return
	}
	// Scope type validation: nil, 'ou', or 'set' accepted; group/user retired.
	if req.ScopeType != nil {
		switch *req.ScopeType {
		case "ou", "set":
			if req.ScopeID == nil {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "scopeId is required when scopeType is '" + *req.ScopeType + "'"})
				return
			}
		case "group", "user":
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "group/user scope is retired; use a scope-set"})
			return
		default:
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid scopeType"})
			return
		}
	} else if req.ScopeID != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "scopeId requires scopeType"})
		return
	}

	// Rule B — mutation-scope-confinement:
	//   (a) target must be reachable by the actor (domain AND OU axes).
	//   (b) any domainOverride must equal the actor's domain-scope.
	//   (c) the assignment's effective scope must equal the actor's domain.
	if scope := middleware.DomainScopeFromContext(ctx); scope > 0 {
		// Domain-scoped actor: enforce via JWT-derived scope (existing behaviour).
		var inScope bool
		if err := h.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND domain_id = $2)`,
			req.UserID, scope).Scan(&inScope); err != nil || !inScope {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "user not found"})
			return
		}
		// (b) domainOverride must equal actor's scope.
		if req.DomainOverride != nil && *req.DomainOverride != scope {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "cannot assign a role outside your domain"})
			return
		}
		// (c) the role's effective scope must equal actor's scope.
		effectiveScope := roleScope
		if req.DomainOverride != nil {
			effectiveScope = req.DomainOverride
		}
		if effectiveScope == nil || *effectiveScope != scope {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "cannot assign a role outside your domain"})
			return
		}
		// ponytail: AND gate — domain check above passed; now enforce OU narrowing.
		// A domain-only actor (no OU assignment) short-circuits true in admin_can_reach.
		var canReach bool
		if err := h.pool.QueryRow(ctx, `
			SELECT admin_can_manage($1, $2)`, claims.UserID, req.UserID).Scan(&canReach); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "assign member reach check (scoped) failed", err)
			return
		}
		if !canReach {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "user not found"})
			return
		}
	} else {
		// Unscoped actor: admin_can_reach enforces OU scope (and domain for any
		// domain-restricted assignments). Returns true for global actors (NULL scope
		// on every assignment).
		// ponytail: actors without any active DB assignments pass through — in
		// production every admin has at least one active assignment. Test actors
		// that inject claims without DB rows are unaffected.
		var canReach bool
		if err := h.pool.QueryRow(ctx, `
			SELECT admin_can_manage($1, $2)`, claims.UserID, req.UserID).Scan(&canReach); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "assign member reach check failed", err)
			return
		}
		if !canReach {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "user not found"})
			return
		}
	}

	// ── 等保三级 SoD pre-check (AssignMember) ──────────────────────────────────
	// When SodMode is ON and the role carries a sod_class, take a principal-scoped
	// lock then query the principal's current distinct non-null sod_class values
	// over UNEXPIRED assignments. If adding this role's class would make the union
	// span ≥2 classes, return a clean 409 before the trigger fires.
	//
	// This runs on tx (snapshot consistency with the role lock above). The DB
	// trigger trg_sod_exclusion is the authoritative backstop — this is UX only.
	if sodOn && roleSodClass != nil && *roleSodClass != "" {
		// Principal-scoped lock: prevents concurrent requests from both passing the
		// pre-check and both attempting the INSERT (TOCTOU on the class union).
		if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, req.UserID); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "sod assign member principal lock failed", err)
			return
		}
		// ONE query: fetch the distinct non-null sod_class values for this
		// principal's UNEXPIRED assignments (excluding the target role itself,
		// in case it's already assigned — ON CONFLICT DO UPDATE path).
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT rg.sod_class
			FROM admin_role_assignments ara
			JOIN admin_role_groups rg ON rg.id = ara.role_group_id
			WHERE ara.user_id = $1
			  AND ara.role_group_id <> $2
			  AND (ara.expires_at IS NULL OR ara.expires_at > now())
			  AND rg.sod_class IS NOT NULL`,
			req.UserID, roleID)
		if err != nil {
			httputil.WriteDBErr(w, r, h.logger, "sod assign member class query failed", err)
			return
		}
		var existingClasses []string
		for rows.Next() {
			var cls string
			if err := rows.Scan(&cls); err != nil {
				rows.Close()
				httputil.WriteDBErr(w, r, h.logger, "sod assign member class scan failed", err)
				return
			}
			existingClasses = append(existingClasses, cls)
		}
		rows.Close()
		if rows.Err() != nil {
			httputil.WriteDBErr(w, r, h.logger, "sod assign member class query rows error", rows.Err())
			return
		}
		if sodClassConflict(h.toggles, existingClasses, *roleSodClass) {
			httputil.WriteProblem(w, r, httputil.NewConflictProblem(
				"SoD class conflict: this assignment would give the principal roles spanning multiple 等保 classes"))
			return
		}
	}

	// Grant-time Rule A under set FOR UPDATE (spec §3.4c — no TOCTOU): lock the set
	// row inside the existing tx so membership cannot widen between the
	// admin_scope_within containment check and the INSERT below.
	if req.ScopeType != nil && *req.ScopeType == "set" {
		var dummy int64
		if err := tx.QueryRow(ctx, `SELECT id FROM admin_scope_sets WHERE id = $1 FOR UPDATE`, *req.ScopeID).Scan(&dummy); err != nil {
			if err == pgx.ErrNoRows {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "scope-set not found"})
				return
			}
			httputil.WriteDBErr(w, r, h.logger, "assign member scope-set lock failed", err)
			return
		}
	}

	// Rule A scope arm — self-broaden check: an OU-confined actor cannot write a
	// grant broader than their own reach (e.g. a domain-wide null-scope grant from
	// an /eng-scoped actor). admin_scope_within(actor, grantScopeType, grantScopeID,
	// grantDomain) returns FALSE iff the grant would broaden → 403.
	// A global actor (null scope, null ou_reach) passes unconditionally.
	// grantDomain: null (domain-wide on the domain axis) → ok for global actors;
	// a domain-scoped actor is already blocked by the domain-confinement branch
	// earlier, so passing NULL here is safe.
	var scopeAllowed bool
	var grantDomain *int64 // ponytail: null = domain-wide grant; domain axis enforced upstream
	if err := tx.QueryRow(ctx, `SELECT admin_scope_within($1, $2, $3, $4)`,
		claims.UserID, req.ScopeType, req.ScopeID, grantDomain).Scan(&scopeAllowed); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "assign member scope_within check failed", err)
		return
	}
	if !scopeAllowed {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "cannot grant a scope broader than your own reach"})
		return
	}

	// Protection check: reject role assignments blocked by policy.
	// Runs on tx (snapshot consistency with the role FOR UPDATE lock above).
	if _, err := tx.Exec(ctx, `SELECT admin_protection_check($1,$2,'assign_role',$3)`, claims.UserID, req.UserID, roleID); err != nil {
		if mapProtectionErr(h.pool, h.logger, w, r, err, claims.UserID, req.UserID) {
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "assign member protection check failed", err)
		return
	}

	// Get the granting user from auth context.
	grantedBy := claims.UserID

	var expiresAt any
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid expiresAt: must be RFC3339"})
			return
		}
		expiresAt = t
	}

	var assignmentID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO admin_role_assignments (user_id, role_group_id, domain_override, granted_by, expires_at, scope_type, scope_id, eligible)
		VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, false))
		ON CONFLICT (user_id, role_group_id)
		DO UPDATE SET domain_override = EXCLUDED.domain_override,
		              expires_at = EXCLUDED.expires_at,
		              granted_by = EXCLUDED.granted_by,
		              granted_at = now(),
		              scope_type = EXCLUDED.scope_type,
		              scope_id = EXCLUDED.scope_id,
		              eligible = EXCLUDED.eligible
		RETURNING id`,
		req.UserID, roleID, req.DomainOverride, grantedBy, expiresAt, req.ScopeType, req.ScopeID, req.Eligible).Scan(&assignmentID)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "assign member failed", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "assign member tx commit failed", err)
		return
	}

	assignAfterJSON, _ := json.Marshal(map[string]any{
		"targetUserId": req.UserID, "roleId": roleID,
		"scopeType": req.ScopeType, "scopeId": req.ScopeID,
	})
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: grantedBy, Action: "role_assign", TargetType: "role_assignment", TargetID: &assignmentID,
		After: assignAfterJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"id": assignmentID})
}

// RemoveMember removes a user from a role group.
func (h *RolesHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	roleIDStr := r.PathValue("id")
	roleID, err := strconv.ParseInt(roleIDStr, 10, 64)
	userIDStr := r.PathValue("userId")
	userID, err2 := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil || err2 != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid role id or user id"})
		return
	}

	// Rule B — mutation-scope-confinement: target must be reachable by the actor.
	if scope := middleware.DomainScopeFromContext(ctx); scope > 0 {
		// Domain-scoped actor: enforce via JWT-derived scope (existing behaviour).
		var inScope bool
		if err := h.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND domain_id = $2)`,
			userID, scope).Scan(&inScope); err != nil || !inScope {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "assignment not found"})
			return
		}
		// ponytail: AND gate — domain check above passed; now enforce OU narrowing.
		// A domain-only actor (no OU assignment) short-circuits true in admin_can_reach.
		var canReach bool
		if err := h.pool.QueryRow(ctx, `
			SELECT admin_can_manage($1, $2)`, claims.UserID, userID).Scan(&canReach); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "remove member reach check (scoped) failed", err)
			return
		}
		if !canReach {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "assignment not found"})
			return
		}
	} else {
		// Unscoped actor: admin_can_reach enforces OU scope (and domain for any
		// domain-restricted assignments). Returns true for global actors (NULL scope
		// on every assignment).
		// ponytail: actors without any active DB assignments pass through — in
		// production every admin has at least one active assignment.
		var canReach bool
		if err := h.pool.QueryRow(ctx, `
			SELECT admin_can_manage($1, $2)`, claims.UserID, userID).Scan(&canReach); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "remove member reach check failed", err)
			return
		}
		if !canReach {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "assignment not found"})
			return
		}
	}

	// Wrap protection check + DELETE in a transaction so the guard and the
	// mutation see the same snapshot (BZ065/BZ066 snapshot-consistency requirement).
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "remove member tx begin failed", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `SELECT admin_protection_check($1,$2,'remove_role',$3)`, claims.UserID, userID, roleID); err != nil {
		if mapProtectionErr(h.pool, h.logger, w, r, err, claims.UserID, userID) {
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "remove member protection check failed", err)
		return
	}

	var assignmentID int64
	err = tx.QueryRow(ctx,
		`DELETE FROM admin_role_assignments WHERE role_group_id = $1 AND user_id = $2 RETURNING id`,
		roleID, userID).Scan(&assignmentID)
	if err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "assignment not found"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "remove member failed", err)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "remove member tx commit failed", err)
		return
	}

	revokeActor := claims.UserID
	revokeBeforeJSON, _ := json.Marshal(map[string]any{"targetUserId": userID, "roleId": roleID})
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: revokeActor, Action: "role_revoke", TargetType: "role_assignment", TargetID: &assignmentID,
		Before: revokeBeforeJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	w.WriteHeader(http.StatusNoContent)
}

type effectivePermSource struct {
	RoleGroupID    int64    `json:"roleGroupId"`
	RoleName       string   `json:"roleName"`
	Permissions    []string `json:"permissions"`
	EffectiveScope *int64   `json:"effectiveScope,omitempty"`
}

type effectivePermsResponse struct {
	Permissions []string              `json:"permissions"`
	DomainScope *int64                `json:"domainScope,omitempty"`
	Sources     []effectivePermSource `json:"sources"`
	Consoles    []ConsoleID           `json:"consoles"`
}

// EffectivePermissions returns a user's resolved permission union + narrowest
// scope (via permissions.Resolve) plus the per-role breakdown for "inherited
// from" annotation. Honors the caller's domain scope: a scoped admin may only
// inspect users within their domain.
func (h *RolesHandler) EffectivePermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid user id")
	if !ok {
		return
	}

	// Domain-scope guard: a scoped admin can only inspect in-scope users.
	if scope := middleware.DomainScopeFromContext(ctx); scope > 0 {
		var inScope bool
		if err := h.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND domain_id = $2)`, id, scope).Scan(&inScope); err != nil || !inScope {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "user not found"})
			return
		}
	}

	perms, domainScope, err := permissions.Resolve(ctx, h.pool, id)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "resolve effective permissions failed", err)
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT rg.id, rg.name, rg.permissions, COALESCE(ra.domain_override, rg.domain_scope)
		FROM admin_role_assignments ra
		JOIN admin_role_groups rg ON rg.id = ra.role_group_id
		WHERE ra.user_id = $1 AND (ra.expires_at IS NULL OR ra.expires_at > now())
		ORDER BY rg.name`, id)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "effective permission sources failed", err)
		return
	}
	defer rows.Close()

	sources := []effectivePermSource{}
	for rows.Next() {
		var s effectivePermSource
		if err := rows.Scan(&s.RoleGroupID, &s.RoleName, &s.Permissions, &s.EffectiveScope); err != nil {
			continue
		}
		sources = append(sources, s)
	}
	if rows.Err() != nil {
		httputil.WriteDBErr(w, r, h.logger, "effective permission sources rows error", rows.Err())
		return
	}
	if perms == nil {
		perms = []string{}
	}
	httputil.WriteJSON(w, http.StatusOK, effectivePermsResponse{
		Permissions: perms, DomainScope: domainScope, Sources: sources,
		Consoles: ConsolesForPerms(perms),
	})
}

// ── Bulk enqueue handlers ───────────────────────────────────────────────────

// enqueueBulkRole is the shared helper for BulkAssign and BulkRevoke.
// It validates Rule A (actor must hold every perm the role grants), decodes
// the body, deduplicates userIds, validates caps and expiresAt, then inserts
// a bulk_role_jobs row and returns 202 {jobId}.
func (h *RolesHandler) enqueueBulkRole(w http.ResponseWriter, r *http.Request, op string) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	roleIDStr := r.PathValue("id")
	roleID, err := strconv.ParseInt(roleIDStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid role id"})
		return
	}

	// Rule A — grant-only-what-you-hold: mirror of AssignMember:719-724.
	// No FOR UPDATE here — bulk enqueue is not atomic with the per-user work;
	// the worker re-derives live. A plain read is sufficient.
	var rolePerms []string
	if err := h.pool.QueryRow(ctx,
		`SELECT permissions FROM admin_role_groups WHERE id = $1`, roleID,
	).Scan(&rolePerms); err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "role not found"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "enqueueBulkRole role lookup", err)
		return
	}
	for _, p := range rolePerms {
		if !claims.HasPermission(p) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "cannot assign a role granting a permission you do not hold: " + p})
			return
		}
	}

	// Decode body.
	var req struct {
		UserIDs   []int64 `json:"userIds"`
		ExpiresAt *string `json:"expiresAt,omitempty"`
		ScopeType *string `json:"scopeType,omitempty"`
		ScopeID   *int64  `json:"scopeId,omitempty"`
		Eligible  *bool   `json:"eligible,omitempty"` // decision 14: eligible flag, default false
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	// Scope type validation (assign only; revoke carries no scope).
	// Accepts 'ou' and 'set'; group/user retired. Self-broaden (Rule A scope arm)
	// is enforced by the reducer's job-level admin_scope_within check — not
	// duplicated here. ponytail: one enforcement point, no TOCTOU.
	if op == "assign" && req.ScopeType != nil {
		switch *req.ScopeType {
		case "ou", "set":
			if req.ScopeID == nil {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "scopeId is required when scopeType is '" + *req.ScopeType + "'"})
				return
			}
		case "group", "user":
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "group/user scope is retired; use a scope-set"})
			return
		default:
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid scopeType"})
			return
		}
	} else if op == "assign" && req.ScopeID != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "scopeId requires scopeType"})
		return
	}

	// Dedup userIds preserving first-seen order.
	seen := make(map[int64]struct{}, len(req.UserIDs))
	deduped := req.UserIDs[:0:0] // ponytail: reuse backing array len, new slice header
	for _, id := range req.UserIDs {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			deduped = append(deduped, id)
		}
	}

	if len(deduped) == 0 || len(deduped) > 1000 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "userIds must have 1–1000 entries"})
		return
	}

	// Parse and validate expiresAt for assign; ignored for revoke.
	var expiresAt *time.Time
	if op == "assign" && req.ExpiresAt != nil {
		t, parseErr := time.Parse(time.RFC3339, *req.ExpiresAt)
		if parseErr != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "expiresAt must be RFC3339"})
			return
		}
		if t.Before(time.Now()) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "expiresAt must be in the future"})
			return
		}
		expiresAt = &t
	}

	// Scope and eligible are assign-only inputs: drop them for revoke so stray
	// client-sent values are not persisted as dead data or tripped into a 500 by
	// the bulk_role_jobs scope CHECK. (Single-revoke has no scope/eligible concept.)
	var scopeType *string
	var scopeID *int64
	eligible := false
	if op == "assign" {
		scopeType, scopeID = req.ScopeType, req.ScopeID
		if req.Eligible != nil {
			eligible = *req.Eligible
		}
	}

	var jobID int64
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO bulk_role_jobs (op, role_id, actor_id, user_ids, expires_at, total, scope_type, scope_id, eligible)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
		op, roleID, claims.UserID, deduped, expiresAt, len(deduped), scopeType, scopeID, eligible,
	).Scan(&jobID); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "enqueueBulkRole insert", err)
		return
	}

	httputil.WriteJSON(w, http.StatusAccepted, map[string]int64{"jobId": jobID})
}

// BulkAssign enqueues a bulk assign job (op="assign").
// POST /admin/roles/{id}/members:bulk  body: {userIds []int64, expiresAt *string}
func (h *RolesHandler) BulkAssign(w http.ResponseWriter, r *http.Request) {
	h.enqueueBulkRole(w, r, "assign")
}

// BulkRevoke enqueues a bulk revoke job (op="revoke").
// DELETE /admin/roles/{id}/members:bulk  body: {userIds []int64}
func (h *RolesHandler) BulkRevoke(w http.ResponseWriter, r *http.Request) {
	h.enqueueBulkRole(w, r, "revoke")
}
