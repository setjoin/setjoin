package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"
)

// ScopeSetsHandler provides admin CRUD for named scope containers (admin_scope_sets).
// Gated by scope_sets.manage (Super-only seed; delegation lands with spec §11).
// ponytail: no toggles field — scope-sets carry no feature-flag checks.
type ScopeSetsHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewScopeSetsHandler creates a scope-sets admin handler.
func NewScopeSetsHandler(pool *pgxpool.Pool, logger *slog.Logger) *ScopeSetsHandler {
	return &ScopeSetsHandler{pool: pool, logger: logger}
}

// requireScopeSetsManageClaims is the in-handler gate: returns the claims and
// true on success, writes 401/403 and returns nil/false on failure.
func (h *ScopeSetsHandler) requireScopeSetsManageClaims(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return nil, false
	}
	if !claims.HasPermission(permissions.PermScopeSetsManage) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "scope_sets.manage required"})
		return nil, false
	}
	return claims, true
}

// scopeSetResponse is the JSON shape for a scope set (without members).
type scopeSetResponse struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	DomainID    *int64 `json:"domainId,omitempty"`
	Description string `json:"description"`
	CreatedBy   *int64 `json:"createdBy,omitempty"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

// scopeSetMemberResponse is the JSON shape for a single member row.
type scopeSetMemberResponse struct {
	MemberType string  `json:"memberType"`
	MemberID   int64   `json:"memberId"`
	AddedBy    *int64  `json:"addedBy,omitempty"`
	AddedAt    string  `json:"addedAt"`
	Label      *string `json:"label,omitempty"`
}

// ListScopeSets returns all scope sets.
func (h *ScopeSetsHandler) ListScopeSets(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireScopeSetsManageClaims(w, r); !ok {
		return
	}
	ctx := r.Context()

	rows, err := h.pool.Query(ctx, `
		SELECT id, name, domain_id, COALESCE(description,''), created_by,
		       created_at::TEXT, updated_at::TEXT
		FROM admin_scope_sets
		ORDER BY name`)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list scope sets failed", err)
		return
	}
	defer rows.Close()

	out := []scopeSetResponse{}
	for rows.Next() {
		var s scopeSetResponse
		if err := rows.Scan(&s.ID, &s.Name, &s.DomainID, &s.Description, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "list scope sets scan error", err)
			return
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list scope sets rows error", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// GetScopeSet returns a single scope set with its members.
func (h *ScopeSetsHandler) GetScopeSet(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireScopeSetsManageClaims(w, r); !ok {
		return
	}
	ctx := r.Context()

	id, ok := httputil.ParseIDPath(w, r, "id", "invalid scope set id")
	if !ok {
		return
	}

	var s scopeSetResponse
	err := h.pool.QueryRow(ctx, `
		SELECT id, name, domain_id, COALESCE(description,''), created_by,
		       created_at::TEXT, updated_at::TEXT
		FROM admin_scope_sets WHERE id = $1`, id).Scan(
		&s.ID, &s.Name, &s.DomainID, &s.Description, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "scope set not found"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "get scope set failed", err)
		return
	}

	mrows, err := h.pool.Query(ctx, `
		SELECT m.member_type, m.member_id, m.added_by, m.added_at::TEXT,
		       CASE m.member_type
		           WHEN 'ou'    THEN d.name
		           WHEN 'group' THEN mb.display_name
		           WHEN 'user'  THEN u.email
		       END AS label
		FROM admin_scope_set_members m
		LEFT JOIN departments d ON m.member_type = 'ou' AND d.id = m.member_id
		LEFT JOIN distribution_groups dg ON m.member_type = 'group' AND dg.id = m.member_id
		LEFT JOIN mailboxes mb ON m.member_type = 'group' AND mb.id = dg.mailbox_id
		LEFT JOIN users u ON m.member_type = 'user' AND u.id = m.member_id
		WHERE m.set_id = $1
		ORDER BY m.member_type, m.member_id`, id)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "get scope set members failed", err)
		return
	}
	defer mrows.Close()

	members := []scopeSetMemberResponse{}
	for mrows.Next() {
		var m scopeSetMemberResponse
		if err := mrows.Scan(&m.MemberType, &m.MemberID, &m.AddedBy, &m.AddedAt, &m.Label); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "get scope set members scan error", err)
			return
		}
		members = append(members, m)
	}
	if err := mrows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "get scope set members rows error", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"set": s, "members": members})
}

// CreateScopeSet creates a new named scope set.
func (h *ScopeSetsHandler) CreateScopeSet(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireScopeSetsManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req struct {
		Name        string `json:"name"`
		DomainID    *int64 `json:"domainId,omitempty"`
		Description string `json:"description,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.Name == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "name is required"})
		return
	}

	var id int64
	err := h.pool.QueryRow(ctx, `
		INSERT INTO admin_scope_sets (name, domain_id, description, created_by)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		req.Name, req.DomainID, req.Description, claims.UserID).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			httputil.WriteProblem(w, r, httputil.NewConflictProblem(
				fmt.Sprintf("a set named %q already exists in this domain", req.Name)))
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "create scope set failed", err)
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{"name": req.Name, "domainId": req.DomainID})
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "scope_set_create", TargetType: "admin_scope_set", TargetID: &id,
		After: afterJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// UpdateScopeSet updates name and/or description of a scope set.
func (h *ScopeSetsHandler) UpdateScopeSet(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireScopeSetsManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	id, ok := httputil.ParseIDPath(w, r, "id", "invalid scope set id")
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Name        *string `json:"name,omitempty"`
		Description *string `json:"description,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	tag, err := h.pool.Exec(ctx, `
		UPDATE admin_scope_sets
		SET name        = COALESCE($2, name),
		    description = COALESCE($3, description),
		    updated_at  = now()
		WHERE id = $1`, id, req.Name, req.Description)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			httputil.WriteProblem(w, r, httputil.NewConflictProblem("a set with that name already exists in this domain"))
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "update scope set failed", err)
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "scope set not found"})
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{"id": id, "name": req.Name, "description": req.Description})
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "scope_set_update", TargetType: "admin_scope_set", TargetID: &id,
		After: afterJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	w.WriteHeader(http.StatusNoContent)
}

// DeleteScopeSet deletes a scope set. The DB RESTRICT trigger raises P0001 when in use.
func (h *ScopeSetsHandler) DeleteScopeSet(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireScopeSetsManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	id, ok := httputil.ParseIDPath(w, r, "id", "invalid scope set id")
	if !ok {
		return
	}

	tag, err := h.pool.Exec(ctx, `DELETE FROM admin_scope_sets WHERE id = $1`, id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "P0001" {
			// Count how many grants reference this set so the error message is actionable.
			var n int
			_ = h.pool.QueryRow(ctx,
				`SELECT COUNT(*) FROM admin_role_assignments WHERE scope_type='set' AND scope_id=$1`, id).Scan(&n)
			httputil.WriteProblem(w, r, httputil.NewConflictProblem(
				fmt.Sprintf("%d admin grant(s) are scoped to this set; reassign them first", n)))
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "delete scope set failed", err)
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "scope set not found"})
		return
	}

	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "scope_set_delete", TargetType: "admin_scope_set", TargetID: &id,
		IP: httputil.ClientIP(r), Tier: "core",
	})

	w.WriteHeader(http.StatusNoContent)
}

// AddMember adds a member (ou/group/user) to a scope set, with per-type validation.
func (h *ScopeSetsHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireScopeSetsManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	setIDStr := r.PathValue("id")
	setID, err := strconv.ParseInt(setIDStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid scope set id"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		MemberType string `json:"memberType"`
		MemberID   int64  `json:"memberId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.MemberType == "" || req.MemberID == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "memberType and memberId are required"})
		return
	}

	// Load the set's domain_id (needed for OU scope-within check).
	var domainID *int64
	if err := h.pool.QueryRow(ctx,
		`SELECT domain_id FROM admin_scope_sets WHERE id = $1`, setID).Scan(&domainID); err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "scope set not found"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "add member: load set failed", err)
		return
	}

	// Per-type validation (actor = claims.UserID, never from request body — R2).
	actor := claims.UserID
	switch req.MemberType {
	case "ou":
		// Rule A: the grant's OU must be within the actor's own OU reach.
		var allowed bool
		if err := h.pool.QueryRow(ctx,
			`SELECT admin_scope_within($1, 'ou', $2, $3)`,
			actor, req.MemberID, domainID).Scan(&allowed); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "add member ou: scope_within check failed", err)
			return
		}
		if !allowed {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "OU is outside your admin reach"})
			return
		}

	case "user":
		// admin_can_reach: actor must be able to manage this user.
		var canReach bool
		if err := h.pool.QueryRow(ctx,
			`SELECT admin_can_reach($1, $2)`, actor, req.MemberID).Scan(&canReach); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "add member user: can_reach check failed", err)
			return
		}
		if !canReach {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "user is outside your admin reach"})
			return
		}

	case "group":
		// Load group eligibility flags.
		var isDynamic bool
		var eligible bool // scim_external_id IS NOT NULL OR usable_as_admin_scope
		err := h.pool.QueryRow(ctx, `
			SELECT is_dynamic,
			       (scim_external_id IS NOT NULL OR usable_as_admin_scope)
			FROM distribution_groups WHERE id = $1`, req.MemberID).Scan(&isDynamic, &eligible)
		if err != nil {
			if err == pgx.ErrNoRows {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "group not found"})
				return
			}
			httputil.WriteDBErr(w, r, h.logger, "add member group: load group failed", err)
			return
		}
		if isDynamic {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "dynamic groups cannot be used as admin scope members"})
			return
		}
		if !eligible {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "group is not usable as admin scope (set usable_as_admin_scope or provision via SCIM)"})
			return
		}
		// Every static member's primary-mailbox user must be reachable by the editor.
		var allReachable bool
		if err := h.pool.QueryRow(ctx, `
			SELECT NOT EXISTS(
				SELECT 1 FROM distribution_group_members dgm
				JOIN mailboxes mb ON mb.id = dgm.mailbox_id AND mb.is_primary
				WHERE dgm.group_id = $1
				  AND NOT admin_can_reach($2, mb.user_id)
			)`, req.MemberID, actor).Scan(&allReachable); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "add member group: reach check failed", err)
			return
		}
		if !allReachable {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "group contains members outside your admin reach"})
			return
		}

	default:
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "memberType must be ou, group, or user"})
		return
	}

	// Insert the member.
	// ponytail: "editor may not edit a set they're scoped through" is moot for
	// Super-only seed — add guard when delegation lands (spec §11).
	itag, err := h.pool.Exec(ctx, `
		INSERT INTO admin_scope_set_members (set_id, member_type, member_id, added_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (set_id, member_type, member_id) DO NOTHING`,
		setID, req.MemberType, req.MemberID, actor)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "add member insert failed", err)
		return
	}
	if itag.RowsAffected() == 0 {
		// Already a member — idempotent no-op, skip audit.
		w.WriteHeader(http.StatusOK)
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{"setId": setID, "memberType": req.MemberType, "memberId": req.MemberID})
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: actor, Action: "scope_set_member_add", TargetType: "admin_scope_set", TargetID: &setID,
		After: afterJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	w.WriteHeader(http.StatusCreated)
}

// directoryGroupResponse is the JSON shape for GET /admin/distribution-groups.
// Field names match the DirectoryGroup TypeScript interface in webmail/src/lib/admin/client.ts.
type directoryGroupResponse struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	IsDynamic          bool   `json:"isDynamic"`
	ScimSynced         bool   `json:"scimSynced"`
	UsableAsAdminScope bool   `json:"usableAsAdminScope"`
	MemberCount        int64  `json:"memberCount"`
}

// ListDistributionGroups returns ALL distribution groups with eligibility flags.
// The picker UI uses isDynamic+scimSynced+usableAsAdminScope to compute eligible
// client-side; disabled groups are shown greyed-out with a reason.
// ponytail: distribution_groups are org-level objects (not per-user data);
//
//	R1–R4 apply to user-data tables — this is a read of org config gated by scope_sets.manage.
func (h *ScopeSetsHandler) ListDistributionGroups(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireScopeSetsManageClaims(w, r); !ok {
		return
	}
	ctx := r.Context()

	rows, err := h.pool.Query(ctx, `
		SELECT dg.id,
		       mb.display_name,
		       dg.is_dynamic,
		       dg.scim_external_id IS NOT NULL,
		       dg.usable_as_admin_scope,
		       COUNT(dgm.mailbox_id)
		FROM distribution_groups dg
		JOIN mailboxes mb ON mb.id = dg.mailbox_id
		LEFT JOIN distribution_group_members dgm ON dgm.group_id = dg.id
		GROUP BY dg.id, mb.display_name, dg.is_dynamic, dg.scim_external_id, dg.usable_as_admin_scope
		ORDER BY mb.display_name`)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list distribution groups failed", err)
		return
	}
	defer rows.Close()

	out := []directoryGroupResponse{}
	for rows.Next() {
		var g directoryGroupResponse
		if err := rows.Scan(&g.ID, &g.Name, &g.IsDynamic, &g.ScimSynced, &g.UsableAsAdminScope, &g.MemberCount); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "list distribution groups scan error", err)
			return
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list distribution groups rows error", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// RemoveMember removes a member from a scope set.
func (h *ScopeSetsHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireScopeSetsManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	setID, ok := httputil.ParseIDPath(w, r, "id", "invalid scope set id")
	if !ok {
		return
	}
	memberType := r.PathValue("memberType")
	switch memberType {
	case "ou", "user", "group":
	default:
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid memberType"})
		return
	}
	memberID, ok := httputil.ParseIDPath(w, r, "memberId", "invalid member id")
	if !ok {
		return
	}

	rtag, err := h.pool.Exec(ctx, `
		DELETE FROM admin_scope_set_members
		WHERE set_id = $1 AND member_type = $2 AND member_id = $3`,
		setID, memberType, memberID)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "remove scope set member failed", err)
		return
	}
	if rtag.RowsAffected() == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "member not found"})
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{"setId": setID, "memberType": memberType, "memberId": memberID})
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "scope_set_member_remove", TargetType: "admin_scope_set", TargetID: &setID,
		After: afterJSON, IP: httputil.ClientIP(r), Tier: "core",
	})

	w.WriteHeader(http.StatusNoContent)
}
