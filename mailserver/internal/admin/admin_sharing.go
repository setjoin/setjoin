package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/reducererr"
)

// SharingHandler is the admin Sharing console surface (spec
// 2026-06-27-sharing-delegation-design.md §7): sharing_defaults CRUD
// (org/OU/group), per-user sharing oversight, and the sharing audit view.
// Gated sharing.read (view) / sharing.manage (write) at the route AND
// re-checked here; the write reducers ALSO enforce the ladder + D7 domain
// scoping against admin_effective_authority (defense in depth, §8).
//
// Cross-tenant admin read surface (W7): constructed on workerPool (BYPASSRLS)
// — a tenant GUC would hide other tenants' rows once the native-RLS DSN flips.
// workerPool aliases pool until DB_WORKER_DSN is set, so this is INERT today.
type SharingHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewSharingHandler creates a SharingHandler.
func NewSharingHandler(workerPool pgxutil.WorkerPool, logger *slog.Logger) *SharingHandler {
	return &SharingHandler{pool: workerPool.Pool, logger: logger}
}

func (h *SharingHandler) requireManageClaims(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return nil, false
	}
	if !claims.HasPermission(permissions.PermSharingManage) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "sharing.manage required"})
		return nil, false
	}
	return claims, true
}

func (h *SharingHandler) requireViewClaims(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return nil, false
	}
	if !claims.HasPermission(permissions.PermSharingRead) && !claims.HasPermission(permissions.PermSharingManage) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "sharing.read or sharing.manage required"})
		return nil, false
	}
	return claims, true
}

// sharingDefaultAdminRow is the JSON shape for a sharing_defaults row with
// resolved human labels for the owner-scope target and audience.
type sharingDefaultAdminRow struct {
	ID            int64  `json:"id"`
	Resource      string `json:"resource"`
	OwnerScope    string `json:"ownerScope"`
	OwnerRef      int64  `json:"ownerRef"`
	OwnerLabel    string `json:"ownerLabel"`
	Audience      string `json:"audience"`
	AudienceRef   int64  `json:"audienceRef"`
	AudienceLabel string `json:"audienceLabel"`
	Level         string `json:"level"`
	CreatedBy     int64  `json:"createdBy"`
	UpdatedAt     string `json:"updatedAt"`
}

// sharingDefaultsQuery resolves labels per ref kind; the D7 domain filter
// (scope > 0) keeps org rows to the admin's domain, user rows to users in it,
// and group rows to groups whose mailbox lives in it. OU rows carry no domain
// axis (departments have no domain_id) and are always listed.
const sharingDefaultsQuery = `
	SELECT sd.id, sd.resource, sd.owner_scope, sd.owner_ref,
	       COALESCE(CASE sd.owner_scope
	         WHEN 'org'   THEN (SELECT name  FROM domains             WHERE id = sd.owner_ref)
	         WHEN 'ou'    THEN (SELECT name  FROM departments         WHERE id = sd.owner_ref)
	         WHEN 'group' THEN (SELECT m.email FROM distribution_groups g
	                              JOIN mailboxes m ON m.id = g.mailbox_id WHERE g.id = sd.owner_ref)
	         WHEN 'user'  THEN (SELECT email FROM users               WHERE id = sd.owner_ref)
	       END, '') AS owner_label,
	       sd.audience, sd.audience_ref,
	       COALESCE(CASE sd.audience
	         WHEN 'everyone' THEN (SELECT name  FROM domains             WHERE id = sd.audience_ref)
	         WHEN 'ou'       THEN (SELECT name  FROM departments         WHERE id = sd.audience_ref)
	         WHEN 'group'    THEN (SELECT m.email FROM distribution_groups g
	                                 JOIN mailboxes m ON m.id = g.mailbox_id WHERE g.id = sd.audience_ref)
	       END, '') AS audience_label,
	       sd.level, sd.created_by, sd.updated_at::TEXT
	FROM sharing_defaults sd
	WHERE ($1::bigint = 0
	   OR (sd.owner_scope = 'org'   AND sd.owner_ref = $1)
	   OR (sd.owner_scope = 'ou')
	   OR (sd.owner_scope = 'group' AND EXISTS (
	         SELECT 1 FROM distribution_groups g JOIN mailboxes m ON m.id = g.mailbox_id
	          WHERE g.id = sd.owner_ref AND m.domain_id = $1))
	   OR (sd.owner_scope = 'user'  AND EXISTS (
	         SELECT 1 FROM users u WHERE u.id = sd.owner_ref AND u.domain_id = $1)))
	ORDER BY sd.owner_scope, sd.id`

// ListDefaults implements GET /admin/sharing/defaults. Requires sharing.read.
func (h *SharingHandler) ListDefaults(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireViewClaims(w, r); !ok {
		return
	}
	domainScope := middleware.DomainScopeFromContext(r.Context())
	rows, err := h.pool.Query(r.Context(), sharingDefaultsQuery, domainScope)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list sharing defaults failed", err)
		return
	}
	defer rows.Close()
	out := []sharingDefaultAdminRow{}
	for rows.Next() {
		var d sharingDefaultAdminRow
		if err := rows.Scan(&d.ID, &d.Resource, &d.OwnerScope, &d.OwnerRef, &d.OwnerLabel,
			&d.Audience, &d.AudienceRef, &d.AudienceLabel, &d.Level, &d.CreatedBy, &d.UpdatedAt); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "scan sharing default failed", err)
			return
		}
		out = append(out, d)
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// CreateDefault implements POST /admin/sharing/defaults — an UPSERT on the
// (resource, scope, ref, audience, ref) key. Requires sharing.manage; the
// reducer re-enforces the ladder + D7 domain scope (BZ116) and validates the
// combination (BZ117).
func (h *SharingHandler) CreateDefault(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		OwnerScope  string `json:"ownerScope"`
		OwnerRef    int64  `json:"ownerRef"`
		Audience    string `json:"audience"`
		AudienceRef int64  `json:"audienceRef"`
		Level       string `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	var id int64
	if err := h.pool.QueryRow(r.Context(),
		`SELECT sharing_default_set($1, 'calendar', $2, $3, $4, $5, $6)`,
		claims.UserID, req.OwnerScope, req.OwnerRef, req.Audience, req.AudienceRef, req.Level).Scan(&id); err != nil {
		h.logger.Info("admin sharing default set rejected", "error", err)
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "request failed"})
		}
		return
	}
	// Audit is written by the reducer (audit_write tier core, D8).
	httputil.WriteJSON(w, http.StatusOK, map[string]int64{"id": id})
}

// DeleteDefault implements DELETE /admin/sharing/defaults/{id}. Requires
// sharing.manage; the reducer enforces the ladder + domain scope.
func (h *SharingHandler) DeleteDefault(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid id")
	if !ok {
		return
	}
	if _, err := h.pool.Exec(r.Context(),
		`SELECT sharing_default_clear($1, $2)`, claims.UserID, id); err != nil {
		h.logger.Info("admin sharing default clear rejected", "error", err)
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "request failed"})
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// userOversight is the per-user §7 panel: the user's delegates, explicit
// calendar grantees, and every sharing_defaults row that applies to them.
type userOversight struct {
	UserID         int64                    `json:"userId"`
	Email          string                   `json:"email"`
	DisplayName    string                   `json:"displayName"`
	Delegates      []map[string]any         `json:"delegates"`
	CalendarGrants []map[string]any         `json:"calendarGrants"`
	Defaults       []sharingDefaultAdminRow `json:"defaults"`
}

// UserOversight implements GET /admin/sharing/users/{id}. Requires
// sharing.read. Domain-scoped admins (D7) fold their domain into the SAME
// resolving SELECT — an out-of-scope user is indistinguishable from a missing
// one (404).
func (h *SharingHandler) UserOversight(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireViewClaims(w, r); !ok {
		return
	}
	userID, ok := httputil.ParseIDPath(w, r, "id", "invalid user id")
	if !ok {
		return
	}
	ctx := r.Context()
	domainScope := middleware.DomainScopeFromContext(ctx)

	out := userOversight{UserID: userID, Delegates: []map[string]any{}, CalendarGrants: []map[string]any{}, Defaults: []sharingDefaultAdminRow{}}
	// R1 + D7: scope rides in the resolving SELECT (404-indistinguishable).
	err := h.pool.QueryRow(ctx,
		`SELECT email, display_name FROM users WHERE id = $1 AND ($2 = 0 OR domain_id = $2)`,
		userID, domainScope).Scan(&out.Email, &out.DisplayName)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "user not found"})
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT u.id, u.email, u.display_name, md.permission, md.granted_at::TEXT
		FROM mailbox_delegates md
		JOIN mailboxes m ON m.id = md.mailbox_id
		JOIN users u ON u.id = md.user_id
		WHERE m.user_id = $1
		ORDER BY u.email, md.permission`, userID)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "oversight delegates failed", err)
		return
	}
	for rows.Next() {
		var id int64
		var email, name, perm, at string
		if err := rows.Scan(&id, &email, &name, &perm, &at); err == nil {
			out.Delegates = append(out.Delegates, map[string]any{
				"userId": id, "email": email, "name": name, "permission": perm, "grantedAt": at})
		}
	}
	rows.Close()

	rows, err = h.pool.Query(ctx, `
		SELECT c.id, c.name, u.email, u.display_name, a.permission
		FROM calendar_acls a
		JOIN calendars c ON c.id = a.calendar_id
		JOIN mailboxes m ON m.id = c.mailbox_id
		JOIN users u ON u.id = a.user_id
		WHERE m.user_id = $1
		ORDER BY c.id, u.email`, userID)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "oversight grants failed", err)
		return
	}
	for rows.Next() {
		var calID int64
		var calName, email, name, level string
		if err := rows.Scan(&calID, &calName, &email, &name, &level); err == nil {
			out.CalendarGrants = append(out.CalendarGrants, map[string]any{
				"calendarId": calID, "calendarName": calName, "userEmail": email, "userName": name, "level": level})
		}
	}
	rows.Close()

	rows, err = h.pool.Query(ctx, `
		SELECT sd.id, sd.resource, sd.owner_scope, sd.owner_ref, '' AS owner_label,
		       sd.audience, sd.audience_ref, '' AS audience_label,
		       sd.level, sd.created_by, sd.updated_at::TEXT
		FROM sharing_defaults sd
		JOIN users u ON u.id = $1
		WHERE sd.resource = 'calendar'
		  AND (   (sd.owner_scope = 'user'  AND sd.owner_ref = u.id)
		       OR (sd.owner_scope = 'org'   AND sd.owner_ref = u.domain_id)
		       OR (sd.owner_scope = 'ou'    AND sd.owner_ref = u.department_id)
		       OR (sd.owner_scope = 'group' AND EXISTS (
		             SELECT 1 FROM distribution_group_members dgm
		             JOIN mailboxes mm ON mm.id = dgm.mailbox_id
		             WHERE dgm.group_id = sd.owner_ref AND mm.user_id = u.id)))
		ORDER BY sd.id`, userID)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "oversight defaults failed", err)
		return
	}
	for rows.Next() {
		var d sharingDefaultAdminRow
		if err := rows.Scan(&d.ID, &d.Resource, &d.OwnerScope, &d.OwnerRef, &d.OwnerLabel,
			&d.Audience, &d.AudienceRef, &d.AudienceLabel, &d.Level, &d.CreatedBy, &d.UpdatedAt); err == nil {
			out.Defaults = append(out.Defaults, d)
		}
	}
	rows.Close()

	httputil.WriteJSON(w, http.StatusOK, out)
}

// sharingAuditActions are the four D8 audit actions the sharing reducers write.
var sharingAuditActions = []string{
	"mailbox_delegate_granted", "mailbox_delegate_revoked",
	"sharing_default_set", "sharing_default_cleared",
}

// Audit implements GET /admin/sharing/audit?user_id=&limit=&offset= — the §7
// audit view over the sharing-related audit_write rows. Requires sharing.read.
func (h *SharingHandler) Audit(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireViewClaims(w, r); !ok {
		return
	}
	limit, offset := httputil.ParseLimitOffset(r, 50, 500)
	where := `al.action = ANY($1)`
	args := []any{sharingAuditActions}
	if s := r.URL.Query().Get("user_id"); s != "" {
		if uid, err := strconv.ParseInt(s, 10, 64); err == nil {
			where += ` AND al.user_id = $2`
			args = append(args, uid)
		}
	}
	query := `SELECT al.id, al.occurred_at, al.user_id, COALESCE(u.email,'system'),
	          al.action, al.target_type, al.target_id, al.before_state, al.after_state
	          FROM admin_audit_log al LEFT JOIN users u ON u.id = al.user_id
	          WHERE ` + where + ` ORDER BY al.occurred_at DESC
	          LIMIT $` + strconv.Itoa(len(args)+1) + ` OFFSET $` + strconv.Itoa(len(args)+2)
	args = append(args, limit, offset)

	rows, err := h.pool.Query(r.Context(), query, args...)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "sharing audit list failed", err)
		return
	}
	defer rows.Close()

	type item struct {
		ID          int64           `json:"id"`
		OccurredAt  string          `json:"occurredAt"`
		UserID      *int64          `json:"userId,omitempty"`
		UserEmail   string          `json:"userEmail"`
		Action      string          `json:"action"`
		TargetType  *string         `json:"targetType,omitempty"`
		TargetID    *int64          `json:"targetId,omitempty"`
		BeforeState json.RawMessage `json:"beforeState,omitempty"`
		AfterState  json.RawMessage `json:"afterState,omitempty"`
	}
	out := []item{}
	for rows.Next() {
		var i item
		var t time.Time
		if err := rows.Scan(&i.ID, &t, &i.UserID, &i.UserEmail, &i.Action,
			&i.TargetType, &i.TargetID, &i.BeforeState, &i.AfterState); err == nil {
			i.OccurredAt = t.Format(time.RFC3339)
			out = append(out, i)
		}
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}
