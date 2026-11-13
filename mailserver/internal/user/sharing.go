package user

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

// SharingHandler is the END-USER sharing/delegation surface (spec
// 2026-06-27-sharing-delegation-design.md §6): mailbox delegate grant/revoke
// (the §2.2 gap — populates the mailbox_delegates table send.sql already
// enforces), the user's own default-visibility rows (owner_scope='user'), and
// the who-can-see panel data (§6-C). Every mutation goes through a reducer
// whose ownership check rides in the mutation's own WHERE (R1–R3); the actor
// is always claims.UserID, never req.* (R2). Constructed on the workerPool
// (BYPASSRLS, native-RLS V090): mailbox_delegates and sharing_defaults are
// FORCE'd and this surface has no GUC seam — every query/reducer here is
// R1-scoped to claims.UserID (cross-mailbox-for-one-user, the W7 user
// self-service class). INERT until DB_WORKER_DSN is set.
type SharingHandler struct {
	pool   *pgxpool.Pool
	flags  *toggle.FeatureFlags
	logger *slog.Logger
}

// NewSharingHandler creates a SharingHandler.
func NewSharingHandler(workerPool pgxutil.WorkerPool, flags *toggle.FeatureFlags, logger *slog.Logger) *SharingHandler {
	return &SharingHandler{pool: workerPool.Pool, flags: flags, logger: logger}
}

type sharingDelegateRow struct {
	UserID     int64  `json:"userId"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	Permission string `json:"permission"`
	GrantedAt  string `json:"grantedAt"`
}

type sharingCalendarGrantRow struct {
	CalendarID   int64  `json:"calendarId"`
	CalendarName string `json:"calendarName"`
	UserEmail    string `json:"userEmail"`
	UserName     string `json:"userName"`
	Level        string `json:"level"`
}

type sharingDefaultRow struct {
	ID          int64  `json:"id"`
	OwnerScope  string `json:"ownerScope"`
	Audience    string `json:"audience"`
	AudienceRef int64  `json:"audienceRef"`
	Level       string `json:"level"`
}

type sharingOverview struct {
	Delegates         []sharingDelegateRow      `json:"delegates"`
	CalendarGrants    []sharingCalendarGrantRow `json:"calendarGrants"`
	MyDefaults        []sharingDefaultRow       `json:"myDefaults"`
	InheritedDefaults []sharingDefaultRow       `json:"inheritedDefaults"`
	DefaultsEnabled   bool                      `json:"defaultsEnabled"`
}

// Overview implements GET /me/sharing — the §6-C "who can see my calendar /
// mail" panel data: mailbox delegates, explicit calendar grantees, the
// caller's own user-scope defaults, and the inherited org/OU/group defaults
// that currently apply to them as an owner.
func (h *SharingHandler) Overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	if user == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	out := sharingOverview{
		Delegates:         []sharingDelegateRow{},
		CalendarGrants:    []sharingCalendarGrantRow{},
		MyDefaults:        []sharingDefaultRow{},
		InheritedDefaults: []sharingDefaultRow{},
		DefaultsEnabled:   h.flags.IsEnabled(toggle.FeatureSharingDefaults),
	}

	// R1: every list is scoped to the caller's own mailboxes/rows.
	rows, err := h.pool.Query(ctx, `
		SELECT u.id, u.email, u.display_name, md.permission, md.granted_at::TEXT
		FROM mailbox_delegates md
		JOIN mailboxes m ON m.id = md.mailbox_id
		JOIN users u ON u.id = md.user_id
		WHERE m.user_id = $1
		ORDER BY u.email, md.permission`, user.UserID)
	if err != nil {
		h.logger.Error("sharing overview delegates failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	for rows.Next() {
		var d sharingDelegateRow
		if err := rows.Scan(&d.UserID, &d.Email, &d.Name, &d.Permission, &d.GrantedAt); err == nil {
			out.Delegates = append(out.Delegates, d)
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
		ORDER BY c.id, u.email`, user.UserID)
	if err != nil {
		h.logger.Error("sharing overview grants failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	for rows.Next() {
		var g sharingCalendarGrantRow
		if err := rows.Scan(&g.CalendarID, &g.CalendarName, &g.UserEmail, &g.UserName, &g.Level); err == nil {
			out.CalendarGrants = append(out.CalendarGrants, g)
		}
	}
	rows.Close()

	// Own user-scope rows + the inherited (org/ou/group) rows that match the
	// caller AS OWNER — the §6-A "Org default: … — your setting overrides it"
	// status line data.
	rows, err = h.pool.Query(ctx, `
		SELECT sd.id, sd.owner_scope, sd.audience, sd.audience_ref, sd.level
		FROM sharing_defaults sd
		JOIN users me ON me.id = $1
		WHERE sd.resource = 'calendar'
		  AND (   (sd.owner_scope = 'user'  AND sd.owner_ref = me.id)
		       OR (sd.owner_scope = 'org'   AND sd.owner_ref = me.domain_id)
		       OR (sd.owner_scope = 'ou'    AND sd.owner_ref = me.department_id)
		       OR (sd.owner_scope = 'group' AND EXISTS (
		             SELECT 1 FROM distribution_group_members dgm
		             JOIN mailboxes mm ON mm.id = dgm.mailbox_id
		             WHERE dgm.group_id = sd.owner_ref AND mm.user_id = me.id)))
		ORDER BY sd.id`, user.UserID)
	if err != nil {
		h.logger.Error("sharing overview defaults failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	for rows.Next() {
		var d sharingDefaultRow
		if err := rows.Scan(&d.ID, &d.OwnerScope, &d.Audience, &d.AudienceRef, &d.Level); err == nil {
			if d.OwnerScope == "user" {
				out.MyDefaults = append(out.MyDefaults, d)
			} else {
				out.InheritedDefaults = append(out.InheritedDefaults, d)
			}
		}
	}
	rows.Close()

	httputil.WriteJSON(w, http.StatusOK, out)
}

// GrantDelegate implements POST /me/sharing/delegates. The mailbox is always
// the caller's primary mailbox (R2 — never client-chosen); the reducer's
// ownership backstop (BZ114) still rides in the same statement.
func (h *SharingHandler) GrantDelegate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	if user == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req struct {
		GranteeEmail string `json:"granteeEmail"`
		Permission   string `json:"permission"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.GranteeEmail == "" {
		httputil.WriteError(w, http.StatusBadRequest, "granteeEmail and permission are required")
		return
	}
	mbID, err := identity.ResolvePrimaryMailbox(ctx, h.pool, user.UserID)
	if err != nil {
		h.logger.Error("sharing grant: resolve mailbox failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "mailbox not found")
		return
	}
	if _, err := h.pool.Exec(ctx,
		`SELECT mailbox_delegate_grant($1, $2, $3, $4)`,
		user.UserID, mbID, req.GranteeEmail, req.Permission); err != nil {
		h.logger.Info("sharing grant rejected", "error", err)
		httputil.WriteError(w, reducerErrorStatus(err), reducererr.Detail(err))
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// RevokeDelegate implements DELETE /me/sharing/delegates/{userId} — removes
// ALL of the grantee's permission rows on the caller's primary mailbox.
func (h *SharingHandler) RevokeDelegate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	if user == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	granteeID, err := strconv.ParseInt(r.PathValue("userId"), 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	mbID, err := identity.ResolvePrimaryMailbox(ctx, h.pool, user.UserID)
	if err != nil {
		h.logger.Error("sharing revoke: resolve mailbox failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "mailbox not found")
		return
	}
	if _, err := h.pool.Exec(ctx,
		`SELECT mailbox_delegate_revoke($1, $2, $3)`,
		user.UserID, mbID, granteeID); err != nil {
		h.logger.Info("sharing revoke rejected", "error", err)
		httputil.WriteError(w, reducerErrorStatus(err), reducererr.Detail(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetDefault implements PUT /me/sharing/default — upserts the caller's own
// user-scope default (§6-A). audienceRef defaults to the caller's domain for
// audience=everyone (D7); owner scope/ref are forced server-side (R2).
func (h *SharingHandler) SetDefault(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	if user == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req struct {
		Audience    string `json:"audience"`
		AudienceRef int64  `json:"audienceRef"`
		Level       string `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Audience == "everyone" && req.AudienceRef == 0 {
		if err := h.pool.QueryRow(ctx,
			`SELECT domain_id FROM users WHERE id = $1`, user.UserID).Scan(&req.AudienceRef); err != nil {
			h.logger.Error("sharing default: resolve domain failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "database error")
			return
		}
	}
	var id int64
	if err := h.pool.QueryRow(ctx,
		`SELECT sharing_default_set($1, 'calendar', 'user', $1, $2, $3, $4)`,
		user.UserID, req.Audience, req.AudienceRef, req.Level).Scan(&id); err != nil {
		h.logger.Info("sharing default set rejected", "error", err)
		httputil.WriteError(w, reducerErrorStatus(err), reducererr.Detail(err))
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]int64{"id": id})
}

// ClearDefault implements DELETE /me/sharing/default/{id}. The reducer's auth
// ladder (BZ116) rejects clearing a row the caller does not own.
func (h *SharingHandler) ClearDefault(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := auth.UserFromContext(ctx)
	if user == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if _, err := h.pool.Exec(ctx,
		`SELECT sharing_default_clear($1, $2)`, user.UserID, id); err != nil {
		h.logger.Info("sharing default clear rejected", "error", err)
		httputil.WriteError(w, reducerErrorStatus(err), reducererr.Detail(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
