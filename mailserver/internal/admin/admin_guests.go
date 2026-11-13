// admin_guests.go — Guest Accounts G1 direct-invite administration.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/guestinvite"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
	"setjoin.com/shared/validate"
)

// GuestsHandler serves the admin guest invite, revoke, and domain-allowlist routes.
// pool is workerPool.Pool: all guest_invites access is a BYPASSRLS carve-out.
type GuestsHandler struct {
	pool      *pgxpool.Pool
	toggles   *toggle.FeatureFlags
	mc        *minio.Client
	bucket    string
	logger    *slog.Logger
	lifecycle guestLifecycleDrainer
}

type guestLifecycleDrainer interface {
	DrainUser(ctx context.Context, userID int64) error
}

func NewGuestsHandler(pool *pgxpool.Pool, toggles *toggle.FeatureFlags,
	mc *minio.Client, bucket string, logger *slog.Logger) *GuestsHandler {
	return &GuestsHandler{pool: pool, toggles: toggles, mc: mc, bucket: bucket, logger: logger}
}

// SetLifecycleDrainer wires the G5 post-commit immediate SFU attempt. The
// durable worker remains the convergence authority when this seam is nil or
// the attempt fails.
func (h *GuestsHandler) SetLifecycleDrainer(drainer guestLifecycleDrainer) {
	h.lifecycle = drainer
}

type createGuestRequest struct {
	Email       string     `json:"email"`
	DisplayName string     `json:"displayName"`
	ExpiresAt   *time.Time `json:"expiresAt"`
	ProfileID   *int64     `json:"profileId"`
}

type guestProfileAssignmentInput struct {
	ProfileID json.RawMessage `json:"profileId"`
}

type guestExtendInput struct {
	ExpiresAt time.Time `json:"expiresAt"`
}

type guestTransferInput struct {
	SponsorUserID int64 `json:"sponsorUserId"`
}

type guestReinviteInput struct {
	ExpiresAt *time.Time `json:"expiresAt"`
}

type guestInviteRevokeInput struct {
	ExpectedInviteID string `json:"expectedInviteId"`
}

func (h *GuestsHandler) Gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.toggles == nil || !h.toggles.IsEnabled(toggle.FeatureGuestAccounts) {
			httpProblem(w, r, http.StatusNotFound, "not found")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *GuestsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authorize(w, r)
	if !ok {
		return
	}
	var req createGuestRequest
	if err := decodeGuestJSON(w, r, &req); err != nil {
		httpProblem(w, r, http.StatusBadRequest, "invalid JSON body")
		return
	}
	validatedEmail, err := identity.ValidateAndCanonicalizeEmail(req.Email)
	if err != nil {
		if ve := new(validate.ValidationError); errors.As(err, &ve) {
			httpProblem(w, r, http.StatusBadRequest, ve.ToFieldError().Message)
		} else {
			httpProblem(w, r, http.StatusBadRequest, err.Error())
		}
		return
	}
	if req.ProfileID != nil && *req.ProfileID <= 0 {
		httpProblem(w, r, http.StatusBadRequest, "invalid profileId")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.writeDBErr(w, r, "begin guest invite", err)
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck

	allowed, err := checkGuestDomainAllowlist(r.Context(), tx, validatedEmail.String())
	if err != nil {
		h.writeDBErr(w, r, "check guest invite domain", err)
		return
	}
	if !allowed {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusForbidden,
			Type:   "BZ218",
			Detail: "invited domain is not in the guest invite allowlist",
		})
		return
	}
	guestExpiresAt := req.ExpiresAt
	if req.ProfileID != nil {
		var profile json.RawMessage
		if err := tx.QueryRow(r.Context(), `SELECT guest_profile_invite_snapshot($1,$2)`, claims.UserID, *req.ProfileID).Scan(&profile); err != nil {
			if reducererr.WriteClassified(w, r, err) {
				return
			}
			h.writeDBErr(w, r, "get guest invite profile", err)
			return
		}
		if guestExpiresAt == nil {
			var defaults struct {
				DefaultExpiryDays *int `json:"defaultExpiryDays"`
			}
			if err := json.Unmarshal(profile, &defaults); err != nil {
				h.writeDBErr(w, r, "decode guest invite profile", err)
				return
			}
			if defaults.DefaultExpiryDays != nil {
				expires := time.Now().UTC().Add(time.Duration(*defaults.DefaultExpiryDays) * 24 * time.Hour)
				guestExpiresAt = &expires
			}
		}
	}

	invitedBy := claims.UserID
	result, err := identity.ProvisionAccount(r.Context(), tx, identity.ProvisionAccountParams{
		Email:          validatedEmail,
		DisplayName:    req.DisplayName,
		Guest:          true,
		InvitedBy:      &invitedBy,
		GuestExpiresAt: guestExpiresAt,
		ActorID:        &invitedBy,
	})
	if err != nil {
		if reducererr.WriteClassified(w, r, err) {
			return
		}
		h.writeDBErr(w, r, "admin guest provision failed", err)
		return
	}
	var provisioned struct {
		UserID int64 `json:"user_id"`
	}
	if err := json.Unmarshal(result, &provisioned); err != nil {
		h.writeDBErr(w, r, "decode guest provision result", err)
		return
	}
	if provisioned.UserID == 0 {
		httpProblem(w, r, http.StatusInternalServerError, "guest provision returned no user")
		return
	}
	if req.ProfileID != nil {
		if _, err := tx.Exec(r.Context(), `SELECT guest_profile_apply($1,$2,$3)`,
			claims.UserID, provisioned.UserID, *req.ProfileID); err != nil {
			if reducererr.WriteClassified(w, r, err) {
				return
			}
			h.writeDBErr(w, r, "apply guest invite profile", err)
			return
		}
	}

	invite, err := guestinvite.Prepare(r.Context(), tx, claims.UserID, provisioned.UserID)
	if err != nil {
		if reducererr.WriteClassified(w, r, err) {
			return
		}
		h.writeDBErr(w, r, "prepare guest invite", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.writeDBErr(w, r, "commit guest invite", err)
		return
	}

	if err := guestinvite.Send(r.Context(), h.pool, h.mc, h.bucket, invite, validatedEmail.String()); err != nil {
		// The invite is already committed: keep it pending for resend/re-invite.
		// Do not log the opaque transport error: a sender can include the MIME
		// body (and therefore the raw invite token) in that error.
		if h.logger != nil {
			h.logger.Error("guest invite email failed", "user_id", provisioned.UserID, "error", "send_failed")
		}
		h.writeInviteDeliveryUnconfirmed(w, provisioned.UserID, invite)
		return
	}

	httputil.WriteJSON(w, http.StatusAccepted, map[string]any{
		"guestUserId":  provisioned.UserID,
		"inviteId":     invite.InviteIDString(),
		"invitedEmail": validatedEmail.String(),
		"expiresAt":    invite.ExpiresAt(),
	})
}

func checkGuestDomainAllowlist(ctx context.Context, tx pgx.Tx, email string) (bool, error) {
	_, domain, ok := strings.Cut(email, "@")
	if !ok {
		return false, nil
	}
	var allowed bool
	err := tx.QueryRow(ctx,
		`SELECT NOT EXISTS (SELECT 1 FROM guest_invite_domains)
		        OR EXISTS (SELECT 1 FROM guest_invite_domains WHERE domain=$1)`,
		strings.ToLower(domain)).Scan(&allowed)
	return allowed, err
}

func (h *GuestsHandler) DeleteInvite(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authorize(w, r)
	if !ok {
		return
	}
	guestUserID, err := strconv.ParseInt(r.PathValue("userId"), 10, 64)
	if err != nil || guestUserID <= 0 {
		httpProblem(w, r, http.StatusBadRequest, "invalid userId")
		return
	}
	var in guestInviteRevokeInput
	if err := decodeGuestJSON(w, r, &in); err != nil || in.ExpectedInviteID == "" {
		httpProblem(w, r, http.StatusBadRequest, "expectedInviteId is required")
		return
	}
	expectedInviteID, err := strconv.ParseInt(in.ExpectedInviteID, 10, 64)
	if err != nil || expectedInviteID <= 0 || strconv.FormatInt(expectedInviteID, 10) != in.ExpectedInviteID {
		httpProblem(w, r, http.StatusBadRequest, "invalid expectedInviteId")
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.writeDBErr(w, r, "begin guest invite revoke", err)
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck
	// Make the handler's cross-tenant boundary explicit for the admin reach
	// coverage guard and return the same non-oracular denial before entering the
	// reducer. guest_invite_revoke repeats admin_can_reach while holding the guest
	// and user rows, so this UX preflight is never the mutation's TOCTOU authority.
	var canReach bool
	if err := tx.QueryRow(r.Context(), `SELECT admin_can_reach($1,$2)`,
		claims.UserID, guestUserID).Scan(&canReach); err != nil {
		h.writeDBErr(w, r, "guest invite revoke reach check failed", err)
		return
	}
	if !canReach {
		httpProblem(w, r, http.StatusForbidden, "forbidden")
		return
	}
	var result string
	if err := tx.QueryRow(r.Context(), `SELECT guest_invite_revoke($1,$2,$3)`,
		claims.UserID, guestUserID, expectedInviteID).Scan(&result); err != nil {
		if reducererr.WriteClassified(w, r, err) {
			return
		}
		h.writeDBErr(w, r, "guest invite revoke failed", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.writeDBErr(w, r, "commit guest invite revoke", err)
		return
	}
	switch result {
	case "revoked":
		w.WriteHeader(http.StatusOK)
	case "not_found":
		httpProblem(w, r, http.StatusNotFound, "no pending invite for this guest")
	case "stale":
		httpProblem(w, r, http.StatusConflict, "invitation changed; refresh before revoking")
	default:
		h.writeDBErr(w, r, "classify guest invite revoke", errors.New("unknown revoke result"))
	}
}

func (h *GuestsHandler) AddInviteDomain(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authorize(w, r)
	if !ok {
		return
	}
	var req struct {
		Domain string `json:"domain"`
	}
	if err := decodeGuestJSON(w, r, &req); err != nil {
		httpProblem(w, r, http.StatusBadRequest, "domain is required")
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if err := validate.ValidateDomain(domain); err != nil {
		httpProblem(w, r, http.StatusBadRequest, err.Error())
		return
	}
	var hostDomainID int64
	var actorEmail string
	if err := h.pool.QueryRow(r.Context(),
		`SELECT domain_id, email FROM users WHERE id=$1`, claims.UserID,
	).Scan(&hostDomainID, &actorEmail); err != nil {
		h.writeDBErr(w, r, "resolve guest domain actor", err)
		return
	}
	if _, err := h.pool.Exec(r.Context(),
		`SELECT guest_invite_domain_set($1,$2,$3,$4,FALSE)`,
		claims.UserID, domain, hostDomainID, actorEmail); err != nil {
		if reducererr.WriteClassified(w, r, err) {
			return
		}
		h.writeDBErr(w, r, "add guest invite domain", err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]string{"domain": domain})
}

func (h *GuestsHandler) RemoveInviteDomain(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authorize(w, r)
	if !ok {
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	if err := validate.ValidateDomain(domain); err != nil {
		httpProblem(w, r, http.StatusBadRequest, "invalid domain")
		return
	}
	if _, err := h.pool.Exec(r.Context(),
		`SELECT guest_invite_domain_set($1,$2,0,'',TRUE)`, claims.UserID, domain); err != nil {
		if reducererr.WriteClassified(w, r, err) {
			return
		}
		h.writeDBErr(w, r, "remove guest invite domain", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *GuestsHandler) List(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authorizeRead(w, r)
	if !ok {
		return
	}
	h.writeGuestJSON(w, r, "list guests", `
		SELECT COALESCE(jsonb_agg(jsonb_build_object(
		  'id',g.user_id,'displayName',u.display_name,'invitedEmail',g.invited_email,
		  'status',g.status,'effectiveStatus',CASE WHEN g.expires_at < now() THEN 'expired' ELSE g.status END,
		  'expiresAt',g.expires_at,'sponsorUserId',g.sponsor_user_id,
		  'sponsorDisplayName',s.display_name,
		  'sponsorNeedsReview',(s.id IS NULL OR NOT s.enabled OR is_guest_account(s.id)),
		  'profileId',g.profile_id,'profileName',gp.name,
		  'pendingInvite',EXISTS(SELECT 1 FROM guest_invites gi
		    WHERE gi.guest_user_id=g.user_id AND gi.used_at IS NULL AND gi.expires_at > now()),
		  'channelGrantCount',(SELECT count(*) FROM chat_channel_members cm WHERE cm.user_id=g.user_id),
		  'createdAt',g.created_at,'updatedAt',g.updated_at
		) ORDER BY lower(u.display_name),g.user_id),'[]'::jsonb)
		FROM guest_accounts g JOIN users u ON u.id=g.user_id
		LEFT JOIN users s ON s.id=g.sponsor_user_id
		LEFT JOIN guest_profiles gp ON gp.id=g.profile_id
		WHERE guest_admin_can_reach_with_permission($1,g.user_id,'guests.view')
		   OR guest_admin_can_reach_with_permission($1,g.user_id,'guests.manage')`, claims.UserID)
}

func (h *GuestsHandler) Get(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authorizeRead(w, r)
	if !ok {
		return
	}
	id, ok := positivePathID(w, r, "id")
	if !ok {
		return
	}
	var out json.RawMessage
	err := h.pool.QueryRow(r.Context(), `
		SELECT jsonb_build_object(
		  'id',g.user_id,'displayName',u.display_name,'invitedEmail',g.invited_email,
		  'invitedBy',g.invited_by,'invitedByEmail',g.invited_by_email,
		  'status',g.status,'effectiveStatus',CASE WHEN g.expires_at < now() THEN 'expired' ELSE g.status END,
		  'expiresAt',g.expires_at,'sponsorUserId',g.sponsor_user_id,
		  'sponsorDisplayName',s.display_name,
		  'sponsorNeedsReview',(s.id IS NULL OR NOT s.enabled OR is_guest_account(s.id)),
		  'profileId',g.profile_id,'profileName',gp.name,
		  'pendingInvite',(SELECT jsonb_build_object(
		      'inviteId',gi.id::text,'expiresAt',gi.expires_at,'createdAt',gi.created_at,
		      'createdByEmail',CASE WHEN gi.created_by IS NOT NULL
		        AND admin_can_reach($1,gi.created_by) THEN gi.created_by_email ELSE NULL END)
		    FROM guest_invites gi WHERE gi.guest_user_id=g.user_id AND gi.used_at IS NULL
		      AND gi.expires_at > now()
		    ORDER BY gi.created_at DESC LIMIT 1),
		  'inviteHistory',(SELECT COALESCE(jsonb_agg(h.item ORDER BY h.created_at DESC,h.id DESC),'[]'::jsonb)
		    FROM (SELECT gi.id,gi.created_at,jsonb_build_object(
		      'inviteId',gi.id::text,
		      'state',CASE
		        WHEN gi.used_at IS NULL AND gi.expires_at <= now() THEN 'expired'
		        WHEN gi.used_at IS NULL THEN 'pending'
		        WHEN gi.terminal_reason = 'legacy_unknown' THEN 'unknown'
		        ELSE gi.terminal_reason END,
		      'createdAt',gi.created_at,'expiresAt',gi.expires_at,
		      'terminalAt',CASE
		        WHEN gi.used_at IS NULL AND gi.expires_at <= now() THEN gi.expires_at
		        WHEN gi.used_at IS NULL THEN NULL ELSE gi.used_at END,
		      'createdByEmail',CASE WHEN gi.created_by IS NOT NULL
		        AND admin_can_reach($1,gi.created_by) THEN gi.created_by_email ELSE NULL END
		    ) AS item FROM guest_invites gi WHERE gi.guest_user_id=g.user_id
		      ORDER BY gi.created_at DESC,gi.id DESC LIMIT 10) h),
		  'inviteHistoryHasMore',EXISTS(SELECT 1 FROM guest_invites gi
		    WHERE gi.guest_user_id=g.user_id ORDER BY gi.created_at DESC,gi.id DESC OFFSET 10 LIMIT 1),
		  'channelGrantCount',(SELECT count(*) FROM chat_channel_members cm WHERE cm.user_id=g.user_id),
		  'channelGrants',(SELECT COALESCE(jsonb_agg(jsonb_build_object(
		    'channelId',c.id,'kind',c.kind,'name',c.name,'role',cm.role,
		    'canPost',cm.can_post,'historyFloorSeq',cm.history_floor_seq
		  ) ORDER BY c.id),'[]'::jsonb) FROM chat_channel_members cm
		    JOIN chat_channels c ON c.id=cm.channel_id WHERE cm.user_id=g.user_id),
		  'appEntitlements',(SELECT jsonb_object_agg(apps.app,COALESCE(e.enabled,false) ORDER BY apps.app)
		    FROM (VALUES ('mail'),('calendar'),('contacts'),('tasks'),('chat'),('drive'),('meet')) apps(app)
		    LEFT JOIN user_app_entitlements e ON e.user_id=g.user_id AND e.app=apps.app),
		  'createdAt',g.created_at,'updatedAt',g.updated_at
		)
		FROM guest_accounts g JOIN users u ON u.id=g.user_id
		LEFT JOIN users s ON s.id=g.sponsor_user_id
		LEFT JOIN guest_profiles gp ON gp.id=g.profile_id
		WHERE g.user_id=$2
		  AND (guest_admin_can_reach_with_permission($1,g.user_id,'guests.view')
		       OR guest_admin_can_reach_with_permission($1,g.user_id,'guests.manage'))`, claims.UserID, id).Scan(&out)
	if errors.Is(err, pgx.ErrNoRows) {
		httpProblem(w, r, http.StatusNotFound, "guest not found")
		return
	}
	if err != nil {
		h.writeDBErr(w, r, "get guest", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

func (h *GuestsHandler) Disable(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, "disable", nil)
}

// Reinvite is the explicit credential-recovery transition for an existing
// guest. Lifecycle freeze/session revocation and replacement invite creation
// share one transaction; the raw token exists only in Prepared and the email.
func (h *GuestsHandler) Reinvite(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authorize(w, r)
	if !ok {
		return
	}
	id, ok := positivePathID(w, r, "id")
	if !ok {
		return
	}
	var in guestReinviteInput
	if err := decodeGuestJSON(w, r, &in); err != nil {
		httpProblem(w, r, http.StatusBadRequest, "invalid JSON body")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.writeDBErr(w, r, "begin guest recovery", err)
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck

	if _, err := tx.Exec(r.Context(), `SELECT guest_set_status($1,$2,'reinvite',$3)`,
		claims.UserID, id, in.ExpiresAt); err != nil {
		h.writeReducerErr(w, r, "re-arm guest recovery", err)
		return
	}
	var invitedEmail string
	if err := tx.QueryRow(r.Context(),
		`SELECT invited_email FROM guest_accounts WHERE user_id=$1`, id,
	).Scan(&invitedEmail); err != nil {
		h.writeDBErr(w, r, "resolve guest recovery email", err)
		return
	}
	invite, err := guestinvite.Prepare(r.Context(), tx, claims.UserID, id)
	if err != nil {
		if reducererr.WriteClassified(w, r, err) {
			return
		}
		h.writeDBErr(w, r, "prepare guest recovery invite", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.writeDBErr(w, r, "commit guest recovery", err)
		return
	}

	// Evict before doing token-bearing mail work so a slow queue/store cannot
	// extend the stale-session window after the recovery transition commits.
	if h.lifecycle != nil {
		attemptCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		err := h.lifecycle.DrainUser(attemptCtx, id)
		cancel()
		if err != nil {
			logger := h.logger
			if logger == nil {
				logger = slog.Default()
			}
			logger.Warn("guest recovery committed; immediate SFU eviction deferred to durable worker",
				"guest_user_id", id, "error", err)
		}
	}
	if err := guestinvite.Send(r.Context(), h.pool, h.mc, h.bucket, invite, invitedEmail); err != nil {
		// Never log the transport error: it may contain the token-bearing MIME.
		if h.logger != nil {
			h.logger.Error("guest recovery email failed", "user_id", id, "error", "send_failed")
		}
		h.writeInviteDeliveryUnconfirmed(w, id, invite)
		return
	}

	httputil.WriteJSON(w, http.StatusAccepted, map[string]any{
		"guestUserId": id,
		"inviteId":    invite.InviteIDString(),
		"expiresAt":   invite.ExpiresAt(),
	})
}

func (h *GuestsHandler) writeInviteDeliveryUnconfirmed(w http.ResponseWriter, guestUserID int64, invite guestinvite.Prepared) {
	httputil.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{
		"code":        "invite_delivery_unconfirmed",
		"retryable":   true,
		"inviteId":    invite.InviteIDString(),
		"guestUserId": guestUserID,
		"error":       "invitation created; email delivery could not be confirmed",
	})
}

func (h *GuestsHandler) Enable(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, "enable", nil)
}

func (h *GuestsHandler) Extend(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r); !ok {
		return
	}
	var in guestExtendInput
	if err := decodeGuestJSON(w, r, &in); err != nil || in.ExpiresAt.IsZero() {
		httpProblem(w, r, http.StatusBadRequest, "expiresAt is required")
		return
	}
	h.setStatusAuthorized(w, r, "extend", &in.ExpiresAt)
}

func (h *GuestsHandler) setStatus(w http.ResponseWriter, r *http.Request, action string, expiresAt *time.Time) {
	if _, ok := h.authorize(w, r); !ok {
		return
	}
	h.setStatusAuthorized(w, r, action, expiresAt)
}

func (h *GuestsHandler) setStatusAuthorized(w http.ResponseWriter, r *http.Request, action string, expiresAt *time.Time) {
	claims := auth.UserFromContext(r.Context())
	id, ok := positivePathID(w, r, "id")
	if !ok {
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.writeDBErr(w, r, "begin guest status change", err)
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck
	if err := acquireAdminAuthorityFence(r.Context(), tx); err != nil {
		h.writeDBErr(w, r, "fence guest status change", err)
		return
	}
	var lockedID int64
	err = tx.QueryRow(r.Context(), `SELECT g.user_id FROM guest_accounts g
		WHERE g.user_id=$2
		  AND guest_admin_can_reach_with_permission($1,g.user_id,'guests.manage')
		FOR UPDATE`, claims.UserID, id).Scan(&lockedID)
	if errors.Is(err, pgx.ErrNoRows) {
		httpProblem(w, r, http.StatusNotFound, "guest not found")
		return
	}
	if err != nil {
		h.writeDBErr(w, r, "lock guest status target", err)
		return
	}
	if _, err := tx.Exec(r.Context(), `SELECT guest_set_status($1,$2,$3,$4)`,
		claims.UserID, id, action, expiresAt); err != nil {
		h.writeReducerErr(w, r, "set guest status", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.writeDBErr(w, r, "commit guest status change", err)
		return
	}
	if (action == "disable" || action == "expire") && h.lifecycle != nil {
		attemptCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		err := h.lifecycle.DrainUser(attemptCtx, id)
		cancel()
		if err != nil {
			logger := h.logger
			if logger == nil {
				logger = slog.Default()
			}
			logger.Warn("guest lifecycle transition committed; immediate SFU eviction deferred to durable worker",
				"guest_user_id", id, "action", action, "error", err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// SponsorOptions lists enabled ordinary members that the same guests.manage
// assignment can reach together with this guest.
func (h *GuestsHandler) SponsorOptions(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authorize(w, r)
	if !ok {
		return
	}
	id, ok := positivePathID(w, r, "id")
	if !ok {
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > 200 {
		httpProblem(w, r, http.StatusBadRequest, "q is too long")
		return
	}
	rows, err := h.pool.Query(r.Context(), `
		SELECT u.id, u.email, u.display_name
		  FROM users u
		 WHERE u.enabled
		   AND NOT is_guest_account(u.id)
		   AND guest_admin_can_transfer_to($1,$2,u.id)
		   AND ($3='' OR u.email ILIKE '%'||$3||'%' OR u.display_name ILIKE '%'||$3||'%')
		 ORDER BY lower(u.display_name), u.id
		 LIMIT 50`, claims.UserID, id, q)
	if err != nil {
		h.writeDBErr(w, r, "list guest sponsor options", err)
		return
	}
	defer rows.Close()
	type option struct {
		ID          int64  `json:"id"`
		Email       string `json:"email"`
		DisplayName string `json:"displayName"`
	}
	options := make([]option, 0)
	for rows.Next() {
		var out option
		if err := rows.Scan(&out.ID, &out.Email, &out.DisplayName); err != nil {
			h.writeDBErr(w, r, "scan guest sponsor option", err)
			return
		}
		options = append(options, out)
	}
	if err := rows.Err(); err != nil {
		h.writeDBErr(w, r, "list guest sponsor options rows", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, options)
}

// Transfer atomically changes sponsorship and the guest-owned Chat/Drive
// authority columns named by the G5 specification.
func (h *GuestsHandler) Transfer(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authorize(w, r)
	if !ok {
		return
	}
	id, ok := positivePathID(w, r, "id")
	if !ok {
		return
	}
	var in guestTransferInput
	if err := decodeGuestJSON(w, r, &in); err != nil || in.SponsorUserID <= 0 {
		httpProblem(w, r, http.StatusBadRequest, "positive sponsorUserId is required")
		return
	}
	var out json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT guest_transfer($1,$2,$3)`,
		claims.UserID, id, in.SponsorUserID).Scan(&out); err != nil {
		h.writeReducerErr(w, r, "transfer guest", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

func (h *GuestsHandler) AssignProfile(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authorize(w, r)
	if !ok {
		return
	}
	id, ok := positivePathID(w, r, "id")
	if !ok {
		return
	}
	var in guestProfileAssignmentInput
	if err := decodeGuestJSON(w, r, &in); err != nil {
		httpProblem(w, r, http.StatusBadRequest, "invalid JSON body")
		return
	}
	profileID, err := decodeNullablePositiveID(in.ProfileID)
	if err != nil {
		httpProblem(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := h.pool.Exec(r.Context(), `SELECT guest_profile_apply($1,$2,$3)`,
		claims.UserID, id, profileID); err != nil {
		h.writeReducerErr(w, r, "assign guest profile", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *GuestsHandler) writeGuestJSON(w http.ResponseWriter, r *http.Request, message, query string, args ...any) {
	var out json.RawMessage
	if err := h.pool.QueryRow(r.Context(), query, args...).Scan(&out); err != nil {
		h.writeDBErr(w, r, message, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

func (h *GuestsHandler) writeReducerErr(w http.ResponseWriter, r *http.Request, message string, err error) {
	if reducererr.WriteClassified(w, r, err) {
		return
	}
	h.writeDBErr(w, r, message, err)
}

func (h *GuestsHandler) authorize(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	if h.toggles == nil || !h.toggles.IsEnabled(toggle.FeatureGuestAccounts) {
		httpProblem(w, r, http.StatusNotFound, "not found")
		return nil, false
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil || !claims.HasPermission(permissions.PermGuestsManage) {
		httpProblem(w, r, http.StatusForbidden, "guests.manage required")
		return nil, false
	}
	return claims, true
}

func (h *GuestsHandler) authorizeRead(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	if h.toggles == nil || !h.toggles.IsEnabled(toggle.FeatureGuestAccounts) {
		httpProblem(w, r, http.StatusNotFound, "not found")
		return nil, false
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil || (!claims.HasPermission(permissions.PermGuestsView) &&
		!claims.HasPermission(permissions.PermGuestsManage)) {
		httpProblem(w, r, http.StatusForbidden, "guests.view required")
		return nil, false
	}
	return claims, true
}

func (h *GuestsHandler) writeDBErr(w http.ResponseWriter, r *http.Request, message string, err error) {
	logger := h.logger
	if logger == nil {
		logger = slog.Default()
	}
	httputil.WriteDBErr(w, r, logger, message, err)
}

func httpProblem(w http.ResponseWriter, r *http.Request, status int, detail string) {
	httputil.WriteProblem(w, r, &httputil.Problem{Status: status, Detail: detail})
}

func decodeGuestJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}
