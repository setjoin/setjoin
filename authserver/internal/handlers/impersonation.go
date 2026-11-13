package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"setjoin.com/shared/httputil"
	"setjoin.com/shared/jwtutil"
)

// impersonationHandler owns admin impersonation: the privilege-tier guard
// (impersonationRank, a free function shared with the package) and the
// scope-constrained impersonation token. It never grants admin authority.

// superAdminGroupID is the builtin Super Admin role group (AllPermissions),
// seeded as id 1 in V001. Holding an unexpired governed assignment to this group
// is the only way to reach the top impersonation tier.
const superAdminGroupID = 1

// resolveImpersonationTier derives a user's privilege tier inputs from its
// GOVERNED, unexpired admin_role_assignments (the users.admin_role enum is gone).
// It returns (hasGoverned, isSuperAdminGroup): hasGoverned is true if the user
// holds any unexpired governed assignment; isSuperAdminGroup is true if one of
// those assignments is to the Super Admin builtin group. Both feed
// impersonationRank. Fails closed: a query error is returned so the caller denies.
func (h *deps) resolveImpersonationTier(ctx context.Context, userID int64) (hasGoverned, isSuperAdminGroup bool, err error) {
	qerr := h.pool.QueryRow(ctx,
		`SELECT
		   EXISTS(
		     SELECT 1 FROM admin_role_assignments ara
		      WHERE ara.user_id = $1
		        AND (ara.expires_at IS NULL OR ara.expires_at > now())
		   ),
		   EXISTS(
		     SELECT 1 FROM admin_role_assignments ara
		      WHERE ara.user_id = $1
		        AND ara.role_group_id = $2
		        AND (ara.expires_at IS NULL OR ara.expires_at > now())
		   )`,
		userID, superAdminGroupID,
	).Scan(&hasGoverned, &isSuperAdminGroup)
	if qerr != nil {
		return false, false, qerr
	}
	return hasGoverned, isSuperAdminGroup, nil
}

// AdminImpersonate issues a short-lived access token for an admin to view
// another user's mailbox. Requires admin authentication. Logs to audit_log.
func (h *impersonationHandler) AdminImpersonate(w http.ResponseWriter, r *http.Request) {
	adminClaims := tokenClaims(r)
	if adminClaims == nil || !adminClaims.IsAdmin {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "admin access required"})
		return
	}
	targetID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid user ID"})
		return
	}
	if targetID == adminClaims.UserID {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "cannot impersonate yourself"})
		return
	}

	// Re-validate admin status against current DB state
	// (defense-in-depth: JWT may be stale if admin was demoted/disabled).
	// Also derive the actor's privilege TIER from its governed admin_role_assignments
	// (the users.admin_role enum is gone) so we can enforce the no-upward/equal
	// privilege-escalation rule below.
	var adminEnabled bool
	var adminIsAdmin bool
	actorGoverned, actorSuper, err := h.resolveImpersonationTier(r.Context(), adminClaims.UserID)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "admin access required"})
		return
	}
	// is_admin is DERIVED from admin_role_assignments (isAdminExprSQL), NOT the
	// vestigial users.is_admin column — the RBAC cut-over left that column
	// DEFAULT false NOT NULL and the grant path (AssignMember/SSO) never sets it,
	// so reading it denied EVERY governed/SSO-provisioned admin (the only kind the
	// modern model produces). This is the same canonical derivation the JWT mint
	// (lookupUser), session.Me, and resolveImpersonationTier use.
	if err := h.pool.QueryRow(r.Context(),
		"SELECT enabled, "+isAdminExprSQL+" FROM users WHERE id = $1",
		adminClaims.UserID,
	).Scan(&adminEnabled, &adminIsAdmin); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "admin access required"})
		return
	}
	if !adminEnabled || !adminIsAdmin {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "admin access required"})
		return
	}

	// Load the target together with its privilege so we can refuse
	// cross-or-upward admin impersonation (privilege escalation guard).
	var targetEmail string
	var targetIsAdmin bool
	if err := h.pool.QueryRow(r.Context(),
		`SELECT email, `+isAdminExprSQL+` FROM users WHERE id = $1`, targetID,
	).Scan(&targetEmail, &targetIsAdmin); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "user not found"})
		return
	}
	targetGoverned, targetSuper, err := h.resolveImpersonationTier(r.Context(), targetID)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "privilege resolution failed"})
		return
	}

	// Privilege-escalation guard (safe default — refuse cross-or-upward admin
	// impersonation). An admin may impersonate a strictly less-privileged
	// account, but never one whose privilege is >= their own. This blocks an
	// admin from minting a session for a peer/super-admin (which, combined with
	// an MFA-less impersonation cookie, would be a lateral/upward takeover).
	// The tier is derived from governed admin_role_assignments; a user with
	// is_admin but no governed row is treated as a floor admin tier so the
	// retained is_admin flag still gates upward jumps.
	actorRank := impersonationRank(adminIsAdmin, actorGoverned, actorSuper)
	targetRank := impersonationRank(targetIsAdmin, targetGoverned, targetSuper)
	if targetRank >= actorRank {
		h.logger.Warn("impersonation refused: target privilege >= actor privilege",
			"actor_id", adminClaims.UserID, "actor_rank", actorRank,
			"target_id", targetID, "target_rank", targetRank)
		// Audit the refusal so attempted escalations are visible.
		h.pool.Exec(r.Context(),
			`INSERT INTO audit_log (user_id, source_ip, event_type, metadata)
			 VALUES ($1, $2::INET, 'admin_impersonate_denied', jsonb_build_object('target_user_id',$3::bigint,'reason','privilege_escalation'))`,
			adminClaims.UserID, httputil.ClientIP(r), targetID)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "cannot impersonate a user with equal or higher privilege"})
		return
	}

	// Guest Accounts P13: derive the target's acct claim from the satellite so
	// impersonating a guest yields a guest-claimed token (the chain.go belt
	// would force it anyway; this keeps the fast-path claim honest).
	var targetIsGuest bool
	if err := h.pool.QueryRow(r.Context(), `SELECT is_guest_account($1)`, targetID).Scan(&targetIsGuest); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "account type resolution failed"})
		return
	}
	accountType := ""
	if targetIsGuest {
		accountType = jwtutil.AccountTypeGuest
	}

	token, err := h.jwt.IssueImpersonation(targetID, targetEmail, adminClaims.UserID, accountType)
	if err != nil {
		h.logger.Error("impersonation token issue failed", "user", adminClaims.Email)
		h.logger.Debug("impersonation token issue debug", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "token issue failed"})
		return
	}

	// Defense-in-depth: the impersonation token MUST be scope-constrained — it
	// carries the actor (act) claim for audit but must never grant admin
	// authority. Refuse to hand out a token that resolves as admin. (The
	// admin_role claim no longer exists — the cut-over dropped it — so IsAdmin is
	// the remaining authority flag to assert is unset.)
	if issued, verr := h.jwt.Validate(token); verr != nil ||
		issued.IsAdmin || issued.AdminActorID == nil {
		h.logger.Error("impersonation token failed scope constraint, refusing",
			"actor_id", adminClaims.UserID, "target_id", targetID)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "token issue failed"})
		return
	}

	// Log impersonation to audit_log
	h.pool.Exec(r.Context(),
		`INSERT INTO audit_log (user_id, source_ip, event_type, metadata)
		 VALUES ($1, $2::INET, 'admin_impersonate', jsonb_build_object('target_user_id',$3::bigint,'target_email',$4::text))`,
		adminClaims.UserID, httputil.ClientIP(r), targetID, targetEmail)

	// Set the session cookie under the name the gateway auth chain + authserver
	// session actually read ("access_token") — NOT "auth_token", which nothing in
	// the system reads, so the impersonation session was silently never picked up
	// (the admin kept their own session). Reuses the one access-cookie helper so the
	// attributes (HttpOnly / Secure / SameSite=Strict) match a normal login; 900 s
	// matches the 15-min impersonation token TTL. This deliberately replaces the
	// admin's own access_token for the impersonation window.
	h.setAccessCookie(w, r, token, 900)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"target_email":  targetEmail,
		"expires_in":    900,
		"impersonating": true,
	})
}
