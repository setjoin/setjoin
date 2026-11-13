package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/httputil"
)

// sessionHandler owns the established-session lifecycle: refresh-token rotation,
// logout (revoke-all), and the /auth/me profile read. Token revocation/rotation
// funnels through the Wave-3 TokenService (h.svc); no oauth_tokens SQL lives here.

// Refresh handles refresh token rotation.
func (h *sessionHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	// Shared bounded auth ingress (MaxBytesReader BEFORE decode): /auth/refresh
	// is unauthenticated, so an unbounded decode here was a request-memory
	// exhaustion primitive — the same resource-exhaustion class Login closes
	// with decodeBoundedAuthJSON.
	if !decodeBoundedAuthJSON(w, r, &req) {
		return
	}

	result, err := h.svc.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "invalid or revoked refresh token"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"expires_in":    result.ExpiresIn,
	})
}

// SessionToken is the per-tab DPoP admission-recovery read (GET
// /auth/session/token, r3). The session cookie is shared by every tab of the
// browser profile, but the RFC 9449 ath source is per-tab (sessionStorage):
// a freshly opened tab holds the cookie and the persisted binding key yet NO
// token string, and a stale tab holds a string another tab's refresh already
// rotated away — both mint inadmissible proofs and fail authentication with
// no way back. This read hands the PRESENTED string back through the
// admission-recovery funnel (AuthenticateAdmissionRecovery: everything the
// regular funnel enforces except the ath claim — a cnf-bound token still
// requires a proof bound to its cnf.jkt), so the tab re-derives its ath
// source without minting or rotating anything and the other tabs' view of
// the session is untouched. NOT mounted behind requireAuth deliberately:
// requireAuth enforces the very ath claim the recovering tab cannot compute
// yet; the handler self-authenticates through the recovery funnel instead.
func (h *sessionHandler) SessionToken(w http.ResponseWriter, r *http.Request) {
	if _, err := h.sessionAuthenticator().AuthenticateAdmissionRecovery(r); err != nil {
		if errors.Is(err, token.ErrWrongTokenType) {
			httputil.WriteProblemStatus(w, http.StatusForbidden, "Invalid token type")
			return
		}
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	// The authenticated string is returned verbatim: it IS the token the
	// caller has been presenting (cookie or bearer) — the reveal only fills
	// the per-tab ath source.
	tokenStr, _ := token.PresentedAccessToken(r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"access_token": tokenStr})
}

// Logout revokes all tokens for the user.
func (h *sessionHandler) Logout(w http.ResponseWriter, r *http.Request) {
	claims := tokenClaims(r)
	if claims == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "unauthorized"})
		return
	}
	if err := h.svc.RevokeAllForUser(r.Context(), claims.UserID); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusServiceUnavailable,
			Detail: "session revocation failed",
		})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Me returns the authenticated user's profile.
func (h *sessionHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims := tokenClaims(r)
	if claims == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "unauthorized"})
		return
	}
	var hasMailbox bool
	var isAdmin bool
	var totpEnabled bool
	var totpEnabledAt *time.Time
	var displayName string
	var primaryEmail string
	// is_admin is DERIVED from a governed, unexpired admin_role_assignments row —
	// the RBAC cut-over dropped users.admin_role, so there is no enum to key off.
	// A user with no governed assignment is not an admin (deny-by-default), which
	// matches the gateway's permission resolution (an empty perm set denies).
	if err := h.pool.QueryRow(r.Context(),
		`SELECT EXISTS(
		          SELECT 1 FROM admin_role_assignments ara
		           WHERE ara.user_id = u.id
		             AND (ara.expires_at IS NULL OR ara.expires_at > now())
		        ),
		        EXISTS(SELECT 1 FROM mailboxes WHERE user_id = u.id AND is_primary = TRUE LIMIT 1),
		        COALESCE(u.totp_enabled, FALSE), u.totp_enabled_at,
		        COALESCE(u.display_name, ''), u.email
		 FROM users u WHERE u.id = $1`,
		claims.UserID,
	).Scan(&isAdmin, &hasMailbox, &totpEnabled, &totpEnabledAt, &displayName, &primaryEmail); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusServiceUnavailable, Detail: "profile lookup failed"})
		return
	}

	// Load only direct send-as delegates for the personal-account From picker.
	// Read-only and send-on-behalf grants are not valid direct From identities;
	// shared-account composition exposes send-on-behalf through its distinct,
	// account-pinned path instead.
	type delegateEntry struct {
		ID         int64  `json:"id"`
		Email      string `json:"email"`
		Permission string `json:"permission"`
	}
	var delegates []delegateEntry
	rows, err := h.pool.Query(r.Context(),
		`SELECT mb.id, mb.email, md.permission
		 FROM mailbox_delegates md
		 JOIN mailboxes mb ON mb.id = md.mailbox_id
		 WHERE md.user_id = $1
		   AND md.permission IN ('send_as', 'full_access')
		   AND mb.enabled = TRUE
		 ORDER BY lower(mb.email), mb.id`, claims.UserID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var d delegateEntry
			if rows.Scan(&d.ID, &d.Email, &d.Permission) == nil {
				delegates = append(delegates, d)
			}
		}
	}
	if delegates == nil {
		delegates = []delegateEntry{}
	}

	// Load send-as aliases on the user's enabled PRIMARY mailbox for the compose
	// From picker. Compose submits its personal-mail accountId, so aliases on a
	// different owned mailbox would be rejected by send.sql §1.5 and must not be
	// offered here. Exclude a legacy alias row that duplicates users.email.
	type aliasEntry struct {
		Email string `json:"email"`
	}
	var aliases []aliasEntry
	arows, aerr := h.pool.Query(r.Context(),
		`SELECT a.email
		 FROM aliases a
		 JOIN mailboxes m ON m.id = a.mailbox_id
		 JOIN users u ON u.id = m.user_id
		 WHERE m.user_id = $1
		   AND m.is_primary = TRUE
		   AND m.enabled = TRUE
		   AND lower(a.email) <> lower(u.email)
		 ORDER BY lower(a.email), a.id`, claims.UserID)
	if aerr == nil {
		defer arows.Close()
		for arows.Next() {
			var a aliasEntry
			if arows.Scan(&a.Email) == nil {
				aliases = append(aliases, a)
			}
		}
	}
	if aliases == nil {
		aliases = []aliasEntry{}
	}

	// Guest Accounts P14: server-derived account type — never client-supplied.
	// Deny-on-error (re-score minor): a lookup failure must NOT render a guest
	// as a member — match Task 4's P11 posture for the same predicate rather
	// than failing open on a DB blip. Display-only surface, but consistent.
	accountType := "member"
	var sessIsGuest bool
	if err := h.pool.QueryRow(r.Context(), `SELECT is_guest_account($1)`, claims.UserID).Scan(&sessIsGuest); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusServiceUnavailable, Detail: "account type lookup failed"})
		return
	} else if sessIsGuest {
		accountType = "guest"
	}

	resp := map[string]interface{}{
		// whole-pipeline review UX #17: the numeric user id, straight from the
		// validated JWT claims (R2 — never a request field). Chat's ChatApp.svelte
		// used to resolve its own numeric selfUserId by matching displayName
		// against a fetched roster — wrong in duplicate-displayName orgs. This
		// lets the client carry the real id from login instead of guessing.
		"user_id": claims.UserID,
		// The primary address is authoritative DB state, not the address carried
		// by an older token or used to resolve an alias/UPN login.
		"email":           primaryEmail,
		"display_name":    displayName,
		"is_admin":        isAdmin,
		"has_mailbox":     hasMailbox,
		"totp_enabled":    totpEnabled,
		"totp_enabled_at": totpEnabledAt,
		"delegates":       delegates,
		"aliases":         aliases,
		"account_type":    accountType,
	}
	if claims.AdminActorID != nil {
		resp["impersonating"] = true
		resp["actor_id"] = *claims.AdminActorID
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
