package handlers

import (
	"net/http"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/httputil"
)

// VAPIDKey serves the server's webpush VAPID public key.
//
// GET /auth/push/vapid-key — unauthenticated (proxied by the mailserver
// gateway's existing "/auth/push/" prefix, no new route wiring needed there).
// Not a secret — the public half of VAPID_PRIVATE_KEY, safe to hand to any
// browser about to pushManager.subscribe(). Used by the webmail settings
// Notifications toggle (QoL #9) to VAPID-authenticate its push subscription
// to the same key sendWebPushTo (authn/push.go) signs payloads with.
func (h *mfaHandler) VAPIDKey(w http.ResponseWriter, r *http.Request) {
	if h.vapidPublicKey == "" {
		httputil.WriteProblem(w, r, httputil.NewNotFoundProblem("push not configured"))
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"vapid_public_key": h.vapidPublicKey})
}

// ── Push MFA ──

// PushMFAVerify is the login client's number-match push step.
//
// POST /auth/push/verify — unauthenticated; accepts {"mfa_token":"...","nonce":"...","answer":"..."}.
//
// SECURITY (C10): this endpoint NO LONGER completes MFA from a client-submitted
// answer. Number-match is an OUT-OF-BAND proof: the correct code is delivered
// only to the enrolled device (ECIES native push / webpush) and never returned
// to the login client. Accepting the answer back in-band here let a
// password-only attacker who could read the code submit it as the second factor
// — a full 2FA bypass. The answer is now verified solely on the
// device-authenticated channel (POST /auth/mfa/approve), which is bound to
// device possession and rate-limited against guessing.
//
// The mfa_token is still validated so a bad/expired session is rejected with the
// usual 401, but a valid session that submits an answer is refused: the browser
// learns success by re-checking auth state after the device approves.
//
// ponytail: hard-reject the in-band answer until the device-approval status poll
// lands (deferred UX — needs an approved_at column distinct from verified_at so a
// 3-strike lockout is never mistaken for an approval). Native push login already
// completes end-to-end via /auth/mfa/approve.
func (h *mfaHandler) PushMFAVerify(w http.ResponseWriter, r *http.Request) {
	if h.pushMFA == nil {
		httputil.WriteProblem(w, r, httputil.NewNotFoundProblem("push MFA not configured"))
		return
	}
	var req struct {
		MFAToken string `json:"mfa_token"`
		Nonce    string `json:"nonce"`
		Answer   string `json:"answer"`
	}
	if !decodeBoundedAuthJSON(w, r, &req) {
		return
	}

	claims, err := h.jwt.Validate(req.MFAToken)
	if err != nil || claims.Type != token.TypeMFAPending {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("invalid MFA token"))
		return
	}

	// Refuse the in-band answer. We do not call VerifyChallenge with a
	// client-submitted answer and we never issue tokens from this path.
	httputil.WriteProblem(w, r, &httputil.Problem{
		Status: http.StatusGone,
		Detail: "in-band push answer is not accepted; approve the sign-in on your enrolled device",
	})
}

// PushMFAStatus is the login client's poll for OUT-OF-BAND push approval (C10).
//
// POST /auth/push/status — unauthenticated; accepts {"mfa_token":"...","nonce":"..."}.
//
// Number-match push completes only on the enrolled device (/auth/mfa/approve),
// so the browser / webpush login flow cannot submit the answer itself. After
// /auth/mfa/push/send the client polls here until the device approves, then this
// endpoint issues the login session to the poller.
//
// SECURITY (C10):
//   - The poll is BOUND to the login session by the MFA-pending token: it proves
//     the password factor and identifies the user. Without it (or with a bad /
//     expired one) the caller gets 401 — the nonce alone is never enough, or an
//     attacker who learned a victim's nonce could harvest the victim's session by
//     polling until the victim approves.
//   - The challenge is looked up by nonce SCOPED to the mfa_token's user, so one
//     user can never poll another user's challenge.
//   - Tokens are issued ONLY when push_mfa_challenges.approved_at IS NOT NULL.
//     approved_at is a DISTINCT column from verified_at: VerifyChallenge stamps
//     verified_at on a 3-strike lockout too, so reading verified_at here would
//     let a lockout masquerade as an approval and hand out a session.
func (h *mfaHandler) PushMFAStatus(w http.ResponseWriter, r *http.Request) {
	if h.pushMFA == nil {
		httputil.WriteProblem(w, r, httputil.NewNotFoundProblem("push MFA not configured"))
		return
	}
	var req struct {
		MFAToken string         `json:"mfa_token"`
		Nonce    string         `json:"nonce"`
		DPoPJWK  map[string]any `json:"dpop_jwk,omitempty"`
	}
	if !decodeBoundedAuthJSON(w, r, &req) {
		return
	}
	if req.Nonce == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "nonce is required"})
		return
	}

	// Validate the session binding BEFORE any infra/DB work: a bad/expired
	// MFA-pending token is rejected 401 regardless of pool availability.
	claims, err := h.jwt.Validate(req.MFAToken)
	if err != nil || claims.Type != token.TypeMFAPending {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("invalid MFA token"))
		return
	}
	if h.pool == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database not available"})
		return
	}

	// approved_at IS NOT NULL is the SOLE approval gate (never verified_at). A
	// missing row (expired/unknown/foreign challenge) is reported as "not yet
	// approved", not an error — the poll just keeps waiting until TTL.
	var approved bool
	err = h.pool.QueryRow(r.Context(),
		`SELECT approved_at IS NOT NULL
		 FROM push_mfa_challenges
		 WHERE nonce = decode($1, 'hex') AND user_id = $2
		 ORDER BY created_at DESC LIMIT 1`,
		req.Nonce, claims.UserID,
	).Scan(&approved)
	if err != nil || !approved {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"approved": false})
		return
	}

	// Approved out-of-band — harvest with a one-time-use fence. The poll is
	// bound to the session that minted the challenge (the challenge row's
	// session_id IS the initiating MFA-pending token, stamped by PushMFASend and
	// the Login push branch), must still be within its challenge TTL, and is
	// CONSUMED by the first harvest (session_id CAS → NULL): an approved
	// challenge can complete exactly one login session. Without this fence an
	// approved challenge could be replayed across sessions — any second
	// MFA-pending token of the user (or the same token re-presented forever)
	// minted fresh sessions — and long after the challenge's expiry.
	var consumed bool
	err = h.pool.QueryRow(r.Context(),
		`UPDATE push_mfa_challenges
		    SET session_id = NULL
		  WHERE nonce = decode($1, 'hex') AND user_id = $2
		    AND session_id = $3
		    AND approved_at IS NOT NULL
		    AND expires_at > now()
		  RETURNING true`,
		req.Nonce, claims.UserID, req.MFAToken,
	).Scan(&consumed)
	if err != nil {
		// No row matched: not approved yet, foreign session, expired, or already
		// harvested — the uniform "not yet approved" poll answer reveals nothing.
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"approved": false})
		return
	}
	_ = consumed

	// Issuing the session to THIS caller — the mfa_token holder, i.e. the browser
	// that completed the password step AND minted this challenge.
	user, err := h.lookupUser(r.Context(), "id", claims.UserID)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "user lookup failed"})
		return
	}
	// password (from the MFA-pending token) + number-match push: software-key
	// proof-of-possession (swk) + human presence (user), per RFC 8176.
	h.issueTokensFromMFAPending(
		w, r, user, claims,
		h.completionMetadataForDPoP(req.DPoPJWK, true),
		token.AMRSoftwareKey, token.AMRUserPresence,
	)
}
