package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/httputil"
)

// ipChallengeLimiter is implemented by push providers that enforce a per-IP
// challenge budget. The concrete *authn.NumberMatchPushProvider satisfies it;
// the interface keeps the handler decoupled from the concrete type (and lets
// mocks opt in or out of per-IP limiting).
type ipChallengeLimiter interface {
	AllowIP(clientIP string) bool
}

// PushMFASend initiates a number-match push MFA challenge.
//
// POST /auth/mfa/push/send
// Body: { "mfa_token": "<MFA-pending JWT>" }
// Returns: { "challenge_id": "...", "mfa_method": "push", "nonce": "...", "ttl_seconds": 120, "timeout": 120 }
//
// SECURITY (C10): the correct number-match code is NOT in the response. It is an
// out-of-band proof delivered only to the enrolled device and verified via
// POST /auth/mfa/approve.
//
// The request must include an MFA-pending token obtained from /auth/login.
// This handler generates a new challenge, stores it in push_mfa_challenges,
// and dispatches it via WebPush and/or native push (APNs/FCM/HMS with ECIES
// encryption) to all the user's registered devices.
func (h *mfaHandler) PushMFASend(w http.ResponseWriter, r *http.Request) {
	if h.pushMFA == nil {
		httputil.WriteProblem(w, r, httputil.NewNotFoundProblem("push MFA not configured"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		MFAToken string `json:"mfa_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MFAToken == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "mfa_token is required"})
		return
	}

	claims, err := h.jwt.Validate(req.MFAToken)
	if err != nil || claims.Type != token.TypeMFAPending {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("invalid MFA token"))
		return
	}

	// Per-IP rate limit: stop a single source IP from fanning push challenges
	// out across many accounts (MFA-fatigue / enumeration) while staying under
	// each account's per-user cap. Complements the per-user limit enforced in
	// GenerateChallenge and the threat interceptor's generic per-IP budget.
	if l, ok := h.pushMFA.(ipChallengeLimiter); ok {
		if !l.AllowIP(httputil.ClientIP(r)) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusTooManyRequests, Detail: "too many push challenges from this client, wait before retrying"})
			return
		}
	}

	// Generate a new challenge and dispatch via all configured push providers.
	// sessionID is the MFA pending token so the challenge can be correlated.
	resp, err := h.pushMFA.GenerateChallenge(r.Context(), claims.UserID, req.MFAToken)
	if err != nil {
		if err.Error() == "push_mfa_rate_limited: too many push challenges" {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusTooManyRequests, Detail: "too many push challenges, wait before retrying"})
			return
		}
		h.logger.Error("push MFA challenge generation failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "failed to generate challenge"})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"challenge_id": strconv.FormatInt(claims.UserID, 10),
		"mfa_method":   resp.Method,
		"nonce":        resp.Nonce,
		"ttl_seconds":  resp.TTLSeconds,
		"timeout":      resp.TTLSeconds,
	})
}
