package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/shared/httputil"
)

// totpRemovalConfirmWord is the typed confirmation the removal POST must
// carry. A typed word (mirroring the secure-account flow) keeps a single
// misclick — or a CSRF/Drive-by UI gesture — from destroying the factor.
const totpRemovalConfirmWord = "REMOVE"

// TOTPRemovalBegin runs the de-enrollment decision table for the
// authenticated user and, on success, issues a single-use session-bound
// step-up token for the follow-up removal POST.
//
// Body {"password":"...","code":"..."}: password plus the current TOTP code,
// or — when the authenticator is lost and recovery codes remain — a valid
// recovery code. A locked-out user (lost authenticator, no recovery codes)
// fails code verification and is refused on this self-service path.
//
// POST /auth/totp/remove/begin — requires access token; CSRF checked at the
// mux; the gateway's /auth/totp/ subtree proxy applies its auth rate limit.
func (h *mfaHandler) TOTPRemovalBegin(w http.ResponseWriter, r *http.Request) {
	claims := h.mustUser(w, r)
	if claims == nil {
		return
	}
	// v7 §1.7 last row (r2 disposition): impersonated bearers are refused
	// unconditionally on the removal flow, begin and confirm.
	if rejectImpersonated(w, r, claims) {
		return
	}
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !decodeBoundedAuthJSON(w, r, &req) {
		// Every-attempt contract: an authenticated malformed body is still a
		// de-enrollment attempt. The decoder already wrote the 400; audit the
		// refusal before returning so the attempt never bypasses the trail.
		h.auditTOTPRemovalRefusal(r, claims.UserID, "totp_removal_step_up_refused", "malformed body")
		return
	}
	if req.Password == "" || req.Code == "" {
		h.auditTOTPRemovalRefusal(r, claims.UserID, "totp_removal_step_up_refused", "missing password or code")
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "password and code are required"})
		return
	}

	stepUpToken, err := authn.BeginTOTPRemoval(r.Context(), h.pool, claims.UserID, req.Password, req.Code, claims.JTI)
	if err != nil {
		switch {
		case errors.Is(err, authn.ErrTOTPNotEnabled):
			h.auditTOTPRemovalRefusal(r, claims.UserID, "totp_removal_step_up_refused", "totp not enabled")
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusConflict, Detail: "TOTP is not enabled"})
		case errors.Is(err, authn.ErrInvalidRemovalPassword):
			h.auditTOTPRemovalRefusal(r, claims.UserID, "totp_removal_step_up_refused", "invalid password")
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "invalid password"})
		case errors.Is(err, authn.ErrTOTPLocked):
			h.auditTOTPRemovalRefusal(r, claims.UserID, "totp_removal_step_up_refused", "account locked")
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusTooManyRequests, Detail: "account locked due to too many TOTP failures"})
		case errors.Is(err, authn.ErrInvalidRemovalCode):
			h.auditTOTPRemovalRefusal(r, claims.UserID, "totp_removal_step_up_refused", "invalid code")
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "invalid code"})
		default:
			h.logger.Error("totp removal step-up failed", "user_id", claims.UserID, "error", err)
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp removal failed"})
		}
		return
	}

	h.pool.Exec(r.Context(),
		`INSERT INTO admin_audit_log (user_id, ip, action, target_type, target_id)
		 VALUES ($1, $2::INET, 'totp_removal_step_up_authorized', 'user', $1)`,
		claims.UserID, httputil.ClientIP(r))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"step_up_token": stepUpToken,
		"expires_in":    int(authn.TOTPRemovalStepUpTTL.Seconds()),
	})
}

// TOTPRemovalConfirm consumes the single-use step-up token and removes the
// TOTP factor and all recovery codes in one serialized transaction.
//
// Body {"step_up_token":"...","confirm":"REMOVE"}. A missing/mistyped
// confirmation, a replayed/expired/foreign-session token, or a concurrent
// double-submission is refused with the factor intact; every refusal is
// audited, and the success audit row commits inside the removal transaction.
//
// POST /auth/totp/remove — requires access token; CSRF checked at the mux.
func (h *mfaHandler) TOTPRemovalConfirm(w http.ResponseWriter, r *http.Request) {
	claims := h.mustUser(w, r)
	if claims == nil {
		return
	}
	// v7 §1.7 last row (r2 disposition): impersonated bearers are refused
	// unconditionally on the removal flow, begin and confirm.
	if rejectImpersonated(w, r, claims) {
		return
	}
	var req struct {
		StepUpToken string `json:"step_up_token"`
		Confirm     string `json:"confirm"`
	}
	if !decodeBoundedAuthJSON(w, r, &req) {
		// Every-attempt contract: an authenticated malformed body is still a
		// de-enrollment attempt. The decoder already wrote the 400; audit the
		// refusal before returning so the attempt never bypasses the trail.
		h.auditTOTPRemovalRefusal(r, claims.UserID, "totp_removal_refused", "malformed body")
		return
	}
	if req.Confirm != totpRemovalConfirmWord {
		h.auditTOTPRemovalRefusal(r, claims.UserID, "totp_removal_refused", "confirmation mismatch")
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest,
			Detail: "type REMOVE to confirm authenticator removal",
		})
		return
	}

	if err := authn.DisableTOTPWithStepUp(r.Context(), h.pool, claims.UserID, claims.JTI, req.StepUpToken, httputil.ClientIP(r)); err != nil {
		switch {
		case errors.Is(err, authn.ErrTOTPRemovalStepUpInvalid):
			h.auditTOTPRemovalRefusal(r, claims.UserID, "totp_removal_refused", "step-up token invalid, expired, or replayed")
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "step-up token invalid or expired"})
		case errors.Is(err, authn.ErrTOTPNotEnabled):
			h.auditTOTPRemovalRefusal(r, claims.UserID, "totp_removal_refused", "totp not enabled")
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusConflict, Detail: "TOTP is not enabled"})
		default:
			h.logger.Error("totp removal failed", "user_id", claims.UserID, "error", err)
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp removal failed"})
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// auditTOTPRemovalRefusal records a de-enrollment refusal (best-effort, the
// established admin_audit_log convention on non-transactional paths — the
// success audit is transactional inside the removal itself).
func (h *mfaHandler) auditTOTPRemovalRefusal(r *http.Request, userID int64, action, notes string) {
	h.pool.Exec(r.Context(),
		`INSERT INTO admin_audit_log (user_id, ip, action, target_type, target_id, notes)
		 VALUES ($1, $2::INET, $3, 'user', $1, $4)`,
		userID, httputil.ClientIP(r), action, notes)
}
