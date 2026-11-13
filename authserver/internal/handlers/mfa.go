package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/threat"
)

// mfaHandler owns the second-factor / step-up concern. The TOTP, push, WebAuthn,
// and native-device methods live in the sibling files totp.go, push.go,
// push_mfa.go, webauthn.go, and device.go (all on the same mfaHandler receiver);
// this file owns the backup-code step. Every verify path that completes MFA
// issues tokens via the shared h.issueTokensWithFactors helper (on *deps).

// -- Backup Codes --

// GenerateBackupCodes creates 10 single-use backup codes for the authenticated
// user.
//
// Possession gate (v7 §3): regeneration is operation `recovery.regenerate`
// for EVERY account — a fresh proof grant is consumed INSIDE the same
// §2.2-fenced transaction that mints the codes and bumps the factor
// generation, so grant consumption + mutation + audit commit or roll back
// together. A caller without a valid proof receives the typed 403
// reauth_required problem — never a silent failure.
func (h *mfaHandler) GenerateBackupCodes(w http.ResponseWriter, r *http.Request) {
	claims := h.mustUser(w, r)
	if claims == nil {
		return
	}
	if rejectImpersonated(w, r, claims) {
		return
	}
	tx, _, ok := h.fencedFactorTx(w, r, claims)
	if !ok {
		return
	}
	ctx := r.Context()
	defer func() { _ = tx.Rollback(ctx) }()

	if _, gateOK := h.requirePossessionGrant(w, r, tx, claims, authn.OperationRecoveryRegenerate, nil, true, reauthTokenFromRequest(w, r)); !gateOK {
		return
	}
	codes, err := authn.GenerateBackupCodesTx(ctx, tx, claims.UserID)
	if err != nil {
		h.logger.Error("backup codes generation failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "generation failed"})
		return
	}
	// §1.8: every factor mutation bumps the generation — regeneration kills
	// every outstanding grant, including its own proof's (already consumed).
	if _, err := tx.Exec(ctx,
		`UPDATE users SET factor_generation = factor_generation + 1 WHERE id = $1`,
		claims.UserID,
	); err != nil {
		h.logger.Error("backup codes generation bump failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "generation failed"})
		return
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO admin_audit_log (user_id, ip, action, target_type, target_id)
		 VALUES ($1, $2::INET, 'backup_codes_regenerated', 'user', $1)`,
		claims.UserID, httputil.ClientIP(r)); err != nil {
		h.logger.Error("backup codes audit failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "generation failed"})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("backup codes commit failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "generation failed"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"backup_codes": codes,
	})
}

// VerifyBackupCode checks a submitted backup code.
func (h *mfaHandler) VerifyBackupCode(w http.ResponseWriter, r *http.Request) {
	claims := h.mustUser(w, r)
	if claims == nil {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	valid, err := authn.VerifyBackupCode(r.Context(), h.pool, claims.UserID, req.Code)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "verification failed"})
		return
	}
	if !valid {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid or used backup code"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// BackupCodeVerify handles the MFA step using a backup code.
// Unlike VerifyBackupCode, this endpoint is unauthenticated — the client
// presents the MFA-pending token from the login response alongside a
// backup code. On success, access and refresh tokens are issued.
func (h *mfaHandler) BackupCodeVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MFAToken string         `json:"mfa_token"`
		Code     string         `json:"code"`
		DPoPJWK  map[string]any `json:"dpop_jwk,omitempty"`
	}
	if !decodeBoundedAuthJSON(w, r, &req) {
		return
	}
	if req.MFAToken == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "mfa_token is required"})
		return
	}
	if req.Code == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "code is required"})
		return
	}

	claims, err := h.jwt.Validate(req.MFAToken)
	if err != nil || claims.Type != token.TypeMFAPending {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "invalid MFA token"})
		return
	}

	valid, err := authn.VerifyBackupCode(r.Context(), h.pool, claims.UserID, req.Code)
	if err != nil {
		slog.Error("backup code verification failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "verification failed"})
		return
	}
	if !valid {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "invalid or used backup code"})
		return
	}

	user, err := h.lookupUser(r.Context(), "id", claims.UserID)
	if err != nil {
		slog.Error("backup code verify: user lookup failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "user not found"})
		return
	}

	*r = *r.WithContext(threat.WithUserID(r.Context(), user.ID))
	// First factor (from the MFA-pending token) + the single-use backup code,
	// which is a one-time recovery passcode → reported as otp per RFC 8176.
	h.issueTokensFromMFAPending(
		w, r, user, claims,
		h.completionMetadataForDPoP(req.DPoPJWK, true),
		token.AMROTP,
	)
}
