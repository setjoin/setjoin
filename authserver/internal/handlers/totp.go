package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/threat"
)

// totp.go — the TOTP arms under the first-factor possession gate (v7 §3):
//
//   - GET /auth/totp/setup       — peek grant + ONE-TIME target binding +
//     staged pending row (totp.enroll / totp.replace). The secret is staged
//     into totp_pending_enrollments, never written onto the ACTIVE factor —
//     cancellation/abandonment preserves the active TOTP (the §2.2 repair).
//   - POST /auth/totp/confirm    — validates binding + enrollment_id,
//     verifies the code against the STAGED secret, then promotion +
//     factor_generation bump + grant consumption in ONE transaction.
//   - POST /auth/totp/verify     — login second factor; the §2.3 shared
//     ONE-cycle caller (bookkeeping failure → 500, never accepted-with-error).
//   - POST /auth/totp/enroll/setup|confirm — the mfa_pending bootstrap arms;
//     the setup peeks the bootstrap grant (C2/C3 password grant minted at
//     login; C1 passkey holders have NO grant here and must prove UV on the
//     possession endpoints), confirm consumes it in the promotion tx.
//
// Every arm refuses impersonated bearers (§1.7 last row).

// fencedFactorTx opens the §2.2-fenced transaction every gated arm runs in:
// person fence → users fence (returns the bound generation) → durable
// revocation recheck. On any failure the problem is written and ok=false.
func (h *mfaHandler) fencedFactorTx(
	w http.ResponseWriter, r *http.Request, claims *token.Claims,
) (pgx.Tx, int64, bool) {
	ctx := r.Context()
	tx, err := h.beginGateTx(ctx)
	if err != nil {
		h.logger.Error("factor tx begin failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return nil, 0, false
	}
	if err := authn.PersonFence(ctx, tx, claims.UserID); err != nil {
		_ = tx.Rollback(ctx)
		h.logger.Error("person fence failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return nil, 0, false
	}
	generation, err := authn.UsersFence(ctx, tx, claims.UserID)
	if err != nil {
		_ = tx.Rollback(ctx)
		h.logger.Error("users fence failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return nil, 0, false
	}
	revoked, err := durableRecheckForClaims(ctx, tx, claims)
	if err != nil {
		_ = tx.Rollback(ctx)
		h.logger.Error("revocation recheck failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return nil, 0, false
	}
	if revoked {
		_ = tx.Rollback(ctx)
		writeReauthRequired(w, r)
		return nil, 0, false
	}
	return tx, generation, true
}

// TOTPSetup stages a new TOTP enrollment behind a peeked possession grant
// (§1.6 begin arm). Repeated setup on the SAME grant with the SAME JTI and
// a live staged row is a RESUME: the provisioning URI is re-derived from
// the SAME pending secret (retry-after-network-loss works; no second secret
// is minted, no re-binding occurs). A bound grant whose target is dead (or
// staged by another session) refuses with the typed 409 proof_already_bound
// — one proof authorizes exactly one staged target.
//
// GET /auth/totp/setup — requires access token + the X-MFA-Reauth grant.
func (h *mfaHandler) TOTPSetup(w http.ResponseWriter, r *http.Request) {
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

	// The operation follows the fenced account state: replace over an
	// enabled factor, enroll otherwise (C3's first enrollment keeps its
	// password-grant posture — §1.3).
	var totpEnabled bool
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(totp_enabled, FALSE) FROM users WHERE id = $1`,
		claims.UserID,
	).Scan(&totpEnabled); err != nil {
		h.logger.Error("totp setup: user lookup failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp setup failed"})
		return
	}
	operation := authn.OperationTOTPEnroll
	if totpEnabled {
		operation = authn.OperationTOTPReplace
	}

	family := claims.RefreshFamilyID()
	tokenHash := authn.ReauthTokenHash(reauthTokenFromRequest(w, r))
	grant, err := authn.PeekGrant(ctx, tx, authn.GrantPredicate{
		TokenHash:     tokenHash,
		UserID:        claims.UserID,
		SessionJTI:    claims.JTI,
		Operation:     operation,
		TargetBound:   false,
		TokenScope:    authn.ProofScopeSession,
		FamilyBound:   true,
		RefreshFamily: &family,
	})
	if err != nil {
		h.writeGrantGateRefusal(w, r, tx, claims.UserID, err, "totp setup")
		return
	}

	// RESUME: the grant is already bound and the bound enrollment row is
	// live and staged by THIS token's JTI — re-derive the URI from the SAME
	// pending secret, no new rows.
	if grant.TargetRef != nil {
		secret, _, readErr := authn.ReadPendingTOTPEnrollment(ctx, tx, claims.UserID, *grant.TargetRef, claims.JTI)
		if readErr == nil {
			uri, uriErr := authn.ProvisioningURIForSecret(secret, claims.Email, h.jwt.Issuer())
			if uriErr != nil {
				h.logger.Error("totp setup resume failed", "error", uriErr)
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp setup failed"})
				return
			}
			if err := tx.Commit(ctx); err != nil {
				h.logger.Error("totp setup resume commit failed", "error", err)
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp setup failed"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"provisioning_uri": uri,
				"enrollment_id":    *grant.TargetRef,
			})
			return
		}
		// Bound grant with a dead/foreign target: fail-closed 409 — the
		// client must re-prove (new grant) to stage a different enrollment.
		_ = tx.Rollback(ctx)
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusConflict,
			Detail: "this proof already authorized a different enrollment; present a fresh proof",
			Code:   "proof_already_bound",
		})
		return
	}

	// FIRST BIND: stage the pending secret (the ACTIVE factor is never
	// touched) and perform the grant's one-time target binding atomically.
	_, secret, err := authn.NewTOTPProvisioningSecret(claims.Email, h.jwt.Issuer())
	if err != nil {
		h.logger.Error("totp key generation failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp setup failed"})
		return
	}
	enrollmentID, err := authn.StagePendingTOTPEnrollment(ctx, tx, claims.UserID, secret, claims.JTI, "totp_setup")
	if err != nil {
		h.logger.Error("totp pending stage failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp setup failed"})
		return
	}
	bound, err := authn.BindGrantTarget(ctx, tx, grant.TokenHash, claims.UserID, claims.JTI, enrollmentID)
	if err != nil {
		h.writeGrantGateRefusal(w, r, tx, claims.UserID, err, "totp setup binding")
		return
	}
	if !bound {
		// Lost a binding race on the same grant: fail closed (§1.6).
		_ = tx.Rollback(ctx)
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusConflict,
			Detail: "this proof already authorized a different enrollment; present a fresh proof",
			Code:   "proof_already_bound",
		})
		return
	}
	uri, err := authn.ProvisioningURIForSecret(secret, claims.Email, h.jwt.Issuer())
	if err != nil {
		h.logger.Error("totp provisioning uri failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp setup failed"})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("totp setup commit failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp setup failed"})
		return
	}

	h.pool.Exec(r.Context(),
		`INSERT INTO admin_audit_log (user_id, ip, action, target_type, target_id)
		 VALUES ($1, $2::INET, 'totp_setup_initiated', 'user', $1)`,
		claims.UserID, httputil.ClientIP(r))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"provisioning_uri": uri,
		"enrollment_id":    enrollmentID,
	})
}

// writeGrantGateRefusal maps a grant-store error to the wire contract:
// mismatch (whose handler DELETED the dead grant) or missing → typed 403
// reauth_required + audit; anything else → 500 fail-closed. commit is the
// caller's open transaction — the §1.7 mismatch deletion lives in it and
// MUST commit (a refusal that leaves the dead grant rows behind would let a
// consumed proof be retried against another endpoint).
func (h *mfaHandler) writeGrantGateRefusal(w http.ResponseWriter, r *http.Request, tx pgx.Tx, userID int64, err error, what string) {
	var mismatch *authn.GrantMismatchError
	if errors.As(err, &mismatch) || errors.Is(err, authn.ErrGrantRequired) {
		if tx != nil {
			if commitErr := tx.Commit(r.Context()); commitErr != nil {
				h.logger.Error("possession refusal commit failed", "user_id", userID, "error", commitErr)
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
				return
			}
		}
		h.auditMFAReauthRefusal(r, userID, what+" without a valid possession proof")
		writeReauthRequired(w, r)
		return
	}
	h.logger.Error("possession grant gate failed", "user_id", userID, "arm", what, "error", err)
	httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
}

// commitGrantMismatchRefusal finalizes a §1.7 tuple-mismatch refusal whose
// cleanup must SURVIVE the handler's return (r8): the outstanding grant is
// deleted (checked), the refusal audit rides the SAME transaction, and the
// commit lands BEFORE the typed 403 is written. The two refusal sites that
// do their own cleanup — the session TOTP confirm's dead staged row and the
// bootstrap promotion's peek/binding mismatches — run inside a transaction
// the caller still rolls back on the error return, and a rolled-back
// mismatch deletion RESURRECTS the burned grant (usable again at the next
// attempt, contrary to §1.7). A cleanup failure commits nothing: the caller
// answers the fail-closed 500 — the grant alone completes nothing (its
// staged row is the dead member of the tuple), and a 500 never lies about a
// refusal.
func (h *mfaHandler) commitGrantMismatchRefusal(
	ctx context.Context, tx pgx.Tx, userID int64, tokenHash, sessionJTI, clientIP, notes string,
) error {
	if _, err := tx.Exec(ctx,
		`DELETE FROM mfa_reauth_step_ups
		  WHERE token_hash = $1 AND user_id = $2 AND session_jti = $3`,
		tokenHash, userID, sessionJTI); err != nil {
		return fmt.Errorf("grant mismatch cleanup: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO admin_audit_log (user_id, ip, action, target_type, target_id, notes)
		 VALUES ($1, NULLIF($2, '')::INET, 'mfa_reauth_refused', 'user', $1, $3)`,
		userID, clientIP, notes); err != nil {
		return fmt.Errorf("grant mismatch refusal audit: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("grant mismatch refusal commit: %w", err)
	}
	return nil
}

// TOTPConfirm activates (enroll) or swaps (replace) the TOTP factor from
// the STAGED pending secret (§1.6 finish arm): validates the binding tuple
// {grant live with target_ref = enrollment_id, pending row id = enrollment_id,
// staged_by_jti = this token's JTI}, verifies the code against THAT row's
// secret, then deletes the pending row, promotes
// (totp_enabled + factor_generation + 1), consumes the grant, and writes
// the success audit — all ONE commit. Every stale combination refuses by
// construction with the factor untouched.
//
// POST /auth/totp/confirm — requires access token; body
// {"code":"...","enrollment_id":"<uuid>"}.
func (h *mfaHandler) TOTPConfirm(w http.ResponseWriter, r *http.Request) {
	claims := h.mustUser(w, r)
	if claims == nil {
		return
	}
	if rejectImpersonated(w, r, claims) {
		return
	}
	var req struct {
		Code         string `json:"code"`
		EnrollmentID string `json:"enrollment_id"`
		ReauthToken  string `json:"reauth_token"`
	}
	if !decodeBoundedAuthJSON(w, r, &req) {
		return
	}
	if req.Code == "" || req.EnrollmentID == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "code and enrollment_id are required"})
		return
	}
	// The bounded decoder buffers the whole body, so the token member rides
	// the SAME decode — a second body read would yield nothing. The header
	// still takes precedence (the GET-setup transport parity).
	reauthToken := r.Header.Get(ReauthTokenHeader)
	if reauthToken == "" {
		reauthToken = req.ReauthToken
	}

	tx, _, ok := h.fencedFactorTx(w, r, claims)
	if !ok {
		return
	}
	ctx := r.Context()
	defer func() { _ = tx.Rollback(ctx) }()

	// The operation follows the fenced account state (§1.3), mirroring the
	// setup arm that staged this enrollment.
	var totpEnabled bool
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(totp_enabled, FALSE) FROM users WHERE id = $1`,
		claims.UserID,
	).Scan(&totpEnabled); err != nil {
		h.logger.Error("totp confirm: user lookup failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp confirmation failed"})
		return
	}
	operation := authn.OperationTOTPEnroll
	if totpEnabled {
		operation = authn.OperationTOTPReplace
	}

	family := claims.RefreshFamilyID()
	// Peek the grant against the presented binding (the consumption happens
	// after the code verifies — a wrong code must not burn the proof; the
	// §1.7 tuple-mismatch refusal, by contrast, DELETES the grant).
	tokenHash := authn.ReauthTokenHash(reauthToken)
	pred := authn.GrantPredicate{
		TokenHash:     tokenHash,
		UserID:        claims.UserID,
		SessionJTI:    claims.JTI,
		Operation:     operation,
		TargetBound:   true,
		TargetRef:     &req.EnrollmentID,
		TokenScope:    authn.ProofScopeSession,
		FamilyBound:   true,
		RefreshFamily: &family,
	}
	if _, err := authn.PeekGrant(ctx, tx, pred); err != nil {
		h.writeGrantGateRefusal(w, r, tx, claims.UserID, err, "totp confirm binding")
		return
	}

	// The staged row must resolve for THIS user + JTI.
	secret, _, err := authn.ReadPendingTOTPEnrollment(ctx, tx, claims.UserID, req.EnrollmentID, claims.JTI)
	if err != nil {
		// Tuple mismatch (dead ID, another session's staging): the §1.7
		// refusal deletes the outstanding grant — and the deletion COMMITS
		// (r8: the deferred rollback used to resurrect the dead grant,
		// leaving the burned proof consumable at the next arm).
		if errors.Is(err, authn.ErrGrantRequired) {
			if cleanupErr := h.commitGrantMismatchRefusal(ctx, tx, claims.UserID, tokenHash, claims.JTI,
				httputil.ClientIP(r), "totp confirm binding mismatch"); cleanupErr != nil {
				h.logger.Error("totp confirm refusal cleanup failed", "user_id", claims.UserID, "error", cleanupErr)
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp confirmation failed"})
				return
			}
			writeReauthRequired(w, r)
			return
		}
		h.logger.Error("totp pending lookup failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp confirmation failed"})
		return
	}

	// Verify the code against the STAGED secret. An invalid code leaves the
	// grant and the pending row intact (bounded by the pending TTL).
	if !authn.ValidateTOTPCode(req.Code, secret) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "invalid code"})
		return
	}

	// Consume the grant BEFORE the factor activates (§1.6 finish arm; the
	// V271 confirm semantics) — the single-use DELETE carries the generation
	// equality against the still-unbumped users row, and the fence guarantees
	// the promotion below commits in the same serialized transaction.
	g, err := authn.ConsumeGrant(ctx, tx, pred)
	if err != nil {
		h.writeGrantGateRefusal(w, r, tx, claims.UserID, err, "totp confirm consume")
		return
	}
	// §1.1 full-tuple consumption (opus r1 finding 4): the proving factor is
	// still enabled/not-revoked (tx rolls back on the refusal).
	live, factorErr := authn.ProvingFactorStillEnabled(ctx, tx, g)
	if factorErr != nil {
		h.logger.Error("proving factor check failed", "user_id", claims.UserID, "error", factorErr)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp confirmation failed"})
		return
	}
	if !live {
		h.auditMFAReauthRefusal(r, claims.UserID, "possession proof refused: proving factor no longer live")
		writeReauthRequired(w, r)
		return
	}

	// Promotion: swap the staged secret in, enable, bump the generation —
	// the guarded enable matches the operation's expected state, so an
	// enroll can never resurrect a removed factor and a replace can never
	// run over a concurrently-disabled one.
	expectedEnabled := "FALSE"
	if totpEnabled {
		expectedEnabled = "TRUE"
	}
	tag, err := tx.Exec(ctx,
		`UPDATE users
		    SET totp_secret_enc = pgp_sym_encrypt($2, current_setting('app.encryption_key')),
		        totp_enabled = TRUE,
		        totp_enabled_at = now(),
		        last_totp_used_at = now(),
		        totp_failed_attempts = 0,
		        totp_locked_until = NULL,
		        factor_generation = factor_generation + 1
		  WHERE id = $1
		    AND enabled = TRUE
		    AND COALESCE(totp_enabled, FALSE) = `+expectedEnabled,
		claims.UserID, secret,
	)
	if err != nil {
		h.logger.Error("totp promotion failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp confirmation failed"})
		return
	}
	if tag.RowsAffected() != 1 {
		// Factor state changed under us (removal won the fence): fail closed.
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusConflict, Detail: "totp state changed; present a fresh proof"})
		return
	}
	if err := authn.DeletePendingTOTPEnrollment(ctx, tx, claims.UserID, req.EnrollmentID); err != nil {
		h.logger.Error("totp pending delete failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp confirmation failed"})
		return
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO admin_audit_log (user_id, ip, action, target_type, target_id)
		 VALUES ($1, $2::INET, 'totp_confirmed', 'user', $1)`,
		claims.UserID, httputil.ClientIP(r)); err != nil {
		h.logger.Error("totp confirm audit failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp confirmation failed"})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("totp confirm commit failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp confirmation failed"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// TOTPEnrollmentSetup stages the bootstrap enrollment behind the mfa_pending
// grant (§1.6 bootstrap row): C2/C3 accounts hold the password grant minted
// atomically with the login response (§1.5.1); a C1 passkey holder has NO
// grant here and is refused with the typed 403 — its proof is the UV
// ceremony on the possession endpoints.
//
// POST /auth/totp/enroll/setup — unauthenticated; accepts
// {"mfa_token":"..."}; returns {"provisioning_uri","enrollment_id"}.
func (h *mfaHandler) TOTPEnrollmentSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MFAToken string `json:"mfa_token"`
	}
	if !decodeBoundedAuthJSON(w, r, &req) {
		return
	}
	claims, err := h.jwt.Validate(req.MFAToken)
	if err != nil || claims.Type != token.TypeMFAPending {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "invalid MFA token"})
		return
	}
	if rejectImpersonated(w, r, claims) {
		return
	}

	ctx := r.Context()
	tx, err := h.beginGateTx(ctx)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusServiceUnavailable,
			Detail: "identity mint fence unavailable",
		})
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck
	if fenceErr := applyAuthenticationMintFence(
		r.Context(), tx, claims.UserID, claims.IdentityFence,
	); fenceErr != nil {
		if !reducererr.WriteClassified(w, r, fenceErr) {
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusConflict,
				Detail: "authentication identity changed before MFA enrollment",
			})
		}
		return
	}
	if fenceErr := verifyCredentialFence(
		r.Context(), tx, claims.UserID, claims.CredentialFence,
	); fenceErr != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusUnauthorized,
			Detail: "Credentials changed during sign-in. Please authenticate again.",
		})
		return
	}
	// §2.2 fences + durable revocation recheck (family is NULL for the
	// pending scope; the iat watermark still applies).
	if err := authn.PersonFence(ctx, tx, claims.UserID); err != nil {
		h.logger.Error("enrollment setup person fence failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp setup failed"})
		return
	}
	if _, err := authn.UsersFence(ctx, tx, claims.UserID); err != nil {
		h.logger.Error("enrollment setup users fence failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp setup failed"})
		return
	}
	revoked, err := durableRecheckForClaims(ctx, tx, claims)
	if err != nil {
		h.logger.Error("enrollment setup recheck failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp setup failed"})
		return
	}
	if revoked {
		writeReauthRequired(w, r)
		return
	}
	// Enrollment must still be policy-required (the historical guard).
	var mfaStatus string
	if err := tx.QueryRow(ctx,
		`SELECT mfa_status($1)->>'status'`, claims.UserID,
	).Scan(&mfaStatus); err != nil || mfaStatus != "enrollment_required" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusConflict, Detail: "MFA enrollment state changed; sign in again"})
		return
	}

	// Peek the bootstrap grant: a C1 passkey holder (no grant) or any dead
	// proof answers the typed 403.
	family := ""
	grant, err := authn.PeekGrant(ctx, tx, authn.GrantPredicate{
		TokenHash:     authn.ReauthTokenHash(req.MFAToken),
		UserID:        claims.UserID,
		SessionJTI:    claims.JTI,
		Operation:     authn.OperationBootstrapTOTPEnroll,
		TargetBound:   false,
		TokenScope:    authn.ProofScopeMFAPending,
		FamilyBound:   true,
		RefreshFamily: &family,
	})
	if err != nil {
		h.writeGrantGateRefusal(w, r, tx, claims.UserID, err, "bootstrap enrollment setup")
		return
	}

	// Resume: same grant + same JTI + live staged row → same secret/URI.
	if grant.TargetRef != nil {
		secret, _, readErr := authn.ReadPendingTOTPEnrollment(ctx, tx, claims.UserID, *grant.TargetRef, claims.JTI)
		if readErr == nil {
			uri, uriErr := authn.ProvisioningURIForSecret(secret, claims.Email, h.jwt.Issuer())
			if uriErr != nil {
				h.logger.Error("enrollment resume failed", "error", uriErr)
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp setup failed"})
				return
			}
			if err := tx.Commit(ctx); err != nil {
				h.logger.Error("enrollment resume commit failed", "error", err)
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp setup failed"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"provisioning_uri": uri,
				"enrollment_id":    *grant.TargetRef,
			})
			return
		}
		_ = tx.Rollback(ctx)
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusConflict,
			Detail: "this proof already authorized a different enrollment; sign in again for a fresh proof",
			Code:   "proof_already_bound",
		})
		return
	}

	_, secret, err := authn.NewTOTPProvisioningSecret(claims.Email, h.jwt.Issuer())
	if err != nil {
		h.logger.Error("totp key generation failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp setup failed"})
		return
	}
	enrollmentID, err := authn.StagePendingTOTPEnrollment(ctx, tx, claims.UserID, secret, claims.JTI, "enroll_setup")
	if err != nil {
		h.logger.Error("totp pending stage failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp setup failed"})
		return
	}
	bound, err := authn.BindGrantTarget(ctx, tx, grant.TokenHash, claims.UserID, claims.JTI, enrollmentID)
	if err != nil {
		h.writeGrantGateRefusal(w, r, tx, claims.UserID, err, "bootstrap enrollment binding")
		return
	}
	if !bound {
		_ = tx.Rollback(ctx)
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusConflict,
			Detail: "this proof already authorized a different enrollment; sign in again for a fresh proof",
			Code:   "proof_already_bound",
		})
		return
	}
	uri, err := authn.ProvisioningURIForSecret(secret, claims.Email, h.jwt.Issuer())
	if err != nil {
		h.logger.Error("totp provisioning uri failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp setup failed"})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("enrollment setup commit failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp setup failed"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"provisioning_uri": uri,
		"enrollment_id":    enrollmentID,
	})
}

// TOTPVerify completes the MFA step: validates a TOTP code against the
// mfa_pending token issued at login, then issues full access + refresh
// tokens. The verification rides the §2.3 ONE fenced cycle; a bookkeeping
// failure is a 500 — NO tokens, NO session state change (the supersession
// of the historical accepted-with-error behaviour).
//
// POST /auth/totp/verify — unauthenticated; accepts
// {"mfa_token":"...","code":"..."}.
func (h *mfaHandler) TOTPVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MFAToken string         `json:"mfa_token"`
		Code     string         `json:"code"`
		DPoPJWK  map[string]any `json:"dpop_jwk,omitempty"`
	}
	if !decodeBoundedAuthJSON(w, r, &req) {
		return
	}

	claims, err := h.jwt.Validate(req.MFAToken)
	if err != nil || claims.Type != token.TypeMFAPending {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "invalid MFA token"})
		return
	}

	// Per-account lockout (RFC 4226 §7.2-7.3) through the WHOLE-cycle-in-one-
	// transaction seam (v7 §2.3): lock check and reset share the users fence,
	// so a lock committed by a concurrent cycle can never be cleared by a
	// stale unlocked observation.
	outcome, cycleErr := authn.VerifyTOTPWithLockout(r.Context(), h.pool, claims.UserID, req.Code)
	switch outcome {
	case authn.TOTPLocked:
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusTooManyRequests, Detail: "account locked due to too many TOTP failures"})
		return
	case authn.TOTPInvalid:
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "invalid TOTP code"})
		return
	case authn.TOTPBookkeepingError:
		// 500 `internal error`; no tokens; no session state change.
		h.logger.Error("totp: lockout bookkeeping error", "user_id", claims.UserID, "error", cycleErr)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}

	user, err := h.lookupUser(r.Context(), "id", claims.UserID)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "user not found"})
		return
	}
	*r = *r.WithContext(threat.WithUserID(r.Context(), user.ID))
	// First factor (recorded in the MFA-pending token) + OTP just verified.
	h.issueTokensFromMFAPending(
		w, r, user, claims,
		h.completionMetadataForDPoP(req.DPoPJWK, true),
		token.AMROTP,
	)
}

// TOTPEnrollmentConfirm verifies the first code against the STAGED pending
// secret, activates mandatory TOTP, consumes the bootstrap grant, and bumps
// the generation — all in the confirmation transaction — then issues the
// same MFA-complete session as TOTPVerify. Signed-fence challenges keep the
// row lock, fence rechecks, activation, family anchor, and deferred response
// under one caller-owned transaction.
//
// POST /auth/totp/enroll/confirm — unauthenticated; accepts
// {"mfa_token":"...","code":"...","enrollment_id":"<uuid>","dpop_jwk":{...}}.
func (h *mfaHandler) TOTPEnrollmentConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MFAToken     string         `json:"mfa_token"`
		Code         string         `json:"code"`
		EnrollmentID string         `json:"enrollment_id"`
		DPoPJWK      map[string]any `json:"dpop_jwk,omitempty"`
	}
	if !decodeBoundedAuthJSON(w, r, &req) {
		return
	}
	claims, err := h.jwt.Validate(req.MFAToken)
	if err != nil || claims.Type != token.TypeMFAPending {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "invalid MFA token"})
		return
	}
	if rejectImpersonated(w, r, claims) {
		return
	}
	if req.Code == "" || req.EnrollmentID == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "code and enrollment_id are required"})
		return
	}

	if claims.IdentityFence != nil || claims.CredentialFence != "" {
		h.confirmFencedTOTPEnrollment(w, r, claims, req.Code, req.EnrollmentID, req.MFAToken, req.DPoPJWK)
		return
	}

	// Legacy challenges: one transaction for fences + grant + promotion.
	tx, err := h.beginGateTx(r.Context())
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusServiceUnavailable, Detail: "identity mint fence unavailable"})
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck
	outcome, promoErr := h.promoteBootstrapTOTPEnrollment(r.Context(), tx, claims, req.Code, req.EnrollmentID, req.MFAToken, httputil.ClientIP(r))
	if promoErr != nil {
		h.writeBootstrapPromotionError(w, r, claims, promoErr)
		return
	}
	if outcome != authn.TOTPAccepted {
		if err := tx.Commit(r.Context()); err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusServiceUnavailable, Detail: "totp confirmation commit failed"})
			return
		}
		if outcome == authn.TOTPLocked {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusTooManyRequests, Detail: "account locked due to too many TOTP failures"})
		} else {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "invalid TOTP code"})
		}
		return
	}
	user, err := h.lookupUser(r.Context(), "id", claims.UserID)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "user not found"})
		return
	}
	*r = *r.WithContext(threat.WithUserID(r.Context(), user.ID))
	completionMetadata := h.completionMetadataForDPoP(req.DPoPJWK, true)
	completionMetadata.MintTx = tx
	pending := newDeferredTokenResponse()
	h.issueTokensFromMFAPending(pending, r, user, claims, completionMetadata, token.AMROTP)
	if _, err := commitDeferredTokenResponse(r.Context(), w, pending, tx.Commit); err != nil {
		h.logger.Error("totp enrollment commit failed before token response", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusServiceUnavailable, Detail: "identity token commit failed"})
	}
}

// confirmFencedTOTPEnrollment is the signed-fence variant: everything under
// the one caller-owned transaction (identity fence → credential fence →
// grant + promotion → deferred token response → commit).
func (h *mfaHandler) confirmFencedTOTPEnrollment(
	w http.ResponseWriter,
	r *http.Request,
	claims *token.Claims,
	code, enrollmentID, mfaToken string,
	dpopJWK map[string]any,
) {
	user, err := h.lookupUser(r.Context(), "id", claims.UserID)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusUnauthorized,
			Detail: "user not found",
		})
		return
	}
	tx, err := h.beginGateTx(r.Context())
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusServiceUnavailable,
			Detail: "identity mint fence unavailable",
		})
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck
	if err := applyAuthenticationMintFence(
		r.Context(), tx, claims.UserID, claims.IdentityFence,
	); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusConflict,
				Detail: "authentication identity changed before MFA enrollment",
			})
		}
		return
	}
	if err := verifyCredentialFence(
		r.Context(), tx, claims.UserID, claims.CredentialFence,
	); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusUnauthorized,
			Detail: "Credentials changed during sign-in. Please authenticate again.",
		})
		return
	}

	outcome, promoErr := h.promoteBootstrapTOTPEnrollment(r.Context(), tx, claims, code, enrollmentID, mfaToken, httputil.ClientIP(r))
	if promoErr != nil {
		h.writeBootstrapPromotionError(w, r, claims, promoErr)
		return
	}
	if outcome != authn.TOTPAccepted {
		if err := tx.Commit(r.Context()); err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusServiceUnavailable,
				Detail: "totp confirmation commit failed",
			})
			return
		}
		if outcome == authn.TOTPLocked {
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusTooManyRequests,
				Detail: "account locked due to too many TOTP failures",
			})
		} else {
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusUnauthorized,
				Detail: "invalid TOTP code",
			})
		}
		return
	}

	*r = *r.WithContext(threat.WithUserID(r.Context(), user.ID))
	completionMetadata := h.completionMetadataForDPoP(dpopJWK, true)
	completionMetadata.MintTx = tx
	pending := newDeferredTokenResponse()
	h.issueTokensFromMFAPending(
		pending, r, user, claims, completionMetadata, token.AMROTP,
	)
	if _, err := commitDeferredTokenResponse(
		r.Context(), w, pending, tx.Commit,
	); err != nil {
		h.logger.Error("fenced totp enrollment commit failed before token response",
			"user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusServiceUnavailable,
			Detail: "identity token commit failed",
		})
	}
}

// promoteBootstrapTOTPEnrollment runs the bootstrap promotion INSIDE the
// caller's transaction: the enrollment-confirm budget caller (§2.3 item 5),
// the grant consumption (bootstrap.totp.enroll, mfa_pending scope, bound to
// the presented enrollment_id) and the enable + generation bump + audit.
// The identity/credential fences are the caller's responsibility (they ran
// already when this is called on the fenced path; the legacy path runs them
// via ConfirmTOTPEnrollment's replacement here — no, the legacy path runs
// them in its own wrapper).
func (h *mfaHandler) promoteBootstrapTOTPEnrollment(
	ctx context.Context, tx pgx.Tx, claims *token.Claims, code, enrollmentID, mfaToken, clientIP string,
) (authn.TOTPVerifyOutcome, error) {
	// The §2.2 fences (the enrollment tx owns the users row from here).
	if err := authn.PersonFence(ctx, tx, claims.UserID); err != nil {
		return authn.TOTPBookkeepingError, err
	}
	if _, err := authn.UsersFence(ctx, tx, claims.UserID); err != nil {
		return authn.TOTPBookkeepingError, err
	}
	revoked, err := durableRecheckForClaims(ctx, tx, claims)
	if err != nil {
		return authn.TOTPBookkeepingError, err
	}
	if revoked {
		return authn.TOTPInvalid, errBootstrapRevoked
	}
	// Enrollment must still be policy-required.
	var mfaStatus string
	if err := tx.QueryRow(ctx,
		`SELECT mfa_status($1)->>'status'`, claims.UserID,
	).Scan(&mfaStatus); err != nil {
		return authn.TOTPBookkeepingError, err
	}
	if mfaStatus != "enrollment_required" {
		return authn.TOTPInvalid, authn.ErrTOTPEnrollmentUnavailable
	}

	// Grant binding tuple: {bootstrap.totp.enroll, mfa_pending scope,
	// target_ref = presented enrollment_id}.
	family := ""
	pred := authn.GrantPredicate{
		TokenHash:     authn.ReauthTokenHash(mfaToken),
		UserID:        claims.UserID,
		SessionJTI:    claims.JTI,
		Operation:     authn.OperationBootstrapTOTPEnroll,
		TargetBound:   true,
		TargetRef:     &enrollmentID,
		TokenScope:    authn.ProofScopeMFAPending,
		FamilyBound:   true,
		RefreshFamily: &family,
	}
	if _, err := authn.PeekGrant(ctx, tx, pred); err != nil {
		var mismatch *authn.GrantMismatchError
		if errors.As(err, &mismatch) || errors.Is(err, authn.ErrGrantRequired) {
			// The §1.7 mismatch refusal (classifyGrantMiss already deleted
			// the dead grant in-tx). The cleanup COMMITS before the refusal
			// is returned (r8): a rolled-back mismatch deletion hands the
			// burned bootstrap proof back, so a wrong enrollment-ID attempt
			// leaves the grant usable on the next attempt (§1.7 violation).
			if cleanupErr := h.commitGrantMismatchRefusal(ctx, tx, claims.UserID, pred.TokenHash, claims.JTI,
				clientIP, "bootstrap enrollment grant mismatch"); cleanupErr != nil {
				return authn.TOTPBookkeepingError, cleanupErr
			}
			return authn.TOTPInvalid, errBootstrapGrantRequired
		}
		return authn.TOTPBookkeepingError, err
	}
	// The staged row must resolve for THIS user + pending JTI.
	secret, _, err := authn.ReadPendingTOTPEnrollment(ctx, tx, claims.UserID, enrollmentID, claims.JTI)
	if err != nil {
		if errors.Is(err, authn.ErrGrantRequired) {
			// Tuple mismatch: the §1.7 refusal deletes the outstanding grant
			// — and the deletion COMMITS (r8, same shape as the peek path).
			if cleanupErr := h.commitGrantMismatchRefusal(ctx, tx, claims.UserID, pred.TokenHash, claims.JTI,
				clientIP, "bootstrap enrollment binding mismatch"); cleanupErr != nil {
				return authn.TOTPBookkeepingError, cleanupErr
			}
			return authn.TOTPInvalid, errBootstrapGrantRequired
		}
		return authn.TOTPBookkeepingError, err
	}

	// The §2.3 budget read BEFORE evaluation (r3 defect 6): the fences above
	// hold the users row, so this read sees every lock committed before the
	// fence was taken. A locked budget refuses WITHOUT evaluating the code —
	// a valid code must never reach promotion, whose write clears the active
	// lock.
	locked, err := authn.TOTPLockedUnderFence(ctx, tx, claims.UserID)
	if err != nil {
		return authn.TOTPBookkeepingError, err
	}
	if locked {
		return authn.TOTPLocked, nil
	}

	// The §2.3 enrollment-confirm budget cycle (item 5): the code is checked
	// against the STAGED secret; failure records the atomic increment.
	now := time.Now()
	if !authn.ValidateTOTPCode(code, secret) {
		var lockedAfter *time.Time
		err := tx.QueryRow(ctx,
			`UPDATE users
			    SET totp_failed_attempts = totp_failed_attempts + 1,
			        totp_locked_until =
			          CASE WHEN totp_failed_attempts + 1 >= $2
			               THEN now() + make_interval(secs => $3)
			               ELSE totp_locked_until END
			  WHERE id = $1
			    AND (totp_locked_until IS NULL OR totp_locked_until <= now())
			  RETURNING totp_locked_until`,
			claims.UserID, authn.TOTPMaxFailures, authn.TOTPLockDurationSecs,
		).Scan(&lockedAfter)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return authn.TOTPLocked, nil
			}
			return authn.TOTPBookkeepingError, err
		}
		if lockedAfter != nil && lockedAfter.After(now) {
			return authn.TOTPLocked, nil
		}
		return authn.TOTPInvalid, nil
	}

	// Consume the grant before activation (§1.6: the single-use DELETE with
	// the generation equality against the still-unbumped users row).
	g, err := authn.ConsumeGrant(ctx, tx, pred)
	if err != nil {
		return authn.TOTPBookkeepingError, err
	}
	// §1.1 full-tuple consumption (opus r1 finding 4): the mfa_pending
	// grant's proving credential must still be live (password-proven C3
	// grants pass trivially; a webauthn_uv-proven grant whose credential was
	// revoked between finish and confirm refuses — tx rolls back).
	if live, factorErr := authn.ProvingFactorStillEnabled(ctx, tx, g); factorErr != nil {
		return authn.TOTPBookkeepingError, factorErr
	} else if !live {
		return authn.TOTPInvalid, errBootstrapGrantRequired
	}
	// Promotion: INSTALL the staged secret as the active factor (r1 defect 3:
	// the enable ran without the secret, leaving a fresh account with an
	// unusable active factor), enable, bump the generation (§1.8), delete the
	// pending row, audit — one commit by the caller.
	tag, err := tx.Exec(ctx,
		`UPDATE users
		    SET totp_secret_enc = pgp_sym_encrypt($2, current_setting('app.encryption_key')),
		        totp_enabled = TRUE,
		        totp_enabled_at = $3,
		        last_totp_used_at = $3,
		        totp_failed_attempts = 0,
		        totp_locked_until = NULL,
		        factor_generation = factor_generation + 1
		  WHERE id = $1
		    AND enabled = TRUE
		    AND COALESCE(totp_enabled, FALSE) = FALSE`,
		claims.UserID, secret, now,
	)
	if err != nil {
		return authn.TOTPBookkeepingError, err
	}
	if tag.RowsAffected() != 1 {
		return authn.TOTPInvalid, authn.ErrTOTPEnrollmentUnavailable
	}
	if err := authn.DeletePendingTOTPEnrollment(ctx, tx, claims.UserID, enrollmentID); err != nil {
		return authn.TOTPBookkeepingError, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO admin_audit_log (user_id, ip, action, target_type, target_id)
		 VALUES ($1, NULLIF($2, '')::INET, 'totp_confirmed', 'user', $1)`,
		claims.UserID, clientIP,
	); err != nil {
		return authn.TOTPBookkeepingError, err
	}
	return authn.TOTPAccepted, nil
}

// writeBootstrapPromotionError maps promotion errors to the bootstrap wire
// contract (fail-closed: bookkeeping → 500; binding/refusal → 403/401/409).
func (h *mfaHandler) writeBootstrapPromotionError(w http.ResponseWriter, r *http.Request, claims *token.Claims, err error) {
	switch {
	case errors.Is(err, authn.ErrTOTPEnrollmentUnavailable):
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusConflict, Detail: "MFA enrollment state changed; sign in again"})
	case errors.Is(err, errBootstrapGrantRequired), errors.Is(err, errBootstrapRevoked):
		writeReauthRequired(w, r)
	default:
		h.logger.Error("bootstrap enrollment confirm failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "totp confirmation failed"})
	}
}

// Sentinels for the bootstrap promotion mapping.
var (
	errBootstrapGrantRequired = errors.New("bootstrap possession grant required")
	errBootstrapRevoked       = errors.New("session revoked")
)
