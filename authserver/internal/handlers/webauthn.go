package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/token"
	shareddevice "setjoin.com/shared/device"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pwhash"
	"setjoin.com/shared/threat"
)

// ── WebAuthn (Passkeys) ──

// webauthnRegistrationBodyLimit mirrors the mount cap (main.go): the finish
// arm buffers the attestation body itself for the in-transaction
// verification, so the cap must exist at both layers.
const webauthnRegistrationBodyLimit int64 = 64 << 10

// WebAuthnRegisterBegin returns PublicKeyCredentialCreationOptions for registering a new passkey.
//
// Possession gate (v7 §1.6/§1.4): begin is the REGISTRATION begin arm — it
// PEEKS the webauthn.register grant, performs the grant's ONE-TIME target
// binding (target_ref = the ceremony's challenge hash), and creates the
// server-side registration ceremony row, all in the §2.2-fenced transaction
// that also mints the creation options. A grant already bound to a live
// ceremony answers 200 with its binding status (the client reuses its
// already-issued options + wa_reg_sess cookie — no second ceremony).
func (h *mfaHandler) WebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	claims := h.mustUser(w, r)
	if claims == nil {
		return
	}
	cp := h.ceremonyProvider()
	if cp == nil {
		http.NotFound(w, r)
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

	family := claims.RefreshFamilyID()
	grant, err := authn.PeekGrant(ctx, tx, authn.GrantPredicate{
		TokenHash:     authn.ReauthTokenHash(reauthTokenFromRequest(w, r)),
		UserID:        claims.UserID,
		SessionJTI:    claims.JTI,
		Operation:     authn.OperationWebAuthnRegister,
		TargetBound:   false,
		TokenScope:    authn.ProofScopeSession,
		FamilyBound:   true,
		RefreshFamily: &family,
	})
	if err != nil {
		h.writeGrantGateRefusal(w, r, tx, claims.UserID, err, "webauthn register begin")
		return
	}

	// RESUME: already bound + live ceremony → no second ceremony; the client
	// reuses its already-issued creation options and cookie.
	if grant.TargetRef != nil {
		var live bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (
			   SELECT 1 FROM webauthn_ceremonies
			    WHERE challenge_hash = $1 AND user_id = $2 AND kind = 'registration'
			      AND expires_at > now()
			 )`,
			*grant.TargetRef, claims.UserID,
		).Scan(&live); err != nil {
			h.logger.Error("webauthn register resume lookup failed", "error", err)
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
			return
		}
		if live {
			if err := tx.Commit(ctx); err != nil {
				h.logger.Error("webauthn register resume commit failed", "error", err)
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"status": "bound"})
			return
		}
		// Bound grant with a dead ceremony: fail closed 409 — re-prove.
		_ = tx.Rollback(ctx)
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusConflict,
			Detail: "this proof already authorized a different ceremony; present a fresh proof",
			Code:   "proof_already_bound",
		})
		return
	}

	optJSON, sessJSON, challengeHash, err := cp.BeginRegistrationCeremony(ctx, tx, claims.UserID)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "webauthn error: " + err.Error()})
		return
	}
	// One-time binding + ceremony row, atomically with the options.
	bound, err := authn.BindGrantTarget(ctx, tx, grant.TokenHash, claims.UserID, claims.JTI, challengeHash)
	if err != nil {
		h.writeGrantGateRefusal(w, r, tx, claims.UserID, err, "webauthn register binding")
		return
	}
	if !bound {
		_ = tx.Rollback(ctx)
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusConflict,
			Detail: "this proof already authorized a different ceremony; present a fresh proof",
			Code:   "proof_already_bound",
		})
		return
	}
	if err := authn.CreateCeremony(ctx, tx, authn.Ceremony{
		ChallengeHash:   challengeHash,
		UserID:          claims.UserID,
		Kind:            ceremonyKindRegistration,
		Operation:       authn.OperationWebAuthnRegister,
		TargetRef:       &challengeHash,
		SessionJTI:      claims.JTI,
		TokenScope:      authn.ProofScopeSession,
		RefreshFamilyID: familyOrNil(family),
	}); err != nil {
		h.logger.Error("webauthn ceremony create failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("webauthn register begin commit failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}

	// The response cookie stays as TRANSPORT (the attestation session data);
	// the ceremony row is the authority.
	enc, err := h.encryptCookieValue(sessJSON)
	if err != nil {
		h.logger.Error("webauthn cookie encrypt failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "wa_reg_sess", Value: enc,
		MaxAge: 300, HttpOnly: true, Secure: h.cookieSecure || r.TLS != nil || h.forwardedHTTPS(r), SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Content-Type", "application/json")
	w.Write(optJSON)
}

// WebAuthnRegisterFinish validates the attestation and persists the passkey.
//
// Possession gate (v7 §1.6/§2.2): the finish is ONE transaction — fences →
// durable revocation recheck → attestation verification → consume the
// ceremony row AND the presented webauthn.register grant (whose target_ref
// must equal the ceremony's challenge hash) → persist the credential (with
// its attested uv_capable flag) → bump factor_generation → success audit.
// One replayed ceremony can never produce two credentials/grants.
func (h *mfaHandler) WebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	claims := h.mustUser(w, r)
	if claims == nil {
		return
	}
	cp := h.ceremonyProvider()
	if cp == nil {
		http.NotFound(w, r)
		return
	}
	if rejectImpersonated(w, r, claims) {
		return
	}
	cookie, err := r.Cookie("wa_reg_sess")
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "missing session cookie"})
		return
	}
	sessJSON, err := h.decryptCookieValue(cookie.Value)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid session cookie"})
		return
	}
	// Buffer the attestation body for the in-transaction verification, and
	// decode the reauth_token from THESE bytes (r1 defect 1: a second body
	// read yields nothing — the ordinary UI presents the token as a body
	// member on this POST; the X-MFA-Reauth header keeps GET-arm parity and
	// takes precedence when present).
	r.Body = http.MaxBytesReader(w, r.Body, webauthnRegistrationBodyLimit) // 1 MiB, the mount's cap
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid request body"})
		return
	}
	challengeHash, err := authn.ChallengeHashFromSessionJSON(sessJSON)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid session cookie"})
		return
	}
	reauthToken := reauthTokenFromBodyBytes(r, bodyBytes)

	tx, _, ok := h.fencedFactorTx(w, r, claims)
	if !ok {
		return
	}
	ctx := r.Context()
	defer func() { _ = tx.Rollback(ctx) }()

	family := claims.RefreshFamilyID()
	// Verify + consume + persist, one commit, in the §2.2 authorization
	// order (r1 defect 1): the attestation is VERIFIED first (no writes),
	// the ceremony row and the presented webauthn.register grant (whose
	// target_ref must equal the ceremony's challenge hash) are CONSUMED
	// next — the grant refusal's commit therefore carries nothing but the
	// §1.7 mismatch deletion — and ONLY THEN is the credential persisted.
	// A verification failure consumed nothing; a refused authorization
	// persists nothing; a replayed ceremony loses the single-use DELETE.
	cred, verifyErr := cp.VerifyRegistrationCredential(ctx, tx, claims.UserID, sessJSON, bodyBytes)
	if verifyErr != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "registration failed: " + verifyErr.Error()})
		return
	}
	if _, err := authn.ConsumeCeremony(ctx, tx, claims.UserID,
		ceremonyKindRegistration, authn.ProofScopeSession, claims.JTI, challengeHash); err != nil {
		if errors.Is(err, authn.ErrGrantRequired) {
			writeReauthRequired(w, r)
			return
		}
		h.logger.Error("webauthn ceremony consume failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	pred := authn.GrantPredicate{
		TokenHash:     authn.ReauthTokenHash(reauthToken),
		UserID:        claims.UserID,
		SessionJTI:    claims.JTI,
		Operation:     authn.OperationWebAuthnRegister,
		TargetBound:   true,
		TargetRef:     &challengeHash,
		TokenScope:    authn.ProofScopeSession,
		FamilyBound:   true,
		RefreshFamily: &family,
	}
	g, err := authn.ConsumeGrant(ctx, tx, pred)
	if err != nil {
		h.writeGrantGateRefusal(w, r, tx, claims.UserID, err, "webauthn register finish")
		return
	}
	// §1.1 full-tuple consumption (opus r1 finding 4): the proving factor is
	// still enabled/not-revoked — a webauthn_uv-proof grant whose proving
	// credential was revoked between proof and finish refuses here (the tx
	// rolls back: ceremony and grant stay, nothing partial commits).
	if live, factorErr := authn.ProvingFactorStillEnabled(ctx, tx, g); factorErr != nil {
		h.logger.Error("proving factor check failed", "user_id", claims.UserID, "error", factorErr)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	} else if !live {
		h.auditMFAReauthRefusal(r, claims.UserID, "possession proof refused: proving factor no longer live")
		writeReauthRequired(w, r)
		return
	}
	if err := cp.PersistRegistrationCredentialTx(ctx, tx, claims.UserID, cred); err != nil {
		h.logger.Error("webauthn credential persist failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	// §1.8: registration (including same-ID replacement) bumps the
	// generation — every outstanding grant dies.
	if _, err := tx.Exec(ctx,
		`UPDATE users SET factor_generation = factor_generation + 1 WHERE id = $1`,
		claims.UserID,
	); err != nil {
		h.logger.Error("webauthn registration generation bump failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO admin_audit_log (user_id, ip, action, target_type, target_id, notes)
		 VALUES ($1, $2::INET, 'passkey_registered', 'user', $1, $3)`,
		claims.UserID, httputil.ClientIP(r), uvCapabilityNote(cred.Flags.UserVerified)); err != nil {
		h.logger.Error("webauthn registration audit failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("webauthn register finish commit failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// uvCapabilityNote is the audit note recording the persisted uv_capable
// classification (§1.2 — cohort input; pre-GA unknowns classify non-UV).
func uvCapabilityNote(uvCapable bool) string {
	if uvCapable {
		return "uv_capable=true"
	}
	return "uv_capable=false"
}

// WebAuthnLoginBegin returns PublicKeyCredentialRequestOptions for passkey login.
func (h *mfaHandler) WebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	if h.passkey == nil {
		http.NotFound(w, r)
		return
	}
	email := r.URL.Query().Get("email")
	userID, optJSON, sessJSON, err := h.passkey.BeginLogin(r.Context(), email)
	if err != nil {
		// BeginLogin returns a decoy assertion for unknown / credential-less
		// accounts, so an error here is a genuine internal failure. Keep the
		// status uniform with the success path's failure modes.
		h.logger.Error("webauthn login begin failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	enc, err := h.encryptCookieValue(sessJSON)
	if err != nil {
		h.logger.Error("webauthn login cookie encrypt failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	// Encrypt the user id: a plaintext uid (0 for the decoy path) would let the
	// client distinguish a real account from a decoy, re-introducing the
	// enumeration leak this endpoint is hardened against.
	uidEnc, err := h.encryptCookieValue([]byte(strconv.FormatInt(userID, 10)))
	if err != nil {
		h.logger.Error("webauthn login uid cookie encrypt failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "wa_login_sess", Value: enc,
		MaxAge: 300, HttpOnly: true, Secure: h.cookieSecure || r.TLS != nil || h.forwardedHTTPS(r), SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "wa_login_uid", Value: uidEnc,
		MaxAge: 300, HttpOnly: true, Secure: h.cookieSecure || r.TLS != nil || h.forwardedHTTPS(r), SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Content-Type", "application/json")
	w.Write(optJSON)
}

// WebAuthnLoginFinish verifies the assertion and issues a JWT.
func (h *mfaHandler) WebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	if h.passkey == nil {
		http.NotFound(w, r)
		return
	}
	sessCookie, err := r.Cookie("wa_login_sess")
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "missing session cookie"})
		return
	}
	uidCookie, err := r.Cookie("wa_login_uid")
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "missing uid cookie"})
		return
	}
	uidPlain, err := h.decryptCookieValue(uidCookie.Value)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid uid cookie"})
		return
	}
	userID, err := strconv.ParseInt(string(uidPlain), 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid uid cookie"})
		return
	}
	sessJSON, err := h.decryptCookieValue(sessCookie.Value)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid session cookie"})
		return
	}

	// CA-3a/DPoP: the SPA POSTs its DPoP JWK as an extra top-level `dpop_jwk`
	// field alongside the WebAuthn assertion body. h.passkey.FinishLogin reads
	// r.Body itself (go-webauthn's own JSON parse of the assertion), so the body
	// must be buffered here and restored — a single io.Reader can't be consumed
	// twice. A malformed/missing dpop_jwk is a best-effort no-op (nil map), never
	// a login failure; the real assertion parse below still validates the body.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid request body"})
		return
	}
	// med-shard2-006 body binding: go-webauthn re-consumes the restored body
	// during FinishLogin, so by the time the completion CA gate verifies the
	// device proof (threat.DeviceCredentialResolver →
	// shared/device.VerifyDeviceRequest) the bytes are gone. Stamp the
	// server-computed digest over the buffered bytes
	// (shared/device.WithServerBodyDigest) so the signed X-Device-Body-SHA256
	// commitment binds to what this handler actually observed.
	*r = *shareddevice.WithServerBodyDigest(r, bodySHA256Hex(bodyBytes))
	var dpop struct {
		DPoPJWK map[string]any `json:"dpop_jwk,omitempty"`
	}
	_ = json.Unmarshal(bodyBytes, &dpop) // best-effort; a real parse error surfaces from FinishLogin below
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	if err := h.passkey.FinishLogin(r.Context(), userID, sessJSON, r); err != nil {
		pwhash.LogAuthEvent(r.Context(), h.pool, pwhash.AuthEvent{
			Event: "login_failed", Provider: "webauthn",
			IPAddress: httputil.ClientIP(r),
		}, nil)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "login failed: " + err.Error()})
		return
	}
	user, err := h.lookupUser(r.Context(), "id", userID)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "user not found"})
		return
	}

	// Check if the user has a challengeable second factor — route through MFA if
	// so. The enrollment snapshot + accept order come from the one shared seam
	// (CredentialStore + SelectMFAMethod), the same Login uses. A lookup error
	// degrades to "no MFA enrolled" (all-false), exactly as the prior unchecked
	// SELECT-and-Scan did when it failed.
	creds, _ := h.credentials.CredentialsFor(r.Context(), userID)
	totpEnabled := creds.TOTPEnrolled

	if creds.AnyChallengeMFAEnrolled() {
		// G4: WebAuthn is passwordless — evaluate + enforce conditional access HERE,
		// before issuing the mfa_pending token, mirroring the password Login path
		// (auth.go runs CA before its MFA branch). The downstream second-factor
		// completion (totp/push) runs audit-only under CompletionMetadata and
		// ASSUMES a prior enforced leg; without this, a passkey-then-2FA login from a
		// blocked context would have its block silently discarded (the completion gate
		// computes but never enforces it). AuthMethod resolves to "webauthn" (the leg
		// completed so far). No-op when no policy engine is wired.
		if stop, _ := h.evaluateCompletionConditionalAccess(w, r, user, CompletionRequest{
			Factors: []string{token.AMRHardwareKey},
		}); stop {
			return
		}
		resp := map[string]interface{}{"mfa_required": true}

		// Push MFA is the preferred method (prevents MFA fatigue via number matching)
		if creds.SelectMFAMethod(h.pushMFA != nil) == "push" {
			// The passkey assertion is the first factor (hwk); record it in the
			// MFA-pending token so the push-verify step derives aal2 over hwk+push.
			mfaToken, err := h.jwt.IssueMFAPendingWithAMR(user.ID, user.Email, token.AMRHardwareKey)
			if err != nil {
				h.logger.Warn("push MFA: failed to issue mfa_token, falling back to TOTP", "error", err)
			} else {
				challenge, err := h.pushMFA.GenerateChallenge(r.Context(), user.ID, "")
				if err == nil {
					resp["mfa_method"] = challenge.Method
					resp["mfa_token"] = mfaToken
					resp["nonce"] = challenge.Nonce
					// SECURITY (C10): the correct number-match code is NOT returned to the
					// login client — it is an out-of-band proof verified only on the
					// enrolled device (POST /auth/mfa/approve).
					resp["ttl_seconds"] = challenge.TTLSeconds
					resp["fallback"] = []string{"totp", "backup_codes"}
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(resp)
					return
				}
				h.logger.Warn("push MFA challenge generation failed, falling back to TOTP", "error", err)
			}
		}

		// TOTP fallback
		if totpEnabled {
			// Passkey assertion is the first factor (hwk); TOTP verify appends otp.
			totpToken, err := h.jwt.IssueMFAPendingWithAMR(user.ID, user.Email, token.AMRHardwareKey)
			if err != nil {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
				return
			}
			resp["mfa_method"] = "totp"
			resp["mfa_token"] = totpToken
			resp["fallback"] = []string{"backup_codes"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "MFA required but no method available"})
		return
	}

	*r = *r.WithContext(threat.WithUserID(r.Context(), user.ID))
	// CA-3a/DPoP: WebAuthn login is passwordless — there is no earlier password
	// step to carry a JWK forward from, so this completion request is the ONLY
	// place the SPA can supply one (shape (a), see totp.go for the two-shape
	// rationale).
	// Passkey login with no additional MFA: a single hardware-key factor (hwk).
	h.issueTokensWithFactors(w, r, user, CompletionRequest{
		Factors:  []string{token.AMRHardwareKey},
		Metadata: h.completionMetadataForDPoP(dpop.DPoPJWK, false),
	})
}

// WebAuthnNameCredential sets a human-readable name for a passkey.
func (h *mfaHandler) WebAuthnNameCredential(w http.ResponseWriter, r *http.Request) {
	claims := h.mustUser(w, r)
	if claims == nil {
		return
	}
	if h.passkey == nil {
		http.NotFound(w, r)
		return
	}
	credID := r.PathValue("id")
	if credID == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "missing credential id"})
		return
	}
	var req struct {
		DeviceName string `json:"device_name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.DeviceName == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "device_name required"})
		return
	}
	credIDBytes, ok := decodeCredentialID(w, r, credID)
	if !ok {
		return
	}
	err := h.passkey.NameCredential(r.Context(), credIDBytes, claims.UserID, req.DeviceName)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "failed: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
}

// decodeCredentialID decodes the base64url credential id the wire carries back
// into the RAW bytes passkey_credentials.id stores. WebAuthnListCredentials
// emits base64.RawURLEncoding.EncodeToString(id); handing the ENCODED string's
// bytes straight to RevokeCredential/NameCredential compared base64 text
// against raw authenticator IDs — a roundtrip mismatch that matched no row, so
// revocation (the credential-lifecycle control for a stolen laptop) silently
// did nothing and renaming always failed.
func decodeCredentialID(w http.ResponseWriter, r *http.Request, credID string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(credID)
	if err != nil || len(raw) == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid credential id"})
		return nil, false
	}
	return raw, true
}

// WebAuthnRevokeCredential revokes a single passkey.
//
// Possession gate (v7 §3, §3.2 T4): targeted revocation consumes a
// webauthn.revoke grant whose target_ref — bound AT ISSUANCE and
// ownership-validated there — must byte-equal the presented {id}; the
// revocation runs INSIDE the §2.2-fenced transaction (the consume-vs-revoke
// race closure) with the generation bump, closing the historical
// fence-less UPDATE. Consumption re-checks the presented {id} against
// target_ref (byte equality, §1.1).
func (h *mfaHandler) WebAuthnRevokeCredential(w http.ResponseWriter, r *http.Request) {
	claims := h.mustUser(w, r)
	if claims == nil {
		return
	}
	cp := h.ceremonyProvider()
	if cp == nil {
		http.NotFound(w, r)
		return
	}
	if rejectImpersonated(w, r, claims) {
		return
	}
	credID := r.PathValue("id")
	if credID == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "missing credential id"})
		return
	}
	credIDBytes, ok := decodeCredentialID(w, r, credID)
	if !ok {
		return
	}

	tx, _, ok := h.fencedFactorTx(w, r, claims)
	if !ok {
		return
	}
	ctx := r.Context()
	defer func() { _ = tx.Rollback(ctx) }()

	family := claims.RefreshFamilyID()
	// target_ref comparison: byte equality between the presented {id} and
	// the grant's bound target (stored canonically).
	targetRef := base64.RawURLEncoding.EncodeToString(credIDBytes)
	pred := authn.GrantPredicate{
		TokenHash:     authn.ReauthTokenHash(reauthTokenFromRequest(w, r)),
		UserID:        claims.UserID,
		SessionJTI:    claims.JTI,
		Operation:     authn.OperationWebAuthnRevoke,
		TargetBound:   true,
		TargetRef:     &targetRef,
		TokenScope:    authn.ProofScopeSession,
		FamilyBound:   true,
		RefreshFamily: &family,
	}
	g, err := authn.ConsumeGrant(ctx, tx, pred)
	if err != nil {
		h.writeGrantGateRefusal(w, r, tx, claims.UserID, err, "webauthn revoke")
		return
	}
	// §1.1 full-tuple consumption (opus r1 finding 4): the proving factor is
	// still enabled/not-revoked — a revoke whose PROVING credential died
	// between proof and DELETE refuses before the target is touched (tx
	// rolls back: the grant survives until its TTL).
	if live, factorErr := authn.ProvingFactorStillEnabled(ctx, tx, g); factorErr != nil {
		h.logger.Error("proving factor check failed", "user_id", claims.UserID, "error", factorErr)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	} else if !live {
		h.auditMFAReauthRefusal(r, claims.UserID, "possession proof refused: proving factor no longer live")
		writeReauthRequired(w, r)
		return
	}
	revoked, err := cp.RevokeCredentialTx(ctx, tx, credIDBytes, claims.UserID)
	if err != nil {
		h.logger.Error("webauthn revoke failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "failed: " + err.Error()})
		return
	}
	if !revoked {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "credential not found or already revoked"})
		return
	}
	// §1.8 + §2.5: revocation mutates the factor set (generation bump kills
	// every outstanding grant) and best-effort-deletes grants proven by the
	// revoked credential as immediate cleanup.
	if _, err := tx.Exec(ctx,
		`UPDATE users SET factor_generation = factor_generation + 1 WHERE id = $1`,
		claims.UserID,
	); err != nil {
		h.logger.Error("webauthn revoke generation bump failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	if err := authn.DeleteGrantsForFactor(ctx, tx, claims.UserID, credIDBytes); err != nil {
		h.logger.Error("webauthn revoke grant cleanup failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO admin_audit_log (user_id, ip, action, target_type, target_id)
		 VALUES ($1, $2::INET, 'passkey_revoked', 'user', $1)`,
		claims.UserID, httputil.ClientIP(r)); err != nil {
		h.logger.Error("webauthn revoke audit failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("webauthn revoke commit failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// WebAuthnListCredentials returns the list of registered passkey credentials for the authenticated user.
//
// Possession gate (v7 §3 — read-only, not gated): each credential carries
// its persisted uv_capable flag (§1.2) so clients can decide whether to
// offer the WebAuthn-UV proof arm to passkey-only C1 accounts; without it
// they fail-close to the server's method-aware 403 backstop.
func (h *mfaHandler) WebAuthnListCredentials(w http.ResponseWriter, r *http.Request) {
	claims := h.mustUser(w, r)
	if claims == nil {
		return
	}
	if h.pool == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database unavailable"})
		return
	}
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, COALESCE(device_name,'') AS device_name, created_at, uv_capable
		 FROM passkey_credentials
		 WHERE user_id = $1 AND revoked_at IS NULL
		 ORDER BY created_at DESC`,
		claims.UserID)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		return
	}
	defer rows.Close()

	type cred struct {
		ID         string    `json:"id"`
		DeviceName string    `json:"device_name"`
		CreatedAt  time.Time `json:"created_at"`
		UVCapable  bool      `json:"uv_capable"`
	}
	creds := make([]cred, 0)
	for rows.Next() {
		var (
			c  cred
			id []byte
		)
		if err := rows.Scan(&id, &c.DeviceName, &c.CreatedAt, &c.UVCapable); err != nil {
			continue
		}
		c.ID = base64.RawURLEncoding.EncodeToString(id)
		creds = append(creds, c)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"credentials": creds})
}

// decodeJSON helper for small request bodies.
func decodeJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}
