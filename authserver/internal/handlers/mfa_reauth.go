package handlers

// mfa_reauth.go — the client-visible re-authentication / possession-proof
// contract for factor management (possession scheme v7, §1-§3; the V271
// root: ER5 s07).
//
// Owner decision (a): every factor-set mutation requires a fresh proof —
// bearer identity alone never extends a factor set. The proof artifact is a
// single-use grant row in mfa_reauth_step_ups (V271 transport, V272 tuple)
// issued by one of the ISSUANCE endpoints:
//
//   - POST /auth/mfa/reauth                — password proof (C2/C3; C1 is
//     refused with a method-aware 403 naming the possession endpoints)
//   - POST /auth/mfa/possession/totp       — TOTP proof (C1, session scope)
//   - POST /auth/mfa/possession/webauthn/begin|finish — UV assertion proof
//     (C1, session or mfa_pending scope) — see mfa_possession.go
//
// Contract surface (all refusals are RFC 7807 problem+json via
// httputil.WriteProblem — never a silent failure):
//
//   - A gated arm reached without a valid grant answers 403 with
//     Type .../errors/reauth-required, Code "reauth_required", Remediation
//     "reauth". Consumption re-validates the FULL tuple (§1.1): live
//     session, token scope, JTI, family, operation, target, TTL, the
//     bound factor generation, and the proving factor's continued
//     liveness — any mismatch is a refusal and the dead grant is deleted.
//
// Gated arms (enforcement next to each arm):
//
//   - GET  /auth/totp/setup / POST /auth/totp/confirm   — totp.enroll /
//     totp.replace (peek + one-time target binding at setup; consume at
//     confirm, inside the promotion transaction)
//   - GET/POST /auth/webauthn/register/begin|finish     — webauthn.register
//   - DELETE /auth/webauthn/credential/{id}             — webauthn.revoke
//   - POST /auth/backup-codes/generate                  — recovery.regenerate
//   - POST /auth/device/register (native providers)     — device.register.native

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/token"
	shareddevice "setjoin.com/shared/device"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pwhash"
)

// MFAReauthChallengePath is the authenticated challenge endpoint a client
// must call to obtain a reauth_token. It is named in the 403
// reauth_required problem Detail so the contract is self-describing.
const MFAReauthChallengePath = "/auth/mfa/reauth"

// ReauthTokenHeader carries the reauth_token on the gated arms. The setup
// arm is a GET and fetch refuses a request body on GET, so the header is
// the transport every method can use; the POST arms also accept the JSON
// body member "reauth_token".
const ReauthTokenHeader = "X-MFA-Reauth"

// reauthRequiredProblemType / ReauthRequiredCode / reauthRemediation are the
// machine-readable members of the typed 403: RFC 7807 Type URI, the problem
// Code, and the Remediation action ("reauth" — the established stable
// remediation vocabulary alongside "terms" and "risk").
const (
	reauthRequiredProblemType = "https://setjoin.com/errors/reauth-required"
	ReauthRequiredCode        = "reauth_required"
	reauthRemediation         = "reauth"
)

// possessionRequiredProblemType / PossessionRequiredCode / the C1 refusal
// Remediation: the method-aware 403 a C1 (possession-capable) account
// receives when it presents a password proof — the refusal NAMES the
// possession endpoints (v7 §3 reauth row, addition ii).
const (
	possessionRequiredProblemType = "https://setjoin.com/errors/possession-proof-required"
	PossessionRequiredCode        = "possession_proof_required"
	possessionRemediation         = "possession"
	possessionEndpointsDetail     = "this account proves possession with a TOTP code at POST /auth/mfa/possession/totp or a user-verified passkey assertion via POST /auth/mfa/possession/webauthn/begin + finish"
)

// MFAReauthStepUpTTL bounds the single-use re-authentication token. It
// mirrors TOTPRemovalStepUpTTL: long enough for one settings round trip,
// short enough that an intercepted token expires before it is useful.
const MFAReauthStepUpTTL = 5 * time.Minute

// ErrMFAReauthRequired: the reauth_token is missing, malformed, expired,
// bound to a different session, already consumed (replay), or its tuple
// does not match this arm.
var ErrMFAReauthRequired = authn.ErrGrantRequired

// writeReauthRequired writes the typed, client-visible 403 contract. The
// challenge path travels in the human-readable Detail; machine clients
// branch on Code ("reauth_required") and the Remediation action.
func writeReauthRequired(w http.ResponseWriter, r *http.Request) {
	httputil.WriteProblem(w, r, &httputil.Problem{
		Type:        reauthRequiredProblemType,
		Title:       "Re-authentication required",
		Status:      http.StatusForbidden,
		Detail:      "prove possession at " + MFAReauthChallengePath + " (or the possession endpoints for C1 accounts) and retry with the issued reauth_token",
		Code:        ReauthRequiredCode,
		Remediation: reauthRemediation,
	})
}

// writePossessionRequired writes the C1 method-aware refusal naming the
// possession endpoints (v7 §3: "C1 accounts receive the method-aware 403
// refusal NAMING the possession endpoints").
func writePossessionRequired(w http.ResponseWriter, r *http.Request) {
	httputil.WriteProblem(w, r, &httputil.Problem{
		Type:        possessionRequiredProblemType,
		Title:       "Possession proof required",
		Status:      http.StatusForbidden,
		Detail:      possessionEndpointsDetail,
		Code:        PossessionRequiredCode,
		Remediation: possessionRemediation,
	})
}

// auditMFAReauthRefusal records a re-auth or gated-arm refusal (best-effort,
// the established admin_audit_log convention on non-transactional paths).
func (h *mfaHandler) auditMFAReauthRefusal(r *http.Request, userID int64, notes string) {
	h.pool.Exec(r.Context(),
		`INSERT INTO admin_audit_log (user_id, ip, action, target_type, target_id, notes)
		 VALUES ($1, $2::INET, 'mfa_reauth_refused', 'user', $1, $3)`,
		userID, httputil.ClientIP(r), notes)
}

// decodeReauthToken best-effort reads {"reauth_token":"..."} from a bounded
// body without writing any response. A missing or malformed body simply
// yields no token: the gate's answer is the same typed 403 reauth_required
// either way — the one honest, client-visible outcome — rather than a 400
// that hides the real requirement from a client that previously sent no
// body at all.
func decodeReauthToken(w http.ResponseWriter, r *http.Request) string {
	var req struct {
		ReauthToken string `json:"reauth_token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, authJSONBodyLimit)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return ""
	}
	*r = *shareddevice.WithServerBodyDigest(r, bodySHA256Hex(raw))
	if json.Unmarshal(raw, &req) != nil {
		return ""
	}
	return req.ReauthToken
}

// reauthTokenFromRequest resolves the presented reauth_token: the
// X-MFA-Reauth header first (the setup arm is a GET, and fetch refuses a
// request body on GET), then the JSON body member for the POST arms.
func reauthTokenFromRequest(w http.ResponseWriter, r *http.Request) string {
	if v := r.Header.Get(ReauthTokenHeader); v != "" {
		return v
	}
	return decodeReauthToken(w, r)
}

// reauthTokenFromBodyBytes resolves the presented reauth_token from an
// ALREADY-BUFFERED body (the header still takes precedence): arms that
// read the body bytes for their own decoder cannot re-read the stream, so
// the token member is decoded from the buffered bytes instead (r1 defect 1:
// the registration finish presented its token as a body member and a second
// body read returned nothing).
func reauthTokenFromBodyBytes(r *http.Request, body []byte) string {
	if v := r.Header.Get(ReauthTokenHeader); v != "" {
		return v
	}
	var req struct {
		ReauthToken string `json:"reauth_token"`
	}
	if json.Unmarshal(body, &req) != nil {
		return ""
	}
	return req.ReauthToken
}

// requirePossessionGrant is the ONE gated-arm gate: it validates (and, when
// consume is set, consumes) the presented grant against the full §1.1 tuple
// INSIDE the caller's transaction, which must already hold the §2.2 fences
// (person fence → users fence) — the caller completes the mutation, the
// generation bump and the success audit on the same transaction.
//
// Zero rows / dead grant / any tuple mismatch → the typed 403
// reauth_required problem plus the refusal audit; a PRESENT-but-mismatched
// grant is additionally deleted (§1.7: the mismatch refusal kills the row).
// A lookup failure answers 500 — fail closed, never a silent fallback into
// an ungated arm.
func (h *mfaHandler) requirePossessionGrant(
	w http.ResponseWriter, r *http.Request,
	tx pgx.Tx, claims *token.Claims,
	operation string, targetRef *string, consume bool,
	token string,
) (authn.Grant, bool) {
	if token == "" {
		// The header/body transport may not have been read yet on GET arms.
		token = reauthTokenFromRequest(w, r)
	}
	if token == "" {
		h.auditMFAReauthRefusal(r, claims.UserID, "factor mutation without a fresh possession proof")
		writeReauthRequired(w, r)
		return authn.Grant{}, false
	}
	family := claims.RefreshFamilyID()
	pred := authn.GrantPredicate{
		TokenHash:     authn.ReauthTokenHash(token),
		UserID:        claims.UserID,
		SessionJTI:    claims.JTI,
		Operation:     operation,
		TargetBound:   targetRef != nil,
		TokenScope:    authn.ProofScopeSession,
		FamilyBound:   true,
		RefreshFamily: &family,
	}
	if targetRef != nil {
		pred.TargetRef = targetRef
	}
	var (
		g   authn.Grant
		err error
	)
	if consume {
		g, err = authn.ConsumeGrant(r.Context(), tx, pred)
	} else {
		g, err = authn.PeekGrant(r.Context(), tx, pred)
	}
	if err != nil {
		var mismatch *authn.GrantMismatchError
		if errors.As(err, &mismatch) || errors.Is(err, authn.ErrGrantRequired) {
			// The §1.7 mismatch refusal DELETES the outstanding grant — that
			// deletion lives in this transaction, so COMMIT it (the tx holds
			// nothing else: the mutation never started).
			if commitErr := tx.Commit(r.Context()); commitErr != nil {
				h.logger.Error("possession refusal commit failed", "user_id", claims.UserID, "error", commitErr)
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
				return authn.Grant{}, false
			}
			reason := "possession proof missing"
			if errors.As(err, &mismatch) {
				reason = "possession proof refused: " + mismatch.Reason
			}
			h.auditMFAReauthRefusal(r, claims.UserID, reason)
			writeReauthRequired(w, r)
			return authn.Grant{}, false
		}
		h.logger.Error("possession grant gate failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return authn.Grant{}, false
	}
	// Proving factor still enabled/not-revoked (§1.1).
	live, err := authn.ProvingFactorStillEnabled(r.Context(), tx, g)
	if err != nil {
		h.logger.Error("proving factor check failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return authn.Grant{}, false
	}
	if !live {
		h.auditMFAReauthRefusal(r, claims.UserID, "possession proof refused: proving factor no longer live")
		writeReauthRequired(w, r)
		return authn.Grant{}, false
	}
	return g, true
}

// rejectImpersonated refuses ANY factor-management work for an impersonated
// bearer (claims.AdminActorID != nil) — unconditionally, at issuance AND
// every consumption, including the V250 removal flow (v7 §1.7 last row, r2
// disposition).
func rejectImpersonated(w http.ResponseWriter, r *http.Request, claims *token.Claims) bool {
	if claims != nil && claims.AdminActorID != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusForbidden,
			Detail: "impersonated sessions may not manage authentication factors",
			Code:   "impersonation_forbidden",
		})
		return true
	}
	return false
}

// MFAReauthBegin is the fresh re-authentication challenge for C2/C3
// accounts: it verifies the session holder's CURRENT password and issues a
// single-use, session-bound reauth_token carrying the DECLARED operation
// (and, for webauthn.revoke, the ownership-validated target_ref) — §3.2 T3.1.
//
// The whole issuance lives in ONE §2.2-fenced transaction: person fence →
// users fence → durable revocation recheck → cohort classification (C1 →
// the method-aware 403 naming the possession endpoints) → password budget
// (§2.3: locked → 429 without increment; evaluated failures increment and
// COMMIT; any bookkeeping failure → 500, nothing partial) → password verify
// → grant insert. Every refusal is audited.
//
// POST /auth/mfa/reauth — requires access token; CSRF + strict JSON media
// type checked at the mux; the threat interceptor's per-IP admission bounds
// apply (factor-management mount precedent).
func (h *mfaHandler) MFAReauthBegin(w http.ResponseWriter, r *http.Request) {
	claims := h.mustUser(w, r)
	if claims == nil {
		return
	}
	if rejectImpersonated(w, r, claims) {
		h.auditMFAReauthRefusal(r, claims.UserID, "impersonated bearer refused at re-auth issuance")
		return
	}
	var req struct {
		Operation string `json:"operation"`
		Password  string `json:"password"`
		TargetRef string `json:"target_ref,omitempty"`
	}
	if !decodeBoundedAuthJSON(w, r, &req) {
		// Every-attempt contract: an authenticated malformed body is still a
		// re-auth attempt. The decoder already wrote the 400; audit before
		// returning so the attempt never bypasses the trail.
		h.auditMFAReauthRefusal(r, claims.UserID, "malformed body")
		return
	}
	if req.Password == "" {
		h.auditMFAReauthRefusal(r, claims.UserID, "missing password")
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "password is required"})
		return
	}
	targetRef, ok := validateIssuanceOperation(w, r, req.Operation, req.TargetRef)
	if !ok {
		h.auditMFAReauthRefusal(r, claims.UserID, "invalid operation/target at re-auth issuance")
		return
	}

	ctx := r.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		h.logger.Error("mfa re-auth tx begin failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "re-authentication failed"})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// §2.2 canonical fences: person fence, then the users row.
	if err := authn.PersonFence(ctx, tx, claims.UserID); err != nil {
		h.logger.Error("mfa re-auth person fence failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "re-authentication failed"})
		return
	}
	if _, err := authn.UsersFence(ctx, tx, claims.UserID); err != nil {
		h.logger.Error("mfa re-auth users fence failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "re-authentication failed"})
		return
	}
	// Durable revocation recheck (§2.2) — the request-time denylist check is
	// an earlier in-memory check, not a durable one inside the tx.
	revoked, err := durableRecheckForClaims(ctx, tx, claims)
	if err != nil {
		h.logger.Error("mfa re-auth revocation recheck failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "re-authentication failed"})
		return
	}
	if revoked {
		h.auditMFAReauthRefusal(r, claims.UserID, "session revoked")
		writeReauthRequired(w, r)
		return
	}

	// Cohort: C1 accounts must prove possession, not knowledge.
	cohort, err := authn.ClassifyCohort(ctx, tx, claims.UserID)
	if err != nil {
		h.logger.Error("cohort classification failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "re-authentication failed"})
		return
	}
	if cohort == authn.CohortC1 {
		h.auditMFAReauthRefusal(r, claims.UserID, "possession-capable account presented a password proof")
		writePossessionRequired(w, r)
		return
	}

	// §2.3 password budget — inside the issuance transaction.
	budget, err := authn.LoadPossessionBudget(ctx, tx, authn.ProofMethodPassword, claims.UserID)
	if err != nil {
		h.logger.Error("possession budget read failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "re-authentication failed"})
		return
	}
	if budget.Locked(time.Now()) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusTooManyRequests, Detail: "account locked due to too many failed proof attempts"})
		return
	}

	// Password verification rides the SAME transaction (the fence is already
	// held; the hash read is fence-protected). The sentinel means "wrong
	// password"; anything else fails closed with a 500 — a DB outage must
	// never read as "invalid password".
	var hash string
	if err := tx.QueryRow(ctx,
		`SELECT password_hash FROM users WHERE id = $1`, claims.UserID,
	).Scan(&hash); err != nil {
		h.logger.Error("mfa re-auth password lookup failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "re-authentication failed"})
		return
	}
	if hash == "" || pwhash.VerifyPasswordHash(hash, req.Password) != nil {
		// Evaluated failure: increment the budget and COMMIT the refusal
		// bookkeeping (§2.3 — never an uncommitted increment).
		if _, recErr := authn.RecordPossessionFailure(ctx, tx, authn.ProofMethodPassword, claims.UserID); recErr != nil {
			h.logger.Error("possession budget increment failed", "user_id", claims.UserID, "error", recErr)
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "re-authentication failed"})
			return
		}
		if err := tx.Commit(ctx); err != nil {
			h.logger.Error("mfa re-auth refusal commit failed", "user_id", claims.UserID, "error", err)
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "re-authentication failed"})
			return
		}
		h.auditMFAReauthRefusal(r, claims.UserID, "invalid password")
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "invalid password"})
		return
	}

	// Success: reset the budget and issue the grant IN THIS TRANSACTION —
	// a reset failure rolls the whole issuance back (§2.3).
	if err := authn.ResetPossessionBudget(ctx, tx, authn.ProofMethodPassword, claims.UserID); err != nil {
		h.logger.Error("possession budget reset failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "re-authentication failed"})
		return
	}
	// §3.2 T4: the revoke target's {exists, owned, live} ownership check runs
	// INSIDE the issuance transaction (user-scoped SELECT — R1).
	if targetRef != nil {
		raw, decErr := base64.RawURLEncoding.DecodeString(*targetRef)
		if decErr != nil || authn.ValidateCredentialOwnership(ctx, tx, claims.UserID, raw) != nil {
			h.auditMFAReauthRefusal(r, claims.UserID, "invalid revoke target at re-auth issuance")
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid target_ref", Code: "invalid_target"})
			return
		}
	}

	family := claims.RefreshFamilyID()
	granted, err := authn.IssueSessionGrant(ctx, tx, claims.UserID, claims.JTI, family,
		req.Operation, targetRef, authn.ProofMethodPassword, nil, MFAReauthStepUpTTL)
	if err != nil {
		h.logger.Error("mfa re-auth token issuance failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "re-authentication failed"})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("mfa re-auth commit failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "re-authentication failed"})
		return
	}

	h.pool.Exec(r.Context(),
		`INSERT INTO admin_audit_log (user_id, ip, action, target_type, target_id)
		 VALUES ($1, $2::INET, 'mfa_reauth_authorized', 'user', $1)`,
		claims.UserID, httputil.ClientIP(r))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"reauth_token": granted,
		"expires_in":   int(MFAReauthStepUpTTL.Seconds()),
	})
}

// durableRecheckForClaims runs the §2.2 durable revocation recheck with the
// presented token's own identity: family (NULL-safe), JTI, and the
// issuance-time watermark input (claims.IssuedAt; a missing claim is bound
// as NULL — the fail-closed mirror of the denylist's zero-time handling).
func durableRecheckForClaims(ctx context.Context, q authn.GrantStore, claims *token.Claims) (bool, error) {
	var iat *time.Time
	if claims.IssuedAt != nil {
		t := claims.IssuedAt.Time
		iat = &t
	}
	return authn.DurableRevocationRecheck(ctx, q, claims.UserID, claims.RefreshFamilyID(), claims.JTI, iat)
}

// validateIssuanceOperation validates the declared operation + target_ref
// pair at the issuance surfaces (v7 §3.2 T4): operation must be one of the
// session-scope kinds (bootstrap.totp.enroll is mfa_pending-only);
// target_ref is REQUIRED iff the operation is webauthn.revoke and FORBIDDEN
// on every other operation — one proof authorizes exactly one target. The
// revoke target's base64url encoding is decoded here; {exists, owned,
// live} ownership validation belongs INSIDE the issuance/begin transaction.
// Writes the 400 problem and returns ok=false on any violation.
func validateIssuanceOperation(w http.ResponseWriter, r *http.Request, operation, targetRef string) (*string, bool) {
	if !authn.ValidSessionScopeOperation(operation) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "unknown operation", Code: "invalid_operation"})
		return nil, false
	}
	if operation == authn.OperationWebAuthnRevoke {
		if targetRef == "" {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "target_ref is required for webauthn.revoke", Code: "invalid_target"})
			return nil, false
		}
		raw, err := base64.RawURLEncoding.DecodeString(targetRef)
		if err != nil || len(raw) == 0 {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid target_ref", Code: "invalid_target"})
			return nil, false
		}
		// Store the CANONICAL re-encoding, never the presented text.
		canonical := base64.RawURLEncoding.EncodeToString(raw)
		return &canonical, true
	}
	if targetRef != "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "target_ref is only valid for webauthn.revoke", Code: "invalid_target"})
		return nil, false
	}
	return nil, true
}
