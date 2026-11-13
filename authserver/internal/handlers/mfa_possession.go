package handlers

// mfa_possession.go — the C1 possession-proof issuance family (scheme v7
// §1.4, §3, §3.2): the three NEW endpoints
//
//   - POST /auth/mfa/possession/totp            — TOTP proof → session grant
//   - POST /auth/mfa/possession/webauthn/begin  — UV assertion ceremony create
//   - POST /auth/mfa/possession/webauthn/finish — UV ceremony finish → grant
//
// Wire rules (§3.2):
//
//   - T1 dual token admission with deterministic precedence: (1) an
//     Authorization header that validates as an ACCESS token → session
//     scope (any mfa_token member ignored); (2) else the access_token
//     cookie that validates → session scope; (3) else a presented
//     mfa_token member validating as TypeMFAPending → mfa_pending scope;
//     (4) else 401. A FAILED earlier mode falls through (a stale browser
//     cookie must not break bootstrap); no hybrid admission — the
//     ceremony/grant scope is fixed by the token that actually validated.
//   - T1 scope/operation parity: mfa_pending scope accepts ONLY
//     bootstrap.totp.enroll; bootstrap.totp.enroll is issuable ONLY under
//     mfa_pending scope.
//   - T2 strict media type: these endpoints REQUIRE Content-Type:
//     application/json (parameters accepted); anything else → 415
//     unsupported_media_type at the mount, BEFORE the decoder.
//   - Check order at begin: media type (415) → body decode (400) →
//     admission (401) → operation/target validation (400) →
//     cohort/impersonation/budget guards → ceremony create. At finish (v7
//     corrected order): 415 → 400 decode → 401 → 403 reauth_required for
//     an unknown/expired/consumed ceremony → 400 operation/target equality
//     → 403 impersonation → THEN the ONE §2.2 transaction: fences →
//     durable revocation recheck → budget check (429; ceremony NOT
//     consumed) → assertion verification (403 on failure, counter recorded
//     in the same transaction) → record/reset → consume ceremony row +
//     issue grant, committed atomically.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/token"
	shareddevice "setjoin.com/shared/device"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/threat"
)

// unsupportedMediaTypeProblemType is the 415 slug (§3.2 T2).
const unsupportedMediaTypeProblemType = "https://setjoin.com/errors/unsupported-media-type"

// ceremonyKindRegistration / ceremonyKindManagementAssertion are the
// webauthn_ceremonies.kind values (§1.4).
const (
	ceremonyKindRegistration        = "registration"
	ceremonyKindManagementAssertion = "management_assertion"
)

// RequireJSONContentType enforces the §3.2 T2 strict media-type policy for
// the four ISSUANCE endpoints: the shared auth decoder's non-JSON tolerance
// is deliberately NOT extended to the mint surfaces. The check runs at the
// mount BEFORE the decoder; parameters (charset) are accepted.
func RequireJSONContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		mediaType := strings.TrimSpace(strings.SplitN(ct, ";", 2)[0])
		if !strings.EqualFold(mediaType, "application/json") {
			httputil.WriteProblem(w, r, &httputil.Problem{
				Type:   unsupportedMediaTypeProblemType,
				Title:  "Unsupported media type",
				Status: http.StatusUnsupportedMediaType,
				Detail: "this endpoint requires Content-Type: application/json",
				Code:   "unsupported_media_type",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// possessionCeremonyProvider is the ceremony-capable WebAuthn seam the
// possession endpoints need (satisfied by *authn.PasskeyProvider in
// production). Kept separate from passkeyProvider so the existing login /
// registration mocks stay untouched.
type possessionCeremonyProvider interface {
	// The tx parameter is the caller's FENCED transaction: the user load and
	// assertion verification inside these ceremonies ride it (r2 defect 2),
	// so a begin/finish never needs a second pooled connection while holding
	// its own — the old pool-issued reads self-deadlocked at pool saturation.
	BeginManagementAssertion(ctx context.Context, tx pgx.Tx, userID int64) (optionsJSON []byte, challengeHash string, err error)
	ValidateManagementAssertion(ctx context.Context, tx pgx.Tx, userID int64, challengeHash string, body []byte) (credentialID []byte, err error)
	BeginRegistrationCeremony(ctx context.Context, tx pgx.Tx, userID int64) (optionsJSON, sessionJSON []byte, challengeHash string, err error)
	// The finish arm's two-phase §2.2 ordering (r1 defect 1): authorization
	// (ceremony + grant consumption) completes BEFORE the verified credential
	// is persisted, so a refused finish never commits the passkey.
	VerifyRegistrationCredential(ctx context.Context, tx pgx.Tx, userID int64, sessionJSON, body []byte) (*webauthn.Credential, error)
	PersistRegistrationCredentialTx(ctx context.Context, tx pgx.Tx, userID int64, cred *webauthn.Credential) error
	RevokeCredentialTx(ctx context.Context, tx pgx.Tx, credentialID []byte, userID int64) (bool, error)
	ValidateCredentialOwnership(ctx context.Context, q authn.GrantStore, userID int64, credentialID []byte) error
}

// txBeginner is the transaction-open seam the possession gate's handler
// arms need (satisfied by *pgxpool.Pool in production). The concrete pool
// stays on deps for every non-possession path; this narrow interface exists
// so failure-injection tests can substitute a scripted pgx.Tx at the seam
// (TODOS: possession surface coverage seams) without widening the deps
// pool's type beyond the possession surface.
type txBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// beginGateTx opens a possession arm's §2.2 transaction: through the
// injection seam when one is installed, else the concrete pool. The two are
// call-for-call identical (production never sets the seam).
func (h *mfaHandler) beginGateTx(ctx context.Context) (pgx.Tx, error) {
	if b := h.possessionTxBeginner; b != nil {
		return b.Begin(ctx)
	}
	return h.pool.Begin(ctx)
}

// ceremonyProvider type-asserts h.passkey to the ceremony seam. A nil
// result means WebAuthn is unconfigured — the endpoints answer 404, the
// same posture as the existing webauthn handlers.
func (h *mfaHandler) ceremonyProvider() possessionCeremonyProvider {
	if h.passkey == nil {
		return nil
	}
	p, ok := h.passkey.(possessionCeremonyProvider)
	if !ok {
		return nil
	}
	return p
}

// admissionScope names which token admitted a possession request.
type admissionScope string

const (
	// admissionSession: a valid ACCESS bearer (header or ambient cookie).
	admissionSession admissionScope = "session"
	// admissionMFAPending: a presented mfa_token validating as TypeMFAPending.
	admissionMFAPending admissionScope = "mfa_pending"
)

// decodePossessionBody reads the request body ONCE and returns both the
// decoded possession body and the raw bytes (the assertion fields ride
// through for finish — the verification re-reads the same bytes). A plain
// json.Decoder would over-read the restored stream and leave nothing for the
// second read, so the raw bytes are captured here up front (r1 defect 5:
// real ceremonies failed before authentication — the verification parse saw
// an empty body).
func decodePossessionBody(w http.ResponseWriter, r *http.Request) (possessionBody, []byte, bool) {
	var req possessionBody
	r.Body = http.MaxBytesReader(w, r.Body, authJSONBodyLimit)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return req, nil, false
	}
	*r = *shareddevice.WithServerBodyDigest(r, bodySHA256Hex(raw))
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if err := json.Unmarshal(raw, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return req, nil, false
	}
	return req, raw, true
}

// admitPossessionToken resolves the §3.2 T1 admission with deterministic
// bearer-first precedence. Writes the 401 problem and returns ok=false when
// NOTHING valid was presented.
//
// The two ACCESS-token modes run through the configured bearer
// authenticator's FULL session-acceptance funnel (AuthenticatePresented):
// signature, access-type parity, CA-3a revocation, and DPoP
// proof-of-possession for cnf-bound tokens (r1 defect 4: bare jwt.Validate
// let a stolen bound token replace ceremonies and submit proofs without its
// binding key on exactly these requireAuth-less routes). The mfa_pending
// member keeps plain validation — the specified pending-token fallback;
// pending tokens carry no cnf.
func (h *mfaHandler) admitPossessionToken(w http.ResponseWriter, r *http.Request, mfaTokenMember string) (*token.Claims, admissionScope, bool) {
	// The uniform 401 answer is ADMISSION-typed (threat.DPoPAdmissionCode):
	// a live shared session presenting an inadmissible per-tab proof must be
	// distinguishable, through the problem body alone, from an
	// application-level refusal — the webmail client replays ONLY this shape
	// after its /auth/session/token recovery. Application 401s further down
	// the arms (an evaluated invalid TOTP-removal code, for one) never carry
	// the marker and therefore execute exactly once.
	unauthorized := func() (*token.Claims, admissionScope, bool) {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusUnauthorized,
			Detail: "invalid MFA token",
			Code:   threat.DPoPAdmissionCode,
		})
		return nil, "", false
	}
	authenticator := h.sessionAuthenticator()
	// (1) Authorization header validating as an ACCESS token — any mfa_token
	// member is ignored (no hybrid admission).
	if hdr := r.Header.Get("Authorization"); strings.HasPrefix(hdr, "Bearer ") {
		if claims, err := authenticator.AuthenticatePresented(r, strings.TrimPrefix(hdr, "Bearer ")); err == nil {
			return claims, admissionSession, true
		}
	}
	// (2) The ambient access_token cookie validating as an ACCESS token.
	if c, err := r.Cookie("access_token"); err == nil && c.Value != "" {
		if claims, err := authenticator.AuthenticatePresented(r, c.Value); err == nil {
			return claims, admissionSession, true
		}
	}
	// (3) The mfa_token member validating as TypeMFAPending.
	if mfaTokenMember != "" {
		if claims, err := h.jwt.Validate(mfaTokenMember); err == nil && claims.Type == token.TypeMFAPending {
			return claims, admissionMFAPending, true
		}
	}
	// (4) Nothing valid presented — the uniform 401 answer.
	return unauthorized()
}

// possessionClaimsForScope projects the admission claims into the
// grant/ceremony identity: session scope carries {access JTI, family};
// mfa_pending scope carries {pending JTI, no family}.
type possessionIdentity struct {
	UserID   int64
	JTI      string
	Family   string // "" for mfa_pending scope
	Scope    string // authn.ProofScopeSession | authn.ProofScopeMFAPending
	IsMFAPnd bool
}

func possessionIdentityFor(claims *token.Claims, scope admissionScope) possessionIdentity {
	id := possessionIdentity{UserID: claims.UserID, JTI: claims.JTI}
	if scope == admissionMFAPending {
		id.Scope = authn.ProofScopeMFAPending
		id.IsMFAPnd = true
		return id
	}
	id.Family = claims.RefreshFamilyID()
	id.Scope = authn.ProofScopeSession
	return id
}

// possessionBody is the common decode target for the possession endpoints
// (the assertion fields ride through for finish — the raw body is re-read).
type possessionBody struct {
	Operation string `json:"operation"`
	MFAToken  string `json:"mfa_token,omitempty"`
	TargetRef string `json:"target_ref,omitempty"`
	Code      string `json:"code,omitempty"`
}

// validatePossessionOperation enforces the T1 parity + T4 target rules on
// the possession endpoints: mfa_pending scope accepts ONLY
// bootstrap.totp.enroll; session scope never accepts it; target_ref is
// required iff webauthn.revoke (canonicalized) and forbidden otherwise.
func validatePossessionOperation(w http.ResponseWriter, r *http.Request, operation, targetRef string, id possessionIdentity) (*string, bool) {
	if id.IsMFAPnd {
		if operation != authn.OperationBootstrapTOTPEnroll {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "this admission authorizes only bootstrap.totp.enroll", Code: "invalid_operation"})
			return nil, false
		}
	} else {
		if operation == authn.OperationBootstrapTOTPEnroll {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "bootstrap.totp.enroll requires an mfa_pending admission", Code: "invalid_operation"})
			return nil, false
		}
		if !authn.ValidSessionScopeOperation(operation) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "unknown operation", Code: "invalid_operation"})
			return nil, false
		}
	}
	// Target rules mirror the issuance contract (T4).
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

// ---- POST /auth/mfa/possession/totp ----

// MFAPossessionTOTP issues a session-scope totp-proof grant for a C1
// account (§3 row 2): the enabled secret is verified through the §2.3 ONE
// cycle INSIDE the §2.2 issuance transaction (person fence → users fence →
// durable revocation recheck → budget → verify → grant). C2/C3 → 403
// naming the password path. Session scope ONLY: an mfa_pending holder never
// has TOTP enabled, so no bootstrap TOTP surface exists here.
func (h *mfaHandler) MFAPossessionTOTP(w http.ResponseWriter, r *http.Request) {
	claims := h.mustUser(w, r)
	if claims == nil {
		return
	}
	if rejectImpersonated(w, r, claims) {
		return
	}
	var req possessionBody
	if !decodeBoundedAuthJSON(w, r, &req) {
		return
	}
	targetRef, ok := validatePossessionOperation(w, r, req.Operation, req.TargetRef, possessionIdentityFor(claims, admissionSession))
	if !ok {
		return
	}
	if req.Code == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "code is required"})
		return
	}

	ctx := r.Context()
	tx, err := h.beginGateTx(ctx)
	if err != nil {
		h.logger.Error("possession totp tx begin failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// §2.2 canonical fences + durable revocation recheck.
	if err := authn.PersonFence(ctx, tx, claims.UserID); err != nil {
		h.possessionTxError(w, r, claims.UserID, "person fence", err)
		return
	}
	if _, err := authn.UsersFence(ctx, tx, claims.UserID); err != nil {
		h.possessionTxError(w, r, claims.UserID, "users fence", err)
		return
	}
	revoked, err := durableRecheckForClaims(ctx, tx, claims)
	if err != nil {
		h.possessionTxError(w, r, claims.UserID, "revocation recheck", err)
		return
	}
	if revoked {
		writeReauthRequired(w, r)
		return
	}

	// C1 only (§3): a C2/C3 account proves with its password at
	// /auth/mfa/reauth — the refusal NAMES the password path.
	cohort, err := authn.ClassifyCohort(ctx, tx, claims.UserID)
	if err != nil {
		h.possessionTxError(w, r, claims.UserID, "cohort classification", err)
		return
	}
	if cohort != authn.CohortC1 {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusForbidden,
			Detail: "this account proves with its account password at " + MFAReauthChallengePath,
			Code:   "password_proof_required",
		})
		return
	}

	// The §2.3 ONE cycle, INSIDE this transaction (its first statement takes
	// the users row fence this transaction already holds). TOTPLocked → 429;
	// TOTPBookkeepingError → 500 with NO grant (fail-closed).
	outcome, cycleErr := authn.VerifyTOTPWithLockoutTx(ctx, tx, claims.UserID, req.Code)
	switch outcome {
	case authn.TOTPLocked:
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusTooManyRequests, Detail: "account locked due to too many TOTP failures"})
		return
	case authn.TOTPBookkeepingError:
		h.logger.Error("possession totp bookkeeping failed", "user_id", claims.UserID, "error", cycleErr)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	case authn.TOTPInvalid:
		// Evaluated failure: the increment is real bookkeeping — COMMIT it
		// before answering 403 (r1 defect 2: the deferred rollback was
		// erasing the failure, so guesses against an unlocked account never
		// accumulated toward the five-attempt lock). Bookkeeping errors keep
		// the rollback: counters stay exactly as before the attempt.
		if err := tx.Commit(ctx); err != nil {
			h.possessionTxError(w, r, claims.UserID, "failure bookkeeping commit", err)
			return
		}
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "invalid TOTP code"})
		return
	}

	// §3.2 T4: the revoke target's ownership check inside the issuance tx.
	if targetRef != nil {
		raw, decErr := base64.RawURLEncoding.DecodeString(*targetRef)
		if decErr != nil || authn.ValidateCredentialOwnership(ctx, tx, claims.UserID, raw) != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid target_ref", Code: "invalid_target"})
			return
		}
	}

	// Grant issuance inside the same transaction: token_hash =
	// SHA-256(minted reauth_token), bound {JTI, family, operation, target,
	// generation}.
	family := claims.RefreshFamilyID()
	granted, err := authn.IssueSessionGrant(ctx, tx, claims.UserID, claims.JTI, family,
		req.Operation, targetRef, authn.ProofMethodTOTP, nil, MFAReauthStepUpTTL)
	if err != nil {
		h.possessionTxError(w, r, claims.UserID, "grant issuance", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.possessionTxError(w, r, claims.UserID, "commit", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"reauth_token": granted,
		"expires_in":   int(MFAReauthStepUpTTL.Seconds()),
	})
}

func (h *mfaHandler) possessionTxError(w http.ResponseWriter, r *http.Request, userID int64, what string, err error) {
	h.logger.Error("possession endpoint failure", "user_id", userID, "stage", what, "error", err)
	httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
}

// ---- POST /auth/mfa/possession/webauthn/begin ----

// MFAPossessionWebAuthnBegin creates the management-assertion ceremony
// (§1.4, §3 row 3): an AUTHENTICATION ceremony issued WITHOUT any grant —
// guarded by {token admitted, cohort C1, webauthn_uv budget not locked, not
// impersonated}. It declares the operation (and, for webauthn.revoke, the
// ownership-validated target_ref) on the ceremony row, deletes the user's
// prior management_assertion rows, and returns assertion options with
// userVerification:'required' forced server-side. NO ceremony cookie — the
// server-side row is the authority.
func (h *mfaHandler) MFAPossessionWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	cp := h.ceremonyProvider()
	if cp == nil {
		http.NotFound(w, r)
		return
	}
	var req possessionBody
	if !decodeBoundedAuthJSON(w, r, &req) {
		return
	}
	// T1 admission (after decode, per the T2 check order).
	claims, scope, ok := h.admitPossessionToken(w, r, req.MFAToken)
	if !ok {
		return
	}
	id := possessionIdentityFor(claims, scope)
	if rejectImpersonated(w, r, claims) {
		return
	}
	targetRef, ok := validatePossessionOperation(w, r, req.Operation, req.TargetRef, id)
	if !ok {
		return
	}

	ctx := r.Context()
	tx, err := h.beginGateTx(ctx)
	if err != nil {
		h.possessionTxError(w, r, claims.UserID, "begin tx", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := authn.PersonFence(ctx, tx, claims.UserID); err != nil {
		h.possessionTxError(w, r, claims.UserID, "person fence", err)
		return
	}
	if _, err := authn.UsersFence(ctx, tx, claims.UserID); err != nil {
		h.possessionTxError(w, r, claims.UserID, "users fence", err)
		return
	}
	revoked, err := durableRecheckForClaims(ctx, tx, claims)
	if err != nil {
		h.possessionTxError(w, r, claims.UserID, "revocation recheck", err)
		return
	}
	if revoked {
		writeReauthRequired(w, r)
		return
	}

	// Cohort C1 required (§1.4): the ceremony is a possession proof.
	cohort, err := authn.ClassifyCohort(ctx, tx, claims.UserID)
	if err != nil {
		h.possessionTxError(w, r, claims.UserID, "cohort classification", err)
		return
	}
	if cohort != authn.CohortC1 {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status:      http.StatusForbidden,
			Type:        possessionRequiredProblemType,
			Title:       "Possession proof required",
			Detail:      "no user-verified passkey is enrolled on this account",
			Code:        PossessionRequiredCode,
			Remediation: possessionRemediation,
		})
		return
	}

	// webauthn_uv budget not locked (§1.7 begin guard).
	budget, err := authn.LoadPossessionBudget(ctx, tx, authn.ProofMethodWebAuthn, claims.UserID)
	if err != nil {
		h.possessionTxError(w, r, claims.UserID, "budget read", err)
		return
	}
	if budget.Locked(time.Now()) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusTooManyRequests, Detail: "account locked due to too many failed proof attempts"})
		return
	}

	// webauthn.revoke: ownership validated INSIDE the begin transaction
	// (§3.2 T3.3 — user-scoped SELECT, one refusal shape).
	if targetRef != nil {
		raw, decErr := base64.RawURLEncoding.DecodeString(*targetRef)
		if decErr != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid target_ref", Code: "invalid_target"})
			return
		}
		if err := cp.ValidateCredentialOwnership(ctx, tx, claims.UserID, raw); err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid target_ref", Code: "invalid_target"})
			return
		}
	}

	// Mint the assertion options (UV required server-side) and store the
	// ceremony row in the SAME transaction. The user load rides tx (r2
	// defect 2) — no second pooled connection while the fence is held.
	optionsJSON, challengeHash, err := cp.BeginManagementAssertion(ctx, tx, claims.UserID)
	if err != nil {
		h.possessionTxError(w, r, claims.UserID, "assertion begin", err)
		return
	}
	if err := authn.CreateCeremony(ctx, tx, authn.Ceremony{
		ChallengeHash:   challengeHash,
		UserID:          claims.UserID,
		Kind:            ceremonyKindManagementAssertion,
		Operation:       req.Operation,
		TargetRef:       targetRef,
		SessionJTI:      id.JTI,
		TokenScope:      id.Scope,
		RefreshFamilyID: familyOrNil(id.Family),
	}); err != nil {
		h.possessionTxError(w, r, claims.UserID, "ceremony create", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.possessionTxError(w, r, claims.UserID, "commit", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(optionsJSON)
}

// ---- POST /auth/mfa/possession/webauthn/finish ----

// MFAPossessionWebAuthnFinish consumes the management-assertion ceremony and
// issues the grant in ONE transaction (§3 row 4, v7 corrected check order):
// fences → durable revocation recheck → budget check (429; the ceremony row
// is NOT consumed — the guard fails, state stays CEREMONY_LIVE) → assertion
// verification (UV required; 403 on failure with the webauthn_uv counter
// recorded in the same transaction) → record/reset → consume ceremony row +
// issue grant. Session scope returns {"reauth_token","expires_in"};
// mfa_pending scope returns {"granted":true} with the grant hash bound to
// SHA-256(presented mfa_token) (§1.5.1 step 5).
func (h *mfaHandler) MFAPossessionWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	cp := h.ceremonyProvider()
	if cp == nil {
		http.NotFound(w, r)
		return
	}
	// Read the body once: the decode target and the raw assertion bytes come
	// from the SAME read (the verification below re-verifies these bytes).
	req, assertionBody, ok := decodePossessionBody(w, r)
	if !ok {
		return
	}

	// T1 admission.
	claims, scope, ok := h.admitPossessionToken(w, r, req.MFAToken)
	if !ok {
		return
	}
	id := possessionIdentityFor(claims, scope)

	// 403 reauth_required for a ceremony unknown/expired/already-consumed —
	// the established remediation vocabulary with ceremony-specific Detail.
	ceremony, err := authn.PeekCeremony(r.Context(), h.pool, claims.UserID,
		ceremonyKindManagementAssertion, id.Scope, id.JTI)
	if err != nil {
		if errors.Is(err, authn.ErrGrantRequired) {
			httputil.WriteProblem(w, r, &httputil.Problem{
				Type:        reauthRequiredProblemType,
				Title:       "Re-authentication required",
				Status:      http.StatusForbidden,
				Detail:      "no live management-assertion ceremony for this session — begin one at POST /auth/mfa/possession/webauthn/begin",
				Code:        ReauthRequiredCode,
				Remediation: reauthRemediation,
			})
			return
		}
		h.possessionTxError(w, r, claims.UserID, "ceremony lookup", err)
		return
	}

	// v6/r5: the presented operation MUST equal the ceremony's; the revoke
	// target MUST equal the ceremony's bound target.
	if req.Operation == "" || req.Operation != ceremony.Operation {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "operation does not match the ceremony", Code: "operation_mismatch"})
		return
	}
	if ceremony.TargetRef != nil {
		if req.TargetRef == "" || *ceremony.TargetRef != req.TargetRef {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "target_ref does not match the ceremony", Code: "target_mismatch"})
			return
		}
	} else if req.TargetRef != "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "target_ref does not match the ceremony", Code: "target_mismatch"})
		return
	}

	if rejectImpersonated(w, r, claims) {
		return
	}

	ctx := r.Context()
	tx, err := h.beginGateTx(ctx)
	if err != nil {
		h.possessionTxError(w, r, claims.UserID, "finish tx", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// §2.2 fences + durable revocation recheck.
	if err := authn.PersonFence(ctx, tx, claims.UserID); err != nil {
		h.possessionTxError(w, r, claims.UserID, "person fence", err)
		return
	}
	if _, err := authn.UsersFence(ctx, tx, claims.UserID); err != nil {
		h.possessionTxError(w, r, claims.UserID, "users fence", err)
		return
	}
	revoked, err := durableRecheckForClaims(ctx, tx, claims)
	if err != nil {
		h.possessionTxError(w, r, claims.UserID, "revocation recheck", err)
		return
	}
	if revoked {
		writeReauthRequired(w, r)
		return
	}

	// Budget check INSIDE the fenced transaction (v7 §3.2 T3.4): a locked
	// finish refuses 429 for VALID and INVALID assertions alike, and the
	// ceremony row is NOT consumed.
	budget, err := authn.LoadPossessionBudget(ctx, tx, authn.ProofMethodWebAuthn, claims.UserID)
	if err != nil {
		h.possessionTxError(w, r, claims.UserID, "budget read", err)
		return
	}
	if budget.Locked(time.Now()) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusTooManyRequests, Detail: "account locked due to too many failed proof attempts"})
		return
	}

	// §3.2 T3.4/T4 (opus r1 finding 2): for a ceremony bound to a
	// webauthn.revoke target, the finish transaction RE-VALIDATES
	// ownership+live under the §2.2 fence — a credential revoked between
	// begin and finish refuses here (400 invalid_target, the single T4
	// refusal shape; the assertion is never evaluated, so the webauthn_uv
	// counter does not move, and the ceremony row is not consumed).
	if ceremony.TargetRef != nil {
		raw, decErr := base64.RawURLEncoding.DecodeString(*ceremony.TargetRef)
		if decErr != nil || cp.ValidateCredentialOwnership(ctx, tx, claims.UserID, raw) != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid target_ref", Code: "invalid_target"})
			return
		}
	}

	// Assertion verification: UV required, origin/RP per the existing config,
	// challenge proven against the ceremony hash.
	credentialID, verifyErr := cp.ValidateManagementAssertion(ctx, tx, claims.UserID, ceremony.ChallengeHash, assertionBody)
	if verifyErr != nil {
		// Machinery-vs-observation split (opus r1 finding 4): a body that
		// never PARSED is a malformed request — 400, the proof was never
		// evaluated, so the webauthn_uv counter does not move and the
		// ceremony is not consumed (tx rolls back). Parsed-but-wrong proofs
		// are evaluated failures and count below.
		if errors.Is(verifyErr, authn.ErrManagementAssertionMalformed) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "malformed assertion body", Code: "invalid_request"})
			return
		}
		// Evaluated failure: record the webauthn_uv counter in the SAME
		// transaction and commit the refusal bookkeeping.
		if _, recErr := authn.RecordPossessionFailure(ctx, tx, authn.ProofMethodWebAuthn, claims.UserID); recErr != nil {
			h.possessionTxError(w, r, claims.UserID, "budget increment", recErr)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			h.possessionTxError(w, r, claims.UserID, "refusal commit", err)
			return
		}
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "assertion verification failed"})
		return
	}

	// Record/reset: success resets the budget in the same transaction.
	if err := authn.ResetPossessionBudget(ctx, tx, authn.ProofMethodWebAuthn, claims.UserID); err != nil {
		h.possessionTxError(w, r, claims.UserID, "budget reset", err)
		return
	}

	// Consume the ceremony row (single-use) + issue the grant, atomically.
	if _, err := authn.ConsumeCeremony(ctx, tx, claims.UserID,
		ceremonyKindManagementAssertion, id.Scope, id.JTI, ceremony.ChallengeHash); err != nil {
		if errors.Is(err, authn.ErrGrantRequired) {
			writeReauthRequired(w, r)
			return
		}
		h.possessionTxError(w, r, claims.UserID, "ceremony consume", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if id.IsMFAPnd {
		// §1.5.1 step 5: grant hash = SHA-256(presented mfa_token) — the same
		// bytes the login returned and the client keeps presenting; response
		// {"granted": true}, NO new secret.
		if err := authn.IssueMFAPendingGrant(ctx, tx, claims.UserID, id.JTI,
			authn.ReauthTokenHash(req.MFAToken), ceremony.Operation,
			authn.ProofMethodWebAuthn, credentialID, MFAReauthStepUpTTL); err != nil {
			h.possessionTxError(w, r, claims.UserID, "grant issuance", err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			h.possessionTxError(w, r, claims.UserID, "commit", err)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"granted": true})
		return
	}

	family := claims.RefreshFamilyID()
	granted, err := authn.IssueSessionGrant(ctx, tx, claims.UserID, id.JTI, family,
		ceremony.Operation, ceremony.TargetRef, authn.ProofMethodWebAuthn, credentialID, MFAReauthStepUpTTL)
	if err != nil {
		h.possessionTxError(w, r, claims.UserID, "grant issuance", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.possessionTxError(w, r, claims.UserID, "commit", err)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"reauth_token": granted,
		"expires_in":   int(MFAReauthStepUpTTL.Seconds()),
	})
}

// familyOrNil maps "" to a nil *string for the family columns.
func familyOrNil(family string) *string {
	if family == "" {
		return nil
	}
	return &family
}
