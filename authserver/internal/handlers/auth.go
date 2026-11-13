package handlers

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oschwald/geoip2-golang"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/connector"
	"setjoin.com/authserver/internal/federation"
	"setjoin.com/authserver/internal/federation/pkce"
	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/pwhash"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

// AuthHandlerConfig holds all dependencies for AuthHandler.
type AuthHandlerConfig struct {
	Pool           *pgxpool.Pool
	DatabaseWorker pgxutil.WorkerPool
	JWT            *token.JWTProvider
	CookieKey      []byte
	Logger         *slog.Logger
	SAMLSP         *federation.SAMLSPRegistry
	OIDCRP         *federation.OIDCRPProvider
	Passkey        *authn.PasskeyProvider
	PushMFA        authn.ChallengeProvider
	JITEnabled     bool
	CookieSecure   bool

	// TrustProxy opts in to honoring X-Forwarded-Proto from ANY peer, not just
	// loopback or an allowlisted proxy, when deciding the session cookie's
	// Secure attribute (see isTrustedProxyPeer / forwardedHTTPS below). Default
	// false; the standard single-node deploy (gateway proxies to authserver
	// over 127.0.0.1) needs no config at all.
	TrustProxy bool

	// TrustedProxyCIDRs is the explicit trusted-proxy allowlist
	// (AUTH_TRUSTED_PROXY_CIDRS / auth.trusted_proxy_cidrs): comma-separated
	// CIDR ranges whose immediate peers may drive forwarded-header trust.
	// Default empty = LOOPBACK-ONLY trust — since AUTHSERVERD-005 finding 3 a
	// private-range peer is NOT implicitly trusted; loopback peers always are.
	// config.LoadWithKoanf validation refuses malformed entries and the
	// default routes; NewAuthHandler fail-closes the whole list if anything is
	// unparseable anyway (defense-in-depth for embedders bypassing config).
	TrustedProxyCIDRs []string

	PolicyEngine   *threat.PolicyEngine  // conditional access (may be nil)
	GeoipDB        *geoip2.Reader        // GeoLite2 database for login event location (may be nil)
	SignInRecorder threat.SignInRecorder // CA sign-in telemetry; defaults to NoopSignInRecorder when nil

	// Connectors is the injected identity-source manager the AD password write-back
	// reads (h.connectors.CachedGet("ad")). nil defaults to an empty
	// connector.NewManager() so existing callers/tests are unchanged; no handler
	// reads a package global.
	Connectors *connector.ConnectorManager

	// Credentials is the injected MFA-enrollment store the pre-auth flows read to
	// pick the second factor to offer (Push>TOTP>Backup via SelectMFAMethod). nil
	// defaults to dbCredentialStore{Pool}, so existing callers/tests are unchanged.
	Credentials CredentialStore

	// SSOAllowSuperAdminMapping opts in to letting an admin-configured IdP
	// group->role mapping grant super_admin. Default false (safe): a group
	// mapping can never silently confer super_admin; the ceiling caps SSO-mapped
	// roles at user_admin unless an admin explicitly flips this on.
	SSOAllowSuperAdminMapping bool

	// DeviceTrust resolves the login-time DeviceClaim from managed_devices
	// (compliance_status -> trust tier), fail-open. May be nil (then no claim is
	// ever embedded). See ResolveDeviceClaim.
	DeviceTrust *threat.DeviceTrustResolver

	// Toggles gates device-trust enforcement (feature.device_trust_enforcement,
	// DEFAULT OFF). May be nil (then the feature is treated as OFF — no claim
	// embedded). The login claim is only produced when this is non-nil AND the
	// toggle is explicitly enabled.
	Toggles *toggle.FeatureFlags

	// DeviceResolver resolves device-bound credential signals (CA-2) from the
	// request's X-Device-* proof headers. When non-nil, Login stamps
	// pectx.DeviceBound/DeviceID/EnrollState before CA policy evaluation so
	// policies can gate on bound-device + enroll_state. May be nil (then
	// DeviceBound is always false — fail-closed for device_bound policies).
	DeviceResolver *threat.DeviceCredentialResolver

	// VAPIDPublicKey is the base64url-encoded VAPID public key, derived once at
	// startup from cfg.VAPIDPrivateKey (see main.go). Exposed unauthenticated via
	// WellKnown so the webmail PWA can pushManager.subscribe() with it. Empty
	// when push MFA/webpush is not configured (VAPID_PRIVATE_KEY unset).
	VAPIDPublicKey string

	// Bearer is the configured BearerAuthenticator (the same instance the
	// requireAuth middleware guards every route with). The dual-admission
	// possession endpoints reuse its full session-acceptance funnel — DPoP
	// proof-of-possession for cnf-bound tokens and the CA-3a revocation
	// check — for their access-token admission modes (r1 defect 4). Nil (the
	// zero value, e.g. in older tests): sessionAuthenticator lazily supplies
	// an equivalent authenticator over the configured JWT provider, so the
	// DPoP enforcement can never be silently skipped.
	Bearer *token.BearerAuthenticator
}

// passkeyProvider is the handler-owned WebAuthn seam. Production still injects
// *authn.PasskeyProvider through AuthHandlerConfig; keeping the shared deps bag
// behind the behavior it consumes lets handler tests exercise complete HTTP
// flows without manufacturing a cryptographic authenticator.
type passkeyProvider interface {
	BeginRegistration(context.Context, int64) ([]byte, []byte, error)
	FinishRegistration(context.Context, int64, []byte, *http.Request) error
	BeginLogin(context.Context, string) (int64, []byte, []byte, error)
	FinishLogin(context.Context, int64, []byte, *http.Request) error
	NameCredential(context.Context, []byte, int64, string) error
	RevokeCredential(context.Context, []byte, int64) error
}

// deps is the shared dependency + helper core for the auth-server HTTP handlers.
// It is constructed ONCE (in NewAuthHandler) and shared by reference across every
// cohesive sub-handler (login / MFA / account-recovery / impersonation / session),
// so the sub-handlers split the ~40 endpoints by concern without each one carrying
// — or re-creating — its own copy of the dependency bag. Cross-concern helpers
// (token issuance, user lookup, cookie crypto, login-event logging, the
// resolve_identity seam) live here too, so any sub-handler that embeds *deps reaches
// them as h.<helper>(...) exactly as before the split.
type deps struct {
	pool       *pgxpool.Pool
	workerPool pgxutil.WorkerPool
	// possessionTxBeginner is the query-failure injection seam for the
	// possession gate's handler-owned §2.2 transactions (mfa_possession.go,
	// totp.go). *pgxpool.Pool satisfies the interface; nil (production)
	// falls back to the concrete pool's Begin. Never set outside tests.
	possessionTxBeginner txBeginner
	jwt                  *token.JWTProvider
	svc                  *token.TokenService // token lifecycle seam (Wave 3): refresh + revoke
	cookieKey            []byte
	logger               *slog.Logger
	samlSP               *federation.SAMLSPRegistry
	oidcRP               *federation.OIDCRPProvider
	passkey              passkeyProvider
	pushMFA              authn.ChallengeProvider
	jitEnabled           bool
	cookieSecure         bool
	trustProxy           bool // see AuthHandlerConfig.TrustProxy
	// trustedProxyCIDRs is the parsed AUTHSERVERD-005 finding 3 allowlist
	// widening forwarded-header trust beyond loopback. nil = loopback-only
	// (the default). See AuthHandlerConfig.TrustedProxyCIDRs.
	trustedProxyCIDRs []*net.IPNet
	policyEngine      *threat.PolicyEngine  // conditional access (may be nil)
	geoipDB           *geoip2.Reader        // GeoLite2 database for login event location (may be nil)
	signInRecorder    threat.SignInRecorder // CA sign-in telemetry; defaults to NoopSignInRecorder

	// connectors is the injected identity-source manager (see AuthHandlerConfig.Connectors).
	connectors *connector.ConnectorManager

	// credentials is the injected MFA-enrollment store (see AuthHandlerConfig.Credentials).
	credentials CredentialStore

	// deviceTrust + toggles drive the login-embedded DeviceClaim (P1). Both may
	// be nil; the claim is produced only when deviceTrust != nil AND the
	// feature.device_trust_enforcement toggle is explicitly enabled (default OFF).
	deviceTrust *threat.DeviceTrustResolver
	toggles     *toggle.FeatureFlags

	// deviceResolver stamps DeviceBound/DeviceID/EnrollState into pectx at login
	// (CA-2 Task 7). May be nil (then DeviceBound is always false).
	deviceResolver *threat.DeviceCredentialResolver
	// guestScopeResolver derives Conditional Access guest scope from the
	// guest_accounts satellite. Production always wires it in NewAuthHandler;
	// nil is the explicit claim-free hermetic unit seam.
	guestScopeResolver func(context.Context, int64) (bool, error)

	// vapidPublicKey is the derived public half of VAPID_PRIVATE_KEY (see
	// AuthHandlerConfig.VAPIDPublicKey). Empty string when unconfigured.
	vapidPublicKey string

	// bearer is the configured BearerAuthenticator (AuthHandlerConfig.Bearer;
	// main.go wires the same instance requireAuth uses, with the CA-3a
	// revocation denylist attached). The dual-admission possession endpoints
	// reuse its session-acceptance funnel (DPoP + revocation) for their
	// access-token admission modes (r1 defect 4). Nil in constructions that
	// predate the seam; sessionAuthenticator lazily fills it Once-guarded so
	// the funnel is never silently skipped.
	bearer     *token.BearerAuthenticator
	bearerOnce sync.Once

	// ssoAllowSuperAdminMapping is the operator opt-in (default false) that gates
	// an admin-configured IdP group->role mapping conferring super_admin. When
	// false, applyGroupMappings REFUSES (+ Warn-logs) any super_admin mapping
	// before the upsert — a group mapping can never silently confer super_admin.
	// See AuthHandlerConfig.SSOAllowSuperAdminMapping (BUG 006: the knob was parsed
	// + wired but no longer consumed once cappedSSORole was deleted).
	ssoAllowSuperAdminMapping bool

	// identityResolver is the SP-mode "is this assertion an existing person?"
	// cascade (OIDC stable id → SAML stable id → resolve_identity address),
	// extracted behind a fake-able seam. Defaults to dbIdentityResolver{deps} in
	// NewAuthHandler so production behavior is unchanged; a test can substitute a
	// fake without wiring full OIDC/SAML rows.
	identityResolver IdentityResolver

	// identityLinkElevationBegin persists the one-use, session-bound database
	// authorization before a browser leaves for an external IdP. Production
	// wires the reducer-backed implementation below; the function seam keeps
	// cookie-shape unit tests hermetic.
	identityLinkElevationBegin func(
		context.Context, identityLinkFlow, []byte,
	) error
}

// AttachBearer installs the production BearerAuthenticator (the requireAuth
// instance, with the CA-3a revocation denylist attached) AFTER construction —
// main.go builds the denylist once the worker pool exists, later than
// NewAuthHandler. The possession endpoints' admission funnel picks it up;
// without it they fall back to the revocation-less default over the same JWT
// provider.
func (a *AuthHandler) AttachBearer(b *token.BearerAuthenticator) {
	if b != nil {
		a.bearer = b
	}
}

// sessionAuthenticator returns the configured bearer authenticator, lazily
// supplying an equivalent one over the configured JWT provider when the
// construction predated the seam (older tests build deps literals). Once-
// guarded so the DPoP replay cache stays per-handler, never per-request.
func (h *deps) sessionAuthenticator() *token.BearerAuthenticator {
	h.bearerOnce.Do(func() {
		if h.bearer == nil && h.jwt != nil {
			h.bearer = token.NewBearerAuthenticator(h.jwt)
		}
	})
	return h.bearer
}

// loginHandler owns the password-login concern: credential verification, the
// must-change-password / MFA-enrollment gates, conditional-access evaluation,
// SAML SP + OIDC RP federation entry/callback, JIT provisioning, the
// resolve_identity seam, and the (cross-concern) token-issuance helper. Methods
// live in auth.go.
type loginHandler struct{ *deps }

// mfaHandler owns the second-factor / step-up concern: TOTP, number-match push,
// WebAuthn passkeys, backup codes, the native-push MFA approve path, and native
// push-device registration. Methods live in mfa.go, totp.go, webauthn.go,
// push.go, push_mfa.go, device.go.
type mfaHandler struct{ *deps }

// accountRecoveryHandler owns self-service password recovery: forgot-password
// begin / verify / reset (feature-flagged). Methods live in account_recovery.go
// (forgot_password.go).
type accountRecoveryHandler struct{ *deps }

// impersonationHandler owns admin impersonation: the tier guard and the
// scope-constrained impersonation token. Methods live in impersonation.go.
type impersonationHandler struct{ *deps }

// sessionHandler owns established-session lifecycle: refresh rotation, logout
// (revoke-all), and the /auth/me profile read. Methods live in session.go.
type sessionHandler struct{ *deps }

// AuthHandler is the façade over the five cohesive sub-handlers. It embeds each
// one, so every endpoint method is promoted and remains reachable as
// authH.<Method> — the route wiring in main.go and the handler tests are
// unchanged. The single *deps is shared by every sub-handler (one bag, by
// reference), not re-created per handler.
type AuthHandler struct {
	*deps
	loginHandler
	mfaHandler
	accountRecoveryHandler
	impersonationHandler
	sessionHandler
}

// NewAuthHandler creates an auth handler.
func NewAuthHandler(cfg AuthHandlerConfig) *AuthHandler {
	// The token lifecycle seam composes the signing core with the oauth_tokens
	// store, so refresh + revoke go through one owner. Derived here (rather than
	// passed in) so existing callers/tests that supply Pool+JWT are unchanged.
	var svc *token.TokenService
	if cfg.JWT != nil {
		svc = token.NewTokenService(cfg.JWT, cfg.Pool, cfg.Toggles)
	}
	connectors := cfg.Connectors
	if connectors == nil {
		// Safe default: an empty manager (no factories, no warmed instances). The
		// AD write-back's CachedGet("ad") reads nil, matching the pre-refactor
		// production behaviour where no connector instance was ever created —
		// keeps callers/tests that omit Connectors working.
		connectors = connector.NewManager()
	}
	credentials := cfg.Credentials
	if credentials == nil {
		// Safe default: the pool-backed store. Keeps callers/tests that omit
		// Credentials working with unchanged DB-backed enrollment reads.
		credentials = dbCredentialStore{cfg.Pool}
	}
	signInRecorder := cfg.SignInRecorder
	if signInRecorder == nil {
		// ponytail: noop default — callers that omit SignInRecorder pay zero cost;
		// production wires NewPgxSignInRecorder when a pool + CA toggle are present.
		signInRecorder = threat.NoopSignInRecorder{}
	}
	workerPool := cfg.DatabaseWorker
	if workerPool.Pool == nil {
		// Safe compatibility default: existing tests and embedders that only pass
		// Pool keep working. Production main wires the explicit BYPASSRLS pool.
		workerPool = pgxutil.WorkerPool{Pool: cfg.Pool}
	}
	d := &deps{
		pool: cfg.Pool, workerPool: workerPool, jwt: cfg.JWT, svc: svc, cookieKey: cfg.CookieKey,
		logger: cfg.Logger, samlSP: cfg.SAMLSP, oidcRP: cfg.OIDCRP,
		passkey: cfg.Passkey, pushMFA: cfg.PushMFA,
		bearer:     cfg.Bearer,
		jitEnabled: cfg.JITEnabled, cookieSecure: cfg.CookieSecure, trustProxy: cfg.TrustProxy,
		trustedProxyCIDRs: parseTrustedProxyCIDRs(cfg.TrustedProxyCIDRs),
		policyEngine:      cfg.PolicyEngine, geoipDB: cfg.GeoipDB,
		signInRecorder:            signInRecorder,
		connectors:                connectors,
		credentials:               credentials,
		deviceTrust:               cfg.DeviceTrust,
		toggles:                   cfg.Toggles,
		ssoAllowSuperAdminMapping: cfg.SSOAllowSuperAdminMapping,
		deviceResolver:            cfg.DeviceResolver,
		vapidPublicKey:            cfg.VAPIDPublicKey,
	}
	d.guestScopeResolver = func(ctx context.Context, userID int64) (bool, error) {
		if cfg.Pool == nil {
			return false, errors.New("guest scope database unavailable")
		}
		var isGuest bool
		err := cfg.Pool.QueryRow(ctx, `SELECT is_guest_account($1)`, userID).Scan(&isGuest)
		return isGuest, err
	}
	d.identityLinkElevationBegin = func(
		ctx context.Context, flow identityLinkFlow, sessionHash []byte,
	) error {
		var result json.RawMessage
		return d.workerPool.QueryRow(ctx, `
			SELECT identity_auth_link_elevation_begin(
				$1,$2::uuid,$3,$4,$5,$6,to_timestamp($7)
			)`,
			flow.UserID, flow.FlowID, flow.SessionJTI, sessionHash,
			flow.Kind, flow.ProviderKey, flow.ExpiresAt,
		).Scan(&result)
	}
	// The default resolver runs the unchanged cascade against d's DB helpers. A
	// test may overwrite d.identityResolver to inject a fake before driving
	// lookupOrJITUser.
	d.identityResolver = dbIdentityResolver{d}
	return &AuthHandler{
		deps:                   d,
		loginHandler:           loginHandler{d},
		mfaHandler:             mfaHandler{d},
		accountRecoveryHandler: accountRecoveryHandler{d},
		impersonationHandler:   impersonationHandler{d},
		sessionHandler:         sessionHandler{d},
	}
}

// PasswordPolicy returns the current password policy from system_config.
// No authentication required — the client calls this before submitting a password.
func (h *loginHandler) PasswordPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusMethodNotAllowed, Detail: "Method not allowed"})
		return
	}

	p, err := pwhash.LoadPasswordPolicy(r.Context(), h.pool)
	if err != nil {
		slog.Error("failed to read password policy", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "An internal error occurred. Please try again."})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"minLength":        p.MinLength,
		"maxBytes":         pwhash.PasswordMaxBytes,
		"requireUppercase": p.RequireUppercase,
		"requireLowercase": p.RequireLowercase,
		"requireDigit":     p.RequireDigit,
		"requireSpecial":   p.RequireSpecial,
	})
}

// CompletionRequest is the single typed boundary into the existing authentication
// completion/issuance funnel. Request context remains reserved for request-scoped
// identity and audit state; security-critical completion metadata is explicit at
// every caller and cannot disappear through an untyped private context key.
type CompletionRequest struct {
	Factors  []string
	Metadata CompletionMetadata
}

type CompletionMetadata struct {
	ConditionalAccess CompletionConditionalAccess
	Session           *CompletionSessionMetadata
	IdentityFence     *jwtutil.IdentityFenceClaim
	CredentialFence   string
	// MintTx is caller-owned. The funnel may use it to persist the refresh-family
	// anchor but never commits, rolls back, or publishes a response for the caller.
	MintTx pgx.Tx
}

type CompletionConditionalAccess struct {
	// Evaluated prevents a second CA decision/log when password or SSO already ran
	// the login-time gate before entering the completion funnel.
	Evaluated bool
	// StepUpInProgress makes the completion CA leg audit-only, preventing a server-
	// demanded factor from being terminally re-challenged or blocked mid-completion.
	StepUpInProgress bool
}

type CompletionSessionMetadata struct {
	Confirmation      *jwtutil.ConfirmationClaim
	SignInFrequency   *int64
	PersistentSession string
	StaySignedIn      bool
}

func (h *deps) completionMetadataForDPoP(dpopJWK map[string]any, stepUpInProgress bool) CompletionMetadata {
	return CompletionMetadata{
		ConditionalAccess: CompletionConditionalAccess{StepUpInProgress: stepUpInProgress},
		Session: &CompletionSessionMetadata{
			Confirmation: h.cnfForToggle(dpopJWK),
		},
	}
}

func applyIdentityFenceClaim(
	ctx context.Context,
	tx pgx.Tx,
	userID int64,
	fence *jwtutil.IdentityFenceClaim,
) error {
	if fence == nil {
		return nil
	}
	if fence.SourceID <= 0 || fence.SourceGeneration <= 0 ||
		fence.LinkID <= 0 || fence.LinkGeneration <= 0 {
		return errors.New("invalid normalized identity fence claim")
	}
	_, err := tx.Exec(ctx,
		`SELECT identity_auth_mint_fence($1,$2,$3,$4,$5)`,
		userID,
		fence.SourceID,
		fence.SourceGeneration,
		fence.LinkID,
		fence.LinkGeneration,
	)
	return err
}

func applyAuthenticationMintFence(
	ctx context.Context,
	tx pgx.Tx,
	userID int64,
	identityFence *jwtutil.IdentityFenceClaim,
) error {
	if identityFence != nil {
		return applyIdentityFenceClaim(ctx, tx, userID, identityFence)
	}
	_, err := tx.Exec(ctx, `SELECT identity_auth_local_mint_fence($1)`, userID)
	return err
}

func credentialFenceForPasswordHash(passwordHash string) string {
	digest := sha256.Sum256([]byte(passwordHash))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func verifyCredentialFence(
	ctx context.Context,
	tx pgx.Tx,
	userID int64,
	expected string,
) error {
	if expected == "" {
		return nil
	}
	var currentHash string
	if err := tx.QueryRow(ctx,
		`SELECT password_hash FROM users WHERE id=$1 AND enabled`,
		userID,
	).Scan(&currentHash); err != nil {
		return fmt.Errorf("credential fence lookup: %w", err)
	}
	actual := credentialFenceForPasswordHash(currentHash)
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return errors.New("credential proof is stale")
	}
	return nil
}

func (h *deps) issueMFAPending(
	ctx context.Context,
	userID int64,
	email string,
	completion CompletionRequest,
) (string, error) {
	return h.jwt.IssueMFAPendingWithFences(
		userID, email, completion.Metadata.IdentityFence,
		completion.Metadata.CredentialFence, completion.Factors...,
	)
}

// issueMFAPendingBootstrap is the mandatory-enrollment branch's minting seam
// (possession scheme v7 §1.5.1): the mfa_token and — for C2/C3 accounts —
// its bootstrap possession grant commit in ONE transaction, so a client
// never holds an mfa_token whose bootstrap grant did not commit.
//
//  1. BEGIN on the pool.
//  2. applyAuthenticationMintFence + verifyCredentialFence in that tx (the
//     identical fences the enrollment setup/confirm arms run) — a
//     concurrent password change or identity transition fails the login
//     closed.
//  3. Cohort evaluation inside the tx (§1.2): enabled TOTP or a non-revoked
//     uv_capable credential ⇒ C1.
//  4. The token is signed with a pre-generated JTI (pure CPU; the token
//     string exists before any DB write).
//  5. C2/C3 only: DELETE prior grant rows + INSERT the bootstrap grant
//     {token_hash = SHA-256(mfa_token), session_jti = jti, operation
//     'bootstrap.totp.enroll', proof_method 'password', bound generation,
//     scope 'mfa_pending', refresh_family_id NULL, target NULL, 5-min TTL}.
//     C1 (UV-capable passkey holder): NO password grant — the grant is
//     minted later by the webauthn_uv management-assertion FINISH on the
//     possession endpoints (§1.5.1 step 5).
//  6. COMMIT. Only after commit does the caller write the response; any
//     failure → 500, token never returned.
func (h *deps) issueMFAPendingBootstrap(
	ctx context.Context,
	pool *pgxpool.Pool,
	userID int64,
	email string,
	completion CompletionRequest,
) (string, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("bootstrap tx begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := applyAuthenticationMintFence(ctx, tx, userID, completion.Metadata.IdentityFence); err != nil {
		return "", fmt.Errorf("bootstrap identity fence: %w", err)
	}
	if err := verifyCredentialFence(ctx, tx, userID, completion.Metadata.CredentialFence); err != nil {
		return "", fmt.Errorf("bootstrap credential fence: %w", err)
	}

	cohort, err := authn.ClassifyCohort(ctx, tx, userID)
	if err != nil {
		return "", fmt.Errorf("bootstrap cohort: %w", err)
	}

	// Step 4 first: sign with a pre-generated JTI so the grant row can bind
	// it inside this same transaction.
	tokenStr, jti, err := h.jwt.IssueMFAPendingWithFencesJTI(
		userID, email, completion.Metadata.IdentityFence,
		completion.Metadata.CredentialFence, "", completion.Factors...,
	)
	if err != nil {
		return "", fmt.Errorf("bootstrap token issue: %w", err)
	}

	if cohort != authn.CohortC1 {
		// C2/C3: the bootstrap grant commits atomically with the token's
		// return. The grant's presentation secret IS the mfa_token itself —
		// hash-only storage (V271 posture), no second opaque secret.
		if err := authn.IssueMFAPendingGrant(ctx, tx, userID, jti,
			authn.ReauthTokenHash(tokenStr), authn.OperationBootstrapTOTPEnroll,
			authn.ProofMethodPassword, nil, MFAReauthStepUpTTL); err != nil {
			return "", fmt.Errorf("bootstrap grant insert: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("bootstrap commit: %w", err)
	}
	return tokenStr, nil
}

type mfaStatusQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type mfaStatusResult struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func readMFAStatus(
	ctx context.Context,
	q mfaStatusQuerier,
	userID int64,
) (mfaStatusResult, error) {
	var raw json.RawMessage
	if err := q.QueryRow(ctx, `SELECT mfa_status($1)`, userID).Scan(&raw); err != nil {
		return mfaStatusResult{}, fmt.Errorf("query mfa status: %w", err)
	}
	var result mfaStatusResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return mfaStatusResult{}, fmt.Errorf("decode mfa status: %w", err)
	}
	switch result.Status {
	case "exempt", "enrolled", "enrollment_required", "optional":
		return result, nil
	default:
		return mfaStatusResult{}, fmt.Errorf("invalid mfa status %q", result.Status)
	}
}

// buildCnf converts an SPA-supplied DPoP public JWK into a token-binding cnf
// claim. Returns nil (unbound token) when the JWK is absent — binding is
// opt-in and default report_only until an org confirms client cooperation (§9).
func buildCnf(jwk map[string]any) (*jwtutil.ConfirmationClaim, error) {
	if len(jwk) == 0 {
		return nil, nil
	}
	jkt, err := threat.JKTFromJWK(jwk)
	if err != nil {
		return nil, err
	}
	return &jwtutil.ConfirmationClaim{JKT: jkt}, nil
}

// cnfForToggle is the single gate every token-minting completion path shares:
// it builds the cnf claim from an SPA-supplied JWK (buildCnf) and then applies
// the feature.token_binding toggle, so "does this session bind" can't drift
// between the password Login path and the MFA/backup-code/WebAuthn/push
// completion paths (TOTP verify, push status poll, backup-code verify,
// WebAuthn login finish, native push approve). A malformed JWK (buildCnf
// error) degrades to unbound rather than failing the login/completion.
func (h *deps) cnfForToggle(jwk map[string]any) *jwtutil.ConfirmationClaim {
	cnf, _ := buildCnf(jwk)
	if cnf != nil && (h.toggles == nil || !h.toggles.IsEnabled(toggle.FeatureTokenBinding)) {
		return nil // binding toggle off — issue unbound token
	}
	return cnf
}

// sifDBErrorFallbackSecs is embedded as the SIF when a matched policy's DB read
// fails. 1 hour caps the token so a time-bounded session control is never
// silently disabled for the full access-token TTL.
// ponytail: if per-org failure SIF is needed, read from system_config.
const sifDBErrorFallbackSecs int64 = 3600

// signInFreqSecondsFromPolicy reads policy_session_view(policyID).sign_in_frequency
// and converts {value,unit} → seconds. Returns nil when the policy has no SIF
// configured (no max age). Fails CLOSED on DB error: embeds sifDBErrorFallbackSecs
// so a transient failure never silently disables a time-bounded session control.
func signInFreqSecondsFromPolicy(ctx context.Context, pool *pgxpool.Pool, policyID int64) *int64 {
	if policyID == 0 {
		return nil
	}
	var raw []byte
	if err := pool.QueryRow(ctx,
		`SELECT (policy_session_view($1)->'sign_in_frequency')::text`, policyID,
	).Scan(&raw); err != nil {
		// ponytail: fail closed — DB error on a matched policy must not silently
		// disable sign-in-frequency enforcement for the lifetime of that token.
		s := sifDBErrorFallbackSecs
		return &s
	}
	if raw == nil {
		return nil // policy exists but no SIF configured — no constraint
	}
	var sif struct {
		Value int64  `json:"value"`
		Unit  string `json:"unit"`
	}
	if err := json.Unmarshal(raw, &sif); err != nil || sif.Value <= 0 {
		return nil
	}
	var secs int64
	switch sif.Unit {
	case "hours":
		secs = sif.Value * 3600
	case "days":
		secs = sif.Value * 86400
	default:
		return nil
	}
	return &secs
}

// persistentSessionFromPolicy reads policy_session_view(policyID).persistent_session.
// Returns "always" when absent (no matched policy → permissive default). Fails CLOSED
// on DB error: returns "never" so a transient failure never silently issues a
// full-TTL persistent cookie when the admin mandated session-cookie-only ("never").
func persistentSessionFromPolicy(ctx context.Context, pool *pgxpool.Pool, policyID int64) string {
	if policyID == 0 {
		return "always"
	}
	var v string
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(policy_session_view($1)->>'persistent_session','always')`, policyID,
	).Scan(&v); err != nil {
		// ponytail: fail closed — DB error on a matched policy must not default to
		// the most permissive cookie behavior. An admin who set persistent_session=
		// "never" for shared terminals must not get a full-TTL cookie on pool exhaustion.
		return "never"
	}
	if v == "" {
		return "always"
	}
	return v
}

// Login handles password login: bcrypt verify -> issue tokens -> set cookies.
func (h *loginHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email        string         `json:"email"`
		Password     string         `json:"password"`
		DPoPJWK      map[string]any `json:"dpop_jwk,omitempty"`
		StaySignedIn bool           `json:"stay_signed_in,omitempty"`
	}
	// Shared bounded ingress (not a raw decode): Login's CA evaluation below
	// resolves the device credential from the X-Device-* proof headers whose
	// HMAC is bound to the SHA-256 of the exact body — but this decode consumes
	// the body before that resolver runs. decodeBoundedAuthJSON stamps the
	// server-computed body digest (shared/device.WithServerBodyDigest) so the
	// proof binds to the bytes actually observed instead of failing closed
	// (med-shard2-006).
	if !decodeBoundedAuthJSON(w, r, &req) {
		return
	}

	clientIP := httputil.ClientIP(r)
	userAgent := r.UserAgent()

	user, err := h.verifyPassword(r.Context(), req.Email, req.Password, clientIP)
	if err != nil {
		// Best-effort: attribute the failure to a known user ID if the address exists (L3).
		// ponytail: lookupUser is cheap (indexed); 0 on miss → NULL in login_events.
		var failUserID int64
		if u, lerr := h.lookupUser(r.Context(), "email", req.Email); lerr == nil {
			failUserID = u.ID
		}
		threat.RecordSignIn(r.Context(), h.pool, threat.SignInRecord{
			UserID:     failUserID,
			Success:    false,
			Client:     "web",
			Protocol:   "http",
			AuthMethod: "password",
			SourceIP:   clientIP,
			Location:   h.geoIPLookup(clientIP),
			FailReason: "invalid_credentials",
		})
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "invalid credentials"})
		return
	}
	// Bind every later mint, including MFA completion, to the exact local
	// credential version that this request proved.
	completion := CompletionRequest{
		Factors: []string{token.AMRPassword},
		Metadata: CompletionMetadata{
			CredentialFence: user.CredentialFence,
		},
	}

	// Conditional access policy evaluation — runs after password verification
	var caPolicyID int64
	if h.policyEngine != nil {
		groupIDs := h.fetchUserGroups(r.Context(), user.ID)
		pectx := threat.PolicyEvalContext{
			UserID:      user.ID,
			GroupIDs:    groupIDs,
			SourceIP:    clientIP,
			Country:     h.geoIPCountryCode(clientIP), // ISO code -> geo_risk_tier (P3); "" degrades to "low"
			DeviceFP:    threat.MakeDeviceFP(userAgent, clientIP),
			AuthMethod:  "password",
			ClientType:  threat.ClientTypeWeb,
			Protocol:    threat.ProtocolHTTP,
			UserAgent:   userAgent,
			RequestTime: time.Now(),
		}
		if !h.populateGuestCAScope(w, r, &pectx, user.ID) {
			return
		}
		// CA-2 Task 7: stamp device-bound credential signals before evaluation.
		// Fail-closed: if the resolver is absent, DeviceBound stays false so a
		// device_bound policy blocks unprovable requests — never silently allows them.
		// user.ID is the just-verified authenticated user; Resolve gates on
		// devices.user_id = user.ID to block cross-user device replay.
		if h.deviceResolver != nil {
			b, id, st := h.deviceResolver.Resolve(r.Context(), r, user.ID)
			pectx.DeviceBound, pectx.DeviceID, pectx.EnrollState = b, id, st
		}
		blocked, pid := h.evaluateAndRespond(w, r, pectx, user.ID, user.Email, completion)
		if blocked {
			return
		}
		caPolicyID = pid
	}

	// Enforce must_change_password flag.
	// If set, the user must change their password before any other access is granted.
	if user.MustChangePassword {
		forceToken, tokenErr := h.jwt.IssueForcePasswordChange(user.ID, user.Email)
		if tokenErr != nil {
			slog.Error("must_change_password: token issue failed", "user_id", user.ID, "error", tokenErr)
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "token issue failed"})
			return
		}
		resp := map[string]interface{}{
			"status":                "force_password_change",
			"force_password_change": true,
			"force_token":           forceToken,
			"reason":                "Administrator requires a password change before access is granted.",
		}
		// Credentials verified — a repeat correct-password login must not trip the
		// threat pipeline's CAPTCHA/lockout counters (see WithVerifiedNoOutcome).
		*r = *r.WithContext(threat.WithVerifiedNoOutcome(r.Context()))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// MFA enforcement policy — check if MFA is required but user hasn't enrolled.
	// This must run before the per-user TOTP/Push check so that non-enrolled users
	// are told to enroll rather than getting full access.
	{
		mfaResult, err := readMFAStatus(r.Context(), h.pool, user.ID)
		if err != nil {
			slog.Error("mfa status check failed", "user_id", user.ID, "error", err)
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusServiceUnavailable,
				Detail: "MFA policy verification unavailable. Please try again.",
			})
			return
		}
		if mfaResult.Status == "enrollment_required" {
			// Bootstrap minting seam (v7 §1.5.1): the token and — for C2/C3 —
			// its bootstrap grant commit in ONE transaction; any failure →
			// 500 with the token never returned.
			mfaToken, tokenErr := h.issueMFAPendingBootstrap(
				r.Context(), h.pool, user.ID, user.Email, completion,
			)
			if tokenErr != nil {
				slog.Error("mfa enrollment: bootstrap issuance failed", "user_id", user.ID, "error", tokenErr)
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "token issue failed"})
				return
			}
			resp := map[string]interface{}{
				"status":       "mfa_enrollment_required",
				"mfa_required": true,
				"mfa_token":    mfaToken,
				"reason":       "enrollment_required",
			}
			if mfaResult.Message != "" {
				resp["message"] = mfaResult.Message
			}
			// Credentials verified (password correct); enrollment is pending, not
			// a failed login — see WithVerifiedNoOutcome.
			*r = *r.WithContext(threat.WithVerifiedNoOutcome(r.Context()))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(resp)
			return
		}
	}

	// MFA: push > TOTP > backup codes. Offer the strongest available method.
	// The enrollment flags loaded by verifyPassword feed the one selection helper
	// (UserCredentials.SelectMFAMethod), so the accept order is single-sourced with
	// the WebAuthn login-finish path rather than hand-copied here.
	if user.TOTPEnabled || user.PushMFAEnabled {
		creds := UserCredentials{TOTPEnrolled: user.TOTPEnabled, PushMFAEnrolled: user.PushMFAEnabled}
		resp := map[string]interface{}{"mfa_required": true, "status": "mfa_required"}

		// Push MFA is the preferred method (prevents MFA fatigue via number matching)
		if creds.SelectMFAMethod(h.pushMFA != nil) == "push" {
			// Issue MFA-pending JWT to bind the push challenge to this auth session
			mfaToken, err := h.issueMFAPending(
				r.Context(), user.ID, user.Email, completion,
			)
			if err != nil {
				h.logger.Warn("push MFA: failed to issue mfa_token, falling back to TOTP", "error", err)
			} else {
				// sessionID = the initiating MFA-pending token (the same
				// correlation PushMFASend uses): the /auth/push/status harvest
				// fence keys on this exact binding so an approved challenge can
				// only ever complete the browser session that minted it.
				challenge, err := h.pushMFA.GenerateChallenge(r.Context(), user.ID, mfaToken)
				if err == nil {
					resp["mfa_method"] = challenge.Method
					resp["mfa_token"] = mfaToken
					resp["nonce"] = challenge.Nonce
					// SECURITY (C10): the correct number-match code is NOT returned to the
					// login client — it is an out-of-band proof verified only on the
					// enrolled device (POST /auth/mfa/approve).
					resp["ttl_seconds"] = challenge.TTLSeconds
					resp["fallback"] = []string{"totp", "backup_codes"}
					// Credentials verified; a push MFA challenge is not a failed login.
					*r = *r.WithContext(threat.WithVerifiedNoOutcome(r.Context()))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusAccepted)
					json.NewEncoder(w).Encode(resp)
					return
				}
				h.logger.Warn("push MFA challenge generation failed, falling back to TOTP", "error", err)
			}
		}

		// TOTP fallback
		if user.TOTPEnabled {
			mfaToken, err := h.issueMFAPending(
				r.Context(), user.ID, user.Email, completion,
			)
			if err != nil {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "token issue failed"})
				return
			}
			resp["mfa_method"] = "totp"
			resp["mfa_token"] = mfaToken
			resp["fallback"] = []string{"backup_codes"}
			// Credentials verified; a TOTP MFA challenge is not a failed login.
			*r = *r.WithContext(threat.WithVerifiedNoOutcome(r.Context()))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(resp)
			return
		}

		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "MFA required but no method available"})
		return
	}

	*r = *r.WithContext(threat.WithUserID(r.Context(), user.ID))

	// CA-3a: embed cnf (token-binding) + sif (sign-in-frequency) + persistent-session
	// cookie from the matched policy. cnf is only set when the client presented a
	// DPoP JWK AND feature.token_binding is on — otherwise the token is unbound.
	cnf := h.cnfForToggle(req.DPoPJWK)
	sif := signInFreqSecondsFromPolicy(r.Context(), h.pool, caPolicyID)
	persist := persistentSessionFromPolicy(r.Context(), h.pool, caPolicyID)
	completion.Metadata.Session = &CompletionSessionMetadata{
		Confirmation: cnf, SignInFrequency: sif,
		PersistentSession: persist, StaySignedIn: req.StaySignedIn,
	}
	// G4: CA already evaluated at :evaluateAndRespond above — the issuance gate must
	// not re-evaluate (and double-log) this password login.
	completion.Metadata.ConditionalAccess.Evaluated = true

	h.issueTokens(w, r, user, completion)
}

// evaluateAndRespond calls policyEngine.Evaluate, records the result, and
// writes the HTTP response for block/step-up decisions.
// Returns (true, 0) when a terminal response has been written (block, or step-up);
// (false, policyID) when the login should continue (DecisionAllow or report-only).
// The policyID is the matched policy's ID (0 = default-allow path); callers use
// it to read session_control for cnf/sif/persistent-session embedding (CA-3a T11).
// userID and email are the authenticated user's identifiers, needed for
// IssueMFAPending in the step-up branch.
//
// ponytail: extracted from Login for direct unit-testing without a DB. Receiver is
// *deps (not *loginHandler) so the SSO issuance seam (settleSSOMappingsThenIssue,
// a *deps method) can reach the same block/step-up logic — the password Login path
// still calls it via promotion through loginHandler's embedded *deps.
func (h *deps) evaluateAndRespond(w http.ResponseWriter, r *http.Request, pectx threat.PolicyEvalContext, userID int64, email string, completion CompletionRequest) (blocked bool, policyID int64) {
	result := h.policyEngine.Evaluate(r.Context(), pectx)
	h.signInRecorder.Record(r.Context(), pectx, result)

	switch result.Decision {
	case threat.DecisionBlock:
		// CA-3b: require_terms / require_risk_remediation blocks at LOGIN are a
		// chicken-and-egg lockout — the user needs a token to reach /terms/pending
		// and /terms/accept. Let login proceed; the runtime gate (RequireRuntimeAccess)
		// enforces the block on every subsequent request. Only hard blocks (no
		// remediation hint) are terminal at login time.
		if result.Remediation != "" {
			return false, result.PolicyID // issue token; runtime gate enforces
		}
		if result.CorrelationID != "" {
			w.Header().Set("X-CA-Correlation-Id", result.CorrelationID)
		}
		h.logger.Warn("conditional access blocked login",
			"user_id", userID, "policy_id", result.PolicyID,
			"reason", result.Reason, "correlation_id", result.CorrelationID,
		)
		detail := result.Reason
		if result.CorrelationID != "" {
			// ponytail: append correlation ref so the blocked user can quote it to support.
			detail = result.Reason + " (reference " + result.CorrelationID + ")"
		}
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status:           http.StatusForbidden,
			Detail:           detail,
			Remediation:      result.Remediation,
			RemediationTouID: result.RemediationTermsID,
		})
		return true, 0

	case threat.DecisionStepUp:
		if result.CorrelationID != "" {
			w.Header().Set("X-CA-Correlation-Id", result.CorrelationID)
		}
		mfaToken, err := h.issueMFAPending(
			r.Context(), userID, email, completion,
		)
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "token issue failed"})
			return true, 0
		}
		resp := map[string]interface{}{
			"status":          "mfa_required",
			"mfa_required":    true,
			"mfa_token":       mfaToken,
			"mfa_method":      "totp",
			"step_up_reason":  result.Reason,
			"step_up_methods": result.StepUpMethods,
			"correlation_id":  result.CorrelationID,
		}
		h.logger.Info("conditional access step-up required",
			"user_id", userID, "policy_id", result.PolicyID,
			"methods", result.StepUpMethods, "correlation_id", result.CorrelationID,
		)
		// Credentials verified; a policy-driven step-up challenge is not a failed
		// login (same root cause as the enrollment/MFA branches in Login above).
		*r = *r.WithContext(threat.WithVerifiedNoOutcome(r.Context()))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(resp)
		return true, 0
	}

	return false, result.PolicyID // DecisionAllow or report-only: continue login
}

// ChangePassword handles password change with transaction locking.
func (h *loginHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	claims := tokenClaims(r)
	if claims == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "unauthorized"})
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	// Reject if new password is the same as the current one (plaintext check).
	// This catches the case before any expensive bcrypt operations.
	if req.NewPassword == req.OldPassword {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "New password must differ from current password"})
		return
	}

	// Validate password complexity via shared PL/pgSQL function
	var pwCheckRaw json.RawMessage
	if err := h.pool.QueryRow(r.Context(),
		`SELECT validate_password($1, $2)`, req.NewPassword, claims.IsAdmin,
	).Scan(&pwCheckRaw); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	var pwCheck struct {
		Valid bool   `json:"valid"`
		Error string `json:"error"`
	}
	json.Unmarshal(pwCheckRaw, &pwCheck)
	if !pwCheck.Valid {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: pwCheck.Error})
		return
	}

	// Check if the password is too common (matches a well-known weak password).
	if common, err := pwhash.CheckCommonPassword(r.Context(), h.pool, req.NewPassword); err != nil {
		slog.Error("common password check failed", "user_id", claims.UserID, "error", err)
		// Don't block on check failure — proceed with other checks
	} else if common {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "This password is too common and easily guessed. Please choose a stronger password."})
		return
	}

	// Reject if the password contains the user's email local-part or domain.
	if passwordContainsEmail(req.NewPassword, claims.Email) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "Password must not contain your email address or name."})
		return
	}

	// Load password history retention depth from system_config.
	var historyDepth int
	if err := h.pool.QueryRow(r.Context(),
		`SELECT COALESCE((SELECT (value->>0)::INT FROM system_config WHERE key = 'password_history_depth'), 5)`,
	).Scan(&historyDepth); err != nil || historyDepth < 1 {
		historyDepth = 5
	}

	// Wrap in transaction to prevent concurrent password change race
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	defer tx.Rollback(r.Context())
	if _, err := tx.Exec(r.Context(),
		`SELECT identity_auth_local_mint_fence($1)`, claims.UserID,
	); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusServiceUnavailable,
			Detail: "credential update fence unavailable",
		})
		return
	}

	// Defense-in-depth: claims.Email is minted from the canonical users.email,
	// but route it through the one seam (shared/identity) so the lookup key
	// matches the stored row even for a legacy non-canonical row predating the
	// writer-canonicalization (P3), and so authserver/AGENTS.md:325's
	// "CanonicalizeAddress at every consumer" invariant is literally true.
	canonEmail := identity.CanonicalizeAddress(claims.Email).String()
	var hash string
	if err := tx.QueryRow(r.Context(),
		`SELECT password_hash FROM users WHERE email = $1 FOR UPDATE`, canonEmail,
	).Scan(&hash); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "invalid current password"})
		return
	}
	if err := pwhash.VerifyPasswordHash(hash, req.OldPassword); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "invalid current password"})
		return
	}

	// Check new password against password history (prevents reuse).
	if historyDepth > 0 {
		rows, histErr := tx.Query(r.Context(),
			`SELECT password_hash FROM password_history
			 WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`,
			claims.UserID, historyDepth,
		)
		if histErr == nil {
			reused := false
			for rows.Next() {
				var oldHash string
				if rows.Scan(&oldHash) == nil {
					if pwhash.VerifyPasswordHash(oldHash, req.NewPassword) == nil {
						reused = true
						break
					}
				}
			}
			rows.Close()
			if reused {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "This password was used recently. Please choose a new one."})
				return
			}
		} else {
			slog.Error("password history check failed", "user_id", claims.UserID, "error", histErr)
			// Don't block on read failure — proceed to password change
		}
	}

	newHash, err := pwhash.HashPasswordWithProfile(req.NewPassword)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}

	// Update password hash and clear any enforced password change flag.
	// rows_affected == 1 is a structural backstop against the silent zero-rows
	// no-op class (a non-matching predicate would otherwise "succeed" writing
	// nothing) — mirrors connector.ChangePassword (P4/D3).
	tag, err := tx.Exec(r.Context(),
		`UPDATE users SET password_hash = $1, must_change_password = FALSE WHERE email = $2`,
		string(newHash), canonEmail)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	if n := tag.RowsAffected(); n != 1 {
		slog.Error("change password: expected to update exactly 1 row", "rows", n, "user_id", claims.UserID)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}

	// Record this password in history for future reuse checks.
	tx.Exec(r.Context(),
		`INSERT INTO password_history (user_id, password_hash) VALUES ($1, $2)`,
		claims.UserID, string(newHash))

	// Trim history to the configured depth.
	tx.Exec(r.Context(),
		`DELETE FROM password_history WHERE user_id = $1 AND id NOT IN
		 (SELECT id FROM password_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2)`,
		claims.UserID, historyDepth)

	if err := h.svc.RevokeAllForUserTx(r.Context(), tx, claims.UserID); err != nil {
		tx.Rollback(r.Context())
		h.logger.Error("revoke tokens failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "token revocation failed"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	w.WriteHeader(http.StatusNoContent)

	// Best-effort AD password write-back
	var syncSource string
	var adObjectGUID string
	if err := h.pool.QueryRow(r.Context(),
		`SELECT COALESCE(sync_source, 'local'), COALESCE(ad_object_guid::TEXT, '')
		 FROM users WHERE id = $1`, claims.UserID,
	).Scan(&syncSource, &adObjectGUID); err != nil {
		h.logger.Warn("AD password write-back skipped: user lookup failed", "error", err)
		// Continue with the password change, skip write-back
	}
	if syncSource == "ad" && adObjectGUID != "" {
		if adConn := h.connectors.CachedGet("ad"); adConn != nil {
			if err := adConn.ChangePassword(r.Context(), adObjectGUID, req.OldPassword, req.NewPassword); err != nil {
				h.logger.Warn("AD password write-back failed", "user", claims.Email, "error", err)
			}
		}
	}
}

// -- SAML 2.0 --

// SAMLMetadata serves the SP metadata XML for an IdP registration.
func (h *loginHandler) SAMLMetadata(w http.ResponseWriter, r *http.Request) {
	idp := r.PathValue("idp")
	if idp == "" || h.samlSP == nil {
		http.NotFound(w, r)
		return
	}
	reg := h.samlSP.Registration(idp)
	if reg == nil {
		http.NotFound(w, r)
		return
	}
	reg.Middleware().ServeHTTP(w, r)
}

// SAMLLogin initiates SP-initiated SAML SSO for a given IdP.
func (h *loginHandler) SAMLLogin(w http.ResponseWriter, r *http.Request) {
	idp := r.PathValue("idp")
	if idp == "" || h.samlSP == nil {
		http.NotFound(w, r)
		return
	}
	reg := h.samlSP.Registration(idp)
	if reg == nil {
		http.NotFound(w, r)
		return
	}
	reg.Middleware().RequireAccount(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		}),
	).ServeHTTP(w, r)
}

// SAMLACS handles the IdP's SAML assertion response.
func (h *loginHandler) SAMLACS(w http.ResponseWriter, r *http.Request) {
	idp := r.PathValue("idp")
	if idp == "" || h.samlSP == nil {
		http.NotFound(w, r)
		return
	}
	reg := h.samlSP.Registration(idp)
	if reg == nil {
		http.NotFound(w, r)
		return
	}

	// Wrap the ResponseWriter to suppress SAML middleware redirects
	wrapper := &samlACSResponseWriter{ResponseWriter: w, logger: h.logger}
	reg.Middleware().ServeHTTP(wrapper, r)

	// Extract session cookie set by SAML middleware
	cookieVal := ""
	for _, sc := range wrapper.Header()["Set-Cookie"] {
		for _, part := range strings.Split(sc, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "token=") {
				cookieVal = strings.TrimPrefix(part, "token=")
				break
			}
		}
	}
	if cookieVal == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "SAML authentication failed"})
		return
	}

	// Create a synthetic request with the session cookie to extract NameID
	synth, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "/", nil)
	synth.AddCookie(&http.Cookie{Name: "token", Value: cookieVal})

	// Assertion replay detection — atomic insert-or-detect (OASIS Core §2.5.1)
	// Must run after the SAML middleware sets the session cookie so AssertionID can
	// extract the assertion ID from the session.
	assertionID, err := reg.AssertionID(synth)
	if err != nil || assertionID == "" {
		h.logger.Warn("saml acs: assertion ID missing, rejecting", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "SAML assertion missing ID"})
		return
	}
	var insertedID string
	err = h.pool.QueryRow(r.Context(),
		`INSERT INTO used_saml_assertions (assertion_id) VALUES ($1)
		 ON CONFLICT (assertion_id) DO NOTHING
		 RETURNING assertion_id`,
		assertionID,
	).Scan(&insertedID)
	if err != nil {
		h.logger.Warn("saml acs: replay detected", "assertion_id", assertionID)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "SAML assertion already used"})
		return
	}

	nameID, err := reg.NameIDFromRequest(synth)
	if err != nil {
		h.logger.Error("saml nameid extraction failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "SAML authentication failed"})
		return
	}

	// Preserve raw NameID -- don't force email format
	nameID = strings.TrimPrefix(nameID, "mailto:")
	email := nameID
	if !strings.Contains(email, "@") {
		// NameID is not an email -- try assertion attributes
		var attrErr error
		email, attrErr = reg.EmailFromAssertion(synth)
		if attrErr != nil {
			h.logger.Error("saml email extraction failed", "nameid", nameID, "error", attrErr)
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "SAML authentication failed: no email in assertion"})
			return
		}
	}

	// Extract groups from assertion
	groups, err := reg.GroupsFromAssertion(synth)
	if h.completeFederatedCallback(w, r, "SAML", groups, err, federatedIdentityLink{"saml", reg.SSOProviderKey(), reg.IDPEntityID, nameID, nil, reg}) {
		return
	}

	jitOK := reg.JITEnabled()
	h.lookupOrJITUser(w, r, email, "", "", nameID, reg.IDPEntityID, groups, jitOK, reg)
}

// -- OIDC (OpenID Connect) --

// oidcFlowTTL is the lifetime of OIDC login-flow cookies (state, nonce,
// provider, PKCE verifier). Must be long enough for slow IdPs, MFA prompts,
// and SSO consent screens.
const oidcFlowTTL = 600 // 10 minutes

// OIDCLogin redirects to the OIDC provider for authentication.
func (h *loginHandler) OIDCLogin(w http.ResponseWriter, r *http.Request) {
	if h.oidcRP == nil {
		http.NotFound(w, r)
		return
	}
	providerName := r.URL.Query().Get("provider")
	cfg := h.oidcRP.Provider(providerName)
	if cfg == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "unknown OIDC provider"})
		return
	}
	state, err := federation.RandomState()
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	nonce, err := federation.RandomState()
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	// PKCE (FEDERATION-003, RFC 7636): AuthCodeURL mints the code_verifier and
	// carries its S256 code_challenge in the authorization URL. The verifier
	// rides the same request-bound HttpOnly SameSite=Strict flow-cookie set as
	// state/nonce and is required (and cleared) at the callback.
	authURL, verifier, err := cfg.AuthCodeURL(state, nonce)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "oidc_state", Value: state,
		MaxAge: oidcFlowTTL, HttpOnly: true, Secure: h.cookieSecure || r.TLS != nil || h.forwardedHTTPS(r), SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "oidc_nonce", Value: nonce,
		MaxAge: oidcFlowTTL, HttpOnly: true, Secure: h.cookieSecure || r.TLS != nil || h.forwardedHTTPS(r), SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "oidc_provider", Value: providerName,
		MaxAge: oidcFlowTTL, HttpOnly: true, Secure: h.cookieSecure || r.TLS != nil || h.forwardedHTTPS(r), SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "oidc_verifier", Value: verifier,
		MaxAge: oidcFlowTTL, HttpOnly: true, Secure: h.cookieSecure || r.TLS != nil || h.forwardedHTTPS(r), SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, authURL, http.StatusFound)
}

// OIDCCallback handles the OIDC provider's authorization code callback.
func (h *loginHandler) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	if h.oidcRP == nil {
		http.NotFound(w, r)
		return
	}
	stateCookie, err := r.Cookie("oidc_state")
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid state"})
		return
	}
	// PKCE (FEDERATION-003): the flow's code_verifier cookie is request-bound
	// state like the state cookie. Missing or malformed flow state fails closed
	// before any provider resolution or token exchange; a well-formed verifier
	// that does not derive the challenge sent at redirect time is rejected by
	// the IdP during Exchange (RFC 7636 §4.6).
	verifierCookie, err := r.Cookie("oidc_verifier")
	if err != nil || verifierCookie.Value == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "missing code verifier"})
		return
	}
	if err := pkce.ValidateVerifier(verifierCookie.Value); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid code verifier"})
		return
	}
	providerCookie, err := r.Cookie("oidc_provider")
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "missing provider"})
		return
	}
	cfg := h.oidcRP.Provider(providerCookie.Value)
	if cfg == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "unknown OIDC provider"})
		return
	}

	// Validate redirect_uri if present (OIDC Core §3.1.2.7)
	if redirectURI := r.URL.Query().Get("redirect_uri"); redirectURI != "" {
		if redirectURI != cfg.RedirectURL() {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "redirect_uri mismatch"})
			return
		}
	}

	// Clear state and PKCE verifier cookies immediately to prevent replay
	h.clearAuthCookie(w, r, "oidc_state", "")
	h.clearAuthCookie(w, r, "oidc_verifier", "")

	tokens, err := cfg.Exchange(r.Context(), r.URL.Query().Get("code"), verifierCookie.Value)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "token exchange failed"})
		return
	}

	claims := tokens.IDTokenClaims

	// Validate nonce for replay protection (OIDC Core §3.1.2.1, §15.5.2)
	nonceCookie, err := r.Cookie("oidc_nonce")
	if err != nil || claims.Nonce != nonceCookie.Value {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid nonce"})
		return
	}
	// Clear nonce and provider cookies
	h.clearAuthCookie(w, r, "oidc_nonce", "")
	h.clearAuthCookie(w, r, "oidc_provider", "")

	// Verify email_verified claim (OIDC Core §5.1)
	if !federation.EmailVerifiedFromIDToken(claims) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "email not verified by provider"})
		return
	}

	email, err := federation.EmailFromIDToken(claims)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "no email in ID token"})
		return
	}

	// Extract stable identity
	sub, iss, err := federation.SubjectFromIDToken(claims.Subject, claims.Issuer)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "no subject in ID token"})
		return
	}

	// Extract group claims from ID token
	groups, err := federation.GroupsFromClaims(claims.Claims, cfg.GroupClaim())
	if h.completeFederatedCallback(w, r, "OIDC", groups, err, federatedIdentityLink{"oidc", cfg.SSOProviderKey(), iss, sub, nil, cfg}) {
		return
	}

	// Pass to lookup/JIT with OIDC identity
	jitOK := cfg.JITEnabled() || h.jitEnabled
	h.lookupOrJITUser(w, r, email, sub, iss, "", "", groups, jitOK, cfg)
}

// -- JIT (Just-In-Time) Provisioning --

// lookupOrJITUser resolves a user by stable ID, email, or creates one via JIT provisioning.
// Priority: OIDC stable ID > SAML stable ID > email > JIT create.
// On every SSO login, group mappings are refreshed.
func (h *loginHandler) lookupOrJITUser(
	w http.ResponseWriter, r *http.Request,
	email, oidcSub, oidcIss, samlNameID, samlIDP string,
	groups []string,
	jitEnabled bool,
	mapper federation.GroupMappingProvider,
) {
	ctx := r.Context()

	keys := identityKeys{
		email:      email,
		oidcSub:    oidcSub,
		oidcIss:    oidcIss,
		samlNameID: samlNameID,
		samlIDP:    samlIDP,
	}

	// authMethod feeds PolicyEvalContext.AuthMethod in the CA gate (settleSSOMappingsThenIssue)
	// so auth-method-scoped CA policies match the federated protocol (RFC-8176-style "saml"/"oidc").
	authMethod := "saml"
	if keys.hasOIDC() {
		authMethod = "oidc"
	}

	// Run the unchanged SP-mode resolution cascade behind the IdentityResolver
	// seam: OIDC stable id → SAML stable id → resolve_identity address (ADR-004).
	// The resolver is read-only; the per-source side effects below (SSO-email
	// refresh on a stable-id hit, stable-id link on an address hit, then token
	// issuance + group mapping) stay here exactly as before.
	user, src, err := h.identityResolver.ResolveExisting(ctx, keys)
	if errors.Is(err, errNormalizedIdentityResolution) {
		h.logger.Warn("normalized identity resolution failed closed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusServiceUnavailable,
			Detail: "normalized identity resolution unavailable",
		})
		return
	}

	// Guest Accounts P17: a guest row never participates in SSO resolution,
	// linking, or JIT. Fail CLOSED — no identity link, no token issuance, no
	// email refresh. (SSO-federated guest identity is an explicit v1
	// anti-scope; until that reverses, an SSO touch of a guest row is an
	// identity-plane confusion, not a feature.) Checked at the first point
	// `user` is non-nil, before any of the per-source side effects below.
	if user != nil {
		var resolvedIsGuest bool
		if qerr := h.pool.QueryRow(ctx, `SELECT is_guest_account($1)`, user.ID).Scan(&resolvedIsGuest); qerr != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "account type resolution failed"})
			return
		}
		if resolvedIsGuest {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "sso: identity resolves to a guest account"})
			return
		}
	}

	switch src {
	case resolveOIDC, resolveSAML:
		if berr := h.bindSSOProvider(ctx, keys, mapper); berr != nil &&
			h.toggles != nil &&
			h.toggles.IsEnabled(toggle.FeatureIdentityModelV2) {
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusServiceUnavailable,
				Detail: "normalized identity source binding failed",
			})
			return
		}
		h.settleSSOMappingsThenIssue(w, r, user, email, groups, mapper, authMethod)
		return
	case resolveAddress:
		// Email, alias, and UPN are discovery candidates only. They never prove
		// that the IdP subject is the already-existing local person, regardless
		// of rollout-toggle state. Requiring an authenticated fresh-AAL2 link
		// prevents a compromised/misconfigured IdP from claiming a victim by
		// asserting the victim's address.
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusConflict,
			Detail: "explicit account linking is required",
		})
		return
	}
	// src == resolveNone: no existing person matched (err carries the
	// address-lookup miss). Fall through to JIT provisioning, exactly as before.

	// 4. JIT provision if enabled
	if !jitEnabled {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "user not found"})
		return
	}

	normalizedJIT := src == resolveNormalizedNone
	if normalizedJIT {
		user, err = h.createNormalizedJITUser(ctx, email, oidcSub, oidcIss, samlNameID, samlIDP)
	} else {
		user, err = h.createJITUser(ctx, email, oidcSub, oidcIss, samlNameID, samlIDP)
	}
	if err != nil {
		h.logger.Error("JIT user creation failed", "email", email, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "user creation failed"})
		return
	}

	// Legacy JIT still creates its mailbox here. The normalized reducer commits
	// person, mailbox, link, lifecycle authority, and event atomically.
	// (applyGroupMappings needs a primary mailbox to assign distribution
	// group memberships) and for mail delivery.
	if !normalizedJIT {
		if _, err := h.pool.Exec(ctx,
			`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 SELECT u.id, u.domain_id, u.email, u.display_name, 'personal', TRUE
		 FROM users u WHERE u.id = $1
		 ON CONFLICT DO NOTHING`, user.ID,
		); err != nil {
			h.logger.Error("JIT primary mailbox creation failed", "user_id", user.ID, "error", err)
		}
	}

	if berr := h.bindSSOProvider(ctx, keys, mapper); berr != nil &&
		h.toggles != nil &&
		h.toggles.IsEnabled(toggle.FeatureIdentityModelV2) {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusServiceUnavailable,
			Detail: "normalized identity source binding failed",
		})
		return
	}
	h.settleSSOMappingsThenIssue(w, r, user, email, groups, mapper, authMethod)
}

func (h *loginHandler) createNormalizedJITUser(
	ctx context.Context,
	email, oidcSub, oidcIss, samlNameID, samlIDP string,
) (*userRow, error) {
	normalized, err := normalizeAndValidateSSOEmail(email)
	if err != nil {
		return nil, fmt.Errorf("jit_user_creation_rejected_invalid_email: %w", err)
	}
	kind, provider, subject := "oidc", oidcIss, oidcSub
	if subject == "" || provider == "" {
		kind, provider, subject = "saml", samlIDP, samlNameID
	}
	if subject == "" || provider == "" {
		return nil, fmt.Errorf("jit_user_creation_rejected_missing_stable_pair")
	}
	displayName := strings.SplitN(normalized, "@", 2)[0]
	var raw []byte
	if err := h.workerPool.QueryRow(ctx,
		`SELECT identity_auth_jit($1,$2,$3,$4,$5)`,
		kind, provider, subject, normalized, displayName,
	).Scan(&raw); err != nil {
		return nil, err
	}
	return parseNormalizedJITResult(raw, func(userID int64) (*userRow, error) {
		return h.lookupUser(ctx, "id", userID)
	})
}

type normalizedJITResult struct {
	State            string `json:"state"`
	Code             string `json:"code"`
	UserID           string `json:"userId"`
	SourceID         string `json:"sourceId"`
	SourceGeneration string `json:"sourceGeneration"`
	LinkID           string `json:"linkId"`
	LinkGeneration   string `json:"linkGeneration"`
}

func parseNormalizedJITResult(
	raw []byte,
	lookup func(int64) (*userRow, error),
) (*userRow, error) {
	var result normalizedJITResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	if result.State == "blocked" || result.UserID == "" {
		return nil, fmt.Errorf("normalized JIT blocked (%s)", result.Code)
	}
	userID, err := strconv.ParseInt(result.UserID, 10, 64)
	if err != nil {
		return nil, err
	}
	user, err := lookup(userID)
	if err != nil {
		return nil, err
	}
	if user.IdentitySourceID, err = strconv.ParseInt(result.SourceID, 10, 64); err != nil {
		return nil, err
	}
	if user.IdentitySourceGeneration, err = strconv.ParseInt(
		result.SourceGeneration, 10, 64,
	); err != nil {
		return nil, err
	}
	if user.IdentityLinkID, err = strconv.ParseInt(result.LinkID, 10, 64); err != nil {
		return nil, err
	}
	if user.IdentityLinkGeneration, err = strconv.ParseInt(
		result.LinkGeneration, 10, 64,
	); err != nil {
		return nil, err
	}
	return user, nil
}

// createJITUser creates a new user for just-in-time provisioning.
//
// The email originates from an untrusted IdP attribute (SAML NameID / OIDC sub),
// so it MUST be normalized and validated before it is written into users.email —
// otherwise a malicious IdP (or a compromised/misconfigured one) could inject
// header-injection / control-character / non-email payloads into provisioning.
func (h *loginHandler) createJITUser(ctx context.Context, email, oidcSub, oidcIss, samlNameID, samlIDP string) (*userRow, error) {
	// Normalize + validate through the shared SSO-identity seam before any
	// provisioning side effect.
	normalized, err := normalizeAndValidateSSOEmail(email)
	if err != nil {
		return nil, fmt.Errorf("jit_user_creation_rejected_invalid_email: %w", err)
	}
	email = normalized

	var user userRow
	var displayName string
	parts := strings.SplitN(email, "@", 2)
	domain := "local"
	if len(parts) == 2 {
		domain = parts[1]
	}
	localPart := parts[0]

	// Build display_name: prefer the SAML NameID if it looks like a human name,
	// otherwise use the email local-part.
	if samlNameID != "" && !strings.Contains(samlNameID, "@") {
		displayName = samlNameID
	} else {
		displayName = localPart
	}

	// If the username (local-part) contains non-ASCII characters,
	// generate an ASCII-safe username from the email address.
	username := localPart
	if !isASCII(localPart) {
		username = strings.ToLower(strings.ReplaceAll(email, "@", "."))
		// Truncate to a reasonable length for username column.
		if len(username) > 64 {
			username = username[:64]
		}
	}

	err = h.pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled,
		                    oidc_subject, oidc_issuer, saml_name_id, saml_idp_entity_id)
		 SELECT $1, $2, $3, id, 'sso', TRUE, $5, $6, $7, $8
		 FROM domains WHERE name = $4 AND is_local = TRUE
		 ON CONFLICT DO NOTHING
		 RETURNING id, email, `+isAdminExprSQL,
		username, email, displayName, domain,
		nullIfEmpty(oidcSub), nullIfEmpty(oidcIss), nullIfEmpty(samlNameID), nullIfEmpty(samlIDP),
	).Scan(&user.ID, &user.Email, &user.IsAdmin)
	if err != nil {
		return nil, fmt.Errorf("jit_user_creation_failed: %w", err)
	}

	h.logger.Info("JIT user created", "email", email, "user_id", user.ID)
	return &user, nil
}

// -- SAML Response Writer --

type samlACSResponseWriter struct {
	http.ResponseWriter
	logger      *slog.Logger
	wroteHeader bool
}

func (w *samlACSResponseWriter) WriteHeader(code int) {
	if code >= 300 && code < 400 {
		return // suppress SAML middleware redirect
	}
	w.ResponseWriter.WriteHeader(code)
	w.wroteHeader = true
}

func (w *samlACSResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.logger.Warn("saml acs: suppressing error response", "body", string(b))
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

type userRow struct {
	ID                 int64
	Email              string
	IsAdmin            bool
	TOTPEnabled        bool
	PushMFAEnabled     bool
	MustChangePassword bool
	CredentialFence    string

	// Set only when this login resolved or JIT-created through the normalized
	// SAML/OIDC link model. settleSSOMappingsThenIssue holds the exact source
	// and link generations through refresh-family persistence, closing the
	// detach-between-resolve-and-mint race.
	IdentitySourceID         int64
	IdentitySourceGeneration int64
	IdentityLinkID           int64
	IdentityLinkGeneration   int64
}

func (h *deps) verifyPassword(ctx context.Context, email, password, clientIP string) (*userRow, error) {
	var row struct {
		ID                 int64
		Email              string
		IsAdmin            bool
		Hash               string
		TOTPEnabled        bool
		PushMFAEnabled     bool
		MustChangePassword bool
	}
	// BUG FIX (login case-sensitivity): users.email is ALWAYS stored lower(trim())
	// and uniqueness is users_email_lower_idx UNIQUE on lower(email), while the
	// sister lookups (lookupUser, forgot-password) match lower(email) = lower($1).
	// This lookup was the ONLY one using `email = $1` (case-SENSITIVE), so a user
	// who typed `Alice@Corp.com` could reset their password and be found by admin
	// but could NOT log in. Aligning to lower(email) = lower($1) can only ADD the
	// match the lowercased UNIQUE already made the single owner row — it cannot
	// reach a different person. Strictly safe.
	// is_admin is DERIVED from a governed, unexpired admin_role_assignments row, NOT
	// read from the vestigial users.is_admin column (BUG 003 / RBAC cut-over). A
	// freshly-granted admin (AssignMember / SSO writes the assignment but never sets
	// users.is_admin) would otherwise mint IsAdmin=false and be 403'd on every admin
	// route by the gateway (chain.go skips permissions.Resolve when !IsAdmin). The
	// EXISTS predicate matches session.go and shared/permissions.Resolve (same
	// expires_at filter), so the minted claim agrees with the enforced one.
	err := h.pool.QueryRow(ctx,
		`SELECT id, email, `+isAdminExprSQL+`, password_hash,
		        COALESCE(totp_enabled, FALSE), COALESCE(push_mfa_enabled, FALSE),
		        COALESCE(must_change_password, FALSE)
		 FROM users WHERE lower(email) = lower($1) AND enabled = TRUE`, email,
	).Scan(&row.ID, &row.Email, &row.IsAdmin, &row.Hash, &row.TOTPEnabled, &row.PushMFAEnabled,
		&row.MustChangePassword)
	if err != nil {
		pwhash.LogAuthEvent(ctx, h.pool, pwhash.AuthEvent{
			Event: "login_failed", Provider: "bcrypt", Email: email,
			IPAddress: clientIP, Details: `{"reason": "user_not_found"}`,
		}, nil)
		return nil, err
	}
	if err := pwhash.VerifyPasswordHash(row.Hash, password); err != nil {
		pwhash.LogAuthEvent(ctx, h.pool, pwhash.AuthEvent{
			Event: "login_failed", Provider: "bcrypt", Email: email,
			IPAddress: clientIP,
		}, nil)
		return nil, err
	}
	return &userRow{
		ID:                 row.ID,
		Email:              row.Email,
		IsAdmin:            row.IsAdmin,
		TOTPEnabled:        row.TOTPEnabled,
		PushMFAEnabled:     row.PushMFAEnabled,
		MustChangePassword: row.MustChangePassword,
		CredentialFence:    credentialFenceForPasswordHash(row.Hash),
	}, nil
}

// issueTokens issues access + refresh tokens for a single-factor (password-only)
// session. Use issueTokensWithFactors when one or more additional factors were
// satisfied so the access token advertises the correct acr/amr.
func (h *deps) issueTokens(w http.ResponseWriter, r *http.Request, user *userRow, completion CompletionRequest) {
	h.issueTokensWithFactors(w, r, user, completion)
}

// issueTokensWithFactors is the thin HTTP adapter over token.TokenService.Issue:
// it shapes an explicit token.IssueInput from the request plus CompletionRequest
// (device/risk claims, fail-closed domain scope, typed CA-3a metadata), calls
// the service — which mints the pair AND persists the oauth_tokens anchor row
// WITH family_id — then handles the HTTP tail: auth-event log, sign-in record,
// the access_token cookie, and the JSON body. The access token's acr/amr are
// derived from factors inside the service (RFC 8176 amr, NIST AAL acr, incl.
// the "mfa"/aal2 marker when ≥2 distinct factors completed).
func (h *deps) issueTokensWithFactors(w http.ResponseWriter, r *http.Request, user *userRow, completion CompletionRequest) {
	ctx := r.Context()
	factors := completion.Factors

	// G4: login-time CA gate for factor-completion paths. Password/SSO already
	// evaluated (they set completion.Metadata.ConditionalAccess.Evaluated); the five
	// second-factor/passwordless handlers did not, so this is their only login-time CA decision +
	// ca_signin_log row. See evaluateCompletionConditionalAccess for decisions 1/2.
	completionPolicyID := int64(0)
	if h.policyEngine != nil {
		if !completion.Metadata.ConditionalAccess.Evaluated {
			stop, pid := h.evaluateCompletionConditionalAccess(w, r, user, completion)
			if stop {
				return
			}
			completionPolicyID = pid
		}
	}

	// Resolve domain scope from admin role assignments. A non-super_admin admin
	// may be restricted to a single domain (via the role group's domain_scope or
	// a narrower per-assignment domain_override). The join is on role_group_id ->
	// admin_role_groups.id (there is no ra.role_group column). We fail CLOSED: if
	// scope resolution errors we deny the token rather than issue an unscoped one,
	// which would silently grant a scoped admin global access.
	var domainScope *int64
	if user.IsAdmin {
		// All admins (including super_admin) go through scope resolution.
		// MintDomainScope returns nil when there are no domain-scoped role assignments
		// → global scope. super_admin typically has no narrowing rows so nil (global)
		// is the correct outcome for them too; removing the AdminRole != "super_admin"
		// carve-out keeps the condition consistent with the gateway enforcement path
		// (which calls MintDomainScope without special-casing the role).
		//
		// Single-sourced with the gateway's ENFORCED scope: permissions.MintDomainScope
		// is the inverse-projection sibling of shared/permissions.Resolve over the
		// same rows (MIN of the effective scope, EXPIRED grants dropped). Sharing
		// code — not a hand-copied twin kept in lockstep by a comment — is what
		// keeps mint == enforce: without the expires_at filter an expired narrowing
		// override would win the MIN here while Resolve drops it, so the gateway
		// would enforce a BROADER scope than this token mints (scope-broadening).
		scope, err := permissions.MintDomainScope(ctx, h.pool, user.ID)
		if err != nil {
			// Fail CLOSED: deny the token rather than mint an unscoped (global) one.
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "authorization scope resolution failed"})
			return
		}
		// scope is nil when the admin has no domain-scoped role assignments → global.
		domainScope = scope
	}

	// Guest Accounts P13: derive the acct claim from the satellite — the ONE
	// login-mint derivation for all seven login-shaped flows. Fail CLOSED on a
	// lookup error: deny the token rather than mint a guest a member claim.
	var isGuest bool
	var identityAdmissionAllowed bool
	if err := h.pool.QueryRow(ctx,
		`SELECT identity_transition_admission_allowed($1)`, user.ID,
	).Scan(&identityAdmissionAllowed); err != nil {
		// Fail closed: a database/RLS/function failure must not mint a token
		// around an unfinished transition revocation fence.
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusInternalServerError,
			Detail: "identity transition admission resolution failed",
		})
		return
	}
	if !identityAdmissionAllowed {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Type:   httputil.TypeConflict,
			Status: http.StatusConflict,
			Detail: "Sign-in is temporarily fenced while identity transition security effects converge.",
		})
		return
	}
	if err := h.pool.QueryRow(ctx, `SELECT is_guest_account($1)`, user.ID).Scan(&isGuest); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "account type resolution failed"})
		return
	}

	in := token.IssueInput{
		UserID:      user.ID,
		Email:       user.Email,
		IsAdmin:     user.IsAdmin,
		Factors:     factors,
		Device:      h.resolveLoginDeviceClaim(r, user.ID),
		Risk:        h.riskClaimFor(ctx, user.ID),
		DomainScope: domainScope,
		AccountType: func() string {
			if isGuest {
				return jwtutil.AccountTypeGuest
			}
			return ""
		}(),
	}
	// CA-3a: embed cnf+sif when a caller supplied session metadata. Nil metadata
	// preserves the legacy SAML/OIDC cookie and token shape.
	ca := completion.Metadata.Session
	hasCA := ca != nil
	if hasCA {
		in.Cnf, in.SIF = ca.Confirmation, ca.SignInFrequency
		// MFA completions carry the session envelope (for cnf) but historically
		// omitted the conditional-access sign-in-frequency control the matched
		// policy mandates — password logins embedded it, every MFA-completed
		// session silently outlived the policy's max session age. When the CA
		// gate above matched a policy, apply ITS sif exactly as the password
		// Login path does (signInFreqSecondsFromPolicy, same fail-closed DB
		// fallback). Callers that already set an sif are honored, not overridden.
		if in.SIF == nil && completionPolicyID != 0 {
			in.SIF = signInFreqSecondsFromPolicy(ctx, h.pool, completionPolicyID)
		}
	}

	// The service mints access+refresh and persists the oauth_tokens anchor row
	// with family_id = the refresh JWT's fam claim (previous_token_hash NULL —
	// hop one of the rotation chain inherits this family, see refresh.go).
	var res *token.IssueResult
	var err error
	if fenceTx := completion.Metadata.MintTx; fenceTx != nil {
		// Normalized SSO stores the refresh-family anchor in the SAME transaction
		// that holds identity_auth_mint_fence. Account disable therefore cannot
		// commit between the enabled-user recheck and token persistence.
		res, err = h.svc.IssueTx(ctx, fenceTx, in)
	} else {
		mintTx, beginErr := h.pool.Begin(ctx)
		if beginErr != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusServiceUnavailable,
				Detail: "identity mint fence unavailable",
			})
			return
		}
		defer mintTx.Rollback(ctx) //nolint:errcheck -- commit makes this a no-op.
		fenceErr := applyAuthenticationMintFence(
			ctx, mintTx, user.ID, completion.Metadata.IdentityFence,
		)
		if fenceErr != nil {
			if !reducererr.WriteClassified(w, r, fenceErr) {
				httputil.WriteProblem(w, r, &httputil.Problem{
					Status: http.StatusInternalServerError,
					Detail: "identity transition admission resolution failed",
				})
			}
			return
		}
		if credentialFence := completion.Metadata.CredentialFence; credentialFence != "" {
			if err := verifyCredentialFence(ctx, mintTx, user.ID, credentialFence); err != nil {
				httputil.WriteProblem(w, r, &httputil.Problem{
					Status: http.StatusUnauthorized,
					Detail: "Credentials changed during sign-in. Please authenticate again.",
				})
				return
			}
		}
		res, err = h.svc.IssueTx(ctx, mintTx, in)
		if err == nil {
			err = mintTx.Commit(ctx)
			if err != nil {
				err = fmt.Errorf("%w: commit refresh token anchor: %v", token.ErrIssueStore, err)
			}
		}
	}
	if err != nil {
		if errors.Is(err, token.ErrIssueStore) {
			slog.Error("failed to store refresh token", "user_id", user.ID, "error", err)
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "An internal error occurred. Please try again."})
			return
		}
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "token issue failed"})
		return
	}

	pwhash.LogAuthEvent(ctx, h.pool, pwhash.AuthEvent{
		UserID: &user.ID, Event: "login", Provider: "jwt", Email: user.Email,
		IPAddress: httputil.ClientIP(r),
	}, nil)

	// Record the successful sign-in to login_events (T7). Best-effort; never blocks issuance.
	// auth_method must be a value the login_events_auth_method_chk constraint accepts
	// (password|webauthn|totp|push|backup_code|saml|oidc|kerberos|app_password) — NOT
	// the raw RFC 8176 AMR code of the first factor (pwd/hwk/swk), which the constraint
	// rejects and which silently dropped the row for EVERY factored login.
	authMethod := authMethodFromFactors(factors)
	clientIPStr := httputil.ClientIP(r)
	threat.RecordSignIn(ctx, h.pool, threat.SignInRecord{
		UserID:     user.ID,
		Success:    true,
		Client:     "web",
		Protocol:   "http",
		AuthMethod: authMethod,
		SourceIP:   clientIPStr,
		Location:   h.geoIPLookup(clientIPStr),
	})

	// Populate the `sessions` row for this web login (web-session-revoke Tier 1,
	// TODOS.md) so it shows up in GET /user/sessions — before this, web logins
	// never appeared there (only OAuth/IMAP families did). id = the access
	// token's own jti, so the "current" flag in SessionsHandler.List and a
	// future Tier-2 per-sid revoke both key off the same value already on the
	// token. Self-validate the just-minted token to read its jti back (h.jwt is
	// the same provider that signed it, so this can't fail in practice) rather
	// than widen TokenService.IssueResult for one caller. Best-effort — a write
	// failure here must never block issuance, mirroring RecordSignIn above.
	if issuedClaims, verr := h.jwt.Validate(res.AccessToken); verr == nil {
		hash := sha256.Sum256([]byte(res.AccessToken))
		if _, err := h.pool.Exec(ctx,
			`INSERT INTO sessions (id, user_id, token_hash, expires_at, ip, user_agent, auth_method)
			 VALUES ($1, $2, $3, now() + make_interval(secs => $4), NULLIF($5,'')::inet, $6, $7)
			 ON CONFLICT (id) DO NOTHING`,
			issuedClaims.JTI, user.ID, hash[:], res.ExpiresIn, clientIPStr, r.UserAgent(), authMethod,
		); err != nil {
			slog.Warn("issueTokensWithFactors: sessions row insert failed (dropped)",
				"user_id", user.ID, "error", err)
		}
	} else {
		slog.Warn("issueTokensWithFactors: could not self-validate access token for sessions row",
			"user_id", user.ID, "error", verr)
	}

	// Set the HttpOnly access_token session cookie. The webmail SPA holds no
	// token (it sends cookies via credentials:'include'); both the authserver's
	// BearerAuthenticator and the gateway Chain accept this cookie. Must precede
	// the body write so the header lands. (The body still carries the tokens for
	// native/API clients that use Bearer.)
	//
	// CA-3a: persistent-session cookie per session_control.persistent_session.
	// "never" → session cookie (MaxAge=0); "always" → full TTL; "user_choice" →
	// honour StaySignedIn from the login request.
	if hasCA {
		h.setAccessCookiePersist(w, r, res.AccessToken, res.ExpiresIn, ca.PersistentSession, ca.StaySignedIn)
	} else {
		h.setAccessCookie(w, r, res.AccessToken, res.ExpiresIn)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  res.AccessToken,
		"refresh_token": res.RefreshToken,
		"expires_in":    res.ExpiresIn,
	})
}

// peerIP extracts the immediate socket peer's IP (RemoteAddr minus port) —
// the only trust anchor for forwarded headers: never anything inside the
// request itself.
func peerIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

// parseTrustedProxyCIDRs converts the configured allowlist
// (AuthHandlerConfig.TrustedProxyCIDRs) into networks for peer matching. Any
// malformed entry fails the WHOLE allowlist closed to loopback-only: config
// validation already refuses malformed lists at startup, so this is
// defense-in-depth for embedders that bypass config — trusting a network we
// failed to parse is never an option.
func parseTrustedProxyCIDRs(entries []string) []*net.IPNet {
	var out []*net.IPNet
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			slog.Warn("unparseable trusted-proxy CIDR — dropping the whole allowlist, proxy trust falls back to loopback-only",
				"entry", entry)
			return nil
		}
		out = append(out, ipNet)
	}
	return out
}

// isTrustedProxyPeer reports whether the immediate peer (RemoteAddr) may be
// trusted for forwarded-header purposes — the trust boundary that lets
// forwardedHTTPS honor X-Forwarded-Proto with NO operator configuration in
// the standard single-node deploy (the gateway terminates TLS at :443 and
// proxies to authserver over 127.0.0.1 plain HTTP, so authserver's own
// r.TLS is nil even though the browser connection was TLS).
//
// AUTHSERVERD-005 finding 3, explicit-config posture: LOOPBACK peers are
// always trusted (the default same-host proxy hop needs no config); any OTHER
// peer is trusted only when the operator allowlisted its network via
// auth.trusted_proxy_cidrs — a private-range peer is NO longer implicitly
// trusted, because every RFC 1918/4193 neighbor (container bridges, Wi-Fi
// clients, compromised LAN hosts) could otherwise forge the header. The
// blanket AUTH_TRUST_PROXY (h.trustProxy) still trusts all peers for
// topologies no allowlist expresses.
func (h *deps) isTrustedProxyPeer(r *http.Request) bool {
	ip := peerIP(r)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, ipNet := range h.trustedProxyCIDRs {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// forwardedHTTPS reports whether the request should be treated as arriving
// over TLS based on X-Forwarded-Proto, gated behind a trust-proxy conviction
// (wave-7: authserver previously keyed cookie Secure off its OWN r.TLS,
// which is always nil behind a TLS-terminating gateway proxying over plain
// HTTP — session cookies shipped without Secure on the standard single-node
// deploy). The header is honored only when the immediate peer is loopback or
// explicitly allowlisted (isTrustedProxyPeer) OR the operator set the
// blanket AUTH_TRUST_PROXY (h.trustProxy) — never for an arbitrary peer.
func (h *deps) forwardedHTTPS(r *http.Request) bool {
	if !h.trustProxy && !h.isTrustedProxyPeer(r) {
		return false
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// setAccessCookie sets the HttpOnly access_token cookie the SPA reads for its
// online session. Secure is on when cookieSecure is configured, the request
// arrived over TLS directly, or a trusted proxy forwarded it as TLS
// (forwardedHTTPS) — so dev-HTTP stays usable while prod (direct TLS or
// gateway-terminated TLS) is always Secure.
// ponytail: this is the §15 ONLINE-SESSION cookie — NOT the offline-cache key
// (the cache key is an SQLCipher key provisioned by guard-core on-device, never on the wire).
func (h *deps) setAccessCookie(w http.ResponseWriter, r *http.Request, access string, expiresSecs int64) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    access,
		Path:     "/",
		MaxAge:   int(expiresSecs),
		HttpOnly: true,
		Secure:   h.cookieSecure || r.TLS != nil || h.forwardedHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

// setAccessCookiePersist is setAccessCookie with persistent-session logic (CA-3a T11).
// persist controls Max-Age: "never" → session cookie (MaxAge=0); "always" → full
// TTL; "user_choice" → honour staySignedIn (true=full TTL, false=session cookie).
// ponytail: three cases, no state; MaxAge=0 means browser discards on close.
func (h *deps) setAccessCookiePersist(w http.ResponseWriter, r *http.Request, access string, expiresSecs int64, persist string, staySignedIn bool) {
	maxAge := int(expiresSecs) // default: full TTL ("always")
	switch persist {
	case "never":
		maxAge = 0
	case "user_choice":
		if !staySignedIn {
			maxAge = 0
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    access,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.cookieSecure || r.TLS != nil || h.forwardedHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

// deferredTokenResponse buffers every header and body byte produced by the
// issuance adapter. Normalized SSO uses it while its refresh-family anchor is
// still tentative, then publishes the response only after the caller-owned
// mint-fence transaction commits.
type deferredTokenResponse struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newDeferredTokenResponse() *deferredTokenResponse {
	return &deferredTokenResponse{header: make(http.Header)}
}

func (d *deferredTokenResponse) Header() http.Header { return d.header }

func (d *deferredTokenResponse) WriteHeader(status int) {
	if d.status == 0 {
		d.status = status
	}
}

func (d *deferredTokenResponse) Write(p []byte) (int, error) {
	if d.status == 0 {
		d.status = http.StatusOK
	}
	return d.body.Write(p)
}

func (d *deferredTokenResponse) successful() bool {
	return d.status >= http.StatusOK && d.status < http.StatusMultipleChoices
}

func (d *deferredTokenResponse) flushTo(w http.ResponseWriter) {
	for key, values := range d.header {
		w.Header()[key] = append([]string(nil), values...)
	}
	if d.status != 0 {
		w.WriteHeader(d.status)
	}
	if d.body.Len() != 0 {
		_, _ = w.Write(d.body.Bytes())
	}
}

// commitDeferredTokenResponse publishes a successful buffered issuance only
// after commit. Error responses are safe to publish without committing because
// they contain no token material. A commit failure leaves dst completely
// untouched so the caller can emit a clean 5xx.
func commitDeferredTokenResponse(
	ctx context.Context,
	dst http.ResponseWriter,
	pending *deferredTokenResponse,
	commit func(context.Context) error,
) (bool, error) {
	if !pending.successful() {
		pending.flushTo(dst)
		return false, nil
	}
	if err := commit(ctx); err != nil {
		return false, err
	}
	pending.flushTo(dst)
	return true, nil
}

// settleSSOMappingsThenIssue is the SSO token-issuance seam. Every governed
// mapping, exact-provider provenance row, and normalized entitlement row settles
// in one worker transaction. Any validation, SoD, FK, reconciliation, or commit
// failure blocks the login; a session is never minted from partially-settled
// access. The mapping transaction commits before the final normalized mint
// fence, so it cannot self-block trying to update a users row held by a second
// transaction. After CA succeeds, normalized logins recheck and hold the exact
// source+link generations until the refresh-family anchor commits. Concurrent
// detach/retire therefore either wins first and rejects this mint, or waits and
// then revokes the newly committed token family.
func (h *deps) settleSSOMappingsThenIssue(w http.ResponseWriter, r *http.Request, user *userRow, assertedEmail string, groups []string, mapper federation.GroupMappingProvider, authMethod string) {
	ctx := r.Context()
	mappingTx, err := h.workerPool.Begin(ctx)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusServiceUnavailable,
			Detail: "SSO entitlement transaction unavailable",
		})
		return
	}
	defer mappingTx.Rollback(ctx) //nolint:errcheck -- commit makes this a no-op.
	if assertedEmail != "" {
		if err := h.updateSSOEmailTx(ctx, mappingTx, user.ID, assertedEmail); err != nil {
			h.logger.Warn("SSO email update failed closed",
				"user_id", user.ID, "error", err)
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusConflict,
				Detail: "SSO profile reconciliation failed",
			})
			return
		}
	}
	if err := h.applyGroupMappingsAtomic(
		ctx, mappingTx, user.ID, groups, mapper,
	); err != nil {
		h.logger.Warn("SSO group reconciliation failed closed",
			"user_id", user.ID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusConflict,
			Detail: "SSO entitlement reconciliation failed",
		})
		return
	}
	if mapper != nil && h.toggles != nil &&
		h.toggles.IsEnabled(toggle.FeatureIdentityModelV2) {
		if err := h.reconcileSSOEntitlementsAtomic(
			ctx, mappingTx, user.ID, mapper.SSOProviderKey(),
		); err != nil {
			h.logger.Warn("normalized SSO entitlement reconciliation failed closed",
				"user_id", user.ID, "error", err)
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusConflict,
				Detail: "normalized SSO entitlement reconciliation failed",
			})
			return
		}
	}
	if err := mappingTx.Commit(ctx); err != nil {
		h.logger.Warn("SSO entitlement transaction commit failed",
			"user_id", user.ID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusServiceUnavailable,
			Detail: "SSO entitlement commit failed",
		})
		return
	}
	if refreshed, err := h.lookupUser(ctx, "id", user.ID); err == nil {
		user.IsAdmin = refreshed.IsAdmin
		user.Email = refreshed.Email
	} else {
		h.logger.Warn("is_admin re-derive after SSO group mapping failed closed",
			"user_id", user.ID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusServiceUnavailable,
			Detail: "SSO authorization state unavailable",
		})
		return
	}
	completion := CompletionRequest{
		Factors: []string{token.AMRPassword},
		Metadata: CompletionMetadata{
			ConditionalAccess: CompletionConditionalAccess{Evaluated: true},
		},
	}
	if user.IdentitySourceID > 0 {
		completion.Metadata.IdentityFence = &jwtutil.IdentityFenceClaim{
			SourceID:         user.IdentitySourceID,
			SourceGeneration: user.IdentitySourceGeneration,
			LinkID:           user.IdentityLinkID,
			LinkGeneration:   user.IdentityLinkGeneration,
		}
	}
	// Conditional access: a federated login MUST clear CA (block / step-up / geo /
	// device) before a session is minted — the same gate the password Login path
	// runs. Without this, SAML/OIDC logins bypassed CA entirely (the primary
	// enterprise login path). Eval runs after the mappings settle so group-scoped
	// policies see THIS login's freshly-provisioned SSO groups. When it writes a
	// terminal block/step-up response it returns true and we must not mint a session.
	if h.evaluateSSOConditionalAccess(w, r, user, authMethod, completion) {
		return
	}

	if user.IdentitySourceID > 0 {
		fenceTx, err := h.workerPool.Begin(ctx)
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusServiceUnavailable,
				Detail: "identity mint fence unavailable",
			})
			return
		}
		defer fenceTx.Rollback(ctx) //nolint:errcheck -- commit makes this a no-op.
		if _, err := fenceTx.Exec(ctx,
			`SELECT identity_auth_mint_fence($1,$2,$3,$4,$5)`,
			user.ID,
			user.IdentitySourceID,
			user.IdentitySourceGeneration,
			user.IdentityLinkID,
			user.IdentityLinkGeneration,
		); err != nil {
			if !reducererr.WriteClassified(w, r, err) {
				httputil.WriteProblem(w, r, &httputil.Problem{
					Status: http.StatusConflict,
					Detail: "federated identity changed before SSO settlement",
				})
			}
			return
		}
		completion.Metadata.MintTx = fenceTx
		pending := newDeferredTokenResponse()
		h.issueTokens(pending, r, user, completion)
		if _, err := commitDeferredTokenResponse(ctx, w, pending, fenceTx.Commit); err != nil {
			h.logger.Error("identity mint fence commit failed before token response",
				"user_id", user.ID, "error", err)
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusServiceUnavailable,
				Detail: "identity token commit failed",
			})
		}
		return
	}
	h.issueTokens(w, r, user, completion)
}

// populateGuestCAScope resolves the Guest G5 Conditional Access set from the
// FORCE-RLS-safe satellite helper. A lookup error is an enforcement-input
// failure, never an ordinary-member answer, so login fails closed.
func (h *deps) populateGuestCAScope(w http.ResponseWriter, r *http.Request, pectx *threat.PolicyEvalContext, userID int64) bool {
	if h.guestScopeResolver == nil {
		return true // hermetic unit seams; production always wires the auth DB pool
	}
	isGuest, err := h.guestScopeResolver(r.Context(), userID)
	if err != nil {
		logger := h.logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("conditional access: guest scope lookup failed", "user_id", userID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusServiceUnavailable,
			Detail: "conditional access context unavailable",
		})
		return false
	}
	pectx.IsGuest = isGuest
	return true
}

// evaluateSSOConditionalAccess runs conditional-access policy evaluation for a
// federated (SAML SP / OIDC RP) login before token issuance, mirroring the password
// Login gate (evaluateAndRespond). Returns true when a terminal response — a
// DecisionBlock 403 or a DecisionStepUp MFA-pending body — has already been written
// and issuance MUST stop. authMethod is "saml" or "oidc" so auth-method-scoped
// policies match. No-op (returns false) when no policy engine is wired.
func (h *deps) evaluateSSOConditionalAccess(w http.ResponseWriter, r *http.Request, user *userRow, authMethod string, completion CompletionRequest) (stop bool) {
	if h.policyEngine == nil {
		return false
	}
	clientIP := httputil.ClientIP(r)
	userAgent := r.UserAgent()
	pectx := threat.PolicyEvalContext{
		UserID:      user.ID,
		GroupIDs:    h.fetchUserGroups(r.Context(), user.ID),
		SourceIP:    clientIP,
		Country:     h.geoIPCountryCode(clientIP), // "" degrades to geo tier "low"
		DeviceFP:    threat.MakeDeviceFP(userAgent, clientIP),
		AuthMethod:  authMethod,
		ClientType:  threat.ClientTypeWeb,
		Protocol:    threat.ProtocolHTTP,
		UserAgent:   userAgent,
		RequestTime: time.Now(),
	}
	if !h.populateGuestCAScope(w, r, &pectx, user.ID) {
		return true
	}
	// Stamp device-bound credential signals when a resolver is wired (CA-2).
	// Fail-closed: an absent resolver leaves DeviceBound=false so a device_bound
	// policy blocks an unprovable SSO request rather than letting it through.
	if h.deviceResolver != nil {
		b, id, st := h.deviceResolver.Resolve(r.Context(), r, user.ID)
		pectx.DeviceBound, pectx.DeviceID, pectx.EnrollState = b, id, st
	}
	blocked, _ := h.evaluateAndRespond(w, r, pectx, user.ID, user.Email, completion)
	return blocked
}

// evaluateCompletionConditionalAccess runs CA policy evaluation for a factor-
// completion issuance (TOTP/backup-code/push/WebAuthn/device-approve) — the leg
// that previously minted a session with no login-time CA decision and no
// ca_signin_log row (G4). It mirrors evaluateSSOConditionalAccess's pectx
// construction (clientIP, UA, groups, geo, device-bound resolver) but derives
// AuthMethod from the COMPLETED factor so an auth-method-scoped policy matches the
// method actually used this leg (decision 1). No-op (returns false) when no policy
// engine is wired.
//
// CompletionMetadata.ConditionalAccess.StepUpInProgress splits two cases
// (decision 2 — the step-up deadlock):
//   - false (fresh passwordless/device login, no prior CA leg): honor block/step-up
//     terminal responses via evaluateAndRespond exactly like password/SSO. This is
//     the real bypass being closed — these paths had zero CA before.
//   - true  (step-up-in-progress: completing a server-issued mfa_token): evaluate
//     for the AUDIT row, never re-challenge (a re-issued step-up here would strand
//     a user mid-completion of the exact factor the server demanded), and keep
//     remediable blocks riding the runtime gate — but a FRESH HARD BLOCK (block
//     decision with no remediation hint) is terminal, exactly as it is at password
//     login. A hard block names no remediation the user can perform; the policy
//     intent is denial, and the completion leg is the last acceptance gate before
//     tokens are minted — issuing first and deferring to RequireRuntimeAccess
//     would mint a full session the policy just refused (and with feature.cae_runtime
//     off there is no runtime gate to defer to at all).
//
// Returns (stop, matchedPolicyID). policyID feeds the CA-3a session-control read
// (sign-in-frequency embedding) for the session this completion is about to mint.
func (h *deps) evaluateCompletionConditionalAccess(w http.ResponseWriter, r *http.Request, user *userRow, completion CompletionRequest) (stop bool, policyID int64) {
	if h.policyEngine == nil {
		return false, 0
	}
	clientIP := httputil.ClientIP(r)
	userAgent := r.UserAgent()
	pectx := threat.PolicyEvalContext{
		UserID:      user.ID,
		GroupIDs:    h.fetchUserGroups(r.Context(), user.ID),
		SourceIP:    clientIP,
		Country:     h.geoIPCountryCode(clientIP), // "" degrades to geo tier "low"
		DeviceFP:    threat.MakeDeviceFP(userAgent, clientIP),
		AuthMethod:  authMethodFromCompletedFactors(completion.Factors),
		ClientType:  threat.ClientTypeWeb,
		Protocol:    threat.ProtocolHTTP,
		UserAgent:   userAgent,
		RequestTime: time.Now(),
	}
	if !h.populateGuestCAScope(w, r, &pectx, user.ID) {
		return true, 0
	}
	if h.deviceResolver != nil {
		b, id, st := h.deviceResolver.Resolve(r.Context(), r, user.ID)
		pectx.DeviceBound, pectx.DeviceID, pectx.EnrollState = b, id, st
	}
	if !completion.Metadata.ConditionalAccess.StepUpInProgress {
		return h.evaluateAndRespond(w, r, pectx, user.ID, user.Email, completion)
	}
	// Step-up-in-progress: audit, plus terminal only for a fresh HARD block.
	res := h.policyEngine.Evaluate(r.Context(), pectx)
	h.signInRecorder.Record(r.Context(), pectx, res)
	if res.Decision == threat.DecisionBlock && res.Remediation == "" {
		if res.CorrelationID != "" {
			w.Header().Set("X-CA-Correlation-Id", res.CorrelationID)
		}
		h.logger.Warn("conditional access hard-blocked MFA completion",
			"user_id", user.ID, "policy_id", res.PolicyID,
			"reason", res.Reason, "correlation_id", res.CorrelationID,
		)
		detail := res.Reason
		if res.CorrelationID != "" {
			detail = res.Reason + " (reference " + res.CorrelationID + ")"
		}
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status:           http.StatusForbidden,
			Detail:           detail,
			Remediation:      res.Remediation,
			RemediationTouID: res.RemediationTermsID,
		})
		return true, res.PolicyID
	}
	return false, res.PolicyID
}

// resolveLoginDeviceClaim builds the device-trust claim embedded in the access
// token at login (P1). It is gated TOGGLE-OFF by default: unless deviceTrust is
// wired AND feature.device_trust_enforcement is explicitly enabled, it returns
// nil so issued tokens are byte-for-byte unchanged (no Device claim).
//
// When on, it derives the same device_hash the resolver/middleware use
// (sha256-hex of MakeDeviceFP(userAgent, clientIP)) and looks up managed_devices
// for THIS user, mapping compliance_status -> trust tier. The lookup FAILS OPEN
// (any DB error -> nil), and an unenrolled device (no row) -> nil, so the gate's
// nil-Device pass-through lets legacy/unenrolled devices ride free. Never blocks
// login; never embeds a quarantine on a lookup error.
func (h *deps) resolveLoginDeviceClaim(r *http.Request, userID int64) *jwtutil.DeviceClaim {
	if h.deviceTrust == nil || h.toggles == nil {
		return nil
	}
	// DEFAULT OFF — an unseeded/unknown toggle key must NOT enable enforcement
	// (the toggle registry pins this key's absent-row default to false).
	if !h.toggles.IsEnabled(toggle.FeatureDeviceTrustEnforcement) {
		return nil
	}
	deviceFP := threat.MakeDeviceFP(r.UserAgent(), httputil.ClientIP(r))
	return h.deviceTrust.ResolveDeviceClaim(r.Context(), deviceFP, userID)
}

// riskClaimFor reads the user's local risk row and maps it to the JWT Risk claim.
// Gated on feature.user_risk; returns nil when off (or toggles nil), on a clean
// user (none/empty), or on a read error — fail-open: a scorer hiccup must not block login.
func (h *deps) riskClaimFor(ctx context.Context, userID int64) *jwtutil.RiskClaim {
	if h.toggles == nil || !h.toggles.IsEnabled(toggle.FeatureUserRisk) {
		return nil
	}
	var score int
	var level string
	var signalsJSON []byte
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT score, level, signals FROM user_risk WHERE user_id = $1`, userID,
		).Scan(&score, &level, &signalsJSON)
	})
	if err != nil {
		return nil // no row or DB error: fail-open (clean user or transient)
	}
	var signals []string
	json.Unmarshal(signalsJSON, &signals) //nolint:errcheck // nil signals is fine
	return threat.RiskFromRow(score, level, signals)
}

// sodModeOn reports whether 等保三级 SoD mode is enabled, read the same way
// device-trust enforcement is read: via the injected FeatureFlags. DEFAULT OFF —
// a nil toggle source or an absent/unseeded key reads false (the toggle
// registry default), so the SSO admin-role freeze is never engaged by accident.
func (h *deps) sodModeOn() bool {
	if h.toggles == nil {
		return false
	}
	return h.toggles.IsEnabled(toggle.FeatureDengbaoSodMode)
}

// fetchUserGroups returns the group IDs a user belongs to for conditional access evaluation.
// Delegates to the shared resolver so the HTTP login path and the IMAP/SMTP post-auth
// pass can never drift apart.
func (h *deps) fetchUserGroups(ctx context.Context, userID int64) []int64 {
	return threat.ResolveUserGroups(ctx, h.pool, userID)
}

// factorsFromMFAPending returns the authentication factors a completed MFA
// session satisfied: the factor(s) recorded in the MFA-pending token (the first
// factor — password, or a passkey when WebAuthn routed into a second factor)
// plus the second factor just verified. The result feeds issueTokensWithFactors
// so the access token's acr/amr reflect every method actually performed.
func factorsFromMFAPending(mfaClaims *token.Claims, secondFactors ...string) []string {
	factors := make([]string, 0, len(mfaClaims.AMR)+len(secondFactors)+1)
	factors = append(factors, mfaClaims.AMR...)
	for _, f := range secondFactors {
		if f != "" {
			factors = append(factors, f)
		}
	}
	// A legacy MFA-pending token (issued before acr/amr) carries no AMR; assume
	// the password first factor so the result is still a true MFA (aal2) session.
	if len(mfaClaims.AMR) == 0 {
		factors = append(factors, token.AMRPassword)
	}
	return factors
}

// issueTokensFromMFAPending restores the exact normalized federated fence, if
// present, before entering the single issuance funnel. Local and legacy
// challenges have no fence claim and keep the local-mint behavior.
func (h *deps) issueTokensFromMFAPending(
	w http.ResponseWriter,
	r *http.Request,
	user *userRow,
	claims *token.Claims,
	metadata CompletionMetadata,
	secondFactors ...string,
) {
	metadata.IdentityFence = claims.IdentityFence
	metadata.CredentialFence = claims.CredentialFence
	h.issueTokensWithFactors(
		w, r, user, CompletionRequest{
			Factors:  factorsFromMFAPending(claims, secondFactors...),
			Metadata: metadata,
		},
	)
}

// authMethodFromFactors maps the FIRST authentication factor (an RFC 8176 AMR
// code) to the login_events.auth_method vocabulary the check constraint enforces.
// The raw AMR codes (pwd/hwk/swk/otp) are NOT valid auth_method values, so writing
// them verbatim made RecordSignIn's INSERT violate login_events_auth_method_chk and
// the row was silently dropped (best-effort) — losing the sign-in record for every
// password/passkey/push/TOTP login. Unknown/empty falls back to "password" (a valid
// constraint value) so a future factor degrades to a recorded row, not a dropped one.
func authMethodFromFactors(factors []string) string {
	if len(factors) == 0 {
		return "password"
	}
	switch factors[0] {
	case token.AMRHardwareKey:
		return "webauthn"
	case token.AMRSoftwareKey:
		return "push"
	case token.AMROTP:
		return "totp"
	case token.AMRPassword:
		return "password"
	default:
		return "password"
	}
}

// authMethodFromCompletedFactors maps the AMR codes a factor-completion leg
// satisfied to the PolicyEvalContext.AuthMethod vocabulary
// (password|webauthn|totp|push), so an auth-method-scoped CA policy matches the
// factor the user actually COMPLETED this leg — not the password first factor that
// authMethodFromFactors (factors[0]) would report. Scans left→right so the last-
// appended second factor wins over the first (e.g. [hwk, otp] passkey-then-TOTP →
// "totp"). RFC 8176 collapse: backup_code and device-approve are indistinguishable
// from totp/push by AMR alone (identical otp / swk+user codes) — a per-method split
// would require each handler to pass an explicit method string (the 5-callsite
// shape the single gate deliberately avoids). Unknown/empty → "password".
func authMethodFromCompletedFactors(factors []string) string {
	method := "password"
	for _, f := range factors {
		switch f {
		case token.AMROTP:
			method = "totp"
		case token.AMRSoftwareKey, token.AMRUserPresence:
			method = "push"
		case token.AMRHardwareKey:
			if method == "password" { // hwk as sole/first factor = passwordless webauthn
				method = "webauthn"
			}
		}
	}
	return method
}

func tokenClaims(r *http.Request) *token.Claims {
	claims, ok := r.Context().Value(ctxKeyUser).(*token.Claims)
	if !ok {
		return nil
	}
	return claims
}

// geoIPCountryCode resolves an IP to its ISO 3166-1 alpha-2 country code (e.g.
// "US") using the GeoLite2 database. Returns "" when the DB is unavailable, the
// IP is unparseable, or the lookup fails — so threading it into
// PolicyEvalContext.Country degrades safely (an empty Country resolves the geo
// tier to "low", the prior behavior). The ISO code (not the display name) is the
// key geo_country_tiers / ResolveGeoTier expect.
func (h *deps) geoIPCountryCode(ip string) string {
	if h.geoipDB == nil {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	record, err := h.geoipDB.City(parsed)
	if err != nil {
		return ""
	}
	return record.Country.IsoCode
}

// geoIPLookup resolves an IP to "city, country" using the GeoLite2 database.
func (h *deps) geoIPLookup(ip string) string {
	if h.geoipDB == nil {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	record, err := h.geoipDB.City(parsed)
	if err != nil {
		return ""
	}
	city := record.City.Names["en"]
	country := record.Country.Names["en"]
	if city == "" {
		return country
	}
	return city + ", " + country
}

// -- Cookie encryption --

func (h *deps) encryptCookieValue(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(h.cookieKey)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func (h *deps) decryptCookieValue(encoded string) ([]byte, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(h.cookieKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

func (h *deps) clearAuthCookie(w http.ResponseWriter, r *http.Request, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: path,
		MaxAge: -1, HttpOnly: true, Secure: h.cookieSecure || r.TLS != nil || h.forwardedHTTPS(r), SameSite: http.SameSiteStrictMode,
	})
}

// isAdminExprSQL is the canonical JWT-mint is_admin derivation: TRUE iff the user
// holds an UNEXPIRED governed admin_role_assignments row. It replaces every raw
// `users.is_admin` read in a mint path (BUG 003 / RBAC cut-over). The vestigial
// users.is_admin column is no longer authoritative — neither AssignMember nor SSO
// sets it, so reading it minted IsAdmin=false for freshly-granted admins, which the
// gateway (chain.go) then denied on every admin route. The EXISTS + expires_at
// filter is byte-aligned with session.go (Me) and shared/permissions.Resolve, so
// the MINTED claim agrees with the ENFORCED scope. Selectable as a bare column
// expression in single-table SELECTs over `users` (the correlation references
// `users.id` EXPLICITLY — an unqualified `id` would bind to the subquery's own
// admin_role_assignments.id, making the predicate `ara.user_id = ara.id`, ~always
// false; that was the original RED in the derivation tests).
// ponytail: intentionally counts eligible rows (JIT decision 9) — a dormant-eligible
// admin keeps is_admin=true so their session runs permissions.Resolve, which mints
// nothing until they call admin_role_activate. Do NOT add the admin_assignment_active
// JIT gate here; that gate lives in admin_effective_authority (the reducer), not here.
const isAdminExprSQL = `EXISTS(
	SELECT 1 FROM admin_role_assignments ara
	 WHERE ara.user_id = users.id
	   AND (ara.expires_at IS NULL OR ara.expires_at > now())
)`

// isAdminExprSQLAlias is the same derivation keyed on a `u`-aliased user row, for
// SELECTs that qualify columns (resolveUserByAddress joins aliases).
const isAdminExprSQLAlias = `EXISTS(
	SELECT 1 FROM admin_role_assignments ara
	 WHERE ara.user_id = u.id
	   AND (ara.expires_at IS NULL OR ara.expires_at > now())
)`

// lookupUser finds a user by the given field ("id", "email").
func (h *deps) lookupUser(ctx context.Context, field string, value any) (*userRow, error) {
	var user userRow
	var query string
	switch field {
	case "id":
		query = `SELECT id, email, ` + isAdminExprSQL + ` FROM users WHERE id = $1 AND enabled = TRUE`
	case "email":
		query = `SELECT id, email, ` + isAdminExprSQL + ` FROM users WHERE lower(email) = lower($1) AND enabled = TRUE`
	default:
		return nil, fmt.Errorf("unknown lookup field: %s", field)
	}
	err := h.pool.QueryRow(ctx, query, value).Scan(&user.ID, &user.Email, &user.IsAdmin)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// resolveUserByAddress is the SP-mode consumer of the resolve_identity seam
// (ADR-004): it resolves an existing person by ANY of their addresses —
// `users.email` ∪ `aliases.email` ∪ `users.ad_upn`, case-insensitive — using the
// single shared connector.ResolveIdentitySQL rule (the same matching key the
// local/AD connectors use), so the SP flow cannot drift back to primary-only
// matching. An inbound SAML/OIDC assertion subject that is a UPN or a
// sister-domain alias therefore resolves to the existing user instead of
// JIT-provisioning a duplicate. Returns the canonical userRow (with admin fields,
// which connector.Identity lacks) so the SP flow can issue a fully-scoped token.
func (h *deps) resolveUserByAddress(ctx context.Context, address string) (*userRow, error) {
	// Canonicalize the inbound assertion subject through the SAME seam the
	// provision path (normalizeAndValidateSSOEmail → identity.NormalizeAndValidate)
	// uses, so the match key equals the provision key by construction. A NameID /
	// claim carrying surrounding whitespace or an RFC-5322 display-name form
	// (`"Alice" <a@x>`) now resolves the existing person instead of match-missing
	// and JIT-duplicating them (ARCH-004 normalization axis). The predicate
	// (ResolveIdentitySQL) is unchanged — only its INPUT is normalized.
	var user userRow
	err := h.pool.QueryRow(ctx,
		`SELECT u.id, u.email, `+isAdminExprSQLAlias+
			connector.ResolveIdentitySQL, identity.CanonicalizeAddress(address).String(),
	).Scan(&user.ID, &user.Email, &user.IsAdmin)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// lookupUserByOIDC finds a user by their OIDC stable identity (sub + iss).
func (h *deps) lookupUserByOIDC(ctx context.Context, sub, iss string) (*userRow, error) {
	var user userRow
	err := h.pool.QueryRow(ctx,
		`SELECT id, email, `+isAdminExprSQL+` FROM users
		 WHERE oidc_subject = $1 AND oidc_issuer = $2 AND enabled = TRUE`,
		sub, iss,
	).Scan(&user.ID, &user.Email, &user.IsAdmin)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// lookupUserBySAML finds a user by their SAML stable identity (name_id + idp_entity_id).
func (h *deps) lookupUserBySAML(ctx context.Context, nameID, idpEntityID string) (*userRow, error) {
	var user userRow
	err := h.pool.QueryRow(ctx,
		`SELECT id, email, `+isAdminExprSQL+` FROM users
		 WHERE saml_name_id = $1 AND saml_idp_entity_id = $2 AND enabled = TRUE`,
		nameID, idpEntityID,
	).Scan(&user.ID, &user.Email, &user.IsAdmin)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// normalizeAndValidateSSOEmail is the single validated-SSO-identity seam. Every
// path that writes an IdP-provided email into users.email (JIT create AND the
// returning-user updateSSOEmail) MUST route through it, so the validation can
// never be missed at one site again.
//
// It is a thin wrapper over identity.NormalizeAndValidate (shared/identity) —
// the PROVISIONING half of the one canonicalizer seam. The matching half
// (identity.CanonicalizeAddress, called by resolveUserByAddress and the
// local/AD connectors) computes the SAME canonical form by construction, so a
// federated assertion subject that resolves an existing person is byte-identical
// to the value this would write — closing the duplicate-JIT-on-normalization
// bug (ARCH-004 normalization axis). The email originates from an untrusted IdP
// attribute (SAML NameID / OIDC sub / email claim): it is trim + ASCII-fold
// lower + RFC-5322 display-name stripped, then validated (well-formed, <=254
// chars, no control chars / header-injection, domain has a dot). An invalid
// address is rejected and the caller must NOT persist it.
func normalizeAndValidateSSOEmail(email string) (string, error) {
	// .String() exits the CanonicalAddress newtype: this SSO path already routed
	// through the one canonicalizer (NormalizeAndValidate) in wave 1, so the
	// returned value IS canonical. The AD/LDAP/admin writers (this wave) keep the
	// value typed all the way to the bind; the SSO JIT body downstream does
	// string surgery (SplitN on "@", username derivation), so it consumes the
	// canonical string form here.
	canon, err := identity.NormalizeAndValidate(email)
	return canon.String(), err
}

// updateSSOEmail updates email when the IdP reports a different one. The IdP
// value is untrusted, so it is normalized + validated through the shared seam
// before the UPDATE; an invalid address is rejected (no write) and an error is
// returned for the caller to log.
func (h *deps) updateSSOEmail(ctx context.Context, userID int64, email string) error {
	normalized, err := normalizeAndValidateSSOEmail(email)
	if err != nil {
		return err
	}
	_, err = h.pool.Exec(ctx,
		`UPDATE users SET email = $2 WHERE id = $1 AND lower(email) != lower($2)`,
		userID, normalized)
	return err
}

func (h *deps) updateSSOEmailTx(
	ctx context.Context,
	tx pgx.Tx,
	userID int64,
	email string,
) error {
	normalized, err := normalizeAndValidateSSOEmail(email)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`UPDATE users SET email=$2,updated_at=statement_timestamp()
		  WHERE id=$1 AND lower(email)<>lower($2)`,
		userID, normalized)
	return err
}

func (h *deps) bindSSOProvider(ctx context.Context, keys identityKeys, mapper federation.GroupMappingProvider) error {
	if mapper == nil {
		return nil
	}
	providerKey := mapper.SSOProviderKey()
	var kind, provider string
	if keys.hasOIDC() {
		kind, provider = "oidc", keys.oidcIss
	} else if keys.hasSAML() {
		kind, provider = "saml", keys.samlIDP
	} else {
		return nil
	}
	if _, err := h.workerPool.Exec(ctx,
		`SELECT identity_source_provider_bind($1,$2,$3)`,
		kind, provider, providerKey); err != nil {
		h.logger.Warn("normalized identity provider binding failed",
			"provider_key", providerKey, "error", err)
		return err
	}
	return nil
}

// adminRoleToGroupID maps the role labels an admin may configure on an IdP
// group->role mapping (the SSO-config axis, NOT the dropped users.admin_role
// column) to their corresponding builtin admin_role_groups.id values (seeded by
// V010). Unknown / empty labels map to 0 (no insert) — a structural ceiling: an
// SSO group can only confer one of these four governed builtin roles.
var adminRoleToGroupID = map[string]int64{
	"super_admin": 1,
	"user_admin":  2,
	"auditor":     4,
	"read_only":   8,
}

// upsertSSOAdminAssignment inserts a governed admin_role_assignment row for a
// user (NULL granted_by = system/SSO-provisioned).  Each call is a single
// autocommit statement on the pool — no enclosing transaction exists, so no
// savepoint is needed; a failed INSERT affects nothing else by construction.
//
// Callers MUST establish the grant authority first (ssoMintAuthorityCovers +
// the super_admin operator knob): this function itself performs no Rule A
// validation, it only persists an already-authorized mint.
//
// Returns an error when the INSERT fails.  ERRCODE BZ001 means the
// trg_sod_exclusion trigger rejected the assignment because it would violate
// 等保三级 Separation-of-Duties partitioning (e.g. assigning both a 系统管理员
// and an 审计管理员 role to the same user).  Any other error is a plain DB
// failure.  The caller is expected to log and continue the loop.
func (h *deps) upsertSSOAdminAssignment(ctx context.Context, userID, groupID int64, providerKey string) error {
	_, err := h.pool.Exec(ctx,
		`WITH inserted AS (
		     INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		     VALUES ($1, $2, NULL)
		     ON CONFLICT (user_id, role_group_id) DO NOTHING
		     RETURNING id
		 ),
		 effective AS (
		     SELECT id FROM inserted
		     UNION ALL
		     SELECT id
		       FROM admin_role_assignments
		      WHERE user_id = $1 AND role_group_id = $2
		     LIMIT 1
		 )
		 INSERT INTO sso_admin_role_provenance (provider_key, assignment_id)
		 SELECT $3, id FROM effective
		 ON CONFLICT DO NOTHING`,
		userID, groupID, providerKey,
	)
	return err
}

// ssoMintAuthorityCovers reports whether the operator grant-authority record
// for roleLabel (system_config key 'sso_admin_role_grant_authority') still
// authorizes minting groupID's CURRENT permission set — Rule A
// (grant-only-what-you-hold) evaluated at mint time (F-004, Astra waves34
// HOLD 2: login-time assignment was previously unguarded). The record is
// seeded for the four governed builtin labels by V244 (so mappings that
// predate the fence keep minting) and refreshed by the mailserver console's
// roles.manage-fenced mapping write (admin_identity.go UpdateGroupMappings),
// whose author must hold every permission the role grants. FALSE — record
// absent, or the role group's live permissions widened beyond the recorded
// authorized_perms ceiling — refuses the mint (authority loss).
func (h *deps) ssoMintAuthorityCovers(ctx context.Context, roleLabel string, groupID int64) (bool, error) {
	var covered bool
	err := h.pool.QueryRow(ctx,
		`SELECT COALESCE(sc.value -> $2 -> 'authorized_perms', '[]'::jsonb)
		        @> to_jsonb(rg.permissions)
		   FROM admin_role_groups rg
		   LEFT JOIN system_config sc
		      ON sc.key = 'sso_admin_role_grant_authority'
		  WHERE rg.id = $1`,
		groupID, roleLabel,
	).Scan(&covered)
	return covered, err
}

func (h *deps) upsertSSODistributionMembership(
	ctx context.Context,
	groupID, mailboxID int64,
	providerKey string,
) error {
	_, err := h.pool.Exec(ctx,
		`WITH effective AS (
		     INSERT INTO distribution_group_members (group_id, mailbox_id, source)
		     VALUES ($1, $2, 'sso')
		     ON CONFLICT DO NOTHING
		 )
		 INSERT INTO sso_distribution_group_provenance (provider_key, group_id, mailbox_id)
		 SELECT $3, group_id, mailbox_id
		   FROM distribution_group_members
		  WHERE group_id = $1 AND mailbox_id = $2
		 ON CONFLICT DO NOTHING`,
		groupID, mailboxID, providerKey,
	)
	return err
}

// applyGroupMappings refreshes group memberships and admin role assignments
// based on the user's current IdP groups.  Called on every SSO login.
//
// Admin role writes go to admin_role_assignments (governed, audited) with
// NULL granted_by (system-provisioned) instead of directly updating
// users.admin_role.  There is no enclosing transaction — every INSERT is its
// own autocommit statement — so no savepoint is required or used.  If a
// single-statement INSERT fails (e.g. ERRCODE BZ001 from trg_sod_exclusion
// for a SoD-partition violation, or an FK error), the error is logged at Warn
// level and the loop continues; no other mapping or distribution-group insert
// is affected.
func (h *deps) applyGroupMappings(ctx context.Context, userID int64, idpGroups []string, mapper federation.GroupMappingProvider) {
	// nil means the configured claim/attribute was absent, so destructive
	// reconciliation must fail closed. A present-but-empty slice is authoritative:
	// this provider currently grants none of its mapped groups and stale grants
	// must be revoked.
	if mapper == nil || idpGroups == nil {
		return
	}
	if err := identity.ValidateSSOGroupClaims(idpGroups); err != nil {
		h.logger.Warn("SSO group reconciliation refused unbounded claim", "user_id", userID, "error", err)
		return
	}
	mappings := mapper.GetGroupMappings()
	if len(mappings) == 0 {
		return
	}
	mappingGroups := make([]string, len(mappings))
	for i := range mappings {
		mappingGroups[i] = mappings[i].IDPGroup
	}
	if err := identity.ValidateSSOGroupMappings(mappingGroups); err != nil {
		h.logger.Warn("SSO group reconciliation refused invalid mappings", "user_id", userID, "error", err)
		return
	}
	providerKey := mapper.SSOProviderKey()
	if !federation.ValidSSOProviderKey(providerKey) {
		h.logger.Warn("SSO group mapping refused invalid provider key", "user_id", userID)
		return
	}

	var mailboxID int64
	if err := h.pool.QueryRow(ctx,
		`SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1`, userID,
	).Scan(&mailboxID); err != nil {
		return
	}

	// Remove only this provider's stale distribution-group provenance. The
	// effective membership is deleted only when no exact provider and no
	// pre-V153 ambiguous inventory marker remains. Manual rows are never deleted.
	if _, err := h.pool.Exec(ctx,
		`WITH removed AS (
		     DELETE FROM sso_distribution_group_provenance
		      WHERE provider_key = $1 AND mailbox_id = $2
		     RETURNING group_id, mailbox_id
		 )
		 DELETE FROM distribution_group_members dgm
		  USING removed r
		  WHERE dgm.group_id = r.group_id
		    AND dgm.mailbox_id = r.mailbox_id
		    AND dgm.mailbox_id = $2
		    AND dgm.source = 'sso'
		    AND NOT EXISTS (
		        SELECT 1
		          FROM sso_distribution_group_provenance p
		         WHERE p.group_id = dgm.group_id
		           AND p.mailbox_id = dgm.mailbox_id
		           AND p.provider_key <> $1
		    )
		    AND NOT EXISTS (
		        SELECT 1
		          FROM sso_distribution_group_legacy_inventory legacy
		         WHERE legacy.group_id = dgm.group_id
		           AND legacy.mailbox_id = dgm.mailbox_id
		    )`,
		providerKey, mailboxID,
	); err != nil {
		h.logger.Warn("SSO stale distribution-group cleanup failed", "user_id", userID, "error", err)
	}

	// BUG 001: remove old SSO-PROVISIONED admin assignments before re-applying the
	// current mappings, so an IdP group removal / mapping change actually DEMOTES
	// the user (the upsert below is ON CONFLICT DO NOTHING and never deletes, so
	// without this sweep a revoked IdP group left a stale governed grant —
	// privilege retention / failed demotion). granted_by IS NULL is V015's
	// SSO-provisioned marker, so admin-UI grants (real granter) are untouched. This
	// is the symmetric cleanup the distribution-group code above already does.
	//
	// Trigger-coexistence fix: V032 added trg_protect_last_super_admin (BEFORE DELETE
	// on admin_role_assignments, raises BZ064 when removing the last enabled Super
	// Admin). A sole SSO-provisioned Super Admin re-syncing would fire that trigger
	// against itself. We exclude role 1 from the sweep EXACTLY when the re-insert
	// loop below will re-grant it — i.e. when super_admin is still in this login's
	// IdP mappings AND the operator knob is ON (same conjunction as the re-insert
	// gate at the BUG 006 check below). This keeps the exclusion CONGRUENT with the
	// upsert: role 1 is preserved precisely when it would be re-granted (idempotent,
	// no BZ064 on self-resync). In every other case (knob OFF, or super_admin no
	// longer an active IdP mapping) the sweep includes role 1 and demotion works.
	//
	// Edge: knob OFF + sole Super Admin — when ssoAllowSuperAdminMapping is false
	// (or the group is no longer mapped) and the swept user is the only enabled
	// Super Admin, the sweep's DELETE fires trg_protect_last_super_admin → BZ064.
	// Because the sweep is non-transactional (autocommit, warn-only), the BZ064 is
	// swallowed and the row is RETAINED — which is the INTENDED behaviour: the
	// last-Super-Admin invariant wins. To demote a sole SSO Super Admin, provision
	// another Super Admin first. Do NOT "fix" this into a forced demotion.

	// Determine if super_admin is still mapped for this login — mirrors the gate
	// at the re-insert loop (BUG 006 check). A mapping counts only when both the
	// IdP group is present in this login's claims AND AdminRole == "super_admin".
	superAdminStillMapped := false
	for _, m := range mappings {
		if m.AdminRole != nil && *m.AdminRole == "super_admin" &&
			federation.ContainsString(idpGroups, m.IDPGroup) {
			superAdminStillMapped = true
			break
		}
	}
	// excludeSuper is true when the re-insert loop WILL re-grant role 1, so the
	// sweep must leave it alone to avoid a spurious BZ064 self-resync.
	excludeSuper := superAdminStillMapped && h.ssoAllowSuperAdminMapping
	if _, err := h.pool.Exec(ctx,
		`WITH removed AS (
		     DELETE FROM sso_admin_role_provenance p
		      USING admin_role_assignments ara
		      WHERE p.provider_key = $1
		        AND p.assignment_id = ara.id
		        AND ara.user_id = $2
		        AND NOT (ara.role_group_id = 1 AND $3)
		     RETURNING p.assignment_id
		 )
		 DELETE FROM admin_role_assignments ara
		  USING removed r
		  WHERE ara.id = r.assignment_id
		    AND ara.user_id = $2
		    AND ara.granted_by IS NULL
		    AND NOT EXISTS (
		        SELECT 1
		          FROM sso_admin_role_provenance p
		         WHERE p.assignment_id = ara.id
		           AND p.provider_key <> $1
		    )
		    AND NOT EXISTS (
		        SELECT 1
		          FROM sso_admin_role_legacy_inventory legacy
		         WHERE legacy.assignment_id = ara.id
		    )`,
		providerKey, userID, excludeSuper,
	); err != nil {
		h.logger.Warn("SSO stale admin-assignment cleanup failed", "user_id", userID, "error", err)
	}

	var departmentID *int64

	for _, mapping := range mappings {
		if !federation.ContainsString(idpGroups, mapping.IDPGroup) {
			continue
		}
		if mapping.DistributionGroupID != nil {
			if execErr := h.upsertSSODistributionMembership(
				ctx, *mapping.DistributionGroupID, mailboxID, providerKey,
			); execErr != nil {
				h.logger.Warn("SSO distribution-group membership upsert failed",
					"user_id", userID,
					"group_id", *mapping.DistributionGroupID,
					"error", execErr,
				)
			}
		}
		if mapping.AdminRole != nil {
			// BUG 006: the SSO_ALLOW_SUPER_ADMIN_MAPPING safety knob (default false)
			// gates whether an IdP group mapping may confer super_admin. When the
			// operator has not opted in, refuse the super_admin mapping (no upsert)
			// and Warn-log — a group mapping can never SILENTLY grant super_admin.
			if *mapping.AdminRole == "super_admin" && !h.ssoAllowSuperAdminMapping {
				h.logger.Warn("SSO admin mapping to super_admin refused (operator did not opt in via SSO_ALLOW_SUPER_ADMIN_MAPPING)",
					"user_id", userID)
				continue
			}
			groupID, known := adminRoleToGroupID[*mapping.AdminRole]
			if known && groupID > 0 {
				// F-004 (Astra waves34 HOLD 2): the login-time mint is gated on
				// the grant authority BEFORE the assignment is written. The
				// operator grant-authority record for this role label must
				// still cover the role group's live permission set (Rule A at
				// mint time); a missing record (authority lost/revoked) or a
				// role widened past its authorized ceiling refuses the mint.
				// A failed authority CHECK also refuses (fail closed).
				authorized, authErr := h.ssoMintAuthorityCovers(ctx, *mapping.AdminRole, groupID)
				if authErr != nil {
					h.logger.Warn("SSO admin mapping refused: grant-authority check failed",
						"user_id", userID,
						"role", *mapping.AdminRole,
						"group_id", groupID,
						"error", authErr,
					)
					continue
				}
				if !authorized {
					h.logger.Warn("SSO admin mapping refused: grant authority absent or exceeded (Rule A)",
						"user_id", userID,
						"role", *mapping.AdminRole,
						"group_id", groupID,
					)
					continue
				}
				if execErr := h.upsertSSOAdminAssignment(ctx, userID, groupID, providerKey); execErr != nil {
					if reducererr.IsCode(execErr, reducererr.ErrOverQuota) {
						h.logger.Warn("SSO admin mapping rejected by SoD partition",
							"user_id", userID,
							"role", *mapping.AdminRole,
							"group_id", groupID,
						)
					} else {
						h.logger.Warn("SSO admin_role_assignments upsert failed",
							"user_id", userID,
							"role", *mapping.AdminRole,
							"error", execErr,
						)
					}
				}
			}
		}
		if mapping.DepartmentID != nil {
			departmentID = mapping.DepartmentID
		}
	}

	if departmentID != nil {
		h.pool.Exec(ctx, `UPDATE users SET department_id = $2 WHERE id = $1`, userID, *departmentID)
	}
}

// nullIfEmpty returns nil for empty strings (for nullable DB columns).
func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// passwordContainsEmail checks case-insensitively whether the password contains
// the local-part or domain of the given email address.
func passwordContainsEmail(password, email string) bool {
	lowerPw := strings.ToLower(password)
	lowerEmail := strings.ToLower(email)
	if atIdx := strings.Index(lowerEmail, "@"); atIdx >= 0 {
		localPart := lowerEmail[:atIdx]
		domain := lowerEmail[atIdx+1:]
		if localPart != "" && strings.Contains(lowerPw, localPart) {
			return true
		}
		if domain != "" && strings.Contains(lowerPw, domain) {
			return true
		}
	}
	return false
}

// impersonationRank returns a numeric privilege tier used to enforce the
// no-upward/equal impersonation rule. Higher = more privileged.
//
// Post-RBAC-cut-over the users.admin_role enum is gone, so the tier is derived
// from the user's GOVERNED admin_role_assignments (resolveImpersonationTier):
//
//	non-admin (no governed assignment, not is_admin) -> 0
//	is_admin w/ no governed assignment (legacy floor) -> 1
//	governed admin holding a non-super-admin role     -> 3
//	governed admin holding the Super Admin group (id 1) -> 4
//
// The legacy floor (1) keeps a bare is_admin account (defense-in-depth: is_admin
// is retained) from impersonating any governed admin (which all rank >= 3) while
// still letting it impersonate ordinary non-admin users (rank 0). A scoped
// governed admin (rank 3) can never impersonate a Super Admin (rank 4) or a peer
// governed admin (equal rank ⇒ refused), preserving the no-upward/equal rule
// without an enum. Custom roles all map to rank 3 unless they ARE the Super Admin
// group, so the only way to reach the top tier is the AllPermissions builtin.
func impersonationRank(isAdmin bool, hasGoverned, isSuperAdminGroup bool) int {
	if isSuperAdminGroup {
		return 4
	}
	if hasGoverned {
		return 3
	}
	if isAdmin {
		return 1
	}
	return 0
}

// isASCII reports whether s contains only ASCII characters (<= 127).
func isASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}

// mustUser extracts the authenticated user claims from context.
// Returns nil and writes 401 if no valid claims are present.
func (h *deps) mustUser(w http.ResponseWriter, r *http.Request) *token.Claims {
	claims := tokenClaims(r)
	if claims == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "authentication required"})
		return nil
	}
	return claims
}
