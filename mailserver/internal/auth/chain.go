package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/config"
	"setjoin.com/mailserver/internal/db"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pwhash"
	"setjoin.com/shared/threat"
)

// contextKey is the unexported type used for context values set by the auth chain.
type contextKey int

const (
	ctxUser contextKey = iota
)

// AuthMethod is a single authentication strategy that can be tried per request.
type AuthMethod interface {
	Slug() string
	Priority() int
	Authenticate(r *http.Request) (*Claims, error)
}

// Chain is the auth priority resolver. Methods are loaded from the auth_methods
// database table and tried in priority order (lowest number first).
type Chain struct {
	pool              *pgxpool.Pool
	jwt               *JWTProvider
	cfg               *config.Config
	mu                sync.RWMutex
	methods           []AuthMethod
	threatInterceptor *threat.ThreatInterceptor
	guestPool         *pgxpool.Pool
}

// SetThreatInterceptor sets the threat interceptor for password-based auth methods.
func (c *Chain) SetThreatInterceptor(ti *threat.ThreatInterceptor) {
	c.threatInterceptor = ti
}

// SetGuestPool wires the worker/BYPASSRLS pool the guest satellite belt reads
// (guest-accounts P13, codex C-14): auth-chain infrastructure evaluated before
// any user identity is trusted — the federation AnchorLookup posture. Never
// the RLS-scoped app pool (its policies would see no app.current_user_id yet).
func (c *Chain) SetGuestPool(pool *pgxpool.Pool) { c.guestPool = pool }

func NewChain(cfg *config.Config, pool *pgxpool.Pool) (*Chain, error) {
	// SMx / hybrid-with-SM2 deployments: the authserver issues SM2-signed access
	// tokens (kid=authserver-sm2-1). The gateway must load the shared SM2 key file
	// to verify them — the symmetric-trust model (the same PEM is mounted to both
	// services, exactly like the shared JWT_SECRET backs HS256). SM2 is NOT
	// distributed via the JWKS (only ES256 is, ADR-005), so without this wiring an
	// SMx gateway has sm2Key==nil and rejects EVERY token — SMx logins fail closed.
	// Mirror authserver main.go's profile gate + LoadSM2PrivateKey loader.
	var sm2Key *ecdsa.PrivateKey
	if cfg.CryptoProfile == cryptokey.ProfileSMx ||
		(cfg.CryptoProfile == cryptokey.ProfileHybrid && cfg.SM2PrivateKeyFile != "") {
		k, err := cryptokey.LoadSM2PrivateKey(cfg.SM2PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("auth.chain: load SM2 verification key (profile %s): %w", cfg.CryptoProfile, err)
		}
		sm2Key = k
	}
	jwtProvider := NewJWTProvider(cfg.JWTSecret, sm2Key, cfg.JWTIssuer)
	jwtProvider.SetMailAttachmentSecret(cfg.MailAttachmentTokenSecret)
	jwtProvider.SetMailAttachmentPreviousSecret(cfg.MailAttachmentTokenPreviousSecret)

	// ADR-005 dual-verify: when an authserver JWKS URL is configured, verify
	// ES256 first-party access tokens against the fetched + cached public keys
	// (alongside the legacy HS256 path). When unset, ES256 tokens fail closed —
	// HS256-only mode — so rollout is never a flag day.
	if cfg.AuthServerJWKSURL != "" {
		jwks := NewJWKSClient(cfg.AuthServerJWKSURL)
		jwtProvider.SetES256Verifier(jwks)
		slog.Info("auth.chain: ES256 first-party token verification enabled (dual-verify with HS256)",
			"jwks_url", cfg.AuthServerJWKSURL)
		// Warm the cache in the background so a misconfigured/unreachable JWKS URL
		// surfaces at boot rather than silently on the first ES256 token. Non-
		// blocking: startup never waits on authserver, and a failure is non-fatal
		// (KeyByKID still refreshes lazily, and verification fails closed).
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := jwks.Refresh(ctx); err != nil {
				slog.Warn("auth.chain: initial JWKS warm-up failed (will retry lazily on first ES256 token)",
					"jwks_url", cfg.AuthServerJWKSURL, "error", err)
			} else {
				slog.Info("auth.chain: JWKS warm-up succeeded", "jwks_url", cfg.AuthServerJWKSURL)
			}
		}()
	} else {
		slog.Info("auth.chain: AUTHSERVER_JWKS_URL unset — HS256-only token verification (ES256 tokens will be rejected)")
	}

	c := &Chain{
		pool: pool,
		jwt:  jwtProvider,
		cfg:  cfg,
	}

	if err := c.ReloadMethods(context.Background()); err != nil {
		return nil, err
	}

	return c, nil
}

// ListenForChanges subscribes to config_changed NOTIFY and reloads auth methods on any change.
func (c *Chain) ListenForChanges(ctx context.Context, listener *db.Listener) {
	listener.OnReconnect(c.ReloadMethods)
	handler := func(msg *pgconn.Notification) {
		if err := c.ReloadMethods(ctx); err != nil {
			slog.Error("auth.chain: reload methods failed", "error", err)
		}
	}
	if _, err := listener.SubscribeDurable(ctx, "config_changed", handler); err != nil {
		c.installFailClosedMethods()
		slog.Error("auth.chain: config subscription pending reconnect; password methods disabled", "error", err)
	}
}

// ReloadMethods reads enabled auth methods from the database and rebuilds the chain.
func (c *Chain) ReloadMethods(ctx context.Context) error {
	rows, err := c.pool.Query(ctx,
		`SELECT slug, priority, config_json FROM auth_methods WHERE enabled = TRUE ORDER BY priority ASC`)
	if err != nil {
		c.installFailClosedMethods()
		return err
	}
	defer rows.Close()

	var methods []AuthMethod
	for rows.Next() {
		var slug string
		var priority int
		var configJSON []byte
		if err := rows.Scan(&slug, &priority, &configJSON); err != nil {
			slog.Warn("auth.chain: skipping corrupt auth_methods row", "error", err)
			continue
		}

		switch slug {
		case "jwt_bearer":
			methods = append(methods, &jwtAuthMethod{jwt: c.jwt})
		case "kerberos":
			if c.cfg.KerberosEnabled {
				krb, err := NewKerberosProvider(c.cfg.KerberosKeytab, c.cfg.KerberosRealm)
				if err == nil {
					methods = append(methods, &kerberosAuthMethod{provider: krb, pool: c.pool})
				}
			}
		case "certificate":
			roots, perr := loadCertRoots(slug, configJSON)
			if perr != nil {
				// ponytail: warn+skip so a misconfigured CA bundle never bricks login.
				slog.Warn("auth.chain: certificate method skipped (CA bundle unreadable)", "error", perr)
				continue
			}
			crls, cerr := loadCRLFiles(configJSON)
			if cerr != nil {
				slog.Warn("auth.chain: certificate method skipped (CRL unreadable)", "error", cerr)
				continue
			}
			methods = append(methods, &certAuthMethod{pool: c.pool, roots: roots, crls: crls})
		}
		// SAML, OIDC, WebAuthn are endpoint-based and issue JWTs;
		// they don't participate in per-request Bearer auth.
	}
	if err := rows.Err(); err != nil {
		c.installFailClosedMethods()
		return err
	}

	// Ensure JWT is always present as a fallback
	hasJWT := false
	for _, m := range methods {
		if m.Slug() == "jwt_bearer" {
			hasJWT = true
			break
		}
	}
	if !hasJWT {
		methods = append(methods, &jwtAuthMethod{jwt: c.jwt})
	}

	// Basic Auth is available unless disabled via feature toggle
	var disableBasic bool
	if err := c.pool.QueryRow(ctx,
		"SELECT enabled FROM feature_toggles WHERE key = 'feature.disable_basic_auth'",
	).Scan(&disableBasic); err != nil {
		// DB error: default to safe state (Basic Auth disabled) until
		// the toggle can be read successfully on the next reload cycle.
		slog.Warn("auth.chain: failed to read disable_basic_auth toggle, defaulting to disabled", "error", err)
		disableBasic = true
	}
	if !disableBasic {
		methods = append(methods, &basicAuthMethod{pool: c.pool, threatInterceptor: c.threatInterceptor})
	}

	c.mu.Lock()
	c.methods = methods
	c.mu.Unlock()
	return nil
}

// installFailClosedMethods preserves only signed bearer-token verification
// when the authoritative authentication-method snapshot cannot be loaded.
// Password, Kerberos, and certificate methods must not remain enabled from a
// stale pre-outage cache.
func (c *Chain) installFailClosedMethods() {
	c.mu.Lock()
	c.methods = []AuthMethod{&jwtAuthMethod{jwt: c.jwt}}
	c.mu.Unlock()
}

// JWT returns the JWTProvider so handlers can issue tokens.
func (c *Chain) JWT() *JWTProvider { return c.jwt }

// These are the push-only claim-shape rejections AuthenticatePushToken raises.
// Distinct sentinels keep the acceptance seam testable; the push handlers
// collapse all of them into one "invalid token" 401.
var (
	ErrNonAccessTokenOnPush  = errors.New("non-access token not accepted on push channel")
	ErrScopedTokenOnPush     = errors.New("scoped token not accepted on push channel")
	ErrMissingIssuedAtOnPush = errors.New("token without issued-at not accepted on push channel")
)

// ErrGuestLookupUnavailable: the satellite belt could not be evaluated.
// DENY — the guest middleware maps this to 503; every other caller's error
// path denies. A DB blip must never be a containment escape (P13).
var ErrGuestLookupUnavailable = errors.New("guest lookup unavailable")

// ErrGuestInactive: the caller is a guest whose status/expiry fails BZ219 at
// token validation (disabled, expired, or not yet accepted).
var ErrGuestInactive = errors.New("guest account not active")

// applyGuestBelt is the UNCONDITIONAL satellite belt (P13 as amended, codex
// C-1): a guest_accounts hit forces AccountType=guest regardless of what the
// token claims — a stale, stripped, pre-G0, or wrongly-member-claiming token
// can never fail open. no-row ≠ error: a member proceeds as claimed; a
// guest-CLAIMING token with no satellite row is denied (fail closed). A query
// error denies via ErrGuestLookupUnavailable.
// ponytail: per-request indexed PK probe (the spec's blessed naive form); a
// LISTEN/NOTIFY-fed in-process guest-id set is the named upgrade if the probe
// ever shows up in profiles.
func (c *Chain) applyGuestBelt(ctx context.Context, claims *Claims) error {
	if c.guestPool == nil {
		return nil // claim-only enforcement (unit seams); belt never CLEARS a claim
	}
	var status string
	var expires *time.Time
	err := c.guestPool.QueryRow(ctx,
		`SELECT status, expires_at FROM guest_account_status($1)`, claims.UserID,
	).Scan(&status, &expires)
	switch {
	case err == nil:
		claims.AccountType = jwtutil.AccountTypeGuest
		if status != "active" || (expires != nil && expires.Before(time.Now())) {
			return ErrGuestInactive // BZ219 at validation
		}
		return nil
	case errors.Is(err, pgx.ErrNoRows):
		if claims.IsGuest() {
			// A guest-claiming token with no satellite row is inconsistent —
			// deny rather than trust either half of the contradiction.
			return ErrGuestInactive
		}
		return nil // not a guest; proceed as the claim says
	default:
		return fmt.Errorf("%w: %v", ErrGuestLookupUnavailable, err)
	}
}

// AuthenticatePushToken validates a token arriving out-of-band (a WS/SSE
// handshake cookie/query param, not an Authorization header the auth-method
// chain can read) and is the ONE acceptance path for push channels. It enforces
// both guards the push handlers carried inline: the token must be an access
// token (a refresh token has empty Scp, so the Type guard is what stops it from
// opening a stream), and a scoped/mirror token (non-empty Scp) is a REST-surface
// credential refused here categorically — a drive-scoped token must never open a
// full JMAP push session. The handshake can't route through AuthenticateRequest
// (no Authorization header to read), so this seam holds the invariant instead.
func (c *Chain) AuthenticatePushToken(ctx context.Context, tokenStr string) (*Claims, error) {
	claims, err := c.jwt.Validate(tokenStr)
	if err != nil {
		return nil, err
	}
	if claims.Type != TypeAccess {
		return nil, ErrNonAccessTokenOnPush
	}
	if claims.Scp != "" {
		return nil, ErrScopedTokenOnPush
	}
	// Long-lived push transports are registered against their token issue time.
	// A signed but malformed token without iat would otherwise authenticate yet
	// evade runtime scope=all closure because the registry cannot place it
	// relative to the revocation watermark. Every supported first-party mint
	// includes iat, so fail closed at the one push-acceptance seam.
	if claims.IssuedAt == nil {
		return nil, ErrMissingIssuedAtOnPush
	}
	// Guest belt on the push seam too: GET /jmap/ws + /jmap/eventsource are
	// guest-ALLOWLISTED (chat's entire live rail rides them), so the direct-
	// validate path must apply the same satellite belt + BZ219 status check
	// the REST chain does (guest-accounts §4.1).
	if err := c.applyGuestBelt(ctx, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// NewChainWithJWT builds a Chain carrying the given JWT provider with the
// jwt_bearer method wired — the one method ReloadMethods always ensures is
// present as a fallback even against a live pool/config, so this seam mirrors
// production for Bearer auth without needing kerberos/certificate/basic (each
// of which needs a live pool). A minimal seam for callers/tests that need
// chain.JWT()/AuthenticatePushToken (e.g. the ws/eventsource push endpoints,
// which validate the JWT directly) or a real chain.AuthenticateRequest over
// Bearer tokens (guest_dispatch_test.go's REAL-dispatch containment proof)
// without the full auth-method wiring NewChain performs against a live
// pool/config. guestPool stays nil unless the caller opts in via
// SetGuestPool — so AuthenticateRequest here is claim-only belt enforcement
// (applyGuestBelt's pool-nil seam), exactly like any other unit-test chain.
func NewChainWithJWT(p *JWTProvider) *Chain {
	return &Chain{jwt: p, methods: []AuthMethod{&jwtAuthMethod{jwt: p}}}
}

// CertStatus returns a non-fatal hint string when a client certificate was
// presented on the request but FAILED verification — "expired", "untrusted", or
// "no_match". Returns "" when no cert was presented, when verification succeeded,
// or when no certAuthMethod is loaded. Never blocks or changes the auth outcome;
// the caller sets X-Cert-Status on the response for the SPA login banner.
func (c *Chain) CertStatus(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, m := range c.methods {
		cm, ok := m.(*certAuthMethod)
		if !ok || cm.roots == nil {
			continue
		}
		leaf := r.TLS.PeerCertificates[0]
		if err := verifyClientCert(leaf, cm.roots, cm.crls...); err != nil {
			msg := err.Error()
			if strings.Contains(msg, "expired") || strings.Contains(msg, "after") {
				return "expired"
			}
			return "untrusted"
		}
		// Cert is cryptographically valid; check if it maps to a known user.
		if _, mapErr := lookupByCertSubject(r.Context(), c.pool, leaf.Subject.CommonName, leaf.EmailAddresses); mapErr != nil {
			return "no_match"
		}
		return "" // valid cert + valid user — success, no hint needed
	}
	return ""
}

// ClientCertPool returns the merged x509 CA pool from all loaded certificate
// auth methods. Used by the HTTPS listener to set tls.Config.ClientCAs so the
// TLS handshake sends a CertificateRequest naming the accepted CAs (clients then
// know which cert to present). Returns nil when no certificate method is loaded
// (listener still functions; mTLS clients fall back to Bearer).
func (c *Chain) ClientCertPool() *x509.CertPool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, m := range c.methods {
		if cm, ok := m.(*certAuthMethod); ok && cm.roots != nil {
			return cm.roots
		}
	}
	return nil
}

// Authenticate implements shared/auth.Authenticator. It wraps AuthenticateRequest
// so the shared middleware can depend on the interface, not the concrete chain.
func (c *Chain) Authenticate(ctx context.Context, r *http.Request) (*Claims, error) {
	// Honor the caller's context (may carry deadline, trace, or values)
	// instead of relying solely on r.Context().
	return c.AuthenticateRequest(r.WithContext(ctx))
}

// AuthenticateRequest resolves the authenticated user by trying each
// AuthMethod in priority order. The first method that returns a non-nil
// Claims without error wins — subsequent methods are not tried.
//
// This means a request with both an invalid/expired JWT cookie AND valid
// Basic Auth credentials will authenticate as the Basic Auth user.
// This is intentional: the chain provides fallback for clients that
// support multiple auth methods, not multi-factor authentication.
// If per-request method exclusivity is needed, clients should not send
// multiple credential types simultaneously.
func (c *Chain) AuthenticateRequest(r *http.Request) (*Claims, error) {
	c.mu.RLock()
	methods := make([]AuthMethod, len(c.methods))
	copy(methods, c.methods)
	c.mu.RUnlock()

	// Ensure methods are tried in priority order (lowest number first)
	sort.Slice(methods, func(i, j int) bool {
		return methods[i].Priority() < methods[j].Priority()
	})

	for _, m := range methods {
		claims, err := m.Authenticate(r)
		if err == nil {
			// Scope containment (Drive P1 native-token bridge, batch-3 item 6): a
			// token minted with a non-empty Scp is a MIRROR credential scoped to
			// the one surface it names, never a full-session credential — reject
			// it here, the single claim-acceptance choke point every auth method
			// funnels through, unless the request path is on that surface. A
			// leaked drive mirror token must never authenticate anything else.
			if claims.Scp != "" && !pathWithinScope(r.URL.Path, claims.Scp) {
				continue
			}
			// Guest-accounts P13 belt: an UNCONDITIONAL satellite lookup that
			// forces AccountType=guest regardless of the token claim, and
			// fails closed (deny) on a guest-claim/no-row mismatch or a
			// lookup error. Must run before permissions are resolved.
			if err := c.applyGuestBelt(r.Context(), claims); err != nil {
				return nil, err
			}
			// Resolve permissions from the user's admin role at auth time (Phase 1).
			// In Phase 2, permissions will be embedded directly in the JWT.
			c.resolvePermissions(r.Context(), claims)
			return claims, nil
		}
	}

	return nil, errors.New("no credentials provided")
}

func pathWithinScope(path, scope string) bool {
	root := "/" + scope
	return path == root || strings.HasPrefix(path, root+"/")
}

// resolvePermissions populates claims.Permissions and claims.DomainScope from
// the user's admin role assignments. Resolution is by USER ID — multi-role
// union, honoring expires_at, narrowest domain_override ?? domain_scope — the
// SAME rule authserver uses to mint the JWT's domain scope, so the ENFORCED
// scope here agrees with the minted one (closes the prior double-resolution
// where this overwrote claims.DomainScope from a single-role-by-name lookup).
// On failure it logs a warning and leaves permissions nil; with the legacy
// is_admin bridge deleted, that means the request is denied downstream
// (deny-by-default) — authority flows exclusively from governed assignments.
//
// Gate on IsAdmin (not the removed admin_role enum — the RBAC cut-over dropped
// users.admin_role): a non-admin carries no governed assignment to resolve, so
// the Resolve query is skipped. An admin with no governed row resolves to an
// empty perm set and is denied everywhere by HasPermission (no enum fallback).
func (c *Chain) resolvePermissions(ctx context.Context, claims *Claims) {
	if !claims.IsAdmin {
		return
	}
	if c.pool == nil {
		return
	}

	authority, err := permissions.ResolveAuthority(ctx, c.pool, claims.UserID)
	if err != nil {
		slog.Warn("auth.chain: failed to resolve admin permissions",
			"user_id", claims.UserID, "error", err)
		return
	}
	claims.Permissions = authority.Permissions
	claims.GlobalPermissions = authority.GlobalPermissions
	claims.DomainScope = authority.DomainScope
}

// ContextWithUser attaches Claims to a context for downstream handlers.
func ContextWithUser(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, ctxUser, claims)
}

// UserFromContext retrieves Claims attached by ContextWithUser. Returns nil if absent.
func UserFromContext(ctx context.Context) *Claims {
	v, _ := ctx.Value(ctxUser).(*Claims)
	return v
}

// --- JWT Bearer auth method ---

type jwtAuthMethod struct {
	jwt *JWTProvider
}

func (m *jwtAuthMethod) Slug() string  { return "jwt_bearer" }
func (m *jwtAuthMethod) Priority() int { return 10 }

const accessTokenCookie = "access_token"

func (m *jwtAuthMethod) Authenticate(r *http.Request) (*Claims, error) {
	var tokenStr string

	// 1. Try Authorization header
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
	}

	// 2. Fall back to HttpOnly cookie
	if tokenStr == "" {
		cookie, err := r.Cookie(accessTokenCookie)
		if err == nil && cookie.Value != "" {
			tokenStr = cookie.Value
		}
	}

	if tokenStr == "" {
		return nil, errors.New("no bearer token")
	}

	claims, err := m.jwt.Validate(tokenStr)
	if err != nil {
		return nil, errors.New("invalid token")
	}
	if claims.Type == TypeMFAPending {
		return nil, errors.New("MFA required: complete TOTP verification")
	}
	if claims.Type == TypeRefresh {
		return nil, errors.New("refresh token cannot be used as access token")
	}
	if claims.Type != TypeAccess {
		return nil, errors.New("invalid token type")
	}
	return claims, nil
}

// --- Kerberos auth method ---

type kerberosAuthMethod struct {
	provider *KerberosProvider
	pool     *pgxpool.Pool
}

func (m *kerberosAuthMethod) Slug() string  { return "kerberos" }
func (m *kerberosAuthMethod) Priority() int { return 20 }

func (m *kerberosAuthMethod) Authenticate(r *http.Request) (*Claims, error) {
	if !IsNegotiateRequest(r) {
		return nil, errors.New("no negotiate header")
	}
	principal, err := m.provider.ValidateSPNEGO(r)
	if err != nil {
		pwhash.LogAuthEvent(r.Context(), m.pool, pwhash.AuthEvent{
			Event:     "login_failed",
			Provider:  "kerberos",
			IPAddress: httputil.ClientIP(r),
			Details:   `{"reason":"spnego_validation_failed"}`,
		}, nil)
		return nil, err
	}
	user, err := m.lookupByKerberosPrincipal(r.Context(), principal)
	if err != nil {
		pwhash.LogAuthEvent(r.Context(), m.pool, pwhash.AuthEvent{
			Event:     "login_failed",
			Provider:  "kerberos",
			IPAddress: httputil.ClientIP(r),
			Details:   `{"reason":"user_not_found"}`,
		}, nil)
		return nil, err
	}
	pwhash.LogAuthEvent(r.Context(), m.pool, pwhash.AuthEvent{
		UserID:    &user.ID,
		Event:     "login",
		Provider:  "kerberos",
		Email:     user.Email,
		IPAddress: httputil.ClientIP(r),
	}, nil)
	if user.TOTPEnabled {
		return nil, errors.New("MFA required: complete TOTP verification")
	}
	return &Claims{
		UserID:     user.ID,
		Email:      user.Email,
		IsAdmin:    user.IsAdmin,
		Type:       TypeAccess,
		AuthMethod: m.Slug(), // CA eval keys on this; empty would misclassify as jwt_bearer
	}, nil
}

func (m *kerberosAuthMethod) lookupByKerberosPrincipal(ctx context.Context, principal string) (*User, error) {
	// GovernedAdminExpr (the occ_7512aa859c19ceb6691b64c7 closure, shared with
	// CheckPassword/LookupByEmail): this seam feeds Claims.IsAdmin (line ~598)
	// exactly like the password seam does, so the bare legacy users.is_admin
	// flag must not establish admin here either — a flagged-but-ungoverned
	// user reads as a non-admin.
	var u User
	err := m.pool.QueryRow(ctx,
		`SELECT u.id, u.email, u.display_name, `+pwhash.GovernedAdminExpr+`,
		 u.totp_enabled
		 FROM users u WHERE u.krb5_principal = $1 AND u.enabled = TRUE`,
		principal,
	).Scan(&u.ID, &u.Email, &u.DisplayName, &u.IsAdmin, &u.TOTPEnabled)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	return &u, nil
}

// --- Certificate (mTLS) auth method ---

// certAuthMethod authenticates requests via mutual TLS client certificates.
// Priority 5 — outranks jwt_bearer(10) so mTLS clients are identified by cert
// before the Bearer token is attempted, matching the CA-3b auth_method=certificate
// policy-condition design.
// A missing or unverified client cert falls through (returns error) — never blocks
// other methods, so a misconfigured mTLS client can still fall back to Bearer.
type certAuthMethod struct {
	pool  *pgxpool.Pool
	roots *x509.CertPool
	crls  []*x509.RevocationList // ponytail: nil == no CRL check; wired from crl_paths in config_json
}

func (m *certAuthMethod) Slug() string  { return "certificate" }
func (m *certAuthMethod) Priority() int { return 5 }

func (m *certAuthMethod) Authenticate(r *http.Request) (*Claims, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New("no client certificate")
	}
	return m.authenticateCert(r.Context(), r.TLS.PeerCertificates[0])
}

// authenticateCert is the TLS-state-free core: verify the leaf cert, map it to an
// enabled user, and emit Claims with AuthMethod="certificate". Extracted from
// Authenticate so tests can exercise cert verification + user lookup without
// constructing a full *tls.ConnectionState.
// ponytail: single-arg nil check covers both the no-TLS path (Authenticate early-
// returns) and direct test calls with nil; keeps the hot path branchless.
func (m *certAuthMethod) authenticateCert(ctx context.Context, leaf *x509.Certificate) (*Claims, error) {
	if leaf == nil {
		return nil, errors.New("no client certificate")
	}
	if err := verifyClientCert(leaf, m.roots, m.crls...); err != nil {
		return nil, err
	}
	user, err := lookupByCertSubject(ctx, m.pool, leaf.Subject.CommonName, leaf.EmailAddresses)
	if err != nil {
		return nil, err
	}
	return &Claims{
		UserID:     user.ID,
		Email:      user.Email,
		IsAdmin:    user.IsAdmin,
		Type:       TypeAccess,
		AuthMethod: "certificate",
	}, nil
}
