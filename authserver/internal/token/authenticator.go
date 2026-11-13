package token

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	sharedauth "setjoin.com/shared/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/threat"
)

// BearerAuthenticator adapts a JWTProvider to shared/auth.Authenticator so the
// shared middleware (and any future cross-service middleware) can authenticate
// authserver requests through the same seam mailserver's Chain uses.
//
// It is the single acceptance funnel for EVERY authserver route (direct and
// gateway-proxied alike — the gateway's /auth proxy performs no token
// validation of its own), so the session-acceptance semantics beyond signature
// validity live here:
//
//   - Revocation (occ-acab, session-revocation.authserver-access-jwt): when a
//     CA-3a denylist is attached (WithRevocations), a positive
//     SessionDenylist.IsRevoked match on the presented token's
//     (user, jti, family, iat) rejects the request with ErrRevoked — the same
//     durable session_revocations authority the gateway's
//     RequireRuntimeAccess spine consults, fed by the same
//     revoke_user_sessions reducer. A nil denylist preserves the pre-CAE
//     positive-match posture (no mirror, no negative-trust claim) rather than
//     pretending to verify revocation state it cannot see.
//
//   - Token binding (occ-dpop, token-binding.authserver-dpop-bypass): a
//     cnf-bound (DPoP) access token is refused unless the request carries a
//     verifiable RFC 9449 proof binding the token's cnf.jkt to this exact
//     request (method + client-facing htu + ath over the presented token).
//     This is fail-closed WITHOUT configuration: an in-process replay cache is
//     created at construction (the same per-process granularity the gateway
//     spine uses), and a cnf-bearing token can only exist when an operator
//     enabled feature.token_binding, so unbound deployments see no change.
//     shared/threat.VerifyDPoP is the tested shared proof verifier this seam
//     binds (the acceptance-path proof-seam genre of shared/device + the
//     telemetry mount).
type BearerAuthenticator struct {
	jwt         *JWTProvider
	revocations *threat.SessionDenylist
	replay      *threat.DPoPReplayCache
	logger      *slog.Logger
}

// NewBearerAuthenticator wraps a JWTProvider as a shared/auth.Authenticator.
// The DPoP replay cache is created here so cnf enforcement is fail-closed by
// default; use WithRevocations to attach the CA-3a denylist mirror.
func NewBearerAuthenticator(jwt *JWTProvider) *BearerAuthenticator {
	return &BearerAuthenticator{
		jwt:    jwt,
		replay: threat.NewDPoPReplayCache(dpopReplayTTL),
	}
}

// dpopReplayTTL bounds how long a proof jti stays remembered. RFC 9449 §4.2
// bounds proof iat skew to ±60s; remembering jtis for twice that covers every
// replayable window the verifier will accept.
const dpopReplayTTL = 2 * time.Minute

// WithRevocations attaches the CA-3a session-revocation denylist (the shared
// threat.SessionDenylist mirror of session_revocations). Non-nil: a positive
// IsRevoked match rejects authentication with ErrRevoked on every route this
// authenticator guards.
func (a *BearerAuthenticator) WithRevocations(d *threat.SessionDenylist) *BearerAuthenticator {
	a.revocations = d
	return a
}

// WithLogger attaches a structured logger for revocation/binding denials.
func (a *BearerAuthenticator) WithLogger(l *slog.Logger) *BearerAuthenticator {
	a.logger = l
	return a
}

// compile-time: BearerAuthenticator satisfies the shared seam.
var _ sharedauth.Authenticator = (*BearerAuthenticator)(nil)

// ErrNoBearer is returned when the request carries neither a Bearer Authorization
// header nor an access_token cookie.
var ErrNoBearer = errors.New("no bearer token")

// ErrRevoked is returned when the presented token's session has been revoked
// (CA-3a denylist positive match). RequireAuth maps it like any other
// authentication failure: 401, never a stack-specific oracle.
var ErrRevoked = errors.New("session revoked")

// ErrTokenBinding is returned when a cnf-bound access token arrives without a
// verifiable DPoP proof (missing, malformed, wrong key, replayed jti, or htm/htu
// mismatch). The possession proof is the second half of a bound token's
// authentication; without it the token must not authenticate anything.
var ErrTokenBinding = errors.New("token binding verification failed")

// accessTokenCookie is the HttpOnly cookie the webmail SPA relies on (set by
// POST /auth/login). It mirrors mailserver's gateway Chain
// (internal/auth/chain.go), so both services accept the same session cookie.
const accessTokenCookie = "access_token"

// ErrWrongTokenType is returned when a valid token is presented whose type is not
// an access token. RequireAuth maps this sentinel to HTTP 403 (token-type parity
// with the pre-seam middleware, which returned 403 "Invalid token type"); every
// other authentication error maps to 401.
var ErrWrongTokenType = errors.New("token is not an access token")

// PresentedAccessToken resolves the request's access-token string exactly the
// way Authenticate does — Authorization: Bearer header first (CSRF-immune),
// then the ambient HttpOnly access_token cookie — without validating it. The
// per-tab admission-recovery read (session.go SessionToken) needs the same
// string back it just authenticated.
func PresentedAccessToken(r *http.Request) (string, bool) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if tok := strings.TrimPrefix(h, "Bearer "); tok != "" {
			return tok, true
		}
	}
	if c, err := r.Cookie(accessTokenCookie); err == nil && c.Value != "" {
		return c.Value, true
	}
	return "", false
}

// Authenticate validates the Bearer access token on the request. The signature
// verification is lifted from the old middleware.RequireAuth body (Bearer
// prefix, Validate, Type==TypeAccess) but returns errors instead of writing
// HTTP, so the shared middleware owns the response. A non-access token yields
// ErrWrongTokenType; a revoked session yields ErrRevoked; a cnf-bound token
// without a verifiable DPoP proof yields ErrTokenBinding.
func (a *BearerAuthenticator) Authenticate(_ context.Context, r *http.Request) (*jwtutil.Claims, error) {
	tokenStr, ok := PresentedAccessToken(r)
	if !ok {
		return nil, ErrNoBearer
	}
	return a.AuthenticatePresented(r, tokenStr)
}

// AuthenticatePresented runs the FULL session-acceptance funnel — signature,
// access-type parity, revocation, and DPoP proof-of-possession for cnf-bound
// tokens — for an EXPLICITLY presented access token string, instead of
// Authenticate's header-or-cookie resolution. The dual-admission possession
// endpoints resolve their §3.2 T1 precedence per presented token (bearer
// header, then ambient cookie, then the mfa_token member) and reuse THIS
// funnel for the access-token modes, so a cnf-bound token is refused without
// its binding proof there too (r1 defect 4: bare jwt.Validate skipped DPoP
// and revocation on exactly those routes).
func (a *BearerAuthenticator) AuthenticatePresented(r *http.Request, tokenStr string) (*jwtutil.Claims, error) {
	return a.authenticatePresented(r, tokenStr, true)
}

// AuthenticateAdmissionRecovery runs the session-acceptance funnel for the
// per-tab DPoP admission-recovery read (GET /auth/session/token, r3): the
// session cookie is shared by every tab of the browser profile, but the RFC
// 9449 ath source is per-tab — a freshly opened tab holds the cookie and the
// persisted binding key yet NO token string, and a stale tab holds a string
// another tab's refresh already rotated away; both mint inadmissible proofs
// with no way back. The recovery read reveals the PRESENTED string to a
// caller that proves everything EXCEPT knowledge of the string: signature,
// access-type parity, revocation and — whenever the token is cnf-bound — a
// DPoP proof bound to cnf.jkt withOUT the ath claim (VerifyDPoP's documented
// caller class: the caller is here precisely because it cannot compute ath
// yet). The string alone stays inadmissible for every other request, so the
// reveal cannot bypass the binding; it only restores this tab's ability to
// compute ath over the token it is already carrying.
func (a *BearerAuthenticator) AuthenticateAdmissionRecovery(r *http.Request) (*jwtutil.Claims, error) {
	tokenStr, ok := PresentedAccessToken(r)
	if !ok {
		return nil, ErrNoBearer
	}
	return a.authenticatePresented(r, tokenStr, false)
}

// authenticatePresented is the shared funnel: requireATH selects the RFC
// 9449 §4.3 enforcement (VerifyDPoPForToken) over the ath-less recovery
// class (VerifyDPoP) — every other check is identical.
func (a *BearerAuthenticator) authenticatePresented(r *http.Request, tokenStr string, requireATH bool) (*jwtutil.Claims, error) {
	if tokenStr == "" {
		return nil, ErrNoBearer
	}
	claims, err := a.jwt.Validate(tokenStr)
	if err != nil {
		return nil, err
	}
	if claims.Type != jwtutil.TypeAccess {
		return nil, ErrWrongTokenType
	}
	// Session acceptance (post-signature): revocation, then proof-of-possession.
	if a.revocations != nil {
		iat := time.Time{}
		if claims.IssuedAt != nil {
			iat = claims.IssuedAt.Time
		}
		if a.revocations.IsRevoked(claims.UserID, claims.JTI, claims.RefreshFamilyID(), iat) {
			a.logRevoked(claims)
			return nil, ErrRevoked
		}
	}
	if claims.Cnf != nil && claims.Cnf.JKT != "" {
		// RFC 9449 §4.1: the DPoP header carries the proof. VerifyDPoPForToken
		// additionally enforces the ath claim binding the proof to THIS access
		// token, and the single-use jti check against the authenticator-owned
		// replay cache (fail-closed: a nil cache would nil-deref, so the cache
		// is created at construction and never nil here).
		proof := r.Header.Get("DPoP")
		var proofErr error
		if requireATH {
			proofErr = threat.VerifyDPoPForToken(proof, r.Method, dpopClientFacingURI(r), claims.Cnf.JKT, tokenStr, time.Now(), a.replay)
		} else {
			proofErr = threat.VerifyDPoP(proof, r.Method, dpopClientFacingURI(r), claims.Cnf.JKT, time.Now(), a.replay)
		}
		if proofErr != nil {
			a.logBinding(claims, proofErr)
			return nil, ErrTokenBinding
		}
	}
	return claims, nil
}

func (a *BearerAuthenticator) logRevoked(claims *jwtutil.Claims) {
	if a.logger != nil {
		a.logger.Info("authserver bearer: session revoked",
			"user_id", claims.UserID, "jti", claims.JTI, "family", claims.RefreshFamilyID())
	}
}

func (a *BearerAuthenticator) logBinding(claims *jwtutil.Claims, err error) {
	if a.logger != nil {
		a.logger.Warn("authserver bearer: DPoP proof failed",
			"user_id", claims.UserID, "error", err)
	}
}

// dpopClientFacingURI reconstructs the htu a DPoP proof was minted against: the
// client-facing scheme + host + path, without query. Direct access uses r.Host
// and the connection TLS state; behind the gateway's auth proxy (which rewrites
// Host to the internal target but forwards the client-facing X-Forwarded-Proto
// and single-token sanitized X-Forwarded-Host), the forwarded values restore the
// exact URI the client signed — the same sanitized-forwarded-header trust
// argument shared/middleware's CSRF check and the gateway proxy's own header
// sanitization (mailserver/internal/authproxy) establish.
func dpopClientFacingURI(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if fp := forwardedProtoToken(r.Header.Get("X-Forwarded-Proto")); fp != "" {
		scheme = fp
	}
	host := r.Host
	if fh := sanitizedForwardedHost(r.Header.Get("X-Forwarded-Host")); fh != "" {
		host = fh
	}
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
}

// forwardedProtoToken accepts the header value only as a single sanitized
// http/https token (no list syntax, whitespace, or other scheme names), mirroring
// shared/middleware's sanitizedForwardedProto contract.
func forwardedProtoToken(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "http":
		return "http"
	case "https":
		return "https"
	default:
		return ""
	}
}

// sanitizedForwardedHost returns the X-Forwarded-Host value only when it is a
// syntactically valid single host[:port] — no list syntax, whitespace, userinfo,
// or scheme — so a client-supplied chain can never smuggle a host past the htu
// check. Mirrors the shared/middleware CSRF sanitizer's contract at this seam.
func sanitizedForwardedHost(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.ContainsAny(v, " ,\t/\\@?#") || strings.Contains(v, "..") {
		return ""
	}
	// Bracketed IPv6 literal: validate the bracket shape, accept as-is.
	if strings.HasPrefix(v, "[") {
		closing := strings.Index(v, "]")
		if closing < 0 || closing != len(v)-1 && !strings.HasPrefix(v[closing+1:], ":") {
			return ""
		}
		inner := v[1:closing]
		if ip := net.ParseIP(inner); ip == nil || !strings.Contains(inner, ":") {
			return ""
		}
		if rest := v[closing+1:]; rest != "" {
			if _, err := net.LookupPort("tcp", rest[1:]); err != nil {
				return ""
			}
		}
		return v
	}
	if host, port, err := net.SplitHostPort(v); err == nil {
		if host == "" || strings.ContainsAny(host, "[]:") {
			return ""
		}
		if _, err := net.LookupPort("tcp", port); err != nil {
			return ""
		}
		return v
	}
	if strings.ContainsAny(v, "[]:") {
		return ""
	}
	return v
}
