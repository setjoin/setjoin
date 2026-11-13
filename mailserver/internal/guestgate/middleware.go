package guestgate

import (
	"errors"
	"net/http"
	"strings"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

// accessTokenCookieName mirrors internal/auth/chain.go's unexported
// accessTokenCookie constant ("access_token") — the cookie the JWT auth
// method falls back to when there's no Authorization header. Kept as a
// literal (not imported — the constant is unexported) rather than exporting
// it across a package boundary for one string.
const accessTokenCookieName = "access_token"

// carriesJWTCredential reports whether the request carries anything the JWT
// auth method would read: a Bearer Authorization header or the access_token
// cookie. A guest principal is JWT-borne ONLY (the AccountType=guest claim
// lives only inside a JWT; Basic-auth guests are already refused at
// auth.CheckPassword, Task 5) — so a request with neither cannot be a guest,
// and the gate has nothing to narrow.
func carriesJWTCredential(r *http.Request) bool {
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return true
	}
	c, err := r.Cookie(accessTokenCookieName)
	return err == nil && c.Value != ""
}

// Middleware enforces the allowlist for the guest claim on the WHOLE gateway
// API surface — buildRootDispatch routes both the /api mount and the
// bare-root pinned branch (/jmap, /auth, /.well-known, …) through it (E-B1).
// Unauthenticated requests pass through (each handler enforces its own auth —
// this middleware only ever NARROWS, which is what makes wrapping non-JWT
// pinned surfaces (CalDAV basic-auth, SCIM bearer, ops probes) a no-op for
// them). A guest-belt lookup failure is the one place the spec's error⇒503
// semantics surface (P13/C-14); any other auth error passes through for the
// handler's own 401.
// featureGate is deliberately tiny so the production live FeatureFlags and
// focused test doubles can both drive the program-level runtime belt.
type featureGate interface {
	IsEnabled(string) bool
}

// Middleware accepts an optional feature gate for compatibility with focused
// package tests and tracer helpers that exercise the G0 allowlist in isolation.
// Production always supplies the live gate through buildRootDispatch. When it
// is supplied, an authenticated guest becomes indistinguishable from a missing
// route while feature.guest_accounts is OFF, including on otherwise allowlisted
// Chat/push/session paths. Unauthenticated invite acceptance remains reachable.
func Middleware(ch *auth.Chain, next http.Handler, gates ...featureGate) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A non-JWT-borne request (no Bearer header, no access_token cookie)
		// cannot carry a guest claim — skip the chain call entirely instead of
		// re-authenticating. Without this, every CalDAV/CardDAV request (Basic
		// auth, already wrapped in d.requireAuth) authenticated TWICE: 2x
		// bcrypt, 2x threat-score record, 2x audit row, doubled tarpit sleep,
		// and failed passwords counted double toward lockout/threat velocity.
		if !carriesJWTCredential(r) {
			next.ServeHTTP(w, r)
			return
		}
		claims, err := ch.AuthenticateRequest(r)
		if err != nil {
			if errors.Is(err, auth.ErrGuestLookupUnavailable) {
				// Task-16 error-shape decision: this gate fronts app-JSON /api
				// handlers, so its own errors follow the SAME RFC 7807
				// convention every other app-JSON path uses
				// (docs/standards/API_ERROR_SHAPE.md, check-http-error-shape.sh)
				// rather than a bespoke plain-text emitter.
				httputil.WriteProblemStatus(w, http.StatusServiceUnavailable, "service unavailable")
				return
			}
			if errors.Is(err, auth.ErrGuestInactive) {
				// BZ219 at validation: a disabled/expired guest gets the EXACT
				// same 401 shape middleware.RequireAuth emits for any invalid
				// credential (status + problem+json body + the "Unauthorized"
				// detail) — no oracle between "your guest account is
				// disabled" and "your token doesn't even parse".
				httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if claims.IsGuest() && len(gates) > 0 && gates[0] != nil &&
			!gates[0].IsEnabled(toggle.FeatureGuestAccounts) {
			http.NotFound(w, r)
			return
		}
		if claims.IsGuest() && !GuestAllowed(r.Method, r.URL.Path) {
			// Everything not allowlisted is 404 for the guest claim —
			// indistinguishable from a route that does not exist (P11b).
			// http.NotFound is the SAME emitter the real "unknown route" path
			// uses (main.go's spaFallback/asset-miss branches) — byte-identical
			// plain-text 404 — which is why this site stays http.NotFound
			// instead of converting to problem+json: converting it would make a
			// blocked-guest request DISTINGUISHABLE from a genuinely missing
			// route, defeating P11b's whole point.
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
