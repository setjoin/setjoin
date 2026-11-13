package middleware

import (
	"context"
	"log/slog"
	"net/http"

	"setjoin.com/mailserver/internal/auth"
	sharedauth "setjoin.com/shared/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/jwtutil"
)

// RequireAuth returns an HTTP middleware that enforces authentication.
// It tries the auth chain (Kerberos → JWT Bearer) and attaches the resolved
// Claims to the request context. On failure it returns 401 with a WWW-Authenticate
// header that lists both Negotiate and Bearer, so:
//   - Windows clients send a Kerberos ticket automatically on 401.
//   - Other clients know to send Bearer tokens.
func RequireAuth(authn sharedauth.Authenticator, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := authn.Authenticate(r.Context(), r)
			if err != nil {
				// Challenge both Negotiate and Bearer so clients know their options.
				w.Header().Set("WWW-Authenticate", `Negotiate, Bearer realm="mailserver"`)
				httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			if claims.Type != jwtutil.TypeAccess {
				httputil.WriteProblemStatus(w, http.StatusForbidden, "MFA required")
				return
			}
			// Device-compliance gating is wired downstream, not here: main.go wraps
			// the authenticated chain as authMW(deviceTrustGate(deviceRevocationGate(next))),
			// so middleware.DeviceTrustGate runs right after this RequireAuth — it reads
			// the claims we attach below and, when feature.device_trust_enforcement is
			// ON, 403s a quarantined/wipe-requested device. The toggle DEFAULTs OFF, so
			// the gate is an inert pass-through until deliberately flipped. See
			// device_trust_gate.go + shared/middleware.RequireDeviceCompliance.
			//
			// Attach user to context so handlers can call auth.UserFromContext(ctx).
			ctx := auth.ContextWithUser(r.Context(), claims)
			// Attach domain scope so admin handlers can enforce per-domain isolation.
			if claims.DomainScope != nil {
				ctx = context.WithValue(ctx, ctxKeyDomainScope, *claims.DomainScope)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdmin and RequireRole — the enum-role wrappers — were removed in the
// RBAC cut-over. Authorization no longer keys off the AdminRole enum; every
// admin route is now requireAuth (authn-only, above) + a granular
// RequirePermAudited gate (below). The permission, not the role, is the
// authority.

// ── Permission-based middleware ──────────────────────────────────────────

// ctxKey is the unexported type used for context values set by the
// permission middleware (RequirePermAudited / RequireAnyPermAudited).
type ctxKey int

const ctxKeyDomainScope ctxKey = iota

// DomainScopeFromContext extracts the domain scope from the request context.
// Returns 0 if no domain scope is set (global access).
func DomainScopeFromContext(ctx context.Context) int64 {
	v, ok := ctx.Value(ctxKeyDomainScope).(int64)
	if !ok {
		return 0
	}
	return v
}

// ContextWithDomainScope returns a new context with the given domain scope.
// Used by tests to inject domain scope into request contexts.
func ContextWithDomainScope(ctx context.Context, scope int64) context.Context {
	return context.WithValue(ctx, ctxKeyDomainScope, scope)
}
