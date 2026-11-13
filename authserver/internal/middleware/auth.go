package middleware

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"setjoin.com/authserver/internal/handlers"
	"setjoin.com/authserver/internal/token"
	sharedauth "setjoin.com/shared/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/threat"
)

// RequireAuth validates the request through the shared Authenticator seam and
// attaches the resolved claims to context. It depends on shared/auth.Authenticator
// (not a concrete *token.JWTProvider), the same seam mailserver's Chain implements.
//
// Status parity with the pre-seam middleware is preserved: a valid token of the
// wrong type (token.ErrWrongTokenType) yields 403 "Invalid token type"; every
// other authentication failure (missing/invalid Bearer) yields 401 with a
// WWW-Authenticate challenge. The one typed exception: a DPoP/token-binding
// refusal (token.ErrTokenBinding) keeps the 401 + challenge but marks the
// problem body with threat.DPoPAdmissionCode — the session itself is alive and
// the per-tab recovery may lawfully re-admit the request; the marker is what
// the webmail client's replay gate keys on (application-level 401s further
// down the handlers never carry it, so they execute exactly once).
func RequireAuth(authn sharedauth.Authenticator, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := authn.Authenticate(r.Context(), r)
			if err != nil {
				if errors.Is(err, token.ErrWrongTokenType) {
					httputil.WriteProblemStatus(w, http.StatusForbidden, "Invalid token type")
					return
				}
				if errors.Is(err, token.ErrTokenBinding) {
					w.Header().Set("WWW-Authenticate", `Bearer realm="authserver"`)
					httputil.WriteProblem(w, r, &httputil.Problem{
						Status: http.StatusUnauthorized,
						Detail: "Unauthorized",
						Code:   threat.DPoPAdmissionCode,
					})
					return
				}
				w.Header().Set("WWW-Authenticate", `Bearer realm="authserver"`)
				httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			ctx := handlers.ContextWithUser(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAuthOrRedirect validates an ordinary Setjoin access session but sends
// an anonymous browser to the same-origin login page with a bounded relative
// continuation. This is for interactive protocol hand-offs such as the OIDC OP
// authorization request, not JSON APIs (which must retain RequireAuth's 401).
func RequireAuthOrRedirect(
	authn sharedauth.Authenticator,
	loginPath string,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := authn.Authenticate(r.Context(), r)
			if err != nil {
				if errors.Is(err, token.ErrWrongTokenType) {
					httputil.WriteProblemStatus(w, http.StatusForbidden, "Invalid token type")
					return
				}
				target := loginPath + "?continue=" + url.QueryEscape(r.URL.RequestURI())
				http.Redirect(w, r, target, http.StatusFound)
				return
			}
			ctx := handlers.ContextWithUser(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
