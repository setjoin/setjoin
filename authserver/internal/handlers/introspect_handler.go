package handlers

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/httputil"
)

// IntrospectHandler handles RFC 7662 token introspection requests.
//
// Two caller classes are accepted:
//   - The internal gateway, presenting INTERNAL_API_KEY as a Bearer token
//     (the historical gate, kept for the IMAP/SMTP AUTH path).
//   - A registered OAuth client, presenting client_id+client_secret via HTTP
//     Basic or in the request body (RFC 7662 §2.1).
//
// An authenticated caller submitting an unknown/expired/revoked token receives
// {"active":false} — never an error — so the endpoint is not an oracle. An
// unauthenticated caller receives 401 and no token information.
type IntrospectHandler struct {
	// Svc is the token lifecycle owner; introspection reads through it so the
	// oauth_tokens store has a single owner (Wave 3 TokenService seam).
	Svc *token.TokenService
	// Pool is the oauth_tokens store, used for OAuth-client authentication
	// (oidc_clients lookup). Token introspection itself goes through Svc.
	Pool *pgxpool.Pool
	// APIKey is the INTERNAL_API_KEY; an empty value disables the internal gate
	// (client authentication is then the only accepted path).
	APIKey string
	// Issuer / Audience are reported as iss / aud in the introspection response
	// (RFC 7662 §2.2). They mirror the claims the auth server stamps into tokens.
	Issuer   string
	Audience string
}

// ServeHTTP authenticates the caller, then returns the introspection result for
// the submitted token. The token is read from the form/body "token" parameter
// (RFC 7662 §2.1) or, for backward compatibility, a JSON {"token":...} body.
func (h *IntrospectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tokenStr, ok := h.authenticateAndExtractToken(w, r)
	if !ok {
		return
	}

	opts := token.IntrospectOptions{Issuer: h.Issuer, Audience: h.Audience}
	// Introspection reads through the TokenService seam in production. Tests that
	// construct the handler with only a Pool (no Svc) fall back to the same
	// underlying primitive against that pool — identical behavior.
	var (
		result *token.IntrospectResponse
		err    error
	)
	if h.Svc != nil {
		result, err = h.Svc.Introspect(r.Context(), tokenStr, opts)
	} else {
		result, err = token.Introspect(r.Context(), h.Pool, tokenStr, opts)
	}
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "introspection failed"})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, result)
}

// authenticateAndExtractToken validates the caller (API key or client auth) and
// returns the token to introspect. It writes the error response and returns
// ok=false when authentication fails or no token was supplied.
func (h *IntrospectHandler) authenticateAndExtractToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	// JSON bodies (the legacy internal contract) carry the token in {"token":...}
	// and authenticate via the INTERNAL_API_KEY Bearer header.
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		if !h.apiKeyAuthenticated(r) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "unauthorized"})
			return "", false
		}
		var req struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "token is required"})
			return "", false
		}
		return req.Token, true
	}

	// Standard RFC 7662 form-encoded request: parse the body so both the token
	// parameter and any client_secret_post credentials are available.
	if err := r.ParseForm(); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid request body"})
		return "", false
	}

	if !h.apiKeyAuthenticated(r) &&
		!authenticateClient(r.Context(), h.Pool, extractClientCredentials(r)) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "unauthorized"})
		return "", false
	}

	tokenStr := r.PostFormValue("token")
	if tokenStr == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "token is required"})
		return "", false
	}
	return tokenStr, true
}

// apiKeyAuthenticated reports whether the request carries the INTERNAL_API_KEY
// as a Bearer token. A constant-time compare avoids leaking the key by timing.
func (h *IntrospectHandler) apiKeyAuthenticated(r *http.Request) bool {
	if h.APIKey == "" {
		return false
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	presented := strings.TrimPrefix(auth, "Bearer ")
	return subtle.ConstantTimeCompare([]byte(presented), []byte(h.APIKey)) == 1
}
