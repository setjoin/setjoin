package handlers

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/httputil"
)

// RevokeHandler implements RFC 7009 OAuth 2.0 token revocation for
// authserver-issued tokens (access + refresh) held in oauth_tokens.
//
// It is distinct from the OIDC OP's /revoke (which revokes oidc_tokens issued
// to OIDC clients). The caller authenticates as a registered OAuth client
// (client_id+client_secret via HTTP Basic or body) or via INTERNAL_API_KEY.
//
// Per RFC 7009 §2.2 the response is always 200 for an authenticated request,
// whether or not the token existed — revocation is idempotent and reveals
// nothing about token validity. An invalid request (no token) is 400; an
// unauthenticated caller is 401.
type RevokeHandler struct {
	// Svc is the token lifecycle owner; revocation funnels through it so the
	// oauth_tokens revoke SQL has a single caller (Wave 3 TokenService seam).
	Svc *token.TokenService
	// Pool is the oauth_tokens store, used for OAuth-client authentication
	// (oidc_clients lookup). The revocation itself goes through Svc.
	Pool *pgxpool.Pool
	// APIKey is the INTERNAL_API_KEY; empty disables that gate (client auth only).
	APIKey string
}

// ServeHTTP authenticates the client, then revokes the presented token.
func (h *RevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid request body"})
		return
	}

	// clientID is the authenticated OAuth client whose tokens may be revoked
	// (RFC 7009 §2.1). The internal-API-key caller is not an OAuth client, so it
	// stays empty — RevokeByToken then only reaches NULL-client tokens.
	var clientID string
	creds := extractClientCredentials(r)
	switch {
	case h.apiKeyAuthenticated(r):
		// Internal caller: no owning client, clientID stays "".
	case authenticateClient(r.Context(), h.Pool, creds):
		clientID = creds.id
	default:
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnauthorized, Detail: "unauthorized"})
		return
	}

	tokenStr := r.PostFormValue("token")
	if tokenStr == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "token is required"})
		return
	}

	// Idempotent: a no-op (unknown/already-revoked, or a token owned by another
	// client) is still a success. A genuine DB failure is the only 5xx — never
	// surfaced as a token-state oracle. Revocation funnels through the
	// TokenService seam (the one place a first-party token is revoked); tests
	// constructing the handler with only a Pool fall back to the same primitive.
	var revErr error
	if h.Svc != nil {
		revErr = h.Svc.RevokeByToken(r.Context(), tokenStr, clientID)
	} else {
		revErr = token.RevokeByToken(r.Context(), h.Pool, tokenStr, clientID)
	}
	if revErr != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "revocation failed"})
		return
	}

	w.WriteHeader(http.StatusOK)
}

// apiKeyAuthenticated reuses the introspection handler's API-key gate so the
// internal caller can revoke without registering as an OAuth client.
func (h *RevokeHandler) apiKeyAuthenticated(r *http.Request) bool {
	ih := &IntrospectHandler{APIKey: h.APIKey}
	return ih.apiKeyAuthenticated(r)
}
