package handlers

import (
	"net/http"
	"strings"

	"setjoin.com/shared/httputil"
)

// OAuthMetadata is the RFC 8414 OAuth 2.0 Authorization Server Metadata
// document, served at /.well-known/oauth-authorization-server. It overlaps the
// OIDC discovery document (RFC 8414 §2 deliberately mirrors OpenID Connect
// Discovery field names) so OAuth-only clients that do not speak OIDC can still
// locate the authorization, token, introspection, and revocation endpoints and
// learn the server's PKCE/grant/auth-method support.
type OAuthMetadata struct {
	Issuer                                    string   `json:"issuer"`
	AuthorizationEndpoint                     string   `json:"authorization_endpoint"`
	TokenEndpoint                             string   `json:"token_endpoint"`
	IntrospectionEndpoint                     string   `json:"introspection_endpoint"`
	RevocationEndpoint                        string   `json:"revocation_endpoint"`
	JwksURI                                   string   `json:"jwks_uri"`
	UserinfoEndpoint                          string   `json:"userinfo_endpoint,omitempty"`
	ScopesSupported                           []string `json:"scopes_supported"`
	ResponseTypesSupported                    []string `json:"response_types_supported"`
	GrantTypesSupported                       []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported         []string `json:"token_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported"`
	ACRValuesSupported                        []string `json:"acr_values_supported,omitempty"`
	ClaimsSupported                           []string `json:"claims_supported"`
}

// OAuthMetadataHandler serves the RFC 8414 AS metadata document.
//
// The issuer is fixed at startup to match the OIDC OP's StaticIssuer
// (https://<hostname>) so the two discovery documents agree. Endpoint URLs are
// derived from that issuer base and all point at one OIDC OP token universe.
// The separate /auth/introspect and /auth/revoke endpoints own first-party
// Setjoin access tokens and must not be mixed into this metadata document.
type OAuthMetadataHandler struct {
	// Issuer is the authorization server's issuer identifier, e.g.
	// "https://auth.example.com". Endpoint URLs are built relative to it.
	Issuer string
	// JwksURI advertises the OIDC OP's RS256 key set. If empty, it defaults to
	// base+"/keys".
	JwksURI string
	// ScopesSupported / ClaimsSupported / ACRValuesSupported mirror the OIDC
	// discovery document so OAuth-only and OIDC clients see the same values.
	ScopesSupported    []string
	ClaimsSupported    []string
	ACRValuesSupported []string
}

// ServeHTTP returns the metadata document. No authentication (RFC 8414 §3: the
// document is public).
func (h *OAuthMetadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	base := strings.TrimRight(h.Issuer, "/")

	jwksURI := h.JwksURI
	if jwksURI == "" {
		jwksURI = base + "/keys"
	}

	meta := OAuthMetadata{
		Issuer:                 base,
		AuthorizationEndpoint:  base + "/authorize",
		TokenEndpoint:          base + "/oauth/token",
		IntrospectionEndpoint:  base + "/oauth/introspect",
		RevocationEndpoint:     base + "/revoke",
		JwksURI:                jwksURI,
		UserinfoEndpoint:       base + "/userinfo",
		ScopesSupported:        h.scopes(),
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
		// Confidential clients authenticate with a secret (Basic or POST);
		// public clients use PKCE with no client secret.
		TokenEndpointAuthMethodsSupported:         []string{"client_secret_basic", "client_secret_post", "none"},
		IntrospectionEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		RevocationEndpointAuthMethodsSupported:    []string{"client_secret_basic", "client_secret_post"},
		// PKCE: S256 only (OAuth 2.1 / RFC 9700 — plain is not advertised).
		CodeChallengeMethodsSupported: []string{"S256"},
		ACRValuesSupported:            h.acrValues(),
		ClaimsSupported:               h.claims(),
	}

	httputil.WriteJSON(w, http.StatusOK, meta)
}

func (h *OAuthMetadataHandler) scopes() []string {
	if len(h.ScopesSupported) > 0 {
		return h.ScopesSupported
	}
	return []string{"openid", "profile", "email", "offline_access"}
}

func (h *OAuthMetadataHandler) claims() []string {
	if len(h.ClaimsSupported) > 0 {
		return h.ClaimsSupported
	}
	return []string{"sub", "email", "email_verified", "name", "acr", "amr", "iss", "aud", "exp", "iat"}
}

func (h *OAuthMetadataHandler) acrValues() []string {
	if len(h.ACRValuesSupported) > 0 {
		return h.ACRValuesSupported
	}
	// Fallback (analogous to scopes()/claims()) so acr_values_supported is never
	// null: NIST-AAL values the OP advertises and the auth server derives into
	// the acr claim. With ,omitempty this could never serialize as null anyway,
	// but the hardcoded default keeps the field present and truthful.
	return []string{"aal1", "aal2"}
}
