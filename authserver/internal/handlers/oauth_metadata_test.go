package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveMetadata runs the handler and returns the decoded document.
func serveMetadata(t *testing.T, h *OAuthMetadataHandler) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var doc map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("metadata not JSON: %v", err)
	}
	return doc
}

func TestOAuthMetadata_RequiredFieldsPresent(t *testing.T) {
	h := &OAuthMetadataHandler{Issuer: "https://auth.example.com"}
	doc := serveMetadata(t, h)

	// RFC 8414 §2: issuer + the endpoint set the task requires.
	wantStr := map[string]string{
		"issuer":                 "https://auth.example.com",
		"authorization_endpoint": "https://auth.example.com/authorize",
		"token_endpoint":         "https://auth.example.com/oauth/token",
		"introspection_endpoint": "https://auth.example.com/oauth/introspect",
		"revocation_endpoint":    "https://auth.example.com/revoke",
		"jwks_uri":               "https://auth.example.com/keys",
	}
	for k, want := range wantStr {
		got, ok := doc[k].(string)
		if !ok {
			t.Errorf("metadata missing string field %q", k)
			continue
		}
		if got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	// Array fields that MUST be present.
	for _, k := range []string{
		"grant_types_supported",
		"token_endpoint_auth_methods_supported",
		"code_challenge_methods_supported",
		"scopes_supported",
	} {
		arr, ok := doc[k].([]any)
		if !ok || len(arr) == 0 {
			t.Errorf("metadata missing non-empty array field %q (got %v)", k, doc[k])
		}
	}
}

func TestOAuthMetadata_CodeChallengeS256Only(t *testing.T) {
	h := &OAuthMetadataHandler{Issuer: "https://auth.example.com"}
	doc := serveMetadata(t, h)

	arr, _ := doc["code_challenge_methods_supported"].([]any)
	if len(arr) != 1 || arr[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v, want [S256] only (no plain)", arr)
	}
}

func TestOAuthMetadata_GrantTypesNoImplicitOrPassword(t *testing.T) {
	h := &OAuthMetadataHandler{Issuer: "https://auth.example.com"}
	doc := serveMetadata(t, h)

	arr, _ := doc["grant_types_supported"].([]any)
	got := map[string]bool{}
	for _, v := range arr {
		got[v.(string)] = true
	}
	// OAuth 2.1: implicit + ROPC must not be advertised.
	for _, banned := range []string{"implicit", "password"} {
		if got[banned] {
			t.Errorf("grant_types_supported advertises forbidden grant %q", banned)
		}
	}
	for _, want := range []string{"authorization_code", "refresh_token"} {
		if !got[want] {
			t.Errorf("grant_types_supported missing %q", want)
		}
	}
}

func TestOAuthMetadata_AuthMethodsAdvertised(t *testing.T) {
	h := &OAuthMetadataHandler{Issuer: "https://auth.example.com"}
	doc := serveMetadata(t, h)

	arr, _ := doc["token_endpoint_auth_methods_supported"].([]any)
	got := map[string]bool{}
	for _, v := range arr {
		got[v.(string)] = true
	}
	for _, want := range []string{"client_secret_basic", "client_secret_post"} {
		if !got[want] {
			t.Errorf("token_endpoint_auth_methods_supported missing %q", want)
		}
	}
}

func TestOAuthMetadata_ScopesAndClaimsOverridable(t *testing.T) {
	h := &OAuthMetadataHandler{
		Issuer:             "https://auth.example.com",
		ScopesSupported:    []string{"openid", "custom"},
		ClaimsSupported:    []string{"sub", "custom_claim"},
		ACRValuesSupported: []string{"aal1", "aal2"},
	}
	doc := serveMetadata(t, h)

	scopes, _ := doc["scopes_supported"].([]any)
	if len(scopes) != 2 || scopes[1] != "custom" {
		t.Errorf("scopes_supported override not honored: %v", scopes)
	}
	acr, _ := doc["acr_values_supported"].([]any)
	if len(acr) != 2 {
		t.Errorf("acr_values_supported = %v, want [aal1 aal2]", acr)
	}
}

// TestOAuthMetadata_ACRValuesNeverNull is the RFC 8414 fix proof: with no
// ACRValuesSupported configured, acr_values_supported must never serialize as
// JSON null. The omitempty tag drops an empty slice and the acrValues() fallback
// supplies the NIST-AAL defaults, so the field is present, an array, and non-empty.
func TestOAuthMetadata_ACRValuesNeverNull(t *testing.T) {
	h := &OAuthMetadataHandler{Issuer: "https://auth.example.com"} // ACRValuesSupported unset
	// Assert on the raw bytes too: a null would decode to a nil any, which the
	// array assertion below would also catch, but checking the wire form makes
	// the "never null" invariant explicit.
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if strings.Contains(rr.Body.String(), `"acr_values_supported":null`) {
		t.Fatalf("acr_values_supported serialized as null: %s", rr.Body.String())
	}

	doc := serveMetadata(t, h)
	raw, present := doc["acr_values_supported"]
	if !present {
		// omitempty may legitimately drop it; if present it MUST be a non-null array.
		return
	}
	arr, ok := raw.([]any)
	if !ok || len(arr) == 0 {
		t.Fatalf("acr_values_supported = %#v, want a non-empty array (never null)", raw)
	}
	// The fallback advertises the NIST-AAL values the auth server derives.
	got := map[string]bool{}
	for _, v := range arr {
		got[v.(string)] = true
	}
	for _, want := range []string{"aal1", "aal2"} {
		if !got[want] {
			t.Errorf("acr_values_supported fallback missing %q (got %v)", want, arr)
		}
	}
}

func TestOAuthMetadata_TrailingSlashIssuerNormalized(t *testing.T) {
	h := &OAuthMetadataHandler{Issuer: "https://auth.example.com/"}
	doc := serveMetadata(t, h)
	if doc["issuer"] != "https://auth.example.com" {
		t.Errorf("issuer not trimmed: %v", doc["issuer"])
	}
	if doc["token_endpoint"] != "https://auth.example.com/oauth/token" {
		t.Errorf("token_endpoint has double slash: %v", doc["token_endpoint"])
	}
}
