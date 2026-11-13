package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"setjoin.com/authserver/internal/token"
)

const testAPIKey = "internal-api-key-for-introspect-tests-32b"

// -- auth gate --

func TestIntrospect_RejectsUnauthenticatedJSON(t *testing.T) {
	h := &IntrospectHandler{Pool: createClosedPool(t), APIKey: testAPIKey}
	body, _ := json.Marshal(map[string]string{"token": "anything"})
	req := httptest.NewRequest("POST", "/auth/introspect", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no API key, no client auth)", rr.Code)
	}
}

func TestIntrospect_RejectsWrongAPIKey(t *testing.T) {
	h := &IntrospectHandler{Pool: createClosedPool(t), APIKey: testAPIKey}
	body, _ := json.Marshal(map[string]string{"token": "anything"})
	req := httptest.NewRequest("POST", "/auth/introspect", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer not-the-right-key")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for wrong API key", rr.Code)
	}
}

func TestIntrospect_RejectsFormWithoutClientAuth(t *testing.T) {
	// Standard RFC 7662 form request with no client credentials and no API key.
	h := &IntrospectHandler{Pool: createClosedPool(t), APIKey: testAPIKey}
	form := url.Values{"token": {"abc"}}
	req := httptest.NewRequest("POST", "/auth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no client auth)", rr.Code)
	}
}

// -- inactive response (authenticated, but token unknown) --

// withClosedPool: the API key authenticates the caller, but the token lookup
// fails against the closed pool, so Introspect returns the uniform inactive
// response — proving an authenticated caller gets {active:false}, never an
// error oracle, for a token that does not resolve.
func TestIntrospect_AuthenticatedUnknownTokenIsInactive(t *testing.T) {
	h := &IntrospectHandler{
		Pool:     createClosedPool(t),
		APIKey:   testAPIKey,
		Issuer:   "test-issuer",
		Audience: "mailserver-gateway",
	}
	body, _ := json.Marshal(map[string]string{"token": "unknown-token"})
	req := httptest.NewRequest("POST", "/auth/introspect", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if active, _ := resp["active"].(bool); active {
		t.Errorf("active = true, want false for unknown token")
	}
	// No other field may leak for an inactive token (no oracle).
	for _, leaked := range []string{"sub", "username", "email", "scope", "exp", "iss", "aud", "token_type"} {
		if _, ok := resp[leaked]; ok {
			t.Errorf("inactive response leaked field %q = %v", leaked, resp[leaked])
		}
	}
}

func TestIntrospect_MissingTokenIsBadRequest(t *testing.T) {
	h := &IntrospectHandler{Pool: createClosedPool(t), APIKey: testAPIKey}
	req := httptest.NewRequest("POST", "/auth/introspect", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for missing token", rr.Code)
	}
}

// -- RFC 7662 field set on an active response (pure serialization) --

// The DB path is exercised by the integration test; here we prove the response
// type carries the complete RFC 7662 field set and that token_type serializes
// to "Bearer" (not the raw oauth_tokens discriminator) when the token is active.
func TestIntrospectResponse_ActiveCarriesFullRFC7662Set(t *testing.T) {
	resp := &token.IntrospectResponse{
		Active:   true,
		Sub:      "42",
		Username: "alice@example.com",
		Email:    "alice@example.com",
		// RFC 7662 §2.2: scope is the space-delimited *string* form.
		Scope:     "openid email",
		ClientID:  "imap-client",
		TokenType: "Bearer",
		Iss:       "mailserver",
		Aud:       "mailserver-gateway",
		Iat:       1000,
		Nbf:       1000,
		Exp:       5000,
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	json.Unmarshal(raw, &got)

	// Every field RFC 7662 requires for our tokens must be present...
	for _, field := range []string{
		"active", "token_type", "scope", "client_id", "username",
		"sub", "aud", "iss", "exp", "iat", "nbf",
	} {
		if _, ok := got[field]; !ok {
			t.Errorf("active response missing RFC 7662 field %q", field)
		}
	}
	// ...and token_type is the Bearer token *type*, not access/refresh.
	if got["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want \"Bearer\"", got["token_type"])
	}

	// RFC 7662 §2.2: "scope" MUST serialize as a space-separated JSON *string*,
	// not a JSON array. encoding/json decodes a JSON string into a Go string and
	// a JSON array into []any, so the concrete type asserts the wire shape.
	scopeVal, ok := got["scope"].(string)
	if !ok {
		t.Fatalf("scope is %T (%v), want JSON string per RFC 7662 §2.2 (not an array)", got["scope"], got["scope"])
	}
	if scopeVal != "openid email" {
		t.Errorf("scope = %q, want %q (space-separated)", scopeVal, "openid email")
	}
}

// TestIntrospect_ScopeJoinsWithSpace proves the DB-backed Introspect() collapses
// the multi-value oauth_tokens.scope array into the single space-delimited string
// RFC 7662 §2.2 mandates (the join happens in Introspect, not just the struct tag).
func TestIntrospect_ScopeWireShapeIsString(t *testing.T) {
	// Empty scope omits the field entirely (omitempty), never "" or [].
	raw, _ := json.Marshal(&token.IntrospectResponse{Active: true, Scope: ""})
	var got map[string]any
	json.Unmarshal(raw, &got)
	if _, present := got["scope"]; present {
		t.Errorf("empty scope should be omitted, got %v", got["scope"])
	}

	// A single scope still serializes as a bare string, not a one-element array.
	raw, _ = json.Marshal(&token.IntrospectResponse{Active: true, Scope: "openid"})
	json.Unmarshal(raw, &got)
	if v, ok := got["scope"].(string); !ok || v != "openid" {
		t.Errorf("single scope = %T %v, want string \"openid\"", got["scope"], got["scope"])
	}
}

// TestIntrospect_JoinsScopeWithSpaceBySource pins that Introspect() collapses the
// oauth_tokens.scope array into a space-delimited string (RFC 7662 §2.2) rather
// than handing the raw slice to the JSON encoder — verified without a live DB.
func TestIntrospect_JoinsScopeWithSpaceBySource(t *testing.T) {
	src := funcSrc(t, "../token/introspect.go", "Introspect")
	if !strings.Contains(src, `strings.Join(scope, " ")`) {
		t.Error(`Introspect must join scopes with a single space (strings.Join(scope, " ")) per RFC 7662 §2.2`)
	}
}

func TestIntrospectResponse_InactiveIsBareObject(t *testing.T) {
	raw, _ := json.Marshal(&token.IntrospectResponse{Active: false})
	var got map[string]any
	json.Unmarshal(raw, &got)
	if len(got) != 1 {
		t.Errorf("inactive response = %v, want only {active:false}", got)
	}
	if got["active"] != false {
		t.Errorf("active = %v, want false", got["active"])
	}
}

// -- client auth via Basic header reaches the lookup (closed pool => unknown) --

func TestIntrospect_ClientBasicAuthUnknownClientRejected(t *testing.T) {
	// A Basic-auth client credential that does not resolve (closed pool) must be
	// rejected with 401, never treated as authenticated.
	h := &IntrospectHandler{Pool: createClosedPool(t), APIKey: testAPIKey}
	form := url.Values{"token": {"abc"}}
	req := httptest.NewRequest("POST", "/auth/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	basic := base64.StdEncoding.EncodeToString([]byte("some-client:some-secret"))
	req.Header.Set("Authorization", "Basic "+basic)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for unresolvable client", rr.Code)
	}
}
