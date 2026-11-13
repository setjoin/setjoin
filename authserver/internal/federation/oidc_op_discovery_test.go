package federation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/jwtutil"
)

// fakeDiscoveryHandler stands in for the zitadel OP, emitting a minimal
// discovery document (without acr_values_supported, as zitadel does) and a
// distinct body for any other path so pass-through can be asserted.
type fakeDiscoveryHandler struct{}

func (fakeDiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/.well-known/openid-configuration" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                        "https://idp.example.com",
			"claims_supported":              []string{"sub", "acr", "amr"},
			"response_types_supported":      []string{"code", "id_token"},
			"grant_types_supported":         []string{"authorization_code", "implicit"},
			"device_authorization_endpoint": "https://idp.example.com/device_authorization",
		})
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Write([]byte(`{"keys":[]}`))
}

func TestOPDiscoveryWrapper_AdvertisesACRValues(t *testing.T) {
	h := NewOPDiscoveryWrapper(fakeDiscoveryHandler{})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("discovery body not JSON: %v", err)
	}

	raw, ok := doc["acr_values_supported"]
	if !ok {
		t.Fatal("discovery missing acr_values_supported")
	}
	vals, _ := raw.([]any)
	got := map[string]bool{}
	for _, v := range vals {
		if s, ok := v.(string); ok {
			got[s] = true
		}
	}
	for _, want := range []string{jwtutil.ACRAAL1, jwtutil.ACRAAL2} {
		if !got[want] {
			t.Errorf("acr_values_supported missing %q (got %v)", want, vals)
		}
	}

	// Existing fields preserved.
	if doc["issuer"] != "https://idp.example.com" {
		t.Errorf("issuer not preserved: %v", doc["issuer"])
	}
}

// TestOPDiscoveryWrapper_InjectsMissingConformanceFields proves the wrapper
// guarantees scopes_supported, claims_supported, and code_challenge_methods_supported
// when the OP omits them — so OAuth/OIDC clients always discover them.
func TestOPDiscoveryWrapper_InjectsMissingConformanceFields(t *testing.T) {
	h := NewOPDiscoveryWrapper(fakeDiscoveryHandler{})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	var doc map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("discovery body not JSON: %v", err)
	}

	// scopes_supported and code_challenge_methods_supported were absent in the
	// fake OP response; the wrapper must inject them.
	if _, ok := doc["scopes_supported"]; !ok {
		t.Error("discovery missing scopes_supported (should be injected)")
	}
	ccm, ok := doc["code_challenge_methods_supported"].([]any)
	if !ok || len(ccm) != 1 || ccm[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v, want [S256]", doc["code_challenge_methods_supported"])
	}

	// claims_supported was provided by the fake OP — must NOT be clobbered.
	claims, _ := doc["claims_supported"].([]any)
	got := map[string]bool{}
	for _, c := range claims {
		got[c.(string)] = true
	}
	if !got["sub"] || !got["acr"] || !got["amr"] {
		t.Errorf("OP-provided claims_supported was clobbered: %v", claims)
	}
	// The fake OP's claims_supported had exactly 3 entries; injection must not
	// have replaced it with the fuller fallback.
	if len(claims) != 3 {
		t.Errorf("claims_supported len = %d, want 3 (OP value preserved, not clobbered)", len(claims))
	}

	responseTypes, _ := doc["response_types_supported"].([]any)
	if len(responseTypes) != 1 || responseTypes[0] != "code" {
		t.Errorf("response_types_supported = %v, want [code]", responseTypes)
	}
	grantTypes, _ := doc["grant_types_supported"].([]any)
	if len(grantTypes) != 2 ||
		grantTypes[0] != "authorization_code" ||
		grantTypes[1] != "refresh_token" {
		t.Errorf("grant_types_supported = %v, want authorization_code + refresh_token", grantTypes)
	}
	if _, advertised := doc["device_authorization_endpoint"]; advertised {
		t.Error("unsupported device_authorization_endpoint must not be advertised")
	}
}

func TestOPDiscoveryWrapper_PassesThroughNonDiscovery(t *testing.T) {
	h := NewOPDiscoveryWrapper(fakeDiscoveryHandler{})

	req := httptest.NewRequest(http.MethodGet, "/keys", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Body.String() != `{"keys":[]}` {
		t.Errorf("non-discovery path body mutated: %q", rr.Body.String())
	}
	if _, exists := func() (any, bool) {
		var m map[string]any
		json.Unmarshal(rr.Body.Bytes(), &m)
		v, ok := m["acr_values_supported"]
		return v, ok
	}(); exists {
		t.Error("acr_values_supported must not be injected into non-discovery responses")
	}
}

func TestStoredAuthRequest_ACRFloor(t *testing.T) {
	// A request with no recorded context reports the aal1/[pwd] floor — never the
	// empty values the zitadel interface defaults to.
	r := &storedAuthRequest{}
	if r.GetACR() != jwtutil.ACRAAL1 {
		t.Errorf("GetACR() = %q, want aal1 floor", r.GetACR())
	}
	amr := r.GetAMR()
	if len(amr) != 1 || amr[0] != jwtutil.AMRPassword {
		t.Errorf("GetAMR() = %v, want [pwd] floor", amr)
	}

	// A recorded stronger context is reflected verbatim.
	r2 := (&storedAuthRequest{}).withAuthContext(jwtutil.ACRAAL2, []string{jwtutil.AMRPassword, jwtutil.AMROTP, jwtutil.AMRMultiFactor})
	if r2.GetACR() != jwtutil.ACRAAL2 {
		t.Errorf("GetACR() = %q, want aal2", r2.GetACR())
	}
	if len(r2.GetAMR()) != 3 {
		t.Errorf("GetAMR() = %v, want 3 entries", r2.GetAMR())
	}
}
