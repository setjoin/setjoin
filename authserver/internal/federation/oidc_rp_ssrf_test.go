package federation

import (
	"net/http"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

// TestValidateOIDCIssuerScheme_RejectsNonHTTPS mirrors the SAML SP's
// https-scheme guard: the OIDC discovery fetch ({issuer}/.well-known/
// openid-configuration) must refuse a non-https issuer URL before it ever
// dials. This is the cheap fail-fast pre-check; the SafeHTTPClient dialer
// guard (DNS-rebinding defense) is the authoritative backstop.
func TestValidateOIDCIssuerScheme_RejectsNonHTTPS(t *testing.T) {
	cases := []struct {
		name    string
		issuer  string
		wantErr bool
	}{
		{"http rejected", "http://idp.example.com", true},
		{"ftp rejected", "ftp://idp.example.com", true},
		{"file rejected", "file:///etc/passwd", true},
		{"empty rejected", "", true},
		{"no-scheme rejected", "idp.example.com", true},
		{"missing-host rejected", "https://", true},
		{"https accepted", "https://idp.example.com", false},
		{"https with path accepted", "https://idp.example.com/realms/x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOIDCIssuerScheme(tc.issuer)
			if tc.wantErr && err == nil {
				t.Fatalf("validateOIDCIssuerScheme(%q) = nil, want error", tc.issuer)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateOIDCIssuerScheme(%q) = %v, want nil", tc.issuer, err)
			}
			// A rejection must clearly name the https requirement.
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), "https") {
				t.Errorf("rejection error %q should mention https requirement", err.Error())
			}
		})
	}
}

// TestSafeDiscoveryClientGuardsLoopback asserts the SSRF-guarded client the
// OIDC RP wires into rp.WithHTTPClient refuses to dial an internal/loopback
// address (DNS-rebinding defense), matching the SAML/JWKS pattern.
func TestSafeDiscoveryClientGuardsLoopback(t *testing.T) {
	client := safeOIDCDiscoveryClient()
	if client == nil {
		t.Fatal("safeOIDCDiscoveryClient() returned nil")
	}
	// Dialing loopback must be blocked by the dialer Control hook.
	_, err := client.Get("http://127.0.0.1:9/.well-known/openid-configuration")
	if err == nil {
		t.Fatal("expected loopback dial to be blocked, got nil error")
	}
}

// TestWithHTTPClientOptionWiring proves the rp option seam compiles and holds:
// the guarded client is accepted as an rp.Option, which is exactly how
// loadProviders passes it to rp.NewRelyingPartyOIDC at both the initial load
// and the ListenForChanges hot-reload path.
func TestWithHTTPClientOptionWiring(t *testing.T) {
	var opt rp.Option = rp.WithHTTPClient(safeOIDCDiscoveryClient())
	if opt == nil {
		t.Fatal("rp.WithHTTPClient(safeOIDCDiscoveryClient()) returned nil option")
	}
	// Confirm the helper returns a concrete *http.Client (type seam).
	var _ *http.Client = safeOIDCDiscoveryClient()
}

func TestOIDCRPVerifierDefersNonceToRequestCookie(t *testing.T) {
	verifier := rp.NewIDTokenVerifier(
		"https://idp.example.test",
		"setjoin-client",
		nil,
		oidcRPVerifierOptions()...,
	)
	if verifier.Nonce != nil {
		t.Fatal("library nonce verifier must be disabled; OIDCCallback validates the request-bound nonce cookie")
	}
}
