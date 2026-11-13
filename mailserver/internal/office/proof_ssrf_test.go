package office

// Runtime-fetch SSRF wiring tests (er5-s15, sealed anchors
// wopi-proof-discovery-runtime-client ×2): the PRODUCTION proof verifier
// (newProofVerifier(nil)) must dial through the repo-standard ssrf guard —
// resolved A/AAAA answers checked at dial time with private addresses
// blocked — so a DNS repoint of an allow-listed discovery hostname cannot
// pivot the runtime fetch at internal addresses. The sealed defect class is
// the runtime fetch, not URL string validation (already covered by
// TestDiscoveryURLAndRedirectOriginValidation); these tests pin the wiring.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestProofDiscoveryRuntimeFetch_DialTimePrivateAddressRefusal: the
// production client refuses to fetch discovery from a private/loopback
// address AT DIAL TIME (httptest always binds 127.0.0.1) — the fetch fails
// with the guard's refusal, never the document's content. An injected plain
// client against the same server succeeds, proving the refusal comes from
// the production wiring, not the URL or the fixture.
func TestProofDiscoveryRuntimeFetch_DialTimePrivateAddressRefusal(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048) // passes the 2048-bit proof floor
	if err != nil {
		t.Fatal(err)
	}
	doc := `<?xml version="1.0"?>
<wopi-discovery>
  <proof-key modulus="` + base64.StdEncoding.EncodeToString(key.PublicKey.N.Bytes()) +
		`" exponent="` + base64.StdEncoding.EncodeToString([]byte{1, 0, 1}) + `"/>
</wopi-discovery>`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(doc))
	}))
	t.Cleanup(srv.Close)

	guarded := newProofVerifier(nil) // the production wiring: no client injected
	if _, err := guarded.keys(context.Background(), srv.URL+"/hosting/discovery"); err == nil {
		t.Fatal("production proof client fetched discovery from loopback; want dial-time ssrf refusal")
	} else if !strings.Contains(err.Error(), "not allowed") && !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("refusal error = %v; want the ssrf dial guard's message (ErrUnsafeURL wraps \"not allowed\")", err)
	}

	naive := newProofVerifier(srv.Client()) // test seam: plain client, no guard
	keys, err := naive.keys(context.Background(), srv.URL+"/hosting/discovery")
	if err != nil {
		t.Fatalf("injected plain client could not fetch the same URL: %v", err)
	}
	if keys.current == nil {
		t.Fatal("plain client fetched discovery but parsed no key; fixture broken")
	}
}
