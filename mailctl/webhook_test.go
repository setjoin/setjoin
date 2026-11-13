package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWebhookRotateSecretPrintsSecret pins commit 69a5bae3: rotate-secret used
// to discard the server's returned "secret" field entirely, leaving the
// operator with a rotated-but-unknown secret and a broken HMAC integration.
// The fixed runWebhook (commands.go rotate-secret case) must print the new
// secret to stdout.
func TestWebhookRotateSecretPrintsSecret(t *testing.T) {
	const wantSecret = "rotated-secret-abc123def456"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("rotate-secret: expected POST, got %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/admin/webhooks/42/rotate-secret") {
			t.Errorf("rotate-secret: unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"secret": wantSecret})
	}))
	defer srv.Close()

	c := &cmdCtx{client: stubClient(srv), json: false, quiet: false}

	out := captureStdout(t, func() {
		if err := runWebhook(c, "rotate-secret", []string{"42"}); err != nil {
			t.Fatalf("rotate-secret: %v", err)
		}
	})

	if !strings.Contains(out, wantSecret) {
		t.Errorf("rotate-secret output must contain the new secret %q, got: %q", wantSecret, out)
	}
}

// TestWebhookRotateSecretJSONModePrintsSecret is the --json-mode sibling: the
// raw JSON result (still containing "secret") is printed instead of the
// human-readable message, so the secret must be present there too.
func TestWebhookRotateSecretJSONModePrintsSecret(t *testing.T) {
	const wantSecret = "rotated-secret-json-xyz789"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"secret": wantSecret})
	}))
	defer srv.Close()

	c := &cmdCtx{client: stubClient(srv), json: true, quiet: false}

	out := captureStdout(t, func() {
		if err := runWebhook(c, "rotate-secret", []string{"7"}); err != nil {
			t.Fatalf("rotate-secret: %v", err)
		}
	})

	if !strings.Contains(out, wantSecret) {
		t.Errorf("rotate-secret --json output must contain the new secret %q, got: %q", wantSecret, out)
	}
}
