package handlers

// ER5 er5-s08 occurrence test (ssrf.webpush-unvalidated-endpoint): the WebPush
// registration path must refuse an attacker-chosen subscription endpoint — the
// outbound delivery target for every future challenge — using the shared SSRF
// guard (shared/ssrf.ValidateURL: scheme + host + literal-IP checks), BEFORE the
// endpoint is ever persisted. Also pins the body/subscription size bounds.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postDeviceRegister(h *AuthHandler, payload map[string]any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/auth/device/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.DeviceRegister(rr, req)
	return rr
}

// TestDeviceRegister_WebPushEndpointSSRFRefused proves the registration-time
// SSRF fence: unsafe endpoints are refused 400 at the validation layer (which
// runs BEFORE the auth gate — a 400, not a 401, proves the fence fired), while
// a legitimate public HTTPS push service endpoint passes validation and reaches
// the auth gate (401 with no credentials).
func TestDeviceRegister_WebPushEndpointSSRFRefused(t *testing.T) {
	h := newMinimalAuthHandler()

	refused := map[string]string{
		"loopback ipv4":       `{"endpoint":"http://127.0.0.1:9090/hook","keys":{"p256dh":"a","auth":"b"}}`,
		"loopback hostname":   `{"endpoint":"http://localhost:9090/hook","keys":{"p256dh":"a","auth":"b"}}`,
		"private range":       `{"endpoint":"https://10.1.2.3/push","keys":{"p256dh":"a","auth":"b"}}`,
		"metadata link-local": `{"endpoint":"http://169.254.169.254/latest/meta-data","keys":{"p256dh":"a","auth":"b"}}`,
		"file scheme":         `{"endpoint":"file:///etc/passwd","keys":{"p256dh":"a","auth":"b"}}`,
		"missing endpoint":    `{"keys":{"p256dh":"a","auth":"b"}}`,
		"not json":            `just-a-token-string`,
	}
	for name, token := range refused {
		rr := postDeviceRegister(h, map[string]any{"provider": "webpush", "push_token": token})
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400 (endpoint must be refused pre-persistence): %s", name, rr.Code, rr.Body.String())
		}
	}

	rr := postDeviceRegister(h, map[string]any{
		"provider":   "webpush",
		"push_token": `{"endpoint":"https://push.example.com/send/x","keys":{"p256dh":"a","auth":"b"}}`,
	})
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("legitimate public endpoint: got %d, want 401 (validation passed, auth gate reached): %s", rr.Code, rr.Body.String())
	}
}

// TestDeviceRegister_NativeProviderUntouchedByWebPushFence guards the fence's
// blast radius: native ECIES providers carry no endpoint URL, so a native
// registration with a VALID device key passes validation and reaches the auth
// gate (401 with no credentials) — the fence refuses webpush endpoints only.
func TestDeviceRegister_NativeProviderUntouchedByWebPushFence(t *testing.T) {
	h := newMinimalAuthHandler()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(elliptic.Marshal(elliptic.P256(), key.X, key.Y))
	rr := postDeviceRegister(h, map[string]any{
		"provider":          "fcm",
		"push_token":        "native-token-not-a-subscription-json",
		"device_public_key": pubHex,
	})
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("native provider: got %d, want 401 (past validation, no auth claims): %s", rr.Code, rr.Body.String())
	}
}

// TestDeviceRegister_BodyCapRefused oversized: the 1 MiB MaxBytesReader refuses
// a body beyond the bound with 400 before any decode work (worker-admission
// bounds genre; oversized-body rejection reads as a decode failure 400).
func TestDeviceRegister_BodyCapRefused(t *testing.T) {
	h := newMinimalAuthHandler()
	huge := `{"provider":"webpush","push_token":"` + strings.Repeat("x", 2<<20) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/device/register", strings.NewReader(huge))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.DeviceRegister(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("oversized body: got %d, want 400", rr.Code)
	}
}

// TestWebpushEndpointSizeBound pins the persisted-subscription size bound.
func TestWebpushEndpointSizeBound(t *testing.T) {
	tooBig := `{"endpoint":"https://push.example.com/x","pad":"` + strings.Repeat("a", maxWebPushSubscriptionBytes+1) + `"}`
	if _, err := webpushEndpoint(tooBig); err == nil {
		t.Fatal("subscription beyond the size bound must be refused")
	}
	ok := `{"endpoint":"https://push.example.com/x","keys":{"p256dh":"a","auth":"b"}}`
	if _, err := webpushEndpoint(ok); err != nil {
		t.Fatalf("legitimate subscription refused: %v", err)
	}
}

// TestUHost pins the endpoint hostname extraction used for the loopback-name
// guard (and its defensive unparseable-input leg).
func TestUHost(t *testing.T) {
	if got := uHost("https://Push.Example.COM:443/x"); got != "Push.Example.COM" {
		t.Errorf("uHost = %q, want Push.Example.COM (raw hostname; the caller lowercases)", got)
	}
	if got := uHost("http://[2001:db8::1]/x"); got != "2001:db8::1" {
		t.Errorf("uHost = %q, want 2001:db8::1", got)
	}
	if got := uHost("http://[::1:80/x"); got != "" {
		t.Errorf("uHost on an unparseable URL = %q, want \"\"", got)
	}
}
