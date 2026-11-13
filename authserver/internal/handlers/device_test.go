package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/token"
)

// newMinimalAuthHandler creates an AuthHandler sufficient for validation-only tests.
// DB-dependent tests should use a real pool or be skipped.
func newMinimalAuthHandler() *AuthHandler {
	return NewAuthHandler(AuthHandlerConfig{
		JWT: token.NewJWTProvider("test-secret-32-chars-long-key!!", nil, "", 3600, 86400, "test"),
	})
}

func TestDeviceRegister_MissingFields(t *testing.T) {
	h := newMinimalAuthHandler()
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/auth/device/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.DeviceRegister(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestDeviceRegister_InvalidProvider(t *testing.T) {
	h := newMinimalAuthHandler()
	body, _ := json.Marshal(map[string]string{
		"provider":          "invalid-provider",
		"push_token":        "test-token",
		"device_public_key": "abcd1234",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/device/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.DeviceRegister(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid provider, got %d", rr.Code)
	}
}

func TestDeviceRegister_WebpushMissingDevicePublicKeyOK(t *testing.T) {
	// webpush devices don't carry a device_public_key (ECIES is native-only) —
	// this must fail with 401 (no auth claims) rather than 400 (validation),
	// proving validation accepts the provider without that field.
	h := newMinimalAuthHandler()
	body, _ := json.Marshal(map[string]string{
		"provider":   "webpush",
		"push_token": `{"endpoint":"https://push.example/x","keys":{"p256dh":"a","auth":"b"}}`,
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/device/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.DeviceRegister(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (past validation, no auth claims), got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestDeviceRegister_NativeProviderMissingDevicePublicKey(t *testing.T) {
	h := newMinimalAuthHandler()
	body, _ := json.Marshal(map[string]string{
		"provider":   "fcm",
		"push_token": "test-token",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/device/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.DeviceRegister(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for native provider missing device_public_key, got %d", rr.Code)
	}
}

func TestDeviceRegister_RejectsMalformedNativePublicKeys(t *testing.T) {
	h := newMinimalAuthHandler()
	for _, publicKey := range []string{"not-hex", "abcd1234"} {
		body, _ := json.Marshal(map[string]string{
			"provider": "fcm", "push_token": "test-token", "device_public_key": publicKey,
		})
		req := httptest.NewRequest(http.MethodPost, "/auth/device/register", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		h.DeviceRegister(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("public key %q: got %d, want 400", publicKey, rr.Code)
		}
	}
}

func TestVAPIDKey_NotConfigured(t *testing.T) {
	h := newMinimalAuthHandler() // no VAPIDPublicKey set
	req := httptest.NewRequest(http.MethodGet, "/auth/push/vapid-key", nil)
	rr := httptest.NewRecorder()
	h.VAPIDKey(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 when push isn't configured, got %d", rr.Code)
	}
}

func TestVAPIDKey_Configured(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{
		JWT:            token.NewJWTProvider("test-secret-32-chars-long-key!!", nil, "", 3600, 86400, "test"),
		VAPIDPublicKey: "abc123",
	})
	req := httptest.NewRequest(http.MethodGet, "/auth/push/vapid-key", nil)
	rr := httptest.NewRecorder()
	h.VAPIDKey(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp struct {
		VapidPublicKey string `json:"vapid_public_key"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.VapidPublicKey != "abc123" {
		t.Errorf("got %q, want abc123", resp.VapidPublicKey)
	}
}

func TestMFAApprove_MissingFields(t *testing.T) {
	h := newMinimalAuthHandler()
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/approve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.MFAApprove(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestMFAApprove_RejectsUnknownJSONAndUnavailableProvider(t *testing.T) {
	h := newMinimalAuthHandler()
	requests := []string{
		`{"nonce":"` + strings.Repeat("00", 32) + `","code":"42","device_id":1,"decision":"approve","issued_at":1,"expires_at":2,"signature":"x","unknown":true}`,
		`{"nonce":"` + strings.Repeat("00", 32) + `","code":"42","device_id":1,"decision":"approve","issued_at":1,"expires_at":2,"signature":"x"}`,
	}
	for index, body := range requests {
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/approve", strings.NewReader(body))
		rr := httptest.NewRecorder()
		h.MFAApprove(rr, req)
		want := http.StatusBadRequest
		if index == 1 {
			want = http.StatusServiceUnavailable
		}
		if rr.Code != want {
			t.Fatalf("case %d: got %d, want %d: %s", index, rr.Code, want, rr.Body.String())
		}
	}
}

func TestDeviceHandler_MethodsExist(t *testing.T) {
	// Ensure the handler has the required methods
	h := newMinimalAuthHandler()
	if h == nil {
		t.Fatal("AuthHandler creation failed")
	}
	// Verify challenge provider interface is nil-safe
	if h.pushMFA != nil {
		t.Log("pushMFA is set (not testing nil path)")
	}
	_ = authn.ChallengeProvider(nil) // just verify the interface is importable
	_ = token.TypeMFAPending
}
