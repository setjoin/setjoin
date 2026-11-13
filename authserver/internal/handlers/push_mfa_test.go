package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/token"
)

// mockPushProvider implements authn.ChallengeProvider for handler tests.
type mockPushProvider struct {
	name string
	// verifyCalled records whether VerifyChallenge ran — used by the C10
	// regression test to prove the in-band /auth/push/verify path never feeds a
	// client-submitted answer into challenge verification.
	verifyCalled bool
}

func (m *mockPushProvider) Name() string                              { return m.name }
func (m *mockPushProvider) Available(_ context.Context, _ int64) bool { return true }
func (m *mockPushProvider) GenerateChallenge(_ context.Context, _ int64, _ string) (*authn.ChallengeResponse, error) {
	return &authn.ChallengeResponse{
		Method:     "push",
		Nonce:      "test-nonce-abc",
		TTLSeconds: 120,
		Fallback:   "totp",
	}, nil
}
func (m *mockPushProvider) VerifyChallenge(_ context.Context, _ int64, _, _ string) error {
	m.verifyCalled = true
	return nil
}

// newTestAuthHandler creates an AuthHandler with a mock push MFA provider for testing.
func newTestAuthHandler() *AuthHandler {
	return NewAuthHandler(AuthHandlerConfig{
		JWT:     token.NewJWTProvider("test-secret-32-chars-long-key!!", nil, "", 3600, 86400, "test"),
		PushMFA: &mockPushProvider{name: "push"},
	})
}

// ipLimitedPushProvider also implements ipChallengeLimiter: AllowIP blocks after
// `budget` calls, and GenerateChallenge records whether it was reached so tests
// can assert the per-IP gate runs before challenge generation.
type ipLimitedPushProvider struct {
	mockPushProvider
	budget        int
	calls         int
	genCalled     bool
	lastAllowedIP string
}

func (m *ipLimitedPushProvider) AllowIP(clientIP string) bool {
	m.lastAllowedIP = clientIP
	m.calls++
	return m.calls <= m.budget
}

func (m *ipLimitedPushProvider) GenerateChallenge(ctx context.Context, uid int64, sid string) (*authn.ChallengeResponse, error) {
	m.genCalled = true
	return m.mockPushProvider.GenerateChallenge(ctx, uid, sid)
}

// TestPushMFASend_PerIPRateLimit proves the handler enforces a per-IP challenge
// budget. Against the old code there was no per-IP gate, so a single IP could
// request unlimited challenges across accounts; this test fails without the
// AllowIP check.
func TestPushMFASend_PerIPRateLimit(t *testing.T) {
	prov := &ipLimitedPushProvider{mockPushProvider: mockPushProvider{name: "push"}, budget: 2}
	h := NewAuthHandler(AuthHandlerConfig{
		JWT:     token.NewJWTProvider("test-secret-32-chars-long-key!!", nil, "", 3600, 86400, "test"),
		PushMFA: prov,
	})
	mfaToken, err := h.jwt.IssueMFAPending(42, "test@example.com")
	if err != nil {
		t.Fatalf("issue mfa token: %v", err)
	}

	send := func() int {
		body, _ := json.Marshal(map[string]string{"mfa_token": mfaToken})
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/push/send", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.42:5555"
		rr := httptest.NewRecorder()
		h.PushMFASend(rr, req)
		return rr.Code
	}

	if code := send(); code != http.StatusOK {
		t.Fatalf("request 1: got %d, want 200", code)
	}
	if code := send(); code != http.StatusOK {
		t.Fatalf("request 2: got %d, want 200", code)
	}
	prov.genCalled = false
	if code := send(); code != http.StatusTooManyRequests {
		t.Fatalf("request 3 (over budget): got %d, want 429", code)
	}
	if prov.genCalled {
		t.Error("GenerateChallenge ran despite the per-IP limit being hit — gate must short-circuit before generation")
	}
	if prov.lastAllowedIP != "203.0.113.42" {
		t.Errorf("AllowIP received client IP %q, want 203.0.113.42", prov.lastAllowedIP)
	}
}

func TestPushMFASend_MissingToken(t *testing.T) {
	h := newTestAuthHandler()
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/push/send", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PushMFASend(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing mfa_token, got %d", rr.Code)
	}
}

func TestPushMFASend_InvalidToken(t *testing.T) {
	h := newTestAuthHandler()
	body, _ := json.Marshal(map[string]string{
		"mfa_token": "not-a-valid-jwt",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/push/send", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PushMFASend(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid MFA token, got %d", rr.Code)
	}
}

func TestPushMFASend_WrongTokenType(t *testing.T) {
	h := newTestAuthHandler()
	// Issue a valid access token (not MFA-pending type) and try to use it
	accessToken, err := h.jwt.IssueAccess(42, "test@example.com", false)
	if err != nil {
		t.Fatalf("failed to issue access token: %v", err)
	}
	body, _ := json.Marshal(map[string]string{
		"mfa_token": accessToken,
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/push/send", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PushMFASend(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong token type, got %d", rr.Code)
	}
}

func TestPushMFASend_NoPushMFA(t *testing.T) {
	// AuthHandler with pushMFA=nil should return 404
	h := newMinimalAuthHandler()
	// Issue a valid MFA-pending token
	mfaToken, err := h.jwt.IssueMFAPending(42, "test@example.com")
	if err != nil {
		t.Fatalf("failed to issue MFA token: %v", err)
	}
	body, _ := json.Marshal(map[string]string{
		"mfa_token": mfaToken,
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/push/send", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PushMFASend(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 when pushMFA is nil, got %d", rr.Code)
	}
}

func TestPushMFASend_Success(t *testing.T) {
	h := newTestAuthHandler()
	mfaToken, err := h.jwt.IssueMFAPending(42, "test@example.com")
	if err != nil {
		t.Fatalf("failed to issue MFA token: %v", err)
	}
	body, _ := json.Marshal(map[string]string{
		"mfa_token": mfaToken,
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/push/send", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PushMFASend(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: body=%s", rr.Code, rr.Body.String())
	}
	// Verify response contains expected fields
	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	wantKeys := []string{"challenge_id", "mfa_method", "nonce", "ttl_seconds", "timeout"}
	for _, k := range wantKeys {
		if _, ok := resp[k]; !ok {
			t.Errorf("missing key %q in response: %v", k, resp)
		}
	}
	if resp["mfa_method"] != "push" {
		t.Errorf("mfa_method = %q, want %q", resp["mfa_method"], "push")
	}
	// SECURITY (C10): the correct number-match code must NOT be returned to the
	// login client.
	if _, ok := resp["challenge_number"]; ok {
		t.Errorf("response leaked challenge_number in-band: %v", resp)
	}
}

// TestPushMFASend_NoAnswerLeak proves the /auth/mfa/push/send response carries no
// field a password-only attacker could read and replay (C10). Against the old
// code (which emitted "challenge_number": "42") this fails.
func TestPushMFASend_NoAnswerLeak(t *testing.T) {
	h := newTestAuthHandler()
	mfaToken, err := h.jwt.IssueMFAPending(42, "test@example.com")
	if err != nil {
		t.Fatalf("issue mfa token: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"mfa_token": mfaToken})
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/push/send", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PushMFASend(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("send: got %d, want 200: %s", rr.Code, rr.Body.String())
	}
	for _, banned := range []string{"challenge_number", "challenge_code", "\"answer\""} {
		if strings.Contains(rr.Body.String(), banned) {
			t.Errorf("send response leaked %q in-band: %s", banned, rr.Body.String())
		}
	}
}

// TestPushMFAVerify_RejectsInBandAnswer proves the in-band /auth/push/verify path
// can NOT complete MFA from a client-submitted answer (the C10 bypass). It must
// neither issue tokens (200) nor feed the answer into VerifyChallenge. Against the
// old code — which called VerifyChallenge(answer) and issued tokens on success —
// this fails (verifyCalled would be true).
func TestPushMFAVerify_RejectsInBandAnswer(t *testing.T) {
	prov := &mockPushProvider{name: "push"}
	h := NewAuthHandler(AuthHandlerConfig{
		JWT:     token.NewJWTProvider("test-secret-32-chars-long-key!!", nil, "", 3600, 86400, "test"),
		PushMFA: prov,
	})
	mfaToken, err := h.jwt.IssueMFAPending(42, "test@example.com")
	if err != nil {
		t.Fatalf("issue mfa token: %v", err)
	}
	body, _ := json.Marshal(map[string]string{
		"mfa_token": mfaToken,
		"nonce":     "test-nonce-abc",
		"answer":    "42",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/push/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PushMFAVerify(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatalf("in-band answer was accepted (got 200) — 2FA bypass")
	}
	if prov.verifyCalled {
		t.Error("PushMFAVerify fed a client-submitted answer into VerifyChallenge — the answer must be verified out-of-band only")
	}
	// No access/refresh cookies may be set by a rejected in-band answer.
	for _, c := range rr.Result().Cookies() {
		if c.Name == "token" || c.Name == "refresh_token" {
			t.Errorf("rejected in-band answer still set auth cookie %q", c.Name)
		}
	}
}

// TestNoInBandChallengeNumberEmitted is a machine guard (not a manual sweep): no
// non-test handler source may emit "challenge_number", so a future edit can't
// silently re-open the C10 leak in any login/verify response builder.
func TestNoInBandChallengeNumberEmitted(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read handlers dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.Contains(string(b), "challenge_number") {
			t.Errorf("%s references \"challenge_number\": the number-match answer must never be emitted in-band (C10)", name)
		}
	}
}

func TestPushMFAVerify_MissingFields(t *testing.T) {
	h := newTestAuthHandler()
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/push/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PushMFAVerify(rr, req)
	// Empty mfa_token fails JWT validation → 401
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing mfa_token, got %d", rr.Code)
	}
}

func TestPushMFAVerify_InvalidToken(t *testing.T) {
	h := newTestAuthHandler()
	body, _ := json.Marshal(map[string]string{
		"mfa_token": "not-valid",
		"nonce":     "abc123",
		"answer":    "42",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/push/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PushMFAVerify(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid MFA token, got %d", rr.Code)
	}
}

func TestPushMFAVerify_WrongTokenType(t *testing.T) {
	h := newTestAuthHandler()
	accessToken, err := h.jwt.IssueAccess(42, "test@example.com", false)
	if err != nil {
		t.Fatalf("failed to issue access token: %v", err)
	}
	body, _ := json.Marshal(map[string]string{
		"mfa_token": accessToken,
		"nonce":     "abc123",
		"answer":    "42",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/push/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PushMFAVerify(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong token type, got %d", rr.Code)
	}
}

func TestPushMFASendEmptyBody(t *testing.T) {
	h := newTestAuthHandler()
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/push/send", bytes.NewReader([]byte("")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PushMFASend(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty body, got %d", rr.Code)
	}
}

func TestPushMFAHandler_MethodsExist(t *testing.T) {
	h := newMinimalAuthHandler()
	if h == nil {
		t.Fatal("AuthHandler creation failed")
	}
	// Ensure the token types are importable
	_ = token.TypeMFAPending
	_ = token.TypeAccess
}
