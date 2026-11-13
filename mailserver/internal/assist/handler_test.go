// Package assist — handler tests for POST /assist/complete.
// All fakes are injected; no DB required.
package assist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	sharedassist "setjoin.com/shared/assist"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/jwtutil"
)

// ── fakes ────────────────────────────────────────────────────────────────────

// fakeProvider implements sharedassist.Provider.
type fakeProvider struct {
	resp sharedassist.Response
	err  error
	// called is set to true when Complete is invoked.
	called bool
}

func (f *fakeProvider) Complete(_ context.Context, _ sharedassist.Request) (sharedassist.Response, error) {
	f.called = true
	return f.resp, f.err
}

// fakeGate implements assistGate.
type fakeGate struct {
	// allow controls what Allowed returns.
	allow bool
}

func (g *fakeGate) Allowed(_ context.Context, _ int64) bool {
	return g.allow
}

// fakeConfigReader implements configReader (same interface as config.go uses).
type fakeConfigReader struct {
	data map[string]string
	err  error
}

func (f *fakeConfigReader) Get(_ context.Context, key string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.data[key], nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

// claimsCtx returns a context with a valid auth.Claims attached (user ID 99).
func claimsCtx() context.Context {
	claims := &auth.Claims{
		UserID: 99,
		Email:  "alice@example.com",
		Type:   jwtutil.TypeAccess,
	}
	return auth.ContextWithUser(context.Background(), claims)
}

// configuredReader returns a fakeConfigReader with all three keys set.
func configuredReader() *fakeConfigReader {
	return &fakeConfigReader{data: map[string]string{
		"assist.provider_url": "http://localhost:11434/v1",
		"assist.model":        "llama3",
		"assist.api_key":      "sk-test",
	}}
}

// goodBody returns a JSON body for a valid Complete request.
func goodBody() []byte {
	b, _ := json.Marshal(sharedassist.Request{
		Messages: []sharedassist.Message{{Role: "user", Content: "hello"}},
	})
	return b
}

// newHandler constructs a Handler with all fakes wired.
func newHandler(p sharedassist.Provider, gate assistGate, cfg configReader) *Handler {
	return &Handler{provider: p, gate: gate, cfgReader: cfg}
}

// ── tests ─────────────────────────────────────────────────────────────────────

// TestComplete_GateOff: feature.assist disabled → 403; provider NOT called.
func TestComplete_GateOff(t *testing.T) {
	prov := &fakeProvider{}
	h := newHandler(prov, &fakeGate{allow: false}, configuredReader())

	req := httptest.NewRequest(http.MethodPost, "/assist/complete", bytes.NewReader(goodBody()))
	req = req.WithContext(claimsCtx())
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.Complete(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("got status %d, want 403", rr.Code)
	}
	if prov.called {
		t.Error("provider should NOT be called when gate is off")
	}

	// Assert the 403 body type is the forbidden constant.
	var prob httputil.Problem
	if err := json.Unmarshal(rr.Body.Bytes(), &prob); err != nil {
		t.Fatalf("response is not a Problem JSON: %v", err)
	}
	if prob.Type != httputil.TypeForbidden {
		t.Errorf("problem type = %q, want %q", prob.Type, httputil.TypeForbidden)
	}
}

// TestComplete_OK: configured + enabled + valid body → 200 with {content}.
func TestComplete_OK(t *testing.T) {
	prov := &fakeProvider{resp: sharedassist.Response{Content: "world"}}
	h := newHandler(prov, &fakeGate{allow: true}, configuredReader())

	req := httptest.NewRequest(http.MethodPost, "/assist/complete", bytes.NewReader(goodBody()))
	req = req.WithContext(claimsCtx())
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.Complete(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("got status %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if resp["content"] != "world" {
		t.Errorf("content = %q, want %q", resp["content"], "world")
	}
}

// TestComplete_EmptyMessages: empty messages → 400 validation problem.
func TestComplete_EmptyMessages(t *testing.T) {
	prov := &fakeProvider{}
	h := newHandler(prov, &fakeGate{allow: true}, configuredReader())

	body, _ := json.Marshal(sharedassist.Request{Messages: nil})
	req := httptest.NewRequest(http.MethodPost, "/assist/complete", bytes.NewReader(body))
	req = req.WithContext(claimsCtx())
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.Complete(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("got status %d, want 422", rr.Code)
	}
	var prob httputil.Problem
	if err := json.Unmarshal(rr.Body.Bytes(), &prob); err != nil {
		t.Fatalf("response is not a Problem JSON: %v", err)
	}
	if prob.Type != httputil.TypeValidationFailed {
		t.Errorf("problem type = %q, want %q", prob.Type, httputil.TypeValidationFailed)
	}
}

// TestComplete_ProviderError: provider error → 502 problem; upstream body NOT leaked.
func TestComplete_ProviderError(t *testing.T) {
	prov := &fakeProvider{err: errors.New("connection refused")}
	h := newHandler(prov, &fakeGate{allow: true}, configuredReader())

	req := httptest.NewRequest(http.MethodPost, "/assist/complete", bytes.NewReader(goodBody()))
	req = req.WithContext(claimsCtx())
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.Complete(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("got status %d, want 502", rr.Code)
	}
	// The raw error text must not appear in the response body.
	if bytes.Contains(rr.Body.Bytes(), []byte("connection refused")) {
		t.Error("upstream error should not be leaked to clients")
	}
}

// TestComplete_ErrNotConfigured: config missing → 503 problem.
func TestComplete_ErrNotConfigured(t *testing.T) {
	prov := &fakeProvider{}
	// Empty reader → no provider_url → ErrNotConfigured.
	h := newHandler(prov, &fakeGate{allow: true}, &fakeConfigReader{data: map[string]string{}})

	req := httptest.NewRequest(http.MethodPost, "/assist/complete", bytes.NewReader(goodBody()))
	req = req.WithContext(claimsCtx())
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.Complete(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("got status %d, want 503", rr.Code)
	}
	var prob httputil.Problem
	if err := json.Unmarshal(rr.Body.Bytes(), &prob); err != nil {
		t.Fatalf("response is not a Problem JSON: %v", err)
	}
	if prob.Type != httputil.TypeServiceUnavailable {
		t.Errorf("problem type = %q, want %q", prob.Type, httputil.TypeServiceUnavailable)
	}
}

// TestStream_ReturnsNotImplemented: POST /assist/stream always 501.
func TestStream_ReturnsNotImplemented(t *testing.T) {
	h := newHandler(&fakeProvider{}, &fakeGate{allow: true}, configuredReader())

	req := httptest.NewRequest(http.MethodPost, "/assist/stream", nil)
	req = req.WithContext(claimsCtx())
	rr := httptest.NewRecorder()

	h.Stream(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Errorf("got status %d, want 501", rr.Code)
	}
}
