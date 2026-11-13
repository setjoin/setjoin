package handlers

// Tests for Task 6: CA login seam — signInRecorder wiring + correlation ID header/body.
//
// Pattern mirrors device_trust_test.go: build deps{} directly, no DB needed.
// evaluateAndRespond is extracted from Login for this test + future IMAP/SMTP seams.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

// -- fake helpers --

// captureRecorder records the last Record call for assertion.
type captureRecorder struct {
	called bool
	result threat.PolicyResult
}

func (c *captureRecorder) Record(_ context.Context, _ threat.PolicyEvalContext, res threat.PolicyResult) {
	c.called = true
	c.result = res
}

// staticPolicyStore implements threat.PolicyStore with a fixed row set.
// ponytail: Country="" + ipRisk=nil means only LoadAllPolicies is called in Evaluate.
type staticPolicyStore struct {
	rows []threat.PolicyRow
}

func (s *staticPolicyStore) LoadAllPolicies(_ context.Context) ([]threat.PolicyRow, error) {
	return s.rows, nil
}
func (s *staticPolicyStore) LoadPolicies(_ context.Context, _ threat.PolicyEvalContext) ([]threat.PolicyRow, error) {
	return s.rows, nil
}
func (s *staticPolicyStore) ResolveGeoTier(_ context.Context, _ string) (string, error) {
	return "low", nil
}
func (s *staticPolicyStore) LoadBreakGlass(_ context.Context) ([]int64, error) { return nil, nil }
func (s *staticPolicyStore) LoadNamedLocations(_ context.Context) ([]threat.NamedLocation, error) {
	return nil, nil
}
func (s *staticPolicyStore) LoadAuthStrengths(_ context.Context) ([]threat.AuthStrength, error) {
	return nil, nil
}

func newBlockEngine() *threat.PolicyEngine {
	return threat.NewPolicyEngine(
		&staticPolicyStore{rows: []threat.PolicyRow{
			{ID: 1, Name: "block-all", State: "on", ScopeType: "global",
				Conditions: map[string]interface{}{},
				Actions:    map[string]interface{}{"action": "block"}},
		}},
		toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true}),
		nil, nil, discardLogger(), false,
	)
}

func newStepUpEngine() *threat.PolicyEngine {
	return threat.NewPolicyEngine(
		&staticPolicyStore{rows: []threat.PolicyRow{
			{ID: 2, Name: "step-up-all", State: "on", ScopeType: "global",
				Conditions: map[string]interface{}{},
				Actions:    map[string]interface{}{"action": "step_up", "methods": []string{"totp"}}},
		}},
		toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true}),
		nil, nil, discardLogger(), false,
	)
}

func testPectx() threat.PolicyEvalContext {
	return threat.PolicyEvalContext{
		UserID:      42,
		SourceIP:    "203.0.113.5",
		AuthMethod:  "password",
		ClientType:  threat.ClientTypeWeb,
		Protocol:    threat.ProtocolHTTP,
		RequestTime: time.Now(),
	}
}

// -- tests --

// TestCARecorder_BlockRecordsAndSetsHeader: core wiring — Record called, header set, detail has ref.
func TestCARecorder_BlockRecordsAndSetsHeader(t *testing.T) {
	rec := &captureRecorder{}
	d := &deps{
		policyEngine:   newBlockEngine(),
		signInRecorder: rec,
		logger:         discardLogger(),
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)

	blocked, _ := (&loginHandler{d}).evaluateAndRespond(w, r, testPectx(), 42, "u@example.com", CompletionRequest{Factors: []string{token.AMRPassword}})
	if !blocked {
		t.Fatal("evaluateAndRespond must return true on block")
	}
	if !rec.called {
		t.Fatal("signInRecorder.Record must be called after every CA evaluation")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("block must 403, got %d", w.Code)
	}
	corrID := w.Header().Get("X-CA-Correlation-Id")
	if corrID == "" {
		t.Fatal("X-CA-Correlation-Id header must be set on block")
	}
	if !strings.HasPrefix(corrID, "CA-") {
		t.Fatalf("correlation id must have CA- prefix, got %q", corrID)
	}
	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)
	detail, _ := body["detail"].(string)
	if !strings.Contains(detail, corrID) {
		t.Fatalf("403 detail must contain correlation id %q; got %q", corrID, detail)
	}
	if rec.result.CorrelationID != corrID {
		t.Fatalf("recorder got %q, header has %q", rec.result.CorrelationID, corrID)
	}
}

// TestCARecorder_NoopRecorder_BlockStillWorks: NoopSignInRecorder must not panic.
func TestCARecorder_NoopRecorder_BlockStillWorks(t *testing.T) {
	d := &deps{
		policyEngine:   newBlockEngine(),
		signInRecorder: threat.NoopSignInRecorder{},
		logger:         discardLogger(),
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	blocked, _ := (&loginHandler{d}).evaluateAndRespond(w, r, testPectx(), 42, "u@example.com", CompletionRequest{Factors: []string{token.AMRPassword}})
	if !blocked || w.Code != http.StatusForbidden {
		t.Fatalf("noop recorder: want blocked=true, 403; got blocked=%v, %d", blocked, w.Code)
	}
}

// TestCARecorder_StepUpRecordsAndSetsHeader: step-up path also records and stamps header.
func TestCARecorder_StepUpRecordsAndSetsHeader(t *testing.T) {
	rec := &captureRecorder{}
	d := &deps{
		policyEngine:   newStepUpEngine(),
		signInRecorder: rec,
		logger:         discardLogger(),
		jwt:            newTestJWT(),
		pool:           createClosedPool(t),
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	blocked, _ := (&loginHandler{d}).evaluateAndRespond(w, r, testPectx(), 42, "u@example.com", CompletionRequest{Factors: []string{token.AMRPassword}})
	if !blocked {
		t.Fatal("step-up must return true (response already written)")
	}
	if !rec.called {
		t.Fatal("signInRecorder.Record must be called on step-up")
	}
	// The shipped webmail client dispatches MFA on HTTP 202 + status:"mfa_required"
	// (not a 200 + boolean), so the real handler response must carry both.
	if w.Code != http.StatusAccepted {
		t.Fatalf("step-up must respond 202, got %d", w.Code)
	}
	corrID := w.Header().Get("X-CA-Correlation-Id")
	if corrID == "" {
		t.Fatal("X-CA-Correlation-Id header must be set on step-up response")
	}
	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "mfa_required" {
		t.Fatalf("step-up body status=%q, want \"mfa_required\"", body["status"])
	}
	if body["mfa_required"] != true {
		t.Fatalf("step-up body must keep mfa_required=true, got %v", body["mfa_required"])
	}
	if body["correlation_id"] != corrID {
		t.Fatalf("step-up body correlation_id=%q, header=%q", body["correlation_id"], corrID)
	}
}

// TestCARecorder_AllowDoesNotBlock: allow path returns false and does not 403.
func TestCARecorder_AllowDoesNotBlock(t *testing.T) {
	rec := &captureRecorder{}
	d := &deps{
		policyEngine: threat.NewPolicyEngine(
			&staticPolicyStore{rows: nil}, // no policies → default allow
			toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true}),
			nil, nil, discardLogger(), false,
		),
		signInRecorder: rec,
		logger:         discardLogger(),
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	blocked, _ := (&loginHandler{d}).evaluateAndRespond(w, r, testPectx(), 42, "u@example.com", CompletionRequest{Factors: []string{token.AMRPassword}})
	if blocked {
		t.Fatal("allow must return false")
	}
	if !rec.called {
		t.Fatal("signInRecorder.Record must be called on allow too")
	}
	if w.Code == http.StatusForbidden {
		t.Fatal("allow must not 403")
	}
}
