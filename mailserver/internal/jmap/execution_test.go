package jmap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/metrics"
	"setjoin.com/shared/pgxutil"
)

type countingEntitlementGate struct{ calls atomic.Int32 }

func (g *countingEntitlementGate) Allowed(context.Context, int64, string) bool {
	g.calls.Add(1)
	return true
}

func batchTestHandler(fn MethodFunc) *JMAPHandler {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "test.local", nil, "", 0, nil)
	h.RegisterMethod("Test/run", fn)
	return h
}

func TestExecuteBatchRequestValidationAndLimits(t *testing.T) {
	var dispatched atomic.Int32
	h := batchTestHandler(func(_ context.Context, _ *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
		dispatched.Add(1)
		return "Test/run", args
	})
	claims := &auth.Claims{UserID: 1, Type: "access"}
	call := MethodCall{Name: "Test/run", Args: json.RawMessage(`{}`), ClientID: "c0"}
	core := []string{capCore}

	cases := []struct {
		name    string
		req     BatchRequest
		wantErr string
	}{
		{"empty using", BatchRequest{MethodCalls: []MethodCall{call}}, "notRequest"},
		{"33 calls", BatchRequest{Using: core, MethodCalls: make([]MethodCall, 33)}, "requestTooLarge"},
		{"call over 2 MB", BatchRequest{Using: core, MethodCalls: []MethodCall{{Name: "Test/run", Args: json.RawMessage(strings.Repeat("x", maxCallArgsSize+1))}}}, "requestTooLarge"},
		{"undeclared capability", BatchRequest{Using: []string{capMail}, MethodCalls: []MethodCall{call}}, "unknownCapability"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dispatched.Store(0)
			result := h.ExecuteBatch(context.Background(), claims, tc.req)
			if result.Problem == nil || result.Response != nil {
				t.Fatalf("result = %+v, want request-level problem only", result)
			}
			if got := strings.TrimPrefix(result.Problem.Type, "urn:ietf:params:jmap:error:"); got != tc.wantErr {
				t.Fatalf("problem type = %q, want %q", got, tc.wantErr)
			}
			if result.Problem.Status != http.StatusBadRequest {
				t.Fatalf("problem status = %d, want 400", result.Problem.Status)
			}
			if got := dispatched.Load(); got != 0 {
				t.Fatalf("validation failure dispatched %d methods, want 0", got)
			}
		})
	}

	t.Run("exact bounds accepted", func(t *testing.T) {
		dispatched.Store(0)
		args := `{"value":"` + strings.Repeat("x", maxCallArgsSize-len(`{"value":""}`)) + `"}`
		calls := make([]MethodCall, maxCallsInBatch)
		for i := range calls {
			calls[i] = call
		}
		calls[0].Args = json.RawMessage(args)
		if len(calls[0].Args) != maxCallArgsSize {
			t.Fatalf("test args size = %d, want %d", len(calls[0].Args), maxCallArgsSize)
		}
		result := h.ExecuteBatch(context.Background(), claims, BatchRequest{Using: core, MethodCalls: calls})
		if result.Problem != nil {
			t.Fatalf("exact bounds rejected: %+v", *result.Problem)
		}
		if got := dispatched.Load(); got != maxCallsInBatch {
			t.Fatalf("dispatched %d methods, want %d", got, maxCallsInBatch)
		}
	})
}

func TestExecuteBatchOrderingReferencesCreatedIDsAndContinuation(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "test.local", nil, "", 0, nil)
	h.RegisterMethod("Test/produce", func(_ context.Context, _ *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
		return "Test/produce", args
	})
	h.RegisterMethod("Test/set", func(_ context.Context, _ *auth.Claims, _ json.RawMessage) (string, json.RawMessage) {
		return "Test/set", json.RawMessage(`{"created":{"draft":{"id":"m9"}}}`)
	})

	result := h.ExecuteBatch(context.Background(), &auth.Claims{UserID: 1}, BatchRequest{
		Using: []string{capCore},
		MethodCalls: []MethodCall{
			{Name: "Test/produce", Args: json.RawMessage(`{"ids":["m1","m2"]}`), ClientID: "c0"},
			{Name: "No/such", Args: json.RawMessage(`{}`), ClientID: "c1"},
			{Name: "Test/produce", Args: json.RawMessage(`{"#ids":{"resultOf":"missing","name":"Test/produce","path":"/ids"}}`), ClientID: "c2"},
			{Name: "Test/produce", Args: json.RawMessage(`{"#ids":{"resultOf":"c0","name":"Test/produce","path":"/ids"}}`), ClientID: "c3"},
			{Name: "Test/set", Args: json.RawMessage(`{}`), ClientID: "c4"},
		},
	})
	if result.Problem != nil {
		t.Fatalf("ExecuteBatch problem: %+v", *result.Problem)
	}
	responses := result.Response.MethodResponses
	if len(responses) != 5 {
		t.Fatalf("responses = %d, want 5", len(responses))
	}
	for i, want := range []string{"Test/produce", "error", "error", "Test/produce", "Test/set"} {
		if responses[i].Name != want || responses[i].ClientID != "c"+string(rune('0'+i)) {
			t.Errorf("response[%d] = (%q,%q), want (%q,c%d)", i, responses[i].Name, responses[i].ClientID, want, i)
		}
	}
	var resolved map[string]any
	if err := json.Unmarshal(responses[3].Args, &resolved); err != nil {
		t.Fatal(err)
	}
	if ids, ok := resolved["ids"].([]any); !ok || len(ids) != 2 || ids[0] != "m1" || ids[1] != "m2" {
		t.Errorf("resolved ids = %#v, want [m1 m2]", resolved["ids"])
	}
	if got := result.Response.CreatedIDs["draft"]; got != "m9" {
		t.Errorf("createdIds[draft] = %q, want m9", got)
	}
}

func TestExecuteBatchCarriesAllRegistryInvocationMetadata(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "test.local", nil, "", 0, nil)
	if got := len(h.methods); got != 111 {
		t.Fatalf("registry size = %d, want 111", got)
	}
	claims := &auth.Claims{UserID: 1}
	for name, original := range h.methods {
		name, original := name, original
		t.Run(name, func(t *testing.T) {
			var got invocationMetadata
			entry := original
			entry.fn = func(ctx context.Context, _ *auth.Claims, _ json.RawMessage) (string, json.RawMessage) {
				invCtx, ok := ctx.(invocationContext)
				if !ok {
					t.Fatalf("context type = %T, want invocationContext", ctx)
				}
				got = invCtx.Metadata
				return name, json.RawMessage(`{}`)
			}
			h.methods[name] = entry
			defer func() { h.methods[name] = original }()

			result := h.ExecuteBatch(context.Background(), claims, BatchRequest{
				Using:       []string{original.capability},
				MethodCalls: []MethodCall{{Name: name, Args: json.RawMessage(`{}`), ClientID: "c"}},
			})
			if result.Problem != nil {
				t.Fatalf("problem: %+v", *result.Problem)
			}
			want := invocationMetadata{Capability: original.capability, App: original.app, Gate: original.gate}
			if got != want {
				t.Fatalf("metadata = %+v, want %+v", got, want)
			}
		})
	}
}

func TestExecuteBatchPropagatesCancellation(t *testing.T) {
	h := batchTestHandler(func(ctx context.Context, _ *auth.Claims, _ json.RawMessage) (string, json.RawMessage) {
		if ctx.Err() != context.Canceled {
			t.Fatalf("ctx.Err() = %v, want context.Canceled", ctx.Err())
		}
		return "Test/run", json.RawMessage(`{}`)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := h.ExecuteBatch(ctx, &auth.Claims{UserID: 1}, BatchRequest{
		Using: []string{capCore}, MethodCalls: []MethodCall{{Name: "Test/run", Args: json.RawMessage(`{}`)}},
	})
	if result.Problem != nil || len(result.Response.MethodResponses) != 1 {
		t.Fatalf("canceled execution result = %+v", result)
	}
}

func TestExecuteBatchRunsInvocationGatesAndMetricsOnce(t *testing.T) {
	h := batchTestHandler(func(_ context.Context, _ *auth.Claims, _ json.RawMessage) (string, json.RawMessage) {
		return "Test/run", json.RawMessage(`{}`)
	})
	entry := h.methods["Test/run"]
	entry.app = "calendar"
	h.methods["Test/run"] = entry
	gate := &countingEntitlementGate{}
	h.SetEntitlementChecker(gate)
	metricHandler := metrics.NewHandler()
	h.SetMetrics(metricHandler)

	result := h.ExecuteBatch(context.Background(), &auth.Claims{UserID: 1}, BatchRequest{
		Using: []string{capCore}, MethodCalls: []MethodCall{{Name: "Test/run", Args: json.RawMessage(`{}`)}},
	})
	if result.Problem != nil {
		t.Fatalf("problem: %+v", *result.Problem)
	}
	if got := gate.calls.Load(); got != 1 {
		t.Fatalf("entitlement gate calls = %d, want 1", got)
	}
	rec := httptest.NewRecorder()
	metricHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if got := strings.Count(rec.Body.String(), `gateway_method_duration_seconds_count{method="jmap/Test/run"} 1`); got != 1 {
		t.Fatalf("metric count line occurrences = %d, want 1\n%s", got, rec.Body.String())
	}
}

func TestHTTPRequestProjectsBatchProblemAndResponse(t *testing.T) {
	h := batchTestHandler(func(_ context.Context, _ *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
		return "Test/run", args
	})
	claims := &auth.Claims{UserID: 1}
	run := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/jmap", strings.NewReader(body))
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
		rec := httptest.NewRecorder()
		h.Request(rec, req)
		return rec
	}

	bad := run(`{"using":[],"methodCalls":[]}`)
	if bad.Code != http.StatusBadRequest || bad.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("bad response = %d %q", bad.Code, bad.Header().Get("Content-Type"))
	}
	var problem ProblemDetails
	if err := json.Unmarshal(bad.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Type != "urn:ietf:params:jmap:error:notRequest" || problem.Status != 400 {
		t.Fatalf("problem = %+v", problem)
	}

	ok := run(`{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Test/run",{"ok":true},"c0"]]}`)
	if ok.Code != http.StatusOK {
		t.Fatalf("ok status = %d, body=%s", ok.Code, ok.Body.String())
	}
	var response Response
	if err := json.Unmarshal(ok.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.MethodResponses) != 1 || response.MethodResponses[0].Name != "Test/run" {
		t.Fatalf("response = %+v", response)
	}
}
