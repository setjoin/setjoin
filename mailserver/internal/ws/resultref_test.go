package ws

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/jmap"
	"setjoin.com/shared/pgxutil"
)

// newEchoHandler builds a nil-pool JMAP handler with two echo methods so a WS
// chain can be exercised with no Postgres: Test/produce echoes its args back
// (so a downstream call can reference its result), Test/consume echoes the args
// it is dispatched with (so the test can read the resolved value).
func newEchoHandler() *jmap.JMAPHandler {
	jh := jmap.NewJMAPHandler(nil, pgxutil.WorkerPool{}, "test.local", nil, "", 0, slog.Default())
	echo := func(name string) jmap.MethodFunc {
		return func(_ context.Context, _ *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
			return name, args
		}
	}
	jh.RegisterMethod("Test/produce", echo("Test/produce"))
	jh.RegisterMethod("Test/consume", echo("Test/consume"))
	return jh
}

// runWSRequest enters the same transport projection handleMessage uses. Tests
// do not replay any validation, reference, gate, or dispatch loop.
func runWSRequest(jh *jmap.JMAPHandler, user *auth.Claims, using []string, calls []jmap.MethodCall) wsEnvelope {
	h := &Handler{jmap: jh}
	return h.executeRequest(context.Background(), user, wsEnvelope{
		Type: "Request", Using: using, MethodCalls: calls,
	})
}

// TestWSChainResolvesBackRefs proves the WebSocket transport now resolves RFC
// 8620 §3.7 result references — the bug the plan calls out (ws/handler.go used
// to dispatch call.Args RAW with NO back-ref resolution). The second call
// references the first via #ids and must be dispatched with the resolved array.
func TestWSChainResolvesBackRefs(t *testing.T) {
	jh := newEchoHandler()
	user := &auth.Claims{UserID: 1, Type: "access"}

	calls := []jmap.MethodCall{
		{Name: "Test/produce", Args: json.RawMessage(`{"ids":["m1","m2"]}`), ClientID: "t0"},
		{Name: "Test/consume", Args: json.RawMessage(`{"#ids":{"resultOf":"t0","name":"Test/produce","path":"/ids"}}`), ClientID: "t1"},
	}
	responses := runWSRequest(jh, user, []string{"urn:ietf:params:jmap:core"}, calls).MethodResponses

	if len(responses) != 2 {
		t.Fatalf("got %d responses, want 2", len(responses))
	}
	var consumed map[string]any
	if err := json.Unmarshal(responses[1].Args, &consumed); err != nil {
		t.Fatalf("t1 args not an object: %v", err)
	}
	ids, ok := consumed["ids"].([]any)
	if !ok || len(ids) != 2 || ids[0] != "m1" || ids[1] != "m2" {
		t.Errorf("WS path dispatched t1 with ids = %#v, want [m1 m2] — back-ref not resolved", consumed["ids"])
	}
	if _, leaked := consumed["#ids"]; leaked {
		t.Errorf("unresolved #ids leaked to the WS-dispatched method: %v", consumed)
	}
}

// TestWSChainRejectsBadRef proves the WS loop rejects an unresolvable reference
// with invalidResultReference (instead of dispatching raw, as it used to).
func TestWSChainRejectsBadRef(t *testing.T) {
	jh := newEchoHandler()
	user := &auth.Claims{UserID: 1, Type: "access"}

	calls := []jmap.MethodCall{
		{Name: "Test/consume", Args: json.RawMessage(`{"#ids":{"resultOf":"tX","name":"Test/produce","path":"/ids"}}`), ClientID: "t0"},
	}
	responses := runWSRequest(jh, user, []string{"urn:ietf:params:jmap:core"}, calls).MethodResponses

	if responses[0].Name != "error" {
		t.Fatalf("response name = %q, want error", responses[0].Name)
	}
	var pd jmap.ProblemDetails
	if err := json.Unmarshal(responses[0].Args, &pd); err != nil {
		t.Fatalf("error args not a Problem Details: %v", err)
	}
	if pd.Type != "urn:ietf:params:jmap:error:invalidResultReference" {
		t.Errorf("error type = %q, want …:invalidResultReference", pd.Type)
	}
	if pd.Status != 400 {
		t.Errorf("status = %d, want 400", pd.Status)
	}
}

// TestWSRejectsUndeclaredCapability proves the WS Request loop enforces the
// RFC 8620 §3.2 unknownCapability check on the SAME path that dispatches — the
// bug the plan calls out (the check ran in a dead pre-loop that never gated
// Dispatch, so any method ran without its capability in `using`). The echo
// method's capability (core) is NOT in the declared `using`, so the call must be
// rejected with a single {"type":"unknownCapability"} error and NEVER dispatched
// (the echo would otherwise return the method name in the response body).
func TestWSRejectsUndeclaredCapability(t *testing.T) {
	jh := newEchoHandler()
	user := &auth.Claims{UserID: 1, Type: "access"}

	using := []string{"urn:ietf:params:jmap:submission"} // wrong capability for Test/produce (core)
	calls := []jmap.MethodCall{
		{Name: "Test/produce", Args: json.RawMessage(`{"ids":["m1"]}`), ClientID: "t0"},
	}
	resp := runWSRequest(jh, user, using, calls)

	if resp.Type != "RequestError" {
		t.Fatalf("@type = %q, want RequestError", resp.Type)
	}
	if resp.ProblemType != "urn:ietf:params:jmap:error:unknownCapability" {
		t.Errorf("error type = %q, want unknownCapability URN", resp.ProblemType)
	}
}

// TestWSBatchLimitsCharacterization pins the transport drift being removed by
// the shared JMAP execution envelope. HTTP already rejects all three requests
// before dispatch; the WebSocket loop must do the same.
func TestWSBatchLimitsCharacterization(t *testing.T) {
	jh := newEchoHandler()
	user := &auth.Claims{UserID: 1, Type: "access"}
	call := jmap.MethodCall{Name: "Test/produce", Args: json.RawMessage(`{}`), ClientID: "t0"}

	t.Run("empty using", func(t *testing.T) {
		resp := runWSRequest(jh, user, nil, []jmap.MethodCall{call})
		if resp.Type != "RequestError" || resp.ProblemType != "urn:ietf:params:jmap:error:notRequest" {
			t.Fatalf("empty using = (%q, %q), want RequestError/notRequest", resp.Type, resp.ProblemType)
		}
	})

	t.Run("more than 32 calls", func(t *testing.T) {
		calls := make([]jmap.MethodCall, 33)
		for i := range calls {
			calls[i] = call
		}
		resp := runWSRequest(jh, user, []string{"urn:ietf:params:jmap:core"}, calls)
		if resp.Type != "RequestError" || resp.ProblemType != "urn:ietf:params:jmap:error:requestTooLarge" {
			t.Fatalf("33 calls = (%q, %q), want RequestError/requestTooLarge", resp.Type, resp.ProblemType)
		}
	})

	t.Run("call over 2 MB", func(t *testing.T) {
		tooLarge := call
		tooLarge.Args = json.RawMessage(`{"value":"` + strings.Repeat("x", 2_000_000) + `"}`)
		resp := runWSRequest(jh, user, []string{"urn:ietf:params:jmap:core"}, []jmap.MethodCall{tooLarge})
		if resp.Type != "RequestError" || resp.ProblemType != "urn:ietf:params:jmap:error:requestTooLarge" {
			t.Fatalf("oversized call = (%q, %q), want RequestError/requestTooLarge", resp.Type, resp.ProblemType)
		}
	})
}

func TestWSExecutionEnvelopeRFC8887Projection(t *testing.T) {
	jh := newEchoHandler()
	user := &auth.Claims{UserID: 1, Type: "access"}

	success := (&Handler{jmap: jh}).executeRequest(context.Background(), user, wsEnvelope{
		Type: "Request", ID: "r1", Using: []string{"urn:ietf:params:jmap:core"},
		MethodCalls: []jmap.MethodCall{{Name: "Test/produce", Args: json.RawMessage(`{"ok":true}`), ClientID: "c0"}},
	})
	if success.Type != "Response" || success.RequestID != "r1" || len(success.MethodResponses) != 1 {
		t.Fatalf("success projection = %+v", success)
	}
	if success.MethodResponses[0].Name != "Test/produce" || success.MethodResponses[0].ClientID != "c0" {
		t.Fatalf("success method response = %+v", success.MethodResponses[0])
	}

	requestError := (&Handler{jmap: jh}).executeRequest(context.Background(), user, wsEnvelope{
		Type: "Request", ID: "r2", MethodCalls: []jmap.MethodCall{},
	})
	wire, err := json.Marshal(requestError)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"@type":"RequestError","requestId":"r2","type":"urn:ietf:params:jmap:error:notRequest","status":400,"detail":"'using' array must not be empty"}`
	if string(wire) != want {
		t.Fatalf("RequestError wire = %s\nwant              = %s", wire, want)
	}
}

func TestHTTPWSExecutionCorpusParity(t *testing.T) {
	jh := newEchoHandler()
	jh.RegisterMethod("Test/set", func(_ context.Context, _ *auth.Claims, _ json.RawMessage) (string, json.RawMessage) {
		return "Test/set", json.RawMessage(`{"created":{"k":{"id":"m1"}}}`)
	})
	claims := &auth.Claims{UserID: 1, Type: "access"}
	core := []string{"urn:ietf:params:jmap:core"}
	produce := jmap.MethodCall{Name: "Test/produce", Args: json.RawMessage(`{"ids":["m1"]}`), ClientID: "c0"}

	cases := []struct {
		name string
		req  jmap.BatchRequest
	}{
		{"ordered refs and createdIds", jmap.BatchRequest{Using: core, MethodCalls: []jmap.MethodCall{
			produce,
			{Name: "Test/consume", Args: json.RawMessage(`{"#ids":{"resultOf":"c0","name":"Test/produce","path":"/ids"}}`), ClientID: "c1"},
			{Name: "Test/set", Args: json.RawMessage(`{}`), ClientID: "c2"},
		}}},
		{"bad ref continues", jmap.BatchRequest{Using: core, MethodCalls: []jmap.MethodCall{
			{Name: "Test/consume", Args: json.RawMessage(`{"#ids":{"resultOf":"missing","name":"Test/produce","path":"/ids"}}`), ClientID: "c0"},
			produce,
		}}},
		{"unknown method continues", jmap.BatchRequest{Using: core, MethodCalls: []jmap.MethodCall{
			{Name: "No/such", Args: json.RawMessage(`{}`), ClientID: "c0"}, produce,
		}}},
		{"empty using", jmap.BatchRequest{MethodCalls: []jmap.MethodCall{produce}}},
		{"unknown capability", jmap.BatchRequest{Using: []string{"urn:ietf:params:jmap:mail"}, MethodCalls: []jmap.MethodCall{produce}}},
		{"33 calls", jmap.BatchRequest{Using: core, MethodCalls: make([]jmap.MethodCall, 33)}},
		{"over 2 MB", jmap.BatchRequest{Using: core, MethodCalls: []jmap.MethodCall{{
			Name: "Test/produce", Args: json.RawMessage(`{"x":"` + strings.Repeat("x", 2_000_001) + `"}`),
		}}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.req)
			if err != nil {
				t.Fatal(err)
			}
			httpReq := httptest.NewRequest(http.MethodPost, "/jmap", strings.NewReader(string(body)))
			httpReq = httpReq.WithContext(auth.ContextWithUser(httpReq.Context(), claims))
			httpRec := httptest.NewRecorder()
			jh.Request(httpRec, httpReq)

			wsResp := (&Handler{jmap: jh}).executeRequest(context.Background(), claims, wsEnvelope{
				Type: "Request", ID: "r", Using: tc.req.Using, MethodCalls: tc.req.MethodCalls, CreatedIDs: tc.req.CreatedIDs,
			})
			if httpRec.Code == http.StatusBadRequest {
				var problem jmap.ProblemDetails
				if err := json.Unmarshal(httpRec.Body.Bytes(), &problem); err != nil {
					t.Fatal(err)
				}
				if wsResp.Type != "RequestError" || wsResp.RequestID != "r" ||
					wsResp.ProblemType != problem.Type || wsResp.Status != problem.Status || wsResp.Detail != problem.Detail {
					t.Fatalf("HTTP problem %+v != WS projection %+v", problem, wsResp)
				}
				return
			}
			if httpRec.Code != http.StatusOK || wsResp.Type != "Response" || wsResp.RequestID != "r" {
				t.Fatalf("HTTP status %d / WS response %+v", httpRec.Code, wsResp)
			}
			var httpResp jmap.Response
			if err := json.Unmarshal(httpRec.Body.Bytes(), &httpResp); err != nil {
				t.Fatal(err)
			}
			if httpResp.SessionState != wsResp.SessionState ||
				!reflect.DeepEqual(httpResp.MethodResponses, wsResp.MethodResponses) ||
				!reflect.DeepEqual(httpResp.CreatedIDs, wsResp.CreatedIDs) {
				t.Fatalf("HTTP response %+v != WS projection %+v", httpResp, wsResp)
			}
		})
	}
}

func TestExecutionEnvelopeDeletionGuard(t *testing.T) {
	wsSource, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		".Dispatch(", ".HasCapability(", ".ResolveReferences(", "ExtractCreatedIDs(",
		"for _, call := range env.MethodCalls",
	} {
		if strings.Contains(string(wsSource), forbidden) {
			t.Errorf("WebSocket transport reintroduced private execution policy %q", forbidden)
		}
	}
	if !strings.Contains(string(wsSource), ".ExecuteBatch(") {
		t.Error("WebSocket Request transport no longer delegates to ExecuteBatch")
	}

	jmapSource, err := os.ReadFile("../jmap/handler.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(jmapSource), "gateClassKey") || strings.Contains(string(jmapSource), "context.WithValue(ctx") {
		t.Error("private context-key invocation metadata was reintroduced")
	}
	if got := strings.Count(string(jmapSource), "for _, call := range req.MethodCalls"); got != 1 {
		t.Errorf("JMAP method-call execution loop count = %d, want exactly one", got)
	}
}
