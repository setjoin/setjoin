package jmap

import (
	"context"
	"encoding/json"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

// chainLoop enters the production execution envelope; it deliberately owns no
// private copy of reference, continuation, or dispatch semantics.
func chainLoop(t *testing.T, h *JMAPHandler, user *auth.Claims, calls []MethodCall) []MethodCall {
	t.Helper()
	result := h.ExecuteBatch(context.Background(), user, BatchRequest{
		Using: []string{capCore}, MethodCalls: calls,
	})
	if result.Problem != nil {
		t.Fatalf("ExecuteBatch problem: %+v", *result.Problem)
	}
	return result.Response.MethodResponses
}

// newChainHandler builds a nil-pool handler with two test methods registered:
//   - "Test/produce" echoes its args straight back (so a response can carry an
//     "ids" array a downstream call references).
//   - "Test/consume" echoes its args back too, letting a test read the resolved
//     "ids" the evaluator substituted.
func newChainHandler() *JMAPHandler {
	h := &JMAPHandler{methods: make(map[string]methodEntry)}
	echo := func(_ context.Context, _ *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
		return "ok", args
	}
	h.RegisterMethod("Test/produce", func(ctx context.Context, u *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
		_, r := echo(ctx, u, args)
		return "Test/produce", r
	})
	h.RegisterMethod("Test/consume", func(ctx context.Context, u *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
		_, r := echo(ctx, u, args)
		return "Test/consume", r
	})
	return h
}

// TestHTTPChainWiring drives the HTTP loop core: t0 produces {ids:[...]}, t1
// back-references it via #ids path /ids, and the dispatched t1 sees the resolved
// ids array. Proves the spec back-ref the OLD string-hack silently dropped now
// resolves end-to-end through Dispatch.
func TestHTTPChainWiring(t *testing.T) {
	h := newChainHandler()
	user := &auth.Claims{UserID: 1, Type: "access"}

	calls := []MethodCall{
		mc("Test/produce", `{"ids":["m1","m2"]}`, "t0"),
		mc("Test/consume", `{"accountId":"A1","#ids":{"resultOf":"t0","name":"Test/produce","path":"/ids"}}`, "t1"),
	}
	resp := chainLoop(t, h, user, calls)
	if len(resp) != 2 {
		t.Fatalf("got %d responses, want 2", len(resp))
	}
	if resp[1].Name != "Test/consume" {
		t.Fatalf("t1 response name = %q, want Test/consume", resp[1].Name)
	}
	var consumed map[string]any
	if err := json.Unmarshal(resp[1].Args, &consumed); err != nil {
		t.Fatalf("t1 args not an object: %v", err)
	}
	ids, ok := consumed["ids"].([]any)
	if !ok || len(ids) != 2 || ids[0] != "m1" || ids[1] != "m2" {
		t.Errorf("t1 dispatched with ids = %#v, want [m1 m2]", consumed["ids"])
	}
	if _, leaked := consumed["#ids"]; leaked {
		t.Errorf("unresolved #ids leaked to the dispatched method: %v", consumed)
	}
}

// TestHTTPChainWiring_ErroredPredecessorRejected proves a method whose back-ref
// predecessor errored is rejected with invalidResultReference (NOT silently run
// on stale/empty args), while the batch still continues.
func TestHTTPChainWiring_ErroredPredecessorRejected(t *testing.T) {
	h := newChainHandler()
	// Register a method that always errors so t0 yields an ("error",…) response.
	h.RegisterMethod("Test/fail", func(_ context.Context, _ *auth.Claims, _ json.RawMessage) (string, json.RawMessage) {
		errJSON, _ := json.Marshal(Error{Type: "serverFail", Description: "boom"})
		return "error", errJSON
	})
	user := &auth.Claims{UserID: 1, Type: "access"}

	calls := []MethodCall{
		mc("Test/fail", `{}`, "t0"),
		mc("Test/consume", `{"#ids":{"resultOf":"t0","name":"Test/produce","path":"/ids"}}`, "t1"),
		mc("Test/produce", `{"ok":true}`, "t2"), // unrelated; batch must continue
	}
	resp := chainLoop(t, h, user, calls)
	if len(resp) != 3 {
		t.Fatalf("got %d responses, want 3 (batch must continue)", len(resp))
	}
	if resp[1].Name != "error" {
		t.Fatalf("t1 name = %q, want error", resp[1].Name)
	}
	var e Error
	if err := json.Unmarshal(resp[1].Args, &e); err != nil {
		t.Fatalf("t1 error not a Problem Details: %v", err)
	}
	if e.Type != "invalidResultReference" {
		t.Errorf("t1 error type = %q, want invalidResultReference", e.Type)
	}
	if resp[2].Name != "Test/produce" {
		t.Errorf("t2 (unrelated) name = %q, want Test/produce — batch did not continue", resp[2].Name)
	}
}
