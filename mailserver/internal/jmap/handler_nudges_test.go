package jmap

import (
	"context"
	"encoding/json"
	"testing"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// newNudgesHandler builds a nil-pool handler with feature.stale_nudges set to
// the given state, for exercising the two nudge vendor methods without a DB.
func newNudgesHandler(enabled bool) *JMAPHandler {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	h.SetFeatureFlags(toggle.NewStatic(map[string]bool{"feature.stale_nudges": enabled}))
	return h
}

// TestEmailNudgesMethodsRegistered verifies both nudge vendor methods dispatch.
func TestEmailNudgesMethodsRegistered(t *testing.T) {
	h := newNudgesHandler(true)
	for _, m := range []string{"Email/nudges", "Email/nudgeDismiss"} {
		if _, ok := h.methods[m]; !ok {
			t.Errorf("%s method is not registered in the JMAP dispatcher", m)
		}
	}
}

// TestEmailNudgesNilPoolReturnsEmptyList verifies that Email/nudges returns an
// empty nudge list (not an error) with a nil pool even when the toggle is ON.
func TestEmailNudgesNilPoolReturnsEmptyList(t *testing.T) {
	h := newNudgesHandler(true)
	user := testClaims(1)
	args, _ := json.Marshal(map[string]any{"accountId": "1", "limit": 50, "position": 0})

	name, result := h.Dispatch(context.Background(), user, "Email/nudges", args)
	if name == "error" {
		t.Fatalf("Email/nudges returned error in nil-pool mode: %s", string(result))
	}
	if name != "Email/nudges" {
		t.Fatalf("Email/nudges returned unexpected method name %q", name)
	}
	var obj map[string]any
	if err := json.Unmarshal(result, &obj); err != nil {
		t.Fatalf("Email/nudges result is not valid JSON: %v", err)
	}
	if _, ok := obj["nudges"]; !ok {
		t.Error("Email/nudges result missing 'nudges' key")
	}
}

// TestEmailNudgesToggleOffReturnsEmptyList verifies the default-OFF gate: with
// feature.stale_nudges OFF the method is inert (empty list, no error).
func TestEmailNudgesToggleOffReturnsEmptyList(t *testing.T) {
	h := newNudgesHandler(false)
	if h.staleNudgesEnabled() {
		t.Fatal("staleNudgesEnabled() = true with the toggle OFF")
	}
	user := testClaims(1)
	args, _ := json.Marshal(map[string]any{"accountId": "1"})
	name, result := h.Dispatch(context.Background(), user, "Email/nudges", args)
	if name != "Email/nudges" {
		t.Fatalf("Email/nudges (toggle off) returned %q: %s", name, string(result))
	}
	var obj map[string]any
	_ = json.Unmarshal(result, &obj)
	nudges, ok := obj["nudges"].([]any)
	if !ok || len(nudges) != 0 {
		t.Errorf("Email/nudges (toggle off) nudges = %v, want empty array", obj["nudges"])
	}
}

// TestEmailNudgeDismissNilPoolNoOp verifies Email/nudgeDismiss is a no-op
// success (not an error) with a nil pool.
func TestEmailNudgeDismissNilPoolNoOp(t *testing.T) {
	h := newNudgesHandler(true)
	user := testClaims(1)
	args, _ := json.Marshal(map[string]any{"accountId": "1", "threadId": "thread-x"})

	name, result := h.Dispatch(context.Background(), user, "Email/nudgeDismiss", args)
	if name == "error" {
		t.Fatalf("Email/nudgeDismiss returned error in nil-pool mode: %s", string(result))
	}
	if name != "Email/nudgeDismiss" {
		t.Fatalf("Email/nudgeDismiss returned unexpected method name %q", name)
	}
	var obj map[string]any
	if err := json.Unmarshal(result, &obj); err != nil {
		t.Fatalf("Email/nudgeDismiss result is not valid JSON: %v", err)
	}
	if _, ok := obj["dismissed"]; !ok {
		t.Error("Email/nudgeDismiss result missing 'dismissed' key")
	}
}

// TestEmailNudgesMissingAccountID verifies an invalid/missing accountId errors.
func TestEmailNudgesMissingAccountID(t *testing.T) {
	h := newNudgesHandler(true)
	user := testClaims(1)
	args, _ := json.Marshal(map[string]any{})
	name, _ := h.Dispatch(context.Background(), user, "Email/nudges", args)
	if name != "error" {
		t.Fatalf("Email/nudges without accountId returned %q, want \"error\"", name)
	}
}
