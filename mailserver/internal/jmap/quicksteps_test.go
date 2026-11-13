package jmap

import (
	"context"
	"encoding/json"
	"testing"

	"setjoin.com/shared/pgxutil"
)

// TestQuickStepMethodsRegistered verifies the three QuickStep/* methods are wired
// into the JMAP dispatcher, and that an unknown method still routes to an error.
func TestQuickStepMethodsRegistered(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)

	for _, m := range []string{"QuickStep/get", "QuickStep/set", "QuickStep/apply"} {
		if _, ok := h.methods[m]; !ok {
			t.Errorf("%s is not registered in the JMAP dispatcher", m)
		}
	}

	// An unknown method must dispatch to ("error", unknownMethod).
	user := testClaims(1)
	name, _ := h.Dispatch(context.Background(), user, "QuickStep/nope", json.RawMessage(`{"accountId":"1"}`))
	if name != "error" {
		t.Fatalf("unknown QuickStep method returned %q, want \"error\"", name)
	}
}

// TestQuickStepGetNilPoolReturnsEmptyList verifies QuickStep/get returns an empty
// list in nil-pool (unit-test) mode rather than an error.
func TestQuickStepGetNilPoolReturnsEmptyList(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := testClaims(1)

	args, _ := json.Marshal(map[string]any{"accountId": "1"})
	name, result := h.Dispatch(context.Background(), user, "QuickStep/get", args)
	if name == "error" {
		t.Fatalf("QuickStep/get returned error in nil-pool mode: %s", string(result))
	}
	if name != "QuickStep/get" {
		t.Fatalf("QuickStep/get returned unexpected method name %q", name)
	}
	var obj map[string]any
	if err := json.Unmarshal(result, &obj); err != nil {
		t.Fatalf("QuickStep/get result is not valid JSON: %v", err)
	}
	if _, ok := obj["list"]; !ok {
		t.Error("QuickStep/get result missing 'list' key")
	}
}

// TestQuickStepAccountIDFromAuth verifies the mailbox id comes from auth, not the
// request: a request whose accountId does not match the user's id is rejected (R2).
func TestQuickStepAccountIDFromAuth(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := testClaims(1)

	for _, m := range []string{"QuickStep/get", "QuickStep/set", "QuickStep/apply"} {
		// Wrong accountId (does not match userID=1 in nil-pool mode).
		args, _ := json.Marshal(map[string]any{"accountId": "99999", "id": "1", "messageId": "1"})
		name, _ := h.Dispatch(context.Background(), user, m, args)
		if name != "error" {
			t.Fatalf("%s with mismatched accountId returned %q, want \"error\"", m, name)
		}

		// Missing accountId.
		args2, _ := json.Marshal(map[string]any{})
		name2, result2 := h.Dispatch(context.Background(), user, m, args2)
		if name2 != "error" {
			t.Fatalf("%s without accountId returned %q, want \"error\"", m, name2)
		}
		var errObj map[string]any
		_ = json.Unmarshal(result2, &errObj)
		if typ, _ := errObj["type"].(string); typ == "" {
			t.Errorf("%s error response missing 'type' field", m)
		}
	}
}
