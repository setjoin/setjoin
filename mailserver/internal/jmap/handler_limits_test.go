package jmap

import (
	"encoding/json"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

// TestEmailGetRejectsTooManyIDs verifies M30: Email/get enforces maxObjectsInGet (256).
func TestEmailGetRejectsTooManyIDs(t *testing.T) {
	h := &JMAPHandler{} // nil pool is fine — the id cap fires before any DB call
	user := &auth.Claims{UserID: 1, Type: "access"}

	// Build a request with 257 ids — one over the cap.
	ids := make([]string, 257)
	for i := range ids {
		ids[i] = "1"
	}
	args, _ := json.Marshal(map[string]any{
		"accountId": "1",
		"ids":       ids,
	})
	method, result := h.emailGet(nil, user, args)

	if method != "error" {
		t.Fatalf("expected method 'error', got %q", method)
	}
	var e Error
	if err := json.Unmarshal(result, &e); err != nil {
		t.Fatalf("failed to unmarshal error: %v", err)
	}
	if e.Type != "requestTooLarge" {
		t.Errorf("expected error type 'requestTooLarge', got %q", e.Type)
	}
}

// TestMailboxGetRejectsTooManyIDs verifies M30: Mailbox/get enforces maxObjectsInGet (256).
func TestMailboxGetRejectsTooManyIDs(t *testing.T) {
	h := &JMAPHandler{}
	user := &auth.Claims{UserID: 1, Type: "access"}

	ids := make([]string, 257)
	for i := range ids {
		ids[i] = "1"
	}
	args, _ := json.Marshal(map[string]any{
		"accountId": "1",
		"ids":       ids,
	})
	method, result := h.mailboxGet(nil, user, args)

	if method != "error" {
		t.Fatalf("expected method 'error', got %q", method)
	}
	var e Error
	if err := json.Unmarshal(result, &e); err != nil {
		t.Fatalf("failed to unmarshal error: %v", err)
	}
	if e.Type != "requestTooLarge" {
		t.Errorf("expected error type 'requestTooLarge', got %q", e.Type)
	}
}
