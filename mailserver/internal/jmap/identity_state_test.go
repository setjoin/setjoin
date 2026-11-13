package jmap

import (
	"context"
	"encoding/json"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

// TestIdentityStateConsistency pins arch A4: Identity/get and Identity/changes
// MUST return the same state token. Before the fix, Identity/get returned the
// constant user id while Identity/changes returned users.updated_at — two
// different values — so an up-to-date client's cached get-state never matched,
// Identity/changes reported a spurious perpetual "updated", and the get-state
// never advanced on an edit. Both now route through identityState(), so this
// asserts they agree AND that an up-to-date client sees no change.
func TestIdentityStateConsistency(t *testing.T) {
	pool := testPoolDB(t)
	_, userID, _ := insertTestUserWithMailbox(t, pool, false)
	h := &JMAPHandler{pool: pool, workerPool: pool, logger: testLoggerDB(t)} // workerPool aliases pool (W1b test posture): identityGet reads mailbox_delegates on it (V090)
	claims := &auth.Claims{UserID: userID}
	ctx := context.Background()

	_, getRaw := h.identityGet(ctx, claims, nil)
	var getResp struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(getRaw, &getResp); err != nil {
		t.Fatalf("identityGet unmarshal: %v", err)
	}
	if getResp.State == "" {
		t.Fatal("identityGet returned an empty state")
	}

	// An up-to-date client passes the get-state as sinceState; changes must report
	// the SAME newState and NO updates.
	changesArgs, _ := json.Marshal(map[string]any{"sinceState": getResp.State})
	_, chRaw := h.identityChanges(ctx, claims, changesArgs)
	var chResp struct {
		NewState string   `json:"newState"`
		Updated  []string `json:"updated"`
	}
	if err := json.Unmarshal(chRaw, &chResp); err != nil {
		t.Fatalf("identityChanges unmarshal: %v", err)
	}

	if getResp.State != chResp.NewState {
		t.Errorf("Identity/get state %q != Identity/changes newState %q — the get≠changes desync is back", getResp.State, chResp.NewState)
	}
	if len(chResp.Updated) != 0 {
		t.Errorf("an up-to-date client got a spurious updated=%v (want empty)", chResp.Updated)
	}
}
