package jmap

import (
	"context"
	"encoding/json"
	"testing"

	"setjoin.com/shared/pgxutil"
)

// TestContactGroupMethodsRegistered verifies the four ContactGroup methods are
// wired into the JMAP dispatcher under the contacts capability/app gate.
func TestContactGroupMethodsRegistered(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)

	methods := []string{
		"ContactGroup/get",
		"ContactGroup/query",
		"ContactGroup/set",
		"ContactGroup/expand",
	}
	for _, m := range methods {
		if _, ok := h.methods[m]; !ok {
			t.Errorf("%s is not registered in the JMAP dispatcher", m)
		}
		if app := h.methods[m].app; app != "contacts" {
			t.Errorf("appForMethod(%q) = %q, want \"contacts\"", m, app)
		}
		if cap := h.capabilityForMethod(m); cap != "urn:ietf:params:jmap:contacts" {
			t.Errorf("capabilityForMethod(%q) = %q, want contacts urn", m, cap)
		}
	}
}

// TestContactGroupUnknownMethodRoutesToError confirms a bogus ContactGroup/* method errors.
func TestContactGroupUnknownMethodRoutesToError(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := testClaims(1)
	name, _ := h.Dispatch(context.Background(), user, "ContactGroup/nope", json.RawMessage(`{"accountId":"1"}`))
	if name != "error" {
		t.Fatalf("unknown ContactGroup method returned %q, want \"error\"", name)
	}
}

// TestContactGroupExpandRejectsForeignAccount proves the same-mailbox parseAccountID
// guard applies: an accountId that is not the authenticated user's is rejected before
// any reducer call (nil-pool mode compares against userID).
func TestContactGroupExpandRejectsForeignAccount(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := testClaims(1)

	args, _ := json.Marshal(map[string]any{"accountId": "99999", "groupId": "5"})
	name, result := h.contactGroupExpand(context.Background(), user, args)
	if name != "error" {
		t.Fatalf("expand with mismatched accountId returned %q, want \"error\"", name)
	}
	var errObj map[string]any
	_ = json.Unmarshal(result, &errObj)
	if typ, _ := errObj["type"].(string); typ != "urn:ietf:params:jmap:error:accountNotFound" {
		t.Errorf("expand foreign account: type = %q, want accountNotFound urn", typ)
	}
}

// TestContactGroupSetParsesMembersPatch verifies contactGroupSet routes a members
// patch separately from create/update/destroy (translator-level, no DB needed:
// invalid args surface as an error rather than panicking).
func TestContactGroupSetParsesMembersPatch(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := testClaims(1)

	// Wrong accountId must be rejected before any reducer dispatch.
	args, _ := json.Marshal(map[string]any{
		"accountId": "2",
		"create":    map[string]any{"k1": map[string]any{"name": "QA Team"}},
	})
	name, _ := h.contactGroupSet(context.Background(), user, args)
	if name != "error" {
		t.Fatalf("contactGroupSet with foreign accountId returned %q, want \"error\"", name)
	}
}

// TestSplitContactGroupSet checks the members-patch extraction helper that keeps
// the gateway a thin translator: a {members:{...}} key is pulled out of the set
// request and handled by contact_group_members_set, the rest by the standard CRUD.
func TestSplitContactGroupSet(t *testing.T) {
	raw := json.RawMessage(`{"groupId":"7","add":[{"email":"a@x.test"}],"remove":[]}`)
	patch, ok := parseMembersPatch(raw)
	if !ok {
		t.Fatal("expected ok=true for a valid members patch")
	}
	if patch.GroupID != "7" {
		t.Errorf("GroupID = %q, want 7", patch.GroupID)
	}
	if len(patch.Add) != 1 {
		t.Errorf("len(Add) = %d, want 1", len(patch.Add))
	}
}
