package jmap

import (
	"context"
	"encoding/json"
	"testing"

	"setjoin.com/shared/pgxutil"
)

func TestEmailTemplateTranslatorsValidateOwnershipAndShapeResponses(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "bucket", 1<<20, nil)
	user := testClaims(42)
	ctx := context.Background()

	t.Run("list", func(t *testing.T) {
		name, raw := h.emailTemplateList(ctx, user, json.RawMessage(`{"accountId":"42"}`))
		if name != "EmailTemplate/list" {
			t.Fatalf("name=%q body=%s", name, raw)
		}
		var response struct {
			AccountID string `json:"accountId"`
			List      []any  `json:"list"`
		}
		if err := json.Unmarshal(raw, &response); err != nil {
			t.Fatal(err)
		}
		if response.AccountID != "42" || response.List == nil || len(response.List) != 0 {
			t.Fatalf("response=%+v", response)
		}
	})

	t.Run("set", func(t *testing.T) {
		name, raw := h.emailTemplateSet(ctx, user, json.RawMessage(
			`{"accountId":"42","name":"Follow up","subject":"Hello","bodyHtml":"<p>Body</p>"}`,
		))
		if name != "EmailTemplate/set" {
			t.Fatalf("name=%q body=%s", name, raw)
		}
		var response map[string]any
		if err := json.Unmarshal(raw, &response); err != nil {
			t.Fatal(err)
		}
		if response["accountId"] != "42" {
			t.Fatalf("response=%v", response)
		}
	})

	t.Run("delete", func(t *testing.T) {
		name, raw := h.emailTemplateDelete(ctx, user, json.RawMessage(`{"accountId":"42","id":"7"}`))
		if name != "EmailTemplate/delete" {
			t.Fatalf("name=%q body=%s", name, raw)
		}
		var response map[string]any
		if err := json.Unmarshal(raw, &response); err != nil {
			t.Fatal(err)
		}
		if response["accountId"] != "42" || response["deleted"] != "7" {
			t.Fatalf("response=%v", response)
		}
	})

	for _, tc := range []struct {
		name string
		call func(json.RawMessage) (string, json.RawMessage)
	}{
		{name: "list", call: func(raw json.RawMessage) (string, json.RawMessage) {
			return h.emailTemplateList(ctx, user, raw)
		}},
		{name: "set", call: func(raw json.RawMessage) (string, json.RawMessage) {
			return h.emailTemplateSet(ctx, user, raw)
		}},
		{name: "delete", call: func(raw json.RawMessage) (string, json.RawMessage) {
			return h.emailTemplateDelete(ctx, user, raw)
		}},
	} {
		t.Run(tc.name+" invalid JSON", func(t *testing.T) {
			name, raw := tc.call(json.RawMessage(`{"accountId":`))
			assertJMAPErrorType(t, name, raw, "invalidArguments")
		})
		t.Run(tc.name+" foreign account", func(t *testing.T) {
			name, raw := tc.call(json.RawMessage(`{"accountId":"99","id":"7"}`))
			assertJMAPErrorType(t, name, raw, "accountNotFound")
		})
	}

	name, raw := h.emailTemplateDelete(ctx, user, json.RawMessage(`{"accountId":"42","id":"not-a-number"}`))
	assertJMAPErrorType(t, name, raw, "invalidArguments")
}

func TestSavedSearchTranslatorsValidateOwnershipAndShapeResponses(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "bucket", 1<<20, nil)
	user := testClaims(42)
	ctx := context.Background()

	name, raw := h.savedSearchList(ctx, user, json.RawMessage(`{"accountId":"42"}`))
	if name != "SavedSearch/list" {
		t.Fatalf("list name=%q body=%s", name, raw)
	}
	var list struct {
		AccountID string `json:"accountId"`
		Items     []any  `json:"list"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	if list.AccountID != "42" || list.Items == nil || len(list.Items) != 0 {
		t.Fatalf("list=%+v", list)
	}

	name, raw = h.savedSearchSet(ctx, user, json.RawMessage(
		`{"accountId":"42","name":"Unread from finance","query":"from:finance is:unread"}`,
	))
	if name != "SavedSearch/set" {
		t.Fatalf("set name=%q body=%s", name, raw)
	}
	var set map[string]any
	if err := json.Unmarshal(raw, &set); err != nil || set["accountId"] != "42" {
		t.Fatalf("set=%v err=%v", set, err)
	}

	name, raw = h.savedSearchDelete(ctx, user, json.RawMessage(`{"accountId":"42","id":"9"}`))
	if name != "SavedSearch/delete" {
		t.Fatalf("delete name=%q body=%s", name, raw)
	}
	var deleted map[string]any
	if err := json.Unmarshal(raw, &deleted); err != nil {
		t.Fatal(err)
	}
	if deleted["accountId"] != "42" || deleted["deleted"] != "9" {
		t.Fatalf("delete=%v", deleted)
	}

	for _, call := range []func(json.RawMessage) (string, json.RawMessage){
		func(raw json.RawMessage) (string, json.RawMessage) { return h.savedSearchList(ctx, user, raw) },
		func(raw json.RawMessage) (string, json.RawMessage) { return h.savedSearchSet(ctx, user, raw) },
		func(raw json.RawMessage) (string, json.RawMessage) { return h.savedSearchDelete(ctx, user, raw) },
	} {
		name, raw = call(json.RawMessage(`{"accountId":`))
		assertJMAPErrorType(t, name, raw, "invalidArguments")
	}
	name, raw = h.savedSearchDelete(ctx, user, json.RawMessage(`{"accountId":"42","id":"bad"}`))
	assertJMAPErrorType(t, name, raw, "invalidArguments")
}

func TestContactGroupTranslatorCallsReducersAndMergesMembers(t *testing.T) {
	ctx := context.Background()
	user := testClaims(42)

	fake := &fakeCaller{returnRaw: json.RawMessage(`{"accountId":"42","list":[]}`)}
	h := newFakeHandler(fake)
	name, raw := h.contactGroupGet(ctx, user, json.RawMessage(`{"accountId":"42","ids":["7","bad"]}`))
	if name != "ContactGroup/get" || fake.gotFn != "jmap_contact_group_get" || fake.gotMailboxID != 42 {
		t.Fatalf("name=%q fn=%q mailbox=%d body=%s", name, fake.gotFn, fake.gotMailboxID, raw)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	var notFound []string
	if err := json.Unmarshal(got["notFound"], &notFound); err != nil || len(notFound) != 1 || notFound[0] != "bad" {
		t.Fatalf("notFound=%v err=%v body=%s", notFound, err, raw)
	}

	fake = &fakeCaller{returnRaw: json.RawMessage(`{"queryState":"3","ids":["7"]}`)}
	h = newFakeHandler(fake)
	name, raw = h.contactGroupQuery(ctx, user, json.RawMessage(`{"accountId":"42","filter":{"text":"finance"}}`))
	if name != "ContactGroup/query" || fake.gotFn != "jmap_contact_group_query" ||
		string(raw) != string(fake.returnRaw) {
		t.Fatalf("name=%q fn=%q body=%s", name, fake.gotFn, raw)
	}

	fake = &fakeCaller{returnRaw: json.RawMessage(`[{"email":"a@example.com"}]`)}
	h = newFakeHandler(fake)
	name, raw = h.contactGroupExpand(ctx, user, json.RawMessage(`{"accountId":"42","groupId":"7"}`))
	if name != "ContactGroup/expand" || fake.gotFn != "expand_contact_group" {
		t.Fatalf("name=%q fn=%q body=%s", name, fake.gotFn, raw)
	}

	items := []json.RawMessage{json.RawMessage(`{"email":"a@example.com"}`)}
	if got := string(rawListToJSON(items)); got != `[{"email":"a@example.com"}]` {
		t.Fatalf("rawListToJSON=%s", got)
	}
	if got := string(rawListToJSON(nil)); got != `[]` {
		t.Fatalf("rawListToJSON(nil)=%s", got)
	}
	merged := mergeMembersResult(
		json.RawMessage(`{"accountId":"42","created":{"k":"7"}}`),
		json.RawMessage(`{"memberCount":1}`),
	)
	var mergedObject map[string]json.RawMessage
	if err := json.Unmarshal(merged, &mergedObject); err != nil || mergedObject["members"] == nil {
		t.Fatalf("merged=%s err=%v", merged, err)
	}
}

func assertJMAPErrorType(t *testing.T, name string, raw json.RawMessage, want string) {
	t.Helper()
	if name != "error" {
		t.Fatalf("name=%q body=%s", name, raw)
	}
	var response Error
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	if response.Type != want {
		t.Fatalf("error type=%q want=%q body=%s", response.Type, want, raw)
	}
}
