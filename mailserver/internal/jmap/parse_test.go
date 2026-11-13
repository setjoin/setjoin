package jmap

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseIDAndParseArg(t *testing.T) {
	if v, ok := parseID("42"); !ok || v != 42 {
		t.Errorf("parseID(42) = %d,%v", v, ok)
	}
	for _, bad := range []string{"", "abc", "0", "-3", "1.5", "9999999999999999999999"} {
		if _, ok := parseID(bad); ok {
			t.Errorf("parseID(%q) accepted", bad)
		}
	}
	if _, errJSON := parseArg("7", "eventId"); errJSON != nil {
		t.Errorf("parseArg valid id returned error: %s", errJSON)
	}
	_, errJSON := parseArg("nope", "eventId")
	if errJSON == nil {
		t.Fatal("parseArg malformed id: want invalidArguments")
	}
	var e Error
	if err := json.Unmarshal(errJSON, &e); err != nil {
		t.Fatal(err)
	}
	if e.Type != "invalidArguments" || !strings.Contains(e.Description, "eventId") {
		t.Errorf("parseArg error = %+v, want invalidArguments naming eventId", e)
	}
}

func TestParseIDListAllMalformedIsEmptyNotNil(t *testing.T) {
	valid, bad := parseIDList([]string{"x", "y"})
	if valid == nil || len(valid) != 0 {
		t.Errorf("valid = %#v, want non-nil empty (empty pg array, never NULL/all)", valid)
	}
	if len(bad) != 2 {
		t.Errorf("bad = %v", bad)
	}
	valid, bad = parseIDList(nil)
	if valid != nil || bad != nil {
		t.Errorf("nil input must stay nil (NULL → get-all semantics preserved): %#v %#v", valid, bad)
	}
}

func TestAddNotFoundPreservesValidShape(t *testing.T) {
	in := json.RawMessage(`{"accountId":"1","state":"5","list":[],"notFound":null}`)
	if out := addNotFound(in, nil); string(out) != string(in) {
		t.Errorf("no-bad path must be byte-identical: %s", out)
	}
	out := addNotFound(in, []string{"abc"})
	var obj struct {
		NotFound []string `json:"notFound"`
	}
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatal(err)
	}
	if len(obj.NotFound) != 1 || obj.NotFound[0] != "abc" {
		t.Errorf("notFound = %v, want [abc]", obj.NotFound)
	}
	// Existing entries survive the merge.
	out = addNotFound(json.RawMessage(`{"notFound":["9"]}`), []string{"abc"})
	_ = json.Unmarshal(out, &obj)
	if len(obj.NotFound) != 2 || obj.NotFound[0] != "9" || obj.NotFound[1] != "abc" {
		t.Errorf("merged notFound = %v, want [9 abc]", obj.NotFound)
	}
}

func TestAddSetErrors(t *testing.T) {
	in := json.RawMessage(`{"destroyed":["4"],"notDestroyed":{"9":{"type":"notFound"}}}`)
	if out := addSetErrors(in, "notDestroyed", nil); string(out) != string(in) {
		t.Errorf("no-bad path must be byte-identical: %s", out)
	}
	out := addSetErrors(in, "notDestroyed", []string{"zap"})
	var obj struct {
		NotDestroyed map[string]struct {
			Type string `json:"type"`
		} `json:"notDestroyed"`
	}
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatal(err)
	}
	if obj.NotDestroyed["zap"].Type != "notFound" || obj.NotDestroyed["9"].Type != "notFound" {
		t.Errorf("notDestroyed = %v", obj.NotDestroyed)
	}
}

// TestGetMalformedIDsLandInNotFound drives a real get handler through the
// fake caller: the malformed id must (a) not reach the reducer, (b) not turn
// the request into a fetch-all NULL, and (c) surface in notFound.
func TestGetMalformedIDsLandInNotFound(t *testing.T) {
	fake := &fakeCaller{returnRaw: json.RawMessage(`{"accountId":"1","state":"3","list":[],"notFound":[]}`)}
	h := newFakeHandler(fake)

	name, res := h.taskGet(context.Background(), testClaims(1), json.RawMessage(`{"accountId":"1","ids":["5","abc"]}`))
	if name != "Task/get" {
		t.Fatalf("got %s: %s", name, res)
	}
	// Reducer saw only the valid id ($1 is the scope mailbox id).
	ids, ok := fake.gotArgs[1].([]int64)
	if !ok || len(ids) != 1 || ids[0] != 5 {
		t.Errorf("reducer ids = %#v, want [5]", fake.gotArgs[1])
	}
	var out struct {
		NotFound []string `json:"notFound"`
	}
	_ = json.Unmarshal(res, &out)
	if len(out.NotFound) != 1 || out.NotFound[0] != "abc" {
		t.Errorf("notFound = %v, want [abc]", out.NotFound)
	}
}

// TestGetAllMalformedIDsDoesNotFetchAll pins the worst pre-c4 defect: a get
// whose every id was malformed passed NULL to the reducer — the "fetch ALL"
// sentinel — returning the entire collection for garbage input.
func TestGetAllMalformedIDsDoesNotFetchAll(t *testing.T) {
	fake := &fakeCaller{returnRaw: json.RawMessage(`{"accountId":"1","state":"3","list":[],"notFound":[]}`)}
	h := newFakeHandler(fake)

	_, res := h.mailboxGet(context.Background(), testClaims(1), json.RawMessage(`{"accountId":"1","ids":["abc"]}`))
	if got, isNil := fake.gotArgs[1], fake.gotArgs[1] == nil; isNil {
		t.Errorf("reducer received NULL ids (fetch-all) for all-malformed input: %#v", got)
	}
	var out struct {
		NotFound []string `json:"notFound"`
	}
	_ = json.Unmarshal(res, &out)
	if len(out.NotFound) != 1 || out.NotFound[0] != "abc" {
		t.Errorf("notFound = %v, want [abc]", out.NotFound)
	}

	// Absent ids still means fetch-all (NULL) — valid-input behavior pinned.
	h.mailboxGet(context.Background(), testClaims(1), json.RawMessage(`{"accountId":"1"}`))
	if fake.gotArgs[1] != nil {
		t.Errorf("absent ids must stay NULL (get-all), got %#v", fake.gotArgs[1])
	}
}

// TestSetDestroyMalformedIDsLandInNotDestroyed drives dispatchSet (Task/set)
// with one valid and one malformed destroy id.
func TestSetDestroyMalformedIDsLandInNotDestroyed(t *testing.T) {
	fake := &fakeCaller{
		batchResults: map[string]json.RawMessage{
			"jmap_task_set_destroy": json.RawMessage(`{"destroyed":["7"],"notDestroyed":{},"newState":"4"}`),
		},
	}
	h := newFakeHandler(fake)

	name, res := h.taskSet(context.Background(), testClaims(1), json.RawMessage(`{"accountId":"1","destroy":["7","xyz"]}`))
	if name != "Task/set" {
		t.Fatalf("got %s: %s", name, res)
	}
	ids, ok := fake.gotBatchArgs[0][1].([]int64)
	if !ok || len(ids) != 1 || ids[0] != 7 {
		t.Errorf("destroy reducer ids = %#v, want [7]", fake.gotBatchArgs[0][1])
	}
	var out struct {
		NotDestroyed map[string]struct {
			Type string `json:"type"`
		} `json:"notDestroyed"`
	}
	_ = json.Unmarshal(res, &out)
	if out.NotDestroyed["xyz"].Type != "notFound" {
		t.Errorf("notDestroyed = %v, want xyz→notFound", out.NotDestroyed)
	}
}

// TestFreeBusyMalformedUserIDRejected pins the availability-correctness fix:
// a malformed userIds entry rejects with invalidArguments naming the position
// instead of silently computing free/busy for a subset.
func TestFreeBusyMalformedUserIDRejected(t *testing.T) {
	fake := &fakeCaller{returnRaw: json.RawMessage(`{}`)}
	h := newFakeHandler(fake)

	name, res := h.calendarEventQueryFreeSlots(context.Background(), testClaims(1),
		json.RawMessage(`{"accountId":"1","userIds":["3","bogus"],"start":"2026-01-01T00:00:00Z","end":"2026-01-02T00:00:00Z"}`))
	if name != "error" {
		t.Fatalf("got %s: %s", name, res)
	}
	var e Error
	_ = json.Unmarshal(res, &e)
	if e.Type != "invalidArguments" || !strings.Contains(e.Description, "userIds[1]") {
		t.Errorf("error = %+v, want invalidArguments naming userIds[1]", e)
	}
}
