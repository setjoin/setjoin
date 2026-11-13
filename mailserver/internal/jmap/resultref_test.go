package jmap

import (
	"encoding/json"
	"reflect"
	"testing"
)

// mc is a small constructor for a prior MethodCall response (name + JSON args
// under a client id), used to seed the resolver's `prior` slice.
func mc(name, argsJSON, clientID string) MethodCall {
	return MethodCall{Name: name, ClientID: clientID, Args: json.RawMessage(argsJSON)}
}

// TestEvalPointer drives the RFC 6901 + §3.7 JSON Pointer evaluator directly.
func TestEvalPointer(t *testing.T) {
	doc := mustDecode(t, `{
		"ids": ["a", "b", "c"],
		"nested": {"deep": 42},
		"list": [
			{"emailIds": ["m1", "m2"], "threadId": "t1"},
			{"emailIds": ["m3"], "threadId": "t2"}
		],
		"a~b": "tilde",
		"a/b": "slash"
	}`)

	cases := []struct {
		name    string
		pointer string
		want    any
		wantErr bool
	}{
		{"empty returns whole doc", "", doc, false},
		{"simple property (array)", "/ids", []any{"a", "b", "c"}, false},
		{"nested property", "/nested/deep", float64(42), false},
		{"array index", "/ids/1", "b", false},
		{"star maps scalar field", "/list/*/threadId", []any{"t1", "t2"}, false},
		{"star maps and flattens arrays", "/list/*/emailIds", []any{"m1", "m2", "m3"}, false},
		{"tilde-0 unescape (~)", "/a~0b", "tilde", false},
		{"tilde-1 unescape (/)", "/a~1b", "slash", false},
		{"missing key fails", "/nope", nil, true},
		{"bad index fails", "/ids/9", nil, true},
		{"non-numeric index fails", "/ids/x", nil, true},
		{"star on non-array fails", "/nested/*", nil, true},
		{"pointer without leading slash fails", "ids", nil, true},
		{"descend into scalar fails", "/nested/deep/more", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := evalPointer(doc, c.pointer)
			if c.wantErr {
				if err == nil {
					t.Fatalf("evalPointer(%q) = %v, want error", c.pointer, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("evalPointer(%q) unexpected error: %v", c.pointer, err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("evalPointer(%q) = %#v, want %#v", c.pointer, got, c.want)
			}
		})
	}
}

// TestResolveReferences_RFCExample1_Created mirrors the RFC 8620 §3.7 first
// worked example: a "#id" arg taken from a prior /set response's "/created".
func TestResolveReferences_RFCExample1_Created(t *testing.T) {
	prior := []MethodCall{
		mc("Email/set", `{"created": {"draft1": {"id": "M1234"}}}`, "t0"),
	}
	args := json.RawMessage(`{"accountId":"A","#id":{"resultOf":"t0","name":"Email/set","path":"/created/draft1/id"}}`)
	out, refErr := resolveReferences(args, prior)
	if refErr != nil {
		t.Fatalf("unexpected error: %+v", *refErr)
	}
	var m map[string]any
	mustUnmarshal(t, out, &m)
	if _, present := m["#id"]; present {
		t.Errorf("resolved output still carries the #id key: %s", out)
	}
	if m["id"] != "M1234" {
		t.Errorf("resolved id = %v, want M1234 (out=%s)", m["id"], out)
	}
	if m["accountId"] != "A" {
		t.Errorf("plain accountId lost: %s", out)
	}
}

// TestResolveReferences_RFCExample2_Chain mirrors the §3.7 three-link example:
// Email/query → Email/get (#ids from /ids) → Thread/get (#ids from
// /list/*/threadId), plus an Email/get reading /list/*/emailIds and flattening.
func TestResolveReferences_RFCExample2_Chain(t *testing.T) {
	prior := []MethodCall{
		mc("Email/query", `{"ids": ["e1", "e2"]}`, "t0"),
		mc("Email/get", `{"list": [
			{"id": "e1", "threadId": "th1", "emailIds": ["e1", "e9"]},
			{"id": "e2", "threadId": "th2", "emailIds": ["e2"]}
		]}`, "t1"),
	}

	// Email/get pulls #ids from Email/query's /ids.
	getArgs := json.RawMessage(`{"#ids":{"resultOf":"t0","name":"Email/query","path":"/ids"}}`)
	getOut, e1 := resolveReferences(getArgs, prior)
	if e1 != nil {
		t.Fatalf("Email/get ref: %+v", *e1)
	}
	var gm map[string]any
	mustUnmarshal(t, getOut, &gm)
	if !reflect.DeepEqual(gm["ids"], []any{"e1", "e2"}) {
		t.Errorf("Email/get ids = %v, want [e1 e2]", gm["ids"])
	}

	// Thread/get pulls #ids from Email/get's /list/*/threadId.
	thrArgs := json.RawMessage(`{"#ids":{"resultOf":"t1","name":"Email/get","path":"/list/*/threadId"}}`)
	thrOut, e2 := resolveReferences(thrArgs, prior)
	if e2 != nil {
		t.Fatalf("Thread/get ref: %+v", *e2)
	}
	var tm map[string]any
	mustUnmarshal(t, thrOut, &tm)
	if !reflect.DeepEqual(tm["ids"], []any{"th1", "th2"}) {
		t.Errorf("Thread/get ids = %v, want [th1 th2]", tm["ids"])
	}

	// A nested /list/*/emailIds flattens array-of-arrays one level.
	flatArgs := json.RawMessage(`{"#ids":{"resultOf":"t1","name":"Email/get","path":"/list/*/emailIds"}}`)
	flatOut, e3 := resolveReferences(flatArgs, prior)
	if e3 != nil {
		t.Fatalf("flatten ref: %+v", *e3)
	}
	var fm map[string]any
	mustUnmarshal(t, flatOut, &fm)
	if !reflect.DeepEqual(fm["ids"], []any{"e1", "e9", "e2"}) {
		t.Errorf("flattened emailIds = %v, want [e1 e9 e2]", fm["ids"])
	}
}

// TestResolveReferences_Errors covers the RFC §3.7 error matrix.
func TestResolveReferences_Errors(t *testing.T) {
	prior := []MethodCall{
		mc("Email/query", `{"ids": ["e1"]}`, "t0"),
		mc("error", `{"type":"serverFail"}`, "terr"),
	}
	cases := []struct {
		name     string
		args     string
		wantType string
	}{
		{"unknown resultOf", `{"#ids":{"resultOf":"nope","name":"Email/query","path":"/ids"}}`, "invalidResultReference"},
		{"name mismatch", `{"#ids":{"resultOf":"t0","name":"Mailbox/query","path":"/ids"}}`, "invalidResultReference"},
		{"predecessor errored", `{"#ids":{"resultOf":"terr","name":"Email/query","path":"/ids"}}`, "invalidResultReference"},
		{"bad path does not resolve", `{"#ids":{"resultOf":"t0","name":"Email/query","path":"/missing"}}`, "invalidResultReference"},
		{"malformed ResultReference (missing resultOf)", `{"#ids":{"name":"Email/query","path":"/ids"}}`, "invalidResultReference"},
		{"malformed ResultReference (not an object)", `{"#ids":"justastring"}`, "invalidResultReference"},
		{"plain and referenced form clash", `{"ids":["x"],"#ids":{"resultOf":"t0","name":"Email/query","path":"/ids"}}`, "invalidArguments"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, refErr := resolveReferences(json.RawMessage(c.args), prior)
			if refErr == nil {
				t.Fatalf("expected %s error, got nil", c.wantType)
			}
			if refErr.Type != c.wantType {
				t.Errorf("error type = %q, want %q (desc=%q)", refErr.Type, c.wantType, refErr.Description)
			}
		})
	}
}

// TestResolveReferences_NoopOnPlainArgs proves args without any "#" key pass
// through byte-for-byte (the common non-chained path).
func TestResolveReferences_NoopOnPlainArgs(t *testing.T) {
	prior := []MethodCall{mc("Email/query", `{"ids":["e1"]}`, "t0")}
	args := json.RawMessage(`{"accountId":"A","ids":["x","y"]}`)
	out, refErr := resolveReferences(args, prior)
	if refErr != nil {
		t.Fatalf("unexpected error: %+v", *refErr)
	}
	if string(out) != string(args) {
		t.Errorf("plain args mutated: got %s, want %s", out, args)
	}
}

// TestResolveReferences_NoBareStringSubstitution is the mutation-proof
// regression for the deleted string-hack: a plain arg whose VALUE happens to
// equal a prior call's client id ("t0") must survive untouched. The old
// strings.ReplaceAll-based resolver would have corrupted it.
func TestResolveReferences_NoBareStringSubstitution(t *testing.T) {
	prior := []MethodCall{mc("Email/query", `{"ids":["e1","e2"]}`, "t0")}
	args := json.RawMessage(`{"accountId":"t0","filter":{"text":"t0"}}`)
	out, refErr := resolveReferences(args, prior)
	if refErr != nil {
		t.Fatalf("unexpected error: %+v", *refErr)
	}
	var m map[string]any
	mustUnmarshal(t, out, &m)
	if m["accountId"] != "t0" {
		t.Errorf("bare client-id string was substituted: accountId = %v, want \"t0\" (out=%s)", m["accountId"], out)
	}
}

func mustDecode(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return v
}

func mustUnmarshal(t *testing.T, data json.RawMessage, dst any) {
	t.Helper()
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatalf("unmarshal %s: %v", data, err)
	}
}
