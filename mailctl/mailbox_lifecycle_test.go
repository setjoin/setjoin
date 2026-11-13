package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMailboxLifecycleSuspendCarriesFences(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/admin/mailboxes/42/lifecycle" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["action"] != "suspend" || body["expectedGeneration"] != "7" ||
			r.Header.Get("X-Audit-Reason") != "security investigation" ||
			r.Header.Get("Idempotency-Key") == "" || r.Header.Get("Idempotency-Key") != body["idempotencyKey"] {
			t.Fatalf("request fences/body = %#v headers=%v", body, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"mailboxId":"42","generation":"8","access":"suspended"}`))
	}))
	defer server.Close()
	c := &cmdCtx{client: &Client{Server: server.URL, HTTP: server.Client()}, quiet: true, yes: true}
	if err := runMailboxLifecycle(c, "suspend", []string{"42", "--generation", "7", "--reason", "security investigation"}); err != nil {
		t.Fatal(err)
	}
}

func TestMailboxLifecycleRejectsUnsafeReasonBeforeRequest(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer server.Close()
	c := &cmdCtx{client: &Client{Server: server.URL, HTTP: server.Client()}, quiet: true, yes: true}
	if err := runMailboxLifecycle(c, "detach-retain", []string{"42", "--generation", "7", "--reason", "bad\nreason"}); err == nil {
		t.Fatal("expected unsafe reason rejection")
	}
	if calls != 0 {
		t.Fatalf("unsafe input made %d requests", calls)
	}
}
