package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpgradeRetiresCallerOwnedBinaryAndRollbackVerbs(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer server.Close()
	ctx := &cmdCtx{client: &Client{Server: server.URL, HTTP: server.Client()}, yes: true}
	for _, action := range []string{"check", "apply", "rollback"} {
		if err := runUpgrade(ctx, action, []string{"/tmp/caller-owned"}); err == nil ||
			!strings.Contains(err.Error(), "unknown upgrade action") {
			t.Fatalf("%s error=%v", action, err)
		}
	}
	if calls != 0 {
		t.Fatalf("retired mutation verbs contacted server %d times", calls)
	}
}

func TestUpgradeStatusAndHistoryUseTransactionalReadModel(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Method != http.MethodGet || r.URL.Path != "/api/admin/system/upgrades" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schemaVersion": 1, "flags": map[string]bool{"catalog": true, "execution": false},
			"history": []map[string]any{{"intentId": "42", "releaseId": "release-179", "state": "verified", "createdAt": "2026-08-01T00:00:00Z"}},
		})
	}))
	defer server.Close()
	ctx := &cmdCtx{client: &Client{Server: server.URL, HTTP: server.Client()}, json: true}
	if err := runUpgrade(ctx, "status", nil); err != nil {
		t.Fatal(err)
	}
	if err := runUpgrade(ctx, "history", nil); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("paths=%v", paths)
	}
}

func TestUpgradeCancelValidatesDecimalBindingsAndSendsReason(t *testing.T) {
	var gotReason string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/system/upgrades/intents/42/cancel" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		gotReason = r.Header.Get("X-Audit-Reason")
		_ = json.NewEncoder(w).Encode(map[string]any{"intentId": "42", "state": "cancel_requested", "stateGeneration": "8"})
	}))
	defer server.Close()
	ctx := &cmdCtx{client: &Client{Server: server.URL, HTTP: server.Client()}, json: true}
	if err := runUpgrade(ctx, "cancel", []string{"042", "--generation", "7", "--reason", "planned cancel"}); err == nil {
		t.Fatal("non-canonical intent id accepted")
	}
	if err := runUpgrade(ctx, "cancel", []string{"42", "--generation", "7", "--reason", "planned cancel"}); err != nil {
		t.Fatal(err)
	}
	if gotReason != "planned cancel" {
		t.Fatalf("reason=%q", gotReason)
	}
}

func TestUpgradeDiagnosticsIsIDDrivenBoundedAndCreatesPrivateFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/system/upgrades/intents/42/diagnostics" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"intentId": "42", "manifestDigest": strings.Repeat("a", 64), "events": []any{}})
	}))
	defer server.Close()
	ctx := &cmdCtx{client: &Client{Server: server.URL, HTTP: server.Client()}}
	output := filepath.Join(t.TempDir(), "upgrade-diagnostics.json")
	if err := runUpgrade(ctx, "diagnostics", []string{"42", "--output", output}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	if err := runUpgrade(ctx, "diagnostics", []string{"42", "--output", output}); err == nil {
		t.Fatal("existing output was overwritten")
	}
}

func TestUpgradeWatchCoversSuccessFailureTimeoutAndValidation(t *testing.T) {
	for name, states := range map[string][]string{
		"verified": {"claimed", "verified"},
		"failed":   {"failed"},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/admin/system/upgrades/intents/42" {
					t.Fatalf("path=%s", r.URL.Path)
				}
				state := states[calls]
				if calls < len(states)-1 {
					calls++
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"state": state, "updatedAt": "2026-08-01T00:00:00Z"})
			}))
			defer server.Close()
			ctx := &cmdCtx{client: &Client{Server: server.URL, HTTP: server.Client()}, json: name == "verified", quiet: true}
			err := runUpgrade(ctx, "watch", []string{"42", "--interval", "250ms", "--timeout", "2s"})
			if name == "verified" && err != nil {
				t.Fatal(err)
			}
			if name == "failed" && (err == nil || !strings.Contains(err.Error(), "terminal state failed")) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	timeoutServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"state": "claimed"})
	}))
	defer timeoutServer.Close()
	ctx := &cmdCtx{client: &Client{Server: timeoutServer.URL, HTTP: timeoutServer.Client()}, quiet: true}
	if err := runUpgrade(ctx, "watch", []string{"42", "--interval", "250ms", "--timeout", "1ns"}); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout err=%v", err)
	}
	for name, args := range map[string][]string{
		"missing":  nil,
		"id":       {"042"},
		"interval": {"42", "--interval", "1ms"},
		"timeout":  {"42", "--timeout", "25h"},
		"extra":    {"42", "extra"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := runUpgrade(ctx, "watch", args); err == nil {
				t.Fatal("invalid watch accepted")
			}
		})
	}
}

func TestUpgradeReadAndMutationTransportFailuresAreReturned(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	ctx := &cmdCtx{client: &Client{Server: server.URL, HTTP: server.Client()}, quiet: true}
	for _, call := range []struct {
		action string
		args   []string
	}{
		{action: "status"}, {action: "history"},
		{action: "watch", args: []string{"42", "--timeout", "1s"}},
		{action: "cancel", args: []string{"42", "--generation", "7", "--reason", "planned cancel"}},
		{action: "diagnostics", args: []string{"42", "--output", filepath.Join(t.TempDir(), "out")}},
	} {
		if err := runUpgrade(ctx, call.action, call.args); err == nil {
			t.Fatalf("%s transport failure ignored", call.action)
		}
	}
}

func TestUpgradeCancelAndDiagnosticsRejectEveryLocalBoundary(t *testing.T) {
	ctx := &cmdCtx{client: &Client{}}
	for name, args := range map[string][]string{
		"missing":      nil,
		"id":           {"042"},
		"parse":        {"42", "--unknown"},
		"extra":        {"42", "extra"},
		"generation":   {"42", "--generation", "0", "--reason", "planned cancel"},
		"reason short": {"42", "--generation", "7", "--reason", "short"},
		"reason long":  {"42", "--generation", "7", "--reason", strings.Repeat("x", 1025)},
	} {
		t.Run("cancel "+name, func(t *testing.T) {
			if err := runUpgrade(ctx, "cancel", args); err == nil {
				t.Fatal("invalid cancel accepted")
			}
		})
	}
	for name, args := range map[string][]string{
		"missing": nil,
		"id":      {"042"},
		"output":  {"42"},
		"parse":   {"42", "--unknown"},
		"extra":   {"42", "--output", "/tmp/out", "extra"},
	} {
		t.Run("diagnostics "+name, func(t *testing.T) {
			if err := runUpgrade(ctx, "diagnostics", args); err == nil {
				t.Fatal("invalid diagnostics accepted")
			}
		})
	}
}

func TestUpgradeHistoryHumanAndTerminalStateContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"history": []map[string]any{{"createdAt": "now", "intentId": "42", "releaseId": "r", "state": "verified"}}})
	}))
	defer server.Close()
	if err := runUpgrade(&cmdCtx{client: &Client{Server: server.URL, HTTP: server.Client()}}, "history", nil); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"verified", "rolled_back", "failed", "recovery_required", "cancelled", "expired"} {
		if !terminalUpgradeState(state) {
			t.Fatalf("terminal state %q rejected", state)
		}
	}
	if terminalUpgradeState("claimed") {
		t.Fatal("nonterminal state accepted")
	}
	for _, raw := range []string{"", "0", "-1", "01", "x"} {
		if _, err := canonicalIntentID(raw); err == nil {
			t.Fatalf("invalid id %q accepted", raw)
		}
	}
}
