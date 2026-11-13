package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"setjoin.com/authserver/internal/config"
	"setjoin.com/authserver/internal/handlers"
	sharedcfg "setjoin.com/shared/config"
)

// probeWithBearer POSTs a form request (no OAuth client credentials supplied)
// carrying an optional Bearer key. The introspect/revoke handlers authenticate
// the INTERNAL_API_KEY BEFORE touching any store, and authenticateClient
// short-circuits on absent credentials, so no database is in the loop: an
// authenticated caller without a token is answered 400 "token is required"
// (key accepted) while a failed authentication answers 401 (key rejected).
func probeWithBearer(t *testing.T, h http.Handler, key string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/probe", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// TestReloadRotatesInternalAPIKeyWithoutRestart pins the D-AUTHSERVER-CMD-
// AUTHSERVERD-002 remediation: POST /admin/reload (and SIGHUP) commit a fresh
// config through commitReload so a rotated INTERNAL_API_KEY takes effect on
// every consumer — introspect, revoke and the dynamic RequireAPIKey gates —
// without a restart, and the old key stops authenticating immediately.
func TestReloadRotatesInternalAPIKeyWithoutRestart(t *testing.T) {
	var cfgPtr sharedcfg.ConfigPtr[config.Config]
	cfgPtr.Store(&config.Config{InternalAPIKey: "key-a"})

	// Mirrors the composition-root wiring: the handlers sit behind atomic
	// pointers and are rebuilt on reload. They run with no pool here because
	// the probes below never present a token after authenticating.
	var introspectLive atomic.Pointer[handlers.IntrospectHandler]
	var revokeLive atomic.Pointer[handlers.RevokeHandler]
	rebuild := func(cfg *config.Config) {
		introspectLive.Store(&handlers.IntrospectHandler{APIKey: cfg.InternalAPIKey})
		revokeLive.Store(&handlers.RevokeHandler{APIKey: cfg.InternalAPIKey})
	}
	rebuild(cfgPtr.Load())

	introspectRoute := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		introspectLive.Load().ServeHTTP(w, r)
	})
	revokeRoute := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		revokeLive.Load().ServeHTTP(w, r)
	})
	scimGate := requireAPIKeyLive(&cfgPtr)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	if got := probeWithBearer(t, introspectRoute, "key-a"); got != http.StatusBadRequest {
		t.Fatalf("introspect with boot key: status=%d, want 400 (authenticated, token required)", got)
	}
	if got := probeWithBearer(t, revokeRoute, "key-a"); got != http.StatusBadRequest {
		t.Fatalf("revoke with boot key: status=%d, want 400 (authenticated, token required)", got)
	}
	if got := probeWithBearer(t, scimGate, "key-a"); got != http.StatusNoContent {
		t.Fatalf("scim gate with boot key: status=%d, want 204", got)
	}

	report := commitReload(&cfgPtr, rebuild, &config.Config{InternalAPIKey: "key-b"})
	if len(report.Rearmed) != 1 || report.Rearmed[0] != "internal_api_key" {
		t.Fatalf("report.Rearmed=%v, want [internal_api_key]", report.Rearmed)
	}
	if len(report.RestartRequired) == 0 {
		t.Fatal("reload report claimed a complete reload: no restart-required consumers listed")
	}
	if got := cfgPtr.Load().InternalAPIKey; got != "key-b" {
		t.Fatalf("live config key=%q, want key-b after reload", got)
	}

	// The rotated-out key is dead on every consumer; the rotated-in key works.
	consumers := map[string]struct {
		handler http.Handler
		newWant int
	}{
		"introspect": {introspectRoute, http.StatusBadRequest},
		"revoke":     {revokeRoute, http.StatusBadRequest},
		"scim_gate":  {scimGate, http.StatusNoContent},
	}
	for name, consumer := range consumers {
		if got := probeWithBearer(t, consumer.handler, "key-a"); got != http.StatusUnauthorized {
			t.Fatalf("%s with rotated-out key: status=%d, want 401", name, got)
		}
		if got := probeWithBearer(t, consumer.handler, "key-b"); got != consumer.newWant {
			t.Fatalf("%s with rotated-in key: status=%d, want %d", name, got, consumer.newWant)
		}
	}
}

// TestCommitReloadPublishesConfigAndReportsRestartBoundConsumers verifies the
// commit seam itself: the fresh config becomes live, the rebuild hook runs,
// and the report names every boot-captured consumer that stays restart-bound
// instead of claiming an unconditional success.
func TestCommitReloadPublishesConfigAndReportsRestartBoundConsumers(t *testing.T) {
	var cfgPtr sharedcfg.ConfigPtr[config.Config]
	cfgPtr.Store(&config.Config{InternalAPIKey: "old"})
	rebuilds := 0
	report := commitReload(&cfgPtr, func(*config.Config) { rebuilds++ }, &config.Config{InternalAPIKey: "new"})
	if got := cfgPtr.Load().InternalAPIKey; got != "new" {
		t.Fatalf("live config key=%q, want new after commit", got)
	}
	if rebuilds != 1 {
		t.Fatalf("rebuild calls=%d, want 1", rebuilds)
	}
	if len(report.Rearmed) == 0 {
		t.Fatal("reload report listed no rearmed seams")
	}
	for _, consumer := range restartBoundConfigConsumers {
		found := false
		for _, listed := range report.RestartRequired {
			if listed == consumer {
				found = true
			}
		}
		if !found {
			t.Fatalf("report.RestartRequired=%v is missing boot-captured consumer %q", report.RestartRequired, consumer)
		}
	}
}

// TestRequireAPIKeyLiveFailsClosedOnEmptyLiveKey: a reload that empties the
// key must never leave the gate open; the shared middleware's empty-key
// behavior rejects with 500.
func TestRequireAPIKeyLiveFailsClosedOnEmptyLiveKey(t *testing.T) {
	var cfgPtr sharedcfg.ConfigPtr[config.Config]
	cfgPtr.Store(&config.Config{})
	gate := requireAPIKeyLive(&cfgPtr)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("gate passed with an empty live INTERNAL_API_KEY")
	}))
	req := httptest.NewRequest(http.MethodPost, "/auth/scim/disable", nil)
	req.Header.Set("Authorization", "Bearer whatever")
	rr := httptest.NewRecorder()
	gate.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500 fail-closed for empty live key", rr.Code)
	}
}

// TestReloadReportJSONNamesRestartRequired keeps the wire contract explicit:
// the response must carry restart_required so an operator can never mistake a
// partial reload for a full one.
func TestReloadReportJSONNamesRestartRequired(t *testing.T) {
	body, err := json.Marshal(reloadReport{
		Rearmed:         []string{"internal_api_key"},
		RestartRequired: []string{"threat_settings"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"rearmed":["internal_api_key"]`, `"restart_required":["threat_settings"]`} {
		if !bytes.Contains(body, []byte(want)) {
			t.Fatalf("report JSON %s missing %s", body, want)
		}
	}
}

// TestOverlappingReloadsPublishOneConsistentGeneration pins the overlapping-
// reload serialization (Astra wave89 P2, med-shard3-001): the HTTP
// /admin/reload handler goroutine and the SIGHUP drain goroutine both call
// commitReload, and without serialized publication they can interleave the
// Store and rebuild halves — B publishes its config and finishes its handlers,
// then A's stale rebuild overwrites them, leaving introspect/revoke on
// generation A while the dynamic RequireAPIKey gates serve generation B.
//
// The schedule is fully deterministic: reload A is frozen mid-commit inside
// its rebuild while reload B runs commitReload in full, and a TryLock probe
// proves the rebuild half runs under reloadCommitMu. The end state must be a
// single consistent handler generation.
func TestOverlappingReloadsPublishOneConsistentGeneration(t *testing.T) {
	var cfgPtr sharedcfg.ConfigPtr[config.Config]
	cfgPtr.Store(&config.Config{InternalAPIKey: "boot"})

	inRebuildA := make(chan struct{})
	releaseA := make(chan struct{})
	var introspectLive atomic.Pointer[handlers.IntrospectHandler]
	rebuild := func(cfg *config.Config) {
		// With publication serialized, the live config at rebuild time is
		// always exactly the config being rebuilt — never another reload's.
		if live := cfgPtr.Load(); live != cfg {
			if live == nil {
				t.Errorf("torn generation mid-commit: rebuilding %q while live config is unset", cfg.InternalAPIKey)
			} else {
				t.Errorf("torn generation mid-commit: rebuilding %q while live config holds %q",
					cfg.InternalAPIKey, live.InternalAPIKey)
			}
		}
		if cfg.InternalAPIKey == "key-a" {
			// The rebuild half of a commit must run under reloadCommitMu. A
			// successful TryLock here means publication is not serialized and
			// a concurrent reload could interleave Store with this rebuild.
			if reloadCommitMu.TryLock() {
				reloadCommitMu.Unlock()
				t.Error("commitReload rebuild ran without holding reloadCommitMu: overlapping reloads can interleave Store and rebuild")
			}
			close(inRebuildA)
			<-releaseA
		}
		introspectLive.Store(&handlers.IntrospectHandler{APIKey: cfg.InternalAPIKey})
	}

	done := make(chan struct{}, 2)
	commit := func(key string) {
		defer func() { done <- struct{}{} }()
		commitReload(&cfgPtr, rebuild, &config.Config{InternalAPIKey: key})
	}

	// Overlap the two reload entry points: the HTTP /admin/reload goroutine is
	// frozen mid-commit inside its rebuild while the SIGHUP drain goroutine
	// runs its own commitReload from Store through rebuild.
	go commit("key-a")
	<-inRebuildA
	go commit("key-b")
	close(releaseA)
	<-done
	<-done

	// The overlapping reloads must end as ONE generation: the published
	// config and the rebuilt handlers always agree. Under the defect this
	// schedule deterministically left the handlers on key-a while the live
	// config served key-b.
	liveKey := cfgPtr.Load().InternalAPIKey
	if h := introspectLive.Load(); h == nil || h.APIKey != liveKey {
		t.Fatalf("overlapping reloads left a torn generation: published config key=%q, rebuilt handler key=%v",
			liveKey, h)
	}
}
