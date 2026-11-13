// service_test.go — Pillar C1 Task 5: unit coverage for federation.Service's
// two gates. A real 2-instance dial/accept round trip is Task 9's live gate
// (linux-ci-host, real DNS/TLS/DB) — these tests instead pin the two things that
// MUST be true without any of that: (a) the static gate is inert with no
// config, and (b)/(c) reconcileOnce's core decision — which peers get a
// dial loop, given the allow-list + toggle state — via injected stubs
// (AllowlistLister, Resolver), the AnchorLookup/testharness precedent for
// keeping this logic testable without a database or real network I/O.
package federation

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// fakeResolver always fails SRV lookup immediately — used by the
// dial-loop tests below so a spawned runDialer goroutine never attempts a
// real DNS round trip; it hits sleepBackoff on its very first iteration,
// which returns instantly once the test cancels its context.
type fakeResolver struct{}

func (fakeResolver) LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error) {
	return "", nil, errors.New("fakeResolver: no records (test stub)")
}

func TestDialsFirst(t *testing.T) {
	cases := []struct {
		local, peer string
		want        bool
	}{
		{"alpha.test", "bravo.test", true},
		{"bravo.test", "alpha.test", false},
		{"alpha.test", "charlie.test", true},
		{"charlie.test", "bravo.test", false},
	}
	for _, c := range cases {
		if got := dialsFirst(c.local, c.peer); got != c.want {
			t.Errorf("dialsFirst(%q,%q) = %v, want %v", c.local, c.peer, got, c.want)
		}
	}
	// Exactly one side of every ordered pair dials — the other accepts.
	for _, c := range cases {
		if dialsFirst(c.local, c.peer) == dialsFirst(c.peer, c.local) {
			t.Errorf("dialsFirst(%q,%q) and its reverse must disagree (no double-dial, no double-skip)", c.local, c.peer)
		}
	}
}

// TestNewServiceInertWithoutLocalDomain pins the STATIC gate: no
// FEDERATION_LOCAL_DOMAIN configured (Config.LocalDomain empty, the
// cmd/mailserverd/main.go posture when the env var is unset) means
// NewService returns nil — main.go's own gate additionally never calls it,
// but this is the inert posture at the constructor boundary itself.
func TestNewServiceInertWithoutLocalDomain(t *testing.T) {
	svc := NewService(Config{}, pgxutil.WorkerPool{}, toggle.NewTestFlags(nil), nil, tls.Certificate{}, testLogger())
	if svc != nil {
		t.Fatalf("NewService(empty Config) = %v, want nil (inert — the static gate)", svc)
	}
}

func TestNewServiceBuildsWithLocalDomain(t *testing.T) {
	svc := NewService(Config{LocalDomain: "alpha.test"}, pgxutil.WorkerPool{}, toggle.NewTestFlags(nil), nil, tls.Certificate{}, testLogger())
	if svc == nil {
		t.Fatal("NewService(LocalDomain set) = nil, want a non-nil Service")
	}
}

func TestAcceptLoopSurvivesBootOffAndStartsAfterLiveEnable(t *testing.T) {
	flags := toggle.NewTestFlags(map[string]bool{toggle.FeatureFederation: false})
	svc := NewService(
		Config{LocalDomain: "alpha.test"},
		pgxutil.WorkerPool{}, flags, nil, tls.Certificate{}, testLogger(),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	entered := make(chan struct{})
	go svc.runAcceptLoop(ctx, time.Millisecond, func() error {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-ctx.Done()
		return nil
	})
	time.Sleep(10 * time.Millisecond)
	if got := calls.Load(); got != 0 {
		t.Fatalf("accept loop started while boot toggle was OFF: calls=%d", got)
	}

	flags.OnNotify(toggle.FeatureFederation, true)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("accept loop did not start after live feature enable")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("accept loop calls=%d, want exactly one", got)
	}
}

func TestAcceptLoopStopsWhenContextEndsWhileFeatureIsOff(t *testing.T) {
	flags := toggle.NewTestFlags(map[string]bool{toggle.FeatureFederation: false})
	svc := NewService(Config{LocalDomain: "alpha.test"}, pgxutil.WorkerPool{}, flags, nil, tls.Certificate{}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	svc.runAcceptLoop(ctx, time.Millisecond, func() error {
		called = true
		return nil
	})
	if called {
		t.Fatal("accept callback ran after cancellation while federation was disabled")
	}
}

func TestAcceptLoopRetriesDynamicDisableThenStopsOnRealFailure(t *testing.T) {
	flags := toggle.NewTestFlags(map[string]bool{toggle.FeatureFederation: true})
	svc := NewService(Config{LocalDomain: "alpha.test"}, pgxutil.WorkerPool{}, flags, nil, tls.Certificate{}, testLogger())
	calls := 0
	svc.runAcceptLoop(context.Background(), time.Millisecond, func() error {
		calls++
		if calls == 1 {
			return ErrFederationDisabled
		}
		return errors.New("listener failed")
	})
	if calls != 2 {
		t.Fatalf("accept callback calls=%d, want one retry and one terminal failure", calls)
	}
}

// TestReconcileOnceOffDropsExistingAndSkipsAllowlistRead pins the DYNAMIC
// gate's OFF branch: reconcileOnce must (1) never call listAllow — a
// disabled feature has nothing to read the allow-list FOR — and (2)
// actively cancel every dial loop it currently owns (dropAll), not just
// refuse to start new ones. A ghost dialer entry is seeded directly
// (bypassing the network dial path entirely) so dropAll's teardown is what
// gets exercised, not runDialer's own machinery.
func TestReconcileOnceOffDropsExistingAndSkipsAllowlistRead(t *testing.T) {
	svc := NewService(Config{LocalDomain: "bravo.test"}, pgxutil.WorkerPool{},
		toggle.NewTestFlags(map[string]bool{toggle.FeatureFederation: false}), nil, tls.Certificate{}, testLogger())
	if svc == nil {
		t.Fatal("NewService returned nil for a non-empty LocalDomain")
	}

	cancelled := false
	svc.dialers["ghost.test"] = func() { cancelled = true }

	listed := false
	svc.listAllow = func(context.Context) ([]AllowlistPeer, error) {
		listed = true
		return []AllowlistPeer{{Domain: "ghost.test", Scope: "dm"}}, nil
	}

	svc.reconcileOnce(context.Background())

	if listed {
		t.Error("reconcileOnce read the allow-list while feature.federation is OFF — must short-circuit before any DB read")
	}
	if len(svc.dialers) != 0 {
		t.Errorf("dialers = %v, want empty after an OFF reconcile (dropAll)", svc.dialers)
	}
	if !cancelled {
		t.Error("dropAll did not cancel the existing dial loop's context — a mid-run OFF flip must actively tear down, not merely stop opening new streams")
	}
}

// TestReconcileOnceDialVsAcceptSplit pins the dial-vs-accept wiring rule
// (dialsFirst) as reconcileOnce actually applies it: given two ENABLED
// peers, one lexicographically smaller than the local domain and one
// larger, exactly the larger one gets a tracked dial loop — the smaller one
// dials US (Listen's forever-running accept loop covers it, no dialer
// entry expected).
func TestReconcileOnceDialVsAcceptSplit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // unblocks any spawned runDialer goroutine's sleepBackoff immediately

	svc := NewService(Config{LocalDomain: "bravo.test"}, pgxutil.WorkerPool{},
		toggle.NewTestFlags(map[string]bool{toggle.FeatureFederation: true}), nil, tls.Certificate{}, testLogger())
	if svc == nil {
		t.Fatal("NewService returned nil for a non-empty LocalDomain")
	}
	svc.resolver = fakeResolver{} // no real DNS I/O from the spawned dial goroutine
	svc.listAllow = func(context.Context) ([]AllowlistPeer, error) {
		return []AllowlistPeer{
			{Domain: "alpha.test", Scope: "dm"},   // alpha.test < bravo.test -> alpha dials us, we ACCEPT
			{Domain: "charlie.test", Scope: "dm"}, // bravo.test < charlie.test -> WE dial charlie
		}, nil
	}

	svc.reconcileOnce(ctx)

	svc.mu.Lock()
	_, dialingAlpha := svc.dialers["alpha.test"]
	_, dialingCharlie := svc.dialers["charlie.test"]
	dialerCount := len(svc.dialers)
	svc.mu.Unlock()

	if dialingAlpha {
		t.Error("dialers contains alpha.test — bravo.test > alpha.test means alpha dials us, we must NOT dial alpha")
	}
	if !dialingCharlie {
		t.Error("dialers missing charlie.test — bravo.test < charlie.test means we must dial charlie")
	}
	if dialerCount != 1 {
		t.Errorf("dialers has %d entries, want exactly 1 (charlie.test only)", dialerCount)
	}
}

// TestReconcileOnceDropsDisabledPeerDialer confirms a peer that drops out of
// the enabled set on a LATER reconcile (an admin disabling it, Task 8) gets
// its dial loop actively cancelled — not merely left alone.
func TestReconcileOnceDropsDisabledPeerDialer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc := NewService(Config{LocalDomain: "bravo.test"}, pgxutil.WorkerPool{},
		toggle.NewTestFlags(map[string]bool{toggle.FeatureFederation: true}), nil, tls.Certificate{}, testLogger())
	if svc == nil {
		t.Fatal("NewService returned nil for a non-empty LocalDomain")
	}
	svc.resolver = fakeResolver{}

	enabled := true
	svc.listAllow = func(context.Context) ([]AllowlistPeer, error) {
		if !enabled {
			return nil, nil
		}
		return []AllowlistPeer{{Domain: "charlie.test", Scope: "dm"}}, nil
	}

	svc.reconcileOnce(ctx)
	svc.mu.Lock()
	_, present := svc.dialers["charlie.test"]
	svc.mu.Unlock()
	if !present {
		t.Fatal("charlie.test dial loop not started on the first reconcile")
	}

	enabled = false
	svc.reconcileOnce(ctx)
	svc.mu.Lock()
	_, stillPresent := svc.dialers["charlie.test"]
	svc.mu.Unlock()
	if stillPresent {
		t.Error("charlie.test dial loop still present after it dropped out of the enabled allow-list — disable must actively drop it (DES-011 eviction)")
	}
}

// TestStreamRegistry_SupersedeClosesPreviousStream pins the supersede-and-close
// discipline (D-MAILSERVER-INTERNAL-FEDERATION-P1-002): registering a new
// stream for a domain whose old stream is still live must CLOSE the old one —
// its read loop and sender goroutines can no longer linger unreferenced and
// unfindable by reconcileOnce — while the registry itself only ever hands out
// the newest stream. The clear-if-current guard still protects the newer
// entry from the old stream's unwind.
func TestStreamRegistry_SupersedeClosesPreviousStream(t *testing.T) {
	reg := newStreamRegistry()

	connA, _ := net.Pipe()
	connB, _ := net.Pipe()
	defer connB.Close() //nolint:errcheck
	old := &PeerStream{conn: connA, Domain: "peer.test"}
	new := &PeerStream{conn: connB, Domain: "peer.test"}

	reg.set("peer.test", old)
	reg.set("peer.test", new)

	// The old stream's conn must be closed by the supersede...
	if err := connA.SetDeadline(time.Now()); err == nil {
		t.Error("superseded stream was not closed (write deadline still settable on a live conn)")
	}
	// ...and the registry must hand out only the newest stream.
	if s := func() *PeerStream {
		reg.mu.RLock()
		defer reg.mu.RUnlock()
		return reg.m["peer.test"]
	}(); s != new {
		t.Errorf("registry entry = %v, want the newest stream", s)
	}

	// The old stream's unwind calls clear(old): clear-if-current must NOT
	// evict the newer registration.
	reg.clear("peer.test", old)
	if s := func() *PeerStream {
		reg.mu.RLock()
		defer reg.mu.RUnlock()
		return reg.m["peer.test"]
	}(); s != new {
		t.Error("stale stream's clear must not evict the superseding registration")
	}
}
