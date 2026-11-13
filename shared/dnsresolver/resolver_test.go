package dnsresolver

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fileTimeout matches net i/o timeouts produced when a deadline (the total
// per-lookup budget) cuts off a dial or read.
var fileTimeout = os.ErrDeadlineExceeded

const testQPSInterval = 2 * time.Millisecond

// queryCounter counts the upstream queries a test DNS server receives.
type queryCounter struct {
	n atomic.Int64
}

// answeringHandler scripts an authoritative DNSSEC (AD-bit) server answering
// A, AAAA, TXT and MX questions; optionally with a per-query delay.
func answeringHandler(counter *queryCounter, delay time.Duration) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		if delay > 0 {
			time.Sleep(delay)
		}
		if counter != nil {
			counter.n.Add(1)
		}
		m := new(dns.Msg)
		m.SetReply(req)
		m.AuthenticatedData = true
		for _, q := range req.Question {
			switch q.Qtype {
			case dns.TypeA:
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IPv4(192, 0, 2, 1),
				})
			case dns.TypeAAAA:
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: net.IPv6loopback,
				})
			case dns.TypeTXT:
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
					Txt: []string{"v=spf1"},
				})
			case dns.TypeMX:
				m.Answer = append(m.Answer, &dns.MX{
					Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60},
					Preference: 10,
					Mx:         "mail." + q.Name,
				})
			}
		}
		_ = w.WriteMsg(m)
	}
}

func startTestServer(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen test DNS server: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return pc.LocalAddr().String()
}

// startGatedServer starts a DNS server whose handler blocks until release is
// closed (or the test ends), simulating an unresponsive upstream.
func startGatedServer(t *testing.T) (release chan struct{}, addr string) {
	t.Helper()
	release = make(chan struct{})
	stopped := make(chan struct{})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen gated DNS server: %v", err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		select {
		case <-release:
		case <-stopped:
			return
		}
		answeringHandler(nil, 0)(w, req)
	})
	server := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() {
		close(stopped)
		_ = server.Shutdown()
	})
	return release, pc.LocalAddr().String()
}

func newTestResolver(t *testing.T, upstream string) *Resolver {
	t.Helper()
	r := New(upstream, nil, slog.New(slog.DiscardHandler))
	t.Cleanup(r.rateLimit.Stop)
	return r
}

// newTrustedTestResolver returns a resolver whose trusted allowlist contains
// exactly the given upstream endpoint — the test-only trusted configuration
// that production reaches only through an explicit dnssec.trusted_resolvers
// entry. AD-set mocks asserted Secure before the trust binding; under it they
// keep that meaning only via this constructor (r2-C6-2: no implicit loopback
// trust, so the default untrusted constructor is what demotes).
func newTrustedTestResolver(t *testing.T, upstream string) *Resolver {
	t.Helper()
	r := newTestResolver(t, upstream)
	r.trustedResolvers = map[string]struct{}{upstream: {}}
	return r
}

// freezeTicker replaces the resolver's 20-QPS ticker with one that never
// fires during the test, so queue slots stay held deterministically.
func freezeTicker(t *testing.T, r *Resolver) {
	t.Helper()
	r.rateLimit.Stop()
	r.rateLimit = time.NewTicker(time.Hour)
	t.Cleanup(r.rateLimit.Stop)
}

// speedUpTicker makes the resolver's ticker fire fast so many lookups can
// pass the rate limiter quickly in tests that exercise other bounds.
func speedUpTicker(t *testing.T, r *Resolver) {
	t.Helper()
	r.rateLimit.Stop()
	r.rateLimit = time.NewTicker(testQPSInterval)
	t.Cleanup(r.rateLimit.Stop)
}

func overrideBudget(t *testing.T, d time.Duration) {
	t.Helper()
	old := lookupBudget
	lookupBudget = d
	t.Cleanup(func() { lookupBudget = old })
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

func uniqueName(prefix string, i int) string {
	return prefix + "-" + strconv.Itoa(i) + ".example.test"
}

func isQueueWait(err error) bool {
	var qwe *QueueWaitError
	return errors.As(err, &qwe)
}

// TestUniqueSubdomainFloodStaysBounded verifies that a flood of unique
// attacker-chosen subdomains does not grow goroutines without bound: excess
// work is rejected at the bounded queue and never diverted through the
// system-resolver fallback.
func TestUniqueSubdomainFloodStaysBounded(t *testing.T) {
	overrideBudget(t, 400*time.Millisecond)
	counter := &queryCounter{}
	upstream := startTestServer(t, answeringHandler(counter, 0))
	r := newTestResolver(t, upstream)

	var fallbackCalls atomic.Int64
	oldIP := systemLookupIP
	systemLookupIP = func(context.Context, string) ([]net.IP, error) {
		fallbackCalls.Add(1)
		return nil, errors.New("system fallback must not run under flood")
	}
	defer func() { systemLookupIP = oldIP }()

	baseline := runtime.NumGoroutine()

	const flood = 500
	var (
		wg           sync.WaitGroup
		rateLimited  atomic.Int64
		succeeded    atomic.Int64
		queueWaitErr atomic.Int64
	)
	for i := 0; i < flood; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := r.LookupIP(context.Background(), uniqueName("flood", i))
			switch {
			case err == nil:
				succeeded.Add(1)
			case errors.Is(err, ErrRateLimited):
				rateLimited.Add(1)
			case isQueueWait(err),
				errors.Is(err, context.DeadlineExceeded),
				errors.Is(err, context.Canceled),
				errors.Is(err, fileTimeout):
				// Bounded outcome: cancelled wait or the total per-lookup
				// budget expired (queueing or exchange phase).
				queueWaitErr.Add(1)
			default:
				t.Errorf("unexpected error for unique subdomain: %v", err)
			}
		}(i)
	}
	wg.Wait()

	if fallbackCalls.Load() != 0 {
		t.Errorf("system-resolver fallback ran %d times under flood; flood must not divert around the bound", fallbackCalls.Load())
	}
	if rateLimited.Load() == 0 {
		t.Errorf("expected bounded-queue rejections under a %d-lookup flood, got none", flood)
	}
	if got := succeeded.Load() + queueWaitErr.Load(); got >= flood {
		t.Errorf("resolver admitted %d of %d flood lookups; waiter bound not effective", got, flood)
	}

	// Bounded queues drain: no goroutines pile up without bound.
	waitFor(t, 3*time.Second, func() bool {
		return r.queueWaiters.Load() == 0 && r.coalesceWaiters.Load() == 0
	}, "queue gauges did not drain after flood")
	waitFor(t, 3*time.Second, func() bool {
		return runtime.NumGoroutine() <= baseline+25
	}, "goroutine count did not return near baseline after flood")
}

// TestCancelledWaitsReleaseQueueSlots verifies that waits on the shared
// 20-QPS ticker are context-cancellation-aware: cancelled waits return a
// distinct *QueueWaitError, release their queue slots, and leave no
// goroutines behind.
func TestCancelledWaitsReleaseQueueSlots(t *testing.T) {
	overrideBudget(t, 300*time.Millisecond)
	counter := &queryCounter{}
	upstream := startTestServer(t, answeringHandler(counter, 0))
	r := newTestResolver(t, upstream)
	freezeTicker(t, r) // no ticker tokens: everyone waits on the queue

	// Phase 1: budget expiry while queued is a distinct, bounded outcome.
	baseline := runtime.NumGoroutine()
	var wg sync.WaitGroup
	for i := 0; i < maxQueueWaiters; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := r.LookupIP(context.Background(), uniqueName("budget", i))
			if !isQueueWait(err) || !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("expected QueueWaitError wrapping DeadlineExceeded, got %v", err)
			}
		}(i)
	}
	wg.Wait()
	waitFor(t, 2*time.Second, func() bool { return r.queueWaiters.Load() == 0 },
		"queue slots not released after budget expiry")
	waitFor(t, 3*time.Second, func() bool {
		return runtime.NumGoroutine() <= baseline+25
	}, "goroutines left behind after budget expiry")

	// Phase 2: explicit cancellation releases slots promptly.
	parent, parentCancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	for i := 0; i < maxQueueWaiters; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := r.LookupIP(parent, uniqueName("cancel", i))
			if !isQueueWait(err) || !errors.Is(err, context.Canceled) {
				t.Errorf("expected QueueWaitError wrapping context.Canceled, got %v", err)
			}
		}(i)
	}
	go func() {
		wg.Wait()
		close(done)
	}()
	waitFor(t, 2*time.Second, func() bool { return r.queueWaiters.Load() == maxQueueWaiters },
		"waiters did not fill the bounded queue")
	cancelStart := time.Now()
	parentCancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled waits did not return promptly")
	}
	if elapsed := time.Since(cancelStart); elapsed > time.Second {
		t.Errorf("cancelled waits returned after %v; cancellation must release slots promptly", elapsed)
	}
	waitFor(t, 2*time.Second, func() bool { return r.queueWaiters.Load() == 0 },
		"queue slots not released after cancellation")

	// Phase 3: released slots are reusable — a fresh waiter acquires a slot
	// (it times out waiting on the frozen ticker, not rejected at the bound).
	_, _, err := r.LookupIP(context.Background(), uniqueName("after-cancel", 0))
	if errors.Is(err, ErrRateLimited) {
		t.Error("fresh lookup rejected at bound after cancelled waits released slots")
	}
	if !isQueueWait(err) {
		t.Errorf("expected QueueWaitError on frozen ticker, got %v", err)
	}
}

// TestSaturationNoFallbackDiversion verifies that at saturation the bounded
// rejections do NOT divert work through the system-resolver fallback:
// fallback activity stays flat (zero) while excess work is rejected at the
// bound.
func TestSaturationNoFallbackDiversion(t *testing.T) {
	overrideBudget(t, 300*time.Millisecond)
	counter := &queryCounter{}
	upstream := startTestServer(t, answeringHandler(counter, 0))
	r := newTestResolver(t, upstream)
	freezeTicker(t, r)

	var fallbackCalls atomic.Int64
	oldTXT := systemLookupTXT
	systemLookupTXT = func(context.Context, string) ([]string, error) {
		fallbackCalls.Add(1)
		return []string{"diverted"}, nil
	}
	defer func() { systemLookupTXT = oldTXT }()

	const load = 300
	var (
		wg          sync.WaitGroup
		rateLimited atomic.Int64
		queueWait   atomic.Int64
		diverted    atomic.Int64
	)
	for i := 0; i < load; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			txts, _, err := r.LookupTXT(context.Background(), uniqueName("sat", i))
			switch {
			case err == nil:
				if len(txts) > 0 && txts[0] == "diverted" {
					diverted.Add(1)
				}
			case errors.Is(err, ErrRateLimited):
				rateLimited.Add(1)
			case isQueueWait(err):
				queueWait.Add(1)
			default:
				t.Errorf("unexpected error under saturation: %v", err)
			}
		}(i)
	}
	wg.Wait()

	if fallbackCalls.Load() != 0 || diverted.Load() != 0 {
		t.Errorf("saturation diverted work through the system-resolver fallback (%d calls, %d diverted results)",
			fallbackCalls.Load(), diverted.Load())
	}
	if rateLimited.Load() == 0 {
		t.Error("expected bounded-queue rejections at saturation, got none")
	}
	if got := rateLimited.Load() + queueWait.Load(); got != load {
		t.Errorf("expected every saturated lookup rejected/deferred at the bound, got %d of %d", got, load)
	}
}

// TestFallbackBoundedAndAccounted verifies the fallback itself is bounded
// (hard concurrency cap) and accounted (rejections counted) so legitimate
// resolver failures cannot flood the system resolver either.
func TestFallbackBoundedAndAccounted(t *testing.T) {
	// SERVFAIL upstream: a legitimate (recurring) resolver failure whose
	// empty answer drives every lookup into the fallback path.
	servfail := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	})
	upstream := startTestServer(t, servfail)
	r := newTestResolver(t, upstream)
	speedUpTicker(t, r) // let all exchanges pass the rate limiter quickly

	var (
		cur    atomic.Int64
		maxCon atomic.Int64
	)
	oldMX := systemLookupMX
	systemLookupMX = func(_ context.Context, domain string) ([]*net.MX, error) {
		n := cur.Add(1)
		for {
			m := maxCon.Load()
			if n <= m || maxCon.CompareAndSwap(m, n) {
				break
			}
		}
		defer cur.Add(-1)
		time.Sleep(80 * time.Millisecond)
		return []*net.MX{{Host: "mail." + domain, Pref: 10}}, nil
	}
	defer func() { systemLookupMX = oldMX }()

	const load = 100
	var (
		wg       sync.WaitGroup
		ok       atomic.Int64
		rejected atomic.Int64
		other    atomic.Int64
	)
	for i := 0; i < load; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := r.LookupMX(context.Background(), uniqueName("fb", i))
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrRateLimited):
				rejected.Add(1)
			default:
				other.Add(1)
				t.Logf("unexpected fallback outcome: %v", err)
			}
		}(i)
	}
	wg.Wait()

	if maxCon.Load() > maxFallbackConns {
		t.Errorf("fallback concurrency reached %d, bound is %d", maxCon.Load(), maxFallbackConns)
	}
	if r.fallbackRejects.Load() == 0 {
		t.Error("expected fallback-bound rejections to be accounted")
	}
	if ok.Load() == 0 || rejected.Load() == 0 {
		t.Errorf("expected a mix of fallback successes (%d) and bound rejections (%d)", ok.Load(), rejected.Load())
	}
	if other.Load() != 0 {
		t.Errorf("%d lookups ended in unexpected errors", other.Load())
	}
}

// TestCacheAbsorptionAndBounds verifies for legitimate traffic that cache
// absorption, DNSSEC classification, per-key coalescing, and the per-exchange
// hard bound (covering queueing, not just the wire exchange) are preserved.
func TestCacheAbsorptionAndBounds(t *testing.T) {
	counter := &queryCounter{}
	upstream := startTestServer(t, answeringHandler(counter, 0))
	// The AD-set mock means the Secure assertions below are meaningful only
	// under the trusted posture (C6: empty allowlist demotes AD, so the
	// default untrusted constructor would classify every answer
	// Indeterminate — see TestSpoofedADDemotedToIndeterminate).
	r := newTrustedTestResolver(t, upstream)

	// Cache absorption: a repeat lookup issues no upstream queries and keeps
	// the DNSSEC classification.
	if _, sec, err := r.LookupTXT(context.Background(), "absorb.example.test"); err != nil || sec != Secure {
		t.Fatalf("first LookupTXT: sec=%v err=%v, want secure/nil", sec, err)
	}
	before := counter.n.Load()
	if _, sec, err := r.LookupTXT(context.Background(), "absorb.example.test"); err != nil || sec != Secure {
		t.Fatalf("cached LookupTXT: sec=%v err=%v, want secure/nil", sec, err)
	}
	if got := counter.n.Load(); got != before {
		t.Errorf("cached lookup issued %d extra upstream queries", got-before)
	}

	// Per-key coalescing: 20 concurrent lookups of one uncached name perform
	// exactly ONE upstream exchange.
	const joins = 20
	before = counter.n.Load()
	var wg sync.WaitGroup
	for i := 0; i < joins; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			txts, sec, err := r.LookupTXT(context.Background(), "coalesce.example.test")
			if err != nil || len(txts) != 1 || txts[0] != "v=spf1" || sec != Secure {
				t.Errorf("coalesced lookup: txts=%v sec=%v err=%v", txts, sec, err)
			}
		}()
	}
	wg.Wait()
	if got := counter.n.Load() - before; got != 1 {
		t.Errorf("%d concurrent same-key lookups performed %d upstream exchanges, want 1", joins, got)
	}
	if r.coalesceRejects.Load() != 0 {
		t.Errorf("legitimate concurrent traffic rejected %d times at the coalesce bound", r.coalesceRejects.Load())
	}

	// Per-exchange hard bound, queue phase: with no ticker tokens available,
	// the total budget still fires — the old design waited without bound.
	overrideBudget(t, 250*time.Millisecond)
	bounded := newTestResolver(t, upstream)
	freezeTicker(t, bounded)
	start := time.Now()
	_, _, err := bounded.LookupIP(context.Background(), "slowqueue.example.test")
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("queue phase consumed %v; the per-lookup budget must cover queueing", elapsed)
	}
	if !isQueueWait(err) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected QueueWaitError wrapping DeadlineExceeded, got %v", err)
	}

	// Per-exchange hard bound, exchange phase: with a slot and token
	// instantly available, an unresponsive upstream is still bounded.
	overrideBudget(t, 300*time.Millisecond)
	_, gatedAddr := startGatedServer(t)
	gated := newTestResolver(t, gatedAddr)
	start = time.Now()
	if _, _, err := gated.LookupIP(context.Background(), "slowexchange.example.test"); err == nil {
		t.Error("expected error from unresponsive upstream")
	} else if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("exchange phase consumed %v; per-exchange hard bound lost", elapsed)
	}
}

// ---- Round-2 delta: ONE per-lookup deadline and mixed-error precedence ----

// legScript scripts how scriptedHandler answers one question type. shape is
// "answer" (valid records), "empty" (NOERROR, no records), "wrongid" (valid
// reply with a mismatched transaction id: an ordinary upstream wire failure)
// or "gated" (block until the server is torn down).
type legScript struct {
	shape string
	delay time.Duration // pause before replying
}

// scriptedHandler answers each question according to its per-qtype script;
// unknown types get an empty NOERROR. Gated replies block until stop is
// closed, which the test server's cleanup does before Shutdown.
func scriptedHandler(scripts map[uint16]legScript, counter *queryCounter, stop <-chan struct{}) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		script, ok := scripts[req.Question[0].Qtype]
		if !ok {
			script = legScript{shape: "empty"}
		}
		if script.shape == "gated" {
			<-stop
			return
		}
		if script.delay > 0 {
			time.Sleep(script.delay)
		}
		if counter != nil {
			counter.n.Add(1)
		}
		m := new(dns.Msg)
		m.SetReply(req)
		m.AuthenticatedData = true
		if script.shape == "answer" {
			q := req.Question[0]
			switch q.Qtype {
			case dns.TypeA:
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IPv4(192, 0, 2, 1),
				})
			case dns.TypeAAAA:
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: net.IPv6loopback,
				})
			case dns.TypeTXT:
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
					Txt: []string{"v=spf1"},
				})
			}
		}
		if script.shape == "wrongid" {
			m.Id++
		}
		_ = w.WriteMsg(m)
	}
}

// startTestTCPServer starts a TCP test DNS server. Unlike UDP, the TCP client
// surfaces a wrongid reply immediately as dns.ErrId — a prompt, ordinary
// (fallback-eligible) upstream wire failure. stop is closed before Shutdown
// so gated handlers never stall the teardown.
func startTestTCPServer(t *testing.T, handler dns.HandlerFunc, stop chan struct{}) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen test TCP DNS server: %v", err)
	}
	server := &dns.Server{Listener: ln, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() {
		close(stop)
		_ = server.Shutdown()
	})
	return ln.Addr().String()
}

// newTCPResolver returns a resolver pointed at a TCP test server so wrongid
// replies surface immediately as ordinary wire failures.
func newTCPResolver(t *testing.T, scripts map[uint16]legScript, counter *queryCounter) *Resolver {
	t.Helper()
	stop := make(chan struct{})
	addr := startTestTCPServer(t, scriptedHandler(scripts, counter, stop), stop)
	r := newTestResolver(t, addr)
	r.client.Net = "tcp"
	return r
}

// TestWireTimeoutNoFallbackAfterBudget verifies wire-timeout behavior: when
// the total per-lookup budget expires inside the wire exchange, the outcome
// is the budget deadline — a socket i/o timeout must not escape the
// context-error classification and start the system-resolver fallback after
// the budget is gone.
func TestWireTimeoutNoFallbackAfterBudget(t *testing.T) {
	overrideBudget(t, 250*time.Millisecond)
	_, gatedAddr := startGatedServer(t)
	r := newTestResolver(t, gatedAddr)

	var fallbackCalls atomic.Int64
	oldTXT := systemLookupTXT
	systemLookupTXT = func(context.Context, string) ([]string, error) {
		fallbackCalls.Add(1)
		return nil, errors.New("system fallback must not run after the budget expired")
	}
	defer func() { systemLookupTXT = oldTXT }()

	start := time.Now()
	_, _, err := r.LookupTXT(context.Background(), "wiretimeout.example.test")
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Errorf("wire timeout consumed %v; the per-lookup budget must end the lookup", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected the budget deadline, got %v", err)
	}
	if fallbackCalls.Load() != 0 {
		t.Errorf("system-resolver fallback ran %d times after the budget expired", fallbackCalls.Load())
	}
}

// TestLookupBudgetCoversBothIPLegs verifies ONE deadline is carried through
// queueing, both A/AAAA exchanges and the fallback: a budget consumed by the
// AAAA leg is not renewed for the A leg, and no fallback starts after it
// expires.
func TestLookupBudgetCoversBothIPLegs(t *testing.T) {
	overrideBudget(t, 600*time.Millisecond)
	counter := &queryCounter{}
	// AAAA: empty success after 400ms. A: answer after another 400ms — under
	// the old per-exchange budget renewal the A leg would complete at ~800ms
	// with a fresh budget and the lookup would succeed; under one shared
	// deadline the A leg dies on the budget at ~600ms.
	upstream := startTestServer(t, scriptedHandler(map[uint16]legScript{
		dns.TypeAAAA: {shape: "empty", delay: 400 * time.Millisecond},
		dns.TypeA:    {shape: "answer", delay: 400 * time.Millisecond},
	}, counter, make(chan struct{})))
	r := newTestResolver(t, upstream)
	speedUpTicker(t, r)

	var fallbackCalls atomic.Int64
	oldIP := systemLookupIP
	systemLookupIP = func(context.Context, string) ([]net.IP, error) {
		fallbackCalls.Add(1)
		return nil, errors.New("system fallback must not run after the budget expired")
	}
	defer func() { systemLookupIP = oldIP }()

	start := time.Now()
	ips, _, err := r.LookupIP(context.Background(), "onebudget.example.test")
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Errorf("lookup consumed %v; the per-lookup budget must cover both legs", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected the A leg to hit the shared budget deadline, got %v", err)
	}
	if len(ips) != 0 {
		t.Errorf("expected no addresses, got %v", ips)
	}
	if fallbackCalls.Load() != 0 {
		t.Errorf("system-resolver fallback ran %d times after the budget expired", fallbackCalls.Load())
	}
}

// TestLookupIPMixedErrorPrecedence locks the mixed-error precedence matrix
// for LookupIP: an overload or cancellation outcome (bounded-queue rejection,
// cancelled wait, expired per-lookup budget) on either A/AAAA leg — or on the
// system-resolver fallback itself — outranks an ordinary resolver failure,
// while a non-empty answer from either leg still wins outright. A wrongid
// reply provides the ordinary upstream failure (dns.ErrId over TCP).
func TestLookupIPMixedErrorPrecedence(t *testing.T) {
	// spyIP scripts the system-resolver fallback and counts its calls.
	spyIP := func(t *testing.T, res []net.IP, err error) *atomic.Int64 {
		calls := &atomic.Int64{}
		old := systemLookupIP
		systemLookupIP = func(context.Context, string) ([]net.IP, error) {
			calls.Add(1)
			return res, err
		}
		t.Cleanup(func() { systemLookupIP = old })
		return calls
	}

	t.Run("ordinary AAAA failure must not mask A-leg deadline", func(t *testing.T) {
		overrideBudget(t, 600*time.Millisecond)
		r := newTCPResolver(t, map[uint16]legScript{
			dns.TypeAAAA: {shape: "wrongid"},
			dns.TypeA:    {shape: "gated"},
		}, nil)
		calls := spyIP(t, nil, errors.New("fallback must not run"))

		_, _, err := r.LookupIP(context.Background(), uniqueName("mixed-a", 1))
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected the A-leg budget deadline to win, got %v", err)
		}
		if errors.Is(err, dns.ErrId) {
			t.Fatalf("ordinary AAAA wire failure masked the A-leg deadline: %v", err)
		}
		if calls.Load() != 0 {
			t.Errorf("fallback ran %d times after the budget expired", calls.Load())
		}
	})

	t.Run("AAAA-leg deadline is not masked by the A leg", func(t *testing.T) {
		overrideBudget(t, 300*time.Millisecond)
		r := newTCPResolver(t, map[uint16]legScript{
			dns.TypeAAAA: {shape: "gated"},
			dns.TypeA:    {shape: "wrongid"},
		}, nil)
		calls := spyIP(t, nil, errors.New("fallback must not run"))

		_, _, err := r.LookupIP(context.Background(), uniqueName("mixed-b", 1))
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected the AAAA-leg budget deadline to win, got %v", err)
		}
		if calls.Load() != 0 {
			t.Errorf("fallback ran %d times after the budget expired", calls.Load())
		}
	})

	t.Run("fallback overload must not be masked by upstream failure", func(t *testing.T) {
		r := newTCPResolver(t, map[uint16]legScript{
			dns.TypeAAAA: {shape: "wrongid"},
			dns.TypeA:    {shape: "wrongid"},
		}, nil)
		calls := spyIP(t, nil, errors.New("fallback must not run"))

		// Occupy the fallback bound: the fallback must be rejected at the
		// bound and that overload outcome must outrank the upstream wire
		// failures on both legs.
		for i := 0; i < maxFallbackConns; i++ {
			r.fallbackSlots <- struct{}{}
		}

		_, _, err := r.LookupIP(context.Background(), uniqueName("mixed-c", 1))
		if !errors.Is(err, ErrRateLimited) {
			t.Fatalf("expected the fallback bound rejection to win, got %v", err)
		}
		if calls.Load() != 0 {
			t.Errorf("spy fallback ran %d times despite a full bound", calls.Load())
		}
	})

	t.Run("ordinary fallback failure keeps the upstream error", func(t *testing.T) {
		r := newTCPResolver(t, map[uint16]legScript{
			dns.TypeAAAA: {shape: "wrongid"},
			dns.TypeA:    {shape: "wrongid"},
		}, nil)
		calls := spyIP(t, nil, errors.New("system resolver down"))

		_, _, err := r.LookupIP(context.Background(), uniqueName("mixed-d", 1))
		if !errors.Is(err, dns.ErrId) {
			t.Fatalf("expected the upstream wire failure to be preserved, got %v", err)
		}
		if calls.Load() != 1 {
			t.Errorf("expected exactly one fallback attempt, got %d", calls.Load())
		}
	})

	t.Run("empty answers fall back to the system resolver", func(t *testing.T) {
		r := newTCPResolver(t, map[uint16]legScript{
			dns.TypeAAAA: {shape: "empty"},
			dns.TypeA:    {shape: "empty"},
		}, nil)
		want := net.IPv4(192, 0, 2, 9)
		calls := spyIP(t, []net.IP{want}, nil)

		ips, _, err := r.LookupIP(context.Background(), uniqueName("mixed-e", 1))
		if err != nil || len(ips) != 1 || !ips[0].Equal(want) {
			t.Fatalf("expected fallback address %v, got ips=%v err=%v", want, ips, err)
		}
		if calls.Load() != 1 {
			t.Errorf("expected exactly one fallback attempt, got %d", calls.Load())
		}
	})

	t.Run("AAAA answer wins over A-leg deadline", func(t *testing.T) {
		overrideBudget(t, 600*time.Millisecond)
		r := newTCPResolver(t, map[uint16]legScript{
			dns.TypeAAAA: {shape: "answer"},
			dns.TypeA:    {shape: "gated"},
		}, nil)
		calls := spyIP(t, nil, errors.New("fallback must not run"))

		ips, _, err := r.LookupIP(context.Background(), uniqueName("mixed-f", 1))
		if err != nil || len(ips) == 0 {
			t.Fatalf("expected a non-empty answer to win outright, got ips=%v err=%v", ips, err)
		}
		if calls.Load() != 0 {
			t.Errorf("fallback ran %d times despite a successful AAAA leg", calls.Load())
		}
	})
}

// ---- C6: AD-bit trust binding (UDP-only scope) ----

// TestSpoofedADDemotedToIndeterminate is the spoofed-AD negative: an upstream
// NOT on the trusted allowlist answers every question with
// AuthenticatedData set. Every lookup path must return Indeterminate — the
// "valid response, validation claim unverifiable" level — never Secure and
// never Unsigned, with cache hits and coalesced joins re-classifying
// consistently through the same choke point. IsDNSSECEnabled must likewise
// refuse the spoofable AD bit.
func TestSpoofedADDemotedToIndeterminate(t *testing.T) {
	counter := &queryCounter{}
	upstream := startTestServer(t, answeringHandler(counter, 0))
	r := newTestResolver(t, upstream) // empty allowlist: AD never honored

	assertIndeterminate := func(sec SecurityLevel, err error, what string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", what, err)
		}
		if sec != Indeterminate {
			t.Errorf("%s: sec=%v, want indeterminate (spoofed AD demoted, never secure/unsigned)", what, sec)
		}
	}

	// Every lookup family funnels through the single classify choke point.
	_, sec, err := r.LookupMX(context.Background(), "spoof-mx.example.test")
	assertIndeterminate(sec, err, "LookupMX")
	_, sec, err = r.LookupTXT(context.Background(), "spoof-txt.example.test")
	assertIndeterminate(sec, err, "LookupTXT")
	_, sec, err = r.LookupIP(context.Background(), "spoof-ip.example.test")
	assertIndeterminate(sec, err, "LookupIP")
	_, sec, err = r.LookupPTR(context.Background(), "192.0.2.77")
	assertIndeterminate(sec, err, "LookupPTR")
	records, sec, err := r.LookupTLSA("spoof-tlsa.example.test")
	assertIndeterminate(sec, err, "LookupTLSA")
	if len(records) != 0 {
		t.Errorf("LookupTLSA records = %v, want none", records)
	}

	// Cache hits re-classify the cached raw message: the repeat lookup issues
	// no upstream exchange and stays Indeterminate.
	before := counter.n.Load()
	_, sec, err = r.LookupTXT(context.Background(), "spoof-txt.example.test")
	assertIndeterminate(sec, err, "cached LookupTXT")
	if got := counter.n.Load(); got != before {
		t.Errorf("cached lookup issued %d extra upstream queries", got-before)
	}

	// Coalesced joiners receive the same raw message and re-classify
	// consistently: all joiners see Indeterminate from exactly one exchange.
	speedUpTicker(t, r)
	const joins = 8
	before = counter.n.Load()
	var wg sync.WaitGroup
	for i := 0; i < joins; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, jsec, jerr := r.LookupTXT(context.Background(), "spoof-join.example.test")
			assertIndeterminate(jsec, jerr, "coalesced LookupTXT")
		}()
	}
	wg.Wait()
	if got := counter.n.Load() - before; got != 1 {
		t.Errorf("%d concurrent same-key lookups performed %d exchanges, want 1", joins, got)
	}

	if r.IsDNSSECEnabled() {
		t.Error("IsDNSSECEnabled = true under an untrusted AD-bearing upstream; spoofable AD must not count as enabled")
	}
}

// TestSpoofedADNegativeStaysIndeterminate is the negative-response coverage
// for the AD-trust predicate: an AD-bearing NXDOMAIN from an upstream outside
// the trusted allowlist classifies Indeterminate. The AD bit is set, so the
// response carries an unverifiable validation claim — an authenticated-style
// denial is a well-formed negative answer, not a validation failure — so it
// must never fall through to Bogus. The same choke point must keep an
// AD-bearing NXDOMAIN from a TRUSTED upstream Secure: the demotion applies to
// untrusted endpoints, not to negative responses.
func TestSpoofedADNegativeStaysIndeterminate(t *testing.T) {
	counter := &queryCounter{}
	// Validating-resolver-style authenticated denial: AD set, Rcode
	// NXDOMAIN, SOA in the authority section.
	nxdomain := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		counter.n.Add(1)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		m.AuthenticatedData = true
		m.Ns = append(m.Ns, &dns.SOA{
			Hdr:     dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:      "ns1.example.test.",
			Mbox:    "hostmaster.example.test.",
			Serial:  1,
			Refresh: 1,
			Retry:   1,
			Expire:  1,
			Minttl:  1,
		})
		_ = w.WriteMsg(m)
	})
	upstream := startTestServer(t, nxdomain)
	r := newTestResolver(t, upstream) // empty allowlist: AD never honored

	// Choke point, unfiltered: an AD-bearing NXDOMAIN message classifies
	// Indeterminate on an untrusted resolver.
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn("nx.example.test"), dns.TypeMX)
	neg := new(dns.Msg)
	neg.SetRcode(q, dns.RcodeNameError)
	neg.AuthenticatedData = true
	if got := r.classifySecurity(neg); got != Indeterminate {
		t.Errorf("classifySecurity(AD+NXDOMAIN) = %v on untrusted upstream, want indeterminate (never bogus)", got)
	}

	// Fresh exchange through the lookup path: Indeterminate. MX/TXT/IP
	// public lookups divert empty answers to the system-resolver fallback by
	// the fallback-stays-Unsigned contract, so the exchange-level negative
	// classification is asserted here directly.
	_, sec, err := r.lookup(context.Background(), "nx.example.test", dns.TypeMX)
	if err != nil {
		t.Fatalf("fresh NXDOMAIN lookup: unexpected error: %v", err)
	}
	if sec != Indeterminate {
		t.Errorf("fresh NXDOMAIN exchange: sec=%v, want indeterminate", sec)
	}

	// Cache hit re-classifies the cached raw NXDOMAIN message, with no new
	// upstream exchange.
	before := counter.n.Load()
	_, sec, err = r.lookup(context.Background(), "nx.example.test", dns.TypeMX)
	if err != nil {
		t.Fatalf("cached NXDOMAIN lookup: unexpected error: %v", err)
	}
	if sec != Indeterminate {
		t.Errorf("cached NXDOMAIN hit: sec=%v, want indeterminate", sec)
	}
	if got := counter.n.Load(); got != before {
		t.Errorf("cached NXDOMAIN lookup issued %d extra upstream queries", got-before)
	}

	// Coalesced joiners re-classify the same negative response
	// consistently: all Indeterminate from exactly one exchange.
	speedUpTicker(t, r)
	const joins = 8
	before = counter.n.Load()
	var wg sync.WaitGroup
	for i := 0; i < joins; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, jsec, jerr := r.lookup(context.Background(), "nx-join.example.test", dns.TypeMX)
			if jerr != nil {
				t.Errorf("coalesced NXDOMAIN join: unexpected error: %v", jerr)
				return
			}
			if jsec != Indeterminate {
				t.Errorf("coalesced NXDOMAIN join: sec=%v, want indeterminate", jsec)
			}
		}()
	}
	wg.Wait()
	if got := counter.n.Load() - before; got != 1 {
		t.Errorf("%d concurrent same-key negative lookups performed %d exchanges, want 1", joins, got)
	}

	// Public lookup families that surface a negative response's own
	// classification (PTR and TLSA do not divert empty answers to the
	// system fallback) return Indeterminate, not Bogus.
	if _, sec, err := r.LookupPTR(context.Background(), "192.0.2.78"); err != nil || sec != Indeterminate {
		t.Errorf("LookupPTR NXDOMAIN: sec=%v err=%v, want indeterminate/nil", sec, err)
	}
	if _, sec, err := r.LookupTLSA("nx-tlsa.example.test"); err != nil || sec != Indeterminate {
		t.Errorf("LookupTLSA NXDOMAIN: sec=%v err=%v, want indeterminate/nil", sec, err)
	}

	// Trusted-leg symmetry: the identical AD-bearing NXDOMAIN from an
	// allowlisted endpoint is honored as Secure on the choke point, on the
	// exchange path, and through LookupPTR.
	trusted := newTrustedTestResolver(t, upstream)
	if got := trusted.classifySecurity(neg); got != Secure {
		t.Errorf("classifySecurity(AD+NXDOMAIN) = %v on trusted upstream, want secure (authenticated denial honored)", got)
	}
	if _, sec, err := trusted.lookup(context.Background(), "nx-trusted.example.test", dns.TypeMX); err != nil || sec != Secure {
		t.Errorf("trusted NXDOMAIN exchange: sec=%v err=%v, want secure/nil", sec, err)
	}
	if _, sec, err := trusted.LookupPTR(context.Background(), "192.0.2.79"); err != nil || sec != Secure {
		t.Errorf("trusted LookupPTR NXDOMAIN: sec=%v err=%v, want secure/nil", sec, err)
	}
}

// TestTrustedResolverHonorsAD is the trusted-resolver positive: the same
// scripted AD answer, from an upstream explicitly on the allowlist (the
// byte-equal "host:port" entry production configures via
// dnssec.trusted_resolvers), is honored as Secure, and IsDNSSECEnabled is
// true only under that posture. A non-matching allowlist entry must not
// trust the endpoint.
func TestTrustedResolverHonorsAD(t *testing.T) {
	upstream := startTestServer(t, answeringHandler(nil, 0))
	r := newTrustedTestResolver(t, upstream)

	if _, sec, err := r.LookupTXT(context.Background(), "trusted.example.test"); err != nil || sec != Secure {
		t.Fatalf("LookupTXT under trusted upstream: sec=%v err=%v, want secure/nil", sec, err)
	}
	if _, sec, err := r.LookupMX(context.Background(), "trusted.example.test"); err != nil || sec != Secure {
		t.Fatalf("LookupMX under trusted upstream: sec=%v err=%v, want secure/nil", sec, err)
	}
	if _, sec, err := r.LookupIP(context.Background(), "trusted.example.test"); err != nil || sec != Secure {
		t.Fatalf("LookupIP under trusted upstream: sec=%v err=%v, want secure/nil", sec, err)
	}
	if !r.IsDNSSECEnabled() {
		t.Error("IsDNSSECEnabled = false under a trusted AD-bearing validating upstream")
	}

	// Byte-equal endpoint matching: an allowlist naming a different endpoint
	// leaves this upstream untrusted.
	other := newTestResolver(t, upstream)
	other.trustedResolvers = map[string]struct{}{"9.9.9.9:53": {}}
	if _, sec, err := other.LookupTXT(context.Background(), "other.example.test"); err != nil || sec != Indeterminate {
		t.Fatalf("LookupTXT with non-matching allowlist entry: sec=%v err=%v, want indeterminate/nil", sec, err)
	}
	if other.IsDNSSECEnabled() {
		t.Error("IsDNSSECEnabled = true when the allowlist does not contain the upstream endpoint")
	}
}

// TestFallbackResultsStayUnsigned pins the fallback contract: every
// system-resolver fallback outcome is classified Unsigned on all four lookup
// families — including a LookupIP whose A/AAAA legs classified Secure — so a
// fallback result can never inherit or promote an exchange leg's security
// level.
func TestFallbackResultsStayUnsigned(t *testing.T) {
	// SERVFAIL upstream: replies are valid (so no error path runs) but carry
	// no answers, driving MX/TXT/IP through the empty-answer fallback leg.
	servfail := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	})
	upstream := startTestServer(t, servfail)
	r := newTestResolver(t, upstream)
	speedUpTicker(t, r)

	oldMX, oldTXT, oldIP, oldAddr := systemLookupMX, systemLookupTXT, systemLookupIP, systemLookupAddr
	systemLookupMX = func(context.Context, string) ([]*net.MX, error) {
		return []*net.MX{{Host: "mail.fallback.test.", Pref: 10}}, nil
	}
	systemLookupTXT = func(context.Context, string) ([]string, error) {
		return []string{"fallback"}, nil
	}
	systemLookupIP = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.IPv4(192, 0, 2, 9)}, nil
	}
	systemLookupAddr = func(context.Context, string) ([]string, error) {
		return []string{"fallback.test."}, nil
	}
	defer func() {
		systemLookupMX, systemLookupTXT, systemLookupIP, systemLookupAddr = oldMX, oldTXT, oldIP, oldAddr
	}()

	if _, sec, err := r.LookupMX(context.Background(), "fb-mx.example.test"); err != nil || sec != Unsigned {
		t.Errorf("LookupMX fallback: sec=%v err=%v, want unsigned/nil", sec, err)
	}
	if _, sec, err := r.LookupTXT(context.Background(), "fb-txt.example.test"); err != nil || sec != Unsigned {
		t.Errorf("LookupTXT fallback: sec=%v err=%v, want unsigned/nil", sec, err)
	}
	// PTR has no empty-answer fallback: an ordinary upstream wire failure
	// (nothing listening) drives it into the bounded fallback instead.
	pr := newTestResolver(t, "127.0.0.1:1")
	if _, sec, err := pr.LookupPTR(context.Background(), "192.0.2.78"); err != nil || sec != Unsigned {
		t.Errorf("LookupPTR fallback: sec=%v err=%v, want unsigned/nil", sec, err)
	}
	if ips, sec, err := r.LookupIP(context.Background(), "fb-ip.example.test"); err != nil || sec != Unsigned || len(ips) != 1 {
		t.Errorf("LookupIP fallback: ips=%v sec=%v err=%v, want one address unsigned/nil", ips, sec, err)
	}

	// Mixed precedence, no promotion: an AD-bearing server that answers both
	// A/AAAA legs EMPTY (so the lookup falls back) classifies Indeterminate
	// untrusted — and Secure under a trusted resolver — yet the fallback
	// result must be Unsigned in both postures, never the legs' level.
	emptyAD := startTestServer(t, scriptedHandler(map[uint16]legScript{}, nil, make(chan struct{})))
	spy := &atomic.Bool{}
	systemLookupIP = func(context.Context, string) ([]net.IP, error) {
		spy.Store(true)
		return []net.IP{net.IPv4(192, 0, 2, 9)}, nil
	}
	defer func() { systemLookupIP = oldIP }()

	for _, tc := range []struct {
		name string
		r    *Resolver
	}{
		{"untrusted-legs-indeterminate", newTestResolver(t, emptyAD)},
		{"trusted-legs-secure", newTrustedTestResolver(t, emptyAD)},
	} {
		ips, sec, err := tc.r.LookupIP(context.Background(), uniqueName("fb-mixed", 1))
		if err != nil || len(ips) != 1 {
			t.Fatalf("%s: fallback ips=%v err=%v, want one address/nil", tc.name, ips, err)
		}
		if sec != Unsigned {
			t.Errorf("%s: fallback sec=%v, want unsigned (fallback must not inherit the legs' level)", tc.name, sec)
		}
	}
	if !spy.Load() {
		t.Fatal("fallback spy never ran; the mixed-precedence arms did not exercise the fallback")
	}
}

// TestUDPOnlyTransport is the r3 UDP-only scope assertion: the plaintext-UDP
// dns.Client built by New is the only exchange path in this package — no Net
// override and no tcp/tcp-tls dialing. miekg/dns treats an empty Net as
// plaintext UDP; a transport selector (TCP/DoT) is deferred follow-up work,
// and a future transport must never honor AD by transport alone.
func TestUDPOnlyTransport(t *testing.T) {
	upstream := startTestServer(t, answeringHandler(nil, 0))
	for _, tc := range []struct {
		name string
		r    *Resolver
	}{
		{"default", newTestResolver(t, upstream)},
		{"trusted", newTrustedTestResolver(t, upstream)},
		{"default-upstream", newTestResolver(t, "")},
	} {
		if tc.r.client == nil {
			t.Fatalf("%s: nil client", tc.name)
		}
		if tc.r.client.Net != "" {
			t.Errorf("%s: client.Net = %q, want empty (plaintext UDP; this package admits no Net override)", tc.name, tc.r.client.Net)
		}
	}
	// The bound client completes a real exchange against a UDP-only listener
	// (every helper server in this file binds UDP exclusively).
	if _, _, err := newTrustedTestResolver(t, upstream).LookupTXT(context.Background(), "udp.example.test"); err != nil {
		t.Fatalf("LookupTXT over the plaintext-UDP client: %v", err)
	}
}
