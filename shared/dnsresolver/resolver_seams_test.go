package dnsresolver

// Seam and boundary coverage the bounded-queue suites bypass: error-type
// formatting, constructor defaults and allowlist filtering, the cache-prune
// threshold, the coalesce-join bound and its cancellation, the
// fallbackEligible classification table, and the system-resolver fallback
// driven through the REAL net seams against loopback stub servers.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestQueueWaitErrorFormattingAndUnwrap(t *testing.T) {
	cause := context.Canceled
	err := &QueueWaitError{Err: cause}
	if got := err.Error(); !strings.HasPrefix(got, "dnsresolver: ") ||
		!strings.Contains(got, "while waiting for rate-limited query") {
		t.Fatalf("QueueWaitError.Error() = %q, want the documented formatting", got)
	}
	if !errors.Is(err, cause) {
		t.Fatal("QueueWaitError must unwrap to its context cause")
	}
}

func TestNewDefaultsAndAllowlistFiltering(t *testing.T) {
	r := New("", nil, nil)
	if r.upstream != defaultUpstream {
		t.Fatalf("empty upstream = %q, want the default %q", r.upstream, defaultUpstream)
	}
	if r.client == nil || r.cache == nil || r.inflight == nil || r.rateLimit == nil {
		t.Fatal("constructor left wiring unset")
	}
	if _, ok := r.trustedResolvers[defaultUpstream]; ok {
		t.Fatal("empty allowlist must trust nothing (no implicit default trust)")
	}

	// Allowlist entries are byte-exact: empty entries are dropped, but
	// anything else is kept verbatim — never trimmed or normalized.
	r2 := New("10.0.0.1:53", []string{"", "10.0.0.1:53", "  "}, nil)
	if _, ok := r2.trustedResolvers["10.0.0.1:53"]; !ok {
		t.Fatal("non-empty allowlist entry missing")
	}
	if _, ok := r2.trustedResolvers["  "]; !ok {
		t.Fatal("non-empty entries are kept byte-exactly (no normalization)")
	}
	if len(r2.trustedResolvers) != 2 {
		t.Fatalf("trustedResolvers = %v, want the two verbatim entries", r2.trustedResolvers)
	}
	if !r2.honorAD("10.0.0.1:53") || r2.honorAD("10.0.0.1:54") {
		t.Fatal("honorAD must match the endpoint byte-exactly")
	}
}

func TestCachePrunesExpiredAtThreshold(t *testing.T) {
	addr := startTestServer(t, answeringHandler(&queryCounter{}, 0))
	r := newTestResolver(t, addr)
	speedUpTicker(t, r)

	// Stuff the cache past the prune threshold with already-expired entries.
	r.mu.Lock()
	for i := 0; i < 1002; i++ {
		r.cache[cacheKey{dns.TypeA, uniqueName("prune", i)}] =
			cacheEntry{msg: new(dns.Msg), expiresAt: time.Now().Add(-time.Hour)}
	}
	r.mu.Unlock()

	// One more successful lookup pushes the cache over the threshold, so the
	// publish path prunes the expired entries.
	if _, _, err := r.LookupIP(context.Background(), "prune-fresh.example.test"); err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	r.mu.RLock()
	size := len(r.cache)
	_, staleLeft := r.cache[cacheKey{dns.TypeA, uniqueName("prune", 0)}]
	r.mu.RUnlock()
	if staleLeft {
		t.Fatal("expired entries survived the prune")
	}
	if size > cachePruneThreshold {
		t.Fatalf("cache size %d still above the prune threshold", size)
	}
}

// blockedUpstream starts a gated upstream and returns a resolver whose
// in-flight exchange parks in the server handler until release closes.
func blockedUpstream(t *testing.T) (*Resolver, chan struct{}) {
	t.Helper()
	release, addr := startGatedServer(t)
	r := newTestResolver(t, addr)
	// The leader parks inside the server handler well past the default
	// budget; give the parked exchange room while the test manipulates the
	// bounds.
	overrideBudget(t, 30*time.Second)
	return r, release
}

func waitForInflight(t *testing.T, r *Resolver) {
	t.Helper()
	waitFor(t, 5*time.Second, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.inflight) > 0
	}, "upstream exchange never became in-flight")
}

func TestCoalesceJoinRejectsAtBound(t *testing.T) {
	r, release := blockedUpstream(t)

	errc := make(chan error, 1)
	go func() {
		_, _, err := r.LookupIP(context.Background(), "coalesce.example.test")
		errc <- err
	}()
	waitForInflight(t, r)

	// Fill the join bound: further lookups for the same key must be rejected
	// at the bound, never queued without limit and never diverted into a
	// second upstream exchange or the system fallback.
	for i := 0; i < maxCoalesceWaiters; i++ {
		r.joinSlots <- struct{}{}
	}
	// Join the leader's CURRENT in-flight key (its AAAA leg) directly: a
	// second full LookupIP would lead a fresh A-leg exchange behind the
	// single-threaded gated server instead of joining.
	_, _, err := r.lookup(context.Background(), "coalesce.example.test", dns.TypeAAAA)
	if !errors.Is(err, ErrRateLimited) || !strings.Contains(err.Error(), "coalesced waiters") {
		t.Fatalf("join at bound = %v, want the coalesce-bound ErrRateLimited", err)
	}
	for i := 0; i < maxCoalesceWaiters; i++ {
		<-r.joinSlots
	}
	close(release)
	if err := <-errc; err != nil {
		t.Fatalf("leader lookup: %v", err)
	}
}

func TestJoinInflightContextCancelled(t *testing.T) {
	r, release := blockedUpstream(t)

	errc := make(chan error, 1)
	go func() {
		_, _, err := r.LookupIP(context.Background(), "joincancel.example.test")
		errc <- err
	}()
	waitForInflight(t, r)

	ctx, cancel := context.WithCancel(context.Background())
	joinErr := make(chan error, 1)
	go func() {
		_, _, err := r.lookup(ctx, "joincancel.example.test", dns.TypeAAAA)
		joinErr <- err
	}()
	waitFor(t, 5*time.Second, func() bool {
		return r.coalesceWaiters.Load() > 0
	}, "joiner never joined the in-flight call")
	cancel()
	select {
	case err := <-joinErr:
		if !isQueueWait(err) || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled join = %v, want a QueueWaitError wrapping context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled join never returned")
	}
	close(release)
	if err := <-errc; err != nil {
		t.Fatalf("leader lookup: %v", err)
	}
}

func TestFallbackEligibleClassification(t *testing.T) {
	// nil: no failure, nothing to fall back for.
	if fallbackEligible(nil) {
		t.Fatal("fallbackEligible(nil) = true, want false")
	}
	if fallbackEligible(fmt.Errorf("wrapped rate limit: %w", ErrRateLimited)) {
		t.Fatal("bounded-queue rejections must never divert through the fallback")
	}
	if fallbackEligible(&QueueWaitError{Err: context.DeadlineExceeded}) {
		t.Fatal("cancelled waits must never divert through the fallback")
	}
	if fallbackEligible(context.Canceled) || fallbackEligible(context.DeadlineExceeded) {
		t.Fatal("context outcomes must never divert through the fallback")
	}
	if fallbackEligible(os.ErrDeadlineExceeded) {
		t.Fatal("the budget's socket deadline form must never divert through the fallback")
	}
	if !fallbackEligible(errors.New("connection refused")) {
		t.Fatal("an ordinary resolver failure must be fallback-eligible")
	}
}

// fullDNSStub answers A/AAAA/MX/TXT/PTR — rich enough for every
// system-resolver seam (LookupMX/LookupTXT/LookupIP/LookupAddr).
func fullDNSStub(counter *queryCounter) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		if counter != nil {
			counter.n.Add(1)
		}
		m := new(dns.Msg)
		m.SetReply(req)
		for _, q := range req.Question {
			switch q.Qtype {
			case dns.TypeA:
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IPv4(192, 0, 2, 7),
				})
			case dns.TypeAAAA:
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: net.IPv6loopback,
				})
			case dns.TypeTXT:
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
					Txt: []string{"fallback"},
				})
			case dns.TypeMX:
				m.Answer = append(m.Answer, &dns.MX{
					Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60},
					Preference: 10,
					Mx:         "mail.example.test.",
				})
			case dns.TypePTR:
				m.Answer = append(m.Answer, &dns.PTR{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
					Ptr: "host.example.test.",
				})
			}
		}
		_ = w.WriteMsg(m)
	}
}

// overrideSystemResolver swaps net.DefaultResolver for one that dials the
// given loopback address (or a closed port when addr is empty). The global is
// restored via t.Cleanup; the test must not run in parallel.
func overrideSystemResolver(t *testing.T, addr string) {
	t.Helper()
	old := net.DefaultResolver
	dialAddr := addr
	if dialAddr == "" {
		dialAddr = "127.0.0.1:1" // loopback closed port: fast refusal
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, dialAddr)
		},
	}
	t.Cleanup(func() { net.DefaultResolver = old })
}

// TestFallbackGoesThroughRealSystemSeamsWithBrokenUpstream drives every
// lookup's legitimate-failure path: the upstream refuses (an ordinary
// resolver failure), so each lookup diverts through the bounded fallback and
// the REAL system seams run against a loopback stub (a closed port there —
// the fallback error surfaces rather than masquerading as an empty answer).
func TestFallbackGoesThroughRealSystemSeamsWithBrokenUpstream(t *testing.T) {
	overrideSystemResolver(t, "")
	r := newTestResolver(t, "127.0.0.1:1") // upstream refuses: fallback-eligible
	speedUpTicker(t, r)
	overrideBudget(t, 10*time.Second)

	if _, _, err := r.LookupMX(context.Background(), "seam.example.test"); err == nil {
		t.Fatal("LookupMX fallback failure must surface as an error")
	}
	if _, _, err := r.LookupTXT(context.Background(), "seam.example.test"); err == nil {
		t.Fatal("LookupTXT fallback failure must surface as an error")
	}
	if _, _, err := r.LookupIP(context.Background(), "seam.example.test"); err == nil {
		t.Fatal("LookupIP fallback failure must surface as an error")
	}
	if _, _, err := r.LookupPTR(context.Background(), "192.0.2.99"); err == nil {
		t.Fatal("LookupPTR fallback failure must surface as an error")
	}
}

// TestFallbackSucceedsThroughRealSystemSeams runs the same paths with a
// WORKING loopback system stub: the fallback results carry the stub's records
// at the Unsigned level (fallback outcomes never claim DNSSEC validation).
func TestFallbackSucceedsThroughRealSystemSeams(t *testing.T) {
	addr := startTestServer(t, fullDNSStub(nil))
	overrideSystemResolver(t, addr)
	r := newTestResolver(t, "127.0.0.1:1")
	speedUpTicker(t, r)
	overrideBudget(t, 10*time.Second)

	mxs, sec, err := r.LookupMX(context.Background(), "seamok.example.test")
	if err != nil || len(mxs) == 0 {
		t.Fatalf("LookupMX fallback = (%v, %v)", mxs, err)
	}
	if sec != Unsigned {
		t.Fatalf("fallback MX security = %q, want unsigned", sec)
	}

	txts, sec, err := r.LookupTXT(context.Background(), "seamok.example.test")
	if err != nil || len(txts) == 0 {
		t.Fatalf("LookupTXT fallback = (%v, %v)", txts, err)
	}
	if sec != Unsigned {
		t.Fatalf("fallback TXT security = %q, want unsigned", sec)
	}

	ips, sec, err := r.LookupIP(context.Background(), "seamok.example.test")
	if err != nil || len(ips) == 0 {
		t.Fatalf("LookupIP fallback = (%v, %v)", ips, err)
	}
	if sec != Unsigned {
		t.Fatalf("fallback IP security = %q, want unsigned", sec)
	}

	names, sec, err := r.LookupPTR(context.Background(), "192.0.2.99")
	if err != nil || len(names) == 0 {
		t.Fatalf("LookupPTR fallback = (%v, %v)", names, err)
	}
	if sec != Unsigned {
		t.Fatalf("fallback PTR security = %q, want unsigned", sec)
	}
}

// TestLookupIPEmptyLegsFallbackError pins the precedence tail: both upstream
// legs answer successfully but EMPTY (a genuine no-record answer), the
// fallback itself then fails with an ordinary error and there is NO ordinary
// upstream failure in lastErr — the fallback's own error is the result.
func TestLookupIPEmptyLegsFallbackError(t *testing.T) {
	empty := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		_ = w.WriteMsg(m) // NOERROR, no answers
	})
	addr := startTestServer(t, empty)
	overrideSystemResolver(t, "") // the fallback's own lookups fail
	r := newTestResolver(t, addr)
	speedUpTicker(t, r)
	overrideBudget(t, 10*time.Second)

	ips, sec, err := r.LookupIP(context.Background(), "empty.example.test")
	if err == nil {
		t.Fatalf("LookupIP with empty legs and failing fallback = (%v, nil), want the fallback error", ips)
	}
	if errors.Is(err, context.DeadlineExceeded) || isQueueWait(err) || errors.Is(err, ErrRateLimited) {
		t.Fatalf("LookupIP error %v is a bound outcome, want the ordinary fallback failure", err)
	}
	if sec != Unsigned {
		t.Fatalf("security = %q, want unsigned on a fallback outcome", sec)
	}
}

// TestExchangeClientTimeoutBeforeBudgetMapsToContextDeadline pins the
// deadline-classification branch: a client-scoped socket timeout (shorter
// than the lookup budget) surfaces as context.DeadlineExceeded — never as a
// fallback-eligible resolver failure and never as a QueueWaitError — so a
// stalled upstream cannot divert work through the system fallback.
func TestExchangeClientTimeoutBeforeBudgetMapsToContextDeadline(t *testing.T) {
	release, addr := startGatedServer(t)
	r := newTestResolver(t, addr)
	overrideBudget(t, 30*time.Second)
	r.client.Timeout = 200 * time.Millisecond // the socket deadline fires first

	// Guard the fallback seams: this outcome must NEVER reach them (they
	// would perform real system lookups).
	guardFallbackSeams(t)

	_, _, err := r.LookupMX(context.Background(), "socketdeadline.example.test")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("socket-timeout outcome = %v, want context.DeadlineExceeded", err)
	}
	if isQueueWait(err) || errors.Is(err, ErrRateLimited) {
		t.Fatalf("socket-timeout outcome %v must not be a queue/ bound outcome", err)
	}
	close(release)

	// The pure reverse-name guard while we are here: an unparseable IP fails
	// before any lookup.
	if _, _, err := r.LookupPTR(context.Background(), "not-an-ip-address"); err == nil {
		t.Fatal("LookupPTR of an invalid IP must error before any exchange")
	}
}

// TestLookupIPBoundOutcomeOutranksSecondLegEligible pins the error
// precedence: a bound/cancellation outcome on the AAAA leg must not be
// masked when the A leg fails with an ordinary resolver error.
func TestLookupIPBoundOutcomeOutranksSecondLegEligible(t *testing.T) {
	mixed := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if req.Question[0].Qtype == dns.TypeAAAA {
			time.Sleep(300 * time.Millisecond) // past the client timeout: a bound outcome
			m := new(dns.Msg)
			m.SetReply(req)
			_ = w.WriteMsg(m)
			return
		}
		_, _ = w.Write([]byte{0xff, 0xff, 0x00}) // malformed: an eligible unpack failure
	})
	addr := startTestServer(t, mixed)
	r := newTestResolver(t, addr)
	overrideBudget(t, 30*time.Second)
	r.client.Timeout = 200 * time.Millisecond
	guardFallbackSeams(t)

	_, _, err := r.LookupIP(context.Background(), "mixed.example.test")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("LookupIP = %v, want the AAAA bound outcome to outrank the A-leg failure", err)
	}
}

// guardFallbackSeams replaces the system-resolver seams with sentinels that
// fail the test if the fallback is ever diverted into.
func guardFallbackSeams(t *testing.T) {
	t.Helper()
	boom := func(context.Context, ...string) error {
		t.Error("system-resolver fallback diverted around the bound outcome")
		return errors.New("fallback must not run")
	}
	oldMX, oldTXT, oldIP, oldAddr := systemLookupMX, systemLookupTXT, systemLookupIP, systemLookupAddr
	systemLookupMX = func(ctx context.Context, domain string) ([]*net.MX, error) {
		boom(ctx, domain)
		return nil, errors.New("no")
	}
	systemLookupTXT = func(ctx context.Context, domain string) ([]string, error) {
		boom(ctx, domain)
		return nil, errors.New("no")
	}
	systemLookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
		boom(ctx, host)
		return nil, errors.New("no")
	}
	systemLookupAddr = func(ctx context.Context, ip string) ([]string, error) {
		boom(ctx, ip)
		return nil, errors.New("no")
	}
	t.Cleanup(func() {
		systemLookupMX, systemLookupTXT, systemLookupIP, systemLookupAddr = oldMX, oldTXT, oldIP, oldAddr
	})
}

// --- Straggler-wave gap tests: cancellation-after-cache and Stats snapshot ---

// expiredContext returns an already-expired context: every context-sensitive
// seam downstream must treat it as dead.
func expiredContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	t.Cleanup(cancel)
	time.Sleep(10 * time.Millisecond)
	if ctx.Err() == nil {
		t.Fatal("test setup: 1ns context did not expire")
	}
	return ctx
}

// emptyAnswerHandler replies NOERROR with zero answers for every question.
func emptyAnswerHandler() dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		_ = w.WriteMsg(m)
	}
}

// TestLookupMX_EmptyCacheHitWithDeadContextSurfacesCancellation pins the
// post-lookup cancellation check on the success path: an EMPTY answer served
// from cache (which does not consult the context) must still surface the
// caller's cancellation instead of diverting through the system fallback.
func TestLookupMX_EmptyCacheHitWithDeadContextSurfacesCancellation(t *testing.T) {
	addr := startTestServer(t, emptyAnswerHandler())
	overrideSystemResolver(t, addr)
	r := newTestResolver(t, addr)
	speedUpTicker(t, r)
	overrideBudget(t, 10*time.Second)

	name := uniqueName("mx-expired", 0)
	// Healthy pass: the empty upstream answer is cached; the empty result
	// then diverts to the system fallback, whose own outcome is irrelevant
	// here — only the cache population matters.
	_, _, _ = r.LookupMX(context.Background(), name)

	if _, _, err := r.LookupMX(expiredContext(t), name); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("LookupMX with dead context = %v, want context.DeadlineExceeded", err)
	}
}

// TestLookupTXT_EmptyCacheHitWithDeadContextSurfacesCancellation is the TXT
// twin of the MX cancellation-after-cache check.
func TestLookupTXT_EmptyCacheHitWithDeadContextSurfacesCancellation(t *testing.T) {
	addr := startTestServer(t, emptyAnswerHandler())
	overrideSystemResolver(t, addr)
	r := newTestResolver(t, addr)
	speedUpTicker(t, r)
	overrideBudget(t, 10*time.Second)

	name := uniqueName("txt-expired", 0)
	_, _, _ = r.LookupTXT(context.Background(), name) // cache the empty answer

	if _, _, err := r.LookupTXT(expiredContext(t), name); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("LookupTXT with dead context = %v, want context.DeadlineExceeded", err)
	}
}

// TestLookupIP_EmptyCacheHitWithDeadContextSurfacesCancellation pins the IP
// path: both cached-empty legs answer without consulting the dead context,
// and the empty-result cancellation check fires before the fallback.
func TestLookupIP_EmptyCacheHitWithDeadContextSurfacesCancellation(t *testing.T) {
	addr := startTestServer(t, emptyAnswerHandler())
	overrideSystemResolver(t, addr)
	r := newTestResolver(t, addr)
	speedUpTicker(t, r)
	overrideBudget(t, 10*time.Second)

	host := uniqueName("ip-expired", 0)
	_, _, _ = r.LookupIP(context.Background(), host) // cache the empty legs

	if _, _, err := r.LookupIP(expiredContext(t), host); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("LookupIP with dead context = %v, want context.DeadlineExceeded", err)
	}
}

// TestLookupPTR_DeadContextIsNotFallbackEligible pins the PTR classification:
// the budget's context deadline is a cancellation outcome, never a fallback
// trigger — the error is returned as-is.
func TestLookupPTR_DeadContextIsNotFallbackEligible(t *testing.T) {
	addr := startTestServer(t, emptyAnswerHandler())
	overrideSystemResolver(t, addr)
	r := newTestResolver(t, addr)
	speedUpTicker(t, r)
	overrideBudget(t, 10*time.Second)

	_, _, err := r.LookupPTR(expiredContext(t), "192.0.2.31")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("LookupPTR with dead context = %v, want context.DeadlineExceeded", err)
	}
}

// TestStatusSnapshotReflectsResolver pins the operator status snapshot: the
// reported upstream, cache size and security posture come from live state.
func TestStatusSnapshotReflectsResolver(t *testing.T) {
	addr := startTestServer(t, emptyAnswerHandler())
	r := newTestResolver(t, addr)
	speedUpTicker(t, r)

	// The empty upstream answer is cached even when the fallback leg that
	// follows it fails — only the cache population matters for the snapshot.
	_, _, _ = r.LookupTXT(context.Background(), uniqueName("status", 0))

	st := r.Status()
	if st.ResolverAddr != addr {
		t.Errorf("ResolverAddr = %q, want %q", st.ResolverAddr, addr)
	}
	if st.CacheSize < 1 {
		t.Errorf("CacheSize = %d, want at least the warmed entry", st.CacheSize)
	}
	if st.CacheTTL == "" {
		t.Error("CacheTTL must be rendered, never empty")
	}
}
