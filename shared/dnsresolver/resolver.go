// Package dnsresolver provides a DNSSEC-aware DNS resolver with caching
// and rate limiting. All SMTP DNS lookups (MX, TXT, A, AAAA, PTR, TLSA)
// should use this resolver rather than net.DefaultResolver so that
// DNSSEC validation state is available to callers.
//
// The resolver wraps miekg/dns (already in go.mod) with EDNS0 DO bit set,
// checks AuthenticatedData for DNSSEC validation state — honored ONLY from
// endpoints on the configured trusted-resolver allowlist — caches responses
// keyed on (query type, name), and enforces per-second rate limits.
//
// Overload and cancellation are first-class outcomes: the shared 20-QPS
// ticker queue is context-cancellation-aware, the waiter count is bounded,
// concurrent queries for the same key coalesce into one upstream exchange,
// and ONE total per-lookup deadline covers queueing, every wire exchange and
// the system-resolver fallback. Bounded-queue rejections (ErrRateLimited) and
// cancelled waits (*QueueWaitError) are surfaced as distinct outcomes and
// never divert through the system-resolver fallback; the fallback itself is
// bounded, accounted, and never started once the per-lookup deadline has
// expired, so attacker-chosen unique subdomains cannot pile up goroutines
// without bound or delay legitimate resolution.
package dnsresolver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// SecurityLevel classifies the DNSSEC validation state of a DNS response.
type SecurityLevel string

const (
	// Secure means DNSSEC validated — AuthenticatedData bit set.
	Secure SecurityLevel = "secure"
	// Indeterminate means valid response but no DNSSEC validation.
	Indeterminate SecurityLevel = "indeterminate"
	// Bogus means DNSSEC validation failed.
	Bogus SecurityLevel = "bogus"
	// Unsigned means the zone is not DNSSEC-signed.
	Unsigned SecurityLevel = "unsigned"
)

const (
	// defaultUpstream is the default DNSSEC-capable upstream resolver.
	defaultUpstream = "1.1.1.1:53"
	// defaultQPSInterval paces upstream queries to at most 20 QPS.
	defaultQPSInterval = 50 * time.Millisecond
	// defaultLookupBudget bounds the TOTAL time a single lookup may spend:
	// the wait for a rate-limit slot, every upstream wire exchange (both
	// A/AAAA legs) and any system-resolver fallback. It is applied ONCE per
	// public lookup, so the same deadline governs the whole call: the DNS
	// client's own timeout only covers a single exchange, and a budget that
	// ends inside the exchange would let a wire timeout start a fallback
	// after the deadline.
	defaultLookupBudget = 5 * time.Second
	// defaultCacheTTL is how long successful responses are cached.
	defaultCacheTTL = 5 * time.Minute
	// maxQueueWaiters bounds the goroutines holding rate-limit queue slots
	// (waiting for a ticker token or running their exchange). Excess work
	// is rejected with ErrRateLimited, never queued without bound.
	maxQueueWaiters = 64
	// maxCoalesceWaiters bounds the goroutines joined on one coalesced
	// in-flight query. Joins never consume upstream rate-limit slots.
	maxCoalesceWaiters = 128
	// maxFallbackConns bounds concurrent system-resolver fallback lookups.
	maxFallbackConns = 16
	// cachePruneThreshold is the cache size that triggers expired-entry
	// pruning.
	cachePruneThreshold = 1000
)

// lookupBudget is the total per-lookup budget (queue wait + every wire
// exchange + system-resolver fallback), applied once per public lookup. It
// is a variable so tests can shrink it deterministically.
var lookupBudget = defaultLookupBudget

// withLookupBudget derives the per-lookup context: ONE deadline
// (lookupBudget) that covers queueing, every wire exchange and any
// system-resolver fallback. Each public lookup applies it once at entry;
// exchange and the fallbacks inherit it instead of renewing their own.
func withLookupBudget(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, lookupBudget)
}

// ErrRateLimited reports that a bounded queue is full: the rate-limit wait
// queue, a per-key coalescing queue, or the system-resolver fallback bound.
// Work is rejected at the bound instead of being diverted around it. This is
// an overload outcome, not a resolver failure: callers must not treat it as
// grounds to retry via the system resolver.
var ErrRateLimited = errors.New("dnsresolver: bounded queue full")

// QueueWaitError reports a cancelled or timed-out wait for a rate-limit slot
// or for a coalesced in-flight query. Err is the context error
// (context.Canceled or context.DeadlineExceeded). Like ErrRateLimited this
// is an overload/cancellation outcome, not a resolver failure, and must not
// trigger the system-resolver fallback.
type QueueWaitError struct {
	Err error
}

func (e *QueueWaitError) Error() string {
	return "dnsresolver: " + e.Err.Error() + " while waiting for rate-limited query"
}

func (e *QueueWaitError) Unwrap() error { return e.Err }

// System-resolver seams. Production fallbacks go through boundedFallback so
// attacker-driven floods cannot pile up goroutines here; tests script these
// to count fallback activity.
var (
	systemLookupMX = func(ctx context.Context, domain string) ([]*net.MX, error) {
		return net.DefaultResolver.LookupMX(ctx, domain)
	}
	systemLookupTXT = func(ctx context.Context, domain string) ([]string, error) {
		return net.DefaultResolver.LookupTXT(ctx, domain)
	}
	systemLookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
		return net.DefaultResolver.LookupIP(ctx, "ip", host)
	}
	systemLookupAddr = func(ctx context.Context, ip string) ([]string, error) {
		return net.DefaultResolver.LookupAddr(ctx, ip)
	}
)

// Resolver is a DNSSEC-aware DNS resolver with caching and rate limiting.
type Resolver struct {
	client    *dns.Client
	upstream  string
	logger    *slog.Logger
	cache     map[cacheKey]cacheEntry
	mu        sync.RWMutex
	rateLimit *time.Ticker
	cacheTTL  time.Duration

	// trustedResolvers is the allowlist of exact "host:port" upstream
	// endpoints whose AuthenticatedData (AD) claims may be honored (the
	// dnssec.trusted_resolvers config). An empty allowlist means AD is never
	// honored; there is no implicit loopback/link-local trust. UDP-only
	// scope: the only exchange transport is the plaintext-UDP client built
	// in New, so trust is evaluated per ENDPOINT — no transport selector
	// exists in this package (TCP/DoT is deferred follow-up work and a
	// future transport must never honor AD by transport alone).
	trustedResolvers map[string]struct{}

	// queueSlots bounds goroutines holding rate-limit queue slots,
	// joinSlots bounds goroutines joined on coalesced in-flight queries,
	// and fallbackSlots bounds concurrent system-resolver fallbacks.
	queueSlots    chan struct{}
	joinSlots     chan struct{}
	fallbackSlots chan struct{}
	inflight      map[cacheKey]*inflightCall

	// Accounting: queueWaiters/coalesceWaiters/fallbackActive are gauges;
	// queueRejects/coalesceRejects/fallbackRejects are monotonic.
	queueWaiters    atomic.Int64
	queueRejects    atomic.Int64
	coalesceWaiters atomic.Int64
	coalesceRejects atomic.Int64
	fallbackActive  atomic.Int64
	fallbackRejects atomic.Int64
}

type cacheKey struct {
	qtype uint16
	name  string
}

type cacheEntry struct {
	msg       *dns.Msg
	expiresAt time.Time
}

// inflightCall tracks one in-flight upstream query that concurrent lookups
// for the same key may coalesce onto.
type inflightCall struct {
	done chan struct{}
	msg  *dns.Msg
	err  error
}

// New creates a new DNSSEC-aware DNS resolver.
//
// upstream is the DNS server address (e.g., "8.8.8.8:53"). If empty, the
// default upstream (defaultUpstream) is used. trustedResolvers is the
// allowlist of exact "host:port" upstream endpoints whose AuthenticatedData
// (AD) claims are honored (RFC 4035 §4.3 / RFC 6840 §5.7: a stub must ignore
// AD unless the channel to the validating resolver is trusted). An AD bit
// from any other endpoint is demoted to Indeterminate — never Unsigned,
// which stays reserved for system-resolver fallback outcomes — and an empty
// allowlist means AD is never honored at all; there is no implicit
// loopback/link-local trust. The exchange transport is plaintext UDP only:
// the dns.Client built here carries no Net override, and no TCP/DoT
// transport selector exists in this package.
func New(upstream string, trustedResolvers []string, logger *slog.Logger) *Resolver {
	if upstream == "" {
		// Use Cloudflare as default — supports DNSSEC
		upstream = defaultUpstream
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	trusted := make(map[string]struct{}, len(trustedResolvers))
	for _, endpoint := range trustedResolvers {
		// Byte-exact allowlist: entries are matched byte-equal against the
		// exchange endpoint, so no normalization beyond dropping empties.
		if endpoint != "" {
			trusted[endpoint] = struct{}{}
		}
	}
	return &Resolver{
		client: &dns.Client{
			// No Net field: miekg/dns defaults to plaintext UDP. This is the
			// only exchange path in the package (UDP-only scope).
			Timeout: 5 * time.Second,
		},
		upstream:         upstream,
		logger:           logger,
		trustedResolvers: trusted,
		cache:            make(map[cacheKey]cacheEntry),
		inflight:         make(map[cacheKey]*inflightCall),
		rateLimit:        time.NewTicker(defaultQPSInterval), // 20 QPS max to upstream
		cacheTTL:         defaultCacheTTL,
		queueSlots:       make(chan struct{}, maxQueueWaiters),
		joinSlots:        make(chan struct{}, maxCoalesceWaiters),
		fallbackSlots:    make(chan struct{}, maxFallbackConns),
	}
}

// exchange performs a single rate-limited upstream DNS query with the DNSSEC
// DO bit set. ctx already carries the total per-lookup budget, applied once
// by the public entry point: the SAME deadline governs the rate-limit wait,
// this wire exchange and any later system-resolver fallback. It is not
// renewed per exchange.
func (r *Resolver) exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	// Bounded waiter queue: reject instead of piling up goroutines.
	select {
	case r.queueSlots <- struct{}{}:
	default:
		r.queueRejects.Add(1)
		r.logger.Debug("dnsresolver: rate-limit queue full, rejecting",
			"name", name, "qtype", dns.TypeToString[qtype])
		return nil, fmt.Errorf("%w: rate-limit wait queue at %d waiters", ErrRateLimited, maxQueueWaiters)
	}
	r.queueWaiters.Add(1)
	defer r.queueWaiters.Add(-1)
	defer func() { <-r.queueSlots }()

	// Context-cancellation-aware wait on the shared 20-QPS ticker.
	select {
	case <-r.rateLimit.C:
	case <-ctx.Done():
		return nil, &QueueWaitError{Err: ctx.Err()}
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.SetEdns0(1232, true) // DO bit = DNSSEC OK
	msg.RecursionDesired = true

	resp, _, err := r.client.ExchangeContext(ctx, msg, r.upstream)
	if err != nil {
		// The wire exchange runs against the budget deadline: the client
		// clamps its socket deadlines to min(client timeout, ctx deadline).
		// A socket timeout surfaces as a net i/o timeout wrapping
		// os.ErrDeadlineExceeded, which does not match
		// context.DeadlineExceeded — and because both deadlines coincide,
		// either timer can win the race, so ctx.Err() alone is not a
		// reliable test at the boundary. Surface the budget deadline in
		// both cases: a budget-driven wire timeout is never a
		// fallback-eligible resolver failure.
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, err
	}
	return resp, nil
}

// lookup performs a cached DNSSEC-aware query. Concurrent queries for the
// same (type, name) coalesce into a single upstream exchange; joined waiters
// are bounded and context-aware.
//
// ALIASING CONTRACT: every *dns.Msg handed to a caller is a private deep
// copy. The cache and the coalesced in-flight call retain the canonical
// message; mutating a returned message cannot poison cached answers for
// other lookups.
func (r *Resolver) lookup(ctx context.Context, name string, qtype uint16) (*dns.Msg, SecurityLevel, error) {
	key := cacheKey{qtype, name}

	// Check cache
	r.mu.RLock()
	if entry, ok := r.cache[key]; ok && time.Now().Before(entry.expiresAt) {
		r.mu.RUnlock()
		return entry.msg.Copy(), r.classifySecurity(entry.msg), nil
	}
	r.mu.RUnlock()

	msg, err := r.lookupCoalesced(ctx, key, name, qtype)
	if err != nil {
		return nil, Unsigned, err
	}
	// The fresh message is retained by the cache (and shared with coalesced
	// joiners); hand the caller its own copy.
	return msg.Copy(), r.classifySecurity(msg), nil
}

// lookupCoalesced joins the in-flight query for key if one exists, otherwise
// runs the exchange and publishes the result to joined waiters and the cache.
func (r *Resolver) lookupCoalesced(ctx context.Context, key cacheKey, name string, qtype uint16) (*dns.Msg, error) {
	r.mu.Lock()
	if c, ok := r.inflight[key]; ok {
		r.mu.Unlock()
		return r.joinInflight(ctx, c, name, qtype)
	}
	c := &inflightCall{done: make(chan struct{})}
	r.inflight[key] = c
	r.mu.Unlock()

	msg, err := r.exchange(ctx, name, qtype)

	// Publish the result, cache successes, and wake joined waiters.
	r.mu.Lock()
	delete(r.inflight, key)
	if err == nil {
		r.cache[key] = cacheEntry{msg: msg, expiresAt: time.Now().Add(r.cacheTTL)}
		// Prune expired entries occasionally
		if len(r.cache) > cachePruneThreshold {
			for k, v := range r.cache {
				if time.Now().After(v.expiresAt) {
					delete(r.cache, k)
				}
			}
		}
	}
	r.mu.Unlock()

	c.msg, c.err = msg, err
	close(c.done)
	return msg, err
}

// joinInflight waits for an already in-flight query for the same key. The
// join queue is bounded; joins never consume upstream rate-limit slots.
func (r *Resolver) joinInflight(ctx context.Context, c *inflightCall, name string, qtype uint16) (*dns.Msg, error) {
	select {
	case r.joinSlots <- struct{}{}:
	default:
		r.coalesceRejects.Add(1)
		r.logger.Debug("dnsresolver: coalesce queue full, rejecting",
			"name", name, "qtype", dns.TypeToString[qtype])
		return nil, fmt.Errorf("%w: %d coalesced waiters for %s %s", ErrRateLimited, maxCoalesceWaiters, dns.TypeToString[qtype], name)
	}
	r.coalesceWaiters.Add(1)
	defer r.coalesceWaiters.Add(-1)
	defer func() { <-r.joinSlots }()

	select {
	case <-c.done:
		return c.msg, c.err
	case <-ctx.Done():
		return nil, &QueueWaitError{Err: ctx.Err()}
	}
}

// fallbackEligible reports whether err is a legitimate upstream resolver
// failure that may be retried via the system resolver. Bounded-queue
// rejections, cancelled/timed-out waits, and socket deadline errors must NOT
// divert through the fallback: that would route excess work around the
// rate-limit bound or start a fallback after the per-lookup budget expired.
func fallbackEligible(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrRateLimited) {
		return false
	}
	var qwe *QueueWaitError
	if errors.As(err, &qwe) {
		return false
	}
	// Deadline outcomes: context errors, and the socket i/o timeout the
	// budget produces on the wire. os.ErrDeadlineExceeded does not match
	// context.DeadlineExceeded and the socket deadline can fire before the
	// context timer, so the socket form is classified explicitly.
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	return true
}

// boundedFallback runs a system-resolver lookup under a hard concurrency
// bound. Excess fallbacks are rejected, never queued without bound.
func (r *Resolver) boundedFallback(ctx context.Context, kind, name string, run func(context.Context) error) error {
	select {
	case r.fallbackSlots <- struct{}{}:
	default:
		r.fallbackRejects.Add(1)
		r.logger.Debug("dnsresolver: system-resolver fallback bound reached, rejecting",
			"kind", kind, "name", name)
		return fmt.Errorf("%w: system-resolver fallback bound of %d reached", ErrRateLimited, maxFallbackConns)
	}
	r.fallbackActive.Add(1)
	defer r.fallbackActive.Add(-1)
	defer func() { <-r.fallbackSlots }()
	return run(ctx)
}

func (r *Resolver) fallbackMX(ctx context.Context, domain string) ([]*net.MX, error) {
	var mxs []*net.MX
	err := r.boundedFallback(ctx, "MX", domain, func(fctx context.Context) error {
		var serr error
		mxs, serr = systemLookupMX(fctx, domain)
		return serr
	})
	return mxs, err
}

func (r *Resolver) fallbackTXT(ctx context.Context, domain string) ([]string, error) {
	var txts []string
	err := r.boundedFallback(ctx, "TXT", domain, func(fctx context.Context) error {
		var serr error
		txts, serr = systemLookupTXT(fctx, domain)
		return serr
	})
	return txts, err
}

func (r *Resolver) fallbackIP(ctx context.Context, host string) ([]net.IP, error) {
	var ips []net.IP
	err := r.boundedFallback(ctx, "IP", host, func(fctx context.Context) error {
		var serr error
		ips, serr = systemLookupIP(fctx, host)
		return serr
	})
	return ips, err
}

func (r *Resolver) fallbackAddr(ctx context.Context, ip string) ([]string, error) {
	var names []string
	err := r.boundedFallback(ctx, "PTR", ip, func(fctx context.Context) error {
		var serr error
		names, serr = systemLookupAddr(fctx, ip)
		return serr
	})
	return names, err
}

// honorAD reports whether an AuthenticatedData (AD) claim received from the
// given upstream endpoint may be honored. UDP-only scope: the only admitted
// transport is the plaintext-UDP client built by New, so channel
// authenticity reduces to an exact byte-equal match of the "host:port"
// endpoint against the configured trusted-resolver allowlist. An empty
// allowlist never honors AD, and loopback/link-local endpoints carry no
// implicit trust.
func (r *Resolver) honorAD(endpoint string) bool {
	_, ok := r.trustedResolvers[endpoint]
	return ok
}

// classifySecurity determines DNSSEC validation state from DNS response
// headers. It is the single AD-trust choke point: fresh exchanges, cache
// hits and coalesced joins all re-classify here, so a spoofable AD bit from
// an endpoint outside the trusted allowlist is demoted to Indeterminate
// ("valid response, validation claim unverifiable") on positive AND negative
// responses alike — an AD-bearing NXDOMAIN from an untrusted upstream is
// Indeterminate, never Bogus — and never Unsigned, which stays reserved for
// system-resolver fallback outcomes.
func (r *Resolver) classifySecurity(resp *dns.Msg) SecurityLevel {
	if resp == nil {
		return Unsigned
	}
	if resp.MsgHdr.AuthenticatedData {
		// AD is set: honor it only from a trusted allowlisted endpoint.
		// When it cannot be trusted, the response — positive or negative —
		// is Indeterminate: an AD-bearing NXDOMAIN is a well-formed
		// negative answer whose validation state cannot be confirmed, not
		// a validation failure, so it must not fall through to Bogus.
		if r.honorAD(r.upstream) {
			return Secure
		}
		return Indeterminate
	}
	if resp.Rcode == dns.RcodeSuccess {
		return Indeterminate
	}
	// Negative answers (NXDOMAIN, SERVFAIL, ...) without an AD claim:
	// classification fidelity — Bogus is reserved for a FAILED validation,
	// and no validation was attempted on this path. A well-formed negative
	// answer whose validation state is unknown is Indeterminate; collapsing
	// every non-NOERROR rcode into Bogus would mass-DoS any future consumer
	// that branches on the level (RFC 7646 taxonomy).
	return Indeterminate
}

// LookupMX resolves MX records for a domain with DNSSEC validation.
//
// The total per-lookup budget is applied once here and carried through
// queueing, the exchange and the fallback: no system-resolver fallback is
// started after the budget expires. Bounded-queue rejections and cancelled
// waits surface as ErrRateLimited or *QueueWaitError without touching the
// system resolver; only legitimate upstream resolver failures fall back, and
// the fallback is itself bounded and accounted.
func (r *Resolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, SecurityLevel, error) {
	ctx, cancel := withLookupBudget(ctx)
	defer cancel()

	resp, sec, err := r.lookup(ctx, domain, dns.TypeMX)
	if err != nil {
		if !fallbackEligible(err) {
			return nil, Unsigned, err
		}
		if cerr := ctx.Err(); cerr != nil {
			// The budget expired during the exchange; do not start a
			// fallback after the deadline.
			return nil, Unsigned, cerr
		}
		// Fall back to the system resolver (bounded, under the same budget).
		mxs, ferr := r.fallbackMX(ctx, domain)
		return mxs, Unsigned, ferr
	}

	var mxs []*net.MX
	for _, ans := range resp.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			mxs = append(mxs, &net.MX{
				Host: mx.Mx,
				Pref: mx.Preference,
			})
		}
	}
	if len(mxs) == 0 {
		if cerr := ctx.Err(); cerr != nil {
			// The budget expired between the legs; do not start a fallback
			// after the deadline.
			return nil, Unsigned, cerr
		}
		// Fall back to the system resolver (bounded, under the same budget):
		// some resolvers serve local zones the DNSSEC upstream cannot see. A
		// failed or rejected fallback surfaces as an error rather than
		// masquerading as "no mail exchanger".
		mxs, ferr := r.fallbackMX(ctx, domain)
		return mxs, Unsigned, ferr
	}
	return mxs, sec, nil
}

// LookupTXT resolves TXT records for a domain with DNSSEC validation.
// The total per-lookup budget is applied once here and carried through
// queueing, the exchange and the fallback: no system-resolver fallback is
// started after the budget expires. Overload and cancellation outcomes do
// not divert through the system resolver; see LookupMX.
func (r *Resolver) LookupTXT(ctx context.Context, domain string) ([]string, SecurityLevel, error) {
	ctx, cancel := withLookupBudget(ctx)
	defer cancel()

	resp, sec, err := r.lookup(ctx, domain, dns.TypeTXT)
	if err != nil {
		if !fallbackEligible(err) {
			return nil, Unsigned, err
		}
		if cerr := ctx.Err(); cerr != nil {
			// The budget expired during the exchange; do not start a
			// fallback after the deadline.
			return nil, Unsigned, cerr
		}
		txts, ferr := r.fallbackTXT(ctx, domain)
		return txts, Unsigned, ferr
	}

	var txts []string
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			txts = append(txts, strings.Join(txt.Txt, ""))
		}
	}
	if len(txts) == 0 {
		if cerr := ctx.Err(); cerr != nil {
			// The budget expired between the legs; do not start a fallback
			// after the deadline.
			return nil, Unsigned, cerr
		}
		txts, ferr := r.fallbackTXT(ctx, domain)
		return txts, Unsigned, ferr
	}
	return txts, sec, nil
}

// LookupIP resolves A/AAAA records for a host with DNSSEC validation.
// The total per-lookup budget is applied once here and carried through
// queueing, both wire exchanges and the fallback: no system-resolver fallback
// is started after the budget expires. Overload and cancellation outcomes do
// not divert through the system resolver; see LookupMX.
//
// Error precedence: an overload or cancellation outcome (bounded-queue
// rejection, cancelled wait, expired per-lookup budget) on EITHER leg — or on
// the system-resolver fallback itself — outranks an ordinary resolver
// failure, so one leg's ordinary error can never mask the other leg's
// overload or the fallback's. A non-empty answer from either leg still wins
// outright.
func (r *Resolver) LookupIP(ctx context.Context, host string) ([]net.IP, SecurityLevel, error) {
	ctx, cancel := withLookupBudget(ctx)
	defer cancel()

	// Try AAAA first, then A. lastErr holds an ordinary (fallback-eligible)
	// resolver failure; boundErr holds an overload/cancellation outcome,
	// which takes precedence over lastErr.
	var ips []net.IP
	var sec SecurityLevel
	var lastErr error
	var boundErr error

	resp, s, err := r.lookup(ctx, host, dns.TypeAAAA)
	sec = s
	if err != nil {
		if fallbackEligible(err) {
			lastErr = err
		} else {
			boundErr = err
		}
	} else {
		for _, ans := range resp.Answer {
			if aaaa, ok := ans.(*dns.AAAA); ok {
				ips = append(ips, aaaa.AAAA)
			}
		}
	}

	resp2, s2, err2 := r.lookup(ctx, host, dns.TypeA)
	if sec == Unsigned {
		sec = s2
	}
	if err2 != nil {
		if fallbackEligible(err2) {
			if lastErr == nil {
				lastErr = err2
			}
		} else if boundErr == nil {
			// An A-leg overload/cancellation must not be masked by the
			// earlier ordinary AAAA failure; keep the first bound outcome.
			boundErr = err2
		}
	} else {
		for _, ans := range resp2.Answer {
			if a, ok := ans.(*dns.A); ok {
				ips = append(ips, a.A)
			}
		}
	}

	if len(ips) > 0 {
		return ips, sec, nil
	}
	if boundErr != nil {
		// Overload or cancellation outcome: rejected at the bound (or the
		// budget expired), never diverted through the system resolver.
		return nil, Unsigned, boundErr
	}
	if cerr := ctx.Err(); cerr != nil {
		// The budget expired across the legs; do not start a fallback after
		// the deadline.
		return nil, Unsigned, cerr
	}
	// Legitimate resolver failure or genuine empty answer: fall back to the
	// system resolver (bounded, under the same budget).
	sysIPs, ferr := r.fallbackIP(ctx, host)
	if ferr != nil {
		if !fallbackEligible(ferr) {
			// The fallback hit its own bound or the budget expired
			// mid-fallback: that overload/cancellation outranks the ordinary
			// upstream failure in lastErr.
			return nil, Unsigned, ferr
		}
		if lastErr != nil {
			return nil, Unsigned, lastErr
		}
		return nil, Unsigned, ferr
	}
	return sysIPs, Unsigned, nil
}

// LookupTLSA resolves TLSA records for _25._tcp.{mxHost} with DNSSEC validation.
func (r *Resolver) LookupTLSA(mxHost string) ([]*dns.TLSA, SecurityLevel, error) {
	mxHost = strings.TrimSuffix(mxHost, ".")
	name := "_25._tcp." + mxHost

	// No caller context is available on this signature; the same per-lookup
	// budget, applied once here, still bounds queueing plus the exchange.
	ctx, cancel := withLookupBudget(context.Background())
	defer cancel()
	resp, sec, err := r.lookup(ctx, name, dns.TypeTLSA)
	if err != nil {
		return nil, Unsigned, fmt.Errorf("TLSA lookup failed: %w", err)
	}

	var records []*dns.TLSA
	for _, ans := range resp.Answer {
		if tlsa, ok := ans.(*dns.TLSA); ok {
			records = append(records, tlsa)
		}
	}
	return records, sec, nil
}

// LookupPTR resolves a PTR record for reverse DNS lookups.
// The total per-lookup budget is applied once here and carried through
// queueing, the exchange and the fallback: no system-resolver fallback is
// started after the budget expires. Overload and cancellation outcomes do
// not divert through the system resolver; see LookupMX.
func (r *Resolver) LookupPTR(ctx context.Context, ip string) ([]string, SecurityLevel, error) {
	ctx, cancel := withLookupBudget(ctx)
	defer cancel()

	name, err := dns.ReverseAddr(ip)
	if err != nil {
		return nil, Unsigned, err
	}
	resp, sec, err := r.lookup(ctx, name, dns.TypePTR)
	if err != nil {
		if !fallbackEligible(err) {
			return nil, Unsigned, err
		}
		if cerr := ctx.Err(); cerr != nil {
			// The budget expired during the exchange; do not start a
			// fallback after the deadline.
			return nil, Unsigned, cerr
		}
		names, ferr := r.fallbackAddr(ctx, ip)
		return names, Unsigned, ferr
	}

	var names []string
	for _, ans := range resp.Answer {
		if ptr, ok := ans.(*dns.PTR); ok {
			names = append(names, ptr.Ptr)
		}
	}
	return names, sec, nil
}

// IsDNSSECEnabled checks whether the configured upstream is a DNSSEC
// validating resolver by querying for the root zone's DNSKEY with the DO bit
// set. The answer's AD bit is honored only when the upstream endpoint is on
// the trusted allowlist (the same policy as classifySecurity), so Status()
// cannot report enabled from a spoofable AD bit.
func (r *Resolver) IsDNSSECEnabled() bool {
	msg := new(dns.Msg)
	msg.SetQuestion(".", dns.TypeDNSKEY)
	msg.SetEdns0(1232, true)
	msg.RecursionDesired = true

	resp, _, err := r.client.Exchange(msg, r.upstream)
	if err != nil {
		return false
	}
	return resp.MsgHdr.AuthenticatedData && r.honorAD(r.upstream)
}

// DNSSECStatus returns a summary of DNSSEC capability for the admin UI.
type DNSSECStatus struct {
	Enabled      bool   `json:"enabled"`
	ResolverAddr string `json:"resolver_addr"`
	CacheSize    int    `json:"cache_size"`
	CacheTTL     string `json:"cache_ttl"`
	// Rate-limit queue accounting for the bounded-queue hardening.
	QueueWaiters    int   `json:"queue_waiters"`
	QueueRejects    int64 `json:"queue_rejects"`
	FallbackRejects int64 `json:"fallback_rejects"`
}

// Status returns the current resolver status.
func (r *Resolver) Status() DNSSECStatus {
	r.mu.RLock()
	cacheSize := len(r.cache)
	r.mu.RUnlock()

	return DNSSECStatus{
		Enabled:         r.IsDNSSECEnabled(),
		ResolverAddr:    r.upstream,
		CacheSize:       cacheSize,
		CacheTTL:        r.cacheTTL.String(),
		QueueWaiters:    int(r.queueWaiters.Load()),
		QueueRejects:    r.queueRejects.Load(),
		FallbackRejects: r.fallbackRejects.Load(),
	}
}

func (r *Resolver) addr() string {
	// exposed for dane.go compatibility — returns the resolver's upstream address
	return r.upstream
}
