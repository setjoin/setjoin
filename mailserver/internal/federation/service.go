// service.go — Pillar C1 Task 5: mailserverd's production federation.Service.
//
// Promotes the C0 spike's testharness/cmd/fedharness wiring
// (reconnect.go's dial-reconnect loop + senderRegistry, anchor.go's
// federation_allowlist-backed AnchorLookup) into a long-lived component
// mailserverd starts unconditionally alongside its other job workers
// (drive.NewWorker, meet.NewWorker, pushjobs.NewWorker) — the testharness
// package itself is untouched: this is a SECOND, production-shaped consumer
// of the same internal/federation transport (Dial/Listen/Sender/Receiver),
// not a replacement.
//
// Two INDEPENDENT gates (Global Constraints / plan Task 5 — do not conflate
// them):
//
//   - STATIC (cmd/mailserverd/main.go, decided once at boot): the Service is
//     constructed only when FEDERATION_LOCAL_DOMAIN + FEDERATION_CERT/_KEY
//     are configured on this box — the SFU-reverse-proxy precedent
//     (main.go's `if d.meetCfg.Configured()`). Absent env ⇒ NewService
//     returns nil and main.go never calls Run — no half-started Service.
//
//   - DYNAMIC (Run's reconcile loop, the meet.Worker.tick pattern — NEVER a
//     boot-time decision): feature.federation and the federation_allowlist
//     enabled set can BOTH change at runtime (an admin flips the toggle, or
//     adds/disables/deletes a peer via Task 8's console), so every
//     reconcile tick re-reads both and converges the live set of per-peer
//     dial loops + streams to match — including ACTIVELY DROPPING a stream
//     for a peer that stopped being enabled (DES-011 eviction-not-TTL: a
//     disable must terminate the live transport immediately, never wait for
//     a token/TTL to lapse on its own). Dial/Listen/Sender/Receiver are
//     already flags-gated (they refuse NEW work while OFF); the active
//     teardown here is the piece flags-gating alone can't provide — a
//     mid-run flip to OFF would otherwise leave an already-established
//     stream running until it happens to break on its own.
package federation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"setjoin.com/mailserver/internal/db"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// reconcileInterval is the periodic re-read cadence — the lost-wakeup
// fallback for the federation_allowlist_changed NOTIFY wake (Service.Wake,
// below), the same "ticker + wake channel" shape as Sender.Run's 3s
// ticker. 20s is "modest" per the plan: fast enough that a missed NOTIFY
// (dispatcher restart, a coalesced burst) self-heals within one tick, slow
// enough not to hammer federation_allowlist on an idle box.
const reconcileInterval = 20 * time.Second

// Config carries the Service's own small, static configuration surface —
// the meet.Config precedent (a package-local Config distinct from the whole
// mailserver config.Config), populated by main.go from the formalized
// FEDERATION_LOCAL_DOMAIN/_LISTEN_ADDR fields (config.Config, Task 5).
type Config struct {
	LocalDomain string // this instance's federation domain, e.g. mail.corp.com
	ListenAddr  string // s2s TLS listen address; empty defaults to ":7443"

	// Resolver overrides SRV discovery; nil means NetResolver{} (real DNS,
	// production — main.go leaves this unset). The second adapter that makes
	// the discover.go Resolver seam real: testharness/cmd/fedservice injects
	// the loopback SRV stub here so the Task 9 live gate can run the
	// PRODUCTION Service against harness domains (alpha.test/bravo.test)
	// that no real DNS answers for.
	Resolver Resolver
}

// listenAddr applies the ":7443" default — config.go's own defaults map
// already seeds this, but Config is also constructible directly (tests, the
// harness-genre callers), so the fallback lives here too, belt-and-suspenders.
func (c Config) listenAddr() string {
	if c.ListenAddr == "" {
		return ":7443"
	}
	return c.ListenAddr
}

// AllowlistPeer is one ENABLED federation_allowlist row the reconcile loop
// acts on — Domain + Scope only. The anchor material is a separate,
// narrower read via AnchorLookup (Task 1's split, promoted below).
type AllowlistPeer struct {
	Domain string
	Scope  string
}

// AllowlistLister lists the currently ENABLED federation_allowlist peers —
// an injectable seam (AnchorLookup's genre, stream.go) so reconcileOnce's
// core decision (which peers get a dial loop, given the allow-list +
// toggle state) is unit-testable against a stub, without a database
// (service_test.go).
type AllowlistLister func(ctx context.Context) ([]AllowlistPeer, error)

// newAllowlistLister builds the production AllowlistLister against
// federation_allowlist (FORCE RLS deny-all-to-setjoin_app, V138 — pool must
// bypass RLS: workerPool, which aliases the app pool until DB_WORKER_DSN is
// set, the same INERT-until-flip posture as every other workerPool caller
// in main.go).
func newAllowlistLister(pool pgxutil.WorkerPool) AllowlistLister {
	return func(ctx context.Context) ([]AllowlistPeer, error) {
		rows, err := pool.Query(ctx, `SELECT peer_domain, scope FROM federation_allowlist WHERE enabled`)
		if err != nil {
			return nil, fmt.Errorf("federation: list enabled allow-list peers: %w", err)
		}
		defer rows.Close()
		var out []AllowlistPeer
		for rows.Next() {
			var p AllowlistPeer
			if err := rows.Scan(&p.Domain, &p.Scope); err != nil {
				return nil, fmt.Errorf("federation: scan allow-list peer: %w", err)
			}
			out = append(out, p)
		}
		return out, rows.Err()
	}
}

// newAnchorLookup mirrors testharness/cmd/fedharness/anchor.go's
// newAnchorLookup (promoted, not re-derived — see that file's doc comment
// for why this is a narrower read than AllowlistLister: ANY row, enabled or
// not; local enabled/scope policy is authorizePeer's job at handshake time).
func newAnchorLookup(pool pgxutil.WorkerPool) AnchorLookup {
	return func(ctx context.Context, domain string) (Anchor, bool, error) {
		var pemStr string
		err := pool.QueryRow(ctx,
			`SELECT peer_anchor FROM federation_allowlist WHERE peer_domain = $1`, domain,
		).Scan(&pemStr)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return Anchor{}, false, nil
			}
			return Anchor{}, false, fmt.Errorf("federation: read anchor for %s: %w", domain, err)
		}
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			return Anchor{}, false, fmt.Errorf("federation: anchor for %s: no PEM block found", domain)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return Anchor{}, false, fmt.Errorf("federation: parse anchor for %s: %w", domain, err)
		}
		return Anchor{CACert: cert}, true, nil
	}
}

// dialsFirst is the SAME wiring rule as testharness/cmd/fedharness/gaps.go's
// dialsFirst — kept as a private copy (not an exported shared helper)
// because the testharness stays a standalone `package main` (Task 5's
// brief: the testharness is promoted FROM, not refactored to share code
// WITH, this production package). Exactly ONE side of an ordered pair
// dials; the other accepts via Listen's own forever-running Accept loop.
func dialsFirst(local, peer string) bool {
	return local < peer
}

// sleepBackoff is runDialer's backoff sleep (promoted verbatim from
// reconnect.go): sleeps *backoff (doubling, capped at max) unless ctx is
// cancelled first, in which case it returns false without sleeping —
// cancelling a peer's dial context (reconcileOnce's drop path) unblocks a
// sleeping dialer immediately instead of waiting out the backoff.
func sleepBackoff(ctx context.Context, backoff *time.Duration, max time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(*backoff):
	}
	*backoff *= 2
	if *backoff > max {
		*backoff = max
	}
	return true
}

// streamRegistry tracks the live *PeerStream for each peer domain this
// Service currently has established (either role — dialed OR accepted) so
// reconcileOnce can force-close one on disable/removal (DES-011 eviction —
// the accept-side half; the dial-side half is dropping the per-peer dial
// context, which tears down its own stream via wireAndRun's defer). clear
// is a clear-if-still-current op (the senderRegistry precedent,
// reconnect.go): a slow-to-unwind stale stream must never evict a NEWER one
// that has already superseded it.
type streamRegistry struct {
	mu sync.RWMutex
	m  map[string]*PeerStream
}

func newStreamRegistry() *streamRegistry { return &streamRegistry{m: make(map[string]*PeerStream)} }

func (r *streamRegistry) set(peer string, s *PeerStream) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old := r.m[peer]; old != nil && old != s {
		// Supersede-and-close (D-MAILSERVER-INTERNAL-FEDERATION-P1-002): a
		// transport-trusted peer can open a new stream for a domain whose old
		// stream is still live. Overwriting the registry entry alone left the
		// superseded stream's read loop, sender run and duplicated outbox
		// drain goroutines alive indefinitely — reconcileOnce could no longer
		// find them to force-close. Closing the old stream HERE breaks its
		// read loop immediately: its wireAndRun defer unwinds, and the
		// clear-if-current guard ensures that unwind can never evict this
		// newer registration.
		old.Close() //nolint:errcheck
	}
	r.m[peer] = s
}

func (r *streamRegistry) clear(peer string, s *PeerStream) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m[peer] == s {
		delete(r.m, peer)
	}
}

// closeIfPresent force-closes the live stream for peer, if any, returning
// whether one was found. Idempotent: closing an already-closing/closed
// net.Conn is a harmless error, same posture as reconnect.go's
// `stream.Close() //nolint:errcheck`.
func (r *streamRegistry) closeIfPresent(peer string) bool {
	r.mu.RLock()
	s := r.m[peer]
	r.mu.RUnlock()
	if s == nil {
		return false
	}
	s.Close() //nolint:errcheck
	return true
}

// domains returns a point-in-time snapshot of peer domains with a
// currently-tracked live stream.
func (r *streamRegistry) domains() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.m))
	for d := range r.m {
		out = append(out, d)
	}
	return out
}

// senderRegistry is reconnect.go's senderRegistry, promoted verbatim (same
// swap-map-on-reconnect shape, same clear-if-current guard): tracks the
// live *Sender for each peer so the federation_outbox:<peer> NOTIFY handler
// (subscribed dynamically per enabled peer in reconcileOnce, since the C1
// peer set — unlike the harness's static --peers CSV — changes at runtime)
// can find the CURRENT sender and Wake() it.
type senderRegistry struct {
	mu sync.RWMutex
	m  map[string]*Sender
}

func newSenderRegistry() *senderRegistry { return &senderRegistry{m: make(map[string]*Sender)} }

func (r *senderRegistry) set(peer string, s *Sender) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[peer] = s
}

func (r *senderRegistry) clear(peer string, s *Sender) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m[peer] == s {
		delete(r.m, peer)
	}
}

func (r *senderRegistry) wake(peer string) {
	r.mu.RLock()
	s := r.m[peer]
	r.mu.RUnlock()
	if s != nil {
		s.Wake()
	}
}

// get returns the live Sender for peer, or nil — Pillar C2 Task 6's outbound
// ephemeral path (SendTyping/sendEphemeralTo below) needs a direct handle
// (not just a Wake()), since a fire-and-forget ephemeral send is a normal
// Sender.SendEphemeral call, not an outbox-drain wakeup.
func (r *senderRegistry) get(peer string) *Sender {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.m[peer]
}

// Service is the production, reconcile-driven federation daemon mailserverd
// starts alongside its other unconditional job workers. DES-011 holds
// unchanged: the Service holds no authority — every decision (sequencing,
// dedup, allow-list, apply) is a reducer call; this is transport +
// lifecycle glue, promoted verbatim in shape from the C0 testharness.
type Service struct {
	cfg        Config
	pool       pgxutil.WorkerPool
	flags      *toggle.FeatureFlags
	directLtnr *db.Listener
	leafCert   tls.Certificate
	resolver   Resolver
	anchorLU   AnchorLookup
	listAllow  AllowlistLister
	logger     *slog.Logger

	senders *senderRegistry
	streams *streamRegistry

	mu         sync.Mutex
	dialers    map[string]context.CancelFunc // peer domain -> cancel for THIS instance's dial loop (dial-side peers only, dialsFirst==true)
	outboxSubs map[string]int                // peer domain -> federation_outbox:<peer> subscription id (both roles)

	wake chan struct{} // coalescing wake signal (buffered 1) — the Sender.Wake shape

	// Pillar C2 Task 6 (federated typing, Q5): the OUTBOUND per-peer token
	// bucket — distinct from any Sender's INBOUND ephemeralIn bucket (a
	// Sender only exists per established stream; this side must throttle
	// even before one exists / across reconnects, so it lives here keyed by
	// peer domain instead). No DB writes for typing, ever.
	ephemeralOutMu sync.Mutex
	ephemeralOut   map[string]*tokenBucket
}

// NewService builds the production federation.Service. Returns nil when
// cfg.LocalDomain is empty — the static-gate inert posture (Task 5): a box
// with no FEDERATION_LOCAL_DOMAIN configured gets no Service at all, so
// main.go never calls Run on a half-built one (mirrors meetRooms'
// "unconfigured ⇒ nil, safe" shape, but resolved at the constructor
// boundary since Service, unlike meet.Handler, has no per-request 503 gate
// to fall back on — Run must simply never be started).
func NewService(cfg Config, pool pgxutil.WorkerPool, flags *toggle.FeatureFlags, directLtnr *db.Listener, leafCert tls.Certificate, logger *slog.Logger) *Service {
	if strings.TrimSpace(cfg.LocalDomain) == "" {
		return nil
	}
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = NetResolver{}
	}
	return &Service{
		cfg: cfg, pool: pool, flags: flags, directLtnr: directLtnr, leafCert: leafCert,
		resolver:     resolver,
		anchorLU:     newAnchorLookup(pool),
		listAllow:    newAllowlistLister(pool),
		logger:       logger,
		senders:      newSenderRegistry(),
		streams:      newStreamRegistry(),
		dialers:      make(map[string]context.CancelFunc),
		outboxSubs:   make(map[string]int),
		wake:         make(chan struct{}, 1),
		ephemeralOut: make(map[string]*tokenBucket),
	}
}

// Wake signals the reconcile loop to re-read the allow-list immediately —
// called from the federation_allowlist_changed NOTIFY handler Run
// subscribes below (federation_peer_set/_delete emit it, Task 8) so an
// admin's peer add/enable/disable/delete takes effect within seconds, not
// the next reconcileInterval tick. Non-blocking + coalescing, the
// Sender.Wake shape.
func (s *Service) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run starts the accept-side Listen loop and the reconcile loop; both exit
// when ctx is cancelled. Never returns an error — logs and keeps running,
// the drive.NewWorker/meet.NewWorker `go worker.Run(ctx)` convention
// main.go uses for every unconditional job worker.
func (s *Service) Run(ctx context.Context) {
	if s == nil {
		return // defensive: main.go's static gate should never call Run on a nil Service, but this stays a safe no-op if it ever does
	}
	s.logger.Info("federation: service starting", "local_domain", s.cfg.LocalDomain, "listen", s.cfg.listenAddr())

	ln, err := net.Listen("tcp", s.cfg.listenAddr())
	if err != nil {
		s.logger.Error("federation: listen failed — service not started", "addr", s.cfg.listenAddr(), "error", err)
		return
	}
	go func() {
		<-ctx.Done()
		ln.Close() //nolint:errcheck
	}()

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{s.leafCert}}
	hello := Hello{FromDomain: s.cfg.LocalDomain, Ver: 1}
	// Accept side: Listen's own Accept loop runs for the Service's WHOLE
	// lifetime (ctx-scoped, never restarted) — a peer that (re)dials us is
	// picked up here automatically, no separate reconnect loop needed on
	// this side (the testharness main.go precedent). scope="dm" — the FLOOR
	// scope, deliberately: the wiring contract is exactly ONE stream per
	// ordered pair, and stream establishment only proves "this peer may
	// federate with us at all". federation_peer_authorize refuses p_scope
	// 'room' against a scope='dm' allow-list row, so authorizing the stream
	// at 'room' (as the C0 harness did) would brick every dm-scoped peer —
	// the exact rows the C1 admin console creates for DM federation. A
	// 'room'-scoped row still passes a 'dm' check (superset); room-CONTENT
	// enforcement for dm-scoped peers is the C2 fanout/apply layer's job,
	// per-payload, not a stream-establishment concern.
	go func() {
		s.runAcceptLoop(ctx, 250*time.Millisecond, func() error {
			return Listen(ctx, s.flags, ln, tlsCfg, s.anchorLU, hello, s.pool, "dm", s.logger,
				func(stream *PeerStream) {
					s.logger.Info("federation: accepted inbound stream", "peer", stream.Domain)
					go func() {
						if err := s.wireAndRun(ctx, stream); err != nil && ctx.Err() == nil {
							s.logger.Warn("federation: accepted stream ended", "peer", stream.Domain, "error", err)
						}
					}()
				})
		})
	}()

	if _, err := s.directLtnr.Subscribe(ctx, "federation_allowlist_changed", func(*pgconn.Notification) {
		s.Wake()
	}); err != nil {
		s.logger.Error("federation: subscribe federation_allowlist_changed failed — reconcile falls back to the ticker only", "error", err)
	}

	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	s.reconcileOnce(ctx) // converge immediately on start, don't wait a full tick
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("federation: service stopping")
			return
		case <-ticker.C:
			s.reconcileOnce(ctx)
		case <-s.wake:
			s.reconcileOnce(ctx)
		}
	}
}

// runAcceptLoop keeps a statically configured listener dormant while the
// dynamic feature is OFF, then starts accepting when an operator enables it.
// The old one-shot call let Listen return ErrFederationDisabled at boot and
// permanently lost the accept side, making the documented default-OFF ->
// live-ON rollout impossible without a process restart.
func (s *Service) runAcceptLoop(
	ctx context.Context,
	pollEvery time.Duration,
	accept func() error,
) {
	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()
	for {
		for !s.flags.IsEnabled(toggle.FeatureFederation) {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
		s.logger.Info("federation: accept loop enabled")
		err := accept()
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, ErrFederationDisabled) {
			continue
		}
		s.logger.Error("federation: Listen exited", "error", err)
		return
	}
}

// reconcileOnce re-reads feature.federation + the enabled allow-list and
// converges the live set of per-peer dial loops + streams to match — the
// meet.Worker.tick pattern (a DYNAMIC gate re-evaluated on every call,
// never a boot-time decision). A toggle flip to OFF drops every live
// stream and dial loop unconditionally: Dial/Listen/Sender already refuse
// NEW work while OFF (flags-gated), but an ALREADY-established stream needs
// this active teardown or it would otherwise keep running until it happens
// to break on its own.
func (s *Service) reconcileOnce(ctx context.Context) {
	if !s.flags.IsEnabled(toggle.FeatureFederation) {
		s.dropAll()
		return
	}

	peers, err := s.listAllow(ctx)
	if err != nil {
		s.logger.Warn("federation: reconcile: list enabled allow-list peers failed — leaving existing streams as-is", "error", err)
		return // a transient DB error must never tear down an already-live peer
	}

	enabled := make(map[string]bool, len(peers))
	desiredDial := make(map[string]bool, len(peers))
	for _, p := range peers {
		enabled[p.Domain] = true
		if dialsFirst(s.cfg.LocalDomain, p.Domain) {
			desiredDial[p.Domain] = true
		}
	}

	s.mu.Lock()
	var started, stopped []string
	for d := range desiredDial {
		if _, ok := s.dialers[d]; !ok {
			// #nosec G118 -- cancel is intentionally NOT deferred here: it is
			// stored in s.dialers and invoked later, explicitly, by this same
			// function's drop loop below (or by dropAll) — that IS the
			// DES-011 eviction mechanism (cancelling a live peer's dial
			// context tears down its dial loop AND its current stream).
			dctx, cancel := context.WithCancel(ctx)
			s.dialers[d] = cancel
			started = append(started, d)
			go s.runDialer(dctx, d)
		}
	}
	for d, cancel := range s.dialers {
		if !desiredDial[d] {
			cancel() // stops the dial loop AND tears down its current stream (sender.Run observes ctx.Done, wireAndRun's defer closes it) — DES-011 eviction
			delete(s.dialers, d)
			stopped = append(stopped, d)
		}
	}
	if s.directLtnr != nil {
		for peer := range enabled {
			if _, ok := s.outboxSubs[peer]; !ok {
				p := peer
				id, serr := s.directLtnr.Subscribe(ctx, "federation_outbox:"+p, func(*pgconn.Notification) {
					s.senders.wake(p)
				})
				if serr != nil {
					s.logger.Warn("federation: subscribe federation_outbox failed", "peer", p, "error", serr)
				} else {
					s.outboxSubs[p] = id
				}
			}
		}
		for peer, id := range s.outboxSubs {
			if !enabled[peer] {
				s.directLtnr.Unsubscribe("federation_outbox:"+peer, id)
				delete(s.outboxSubs, peer)
			}
		}
	}
	s.mu.Unlock()

	for _, d := range started {
		s.logger.Info("federation: reconcile: started dial loop", "peer", d)
	}
	for _, d := range stopped {
		s.logger.Info("federation: reconcile: dropped dial loop for disabled/removed peer", "peer", d)
	}

	// Accept-side eviction: a peer we don't dial (dialsFirst==false) can
	// still hold a live INBOUND stream that must be force-closed the moment
	// it stops being enabled — Listen's own authorizePeer call already
	// refuses that peer's NEXT reconnect attempt, but the CURRENT stream
	// stays open until something closes it (DES-011: eviction, not TTL).
	for _, peer := range s.streams.domains() {
		if !enabled[peer] {
			if s.streams.closeIfPresent(peer) {
				s.logger.Info("federation: reconcile: closed live stream for disabled/removed peer", "peer", peer)
			}
		}
	}
}

// dropAll tears down every live dial loop, outbox subscription, and stream
// — called when feature.federation flips OFF mid-run (reconcileOnce's OFF
// branch above).
func (s *Service) dropAll() {
	s.mu.Lock()
	for d, cancel := range s.dialers {
		cancel()
		delete(s.dialers, d)
	}
	if s.directLtnr != nil {
		for peer, id := range s.outboxSubs {
			s.directLtnr.Unsubscribe("federation_outbox:"+peer, id)
			delete(s.outboxSubs, peer)
		}
	}
	s.mu.Unlock()
	for _, peer := range s.streams.domains() {
		s.streams.closeIfPresent(peer)
	}
}

// runDialer owns the reconnect loop for ONE peer this instance dials
// (desiredDial[peer] == true, i.e. dialsFirst(localDomain, peer)).
// Promoted from testharness/cmd/fedharness/reconnect.go's runDialer
// verbatim in shape: re-resolves, re-anchors, and re-Dials on every attempt
// with capped exponential backoff (reset after every successful connect)
// until ctx is cancelled — reconcileOnce cancels this peer's ctx the
// instant it is no longer enabled, which is what makes disable an ACTIVE
// drop rather than a wait-for-the-peer-to-notice.
func (s *Service) runDialer(ctx context.Context, peer string) {
	const (
		initialBackoff = time.Second
		maxBackoff     = 30 * time.Second
		dialTimeout    = 10 * time.Second // bounds each Dial attempt so a hung TCP handshake to a dead peer never wedges past this attempt's own backoff
	)
	backoff := initialBackoff
	for ctx.Err() == nil {
		endpoint, err := ResolvePeer(ctx, s.resolver, peer)
		if err != nil {
			s.logger.Warn("federation: SRV resolve failed", "peer", peer, "error", err)
			if !sleepBackoff(ctx, &backoff, maxBackoff) {
				return
			}
			continue
		}

		anchor, ok, err := s.anchorLU(ctx, peer)
		if err != nil || !ok {
			s.logger.Warn("federation: no allow-list anchor for peer yet", "peer", peer, "error", err)
			if !sleepBackoff(ctx, &backoff, maxBackoff) {
				return
			}
			continue
		}

		hello := Hello{FromDomain: s.cfg.LocalDomain, Ver: 1}
		dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		stream, err := Dial(dialCtx, s.flags, endpoint, s.leafCert, anchor, hello)
		cancel()
		if err != nil {
			s.logger.Warn("federation: dial failed", "peer", peer, "target", endpoint.Target, "port", endpoint.Port, "error", err)
			if !sleepBackoff(ctx, &backoff, maxBackoff) {
				return
			}
			continue
		}

		s.logger.Info("federation: dialed peer", "peer", peer)
		backoff = initialBackoff // reset only after a successful connect

		err = s.wireAndRun(ctx, stream)
		if ctx.Err() != nil {
			return
		}
		s.logger.Warn("federation: stream to peer broke, reconnecting", "peer", peer, "error", err)
		if !sleepBackoff(ctx, &backoff, maxBackoff) {
			return
		}
	}
}

// wireAndRun creates the Receiver+Sender pair for one freshly (re)established
// PeerStream (promoted from reconnect.go's wireAndRun verbatim in shape),
// registers it in both the sender registry (so the federation_outbox NOTIFY
// wake can find it) and the stream registry (so reconcileOnce's force-close
// can find it), and blocks in sender.Run until the stream breaks or ctx is
// cancelled. initCursors (inside Run) resets the send/ack cursors to the
// durable last_acked_seq on every call — the reconnect-resume the C0 spike
// proved, which happens for free just by constructing a new Sender per
// (re)connect, dial-side or accept-side alike.
func (s *Service) wireAndRun(ctx context.Context, stream *PeerStream) error {
	receiver := NewReceiver(s.pool, s.flags, stream.Domain, s.logger)
	sender := NewSender(s.pool, s.flags, stream.Domain, stream, receiver, s.logger)
	// Pillar C2 Task 6: wire the hub-room ephemeral relay hook onto every
	// Sender — a no-op for a DM-only or spoke peer (federation_typing_notify
	// only ever returns relay:true for a hub-shape room's inbound typing
	// frame, which HandleEphemeral checks BEFORE ever calling this).
	//
	// Task 6 review (MAJOR 3): dispatched on its OWN goroutine, not called
	// inline. HandleEphemeral runs synchronously on the ORIGIN peer's
	// readLoop; relayRoomEphemeral fans out to every OTHER roster member via
	// their own Sender.SendEphemeral (a DB read + N wire writes). Even with
	// SendEphemeral's TryLock+deadline (sender.go) bounding each individual
	// write, a room with many members would still string those bounded
	// delays end-to-end on the origin's readLoop — stalling its own
	// acks/replay/message processing over a typing notification. The `go`
	// here fully decouples that: the origin's readLoop never waits on ANY
	// other peer's lock or write, bounded or not. ctx is this stream's
	// lifetime context — if the stream tears down mid-relay the DB read/
	// sends simply error/no-op, never blocking anything (nothing awaits this
	// goroutine).
	sender.relayEphemeral = func(originPeer string, payload json.RawMessage) {
		go s.relayRoomEphemeral(ctx, originPeer, payload)
	}
	s.senders.set(stream.Domain, sender)
	s.streams.set(stream.Domain, stream)
	defer func() {
		s.senders.clear(stream.Domain, sender)
		s.streams.clear(stream.Domain, stream)
		stream.Close() //nolint:errcheck
	}()
	return sender.Run(ctx)
}

// ── Pillar C2 Task 6: federated typing (Q5 — "federated typing", never
// "presence"; the outbound half). The inbound half (HandleEphemeral, the
// per-peer token bucket, the ephemeralPayload wire shape) lives in
// sender.go — see that file's header comment for why the whole ephemeral
// seam avoids receiver.go (Task 4, built in parallel, owns that file). ──

// TypingChannel is what the chat package's outbound hook (chat/presence.go's
// typingSignal, AFTER chat_typing_signal succeeds and the outbound debounce
// already admitted the call — Q5's debounce-first ordering) fills from a
// channel row it can already read under its own RLS scope, and hands to
// SendTyping. Exactly one of the DM/spoke-room/hub-room shapes applies:
//
//   - DM:         RoomID == "",  PeerDomain != "" — RemoteID/LocalUserEmail set.
//   - spoke room: RoomID != "",  PeerDomain != "" (the bound hub) — sent
//     ONLY to that one peer.
//   - hub room:   RoomID != "",  PeerDomain == "" — fanned to the active
//     (non-left, non-parked) roster.
type TypingChannel struct {
	ChannelID      int64
	PeerDomain     string
	RoomID         string
	RemoteID       string
	LocalUserEmail string
}

// SendTyping sends one federated typing signal for ch. Toggle-OFF is a
// silent no-op (the registry is empty while OFF — reconcileOnce's dropAll
// already tore down every sender). Every send passes the Service-side
// outbound per-peer token bucket (ephemeralOutAllow) BEFORE anything else —
// no DB writes for typing, ever; a throttled or registry-miss send simply
// drops (typing is loss-tolerant by definition).
func (s *Service) SendTyping(ctx context.Context, ch TypingChannel) {
	if !s.flags.IsEnabled(toggle.FeatureFederation) {
		return
	}
	switch {
	case ch.RoomID == "":
		// DM.
		s.sendEphemeralTo(ch.PeerDomain, mustJSON(ephemeralPayload{
			Op: "typing", FromAddr: ch.LocalUserEmail, ToAddr: ch.RemoteID,
		}))
	case ch.PeerDomain != "":
		// spoke room: sent only to the one bound hub.
		s.sendEphemeralTo(ch.PeerDomain, mustJSON(ephemeralPayload{Op: "typing", RoomID: ch.RoomID}))
	default:
		// hub room: fan to the active roster — this IS the hub's own send,
		// so there is no origin to exclude.
		s.fanoutEphemeral(ctx, ch.RoomID, "", mustJSON(ephemeralPayload{Op: "typing", RoomID: ch.RoomID}))
	}
}

// relayRoomEphemeral is the hub-room fan-out hook wireAndRun sets on every
// Sender's relayEphemeral field. Called synchronously from HandleEphemeral
// (sender.go) ONLY when federation_typing_notify's verdict said
// relay:true — a live roster member's typing frame arrived at the hub — so
// it fans the SAME minimal payload out to every OTHER active roster member,
// origin excluded (the no-re-relay rule, the federation_room_fanout genre).
// The payload is already minimal (roomId only, no per-member identity) —
// forwarded as-is, never re-derived per recipient.
func (s *Service) relayRoomEphemeral(ctx context.Context, originPeer string, payload json.RawMessage) {
	var env ephemeralPayload
	if err := json.Unmarshal(payload, &env); err != nil || env.RoomID == "" {
		return // internal-invariant guard: only ever called with a room-shaped payload
	}
	s.fanoutEphemeral(ctx, env.RoomID, originPeer, payload)
}

// fanoutEphemeral resolves roomID's active (non-left, non-parked) roster
// members — a plain read, NEVER federation_enqueue/federation_room_fanout:
// ephemeral bypasses the outbox/seq/ack rail entirely (wire.go). excludeDomain
// is the no-re-relay origin skip (empty for the hub's own outbound send,
// which has no origin to exclude — an empty string never matches a real
// domain, so the exclusion is harmlessly inert in that case).
func (s *Service) fanoutEphemeral(ctx context.Context, roomID, excludeDomain string, payload json.RawMessage) {
	rows, err := s.pool.Query(ctx,
		`SELECT member_domain FROM federation_room_members
		  WHERE room_id=$1 AND left_at IS NULL AND parked_at IS NULL AND member_domain <> $2`,
		roomID, excludeDomain)
	if err != nil {
		s.logger.Warn("federation: ephemeral roster read failed", "error", err)
		return
	}
	var members []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			rows.Close()
			s.logger.Warn("federation: ephemeral roster scan failed", "error", err)
			return
		}
		members = append(members, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.logger.Warn("federation: ephemeral roster read failed", "error", err)
		return
	}
	for _, m := range members {
		s.sendEphemeralTo(m, payload)
	}
}

// sendEphemeralTo throttles (ephemeralOutAllow) and, on a live Sender for
// peer, sends. A registry miss (no established stream) or an exhausted
// bucket both silently drop — no logging of the payload/peer's traffic
// content, only ever a bare peer domain on the one error path.
func (s *Service) sendEphemeralTo(peer string, payload json.RawMessage) {
	if !s.ephemeralOutAllow(peer) {
		return
	}
	sender := s.senders.get(peer)
	if sender == nil {
		return
	}
	if err := sender.SendEphemeral(payload); err != nil {
		s.logger.Warn("federation: send ephemeral failed", "peer", peer, "error", err)
	}
}

// ephemeralOutAllow is the Service-side OUTBOUND per-peer token bucket —
// distinct from any Sender's INBOUND ephemeralIn bucket (sender.go): this
// side must throttle even before a Sender exists yet / across reconnects,
// so it is keyed by peer domain here instead of living on the Sender.
func (s *Service) ephemeralOutAllow(peer string) bool {
	s.ephemeralOutMu.Lock()
	b, ok := s.ephemeralOut[peer]
	if !ok {
		b = newTokenBucket(ephemeralBucketSize, ephemeralRefillPerSec)
		s.ephemeralOut[peer] = b
	}
	s.ephemeralOutMu.Unlock()
	return b.allow()
}
