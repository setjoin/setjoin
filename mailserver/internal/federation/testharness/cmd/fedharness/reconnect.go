package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"sync"
	"time"

	"setjoin.com/mailserver/internal/federation"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// appDeps bundles what both the dial-reconnect loop and the accept-side
// wiring need per stream — one struct instead of a five-argument function
// signature repeated in two places.
type appDeps struct {
	pool        pgxutil.WorkerPool
	flags       *toggle.FeatureFlags
	localDomain string
	leafCert    tls.Certificate
	resolver    federation.Resolver
	anchorLU    federation.AnchorLookup
	senders     *senderRegistry
	logger      *slog.Logger
}

// senderRegistry tracks the live *federation.Sender for each peer domain so
// the pg_notify handler (subscribed once per peer at startup) can find the
// CURRENT sender and Wake() it — the sender is replaced wholesale on every
// reconnect (a fresh Sender+Receiver pair, per the reconnect-resume
// contract), so this is a simple swap-map, not a growing set.
type senderRegistry struct {
	mu sync.RWMutex
	m  map[string]*federation.Sender
}

func newSenderRegistry() *senderRegistry {
	return &senderRegistry{m: make(map[string]*federation.Sender)}
}

func (r *senderRegistry) set(peer string, s *federation.Sender) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[peer] = s
}

// clear removes the entry only if it still points at s — a stale clear from
// an old goroutine (e.g. a slow-to-unwind dialer whose stream a NEWER
// connection has already superseded) must never evict the fresh sender.
func (r *senderRegistry) clear(peer string, s *federation.Sender) {
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

// wireAndRun creates the Receiver+Sender pair for one freshly (re)established
// PeerStream, registers the sender so pg_notify wakeups reach it, and blocks
// in sender.Run until the stream breaks or ctx is cancelled. initCursors
// (inside Run) resets the send/ack cursors to the durable last_acked_seq on
// every call — this is the reconnect-resume the whole spike exists to prove,
// and it happens for free just by constructing a new Sender per (re)connect.
func wireAndRun(ctx context.Context, deps *appDeps, stream *federation.PeerStream) error {
	receiver := federation.NewReceiver(deps.pool, deps.flags, stream.Domain, deps.logger)
	sender := federation.NewSender(deps.pool, deps.flags, stream.Domain, stream, receiver, deps.logger)
	deps.senders.set(stream.Domain, sender)
	defer func() {
		deps.senders.clear(stream.Domain, sender)
		stream.Close() //nolint:errcheck
	}()
	return sender.Run(ctx)
}

// runDialer owns the reconnect loop for ONE peer this instance dials
// (dialsFirst(localDomain, peer) == true — see gaps.go). It re-resolves,
// re-anchors, and re-Dials on every attempt (an anchor row can change
// between connects; re-resolving costs nothing on a spike-scale peer list)
// and keeps retrying with a capped exponential backoff, reset after every
// successful connect, until ctx is cancelled — the acceptor side needs no
// equivalent loop because federation.Listen's own Accept loop already runs
// forever and picks up a fresh inbound connection the moment the dialer
// redials (README.md / stream.go's Listen doc comment).
func runDialer(ctx context.Context, deps *appDeps, peer string) {
	const (
		initialBackoff = time.Second
		maxBackoff     = 30 * time.Second
		dialTimeout    = 10 * time.Second // bounds each Dial attempt so a hung TCP handshake to a dead peer never wedges past this attempt's own backoff
	)
	backoff := initialBackoff
	for ctx.Err() == nil {
		endpoint, err := federation.ResolvePeer(ctx, deps.resolver, peer)
		if err != nil {
			deps.logger.Warn("fedharness: SRV resolve failed", "peer", peer, "error", err)
			if !sleepBackoff(ctx, &backoff, maxBackoff) {
				return
			}
			continue
		}

		anchor, ok, err := deps.anchorLU(ctx, peer)
		if err != nil || !ok {
			deps.logger.Warn("fedharness: no allow-list anchor for peer yet", "peer", peer, "error", err)
			if !sleepBackoff(ctx, &backoff, maxBackoff) {
				return
			}
			continue
		}

		hello := federation.Hello{FromDomain: deps.localDomain, Ver: 1}
		dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		stream, err := federation.Dial(dialCtx, deps.flags, endpoint, deps.leafCert, anchor, hello)
		cancel()
		if err != nil {
			deps.logger.Warn("fedharness: dial failed", "peer", peer, "target", endpoint.Target, "port", endpoint.Port, "error", err)
			if !sleepBackoff(ctx, &backoff, maxBackoff) {
				return
			}
			continue
		}

		deps.logger.Info("fedharness: dialed peer", "peer", peer)
		backoff = initialBackoff // reset only after a successful connect

		err = wireAndRun(ctx, deps, stream)
		if ctx.Err() != nil {
			return
		}
		deps.logger.Warn("fedharness: stream to peer broke, reconnecting", "peer", peer, "error", err)
		if !sleepBackoff(ctx, &backoff, maxBackoff) {
			return
		}
	}
}

// sleepBackoff sleeps for *backoff (doubling it, capped at max) unless ctx
// is cancelled first, in which case it returns false without sleeping.
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
