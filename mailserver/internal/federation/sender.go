package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// msgEnvelope is the KindMsg payload: the per-peer sequence number the ordering
// rail turns on, plus the opaque content the archive keeps verbatim. content_type
// is the e2ee-optional seam (E5): 'application/x-setjoin-e2ee' makes Payload
// opaque to the archive while the envelope (from/seq/stanza) is still retained.
type msgEnvelope struct {
	PeerSeq     int64           `json:"peerSeq"`
	ContentType string          `json:"contentType"`
	Payload     json.RawMessage `json:"payload"`
}

// seqEnvelope is the KindAck / KindReplayReq / KindReceipt payload — a bare
// sequence number. On an ack it names the seq the peer durably applied; on a
// replay_req it names the seq the peer wants the stream resumed FROM.
type seqEnvelope struct {
	PeerSeq int64 `json:"peerSeq"`
}

// defaultWindow bounds how far the sender may run ahead of durable acks — a
// dead peer must not let the outbox drain unboundedly into an in-flight backlog.
// ponytail: a fixed window is fine for the spike; a per-peer tunable is the C1 knob.
const defaultWindow = 256

// Sender drives ONE peer's federation stream. It is deliberately NOT the
// pushjobs worker (a 3s SKIP-LOCKED per-row ticker with per-row backoff — an
// unordered mechanism; see the plan's "Why not pushjobs"). Instead: exactly one
// Sender per peer domain owns both directions of the single PeerStream —
//
//   - the DRAIN loop reads federation_outbox strictly in `peer_seq` order
//     (WHERE peer_seq > sentCursor ORDER BY peer_seq, NO SKIP LOCKED) and writes
//     each KindMsg frame in order; a write failure HALTS the peer (the daemon
//     re-dials) — a failed seq is never skipped, so ordering can't be violated.
//   - the READ loop is the single reader of the PeerStream (PeerStream is
//     single-reader): it applies inbound KindMsg via the paired Receiver, and
//     handles our messages' KindAck (advance the durable ack cursor) and
//     KindReplayReq (rewind the send cursor to resend from the named seq).
//
// Wakeups come from Wake() — the fedharness daemon Subscribes the
// `federation_outbox:<peer>` pg_notify channel (emitted by federation_enqueue via
// app_notify) through the DB_DIRECT_DSN db.Listener dispatcher and calls Wake()
// in its handler; a 3s ticker is the lost-wakeup fallback ONLY. Because a wakeup
// means "check the cursor" (not "here is a message"), NOTIFY coalescing is
// harmless — this is the whole reason the outbox+cursor design tolerates the
// existing dispatcher instead of needing a new broker (L1).
//
// Exactly-once across reconnect: on a fresh stream the cursors reset to the
// durable federation_peers.last_acked_seq (initCursors), so the sender resends
// everything past the last ACK; the receiver's federation_apply_inbound dedups
// on the (peer,seq) PK (returns applied=false but STILL acks), so the inbox
// applies each seq exactly once regardless of resend. DES-011: all authority
// (seq assignment, apply, ack) is in the reducers; the Sender is dumb transport.
type Sender struct {
	pool     pgxutil.WorkerPool
	flags    *toggle.FeatureFlags
	peer     string
	stream   *PeerStream
	receiver *Receiver
	logger   *slog.Logger
	window   int64

	mu         sync.Mutex // guards sentCursor / lastAcked
	sentCursor int64      // highest seq written to THIS stream (in-memory)
	lastAcked  int64      // highest seq the peer durably acked (mirror of federation_peers.last_acked_seq)

	writeMu sync.Mutex    // serializes WriteFrame: the read loop (acks for inbound) and the drain loop both write
	wake    chan struct{} // coalescing wake signal (buffered 1)

	// Pillar C2 Task 6 (federated typing — Q5, "federated typing" never
	// "presence"): the ephemeral leg lives ENTIRELY in this file, not
	// receiver.go. Task 4 (inbound federation_apply_room, built in
	// parallel) owns receiver.go; the plan's own Task 6 placement note
	// says the readLoop case for KindEphemeral lands here, so the whole
	// HandleEphemeral seam (below) is a Sender method instead of a
	// Receiver one — Sender is already 1:1 with a peer domain, which is
	// exactly the scope an inbound per-peer throttle needs anyway.
	ephemeralIn *tokenBucket // per-peer inbound typing throttle, lazily initialized (nil until first ephemeral frame)

	// er5-s12 (occ_820410e337d38675e8ff2426, resource-exhaustion
	// .federation-replay-window): per-peer bound on HONORED replay requests —
	// each honored rewind re-sends up to the in-flight window of retained
	// outbox frames, so an unbounded replay loop is a retained-outbox
	// amplification vector. Same tokenBucket/loss-tolerant-drop shape as the
	// inbound typing throttle above; lazily initialized (nil until first
	// replay_req) for Senders built without NewSender.
	replayIn *tokenBucket

	// relayEphemeral is set by Service.wireAndRun (service.go) ONLY for a
	// hub org's room channel: federation_typing_notify's 'relay' verdict
	// tells HandleEphemeral this frame's origin was a live roster member of
	// a HUB-shape room, so it must be re-fanned to the rest of the roster
	// (skipping the origin). nil for every other Sender (a DM-only peer, a
	// spoke's peer, or any Sender built directly in a test) — HandleEphemeral
	// is nil-safe here, never dereferencing without a check.
	relayEphemeral func(originPeer string, payload json.RawMessage)
}

// NewSender creates the Sender for one peer, paired with the Receiver that
// applies that peer's inbound messages on the same stream.
func NewSender(pool pgxutil.WorkerPool, flags *toggle.FeatureFlags, peer string, stream *PeerStream, receiver *Receiver, logger *slog.Logger) *Sender {
	return &Sender{
		pool: pool, flags: flags, peer: peer, stream: stream, receiver: receiver,
		logger: logger, window: defaultWindow, wake: make(chan struct{}, 1),
		ephemeralIn: newTokenBucket(ephemeralBucketSize, ephemeralRefillPerSec),
		replayIn:    newTokenBucket(replayBucketSize, replayRefillPerSec),
	}
}

// Wake signals the drain loop to check the outbox cursor. Non-blocking and
// coalescing — the daemon calls it from the pg_notify handler; the read loop
// calls it after an ack opens the in-flight window. Safe to call before Run.
func (s *Sender) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run drives the peer until ctx is cancelled or the stream breaks (returned as
// an error so the daemon re-dials — a broken stream halts, never silently drops).
// No-op returning ErrFederationDisabled when feature.federation is OFF (D11).
func (s *Sender) Run(ctx context.Context) error {
	if !s.flags.IsEnabled(toggle.FeatureFederation) {
		return ErrFederationDisabled
	}
	if err := s.initCursors(ctx); err != nil {
		return fmt.Errorf("federation: init cursors for %s: %w", s.peer, err)
	}

	errc := make(chan error, 1)
	go func() { errc <- s.readLoop(ctx) }()

	ticker := time.NewTicker(3 * time.Second) // lost-wakeup fallback ONLY
	defer ticker.Stop()

	s.Wake() // drain any backlog on connect
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errc:
			return err // stream broke → halt this peer; the daemon re-dials
		case <-ticker.C:
			if err := s.drain(ctx); err != nil {
				return err
			}
		case <-s.wake:
			if err := s.drain(ctx); err != nil {
				return err
			}
		}
	}
}

// initCursors resets the in-memory send/ack cursors to the durable
// last_acked_seq — the load-bearing reconnect-resume step (§Exactly-once above).
func (s *Sender) initCursors(ctx context.Context) error {
	var acked int64
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE((SELECT last_acked_seq FROM federation_peers WHERE peer_domain=$1),0)`,
		s.peer).Scan(&acked)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.sentCursor, s.lastAcked = acked, acked
	s.mu.Unlock()
	return nil
}

type outRow struct {
	seq         int64
	stanzaID    string
	contentType string
	payload     json.RawMessage
}

// drain writes every outbox row past sentCursor, in seq order, up to the
// in-flight window, HALTING (returning the error) on the first write failure —
// never skipping a seq.
func (s *Sender) drain(ctx context.Context) error {
	for {
		s.mu.Lock()
		low, inflight := s.sentCursor, s.sentCursor-s.lastAcked
		s.mu.Unlock()
		limit := s.window - inflight
		if limit <= 0 {
			return nil // window full — wait for acks (a KindAck Wake()s us)
		}

		// Scan the whole batch before writing: pgx rows must be drained before
		// the conn is reused, and writes are network I/O we don't want holding
		// a DB cursor open.
		rows, err := s.pool.Query(ctx,
			`SELECT peer_seq, stanza_id, content_type, payload
			   FROM federation_outbox
			  WHERE peer_domain=$1 AND peer_seq > $2
			  ORDER BY peer_seq
			  LIMIT $3`,
			s.peer, low, limit)
		if err != nil {
			return err
		}
		var batch []outRow
		for rows.Next() {
			var r outRow
			if err := rows.Scan(&r.seq, &r.stanzaID, &r.contentType, &r.payload); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}

		for _, r := range batch {
			f := Frame{Kind: KindMsg, StanzaID: r.stanzaID, Payload: mustJSON(msgEnvelope{
				PeerSeq: r.seq, ContentType: r.contentType, Payload: r.payload,
			})}
			if err := s.send(f); err != nil {
				return err // halt-on-failure: sentCursor NOT advanced, so retry resumes here in order
			}
			s.mu.Lock()
			s.sentCursor = r.seq
			s.mu.Unlock()
		}
	}
}

// readLoop is the single reader of the PeerStream.
func (s *Sender) readLoop(ctx context.Context) error {
	for {
		f, err := s.stream.ReadFrame()
		if err != nil {
			return fmt.Errorf("federation: read from %s: %w", s.peer, err)
		}
		switch f.Kind {
		case KindAck, KindReceipt:
			// Transport ack doubles as the delivery receipt for the spike
			// (XEP-0184 stanza→message mapping is a C1 item). Advance the durable
			// ack cursor and open the in-flight window.
			var e seqEnvelope
			if err := json.Unmarshal(f.Payload, &e); err != nil {
				return fmt.Errorf("federation: unmarshal ack from %s: %w", s.peer, err)
			}
			// er5-s12 (occ_642310eee5108ebbcdd9780a, integrity
			// .federation-future-ack): applyAck refuses an ack (or receipt)
			// naming a seq beyond our send cursor — a forged future ack would
			// otherwise poison the durable outbox (see applyAck).
			if err := s.applyAck(ctx, e.PeerSeq); err != nil {
				return err
			}
			s.Wake()
		case KindReplayReq:
			// The peer asks us to resume from a named seq (its apply cursor is
			// behind our send cursor — a gap or a lost ack). Rewind so the next
			// drain resends from there.
			var e seqEnvelope
			if err := json.Unmarshal(f.Payload, &e); err != nil {
				return fmt.Errorf("federation: unmarshal replay_req from %s: %w", s.peer, err)
			}
			// er5-s12 (occ_820410e337d38675e8ff2426, resource-exhaustion
			// .federation-replay-window): applyReplayReq refuses a future
			// resume point (cursor poisoning, same forge class as a future
			// ack), clamps the rewind to the durable ack point, and rate-caps
			// honored rewinds — a replay loop must not amplify the retained
			// outbox without bound.
			rewound, err := s.applyReplayReq(e.PeerSeq)
			if err != nil {
				return err
			}
			if rewound {
				s.Wake()
			}
		case KindMsg:
			// Inbound message FROM the peer — apply it and write back the
			// receiver's response (KindAck on success/dup, KindReplayReq on a gap).
			resp, err := s.receiver.Handle(ctx, f)
			if err != nil {
				return fmt.Errorf("federation: handle inbound from %s: %w", s.peer, err)
			}
			if err := s.send(resp); err != nil {
				return err
			}
		case KindHello:
			// A reconnect hello's ResumeFromSeq is honored at dial-time
			// (initCursors already reset to the durable ack point); nothing to do here.
		case KindEphemeral:
			// Federated typing (Q5 — "federated typing", never "presence").
			// No response frame written: ephemeral has no ack/seq/outbox — a
			// dropped or throttled typing frame costs nothing (wire.go's
			// KindEphemeral doc comment). A malformed/unresolvable frame is
			// logged and dropped inside HandleEphemeral itself; it never
			// halts this peer's stream.
			s.HandleEphemeral(ctx, f)
		default:
			s.logger.Warn("federation: unknown frame kind", "peer", s.peer, "kind", f.Kind)
		}
	}
}

// replayBucketSize/replayRefillPerSec size the per-peer inbound replay token
// bucket: a burst of 5 honored rewinds, then 1/s. A legitimate peer replays
// once per gap (rarely a small burst across stream hiccups); sustained replay
// pressure beyond the bucket is a misbehaving peer, and its excess requests
// are dropped loss-tolerantly — the ordered rail's own progress never depends
// on an inbound replay.
const (
	replayBucketSize   = 5
	replayRefillPerSec = 1
)

// applyAck validates one inbound ack/receipt seq against the send cursor and
// advances the durable ack cursor.
//
// er5-s12 (occ_642310eee5108ebbcdd9780a, integrity.federation-future-ack):
// an ack names a seq the peer DURABLY APPLIED, so it can never legitimately
// name a seq this sender has not written to the stream — sentCursor is the
// highest seq written. federation_ack itself blithely advances
// federation_peers.last_acked_seq to any higher value, so an accepted future
// ack would (a) mark unsent outbox rows acked — every later reconnect resumes
// PAST them and the messages are silently lost (the durable-outbox poison),
// and (b) open the in-flight window unboundedly (inflight = sentCursor -
// lastAcked goes negative). A future ack is therefore a protocol violation:
// the error halts the peer (Run returns it; the daemon re-dials and
// initCursors re-reads the durable, unpoisoned cursor). The guard runs BEFORE
// the federation_ack call, so the forged seq never reaches the database.
func (s *Sender) applyAck(ctx context.Context, peerSeq int64) error {
	s.mu.Lock()
	sent := s.sentCursor
	s.mu.Unlock()
	if peerSeq < 0 || peerSeq > sent {
		return fmt.Errorf("federation: forged ack %d from %s: beyond highest sent seq %d — stream halted",
			peerSeq, s.peer, sent)
	}
	if _, err := s.pool.Exec(ctx, `SELECT federation_ack($1,$2)`, s.peer, peerSeq); err != nil {
		return fmt.Errorf("federation: ack %d for %s: %w", peerSeq, s.peer, err)
	}
	s.mu.Lock()
	if peerSeq > s.lastAcked {
		s.lastAcked = peerSeq
	}
	s.mu.Unlock()
	return nil
}

// applyReplayReq validates and applies one inbound replay request, reporting
// whether the send cursor actually moved (the caller wakes the drain loop
// only on a real rewind).
//
// er5-s12 (occ_820410e337d38675e8ff2426, resource-exhaustion
// .federation-replay-window): three bounds, each against a distinct abuse of
// the replay lever:
//   - a resume point beyond the send cursor would JUMP sentCursor FORWARD,
//     silently skipping unsent outbox rows on the next drain — the same
//     cursor-poisoning forge as a future ack, so it is a protocol violation
//     that halts the peer (returned error);
//   - a rewind behind the durable ack point asks us to re-send rows the peer
//     already reported applied — clamped to lastAcked, which also keeps
//     inflight = sentCursor - lastAcked from going negative and widening the
//     drain window past the configured cap;
//   - the replayIn token bucket caps HONORED rewinds per interval: each one
//     re-sends up to the in-flight window of retained frames, so unbounded
//     replay requests are an unbounded retained-outbox amplification. Excess
//     requests are dropped (Debug — a peer-controlled-rate path must not
//     itself become a log flood, the same call as the typing throttle).
func (s *Sender) applyReplayReq(peerSeq int64) (rewound bool, err error) {
	s.mu.Lock()
	sent := s.sentCursor
	s.mu.Unlock()
	if peerSeq < 0 || peerSeq-1 > sent {
		return false, fmt.Errorf("federation: forged replay_req %d from %s: beyond highest sent seq %d — stream halted",
			peerSeq, s.peer, sent)
	}
	if s.replayIn == nil {
		s.replayIn = newTokenBucket(replayBucketSize, replayRefillPerSec)
	}
	if !s.replayIn.allow() {
		s.logger.Debug("federation: inbound replay throttled", "peer", s.peer)
		return false, nil
	}
	s.mu.Lock()
	resume := peerSeq - 1
	if resume < s.lastAcked {
		resume = s.lastAcked // never rewind behind what the peer already durably applied
	}
	if resume < s.sentCursor {
		s.sentCursor = resume
		rewound = true
	}
	s.mu.Unlock()
	if rewound {
		s.logger.Warn("federation: peer requested replay", "peer", s.peer, "resume_from", peerSeq)
	}
	return rewound, nil
}

// ephemeralWriteTimeout bounds SendEphemeral's actual wire write (below) —
// typing is loss-tolerant by definition (Q5), so a black-holed peer must
// never let this write hang. Cleared immediately after (success or
// timeout) so it never leaks a deadline onto the ordered rail's own writes,
// which share this same conn/writeMu.
const ephemeralWriteTimeout = 2 * time.Second

// SendEphemeral writes payload as a KindEphemeral frame — no seq, no outbox
// row, no ack, fire-and-forget by construction (wire.go).
//
// Task 6 review (MAJOR 3 — cross-peer head-of-line blocking): a hub's
// inbound typing frame relays synchronously through HandleEphemeral into
// EVERY other roster member's own Sender.SendEphemeral (service.go's
// fanoutEphemeral), so a naive s.send (blocking Lock + an undeadlined TLS
// write) would let ONE black-holed peer wedge the ORIGIN peer's readLoop —
// stalling that peer's acks/replay/message processing over a mere typing
// notification. Fixed two ways:
//   - TryLock, not Lock: if this stream's writeMu is already held (the drain
//     loop or another writer is mid-write), DROP rather than queue — never
//     compete with the ordered rail for the lock.
//   - a write deadline while holding the lock: even a successfully-acquired
//     write can black-hole on the network; the deadline bounds it instead of
//     blocking forever. (service.go's wireAndRun additionally dispatches the
//     relay fan-out on its own goroutine, so the origin's readLoop is never
//     exposed to this call's latency at all — see wireAndRun's comment.)
//
// A drop returns nil, not an error — a throttled/lock-contended/timed-out
// ephemeral send costs nothing and must not read as a stream failure the way
// a genuine ordered-rail write error does.
func (s *Sender) SendEphemeral(payload json.RawMessage) error {
	if !s.writeMu.TryLock() {
		return nil // ponytail: another writer holds the conn — drop, don't wait
	}
	defer s.writeMu.Unlock()
	if err := s.stream.conn.SetWriteDeadline(time.Now().Add(ephemeralWriteTimeout)); err == nil {
		defer s.stream.conn.SetWriteDeadline(time.Time{}) //nolint:errcheck // best-effort clear
	}
	return s.stream.WriteFrame(Frame{Kind: KindEphemeral, Payload: payload})
}

// ephemeralPayload is the KindEphemeral wire shape (both the room and DM
// variants fit the same struct — the unused field is simply empty JSON on
// the other shape, no separate types needed for a 2-field, loss-tolerant
// frame). Non-typing ops are dropped+logged (Debug, Task 6 review MINOR —
// see HandleEphemeral) — no other ephemeral op class exists in v1 (Q5).
type ephemeralPayload struct {
	Op       string `json:"op"`
	RoomID   string `json:"roomId,omitempty"`
	FromAddr string `json:"fromAddr,omitempty"`
	ToAddr   string `json:"toAddr,omitempty"`
}

// HandleEphemeral applies one inbound KindEphemeral frame. Log hygiene
// (ratified Q5): NEVER logs payload/address material on any path below —
// every slog line here carries at most the peer domain and/or a bare count.
// Typing is ephemeral and unarchived BY DESIGN: federation_typing_notify is
// read-only+NOTIFY, so this whole path makes zero table writes.
func (s *Sender) HandleEphemeral(ctx context.Context, f Frame) {
	if !s.flags.IsEnabled(toggle.FeatureFederation) {
		return
	}

	// Inbound per-peer throttle BEFORE any DB round trip (the Q5 ordering
	// obligation, mirrored from the outbound debounce in chat/presence.go) —
	// a typing storm from a misbehaving/compromised peer must never reach
	// Postgres, let alone the relay fan-out below.
	if s.ephemeralIn == nil {
		s.ephemeralIn = newTokenBucket(ephemeralBucketSize, ephemeralRefillPerSec)
	}
	// Task 6 review (MINOR): these three lines are on a path a misbehaving/
	// compromised peer directly controls the RATE of (a typing storm hits
	// "throttled" once per frame over the bucket; a malformed-payload/wrong-
	// op peer can do the same) — a WARN-per-frame here would itself become
	// the log-flooding vector the throttle exists to prevent. Debug, not
	// rate-limited: cheaper than a per-peer log limiter, and this path never
	// carries anything actionable a human needs paged on (sender.go's other
	// WARNs, e.g. an unknown frame kind or a lost stream, stay at Warn).
	if !s.ephemeralIn.allow() {
		s.logger.Debug("federation: inbound ephemeral throttled", "peer", s.peer)
		return
	}

	var env ephemeralPayload
	if err := json.Unmarshal(f.Payload, &env); err != nil {
		s.logger.Debug("federation: inbound ephemeral unmarshal failed — dropped", "peer", s.peer)
		return
	}
	if env.Op != "typing" {
		s.logger.Debug("federation: inbound ephemeral non-typing op dropped", "peer", s.peer)
		return
	}

	var verdictJSON []byte
	if err := s.pool.QueryRow(ctx,
		`SELECT federation_typing_notify($1,$2)`, s.peer, []byte(f.Payload),
	).Scan(&verdictJSON); err != nil {
		s.logger.Warn("federation: federation_typing_notify failed", "peer", s.peer, "error", err)
		return
	}
	var verdict struct {
		OK    bool `json:"ok"`
		Relay bool `json:"relay"`
	}
	if err := json.Unmarshal(verdictJSON, &verdict); err != nil {
		s.logger.Warn("federation: federation_typing_notify returned unparseable verdict", "peer", s.peer)
		return
	}
	s.applyEphemeralVerdict(verdict.OK, verdict.Relay, env)
}

// applyEphemeralVerdict is the post-DB-call half of HandleEphemeral, split
// out so the relay-dispatch decision (relay iff verdict.Relay AND a hook is
// wired — the hub-room-only case) is unit-testable without a database:
// federation_typing.pg already proves the reducer's OWN ok/relay verdict
// matrix (DM/hub/spoke × honest/spoofed/removed); this function is the ONE
// remaining piece Go itself is responsible for getting right.
func (s *Sender) applyEphemeralVerdict(ok, relay bool, env ephemeralPayload) {
	if !ok {
		return // untrusted/unresolvable — silently dropped, no bookkeeping to keep (no seq)
	}
	if relay && s.relayEphemeral != nil {
		// Hub-room fan-out: rebuild the relay payload from the validated
		// roomId only (never forward the inbound frame verbatim) — a room
		// typing frame carries no identity beyond the roomId (Q5
		// non-attributed shape), so this IS the minimal frame.
		s.relayEphemeral(s.peer, mustJSON(ephemeralPayload{Op: "typing", RoomID: env.RoomID}))
	}
}

// ephemeralBucketSize/ephemeralRefillPerSec size the per-peer typing token
// bucket (both directions — Sender.ephemeralIn inbound, Service's outbound
// buckets in service.go): ~5 tokens, refill 1/s. ponytail: a fixed size is
// fine for v1 (Q5: no per-org typing privacy/rate knob) — promote to a
// system_config row if a customer's usage pattern ever needs a different
// ceiling.
const (
	ephemeralBucketSize   = 5
	ephemeralRefillPerSec = 1
)

// tokenBucket is a tiny in-memory rate limiter for ephemeral (typing) wire
// traffic only — no DB, no persistence, no cross-process sharing. A
// throttled caller simply has its frame dropped; typing is loss-tolerant by
// definition (Q5), so there is nothing to queue or retry.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	max    float64
	refill float64 // tokens added per second
	last   time.Time
}

func newTokenBucket(max, refillPerSec float64) *tokenBucket {
	return &tokenBucket{tokens: max, max: max, refill: refillPerSec, last: time.Now()}
}

// allow reports whether one token is available, consuming it if so.
func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.refill
	if b.tokens > b.max {
		b.tokens = b.max
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// send serializes all writes to the single TLS conn — the drain loop (KindMsg)
// and the read loop (KindAck/KindReplayReq for inbound) both write, and a
// tls.Conn tolerates concurrent Read+Write but NOT concurrent Write+Write.
func (s *Sender) send(f Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.stream.WriteFrame(f)
}
