// sender_ack_replay_bounds_test.go — er5-s12 closure tests for the two
// sender.go occurrences:
//
//   - occ_642310eee5108ebbcdd9780a (integrity.federation-future-ack): a
//     forged future ack must halt the peer BEFORE any federation_ack call —
//     the durable last_acked_seq must never be poisoned past unsent rows.
//   - occ_820410e337d38675e8ff2426 (resource-exhaustion
//     .federation-replay-window): replay requests are bounded three ways —
//     no future resume points (cursor-poisoning forge), no rewinds behind the
//     durable ack point (in-flight window stays capped), and a per-peer cap
//     on honored rewinds (retained-outbox amplification bound).
//
// The DB-free tests use the ephemeral_test.go newPipeSender pattern: the
// Sender carries a zero pgxutil.WorkerPool (nil pool — any DB round trip
// panics), so a guard regression cannot pass silently: reaching the database
// side of applyAck/applyReplayReq crashes the test. The one VALID-ack test
// (the guard must let honest seqs through) is DB-gated on DB_DSN, exactly
// like room_apply_integration_test.go / fanout_concurrency_test.go.
package federation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/shared/pgxutil"
)

// TestReadLoopHaltsOnForgedFutureAck proves the readLoop halts the stream on
// an ack naming a seq beyond the send cursor, and that the forged seq never
// reaches the database (the nil pool would panic if it did).
func TestReadLoopHaltsOnForgedFutureAck(t *testing.T) {
	s, peer := newPipeSender(t, true, nil)
	s.mu.Lock()
	s.sentCursor, s.lastAcked = 5, 5 // mid-stream: five frames written and acked
	s.mu.Unlock()

	errc := make(chan error, 1)
	go func() { errc <- s.readLoop(context.Background()) }()

	if err := WriteFrame(peer, Frame{Kind: KindAck, Payload: mustJSON(seqEnvelope{PeerSeq: 6})}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "forged ack") {
			t.Fatalf("readLoop error = %v, want a forged-ack halt", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop accepted a forged future ack (stream did not halt)")
	}
	s.mu.Lock()
	acked := s.lastAcked
	s.mu.Unlock()
	if acked != 5 {
		t.Fatalf("lastAcked = %d after a forged ack, want the pre-forgery 5 (durable cursor must not advance)", acked)
	}
}

// TestReadLoopHaltsOnForgedFutureReplay is the replay-side twin: a replay_req
// naming a resume point beyond the send cursor would JUMP the cursor forward
// and silently skip unsent outbox rows — it must halt the stream instead.
func TestReadLoopHaltsOnForgedFutureReplay(t *testing.T) {
	s, peer := newPipeSender(t, true, nil)
	s.mu.Lock()
	s.sentCursor, s.lastAcked = 5, 5
	s.mu.Unlock()

	errc := make(chan error, 1)
	go func() { errc <- s.readLoop(context.Background()) }()

	if err := WriteFrame(peer, Frame{Kind: KindReplayReq, Payload: mustJSON(seqEnvelope{PeerSeq: 50})}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "forged replay_req") {
			t.Fatalf("readLoop error = %v, want a forged-replay_req halt", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop accepted a forged future replay_req (stream did not halt)")
	}
	s.mu.Lock()
	sent := s.sentCursor
	s.mu.Unlock()
	if sent != 5 {
		t.Fatalf("sentCursor = %d after a forged replay_req, want the pre-forgery 5 (unsent rows must not be skipped)", sent)
	}
}

// TestApplyReplayReqClampsRewindToDurableAck proves an honest replay that
// names a point behind the peer's own durable ack is clamped to lastAcked —
// it never rewinds the cursor below the acked floor, which would drive
// inflight negative and widen the drain window past the configured cap.
func TestApplyReplayReqClampsRewindToDurableAck(t *testing.T) {
	s, _ := newPipeSender(t, true, nil)
	s.mu.Lock()
	s.sentCursor, s.lastAcked = 100, 90
	s.mu.Unlock()

	rewound, err := s.applyReplayReq(10) // resume-from 10 is far behind the acked 90
	if err != nil {
		t.Fatalf("applyReplayReq: %v", err)
	}
	if !rewound {
		t.Fatal("applyReplayReq reported no rewind for an honest behind-ack request")
	}
	s.mu.Lock()
	sent := s.sentCursor
	s.mu.Unlock()
	if sent != 90 {
		t.Fatalf("sentCursor = %d, want the clamp floor lastAcked=90", sent)
	}
}

// TestApplyReplayReqHonestMidStreamRewind proves the non-clamped honest case:
// a replay to a point between lastAcked and sentCursor rewinds exactly there.
func TestApplyReplayReqHonestMidStreamRewind(t *testing.T) {
	s, _ := newPipeSender(t, true, nil)
	s.mu.Lock()
	s.sentCursor, s.lastAcked = 100, 20
	s.mu.Unlock()

	rewound, err := s.applyReplayReq(41) // resume-from 40, behind sent, ahead of acked
	if err != nil {
		t.Fatalf("applyReplayReq: %v", err)
	}
	if !rewound {
		t.Fatal("applyReplayReq reported no rewind for an honest mid-stream request")
	}
	s.mu.Lock()
	sent := s.sentCursor
	s.mu.Unlock()
	if sent != 40 {
		t.Fatalf("sentCursor = %d, want 40 (peerSeq-1)", sent)
	}
}

// TestApplyReplayReqRateCapped proves the amplification bound: beyond the
// replay bucket's burst, further VALID replay requests are dropped (no rewind,
// no error — loss-tolerant, the typing-throttle contract), leaving the send
// cursor untouched.
func TestApplyReplayReqRateCapped(t *testing.T) {
	s, _ := newPipeSender(t, true, nil)
	s.mu.Lock()
	s.sentCursor, s.lastAcked = 100, 20
	s.mu.Unlock()
	s.replayIn = newTokenBucket(0, 0) // pre-exhausted, refills at 0/s

	rewound, err := s.applyReplayReq(41)
	if err != nil {
		t.Fatalf("a throttled replay must be a loss-tolerant drop, not an error: %v", err)
	}
	if rewound {
		t.Fatal("a throttled replay rewound the send cursor — the rate cap is not binding")
	}
	s.mu.Lock()
	sent := s.sentCursor
	s.mu.Unlock()
	if sent != 100 {
		t.Fatalf("sentCursor = %d after a throttled replay, want it untouched at 100", sent)
	}
}

// TestApplyReplayReqBoundaryAtSentSeq proves the exact boundary: replaying
// from the highest sent seq is honest (resume = sent-1 rewinds one), while
// resume-from sent+1 (peerSeq = sent+2) is a forge.
func TestApplyReplayReqBoundaryAtSentSeq(t *testing.T) {
	s, _ := newPipeSender(t, true, nil)
	s.mu.Lock()
	s.sentCursor, s.lastAcked = 10, 0
	s.mu.Unlock()

	rewound, err := s.applyReplayReq(11) // resume-from 10 == sentCursor: a no-op, nothing unsent to resend
	if err != nil {
		t.Fatalf("applyReplayReq(11): %v", err)
	}
	s.mu.Lock()
	sent := s.sentCursor
	s.mu.Unlock()
	if rewound {
		t.Fatalf("resume-from 10 with sentCursor 10 must be a no-op (nothing to resend), got rewind")
	}
	if sent != 10 {
		t.Fatalf("sentCursor moved to %d on a resume-at-boundary request", sent)
	}

	rewound, err = s.applyReplayReq(10) // resume-from 9 < sent — the honest one-frame rewind
	if err != nil {
		t.Fatalf("applyReplayReq(10): %v", err)
	}
	if !rewound {
		t.Fatal("resume-from 9 must rewind the cursor to 9")
	}
	s.mu.Lock()
	sent = s.sentCursor
	s.mu.Unlock()
	if sent != 9 {
		t.Fatalf("sentCursor = %d, want 9", sent)
	}

	if _, err := s.applyReplayReq(12); err == nil || !strings.Contains(err.Error(), "forged replay_req") {
		t.Fatalf("applyReplayReq(12) = %v, want a forged-replay_req halt (resume 11 > sent 10)", err)
	}
}

// TestReadLoopHonoredReplayWakesDrain proves the readLoop-side honored-rewind
// half: a VALID replay request rewinds the cursor and wakes the drain loop
// (Wake is the coalescing signal — it must fire on a real rewind, never on a
// throttled drop), after which the loop blocks on Read until the peer closes.
func TestReadLoopHonoredReplayWakesDrain(t *testing.T) {
	s, peer := newPipeSender(t, true, nil)
	s.mu.Lock()
	s.sentCursor, s.lastAcked = 5, 0
	s.mu.Unlock()

	errc := make(chan error, 1)
	go func() { errc <- s.readLoop(context.Background()) }()

	if err := WriteFrame(peer, Frame{Kind: KindReplayReq, Payload: mustJSON(seqEnvelope{PeerSeq: 3})}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	// The rewind is synchronous inside readLoop; poll for it, then close the
	// peer so readLoop's next Read unblocks and the goroutine exits.
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		sent := s.sentCursor
		s.mu.Unlock()
		if sent == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sentCursor = %d after an honored replay, want 2 (peerSeq-1)", sent)
		}
		time.Sleep(5 * time.Millisecond)
	}
	peer.Close()
	select {
	case <-errc:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not exit after the peer connection closed")
	}
}

// TestApplyReplayReqNilBucketLazyInit covers the lazily-initialized replay
// bucket seam (a Sender built without NewSender must not nil-panic — the
// same nil-safety contract HandleEphemeral carries for its own bucket).
func TestApplyReplayReqNilBucketLazyInit(t *testing.T) {
	s, _ := newPipeSender(t, true, nil)
	s.replayIn = nil // simulate a Sender built by struct literal, not NewSender

	rewound, err := s.applyReplayReq(1) // sentCursor 0: no rewind, but the bucket must initialize
	if err != nil {
		t.Fatalf("applyReplayReq on a nil-bucket sender: %v", err)
	}
	if rewound {
		t.Fatal("nothing unsent exists (sentCursor 0), rewind must not report movement")
	}
	if s.replayIn == nil {
		t.Fatal("replayIn was not lazily initialized")
	}
}

// TestApplyAckExecErrorWrapped (DB-gated) covers the federation_ack failure
// wrap: with a closed pool, the honest-ack guard passes (proving the guard
// sits BEFORE the DB call) and the reducer error surfaces wrapped with the
// seq and peer — the readLoop halts-with-context contract.
func TestApplyAckExecErrorWrapped(t *testing.T) {
	dsn := fedConcDSN(t)
	pool := fedConcPool(t, dsn)
	s, _ := newPipeSender(t, true, nil)
	s.pool = pgxutil.WorkerPool{Pool: pool}
	s.mu.Lock()
	s.sentCursor, s.lastAcked = 3, 0
	s.mu.Unlock()

	pool.Close() // force the Exec error deterministically
	err := s.applyAck(context.Background(), 2)
	if err == nil || !strings.Contains(err.Error(), "ack 2 for") {
		t.Fatalf("applyAck after pool close = %v, want the wrapped 'ack 2 for' error", err)
	}
}

// TestApplyAckValidSeqPassesGuardAndAdvances is the DB-gated positive leg:
// an honest ack (within the send cursor) passes the er5-s12 guard, reaches
// the real federation_ack reducer, and advances the in-memory ack mirror.
// The er6 residual belt-and-braces guard in federation_ack.sql refuses any
// ack above the peer's enqueued window (GREATEST(last_seq,
// max(outbox.peer_seq))), so the test seeds the durable rail at sentCursor 3
// — an honest sender always has those rows behind its cursor; restoring the
// pre-test rail value keeps this fixture invisible to the other DB-gated
// federation tests sharing the database.
func TestApplyAckValidSeqPassesGuardAndAdvances(t *testing.T) {
	dsn := fedConcDSN(t)
	pool := fedConcPool(t, dsn)
	s, _ := newPipeSender(t, true, nil)
	s.pool = pgxutil.WorkerPool{Pool: pool}
	s.mu.Lock()
	s.sentCursor, s.lastAcked = 3, 0
	s.mu.Unlock()

	ctx := context.Background()
	var priorSeq int64
	var existed bool
	if err := pool.QueryRow(ctx,
		`SELECT last_seq, true FROM federation_peers WHERE peer_domain = $1`,
		"bravo.test").Scan(&priorSeq, &existed); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("read federation_peers fixture: %v", err)
		}
	} else if priorSeq < 3 {
		t.Cleanup(func() {
			_, _ = pool.Exec(ctx,
				`UPDATE federation_peers SET last_seq = $2 WHERE peer_domain = $1`,
				"bravo.test", priorSeq) //nolint:errcheck
		})
	}
	if !existed {
		t.Cleanup(func() {
			_, _ = pool.Exec(ctx,
				`DELETE FROM federation_peers WHERE peer_domain = $1`,
				"bravo.test") //nolint:errcheck
		})
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO federation_peers (peer_domain, last_seq) VALUES ($1, 3)
		 ON CONFLICT (peer_domain) DO UPDATE SET last_seq = GREATEST(federation_peers.last_seq, 3)`,
		"bravo.test"); err != nil {
		t.Fatalf("seed federation_peers rail: %v", err)
	}

	if err := s.applyAck(context.Background(), 2); err != nil {
		t.Fatalf("applyAck(2) with sentCursor 3: %v", err)
	}
	s.mu.Lock()
	acked := s.lastAcked
	s.mu.Unlock()
	if acked != 2 {
		t.Fatalf("lastAcked = %d after an honest ack of 2, want 2", acked)
	}
	// The stale/late duplicate ack is a no-op (the pre-s12 idempotence contract).
	if err := s.applyAck(context.Background(), 2); err != nil {
		t.Fatalf("duplicate applyAck(2): %v", err)
	}
	s.mu.Lock()
	acked = s.lastAcked
	s.mu.Unlock()
	if acked != 2 {
		t.Fatalf("lastAcked = %d after a duplicate ack, want still 2", acked)
	}
	// And the forged seq still halts even with a live pool wired.
	if err := s.applyAck(context.Background(), 4); err == nil || !strings.Contains(err.Error(), "forged ack") {
		t.Fatalf("applyAck(4) with sentCursor 3 = %v, want a forged-ack halt", err)
	}
}
