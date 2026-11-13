// ephemeral_test.go — Pillar C2 Task 6: federated typing (Q5 — "federated
// typing", never "presence"). Covers exactly the DB-INDEPENDENT pieces of
// the ephemeral seam — SendEphemeral's codec round-trip, the readLoop's
// KindEphemeral dispatch (no response frame), the token bucket's burst/
// throttle/refill, the relay-dispatch decision, and log hygiene. The
// trust/resolution matrix federation_typing_notify implements (DM/hub/spoke
// × honest/spoofed/removed) is proven in mailserver/sql/tests/
// federation_typing.pg — this package has no seam to fake a jsonb-returning
// reducer call without a live Postgres connection (pgxutil.WorkerPool wraps
// a concrete *pgxpool.Pool, not an interface — the same reason no existing
// receiver_test.go tests Receiver.Handle's dispatch either), so every test
// below either stays entirely before the DB call (toggle-off, throttled,
// malformed) or exercises the post-verdict half directly via
// applyEphemeralVerdict (the seam sender.go's HandleEphemeral was split at
// for exactly this reason).
package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// newPipeSender builds a Sender wired to one end of a net.Pipe, with the
// other end returned for the test to act as "the peer". flags controls
// whether feature.federation is enabled — HandleEphemeral's very first
// check, so a fake/nil pool is safe as long as every test that leaves it ON
// never reaches the DB call (throttled, malformed, or non-typing payloads
// all return first).
func newPipeSender(t *testing.T, enabled bool, logger *slog.Logger) (*Sender, net.Conn) {
	t.Helper()
	connA, connB := net.Pipe()
	t.Cleanup(func() { connA.Close(); connB.Close() })
	stream := &PeerStream{conn: connA, Domain: "bravo.test"}
	if logger == nil {
		logger = testLogger()
	}
	s := NewSender(pgxutil.WorkerPool{}, toggle.NewTestFlags(map[string]bool{toggle.FeatureFederation: enabled}),
		"bravo.test", stream, nil, logger)
	return s, connB
}

// TestSendEphemeralRoundTrips proves SendEphemeral writes exactly the
// KindEphemeral frame it was given, through the SAME writeMu choke point
// (s.send) the drain/ack writers use — the wire-codec half of the contract.
func TestSendEphemeralRoundTrips(t *testing.T) {
	s, peer := newPipeSender(t, true, nil)
	payload := mustJSON(ephemeralPayload{Op: "typing", RoomID: "room1@alpha.test"})

	errc := make(chan error, 1)
	go func() { errc <- s.SendEphemeral(payload) }()

	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	f, err := ReadFrame(peer)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("SendEphemeral returned an error: %v", err)
	}
	if f.Kind != KindEphemeral {
		t.Fatalf("frame kind = %q, want %q", f.Kind, KindEphemeral)
	}
	if string(f.Payload) != string(payload) {
		t.Fatalf("payload = %s, want %s", f.Payload, payload)
	}
	if f.StanzaID != "" {
		t.Fatalf("an ephemeral frame must carry NO stanza id (no seq/outbox/ack), got %q", f.StanzaID)
	}
}

// TestSendEphemeralDropsWhenWriteBusy is the MAJOR 3 mutant-killer: with
// writeMu already held (simulating the drain/read loop mid-write, or a
// concurrent relay fan-out to the same peer), SendEphemeral must TryLock and
// drop — return promptly, write nothing — rather than block waiting for the
// lock. A mutant reverting SendEphemeral to a blocking s.send would hang
// this test until it times out and fails.
func TestSendEphemeralDropsWhenWriteBusy(t *testing.T) {
	s, peer := newPipeSender(t, true, nil)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	errc := make(chan error, 1)
	go func() { errc <- s.SendEphemeral(mustJSON(ephemeralPayload{Op: "typing", RoomID: "room1@alpha.test"})) }()

	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("SendEphemeral returned an error, want nil (a lock-contended send is a silent drop, not a stream failure): %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SendEphemeral blocked waiting for writeMu instead of dropping — TryLock regression")
	}

	peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var netErr net.Error
	if _, err := ReadFrame(peer); err == nil {
		t.Fatal("SendEphemeral wrote a frame despite writeMu being held by another writer")
	} else if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected a read-deadline timeout (proving nothing was written), got: %v", err)
	}
}

// TestSendEphemeralWriteDeadline proves the write deadline is actually set
// around the wire write (not merely present in a comment): with the peer end
// never draining, the write blocks on the OS/pipe buffer, and SendEphemeral
// must still return within ephemeralWriteTimeout plus a small margin — never
// hanging past it.
func TestSendEphemeralWriteDeadline(t *testing.T) {
	s, _ := newPipeSender(t, true, nil) // peer end deliberately never read from

	// A single small ephemeral payload may fit in the pipe's internal buffer
	// (net.Pipe is unbuffered, actually — every Write blocks until a
	// matching Read, so leaving the peer unread is exactly the black-holed-
	// peer scenario this test needs).
	errc := make(chan error, 1)
	start := time.Now()
	go func() { errc <- s.SendEphemeral(mustJSON(ephemeralPayload{Op: "typing", RoomID: "room1@alpha.test"})) }()

	select {
	case err := <-errc:
		if time.Since(start) > ephemeralWriteTimeout+time.Second {
			t.Fatalf("SendEphemeral took %s, want bounded by ephemeralWriteTimeout (%s)", time.Since(start), ephemeralWriteTimeout)
		}
		if err == nil {
			t.Fatal("a deadline-exceeded write must return a (dropped) error, not nil")
		}
	case <-time.After(ephemeralWriteTimeout + 2*time.Second):
		t.Fatal("SendEphemeral did not return even after ephemeralWriteTimeout elapsed — the write deadline is not being applied")
	}
}

// TestReadLoopDispatchesEphemeralNoResponse proves the readLoop's
// `case KindEphemeral` routes to HandleEphemeral and — unlike KindMsg, which
// always writes back an ack/replay_req — writes NOTHING back on the wire.
// feature.federation is OFF here so HandleEphemeral returns at its very
// first check (no DB round trip); readLoop's dispatch/no-response contract
// is what's under test, not HandleEphemeral's own internals (covered by the
// other tests in this file).
func TestReadLoopDispatchesEphemeralNoResponse(t *testing.T) {
	s, peer := newPipeSender(t, false, nil)

	errc := make(chan error, 1)
	go func() { errc <- s.readLoop(context.Background()) }()

	if err := WriteFrame(peer, Frame{Kind: KindEphemeral,
		Payload: mustJSON(ephemeralPayload{Op: "typing", RoomID: "room1@alpha.test"})}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	peer.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var netErr net.Error
	if _, err := ReadFrame(peer); err == nil {
		t.Fatal("expected no response frame for a KindEphemeral frame, but one was written")
	} else if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected a read-deadline timeout (proving silence), got: %v", err)
	}

	peer.Close() // unblocks s.readLoop's next Read with an error, ending the goroutine
	select {
	case <-errc:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not exit after the peer connection closed")
	}
}

// TestTokenBucketBurstThenThrottleThenRefill exercises the tokenBucket type
// directly (log/wire-independent): a burst up to max is admitted, the very
// next call is throttled, and backdating `last` to simulate elapsed time
// proves the refill.
func TestTokenBucketBurstThenThrottleThenRefill(t *testing.T) {
	b := newTokenBucket(3, 1) // 3 tokens, 1/s refill
	for i := 0; i < 3; i++ {
		if !b.allow() {
			t.Fatalf("burst token %d should have been admitted", i)
		}
	}
	if b.allow() {
		t.Fatal("the 4th consecutive call should be throttled (bucket exhausted)")
	}
	// Simulate 2 seconds elapsed without sleeping the test.
	b.mu.Lock()
	b.last = b.last.Add(-2 * time.Second)
	b.mu.Unlock()
	if !b.allow() {
		t.Fatal("after 2s of simulated elapsed time, a call should be admitted again (refilled)")
	}
}

// TestApplyEphemeralVerdict_RelayDispatch proves the post-DB-call decision:
// relayEphemeral is invoked iff the verdict says ok AND relay, and — when
// invoked — carries the Sender's OWN peer domain as the origin (so the
// Service-level fan-out, service.go's relayRoomEphemeral/fanoutEphemeral,
// can exclude it — the no-re-relay rule, proven at the SQL layer in
// federation_room_fanout.sql's own pgTAP coverage).
func TestApplyEphemeralVerdict_RelayDispatch(t *testing.T) {
	cases := []struct {
		name        string
		ok, relay   bool
		wantRelayed bool
	}{
		{"ok+relay: hub-room verdict relays", true, true, true},
		{"ok, no relay: DM/spoke verdict never relays", true, false, false},
		{"not ok: untrusted/unresolvable never relays even if relay was set", false, true, false},
		{"not ok, no relay: the common drop case", false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _ := newPipeSender(t, true, nil)
			var gotOrigin string
			var gotPayload json.RawMessage
			called := false
			s.relayEphemeral = func(originPeer string, payload json.RawMessage) {
				called = true
				gotOrigin = originPeer
				gotPayload = payload
			}
			s.applyEphemeralVerdict(c.ok, c.relay, ephemeralPayload{Op: "typing", RoomID: "roomZ@alpha.test"})
			if called != c.wantRelayed {
				t.Fatalf("relayEphemeral called = %v, want %v", called, c.wantRelayed)
			}
			if !c.wantRelayed {
				return
			}
			if gotOrigin != s.peer {
				t.Fatalf("relay origin = %q, want the Sender's own peer %q (so the caller can exclude it)", gotOrigin, s.peer)
			}
			var env ephemeralPayload
			if err := json.Unmarshal(gotPayload, &env); err != nil {
				t.Fatalf("relay payload unmarshal: %v", err)
			}
			if env.RoomID != "roomZ@alpha.test" || env.Op != "typing" {
				t.Fatalf("relay payload = %+v, want a rebuilt {op:typing, roomId:roomZ@alpha.test}", env)
			}
		})
	}
}

// TestApplyEphemeralVerdict_NilRelayHookIsSafe proves a Sender with no
// relayEphemeral wired (a DM-only peer, a spoke's peer, or any Sender built
// directly in a test) never panics even when the verdict says relay:true —
// nil-safety for the common case where the hook is simply absent.
func TestApplyEphemeralVerdict_NilRelayHookIsSafe(t *testing.T) {
	s, _ := newPipeSender(t, true, nil)
	s.applyEphemeralVerdict(true, true, ephemeralPayload{Op: "typing", RoomID: "roomZ@alpha.test"}) // must not panic
}

// TestHandleEphemeral_LogHygiene captures every log line HandleEphemeral can
// emit BEFORE any DB round trip (throttled / malformed / non-typing-op) and
// asserts none of them contain the bait address/room material embedded in
// the payloads below — the Q5 ratified log-hygiene obligation: typing
// frames' payloads and addresses are NEVER logged, on any path.
func TestHandleEphemeral_LogHygiene(t *testing.T) {
	var buf bytes.Buffer
	// Task 6 review (MINOR): the throttle/malformed/non-typing-op lines this
	// test exercises were downgraded WARN->Debug (a peer-controlled-rate path
	// must not itself become a log flood) — capture Debug so the hygiene
	// assertions below still observe them.
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s, _ := newPipeSender(t, true, logger)

	const baitFrom = "bob-bait-address@bravo.test"
	const baitTo = "alice-bait-address@alpha.test"
	const baitRoom = "room-bait-secret@alpha.test"

	// Malformed (unparseable JSON) — logs a WARN, must not echo the raw bytes.
	s.HandleEphemeral(context.Background(), Frame{Payload: json.RawMessage(
		`{not json but mentions ` + baitFrom + `}`)})

	// Non-typing op, carrying bait DM addresses that must never be echoed.
	s.HandleEphemeral(context.Background(), Frame{Payload: mustJSON(ephemeralPayload{
		Op: "presence", FromAddr: baitFrom, ToAddr: baitTo,
	})})

	// Throttle: exhaust the bucket first, then one more call must throttle
	// without ever touching the DB (toggle stays ON, but the throttle check
	// runs before the DB call) — carries a bait room id.
	s.ephemeralIn = newTokenBucket(0, 0) // pre-exhausted, refills at 0/s
	s.HandleEphemeral(context.Background(), Frame{Payload: mustJSON(ephemeralPayload{
		Op: "typing", RoomID: baitRoom,
	})})

	log := buf.String()
	for _, bait := range []string{baitFrom, baitTo, baitRoom} {
		if strings.Contains(log, bait) {
			t.Fatalf("log hygiene violation: log output contains bait material %q\nfull log:\n%s", bait, log)
		}
	}
	if !strings.Contains(log, "bravo.test") {
		t.Fatalf("expected at least the bare peer domain to appear in the log (peer-only hygiene, not zero logging)\nfull log:\n%s", log)
	}
}
