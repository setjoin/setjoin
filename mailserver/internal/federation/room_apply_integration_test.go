// room_apply_integration_test.go — Pillar C2 Task 4, Step 4: the security
// crux proven LIVE against a real Postgres instance (the C1/A2 two-DB-roles
// integration genre — attachments_integration_test.go's "real routes/real
// reducers, not a bypassed fixture" posture, adapted here to "real
// Receiver.Handle over the real worker pool" since federation has no HTTP
// surface of its own to drive). DB-gated on DB_DSN (skip-if-absent — the
// fedConcDSN/fedConcPool helpers, fanout_concurrency_test.go, same package).
//
// Drives Receiver.Handle with REAL frames (not a direct reducer call) so the
// content-type dispatch (receiver.go's roomContentType branch into
// handleRoom) is exercised exactly as the wire would exercise it, then
// proves two things pgTAP's federation_room_inbound.pg cannot see from
// inside a single ROLLBACK transaction:
//
//  1. hub ingest -> local land -> relay-visible-in-outbox: a spoke's inbound
//     frame lands in the hub's OWN chat_messages row AND produces a fresh
//     federation_outbox row for the other member, in the SAME call.
//  2. the compliance-for-free claim, PROVEN not asserted: the hub owner
//     reads the landed message via the ORDINARY chat_messages_since reducer
//     — no federation-specific read path, nothing special-cased for a
//     federated room message once it has landed.
package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// TestRoomApplyIntegration_HubIngestLandsAndRelays drives a real inbound
// KindMsg room frame from a roster member (bravo) through Receiver.Handle
// against a real hub room (owner + bravo + charlie), and proves: bravo's
// message lands in the hub's own channel (readable by the owner via the
// ordinary chat_messages_since reducer — ordering guarantee/compliance-for-
// free), relays to charlie (the other member) with origin stamped to
// bravo, and does NOT relay back to bravo itself (the no-re-relay
// exclusion).
func TestRoomApplyIntegration_HubIngestLandsAndRelays(t *testing.T) {
	dsn := fedConcDSN(t)
	pool := fedConcPool(t, dsn)
	ctx := context.Background()

	// unique-per-run peer domains: federation_inbox_cursor/federation_peers
	// are keyed by peer_domain alone and persist across separate `go test`
	// invocations against the same shared test DB (this test does not run
	// inside a pgTAP ROLLBACK) — a fixed literal domain would silently
	// collide with a prior run's cursor state and turn peer_seq=1 into a
	// spurious 'dup' the second time this test (or the whole package) runs.
	nonce := time.Now().UnixNano()
	bravoDomain := fmt.Sprintf("bravo-integ-%d.test", nonce)
	charlieDomain := fmt.Sprintf("charlie-integ-%d.test", nonce)
	const hubUser = 98801001
	channelID, roomID := fedConcSetupRoom(t, pool, hubUser, fmt.Sprintf("apply-integ-%d", nonce), bravoDomain, charlieDomain)

	if _, err := pool.Exec(ctx, `SELECT federation_room_invite($1,$2,$3,$4)`,
		hubUser, channelID, bravoDomain, "bob@"+bravoDomain); err != nil {
		t.Fatalf("invite bravo: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT federation_room_invite($1,$2,$3,$4)`,
		hubUser, channelID, charlieDomain, "carol@"+charlieDomain); err != nil {
		t.Fatalf("invite charlie: %v", err)
	}

	// baseline: each member already holds control-op (invite/roster) outbox
	// rows from the invites above — count only 'message'-op rows below.
	var charlieMsgBaseline, bravoMsgBaseline int
	mustScan(t, pool, ctx, &charlieMsgBaseline,
		`SELECT count(*)::int FROM federation_outbox WHERE peer_domain = $1 AND payload ->> 'op' = 'message'`,
		charlieDomain)
	mustScan(t, pool, ctx, &bravoMsgBaseline,
		`SELECT count(*)::int FROM federation_outbox WHERE peer_domain = $1 AND payload ->> 'op' = 'message'`,
		bravoDomain)

	workerPool := pgxutil.WorkerPool{Pool: pool}
	flags := toggle.NewTestFlags(map[string]bool{"feature.federation": true})
	receiver := NewReceiver(workerPool, flags, bravoDomain, testLogger())

	payload, err := json.Marshal(map[string]any{
		"op":          "message",
		"roomId":      roomID,
		"fromAddr":    "bob@" + bravoDomain,
		"body":        "hi room, from a real Receiver.Handle call",
		"sentAt":      time.Now().Format(time.RFC3339),
		"clientMsgId": "integ-msg-1",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	env := msgEnvelope{PeerSeq: 1, ContentType: roomContentType, Payload: payload}
	envBytes, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	frame := Frame{Kind: KindMsg, StanzaID: "integ-s1", Payload: envBytes}

	resp, err := receiver.Handle(ctx, frame)
	if err != nil {
		t.Fatalf("Receiver.Handle: %v", err)
	}
	if resp.Kind != KindAck {
		t.Fatalf("Handle response kind = %q, want %q", resp.Kind, KindAck)
	}

	// 1. hub ingest -> local land: exactly one row, origin-stamped bravo.
	var landedCount int
	mustScan(t, pool, ctx, &landedCount,
		`SELECT count(*)::int FROM chat_messages WHERE channel_id = $1 AND federated_origin_domain = $2 AND federated_stanza_id = $3`,
		channelID, bravoDomain, "integ-msg-1")
	if landedCount != 1 {
		t.Fatalf("landed chat_messages rows = %d, want 1", landedCount)
	}

	// 2. the compliance-for-free claim, PROVEN: the hub owner reads the
	// landed message via the ORDINARY chat_messages_since reducer — no
	// federation-specific read path.
	var sinceJSON []byte
	if err := pool.QueryRow(ctx, `SELECT chat_messages_since($1,$2,0)`, hubUser, channelID).Scan(&sinceJSON); err != nil {
		t.Fatalf("chat_messages_since: %v", err)
	}
	var msgs []struct {
		Body                string `json:"body"`
		FederatedSenderAddr string `json:"federatedSenderAddr"`
	}
	if err := json.Unmarshal(sinceJSON, &msgs); err != nil {
		t.Fatalf("decode chat_messages_since: %v", err)
	}
	found := false
	for _, m := range msgs {
		if m.FederatedSenderAddr == "bob@"+bravoDomain && m.Body == "hi room, from a real Receiver.Handle call" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the hub owner's ordinary chat_messages_since read did not surface the landed message: %+v", msgs)
	}

	// 3. relay-visible-in-outbox: charlie got exactly one NEW message-op
	// outbox row, origin-stamped bravo-integ.test; bravo (the origin) got
	// none — the no-re-relay exclusion.
	var charlieMsgAfter, bravoMsgAfter int
	mustScan(t, pool, ctx, &charlieMsgAfter,
		`SELECT count(*)::int FROM federation_outbox WHERE peer_domain = $1 AND payload ->> 'op' = 'message'`,
		charlieDomain)
	mustScan(t, pool, ctx, &bravoMsgAfter,
		`SELECT count(*)::int FROM federation_outbox WHERE peer_domain = $1 AND payload ->> 'op' = 'message'`,
		bravoDomain)
	if charlieMsgAfter-charlieMsgBaseline != 1 {
		t.Fatalf("charlie's new message-op outbox rows = %d, want 1", charlieMsgAfter-charlieMsgBaseline)
	}
	if bravoMsgAfter-bravoMsgBaseline != 0 {
		t.Fatalf("bravo (the origin) received %d relayed copies of its own message, want 0", bravoMsgAfter-bravoMsgBaseline)
	}

	var relayOrigin, relayFrom string
	mustScan(t, pool, ctx, &relayOrigin,
		`SELECT payload ->> 'originDomain' FROM federation_outbox WHERE peer_domain = $1 AND payload ->> 'op' = 'message' ORDER BY peer_seq DESC LIMIT 1`,
		charlieDomain)
	mustScan(t, pool, ctx, &relayFrom,
		`SELECT payload ->> 'fromAddr' FROM federation_outbox WHERE peer_domain = $1 AND payload ->> 'op' = 'message' ORDER BY peer_seq DESC LIMIT 1`,
		charlieDomain)
	if relayOrigin != bravoDomain {
		t.Errorf("relayed originDomain = %q, want %q", relayOrigin, bravoDomain)
	}
	if relayFrom != "bob@"+bravoDomain {
		t.Errorf("relayed fromAddr = %q, want %q", relayFrom, "bob@"+bravoDomain)
	}
}

// mustScan is a small QueryRow+Scan helper to keep the test body's
// call-sites terse — every use here is a plain aggregate/text read against
// the same pool this test already owns.
func mustScan(t *testing.T, pool *pgxpool.Pool, ctx context.Context, dest any, sql string, args ...any) {
	t.Helper()
	if err := pool.QueryRow(ctx, sql, args...).Scan(dest); err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
}
