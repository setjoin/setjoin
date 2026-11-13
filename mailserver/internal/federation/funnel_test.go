// funnel_test.go — Pillar C2 Task 8 Step 5: THE FUNNEL. Pins Receiver.Handle's
// generic fallback (any content_type outside the known product set —
// chatContentType/roomContentType/advisoryContentType, all dispatched before
// this fallback is ever reached) against real Postgres: an unknown content
// type is consumed exactly once, acked, and its payload is REDACTED to a
// bounded, content-free envelope before federation_apply_inbound ever sees
// it — never stored verbatim (the compliance concern this step closes).
// DB-gated on DB_DSN (skip-if-absent — the fanout_concurrency_test.go/
// room_apply_integration_test.go genre, same package).
package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// TestReceiverHandle_UnknownContentTypeFunnel drives a real inbound KindMsg
// frame whose content_type is outside the known product set through the
// real worker pool: the frame must still ack (the sender must never be told
// to resend it), the seq must still consume (federation_inbox_cursor
// advances — the poison-discipline law: dropping WITHOUT consuming would
// manufacture a BZ202 gap for the next legitimate frame), and NOTHING of the
// original payload's content may survive in federation_inbox — only the
// funnel's bounded {redacted,contentType,bytes} envelope.
func TestReceiverHandle_UnknownContentTypeFunnel(t *testing.T) {
	dsn := fedConcDSN(t)
	pool := fedConcPool(t, dsn)
	ctx := context.Background()

	// unique-per-run peer domain — federation_inbox_cursor/federation_inbox
	// are keyed by peer_domain alone and persist across separate `go test`
	// invocations against the same shared test DB (this test does not run
	// inside a pgTAP ROLLBACK).
	peer := fmt.Sprintf("funnel-integ-%d.test", time.Now().UnixNano())

	workerPool := pgxutil.WorkerPool{Pool: pool}
	flags := toggle.NewTestFlags(map[string]bool{"feature.federation": true})
	receiver := NewReceiver(workerPool, flags, peer, testLogger())

	const secretContent = "top secret body that must never land in federation_inbox"
	payload, err := json.Marshal(map[string]any{"secret": secretContent, "n": 42})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	env := msgEnvelope{PeerSeq: 1, ContentType: "application/x-unrecognized-test-type", Payload: payload}
	envBytes, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	frame := Frame{Kind: KindMsg, StanzaID: "funnel-s1", Payload: envBytes}

	resp, err := receiver.Handle(ctx, frame)
	if err != nil {
		t.Fatalf("Receiver.Handle: %v", err)
	}
	if resp.Kind != KindAck {
		t.Fatalf("Handle response kind = %q, want %q (unknown content_type must still ack)", resp.Kind, KindAck)
	}

	var storedPayload []byte
	if err := pool.QueryRow(ctx,
		`SELECT payload FROM federation_inbox WHERE peer_domain = $1 AND peer_seq = 1`, peer,
	).Scan(&storedPayload); err != nil {
		t.Fatalf("read federation_inbox: %v", err)
	}

	var stored redactedEnvelope
	if err := json.Unmarshal(storedPayload, &stored); err != nil {
		t.Fatalf("decode stored payload: %v", err)
	}
	if !stored.Redacted {
		t.Errorf("stored payload redacted = false, want true")
	}
	if stored.ContentType != "application/x-unrecognized-test-type" {
		t.Errorf("stored payload contentType = %q, want %q", stored.ContentType, "application/x-unrecognized-test-type")
	}
	if stored.Bytes != len(payload) {
		t.Errorf("stored payload bytes = %d, want %d (len of the original payload)", stored.Bytes, len(payload))
	}

	// exactly 3 keys — a mutant redaction that happened to decode correctly
	// but carried an extra leaked key would still pass the struct-decode
	// assertions above; this catches that.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(storedPayload, &raw); err != nil {
		t.Fatalf("decode stored payload as map: %v", err)
	}
	if len(raw) != 3 {
		t.Errorf("stored payload has %d keys, want exactly 3 (redacted, contentType, bytes): %s", len(raw), storedPayload)
	}

	// belt: a plain substring search on the stored bytes catches the actual
	// secret leaking anywhere, independent of the shape assertions above.
	if containsSecret(storedPayload, secretContent) {
		t.Fatalf("stored federation_inbox payload leaked the original secret content: %s", storedPayload)
	}

	var lastApplied int64
	if err := pool.QueryRow(ctx,
		`SELECT last_applied_seq FROM federation_inbox_cursor WHERE peer_domain = $1`, peer,
	).Scan(&lastApplied); err != nil {
		t.Fatalf("read federation_inbox_cursor: %v", err)
	}
	if lastApplied != 1 {
		t.Fatalf("last_applied_seq = %d, want 1 (the unknown-type frame must still consume its seq)", lastApplied)
	}
}

// TestReceiverHandle_KnownContentTypesUnaffectedByFunnel proves the funnel
// (Task 8 Step 5) changed NOTHING about the known-content-type dispatch
// paths: a chatContentType frame still lands federation_apply_chat's OWN
// envelope-only projection ({fromAddr,toAddr,clientMsgId}), never the
// funnel's {redacted,contentType,bytes} shape — the two appliers remain
// deliberately un-unified (receiver.go's own dispatch-order comment).
func TestReceiverHandle_KnownContentTypesUnaffectedByFunnel(t *testing.T) {
	dsn := fedConcDSN(t)
	pool := fedConcPool(t, dsn)
	ctx := context.Background()

	peer := fmt.Sprintf("funnel-chat-integ-%d.test", time.Now().UnixNano())

	workerPool := pgxutil.WorkerPool{Pool: pool}
	flags := toggle.NewTestFlags(map[string]bool{"feature.federation": true})
	receiver := NewReceiver(workerPool, flags, peer, testLogger())

	// an address that will not resolve locally (this test has no mailbox
	// fixture) is fine — federation_apply_chat still writes its OWN
	// envelope-only federation_inbox row during Step 1 bookkeeping
	// regardless of the later poison verdict; that row's SHAPE is what this
	// test pins, not the apply outcome.
	payload, err := json.Marshal(map[string]any{
		"fromAddr": "bob@" + peer, "toAddr": "nobody@nowhere.invalid",
		"body": "hi", "clientMsgId": "funnel-chat-1",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	env := msgEnvelope{PeerSeq: 1, ContentType: chatContentType, Payload: payload}
	envBytes, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	frame := Frame{Kind: KindMsg, StanzaID: "funnel-chat-s1", Payload: envBytes}

	if _, err := receiver.Handle(ctx, frame); err != nil {
		t.Fatalf("Receiver.Handle: %v", err)
	}

	var storedPayload []byte
	if err := pool.QueryRow(ctx,
		`SELECT payload FROM federation_inbox WHERE peer_domain = $1 AND peer_seq = 1`, peer,
	).Scan(&storedPayload); err != nil {
		t.Fatalf("read federation_inbox: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(storedPayload, &raw); err != nil {
		t.Fatalf("decode stored payload: %v", err)
	}
	if _, ok := raw["redacted"]; ok {
		t.Fatalf("a KNOWN content_type (chat) landed the FUNNEL's redacted shape — the two appliers must stay un-unified: %s", storedPayload)
	}
	if _, ok := raw["fromAddr"]; !ok {
		t.Fatalf("chat content_type's own envelope-only projection is missing fromAddr — unexpected shape: %s", storedPayload)
	}
}

// containsSecret is a plain substring check — belt for the structural
// assertions above (exactly 3 keys, correct shape): even if a mutant
// redaction produced a same-shaped-but-wrong-content object, this still
// catches the actual secret leaking anywhere in the stored bytes.
func containsSecret(stored []byte, secret string) bool {
	return bytes.Contains(stored, []byte(secret))
}
