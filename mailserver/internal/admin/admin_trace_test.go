package admin

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/delivery"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// TestTraceTimeline_UnknownMessageID asserts that Timeline returns 200 with
// an empty events slice and null queue for a message-id that does not exist.
// RBAC (requireAdminOrAuditor + requireMailPerm) is enforced by middleware in
// main.go, not by the handler itself — handler tests focus on shape/ordering.
func TestTraceTimeline_UnknownMessageID(t *testing.T) {
	pool := testsupport.OpenTestPool(t) // skips if DB_DSN unset
	h := NewTraceHandler(pool, pgxutil.WorkerPool{Pool: pool}, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	req := httptest.NewRequest(http.MethodGet, "/admin/trace/no-such-message-id@example.com", nil)
	// Go 1.22+ PathValue requires the pattern to be set on the request.
	req.SetPathValue("messageId", "no-such-message-id@example.com")
	rec := httptest.NewRecorder()

	h.Timeline(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Timeline: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp TimelineResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.MessageID != "no-such-message-id@example.com" {
		t.Errorf("messageId = %q, want no-such-message-id@example.com", resp.MessageID)
	}
	if len(resp.Events) != 0 {
		t.Errorf("events = %d, want 0 for unknown message", len(resp.Events))
	}
	if resp.Queue != nil {
		t.Errorf("queue = %+v, want null for unknown message", resp.Queue)
	}
	if resp.MultiRecipient {
		t.Error("multiRecipient should be false when queue is null")
	}
}

// TestTraceTimeline_EventsOrderedAsc seeds two message_trace rows for the same
// message_id in reverse chronological order and asserts Timeline returns them
// in occurred_at ASC order.
func TestTraceTimeline_EventsOrderedAsc(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewTraceHandler(pool, pgxutil.WorkerPool{Pool: pool}, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx := context.Background()

	msgID := "timeline-order-test@setjoin.test"
	t1 := time.Now().Add(-2 * time.Minute).Truncate(time.Millisecond).UTC()
	t2 := time.Now().Add(-1 * time.Minute).Truncate(time.Millisecond).UTC()

	// Insert newer row first to confirm ASC ordering is by DB, not insert order.
	_, err := pool.Exec(ctx, `
		INSERT INTO message_trace (message_id, event, from_addr, rcpt_addr, occurred_at)
		VALUES ($1, 'delivered', 'sender@example.com', 'rcpt@example.com', $2)`,
		msgID, t2)
	if err != nil {
		t.Fatalf("insert delivered: %v", err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO message_trace (message_id, event, from_addr, rcpt_addr, occurred_at)
		VALUES ($1, 'received', 'sender@example.com', 'rcpt@example.com', $2)`,
		msgID, t1)
	if err != nil {
		t.Fatalf("insert received: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM message_trace WHERE message_id = $1`, msgID)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/trace/"+msgID, nil)
	req.SetPathValue("messageId", msgID)
	rec := httptest.NewRecorder()

	h.Timeline(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Timeline: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp TimelineResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Events) != 2 {
		t.Fatalf("events = %d, want 2", len(resp.Events))
	}
	if resp.Events[0].Event != "received" {
		t.Errorf("events[0].event = %q, want received (ASC order)", resp.Events[0].Event)
	}
	if resp.Events[1].Event != "delivered" {
		t.Errorf("events[1].event = %q, want delivered (ASC order)", resp.Events[1].Event)
	}
	if resp.Queue != nil {
		t.Error("queue should be null — no outbound_queue row was seeded")
	}
	if resp.MultiRecipient {
		t.Error("multiRecipient should be false when queue is null")
	}
}

// TestTraceTimeline_WithQueueRow seeds an outbound_queue row for a message and
// asserts Timeline returns the queue payload with multiRecipient set correctly.
func TestTraceTimeline_WithQueueRow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewTraceHandler(pool, pgxutil.WorkerPool{Pool: pool}, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx := context.Background()

	msgID := "timeline-queue-test@setjoin.test"

	var queueID int64
	err := pool.QueryRow(ctx, `
		INSERT INTO outbound_queue
			(message_id, from_addr, rcpt_addrs, raw_ref, status, attempt_count, next_attempt_at, queued_at)
		VALUES ($1, 'from@example.com', ARRAY['a@example.com','b@example.com'],
		        'blob-ref-placeholder', 'pending', 0, now(), now())
		RETURNING id`,
		msgID).Scan(&queueID)
	if err != nil {
		t.Fatalf("insert outbound_queue: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM outbound_queue WHERE id = $1`, queueID)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/trace/"+msgID, nil)
	req.SetPathValue("messageId", msgID)
	rec := httptest.NewRecorder()

	h.Timeline(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Timeline: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp TimelineResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Queue == nil {
		t.Fatal("queue should be non-null when outbound_queue row exists")
	}
	if resp.Queue.Status != "pending" {
		t.Errorf("queue.status = %q, want pending", resp.Queue.Status)
	}
	if len(resp.Queue.RcptAddrs) != 2 {
		t.Errorf("queue.rcptAddrs len = %d, want 2", len(resp.Queue.RcptAddrs))
	}
	if !resp.MultiRecipient {
		t.Error("multiRecipient should be true for 2 rcptAddrs")
	}
}

// ── Phase 2b: cross-mailbox per-recipient drill-down ─────────────────────────

// randTracePK returns a random positive surrogate key so concurrent suites never
// collide on message_pk/mailbox_id (delivery_attempts has no FK on them).
func randTracePK(t *testing.T) int64 {
	t.Helper()
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	v := int64(binary.BigEndian.Uint64(b[:]) >> 1) // clear sign bit → positive
	if v == 0 {
		v = 1
	}
	return v
}

// seedTraceAttempt inserts one append-only delivery_attempts row.
func seedTraceAttempt(t *testing.T, pool *pgxpool.Pool, msgPK, mailboxID int64, rcpt, mxHost string, attemptNum, code int, text, outcome string, at time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO delivery_attempts
		   (message_pk, received_at, mailbox_id, recipient_email, mx_host, attempt_number, attempted_at, smtp_code, smtp_text, outcome, tls)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		msgPK, at, mailboxID, rcpt, mxHost, attemptNum, at, code, text, outcome, true,
	)
	if err != nil {
		t.Fatalf("seedTraceAttempt: %v", err)
	}
}

// seedQueueRow inserts one outbound_queue row carrying a message_pk link. The
// queue's own mailbox_id is left NULL (it has an FK to mailboxes and is
// display/audit only — the cross-mailbox recipients read keys on message_pk
// alone). The per-recipient mailbox_id lives on delivery_attempts (no FK), which
// is what proves the dropped mailbox filter.
func seedQueueRow(t *testing.T, pool *pgxpool.Pool, msgID string, msgPK int64, rcptAddrs []string, status string, queuedAt time.Time) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(context.Background(), `
		INSERT INTO outbound_queue
			(message_id, from_addr, rcpt_addrs, raw_ref, status, attempt_count, next_attempt_at, queued_at, message_pk)
		VALUES ($1, 'from@example.com', $2, 'blob-ref-placeholder', $3, 0, now(), $4, $5)
		RETURNING id`,
		msgID, rcptAddrs, status, queuedAt, msgPK,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seedQueueRow: %v", err)
	}
	return id
}

func runTimeline(t *testing.T, pool *pgxpool.Pool, msgID string) TimelineResponse {
	t.Helper()
	h := NewTraceHandler(pool, pgxutil.WorkerPool{Pool: pool}, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	req := httptest.NewRequest(http.MethodGet, "/admin/trace/"+msgID, nil)
	req.SetPathValue("messageId", msgID)
	rec := httptest.NewRecorder()
	h.Timeline(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Timeline: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp TimelineResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return resp
}

func recipientByEmail(recips []delivery.Recipient, email string) (delivery.Recipient, bool) {
	for _, r := range recips {
		if r.Email == email {
			return r, true
		}
	}
	return delivery.Recipient{}, false
}

// TestTraceTimeline_PerRecipientCrossMailbox proves the dropped mailbox filter:
// two delivery_attempts rows for ONE message_pk in TWO different mailbox_ids must
// both surface in the admin (cross-mailbox) timeline.
func TestTraceTimeline_PerRecipientCrossMailbox(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	requireTraceDeliveryAttempts(t, pool)
	ctx := context.Background()

	msgID := "trace-xmbox-test@setjoin.test"
	msgPK := randTracePK(t)
	mbA := randTracePK(t)
	mbB := randTracePK(t)
	at := time.Now().Add(-time.Minute).Truncate(time.Microsecond)

	qid := seedQueueRow(t, pool, msgID, msgPK, []string{"alice@a.test", "bob@b.test"}, "delivered", at)
	seedTraceAttempt(t, pool, msgPK, mbA, "alice@a.test", "mx.a.test", 1, 250, "2.0.0 OK", "accepted", at)
	seedTraceAttempt(t, pool, msgPK, mbB, "bob@b.test", "mx.b.test", 1, 550, "5.1.1 nope", "rejected", at)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM delivery_attempts WHERE message_pk = $1`, msgPK)
		_, _ = pool.Exec(ctx, `DELETE FROM outbound_queue WHERE id = $1`, qid)
	})

	resp := runTimeline(t, pool, msgID)

	if len(resp.Recipients) != 2 {
		t.Fatalf("recipients = %d, want 2 (cross-mailbox — NO mailbox filter): %+v", len(resp.Recipients), resp.Recipients)
	}
	alice, ok := recipientByEmail(resp.Recipients, "alice@a.test")
	if !ok {
		t.Fatalf("alice missing from recipients: %+v", resp.Recipients)
	}
	if alice.Status != "delivered" {
		t.Errorf("alice status = %q, want delivered", alice.Status)
	}
	bob, ok := recipientByEmail(resp.Recipients, "bob@b.test")
	if !ok {
		t.Fatalf("bob missing from recipients: %+v", resp.Recipients)
	}
	if bob.Status != "bounced" {
		t.Errorf("bob status = %q, want bounced", bob.Status)
	}
	if bob.LastSmtpCode == nil || *bob.LastSmtpCode != 550 {
		t.Errorf("bob lastSmtpCode = %v, want 550", bob.LastSmtpCode)
	}
	if resp.OverallStatus != "delivered" {
		t.Errorf("overallStatus = %q, want delivered (server-mapped)", resp.OverallStatus)
	}
	if resp.DetailExpired {
		t.Error("detailExpired should be false when attempts are present")
	}
}

// TestTraceTimeline_PerRecipientOverCount proves the DISTINCT-ON over-count guard:
// two append-only attempts for ONE recipient → exactly ONE recipient (latest
// status), with the full attempt history preserved.
func TestTraceTimeline_PerRecipientOverCount(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	requireTraceDeliveryAttempts(t, pool)
	ctx := context.Background()

	msgID := "trace-overcount-test@setjoin.test"
	msgPK := randTracePK(t)
	mb := randTracePK(t)
	at := time.Now().Add(-time.Minute).Truncate(time.Microsecond)

	qid := seedQueueRow(t, pool, msgID, msgPK, []string{"carol@c.test"}, "delivered", at)
	seedTraceAttempt(t, pool, msgPK, mb, "carol@c.test", "mx.c.test", 1, 451, "4.7.0 later", "deferred", at)
	seedTraceAttempt(t, pool, msgPK, mb, "carol@c.test", "mx.c.test", 2, 250, "2.0.0 OK", "accepted", at.Add(time.Second))
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM delivery_attempts WHERE message_pk = $1`, msgPK)
		_, _ = pool.Exec(ctx, `DELETE FROM outbound_queue WHERE id = $1`, qid)
	})

	resp := runTimeline(t, pool, msgID)

	if len(resp.Recipients) != 1 {
		t.Fatalf("recipients = %d, want 1 (over-count collapsed): %+v", len(resp.Recipients), resp.Recipients)
	}
	carol := resp.Recipients[0]
	if carol.Status != "delivered" {
		t.Errorf("carol status = %q, want delivered (latest attempt)", carol.Status)
	}
	if len(carol.Attempts) != 2 {
		t.Errorf("carol attempts = %d, want 2 (full history)", len(carol.Attempts))
	}
}

// TestTraceTimeline_RetentionSkew proves the empty+note path: a terminal queue
// row whose per-recipient attempts were pruned → empty recipients + DetailExpired,
// never a broken panel.
func TestTraceTimeline_RetentionSkew(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	requireTraceDeliveryAttempts(t, pool)
	ctx := context.Background()

	msgID := "trace-retention-test@setjoin.test"
	msgPK := randTracePK(t)
	at := time.Now().Add(-time.Minute).Truncate(time.Microsecond)

	qid := seedQueueRow(t, pool, msgID, msgPK, []string{"dan@d.test", "erin@e.test"}, "delivered", at)
	// NO delivery_attempts rows seeded — they were pruned.
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM outbound_queue WHERE id = $1`, qid)
	})

	resp := runTimeline(t, pool, msgID)

	if len(resp.Recipients) != 0 {
		t.Fatalf("recipients = %d, want 0 (attempts pruned): %+v", len(resp.Recipients), resp.Recipients)
	}
	if !resp.DetailExpired {
		t.Error("detailExpired should be true when terminal queue + zero attempts")
	}
	if resp.OverallStatus != "delivered" {
		t.Errorf("overallStatus = %q, want delivered", resp.OverallStatus)
	}
}

// TestTraceTimeline_LatestQueueRowByQueuedAt proves the non-unique-message_id
// resolution: two outbound_queue rows share a message_id but have different
// message_pk/queued_at → recipients come from the LATEST queued_at row.
func TestTraceTimeline_LatestQueueRowByQueuedAt(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	requireTraceDeliveryAttempts(t, pool)
	ctx := context.Background()

	msgID := "trace-latest-queue-test@setjoin.test"
	pkOld := randTracePK(t)
	pkNew := randTracePK(t)
	mb := randTracePK(t)
	older := time.Now().Add(-10 * time.Minute).Truncate(time.Microsecond)
	newer := time.Now().Add(-1 * time.Minute).Truncate(time.Microsecond)

	// Older send (different recipient) + newer send — same message_id.
	qidOld := seedQueueRow(t, pool, msgID, pkOld, []string{"stale@old.test"}, "delivered", older)
	qidNew := seedQueueRow(t, pool, msgID, pkNew, []string{"fresh@new.test"}, "delivered", newer)
	seedTraceAttempt(t, pool, pkOld, mb, "stale@old.test", "mx.old.test", 1, 250, "2.0.0 OK", "accepted", older)
	seedTraceAttempt(t, pool, pkNew, mb, "fresh@new.test", "mx.new.test", 1, 250, "2.0.0 OK", "accepted", newer)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM delivery_attempts WHERE message_pk = ANY($1)`, []int64{pkOld, pkNew})
		_, _ = pool.Exec(ctx, `DELETE FROM outbound_queue WHERE id = ANY($1)`, []int64{qidOld, qidNew})
	})

	resp := runTimeline(t, pool, msgID)

	if len(resp.Recipients) != 1 {
		t.Fatalf("recipients = %d, want 1 (from latest queued_at): %+v", len(resp.Recipients), resp.Recipients)
	}
	if resp.Recipients[0].Email != "fresh@new.test" {
		t.Errorf("recipient = %q, want fresh@new.test (latest queued_at row's message_pk)", resp.Recipients[0].Email)
	}
}

// requireTraceDeliveryAttempts skips the test unless V017's delivery_attempts
// table is present in the test DB.
func requireTraceDeliveryAttempts(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		   WHERE table_schema = 'public' AND table_name = 'delivery_attempts')`,
	).Scan(&exists); err != nil || !exists {
		t.Skip("delivery_attempts table (V017) not present")
	}
}
