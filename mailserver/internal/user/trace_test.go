package user

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/received"
	"setjoin.com/shared/pgxutil"
)

func testIdentity() received.Identity {
	return received.Identity{Hostnames: map[string]bool{"mailserver": true}}
}

func TestTraceHandler_NotOwnedIs404(t *testing.T) {
	pool := testPool(t)
	h := NewTraceHandler(pgxutil.WorkerPool{Pool: pool}, "http://127.0.0.1/jmap/download", testIdentity(), testLogger())
	req := httptest.NewRequest("GET", "/messages/999999/trace", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1}))
	req.SetPathValue("emailId", "999999")
	w := httptest.NewRecorder()
	h.Trace(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404 for non-owned, got %d", w.Code)
	}
}

// markSent ensures the mailbox has the Sent system tag and tags the message with
// it (Sent location), so direction detection reads the message as outbound.
func markSent(t *testing.T, pool *pgxpool.Pool, msgID, mailboxID int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `SELECT create_system_tags($1)`, mailboxID); err != nil {
		t.Fatalf("create_system_tags: %v", err)
	}
	tagMessageLocation(t, pool, msgID, mailboxID, "Sent")
	// Verify the tag actually attached (create_system_tags must have produced a
	// Sent location/system tag for this mailbox).
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM message_tags mt JOIN tags t ON t.id = mt.tag_id
		  WHERE mt.message_id = $1 AND t.mailbox_id = $2
		    AND t.name = 'Sent' AND t.tag_type = 'system' AND t.exclusive_group = 'location'`,
		msgID, mailboxID,
	).Scan(&n); err != nil {
		t.Fatalf("verify Sent tag: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected message %d to carry the Sent system tag, got %d", msgID, n)
	}
}

// insertDeliveryAttempt writes one append-only delivery_attempts row.
func insertDeliveryAttempt(t *testing.T, pool *pgxpool.Pool, msgPK int64, receivedAt time.Time, mailboxID int64, rcpt, mxHost string, attemptNum int, code int, text, outcome string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO delivery_attempts
		   (message_pk, received_at, mailbox_id, recipient_email, mx_host, attempt_number, smtp_code, smtp_text, outcome, tls)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		msgPK, receivedAt, mailboxID, rcpt, mxHost, attemptNum, code, text, outcome, true,
	)
	if err != nil {
		t.Fatalf("insertDeliveryAttempt: %v", err)
	}
}

// insertOutboundQueue writes an outbound_queue row linking message_pk + mailbox.
func insertOutboundQueue(t *testing.T, pool *pgxpool.Pool, msgPK, mailboxID int64, messageID, status string, rcpts []string, nextAttempt *time.Time, deliveredAt *time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO outbound_queue
		   (message_id, from_addr, rcpt_addrs, raw_ref, status, mailbox_id, message_pk, next_attempt_at, delivered_at)
		 VALUES ($1,'sender@setjoin.test',$2,'',$3,$4,$5,COALESCE($6, now()),$7)`,
		messageID, rcpts, status, mailboxID, msgPK, nextAttempt, deliveredAt,
	)
	if err != nil {
		t.Fatalf("insertOutboundQueue: %v", err)
	}
}

// outboundFixture creates an owned Sent message (tagged Sent) and returns its
// surrogate pk, received_at, mailbox, user, and email.
func outboundFixture(t *testing.T, pool *pgxpool.Pool) (msgPK int64, receivedAt time.Time, mailboxID, userID int64, messageID string) {
	t.Helper()
	userID = createTestUser(t, pool)
	mailboxID = ensureTestMailbox(t, pool, userID)
	messageID = "out-" + randomSuffix(t) + "@setjoin.test"
	receivedAt = time.Now().Add(-3 * time.Minute).Truncate(time.Microsecond)
	msgPK = insertTestMessage(t, pool, mailboxID, messageID, "sender@setjoin.test", receivedAt)
	markSent(t, pool, msgPK, mailboxID)
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM delivery_attempts WHERE message_pk = $1`, msgPK)
		pool.Exec(context.Background(), `DELETE FROM outbound_queue WHERE message_pk = $1`, msgPK)
	})
	return msgPK, receivedAt, mailboxID, userID, messageID
}

// callTrace invokes the handler for emailID as userID and decodes the JSON body.
func callTrace(t *testing.T, pool *pgxpool.Pool, emailID, userID int64) (int, map[string]any) {
	t.Helper()
	h := NewTraceHandler(pgxutil.WorkerPool{Pool: pool}, "http://127.0.0.1/jmap/download", testIdentity(), testLogger())
	req := httptest.NewRequest("GET", "/messages/0/trace", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	req.SetPathValue("emailId", strconv.FormatInt(emailID, 10))
	w := httptest.NewRecorder()
	h.Trace(w, req)
	var body map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body: %v (raw=%s)", err, w.Body.String())
		}
	}
	return w.Code, body
}

func TestTraceHandler_Outbound(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	msgPK, ra, mb, uid, mid := outboundFixture(t, pool)

	// Two recipients: one accepted, one rejected — different recipient_email.
	insertDeliveryAttempt(t, pool, msgPK, ra, mb, "alice@a.test", "mx.a.test", 1, 250, "2.0.0 OK", "accepted")
	insertDeliveryAttempt(t, pool, msgPK, ra, mb, "bob@b.test", "mx.b.test", 1, 550, "5.1.1 No such user", "rejected")
	insertOutboundQueue(t, pool, msgPK, mb, mid, "bounced", []string{"alice@a.test", "bob@b.test"}, nil, nil)

	code, body := callTrace(t, pool, msgPK, uid)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	if body["direction"] != "outbound" {
		t.Fatalf("want direction=outbound, got %v", body["direction"])
	}
	if body["overallStatus"] == nil || body["overallStatus"] == "" {
		t.Fatalf("want non-empty overallStatus, got %v", body["overallStatus"])
	}
	recips := recipientsOf(t, body)
	if len(recips) != 2 {
		t.Fatalf("want 2 recipients, got %d: %v", len(recips), recips)
	}
	byEmail := map[string]map[string]any{}
	for _, r := range recips {
		byEmail[r["email"].(string)] = r
	}
	alice := byEmail["alice@a.test"]
	bob := byEmail["bob@b.test"]
	if alice == nil || bob == nil {
		t.Fatalf("missing a recipient: %v", byEmail)
	}
	if alice["status"] != "delivered" {
		t.Fatalf("alice status: want delivered, got %v", alice["status"])
	}
	if bob["status"] != "bounced" {
		t.Fatalf("bob status: want bounced, got %v", bob["status"])
	}
	if alice["mxHost"] != "mx.a.test" {
		t.Fatalf("alice mxHost: want mx.a.test, got %v", alice["mxHost"])
	}
	if jsonNum(bob["lastSmtpCode"]) != 550 {
		t.Fatalf("bob lastSmtpCode: want 550, got %v", bob["lastSmtpCode"])
	}
	// auth + raw must be present so the frontend tabs don't break.
	if _, ok := body["auth"]; !ok {
		t.Fatalf("outbound trace missing auth key")
	}
	if _, ok := body["raw"]; !ok {
		t.Fatalf("outbound trace missing raw key")
	}
}

func TestTraceHandler_OutboundDistinctOnLatestAttempt(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	msgPK, ra, mb, uid, mid := outboundFixture(t, pool)

	// One recipient, two append-only attempts: first deferred, then accepted.
	// The DISTINCT-ON read must collapse to ONE recipient whose status is from
	// the LATEST (attempt_number=2) row, and whose attempts[] has length 2.
	insertDeliveryAttempt(t, pool, msgPK, ra, mb, "carol@c.test", "mx.c.test", 1, 451, "4.7.0 try later", "deferred")
	insertDeliveryAttempt(t, pool, msgPK, ra, mb, "carol@c.test", "mx.c.test", 2, 250, "2.0.0 OK", "accepted")
	insertOutboundQueue(t, pool, msgPK, mb, mid, "delivered", []string{"carol@c.test"}, nil, nil)

	code, body := callTrace(t, pool, msgPK, uid)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	recips := recipientsOf(t, body)
	if len(recips) != 1 {
		t.Fatalf("DISTINCT-ON over-count: want 1 recipient, got %d", len(recips))
	}
	r := recips[0]
	if r["status"] != "delivered" {
		t.Fatalf("status should be from the latest attempt (delivered), got %v", r["status"])
	}
	attempts, _ := r["attempts"].([]any)
	if len(attempts) != 2 {
		t.Fatalf("want 2 attempts in history, got %d", len(attempts))
	}
}

func TestTraceHandler_OutboundProblemsFirstSort(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	msgPK, ra, mb, uid, mid := outboundFixture(t, pool)

	// A delivered (alpha, sorts first alphabetically) + a bounced (zoe). Problems
	// first must put the bounced recipient at index 0 despite the email order.
	insertDeliveryAttempt(t, pool, msgPK, ra, mb, "alpha@a.test", "mx.a.test", 1, 250, "2.0.0 OK", "accepted")
	insertDeliveryAttempt(t, pool, msgPK, ra, mb, "zoe@z.test", "mx.z.test", 1, 550, "5.1.1 nope", "rejected")
	insertOutboundQueue(t, pool, msgPK, mb, mid, "bounced", []string{"alpha@a.test", "zoe@z.test"}, nil, nil)

	_, body := callTrace(t, pool, msgPK, uid)
	recips := recipientsOf(t, body)
	if len(recips) != 2 {
		t.Fatalf("want 2 recipients, got %d", len(recips))
	}
	if recips[0]["status"] != "bounced" {
		t.Fatalf("problems-first: want bounced at index 0, got %v", recips[0]["status"])
	}
	if recips[0]["email"] != "zoe@z.test" {
		t.Fatalf("problems-first: want zoe@z.test first, got %v", recips[0]["email"])
	}
}

func TestTraceHandler_OutboundQueuedNoAttempt(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	msgPK, _, mb, uid, mid := outboundFixture(t, pool)

	// rcpt_addrs has a recipient with NO delivery_attempts row → status queued.
	insertOutboundQueue(t, pool, msgPK, mb, mid, "pending", []string{"waiting@w.test"}, nil, nil)

	_, body := callTrace(t, pool, msgPK, uid)
	recips := recipientsOf(t, body)
	if len(recips) != 1 {
		t.Fatalf("want 1 recipient from rcpt_addrs, got %d", len(recips))
	}
	if recips[0]["status"] != "queued" {
		t.Fatalf("want queued (no attempt yet), got %v", recips[0]["status"])
	}
}

func TestTraceHandler_OutboundRetentionSkew(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	msgPK, _, mb, uid, mid := outboundFixture(t, pool)

	// Queue row present, ZERO delivery_attempts (pruned). Must return overallStatus
	// with EMPTY recipients (the frontend shows a "detail expired" note) — never an error.
	insertOutboundQueue(t, pool, msgPK, mb, mid, "delivered", []string{"gone@g.test"}, nil, nil)

	code, body := callTrace(t, pool, msgPK, uid)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	if body["direction"] != "outbound" {
		t.Fatalf("want direction=outbound, got %v", body["direction"])
	}
	if body["overallStatus"] == nil || body["overallStatus"] == "" {
		t.Fatalf("want overallStatus present on retention skew, got %v", body["overallStatus"])
	}
	recips := recipientsOf(t, body)
	if len(recips) != 0 {
		t.Fatalf("retention skew: want 0 recipients (detail pruned), got %d", len(recips))
	}
}

func TestTraceHandler_OutboundUndoSend(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	msgPK, ra, mb, uid, _ := outboundFixture(t, pool)

	// Undo-send: queue row ABSENT, delivery_attempts present → recipients built
	// from delivery_attempts alone.
	insertDeliveryAttempt(t, pool, msgPK, ra, mb, "dan@d.test", "mx.d.test", 1, 250, "2.0.0 OK", "accepted")

	code, body := callTrace(t, pool, msgPK, uid)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	if body["direction"] != "outbound" {
		t.Fatalf("want direction=outbound, got %v", body["direction"])
	}
	recips := recipientsOf(t, body)
	if len(recips) != 1 {
		t.Fatalf("undo-send: want 1 recipient from attempts, got %d", len(recips))
	}
	if recips[0]["status"] != "delivered" {
		t.Fatalf("undo-send: want delivered, got %v", recips[0]["status"])
	}
}

func TestTraceHandler_InboundRegression(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	// A non-Sent owned message must still read as inbound (existing path unchanged).
	userID := createTestUser(t, pool)
	mailboxID := ensureTestMailbox(t, pool, userID)
	mid := "in-" + randomSuffix(t) + "@setjoin.test"
	msgPK := insertTestMessage(t, pool, mailboxID, mid, "sender@example.com", time.Now())
	tagMessageLocation(t, pool, msgPK, mailboxID, "Inbox")
	// create the Inbox tag if missing (so tagMessageLocation attaches something).
	pool.Exec(context.Background(), `SELECT create_system_tags($1)`, mailboxID)
	tagMessageLocation(t, pool, msgPK, mailboxID, "Inbox")

	code, body := callTrace(t, pool, msgPK, userID)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	if body["direction"] != "inbound" {
		t.Fatalf("non-Sent message must read inbound, got %v", body["direction"])
	}
}

// recipientsOf extracts the recipients array from the decoded body.
func recipientsOf(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()
	raw, ok := body["recipients"].([]any)
	if !ok {
		if body["recipients"] == nil {
			return nil
		}
		t.Fatalf("recipients is not an array: %T", body["recipients"])
	}
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			t.Fatalf("recipient is not an object: %T", r)
		}
		out = append(out, m)
	}
	return out
}

func jsonNum(v any) int {
	if v == nil {
		return -1
	}
	f, ok := v.(float64)
	if !ok {
		return -1
	}
	return int(f)
}
