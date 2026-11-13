package user

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
)

// requireMailserverSchema skips the test if the full mailserver schema
// (messages, mailboxes, domains tables) is not present.
func requireMailserverSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM information_schema.tables
		 WHERE table_schema = 'public'
		   AND table_name IN ('mailboxes', 'messages', 'domains')`,
	).Scan(&count); err != nil || count < 3 {
		t.Skip("full mailserver schema not applied (missing mailboxes/messages/domains)")
	}
}

// insertTestMessage directly inserts a message row for testing recall.
func insertTestMessage(t *testing.T, pool *pgxpool.Pool, mailboxID int64, messageID, fromAddr string, receivedAt time.Time) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	err := pool.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, received_at, raw_ref, thread_id)
		 VALUES ($1, 1, $2, 'Test Subject', $3, $4, '', $2)
		 RETURNING id`,
		mailboxID, messageID, fromAddr, receivedAt,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestMessage: %v", err)
	}
	return id
}

func ensureTestMailbox(t *testing.T, pool *pgxpool.Pool, userID int64) int64 {
	t.Helper()
	ctx := context.Background()

	// Look up existing primary mailbox first.
	var mailboxID int64
	err := pool.QueryRow(ctx,
		`SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1`,
		userID,
	).Scan(&mailboxID)
	if err == nil {
		return mailboxID
	}

	// Create one if it doesn't exist.
	domainID := ensureTestDomain(t, pool)
	email := fmt.Sprintf("recall-user-%d@recall.test", userID)
	err = pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 VALUES ($1, $2, $3, $3, 'personal', TRUE)
		 RETURNING id`,
		userID, domainID, email,
	).Scan(&mailboxID)
	if err != nil {
		t.Fatalf("ensureTestMailbox: %v", err)
	}
	return mailboxID
}

// tagMessageLocation adds a location-group system tag (by name) to a message,
// mirroring how a delivered copy lands in Inbox. Skips silently if the message
// already carries a location tag.
func tagMessageLocation(t *testing.T, pool *pgxpool.Pool, msgID, mailboxID int64, tagName string) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx,
		`INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary)
		 SELECT m.id, m.received_at, tg.id, 'delivery', TRUE
		 FROM messages m, tags tg
		 WHERE m.id = $1 AND tg.mailbox_id = $2 AND tg.name = $3
		 ON CONFLICT DO NOTHING`,
		msgID, mailboxID, tagName,
	)
	if err != nil {
		t.Fatalf("tagMessageLocation: %v", err)
	}
}

func TestRecallSuccess(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := NewRecallHandler(pgxutil.WorkerPool{Pool: pool}, testLogger(), 5*time.Minute)

	ctx := context.Background()
	// The reducer is gated by the feature.recall toggle.
	if _, err := pool.Exec(ctx,
		`INSERT INTO feature_toggles (key, enabled, description)
		 VALUES ('feature.recall', TRUE, 'Internal message recall')
		 ON CONFLICT (key) DO UPDATE SET enabled = TRUE`,
	); err != nil {
		t.Fatalf("enable feature.recall: %v", err)
	}

	senderID := createTestUser(t, pool)
	senderEmail := "sender-" + randomSuffix(t) + "@setjoin.test"
	// Update the user's email for the test.
	_, err := pool.Exec(ctx, `UPDATE users SET email = $1 WHERE id = $2`, senderEmail, senderID)
	if err != nil {
		t.Fatalf("update sender email: %v", err)
	}
	senderMailbox := ensureTestMailbox(t, pool, senderID)

	recipientID := createTestUser(t, pool)
	recipientMailbox := ensureTestMailbox(t, pool, recipientID)

	// Insert the same message in both sender's and recipient's mailboxes.
	// The recipient's copy is unread (insertTestMessage leaves is_read=FALSE),
	// which is what the reducer recalls; the sender's Sent copy is the structural
	// gate (a sent copy must exist in the recaller's mailbox).
	messageID := "test-msg-" + randomSuffix(t) + "@setjoin.test"
	now := time.Now()
	sentTime := now.Add(-2 * time.Minute) // within 5-min recall window

	msgID1 := insertTestMessage(t, pool, senderMailbox, messageID, senderEmail, sentTime)
	msgID2 := insertTestMessage(t, pool, recipientMailbox, messageID, senderEmail, sentTime)
	tagMessageLocation(t, pool, msgID1, senderMailbox, "Sent")
	tagMessageLocation(t, pool, msgID2, recipientMailbox, "Inbox")

	// Call recall as the sender, using the sender's own copy (msgID1). The handler
	// routes through recall_message(), which SOFT-moves the recipient's unread
	// local copy to Trash (no hard delete), inserts a recoverable stub, and writes
	// the audit row — leaving the sender's Sent copy untouched.
	claims := &auth.Claims{UserID: senderID, Email: senderEmail, Type: auth.TypeAccess}
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/messages/"+fmt.Sprintf("%d", msgID1)+"/recall", bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", msgID1))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Recall(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Recall returned %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// The response body is CALLER-SAFE: {status, recalled} only. It must NOT carry
	// any cross-mailbox count or recipient list (recipient-enumeration oracle).
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode recall response: %v", err)
	}
	if resp["status"] != "success" {
		t.Errorf("response status = %v, want \"success\"", resp["status"])
	}
	if resp["recalled"] != true {
		t.Errorf("response recalled = %v, want true", resp["recalled"])
	}
	for _, leaked := range []string{"recalled_count", "copyCount", "cannotCount", "recipients", "count"} {
		if _, ok := resp[leaked]; ok {
			t.Errorf("response leaked oracle field %q: %v", leaked, resp)
		}
	}

	// Verify the recipient's copy was SOFT-moved to Trash (location tag), not
	// hard-deleted. The reducer narrows recall to soft-to-Trash.
	var trashTags int
	err = pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM message_tags mt JOIN tags t ON t.id = mt.tag_id
		 WHERE mt.message_id = $1 AND t.name = 'Trash'
		   AND t.exclusive_group = 'location' AND t.mailbox_id = $2`,
		msgID2, recipientMailbox,
	).Scan(&trashTags)
	if err != nil {
		t.Fatalf("query recipient trash tag: %v", err)
	}
	if trashTags != 1 {
		t.Errorf("recipient's copy should carry exactly one Trash location tag, got %d", trashTags)
	}

	// The TRUE copy_count still lands in the message_recalls audit row even though
	// it is absent from the caller-facing response (audit intact, oracle closed).
	var auditCopyCount int
	err = pool.QueryRow(ctx,
		`SELECT copy_count FROM message_recalls WHERE message_id = $1`, messageID,
	).Scan(&auditCopyCount)
	if err != nil {
		t.Fatalf("query message_recalls audit row: %v", err)
	}
	if auditCopyCount != 1 {
		t.Errorf("audit copy_count = %d, want 1 (one unread local copy recalled)", auditCopyCount)
	}

	// Verify a recall stub was inserted into the recipient's mailbox.
	var stubCount int
	err = pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM messages
		 WHERE mailbox_id = $1 AND message_id = $2`,
		recipientMailbox, "recall-"+messageID,
	).Scan(&stubCount)
	if err != nil {
		t.Fatalf("query recall stub: %v", err)
	}
	if stubCount != 1 {
		t.Errorf("expected one recall stub in recipient mailbox, got %d", stubCount)
	}
}

func TestRecallExpiredWindow(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := NewRecallHandler(pgxutil.WorkerPool{Pool: pool}, testLogger(), 5*time.Minute)

	senderID := createTestUser(t, pool)
	senderEmail := "sender-" + randomSuffix(t) + "@setjoin.test"
	ctx := context.Background()
	pool.Exec(ctx, `UPDATE users SET email = $1 WHERE id = $2`, senderEmail, senderID)
	senderMailbox := ensureTestMailbox(t, pool, senderID)

	recipientID := createTestUser(t, pool)
	recipientMailbox := ensureTestMailbox(t, pool, recipientID)

	messageID := "old-msg-" + randomSuffix(t) + "@setjoin.test"
	oldTime := time.Now().Add(-10 * time.Minute) // outside 5-min window

	insertTestMessage(t, pool, senderMailbox, messageID, senderEmail, oldTime)
	msgID := insertTestMessage(t, pool, recipientMailbox, messageID, senderEmail, oldTime)

	claims := &auth.Claims{UserID: senderID, Email: senderEmail, Type: auth.TypeAccess}
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/messages/"+fmt.Sprintf("%d", msgID)+"/recall", bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", msgID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Recall(rec, req)
	if rec.Code == http.StatusOK {
		t.Error("recall outside window should fail")
	}
}

func TestRecallNotSender(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := NewRecallHandler(pgxutil.WorkerPool{Pool: pool}, testLogger(), 5*time.Minute)

	senderID := createTestUser(t, pool)
	senderEmail := "real-sender-" + randomSuffix(t) + "@setjoin.test"
	ctx := context.Background()
	pool.Exec(ctx, `UPDATE users SET email = $1 WHERE id = $2`, senderEmail, senderID)
	senderMailbox := ensureTestMailbox(t, pool, senderID)

	otherUserID := createTestUser(t, pool)

	messageID := "not-mine-" + randomSuffix(t) + "@setjoin.test"
	now := time.Now().Add(-1 * time.Minute)

	insertTestMessage(t, pool, senderMailbox, messageID, senderEmail, now)
	msgID := insertTestMessage(t, pool, senderMailbox, messageID, senderEmail, now)

	// Try to recall as someone else.
	claims := &auth.Claims{UserID: otherUserID, Email: "other@setjoin.test", Type: auth.TypeAccess}
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/messages/"+fmt.Sprintf("%d", msgID)+"/recall", bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", msgID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Recall(rec, req)
	if rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Errorf("recall by non-sender should fail with 403 or 404, got %d", rec.Code)
	}
}

// TestRecallForeignMessageIDOR asserts that an authenticated user cannot use
// recall to read (and thus leak) metadata of a message id that lives in a
// mailbox they do NOT own. Before the R4 fix the metadata SELECT had no
// ownership binding, so any authenticated caller could probe any message id and
// have its from_addr/received_at/Message-ID enter the handler. The bound read
// (JOIN mailboxes ... WHERE mb.user_id = $caller) now makes the row invisible,
// so the caller gets a flat 404 — no metadata leak, no cross-mailbox recall.
func TestRecallForeignMessageIDOR(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := NewRecallHandler(pgxutil.WorkerPool{Pool: pool}, testLogger(), 5*time.Minute)

	// Owner sends a message that lives only in the owner's mailbox.
	ownerID := createTestUser(t, pool)
	ownerEmail := "owner-" + randomSuffix(t) + "@setjoin.test"
	ctx := context.Background()
	pool.Exec(ctx, `UPDATE users SET email = $1 WHERE id = $2`, ownerEmail, ownerID)
	ownerMailbox := ensureTestMailbox(t, pool, ownerID)

	messageID := "owned-msg-" + randomSuffix(t) + "@setjoin.test"
	recent := time.Now().Add(-1 * time.Minute) // inside the recall window
	foreignMsgID := insertTestMessage(t, pool, ownerMailbox, messageID, ownerEmail, recent)

	// Attacker is a different authenticated user with their own mailbox.
	attackerID := createTestUser(t, pool)
	attackerEmail := "attacker-" + randomSuffix(t) + "@setjoin.test"
	pool.Exec(ctx, `UPDATE users SET email = $1 WHERE id = $2`, attackerEmail, attackerID)
	ensureTestMailbox(t, pool, attackerID)

	// Attacker probes the owner's message id via recall.
	claims := &auth.Claims{UserID: attackerID, Email: attackerEmail, Type: auth.TypeAccess}
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/messages/"+fmt.Sprintf("%d", foreignMsgID)+"/recall", bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", foreignMsgID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Recall(rec, req)

	// The bound read returns no row → 404. Crucially it must NOT be 200/403/410:
	// a 403 ("only the sender can recall") or 410 ("window expired") would prove
	// the metadata was read (leaked) before the sender check ran.
	if rec.Code != http.StatusNotFound {
		t.Fatalf("foreign-message recall returned %d, want 404 (no metadata leak): %s", rec.Code, rec.Body.String())
	}
}

func TestRecallUnauthorized(t *testing.T) {
	pool := testPool(t)
	h := NewRecallHandler(pgxutil.WorkerPool{Pool: pool}, testLogger(), 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/messages/1/recall", nil)
	req.SetPathValue("id", "1")
	rec := httptest.NewRecorder()
	h.Recall(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized recall returned %d, want 401", rec.Code)
	}
}
