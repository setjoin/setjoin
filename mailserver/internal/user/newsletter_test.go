package user

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
)

func TestExtractUnsubscribeURL(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "single https URL",
			header:   "<https://example.com/unsub/abc123>",
			expected: "https://example.com/unsub/abc123",
		},
		{
			name:     "https + mailto pair — prefers https",
			header:   "<https://newsletter.example.com/unsub>, <mailto:unsub@example.com>",
			expected: "https://newsletter.example.com/unsub",
		},
		{
			name:     "mailto only",
			header:   "<mailto:unsub@example.com>",
			expected: "mailto:unsub@example.com",
		},
		{
			name:     "empty header",
			header:   "",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractUnsubscribeURL(tc.header)
			if got != tc.expected {
				t.Errorf("extractUnsubscribeURL(%q) = %q, want %q", tc.header, got, tc.expected)
			}
		})
	}
}

func TestNewsletterUnsubscribeUnauthenticated(t *testing.T) {
	pool := testPool(t)
	h := NewNewsletterHandler(pool, pgxutil.WorkerPool{Pool: pool}, testLogger())

	req := httptest.NewRequest("POST", "/messages/msg1/unsubscribe", nil)
	rec := httptest.NewRecorder()
	h.Unsubscribe(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestNewsletterUnsubscribeMissingEmailId(t *testing.T) {
	pool := testPool(t)
	h := NewNewsletterHandler(pool, pgxutil.WorkerPool{Pool: pool}, testLogger())
	userID := createTestUser(t, pool)

	req := httptest.NewRequest("POST", "/messages//unsubscribe", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID, Type: auth.TypeAccess}))
	rec := httptest.NewRecorder()
	h.Unsubscribe(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

// TestNewsletterUnsubscribeBlocksSenderAddress is the regression test for the
// "block that never blocks" bug: the inserted user_sender_list row MUST be keyed
// on the newsletter's SENDER address (messages.from_addr), because that is the
// exact key the inbound delivery consumer matches on. The consumer
// (internal/smtp.inConnState.applyPerUserSpam) runs:
//
//	SELECT EXISTS(SELECT 1 FROM user_sender_list
//	  WHERE user_id = $1 AND sender = $2 AND list_type = 'blocked')   -- $2 = headers.fromAddr
//
// The old code inserted "newsletter:"+message_id, which is unique per message and
// can never equal a future message's from_addr — so nothing was ever blocked.
func TestNewsletterUnsubscribeBlocksSenderAddress(t *testing.T) {
	pool := testPool(t)
	h := NewNewsletterHandler(pool, pgxutil.WorkerPool{Pool: pool}, testLogger())
	ctx := context.Background()

	userID := createTestUser(t, pool)

	const senderAddr = "news@newsletter.example.com"
	const messageID = "<unique-msg-id-12345@newsletter.example.com>"
	// mailto: List-Unsubscribe so the handler records intent WITHOUT firing an
	// outbound HTTP POST (keeps the test hermetic; the sender-block path still runs).
	const listUnsub = "<mailto:unsub@newsletter.example.com>"

	emailID := insertNewsletterMessage(t, pool, userID, senderAddr, messageID, listUnsub)

	req := httptest.NewRequest("POST", "/messages/"+emailID+"/unsubscribe", nil)
	req.SetPathValue("emailId", emailID)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID, Type: auth.TypeAccess}))
	rec := httptest.NewRecorder()
	h.Unsubscribe(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Unsubscribe returned %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// 1. The inserted block key must be the sender address, NOT "newsletter:"+id.
	var blockedSenders []string
	rows, err := pool.Query(ctx,
		`SELECT sender FROM user_sender_list
		 WHERE user_id = $1 AND list_type = 'blocked'`, userID)
	if err != nil {
		t.Fatalf("query blocked senders: %v", err)
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			t.Fatalf("scan: %v", err)
		}
		blockedSenders = append(blockedSenders, s)
	}
	rows.Close()

	if len(blockedSenders) != 1 || blockedSenders[0] != senderAddr {
		t.Fatalf("blocked senders = %v, want exactly [%q]", blockedSenders, senderAddr)
	}

	// 2. Prove the inserted key is exactly what the delivery consumer queries: a
	// future message from senderAddr must now satisfy applyPerUserSpam's EXISTS.
	var blocked bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM user_sender_list
		 WHERE user_id = $1 AND sender = $2 AND list_type = 'blocked')`,
		userID, senderAddr,
	).Scan(&blocked); err != nil {
		t.Fatalf("consumer EXISTS probe: %v", err)
	}
	if !blocked {
		t.Fatal("consumer match (sender = from_addr) returned false — the unsubscribe block does not block future mail")
	}
}

// insertNewsletterMessage creates a domain→mailbox→folder→message chain owned by
// userID and returns the message id as a string (the {emailId} path value).
func insertNewsletterMessage(t *testing.T, pool *pgxpool.Pool, userID int64, fromAddr, messageID, listUnsubscribe string) string {
	t.Helper()
	ctx := context.Background()

	suffix := randomSuffix(t)

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1)
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`, "nl-"+suffix+".test",
	).Scan(&domainID); err != nil {
		t.Skipf("domains insert failed (incomplete test schema?): %v", err)
	}

	var mailboxID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, is_primary)
		 VALUES ($1, $2, $3, 'NL Test', TRUE)
		 RETURNING id`,
		userID, domainID, "nl-"+suffix+"@nl-"+suffix+".test",
	).Scan(&mailboxID); err != nil {
		t.Fatalf("mailboxes insert: %v", err)
	}

	var folderID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO folders (mailbox_id, name, role, path)
		 VALUES ($1, 'Inbox', 'inbox', 'Inbox')
		 RETURNING id`, mailboxID,
	).Scan(&folderID); err != nil {
		t.Fatalf("folders insert: %v", err)
	}

	var msgID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, message_id, from_addr, thread_id, raw_ref, list_unsubscribe)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id`,
		mailboxID, folderID, messageID, fromAddr, "thread-"+suffix, "inbound/test-"+suffix, listUnsubscribe,
	).Scan(&msgID); err != nil {
		t.Fatalf("messages insert: %v", err)
	}

	t.Cleanup(func() {
		bg := context.Background()
		pool.Exec(bg, `DELETE FROM messages WHERE id = $1`, msgID)
		pool.Exec(bg, `DELETE FROM folders WHERE id = $1`, folderID)
		pool.Exec(bg, `DELETE FROM mailboxes WHERE id = $1`, mailboxID)
	})

	return strconv.FormatInt(msgID, 10)
}
