package user

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
)

func TestOfflineSizeEstimate(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := NewOfflineSizeHandler(pgxutil.WorkerPool{Pool: pool}, testLogger())

	userID := createTestUser(t, pool)
	mbID := ensureTestMailbox(t, pool, userID)

	// One in-window message (5 days ago) with body + an attachment-sized size_bytes,
	// and one out-of-window message (200 days ago).
	now := time.Now()
	insertSizedMessage(t, pool, mbID, "recent@x", now.AddDate(0, 0, -5), "hello body html", "hello text", 50000)
	insertSizedMessage(t, pool, mbID, "old@x", now.AddDate(0, 0, -200), "old body html", "old text", 90000)

	req := httptest.NewRequest("GET", "/offline/size-estimate", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp struct {
		Buckets []struct {
			Window       string `json:"window"`
			MessageCount int64  `json:"messageCount"`
			BodyBytes    int64  `json:"bodyBytes"`
		} `json:"buckets"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	by := map[string]struct {
		count, bytes int64
	}{}
	for _, b := range resp.Buckets {
		by[b.Window] = struct{ count, bytes int64 }{b.MessageCount, b.BodyBytes}
	}
	// 7d/30d/90d/180d cover only the 5-day-old message (cumulative).
	if by["30d"].count != 1 {
		t.Fatalf("30d count = %d, want 1", by["30d"].count)
	}
	// 365d & all cover both.
	if by["365d"].count != 2 {
		t.Fatalf("365d count = %d, want 2", by["365d"].count)
	}
	if by["all"].count != 2 {
		t.Fatalf("all count = %d, want 2", by["all"].count)
	}
	// bodyBytes excludes attachments: must be far below the 50000 size_bytes,
	// i.e. just octet_length(body_html)+octet_length(body_text) ≈ tens of bytes.
	if by["30d"].bytes == 0 || by["30d"].bytes > 1000 {
		t.Fatalf("30d bodyBytes = %d, want a small body-only count (<1000)", by["30d"].bytes)
	}
}

// TestOfflineSizeEstimateIsolation locks the R1 filter (WHERE mb.user_id = $1) on the
// BYPASSRLS workerPool: a second user's messages must NOT contribute to user A's totals.
// Without that explicit WHERE this handler would leak every user's body bytes.
func TestOfflineSizeEstimateIsolation(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := NewOfflineSizeHandler(pgxutil.WorkerPool{Pool: pool}, testLogger())

	now := time.Now()

	// User A: one recent message with a known small body.
	userA := createTestUser(t, pool)
	mbA := ensureTestMailbox(t, pool, userA)
	insertSizedMessage(t, pool, mbA, "a@x", now.AddDate(0, 0, -5), "A-html", "A-text", 1000)

	// User B (the attacker's data): a much larger recent body in their own mailbox.
	userB := createTestUser(t, pool)
	mbB := ensureTestMailbox(t, pool, userB)
	insertSizedMessage(t, pool, mbB, "b@x",
		now.AddDate(0, 0, -5),
		"B-html-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"B-text-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 2000)

	req := httptest.NewRequest("GET", "/offline/size-estimate", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userA}))
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp struct {
		Buckets []struct {
			Window       string `json:"window"`
			MessageCount int64  `json:"messageCount"`
			BodyBytes    int64  `json:"bodyBytes"`
		} `json:"buckets"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	by := map[string]struct{ count, bytes int64 }{}
	for _, b := range resp.Buckets {
		by[b.Window] = struct{ count, bytes int64 }{b.MessageCount, b.BodyBytes}
	}

	// A's exact body byte total (html + text), computed the same way the reducer does.
	wantBytes := int64(len("A-html") + len("A-text"))

	// "all" must see ONLY A's single message — never B's.
	if by["all"].count != 1 {
		t.Fatalf("all count = %d, want 1 (B's message leaked into A's totals)", by["all"].count)
	}
	if by["all"].bytes != wantBytes {
		t.Fatalf("all bytes = %d, want %d (B's bytes leaked across the user_id boundary)", by["all"].bytes, wantBytes)
	}
	// Every cumulative window covering the 5-day-old message must match exactly.
	for _, w := range []string{"7d", "30d", "90d", "180d", "365d"} {
		if by[w].count != 1 || by[w].bytes != wantBytes {
			t.Fatalf("%s = {count:%d, bytes:%d}, want {1, %d} — cross-user leak", w, by[w].count, by[w].bytes, wantBytes)
		}
	}
}

func TestOfflineSizeEstimateUnauthorized(t *testing.T) {
	pool := testPool(t)
	h := NewOfflineSizeHandler(pgxutil.WorkerPool{Pool: pool}, testLogger())
	req := httptest.NewRequest("GET", "/offline/size-estimate", nil)
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// insertSizedMessage inserts a message with explicit body fields + size_bytes
// (size_bytes carries the full RFC822 size INCLUDING attachments; bodyBytes must
// not use it).
func insertSizedMessage(t *testing.T, pool *pgxpool.Pool, mailboxID int64, fromAddr string, receivedAt time.Time, bodyHTML, bodyText string, sizeBytes int64) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, body_html, body_text, size_bytes, received_at, raw_ref, thread_id)
		 VALUES ($1, 1, $2, 'S', $3, $4, $5, $6, $7, '', $2)
		 RETURNING id`,
		mailboxID, fromAddr+"-"+receivedAt.Format("20060102150405"), fromAddr, bodyHTML, bodyText, sizeBytes, receivedAt,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insertSizedMessage: %v", err)
	}
	return id
}
