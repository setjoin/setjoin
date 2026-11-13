package user

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
)

// insertTestAttachment inserts a message_attachments row. content_type/size_bytes
// are NOT NULL, so they carry placeholders; disposition is 'attachment' or
// 'inline'. received_at must equal the message's received_at (partitioned-parent
// FK is (message_id, received_at)).
func insertTestAttachment(t *testing.T, pool *pgxpool.Pool, msgID int64, receivedAt time.Time, sha, filename, disposition string) {
	t.Helper()
	// blob_sha256 FKs into blobs — seed the referenced blob first (idempotent).
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO blobs (sha256, minio_ref, size_bytes, content_type)
		 VALUES ($1, $1, 0, 'application/octet-stream')
		 ON CONFLICT (sha256) DO NOTHING`,
		sha,
	); err != nil {
		t.Fatalf("insertTestAttachment (blob): %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO message_attachments
		   (message_id, received_at, blob_sha256, filename, content_type, disposition, size_bytes)
		 VALUES ($1, $2, $3, $4, 'application/octet-stream', $5, 0)`,
		msgID, receivedAt, sha, filename, disposition,
	); err != nil {
		t.Fatalf("insertTestAttachment: %v", err)
	}
}

// zipRequest builds an authenticated GET for a message's attachments.zip.
func zipRequest(t *testing.T, userID int64, msgID int64) *http.Request {
	t.Helper()
	claims := &auth.Claims{UserID: userID, Type: auth.TypeAccess}
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/messages/%d/attachments.zip", msgID), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", msgID))
	return req.WithContext(auth.ContextWithUser(req.Context(), claims))
}

// TestAttachmentsZip_OwnershipReturns404 is the load-bearing R1/R4 assertion:
// user A must not be able to zip user B's message. The ownership read returns
// zero rows for a cross-user request, so it 404s before any blob fetch — the
// getBlob seam fatals if reached, proving the 404 comes from the ownership read.
func TestAttachmentsZip_OwnershipReturns404(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)

	now := time.Now()

	userA := createTestUser(t, pool)
	mailboxA := ensureTestMailbox(t, pool, userA)
	msgA := insertTestMessage(t, pool, mailboxA, "a-"+randomSuffix(t)+"@setjoin.test", "a@setjoin.test", now)
	insertTestAttachment(t, pool, msgA, now, "shaA", "a.txt", "attachment")

	userB := createTestUser(t, pool)
	mailboxB := ensureTestMailbox(t, pool, userB)
	msgB := insertTestMessage(t, pool, mailboxB, "b-"+randomSuffix(t)+"@setjoin.test", "b@setjoin.test", now)
	insertTestAttachment(t, pool, msgB, now, "shaB", "b.txt", "attachment")

	h := &AttachmentsZipHandler{
		getBlob: func(context.Context, string) (io.ReadCloser, error) {
			t.Fatal("getBlob must not be called on a cross-user ownership miss")
			return nil, nil
		},
		workerPool: pool,
		logger:     testLogger(),
	}

	// User A requests user B's message.
	rec := httptest.NewRecorder()
	h.DownloadAll(rec, zipRequest(t, userA, msgB))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-user request: status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAttachmentsZip_HappyPath streams a real zip through a fake blob store and
// asserts the archive contains every attachment's bytes under its filename.
func TestAttachmentsZip_HappyPath(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)

	now := time.Now()
	userID := createTestUser(t, pool)
	mailbox := ensureTestMailbox(t, pool, userID)
	msgID := insertTestMessage(t, pool, mailbox, "h-"+randomSuffix(t)+"@setjoin.test", "h@setjoin.test", now)

	blobs := map[string][]byte{
		"sha-report": []byte("quarterly numbers"),
		"sha-notes":  []byte("meeting notes body"),
	}
	insertTestAttachment(t, pool, msgID, now, "sha-report", "report.txt", "attachment")
	insertTestAttachment(t, pool, msgID, now, "sha-notes", "notes.txt", "attachment")

	h := &AttachmentsZipHandler{
		getBlob: func(_ context.Context, key string) (io.ReadCloser, error) {
			b, ok := blobs[key]
			if !ok {
				return nil, fmt.Errorf("no blob %s", key)
			}
			return io.NopCloser(bytes.NewReader(b)), nil
		},
		workerPool: pool,
		logger:     testLogger(),
	}

	rec := httptest.NewRecorder()
	h.DownloadAll(rec, zipRequest(t, userID, msgID))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("Content-Type = %q, want application/zip", ct)
	}

	body := rec.Body.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	got := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open zip entry %q: %v", f.Name, err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		got[f.Name] = string(data)
	}

	want := map[string]string{
		"report.txt": "quarterly numbers",
		"notes.txt":  "meeting notes body",
	}
	if len(got) != len(want) {
		t.Fatalf("zip has %d entries, want %d: %v", len(got), len(want), got)
	}
	for name, content := range want {
		if got[name] != content {
			t.Errorf("entry %q = %q, want %q", name, got[name], content)
		}
	}
}

// TestAttachmentsZip_InlineOnlyReturns404 confirms a message whose only
// attachments are inline (disposition='inline') zips to nothing → 404.
func TestAttachmentsZip_InlineOnlyReturns404(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)

	now := time.Now()
	userID := createTestUser(t, pool)
	mailbox := ensureTestMailbox(t, pool, userID)
	msgID := insertTestMessage(t, pool, mailbox, "i-"+randomSuffix(t)+"@setjoin.test", "i@setjoin.test", now)
	insertTestAttachment(t, pool, msgID, now, "sha-inline", "logo.png", "inline")

	h := &AttachmentsZipHandler{
		getBlob: func(context.Context, string) (io.ReadCloser, error) {
			t.Fatal("getBlob must not be called when there are no non-inline attachments")
			return nil, nil
		},
		workerPool: pool,
		logger:     testLogger(),
	}

	rec := httptest.NewRecorder()
	h.DownloadAll(rec, zipRequest(t, userID, msgID))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("inline-only: status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}
