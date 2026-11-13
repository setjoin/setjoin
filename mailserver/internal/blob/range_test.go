package blob

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
)

// newFakeMinioServer stands up an httptest S3-like GET endpoint backed by a
// fixed byte slice and returns a real *minio.Client pointed at it. It uses
// http.ServeContent server-side, so — exactly like real MinIO — it replies
// 206 + Content-Range to a ranged GET. That makes it a faithful stand-in: any
// difference the regression test sees is entirely in the blob Handler's own
// response to its caller, which is the thing B4 says is wrong.
func newFakeMinioServer(t *testing.T, data []byte, contentType string) *minio.Client {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		// A real (non-zero) modtime: minio-go's ObjectInfo parsing requires a
		// well-formed Last-Modified header on every response (StatObject
		// fails otherwise), just like a real MinIO/S3 server always sends one.
		http.ServeContent(w, r, "", time.Now(), strings.NewReader(string(data)))
	}))
	t.Cleanup(ts.Close)

	mc, err := minio.New(strings.TrimPrefix(ts.URL, "http://"), &minio.Options{
		Creds:  credentials.NewStaticV4("fake-access", "fake-secret", ""),
		Secure: false,
		// Region set explicitly so the client skips its GetBucketLocation
		// round trip (bucket-cache.go: "Region set then no need to fetch
		// bucket location") — the fake server below only implements GET.
		Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	return mc
}

// insertOwnedAttachment creates a minimal domain→user→mailbox→folder→message
// →message_attachments chain so Get()'s ownership check (mb.user_id = the
// caller) succeeds for the given blob hash. Returns the owning user id.
func insertOwnedAttachment(t *testing.T, pool *pgxpool.Pool, blobHash string, size int64) int64 {
	t.Helper()
	ctx := context.Background()

	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	suffix := fmt.Sprintf("rangetest-%x", b)

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1)
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`, suffix+".test",
	).Scan(&domainID); err != nil {
		t.Skipf("domains insert failed (incomplete test schema?): %v", err)
	}

	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, password_hash, domain_id)
		 VALUES ($1, $2, 'Range Test', '$2a$10$placeholder', $3)
		 RETURNING id`,
		suffix, suffix+"@"+suffix+".test", domainID,
	).Scan(&userID); err != nil {
		t.Fatalf("users insert: %v", err)
	}

	var mailboxID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, is_primary)
		 VALUES ($1, $2, $3, 'Range Test', TRUE)
		 RETURNING id`,
		userID, domainID, suffix+"@"+suffix+".test",
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
	var receivedAt time.Time
	if err := pool.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, message_id, from_addr, thread_id, raw_ref)
		 VALUES ($1, $2, $3, 'from@'||$4, $5, $6)
		 RETURNING id, received_at`,
		mailboxID, folderID, "<"+suffix+"@test>", suffix, "thread-"+suffix, "inline-body",
	).Scan(&msgID, &receivedAt); err != nil {
		t.Fatalf("messages insert: %v", err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO blobs (sha256, minio_ref, size_bytes, content_type, ref_count)
		 VALUES ($1, $2, $3, 'application/octet-stream', 1)
		 ON CONFLICT (sha256) DO NOTHING`,
		blobHash, "blobs/"+blobHash, size,
	); err != nil {
		t.Fatalf("blobs insert: %v", err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO message_attachments (message_id, received_at, blob_sha256, filename, content_type, size_bytes)
		 VALUES ($1, $2, $3, 'file.bin', 'application/octet-stream', $4)`,
		msgID, receivedAt, blobHash, size,
	); err != nil {
		t.Fatalf("message_attachments insert: %v", err)
	}

	t.Cleanup(func() {
		bg := context.Background()
		pool.Exec(bg, `DELETE FROM message_attachments WHERE message_id = $1`, msgID) //nolint:errcheck
		pool.Exec(bg, `DELETE FROM blobs WHERE sha256 = $1`, blobHash)                 //nolint:errcheck
		pool.Exec(bg, `DELETE FROM messages WHERE id = $1`, msgID)                     //nolint:errcheck
		pool.Exec(bg, `DELETE FROM folders WHERE id = $1`, folderID)                   //nolint:errcheck
		tx, err := pool.Begin(bg)
		if err == nil {
			tx.Exec(bg, `DELETE FROM mailboxes WHERE id = $1`, mailboxID) //nolint:errcheck
			tx.Exec(bg, `DELETE FROM users WHERE id = $1`, userID)        //nolint:errcheck
			tx.Commit(bg)                                                 //nolint:errcheck
		}
		pool.Exec(bg, `DELETE FROM domains WHERE id = $1`, domainID) //nolint:errcheck
	})

	return userID
}

// TestGetRangeRequest_Returns206WithContentRange is the B4 red-first case:
// a client sends a byte-range GET for an attachment. Against the pre-fix
// code (Range forwarded straight to MinIO, no status/Content-Range handling
// on the response written back to the caller) this receives a 200 with the
// full-200-semantics but a truncated body and no Content-Range — a resuming
// client reads that as "the whole file is N bytes" and corrupts the
// reassembled download. The fix must reply 206, set Content-Range, and
// return only the requested slice.
func TestGetRangeRequest_Returns206WithContentRange(t *testing.T) {
	pool := testsupport.OpenTestPool(t)

	data := []byte("0123456789abcdefghij") // 20 bytes, size deliberately > 0 and small
	sum := sha256.Sum256(data)
	blobHash := hex.EncodeToString(sum[:])

	userID := insertOwnedAttachment(t, pool, blobHash, int64(len(data)))

	mc := newFakeMinioServer(t, data, "application/octet-stream")
	h := &Handler{minio: mc, workerPool: pool, bucket: "blobs", cache: map[string]cachedBlob{}, logger: discardLogger()}

	req := httptest.NewRequest(http.MethodGet, "/blobs/"+blobHash, nil)
	req.SetPathValue("sha256", blobHash)
	req.Header.Set("Range", "bytes=2-5")
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))

	rec := httptest.NewRecorder()
	h.Get(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d (StatusPartialContent); body=%q", rec.Code, http.StatusPartialContent, rec.Body.String())
	}
	wantContentRange := fmt.Sprintf("bytes 2-5/%d", len(data))
	if got := rec.Header().Get("Content-Range"); got != wantContentRange {
		t.Errorf("Content-Range = %q, want %q", got, wantContentRange)
	}
	if got := rec.Body.String(); got != "2345" {
		t.Errorf("body = %q, want %q (the requested slice only)", got, "2345")
	}
}

// TestGetNoRange_StillReturns200WholeFile is the companion happy-path
// invariant: a plain GET (no Range) must still return the whole object with
// a 200, not regress into always-partial behavior.
func TestGetNoRange_StillReturns200WholeFile(t *testing.T) {
	pool := testsupport.OpenTestPool(t)

	data := []byte("the entire attachment body, unranged")
	sum := sha256.Sum256(data)
	blobHash := hex.EncodeToString(sum[:])

	userID := insertOwnedAttachment(t, pool, blobHash, int64(len(data)))

	mc := newFakeMinioServer(t, data, "application/octet-stream")
	h := &Handler{minio: mc, workerPool: pool, bucket: "blobs", cache: map[string]cachedBlob{}, logger: discardLogger()}

	req := httptest.NewRequest(http.MethodGet, "/blobs/"+blobHash, nil)
	req.SetPathValue("sha256", blobHash)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))

	rec := httptest.NewRecorder()
	h.Get(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != string(data) {
		t.Errorf("body = %q, want %q", got, string(data))
	}
	if got := rec.Header().Get("Content-Range"); got != "" {
		t.Errorf("Content-Range = %q, want empty for an unranged 200", got)
	}
}
