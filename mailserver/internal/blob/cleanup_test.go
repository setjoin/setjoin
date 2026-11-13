package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
)

// insertCleanupCandidate inserts a blobs row (given ref_count) plus a
// blob_cleanup_queue row already past its delay, so the next
// cleanupCandidates() scan picks it up immediately (delay_minutes = 0,
// scheduled_at = now() - 1 minute).
func insertCleanupCandidate(t *testing.T, pool *pgxpool.Pool, sha256 string, refCount int) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO blobs (sha256, minio_ref, size_bytes, content_type, ref_count)
		 VALUES ($1, $2, 1, 'application/octet-stream', $3)`,
		sha256, "blobs/"+sha256, refCount,
	); err != nil {
		t.Fatalf("insert blobs: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM blob_cleanup_queue WHERE blob_sha256 = $1`, sha256) //nolint:errcheck
		pool.Exec(context.Background(), `DELETE FROM blobs WHERE sha256 = $1`, sha256)                   //nolint:errcheck
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO blob_cleanup_queue (blob_sha256, scheduled_at, delay_minutes)
		 VALUES ($1, now() - interval '1 minute', 0)`, sha256,
	); err != nil {
		t.Fatalf("insert blob_cleanup_queue: %v", err)
	}
}

func blobRowExists(t *testing.T, pool *pgxpool.Pool, sha256 string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM blobs WHERE sha256 = $1)`, sha256,
	).Scan(&exists); err != nil {
		t.Fatalf("check blobs: %v", err)
	}
	return exists
}

// TestReapCleanupCandidate_RaceDoesNotDeleteStillReferencedBlob is the B3
// red-first case: cleanupCandidates() snapshots a blob at ref_count = 0, but
// an attach (message_attachments INSERT → V075 trigger) commits and bumps it
// to 1 before the reap step runs — exactly the window between the SELECT
// scan and the RemoveObject call in the old code. Against the pre-fix
// unconditional "RemoveObject then move on" body, this would delete
// still-referenced bytes. The atomic `DELETE ... WHERE ref_count = 0` must
// see the up-to-date ref_count and skip both the object removal and the row
// delete.
func TestReapCleanupCandidate_RaceDoesNotDeleteStillReferencedBlob(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	sha := randomHex(32)
	insertCleanupCandidate(t, pool, sha, 0)

	candidates := (&Handler{pool: pool}).cleanupCandidates(context.Background())
	found := false
	for _, c := range candidates {
		if c == sha {
			found = true
		}
	}
	if !found {
		t.Fatalf("candidate scan should have picked up %q at ref_count=0, got %v", sha, candidates)
	}

	// Simulate an attach committing in the race window between the scan
	// above and the reap step below.
	if _, err := pool.Exec(context.Background(),
		`UPDATE blobs SET ref_count = 1 WHERE sha256 = $1`, sha,
	); err != nil {
		t.Fatalf("simulate attach: %v", err)
	}

	fake := newFakeStore()
	h := &Handler{minio: fake, pool: pool, bucket: "blobs", logger: discardLogger()}
	h.reapCleanupCandidate(context.Background(), sha)

	for _, k := range fake.removeKeys {
		if k == sha {
			t.Fatalf("RemoveObject must NOT be called for a blob re-referenced since the candidate scan (sha=%q)", sha)
		}
	}
	if !blobRowExists(t, pool, sha) {
		t.Error("blobs row for a still-referenced blob must not be deleted")
	}
}

// TestReapCleanupCandidate_DeletesTrulyUnreferencedBlob is the companion
// happy-path invariant the old code was also missing: a blob that is STILL
// ref_count = 0 at reap time must have both its bytes removed from storage
// AND its blobs row deleted (the row was never deleted before this fix).
func TestReapCleanupCandidate_DeletesTrulyUnreferencedBlob(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	sha := randomHex(32)
	insertCleanupCandidate(t, pool, sha, 0)

	fake := newFakeStore()
	h := &Handler{minio: fake, pool: pool, bucket: "blobs", logger: discardLogger()}
	h.reapCleanupCandidate(context.Background(), sha)

	found := false
	for _, k := range fake.removeKeys {
		if k == sha {
			found = true
		}
	}
	if !found {
		t.Errorf("RemoveObject was not called for truly-unreferenced blob %q", sha)
	}
	if blobRowExists(t, pool, sha) {
		t.Error("blobs row for a truly-unreferenced blob must be deleted")
	}
}

// TestReapCleanupCandidate_RemoveObjectFailureIsRetried pins the orphan-retry
// ledger (D-MAILSERVER-INTERNAL-BLOB-005): when the guarded blobs-row delete
// has committed but MinIO's RemoveObject fails, the key must be queued and the
// next cleanup tick must complete the removal — instead of orphaning the bytes
// permanently (the queue row is CASCADE-deleted with the blobs row, so there
// was previously no path back). The retry re-checks the live table first: if
// the content was re-uploaded meanwhile, the ledger entry is dropped and the
// live blob is left to the ref_count-driven lifecycle.
func TestReapCleanupCandidate_RemoveObjectFailureIsRetried(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	sha := randomHex(32)
	insertCleanupCandidate(t, pool, sha, 0)

	fake := newFakeStore()
	fake.failRemove = map[string]bool{sha: true}
	// pool is required alongside workerPool: reapCleanupCandidate's guarded
	// row delete runs on h.pool (matching the sibling reap tests) — a Handler
	// literal without it nil-panics before the failure injection is exercised.
	h := &Handler{minio: fake, pool: pool, workerPool: pool, bucket: "blobs", logger: discardLogger()}
	h.reapCleanupCandidate(ctx, sha)

	if blobRowExists(t, pool, sha) {
		t.Fatal("the guarded row delete must have committed (precondition of the retry path)")
	}
	h.retryMu.Lock()
	_, queued := h.reapRetries[sha]
	h.retryMu.Unlock()
	if !queued {
		t.Fatal("failed RemoveObject must record the key for the cleanup-tick retry")
	}

	// The object is live in storage until the removal succeeds — a plain fake
	// stands in for the MinIO bytes that RemoveObject failed to delete.
	fake.objects[sha] = []byte("orphaned bytes")
	delete(fake.failRemove, sha)

	h.retryFailedReaps(ctx)

	if len(fake.removeKeys) == 0 || fake.removeKeys[len(fake.removeKeys)-1] != sha {
		t.Fatalf("retry tick must re-attempt RemoveObject for %q, removeKeys=%v", sha, fake.removeKeys)
	}
	h.retryMu.Lock()
	_, stillQueued := h.reapRetries[sha]
	h.retryMu.Unlock()
	if stillQueued {
		t.Error("successful retry must clear the ledger entry")
	}
	if _, ok := fake.objects[sha]; ok {
		t.Error("retried RemoveObject must delete the orphaned object")
	}
}

// TestRetryFailedReaps_DropsEntryWhenBlobReuploaded: the retry's live-table
// re-check must not remove bytes that belong to a live blob again — if the
// content was re-uploaded (and attached) between the failure and the retry,
// the ledger entry is dropped without touching storage.
func TestRetryFailedReaps_DropsEntryWhenBlobReuploaded(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	sha := randomHex(32)

	insertCleanupCandidate(t, pool, sha, 0)
	fake := newFakeStore()
	fake.failRemove = map[string]bool{sha: true}
	// pool + workerPool: reapCleanupCandidate's guarded delete runs on h.pool,
	// retryFailedReaps re-checks on h.workerPool — same fixture shape as the
	// other reap tests (a missing pool nil-panics before the assertions).
	h := &Handler{minio: fake, pool: pool, workerPool: pool, bucket: "blobs", logger: discardLogger()}
	h.reapCleanupCandidate(ctx, sha) // row deleted, RemoveObject failed → ledger entry

	// Re-upload the same content: a new live blobs row owns the object again.
	insertCleanupCandidate(t, pool, sha, 1)

	h.retryFailedReaps(ctx)

	for _, k := range fake.removeKeys {
		if k == sha {
			t.Fatalf("retry must not remove an object a live blobs row references again (sha=%q)", sha)
		}
	}
	h.retryMu.Lock()
	_, stillQueued := h.reapRetries[sha]
	h.retryMu.Unlock()
	if stillQueued {
		t.Error("dropped ledger entry must be removed once the content is live again")
	}
}

// flakyRegistry is a RetentionRegistry stub that fails the first N applies.
type flakyRegistry struct {
	failures int
	applied  []string
}

func (f *flakyRegistry) ApplyAll(_ context.Context, key string) error {
	if f.failures > 0 {
		f.failures--
		return errors.New("object-lock transient failure")
	}
	f.applied = append(f.applied, key)
	return nil
}

// TestPut_RetentionFailureIsRetriedOnCleanupTick pins the WORM retry ledger
// (D-MAILSERVER-INTERNAL-BLOB-006): the upload itself stays non-fatal (the
// documented design), but the failed ApplyAll must be queued and applied by a
// later cleanup tick instead of being silently forgotten.
func TestPut_RetentionFailureIsRetriedOnCleanupTick(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := &Handler{
		minio:             newFakeStore(), // Put streams to storage before the WORM ledger path
		pool:              pool,
		workerPool:        pool,
		bucket:            "blobs",
		cache:             map[string]cachedBlob{},
		logger:            discardLogger(),
		retentionRegistry: &flakyRegistry{failures: 1},
	}

	// The URL SHA must be the body's real hash — Put verifies the streamed
	// bytes against it and rejects mismatches (400) before the WORM ledger path.
	body := []byte("worm-pending bytes")
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	req := putRequest(t, sha, body)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1}))
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload PUT: status = %d, want 201 (retention failure must stay non-fatal); body=%q", rec.Code, rec.Body.String())
	}

	reg := h.retentionRegistry.(*flakyRegistry)
	if len(reg.applied) != 0 {
		t.Fatalf("first ApplyAll must have failed (flaky stub precondition), applied=%v", reg.applied)
	}
	h.retryMu.Lock()
	_, queued := h.retentionRetries[sha]
	h.retryMu.Unlock()
	if !queued {
		t.Fatal("failed ApplyAll must record the key for the cleanup-tick retry")
	}

	h.retryFailedRetention(context.Background())
	if len(reg.applied) != 1 || reg.applied[0] != sha {
		t.Fatalf("retry tick must apply the WORM policy once for %q, applied=%v", sha, reg.applied)
	}
	h.retryMu.Lock()
	_, stillQueued := h.retentionRetries[sha]
	h.retryMu.Unlock()
	if stillQueued {
		t.Error("successful retry must clear the ledger entry")
	}
}
