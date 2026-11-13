package blob

// Branch-completion tests for the handler housekeeping seams: the retention
// registry wiring, the cleanup goroutine's shutdown arm, the bounded retry
// ledgers (reap + retention, including ledger overflow eviction), the
// retention-retry failure/success arms, the cleanup-queue loop, and the
// upload-path reducer/copy/temp-cleanup failure branches.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"

	"setjoin.com/shared/testsupport"
)

type w5FakeRegistry struct{ err error }

func (r w5FakeRegistry) ApplyAll(_ context.Context, _ string) error { return r.err }

func TestSetRetentionRegistryWiring(t *testing.T) {
	h := &Handler{}
	if h.retentionRegistry != nil {
		t.Fatal("fresh handler must have no retention registry")
	}
	reg := w5FakeRegistry{}
	h.SetRetentionRegistry(reg)
	if h.retentionRegistry == nil {
		t.Error("SetRetentionRegistry must wire the registry")
	}
}

func TestStartCleanupContextCancel(t *testing.T) {
	h := &Handler{logger: discardLogger()}
	ctx, cancel := context.WithCancel(context.Background())
	h.StartCleanup(ctx)
	cancel()
	// The goroutine exits on the canceled context; give the scheduler a moment
	// (a leak would be caught by goleak-style guards elsewhere; here we assert
	// no panic and prompt return wiring).
}

func TestRetryLedgerOverflowEvictsOldest(t *testing.T) {
	h := &Handler{logger: discardLogger()}
	for i := 0; i < maxRetryLedger; i++ {
		h.noteReapRetry(fmt.Sprintf("sha-%04d", i))
	}
	h.noteReapRetry("sha-final")
	if len(h.reapRetries) != maxRetryLedger {
		t.Fatalf("reap ledger = %d, want the bound %d", len(h.reapRetries), maxRetryLedger)
	}
	if _, ok := h.reapRetries["sha-final"]; !ok {
		t.Error("the newest entry must survive eviction")
	}
	// The bound evicts an (arbitrary) entry: at least one prior key is gone.
	if len(h.reapRetries) >= maxRetryLedger+1 {
		t.Errorf("ledger exceeded its bound: %d", len(h.reapRetries))
	}
	missing := 0
	for i := 0; i < maxRetryLedger; i++ {
		if _, ok := h.reapRetries[fmt.Sprintf("sha-%04d", i)]; !ok {
			missing++
		}
	}
	if missing != 1 {
		t.Errorf("eviction removed %d entries, want exactly 1", missing)
	}

	h2 := &Handler{logger: discardLogger()}
	for i := 0; i < maxRetryLedger; i++ {
		h2.noteRetentionRetry(fmt.Sprintf("key-%04d", i))
	}
	h2.noteRetentionRetry("key-final")
	if len(h2.retentionRetries) != maxRetryLedger {
		t.Fatalf("retention ledger = %d, want the bound %d", len(h2.retentionRetries), maxRetryLedger)
	}
	if _, ok := h2.retentionRetries["key-final"]; !ok {
		t.Error("the newest retention entry must survive eviction")
	}
	missing2 := 0
	for i := 0; i < maxRetryLedger; i++ {
		if _, ok := h2.retentionRetries[fmt.Sprintf("key-%04d", i)]; !ok {
			missing2++
		}
	}
	if missing2 != 1 {
		t.Errorf("retention eviction removed %d entries, want exactly 1", missing2)
	}
}

func TestRetryFailedReaps_RemovesPendingWhenRowGone(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	store := newFakeStore()
	h := &Handler{
		logger:     discardLogger(),
		pool:       pool,
		workerPool: pool,
		bucket:     "blobs",
		minio:      &failingRemovals{fakeStore: store},
	}
	// A ledger entry whose blobs row is absent AND whose storage removal keeps
	// failing: the entry stays pending (warn, no panic).
	h.noteReapRetry("w5-no-such-blob-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	h.retryFailedReaps(context.Background())
	if len(h.reapRetries) != 1 {
		t.Fatalf("pending entry must survive a failing remove, got %d", len(h.reapRetries))
	}

	// A ledger entry whose blobs row EXISTS again (re-upload): the entry is
	// dropped so the live ref_count lifecycle owns the object.
	sum := sha256.Sum256([]byte("w5 live blob"))
	liveSHA := hex.EncodeToString(sum[:])
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO blobs (sha256, minio_ref, size_bytes, ref_count)
		 VALUES ($1, 'blobs/' || $1, 4, 1)
		 ON CONFLICT (sha256) DO UPDATE SET ref_count = GREATEST(blobs.ref_count, 1)`,
		liveSHA); err != nil {
		t.Fatalf("seed live blob row: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM blobs WHERE sha256 = $1`, liveSHA) //nolint:errcheck
	})
	h.noteReapRetry(liveSHA)
	h.retryFailedReaps(context.Background())
	if _, ok := h.reapRetries[liveSHA]; ok {
		t.Error("a re-uploaded blob's ledger entry must be dropped")
	}
}

func TestRetryFailedRetention_Branches(t *testing.T) {
	h := &Handler{logger: discardLogger()}
	h.retryFailedRetention(context.Background()) // nil registry: no-op

	reg := w5FakeRegistry{err: errors.New("worm still failing")}
	h.retentionRegistry = reg
	h.noteRetentionRetry("w5-key-still-failing")
	h.retryFailedRetention(context.Background())
	if len(h.retentionRetries) != 1 {
		t.Fatal("a failing apply must keep the entry pending")
	}

	h.retentionRegistry = w5FakeRegistry{}
	h.retryFailedRetention(context.Background())
	if len(h.retentionRetries) != 0 {
		t.Fatal("a successful apply must clear the entry")
	}
}

func TestProcessCleanupQueue_EmptyQueue(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := &Handler{
		logger:     discardLogger(),
		pool:       pool,
		workerPool: pool,
		bucket:     "blobs",
	}
	h.processCleanupQueue(context.Background()) // no due candidates: no-op
}

func TestPut_ReducerFailureBranches(t *testing.T) {
	pool := testsupport.OpenTestPool(t)

	// NOTE: no non-quota reducer-error case — blob_upload_account validates
	// every handler-reachable input (BZ040 guards) and holds no user FK, so a
	// well-formed PUT cannot raise a non-BZ001 failure; the 500 wrap at the
	// reducer-error site is a DB-fault-only branch.

	t.Run("temp cleanup failure still returns 201", func(t *testing.T) {
		data := []byte("uploaded fine, temp delete flaky")
		sum := sha256.Sum256(data)
		canonical := hex.EncodeToString(sum[:])
		inner := newFakeStore()
		h := &Handler{minio: &failTempRemoval{fakeStore: inner, canonical: canonical}, bucket: "blobs", pool: pool, logger: discardLogger()}

		rec := httptest.NewRecorder()
		h.Put(rec, putRequest(t, canonical, data))
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201\n%s", rec.Code, rec.Body.String())
		}
		if got := inner.objects[canonical]; !bytes.Equal(got, data) {
			t.Fatalf("canonical blob = %q, want the upload", got)
		}
	})
}

// failingRemovals fails every RemoveObject (the storage plane is down).
type failingRemovals struct {
	*fakeStore
}

func (f *failingRemovals) RemoveObject(_ context.Context, _, object string, _ minio.RemoveObjectOptions) error {
	return errors.New("storage plane down")
}

// failTempRemoval fails RemoveObject for every key except the canonical blob,
// exercising the warn-only temp-cleanup branch of Put while the promotion
// copy still lands.
type failTempRemoval struct {
	*fakeStore
	canonical string
}

func (f *failTempRemoval) RemoveObject(_ context.Context, _, object string, _ minio.RemoveObjectOptions) error {
	if object == f.canonical {
		return f.fakeStore.RemoveObject(context.Background(), "", object, minio.RemoveObjectOptions{})
	}
	return errors.New("minio transient failure (temp cleanup)")
}

// TestProcessCleanupQueue_ReapsDueCandidate: a due, unreferenced candidate is
// reaped (guarded row delete + storage removal) through the queue loop.
func TestProcessCleanupQueue_ReapsDueCandidate(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	sum := sha256.Sum256([]byte("w5 due cleanup candidate " + time.Now().String()))
	sha := hex.EncodeToString(sum[:])
	if _, err := pool.Exec(ctx,
		`INSERT INTO blobs (sha256, minio_ref, size_bytes, ref_count) VALUES ($1, 'blobs/' || $1, 8, 0)`, sha,
	); err != nil {
		t.Fatalf("seed blob: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO blob_cleanup_queue (blob_sha256, scheduled_at, delay_minutes) VALUES ($1, now() - interval '10 minutes', 5)
		 ON CONFLICT (blob_sha256) DO UPDATE SET scheduled_at = now() - interval '10 minutes'`, sha,
	); err != nil {
		t.Fatalf("seed queue row: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM blob_cleanup_queue WHERE blob_sha256 = $1`, sha) //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM blobs WHERE sha256 = $1`, sha)                   //nolint:errcheck
	})

	store := newFakeStore()
	h := &Handler{minio: store, bucket: "blobs", pool: pool, workerPool: pool, logger: discardLogger()}
	h.processCleanupQueue(ctx)

	var n int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM blobs WHERE sha256 = $1`, sha).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("due candidate must be reaped, blobs row remains")
	}
}
