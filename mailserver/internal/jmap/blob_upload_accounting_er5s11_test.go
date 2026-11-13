package jmap

// blob_upload_accounting_er5s11_test.go — proofs that the JMAP upload's DB
// bookkeeping runs through the shared blob_upload_account reducer (er5-s11,
// sealed anchor jmap-uploads-create-permanent-positive-blob-references... /
// occ_2ee199e390abb01bc5780bf5). The superseded inline INSERT persisted every
// upload at ref_count=1 with NO owner, NO charge, and NO reclamation arming —
// an uploaded-but-never-attached blob was a permanent positive reference no
// cleanup path could ever see. Now: ref_count=0 + an armed blob_cleanup_queue
// row (reclaimed after the grace window unless attached) + a per-user charge
// (the ownership evidence Email/set's attachment gate keys on).
//
// Needs DB_DSN (skipped otherwise), like the other DB-backed jmap tests.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"setjoin.com/shared/pgxutil"
)

// TestJMAPUploadAccountingArmsReclamationAndCharges: one accountUpload call
// lands the three bookkeeping facts the reducer owns — the blobs row at
// ref_count=0 (an upload is NOT yet a reference), the caller's byte charge,
// and the armed cleanup-queue row.
func TestJMAPUploadAccountingArmsReclamationAndCharges(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	ctx := context.Background()

	_, userID, _ := insertTestUserWithMailbox(t, pool, true)

	sum := sha256.Sum256([]byte("upload-accounting-" + randomSuffixDB(t)))
	sha := hex.EncodeToString(sum[:])
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM blobs WHERE sha256 = $1`, sha) //nolint:errcheck
	})

	if err := h.accountUpload(ctx, userID, sha, 4321, "text/plain"); err != nil {
		t.Fatalf("accountUpload: %v", err)
	}

	var refCount int
	if err := pool.QueryRow(ctx,
		`SELECT ref_count FROM blobs WHERE sha256 = $1`, sha).Scan(&refCount); err != nil {
		t.Fatalf("blobs row missing after accounting: %v", err)
	}
	if refCount != 0 {
		t.Errorf("an upload must persist ref_count=0 (attaching bumps it), got %d", refCount)
	}

	var chargedUserID int64
	var chargedBytes int64
	if err := pool.QueryRow(ctx,
		`SELECT user_id, size_bytes FROM blob_user_charges WHERE blob_sha256 = $1`, sha,
	).Scan(&chargedUserID, &chargedBytes); err != nil {
		t.Fatalf("no per-user charge row after accounting: %v", err)
	}
	if chargedUserID != userID || chargedBytes != 4321 {
		t.Errorf("charge = (%d, %d), want (%d, 4321)", chargedUserID, chargedBytes, userID)
	}

	var queueRows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM blob_cleanup_queue WHERE blob_sha256 = $1`, sha,
	).Scan(&queueRows); err != nil {
		t.Fatalf("read cleanup queue: %v", err)
	}
	if queueRows != 1 {
		t.Errorf("want exactly 1 armed reclamation row, got %d", queueRows)
	}
}

// TestJMAPUploadAccountingRerunsAreDedupSafe: re-accounting identical content
// (a dedup re-upload) must neither double-charge nor stack queue rows —
// the reducer's ON CONFLICT DO NOTHING admission.
func TestJMAPUploadAccountingRerunsAreDedupSafe(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	ctx := context.Background()

	_, userID, _ := insertTestUserWithMailbox(t, pool, true)

	sum := sha256.Sum256([]byte("upload-dedup-" + randomSuffixDB(t)))
	sha := hex.EncodeToString(sum[:])
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM blobs WHERE sha256 = $1`, sha) //nolint:errcheck
	})

	if err := h.accountUpload(ctx, userID, sha, 100, "text/plain"); err != nil {
		t.Fatalf("first accountUpload: %v", err)
	}
	if err := h.accountUpload(ctx, userID, sha, 100, "text/plain"); err != nil {
		t.Fatalf("second accountUpload: %v", err)
	}

	var charges int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM blob_user_charges WHERE blob_sha256 = $1`, sha).Scan(&charges); err != nil {
		t.Fatalf("count charges: %v", err)
	}
	if charges != 1 {
		t.Errorf("dedup re-upload must not double-charge, got %d charge rows", charges)
	}
	var queueRows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM blob_cleanup_queue WHERE blob_sha256 = $1`, sha).Scan(&queueRows); err != nil {
		t.Fatalf("count queue rows: %v", err)
	}
	if queueRows != 1 {
		t.Errorf("dedup re-upload must not stack reclamation rows, got %d", queueRows)
	}
}

// TestJMAPUploadBodyCap: the upload admission cap comes from the configured
// maxSizeUpload, with the legacy 100 MiB ceiling as the zero-value fallback.
func TestJMAPUploadBodyCap(t *testing.T) {
	if got := jmapUploadBodyCap(0); got != 100<<20 {
		t.Errorf("jmapUploadBodyCap(0) = %d, want the 100 MiB fallback", got)
	}
	if got := jmapUploadBodyCap(5_000_000); got != 5_000_000 {
		t.Errorf("jmapUploadBodyCap(5_000_000) = %d, want 5_000_000", got)
	}
	if got := jmapUploadBodyCap(-1); got != 100<<20 {
		t.Errorf("jmapUploadBodyCap(-1) = %d, want the 100 MiB fallback (never a negative cap)", got)
	}
}
