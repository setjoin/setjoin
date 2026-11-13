package jmap

// blob_upload_quota_er6_test.go — proofs that the JMAP upload path ENFORCES
// the per-user blob charge bound once SetReclamationPolicy wires it (er6
// residual rollup on occ_2ee199). The blob_upload_account reducer always
// honored p_quota_bytes; the JMAP caller was the last one passing
// enforcement-OFF forever, so uploads here never hit the bound the blob
// gateway enforced on the same bytes. Now: over-bound refused (BZ001 → the
// reducer aborts, persisting no row and no charge), at-bound boundary admits
// exactly, and the zero-value default stays enforcement-OFF (accounting
// still recorded) so unwired callers and unit tests keep the old behavior.
//
// Needs DB_DSN (skipped otherwise), like the other DB-backed jmap tests.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/reducererr"
)

func newQuotaTestHandler(t *testing.T, pool *pgxpool.Pool) *JMAPHandler {
	t.Helper()
	return NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
}

func quotaTestUpload(t *testing.T, h *JMAPHandler, ctx context.Context, userID int64, label string, size int) (sha string, err error) {
	t.Helper()
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i % 251) // deterministic, label-independent content differs by size
	}
	sum := sha256.Sum256(append([]byte(label), body...))
	sha = hex.EncodeToString(sum[:])
	return sha, h.accountUpload(ctx, userID, sha, int64(size), "application/octet-stream")
}

func quotaCleanup(t *testing.T, pool *pgxpool.Pool, shas ...string) {
	t.Helper()
	ctx := context.Background()
	for _, sha := range shas {
		if sha == "" {
			continue
		}
		_, _ = pool.Exec(ctx, `DELETE FROM blob_cleanup_queue WHERE blob_sha256 = $1`, sha) //nolint:errcheck
		_, _ = pool.Exec(ctx, `DELETE FROM blobs WHERE sha256 = $1`, sha)                   //nolint:errcheck
	}
}

// TestJMAPUploadQuotaRefusesOverBound: with a 1000-byte bound, a 600-byte
// upload charges 600; a second 600-byte upload (1200 total) is refused with
// the reducer's registered storage-quota code BZ001 and persists NOTHING —
// no blobs row, no charge, no queue row — while the first upload's charge
// stands untouched.
func TestJMAPUploadQuotaRefusesOverBound(t *testing.T) {
	pool := testPoolDB(t)
	h := newQuotaTestHandler(t, pool)
	h.SetReclamationPolicy(0, 1000)
	ctx := context.Background()

	_, userID, _ := insertTestUserWithMailbox(t, pool, true)

	sha1, err := quotaTestUpload(t, h, ctx, userID, "quota-first-", 600)
	if err != nil {
		t.Fatalf("first upload within bound: %v", err)
	}
	sha2, _ := quotaTestUpload(t, h, ctx, userID, "quota-second-", 600)
	defer quotaCleanup(t, pool, sha1, sha2)

	if err := h.accountUpload(ctx, userID, sha2, 600, "application/octet-stream"); err == nil {
		t.Fatal("second upload past the bound must be refused")
	} else if !reducererr.IsCode(err, "BZ001") {
		t.Fatalf("refusal error = %v, want the BZ001 over_quota code", err)
	}

	var persisted int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM blobs WHERE sha256 = $1`, sha2).Scan(&persisted); err != nil {
		t.Fatalf("count refused blob rows: %v", err)
	}
	if persisted != 0 {
		t.Fatal("a quota-refused upload must persist no blobs row (the reducer aborts whole)")
	}
	var charges int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM blob_user_charges WHERE blob_sha256 = $1`, sha2).Scan(&charges); err != nil {
		t.Fatalf("count refused charge rows: %v", err)
	}
	if charges != 0 {
		t.Fatal("a quota-refused upload must record no charge")
	}
	var charged int64
	if err := pool.QueryRow(ctx,
		`SELECT size_bytes FROM blob_user_charges WHERE blob_sha256 = $1`, sha1).Scan(&charged); err != nil {
		t.Fatalf("read first charge: %v", err)
	}
	if charged != 600 {
		t.Fatalf("first upload charge = %d, want exactly its measured 600", charged)
	}
}

// TestJMAPUploadQuotaBoundaryIsInclusive: charged > bound - measured refuses,
// so filling the bound EXACTLY admits, and the first byte past it refuses.
// Also pins the reclamation-grace pass-through (90 minutes lands in the
// armed queue row) in the same wired-policy call.
func TestJMAPUploadQuotaBoundaryIsInclusive(t *testing.T) {
	pool := testPoolDB(t)
	h := newQuotaTestHandler(t, pool)
	h.SetReclamationPolicy(90, 1000)
	ctx := context.Background()

	_, userID, _ := insertTestUserWithMailbox(t, pool, true)

	sha1, err := quotaTestUpload(t, h, ctx, userID, "quota-boundary-a-", 600)
	if err != nil {
		t.Fatalf("600 of 1000: %v", err)
	}
	sha2, err := quotaTestUpload(t, h, ctx, userID, "quota-boundary-b-", 400)
	defer quotaCleanup(t, pool, sha1, sha2)
	if err != nil {
		t.Fatalf("filling the bound exactly (600+400=1000) must admit: %v", err)
	}

	sha3, _ := quotaTestUpload(t, h, ctx, userID, "quota-boundary-c-", 1)
	defer quotaCleanup(t, pool, sha3)
	if err := h.accountUpload(ctx, userID, sha3, 1, "application/octet-stream"); err == nil {
		t.Fatal("one byte past the filled bound must be refused")
	} else if !reducererr.IsCode(err, "BZ001") {
		t.Fatalf("boundary refusal error = %v, want BZ001", err)
	}

	var delayMinutes int
	if err := pool.QueryRow(ctx,
		`SELECT delay_minutes FROM blob_cleanup_queue WHERE blob_sha256 = $1`, sha1).Scan(&delayMinutes); err != nil {
		t.Fatalf("read armed queue row: %v", err)
	}
	if delayMinutes != 90 {
		t.Fatalf("armed grace delay = %d minutes, want the configured 90", delayMinutes)
	}
}

// TestJMAPUploadQuotaZeroStaysOff: the zero-value (or explicitly zero)
// policy keeps enforcement OFF — an upload of any size succeeds and its
// accounting is still recorded — the pre-wiring contract that unit tests and
// unwired callers rely on.
func TestJMAPUploadQuotaZeroStaysOff(t *testing.T) {
	pool := testPoolDB(t)
	h := newQuotaTestHandler(t, pool)
	h.SetReclamationPolicy(0, 0) // explicit zero: same as never wired
	ctx := context.Background()

	_, userID, _ := insertTestUserWithMailbox(t, pool, true)

	sha1, err := quotaTestUpload(t, h, ctx, userID, "quota-off-a-", 5000)
	if err != nil {
		t.Fatalf("unbounded upload (zero policy): %v", err)
	}
	sha2, err := quotaTestUpload(t, h, ctx, userID, "quota-off-b-", 5000)
	defer quotaCleanup(t, pool, sha1, sha2)
	if err != nil {
		t.Fatalf("second unbounded upload (zero policy): %v", err)
	}

	var total int64
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(size_bytes), 0) FROM blob_user_charges WHERE user_id = $1`, userID).Scan(&total); err != nil {
		t.Fatalf("sum charges: %v", err)
	}
	if total != 10000 {
		t.Fatalf("enforcement-OFF charges = %d, want the full measured 10000", total)
	}
}
