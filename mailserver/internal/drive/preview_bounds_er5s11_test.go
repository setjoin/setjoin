package drive

// preview_bounds_er5s11_test.go — input/output admission-bound proofs for the
// preview worker (er5-s11, sealed anchor cand-drive-preview-exhaustion /
// occ_44691719e73fbbc9802f0908 + occ_6216236af2196172fe689736). Without the
// bounds, one oversized office version turned a render into an unbounded
// plaintext temp-file write and one oversized sidecar product into an
// unbounded heap buffer + unbounded chunk storage. Both bounds fail the
// version 'failed' BEFORE any preview byte is stored.
//
// DB-backed (skips cleanly when DB_DSN is unset), same genre as
// preview_test.go.

import (
	"context"
	"testing"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// lowerPreviewBounds shrinks both admission bounds for the duration of one
// test (they are package vars purely as this test seam) and restores them on
// cleanup.
func lowerPreviewBounds(t *testing.T, sourceBytes, outputBytes int64) {
	t.Helper()
	oldSource, oldOutput := maxPreviewSourceBytes, maxPreviewOutputBytes
	maxPreviewSourceBytes, maxPreviewOutputBytes = sourceBytes, outputBytes
	t.Cleanup(func() {
		maxPreviewSourceBytes, maxPreviewOutputBytes = oldSource, oldOutput
	})
}

// TestPreviewWorkerInputBoundRejectsOversizedSource: a version whose assembled
// source exceeds the input bound fails without a sidecar run and without a
// single preview chunk stored.
func TestPreviewWorkerInputBoundRejectsOversizedSource(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "dpvw-bound-in")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)
	versionID := driveLiveOfficeVersion(t, pool, h, userID, spaceID, "big.docx")

	// The fixture uploads ~18 bytes of content; a 4-byte bound is over it.
	lowerPreviewBounds(t, 4, 64<<20)

	ctx := context.Background()
	if _, err := pool.Exec(ctx, `SELECT drive_preview_request($1, $2)`, userID, versionID); err != nil {
		t.Fatalf("drive_preview_request: %v", err)
	}
	// drive_preview_request may return 'pending' or immediately 'ready' —
	// force 'pending' so the worker claims it.
	if _, err := pool.Exec(ctx, `UPDATE drive_file_versions SET preview_status='pending' WHERE id=$1`, versionID); err != nil {
		t.Fatalf("force pending: %v", err)
	}

	w := NewPreviewWorker(pgxutil.WorkerPool{Pool: pool}, fake, "b", writePreviewCmdScript(t, 0), discardLogger())
	w.tick(ctx)

	var status string
	if err := pool.QueryRow(ctx, `SELECT preview_status FROM drive_file_versions WHERE id=$1`, versionID).Scan(&status); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if status != "failed" {
		t.Fatalf("oversized source must fail the version, got preview_status=%s", status)
	}
	// putKeys also carries the fixture's content-chunk uploads (tmp/upload/*);
	// the bound must have prevented any PREVIEW-stream chunk ("drive/…" keys).
	for _, k := range fake.putKeys {
		if len(k) > 6 && k[:6] == "drive/" {
			t.Errorf("no preview byte may be stored for a rejected source, got PutObject %q", k)
		}
	}
}

// TestPreviewWorkerOutputBoundRejectsOversizedPDF: a sidecar product over the
// output bound is refused after stat, before any ReadFile buffering or chunk
// storage — the version lands 'failed' with nothing persisted.
func TestPreviewWorkerOutputBoundRejectsOversizedPDF(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "dpvw-bound-out")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)
	versionID := driveLiveOfficeVersion(t, pool, h, userID, spaceID, "renders-big.pdf")

	// The fake sidecar writes the ~5.4 KiB fixturePDF; a 1 KiB output bound is
	// under it. Source stays generous so only the OUTPUT leg fires.
	lowerPreviewBounds(t, 64<<20, 1024)

	ctx := context.Background()
	if _, err := pool.Exec(ctx, `SELECT drive_preview_request($1, $2)`, userID, versionID); err != nil {
		t.Fatalf("drive_preview_request: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE drive_file_versions SET preview_status='pending' WHERE id=$1`, versionID); err != nil {
		t.Fatalf("force pending: %v", err)
	}

	w := NewPreviewWorker(pgxutil.WorkerPool{Pool: pool}, fake, "b", writePreviewCmdScript(t, 0), discardLogger())
	w.tick(ctx)

	var status string
	if err := pool.QueryRow(ctx, `SELECT preview_status FROM drive_file_versions WHERE id=$1`, versionID).Scan(&status); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if status != "failed" {
		t.Fatalf("oversized rendition must fail the version, got preview_status=%s", status)
	}
	for _, k := range fake.putKeys {
		if len(k) > 6 && k[:6] == "drive/" {
			t.Errorf("no oversized rendition byte may be stored, got PutObject %q", k)
		}
	}
}

// TestBoundedWriterEnforcesLimit: the copy-time bound fails at exactly the
// limit even when the source reader keeps producing (a lying manifest cannot
// round the upfront declared-size check).
func TestBoundedWriterEnforcesLimit(t *testing.T) {
	sink := &countingSink{}
	bw := &boundedWriter{w: sink, limit: 10}
	if _, err := bw.Write(make([]byte, 10)); err != nil {
		t.Fatalf("write at exactly the limit must succeed: %v", err)
	}
	if _, err := bw.Write(make([]byte, 1)); err == nil {
		t.Fatal("write past the limit must fail")
	}
	if sink.n != 10 {
		t.Errorf("the failing write must not have delivered bytes, sink has %d", sink.n)
	}
}

type countingSink struct{ n int }

func (c *countingSink) Write(p []byte) (int, error) {
	c.n += len(p)
	return len(p), nil
}
