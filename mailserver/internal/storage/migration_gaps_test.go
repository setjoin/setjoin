package storage

// Migration gap coverage: the blobRows loader seam's pool requirement and
// real query, the legacy per-instance Cancel/status paths over the real test
// database, the run/backfill failure outcome, the boundedKeys log cap, the
// copyRows cursor-error and per-1000 progress branches, and the
// discardPartial/verifyBlob integrity-failure paths.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"

	"setjoin.com/shared/testsupport"
)

func gapLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func gapMovers() (*blockingMover, *blockingMover, *eventLog) {
	events := &eventLog{}
	return newBlockingMover(events), newBlockingMover(events), events
}

// TestMigrationBlobRowsRequiresPool pins the seam's fail-closed default: a
// pool-free Migration cannot load the backfill cursor.
func TestMigrationBlobRowsRequiresPool(t *testing.T) {
	src, tgt, _ := gapMovers()
	m := NewMigration(nil, src, tgt, gapLogger())
	rows, err := m.blobRows(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no database pool configured") {
		t.Fatalf("blobRows without a pool = (%v, %v), want the pool error", rows, err)
	}
}

// TestMigrationBlobRowsLoadsFromDatabase covers the real loader: the pool
// fallback queries the blobs cursor (an empty result set is fine).
func TestMigrationBlobRowsLoadsFromDatabase(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	src, tgt, _ := gapMovers()
	m := NewMigration(pool, src, tgt, gapLogger())
	rows, err := m.blobRows(t.Context())
	if err != nil {
		t.Fatalf("blobRows against the test database: %v", err)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("cursor Err: %v", err)
	}
}

// TestLegacyMigrationCancelStatusPaths drives the legacy per-instance
// lifecycle over the real test DB: the detached setStatus pool fallback, the
// cancelFn delivery, the successful cancel flip, the terminal refusal and
// the unknown-row error.
func TestLegacyMigrationCancelStatusPaths(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	src, tgt, _ := gapMovers()
	m := NewMigration(pool, src, tgt, gapLogger()) // statusDB nil → pool fallback

	insert := func(status string) int64 {
		t.Helper()
		var id int64
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO storage_migrations (source_driver, target_driver, status)
			 VALUES ('blocking', 'blocking', $1) RETURNING id`, status).Scan(&id); err != nil {
			t.Fatalf("insert migration row: %v", err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DELETE FROM storage_migrations WHERE id = $1`, id)
		})
		return id
	}

	// setStatus with no statusDB falls back to the pool (the detached write
	// survives cancellation by construction — the ctx here is cancelled).
	id := insert("dual_write")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.setStatus(ctx, id, MigBackfill)
	var status string
	if err := pool.QueryRow(t.Context(),
		`SELECT status FROM storage_migrations WHERE id = $1`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != string(MigBackfill) {
		t.Fatalf("detached setStatus wrote %q, want backfill — cancellation must not swallow the write", status)
	}

	// Cancel delivers the stop function and flips a transitional row.
	called := false
	m.cancelFn = func() { called = true }
	if err := m.Cancel(id); err != nil {
		t.Fatalf("legacy Cancel of a pending row: %v", err)
	}
	if !called {
		t.Fatal("legacy Cancel never invoked the stop function")
	}
	if err := pool.QueryRow(t.Context(),
		`SELECT status FROM storage_migrations WHERE id = $1`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != string(MigCancelled) {
		t.Fatalf("legacy Cancel wrote %q, want cancelled", status)
	}

	// A row resting at cutover is refused, unchanged.
	cutoverID := insert("cutover")
	m.cancelFn = nil
	if err := m.Cancel(cutoverID); !errors.Is(err, ErrNotCancellable) {
		t.Fatalf("legacy Cancel at cutover = %v, want ErrNotCancellable", err)
	}

	// An unknown row surfaces the scan error.
	if err := m.Cancel(99999999); err == nil {
		t.Fatal("legacy Cancel of an unknown row returned nil")
	}
}

// TestLegacyMigrationStatusReadModel covers the legacy Status map over the
// real database (progress omitted while total is zero).
func TestLegacyMigrationStatusReadModel(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	src, tgt, _ := gapMovers()
	m := NewMigration(pool, src, tgt, gapLogger())
	var id int64
	if err := pool.QueryRow(t.Context(),
		`INSERT INTO storage_migrations (source_driver, target_driver, status, total_blobs, migrated)
		 VALUES ('blocking', 'blocking', 'dual_write', 0, 0) RETURNING id`).Scan(&id); err != nil {
		t.Fatalf("insert migration row: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM storage_migrations WHERE id = $1`, id)
	})
	res, err := m.Status(t.Context(), id)
	if err != nil {
		t.Fatalf("legacy Status: %v", err)
	}
	if res["status"] != "dual_write" || res["id"] != id {
		t.Fatalf("legacy Status = %v", res)
	}
	if _, err := m.Status(t.Context(), 99999999); err == nil {
		t.Fatal("legacy Status of an unknown row returned nil error")
	}
}

// TestMigrationRunBackfillErrorPublishesFailed pins the run outcome: a
// cursor-load failure is a failed migration (never stranded at backfill and
// never a cutover).
func TestMigrationRunBackfillErrorPublishesFailed(t *testing.T) {
	src, tgt, _ := gapMovers()
	m := NewMigration(nil, src, tgt, gapLogger())
	store := &fakeMigratorStore{}
	m.statusDB = store
	cause := errors.New("cursor load refused")
	m.blobRows = func(ctx context.Context) (scanCursor, error) { return nil, cause }

	m.run(context.Background(), 1)

	if !hasStatusWrite(store, MigFailed) {
		t.Fatalf("statuses written = %v, want a failed terminal write", store.execSnapshot())
	}
	if hasStatusWrite(store, MigCutover) {
		t.Fatal("a failed backfill must never publish cutover")
	}
	if got := m.outcome(); got != MigFailed {
		t.Fatalf("outcome = %q, want failed", got)
	}
}

// TestBackfillPublishesProgressThroughPool covers the backfill tail: after a
// clean copy the migrated/total counts land through the pool.
func TestBackfillPublishesProgressThroughPool(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	src, tgt, _ := gapMovers()
	m := NewMigration(pool, src, tgt, gapLogger())
	var id int64
	if err := pool.QueryRow(t.Context(),
		`INSERT INTO storage_migrations (source_driver, target_driver, status)
		 VALUES ('blocking', 'blocking', 'backfill') RETURNING id`).Scan(&id); err != nil {
		t.Fatalf("insert migration row: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM storage_migrations WHERE id = $1`, id)
	})

	key := sha256Hex("progress-blob")
	data := []byte("progress-blob")
	tgt.objs[key] = data // pre-verified target: the copy is counted, not rewritten
	m.blobRows = func(ctx context.Context) (scanCursor, error) {
		return &closingRows{&reconRows{keys: []string{key}, sizes: []int64{int64(len(data))}}}, nil
	}

	migrated, failed, err := m.backfill(t.Context(), id)
	if err != nil || len(failed) != 0 || migrated != 1 {
		t.Fatalf("backfill = (%d, %v, %v)", migrated, failed, err)
	}
	var migratedCol, totalCol int64
	if err := pool.QueryRow(t.Context(),
		`SELECT migrated, total_blobs FROM storage_migrations WHERE id = $1`, id).
		Scan(&migratedCol, &totalCol); err != nil {
		t.Fatal(err)
	}
	if migratedCol != 1 || totalCol != 1 {
		t.Fatalf("progress columns = (%d, %d), want (1, 1)", migratedCol, totalCol)
	}
}

func TestBoundedKeysCapsLogEnumeration(t *testing.T) {
	keys := make([]string, 25)
	for i := range keys {
		keys[i] = "aa"
	}
	if got := boundedKeys(keys, 20); len(got) != 20 {
		t.Fatalf("boundedKeys(25) = %d keys, want the 20-key cap", len(got))
	}
	short := []string{"aa", "bb"}
	if got := boundedKeys(short, 20); len(got) != 2 {
		t.Fatalf("boundedKeys(2) truncated to %d", len(got))
	}
}

// errAtEndRows consumes normally then reports a cursor error — the tail the
// copy loop must surface as a hard error, not a clean stop.
type errAtEndRows struct {
	reconRows
	cursorErr error
}

func (r *errAtEndRows) Err() error { return r.cursorErr }

func TestCopyRowsSurfacesCursorError(t *testing.T) {
	src, tgt, _ := gapMovers()
	m := NewMigration(nil, src, tgt, gapLogger())
	rows := &errAtEndRows{cursorErr: errors.New("connection reset mid-cursor")}
	migrated, failed, err := m.copyRows(context.Background(), rows, 0)
	if err == nil || !strings.Contains(err.Error(), "cursor error") {
		t.Fatalf("copyRows = (%d, %v, %v), want the wrapped cursor error", migrated, failed, err)
	}
	if !errors.Is(err, rows.cursorErr) {
		t.Fatalf("cursor error %v does not wrap the cause", err)
	}
}

// TestCopyRowsProgressTickAtThousand covers the per-1000 progress write with
// a real pool and a thousand FRESH copies: the tick fires on the post-copy
// increment (pre-verified skips never reach it), at exactly migrated==1000.
func TestCopyRowsProgressTickAtThousand(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	src, tgt, _ := gapMovers()
	close(tgt.putGate) // the 1000 sequential writes must pass straight through
	m := NewMigration(pool, src, tgt, gapLogger())

	const n = 1000
	keys := make([]string, n)
	sizes := make([]int64, n)
	for i := 0; i < n; i++ {
		data := []byte("blob-" + strconv.Itoa(i))
		key := sha256Hex(string(data))
		keys[i], sizes[i] = key, int64(len(data))
		src.objs[key] = data // fresh copy: target starts empty
	}
	migrated, failed, err := m.copyRows(t.Context(), &reconRows{keys: keys, sizes: sizes}, 1)
	if err != nil || len(failed) != 0 {
		t.Fatalf("copyRows = (%d, %v, %v)", migrated, failed, err)
	}
	if migrated != n {
		t.Fatalf("migrated = %d, want %d verified copies", migrated, n)
	}
	if len(tgt.puts) != n {
		t.Fatalf("target received %d writes, want %d (all fresh copies)", len(tgt.puts), n)
	}
}

// failingDeleteMover overrides DeleteObject to fail (the unverified-copy
// cleanup path must survive a broken delete).
type failingDeleteMover struct {
	*blockingMover
	err error
}

func (f *failingDeleteMover) DeleteObject(context.Context, string) error { return f.err }

func TestDiscardPartialSurvivesDeleteFailure(t *testing.T) {
	src, tgt, _ := gapMovers()
	want := errors.New("delete refused")
	m := NewMigration(nil, src, &failingDeleteMover{blockingMover: tgt, err: want}, gapLogger())
	// No panic, no error surface: best-effort by contract.
	m.discardPartial(context.Background(), "aa")
}

// errBodyMover serves a reader that fails mid-read (a corrupt source body).
type errBodyMover struct {
	*blockingMover
	cause error
}

func (f *errBodyMover) GetObject(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(iotest.ErrReader(f.cause)), nil
}

func TestVerifyBlobRejectsUnreadableBody(t *testing.T) {
	_, tgt, _ := gapMovers()
	cause := errors.New("disk error mid-read")
	mover := &errBodyMover{blockingMover: tgt, cause: cause}
	if err := verifyBlob(context.Background(), mover, sha256Hex("x"), 1); !errors.Is(err, cause) {
		t.Fatalf("verifyBlob = %v, want the read cause", err)
	}
}
