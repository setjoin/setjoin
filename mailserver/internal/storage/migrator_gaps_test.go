package storage

// Migrator gap coverage: constructor defaults, admission validation and
// INSERT failure, the Cancel post-join outcome refusal for a run that rests
// at a non-cancelled, non-cutover outcome, the Migrator.Status read model,
// the Shutdown pending-admission branches (second admission resolving after
// the drain deadline fired; outer-ctx cancellation during the pending wait),
// and the Recover scan/write failure branches. Uses the lifecycle fakes — no
// database.

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/shared/testsupport"
)

// ── additional fakes ─────────────────────────────────────────────────────

// errInsertStore fails every admission INSERT while delegating everything
// else to the base fake — the durable-admission failure path of Start.
type errInsertStore struct {
	*fakeMigratorStore
	cause error
}

func (f *errInsertStore) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if strings.Contains(sql, "INSERT INTO storage_migrations") {
		return fakeRow{err: f.cause}
	}
	return f.fakeMigratorStore.QueryRow(ctx, sql, args...)
}

// statusReadStore serves the Migrator.Status read-model SELECT from a fixed
// row, delegating everything else to the base fake.
type statusReadStore struct {
	*fakeMigratorStore
	status    string
	total     int64
	migrated  int64
	lastKey   *string
	started   time.Time
	completed *time.Time
}

func (f *statusReadStore) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if strings.Contains(sql, "total_blobs") {
		return statusReadRow{f}
	}
	return f.fakeMigratorStore.QueryRow(ctx, sql, args...)
}

type statusReadRow struct{ f *statusReadStore }

func (r statusReadRow) Scan(dest ...any) error {
	*dest[0].(*string) = r.f.status
	*dest[1].(*int64) = r.f.total
	*dest[2].(*int64) = r.f.migrated
	*dest[3].(**string) = r.f.lastKey
	*dest[4].(*time.Time) = r.f.started
	*dest[5].(**time.Time) = r.f.completed
	return nil
}

// errExecStore fails every Exec (the Recover reclaim write failure path).
type errExecStore struct {
	*fakeMigratorStore
	cause error
}

func (f *errExecStore) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag(""), f.cause
}

// brokenScanRows is a scanCursor yielding exactly one row whose Scan fails
// (a corrupted orphan row) — Next must terminate so Recover's loop ends.
type brokenScanRows struct {
	err   error
	first bool
}

func (r *brokenScanRows) Next() bool {
	if r.first {
		return false
	}
	r.first = true
	return true
}
func (r *brokenScanRows) Scan(dest ...any) error { return r.err }
func (r *brokenScanRows) Err() error             { return nil }
func (r *brokenScanRows) Close()                 {}

// ── constructor defaults ─────────────────────────────────────────────────

func TestNewMigratorDefaults(t *testing.T) {
	m := NewMigrator(nil, nil, nil)
	if m.lifecycle == nil {
		t.Fatal("nil lifecycle must default to a live context")
	}
	if m.logger == nil {
		t.Fatal("nil logger must default to slog.Default")
	}
	if m.store != nil {
		t.Fatal("nil pool must leave the store unset")
	}
	if m.terminateProcess == nil {
		t.Fatal("terminateProcess seam must default to production os.Exit")
	}

	// A pool-backed constructor wires the pool as the store (the struct
	// satisfies migratorStore) — asserted through Start's validation below.
	if _, err := m.Start(context.Background(), nil, nil); err == nil ||
		!strings.Contains(err.Error(), "source and target drivers are required") {
		t.Fatalf("Start(nil, nil) = %v, want the driver-validation error", err)
	}
}

// ── admission validation and INSERT failure ──────────────────────────────

func TestStartWithoutStoreRejected(t *testing.T) {
	m := NewMigrator(context.Background(), nil, nil) // no store injected
	_, err := m.Start(context.Background(), newBlockingMover(&eventLog{}), newBlockingMover(&eventLog{}))
	if err == nil || !strings.Contains(err.Error(), "no database store configured") {
		t.Fatalf("Start without a store = %v, want the store error", err)
	}
}

func TestStartInsertFailureResolvesPending(t *testing.T) {
	f := newLifecycleFixture(t, 31)
	cause := errors.New("admission refused by policy")
	f.mg.store = &errInsertStore{fakeMigratorStore: f.store, cause: cause}

	id, err := f.mg.Start(context.Background(), f.src, f.target)
	if !errors.Is(err, cause) {
		t.Fatalf("Start = (%d, %v), want the wrapped admission cause", id, err)
	}
	if !strings.Contains(err.Error(), "record start") {
		t.Fatalf("admission error %v does not name the record-start wrap", err)
	}
	f.mg.mu.Lock()
	defer f.mg.mu.Unlock()
	if len(f.mg.pendingAdmissions) != 0 {
		t.Fatalf("failed admission left %d pending entries — it must resolve out of the pending list", len(f.mg.pendingAdmissions))
	}
	if len(f.mg.runs) != 0 {
		t.Fatal("failed admission registered a run")
	}
}

// ── Cancel: post-join outcome refusal for other outcomes ────────────────

func TestCancelPostJoinRefusesNonCancelledOutcome(t *testing.T) {
	f := newLifecycleFixture(t, 17)

	// A drained run whose selected outcome is `failed` (not cancelled, not
	// cutover): the handshake must report the typed refusal, never a false
	// cancelled success and never the raw nil.
	mig := NewMigration(nil, f.src, f.target, f.mg.logger)
	mig.statusDB = f.store
	mig.lastStatus = MigFailed
	done := make(chan struct{})
	close(done)
	run := &migrationRun{id: 17, ctx: context.Background(), cancel: func() {}, done: done, mig: mig}
	f.mg.mu.Lock()
	f.mg.runs[17] = run
	f.mg.mu.Unlock()
	f.store.statuses[17] = string(MigBackfill)

	err := f.mg.Cancel(context.Background(), 17)
	if !errors.Is(err, ErrNotCancellable) {
		t.Fatalf("Cancel against a failed-outcome run = %v, want ErrNotCancellable", err)
	}
	if !strings.Contains(err.Error(), "not the cancelled outcome") {
		t.Fatalf("refusal %v does not name the non-cancelled outcome", err)
	}
}

// ── Status read model ────────────────────────────────────────────────────

func TestStatusWithoutStoreRejected(t *testing.T) {
	m := NewMigrator(context.Background(), nil, nil)
	if _, err := m.Status(context.Background(), 1); err == nil ||
		!strings.Contains(err.Error(), "no database store configured") {
		t.Fatalf("Status without a store = %v, want the store error", err)
	}
	// rowStatus shares the guard: Cancel against a store-less migrator maps
	// the failure onto the unknown-migration problem.
	if err := m.Cancel(context.Background(), 1); !errors.Is(err, ErrUnknownMigration) {
		t.Fatalf("Cancel without a store = %v, want ErrUnknownMigration", err)
	}
}

func TestStatusReadModelFields(t *testing.T) {
	f := newLifecycleFixture(t, 23)
	completed := time.Unix(1700000000, 0)
	lastKey := "ff00"
	base := &statusReadStore{
		fakeMigratorStore: f.store,
		status:            string(MigBackfill),
		total:             200,
		migrated:          50,
		lastKey:           &lastKey,
		started:           time.Unix(1699999000, 0),
		completed:         &completed,
	}
	f.mg.store = base

	res, err := f.mg.Status(context.Background(), 23)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if res["status"] != string(MigBackfill) || res["total"] != int64(200) || res["migrated"] != int64(50) {
		t.Fatalf("Status core fields = %v", res)
	}
	if res["last_key"] != lastKey || res["completed"] != completed {
		t.Fatalf("Status optional fields = %v", res)
	}
	pct, ok := res["progress_pct"].(float64)
	if !ok || pct != 25.0 {
		t.Fatalf("progress_pct = %v, want 25.0", res["progress_pct"])
	}

	// Nil pointers and a zero total omit the optional keys entirely.
	base.lastKey, base.completed, base.total = nil, nil, 0
	res, err = f.mg.Status(context.Background(), 23)
	if err != nil {
		t.Fatalf("Status (minimal row): %v", err)
	}
	if _, ok := res["last_key"]; ok {
		t.Fatal("nil last_key must be omitted")
	}
	if _, ok := res["completed"]; ok {
		t.Fatal("nil completed_at must be omitted")
	}
	if _, ok := res["progress_pct"]; ok {
		t.Fatal("zero total must omit progress_pct")
	}

	// Unknown row → the raw scan error surfaces.
	f.mg.store = f.store // base fake serves ErrNoRows for unknown SELECTs
	if _, err := f.mg.Status(context.Background(), 9999); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("Status(unknown) = %v, want ErrNoRows", err)
	}
}

// TestStatusNullTotalBlobsFreshRow is the D-4 regression: a freshly admitted
// storage_migrations row (the exact INSERT Start performs — total_blobs NULL,
// migrated defaulted) must yield a DEFINED Status read model, not the
// "cannot scan NULL into *int64" scan error that previously errored admin
// Status against a just-started migration. The defined shape is the read
// model's existing not-started form: total 0 / migrated 0 with progress_pct
// omitted (the zero-total contract), status and started_at present.
func TestStatusNullTotalBlobsFreshRow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	var id int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO storage_migrations (source_driver, target_driver, status)
		 VALUES ('d4-null-regression', 'd4-null-regression', 'dual_write') RETURNING id`,
	).Scan(&id); err != nil {
		t.Fatalf("seed fresh storage_migrations row: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM storage_migrations WHERE id = $1`, id)
	})

	legacy := NewMigration(pool, nil, nil, gapLogger())
	legacyResult, err := legacy.Status(ctx, id)
	if err != nil {
		t.Fatalf("legacy Status on a NULL-total row: %v", err)
	}
	if legacyResult["total"] != int64(0) || legacyResult["migrated"] != int64(0) {
		t.Fatalf("legacy not-started counters: %v", legacyResult)
	}
	if _, exists := legacyResult["progress_pct"]; exists {
		t.Fatalf("legacy not-started projection invents progress: %v", legacyResult)
	}
	m := NewMigrator(context.Background(), pool, gapLogger())
	res, err := m.Status(ctx, id)
	if err != nil {
		t.Fatalf("Status on a NULL-total_blobs row = %v, want a defined read model (D-4)", err)
	}
	if res["status"] != string(MigDualWrite) {
		t.Errorf("status = %v, want dual_write", res["status"])
	}
	if res["total"] != int64(0) || res["migrated"] != int64(0) {
		t.Errorf("total/migrated = %v/%v, want 0/0 (NULL coalesced to the not-started shape)", res["total"], res["migrated"])
	}
	if _, ok := res["progress_pct"]; ok {
		t.Error("progress_pct must stay omitted for a not-started (total 0) row")
	}
	if _, ok := res["started"]; !ok {
		t.Error("started_at must still be present on the fresh row")
	}
	if _, ok := res["last_key"]; ok {
		t.Error("last_key must stay omitted (NULL) on the fresh row")
	}
}

// ── Shutdown pending-admission branches ─────────────────────────────────

// TestShutdownSecondPendingAdmissionResolvesAfterDeadlineFired pins the
// first-pass deadline branch: once the drain budget is burned by a stalled
// admission, a SECOND admission that resolves deadline-free still folds its
// run into the drain set instead of escaping the snapshot.
func TestShutdownSecondPendingAdmissionResolvesAfterDeadlineFired(t *testing.T) {
	f := newLifecycleFixture(t, 41)
	key := sha256Hex("second-pending")
	f.src.objs[key] = []byte("second-pending")

	f.openRun(t, context.Background(), []string{key}, []int64{int64(len("second-pending"))})
	waitForPutStarted(t, f.target)
	f.store.insertGate = make(chan struct{})

	loaderGate := make(chan struct{})
	f.mg.newMigration = func(source, target blobMover) *Migration {
		mig := NewMigration(nil, source, target, f.mg.logger)
		mig.statusDB = f.store
		mig.blobRows = func(ctx context.Context) (scanCursor, error) {
			<-loaderGate
			return &closingRows{&reconRows{keys: []string{key}, sizes: []int64{int64(len("second-pending"))}}}, nil
		}
		return mig
	}

	// Two admissions stall on the shared insert gate.
	starts := make(chan int64, 2)
	for i := 0; i < 2; i++ {
		go func() {
			id, err := f.mg.Start(context.Background(), f.src, f.target)
			if err == nil {
				starts <- id
			}
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.store.insertCount() < 3 {
		if time.Now().After(deadline) {
			t.Fatal("pending admission INSERTs never started")
		}
		time.Sleep(2 * time.Millisecond)
	}

	returned := make(chan error, 1)
	go func() { returned <- f.mg.Shutdown(context.Background(), 80*time.Millisecond) }()
	waitForLog(t, f.logs, "pending migration admission unresolved")

	// Releasing the gate resolves BOTH admissions; the second is awaited in
	// the first pass under the fired deadline and must fold into the drain.
	close(f.store.insertGate)
	<-starts
	<-starts

	close(f.target.putGate)
	close(loaderGate)
	if err := await(t, returned, "Shutdown with two pending admissions"); err != nil {
		t.Fatalf("Shutdown = %v, want nil after all runs drained", err)
	}
}

// TestShutdownPendingOuterCancelHoldsAndEscalatesSeamed pins the outer-ctx
// branch of the pending wait: a stalled admission at OUTER expiry escalates
// through the seamed terminateProcess and keeps holding until the admission
// resolves — dependency closure can never proceed with a launchable worker.
func TestShutdownPendingOuterCancelHoldsAndEscalatesSeamed(t *testing.T) {
	f := newLifecycleFixture(t, 51)
	key := sha256Hex("outer-cancel")
	f.src.objs[key] = []byte("outer-cancel")

	f.openRun(t, context.Background(), []string{key}, []int64{int64(len("outer-cancel"))})
	waitForPutStarted(t, f.target)
	f.store.insertGate = make(chan struct{})

	loaderGate := make(chan struct{})
	f.mg.newMigration = func(source, target blobMover) *Migration {
		mig := NewMigration(nil, source, target, f.mg.logger)
		mig.statusDB = f.store
		mig.blobRows = func(ctx context.Context) (scanCursor, error) {
			<-loaderGate
			return &closingRows{&reconRows{keys: []string{key}, sizes: []int64{int64(len("outer-cancel"))}}}, nil
		}
		return mig
	}

	go func() { _, _ = f.mg.Start(context.Background(), f.src, f.target) }()
	deadline := time.Now().Add(5 * time.Second)
	for f.store.insertCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("pending admission INSERT never started")
		}
		time.Sleep(2 * time.Millisecond)
	}

	var terminated atomic.Int32
	f.mg.terminateProcess = func(int) { terminated.Add(1) }

	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan error, 1)
	go func() { returned <- f.mg.Shutdown(ctx, time.Hour) }()

	// Cancel the OUTER context while the admission is stalled: the pending
	// wait takes the ctx.Done branch, the escalation fires (seamed), and
	// Shutdown keeps holding until the admission resolves.
	cancel()
	waitForLog(t, f.logs, "terminating process")

	giveUp := time.Now().Add(2 * time.Second)
	for {
		if terminated.Load() > 0 {
			break
		}
		if time.Now().After(giveUp) {
			t.Fatal("outer-ctx expiry never escalated through the seam")
		}
		time.Sleep(2 * time.Millisecond)
	}
	select {
	case err := <-returned:
		t.Fatalf("Shutdown returned %v with the admission still launchable — the gate must stay shut", err)
	default:
	}

	close(f.store.insertGate)
	close(loaderGate)
	close(f.target.putGate)
	if err := await(t, returned, "Shutdown after seamed escalation"); err != nil {
		t.Fatalf("Shutdown = %v, want nil after everything drained", err)
	}
	if terminated.Load() != 1 {
		t.Fatalf("terminateProcess fired %d times, want exactly 1", terminated.Load())
	}
}

// ── Recover failure branches ────────────────────────────────────────────

func TestRecoverScanOrphansError(t *testing.T) {
	f := newLifecycleFixture(t, 61)
	cause := errors.New("orphan scan exploded")
	f.mg.scanOrphans = func(ctx context.Context) (scanCursor, error) { return nil, cause }
	err := f.mg.Recover(context.Background())
	if !errors.Is(err, cause) {
		t.Fatalf("Recover = %v, want the wrapped scan cause", err)
	}
	if !strings.Contains(err.Error(), "scan orphaned transitional rows") {
		t.Fatalf("Recover error %v does not name the scan step", err)
	}
}

func TestRecoverBrokenRowScanContinues(t *testing.T) {
	f := newLifecycleFixture(t, 63)
	f.mg.scanOrphans = func(ctx context.Context) (scanCursor, error) {
		return &brokenScanRows{err: errors.New("corrupt row")}, nil
	}
	// The broken row is skipped (logged) and the pass returns the cursor's
	// (nil) Err — never a panic, never an abort.
	if err := f.mg.Recover(context.Background()); err != nil {
		t.Fatalf("Recover with a broken row = %v, want nil", err)
	}
}

func TestRecoverExclusivityProvenWithoutStoreSkipsReclaim(t *testing.T) {
	f := newLifecycleFixture(t, 65)
	f.mg.exclusiveOwnership = func() bool { return true }
	f.mg.store = nil // proven exclusivity but nowhere to write
	rows := &orphanRows{ids: []int64{65}, statuses: []string{"dual_write"}}
	f.mg.scanOrphans = func(ctx context.Context) (scanCursor, error) { return rows, nil }
	if err := f.mg.Recover(context.Background()); err != nil {
		t.Fatalf("Recover without a store = %v, want nil", err)
	}
	if len(f.store.execSnapshot()) != 0 {
		t.Fatal("reclaim write attempted without a store")
	}
}

func TestRecoverReclaimWriteFailureContinues(t *testing.T) {
	f := newLifecycleFixture(t, 67)
	f.mg.exclusiveOwnership = func() bool { return true }
	f.mg.store = &errExecStore{fakeMigratorStore: f.store, cause: errors.New("write refused")}
	rows := &orphanRows{ids: []int64{67, 68}, statuses: []string{"dual_write", "backfill"}}
	f.mg.scanOrphans = func(ctx context.Context) (scanCursor, error) { return rows, nil }
	// Both reclaim writes fail; the pass logs and continues, returning the
	// cursor's nil Err.
	if err := f.mg.Recover(context.Background()); err != nil {
		t.Fatalf("Recover with failing reclaim writes = %v, want nil", err)
	}
	if got := len(f.store.execSnapshot()); got != 0 {
		t.Fatalf("the failing store recorded %d execs via the base fake", got)
	}
}

// ── default scanOrphans seam ────────────────────────────────────────────

func TestRecoverDefaultScanOrphansRequiresPool(t *testing.T) {
	m := NewMigrator(context.Background(), nil, nil)
	err := m.Recover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no database pool configured") {
		t.Fatalf("Recover without a pool = %v, want the pool error", err)
	}
}

// ── pool-backed default seams ────────────────────────────────────────────

// TestMigratorDefaultSeamsWithPool drives the pool-backed constructor's
// default seams against the real test database: the pool wires the store,
// Recover runs the default orphan scan, and Start runs the default
// newMigration seam through a real durable admission.
func TestMigratorDefaultSeamsWithPool(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	m := NewMigrator(context.Background(), pool, gapLogger())
	if m.store == nil {
		t.Fatal("a pool-backed constructor must wire the pool as the store")
	}

	// The default scanOrphans runs the real transitional-row query.
	if err := m.Recover(context.Background()); err != nil {
		t.Fatalf("Recover with the default pool scan: %v", err)
	}

	// Start runs the default newMigration seam: the run copies the (small)
	// real blobs cursor against blocking movers and settles terminal.
	src, tgt, _ := gapMovers()
	close(tgt.putGate)
	id, err := m.Start(context.Background(), src, tgt)
	if err != nil {
		t.Fatalf("Start with the default seams: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM storage_migrations WHERE id = $1`, id)
	})

	// D-4: before the run's first progress write the row's total_blobs is NULL;
	// Status coalesces it to the defined not-started shape, so the poll below
	// simply treats the unsettled window as not-yet-terminal.
	deadline := time.Now().Add(10 * time.Second)
	for {
		res, err := m.Status(context.Background(), id)
		if err == nil &&
			(res["status"] == string(MigCutover) || res["status"] == string(MigFailed)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("run never settled: res=%v err=%v", res, err)
		}
		time.Sleep(5 * time.Millisecond)
	}

	if err := m.Shutdown(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("Shutdown = %v, want nil", err)
	}
	if _, err := m.Start(context.Background(), src, tgt); !errors.Is(err, ErrAdmissionClosed) {
		t.Fatalf("Start after Shutdown = %v, want ErrAdmissionClosed", err)
	}
}
