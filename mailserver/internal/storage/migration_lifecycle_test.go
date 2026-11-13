package storage

// migration_lifecycle_test.go — AR-01 lifetime-owner contracts, DB-free (the
// statusStore/backfillRows/reconMover seams plus the fake store/cursor/movers
// defined here). Covered:
//
//   - admission-then-request-cancel (r2 AR01-3 corrected oracle): durable
//     INSERT first, THEN request cancellation, run proceeds to cutover;
//   - cross-request cancel handshake: DB `cancelled` only after the worker
//     stopped issuing target writes (event-ordering proof), completed_at set;
//   - cancel refusals: unknown/terminal/cutover rows typed-error, row
//     unchanged; bounded cancel join → typed ErrDrainTimeout, no owner write,
//     run retained;
//   - recovery: reclaim only under proven exclusive execution ownership,
//     otherwise log-only deferral; live-run rows untouched; a FINISHED run is
//     released from the registry so it cannot shadow proven-exclusive recovery
//     (Astra impl-r2 finding 4);
//   - shutdown: admission closure + drained join before dependency closure; a
//     pending admission (past the closing check, INSERT in flight) is disposed
//     atomically with shutdown and its registered run is drained — never an
//     unjoined worker launched past the snapshot (Astra impl-r2 finding 2);
//   - pending admissions participate in BOTH shutdown deadline paths (Astra
//     impl-r2 r3 finding 1): the drain deadline is armed before the pending
//     wait, so a stalled INSERT is a failed drain that cannot defer
//     failed-drain logging or termination escalation — even with an existing
//     worker live — and the outer deadline escalates while withholding the
//     dependency-closure gate until the admission resolves and its run exits;
//   - cancellation reconciled BEFORE the backfill outcome: a stop during the
//     final copy publishes `cancelled`/`failed`, never `cutover` (Astra
//     impl-r2 finding 3);
//   - cancel handshake vs cutover persistence (Astra impl-r2 r3 finding 2): a
//     drained handshake whose run rests at `cutover` is a typed refusal, never
//     a false "cancelled" success;
//   - resolved pending admissions are cleared from the pending list's backing
//     array, not retained via stale slots (Astra impl-r2 finding 3);
//   - with TWO pending admissions (impl-r4): the first exhausts the drain
//     deadline, the outer deadline expires with the second still in flight,
//     and the deadlineFired branch must hand that admission EXCLUSIVELY to the
//     pendingHot pass — falling through to the p.run fold reads the run field
//     with no synchronization, racing Start's registration write;
//   - undrained join beyond the pinned deadline (r3-1) and OUTER-deadline
//     overrun escalating to the process-termination seam BEFORE the
//     dependency-closure gate (r4-1).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ── ordering log ─────────────────────────────────────────────────────────

// eventLog records cross-goroutine events so tests can assert happens-before
// ordering (e.g. the terminal status write precedes the dependency-closure
// gate).
type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(e string) {
	l.mu.Lock()
	l.events = append(l.events, e)
	l.mu.Unlock()
}

func (l *eventLog) indexOf(e string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, v := range l.events {
		if v == e {
			return i
		}
	}
	return -1
}

// requireBefore asserts first is present and precedes then (which may not have
// happened yet).
func (l *eventLog) requireBefore(t *testing.T, first, then string) {
	t.Helper()
	i, j := l.indexOf(first), l.indexOf(then)
	if i < 0 {
		t.Fatalf("event %q never happened; log = %v", first, l.snapshot())
	}
	if j >= 0 && i > j {
		t.Fatalf("event %q must precede %q; log = %v", first, then, l.snapshot())
	}
}

func (l *eventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

// syncBuffer is a mutex-protected log sink: the Migrator logs from run and
// shutdown goroutines while test goroutines assert on the captured records.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// ── fakes ────────────────────────────────────────────────────────────────

// blockingMover is a blobMover whose PutObject models a non-cooperative
// driver: once entered it runs to completion only when putGate is closed
// (mirroring posixDriver.PutObject, which discards its context and cannot be
// interrupted in-process).
type blockingMover struct {
	mu      sync.Mutex
	objs    map[string][]byte
	getErr  map[string]error
	puts    []string
	putGate chan struct{} // closed to release a blocked PutObject
	// putStarted is signaled (non-blocking) when a PutObject begins, so tests
	// can pin assertions to "the worker is inside the driver call".
	putStarted chan struct{}
	events     *eventLog
}

func newBlockingMover(events *eventLog) *blockingMover {
	return &blockingMover{
		objs:       map[string][]byte{},
		getErr:     map[string]error{},
		putGate:    make(chan struct{}),
		putStarted: make(chan struct{}, 8),
		events:     events,
	}
}

func (b *blockingMover) ProviderName() string { return "blocking" }

func (b *blockingMover) HeadObject(_ context.Context, key string) (*ObjectInfo, error) {
	b.mu.Lock()
	data, ok := b.objs[key]
	b.mu.Unlock()
	if !ok {
		return nil, io.EOF
	}
	return &ObjectInfo{Key: key, Size: int64(len(data))}, nil
}

func (b *blockingMover) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	if err := b.getErr[key]; err != nil {
		return nil, err
	}
	b.mu.Lock()
	data, ok := b.objs[key]
	b.mu.Unlock()
	if !ok {
		return nil, io.EOF
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (b *blockingMover) PutObject(_ context.Context, key string, r io.Reader, _ int64) error {
	b.events.add("put:start:" + key)
	select {
	case b.putStarted <- struct{}{}:
	default:
	}
	data, err := io.ReadAll(r)
	if err != nil {
		b.events.add("put:err:" + key)
		return err
	}
	<-b.putGate // the non-cooperative stretch: runs to completion once started
	b.mu.Lock()
	b.objs[key] = data
	b.puts = append(b.puts, key)
	b.mu.Unlock()
	b.events.add("put:end:" + key)
	return nil
}

func (b *blockingMover) DeleteObject(_ context.Context, key string) error {
	b.mu.Lock()
	delete(b.objs, key)
	b.mu.Unlock()
	return nil
}

func (b *blockingMover) putKeys() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.puts...)
}

// fakeRow is a pgx.Row over a fixed value or error.
type fakeRow struct {
	v   any
	err error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	switch d := dest[0].(type) {
	case *int64:
		*d = r.v.(int64)
	case *string:
		*d = r.v.(string)
	default:
		return fmt.Errorf("fakeRow: unsupported dest %T", dest[0])
	}
	return nil
}

// gatedRow blocks in Scan until its gate closes — the in-flight stretch of a
// pending admission (past the closing check, before registration).
type gatedRow struct {
	inner fakeRow
	gate  chan struct{}
}

func (r gatedRow) Scan(dest ...any) error {
	if r.gate != nil {
		<-r.gate
	}
	return r.inner.Scan(dest...)
}

type storeExec struct {
	sql  string
	args []any
}

// fakeMigratorStore satisfies migratorStore: INSERT admission returns
// insertID+seq (behind insertGate when set, so tests can pause a Start between
// the closing check and run registration); SELECT status serves the statuses
// map; Exec records writes. When cutoverGate is set, a cutover status write
// signals cutoverStarted and then blocks BEFORE being recorded — the "cutover
// persistence in flight, uncommitted" stretch (Astra impl-r2 r3 finding 2).
type fakeMigratorStore struct {
	mu         sync.Mutex
	inserts    int
	insertID   int64
	insertSeq  int
	insertGate chan struct{}
	statuses   map[int64]string
	execs      []storeExec
	events     *eventLog

	cutoverStarted chan struct{}
	cutoverGate    chan struct{}
}

func (f *fakeMigratorStore) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if len(args) > 0 {
		if s, ok := args[0].(string); ok && s == string(MigCutover) {
			if f.cutoverStarted != nil {
				select {
				case f.cutoverStarted <- struct{}{}:
				default:
				}
			}
			f.mu.Lock()
			gate := f.cutoverGate
			f.mu.Unlock()
			if gate != nil {
				<-gate
			}
		}
	}
	f.mu.Lock()
	f.execs = append(f.execs, storeExec{sql: sql, args: args})
	f.mu.Unlock()
	if f.events != nil && len(args) > 0 {
		if s, ok := args[0].(string); ok {
			f.events.add("status:" + s)
		}
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (f *fakeMigratorStore) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "INSERT INTO storage_migrations"):
		f.mu.Lock()
		f.inserts++
		id := f.insertID + int64(f.insertSeq)
		f.insertSeq++
		gate := f.insertGate
		f.mu.Unlock()
		return gatedRow{inner: fakeRow{v: id}, gate: gate}
	case strings.Contains(sql, "SELECT status FROM"):
		f.mu.Lock()
		status, ok := f.statuses[args[0].(int64)]
		f.mu.Unlock()
		if !ok {
			return fakeRow{err: pgx.ErrNoRows}
		}
		return fakeRow{v: status}
	}
	return fakeRow{err: pgx.ErrNoRows}
}

func (f *fakeMigratorStore) execSnapshot() []storeExec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]storeExec(nil), f.execs...)
}

func (f *fakeMigratorStore) insertCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.inserts
}

// orphanRows is a scanCursor over (id, status) pairs for Recover fixtures.
type orphanRows struct {
	ids      []int64
	statuses []string
	i        int
}

func (r *orphanRows) Next() bool { return r.i < len(r.ids) }

func (r *orphanRows) Scan(dest ...any) error {
	*dest[0].(*int64) = r.ids[r.i]
	*dest[1].(*string) = r.statuses[r.i]
	r.i++
	return nil
}

func (r *orphanRows) Err() error { return nil }

func (r *orphanRows) Close() {}

// closingRows adapts reconRows to the scanCursor loader surface.
type closingRows struct{ *reconRows }

func (c *closingRows) Close() {}

// ── fixture ──────────────────────────────────────────────────────────────

type lifecycleFixture struct {
	mg     *Migrator
	store  *fakeMigratorStore
	src    *blockingMover
	target *blockingMover
	events *eventLog
	logs   *syncBuffer
	id     int64
}

// newLifecycleFixture builds a Migrator over fakes. No run is started yet;
// call openRun to admit one.
func newLifecycleFixture(t *testing.T, id int64) *lifecycleFixture {
	t.Helper()
	f := &lifecycleFixture{
		events: &eventLog{},
		logs:   &syncBuffer{},
	}
	logger := slog.New(slog.NewTextHandler(f.logs, nil))
	f.store = &fakeMigratorStore{insertID: id, statuses: map[int64]string{id: "backfill"}, events: f.events}
	f.src = newBlockingMover(f.events)
	f.target = newBlockingMover(f.events)
	f.mg = NewMigrator(context.Background(), nil, logger)
	f.mg.store = f.store
	return f
}

// useRunRows installs the per-run Migration seam serving the given backfill
// rows (blobs live on the source side). Used by openRun and directly by tests
// that admit runs themselves (the pending-admission interleaving test).
func (f *lifecycleFixture) useRunRows(t *testing.T, keys []string, sizes []int64) {
	t.Helper()
	rows := &reconRows{keys: keys, sizes: sizes}
	f.mg.newMigration = func(source, target blobMover) *Migration {
		mig := NewMigration(nil, source, target, f.mg.logger)
		mig.statusDB = f.store
		mig.blobRows = func(ctx context.Context) (scanCursor, error) {
			return &closingRows{rows}, nil
		}
		return mig
	}
}

// openRun admits a run from reqCtx with the given backfill rows (blobs live on
// the source side). Returns the admitted id.
func (f *lifecycleFixture) openRun(t *testing.T, reqCtx context.Context, keys []string, sizes []int64) int64 {
	t.Helper()
	f.useRunRows(t, keys, sizes)
	id, err := f.mg.Start(reqCtx, f.src, f.target)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	f.id = id
	return id
}

func waitForPutStarted(t *testing.T, b *blockingMover) {
	t.Helper()
	select {
	case <-b.putStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("worker never entered PutObject")
	}
}

func await(t *testing.T, ch <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return nil
	}
}

// watchRunCtxDone records an event when the run's context is cancelled, so
// tests can order the driver-gate release strictly after the stop signal was
// delivered (the worker only observes cancellation at the next row boundary).
func watchRunCtxDone(f *lifecycleFixture, event string) {
	f.mg.mu.Lock()
	runCtx := f.mg.runs[f.id].ctx
	f.mg.mu.Unlock()
	go func() {
		<-runCtx.Done()
		f.events.add(event)
	}()
}

func waitEvent(t *testing.T, f *lifecycleFixture, event string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for f.events.indexOf(event) < 0 {
		if time.Now().After(deadline) {
			t.Fatalf("event %q never happened; log = %v", event, f.events.snapshot())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitForLog polls the capture buffer until the given record appears; used to
// barrier on Migrator state transitions that log after committing (e.g.
// closing=true is set before the shutdown log line).
func waitForLog(t *testing.T, logs *syncBuffer, needle string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if strings.Contains(logs.String(), needle) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("log record %q never appeared; log = %q", needle, logs.String())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitForStatusWrite polls the fake store until a write of the given status
// landed, returning it.
func waitForStatusWrite(t *testing.T, f *fakeMigratorStore, status MigrationStatus) storeExec {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, e := range f.execSnapshot() {
			if len(e.args) == 2 && e.args[0] == string(status) {
				return e
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %q status write landed; execs = %v", status, f.execSnapshot())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func hasStatusWrite(f *fakeMigratorStore, status MigrationStatus) bool {
	for _, e := range f.execSnapshot() {
		if len(e.args) == 2 && e.args[0] == string(status) {
			return true
		}
	}
	return false
}

func runRegistered(mg *Migrator, id int64) bool {
	mg.mu.Lock()
	defer mg.mu.Unlock()
	_, ok := mg.runs[id]
	return ok
}

// waitRunReleased polls until a finished run is no longer registered — the
// Astra impl-r2 finding 4 release happens when the run goroutine stops, a
// moment after its terminal status write lands.
func waitRunReleased(t *testing.T, mg *Migrator, id int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for runRegistered(mg, id) {
		if time.Now().After(deadline) {
			t.Fatalf("run %d still registered after finishing — completed runs must be released from the registry", id)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// ── tests ────────────────────────────────────────────────────────────────

// TestMigrator_AdmissionThenRequestCancelSurvives pins the corrected r2
// AR01-3 oracle: the run is DURABLY admitted first (the storage_migrations
// INSERT commits and the id is returned), THEN the starting request's context
// is cancelled, and the worker — whose context derives from the service
// lifecycle, never from the request — proceeds normally to cutover (the
// terminal state a successful backfill actually lands; `completed` has no
// production writer). An already-cancelled context is NOT the oracle: Start
// would fail at the INSERT itself, exercising admission failure.
//
// Strengthened (Astra impl-r2 finding 3): the fixture uses TWO objects and
// blocks the worker inside the FIRST driver write when the request dies. A
// run that inherited the cancelled request context can never copy the SECOND
// row — the copy loop checks cancellation at the row boundary — so the
// one-row, context-ignoring shape would reach cutover even under the legacy
// derivation. Reaching cutover with BOTH rows copied is the proof.
func TestMigrator_AdmissionThenRequestCancelSurvives(t *testing.T) {
	f := newLifecycleFixture(t, 77)
	k1, k2 := sha256Hex("admission-1"), sha256Hex("admission-2")
	f.src.objs[k1], f.src.objs[k2] = []byte("admission-1"), []byte("admission-2")
	s1, s2 := int64(len("admission-1")), int64(len("admission-2"))

	reqCtx, reqCancel := context.WithCancel(context.Background())
	id := f.openRun(t, reqCtx, []string{k1, k2}, []int64{s1, s2})
	if id != 77 {
		t.Fatalf("admitted id = %d, want 77 (durable INSERT returned the id)", id)
	}
	if got := f.store.insertCount(); got != 1 {
		t.Fatalf("admission INSERTs = %d, want 1", got)
	}

	waitForPutStarted(t, f.target)
	reqCancel() // request cancelled while the run is mid-flight — by design

	close(f.target.putGate) // let the in-flight write complete
	exec := waitForStatusWrite(t, f.store, MigCutover)

	// Cutover is NOT terminal: no completed_at, and no production writer ever
	// lands `completed`.
	if strings.Contains(exec.sql, "completed_at") {
		t.Fatalf("cutover write = %q, want no completed_at (cutover is not terminal)", exec.sql)
	}
	for _, terminal := range []MigrationStatus{MigCompleted, MigFailed, MigCancelled} {
		if hasStatusWrite(f.store, terminal) {
			t.Fatalf("unexpected %q write — request cancellation must not touch the run", terminal)
		}
	}
	// The run outlived the request: the SECOND row was issued to the driver
	// after the request died (a request-derived run context stops here).
	if puts := f.target.putKeys(); len(puts) != 2 || puts[0] != k1 || puts[1] != k2 {
		t.Fatalf("target puts = %v, want both rows copied after the request died", puts)
	}
}

// TestMigrator_CrossRequestCancelStopsWorkerBeforeTerminalWrite proves the
// cancel handshake: a cancel issued from a request unrelated to the starting
// request results in DB `cancelled` only AFTER the run goroutine has stopped
// issuing target writes (ordering proved in the event log), the run performed
// its own terminal write through the detached setStatus path, and the
// cancelled write carries completed_at.
func TestMigrator_CrossRequestCancelStopsWorkerBeforeTerminalWrite(t *testing.T) {
	f := newLifecycleFixture(t, 41)
	k1, k2 := sha256Hex("cross-1"), sha256Hex("cross-2")
	f.src.objs[k1], f.src.objs[k2] = []byte("cross-1"), []byte("cross-2")

	f.openRun(t, context.Background(), []string{k1, k2}, []int64{7, 7}) // starting request never cancelled
	waitForPutStarted(t, f.target)

	watchRunCtxDone(f, "ctx:cancelled")
	cancelErr := make(chan error, 1)
	go func() { cancelErr <- f.mg.Cancel(context.Background(), f.id) }()
	waitEvent(t, f, "ctx:cancelled") // stop signal delivered

	close(f.target.putGate) // the in-flight write completes; the worker then observes cancellation at the next row boundary

	if err := await(t, cancelErr, "Cancel handshake"); err != nil {
		t.Fatalf("Cancel = %v, want nil (drained handshake)", err)
	}
	exec := waitForStatusWrite(t, f.store, MigCancelled)
	if !strings.Contains(exec.sql, "completed_at = now()") {
		t.Fatalf("cancelled write = %q, want completed_at on the terminal write", exec.sql)
	}

	// Ordering: no target write began after the terminal write landed, and the
	// second blob was never issued to the driver.
	f.events.requireBefore(t, "put:end:"+k1, "status:"+string(MigCancelled))
	if i := f.events.indexOf("put:start:" + k2); i >= 0 {
		t.Fatalf("worker issued a target write after cancellation; log = %v", f.events.snapshot())
	}
	if puts := f.target.putKeys(); len(puts) != 1 || puts[0] != k1 {
		t.Fatalf("target puts = %v, want only the single in-flight write", puts)
	}
}

// TestMigrator_CancelDuringFinalCopyPublishesCancelled pins the Astra impl-r2
// finding 3: a cancel delivered during the FINAL copy — after the last row
// boundary the copy loop checks — must still publish the cancelled terminal
// outcome. The previous path reconciled cancellation only when backfill
// returned an error, so a blocked final write that succeeded and exhausted
// the cursor published `cutover` with the handshake drained as success.
func TestMigrator_CancelDuringFinalCopyPublishesCancelled(t *testing.T) {
	f := newLifecycleFixture(t, 63)
	key := sha256Hex("final-object")
	f.src.objs[key] = []byte("final-object")

	f.openRun(t, context.Background(), []string{key}, []int64{13}) // the ONLY row
	waitForPutStarted(t, f.target)                                 // worker inside the final copy

	watchRunCtxDone(f, "ctx:cancelled")
	cancelErr := make(chan error, 1)
	go func() { cancelErr <- f.mg.Cancel(context.Background(), f.id) }()
	waitEvent(t, f, "ctx:cancelled") // stop signal delivered mid-copy

	// The final write completes; the cursor then exhausts WITHOUT another row
	// boundary — exactly the path that used to fall through to cutover.
	close(f.target.putGate)

	if err := await(t, cancelErr, "Cancel handshake"); err != nil {
		t.Fatalf("Cancel = %v, want nil (drained handshake)", err)
	}
	exec := waitForStatusWrite(t, f.store, MigCancelled)
	if !strings.Contains(exec.sql, "completed_at = now()") {
		t.Fatalf("cancelled write = %q, want completed_at", exec.sql)
	}
	for _, forward := range []MigrationStatus{MigCutover, MigCompleted} {
		if hasStatusWrite(f.store, forward) {
			t.Fatalf("cancellation during the final copy published %q — the outcome must reconcile with the observed stop signal", forward)
		}
	}
	f.events.requireBefore(t, "put:end:"+key, "status:"+string(MigCancelled))
}

// TestMigrator_CancelRefusesTerminalRows: cancel of an unknown id is a typed
// error; cancel of a completed/failed/cancelled/cutover row is refused with a
// typed error and the row is UNCHANGED (no unconditional status overwrite); a
// transitional row with no live run in this process is refused too — local
// absence cannot authorize mutating another executor's row (AR01-2).
func TestMigrator_CancelRefusesTerminalRows(t *testing.T) {
	f := newLifecycleFixture(t, 5)
	f.store.statuses[6] = "completed"
	f.store.statuses[7] = "failed"
	f.store.statuses[8] = "cancelled"
	f.store.statuses[9] = "cutover"
	f.store.statuses[10] = "backfill" // transitional but no live run registered

	ctx := context.Background()
	for id, want := range map[int64]error{
		6: ErrNotCancellable, 7: ErrNotCancellable, 8: ErrNotCancellable, 9: ErrNotCancellable,
		99: ErrUnknownMigration,
		10: ErrNotRunning,
	} {
		err := f.mg.Cancel(ctx, int64(id))
		if !errors.Is(err, want) {
			t.Fatalf("Cancel(%d) = %v, want %v", id, err, want)
		}
	}
	if execs := f.store.execSnapshot(); len(execs) != 0 {
		t.Fatalf("refused cancels wrote to the database: %v", execs)
	}
}

// TestMigrator_CancelJoinIsBounded pins the r3 undrained outcome: with the
// fake driver held blocked beyond the pinned join deadline, Cancel returns the
// typed drain-incomplete error — never success — with NO owner status write
// (the row keeps its transitional status) and the run still registered
// (ownership retained). After the fake is released, the run's own terminal
// write lands, the run is released from the registry, and a further handshake
// is refused against the row's terminal `cancelled`.
func TestMigrator_CancelJoinIsBounded(t *testing.T) {
	prev := cancelJoinTimeout
	cancelJoinTimeout = 60 * time.Millisecond
	t.Cleanup(func() { cancelJoinTimeout = prev })

	f := newLifecycleFixture(t, 88)
	k1, k2 := sha256Hex("bounded-1"), sha256Hex("bounded-2")
	f.src.objs[k1], f.src.objs[k2] = []byte("bounded-1"), []byte("bounded-2")
	f.openRun(t, context.Background(), []string{k1, k2}, []int64{9, 9})
	waitForPutStarted(t, f.target)

	start := time.Now()
	err := f.mg.Cancel(context.Background(), f.id)
	elapsed := time.Since(start)
	if !errors.Is(err, ErrDrainTimeout) {
		t.Fatalf("Cancel = %v, want ErrDrainTimeout (expiry is never a completed join)", err)
	}
	if elapsed < 55*time.Millisecond {
		t.Fatalf("Cancel returned after %v — join was not bounded by the pinned deadline", elapsed)
	}
	for _, terminal := range []MigrationStatus{MigCancelled, MigFailed, MigCompleted} {
		if hasStatusWrite(f.store, terminal) {
			t.Fatalf("owner wrote %q on drain expiry — expiry must publish no status", terminal)
		}
	}
	if !runRegistered(f.mg, f.id) {
		t.Fatal("run dropped from the registry on drain expiry — ownership must be retained")
	}
	if log := f.logs.String(); !strings.Contains(log, "drain deadline expired") || !strings.Contains(log, "id=88") {
		t.Fatalf("log = %q, want the failed-drain ERROR naming the id", log)
	}

	// Release the blocked driver: the run alone publishes its terminal write.
	close(f.target.putGate)
	exec := waitForStatusWrite(t, f.store, MigCancelled)
	if !strings.Contains(exec.sql, "completed_at = now()") {
		t.Fatalf("cancelled write = %q, want completed_at", exec.sql)
	}

	// The drained run is RELEASED from the registry (Astra impl-r2 finding 4)
	// — ownership was retained through the expiry, and only the observed exit
	// releases it. The row now rests at the run's own terminal `cancelled`, so
	// a further handshake is refused as non-cancellable, with no new writes.
	waitRunReleased(t, f.mg, f.id)
	f.store.statuses[f.id] = string(MigCancelled) // the run's terminal write is DB truth
	if err := f.mg.Cancel(context.Background(), f.id); !errors.Is(err, ErrNotCancellable) {
		t.Fatalf("post-drain Cancel = %v, want ErrNotCancellable (row rests at the run's terminal cancelled)", err)
	}
}

// TestMigrator_RecoverMarksOrphanedTransitionalRowsFailed pins AR01-2: the
// reclaim mutation runs ONLY under a proven-exclusive-ownership fixture; a
// live run's row is untouched; without proven exclusivity the pass is
// log/observe-only with no `failed` mutation; no convergence claim is logged.
func TestMigrator_RecoverMarksOrphanedTransitionalRowsFailed(t *testing.T) {
	t.Run("proven exclusivity reclaims orphaned transitional rows", func(t *testing.T) {
		f := newLifecycleFixture(t, 1)
		f.mg.exclusiveOwnership = func() bool { return true }
		f.mg.scanOrphans = func(ctx context.Context) (scanCursor, error) {
			return &orphanRows{ids: []int64{7, 8}, statuses: []string{"backfill", "dual_write"}}, nil
		}
		if err := f.mg.Recover(context.Background()); err != nil {
			t.Fatalf("Recover: %v", err)
		}
		execs := f.store.execSnapshot()
		if len(execs) != 2 {
			t.Fatalf("reclaim writes = %d, want 2; execs = %v", len(execs), execs)
		}
		for i, wantID := range []int64{7, 8} {
			if !strings.Contains(execs[i].sql, "SET status = 'failed', completed_at = now()") {
				t.Fatalf("reclaim %d sql = %q, want failed + completed_at", i, execs[i].sql)
			}
			if execs[i].args[0] != wantID {
				t.Fatalf("reclaim %d id = %v, want %d", i, execs[i].args[0], wantID)
			}
		}
		if log := f.logs.String(); !strings.Contains(log, "orphaned transitional row reclaimed") {
			t.Fatalf("log = %q, want the reconcile-reason record", log)
		}
		if log := f.logs.String(); strings.Contains(log, "convergence") || strings.Contains(log, "fully reconciled") {
			t.Fatalf("log = %q, want no convergence claim", log)
		}
	})

	t.Run("unproven exclusivity defers the mutation log-only", func(t *testing.T) {
		f := newLifecycleFixture(t, 1)
		f.mg.scanOrphans = func(ctx context.Context) (scanCursor, error) {
			return &orphanRows{ids: []int64{7}, statuses: []string{"backfill"}}, nil
		}
		if err := f.mg.Recover(context.Background()); err != nil {
			t.Fatalf("Recover: %v", err)
		}
		if execs := f.store.execSnapshot(); len(execs) != 0 {
			t.Fatalf("unproven pass mutated rows: %v", execs)
		}
		if log := f.logs.String(); !strings.Contains(log, "reclaim deferred") {
			t.Fatalf("log = %q, want the deferral record", log)
		}
	})

	t.Run("a live run's row is untouched", func(t *testing.T) {
		f := newLifecycleFixture(t, 12)
		key := sha256Hex("live-run-blob")
		f.src.objs[key] = []byte("live-run-blob")
		f.openRun(t, context.Background(), []string{key}, []int64{int64(len("live-run-blob"))})
		waitForPutStarted(t, f.target)

		f.mg.exclusiveOwnership = func() bool { return true }
		f.mg.scanOrphans = func(ctx context.Context) (scanCursor, error) {
			return &orphanRows{ids: []int64{f.id, 8}, statuses: []string{"backfill", "dual_write"}}, nil
		}
		if err := f.mg.Recover(context.Background()); err != nil {
			t.Fatalf("Recover: %v", err)
		}
		for _, e := range f.store.execSnapshot() {
			if len(e.args) == 1 && e.args[0] == f.id {
				t.Fatalf("live run's row %d was reclaimed: %v", f.id, e)
			}
		}
		if log := f.logs.String(); !strings.Contains(log, "live run") {
			t.Fatalf("log = %q, want the observe-only record for the live run", log)
		}

		// Drain for cleanliness.
		close(f.target.putGate)
		waitForStatusWrite(t, f.store, MigCutover)
	})
}

// TestMigrator_CompletedRunReleasedFromRegistry pins Astra impl-r2 finding 4:
// a finished run is released from the registry once execution stops — it no
// longer reads as live to Recover, so a stranded transitional row with its id
// stays reclaimable under proven-exclusive recovery, and the process does not
// retain the run's context and driver handles for its lifetime.
func TestMigrator_CompletedRunReleasedFromRegistry(t *testing.T) {
	f := newLifecycleFixture(t, 65)
	key := sha256Hex("release-blob")
	data := []byte("release-blob")
	f.target.objs[key] = data // verified target copy: the run skips it, no driver write

	f.openRun(t, context.Background(), []string{key}, []int64{int64(len(data))})
	waitForStatusWrite(t, f.store, MigCutover)

	// The registry release happens when the run goroutine stops — a moment
	// after its terminal write landed.
	waitRunReleased(t, f.mg, f.id)

	// Recover must no longer treat the finished run as live: with exclusivity
	// proven, an orphaned transitional row with this id is reclaimable.
	f.mg.exclusiveOwnership = func() bool { return true }
	f.mg.scanOrphans = func(ctx context.Context) (scanCursor, error) {
		return &orphanRows{ids: []int64{f.id}, statuses: []string{"backfill"}}, nil
	}
	if err := f.mg.Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	reclaimed := false
	for _, e := range f.store.execSnapshot() {
		if len(e.args) == 1 && e.args[0] == f.id {
			reclaimed = true
			if !strings.Contains(e.sql, "SET status = 'failed', completed_at = now()") {
				t.Fatalf("reclaim sql = %q, want failed + completed_at", e.sql)
			}
		}
	}
	if !reclaimed {
		t.Fatalf("Recover treated the finished run %d as live — completed runs must be released from the registry", f.id)
	}
}

// TestMigrator_TerminalWritesSetCompletedAt: the run's `failed` terminal write
// (source read failure enumerated, cutover withheld) carries completed_at —
// repairing the asymmetry where only the old DB-only cancel flip stamped it.
func TestMigrator_TerminalWritesSetCompletedAt(t *testing.T) {
	f := newLifecycleFixture(t, 9)
	key := sha256Hex("doomed-blob")
	f.src.getErr[key] = io.EOF // source read failure → enumerated, run fails

	f.openRun(t, context.Background(), []string{key}, []int64{int64(len("doomed-blob"))})
	exec := waitForStatusWrite(t, f.store, MigFailed)
	if !strings.Contains(exec.sql, "completed_at = now()") {
		t.Fatalf("failed write = %q, want completed_at on the terminal write", exec.sql)
	}
	if hasStatusWrite(f.store, MigCutover) {
		t.Fatal("cutover written despite unreconciled objects")
	}
}

// TestMigrator_ShutdownClosesAdmissionAndJoinsBeforeDependencies pins the
// drained shutdown path (r2 AR01-1): shutdown refuses new Starts, joins the
// live run, and returns — releasing the dependency-closure gate — only after
// the run's exit was observed (its terminal write already landed).
func TestMigrator_ShutdownClosesAdmissionAndJoinsBeforeDependencies(t *testing.T) {
	f := newLifecycleFixture(t, 21)
	k1, k2 := sha256Hex("drain-1"), sha256Hex("drain-2")
	f.src.objs[k1], f.src.objs[k2] = []byte("drain-1"), []byte("drain-2")
	f.openRun(t, context.Background(), []string{k1, k2}, []int64{7, 7})
	waitForPutStarted(t, f.target)

	watchRunCtxDone(f, "ctx:cancelled")
	returned := make(chan error, 1)
	go func() { returned <- f.mg.Shutdown(context.Background(), 5*time.Second) }()
	waitEvent(t, f, "ctx:cancelled") // shutdown stop signal delivered

	close(f.target.putGate) // the in-flight write finishes; the worker observes the shutdown cancellation at the next boundary

	if err := await(t, returned, "Shutdown drain"); err != nil {
		t.Fatalf("Shutdown = %v, want nil (drained)", err)
	}
	f.events.add("shutdown:returned")

	exec := waitForStatusWrite(t, f.store, MigFailed) // shutdown stop, not an admin cancel
	if !strings.Contains(exec.sql, "completed_at = now()") {
		t.Fatalf("failed write = %q, want completed_at", exec.sql)
	}

	// Dependency closure (modeled: what main.go does after Shutdown returns)
	// happened strictly after the run's terminal write and the observed exit.
	f.events.add("deps:closed")
	f.events.requireBefore(t, "status:"+string(MigFailed), "deps:closed")
	f.events.requireBefore(t, "shutdown:returned", "deps:closed")

	if _, err := f.mg.Start(context.Background(), f.src, f.target); !errors.Is(err, ErrAdmissionClosed) {
		t.Fatalf("Start after shutdown = %v, want ErrAdmissionClosed", err)
	}
}

// TestMigrator_ShutdownWaitsForPendingAdmission pins the Astra impl-r2
// finding 2 interleaving: a Start past the closing check whose admission
// INSERT is still in flight when Shutdown snapshots the registry is disposed
// ATOMICALLY with shutdown. Shutdown HOLDS until the INSERT resolves, folds
// the registered run into its drain set (cancelled like every other live
// run), and returns only after that run's exit was OBSERVED — a pending
// admission can never launch an unjoined worker past the snapshot.
func TestMigrator_ShutdownWaitsForPendingAdmission(t *testing.T) {
	f := newLifecycleFixture(t, 55)
	f.store.insertGate = make(chan struct{})
	key := sha256Hex("pending-admission")
	f.src.objs[key] = []byte("pending-admission")

	// The run's row loader blocks on its own gate so the worker parks in a
	// KNOWN place: wherever it is when shutdown's stop signal arrives, it can
	// only proceed after the gate opens, and the first copy-loop boundary then
	// observes the delivered cancellation deterministically.
	loaderGate := make(chan struct{})
	f.mg.newMigration = func(source, target blobMover) *Migration {
		mig := NewMigration(nil, source, target, f.mg.logger)
		mig.statusDB = f.store
		mig.blobRows = func(ctx context.Context) (scanCursor, error) {
			f.events.add("loader:entered")
			<-loaderGate
			return &closingRows{&reconRows{keys: []string{key}, sizes: []int64{16}}}, nil
		}
		return mig
	}

	started := make(chan int64, 1)
	startErr := make(chan error, 1)
	go func() {
		id, err := f.mg.Start(context.Background(), f.src, f.target)
		started <- id
		startErr <- err
	}()
	// The admission is past the closing check and blocked inside the INSERT.
	deadline := time.Now().Add(5 * time.Second)
	for f.store.insertCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("admission INSERT never started")
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Shutdown snapshots an empty registry but a non-empty pending list and
	// must HOLD — the pre-fix path returned into dependency closure here
	// while the admission could still launch an unjoined worker.
	returned := make(chan error, 1)
	go func() { returned <- f.mg.Shutdown(context.Background(), 5*time.Second) }()
	time.Sleep(150 * time.Millisecond)
	select {
	case err := <-returned:
		t.Fatalf("Shutdown returned %v while an admission was pending — pending admissions must be disposed atomically with shutdown", err)
	default:
	}

	close(f.store.insertGate) // the INSERT resolves: the run registers and launches
	if id := <-started; id != 55 {
		t.Fatalf("admitted id = %d, want 55 (the durable admission completes)", id)
	}
	if err := <-startErr; err != nil {
		t.Fatalf("Start = %v, want nil — its run drains under shutdown ownership", err)
	}
	f.id = 55

	// The folded run is cancelled like every other live run.
	watchRunCtxDone(f, "ctx:cancelled")
	waitEvent(t, f, "ctx:cancelled")
	waitEvent(t, f, "loader:entered")
	close(loaderGate) // the loader returns; the next boundary observes the cancellation

	if err := await(t, returned, "Shutdown pending-admission drain"); err != nil {
		t.Fatalf("Shutdown = %v, want nil (drained after the pending run registered and exited)", err)
	}
	f.events.add("shutdown:returned")
	exec := waitForStatusWrite(t, f.store, MigFailed) // shutdown stop, not an admin cancel
	if !strings.Contains(exec.sql, "completed_at = now()") {
		t.Fatalf("failed write = %q, want completed_at", exec.sql)
	}
	f.events.requireBefore(t, "status:"+string(MigFailed), "shutdown:returned")

	if _, err := f.mg.Start(context.Background(), f.src, f.target); !errors.Is(err, ErrAdmissionClosed) {
		t.Fatalf("Start after pending-admission drain = %v, want ErrAdmissionClosed", err)
	}
}

// TestMigrator_JoinTimeoutBeyondDeadlineEscalatesAndHoldsTeardown pins r3-1
// as amended r4-1: with the fake driver held blocked BEYOND the pinned drain
// deadline, the undrained outcome is escalated — typed ErrDrainTimeout on the
// cancel handshake, failed-drain ERROR naming the id, NO owner status write,
// the run still registered and admission still closed — and Shutdown does NOT
// return (dependency closure withheld) while the worker is live. After the
// fake is released, the run's own terminal write lands and teardown proceeds
// only on observed termination.
func TestMigrator_JoinTimeoutBeyondDeadlineEscalatesAndHoldsTeardown(t *testing.T) {
	prev := cancelJoinTimeout
	cancelJoinTimeout = 50 * time.Millisecond
	t.Cleanup(func() { cancelJoinTimeout = prev })

	f := newLifecycleFixture(t, 33)
	k1, k2 := sha256Hex("hold-1"), sha256Hex("hold-2")
	f.src.objs[k1], f.src.objs[k2] = []byte("hold-1"), []byte("hold-2")
	f.openRun(t, context.Background(), []string{k1, k2}, []int64{6, 6})
	waitForPutStarted(t, f.target)

	watchRunCtxDone(f, "ctx:cancelled")
	returned := make(chan error, 1)
	go func() { returned <- f.mg.Shutdown(context.Background(), 60*time.Millisecond) }()

	// Admission closure takes effect before the draining log record is
	// emitted (closing=true is set under the same lock, earlier), so a single
	// refusal assertion after the barrier is deterministic — never a Start
	// that could admit a duplicate run.
	waitForLog(t, f.logs, "shutdown draining live runs")
	if _, err := f.mg.Start(context.Background(), f.src, f.target); !errors.Is(err, ErrAdmissionClosed) {
		t.Fatalf("Start after shutdown began = %v, want ErrAdmissionClosed", err)
	}
	waitEvent(t, f, "ctx:cancelled") // stop signal delivered to the blocked worker

	// The cancel handshake against the blocked driver is bounded: typed
	// drain-incomplete, never success.
	cancelStart := time.Now()
	err := f.mg.Cancel(context.Background(), f.id)
	if !errors.Is(err, ErrDrainTimeout) {
		t.Fatalf("Cancel = %v, want ErrDrainTimeout", err)
	}
	if time.Since(cancelStart) < 45*time.Millisecond {
		t.Fatal("cancel join returned before the pinned deadline expired")
	}
	for _, terminal := range []MigrationStatus{MigCancelled, MigFailed, MigCompleted} {
		if hasStatusWrite(f.store, terminal) {
			t.Fatalf("owner wrote %q on drain expiry", terminal)
		}
	}
	if !runRegistered(f.mg, f.id) {
		t.Fatal("run dropped from the registry on drain expiry")
	}
	if log := f.logs.String(); !strings.Contains(log, "drain deadline expired") || !strings.Contains(log, "id=33") {
		t.Fatalf("log = %q, want failed-drain ERROR naming the id", log)
	}

	// The drain deadline (60ms) has long expired: Shutdown must still be
	// HOLDING — no return through dependency closure with the worker live.
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-returned:
		t.Fatalf("Shutdown returned %v while the worker was live — the r3 fallback must stay erased (r4-1)", err)
	default:
	}

	// Release the blocked driver: the run publishes its own terminal write
	// (an admin cancel was requested → `cancelled`), the exit is observed, and
	// only then does the dependency-closure gate open.
	close(f.target.putGate)
	if err := await(t, returned, "Shutdown late drain"); err != nil {
		t.Fatalf("Shutdown = %v, want nil after observed exit", err)
	}
	f.events.add("shutdown:returned")
	exec := waitForStatusWrite(t, f.store, MigCancelled)
	if !strings.Contains(exec.sql, "completed_at = now()") {
		t.Fatalf("cancelled write = %q, want completed_at", exec.sql)
	}
	f.events.requireBefore(t, "status:"+string(MigCancelled), "shutdown:returned")

	if _, err := f.mg.Start(context.Background(), f.src, f.target); !errors.Is(err, ErrAdmissionClosed) {
		t.Fatalf("Start after late drain = %v, want ErrAdmissionClosed (admission stays closed)", err)
	}
}

// TestMigrator_OuterDeadlineExpiryTerminatesBeforeTeardown extends the
// join-deadline contract to the OUTER process-level deadline (r4-1): with the
// fake driver held blocked beyond the OUTER deadline, the seamed
// process-termination hook fires — BEFORE the dependency-closure gate is
// released — and never returns through teardown with the worker live. After
// the fake is released, the run's own terminal write lands and the gate opens
// only on observed termination.
func TestMigrator_OuterDeadlineExpiryTerminatesBeforeTeardown(t *testing.T) {
	f := newLifecycleFixture(t, 44)
	k1, k2 := sha256Hex("outer-1"), sha256Hex("outer-2")
	f.src.objs[k1], f.src.objs[k2] = []byte("outer-1"), []byte("outer-2")
	f.openRun(t, context.Background(), []string{k1, k2}, []int64{7, 7})
	waitForPutStarted(t, f.target)

	terminated := make(chan int, 1)
	f.mg.terminateProcess = func(code int) {
		f.events.add("terminate")
		terminated <- code
	}

	outerCtx, cancelOuter := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancelOuter()
	returned := make(chan error, 1)
	go func() { returned <- f.mg.Shutdown(outerCtx, 40*time.Millisecond) }()

	// Drain deadline (40ms) expires first: failed-drain ERROR. Then the OUTER
	// deadline (120ms) overruns with the worker live: escalation fires.
	select {
	case code := <-terminated:
		if code != 1 {
			t.Fatalf("termination code = %d, want 1", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("termination escalation never fired")
	}
	if log := f.logs.String(); !strings.Contains(log, "terminating process") {
		t.Fatalf("log = %q, want the escalation record", log)
	}
	if log := f.logs.String(); !strings.Contains(log, "id=44") || !strings.Contains(log, "NOT released") {
		t.Fatalf("log = %q, want the run id and ownership-retention in the escalation record", log)
	}
	drainIdx := strings.Index(f.logs.String(), "drain deadline expired")
	escIdx := strings.Index(f.logs.String(), "terminating process")
	if drainIdx < 0 || escIdx < drainIdx {
		t.Fatalf("log ordering wrong: failed-drain must precede termination; log = %q", f.logs.String())
	}

	// The dependency-closure gate is still shut: no return while the worker is
	// live, even though termination has been invoked.
	select {
	case err := <-returned:
		t.Fatalf("Shutdown returned %v after escalation while the worker was live", err)
	default:
	}

	// Release the worker: its own terminal write lands (shutdown stop →
	// `failed`), the exit is observed, and only then does the gate open.
	close(f.target.putGate)
	if err := await(t, returned, "Shutdown late drain after escalation"); err != nil {
		t.Fatalf("Shutdown = %v, want nil after observed exit", err)
	}
	f.events.add("shutdown:returned")
	exec := waitForStatusWrite(t, f.store, MigFailed)
	if !strings.Contains(exec.sql, "completed_at = now()") {
		t.Fatalf("failed write = %q, want completed_at", exec.sql)
	}
	f.events.requireBefore(t, "terminate", "status:"+string(MigFailed))
	f.events.requireBefore(t, "terminate", "shutdown:returned")
}

// TestMigrator_CancelAgainstCutoverPersistenceRefuses pins the Astra impl-r2
// r3 finding 2 outcome coordination: cutover persistence runs on a detached
// context, so a handshake requested while the cutover UPDATE is in flight can
// drain against an exit that rests at `cutover`. Cancel must then return the
// typed ErrNotCancellable refusal — never a nil the admin adapter would report
// as HTTP "cancelled" — and must never fabricate a `cancelled` write the run
// did not select.
func TestMigrator_CancelAgainstCutoverPersistenceRefuses(t *testing.T) {
	f := newLifecycleFixture(t, 27)
	f.store.cutoverStarted = make(chan struct{}, 1)
	f.store.cutoverGate = make(chan struct{})
	key := sha256Hex("cutover-race")
	data := []byte("cutover-race")
	f.src.objs[key] = data
	f.target.objs[key] = data // verified target copy: the run skips the driver write

	f.openRun(t, context.Background(), []string{key}, []int64{int64(len(data))})

	// The run completed its backfill and is blocked INSIDE the cutover status
	// write — persistence in flight, uncommitted.
	select {
	case <-f.store.cutoverStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("run never entered the cutover status write")
	}

	// Cancel reads the row as `backfill` (the cutover write has not landed)
	// and starts the handshake against the still-registered run.
	watchRunCtxDone(f, "ctx:cancelled")
	cancelErr := make(chan error, 1)
	go func() { cancelErr <- f.mg.Cancel(context.Background(), f.id) }()
	waitEvent(t, f, "ctx:cancelled") // the stop signal was delivered mid-persistence

	close(f.store.cutoverGate) // the cutover UPDATE commits; the run exits at cutover

	err := await(t, cancelErr, "Cancel handshake against cutover persistence")
	if !errors.Is(err, ErrNotCancellable) {
		t.Fatalf("Cancel = %v, want ErrNotCancellable — cutover won the race, a drained handshake must not report a cancelled success", err)
	}
	if !strings.Contains(err.Error(), string(MigCutover)) {
		t.Fatalf("refusal = %v, want it to name the winning %q outcome", err, MigCutover)
	}
	if hasStatusWrite(f.store, MigCancelled) {
		t.Fatal("a cancelled write landed — the handshake must never fabricate an outcome the run did not select")
	}
	if !hasStatusWrite(f.store, MigCutover) {
		t.Fatal("the cutover write never landed")
	}
	// The drained run is released from the registry like any finished run; a
	// further handshake is refused against the row's cutover state (the run's
	// cutover write is DB truth).
	waitRunReleased(t, f.mg, f.id)
	f.store.statuses[f.id] = string(MigCutover)
	if err := f.mg.Cancel(context.Background(), f.id); !errors.Is(err, ErrNotCancellable) {
		t.Fatalf("post-drain Cancel = %v, want ErrNotCancellable (row rests at cutover)", err)
	}
}

// TestMigrator_ShutdownPendingAdmissionBeyondDrainDeadline pins the
// drain-deadline path of Astra impl-r2 r3 finding 1: the drain deadline is
// armed BEFORE the pending-admission wait, so a stalled INSERT cannot defer
// failed-drain logging even while an existing worker remains live. The
// admission is a failed drain itself: the dependency-closure gate stays
// withheld, the run it later materializes is cancelled and drained under the
// same contract, and Shutdown returns only after both exits were observed.
func TestMigrator_ShutdownPendingAdmissionBeyondDrainDeadline(t *testing.T) {
	f := newLifecycleFixture(t, 71)
	key := sha256Hex("deadline-live")
	f.src.objs[key] = []byte("deadline-live")

	// The live worker parks inside the driver when the stop signal arrives.
	// (The insert gate is installed only AFTER its admission resolved, so it
	// gates the pending admission alone.)
	f.openRun(t, context.Background(), []string{key}, []int64{int64(len("deadline-live"))})
	waitForPutStarted(t, f.target)
	f.store.insertGate = make(chan struct{})

	// The pending admission's run parks in its loader so its late drain is
	// deterministic after it registers (the fake's INSERT sequence gives it
	// the next id, 72).
	loaderGate := make(chan struct{})
	f.mg.newMigration = func(source, target blobMover) *Migration {
		mig := NewMigration(nil, source, target, f.mg.logger)
		mig.statusDB = f.store
		mig.blobRows = func(ctx context.Context) (scanCursor, error) {
			f.events.add("loader:entered:72")
			<-loaderGate
			return &closingRows{&reconRows{keys: []string{key}, sizes: []int64{int64(len("deadline-live"))}}}, nil
		}
		return mig
	}

	started := make(chan int64, 1)
	startErr := make(chan error, 1)
	go func() {
		id, err := f.mg.Start(context.Background(), f.src, f.target)
		started <- id
		startErr <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for f.store.insertCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("pending admission INSERT never started")
		}
		time.Sleep(2 * time.Millisecond)
	}

	returned := make(chan error, 1)
	go func() { returned <- f.mg.Shutdown(context.Background(), 80*time.Millisecond) }()

	// The stalled INSERT burns the whole drain budget: the pending-admission
	// failed-drain ERROR must fire while the INSERT is STILL held (pre-fix the
	// code blocked before the timer was even armed and nothing was logged).
	waitForLog(t, f.logs, "pending migration admission unresolved")
	time.Sleep(100 * time.Millisecond) // the drain deadline is long past
	select {
	case err := <-returned:
		t.Fatalf("Shutdown returned %v while a pending admission could still launch a worker — the dependency-closure gate must stay shut", err)
	default:
	}

	close(f.store.insertGate) // the admission resolves; its run joins the drain set
	if id := <-started; id != 72 {
		t.Fatalf("admitted id = %d, want 72 (the durable admission completes)", id)
	}
	if err := <-startErr; err != nil {
		t.Fatalf("Start = %v, want nil — its run drains under shutdown ownership", err)
	}

	// Drain both: the live worker's in-flight write finishes and the late
	// run's loader returns; each observes the shutdown cancellation at the
	// next boundary.
	close(f.target.putGate)
	close(loaderGate)

	if err := await(t, returned, "Shutdown drain beyond the pending deadline"); err != nil {
		t.Fatalf("Shutdown = %v, want nil after both exits were observed", err)
	}
	f.events.add("shutdown:returned")
	exec := waitForStatusWrite(t, f.store, MigFailed)
	if !strings.Contains(exec.sql, "completed_at = now()") {
		t.Fatalf("failed write = %q, want completed_at", exec.sql)
	}
	f.events.requireBefore(t, "status:"+string(MigFailed), "shutdown:returned")

	if _, err := f.mg.Start(context.Background(), f.src, f.target); !errors.Is(err, ErrAdmissionClosed) {
		t.Fatalf("Start after the drain = %v, want ErrAdmissionClosed", err)
	}
}

// TestMigrator_ShutdownPendingAdmissionBeyondOuterDeadlineEscalates pins the
// outer-deadline path of Astra impl-r2 r3 finding 1: a stalled admission
// cannot defer termination escalation past the outer deadline — even with an
// existing worker live — and the dependency-closure gate stays shut, even
// after the seamed escalation, until the admission resolves, its run drains,
// and every exit is observed.
func TestMigrator_ShutdownPendingAdmissionBeyondOuterDeadlineEscalates(t *testing.T) {
	f := newLifecycleFixture(t, 91)
	key := sha256Hex("outer-pending")
	f.src.objs[key] = []byte("outer-pending")

	// The existing worker stays live inside the driver: the stalled admission
	// must not be able to defer its failed-drain logging or the escalation.
	// (The insert gate is installed only AFTER its admission resolved, so it
	// gates the pending admission alone.)
	f.openRun(t, context.Background(), []string{key}, []int64{int64(len("outer-pending"))})
	waitForPutStarted(t, f.target)
	f.store.insertGate = make(chan struct{})

	loaderGate := make(chan struct{})
	f.mg.newMigration = func(source, target blobMover) *Migration {
		mig := NewMigration(nil, source, target, f.mg.logger)
		mig.statusDB = f.store
		mig.blobRows = func(ctx context.Context) (scanCursor, error) {
			f.events.add("loader:entered:92")
			<-loaderGate
			return &closingRows{&reconRows{keys: []string{key}, sizes: []int64{int64(len("outer-pending"))}}}, nil
		}
		return mig
	}

	started := make(chan int64, 1)
	startErr := make(chan error, 1)
	go func() {
		id, err := f.mg.Start(context.Background(), f.src, f.target)
		started <- id
		startErr <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for f.store.insertCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("pending admission INSERT never started")
		}
		time.Sleep(2 * time.Millisecond)
	}

	// The seamed escalation may fire more than once in tests (production
	// os.Exit never returns after the first).
	termCalls := make(chan int, 8)
	f.mg.terminateProcess = func(code int) {
		f.events.add("terminate")
		select {
		case termCalls <- code:
		default:
		}
	}

	outerCtx, cancelOuter := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancelOuter()
	returned := make(chan error, 1)
	go func() { returned <- f.mg.Shutdown(outerCtx, 40*time.Millisecond) }()

	// Drain deadline (40ms) burns on the stalled INSERT: the pending
	// failed-drain ERROR fires while the INSERT is still held.
	waitForLog(t, f.logs, "pending migration admission unresolved")

	// Outer deadline (120ms) overruns with the admission STILL unresolved and
	// the live worker blocked: escalation must fire — pre-fix it could never
	// happen while an admission was stalled.
	select {
	case code := <-termCalls:
		if code != 1 {
			t.Fatalf("termination code = %d, want 1", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("termination escalation never fired while the pending admission was stalled")
	}
	if log := f.logs.String(); !strings.Contains(log, "pending migration admission unresolved — terminating process") {
		t.Fatalf("log = %q, want the pending-admission escalation record", log)
	}

	// The gate is still shut: no return while the admission could launch a
	// worker.
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-returned:
		t.Fatalf("Shutdown returned %v after escalation while the pending admission was unresolved", err)
	default:
	}

	close(f.store.insertGate) // the admission resolves into run 92
	if id := <-started; id != 92 {
		t.Fatalf("admitted id = %d, want 92", id)
	}
	if err := <-startErr; err != nil {
		t.Fatalf("Start = %v, want nil — its run drains under shutdown ownership", err)
	}

	// Release both workers: their own terminal writes land (shutdown stop →
	// `failed`), the exits are observed, and only then does the gate open.
	close(f.target.putGate)
	close(loaderGate)

	if err := await(t, returned, "Shutdown late drain after the pending escalation"); err != nil {
		t.Fatalf("Shutdown = %v, want nil after all exits were observed", err)
	}
	f.events.add("shutdown:returned")
	waitForStatusWrite(t, f.store, MigFailed)
	f.events.requireBefore(t, "terminate", "status:"+string(MigFailed))
	f.events.requireBefore(t, "terminate", "shutdown:returned")
}

// TestMigrator_ShutdownSecondPendingAdmissionRacesOuterExpiry pins the
// deadlineFired-branch handoff (Astra impl-r4): with TWO pending admissions,
// the first exhausts the drain deadline and the OUTER deadline then expires
// while the SECOND is still in flight. That branch must resolve the admission
// EXCLUSIVELY in the pendingHot pass — falling through to the p.run fold
// reads the admission's run field with no synchronization (neither the mutex
// nor a done-receive covers it), racing Start's
// `pending.id, pending.run = id, run` registration write. go test -race is
// the oracle: pre-fix the unsynchronized read/write pair is reported here;
// post-fix the pendingHot pass reads p.run only after p.done closed.
//
// The interleaving is engineered to keep the pair UNSYNCHRONIZED: the insert
// gate is released by a relay on the OUTER context itself (carrying only the
// context clock, never Shutdown's post-read state), a beat AFTER ctx expiry
// so the ctx.Done branch is taken deterministically while the admission is
// still in flight; both materialized runs park in a ctx-blind loader so no
// execRun exit can publish post-read clocks through the registry mutex
// before the racing registration write lands.
func TestMigrator_ShutdownSecondPendingAdmissionRacesOuterExpiry(t *testing.T) {
	f := newLifecycleFixture(t, 61)
	key := sha256Hex("hot-race")
	data := []byte("hot-race")

	// BOTH admissions stall in flight, past the closing check: the first
	// burns the drain deadline, the second is still unresolved at outer
	// expiry — the two-step shape the single-admission deadline tests cannot
	// reach.
	f.store.insertGate = make(chan struct{})

	// Each materialized run gets its OWN cursor (as a real pool query would —
	// a shared reconRows would itself race between the two workers). The
	// ctx-blind loader parks each run at a KNOWN place so neither touches the
	// registry until the test releases it.
	loaderGate := make(chan struct{})
	f.mg.newMigration = func(source, target blobMover) *Migration {
		mig := NewMigration(nil, source, target, f.mg.logger)
		mig.statusDB = f.store
		mig.blobRows = func(ctx context.Context) (scanCursor, error) {
			f.events.add("loader:entered")
			<-loaderGate
			return &closingRows{&reconRows{keys: []string{key}, sizes: []int64{int64(len(data))}}}, nil
		}
		return mig
	}

	starts := make(chan int64, 2)
	startErrs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			id, err := f.mg.Start(context.Background(), f.src, f.target)
			starts <- id
			startErrs <- err
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.store.insertCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("admission INSERTs never started")
		}
		time.Sleep(2 * time.Millisecond)
	}

	// The seamed escalation fires once per unresolved entry while the outer
	// deadline is over (production os.Exit never returns after the first).
	termCalls := make(chan int, 8)
	f.mg.terminateProcess = func(code int) {
		f.events.add("terminate")
		select {
		case termCalls <- code:
		default:
		}
	}

	// Drain (40ms) burns on the FIRST pending admission; the OUTER deadline
	// (200ms) expires with the SECOND still in flight. The relay opens the
	// insert gate a beat AFTER ctx expiry — the second admission's
	// registration write then races the outer-expiry branch UNSYNCHRONIZED
	// (the relay publishes only the context clock, never Shutdown's).
	outerCtx, cancelOuter := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancelOuter()
	go func() {
		<-outerCtx.Done()
		time.Sleep(5 * time.Millisecond)
		close(f.store.insertGate)
	}()
	returned := make(chan error, 1)
	go func() { returned <- f.mg.Shutdown(outerCtx, 40*time.Millisecond) }()

	// Barrier: the first admission burned the whole drain budget — Shutdown is
	// now waiting on the SECOND with deadlineFired already set.
	waitForLog(t, f.logs, "drain deadline expired with a pending migration admission unresolved")

	// Outer expiry escalates while BOTH admissions are still unresolved (the
	// insert gate is still shut), and Shutdown keeps holding.
	select {
	case code := <-termCalls:
		if code != 1 {
			t.Fatalf("termination code = %d, want 1", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("termination escalation never fired while the second admission was in flight")
	}
	if log := f.logs.String(); !strings.Contains(log, "pending migration admission unresolved — terminating process") {
		t.Fatalf("log = %q, want the pending-admission escalation record", log)
	}
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-returned:
		t.Fatalf("Shutdown returned %v while a pending admission could still launch a worker", err)
	default:
	}

	// Both admissions resolved after outer expiry (the relay opened the gate):
	// two distinct durable admissions, none failed.
	ids := map[int64]bool{<-starts: true, <-starts: true}
	if len(ids) != 2 {
		t.Fatalf("admitted ids = %v, want two distinct durable admissions", ids)
	}
	for i := 0; i < 2; i++ {
		if err := <-startErrs; err != nil {
			t.Fatalf("Start = %v, want nil — both runs drain under shutdown ownership", err)
		}
	}

	// Release the parked late runs: each observes the shutdown cancellation at
	// its first row boundary and publishes its own terminal write.
	close(loaderGate)

	// Each late admission resolves inside pendingHot, folds its run into the
	// drain set, and Shutdown returns only after both exits were observed.
	if err := await(t, returned, "Shutdown drain of both late admissions"); err != nil {
		t.Fatalf("Shutdown = %v, want nil after both admissions resolved and their runs exited", err)
	}
	f.events.add("shutdown:returned")

	exec := waitForStatusWrite(t, f.store, MigFailed) // shutdown stops, not admin cancels
	if !strings.Contains(exec.sql, "completed_at = now()") {
		t.Fatalf("failed write = %q, want completed_at", exec.sql)
	}
	f.events.requireBefore(t, "terminate", "status:"+string(MigFailed))
	f.events.requireBefore(t, "terminate", "shutdown:returned")

	// Both resolved admissions left the pending list.
	f.mg.mu.Lock()
	pending := len(f.mg.pendingAdmissions)
	f.mg.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending list holds %d admissions after both resolved", pending)
	}

	if _, err := f.mg.Start(context.Background(), f.src, f.target); !errors.Is(err, ErrAdmissionClosed) {
		t.Fatalf("Start after the drain = %v, want ErrAdmissionClosed", err)
	}
}

// TestMigrator_PendingAdmissionSlotsClearedOnRemoval pins Astra impl-r2
// finding 3: removing a resolved admission clears the vacated backing-array
// slot (slices.Delete). A stale slot would retain the admission, whose run
// field retains the completed migration and its driver handles for the process
// lifetime — even after the registry release.
func TestMigrator_PendingAdmissionSlotsClearedOnRemoval(t *testing.T) {
	f := newLifecycleFixture(t, 81)
	f.store.insertGate = make(chan struct{})
	key := sha256Hex("slot-blob")
	data := []byte("slot-blob")
	f.target.objs[key] = data // verified target copies: both runs skip the driver

	// Two admissions park past the closing check with their INSERTs in
	// flight; each resolves into a registered run when the gate opens. The
	// seam serves each run its OWN cursor (as a real pool query would) — a
	// shared reconRows would itself race between the two workers.
	f.mg.newMigration = func(source, target blobMover) *Migration {
		mig := NewMigration(nil, source, target, f.mg.logger)
		mig.statusDB = f.store
		mig.blobRows = func(ctx context.Context) (scanCursor, error) {
			return &closingRows{&reconRows{keys: []string{key}, sizes: []int64{int64(len(data))}}}, nil
		}
		return mig
	}

	starts := make(chan int64, 2)
	for i := 0; i < 2; i++ {
		go func() {
			id, err := f.mg.Start(context.Background(), f.src, f.target)
			if err != nil {
				t.Errorf("Start: %v", err)
			}
			starts <- id
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.store.insertCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("admission INSERTs never started")
		}
		time.Sleep(2 * time.Millisecond)
	}

	close(f.store.insertGate)
	ids := map[int64]bool{<-starts: true, <-starts: true}
	if len(ids) != 2 {
		t.Fatalf("admitted ids = %v, want two distinct durable admissions", ids)
	}

	// Both runs complete (their copies are pre-verified) and are released.
	for id := range ids {
		waitRunReleased(t, f.mg, id)
	}

	// The pending list is empty AND its backing array carries no stale
	// admission pointers.
	f.mg.mu.Lock()
	pending := f.mg.pendingAdmissions
	trailing := append([]*pendingAdmission(nil), pending[len(pending):cap(pending)]...)
	f.mg.mu.Unlock()
	if len(pending) != 0 {
		t.Fatalf("pending list = %v, want empty after both admissions resolved", pending)
	}
	for i, p := range trailing {
		if p != nil {
			t.Fatalf("pending backing-array slot %d retains a resolved admission — the vacated slot must be cleared", i)
		}
	}
}
