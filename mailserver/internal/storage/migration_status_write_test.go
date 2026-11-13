package storage

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// statusCall records one detached status write as observed by the fake store.
// errAtExec/hasDeadline/deadline are snapshotted at store ENTRY: setStatus's
// deferred cancel fires before the caller can inspect the context afterwards.
type statusCall struct {
	sql         string
	args        []any
	errAtExec   error
	hasDeadline bool
	deadline    time.Time
	returnedErr error // the error the store handed back to setStatus
}

// fakeStatusStore satisfies the statusStore surface with fault injection
// (err) and a blocking mode (blockUntilCtxDone) for the bounded-termination
// test.
type fakeStatusStore struct {
	err               error
	blockUntilCtxDone bool
	calls             []statusCall
}

func (f *fakeStatusStore) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	call := statusCall{sql: sql, args: args}
	call.errAtExec = ctx.Err()
	call.deadline, call.hasDeadline = ctx.Deadline()
	f.calls = append(f.calls, call)

	var retErr error
	if f.blockUntilCtxDone {
		<-ctx.Done()
		retErr = ctx.Err()
	} else {
		retErr = f.err
	}
	f.calls[len(f.calls)-1].returnedErr = retErr
	if retErr != nil {
		return pgconn.CommandTag{}, retErr
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

// TestMigrationSetStatus_CancelledParentStillPersists pins the detach
// contract: the terminal status write must proceed even though the parent
// context is already cancelled (Cancel() cancels the run context, and it is
// exactly that cancellation which used to swallow the failed/cancelled write).
// The detached context must arrive at the store live and uncancelled, carrying
// the migration ID and the intended status.
func TestMigrationSetStatus_CancelledParentStillPersists(t *testing.T) {
	fake := &fakeStatusStore{}
	m := NewMigration(nil, nil, nil, reconLogger())
	m.statusDB = fake

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m.setStatus(ctx, 42, MigCancelled)

	if len(fake.calls) != 1 {
		t.Fatalf("status writes = %d, want 1 (cancelled parent must not swallow the write)", len(fake.calls))
	}
	call := fake.calls[0]
	if err := call.errAtExec; err != nil {
		t.Fatalf("detached write context at store entry = %v, want live (parent cancellation must not leak)", err)
	}
	if !call.hasDeadline || !call.deadline.After(time.Now().Add(-statusWriteTimeout)) {
		t.Fatalf("detached write context deadline = (%v, %v), want a live bound", call.deadline, call.hasDeadline)
	}
	if !strings.Contains(call.sql, "UPDATE storage_migrations") {
		t.Fatalf("sql = %q, want the storage_migrations status update", call.sql)
	}
	if len(call.args) != 2 || call.args[0] != string(MigCancelled) || call.args[1] != int64(42) {
		t.Fatalf("args = %v, want [cancelled 42] (intended status + migration ID)", call.args)
	}
	if call.returnedErr != nil {
		t.Fatalf("store returned %v, want a successful persist", call.returnedErr)
	}
}

// TestMigrationSetStatus_PersistenceFailureHandled pins the error-handling
// leg: a failed terminal write must never be silently ignored (it strands the
// row in a transitional status with no reconciliation evidence) — the failure
// is surfaced with the migration ID and the intended status, and setStatus
// returns normally.
func TestMigrationSetStatus_PersistenceFailureHandled(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	fake := &fakeStatusStore{err: errors.New("db stalled")}
	m := NewMigration(nil, nil, nil, logger)
	m.statusDB = fake

	m.setStatus(context.Background(), 7, MigFailed) // must not panic

	log := buf.String()
	if !strings.Contains(log, "status write failed") {
		t.Fatalf("log = %q, want the status-write failure", log)
	}
	if !strings.Contains(log, "id=7") {
		t.Fatalf("log = %q, want the migration ID in the failure record", log)
	}
	if !strings.Contains(log, "intended_status=failed") {
		t.Fatalf("log = %q, want the intended status in the failure record", log)
	}
}

// TestMigrationSetStatus_BoundedTermination pins the timeout leg: the detached
// write is bounded by its own deadline, so a persistence layer that hangs
// (stalled database) cannot strand the worker — setStatus returns once the
// bound expires, and the store observed DeadlineExceeded, not a hang.
func TestMigrationSetStatus_BoundedTermination(t *testing.T) {
	prev := statusWriteTimeout
	statusWriteTimeout = 25 * time.Millisecond
	t.Cleanup(func() { statusWriteTimeout = prev })

	fake := &fakeStatusStore{blockUntilCtxDone: true}
	m := NewMigration(nil, nil, nil, reconLogger())
	m.statusDB = fake

	done := make(chan struct{})
	go func() {
		m.setStatus(context.Background(), 9, MigCompleted)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("setStatus did not return after the bounded write deadline — worker would hang")
	}

	if len(fake.calls) != 1 {
		t.Fatalf("status writes = %d, want 1", len(fake.calls))
	}
	call := fake.calls[0]
	if !call.hasDeadline {
		t.Fatal("detached write context has no deadline — write is unbounded")
	}
	if !errors.Is(call.returnedErr, context.DeadlineExceeded) {
		t.Fatalf("store returned %v, want context.DeadlineExceeded (write terminated by the bound)", call.returnedErr)
	}
}
