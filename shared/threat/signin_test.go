package threat

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakeTx records Exec calls and satisfies pgx.Tx (all other methods are no-ops).
type fakeTx struct {
	calls []struct {
		sql  string
		args []any
	}
	committed bool
}

func (f *fakeTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.calls = append(f.calls, struct {
		sql  string
		args []any
	}{sql, args})
	return pgconn.CommandTag{}, nil
}
func (f *fakeTx) Commit(_ context.Context) error   { f.committed = true; return nil }
func (f *fakeTx) Rollback(_ context.Context) error { return nil }

// pgx.Tx has many methods; satisfy them all as no-ops.
func (f *fakeTx) Begin(_ context.Context) (pgx.Tx, error) { return f, nil }
func (f *fakeTx) CopyFrom(_ context.Context, _ pgx.Identifier, _ []string, _ pgx.CopyFromSource) (int64, error) {
	return 0, nil
}
func (f *fakeTx) SendBatch(_ context.Context, _ *pgx.Batch) pgx.BatchResults { return nil }
func (f *fakeTx) LargeObjects() pgx.LargeObjects                             { return pgx.LargeObjects{} }
func (f *fakeTx) Prepare(_ context.Context, _, _ string) (*pgconn.StatementDescription, error) {
	return nil, nil
}
func (f *fakeTx) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) { return nil, nil }
func (f *fakeTx) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row        { return nil }
func (f *fakeTx) Conn() *pgx.Conn                                               { return nil }

// fakePool satisfies SignInPool. For the known-user path it returns a fakeTx.
type fakePool struct {
	execSQL  string
	execArgs []any
	tx       *fakeTx
}

func (f *fakePool) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.execSQL = sql
	f.execArgs = args
	return pgconn.CommandTag{}, nil
}
func (f *fakePool) Begin(_ context.Context) (pgx.Tx, error) {
	f.tx = &fakeTx{}
	return f.tx, nil
}

func TestRecordSignIn_NullUserOnZeroID(t *testing.T) {
	fp := &fakePool{}
	RecordSignIn(context.Background(), fp, SignInRecord{
		UserID: 0, Success: false, Client: "imap", Protocol: "imap",
		AuthMethod: "app_password", SourceIP: "203.0.113.7", FailReason: "bad_pw",
	})
	if fp.execSQL == "" {
		t.Fatal("expected an INSERT to be issued via pool.Exec")
	}
	// UserID 0 must be passed as nil (NULL), not 0 (which FKs to user id 0).
	if fp.execArgs[0] != nil {
		t.Errorf("UserID 0 must write NULL, got %#v", fp.execArgs[0])
	}
	if fp.tx != nil {
		t.Error("unknown-user path must NOT open a transaction")
	}
}

func TestRecordSignIn_KnownUserPassesID(t *testing.T) {
	fp := &fakePool{}
	RecordSignIn(context.Background(), fp, SignInRecord{
		UserID: 42, Success: true, Client: "web", Protocol: "http", AuthMethod: "webauthn",
	})
	if fp.execSQL != "" {
		t.Error("known-user path must NOT use pool.Exec (needs transaction)")
	}
	if fp.tx == nil {
		t.Fatal("known-user path must open a transaction")
	}
	if !fp.tx.committed {
		t.Error("transaction must be committed")
	}
	// First tx call: set_config; second: INSERT.
	if len(fp.tx.calls) < 2 {
		t.Fatalf("expected at least 2 tx.Exec calls, got %d", len(fp.tx.calls))
	}
	if !strings.Contains(fp.tx.calls[0].sql, "set_config") {
		t.Errorf("first tx call must be set_config, got %q", fp.tx.calls[0].sql)
	}
	// set_config arg must be "42" (string).
	if fp.tx.calls[0].args[0] != "42" {
		t.Errorf("set_config arg must be \"42\", got %#v", fp.tx.calls[0].args[0])
	}
	// INSERT first arg: user_id — must be int64(42).
	if id, ok := fp.tx.calls[1].args[0].(int64); !ok || id != 42 {
		t.Errorf("INSERT user_id must be int64(42), got %#v", fp.tx.calls[1].args[0])
	}
}

// TestRecordSignIn_ScopedWriteFailureDropsQuietly drives the WP6 delegation's
// error arm: the scoped write (or its begin/set_config/commit wrapper) fails,
// the row is dropped best-effort, and no panic escapes RecordSignIn. The
// failing tx Exec surfaces as the seam's error (signin.go's single warn arm).
func TestRecordSignIn_ScopedWriteFailureDropsQuietly(t *testing.T) {
	fp := &failingBeginPool{}
	RecordSignIn(context.Background(), fp, SignInRecord{
		UserID: 42, Success: true, Client: "imap", Protocol: "imap",
		AuthMethod: "password", SourceIP: "203.0.113.9",
	})
	if !fp.beginAttempted {
		t.Fatal("expected Begin to be attempted for a known user")
	}
}

// failingBeginPool fails Begin — the earliest failure the dbscope seam
// converts into the drop-with-warn path.
type failingBeginPool struct{ beginAttempted bool }

func (f *failingBeginPool) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (f *failingBeginPool) Begin(_ context.Context) (pgx.Tx, error) {
	f.beginAttempted = true
	return nil, errors.New("pool exhausted")
}
