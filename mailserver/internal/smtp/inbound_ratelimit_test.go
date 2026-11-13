package smtp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// fakeRow is a stub pgx.Row whose Scan writes a fixed bool (when scanErr is
// nil) or returns scanErr. It lets us drive allowPerIPConn without a live DB.
type fakeRow struct {
	val     bool
	scanErr error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	if len(dest) == 1 {
		if p, ok := dest[0].(*bool); ok {
			*p = r.val
		}
	}
	return nil
}

// fakeRateLimitQuerier records the SQL + args of the last QueryRow call and
// returns a preset row. It satisfies rateLimitQuerier.
type fakeRateLimitQuerier struct {
	row     pgx.Row
	lastSQL string
	lastArg []any
}

func (q *fakeRateLimitQuerier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	q.lastSQL = sql
	q.lastArg = args
	return q.row
}

func TestDefaultPerIPConnPerMin(t *testing.T) {
	if defaultPerIPConnPerMin <= 0 {
		t.Fatalf("defaultPerIPConnPerMin = %d, must be a positive cap", defaultPerIPConnPerMin)
	}
}

func TestAllowPerIPConnUnderLimit(t *testing.T) {
	// Counter row exists and count < limit → allowed.
	q := &fakeRateLimitQuerier{row: fakeRow{val: true}}
	if !allowPerIPConn(context.Background(), q, nil, "203.0.113.7", defaultPerIPConnPerMin) {
		t.Error("expected allow when count is under the limit")
	}
}

func TestAllowPerIPConnOverLimit(t *testing.T) {
	// Counter row exists and count >= limit → blocked.
	q := &fakeRateLimitQuerier{row: fakeRow{val: false}}
	if allowPerIPConn(context.Background(), q, nil, "203.0.113.7", defaultPerIPConnPerMin) {
		t.Error("expected block when count is at/over the limit")
	}
}

func TestAllowPerIPConnFailsOpen(t *testing.T) {
	// A DB error must fail OPEN (allow) so a blip can't lock out all mail.
	q := &fakeRateLimitQuerier{row: fakeRow{scanErr: errors.New("connection refused")}}
	if !allowPerIPConn(context.Background(), q, nil, "203.0.113.7", defaultPerIPConnPerMin) {
		t.Error("expected fail-open (allow) on a DB/scan error")
	}
}

func TestAllowPerIPConnBindsTwoPlaceholders(t *testing.T) {
	// The fix's core: TWO placeholders — $1 = numeric limit, $2 = text key.
	// The old bug bound one arg (the IP-key string) to both `count < $1` and
	// `key = $1`, so the limit never enforced. Assert both args are passed and
	// are the right types/values, and that the SQL references $1 AND $2.
	q := &fakeRateLimitQuerier{row: fakeRow{val: true}}
	allowPerIPConn(context.Background(), q, nil, "198.51.100.42", defaultPerIPConnPerMin)

	if len(q.lastArg) != 2 {
		t.Fatalf("expected 2 query args (limit, key), got %d: %v", len(q.lastArg), q.lastArg)
	}
	limit, ok := q.lastArg[0].(int)
	if !ok {
		t.Fatalf("arg[0] (limit) should be an int, got %T", q.lastArg[0])
	}
	if limit != defaultPerIPConnPerMin {
		t.Errorf("arg[0] (limit) = %d, want %d", limit, defaultPerIPConnPerMin)
	}
	key, ok := q.lastArg[1].(string)
	if !ok {
		t.Fatalf("arg[1] (key) should be a string, got %T", q.lastArg[1])
	}
	if key != "smtp:conn:198.51.100.42" {
		t.Errorf("arg[1] (key) = %q, want %q", key, "smtp:conn:198.51.100.42")
	}
	// Guard against a regression back to the single-placeholder form.
	if !strings.Contains(q.lastSQL, "$1") || !strings.Contains(q.lastSQL, "$2") {
		t.Errorf("query must reference both $1 and $2, got: %s", q.lastSQL)
	}
}
