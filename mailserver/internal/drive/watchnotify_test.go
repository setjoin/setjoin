package drive

// Unit tests for WatchNotifier — fake pool rows, no live DB/LISTEN (plan
// Task 11). The notify func is injected so the emitted (channel, payload)
// set can be asserted directly.

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakeRow is one canned row of positional values.
type fakeRow struct{ vals []any }

// fakeRows implements pgx.Rows over a fixed slice of fakeRow.
type fakeRows struct {
	rows []fakeRow
	idx  int
}

func (f *fakeRows) Next() bool { f.idx++; return f.idx <= len(f.rows) }
func (f *fakeRows) Scan(dest ...any) error {
	row := f.rows[f.idx-1].vals
	for i, d := range dest {
		switch v := d.(type) {
		case *int64:
			*v = row[i].(int64)
		case *string:
			*v = row[i].(string)
		}
	}
	return nil
}
func (f *fakeRows) Close()                                       {}
func (f *fakeRows) Err() error                                   { return nil }
func (f *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (f *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (f *fakeRows) Values() ([]any, error)                       { return nil, nil }
func (f *fakeRows) RawValues() [][]byte                          { return nil }
func (f *fakeRows) Conn() *pgx.Conn                              { return nil }

// fakeWatchPool implements driveWatchRows: the drive_changes lookup returns
// changeRows, the ancestor-walk-over-drive_watches lookup returns
// watcherRows. changeQueried records whether the drive_changes branch ran.
type fakeWatchPool struct {
	changeRows    []fakeRow
	watcherRows   []fakeRow
	changeQueried bool
}

func (p *fakeWatchPool) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	if strings.Contains(sql, "drive_changes") {
		p.changeQueried = true
		return &fakeRows{rows: p.changeRows}, nil
	}
	return &fakeRows{rows: p.watcherRows}, nil
}

type capturedPush struct{ channel, payload string }

func TestWatchNotifier_SeqPayloadFansOutToWatchers(t *testing.T) {
	pool := &fakeWatchPool{
		changeRows:  []fakeRow{{vals: []any{int64(10), "update"}}},
		watcherRows: []fakeRow{{vals: []any{int64(5)}}, {vals: []any{int64(6)}}},
	}
	var mu sync.Mutex
	var sent []capturedPush
	notify := func(_ context.Context, channel, payload string) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, capturedPush{channel, payload})
		return nil
	}
	wn := NewWatchNotifier(pool, notify, discardLogger())
	wn.Handle(context.Background(), `{"spaceId":1,"seq":42}`)

	if len(sent) != 2 {
		t.Fatalf("want 2 pushes, got %d: %+v", len(sent), sent)
	}
	seen := map[string]bool{"drive-watch:5": false, "drive-watch:6": false}
	for _, s := range sent {
		if _, ok := seen[s.channel]; !ok {
			t.Errorf("unexpected channel %q", s.channel)
		}
		seen[s.channel] = true
		var payload map[string]any
		if err := json.Unmarshal([]byte(s.payload), &payload); err != nil {
			t.Fatalf("payload not JSON: %v", err)
		}
		if payload["nodeId"] != float64(10) || payload["op"] != "update" || payload["spaceId"] != float64(1) {
			t.Errorf("payload = %v, want nodeId=10 op=update spaceId=1", payload)
		}
	}
	for ch, wasSent := range seen {
		if !wasSent {
			t.Errorf("channel %q never received a push", ch)
		}
	}
}

func TestWatchNotifier_DedupesWithinWindow(t *testing.T) {
	pool := &fakeWatchPool{
		changeRows:  []fakeRow{{vals: []any{int64(10), "update"}}},
		watcherRows: []fakeRow{{vals: []any{int64(5)}}},
	}
	var count int
	notify := func(context.Context, string, string) error { count++; return nil }
	wn := NewWatchNotifier(pool, notify, discardLogger())
	wn.Handle(context.Background(), `{"spaceId":1,"seq":42}`)
	wn.Handle(context.Background(), `{"spaceId":1,"seq":42}`) // same (user,node,op) inside the window
	if count != 1 {
		t.Errorf("want 1 push (deduped within %s), got %d", dedupeWindow, count)
	}
}

func TestWatchNotifier_LockKindPayloadSkipsChangeLookupAndUsesLockOp(t *testing.T) {
	pool := &fakeWatchPool{watcherRows: []fakeRow{{vals: []any{int64(7)}}}}
	var gotChannel, gotPayload string
	notify := func(_ context.Context, channel, payload string) error {
		gotChannel, gotPayload = channel, payload
		return nil
	}
	wn := NewWatchNotifier(pool, notify, discardLogger())
	wn.Handle(context.Background(), `{"spaceId":2,"kind":"lock","nodeId":99}`)

	if gotChannel != "drive-watch:7" {
		t.Fatalf("channel = %q, want drive-watch:7", gotChannel)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(gotPayload), &payload); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if payload["op"] != "lock" || payload["nodeId"] != float64(99) || payload["spaceId"] != float64(2) {
		t.Errorf("payload = %v, want op=lock nodeId=99 spaceId=2", payload)
	}
	if pool.changeQueried {
		t.Error("a kind:lock (no-seq) payload must never query drive_changes")
	}
}

func TestWatchNotifier_MalformedPayloadDropsSilently(t *testing.T) {
	pool := &fakeWatchPool{}
	called := false
	notify := func(context.Context, string, string) error { called = true; return nil }
	wn := NewWatchNotifier(pool, notify, discardLogger())
	wn.Handle(context.Background(), `not json`)
	wn.Handle(context.Background(), `{"spaceId":1}`) // neither seq nor kind:"lock"
	if called {
		t.Error("malformed/unrecognized payloads must never trigger a push")
	}
}

func TestWatchNotifier_NoWatchersNoPush(t *testing.T) {
	pool := &fakeWatchPool{changeRows: []fakeRow{{vals: []any{int64(10), "update"}}}}
	called := false
	notify := func(context.Context, string, string) error { called = true; return nil }
	wn := NewWatchNotifier(pool, notify, discardLogger())
	wn.Handle(context.Background(), `{"spaceId":1,"seq":42}`)
	if called {
		t.Error("no matching watchers must never trigger a push")
	}
}
