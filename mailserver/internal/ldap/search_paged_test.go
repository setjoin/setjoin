package ldap

import (
	"context"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	message "github.com/vjeantet/goldap/message"
	ldapserver "github.com/vjeantet/ldapserver"
)

// captureWriter records every ProtocolOp written, so a test can assert the
// final SearchResultDone code.
type captureWriter struct{ ops []message.ProtocolOp }

func (c *captureWriter) Write(po message.ProtocolOp) { c.ops = append(c.ops, po) }

// fakeRows is a minimal pgx.Rows: it yields `remaining` empty rows then stops.
// Only Next/Scan/Err/Close are exercised by pagedSearch; the rest satisfy the
// interface.
type fakeRows struct{ remaining int }

func (f *fakeRows) Next() bool {
	if f.remaining <= 0 {
		return false
	}
	f.remaining--
	return true
}
func (f *fakeRows) Scan(dest ...any) error                       { return nil }
func (f *fakeRows) Close()                                       {}
func (f *fakeRows) Err() error                                   { return nil }
func (f *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (f *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (f *fakeRows) Values() ([]any, error)                       { return nil, nil }
func (f *fakeRows) RawValues() [][]byte                          { return nil }
func (f *fakeRows) Conn() *pgx.Conn                              { return nil }

func lastDone(t *testing.T, ops []message.ProtocolOp) message.ProtocolOp {
	t.Helper()
	if len(ops) == 0 {
		t.Fatal("no ProtocolOp written")
	}
	return ops[len(ops)-1]
}

// TestPagedSearch_DeadlineExceeded guards the folded-in bug fix: every OU's
// subtree search now routes through pagedSearch, so a ctx-deadline mid-search
// yields TimeLimitExceeded (People previously returned a bare Success — audit
// #10). It also covers the Success and SizeLimitExceeded exits of the shared
// loop. No DB needed.
func TestPagedSearch_DeadlineExceeded(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	msg := &ldapserver.Message{Done: make(chan bool)}
	buildEntry := func(pgx.Rows) (message.SearchResultEntry, error) {
		return message.SearchResultEntry{}, nil
	}

	cases := []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		rows int
		lim  int
		want message.ProtocolOp
	}{
		{
			name: "deadline exceeded -> TimeLimitExceeded",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
			},
			rows: 0,
			lim:  10,
			want: ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultTimeLimitExceeded),
		},
		{
			name: "no deadline, empty -> Success",
			ctx:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			rows: 0,
			lim:  10,
			want: ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess),
		},
		{
			name: "over limit -> SizeLimitExceeded",
			ctx:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			rows: 2,
			lim:  1,
			want: ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSizeLimitExceeded),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := tc.ctx()
			defer cancel()
			w := &captureWriter{}
			s.pagedSearch(ctx, w, msg, tc.lim, &fakeRows{remaining: tc.rows}, buildEntry)
			got := lastDone(t, w.ops)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Done code = %#v, want %#v", got, tc.want)
			}
		})
	}
}
