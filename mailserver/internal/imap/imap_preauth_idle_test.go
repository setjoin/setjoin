package imap

// Pre-auth IDLE admission tests (work package med-shard3-012, finding
// D-MAILSERVER-INTERNAL-IMAP-F-002, rule imap/preauth-idle-no-deadline,
// CWE-770).
//
// Pre-fix hole: IDLE was the only long-lived command dispatched without an
// authed check (the handleConn switch ran the idle loops directly). Both loops
// call clearReadDeadline so a quiet client is not disconnected mid-idle —
// reachable pre-authentication, that deadline drop let an unauthenticated
// socket hold a tlsutil.LimitListener accept slot indefinitely: ~maxConns
// silent sockets denied the whole listener (every command-loop read otherwise
// re-arms the 30-minute slowloris deadline via readCommandLine).
//
// Post-fix contract pinned here:
//   - IDLE before authentication is rejected with NO [AUTHENTICATIONREQUIRED]
//     (RFC 5530; IDLE is an authenticated-state command per RFC 9051 §6.3.13)
//     BEFORE any deadline is dropped — the read deadline stays as armed by
//     readCommandLine, the command loop stays responsive, and no `+ idling`
//     continuation is ever emitted pre-auth.
//   - Availability: unauthenticated IDLE attempts cannot enter an unbounded
//     hold, so a real listener under tlsutil.LimitListener keeps accepting new
//     connections once the (ordinary, deadline-bounded) sockets go away.
//   - Regression: authenticated long-lived IDLE behavior is unchanged —
//     idleSimple still clears the read deadline for the duration of the idle
//     and DONE still completes it; the dispatcher==nil dispatch arm (with a
//     selected mailbox) is unchanged.

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// blockingReader models a silent socket: Read blocks forever. If the pre-fix
// code reached idleSimple pre-auth, the idle loop blocks on this reader past
// any deadline (the deadline was cleared) — the timeout guards below turn that
// regression into a test failure instead of a hang.
type blockingReader struct{}

func (blockingReader) Read(p []byte) (int, error) { select {} }

// scriptConn is a net.Conn whose reads come from a fixed script and whose
// writes and SetReadDeadline calls are recorded for assertions. Read returns
// io.EOF once the script is exhausted.
type scriptConn struct {
	mu        sync.Mutex
	script    io.Reader
	writes    bytes.Buffer
	deadlines []time.Time
}

func newScriptConn(script string) *scriptConn {
	return &scriptConn{script: strings.NewReader(script)}
}

// newSilentScriptConn returns a scriptConn that never delivers a byte (the
// quiet-socket case the pre-auth deadline exists for).
func newSilentScriptConn() *scriptConn {
	return &scriptConn{script: blockingReader{}}
}

func (c *scriptConn) Read(p []byte) (int, error) { return c.script.Read(p) }

func (c *scriptConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes.Write(p)
}

func (c *scriptConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadlines = append(c.deadlines, t)
	return nil
}

func (c *scriptConn) transcript() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes.String()
}

func (c *scriptConn) recordedDeadlines() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.deadlines...)
}

func (c *scriptConn) Close() error                     { return nil }
func (c *scriptConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 143} }
func (c *scriptConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50001} }
func (c *scriptConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptConn) SetWriteDeadline(time.Time) error { return nil }

// TestPreauthIDLERejectedWithoutEnteringIdle pins the primary control: IDLE
// from an unauthenticated connection is rejected with NO
// [AUTHENTICATIONREQUIRED] and returns WITHOUT entering an idle loop — no
// `+ idling` continuation, no identity or deadline movement. Against the
// pre-fix code this test times out: the handler entered idleSimple on the
// silent conn and never returned.
func TestPreauthIDLERejectedWithoutEnteringIdle(t *testing.T) {
	conn := newSilentScriptConn()
	c := &connState{
		srv:  &Server{logger: slog.Default()},
		conn: conn,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.handleIdle(context.Background(), "I1")
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pre-auth IDLE did not return — an unauthenticated idle hold is reachable again")
	}

	got := conn.transcript()
	if !strings.Contains(got, "I1 NO") || !strings.Contains(got, "[AUTHENTICATIONREQUIRED]") {
		t.Fatalf("pre-auth IDLE replied %q, want I1 NO [AUTHENTICATIONREQUIRED]", got)
	}
	if strings.Contains(got, "+ idling") {
		t.Fatalf("pre-auth IDLE emitted an idle continuation: %q", got)
	}
	// The guard must not touch the read deadline at all: the ordinary
	// readCommandLine slowloris deadline stays armed exactly as armed. The
	// pre-fix code cleared it here (one zero-time deadline recorded).
	if n := len(conn.recordedDeadlines()); n != 0 {
		t.Fatalf("pre-auth IDLE touched the read deadline %d time(s): %v", n, conn.recordedDeadlines())
	}
	if c.authed || c.userID != 0 || c.mailboxID != 0 {
		t.Fatalf("rejected IDLE moved connection state: authed=%v userID=%d mailboxID=%d",
			c.authed, c.userID, c.mailboxID)
	}
}

// TestAuthenticatedSimpleIdleStillClearsReadDeadline is the regression arm:
// authenticated long-lived IDLE behavior is unchanged. With no dispatcher the
// dispatch lands in idleSimple even with a selected mailbox; idle still drops
// the command-loop read deadline for its duration (the deliberate
// accommodation this package must not regress) and DONE completes it.
func TestAuthenticatedSimpleIdleStillClearsReadDeadline(t *testing.T) {
	conn := newScriptConn("DONE\r\n")
	c := &connState{
		srv:       &Server{logger: slog.Default()},
		conn:      conn,
		reader:    bufio.NewReader(conn),
		authed:    true,
		userID:    7,
		mailboxID: 11,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.handleIdle(context.Background(), "I2")
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("authenticated IDLE did not return after DONE")
	}

	got := conn.transcript()
	if !strings.Contains(got, "+ idling") {
		t.Fatalf("authenticated IDLE lost its continuation reply: %q", got)
	}
	if !strings.Contains(got, "I2 OK IDLE completed") {
		t.Fatalf("authenticated IDLE did not complete on DONE: %q", got)
	}
	deadlines := conn.recordedDeadlines()
	if len(deadlines) != 1 || !deadlines[0].IsZero() {
		t.Fatalf("authenticated IDLE read-deadline handling changed: %v, want exactly one zero-time clear", deadlines)
	}
}

// TestPreauthIDLEListenerStaysAvailable is the availability arm, driven end to
// end against a real listener under tlsutil.LimitListener (no DB needed — the
// guard rejects before any pool access). maxConns pre-auth sockets each send
// IDLE: every one gets the rejection instead of an idle continuation, every
// command loop keeps answering afterwards, and once those ordinary sockets
// close, the listener accepts new connections again.
func TestPreauthIDLEListenerStaysAvailable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewServer(nil, "127.0.0.1:0", nil, slog.Default(), nil, nil)
	s.SetMaxConns(2)
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := s.listener.Addr().String()

	type idleClient struct {
		conn   net.Conn
		reader *bufio.Reader
	}
	clients := make([]idleClient, 0, 2)
	for i := 0; i < 2; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		clients = append(clients, idleClient{conn: conn, reader: bufio.NewReader(conn)})
	}
	defer func() {
		for _, cl := range clients {
			_ = cl.conn.Close()
		}
	}()

	readLine := func(cl idleClient) string {
		_ = cl.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, err := cl.reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read reply: %v", err)
		}
		return line
	}

	for i, cl := range clients {
		greeting := readLine(cl)
		if !strings.HasPrefix(greeting, "* OK") {
			t.Fatalf("client %d greeting = %q", i, greeting)
		}
		if _, err := cl.conn.Write([]byte("i1 IDLE\r\n")); err != nil {
			t.Fatalf("client %d write IDLE: %v", i, err)
		}
		reply := readLine(cl)
		if !strings.HasPrefix(reply, "i1 NO") || !strings.Contains(reply, "[AUTHENTICATIONREQUIRED]") {
			t.Fatalf("client %d pre-auth IDLE reply = %q, want i1 NO [AUTHENTICATIONREQUIRED]", i, reply)
		}
		if strings.Contains(reply, "+ idling") {
			t.Fatalf("client %d received an idle continuation pre-auth: %q", i, reply)
		}
		// The command loop must keep answering after the rejected IDLE. Pre-fix
		// this write starved inside the unbounded idle loop and the NOOP was
		// never answered.
		if _, err := cl.conn.Write([]byte("i2 NOOP\r\n")); err != nil {
			t.Fatalf("client %d write NOOP: %v", i, err)
		}
		if reply := readLine(cl); !strings.HasPrefix(reply, "i2 OK") {
			t.Fatalf("client %d NOOP after rejected IDLE = %q, want i2 OK (loop wedged?)", i, reply)
		}
	}

	// Release the ordinary (deadline-bounded) sockets; the listener must accept
	// again — unauthenticated IDLE left nothing pinned on the accept semaphore.
	for _, cl := range clients {
		_ = cl.conn.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			greeting, err := bufio.NewReader(conn).ReadString('\n')
			_ = conn.Close()
			if err == nil && strings.HasPrefix(greeting, "* OK") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("listener did not serve a fresh connection after pre-auth IDLE sockets closed (greeting=%q err=%v)", greeting, err)
			}
		} else if time.Now().After(deadline) {
			t.Fatalf("listener stopped accepting after pre-auth IDLE sockets closed: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestAuthenticatedIDLEAfterSelectUnchanged is the DB-gated end-to-end arm: a
// real account fixture, a real SELECT Inbox, then IDLE through the guarded
// dispatch. The authenticated connection must still get the `+ idling`
// continuation and complete on DONE — the rejection exists pre-auth only.
func TestAuthenticatedIDLEAfterSelectUnchanged(t *testing.T) {
	sDSN := superDSN()
	if sDSN == "" {
		t.Skip("neither TEST_DB_DSN nor DB_DSN set — skipping IMAP authenticated-IDLE regression test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, sDSN)
	if err != nil {
		t.Skipf("cannot connect test pool (%s): %v", sDSN, err)
	}
	// NOTE: no deferred pool.Close() — t.Cleanup teardown owns it (same as the
	// RLS isolation suite).

	var mbID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account('imapIdleRegress')`).Scan(&mbID); err != nil {
		t.Fatalf("mk_account: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id = $1`, mbID).Scan(&userID); err != nil {
		t.Fatalf("resolve account owner: %v", err)
	}
	t.Cleanup(func() {
		// Same teardown idiom as the RLS isolation suite: mk_account COMMITs
		// real rows into the shared test DB, and the primary-mailbox/user
		// delete guards need trigger suspension on ONE superuser connection.
		if conn, err := pool.Acquire(ctx); err == nil {
			_, _ = conn.Exec(ctx, `SET session_replication_role = 'replica'`)
			_, _ = conn.Exec(ctx, `DELETE FROM message_tags WHERE message_id IN (SELECT id FROM messages WHERE mailbox_id = ANY($1))`, []int64{mbID})
			_, _ = conn.Exec(ctx, `DELETE FROM messages WHERE mailbox_id = ANY($1)`, []int64{mbID})
			_, _ = conn.Exec(ctx, `DELETE FROM mailbox_audit_log WHERE mailbox_id = ANY($1)`, []int64{mbID})
			_, _ = conn.Exec(ctx, `DELETE FROM tags WHERE mailbox_id = ANY($1)`, []int64{mbID})
			_, _ = conn.Exec(ctx, `DELETE FROM folders WHERE mailbox_id = ANY($1)`, []int64{mbID})
			_, _ = conn.Exec(ctx, `DELETE FROM mailboxes WHERE id = ANY($1)`, []int64{mbID})
			_, _ = conn.Exec(ctx, `DELETE FROM users WHERE id = ANY($1)`, []int64{userID})
			_, _ = conn.Exec(ctx, `SET session_replication_role = 'origin'`)
			conn.Release()
		}
		pool.Close()
	})

	conn := newScriptConn("DONE\r\n")
	c := &connState{
		srv:    &Server{pool: pool, logger: slog.Default()},
		conn:   conn,
		reader: bufio.NewReader(conn),
		authed: true,
		userID: userID,
	}

	// Real SELECT resolves the handle exactly as a live session does.
	c.handleSelect(ctx, "S1", "SELECT", "Inbox")
	if got := conn.transcript(); !strings.Contains(got, "S1 OK") {
		t.Fatalf("SELECT Inbox replied %q, want S1 OK", got)
	}
	if c.mailboxID <= 0 || c.tagID <= 0 {
		t.Fatalf("SELECT did not resolve the handle: mailboxID=%d tagID=%d", c.mailboxID, c.tagID)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.handleIdle(ctx, "I3")
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("authenticated IDLE did not return after DONE")
	}
	got := conn.transcript()
	if strings.Contains(got, "I3 NO") || strings.Contains(got, "[AUTHENTICATIONREQUIRED]") {
		t.Fatalf("authenticated IDLE was rejected: %q", got)
	}
	if !strings.Contains(got, "+ idling") || !strings.Contains(got, "I3 OK IDLE completed") {
		t.Fatalf("authenticated IDLE after SELECT changed: %q, want + idling then I3 OK IDLE completed", got)
	}
}
