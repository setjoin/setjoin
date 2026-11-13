package imap

// IMAP login-path acceptance tests completing the auth matrix:
//   - LOGIN via app password (handleLogin's app-password arm, with and
//     without the conditional-access interceptor);
//   - AUTHENTICATE PLAIN via bcrypt and via app password (the SASL arm —
//     previously only LOGIN had coverage);
//   - the per-user connection-limit rejection on the wire;
//   - the command-loop dispatch of UID through a real handleConn session;
//   - IDLE routed to the notification-backed loop when a dispatcher and a
//     selected mailbox are present.
//
// Reuses the CA-gate harness (openCAGatePool/insertCAGateUser) and the
// isolation harness (setupIMAPIso/connFor). Skips without DB_DSN like the
// rest of the DB-backed imap suites.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/db"
	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/mailserver/internal/webhook"
)

// w5InsertAppPassword inserts an app-password row with a known token.
func w5InsertAppPassword(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID int64, token string) {
	t.Helper()
	sum := sha256.Sum256([]byte(token))
	if _, err := pool.Exec(ctx,
		`INSERT INTO app_passwords (user_id, name, token_hash) VALUES ($1, 'w5-test', $2)`,
		userID, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("insert app_passwords: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM app_passwords WHERE user_id=$1 AND name='w5-test'`, userID)
	})
}

// w5Plain builds the SASL PLAIN base64 payload.
func w5Plain(email, password string) string {
	return base64.StdEncoding.EncodeToString([]byte("\x00" + email + "\x00" + password))
}

func TestIMAPLogin_AppPassword(t *testing.T) {
	pool := openCAGatePool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	const (
		email = "cagate-appw@cagate.test"
		token = "w5-app-token-1234"
	)
	userID := insertCAGateUser(t, pool, "cagate-appw", email, "T3stP@ss-cagate")
	w5InsertAppPassword(t, ctx, pool, userID, token)

	srv := &Server{
		pool:              pool,
		logger:            discardLogger(),
		webhookDispatcher: webhook.NewDispatcher(pool, discardLogger()),
	}

	t.Run("LOGIN with app password succeeds", func(t *testing.T) {
		bc := &bufConn{}
		c := &connState{srv: srv, conn: bc, reader: bufio.NewReader(strings.NewReader(""))}
		c.handleLogin(ctx, "A1", fmt.Sprintf(`"%s" "%s"`, email, token))

		out := bc.String()
		if !c.authed || c.userID != userID {
			t.Errorf("app-password LOGIN must authenticate: authed=%v userID=%d\n%s", c.authed, c.userID, out)
		}
		if !strings.Contains(out, "OK [CAPABILITY") {
			t.Errorf("app-password LOGIN must complete with OK:\n%s", out)
		}
		if c.release != nil {
			c.release()
		}
	})

	t.Run("connection limit rejects with NO", func(t *testing.T) {
		srv.userTracker.SetMaxConns(1)
		release, err := srv.userTracker.TryAcquire(userID)
		if err != nil {
			t.Fatalf("pre-acquire: %v", err)
		}
		defer release()

		bc := &bufConn{}
		c := &connState{srv: srv, conn: bc, reader: bufio.NewReader(strings.NewReader(""))}
		c.handleLogin(ctx, "A2", fmt.Sprintf(`"%s" "%s"`, email, token))
		if out := bc.String(); !strings.Contains(out, "NO Too many connections from this account") {
			t.Errorf("exhausted per-user slot must reject the login:\n%s", out)
		}
		if c.authed || c.userID != 0 {
			t.Errorf("rejected login must not leave an authenticated state: authed=%v userID=%d", c.authed, c.userID)
		}
	})
}

// TestIMAPLogin_ImapDisabledPolicyDenies: a user_imap_settings row with
// imap_enabled=false denies LOGIN and AUTHENTICATE on both credential arms —
// the policy fires after credential verification and must close every path.
func TestIMAPLogin_ImapDisabledPolicyDenies(t *testing.T) {
	pool := openCAGatePool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	const (
		email    = "cagate-imapoff@cagate.test"
		password = "T3stP@ss-imapoff"
		appToken = "w5-imapoff-app-token"
	)
	userID := insertCAGateUser(t, pool, "cagate-imapoff", email, password)
	w5InsertAppPassword(t, ctx, pool, userID, appToken)
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_imap_settings (user_id, imap_enabled) VALUES ($1, FALSE)
		 ON CONFLICT (user_id) DO UPDATE SET imap_enabled = FALSE`, userID); err != nil {
		t.Fatalf("disable imap: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM user_imap_settings WHERE user_id=$1`, userID)
	})

	srv := &Server{
		pool:              pool,
		logger:            discardLogger(),
		webhookDispatcher: webhook.NewDispatcher(pool, discardLogger()),
	}

	t.Run("LOGIN app password denied", func(t *testing.T) {
		bc := &bufConn{}
		c := &connState{srv: srv, conn: bc, reader: bufio.NewReader(strings.NewReader(""))}
		c.handleLogin(ctx, "D1", fmt.Sprintf(`"%s" "%s"`, email, appToken))
		if out := bc.String(); !strings.Contains(out, "NO IMAP access disabled for this account by policy") {
			t.Errorf("imap-disabled LOGIN must be denied:\n%s", out)
		}
		if c.authed || c.userID != 0 {
			t.Errorf("denied login must reset the authenticated state: authed=%v userID=%d", c.authed, c.userID)
		}
	})

	t.Run("AUTHENTICATE app password denied", func(t *testing.T) {
		bc := &bufConn{}
		c := &connState{srv: srv, conn: bc, reader: bufio.NewReader(strings.NewReader(w5Plain(email, appToken) + "\r\n"))}
		c.handleAuthenticate(ctx, "D2", "PLAIN")
		if out := bc.String(); !strings.Contains(out, "NO IMAP access disabled for this account by policy") {
			t.Errorf("imap-disabled AUTHENTICATE must be denied:\n%s", out)
		}
	})

	t.Run("AUTHENTICATE bcrypt denied", func(t *testing.T) {
		bc := &bufConn{}
		c := &connState{srv: srv, conn: bc, reader: bufio.NewReader(strings.NewReader(w5Plain(email, password) + "\r\n"))}
		c.handleAuthenticate(ctx, "D3", "PLAIN")
		if out := bc.String(); !strings.Contains(out, "NO IMAP access disabled for this account by policy") {
			t.Errorf("imap-disabled AUTHENTICATE must be denied:\n%s", out)
		}
	})

	t.Run("LOGIN bcrypt denied", func(t *testing.T) {
		bc := &bufConn{}
		c := &connState{srv: srv, conn: bc, reader: bufio.NewReader(strings.NewReader(""))}
		c.handleLogin(ctx, "D4", fmt.Sprintf(`"%s" "%s"`, email, password))
		if out := bc.String(); !strings.Contains(out, "NO IMAP access disabled for this account by policy") {
			t.Errorf("imap-disabled LOGIN must be denied:\n%s", out)
		}
		if c.authed || c.userID != 0 {
			t.Errorf("denied login must reset the authenticated state: authed=%v userID=%d", c.authed, c.userID)
		}
	})
}

func TestIMAPAuthenticate_PLAIN(t *testing.T) {
	pool := openCAGatePool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	const (
		email    = "cagate-authplain@cagate.test"
		password = "T3stP@ss-authplain"
		appToken = "w5-authplain-app-token"
	)
	userID := insertCAGateUser(t, pool, "cagate-authplain", email, password)
	w5InsertAppPassword(t, ctx, pool, userID, appToken)

	srv := &Server{
		pool:              pool,
		logger:            discardLogger(),
		webhookDispatcher: webhook.NewDispatcher(pool, discardLogger()),
	}

	// drive runs one AUTHENTICATE PLAIN: the base64 credentials arrive on the
	// reader after the server's "+" continuation, per RFC 9051 §6.2.2.
	drive := func(tag, secret string) (*connState, string) {
		bc := &bufConn{}
		c := &connState{srv: srv, conn: bc, reader: bufio.NewReader(strings.NewReader(w5Plain(email, secret) + "\r\n"))}
		c.handleAuthenticate(ctx, tag, "PLAIN")
		return c, bc.String()
	}

	t.Run("bcrypt PLAIN authenticates", func(t *testing.T) {
		c, out := drive("B1", password)
		if !c.authed || c.userID != userID {
			t.Errorf("bcrypt AUTHENTICATE must authenticate: authed=%v userID=%d\n%s", c.authed, c.userID, out)
		}
		if !strings.Contains(out, "OK AUTHENTICATE completed") {
			t.Errorf("bcrypt AUTHENTICATE must complete:\n%s", out)
		}
		if c.release != nil {
			c.release()
		}
	})

	t.Run("app password PLAIN authenticates", func(t *testing.T) {
		c, out := drive("B2", appToken)
		if !c.authed || c.userID != userID {
			t.Errorf("app-password AUTHENTICATE must authenticate: authed=%v userID=%d\n%s", c.authed, c.userID, out)
		}
		if !strings.Contains(out, "OK AUTHENTICATE completed") {
			t.Errorf("app-password AUTHENTICATE must complete:\n%s", out)
		}
		if c.release != nil {
			c.release()
		}
	})

	t.Run("wrong bcrypt password rejected", func(t *testing.T) {
		c, out := drive("B3", "wrong-password")
		if c.authed || c.userID != 0 {
			t.Errorf("wrong password must not authenticate: authed=%v userID=%d", c.authed, c.userID)
		}
		if !strings.Contains(out, "NO Authentication failed") {
			t.Errorf("wrong password must yield NO:\n%s", out)
		}
	})

	t.Run("connection limit rejects AUTHENTICATE with NO", func(t *testing.T) {
		srv.userTracker.SetMaxConns(1)
		release, err := srv.userTracker.TryAcquire(userID)
		if err != nil {
			t.Fatalf("pre-acquire: %v", err)
		}
		defer release()

		c, out := drive("B4", password)
		if !strings.Contains(out, "NO Too many connections from this account") {
			t.Errorf("exhausted per-user slot must reject AUTHENTICATE:\n%s", out)
		}
		if c.authed || c.userID != 0 {
			t.Errorf("rejected AUTHENTICATE must not authenticate: authed=%v userID=%d", c.authed, c.userID)
		}
	})
}

// TestIMAPLogin_BcryptConnectionLimitRejects: the bcrypt LOGIN arm enforces
// the same per-user connection limit as the app-password arm.
func TestIMAPLogin_BcryptConnectionLimitRejects(t *testing.T) {
	pool := openCAGatePool(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	const (
		email    = "cagate-limit@cagate.test"
		password = "T3stP@ss-limit"
	)
	userID := insertCAGateUser(t, pool, "cagate-limit", email, password)

	srv := &Server{
		pool:              pool,
		logger:            discardLogger(),
		webhookDispatcher: webhook.NewDispatcher(pool, discardLogger()),
	}
	srv.userTracker.SetMaxConns(1)
	release, err := srv.userTracker.TryAcquire(userID)
	if err != nil {
		t.Fatalf("pre-acquire: %v", err)
	}
	defer release()

	bc := &bufConn{}
	c := &connState{srv: srv, conn: bc, reader: bufio.NewReader(strings.NewReader(""))}
	c.handleLogin(ctx, "L1", fmt.Sprintf(`"%s" "%s"`, email, password))
	if out := bc.String(); !strings.Contains(out, "NO Too many connections from this account") {
		t.Errorf("exhausted per-user slot must reject the bcrypt login:\n%s", out)
	}
	if c.authed || c.userID != 0 {
		t.Errorf("rejected login must not authenticate: authed=%v userID=%d", c.authed, c.userID)
	}
}

// w5ScriptConn is a net.Conn whose reads come from a scripted buffer and whose
// writes accumulate — the driven-socket counterpart of bufConn.
type w5ScriptConn struct {
	mu  sync.Mutex
	in  *strings.Reader
	out strings.Builder
}

func newW5ScriptConn(script string) *w5ScriptConn {
	return &w5ScriptConn{in: strings.NewReader(script)}
}

func (c *w5ScriptConn) Read(p []byte) (int, error) { return c.in.Read(p) }

func (c *w5ScriptConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(p)
}

func (c *w5ScriptConn) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.String()
}

func (c *w5ScriptConn) Close() error                     { return nil }
func (c *w5ScriptConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *w5ScriptConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *w5ScriptConn) SetDeadline(time.Time) error      { return nil }
func (c *w5ScriptConn) SetReadDeadline(time.Time) error  { return nil }
func (c *w5ScriptConn) SetWriteDeadline(time.Time) error { return nil }

// TestIMAPHandleConn_UIDDispatch drives the real command loop with a scripted
// session so the UID and APPEND dispatch arms execute end-to-end (LOGIN →
// SELECT → UID FETCH/SEARCH → APPEND with literal → LOGOUT).
func TestIMAPHandleConn_UIDDispatch(t *testing.T) {
	pool := openCAGatePool(t)
	t.Cleanup(func() { pool.Close() })

	const (
		email    = "cagate-loop@cagate.test"
		password = "T3stP@ss-loop"
	)
	insertCAGateUser(t, pool, "cagate-loop", email, password)

	const appendBody = "From: sender@ext.com\r\nSubject: w5 append\r\n\r\nbody\r\n"
	script := "a1 LOGIN \"" + email + "\" \"" + password + "\"\r\n" +
		"a2 SELECT Inbox\r\n" +
		"a3 UID FETCH 1 (FLAGS)\r\n" +
		"a4 UID SEARCH ALL\r\n" +
		"a5 APPEND Inbox {" + itoa(len(appendBody)) + "}\r\n" + appendBody + "\r\n" +
		"a6 LOGOUT\r\n"
	conn := newW5ScriptConn(script)
	srv := &Server{
		pool:              pool,
		logger:            discardLogger(),
		webhookDispatcher: webhook.NewDispatcher(pool, discardLogger()),
	}
	srv.handleConn(context.Background(), conn)

	out := conn.String()
	for _, want := range []string{
		"a1 OK [CAPABILITY",
		"a2 OK [READ-WRITE]",
		"a5 OK [APPENDUID",
		"a6 OK LOGOUT completed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("session output missing %q:\n%s", want, out)
		}
	}
}

// TestIMAPIdleWithNotifySelectedMailbox: an authenticated IDLE with a selected
// mailbox and a dispatcher routes to the notification-backed loop, which
// completes on DONE.
func TestIMAPIdleWithNotifySelectedMailbox(t *testing.T) {
	env := setupIMAPIso(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dsn := superDSN()
	listenConn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	t.Cleanup(func() { _ = listenConn.Close(context.Background()) })
	listener := db.NewListener(listenConn, discardLogger())
	runDone := make(chan struct{})
	go func() { listener.Run(ctx); close(runDone) }()
	t.Cleanup(func() {
		cancel()
		<-runDone
	})
	dispatcher := notify.NewDispatcher(listener, discardLogger())

	c, bc := env.connFor(env.mbA, env.tagA)
	c.srv.dispatcher = dispatcher
	c.srv.logger = discardLogger()
	c.reader = bufio.NewReader(strings.NewReader("DONE\r\n"))

	done := make(chan struct{})
	go func() {
		c.handleIdle(ctx, "I1")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("IDLE with notify did not complete on DONE")
	}
	if out := bc.String(); !strings.Contains(out, "OK IDLE completed") {
		t.Errorf("IDLE must complete on DONE:\n%s", out)
	}
}
