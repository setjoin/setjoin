package smtp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/textproto"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"setjoin.com/shared/toggle"
)

// emptyToggles returns flags with the network-touching features explicitly
// OFF (IsEnabled defaults unknown keys to true, which would trigger live
// MTA-STS / TLS-RPT DNS+DB calls during the test).
func emptyToggles() *toggle.FeatureFlags {
	return toggle.NewStatic(map[string]bool{
		"feature.mta_sts": false,
		"feature.tls_rpt": false,
		"feature.dnssec":  false,
		"feature.dane":    false,
	})
}

// ----------------------------------------------------------------------------
// (a) Unit tests for the refactored sendEnvelope / sendData against a net.Pipe
//     scripted SMTP server (pattern from inbound_tls_test.go). These validate
//     that (code, text) are captured from the reply, the err gate is unchanged
//     (250→nil, non-250→err), and a short/garbage reply yields code=0 without
//     panicking. No live MX involved.
// ----------------------------------------------------------------------------

// runScriptedServer drives the server side of a net.Pipe for the sendEnvelope/
// sendData unit tests. It pairs each scripted reply with the SMTP exchange:
// for a plain command, read the client line then send the reply; for DATA, send
// the 354 (or refusal), then — if 354 — drain the dot-terminated body before the
// NEXT reply (the post-body final reply follows immediately, with no intervening
// client command).
func runScriptedServer(t *testing.T, serverConn net.Conn, replies []string) {
	t.Helper()
	go func() {
		r := bufio.NewReader(serverConn)
		w := serverConn
		send := func(s string) bool { _, err := fmt.Fprintf(w, "%s\r\n", s); return err == nil }
		readLine := func() (string, bool) { l, err := r.ReadString('\n'); return l, err == nil }
		drainBody := func() bool {
			for {
				bl, ok := readLine()
				if !ok {
					return false
				}
				if strings.TrimRight(bl, "\r\n") == "." {
					return true
				}
			}
		}
		i := 0
		for i < len(replies) {
			line, ok := readLine()
			if !ok {
				return
			}
			reply := replies[i]
			i++
			if !send(reply) {
				return
			}
			// On a DATA 354, drain the body, then send the immediate post-body
			// reply (the next scripted reply) without reading another command.
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "DATA") && strings.HasPrefix(reply, "354") {
				if !drainBody() {
					return
				}
				if i < len(replies) {
					if !send(replies[i]) {
						return
					}
					i++
				}
			}
		}
	}()
}

func TestSendEnvelope_CapturesCodeAndText(t *testing.T) {
	tests := []struct {
		name       string
		mailReply  string
		rcptReply  string
		wantCode   int
		wantErr    bool
		wantInText string
	}{
		{"both accepted", "250 2.1.0 OK", "250 2.1.5 OK", 250, false, "250 2.1.5 OK"},
		{"rcpt rejected 5xx", "250 2.1.0 OK", "550 5.1.1 unknown user", 550, true, "550 5.1.1 unknown user"},
		{"rcpt deferred 4xx", "250 2.1.0 OK", "451 4.7.1 greylisted", 451, true, "451 4.7.1 greylisted"},
		{"mail from rejected", "553 5.7.1 bad sender", "250 ok", 553, true, "553 5.7.1 bad sender"},
		{"garbage rcpt reply", "250 ok", "xx", 0, true, "xx"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := &OutboundWorker{logger: slog.Default()}
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()
			runScriptedServer(t, serverConn, []string{tc.mailReply, tc.rcptReply})

			tp := textproto.NewConn(clientConn)
			code, text, err := w.sendEnvelope(tp, "from@a.test", "to@b.test")

			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if code != tc.wantCode {
				t.Errorf("code = %d, want %d", code, tc.wantCode)
			}
			if !strings.Contains(text, tc.wantInText) {
				t.Errorf("text = %q, want it to contain %q", text, tc.wantInText)
			}
		})
	}
}

func TestSendData_CapturesCodeAndText(t *testing.T) {
	tests := []struct {
		name        string
		dataReply   string // reply to DATA
		finalReply  string // reply after body (only sent if dataReply is 354)
		wantCode    int
		wantErr     bool
		wantInText  string
		expectFinal bool
	}{
		{"accepted", "354 go ahead", "250 2.0.0 queued as ABC", 250, false, "250 2.0.0 queued as ABC", true},
		{"data refused 5xx", "554 5.7.1 message refused", "", 554, true, "554 5.7.1 message refused", false},
		{"data deferred 4xx", "451 4.3.0 try later", "", 451, true, "451 4.3.0 try later", false},
		{"final rejected after 354", "354 go ahead", "550 5.7.1 spam", 550, true, "550 5.7.1 spam", true},
		{"short data reply yields code 0 defensively", "35", "", 0, true, "35", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := &OutboundWorker{logger: slog.Default()}
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			replies := []string{tc.dataReply}
			if tc.expectFinal {
				replies = append(replies, tc.finalReply)
			}
			runScriptedServer(t, serverConn, replies)

			tp := textproto.NewConn(clientConn)
			code, text, err := w.sendData(tp, "Subject: hi\r\n\r\nbody\r\n")

			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if code != tc.wantCode {
				t.Errorf("code = %d, want %d", code, tc.wantCode)
			}
			if !strings.Contains(text, tc.wantInText) {
				t.Errorf("text = %q, want it to contain %q", text, tc.wantInText)
			}
		})
	}
}

func TestParseSMTPCode_Defensive(t *testing.T) {
	cases := map[string]int{
		"250 OK":             250,
		"550 5.1.1 no user":  550,
		"":                   0,
		"x":                  0,
		"25":                 0,
		"2x0 weird":          0,
		"abc def":            0,
		"354":                354,
		"421 4.3.2 shutting": 421,
	}
	for line, want := range cases {
		if got := parseSMTPCode(line); got != want {
			t.Errorf("parseSMTPCode(%q) = %d, want %d", line, got, want)
		}
	}
}

func TestSendEnvelope_RejectsControlChars(t *testing.T) {
	cases := []struct{ name, from, rcpt string }{
		{"CR in from", "bad\rfrom@a.test", "to@b.test"},
		{"LF in from", "bad\nfrom@a.test", "to@b.test"},
		{"CRLF in from", "bad\r\nfrom@a.test", "to@b.test"},
		{"NUL in from", "bad\x00from@a.test", "to@b.test"},
		{"CRLF in rcpt", "from@a.test", "bad\r\nto@b.test"},
		{"DEL in rcpt", "from@a.test", "to\x7fb.test"},
		{"ctrl char in rcpt", "from@a.test", "to\x01b.test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &OutboundWorker{logger: slog.Default()}
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()
			tp := textproto.NewConn(clientConn)
			_, _, err := w.sendEnvelope(tp, tc.from, tc.rcpt)
			if err == nil {
				t.Fatalf("sendEnvelope(%q, %q): expected error for control char, got nil", tc.from, tc.rcpt)
			}
		})
	}
}

func TestOutcomeForCode(t *testing.T) {
	someErr := fmt.Errorf("boom")
	cases := []struct {
		code int
		err  error
		want string
	}{
		{250, nil, outcomeAccepted},
		{250, someErr, outcomeAccepted}, // err==nil short-circuits; here code 2xx
		{451, someErr, outcomeDeferred},
		{550, someErr, outcomeRejected},
		{0, someErr, outcomeError},   // connection/lookup failure, no code
		{0, nil, outcomeAccepted},    // success with unparsed code still accepted
		{600, someErr, outcomeError}, // out of band
	}
	for _, tc := range cases {
		if got := outcomeForCode(tc.code, tc.err); got != tc.want {
			t.Errorf("outcomeForCode(%d, %v) = %q, want %q", tc.code, tc.err, got, tc.want)
		}
	}
}

// ----------------------------------------------------------------------------
// (b) Multi-recipient regression (DB-backed): the per-recipient detail lives in
//     delivery_attempts (one row per recipient per attempt); message_trace stays
//     MESSAGE-level — exactly one 'delivered' row per delivered message (the OLD
//     invariant admin_reports.TotalSent/TotalBounced count directly over). These
//     tests inject scripted MX servers (lookupMXFn + dialMX) and assert that
//     cardinality, plus the per-recipient delivery_attempts columns.
//
//     RLS POSTURE: these DB tests run as the superuser configured in DB_DSN,
//     which BYPASSES FORCE'd RLS, so the worker INSERTs land without setting
//     app.current_mailbox_id. That is intentional for the test. In production the
//     outbound worker's write path (logDeliveryAttempt / message_trace) must move
//     to DB_WORKER_DSN (the setjoin_worker BYPASSRLS pool) BEFORE the native-RLS
//     W6 DB_DSN flip — otherwise a FORCE'd delivery_attempts with no GUC rejects
//     every insert (delivery stays safe; logging silently stops). Documented in
//     V017__delivery_attempts.sql §3 and 2026-06-18-native-rls-backstop.md. We do
//     not build role-based test infra here; superuser-bypass is sufficient.
// ----------------------------------------------------------------------------

func testDSN() string {
	if d := os.Getenv("DB_DSN"); d != "" {
		return d
	}
	return os.Getenv("TEST_DB_DSN")
}

// fullSMTPServer scripts a complete plaintext SMTP session for one delivery:
// greeting → EHLO/250 (no STARTTLS) → MAIL FROM/250 → RCPT TO/<rcptReply> →
// (if accepted) DATA/354 → body → <finalReply>. rcptReply decides the
// per-recipient outcome.
func fullSMTPServer(t *testing.T, serverConn net.Conn, rcptReply, finalReply string) {
	t.Helper()
	go func() {
		defer serverConn.Close()
		r := bufio.NewReader(serverConn)
		w := serverConn
		send := func(s string) bool {
			_, err := fmt.Fprintf(w, "%s\r\n", s)
			return err == nil
		}
		// Greeting (server speaks first).
		if !send("220 mx.test ESMTP ready") {
			return
		}
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				// Single-line 250 (no STARTTLS advertised → plaintext path).
				if !send("250 mx.test at your service") {
					return
				}
			case strings.HasPrefix(cmd, "MAIL FROM"):
				if !send("250 2.1.0 sender ok") {
					return
				}
			case strings.HasPrefix(cmd, "RCPT TO"):
				if !send(rcptReply) {
					return
				}
			case strings.HasPrefix(cmd, "DATA"):
				if !send("354 end with <CRLF>.<CRLF>") {
					return
				}
				for {
					bl, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimRight(bl, "\r\n") == "." {
						break
					}
				}
				if !send(finalReply) {
					return
				}
			case strings.HasPrefix(cmd, "QUIT"):
				send("221 bye")
				return
			case strings.HasPrefix(cmd, "RSET"):
				if !send("250 ok") {
					return
				}
			default:
				if !send("250 ok") {
					return
				}
			}
		}
	}()
}

func TestDeliverToMX_ReusesLiveSessionWithoutQUIT(t *testing.T) {
	w := &OutboundWorker{
		logger:         slog.Default(),
		toggles:        emptyToggles(),
		connPool:       &mxConnPool{conns: make(map[string][]*pooledConn), max: 5, idle: 60 * time.Second},
		commandTimeout: time.Second,
		dataTimeout:    time.Second,
	}
	var dials atomic.Int32
	w.dialMX = func(string) (net.Conn, error) {
		dials.Add(1)
		serverConn, clientConn := net.Pipe()
		fullSMTPServer(t, serverConn, "250 2.1.5 recipient ok", "250 2.0.0 queued")
		return clientConn, nil
	}

	for i := 0; i < 2; i++ {
		got := w.deliverToMX(context.Background(), "mx.example.test", "to@example.test", "from@example.test", cannedRaw, false, false)
		if got.err != nil {
			t.Fatalf("delivery %d failed: %v", i+1, got.err)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dial count = %d, want 1 live SMTP session reused", got)
	}
	if pc := w.connPool.get("mx.example.test"); pc != nil {
		pc.tp.Close()
		pc.conn.Close()
	}
}

func TestDeliverToMX_ContextCancellationUnblocksGreeting(t *testing.T) {
	w := &OutboundWorker{
		logger:         slog.Default(),
		toggles:        emptyToggles(),
		connPool:       &mxConnPool{conns: make(map[string][]*pooledConn), max: 5, idle: 60 * time.Second},
		commandTimeout: time.Minute,
		dataTimeout:    time.Minute,
	}
	w.dialMX = func(string) (net.Conn, error) {
		serverConn, clientConn := net.Pipe()
		t.Cleanup(func() { serverConn.Close() })
		return clientConn, nil // server deliberately never sends a greeting
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(25*time.Millisecond, cancel)
	start := time.Now()
	got := w.deliverToMX(ctx, "mx.example.test", "to@example.test", "from@example.test", cannedRaw, false, false)
	if got.err == nil {
		t.Fatal("expected cancellation to abort the blocked SMTP greeting")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancellation took %s, want <= 1s", elapsed)
	}
}

func TestDeliverToMXRejectsPlaintextWhenPolicyRequiresTLS(t *testing.T) {
	w := &OutboundWorker{
		logger: slog.Default(), toggles: emptyToggles(),
		connPool: &mxConnPool{conns: make(map[string][]*pooledConn), max: 5, idle: time.Minute},
	}
	w.dialMX = func(string) (net.Conn, error) {
		serverConn, clientConn := net.Pipe()
		fullSMTPServer(t, serverConn, "250 recipient ok", "250 queued")
		return clientConn, nil
	}
	got := w.deliverToMX(context.Background(), "mx.example.test", "to@example.test", "from@example.test", cannedRaw, true, false)
	if got.err == nil || !strings.Contains(got.err.Error(), "TLS required") {
		t.Fatalf("delivery error=%v, want fail-closed TLS policy", got.err)
	}
}

func TestDeliverToMXReportsRejectedSTARTTLSUpgrade(t *testing.T) {
	w := &OutboundWorker{
		logger: slog.Default(), toggles: emptyToggles(),
		connPool: &mxConnPool{conns: make(map[string][]*pooledConn), max: 5, idle: time.Minute},
	}
	w.dialMX = func(string) (net.Conn, error) {
		serverConn, clientConn := net.Pipe()
		var saw atomic.Bool
		startTLSAdvertisingServer(t, serverConn, "250 recipient ok", "250 queued", &saw)
		return clientConn, nil
	}
	got := w.deliverToMX(context.Background(), "mx.example.test", "to@example.test", "from@example.test", cannedRaw, false, false)
	if got.err == nil || !strings.Contains(got.err.Error(), "starttls rejected") {
		t.Fatalf("delivery error=%v, want STARTTLS refusal", got.err)
	}
}

type deadlineFailConn struct {
	net.Conn
	err error
}

func (c deadlineFailConn) SetDeadline(time.Time) error { return c.err }

type deadlineSequenceConn struct {
	net.Conn
	calls  atomic.Int32
	failAt int32
	err    error
}

type cancelOnReadConn struct {
	net.Conn
	match  string
	cancel context.CancelFunc
}

func (c *cancelOnReadConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if strings.Contains(string(p[:n]), c.match) {
		c.cancel()
	}
	return n, err
}

func (c *deadlineSequenceConn) SetDeadline(deadline time.Time) error {
	if c.calls.Add(1) == c.failAt {
		return c.err
	}
	return c.Conn.SetDeadline(deadline)
}

func TestSMTPConnectionDeadlineAndCancellationBoundaries(t *testing.T) {
	w := &OutboundWorker{commandTimeout: time.Second, dataTimeout: 2 * time.Second}
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(50*time.Millisecond))
	defer cancel()
	if err := w.setSMTPDeadline(ctx, clientConn, time.Minute); err != nil {
		t.Fatalf("setSMTPDeadline: %v", err)
	}
	release, err := w.armSMTPConnection(ctx, clientConn)
	if err != nil {
		t.Fatalf("armSMTPConnection: %v", err)
	}
	cancel()
	if release(true) {
		t.Fatal("canceled SMTP connection was returned as reusable")
	}

	injected := errors.New("deadline failed")
	if _, err := w.armSMTPConnection(context.Background(), deadlineFailConn{Conn: clientConn, err: injected}); !errors.Is(err, injected) {
		t.Fatalf("deadline error=%v, want injected failure", err)
	}
}

func TestSMTPConnectionReleaseRejectsDeadlineClearFailure(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	wrapped := &deadlineSequenceConn{Conn: clientConn, failAt: 2, err: errors.New("clear deadline failed")}
	w := &OutboundWorker{commandTimeout: time.Second}
	release, err := w.armSMTPConnection(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("armSMTPConnection: %v", err)
	}
	if release(true) {
		t.Fatal("connection with a failed deadline clear was returned as reusable")
	}
}

func TestCommandLinePropagatesWriteFailure(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	serverConn.Close()
	defer clientConn.Close()
	tp := textproto.NewConn(clientConn)
	if _, err := commandLine(tp, "NOOP"); err == nil {
		t.Fatal("commandLine swallowed a closed-connection write failure")
	}
}

func TestDeliverToMXFallsBackAfterPooledSessionFailure(t *testing.T) {
	tests := []struct {
		name       string
		responses  []string
		wantSecond string
	}{
		{"RSET rejected", []string{"550 reset rejected"}, "RSET"},
		{"envelope rejected", []string{"250 reset ok", "550 sender rejected"}, "MAIL FROM"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w := &OutboundWorker{
				logger: slog.Default(), toggles: emptyToggles(),
				connPool:       &mxConnPool{conns: make(map[string][]*pooledConn), max: 5, idle: time.Minute},
				commandTimeout: time.Second, dataTimeout: time.Second,
			}
			serverConn, clientConn := net.Pipe()
			go func() {
				defer serverConn.Close()
				r := bufio.NewReader(serverConn)
				for _, response := range test.responses {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if !strings.Contains(strings.ToUpper(line), test.wantSecond) && response == test.responses[len(test.responses)-1] {
						return
					}
					if _, err := fmt.Fprintf(serverConn, "%s\r\n", response); err != nil {
						return
					}
				}
			}()
			w.connPool.put(&pooledConn{
				tp: textproto.NewConn(clientConn), conn: clientConn, host: "mx.example.test",
			})
			w.dialMX = func(string) (net.Conn, error) {
				freshServer, freshClient := net.Pipe()
				fullSMTPServer(t, freshServer, "250 recipient ok", "250 queued")
				return freshClient, nil
			}
			got := w.deliverToMX(context.Background(), "mx.example.test", "to@example.test", "from@example.test", cannedRaw, false, false)
			if got.err != nil {
				t.Fatalf("fresh-session fallback failed: %v", got.err)
			}
			if pc := w.connPool.get("mx.example.test"); pc != nil {
				pc.tp.Close()
				pc.conn.Close()
			}
		})
	}
}

func TestDeliverToMXReportsFreshSessionDataFailure(t *testing.T) {
	w := &OutboundWorker{
		logger: slog.Default(), toggles: emptyToggles(),
		connPool:       &mxConnPool{conns: make(map[string][]*pooledConn), max: 5, idle: time.Minute},
		commandTimeout: time.Second, dataTimeout: time.Second,
	}
	w.dialMX = func(string) (net.Conn, error) {
		serverConn, clientConn := net.Pipe()
		fullSMTPServer(t, serverConn, "250 recipient ok", "550 body rejected")
		return clientConn, nil
	}
	got := w.deliverToMX(context.Background(), "mx.example.test", "to@example.test", "from@example.test", cannedRaw, false, false)
	if got.err == nil || got.code != 550 {
		t.Fatalf("delivery result = %+v, want DATA rejection", got)
	}
}

func TestDeliverToMXReportsFreshConnectionDeadlineFailure(t *testing.T) {
	w := &OutboundWorker{
		logger: slog.Default(), toggles: emptyToggles(),
		connPool: &mxConnPool{conns: make(map[string][]*pooledConn), max: 5, idle: time.Minute},
	}
	w.dialMX = func(string) (net.Conn, error) {
		serverConn, clientConn := net.Pipe()
		t.Cleanup(func() { serverConn.Close() })
		return deadlineFailConn{Conn: clientConn, err: errors.New("deadline failed")}, nil
	}
	got := w.deliverToMX(context.Background(), "mx.example.test", "to@example.test", "from@example.test", cannedRaw, false, false)
	if got.err == nil || !strings.Contains(got.err.Error(), "connection deadline") {
		t.Fatalf("delivery error = %v, want deadline failure", got.err)
	}
}

func TestDeliverToMXDoesNotPoolFreshConnectionAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	w := &OutboundWorker{
		logger: slog.Default(), toggles: emptyToggles(),
		connPool:       &mxConnPool{conns: make(map[string][]*pooledConn), max: 5, idle: time.Minute},
		commandTimeout: time.Second, dataTimeout: time.Second,
	}
	w.dialMX = func(string) (net.Conn, error) {
		serverConn, clientConn := net.Pipe()
		fullSMTPServer(t, serverConn, "250 recipient ok", "250 queued")
		return &cancelOnReadConn{Conn: clientConn, match: "250 queued", cancel: cancel}, nil
	}
	got := w.deliverToMX(ctx, "mx.example.test", "to@example.test", "from@example.test", cannedRaw, false, false)
	if !errors.Is(got.err, context.Canceled) || got.code != 250 {
		t.Fatalf("delivery result = %+v, want accepted reply fenced by cancellation", got)
	}
	if pc := w.connPool.get("mx.example.test"); pc != nil {
		t.Fatal("canceled fresh connection entered the pool")
	}
}

func TestDeliverToMXDoesNotRepoolReusedConnectionAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	w := &OutboundWorker{
		logger: slog.Default(), toggles: emptyToggles(),
		connPool:       &mxConnPool{conns: make(map[string][]*pooledConn), max: 5, idle: time.Minute},
		commandTimeout: time.Second, dataTimeout: time.Second,
	}
	serverConn, rawClient := net.Pipe()
	go func() {
		defer serverConn.Close()
		r := bufio.NewReader(serverConn)
		for _, response := range []string{"250 reset", "250 sender", "250 recipient", "354 continue"} {
			if _, err := r.ReadString('\n'); err != nil {
				return
			}
			if _, err := fmt.Fprintf(serverConn, "%s\r\n", response); err != nil {
				return
			}
		}
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if strings.TrimRight(line, "\r\n") == "." {
				break
			}
		}
		_, _ = fmt.Fprint(serverConn, "250 queued\r\n")
	}()
	clientConn := &cancelOnReadConn{Conn: rawClient, match: "250 queued", cancel: cancel}
	w.connPool.put(&pooledConn{
		tp: textproto.NewConn(clientConn), conn: clientConn, host: "mx.example.test",
	})
	w.dialMX = func(string) (net.Conn, error) {
		return nil, errors.New("fresh dial must not run after an accepted reused delivery")
	}
	got := w.deliverToMX(ctx, "mx.example.test", "to@example.test", "from@example.test", cannedRaw, false, false)
	if !errors.Is(got.err, context.Canceled) || got.code != 250 {
		t.Fatalf("delivery result = %+v, want reused reply fenced by cancellation", got)
	}
	if pc := w.connPool.get("mx.example.test"); pc != nil {
		t.Fatal("canceled reused connection re-entered the pool")
	}
}

func TestSendDataPropagatesBodyWriteAndFlushFailures(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"flush", "short body"},
		{"write", strings.Repeat("x", 8192)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			go func() {
				r := bufio.NewReader(serverConn)
				_, _ = r.ReadString('\n')
				_, _ = fmt.Fprint(serverConn, "354 continue\r\n")
				_ = serverConn.Close()
			}()
			defer clientConn.Close()
			_, _, err := (&OutboundWorker{}).sendData(textproto.NewConn(clientConn), test.raw)
			if err == nil || (!strings.Contains(err.Error(), "write message body") &&
				!strings.Contains(err.Error(), "flush message body")) {
				t.Fatalf("sendData error = %v, want body write/flush failure", err)
			}
		})
	}
}

func TestUpgradeToTLSPropagatesMissingServerResponse(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	go func() {
		r := bufio.NewReader(serverConn)
		_, _ = r.ReadString('\n')
		_ = serverConn.Close()
	}()
	defer clientConn.Close()
	_, err := (&OutboundWorker{}).upgradeToTLS(
		textproto.NewConn(clientConn), clientConn, "mx.example.test",
	)
	if err == nil || !strings.Contains(err.Error(), "starttls response") {
		t.Fatalf("upgrade error = %v, want missing STARTTLS response", err)
	}
}

func TestEHLOAfterTLSCompletesMultilineHandshakeAndPropagatesDisconnect(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		go func() {
			defer serverConn.Close()
			r := bufio.NewReader(serverConn)
			line, err := r.ReadString('\n')
			if err != nil || !strings.HasPrefix(line, "EHLO ") {
				return
			}
			_, _ = fmt.Fprint(serverConn, "250-mx.example.test\r\n250 PIPELINING\r\n")
		}()
		defer clientConn.Close()
		if err := (&OutboundWorker{}).ehloAfterTLS(textproto.NewConn(clientConn)); err != nil {
			t.Fatalf("EHLO after TLS: %v", err)
		}
	})

	t.Run("disconnect", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		serverConn.Close()
		defer clientConn.Close()
		if err := (&OutboundWorker{}).ehloAfterTLS(textproto.NewConn(clientConn)); err == nil ||
			!strings.Contains(err.Error(), "ehlo after tls") {
			t.Fatalf("EHLO disconnect error = %v", err)
		}
	})

	t.Run("disconnect after command", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		go func() {
			r := bufio.NewReader(serverConn)
			_, _ = r.ReadString('\n')
			_ = serverConn.Close()
		}()
		defer clientConn.Close()
		if err := (&OutboundWorker{}).ehloAfterTLS(textproto.NewConn(clientConn)); err == nil ||
			!strings.Contains(err.Error(), "ehlo after tls") {
			t.Fatalf("EHLO read error = %v", err)
		}
	})
}

// startTLSAdvertisingServer scripts a plaintext SMTP session that ADVERTISES
// 250-STARTTLS in its EHLO reply but treats an actual STARTTLS command as fatal:
// it flips *sawStartTLS and replies 502, proving the client must never issue it.
// A skip-listed domain must deliver over plaintext despite the advertisement.
func startTLSAdvertisingServer(t *testing.T, serverConn net.Conn, rcptReply, finalReply string, sawStartTLS *atomic.Bool) {
	t.Helper()
	go func() {
		defer serverConn.Close()
		r := bufio.NewReader(serverConn)
		w := serverConn
		send := func(s string) bool {
			_, err := fmt.Fprintf(w, "%s\r\n", s)
			return err == nil
		}
		if !send("220 mx.test ESMTP ready") {
			return
		}
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				// Multiline 250 advertising STARTTLS as an available capability.
				if !send("250-mx.test at your service") || !send("250-STARTTLS") || !send("250 HELP") {
					return
				}
			case strings.HasPrefix(cmd, "STARTTLS"):
				// The client must never reach here for a skip-listed domain.
				sawStartTLS.Store(true)
				send("502 5.5.1 STARTTLS not welcome here")
				return
			case strings.HasPrefix(cmd, "MAIL FROM"):
				if !send("250 2.1.0 sender ok") {
					return
				}
			case strings.HasPrefix(cmd, "RCPT TO"):
				if !send(rcptReply) {
					return
				}
			case strings.HasPrefix(cmd, "DATA"):
				if !send("354 end with <CRLF>.<CRLF>") {
					return
				}
				for {
					bl, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimRight(bl, "\r\n") == "." {
						break
					}
				}
				if !send(finalReply) {
					return
				}
			case strings.HasPrefix(cmd, "QUIT"):
				send("221 bye")
				return
			case strings.HasPrefix(cmd, "RSET"):
				if !send("250 ok") {
					return
				}
			default:
				if !send("250 ok") {
					return
				}
			}
		}
	}()
}

// daRow is one scanned delivery_attempts row (the columns the regression checks).
type daRow struct {
	rcpt    string
	outcome string
	code    *int
	text    *string
	mxHost  *string
	tls     bool
	attempt int
}

// traceRow is one scanned message_trace row.
type traceRow struct {
	event   string
	rcpt    string
	details string
}

// detailInts parses a message_trace details JSON (jsonb re-serializes with spaces
// and reorders keys, so assert on parsed numbers, not substrings) and returns the
// int value at key (0 if absent/non-numeric).
func detailInts(t *testing.T, details, key string) int {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(details), &m); err != nil {
		t.Fatalf("details %q not valid JSON: %v", details, err)
	}
	f, _ := m[key].(float64) // JSON numbers decode to float64
	return int(f)
}

// newTestWorker builds an OutboundWorker wired to pool with the MX seam injected.
// rcptReplyFor maps a dial addr → the RCPT reply and final-DATA reply that the
// scripted server should send (final ignored for a 5xx RCPT). This lets each test
// script per-recipient accept/reject/defer by recipient domain.
func newTestWorker(t *testing.T, pool *pgxpool.Pool, script func(addr string) (rcptReply, finalReply string)) *OutboundWorker {
	t.Helper()
	w := &OutboundWorker{
		pool:      pool,
		logger:    slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		toggles:   emptyToggles(),
		connPool:  &mxConnPool{conns: make(map[string][]*pooledConn), max: 5, idle: 60 * time.Second},
		tlsPolicy: &tlsPolicyState{},
	}
	w.lookupMXFn = func(domain string) ([]*net.MX, error) {
		return []*net.MX{{Host: "mx." + domain, Pref: 10}}, nil
	}
	w.dialMX = func(addr string) (net.Conn, error) {
		serverConn, clientConn := net.Pipe()
		rcptReply, finalReply := script(addr)
		fullSMTPServer(t, serverConn, rcptReply, finalReply)
		return clientConn, nil
	}
	return w
}

// cannedRaw is the stub raw message the loadRawFn seam returns in DB tests, so
// deliverOne runs end-to-end without a live MinIO.
const cannedRaw = "Subject: t\r\n\r\nbody\r\n"

// withCannedRaw injects the blob-load seam on w so a deliverOne call skips the
// MinIO fetch and proceeds with the canned raw message (the real per-recipient
// loop, trace, and markFailed logic all run unchanged).
func withCannedRaw(w *OutboundWorker) {
	w.loadRawFn = func(context.Context, queueItem) (string, bool) { return cannedRaw, true }
}

func queryDeliveryAttempts(ctx context.Context, t *testing.T, pool *pgxpool.Pool, messagePK int64) []daRow {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT recipient_email, outcome, smtp_code, smtp_text, mx_host, tls, attempt_number
		 FROM delivery_attempts WHERE message_pk = $1 ORDER BY recipient_email`, messagePK)
	if err != nil {
		t.Fatalf("query delivery_attempts: %v", err)
	}
	defer rows.Close()
	var got []daRow
	for rows.Next() {
		var d daRow
		if err := rows.Scan(&d.rcpt, &d.outcome, &d.code, &d.text, &d.mxHost, &d.tls, &d.attempt); err != nil {
			t.Fatalf("scan delivery_attempts: %v", err)
		}
		got = append(got, d)
	}
	return got
}

func queryTraces(ctx context.Context, t *testing.T, pool *pgxpool.Pool, msgID string) []traceRow {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT event, rcpt_addr, COALESCE(details::text, '') FROM message_trace
		 WHERE message_id = $1 ORDER BY event, rcpt_addr`, msgID)
	if err != nil {
		t.Fatalf("query message_trace: %v", err)
	}
	defer rows.Close()
	var got []traceRow
	for rows.Next() {
		var r traceRow
		if err := rows.Scan(&r.event, &r.rcpt, &r.details); err != nil {
			t.Fatalf("scan message_trace: %v", err)
		}
		got = append(got, r)
	}
	return got
}

// dbFixture sets up a clean pool + unique surrogate identity for one DB test and
// registers cleanup. recipients populates the queue row + item.
func dbFixture(t *testing.T, recipients []string, attemptCount int) (context.Context, *pgxpool.Pool, queueItem, int64, string) {
	t.Helper()
	dsn := testDSN()
	if dsn == "" {
		t.Skip("DB_DSN/TEST_DB_DSN not set; skipping DB-backed test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	messagePK := int64(time.Now().UnixNano())
	var mailboxID int64 = 4242
	receivedAt := time.Now().UTC()
	msgID := fmt.Sprintf("<msg-%d@test>", messagePK)

	_, _ = pool.Exec(ctx, `DELETE FROM message_trace WHERE message_id = $1`, msgID)
	_, _ = pool.Exec(ctx, `DELETE FROM delivery_attempts WHERE message_pk = $1`, messagePK)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM message_trace WHERE message_id = $1`, msgID)
		_, _ = pool.Exec(ctx, `DELETE FROM delivery_attempts WHERE message_pk = $1`, messagePK)
		_, _ = pool.Exec(ctx, `DELETE FROM outbound_queue WHERE id = $1`, messagePK)
	})

	_, err = pool.Exec(ctx,
		`INSERT INTO outbound_queue (id, message_id, from_addr, rcpt_addrs, raw_ref, status, attempt_count, mailbox_id, message_pk)
		 VALUES ($1, $2, $3, $4, $5, 'sending', $6, $7, $1)
		 ON CONFLICT (id) DO NOTHING`,
		messagePK, msgID, "sender@from.test", recipients, "raw/ref", attemptCount, mailboxID,
	)
	if err != nil {
		t.Logf("outbound_queue insert skipped (%v); UPDATE will be a harmless no-op", err)
	}

	item := queueItem{
		id:           int(messagePK),
		messageID:    msgID,
		fromAddr:     "sender@from.test",
		recipients:   recipients,
		rawRef:       "raw/ref",
		attemptCount: attemptCount,
		mailboxID:    &mailboxID,
		messagePK:    &messagePK,
		receivedAt:   &receivedAt,
	}
	return ctx, pool, item, messagePK, msgID
}

// TestDeliverOne_AllDelivered_MessageLevelTrace: a 3-recipient ALL-delivered send
// writes EXACTLY ONE 'delivered' message_trace row (delivered:3,total:3, naming a
// delivered recipient) + THREE delivery_attempts rows (correct per-recipient
// columns). This is the message-level cardinality the OLD invariant + admin_reports
// require.
func TestDeliverOne_AllDelivered_MessageLevelTrace(t *testing.T) {
	recipients := []string{"a@accept.test", "b@accept.test", "c@accept.test"}
	ctx, pool, item, messagePK, msgID := dbFixture(t, recipients, 0)

	w := newTestWorker(t, pool, func(addr string) (string, string) {
		return "250 2.1.5 recipient ok", "250 2.0.0 queued as XYZ"
	})
	withCannedRaw(w)
	w.deliverOne(ctx, item)

	// --- message_trace: EXACTLY ONE 'delivered' row, message-level ---
	traces := queryTraces(ctx, t, pool, msgID)
	if len(traces) != 1 {
		t.Fatalf("expected exactly 1 message_trace row (message-level), got %d: %+v", len(traces), traces)
	}
	if traces[0].event != "delivered" {
		t.Errorf("event = %q, want delivered", traces[0].event)
	}
	deliveredSet := map[string]bool{"a@accept.test": true, "b@accept.test": true, "c@accept.test": true}
	if !deliveredSet[traces[0].rcpt] {
		t.Errorf("rcpt_addr = %q, want one of the delivered recipients", traces[0].rcpt)
	}
	if d, tot := detailInts(t, traces[0].details, "delivered"), detailInts(t, traces[0].details, "total"); d != 3 || tot != 3 {
		t.Errorf("details = %q, want delivered:3,total:3 (parsed delivered=%d total=%d)", traces[0].details, d, tot)
	}

	// --- delivery_attempts: THREE rows, correct per-recipient columns ---
	da := queryDeliveryAttempts(ctx, t, pool, messagePK)
	if len(da) != 3 {
		t.Fatalf("expected 3 delivery_attempts rows, got %d: %+v", len(da), da)
	}
	for i, d := range da {
		if d.outcome != outcomeAccepted {
			t.Errorf("row[%d] outcome = %q, want accepted", i, d.outcome)
		}
		if d.code == nil || *d.code != 250 {
			t.Errorf("row[%d] smtp_code = %v, want 250", i, d.code)
		}
		// smtp_text captured from the final 250.
		if d.text == nil || !strings.Contains(*d.text, "queued as XYZ") {
			t.Errorf("row[%d] smtp_text = %v, want it to contain the 250 text", i, d.text)
		}
		// mx_host populated (mx.<domain>).
		if d.mxHost == nil || !strings.HasPrefix(*d.mxHost, "mx.") {
			t.Errorf("row[%d] mx_host = %v, want mx.<domain>", i, d.mxHost)
		}
		// plaintext stub never does STARTTLS → tls=false.
		if d.tls {
			t.Errorf("row[%d] tls = true, want false (plaintext stub)", i)
		}
		// attempt_number == attemptCount(0) + 1.
		if d.attempt != 1 {
			t.Errorf("row[%d] attempt_number = %d, want 1", i, d.attempt)
		}
	}
}

// TestDeliverOne_PartialDelivery_OneDeliveredTrace: a 2-recipient send (1 accepted,
// 1 5xx-rejected) marks the message DELIVERED — exactly ONE 'delivered' message_trace
// row (NOT a 'bounced' one) + TWO delivery_attempts rows with the right per-recipient
// outcome.
func TestDeliverOne_PartialDelivery_OneDeliveredTrace(t *testing.T) {
	const okRcpt = "good@accept.test"
	const badRcpt = "bad@reject.test"
	ctx, pool, item, messagePK, msgID := dbFixture(t, []string{okRcpt, badRcpt}, 0)

	w := newTestWorker(t, pool, func(addr string) (string, string) {
		if strings.Contains(addr, "reject.test") {
			return "550 5.1.1 user unknown", ""
		}
		return "250 2.1.5 recipient ok", "250 2.0.0 queued as XYZ"
	})
	withCannedRaw(w)
	w.deliverOne(ctx, item)

	// --- message_trace: exactly ONE 'delivered' (partial delivery → delivered) ---
	traces := queryTraces(ctx, t, pool, msgID)
	if len(traces) != 1 {
		t.Fatalf("expected exactly 1 message_trace row, got %d: %+v", len(traces), traces)
	}
	if traces[0].event != "delivered" {
		t.Errorf("event = %q, want delivered (partial delivery is NOT a bounce)", traces[0].event)
	}
	if traces[0].rcpt != okRcpt {
		t.Errorf("rcpt_addr = %q, want the delivered recipient %q (never the failed one)", traces[0].rcpt, okRcpt)
	}
	if d, tot := detailInts(t, traces[0].details, "delivered"), detailInts(t, traces[0].details, "total"); d != 1 || tot != 2 {
		t.Errorf("details = %q, want delivered:1,total:2 (parsed delivered=%d total=%d)", traces[0].details, d, tot)
	}

	// --- delivery_attempts: TWO rows, per-recipient outcome ---
	da := queryDeliveryAttempts(ctx, t, pool, messagePK)
	if len(da) != 2 {
		t.Fatalf("expected 2 delivery_attempts rows, got %d: %+v", len(da), da)
	}
	// ordered by recipient_email: bad@reject.test, good@accept.test
	if da[0].rcpt != badRcpt || da[0].outcome != outcomeRejected {
		t.Errorf("row[0] = %+v, want %s/rejected", da[0], badRcpt)
	}
	if da[0].code == nil || *da[0].code != 550 {
		t.Errorf("row[0] smtp_code = %v, want 550", da[0].code)
	}
	if da[1].rcpt != okRcpt || da[1].outcome != outcomeAccepted {
		t.Errorf("row[1] = %+v, want %s/accepted", da[1], okRcpt)
	}
	if da[1].code == nil || *da[1].code != 250 {
		t.Errorf("row[1] smtp_code = %v, want 250", da[1].code)
	}
}

// TestDeliverOne_NonzeroAttemptCount_AttemptNumber: with a NONZERO attemptCount,
// the logged attempt_number is attemptCount + 1 (the per-pass number from the value
// in hand, no MAX()+1 subselect).
func TestDeliverOne_NonzeroAttemptCount_AttemptNumber(t *testing.T) {
	const rcpt = "a@accept.test"
	ctx, pool, item, messagePK, _ := dbFixture(t, []string{rcpt}, 7) // attemptCount = 7

	w := newTestWorker(t, pool, func(addr string) (string, string) {
		return "250 2.1.5 recipient ok", "250 2.0.0 queued"
	})
	withCannedRaw(w)
	w.deliverOne(ctx, item)

	da := queryDeliveryAttempts(ctx, t, pool, messagePK)
	if len(da) != 1 {
		t.Fatalf("expected 1 delivery_attempts row, got %d", len(da))
	}
	if da[0].attempt != 8 { // attemptCount(7) + 1
		t.Errorf("attempt_number = %d, want 8 (attemptCount 7 + 1)", da[0].attempt)
	}
}

// TestDeliverOne_Deferred4xx_NoTrace: a recipient that gets 450 (transient) logs a
// delivery_attempts row with outcome='deferred' AND writes ZERO message_trace rows
// (a deferred all-fail under the bounce threshold writes neither delivered nor
// bounced).
func TestDeliverOne_Deferred4xx_NoTrace(t *testing.T) {
	const rcpt = "a@defer.test"
	ctx, pool, item, messagePK, msgID := dbFixture(t, []string{rcpt}, 0)

	w := newTestWorker(t, pool, func(addr string) (string, string) {
		return "450 4.2.1 mailbox busy, try later", ""
	})
	withCannedRaw(w)
	w.deliverOne(ctx, item)

	da := queryDeliveryAttempts(ctx, t, pool, messagePK)
	if len(da) != 1 {
		t.Fatalf("expected 1 delivery_attempts row, got %d", len(da))
	}
	if da[0].outcome != outcomeDeferred {
		t.Errorf("outcome = %q, want deferred", da[0].outcome)
	}
	if da[0].code == nil || *da[0].code != 450 {
		t.Errorf("smtp_code = %v, want 450", da[0].code)
	}

	traces := queryTraces(ctx, t, pool, msgID)
	if len(traces) != 0 {
		t.Errorf("expected 0 message_trace rows for a deferred send, got %d: %+v", len(traces), traces)
	}
}

// TestDeliverOne_SkipTLS: a domain on the admin skip list delivers over PLAINTEXT
// even when the remote MX advertises STARTTLS. Asserts (a) delivery succeeds, (b)
// the delivery_attempts.tls column is false, (c) the scripted server never saw a
// STARTTLS command. Fails if the adminSkip value is silently dropped again (the
// pre-fix `_ = adminSkip` regression).
func TestDeliverOne_SkipTLS(t *testing.T) {
	const rcpt = "a@skip.test"
	ctx, pool, item, messagePK, _ := dbFixture(t, []string{rcpt}, 0)

	var sawStartTLS atomic.Bool
	w := newTestWorker(t, pool, func(string) (string, string) {
		return "250 2.1.5 recipient ok", "250 2.0.0 queued"
	})
	// Override the MX seam with a server that advertises STARTTLS and treats an
	// actual STARTTLS command as fatal.
	w.dialMX = func(addr string) (net.Conn, error) {
		serverConn, clientConn := net.Pipe()
		startTLSAdvertisingServer(t, serverConn, "250 2.1.5 recipient ok", "250 2.0.0 queued", &sawStartTLS)
		return clientConn, nil
	}
	// Admin skip-lists this domain: force plaintext despite the STARTTLS advert.
	w.tlsPolicy.skipDomains = []string{"skip.test"}
	withCannedRaw(w)
	w.deliverOne(ctx, item)

	if sawStartTLS.Load() {
		t.Fatalf("client issued STARTTLS to a skip-listed domain; adminSkip wiring regressed")
	}
	da := queryDeliveryAttempts(ctx, t, pool, messagePK)
	if len(da) != 1 {
		t.Fatalf("expected 1 delivery_attempts row, got %d: %+v", len(da), da)
	}
	if da[0].outcome != outcomeAccepted {
		t.Errorf("outcome = %q, want accepted (plaintext delivery to skip-listed domain)", da[0].outcome)
	}
	if da[0].tls {
		t.Errorf("tls = true, want false (STARTTLS skipped for this domain)")
	}
}

// TestLogDeliveryAttempt_SkipsUnlinkedRows verifies the NULL-link guard: a row
// with no message_pk / mailbox_id / received_at — OR a non-nil messagePK pointing
// to 0 — writes nothing (legacy/DMARC/system rows).
func TestLogDeliveryAttempt_SkipsUnlinkedRows(t *testing.T) {
	dsn := testDSN()
	if dsn == "" {
		t.Skip("DB_DSN/TEST_DB_DSN not set; skipping DB-backed test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	w := &OutboundWorker{pool: pool, logger: slog.Default()}

	rr := recipientResult{rcpt: "x@y.test", outcome: outcomeAccepted, smtpCode: 250}

	var mb int64 = 1
	ra := time.Now()
	// No message_pk → skipped.
	w.logDeliveryAttempt(ctx, queueItem{mailboxID: &mb, receivedAt: &ra}, rr)
	// nil mailbox → skipped.
	pk := int64(1)
	w.logDeliveryAttempt(ctx, queueItem{messagePK: &pk, receivedAt: &ra}, rr)
	// nil received_at → skipped.
	w.logDeliveryAttempt(ctx, queueItem{messagePK: &pk, mailboxID: &mb}, rr)
	// non-nil messagePK pointing to ZERO (valid mailbox/received_at) → skipped.
	zero := int64(0)
	w.logDeliveryAttempt(ctx, queueItem{messagePK: &zero, mailboxID: &mb, receivedAt: &ra}, rr)

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM delivery_attempts WHERE recipient_email = 'x@y.test'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 rows for unlinked items, got %d", n)
		_, _ = pool.Exec(ctx, `DELETE FROM delivery_attempts WHERE recipient_email = 'x@y.test'`)
	}
}

// TestMarkFailed_TraceCardinality: markFailed writes the single message-level
// 'bounced' message_trace row ONLY at the bounce threshold (newAttempts>=20), with
// rcpt_addr=recipients[0] and json-marshalled details (no fmt.Sprintf artifact). A
// deferred all-fail (newAttempts<20) writes NO message_trace row.
func TestMarkFailed_TraceCardinality(t *testing.T) {
	dsn := testDSN()
	if dsn == "" {
		t.Skip("DB_DSN/TEST_DB_DSN not set; skipping DB-backed test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	w := &OutboundWorker{
		pool:   pool,
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}

	recipients := []string{"first@x.test", "second@x.test"}

	// --- DEFERRED case: attemptCount 5 → newAttempts 6 (<20) → NO trace row. ---
	deferredMsgID := fmt.Sprintf("<defer-%d@test>", time.Now().UnixNano())
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM message_trace WHERE message_id = $1`, deferredMsgID) })
	w.markFailed(ctx, queueItem{messageID: deferredMsgID, fromAddr: "s@from.test", recipients: recipients, attemptCount: 5}, "transient: greylisted")
	var deferredCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM message_trace WHERE message_id = $1`, deferredMsgID).Scan(&deferredCount); err != nil {
		t.Fatalf("count deferred traces: %v", err)
	}
	if deferredCount != 0 {
		t.Errorf("deferred all-fail wrote %d message_trace rows, want 0", deferredCount)
	}

	// --- BOUNCE case: attemptCount 19 → newAttempts 20 (>=20) → exactly ONE
	//     'bounced' row, rcpt_addr=recipients[0], json details. ---
	bounceMsgID := fmt.Sprintf("<bounce-%d@test>", time.Now().UnixNano())
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM message_trace WHERE message_id = $1`, bounceMsgID) })
	const bounceErr = `permanent: 550 5.1.1 "no such user"` // embeds a quote to prove json-escaping (no fmt.Sprintf artifact)
	w.markFailed(ctx, queueItem{messageID: bounceMsgID, fromAddr: "s@from.test", recipients: recipients, attemptCount: 19}, bounceErr)

	rows := queryTraces(ctx, t, pool, bounceMsgID)
	if len(rows) != 1 {
		t.Fatalf("bounce wrote %d message_trace rows, want exactly 1: %+v", len(rows), rows)
	}
	if rows[0].event != "bounced" {
		t.Errorf("event = %q, want bounced", rows[0].event)
	}
	if rows[0].rcpt != recipients[0] {
		t.Errorf("rcpt_addr = %q, want recipients[0] = %q", rows[0].rcpt, recipients[0])
	}
	// details must be valid JSON carrying the error, with the quote escaped (proves
	// json.Marshal, not fmt.Sprintf). Parse it back.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(rows[0].details), &parsed); err != nil {
		t.Fatalf("details %q is not valid JSON (fmt.Sprintf artifact?): %v", rows[0].details, err)
	}
	if got, _ := parsed["error"].(string); got != bounceErr {
		t.Errorf("details.error = %q, want %q", got, bounceErr)
	}
}

// ----------------------------------------------------------------------------
// (e) loadRawForDelivery raw_ref convention (W5): outbound_queue.raw_ref is
//     EITHER a MinIO object key (Go-side producers store the blob first) OR the
//     inline RFC 5322 message text itself (reducer-built drafts: jmap_email.sql
//     create → send.sql enqueues it verbatim). The load head must discriminate;
//     pre-fix it GetObject'ed everything, so every inline-draft external send
//     deferred until it bounced. These tests use a minio client pointed at a
//     dead endpoint: any fetch attempt fails loudly.
// ----------------------------------------------------------------------------

// deadMinio returns a real *minio.Client aimed at an unroutable endpoint —
// constructing the client performs no I/O, so any test that never touches MinIO
// stays fast; any code path that DOES fetch fails with a connection error.
func deadMinio(t *testing.T) *minio.Client {
	t.Helper()
	mc, err := minio.New("127.0.0.1:1", &minio.Options{
		Creds: credentials.NewStaticV4("test", "test", ""),
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	return mc
}

// rawFixture inserts one outbound_queue row with the given raw_ref and returns
// the matching queueItem. Mirrors dbFixture but parameterizes raw_ref/status
// (dbFixture hardcodes both for the deliverOne trace tests).
func rawFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, rawRef string) queueItem {
	t.Helper()
	id := time.Now().UnixNano()
	msgID := fmt.Sprintf("<raw-%d@test>", id)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM outbound_queue WHERE id = $1`, id)
	})
	_, err := pool.Exec(ctx,
		`INSERT INTO outbound_queue (id, message_id, from_addr, rcpt_addrs, raw_ref, status)
		 VALUES ($1, $2, 'sender@from.test', '{rcpt@ext.test}', $3, 'pending')`,
		id, msgID, rawRef)
	if err != nil {
		t.Fatalf("outbound_queue insert: %v", err)
	}
	return queueItem{id: int(id), messageID: msgID, fromAddr: "sender@from.test",
		recipients: []string{"rcpt@ext.test"}, rawRef: rawRef}
}

func queueState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id int) (status, lastError string) {
	t.Helper()
	var le *string
	if err := pool.QueryRow(ctx,
		`SELECT status, last_error FROM outbound_queue WHERE id = $1`, id,
	).Scan(&status, &le); err != nil {
		t.Fatalf("queue state: %v", err)
	}
	if le != nil {
		lastError = *le
	}
	return status, lastError
}

// TestLoadRawForDelivery_InlineRawRef (red-first): a queue row whose raw_ref IS
// the inline RFC 5322 text must be returned verbatim for delivery — never
// treated as a MinIO key. Pre-fix this deferred the send with "failed to fetch
// blob from MinIO".
func TestLoadRawForDelivery_InlineRawRef(t *testing.T) {
	dsn := testDSN()
	if dsn == "" {
		t.Skip("DB_DSN/TEST_DB_DSN not set; skipping DB-backed test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	inline := "Message-ID: <inline-1@test>\r\nFrom: sender@from.test\r\nTo: rcpt@ext.test\r\nSubject: inline draft\r\n\r\nhello over the wire\r\n"
	item := rawFixture(t, ctx, pool, inline)

	w := newTestWorker(t, pool, func(string) (string, string) { return "250 ok", "250 ok" })
	w.minio = deadMinio(t)
	w.bucket = "test-bucket"

	got, ok := w.loadRawForDelivery(ctx, item)
	if !ok {
		_, lastErr := queueState(t, ctx, pool, item.id)
		t.Fatalf("loadRawForDelivery(inline raw_ref) failed (last_error=%q) — inline RFC 5322 text was treated as a MinIO key", lastErr)
	}
	if got != inline {
		t.Fatalf("raw message mutated:\ngot:  %q\nwant: %q", got, inline)
	}
	if status, lastErr := queueState(t, ctx, pool, item.id); status != "sending" || lastErr != "" {
		t.Errorf("queue row after load: status=%q last_error=%q, want sending/empty", status, lastErr)
	}
}

// TestLoadRawForDelivery_KeyRefStillFetches pins the other side of the
// discriminator: a key-shaped raw_ref must still route to MinIO (here: fail
// against the dead endpoint and defer the row), never be delivered as if it
// were the message text.
func TestLoadRawForDelivery_KeyRefStillFetches(t *testing.T) {
	dsn := testDSN()
	if dsn == "" {
		t.Skip("DB_DSN/TEST_DB_DSN not set; skipping DB-backed test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	item := rawFixture(t, ctx, pool, "blobs/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")

	w := newTestWorker(t, pool, func(string) (string, string) { return "250 ok", "250 ok" })
	w.minio = deadMinio(t)
	w.bucket = "test-bucket"

	if got, ok := w.loadRawForDelivery(ctx, item); ok {
		t.Fatalf("loadRawForDelivery(key raw_ref, dead MinIO) succeeded with %q — the key was mis-delivered as message text", got)
	}
	if _, lastErr := queueState(t, ctx, pool, item.id); !strings.Contains(lastErr, "blob") {
		t.Errorf("last_error = %q, want a MinIO blob-fetch failure", lastErr)
	}
}

// TestLoadRawForDelivery_EmptyRawRefNoPanic (red-first): an empty raw_ref used
// to hit `err.Error()` with a nil err — a panic on the live delivery path.
// It must fail the row cleanly instead.
func TestLoadRawForDelivery_EmptyRawRefNoPanic(t *testing.T) {
	dsn := testDSN()
	if dsn == "" {
		t.Skip("DB_DSN/TEST_DB_DSN not set; skipping DB-backed test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	item := rawFixture(t, ctx, pool, "")

	w := newTestWorker(t, pool, func(string) (string, string) { return "250 ok", "250 ok" })
	w.minio = deadMinio(t)
	w.bucket = "test-bucket"

	if got, ok := w.loadRawForDelivery(ctx, item); ok {
		t.Fatalf("loadRawForDelivery(empty raw_ref) succeeded with %q, want clean failure", got)
	}
	if _, lastErr := queueState(t, ctx, pool, item.id); !strings.Contains(lastErr, "raw_ref") {
		t.Errorf("last_error = %q, want a raw_ref read failure", lastErr)
	}
}
