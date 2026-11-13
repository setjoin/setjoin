package smtp

// Occurrence-specific tests for the ER5 smtp-lane submission bounds:
//
//   - resource-exhaustion.smtp-auth-line: unauthenticated submission command
//     and AUTH lines are byte-bounded at intake (readBoundedLine wired into
//     subConnState.serveCommands); a refusal answers 500 5.5.2 BEFORE any
//     dispatch — the nil srv.pool in these tests is a canary: reaching any
//     DB-backed handler would panic.
//   - smtp-bare-lf-message-smuggling: submission DATA uses the same strict
//     CRLF terminator; a bare-LF "." refuses 500 and terminates the
//     connection (handleData returns false).

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

func newSubmissionBoundsServer() *SubmissionServer {
	return &SubmissionServer{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func driveSubmissionServeCommands(t *testing.T) (net.Conn, *bufio.Reader, chan struct{}) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	c := &subConnState{
		srv:    newSubmissionBoundsServer(),
		conn:   server,
		tp:     textproto.NewConn(server),
		authed: false,
	}
	done := make(chan struct{})
	go func() {
		c.serveCommands(context.Background())
		close(done)
	}()
	return client, bufio.NewReader(client), done
}

// TestSubmissionServeCommands_OverlongCommandRejected500 is the intake bypass
// for unauthenticated command lines: an overlong NOOP is refused 500 5.5.2
// before dispatch, the loop stays in sync, and QUIT still closes cleanly.
func TestSubmissionServeCommands_OverlongCommandRejected500(t *testing.T) {
	client, r, done := driveSubmissionServeCommands(t)

	if got := readReply(t, r); !strings.HasPrefix(got, "220") {
		t.Fatalf("greeting = %q", got)
	}
	fmt.Fprintf(client, "NOOP %s\r\n", strings.Repeat("a", 6000))
	if got := readReply(t, r); !strings.HasPrefix(got, "500 5.5.2") {
		t.Fatalf("overlong command reply = %q, want 500 5.5.2", got)
	}
	fmt.Fprintf(client, "NOOP\r\n")
	if got := readReply(t, r); !strings.HasPrefix(got, "250") {
		t.Fatalf("NOOP after refusal = %q, want 250", got)
	}
	fmt.Fprintf(client, "QUIT\r\n")
	if got := readReply(t, r); !strings.HasPrefix(got, "221") {
		t.Fatalf("QUIT reply = %q, want 221", got)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveCommands did not return after QUIT")
	}
}

// TestSubmissionServeCommands_OverlongAuthLineRejected500 is the AUTH-line
// bypass: a multi-kilobyte AUTH PLAIN argument is one command line, so the
// same intake bound refuses it 500 5.5.2 before handleAuth (and before any
// credential processing or DB access — srv.pool is nil here on purpose).
func TestSubmissionServeCommands_OverlongAuthLineRejected500(t *testing.T) {
	client, r, _ := driveSubmissionServeCommands(t)

	if got := readReply(t, r); !strings.HasPrefix(got, "220") {
		t.Fatalf("greeting = %q", got)
	}
	fmt.Fprintf(client, "AUTH PLAIN %s\r\n", strings.Repeat("Q", 6000))
	if got := readReply(t, r); !strings.HasPrefix(got, "500 5.5.2") {
		t.Fatalf("overlong AUTH reply = %q, want 500 5.5.2", got)
	}
}

// TestSubmissionDataGuards pins the DATA pre-guards without a DB: an
// unauthenticated DATA answers 530; an authenticated session without a
// completed MAIL/RCPT sequence answers 503. Both keep the connection.
func TestSubmissionDataGuards(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	c := &subConnState{
		srv:  newSubmissionBoundsServer(),
		conn: server,
		tp:   textproto.NewConn(server),
	}
	result := make(chan bool, 1)
	go func() { result <- c.handleData(context.Background()) }()
	r := bufio.NewReader(client)
	if got := readReply(t, r); !strings.HasPrefix(got, "530") {
		t.Fatalf("unauthed DATA reply = %q, want 530", got)
	}
	if ok := <-result; !ok {
		t.Fatal("530 DATA guard must keep the connection")
	}

	c2 := &subConnState{
		srv:    newSubmissionBoundsServer(),
		conn:   server,
		tp:     textproto.NewConn(server),
		authed: true,
	}
	go func() { result <- c2.handleData(context.Background()) }()
	if got := readReply(t, r); !strings.HasPrefix(got, "503") {
		t.Fatalf("MAIL-less DATA reply = %q, want 503", got)
	}
	if ok := <-result; !ok {
		t.Fatal("503 DATA guard must keep the connection")
	}
}

// TestSubmissionServeCommands_DataFramingBounds drives the live submission
// loop (pre-authenticated state, no DB) through both DATA framing legs: an
// overlong line answers 550 and the loop continues; a bare-LF "." terminator
// answers 500 5.5.2 and terminates the connection before the trailing
// sender-controlled bytes can be parsed as commands.
func TestSubmissionServeCommands_DataFramingBounds(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	c := &subConnState{
		srv:    newSubmissionBoundsServer(),
		conn:   server,
		tp:     textproto.NewConn(server),
		authed: true,
		from:   "sender@test.local",
		to:     []string{"rcpt@test.local"},
	}
	done := make(chan struct{})
	go func() {
		c.serveCommands(context.Background())
		close(done)
	}()

	r := bufio.NewReader(client)
	if got := readReply(t, r); !strings.HasPrefix(got, "220") {
		t.Fatalf("greeting = %q", got)
	}
	fmt.Fprintf(client, "DATA\r\n")
	if got := readReply(t, r); !strings.HasPrefix(got, "354") {
		t.Fatalf("DATA reply = %q, want 354", got)
	}
	fmt.Fprintf(client, "%s\r\n.\r\n", strings.Repeat("a", 1000))
	if got := readReply(t, r); !strings.HasPrefix(got, "550") {
		t.Fatalf("overlong DATA line reply = %q, want 550", got)
	}
	fmt.Fprintf(client, "DATA\r\n")
	if got := readReply(t, r); !strings.HasPrefix(got, "354") {
		t.Fatalf("second DATA reply = %q, want 354", got)
	}
	fmt.Fprintf(client, "body\r\n.\nQUIT\r\n")
	if got := readReply(t, r); !strings.HasPrefix(got, "500 5.5.2") {
		t.Fatalf("bare-LF DATA reply = %q, want 500 5.5.2", got)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveCommands must terminate after a refused smuggling frame")
	}
}

// TestSubmissionDataBareLFTerminatorRefused drives submission handleData
// directly (authenticated state) with a bare-LF "." terminator: the reply is
// 500 5.5.2 and handleData reports connection termination (false) — the frame
// can never resynchronize against sender-controlled trailing bytes.
func TestSubmissionDataBareLFTerminatorRefused(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	c := &subConnState{
		srv:    newSubmissionBoundsServer(),
		conn:   server,
		tp:     textproto.NewConn(server),
		authed: true,
		from:   "sender@test.local",
		to:     []string{"rcpt@test.local"},
	}

	result := make(chan bool, 1)
	go func() { result <- c.handleData(context.Background()) }()

	r := bufio.NewReader(client)
	if got := readReply(t, r); !strings.HasPrefix(got, "354") {
		t.Fatalf("DATA reply = %q, want 354", got)
	}
	fmt.Fprintf(client, "Subject: smuggling\r\n.\nQUIT\r\n")
	if got := readReply(t, r); !strings.HasPrefix(got, "500 5.5.2") {
		t.Fatalf("bare-LF DATA reply = %q, want 500 5.5.2", got)
	}
	select {
	case ok := <-result:
		if ok {
			t.Fatal("handleData must report connection termination after a bare-LF terminator")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handleData did not return")
	}
}
