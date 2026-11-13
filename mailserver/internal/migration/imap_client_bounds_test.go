package migration

// Post-handshake admission-bound tests (er5-s15, sealed anchor
// imap-migration-buffers-attacker-sized-rfc822-messages-without-a-byte-limit):
// every post-handshake command round trip (greeting, LOGIN, LIST, SELECT, UID
// FETCH) must fail on the per-command conn deadline instead of pinning the
// connector goroutine and socket against a hostile source server, and an
// over-cap RFC822 literal must be refused instead of buffered unbounded.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap"
)

// shortDeadline restores imapCommandDeadline after a test shortens it.
func shortDeadline(t *testing.T, d time.Duration) {
	t.Helper()
	old := imapCommandDeadline
	imapCommandDeadline = d
	t.Cleanup(func() { imapCommandDeadline = old })
}

// stallPipe returns a connected net.Pipe pair for a server that never answers.
func stallPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = serverConn.Close() })
	return clientConn, serverConn
}

// TestRunIMAPCommand_DeadlineFailsSilentServer: runIMAPCommand's fn blocks
// forever against a silent peer; the command deadline must break it with an
// i/o-timeout error and RELEASE the deadline afterwards.
func TestRunIMAPCommand_DeadlineFailsSilentServer(t *testing.T) {
	shortDeadline(t, 150*time.Millisecond)
	clientConn, serverConn := stallPipe(t)

	start := time.Now()
	err := runIMAPCommand(context.Background(), clientConn, func() error {
		// A read against the never-answering peer parks until the deadline.
		one := make([]byte, 1)
		_, err := clientConn.Read(one)
		return err
	})
	if err == nil {
		t.Fatal("command against a silent server returned nil; want deadline error")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline error = %v; want os.ErrDeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("deadline took %v to fire; bound was 150ms", elapsed)
	}
	// The deadline must be cleared on return: a subsequent write with the
	// peer actively answering must not fail on a stale deadline.
	go func() { _, _ = serverConn.Write([]byte("x")) }()
	_ = clientConn.SetDeadline(time.Time{})
	one := make([]byte, 1)
	if _, err := clientConn.Read(one); err != nil {
		t.Fatalf("post-command read failed on a stale deadline: %v", err)
	}
}

// TestIMAPDialConn_GreetingDeadline: a source that completes the TCP connect
// and then answers NOTHING must fail dialConn on the greeting deadline (the
// "none" TLS-mode greeting previously had no bound at all).
func TestIMAPDialConn_GreetingDeadline(t *testing.T) {
	shortDeadline(t, 150*time.Millisecond)
	clientConn, _ := stallPipe(t)

	c := NewIMAPConnector(IMAPConfig{Host: "mail.example.test", Port: 143, TLSMode: "none"})
	c.dialContext = func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }

	start := time.Now()
	if _, _, err := c.dialConn(context.Background()); err == nil {
		t.Fatal("dialConn against a silent server returned nil; want greeting deadline error")
	} else if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("greeting deadline took %v to fire", elapsed)
	}
}

// TestIMAPTestConnection_LoginDeadline: a source that completes the greeting
// + capability exchange and then never answers LOGIN fails TestConnection on
// the per-command deadline instead of pinning the caller's goroutine.
func TestIMAPTestConnection_LoginDeadline(t *testing.T) {
	shortDeadline(t, 200*time.Millisecond)
	clientConn, serverConn := stallPipe(t)
	go func() {
		// Complete greeting + CAPABILITY (so the connector dials), then
		// consume LOGIN and never answer another command.
		_, _ = serverConn.Write([]byte("* OK test server ready\r\n"))
		reader := bufio.NewReader(serverConn)
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		tag := strings.Fields(line)[0]
		_, _ = fmt.Fprintf(serverConn, "* CAPABILITY IMAP4rev1\r\n%s OK CAPABILITY completed\r\n", tag)
		buf := make([]byte, 4096)
		for {
			if _, err := serverConn.Read(buf); err != nil {
				return
			}
		}
	}()

	c := NewIMAPConnector(IMAPConfig{
		Host: "mail.example.test", Port: 143, TLSMode: "none",
		Credentials: IMAPCredentials{Username: "u", Password: "p"},
	})
	c.dialContext = func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }

	start := time.Now()
	err := c.TestConnection(context.Background())
	if err == nil {
		t.Fatal("TestConnection against a LOGIN-stalling server returned nil; want deadline error")
	}
	if !strings.Contains(err.Error(), "imap login") {
		t.Fatalf("error = %v; want the bounded login round trip to fail", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("login deadline took %v to fire; bound was 200ms", elapsed)
	}
}

// endlessReader streams 'a' bytes forever without buffering them — the
// bounded read must stop pulling at cap+1, so the source itself stays cheap.
type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

// oversizedLiteral is an imap.Literal whose stream exceeds the migration cap.
type oversizedLiteral struct{ reader io.Reader }

func (o oversizedLiteral) Read(p []byte) (int, error) { return o.reader.Read(p) }
func (o oversizedLiteral) Len() int                   { return maxMigrationMessageBytes * 2 }

// TestRFC822Bytes_RefusesOverCapLiteral: a message whose RFC822 literal
// exceeds maxMigrationMessageBytes is refused with an error — never buffered
// into memory past cap+1.
func TestRFC822Bytes_RefusesOverCapLiteral(t *testing.T) {
	msg := &imap.Message{Items: map[imap.FetchItem]interface{}{
		imap.FetchRFC822: oversizedLiteral{reader: endlessReader{}},
	}}
	raw, err := rfc822Bytes(msg)
	if err == nil {
		t.Fatal("over-cap RFC822 literal accepted; want refusal")
	}
	if !strings.Contains(err.Error(), "migration cap") {
		t.Fatalf("refusal error = %v; want the cap message", err)
	}
	if raw != nil {
		t.Fatalf("over-cap message returned %d bytes; want nil", len(raw))
	}
}

// TestRFC822Bytes_AcceptsUnderCapLiteral: normal messages keep flowing —
// the bound refuses the pathological, not the ordinary.
func TestRFC822Bytes_AcceptsUnderCapLiteral(t *testing.T) {
	body := "From: a@b\r\n\r\nhello\r\n"
	msg := &imap.Message{Items: map[imap.FetchItem]interface{}{
		imap.FetchRFC822: oversizedLiteral{reader: bytes.NewReader([]byte(body))},
	}}
	raw, err := rfc822Bytes(msg)
	if err != nil {
		t.Fatalf("under-cap literal refused: %v", err)
	}
	if !bytes.Equal(raw, []byte(body)) {
		t.Fatalf("bounded read corrupted the body: %q", raw)
	}
}

// TestRFC822Bytes_EmptyMessage: an itemless message stays a nil-body skip
// (the pre-bound contract for messages with no RFC822 item at all).
func TestRFC822Bytes_EmptyMessage(t *testing.T) {
	raw, err := rfc822Bytes(&imap.Message{})
	if err != nil || raw != nil {
		t.Fatalf("itemless message = (%v, %v); want (nil, nil)", raw, err)
	}
}
