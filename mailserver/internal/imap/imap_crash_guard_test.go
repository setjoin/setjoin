package imap

// Regression tests for C4-imap: bare AUTHENTICATE and bare APPEND panics.
//
// Without the fix, strings.Fields(args)[0] in handleAuthenticate and
// strings.Fields(prefix)[0] in handleAppend index into an empty slice, causing
// an index-out-of-range panic that crashes the per-conn goroutine (and, without
// the recover guard, the whole process).
//
// Each test drives the handler directly via connState + bufConn (no DB needed)
// and asserts: (a) no panic, (b) the response contains "BAD".

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// TestBareAuthenticate_NoPanic is the primary regression: an unauthenticated
// client sends "A1 AUTHENTICATE" with no mechanism argument.
// Before the fix this panics; after the fix it replies BAD and returns.
func TestBareAuthenticate_NoPanic(t *testing.T) {
	srv := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	bc := &bufConn{}
	c := &connState{
		srv:    srv,
		conn:   bc,
		reader: bufio.NewReader(strings.NewReader("")),
	}

	// Must not panic.
	c.handleAuthenticate(context.Background(), "A1", "")

	out := bc.String()
	if !strings.Contains(out, "BAD") {
		t.Errorf("expected BAD response to bare AUTHENTICATE, got: %q", out)
	}
}

// TestAppendNoMailbox_NoPanic is the regression for the authed-DoS vector:
// an authenticated client sends "A2 APPEND {5}" with no mailbox name before
// the literal. Before the fix this panics; after the fix it replies BAD.
func TestAppendNoMailbox_NoPanic(t *testing.T) {
	srv := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	bc := &bufConn{}
	c := &connState{
		srv:    srv,
		conn:   bc,
		reader: bufio.NewReader(strings.NewReader("hello\r\n")), // literal body + trailing CRLF
		authed: true,
	}

	// args = "{5}" — no mailbox name before the literal size.
	// Must not panic.
	c.handleAppend(context.Background(), "A2", "{5}")

	out := bc.String()
	if !strings.Contains(out, "BAD") {
		t.Errorf("expected BAD response to APPEND with no mailbox, got: %q", out)
	}
}
