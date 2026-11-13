package imap

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadLineLimited_NormalLine(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("a001 LOGIN user pass\r\nNEXT\r\n"))
	line, err := readLineLimited(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(line) != "a001 LOGIN user pass" {
		t.Errorf("got %q", line)
	}
	// second line still readable
	line2, err := readLineLimited(r)
	if err != nil || strings.TrimSpace(line2) != "NEXT" {
		t.Errorf("second line: %q err=%v", line2, err)
	}
}

func TestReadLineLimited_TooLong(t *testing.T) {
	// A line with no newline, longer than the cap, must be rejected rather than
	// buffered without bound.
	huge := strings.Repeat("A", maxIMAPLineBytes+1024)
	r := bufio.NewReader(strings.NewReader(huge))
	_, err := readLineLimited(r)
	if err != errIMAPLineTooLong {
		t.Fatalf("expected errIMAPLineTooLong, got %v", err)
	}
}

func TestReadLineLimited_AtBoundary(t *testing.T) {
	// Exactly maxIMAPLineBytes of content followed by newline should still be
	// accepted (the cap guards unbounded growth, not legitimate max-size lines).
	body := strings.Repeat("B", maxIMAPLineBytes-2) // + "\r\n" => maxIMAPLineBytes total
	r := bufio.NewReader(strings.NewReader(body + "\r\n"))
	line, err := readLineLimited(r)
	if err != nil {
		t.Fatalf("boundary line rejected: %v", err)
	}
	if strings.TrimSpace(line) != body {
		t.Errorf("boundary line corrupted (len=%d)", len(strings.TrimSpace(line)))
	}
}

func TestReadLineLimited_EOF(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("partial-no-newline"))
	line, err := readLineLimited(r)
	if err == nil {
		t.Fatalf("expected EOF error, got nil (line=%q)", line)
	}
}
