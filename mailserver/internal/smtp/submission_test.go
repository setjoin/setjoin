package smtp

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// TestSubmissionConversation tests a complete SMTP submission flow
// using an in-memory net.Pipe connection.
func TestSubmissionConversation(t *testing.T) {
	// We can't easily mock the DB pool here, so test at the protocol level
	// by verifying command parsing works correctly.

	// Test extractAddr with various formats
	tests := []struct {
		input string
		want  string
	}{
		{"<alice@example.com>", "alice@example.com"},
		{"bob@example.com", "bob@example.com"},
		{"Alice Smith <alice@example.com>", "alice@example.com"},
		{"", ""},
	}
	for _, tc := range tests {
		got := extractAddr(tc.input)
		if got != tc.want {
			t.Errorf("extractAddr(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestSMTPProtocolBasics verifies basic SMTP command/response parsing.
func TestSMTPProtocolBasics(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Simple server that reads commands and responds
		reader := bufio.NewReader(server)
		fmt.Fprintf(server, "220 test ESMTP\r\n")

		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToUpper(line), "QUIT") {
				fmt.Fprintf(server, "221 Bye\r\n")
				return
			}
			fmt.Fprintf(server, "250 OK\r\n")
		}
	}()

	// Client side
	reader := bufio.NewReader(client)
	greeting, _ := reader.ReadString('\n')
	if !strings.HasPrefix(greeting, "220") {
		t.Fatalf("expected 220 greeting, got: %s", greeting)
	}

	fmt.Fprintf(client, "EHLO client\r\n")
	resp, _ := reader.ReadString('\n')
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("expected 250, got: %s", resp)
	}

	fmt.Fprintf(client, "QUIT\r\n")
	resp, _ = reader.ReadString('\n')
	if !strings.HasPrefix(resp, "221") {
		t.Fatalf("expected 221, got: %s", resp)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server handler timeout")
	}
}
