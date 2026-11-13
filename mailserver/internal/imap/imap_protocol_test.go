package imap

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// TestIMAPProtocolBasics verifies basic IMAP command/response parsing
// using an in-memory net.Pipe connection.
func TestIMAPProtocolBasics(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		reader := bufio.NewReader(server)
		fmt.Fprintf(server, "* OK [CAPABILITY IMAP4rev2] test ready\r\n")

		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			parts := strings.Fields(line)
			if len(parts) < 2 {
				fmt.Fprintf(server, "* BAD Command not understood\r\n")
				continue
			}

			tag := parts[0]
			cmd := strings.ToUpper(parts[1])

			switch cmd {
			case "CAPABILITY":
				fmt.Fprintf(server, "* CAPABILITY IMAP4rev2\r\n")
				fmt.Fprintf(server, "%s OK CAPABILITY completed\r\n", tag)
			case "NOOP":
				fmt.Fprintf(server, "%s OK NOOP completed\r\n", tag)
			case "LOGOUT":
				fmt.Fprintf(server, "* BYE Logging out\r\n")
				fmt.Fprintf(server, "%s OK LOGOUT completed\r\n", tag)
				return
			default:
				fmt.Fprintf(server, "%s BAD Command not implemented\r\n", tag)
			}
		}
	}()

	// Client side
	reader := bufio.NewReader(client)
	greeting, _ := reader.ReadString('\n')
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("expected * OK greeting, got: %s", greeting)
	}

	fmt.Fprintf(client, "A1 CAPABILITY\r\n")
	resp, _ := reader.ReadString('\n')
	if !strings.HasPrefix(resp, "* CAPABILITY") {
		t.Fatalf("expected * CAPABILITY, got: %s", resp)
	}
	resp, _ = reader.ReadString('\n')
	if !strings.HasPrefix(resp, "A1 OK") {
		t.Fatalf("expected A1 OK, got: %s", resp)
	}

	fmt.Fprintf(client, "A2 NOOP\r\n")
	resp, _ = reader.ReadString('\n')
	if !strings.HasPrefix(resp, "A2 OK") {
		t.Fatalf("expected A2 OK, got: %s", resp)
	}

	fmt.Fprintf(client, "A3 LOGOUT\r\n")
	resp, _ = reader.ReadString('\n')
	if !strings.HasPrefix(resp, "* BYE") {
		t.Fatalf("expected * BYE, got: %s", resp)
	}
	resp, _ = reader.ReadString('\n')
	if !strings.HasPrefix(resp, "A3 OK") {
		t.Fatalf("expected A3 OK, got: %s", resp)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server handler timeout")
	}
}
