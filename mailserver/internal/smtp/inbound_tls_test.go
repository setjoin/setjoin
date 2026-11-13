package smtp

import (
	"net"
	"net/textproto"
	"strings"
	"testing"
)

// TestInboundTLSEnforced_RejectsPlaintextMAIL tests that when TLS is enforced,
// a MAIL FROM command sent without prior STARTTLS gets a 530 5.7.0 rejection.
func TestInboundTLSEnforced_RejectsPlaintextMAIL(t *testing.T) {
	srv := &InboundServer{tlsEnforce: true}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	c := &inConnState{
		srv:     srv,
		conn:    serverConn,
		tp:      textproto.NewConn(serverConn),
		state:   phaseEhlo,
		tlsMode: tlsNone,
	}

	go c.handleMail("FROM:<test@example.com>")

	buf := make([]byte, 1024)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	response := string(buf[:n])

	if !strings.HasPrefix(response, "530") {
		t.Errorf("expected 530 5.7.0 TLS enforcement response, got: %s", response)
	}
	if !strings.Contains(response, "5.7.0") {
		t.Errorf("expected enhanced status code 5.7.0, got: %s", response)
	}
	if !strings.Contains(strings.ToLower(response), "starttls") {
		t.Errorf("expected response to mention STARTTLS, got: %s", response)
	}
}

// TestInboundTLSNotEnforced_AllowsPlaintextMAIL tests that when TLS is NOT enforced,
// a plaintext MAIL FROM is not rejected with a 530 TLS error.
func TestInboundTLSNotEnforced_AllowsPlaintextMAIL(t *testing.T) {
	srv := &InboundServer{tlsEnforce: false}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	c := &inConnState{
		srv:     srv,
		conn:    serverConn,
		tp:      textproto.NewConn(serverConn),
		state:   phaseGreeting,
		tlsMode: tlsNone,
	}

	go c.handleMail("FROM:<test@example.com>")

	buf := make([]byte, 1024)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	response := string(buf[:n])

	if strings.HasPrefix(response, "530") {
		t.Errorf("unexpected 530 TLS enforcement when tlsEnforce=false, got: %s", response)
	}
	if !strings.HasPrefix(response, "503") {
		t.Errorf("expected 503 'Send EHLO/HELO first' (next check after TLS guard), got: %s", response)
	}
}
