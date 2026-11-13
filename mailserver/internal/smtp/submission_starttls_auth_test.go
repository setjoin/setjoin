package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
)

// The submission AUTH gate (med-shard2-001 / SMTP-V001): the 530 STARTTLS-first
// guard and the EHLO AUTH advertisement are keyed on ACTIVE TLS state, never on
// tlsCert presence. A cert-less MSA can never upgrade, so it must never
// advertise or accept plaintext AUTH.

// startSubmissionConn runs the real handleConn loop against one end of a
// net.Pipe and returns the client end. The SubmissionServer needs only a
// logger: the paths under test (EHLO capability list, AUTH guard) never reach
// the DB pool.
func startSubmissionConn(t *testing.T, srv *SubmissionServer) net.Conn {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		serverConn.Close()
		clientConn.Close()
	})
	go srv.handleConn(context.Background(), serverConn)
	return clientConn
}

// ehloCapabilities sends EHLO and returns the capability lines (the multiline
// 250 reply with the final "250 " line stripped of its prefix).
func ehloCapabilities(t *testing.T, conn net.Conn, r *bufio.Reader) []string {
	t.Helper()
	if _, err := fmt.Fprintf(conn, "EHLO client.test\r\n"); err != nil {
		t.Fatalf("write EHLO: %v", err)
	}
	var caps []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read EHLO reply: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "250 ") {
			caps = append(caps, strings.TrimPrefix(line, "250 "))
			return caps
		}
		if !strings.HasPrefix(line, "250-") {
			t.Fatalf("unexpected EHLO reply line %q", line)
		}
		caps = append(caps, strings.TrimPrefix(line, "250-"))
	}
}

func readSubmissionReply(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

func capsInclude(caps []string, prefix string) bool {
	for _, c := range caps {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func TestSubmissionCertlessMSANeverAdvertisesOrAcceptsAuth(t *testing.T) {
	// No SetTLS call — the cert-less MSA deployment shape from SMTP-V001.
	srv := &SubmissionServer{logger: testLogger()}
	conn := startSubmissionConn(t, srv)
	r := bufio.NewReader(conn)

	if reply := readSubmissionReply(t, r); !strings.HasPrefix(reply, "220") {
		t.Fatalf("greeting = %q, want 220", reply)
	}

	caps := ehloCapabilities(t, conn, r)
	if capsInclude(caps, "AUTH") {
		t.Errorf("cert-less MSA advertised AUTH before any TLS: %v", caps)
	}
	if capsInclude(caps, "STARTTLS") {
		t.Errorf("cert-less MSA advertised STARTTLS without a configured cert: %v", caps)
	}

	// A client that tries anyway must get the STARTTLS-first 530 (which closes
	// the connection), never a plaintext AUTH continuation.
	if _, err := fmt.Fprintf(conn, "AUTH PLAIN AGFsaWNlAGFsaWNlcHc=\r\n"); err != nil {
		t.Fatalf("write AUTH: %v", err)
	}
	if reply := readSubmissionReply(t, r); !strings.HasPrefix(reply, "530") {
		t.Fatalf("cert-less MSA AUTH reply = %q, want 530 STARTTLS-first refusal", reply)
	}
}

func TestSubmissionCertMSAHidesAuthUntilSTARTTLS(t *testing.T) {
	// Cert paths configured (paths only are read at EHLO/guard time — the files
	// are only loaded on an actual STARTTLS command), before any STARTTLS.
	srv := &SubmissionServer{logger: testLogger(), tlsCert: "/setjoin/test/nonexistent-cert.pem"}
	conn := startSubmissionConn(t, srv)
	r := bufio.NewReader(conn)

	if reply := readSubmissionReply(t, r); !strings.HasPrefix(reply, "220") {
		t.Fatalf("greeting = %q, want 220", reply)
	}

	caps := ehloCapabilities(t, conn, r)
	if !capsInclude(caps, "STARTTLS") {
		t.Errorf("cert-capable MSA must advertise STARTTLS, got %v", caps)
	}
	if capsInclude(caps, "AUTH") {
		t.Errorf("AUTH must not be advertised before STARTTLS, got %v", caps)
	}

	if _, err := fmt.Fprintf(conn, "AUTH PLAIN AGFsaWNlAGFsaWNlcHc=\r\n"); err != nil {
		t.Fatalf("write AUTH: %v", err)
	}
	if reply := readSubmissionReply(t, r); !strings.HasPrefix(reply, "530") {
		t.Fatalf("pre-STARTTLS AUTH reply = %q, want 530 STARTTLS-first refusal", reply)
	}
}

func TestSubmissionActiveTLSAdvertisesAuth(t *testing.T) {
	// With TLS ACTIVE (real in-memory STARTTLS handshake) AUTH is advertised
	// again and the guard passes — the fix must not break the legitimate path.
	cert, key := newSelfSignedCert(t, "localhost")
	certPath, keyPath := writeCertPEMFiles(t, cert, key)

	srv := &SubmissionServer{logger: testLogger()}
	srv.SetTLS(certPath, keyPath)
	conn := startSubmissionConn(t, srv)
	r := bufio.NewReader(conn)

	if reply := readSubmissionReply(t, r); !strings.HasPrefix(reply, "220") {
		t.Fatalf("greeting = %q, want 220", reply)
	}
	if caps := ehloCapabilities(t, conn, r); !capsInclude(caps, "STARTTLS") {
		t.Fatalf("cert-capable MSA must advertise STARTTLS, got %v", caps)
	}

	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		t.Fatalf("write STARTTLS: %v", err)
	}
	if reply := readSubmissionReply(t, r); !strings.HasPrefix(reply, "220") {
		t.Fatalf("STARTTLS reply = %q, want 220 ready", reply)
	}

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	// Post-handshake traffic is TLS-encrypted: read it through the TLS conn.
	tlsReader := bufio.NewReader(tlsConn)

	caps := ehloCapabilities(t, tlsConn, tlsReader)
	if !capsInclude(caps, "AUTH") {
		t.Errorf("AUTH must be advertised on an active TLS session, got %v", caps)
	}
	if _, err := fmt.Fprintf(tlsConn, "QUIT\r\n"); err != nil {
		t.Fatalf("write QUIT: %v", err)
	}
	if reply := readSubmissionReply(t, tlsReader); !strings.HasPrefix(reply, "221") {
		t.Fatalf("QUIT reply = %q, want 221", reply)
	}
}
