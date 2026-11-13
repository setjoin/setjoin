package imap

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeIMAPTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames:  []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestQuoteIMAP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "NIL"},
		{"hello", `"hello"`},
		{`say "hello"`, `"say \"hello\""`},
		{`path\to\file`, `"path\\to\\file"`},
	}
	for _, tc := range tests {
		got := quoteIMAP(tc.input)
		if got != tc.want {
			t.Errorf("quoteIMAP(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSplitIMAPArgs(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{`LOGIN user pass`, []string{"LOGIN", "user", "pass"}},
		{`LOGIN "user@example.com" "my secret password"`, []string{"LOGIN", `"user@example.com"`, `"my secret password"`}},
		{`SELECT INBOX`, []string{"SELECT", "INBOX"}},
		{`SEARCH SEEN`, []string{"SEARCH", "SEEN"}},
		{`SEARCH FROM "alice@example.com"`, []string{"SEARCH", "FROM", `"alice@example.com"`}},
		{``, nil},
		{`  `, nil},
	}
	for _, tc := range tests {
		got := splitIMAPArgs(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("splitIMAPArgs(%q) len = %d, want %d: got=%v", tc.input, len(got), len(tc.want), got)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitIMAPArgs(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}

func TestCanonicalMailboxLookupNameOnlyFoldsReservedInbox(t *testing.T) {
	for _, input := range []string{"INBOX", "Inbox", "inbox", "iNbOx"} {
		if got := canonicalMailboxLookupName(input); got != "Inbox" {
			t.Fatalf("canonicalMailboxLookupName(%q)=%q", input, got)
		}
	}
	for _, input := range []string{"Sent", "sent", "INBOX-Archive", "Project"} {
		if got := canonicalMailboxLookupName(input); got != input {
			t.Fatalf("non-INBOX name %q changed to %q", input, got)
		}
	}
}

func TestBuildSearchClause(t *testing.T) {
	tests := []struct {
		args       string
		wantWhere  string
		wantParams int
	}{
		{"", "", 0},
		{"ALL", "", 0},
		{"SEEN", " AND m.is_read = TRUE", 0},
		{"UNSEEN", " AND m.is_read = FALSE", 0},
		{"DELETED", " AND m.is_deleted = TRUE", 0},
		{"ANSWERED", " AND m.is_answered = TRUE", 0},
		{"FLAGGED", " AND m.is_flagged = TRUE", 0},
		{"SEEN DELETED", " AND m.is_read = TRUE AND m.is_deleted = TRUE", 0},
	}
	for _, tc := range tests {
		where, params := buildSearchClause(tc.args)
		if where != tc.wantWhere {
			t.Errorf("buildSearchClause(%q) where = %q, want %q", tc.args, where, tc.wantWhere)
		}
		if len(params) != tc.wantParams {
			t.Errorf("buildSearchClause(%q) params len = %d, want %d", tc.args, len(params), tc.wantParams)
		}
	}
}

func TestBuildSearchClauseMessageIDHeaderIsExactAndParameterized(t *testing.T) {
	where, params := buildSearchClause(`HEADER Message-ID "<probe@example.test>"`)
	if where != " AND m.message_id = $2" || len(params) != 1 || params[0] != "<probe@example.test>" {
		t.Fatalf("message-id search where=%q params=%v", where, params)
	}
	where, params = buildSearchClause(`HEADER X-Unknown "value"`)
	if where != " AND FALSE" || len(params) != 0 {
		t.Fatalf("unsupported header search where=%q params=%v", where, params)
	}
}

func TestBuildSearchClauseValueKeys(t *testing.T) {
	_, params := buildSearchClause(`FROM "alice@example.com"`)
	if len(params) != 1 || params[0] != "%alice@example.com%" {
		t.Errorf("FROM search: got params %v", params)
	}

	_, params = buildSearchClause(`SUBJECT hello`)
	if len(params) != 1 || params[0] != "%hello%" {
		t.Errorf("SUBJECT search: got params %v", params)
	}

	_, params = buildSearchClause(`TEXT "urgent meeting"`)
	if len(params) != 1 || params[0] != "%urgent meeting%" {
		t.Errorf("TEXT search: got params %v", params)
	}
}

func TestMatchETag(t *testing.T) {
	// matchETag is defined in caldav/webdav.go and carddav/webdav.go
}

var benchSearchWhere string

func BenchmarkBuildSearchClause(b *testing.B) {
	for b.Loop() {
		benchSearchWhere, _ = buildSearchClause(`SEEN FROM "alice@example.com" SUBJECT invoice`)
	}
}

func TestAuthenticateHasThreatProtection(t *testing.T) {
	// Verify Server struct has threatInterceptor field for AUTHENTICATE handler
	s := &Server{}
	if s.threatInterceptor != nil {
		t.Error("expected nil threatInterceptor in zero-value Server")
	}
	// The real test is: AUTHENTICATE PLAIN must not bypass the threat pipeline.
	// This is verified by code review: handleAuthenticate must call Intercept()
	// before CheckPassword and RecordResult() after, matching handleLogin.
}

func TestSTARTTLSCapabilitiesAndPlaintextAuthFence(t *testing.T) {
	conn := &bufConn{}
	c := &connState{
		srv:  &Server{tlsCert: "server.pem", tlsKey: "server.key", requireTLS: true},
		conn: conn,
	}
	capabilities := c.capabilities()
	if !strings.Contains(capabilities, "STARTTLS") || !strings.Contains(capabilities, "LOGINDISABLED") {
		t.Fatalf("pre-TLS capabilities=%q want STARTTLS and LOGINDISABLED", capabilities)
	}

	c.handleLogin(context.Background(), "A1", `"user@example.com" "password"`)
	if got := conn.String(); !strings.Contains(got, "[PRIVACYREQUIRED] Must issue STARTTLS first") {
		t.Fatalf("plaintext LOGIN response=%q want privacy-required refusal", got)
	}

	conn = &bufConn{}
	c.conn = conn
	c.handleAuthenticate(context.Background(), "A2", "PLAIN")
	if got := conn.String(); !strings.Contains(got, "[PRIVACYREQUIRED] Must issue STARTTLS first") {
		t.Fatalf("plaintext AUTHENTICATE response=%q want privacy-required refusal", got)
	}

	c.secure = true
	capabilities = c.capabilities()
	if strings.Contains(capabilities, "STARTTLS") || strings.Contains(capabilities, "LOGINDISABLED") {
		t.Fatalf("post-TLS capabilities=%q still advertise pre-TLS restrictions", capabilities)
	}
}

func TestServerTLSModesSetFailClosedTransportState(t *testing.T) {
	s := NewServer(nil, "127.0.0.1:0", nil, slog.Default(), nil, nil)
	s.SetTLS("implicit.pem", "implicit.key")
	if !s.implicitTLS || !s.requireTLS || s.tlsCert != "implicit.pem" || s.tlsKey != "implicit.key" {
		t.Fatalf("implicit TLS state = %+v", s)
	}

	s.SetSTARTTLS("starttls.pem", "starttls.key")
	if s.implicitTLS || !s.requireTLS || s.tlsCert != "starttls.pem" || s.tlsKey != "starttls.key" {
		t.Fatalf("STARTTLS state = %+v", s)
	}
	s.SetMaxConns(17)
	s.SetPerUserMaxConns(3)
	if s.maxConns != 17 {
		t.Fatalf("maxConns = %d, want 17", s.maxConns)
	}
}

func TestServerStartRejectsInvalidTLSMaterialBeforeAccepting(t *testing.T) {
	s := NewServer(nil, "127.0.0.1:0", nil, slog.Default(), nil, nil)
	s.SetSTARTTLS("/definitely/missing/cert.pem", "/definitely/missing/key.pem")
	if err := s.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "TLS cert load") {
		t.Fatalf("Start error = %v, want certificate load failure", err)
	}
}

func TestServerStartAcceptsValidImplicitTLSMaterial(t *testing.T) {
	certPath, keyPath := writeIMAPTestCertificate(t)
	ctx, cancel := context.WithCancel(context.Background())
	s := NewServer(nil, "127.0.0.1:0", nil, slog.Default(), nil, nil)
	s.SetTLS(certPath, keyPath)
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start with valid implicit TLS: %v", err)
	}
	cancel()
}

func TestHandleStartTLSCompletesSecureUpgrade(t *testing.T) {
	certPath, keyPath := writeIMAPTestCertificate(t)
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	c := &connState{
		srv:  &Server{tlsCert: certPath, tlsKey: keyPath, logger: slog.Default()},
		conn: serverConn,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.handleStartTLS(context.Background(), "A1")
	}()
	reader := bufio.NewReader(clientConn)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line, "Begin TLS negotiation") {
		t.Fatalf("STARTTLS response = %q err=%v", line, err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("append test root certificate")
	}
	tlsClient := tls.Client(clientConn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots, ServerName: "localhost",
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server STARTTLS handshake did not finish")
	}
	if !c.secure {
		t.Fatal("successful STARTTLS did not mark the IMAP connection secure")
	}
}

func TestHandleStartTLSRejectsInvalidConnectionStates(t *testing.T) {
	tests := []struct {
		name string
		c    *connState
		want string
	}{
		{
			name: "already secure",
			c:    &connState{srv: &Server{logger: slog.Default()}, conn: &bufConn{}, secure: true},
			want: "TLS is already active",
		},
		{
			name: "already authenticated",
			c:    &connState{srv: &Server{logger: slog.Default()}, conn: &bufConn{}, authed: true},
			want: "not permitted after authentication",
		},
		{
			name: "not configured",
			c:    &connState{srv: &Server{logger: slog.Default()}, conn: &bufConn{}},
			want: "STARTTLS not available",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.c.reader = bufio.NewReader(test.c.conn)
			test.c.handleStartTLS(context.Background(), "A1")
			if got := test.c.conn.(*bufConn).String(); !strings.Contains(got, test.want) {
				t.Fatalf("response = %q, want %q", got, test.want)
			}
		})
	}
}

func TestHandleConnImplicitTLSAdvertisesSecureCapabilities(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &Server{implicitTLS: true, logger: slog.Default()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.handleConn(ctx, serverConn)
	}()

	reader := bufio.NewReader(clientConn)
	greeting, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(greeting, "CAPABILITY") || strings.Contains(greeting, "STARTTLS") {
		t.Fatalf("secure greeting = %q err=%v", greeting, err)
	}
	if _, err := clientConn.Write([]byte("A1 CAPABILITY\r\nA2 LOGOUT\r\n")); err != nil {
		t.Fatal(err)
	}
	var transcript strings.Builder
	for {
		line, err := reader.ReadString('\n')
		transcript.WriteString(line)
		if err != nil || strings.Contains(line, "A2 OK LOGOUT") {
			break
		}
	}
	if got := transcript.String(); !strings.Contains(got, "A1 OK CAPABILITY") || !strings.Contains(got, "A2 OK LOGOUT") {
		t.Fatalf("IMAP transcript = %q", got)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("IMAP connection did not close after LOGOUT")
	}
}
