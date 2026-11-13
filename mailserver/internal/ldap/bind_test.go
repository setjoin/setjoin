package ldap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ldapclient "github.com/go-ldap/ldap/v3"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/pwhash"
	"setjoin.com/shared/testsupport"
)

func createLDAPTestPrimaryMailbox(t *testing.T, pool *pgxpool.Pool, ctx context.Context, userID, domainID int64, email string) int64 {
	t.Helper()
	var mailboxID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 VALUES ($1, $2, $3, $3, 'personal', TRUE) RETURNING id`,
		userID, domainID, email,
	).Scan(&mailboxID); err != nil {
		t.Fatalf("insert primary mailbox: %v", err)
	}
	return mailboxID
}

// genSelfSignedCert writes a throwaway self-signed cert/key pair to a temp
// dir for a test LDAPS listener. handleBind refuses to authenticate over a
// plaintext connection, so the test server needs real TLS, not a mock.
func genSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

// freeTCPPort grabs an ephemeral port by binding then releasing it.
// ponytail: small TOCTOU race between close and reuse; acceptable for a test.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// TestHandleBind_AuthPath is the regression test for the LDAP GAL bind
// path (handleBind in server.go). It drives the real handler through a live
// LDAPS listener (Start/SetTLS/handleBind), not a mock, and asserts the exact
// result codes the handler emits: LDAPResultInvalidCredentials (49) for a
// wrong password or an unknown DN — handleBind routes both through the same
// auth.CheckPassword failure branch, so both come back invalidCredentials,
// not a distinct "no such object" code — and LDAPResultSuccess (0) for a
// valid bind.
func TestHandleBind_AuthPath(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	ctx := context.Background()

	suffix := fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	domainName := "ldapbind-" + suffix + ".internal"
	email := "bindtest-" + suffix + "@" + domainName
	const password = "correct-horse-battery-staple-1!"

	hash, err := pwhash.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	var domainID, userID int64
	if err := pool.QueryRow(ctx, `INSERT INTO domains (name) VALUES ($1) RETURNING id`, domainName).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID) }) //nolint:errcheck

	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		"bindtest-"+suffix, email, "Bind Test", domainID, hash,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	createLDAPTestPrimaryMailbox(t, pool, ctx, userID, domainID, email)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID) }) //nolint:errcheck

	certFile, keyFile := genSelfSignedCert(t)
	port := freeTCPPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	srv := NewServer(pool, addr, domainName, logger, nil)
	if err := srv.SetTLS(certFile, keyFile); err != nil {
		t.Fatalf("SetTLS: %v", err)
	}

	srvCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(srvCtx) }()

	// Poll until the listener accepts TCP connections; ListenAndServe's
	// net.Listen happens synchronously inside the goroutine above, so the
	// port isn't guaranteed bound the instant Start() is called.
	deadline := time.Now().Add(5 * time.Second)
	var conn *ldapclient.Conn
	for {
		conn, err = ldapclient.DialURL(fmt.Sprintf("ldaps://%s", addr),
			ldapclient.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})) //nolint:gosec // test-only, self-signed
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never accepted connections: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer conn.Close()

	// Wrong password against a real DN → invalidCredentials.
	if err := conn.Bind(email, "wrong-password"); err == nil {
		t.Error("wrong password: bind succeeded, want error")
	} else if !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultInvalidCredentials) {
		t.Errorf("wrong password: got %v, want LDAPResultInvalidCredentials", err)
	}

	// Unknown DN → also invalidCredentials (handleBind does not distinguish
	// "no such user" from "wrong password").
	unknownEmail := "no-such-user-" + suffix + "@" + domainName
	if err := conn.Bind(unknownEmail, password); err == nil {
		t.Error("unknown DN: bind succeeded, want error")
	} else if !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultInvalidCredentials) {
		t.Errorf("unknown DN: got %v, want LDAPResultInvalidCredentials", err)
	}

	// Correct credential → success.
	if err := conn.Bind(email, password); err != nil {
		t.Errorf("valid credential: bind failed: %v", err)
	}

	cancel()
	<-errCh
}

// TestHandleSearch_RequiresBind is the behavioral regression for the GAL
// directory-disclosure fix (A1): a client that sends a Search as its first PDU
// — never binding — must be rejected with insufficientAccessRights, not handed
// the directory. A seeded user is present so that if the bound-state gate were
// broken (e.g. isBound wrongly returning true), the unbound search WOULD return
// an entry and this test would fail. Mutation-checked: forcing isBound→true
// makes the unbound Search return the seeded user and this test red.
func TestHandleSearch_RequiresBind(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	ctx := context.Background()

	suffix := fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	domainName := "ldapsearch-" + suffix + ".internal"
	email := "searchtest-" + suffix + "@" + domainName
	const password = "correct-horse-battery-staple-1!"
	hash, err := pwhash.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	var domainID, userID int64
	if err := pool.QueryRow(ctx, `INSERT INTO domains (name) VALUES ($1) RETURNING id`, domainName).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID) }) //nolint:errcheck
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		"searchtest-"+suffix, email, "Search Test", domainID, hash,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	createLDAPTestPrimaryMailbox(t, pool, ctx, userID, domainID, email)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID) }) //nolint:errcheck

	certFile, keyFile := genSelfSignedCert(t)
	port := freeTCPPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	srv := NewServer(pool, addr, domainName, logger, nil)
	if err := srv.SetTLS(certFile, keyFile); err != nil {
		t.Fatalf("SetTLS: %v", err)
	}
	srvCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(srvCtx) }()

	deadline := time.Now().Add(5 * time.Second)
	var conn *ldapclient.Conn
	for {
		conn, err = ldapclient.DialURL(fmt.Sprintf("ldaps://%s", addr),
			ldapclient.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})) //nolint:gosec // test-only
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never accepted connections: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer conn.Close()

	// dc-style base DN from the domain (dc=ldapsearch-<suffix>,dc=internal).
	base := "ou=People"
	for _, part := range strings.Split(domainName, ".") {
		base += ",dc=" + part
	}

	// UNBOUND search — the vulnerability. Must be rejected, must return no entries.
	req := ldapclient.NewSearchRequest(base, ldapclient.ScopeWholeSubtree,
		ldapclient.NeverDerefAliases, 0, 0, false, "(objectClass=*)",
		[]string{"mail", "cn"}, nil)
	res, searchErr := conn.Search(req)
	if searchErr == nil {
		t.Fatalf("unbound search succeeded with %d entries, want insufficientAccessRights (GAL disclosure)", len(res.Entries))
	}
	if !ldapclient.IsErrorWithCode(searchErr, ldapclient.LDAPResultInsufficientAccessRights) {
		t.Errorf("unbound search: got %v, want LDAPResultInsufficientAccessRights", searchErr)
	}

	// Positive control: after a valid bind the same search is allowed (returns
	// without the access-rights rejection — proves the gate is the discriminator,
	// not a blanket denial).
	if err := conn.Bind(email, password); err != nil {
		t.Fatalf("valid bind failed: %v", err)
	}
	if _, err := conn.Search(req); ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultInsufficientAccessRights) {
		t.Errorf("bound search still rejected with insufficientAccessRights: %v", err)
	}

	cancel()
	<-errCh
}
