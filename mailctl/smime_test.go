package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestParseSmimeManifest(t *testing.T) {
	in := "email,cert_path,key_path,label\n" +
		"# a comment line\n" +
		"\n" +
		"  alice@x.test , /c/a.pem , /k/a.pem , signing \n" +
		"bob@x.test,/c/b.pem,/k/b.pem\n"
	rows, err := parseSmimeManifest(strings.NewReader(in))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 rows (header/comment/blank skipped), got %d: %+v", len(rows), rows)
	}
	if rows[0] != (smimeImportRow{email: "alice@x.test", certPath: "/c/a.pem", keyPath: "/k/a.pem", label: "signing"}) {
		t.Errorf("row0 mismatch (trim + 4-col label): %+v", rows[0])
	}
	if rows[1].label != "imported" {
		t.Errorf("row1 label should default to 'imported', got %q", rows[1].label)
	}
}

func TestParseSmimeManifest_TooFewColumns(t *testing.T) {
	if _, err := parseSmimeManifest(strings.NewReader("alice@x.test,/c/a.pem\n")); err == nil {
		t.Error("want error when a row has fewer than 3 columns")
	}
}

func TestParseSmimeManifest_EmptyRequiredField(t *testing.T) {
	if _, err := parseSmimeManifest(strings.NewReader("alice@x.test,,/k/a.pem\n")); err == nil {
		t.Error("want error when cert_path is empty")
	}
}

func TestValidateKeyPEM(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	good := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err := validateKeyPEM(good); err != nil {
		t.Errorf("valid PKCS#8 key rejected: %v", err)
	}
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := validateKeyPEM(pkcs1); err != nil {
		t.Errorf("valid PKCS#1 key rejected: %v", err)
	}
	if err := validateKeyPEM([]byte("not pem")); err == nil {
		t.Error("non-PEM accepted as key")
	}
	// A certificate is not a private key.
	certDER, key2 := selfSignedCertDER(t, "x@y.test")
	_ = key2
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := validateKeyPEM(certPEM); err == nil {
		t.Error("a certificate PEM was accepted as a private key")
	}
}

func TestParseCertPEM_And_CertMatchesEmail(t *testing.T) {
	der, _ := selfSignedCertDER(t, "alice@corp.test")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if !certMatchesEmail(cert, "ALICE@corp.test") {
		t.Error("SAN match (case-insensitive) failed")
	}
	if certMatchesEmail(cert, "bob@corp.test") {
		t.Error("non-matching email reported as match")
	}
	if _, err := parseCertPEM([]byte("nope")); err == nil {
		t.Error("non-PEM accepted as cert")
	}
}

// TestSmimeImport_DryRunFlagsAnyOrder guards the arg split: --dry-run must work
// whether it appears before OR after the manifest path, and dry-run must never
// open the DB (so it runs with an empty cmdCtx).
func TestSmimeImport_DryRunFlagsAnyOrder(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeCertKeyFiles(t, dir, "x@dry.test")
	manifest := filepath.Join(dir, "m.csv")
	if err := os.WriteFile(manifest,
		[]byte("email,cert_path,key_path\nx@dry.test,"+certPath+","+keyPath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &cmdCtx{} // dry-run must not call openDB
	for _, args := range [][]string{{manifest, "--dry-run"}, {"--dry-run", manifest}} {
		if err := smimeImport(c, args); err != nil {
			t.Errorf("dry-run %v returned error: %v", args, err)
		}
	}
}

// selfSignedCertDER mints an RSA self-signed cert with an rfc822 SAN of email.
func selfSignedCertDER(t *testing.T, email string) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: email},
		EmailAddresses: []string{email},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

// writeCertKeyFiles writes a matching cert.pem + key.pem (PKCS#8) into dir.
func writeCertKeyFiles(t *testing.T, dir, email string) (certPath, keyPath string) {
	t.Helper()
	der, key := selfSignedCertDER(t, email)
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// TestSmimeImportOne_DBRoundTrip is the load-bearing integration: an imported key
// must be stored pgp_sym_encrypt'd AND decrypt back to the original with the same
// DB_ENCRYPTION_KEY value (so the gateway's current_setting decrypt works), and
// the first cert must become is_default.
func TestSmimeImportOne_DBRoundTrip(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("DB_DSN")
	}
	if dsn == "" {
		t.Skip("TEST_DB_DSN/DB_DSN not set; skipping DB-gated import test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// Register Close FIRST so it runs LAST (t.Cleanup is LIFO) — after the row
	// cleanup below; a deferred Close would run before t.Cleanup and leave the
	// cleanup hitting a closed pool (silent no-op → leaked rows on re-run).
	t.Cleanup(pool.Close)

	// Idempotent teardown, also run up-front so a prior aborted run can't collide.
	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM user_smime_certs WHERE user_id IN (SELECT id FROM users WHERE email = 'mctl@mctlsmime.test')`)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE email = 'mctl@mctlsmime.test'`)
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE name = 'mctlsmime.test'`)
	}
	cleanup()
	t.Cleanup(cleanup)

	var domID, userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ('mctlsmime.test', TRUE) RETURNING id`).Scan(&domID); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ('mctlsmimeu', $1, 'mctl@mctlsmime.test', 'M', 'x') RETURNING id`, domID).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	dir := t.TempDir()
	certPath, keyPath := writeCertKeyFiles(t, dir, "mctl@mctlsmime.test")
	keyPEM, _ := os.ReadFile(keyPath)
	const encKey = "mailctl-import-test-key-0123456789"

	row := smimeImportRow{email: "mctl@mctlsmime.test", certPath: certPath, keyPath: keyPath, label: "imported"}
	if ok := smimeImportOne(ctx, pool, encKey, row, 1, false, false); !ok {
		t.Fatal("smimeImportOne returned false (skip) for a valid row")
	}

	var decKey []byte
	var isDefault bool
	if err := pool.QueryRow(ctx,
		`SELECT pgp_sym_decrypt(private_key_enc::bytea, $2), is_default
		   FROM user_smime_certs WHERE user_id = $1 AND label = 'imported'`,
		userID, encKey).Scan(&decKey, &isDefault); err != nil {
		t.Fatalf("read back imported cert: %v", err)
	}
	if string(decKey) != string(keyPEM) {
		t.Error("private key did not round-trip through pgp_sym_encrypt/decrypt")
	}
	if !isDefault {
		t.Error("first imported cert should be is_default=true")
	}
}
