package jmap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/smime"
	"setjoin.com/shared/testsupport"
)

func mustGenDecryptKeypair(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "reader-p5@test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func pemCert(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func pemRSAKey(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

// testEncryptionKey is the app.encryption_key GUC value used for the DB-gated
// decrypt-on-read tests; pgp_sym_encrypt/decrypt are symmetric so any constant works.
const testEncryptionKey = "decrypt-on-read-test-key"

// newDecryptTestPool dials mailserver_test_smime_p5 via TEST_DB_DSN and carries
// the app.encryption_key GUC on every connection (the AfterConnect contract
// loadDecryptKeys relies on). Skips when TEST_DB_DSN is unset.
func newDecryptTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping database-dependent decrypt-on-read test")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SELECT set_config('app.encryption_key', $1, false)", testEncryptionKey)
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestLoadDecryptKeys_DBRoundTrip seeds a user_smime_certs row (key encrypted
// under app.encryption_key) and proves loadDecryptKeys reads + decrypts it into a
// usable DecryptKey whose serial matches a RecipientInfo our smime.Encrypt emits —
// i.e. the keystore→DecryptMulti half of decrypt-on-read works against real
// Postgres. A non-keyholder user gets no keys → no_key state. Rolls back.
func TestLoadDecryptKeys_DBRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: skipping DB-backed decrypt-on-read round-trip")
	}
	pool := newDecryptTestPool(t)
	ctx := context.Background()

	// Build a reader cert+key; encrypt a known plaintext to it.
	cert, key := mustGenDecryptKeypair(t)
	certPEM := pemCert(t, cert)
	keyPEM := pemRSAKey(t, key)
	plaintext := []byte("decrypt-on-read DB round-trip body\r\n")
	wire, err := smime.Encrypt(plaintext, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Seed a user + keystore row inside a tx we roll back (zero residue).
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var domainID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ('p5-decrypt.test', TRUE) RETURNING id`,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	var userID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ('reader-p5', $1, 'reader-p5@p5-decrypt.test', 'Reader P5', 'x') RETURNING id`,
		domainID,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO user_smime_certs (user_id, label, cert_pem, private_key_enc, is_default)
		 VALUES ($1, 'p5', $2, pgp_sym_encrypt($3, current_setting('app.encryption_key')), true)`,
		userID, certPEM, keyPEM,
	); err != nil {
		t.Fatalf("insert cert: %v", err)
	}

	// loadDecryptKeys uses h.pool, which won't see the uncommitted row; assert the
	// keystore read+decrypt directly against the tx (the exact query loadDecryptKeys
	// runs), then DecryptMulti the wire blob with the recovered key.
	var gotCertPEM, gotKeyPEM string
	if err := tx.QueryRow(ctx,
		`SELECT cert_pem, pgp_sym_decrypt(private_key_enc::bytea, current_setting('app.encryption_key'))
		 FROM user_smime_certs WHERE user_id = $1 AND private_key_enc IS NOT NULL`,
		userID,
	).Scan(&gotCertPEM, &gotKeyPEM); err != nil {
		t.Fatalf("keystore read-back: %v", err)
	}
	dk, ok := parseDecryptCandidate(gotCertPEM, gotKeyPEM)
	if !ok {
		t.Fatal("seeded keystore row must parse into a DecryptKey")
	}
	der, err := smime.DecodeEnvelopedDER(wire)
	if err != nil {
		t.Fatalf("DecodeEnvelopedDER: %v", err)
	}
	got, err := smime.DecryptMulti(der, []smime.DecryptKey{dk})
	if err != nil {
		t.Fatalf("DecryptMulti with keystore-decrypted key: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
	}

	// Non-keyholder: a fresh user with no keystore row yields zero keys → no_key.
	var otherID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ('nokey-p5', $1, 'nokey-p5@p5-decrypt.test', 'No Key', 'x') RETURNING id`,
		domainID,
	).Scan(&otherID); err != nil {
		t.Fatalf("insert other user: %v", err)
	}
	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM user_smime_certs WHERE user_id = $1 AND private_key_enc IS NOT NULL`,
		otherID,
	).Scan(&n); err != nil {
		t.Fatalf("count other keys: %v", err)
	}
	if n != 0 {
		t.Errorf("non-keyholder must have 0 keystore keys, got %d", n)
	}
}

// gucGuardFixedKey is a literal (not GUC-derived) pgcrypto key used to seed a
// private_key_enc row independent of any pool's app.encryption_key setting —
// so the seed step never depends on the very GUC these tests are attacking.
const gucGuardFixedKey = "guc-guard-fixed-key-32-chars-xx"

// seedGUCGuardCert inserts a committed (not rolled back) user + user_smime_certs
// row whose private_key_enc is pgp_sym_encrypt'd under gucGuardFixedKey via the
// literal two-arg form, then registers cleanup. Returns the seeded userID.
func seedGUCGuardCert(t *testing.T, seedPool *pgxpool.Pool, keyPEM string) int64 {
	t.Helper()
	ctx := context.Background()

	var domainID int64
	if err := seedPool.QueryRow(ctx, `SELECT id FROM domains WHERE name = 'p5-decrypt-guc.test'`).Scan(&domainID); err != nil {
		if err := seedPool.QueryRow(ctx,
			`INSERT INTO domains (name, is_local) VALUES ('p5-decrypt-guc.test', TRUE) RETURNING id`).Scan(&domainID); err != nil {
			t.Fatalf("ensure guc-guard test domain: %v", err)
		}
	}
	uniq := time.Now().Format("150405.000000000")
	username := "guc-guard-" + uniq
	email := username + "@p5-decrypt-guc.test"
	var userID int64
	if err := seedPool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ($1, $2, $3, 'GUC Guard', 'x') RETURNING id`,
		username, domainID, email,
	).Scan(&userID); err != nil {
		t.Fatalf("insert guc-guard user: %v", err)
	}
	t.Cleanup(func() {
		seedPool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})
	if _, err := seedPool.Exec(ctx,
		`INSERT INTO user_smime_certs (user_id, label, cert_pem, private_key_enc, is_default)
		 VALUES ($1, 'guc-guard', 'unused-cert-pem', pgp_sym_encrypt($2, $3), true)`,
		userID, keyPEM, gucGuardFixedKey,
	); err != nil {
		t.Fatalf("seed guc-guard cert row: %v", err)
	}
	return userID
}

// TestLoadDecryptKeys_GUCMissing_FailsClosed proves the private_key_enc family
// fails closed — never returns a usable key, never silently succeeds — when the
// AfterConnect hook that sets app.encryption_key is absent (a misconfigured or
// bypassed pool). Exercises the REAL loadDecryptKeys code path, not a stand-in.
func TestLoadDecryptKeys_GUCMissing_FailsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: skipping DB-backed GUC regression test")
	}
	_, key := mustGenDecryptKeypair(t)
	keyPEM := pemRSAKey(t, key)

	seedPool := testsupport.OpenTestPoolWithGUC(t, gucGuardFixedKey)
	userID := seedGUCGuardCert(t, seedPool, keyPEM)

	h := &JMAPHandler{pool: testsupport.OpenTestPoolWithGUC(t, "")} // GUC never set
	keys, err := h.loadDecryptKeys(context.Background(), userID)
	if err == nil {
		t.Fatal("loadDecryptKeys must error when app.encryption_key GUC is unset, not silently succeed")
	}
	if len(keys) != 0 {
		t.Fatalf("loadDecryptKeys must return zero keys when the GUC is unset, got %d", len(keys))
	}
}

// TestLoadDecryptKeys_WrongGUC_FailsClosed proves the same family fails loudly
// (an error, not a garbage-plaintext "success") when app.encryption_key is set
// to the WRONG value. pgcrypto's PGP integrity check is what makes this true;
// this test is the proof it actually holds for our exact query shape.
func TestLoadDecryptKeys_WrongGUC_FailsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: skipping DB-backed GUC regression test")
	}
	_, key := mustGenDecryptKeypair(t)
	keyPEM := pemRSAKey(t, key)

	seedPool := testsupport.OpenTestPoolWithGUC(t, gucGuardFixedKey)
	userID := seedGUCGuardCert(t, seedPool, keyPEM)

	h := &JMAPHandler{pool: testsupport.OpenTestPoolWithGUC(t, "definitely-the-wrong-key-xxxxx")}
	keys, err := h.loadDecryptKeys(context.Background(), userID)
	if err == nil {
		t.Fatal("loadDecryptKeys must error when app.encryption_key GUC is wrong, not silently succeed")
	}
	if len(keys) != 0 {
		t.Fatalf("loadDecryptKeys must return zero keys when the GUC is wrong, got %d", len(keys))
	}
}
