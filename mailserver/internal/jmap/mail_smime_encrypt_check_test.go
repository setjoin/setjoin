package jmap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/smime"
	"setjoin.com/shared/pgxutil"
)

// mail_smime_encrypt_check_test.go — DB-gated integration for the submission-time
// fail-closed cert-availability CHECK. The pure decision tree (drop / marker /
// addresses) is unit-tested in mail_encrypt_test.go with a stubbed seam; here we
// drive the REAL DB resolution that the up-front check relies on (poolEncryptOps
// → smime.ResolveRecipientCert) against mailserver_test_smime_p4, proving:
//   - a recipient WITH a seeded encryption-capable cert resolves, and
//   - a recipient with NO cert fails CLOSED (ok=false) — which is exactly what
//     drives ReasonEncryptNoCert + names the address in the up-front check.
//
// All seeding runs inside a tx that is rolled back at test end (re-run safe).

// encryptCheckTx opens a rolled-back tx on a TEST_DB_DSN pool; skips when unset.
func encryptCheckTx(t *testing.T) (context.Context, pgx.Tx, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping database-dependent test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	return ctx, tx, pool
}

// genCapableCertPEM mints a self-signed, currently-valid, RSA, encryption-capable
// (keyEncipherment) cert bound to email, returning its PEM. Mirrors the resolution
// predicate's accept case (RSA + keyEncipherment + now∈[NotBefore,NotAfter]).
func genCapableCertPEM(t *testing.T, email string) string {
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
		KeyUsage:       x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// poolOnlyHandler builds a JMAPHandler with just the pool wired (logger to
// io.Discard) so poolEncryptOps.ResolveEncryptCert runs the real DB query. The
// tx is passed where a Querier is needed directly; the handler's pool is used by
// poolEncryptOps.
func poolOnlyHandler(t *testing.T, pool *pgxpool.Pool) *JMAPHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, logger)
	return h
}

// seedRecipientCert inserts a harvested recipient cert owned by ownerUserID for
// email (R1: owned by the sender). Returns the PEM (for assertions if needed).
func seedRecipientCert(t *testing.T, ctx context.Context, tx pgx.Tx, ownerUserID int64, email, certPEM string) {
	t.Helper()
	sum := sha256.Sum256([]byte(certPEM)) // any stable fp value satisfies the dedup key
	fp := hex.EncodeToString(sum[:])
	if _, err := tx.Exec(ctx,
		`INSERT INTO recipient_smime_certs (owner_user_id, email, cert_pem, fingerprint, source, last_seen)
		 VALUES ($1,$2,$3,$4,'harvested', now())`,
		ownerUserID, email, certPEM, fp); err != nil {
		t.Fatalf("seed recipient cert %s: %v", email, err)
	}
}

// TestPoolEncryptOps_ResolveSeededRecipient proves the real DB resolution the
// up-front check depends on: a seeded encryption-capable recipient cert resolves
// (ok=true). The tx is wired as the handler pool's Querier via a shim handler that
// runs ResolveRecipientCert directly over the tx (the tx satisfies smime.Querier),
// so this needs NO minio and stays inside the rolled-back tx.
func TestPoolEncryptOps_ResolveSeededRecipient(t *testing.T) {
	ctx, tx, _ := encryptCheckTx(t)

	var domID, senderID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ('encchk.test', TRUE) RETURNING id`).Scan(&domID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ('encchkseed', $1, 'encchkseed@encchk.test', 'encchkseed', 'x') RETURNING id`,
		domID).Scan(&senderID); err != nil {
		t.Fatalf("insert sender: %v", err)
	}

	certPEM := genCapableCertPEM(t, "haveit@ext.test")
	seedRecipientCert(t, ctx, tx, senderID, "haveit@ext.test", certPEM)

	// The tx satisfies smime.Querier — drive the resolution the up-front check uses.
	cert, ok := smime.ResolveRecipientCert(ctx, tx, senderID, "HaveIt@Ext.Test", nil)
	if !ok || cert == nil {
		t.Fatalf("seeded encryption-capable recipient must resolve, got ok=%v", ok)
	}
	if !smime.CertMatchesEmail(cert, "haveit@ext.test") {
		t.Errorf("resolved cert does not bind haveit@ext.test")
	}
}

// TestPoolEncryptOps_MissingRecipientFailsClosed proves a recipient with NO cert
// resolves to ok=false (fail-closed) — the condition the up-front check turns into
// ReasonEncryptNoCert + a named address. No seeding for the address under test.
func TestPoolEncryptOps_MissingRecipientFailsClosed(t *testing.T) {
	ctx, tx, _ := encryptCheckTx(t)

	var domID, senderID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ('encchk2.test', TRUE) RETURNING id`).Scan(&domID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ('encchkseed2', $1, 'encchkseed2@encchk2.test', 'encchkseed2', 'x') RETURNING id`,
		domID).Scan(&senderID); err != nil {
		t.Fatalf("insert sender: %v", err)
	}

	if _, ok := smime.ResolveRecipientCert(ctx, tx, senderID, "no-cert@missing.test", nil); ok {
		t.Error("a recipient with no cert must fail closed (ok=false)")
	}
}

// TestPoolEncryptOps_RealPoolResolveEncryptCert exercises the production seam
// (poolEncryptOps over a real pgxpool, not the tx) end-to-end for the resolve
// path: it seeds via a committed-then-cleaned row pattern is avoided — instead we
// verify the missing-recipient fail-closed answer (no seed needed, no residue).
func TestPoolEncryptOps_RealPoolResolveEncryptCert(t *testing.T) {
	ctx, _, pool := encryptCheckTx(t)
	h := poolOnlyHandler(t, pool)
	ops := &poolEncryptOps{h: h}

	// A clearly-absent recipient under a never-seeded sender → fail closed.
	if _, ok := ops.ResolveEncryptCert(ctx, 99999999, "definitely-absent@nowhere.test"); ok {
		t.Error("poolEncryptOps.ResolveEncryptCert must fail closed for an absent recipient")
	}
}
