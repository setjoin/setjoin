package smtp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/pgxutil"

	"setjoin.com/mailserver/internal/smime"
)

// testLogger creates a logger for tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// genSignerCertPEM builds a self-signed RSA cert for a signer and returns its PEM.
// (The harvest hook stores whatever leaf PEM the verdict carried; it does not
// re-verify the chain, so a self-signed cert is fine for the storage test.)
func genSignerCertPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// genMultiSANCertPEM builds a self-signed RSA cert carrying multiple rfc822Name SANs
// (the leaf's CommonName is the FIRST SAN, matching how a real signer cert is shaped).
// Used to prove the harvest hook files under the validated From, not SAN[0].
func genMultiSANCertPEM(t *testing.T, emails []string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	cn := ""
	if len(emails) > 0 {
		cn = emails[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: cn},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		EmailAddresses: emails,
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// seedHarvestRecipient inserts a domain, a mailbox, an alias for the recipient
// address (resolveMailboxID joins aliases), and the receiving user. Returns the
// recipient address and the receiving user's id. Cleaned up via t.Cleanup.
func seedHarvestRecipient(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (rcpt string, ownerUserID int64) {
	t.Helper()

	uniq := big.NewInt(time.Now().UnixNano()).String()
	domain := "harvest-" + uniq + ".example"
	rcpt = "receiver@" + domain

	var domainID, mailboxID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1) RETURNING id`, domain).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	// Create the receiving user first, then its PRIMARY mailbox bound to that user in
	// one insert — the mailbox primary-mailbox trigger rejects binding a user_id whose
	// user has no primary mailbox, so we cannot bind via a later UPDATE.
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name)
		 VALUES ($1, $2, $3, 'Harvest Receiver') RETURNING id`,
		"harvest-recv-"+uniq, domainID, rcpt).Scan(&ownerUserID); err != nil {
		t.Fatalf("insert receiving user: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, is_primary)
		 VALUES ($1, $2, $3, 'Harvest Receiver', TRUE) RETURNING id`,
		ownerUserID, domainID, rcpt).Scan(&mailboxID); err != nil {
		t.Fatalf("insert mailbox: %v", err)
	}
	// resolveMailboxID joins aliases.email = lower(rcpt) → mailboxes.id (enabled).
	if _, err := pool.Exec(ctx,
		`INSERT INTO aliases (mailbox_id, email, domain_id, is_primary)
		 VALUES ($1, $2, $3, TRUE)`,
		mailboxID, rcpt, domainID); err != nil {
		t.Fatalf("insert alias: %v", err)
	}

	t.Cleanup(func() {
		// Delete in FK-safe order so both the primary-mailbox trigger and the
		// mailboxes_shared_not_primary check constraint are satisfied.
		//
		// Two constraints block a naive delete:
		//   (a) trg_mailbox_primary_enforce (AFTER DELETE on mailboxes): fires when
		//       OLD.user_id IS NOT NULL AND OLD.is_primary — raises BZ013 if the user
		//       would be left without a primary mailbox.
		//   (b) mailboxes_shared_not_primary CHECK (is_primary = false OR user_id IS NOT
		//       NULL): the FK ON DELETE SET NULL cascade (deleting the user) tries to
		//       set user_id = NULL while is_primary is still TRUE → violates (b).
		//
		// Solution: clear both fields atomically with a single UPDATE before touching
		// users or mailboxes.  After the UPDATE:
		//   • trigger sees NEW.user_id = NULL → skips the no-primary check → passes.
		//   • check constraint sees is_primary = FALSE → passes.
		// Then users and mailboxes can be deleted in either order.
		_, _ = pool.Exec(ctx, `DELETE FROM recipient_smime_certs WHERE owner_user_id = $1`, ownerUserID)
		_, _ = pool.Exec(ctx, `DELETE FROM aliases WHERE mailbox_id = $1`, mailboxID)
		_, _ = pool.Exec(ctx, `UPDATE mailboxes SET user_id = NULL, is_primary = FALSE WHERE id = $1`, mailboxID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, ownerUserID)
		_, _ = pool.Exec(ctx, `DELETE FROM mailboxes WHERE id = $1`, mailboxID)
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, domainID)
	})
	return rcpt, ownerUserID
}

func countHarvested(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ownerUserID int64) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM recipient_smime_certs WHERE owner_user_id = $1`, ownerUserID).Scan(&n); err != nil {
		t.Fatalf("count harvested rows: %v", err)
	}
	return n
}

// TestHarvestSignerCert exercises the inbound harvest hook end-to-end against the DB.
//   - a valid verdict with a leaf PEM harvests exactly one row (lower-cased signer
//     email, source='harvested', fingerprint == smime.Fingerprint(PEM), metadata set);
//   - a second identical valid verdict upserts (still one row, last_seen bumped);
//   - an untrusted verdict (even with a leaf PEM) harvests nothing;
//   - a valid verdict with an EMPTY leaf PEM harvests nothing (no panic);
//   - an unresolvable recipient harvests nothing (no panic).
func TestHarvestSignerCert(t *testing.T) {
	skipWithoutDB(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("TEST_DB_DSN"))
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(pool.Close) // LIFO: runs after fixture cleanup, so cleanup Execs hit a live pool.

	rcpt, ownerUserID := seedHarvestRecipient(t, ctx, pool)

	srv := NewInboundServer(pgxutil.WorkerPool{Pool: pool}, ":0", testLogger(), nil, nil)
	c := &inConnState{srv: srv}

	signerEmail := "Signer@EXAMPLE.com"
	leafPEM := genSignerCertPEM(t, signerEmail)
	wantFP, _, _, _, err := smime.Fingerprint(leafPEM)
	if err != nil {
		t.Fatalf("fingerprint test cert: %v", err)
	}

	// 1. valid verdict → exactly one harvested row with the expected shape.
	// From == signerEmail here, so the harvested email is its lower-cased form.
	c.harvestSignerCert(ctx, rcpt, signerEmail, &smime.VerifyResult{
		Status:      smime.StatusValid,
		SignerEmail: signerEmail,
		LeafPEM:     leafPEM,
	})
	if n := countHarvested(t, ctx, pool, ownerUserID); n != 1 {
		t.Fatalf("after valid harvest: want 1 row, got %d", n)
	}
	var gotEmail, gotSource, gotFP string
	var firstSeen, lastSeen time.Time
	var notBefore, notAfter *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT email, source, fingerprint, not_before, not_after, first_seen, last_seen
		   FROM recipient_smime_certs WHERE owner_user_id = $1`, ownerUserID,
	).Scan(&gotEmail, &gotSource, &gotFP, &notBefore, &notAfter, &firstSeen, &lastSeen); err != nil {
		t.Fatalf("read harvested row: %v", err)
	}
	if gotEmail != "signer@example.com" {
		t.Errorf("email: want lower-cased %q, got %q", "signer@example.com", gotEmail)
	}
	if gotSource != "harvested" {
		t.Errorf("source: want %q, got %q", "harvested", gotSource)
	}
	if gotFP != wantFP {
		t.Errorf("fingerprint: want %q, got %q", wantFP, gotFP)
	}
	if notBefore == nil || notAfter == nil {
		t.Errorf("not_before/not_after must be populated, got nb=%v na=%v", notBefore, notAfter)
	}

	// 2. second identical valid verdict → upsert, still one row, last_seen >= first.
	c.harvestSignerCert(ctx, rcpt, signerEmail, &smime.VerifyResult{
		Status:      smime.StatusValid,
		SignerEmail: signerEmail,
		LeafPEM:     leafPEM,
	})
	if n := countHarvested(t, ctx, pool, ownerUserID); n != 1 {
		t.Fatalf("after re-harvest: want still 1 row (upsert), got %d", n)
	}
	var firstSeen2, lastSeen2 time.Time
	if err := pool.QueryRow(ctx,
		`SELECT first_seen, last_seen FROM recipient_smime_certs WHERE owner_user_id = $1`, ownerUserID,
	).Scan(&firstSeen2, &lastSeen2); err != nil {
		t.Fatalf("read re-harvested row: %v", err)
	}
	if !firstSeen2.Equal(firstSeen) {
		t.Errorf("first_seen changed on upsert: %v -> %v", firstSeen, firstSeen2)
	}
	if lastSeen2.Before(lastSeen) {
		t.Errorf("last_seen went backwards on upsert: %v -> %v", lastSeen, lastSeen2)
	}

	// 3. untrusted verdict (even with a leaf PEM) harvests nothing new.
	c.harvestSignerCert(ctx, rcpt, "untrusted@example.com", &smime.VerifyResult{
		Status:      smime.StatusUntrusted,
		SignerEmail: "untrusted@example.com",
		LeafPEM:     genSignerCertPEM(t, "untrusted@example.com"),
	})
	if n := countHarvested(t, ctx, pool, ownerUserID); n != 1 {
		t.Fatalf("untrusted must NOT harvest: want 1 row, got %d", n)
	}

	// 4. valid verdict but empty leaf PEM → nothing to store, no panic.
	c.harvestSignerCert(ctx, rcpt, "empty@example.com", &smime.VerifyResult{
		Status:      smime.StatusValid,
		SignerEmail: "empty@example.com",
		LeafPEM:     "",
	})
	if n := countHarvested(t, ctx, pool, ownerUserID); n != 1 {
		t.Fatalf("empty LeafPEM must NOT harvest: want 1 row, got %d", n)
	}

	// 5. unresolvable recipient → nothing, no panic (graceful best-effort).
	c.harvestSignerCert(ctx, "nobody@unresolvable.invalid", signerEmail, &smime.VerifyResult{
		Status:      smime.StatusValid,
		SignerEmail: signerEmail,
		LeafPEM:     leafPEM,
	})
	if n := countHarvested(t, ctx, pool, ownerUserID); n != 1 {
		t.Fatalf("unresolvable rcpt must NOT harvest into our owner: want 1 row, got %d", n)
	}
}

// TestHarvestMultiSANFilesUnderFrom is the P2 review regression: for a MULTI-SAN cert a
// 'valid' verdict only guarantees SOME SAN matched the From — not that the From is the
// FIRST SAN (which is what res.SignerEmail carries). The harvested row's `email` must be
// the SAN-MATCHED From (alice@corp.example), NOT the leaf's first SAN (other@corp.example).
// Filing under the first SAN would store the cert under an address the message never claimed.
func TestHarvestMultiSANFilesUnderFrom(t *testing.T) {
	skipWithoutDB(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("TEST_DB_DSN"))
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(pool.Close)

	rcpt, ownerUserID := seedHarvestRecipient(t, ctx, pool)

	srv := NewInboundServer(pgxutil.WorkerPool{Pool: pool}, ":0", testLogger(), nil, nil)
	c := &inConnState{srv: srv}

	// Multi-SAN cert modelled on TestVerifyDetachedMultiSAN: SAN[0] is other@corp.example,
	// the second SAN (alice@corp.example) is the From the message was validated against.
	const sanFirst = "other@corp.example"
	const fromMatched = "alice@corp.example"
	leafPEM := genMultiSANCertPEM(t, []string{sanFirst, fromMatched})

	// res.SignerEmail = certEmail(leaf) = the FIRST SAN — the buggy filing address.
	c.harvestSignerCert(ctx, rcpt, fromMatched, &smime.VerifyResult{
		Status:      smime.StatusValid,
		SignerEmail: sanFirst,
		LeafPEM:     leafPEM,
	})

	if n := countHarvested(t, ctx, pool, ownerUserID); n != 1 {
		t.Fatalf("multi-SAN valid harvest: want 1 row, got %d", n)
	}
	var gotEmail string
	if err := pool.QueryRow(ctx,
		`SELECT email FROM recipient_smime_certs WHERE owner_user_id = $1`, ownerUserID,
	).Scan(&gotEmail); err != nil {
		t.Fatalf("read harvested row: %v", err)
	}
	if gotEmail != fromMatched {
		t.Errorf("multi-SAN harvest filed under wrong address: want From %q, got %q", fromMatched, gotEmail)
	}
	if gotEmail == sanFirst {
		t.Errorf("multi-SAN harvest filed under SAN[0] %q (the bug) instead of the From %q", sanFirst, fromMatched)
	}
}
