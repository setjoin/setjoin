package smtp

import (
	"context"
	"crypto/x509"
	"os"
	"testing"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/pgxutil"

	"setjoin.com/mailserver/internal/smime"
)

// TestSMIMERevocationGate_AdminBlocklistRemovesBadgeExemptionAndHarvest is the
// inbound-path acceptance arm of the settled revocation policy: with the
// DB-backed admin blocklist wired (the production options shape — no CRL
// source is configured, so CRL evidence is unavailable and fail-open), a
// blocklist entry for the signer leaf must have the same effect as fresh-CRL
// revocation:
//
//   - before the entry: the message grades StatusValid (badge stays, recorded
//     revocation-unknown), the body-mutator exemption applies, and the signer
//     cert harvests;
//   - after the entry: the verdict downgrades to StatusUntrusted with
//     Revocation=revoked, bodyMutatorsApply runs the mutators (no exemption),
//     and the harvest hook stores nothing.
func TestSMIMERevocationGate_AdminBlocklistRemovesBadgeExemptionAndHarvest(t *testing.T) {
	skipWithoutDB(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("TEST_DB_DSN"))
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(pool.Close) // registered FIRST so fixture cleanups run on a live pool

	rcpt, ownerUserID := seedHarvestRecipient(t, ctx, pool)

	// Signer fixture: real CA + leaf + a real detached multipart/signed message.
	const signerEmail = "revoked-signer@corp.example"
	root, leaf, leafKey := testSMIMECA(t, []string{signerEmail})
	contentPart := "Content-Type: text/plain\r\n\r\nSigned body\r\n"
	sigDER, err := cms.SignDetached([]byte(contentPart), []*x509.Certificate{leaf}, leafKey)
	if err != nil {
		t.Fatalf("sign fixture: %v", err)
	}
	msg := buildMultipartSigned(t, contentPart, sigDER, "revbnd")

	roots := x509.NewCertPool()
	roots.AddCert(root)

	// The production options shape: staleness ceiling + DB-backed blocklist,
	// no CRL fetcher (fail-open until an ops decision wires a source).
	opts := &smime.RevocationOptions{
		MaxStaleness: smime.DefaultMaxCRLStaleness,
		Blocklist:    smime.BlocklistCheckFunc(pool),
	}

	// 1. Without a blocklist entry: valid badge, exemption applies, harvest works.
	res := verifyInboundSMIME(ctx, msg, signerEmail, roots, opts)
	if res == nil {
		t.Fatal("nil verdict for a signed message")
	}
	if res.Status != smime.StatusValid {
		t.Fatalf("premise: unblocked signer must grade valid, got %q (%+v)", res.Status, res)
	}
	if res.Revocation != smime.RevocationUnknown {
		t.Errorf("unavailable CRL evidence must record revocation-unknown, got %q", res.Revocation)
	}
	if bodyMutatorsApply(res) {
		t.Error("valid verdict must keep the body-mutator exemption")
	}

	srv := NewInboundServer(pgxutil.WorkerPool{Pool: pool}, ":0", testLogger(), nil, nil)
	c := &inConnState{srv: srv}
	c.harvestSignerCert(ctx, rcpt, signerEmail, res)
	if n := countHarvested(t, ctx, pool, ownerUserID); n != 1 {
		t.Fatalf("premise: valid verdict must harvest one row, got %d", n)
	}

	// 2. Admin blocklist entry for the signer leaf (cleaned up; pool closed last).
	if _, err := pool.Exec(ctx,
		`INSERT INTO smime_revocation_blocklist (fingerprint, reason) VALUES ($1, 'smime_revocation_gate_test')`,
		smime.FingerprintCert(leaf)); err != nil {
		t.Fatalf("seed blocklist entry: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM smime_revocation_blocklist WHERE fingerprint = $1`, smime.FingerprintCert(leaf))
	})

	res = verifyInboundSMIME(ctx, msg, signerEmail, roots, opts)
	if res == nil {
		t.Fatal("nil verdict after blocklisting")
	}
	if res.Status != smime.StatusUntrusted {
		t.Errorf("blocklisted signer must lose the badge (StatusUntrusted), got %q", res.Status)
	}
	if res.Revocation != smime.RevocationRevoked {
		t.Errorf("blocklist entry must record Revocation=revoked, got %q", res.Revocation)
	}
	if !bodyMutatorsApply(res) {
		t.Error("revoked verdict must LOSE the body-mutator exemption (mutators run)")
	}

	// 3. The revoked verdict must never harvest — the earlier valid-verdict row
	// stays, but nothing new is filed for the blocked signer.
	c.harvestSignerCert(ctx, rcpt, signerEmail, res)
	if n := countHarvested(t, ctx, pool, ownerUserID); n != 1 {
		t.Fatalf("revoked verdict must NOT harvest: want still 1 row, got %d", n)
	}
}
