package smime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// certOpts configures a test recipient cert built by makeCert.
type certOpts struct {
	email     string
	keyUsage  x509.KeyUsage // 0 = no keyUsage extension at all
	notBefore time.Time
	notAfter  time.Time
	ec        bool // true → ECDSA key (non-RSA), to exercise the RSA gate
}

// makeCert builds a self-signed test cert per opts and returns it plus its PEM.
// Extends the smime_test.go generateTestCert pattern with keyUsage / validity /
// EC variants used by the resolution + predicate tests.
func makeCert(t *testing.T, o certOpts) (*x509.Certificate, string) {
	t.Helper()
	if o.notBefore.IsZero() {
		o.notBefore = time.Now().Add(-time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: o.email},
		NotBefore:      o.notBefore,
		NotAfter:       o.notAfter,
		EmailAddresses: []string{o.email},
		KeyUsage:       o.keyUsage,
	}

	var der []byte
	var err error
	if o.ec {
		key, kerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if kerr != nil {
			t.Fatal(kerr)
		}
		der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	} else {
		key, kerr := rsa.GenerateKey(rand.Reader, 2048)
		if kerr != nil {
			t.Fatal(kerr)
		}
		der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	}
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	return cert, pemStr
}

// fingerprintHex computes a per-row dedup fingerprint for seeding — the
// lowercase hex SHA-256 of the cert DER (the form the Phase-2 harvest writer
// stores). Resolution itself never reads fingerprint; only the dedup key does.
func fingerprintHex(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func TestIsEncryptionCapable(t *testing.T) {
	rsaKeyEnc, _ := makeCert(t, certOpts{email: "a@x.z", keyUsage: x509.KeyUsageKeyEncipherment})
	rsaNoExt, _ := makeCert(t, certOpts{email: "b@x.z", keyUsage: 0})
	rsaSignOnly, _ := makeCert(t, certOpts{email: "c@x.z", keyUsage: x509.KeyUsageDigitalSignature})
	rsaSignPlusEnc, _ := makeCert(t, certOpts{email: "d@x.z", keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment})
	ecCert, _ := makeCert(t, certOpts{email: "e@x.z", keyUsage: x509.KeyUsageKeyEncipherment, ec: true})

	cases := []struct {
		name string
		cert *x509.Certificate
		want bool
	}{
		{"RSA + keyEncipherment", rsaKeyEnc, true},
		{"RSA + no keyUsage ext", rsaNoExt, true},
		{"RSA + sign-only", rsaSignOnly, false},
		{"RSA + sign|encipher", rsaSignPlusEnc, true},
		{"EC + keyEncipherment", ecCert, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsEncryptionCapable(tc.cert); got != tc.want {
				t.Errorf("IsEncryptionCapable=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolveRecipientCert(t *testing.T) {
	// All mutations run inside a tx that is rolled back at test end (re-run safe;
	// the tx satisfies the smime.Querier seam).
	ctx, tx := newTestTx(t)

	// Seed a domain + an owning (sender) user.
	var domID, senderID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ('resolve.test', TRUE) RETURNING id`).Scan(&domID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ('resolveseed', $1, 'resolveseed@resolve.test', 'resolveseed', 'x') RETURNING id`,
		domID).Scan(&senderID); err != nil {
		t.Fatalf("insert sender: %v", err)
	}

	// Per-subtest reset of the recipient cert rows (subtests share the tx).
	emails := []string{"recip@x.z", "expired@x.z", "signonly@x.z", "ec@x.z", "noext@x.z", "fresh@x.z", "other@x.z"}
	cleanupCerts := func() {
		if _, err := tx.Exec(ctx, `DELETE FROM recipient_smime_certs WHERE owner_user_id=$1 AND email = ANY($2)`, senderID, emails); err != nil {
			t.Fatalf("cleanup certs: %v", err)
		}
	}

	seed := func(email, certPEM, source string, lastSeen time.Time) {
		t.Helper()
		var fp string
		if c, err := ParseCert([]byte(certPEM)); err == nil {
			fp = fingerprintHex(c)
		} else {
			fp = certPEM[:8]
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO recipient_smime_certs (owner_user_id, email, cert_pem, fingerprint, source, last_seen)
			 VALUES ($1,$2,$3,$4,$5,$6)`,
			senderID, email, certPEM, fp, source, lastSeen); err != nil {
			t.Fatalf("seed cert %s: %v", email, err)
		}
	}

	now := time.Now()

	t.Run("encryption-capable RSA valid matching email", func(t *testing.T) {
		cleanupCerts()
		_, capPEM := makeCert(t, certOpts{email: "recip@x.z", keyUsage: x509.KeyUsageKeyEncipherment})
		seed("recip@x.z", capPEM, "harvested", now)
		got, ok := ResolveRecipientCert(ctx, tx, senderID, "Recip@X.Z", nil)
		if !ok || got == nil {
			t.Fatalf("expected cert, got ok=%v cert=%v", ok, got)
		}
		if !CertMatchesEmail(got, "recip@x.z") {
			t.Errorf("resolved cert does not match recip@x.z")
		}
	})

	t.Run("sign-only RSA excluded", func(t *testing.T) {
		cleanupCerts()
		_, soPEM := makeCert(t, certOpts{email: "signonly@x.z", keyUsage: x509.KeyUsageDigitalSignature})
		seed("signonly@x.z", soPEM, "harvested", now)
		if _, ok := ResolveRecipientCert(ctx, tx, senderID, "signonly@x.z", nil); ok {
			t.Error("sign-only cert must NOT resolve")
		}
	})

	t.Run("no-keyUsage-ext RSA capable", func(t *testing.T) {
		cleanupCerts()
		_, nePEM := makeCert(t, certOpts{email: "noext@x.z", keyUsage: 0})
		seed("noext@x.z", nePEM, "harvested", now)
		if _, ok := ResolveRecipientCert(ctx, tx, senderID, "noext@x.z", nil); !ok {
			t.Error("no-keyUsage-ext RSA cert must resolve (unrestricted)")
		}
	})

	t.Run("EC excluded by RSA gate", func(t *testing.T) {
		cleanupCerts()
		_, ecPEM := makeCert(t, certOpts{email: "ec@x.z", keyUsage: x509.KeyUsageKeyEncipherment, ec: true})
		seed("ec@x.z", ecPEM, "harvested", now)
		if _, ok := ResolveRecipientCert(ctx, tx, senderID, "ec@x.z", nil); ok {
			t.Error("EC cert must NOT resolve (RSA gate)")
		}
	})

	t.Run("expired RSA excluded", func(t *testing.T) {
		cleanupCerts()
		_, exPEM := makeCert(t, certOpts{
			email:     "expired@x.z",
			keyUsage:  x509.KeyUsageKeyEncipherment,
			notBefore: now.Add(-48 * time.Hour),
			notAfter:  now.Add(-24 * time.Hour),
		})
		seed("expired@x.z", exPEM, "harvested", now)
		if _, ok := ResolveRecipientCert(ctx, tx, senderID, "expired@x.z", nil); ok {
			t.Error("expired cert must NOT resolve")
		}
	})

	t.Run("non-matching email not found", func(t *testing.T) {
		cleanupCerts()
		_, oPEM := makeCert(t, certOpts{email: "other@x.z", keyUsage: x509.KeyUsageKeyEncipherment})
		seed("other@x.z", oPEM, "harvested", now)
		if _, ok := ResolveRecipientCert(ctx, tx, senderID, "recip@x.z", nil); ok {
			t.Error("query for a different email must NOT resolve another cert")
		}
	})

	t.Run("mis-filed unbound cert excluded (SMIME-004 binding re-verification)", func(t *testing.T) {
		cleanupCerts()
		// The ROW claims recip@x.z but the CERT binds a different address:
		// resolution must fail closed for the queried recipient regardless of
		// the stored email column.
		_, unboundPEM := makeCert(t, certOpts{email: "other@x.z", keyUsage: x509.KeyUsageKeyEncipherment})
		seed("recip@x.z", unboundPEM, "harvested", now)
		if _, ok := ResolveRecipientCert(ctx, tx, senderID, "recip@x.z", nil); ok {
			t.Error("a cert that does not BIND the queried recipient must NOT resolve")
		}
	})

	t.Run("freshest-by-last_seen wins", func(t *testing.T) {
		cleanupCerts()
		olderCert, olderPEM := makeCert(t, certOpts{email: "fresh@x.z", keyUsage: x509.KeyUsageKeyEncipherment})
		newerCert, newerPEM := makeCert(t, certOpts{email: "fresh@x.z", keyUsage: x509.KeyUsageKeyEncipherment})
		seed("fresh@x.z", olderPEM, "harvested", now.Add(-time.Hour))
		seed("fresh@x.z", newerPEM, "harvested", now)
		got, ok := ResolveRecipientCert(ctx, tx, senderID, "fresh@x.z", nil)
		if !ok || got == nil {
			t.Fatalf("expected a cert, got ok=%v", ok)
		}
		if got.SerialNumber.Cmp(newerCert.SerialNumber) != 0 {
			t.Errorf("freshest-by-last_seen: got serial %s, want newer %s (older=%s)",
				got.SerialNumber, newerCert.SerialNumber, olderCert.SerialNumber)
		}
	})

	t.Run("union: internal user_smime_certs cert", func(t *testing.T) {
		// Seed an internal user with a user_smime_certs cert; resolve by that
		// user's email with NO recipient_smime_certs row present. (tx-scoped.)
		const internalEmail = "internal-recip@resolve.test"
		var iuserID int64
		if err := tx.QueryRow(ctx,
			`INSERT INTO users (username, domain_id, email, display_name, password_hash)
			 VALUES ('internal-recip', $1, $2, 'Internal Recip', 'x') RETURNING id`,
			domID, internalEmail).Scan(&iuserID); err != nil {
			t.Fatalf("insert internal user: %v", err)
		}
		_, intPEM := makeCert(t, certOpts{email: internalEmail, keyUsage: x509.KeyUsageKeyEncipherment})
		if _, err := tx.Exec(ctx,
			`INSERT INTO user_smime_certs (user_id, cert_pem) VALUES ($1,$2)`,
			iuserID, intPEM); err != nil {
			t.Fatalf("seed user_smime_certs: %v", err)
		}
		got, ok := ResolveRecipientCert(ctx, tx, senderID, "Internal-Recip@Resolve.test", nil)
		if !ok || got == nil {
			t.Fatalf("internal union cert must resolve, got ok=%v", ok)
		}
		if !CertMatchesEmail(got, internalEmail) {
			t.Errorf("resolved internal cert does not match %s", internalEmail)
		}
	})

	t.Run("alias path resolves cert under primary", func(t *testing.T) {
		// alias addr → primary; the recipient_smime_certs row is stored under the
		// primary. Resolution canonicalizes the alias to the primary then matches.
		// (tx-scoped; rolled back at test end.)
		const aprimary = "alias-primary@resolve.test"
		const aalias = "alias-secondary@resolve.test"
		var auser, ambox int64
		if err := tx.QueryRow(ctx,
			`INSERT INTO users (username, domain_id, email, display_name, password_hash)
			 VALUES ('alias-primary-u', $1, $2, 'Alias Primary', 'x') RETURNING id`,
			domID, aprimary).Scan(&auser); err != nil {
			t.Fatalf("insert alias user: %v", err)
		}
		if err := tx.QueryRow(ctx,
			`INSERT INTO mailboxes (user_id, domain_id, email, display_name, is_primary)
			 VALUES ($1, $2, $3, 'Alias Primary', true) RETURNING id`,
			auser, domID, aprimary).Scan(&ambox); err != nil {
			t.Fatalf("insert alias mailbox: %v", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO aliases (mailbox_id, email, domain_id, is_primary) VALUES ($1,$2,$3,true)`, ambox, aprimary, domID); err != nil {
			t.Fatalf("primary alias: %v", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO aliases (mailbox_id, email, domain_id, is_primary) VALUES ($1,$2,$3,false)`, ambox, aalias, domID); err != nil {
			t.Fatalf("secondary alias: %v", err)
		}
		// Cert stored under the PRIMARY address, owned by the sender.
		_, capPEM := makeCert(t, certOpts{email: aprimary, keyUsage: x509.KeyUsageKeyEncipherment})
		seedFP := ""
		if c, err := ParseCert([]byte(capPEM)); err == nil {
			seedFP = fingerprintHex(c)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO recipient_smime_certs (owner_user_id, email, cert_pem, fingerprint, source) VALUES ($1,$2,$3,$4,'harvested')`,
			senderID, aprimary, capPEM, seedFP); err != nil {
			t.Fatalf("seed primary cert: %v", err)
		}
		// Query by the ALIAS address — must canonicalize to primary and resolve.
		got, ok := ResolveRecipientCert(ctx, tx, senderID, aalias, nil)
		if !ok || got == nil {
			t.Fatalf("alias-path resolution failed, ok=%v", ok)
		}
		if !CertMatchesEmail(got, aprimary) {
			t.Errorf("alias-path cert does not match primary %s", aprimary)
		}
	})
}
