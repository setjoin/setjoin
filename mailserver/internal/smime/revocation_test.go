package smime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"
)

// ── Fixtures (built with Go's x509.CreateRevocationList — no network) ────────

// revPolicyCA builds a self-signed root CA (CRLSign-capable) for the
// revocation-policy tests. Returns the CA cert and its private key so tests
// can mint both certificates and CRLs from the same authority.
func revPolicyCA(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return cert, key
}

// revPolicyImpostorCAWithCopiedSKI builds a DN-colliding impostor CA whose
// SubjectKeyId is COPIED from ca — the "copied identifiers" attack shape for
// the unanchored resolution path: DN matches, and any CRL it mints carries the
// copied AKI, so both identifier checks pass even though the key differs.
func revPolicyImpostorCAWithCopiedSKI(t *testing.T, cn string, ca *x509.Certificate) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate impostor key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          ca.SubjectKeyId, // the copied identifier — an explicit SKI is kept verbatim
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create impostor CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse impostor CA cert: %v", err)
	}
	return cert, key
}

// revPolicyLeaf builds an RSA leaf cert signed by ca (EmailProtection EKU +
// keyEncipherment, so it is both verifiable and encryption-capable). Returns
// the cert and its key so tests can sign fixtures with it.
func revPolicyLeaf(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, serial int64, email string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(serial),
		Subject:        pkix.Name{CommonName: email},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		EmailAddresses: []string{email},
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return cert, key
}

// revPolicyCRL mints a CRL from issuer via x509.CreateRevocationList listing
// the given serials. thisUpdate/nextUpdate are absolute so tests can place the
// CRL anywhere on the freshness timeline.
func revPolicyCRL(t *testing.T, issuer *x509.Certificate, issuerKey *rsa.PrivateKey, thisUpdate, nextUpdate time.Time, serials ...int64) *x509.RevocationList {
	t.Helper()
	entries := make([]x509.RevocationListEntry, 0, len(serials))
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(s),
			RevocationTime: thisUpdate,
		})
	}
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(time.Now().UnixNano()),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, issuerKey)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}
	parsed, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parse minted CRL: %v", err)
	}
	return parsed
}

// tamperCRLDER flips a byte inside the DER encoding of the given serial's
// INTEGER (same length, so the structure still parses) — the parsed CRL still
// lists every original serial but its signature no longer verifies.
func tamperCRLDER(t *testing.T, crl *x509.RevocationList, serial int64) *x509.RevocationList {
	t.Helper()
	orig := []byte{0x02, 0x02, byte(serial >> 8), byte(serial)}
	flipped := []byte{0x02, 0x02, byte(serial >> 8), byte(serial) ^ 0xFF}
	tampered := bytes.Replace(crl.Raw, orig, flipped, 1)
	if bytes.Equal(tampered, crl.Raw) {
		t.Fatal("tamper premise: serial DER not found in CRL")
	}
	parsed, err := x509.ParseRevocationList(tampered)
	if err != nil {
		t.Fatalf("tampered CRL must still parse: %v", err)
	}
	return parsed
}

// crlFetcher builds a CRLFetchFunc returning the given (crl, issuer) pair.
func crlFetcher(crl *x509.RevocationList, issuer *x509.Certificate) CRLFetchFunc {
	return func(*x509.Certificate) (*x509.RevocationList, *x509.Certificate, bool) {
		return crl, issuer, true
	}
}

// ── Policy-core acceptance arms ──────────────────────────────────────────────

// TestEvaluateRevocation_CRLAcceptanceArms pins every CRL arm of the settled
// revocation/freshness policy on the evaluation core:
//
//	fresh + authentic + issuer + listing → revoked
//	fresh + authentic + issuer + NOT listing → clear (fresh authenticated
//	  non-listing evidence — deliberately distinct from unavailable)
//	expired/stale (beyond NextUpdate + ceiling) → unknown, NEVER revokes
//	within NextUpdate + configured ceiling → still fresh evidence
//	future-dated (ThisUpdate in the future) / inverted interval → unknown
//	wrong issuer → not evidence
//	non-authentic (bad signature) → not evidence
//	same-DN different-key issuer (AKI binding) → not evidence
//	unavailable (no fetcher / fetch failure / nil opts) → fail-open unknown
func TestEvaluateRevocation_CRLAcceptanceArms(t *testing.T) {
	ca, caKey := revPolicyCA(t, "Revocation Test CA")
	leaf, _ := revPolicyLeaf(t, ca, caKey, 0x0BAD, "revoked@corp.example")

	// A DN-COLLIDING second CA: same subject, different key — the classic
	// forged-issuer shape. Its CRLs are authentic FOR ITSELF, never for certs
	// issued by the real CA.
	rogueDN, rogueDNKey := revPolicyCA(t, "Revocation Test CA")
	// A genuinely unrelated issuer (different DN AND key).
	unrelated, unrelatedKey := revPolicyCA(t, "Unrelated CA")

	now := time.Now()
	crl := func(this, next time.Time, serials ...int64) CRLFetchFunc {
		return crlFetcher(revPolicyCRL(t, ca, caKey, this, next, serials...), ca)
	}

	cases := []struct {
		name string
		opts *RevocationOptions
		want string
	}{
		{
			name: "fresh authentic issuer CRL listing the serial revokes",
			opts: &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: crl(now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD)},
			want: RevocationRevoked,
		},
		{
			name: "fresh authentic issuer CRL not listing the serial is positive clear evidence",
			opts: &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: crl(now.Add(-time.Hour), now.Add(23*time.Hour), 0xBEEF)},
			want: RevocationClear,
		},
		{
			name: "expired CRL is stale evidence and never revokes",
			opts: &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: crl(now.Add(-48*time.Hour), now.Add(-24*time.Hour), 0x0BAD)},
			want: RevocationUnknown,
		},
		{
			name: "beyond NextUpdate but within the staleness ceiling is still fresh",
			opts: &RevocationOptions{MaxStaleness: 24 * time.Hour, FetchCRL: crl(now.Add(-48*time.Hour), now.Add(-2*time.Hour), 0x0BAD)},
			want: RevocationRevoked,
		},
		{
			name: "zero ceiling expires the CRL exactly at NextUpdate",
			opts: &RevocationOptions{MaxStaleness: 0, FetchCRL: crl(now.Add(-48*time.Hour), now.Add(-time.Hour), 0x0BAD)},
			want: RevocationUnknown,
		},
		{
			name: "wrong-issuer CRL is ignored with no effect either way",
			opts: &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: crlFetcher(
				revPolicyCRL(t, unrelated, unrelatedKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD), unrelated)},
			want: RevocationUnknown,
		},
		{
			name: "same-DN different-key CRL is not evidence (AKI binding, no anchor)",
			opts: &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: crlFetcher(
				revPolicyCRL(t, rogueDN, rogueDNKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD), rogueDN)},
			want: RevocationUnknown,
		},
		{
			name: "non-authentic CRL (tampered DER, still listing the serial) is not evidence",
			opts: &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: crlFetcher(
				tamperCRLDER(t, revPolicyCRL(t, ca, caKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD, 0x0BEE), 0x0BEE), ca)},
			want: RevocationUnknown,
		},
		{
			name: "fetch failure (unavailable) is fail-open unknown",
			opts: &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: func(*x509.Certificate) (*x509.RevocationList, *x509.Certificate, bool) {
				return nil, nil, false
			}},
			want: RevocationUnknown,
		},
		{
			name: "no fetcher configured is fail-open unknown",
			opts: &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness},
			want: RevocationUnknown,
		},
		{
			name: "nil options is fail-open unknown",
			opts: nil,
			want: RevocationUnknown,
		},
		{
			name: "admin blocklist override revokes even with no CRL available",
			opts: &RevocationOptions{Blocklist: func(context.Context, *x509.Certificate) bool { return true }},
			want: RevocationRevoked,
		},
		{
			name: "blocklist miss with no CRL available stays unknown",
			opts: &RevocationOptions{Blocklist: func(context.Context, *x509.Certificate) bool { return false }},
			want: RevocationUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EvaluateRevocation(context.Background(), leaf, tc.opts); got != tc.want {
				t.Errorf("EvaluateRevocation = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEvaluateRevocation_AuthorityAnchorRejectsCollidingDN pins the verify-path
// binding: with the chain-validated issuer as the authority anchor, evidence
// from a same-DN different-key CA is rejected even before the AKI check.
func TestEvaluateRevocation_AuthorityAnchorRejectsCollidingDN(t *testing.T) {
	ca, caKey := revPolicyCA(t, "Anchor Test CA")
	leaf, _ := revPolicyLeaf(t, ca, caKey, 0x0BAD, "anchored@corp.example")
	rogueDN, rogueDNKey := revPolicyCA(t, "Anchor Test CA")

	now := time.Now()
	rogueCRL := revPolicyCRL(t, rogueDN, rogueDNKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD)
	opts := &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: crlFetcher(rogueCRL, rogueDN)}

	// With the true chain-validated issuer as anchor: not evidence.
	if got := evaluateRevocationAt(context.Background(), leaf, opts, now, ca); got != RevocationUnknown {
		t.Errorf("anchored evaluation of a colliding-DN CRL = %q, want %q", got, RevocationUnknown)
	}
	// Premise: the AKI check alone would NOT catch this fixture if the rogue
	// CA somehow had no SKI — the anchor must reject it regardless.
	if got := evaluateRevocationAt(context.Background(), leaf, opts, now, nil); got != RevocationUnknown {
		t.Errorf("unanchored evaluation of a colliding-DN CRL (AKI path) = %q, want %q", got, RevocationUnknown)
	}
}

// ── Transition matrix: durable confirmed revocation ─────────────────────────

// memRevocationStore is an in-memory CertRevocationStore for matrix tests —
// the same seam the DB-backed store (NewCertRevocationStore) fills in
// production. recallErr/recordErr simulate store outages.
type memRevocationStore struct {
	mu        sync.Mutex
	revoked   map[string]string
	recallErr error
	recordErr error
}

func newMemRevocationStore() *memRevocationStore {
	return &memRevocationStore{revoked: make(map[string]string)}
}

func (m *memRevocationStore) IsRevoked(_ context.Context, fingerprint string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recallErr != nil {
		return false, m.recallErr
	}
	_, ok := m.revoked[fingerprint]
	return ok, nil
}

func (m *memRevocationStore) RecordRevoked(_ context.Context, fingerprint, evidence string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recordErr != nil {
		return m.recordErr
	}
	m.revoked[fingerprint] = evidence
	return nil
}

func (m *memRevocationStore) has(fingerprint string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.revoked[fingerprint]
	return ok
}

// TestEvaluateRevocation_ConfirmedRevocationPersists pins the persistence half
// of the transition matrix: once a fresh authenticated issuer CRL listing the
// serial has CONFIRMED a revocation (and the store recorded it), every later
// evidence loss — unavailable, stale, future-dated, non-authentic,
// wrong-issuer, even fresh non-listing evidence — still returns revoked.
// A previously revoked key must never resolve again through evidence loss.
func TestEvaluateRevocation_ConfirmedRevocationPersists(t *testing.T) {
	ca, caKey := revPolicyCA(t, "Persist Matrix CA")
	leaf, _ := revPolicyLeaf(t, ca, caKey, 0x0BAD, "persist@corp.example")
	fp := FingerprintCert(leaf)

	now := time.Now()
	store := newMemRevocationStore()
	opts := func(fetch CRLFetchFunc) *RevocationOptions {
		return &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: fetch, Store: store}
	}
	// listingFor mints a fresh listing CRL for WHICHEVER cert is evaluated —
	// the per-cert shape a real fetcher produces, so per-cert sub-tests
	// exercise the confirmation arm, not the non-listing arm.
	listingFor := func(ca *x509.Certificate, key *rsa.PrivateKey) CRLFetchFunc {
		return func(c *x509.Certificate) (*x509.RevocationList, *x509.Certificate, bool) {
			return revPolicyCRL(t, ca, key, now.Add(-time.Hour), now.Add(23*time.Hour), c.SerialNumber.Int64()), ca, true
		}
	}
	freshListing := opts(crlFetcher(revPolicyCRL(t, ca, caKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD), ca))
	freshClear := opts(crlFetcher(revPolicyCRL(t, ca, caKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0xBEEF), ca))
	staleListing := opts(crlFetcher(revPolicyCRL(t, ca, caKey, now.Add(-48*time.Hour), now.Add(-24*time.Hour), 0x0BAD), ca))
	futureListing := opts(crlFetcher(revPolicyCRL(t, ca, caKey, now.Add(2*time.Hour), now.Add(24*time.Hour), 0x0BAD), ca))
	nonAuthentic := opts(crlFetcher(tamperCRLDER(t, revPolicyCRL(t, ca, caKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD, 0x0BEE), 0x0BEE), ca))
	rogue, rogueKey := revPolicyCA(t, "Persist Matrix CA")
	wrongIssuer := opts(crlFetcher(revPolicyCRL(t, rogue, rogueKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD), rogue))
	unavailable := opts(func(*x509.Certificate) (*x509.RevocationList, *x509.Certificate, bool) { return nil, nil, false })

	// Premise: nothing recorded, no fetcher → fail-open unknown.
	if got := EvaluateRevocation(context.Background(), leaf, unavailable); got != RevocationUnknown {
		t.Fatalf("premise: unevaluated cert with no CRL = %q, want %q", got, RevocationUnknown)
	}
	if store.has(fp) {
		t.Fatal("premise: nothing was recorded before any confirmation")
	}

	// Confirmation: fresh authenticated listing → revoked, durably recorded.
	if got := EvaluateRevocation(context.Background(), leaf, freshListing); got != RevocationRevoked {
		t.Fatalf("confirmation evaluation = %q, want %q", got, RevocationRevoked)
	}
	if !store.has(fp) {
		t.Fatal("confirmed revocation must be durably recorded")
	}

	// Every subsequent evidence loss stays revoked.
	for _, tc := range []struct {
		name string
		opts *RevocationOptions
	}{
		{"unavailable evidence", unavailable},
		{"stale CRL", staleListing},
		{"future-dated CRL", futureListing},
		{"non-authentic CRL", nonAuthentic},
		{"wrong-issuer CRL", wrongIssuer},
		{"no fetcher at all", opts(nil)},
		{"fresh authenticated non-listing (clear) does not un-revoke", freshClear},
	} {
		t.Run("after confirmation: "+tc.name, func(t *testing.T) {
			if got := EvaluateRevocation(context.Background(), leaf, tc.opts); got != RevocationRevoked {
				t.Errorf("persisted revocation = %q, want %q", got, RevocationRevoked)
			}
		})
	}

	t.Run("fresh non-listing evidence on a never-revoked cert is clear and NOT persisted", func(t *testing.T) {
		other, _ := revPolicyLeaf(t, ca, caKey, 0x0CEE, "clear@corp.example")
		otherFP := FingerprintCert(other)
		if got := EvaluateRevocation(context.Background(), other, freshClear); got != RevocationClear {
			t.Fatalf("fresh authenticated non-listing = %q, want %q", got, RevocationClear)
		}
		if store.has(otherFP) {
			t.Error("clear evidence is freshness-bound and must never be persisted")
		}
		// Its later loss degrades to unknown, not revoked — only CONFIRMED
		// revocations persist.
		if got := EvaluateRevocation(context.Background(), other, unavailable); got != RevocationUnknown {
			t.Errorf("lost clear evidence = %q, want %q", got, RevocationUnknown)
		}
	})

	t.Run("a record failure still revokes on live evidence", func(t *testing.T) {
		other, _ := revPolicyLeaf(t, ca, caKey, 0x0DED, "recordfail@corp.example")
		store.recordErr = errStoreOutage{}
		defer func() { store.recordErr = nil }()
		if got := EvaluateRevocation(context.Background(), other, opts(listingFor(ca, caKey))); got != RevocationRevoked {
			t.Errorf("evaluation with failing record = %q, want %q (live evidence exists now)", got, RevocationRevoked)
		}
		if store.has(FingerprintCert(other)) {
			t.Error("a failed record must not have written a durable row")
		}
	})

	t.Run("a store recall error is never a revocation", func(t *testing.T) {
		other, _ := revPolicyLeaf(t, ca, caKey, 0x0EFE, "recallfail@corp.example")
		store.recallErr = errStoreOutage{}
		defer func() { store.recallErr = nil }()
		// Live fresh listing still revokes through the fall-through.
		if got := EvaluateRevocation(context.Background(), other, opts(listingFor(ca, caKey))); got != RevocationRevoked {
			t.Errorf("live evidence despite recall outage = %q, want %q", got, RevocationRevoked)
		}
		// But stale evidence with the store unconsultable stays fail-open unknown.
		if got := EvaluateRevocation(context.Background(), other, staleListing); got != RevocationUnknown {
			t.Errorf("stale evidence despite recall outage = %q, want %q", got, RevocationUnknown)
		}
	})

	t.Run("a blocklist hit is not re-recorded into the durable store", func(t *testing.T) {
		other, _ := revPolicyLeaf(t, ca, caKey, 0x0F0F, "blocklisted@corp.example")
		otherFP := FingerprintCert(other)
		adminOnly := &RevocationOptions{
			MaxStaleness: DefaultMaxCRLStaleness,
			Blocklist:    func(context.Context, *x509.Certificate) bool { return true },
			Store:        store,
		}
		if got := EvaluateRevocation(context.Background(), other, adminOnly); got != RevocationRevoked {
			t.Fatalf("blocklist hit = %q, want %q", got, RevocationRevoked)
		}
		if store.has(otherFP) {
			t.Error("blocklist evidence is durable in the admin-owned table; the matrix must not duplicate it (removing the admin row must stay the operator's un-revocation action)")
		}
	})

	t.Run("the anchored verify path persists and recalls identically", func(t *testing.T) {
		other, _ := revPolicyLeaf(t, ca, caKey, 0x0A0A, "anchored-persist@corp.example")
		anchored := opts(listingFor(ca, caKey))
		if got := evaluateRevocationAt(context.Background(), other, anchored, now, ca); got != RevocationRevoked {
			t.Fatalf("anchored confirmation = %q, want %q", got, RevocationRevoked)
		}
		if got := evaluateRevocationAt(context.Background(), other, unavailable, now, ca); got != RevocationRevoked {
			t.Errorf("anchored recall after evidence loss = %q, want %q", got, RevocationRevoked)
		}
	})
}

// errStoreOutage simulates a durable-store outage in the matrix tests.
type errStoreOutage struct{}

func (errStoreOutage) Error() string { return "revocation store outage" }

// ── Freshness bounds (ThisUpdate lower bound + valid interval) ──────────────

// TestEvaluateRevocation_FreshnessBounds pins the two-sided freshness rule: a
// FUTURE-DATED CRL (ThisUpdate after now) was previously accepted as fresh
// evidence — it must not be; an inverted [ThisUpdate, NextUpdate] interval and
// a missing NextUpdate are never evidence; ThisUpdate == now is the inclusive
// lower bound of usable evidence.
func TestEvaluateRevocation_FreshnessBounds(t *testing.T) {
	ca, caKey := revPolicyCA(t, "Freshness CA")
	leaf, _ := revPolicyLeaf(t, ca, caKey, 0x0BAD, "fresh@corp.example")

	now := time.Now()
	optsWith := func(c *x509.RevocationList) *RevocationOptions {
		return &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: crlFetcher(c, ca)}
	}

	futureDated := revPolicyCRL(t, ca, caKey, now.Add(2*time.Hour), now.Add(24*time.Hour), 0x0BAD)
	justPublished := revPolicyCRL(t, ca, caKey, now, now.Add(23*time.Hour), 0x0BAD)

	zeroNext := revPolicyCRL(t, ca, caKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD)
	zeroNext.NextUpdate = time.Time{} // struct-level fixture: no freshness bound at all

	inverted := revPolicyCRL(t, ca, caKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD)
	inverted.NextUpdate = now.Add(-2 * time.Hour) // struct-level fixture: NextUpdate < ThisUpdate

	cases := []struct {
		name string
		opts *RevocationOptions
		want string
	}{
		{"future-dated CRL is not yet evidence even when listing the serial", optsWith(futureDated), RevocationUnknown},
		{"ThisUpdate == now is the inclusive lower bound of fresh evidence", optsWith(justPublished), RevocationRevoked},
		{"CRL with no NextUpdate carries no freshness bound", optsWith(zeroNext), RevocationUnknown},
		{"CRL with an inverted validity interval is never evidence", optsWith(inverted), RevocationUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EvaluateRevocation(context.Background(), leaf, tc.opts); got != tc.want {
				t.Errorf("EvaluateRevocation = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("crlIsFresh unit arms", func(t *testing.T) {
		crl := func(this, next time.Time) *x509.RevocationList {
			return revPolicyCRL(t, ca, caKey, this, next, 0x0BAD)
		}
		zeroThis := revPolicyCRL(t, ca, caKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD)
		zeroThis.ThisUpdate = time.Time{}
		zeroNext := revPolicyCRL(t, ca, caKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD)
		zeroNext.NextUpdate = time.Time{} // struct-level fixture: CreateRevocationList refuses a zero NextUpdate
		for _, tc := range []struct {
			name string
			crl  *x509.RevocationList
			want bool
		}{
			{"valid window", crl(now.Add(-time.Hour), now.Add(23*time.Hour)), true},
			{"no ThisUpdate", zeroThis, false},
			{"no NextUpdate", zeroNext, false},
			{"future ThisUpdate", crl(now.Add(time.Hour), now.Add(24*time.Hour)), false},
			{"expired beyond any ceiling", crl(now.Add(-48*time.Hour), now.Add(-24*time.Hour)), false},
		} {
			if got := crlIsFresh(tc.crl, DefaultMaxCRLStaleness, now); got != tc.want {
				t.Errorf("crlIsFresh(%s) = %v, want %v", tc.name, got, tc.want)
			}
		}
	})
}

// ── Unanchored key binding: the supplied issuer must have signed the leaf ───

// TestEvaluateRevocation_WrongKeyIssuerIdentifierGames pins the resolution-path
// key binding: matching DN and AKI does NOT prove the supplied issuer signed
// the leaf. A same-DN wrong-key impostor that COPIES the identifier (SubjectKeyId)
// — or one whose identifiers are ABSENT so the AKI clause cannot bind — mints
// CRLs that are perfectly authentic FOR ITSELF and previously qualified as
// revocation evidence for certs it never issued. Only the leaf's own signature
// under the supplied key rejects it.
func TestEvaluateRevocation_WrongKeyIssuerIdentifierGames(t *testing.T) {
	ca, caKey := revPolicyCA(t, "Wrong Key CA")
	leaf, _ := revPolicyLeaf(t, ca, caKey, 0x0BAD, "victim@corp.example")

	now := time.Now()

	t.Run("copied identifiers (same DN, copied AKI) do not make the impostor the issuer", func(t *testing.T) {
		impostor, impostorKey := revPolicyImpostorCAWithCopiedSKI(t, "Wrong Key CA", ca)
		crl := revPolicyCRL(t, impostor, impostorKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD)

		// Premise: DN matches, the CRL's AKI is the copied CA identifier, and
		// the CRL is signature-authentic FOR THE IMPOSTOR — identifier
		// matching alone would accept it.
		if !crlIssuerMatches(leaf, crl, impostor, nil) {
			t.Fatal("premise: the copied-identifier impostor passes DN+AKI matching (that is the attack)")
		}
		if err := crl.CheckSignatureFrom(impostor); err != nil {
			t.Fatal("premise: the impostor's CRL is authentic for the impostor")
		}

		opts := &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: crlFetcher(crl, impostor)}
		if got := EvaluateRevocation(context.Background(), leaf, opts); got != RevocationUnknown {
			t.Errorf("wrong-key issuer with copied identifiers = %q, want %q", got, RevocationUnknown)
		}
	})

	t.Run("absent identifiers (no AKI binding available) do not either", func(t *testing.T) {
		impostor, impostorKey := revPolicyCA(t, "Wrong Key CA") // own auto-derived SKI
		crl := revPolicyCRL(t, impostor, impostorKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD)
		crl.AuthorityKeyId = nil // struct-level fixture: an AKI-less CRL — the AKI clause cannot bind

		if !crlIssuerMatches(leaf, crl, impostor, nil) {
			t.Fatal("premise: with absent identifiers the match degrades to DN-only (that is the gap)")
		}

		opts := &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: crlFetcher(crl, impostor)}
		if got := EvaluateRevocation(context.Background(), leaf, opts); got != RevocationUnknown {
			t.Errorf("wrong-key issuer with absent identifiers = %q, want %q", got, RevocationUnknown)
		}
	})

	t.Run("the real issuer still revokes through the signature binding", func(t *testing.T) {
		crl := revPolicyCRL(t, ca, caKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD)
		opts := &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: crlFetcher(crl, ca)}
		if got := EvaluateRevocation(context.Background(), leaf, opts); got != RevocationRevoked {
			t.Errorf("the genuine issuer's fresh listing CRL = %q, want %q", got, RevocationRevoked)
		}
	})
}

// ── End-to-end verdict mapping (badge / exemption / harvest inputs) ─────────

// TestVerifyDetachedWithRevocation_AcceptanceMatrix drives a real detached
// signature through the full two-pass verifier under each revocation arm:
//
//	fresh authentic issuer CRL listing the serial → StatusUntrusted +
//	  Revocation=revoked (badge removed, body mutators apply, nothing
//	  harvestable: LeafPEM and TrustAnchorPEM stay empty);
//	expired CRL → no revocation, no badge removal (still StatusValid,
//	  recorded revocation-unknown);
//	wrong-issuer CRL → ignored with no effect either way;
//	unavailable revocation data → badge stays, key recorded
//	  revocation-unknown;
//	invalid message signature → StatusInvalid regardless of revocation data;
//	admin blocklist entry → the same effect as fresh-CRL revocation.
func TestVerifyDetachedWithRevocation_AcceptanceMatrix(t *testing.T) {
	ca, caKey := revPolicyCA(t, "Verify Matrix CA")
	email := "signer@corp.example"
	leaf, leafKey := revPolicyLeaf(t, ca, caKey, 0x0BAD, email)

	content := []byte("hello, revocable world")
	// signDetachedForTest (verify_detached_test.go) — ietf-cms signs the
	// fixtures because its format round-trips through its own ParseSignedData
	// (smime.Sign's hand-rolled CMS does not).
	sigDER := signDetachedForTest(t, content, leaf, leafKey)

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	now := time.Now()
	freshListing := crlFetcher(revPolicyCRL(t, ca, caKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD), ca)
	expiredListing := crlFetcher(revPolicyCRL(t, ca, caKey, now.Add(-48*time.Hour), now.Add(-24*time.Hour), 0x0BAD), ca)
	wrongIssuer := func(*x509.Certificate) (*x509.RevocationList, *x509.Certificate, bool) {
		rogue, rogueKey := revPolicyCA(t, "Other CA")
		return revPolicyCRL(t, rogue, rogueKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD), rogue, true
	}
	blocked := &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, Blocklist: func(context.Context, *x509.Certificate) bool { return true }}

	cases := []struct {
		name           string
		content        []byte
		rev            *RevocationOptions
		wantStatus     string
		wantRevocation string
		wantLeafPEM    bool // true → LeafPEM must be populated (valid verdict)
	}{
		{
			name:           "fresh authentic issuer CRL listing the serial removes the badge",
			content:        content,
			rev:            &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: freshListing},
			wantStatus:     StatusUntrusted,
			wantRevocation: RevocationRevoked,
		},
		{
			name:           "expired CRL causes no revocation and no badge removal",
			content:        content,
			rev:            &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: expiredListing},
			wantStatus:     StatusValid,
			wantRevocation: RevocationUnknown,
			wantLeafPEM:    true,
		},
		{
			name:           "wrong-issuer CRL is ignored with no effect either way",
			content:        content,
			rev:            &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: wrongIssuer},
			wantStatus:     StatusValid,
			wantRevocation: RevocationUnknown,
			wantLeafPEM:    true,
		},
		{
			name:           "unavailable revocation data leaves the badge, key revocation-unknown",
			content:        content,
			rev:            nil,
			wantStatus:     StatusValid,
			wantRevocation: RevocationUnknown,
			wantLeafPEM:    true,
		},
		{
			name:           "invalid message signature yields no badge regardless of revocation data",
			content:        []byte("TAMPERED"),
			rev:            &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: freshListing},
			wantStatus:     StatusInvalid,
			wantRevocation: RevocationUnknown,
		},
		{
			name:           "admin blocklist entry has the same effect as fresh-CRL revocation",
			content:        content,
			rev:            blocked,
			wantStatus:     StatusUntrusted,
			wantRevocation: RevocationRevoked,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := VerifyDetachedWithRevocation(context.Background(), tc.content, sigDER, email, roots, tc.rev)
			if res == nil {
				t.Fatal("nil verdict")
			}
			if res.Status != tc.wantStatus {
				t.Errorf("Status = %q, want %q", res.Status, tc.wantStatus)
			}
			if res.Revocation != tc.wantRevocation {
				t.Errorf("Revocation = %q, want %q", res.Revocation, tc.wantRevocation)
			}
			if tc.wantLeafPEM && res.LeafPEM == "" {
				t.Error("valid verdict must expose LeafPEM (harvest input)")
			}
			if !tc.wantLeafPEM && res.LeafPEM != "" {
				t.Errorf("non-valid verdict must NEVER expose LeafPEM, got %q", res.LeafPEM)
			}
			if res.Status != StatusValid && res.TrustAnchorPEM != "" {
				t.Errorf("non-valid verdict must NEVER expose TrustAnchorPEM, got %q", res.TrustAnchorPEM)
			}
		})
	}
}

// ── DB-backed arms: blocklist store + already-harvested resolution ──────────

// TestBlocklistCheckFunc_BlocklistStore pins the DB-backed blocklist seam: a
// seeded smime_revocation_blocklist row matches its certificate by the
// FingerprintCert convention, a different cert does not match, and a DB error
// is fail-open (never revoked).
func TestBlocklistCheckFunc_BlocklistStore(t *testing.T) {
	ca, caKey := revPolicyCA(t, "Blocklist Store CA")
	blockedCert, _ := revPolicyLeaf(t, ca, caKey, 0x0BAD, "blocked@corp.example")
	otherCert, _ := revPolicyLeaf(t, ca, caKey, 0x0BEE, "other@corp.example")

	ctx, tx := newTestTx(t)
	if _, err := tx.Exec(ctx,
		`INSERT INTO smime_revocation_blocklist (fingerprint, reason) VALUES ($1, 'test blocklist entry')`,
		FingerprintCert(blockedCert)); err != nil {
		t.Fatalf("seed blocklist row: %v", err)
	}

	check := BlocklistCheckFunc(tx)
	if !check(ctx, blockedCert) {
		t.Error("blocklisted cert must match (fingerprint convention)")
	}
	if check(ctx, otherCert) {
		t.Error("non-blocklisted cert must NOT match")
	}

	// DB error → fail-open unknown (false), never revoked.
	failing := BlocklistCheckFunc(errQuerier{err: context.DeadlineExceeded})
	if failing(ctx, blockedCert) {
		t.Error("blocklist store failure must fail open (no revocation)")
	}
}

// TestResolveRecipientCert_RevocationExcludesHarvestedTarget proves the
// "already-harvested encryption-target resolution" arm: a cert that resolves
// today stops resolving once positive revocation evidence exists — a fresh
// authentic issuer CRL listing its serial or an admin blocklist row — while an
// expired CRL or a wrong-issuer CRL leaves resolution untouched (fail-open).
func TestResolveRecipientCert_RevocationExcludesHarvestedTarget(t *testing.T) {
	ctx, tx := newTestTx(t)

	ca, caKey := revPolicyCA(t, "Resolve Revocation CA")
	leaf, _ := revPolicyLeaf(t, ca, caKey, 0x0BAD, "target@resolve-revoke.test")
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))

	var domID, senderID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ('resolve-revoke.test', TRUE) RETURNING id`).Scan(&domID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ('revokesender', $1, 'revokesender@resolve-revoke.test', 'revokesender', 'x') RETURNING id`,
		domID).Scan(&senderID); err != nil {
		t.Fatalf("insert sender: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO recipient_smime_certs (owner_user_id, email, cert_pem, fingerprint, source, last_seen)
		 VALUES ($1, 'target@resolve-revoke.test', $2, $3, 'harvested', now())`,
		senderID, leafPEM, FingerprintCert(leaf)); err != nil {
		t.Fatalf("seed harvested cert: %v", err)
	}

	now := time.Now()
	freshListing := crlFetcher(revPolicyCRL(t, ca, caKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD), ca)
	expiredListing := crlFetcher(revPolicyCRL(t, ca, caKey, now.Add(-48*time.Hour), now.Add(-24*time.Hour), 0x0BAD), ca)
	rogue, rogueKey := revPolicyCA(t, "Resolve Revocation CA")
	wrongIssuer := crlFetcher(revPolicyCRL(t, rogue, rogueKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD), rogue)

	// Premise: with no revocation checking the harvested cert resolves.
	if _, ok := ResolveRecipientCert(ctx, tx, senderID, "target@resolve-revoke.test", nil); !ok {
		t.Fatal("premise: harvested cert must resolve with revocation checking disabled")
	}

	t.Run("fresh authentic issuer CRL listing the serial removes resolution", func(t *testing.T) {
		if _, ok := ResolveRecipientCert(ctx, tx, senderID, "target@resolve-revoke.test",
			&RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: freshListing}); ok {
			t.Error("revoked cert must NOT resolve as an encryption target")
		}
	})
	t.Run("expired CRL leaves resolution untouched", func(t *testing.T) {
		if _, ok := ResolveRecipientCert(ctx, tx, senderID, "target@resolve-revoke.test",
			&RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: expiredListing}); !ok {
			t.Error("stale CRL proves nothing: the cert must still resolve")
		}
	})
	t.Run("wrong-issuer CRL leaves resolution untouched", func(t *testing.T) {
		if _, ok := ResolveRecipientCert(ctx, tx, senderID, "target@resolve-revoke.test",
			&RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: wrongIssuer}); !ok {
			t.Error("wrong-issuer CRL is not evidence: the cert must still resolve")
		}
	})
	t.Run("admin blocklist entry removes resolution", func(t *testing.T) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO smime_revocation_blocklist (fingerprint, reason) VALUES ($1, 'test: resolve exclusion')`,
			FingerprintCert(leaf)); err != nil {
			t.Fatalf("seed blocklist row: %v", err)
		}
		if _, ok := ResolveRecipientCert(ctx, tx, senderID, "target@resolve-revoke.test",
			&RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, Blocklist: BlocklistCheckFunc(tx)}); ok {
			t.Error("blocklisted cert must NOT resolve as an encryption target")
		}
	})
}

// TestCertRevocationStore_DB pins the DB-backed durable store over
// smime_cert_revocations: a recorded confirmation recalls by the
// FingerprintCert convention, re-recording is idempotent (one row per
// certificate), other certs recall as misses, and store errors surface (the
// matrix treats them as "durable state unavailable", never as revoked).
func TestCertRevocationStore_DB(t *testing.T) {
	ctx, tx := newTestTx(t)

	ca, caKey := revPolicyCA(t, "Revocation Store CA")
	revokedCert, _ := revPolicyLeaf(t, ca, caKey, 0x0BAD, "recorded@corp.example")
	otherCert, _ := revPolicyLeaf(t, ca, caKey, 0x0BEE, "unrecorded@corp.example")

	store := NewCertRevocationStore(tx)
	if err := store.RecordRevoked(ctx, FingerprintCert(revokedCert), RevocationEvidenceCRL); err != nil {
		t.Fatalf("record revocation: %v", err)
	}

	if ok, err := store.IsRevoked(ctx, FingerprintCert(revokedCert)); err != nil || !ok {
		t.Errorf("IsRevoked(revokedCert) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := store.IsRevoked(ctx, FingerprintCert(otherCert)); err != nil || ok {
		t.Errorf("IsRevoked(otherCert) = %v, %v; want false, nil", ok, err)
	}

	// Idempotent re-confirmation: the conflict clause must keep one row.
	if err := store.RecordRevoked(ctx, FingerprintCert(revokedCert), RevocationEvidenceCRL); err != nil {
		t.Fatalf("re-record revocation: %v", err)
	}
	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM smime_cert_revocations WHERE fingerprint = $1`,
		FingerprintCert(revokedCert)).Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if n != 1 {
		t.Errorf("re-confirmation produced %d rows for one fingerprint, want 1", n)
	}

	// Store outage: the error must surface — the matrix never revokes on (or
	// hides) an unconsultable durable state.
	failing := NewCertRevocationStore(errQuerier{err: context.DeadlineExceeded})
	if ok, err := failing.IsRevoked(ctx, FingerprintCert(revokedCert)); err == nil {
		t.Errorf("IsRevoked through an outage = %v, %v; want an error", ok, err)
	}
	if err := failing.RecordRevoked(ctx, FingerprintCert(revokedCert), RevocationEvidenceCRL); err == nil {
		t.Error("RecordRevoked through an outage must return an error")
	}
}

// TestResolveRecipientCert_ConfirmedRevocationPersists is the Astra HOLD
// scenario end-to-end in resolution: a harvested cert confirmed revoked by a
// fresh authenticated issuer CRL (durably recorded via the store) must NOT
// resolve again when the evidence later goes unavailable or stale — previously
// those results degraded to fail-open unknown and resurrected the key.
func TestResolveRecipientCert_ConfirmedRevocationPersists(t *testing.T) {
	ctx, tx := newTestTx(t)

	ca, caKey := revPolicyCA(t, "Resolve Persist CA")
	leaf, _ := revPolicyLeaf(t, ca, caKey, 0x0BAD, "persist-target@resolve-revoke.test")
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))

	var domID, senderID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ('resolve-persist.test', TRUE) RETURNING id`).Scan(&domID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ('persistsender', $1, 'persistsender@resolve-persist.test', 'persistsender', 'x') RETURNING id`,
		domID).Scan(&senderID); err != nil {
		t.Fatalf("insert sender: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO recipient_smime_certs (owner_user_id, email, cert_pem, fingerprint, source, last_seen)
		 VALUES ($1, 'persist-target@resolve-revoke.test', $2, $3, 'harvested', now())`,
		senderID, leafPEM, FingerprintCert(leaf)); err != nil {
		t.Fatalf("seed harvested cert: %v", err)
	}

	now := time.Now()
	store := NewCertRevocationStore(tx)
	revOpts := func(fetch CRLFetchFunc) *RevocationOptions {
		return &RevocationOptions{MaxStaleness: DefaultMaxCRLStaleness, FetchCRL: fetch, Store: store}
	}
	freshListing := revOpts(crlFetcher(revPolicyCRL(t, ca, caKey, now.Add(-time.Hour), now.Add(23*time.Hour), 0x0BAD), ca))
	unavailable := revOpts(func(*x509.Certificate) (*x509.RevocationList, *x509.Certificate, bool) { return nil, nil, false })
	staleListing := revOpts(crlFetcher(revPolicyCRL(t, ca, caKey, now.Add(-48*time.Hour), now.Add(-24*time.Hour), 0x0BAD), ca))

	// Premise: with no revocation checking the harvested cert resolves.
	if _, ok := ResolveRecipientCert(ctx, tx, senderID, "persist-target@resolve-revoke.test", nil); !ok {
		t.Fatal("premise: harvested cert must resolve with revocation checking disabled")
	}

	// Confirmation: the fresh listing CRL removes resolution and records it.
	if _, ok := ResolveRecipientCert(ctx, tx, senderID, "persist-target@resolve-revoke.test", freshListing); ok {
		t.Fatal("confirmed-revoked cert must not resolve")
	}

	// The HOLD: evidence loss must NOT resurrect the harvested key.
	for _, tc := range []struct {
		name string
		rev  *RevocationOptions
	}{
		{"unavailable evidence", unavailable},
		{"stale CRL", staleListing},
		{"no CRL source at all", revOpts(nil)},
	} {
		t.Run("after confirmation: "+tc.name, func(t *testing.T) {
			if _, ok := ResolveRecipientCert(ctx, tx, senderID, "persist-target@resolve-revoke.test", tc.rev); ok {
				t.Error("persisted confirmed revocation must keep the cert out of resolution")
			}
		})
	}
}
