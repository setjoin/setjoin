package smime

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"time"

	cms "github.com/github/smimesign/ietf-cms"
)

// Status values for VerifyResult.
const (
	// StatusValid: signature verifies, chains to a trusted root, has EmailProtection
	// EKU, is within its validity window, and the signer email matches the From address.
	StatusValid = "valid"

	// StatusInvalid: the signature or digest is cryptographically invalid, or the CMS
	// structure is unparseable. The message must be treated as unsigned.
	StatusInvalid = "invalid"

	// StatusUntrusted: the signature is cryptographically sound but fails the trust
	// policy: untrusted chain, missing EmailProtection EKU, expired cert, or From
	// address does not match any binding email on the signer certificate.
	StatusUntrusted = "untrusted"
)

// VerifyResult holds the graded verdict for an inbound detached S/MIME signature.
type VerifyResult struct {
	Status      string
	SignerEmail string
	SignerCN    string
	IssuerCN    string

	// LeafPEM is the verified signer leaf certificate, PEM-encoded. It is set ONLY
	// when Status == StatusValid (empty for every other verdict). Phase 2's inbound
	// harvest hook stores this for the receiving user so future encrypted replies can
	// target the signer — harvesting an untrusted/invalid signer must never happen, so
	// the field deliberately stays empty unless the trust + From-binding checks pass.
	LeafPEM string

	// TrustAnchorPEM is the trust anchor (root) of the VALIDATED chain — the last
	// certificate of the first pass-2 chain, PEM-encoded. It is set ONLY when
	// Status == StatusValid (empty for every other verdict). Round 5 (Astra HOLD):
	// the signer email's domain must be covered by the trust that validated the
	// chain, and that trust is exactly the anchor this chain terminated at — the
	// caller resolves which tenant domains this anchor actually grants
	// (smime_trust_anchors.domain_id) instead of inferring authority from the
	// claimed signer email. Like LeafPEM, it deliberately stays empty unless the
	// trust + From-binding checks pass.
	TrustAnchorPEM string

	// Revocation records the settled revocation-policy state for the signer
	// leaf: RevocationRevoked when positive evidence existed (a fresh,
	// signature-authenticated CRL from the certificate's issuer listing its
	// serial, or an admin blocklist entry — the explicit override), and
	// RevocationUnknown otherwise (no evidence available: no fetcher, fetch
	// failure, stale/expired CRL, wrong issuer, non-authentic CRL, or a
	// blocklist-store error). Revocation evidence downgrades the verdict to
	// StatusUntrusted — no verified-sender badge, no body-mutator exemption,
	// nothing harvestable — while the no-evidence case is fail-open (the badge
	// stays) with the key recorded revocation-unknown.
	Revocation string
}

// VerifyDetached grades a detached S/MIME signature in two passes:
//   - Pass 1 (StatusInvalid): CMS parse + cryptographic integrity using the embedded
//     certs as self-roots with CurrentTime anchored to the leaf's NotBefore+1ns — any
//     failure here means the bytes are corrupt (not just expired).
//   - Pass 2 (StatusUntrusted): chain verification against the caller's trusted roots
//     with ExtKeyUsageEmailProtection (which checks the validity window at now), and
//     From-address binding.
//
// It applies NO revocation policy (every verdict is recorded RevocationUnknown —
// fail-open). VerifyDetachedWithRevocation is the policy-carrying entry point.
//
// Never returns an error, never panics. Any failure maps to a Status.
func VerifyDetached(content, signatureDER []byte, fromAddr string, roots *x509.CertPool) *VerifyResult {
	return VerifyDetachedWithRevocation(context.Background(), content, signatureDER, fromAddr, roots, nil)
}

// VerifyDetachedWithRevocation is VerifyDetached with the settled
// revocation/freshness policy applied to the signer leaf. A nil rev disables
// the policy (identical to VerifyDetached). Positive revocation evidence — a
// fresh, signature-authenticated CRL from the certificate's issuer listing its
// serial, or an admin blocklist entry — downgrades the verdict to
// StatusUntrusted with Revocation=RevocationRevoked, which removes the
// verified-sender badge, the body-mutator exemption, and harvest targeting
// (LeafPEM/TrustAnchorPEM stay empty on that path). With no revocation evidence
// available the verdict is unaffected (fail-open) and the key is recorded
// RevocationUnknown. Invalid signatures remain StatusInvalid regardless of
// revocation data.
//
// The pass-2 chain supplies the chain-VALIDATED issuing certificate as the
// authority anchor, so CRL evidence is bound to the key that actually issued
// the leaf — a wrong-issuer or DN-colliding CRL never matches.
func VerifyDetachedWithRevocation(ctx context.Context, content, signatureDER []byte, fromAddr string, roots *x509.CertPool, rev *RevocationOptions) *VerifyResult {
	// Defensive: a nil pool would silently fall back to the OS system trust store
	// inside x509.Certificate.Verify, which is wrong for this bundled-only badge path.
	// Replace nil with an empty pool so pass 2 can only yield StatusUntrusted.
	if roots == nil {
		roots = x509.NewCertPool()
	}

	// --- Parse ---
	sd, err := cms.ParseSignedData(signatureDER)
	if err != nil {
		return &VerifyResult{Status: StatusInvalid, Revocation: RevocationUnknown}
	}

	// --- Pass 1: cryptographic integrity using the embedded certs as self-roots ---
	// Build a pool from all certs embedded in the SignedData.
	embeddedCerts, err := sd.GetCertificates()
	if err != nil {
		return &VerifyResult{Status: StatusInvalid, Revocation: RevocationUnknown}
	}
	selfPool := x509.NewCertPool()
	for _, c := range embeddedCerts {
		selfPool.AddCert(c)
	}

	// Find the signer leaf from embedded certs to anchor pass-1 CurrentTime.
	// This separates "cryptographically invalid" from "merely expired": an expired
	// cert is valid at some point in its window (NotBefore+1s), so pass 1 succeeds
	// (integrity OK), and pass 2 then fails on the current-time check → StatusUntrusted.
	signer := leafCert(embeddedCerts)

	pass1Opts := x509.VerifyOptions{
		Roots:     selfPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if signer != nil {
		// Anchor to 1ns after the cert's NotBefore — this is always within any
		// cert's validity window, so expiry doesn't affect pass-1 integrity judgement.
		pass1Opts.CurrentTime = signer.NotBefore.Add(1)
	}

	pass1Chains, err := sd.VerifyDetached(content, pass1Opts)
	if err != nil {
		return &VerifyResult{Status: StatusInvalid, Revocation: RevocationUnknown}
	}

	// --- Extract signer leaf (identity) from the pass-1 verified chains ---
	// chains is [][][]*x509.Certificate: one signer → one chain → certs in chain.
	// The leaf is chains[0][0][0].
	var leaf *x509.Certificate
	if len(pass1Chains) > 0 && len(pass1Chains[0]) > 0 && len(pass1Chains[0][0]) > 0 {
		leaf = pass1Chains[0][0][0]
	}
	if leaf == nil {
		// Fallback: use leafCert to prefer non-CA certs (should not happen after a successful verify).
		leaf = leafCert(embeddedCerts)
		if leaf == nil {
			return &VerifyResult{Status: StatusInvalid, Revocation: RevocationUnknown}
		}
	}

	res := &VerifyResult{
		SignerCN:    leaf.Subject.CommonName,
		IssuerCN:    leaf.Issuer.CommonName,
		SignerEmail: certEmail(leaf),
		Revocation:  RevocationUnknown,
	}

	// --- Pass 2: real trust — caller-supplied roots + EmailProtection EKU ---
	pass2Chains, err := sd.VerifyDetached(content, x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	})
	if err != nil {
		res.Status = StatusUntrusted
		return res
	}

	// --- Revocation policy: positive evidence strips the verified verdict ---
	// A fresh, signature-authenticated CRL from the leaf's issuer listing its
	// serial — or an admin blocklist entry — downgrades to StatusUntrusted with
	// Revocation=revoked: no badge, no body-mutator exemption, nothing
	// harvestable. No evidence (stale/wrong-issuer/non-authentic/unavailable)
	// is fail-open and stays recorded revocation-unknown. Runs BEFORE the
	// trust anchor is exposed so a revoked result never carries anchor
	// authority, and LeafPEM below is never set for it.
	if rev != nil && len(pass2Chains) > 0 && len(pass2Chains[0]) > 0 {
		// chain is leaf-first, root-last: the leaf's issuer is chain[1]
		// (chain[0] itself for a self-issued leaf).
		chain := pass2Chains[0][0]
		authority := chain[0]
		if len(chain) > 1 {
			authority = chain[1]
		}
		if evaluateRevocationAt(ctx, leaf, rev, time.Now(), authority) == RevocationRevoked {
			res.Revocation = RevocationRevoked
			res.Status = StatusUntrusted
			return res
		}
	}

	// Round 5 (Astra HOLD): remember WHICH trust anchor validated the chain. The
	// signer email's domain must be covered by THIS anchor's granted domains, not
	// merely asserted by the certificate — an anchor imported by tenant A must
	// never certify authority over tenant B's signer emails.
	res.TrustAnchorPEM = trustAnchorPEM(pass2Chains)

	// --- Identity binding: signer email must match fromAddr ---
	if !CertMatchesEmail(leaf, fromAddr) {
		res.Status = StatusUntrusted
		return res
	}

	// Fully valid: expose the verified leaf as PEM for the inbound harvest hook.
	// Only set here so an untrusted/invalid/expired signer is never harvestable.
	res.LeafPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	res.Status = StatusValid
	return res
}

// trustAnchorPEM returns the PEM of the trust anchor of the first validated
// chain — the LAST certificate, i.e. the root the caller's pool anchored at —
// or "" when no chain is available. chains is one slice per signer, each
// holding that signer's chains, each chain a root-to-leaf cert path. The empty
// result is fail-closed: callers that need anchor-derived authority must treat
// "" as "no validated anchor".
func trustAnchorPEM(chains [][][]*x509.Certificate) string {
	if len(chains) == 0 || len(chains[0]) == 0 {
		return ""
	}
	chain := chains[0][0]
	if len(chain) == 0 {
		return ""
	}
	anchor := chain[len(chain)-1]
	if anchor == nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchor.Raw}))
}

// leafCert returns the first non-CA cert from the list, or the first cert if all
// are CAs, or nil if the list is empty. Used to anchor the pass-1 CurrentTime.
func leafCert(certs []*x509.Certificate) *x509.Certificate {
	for _, c := range certs {
		if !c.IsCA {
			return c
		}
	}
	if len(certs) > 0 {
		return certs[0]
	}
	return nil
}

// CertEmails returns every binding email on the cert: all SAN rfc822Names plus the
// legacy Subject emailAddress OID (1.2.840.113549.1.9.1).
func CertEmails(cert *x509.Certificate) []string {
	out := append([]string(nil), cert.EmailAddresses...)
	oidEmail := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	for _, n := range cert.Subject.Names {
		if n.Type.Equal(oidEmail) {
			if s, ok := n.Value.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// certEmail returns the first binding email from the cert, or empty string.
func certEmail(cert *x509.Certificate) string {
	if e := CertEmails(cert); len(e) > 0 {
		return e[0]
	}
	return ""
}

// CertMatchesEmail returns true if any cert email equals fromAddr (case-insensitive).
// An empty fromAddr always returns false (fail-closed).
// Group/multi-mailbox From addresses won't match (also fail-closed by design).
func CertMatchesEmail(cert *x509.Certificate, fromAddr string) bool {
	want := strings.TrimSpace(fromAddr)
	if want == "" {
		return false
	}
	for _, e := range CertEmails(cert) {
		if strings.EqualFold(strings.TrimSpace(e), want) {
			return true
		}
	}
	return false
}
