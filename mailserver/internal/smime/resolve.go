package smime

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"time"
)

// IsEncryptionCapable reports whether cert can be used as an S/MIME EnvelopedData
// recipient: an RSA public key AND (keyUsage includes KeyUsageKeyEncipherment OR
// the cert has no keyUsage extension at all). It mirrors smime.Encrypt's RSA-only
// rule (smime.go: "recipient certificate must have RSA public key") so a cert
// that passes resolution can never 500 at the encrypt step.
//
// This is the SINGLE shared predicate: the submission check and the encrypt step
// both call it, so "can I encrypt to this cert?" has exactly one answer.
func IsEncryptionCapable(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	// RSA gate — matches Encrypt's recipient public-key requirement exactly.
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		return false
	}
	// keyUsage gate. Go sets cert.KeyUsage to 0 when the extension is absent;
	// absent = unrestricted = capable (the A1 dual-cert rule). A present keyUsage
	// that lacks keyEncipherment is a sign-only cert → not capable.
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		return false
	}
	return true
}

// resolveCandidate is a parsed, eligible cert plus the timestamp it's ranked by.
type resolveCandidate struct {
	cert     *x509.Certificate
	lastSeen time.Time
}

// ResolveRecipientCert returns the cert to encrypt TO for recipientEmail, scoped
// to senderUserID. It unions internal user_smime_certs (the org directory, by
// canonicalized email) with recipient_smime_certs owned by senderUserID, filters
// to ENCRYPTION-CAPABLE (IsEncryptionCapable) AND currently-valid (now within the
// PARSED cert's [NotBefore, NotAfter] — never the stored columns, defense in
// depth) AND NOT-REVOKED under the settled revocation policy (a rev-blocklisted
// cert, or one covered by a fresh, signature-authenticated issuer CRL listing
// its serial, is removed as an encryption target — including already-harvested
// rows; no evidence is fail-open, the candidate stays), and returns the
// most-recently-last_seen valid one. ok=false when none qualifies, on a DB error
// (fail-closed), or on an empty recipient. A nil rev disables revocation
// filtering.
//
// The SAME predicate (IsEncryptionCapable) gates both this resolution and the
// later encrypt step, so a cert offered here cannot fail at encrypt.
func ResolveRecipientCert(ctx context.Context, q Querier, senderUserID int64, recipientEmail string, rev *RevocationOptions) (*x509.Certificate, bool) {
	if q == nil {
		return nil, false
	}
	email := CanonRecipientEmail(ctx, q, recipientEmail)
	if email == "" {
		return nil, false
	}

	now := time.Now()
	var candidates []resolveCandidate

	add := func(pemStr string, lastSeen time.Time) {
		cert, err := ParseCert([]byte(pemStr))
		if err != nil {
			return // skip unparseable rows
		}
		if !IsEncryptionCapable(cert) {
			return
		}
		// Binding re-verification (D-MAILSERVER-INTERNAL-SMIME-004,
		// defense in depth at the consumption point): the resolved cert must
		// actually BIND the queried recipient address (SAN rfc822Name or the
		// legacy Subject email OID). Every writer is gated upstream, but a
		// mis-filed row — admin error or a future writer bug — must fail
		// resolution closed instead of silently redirecting encrypted mail to
		// the wrong key holder.
		if !CertMatchesEmail(cert, email) {
			return
		}
		// Authoritative validity window is the parsed cert's, never the stored col.
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return
		}
		// Revocation policy: positive evidence (admin blocklist override, or a
		// fresh authenticated issuer CRL listing the serial) removes the cert as
		// an encryption target even though it was already harvested. No
		// evidence (stale/wrong-issuer/non-authentic/unavailable) is fail-open.
		// Resolution holds no validated chain, so no authority anchor is passed;
		// AKI equality still binds the CRL to the cert's issuer when present.
		if evaluateRevocationAt(ctx, cert, rev, now, nil) == RevocationRevoked {
			return
		}
		candidates = append(candidates, resolveCandidate{cert: cert, lastSeen: lastSeen})
	}

	// Internal directory certs (user's OWN signing certs serve as encrypt-to
	// certs for an internal recipient). Rank by created_at as the freshness proxy
	// (user_smime_certs has no last_seen). A DB error → fail-closed.
	if !scanCerts(ctx, q,
		`SELECT sc.cert_pem, sc.created_at
		   FROM user_smime_certs sc
		   JOIN users u ON u.id = sc.user_id
		  WHERE u.email = $1`,
		add, email) {
		return nil, false
	}

	// Harvested / imported recipient certs owned by the sender.
	if !scanCerts(ctx, q,
		`SELECT cert_pem, last_seen
		   FROM recipient_smime_certs
		  WHERE owner_user_id = $1 AND email = $2`,
		add, senderUserID, email) {
		return nil, false
	}

	if len(candidates) == 0 {
		return nil, false
	}
	best := candidates[0]
	for _, c := range candidates[1:] {
		if c.lastSeen.After(best.lastSeen) {
			best = c
		}
	}
	return best.cert, true
}

// scanCerts runs a (cert_pem, last_seen) query and feeds each row to add. The
// Querier seam is QueryRow-only, so multi-row results are gathered via a single
// QueryRow that aggregates rows into arrays (pgx returns them as a single row),
// keeping the seam minimal while still unioning many certs. Returns false on a
// DB error (fail-closed) — distinct from "zero rows" (returns true, no adds).
func scanCerts(ctx context.Context, q Querier, sql string, add func(string, time.Time), args ...any) bool {
	// Wrap the caller's SELECT so a single QueryRow returns parallel arrays of
	// every matching (cert_pem, last_seen) — the Querier seam has no multi-row
	// Query, and resolution sets are tiny (a handful of certs per email).
	wrapped := `SELECT
		COALESCE(array_agg(t.cert_pem), '{}')::text[] AS pems,
		COALESCE(array_agg(t.ts), '{}')::timestamptz[] AS tss
		FROM (` + sql + `) AS t(cert_pem, ts)`
	var pems []string
	var tss []time.Time
	if err := q.QueryRow(ctx, wrapped, args...).Scan(&pems, &tss); err != nil {
		return false
	}
	for i := range pems {
		var ts time.Time
		if i < len(tss) {
			ts = tss[i]
		}
		add(pems[i], ts)
	}
	return true
}
