package smime

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ── S/MIME revocation / freshness policy (one settled policy) ────────────────
//
// The SOLE revocation evidence for an S/MIME certificate is a FRESH and
// signature-AUTHENTICATED CRL issued by the certificate's issuer that lists the
// certificate's serial number, plus the admin blocklist
// (smime_revocation_blocklist) as the explicit override. Concretely:
//
//   - fresh: ThisUpdate ≤ now ≤ CRL.NextUpdate + MaxStaleness (the configured
//     maximum-staleness ceiling; DefaultMaxCRLStaleness when the caller does
//     not override). A FUTURE-DATED CRL (ThisUpdate in the future) or one with
//     an inverted [ThisUpdate, NextUpdate] interval is not evidence. An EXPIRED
//     CRL is stale evidence proving nothing in either direction and NEVER
//     revokes.
//   - authenticated: the CRL's signature verifies against the issuer
//     certificate the fetcher returned; that issuer's subject DER byte-matches
//     the certificate's issuer DER AND its key actually signed the leaf
//     (cert.CheckSignatureFrom — a same-DN same-AKI WRONG-KEY impostor still
//     fails this); and, when the caller can supply the chain-validated issuing
//     certificate as the authority anchor, the returned issuer must BE that
//     certificate. When both sides carry an Authority Key Identifier they must
//     match, so a DN-colliding CA cannot forge evidence for another CA's certs.
//   - lists: a RevokedCertificateEntries entry carries the certificate serial.
//
// The evaluation is a TRANSITION MATRIX over three states — revoked, clear,
// unknown — per certificate (fingerprint):
//
//	admin blocklist hit                          → revoked
//	durable confirmed revocation (stored)        → revoked (stands regardless of
//	                                               today's unavailable/stale/
//	                                               non-authentic/wrong-issuer
//	                                               evidence — a previously
//	                                               confirmed revocation is NEVER
//	                                               downgraded back to unknown)
//	fresh authenticated CRL listing the serial   → revoked + recorded durably
//	                                               (smime_cert_revocations, when
//	                                               RevocationOptions.Store is
//	                                               wired; record failure still
//	                                               yields revoked for THIS
//	                                               evaluation — the evidence
//	                                               exists now)
//	fresh authenticated CRL NOT listing it       → clear (positive non-listing
//	                                               evidence, deliberately
//	                                               distinguishable from
//	                                               unavailable; it is FRESHNESS-
//	                                               BOUND and never persisted —
//	                                               a later stale/unavailable
//	                                               result is unknown again)
//	unavailable / stale / future-dated /
//	non-authentic / wrong-issuer evidence        → unknown (fail-open)
//
// Positive evidence (either mechanism) removes the verified-sender badge, the
// body-mutator exemption, harvest targeting, and already-harvested
// encryption-target resolution. With NO revocation evidence available — no
// fetcher configured, fetch failure, stale CRL, wrong issuer, non-authentic
// CRL, or a blocklist-store error — verification is FAIL-OPEN (no badge
// removal) while the key is recorded RevocationUnknown. Invalid message
// signatures are refused by existing CMS verification regardless of revocation
// data.
//
// Caching of fetched CRLs belongs to the CRLFetchFunc implementation (the
// operational CRL source is an ops decision, deliberately not wired here); the
// seam stays injectable so tests and deployments supply their own source. No
// production code path performs network I/O through this seam.

// Revocation state recorded on VerifyResult.
const (
	// RevocationUnknown: no usable revocation evidence was available —
	// fail-open (no badge removal); the key is recorded revocation-unknown.
	RevocationUnknown = "unknown"

	// RevocationRevoked: positive revocation evidence existed — a fresh,
	// signature-authenticated CRL from the certificate's issuer listing its
	// serial, an admin blocklist entry (the explicit override), or a durable
	// previously confirmed revocation (smime_cert_revocations).
	RevocationRevoked = "revoked"

	// RevocationClear: fresh, signature-authenticated, issuer CRL evidence
	// that does NOT list the certificate — positive non-listing evidence,
	// deliberately distinguishable from RevocationUnknown (unavailable). It
	// is freshness-bound and never persisted, so it never upgrades to a
	// durable state and never blocks a later unknown. Like unknown it is NOT
	// revocation: fail-open (no badge removal).
	RevocationClear = "clear"
)

// RevocationEvidenceCRL marks a smime_cert_revocations row whose revocation
// was confirmed by fresh authenticated issuer CRL evidence.
const RevocationEvidenceCRL = "crl"

// DefaultMaxCRLStaleness is the default maximum-staleness ceiling: a CRL stays
// fresh evidence until NextUpdate + this grace. The numeric ceiling is an ops
// decision; callers configure RevocationOptions.MaxStaleness to override it.
const DefaultMaxCRLStaleness = 24 * time.Hour

// CRLFetchFunc returns the freshest available CRL relevant to cert, together
// with the certificate of the CA whose key signed it. ok=false (or a nil CRL /
// nil issuer) means revocation data is UNAVAILABLE — never an affirmative
// all-clear and never a revocation. Implementations own fetching AND caching;
// production ships no implementation (fail-open unknown) until an ops decision
// wires a source. Tests inject in-memory fixtures — never live HTTP/LDAP.
type CRLFetchFunc func(cert *x509.Certificate) (crl *x509.RevocationList, crlIssuer *x509.Certificate, ok bool)

// BlocklistFunc reports whether cert carries an admin blocklist entry
// (smime_revocation_blocklist). The blocklist is the EXPLICIT override: it
// revokes with no freshness requirement. A false return also covers "the
// blocklist store could not be consulted" — fail-open unknown, never revoked.
type BlocklistFunc func(ctx context.Context, cert *x509.Certificate) bool

// CertRevocationStore is the durable certificate-level revocation store behind
// the transition matrix: a revocation CONFIRMED by fresh authenticated issuer
// CRL evidence is recorded here and thereafter stands on its own — a later
// unavailable, stale, or non-authentic CRL result returns revoked, not
// unknown, so a previously revoked key can never resolve again through
// evidence loss. Keyed by certificate fingerprint (the repo-wide
// FingerprintCert convention), one row per confirmed certificate.
type CertRevocationStore interface {
	// IsRevoked reports whether the certificate carries a durably recorded
	// confirmed revocation. A lookup ERROR means the durable state cannot be
	// consulted: the caller falls through to live evidence (never revoked by
	// a recall failure alone).
	IsRevoked(ctx context.Context, fingerprint string) (bool, error)

	// RecordRevoked durably records a confirmed revocation with its evidence
	// kind (RevocationEvidenceCRL). Idempotent: re-confirming an already
	// recorded certificate must not duplicate or error.
	RecordRevoked(ctx context.Context, fingerprint, evidence string) error
}

// NewCertRevocationStore returns the DB-backed CertRevocationStore over the
// smime_cert_revocations table (fingerprint = lowercase-hex SHA-256 of the
// cert DER — the repo-wide FingerprintCert convention, same key shape as
// smime_revocation_blocklist, so both lookups are single-index EXISTS).
// Wired alongside a CRL source once the ops decision supplies one; the store
// itself needs no network — it is the durability half of the matrix.
func NewCertRevocationStore(q Querier) CertRevocationStore {
	return dbCertRevocationStore{q: q}
}

// dbCertRevocationStore is the Querier-backed implementation. A nil Querier
// makes every lookup a miss and every record a no-op: no durable state was
// wired, the matrix degrades to live evidence only.
type dbCertRevocationStore struct{ q Querier }

func (s dbCertRevocationStore) IsRevoked(ctx context.Context, fingerprint string) (bool, error) {
	if s.q == nil {
		return false, nil
	}
	var revoked bool
	err := s.q.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM smime_cert_revocations WHERE fingerprint = $1)`,
		fingerprint).Scan(&revoked)
	if err != nil {
		return false, err
	}
	return revoked, nil
}

func (s dbCertRevocationStore) RecordRevoked(ctx context.Context, fingerprint, evidence string) error {
	if s.q == nil {
		return nil
	}
	// The Querier seam is QueryRow-only, so the insert reports through
	// RETURNING: pgx.ErrNoRows means the conflict clause swallowed the insert
	// (already recorded) — an idempotent re-confirmation, not an error.
	var one int
	err := s.q.QueryRow(ctx,
		`INSERT INTO smime_cert_revocations (fingerprint, evidence) VALUES ($1, $2)
		 ON CONFLICT (fingerprint) DO NOTHING
		 RETURNING 1`,
		fingerprint, evidence).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}

// RevocationOptions carries the configured revocation-policy inputs. A nil
// *RevocationOptions means "no revocation checking configured": every
// certificate evaluates RevocationUnknown (fail-open).
type RevocationOptions struct {
	// MaxStaleness is the configured maximum-staleness ceiling: a CRL stays
	// fresh evidence until NextUpdate + MaxStaleness. Negative values are
	// treated as 0 (no grace beyond NextUpdate).
	MaxStaleness time.Duration

	// FetchCRL fetches the issuer CRL. nil = no CRL source configured (the
	// production default until an ops decision wires one) → revocation data
	// unavailable → fail-open unknown.
	FetchCRL CRLFetchFunc

	// Blocklist checks the admin blocklist. nil = no blocklist configured.
	Blocklist BlocklistFunc

	// Store is the durable certificate-level revocation store
	// (smime_cert_revocations via NewCertRevocationStore). nil = no durable
	// store wired: confirmed CRL revocations then stand only while their
	// fresh evidence remains fetchable, and the matrix degrades to
	// blocklist/live-evidence only. Wiring the store together with the
	// (still ops-deferred) CRL source makes a confirmed revocation permanent
	// across unavailable/stale/non-authentic evidence and restarts.
	Store CertRevocationStore
}

// maxStaleness normalizes the configured ceiling (negative → zero grace).
func (o *RevocationOptions) maxStaleness() time.Duration {
	if o == nil || o.MaxStaleness < 0 {
		return 0
	}
	return o.MaxStaleness
}

// EvaluateRevocation grades cert under the settled revocation policy (without a
// chain-validated authority anchor — the resolution-path shape) and returns
// RevocationRevoked, RevocationClear or RevocationUnknown per the transition
// matrix. It never returns an error and never performs I/O beyond the injected
// fetch/blocklist/store seams.
func EvaluateRevocation(ctx context.Context, cert *x509.Certificate, opts *RevocationOptions) string {
	return evaluateRevocationAt(ctx, cert, opts, time.Now(), nil)
}

// evaluateRevocationAt is the single policy core — the transition matrix:
//
//  0. nil cert/options → unknown.
//  1. Admin blocklist hit → revoked (the explicit override; durable in its own
//     admin-owned table and deliberately NOT re-recorded — removing the admin
//     row must stay the operator's un-revocation action).
//  2. Durable confirmed revocation (Store) → revoked, regardless of today's
//     evidence. This is the persistence guarantee: once confirmed, a cert can
//     never be downgraded back to unknown by evidence loss. A store LOOKUP
//     error is not a revocation: evaluation falls through to live evidence.
//  3. Live CRL evidence: unavailable/stale/future-dated/wrong-issuer/
//     non-authentic → unknown; listing the serial → revoked and durably
//     recorded (best-effort — a record failure cannot un-confirm evidence that
//     exists right now, so the return is still revoked); fresh authenticated
//     and NOT listing → clear.
//
// authority, when non-nil, is the chain-VALIDATED issuing certificate (the
// verify path): the fetcher's returned issuer must be byte-identical to it, so
// revocation evidence is bound to the same key the trust evaluation just
// validated, not to a colliding DN.
func evaluateRevocationAt(ctx context.Context, cert *x509.Certificate, opts *RevocationOptions, now time.Time, authority *x509.Certificate) string {
	if cert == nil || opts == nil {
		return RevocationUnknown
	}
	// 1. Admin blocklist — the explicit override, no freshness requirement.
	if opts.Blocklist != nil && opts.Blocklist(ctx, cert) {
		return RevocationRevoked
	}
	// 2. Durable confirmed revocation — persists across unavailable, stale,
	//    future-dated, non-authentic, and wrong-issuer results. A recall error
	//    is "durable state unavailable", never "revoked".
	if opts.Store != nil {
		if revoked, err := opts.Store.IsRevoked(ctx, FingerprintCert(cert)); err == nil && revoked {
			return RevocationRevoked
		}
	}
	// 3. Fresh, signature-authenticated, issuer CRL listing the serial.
	if opts.FetchCRL == nil {
		return RevocationUnknown
	}
	crl, crlIssuer, ok := opts.FetchCRL(cert)
	if !ok || crl == nil || crlIssuer == nil {
		return RevocationUnknown // unavailable → fail-open unknown
	}
	if !crlIssuerMatches(cert, crl, crlIssuer, authority) {
		return RevocationUnknown // wrong issuer → not evidence
	}
	if err := cert.CheckSignatureFrom(crlIssuer); err != nil {
		// The issuer-name match (DN/AKI) does not prove the supplied issuer's
		// key signed THIS leaf. In the unanchored resolution path a same-DN
		// impostor can copy the AKI — or omit identifiers entirely — and its
		// CRLs are perfectly authentic FOR ITSELF. Only the leaf's own
		// signature under the supplied key binds the evidence to the real
		// issuing key; a wrong-key issuer never passes.
		return RevocationUnknown // wrong-key issuer → did not sign this leaf
	}
	if err := crl.CheckSignatureFrom(crlIssuer); err != nil {
		return RevocationUnknown // non-authentic → not evidence
	}
	if !crlIsFresh(crl, opts.maxStaleness(), now) {
		// Stale (beyond NextUpdate + ceiling), future-dated (ThisUpdate in
		// the future), inverted interval, or no NextUpdate: proves nothing,
		// never revokes.
		return RevocationUnknown
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber != nil && entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			// Confirmed revocation: durably record it so evidence loss can
			// never resurrect the key. Best-effort — the live evidence is
			// valid NOW, so a store failure still yields revoked for this
			// evaluation; durability resumes with the next confirmation.
			if opts.Store != nil {
				_ = opts.Store.RecordRevoked(ctx, FingerprintCert(cert), RevocationEvidenceCRL)
			}
			return RevocationRevoked
		}
	}
	return RevocationClear // fresh authenticated non-listing evidence
}

// crlIssuerMatches binds the CRL to the certificate's issuer:
//   - the returned issuer certificate must BE the certificate's issuer (its
//     subject DER byte-matches the cert's issuer DER — DER equality is the
//     strict RFC 5280 name match) and must be the CRL's named issuer;
//   - with a chain-validated authority anchor, it must additionally BE that
//     exact certificate (full DER equality), so a same-DN different-key CA can
//     never issue revocation evidence for a cert it did not issue;
//   - when both the cert and the CRL carry an Authority Key Identifier, the
//     identifiers must match (the no-anchor resolution path's key binding —
//     Go auto-derives SKI/AKI for CAs, so colliding-DN evidence is rejected
//     there too; a missing-AKI chain falls back to the DN + signature checks).
//
// Name-and-identifier matching alone does NOT prove the supplied issuer signed
// the leaf — identifiers can be copied and can be absent. The core therefore
// additionally requires cert.CheckSignatureFrom(crlIssuer) to hold (see
// evaluateRevocationAt), which is the actual key binding: only the holder of
// the real issuing key passes it.
func crlIssuerMatches(cert *x509.Certificate, crl *x509.RevocationList, crlIssuer *x509.Certificate, authority *x509.Certificate) bool {
	if !bytes.Equal(cert.RawIssuer, crlIssuer.RawSubject) || !bytes.Equal(crl.RawIssuer, crlIssuer.RawSubject) {
		return false
	}
	if authority != nil && !bytes.Equal(crlIssuer.Raw, authority.Raw) {
		return false
	}
	if len(cert.AuthorityKeyId) > 0 && len(crl.AuthorityKeyId) > 0 &&
		!bytes.Equal(cert.AuthorityKeyId, crl.AuthorityKeyId) {
		return false
	}
	return true
}

// crlIsFresh applies the two-sided freshness rule; a CRL is usable evidence
// only when the whole [ThisUpdate, NextUpdate + ceiling] window is valid:
//   - no ThisUpdate or no NextUpdate (zero time): no usable validity bound —
//     not evidence;
//   - NextUpdate before ThisUpdate: an inverted validity interval — a
//     malformed or forged CRL is never evidence;
//   - now before ThisUpdate: a FUTURE-DATED CRL is not yet evidence — a
//     forged pre-dated list must not revoke anything in the present;
//   - otherwise evidence stays fresh until NextUpdate + the configured
//     staleness ceiling; past that the CRL is stale evidence proving nothing
//     in either direction.
func crlIsFresh(crl *x509.RevocationList, staleness time.Duration, now time.Time) bool {
	if crl.ThisUpdate.IsZero() || crl.NextUpdate.IsZero() {
		return false
	}
	if crl.NextUpdate.Before(crl.ThisUpdate) {
		return false // inverted [ThisUpdate, NextUpdate] interval
	}
	if now.Before(crl.ThisUpdate) {
		return false // future-dated: not yet evidence
	}
	return !now.After(crl.NextUpdate.Add(staleness))
}

// BlocklistCheckFunc returns a BlocklistFunc backed by the
// smime_revocation_blocklist table (fingerprint = lowercase-hex SHA-256 of the
// cert DER — the repo-wide FingerprintCert convention). Any DB error means the
// blocklist could not be consulted → false (fail-open unknown), never revoked.
func BlocklistCheckFunc(q Querier) BlocklistFunc {
	return func(ctx context.Context, cert *x509.Certificate) bool {
		if q == nil || cert == nil {
			return false
		}
		var blocked bool
		err := q.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM smime_revocation_blocklist WHERE fingerprint = $1)`,
			FingerprintCert(cert)).Scan(&blocked)
		return err == nil && blocked
	}
}
