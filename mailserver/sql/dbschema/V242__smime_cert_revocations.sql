-- ════════════════════════════════════════════════════════════════════════
-- V242__smime_cert_revocations.sql — durable certificate-level S/MIME
-- revocation (med-smime-revocation-001, Astra HOLD: confirmed CRL revocation
-- was not persisted).
--
-- The durability half of the settled revocation transition matrix
-- (internal/smime/revocation.go): a revocation CONFIRMED by fresh,
-- signature-authenticated issuer CRL evidence is recorded here and thereafter
-- stands on its own — a subsequent unavailable, stale, future-dated, or
-- non-authentic CRL result returns revoked, never unknown, so a previously
-- revoked harvested key can no longer resolve as an encryption target through
-- evidence loss. Fresh authenticated NON-listing evidence (the `clear` state)
-- is deliberately NOT persisted: it is freshness-bound and expires with its
-- CRL.
--
-- Keyed by fingerprint: the lowercase-hex SHA-256 of the revoked certificate's
-- DER — the same repo-wide fingerprint convention as
-- smime_revocation_blocklist, recipient_smime_certs, smime_trust_anchors and
-- smime_journal_certs, and exactly what smime.FingerprintCert computes, so the
-- Go-side store lookup (NewCertRevocationStore.IsRevoked) is a single-index
-- EXISTS. `evidence` names what confirmed the revocation
-- (smime.RevocationEvidenceCRL today). Rows are written only by the Go policy
-- core on a confirmed revocation; removal is an explicit admin action (SQL/
-- admin tooling) and is the only way a confirmed revocation is undone.
-- No user-owned data (like smime_revocation_blocklist): no RLS.
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.smime_cert_revocations (
    id          bigserial PRIMARY KEY,
    fingerprint text NOT NULL,
    evidence    text NOT NULL DEFAULT '',
    revoked_at  timestamptz NOT NULL DEFAULT now()
);

-- One revocation record per certificate fingerprint (fingerprint is NOT NULL,
-- so NULLS NOT DISTINCT is not needed).
CREATE UNIQUE INDEX IF NOT EXISTS smime_cert_revocations_fingerprint_key
    ON public.smime_cert_revocations (fingerprint);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (242, now())
    ON CONFLICT DO NOTHING;
