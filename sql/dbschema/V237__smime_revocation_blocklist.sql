-- ════════════════════════════════════════════════════════════════════════
-- V237__smime_revocation_blocklist.sql — the S/MIME admin revocation
-- blocklist (med-smime-revocation-001).
--
-- The explicit revocation override in the settled S/MIME revocation/freshness
-- policy: an entry here revokes a signer/encryption-target certificate with no
-- freshness requirement, the same effect as a fresh, signature-authenticated
-- issuer CRL listing its serial (internal/smime/revocation.go). No CRL source
-- is wired — the operational CRL feed is an ops decision — so until one exists
-- this table is the only positive revocation evidence.
--
-- Keyed by fingerprint: the lowercase-hex SHA-256 of the blocked certificate's
-- DER — the same repo-wide fingerprint convention as recipient_smime_certs,
-- smime_trust_anchors and smime_journal_certs, and exactly what
-- smime.FingerprintCert computes, so the Go-side BlocklistCheckFunc lookup is
-- a single-index EXISTS. Administration (who writes rows; UI/CLI surface) is
-- an open ops decision — rows are written by SQL/admin tooling for now.
-- No user-owned data (like smime_trust_anchors/smime_journal_certs): no RLS.
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.smime_revocation_blocklist (
    id          bigserial PRIMARY KEY,
    fingerprint text NOT NULL,
    reason      text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  bigint
);

-- One blocklist entry per certificate fingerprint (NULLS NOT DISTINCT is not
-- needed: fingerprint is NOT NULL).
CREATE UNIQUE INDEX IF NOT EXISTS smime_revocation_blocklist_fingerprint_key
    ON public.smime_revocation_blocklist (fingerprint);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (237, now())
    ON CONFLICT DO NOTHING;
