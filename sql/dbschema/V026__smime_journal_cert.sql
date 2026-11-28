-- ════════════════════════════════════════════════════════════════════════
-- V026__smime_journal_cert.sql — forward migration (SP1 Phase 3: journal-cert
-- config — the enforcement source for smime_encrypt_no_journal_cert).
--
-- When journaling is REQUIRED for a sender's domain, an encrypt-requested
-- submission must add a journal cert as an extra RecipientInfo (encrypt-to-
-- journal) so the archived copy is readable. SP1 enforces against THIS table;
-- the admin UI to populate it is SP2. Mirrors smime_trust_anchors: a NULL
-- domain_id row is deployment-wide; a domain-specific row wins.
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.smime_journal_certs (
    id          bigserial PRIMARY KEY,
    domain_id   bigint REFERENCES public.domains(id) ON DELETE CASCADE,
    cert_pem    text NOT NULL,
    fingerprint text NOT NULL,
    not_before  timestamptz,
    not_after   timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  bigint
);

-- Dedup key. NULLS NOT DISTINCT so a single deployment-wide (NULL-domain) cert
-- with a given fingerprint cannot be inserted twice (mirrors smime_trust_anchors).
CREATE UNIQUE INDEX IF NOT EXISTS smime_journal_certs_fp_domain_key
    ON public.smime_journal_certs (fingerprint, domain_id) NULLS NOT DISTINCT;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (26, now())
    ON CONFLICT (version) DO NOTHING;
