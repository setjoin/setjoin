-- ════════════════════════════════════════════════════════════════════════
-- V015__smime_trust_anchors.sql — forward migration (S/MIME admin trust store).
--
-- Org-imported private-CA roots so air-gapped / internal-PKI deployments verify
-- internally-issued S/MIME certs that never chain to a public CA. PER-TENANT
-- scoped via domain_id (NULL = deployment-wide, super-admin only) — the inbound
-- verifier (Phase A) chains against the bundled Mozilla roots UNION the anchors
-- visible to the RECIPIENT's domain, so one tenant cannot grant trust in another.
-- Global admin config (like feature_toggles) plus domain scoping; reachable only
-- behind admin perms.
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.smime_trust_anchors (
    id          bigserial PRIMARY KEY,
    label       text NOT NULL,
    cert_pem    text NOT NULL,
    subject_cn  text,
    fingerprint text NOT NULL,
    domain_id   bigint,
    not_before  timestamptz,
    not_after   timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  bigint
);

CREATE INDEX IF NOT EXISTS smime_trust_anchors_domain_idx ON public.smime_trust_anchors (domain_id);

-- Per-tenant unique: same fingerprint may appear once per (fingerprint, domain_id) pair.
-- NULLS NOT DISTINCT means two NULL domain_ids (deployment-wide) also deduplicate.
CREATE UNIQUE INDEX IF NOT EXISTS smime_trust_anchors_fp_domain_key
    ON public.smime_trust_anchors (fingerprint, domain_id) NULLS NOT DISTINCT;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (15, now())
    ON CONFLICT (version) DO NOTHING;
