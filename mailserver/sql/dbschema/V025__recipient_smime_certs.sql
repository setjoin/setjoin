-- ════════════════════════════════════════════════════════════════════════
-- V025__recipient_smime_certs.sql — forward migration (SP1: recipient cert store).
--
-- The certs a user can encrypt TO (distinct from user_smime_certs, the user's
-- OWN signing certs). PER-USER scoped via owner_user_id (R1) — a user only sees
-- certs harvested from / imported for THEIR OWN mail; no cross-user leak. Certs
-- are PUBLIC data, stored in the DB as TEXT (a few KB each), NOT in the S3 blob /
-- ref_count machinery (that's for message bodies + attachments). Dedup by
-- (owner_user_id, email, fingerprint); re-harvest bumps last_seen (upsert).
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.recipient_smime_certs (
    id            bigserial PRIMARY KEY,
    owner_user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    email         text NOT NULL,
    cert_pem      text NOT NULL,
    fingerprint   text NOT NULL,
    not_before    timestamptz,
    not_after     timestamptz,
    source        text NOT NULL,
    first_seen    timestamptz NOT NULL DEFAULT now(),
    last_seen     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT recipient_smime_certs_source_check
        CHECK (source IN ('harvested', 'imported')),
    -- Dedup key: the same cert harvested from 50 messages = one row. A table-level
    -- UNIQUE CONSTRAINT (not a bare unique index) so it doubles as the Phase-2
    -- upsert ON CONFLICT target AND is visible to pgTAP's col_is_unique.
    CONSTRAINT recipient_smime_certs_dedup_key
        UNIQUE (owner_user_id, email, fingerprint)
);

-- Resolution looks up by (owner_user_id, email); index it.
CREATE INDEX IF NOT EXISTS recipient_smime_certs_owner_email_idx
    ON public.recipient_smime_certs (owner_user_id, email);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (25, now())
    ON CONFLICT (version) DO NOTHING;
