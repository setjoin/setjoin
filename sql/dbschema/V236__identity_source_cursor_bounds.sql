-- V236: identity-source sync cursor bounds (prune + CHECK layer).
--
-- Security remediation (D-MAILSERVER-INTERNAL-IDENTITYSOURCE-001, CWE-770):
-- the directory-derived sync cursor was persisted unbounded across the three
-- cursor-bearing tables — identity_source_batches.remote_cursor,
-- identity_source_inbox.remote_cursor (one copy per staged entry, up to 500),
-- and identity_sources.pending_cursor/committed_cursor — so a rogue
-- 'ldap'-kind directory returning an adversarially large modifyTimestamp
-- could amplify WAL/disk up to ~502x per staged page on every sync cycle,
-- surviving restarts via committed_cursor.
--
-- Layer 1 (prune/normalize): already-persisted oversized cursors are
-- normalized — source columns to NULL, batch/inbox copies to '{}'::jsonb.
-- Both connector decoders (AD usnCursor, LDAP stampCursor) treat the
-- normalized value as an empty cursor, so the next cycle performs one full
-- resync instead of resuming from a poisoned position. Row-internal digest
-- consistency is preserved (remote_cursor_digest = sha256 of the stored
-- cursor text); the original digests survive in the append-only
-- identity_link_events ledger and identity_sync_log.details. The
-- normalization runs through a one-shot SECURITY DEFINER function owned by
-- setjoin_worker because identity_source_batches and identity_source_inbox
-- are FORCE ROW LEVEL SECURITY with no owner policy while migrations run as
-- the NOBYPASSRLS setjoin_owner; the function is dropped after use.
--
-- Layer 2 (CHECK constraints): every cursor column is bounded to 4096
-- normalized octets, matching MaxCursorBytes in
-- internal/identitysource/pipeline.go and the octet_length guard in
-- identity_source_batch_begin.

CREATE FUNCTION public.identity_source_cursor_prune() RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    -- A pruned committed/pending cursor resumes nothing: NULL makes the
    -- connector re-read from the beginning on the next cycle.
    UPDATE public.identity_sources
       SET committed_cursor = NULL, committed_cursor_digest = NULL
     WHERE committed_cursor IS NOT NULL
       AND octet_length(committed_cursor::text) > 4096;
    UPDATE public.identity_sources
       SET pending_cursor = NULL, pending_cursor_digest = NULL
     WHERE pending_cursor IS NOT NULL
       AND octet_length(pending_cursor::text) > 4096;

    -- Open batches keep draining (resume -> apply -> finish) with a bounded
    -- placeholder cursor; per-entry copies are normalized in the same pass so
    -- identity_source_batch_begin's replay digest comparisons stay consistent.
    UPDATE public.identity_source_batches
       SET remote_cursor = '{}'::jsonb,
           remote_cursor_digest = digest('{}'::jsonb::text, 'sha256')
     WHERE octet_length(remote_cursor::text) > 4096;
    UPDATE public.identity_source_inbox
       SET remote_cursor = '{}'::jsonb,
           remote_cursor_digest = digest('{}'::jsonb::text, 'sha256')
     WHERE octet_length(remote_cursor::text) > 4096;
END;
$$;
SELECT public.apply_worker_ownership(
    'public.identity_source_cursor_prune()'::regprocedure
);
SELECT public.identity_source_cursor_prune();
DROP FUNCTION public.identity_source_cursor_prune();

ALTER TABLE public.identity_sources
    ADD CONSTRAINT identity_sources_committed_cursor_bound_check
    CHECK (octet_length(committed_cursor::text) <= 4096);
ALTER TABLE public.identity_sources
    ADD CONSTRAINT identity_sources_pending_cursor_bound_check
    CHECK (octet_length(pending_cursor::text) <= 4096);
ALTER TABLE public.identity_source_batches
    ADD CONSTRAINT identity_source_batches_cursor_bound_check
    CHECK (octet_length(remote_cursor::text) <= 4096);
ALTER TABLE public.identity_source_inbox
    ADD CONSTRAINT identity_source_inbox_cursor_bound_check
    CHECK (octet_length(remote_cursor::text) <= 4096);

INSERT INTO public.schema_migrations(version, applied_at)
VALUES (236, now()) ON CONFLICT DO NOTHING;
