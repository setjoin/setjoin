-- ════════════════════════════════════════════════════════════════════════
-- V262__gal_visibility_journal.sql — per-mailbox GAL visibility journal
-- (CARDDAV-V-002; triage D-MAILSERVER-INTERNAL-CARDDAV-V-002, disposition
-- "hardening", CWE-863).
--
-- FINDING. The read-only GAL CardDAV collection's sync delta (gal_changes)
-- computed its RFC 6578 "removed" set over ALL users touched since the token
-- who are no longer in directory_visible_users — outside the ADR-004 seam's
-- "previously visible to THIS caller" axis. A never-visible user (invisible
-- to this caller since before the token) whose updated_at bumps inside the
-- same token window as a currently-visible member's hard-delete could be
-- rendered as a removed /gal/u{id}.vcf href: a racy, content-free id-and-
-- timing oracle for directory ids the caller was never entitled to see (the
-- count guard only trips valid-sync-token when the arithmetic happens NOT to
-- balance; when it balances by coincidence the id leaks).
--
-- FIX. Distinguish "removed" from "never seen". The journal records exactly
-- which directory members each caller's primary mailbox has actually been
-- DISCLOSED (rendered as a card, listed in a PROPFIND/query/multiget, or
-- reported in a sync delta). gal_changes then reports a removal ONLY for a
-- journaled user — a never-visible id is structurally impossible to disclose
-- because it was never journaled, regardless of any count arithmetic. The
-- hard-delete count guard keeps its role as the full-resync trigger (a
-- hard-deleted row's updated_at is gone, so the equation breaks and the
-- client full-syncs); the journal makes the race's residual harmless.
--
-- Writers (the ONLY surfaces that insert here):
--   gal_visibility_record(p_mailbox_id, p_user_ids) — the render-path seam;
--     the CardDAV gateway calls it with the ids a response is about to
--     disclose (PROPFIND depth-1 listing, GET, addressbook-query,
--     addressbook-multiget). gal_changes PERFORMs it for the changed set of
--     every sync delta, so a disclosed presence is journaled atomically with
--     the response that disclosed it.
--   gal_changes — filters its removed set through gal_journal_seen().
-- Rows are never deleted here (they cascade only when the underlying
-- mailbox/user row dies — a journaled id whose row is gone is a hard-delete,
-- which is the count guard's resync territory). Steady-state cost is one
-- no-op INSERT per already-journaled id (ON CONFLICT DO NOTHING); the table
-- is bounded by (mailboxes × directory members ever disclosed).
--
-- BOOTSTRAP. Journal rows for pre-migration disclosures do not exist, so a
-- client holding a pre-V262 token whose previously-visible member goes
-- invisible may miss that one removal — the count equation then breaks
-- (the removal is not in v_gone) and the client is forced to resync, which
-- journals every visible member. New initial syncs (token 0) journal the
-- whole visible set by construction. The gap is self-healing in exactly one
-- resync and never over-discloses.
--
-- ISOLATION POSTURE (R4): per-mailbox user-data keyed on mailbox_id —
-- ENABLE + FORCE ROW LEVEL SECURITY with ZERO permissive policies (the
-- V246/V249/V253/V259 deny-all posture), ownership with setjoin_owner. The
-- runtime roles touch NOTHING here directly: every read and write goes
-- through the worker-owned SECURITY DEFINER reducers above (R1 BY
-- RESOLUTION — the reducer validates the caller mailbox in-DB and filters
-- the id set through directory_visible_users itself; the gateway can only
-- ever widen nothing). FORCE binds the owner too, so ENABLE alone cannot
-- silently no-op the posture.
--
-- r2 (hold finding): those SECURITY DEFINER reducers are loaded from
-- reducers/ (this migration owns the TABLE only — reducers stay out of
-- migrations post-collapse, ARCH-007) and schema-qualify every relation they
-- touch — the journal, mailboxes, and the directory_visible_users seam — with
-- `SET search_path = pg_catalog, public, pg_temp` (pg_temp LAST), so a
-- caller-planted TEMP table can never shadow the journal or redirect the
-- privileged writer. Pinned by tests/gal_visibility_journal.pg section 10.
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE public.gal_visibility_journal (
    mailbox_id     BIGINT      NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
    user_id        BIGINT      NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    -- One row per (viewer mailbox, disclosed directory member). The viewer is
    -- the caller's PRIMARY mailbox (the ADR-004 seam's p_mailbox_id axis).
    CONSTRAINT gal_visibility_journal_mailbox_user_key UNIQUE (mailbox_id, user_id)
);

-- The removed-set lookup joins (mailbox_id, user_id) — the unique constraint's
-- btree serves it. This index covers the user-side FK (user hard-deletes must
-- not seq-scan the journal to cascade).
CREATE INDEX gal_visibility_journal_user_idx
    ON public.gal_visibility_journal (user_id);

COMMENT ON TABLE public.gal_visibility_journal IS
  'Per-mailbox GAL visibility journal (V262, CARDDAV-V-002): which directory '
  'members each caller''s primary mailbox has been disclosed. gal_changes '
  'reports a sync-collection removal only for a journaled user, so a '
  'never-visible directory id can never be rendered as removed (the '
  'id-and-timing residual the count guard alone could not close). Written '
  'only by the worker-owned SECURITY DEFINER reducers '
  'gal_visibility_record/gal_changes (gal_journal_seen reads); FORCE RLS '
  'deny-all to every runtime role.';

ALTER TABLE public.gal_visibility_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gal_visibility_journal FORCE ROW LEVEL SECURITY;

-- ── Ownership: the NOBYPASSRLS DDL owner owns the table (V246/V249/V253
-- form) so FORCE binds the owner too. setjoin_owner is provisioned by
-- scripts/provision-roles.sql (loader step 0/4 runs before migrations); the
-- guard keeps a role-less cluster (fresh CI) loading.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
        ALTER TABLE public.gal_visibility_journal OWNER TO setjoin_owner;
    END IF;
END $$;

-- ── Schema migration record (V060 bookkeeping form) ─────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (262, now())
    ON CONFLICT (version) DO NOTHING;
