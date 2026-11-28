-- ════════════════════════════════════════════════════════════════════════
-- V095__entity_changes_journal.sql — A4: generalize the JMAP change journal to
-- ALL datatypes (Email + the PIM satellites Task/ContactCard/AddressBook/
-- Calendar/CalendarEvent) so /changes can return real created/updated/destroyed
-- deltas instead of always raising BZ011 (cannotCalculateChanges → full resync).
--
-- Two structural changes:
--   1. jmap_changes_journal gains a `datatype` discriminator; `message_id` is
--      renamed `entity_id` (email = datatype 'email', entity_id = message_id — the
--      append_email_change shim + jmap_email_changes keep working unchanged).
--   2. A per-(mailbox,datatype) MONOTONIC state counter `jmap_entity_state`. The
--      satellites previously derived their /changes token as MAX(child.jmap_state),
--      which is NOT monotonic (updating a non-max row leaves MAX unmoved → the
--      change is silently dropped; destroying the max row makes MAX regress). A
--      single atomic counter (mirror of mailboxes.jmap_email_state) is the only
--      cursor a journal can key to. See the AUTOPLAN GAUNTLET REVIEW (F2) in
--      docs/superpowers/plans/archive/2026-07-05-satellite-changes-deltas-A4.md.
--
-- Destroyed-tracking is done with AFTER INSERT/UPDATE/DELETE triggers (this file,
-- Task; the other datatypes in their own migrations) so FK ON DELETE CASCADE
-- (parent-task → subtasks) journals every vanished child precisely — a hand-wired
-- append in the set reducer would miss the cascade and leave ghost rows forever (F1).
-- No data seed: with an empty journal the first /changes returns BZ011 (correct
-- resync-once for a datatype that just gained delta support), then precise deltas.
-- ════════════════════════════════════════════════════════════════════════

-- ── 1. Generalize the journal in place ───────────────────────────────────────
ALTER TABLE public.jmap_changes_journal RENAME COLUMN message_id TO entity_id;
ALTER TABLE public.jmap_changes_journal
  ADD COLUMN IF NOT EXISTS datatype TEXT NOT NULL DEFAULT 'email';  -- fast default (PG11+), existing rows → 'email'

ALTER TABLE public.jmap_changes_journal DROP CONSTRAINT jmap_changes_journal_pkey;
ALTER TABLE public.jmap_changes_journal
  ADD PRIMARY KEY (mailbox_id, datatype, state_seq, entity_id);
-- idx_changes_journal_prune (mailbox_id, created_at) is datatype-agnostic — unchanged.

-- ── 2. Per-(mailbox,datatype) monotonic state counter ────────────────────────
-- The /changes token for a satellite datatype. Email keeps its own proven counter
-- (mailboxes.jmap_email_state) — only the 5 satellites read/bump this table.
CREATE TABLE IF NOT EXISTS public.jmap_entity_state (
  mailbox_id BIGINT NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
  datatype   TEXT   NOT NULL,
  seq        BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (mailbox_id, datatype)
);

-- RLS: fail-closed per-mailbox (R4), same pattern + GUC as jmap_changes_journal
-- (V062). Every satellite reducer that touches this table runs under CallScoped
-- (app.current_mailbox_id set in the wrapping tx), so writes pass WITH CHECK.
ALTER TABLE public.jmap_entity_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jmap_entity_state FORCE  ROW LEVEL SECURITY;
CREATE POLICY jmap_entity_state_tenant_isolation ON public.jmap_entity_state
  FOR ALL
  TO public
  USING      (mailbox_id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint))
  WITH CHECK (mailbox_id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint));

-- ── 3. Task journaling trigger ───────────────────────────────────────────────
-- AFTER INSERT/UPDATE/DELETE on tasks → journal created/updated/destroyed at a
-- freshly-bumped state_seq. FOR EACH ROW so a cascade (parent-task destroy →
-- subtasks via tasks_parent_id_fkey ON DELETE CASCADE) journals every child row.
-- bump_entity_state + append_change are reducers (loaded after this migration);
-- PL/pgSQL resolves the calls at RUNTIME, so referencing them here is fine.
CREATE OR REPLACE FUNCTION public.journal_task_change() RETURNS TRIGGER AS $$
BEGIN
  -- Best-effort journal: see the RLS note in journal_calendar_event_change (V097).
  -- On the flipped app pool a write scoped to a different mailbox than the acting
  -- app.current_mailbox_id GUC (or with no mailbox GUC) can't write the FORCE'd,
  -- mailbox-scoped journal (42501). SECURITY DEFINER does NOT help — neither
  -- setjoin_app nor setjoin_owner has BYPASSRLS. Skip the delta rather than break
  -- the mutation (tasks are same-mailbox today; this guards a future/import writer).
  BEGIN
    IF TG_OP = 'DELETE' THEN
      PERFORM append_change(OLD.mailbox_id, 'Task',
                            bump_entity_state(OLD.mailbox_id, 'Task'), OLD.id, 'destroyed');
    ELSIF TG_OP = 'INSERT' THEN
      PERFORM append_change(NEW.mailbox_id, 'Task',
                            bump_entity_state(NEW.mailbox_id, 'Task'), NEW.id, 'created');
    ELSE
      PERFORM append_change(NEW.mailbox_id, 'Task',
                            bump_entity_state(NEW.mailbox_id, 'Task'), NEW.id, 'updated');
    END IF;
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_journal_task ON public.tasks;
CREATE TRIGGER trg_journal_task
  AFTER INSERT OR UPDATE OR DELETE ON public.tasks
  FOR EACH ROW EXECUTE FUNCTION public.journal_task_change();

-- ── Schema migration record ──────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (95, now())
    ON CONFLICT (version) DO NOTHING;
