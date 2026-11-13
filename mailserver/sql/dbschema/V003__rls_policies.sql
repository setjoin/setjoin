-- ════════════════════════════════════════════════════════════════════════
-- V003__rls_policies.sql — forward migration (native-RLS enforcement-flip W2).
--
-- 🔒 INERT — policies are CREATED but RLS is NOT enabled. A `CREATE POLICY` has
-- ZERO runtime effect until `ALTER TABLE … ENABLE ROW LEVEL SECURITY` (and, for
-- the table OWNER, FORCE). This migration deliberately contains NO
-- ENABLE/FORCE ROW LEVEL SECURITY — that is the single all-or-nothing W6 flip,
-- made only after every tenant-scoped protocol (JMAP + CalDAV + SMTP-submission
-- + IMAP) is wrapped. Until then these definitions are dormant: production stays
-- RLS-disabled, the policies sit inert.
--
-- Plan: docs/superpowers/plans/archive/2026-06-18-native-rls-backstop.md
--   · W2 bullet (this artifact: inert FOR ALL USING+WITH CHECK on BOTH tables).
--   · Fork 2 RESOLVED — message_tags has NO mailbox_id column → derive its tenant
--     from the underlying MESSAGE via EXISTS-against-messages (the SOURCE OF
--     TRUTH; NOT a denormalized mailbox_id copy, which would add a "the copy
--     stays in sync" security-load-bearing invariant). A tag-row's visibility
--     follows the underlying message's owner, so it composes with the messages
--     policy. CONTEXT.md → "A folder is a tag; messages.mailbox_id is immutable".
--   · Fork 6 RESOLVED / W1a CONFIRMED — policy on the PARTITIONED PARENT only.
--     `rls_partition_via_parent.pg` empirically pinned that parent ENABLE+FORCE+
--     policy governs the WHOLE hierarchy on the via-parent access path (the only
--     path the gateway/reducers use: they always name `FROM messages`, never a
--     leaf). Per-partition flags are NOT inherited, but via-parent isolation is
--     the operative guarantee.
--   · InitPlan GUC form — `(SELECT NULLIF(current_setting(…, true), '')::bigint)`
--     wrapped in a scalar subquery so the planner evaluates the GUC ONCE per
--     query (an InitPlan), not as a per-row volatile call that degrades to a seq
--     scan. NULLIF(…, '')::bigint is FAIL-CLOSED: an unset/empty GUC (an
--     un-wrapped connection) → NULL → no row qualifies (and no ''::bigint cast
--     error), instead of leaking.
--
-- The shape here is the one validated test-locally (ENABLE+FORCE inside a
-- BEGIN…ROLLBACK on the REAL tables, SET LOCAL ROLE setjoin_app) by
-- mailserver/sql/tests/rls_policies.pg — which proves read isolation, the
-- WITH CHECK write-path, fail-closed, AND the InitPlan perf shape (the GUC is
-- evaluated once per query, not a per-row volatile call), then rolls the
-- enablement back so production stays RLS-disabled.
-- ════════════════════════════════════════════════════════════════════════

-- ── Covering index for the message_tags EXISTS probe ────────────────────────
-- partition key (received_at) FIRST → partition pruning; then id (the FK join
-- key) so the (id, received_at) lookup is satisfied from the index; INCLUDE
-- mailbox_id so the per-row tenant comparison is answered WITHOUT a heap fetch
-- (index-only scan). On the PARTITIONED PARENT this creates a partitioned index
-- that CASCADES to every existing and future partition.
CREATE INDEX IF NOT EXISTS messages_mailbox_covering_idx
  ON public.messages (received_at, id) INCLUDE (mailbox_id);

-- ── Policy: public.messages (the PARENT) ────────────────────────────────────
-- FOR ALL (read + write) TO public. USING governs which rows are VISIBLE
-- (SELECT/UPDATE/DELETE); WITH CHECK governs which rows may be WRITTEN
-- (INSERT/UPDATE) — written explicitly because under FORCE a policy with no
-- WITH CHECK default-denies every write. Both compare the row's immutable
-- mailbox_id against the per-request GUC, evaluated once via the InitPlan
-- scalar subquery.
CREATE POLICY messages_tenant_isolation ON public.messages
  FOR ALL
  TO public
  USING      (mailbox_id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint))
  WITH CHECK (mailbox_id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint));

-- ── Policy: public.message_tags (the PARENT) ────────────────────────────────
-- message_tags has NO mailbox_id column, so a tag-row's tenant is the owner of
-- the MESSAGE it references (fork 2). EXISTS against messages, keyed on the FK
-- (message_id, received_at) → messages(id, received_at), with the SAME InitPlan
-- GUC comparison on messages.mailbox_id. The covering index makes the probe
-- index-only + partition-pruned. WITH CHECK runs the identical EXISTS on the
-- write path so tagging a foreign-mailbox message is rejected.
CREATE POLICY message_tags_tenant_isolation ON public.message_tags
  FOR ALL
  TO public
  USING (
    EXISTS (
      SELECT 1
        FROM public.messages m
       WHERE m.id          = message_tags.message_id
         AND m.received_at = message_tags.received_at
         AND m.mailbox_id  = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint)
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1
        FROM public.messages m
       WHERE m.id          = message_tags.message_id
         AND m.received_at = message_tags.received_at
         AND m.mailbox_id  = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint)
    )
  );

-- ── NO ENABLE / FORCE ROW LEVEL SECURITY HERE ───────────────────────────────
-- Deliberately absent. Enabling RLS while only JMAP sets the GUC would break
-- every un-wrapped tenant protocol (empty GUC → zero rows). Enablement is the
-- W6 all-or-nothing flip; this migration only lays the (dormant) policy bricks.

-- Advance MAX(version) so the loader's apply step + main.go / admin_system see
-- this migration as applied. Columns match the V001 seed (version, applied_at).
INSERT INTO public.schema_migrations (version, applied_at) VALUES (3, now())
    ON CONFLICT (version) DO NOTHING;
