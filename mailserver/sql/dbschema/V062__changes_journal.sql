-- ════════════════════════════════════════════════════════════════════════
-- V062__changes_journal.sql — per-account append-only change journal backing
-- real JMAP Email/changes + Mailbox/changes incremental delta (offline #3).
-- Appended in-txn at the real state-bump owners (notify_state_change +
-- adjust_folder_counters sentinel). message_id=0 is the 'resync' sentinel.
-- ════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS public.jmap_changes_journal (
  mailbox_id  BIGINT       NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
  state_seq   BIGINT       NOT NULL,
  message_id  BIGINT       NOT NULL,           -- 0 = 'resync' sentinel (never a real message id)
  op          TEXT         NOT NULL CHECK (op IN ('created','updated','destroyed','resync')),
  created_at  timestamptz  NOT NULL DEFAULT now(),
  PRIMARY KEY (mailbox_id, state_seq, message_id)
);

-- PK already leads on (mailbox_id, state_seq) — covers the changes read path
-- (WHERE mailbox_id=? AND state_seq > ? ORDER BY state_seq). created_at index
-- for time-based retention prune (Task 9).
-- ponytail: no extra read-path index; PK prefix covers it.
CREATE INDEX IF NOT EXISTS idx_changes_journal_prune
  ON public.jmap_changes_journal (mailbox_id, created_at);

-- RLS: fail-closed per-mailbox (R4). mail user is superuser in dev/test, so
-- policies are no-ops there — ENABLE+FORCE is for the prod setjoin_app role.
-- Pattern mirrors V003/V004 (messages). GUC missing_ok → NULL → fail-closed.
ALTER TABLE public.jmap_changes_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jmap_changes_journal FORCE  ROW LEVEL SECURITY;
CREATE POLICY jmap_changes_journal_tenant_isolation ON public.jmap_changes_journal
  FOR ALL
  TO public
  USING      (mailbox_id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint))
  WITH CHECK (mailbox_id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint));

-- ── Schema migration record ───────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (62, now())
    ON CONFLICT (version) DO NOTHING;
