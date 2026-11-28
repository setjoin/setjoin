-- ════════════════════════════════════════════════════════════════════════
-- V033__journal_retry.sql — journal_queue failure contract + retry/dead-letter (U1).
--
-- journal_queue silently and permanently lost compliance mail: drain selected
-- WHERE status='pending' only, and a first error set status='failed' forever
-- (never re-selected, no retry, no surface). This adopts the F1 failure contract
-- (mailserver/sql/AGENTS.md → Queue failure contract): adds next_attempt_at +
-- last_error, extends the status CHECK with 'deferred' (eligible for retry) and
-- 'dead' (terminal, mail HELD not deleted — posture (a)). The rewritten drain
-- (reducers/journal.sql) routes failures through settle_job (capped exp backoff →
-- deferred | dead + audit + dead-letter alert).
--
-- MIGRATION BONUS: every existing stuck 'failed' row is re-pended ONCE
-- (status='deferred', next_attempt_at=now()) so previously-lost compliance mail
-- gets one bounded retry-or-dead-letter pass. Bounded retry + dead-letter alert
-- prevent a thundering herd. Forward-only; data is held, never deleted.
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.journal_queue
  ADD COLUMN IF NOT EXISTS next_attempt_at timestamp with time zone,
  ADD COLUMN IF NOT EXISTS last_error      text;

-- Extend the status CHECK to admit 'deferred' and 'dead'.
ALTER TABLE public.journal_queue DROP CONSTRAINT IF EXISTS journal_queue_status_check;
ALTER TABLE public.journal_queue
  ADD CONSTRAINT journal_queue_status_check
  CHECK (status = ANY (ARRAY['pending'::text, 'delivered'::text, 'failed'::text,
                             'deferred'::text, 'dead'::text]));

-- Index the retry-eligibility scan (deferred rows due now), mirroring the
-- baseline's partial pending index.
CREATE INDEX IF NOT EXISTS journal_queue_deferred_idx
  ON public.journal_queue (next_attempt_at)
  WHERE status = 'deferred';

-- Re-pend stranded legacy 'failed' rows exactly once: due immediately, attempts
-- preserved so they dead-letter promptly if still poison.
UPDATE public.journal_queue
   SET status = 'deferred', next_attempt_at = now()
 WHERE status = 'failed';

INSERT INTO public.schema_migrations (version, applied_at) VALUES (33, now())
    ON CONFLICT (version) DO NOTHING;
