-- ════════════════════════════════════════════════════════════════════════
-- V124__chat_push.sql — Chat A3.5 mobile-push rider, Task 1.
--
-- Adds chat_push_intents (the V107 push_intents template — see
-- `V107__push_dispatch.sql`) and the feature.chat_push toggle.
--
-- chat_message_send (Task 2) writes ONE row per MESSAGE in-txn, gated by
-- feature.chat_push; the pushjobs worker's second drain leg (Task 3) fans
-- out per member at drain time. No RLS — worker-only table, the same
-- V107 push_intents / scheduled_actions precedent (R4-by-access-path, not
-- native RLS); NOT added to scripts/rls-denial-allowlist.txt (that guard
-- covers FORCE'd tables only).
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE public.chat_push_intents (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  channel_id BIGINT NOT NULL REFERENCES public.chat_channels(id) ON DELETE CASCADE,
  message_id BIGINT NOT NULL UNIQUE REFERENCES public.chat_messages(id) ON DELETE CASCADE,
  sender_user_id BIGINT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','done','failed')),
  attempts INT NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Claim index: the worker selects due pending rows, oldest first.
CREATE INDEX idx_chat_push_intents_due ON public.chat_push_intents (next_attempt_at) WHERE status = 'pending';

-- Backs the Task-3 worker's per-channel mention-safe coalesce EXISTS check.
CREATE INDEX idx_chat_push_intents_chan_pending ON public.chat_push_intents (channel_id) WHERE status = 'pending';

-- Gate: chat push is OFF until an operator flips it. Its OWN toggle — never
-- rides feature.mail_push (unrelated features flip independently).
INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.chat_push', false, 'Chat mobile push dispatch (drain-time notif_level/DND enforcement)')
ON CONFLICT (key) DO NOTHING;

-- ── Schema migration record ──────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (124, now())
    ON CONFLICT (version) DO NOTHING;
