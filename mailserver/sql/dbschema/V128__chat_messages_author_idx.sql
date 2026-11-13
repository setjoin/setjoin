-- V128__chat_messages_author_idx.sql — Chat A4b eng-review F3: index the
-- authored-channels UNION leg in chat_case_hold_set (chat_case_hold_set.sql
-- §L4 coverage snapshot). That leg does `SELECT DISTINCT channel_id FROM
-- chat_messages WHERE author_id = p_custodian_user_id` with no supporting
-- index — a full chat_messages seq scan runs INSIDE the hold-set txn while
-- holding the custodian's chat_hold_user_ advisory lock, so every concurrent
-- hold-set/join on that custodian serializes behind the scan. (author_id,
-- channel_id) makes the DISTINCT scan index-only. Plain CREATE INDEX (not
-- CONCURRENTLY) — every dbschema migration in this tree runs as a single
-- statement inside the loader's own transaction handling (no CONCURRENTLY
-- precedent anywhere under mailserver/sql/dbschema/), and this migration has
-- no live-production-traffic gate on landing instantly.
CREATE INDEX IF NOT EXISTS chat_messages_author_idx
  ON public.chat_messages (author_id, channel_id);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (128, now())
    ON CONFLICT (version) DO NOTHING;
