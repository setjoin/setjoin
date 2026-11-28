-- V132__chat_send_counters_rls.sql — pipeline review security finding #5
-- (R4 completeness gap): chat_send_counters (V126 §H) is user-keyed
-- (user_id PK, one row per sender) but shipped with NO RLS at all, unlike
-- every other V119-V131 user-data chat table (all FORCE-RLS'd + allowlist-
-- covered). The V124/V126 "worker/reducer-only, no RLS" comment on it
-- copied the chat_push_intents precedent verbatim, but that precedent does
-- NOT actually apply here: chat_push_intents has no user_id column at all
-- (a message-fanout queue, sender_user_id is incidental metadata), while
-- chat_send_counters' single-row-per-user shape IS textbook per-user data —
-- root AGENTS.md R4 territory, not a queue.
--
-- Self-scoped policy, the chat_saved_messages_scope (V122) shape verbatim —
-- NOT the chat_audit_log/chat_link_previews deny-all-plus-DEFINER-write
-- pattern: chat_send_counters is written by chat_message_send, an ordinary
-- (non-SECURITY-DEFINER) reducer that upserts the CALLING user's own row
-- (p_user_id), never another user's — the same actor/row-owner shape
-- chat_saved_messages' writer (chat_message.sql's save path) already has.
-- A deny-all policy would make the table permanently unwritable by that
-- reducer once the eventual native-RLS flip lands (chat_send_counters has
-- no DEFINER writer to carve out an exception for); self-scoped is both
-- correct (a user's own send-rate counter is exactly their own data, no
-- audit-invisibility requirement the way a legal-hold log has) and future-
-- compatible with the flip.
--
-- LATENT like every sibling chat table (ARCH-006 posture, mailserver/
-- internal/chat/AGENTS.md): the app pool does not yet run as setjoin_app in
-- any current deployment (native-RLS flip for chat/meet is a separate,
-- staged program), so this migration changes nothing observable today —
-- proven only via SET LOCAL ROLE setjoin_app in rls_chat_compliance.pg,
-- the same posture check-rls-denial.sh's allowlist already exercises for
-- chat_saved_messages/chat_message_pins/chat_polls/etc.

ALTER TABLE public.chat_send_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_send_counters FORCE ROW LEVEL SECURITY;

CREATE POLICY chat_send_counters_scope ON public.chat_send_counters
  FOR ALL TO public
  USING (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
  WITH CHECK (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint));

INSERT INTO public.schema_migrations (version, applied_at) VALUES (132, now())
    ON CONFLICT (version) DO NOTHING;
