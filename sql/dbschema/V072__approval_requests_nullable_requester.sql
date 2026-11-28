-- V047: inbound group-moderation has NO internal requester (the sender is external).
-- Drop the NOT NULL on approval_requests.requester_user_id so group_moderation_hold
-- can park a request with a NULL requester (the external sender address is carried
-- in the subject + payload instead). The RLS "requester sees own" branch simply
-- matches no one for a NULL requester — only the moderator (approver) sees it.
ALTER TABLE public.approval_requests ALTER COLUMN requester_user_id DROP NOT NULL;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (72, now())
  ON CONFLICT (version) DO NOTHING;
