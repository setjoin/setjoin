-- V131__meet_huddle_audit.sql — pipeline-review fix: Slack huddle semantics
-- for a meeting bound to a PRE-EXISTING chat channel (a "huddle" launched
-- from a private channel or DM), closing a DES-008 gap in Meet's chat
-- bridge (spec §3.3). Before this, meeting_join (org-open, any authed user,
-- by enumerable id) unconditionally inserted the joiner into
-- chat_channel_members regardless of whether the bound channel was
-- pre-existing or freshly provisioned FOR the meeting — a non-member who
-- joined a huddle launched from a private channel/DM gained PERMANENT
-- full-history read+write to that channel, surviving meeting end.
--
-- chat_channel_provisioned: true = meeting_create created this channel FOR
-- the meeting (the ad-hoc/no-p_chat_channel_id path) — auto-membership on
-- join/admit is correct, unchanged behavior. false = meeting_create bound a
-- PRE-EXISTING channel (a huddle launched in a channel the creator already
-- belonged to) — a joiner who is not already a member gets the MEETING,
-- never the channel's history. DEFAULT true: this product has no live
-- deployment yet (TODOS.md), so every existing meetings row simply keeps
-- today's auto-add behavior; meeting_create is updated in the same change
-- to set this correctly on both paths going forward.
ALTER TABLE public.meetings
  ADD COLUMN chat_channel_provisioned boolean NOT NULL DEFAULT true;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (131, now())
    ON CONFLICT (version) DO NOTHING;
