-- V119: chat core (Pillar A1). Membership-scoped, app-level-primary (ARCH-006);
-- FORCE-RLS latent backstop via a SECURITY DEFINER scope helper — a literal
-- membership subquery in the policy re-enters its own table and raises
-- 'infinite recursion detected in policy' (V112's documented footgun; V114's
-- drive_member_role is the shipped dodge). Dormant while the runtime connects
-- as BYPASSRLS worker; must activate cleanly at the native-RLS flip.
CREATE TABLE public.chat_channels (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind         text NOT NULL CHECK (kind IN ('channel','dm','group_dm')),
    name         text,
    topic        text,
    visibility   text NOT NULL DEFAULT 'public' CHECK (visibility IN ('public','private')),
    post_permission text NOT NULL DEFAULT 'all' CHECK (post_permission IN ('all','admins')),
    member_key   text,                          -- canonical sorted-id key for dm/group_dm dedup
    change_seq   bigint NOT NULL DEFAULT 0,     -- commit-ordered per-channel mutation counter
    created_by   bigint NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    is_archived  boolean NOT NULL DEFAULT false
);
-- DB-enforced DM dedup: two concurrent chat_dm_open() for the same member set
-- race on this index, not on a lookup (TOCTOU fix).
CREATE UNIQUE INDEX chat_channels_member_key_uq ON public.chat_channels (member_key)
    WHERE kind IN ('dm','group_dm');

CREATE TABLE public.chat_channel_members (
    channel_id   bigint NOT NULL REFERENCES public.chat_channels(id) ON DELETE CASCADE,
    user_id      bigint NOT NULL,
    role         text NOT NULL DEFAULT 'member' CHECK (role IN ('owner','admin','member')),
    joined_at    timestamptz NOT NULL DEFAULT now(),
    last_read_seq bigint NOT NULL DEFAULT 0,
    notif_level  text NOT NULL DEFAULT 'all' CHECK (notif_level IN ('all','mentions','none')),
    PRIMARY KEY (channel_id, user_id)
);
CREATE INDEX chat_channel_members_user_idx ON public.chat_channel_members (user_id);

CREATE TABLE public.chat_messages (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    channel_id   bigint NOT NULL REFERENCES public.chat_channels(id) ON DELETE CASCADE,
    seq          bigint NOT NULL,               -- stamped from change_seq on insert/edit/delete
    author_id    bigint NOT NULL,
    parent_message_id bigint REFERENCES public.chat_messages(id) ON DELETE SET NULL,
    msg_type     text NOT NULL DEFAULT 'text' CHECK (msg_type IN ('text')),  -- widen in A3/A4/B
    payload      jsonb,                          -- structured-message seam; NULL for 'text'
    broadcast    text CHECK (broadcast IN ('channel','all')),
    body         text NOT NULL,                  -- RETAINED on soft-delete (compliance; A4 purges)
    search_tsv   tsvector GENERATED ALWAYS AS (to_tsvector('simple', coalesce(body,''))) STORED,
    edited_at    timestamptz,
    deleted_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (channel_id, seq)
);
CREATE INDEX chat_messages_thread_idx ON public.chat_messages (parent_message_id)
    WHERE parent_message_id IS NOT NULL;
CREATE INDEX chat_messages_search_idx ON public.chat_messages USING GIN (search_tsv);

CREATE TABLE public.chat_message_reactions (
    message_id bigint NOT NULL REFERENCES public.chat_messages(id) ON DELETE CASCADE,
    user_id    bigint NOT NULL,
    emoji      text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (message_id, user_id, emoji)
);
CREATE TABLE public.chat_mentions (
    message_id        bigint NOT NULL REFERENCES public.chat_messages(id) ON DELETE CASCADE,
    mentioned_user_id bigint NOT NULL,
    PRIMARY KEY (message_id, mentioned_user_id)
);
CREATE INDEX chat_mentions_user_idx ON public.chat_mentions (mentioned_user_id);

-- Edit evidence (grill Q3): prior body captured before every edit overwrite.
-- Write-only in A1; A4 eDiscovery is the reader. channel_id denormalized so the
-- RLS policy can scope without a join through chat_messages.
CREATE TABLE public.chat_message_revisions (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    channel_id   bigint NOT NULL REFERENCES public.chat_channels(id) ON DELETE CASCADE,
    message_id   bigint NOT NULL REFERENCES public.chat_messages(id) ON DELETE CASCADE,
    prior_body   text NOT NULL,
    edited_by    bigint NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX chat_message_revisions_msg_idx ON public.chat_message_revisions (message_id);

-- SECURITY DEFINER scope helper (drive V114 pattern): reads membership WITHOUT
-- re-entering the policy. Returns the member's role, or NULL if not a member.
CREATE OR REPLACE FUNCTION chat_member_role(p_channel_id bigint, p_user_id bigint)
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
    SELECT role FROM public.chat_channel_members
     WHERE channel_id = p_channel_id AND user_id = p_user_id;
$$;
SELECT apply_worker_ownership('chat_member_role(bigint,bigint)'::regprocedure);

-- R4 fix (review blocker): chat_channels shipped with no RLS at all — any
-- app-pool request could read every DM's member_key + every private
-- channel's name/topic. SELECT preserves public-channel discoverability
-- (grill Q1); INSERT checks created_by instead of chat_member_role because
-- the creating user's membership row doesn't exist yet at channel-insert
-- time (chicken-egg, same shape as drive_spaces_insert). No UPDATE/DELETE
-- policy yet — ponytail: rename/archive reducers aren't built in Task 1;
-- FORCE's deny-by-default is the correct fail-closed interim (drive V114 precedent).
CREATE POLICY chat_channels_read ON public.chat_channels FOR SELECT TO public
  USING (chat_member_role(id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL
     OR (kind = 'channel' AND visibility = 'public'));
CREATE POLICY chat_channels_insert ON public.chat_channels FOR INSERT TO public
  WITH CHECK (created_by = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint));
ALTER TABLE public.chat_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_channels FORCE  ROW LEVEL SECURITY;

CREATE POLICY chat_members_scope ON public.chat_channel_members
  FOR ALL TO public
  USING (chat_member_role(channel_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL)
  WITH CHECK (chat_member_role(channel_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IN ('owner','admin')
       OR user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint));
ALTER TABLE public.chat_channel_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_channel_members FORCE  ROW LEVEL SECURITY;

CREATE POLICY chat_messages_scope ON public.chat_messages
  FOR ALL TO public
  USING (chat_member_role(channel_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
ALTER TABLE public.chat_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_messages FORCE  ROW LEVEL SECURITY;

-- R4 fix (review blocker): reactions/mentions shipped with no RLS — any
-- app-pool request could read/write any channel's reactions or mentions.
-- Different table than the recursion trap (chat_messages, not
-- chat_channel_members) so a direct EXISTS join is safe (drive_chunks_read
-- uses the same shape via drive_version_chunks -> drive_files).
CREATE POLICY chat_reactions_scope ON public.chat_message_reactions FOR ALL TO public
  USING (EXISTS (SELECT 1 FROM public.chat_messages m WHERE m.id = chat_message_reactions.message_id
           AND chat_member_role(m.channel_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));
ALTER TABLE public.chat_message_reactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_message_reactions FORCE  ROW LEVEL SECURITY;

CREATE POLICY chat_mentions_scope ON public.chat_mentions FOR ALL TO public
  USING (EXISTS (SELECT 1 FROM public.chat_messages m WHERE m.id = chat_mentions.message_id
           AND chat_member_role(m.channel_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));
ALTER TABLE public.chat_mentions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_mentions FORCE  ROW LEVEL SECURITY;

CREATE POLICY chat_revisions_scope ON public.chat_message_revisions
  FOR ALL TO public
  USING (chat_member_role(channel_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
ALTER TABLE public.chat_message_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_message_revisions FORCE  ROW LEVEL SECURITY;

INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.chat', false,
   'Chat/IM Pillar A (channels, DM, threads, reactions, mentions, presence). Seeded OFF; flip per-org at rollout — not CN-shippable before A2+A3.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (119, now())
    ON CONFLICT (version) DO NOTHING;
