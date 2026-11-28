-- V122__chat_qol.sql
-- Chat Pillar A3 (QoL wave) Task 1 — schema substrate for scheduled-send,
-- pin/save, read receipts, translation, voice, notif_level/DND, broadcast
-- permission, polls, CJK search, My-Threads, org-default channels, unfurl.
-- Plan: docs/superpowers/plans/archive/2026-07-12-chat-A3-qol.md "V122 schema" block
-- + Task 1. FORCE-RLS shape follows V119 (chat_member_role, the DEFINER
-- scope helper that dodges the membership-recursion trap) and V114 (zero
-- policies on a FORCE'd table = fail-closed deny-all for the app role, the
-- correct interim for a worker/DEFINER-only-write table).
--
-- File sections:
--   §A chat_messages.msg_type widen + payload/body trgm index (CJK search leg)
--   §B chat_channels.broadcast_permission
--   §C chat_message_pins (channel-scoped) + chat_saved_messages (self-scoped)
--   §D chat_polls / chat_poll_options / chat_poll_votes (channel-derived scope)
--   §E chat_link_previews (FORCE RLS, ZERO policies — worker/DEFINER-only)
--   §F user_notification_prefs.chat_notifications
--   §G org_default_channels (org catalog, no RLS — admin-gated, not user data)
--   §H toggle seeds + footer

-- ════════════════════════════════════════════════════════════════════════
-- §A — msg_type widen ('voice','poll' — Task 6/9 payload seam) + the CJK
-- search leg. pg_trgm is already installed at baseline (V001); the
-- CREATE EXTENSION here is the plan's own explicit belt, idempotent no-op.
-- ════════════════════════════════════════════════════════════════════════

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

ALTER TABLE public.chat_messages DROP CONSTRAINT chat_messages_msg_type_check;
ALTER TABLE public.chat_messages ADD CONSTRAINT chat_messages_msg_type_check
  CHECK (msg_type IN ('text', 'voice', 'poll'));

-- 'simple' tsquery cannot tokenize Han runs (search_tsv, V119, is latin-only
-- in practice) — this trgm leg is the substring-match floor for zh queries
-- (Task 10 routes on script detection; proper segmentation is a later
-- quality upgrade, not built here).
CREATE INDEX chat_messages_body_trgm_idx ON public.chat_messages USING GIN (body gin_trgm_ops);

-- ════════════════════════════════════════════════════════════════════════
-- §B — chat_channels.broadcast_permission (Task 8 reads it to gate
-- @channel/@all instead of the current hard-coded admin-only BZ166 check).
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.chat_channels
  ADD COLUMN broadcast_permission text NOT NULL DEFAULT 'admins'
    CHECK (broadcast_permission IN ('admins', 'all'));

-- ════════════════════════════════════════════════════════════════════════
-- §C — Pin (channel curation act) + Save (personal bookmark). Two different
-- RLS shapes per the plan's domain split: pins are channel-scoped (mirrors
-- chat_message_revisions_scope — a single membership-check policy, no
-- chicken-egg insert case since the channel + caller's membership both
-- already exist by the time a pin can be created); saves are self-scoped
-- (mirrors the user_id = guc shape, e.g. focus_sender_overrides/vip_senders).
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE public.chat_message_pins (
    channel_id bigint      NOT NULL REFERENCES public.chat_channels(id) ON DELETE CASCADE,
    message_id bigint      NOT NULL REFERENCES public.chat_messages(id) ON DELETE CASCADE,
    pinned_by  bigint      NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (channel_id, message_id)
);

CREATE POLICY chat_message_pins_scope ON public.chat_message_pins
  FOR ALL TO public
  USING (chat_member_role(channel_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
ALTER TABLE public.chat_message_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_message_pins FORCE  ROW LEVEL SECURITY;

CREATE TABLE public.chat_saved_messages (
    user_id    bigint      NOT NULL,
    message_id bigint      NOT NULL REFERENCES public.chat_messages(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, message_id)
);

CREATE POLICY chat_saved_messages_scope ON public.chat_saved_messages
  FOR ALL TO public
  USING (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
  WITH CHECK (user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint));
ALTER TABLE public.chat_saved_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_saved_messages FORCE  ROW LEVEL SECURITY;

-- ════════════════════════════════════════════════════════════════════════
-- §D — Polls. chat_polls carries channel_id denormalized (same reason as
-- chat_message_revisions: RLS scopes without a join through chat_messages).
-- chat_poll_options/chat_poll_votes have no channel_id of their own — RLS
-- joins through chat_polls (mirrors chat_reactions_scope's EXISTS-join
-- shape, which joins through chat_messages for the same reason).
-- message_id UNIQUE: a poll is anchored to exactly one message (spec Task 9
-- lifecycle — "a poll is a domain object anchored to its message"), never
-- double-anchored. poll_id+ordinal UNIQUE: distinct option ordinals per poll.
-- chat_poll_votes PK is ALWAYS (poll_id, option_id, user_id) — a constraint
-- cannot reference chat_polls.multi; single-vote enforcement is
-- chat_poll_vote's job (Task 9), not a schema constraint.
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE public.chat_polls (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    message_id bigint      NOT NULL REFERENCES public.chat_messages(id) ON DELETE CASCADE,
    channel_id bigint      NOT NULL REFERENCES public.chat_channels(id) ON DELETE CASCADE,
    question   text        NOT NULL,
    multi      boolean     NOT NULL DEFAULT false,
    closes_at  timestamptz,
    created_by bigint      NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (message_id)
);

CREATE POLICY chat_polls_scope ON public.chat_polls
  FOR ALL TO public
  USING (chat_member_role(channel_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
ALTER TABLE public.chat_polls ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_polls FORCE  ROW LEVEL SECURITY;

CREATE TABLE public.chat_poll_options (
    id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    poll_id bigint NOT NULL REFERENCES public.chat_polls(id) ON DELETE CASCADE,
    ordinal int    NOT NULL,
    label   text   NOT NULL,
    UNIQUE (poll_id, ordinal)
);

CREATE POLICY chat_poll_options_scope ON public.chat_poll_options FOR ALL TO public
  USING (EXISTS (SELECT 1 FROM public.chat_polls p WHERE p.id = chat_poll_options.poll_id
           AND chat_member_role(p.channel_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));
ALTER TABLE public.chat_poll_options ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_poll_options FORCE  ROW LEVEL SECURITY;

CREATE TABLE public.chat_poll_votes (
    poll_id    bigint      NOT NULL REFERENCES public.chat_polls(id) ON DELETE CASCADE,
    option_id  bigint      NOT NULL REFERENCES public.chat_poll_options(id) ON DELETE CASCADE,
    user_id    bigint      NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (poll_id, option_id, user_id)
);

CREATE POLICY chat_poll_votes_scope ON public.chat_poll_votes FOR ALL TO public
  USING (EXISTS (SELECT 1 FROM public.chat_polls p WHERE p.id = chat_poll_votes.poll_id
           AND chat_member_role(p.channel_id, (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL));
ALTER TABLE public.chat_poll_votes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_poll_votes FORCE  ROW LEVEL SECURITY;

-- ════════════════════════════════════════════════════════════════════════
-- §E — chat_link_previews: a global url_hash-keyed cache with NO user
-- column (URL possession is the capability — Task 13's grill decision).
-- FORCE RLS with ZERO policies is deny-all for the app role (V114
-- drive_chunk_gc_queue precedent) — every write is the Task 13 DEFINER
-- cache-write reducer / worker eviction leg, never the app pool directly.
-- image_blob_sha256 refcount mirrors message_attachments' pattern
-- (attachment_blob_refcount/trg_attachment_deleted, V001/V075): the
-- DECREMENT half is this migration's AFTER DELETE trigger; the INCREMENT
-- half happens in Task 13's DEFINER cache-write reducer at insert time (no
-- INSERT trigger to mirror — the precedent increments at write time too,
-- V075). Reap rides the existing trg_blob_refcount_zero (blobs AFTER UPDATE
-- OF ref_count) unchanged.
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE public.chat_link_previews (
    url_hash          text        PRIMARY KEY,
    url               text        NOT NULL,
    title             text,
    description       text,
    image_blob_sha256 text        REFERENCES public.blobs(sha256),
    fetched_at        timestamptz NOT NULL DEFAULT now(),
    status            text        NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending', 'ok', 'error'))
);

ALTER TABLE public.chat_link_previews ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_link_previews FORCE  ROW LEVEL SECURITY;
-- chat_link_previews: ZERO policies (worker/DEFINER-only; FORCE + none = invisible).

CREATE FUNCTION public.trg_chat_link_preview_deleted() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF OLD.image_blob_sha256 IS NOT NULL THEN
    UPDATE public.blobs SET ref_count = ref_count - 1 WHERE sha256 = OLD.image_blob_sha256;
  END IF;
  RETURN OLD;
END;
$$;
CREATE TRIGGER chat_link_preview_blob_refcount AFTER DELETE ON public.chat_link_previews
  FOR EACH ROW EXECUTE FUNCTION public.trg_chat_link_preview_deleted();

-- ════════════════════════════════════════════════════════════════════════
-- §F — user_notification_prefs.chat_notifications (the GLOBAL pref column;
-- values are 'all'/'mentions'/'off' — deliberately NOT the same vocabulary
-- as the PER-CHANNEL chat_channel_members.notif_level ('all'/'mentions'/
-- 'none', V119) — don't cross the two).
-- ════════════════════════════════════════════════════════════════════════

ALTER TABLE public.user_notification_prefs
  ADD COLUMN chat_notifications text NOT NULL DEFAULT 'all'
    CHECK (chat_notifications IN ('all', 'mentions', 'off'));

-- ════════════════════════════════════════════════════════════════════════
-- §G — org_default_channels: an org-wide catalog of channels every
-- provisioned user auto-joins (Task 12). No RLS — this is admin-managed
-- org config, not per-user data (same posture as feature_toggles/
-- retention_policies, neither of which carry RLS); the admin-only write
-- gate lives in Task 12's reducer, not here.
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE public.org_default_channels (
    channel_id bigint      PRIMARY KEY REFERENCES public.chat_channels(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- ════════════════════════════════════════════════════════════════════════
-- §H — toggle seeds + footer.
-- ════════════════════════════════════════════════════════════════════════

INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('chat.unfurl', false,
   'Chat link-preview unfurl (SSRF-hardened URL metadata + image fetch, Task 13). Seeded OFF; independent of feature.chat.'),
  ('chat.channel_creation', true,
   'Allow all users to create chat channels (OFF = admins only) — drive.space_creation''s shape.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (122, now())
    ON CONFLICT (version) DO NOTHING;
