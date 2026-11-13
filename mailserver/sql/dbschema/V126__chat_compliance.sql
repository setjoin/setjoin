-- V126__chat_compliance.sql — Chat A4a records-lifecycle substrate.
-- Channel-level compliance state (mirrors drive_spaces' classification/
-- retention/worm knobs, V114 §A), the per-conversation audit chain table
-- (drive_audit_log clone, V114:175-190), org retention policies, the send-rate
-- counter (V124 chat_push_intents posture: R4-by-access-path, no RLS), the
-- single-homed hold predicate, and the enforcement triggers (no-downgrade
-- BZ192, WORM BZ193, hold BZ194).
-- Spec: docs/superpowers/plans/archive/2026-07-12-chat-A4a-records-lifecycle.md Task 1.

-- §A — chat_channels compliance columns.
-- retention_days is TWO different things by classification (see the plan's
-- vocabulary block): on a 'regular' channel it is a DESTROY CEILING (the purge
-- sweep deletes messages older than it); on a 'gxp' channel it is a WORM
-- KEEP-FLOOR (messages are immutable for that long) and the purge sweep NEVER
-- touches the channel at all. The UI must never conflate the two labels.
ALTER TABLE public.chat_channels
  ADD COLUMN classification    text    NOT NULL DEFAULT 'regular'
    CHECK (classification IN ('regular','gxp')),
  ADD COLUMN retention_days    integer CHECK (retention_days > 0),
  ADD COLUMN worm_mode         text    CHECK (worm_mode IN ('governance','compliance')),
  ADD COLUMN legal_hold        boolean NOT NULL DEFAULT false,
  ADD COLUMN legal_hold_reason text,
  -- NOT a cursor floor: chat_messages.seq is RE-STAMPED on every edit and
  -- delete (chat_message.sql:297,317 / :354,364), so the purged set is selected
  -- by created_at and is NOT a contiguous seq range — MAX(seq) over it can
  -- exceed the seq of LIVE messages. This column is provenance only: "the
  -- highest seq any purge on this channel ever destroyed". Never read it as a
  -- replay floor. (eng review #5.)
  ADD COLUMN last_purged_seq   bigint  NOT NULL DEFAULT 0;

-- gxp knobs are a DB fact, not a reducer promise (eng review #4): without this,
-- a gxp channel with NULL retention_days makes make_interval(days => NULL) NULL,
-- the WORM trigger's IF is never TRUE, and the channel is freely editable and
-- deletable by anyone — a compliance invariant failing OPEN.
ALTER TABLE public.chat_channels
  ADD CONSTRAINT chat_channels_gxp_knobs
  CHECK (classification <> 'gxp' OR (retention_days IS NOT NULL AND worm_mode IS NOT NULL));

-- §B — the single-homed hold predicate (CEO review #7). The BZ194 trigger, the
-- purge sweep's channel selection, and the admin channel list ALL call this and
-- nothing else, so A4b's per-custodian/per-case hold adds ONE `OR EXISTS (...)`
-- arm HERE instead of re-opening the destruction path in three places.
-- DEFINER: chat_channels has no UPDATE policy and a FORCE-RLS SELECT policy;
-- the predicate must answer the same way for the purge worker and for a member.
CREATE FUNCTION public.chat_hold_active(p_channel_id bigint) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT COALESCE((SELECT legal_hold FROM public.chat_channels WHERE id = p_channel_id), false)
$$;
SELECT apply_worker_ownership('chat_hold_active(bigint)'::regprocedure);

-- §C — no-downgrade (BZ192; the V114:388 trg_drive_space_no_downgrade shape).
CREATE FUNCTION public.trg_chat_channel_no_downgrade_fn() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.classification = 'gxp' AND NEW.classification <> 'gxp' THEN
    RAISE EXCEPTION 'classification downgrade forbidden'
      USING ERRCODE='BZ192', HINT='{"type":"stateMismatch","detail":"classification can never be lowered"}';
  END IF;
  IF OLD.classification = 'gxp' THEN
    IF NEW.retention_days IS NULL OR NEW.retention_days < OLD.retention_days THEN
      RAISE EXCEPTION 'gxp retention may only increase' USING ERRCODE='BZ192',
        HINT='{"type":"stateMismatch","detail":"retention_days may only increase"}';
    END IF;
    IF OLD.worm_mode = 'compliance' AND NEW.worm_mode = 'governance' THEN
      RAISE EXCEPTION 'worm_mode may not relax' USING ERRCODE='BZ192',
        HINT='{"type":"stateMismatch","detail":"compliance may not relax to governance"}';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_chat_channel_no_downgrade
  BEFORE UPDATE OF classification, retention_days, worm_mode ON public.chat_channels
  FOR EACH ROW EXECUTE FUNCTION public.trg_chat_channel_no_downgrade_fn();

-- §D — WORM message immutability (BZ193; the V114:472 worm-trigger shape).
-- Fires BELOW the reducer layer, so chat_message_edit / chat_message_delete
-- (chat_message.sql:269-390) hit it regardless of role — "no edit/delete, even
-- by admins". payload/seq/edited_at are EXEMPT (the drive rendition-column
-- analog): pin re-stamps seq, polls stamp payload — curation, not the record
-- body. Unfurl also writes payload, which is why Task 8 DISABLES unfurl in gxp
-- channels (spec-delta 5) rather than widening this exemption to cover content.
-- NULL retention on a gxp channel = INFINITE retention (fail-CLOSED); the
-- chat_channels_gxp_knobs CHECK makes that state unreachable anyway — belt and
-- braces, because this is a compliance invariant.
--
-- TRIGGER FIRING ORDER IS LOAD-BEARING: Postgres fires same-event BEFORE row
-- triggers in trigger-NAME alphabetical order. trg_chat_message_hold sorts
-- before trg_chat_message_worm ('h' < 'w'), so on a held gxp channel a DELETE
-- raises BZ194 (hold) FIRST — which is what the purge's narrowed BZ194 catch
-- expects. Do not rename either trigger without re-checking this.
CREATE FUNCTION public.trg_chat_message_worm_fn() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE v_class text; v_ret int;
BEGIN
  SELECT c.classification, c.retention_days INTO v_class, v_ret
    FROM public.chat_channels c WHERE c.id = OLD.channel_id;
  IF v_class = 'gxp'
     AND (v_ret IS NULL OR OLD.created_at + make_interval(days => v_ret) > now()) THEN
    IF TG_OP = 'UPDATE'
       AND NEW.body = OLD.body
       AND NEW.deleted_at IS NOT DISTINCT FROM OLD.deleted_at THEN
      RETURN NEW;  -- payload/seq/edited_at-only change: allowed
    END IF;
    RAISE EXCEPTION 'gxp message immutable inside retention'
      USING ERRCODE='BZ193', HINT='{"type":"immutable","detail":"record is under retention"}';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_chat_message_worm
  BEFORE UPDATE OR DELETE ON public.chat_messages
  FOR EACH ROW EXECUTE FUNCTION public.trg_chat_message_worm_fn();

-- Revisions are edit-evidence: UPDATE is blocked ALWAYS; DELETE is blocked
-- while the PARENT MESSAGE is inside its channel's retention window.
-- The window is the parent's created_at, NOT the revision's own (eng review #3):
-- a revision row's created_at is the EDIT time, so windowing on it would make a
-- 40-day-old message edited 5 days ago undeletable — and since the purge deletes
-- the message and CASCADEs the revision, BZ193 (which is NOT in the sweep's
-- narrowed catch) would propagate and abort the entire sweep, forever.
-- FOUND=false (parent already gone) => allow: that is the CASCADE case.
CREATE FUNCTION public.trg_chat_revision_worm_fn() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE v_class text; v_ret int; v_msg_created timestamptz;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'revision rows are write-only'
      USING ERRCODE='BZ193', HINT='{"type":"immutable","detail":"edit evidence is write-only"}';
  END IF;
  SELECT c.classification, c.retention_days, m.created_at
    INTO v_class, v_ret, v_msg_created
    FROM public.chat_messages m
    JOIN public.chat_channels c ON c.id = m.channel_id
   WHERE m.id = OLD.message_id;
  IF FOUND AND v_class = 'gxp'
     AND (v_ret IS NULL OR v_msg_created + make_interval(days => v_ret) > now()) THEN
    RAISE EXCEPTION 'gxp revision immutable inside retention'
      USING ERRCODE='BZ193', HINT='{"type":"immutable","detail":"record is under retention"}';
  END IF;
  RETURN OLD;
END $$;
CREATE TRIGGER trg_chat_revision_worm
  BEFORE UPDATE OR DELETE ON public.chat_message_revisions
  FOR EACH ROW EXECUTE FUNCTION public.trg_chat_revision_worm_fn();

-- §E — legal hold (BZ194; the V001:1419 trg_messages_hold_check shape, same
-- HINT type slug 'litigation_hold'). Hold beats retention BY CONSTRUCTION:
-- destruction physically fails. Soft-delete (an UPDATE) stays allowed under
-- hold — body is retained anyway. Predicate via chat_hold_active (§B).
CREATE FUNCTION public.trg_chat_message_hold_fn() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF public.chat_hold_active(OLD.channel_id) THEN
    RAISE EXCEPTION 'channel % is under legal hold', OLD.channel_id
      USING ERRCODE='BZ194',
            HINT=jsonb_build_object('type','litigation_hold','channel_id',OLD.channel_id)::text;
  END IF;
  RETURN OLD;
END $$;
CREATE TRIGGER trg_chat_message_hold
  BEFORE DELETE ON public.chat_messages
  FOR EACH ROW EXECUTE FUNCTION public.trg_chat_message_hold_fn();

-- §F — the per-conversation audit chain table (drive_audit_log clone).
-- DENY-ALL under FORCE RLS, ZERO policies (the chat_link_previews V122
-- precedent). A legal hold must be INVISIBLE to the custodians it targets
-- (CEO review #1): a member-read policy would have let the people under
-- investigation read 'hold.set: case-42' out of their own channel's chain.
-- Every read is an admin route on workerPool (BYPASSRLS); the writer is a
-- SECURITY DEFINER worker-owned reducer. No end-user chain UI exists or is
-- planned. A4b's eDiscovery reader uses the same carve-out (contract #4).
CREATE TABLE public.chat_audit_log (
    channel_id   bigint      NOT NULL REFERENCES public.chat_channels(id) ON DELETE CASCADE,
    id           bigint      NOT NULL,              -- per-channel monotonic
    occurred_at  timestamptz NOT NULL DEFAULT now(),
    user_id      bigint,                            -- NULL = system (cron sweeps)
    ip           inet,
    action       text        NOT NULL,
    target_type  text,
    target_id    bigint,
    before_state jsonb,
    after_state  jsonb,      -- chain checksum in after_state->>'_checksum' (V037 convention)
    notes        text,
    PRIMARY KEY (channel_id, id)
);
CREATE INDEX chat_audit_log_query_idx
    ON public.chat_audit_log (channel_id, action, occurred_at DESC);
ALTER TABLE public.chat_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_audit_log FORCE  ROW LEVEL SECURITY;
-- chat_audit_log: ZERO policies (worker/DEFINER-only; FORCE + none = invisible,
-- same shape as chat_link_previews, V122 §E).

-- §G — org retention policies (org config; no RLS, same posture as
-- org_default_channels, V122 §G).
-- effective_at is the 7-day UNDO WINDOW BY CONSTRUCTION (CEO review #6): the
-- sweep's resolution ignores a policy until now() >= effective_at, so an admin
-- who types 30 meaning thirty MONTHS has a week to notice and edit or delete it
-- before anything is destroyed. Task 12's editor shows "takes effect on <date>".
CREATE TABLE public.chat_retention_policies (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name          text    NOT NULL,
    applies_to    text    NOT NULL DEFAULT 'all'
      CHECK (applies_to IN ('channel','dm','group_dm','all')),   -- matches chat_channels.kind (V119:9)
    duration_days integer NOT NULL CHECK (duration_days > 0),
    enabled       boolean NOT NULL DEFAULT true,
    effective_at  timestamptz NOT NULL DEFAULT now() + interval '7 days',
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- §H — per-user send-rate counter. FORCE RLS + a self-scoped policy land
-- in V132 (pipeline review security finding #5) — the V124 chat_push_intents
-- "no RLS" precedent this comment originally cited does NOT apply here:
-- chat_push_intents has no user_id column (a fanout queue), while this table
-- is one row PER USER — R4 territory, now covered in the rls-denial
-- allowlist like every sibling chat table.
CREATE TABLE public.chat_send_counters (
    user_id      bigint      PRIMARY KEY,
    window_start timestamptz NOT NULL,
    sent_count   integer     NOT NULL DEFAULT 0
);

-- §I — seeds
INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.chat_compliance', false,
   'Chat A4a records lifecycle (audit chain + anchors, retention, legal hold, purge, gxp/WORM channels). Seeded OFF — MUST NOT be flipped in a customer deployment until A4b eDiscovery ships.')
ON CONFLICT (key) DO NOTHING;

-- chat compliance perms: deliberately OUTSIDE the SoD class map for now (the
-- drive.view/drive.manage V114:551-560 precedent — do NOT touch classes.go
-- PermClasses or sod_exclusion_guard(); classify when the chat SoD pass happens).
INSERT INTO public.admin_permissions (permission_key, category, description, is_sensitive) VALUES
  ('chat.compliance_view',   'Chat', 'View chat retention policies, holds, classifications and audit chains', false),
  ('chat.compliance_manage', 'Chat', 'Administer chat retention, legal hold, classification and purge', true)
ON CONFLICT (permission_key) DO NOTHING;

UPDATE public.admin_role_groups
   SET permissions = (SELECT array_agg(DISTINCT p ORDER BY p)
                        FROM unnest(permissions || ARRAY['chat.compliance_view','chat.compliance_manage']) AS p)
 WHERE id = 1;   -- Super Admin, exactly as V114:563-566

INSERT INTO public.schema_migrations (version, applied_at) VALUES (126, now())
    ON CONFLICT (version) DO NOTHING;
