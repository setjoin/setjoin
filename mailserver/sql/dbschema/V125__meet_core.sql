-- V125: Meet B1 core (conferencing meeting-layer). Membership-scoped like chat
-- (V119); app-level-primary (ARCH-006); FORCE-RLS latent backstop via a
-- SECURITY DEFINER scope helper (V114/V119 recursion-dodge, fourth use).
-- The LiveKit SFU holds NO authority: rooms are pre-created by the gateway,
-- tokens are minted from reducer-composed grant specs, webhooks are ingested
-- as loss-tolerant facts only (C0 spike §2).

CREATE TABLE public.meetings (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    room_name         uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    slug              text NOT NULL UNIQUE
                      DEFAULT translate(encode(gen_random_bytes(9), 'base64'), '+/', '-_'),
    title             text NOT NULL,
    owner_user_id     bigint NOT NULL,
    state             text NOT NULL DEFAULT 'scheduled'
                      CHECK (state IN ('scheduled','live','ended')),
    locked            boolean NOT NULL DEFAULT false,
    settings          jsonb NOT NULL DEFAULT '{"guestAllowed": false, "recording": false}',
    scheduled_start   timestamptz,
    scheduled_end     timestamptz,
    chat_channel_id   bigint REFERENCES public.chat_channels(id) ON DELETE SET NULL,
    calendar_event_id bigint REFERENCES public.calendar_events(id) ON DELETE SET NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    ended_at          timestamptz,
    CHECK (scheduled_end IS NULL OR scheduled_start IS NULL OR scheduled_end > scheduled_start)
);
CREATE INDEX meetings_owner_idx ON public.meetings (owner_user_id);
CREATE INDEX meetings_state_idx ON public.meetings (state) WHERE state <> 'ended';

CREATE TABLE public.meeting_participants (
    id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    meeting_id         bigint NOT NULL REFERENCES public.meetings(id) ON DELETE CASCADE,
    user_id            bigint,
    guest_display_name text,
    identity           text NOT NULL,
    role               text NOT NULL DEFAULT 'member'
                       CHECK (role IN ('host','cohost','member','guest')),
    joined_at          timestamptz,
    left_at            timestamptz,
    banned_at          timestamptz,  -- kick = ban until re-admit (gate-ratified):
                                     -- meeting_kick stamps; meeting_join BZ186s while
                                     -- set; meeting_set_role clears (the re-admit)
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (meeting_id, identity),
    CHECK ((user_id IS NOT NULL AND guest_display_name IS NULL)
        OR (user_id IS NULL AND guest_display_name IS NOT NULL))
);
CREATE INDEX meeting_participants_user_idx ON public.meeting_participants (user_id)
    WHERE user_id IS NOT NULL;

CREATE TABLE public.meeting_join_requests (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    meeting_id   bigint NOT NULL REFERENCES public.meetings(id) ON DELETE CASCADE,
    display_name text NOT NULL,
    user_id      bigint,
    secret       text NOT NULL DEFAULT encode(gen_random_bytes(16), 'hex'),
                 -- plaintext accepted (eng #15): host-visible by design, 15-min lifetime,
                 -- grants only a host-approved admission; hashing = ledgered hardening

    state        text NOT NULL DEFAULT 'pending'
                 CHECK (state IN ('pending','admitted','denied','expired')),
    decided_by   bigint,
    decided_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL DEFAULT now() + interval '15 minutes'
);
CREATE INDEX meeting_join_requests_pending_idx
    ON public.meeting_join_requests (meeting_id) WHERE state = 'pending';

-- Scope helper (V114 drive_member_role / V119 chat_member_role pattern):
-- a literal membership subquery in a policy on meeting_participants would
-- re-enter its own table under FORCE and raise 'infinite recursion detected
-- in policy'; the DEFINER helper reads membership without re-entering.
-- SET search_path = public is MANDATORY (eng review #2): a DEFINER function
-- without a pinned search_path is the classic PG privilege-escalation
-- foot-gun — V119's chat_member_role carries the same pin.
CREATE OR REPLACE FUNCTION meeting_member_role(p_meeting_id bigint, p_user_id bigint)
RETURNS text LANGUAGE sql SECURITY DEFINER STABLE SET search_path = public AS $$
    SELECT role FROM public.meeting_participants
     WHERE meeting_id = p_meeting_id AND user_id = p_user_id AND left_at IS NULL
     ORDER BY (role = 'host') DESC, (role = 'cohost') DESC LIMIT 1
$$;
SELECT apply_worker_ownership('meeting_member_role(bigint,bigint)'::regprocedure);

ALTER TABLE public.meetings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.meetings FORCE ROW LEVEL SECURITY;
CREATE POLICY meetings_read ON public.meetings FOR SELECT TO public
  USING (owner_user_id = (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)
      OR meeting_member_role(id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);
CREATE POLICY meetings_insert ON public.meetings FOR INSERT TO public
  WITH CHECK (owner_user_id =
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint));
-- UPDATE/DELETE: no user-role policy — mutations flow through reducers on the
-- app pool (BYPASSRLS today); at the native-RLS flip the mutating meet
-- reducers become worker-owned SECURITY DEFINER like the guest-lobby pair.

ALTER TABLE public.meeting_participants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.meeting_participants FORCE ROW LEVEL SECURITY;
CREATE POLICY meeting_participants_scope ON public.meeting_participants FOR SELECT TO public
  USING (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);

ALTER TABLE public.meeting_join_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.meeting_join_requests FORCE ROW LEVEL SECURITY;
-- Host/cohost decide surface only; guests reach their own row exclusively
-- through the DEFINER lobby reducers (slug+secret), never a direct SELECT.
CREATE POLICY meeting_join_requests_scope ON public.meeting_join_requests FOR SELECT TO public
  USING (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint))
         IN ('host','cohost'));

-- §3.3 bridge: 'call' system messages ride the ordinary chat rail.
ALTER TABLE public.chat_messages DROP CONSTRAINT chat_messages_msg_type_check;
ALTER TABLE public.chat_messages ADD CONSTRAINT chat_messages_msg_type_check
  CHECK (msg_type IN ('text', 'voice', 'poll', 'call'));

INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.meet', false,
   'Meet Pillar B1 (conferencing: meetings, lobby, LiveKit SFU tokens). Seeded OFF; requires the setjoin-sfu sidecar + LIVEKIT_* config.'),
  ('meet.guest_access', true,
   'Org-level guest-lobby kill switch. OFF = the public join-request surface 404s everywhere; per-meeting guestAllowed still gates individually.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (125, now())
    ON CONFLICT (version) DO NOTHING;
