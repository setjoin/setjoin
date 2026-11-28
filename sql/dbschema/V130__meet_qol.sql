-- V130__meet_qol.sql — Meet B3: breakout substrate + Q&A msg_type + toggles.
-- Spec: docs/superpowers/specs/2026-07-15-meet-B3-qol-design.md §5.
-- §A meeting_breakouts (FORCE RLS via meeting_member_role — the V114/V119/
-- V125/V129 DEFINER recursion-dodge, 5th use) · §B the assignment column ·
-- §C the Q&A CHECK widening (the V125 'call' / V122 'poll' precedent) ·
-- §D toggles. Captions state deliberately has NO column: it rides
-- meetings.settings->>'captionsOn' (D8, the guestAllowed genre).

-- §A — breakout rows. room_name is its own uuid (D1: meetings.room_name is
-- a uuid column — no string suffixing; webhook resolution is a table lookup).
CREATE TABLE public.meeting_breakouts (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    meeting_id bigint NOT NULL REFERENCES public.meetings(id) ON DELETE CASCADE,
    idx        int    NOT NULL,                       -- 1..20, display order
    title      text,   -- host-supplied only; NULL = client-rendered i18n default (delta 10 / design D5)
    room_name  uuid   NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    state      text   NOT NULL DEFAULT 'open' CHECK (state IN ('open','closed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    closed_at  timestamptz
);
-- Review F3: PARTIAL unique — closed rows keep their idx without blocking a
-- later reopen (open → close-all → open again is a normal host flow).
CREATE UNIQUE INDEX meeting_breakouts_open_idx
  ON public.meeting_breakouts (meeting_id, idx) WHERE state = 'open';
CREATE INDEX meeting_breakouts_meeting_idx ON public.meeting_breakouts (meeting_id);

ALTER TABLE public.meeting_breakouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.meeting_breakouts FORCE  ROW LEVEL SECURITY;
-- SELECT via the live-membership gate (breakouts are a live-meeting surface;
-- no post-end read exists — meeting_attendee_role is NOT needed here). No
-- mutation policies: reducers on the app pool (ARCH-006 app-level-primary).
CREATE POLICY meeting_breakouts_read ON public.meeting_breakouts FOR SELECT TO public
  USING (meeting_member_role(meeting_id,
           (SELECT NULLIF(current_setting('app.current_user_id', true), '')::bigint)) IS NOT NULL);

-- §B — the assignment column: reducer truth for where a participant BELONGS
-- (NULL = main room). ON DELETE SET NULL: a destroyed breakout row can never
-- strand an assignment.
ALTER TABLE public.meeting_participants
  ADD COLUMN breakout_id bigint REFERENCES public.meeting_breakouts(id) ON DELETE SET NULL;

-- §C — Q&A rides chat: widen the msg_type CHECK (the V125 'call' precedent
-- verbatim). The route-level allowlist (internal/chat/messages.go) is the
-- client-facing gate and gains 'question' in Task 3; 'poll' stays excluded
-- there (only chat_poll_create may post one).
ALTER TABLE public.chat_messages DROP CONSTRAINT chat_messages_msg_type_check;
ALTER TABLE public.chat_messages ADD CONSTRAINT chat_messages_msg_type_check
  CHECK (msg_type IN ('text', 'voice', 'poll', 'call', 'question'));

-- §D — toggles (DN6: exactly two; polls/Q&A ride feature.meet+feature.chat,
-- whiteboard rides feature.meet — no server surface to gate).
INSERT INTO feature_toggles (key, enabled, description) VALUES
  ('feature.meet_breakouts', false,
   'Meet B3 breakout rooms. Gates the breakout OPEN route only (F11); assign/close/join and the worker reconcile arms run unconditionally so a mid-meeting flip never strands anyone.'),
  ('feature.meet_captions', false,
   'Meet B3 live captions (zh-first, FunASR sidecar pair). Gates the captions START route only; off/reconcile run unconditionally. Requires the setjoin-asr-bot + setjoin-funasr sidecars (ASR_URL).')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (130, now())
    ON CONFLICT (version) DO NOTHING;
