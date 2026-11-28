-- meeting_require_authority.sql — the meet authorize-preamble seam (arch
-- review #A9).
--
-- BZ186 ("host or cohost authority required...") was hand-rolled at 11
-- reducer sites across meeting_control/meeting_breakout/meeting_recording/
-- meeting_lobby — the SAME "read this user's meeting role, raise BZ186
-- unless it's host or cohost" idiom retyped at every call site (one comment
-- calls the shape "byte-identical by construction"). This is the ONE home
-- for that code + HINT.
--
-- Deliberately NOT a SECURITY DEFINER / ARCH-018 scope helper itself — it
-- DELEGATES to meeting_member_role (row 5 of the ARCH-018 matrix) for the
-- actual membership read, then applies the host/cohost floor + raises.
-- Never referenced from inside an RLS POLICY body.
--
-- ARCH-018 §5 shape: returns the role (host/cohost), never a bare boolean —
-- this is the FLOOR every real call site needs; the two sites that need a
-- STRICTER host-ONLY gate (meeting_set_role, meeting_end) call this first
-- (closing "not even cohost" with the shared code+HINT) and then add their
-- own trivial `v_role <> 'host'` check on the returned value for the
-- narrower requirement — same BZ186 code, their own specific message.
--
-- Scope note (deliberately NOT swept into this call): meeting_create.sql's
-- BZ186 site is a chat-channel-membership check (launching a huddle into an
-- existing channel), not a meeting-authority check — different predicate,
-- reuses the code by coincidence, not construction. meeting_join.sql's
-- BZ186 site is the banned-participant state check, also a different
-- predicate. Neither is this idiom; both are left untouched.
CREATE OR REPLACE FUNCTION meeting_require_authority(
  p_meeting_id bigint, p_user_id bigint
) RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE
  v_role text;
BEGIN
  v_role := meeting_member_role(p_meeting_id, p_user_id);
  IF COALESCE(v_role, '') NOT IN ('host', 'cohost') THEN
    RAISE EXCEPTION 'host or cohost authority required for meeting %', p_meeting_id
      USING ERRCODE='BZ186', HINT='{"type":"forbidden"}';
  END IF;
  RETURN v_role;
END;
$$;
