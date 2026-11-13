-- chat_require_role.sql — the chat authorize-preamble seam (arch review #A9).
--
-- BZ163 ("not a member of channel %") was hand-rolled at ~20 reducer sites
-- across chat_pin/chat_message/chat_poll/chat_readers/chat_reaction/
-- chat_save/chat_roster/chat_space_ensure/chat_presence/chat_schedule — the
-- SAME "fetch this user's role in this channel, raise BZ163 if absent (or,
-- at a few sites, if present but not one of a required set)" idiom retyped
-- at every call site. This is the ONE home for that code + message + HINT.
--
-- Deliberately NOT a SECURITY DEFINER / ARCH-018 scope helper: this is
-- application-layer authorize code called BY reducers (the same invoker-
-- rights shape the inline SELECT it replaces already had — ARCH-006,
-- "App-level-primary... membership scoped via a direct SELECT against
-- chat_channel_members, not the chat_member_role() DEFINER helper"), never
-- referenced from inside an RLS POLICY body. Calling it from a SECURITY
-- DEFINER reducer (chat_space_ensure) is safe and behavior-identical to the
-- inline SELECT it replaces: a plain (non-DEFINER) function invoked from
-- within a SECURITY DEFINER function runs with that function's effective
-- role for the duration of the call.
--
-- ARCH-018 §5 shape: returns the role (or raises), never a bare boolean —
-- callers that need a STRICTER check than "is any member" (e.g.
-- chat_poll_close's creator-or-owner/admin gate) capture the return and
-- compare further, exactly as they did with the inline v_role before.
--
-- Scope note (deliberately NOT swept into this call): a handful of BZ163
-- sites are NOT this idiom and were left untouched — chat_message_send/
-- chat_mark_read/chat_pin_toggle/chat_reaction_toggle's role fetch is FUSED
-- into a larger JOIN pulling other required columns in the same statement
-- (post_permission/is_archived/kind/etc — converting would either cost a
-- second round-trip or need a second helper, worse either way); chat_channel.
-- sql's three owner/admin gates raise BZ161 (a different code — "owner/admin
-- required", not "not a member" — out of this pass's scope); chat_channel.
-- sql's org-default-leave guard carries a DIFFERENT HINT (not the generic
-- {"type":"forbidden"}); chat_member_set_notif's guard is a single-statement
-- UPDATE-then-check-FOUND (R3, TOCTOU-safe as-is — converting would add a
-- redundant read for no benefit).
CREATE OR REPLACE FUNCTION chat_require_role(
  p_channel_id bigint, p_user_id bigint, VARIADIC p_min_roles text[] DEFAULT '{}'
) RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE
  v_role text;
BEGIN
  SELECT role INTO v_role FROM chat_channel_members
   WHERE channel_id = p_channel_id AND user_id = p_user_id;
  IF v_role IS NULL
     OR (array_length(p_min_roles, 1) IS NOT NULL AND NOT (v_role = ANY(p_min_roles))) THEN
    RAISE EXCEPTION 'not a member of channel %', p_channel_id
      USING ERRCODE='BZ163', HINT='{"type":"forbidden"}';
  END IF;
  RETURN v_role;
END;
$$;
