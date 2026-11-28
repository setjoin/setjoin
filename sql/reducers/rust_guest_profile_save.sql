-- F11 frozen-Go profile save transaction: mutation followed by its authorized
-- representation read. No new business policy; Go keeps its two calls.
CREATE OR REPLACE FUNCTION rust_guest_profile_save(
 p_actor bigint, p_profile_id bigint, p_body jsonb
) RETURNS jsonb LANGUAGE plpgsql VOLATILE AS $$
DECLARE v_id bigint;
BEGIN
 v_id := guest_profile_set(p_actor,p_profile_id,(p_body->>'hostDomainId')::bigint,
  p_body->>'name',(p_body->>'canPost')::boolean,(p_body->>'historyFromJoin')::boolean,
  (p_body->>'allowDownload')::boolean,(p_body->>'allowMeetCreate')::boolean,
  (p_body->>'allowMeetHost')::boolean,(p_body->>'canInitiateDm')::boolean,
  (p_body->>'allowNativeShell')::boolean,(p_body->>'defaultExpiryDays')::integer,
  ARRAY(SELECT jsonb_array_elements_text(p_body->'apps')));
 RETURN guest_profile_get(p_actor,v_id);
END;
$$;
