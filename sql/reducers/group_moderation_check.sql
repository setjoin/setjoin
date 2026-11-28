-- group_moderation_check: inbound moderated-group gate (anti-spam + moderation), T8.
-- Reads the distribution group's now-live settings and returns the delivery verdict:
--   'reject'  → allow_external_senders = false AND the sender is external
--               (hard anti-spam block — an external poster to a closed group).
--   'hold'    → the group is moderated (park for moderator approval).
--   'deliver' → otherwise (expand to members now, exactly as today).
-- An unknown group id → 'deliver' (no moderation; never a new failure mode).
-- Pure read; SECURITY INVOKER.
CREATE OR REPLACE FUNCTION group_moderation_check(
  p_group_id        bigint,
  p_sender_external boolean
) RETURNS text AS $$
DECLARE
  v_grp RECORD;
BEGIN
  SELECT allow_external_senders, moderated
    INTO v_grp
    FROM distribution_groups
   WHERE id = p_group_id;

  IF NOT FOUND THEN
    RETURN 'deliver';
  END IF;

  IF p_sender_external AND NOT v_grp.allow_external_senders THEN
    RETURN 'reject';
  END IF;

  IF v_grp.moderated THEN
    RETURN 'hold';
  END IF;

  RETURN 'deliver';
END;
$$ LANGUAGE plpgsql STABLE SECURITY INVOKER;
