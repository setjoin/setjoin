-- federation_room_has_active_members.sql — Pillar C2 Task 2: the Q13
-- archive-refusal probe. federation_room_members is FORCE RLS deny-all (no
-- membership axis on per-domain federation infrastructure), so a plain
-- invoker-rights SELECT from chat_channel_update (invoker rights, Task 2)
-- would silently see ZERO rows and allow EVERY hub archive — the recurring
-- DEFINER-under-FORCE-RLS trap. This one-query DEFINER probe is the fix,
-- its own file per the one-reducer-per-file rule.
--
-- "Active" here means "non-left" (left_at IS NULL) — a PARKED member still
-- counts (a cap-parked member is a valid room member the hub must remove
-- before archiving, not an already-departed one); only REMOVED/REVOKED
-- (left_at IS NOT NULL) members are excluded.
CREATE OR REPLACE FUNCTION federation_room_has_active_members(p_room_id text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM federation_room_members
     WHERE room_id = p_room_id AND left_at IS NULL
  );
END;
$$;
SELECT apply_worker_ownership('federation_room_has_active_members(text)'::regprocedure);
