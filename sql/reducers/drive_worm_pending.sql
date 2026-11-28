-- mailserver/sql/reducers/drive_worm_pending.sql
-- drive_worm_pending: per-space count of gxp chunks whose Object-Lock apply
-- is still pending (G1 admin surface — wormPending is DERIVED state, no
-- queue: reads drive_chunks.worm_pending, a STORED generated column, C3).
-- SECURITY DEFINER, owned by
-- setjoin_worker (BYPASSRLS) via the V115-genre DO block footer (AUTOPLAN
-- batch-2 #1, BLOCKER): drive_chunks' SELECT policy (I-4 anti-oracle) is
-- per-caller (upload-claim ownership or space membership) — an admin who is
-- not a member of every gxp space would silently see '[]' under an
-- un-escalated run, not a true count. Gated on drive.view via P1's
-- drive_has_admin_perm(p_user_id, 'drive.view') helper — NOT an inline
-- admin_assignment_active subquery (that helper's real signature is
-- (p_eligible boolean, p_activated_until timestamptz), not a single
-- admin_role_assignments row; drive_has_admin_perm already applies it
-- internally).
CREATE OR REPLACE FUNCTION drive_worm_pending(p_user_id bigint) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_out jsonb;
BEGIN
  IF NOT drive_has_admin_perm(p_user_id, 'drive.view') THEN
    RAISE EXCEPTION 'drive.view required' USING ERRCODE = 'BZ140',
      HINT = '{"type":"forbidden","detail":"drive.view required"}';
  END IF;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
           'spaceId', t.space_id, 'pending', t.pending, 'oldest', t.oldest)), '[]'::jsonb)
    INTO v_out
    FROM (SELECT substring(c.scope_key from 2)::bigint AS space_id,
                 count(*) AS pending, min(c.created_at) AS oldest
            FROM drive_chunks c
           WHERE c.scope_key LIKE 's%'
             AND c.worm_pending
           GROUP BY 1) t;
  RETURN v_out;
END;
$$;

SELECT apply_worker_ownership('drive_worm_pending(BIGINT)'::regprocedure);
