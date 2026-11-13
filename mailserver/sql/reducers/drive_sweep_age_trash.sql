-- mailserver/sql/reducers/drive_sweep_age_trash.sql
-- Task 11 (C6 part 2): extracted from drive_maintenance_sweep.sql's
-- two-level trash cadence leg (P6 Task 4, spec §3.5). Deletion test: this
-- leg is two loops + a computed retry-until-no-progress cadence, not a
-- 1-2 line DELETE — it clears the extract bar the journal/claims/grants
-- legs don't. Same invoker-rights posture as drive_maintenance_sweep /
-- drive_alarm_evaluate (worker-only, never granted/revoked explicitly, no
-- apply_worker_ownership footer).
CREATE OR REPLACE FUNCTION drive_sweep_age_trash(OUT p_aged INT, OUT p_destroyed INT) AS $$
DECLARE
  v_pass INT; v_row RECORD;
BEGIN
  -- tier-1 aging: user-trash older than 30 d falls to tier 2 (purged_by NULL
  -- = aged by the system, not a manager action — AUTOPLAN batch-2 #8).
  -- ponytail: 30 d / 30 d are fixed v1 windows; promote to policy knobs if asked.
  -- ponytail (AUTOPLAN batch-2 #9): drive_node_trash stamps every row in a
  -- trashed subtree with the SAME deleted_at, so an aged subtree's rows all
  -- age out together here and each gets its own 'destroy' journal row — a
  -- deliberate divergence from drive_node_destroy's once-per-root journal
  -- (feed noise on a large aged subtree). Upgrade to a batch-roots-only
  -- notify loop if that noise is ever a real complaint.
  p_aged := 0;
  FOR v_row IN
    WITH aged AS (
      UPDATE drive_nodes
         SET purged_at = now(), purged_by = NULL
       WHERE deleted_at < now() - interval '30 days' AND purged_at IS NULL
       RETURNING space_id, id
    ) SELECT space_id, id FROM aged
  LOOP
    p_aged := p_aged + 1;
    PERFORM drive_notify_change(v_row.space_id, v_row.id, 'destroy');
  END LOOP;

  -- tier-2 grace expiry: hard-destroy leaf-first until no progress
  -- (gxp-in-retention rows return false and simply remain — I-16).
  p_destroyed := 0;
  LOOP
    v_pass := 0;
    FOR v_row IN
      SELECT n.space_id, n.id FROM drive_nodes n
       WHERE n.purged_at < now() - interval '30 days'
         AND NOT EXISTS (SELECT 1 FROM drive_nodes c WHERE c.parent_id = n.id)
    LOOP
      IF drive_node_destroy_hard(v_row.id) THEN v_pass := v_pass + 1; END IF;
    END LOOP;
    p_destroyed := p_destroyed + v_pass;
    EXIT WHEN v_pass = 0;
  END LOOP;
END;
$$ LANGUAGE plpgsql;
