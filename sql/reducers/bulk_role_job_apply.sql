-- bulk_role_job_apply.sql — process ONE bulk_role_jobs row. Re-derives the actor's
-- authority + the role's perms LIVE (no enqueue snapshot), then loops user_ids in
-- per-target savepoints: applies passers, records blocked ones, RESUMING at
-- processed so a crash/retry never re-stamps already-applied grants. The SoD and
-- last-Super-Admin triggers are the authoritative backstops; this reducer catches
-- and classifies their raises. Called inside the worker's single job transaction.
CREATE OR REPLACE FUNCTION bulk_role_job_apply(p_job_id bigint) RETURNS void AS $$
DECLARE
  v_job        bulk_role_jobs%ROWTYPE;
  v_actor      record;        -- live perms[] + scope
  v_role_perms text[];        -- role's CURRENT perms (live, not snapshotted)
  v_results    jsonb;
  v_uid        bigint;
  v_status     text;
  v_reason     text;
  v_inserted   boolean;
  v_i          int;
BEGIN
  SELECT * INTO v_job FROM bulk_role_jobs WHERE id = p_job_id FOR UPDATE;
  IF NOT FOUND THEN RETURN; END IF;
  v_results := v_job.results;

  SELECT perms, scope INTO v_actor FROM admin_effective_authority(v_job.actor_id);
  SELECT permissions INTO v_role_perms FROM admin_role_groups WHERE id = v_job.role_id;
  -- The role can be deleted after the job is enqueued (bulk_role_jobs.role_id has no FK;
  -- admin_role_assignments cascade away). Without this guard an 'assign' job's INSERT then
  -- hits the assignments→role FK (SQLSTATE 23503), which the per-target handler below does
  -- NOT classify, so it escapes the txn → the worker retries forever. Fail the job loudly
  -- instead. Mirrors the job-not-found guard above.
  IF NOT FOUND THEN
    UPDATE bulk_role_jobs SET status='error', error='role no longer exists', updated_at=now()
    WHERE id = p_job_id;
    RETURN;
  END IF;
  -- Rule A perms arm — GRANT-only (op='assign'). A grant cannot hand out perms the
  -- actor doesn't hold, so a non-Super actor missing ANY of the role's perms fails
  -- the whole job. Skipped for op='revoke': revoke REMOVES (grants nothing), so the
  -- actor's perm set is irrelevant to it — the per-target admin_protection_check
  -- (BZ065 domination) is the correct, target-scoped guard. This matches the
  -- single-revoke handler (RemoveMember), which applies NEITHER Rule A arm.
  IF v_job.op = 'assign'
     AND NOT admin_is_super(v_job.actor_id)
     AND EXISTS (SELECT 1 FROM unnest(COALESCE(v_role_perms,'{}')) p WHERE NOT (p = ANY(v_actor.perms))) THEN
    UPDATE bulk_role_jobs SET status='error',
      error='actor no longer holds all permissions this role grants', updated_at=now()
    WHERE id = p_job_id;
    RETURN;
  END IF;

  -- Rule A scope arm (companion to the perms-superset check above) — also GRANT-only
  -- (op='assign'). The job carries one uniform OU scope (V040): scope_type/scope_id,
  -- or NULL/NULL for a no-OU (domain-wide on the OU axis) grant. An OU-CONFINED actor
  -- writing a scope wider than their own subtree → self-broaden. We feed the job's
  -- REAL scope into admin_scope_within and pass the actor's own domain (v_actor.scope)
  -- as the grant domain so the domain axis is satisfied by construction — bulk's
  -- per-target loop already enforces the actor's domain via 'out_of_scope' (Rule B),
  -- so admin_scope_within here only tests the OU broadening. Skipped for op='revoke':
  -- a revoke is not a grant, so there is no scope to broaden — the per-target
  -- admin_can_reach (reach/OU) + admin_protection_check (domination/self/last-SA) are
  -- the complete guards, matching the single-revoke handler (neither Rule A arm).
  IF v_job.op = 'assign'
     AND NOT admin_is_super(v_job.actor_id)
     AND NOT admin_scope_within(v_job.actor_id, v_job.scope_type, v_job.scope_id, v_actor.scope) THEN
    UPDATE bulk_role_jobs SET status='error',
      error='actor cannot grant a scope broader than their own reach', updated_at=now()
    WHERE id = p_job_id;
    RETURN;
  END IF;

  FOR v_i IN (v_job.processed + 1) .. cardinality(v_job.user_ids) LOOP
    v_uid := v_job.user_ids[v_i]; v_status := NULL; v_reason := NULL;
    BEGIN
      IF NOT admin_can_reach(v_job.actor_id, v_uid) THEN
        v_status := 'blocked'; v_reason := 'out_of_scope';
      ELSIF v_job.op = 'assign' THEN
        PERFORM admin_protection_check(v_job.actor_id, v_uid, 'assign_role', v_job.role_id);
        INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by, expires_at, scope_type, scope_id, eligible)
          VALUES (v_uid, v_job.role_id, v_job.actor_id, v_job.expires_at, v_job.scope_type, v_job.scope_id, v_job.eligible)
          ON CONFLICT (user_id, role_group_id)
          DO UPDATE SET expires_at = EXCLUDED.expires_at, granted_by = EXCLUDED.granted_by,
                        scope_type = EXCLUDED.scope_type, scope_id = EXCLUDED.scope_id, granted_at = now(),
                        eligible = EXCLUDED.eligible
          RETURNING (xmax = 0) INTO v_inserted;
        v_status := CASE WHEN v_inserted THEN 'assigned' ELSE 'updated' END;
        -- WP3/astra P2-5: granting/updating an admin role assignment is an
        -- authority transition — core-tier evidence with the acting admin.
        PERFORM audit_write(
          v_job.actor_id, 'bulk_role_assign', 'admin_role_assignment', v_uid,
          NULL,
          jsonb_build_object('role_group_id', v_job.role_id,
                             'expires_at', v_job.expires_at,
                             'scope_type', v_job.scope_type),
          NULL, 'bulk job ' || v_job.id, 'core');
      ELSE  -- revoke
        PERFORM admin_protection_check(v_job.actor_id, v_uid, 'remove_role', v_job.role_id);
        DELETE FROM admin_role_assignments WHERE user_id = v_uid AND role_group_id = v_job.role_id;
        v_status := CASE WHEN FOUND THEN 'revoked' ELSE 'not_member' END;
        IF v_status = 'revoked' THEN
          -- WP3/astra P2-5: revoking an admin role assignment is an
          -- authority transition — core-tier evidence with the acting admin.
          PERFORM audit_write(
            v_job.actor_id, 'bulk_role_revoke', 'admin_role_assignment', v_uid,
            jsonb_build_object('role_group_id', v_job.role_id),
            NULL, NULL, 'bulk job ' || v_job.id, 'core');
        END IF;
      END IF;
    EXCEPTION
      WHEN sqlstate 'BZ001' THEN v_status := 'blocked'; v_reason := 'sod_conflict';
      WHEN sqlstate 'BZ065' THEN v_status := 'blocked'; v_reason := 'domination';
      WHEN sqlstate 'BZ066' THEN v_status := 'blocked'; v_reason := 'self';
      WHEN sqlstate 'BZ064' THEN v_status := 'blocked'; v_reason := 'last_super_admin';
    END;
    v_results := v_results || jsonb_build_object('userId', v_uid, 'status', v_status, 'reason', v_reason);
    UPDATE bulk_role_jobs SET processed = v_i, results = v_results, updated_at = now() WHERE id = p_job_id;
  END LOOP;
END;
$$ LANGUAGE plpgsql VOLATILE;
