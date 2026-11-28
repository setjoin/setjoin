-- mailserver/sql/reducers/drive_access_audit.sql
-- Per-space tamper-evident audit chain: writer + verifier (spec §9.3; V037/V087
-- primitives; per-space advisory lock — NOT admin_audit_log's global one, arch D10).
-- Checksum lives in after_state->>'_checksum'; the hash is computed over the
-- checksum-FREE after_state (V037 convention). BZ141 = unknown action.
--
-- Writer is SECURITY DEFINER, owned by setjoin_worker (BYPASSRLS) where
-- provisioned (P1 plan Task 4 correction): it does MAX(id)+1 over
-- drive_audit_log, which under FORCE RLS as an invoker without membership/
-- drive.view (e.g. setjoin_owner running DDL/admin-only quota writes) would
-- see 0 rows and collide every space's chain on primary key id=1. DEFINER +
-- worker ownership makes MAX(id) see the whole table regardless of caller
-- (batch-3 item 2 of the AUTOPLAN CORRECTIONS).
CREATE OR REPLACE FUNCTION drive_access_audit(
  p_user_id     BIGINT,
  p_space_id    BIGINT,
  p_action      TEXT,
  p_target_type TEXT,
  p_target_id   BIGINT,
  p_before      JSONB,
  p_after       JSONB,
  p_ip          INET,
  p_notes       TEXT
) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_id   BIGINT;
  v_now  TIMESTAMPTZ := now();
  v_prev TEXT;
  v_sum  TEXT;
  v_v3   BOOLEAN := coalesce(current_setting('app.audit_hmac_key', TRUE), '') <> '';
BEGIN
  -- Closed event catalog (§9.3): validated against drive_audit_actions(), the
  -- single-source-of-truth catalog (Task 6) — no inline copy of the action
  -- list lives here anymore.
  IF p_action NOT IN (SELECT jsonb_array_elements_text(drive_audit_actions())) THEN
    RAISE EXCEPTION 'unknown drive audit action %', p_action
      USING ERRCODE='BZ141', HINT='{"type":"invalidArguments","detail":"unknown audit action"}';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtext('drive_audit_' || p_space_id::text));
  SELECT COALESCE(MAX(id), 0) + 1 INTO v_id FROM drive_audit_log WHERE space_id = p_space_id;
  SELECT after_state->>'_checksum' INTO v_prev
    FROM drive_audit_log WHERE space_id = p_space_id AND id = v_id - 1;

  v_sum := audit_row_hash_v(v_v3, v_id, v_now, p_user_id, p_ip,
                            p_action, p_target_type, p_target_id,
                            p_before, p_after, p_notes, v_prev);
  INSERT INTO drive_audit_log (space_id, id, occurred_at, user_id, ip, action,
                               target_type, target_id, before_state, after_state, notes)
  VALUES (p_space_id, v_id, v_now, p_user_id, p_ip, p_action,
          p_target_type, p_target_id, p_before,
          COALESCE(p_after, '{}'::jsonb) || jsonb_build_object('_checksum', v_sum), p_notes);
  RETURN v_id;
END;
$$;

SELECT apply_worker_ownership('drive_access_audit(BIGINT, BIGINT, TEXT, TEXT, BIGINT, JSONB, JSONB, INET, TEXT)'::regprocedure);

-- Verifier: walk one space's chain exactly as verify_audit_chain (V087:69) walks
-- the global one — recompute over after_state minus '_checksum', chain forward
-- on the STORED checksum, per-row V2/V3 branch on the 'v3:' prefix. Invoker
-- rights: a caller only sees rows their own drive_audit_log_read policy grants
-- (member or drive.view admin) — that IS the desired scoping, not a bypass.
CREATE OR REPLACE FUNCTION verify_drive_audit_chain(
  p_space_id BIGINT, p_from_id BIGINT DEFAULT NULL, p_to_id BIGINT DEFAULT NULL
) RETURNS TABLE(row_id BIGINT, valid BOOLEAN, occurred_at TIMESTAMPTZ, action TEXT) AS $$
DECLARE
  v_prev TEXT := NULL; v_row RECORD; v_calc TEXT; v_is_v3 BOOLEAN;
  v_have_key BOOLEAN := coalesce(current_setting('app.audit_hmac_key', TRUE), '') <> '';
BEGIN
  IF p_from_id IS NOT NULL THEN
    SELECT after_state->>'_checksum' INTO v_prev FROM drive_audit_log
     WHERE space_id = p_space_id AND id < p_from_id ORDER BY id DESC LIMIT 1;
  END IF;
  FOR v_row IN
    SELECT * FROM drive_audit_log
     WHERE space_id = p_space_id
       AND (p_from_id IS NULL OR id >= p_from_id) AND (p_to_id IS NULL OR id <= p_to_id)
     ORDER BY id
  LOOP
    v_is_v3 := (v_row.after_state->>'_checksum') LIKE 'v3:%';
    row_id := v_row.id; occurred_at := v_row.occurred_at; action := v_row.action;
    IF v_is_v3 AND NOT v_have_key THEN
      valid := FALSE;  -- unverifiable without the secret
    ELSE
      v_calc := audit_row_hash_v(v_is_v3,
        v_row.id, v_row.occurred_at, v_row.user_id, v_row.ip,
        v_row.action, v_row.target_type, v_row.target_id, v_row.before_state,
        (v_row.after_state - '_checksum'), v_row.notes, v_prev);
      valid := (v_calc = v_row.after_state->>'_checksum');
    END IF;
    v_prev := v_row.after_state->>'_checksum';
    RETURN NEXT;
  END LOOP;
END;
$$ LANGUAGE plpgsql STABLE;
