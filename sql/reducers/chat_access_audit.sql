-- mailserver/sql/reducers/chat_access_audit.sql
-- Per-channel tamper-evident audit chain: writer + verifier. A hand-transcribed
-- clone of drive_access_audit.sql:14-56/65-97 — the root of trust for every
-- evidentiary claim A4a makes (Task 2, verify C4 — HIGHEST-RISK uncoded step
-- in the A4a plan; full adversarial review required before Task 3 builds on
-- this file). Checksum lives in after_state->>'_checksum' (V037 convention);
-- the hash is computed over the checksum-FREE after_state. BZ191 = unknown
-- action (the drive BZ141 genre, chat's own namespace).
--
-- Writer is SECURITY DEFINER, worker-owned (apply_worker_ownership): it does
-- MAX(id)+1 over chat_audit_log, which is FORCE-RLS + ZERO policies (deny-all)
-- — an invoker-rights caller would see 0 rows and collide every channel's
-- chain on id=1 (the same P1-Task-4 DEFINER-under-FORCE-RLS trap drive's
-- writer dodges).
CREATE OR REPLACE FUNCTION chat_access_audit(
  p_user_id     BIGINT,
  p_channel_id  BIGINT,
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
  -- Closed event catalog: validated against chat_audit_actions(), the
  -- single-source-of-truth catalog (Task 2) — no inline copy of the action
  -- list lives here.
  IF p_action NOT IN (SELECT jsonb_array_elements_text(chat_audit_actions())) THEN
    RAISE EXCEPTION 'unknown chat audit action %', p_action
      USING ERRCODE='BZ191', HINT='{"type":"invalidArguments","detail":"unknown audit action"}';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtext('chat_audit_' || p_channel_id::text));
  SELECT COALESCE(MAX(id), 0) + 1 INTO v_id FROM chat_audit_log WHERE channel_id = p_channel_id;
  SELECT after_state->>'_checksum' INTO v_prev
    FROM chat_audit_log WHERE channel_id = p_channel_id AND id = v_id - 1;

  v_sum := audit_row_hash_v(v_v3, v_id, v_now, p_user_id, p_ip,
                            p_action, p_target_type, p_target_id,
                            p_before, p_after, p_notes, v_prev);
  INSERT INTO chat_audit_log (channel_id, id, occurred_at, user_id, ip, action,
                              target_type, target_id, before_state, after_state, notes)
  VALUES (p_channel_id, v_id, v_now, p_user_id, p_ip, p_action,
          p_target_type, p_target_id, p_before,
          COALESCE(p_after, '{}'::jsonb) || jsonb_build_object('_checksum', v_sum), p_notes);
  RETURN v_id;
END;
$$;

SELECT apply_worker_ownership('chat_access_audit(BIGINT, BIGINT, TEXT, TEXT, BIGINT, JSONB, JSONB, INET, TEXT)'::regprocedure);

-- Verifier: walk one channel's chain exactly as verify_drive_audit_chain
-- (drive_access_audit.sql:65-97) walks a space's — recompute over after_state
-- minus '_checksum', chain forward on the STORED checksum, per-row V2/V3
-- branch on the 'v3:' prefix. Invoker rights: chat_audit_log is deny-all, so
-- this only ever returns rows on the workerPool (BYPASSRLS) admin path — the
-- desired scoping, and why authorization is route-declared, not RLS-declared.
CREATE OR REPLACE FUNCTION verify_chat_audit_chain(
  p_channel_id BIGINT, p_from_id BIGINT DEFAULT NULL, p_to_id BIGINT DEFAULT NULL
) RETURNS TABLE(row_id BIGINT, valid BOOLEAN, occurred_at TIMESTAMPTZ, action TEXT) AS $$
DECLARE
  v_prev TEXT := NULL; v_row RECORD; v_calc TEXT; v_is_v3 BOOLEAN;
  v_have_key BOOLEAN := coalesce(current_setting('app.audit_hmac_key', TRUE), '') <> '';
BEGIN
  IF p_from_id IS NOT NULL THEN
    SELECT after_state->>'_checksum' INTO v_prev FROM chat_audit_log
     WHERE channel_id = p_channel_id AND id < p_from_id ORDER BY id DESC LIMIT 1;
  END IF;
  FOR v_row IN
    SELECT * FROM chat_audit_log
     WHERE channel_id = p_channel_id
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
