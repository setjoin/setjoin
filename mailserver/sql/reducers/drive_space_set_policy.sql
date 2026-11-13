-- mailserver/sql/reducers/drive_space_set_policy.sql
-- Manager-gated (or drive.manage admin) validation + write of export_policy
-- plus the gxp knobs (retention_days/worm_mode) and the client-side vault pin
-- quota (vault_quota_mb — distinct from the server drive_spaces.quota_bytes,
-- §9.2). Closed key/value catalog; a gxp space may never store a value that
-- weakens the §9.2 hard floor (drive_policy_resolve's own floor still wins
-- even if this check had a gap — belt and suspenders).
CREATE OR REPLACE FUNCTION drive_space_set_policy(
  p_user_id        BIGINT,
  p_space_id       BIGINT,
  p_export_policy  JSONB,
  p_retention_days INT   DEFAULT NULL,
  p_worm_mode      TEXT  DEFAULT NULL,
  p_vault_quota_mb INT   DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
  v_role   TEXT;
  v_key    TEXT;
  v_val    JSONB;
  v_old    JSONB;
  v_class  TEXT;
  v_policy JSONB := COALESCE(p_export_policy, '{}'::jsonb);
BEGIN
  IF NOT public.drive_runtime_has_space_root_capability(
       p_user_id,p_space_id,'manage_acl')
     AND NOT drive_has_admin_perm(p_user_id, 'drive.manage') THEN
    RAISE EXCEPTION 'space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;

  FOR v_key, v_val IN SELECT key, value FROM jsonb_each(v_policy) LOOP
    IF v_key NOT IN ('export','print','share','watermark','audit_reads',
                     'edit_lock','upload_max_bytes','upload_ext_deny') THEN
      RAISE EXCEPTION 'unknown policy key %', v_key USING ERRCODE='BZ141',
        HINT=jsonb_build_object('type','invalidArguments','detail','unknown policy key: '||v_key)::text;
    END IF;
    IF v_key IN ('export','print') AND (v_val#>>'{}') NOT IN ('allow','approval') THEN
      RAISE EXCEPTION 'invalid % value', v_key USING ERRCODE='BZ141',
        HINT=jsonb_build_object('type','invalidArguments','detail',v_key||' must be allow|approval')::text;
    END IF;
    IF v_key = 'share' AND (v_val#>>'{}') NOT IN ('direct','approval') THEN
      RAISE EXCEPTION 'invalid share value' USING ERRCODE='BZ141',
        HINT='{"type":"invalidArguments","detail":"share must be direct|approval"}';
    END IF;
    IF v_key = 'edit_lock' AND (v_val#>>'{}') NOT IN ('soft','required') THEN
      RAISE EXCEPTION 'invalid edit_lock value' USING ERRCODE='BZ141',
        HINT='{"type":"invalidArguments","detail":"edit_lock must be soft|required"}';
    END IF;
    IF v_key IN ('watermark','audit_reads') AND jsonb_typeof(v_val) <> 'boolean' THEN
      RAISE EXCEPTION 'invalid % value', v_key USING ERRCODE='BZ141',
        HINT=jsonb_build_object('type','invalidArguments','detail',v_key||' must be boolean')::text;
    END IF;
    IF v_key = 'upload_max_bytes'
       AND (jsonb_typeof(v_val) <> 'number' OR (v_val#>>'{}')::numeric <= 0) THEN
      RAISE EXCEPTION 'invalid upload_max_bytes' USING ERRCODE='BZ141',
        HINT='{"type":"invalidArguments","detail":"upload_max_bytes must be a positive number"}';
    END IF;
    IF v_key = 'upload_ext_deny'
       AND (jsonb_typeof(v_val) <> 'array'
            OR EXISTS (SELECT 1 FROM jsonb_array_elements(v_val) e WHERE jsonb_typeof(e) <> 'string')) THEN
      RAISE EXCEPTION 'invalid upload_ext_deny' USING ERRCODE='BZ141',
        HINT='{"type":"invalidArguments","detail":"upload_ext_deny must be an array of strings"}';
    END IF;
  END LOOP;

  SELECT classification INTO v_class FROM drive_spaces WHERE id = p_space_id;
  IF v_class = 'gxp' THEN
    IF COALESCE(v_policy->>'export', 'approval') <> 'approval'
       OR COALESCE(v_policy->>'print', 'approval') <> 'approval'
       OR COALESCE(v_policy->>'share', 'approval') <> 'approval'
       OR COALESCE((v_policy->>'audit_reads')::boolean, TRUE) = FALSE THEN
      RAISE EXCEPTION 'gxp floor cannot be weakened' USING ERRCODE='BZ141',
        HINT='{"type":"invalidArguments","detail":"gxp requires export/print/share=approval and audit_reads=true"}';
    END IF;
  END IF;

  IF p_vault_quota_mb IS NOT NULL AND p_vault_quota_mb <= 0 THEN
    RAISE EXCEPTION 'invalid vault_quota_mb' USING ERRCODE='BZ141',
      HINT='{"type":"invalidArguments","detail":"vault_quota_mb must be positive"}';
  END IF;

  SELECT export_policy INTO v_old FROM drive_spaces WHERE id = p_space_id;
  UPDATE drive_spaces
     SET export_policy   = v_policy,
         retention_days  = COALESCE(p_retention_days, retention_days),
         worm_mode       = COALESCE(p_worm_mode, worm_mode),
         vault_quota_mb  = COALESCE(p_vault_quota_mb, vault_quota_mb)
   WHERE id = p_space_id;  -- trigger backstops any gxp retention/worm relaxation (BZ142)
  IF NOT FOUND THEN
    RAISE EXCEPTION 'space not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"space not found"}';
  END IF;

  PERFORM drive_access_audit(p_user_id, p_space_id, 'policy.change', 'space', p_space_id,
    jsonb_build_object('exportPolicy', v_old), jsonb_build_object('exportPolicy', v_policy), NULL, NULL);
  PERFORM drive_notify_change(p_space_id, 0, 'space');
END;
$$ LANGUAGE plpgsql;
