-- V087__audit_chain_hmac.sql — audit chain V3: HMAC-keyed row hash.
--
-- V037's chain hashes rows with plain sha256 — anyone who can READ
-- admin_audit_log can recompute (forge) any checksum from scratch; V068's
-- REVOKE narrowed who may CALL the functions, not who can reproduce the math.
-- V3 keys the hash with HMAC-SHA256 under `app.audit_hmac_key`, a session GUC
-- the gateway/authserver set at connect time from the AUDIT_HMAC_KEY
-- environment secret (never stored in the DB — see shared/pgxutil/pool.go and
-- deploy/pgbouncer.ini track_extra_parameters). Without the secret, forging a
-- V3 checksum is computationally infeasible.
--
-- VERSIONED chain migration (V2 → V3), NOT in-place: existing rows keep their
-- V2 sha256 checksums (no backfill — a backfill would need the key inside the
-- migration, i.e. in the DB). The discriminator is a checksum PREFIX: V3 rows
-- store 'v3:' || hmac-hex; V2 rows stay bare sha256 hex. verify_audit_chain
-- branches per row on that stored prefix, so a mixed chain verifies.
--
-- Missing key (GUC unset/empty) = fall back to unkeyed V2 writes, so an
-- on-prem upgrade without AUDIT_HMAC_KEY configured keeps working (the
-- gateway WARNs loudly at boot). verify reports a V3 row as invalid (not an
-- error) in a keyless session — it is unverifiable without the secret.
-- ponytail: graceful fallback means an attacker with DB write access could
-- rewrite V3 rows back to V2 form; a strict mode (reject V2 rows after a
-- cutover id) can come when the threat model demands it.

-- The SINGLE V2+V3 formula (field-concat + both algorithms) — trigger AND
-- verify route through this so there is no formula drift (V037's invariant).
-- p_v3 selects the algorithm: TRUE → 'v3:'||HMAC(session key), FALSE → sha256.
-- STABLE (not IMMUTABLE): the V3 branch reads the session GUC.
CREATE OR REPLACE FUNCTION public.audit_row_hash_v(
  p_v3 boolean,
  p_id bigint, p_occurred_at timestamptz, p_user_id bigint, p_ip inet,
  p_action text, p_target_type text, p_target_id bigint,
  p_before jsonb, p_after jsonb, p_notes text, p_prev text
) RETURNS text AS $$
  SELECT CASE WHEN p_v3
    THEN 'v3:' || encode(public.hmac(
      (p_id::text || coalesce(p_occurred_at::text,'') || coalesce(p_user_id::text,'') ||
       coalesce(p_ip::text,'') || p_action || coalesce(p_target_type,'') ||
       coalesce(p_target_id::text,'') || public.audit_canon(p_before) ||
       public.audit_canon(p_after) || coalesce(p_notes,'') || coalesce(p_prev,''))::bytea,
      current_setting('app.audit_hmac_key', TRUE)::bytea, 'sha256'), 'hex')
    ELSE encode(sha256((
      p_id::text || coalesce(p_occurred_at::text,'') || coalesce(p_user_id::text,'') ||
      coalesce(p_ip::text,'') || p_action || coalesce(p_target_type,'') ||
      coalesce(p_target_id::text,'') || public.audit_canon(p_before) ||
      public.audit_canon(p_after) || coalesce(p_notes,'') || coalesce(p_prev,'')
    )::bytea), 'hex')
  END;
$$ LANGUAGE sql STABLE;

-- audit_row_hash keeps its V037 signature (the trigger calls it unchanged) but
-- now writes V3 when the session key is present, V2 otherwise. CREATE OR
-- REPLACE preserves the V068 ACL (PUBLIC revoked, three runtime roles granted).
CREATE OR REPLACE FUNCTION public.audit_row_hash(
  p_id bigint, p_occurred_at timestamptz, p_user_id bigint, p_ip inet,
  p_action text, p_target_type text, p_target_id bigint,
  p_before jsonb, p_after jsonb, p_notes text, p_prev text
) RETURNS text AS $$
  SELECT public.audit_row_hash_v(
    coalesce(current_setting('app.audit_hmac_key', TRUE), '') <> '',
    p_id, p_occurred_at, p_user_id, p_ip, p_action, p_target_type, p_target_id,
    p_before, p_after, p_notes, p_prev);
$$ LANGUAGE sql STABLE;

-- verify: branch per ROW on the stored 'v3:' prefix (not on the session key),
-- so a mixed V2+V3 chain verifies. A V3 row in a keyless session is reported
-- invalid — unverifiable without the secret — rather than raising.
CREATE OR REPLACE FUNCTION public.verify_audit_chain(p_from_id bigint DEFAULT NULL, p_to_id bigint DEFAULT NULL)
RETURNS TABLE(row_id bigint, valid boolean, occurred_at timestamptz, action text) AS $$
DECLARE
  v_prev text := NULL; v_row RECORD; v_calc text; v_is_v3 boolean;
  v_have_key boolean := coalesce(current_setting('app.audit_hmac_key', TRUE), '') <> '';
BEGIN
  IF p_from_id IS NOT NULL THEN
    SELECT checksum INTO v_prev FROM admin_audit_log WHERE id < p_from_id ORDER BY id DESC LIMIT 1;
  END IF;
  FOR v_row IN
    SELECT * FROM admin_audit_log
     WHERE (p_from_id IS NULL OR id >= p_from_id) AND (p_to_id IS NULL OR id <= p_to_id)
     ORDER BY id
  LOOP
    v_is_v3 := v_row.checksum LIKE 'v3:%';
    row_id := v_row.id; occurred_at := v_row.occurred_at; action := v_row.action;
    IF v_is_v3 AND NOT v_have_key THEN
      valid := FALSE;   -- V3 row, no key in this session: unverifiable.
    ELSE
      v_calc := public.audit_row_hash_v(v_is_v3,
        v_row.id, v_row.occurred_at, v_row.user_id, v_row.ip,
        v_row.action, v_row.target_type, v_row.target_id, v_row.before_state,
        v_row.after_state, v_row.notes, v_prev);
      valid := (v_calc = v_row.checksum);
    END IF;
    v_prev := v_row.checksum;   -- chain forward on the STORED checksum
    RETURN NEXT;
  END LOOP;
END;
$$ LANGUAGE plpgsql STABLE;

-- ACL: mirror V068 for the new helper (audit_row_hash / verify_audit_chain
-- keep their V068 ACLs across CREATE OR REPLACE).
REVOKE EXECUTE ON FUNCTION public.audit_row_hash_v(
  boolean, bigint, timestamptz, bigint, inet, text, text, bigint, jsonb, jsonb, text, text
) FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
    GRANT EXECUTE ON FUNCTION public.audit_row_hash_v(boolean, bigint, timestamptz, bigint, inet, text, text, bigint, jsonb, jsonb, text, text) TO setjoin_owner;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
    GRANT EXECUTE ON FUNCTION public.audit_row_hash_v(boolean, bigint, timestamptz, bigint, inet, text, text, bigint, jsonb, jsonb, text, text) TO setjoin_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    GRANT EXECUTE ON FUNCTION public.audit_row_hash_v(boolean, bigint, timestamptz, bigint, inet, text, text, bigint, jsonb, jsonb, text, text) TO setjoin_worker;
  END IF;
END $$;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (87, now()) ON CONFLICT DO NOTHING;
