-- V232: protected audit V3 cutover. After activation, every new row must use
-- the configured HMAC key and a stored checksum prefix can no longer downgrade
-- verification back to unkeyed SHA-256.
CREATE TABLE IF NOT EXISTS public.audit_chain_cutover (
  singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  activated_at timestamptz NOT NULL DEFAULT now(),
  first_v3_id bigint NOT NULL CHECK (first_v3_id > 0),
  anchor_checksum text
);

CREATE OR REPLACE FUNCTION public.audit_chain_activate_v3() RETURNS bigint AS $$
DECLARE v_first bigint; v_anchor text;
BEGIN
  IF coalesce(current_setting('app.audit_hmac_key', TRUE), '') = '' THEN
    RAISE EXCEPTION 'AUDIT_HMAC_KEY is required to activate audit V3';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('audit-chain-v3-cutover', 0));
  SELECT first_v3_id INTO v_first FROM public.audit_chain_cutover WHERE singleton;
  IF FOUND THEN RETURN v_first; END IF;
  SELECT coalesce(max(id), 0) + 1 INTO v_first FROM public.admin_audit_log;
  SELECT checksum INTO v_anchor FROM public.admin_audit_log ORDER BY id DESC LIMIT 1;
  INSERT INTO public.audit_chain_cutover(singleton, first_v3_id, anchor_checksum)
  VALUES (TRUE, v_first, v_anchor);
  RETURN v_first;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION public.audit_row_hash(
  p_id bigint, p_occurred_at timestamptz, p_user_id bigint, p_ip inet,
  p_action text, p_target_type text, p_target_id bigint,
  p_before jsonb, p_after jsonb, p_notes text, p_prev text
) RETURNS text AS $$
DECLARE v_cutover bigint; v_have_key boolean;
BEGIN
  v_have_key := coalesce(current_setting('app.audit_hmac_key', TRUE), '') <> '';
  SELECT first_v3_id INTO v_cutover FROM public.audit_chain_cutover WHERE singleton;
  IF v_cutover IS NOT NULL AND p_id >= v_cutover AND NOT v_have_key THEN
    RAISE EXCEPTION 'audit HMAC key missing after protected cutover';
  END IF;
  RETURN public.audit_row_hash_v(v_have_key, p_id, p_occurred_at, p_user_id, p_ip,
    p_action, p_target_type, p_target_id, p_before, p_after, p_notes, p_prev);
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION public.verify_audit_chain(p_from_id bigint DEFAULT NULL, p_to_id bigint DEFAULT NULL)
RETURNS TABLE(row_id bigint, valid boolean, occurred_at timestamptz, action text) AS $$
DECLARE
  v_prev text := NULL; v_row RECORD; v_calc text; v_is_v3 boolean;
  v_have_key boolean := coalesce(current_setting('app.audit_hmac_key', TRUE), '') <> '';
  v_cutover bigint;
BEGIN
  SELECT first_v3_id INTO v_cutover FROM public.audit_chain_cutover WHERE singleton;
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
    IF (v_cutover IS NOT NULL AND v_row.id >= v_cutover AND NOT v_is_v3)
       OR (v_is_v3 AND NOT v_have_key) THEN
      valid := FALSE;
    ELSE
      v_calc := public.audit_row_hash_v(v_is_v3, v_row.id, v_row.occurred_at,
        v_row.user_id, v_row.ip, v_row.action, v_row.target_type, v_row.target_id,
        v_row.before_state, v_row.after_state, v_row.notes, v_prev);
      valid := (v_calc = v_row.checksum);
    END IF;
    v_prev := v_row.checksum;
    RETURN NEXT;
  END LOOP;
END;
$$ LANGUAGE plpgsql STABLE;

REVOKE ALL ON public.audit_chain_cutover FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.audit_chain_activate_v3() FROM PUBLIC;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_app') THEN
    GRANT SELECT ON public.audit_chain_cutover TO setjoin_app;
    GRANT EXECUTE ON FUNCTION public.audit_chain_activate_v3() TO setjoin_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_worker') THEN
    GRANT SELECT ON public.audit_chain_cutover TO setjoin_worker;
    GRANT EXECUTE ON FUNCTION public.audit_chain_activate_v3() TO setjoin_worker;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='setjoin_owner') THEN
    GRANT ALL ON public.audit_chain_cutover TO setjoin_owner;
    GRANT EXECUTE ON FUNCTION public.audit_chain_activate_v3() TO setjoin_owner;
  END IF;
END $$;

INSERT INTO public.schema_migrations(version, applied_at) VALUES (232, now()) ON CONFLICT DO NOTHING;
