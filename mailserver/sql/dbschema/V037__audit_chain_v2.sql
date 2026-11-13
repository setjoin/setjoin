-- V037__audit_chain_v2.sql — make the audit hash-chain real + full-field.
-- The functions live HERE (not sql/reducers/) because the one-time backfill below
-- calls audit_row_hash, and reducers load AFTER migrations. CREATE OR REPLACE
-- overrides the V001 baseline definitions.

ALTER TABLE public.admin_audit_log ADD COLUMN IF NOT EXISTS checksum text;

-- Canonical jsonb so a DR dump/restore can't reorder keys and flip rows to "tampered".
CREATE OR REPLACE FUNCTION public.audit_canon(p jsonb) RETURNS text AS $$
  SELECT COALESCE(
    (SELECT string_agg(key || ':' || value::text, ',' ORDER BY key)
       FROM jsonb_each(COALESCE(p, '{}'::jsonb))), '');
$$ LANGUAGE sql IMMUTABLE;

-- The SINGLE row-hash. Trigger AND verify both call this (no formula drift).
CREATE OR REPLACE FUNCTION public.audit_row_hash(
  p_id bigint, p_occurred_at timestamptz, p_user_id bigint, p_ip inet,
  p_action text, p_target_type text, p_target_id bigint,
  p_before jsonb, p_after jsonb, p_notes text, p_prev text
) RETURNS text AS $$
  SELECT encode(sha256((
    p_id::text || coalesce(p_occurred_at::text,'') || coalesce(p_user_id::text,'') ||
    coalesce(p_ip::text,'') || p_action || coalesce(p_target_type,'') ||
    coalesce(p_target_id::text,'') || public.audit_canon(p_before) ||
    public.audit_canon(p_after) || coalesce(p_notes,'') || coalesce(p_prev,'')
  )::bytea), 'hex');
$$ LANGUAGE sql IMMUTABLE;

-- v2 trigger: write checksum into the dedicated column, chaining off the prev row's
-- checksum, all under the advisory lock so chain-order == commit-order. Assign id
-- under the lock so id-order == chain-order (verify walks ORDER BY id).
CREATE OR REPLACE FUNCTION public.trg_admin_audit_checksum() RETURNS trigger AS $$
DECLARE v_prev text; v_max bigint;
BEGIN
  PERFORM pg_advisory_xact_lock('admin_audit_log'::regclass::int, 0);
  -- Assign id UNDER the lock so id-order == chain-order == commit-order. The column
  -- default nextval ran before this trigger; we overwrite NEW.id (sequence gaps are
  -- harmless). Without this, a tx that took a lower id but commits later would chain
  -- out of id-order, and the id-ordered verify walk would report false tamper.
  SELECT id, checksum INTO v_max, v_prev FROM admin_audit_log ORDER BY id DESC LIMIT 1;
  NEW.id := COALESCE(v_max, 0) + 1;
  NEW.checksum := public.audit_row_hash(NEW.id, NEW.occurred_at, NEW.user_id, NEW.ip,
    NEW.action, NEW.target_type, NEW.target_id, NEW.before_state, NEW.after_state,
    NEW.notes, v_prev);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Real verify: recompute + compare, seeding v_prev from the row BEFORE p_from_id.
CREATE OR REPLACE FUNCTION public.verify_audit_chain(p_from_id bigint DEFAULT NULL, p_to_id bigint DEFAULT NULL)
RETURNS TABLE(row_id bigint, valid boolean, occurred_at timestamptz, action text) AS $$
DECLARE v_prev text := NULL; v_row RECORD; v_calc text;
BEGIN
  IF p_from_id IS NOT NULL THEN
    SELECT checksum INTO v_prev FROM admin_audit_log WHERE id < p_from_id ORDER BY id DESC LIMIT 1;
  END IF;
  FOR v_row IN
    SELECT * FROM admin_audit_log
     WHERE (p_from_id IS NULL OR id >= p_from_id) AND (p_to_id IS NULL OR id <= p_to_id)
     ORDER BY id
  LOOP
    v_calc := public.audit_row_hash(v_row.id, v_row.occurred_at, v_row.user_id, v_row.ip,
      v_row.action, v_row.target_type, v_row.target_id, v_row.before_state, v_row.after_state,
      v_row.notes, v_prev);
    row_id := v_row.id; occurred_at := v_row.occurred_at; action := v_row.action;
    valid := (v_calc = v_row.checksum);
    v_prev := v_row.checksum;   -- chain forward on the STORED checksum
    RETURN NEXT;
  END LOOP;
END;
$$ LANGUAGE plpgsql STABLE;

-- One-time backfill: re-key existing rows under v2, in id order. The append-only
-- trigger blocks UPDATE, so disable it for the backfill (transactional). DISABLE
-- TRIGGER takes the TRIGGER name (admin_audit_append_only), not the function name.
ALTER TABLE public.admin_audit_log DISABLE TRIGGER admin_audit_append_only;
DO $$
DECLARE v_prev text := NULL; v_row RECORD; v_calc text;
BEGIN
  FOR v_row IN SELECT * FROM admin_audit_log ORDER BY id LOOP
    v_calc := public.audit_row_hash(v_row.id, v_row.occurred_at, v_row.user_id, v_row.ip,
      v_row.action, v_row.target_type, v_row.target_id, v_row.before_state, v_row.after_state,
      v_row.notes, v_prev);
    UPDATE admin_audit_log SET checksum = v_calc WHERE id = v_row.id;
    v_prev := v_calc;
  END LOOP;
END $$;
ALTER TABLE public.admin_audit_log ENABLE TRIGGER admin_audit_append_only;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (37, now()) ON CONFLICT (version) DO NOTHING;
