-- V300__audit_row_hash_utf8.sql — Fix #181: use convert_to(..., 'UTF8') instead
-- of ::bytea in audit_row_hash_v so titles/notes containing '"' or '\' (which
-- audit_canon escapes as '\"' / '\\') do not fail with 22P02 invalid input
-- syntax for type bytea.
--
-- Compatibility: for strings containing no backslashes, convert_to(text, 'UTF8')
-- produces identical bytes to text::bytea, so all existing V2 and V3 audit chain
-- rows verify unchanged.

BEGIN;

CREATE OR REPLACE FUNCTION public.audit_row_hash_v(
  p_v3 boolean,
  p_id bigint, p_occurred_at timestamptz, p_user_id bigint, p_ip inet,
  p_action text, p_target_type text, p_target_id bigint,
  p_before jsonb, p_after jsonb, p_notes text, p_prev text
) RETURNS text AS $$
  SELECT CASE WHEN p_v3
    THEN 'v3:' || encode(public.hmac(
      pg_catalog.convert_to(
        p_id::text || coalesce(p_occurred_at::text,'') || coalesce(p_user_id::text,'') ||
        coalesce(p_ip::text,'') || p_action || coalesce(p_target_type,'') ||
        coalesce(p_target_id::text,'') || public.audit_canon(p_before) ||
        public.audit_canon(p_after) || coalesce(p_notes,'') || coalesce(p_prev,''),
        'UTF8'),
      pg_catalog.convert_to(current_setting('app.audit_hmac_key', TRUE), 'UTF8'),
      'sha256'), 'hex')
    ELSE encode(pg_catalog.sha256(pg_catalog.convert_to(
      p_id::text || coalesce(p_occurred_at::text,'') || coalesce(p_user_id::text,'') ||
      coalesce(p_ip::text,'') || p_action || coalesce(p_target_type,'') ||
      coalesce(p_target_id::text,'') || public.audit_canon(p_before) ||
      public.audit_canon(p_after) || coalesce(p_notes,'') || coalesce(p_prev,''),
      'UTF8')), 'hex')
  END;
$$ LANGUAGE sql STABLE;

-- Re-assert V087 ACLs idempotently.
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

INSERT INTO public.schema_migrations (version, applied_at) VALUES (300, now())
  ON CONFLICT (version) DO NOTHING;

COMMIT;
