-- V068__audit_chain_revoke_public.sql
--
-- Security: revoke PUBLIC EXECUTE on audit hash-chain functions.
--
-- audit_row_hash and audit_canon are internal helpers (called only by the
-- BEFORE-INSERT trigger and verify_audit_chain).  verify_audit_chain is an
-- admin-only integrity check.  None of these should be callable by arbitrary
-- DB roles — PUBLIC EXECUTE lets any role recompute/forge the (unkeyed) chain.
--
-- After this migration:
--   • audit_canon        — internal to audit_row_hash; no direct callers outside.
--   • audit_row_hash     — called by trg_admin_audit_checksum (trigger, non-SECURITY DEFINER)
--                          and by verify_audit_chain.  Inserting roles need EXECUTE.
--   • verify_audit_chain — admin integrity check; privileged roles only.
--
-- Grants are to the three setjoin runtime roles (created by provision-roles.sql).
-- A DO block guards against a cluster that has not yet run provision-roles.sql
-- (roles are cluster-global; their absence would make a bare GRANT fail).
-- Superusers (the 'mail' user used in migrations and pgTAP) bypass EXECUTE
-- checks and are unaffected by this REVOKE.
--
-- ponytail: HMAC-keying the chain (replace plain SHA-256 with HMAC + a server
-- secret) is the deeper fix — this migration is the immediate surface reduction.
-- Tracked as a TODO (see TODOS.md, audit-chain HMAC follow-up).

REVOKE EXECUTE ON FUNCTION public.audit_canon(jsonb) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.audit_row_hash(
  bigint, timestamptz, bigint, inet, text, text, bigint, jsonb, jsonb, text, text
) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.verify_audit_chain(bigint, bigint) FROM PUBLIC;

-- Grant back to the three runtime roles (owner owns DDL; app + worker fire the
-- INSERT trigger and/or run verify).  Conditional on role existence so the
-- migration loads clean on clusters where provision-roles.sql has not yet run.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
    GRANT EXECUTE ON FUNCTION public.audit_canon(jsonb)                                                            TO setjoin_owner;
    GRANT EXECUTE ON FUNCTION public.audit_row_hash(bigint, timestamptz, bigint, inet, text, text, bigint, jsonb, jsonb, text, text) TO setjoin_owner;
    GRANT EXECUTE ON FUNCTION public.verify_audit_chain(bigint, bigint)                                            TO setjoin_owner;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
    GRANT EXECUTE ON FUNCTION public.audit_canon(jsonb)                                                            TO setjoin_app;
    GRANT EXECUTE ON FUNCTION public.audit_row_hash(bigint, timestamptz, bigint, inet, text, text, bigint, jsonb, jsonb, text, text) TO setjoin_app;
    GRANT EXECUTE ON FUNCTION public.verify_audit_chain(bigint, bigint)                                            TO setjoin_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    GRANT EXECUTE ON FUNCTION public.audit_canon(jsonb)                                                            TO setjoin_worker;
    GRANT EXECUTE ON FUNCTION public.audit_row_hash(bigint, timestamptz, bigint, inet, text, text, bigint, jsonb, jsonb, text, text) TO setjoin_worker;
    GRANT EXECUTE ON FUNCTION public.verify_audit_chain(bigint, bigint)                                            TO setjoin_worker;
  END IF;
END $$;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (68, now());
