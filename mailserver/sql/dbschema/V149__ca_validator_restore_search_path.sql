-- V149__ca_validator_restore_search_path.sql — make Conditional Access policy
-- validation safe under pg_restore's empty search_path.
--
-- ca_validate_policy_document recursively calls itself for each nested grant.
-- pg_dump/pg_restore deliberately restore objects with an empty search_path;
-- without a function-local path, restoring conditional_access_policies data
-- therefore fails when the CHECK constraint evaluates a nested grant. Pinning
-- pg_catalog first and public second makes built-ins and the recursive call
-- deterministic without changing the validator's accepted policy language.

ALTER FUNCTION public.ca_validate_policy_document(jsonb, jsonb)
    SET search_path = pg_catalog, public;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (149, now())
    ON CONFLICT (version) DO NOTHING;
