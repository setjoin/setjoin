-- ════════════════════════════════════════════════════════════════════════
-- V256__test_fixture_acl_hygiene.sql — revoke PUBLIC execution on the
-- non-production test-fixture helpers that ship inside the production
-- baseline (DBSCHEMA-009 / attack-surface hygiene: V001 minted mk_account,
-- mk_shared_mailbox, the _test_notify_log accessors and their trigger
-- function with PostgreSQL's default PUBLIC EXECUTE grant, and no migration
-- ever revoked it).
--
-- These objects exist ONLY for the pgTAP suites (sql/tests/*.pg) and the
-- notify-decouple fixtures. pgTAP runs as the provisioning superuser/owner,
-- which bypasses ACL checks entirely — the revocation cannot break any test.
-- The provision-roles.sql blanket `REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA
-- public FROM PUBLIC` covers the standard provisioning path, but a cluster
-- built by any other route (or a function re-created later) relied on nothing
-- here. Revoking from PUBLIC closes that ambient capability; nothing is
-- re-granted because no runtime role has a legitimate call path.
--
-- The objects are deliberately NOT dropped: live tests and fixtures still
-- call them (moving them to a test schema is a larger re-plumbing decision
-- that stays with the owner).
-- ════════════════════════════════════════════════════════════════════════

REVOKE EXECUTE ON FUNCTION public.mk_account(text)              FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.mk_shared_mailbox(text)       FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.last_notify_event(text)       FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.notified_on(text)             FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.notify_count(text)            FROM PUBLIC;

-- ── Schema migration record (V060 bookkeeping form) ───────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (256, now())
    ON CONFLICT (version) DO NOTHING;
