-- V245__task_list_roster_overload_retirement.sql — retire the pre-fix
-- task_list_get_roster(bigint) overload (med-jmap-task-roster-001, Astra
-- waves12 HOLD 1).
--
-- (Numbered V245: the V244 slot was taken concurrently by
-- V244__ediscovery_result_binding_sso_grant_authority.sql — med-shard3-007.)
--
-- reducers/task_lists.sql replaced the unscoped roster read with the
-- caller-scoped (R1) two-argument form. CREATE OR REPLACE with a NEW
-- signature ADDS a function — it can never remove the old one — so every
-- database that ever loaded the pre-fix reducer still carries the unscoped
-- task_list_get_roster(p_list_id): a live cross-tenant roster oracle (any
-- caller could project any list's roster by list id alone). This migration
-- retires the old overload explicitly.
--
-- Idempotent by construction: a fresh database (baseline + forward chain)
-- never had the one-arg form, so the DROP is a no-op there. No drop-order
-- hazard: PL/pgSQL/SQL function bodies carry no pg_depend edges to the
-- functions they call, so dropping the one-arg form succeeds even while the
-- pre-fix add_member/remove_member/task_list_get bodies (which call it) are
-- still installed; the reducer reload that follows the migration chain
-- (load-test-schema.sh step 1 → step 2; mailctl schema apply → reducer
-- reload) replaces those callers with the two-argument forms before anything
-- executes them again.
--
-- The load-over-the-previous-definitions regression (old overload installed →
-- this DROP → new reducer set reloaded → old signature absent, new read
-- fails closed) is pinned by tests/task_lists_roster_overload_retirement.pg.

DROP FUNCTION IF EXISTS public.task_list_get_roster(BIGINT);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (245, now())
  ON CONFLICT (version) DO NOTHING;
