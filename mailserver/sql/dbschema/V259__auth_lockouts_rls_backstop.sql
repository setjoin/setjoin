-- ════════════════════════════════════════════════════════════════════════
-- V259__auth_lockouts_rls_backstop.sql — R4 FORCE-RLS deny-all backstop for
-- auth_lockouts (PLAN-20260913 D2 / REDUCERS-004, Astra AGREE).
--
-- auth_lockouts is pre-auth attack-accounting state keyed by attacker-
-- supplied material (ip:{ip} / user:{username} / ip_user:{ip}:{username} /
-- push_user:{id}). No row belongs to an authenticated principal: there is
-- no user GUC predicate that is not also readable by the attacker grinding
-- the login path. The table therefore takes the deny-all posture
-- (V217/V246/V249/V254 posture D): ENABLE + FORCE ROW LEVEL SECURITY with
-- ZERO policies = fail-closed for every runtime role, INCLUDING the owner
-- (FORCE binds the owner; only a BYPASSRLS credential — setjoin_worker —
-- escapes, and a superuser bypasses RLS entirely, which keeps the flip
-- INERT for the current owner-credentialed pools until the DSN switch).
--
-- EVERY accessor path moves behind worker-owned SECURITY DEFINER functions
-- (authserver/sql/reducers — the fixed-point reducer load applies them
-- AFTER this migration in every loader/deploy path):
--   lockout_escalate(text, int)      — threat failure escalation (converted
--                                      in place; signature unchanged so the
--                                      shared/threat call keeps resolving)
--   prune_old_lockouts(int, int)     — the cron cleanup (converted in place;
--                                      the Go cron registry's SQL is unchanged)
--   lockout_check(text[])            — IsLocked probe (lock state + remaining)
--   lockout_clear(text[])            — auth-success reset (DELETE by keys)
--   lockout_arm(text, int)           — spray IP lock upsert
--   lockout_list(text, int, int)     — admin threat-console lockouts view
--                                      (GetDeviceEvents-style read accessor)
--   push_lockout_acquire(bigint)     — push-MFA account-row lock + read
--   push_lockout_record(bigint,int,timestamptz) — push-MFA outcome write
--   push_lockout_count_locked(bigint)— push-MFA count-only locked attempt
--
-- All nine carry worker-only function ACLs (the V253 security_event_enqueue
-- footer form: OWNER TO setjoin_worker + REVOKE from PUBLIC/setjoin_app +
-- GRANT EXECUTE to setjoin_worker), and their exact signatures belong in
-- scripts/provision-roles.sql's worker-only carve-out block so every
-- provisioning run re-establishes the denial after the broad
-- GRANT EXECUTE ON ALL FUNCTIONS (provision-roles.sql:168) — the same
-- registration duty the V253 carve-out carries.
--
-- Go routing note (D7, RECORD): routing these accessor calls through the
-- DB_WORKER_DSN pool is INDEPENDENT of the global RLS flip. Until the
-- prod DSN switch the owner-credentialed pools bypass RLS entirely, so the
-- direct-table statements they still host keep working; post-flip only the
-- accessor paths remain live.
--
-- OWNERSHIP: the table moves to setjoin_owner (NOBYPASSRLS owner) so FORCE
-- binds it too — ENABLE alone would silently no-op for the owner (the
-- V246/V249 rationale). setjoin_owner is provisioned by
-- scripts/provision-roles.sql (loader step 0/4 runs before migrations).
-- ════════════════════════════════════════════════════════════════════════

-- ── Deny-all FORCE: zero policies = fail-closed for every runtime role ────
ALTER TABLE public.auth_lockouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.auth_lockouts FORCE ROW LEVEL SECURITY;

-- ── Ownership: the NOBYPASSRLS owner owns the table so FORCE binds it ─────
ALTER TABLE public.auth_lockouts OWNER TO setjoin_owner;

-- ── Schema migration record (V060 bookkeeping form) ───────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (259, now())
    ON CONFLICT (version) DO NOTHING;
