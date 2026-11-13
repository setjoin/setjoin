-- ─────────────────────────────────────────────────────────────────────────────
-- provision-roles.sql — the native-RLS role/ownership provisioning artifact
-- (native-rls-backstop W1; fork 7 home — see
-- retired-docs:superpowers/plans/archive/2026-06-18-native-rls-backstop.md).
--
-- 🔒 FORK 7 — THIS IS NOT A V-MIGRATION. Roles are CLUSTER-GLOBAL objects, not
-- per-database schema; a `V00x__*.sql` forward migration replayed per-DB cannot
-- own them (a CREATE ROLE in a migration would fail the 2nd time the same cluster
-- rebuilds a database). So role/ownership provisioning lives HERE — a dedicated,
-- idempotent, re-runnable script that the loader (load-test-schema.sql step 4) and
-- the deploy runbook both invoke against an ALREADY-LOADED public schema.
--
-- Operator runbook: docs/guides/NATIVE_RLS_FLIP_RUNBOOK.md (plain-language
-- steps + footgun checklist for a customer sysadmin doing the DSN switch).
--
-- 🔒 RUNTIME ROLE BOUNDARY. The gateway's tenant-facing runtime connects ONLY as
-- setjoin_app. It must NEVER connect as setjoin_owner and must NEVER `SET ROLE` to
-- it (the owner is NOSUPERUSER NOBYPASSRLS, yet still holds unconditional table
-- privileges and the authority to reshape its tables' RLS posture — an
-- owner-credentialed runtime would bypass tenant policy either way). All DDL,
-- migrations, and partition creation run as setjoin_owner out of band; cross-tenant
-- carve-outs (inbound delivery, the cron worker, journaling, admin reads) run as
-- setjoin_worker (BYPASSRLS) on a SEPARATE pool — never via `SET ROLE` on a shared
-- pool (that re-imports the switch/leak hazard the role split exists to remove).
--
-- IDEMPOTENT. Roles persist across DB rebuilds (cluster-global), so every CREATE is
-- guarded `IF NOT EXISTS` in a DO block, and the attributes are (re)asserted with
-- ALTER ROLE every run — so a role that pre-exists with drifted attributes is
-- corrected, not skipped. The GRANTs re-run per database (harmless to repeat).
--
-- INERT. This artifact creates roles + GRANTs runtime privileges on the EXISTING
-- loaded schema. It does NOT enable/force RLS on any table and does NOT change any
-- table's owner. In the dev/test cluster the tables are owned by `mail` (superuser),
-- so `mail` issues the GRANTs below — correct and inert. The RLS enable/force on
-- messages + message_tags is now done by V004__rls_enable.sql (the W6 flip), but it
-- is a NO-OP until the runtime connects as setjoin_app (see DEPLOY GATE below). In
-- production setjoin_owner owns the user-data tables and issues these GRANTs.
--
-- ═══════════════════════════════════════════════════════════════════════════════
-- 🔒 DEPLOY GATE — switching prod DB_DSN to setjoin_app (USER-AUTHORIZED; NOT a
-- code-deploy step). Applying V004 is inert for the superuser and fail-closing for
-- the NOBYPASSRLS owner (FORCE'd RLS applies to it until its own policies admit).
-- Making native RLS LIVE = pointing the gateway's tenant-facing DB_DSN at the
-- setjoin_app role. Do NOT flip this automatically. Preconditions (ALL must hold;
-- canonical copy in docs/standards/DATABASE_SECURITY.md → "Deploy gate"):
--   (a) Verify the prod role list so V004 is confirmed inert pre-switch: setjoin_app
--       is NOSUPERUSER NOBYPASSRLS and does NOT own messages/message_tags (else
--       owner-bypass); setjoin_worker has BYPASSRLS; setjoin_owner owns the
--       user-data tables. (rls_role_model.pg asserts this.)
--   (b) ALL isolation tests green — especially the IMAP streaming dual-tenant proof
--       (go test ./internal/imap -run TestIMAPIsolation, DB_DSN set + V004 applied)
--       + the JMAP/SMTP pgTAP proofs + the full pgTAP suite under FORCE.
--   (b2) ⚠️ THE COVERAGE GUARD IS GREEN (W7). The isolation proofs cover the
--       WRAPPED paths only; they do NOT prove the whole Go surface is wrapped.
--       ~17 non-test Go files touch messages/message_tags on the app pool and
--       only jmap+imap+recall+content-search are wrapped/routed today. The DSN
--       switch MUST wait until W7 wraps/routes the rest (blob, user/*, admin/*,
--       smtp/outbound, spam) AND the machine-checked coverage guard passes.
--       Flipping before then fail-closes own-attachment download / .eml export /
--       unsubscribe / quarantine and blinds eDiscovery/monitor/DMARC/admin-delete.
--   (c) User reviews the implementation (V004 + carve-out routing + the proofs).
--   (d) V004 applied in a MAINTENANCE WINDOW (ENABLE/FORCE take a brief ACCESS
--       EXCLUSIVE lock per parent — lock-DDL safety).
--   (e) DSN-switch ROLLBACK rehearsed: switching DB_DSN back to the owner/superuser
--       (or setjoin_worker) instantly disables enforcement with no migration —
--       rehearse it so rollback is a known, fast op. (A bad switch fails CLOSED:
--       un-wrapped reads return empty on an unset GUC, never a cross-tenant leak.)
-- The cross-tenant carve-outs (delivery, submission, cron worker, recall, admin
-- content-search) must run on setjoin_worker via DB_WORKER_DSN at the same time.
-- ═══════════════════════════════════════════════════════════════════════════════
-- ─────────────────────────────────────────────────────────────────────────────

-- ── Roles (cluster-global; idempotent create + attribute re-assert) ──────────
-- CONCURRENCY NOTE: these are CLUSTER-GLOBAL catalog objects (pg_authid). Parallel
-- builds, each provisioning its OWN database, still race on them — the `IF NOT
-- EXISTS` create is a TOCTOU (duplicate_object) and concurrent `ALTER ROLE` throws
-- `tuple concurrently updated`. A Postgres advisory lock can NOT serialize this:
-- advisory locks are PER-DATABASE, but the race is across databases on one cluster.
-- Because this whole script is idempotent, the fix lives in the CALLER
-- (load-test-schema.sh retries it with jittered backoff). Single-node / deploy
-- callers run it once with no contention, so they are unaffected.

-- setjoin_owner — owns the user-data tables in production (the isolated DDL /
-- migration / partition-creation identity). Ordinary RLS is bypassed by table
-- ownership, but FORCE RLS removes that exemption; owner-run migrations must
-- therefore perform data backfills before enabling FORCE. The gateway runtime
-- must never hold this credential. NOLOGIN here is correct for the test cluster;
-- deploy sets LOGIN + a password out of band.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
    CREATE ROLE setjoin_owner NOLOGIN;
  END IF;
END
$$;

ALTER ROLE setjoin_owner NOSUPERUSER NOCREATEDB NOBYPASSRLS;

-- setjoin_app — the gateway's tenant-facing runtime role (fork 1: the NON-OWNER
-- constrained role). NOSUPERUSER + NOBYPASSRLS is load-bearing: under FORCE'd RLS
-- (the W6 flip) this is the role the policies actually constrain. NOCREATEDB /
-- NOCREATEROLE keep it from minting escalation surface. LOGIN-capable; password
-- supplied externally at deploy.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
    CREATE ROLE setjoin_app LOGIN;
  END IF;
END
$$;

ALTER ROLE setjoin_app NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

-- setjoin_worker — the cross-tenant carve-out role (B2). BYPASSRLS lets the
-- inbound-delivery / cron-worker / journaling / admin connections cross mailboxes
-- without a per-policy escape predicate (the connection IS the boundary). BYPASSRLS
-- bypasses POLICIES only, not table GRANTs — so it still needs the table privileges
-- granted below. NOSUPERUSER keeps the bypass scoped to RLS, not the whole cluster.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    CREATE ROLE setjoin_worker LOGIN;
  END IF;
END
$$;
ALTER ROLE setjoin_worker NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE;

-- setjoin_updater — the host coordinator's narrow database identity. It has no
-- table, sequence, schema-create, role-management, owner, or BYPASSRLS grant.
-- V178 reducer footers grant only the exact claim/progress/complete/read
-- functions needed by the compiled updater. LOGIN is enabled so systemd can
-- supply a dedicated root-readable credential out of band.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_updater') THEN
    CREATE ROLE setjoin_updater LOGIN;
  END IF;
END
$$;
ALTER ROLE setjoin_updater NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

-- apply_worker_ownership() transfers SECURITY DEFINER reducer ownership from
-- the migration identity to the isolated BYPASSRLS worker. PostgreSQL permits
-- ALTER FUNCTION ... OWNER TO only when the current owner can SET ROLE to the
-- target role. This membership is for the out-of-band DDL identity only; it
-- does not confer BYPASSRLS unless that identity explicitly SET ROLEs, and no
-- runtime pool uses setjoin_owner.
GRANT setjoin_worker TO setjoin_owner;

-- ── Runtime GRANTs on the existing loaded schema (setjoin_app + setjoin_worker) ─
-- Both runtime roles need the same data-plane privileges; setjoin_app is then
-- additionally constrained by RLS policies at the flip, setjoin_worker is not.
-- In the test cluster `mail` (the table owner) issues these; in production
-- setjoin_owner issues them.

GRANT USAGE ON SCHEMA public TO setjoin_app, setjoin_worker;

-- USAGE permits resolving the three explicitly granted updater functions; it
-- does not permit creating objects or reading any table.
GRANT USAGE ON SCHEMA public TO setjoin_updater;

GRANT SELECT, INSERT, UPDATE, DELETE
  ON ALL TABLES IN SCHEMA public
  TO setjoin_app, setjoin_worker;

GRANT USAGE, SELECT
  ON ALL SEQUENCES IN SCHEMA public
  TO setjoin_app, setjoin_worker;

GRANT EXECUTE
  ON ALL FUNCTIONS IN SCHEMA public
  TO setjoin_app, setjoin_worker;

-- PostgreSQL grants new functions to PUBLIC by default. That would let the
-- narrow updater role execute arbitrary reducers merely through membership in
-- PUBLIC. Remove that ambient capability; app/worker retain their explicit
-- runtime grant above, while the exact updater grant list is restored below.
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

DO $$
DECLARE
  v_func regprocedure;
BEGIN
  FOR v_func IN
    SELECT to_regprocedure(signature)
      FROM (VALUES
        ('public.upgrade_intent_claim(bigint,bigint,text,uuid)'),
        ('public.upgrade_intent_progress(bigint,bigint,text,uuid,text,text,jsonb)'),
        ('public.upgrade_intent_complete(bigint,bigint,text,uuid,text,text,jsonb)')
      ) AS exact_updater(signature)
     WHERE to_regprocedure(signature) IS NOT NULL
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM setjoin_app',v_func::text);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO setjoin_updater',v_func::text);
  END LOOP;
  v_func := to_regprocedure('public.upgrade_intent_read(bigint)');
  IF v_func IS NOT NULL THEN
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO setjoin_updater',v_func::text);
  END IF;
END
$$;

-- R4 webhook publication is a cross-tenant worker protocol. Keep the exact
-- reducer family off the app credential after the broad compatibility grant;
-- handlers that enroll user.deleted already run on DB_WORKER_DSN.
DO $$
DECLARE v_func regprocedure;
BEGIN
  FOR v_func IN
    SELECT to_regprocedure(signature)
      FROM (VALUES
        ('public.webhook_user_deleted_publish(bigint,bigint)'),
        ('public.webhook_user_changed_publish(bigint,bigint,text)'),
        ('public.webhook_migration_terminal_publish(bigint,text)'),
        ('public.webhook_mail_committed_publish(bigint,text,text,text,text,integer)'),
        ('public.smtp_inbound_deliver(jsonb,text,text)'),
        ('public.smtp_submission_send(bigint,bigint,text,text,text,jsonb,jsonb,jsonb,text,text,text,text,text,bigint,boolean,timestamptz,jsonb)'),
        ('public.webhook_publication_claim(uuid,integer)'),
        ('public.webhook_publication_fanout(bigint,uuid)'),
        ('public.webhook_publication_complete(bigint,uuid,boolean,text)'),
        ('public.webhook_publication_prune(integer,integer)'),
        ('public.webhook_delivery_claim(uuid,integer,text)'),
        ('public.webhook_delivery_complete(bigint,uuid,boolean,boolean,integer,text,integer,text)'),
        -- L2-C4 (V253): the security-event outbox enqueue is the single writer
        -- of the FORCE-RLS-deny-all security_event_outbox. It deliberately
        -- avoids apply_worker_ownership (whose contract grants setjoin_app
        -- EXECUTE, V118:19-20) and carries its own webhook-shaped footer; this
        -- carve-out re-establishes the app denial after the broad :168 grant
        -- on every provisioning run.
        ('public.security_event_enqueue(text,jsonb)'),
        -- W-P1.5 / C4-RETENTION r2 (V261): the retention sweep is the ONE
        -- deleter of the FORCE-RLS-deny-all security_event_outbox. Like the
        -- enqueue reducer above, it is a SECURITY DEFINER owned by
        -- setjoin_worker with its own worker-only ACL footer; this carve-out
        -- re-establishes the app denial after the broad :168 grant on every
        -- provisioning run (the sweep must never be callable on the app
        -- credential).
        ('public.security_event_outbox_prune()'),
        -- PLAN-20260913 D2 / REDUCERS-004 (V259): ALL TWELVE auth_lockouts
        -- accessors. auth_lockouts is ENABLE+FORCE RLS with ZERO policies
        -- (deny-all to every runtime role), and these worker-owned SECURITY
        -- DEFINER functions are the table's only read/write surface — their
        -- ACL footers REVOKE setjoin_app at reducer-load time, but the
        -- post-load provisioning pass (install.sh post-load step,
        -- load-test-schema.sh 4/4) runs AFTER the reducers and its broad
        -- GRANT EXECUTE ON ALL FUNCTIONS (:168) would re-admit setjoin_app to
        -- every one of them. Registering the exact signatures here makes the
        -- worker-only denial survive every reprovisioning run. Signatures
        -- MUST stay byte-identical to the SQL definitions
        -- (authserver/sql/reducers: lockout_accessors.sql, lockout_escalate.sql,
        -- prune_lockouts.sql, push_lockout_accessors.sql,
        -- recovery_budget_accessors.sql). Astra impl-r2 P2:
        -- lockout_list gained its p_sort/p_dir arguments and lockout_count is
        -- new (the admin view's FULL filtered count) — both carry the same
        -- worker-only carve-out duty. The recovery_budget_* pair (ER5 s07
        -- residual) is the forgot-password per-account recovery budget — same
        -- deny-all FORCE posture, same worker-only duty.
        ('public.lockout_escalate(text,int)'),
        ('public.prune_old_lockouts(int,int)'),
        ('public.lockout_check(text[])'),
        ('public.lockout_clear(text[])'),
        ('public.lockout_arm(text,int)'),
        ('public.lockout_list(text,int,int,text,text)'),
        ('public.lockout_count(text)'),
        ('public.push_lockout_acquire(bigint)'),
        ('public.push_lockout_record(bigint,int,timestamptz)'),
        ('public.push_lockout_count_locked(bigint)'),
        ('public.recovery_budget_acquire(bigint)'),
        ('public.recovery_budget_record(bigint,int,timestamptz)'),
        -- #536: the Microsoft migration auxiliary-object reducers take a
        -- caller-chosen job id (SECURITY DEFINER, worker-owned); their own
        -- worker-only footers must survive this pass's broad grant too.
        ('public.rust_migration_apply_aux_object(bigint,uuid,text,text,text,text,text,text,jsonb,text)'),
        ('public.migration_aux_object_begin(bigint,uuid,text,text,text,text,text,text)'),
        ('public.migration_aux_object_complete(bigint,uuid,text,text,bigint)'),
        -- #526: preserve SMTP's cross-tenant worker-only wrapper after the broad grant.
        ('public.rust_smtp_inbound_security(jsonb,text,text,boolean,text)'),
        ('public.rust_smtp_imip_request_gate(jsonb,text)'),
        ('public.rust_smtp_imip_request_apply(jsonb,jsonb,timestamptz)'),
        ('public.rust_smtp_imip_cancel_occurrence(text,bigint,text,timestamptz)')
      ) AS exact_worker(signature)
     WHERE to_regprocedure(signature) IS NOT NULL
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM setjoin_app',v_func::text);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO setjoin_worker',v_func::text);
  END LOOP;
END
$$;

-- ── Default privileges so FUTURE objects are covered automatically ───────────
-- ALTER DEFAULT PRIVILEGES applies only to objects created BY the role running it
-- (here the schema owner). At the flip, setjoin_owner creates new tables/partitions
-- and these defaults grant the runtime roles automatically — so a freshly-rolled
-- monthly partition is reachable by the app/worker roles without a manual GRANT.
-- (RLS isolation on that new partition is a SEPARATE concern handled via-parent —
-- see fork 6 / rls_partition_via_parent.pg.)
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO setjoin_app, setjoin_worker;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO setjoin_app, setjoin_worker;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO setjoin_app, setjoin_worker;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- ─────────────────────────────────────────────────────────────────────────────
-- Materialized-view refresh ownership (found by the 2026-07-03 RLS flip
-- rehearsal — the ONLY permission failure in a full e2e run under the flipped
-- credentials). REFRESH MATERIALIZED VIEW is owner-only (not grantable), and
-- the cron worker (setjoin_worker) runs "refresh-antiphish-contact-graph"
-- every 5m — so the worker must OWN the matview. Ownership of one matview
-- grants nothing beyond refreshing/altering that object. Idempotent; guarded
-- for pre-provisioning loads where the matview may not exist yet.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_matviews WHERE schemaname='public' AND matviewname='antiphish_contact_graph') THEN
    EXECUTE 'ALTER MATERIALIZED VIEW public.antiphish_contact_graph OWNER TO setjoin_worker';
  END IF;
END $$;

-- Rust commit receipts are system metadata, owned by the DDL credential even
-- on a fresh cluster where V276 ran before roles existed. No user data / RLS.
DO $$ BEGIN
  IF to_regclass('public.rust_operation_receipts') IS NOT NULL THEN
    ALTER TABLE public.rust_operation_receipts OWNER TO setjoin_owner;
    GRANT SELECT, INSERT ON public.rust_operation_receipts TO setjoin_app, setjoin_worker;
  END IF;
END $$;

-- The deploy fence (V280) is cleared only by an operator: the runtime roles may read, set and
-- update it, never delete it. The blanket table GRANT above re-admits DELETE whenever this
-- script runs after V280, so the narrowing is restated here (idempotent; #472).
DO $$ BEGIN
  IF to_regclass('public.deploy_remote_fence') IS NOT NULL THEN
    ALTER TABLE public.deploy_remote_fence OWNER TO setjoin_owner;
    REVOKE ALL ON public.deploy_remote_fence FROM setjoin_app, setjoin_worker;
    GRANT SELECT, INSERT, UPDATE ON public.deploy_remote_fence TO setjoin_app, setjoin_worker;
  END IF;
END $$;

-- The SAML/OIDC link tables (V281/V282) are reachable only through their SECURITY DEFINER
-- reducers: the app role has no access and the worker may read, insert and delete. The blanket
-- GRANT above re-widens them whenever this script runs after the migrations, so the V281/V282
-- grants are restated here (idempotent; #472).
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['saml_assertion_replay','saml_link_completions','oidc_link_completions'] LOOP
    IF to_regclass('public.' || t) IS NOT NULL THEN
      EXECUTE format('ALTER TABLE public.%I OWNER TO setjoin_owner', t);
      EXECUTE format('REVOKE ALL ON public.%I FROM setjoin_app, setjoin_worker', t);
      EXECUTE format('GRANT SELECT, INSERT, DELETE ON public.%I TO setjoin_worker', t);
    END IF;
  END LOOP;
END $$;
