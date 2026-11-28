//! Live-DB integration tests for Wave 1.7 (#545):
//! - ARCH-018 scope-helper drift detection & repair before Pass 2
//! - Worker-only SECURITY DEFINER carve-out preservation (`setjoin_app` denied)
//! - Non-superuser `setjoin_owner` owner-safe pass (Pass 1 verify-only, zero `42501`)
//! - `pg_authid` privilege gating for non-superuser callers
//!
//! Runs strictly against a disposable database (`mailserver_e2e_545`) cloned
//! from `mailserver_test` and cleans up all temporary DB/role state unconditionally.

use setjoin_pg::rls_preflight::{
    inspect_rls_posture_client, provision_roles_and_verify_client, rewrite_dsn_credentials,
    PostureContext,
};
use tokio_postgres::NoTls;

async fn connect(dsn: &str) -> tokio_postgres::Client {
    let (client, conn) = tokio_postgres::connect(dsn, NoTls)
        .await
        .expect("connect to postgres");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
}

fn extract_dbname(dsn: &str) -> &str {
    let base = match dsn.split_once('?') {
        Some((b, _)) => b,
        None => dsn,
    };
    let slash = base.rfind('/').expect("dsn has /dbname");
    &base[slash + 1..]
}

fn replace_dbname(dsn: &str, new_db: &str) -> String {
    let (base, query) = match dsn.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (dsn, None),
    };
    let slash = base.rfind('/').expect("dsn has /dbname");
    match query {
        Some(q) => format!("{}/{new_db}?{q}", &base[..slash]),
        None => format!("{}/{new_db}", &base[..slash]),
    }
}

#[tokio::test]
async fn live_db_rls_preflight_repair_carveouts_and_owner_safe_pass() {
    let Ok(test_dsn) = std::env::var("TEST_DB_DSN") else {
        assert_ne!(
            std::env::var("REQUIRE_DB").as_deref(),
            Ok("1"),
            "TEST_DB_DSN is required when REQUIRE_DB=1"
        );
        eprintln!("SETJOIN-PG-DB-SKIP (reason=no-dsn)");
        return;
    };

    let template_db = extract_dbname(&test_dsn);
    assert!(
        !template_db.is_empty()
            && template_db
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "unexpected template db name: {template_db}"
    );
    let disposable_db = format!("mailserver_e2e_545_{}", std::process::id());
    let admin_dsn = replace_dbname(&test_dsn, "postgres");
    let admin = connect(&admin_dsn).await;

    // Clean any leftover disposable DB, clone TEST_DB_DSN template schema cleanly.
    let _ = admin
        .batch_execute(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{disposable_db}' AND pid <> pg_backend_pid();"
        ))
        .await;
    admin
        .batch_execute(&format!("DROP DATABASE IF EXISTS {disposable_db};"))
        .await
        .expect("drop old disposable db");
    admin
        .batch_execute(&format!(
            "CREATE DATABASE {disposable_db} TEMPLATE {template_db};"
        ))
        .await
        .expect("create disposable db from TEST_DB_DSN template");

    let e2e_dsn = replace_dbname(&test_dsn, &disposable_db);

    // Save original setjoin_owner rolcanlogin so we always restore it cleanly.
    let orig_owner_login: bool = admin
        .query_one(
            "SELECT rolcanlogin FROM pg_roles WHERE rolname = 'setjoin_owner'",
            &[],
        )
        .await
        .expect("read setjoin_owner")
        .get(0);

    let test_result = async {
        let mut super_client = connect(&e2e_dsn).await;

        // 1. Introduce drift on one canonical ARCH-018 scope helper AND check
        //    that a worker-only SECURITY DEFINER function stays revoked from setjoin_app.
        super_client
            .batch_execute(
                "ALTER FUNCTION public.drive_member_role(bigint,bigint) OWNER TO CURRENT_USER; \
                 ALTER FUNCTION public.drive_member_role(bigint,bigint) RESET search_path; \
                 GRANT EXECUTE ON FUNCTION public.drive_member_role(bigint,bigint) TO PUBLIC;",
            )
            .await
            .expect("inject scope helper drift");

        let drifted = inspect_rls_posture_client(&super_client, PostureContext::OperatorOwner, None)
            .await
            .expect("inspect drifted posture");
        assert!(
            drifted
                .scope_helpers_drifted
                .iter()
                .any(|d| d.signature.contains("drive_member_role")),
            "expected drive_member_role drift, got: {:?}",
            drifted.scope_helpers_drifted
        );
        assert!(
            drifted.other_secdef_drifted.is_empty(),
            "unexpected non-extension secdef drift: {:?}",
            drifted.other_secdef_drifted
        );

        // 2. Superuser provision_roles_and_verify repairs ARCH-018 drift AND
        //    preserves worker-only REVOKE ALL FROM setjoin_app carve-outs.
        let prov = provision_roles_and_verify_client(&mut super_client, None)
            .await
            .expect("superuser provision_roles_and_verify");
        assert!(prov.pass1_executed);
        assert!(prov.pass2_executed);
        assert!(
            prov.scope_helpers_repaired
                .iter()
                .any(|s| s.contains("drive_member_role")),
            "expected drive_member_role in repaired list: {:?}",
            prov.scope_helpers_repaired
        );
        assert!(prov.verified.scope_helpers_drifted.is_empty());

        let app_can_enqueue: bool = super_client
            .query_one(
                "SELECT has_function_privilege('setjoin_app', 'public.security_event_enqueue(text,jsonb)'::regprocedure, 'EXECUTE')",
                &[],
            )
            .await
            .expect("check worker-only carve-out")
            .get(0);
        assert!(
            !app_can_enqueue,
            "worker-only security_event_enqueue must stay revoked from setjoin_app after Pass 2"
        );

        // 3. Re-own public-schema user objects in the disposable DB to setjoin_owner
        //    (never touching bootstrap pg_catalog / extension objects) and temporarily
        //    enable LOGIN on setjoin_owner to exercise the exact non-superuser
        //    updater `apply_migrations` owner-safe pass (zero 42501!).
        super_client
            .batch_execute(
                "DO $$
                DECLARE r record;
                BEGIN
                  ALTER SCHEMA public OWNER TO setjoin_owner;
                  FOR r IN
                    SELECT c.oid, c.relkind
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    JOIN pg_roles o ON o.oid = c.relowner
                    WHERE n.nspname = 'public'
                      AND o.rolname = current_user
                      AND c.relkind IN ('r','p','v','m')
                      AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = c.oid AND d.deptype = 'e')
                  LOOP
                    IF r.relkind = 'm' THEN
                      EXECUTE format('ALTER MATERIALIZED VIEW %s OWNER TO setjoin_owner', r.oid::regclass);
                    ELSIF r.relkind = 'v' THEN
                      EXECUTE format('ALTER VIEW %s OWNER TO setjoin_owner', r.oid::regclass);
                    ELSE
                      EXECUTE format('ALTER TABLE %s OWNER TO setjoin_owner', r.oid::regclass);
                    END IF;
                  END LOOP;
                  FOR r IN
                    SELECT c.oid
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    JOIN pg_roles o ON o.oid = c.relowner
                    WHERE n.nspname = 'public'
                      AND o.rolname = current_user
                      AND c.relkind = 'S'
                      AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = c.oid AND d.deptype IN ('e', 'a', 'i'))
                  LOOP
                    EXECUTE format('ALTER SEQUENCE %s OWNER TO setjoin_owner', r.oid::regclass);
                  END LOOP;
                  FOR r IN
                    SELECT p.oid::regprocedure AS sig
                    FROM pg_proc p
                    JOIN pg_namespace n ON n.oid = p.pronamespace
                    JOIN pg_roles o ON o.oid = p.proowner
                    WHERE n.nspname = 'public'
                      AND o.rolname = current_user
                      AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')
                  LOOP
                    EXECUTE format('ALTER FUNCTION %s OWNER TO setjoin_owner', r.sig);
                  END LOOP;
                END $$;
                ALTER MATERIALIZED VIEW public.antiphish_contact_graph OWNER TO setjoin_worker;
                ALTER FUNCTION public.drive_member_role(bigint,bigint) OWNER TO setjoin_owner;
                GRANT EXECUTE ON FUNCTION public.drive_member_role(bigint,bigint) TO PUBLIC;
                ALTER ROLE setjoin_owner WITH LOGIN PASSWORD 'e2e_owner_tmp_pw';",
            )
            .await
            .expect("prepare non-superuser setjoin_owner fixture");

        let owner_dsn =
            rewrite_dsn_credentials(&e2e_dsn, "setjoin_owner", "e2e_owner_tmp_pw").unwrap();
        let mut owner_client = connect(&owner_dsn).await;

        // Verify pg_authid gating: non-superuser inspect succeeds with has_password = None.
        let pre_owner =
            inspect_rls_posture_client(&owner_client, PostureContext::OperatorOwner, None)
                .await
                .expect("non-superuser inspect_rls_posture");
        assert_eq!(pre_owner.current_role.name, "setjoin_owner");
        assert!(!pre_owner.current_role.rolsuper);
        assert!(pre_owner.roles.iter().all(|r| r.has_password.is_none()));
        assert!(pre_owner
            .scope_helpers_drifted
            .iter()
            .any(|d| d.signature.contains("drive_member_role")));

        // Owner-safe pass: Pass 1 is verify-only (pass1_executed == false, no 42501!),
        // ARCH-018 helper repaired via apply_worker_ownership, Pass 2 grants + carve-outs succeed!
        let owner_prov = provision_roles_and_verify_client(&mut owner_client, None)
            .await
            .expect("non-superuser setjoin_owner provision_roles_and_verify");
        assert!(
            !owner_prov.pass1_executed,
            "non-superuser setjoin_owner must skip Pass 1 DDL when roles already exist"
        );
        assert!(owner_prov.pass2_executed);
        assert!(owner_prov.verified.scope_helpers_drifted.is_empty());

        let app_can_enqueue_after_owner: bool = owner_client
            .query_one(
                "SELECT has_function_privilege('setjoin_app', 'public.security_event_enqueue(text,jsonb)'::regprocedure, 'EXECUTE')",
                &[],
            )
            .await
            .expect("check carve-out after owner pass")
            .get(0);
        assert!(!app_can_enqueue_after_owner);
        let worker_has_create: bool = owner_client
            .query_one(
                "SELECT has_schema_privilege('setjoin_worker', 'public', 'CREATE')",
                &[],
            )
            .await
            .expect("check worker schema CREATE revoked")
            .get(0);
        assert!(
            !worker_has_create,
            "setjoin_worker must not retain CREATE on schema public after owner-safe pass"
        );

        // 4. Wave 1.9 (#547): verify BOTH inspect_rls_posture_client AND
        //    inspect_rls_posture_executor detect:
        //    (a) ENABLE ROW LEVEL SECURITY without FORCE ROW LEVEL SECURITY, and
        //    (b) indirect FORCE-RLS table ownership via role membership (including
        //        WITH INHERIT FALSE) using pg_has_role(..., 'MEMBER').
        let unforced_tbl = format!("rls_unforced_547_{}", std::process::id());
        let indirect_tbl = format!("rls_indirect_547_{}", std::process::id());
        let indirect_app = format!("rls_app_547_{}", std::process::id());
        let indirect_app_pw = "rls_app_547_pw";
        super_client
            .batch_execute(&format!(
                "DROP ROLE IF EXISTS {indirect_app}; \
                 CREATE ROLE {indirect_app} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{indirect_app_pw}'; \
                 GRANT USAGE ON SCHEMA public TO {indirect_app}; \
                 CREATE TABLE {unforced_tbl}(id int); \
                 ALTER TABLE {unforced_tbl} ENABLE ROW LEVEL SECURITY; \
                 CREATE POLICY p_{unforced_tbl} ON {unforced_tbl} USING (true); \
                 CREATE TABLE {indirect_tbl}(id int); \
                 ALTER TABLE {indirect_tbl} OWNER TO setjoin_owner; \
                 ALTER TABLE {indirect_tbl} ENABLE ROW LEVEL SECURITY; \
                 ALTER TABLE {indirect_tbl} FORCE ROW LEVEL SECURITY; \
                 GRANT setjoin_owner TO {indirect_app} WITH INHERIT FALSE;"
            ))
            .await
            .expect("seed wave 1.9 unforced & indirect-owner fixtures");

        let indirect_app_dsn =
            rewrite_dsn_credentials(&e2e_dsn, &indirect_app, indirect_app_pw).unwrap();
        let indirect_client = connect(&indirect_app_dsn).await;
        let indirect_exec =
            setjoin_pg::ScopedExecutor::from_dsn(&indirect_app_dsn, 2).expect("indirect exec");

        let rep_client = setjoin_pg::rls_preflight::inspect_rls_posture_client(
            &indirect_client,
            PostureContext::RuntimeApp,
            None,
        )
        .await
        .expect("inspect_rls_posture_client");
        let rep_exec = setjoin_pg::rls_preflight::inspect_rls_posture_executor(
            &indirect_exec,
            PostureContext::RuntimeApp,
            None,
        )
        .await
        .expect("inspect_rls_posture_executor");

        for (label, rep) in [("client", &rep_client), ("executor", &rep_exec)] {
            assert!(
                rep.policy_tables_rls_disabled.contains(&unforced_tbl),
                "{label}: expected {unforced_tbl} in policy_tables_rls_disabled: {:?}",
                rep.policy_tables_rls_disabled
            );
            assert!(
                rep.owns_forced_rls_tables.contains(&indirect_tbl),
                "{label}: expected {indirect_tbl} in owns_forced_rls_tables via WITH INHERIT FALSE membership: {:?}",
                rep.owns_forced_rls_tables
            );
            let errs = rep.fail_closed_errors(false);
            assert!(
                errs.iter()
                    .any(|e| e.contains("missing ENABLE or FORCE ROW LEVEL SECURITY")),
                "{label}: missing unforced diagnostic: {errs:?}"
            );
            assert!(
                errs.iter().any(|e| e.contains("owns FORCE-RLS table")),
                "{label}: missing indirect-owner diagnostic: {errs:?}"
            );
        }

        drop(indirect_exec);
        drop(indirect_client);
        super_client
            .batch_execute(&format!(
                "REVOKE setjoin_owner FROM {indirect_app}; \
                 REVOKE USAGE ON SCHEMA public FROM {indirect_app}; \
                 DROP TABLE IF EXISTS {unforced_tbl}; \
                 DROP TABLE IF EXISTS {indirect_tbl}; \
                 DROP ROLE IF EXISTS {indirect_app};"
            ))
            .await
            .expect("cleanup wave 1.9 fixtures");

        drop(owner_client);
        drop(super_client);
    }
    .await;

    // Unconditional cleanup: restore setjoin_owner attribute & drop disposable DB.
    if !orig_owner_login {
        let _ = admin
            .batch_execute("ALTER ROLE setjoin_owner NOLOGIN PASSWORD NULL;")
            .await;
    }
    let _ = admin
        .batch_execute(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{disposable_db}' AND pid <> pg_backend_pid();"
        ))
        .await;
    let _ = admin
        .batch_execute(&format!("DROP DATABASE IF EXISTS {disposable_db};"))
        .await;

    test_result
}
