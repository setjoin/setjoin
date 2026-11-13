//! DB-backed proofs that the scoped executor cannot read or write another
//! mailbox's rows, and that commit / rollback / unknown map to the lifecycle.
//!
//! Gate: the owner DSN comes from `TEST_DB_DSN` (else `DB_DSN`); the executor
//! connects as the constrained `setjoin_app` role from `DB_APP_DSN` (else the
//! owner DSN with the user swapped to `setjoin_app`). With no DSN every test
//! prints `SETJOIN-PG-DB-SKIP (reason=no-dsn)` and returns; with
//! `REQUIRE_DB=1` a missing or unreachable database FAILS instead.
//! Schema: `scripts/load-test-schema.sh` (V004 FORCE RLS on messages/message_tags).
use futures_util::FutureExt;
use setjoin_contracts::{
    command::{CommandEnvelope, RecoveryAction},
    ids::{ActorId, Digest, Generation, MailboxId, OperationId},
};
use setjoin_db::lifecycle::{accepted_contract, LifecycleError};
use setjoin_pg::{CommandOutcome, MailboxAuthContext, Rejection, ScopedExecutor, ScopedTx, Type};
use std::io;
use std::{
    panic::AssertUnwindSafe,
    sync::atomic::{AtomicU8, Ordering},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_postgres::{Client, NoTls};

struct Tenant {
    mailbox: i64,
    user: i64,
    message: i64,
}

#[tokio::test]
async fn user_scoped_reads_need_only_an_actor_and_release_the_pool_scope() {
    with_env("user_scope_without_mailbox",async |env:&Env| {
        for user in [env.a.user,env.b.user] {
            let rows=env.exec.read_user_scoped(ActorId::new(user).unwrap(),
                "SELECT current_setting('app.current_user_id',true), NULLIF(current_setting('app.current_mailbox_id',true),'')",&[]).await.unwrap();
            assert_eq!(rows[0].get::<_,String>(0),user.to_string());
            assert_eq!(rows[0].get::<_,Option<String>>(1),None,"user scope must not invent a mailbox");
            // Pool of one: observe the same backend after COMMIT, before a
            // different actor borrows it. No identity may persist on the pool.
            let rows=env.exec.read("SELECT NULLIF(current_setting('app.current_user_id',true),'')",&[]).await.unwrap();
            assert_eq!(rows[0].get::<_,Option<String>>(0),None);
        }
    }).await;
}

impl Tenant {
    fn auth(&self) -> MailboxAuthContext {
        MailboxAuthContext::from_authenticated_session(
            ActorId::new(self.user).unwrap(),
            MailboxId::new(self.mailbox).unwrap(),
            Generation(1),
        )
    }
}

#[tokio::test]
async fn protected_audit_configuration_does_not_admit_caller_supplied_set_statements() {
    with_env("protected_audit_refusal", async |env: &Env| {
        let exec = env
            .exec
            .clone()
            .with_audit_keys("test-encryption-key".into(), "test-audit-key".into());
        let auth = env.a.auth();
        for sql in [
            "SET LOCAL app.unreviewed_audit = 'forged'",
            "SET LOCAL app.audit_hmac_key = 'forged'",
            "SELECT set_config('app.audit_hmac_key', 'forged', true)",
        ] {
            let result = exec
                .run(
                    &envelope(&auth),
                    &auth,
                    deadline(),
                    async |tx: &mut ScopedTx| tx.execute(sql, &[]).await,
                )
                .await;
            assert!(
                matches!(result, CommandOutcome::RolledBack(Rejection::Statement(_))),
                "{result:?}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn protected_audit_gucs_are_bound_to_the_authenticated_transaction_and_do_not_leak() {
    with_env("protected_audit_gucs", async |env: &Env| {
        let exec = env.exec.clone().with_audit_keys("test-encryption-key".into(), "test-audit-key".into());
        let auth = env.a.auth();
        let result = setjoin_pg::run_command(&exec, &envelope(&auth), &auth, deadline(),
            "SELECT current_setting('app.current_mailbox_id')::bigint, current_setting('app.encryption_key'), current_setting('app.audit_hmac_key'), audit_row_hash(1, '2026-01-01T00:00:00Z'::timestamptz, $2, NULL, 'test', NULL, NULL, NULL, NULL, NULL, NULL) WHERE $1::bigint > 0 AND $3::text <> ''",
            &[], |rows| Ok((rows[0].get::<_,i64>(0), rows[0].get::<_,String>(1), rows[0].get::<_,String>(2), rows[0].get::<_,String>(3)))).await;
        match result {
            CommandOutcome::Committed((mailbox, encryption, audit, checksum)) => {
                assert_eq!(mailbox, env.a.mailbox);
                assert_eq!(encryption, "test-encryption-key");
                assert_eq!(audit, "test-audit-key");
                assert!(checksum.starts_with("v3:"), "configured audit key must produce the protected Go chain format");
            }
            other => panic!("protected transaction failed: {other:?}"),
        }
        let values = exec.read("SELECT current_setting('app.encryption_key',true), current_setting('app.audit_hmac_key',true), current_setting('app.current_mailbox_id',true)", &[]).await.unwrap();
        for i in 0..3 { assert!(values[0].get::<_, Option<String>>(i).unwrap_or_default().is_empty(), "transaction GUC leaked to pooled connection"); }
    }).await;
}

#[tokio::test]
async fn foundation_receipt_tracks_commit_and_decoder_rollback_without_family_metadata() {
    with_env("foundation_receipt", async |env: &Env| {
        let registered: bool = env.owner.query_one("SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=276)", &[]).await.unwrap().get(0);
        assert!(registered, "receipt migration must register its schema version");
        let auth = env.a.auth();
        let command = setjoin_pg::ReceiptCommand { family: "F16", command: "test.receipt" };
        let mut request = envelope(&auth);
        request.operation.0.copy_from_slice(&env.a.mailbox.to_be_bytes().repeat(2));
        let sql = "SELECT $1::bigint, $2::bigint, $3::text";
        let outcome = setjoin_pg::run_receipted_command(
            &env.exec, command, &request, &auth, deadline(), sql, &[], |rows| Ok(rows.len()),
        ).await;
        assert!(matches!(outcome, CommandOutcome::Committed(1)), "{outcome:?}");
        assert_eq!(setjoin_pg::lookup_command(&env.exec, &auth, request.operation, command).await.unwrap(), setjoin_pg::OperationLookup::Committed);
        let committed_operation = request.operation;
        request.operation.0[0] ^= 0x80;
        let outcome = setjoin_pg::run_receipted_command(
            &env.exec, command, &request, &auth, deadline(), sql, &[], |_| -> Result<(), setjoin_pg::StatementFailure> {
                Err(setjoin_pg::StatementFailure { hint: None, sqlstate: None, message: "invalid command response".into() })
            },
        ).await;
        assert!(matches!(outcome, CommandOutcome::RolledBack(_)), "{outcome:?}");
        assert_eq!(setjoin_pg::lookup_command(&env.exec, &auth, request.operation, command).await.unwrap(), setjoin_pg::OperationLookup::Absent);
        let row = env.owner.query_one("SELECT family, command, committed_at <= clock_timestamp(), pg_get_userbyid(c.relowner), c.relrowsecurity FROM rust_operation_receipts r CROSS JOIN pg_class c WHERE r.operation_id=$1::text::uuid AND c.oid='rust_operation_receipts'::regclass", &[&setjoin_pg::operation_hex(committed_operation)]).await.unwrap();
        assert_eq!(row.get::<_, String>(0), "F16");
        assert_eq!(row.get::<_, String>(1), "test.receipt");
        assert!(row.get::<_, bool>(2));
        assert_eq!(row.get::<_, String>(3), "setjoin_owner");
        assert!(!row.get::<_, bool>(4), "receipt contains no user data");
        env.owner.execute("DELETE FROM rust_operation_receipts WHERE operation_id=$1::text::uuid", &[&setjoin_pg::operation_hex(committed_operation)]).await.unwrap();
    }).await;
}

#[tokio::test]
async fn command_helper_binds_authenticated_mailbox_actor_and_operation() {
    with_env("command_identity", async |env: &Env| {
        let auth = env.a.auth();
        let request = envelope(&auth);
        let outcome = setjoin_pg::run_command(
            &env.exec,
            &request,
            &auth,
            deadline(),
            "SELECT $1::bigint, $2::bigint, $3::text, \
             current_setting('app.current_mailbox_id')::bigint",
            &[],
            |rows| {
                let row = &rows[0];
                Ok((
                    row.get::<_, i64>(0),
                    row.get::<_, i64>(1),
                    row.get::<_, String>(2),
                    row.get::<_, i64>(3),
                ))
            },
        )
        .await;
        match outcome {
            CommandOutcome::Committed((mailbox, actor, operation, scope)) => {
                assert_eq!(mailbox, env.a.mailbox);
                assert_eq!(actor, env.a.user);
                assert_eq!(
                    operation,
                    format!("{:02x}", request.operation.0[0]).repeat(16)
                );
                assert_eq!(scope, env.a.mailbox);
                assert_ne!(scope, env.b.mailbox);
            }
            other => panic!("authenticated command failed: {other:?}"),
        }
    })
    .await;
}

#[tokio::test]
async fn operation_lookup_is_scoped_and_distinguishes_committed_from_absent() {
    with_env("command_lookup", async |env: &Env| {
        let auth = env.a.auth();
        let request = envelope(&auth);
        let result = setjoin_pg::run_command(
            &env.exec,
            &request,
            &auth,
            deadline(),
            "INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, details) \
             VALUES ($1, $2, 'test_command', jsonb_build_object('operation', $3::text)) \
             RETURNING 1",
            &[],
            |rows| Ok(rows.len()),
        )
        .await;
        assert!(matches!(result, CommandOutcome::Committed(1)), "{result:?}");

        let sql = "SELECT EXISTS(SELECT 1 FROM mailbox_audit_log \
                   WHERE mailbox_id = $1 AND actor_user_id = $2 \
                   AND details->>'operation' = $3 AND action = 'test_command')";
        let committed =
            setjoin_pg::lookup_operation(&env.exec, &auth, request.operation, sql, &[]).await;
        let absent =
            setjoin_pg::lookup_operation(&env.exec, &auth, OperationId([0xee; 16]), sql, &[]).await;
        let foreign =
            setjoin_pg::lookup_operation(&env.exec, &env.b.auth(), request.operation, sql, &[])
                .await;
        assert_eq!(committed.unwrap(), setjoin_pg::OperationLookup::Committed);
        assert_eq!(absent.unwrap(), setjoin_pg::OperationLookup::Absent);
        assert_eq!(foreign.unwrap(), setjoin_pg::OperationLookup::Absent);
    })
    .await;
}

#[tokio::test]
async fn operation_lookup_waits_for_an_in_flight_commit_before_answering() {
    with_env("lookup_inflight", async |env: &Env| {
        let auth = env.a.auth();
        let request = envelope(&auth);
        let operation = request.operation;
        let blocker = env.a.mailbox + 9_000_000_000_i64;
        // A pool may default to REPEATABLE READ. The lookup still has to take
        // its receipt snapshot after the in-flight writer has finished.
        let base_dsn = app_dsn(&owner_dsn().unwrap());
        let dsn = if base_dsn.starts_with("postgres://") || base_dsn.starts_with("postgresql://") {
            let separator = if base_dsn.contains('?') { '&' } else { '?' };
            format!("{base_dsn}{separator}options=-c%20default_transaction_isolation%3Drepeatable%5C%20read")
        } else {
            format!("{base_dsn} options='-c default_transaction_isolation=repeatable\\\\ read'")
        };
        let lookup_exec = ScopedExecutor::from_dsn(&dsn, 1).unwrap();
        let isolation = lookup_exec.read("SELECT current_setting('transaction_isolation')", &[]).await.unwrap();
        assert_eq!(isolation[0].get::<_, String>(0), "repeatable read");
        env.owner
            .query_one("SELECT pg_advisory_lock($1)", &[&blocker])
            .await
            .unwrap();

        let exec = env.exec.clone();
        let task_auth = auth.clone();
        let task = tokio::spawn(async move {
            setjoin_pg::run_command(
                &exec,
                &request,
                &task_auth,
                deadline(),
                "WITH audit AS (INSERT INTO mailbox_audit_log \
                 (mailbox_id, actor_user_id, action, details) VALUES \
                 ($1, $2, 'test_command', jsonb_build_object('operation', $3::text)) \
                 RETURNING 1) SELECT pg_advisory_xact_lock($4::bigint)::text FROM audit \
                 /* gofree-t6-lookup-race */",
                &[(&blocker, Type::INT8)],
                |rows| Ok(rows.len()),
            )
            .await
        });

        // Wait until the command is inside its statement, with its receipt
        // uncommitted. The advisory lock is only a test barrier.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let waiting: bool = env.owner.query_one(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() \
                     AND wait_event = 'advisory' AND query LIKE '%gofree-t6-lookup-race%')",
                    &[],
                ).await.unwrap().get(0);
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.expect("command did not reach the test barrier");

        let sql = "SELECT EXISTS(SELECT 1 FROM mailbox_audit_log \
                   WHERE mailbox_id = $1 AND actor_user_id = $2 \
                   AND details->>'operation' = $3 AND action = 'test_command')";
        let mut lookup = Box::pin(setjoin_pg::lookup_operation(&lookup_exec, &auth, operation, sql, &[]));
        let early = tokio::time::timeout(Duration::from_millis(500), &mut lookup).await;
        env.owner
            .query_one("SELECT pg_advisory_unlock($1)", &[&blocker])
            .await
            .unwrap();
        let committed = task.await.unwrap();
        let was_early = early.is_ok();
        let lookup_result = match early {
            Ok(result) => result,
            Err(_) => lookup.await,
        };

        assert!(matches!(committed, CommandOutcome::Committed(1)), "{committed:?}");
        assert!(!was_early, "lookup answered before the in-flight transaction resolved");
        assert_eq!(lookup_result.unwrap(), setjoin_pg::OperationLookup::Committed);
    }).await;
}

#[tokio::test]
async fn command_helper_refuses_a_different_envelope_authority() {
    with_env("command_authority", async |env: &Env| {
        let auth = env.a.auth();
        let request = envelope(&env.b.auth());
        let message = env.a.message;
        let outcome = setjoin_pg::run_command(
            &env.exec,
            &request,
            &auth,
            deadline(),
            "UPDATE messages SET is_read = TRUE WHERE mailbox_id = $1 AND id = $4 RETURNING id",
            &[(&message, Type::INT8)],
            |rows| Ok(rows.len()),
        )
        .await;
        assert!(
            matches!(outcome, CommandOutcome::RolledBack(Rejection::Authority(_))),
            "{outcome:?}"
        );
        assert!(!env.is_read(message).await);
    })
    .await;
}

#[tokio::test]
async fn operation_lookup_rejects_a_malformed_receipt_result() {
    with_env("lookup_result_shape", async |env: &Env| {
        let auth = env.a.auth();
        let operation = envelope(&auth).operation;
        let result = setjoin_pg::lookup_operation(
            &env.exec,
            &auth,
            operation,
            "SELECT true, 42 WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
            &[],
        )
        .await;
        assert!(
            result.is_err(),
            "ambiguous receipt results must not report committed"
        );
    })
    .await;
}

struct Env {
    owner: Client,
    exec: ScopedExecutor,
    a: Tenant,
    b: Tenant,
}

static NEXT_OPERATION: AtomicU8 = AtomicU8::new(1);

fn envelope(auth: &MailboxAuthContext) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId([NEXT_OPERATION.fetch_add(1, Ordering::Relaxed); 16]),
        authority: auth.authority(),
        binding: accepted_contract(),
        payload_digest: Digest([7; 32]),
        command: (),
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

fn owner_dsn() -> Option<String> {
    ["TEST_DB_DSN", "DB_DSN"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
}

fn require_db() -> bool {
    std::env::var("REQUIRE_DB").as_deref() == Ok("1")
}

fn skip_or_fail(test: &str, reason: &str) -> Option<Env> {
    if require_db() {
        panic!("REQUIRE_DB=1 but {test} cannot reach its database: {reason}");
    }
    // Straight to stderr, past libtest's capture, so the guard counts it.
    use std::io::Write;
    let line = format!(
        "SETJOIN-PG-DB-SKIP (reason={reason}) test={test} — DB-backed executor test NOT run\n"
    );
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
    None
}

async fn connect(dsn: &str) -> Result<Client, tokio_postgres::Error> {
    let (client, connection) = tokio_postgres::connect(dsn, NoTls).await?;
    tokio::spawn(connection);
    Ok(client)
}

fn app_dsn(owner: &str) -> String {
    if let Ok(v) = std::env::var("DB_APP_DSN") {
        if !v.is_empty() {
            return v;
        }
    }
    let mut config: tokio_postgres::Config = owner.parse().expect("owner DSN parses");
    config.user("setjoin_app");
    let host = match &config.get_hosts()[0] {
        tokio_postgres::config::Host::Tcp(h) => h.clone(),
        #[allow(unreachable_patterns)]
        _ => "127.0.0.1".into(),
    };
    format!(
        "host={host} port={} dbname={} user=setjoin_app",
        config.get_ports().first().copied().unwrap_or(5432),
        config.get_dbname().unwrap_or("mailserver_test"),
    )
}

async fn tenant(owner: &Client, label: &str) -> Tenant {
    let mailbox: i64 = owner
        .query_one("SELECT mk_account($1)", &[&label])
        .await
        .expect("mk_account")
        .get(0);
    let user: i64 = owner
        .query_one("SELECT user_id FROM mailboxes WHERE id = $1", &[&mailbox])
        .await
        .unwrap()
        .get(0);
    let tag: i64 = owner
        .query_one("SELECT get_tag_id('Inbox', $1)", &[&mailbox])
        .await
        .unwrap()
        .get(0);
    let hdr = format!("{label}-m1");
    let row = owner
        .query_one(
            "INSERT INTO messages (mailbox_id, folder_id, imap_uid, message_id, subject, from_addr, \
             to_addrs, cc_addrs, size_bytes, thread_id, raw_ref, received_at, is_read) \
             VALUES ($1, $2, 1, $3, 'subject', 'sender@ext.test', '[]'::jsonb, '[]'::jsonb, 10, \
             'thr-' || $3, 'raw-' || $3, now(), FALSE) RETURNING id, received_at::text",
            &[&mailbox, &tag, &hdr],
        )
        .await
        .expect("insert message");
    let message: i64 = row.get(0);
    let received: String = row.get(1);
    owner
        .execute(
            "SELECT tag_message($1, $2::text::timestamptz, 'Inbox', $3, 'deliver', TRUE)",
            &[&message, &received, &mailbox],
        )
        .await
        .expect("tag_message");
    Tenant {
        mailbox,
        user,
        message,
    }
}

async fn setup(test: &str) -> Option<Env> {
    let Some(dsn) = owner_dsn() else {
        return skip_or_fail(test, "no-dsn");
    };
    let owner = match connect(&dsn).await {
        Ok(c) => c,
        Err(e) => return skip_or_fail(test, &format!("owner-connect-failed: {e}")),
    };
    // Non-vacuity: FORCE RLS must be on, and the executor's role constrained.
    let forced: bool = owner
        .query_one(
            "SELECT bool_and(relforcerowsecurity) FROM pg_class \
             WHERE relnamespace = 'public'::regnamespace AND relname IN ('messages','message_tags')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        forced,
        "V004 FORCE ROW LEVEL SECURITY missing; load scripts/load-test-schema.sh"
    );

    let app = app_dsn(&dsn);
    let probe = match connect(&app).await {
        Ok(c) => c,
        Err(e) => return skip_or_fail(test, &format!("app-role-connect-failed: {e}")),
    };
    let row = probe
        .query_one(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user",
            &[],
        )
        .await
        .unwrap();
    let (sup, bypass): (bool, bool) = (row.get(0), row.get(1));
    assert!(
        !sup && !bypass,
        "executor credential must be a constrained role (super={sup} bypassrls={bypass})"
    );
    let exec = ScopedExecutor::from_dsn(&app, 1).expect("executor pool");
    let pid = std::process::id();
    let a = tenant(&owner, &format!("rp07x-{test}-a-{pid}")).await;
    let b = tenant(&owner, &format!("rp07x-{test}-b-{pid}")).await;
    assert_ne!(
        a.mailbox, a.user,
        "fixtures must keep user_id != mailbox_id"
    );
    Some(Env { owner, exec, a, b })
}

/// Runs `f` against fresh fixtures and always tears them down (mk_account
/// commits real rows; leaked users would skew org-wide pgTAP counts), then
/// re-raises any assertion failure.
async fn with_env(test: &str, f: impl AsyncFnOnce(&Env)) {
    let Some(env) = setup(test).await else {
        return;
    };
    let result = AssertUnwindSafe(f(&env)).catch_unwind().await;
    env.teardown().await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

impl Env {
    async fn teardown(self) {
        let mbs = vec![self.a.mailbox, self.b.mailbox];
        let users = vec![self.a.user, self.b.user];
        let o = &self.owner;
        o.batch_execute("BEGIN; SET LOCAL session_replication_role = replica")
            .await
            .unwrap();
        o.execute(
            "DELETE FROM mailbox_audit_log WHERE mailbox_id = ANY($1)",
            &[&mbs],
        )
        .await
        .unwrap();
        o.batch_execute("COMMIT").await.unwrap();
        // Release partition locks before FK cascades. Keep FK triggers active
        // so membership UID ledgers and all other fixture children disappear.
        o.execute("DELETE FROM messages WHERE mailbox_id = ANY($1)", &[&mbs])
            .await
            .unwrap();
        o.batch_execute("BEGIN").await.unwrap();
        o.execute("DELETE FROM mailboxes WHERE id = ANY($1)", &[&mbs])
            .await
            .unwrap();
        o.execute("DELETE FROM users WHERE id = ANY($1)", &[&users])
            .await
            .unwrap();
        o.batch_execute("COMMIT").await.unwrap();
        let orphaned: bool = o.query_one("SELECT EXISTS(SELECT 1 FROM imap_membership_uid_ledger l WHERE NOT EXISTS(SELECT 1 FROM tags t WHERE t.id=l.tag_id))", &[]).await.unwrap().get(0);
        assert!(
            !orphaned,
            "fixture cleanup must preserve UID-ledger foreign keys for dump/restore"
        );
    }

    async fn is_read(&self, message: i64) -> bool {
        self.owner
            .query_one("SELECT is_read FROM messages WHERE id = $1", &[&message])
            .await
            .unwrap()
            .get(0)
    }
}

fn ids(tx_rows: &[setjoin_pg::Row]) -> Vec<i64> {
    tx_rows.iter().map(|r| r.get::<_, i64>(0)).collect()
}

#[tokio::test]
async fn own_mailbox_rows_are_visible_through_the_executor() {
    with_env("own_visible", async |env: &Env| {
        let auth = env.a.auth();
        let target = env.a.message;
        let out = env
            .exec
            .run(
                &envelope(&auth),
                &auth,
                deadline(),
                async move |tx: &mut ScopedTx| {
                    tx.query(
                        "SELECT id FROM messages WHERE id = $1",
                        &[(&target, Type::INT8)],
                    )
                    .await
                },
            )
            .await;
        match out {
            CommandOutcome::Committed(rows) => assert_eq!(ids(&rows), vec![target]),
            other => panic!("expected committed read, got {other:?}"),
        }
    })
    .await;
}

#[tokio::test]
async fn cross_mailbox_read_returns_no_rows() {
    with_env("cross_read", async |env: &Env| {
        let auth = env.a.auth();
        let foreign = env.b.message;
        let own = env.a.message;
        let out = env
            .exec
            .run(
                &envelope(&auth),
                &auth,
                deadline(),
                async move |tx: &mut ScopedTx| {
                    let by_id = tx
                        .query(
                            "SELECT id FROM messages WHERE id = $1",
                            &[(&foreign, Type::INT8)],
                        )
                        .await?;
                    // No ownership predicate at all: RLS still confines it to A.
                    let all = tx
                        .query(
                            "SELECT id FROM messages WHERE id = ANY($1)",
                            &[(&vec![own, foreign], Type::INT8_ARRAY)],
                        )
                        .await?;
                    let tags = tx
                        .query(
                            "SELECT message_id FROM message_tags WHERE message_id = $1",
                            &[(&foreign, Type::INT8)],
                        )
                        .await?;
                    Ok::<_, setjoin_pg::StatementFailure>((ids(&by_id), ids(&all), tags.len()))
                },
            )
            .await;
        match out {
            CommandOutcome::Committed((by_id, all, tags)) => {
                assert!(by_id.is_empty(), "foreign message visible: {by_id:?}");
                assert_eq!(all, vec![own]);
                assert_eq!(tags, 0, "foreign message_tags visible");
            }
            other => panic!("expected committed read, got {other:?}"),
        }
    })
    .await;
}

#[tokio::test]
async fn cross_mailbox_update_changes_nothing() {
    with_env("cross_update", async |env: &Env| {
        let auth = env.a.auth();
        let foreign = env.b.message;
        let out = env
            .exec
            .run(
                &envelope(&auth),
                &auth,
                deadline(),
                async move |tx: &mut ScopedTx| {
                    tx.execute(
                        "UPDATE messages SET is_read = TRUE WHERE id = $1",
                        &[(&foreign, Type::INT8)],
                    )
                    .await
                },
            )
            .await;
        match out {
            CommandOutcome::Committed(n) => assert_eq!(n, 0, "foreign row updated"),
            other => panic!("expected committed no-op, got {other:?}"),
        }
        assert!(!env.is_read(env.b.message).await, "foreign message changed");
    })
    .await;
}

#[tokio::test]
async fn cross_mailbox_insert_is_refused_and_rolled_back() {
    with_env("cross_insert", async |env: &Env| {
    let auth = env.a.auth();
    let foreign_mailbox = env.b.mailbox;
    let own = env.a.message;
    let out = env
        .exec
        .run(&envelope(&auth), &auth, deadline(), async move |tx: &mut ScopedTx| {
                // An own-row write first: it must not survive the refused insert.
                let n = tx
                    .execute("UPDATE messages SET is_read = TRUE WHERE id = $1", &[(&own, Type::INT8)])
                    .await?;
                assert_eq!(n, 1, "own row not writable (scope missing?)");
                tx.execute(
                    "INSERT INTO messages (mailbox_id, imap_uid, message_id, subject, from_addr, to_addrs, \
                     cc_addrs, size_bytes, thread_id, raw_ref, received_at, is_read) \
                     VALUES ($1, 99, 'rp07x-forged', 's', 'x@ext.test', '[]'::jsonb, '[]'::jsonb, 1, 't', 'r', now(), FALSE)",
                    &[(&foreign_mailbox, Type::INT8)],
                )
                .await
        })
        .await;
    match &out {
        CommandOutcome::RolledBack(Rejection::Statement(f)) => {
            assert_eq!(f.sqlstate.as_deref(), Some("42501"), "{f:?}")
        }
        other => panic!("expected RLS refusal, got {other:?}"),
    }
    assert_eq!(out.recovery(), RecoveryAction::ReturnRejected);
    assert!(
        !env.is_read(env.a.message).await,
        "own write survived a rollback"
    );
    let forged: i64 = env
        .owner
        .query_one(
            "SELECT count(*) FROM messages WHERE message_id = 'rp07x-forged'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(forged, 0);
    })
    .await;
}

#[tokio::test]
async fn request_owned_mailbox_cannot_redirect_the_scope() {
    with_env("redirect", async |env: &Env| {
        // The envelope claims mailbox B; the authenticated session is A.
        let auth = env.a.auth();
        let forged = envelope(&env.b.auth());
        let out = env
            .exec
            .run(
                &forged,
                &auth,
                deadline(),
                async move |_tx: &mut ScopedTx| -> Result<(), ()> {
                    unreachable!("body must not run")
                },
            )
            .await;
        assert!(
            matches!(
                out,
                CommandOutcome::RolledBack(Rejection::Authority(LifecycleError::Contract(_)))
            ),
            "{out:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn commit_persists_and_scope_does_not_leak_to_the_next_transaction() {
    with_env("commit_noleak", async |env: &Env| {
        let auth = env.a.auth();
        let own = env.a.message;
        let out = env
            .exec
            .run(
                &envelope(&auth),
                &auth,
                deadline(),
                async move |tx: &mut ScopedTx| {
                    let mailbox = tx.mailbox().get();
                    tx.execute(
                        "UPDATE messages SET is_read = TRUE WHERE id = $1 AND mailbox_id = $2",
                        &[(&own, Type::INT8), (&mailbox, Type::INT8)],
                    )
                    .await
                },
            )
            .await;
        assert!(matches!(out, CommandOutcome::Committed(1)), "{out:?}");
        assert_eq!(out.recovery(), RecoveryAction::ReadAcceptedResult);
        assert!(env.is_read(own).await);

        // Pool of one: the same server connection now runs B's command and must
        // see neither A's GUC nor A's rows.
        let auth_b = env.b.auth();
        let a_msg = env.a.message;
        let out = env
            .exec
            .run(
                &envelope(&auth_b),
                &auth_b,
                deadline(),
                async move |tx: &mut ScopedTx| {
                    let scope = tx
                        .query(
                            "SELECT current_setting('app.current_mailbox_id', true)",
                            &[],
                        )
                        .await?;
                    let rows = tx
                        .query(
                            "SELECT id FROM messages WHERE id = $1",
                            &[(&a_msg, Type::INT8)],
                        )
                        .await?;
                    Ok::<_, setjoin_pg::StatementFailure>((
                        scope[0].get::<_, Option<String>>(0),
                        rows.len(),
                    ))
                },
            )
            .await;
        match out {
            CommandOutcome::Committed((scope, n)) => {
                assert_eq!(scope, Some(env.b.mailbox.to_string()));
                assert_eq!(n, 0);
            }
            other => panic!("{other:?}"),
        }
    })
    .await;
}

#[tokio::test]
async fn body_error_rolls_back_every_write() {
    with_env("body_error", async |env: &Env| {
        let auth = env.a.auth();
        let own = env.a.message;
        let out = env
            .exec
            .run(
                &envelope(&auth),
                &auth,
                deadline(),
                async move |tx: &mut ScopedTx| {
                    let n = tx
                        .execute(
                            "UPDATE messages SET is_read = TRUE WHERE id = $1",
                            &[(&own, Type::INT8)],
                        )
                        .await
                        .map_err(|_| "statement")?;
                    assert_eq!(n, 1, "own row not writable (scope missing?)");
                    Err::<(), _>("audit failed")
                },
            )
            .await;
        assert!(
            matches!(
                out,
                CommandOutcome::RolledBack(Rejection::Body("audit failed"))
            ),
            "{out:?}"
        );
        assert!(!env.is_read(own).await, "write survived body rollback");
    })
    .await;
}

#[tokio::test]
async fn swallowed_statement_error_cannot_commit() {
    with_env("swallowed", async |env: &Env| {
        let auth = env.a.auth();
        let own = env.a.message;
        let out = env
            .exec
            .run(
                &envelope(&auth),
                &auth,
                deadline(),
                async move |tx: &mut ScopedTx| {
                    let n = tx
                        .execute(
                            "UPDATE messages SET is_read = TRUE WHERE id = $1",
                            &[(&own, Type::INT8)],
                        )
                        .await;
                    assert_eq!(n, Ok(1), "own row not writable (scope missing?)");
                    let _ = tx.query("SELECT 1/0", &[]).await; // error ignored by the body
                    Ok::<_, ()>(())
                },
            )
            .await;
        match out {
            CommandOutcome::RolledBack(Rejection::Statement(f)) => {
                assert_eq!(f.sqlstate.as_deref(), Some("22012"))
            }
            other => panic!("{other:?}"),
        }
        assert!(!env.is_read(own).await);
    })
    .await;
}

#[tokio::test]
async fn set_role_is_refused_before_reaching_the_server() {
    with_env("set_role", async |env: &Env| {
        let auth = env.a.auth();
        let out = env
            .exec
            .run(
                &envelope(&auth),
                &auth,
                deadline(),
                async move |tx: &mut ScopedTx| {
                    let refused = tx.execute("SET ROLE setjoin_worker", &[]).await;
                    let role = tx.query("SELECT current_user::text", &[]).await;
                    Ok::<_, ()>((refused.is_err(), role.is_err()))
                },
            )
            .await;
        match out {
            CommandOutcome::RolledBack(Rejection::Statement(f)) => {
                assert_eq!(f.sqlstate, None);
                assert!(f.message.contains("refused by executor"), "{f:?}");
            }
            other => panic!("{other:?}"),
        }
    })
    .await;
}

#[tokio::test]
async fn lost_connection_during_commit_is_unknown_not_success() {
    with_env("lost_commit", async |env: &Env| {
        let auth = env.a.auth();
        let own = env.a.message;
        let operation_envelope = envelope(&auth);
        let owner = &env.owner;
        let out = env
            .exec
            .run(
                &operation_envelope,
                &auth,
                deadline(),
                async move |tx: &mut ScopedTx| {
                    let n = tx
                        .execute(
                            "UPDATE messages SET is_read = TRUE WHERE id = $1",
                            &[(&own, Type::INT8)],
                        )
                        .await
                        .map_err(|_| ())?;
                    assert_eq!(n, 1, "own row not writable (scope missing?)");
                    let pid: i32 = tx
                        .query("SELECT pg_backend_pid()", &[])
                        .await
                        .map_err(|_| ())?[0]
                        .get(0);
                    // The server connection dies after the body and before COMMIT's reply.
                    owner
                        .execute("SELECT pg_terminate_backend($1)", &[&pid])
                        .await
                        .map_err(|_| ())?;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Ok::<_, ()>(())
                },
            )
            .await;
        match out {
            CommandOutcome::Unknown { operation } => {
                assert_eq!(operation, operation_envelope.operation)
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
        assert_eq!(out.recovery(), RecoveryAction::LookupUnderCurrentAuthority);

        // The quarantined connection is gone; the pool serves a fresh one.
        let out = env
            .exec
            .run(
                &envelope(&auth),
                &auth,
                deadline(),
                async move |tx: &mut ScopedTx| tx.query("SELECT 1", &[]).await.map(|r| r.len()),
            )
            .await;
        assert!(matches!(out, CommandOutcome::Committed(1)), "{out:?}");
    })
    .await;
}

/// Compile-time proof: `run` stays `Send` (spawnable on a multi-thread runtime)
/// while the body borrows from the caller's stack.
#[allow(dead_code)]
fn run_future_is_send(exec: ScopedExecutor, auth: MailboxAuthContext, borrowed: &str) {
    fn is_send<T: Send>(_: T) {}
    is_send(async move {
        let env = envelope(&auth);
        exec.run(&env, &auth, deadline(), async |tx: &mut ScopedTx| {
            let len = borrowed.len() as i64;
            tx.execute("SELECT $1", &[(&len, Type::INT8)]).await
        })
        .await
    });
}

// ── read_scoped (#216): one READ ONLY transaction scoped like `run` ──

#[tokio::test]
async fn scoped_read_sees_own_rows_and_never_a_foreign_one() {
    with_env("scoped_read_scope", async |env: &Env| {
        let auth = env.a.auth();
        let (own, foreign) = (env.a.message, env.b.message);
        let rows = env
            .exec
            .read_scoped(
                &auth,
                "SELECT id FROM messages WHERE id = ANY($1)",
                &[(&vec![own, foreign], Type::INT8_ARRAY)],
            )
            .await
            .expect("scoped read");
        assert_eq!(ids(&rows), vec![own]);
        let scope = env
            .exec
            .read_scoped(
                &auth,
                "SELECT current_setting('app.current_mailbox_id', true)",
                &[],
            )
            .await
            .expect("scope probe");
        assert_eq!(
            scope[0].get::<_, Option<String>>(0),
            Some(env.a.mailbox.to_string())
        );
        // Pool of one: the scope is transaction-local and gone afterwards.
        let after = env
            .exec
            .read(
                "SELECT current_setting('app.current_mailbox_id', true)",
                &[],
            )
            .await
            .expect("autocommit probe");
        assert!(matches!(
            after[0].get::<_, Option<String>>(0).as_deref(),
            None | Some("")
        ));
    })
    .await;
}

#[tokio::test]
async fn scoped_read_cannot_write() {
    with_env("scoped_read_ro", async |env: &Env| {
        let auth = env.a.auth();
        let own = env.a.message;
        // A SELECT that calls a writing reducer helper: the READ ONLY
        // transaction refuses it on the server (SQLSTATE 25006).
        let mailbox = env.a.mailbox;
        let err = env
            .exec
            .read_scoped(
                &auth,
                "SELECT bump_tag_mailbox_state($1)",
                &[(&mailbox, Type::INT8)],
            )
            .await
            .expect_err("a writing function is refused");
        assert_eq!(err.sqlstate.as_deref(), Some("25006"), "{err:?}");
        let refused = env
            .exec
            .read_scoped(
                &auth,
                "UPDATE messages SET is_read = TRUE WHERE id = $1",
                &[(&own, Type::INT8)],
            )
            .await
            .expect_err("non-SELECT refused");
        assert_eq!(refused.sqlstate, None, "refused before reaching the server");
        assert!(!env.is_read(own).await);
        // The connection is healthy for the next caller.
        let rows = env
            .exec
            .read_scoped(&auth, "SELECT 1::int8", &[])
            .await
            .expect("pool usable after a refused write");
        assert_eq!(ids(&rows), vec![1]);
    })
    .await;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitCut {
    BeforeCommit,
    AfterCommit,
}

/// A one-connection wire proxy that cuts exactly at COMMIT. For the
/// committed case, PostgreSQL's CommandComplete is intercepted before it
/// reaches the client; for the absent case, COMMIT never reaches PostgreSQL.
async fn commit_cut_proxy(
    dsn: &str,
    cut: CommitCut,
) -> (String, JoinHandle<io::Result<CommitCut>>) {
    let config: tokio_postgres::Config = dsn.parse().unwrap();
    let host = match config.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(host)) => host.clone(),
        None => "127.0.0.1".into(),
        _ => panic!("commit-loss test needs a TCP DB_APP_DSN"),
    };
    let port = *config.get_ports().first().unwrap_or(&5432);
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let mut proxied = format!("host=127.0.0.1 port={proxy_port}");
    // Reconstruct a libpq DSN so URI and keyword inputs both work; never
    // print it, since it can contain the app credential.
    let mut add = |key: &str, value: &str| {
        let escaped = value.replace('\\', "\\\\").replace('\'', "\\'");
        proxied.push_str(&format!(" {key}='{escaped}'"));
    };
    if let Some(user) = config.get_user() {
        add("user", user);
    }
    if let Some(password) = config.get_password() {
        add(
            "password",
            std::str::from_utf8(password).expect("DB password is not UTF-8"),
        );
    }
    if let Some(database) = config.get_dbname() {
        add("dbname", database);
    }
    if let Some(options) = config.get_options() {
        add("options", options);
    }

    let task = tokio::spawn(async move {
        let (client, _) = listener.accept().await?;
        let server = TcpStream::connect((host.as_str(), port)).await?;
        let (mut client_read, mut client_write) = client.into_split();
        let (mut server_read, mut server_write) = server.into_split();

        // The first PostgreSQL packet is a length-prefixed startup packet,
        // without a message tag; the executor uses NoTls.
        let startup_len = client_read.read_u32().await?;
        if !(8..=65_536).contains(&startup_len) {
            return Err(io::Error::other("invalid PostgreSQL startup packet"));
        }
        let mut startup = vec![0; startup_len as usize - 4];
        client_read.read_exact(&mut startup).await?;
        server_write.write_u32(startup_len).await?;
        server_write.write_all(&startup).await?;

        let requests = async {
            loop {
                let tag = client_read.read_u8().await?;
                let len = client_read.read_u32().await?;
                if !(4..=1_048_576).contains(&len) {
                    return Err(io::Error::other("invalid PostgreSQL request"));
                }
                let mut body = vec![0; len as usize - 4];
                client_read.read_exact(&mut body).await?;
                if tag == b'Q' && body == b"COMMIT\0" && cut == CommitCut::BeforeCommit {
                    return Ok(CommitCut::BeforeCommit);
                }
                server_write.write_u8(tag).await?;
                server_write.write_u32(len).await?;
                server_write.write_all(&body).await?;
            }
        };
        let responses = async {
            loop {
                let tag = server_read.read_u8().await?;
                let len = server_read.read_u32().await?;
                if !(4..=1_048_576).contains(&len) {
                    return Err(io::Error::other("invalid PostgreSQL response"));
                }
                let mut body = vec![0; len as usize - 4];
                server_read.read_exact(&mut body).await?;
                if tag == b'C' && body == b"COMMIT\0" && cut == CommitCut::AfterCommit {
                    return Ok(CommitCut::AfterCommit);
                }
                client_write.write_u8(tag).await?;
                client_write.write_u32(len).await?;
                client_write.write_all(&body).await?;
            }
        };
        tokio::select! { result = requests => result, result = responses => result }
    });
    (proxied, task)
}

#[tokio::test]
async fn foundation_receipt_resolves_real_commit_loss_without_replaying_command() {
    with_env("receipt_commit_loss", async |env: &Env| {
        let auth = env.a.auth();
        let command = setjoin_pg::ReceiptCommand { family: "F16", command: "test.commit-loss" };
        for cut in [CommitCut::BeforeCommit, CommitCut::AfterCommit] {
            let mut request = envelope(&auth);
            request.operation.0.copy_from_slice(&env.a.mailbox.to_be_bytes().repeat(2));
            request.operation.0[0] = if cut == CommitCut::BeforeCommit { 0xc1 } else { 0xc2 };
            let (dsn, proxy) = commit_cut_proxy(&app_dsn(&owner_dsn().unwrap()), cut).await;
            let exec = ScopedExecutor::from_dsn(&dsn, 1).unwrap();
            let result = setjoin_pg::run_receipted_command(&exec, command, &request, &auth, deadline(),
                "UPDATE messages SET is_read=TRUE WHERE mailbox_id=$1 AND id=$4 AND $2::bigint>0 AND $3::text<>'' RETURNING id",
                &[(&env.a.message, Type::INT8)], |rows| Ok(rows.len())).await;
            assert!(matches!(result, CommandOutcome::Unknown { operation } if operation == request.operation), "{result:?}");
            assert_eq!(tokio::time::timeout(Duration::from_secs(10), proxy).await.unwrap().unwrap().unwrap(), cut);
            let lookup = setjoin_pg::lookup_command(&env.exec, &auth, request.operation, command).await.unwrap();
            assert_eq!(lookup, if cut == CommitCut::BeforeCommit { setjoin_pg::OperationLookup::Absent } else { setjoin_pg::OperationLookup::Committed });
            assert_eq!(env.is_read(env.a.message).await, cut == CommitCut::AfterCommit);
            env.owner.execute("DELETE FROM rust_operation_receipts WHERE operation_id=$1::text::uuid", &[&setjoin_pg::operation_hex(request.operation)]).await.unwrap();
        }
    }).await;
}

#[tokio::test]
async fn foundation_receipt_lookup_waits_for_in_flight_commit() {
    with_env("receipt_inflight", async |env: &Env| {
        let auth = env.a.auth();
        let mut request = envelope(&auth);
        request.operation.0.copy_from_slice(&env.a.mailbox.to_be_bytes().repeat(2));
        let command = setjoin_pg::ReceiptCommand { family: "F16", command: "test.inflight" };
        let operation = request.operation;
        let blocker = env.a.mailbox + 9_000_000_000_i64;
        // A pool may default to REPEATABLE READ. The lookup still has to take
        // its receipt snapshot after the in-flight writer has finished.
        let base_dsn = app_dsn(&owner_dsn().unwrap());
        let dsn = if base_dsn.starts_with("postgres://") || base_dsn.starts_with("postgresql://") {
            let separator = if base_dsn.contains('?') { '&' } else { '?' };
            format!("{base_dsn}{separator}options=-c%20default_transaction_isolation%3Drepeatable%5C%20read")
        } else {
            format!("{base_dsn} options='-c default_transaction_isolation=repeatable\\\\ read'")
        };
        let lookup_exec = ScopedExecutor::from_dsn(&dsn, 1).unwrap();
        let isolation = lookup_exec.read("SELECT current_setting('transaction_isolation')", &[]).await.unwrap();
        assert_eq!(isolation[0].get::<_, String>(0), "repeatable read");
        env.owner
            .query_one("SELECT pg_advisory_lock($1)", &[&blocker])
            .await
            .unwrap();

        let exec = env.exec.clone();
        let task_auth = auth.clone();
        let task = tokio::spawn(async move {
            setjoin_pg::run_receipted_command(
                &exec, command,
                &request,
                &task_auth,
                deadline(),
                "WITH audit AS (INSERT INTO mailbox_audit_log \
                 (mailbox_id, actor_user_id, action, details) VALUES \
                 ($1, $2, 'test_command', jsonb_build_object('operation', $3::text)) \
                 RETURNING 1) SELECT pg_advisory_xact_lock($4::bigint)::text FROM audit \
                 /* gofree-t6-lookup-race */",
                &[(&blocker, Type::INT8)],
                |rows| Ok(rows.len()),
            )
            .await
        });

        // Wait until the command is inside its statement, with its receipt
        // uncommitted. The advisory lock is only a test barrier.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let waiting: bool = env.owner.query_one(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() \
                     AND wait_event = 'advisory' AND query LIKE '%gofree-t6-lookup-race%')",
                    &[],
                ).await.unwrap().get(0);
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.expect("command did not reach the test barrier");

        let mut lookup = Box::pin(setjoin_pg::lookup_command(&lookup_exec, &auth, operation, command));
        let early = tokio::time::timeout(Duration::from_millis(500), &mut lookup).await;
        env.owner
            .query_one("SELECT pg_advisory_unlock($1)", &[&blocker])
            .await
            .unwrap();
        let committed = task.await.unwrap();
        let was_early = early.is_ok();
        let lookup_result = match early {
            Ok(result) => result,
            Err(_) => lookup.await,
        };

        assert!(matches!(committed, CommandOutcome::Committed(1)), "{committed:?}");
        assert!(!was_early, "lookup answered before the in-flight transaction resolved");
        assert_eq!(lookup_result.unwrap(), setjoin_pg::OperationLookup::Committed);
        env.owner.execute("DELETE FROM rust_operation_receipts WHERE operation_id=$1::text::uuid", &[&setjoin_pg::operation_hex(operation)]).await.unwrap();
    }).await;
}

#[tokio::test]
async fn auth_crypto_context_is_local_on_commit_and_rollback() {
    with_env("idlogin3_crypto_context", async |env: &Env| {
        let encryption="33".repeat(32);let hmac="44".repeat(32);
        let exec=env.exec.clone().with_audit_keys(encryption.clone(),hmac.clone());
        let actor=ActorId::new(env.a.user).unwrap();
        let outcome=exec.run_user_command(actor,OperationId([33;16]),"SELECT current_setting('app.encryption_key',true),current_setting('app.audit_hmac_key',true)",&[],|rows|Ok((rows[0].get::<_,Option<String>>(0),rows[0].get::<_,Option<String>>(1)))).await;
        assert!(matches!(outcome,CommandOutcome::Committed((Some(ref e),Some(ref h))) if e==&encryption && h==&hmac),"{outcome:?}");
        for rollback in [false,true] {
            if rollback {let outcome=exec.run_user_command(actor,OperationId([34;16]),"SELECT 1/0",&[],|_|Ok(())).await;assert!(matches!(outcome,CommandOutcome::RolledBack(_)),"{outcome:?}");}
            let rows=exec.read("SELECT NULLIF(current_setting('app.encryption_key',true),''),NULLIF(current_setting('app.audit_hmac_key',true),'')",&[]).await.unwrap();
            assert_eq!(rows[0].get::<_,Option<String>>(0),None,"encryption key leaked after transaction");
            assert_eq!(rows[0].get::<_,Option<String>>(1),None,"audit key leaked after transaction");
        }
    }).await;
}

#[tokio::test]
async fn credential_proof_and_reducer_share_transaction_scope_and_snapshot() {
    with_env("credential_proof", async |env: &Env| {
        let user=env.a.user;
        let exec=env.exec.clone().with_audit_keys("proof-key".into(),"proof-audit".into());
        let op=OperationId([0x34;16]);
        let out=exec.run_user_proof_command(ActorId::new(user).unwrap(),op,
            "SELECT txid_current(),current_setting('app.current_user_id'),current_setting('app.encryption_key')",&[],
            |rows| {
                assert_eq!(rows[0].get::<_,String>(1),user.to_string());
                assert_eq!(rows[0].get::<_,String>(2),"proof-key");
                Ok(setjoin_pg::ProvenStatement::new("SELECT txid_current()=$1,current_setting('app.current_user_id')=$2,current_setting('app.encryption_key')=$3")
                    .bind(rows[0].get::<_,i64>(0),Type::INT8).bind(user.to_string(),Type::TEXT).bind("proof-key".to_owned(),Type::TEXT))
            },
            |rows|Ok(rows[0].get::<_,bool>(0)&&rows[0].get::<_,bool>(1)&&rows[0].get::<_,bool>(2))).await;
        assert!(matches!(out,CommandOutcome::Committed(true)),"{out:?}");
        let clean=exec.read("SELECT NULLIF(current_setting('app.current_user_id',true),''),NULLIF(current_setting('app.encryption_key',true),'')",&[]).await.unwrap();
        assert_eq!(clean[0].get::<_,Option<String>>(0),None);
        assert_eq!(clean[0].get::<_,Option<String>>(1),None);
    }).await;
}

#[tokio::test]
async fn async_credential_proof_keeps_the_user_fence_until_reducer_commit() {
    with_env("async_credential_proof", async |env: &Env| {
        let user=env.a.user;
        let out=env.exec.run_user_async_proof_command_with_tail(ActorId::new(user).unwrap(),OperationId([0x35;16]),
            "SELECT txid_current() FROM users WHERE id=$1 FOR NO KEY UPDATE",&[(&user,Type::INT8)],
            |rows| {
                let transaction: i64=rows[0].get(0);
                async move {
                    env.owner.batch_execute("BEGIN;SET LOCAL lock_timeout='50ms'").await.unwrap();
                    let refusal=env.owner.execute("UPDATE users SET display_name='must-not-commit' WHERE id=$1",&[&user]).await.unwrap_err();
                    assert_eq!(refusal.as_db_error().map(|e|e.code().code()),Some("55P03"),"credential read must retain its fence across await");
                    env.owner.batch_execute("ROLLBACK").await.unwrap();
                    Ok(setjoin_pg::ProvenStatement::new("SELECT txid_current()=$1").bind(transaction,Type::INT8))
                }
            },|rows|Ok(rows[0].get::<_,bool>(0)),|_|std::future::ready(())).await;
        assert!(matches!(out,CommandOutcome::Committed(true)),"{out:?}");
    }).await;
}
