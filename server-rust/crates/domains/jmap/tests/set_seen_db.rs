//! DB-backed proofs for what the parity oracle does not observe (#214): the
//! actor audit row is written in the command's transaction, an audit failure
//! rolls every effect back, and a request for another mailbox is refused.
//!
//! Gate and fixtures are the conformance harness's (`setjoin-conformance`):
//! owner DSN `TEST_DB_DSN`/`DB_DSN`, the command on `DB_APP_DSN`
//! (`setjoin_app`) when set; no DSN → `CONFORMANCE-SKIP` line, `REQUIRE_DB=1`
//! → FAIL.
use std::io;
use std::time::{Duration, Instant};

use setjoin_conformance::fixture::{self, Account, Snapshot};
use setjoin_conformance::harness::Db;
use setjoin_contracts::command::{CommandEnvelope, OperationResult, SetMessageSeen};
use setjoin_contracts::ids::{ActorId, Digest, Generation, MailboxId, MessageId, OperationId};
use setjoin_db::lifecycle::accepted_contract;
use setjoin_jmap::{lookup_set_seen, set_message_seen, OperationLookup, SeenEffect, SetSeenReply};
use setjoin_pg::{MailboxAuthContext, Rejection, ScopedExecutor};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_postgres::types::Type;
use tokio_postgres::Client;

/// The audit-failure case adds and drops a trigger on the partitioned audit
/// table; DDL there deadlocks with concurrent audit inserts, so this file's
/// DB cases run one at a time.
static SERIAL: Mutex<()> = Mutex::const_new(());

struct Env {
    owner: Client,
    exec: ScopedExecutor,
    a: Account,
}

async fn env(db: &Db, label: &str) -> Env {
    let owner = db.connect().await.expect("owner connection");
    let exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).expect("pool");
    let a = fixture::account(&owner, label).await.expect("fixture");
    Env { owner, exec, a }
}

impl Env {
    fn auth(&self) -> MailboxAuthContext {
        MailboxAuthContext::from_authenticated_session(
            ActorId::new(self.a.user).unwrap(),
            MailboxId::new(self.a.mailbox).unwrap(),
            Generation(1),
        )
    }

    async fn run(&self, mailbox: i64, message: i64, seen: bool) -> SetSeenReply {
        self.run_op(OperationId([0x5E; 16]), mailbox, message, seen)
            .await
    }

    async fn run_op(
        &self,
        operation: OperationId,
        mailbox: i64,
        message: i64,
        seen: bool,
    ) -> SetSeenReply {
        let auth = self.auth();
        let envelope = CommandEnvelope {
            operation,
            authority: auth.authority(),
            binding: accepted_contract(),
            payload_digest: Digest([9; 32]),
            command: SetMessageSeen {
                mailbox: MailboxId::new(mailbox).unwrap(),
                message: MessageId::new(message).unwrap(),
                seen,
            },
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        set_message_seen(&self.exec, &envelope, &auth, deadline).await
    }

    async fn snapshot(&self) -> Snapshot {
        fixture::snapshot(&self.owner, self.a.mailbox)
            .await
            .unwrap()
    }

    /// (actor_user_id, action, message_id) for every audit row of the mailbox.
    async fn audit_rows(&self) -> Vec<(Option<i64>, String, Option<i64>)> {
        self.owner
            .query_typed(
                "SELECT actor_user_id, action, message_id FROM mailbox_audit_log \
                 WHERE mailbox_id = $1 ORDER BY id",
                &[(&self.a.mailbox, Type::INT8)],
            )
            .await
            .unwrap()
            .iter()
            .map(|r| (r.get(0), r.get(1), r.get(2)))
            .collect()
    }

    async fn close(self) {
        fixture::remove(&self.owner, &self.a)
            .await
            .expect("fixture cleanup");
    }
}

fn email_set(actor: i64, n: usize) -> Vec<(Option<i64>, String, Option<i64>)> {
    vec![(Some(actor), "email_set".to_string(), None); n]
}

/// Every committed command writes exactly one `email_set` audit row naming the
/// session's actor, whether `is_read` changed, was already equal, or the
/// message was not found.
#[tokio::test(flavor = "current_thread")]
async fn every_committed_command_writes_one_actor_audit_row() {
    let Some(db) = Db::for_case("every_committed_command_writes_one_actor_audit_row") else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let e = env(&db, "mail-audit").await;
    let (mb, msg, user) = (e.a.mailbox, e.a.two_labels, e.a.user);
    let first = e.run(mb, msg, true).await;
    let second = e.run(mb, msg, true).await;
    let missing = e.run(mb, i64::MAX, true).await;
    let rows = e.audit_rows().await;
    e.close().await;

    assert!(matches!(
        first.result,
        OperationResult::Accepted(SeenEffect::Changed { .. })
    ));
    assert!(matches!(
        second.result,
        OperationResult::Accepted(SeenEffect::Unchanged { .. })
    ));
    assert!(matches!(
        missing.result,
        OperationResult::Accepted(SeenEffect::NotFound { .. })
    ));
    assert_eq!(rows, email_set(user, 3));
}

/// If the audit insert fails, nothing commits: no is_read, counter, state,
/// journal or audit change.
#[tokio::test(flavor = "current_thread")]
async fn audit_failure_rolls_every_effect_back() {
    let Some(db) = Db::for_case("audit_failure_rolls_every_effect_back") else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let e = env(&db, "mail-auditfail").await;
    let mb = e.a.mailbox;
    // A trigger that refuses this fixture mailbox's audit rows only, so
    // concurrent suites on the shared database are unaffected. Identifiers are
    // server-issued integers.
    let (func, trig) = (
        format!("t214_refuse_audit_{mb}"),
        format!("t214_refuse_{mb}"),
    );
    e.owner
        .batch_execute(&format!(
            "CREATE FUNCTION {func}() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN IF NEW.mailbox_id = {mb} THEN RAISE EXCEPTION 'audit refused' USING ERRCODE = 'P0001'; END IF; \
             RETURN NEW; END $$; \
             CREATE TRIGGER {trig} BEFORE INSERT ON mailbox_audit_log FOR EACH ROW EXECUTE FUNCTION {func}();"
        ))
        .await
        .unwrap();
    let before = e.snapshot().await;
    let reply = e.run(mb, e.a.two_labels, true).await;
    let after = e.snapshot().await;
    let rows = e.audit_rows().await;
    e.owner
        .batch_execute(&format!(
            "DROP TRIGGER {trig} ON mailbox_audit_log; DROP FUNCTION {func}();"
        ))
        .await
        .unwrap();
    e.close().await;

    assert_eq!(reply.result, OperationResult::Rejected);
    assert!(
        matches!(&reply.rejection, Some(Rejection::Statement(f)) if f.sqlstate.as_deref() == Some("P0001")),
        "{:?}",
        reply.rejection
    );
    assert_eq!(after, before);
    assert!(rows.is_empty(), "{rows:?}");
}

/// A command naming a mailbox other than the authenticated one is refused
/// before any statement, and writes nothing.
#[tokio::test(flavor = "current_thread")]
async fn command_for_another_mailbox_is_refused_without_effect() {
    let Some(db) = Db::for_case("command_for_another_mailbox_is_refused_without_effect") else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let e = env(&db, "mail-scope").await;
    let before = e.snapshot().await;
    let reply = e.run(e.a.mailbox + 1_000_000, e.a.two_labels, true).await;
    let after = e.snapshot().await;
    let rows = e.audit_rows().await;
    e.close().await;

    assert_eq!(reply.result, OperationResult::Rejected);
    assert!(matches!(reply.rejection, Some(Rejection::Authority(_))));
    assert_eq!(after, before);
    assert!(rows.is_empty());
}

/// Review item 6 (+a): when the reducer reports a per-item error (it caught
/// the failure and rolled its subtransaction back), the command commits that
/// reducer result like Go does: the audit row is written, nothing else
/// changes, and the effect carries the reducer's own `notUpdated` entry.
#[tokio::test(flavor = "current_thread")]
async fn a_reducer_item_error_commits_the_reducers_not_updated_entry() {
    let Some(db) = Db::for_case("a_reducer_item_error_commits_the_reducers_not_updated_entry")
    else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let e = env(&db, "mail-itemerr").await;
    let msg = e.a.two_labels;
    let (func, trig) = (format!("t6_item_{msg}"), format!("t6_item_{msg}"));
    e.owner
        .batch_execute(&format!(
            "CREATE FUNCTION {func}() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN IF NEW.id = {msg} THEN RAISE EXCEPTION 'item refused' USING ERRCODE = 'P0001'; END IF; \
             RETURN NEW; END $$; \
             CREATE TRIGGER {trig} BEFORE UPDATE ON messages FOR EACH ROW EXECUTE FUNCTION {func}();"
        ))
        .await
        .unwrap();
    let before = e.snapshot().await;
    let reply = e.run(e.a.mailbox, msg, true).await;
    let after = e.snapshot().await;
    let rows = e.audit_rows().await;
    e.owner
        .batch_execute(&format!(
            "DROP TRIGGER {trig} ON messages; DROP FUNCTION {func}();"
        ))
        .await
        .unwrap();
    let user = e.a.user;
    e.close().await;

    assert_eq!(
        reply.result,
        OperationResult::Accepted(SeenEffect::NotUpdated {
            email_state: before.email_state,
            set_error: r#"{"type": "invalidArguments", "description": "Update failed"}"#.into(),
        })
    );
    assert_eq!(after, before);
    assert_eq!(rows, email_set(user, 1));
}

/// Review item 5 (owner decision 2026-10-29): the operation ID is recorded in
/// the `email_set` audit row in the command's own transaction, and the lookup
/// answers committed for it and absent for anything else — another
/// operation, or another mailbox's auth (R1). (A rolled-back command writes
/// no audit row: `audit_failure_rolls_every_effect_back`.)
#[tokio::test(flavor = "current_thread")]
async fn operation_lookup_answers_committed_or_absent() {
    let Some(db) = Db::for_case("operation_lookup_answers_committed_or_absent") else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let e = env(&db, "mail-lookup").await;
    let other = fixture::account(&e.owner, "mail-lookup-b")
        .await
        .expect("fixture b");
    let op = OperationId([0xA5; 16]);
    let reply = e.run_op(op, e.a.mailbox, e.a.two_labels, true).await;
    let committed = lookup_set_seen(&e.exec, &e.auth(), op).await;
    let never_ran = lookup_set_seen(&e.exec, &e.auth(), OperationId([0x01; 16])).await;
    let other_auth = MailboxAuthContext::from_authenticated_session(
        ActorId::new(other.user).unwrap(),
        MailboxId::new(other.mailbox).unwrap(),
        Generation(1),
    );
    let foreign = lookup_set_seen(&e.exec, &other_auth, op).await;
    let details: Vec<Option<String>> = e
        .owner
        .query_typed(
            "SELECT details->>'operation' FROM mailbox_audit_log WHERE mailbox_id = $1",
            &[(&e.a.mailbox, Type::INT8)],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    fixture::remove(&e.owner, &other).await.unwrap();
    e.close().await;

    assert!(matches!(reply.result, OperationResult::Accepted(_)));
    assert_eq!(details, vec![Some("a5".repeat(16))]);
    assert_eq!(committed.unwrap(), OperationLookup::Committed);
    assert_eq!(never_ran.unwrap(), OperationLookup::Absent);
    assert_eq!(foreign.unwrap(), OperationLookup::Absent);
}

#[tokio::test(flavor = "current_thread")]
async fn operation_lookup_does_not_disclose_another_actors_receipt() {
    let Some(db) = Db::for_case("operation_lookup_does_not_disclose_another_actors_receipt") else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let e = env(&db, "mail-lookup-actor").await;
    let other = fixture::account(&e.owner, "mail-lookup-other")
        .await
        .unwrap();
    let op = OperationId([0xB7; 16]);
    let reply = e.run_op(op, e.a.mailbox, e.a.two_labels, true).await;
    let other_actor = MailboxAuthContext::from_authenticated_session(
        ActorId::new(other.user).unwrap(),
        MailboxId::new(e.a.mailbox).unwrap(),
        Generation(1),
    );
    let result = lookup_set_seen(&e.exec, &other_actor, op).await;
    fixture::remove(&e.owner, &other).await.unwrap();
    e.close().await;

    assert!(matches!(reply.result, OperationResult::Accepted(_)));
    assert_eq!(result.unwrap(), OperationLookup::Absent);
}

#[tokio::test(flavor = "current_thread")]
async fn command_data_audit_and_notification_commit_or_roll_back_together() {
    let Some(db) = Db::for_case("command_data_audit_and_notification_commit_or_roll_back_together")
    else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let e = env(&db, "mail-command-atomic").await;
    let auth = e.auth();
    let message = e.a.two_labels;
    let channel = format!("tag:{}", e.a.mailbox);
    let mut listener = db.listen(&channel).await.unwrap();
    listener.drain(&e.owner).await.unwrap();
    let before = e.snapshot().await;
    let mut request = CommandEnvelope {
        operation: OperationId([0xc1; 16]),
        authority: auth.authority(),
        binding: accepted_contract(),
        payload_digest: Digest([9; 32]),
        command: (),
    };
    // A small independent command using the same public seam a family uses.
    let sql = "WITH changed AS (UPDATE messages SET is_read = TRUE \
        WHERE id = $4 AND mailbox_id = $1 RETURNING id), \
        audit AS (INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, details) \
        SELECT $1, $2, 'test_command', jsonb_build_object('operation', $3::text) FROM changed \
        RETURNING 1) SELECT app_notify($5::text, $3::text)::text FROM audit";
    let params = &[
        (
            &message as &(dyn tokio_postgres::types::ToSql + Sync),
            Type::INT8,
        ),
        (
            &channel as &(dyn tokio_postgres::types::ToSql + Sync),
            Type::TEXT,
        ),
    ];
    let rejected = setjoin_pg::run_command(
        &e.exec,
        &request,
        &auth,
        Instant::now() + Duration::from_secs(30),
        sql,
        params,
        |rows| {
            assert_eq!(
                rows.len(),
                1,
                "the command must execute before decoder failure"
            );
            Err::<(), _>(setjoin_pg::StatementFailure {
                hint: None,
                sqlstate: None,
                message: "invalid result".into(),
            })
        },
    )
    .await;
    let after_rejected = e.snapshot().await;
    let rejected_audit = e.audit_rows().await;
    let rejected_notifications = listener.drain(&e.owner).await.unwrap();

    request.operation = OperationId([0xc2; 16]);
    let accepted = setjoin_pg::run_command(
        &e.exec,
        &request,
        &auth,
        Instant::now() + Duration::from_secs(30),
        sql,
        params,
        |rows| Ok(rows.len()),
    )
    .await;
    let after_accepted = e.snapshot().await;
    let accepted_audit = e.audit_rows().await;
    let accepted_notifications = listener.drain(&e.owner).await.unwrap();
    let actor = e.a.user;
    e.close().await;

    assert!(
        matches!(
            rejected,
            setjoin_pg::CommandOutcome::RolledBack(Rejection::Body(_))
        ),
        "{rejected:?}"
    );
    assert_eq!(after_rejected, before);
    assert!(rejected_audit.is_empty());
    assert!(rejected_notifications.is_empty());
    assert!(
        matches!(accepted, setjoin_pg::CommandOutcome::Committed(1)),
        "{accepted:?}"
    );
    assert!(after_accepted.is_read[&message]);
    assert_eq!(
        accepted_audit,
        vec![(Some(actor), "test_command".into(), None)]
    );
    assert_eq!(accepted_notifications, vec!["c2".repeat(16)]);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitCut {
    BeforeCommit,
    AfterCommit,
}

/// A one-connection wire proxy that cuts exactly at COMMIT. For the
/// committed case, PostgreSQL's CommandComplete is intercepted before it
/// reaches the client; for the absent case, COMMIT never reaches PostgreSQL.
async fn commit_cut_proxy(db: &Db, cut: CommitCut) -> (String, JoinHandle<io::Result<CommitCut>>) {
    let dsn = db.app.as_deref().unwrap_or(&db.dsn);
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

async fn lost_commit_case(cut: CommitCut) {
    let Some(db) = Db::for_case("lost_commit_case") else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let mut e = env(&db, "mail-commit-loss").await;
    let recovery_exec = e.exec.clone();
    let (dsn, proxy) = commit_cut_proxy(&db, cut).await;
    e.exec = ScopedExecutor::from_dsn(&dsn, 1).unwrap();
    let operation = match cut {
        CommitCut::BeforeCommit => OperationId([0xd1; 16]),
        CommitCut::AfterCommit => OperationId([0xd2; 16]),
    };
    let reply = e.run_op(operation, e.a.mailbox, e.a.two_labels, true).await;
    let stopped_at = tokio::time::timeout(Duration::from_secs(10), proxy)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let lookup = lookup_set_seen(&recovery_exec, &e.auth(), operation).await;
    let snapshot = e.snapshot().await;
    let message = e.a.two_labels;
    e.close().await;

    assert_eq!(stopped_at, cut);
    assert_eq!(reply.result, OperationResult::Unknown, "{reply:?}");
    assert_eq!(reply.operation, operation);
    let expected = match cut {
        CommitCut::BeforeCommit => OperationLookup::Absent,
        CommitCut::AfterCommit => OperationLookup::Committed,
    };
    assert_eq!(lookup.unwrap(), expected);
    assert_eq!(snapshot.is_read[&message], cut == CommitCut::AfterCommit);
}

#[tokio::test(flavor = "current_thread")]
async fn lost_commit_before_send_returns_unknown_and_lookup_absent() {
    lost_commit_case(CommitCut::BeforeCommit).await;
}

#[tokio::test(flavor = "current_thread")]
async fn lost_commit_reply_returns_unknown_and_lookup_committed() {
    lost_commit_case(CommitCut::AfterCommit).await;
}
