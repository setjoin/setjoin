//! Golden recording/replay through the real front door and committed DB seam.
mod common;
#[allow(dead_code, unused_imports)]
mod jmap_email_oracle;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http_body_util::BodyExt;
use hyper::Request;
use p256::ecdsa::{signature::Signer, SigningKey};
use serde_json::{json, Value};
use setjoin_conformance::fixture::{self, Account};
use setjoin_conformance::golden;
use setjoin_conformance::harness::{BoxError, Db};
use setjoin_gateway::jmap::jwks::{jwk, Jwks};
use setjoin_gateway::jmap::{JmapCommands, JmapRoute};
use setjoin_gateway::{
    Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use tokio::net::TcpListener;
use tokio_postgres::{types::Type, Client};

/// The gateway's verifying key for a RustCrypto test signer (production
/// verifies ES256 with ring).
fn public(key: &SigningKey) -> setjoin_gateway::jmap::token::VerifyingKey {
    setjoin_gateway::jmap::token::VerifyingKey::from_sec1(
        key.verifying_key().to_sec1_point(false).as_bytes(),
    )
    .unwrap()
}

const KEY_ID: &str = "test-es256-1";
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const TOGGLES: [&str; 6] = [
    "feature.rust_mark_read",
    "feature.rust_inbox_list",
    "feature.cae_runtime",
    "feature.device_trust_enforcement",
    "feature.conditional_access",
    "feature.device_lockdown",
];
const RULES: &[&str] = &[
    "request accountId and inMailbox: fixture mailbox and tag IDs",
    "response accountId and ids: fixture mailbox and message IDs",
    "response sessionState: retain state counters; replace final user timestamp",
    "response date: timestamp; content-length: normalized body byte length",
    "database fixture IDs: stable names; notification channel: fixture mailbox",
    "audit id and occurred_at: generated ID and timestamp; mailbox and actor: fixture IDs",
];
const FOREIGN_INBOX_RULES: &[&str] = &[
    "request accountId and inMailbox: fixture mailbox and foreign tag IDs",
    "response accountId and ids: fixture mailbox and message IDs",
    "response sessionState: retain state counters; replace final user timestamp",
    "response date: timestamp; content-length: normalized body byte length",
    "database fixture IDs: stable names; notification channel: fixture mailbox",
    "audit id and occurred_at: generated ID and timestamp; mailbox and actor: fixture IDs",
    "observe the foreign mailbox, its row effects, audit and notifications",
];
const MARK_RULES: &[&str] = &[
    "request accountId and update key: fixture mailbox and message IDs",
    "response accountId and updated: fixture mailbox and message IDs",
    "response sessionState: retain state counters; replace final user timestamp",
    "response date: timestamp; content-length: normalized body byte length",
    "database fixture IDs: stable names; notification channel: fixture mailbox",
    "audit id and occurred_at: generated ID and timestamp; mailbox and actor: fixture IDs",
    "audit details.operation: generated 32-digit hexadecimal operation ID",
];
const FOREIGN_MARK_RULES: &[&str] = &[
    "request accountId and update key: fixture mailbox and foreign message IDs",
    "response accountId and notUpdated key: fixture mailbox and foreign message IDs",
    "response sessionState: retain state counters; replace final user timestamp",
    "response date: timestamp; content-length: normalized body byte length",
    "database fixture IDs: stable names; notification channel: fixture mailbox",
    "audit id and occurred_at: generated ID and timestamp; mailbox and actor: fixture IDs",
    "audit details.operation: generated 32-digit hexadecimal operation ID",
    "observe the foreign mailbox, its row effects, audit and notifications",
];
const INVALID_MARK_RULES: &[&str] = &[
    "request accountId and update key: fixture mailbox and message IDs",
    "response accountId and notUpdated key: fixture mailbox and message IDs",
    "response sessionState: retain state counters; replace final user timestamp",
    "response date: timestamp; content-length: normalized body byte length",
    "database fixture IDs: stable names; notification channel: fixture mailbox",
    "audit id and occurred_at: generated ID and timestamp; mailbox and actor: fixture IDs",
    "audit details.operation: generated 32-digit hexadecimal operation ID",
];
const REPEAT_MARK_RULES: &[&str] = &[
    "request accountId and update key: fixture mailbox and message IDs",
    "response accountId and updated: fixture mailbox and message IDs",
    "response sessionState: retain state counters; replace final user timestamp",
    "response date: timestamp; content-length: normalized body byte length",
    "database fixture IDs: stable names; notification channel: fixture mailbox",
    "audit id and occurred_at: generated ID and timestamp; mailbox and actor: fixture IDs",
    "audit details.operation: generated 32-digit hexadecimal operation ID",
    "both responses are normalized by the same rules",
];

const CHANGES_RULES: &[&str] = &[
    "request accountId: fixture mailbox ID",
    "response accountId, created, updated and destroyed: fixture mailbox and message IDs",
    "response sessionState: retain state counters; replace final user timestamp",
    "response date: timestamp; content-length: normalized body byte length",
    "database fixture IDs: stable names; notification channel: fixture mailbox",
    "audit id and occurred_at: generated ID and timestamp; mailbox and actor: fixture IDs",
    "seed: one mark-read through the reducer before the request, so the journal has a row",
];
const FOREIGN_CHANGES_RULES: &[&str] = &[
    "request accountId: foreign fixture mailbox ID",
    "response sessionState: retain state counters; replace final user timestamp",
    "response date: timestamp; content-length: normalized body byte length",
    "database fixture IDs: stable names; notification channel: fixture mailbox",
    "audit id and occurred_at: generated ID and timestamp; mailbox and actor: fixture IDs",
    "observe the foreign mailbox, its row effects, audit and notifications",
];
const INVALID_CHANGES_RULES: &[&str] = &[
    "request accountId: fixture mailbox ID",
    "response sessionState: retain state counters; replace final user timestamp",
    "response date: timestamp; content-length: normalized body byte length",
    "database fixture IDs: stable names; notification channel: fixture mailbox",
    "audit id and occurred_at: generated ID and timestamp; mailbox and actor: fixture IDs",
];

#[derive(Clone, Copy)]
enum Pilot {
    Changes,
    ChangesForeign,
    ChangesInvalid,
    ChangesStale,
    Inbox,
    InboxForeign,
    InboxInvalid,
    MarkRead,
    MarkReadForeign,
    MarkReadInvalid,
    MarkReadRepeat,
}

#[derive(Clone, Copy)]
enum Mutation {
    None,
    WrongStatus,
    Subject,
    NoAudit,
    NoNotify,
    DoubleBump,
    NoTenantFilter,
}

const ROW_RULES: &[&str] = &[
    "compare every column of mailbox-scoped mailboxes, messages, tags, message_tags, and jmap_changes_journal",
    "identify fixture mailbox, message and tag rows by stable names",
    "journal mailbox and entity IDs: fixture IDs; created_at: timestamp",
    "updated_at values in changed columns: timestamps, retaining the fact of change",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn email_changes_replays_frozen_go_recording_without_go() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("email_changes_replays_frozen_go_recording_without_go") else {
        return Ok(());
    };
    run_case(&db, Pilot::Changes, Mutation::None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn email_changes_replays_cross_tenant_denial_without_go() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("email_changes_replays_cross_tenant_denial_without_go") else {
        return Ok(());
    };
    run_case(&db, Pilot::ChangesForeign, Mutation::None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn email_changes_replays_malformed_state_without_go() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("email_changes_replays_malformed_state_without_go") else {
        return Ok(());
    };
    run_case(&db, Pilot::ChangesInvalid, Mutation::None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn email_changes_replays_a_state_ahead_of_the_server_without_go() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("email_changes_replays_a_state_ahead_of_the_server_without_go")
    else {
        return Ok(());
    };
    run_case(&db, Pilot::ChangesStale, Mutation::None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn email_changes_replay_reports_a_changed_rust_http_response() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("email_changes_replay_reports_a_changed_rust_http_response") else {
        return Ok(());
    };
    let diff = run_case(&db, Pilot::Changes, Mutation::WrongStatus)
        .await
        .expect_err("a changed status must fail the replay")
        .to_string();
    assert!(diff.contains("/response/status"), "{diff}");
    println!("MUTANT-REJECTED: POST /jmap Email/changes :: changed-status");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbox_list_replays_frozen_go_recording_without_go() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("inbox_list_replays_frozen_go_recording_without_go") else {
        return Ok(());
    };
    run_case(&db, Pilot::Inbox, Mutation::None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbox_list_replays_cross_tenant_denial_without_go() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("inbox_list_replays_cross_tenant_denial_without_go") else {
        return Ok(());
    };
    run_case(&db, Pilot::InboxForeign, Mutation::None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbox_list_replays_negative_limit_without_go() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("inbox_list_replays_negative_limit_without_go") else {
        return Ok(());
    };
    run_case(&db, Pilot::InboxInvalid, Mutation::None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mark_read_replays_frozen_go_recording_without_go() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("mark_read_replays_frozen_go_recording_without_go") else {
        return Ok(());
    };
    run_case(&db, Pilot::MarkRead, Mutation::None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mark_read_replays_cross_tenant_denial_without_go() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("mark_read_replays_cross_tenant_denial_without_go") else {
        return Ok(());
    };
    run_case(&db, Pilot::MarkReadForeign, Mutation::None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mark_read_replays_invalid_seen_without_go() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("mark_read_replays_invalid_seen_without_go") else {
        return Ok(());
    };
    run_case(&db, Pilot::MarkReadInvalid, Mutation::None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mark_read_replays_a_repeated_request_without_go() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("mark_read_replays_a_repeated_request_without_go") else {
        return Ok(());
    };
    run_case(&db, Pilot::MarkReadRepeat, Mutation::None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_reports_a_changed_rust_http_response() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("replay_reports_a_changed_rust_http_response") else {
        return Ok(());
    };
    let diff = run_case(&db, Pilot::Inbox, Mutation::WrongStatus)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        diff.contains("/response/status") && diff.contains("200") && diff.contains("418"),
        "{diff}"
    );
    println!("MUTANT-REJECTED: POST /jmap Email/query :: changed-status");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mark_read_replay_rejects_a_changed_rust_status() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("mark_read_replay_rejects_a_changed_rust_status") else {
        return Ok(());
    };
    let diff = run_case(&db, Pilot::MarkRead, Mutation::WrongStatus)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        diff.contains("/response/status") && diff.contains("200") && diff.contains("418"),
        "{diff}"
    );
    println!("MUTANT-REJECTED: POST /jmap Email/set :: changed-status");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mark_read_replay_rejects_a_missing_audit() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("mark_read_replay_rejects_a_missing_audit") else {
        return Ok(());
    };
    let diff = run_case(&db, Pilot::MarkRead, Mutation::NoAudit)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        diff.contains("/audit/0") && diff.contains("<missing>"),
        "{diff}"
    );
    println!("MUTANT-REJECTED: POST /jmap Email/set :: no-audit");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mark_read_replay_rejects_a_missing_notification() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("mark_read_replay_rejects_a_missing_notification") else {
        return Ok(());
    };
    let diff = run_case(&db, Pilot::MarkRead, Mutation::NoNotify)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        diff.contains("/notify/0") && diff.contains("<missing>"),
        "{diff}"
    );
    println!("MUTANT-REJECTED: POST /jmap Email/set :: no-notify");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mark_read_replay_rejects_a_double_state_bump() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("mark_read_replay_rejects_a_double_state_bump") else {
        return Ok(());
    };
    let diff = run_case(&db, Pilot::MarkRead, Mutation::DoubleBump)
        .await
        .unwrap_err()
        .to_string();
    assert!(diff.contains("/effects/after/email_state"), "{diff}");
    println!("MUTANT-REJECTED: POST /jmap Email/set :: double-bump");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mark_read_replay_rejects_a_missing_tenant_filter() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("mark_read_replay_rejects_a_missing_tenant_filter") else {
        return Ok(());
    };
    let diff = run_case(&db, Pilot::MarkReadForeign, Mutation::NoTenantFilter)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        diff.contains("foreign_effects") && diff.contains("is_read"),
        "{diff}"
    );
    println!("MUTANT-REJECTED: POST /jmap Email/set :: no-tenant-filter");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_reports_an_unexpected_database_row_change() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("replay_reports_an_unexpected_database_row_change") else {
        return Ok(());
    };
    let diff = run_case(&db, Pilot::Inbox, Mutation::Subject)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        diff.contains("messages") && diff.contains("subject"),
        "{diff}"
    );
    Ok(())
}

async fn run_case(db: &Db, pilot: Pilot, mutation: Mutation) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let owner = db.connect().await?;
    let mut saved = Vec::new();
    for key in TOGGLES {
        let rows = owner
            .query_typed(
                "SELECT enabled FROM feature_toggles WHERE key = $1",
                &[(&key, Type::TEXT)],
            )
            .await?;
        saved.push((key, rows.first().map(|r| r.get::<_, bool>(0))));
    }
    let account = fixture::account(&owner, "recorded-inbox").await?;
    let foreign = if matches!(
        pilot,
        Pilot::InboxForeign | Pilot::MarkReadForeign | Pilot::ChangesForeign
    ) {
        match fixture::account(&owner, "recorded-foreign").await {
            Ok(account) => Some(account),
            Err(error) => {
                fixture::remove(&owner, &account).await?;
                return Err(error);
            }
        }
    } else {
        None
    };
    let mut mutant_schema = None;
    let result = match mutant_database(db, &owner, mutation).await {
        Ok(Some((mutant_db, schema))) => {
            mutant_schema = Some(schema);
            execute_case(
                &mutant_db,
                &owner,
                &account,
                foreign.as_ref(),
                pilot,
                mutation,
            )
            .await
        }
        Ok(None) => execute_case(db, &owner, &account, foreign.as_ref(), pilot, mutation).await,
        Err(error) => Err(error),
    };
    let mut cleanup = Vec::new();
    if let Some(schema) = mutant_schema {
        if let Err(error) = owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
        {
            cleanup.push(error.to_string());
        }
    }
    for (key, old) in saved {
        let r = match old {
            Some(value) => owner.query_typed("INSERT INTO feature_toggles (key, enabled) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET enabled = EXCLUDED.enabled", &[(&key, Type::TEXT), (&value, Type::BOOL)]).await,
            None => owner.query_typed("DELETE FROM feature_toggles WHERE key = $1", &[(&key, Type::TEXT)]).await,
        };
        if let Err(e) = r {
            cleanup.push(e.to_string());
        }
    }
    if let Err(e) = fixture::remove(&owner, &account).await {
        cleanup.push(e.to_string());
    }
    if let Some(foreign) = &foreign {
        if let Err(e) = fixture::remove(&owner, foreign).await {
            cleanup.push(e.to_string());
        }
    }
    if !cleanup.is_empty() {
        return Err(format!(
            "case result: {result:?}; cleanup failed: {}",
            cleanup.join("; ")
        )
        .into());
    }
    result
}

/// Resolve test-only mutant objects before public objects on the command
/// connection. The authoritative schema is unchanged and the application
/// credential remains the normal one. Cleanup drops this exact random schema.
async fn mutant_database(
    db: &Db,
    owner: &Client,
    mutation: Mutation,
) -> Result<Option<(Db, String)>, BoxError> {
    if !matches!(
        mutation,
        Mutation::NoAudit | Mutation::NoNotify | Mutation::DoubleBump | Mutation::NoTenantFilter
    ) {
        return Ok(None);
    }
    let id: String = owner
        .query_typed("SELECT replace(gen_random_uuid()::text, '-', '')", &[])
        .await?[0]
        .get(0);
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid mutant schema id".into());
    }
    let schema = format!("gofree_oracle_mutant_{id}");
    let base = db.app.as_deref().unwrap_or(&db.dsn);
    if base.contains("options=") {
        return Err("mutant test DSN already specifies connection options".into());
    }
    let dsn = if base.starts_with("postgres://") || base.starts_with("postgresql://") {
        let separator = if base.contains('?') { '&' } else { '?' };
        format!("{base}{separator}options=-csearch_path%3D{schema}%2Cpublic")
    } else {
        format!("{base} options='-csearch_path={schema},public'")
    };
    let mut sql =
        format!("BEGIN; CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO PUBLIC; ");
    if matches!(mutation, Mutation::NoAudit) {
        sql.push_str(&format!(
            "CREATE VIEW {schema}.mailbox_audit_log AS SELECT * FROM public.mailbox_audit_log WHERE FALSE; \
             CREATE FUNCTION {schema}.discard_audit() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN RETURN NEW; END $$; \
             CREATE TRIGGER discard_audit INSTEAD OF INSERT ON {schema}.mailbox_audit_log \
             FOR EACH ROW EXECUTE FUNCTION {schema}.discard_audit(); \
             GRANT SELECT, INSERT ON {schema}.mailbox_audit_log TO PUBLIC; "
        ));
    } else {
        let row = owner.query_typed("SELECT pg_get_functiondef('public.jmap_email_set_update(bigint,jsonb)'::regprocedure)", &[]).await?;
        let mut definition: String = row[0].get(0);
        replace_mutant_once(
            &mut definition,
            "CREATE OR REPLACE FUNCTION public.jmap_email_set_update(",
            &format!("CREATE OR REPLACE FUNCTION {schema}.jmap_email_set_update("),
        )?;
        if matches!(mutation, Mutation::NoNotify) {
            replace_mutant_once(&mut definition,
                "PERFORM app_notify('tag:' || p_mailbox_id, json_build_object(\n      'event', 'state_change', 'tag_id', NULL, 'state', v_new_state)::TEXT);",
                "NULL;")?;
        } else if matches!(mutation, Mutation::DoubleBump) {
            replace_mutant_once(&mut definition,
                "v_new_state := bump_email_state(p_mailbox_id);",
                "v_new_state := bump_email_state(p_mailbox_id); PERFORM bump_email_state(p_mailbox_id);")?;
        } else {
            // Expose an owner-backed view only in this disposable mutant schema
            // so the application predicate is tested independently of RLS.
            sql.push_str(&format!(
                "CREATE VIEW {schema}.messages AS SELECT * FROM public.messages; \
                GRANT SELECT, UPDATE ON {schema}.messages TO PUBLIC; "
            ));
            replace_mutant_once(
                &mut definition,
                "FROM messages WHERE id = v_id AND mailbox_id = p_mailbox_id FOR UPDATE;",
                "FROM messages WHERE id = v_id FOR UPDATE;",
            )?;
            replace_mutant_once(&mut definition,
                "WHERE id = v_id AND mailbox_id = p_mailbox_id\n          RETURNING is_read INTO v_new_read;",
                "WHERE id = v_id\n          RETURNING is_read INTO v_new_read;")?;
        }
        sql.push_str(&definition);
        sql.push_str("; ");
    }
    sql.push_str("COMMIT;");
    if let Err(error) = owner.batch_execute(&sql).await {
        let _ = owner.batch_execute("ROLLBACK").await;
        return Err(error.into());
    }
    Ok(Some((
        Db {
            dsn: db.dsn.clone(),
            direct: db.direct.clone(),
            app: Some(dsn),
        },
        schema,
    )))
}

fn replace_mutant_once(text: &mut String, from: &str, to: &str) -> Result<(), BoxError> {
    if text.matches(from).count() != 1 {
        return Err(format!("mutant source does not contain exactly one {from:?}").into());
    }
    *text = text.replacen(from, to, 1);
    Ok(())
}

struct WrongStatus(JmapRoute);

impl Intercept for WrongStatus {
    fn matches(&self, request: &Request<Body>) -> bool {
        self.0.matches(request)
    }
    fn handle(
        &self,
        request: Request<Body>,
        context: RequestContext,
    ) -> BoxFuture<hyper::Response<Body>> {
        let response = self.0.handle(request, context);
        Box::pin(async move {
            let mut response = response.await;
            *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            response
        })
    }
}

async fn execute_case(
    db: &Db,
    owner: &Client,
    account: &Account,
    foreign: Option<&Account>,
    pilot: Pilot,
    mutation: Mutation,
) -> Result<(), BoxError> {
    let recording = std::env::var("GOFREE_RECORD_UPSTREAM")
        .ok()
        .filter(|s| !s.is_empty());
    if !matches!(mutation, Mutation::None) && recording.is_some() {
        return Err("cannot record a mutant".into());
    }
    let (flag, route, case, method, rules) = match pilot {
        Pilot::Changes => (
            "",
            "POST /jmap Email/changes",
            "email-changes",
            "Email/changes",
            CHANGES_RULES,
        ),
        Pilot::ChangesForeign => (
            "",
            "POST /jmap Email/changes",
            "email-changes-cross-tenant",
            "error",
            FOREIGN_CHANGES_RULES,
        ),
        Pilot::ChangesInvalid => (
            "",
            "POST /jmap Email/changes",
            "email-changes-malformed-state",
            "error",
            INVALID_CHANGES_RULES,
        ),
        Pilot::ChangesStale => (
            "",
            "POST /jmap Email/changes",
            "email-changes-state-ahead",
            "error",
            INVALID_CHANGES_RULES,
        ),
        Pilot::Inbox => (
            "feature.rust_inbox_list",
            "POST /jmap Email/query",
            "inbox-list",
            "Email/query",
            RULES,
        ),
        Pilot::InboxForeign => (
            "feature.rust_inbox_list",
            "POST /jmap Email/query",
            "inbox-list-cross-tenant",
            "Email/query",
            FOREIGN_INBOX_RULES,
        ),
        Pilot::InboxInvalid => (
            "feature.rust_inbox_list",
            "POST /jmap Email/query",
            "inbox-list-invalid-limit",
            "Email/query",
            RULES,
        ),
        Pilot::MarkRead => (
            "feature.rust_mark_read",
            "POST /jmap Email/set",
            "mark-read",
            "Email/set",
            MARK_RULES,
        ),
        Pilot::MarkReadForeign => (
            "feature.rust_mark_read",
            "POST /jmap Email/set",
            "mark-read-cross-tenant",
            "Email/set",
            FOREIGN_MARK_RULES,
        ),
        Pilot::MarkReadInvalid => (
            "feature.rust_mark_read",
            "POST /jmap Email/set",
            "mark-read-invalid-seen",
            "Email/set",
            INVALID_MARK_RULES,
        ),
        Pilot::MarkReadRepeat => (
            "feature.rust_mark_read",
            "POST /jmap Email/set",
            "mark-read-repeat",
            "Email/set",
            REPEAT_MARK_RULES,
        ),
    };
    for key in TOGGLES {
        let enabled = recording.is_none() && key == flag;
        owner.query_typed("INSERT INTO feature_toggles (key, enabled) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET enabled = EXCLUDED.enabled", &[(&key, Type::TEXT), (&enabled, Type::BOOL)]).await?;
    }
    let key = SigningKey::from_slice(&[0x11; 32])?;
    let doc = json!({"keys": [jwk(KEY_ID, &public(&key))]})
        .to_string()
        .into_bytes();
    let keys = Jwks::with_fetch(Box::new(move || {
        let doc = doc.clone();
        Box::pin(async move { Ok(doc) })
    }));
    let exec =
        ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).map_err(|e| e.0)?;
    let route_handler = JmapRoute(Arc::new(JmapCommands {
        services: None,
        worker: None,
        denylist: None,
        exec,
        keys,
        issuer: "mailserver".into(),
    }));
    let routes = if recording.is_some() {
        // Recording: every request goes to frozen Go, none is served by Rust.
        RouteTable::proxy_all()
    } else if matches!(mutation, Mutation::WrongStatus) {
        RouteTable::proxy_all().with(WrongStatus(route_handler))
    } else {
        RouteTable::proxy_all().with(route_handler)
    };
    let upstream = recording.as_deref().map(str::parse).transpose()?;
    let gateway = Gateway::new(
        Config {
            upstream,
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        routes,
    )?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(gateway.serve(listener));

    if matches!(pilot, Pilot::Changes) {
        // Seed one journal row through the real reducer (both oracles see it).
        owner
            .query_typed(
                "SELECT jmap_email_set_update($1, jsonb_build_object($2::bigint::text, '{\"keywords\":{\"$seen\":true}}'::jsonb))",
                &[(&account.mailbox, Type::INT8), (&account.two_labels, Type::INT8)],
            )
            .await?;
    }
    let before = snapshot(owner, account).await?;
    let rows_before = rows(owner, account).await?;
    let foreign_before = if let Some(other) = foreign {
        Some((snapshot(owner, other).await?, rows(owner, other).await?))
    } else {
        None
    };
    let mut notifications = db.listen(&format!("tag:{}", account.mailbox)).await?;
    notifications.drain(owner).await?;
    let mut foreign_notifications = if let Some(other) = foreign {
        let mut listener = db.listen(&format!("tag:{}", other.mailbox)).await?;
        listener.drain(owner).await?;
        Some(listener)
    } else {
        None
    };
    let message = foreign.map_or(account.two_labels, |other| other.two_labels);
    let changes_body = |account_id: i64, since: &str| {
        format!(
            r#"{{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/changes",{{"accountId":"{account_id}","sinceState":"{since}","maxChanges":50}},"0"]]}}"#
        )
    };
    let body = match pilot {
        Pilot::Changes => changes_body(account.mailbox, "0"),
        Pilot::ChangesForeign => changes_body(
            foreign.map_or(account.mailbox, |other| other.mailbox),
            "0",
        ),
        Pilot::ChangesInvalid => changes_body(account.mailbox, "not-a-state"),
        Pilot::ChangesStale => changes_body(account.mailbox, "999999"),
        Pilot::Inbox | Pilot::InboxForeign => format!(
            r#"{{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/query",{{"accountId":"{}","filter":{{"inMailbox":"{}"}},"limit":50}},"0"]]}}"#,
            account.mailbox,
            foreign.map_or(account.inbox, |other| other.inbox)
        ),
        Pilot::InboxInvalid => format!(
            r#"{{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/query",{{"accountId":"{}","filter":{{"inMailbox":"{}"}},"limit":-1}},"0"]]}}"#,
            account.mailbox, account.inbox
        ),
        Pilot::MarkRead | Pilot::MarkReadForeign | Pilot::MarkReadRepeat => format!(
            r#"{{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{{"accountId":"{}","create":null,"update":{{"{}":{{"keywords":{{"$seen":true}}}}}},"destroy":null}},"0"]]}}"#,
            account.mailbox, message
        ),
        Pilot::MarkReadInvalid => format!(
            r#"{{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{{"accountId":"{}","create":null,"update":{{"{}":{{"keywords":{{"$seen":""}}}}}},"destroy":null}},"0"]]}}"#,
            account.mailbox, message
        ),
    };
    let token = token(&key, account.user);
    let request = || {
        Request::post("/jmap")
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("x-request-id", "gofree-t2-golden")
            .body(common::full(body.clone()))
    };
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
    let connection = tokio::spawn(async move {
        let _ = conn.await;
    });
    let first_response = if matches!(pilot, Pilot::MarkReadRepeat) {
        sender.ready().await?;
        let response = sender.send_request(request()?).await?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await?.to_bytes();
        let raw = std::str::from_utf8(&bytes)?;
        let body = normalize_body(raw, account, foreign, pilot)?;
        Some(
            json!({"status": status, "headers": normalize_headers(&headers, raw.len(), body.len())?, "body": body}),
        )
    } else {
        None
    };
    sender.ready().await?;
    let response = sender.send_request(request()?).await?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let response_body = response.into_body().collect().await?.to_bytes();
    let response_body = std::str::from_utf8(&response_body)?;
    let normalized_body = normalize_body(response_body, account, foreign, pilot).map_err(|e| {
        format!("response {status} cannot be normalized: {e}; body: {response_body}")
    })?;
    let normalized_headers =
        normalize_headers(&headers, response_body.len(), normalized_body.len())?;
    if matches!(mutation, Mutation::Subject) {
        owner
            .query_typed(
                "UPDATE messages SET subject = $1 WHERE mailbox_id = $2 AND id = $3",
                &[
                    (&"oracle-mutant", Type::TEXT),
                    (&account.mailbox, Type::INT8),
                    (&account.two_labels, Type::INT8),
                ],
            )
            .await?;
    }
    let after = snapshot(owner, account).await?;
    let rows_after = rows(owner, account).await?;
    let row_effects = row_diff(&rows_before, &rows_after, account)?;
    let notify: Vec<Value> = notifications
        .drain(owner)
        .await?
        .into_iter()
        .map(|payload| json!({"channel":"tag:<mailbox>", "payload":payload}))
        .collect();
    let audit = audit_rows(owner, account).await?;
    let foreign_effects = if let (Some(other), Some((before, rows_before)), Some(listener)) =
        (foreign, foreign_before, foreign_notifications.as_mut())
    {
        let after = snapshot(owner, other).await?;
        let rows_after = rows(owner, other).await?;
        let notify: Vec<Value> = listener
            .drain(owner)
            .await?
            .into_iter()
            .map(|payload| json!({"channel":"tag:<foreign-mailbox>", "payload":payload}))
            .collect();
        Some(json!({"before":before, "after":after,
            "rows":row_diff(&rows_before, &rows_after, other)?,
            "audit":audit_rows(owner, other).await?, "notify":notify}))
    } else {
        None
    };
    connection.abort();
    server.abort();

    let request_body: Value = serde_json::from_str(&body)?;
    let account_placeholder = if matches!(pilot, Pilot::ChangesForeign) {
        "<foreign-mailbox>"
    } else {
        "<mailbox>"
    };
    let mut request_rules = vec![
        json!({"field":"/methodCalls/0/1/accountId", "kind":"id", "placeholder":account_placeholder}),
    ];
    if matches!(
        pilot,
        Pilot::Inbox | Pilot::InboxForeign | Pilot::InboxInvalid
    ) {
        let placeholder = if foreign.is_some() {
            "<foreign-inbox>"
        } else {
            "<inbox>"
        };
        request_rules.push(json!({"field":"/methodCalls/0/1/filter/inMailbox", "kind":"id", "placeholder":placeholder}));
    }
    let mut normalized_request = golden::normalize(&request_body, &Value::Array(request_rules))?;
    if matches!(
        pilot,
        Pilot::MarkRead | Pilot::MarkReadForeign | Pilot::MarkReadInvalid | Pilot::MarkReadRepeat
    ) {
        let update = normalized_request
            .pointer_mut("/methodCalls/0/1/update")
            .and_then(Value::as_object_mut)
            .ok_or("missing update")?;
        let patch = update
            .remove(&message.to_string())
            .ok_or("missing fixture message")?;
        update.insert(
            if foreign.is_some() {
                "<foreign-message>"
            } else {
                "<two-labels>"
            }
            .into(),
            patch,
        );
    }
    let mut observed = json!({
        "request": {"method":"POST", "path":"/jmap", "headers": {
            "host":"mail.test", "origin":"http://mail.test", "content-type":"application/json",
            "authorization":"Bearer <fixture-token>", "x-request-id":"gofree-t2-golden"
        }, "body":normalized_request},
        "response": {"status":status, "headers":normalized_headers, "body":normalized_body},
        "effects": {"before":before, "after":after}, "audit":audit,
        "notify":notify,
    });
    if let Some(effects) = foreign_effects {
        observed["foreign_effects"] = effects;
    }
    if let Some(first) = first_response {
        observed["first_response"] = first;
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../tests/conformance/jmap/goldens/{case}.json"));
    let row_case = format!("{case}-row-effects");
    let row_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../tests/conformance/jmap/goldens/{row_case}.json"
    ));
    if recording.is_some() {
        if status != 200 || !response_body.contains(&format!("\"{method}\"")) {
            return Err(format!(
                "refusing to record unexpected Go response {status}: {response_body}"
            )
            .into());
        }
        let source = std::env::var("GOFREE_GO_SOURCE")?;
        if std::env::var("GOFREE_RECORD_EFFECTS").as_deref() == Ok("1") {
            let document = json!({"format":1, "route":route, "case":row_case, "go_source":source,
                "normalization":ROW_RULES, "effects":row_effects});
            golden::record(&row_path, &document)?;
        } else {
            let document = json!({"format":1, "route":route, "case":case, "go_source":source,
                "normalization":rules, "observation":observed});
            golden::record(&path, &document)?;
        }
    } else {
        let document: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        if document["format"] != 1
            || document["route"] != route
            || document["case"] != case
            || document["normalization"] != json!(rules)
        {
            return Err("golden metadata or normalization rules do not match the case".into());
        }
        let divergences_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/conformance/jmap/divergences.json");
        let divergences: Value = serde_json::from_slice(&std::fs::read(divergences_path)?)?;
        golden::compare_reviewed(
            route,
            case,
            &document["observation"],
            &observed,
            &divergences,
        )?;
        let row_document: Value = serde_json::from_slice(&std::fs::read(row_path)?)?;
        if row_document["format"] != 1
            || row_document["route"] != route
            || row_document["case"] != row_case
            || row_document["normalization"] != json!(ROW_RULES)
        {
            return Err(
                "row-effects golden metadata or normalization rules do not match the case".into(),
            );
        }
        golden::compare_reviewed(
            route,
            &row_case,
            &row_document["effects"],
            &row_effects,
            &divergences,
        )?;
        println!("GOLDEN-REPLAY: {route} :: {case}");
    }
    Ok(())
}

fn token(key: &SigningKey, user: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = json!({"uid":user, "email":"x@test", "typ":"access", "jti":format!("jti-{user}"),
        "fam":format!("fam-{user}"), "iss":"mailserver", "aud":["mailserver-gateway"], "iat":now-10, "exp":now+600});
    let header = json!({"alg":"ES256", "kid":KEY_ID, "typ":"JWT"});
    let h = URL_SAFE_NO_PAD.encode(header.to_string());
    let p = URL_SAFE_NO_PAD.encode(claims.to_string());
    let sig: p256::ecdsa::Signature = key.sign(format!("{h}.{p}").as_bytes());
    format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

fn replace_once(body: &mut String, from: &str, to: &str) -> Result<(), BoxError> {
    let Some(at) = body.find(from) else {
        return Err(format!("normalization input missing {from}").into());
    };
    body.replace_range(at..at + from.len(), to);
    Ok(())
}

fn normalize_body(
    body: &str,
    a: &Account,
    foreign: Option<&Account>,
    pilot: Pilot,
) -> Result<String, BoxError> {
    let parsed: Value = serde_json::from_str(body)?;
    let state = parsed["sessionState"]
        .as_str()
        .ok_or("missing sessionState")?;
    let (counters, timestamp) = state.rsplit_once('-').ok_or("malformed sessionState")?;
    timestamp.parse::<u64>()?;
    let mut out = body.to_owned();
    replace_once(
        &mut out,
        &format!("\"sessionState\":\"{state}\""),
        &format!("\"sessionState\":\"{counters}-<timestamp>\""),
    )?;
    if matches!(
        pilot,
        Pilot::Changes | Pilot::ChangesForeign | Pilot::ChangesInvalid | Pilot::ChangesStale
    ) {
        // Method errors carry no accountId; a delta carries three id lists.
        if parsed["methodResponses"][0][0] == "Email/changes" {
            replace_once(
                &mut out,
                &format!("\"accountId\":\"{}\"", a.mailbox),
                "\"accountId\":\"<mailbox>\"",
            )?;
            for field in ["created", "updated", "destroyed"] {
                let ids = parsed["methodResponses"][0][1][field]
                    .as_array()
                    .ok_or("missing delta list")?;
                let named: Vec<Value> = ids
                    .iter()
                    .map(|id| {
                        if id.as_i64() == Some(a.two_labels) {
                            json!("<two-labels>")
                        } else if id.as_i64() == Some(a.inbox_only) {
                            json!("<inbox-only>")
                        } else {
                            id.clone()
                        }
                    })
                    .collect();
                replace_once(
                    &mut out,
                    &format!("\"{field}\":{}", Value::Array(ids.clone())),
                    &format!("\"{field}\":{}", Value::Array(named)),
                )?;
            }
        }
        return Ok(out);
    }
    replace_once(
        &mut out,
        &format!("\"accountId\":\"{}\"", a.mailbox),
        "\"accountId\":\"<mailbox>\"",
    )?;
    let field = match pilot {
        Pilot::Inbox | Pilot::InboxForeign | Pilot::InboxInvalid => "ids",
        Pilot::Changes | Pilot::ChangesForeign | Pilot::ChangesInvalid | Pilot::ChangesStale => {
            unreachable!("changes responses are normalized above")
        }
        Pilot::MarkRead
        | Pilot::MarkReadForeign
        | Pilot::MarkReadInvalid
        | Pilot::MarkReadRepeat => "updated",
    };
    let ids = parsed["methodResponses"][0][1][field]
        .as_array()
        .ok_or("missing ids")?;
    let normalized: Vec<Value> = ids
        .iter()
        .map(|id| {
            if id.as_str() == Some(&a.two_labels.to_string()) || id.as_i64() == Some(a.two_labels) {
                json!("<two-labels>")
            } else if foreign.is_some_and(|other| {
                id.as_str() == Some(&other.two_labels.to_string())
                    || id.as_i64() == Some(other.two_labels)
            }) {
                json!("<foreign-message>")
            } else if id.as_str() == Some(&a.inbox_only.to_string())
                || id.as_i64() == Some(a.inbox_only)
            {
                json!("<inbox-only>")
            } else {
                id.clone()
            }
        })
        .collect();
    replace_once(
        &mut out,
        &format!("\"{field}\":{}", Value::Array(ids.clone())),
        &format!("\"{field}\":{}", Value::Array(normalized)),
    )?;
    if let (Pilot::MarkReadForeign, Some(other)) = (pilot, foreign) {
        let field = format!("\"{}\":", other.two_labels);
        if out.contains(&field) {
            replace_once(&mut out, &field, "\"<foreign-message>\":")?;
        }
    }
    if matches!(pilot, Pilot::MarkReadInvalid) {
        replace_once(
            &mut out,
            &format!("\"{}\":", a.two_labels),
            "\"<two-labels>\":",
        )?;
    }
    Ok(out)
}

fn normalize_headers(
    headers: &hyper::HeaderMap,
    raw_len: usize,
    normalized_len: usize,
) -> Result<Value, BoxError> {
    let mut result = serde_json::Map::new();
    for name in headers.keys() {
        let mut values = Vec::new();
        for value in headers.get_all(name) {
            let value = value.to_str()?;
            values.push(if name == "date" {
                "<timestamp>".to_owned()
            } else if name == "content-length" {
                if value.parse::<usize>()? != raw_len {
                    return Err("incorrect response content-length".into());
                }
                normalized_len.to_string()
            } else {
                value.to_owned()
            });
        }
        result.insert(name.to_string(), json!(values));
    }
    Ok(Value::Object(result))
}

fn message_id(a: &Account, id: i64) -> Value {
    if id == a.two_labels {
        json!("<two-labels>")
    } else if id == a.inbox_only {
        json!("<inbox-only>")
    } else {
        json!(id)
    }
}

type Rows = BTreeMap<String, BTreeMap<String, Value>>;

/// Capture all columns, scoped to the authenticated fixture mailbox. Only
/// changed columns (or complete inserted/deleted rows) enter the golden.
async fn rows(c: &Client, a: &Account) -> Result<Rows, BoxError> {
    let p = [(
        &a.mailbox as &(dyn tokio_postgres::types::ToSql + Sync),
        Type::INT8,
    )];
    let mut tables = Rows::new();
    let mailbox = c
        .query_typed(
            "SELECT to_jsonb(m)::text FROM mailboxes m WHERE m.id = $1",
            &p,
        )
        .await?;
    let mut mailbox_rows = BTreeMap::new();
    for row in mailbox {
        mailbox_rows.insert(
            "<mailbox>".into(),
            serde_json::from_str(&row.get::<_, String>(0))?,
        );
    }
    tables.insert("mailboxes".into(), mailbox_rows);

    let mut tag_names = BTreeMap::new();
    let mut tag_rows = BTreeMap::new();
    for row in c
        .query_typed(
            "SELECT id, name, to_jsonb(t)::text FROM tags t WHERE mailbox_id = $1",
            &p,
        )
        .await?
    {
        let id: i64 = row.get(0);
        let name: String = row.get(1);
        tag_names.insert(id, name.clone());
        tag_rows.insert(name, serde_json::from_str(&row.get::<_, String>(2))?);
    }
    tables.insert("tags".into(), tag_rows);

    let mut messages = BTreeMap::new();
    for row in c
        .query_typed(
            "SELECT id, to_jsonb(m)::text FROM messages m WHERE mailbox_id = $1",
            &p,
        )
        .await?
    {
        let id: i64 = row.get(0);
        messages.insert(
            row_message(a, id),
            serde_json::from_str(&row.get::<_, String>(1))?,
        );
    }
    tables.insert("messages".into(), messages);

    let mut memberships = BTreeMap::new();
    for row in c
        .query_typed(
            "SELECT mt.message_id, mt.tag_id, to_jsonb(mt)::text FROM message_tags mt \
         JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at \
         WHERE m.mailbox_id = $1",
            &p,
        )
        .await?
    {
        let message: i64 = row.get(0);
        let tag: i64 = row.get(1);
        let tag = tag_names
            .get(&tag)
            .cloned()
            .unwrap_or_else(|| format!("unexpected-tag-{tag}"));
        memberships.insert(
            format!("{}:{tag}", row_message(a, message)),
            serde_json::from_str(&row.get::<_, String>(2))?,
        );
    }
    tables.insert("message_tags".into(), memberships);

    let mut journal = BTreeMap::new();
    for row in c.query_typed("SELECT datatype, state_seq, entity_id, to_jsonb(j)::text FROM jmap_changes_journal j WHERE mailbox_id = $1", &p).await? {
        let datatype: String = row.get(0);
        let seq: i64 = row.get(1);
        let entity: i64 = row.get(2);
        journal.insert(format!("{datatype}:{seq}:{}", row_message(a, entity)), serde_json::from_str(&row.get::<_, String>(3))?);
    }
    tables.insert("jmap_changes_journal".into(), journal);
    Ok(tables)
}

fn row_message(a: &Account, id: i64) -> String {
    if id == a.two_labels {
        "<two-labels>".into()
    } else if id == a.inbox_only {
        "<inbox-only>".into()
    } else {
        format!("unexpected-message-{id}")
    }
}

fn row_diff(before: &Rows, after: &Rows, a: &Account) -> Result<Value, BoxError> {
    let mut result = Vec::new();
    for table in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
        let empty = BTreeMap::new();
        let left = before.get(table).unwrap_or(&empty);
        let right = after.get(table).unwrap_or(&empty);
        for key in left.keys().chain(right.keys()).collect::<BTreeSet<_>>() {
            match (left.get(key), right.get(key)) {
                (Some(old), Some(new)) => {
                    let old = old.as_object().ok_or("snapshot row is not an object")?;
                    let new = new.as_object().ok_or("snapshot row is not an object")?;
                    let mut columns = serde_json::Map::new();
                    for name in old.keys().chain(new.keys()).collect::<BTreeSet<_>>() {
                        let l = old.get(name);
                        let r = new.get(name);
                        if l != r {
                            let value = |v: Option<&Value>| -> Value {
                                match (name.as_str(), v) {
                                    ("updated_at", Some(Value::String(_))) => json!("<timestamp>"),
                                    (_, Some(v)) => v.clone(),
                                    (_, None) => json!({"missing":true}),
                                }
                            };
                            columns.insert(name.clone(), json!({"before":value(l), "after":value(r)}));
                        }
                    }
                    if !columns.is_empty() { result.push(json!({"table":table, "row":key, "change":"update", "columns":columns})); }
                }
                (None, Some(row)) => result.push(json!({"table":table, "row":key, "change":"insert", "after":normalize_new_row(table, row, a)?})),
                (Some(row), None) => result.push(json!({"table":table, "row":key, "change":"delete", "before":normalize_new_row(table, row, a)?})),
                (None, None) => unreachable!(),
            }
        }
    }
    Ok(Value::Array(result))
}

fn normalize_new_row(table: &str, row: &Value, a: &Account) -> Result<Value, BoxError> {
    let mut row = row.clone();
    if table == "jmap_changes_journal" {
        if row["mailbox_id"].as_i64() != Some(a.mailbox) {
            return Err("journal mailbox differs from fixture".into());
        }
        let entity = row["entity_id"].as_i64().ok_or("invalid journal entity")?;
        if !row["created_at"].is_string() {
            return Err("invalid journal timestamp".into());
        }
        row["mailbox_id"] = json!("<mailbox>");
        row["entity_id"] = message_id(a, entity);
        row["created_at"] = json!("<timestamp>");
    }
    Ok(row)
}

async fn snapshot(c: &Client, a: &Account) -> Result<Value, BoxError> {
    let before = fixture::snapshot(c, a.mailbox).await?;
    let rows = c
        .query_typed(
            "SELECT id, name FROM tags WHERE mailbox_id = $1 ORDER BY name",
            &[(&a.mailbox, Type::INT8)],
        )
        .await?;
    let mut tags = serde_json::Map::new();
    for row in rows {
        let id: i64 = row.get(0);
        let name: String = row.get(1);
        let (unread, state) = before.tags[&id];
        tags.insert(name, json!({"unread":unread, "state":state}));
    }
    let messages: Vec<Value> = before
        .is_read
        .iter()
        .map(|(id, read)| json!({"id":message_id(a, *id), "is_read":read}))
        .collect();
    let journal: Vec<Value> = before.journal.iter().map(|r| json!({"datatype":r.datatype, "state_seq":r.state_seq, "entity_id":message_id(a, r.entity_id), "op":r.op})).collect();
    Ok(
        json!({"messages":messages, "tags":tags, "email_state":before.email_state, "journal":journal}),
    )
}

async fn audit_rows(c: &Client, a: &Account) -> Result<Value, BoxError> {
    let rows = c.query_typed("SELECT id, occurred_at::text, mailbox_id, actor_user_id, action, message_id, details::text FROM mailbox_audit_log WHERE mailbox_id = $1 ORDER BY id", &[(&a.mailbox, Type::INT8)]).await?;
    let mut result = Vec::new();
    for row in rows {
        let id: i64 = row.get(0);
        let time: String = row.get(1);
        let mailbox: i64 = row.get(2);
        let actor: Option<i64> = row.get(3);
        let action: String = row.get(4);
        let message: Option<i64> = row.get(5);
        let details: Option<String> = row.get(6);
        if mailbox != a.mailbox || actor != Some(a.user) {
            return Err(
                format!("audit row has unexpected mailbox {mailbox} or actor {actor:?}").into(),
            );
        }
        let mut details: Value = match details {
            Some(value) => serde_json::from_str(&value)?,
            None => Value::Null,
        };
        if let Some(operation) = details.get_mut("operation") {
            let text = operation.as_str().ok_or("invalid audit operation ID")?;
            if text.len() != 32
                || !text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("invalid audit operation ID".into());
            }
            *operation = json!("<operation-id>");
        }
        result.push(
            json!({"id":id, "occurred_at":time, "mailbox_id":mailbox, "actor_user_id":actor,
            "action":action, "message_id":message, "details":details}),
        );
    }
    let mut rules = Vec::new();
    for (i, _) in result.iter().enumerate() {
        for (field, kind, placeholder) in [
            ("id", "id", "<audit-id>"),
            ("occurred_at", "timestamp", "<timestamp>"),
            ("mailbox_id", "id", "<mailbox>"),
            ("actor_user_id", "id", "<user>"),
        ] {
            rules.push(
                json!({"field":format!("/{i}/{field}"), "kind":kind, "placeholder":placeholder}),
            );
        }
    }
    Ok(golden::normalize(
        &Value::Array(result),
        &Value::Array(rules),
    )?)
}

// Cases of the shared email-method oracle (`jmap_email_oracle/cases.rs`) for
// the commands whose catalog suite also holds the pilot cases above: one
// suite replays from one test binary.
macro_rules! replay {
    ($name:ident, $case:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() -> Result<(), BoxError> {
            let Some(db) = Db::for_case(stringify!($name)) else {
                return Ok(());
            };
            jmap_email_oracle::run(&db, $case, jmap_email_oracle::Mutation::None).await
        }
    };
}

replay!(email_query_replays_a_text_search_without_go, "email-query-text");
replay!(email_query_replays_a_combined_filter_without_go, "email-query-combined-filter");
replay!(email_query_replays_cross_tenant_denial_without_go, "email-query-cross-tenant");
replay!(email_query_replays_a_foreign_tag_as_empty_without_go, "email-query-foreign-tag");
replay!(email_query_replays_clamped_paging_without_go, "email-query-clamped-paging");
replay!(email_query_replays_a_bad_date_filter_without_go, "email-query-bad-date");
replay!(email_set_replays_a_flag_update_without_go, "email-set-update-flag");
replay!(email_set_replays_a_repeated_update_without_go, "email-set-update-repeat");
replay!(email_set_replays_a_label_move_without_go, "email-set-move-label");
replay!(email_set_replays_a_destroy_without_go, "email-set-destroy");
replay!(email_set_replays_cross_tenant_denial_without_go, "email-set-cross-tenant");
replay!(email_set_replays_a_foreign_tag_denial_without_go, "email-set-foreign-tag");
replay!(email_set_replays_an_invalid_keyword_without_go, "email-set-invalid-keyword");
replay!(email_set_replays_malformed_destroy_ids_without_go, "email-set-destroy-malformed");
