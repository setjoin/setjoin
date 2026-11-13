//! JMAP (#315/#317) HTTP/effect oracle: one case table and runner. Each case
//! sends one signed request through the real front door against a fresh
//! fixture (two when the case needs a foreign tenant) and compares the response
//! bytes, mailbox snapshots, audit rows, notifications and, per case, the
//! complete row effects with the checked-in recording from frozen Go. With
//! `GOFREE_RECORD_UPSTREAM` the same request goes to Go and the golden is
//! written (exclusive creation), see `server-rust/tests/conformance/jmap/README.md`.
pub mod cases;
pub mod scrub;
pub mod storage;
mod transfer;

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

pub use cases::{spec, Fx, Seed, Spec};
use scrub::{scrub, scrub_session_state, Names};

use crate::common;

const KEY_ID: &str = "test-es256-1";
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const TOGGLES: [&str; 15] = [
    "feature.client_recovery_receipts",
    "feature.rust_mark_read",
    "feature.rust_inbox_list",
    "feature.cae_runtime",
    "feature.device_trust_enforcement",
    "feature.conditional_access",
    "feature.device_lockdown",
    "feature.stale_nudges",
    "feature.shared_task_lists",
    "feature.biometric_unlock",
    "feature.windows_sso_unlock",
    "dengbao.sod_mode",
    "feature.offline_mail",
    "feature.connectivity_aware_sync",
    "feature.recall",
];
pub const ROW_RULES: &[&str] = &[
    "all columns of the declared mailbox-scoped tables before and after; only changed columns or whole inserted/deleted rows are kept",
    "fixture and generated IDs: stable names; timestamps: <timestamp>",
    "updated_at values in changed columns: timestamps, retaining the fact of change",
];
pub const RULES: &[&str] = &[
    "request and response IDs (mailbox, user, tags, messages): fixture names; messages created by the request: <new-message-N> in ID order",
    "response sessionState: retain state counters; replace final user timestamp",
    "response date: timestamp; content-length: normalized body byte length",
    "every timestamp in a body, row or audit: <timestamp>",
    "message_id, thread_id and raw_ref of fixture messages: fixed per fixture name before the request",
    "audit id and occurred_at: generated ID and timestamp; mailbox and actor: fixture IDs",
    "audit details.operation: generated 32-digit hexadecimal operation ID",
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    None,
    WrongStatus,
    PreprocessingOwner,
    NoNotify,
    NoRecallAudit,
    CommitBefore,
    CommitAfter,
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

fn public(key: &SigningKey) -> setjoin_gateway::jmap::token::VerifyingKey {
    setjoin_gateway::jmap::token::VerifyingKey::from_sec1(
        key.verifying_key().to_sec1_point(false).as_bytes(),
    )
    .unwrap()
}

fn token(key: &SigningKey, user: i64, native: bool, admin: bool) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut claims = json!({"uid":user, "email":"x@test", "typ":"access", "jti":format!("jti-{user}"),
        "fam":format!("fam-{user}"), "iss":"mailserver", "aud":["mailserver-gateway"], "iat":now-10, "exp":now+if native {60}else{600}});
    if native {
        claims["device"] = json!({"id":"gofree-jmap2-device","platform":"desktop","trust_tier":"managed","compliance_status":"compliant","wipe_requested":false});
    }
    if admin {
        claims["admin"] = json!(true);
        claims["perms"] = json!(["stale.signed.permission"]);
    }
    let header = json!({"alg":"ES256", "kid":KEY_ID, "typ":"JWT"});
    let h = URL_SAFE_NO_PAD.encode(header.to_string());
    let p = URL_SAFE_NO_PAD.encode(claims.to_string());
    let sig: p256::ecdsa::Signature = key.sign(format!("{h}.{p}").as_bytes());
    format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

pub async fn run(db: &Db, case: &str, mutation: Mutation) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let spec = spec(case);
    let owner = db.connect().await?;
    let mut saved = Vec::new();
    let continuity = if spec.route.contains("/jmap/recovery-raw") {
        Some(owner.query_typed("SELECT jsonb_build_object('continuity_last_wall_clock',continuity_last_wall_clock,'continuity_last_boot_epoch',continuity_last_boot_epoch,'continuity_last_boot_at',continuity_last_boot_at)::text FROM upgrade_control_state WHERE singleton",&[]).await?[0].get::<_,String>(0))
    } else {
        None
    };
    if continuity.is_some() {
        owner.batch_execute("UPDATE upgrade_control_state SET continuity_last_wall_clock=NULL,continuity_last_boot_epoch=NULL,continuity_last_boot_at=NULL WHERE singleton").await?;
    }
    let config_keys = vec![
        "brand_name",
        "brand_logo_url",
        "help_email",
        "apps_caps_strict",
    ];
    let config = owner
        .query_typed(
            "SELECT key,value::text FROM system_config WHERE key=ANY($1::text[])",
            &[(&config_keys, Type::TEXT_ARRAY)],
        )
        .await?;

    for key in TOGGLES {
        let rows = owner
            .query_typed(
                "SELECT enabled FROM feature_toggles WHERE key = $1",
                &[(&key, Type::TEXT)],
            )
            .await?;
        saved.push((key, rows.first().map(|r| r.get::<_, bool>(0))));
    }
    // Fixture IDs well above every counter, size and position a response carries.
    // Distinct ranges per table so a name never stands for two kinds of ID.
    for (sequence, floor) in [
        ("users", 1_000_000),
        ("mailboxes", 2_000_000),
        ("tags", 3_000_000),
        ("messages", 4_000_000),
        ("message_attachments", 5_000_000),
        ("domains", 6_000_000),
        ("user_devices", 7_000_000),
        ("devices", 8_000_000),
        ("offline_policies", 9_000_000),
        ("aliases", 10_000_000),
    ] {
        owner
            .batch_execute(&format!(
                "SELECT setval('{sequence}_id_seq', GREATEST((SELECT last_value FROM {sequence}_id_seq), {floor}))"
            ))
            .await?;
    }
    let fault = match spec.case {
        "identity-set-database-fault" => Some("jmap_identity_set_destroy(bigint,bigint[])"),
        "mailbox-set-database-fault" => Some("jmap_mailbox_set_create(bigint,jsonb)"),
        "mailbox-get-database-fault" => Some("jmap_mailbox_get(bigint,bigint[],text[])"),
        _ => None,
    };
    let definition = if let Some(function) = fault {
        let source: String = owner
            .query_typed(
                "SELECT pg_get_functiondef($1::text::regprocedure)",
                &[(&function, Type::TEXT)],
            )
            .await?[0]
            .get(0);
        let injected = source.replacen(
            "BEGIN",
            "BEGIN\nRAISE EXCEPTION 'injected database cancellation' USING ERRCODE='57014';",
            1,
        );
        if injected == source {
            return Err("could not inject reducer cancellation".into());
        }
        owner.batch_execute(&injected).await?;
        Some(source)
    } else {
        None
    };
    // deliver() allocates a message modseq from this database-wide sequence.
    // This runner owns the disposable DB and serializes fixtures: seed the
    // allocator rather than hiding a protocol-visible field from the oracle.
    owner
        .batch_execute("SELECT setval('imap_modseq_seq',1,false)")
        .await?;
    let mut fx = cases::fixture(&owner, &spec).await?;
    let mut mutant_schema = None;
    let result = match mutant_database(db, &owner, mutation).await {
        Ok(Some((mutant, schema))) => {
            mutant_schema = Some(schema);
            execute(&mutant, &owner, &mut fx, &spec, mutation).await
        }
        Ok(None) => execute(db, &owner, &mut fx, &spec, mutation).await,
        Err(error) => Err(error),
    };
    let mut cleanup = Vec::new();
    if let Some(definition) = definition {
        owner.batch_execute(&definition).await?;
    }

    if let Some(saved) = continuity {
        owner.query_typed("UPDATE upgrade_control_state SET continuity_last_wall_clock=($1::text::jsonb->>'continuity_last_wall_clock')::timestamptz,continuity_last_boot_epoch=($1::text::jsonb->>'continuity_last_boot_epoch')::uuid,continuity_last_boot_at=($1::text::jsonb->>'continuity_last_boot_at')::timestamptz WHERE singleton", &[(&saved,Type::TEXT)]).await?;
    }

    owner
        .query_typed(
            "DELETE FROM system_config WHERE key=ANY($1::text[])",
            &[(&config_keys, Type::TEXT_ARRAY)],
        )
        .await?;
    for row in config {
        let key: String = row.get(0);
        let value: String = row.get(1);
        owner
            .query_typed(
                "INSERT INTO system_config(key,value) VALUES ($1,$2::text::jsonb)",
                &[(&key, Type::TEXT), (&value, Type::TEXT)],
            )
            .await?;
    }

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
    if let Err(e) = cases::remove(&owner, &fx).await {
        cleanup.push(e.to_string());
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

/// Mutants exist only on this case's connections, never in public schema.
async fn mutant_database(
    db: &Db,
    owner: &Client,
    mutation: Mutation,
) -> Result<Option<(Db, String)>, BoxError> {
    if !matches!(mutation, Mutation::NoNotify | Mutation::NoRecallAudit) {
        return Ok(None);
    }
    let id: String = owner
        .query_typed("SELECT replace(gen_random_uuid()::text,'-','')", &[])
        .await?[0]
        .get(0);
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid mutant schema".into());
    }
    let schema = format!("gofree_jmap3_mutant_{id}");
    let scoped = |base: &str| -> Result<String, BoxError> {
        if base.contains("options=") {
            return Err("mutant DSN already has options".into());
        }
        if base.starts_with("postgres://") || base.starts_with("postgresql://") {
            let mut uri = url::Url::parse(base)?;
            uri.query_pairs_mut()
                .append_pair("options", &format!("-csearch_path={schema},public"));
            Ok(uri.to_string())
        } else {
            Ok(format!("{base} options='-csearch_path={schema},public'"))
        }
    };
    let mutant = Db {
        dsn: scoped(&db.dsn)?,
        direct: db.direct.clone(),
        app: Some(scoped(db.app.as_deref().unwrap_or(&db.dsn))?),
    };
    let mut sql =
        format!("BEGIN; CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO PUBLIC; ");
    if mutation == Mutation::NoNotify {
        sql.push_str(&format!("CREATE FUNCTION {schema}.app_notify(text,text) RETURNS void LANGUAGE plpgsql AS $$ BEGIN RETURN; END $$; "));
    } else {
        let mut definition:String=owner.query_typed("SELECT pg_get_functiondef('public.recall_message(text,bigint,bigint,text)'::regprocedure)",&[]).await?[0].get(0);
        let header = "CREATE OR REPLACE FUNCTION public.recall_message(";
        if definition.matches(header).count() != 1
            || definition.matches("INSERT INTO message_recalls (").count() != 1
        {
            return Err("recall audit mutant source changed".into());
        }
        definition = definition.replacen(
            header,
            &format!("CREATE OR REPLACE FUNCTION {schema}.recall_message("),
            1,
        );
        let begin = definition
            .find("    INSERT INTO message_recalls (")
            .ok_or("recall audit start")?;
        let tail = "    ON CONFLICT (message_id) DO NOTHING;";
        let end = begin + definition[begin..].find(tail).ok_or("recall audit end")? + tail.len();
        definition.replace_range(begin..end, "    NULL; -- planted no-recall-audit mutant");
        sql.push_str(&definition);
        sql.push_str("; ");
    }
    sql.push_str(&format!(
        "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {schema} TO PUBLIC; COMMIT;"
    ));
    if let Err(error) = owner.batch_execute(&sql).await {
        let _ = owner.batch_execute("ROLLBACK").await;
        return Err(error.into());
    }

    Ok(Some((mutant, schema)))
}

type Rows = BTreeMap<String, BTreeMap<String, Value>>;

fn name_of(names: &Names, id: i64) -> String {
    names
        .get(&id)
        .cloned()
        .unwrap_or_else(|| format!("unexpected-{id}"))
}

/// Messages the request created get `<new-message-N>` in ID order.
async fn register_new(owner: &Client, fx: &mut Fx) -> Result<(), BoxError> {
    for account in [Some(&fx.a), fx.f.as_ref()].into_iter().flatten() {
        for row in owner
            .query_typed(
                "SELECT id, name FROM tags WHERE mailbox_id=$1 ORDER BY id",
                &[(&account.mailbox, Type::INT8)],
            )
            .await?
        {
            let id: i64 = row.get(0);
            fx.names
                .entry(id)
                .or_insert_with(|| format!("<new-tag:{}>", row.get::<_, String>(1)));
        }
    }

    for (account, prefix) in [
        (Some(&fx.a), "new-message"),
        (fx.f.as_ref(), "foreign-new-message"),
    ] {
        let Some(account) = account else { continue };
        let ids: Vec<i64> = owner
            .query_typed(
                "SELECT id FROM messages WHERE mailbox_id = $1 ORDER BY id",
                &[(&account.mailbox, Type::INT8)],
            )
            .await?
            .iter()
            .map(|r| r.get(0))
            .collect();
        let mut n = 0;
        for id in ids {
            if let std::collections::btree_map::Entry::Vacant(entry) = fx.names.entry(id) {
                n += 1;
                entry.insert(format!("<{prefix}-{n}>"));
            }
        }
    }
    Ok(())
}

/// All columns of the mailbox-scoped tables, keyed by stable names.
async fn rows(c: &Client, fx: &Fx, a: &Account) -> Result<Rows, BoxError> {
    let p = [(
        &a.mailbox as &(dyn tokio_postgres::types::ToSql + Sync),
        Type::INT8,
    )];
    let user = [(
        &a.user as &(dyn tokio_postgres::types::ToSql + Sync),
        Type::INT8,
    )];
    let mut tables = Rows::new();
    let mut one = BTreeMap::new();
    for row in c
        .query_typed(
            "SELECT to_jsonb(m)::text FROM mailboxes m WHERE m.id = $1",
            &p,
        )
        .await?
    {
        one.insert(
            "<mailbox>".into(),
            serde_json::from_str(&row.get::<_, String>(0))?,
        );
    }
    tables.insert("mailboxes".into(), one);
    let mut one = BTreeMap::new();
    for row in c
        .query_typed(
            "SELECT to_jsonb(u)::text FROM users u WHERE u.id = $1",
            &user,
        )
        .await?
    {
        one.insert(
            "<user>".into(),
            serde_json::from_str(&row.get::<_, String>(0))?,
        );
    }
    tables.insert("users".into(), one);
    let mut tag_rows = BTreeMap::new();
    for row in c
        .query_typed(
            "SELECT id, name, to_jsonb(t)::text FROM tags t WHERE mailbox_id = $1",
            &p,
        )
        .await?
    {
        tag_rows.insert(
            row.get::<_, String>(1),
            serde_json::from_str(&row.get::<_, String>(2))?,
        );
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
        messages.insert(
            name_of(&fx.names, row.get(0)),
            serde_json::from_str(&row.get::<_, String>(1))?,
        );
    }
    tables.insert("messages".into(), messages);
    let mut memberships = BTreeMap::new();
    for row in c.query_typed(
        "SELECT mt.message_id, mt.tag_id, to_jsonb(mt)::text FROM message_tags mt \
         JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at WHERE m.mailbox_id = $1", &p).await? {
        memberships.insert(
            format!("{}:{}", name_of(&fx.names, row.get(0)), name_of(&fx.names, row.get(1))),
            serde_json::from_str(&row.get::<_, String>(2))?,
        );
    }
    tables.insert("message_tags".into(), memberships);
    let mut journal = BTreeMap::new();
    for row in c.query_typed("SELECT datatype, state_seq, entity_id, to_jsonb(j)::text FROM jmap_changes_journal j WHERE mailbox_id = $1", &p).await? {
        journal.insert(
            format!("{}:{}:{}", row.get::<_, String>(0), row.get::<_, i64>(1), name_of(&fx.names, row.get(2))),
            serde_json::from_str(&row.get::<_, String>(3))?,
        );
    }
    tables.insert("jmap_changes_journal".into(), journal);
    let mut aliases = BTreeMap::new();
    for row in c
        .query_typed(
            "SELECT id,to_jsonb(a)::text FROM aliases a WHERE mailbox_id=$1",
            &p,
        )
        .await?
    {
        aliases.insert(
            name_of(&fx.names, row.get(0)),
            serde_json::from_str(&row.get::<_, String>(1))?,
        );
    }
    tables.insert("aliases".into(), aliases);
    let mut attachments = BTreeMap::new();
    for row in c.query_typed(
        "SELECT ma.message_id, ma.id, to_jsonb(ma)::text FROM message_attachments ma \
         JOIN messages m ON m.id = ma.message_id AND m.received_at = ma.received_at WHERE m.mailbox_id = $1", &p).await? {
        attachments.insert(
            format!("{}:{}", name_of(&fx.names, row.get(0)), row.get::<_, i64>(1)),
            serde_json::from_str(&row.get::<_, String>(2))?,
        );
    }
    // Attachment rows keep their own generated IDs out of the key.
    let mut by_message: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for (key, value) in attachments {
        let message = key.split(':').next().unwrap_or("").to_owned();
        by_message.entry(message).or_default().push(value);
    }
    let mut attachments = BTreeMap::new();
    for (message, list) in by_message {
        for (i, value) in list.into_iter().enumerate() {
            attachments.insert(format!("{message}:{i}"), value);
        }
    }
    tables.insert("message_attachments".into(), attachments);
    // Purge queues the raw blob of a message no other message shares.
    let prefix = if a.mailbox == fx.a.mailbox {
        ""
    } else {
        "foreign-"
    };
    let refs: Vec<String> = ["two-labels", "inbox-only"]
        .iter()
        .map(|n| format!("raw-{prefix}{n}"))
        .collect();
    let mut orphans = BTreeMap::new();
    for row in c
        .query_typed(
            "SELECT raw_ref, to_jsonb(o)::text FROM orphaned_message_blobs o WHERE raw_ref = ANY($1::text[])",
            &[(&refs, Type::TEXT_ARRAY)],
        )
        .await?
    {
        orphans.insert(row.get::<_, String>(0), serde_json::from_str(&row.get::<_, String>(1))?);
    }
    tables.insert("orphaned_message_blobs".into(), orphans);
    // Device heartbeat updates are part of the session GET's committed effect.
    let mut devices = BTreeMap::new();
    for row in c
        .query_typed(
            "SELECT id,to_jsonb(d)::text FROM user_devices d WHERE user_id=$1 ORDER BY id",
            &[(&a.user, Type::INT8)],
        )
        .await?
    {
        devices.insert(
            name_of(&fx.names, row.get(0)),
            serde_json::from_str(&row.get::<_, String>(1))?,
        );
    }
    tables.insert("user_devices".into(), devices);
    // #469 unsubscribe: the sender block list and the unsubscribe audit rows.
    let mut senders = BTreeMap::new();
    for row in c
        .query_typed(
            "SELECT sender||':'||list_type,to_jsonb(s)::text FROM user_sender_list s WHERE user_id=$1",
            &user,
        )
        .await?
    {
        senders.insert(
            row.get::<_, String>(0),
            serde_json::from_str(&row.get::<_, String>(1))?,
        );
    }
    tables.insert("user_sender_list".into(), senders);
    // #469 focus: the per-sender override the reducer remembers.
    let mut overrides = BTreeMap::new();
    for row in c
        .query_typed(
            "SELECT sender,to_jsonb(f)::text FROM focus_sender_overrides f WHERE user_id=$1",
            &user,
        )
        .await?
    {
        overrides.insert(
            row.get::<_, String>(0),
            serde_json::from_str(&row.get::<_, String>(1))?,
        );
    }
    tables.insert("focus_sender_overrides".into(), overrides);
    let mut trail = BTreeMap::new();
    for row in c
        .query_typed(
            "SELECT row_number() OVER (ORDER BY id)::text,(to_jsonb(l)-'id'-'checksum')::text FROM admin_audit_log l \
             WHERE user_id=$1 AND action='unsubscribe_newsletter'",
            &user,
        )
        .await?
    {
        trail.insert(
            row.get::<_, String>(0),
            serde_json::from_str(&row.get::<_, String>(1))?,
        );
    }
    tables.insert("admin_audit_log".into(), trail);

    let hashes = vec![
        cases::OWN_BLOB.to_string(),
        cases::FOREIGN_BLOB.to_string(),
        format!(
            "{:x}",
            <sha2::Sha256 as sha2::Digest>::digest(b"JMAP2 uploaded body\n")
        ),
    ];
    for (table, sql, params) in [
        (
            "blobs",
            "SELECT sha256,to_jsonb(b)::text FROM blobs b WHERE sha256=ANY($1::text[])",
            vec![(
                &hashes as &(dyn tokio_postgres::types::ToSql + Sync),
                Type::TEXT_ARRAY,
            )],
        ),
        (
            "blob_user_charges",
            "SELECT blob_sha256,to_jsonb(b)::text FROM blob_user_charges b WHERE user_id=$1",
            vec![(
                &a.user as &(dyn tokio_postgres::types::ToSql + Sync),
                Type::INT8,
            )],
        ),
        (
            "blob_user_usage",
            "SELECT user_id::text,to_jsonb(b)::text FROM blob_user_usage b WHERE user_id=$1",
            vec![(
                &a.user as &(dyn tokio_postgres::types::ToSql + Sync),
                Type::INT8,
            )],
        ),
        (
            "blob_cleanup_queue",
            "SELECT blob_sha256,to_jsonb(b)::text FROM blob_cleanup_queue b WHERE blob_sha256=ANY($1::text[])",
            vec![(
                &hashes as &(dyn tokio_postgres::types::ToSql + Sync),
                Type::TEXT_ARRAY,
            )],
        ),
    ] {
        let mut values = BTreeMap::new();
        for row in c.query_typed(sql, &params).await? {
            values.insert(
                row.get::<_, String>(0),
                serde_json::from_str(&row.get::<_, String>(1))?,
            );
        }
        tables.insert(table.into(), values);
    }
    let mut control = BTreeMap::new();
    for row in c
        .query_typed(
            "SELECT to_jsonb(u)::text FROM upgrade_control_state u WHERE singleton",
            &[],
        )
        .await?
    {
        let mut v: Value = serde_json::from_str(&row.get::<_, String>(0))?;
        if let Some(boot) = v
            .get_mut("continuity_last_boot_epoch")
            .filter(|v| !v.is_null())
        {
            let text = boot.as_str().ok_or("invalid boot epoch")?;
            if text.len() != 36 {
                return Err("invalid boot epoch".into());
            }
            *boot = json!("<boot-epoch>");
        }
        control.insert("singleton".into(), v);
    }
    tables.insert("upgrade_control_state".into(), control);
    // Submission lifecycle rows; replace generated action IDs and their default
    // dedup keys together. All other columns participate in the diff.
    let mut actions = BTreeMap::new();
    for (i,row) in c.query_typed(
        "SELECT to_jsonb(sa)::text FROM scheduled_actions sa WHERE mailbox_id=$1 ORDER BY created_at,id", &p).await?.into_iter().enumerate() {
        let mut value:Value=serde_json::from_str(&row.get::<_,String>(0))?;
        let id=value["id"].clone();
        value["id"]=json!(format!("<scheduled-action-{}>",i+1));
        if value["dedup_key"]==id { value["dedup_key"]=value["id"].clone(); }
        actions.insert(format!("action-{}",i+1),value);
    }
    let mut recalls = BTreeMap::new();
    for row in c.query_typed("SELECT to_jsonb(r)::text FROM message_recalls r WHERE recalled_by=$1 ORDER BY message_id",&user).await? {
        let value:Value=serde_json::from_str(&row.get::<_,String>(0))?;
        recalls.insert(value["message_id"].as_str().ok_or("recall message id")?.to_owned(),value);
    }
    tables.insert("message_recalls".into(), recalls);
    tables.insert("scheduled_actions".into(), actions);
    for table in ["outbound_queue", "outbound_queue_hot"] {
        let mut entries = BTreeMap::new();
        for (i, row) in c
            .query_typed(
                &format!("SELECT to_jsonb(q)::text FROM {table} q WHERE mailbox_id=$1 ORDER BY id"),
                &p,
            )
            .await?
            .into_iter()
            .enumerate()
        {
            let mut value: Value = serde_json::from_str(&row.get::<_, String>(0))?;
            let id = value["id"].clone();
            value["id"] = json!(format!("<{table}-{}>", i + 1));
            if value["dedup_key"] == id {
                value["dedup_key"] = value["id"].clone();
            }
            entries.insert(format!("item-{}", i + 1), value);
        }
        tables.insert(table.into(), entries);
    }
    Ok(tables)
}

fn row_diff(before: &Rows, after: &Rows) -> Result<Value, BoxError> {
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
                        let (l, r) = (old.get(name), new.get(name));
                        if l != r {
                            let value = |v: Option<&Value>| -> Value {
                                match v {
                                    Some(v) => v.clone(),
                                    None => json!({"missing":true}),
                                }
                            };
                            columns
                                .insert(name.clone(), json!({"before":value(l), "after":value(r)}));
                        }
                    }
                    if !columns.is_empty() {
                        result.push(
                            json!({"table":table, "row":key, "change":"update", "columns":columns}),
                        );
                    }
                }
                (None, Some(row)) => {
                    result.push(json!({"table":table, "row":key, "change":"insert", "after":row}))
                }
                (Some(row), None) => {
                    result.push(json!({"table":table, "row":key, "change":"delete", "before":row}))
                }
                (None, None) => unreachable!(),
            }
        }
    }
    Ok(Value::Array(result))
}

async fn snapshot(c: &Client, fx: &Fx, a: &Account) -> Result<Value, BoxError> {
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
    let mut messages: Vec<Value> = before
        .is_read
        .iter()
        .map(|(id, read)| json!({"id":name_of(&fx.names, *id), "is_read":read}))
        .collect();
    messages.sort_by_key(|m| m["id"].as_str().unwrap_or("").to_owned());
    let journal: Vec<Value> = before.journal.iter().map(|r| json!({"datatype":r.datatype, "state_seq":r.state_seq, "entity_id":name_of(&fx.names, r.entity_id), "op":r.op})).collect();
    Ok(
        json!({"messages":messages, "tags":tags, "email_state":before.email_state, "journal":journal}),
    )
}

async fn audit_rows(c: &Client, fx: &Fx, a: &Account) -> Result<Value, BoxError> {
    let rows = c.query_typed("SELECT id, occurred_at::text, mailbox_id, actor_user_id, action, message_id, details::text FROM mailbox_audit_log WHERE mailbox_id = $1 ORDER BY id", &[(&a.mailbox, Type::INT8)]).await?;
    let mut result = Vec::new();
    for row in rows {
        let (id, mailbox, actor): (i64, i64, Option<i64>) = (row.get(0), row.get(2), row.get(3));
        if mailbox != a.mailbox || actor != Some(a.user) {
            return Err(
                format!("audit row has unexpected mailbox {mailbox} or actor {actor:?}").into(),
            );
        }
        let message: Option<i64> = row.get(5);
        let details: Option<String> = row.get(6);
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
        result.push(json!({"id":"<audit-id>", "occurred_at":"<timestamp>", "mailbox_id":"<mailbox>", "actor_user_id":"<user>",
            "action":row.get::<_, String>(4), "message_id":message.map(|m| name_of(&fx.names, m)), "details":details, "raw_id":id}));
    }
    for r in &mut result {
        r.as_object_mut().map(|o| o.remove("raw_id"));
    }
    Ok(Value::Array(result))
}

fn normalize_headers(
    headers: &hyper::HeaderMap,
    raw_len: usize,
    normalized_len: usize,
    names: &Names,
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
            } else if name == "content-disposition"
                && value.starts_with("attachment; filename=\"recovery-")
            {
                let mut value = value.to_owned();
                for (id, label) in names {
                    value = value.replace(
                        &format!("recovery-{id}.eml"),
                        &format!("recovery-{label}.eml"),
                    );
                }
                value
            } else {
                value.to_owned()
            });
        }
        result.insert(name.to_string(), json!(values));
    }
    Ok(Value::Object(result))
}

fn normalize_body(raw: &str, names: &Names, jmap: bool) -> Result<String, BoxError> {
    Ok(scrub(
        &if jmap {
            scrub_session_state(raw)?
        } else {
            raw.to_owned()
        },
        names,
    ))
}

async fn execute(
    db: &Db,
    owner: &Client,
    fx: &mut Fx,
    spec: &Spec,
    mutation: Mutation,
) -> Result<(), BoxError> {
    let recording = std::env::var("GOFREE_RECORD_UPSTREAM")
        .ok()
        .filter(|s| !s.is_empty());
    if mutation != Mutation::None && recording.is_some() {
        return Err("cannot record a mutant".into());
    }
    for key in TOGGLES {
        let enabled = (key == "feature.stale_nudges" && spec.nudges_on)
            || (key == "feature.client_recovery_receipts"
                && matches!(spec.seed, Seed::RecoveryRaw | Seed::RecoveryS3))
            || (matches!(
                key,
                "feature.offline_mail" | "feature.connectivity_aware_sync"
            ) && spec.seed == Seed::Transfer)
            || (key == "feature.recall" && spec.recall_on);
        owner.query_typed("INSERT INTO feature_toggles (key, enabled) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET enabled = EXCLUDED.enabled", &[(&key, Type::TEXT), (&enabled, Type::BOOL)]).await?;
    }
    if recording.is_some() {
        // Go's flag cache follows the toggle table by notification.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    cases::seed(owner, fx, spec.seed).await?;
    if spec.case == "jmap-attachment-token-policy-denied" {
        owner
            .query_typed(
                "UPDATE user_devices SET offline_approval='denied' WHERE user_id=$1",
                &[(&fx.a.user, Type::INT8)],
            )
            .await?;
    }
    let key = SigningKey::from_slice(&[0x11; 32])?;
    let doc = json!({"keys": [jwk(KEY_ID, &public(&key))]})
        .to_string()
        .into_bytes();
    let keys = Jwks::with_fetch(Box::new(move || {
        let doc = doc.clone();
        Box::pin(async move { Ok(doc) })
    }));
    let exec = ScopedExecutor::from_dsn(
        if spec.owner_pool {
            &db.dsn
        } else {
            db.app.as_deref().unwrap_or(&db.dsn)
        },
        4,
    )
    .map_err(|e| e.0)?;
    let storage = if spec.http.is_some() {
        Some(storage::Storage::start().await)
    } else {
        None
    };
    if let Some(store) = &storage {
        store.put(cases::OWN_BLOB, b"JMAP2 attachment body\n");
        store.put(cases::FOREIGN_BLOB, b"JMAP2 foreign attachment\n");
        if matches!(spec.seed, Seed::RawDownloadLarge | Seed::ZipLarge) {
            store.put(cases::LARGE_BLOB, &cases::large_bytes());
        }
    }
    if let Some(store) = storage
        .as_ref()
        .filter(|_| spec.route.contains("/jmap/recovery-raw"))
    {
        store.put(
            "raw-inbox-only",
            b"From: oracle@example.test\r\nSubject: Recovery\r\n\r\nJMAP2 raw body\r\n",
        );
    }
    let mut services = setjoin_gateway::jmap::JmapServices::new(
        ScopedExecutor::from_dsn(&db.dsn, 4).map_err(|e| e.0)?,
        "mail.test".into(),
        52428800,
    );
    if let Some(storage) = &storage {
        services.store = Some(Arc::new(setjoin_gateway::recovery_worker::S3Store::new(
            &format!("http://{}", storage.addr),
            "mailblobs",
            "test-access",
            "test-secret",
        )?));
    }
    services.attachment_signer = Some(Arc::new(
        setjoin_gateway::jmap::transfer::Signer::from_master(
            b"blobs1-test-jwt-secret-for-recording",
        )?,
    ));
    if spec.route.contains("/jmap/recovery-raw") {
        services.continuity_boot = Some("bba31885-d8f1-4c47-8753-56bf86e59807".into());
    }
    if spec.case == "jmap-upload-over-quota" {
        services.quota = 1;
    }
    let mut commit_proxy = None;
    let worker_dsn = if matches!(mutation, Mutation::CommitBefore | Mutation::CommitAfter) {
        let cut = if mutation == Mutation::CommitBefore {
            common::commit::CommitCut::BeforeCommit
        } else {
            common::commit::CommitCut::AfterCommit
        };
        let (dsn, task) = common::commit::commit_cut_proxy(&db.dsn, cut).await;
        commit_proxy = Some((cut, task));
        dsn
    } else {
        db.dsn.clone()
    };
    let handler = JmapRoute(Arc::new(JmapCommands {
        services: Some(Arc::new(services)),
        worker: Some(ScopedExecutor::from_dsn(&worker_dsn, 1).map_err(|e| e.0)?),
        denylist: None,
        exec: exec.clone(),
        keys,
        issuer: "mailserver".into(),
    }));
    let routes = if recording.is_some() {
        // Recording: every request goes to frozen Go, none is served by Rust.
        RouteTable::proxy_all()
    } else if mutation == Mutation::WrongStatus {
        RouteTable::proxy_all().with(WrongStatus(handler))
    } else {
        RouteTable::proxy_all().with(handler)
    };
    let _http_go = if recording.is_some() && spec.http.is_some() {
        let extra = if spec.case == "jmap-upload-over-quota" {
            vec![("BLOB_USER_QUOTA_BYTES", "1".to_owned())]
        } else {
            vec![]
        };
        Some(
            (if spec.owner_pool {
                common::go_oracle::start_unscoped_with_env(
                    db,
                    storage.as_ref().unwrap().addr,
                    "gofree-jmap2-http",
                    &extra,
                )
                .await?
            } else {
                common::go_oracle::start_named_with_env(
                    db,
                    storage.as_ref().unwrap().addr,
                    "gofree-jmap2-http",
                    &extra,
                )
                .await?
            })
            .ok_or("HTTP recording needs GOFREE_RECORD_GO_BINARY")?,
        )
    } else {
        None
    };
    // Frozen Go's raw `.eml` download dials `http://127.0.0.1/jmap/download/...`
    // (hard-coded, port 80). Recording relays that to the same Go process, so the
    // answer is its real native JMAP download, byte for byte.
    let _download_relay = match (&_http_go, spec.route) {
        (Some(go), "GET /messages/{emailId}/download") => {
            let target = go.address;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:80")
                .await
                .map_err(|e| format!("cannot bind 127.0.0.1:80 for Go's download relay: {e}"))?;
            Some(tokio::spawn(async move {
                loop {
                    let Ok((mut inbound, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(async move {
                        if let Ok(mut outbound) = tokio::net::TcpStream::connect(target).await {
                            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                        }
                    });
                }
            }))
        }
        _ => None,
    };
    let recording = _http_go
        .as_ref()
        .map(|go| format!("http://{}", go.address))
        .or(recording);
    let forwarded = Arc::new(std::sync::Mutex::new(None::<Vec<u8>>));
    let preprocessing_upstream = if mutation == Mutation::PreprocessingOwner {
        let capture = forwarded.clone();
        let addr = common::fake_upstream(move |req| {
            let capture = capture.clone();
            async move {
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                *capture.lock().unwrap() = Some(bytes.to_vec());
                hyper::Response::builder()
                    .status(202)
                    .body(common::full("submission-preprocessing-owner-328"))
                    .unwrap()
            }
        })
        .await;
        Some(format!("http://{addr}").parse()?)
    } else {
        None
    };
    let upstream = preprocessing_upstream.or(recording.as_deref().map(str::parse).transpose()?);
    let gateway = Gateway::new(
        Config {
            upstream,
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        routes,
    )?;
    let gateway = if spec.http.is_some() && recording.is_some() {
        let mut inventory: Value = serde_json::from_str(setjoin_gateway::inventory::BUNDLED)?;
        for route in inventory["routes"].as_array_mut().ok_or("route table")? {
            if format!(
                "{} {}",
                route["method"].as_str().unwrap_or(""),
                route["path"].as_str().unwrap_or("")
            ) == spec.route
            {
                route["state"] = json!(if recording.is_some() { "OFF" } else { "ON" });
                route["upstream"] = json!(if recording.is_some() {
                    "go-mail"
                } else {
                    "local-rust"
                });
            }
        }
        gateway.with_inventory(&inventory.to_string())?
    } else {
        gateway
    };
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(gateway.serve(listener));

    if let Some(storage) = &storage {
        storage.clear_log();
    }
    let a = fx.a.clone();
    let before = snapshot(owner, fx, &a).await?;
    let rows_before = rows(owner, fx, &a).await?;
    let foreign = fx.f.clone();
    let foreign_before = match &foreign {
        Some(f) => Some((snapshot(owner, fx, f).await?, rows(owner, fx, f).await?)),
        None => None,
    };
    let mut notifications = db.listen(&format!("tag:{}", a.mailbox)).await?;
    notifications.drain(owner).await?;
    let mut foreign_notifications = match &foreign {
        Some(f) => {
            let mut l = db.listen(&format!("tag:{}", f.mailbox)).await?;
            l.drain(owner).await?;
            Some(l)
        }
        None => None,
    };
    let generation = if spec.seed == Seed::Transfer {
        let raw: String = owner
            .query_typed(
                "SELECT offline_effective_policy_snapshot($1,$2)::text",
                &[
                    (&a.mailbox, Type::INT8),
                    (&fx.extra["native-device"], Type::INT8),
                ],
            )
            .await?[0]
            .get(0);
        Some(format!(
            "{:x}",
            <sha2::Sha256 as sha2::Digest>::digest(raw.as_bytes())
        ))
    } else {
        None
    };
    let body = (spec.body)(fx);
    let token = token(
        &key,
        a.user,
        matches!(spec.seed, Seed::SessionNative | Seed::Transfer)
            && spec.case != "jmap-attachment-token-browser",
        spec.seed == Seed::SessionAdmin,
    );
    let (verb, path) = spec
        .http
        .map(|h| (h.verb, (h.path)(fx)))
        .unwrap_or(("POST", (spec.path)(fx)));
    let request = || {
        let mut builder = Request::builder()
            .method(verb)
            .uri(path.as_str())
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header(
                "x-setjoin-native-platform",
                if spec.seed == Seed::SessionNative {
                    "desktop"
                } else {
                    ""
                },
            )
            .header("x-request-id", "gofree-t2-golden");
        for (key, value) in spec.http.map(|h| h.headers).unwrap_or(&[]) {
            builder = builder.header(*key, *value);
        }
        builder.body(common::full(body.clone()))
    };
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
    let connection = tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut raw_responses = Vec::new();
    for _ in 0..if spec.repeat { 2 } else { 1 } {
        sender.ready().await?;
        let response = sender.send_request(request()?).await?;
        let status = response.status().as_u16();
        let mut headers = response.headers().clone();
        let bytes = response.into_body().collect().await?.to_bytes();
        common::problem_bytes::check_if_problem(
            headers.get("content-type").and_then(|v| v.to_str().ok()),
            &bytes,
        );
        let text = if headers.get("content-type").is_some_and(|v| v == "application/zip") {
            // A zip is observed as its verified entry listing (names, sizes, digests).
            if let Some(length) = headers.get("content-length") {
                if length.to_str()?.parse::<usize>()? != bytes.len() {
                    return Err("incorrect zip content-length".into());
                }
            }
            let listing = zip_listing(&bytes)?;
            if headers.contains_key("content-length") {
                headers.insert("content-length", listing.len().to_string().parse()?);
            }
            listing
        } else {
            std::str::from_utf8(&bytes)?.to_owned()
        };
        raw_responses.push((status, headers, text));
    }
    if recording.is_none() {
        sender.ready().await?;
        let metrics = sender
            .send_request(
                Request::get("/_gateway/metrics")
                    .header("host", "mail.test")
                    .body(common::full(""))?,
            )
            .await?;
        let bytes = metrics.into_body().collect().await?.to_bytes();
        let metrics = std::str::from_utf8(&bytes)?;
        let expected = if mutation == Mutation::PreprocessingOwner {
            1
        } else {
            0
        };
        if !metrics
            .lines()
            .any(|line| line == format!("setjoin_gateway_proxied_to_go_total {expected}"))
            || !metrics.lines().any(|line| {
                line == format!(
                    "setjoin_gateway_proxied_to_go_by_family_total{{family=\"F18\"}} {expected}"
                )
            })
        {
            return Err("proxy counter did not match the selected owner".into());
        }
    }
    let commit_fault = if let Some((cut, mut task)) = commit_proxy {
        let reached =
            match tokio::time::timeout(std::time::Duration::from_secs(30), &mut task).await {
                Ok(result) => result??,
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    return Err("COMMIT barrier not reached".into());
                }
            };
        if reached != cut {
            return Err("wrong COMMIT barrier".into());
        }
        let (status, _, raw) = raw_responses.last().ok_or("fault response")?;
        let body: Value = serde_json::from_str(raw)?;
        let detail = body["methodResponses"][0][1]["detail"]
            .as_str()
            .ok_or("unknown detail missing")?;
        let hex = detail
            .strip_prefix("commit outcome unknown; look up operation ")
            .ok_or("fault claimed success")?;
        if *status != 200 || hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid unknown-commit response".into());
        }
        let mut operation = [0; 16];
        for (i, byte) in operation.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
        }
        let auth = setjoin_pg::MailboxAuthContext::from_authenticated_session(
            setjoin_contracts::ids::ActorId::new(fx.a.user).map_err(|_| "actor")?,
            setjoin_contracts::ids::MailboxId::new(fx.a.mailbox).map_err(|_| "mailbox")?,
            setjoin_contracts::ids::Generation(1),
        );
        let outcome = setjoin_pg::lookup_command(
            &exec,
            &auth,
            setjoin_contracts::ids::OperationId(operation),
            setjoin_pg::ReceiptCommand {
                family: "jmap",
                command: "submission.set",
            },
        )
        .await
        .map_err(|error| format!("receipt lookup failed: {error:?}"))?;
        let expected = if cut == common::commit::CommitCut::AfterCommit {
            setjoin_pg::OperationLookup::Committed
        } else {
            setjoin_pg::OperationLookup::Absent
        };
        if outcome != expected {
            return Err("receipt lookup disagrees with COMMIT barrier".into());
        }
        Some((cut, hex.to_owned()))
    } else {
        None
    };
    register_new(owner, fx).await?;
    let after = snapshot(owner, fx, &a).await?;
    let rows_after = rows(owner, fx, &a).await?;
    let row_effects = row_diff(&rows_before, &rows_after)?;
    let notify: Vec<Value> = notifications
        .drain(owner)
        .await?
        .into_iter()
        .map(|payload| json!({"channel":"tag:<mailbox>", "payload":scrub(&payload,&fx.names)}))
        .collect();
    let audit = audit_rows(owner, fx, &a).await?;
    let foreign_effects = match (&foreign, foreign_before, foreign_notifications.as_mut()) {
        (Some(f), Some((before, rows_before)), Some(listener)) => {
            let after = snapshot(owner, fx, f).await?;
            let rows_after = rows(owner, fx, f).await?;
            let notify: Vec<Value> = listener
                .drain(owner)
                .await?
                .into_iter()
                .map(|payload| json!({"channel":"tag:<foreign-mailbox>", "payload":scrub(&payload,&fx.names)}))
                .collect();
            Some(
                json!({"before":before, "after":after, "rows":row_diff(&rows_before, &rows_after)?,
                "audit":audit_rows(owner, fx, f).await?, "notify":notify}),
            )
        }
        _ => None,
    };
    connection.abort();
    server.abort();
    if let Some(relay) = &_download_relay {
        relay.abort();
    }

    if mutation == Mutation::PreprocessingOwner {
        let (status, _, raw) = raw_responses.last().ok_or("missing response")?;
        if *status != 202 || raw != "submission-preprocessing-owner-328" {
            return Err("mixed preprocessing map did not reach its unported #328 owner".into());
        }
        if forwarded.lock().unwrap().as_deref() != Some(body.as_bytes()) {
            return Err("preprocessing body changed in forwarding".into());
        }
        if before != after || row_effects != json!([]) || !notify.is_empty() || audit != json!([]) {
            return Err("preprocessing forwarding wrote native effects".into());
        }
        println!("DEFERRED-OWNER: EmailSubmission/set MIME/S/MIME :: #328");
        return Ok(());
    }
    let names = &fx.names;
    let mut shaped = Vec::new();
    let mut minted = Vec::new();
    for (status, headers, raw) in &raw_responses {
        let normalized_raw = if let Some(generation) = &generation {
            transfer::normalize(raw, &token, fx, generation, &mut minted)?
        } else {
            raw.clone()
        };
        let normalized_raw = if spec.route.contains("Identity/") {
            identity_ids(&normalized_raw, names)
        } else {
            normalized_raw
        };
        let raw = &normalized_raw;
        let normalized = if spec.http.is_some() {
            if raw.trim_start().starts_with('{') {
                let raw = if spec.route == "GET /.well-known/jmap" && raw.contains("\"state\":\"") {
                    scrub::scrub_named_session_state(raw, "state")?
                } else {
                    raw.clone()
                };
                Ok(scrub(&raw, names))
            } else {
                Ok(raw.clone())
            }
        } else {
            normalize_body(raw, names, spec.pattern == "/jmap")
        }
        .map_err(|e| format!("response {status} cannot be normalized: {e}; body: {raw}"))?;
        let headers = normalize_headers(
            headers,
            raw_responses[shaped.len()].2.len(),
            normalized.len(),
            names,
        )?;
        shaped.push(json!({"status":status, "headers":headers, "body":normalized}));
    }
    let (status, response_body) = (
        raw_responses[raw_responses.len() - 1].0,
        raw_responses[raw_responses.len() - 1].2.clone(),
    );
    let request_body: Value = if spec.http.is_some() {
        json!(scrub(&body, names))
    } else if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&scrub(&identity_ids(&body, names), names))?
    };
    let scrubbed = |v: Value| -> Result<Value, BoxError> {
        Ok(serde_json::from_str(&scrub(&v.to_string(), names))?)
    };
    let mut observed = json!({
        "request": {"method":verb, "path":if spec.http.is_some(){spec.route.split_once(' ').unwrap().1.to_owned()}else{spec.pattern.to_owned()}, "headers": {
            "host":"mail.test", "origin":"http://mail.test", "content-type":"application/json",
            "authorization":"Bearer <fixture-token>", "x-request-id":"gofree-t2-golden"
        }, "body":request_body},
        "response": shaped[shaped.len() - 1].clone(),
        "effects": scrubbed(json!({"before":before, "after":after}))?, "audit":scrubbed(audit)?,
        "notify":scrubbed(Value::Array(notify))?,
    });
    if let Some(http) = spec.http {
        observed["request"]["uri"] = json!(scrub(&path, names));
        for (key, value) in http.headers {
            observed["request"]["headers"][*key] = json!(value);
        }
        if spec.seed == Seed::SessionNative {
            observed["request"]["headers"]["x-setjoin-native-platform"] = json!("desktop");
        }
    }
    if spec.route.contains("/jmap/upload") || spec.route.contains("/jmap/download") {
        observed["storage"] = storage.as_ref().unwrap().observe()?;
    }
    if spec.pattern != "/jmap" {
        let id = path.rsplit('/').nth(1).ok_or("REST id")?;
        observed["request"]["path_values"] =
            json!({"id":scrub(&format!("\"{id}\""),names).trim_matches('"')});
    }
    if let Some(effects) = foreign_effects {
        observed["foreign_effects"] = scrubbed(effects)?;
    }
    if spec.repeat {
        observed["first_response"] = shaped[0].clone();
    }
    let row_effects = scrubbed(row_effects)?;
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/jmap/goldens");
    let (path, row_case) = (
        dir.join(format!("{}.json", spec.case)),
        format!("{}-row-effects", spec.case),
    );
    let row_path = dir.join(format!("{row_case}.json"));
    let route = spec.route;
    if let Some((cut, operation)) = commit_fault {
        let document: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        let mut expected = document["observation"].clone();
        let success: Value = serde_json::from_str(
            expected["response"]["body"]
                .as_str()
                .ok_or("success body")?,
        )?;
        let unknown: Value = serde_json::from_str(
            observed["response"]["body"]
                .as_str()
                .ok_or("unknown body")?,
        )?;
        let expected_unknown = json!({"sessionState":success["sessionState"],"methodResponses":[["error",{
            "type":"urn:ietf:params:jmap:error:serverFail","status":500,
            "detail":format!("commit outcome unknown; look up operation {operation}")},"0"]]});
        golden::compare(&expected_unknown, &unknown).map_err(|e| e.to_string())?;
        let mut expected_headers = expected["response"]["headers"].clone();
        let mut actual_headers = observed["response"]["headers"].clone();
        expected_headers
            .as_object_mut()
            .ok_or("headers")?
            .remove("content-length");
        actual_headers
            .as_object_mut()
            .ok_or("headers")?
            .remove("content-length");
        golden::compare(&expected_headers, &actual_headers).map_err(|e| e.to_string())?;
        // Fault replies have their own complete contract above. User effects
        // still compare with one ordinary Go request, or none before COMMIT.
        expected["response"] = observed["response"].clone();
        let expected_rows = if cut == common::commit::CommitCut::BeforeCommit {
            expected["effects"]["after"] = expected["effects"]["before"].clone();
            expected["audit"] = json!([]);
            expected["notify"] = json!([]);
            json!([])
        } else {
            let rows: Value = serde_json::from_slice(&std::fs::read(&row_path)?)?;
            rows["effects"].clone()
        };
        golden::compare(&expected, &observed).map_err(|e| e.to_string())?;
        golden::compare(&expected_rows, &row_effects).map_err(|e| e.to_string())?;
        println!("COMMIT-LOSS: submission.set :: {cut:?} :: receipt resolved");
        return Ok(());
    }
    if recording.is_some() {
        let expected_status = spec.http.map_or(spec.status, |h| h.status);
        let marker = if spec.http.is_some() {
            spec.method.to_owned()
        } else {
            format!("\"{}\"", spec.method)
        };
        if status != expected_status
            || (!spec.method.is_empty() && !response_body.contains(&marker))
        {
            return Err(format!(
                "refusing to record unexpected Go response {status}: {response_body}"
            )
            .into());
        }
        let source = std::env::var("GOFREE_GO_SOURCE")?;
        if std::env::var("GOFREE_RECORD_EFFECTS").as_deref() == Ok("1") {
            if !spec.mutator {
                return Err("only mutators have a row-effects golden".into());
            }
            let document = json!({"format":1, "route":route, "case":row_case, "go_source":source,
                "normalization":ROW_RULES, "effects":row_effects});
            golden::record(&row_path, &document)?;
        } else {
            let document = json!({"format":1, "route":route, "case":spec.case, "go_source":source,
                "normalization":RULES, "observation":observed});
            golden::record(&path, &document)?;
        }
    } else {
        let document: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        if document["format"] != 1
            || document["route"] != route
            || document["case"] != spec.case
            || document["normalization"] != json!(RULES)
        {
            return Err("golden metadata or normalization rules do not match the case".into());
        }
        let divergences: Value = serde_json::from_slice(&std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/conformance/jmap/divergences.json"),
        )?)?;
        // An owner-approved security fix pins the golden and compares the reviewed expectation.
        let expected_observation = if common::is_pinned(&path) {
            common::golden_doc(&path, "observation", &observed)["observation"].clone()
        } else {
            document["observation"].clone()
        };
        golden::compare_reviewed(
            route,
            spec.case,
            &expected_observation,
            &observed,
            &divergences,
        )?;
        if spec.mutator {
            let row_document: Value = serde_json::from_slice(&std::fs::read(&row_path)?)?;
            if row_document["format"] != 1
                || row_document["route"] != route
                || row_document["case"] != row_case
                || row_document["normalization"] != json!(ROW_RULES)
            {
                return Err(
                    "row-effects golden metadata or normalization rules do not match the case"
                        .into(),
                );
            }
            let expected_effects = if common::is_pinned(&row_path) {
                common::golden_doc(&row_path, "effects", &row_effects)["effects"].clone()
            } else {
                row_document["effects"].clone()
            };
            golden::compare_reviewed(
                route,
                &row_case,
                &expected_effects,
                &row_effects,
                &divergences,
            )?;
        }
        println!("GOLDEN-REPLAY: {route} :: {}", spec.case);
    }
    Ok(())
}

fn zip_listing(bytes: &[u8]) -> Result<String, BoxError> {
    use std::io::Write;
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/jmap/zip_listing.py");
    let mut process = std::process::Command::new("python3")
        .arg("-I")
        .arg(script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let mut stdin = process.stdin.take().ok_or("zip observer stdin")?;
    let input = bytes.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let output = process.wait_with_output()?;
    let _ = writer.join();
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn identity_ids(raw: &str, names: &Names) -> String {
    let mut raw = raw.to_owned();
    for (id, name) in names {
        for prefix in ["i", "a", "d"] {
            raw = raw.replace(&format!("\"{prefix}{id}\""), &format!("\"{prefix}{name}\""));
        }
    }
    raw
}
