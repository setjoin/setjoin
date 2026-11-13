//! Slice `queue` (#321): the admin outbound-queue summary, list, retry and bounce.
//!
//! `outbound_queue` is a global table, so a case moves every row it did not seed aside
//! (triggers off) and `teardown` removes its own rows and the DSN actions they enqueued,
//! then puts the others back.
use super::{Req, Seed};
use crate::common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::fixture::Account;

pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "summary" => ("GET", "/admin/queue/summary"),
        "list" => ("GET", "/admin/queue"),
        "retry" => ("POST", "/admin/queue/{id}/retry"),
        "bounce" => ("POST", "/admin/queue/{id}/bounce"),
        _ => panic!("unknown queue action {action}"),
    }
}

/// The permission that satisfies an action's gate (`requireMailPerm` / `requireQueueWrite`).
pub fn granted(action: &str) -> Vec<&'static str> {
    match action {
        "retry" | "bounce" => vec!["queue.write"],
        _ => vec!["mail.pipeline"],
    }
}

pub fn wanted(action: &str, label: &str) -> Option<u16> {
    let write = matches!(action, "retry" | "bounce");
    match (action, label) {
        (_, "denied") => Some(403),
        (_, "bad-id") => Some(400),
        ("retry", "already" | "missing" | "sending" | "bounced") => Some(404),
        ("bounce", "missing") => Some(404),
        ("bounce", "delivered") => Some(500),
        _ if write => Some(204),
        _ => Some(200),
    }
}

struct Spec {
    key: &'static str,
    status: &'static str,
    attempts: i32,
    error: Option<&'static str>,
    rcpts: &'static [&'static str],
    mailbox: Option<bool>,
    queued: &'static str,
}

const SPECS: [Spec; 6] = [
    Spec {
        key: "q1",
        status: "pending",
        attempts: 0,
        error: None,
        rcpts: &["a@ext.test"],
        mailbox: Some(true),
        queued: "2026-10-01T10:00:05Z",
    },
    Spec {
        key: "q2",
        status: "deferred",
        attempts: 3,
        error: Some("temp <fail> & retry \u{2028}"),
        rcpts: &["b@ext.test", "c@ext.test"],
        mailbox: Some(true),
        queued: "2026-10-01T10:00:04Z",
    },
    Spec {
        key: "q3",
        status: "deferred",
        attempts: 10,
        error: Some("held for good"),
        rcpts: &["d@ext.test"],
        mailbox: Some(false),
        queued: "2026-10-01T10:00:03Z",
    },
    Spec {
        key: "q4",
        status: "bounced",
        attempts: 5,
        error: Some("550 no such user"),
        rcpts: &["e@ext.test"],
        mailbox: None,
        queued: "2026-10-01T10:00:02Z",
    },
    Spec {
        key: "q5",
        status: "delivered",
        attempts: 1,
        error: None,
        rcpts: &["f@ext.test"],
        mailbox: Some(true),
        queued: "2026-10-01T10:00:01Z",
    },
    Spec {
        key: "q6",
        status: "pending",
        attempts: 2,
        error: None,
        rcpts: &["g@ext.test"],
        mailbox: Some(true),
        queued: "2026-10-01T10:00:00Z",
    },
];

pub async fn seed(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    action: &str,
    label: &str,
) -> Result<Seed, BoxError> {
    // Move every foreign row aside so a list shows exactly this case's rows.
    let stash: Vec<String> = owner
        .query("SELECT to_jsonb(q)::text FROM outbound_queue q", &[])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM outbound_queue; COMMIT;")
        .await?;
    let mut names: Vec<(&'static str, i64, String)> = vec![];
    let mut vars = std::collections::BTreeMap::new();
    if label != "empty" {
        for spec in &SPECS {
            let mailbox = spec
                .mailbox
                .map(|mine| if mine { a.mailbox } else { b.mailbox });
            let rcpts: Vec<String> = spec.rcpts.iter().map(|s| s.to_string()).collect();
            // The summary's oldest-minutes figure needs a stable age: 90 minutes plus the
            // seed's position, so it renders "90 min" however slowly the case runs.
            let queued = if action == "summary" {
                "now() - interval '90 minutes' + (6 - ".to_owned()
                    + &spec.key[1..]
                    + ") * interval '1 second'"
            } else {
                format!("'{}'::timestamptz", spec.queued)
            };
            let sql = format!(
                "INSERT INTO outbound_queue (message_id,from_addr,rcpt_addrs,raw_ref,status,attempt_count,next_attempt_at,last_error,queued_at,delivered_at,mailbox_id) \
                 VALUES ($1,'sender@q.test',$2,$3,$4,$5,'2026-10-01T11:00:00Z',$6,{queued},CASE WHEN $4 IN ('bounced','delivered') THEN now() - interval '1 hour' END,$7) RETURNING id"
            );
            let id: i64 = owner
                .query_one(
                    &sql,
                    &[
                        &format!("<{}@q.test>", spec.key),
                        &rcpts,
                        &format!("raw-{}", spec.key),
                        &spec.status,
                        &spec.attempts,
                        &spec.error,
                        &mailbox,
                    ],
                )
                .await?
                .get(0);
            vars.insert(spec.key, id);
            names.push(("id", id, format!("<{}>", spec.key)));
        }
    }
    for (account, who) in [(a, "actor"), (b, "other")] {
        names.push(("mailboxId", account.mailbox, format!("<mailbox-{who}>")));
        names.push(("mailbox_id", account.mailbox, format!("<mailbox-{who}>")));
    }
    Ok(Seed { stash, names, vars })
}

/// Go's startup recovery resets every `sending` row to `pending` when it boots, so the
/// `sending` item exists only once the process is up: the case flips it here, in record and
/// in replay alike.
pub async fn after_start(owner: &tokio_postgres::Client, seed: &Seed) -> Result<(), BoxError> {
    if let Some(id) = seed.vars.get("q6") {
        owner
            .execute(
                "UPDATE outbound_queue SET status='sending' WHERE id=$1",
                &[id],
            )
            .await?;
    }
    Ok(())
}

/// Removes this case's rows and their DSN actions, then restores the rows moved aside.
pub async fn teardown(owner: &tokio_postgres::Client, seed: &Seed) -> Result<(), BoxError> {
    let ids: Vec<i64> = seed.vars.values().copied().collect();
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica;")
        .await?;
    owner
        .execute("DELETE FROM scheduled_actions WHERE action_kind='dsn' AND (payload->>'queue_id')::bigint = ANY($1)", &[&ids])
        .await?;
    owner
        .execute("DELETE FROM outbound_queue WHERE id = ANY($1)", &[&ids])
        .await?;
    for row in &seed.stash {
        owner
            .execute("INSERT INTO outbound_queue SELECT * FROM jsonb_populate_record(NULL::outbound_queue, $1::text::jsonb)", &[row])
            .await?;
    }
    owner.batch_execute("COMMIT;").await?;
    Ok(())
}

pub fn request(action: &str, label: &str, seed: &Seed) -> Req {
    let (_, pattern) = route(action);
    let var = |k: &str| seed.vars.get(k).copied().unwrap_or(0);
    let id = match (action, label) {
        (_, "bad-id") => "abc".to_string(),
        (_, "missing") => "999999999".to_string(),
        ("retry", "already") => var("q5").to_string(),
        ("retry", "sending") => var("q6").to_string(),
        ("retry", "bounced") => var("q4").to_string(),
        ("retry", "pending") => var("q1").to_string(),
        ("bounce", "delivered") => var("q5").to_string(),
        ("bounce", "bounced-again") => var("q4").to_string(),
        ("bounce", "deferred") => var("q2").to_string(),
        ("bounce", _) => var("q1").to_string(),
        _ => var("q2").to_string(),
    };
    let query = match (action, label) {
        ("list", "pending") => "?status=pending",
        ("list", "deferred") => "?status=deferred",
        ("list", "bounced") => "?status=bounced",
        ("list", "sending") => "?status=sending",
        ("list", "delivered") => "?status=delivered",
        ("list", "failed") => "?status=failed",
        ("list", "held") => "?status=held",
        ("list", "all") => "?status=all",
        ("list", "unknown-status") => "?status=bogus%27",
        ("list", "limit") => "?limit=2",
        ("list", "offset") => "?limit=2&offset=2",
        ("list", "bad-limit") => "?limit=abc&offset=zz",
        ("list", "negative-offset") => "?offset=-5",
        ("list", "big-limit") => "?limit=201",
        ("list", "zero-limit") => "?limit=0",
        ("list", "max-limit") => "?limit=200",
        ("list", "status-limit") => "?status=deferred&limit=1&offset=1",
        (_, "ignored-query") => "?limit=-1&x=%zz",
        _ => "",
    };
    Req {
        path: pattern.replace("{id}", &id),
        query: query.to_string(),
        recorded_query: String::new(),
        body: String::new(),
        recorded_body: String::new(),
        headers: vec![],
    }
}

pub async fn snapshot(
    owner: &tokio_postgres::Client,
    _a: &Account,
    _b: &Account,
    seed: &Seed,
) -> Result<Value, BoxError> {
    let mut queue = vec![];
    for (key, id) in &seed.vars {
        let row = owner
            .query_opt(
                "SELECT jsonb_build_object('seed',$2::text,'status',q.status,'attempt_count',q.attempt_count,'next_attempt_at',q.next_attempt_at,'delivered_at',q.delivered_at,'last_error',q.last_error,'mailbox_id',q.mailbox_id,\
                 'dsn_actions',(SELECT COALESCE(jsonb_agg(jsonb_build_object('kind',s.action_kind,'status',s.status,'dedup_matches',s.dedup_key='dsn:'||q.id::text,'mailbox_id',s.mailbox_id)),'[]'::jsonb) FROM scheduled_actions s WHERE s.action_kind='dsn' AND (s.payload->>'queue_id')::bigint=q.id))::text \
                 FROM outbound_queue q WHERE q.id=$1",
                &[id, &key.to_string()],
            )
            .await?;
        queue.push(match row {
            Some(r) => serde_json::from_str(&r.get::<_, String>(0))?,
            None => json!({"seed":key,"row":"gone"}),
        });
    }
    Ok(json!({"queue":queue}))
}
