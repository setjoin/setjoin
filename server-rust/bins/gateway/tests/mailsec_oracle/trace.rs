//! Slice `trace` (#327): the admin message trace (`list`, `export`, `timeline`) and the user
//! delivery trace (`user`).
//!
//! `message_trace` and `outbound_queue` are global tables: a case moves every foreign row
//! aside and `teardown` puts them back. The user trace reads the actor's own messages; its
//! inbound path fetches the header block from `http://127.0.0.1/jmap/download/...`, so a
//! case that needs the download starts a stand-in on 127.0.0.1:80 that both Go and Rust
//! reach (record and replay alike) and that serves only the exact path and credentials Go
//! sends.
use super::{Req, Seed};
use crate::common::BoxError;
use serde_json::Value;
use setjoin_conformance::fixture::Account;

pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "list" => ("GET", "/admin/trace"),
        "export" => ("GET", "/admin/trace/export"),
        "timeline" => ("GET", "/admin/trace/{messageId}"),
        "user" => ("GET", "/messages/{emailId}/trace"),
        _ => panic!("unknown trace action {action}"),
    }
}

/// The permission that satisfies an action's gate (`requireMailPerm` / `requireMailExport`).
pub fn granted(action: &str) -> Vec<&'static str> {
    match action {
        "export" => vec!["mail.export"],
        _ => vec!["mail.pipeline"],
    }
}

pub fn wanted(action: &str, label: &str) -> Option<u16> {
    match (action, label) {
        ("user", "other" | "missing" | "negative-id") => Some(404),
        ("user", "bad-id" | "float-id" | "huge-id" | "empty-id") => Some(400),
        (_, "denied") => Some(403),
        // An unparsable date is ignored, so even invalid UTF-8 there answers 200.
        (_, "bad-utf8-date") => Some(200),
        // pgx prepares first, so the bind error reaches an iteration the export never checks.
        ("export", l) if l.starts_with("bad-utf8") || l == "nul-byte" => Some(200),
        (_, l) if l.starts_with("bad-utf8") || l == "nul-byte" => Some(500),
        _ => Some(200),
    }
}

/// `(message_id, event, from, rcpt, remote_host, details json text, occurred_at)`.
type Trace = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
    &'static str,
);
const TRACES: [Trace; 14] = [
    (
        "<out1@trace.test>",
        "received",
        "alice@x.test",
        "bob@y.test",
        Some("mx1.x.test"),
        Some(r#"{"status":"ok","subject":"Hello World","size":120}"#),
        "2026-10-01T10:00:09Z",
    ),
    (
        "<out1@trace.test>",
        "delivered",
        "alice@x.test",
        "bob@y.test",
        None,
        Some(r#"{"status":"delivered","subject":"Hello World"}"#),
        "2026-10-01T10:00:08Z",
    ),
    (
        "<tl2@trace.test>",
        "deferred",
        "carol@x.test",
        "dave@z.test",
        Some("mx2.z.test"),
        Some(r#"{"status":"deferred","subject":"hôtel <b>&</b>","code":451}"#),
        "2026-10-01T10:00:07Z",
    ),
    (
        "<tl2@trace.test>",
        "bounced",
        "carol@x.test",
        "dave@z.test",
        Some(""),
        Some(r#"{"status":"bounced","subject":"Re: 100%_sure"}"#),
        "2026-10-01T10:00:06Z",
    ),
    (
        "<a%b_c@trace.test>",
        "spam_filtered",
        "=HYPERLINK(\"x\")",
        "+1555@y.test",
        Some("mx3.x.test"),
        None,
        "2026-10-01T10:00:05Z",
    ),
    (
        "<t,6@trace.test>",
        "rule_applied",
        "\"quoted\"@x.test",
        "@at@y.test",
        Some(" lead\nnl"),
        Some("null"),
        "2026-10-01T10:00:04Z",
    ),
    (
        "<t7@trace.test>",
        "quarantined",
        "-dash@x.test",
        "\tTab@y.test",
        Some("mx4.x.test"),
        Some(r#"["arr",1,{"k":"v"}]"#),
        "2026-10-01T10:00:03Z",
    ),
    (
        "<t8@trace.test>",
        "held",
        "ALICE@X.TEST",
        "bob2@y.test",
        Some("mx5.x.test"),
        Some(r#"{"status":"ok","subject":"hello world"}"#),
        "2026-10-01T10:00:02Z",
    ),
    (
        "<t9@trace.test>",
        "archived",
        "erin@x.test",
        "frank@y.test",
        Some("mx6.x.test"),
        Some(r#"{"nested":{"a":[1,2,{"b":null}]},"u":"é "}"#),
        "2026-10-01T10:00:01Z",
    ),
    (
        "<t10@trace.test>",
        "expired",
        "erin@x.test",
        "gina@y.test",
        None,
        Some(r#"{}"#),
        "2026-10-01T10:00:00.5Z",
    ),
    (
        "<out5@trace.test>",
        "received",
        "alice@x.test",
        "d1@ext.test",
        Some("mx1.x.test"),
        Some(r#"{"status":"ok"}"#),
        "2026-10-02T10:00:00Z",
    ),
    (
        "<out5@trace.test>",
        "deferred",
        "alice@x.test",
        "d1@ext.test",
        Some("mx9.ext.test"),
        Some(r#"{"status":"deferred","code":451,"text":"later"}"#),
        "2026-10-02T10:05:00.123456Z",
    ),
    (
        "<out1@trace.test>",
        "received",
        "zed@x.test",
        "yan@y.test",
        Some("mx1.x.test"),
        Some(r#"{"subject":"ZZZ"}"#),
        "2026-10-03T10:00:00Z",
    ),
    (
        "<out1@trace.test>",
        "delivered",
        "zed@x.test",
        "yan@y.test",
        None,
        Some(r#"{"status":"delivered","subject":"ZZZ"}"#),
        "2026-10-04T10:00:00Z",
    ),
];

/// One seeded message: key, subject, sent, the day of its `received_at`.
struct Msg {
    key: &'static str,
    subject: Option<&'static str>,
    sent: bool,
}
const MESSAGES: [Msg; 11] = [
    Msg {
        key: "in1",
        subject: Some("Inbound hello"),
        sent: false,
    },
    Msg {
        key: "in2",
        subject: Some("Re: h\u{e9}llo / x<>.eml"),
        sent: false,
    },
    Msg {
        key: "in3",
        subject: None,
        sent: false,
    },
    Msg {
        key: "out1",
        subject: Some("Sent one"),
        sent: true,
    },
    Msg {
        key: "out2",
        subject: Some("Sent two"),
        sent: true,
    },
    Msg {
        key: "out3",
        subject: Some("Sent three"),
        sent: true,
    },
    Msg {
        key: "out4",
        subject: Some("Sent four"),
        sent: true,
    },
    Msg {
        key: "out5",
        subject: Some("Sent five"),
        sent: true,
    },
    Msg {
        key: "out6",
        subject: Some("Sent six"),
        sent: true,
    },
    Msg {
        key: "out7",
        subject: Some("Sent seven"),
        sent: true,
    },
    Msg {
        key: "out8",
        subject: Some("Sent eight"),
        sent: true,
    },
];
const RECEIVED: &str = "2026-10-01T10:00:00Z";

async fn insert_message(
    owner: &tokio_postgres::Client,
    account: &Account,
    key: &str,
    subject: Option<&str>,
    sent: bool,
) -> Result<i64, BoxError> {
    let tag: i64 = if sent {
        owner
            .query_one(
                "SELECT id FROM tags WHERE mailbox_id=$1 AND name='Sent'",
                &[&account.mailbox],
            )
            .await?
            .get(0)
    } else {
        account.inbox
    };
    let id: i64 = owner
        .query_one(
            "INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, size_bytes, thread_id, raw_ref, received_at, is_read) \
             VALUES ($1,$2,'<'||$3::text||'@trace.test>',$4,'me@x.test',10,'thr-'||$3::text,'raw-'||$3::text,$5::text::timestamptz,false) RETURNING id",
            &[&account.mailbox, &tag, &key, &subject, &RECEIVED],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary) SELECT id, received_at, $2, 'system', true FROM messages WHERE id=$1",
            &[&id, &tag],
        )
        .await?;
    Ok(id)
}

struct Attempt {
    to: &'static str,
    n: i32,
    mx: Option<&'static str>,
    code: Option<i32>,
    text: Option<&'static str>,
    outcome: &'static str,
    tls: bool,
    at: &'static str,
}
#[allow(clippy::too_many_arguments)]
const fn at(
    to: &'static str,
    n: i32,
    mx: Option<&'static str>,
    code: Option<i32>,
    text: Option<&'static str>,
    outcome: &'static str,
    tls: bool,
    at: &'static str,
) -> Attempt {
    Attempt {
        to,
        n,
        mx,
        code,
        text,
        outcome,
        tls,
        at,
    }
}

/// Attempts per message key.
fn attempts(key: &str) -> Vec<Attempt> {
    match key {
        "out1" => vec![
            at(
                "r1@ext.test",
                1,
                Some("mx1.ext.test"),
                Some(451),
                Some("try <later> & retry"),
                "deferred",
                false,
                "2026-10-01T10:01:00Z",
            ),
            at(
                "r1@ext.test",
                2,
                Some("mx1.ext.test"),
                Some(250),
                Some("ok"),
                "accepted",
                true,
                "2026-10-01T10:05:00.25Z",
            ),
            at(
                "r2@ext.test",
                1,
                Some("mx2.ext.test"),
                Some(550),
                Some("no such user"),
                "rejected",
                true,
                "2026-10-01T10:02:00Z",
            ),
        ],
        "out4" => vec![
            at(
                "u1@ext.test",
                1,
                Some("mx.ext.test"),
                Some(250),
                Some("ok"),
                "accepted",
                true,
                "2026-10-01T10:03:00Z",
            ),
            at(
                "u2@ext.test",
                1,
                Some("mx.ext.test"),
                Some(451),
                Some("later"),
                "deferred",
                false,
                "2026-10-01T10:04:00Z",
            ),
        ],
        "out5" => vec![
            at(
                "d1@ext.test",
                1,
                Some("mx9.ext.test"),
                Some(451),
                Some("later"),
                "deferred",
                false,
                "2026-10-02T10:05:00.123456Z",
            ),
            at(
                "d2@ext.test",
                1,
                None,
                None,
                None,
                "error",
                false,
                "2026-10-02T10:06:00Z",
            ),
        ],
        "out6" => vec![
            at(
                "b1@ext.test",
                1,
                Some("mx.ext.test"),
                Some(554),
                Some("rejected \u{e9}"),
                "rejected",
                true,
                "2026-10-01T10:07:00Z",
            ),
            at(
                "b1@ext.test",
                2,
                Some("mx.ext.test"),
                Some(554),
                Some("rejected again"),
                "rejected",
                true,
                "2026-10-01T10:08:00Z",
            ),
        ],
        "out8" => vec![at(
            "s1@ext.test",
            1,
            Some("mx.ext.test"),
            Some(250),
            Some("ok"),
            "accepted",
            true,
            "2026-10-01T10:09:00Z",
        )],
        _ => vec![],
    }
}

/// `(key, status, rcpts, next_attempt_at, delivered_at, queued_at, message_id override, with pk)`
type Queue = (
    &'static str,
    &'static str,
    &'static [&'static str],
    &'static str,
    Option<&'static str>,
    &'static str,
    Option<&'static str>,
    bool,
);
const QUEUES: [Queue; 9] = [
    (
        "out1",
        "delivered",
        &["r1@ext.test", "r2@ext.test", "r3@ext.test"],
        "2026-10-02T09:00:00Z",
        Some("2026-10-02T10:00:00Z"),
        "2026-10-01T10:00:00Z",
        None,
        true,
    ),
    (
        "out2",
        "pending",
        &["p1@ext.test"],
        "2026-10-01T11:00:00Z",
        None,
        "2026-10-01T10:00:01Z",
        None,
        true,
    ),
    (
        "out3",
        "delivered",
        &["k1@ext.test"],
        "2026-10-01T11:00:00Z",
        Some("2026-10-01T12:00:00Z"),
        "2026-10-01T10:00:02Z",
        None,
        true,
    ),
    (
        "out5",
        "deferred",
        &["d1@ext.test", "d2@ext.test", "d3@ext.test"],
        "2026-10-03T12:00:00Z",
        None,
        "2026-10-02T10:00:00Z",
        None,
        true,
    ),
    (
        "out6",
        "bounced",
        &["b1@ext.test"],
        "2026-10-01T11:00:00Z",
        Some("2026-10-01T10:09:00Z"),
        "2026-10-01T10:00:03Z",
        None,
        true,
    ),
    (
        "out8",
        "sending",
        &["s1@ext.test", "s2@ext.test"],
        "2026-10-01T11:00:00Z",
        None,
        "2026-10-01T10:00:04Z",
        None,
        true,
    ),
    (
        "out2",
        "bounced",
        &["old@ext.test"],
        "2026-10-01T11:00:00Z",
        Some("2026-10-01T09:00:00Z"),
        "2026-10-01T09:00:00Z",
        Some("<dup@trace.test>"),
        false,
    ),
    (
        "out2",
        "pending",
        &["new1@ext.test", "new2@ext.test"],
        "2026-10-01T11:00:00Z",
        None,
        "2026-10-01T09:30:00Z",
        Some("<dup@trace.test>"),
        true,
    ),
    (
        "out2",
        "pending",
        &["legacy@ext.test"],
        "2026-10-01T11:00:00Z",
        None,
        "2026-10-01T09:45:00Z",
        Some("<legacy@trace.test>"),
        false,
    ),
];

pub async fn seed(
    owner: &tokio_postgres::Client,
    a: &Account,
    b: &Account,
    action: &str,
    label: &str,
) -> Result<Seed, BoxError> {
    let mut stash = vec![];
    for table in ["message_trace", "outbound_queue"] {
        for row in owner
            .query(&format!("SELECT to_jsonb(t)::text FROM {table} t"), &[])
            .await?
        {
            stash.push(format!("{table}\t{}", row.get::<_, String>(0)));
        }
    }
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM message_trace; DELETE FROM outbound_queue; COMMIT;")
        .await?;
    // `message_trace` is partitioned by month: make sure October 2026 has its partition.
    owner
        .batch_execute(
            "DO $$ BEGIN \
              IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'message_trace_2026_10') THEN \
               EXECUTE 'CREATE TABLE message_trace_2026_10 PARTITION OF message_trace FOR VALUES FROM (''2026-09-30 00:00:00+00'') TO (''2026-11-01 00:00:00+00'')'; \
              END IF; END $$;",
        )
        .await
        .ok();
    owner
        .execute(
            "SELECT setval('message_trace_id_seq', $1)",
            &[&(3_000_000 + a.user * 10)],
        )
        .await?;
    let mut names: Vec<(&'static str, i64, String)> = vec![];
    let mut vars = std::collections::BTreeMap::new();
    if label != "empty" {
        for (n, (mid, event, from, rcpt, host, details, when)) in TRACES.iter().enumerate() {
            let id: i64 = owner
                .query_one(
                    "INSERT INTO message_trace (message_id,event,from_addr,rcpt_addr,remote_host,details,occurred_at) VALUES ($1,$2,$3,$4,$5,$6::text::jsonb,$7::text::timestamptz) RETURNING id",
                    &[mid, event, from, rcpt, host, details, when],
                )
                .await?
                .get(0);
            let key: &'static str = [
                "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10", "t11", "t12", "t13",
                "t14",
            ][n];
            vars.insert(key, id);
            names.push(("id", id, format!("<{key}>")));
        }
    }
    // Messages: the actor's, plus one that belongs to the other tenant.
    let mut pks: std::collections::BTreeMap<&str, i64> = Default::default();
    for m in &MESSAGES {
        let pk = insert_message(owner, a, m.key, m.subject, m.sent).await?;
        pks.insert(m.key, pk);
        let key: &'static str = m.key;
        vars.insert(key, pk);
        names.push(("id", pk, format!("<{}>", m.key)));
    }
    let other = insert_message(owner, b, "bm1", Some("Other tenant"), false).await?;
    vars.insert("bm1", other);
    names.push(("id", other, "<bm1>".into()));
    for (key, status, rcpts, next, delivered, queued, mid, with_pk) in QUEUES {
        let rcpts: Vec<String> = rcpts.iter().map(|r| (*r).to_owned()).collect();
        let message_id = mid.map_or_else(|| format!("<{key}@trace.test>"), str::to_owned);
        let pk: Option<i64> = with_pk.then(|| pks[key]);
        owner
            .execute(
                "INSERT INTO outbound_queue (message_id,from_addr,rcpt_addrs,raw_ref,status,attempt_count,next_attempt_at,last_error,queued_at,delivered_at,mailbox_id,message_pk) \
                 VALUES ($1,'me@x.test',$2,$3,$4,2,$5::text::timestamptz,CASE WHEN $4='deferred' THEN 'temp <fail> & retry' END,$6::text::timestamptz,$7::text::timestamptz,$8,$9)",
                &[&message_id, &rcpts, &format!("raw-{key}"), &status, &next, &queued, &delivered, &a.mailbox, &pk],
            )
            .await?;
    }
    for m in &MESSAGES {
        for t in attempts(m.key) {
            owner
                .execute(
                    "INSERT INTO delivery_attempts (message_pk,received_at,mailbox_id,recipient_email,mx_host,attempt_number,attempted_at,smtp_code,smtp_text,outcome,tls) \
                     VALUES ($1,$2::text::timestamptz,$3,$4,$5,$6,$7::text::timestamptz,$8,$9,$10,$11)",
                    &[&pks[m.key], &RECEIVED, &a.mailbox, &t.to, &t.mx, &t.n, &t.at, &t.code, &t.text, &t.outcome, &t.tls],
                )
                .await?;
        }
    }
    let _ = action;
    for (account, who) in [(a, "actor"), (b, "other")] {
        names.push(("mailboxId", account.mailbox, format!("<mailbox-{who}>")));
    }
    Ok(Seed { stash, names, vars })
}

/// Go's startup recovery resets every `sending` queue row to `pending`, so the `sending`
/// item exists only once the process is up (record and replay alike).
pub async fn after_start(owner: &tokio_postgres::Client, a: &Account) -> Result<(), BoxError> {
    owner
        .execute("UPDATE outbound_queue SET status='sending', last_error='reset by startup_recovery after crash' WHERE message_id='<out8@trace.test>' AND mailbox_id=$1", &[&a.mailbox])
        .await?;
    Ok(())
}

/// Removes what the case left in the global tables and restores the stash.
pub async fn teardown(
    owner: &tokio_postgres::Client,
    a: &Account,
    seed: &Seed,
) -> Result<(), BoxError> {
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM message_trace; DELETE FROM outbound_queue; COMMIT;")
        .await?;
    owner
        .execute(
            "DELETE FROM delivery_attempts WHERE mailbox_id=$1",
            &[&a.mailbox],
        )
        .await?;
    for entry in &seed.stash {
        let (table, row) = entry.split_once('\t').ok_or("stash entry")?;
        owner
            .batch_execute("BEGIN; SET LOCAL session_replication_role=replica;")
            .await?;
        owner
            .execute(
                &format!("INSERT INTO {table} SELECT * FROM jsonb_populate_record(NULL::{table}, $1::text::jsonb)"),
                &[&row],
            )
            .await?;
        owner.batch_execute("COMMIT;").await?;
    }
    Ok(())
}

fn list_query(label: &str) -> String {
    match label {
        "from" => "?from=ALICE",
        "to" => "?to=y.test",
        "from-wildcard" => "?from=%25%40x",
        "to-underscore" => "?to=_y.test",
        "event" => "?event=deferred",
        "event-none" => "?event=Deferred",
        "status" => "?status=ok",
        "subject" => "?subject=hello",
        "subject-wildcard" => "?subject=100%25_s",
        "subject-unicode" => "?subject=h%C3%B4tel",
        "combined" => "?from=x.test&to=y.test&event=received&status=ok",
        "no-match" => "?from=zzz-no-match",
        "date-from" => "?dateFrom=2026-10-01T10:00:05Z",
        "date-to" => "?dateTo=2026-10-01T10:00:05Z",
        "date-range" => "?dateFrom=2026-10-01T10:00:02Z&dateTo=2026-10-01T10:00:06Z",
        "date-offset" => "?dateFrom=2026-10-01T12:00:05%2B02:00",
        "date-fraction" => "?dateFrom=2026-10-01T10:00:00.4Z&dateTo=2026-10-01T10:00:00.6Z",
        "date-micro" => "?dateFrom=2026-10-02T10:05:00.123456Z&dateTo=2026-10-02T10:05:00.1234569Z",
        "bad-date" => "?dateFrom=yesterday&dateTo=2026-13-01T00:00:00Z",
        "date-space" => "?dateFrom=2026-10-01%2010:00:05Z",
        "date-lower" => "?dateFrom=2026-10-01t10:00:05z",
        "date-offset-24" => "?dateFrom=2026-10-01T10:00:00%2B24:00",
        "limit" => "?limit=3",
        "offset" => "?limit=3&offset=3",
        "big-limit" => "?limit=201",
        "max-limit" => "?limit=200",
        "bad-limit" => "?limit=abc&offset=zz",
        "zero-limit" => "?limit=0",
        "negative-offset" => "?offset=-5",
        "huge-offset" => "?offset=3000000000",
        "past-end" => "?offset=1000",
        "plus-limit" => "?limit=%2B2",
        "ignored-query" => "?x=%zz&sort=id&dir=asc",
        "bad-utf8-from" => "?from=%ff",
        "bad-utf8-subject" => "?subject=%c3",
        "bad-utf8-status" => "?status=%ff",
        "bad-utf8-event" => "?event=%80",
        "bad-utf8-to" => "?to=%ff",
        "nul-byte" => "?from=a%00b",
        "bad-utf8-date" => "?dateFrom=%ff",
        _ => "",
    }
    .into()
}

fn timeline_id(label: &str) -> &'static str {
    match label {
        "queue-deferred" => "%3Cout5%40trace.test%3E",
        "queue-bounced" => "%3Cout6%40trace.test%3E",
        "queue-pending" => "%3Cout2%40trace.test%3E",
        "queue-skew" => "%3Cout3%40trace.test%3E",
        "queue-sending" => "%3Cout8%40trace.test%3E",
        "queue-legacy" => "%3Clegacy%40trace.test%3E",
        "queue-latest" => "%3Cdup%40trace.test%3E",
        "events-only" => "%3Ctl2%40trace.test%3E",
        "events-null-details" => "%3Ca%25b_c%40trace.test%3E",
        "events-json-null" => "%3Ct%2C6%40trace.test%3E",
        "events-array" => "%3Ct7%40trace.test%3E",
        "events-nested" => "%3Ct9%40trace.test%3E",
        "unknown" => "%3Cnope%40trace.test%3E",
        "plain-id" => "plain",
        "wildcard-id" => "%25",
        "unescaped-id" => "%3Cout1@trace.test%3E",
        "bad-utf8" => "%ff",
        "nul-byte" => "a%00b",
        "case-sensitive" => "%3COUT1%40trace.test%3E",
        "undo" => "%3Cout4%40trace.test%3E",
        "nothing" => "%3Cout7%40trace.test%3E",
        "slash-id" => "a%2Fb",
        "dot-id" => "..",
        _ => "%3Cout1%40trace.test%3E",
    }
}

fn user_id(label: &str, seed: &Seed) -> String {
    let var = |k: &str| seed.vars.get(k).copied().unwrap_or(0);
    match label {
        "other" => var("bm1").to_string(),
        "missing" => "999999999".into(),
        "bad-id" => "abc".into(),
        "float-id" => "1.5".into(),
        "huge-id" => "99999999999999999999".into(),
        "negative-id" => "-4".into(),
        "plus-id" => format!("%2B{}", var("in1")),
        "inbound-subject" => var("in2").to_string(),
        "inbound-nosubject" => var("in3").to_string(),
        l if l.starts_with("sent-") => {
            let key = match l {
                "sent-delivered" => "out1",
                "sent-pending" => "out2",
                "sent-skew" => "out3",
                "sent-undo" => "out4",
                "sent-deferred" => "out5",
                "sent-bounced" => "out6",
                "sent-nothing" => "out7",
                "sent-sending" => "out8",
                _ => "out1",
            };
            var(key).to_string()
        }
        _ => var("in1").to_string(),
    }
}

pub fn request(action: &str, label: &str, seed: &Seed) -> Req {
    let (_, pattern) = route(action);
    let mut req = Req {
        path: pattern.to_owned(),
        query: String::new(),
        recorded_query: String::new(),
        body: String::new(),
        recorded_body: String::new(),
        headers: vec![],
    };
    match action {
        "list" | "export" => req.query = list_query(label.strip_prefix("csv-").unwrap_or(label)),
        "timeline" => {
            req.path = pattern.replace("{messageId}", timeline_id(label));
        }
        "user" => {
            req.path = pattern.replace("{emailId}", &user_id(label, seed));
            if label == "inbound-cookie" {
                req.headers
                    .push(("cookie".into(), "sid=trace-cookie".into()));
            }
        }
        _ => panic!("unknown trace action {action}"),
    }
    req
}

pub async fn snapshot(
    owner: &tokio_postgres::Client,
    _a: &Account,
    _b: &Account,
    _seed: &Seed,
) -> Result<Value, BoxError> {
    let text: String = owner
        .query_one(
            "SELECT jsonb_build_object('message_trace',(SELECT count(*) FROM message_trace),\
             'outbound_queue',(SELECT COALESCE(jsonb_agg(jsonb_build_array(q.message_id,q.status,q.attempt_count) ORDER BY q.id),'[]'::jsonb) FROM outbound_queue q),\
             'delivery_attempts',(SELECT count(*) FROM delivery_attempts))::text",
            &[],
        )
        .await?
        .get(0);
    Ok(serde_json::from_str(&text)?)
}

/// The masks beyond the shared ones: the run's mailbox id in the download link and the
/// percent-encoded `+id` a path id may carry.
pub fn mask_text(text: &str, a: &Account, b: &Account, seed: &Seed) -> String {
    let plus = format!("%2B{}", seed.vars.get("in1").copied().unwrap_or(0));
    text.replace(&plus, "%2B<in1>")
        .replace(
            &format!("/download/{}/", a.mailbox),
            "/download/<mailbox-actor>/",
        )
        .replace(
            &format!("/download/{}/", b.mailbox),
            "/download/<mailbox-other>/",
        )
}

// ---- the loopback JMAP download stand-in ----

fn received(host: &str, by: &str, date: &str) -> String {
    format!("Received: from {host} (mx.{host} [203.0.113.5]) by {by} with ESMTPS id 1; {date}\r\n")
}

/// The body served for a label (`None` answers 404 for every request).
fn jmap_body(label: &str) -> Option<Vec<u8>> {
    let chain = format!(
        "{}{}{}Subject: x\r\nFrom: a@b.c\r\n\r\nbody text\r\n",
        received("edge.test", "mail.test", "Mon, 02 Oct 2026 10:00:03 +0000"),
        received(
            "relay.example",
            "edge.test",
            "Mon, 02 Oct 2026 10:00:02 +0000"
        ),
        received(
            "origin.example",
            "relay.example",
            "Mon, 02 Oct 2026 10:00:00 +0100"
        ),
    );
    Some(match label {
        "inbound-empty" => vec![],
        "inbound-no-received" => b"Subject: x\r\nFrom: a@b.c\r\n\r\nbody\r\n".to_vec(),
        "inbound-hostile" => b"Subject: x\r\ngarbage line\r\nReceived: from a.example by mailserver; Mon, 02 Oct 2026 10:00:00 +0000\r\nReceived: bad\x01ctl\r\n\r\n".to_vec(),
        "inbound-space-start" => b" Received: from a by b\r\n\r\n".to_vec(),
        "inbound-folded" => b"Received: from a.example (x.example [10.0.0.1])\r\n\tby mailserver with ESMTP\r\n  id 7; Mon, 02 Oct 2026\r\n 10:00:00 +0000\r\n\r\n".to_vec(),
        "inbound-dates" => format!(
            "{}{}{}{}{}",
            received("h1.example", "mail.test", "Mon, 02 Oct 2026 10:00:00 +0000"),
            received("h2.example", "h1.example", "Mon, 02 Oct 2026 09:59:50 +0000"),
            received("h3.example", "h2.example", "garbage"),
            received("h4.example", "h3.example", "2 Oct 26 10:00 EST"),
            received("h5.example", "h4.example", "Mon, 02 Oct 2026 10:00:00.5 -0700 (PDT)"),
        )
        .into_bytes(),
        "inbound-year-overflow" => format!(
            "{}{}",
            received("h1.example", "mail.test", "Fri, 31 Dec 9999 23:59:59 -0100"),
            received("h2.example", "h1.example", "Mon, 02 Oct 2026 10:00:00 +0000"),
        )
        .into_bytes(),
        "inbound-invalid-utf8" => {
            let mut v = b"Received: from a.example by mailserver (\xff\xfe) with SMTP; Mon, 02 Oct 2026 10:00:00 +0000\r\n\r\n".to_vec();
            v.extend_from_slice(b"body\xff");
            v
        }
        "inbound-many" => {
            let mut s = String::new();
            for i in 0..105 {
                s += &received(&format!("h{i}.example"), "mail.test", &format!("Mon, 02 Oct 2026 10:{:02}:00 +0000", i % 60));
            }
            s += "\r\n";
            s.into_bytes()
        }
        "inbound-long-line" => format!(
            "Received: from {} by mailserver; Mon, 02 Oct 2026 10:00:00 +0000\r\n\r\n",
            "a".repeat(5000)
        )
        .into_bytes(),
        // More than the 1 MiB cap: the second Received header lies past it.
        "inbound-big" => {
            let mut s = received("first.example", "mail.test", "Mon, 02 Oct 2026 10:00:00 +0000");
            while s.len() < (1 << 20) + 4096 {
                s += &format!("X-Pad: {}\r\n", "p".repeat(900));
            }
            s += &received("late.example", "mail.test", "Mon, 02 Oct 2026 10:00:09 +0000");
            s.into_bytes()
        }
        "inbound-non200" | "inbound-server-error" => return None,
        _ => chain.into_bytes(),
    })
}

/// Starts the stand-in on 127.0.0.1:80 (Go's hard-coded base) for the labels that reach it.
pub async fn jmap_standin(
    label: &str,
    a: &Account,
    seed: &Seed,
    token: &str,
) -> Result<Option<tokio::task::JoinHandle<()>>, BoxError> {
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    if !label.starts_with("inbound") || label == "inbound-no-listener" {
        return Ok(None);
    }
    let subject = match label {
        "inbound-subject" => "Re__h_llo___x__.eml",
        "inbound-nosubject" => "message",
        _ => "Inbound_hello",
    };
    let key = match label {
        "inbound-subject" => "in2",
        "inbound-nosubject" => "in3",
        _ => "in1",
    };
    let _ = seed;
    let want_path = format!("/jmap/download/{}/raw-{key}/{subject}.eml", a.mailbox);
    let want_auth = format!("Bearer {token}");
    let cookie = label == "inbound-cookie";
    let status: u16 = match label {
        "inbound-non200" => 404,
        "inbound-server-error" => 500,
        _ => 200,
    };
    let body = jmap_body(label);
    let redirect = label == "inbound-redirect";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:80").await?;
    Ok(Some(tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (want_path, want_auth, body) = (want_path.clone(), want_auth.clone(), body.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let (want_path, want_auth, body) =
                        (want_path.clone(), want_auth.clone(), body.clone());
                    async move {
                        let auth = req
                            .headers()
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned();
                        let got_cookie = req
                            .headers()
                            .get("cookie")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned();
                        let path = req.uri().path().to_owned();
                        let ok = auth == want_auth && (!cookie || got_cookie == "sid=trace-cookie");
                        let mut response = hyper::Response::new(crate::common::full(""));
                        if redirect && path == want_path {
                            *response.status_mut() = hyper::StatusCode::FOUND;
                            response
                                .headers_mut()
                                .insert("location", "/jmap/redirected.eml".parse().unwrap());
                        } else if (redirect && path == "/jmap/redirected.eml" || path == want_path)
                            && ok
                        {
                            match &body {
                                Some(b) if status == 200 => {
                                    response = hyper::Response::new(crate::common::full(b.clone()));
                                }
                                _ => {
                                    *response.status_mut() =
                                        hyper::StatusCode::from_u16(status).unwrap()
                                }
                            }
                        } else {
                            *response.status_mut() = hyper::StatusCode::NOT_FOUND;
                        }
                        Ok::<_, std::convert::Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    })))
}
