//! #302: seed-plus-one-tick oracle for `webhook-retry` and `webhook-publications`.
//! Frozen Go's real workers (overlays in `tests/conformance/drain/`) run one tick over a
//! seeded database against in-process fake receivers; the Rust workers' `tick()` must
//! leave the same delivery, subscription and publication rows and send the same requests
//! (path, method, content type, a signature that verifies under the subscription secret,
//! the exact body bytes). The loopback receivers need the unguarded clients (Go: the
//! overlay's client; Rust: `Dispatcher::unguarded_for_tests`); the dial-time SSRF guard
//! is checked separately in `webhook_dispatch.rs`.
//!
//! Record: `GOFREE_RECORD_DRAIN=all|case,case` (+ `GOFREE_GO_SOURCE`); replay needs no Go.
mod common;
mod drain_oracle;
use drain_oracle::{settle, BoxError, GoTick};
use hyper::Response;
use serde_json::{json, Value};
use setjoin_config_secret::{seal_column, CryptoProfile};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::webhook::{Dispatcher, PublicationWorker, RetryWorker};
use setjoin_pg::workers::WorkerDatabase;
use setjoin_platform::webhook_secret::SecretCodec;
use std::sync::{Arc, Mutex};

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
const MASTER: &str = "gofree-webhook-oracle-master";
const S1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const S2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const S3: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const SECRETS: [(&str, &str); 3] = [("s1", S1), ("s2", S2), ("s3", S3)];

#[derive(Clone, Copy)]
enum Secret {
    Legacy(&'static str),
    LegacyWithPrev(&'static str, &'static str),
    Sealed(&'static str, Option<&'static str>),
    Nothing,
}

#[derive(Clone, Copy)]
struct Sub {
    label: &'static str,
    /// `a`, `b` or `org` (no owner).
    owner: &'static str,
    /// Receiver path, or `refused` for a closed port.
    path: &'static str,
    scope: &'static str,
    active: bool,
    types: &'static str,
    secret: Secret,
    retry: bool,
    max: i32,
}

const fn sub(label: &'static str, path: &'static str) -> Sub {
    Sub {
        label,
        owner: "org",
        path,
        scope: "organization",
        active: true,
        types: r#"["user.updated"]"#,
        secret: Secret::Sealed(S2, Some("v1")),
        retry: true,
        max: 12,
    }
}

#[derive(Clone, Copy)]
struct Del {
    sub: &'static str,
    event: &'static str,
    attempt: i32,
    status: &'static str,
    /// Seconds from now until the row is due (negative: overdue).
    due: i64,
    /// Lease expiry offset in seconds, when leased.
    lease: Option<i64>,
}
const fn del(sub: &'static str, event: &'static str) -> Del {
    Del { sub, event, attempt: 0, status: "pending", due: -5, lease: None }
}

#[derive(Clone, Copy)]
struct Publication {
    event: &'static str,
    kind: &'static str,
    /// `user` or `mailbox`, both about account `a`.
    audience: &'static str,
    state: &'static str,
    attempts: i32,
    due: i64,
    lease: Option<i64>,
    /// Days since completion for a terminal row.
    done_days: Option<i64>,
}
const fn publication(event: &'static str) -> Publication {
    Publication { event, kind: "user.updated", audience: "user", state: "pending", attempts: 0, due: -5, lease: None, done_days: None }
}

struct Case {
    name: &'static str,
    worker: &'static str,
    subs: &'static [Sub],
    dels: &'static [Del],
    pubs: &'static [Publication],
}

macro_rules! subs { ($($e:expr),* $(,)?) => { &[$($e),*] }; }

const CASES: &[Case] = &[
    Case { name: "webhook-retry-legacy-secret-lazy-seal", worker: "retry",
        subs: subs![Sub { secret: Secret::LegacyWithPrev(S1, S3), ..sub("a", "/ok") }],
        dels: &[del("a", "evt_lazy")], pubs: &[] },
    Case { name: "webhook-retry-sealed-secret-created", worker: "retry",
        subs: subs![sub("a", "/created")], dels: &[del("a", "evt_sealed")], pubs: &[] },
    Case { name: "webhook-retry-server-error-backoff", worker: "retry",
        subs: subs![sub("a", "/five")], dels: &[del("a", "evt_five")], pubs: &[] },
    Case { name: "webhook-retry-unavailable-and-rate-limited", worker: "retry",
        subs: subs![sub("a", "/busy"), sub("b", "/limit")],
        dels: &[del("a", "evt_busy"), del("b", "evt_limit")], pubs: &[] },
    Case { name: "webhook-retry-client-error-exhausted", worker: "retry",
        subs: subs![sub("a", "/missing")], dels: &[del("a", "evt_missing")], pubs: &[] },
    Case { name: "webhook-retry-redirect-not-followed", worker: "retry",
        subs: subs![sub("a", "/moved")], dels: &[del("a", "evt_moved")], pubs: &[] },
    Case { name: "webhook-retry-response-body-truncated", worker: "retry",
        subs: subs![sub("a", "/big")], dels: &[del("a", "evt_big")], pubs: &[] },
    Case { name: "webhook-retry-connection-refused", worker: "retry",
        subs: subs![sub("a", "refused")], dels: &[del("a", "evt_refused")], pubs: &[] },
    Case { name: "webhook-retry-short-secret-exhausted", worker: "retry",
        subs: subs![Sub { secret: Secret::Legacy("short"), ..sub("a", "/ok") }],
        dels: &[del("a", "evt_short")], pubs: &[] },
    Case { name: "webhook-retry-no-secret-retryable", worker: "retry",
        subs: subs![Sub { secret: Secret::Nothing, ..sub("a", "/ok") }],
        dels: &[del("a", "evt_nosecret")], pubs: &[] },
    Case { name: "webhook-retry-unknown-key-version", worker: "retry",
        subs: subs![Sub { secret: Secret::Sealed(S2, Some("v2")), ..sub("a", "/ok") }],
        dels: &[del("a", "evt_v2")], pubs: &[] },
    Case { name: "webhook-retry-missing-key-id", worker: "retry",
        subs: subs![Sub { secret: Secret::Sealed(S2, None), ..sub("a", "/ok") }],
        dels: &[del("a", "evt_nokey")], pubs: &[] },
    Case { name: "webhook-retry-inactive-subscription", worker: "retry",
        subs: subs![Sub { active: false, ..sub("a", "/ok") }],
        dels: &[del("a", "evt_inactive")], pubs: &[] },
    Case { name: "webhook-retry-retries-disabled", worker: "retry",
        subs: subs![Sub { retry: false, ..sub("a", "/five") }],
        dels: &[del("a", "evt_first"), Del { attempt: 1, status: "failed", due: -5, ..del("a", "evt_failed_before") }],
        pubs: &[] },
    Case { name: "webhook-retry-future-attempt-untouched", worker: "retry",
        subs: subs![sub("a", "/ok")],
        dels: &[Del { due: 3600, ..del("a", "evt_later") }], pubs: &[] },
    Case { name: "webhook-retry-expired-lease-reclaimed", worker: "retry",
        subs: subs![sub("a", "/ok")],
        dels: &[Del { attempt: 1, lease: Some(-30), ..del("a", "evt_lease") }], pubs: &[] },
    Case { name: "webhook-retry-expired-lease-retries-off", worker: "retry",
        subs: subs![Sub { retry: false, ..sub("a", "/ok") }],
        dels: &[Del { attempt: 1, lease: Some(-30), ..del("a", "evt_lease_off") }], pubs: &[] },
    Case { name: "webhook-retry-failed-row-redelivered", worker: "retry",
        subs: subs![sub("a", "/ok")],
        dels: &[Del { attempt: 2, status: "failed", ..del("a", "evt_again") }], pubs: &[] },
    Case { name: "webhook-retry-attempt-limit", worker: "retry",
        subs: subs![Sub { max: 3, ..sub("a", "/ok") }],
        dels: &[Del { attempt: 3, status: "failed", ..del("a", "evt_limit_reached") }], pubs: &[] },
    Case { name: "webhook-retry-two-subscribers", worker: "retry",
        subs: subs![sub("a", "/ok"), sub("b", "/five")],
        dels: &[del("a", "evt_both"), del("b", "evt_both")], pubs: &[] },
    Case { name: "webhook-retry-idle", worker: "retry", subs: subs![sub("a", "/ok")], dels: &[], pubs: &[] },
    Case { name: "webhook-publication-fanout-and-immediate-delivery", worker: "publication",
        subs: subs![
            sub("org", "/org"),
            Sub { owner: "a", scope: "self", ..sub("self-a", "/self-a") },
            Sub { owner: "b", scope: "self", ..sub("self-b", "/self-b") },
            Sub { active: false, ..sub("inactive", "/inactive") },
            Sub { types: r#"["mail.received"]"#, ..sub("other-type", "/other-type") },
        ],
        dels: &[], pubs: &[publication("evt_pub_one")] },
    Case { name: "webhook-publication-mailbox-audience", worker: "publication",
        subs: subs![sub("org", "/org"), Sub { owner: "a", scope: "self", ..sub("self-a", "/self-a") }],
        dels: &[], pubs: &[Publication { audience: "mailbox", kind: "user.updated", ..publication("evt_pub_mailbox") }] },
    Case { name: "webhook-publication-no-subscribers", worker: "publication",
        subs: subs![], dels: &[], pubs: &[publication("evt_pub_none")] },
    Case { name: "webhook-publication-existing-delivery-kept", worker: "publication",
        subs: subs![sub("org", "/org")],
        dels: &[Del { attempt: 1, status: "success", due: -5, ..del("org", "evt_pub_dup") }],
        pubs: &[publication("evt_pub_dup")] },
    Case { name: "webhook-publication-attempts-exhausted", worker: "publication",
        subs: subs![sub("org", "/org")], dels: &[],
        pubs: &[Publication { attempts: 12, ..publication("evt_pub_spent") }] },
    Case { name: "webhook-publication-expired-lease-reclaimed", worker: "publication",
        subs: subs![sub("org", "/org")], dels: &[],
        pubs: &[Publication { state: "leased", attempts: 2, lease: Some(-30), ..publication("evt_pub_lease") }] },
    Case { name: "webhook-publication-not-due", worker: "publication",
        subs: subs![sub("org", "/org")], dels: &[],
        pubs: &[Publication { due: 3600, ..publication("evt_pub_later") }] },
    Case { name: "webhook-publication-prune-old-terminal-rows", worker: "publication",
        subs: subs![], dels: &[],
        pubs: &[
            Publication { state: "delivered", done_days: Some(40), ..publication("evt_pub_old_done") },
            Publication { state: "exhausted", done_days: Some(40), ..publication("evt_pub_old_spent") },
            Publication { state: "delivered", done_days: Some(10), ..publication("evt_pub_new_done") },
        ] },
    Case { name: "webhook-publication-idle", worker: "publication", subs: subs![], dels: &[], pubs: &[] },
];

type Seen = Arc<Mutex<Vec<Value>>>;

fn signature_label(header: &str, body: &str) -> String {
    use hmac::{Hmac, Mac};
    let Some(rest) = header.strip_prefix("v1,t=") else { return "<missing-or-malformed>".into() };
    let Some((t, sig)) = rest.split_once(",sig=") else { return "<malformed>".into() };
    for (label, secret) in SECRETS {
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{t}.{body}").as_bytes());
        let expected: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
        if expected == sig {
            return format!("<valid:{label}>");
        }
    }
    "<invalid>".into()
}

async fn receiver(seen: Seen) -> std::net::SocketAddr {
    use http_body_util::BodyExt;
    common::fake_upstream(move |request| {
        let seen = seen.clone();
        async move {
            let path = request.uri().path().to_owned();
            let method = request.method().to_string();
            let header = |name: &str| request.headers().get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_owned();
            let (content_type, signature) = (header("content-type"), header("x-webhook-signature"));
            let body = String::from_utf8(request.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
            seen.lock().unwrap().push(json!({
                "path": path, "method": method, "content_type": content_type,
                "signature": signature_label(&signature, &body), "body": body,
            }));
            let reply = |status: u16, text: String| Response::builder().status(status).body(common::full(text)).unwrap();
            match path.as_str() {
                "/created" => reply(201, "created".into()),
                "/five" => reply(500, "boom".into()),
                "/busy" => reply(503, "busy".into()),
                "/limit" => reply(429, "slow down".into()),
                "/missing" => reply(404, "nope".into()),
                "/moved" => Response::builder().status(302).header("location", "/ok").body(common::full("")).unwrap(),
                "/big" => reply(200, "x".repeat(5000)),
                _ => reply(200, "ok".into()),
            }
        }
    })
    .await
}

fn norm_error(text: &str) -> String {
    if text.starts_with("Post ") && text.contains("onnect") {
        return "<transport:refused>".into();
    }
    // `subscription 12 holds no usable signing secret`: the id is run-specific.
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = rest.find("subscription ") {
        let (head, tail) = rest.split_at(i + "subscription ".len());
        out.push_str(head);
        let digits = tail.chars().take_while(char::is_ascii_digit).count();
        if digits > 0 { out.push_str("<id>"); }
        rest = &tail[digits..];
    }
    out.push_str(rest);
    out
}

async fn observe(owner: &tokio_postgres::Client, seen: &Seen, ids: &[(i64, &str)]) -> Result<Value, BoxError> {
    let label_of = |id: i64| ids.iter().find(|(i, _)| *i == id).map_or("<unknown>".to_string(), |(_, l)| l.to_string());
    let mut deliveries = Vec::new();
    for row in owner
        .query(
            "SELECT subscription_id,event_id,event_type,request_body::text,response_code,response_body,latency_ms,attempt,status,error_message,\
             lease_owner IS NOT NULL,completed_at IS NOT NULL,\
             CASE WHEN status<>'failed' OR completed_at IS NULL THEN NULL ELSE round(extract(epoch FROM next_attempt_at-completed_at)*1000)::bigint END, \
             next_attempt_at>now()+interval '5 minutes' FROM webhook_deliveries ORDER BY subscription_id,event_id",
            &[],
        )
        .await?
    {
        let error: Option<String> = row.get(9);
        deliveries.push(json!({
            "subscription": label_of(row.get(0)), "event_id": row.get::<_, String>(1), "event_type": row.get::<_, String>(2),
            "request_body": row.get::<_, String>(3), "response_code": row.get::<_, Option<i32>>(4),
            "response_body": row.get::<_, Option<String>>(5), "latency_recorded": row.get::<_, Option<i32>>(6).is_some(),
            "attempt": row.get::<_, i32>(7), "status": row.get::<_, String>(8), "error": error.map(|e| norm_error(&e)),
            "leased": row.get::<_, bool>(10), "completed": row.get::<_, bool>(11),
            "backoff_ms": row.get::<_, Option<i64>>(12), "due_far_future": row.get::<_, bool>(13),
        }));
    }
    let mut subscriptions = Vec::new();
    for row in owner
        .query("SELECT id,secret IS NOT NULL,prev_secret IS NOT NULL,secret_enc IS NOT NULL,secret_key_id,prev_secret_enc IS NOT NULL,prev_secret_key_id FROM webhook_subscriptions ORDER BY id", &[])
        .await?
    {
        subscriptions.push(json!({
            "label": label_of(row.get(0)), "legacy_secret": row.get::<_, bool>(1), "legacy_prev": row.get::<_, bool>(2),
            "sealed": row.get::<_, bool>(3), "key_id": row.get::<_, Option<String>>(4),
            "sealed_prev": row.get::<_, bool>(5), "prev_key_id": row.get::<_, Option<String>>(6),
        }));
    }
    let mut publications = Vec::new();
    for row in owner
        .query("SELECT event_id,state,attempt_count,last_error,completed_at IS NOT NULL,lease_owner IS NOT NULL FROM webhook_publications ORDER BY event_id", &[])
        .await?
    {
        publications.push(json!({
            "event_id": row.get::<_, String>(0), "state": row.get::<_, String>(1), "attempts": row.get::<_, i32>(2),
            "last_error": row.get::<_, Option<String>>(3), "completed": row.get::<_, bool>(4), "leased": row.get::<_, bool>(5),
        }));
    }
    let mut requests: Vec<Value> = seen.lock().unwrap().clone();
    requests.sort_by_key(|r| (r["path"].as_str().unwrap().to_owned(), r["body"].as_str().unwrap().to_owned()));
    Ok(json!({"deliveries":deliveries,"subscriptions":subscriptions,"publications":publications,"requests":requests}))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webhook_workers_seed_plus_one_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("webhook-workers-tick") else { return Ok(()) };
    let owner = db.connect().await?;
    let record = std::env::var("GOFREE_RECORD_DRAIN").ok();
    let only = std::env::var("GOFREE_DRAIN_ONLY").ok();
    let listed = |filter: &Option<String>, name: &str| {
        filter.as_deref().is_none_or(|f| f == "all" || f.split(',').any(|t| t == name))
    };
    let a = fixture::account(&owner, "plat4w-a").await?;
    let b = fixture::account(&owner, "plat4w-b").await?;
    let (mut failures, mut ran) = (Vec::new(), 0);
    for case in CASES {
        let recording = record.is_some() && listed(&record, case.name);
        if record.is_some() && !recording || !listed(&only, case.name) {
            continue;
        }
        ran += 1;
        let result = run_case(&db, &owner, case, &a, &b, recording).await;
        let _ = owner.batch_execute("DELETE FROM webhook_deliveries; DELETE FROM webhook_subscriptions; DELETE FROM webhook_publications").await;
        if let Err(error) = result {
            failures.push(format!("{}: {error}", case.name));
        }
    }
    for account in [&a, &b] {
        common::remove_blob_account(&owner, account).await?;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(ran > 0, "no case selected");
    Ok(())
}

async fn run_case(db: &Db, owner: &tokio_postgres::Client, case: &Case, a: &fixture::Account, b: &fixture::Account, recording: bool) -> Result<(), BoxError> {
    owner.batch_execute("DELETE FROM webhook_deliveries; DELETE FROM webhook_subscriptions; DELETE FROM webhook_publications").await?;
    let seen: Seen = Arc::default();
    let hook = receiver(seen.clone()).await;
    // A port nothing listens on: the connection is refused.
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.local_addr()?
    };
    let mut ids: Vec<(i64, &str)> = Vec::new();
    for s in case.subs {
        let url = if s.path == "refused" { format!("http://{closed}/refused") } else { format!("http://{hook}{}", s.path) };
        let user: Option<i64> = match s.owner { "a" => Some(a.user), "b" => Some(b.user), _ => None };
        let (legacy, prev_legacy, enc, key): (Option<&str>, Option<&str>, Option<Vec<u8>>, Option<&str>) = match s.secret {
            Secret::Legacy(v) => (Some(v), None, None, None),
            Secret::LegacyWithPrev(v, p) => (Some(v), Some(p), None, None),
            Secret::Sealed(v, key) => (None, None, Some(seal_column(v.as_bytes(), MASTER.as_bytes(), CryptoProfile::Standard)?), key),
            Secret::Nothing => (None, None, None, None),
        };
        let id: i64 = owner
            .query_one(
                "INSERT INTO webhook_subscriptions(user_id,url,secret,prev_secret,secret_enc,secret_key_id,event_types,scope,is_active,retry_enabled,max_retries) \
                 VALUES($1,$2,$3,$4,$5,$6,$7::text::jsonb,$8,$9,$10,$11) RETURNING id",
                &[&user, &url, &legacy, &prev_legacy, &enc, &key, &s.types, &s.scope, &s.active, &s.retry, &s.max],
            )
            .await?
            .get(0);
        ids.push((id, s.label));
    }
    let id_of = |label: &str| ids.iter().find(|(_, l)| *l == label).map(|(i, _)| *i).unwrap();
    for d in case.dels {
        let body = format!(r#"{{"specversion":"1.0","id":"{0}","source":"mailserver/test","type":"user.updated","time":"2026-10-01T10:00:00Z","datacontenttype":"application/json","data":{{"user_id":7,"note":"café <b> & more"}}}}"#, d.event);
        owner
            .execute(
                "INSERT INTO webhook_deliveries(subscription_id,event_id,event_type,request_body,attempt,status,next_attempt_at,lease_owner,lease_expires_at) \
                 VALUES($1,$2,'user.updated',$3::text::jsonb,$4,$5,now()+($6::bigint*interval '1 second'),CASE WHEN $7::bigint IS NULL THEN NULL ELSE gen_random_uuid() END,CASE WHEN $7::bigint IS NULL THEN NULL ELSE now()+($7::bigint*interval '1 second') END)",
                &[&id_of(d.sub), &d.event, &body, &d.attempt, &d.status, &d.due, &d.lease],
            )
            .await?;
    }
    for p in case.pubs {
        let mailbox: Option<i64> = (p.audience == "mailbox").then_some(a.mailbox);
        owner
            .execute(
                "INSERT INTO webhook_publications(event_id,event_type,source,audience,subject_user_id,subject_mailbox_id,payload,state,attempt_count,next_attempt_at,lease_owner,lease_expires_at,completed_at,created_at) \
                 VALUES($1,$2,'mailserver/test',$3,$4,$5,'{\"user_id\":7,\"note\":\"caf\\u00e9 <b>\"}'::jsonb,$6,$7,now()+($8::bigint*interval '1 second'),\
                 CASE WHEN $9::bigint IS NULL THEN NULL ELSE gen_random_uuid() END,CASE WHEN $9::bigint IS NULL THEN NULL ELSE now()+($9::bigint*interval '1 second') END,\
                 CASE WHEN $10::bigint IS NULL THEN NULL ELSE now()-($10::bigint*interval '1 day') END,'2026-10-01T10:00:00Z')",
                &[&p.event, &p.kind, &p.audience, &a.user, &mailbox, &p.state, &p.attempts, &p.due, &p.lease, &p.done_days],
            )
            .await?;
    }
    if recording {
        let (test, overlay, file) = if case.worker == "retry" {
            ("TestGoFreeWebhookRetryTick", "webhook_retry_tick_test.go.txt", "gofree_webhook_retry_tick_test.go")
        } else {
            ("TestGoFreeWebhookPublicationTick", "webhook_publication_tick_test.go.txt", "gofree_webhook_publication_tick_test.go")
        };
        GoTick {
            package: "internal/webhook",
            overlay,
            test,
            file,
            env: vec![("GOFREE_DRAIN_DSN".into(), db.dsn.clone()), ("GOFREE_WEBHOOK_MASTER".into(), MASTER.into())],
            docker: vec![],
        }
        .run()?;
    } else {
        let dispatcher = Dispatcher::unguarded_for_tests(
            WorkerDatabase::new(&db.dsn)?,
            Some(SecretCodec::new(MASTER.as_bytes(), CryptoProfile::Standard)),
        );
        if case.worker == "retry" {
            RetryWorker::new(dispatcher.clone()).tick().await;
        } else {
            PublicationWorker::new(dispatcher.clone()).tick().await;
        }
        dispatcher.shutdown().await;
    }
    let observation = observe(owner, &seen, &ids).await?;
    settle(case.name, observation, recording)
}
