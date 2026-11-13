//! Webhook delivery executor and the `webhook-publications` and `webhook-retry`
//! workers (#302), a port of frozen Go's `mailserver/internal/webhook` over
//! `shared/webhook` and `shared/ssrf`.
//!
//! One [`Dispatcher`] per process. Its fixed executor (8 delivery tasks, a queue of 8, 16
//! admission tokens) starts lazily on the first submit or claim, so Rust request
//! handlers can dispatch without owning the durable workers. Durable rows are claimed
//! through `webhook_delivery_claim` and settled through `webhook_delivery_complete`
//! (leases and SKIP LOCKED make several processes safe); legacy best-effort events keep
//! Go's upsert log. The signing secret is opened per delivery through the process codec
//! (never copied into a claim); a subscription whose secret cannot be opened is skipped
//! (legacy) or settled retryable (durable), and nothing is sent. Outbound HTTP refuses
//! non-public addresses at dial time (the guard that also defeats DNS rebinding) and
//! never follows redirects.
//!
//! The workers are cross-tenant and use the worker credential only. They are not
//! process-local: Go's copy must be off (`GO_WORKERS_OFF`) before Rust runs one.
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use serde::Deserialize;
use serde_json::{value::RawValue, Value};
use setjoin_pg::{
    workers::{WorkerConnection, WorkerDatabase},
    Type,
};
use setjoin_platform::webhook_secret::{load_subscription_secret, sign, SecretCodec};
use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

pub const PUBLICATIONS: &str = "webhook-publications";
pub const RETRY: &str = "webhook-retry";
/// Go's `deliveryTimeout`: one attempt (HTTP and log write).
pub const DELIVERY_TIMEOUT: Duration = Duration::from_secs(30);
/// Go's `retryTickInterval`, deliberately longer than a delivery.
pub const RETRY_TICK: Duration = Duration::from_secs(60);
const SETTLEMENT_TIMEOUT: Duration = Duration::from_secs(5);
const BATCH: usize = 100;
const WORKERS: usize = 8;
const QUEUE: usize = WORKERS;
const POLL: Duration = Duration::from_secs(5);
const PRUNE_EVERY: Duration = Duration::from_secs(12 * 60 * 60);

fn warn(what: &str, detail: impl std::fmt::Display) {
    eprintln!("webhook: {what}: {detail}");
}

/// Go's `ssrf.safeControl` as a resolver: only public addresses survive.
pub(crate) struct PublicOnly;
impl Resolve for PublicOnly {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let found: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .filter(|a| !crate::ssrf::blocked(a.ip()))
                .collect();
            if found.is_empty() {
                return Err("URL is not allowed (must be http/https to a public host)".into());
            }
            Ok(Box::new(found.into_iter()) as Addrs)
        })
    }
}

/// Go's `ssrf.SafeHTTPClient(timeout)`: public addresses only, no proxy, redirects not followed.
pub(crate) fn safe_http_client(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .dns_resolver(Arc::new(PublicOnly))
        .connect_timeout(Duration::from_secs(10))
        .timeout(timeout)
        .build()
        .expect("ssrf client")
}

/// A CloudEvents 1.0 envelope (`shared/webhook.CloudEvent`).
pub struct CloudEvent {
    pub id: String,
    pub source: String,
    pub kind: String,
    pub time: String,
    pub data: Value,
    /// Data kept as the producer's exact JSON text (Go's `json.RawMessage`): it is
    /// compacted, not re-ordered, when the envelope is marshalled.
    raw_data: Option<String>,
}

impl CloudEvent {
    /// An envelope with a caller-chosen id and time whose `data` is raw JSON text
    /// (frozen Go's lifecycle events carry `json.RawMessage`). `None` marshals `null`.
    pub fn with_raw_data(id: &str, source: &str, kind: &str, time: &str, raw: Option<&str>) -> Self {
        Self {
            id: id.into(),
            source: source.into(),
            kind: kind.into(),
            time: time.into(),
            data: Value::Null,
            raw_data: raw.map(str::to_owned),
        }
    }

    /// `NewCloudEvent`: `evt_` plus 13 random base-36 characters, RFC 3339 UTC time.
    pub fn new(source: &str, kind: &str, data: Value) -> Self {
        let mut random = [0u8; 13];
        getrandom::getrandom(&mut random).expect("system randomness");
        const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
        let id: String = random
            .iter()
            .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
            .collect();
        Self {
            id: format!("evt_{id}"),
            source: source.into(),
            kind: kind.into(),
            time: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            data,
            raw_data: None,
        }
    }

    /// `json.Marshal`: struct field order, map keys sorted, HTML-escaped strings.
    pub fn marshal(&self) -> String {
        format!(
            "{{\"specversion\":\"1.0\",\"id\":{},\"source\":{},\"type\":{},\"time\":{},\"datacontenttype\":\"application/json\",\"data\":{}}}",
            go_string(&self.id),
            go_string(&self.source),
            go_string(&self.kind),
            go_string(&self.time),
            match &self.raw_data {
                Some(raw) => go_compact(raw),
                None => go_value(&self.data),
            },
        )
    }
}

/// `encoding/json`'s `compact` with HTML escaping, as applied to a `json.RawMessage`:
/// insignificant whitespace is dropped; inside strings `<`, `>`, `&`, U+2028 and U+2029
/// become `\u00XX` escapes; every other byte, including existing escapes, is kept.
fn go_compact(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let (mut in_string, mut escaped) = (false, false);
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            } else if matches!(b, b'<' | b'>' | b'&') {
                out.push_str(&format!("\\u{:04x}", b));
                i += 1;
                continue;
            } else if b == 0xE2 && bytes.get(i + 1) == Some(&0x80) && matches!(bytes.get(i + 2), Some(0xA8 | 0xA9)) {
                out.push_str(&format!("\\u202{:x}", bytes[i + 2] - 0xA0));
                i += 3;
                continue;
            }
        } else if b == b'"' {
            in_string = true;
        } else if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
            continue;
        }
        // Copy one whole UTF-8 scalar so the output stays valid text.
        let width = match b {
            0..=0x7F => 1,
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            _ => 4,
        };
        out.push_str(&raw[i..i + width]);
        i += width;
    }
    out
}

fn go_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn go_value(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) if n.is_f64() => go_f64(n.as_f64().unwrap_or_default()),
        Value::Number(n) => n.to_string(),
        Value::String(s) => go_string(s),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(go_value).collect::<Vec<_>>().join(",")
        ),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            format!(
                "{{{}}}",
                keys.iter()
                    .map(|k| format!("{}:{}", go_string(k), go_value(&map[*k])))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

/// `encoding/json` float64: shortest decimal, exponent form below 1e-6 and from 1e21.
fn go_f64(f: f64) -> String {
    let abs = f.abs();
    if abs != 0.0 && (abs < 1e-6 || abs >= 1e21) {
        let text = format!("{f:e}");
        let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
        let exponent: i32 = exponent.parse().unwrap_or(0);
        let sign = if exponent < 0 { '-' } else { '+' };
        // Go writes at least two exponent digits ("1e-07"), then trims a leading zero
        // of a two-digit exponent below ten ("1e-7").
        return format!("{mantissa}e{sign}{}", exponent.abs());
    }
    format!("{f}")
}

/// Go's failure-counting circuit breaker: ten failures open it for two minutes.
#[derive(Default)]
struct Breaker {
    failures: u32,
    last_failure: Option<Instant>,
    open: bool,
}
impl Breaker {
    fn success(&mut self) {
        self.failures = 0;
        self.open = false;
    }
    fn failure(&mut self) {
        self.failures += 1;
        self.last_failure = Some(Instant::now());
        if self.failures >= 10 {
            self.open = true;
        }
    }
    fn is_open(&mut self) -> bool {
        if !self.open {
            return false;
        }
        if self
            .last_failure
            .is_some_and(|t| t.elapsed() > Duration::from_secs(120))
        {
            self.open = false;
            self.failures = 0;
            return false;
        }
        true
    }
}

struct Task {
    sub: i64,
    url: String,
    secret: String,
    event_id: String,
    event_type: String,
    body: String,
    attempt: i32,
    durable: Option<i64>,
    _permit: OwnedSemaphorePermit,
}

struct Executor {
    tx: mpsc::Sender<Task>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

#[derive(Deserialize)]
struct Claim {
    id: i64,
    subscription_id: i64,
    event_id: String,
    event_type: String,
    request_body: Box<RawValue>,
    attempt: i32,
    url: String,
}

type Rows<'c> = Pin<Box<dyn Future<Output = Result<Vec<setjoin_pg::Row>, String>> + Send + 'c>>;
/// Longest the claim turn is held for one connect plus claim query. On expiry the session is
/// dropped before COMMIT, so the server rolls the claim back.
const CLAIM_TIMEOUT: Duration = Duration::from_secs(5);


struct Inner {
    db: WorkerDatabase,
    codec: Option<SecretCodec>,
    client: reqwest::Client,
    breakers: Mutex<HashMap<i64, Breaker>>,
    worker_id: String,
    admission: Arc<Semaphore>,
    /// Claims reserve admission permits before they know how many rows they get; two
    /// overlapping claims would starve each other (the loser returned 0 and its row waited a
    /// whole retry tick), so claims take turns (#472).
    claim_turn: tokio::sync::Mutex<()>,
    executor: Mutex<Option<Executor>>,
    stopping: AtomicBool,
    idle: Mutex<Vec<WorkerConnection>>,
    /// Refuse literal blocked addresses (the dial-time resolver never sees them).
    guard_literals: bool,
}

/// Delivers CloudEvents to webhook subscriptions (Go's `webhook.Dispatcher`).
#[derive(Clone)]
pub struct Dispatcher {
    inner: Arc<Inner>,
}

fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("system randomness");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

impl Dispatcher {
    /// Production dispatcher: SSRF-safe client, no proxy, no redirects.
    pub fn new(db: WorkerDatabase, codec: Option<SecretCodec>) -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .dns_resolver(Arc::new(PublicOnly))
            .connect_timeout(Duration::from_secs(10))
            .timeout(DELIVERY_TIMEOUT)
            .build()
            .expect("webhook client");
        Self::with_client(db, codec, client, true)
    }

    /// Test seam: the client may dial loopback receivers (the oracle's fakes).
    pub fn unguarded_for_tests(db: WorkerDatabase, codec: Option<SecretCodec>) -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(DELIVERY_TIMEOUT)
            .build()
            .expect("webhook client");
        Self::with_client(db, codec, client, false)
    }

    fn with_client(
        db: WorkerDatabase,
        codec: Option<SecretCodec>,
        client: reqwest::Client,
        guard_literals: bool,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                db,
                codec,
                client,
                breakers: Mutex::new(HashMap::new()),
                worker_id: uuid_v4(),
                admission: Arc::new(Semaphore::new(WORKERS + QUEUE)),
                claim_turn: tokio::sync::Mutex::new(()),
                executor: Mutex::new(None),
                stopping: AtomicBool::new(false),
                idle: Mutex::new(Vec::new()),
                guard_literals,
            }),
        }
    }

    // ---- database access: a small idle list, a failed session is dropped ------------------

    async fn with_rows(
        &self,
        run: impl for<'c> FnOnce(&'c WorkerConnection) -> Rows<'c>,
    ) -> Result<Vec<setjoin_pg::Row>, String> {
        let cached = self.inner.idle.lock().expect("idle").pop();
        let conn = match cached {
            Some(c) => c,
            None => self.inner.db.connect().await.map_err(|e| e.to_string())?,
        };
        let result = run(&conn).await;
        if result.is_ok() {
            let mut idle = self.inner.idle.lock().expect("idle");
            if idle.len() < WORKERS {
                idle.push(conn);
            }
        }
        result
    }

    async fn query(
        &self,
        sql: &'static str,
        params: Vec<Arg>,
    ) -> Result<Vec<setjoin_pg::Row>, String> {
        self.with_rows(move |c| {
            Box::pin(async move {
                let refs: Vec<setjoin_pg::Param<'_>> = params.iter().map(Arg::param).collect();
                c.query(sql, &refs).await
            })
        })
        .await
    }

    // ---- executor ---------------------------------------------------------------------------

    fn ensure_started(&self) -> Option<mpsc::Sender<Task>> {
        if self.inner.stopping.load(Ordering::SeqCst) {
            return None;
        }
        let mut slot = self.inner.executor.lock().expect("executor");
        if slot.is_none() {
            let (tx, rx) = mpsc::channel::<Task>(QUEUE);
            let rx = Arc::new(tokio::sync::Mutex::new(rx));
            let handles = (0..WORKERS)
                .map(|_| {
                    let (rx, me) = (rx.clone(), self.clone());
                    tokio::spawn(async move {
                        loop {
                            let next = rx.lock().await.recv().await;
                            let Some(task) = next else { return };
                            me.deliver(&task).await;
                        }
                    })
                })
                .collect();
            *slot = Some(Executor { tx, handles });
        }
        slot.as_ref().map(|e| e.tx.clone())
    }

    /// Stops accepting work and waits for queued and in-flight deliveries.
    pub async fn shutdown(&self) {
        self.inner.stopping.store(true, Ordering::SeqCst);
        let executor = self.inner.executor.lock().expect("executor").take();
        if let Some(Executor { tx, handles }) = executor {
            drop(tx);
            for handle in handles {
                let _ = handle.await;
            }
        }
    }

    /// Resolves once every admitted delivery has settled (tests and drain checks).
    pub async fn quiesce(&self) {
        loop {
            if self.inner.admission.available_permits() == WORKERS + QUEUE {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn submit(&self, tasks: Vec<PendingTask>, durable: bool) -> usize {
        if tasks.is_empty() {
            return 0;
        }
        let Some(tx) = self.ensure_started() else {
            return 0;
        };
        let mut accepted = 0;
        for pending in tasks {
            let Ok(permit) = self.inner.admission.clone().try_acquire_owned() else {
                warn(
                    "delivery executor saturated",
                    format!("durable={durable} event_id={}", pending.event_id),
                );
                continue;
            };
            if tx.try_send(pending.into_task(permit, None)).is_ok() {
                accepted += 1;
            } else {
                warn("delivery executor saturated", format!("durable={durable}"));
            }
        }
        accepted
    }

    // ---- dispatch ----------------------------------------------------------------------------

    /// A generic event: only organization-scoped subscriptions receive it.
    pub async fn dispatch(&self, event: &CloudEvent) {
        self.dispatch_scoped(event, None, None).await
    }

    /// A user-scoped event: organization subscriptions and the subject's own.
    pub async fn dispatch_for_user(&self, subject_user: i64, event: &CloudEvent) {
        self.dispatch_scoped(event, Some(subject_user), None).await
    }

    /// A mailbox-scoped event; a mailbox that is not the subject's fails closed.
    pub async fn dispatch_for_mailbox(&self, subject_user: i64, mailbox: i64, event: &CloudEvent) {
        self.dispatch_scoped(event, Some(subject_user), Some(mailbox))
            .await
    }

    async fn dispatch_scoped(&self, event: &CloudEvent, user: Option<i64>, mailbox: Option<i64>) {
        let body = event.marshal();
        let types = format!("[{}]", go_string(&event.kind));
        let mut sql = String::from(
            "SELECT id,url FROM webhook_subscriptions WHERE is_active=TRUE AND event_types @> $1::jsonb",
        );
        let mut params: Vec<Arg> = vec![Arg::Text(types)];
        match (user, mailbox) {
            (Some(user), Some(mailbox)) => {
                sql.push_str(
                    " AND EXISTS (SELECT 1 FROM mailboxes WHERE id=$3 AND user_id=$2) \
                     AND (scope='organization' OR (scope='self' AND user_id=$2))",
                );
                params.push(Arg::I8(user));
                params.push(Arg::I8(mailbox));
            }
            (Some(user), None) => {
                sql.push_str(" AND (scope='organization' OR (scope='self' AND user_id=$2))");
                params.push(Arg::I8(user));
            }
            _ => sql.push_str(" AND scope='organization'"),
        }
        sql.push_str(" ORDER BY id");
        let rows = self
            .with_rows(|c| {
                Box::pin(async move {
                    let refs: Vec<setjoin_pg::Param<'_>> = params.iter().map(Arg::param).collect();
                    c.query(&sql, &refs).await
                })
            })
            .await;
        let rows = match rows {
            Ok(rows) => rows,
            Err(e) => return warn("query failed", e),
        };
        let mut pending = Vec::new();
        for row in &rows {
            let (Ok(id), Ok(url)) = (row.try_get::<_, i64>(0), row.try_get::<_, String>(1)) else {
                continue;
            };
            match self.secret_of(id).await {
                Ok(secret) => pending.push(PendingTask {
                    sub: id,
                    url,
                    secret,
                    event_id: event.id.clone(),
                    event_type: event.kind.clone(),
                    body: body.clone(),
                    attempt: 1,
                }),
                Err(e) => warn(
                    "dispatch: signing secret unavailable, skipping subscription (fail-closed)",
                    format!("subscription_id={id}: {e}"),
                ),
            }
        }
        self.submit(pending, false);
    }

    async fn secret_of(&self, subscription: i64) -> Result<String, String> {
        let codec = self.inner.codec.clone();
        let cached = self.inner.idle.lock().expect("idle").pop();
        let conn = match cached {
            Some(c) => c,
            None => self.inner.db.connect().await.map_err(|e| e.to_string())?,
        };
        let result = load_subscription_secret(&conn, codec.as_ref(), subscription).await;
        if result.is_ok() {
            self.inner.idle.lock().expect("idle").push(conn);
        }
        result
    }

    /// Records one pending delivery per matching organization subscription before
    /// returning, then hands the event to the executor. A stable event id makes a replay
    /// a no-op at the subscriber boundary.
    pub async fn enqueue_durable(&self, event: &CloudEvent) -> Result<(), String> {
        let body = event.marshal();
        let types = format!("[{}]", go_string(&event.kind));
        let rows = self
            .query(
                "SELECT id FROM webhook_subscriptions WHERE is_active=TRUE AND scope='organization' \
                 AND event_types @> $1::jsonb ORDER BY id",
                vec![Arg::Text(types)],
            )
            .await?;
        for row in &rows {
            let id: i64 = row.try_get(0).map_err(|e| e.to_string())?;
            self.query(
                "INSERT INTO webhook_deliveries(subscription_id,event_id,event_type,request_body,attempt,status) \
                 VALUES($1,$2,$3,$4::text::jsonb,0,'pending') \
                 ON CONFLICT(subscription_id,event_id) DO UPDATE SET event_type=webhook_deliveries.event_type \
                 RETURNING status,attempt",
                vec![
                    Arg::I8(id),
                    Arg::Text(event.id.clone()),
                    Arg::Text(event.kind.clone()),
                    Arg::Text(body.clone()),
                ],
            )
            .await?;
        }
        self.claim_durable(Some(&event.id)).await;
        Ok(())
    }

    /// The bounded immediate handoff after a publication fanned out; the retry worker
    /// recovers rows a crash leaves behind, so this is never the durability owner.
    pub async fn deliver_pending_event(&self, event_id: &str) {
        self.claim_durable(Some(event_id)).await;
    }

    /// One retry pass: claim whatever the executor can admit (backoff and the
    /// subscription's retry policy are re-checked by the claim reducer).
    pub async fn retry_pending(&self) {
        self.claim_durable(None).await;
    }

    async fn claim_durable(&self, event_id: Option<&str>) -> usize {
        let Some(tx) = self.ensure_started() else {
            return 0;
        };
        let _turn = self.inner.claim_turn.lock().await;
        let mut permits = Vec::new();
        while permits.len() < BATCH {
            match self.inner.admission.clone().try_acquire_owned() {
                Ok(p) => permits.push(p),
                Err(_) => break,
            }
        }
        if permits.is_empty() {
            return 0;
        }
        let reserved = permits.len() as i32;
        let filter: Option<String> = event_id.map(str::to_owned);
        // Bounded: the turn is held across the connect and the claim, so one stalled database
        // call must not block every other claim. The claim runs in an explicit transaction that
        // is committed only after its rows are decoded: on timeout the session is dropped before
        // COMMIT and the server rolls the claim back, so no lease or attempt is spent on rows
        // nothing dispatches (with retry disabled such a lease would expire into `exhausted`).
        let cached = self.inner.idle.lock().expect("idle").pop();
        let worker = self.inner.worker_id.clone();
        let claimed = tokio::time::timeout(CLAIM_TIMEOUT, async move {
            let conn = match cached {
                Some(c) => c,
                None => self.inner.db.connect().await.map_err(|e| e.to_string())?,
            };
            conn.batch("BEGIN").await?;
            let args = [Arg::Text(worker), Arg::I4(reserved), Arg::OptText(filter)];
            let refs: Vec<setjoin_pg::Param<'_>> = args.iter().map(Arg::param).collect();
            let rows = conn
                .query(
                    "SELECT webhook_delivery_claim($1::text::uuid,$2::int,$3::text)::text",
                    &refs,
                )
                .await?;
            Ok::<_, String>((conn, rows))
        })
        .await
        .unwrap_or_else(|_| Err("claim timed out".to_owned()));
        // Every early return below drops `conn` with the transaction open: the claim rolls back.
        let (conn, rows) = match claimed {
            Ok(claimed) => claimed,
            Err(e) => {
                warn("delivery claim failed", e);
                return 0;
            }
        };
        let raw: String = match rows.first().map(|row| row.try_get::<_, String>(0)) {
            Some(Ok(text)) => text,
            Some(Err(e)) => {
                warn("delivery claim failed", e);
                return 0;
            }
            None => return 0,
        };
        let claims: Vec<Claim> = match serde_json::from_str(&raw) {
            Ok(c) => c,
            Err(e) => {
                warn("delivery claim decode failed", e);
                return 0;
            }
        };
        permits.truncate(claims.len());
        drop(_turn);
        // COMMIT runs after the turn is released and is bounded too, so a stalled database
        // cannot hold `retry_pending` either. It precedes every dispatch and settlement (those
        // use other sessions and would wait on this transaction's row locks). Only a COMMIT that
        // succeeded returns the session to the idle list. When its outcome is unknown (timeout
        // or error) the claim is dispatched anyway: if it committed nothing is lost; if it rolled
        // back, settlement reports `completed=false` and the row is claimed and sent again
        // (at-least-once; the stable event id makes the replay a no-op at the subscriber).
        // Settlement is fenced by worker id, not attempt, so if the rolled-back row is claimed
        // again by this worker before the first dispatch settles, the first settlement may
        // record the row's outcome (as with a lease-expiry reclaim); with retry disabled a failed
        // first send can then leave a delivered row `exhausted`.
        let committed = tokio::time::timeout(CLAIM_TIMEOUT, conn.batch("COMMIT")).await;
        match committed {
            Ok(Ok(())) => {
                let mut idle = self.inner.idle.lock().expect("idle");
                if idle.len() < WORKERS {
                    idle.push(conn);
                }
            }
            Ok(Err(e)) => {
                drop(conn);
                warn("delivery claim commit outcome unknown, dispatching", e);
            }
            Err(_) => {
                drop(conn);
                warn("delivery claim commit outcome unknown, dispatching", "timeout");
            }
        }
        let mut accepted = 0;
        for claim in claims {
            let Some(permit) = permits.pop() else { break };
            let event_ok = matches!(
                serde_json::from_str::<Value>(claim.request_body.get()),
                Ok(Value::Object(_) | Value::Null)
            );
            if claim.id <= 0 || claim.subscription_id <= 0 || claim.attempt < 1 || !event_ok {
                self.complete_durable(
                    claim.id,
                    false,
                    false,
                    0,
                    "",
                    0,
                    "invalid durable delivery claim",
                )
                .await;
                continue;
            }
            let secret = match self.secret_of(claim.subscription_id).await {
                Ok(secret) => secret,
                Err(e) => {
                    warn(
                        "delivery: signing secret unavailable, failing delivery retryable (fail-closed, no HTTP)",
                        format!("subscription_id={} delivery_id={}: {e}", claim.subscription_id, claim.id),
                    );
                    self.complete_durable(
                        claim.id,
                        false,
                        true,
                        0,
                        "",
                        0,
                        &format!("signing secret unavailable: {e}"),
                    )
                    .await;
                    continue;
                }
            };
            let task = PendingTask {
                sub: claim.subscription_id,
                url: claim.url,
                secret,
                event_id: claim.event_id,
                event_type: claim.event_type,
                body: claim.request_body.get().to_owned(),
                attempt: claim.attempt,
            }
            .into_task(permit, Some(claim.id));
            if tx.send(task).await.is_err() {
                break;
            }
            accepted += 1;
        }
        accepted
    }

    #[allow(clippy::too_many_arguments)]
    async fn complete_durable(
        &self,
        delivery: i64,
        succeeded: bool,
        retryable: bool,
        code: i32,
        body: &str,
        latency: i32,
        error: &str,
    ) {
        if delivery <= 0 {
            return;
        }
        let settle = self.query(
            "SELECT webhook_delivery_complete($1,$2::text::uuid,$3,$4,$5,$6,$7,$8)",
            vec![
                Arg::I8(delivery),
                Arg::Text(self.inner.worker_id.clone()),
                Arg::Bool(succeeded),
                Arg::Bool(retryable),
                Arg::I4(code),
                Arg::Text(body.to_owned()),
                Arg::I4(latency),
                Arg::Text(error.to_owned()),
            ],
        );
        match tokio::time::timeout(SETTLEMENT_TIMEOUT, settle).await {
            Ok(Ok(rows))
                if rows
                    .first()
                    .is_some_and(|r| r.try_get::<_, bool>(0).unwrap_or(false)) => {}
            Ok(Ok(_)) => warn(
                "durable delivery settlement failed",
                format!("delivery_id={delivery} completed=false"),
            ),
            Ok(Err(e)) => warn(
                "durable delivery settlement failed",
                format!("delivery_id={delivery}: {e}"),
            ),
            Err(_) => warn(
                "durable delivery settlement failed",
                format!("delivery_id={delivery}: timeout"),
            ),
        }
    }

    // ---- one delivery -----------------------------------------------------------------------

    async fn deliver(&self, task: &Task) {
        let open = {
            let mut breakers = self.inner.breakers.lock().expect("breakers");
            breakers.entry(task.sub).or_default().is_open()
        };
        if open {
            warn(
                "circuit breaker open, skipping delivery",
                format!("subscription_id={}", task.sub),
            );
            if let Some(id) = task.durable {
                self.complete_durable(id, false, true, 0, "", 0, "circuit breaker open")
                    .await;
            }
            return;
        }
        let now = chrono::Utc::now().timestamp();
        let signature = match sign(task.body.as_bytes(), &task.secret, now) {
            Ok(h) => h,
            Err(e) => {
                warn(
                    "delivery: signing secret rejected, failing delivery (fail-closed)",
                    format!("subscription_id={}: {e}", task.sub),
                );
                if let Some(id) = task.durable {
                    self.complete_durable(id, false, false, 0, "", 0, &e).await;
                }
                return;
            }
        };
        let request = match self
            .inner
            .client
            .post(&task.url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-Signature", signature)
            .body(task.body.clone())
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                if let Some(id) = task.durable {
                    self.complete_durable(id, false, false, 0, "", 0, &error_text(&task.url, &e))
                        .await;
                }
                return;
            }
        };
        let start = Instant::now();
        let refused = self.inner.guard_literals
            && match request.url().host() {
                Some(url::Host::Ipv4(ip)) => crate::ssrf::blocked(std::net::IpAddr::V4(ip)),
                Some(url::Host::Ipv6(ip)) => crate::ssrf::blocked(std::net::IpAddr::V6(ip)),
                _ => false,
            };
        let response = if refused {
            Err(format!(
                "Post {}: dial tcp {}: URL is not allowed (must be http/https to a public host)",
                go_string(&task.url),
                request.url().host_str().unwrap_or("")
            ))
        } else {
            self.inner
                .client
                .execute(request)
                .await
                .map_err(|e| error_text(&task.url, &e))
        };
        let latency = start.elapsed().as_millis() as i32;
        let (mut status, mut code, mut body, mut error) =
            ("success", 0i32, String::new(), String::new());
        match response {
            Err(e) => {
                status = "failed";
                error = e;
            }
            Ok(mut response) => {
                code = i32::from(response.status().as_u16());
                // One read of at most 1 KiB, like Go's single `Body.Read`.
                if let Ok(Some(chunk)) = response.chunk().await {
                    let take = chunk.len().min(1024);
                    body = String::from_utf8_lossy(&chunk[..take]).into_owned();
                }
                if code >= 500 || code == 429 {
                    status = "failed";
                } else if code >= 400 {
                    status = "exhausted";
                }
            }
        }
        if let Some(id) = task.durable {
            self.complete_durable(
                id,
                status == "success",
                status == "failed",
                code,
                &body,
                latency,
                &error,
            )
            .await;
        } else {
            let logged = self
                .query(
                    "INSERT INTO webhook_deliveries (subscription_id, event_id, event_type, request_body, response_code, response_body, latency_ms, attempt, status, error_message, completed_at) \
                     VALUES ($1,$2,$3,$4::text::jsonb,$5,$6,$7,$8,$9,$10,now()) \
                     ON CONFLICT (subscription_id,event_id) DO UPDATE SET \
                       attempt=EXCLUDED.attempt,status=EXCLUDED.status,response_code=EXCLUDED.response_code, \
                       response_body=EXCLUDED.response_body,latency_ms=EXCLUDED.latency_ms, \
                       error_message=EXCLUDED.error_message,completed_at=EXCLUDED.completed_at \
                     WHERE webhook_deliveries.status IN ('pending','failed') \
                       AND webhook_deliveries.attempt<EXCLUDED.attempt \
                     RETURNING id",
                    vec![
                        Arg::I8(task.sub),
                        Arg::Text(task.event_id.clone()),
                        Arg::Text(task.event_type.clone()),
                        Arg::Text(task.body.clone()),
                        Arg::I4(code),
                        Arg::Text(body.clone()),
                        Arg::I4(latency),
                        Arg::I4(task.attempt),
                        Arg::Text(status.to_owned()),
                        Arg::Text(error.clone()),
                    ],
                )
                .await;
            if let Err(e) = logged {
                warn(
                    "delivery log write failed",
                    format!("sub_id={} event_id={}: {e}", task.sub, task.event_id),
                );
            }
        }
        let mut breakers = self.inner.breakers.lock().expect("breakers");
        let breaker = breakers.entry(task.sub).or_default();
        if status == "success" {
            breaker.success();
        } else {
            breaker.failure();
        }
    }
}

/// Go's `*url.Error` text: `Post "<url>": <cause>`.
fn error_text(url: &str, error: &reqwest::Error) -> String {
    use std::error::Error;
    let mut parts = Vec::new();
    let mut source = error.source();
    while let Some(cause) = source {
        parts.push(cause.to_string());
        source = cause.source();
    }
    if parts.is_empty() {
        parts.push(error.to_string());
    }
    let cause = parts.join(": ");
    if cause.contains("URL is not allowed") {
        return format!(
            "Post {}: dial tcp: URL is not allowed (must be http/https to a public host)",
            go_string(url)
        );
    }
    format!("Post {}: {}", go_string(url), cause)
}

struct PendingTask {
    sub: i64,
    url: String,
    secret: String,
    event_id: String,
    event_type: String,
    body: String,
    attempt: i32,
}
impl PendingTask {
    fn into_task(self, permit: OwnedSemaphorePermit, durable: Option<i64>) -> Task {
        Task {
            sub: self.sub,
            url: self.url,
            secret: self.secret,
            event_id: self.event_id,
            event_type: self.event_type,
            body: self.body,
            attempt: self.attempt,
            durable,
            _permit: permit,
        }
    }
}

/// A statement argument; the driver's types stay behind `setjoin-pg`.
enum Arg {
    I8(i64),
    I4(i32),
    Bool(bool),
    Text(String),
    OptText(Option<String>),
}
impl Arg {
    fn param(&self) -> setjoin_pg::Param<'_> {
        match self {
            Arg::I8(v) => (v, Type::INT8),
            Arg::I4(v) => (v, Type::INT4),
            Arg::Bool(v) => (v, Type::BOOL),
            Arg::Text(v) => (v, Type::TEXT),
            Arg::OptText(v) => (v, Type::TEXT),
        }
    }
}

// ---- workers ------------------------------------------------------------------------------

/// `webhook-retry`: re-delivers failed and abandoned durable rows. Runs the executor's
/// first residue claim immediately, then every [`RETRY_TICK`].
pub struct RetryWorker {
    dispatcher: Dispatcher,
}

impl RetryWorker {
    pub fn new(dispatcher: Dispatcher) -> Self {
        Self { dispatcher }
    }

    /// One pass (the oracle seam): claim, deliver and settle what the executor admits.
    pub async fn tick(&self) {
        self.dispatcher.retry_pending().await;
        self.dispatcher.quiesce().await;
    }

    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) {
        tokio::pin!(stop);
        // The executor starts and the first residue claim completes before any tick.
        let first = self.dispatcher.retry_pending();
        tokio::select! {biased; _ = &mut stop => return, _ = first => {}}
        let mut ticks =
            tokio::time::interval_at(tokio::time::Instant::now() + RETRY_TICK, RETRY_TICK);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {biased; _ = &mut stop => return, _ = ticks.tick() => {}}
            self.dispatcher.retry_pending().await;
        }
    }
}

#[derive(Deserialize)]
struct PublicationClaim {
    id: i64,
    event_id: String,
    attempt_count: i32,
}

/// `webhook-publications`: drains committed publication residue (the flag is checked
/// only by the enrollment reducer, never here).
pub struct PublicationWorker {
    dispatcher: Dispatcher,
    id: String,
    last_prune: Mutex<Option<Instant>>,
}

impl PublicationWorker {
    pub fn new(dispatcher: Dispatcher) -> Self {
        Self {
            dispatcher,
            id: uuid_v4(),
            last_prune: Mutex::new(None),
        }
    }

    /// One drain (the oracle seam).
    pub async fn tick(&self) {
        self.drain().await;
        self.dispatcher.quiesce().await;
    }

    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) {
        tokio::pin!(stop);
        tokio::select! {biased; _ = &mut stop => return, _ = self.drain() => {}}
        let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + POLL, POLL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {biased; _ = &mut stop => return, _ = ticks.tick() => {}}
            tokio::select! {biased; _ = &mut stop => return, _ = self.drain() => {}}
        }
    }

    async fn drain(&self) {
        let d = &self.dispatcher;
        let rows = d
            .query(
                "SELECT webhook_publication_claim($1::text::uuid,$2::int)::text",
                vec![Arg::Text(self.id.clone()), Arg::I4(100i32)],
            )
            .await;
        let raw: String = match rows.as_deref() {
            Ok([row, ..]) => row.try_get(0).unwrap_or_default(),
            Ok([]) => String::new(),
            Err(e) => return warn("publication claim failed", e),
        };
        let claims: Vec<PublicationClaim> = match serde_json::from_str(&raw) {
            Ok(c) => c,
            Err(e) => return warn("publication claim decode failed", e),
        };
        for claim in claims {
            if claim.id <= 0
                || claim.event_id.is_empty()
                || claim.attempt_count < 1
                || claim.attempt_count > 12
            {
                warn("publication returned invalid claim", "");
                continue;
            }
            match self.publish(&claim).await {
                Ok(()) => d.deliver_pending_event(&claim.event_id).await,
                Err(error) => {
                    let mut bounded = error;
                    if bounded.len() > 2048 {
                        let mut end = 2048;
                        while !bounded.is_char_boundary(end) {
                            end -= 1;
                        }
                        bounded.truncate(end);
                    }
                    let finished = d
                        .query(
                            "SELECT webhook_publication_complete($1,$2::text::uuid,false,$3)",
                            vec![
                                Arg::I8(claim.id),
                                Arg::Text(self.id.clone()),
                                Arg::Text(bounded),
                            ],
                        )
                        .await;
                    if let Err(e) = finished {
                        warn(
                            "publication failure recording failed",
                            format!("publication_id={}: {e}", claim.id),
                        );
                    }
                }
            }
        }
        let due = self
            .last_prune
            .lock()
            .expect("prune")
            .is_none_or(|t| t.elapsed() >= PRUNE_EVERY);
        if due {
            match d
                .query("SELECT webhook_publication_prune(30,500)", vec![])
                .await
            {
                Ok(_) => *self.last_prune.lock().expect("prune") = Some(Instant::now()),
                Err(e) => warn("publication prune failed", e),
            }
        }
    }

    async fn publish(&self, claim: &PublicationClaim) -> Result<(), String> {
        let d = &self.dispatcher;
        d.query(
            "SELECT webhook_publication_fanout($1,$2::text::uuid)::bigint",
            vec![Arg::I8(claim.id), Arg::Text(self.id.clone())],
        )
        .await?;
        let rows = d
            .query(
                "SELECT webhook_publication_complete($1,$2::text::uuid,true,NULL)",
                vec![Arg::I8(claim.id), Arg::Text(self.id.clone())],
            )
            .await?;
        match rows.first().map(|r| r.try_get::<_, bool>(0)) {
            Some(Ok(true)) => Ok(()),
            Some(Err(e)) => Err(e.to_string()),
            _ => Err("publication lease lost before completion".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database that accepts the connection and never answers must not hold the claim turn
    /// beyond `CLAIM_TIMEOUT`: the claim returns 0 and the next claim gets its turn (#472).
    /// Paused time makes the bound exact under any load: the two claims take turns, each
    /// holding the turn for exactly one timeout.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_claim_gives_up_its_turn() {
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = silent.local_addr().unwrap().port();
        let hold = tokio::spawn(async move {
            let mut open = Vec::new();
            while let Ok((conn, _)) = silent.accept().await {
                open.push(conn);
            }
        });
        let db = WorkerDatabase::new(&format!("postgres://u:p@127.0.0.1:{port}/d")).unwrap();
        let dispatcher = Dispatcher::unguarded_for_tests(db, None);
        let started = tokio::time::Instant::now();
        let (first, second) = tokio::join!(dispatcher.claim_durable(None), dispatcher.claim_durable(None));
        assert_eq!((first, second), (0, 0));
        let elapsed = started.elapsed();
        assert!(
            elapsed >= CLAIM_TIMEOUT * 2 && elapsed < CLAIM_TIMEOUT * 2 + Duration::from_secs(1),
            "the claims take turns and each stalled claim is bounded by one timeout: {elapsed:?}"
        );
        hold.abort();
    }

    #[test]
    fn breaker_opens_after_ten_failures_and_a_success_closes_it() {
        let mut breaker = Breaker::default();
        for _ in 0..9 {
            breaker.failure();
            assert!(!breaker.is_open());
        }
        breaker.failure();
        assert!(breaker.is_open());
        breaker.success();
        assert!(!breaker.is_open());
    }

    #[test]
    fn breaker_closes_again_after_two_minutes() {
        let mut breaker = Breaker::default();
        for _ in 0..10 {
            breaker.failure();
        }
        breaker.last_failure = Some(Instant::now() - Duration::from_secs(121));
        assert!(!breaker.is_open());
        assert_eq!(breaker.failures, 0);
    }

    #[test]
    fn cloud_event_marshals_in_go_field_order_with_sorted_html_escaped_data() {
        let mut event = CloudEvent::new(
            "mailserver/auth",
            "user.updated",
            serde_json::json!({"z": 1, "a": "<b>&", "m": [true, null]}),
        );
        event.id = "evt_x".into();
        event.time = "2026-10-01T10:00:00Z".into();
        assert_eq!(
            event.marshal(),
            r#"{"specversion":"1.0","id":"evt_x","source":"mailserver/auth","type":"user.updated","time":"2026-10-01T10:00:00Z","datacontenttype":"application/json","data":{"a":"\u003cb\u003e\u0026","m":[true,null],"z":1}}"#
        );
    }

    #[test]
    fn event_ids_and_worker_ids_have_go_shapes() {
        let event = CloudEvent::new("s", "t", Value::Null);
        assert_eq!(event.id.len(), 17);
        assert!(event.id[4..]
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()));
        let id = uuid_v4();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
    }
}
