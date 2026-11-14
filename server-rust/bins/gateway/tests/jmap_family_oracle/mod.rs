//! Shared frozen-Go oracle for per-family JMAP methods (#369-#377).
//!
//! A case seeds fresh own (`a`) and foreign (`f`) fixtures, sends its setup
//! and observed requests through the real front door (HTTP `POST /jmap`, or
//! frames on one `/jmap/ws` session) and observes the response plus declared
//! effects, audit rows and notifications. With `GOFREE_RECORD_GO_BINARY` (the
//! dispatch-only gofree-record workflow, go_upstream=none) the covered frozen
//! Go answers and a missing golden is created exclusively, stamped with
//! `GOFREE_GO_SOURCE`; otherwise Rust answers with no Go upstream and the
//! proxied-to-Go counter must stay 0. Golden shape:
//! `{"format":1,"route","case","kind","go_source","normalization","observation":
//! {"request":{"method","path","body"},"setup":[..],"response":{"status","headers","body"},
//! "repeat":..|null,"effects":{"<name>":{"before","after"}},"audit":[..],"notify":[..],"absent":[..]}}`.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use hyper::Request;
use regex::Regex;
use serde_json::{json, Value};
use setjoin_conformance::fixture::{self, Account};
use setjoin_conformance::golden;
use setjoin_conformance::harness::{BoxError, Db, Listener};
use setjoin_gateway::jmap::family::ContinuitySigner;
use setjoin_gateway::jmap::push::WebSocketRoute;
use setjoin_gateway::jmap::{JmapCommands, JmapRoute, JmapServices};
use setjoin_gateway::{
    Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use tokio::net::TcpListener;
use tokio_postgres::{types::Type, Client};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

use crate::common;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The continuity key go_oracle gives frozen Go (Ed25519 seed of 0x22 bytes).
pub const CONTINUITY_KEY_ID: &str = "blobs1-test-continuity";
pub const CONTINUITY_SEED: [u8; 32] = [0x22; 32];
const BOOT: &str = "bba31885-d8f1-4c47-8753-56bf86e59807";
const REQUEST_ID: &str = "gofree-jmapfam";
const DIFF_PREFIX: &str = "GOLDEN-DIFF ";

/// Kinds whose golden must show no effect, no notification and no divergence.
pub const DENIAL_KINDS: &[&str] = &[
    "cross-tenant",
    "delegate-insufficient",
    "delegate-personal",
    "delegate-revoked",
    "entitlement-denied",
    "suspended",
    "foreign-object",
];

const RULES: &[&str] = &[
    "case pointer values and vars: <name>",
    "sessionState: text after the last '-' replaced by <timestamp>",
    "timestamps (date and time, fraction): <timestamp>; the zone suffix is kept",
    "UUIDs: <uuid>",
    "fixture and seed ids (whole digit runs): <a.mailbox> <a.user> <f.mailbox> <f.user> <seed.N>",
    "headers: date, content-length and transfer-encoding dropped",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Http,
    Ws,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutation {
    None,
    /// The HTTP route answers 418; `run` returns the comparison error.
    Status,
    /// `from` in `function` becomes `TRUE` for the run; `run` returns `Ok`
    /// only when the oracle rejected the mutant (and prints the receipt).
    NoTenantFilter {
        function: &'static str,
        from: &'static str,
    },
}

/// One recorded case. Templates take `{a.mailbox} {a.user} {f.mailbox}
/// {f.user} {seed.N} {var.NAME} {resp.I:/json/pointer}`.
pub struct Case {
    pub family: &'static str,
    pub name: &'static str,
    pub kind: &'static str,
    pub method: &'static str,
    pub transport: Transport,
    pub mutator: bool,
    pub repeat: bool,
    pub toggles: &'static [(&'static str, bool)],
    /// Owner statements; a returned first column (i64) becomes `{seed.N}`.
    pub seed: &'static [&'static str],
    /// Requests (HTTP bodies or WS frames) before the observed one.
    pub setup: &'static [&'static str],
    pub vars: fn(&[String]) -> Result<Vec<(String, String)>, BoxError>,
    /// Owner SQL after setup and vars, before the observed request.
    pub between: &'static [&'static str],
    pub request: &'static str,
    /// Values that must not occur in the observed response body.
    pub absent: &'static [&'static str],
    /// `(name, SELECT … returning one text value)`, run before and after.
    pub effects: &'static [(&'static str, &'static str)],
    pub notify: &'static [&'static str],
    /// `(JSON pointer into a response, placeholder)`.
    pub scrub: &'static [(&'static str, &'static str)],
    pub restore_continuity: bool,
}

impl Case {
    /// A case with empty optional parts; fill the rest with struct update syntax.
    pub const fn new(
        family: &'static str,
        name: &'static str,
        kind: &'static str,
        method: &'static str,
        request: &'static str,
    ) -> Self {
        Self {
            family,
            name,
            kind,
            method,
            transport: Transport::Http,
            mutator: false,
            repeat: false,
            toggles: &[],
            seed: &[],
            setup: &[],
            vars: no_vars,
            between: &[],
            request,
            absent: &[],
            effects: &[],
            notify: &[],
            scrub: &[],
            restore_continuity: false,
        }
    }
}

pub fn no_vars(_: &[String]) -> Result<Vec<(String, String)>, BoxError> {
    Ok(Vec::new())
}

/// Lifecycle-aware suspension of one mailbox (a template such as
/// `{f.mailbox}`): `mailboxes.enabled=false` (with the lifecycle toggle off the
/// update trigger copies it to `access_state`) and, for the toggle-on case,
/// `access_state='suspended'` (the only non-active value legal for a bound or
/// shared mailbox, V199 `mailbox_lifecycle_binding_shape`).
pub fn suspend(target: &str) -> [String; 2] {
    [
        format!("UPDATE mailboxes SET enabled = false WHERE id = {target}"),
        format!(
            "UPDATE mailbox_lifecycle SET access_state = 'suspended', generation = generation + 1, \
             updated_at = statement_timestamp() \
             WHERE mailbox_id = {target} AND binding_state IN ('bound','shared')"
        ),
    ]
}

struct Fx {
    a: Account,
    f: Account,
    seeds: Vec<i64>,
}

fn pattern(cell: &'static OnceLock<Regex>, source: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(source).expect("static pattern"))
}

fn placeholder() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"\{(a|f|seed|var|resp)\.([^}]+)\}")
}

fn render(
    template: &str,
    fx: &Fx,
    prior: &[String],
    vars: &[(String, String)],
) -> Result<String, BoxError> {
    let mut out = String::with_capacity(template.len());
    let mut last = 0;
    for captures in placeholder().captures_iter(template) {
        let whole = captures.get(0).expect("whole match");
        out.push_str(&template[last..whole.start()]);
        let value = match (&captures[1], &captures[2]) {
            ("a", "mailbox") => fx.a.mailbox.to_string(),
            ("a", "user") => fx.a.user.to_string(),
            ("f", "mailbox") => fx.f.mailbox.to_string(),
            ("f", "user") => fx.f.user.to_string(),
            ("seed", index) => fx
                .seeds
                .get(index.parse::<usize>()?)
                .ok_or("seed index out of range")?
                .to_string(),
            ("var", name) => vars
                .iter()
                .find(|(candidate, _)| candidate == name)
                .map(|(_, value)| value.clone())
                .ok_or_else(|| format!("unknown var {name}"))?,
            ("resp", spec) => {
                let (index, pointer) = spec
                    .split_once(':')
                    .ok_or("resp placeholder needs I:/pointer")?;
                let response: Value = serde_json::from_str(
                    prior
                        .get(index.parse::<usize>()?)
                        .ok_or("resp index out of range")?,
                )?;
                let value = response
                    .pointer(pointer)
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("resp pointer {pointer} is not a string"))?;
                let encoded = serde_json::to_string(value)?;
                encoded[1..encoded.len() - 1].to_owned()
            }
            _ => return Err(format!("unknown placeholder {}", whole.as_str()).into()),
        };
        out.push_str(&value);
        last = whole.end();
    }
    out.push_str(&template[last..]);
    Ok(out)
}

struct Scrubber {
    replacements: Vec<(String, String)>,
    ids: Vec<(i64, String)>,
}

impl Scrubber {
    fn apply(&self, text: &str) -> String {
        static SESSION: OnceLock<Regex> = OnceLock::new();
        static TIMESTAMP: OnceLock<Regex> = OnceLock::new();
        static UUID: OnceLock<Regex> = OnceLock::new();
        let mut out = text.to_owned();
        for (raw, name) in &self.replacements {
            if !raw.is_empty() {
                out = out.replace(raw.as_str(), &format!("<{name}>"));
            }
        }
        out = pattern(&SESSION, r#"("sessionState":"[^"]*-)[^"-]*""#)
            .replace_all(&out, "${1}<timestamp>\"")
            .into_owned();
        out = pattern(
            &TIMESTAMP,
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?",
        )
        .replace_all(&out, "<timestamp>")
        .into_owned();
        out = pattern(
            &UUID,
            r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        )
        .replace_all(&out, "<uuid>")
        .into_owned();
        digit_runs(&out, &self.ids)
    }
}

/// Replace every maximal ASCII digit run equal to a fixture id by its name.
fn digit_runs(text: &str, ids: &[(i64, String)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if !run.is_empty() {
            match ids.iter().find(|(id, _)| id.to_string() == *run) {
                Some((_, name)) => {
                    out.push('<');
                    out.push_str(name);
                    out.push('>');
                }
                None => out.push_str(run),
            }
            run.clear();
        }
    };
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            run.push(ch);
        } else {
            flush(&mut run, &mut out);
            out.push(ch);
        }
    }
    flush(&mut run, &mut out);
    out
}

fn contains_token(body: &str, value: &str) -> bool {
    if body.contains(&format!("\"{value}\"")) {
        return true;
    }
    value.bytes().all(|b| b.is_ascii_digit())
        && body
            .split(|c: char| !c.is_ascii_digit())
            .any(|run| run == value)
}

fn mask(value: &mut Value, scrub: &[(&str, &str)]) {
    for (pointer, name) in scrub {
        if let Some(slot) = value.pointer_mut(pointer) {
            if slot.is_string() {
                *slot = json!(format!("<{name}>"));
            }
        }
    }
}

struct StatusMutant<T>(T);

impl<T: Intercept> Intercept for StatusMutant<T> {
    fn shutdown(&self) {
        self.0.shutdown()
    }
    fn requires_session(&self, request: &Request<Body>) -> bool {
        self.0.requires_session(request)
    }
    fn matches(&self, request: &Request<Body>) -> bool {
        self.0.matches(request)
    }
    fn admits_member(&self, headers: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        self.0.admits_member(headers, scheme)
    }
    fn handle(
        &self,
        request: Request<Body>,
        context: RequestContext,
    ) -> BoxFuture<hyper::Response<Body>> {
        let pending = self.0.handle(request, context);
        Box::pin(async move {
            let mut response = pending.await;
            *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            response
        })
    }
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn http(
    address: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> Result<(u16, Value, String), BoxError> {
    let stream = tokio::net::TcpStream::connect(address).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "mail.test")
        .header("origin", "http://mail.test")
        .header("content-type", "application/json")
        .header("x-request-id", REQUEST_ID);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = sender
        .send_request(builder.body(common::full(body.to_owned()))?)
        .await?;
    let status = response.status().as_u16();
    let mut headers = BTreeMap::new();
    for (name, value) in response.headers() {
        if matches!(
            name.as_str(),
            "date" | "content-length" | "transfer-encoding"
        ) {
            continue;
        }
        headers.insert(name.as_str().to_owned(), value.to_str()?.to_owned());
    }
    let bytes = response.into_body().collect().await?.to_bytes();
    task.abort();
    Ok((status, json!(headers), String::from_utf8(bytes.to_vec())?))
}

async fn ws_open(address: SocketAddr, token: &str) -> Result<Socket, BoxError> {
    let mut request = format!("ws://{address}/jmap/ws").into_client_request()?;
    request
        .headers_mut()
        .insert("cookie", format!("access_token={token}").parse()?);
    let (socket, _) = tokio_tungstenite::connect_async(request).await?;
    Ok(socket)
}

async fn ws_send(socket: &mut Socket, frame: &str) -> Result<String, BoxError> {
    let id = serde_json::from_str::<Value>(frame)?["id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    socket.send(Message::Text(frame.to_owned().into())).await?;
    loop {
        let message = tokio::time::timeout(Duration::from_secs(10), socket.next())
            .await?
            .ok_or("socket ended")??;
        if let Message::Text(text) = message {
            let value: Value = serde_json::from_str(&text)?;
            if matches!(value["@type"].as_str(), Some("Response" | "RequestError"))
                && value["requestId"].as_str().unwrap_or_default() == id
            {
                return Ok(text.to_string());
            }
        }
    }
}

async fn exchange(
    transport: Transport,
    address: SocketAddr,
    token: &str,
    socket: &mut Option<Socket>,
    body: &str,
) -> Result<(u16, Value, String), BoxError> {
    match transport {
        Transport::Http => http(address, "POST", "/jmap", Some(token), body).await,
        Transport::Ws => {
            let socket = socket.as_mut().ok_or("no WebSocket session")?;
            Ok((101, json!({}), ws_send(socket, body).await?))
        }
    }
}

async fn effects(
    owner: &Client,
    fx: &Fx,
    case: &Case,
    prior: &[String],
    vars: &[(String, String)],
) -> Result<Vec<(String, String)>, BoxError> {
    let mut out = Vec::new();
    for (name, template) in case.effects {
        let sql = render(template, fx, prior, vars)?;
        let row = owner.query_one(sql.as_str(), &[]).await?;
        let value: Option<String> = row.try_get(0)?;
        out.push((
            (*name).to_owned(),
            value.unwrap_or_else(|| "null".to_owned()),
        ));
    }
    Ok(out)
}

async fn audit_marks(owner: &Client) -> Result<(i64, i64), BoxError> {
    let row = owner
        .query_one(
            "SELECT coalesce((SELECT max(id) FROM admin_audit_log),0)::int8, \
             coalesce((SELECT max(id) FROM mailbox_audit_log),0)::int8",
            &[],
        )
        .await?;
    Ok((row.get(0), row.get(1)))
}

async fn audit_rows(owner: &Client, fx: &Fx, marks: (i64, i64)) -> Result<Vec<String>, BoxError> {
    let users = vec![fx.a.user, fx.f.user];
    let mailboxes = vec![fx.a.mailbox, fx.f.mailbox];
    let mut rows = Vec::new();
    for row in owner
        .query_typed(
            "SELECT (to_jsonb(x) - 'id' - 'occurred_at' - 'checksum')::text FROM admin_audit_log x \
             WHERE x.id > $1 AND x.user_id = ANY($2) ORDER BY x.id",
            &[(&marks.0, Type::INT8), (&users, Type::INT8_ARRAY)],
        )
        .await?
    {
        rows.push(format!("admin {}", row.get::<_, String>(0)));
    }
    for row in owner
        .query_typed(
            "SELECT (to_jsonb(x) - 'id' - 'occurred_at')::text FROM mailbox_audit_log x \
             WHERE x.id > $1 AND x.mailbox_id = ANY($2) ORDER BY x.id",
            &[(&marks.1, Type::INT8), (&mailboxes, Type::INT8_ARRAY)],
        )
        .await?
    {
        rows.push(format!("mailbox {}", row.get::<_, String>(0)));
    }
    Ok(rows)
}

type Continuity = (Option<String>, Option<String>, Option<String>);

async fn save_continuity(owner: &Client) -> Result<Continuity, BoxError> {
    let row = owner
        .query_one(
            "SELECT continuity_last_wall_clock::text, continuity_last_boot_epoch::text, \
             continuity_last_boot_at::text FROM upgrade_control_state WHERE singleton",
            &[],
        )
        .await?;
    owner
        .batch_execute(
            "UPDATE upgrade_control_state SET continuity_last_wall_clock=NULL, \
             continuity_last_boot_epoch=NULL, continuity_last_boot_at=NULL WHERE singleton",
        )
        .await?;
    Ok((row.get(0), row.get(1), row.get(2)))
}

/// Record or compare one case. See the module documentation.
pub async fn run(case: &Case, mutation: Mutation) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case(case.name) else {
        return Ok(());
    };
    let owner = db.connect().await?;
    for (sequence, floor) in [
        ("users", 1_000_000_i64),
        ("mailboxes", 2_000_000),
        ("tags", 3_000_000),
        ("messages", 4_000_000),
        ("reminders", 11_000_000),
    ] {
        owner
            .batch_execute(&format!(
                "SELECT setval('{sequence}_id_seq', GREATEST((SELECT last_value FROM {sequence}_id_seq), {floor}))"
            ))
            .await?;
    }
    let a = fixture::account(&owner, &format!("fam-{}", case.family)).await?;
    let f = fixture::account(&owner, &format!("fam-{}-foreign", case.family)).await?;
    let mut toggles = Vec::new();
    for (key, _) in case.toggles {
        let rows = owner
            .query_typed(
                "SELECT enabled FROM feature_toggles WHERE key = $1",
                &[(key, Type::TEXT)],
            )
            .await?;
        toggles.push((*key, rows.first().map(|row| row.get::<_, bool>(0))));
    }
    let continuity = if case.restore_continuity {
        Some(save_continuity(&owner).await?)
    } else {
        None
    };
    let mut fx = Fx {
        a,
        f,
        seeds: Vec::new(),
    };
    let outcome = execute(&db, &owner, &mut fx, case, mutation).await;
    let cleaned = cleanup(&owner, &fx, &toggles, continuity).await;
    outcome?;
    cleaned
}

async fn execute(
    db: &Db,
    owner: &Client,
    fx: &mut Fx,
    case: &Case,
    mutation: Mutation,
) -> Result<(), BoxError> {
    if std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() && mutation != Mutation::None {
        return Err("cannot record a mutant".into());
    }
    for (key, enabled) in case.toggles {
        owner
            .query_typed(
                "INSERT INTO feature_toggles (key, enabled) VALUES ($1, $2) \
                 ON CONFLICT (key) DO UPDATE SET enabled = EXCLUDED.enabled",
                &[(key, Type::TEXT), (enabled, Type::BOOL)],
            )
            .await?;
    }
    for template in case.seed {
        let sql = render(template, fx, &[], &[])?;
        let rows = owner.query(sql.as_str(), &[]).await?;
        if let Some(Ok(id)) = rows.first().map(|row| row.try_get::<_, i64>(0)) {
            fx.seeds.push(id);
        }
    }
    let mut restore = None;
    if let Mutation::NoTenantFilter { function, from } = mutation {
        if std::env::var("LANE_TEST_DB").map_or(true, |db| db.is_empty()) {
            return Err(
                "no-tenant-filter mutants run only on a per-test clone (LANE_TEST_DB)".into(),
            );
        }
        if !case
            .seed
            .iter()
            .any(|s| s.contains("{f.mailbox}") || s.contains("{f.user}"))
        {
            return Err("a no-tenant-filter mutant needs a seeded foreign row".into());
        }
        let definition: String = owner
            .query_typed(
                "SELECT pg_get_functiondef($1::text::regprocedure)",
                &[(&function, Type::TEXT)],
            )
            .await?[0]
            .get(0);
        if !definition.contains(from) {
            return Err(format!("{function} does not contain {from:?}").into());
        }
        owner
            .batch_execute(&definition.replace(from, "TRUE"))
            .await?;
        restore = Some(definition);
    }
    let result = observe(db, owner, fx, case, mutation).await;
    if let Some(definition) = restore {
        owner.batch_execute(&definition).await?;
        return match result {
            Err(error) if error.to_string().starts_with(DIFF_PREFIX) => {
                println!(
                    "MUTANT-REJECTED: POST /jmap {} :: no-tenant-filter",
                    case.method
                );
                Ok(())
            }
            Err(error) => Err(error),
            Ok(()) => Err("no-tenant-filter mutant survived the oracle".into()),
        };
    }
    result
}

async fn observe(
    db: &Db,
    owner: &Client,
    fx: &Fx,
    case: &Case,
    mutation: Mutation,
) -> Result<(), BoxError> {
    let unused =
        common::fake_upstream(|_| async { hyper::Response::new(common::full("unused")) }).await;
    let go = common::go_oracle::start_named(db, unused, None, "gofree-jmapfam").await?;
    let recording = go.is_some();
    let routes = if recording {
        RouteTable::proxy_all()
    } else {
        let mut services = JmapServices::new(
            common::patient_exec(&db.dsn, 4)?,
            "mail.test".into(),
            52428800,
        );
        services.continuity_boot = Some(BOOT.into());
        services.continuity_signer = Some(Arc::new(ContinuitySigner::new(
            CONTINUITY_KEY_ID.into(),
            ring::signature::Ed25519KeyPair::from_seed_unchecked(&CONTINUITY_SEED)
                .map_err(|_| "continuity key")?,
        )));
        let commands = Arc::new(JmapCommands {
            services: Some(Arc::new(services)),
            worker: Some(common::patient_exec(&db.dsn, 1)?),
            exec: common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?,
            keys: common::recovery_keys(),
            issuer: "mailserver".into(),
            denylist: None,
        });
        let table = if mutation == Mutation::Status {
            RouteTable::proxy_all().with(StatusMutant(JmapRoute(commands.clone())))
        } else {
            RouteTable::proxy_all().with(JmapRoute(commands.clone()))
        };
        table.with(WebSocketRoute::new(commands, db.direct.clone()))
    };
    let upstream = match &go {
        Some(oracle) => Some(format!("http://{}", oracle.address).parse()?),
        None => None,
    };
    let gateway = Gateway::new(
        Config {
            upstream,
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: Duration::from_secs(30),
            edge_limit: None,
        },
        routes,
    )?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(gateway.serve(listener));
    let result = observe_on(db, owner, fx, case, address, recording).await;
    server.abort();
    let _ = server.await;
    drop(go);
    result
}

async fn observe_on(
    db: &Db,
    owner: &Client,
    fx: &Fx,
    case: &Case,
    address: SocketAddr,
    recording: bool,
) -> Result<(), BoxError> {
    let token = common::recovery_token(fx.a.user);
    let mut socket = if case.transport == Transport::Ws {
        Some(ws_open(address, &token).await?)
    } else {
        None
    };
    let mut prior = Vec::new();
    for template in case.setup {
        let body = render(template, fx, &prior, &[])?;
        let (_, _, text) = exchange(case.transport, address, &token, &mut socket, &body).await?;
        prior.push(text);
    }
    let vars = (case.vars)(&prior)?;
    for template in case.between {
        owner
            .batch_execute(&render(template, fx, &prior, &vars)?)
            .await?;
    }
    let before = effects(owner, fx, case, &prior, &vars).await?;
    let marks = audit_marks(owner).await?;
    let mut listeners: Vec<(String, Listener)> = Vec::new();
    for template in case.notify {
        let channel = render(template, fx, &prior, &vars)?;
        let listener = db.listen(&channel).await?;
        listeners.push((channel, listener));
    }
    let request = render(case.request, fx, &prior, &vars)?;
    let first = exchange(case.transport, address, &token, &mut socket, &request).await?;
    let repeat = if case.repeat {
        Some(exchange(case.transport, address, &token, &mut socket, &request).await?)
    } else {
        None
    };
    let after = effects(owner, fx, case, &prior, &vars).await?;
    let audit = audit_rows(owner, fx, marks).await?;
    let mut notify = Vec::new();
    for (channel, listener) in &mut listeners {
        for payload in listener.drain(owner).await? {
            notify.push(format!("{channel} {payload}"));
        }
    }
    if let Some(mut socket) = socket.take() {
        let _ = socket.close(None).await;
    }

    let denial = DENIAL_KINDS.contains(&case.kind);
    if denial && case.effects.is_empty() {
        return Err(format!("{}: denial cases must declare effects", case.name).into());
    }
    let mut absent = Vec::new();
    for template in case.absent {
        let value = render(template, fx, &prior, &vars)?;
        if contains_token(&first.2, &value) {
            return Err(format!("{}: {value} must not appear in the response", case.name).into());
        }
        absent.push(value);
    }

    // WS cross-check: the same call over the socket must answer identically.
    if case.transport == Transport::Http && before == after && notify.is_empty() {
        let sent: Value = serde_json::from_str(&request)?;
        let frame = json!({"@type": "Request", "id": "ws-replay",
            "using": sent["using"], "methodCalls": sent["methodCalls"]})
        .to_string();
        let mut ws = Some(ws_open(address, &token).await?);
        let (_, _, text) = exchange(Transport::Ws, address, &token, &mut ws, &frame).await?;
        if let Some(mut ws) = ws.take() {
            let _ = ws.close(None).await;
        }
        let pick = |raw: &str| -> Result<Value, BoxError> {
            let mut value: Value = serde_json::from_str(raw)?;
            mask(&mut value, case.scrub);
            let mut call = value["methodResponses"][0].clone();
            if let Some(items) = call.as_array_mut() {
                items.truncate(2);
            }
            Ok(call)
        };
        if pick(&first.2)? != pick(&text)? {
            return Err(
                format!("{}: WebSocket answer differs from HTTP: {text}", case.name).into(),
            );
        }
    }
    if !recording {
        let (_, _, metrics) = http(address, "GET", "/_gateway/metrics", None, "").await?;
        if !metrics
            .lines()
            .any(|line| line == "setjoin_gateway_proxied_to_go_total 0")
        {
            return Err(format!("{}: a native route used Go", case.name).into());
        }
    }

    // Distinct ids, checked on raw values before scrubbing.
    let mut ids = vec![
        (fx.a.mailbox, "a.mailbox".to_owned()),
        (fx.a.user, "a.user".to_owned()),
        (fx.f.mailbox, "f.mailbox".to_owned()),
        (fx.f.user, "f.user".to_owned()),
    ];
    for (index, seed) in fx.seeds.iter().enumerate() {
        ids.push((*seed, format!("seed.{index}")));
    }
    let distinct: BTreeSet<i64> = ids.iter().map(|(id, _)| *id).collect();
    if distinct.len() != ids.len() {
        return Err(format!("{}: fixture ids are not pairwise distinct", case.name).into());
    }
    let mut replacements = Vec::new();
    let responses: Vec<&String> = prior
        .iter()
        .chain(std::iter::once(&first.2))
        .chain(repeat.iter().map(|r| &r.2))
        .collect();
    for text in responses {
        if let Ok(value) = serde_json::from_str::<Value>(text) {
            for (pointer, name) in case.scrub {
                if let Some(raw) = value.pointer(pointer).and_then(Value::as_str) {
                    replacements.push((raw.to_owned(), (*name).to_owned()));
                }
            }
        }
    }
    for (name, value) in &vars {
        replacements.push((value.clone(), format!("var.{name}")));
    }
    let scrub = Scrubber { replacements, ids };

    let response = |r: &(u16, Value, String)| json!({"status": r.0, "headers": r.1, "body": scrub.apply(&r.2)});
    let mut effect_map = serde_json::Map::new();
    let mut effect_rows = Vec::new();
    for ((name, was), (_, now)) in before.iter().zip(after.iter()) {
        let (was, now) = (scrub.apply(was), scrub.apply(now));
        effect_map.insert(name.clone(), json!({"before": was, "after": now}));
        effect_rows.push(json!({"name": name, "before": was, "after": now}));
    }
    let (method, path) = match case.transport {
        Transport::Http => ("POST", "/jmap"),
        Transport::Ws => ("GET", "/jmap/ws"),
    };
    let observation = json!({
        "request": {"method": method, "path": path, "body": scrub.apply(&request)},
        "setup": prior.iter().map(|text| scrub.apply(text)).collect::<Vec<_>>(),
        "response": response(&first),
        "repeat": repeat.as_ref().map(response),
        "effects": Value::Object(effect_map),
        "audit": audit.iter().map(|row| scrub.apply(row)).collect::<Vec<_>>(),
        "notify": notify.iter().map(|row| scrub.apply(row)).collect::<Vec<_>>(),
        "absent": absent.iter().map(|value| scrub.apply(value)).collect::<Vec<_>>(),
    });

    let route = match case.transport {
        Transport::Http => format!("POST /jmap {}", case.method),
        Transport::Ws => "GET /jmap/ws".to_owned(),
    };
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/jmap/families")
        .join(case.family);
    let divergences: Value = match std::fs::read(directory.join("divergences.json")) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(_) => json!([]),
    };
    if denial
        && divergences
            .as_array()
            .is_some_and(|records| records.iter().any(|r| r["case"] == case.name))
    {
        return Err(format!("{}: denial cases may not carry divergences", case.name).into());
    }
    let path = directory.join(format!("{}.json", case.name));
    let row_path = directory.join(format!("{}-row-effects.json", case.name));
    if recording && !path.exists() {
        std::fs::create_dir_all(&directory)?;
        let source = std::env::var("GOFREE_GO_SOURCE")?;
        golden::record(
            &path,
            &json!({"format": 1, "route": route, "case": case.name, "kind": case.kind,
                "go_source": source, "normalization": RULES, "observation": observation}),
        )?;
        if case.mutator && !row_path.exists() {
            golden::record(
                &row_path,
                &json!({"format": 1, "route": route,
                    "case": format!("{}-row-effects", case.name),
                    "go_source": source, "effects": effect_rows}),
            )?;
        }
        println!("GOLDEN-RECORDED: {route} :: {}", case.name);
        return Ok(());
    }
    let expected: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    if expected["kind"] != case.kind {
        return Err(format!("{}: golden kind differs from the case kind", case.name).into());
    }
    golden::compare_reviewed(
        &route,
        case.name,
        &expected["observation"],
        &observation,
        &divergences,
    )
    .map_err(|diff| format!("{DIFF_PREFIX}{diff}"))?;
    if case.mutator {
        let rows: Value = serde_json::from_slice(&std::fs::read(&row_path)?)?;
        golden::compare(&rows["effects"], &json!(effect_rows))
            .map_err(|diff| format!("{DIFF_PREFIX}row effects: {diff}"))?;
    }
    println!("GOLDEN-REPLAY: {route} :: {}", case.name);
    Ok(())
}

async fn cleanup(
    owner: &Client,
    fx: &Fx,
    toggles: &[(&'static str, Option<bool>)],
    continuity: Option<Continuity>,
) -> Result<(), BoxError> {
    let users = vec![fx.a.user, fx.f.user];
    let mailboxes = vec![fx.a.mailbox, fx.f.mailbox];
    owner
        .query_typed(
            "UPDATE mailboxes SET enabled = true WHERE id = ANY($1) AND NOT enabled",
            &[(&mailboxes, Type::INT8_ARRAY)],
        )
        .await?;
    owner
        .query_typed(
            "UPDATE mailbox_lifecycle SET access_state = 'active', generation = generation + 1, \
             updated_at = statement_timestamp() \
             WHERE mailbox_id = ANY($1) AND access_state = 'suspended'",
            &[(&mailboxes, Type::INT8_ARRAY)],
        )
        .await?;
    owner
        .query_typed(
            "DELETE FROM mailbox_delegates WHERE mailbox_id = ANY($1) OR user_id = ANY($2)",
            &[(&mailboxes, Type::INT8_ARRAY), (&users, Type::INT8_ARRAY)],
        )
        .await?;
    owner
        .query_typed(
            "DELETE FROM user_app_entitlements WHERE user_id = ANY($1)",
            &[(&users, Type::INT8_ARRAY)],
        )
        .await?;
    owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; \
             DELETE FROM continuity_client_witnesses WHERE mailbox_id IN ({},{}); \
             DELETE FROM admin_audit_log WHERE user_id IN ({},{}); COMMIT;",
            fx.a.mailbox, fx.f.mailbox, fx.a.user, fx.f.user
        ))
        .await?;
    for (key, value) in toggles {
        match value {
            Some(enabled) => {
                owner
                    .query_typed(
                        "UPDATE feature_toggles SET enabled = $2 WHERE key = $1",
                        &[(key, Type::TEXT), (enabled, Type::BOOL)],
                    )
                    .await?;
            }
            None => {
                owner
                    .query_typed(
                        "DELETE FROM feature_toggles WHERE key = $1",
                        &[(key, Type::TEXT)],
                    )
                    .await?;
            }
        }
    }
    if let Some((wall, boot, boot_at)) = continuity {
        owner
            .query_typed(
                "UPDATE upgrade_control_state SET continuity_last_wall_clock = $1::text::timestamptz, \
                 continuity_last_boot_epoch = $2::text::uuid, \
                 continuity_last_boot_at = $3::text::timestamptz WHERE singleton",
                &[(&wall, Type::TEXT), (&boot, Type::TEXT), (&boot_at, Type::TEXT)],
            )
            .await?;
    }
    fixture::remove(owner, &fx.a).await?;
    fixture::remove(owner, &fx.f).await?;
    Ok(())
}
