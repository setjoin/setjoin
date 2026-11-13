//! F05 slice `migration`, job runner routes (#431): frozen-Go oracle. Record mode
//! runs the covered Go binary behind the front door with a fake S3 and a scripted
//! IMAP source; replay serves the same requests from Rust with no Go upstream. The
//! observation is the HTTP answer, the committed job/message/tag rows, the
//! object-store requests and the audit rows, after the job settled.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{golden, harness::Db};
use setjoin_gateway::{
    migration::{MigrationRoute, Runner},
    migration_runner::{Config as RunnerConfig, Dialer, Orchestrator},
    recovery_worker::S3Store,
    Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

#[path = "../common/fake_imap.rs"]
mod fake_imap;
#[path = "../drive_workers_oracle/fake_s3.rs"]
mod fake_s3;
mod plan;
mod providers;
use plan::{Fx, Settle, Setup};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Probe {
    inner: MigrationRoute<setjoin_gateway::jmap::jwks::Jwks>,
    changed_status: bool,
}
impl Intercept for Probe {
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let future = self.inner.handle(r, c);
        let changed = self.changed_status;
        Box::pin(async move {
            let mut response = future.await;
            if changed {
                *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            response
        })
    }
}

fn admin_token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
    let fields: Vec<&str> = source.split('.').collect();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = json!(true);
    claims["perms"] = json!(["forged.permission"]);
    claims["auth_time"] = json!(claims["iat"].clone());
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        fields[0],
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn timestamp_like(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && (b[10] == b'T' || b[10] == b' ')
        && b[13] == b':'
}

/// Replace run-specific identities: numeric ids by the key that names them and timestamps.
fn mask(v: &mut Value, ids: &[(&str, i64, String)]) {
    match v {
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                // Provider content dates are fixed input, never wall-clock placeholders.
                if matches!(
                    k.as_str(),
                    "start_at"
                        | "end_at"
                        | "due_at"
                        | "completed_at"
                        | "recurrence_id"
                        | "rdate"
                        | "exdate"
                ) {
                    continue;
                }
                let named = |n: i64| {
                    ids.iter()
                        .find(|(key, id, _)| key == k && *id == n)
                        .map(|(_, _, name)| name.clone())
                };
                if let Some(name) = x.as_i64().and_then(named) {
                    *x = json!(name);
                } else {
                    mask(x, ids);
                }
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask(x, ids)),
        Value::String(s) if timestamp_like(s) => *s = "<timestamp>".into(),
        _ => {}
    }
}

/// An invented Message-ID is random; every other id is a fixture constant.
fn mask_random(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("<imported-") {
        out.push_str(&rest[..at]);
        match rest[at..].find("@migration>") {
            Some(end) => {
                out.push_str("<imported-RANDOM@migration>");
                rest = &rest[at + end + "@migration>".len()..];
            }
            None => {
                out.push_str(&rest[at..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}

async fn snapshot(
    c: &tokio_postgres::Client,
    fx: &Fx,
    s3: &fake_s3::DriveS3,
) -> Result<Value, BoxError> {
    let users = format!("({},{})", fx.a.user, fx.b.user);
    let boxes = format!("({},{})", fx.a.mailbox, fx.b.mailbox);
    let key = setjoin_mailboxes::migration::derive_key(&plan::root(), "migration").expect("key");
    let mut jobs = vec![];
    for row in c
        .query(
            &format!(
                "SELECT jsonb_build_object('id',id,'user_id',user_id,'source',source_type,'status',status,'strategy',conflict_strategy,\
                 'progress',progress,'error_log',error_log,'started',started_at IS NOT NULL,'completed',completed_at IS NOT NULL,\
                 'mailbox',target_mailbox_id,'cursor',resume_cursor::jsonb)::text, source_config_enc \
                 FROM migration_jobs WHERE user_id IN {users} ORDER BY created_at, id"
            ),
            &[],
        )
        .await?
    {
        let mut job: Value = serde_json::from_str(&row.get::<_, String>(0))?;
        let config: Option<Vec<u8>> = row.get(1);
        job["config"] = match config {
            None => json!(null),
            Some(bytes) => match setjoin_mailboxes::migration::open(&bytes, &key) {
                Some(plain) => serde_json::from_slice(&plain)?,
                None => json!("<sealed>"),
            },
        };
        jobs.push(job);
    }
    let mut log = s3.take_log();
    log.sort_by_key(|v| v.to_string());
    Ok(json!({
        "jobs": jobs,
        "messages": rows(c, &format!(
            "SELECT jsonb_build_object('mailbox',mailbox_id,'subject',subject,'message_id',message_id,'from_addr',from_addr,'from_name',from_name,\
             'to',to_addrs,'cc',cc_addrs,'in_reply_to',in_reply_to,'size',size_bytes,'raw_ref',raw_ref,'body_text',body_text,\
             'tags',(SELECT COALESCE(array_agg(t.name ORDER BY t.name),'{{}}') FROM message_tags mt JOIN tags t ON t.id=mt.tag_id \
                     WHERE mt.message_id=messages.id AND mt.received_at=messages.received_at))::text \
             FROM messages WHERE mailbox_id IN {boxes} AND raw_ref NOT LIKE 'raw-%' ORDER BY subject, raw_ref")).await?,
        "tags": rows(c, &format!(
            "SELECT jsonb_build_object('mailbox',t.mailbox_id,'name',t.name,'type',t.tag_type,'color',t.color,'sort',t.sort_order,\
             'parent',(SELECT p.name FROM tags p WHERE p.id=t.parent_id))::text \
             FROM tags t WHERE t.mailbox_id IN {boxes} AND t.tag_type='user' ORDER BY t.mailbox_id, t.name")).await?,
        "objects": s3.keys().into_iter().filter(|k| !k.is_empty()).collect::<Vec<_>>(),
        "s3": log,
    }))
}

pub async fn run(action: &str, kind: &str, is_provider: bool) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(action, kind, is_provider).await
}

fn source_folders() -> Vec<fake_imap::Folder> {
    use fake_imap::{folder, message, message_without_id};
    vec![
        folder(
            "INBOX",
            &["\\HasNoChildren"],
            100,
            vec![
                message(1, "hello", "first body"),
                message(2, "second", "second body"),
                message_without_id(3, "no id", "anonymous"),
            ],
        ),
        folder(
            "Sent",
            &["\\HasNoChildren", "\\Sent"],
            200,
            vec![message(5, "outgoing", "sent body")],
        ),
        folder(
            "Work/Projects",
            &["\\HasNoChildren"],
            300,
            vec![message(1, "nested", "project body")],
        ),
    ]
}

async fn run_inner(action: &str, kind: &str, is_provider: bool) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(db) = Db::for_case("migration-runner-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let p = if is_provider {
        plan::provider_plan(action, label)
    } else {
        plan::plan(action, label)
    };
    let recording = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    // The source: the frozen Go process (in a container) reaches the Docker bridge.
    let bind = match (recording, p.public) {
        (true, true) => format!("{}:0", plan::PUBLIC),
        (true, false) => "172.17.0.1:0".to_owned(),
        _ => "127.0.0.1:0".to_owned(),
    };
    let imap = fake_imap::FakeImap::start(&bind, plan::USER, p.password, source_folders()).await?;
    let port = imap.address.port();
    let mut fx = Fx::build(&owner, label, port).await?;
    let mut providers = if is_provider {
        Some(providers::Providers::start(recording, label).await?)
    } else {
        None
    };
    if let Some(provider) = providers.as_mut() {
        provider.seed(&owner, &fx, action, label).await?;
    }
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F05'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    let s3 = fake_s3::DriveS3::start().await;
    let result = exercise(
        &db,
        &owner,
        &mut fx,
        &p,
        &imap,
        &s3,
        action,
        label,
        mutant,
        providers.as_ref(),
    )
    .await;
    if let Some(provider) = providers.as_ref() {
        provider.restore(&owner).await?;
    }
    imap.release();
    if let Err(error) = &result {
        eprintln!("oracle exercise failed before cleanup: {error}");
    }
    owner
        .execute("DELETE FROM rust_operation_receipts WHERE family='F05' AND operation_id::text<>ALL($1)", &[&receipts])
        .await?;
    fx.remove(&owner).await?;
    owner
        .batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;"))
        .await?;
    result
}

async fn settle(owner: &tokio_postgres::Client, fx: &Fx, how: Settle) -> Result<(), BoxError> {
    match how {
        Settle::Fixed(ms) => tokio::time::sleep(std::time::Duration::from_millis(ms)).await,
        Settle::Terminal => {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
            let mut last = String::new();
            let mut stable_since = std::time::Instant::now();
            loop {
                let state: String = owner
                    .query_one(
                        "SELECT COALESCE(string_agg(id::text||status||COALESCE(progress::text,''), ',' ORDER BY id),'') FROM migration_jobs WHERE user_id=ANY($1)",
                        &[&vec![fx.a.user, fx.b.user]],
                    )
                    .await?
                    .get(0);
                let active: i64 = owner
                    .query_one(
                        "SELECT count(*) FROM migration_jobs WHERE user_id=ANY($1) AND status IN ('fetching','importing')",
                        &[&vec![fx.a.user, fx.b.user]],
                    )
                    .await?
                    .get(0);
                if state != last {
                    last = state;
                    stable_since = std::time::Instant::now();
                }
                if active == 0 && stable_since.elapsed() > std::time::Duration::from_millis(800) {
                    return Ok(());
                }
                if std::time::Instant::now() > deadline {
                    return Err("job did not settle".into());
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn exercise(
    db: &Db,
    owner: &tokio_postgres::Client,
    fx: &mut Fx,
    p: &plan::Plan,
    imap: &fake_imap::FakeImap,
    s3: &fake_s3::DriveS3,
    action: &str,
    label: &str,
    mutant: bool,
    providers: Option<&providers::Providers>,
) -> Result<(), BoxError> {
    let port = imap.address.port();
    let learn = std::env::var_os("GOFREE_ORACLE_LEARN").is_some();
    if p.profile {
        fx.put_profile(owner, port).await?;
    }
    let go = if let Some(provider) = providers {
        provider.go(db, s3.addr).await?
    } else {
        common::go_oracle::start_named(db, s3.addr, None, "gofree-mbox6-run").await?
    };
    let recording = go.is_some();
    for status in ["pending", "paused"] {
        if p.path.contains(&format!("{{ID:{status}}}")) {
            fx.add_active(owner, status).await?;
        }
    }
    if let Some(provider) = providers {
        if !matches!(action, "start" | "test-connection" | "callback") {
            if label.starts_with("upload-") {
                provider.upload_job(owner, fx, s3, label).await?;
            } else {
                provider
                    .control_job(owner, fx, label.split('-').next().unwrap())
                    .await?;
            }
        }
    }
    // The frozen process recomputes used_bytes at startup; set what it would.
    owner.execute("UPDATE mailboxes SET used_bytes=COALESCE((SELECT sum(size_bytes) FROM messages WHERE mailbox_id=mailboxes.id),0) WHERE domain_id=ANY($1)", &[&vec![fx.a.domain, fx.b.domain]]).await?;
    let _ = s3.take_log();
    let patient = std::time::Duration::from_secs(30);
    let timeouts = setjoin_pg::Timeouts {
        pool_wait: patient,
        create: patient,
        statement: patient,
    };
    let exec = ScopedExecutor::from_dsn_with(db.app.as_deref().unwrap_or(&db.dsn), 4, timeouts)
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
    let worker = ScopedExecutor::from_dsn_with(&db.dsn, 4, timeouts)
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
    let store = S3Store::new(
        &format!("http://{}", s3.addr),
        "mailblobs",
        "test-access",
        "test-secret",
    )?;
    // The names the profile lists resolve to the Docker bridge; replay dials the fake directly.
    let target = imap.address;
    let dialer = Dialer::custom(
        |host| {
            Box::pin(async move {
                // A literal names itself; the profile's host resolves to the Docker bridge.
                Ok(vec![host
                    .parse::<std::net::IpAddr>()
                    .unwrap_or_else(|_| "172.17.0.1".parse().unwrap())])
            })
        },
        move |address| {
            Box::pin(async move {
                if address.port() != target.port() {
                    return Err(format!("dial tcp {address}: connect: connection refused"));
                }
                let s = tokio::net::TcpStream::connect(target)
                    .await
                    .map_err(|e| format!("dial tcp {target}: {e}"))?;
                Ok(Box::new(s) as Box<dyn setjoin_gateway::migration_runner::imap::Io>)
            })
        },
    );
    let orchestrator = Orchestrator::with_provider_client(
        RunnerConfig {
            db: setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?
                .with_audit_keys(plan::root(), String::new()),
            store: Arc::new(store),
            root: plan::root(),
            dialer,
            dispatcher: None,
        },
        providers.map(|p| p.peer.client.clone()),
    );
    let adapter = Probe {
        inner: MigrationRoute {
            exec,
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
            encryption_key: plan::root(),
            public_host: "mail.test".into(),
            runner: Some(Runner {
                orchestrator,
                worker,
            }),
        },
        changed_status: mutant,
    };
    let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
    for r in inventory["routes"].as_array_mut().ok_or("routes")? {
        if r["family"] == "F05" && r["slice"] == "migration" {
            r["state"] = json!(if recording { "OFF" } else { "ON" });
            r["upstream"] = json!(if recording { "go-mail" } else { "local-rust" });
            r["oracle_commands"] = json!([""]);
        }
    }
    let gateway = Gateway::new(
        Config {
            upstream: go
                .as_ref()
                .map(|g| format!("http://{}", g.address).parse())
                .transpose()?,
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        RouteTable::proxy_all().with(adapter),
    )?
    .with_inventory(&inventory.to_string())?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(gateway.serve(listener));
    let send = |method: &str, path: String, body: String| {
        let token = admin_token(fx.a.user);
        let method = method.to_owned();
        async move {
            let mut request = Request::builder()
                .method(method.as_str())
                .uri(format!("/api{path}"))
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("content-type", "application/json")
                .header("x-request-id", "gofree-mbox6-oracle")
                .header("authorization", format!("Bearer {token}"));
            if action == "callback" && label != "no-cookie" {
                request = request.header("cookie", "m365_oauth_state=fixture-state");
            }
            Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
        }
    };
    // Setup: a job running over a source that holds its fetches.
    let mut started: Option<i64> = None;
    if p.stall {
        imap.hold_fetches();
    }
    if p.setup == Setup::Running {
        let body = plan::fill(
            &format!(
                r#"{{"source_type":"imap","imap_host":"{}","imap_port":{{PORT}},"imap_ssl":false,"targets":[{{"source_email":"alice","target_email":"{{TARGET}}","password":"pw"}}]}}"#,
                plan::HOST
            ),
            fx,
            None,
            port,
        );
        let first = send("POST", "/admin/migration/start".into(), body).await?;
        let status = first.status().as_u16();
        let text = String::from_utf8(common::body_bytes(first).await.to_vec())?;
        if status != 201 && !(mutant && status == 418) {
            return Err(format!("setup start: {status} {text}").into());
        }
        let v: Value = serde_json::from_str(&text)?;
        started = v["ids"][0].as_i64();
        tokio::time::timeout(
            std::time::Duration::from_secs(20),
            imap.state.reached_fetch.notified(),
        )
        .await
        .map_err(|_| "the job never reached the source")?;
    }
    if p.repeat && p.setup == Setup::None {
        let first = send(
            p.method,
            plan::fill(&p.path, fx, started, port),
            plan::fill(&p.body, fx, started, port),
        )
        .await?;
        let status = first.status().as_u16();
        let data = common::body_bytes(first).await;
        if recording && action == "start" && !(200..300).contains(&status) {
            return Err(format!("initial {action}: {status} {data:?}").into());
        }
        settle(owner, fx, p.settle).await?;
    }
    let since_audit: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let mut listeners = vec![];
    if providers.is_some() {
        for mailbox in [fx.a.mailbox, fx.b.mailbox] {
            for kind in ["calendar", "contact", "email", "tag", "thread"] {
                let channel = format!("{kind}:{mailbox}");
                listeners.push((channel, db.listen(&format!("{kind}:{mailbox}")).await?));
            }
        }
    }
    let mut before = snapshot(owner, fx, s3).await?;
    if providers.is_some() {
        before["provider_effects"] = providers::snapshot(owner, fx).await?;
    }
    if let Some(provider) = providers {
        provider.peer.seen.lock().unwrap().clear();
    }
    let request_path = plan::fill(&p.path, fx, started, port);
    let request_body = plan::fill(&p.body, fx, started, port);
    let response = send(p.method, request_path.clone(), request_body.clone()).await?;
    let status = response.status().as_u16();
    let mut headers = serde_json::Map::new();
    for name in response.headers().keys() {
        headers.insert(
            name.to_string(),
            json!(response
                .headers()
                .get_all(name)
                .iter()
                .map(|v| v.to_str().unwrap().to_owned())
                .collect::<Vec<_>>()),
        );
    }
    let bytes = common::body_bytes(response).await;
    let raw = String::from_utf8(bytes.to_vec())?;
    if recording && learn {
        eprintln!(
            "LEARN {action}/{label} {status} {}",
            raw.chars().take(200).collect::<String>().replace('\n', " ")
        );
    }
    // A repeated cancel/pause of a stalled job must not leave the source blocked.
    if p.stall && p.settle == Settle::Terminal {
        imap.release();
    }
    settle(owner, fx, p.settle).await?;
    imap.release();
    if label.starts_with("upload-") && !label.ends_with("missing") {
        let row = owner
            .query_one(
                "SELECT status,progress::text FROM migration_jobs WHERE id=$1",
                &[&fx.pending],
            )
            .await?;
        let progress: Value = serde_json::from_str(&row.get::<_, String>(1))?;
        let phases: Vec<&str> = if label.contains("compound") {
            vec!["ics", "vcf"]
        } else if label.contains("ics") {
            vec!["ics"]
        } else {
            vec!["vcf"]
        };
        for phase in phases {
            let count = progress[phase]["imported"].as_i64().unwrap_or(0)
                + progress[phase]["skipped"].as_i64().unwrap_or(0);
            if row.get::<_, String>(0) != "completed" || count == 0 {
                return Err(format!("positive upload fixture failed {phase}: {progress}").into());
            }
        }
    }
    let mut after = snapshot(owner, fx, s3).await?;
    if providers.is_some() {
        after["provider_effects"] = providers::snapshot(owner, fx).await?;
    }
    let mut ids = fx.ids();
    if providers.is_some() {
        ids.extend(providers::ids(owner, fx).await?);
    }
    let mut notifications = vec![];
    for (channel, mut listener) in listeners {
        for payload in listener.drain(owner).await? {
            let mut v: Value = serde_json::from_str(&payload)?;
            mask(&mut v, &ids);
            let channel = channel
                .replace(&fx.a.mailbox.to_string(), "<mailbox-a>")
                .replace(&fx.b.mailbox.to_string(), "<mailbox-b>");
            notifications.push(json!({"channel":channel,"payload":v}));
        }
    }
    notifications.sort_by_key(|v| v.to_string());
    // Jobs the requests created: named by the order they were created in.
    let known: Vec<i64> = fx.jobs().iter().map(|(id, _)| *id).collect();
    let mut extra: Vec<(i64, String)> = vec![];
    for (n, row) in owner
        .query(
            "SELECT id FROM migration_jobs WHERE user_id=ANY($1) AND id<>ALL($2) ORDER BY id",
            &[&vec![fx.a.user, fx.b.user], &known],
        )
        .await?
        .iter()
        .enumerate()
    {
        let id: i64 = row.get(0);
        let name = if Some(id) == started {
            "<job-started>".to_owned()
        } else {
            format!("<job-new-{}>", n + 1 - usize::from(started.is_some()))
        };
        ids.push(("id", id, name.clone()));
        ids.push(("job_id", id, name.clone()));
        extra.push((id, name));
    }
    let mut audit: Vec<Value> = owner
        .query(
            "SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id",
            &[&since_audit],
        )
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)))
        .collect::<Result<_, _>>()?;
    for row in &mut audit {
        row["id"] = json!("<audit>");
        for key in ["checksum", "prev_checksum"] {
            if row[key].as_str().is_some_and(|s| !s.is_empty()) {
                row[key] = json!("<checksum>");
            }
        }
        let text = names(&fx.names(&row.to_string(), port), fx, &extra);
        *row = serde_json::from_str(&text)?;
        mask(row, &ids);
    }
    if let Some(date) = headers.get_mut("date") {
        *date = json!(["<timestamp>"]);
    }
    let text = names(&fx.names(&mask_random(&raw), port), fx, &extra);
    if let Some(length) = headers.get_mut("content-length") {
        *length = json!([text.len().to_string()]);
    }
    let finish = |v: Value| -> Value {
        let mut v: Value = serde_json::from_str(&names(
            &fx.names(&mask_random(&v.to_string()), port),
            fx,
            &extra,
        ))
        .expect("json");
        mask(&mut v, &ids);
        v
    };
    let (before, after) = (finish(before), finish(after));
    let effects =
        json!([{"table":"migration_jobs+messages+tags+objects","before":before,"after":after}]);
    let mut request =
        json!({"method":p.method,"path":p.pattern,"external_path":format!("/api{}", p.pattern)});
    if !p.body.is_empty() {
        request["body"] = json!(p.body);
    }
    let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notifications});
    let mut observation = observation;
    if let Some(provider) = providers {
        observation["provider_requests"] = providers::requests(&provider.peer);
    }

    if !recording {
        let metrics = common::send(
            address,
            Request::get("/_gateway/metrics").body(common::full(""))?,
        )
        .await;
        let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
        if !metrics
            .lines()
            .any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F05\"} 0")
        {
            return Err(format!("F05 replay forwarded to Go: {metrics}").into());
        }
    }
    server.abort();
    if let Some(dir) = std::env::var_os("GOFREE_ORACLE_DUMP") {
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            std::path::Path::new(&dir).join(format!("{action}-{label}.json")),
            serde_json::to_string_pretty(&observation)?,
        )?;
    }
    if recording && learn {
        if let Some(dir) = std::env::var_os("GOFREE_ORACLE_DUMP") {
            std::fs::create_dir_all(&dir)?;
            std::fs::write(
                std::path::Path::new(&dir).join(format!("{action}-{label}.json")),
                serde_json::to_string_pretty(&observation)?,
            )?;
        }
        return Ok(());
    }
    let name = format!("{action}-{label}");
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/migration/goldens");
    std::fs::create_dir_all(&dir)?;
    let file = dir.join(format!("{name}.json"));
    let row_file = dir.join(format!("{name}-row-effects.json"));
    let route_name = format!("{} {}", p.method, p.pattern);
    if recording {
        let source = std::env::var("GOFREE_GO_SOURCE")?;
        record(
            &file,
            &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}),
        )?;
        record(
            &row_file,
            &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}),
        )?;
    } else {
        // A baseline pinned in migration/divergences.json (#536) is compared with its reviewed
        // security expectation; every other golden is the immutable frozen-Go recording.
        let expected = common::golden_doc(&file, "observation", &observation);
        let compared = golden::compare(&expected["observation"], &observation);
        if mutant {
            let error = compared.err().ok_or("planted status mutant survived")?;
            if !error.contains("/response/status") {
                return Err(format!("mutant failed outside response status: {error}").into());
            }
            eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
            return Ok(());
        }
        compared?;
        let expected = common::golden_doc(&row_file, "effects", &observation["effects"]);
        golden::compare(&expected["effects"], &observation["effects"])?;
        eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
    }
    Ok(())
}

/// Job and mailbox ids named by fixture.
fn names(text: &str, fx: &Fx, extra: &[(i64, String)]) -> String {
    let mut out = text.to_owned();
    for (id, name) in fx.jobs() {
        out = out.replace(
            &format!("migration/upload/{id}/"),
            &format!("migration/upload/{name}/"),
        );
        out = out.replace(&format!("/jobs/{id}/"), &format!("/jobs/{name}/"));
        out = out.replace(&format!("/jobs/{id}\""), &format!("/jobs/{name}\""));
    }
    for (id, name) in extra {
        out = out.replace(
            &format!("migration/upload/{id}/"),
            &format!("migration/upload/{name}/"),
        );
        out = out.replace(&format!("/jobs/{id}/"), &format!("/jobs/{name}/"));
        out = out.replace(&format!("\"ids\":[{id}]"), &format!("\"ids\":[\"{name}\"]"));
        out = out.replace(&format!("\"ids\":[{id},"), &format!("\"ids\":[\"{name}\","));
        out = out.replace(&format!(",{id}]"), &format!(",\"{name}\"]"));
    }
    out.replace(&format!("domain={})", fx.a.domain), "domain=<domain-a>)")
}

fn record(path: &std::path::Path, value: &Value) -> Result<(), BoxError> {
    if path.exists() || std::env::var_os("GOFREE_VERIFY_GO").is_some() {
        let expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        golden::compare(&expected, value)?;
        Ok(())
    } else {
        golden::record(path, value).map_err(Into::into)
    }
}
