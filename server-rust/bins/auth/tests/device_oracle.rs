//! #341 device trust accept side: frozen Go -> actual front door recording;
//! native replay has no Go upstream. Contract and recording inputs:
//! tests/conformance/identity-device/README.md.
#[allow(dead_code)]
mod common;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{Gateway, RouteTable, TrustedProxies};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_postgres::Client;

type Err = Box<dyn std::error::Error + Send + Sync>;
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// Frozen-Go commit of the recorded corpus (phase 2 pins the artifact's value).
const GO_SOURCE: &str = "0000000000000000000000000000000000000000";
const REVIEW: &str = "owner-approved security policy (Go-free security bug policy)";
const SECRET_A: &str = "a341a341a341a341a341a341a341a341a341a341a341a341a341a341a341a341";
const SECRET_B: &str = "b341b341b341b341b341b341b341b341b341b341b341b341b341b341b341b341";
const WRONG_SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const SEEDED_SEEN: &str = "2026-01-02T03:04:05Z";

struct Server {
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
    addr: std::net::SocketAddr,
}
impl Server {
    async fn close(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.task).await;
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn auth_server(server: Arc<AuthServer>, mutant: bool) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        tokio::pin!(rx);
        loop {
            tokio::select! {
                _ = &mut rx => break,
                accepted = listener.accept() => {
                    let (stream, peer) = accepted.unwrap();
                    let server = server.clone();
                    connections.spawn(async move {
                        let service = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
                            let server = server.clone();
                            req.extensions_mut().insert(setjoin_auth::ConnectionMeta { peer, tls: false });
                            async move {
                                let mut response = server.handle(req.map(|b| b.map_err(std::io::Error::other).boxed())).await;
                                if mutant {
                                    *response.status_mut() = hyper::StatusCode::from_u16(599).unwrap();
                                }
                                Ok::<_, std::convert::Infallible>(response)
                            }
                        });
                        let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                            .await;
                    });
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    });
    Server {
        stop: Some(tx),
        task,
        addr,
    }
}
async fn gateway(auth: std::net::SocketAddr, record: Option<String>) -> Server {
    let mut inventory: Value = serde_json::from_str(setjoin_gateway::inventory::BUNDLED).unwrap();
    inventory["routes"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["listener"] == "auth");
    for r in inventory["routes"].as_array_mut().unwrap() {
        r["state"] = json!(if record.is_some() { "OFF" } else { "ON" });
        r["upstream"] = json!(if record.is_some() {
            "go-auth"
        } else {
            "rust-auth"
        });
    }
    let gw = Gateway::new(
        setjoin_gateway::Config {
            upstream: record.as_ref().map(|u| u.parse().unwrap()),
            upstream_header_timeout: std::time::Duration::from_secs(30),
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            edge_limit: Some(setjoin_gateway::jmap::limit::EdgeLimit::for_front_door(
                setjoin_gateway::jmap::limit::Limiter::new(60000, 60),
            )),
        },
        RouteTable::proxy_all(),
    )
    .unwrap()
    .with_inventory(&inventory.to_string())
    .unwrap();
    let gw = if let Some(url) = record {
        gw.with_auth_upstream(url.parse().unwrap()).unwrap()
    } else {
        gw.with_rust_auth_upstream(format!("http://{auth}").parse().unwrap())
            .unwrap()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let task = tokio::spawn(gw.serve_until(listener, async {
        let _ = rx.await;
    }));
    Server {
        stop: Some(tx),
        task,
        addr,
    }
}
async fn request(
    addr: std::net::SocketAddr,
    method: &str,
    uri: &str,
    payload: &str,
    headers: &[(String, String)],
) -> Result<(u16, Value, String), Err> {
    let client: hyper_util::client::legacy::Client<_, setjoin_auth::Body> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let mut req = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{uri}"))
        .header("host", "auth.device341.test")
        .header("user-agent", "DEVICE341 oracle");
    if method == "POST" {
        req = req.header("content-type", "application/json");
    }
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = client.request(req.body(body(payload.to_owned()))?).await?;
    let status = resp.status().as_u16();
    let mut hs = serde_json::Map::new();
    for name in [
        "content-type",
        "cache-control",
        "etag",
        "allow",
        "x-content-type-options",
    ] {
        if let Some(v) = resp.headers().get(name) {
            hs.insert(name.into(), json!(v.to_str()?));
        }
    }
    if method == "HEAD" {
        if let Some(v) = resp.headers().get("content-length") {
            hs.insert("content-length".into(), json!(v.to_str()?));
        }
    }
    let raw = String::from_utf8(resp.into_body().collect().await?.to_bytes().to_vec())?;
    Ok((status, Value::Object(hs), raw))
}
fn corpus() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/identity-device/goldens")
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn sha(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(bytes))
}
fn go_source(record: bool) -> Result<String, Err> {
    if !record {
        return Ok(GO_SOURCE.into());
    }
    let sha = match std::env::var("GOFREE_RECORD_GO_SOURCE") {
        Ok(v) => v,
        Err(_) => String::from_utf8(
            std::process::Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .output()?
                .stdout,
        )?
        .trim()
        .to_owned(),
    };
    if sha.len() != 40
        || !sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!("frozen Go source is not a commit: {sha}").into());
    }
    Ok(sha)
}
/// The frozen-Go baseline, or for a reviewed security divergence the baseline
/// with its owner-approved replacements (hash-pinned; never in record mode).
fn expected(file: &std::path::Path, record: bool) -> Result<Value, Err> {
    let bytes = std::fs::read(file)?;
    let baseline: Value = serde_json::from_slice(&bytes)?;
    if record {
        return Ok(baseline);
    }
    let entries: Value = serde_json::from_str(&std::fs::read_to_string(
        corpus().with_file_name("divergences.json"),
    )?)?;
    let name = format!(
        "goldens/{}",
        file.file_name()
            .and_then(|n| n.to_str())
            .ok_or("golden name")?
    );
    let Some(entry) = entries
        .as_array()
        .ok_or("divergences.json must be an array")?
        .iter()
        .find(|e| e["baseline"] == name.as_str())
    else {
        return Ok(baseline);
    };
    if entry["reviewed"] != true || entry["review"] != REVIEW {
        return Err(format!("{name}: divergence is not owner-reviewed").into());
    }
    if entry["sha256"] != sha(&bytes).as_str() {
        return Err(format!("{name}: frozen-Go capture changed").into());
    }
    let mut doc = baseline;
    for r in entry["replace"].as_array().ok_or("replace list")? {
        let pointer = r["pointer"].as_str().ok_or("pointer")?;
        *doc.pointer_mut(pointer)
            .ok_or_else(|| format!("{name}: stale pointer {pointer}"))? = r["value"].clone();
    }
    Ok(doc)
}

/// shared/device.ChallengeForRequest signed with a per-device secret.
struct Sign<'a> {
    id: i64,
    secret: &'a str,
    method: &'a str,
    uri: &'a str,
    payload: &'a str,
    nonce: &'a str,
    ts: String,
    hash: Option<String>,
}
impl Sign<'_> {
    fn headers(self) -> Vec<(String, String)> {
        let hash = self.hash.unwrap_or_else(|| sha(self.payload.as_bytes()));
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, self.secret.as_bytes());
        let challenge = format!(
            "{}:{}:{}:{}:{hash}:{}",
            self.id, self.ts, self.method, self.uri, self.nonce
        );
        let mac = hex(ring::hmac::sign(&key, challenge.as_bytes()).as_ref());
        vec![
            ("x-device-timestamp".into(), self.ts),
            ("x-device-nonce".into(), self.nonce.into()),
            ("x-device-body-sha256".into(), hash),
            ("x-device-hmac".into(), mac),
        ]
    }
}
struct Step {
    method: &'static str,
    uri: String,
    payload: String,
    headers: Vec<(String, String)>,
}
fn burst(n: usize) -> String {
    (0..n)
        .map(|i| format!(r#"{{"type":"burst","data":"{i}"}}"#))
        .collect::<Vec<_>>()
        .join(",")
}
fn main_nonce(route: &str, kind: &str) -> String {
    match kind {
        "nonce-too-long" => "n".repeat(129),
        "nonce-max" => "n".repeat(128),
        "nonce-purge" => "gofree341-stale".to_owned(),
        _ => format!("gofree341-{route}-{kind}"),
    }
}
fn step(route: &str, kind: &str, s: &Seed, etag: Option<&str>, nonce: &str) -> Step {
    let (a, b) = (s.dev_a, s.dev_b);
    let (method, uri, payload) = if route == "policy" {
        let uri = match kind {
            "invalid-input" => "/device/policy".to_owned(),
            "malformed-id" => "/device/policy?device_id=abc".to_owned(),
            "prefix-id" => format!("/device/policy?device_id={a}x"),
            _ => format!("/device/policy?device_id={a}"),
        };
        (
            if kind == "head" { "HEAD" } else { "GET" },
            uri,
            String::new(),
        )
    } else {
        let payload = match kind {
            "prelude" => format!(r#"{{"device_id":{a}}}"#),
            "invalid-input" => r#"{"policy_version":0}"#.to_owned(),
            "malformed-id" => format!(r#"{{"device_id":"{a}"}}"#),
            "malformed-json" => "{bad".to_owned(),
            "invalid-events" => format!(r#"{{"device_id":{a},"events":"os_update"}}"#),
            "null-event" => format!(r#"{{"device_id":{a},"events":[null,{{"type":"crash"}}]}}"#),
            "folded-keys" => format!(
                r#"{{"DEVICE_ID":{a},"Events":[{{"TYPE":"os_update","Data":"folded"}}],"Policy_Version":0}}"#
            ),
            "current-version" => format!(
                r#"{{"device_id":{a},"policy_version":{}}}"#,
                etag.unwrap_or("0")
            ),
            "duplicate-id" => format!(r#"{{"device_id":{b},"device_id":{a},"policy_version":0}}"#),
            "event-cap" => format!(r#"{{"device_id":{a},"events":[{}]}}"#, burst(100)),
            "event-flood" => format!(r#"{{"device_id":{a},"events":[{}]}}"#, burst(101)),
            "fault" => format!(r#"{{"device_id":{a},"events":[{{"type":"gofree341-fail"}}]}}"#),
            "oversize" => format!(r#"{{"device_id":{a},"pad":"{}"}}"#, "x".repeat(70_000)),
            _ => format!(
                r#"{{"device_id":{a},"policy_version":0,"events":[{{"type":"os_update","timestamp":"2026-01-02T03:04:05Z","data":"17.1"}},{{"type":"jailbreak_detected","data":"<frida>&"}}]}}"#
            ),
        };
        ("POST", "/device/checkin".to_owned(), payload)
    };
    let secret = match kind {
        "cross-tenant" => SECRET_B,
        "bad-hmac" => WRONG_SECRET,
        _ => SECRET_A,
    };
    let ts = match kind {
        "expired" => (now() - 600).to_string(),
        "future-skew" => (now() + 600).to_string(),
        "skew-inside" => (now() - 240).to_string(),
        "success" => chrono::DateTime::from_timestamp(now(), 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        _ => now().to_string(),
    };
    let unsigned = matches!(
        kind,
        "missing-proof" | "invalid-input" | "malformed-id" | "malformed-json" | "oversize"
    );
    let mut headers = if unsigned {
        Vec::new()
    } else {
        Sign {
            id: a,
            secret,
            method,
            uri: &uri,
            payload: &payload,
            nonce,
            ts,
            hash: (kind == "body-digest").then(|| sha(b"gofree341-tampered-body")),
        }
        .headers()
    };
    match (kind, etag) {
        ("not-modified" | "wipe-etag", Some(tag)) => {
            headers.push(("if-none-match".into(), tag.into()))
        }
        ("stale-etag", _) => headers.push(("if-none-match".into(), "1".into())),
        _ => {}
    }
    Step {
        method,
        uri,
        payload,
        headers,
    }
}

struct Seed {
    a: fixture::Account,
    b: fixture::Account,
    dev_a: i64,
    dev_b: i64,
    dept: Option<i64>,
}
impl Seed {
    async fn create(c: &Client, master: &str, kind: &str) -> Result<Self, Err> {
        let residue: i64 = c
            .query_one(
                "SELECT count(*) FROM device_policy WHERE device_id IS NULL AND policy_key LIKE 'gofree341\\_%'",
                &[],
            )
            .await?
            .get(0);
        if residue != 0 {
            return Err(
                "gofree341 org-wide device_policy residue; baseline V001 org-wide rows are part of the corpus"
                    .into(),
            );
        }
        let a = fixture::account(c, "device341-actor").await?;
        let b = fixture::account(c, "device341-foreign").await?;
        let mut seed = Seed {
            a,
            b,
            dev_a: 0,
            dev_b: 0,
            dept: None,
        };
        if let Err(error) = seed.populate(c, master, kind).await {
            seed.cleanup(c).await?;
            return Err(error);
        }
        Ok(seed)
    }
    async fn populate(&mut self, c: &Client, master: &str, kind: &str) -> Result<(), Err> {
        let seal = |secret: &str| {
            setjoin_config_secret::seal_column(
                secret.as_bytes(),
                master.as_bytes(),
                setjoin_config_secret::CryptoProfile::Standard,
            )
        };
        let (plain_a, enc_a, key_a): (Option<&str>, Option<Vec<u8>>, Option<&str>) = match kind {
            "legacy-secret" => (Some(SECRET_A), None, None),
            "unknown-key" => (None, Some(seal(SECRET_A)?), Some("v2")),
            "corrupt-envelope" => (
                None,
                Some(b"gofree341-not-an-envelope".to_vec()),
                Some("v1"),
            ),
            "no-secret" => (None, None, None),
            _ => (None, Some(seal(SECRET_A)?), Some("v1")),
        };
        let enc_b = Some(seal(SECRET_B)?);
        let insert = "INSERT INTO devices(user_id,device_name,platform,os_version,app_version,fingerprint,hmac_secret,hmac_secret_enc,hmac_secret_key_id,last_seen) VALUES($1,$2,'ios','17.0','1.0.0',$3,$4,$5,$6,$7::text::timestamptz) RETURNING id";
        self.dev_a = c
            .query_one(
                insert,
                &[
                    &self.a.user,
                    &"Oracle device A",
                    &"gofree341-fingerprint-a-0123456789abcdef",
                    &plain_a,
                    &enc_a,
                    &key_a,
                    &SEEDED_SEEN,
                ],
            )
            .await?
            .get(0);
        self.dev_b = c
            .query_one(
                insert,
                &[
                    &self.b.user,
                    &"Oracle device B",
                    &"gofree341-fingerprint-b-0123456789abcdef",
                    &None::<&str>,
                    &enc_b,
                    &Some("v1"),
                    &SEEDED_SEEN,
                ],
            )
            .await?
            .get(0);
        c.execute(
            "INSERT INTO device_policy(device_id,policy_key,policy_value) VALUES($1,'gofree341_lock_timeout','300'),($1,'gofree341_note','<b>&ok</b>'),($2,'gofree341_lock_timeout','60'),($2,'gofree341_foreign','never-a')",
            &[&self.dev_a, &self.dev_b],
        )
        .await?;
        match kind {
            "revoked" => {
                c.execute(
                    "UPDATE devices SET enroll_state='revoked',revoked_at=now() WHERE id=$1",
                    &[&self.dev_a],
                )
                .await?;
            }
            "wipe" => {
                c.execute(
                    "UPDATE devices SET wipe_requested=true WHERE id=$1",
                    &[&self.dev_a],
                )
                .await?;
            }
            "nonce-purge" => {
                c.execute(
                    "INSERT INTO device_auth_nonces(device_id,nonce,expires_at,claimed_at) VALUES($1,'gofree341-stale',now()-interval '1 hour',now()-interval '2 hours')",
                    &[&self.dev_a],
                )
                .await?;
            }
            "fault" => {
                c.batch_execute("CREATE FUNCTION public.gofree341_event_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.event_type='gofree341-fail' THEN RAISE EXCEPTION 'gofree341 injected event failure'; END IF; RETURN NEW; END;$$;CREATE TRIGGER gofree341_event_fail BEFORE INSERT ON device_events FOR EACH ROW EXECUTE FUNCTION public.gofree341_event_fail();").await?;
            }
            "group" => {
                let dept: i64 = c
                    .query_one("INSERT INTO departments(name,path,ldap_ou) VALUES('gofree341-dept','/gofree341-dept','ou=gofree341') RETURNING id", &[])
                    .await?
                    .get(0);
                self.dept = Some(dept);
                c.execute(
                    "UPDATE users SET department_id=$1 WHERE id=$2",
                    &[&dept, &self.a.user],
                )
                .await?;
                c.execute(
                    "INSERT INTO device_policy_groups(group_type,group_id,policy_key,policy_value) VALUES('department',$1,'gofree341_layer','group'),('department',$1,'gofree341_group_only','d')",
                    &[&dept],
                )
                .await?;
                c.execute(
                    "INSERT INTO device_policy(device_id,policy_key,policy_value) VALUES(NULL,'gofree341_layer','global'),(NULL,'gofree341_global_only','g'),($1,'gofree341_layer','device')",
                    &[&self.dev_a],
                )
                .await?;
            }
            _ => {}
        }
        Ok(())
    }
    fn mask(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for (id, label) in [(self.dev_a, "device-a"), (self.dev_b, "device-b")] {
            out = out.replace(
                &format!("\"device_id\":\"{id}\""),
                &format!("\"device_id\":\"<{label}-text>\""),
            );
            for key in ["device_id", "DEVICE_ID"] {
                for end in [",", "}"] {
                    out = out.replace(
                        &format!("\"{key}\":{id}{end}"),
                        &format!("\"{key}\":\"<{label}>\"{end}"),
                    );
                }
            }
        }
        out
    }
    fn mask_query(&self, query: &str) -> String {
        match query.strip_prefix(&format!("device_id={}", self.dev_a)) {
            Some(rest) => format!("device_id=<device-a>{rest}"),
            None => query.to_owned(),
        }
    }
    fn response(&self, raw: &str) -> Result<String, Err> {
        let mut out = self.mask(raw);
        if let Ok(v) = serde_json::from_str::<Value>(raw) {
            if let Some(t) = v.get("updated_at") {
                let t = t.as_str().ok_or("updated_at is not a string")?;
                let parsed = chrono::DateTime::parse_from_rfc3339(t)?;
                if !t.ends_with('Z') || (now() - parsed.timestamp()).abs() > 60 {
                    return Err(format!("updated_at is not a fresh UTC time: {t}").into());
                }
                out = out.replace(t, "<timestamp>");
            }
        }
        Ok(out)
    }
    async fn effects(&self, c: &Client) -> Result<Value, Err> {
        let ids = vec![self.dev_a, self.dev_b];
        let raw: String = c.query_one("SELECT jsonb_build_object(
            'devices',(SELECT COALESCE(jsonb_agg(jsonb_build_object('device',CASE WHEN d.id=$1 THEN '<device-a>' ELSE '<device-b>' END,'last_seen',CASE WHEN d.last_seen=$3::text::timestamptz THEN 'seeded' WHEN d.last_seen>now()-interval '5 minutes' THEN 'fresh' ELSE 'other' END,'wipe_requested',d.wipe_requested,'enroll_state',d.enroll_state,'revoked',d.revoked_at IS NOT NULL,'secret_key',d.hmac_secret_key_id,'plaintext_secret',d.hmac_secret IS NOT NULL) ORDER BY d.id),'[]'::jsonb) FROM devices d WHERE d.id=ANY($2)),
            'device_events',(SELECT COALESCE(jsonb_agg(jsonb_build_object('device',CASE WHEN e.device_id=$1 THEN '<device-a>' ELSE '<device-b>' END,'event_type',e.event_type,'event_data',e.event_data,'severity',e.severity,'details',e.details) ORDER BY e.id),'[]'::jsonb) FROM device_events e WHERE e.device_id=ANY($2)),
            'device_auth_nonces',(SELECT COALESCE(jsonb_agg(jsonb_build_object('device',CASE WHEN n.device_id=$1 THEN '<device-a>' ELSE '<device-b>' END,'nonce',n.nonce,'window_seconds',extract(epoch FROM n.expires_at-n.claimed_at)::int) ORDER BY n.device_id,n.nonce),'[]'::jsonb) FROM device_auth_nonces n WHERE n.device_id=ANY($2)))::text",
            &[&self.dev_a, &ids, &SEEDED_SEEN]).await?.get(0);
        Ok(serde_json::from_str(&raw)?)
    }
    async fn cleanup(&self, c: &Client) -> Result<(), Err> {
        let ids = format!("{},{}", self.dev_a, self.dev_b);
        c.batch_execute("DROP TRIGGER IF EXISTS gofree341_event_fail ON device_events;DROP FUNCTION IF EXISTS public.gofree341_event_fail()").await?;
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM device_auth_nonces WHERE device_id IN ({ids});DELETE FROM device_events WHERE device_id IN ({ids});DELETE FROM device_policy WHERE device_id IN ({ids}) OR (device_id IS NULL AND policy_key LIKE 'gofree341\\_%');DELETE FROM device_policy_groups WHERE policy_key LIKE 'gofree341\\_%';DELETE FROM devices WHERE id IN ({ids});COMMIT;")).await?;
        if let Some(dept) = self.dept {
            c.execute(
                "UPDATE users SET department_id=NULL WHERE id=$1",
                &[&self.a.user],
            )
            .await?;
            c.execute("DELETE FROM departments WHERE id=$1", &[&dept])
                .await?;
        }
        fixture::remove(c, &self.a).await?;
        fixture::remove(c, &self.b).await?;
        Ok(())
    }
}

async fn run(route: &'static str, kind: &'static str, mutant: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("DEVICE341-http") else {
        return Ok(());
    };
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none(), "mutants cannot record");
    let app = db.app.clone().ok_or(
        "DB_APP_DSN is required: Go's heartbeat UPDATE is recorded under the runtime credential",
    )?;
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    let result = exercise(&c, &app, route, kind, mutant, record).await;
    c.query_one(
        "SELECT pg_advisory_unlock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    result
}
async fn exercise(
    c: &Client,
    app: &str,
    route: &'static str,
    kind: &'static str,
    mutant: bool,
    record: Option<String>,
) -> Result<(), Err> {
    common::signing_key(c).await;
    let receipts = common::receipt_ids(c).await;
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let master = keys["secret"]
        .as_str()
        .ok_or("keys.json secret")?
        .to_owned();
    let seed = Seed::create(c, &master, kind).await?;
    let outcome = async {
        let exec = setjoin_pg::ScopedExecutor::from_dsn(app, 4).map_err(|e| e.0)?;
        let auth = auth_server(
            Arc::new(AuthServer::load(exec, Config::for_secret(master.clone())).await?),
            mutant,
        )
        .await;
        let gw = gateway(auth.addr, record.clone()).await;
        let observed = observe(c, &seed, gw.addr, route, kind, mutant, record.as_deref()).await;
        gw.close().await;
        auth.close().await;
        observed
    }
    .await;
    let cleaned = seed.cleanup(c).await;
    common::restore_receipts(c, &receipts).await;
    outcome.and(cleaned)
}
async fn observe(
    c: &Client,
    s: &Seed,
    addr: std::net::SocketAddr,
    route: &'static str,
    kind: &'static str,
    mutant: bool,
    record: Option<&str>,
) -> Result<(), Err> {
    let (method, path) = if route == "policy" {
        ("GET", "/device/policy")
    } else {
        ("POST", "/device/checkin")
    };
    let route_name = format!("{method} {path}");
    let go_source = go_source(record.is_some())?;
    let nonce = main_nonce(route, kind);
    let before = s.effects(c).await?;
    let prelude_route = match kind {
        "not-modified" | "current-version" => Some(route),
        "wipe-etag" | "cross-endpoint-nonce" => Some("policy"),
        _ => None,
    };
    let mut prelude = None;
    let mut etag = None;
    if let Some(prelude_route) = prelude_route {
        let prelude_nonce = if kind == "cross-endpoint-nonce" {
            nonce.clone()
        } else {
            format!("{nonce}-prelude")
        };
        let p = step(prelude_route, "prelude", s, None, &prelude_nonce);
        let (status, headers, raw) =
            request(addr, p.method, &p.uri, &p.payload, &p.headers).await?;
        let tag = headers
            .get("etag")
            .and_then(Value::as_str)
            .filter(|_| status == 200)
            .ok_or_else(|| format!("prelude {status} without ETag: {raw}"))?
            .to_owned();
        prelude = Some(json!({"status":status,"headers":headers,"body":s.response(&raw)?}));
        etag = Some(tag);
        if kind == "wipe-etag" {
            c.execute(
                "UPDATE devices SET wipe_requested=true WHERE id=$1",
                &[&s.dev_a],
            )
            .await?;
        }
    }
    let p = step(route, kind, s, etag.as_deref(), &nonce);
    let (status, headers, raw) = request(addr, p.method, &p.uri, &p.payload, &p.headers).await?;
    let repeat = if kind == "repeat" {
        let (status, headers, raw) =
            request(addr, p.method, &p.uri, &p.payload, &p.headers).await?;
        Some(json!({"status":status,"headers":headers,"body":s.response(&raw)?}))
    } else {
        None
    };
    let after = s.effects(c).await?;
    let (request_path, query) = p
        .uri
        .split_once('?')
        .map_or((p.uri.as_str(), None), |(path, query)| {
            (path, Some(s.mask_query(query)))
        });
    let mut actual = json!({"format":1,"go_source":go_source,"route":route_name,"case":format!("{route}-{kind}"),
        "observation":{"request":{"method":method,"path":request_path,"query":query,"body":s.mask(&p.payload)},
        "response":{"status":status,"headers":headers,"body":s.response(&raw)?},"effects":after,"audit":[],"notify":[]}});
    if let Some(p) = prelude {
        actual["observation"]["prelude_response"] = p;
    }
    if let Some(r) = repeat {
        actual["observation"]["repeat_response"] = r;
    }
    if record.is_some() {
        std::fs::create_dir_all(corpus())?;
    }
    if route == "checkin" {
        let effects: Vec<Value> = ["devices", "device_events", "device_auth_nonces"]
            .iter()
            .map(|t| json!({"table":t,"before":before[*t],"after":after[*t]}))
            .collect();
        let rows = json!({"format":1,"go_source":actual["go_source"],"route":route_name,"case":format!("{route}-{kind}-row-effects"),"effects":effects});
        let file = corpus().join(format!("{route}-{kind}-rows.json"));
        if record.is_some() && !file.exists() {
            golden::record(&file, &rows)?;
        }
        golden::compare(&expected(&file, record.is_some())?, &rows)?;
    }
    let file = corpus().join(format!("{route}-{kind}.json"));
    if record.is_some() && !file.exists() {
        golden::record(&file, &actual)?;
    }
    let expected = expected(&file, record.is_some())?;
    if mutant {
        let error = golden::compare(&expected, &actual)
            .err()
            .ok_or("planted mutant survived its oracle")?;
        if !error.contains("/observation/response/status") {
            return Err(format!("wrong mutant rejection: {error}").into());
        }
        println!("MUTANT-REJECTED: {route_name} :: status");
    } else {
        golden::compare(&expected, &actual)?;
        println!("GOLDEN-REPLAY: {route_name} :: {route}-{kind}");
    }
    if record.is_none() {
        let (_, _, metrics) = request(addr, "GET", "/_gateway/metrics", "", &[]).await?;
        if !metrics.contains("setjoin_gateway_proxied_to_go_total 0") {
            return Err(format!("unexpected Go hop: {metrics}").into());
        }
    }
    Ok(())
}

macro_rules! cases {
    ($route:literal => $($test:ident: $kind:literal),+ $(,)?) => {
        $(
            #[tokio::test]
            async fn $test() {
                run($route, $kind, false).await.unwrap();
            }
        )+
    };
}
cases!("policy" =>
    device_policy_success: "success",
    device_policy_cross_tenant: "cross-tenant",
    device_policy_invalid_input: "invalid-input",
    device_policy_malformed_id: "malformed-id",
    device_policy_prefix_id: "prefix-id",
    device_policy_bad_hmac: "bad-hmac",
    device_policy_missing_proof: "missing-proof",
    device_policy_expired: "expired",
    device_policy_repeat: "repeat",
    device_policy_revoked: "revoked",
    device_policy_body_digest: "body-digest",
    device_policy_not_modified: "not-modified",
    device_policy_stale_etag: "stale-etag",
    device_policy_wipe: "wipe",
    device_policy_wipe_etag: "wipe-etag",
    device_policy_group: "group",
    device_policy_head: "head",
);
cases!("checkin" =>
    device_checkin_success: "success",
    device_checkin_cross_tenant: "cross-tenant",
    device_checkin_invalid_input: "invalid-input",
    device_checkin_malformed_id: "malformed-id",
    device_checkin_malformed_json: "malformed-json",
    device_checkin_bad_hmac: "bad-hmac",
    device_checkin_missing_proof: "missing-proof",
    device_checkin_expired: "expired",
    device_checkin_future_skew: "future-skew",
    device_checkin_skew_inside: "skew-inside",
    device_checkin_repeat: "repeat",
    device_checkin_cross_endpoint_nonce: "cross-endpoint-nonce",
    device_checkin_nonce_max: "nonce-max",
    device_checkin_nonce_too_long: "nonce-too-long",
    device_checkin_nonce_purge: "nonce-purge",
    device_checkin_revoked: "revoked",
    device_checkin_body_digest: "body-digest",
    device_checkin_not_modified: "not-modified",
    device_checkin_current_version: "current-version",
    device_checkin_wipe: "wipe",
    device_checkin_group: "group",
    device_checkin_invalid_events: "invalid-events",
    device_checkin_null_event: "null-event",
    device_checkin_folded_keys: "folded-keys",
    device_checkin_duplicate_id: "duplicate-id",
    device_checkin_event_cap: "event-cap",
    device_checkin_event_flood: "event-flood",
    device_checkin_fault: "fault",
    device_checkin_oversize: "oversize",
    device_checkin_unknown_key: "unknown-key",
    device_checkin_corrupt_envelope: "corrupt-envelope",
    device_checkin_no_secret: "no-secret",
    device_checkin_legacy_secret: "legacy-secret",
);
// Named without "device_" so the recording filter never selects a mutant.
#[tokio::test]
async fn status_mutant_policy_route() {
    run("policy", "success", true).await.unwrap();
}
#[tokio::test]
async fn status_mutant_checkin_route() {
    run("checkin", "success", true).await.unwrap();
}
