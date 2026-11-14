//! #342 guest-invite acceptance: frozen-Go HTTP/effect oracle through the real front
//! door (auth listener and gateway alias share these replays), plus native
//! timing, lock, deadline, threat and upgrade tests.
mod common;
use base64::Engine as _;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{Gateway, RouteTable, TrustedProxies};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_postgres::Client;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
type Err = Box<dyn std::error::Error + Send + Sync>;

const PATH: &str = "/auth/guest-invite/accept";
const PASSWORD: &str = "ValidGuestPass1!";
const GUEST: &str = "guest@guestaccept-partner.test";
const DELAY: Duration = Duration::from_millis(100);
const TERMINAL: &str = "{\"error\":\"invite link is invalid or has expired\"}\n";
const OK_BODY: &str = "{\"invited_email\":\"guest@guestaccept-partner.test\",\"message\":\"Account activated. You may now sign in.\"}\n";
const INVALID_JSON: &str = "{\"error\":\"invalid JSON body\"}\n";
const TOO_LONG: &str = "{\"error\":\"password exceeds the 72-byte limit\"}\n";
const RATE: &str = "{\"error\":\"too many requests, please wait and try again\"}\n";
const INTERNAL: &str = "{\"error\":\"internal error\"}\n";
const IP_BLOCKED: &str =
    "{\"captcha_prompt\":\"Access denied by security policy\",\"error\":\"ip_blocked\"}\n";
const OWNER: &str = "auth shape awaits its owner ticket\n";
const TOGGLES: [&str; 3] = [
    "feature.rate_limit",
    "feature.conditional_access",
    "feature.device_trust_enforcement",
];
const CONFIG_KEYS: [&str; 2] = ["installation.locality", "guest.disclosure_addendum"];
/// Catalog cases; each uses source IP 127.0.0.(10 + index) so Go's process-wide
/// enumeration guard is never shared between cases.
const CASES: [&str; 46] = [
    "guest-get-success",
    "guest-get-repeat",
    "guest-get-cross-tenant",
    "guest-get-invalid-input",
    "guest-get-expired",
    "guest-get-lifecycle-expired",
    "guest-get-used",
    "guest-get-revoked",
    "guest-get-unknown",
    "guest-get-federated",
    "guest-get-localized",
    "guest-get-head",
    "guest-get-rate-limited",
    "guest-get-ip-rule-ignored",
    "guest-get-gateway-guest-bearer",
    "guest-post-success",
    "guest-post-repeat",
    "guest-post-cross-tenant",
    "guest-post-invalid-input",
    "guest-post-expired",
    "guest-post-lifecycle-expired",
    "guest-post-used",
    "guest-post-revoked",
    "guest-post-unknown",
    "guest-post-federated",
    "guest-post-missing-token",
    "guest-post-disclosure-false",
    "guest-post-password-empty",
    "guest-post-password-policy",
    "guest-post-password-72",
    "guest-post-password-too-long",
    "guest-post-password-1mib",
    "guest-post-password-multibyte",
    "guest-post-password-nul",
    "guest-post-password-too-long-used",
    "guest-post-unknown-field",
    "guest-post-trailing-data",
    "guest-post-oversize",
    "guest-post-concurrent",
    "guest-post-rate-limited",
    "guest-post-ip-blocked",
    "guest-post-fault-users-update",
    "guest-post-fault-audit-write",
    "guest-post-gateway-cross-site-origin",
    "guest-post-gateway-guest-bearer",
    "guest-post-gateway-spoofed-xff",
];
const FIXTURE_RESET: &str = "
DROP TRIGGER IF EXISTS guestaccept_fault ON users;
DROP TRIGGER IF EXISTS guestaccept_fault ON admin_audit_log;
DROP FUNCTION IF EXISTS guestaccept_fault();
DELETE FROM ip_rules WHERE description = 'GUESTACCEPT';
DO $$
BEGIN
  IF to_regprocedure('rust_guest_invite_disclosure_absent_342(bigint,text)') IS NOT NULL THEN
    ALTER FUNCTION rust_guest_invite_disclosure_absent_342(bigint, text)
      RENAME TO rust_guest_invite_disclosure;
  END IF;
  IF to_regprocedure('rust_guest_invite_accept_read_absent_342(bigint,text,text,boolean)') IS NOT NULL THEN
    ALTER FUNCTION rust_guest_invite_accept_read_absent_342(bigint, text, text, boolean)
      RENAME TO rust_guest_invite_accept_read;
  END IF;
  IF to_regprocedure('rust_guest_invite_accept_finish_absent_342(bigint,bigint,text,text,inet)') IS NOT NULL THEN
    ALTER FUNCTION rust_guest_invite_accept_finish_absent_342(bigint, bigint, text, text, inet)
      RENAME TO rust_guest_invite_accept_finish;
  END IF;
END $$;";
const HIDE_REDUCERS: &str = "
ALTER FUNCTION rust_guest_invite_disclosure(bigint, text)
  RENAME TO rust_guest_invite_disclosure_absent_342;
ALTER FUNCTION rust_guest_invite_accept_read(bigint, text, text, boolean)
  RENAME TO rust_guest_invite_accept_read_absent_342;
ALTER FUNCTION rust_guest_invite_accept_finish(bigint, bigint, text, text, inet)
  RENAME TO rust_guest_invite_accept_finish_absent_342;";
const FAULT_FN: &str = "
CREATE OR REPLACE FUNCTION guestaccept_fault() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_TABLE_NAME = 'users' THEN
    IF NEW.email LIKE 'guest-%@guestaccept-partner.test' THEN
      RAISE EXCEPTION 'injected failure';
    END IF;
  ELSIF NEW.target_type = 'guest_invite' THEN
    RAISE EXCEPTION 'injected failure';
  END IF;
  RETURN NEW;
END $$;";

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
             _=&mut rx=>break,
             accepted=listener.accept()=>{
              let (stream,peer)=accepted.unwrap();let server=server.clone();
              connections.spawn(async move {
               let service=hyper::service::service_fn(move |mut req:Request<hyper::body::Incoming>|{
                let server=server.clone();req.extensions_mut().insert(setjoin_auth::ConnectionMeta{peer,tls:false});
                async move {
                 let mut response=server.handle(req.map(|b|b.map_err(std::io::Error::other).boxed())).await;
                 if mutant {*response.status_mut()=hyper::StatusCode::from_u16(599).unwrap();}
                 Ok::<_,std::convert::Infallible>(response)
                }
               });
               let _=hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new()).serve_connection(hyper_util::rt::TokioIo::new(stream),service).await;
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

async fn gateway(auth: SocketAddr, record: Option<String>) -> Server {
    let mut inventory: Value = serde_json::from_str(setjoin_gateway::inventory::BUNDLED).unwrap();
    inventory["routes"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["listener"] == "auth" || r["path"] == PATH);
    for r in inventory["routes"].as_array_mut().unwrap().iter_mut() {
        if record.is_some() {
            r["state"] = json!("OFF");
            r["upstream"] = json!("go-auth");
        } else if r["path"] == PATH {
            // Phase 1 only (#342): bundled rows stay OFF until goldens land.
            r["state"] = json!("ON");
            r["upstream"] = json!("rust-auth");
        }
    }
    let gw = Gateway::new(
        setjoin_gateway::Config {
            upstream: record.as_ref().map(|u| u.parse().unwrap()),
            upstream_header_timeout: Duration::from_secs(30),
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

struct Reply {
    status: u16,
    headers: Value,
    body: String,
    elapsed: Duration,
}

impl Reply {
    fn doc(&self, email: &str) -> Value {
        json!({
            "status": self.status,
            "headers": self.headers,
            "body": self.body.replace(email, GUEST),
        })
    }
}

async fn request(
    addr: SocketAddr,
    from: Ipv4Addr,
    method: &str,
    target: &str,
    payload: Vec<u8>,
    headers: &[(&str, String)],
) -> Result<Reply, Err> {
    let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
    http.set_local_address(Some(IpAddr::V4(from)));
    let client: hyper_util::client::legacy::Client<_, setjoin_auth::Body> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(http);
    let mut req = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{target}"))
        .header("host", "auth.guestaccept.test")
        .header("user-agent", "GUESTACCEPT oracle");
    if method == "POST" {
        req = req.header("content-type", "application/json");
    }
    for (k, v) in headers {
        req = req.header(*k, v.as_str());
    }
    let started = Instant::now();
    let resp = client.request(req.body(body(payload))?).await?;
    let status = resp.status().as_u16();
    let mut hs = serde_json::Map::new();
    for name in [
        "content-type",
        "cache-control",
        "content-language",
        "x-content-type-options",
        "x-threat-reason",
        "allow",
        "x-operation-id",
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
    Ok(Reply {
        status,
        headers: Value::Object(hs),
        body: raw,
        elapsed: started.elapsed(),
    })
}

async fn assert_go_recording(addr: SocketAddr, recording: bool) -> Result<(), Err> {
    if recording {
        let metrics = request(
            addr,
            Ipv4Addr::LOCALHOST,
            "GET",
            "/_gateway/metrics",
            Vec::new(),
            &[],
        )
        .await?
        .body;
        let hops = metrics
            .lines()
            .find_map(|line| line.strip_prefix("setjoin_gateway_proxied_to_go_total "))
            .ok_or("Go-hop metric missing")?
            .parse::<u64>()?;
        assert!(hops > 0, "a Go golden must traverse the frozen Go upstream");
    }
    Ok(())
}

fn corpus() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/identity-guest-invite")
}

async fn set_toggle(c: &Client, key: &str, value: Option<bool>) -> Result<(), Err> {
    match value {
        Some(v) => {
            c.execute(
                "INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET enabled=$2",
                &[&key, &v],
            )
            .await?;
        }
        None => {
            c.execute("DELETE FROM feature_toggles WHERE key=$1", &[&key])
                .await?;
        }
    }
    Ok(())
}

async fn now_text(c: &Client) -> Result<String, Err> {
    Ok(c.query_one("SELECT clock_timestamp()::text", &[])
        .await?
        .get(0))
}

struct Ctx {
    db: Db,
    c: Client,
    keys: Value,
    receipts: Vec<String>,
    toggles: Vec<(String, Option<bool>)>,
    config: Vec<(String, Option<String>)>,
}

impl Ctx {
    async fn open(case: &str) -> Result<Option<Ctx>, Err> {
        let Some(db) = Db::for_case(case) else {
            return Ok(None);
        };
        let c = db.connect().await?;
        c.query_one(
            "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
            &[],
        )
        .await?;
        common::signing_key(&c).await;
        let receipts = common::receipt_ids(&c).await;
        let mut toggles = Vec::new();
        for key in TOGGLES {
            let prior = c
                .query_opt("SELECT enabled FROM feature_toggles WHERE key=$1", &[&key])
                .await?
                .map(|r| r.get::<_, bool>(0));
            toggles.push((key.to_owned(), prior));
            set_toggle(&c, key, Some(false)).await?;
        }
        let mut config = Vec::new();
        for key in CONFIG_KEYS {
            let prior = c
                .query_opt(
                    "SELECT value::text FROM system_config WHERE key=$1",
                    &[&key],
                )
                .await?
                .map(|r| r.get::<_, String>(0));
            config.push((key.to_owned(), prior));
        }
        c.batch_execute(FIXTURE_RESET).await?;
        let keys = serde_json::from_str(include_str!(
            "../../../tests/conformance/identity-login/keys.json"
        ))?;
        Ok(Some(Ctx {
            db,
            c,
            keys,
            receipts,
            toggles,
            config,
        }))
    }

    async fn close(self) -> Result<(), Err> {
        for (key, prior) in &self.toggles {
            set_toggle(&self.c, key, *prior).await?;
        }
        for (key, prior) in &self.config {
            match prior {
                Some(v) => {
                    self.c
                        .execute(
                            "UPDATE system_config SET value=$2::text::jsonb WHERE key=$1",
                            &[key, v],
                        )
                        .await?
                }
                None => {
                    self.c
                        .execute("DELETE FROM system_config WHERE key=$1", &[key])
                        .await?
                }
            };
        }
        self.c.batch_execute(FIXTURE_RESET).await?;
        common::restore_receipts(&self.c, &self.receipts).await;
        Ok(())
    }

    fn secret(&self) -> &str {
        self.keys["secret"].as_str().unwrap_or("")
    }
}

async fn load(ctx: &Ctx, client_proxy: bool, default_deadlines: bool) -> Result<AuthServer, Err> {
    let mut cfg = Config::for_secret(ctx.secret().into());
    cfg.signing_alg = "ES256".into();
    cfg.dsn = ctx.db.dsn.clone();
    if client_proxy {
        cfg.client_proxy = "127.0.0.1".into();
    }
    let exec =
        setjoin_pg::ScopedExecutor::from_dsn(ctx.db.app.as_deref().unwrap_or(&ctx.db.dsn), 4)
            .unwrap();
    let server = AuthServer::load(exec, cfg).await?;
    Ok(if default_deadlines {
        server.with_guest_worker(
            setjoin_pg::ScopedExecutor::from_dsn_with(
                &ctx.db.dsn,
                2,
                setjoin_pg::Timeouts::default(),
            )
            .unwrap(),
        )
    } else {
        server
    })
}

struct Fx {
    guest: i64,
    guest_email: String,
    invite: i64,
    foreign: i64,
    foreign_invite: i64,
    token: String,
    member: i64,
    active: i64,
}

async fn invited(
    c: &Client,
    email: &str,
    host: &str,
    token: &str,
    state: &str,
) -> Result<(i64, i64), Err> {
    let user: i64 = c
        .query_one(
            "INSERT INTO users(username,domain_id,email,display_name,enabled) SELECT $1,id,$1,'GUESTACCEPT Guest',FALSE FROM domains WHERE name='guest.invalid' RETURNING id",
            &[&email],
        )
        .await?
        .get(0);
    let lifecycle = state == "lifecycle-expired";
    c.execute(
        "INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status,expires_at) SELECT $1,$2,'inviter@guestaccept-host.test',id,'invited',CASE WHEN $4 THEN now()-interval '1 minute' END FROM domains WHERE name=$3",
        &[&user, &email, &host, &lifecycle],
    )
    .await?;
    let invite: i64 = c
        .query_one(
            "INSERT INTO guest_invites(guest_user_id,token_hash,host_domain_id,created_by_email,expires_at,used_at,terminal_reason) SELECT $1,encode(sha256(convert_to($2,'UTF8')),'hex'),id,'inviter@guestaccept-host.test',CASE WHEN $3='expired' THEN now()-interval '1 hour' ELSE now()+interval '1 hour' END,CASE WHEN $3 IN ('used','revoked') THEN now()-interval '1 minute' END,CASE $3 WHEN 'used' THEN 'legacy_unknown' WHEN 'revoked' THEN 'revoked' END FROM domains WHERE name=$4 RETURNING id",
            &[&user, &token, &state, &host],
        )
        .await?
        .get(0);
    Ok((user, invite))
}

/// Users with audit rows are append-only-protected, so every seed is uniquely named.
async fn seed(c: &Client, state: &str) -> Result<Fx, Err> {
    let unique: String = c
        .query_one("SELECT replace(gen_random_uuid()::text,'-','')", &[])
        .await?
        .get(0);
    c.batch_execute(
        "INSERT INTO domains(name,is_local) VALUES('guestaccept-host.test',true),('guestaccept-foreign.test',true) ON CONFLICT(name) DO NOTHING",
    )
    .await?;
    let guest_email = format!("guest-{unique}@guestaccept-partner.test");
    let token = format!("guest-invite-token-{unique}");
    let (guest, invite) = invited(c, &guest_email, "guestaccept-host.test", &token, state).await?;
    let (foreign, foreign_invite) = invited(
        c,
        &format!("foreign-{unique}@guestaccept-partner.test"),
        "guestaccept-foreign.test",
        &format!("guest-invite-foreign-{unique}"),
        "valid",
    )
    .await?;
    let active: i64 = c
        .query_one(
            "INSERT INTO users(username,domain_id,email,display_name,enabled) SELECT $1,id,$1,'GUESTACCEPT Active',TRUE FROM domains WHERE name='guest.invalid' RETURNING id",
            &[&format!("active-{unique}@guestaccept-partner.test")],
        )
        .await?
        .get(0);
    c.execute(
        "INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) SELECT $1,'active@guestaccept-partner.test','inviter@guestaccept-host.test',id,'active' FROM domains WHERE name='guestaccept-host.test'",
        &[&active],
    )
    .await?;
    let member = fixture::account(c, "guestaccept-member").await?.user;
    match state {
        "federated" => {
            c.execute(
                "UPDATE users SET saml_name_id='guestaccept-fed-'||$2 WHERE id=$1",
                &[&guest, &unique],
            )
            .await?;
        }
        "localized" => {
            for (key, value) in [
                ("installation.locality", "在示例园区"),
                ("guest.disclosure_addendum", "Addendum & <terms>"),
            ] {
                c.execute(
                    "INSERT INTO system_config(key,value) VALUES($1,to_jsonb($2::text)) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                    &[&key, &value],
                )
                .await?;
            }
            let channel: i64 = c
                .query_one(
                    "INSERT INTO chat_channels(kind,name,visibility,created_by) VALUES('channel','GUESTACCEPT Launch','private',$1) RETURNING id",
                    &[&guest],
                )
                .await?
                .get(0);
            c.execute(
                "INSERT INTO chat_channel_members(channel_id,user_id) VALUES($1,$2)",
                &[&channel, &guest],
            )
            .await?;
        }
        _ => {}
    }
    Ok(Fx {
        guest,
        guest_email,
        invite,
        foreign,
        foreign_invite,
        token,
        member,
        active,
    })
}

fn user_label(fx: &Fx, id: Option<i64>) -> Value {
    match id {
        Some(v) if v == fx.guest => json!("<actor>"),
        Some(v) if v == fx.foreign => json!("<foreign>"),
        other => json!(other),
    }
}

fn invite_label(fx: &Fx, id: Option<i64>) -> Value {
    match id {
        Some(v) if v == fx.invite => json!("<invite>"),
        Some(v) if v == fx.foreign_invite => json!("<foreign-invite>"),
        other => json!(other),
    }
}

async fn rows(c: &Client, fx: &Fx, since: &str, password: &str) -> Result<Value, Err> {
    let mut guests = Vec::new();
    for (id, label) in [(fx.guest, "actor"), (fx.foreign, "foreign")] {
        let r = c
            .query_one(
                "SELECT ga.status, ga.expires_at IS NOT NULL, u.enabled, u.must_change_password, u.password_hash, gi.used_at IS NOT NULL, COALESCE(gi.used_at = gi.expires_at, false), gi.terminal_reason, gi.disclosure_version, gi.disclosure_accepted_at IS NOT NULL, gi.expires_at > now() FROM guest_accounts ga JOIN users u ON u.id = ga.user_id JOIN guest_invites gi ON gi.guest_user_id = ga.user_id WHERE ga.user_id = $1",
                &[&id],
            )
            .await?;
        let hash: Option<String> = r.get(4);
        let verdict = match hash {
            None => "absent",
            Some(h) if bcrypt::verify(password, &h).unwrap_or(false) => "verifies",
            Some(_) => "other",
        };
        guests.push(json!({
            "owner": label,
            "status": r.get::<_, String>(0),
            "lifecycle_expiry": r.get::<_, bool>(1),
            "enabled": r.get::<_, Option<bool>>(2),
            "must_change_password": r.get::<_, Option<bool>>(3),
            "password": verdict,
            "invite": {
                "used": r.get::<_, bool>(5),
                "used_at_is_expiry": r.get::<_, bool>(6),
                "terminal_reason": r.get::<_, Option<String>>(7),
                "disclosure_version": r.get::<_, Option<String>>(8),
                "disclosure_accepted": r.get::<_, bool>(9),
                "live": r.get::<_, bool>(10),
            },
        }));
    }
    let mut audit = Vec::new();
    for r in c
        .query(
            "SELECT user_id, action, target_type, target_id, after_state::text, host(ip), notes FROM admin_audit_log WHERE target_type = 'guest_invite' AND target_id = ANY($1) ORDER BY id",
            &[&vec![fx.invite, fx.foreign_invite]],
        )
        .await?
    {
        let mut after: Value = serde_json::from_str(
            &r.get::<_, Option<String>>(4).unwrap_or_else(|| "null".into()),
        )?;
        if after["guestUserId"] == json!(fx.guest.to_string()) {
            after["guestUserId"] = json!("<actor>");
        }
        audit.push(json!({
            "user": user_label(fx, r.get(0)),
            "action": r.get::<_, String>(1),
            "target_type": r.get::<_, Option<String>>(2),
            "target": invite_label(fx, r.get(3)),
            "after": after,
            "ip": r.get::<_, Option<String>>(5),
            "notes": r.get::<_, Option<String>>(6),
        }));
    }
    let mut attempts = Vec::new();
    for r in c
        .query(
            "SELECT host(source_ip), target_username, protocol, outcome, geo_country, device_fingerprint FROM auth_attempts WHERE source_ip <<= '127.0.0.0/8'::inet AND occurred_at >= $1::text::timestamptz ORDER BY host(source_ip), outcome, occurred_at",
            &[&since],
        )
        .await?
    {
        attempts.push(json!({
            "ip": r.get::<_, Option<String>>(0),
            "target_username": r.get::<_, String>(1),
            "protocol": r.get::<_, String>(2),
            "outcome": r.get::<_, String>(3),
            "geo_country": r.get::<_, Option<String>>(4),
            "device_fingerprint": r.get::<_, Option<String>>(5),
        }));
    }
    Ok(json!({ "guests": guests, "audit": audit, "attempts": attempts }))
}

fn state(method: &str, kind: &str) -> &'static str {
    match kind {
        "expired" => "expired",
        "lifecycle-expired" => "lifecycle-expired",
        "used" | "password-too-long-used" => "used",
        "rate-limited" if method == "POST" => "used",
        "revoked" => "revoked",
        "federated" => "federated",
        "localized" => "localized",
        _ => "valid",
    }
}

fn password_of(kind: &str) -> String {
    match kind {
        "password-empty" => String::new(),
        "password-policy" => "short".to_owned(),
        "password-72" => format!("Aa1!{}Wx9$", "Kq7#mZ2p".repeat(8)),
        "password-too-long" | "password-too-long-used" => {
            format!("Aa1!{}Wx9$y", "Kq7#mZ2p".repeat(8))
        }
        "password-1mib" => "a".repeat((1 << 20) - 200),
        "password-multibyte" => format!("Aa1!{}", "é".repeat(35)),
        "password-nul" => "Aa1!\u{0}bcdefgh".to_owned(),
        _ => PASSWORD.to_owned(),
    }
}

fn shape(method: &str, kind: &str, token: &str) -> (String, Vec<u8>) {
    if method == "GET" {
        let target = if token.is_empty() {
            PATH.to_owned()
        } else {
            format!("{PATH}?token={token}")
        };
        return (target, Vec::new());
    }
    let password = password_of(kind);
    let good = json!({ "token": token, "disclosure_accepted": true, "new_password": password });
    let body = match kind {
        "invalid-input" => "{".to_owned(),
        "missing-token" => {
            json!({ "disclosure_accepted": true, "new_password": password }).to_string()
        }
        "disclosure-false" => {
            json!({ "token": token, "disclosure_accepted": false, "new_password": password })
                .to_string()
        }
        "unknown-field" => json!({
            "token": token,
            "disclosure_accepted": true,
            "new_password": password,
            "extra": 1,
        })
        .to_string(),
        "trailing-data" => format!("{good} {{}}"),
        "oversize" => format!("{{\"token\":\"{}\"}}", "a".repeat(1 << 20)),
        _ => good.to_string(),
    };
    (PATH.to_owned(), body.into_bytes())
}

fn bearer(secret: &str, uid: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    setjoin_authz::legacy_jwt::sign_hs256(
        secret.as_bytes(),
        &json!({
            "uid": uid,
            "typ": "access",
            "iss": "mailserver",
            "aud": ["mailserver-gateway"],
            "iat": now,
            "exp": now + 3600,
        })
        .to_string(),
    )
}

/// Go-derived contract asserted until the frozen-Go goldens are recorded.
fn expected(method: &str, kind: &str) -> (Option<u16>, Option<&'static str>) {
    match (method, kind) {
        (
            "GET",
            "success"
            | "repeat"
            | "cross-tenant"
            | "localized"
            | "ip-rule-ignored"
            | "gateway-guest-bearer",
        ) => (Some(200), None),
        ("GET", "head") => (Some(200), Some("")),
        (_, "rate-limited") => (Some(429), Some(RATE)),
        ("GET", _) => (Some(401), Some(TERMINAL)),
        (
            _,
            "success"
            | "repeat"
            | "cross-tenant"
            | "concurrent"
            | "password-72"
            | "gateway-guest-bearer"
            | "gateway-spoofed-xff",
        ) => (Some(200), Some(OK_BODY)),
        (_, "gateway-cross-site-origin") => (None, None),
        (_, "invalid-input" | "unknown-field" | "trailing-data") => (Some(400), Some(INVALID_JSON)),
        (_, "disclosure-false") => (
            Some(400),
            Some("{\"error\":\"disclosure acceptance is required\"}\n"),
        ),
        (_, "password-empty") => (
            Some(400),
            Some("{\"error\":\"new password is required\"}\n"),
        ),
        (_, "password-policy") => (Some(400), None),
        (_, "password-too-long" | "password-1mib" | "password-multibyte") => {
            (Some(400), Some(TOO_LONG))
        }
        (_, "password-nul" | "fault-users-update" | "fault-audit-write") => {
            (Some(500), Some(INTERNAL))
        }
        (_, "oversize") => (Some(413), Some("request body too large\n")),
        (_, "ip-blocked") => (Some(403), Some(IP_BLOCKED)),
        _ => (Some(401), Some(TERMINAL)),
    }
}

fn phase1(
    name: &str,
    method: &str,
    kind: &str,
    status: u16,
    body: &str,
    mutant: bool,
) -> Result<(), Err> {
    let (want, text) = expected(method, kind);
    if mutant {
        assert_ne!(Some(status), want, "{name}: status mutant survived");
        return Ok(());
    }
    match want {
        Some(w) => assert_eq!(status, w, "{name}: {body}"),
        None => assert!(status < 500, "{name}: {status} {body}"),
    }
    if let Some(text) = text {
        assert_eq!(body, text, "{name}");
    }
    Ok(())
}

fn check_effects(
    method: &str,
    kind: &str,
    status: u16,
    before: &Value,
    after: &Value,
    receipts_unchanged: bool,
) -> Result<(), Err> {
    let (b, a) = (&before["guests"], &after["guests"]);
    if b[1] != a[1] {
        return Err(format!("{kind}: foreign guest changed").into());
    }
    let actor = &a[0];
    match (method, status) {
        ("POST", 200) => {
            if actor["status"] != "active"
                || actor["password"] != "verifies"
                || actor["invite"]["terminal_reason"] != "accepted"
            {
                return Err(format!("{kind}: accept effects missing: {actor}").into());
            }
            if after["audit"].as_array().map_or(0, Vec::len) != 1 {
                return Err(format!("{kind}: exactly one accept audit expected").into());
            }
        }
        ("POST", 401) if matches!(kind, "expired" | "lifecycle-expired") => {
            if actor["invite"]["terminal_reason"] != "expired"
                || actor["invite"]["used_at_is_expiry"] != true
                || before["audit"] != after["audit"]
            {
                return Err(format!("{kind}: expiry settlement missing: {actor}").into());
            }
        }
        ("GET", 200) => {
            if actor["invite"]["disclosure_version"] != "v1" {
                return Err(format!("{kind}: disclosure stamp missing").into());
            }
        }
        _ => {
            if b[0] != a[0] || before["audit"] != after["audit"] {
                return Err(format!("{kind}: refused request changed state").into());
            }
            if !receipts_unchanged {
                return Err(format!("{kind}: refused request left a receipt").into());
            }
        }
    }
    Ok(())
}

async fn run(method: &'static str, kind: &'static str, mutant: bool) -> Result<(), Err> {
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none(), "mutants cannot record");
    let _serial = SERIAL.lock().await;
    let Some(ctx) = Ctx::open("GUESTACCEPT").await? else {
        return Ok(());
    };
    let result = run_in(&ctx, method, kind, mutant, record).await;
    let closed = ctx.close().await;
    result.and(closed)
}

async fn run_in(
    ctx: &Ctx,
    method: &str,
    kind: &str,
    mutant: bool,
    record: Option<String>,
) -> Result<(), Err> {
    let name = format!("guest-{}-{kind}", method.to_ascii_lowercase());
    let idx = CASES
        .iter()
        .position(|c| *c == name)
        .ok_or("case missing from CASES")?;
    let from = Ipv4Addr::new(127, 0, 0, 10 + idx as u8);
    let c = &ctx.c;
    let fx = seed(c, state(method, kind)).await?;
    match kind {
        "fault-users-update" => {
            c.batch_execute(FAULT_FN).await?;
            c.batch_execute(
                "CREATE TRIGGER guestaccept_fault BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION guestaccept_fault()",
            )
            .await?;
        }
        "fault-audit-write" => {
            c.batch_execute(FAULT_FN).await?;
            c.batch_execute(
                "CREATE TRIGGER guestaccept_fault BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION guestaccept_fault()",
            )
            .await?;
        }
        "ip-blocked" | "ip-rule-ignored" => {
            c.execute(
                "INSERT INTO ip_rules(cidr,action,description) VALUES($1::text::inet,'block','GUESTACCEPT')",
                &[&format!("{from}/32")],
            )
            .await?;
        }
        _ => {}
    }
    let server = auth_server(
        Arc::new(load(ctx, true, kind == "concurrent").await?),
        mutant,
    )
    .await;
    let gw = gateway(server.addr, record.clone()).await;
    let outcome = exercise(
        ctx,
        &fx,
        &name,
        from,
        method,
        kind,
        mutant,
        record.is_some(),
        gw.addr,
    )
    .await;
    let hops = if record.is_none() {
        request(
            gw.addr,
            Ipv4Addr::LOCALHOST,
            "GET",
            "/_gateway/metrics",
            Vec::new(),
            &[],
        )
        .await
        .map(|r| r.body.contains("setjoin_gateway_proxied_to_go_total 0"))
    } else {
        Ok(true)
    };
    gw.close().await;
    server.close().await;
    outcome?;
    if !hops? {
        return Err("replay reached frozen Go".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn exercise(
    ctx: &Ctx,
    fx: &Fx,
    name: &str,
    from: Ipv4Addr,
    method: &str,
    kind: &str,
    mutant: bool,
    recording: bool,
    gw: SocketAddr,
) -> Result<(), Err> {
    let c = &ctx.c;
    let token = match (method, kind) {
        (_, "unknown") | ("GET", "rate-limited") => "guest-invite-token-unknown-absent".to_owned(),
        ("GET", "invalid-input") => String::new(),
        _ => fx.token.clone(),
    };
    let (target, payload) = shape(method, kind, &token);
    let mut headers: Vec<(&str, String)> = Vec::new();
    match kind {
        "cross-tenant" => headers.push((
            "authorization",
            format!("Bearer {}", bearer(ctx.secret(), fx.member)),
        )),
        "gateway-guest-bearer" => headers.push((
            "authorization",
            format!("Bearer {}", bearer(ctx.secret(), fx.active)),
        )),
        "localized" => headers.push(("accept-language", "zh-CN,zh;q=0.9".to_owned())),
        "gateway-cross-site-origin" => {
            headers.push(("origin", "https://evil.example".to_owned()));
            headers.push(("sec-fetch-site", "cross-site".to_owned()));
        }
        "gateway-spoofed-xff" => headers.push(("x-forwarded-for", "203.0.113.9".to_owned())),
        _ => {}
    }
    let wire = if kind == "head" { "HEAD" } else { method };
    let password = password_of(kind);
    let receipts = common::receipt_ids(c).await;
    let since = now_text(c).await?;
    let mut listener = ctx.db.listen("session_revoke").await?;
    let before = rows(c, fx, &since, &password).await?;
    let mut extra = Vec::new();
    let reply = match kind {
        "repeat" => {
            let first = request(gw, from, wire, &target, payload.clone(), &headers).await?;
            let again = request(gw, from, wire, &target, payload.clone(), &headers).await?;
            extra.push(again.doc(&fx.guest_email));
            first
        }
        "concurrent" => {
            let (a, b) = tokio::join!(
                request(
                    gw,
                    Ipv4Addr::new(127, 0, 0, 200),
                    wire,
                    &target,
                    payload.clone(),
                    &headers
                ),
                request(
                    gw,
                    Ipv4Addr::new(127, 0, 0, 201),
                    wire,
                    &target,
                    payload.clone(),
                    &headers
                )
            );
            let mut both = vec![a?, b?];
            both.sort_by_key(|r| r.status);
            let loser = both.pop().ok_or("no concurrent reply")?;
            extra.push(loser.doc(&fx.guest_email));
            both.pop().ok_or("no concurrent reply")?
        }
        "rate-limited" => {
            let mut last = None;
            for _ in 0..11 {
                let r = request(gw, from, wire, &target, payload.clone(), &headers).await?;
                extra.push(json!(r.status));
                last = Some(r);
            }
            last.ok_or("no rate-limited reply")?
        }
        _ => request(gw, from, wire, &target, payload.clone(), &headers).await?,
    };
    if recording {
        if matches!(reply.status, 502 | 503) {
            return Err(
                "frozen Go recorder unavailable; refusing to capture a transport failure".into(),
            );
        }
        if reply.status == 429 && kind != "rate-limited" {
            return Err("Go enumeration budget already spent; record this case alone".into());
        }
        if reply.body.contains("captcha_prompt") && kind != "ip-blocked" {
            return Err("threat fixture leaked into the capture".into());
        }
    }
    if !mutant {
        if reply.status == 401 {
            assert!(
                reply.elapsed >= DELAY,
                "{name}: terminal 401 answered before the delay"
            );
        }
        if kind == "rate-limited" {
            assert!(reply.elapsed < DELAY, "{name}: 429 must not be delayed");
        }
    }
    let mut body = reply.body.replace(&fx.guest_email, GUEST);
    if method == "GET" && reply.status == 200 && kind != "head" {
        let expires: String = c
            .query_one(
                "SELECT to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM guest_invites WHERE id=$1",
                &[&fx.invite],
            )
            .await?
            .get(0);
        let parsed: Value = serde_json::from_str(&reply.body)?;
        assert_eq!(parsed["expires_at"], json!(expires), "{name}: expires_at");
        body = body.replace(&expires, "<expires-at>");
    }
    let after = rows(c, fx, &since, &password).await?;
    let notify = listener.drain(c).await?;
    let receipts_unchanged = common::receipt_ids(c).await.len() == receipts.len();
    if !mutant {
        check_effects(
            method,
            kind,
            reply.status,
            &before,
            &after,
            receipts_unchanged,
        )?;
    }
    let request_headers: serde_json::Map<String, Value> = headers
        .iter()
        .map(|(k, v)| {
            let shown = if *k == "authorization" {
                "<bearer>"
            } else {
                v.as_str()
            };
            ((*k).to_owned(), json!(shown))
        })
        .collect();
    let query = match target.split_once('?') {
        Some((_, q)) if !token.is_empty() => q.replace(&token, "<token>"),
        Some((_, q)) => q.to_owned(),
        None => String::new(),
    };
    let body_doc = if payload.len() > 4096 {
        format!("<{} bytes>", payload.len())
    } else {
        let text = String::from_utf8_lossy(&payload).into_owned();
        if token.is_empty() {
            text
        } else {
            text.replace(&token, "<token>")
        }
    };
    let route = format!("{method} {PATH}");
    let mut actual = json!({
        "format": 1,
        "go_source": "",
        "route": route,
        "case": name,
        "observation": {
            "request": {
                "method": wire,
                "path": PATH,
                "query": query,
                "headers": request_headers,
                "body": body_doc,
            },
            "response": { "status": reply.status, "headers": reply.headers, "body": body },
            "effects": after,
            "audit": after["audit"],
            "notify": notify,
        },
    });
    if !extra.is_empty() {
        actual["observation"]["extra_responses"] = json!(extra);
    }
    let mut effects = json!({
        "format": 1,
        "go_source": "",
        "route": route,
        "case": format!("{name}-row-effects"),
        "effects": [{ "table": "guest_invite", "before": before, "after": after }],
    });
    let file = corpus().join("goldens").join(format!("{name}.json"));
    let rowfile = corpus().join("qualified").join(format!("{name}-rows.json"));
    if recording {
        let source = std::env::var("GOFREE_GO_SOURCE")
            .map_err(|_| "GOFREE_GO_SOURCE (the checked-out HEAD) is required to record")?;
        if source.len() != 40 || !source.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("GOFREE_GO_SOURCE must be a 40-hex commit".into());
        }
        assert_go_recording(gw, true).await?;
        actual["go_source"] = json!(source);
        effects["go_source"] = json!(source);
        for (path, doc) in [(&file, &actual), (&rowfile, &effects)] {
            if !path.exists() {
                std::fs::create_dir_all(path.parent().ok_or("corpus path")?)?;
                golden::record(path, doc)?;
            }
        }
    }
    if !file.exists() {
        // Phase 1 (#342): Go goldens are not yet recorded; pin the Go-derived contract.
        return phase1(name, method, kind, reply.status, &body, mutant);
    }
    let expected: Value = serde_json::from_str(&std::fs::read_to_string(&file)?)?;
    actual["go_source"] = expected["go_source"].clone();
    effects["go_source"] = expected["go_source"].clone();
    if mutant {
        assert!(
            golden::compare(&expected, &actual).is_err(),
            "mutant survived"
        );
        return Ok(());
    }
    golden::compare(&expected, &actual)?;
    let expected_rows: Value = serde_json::from_str(&std::fs::read_to_string(&rowfile)?)?;
    golden::compare(&expected_rows, &effects)?;
    Ok(())
}

macro_rules! cases {
    ($($name:ident => $method:literal, $kind:literal;)*) => {
        $(
            #[tokio::test]
            async fn $name() {
                run($method, $kind, false).await.unwrap();
            }
        )*
    };
}

cases! {
    guest_get_success => "GET", "success";
    guest_get_repeat => "GET", "repeat";
    guest_get_cross_tenant => "GET", "cross-tenant";
    guest_get_invalid_input => "GET", "invalid-input";
    guest_get_expired => "GET", "expired";
    guest_get_lifecycle_expired => "GET", "lifecycle-expired";
    guest_get_used => "GET", "used";
    guest_get_revoked => "GET", "revoked";
    guest_get_unknown => "GET", "unknown";
    guest_get_federated => "GET", "federated";
    guest_get_localized => "GET", "localized";
    guest_get_head => "GET", "head";
    guest_get_rate_limited => "GET", "rate-limited";
    guest_get_ip_rule_ignored => "GET", "ip-rule-ignored";
    guest_get_gateway_guest_bearer => "GET", "gateway-guest-bearer";
    guest_post_success => "POST", "success";
    guest_post_repeat => "POST", "repeat";
    guest_post_cross_tenant => "POST", "cross-tenant";
    guest_post_invalid_input => "POST", "invalid-input";
    guest_post_expired => "POST", "expired";
    guest_post_lifecycle_expired => "POST", "lifecycle-expired";
    guest_post_used => "POST", "used";
    guest_post_revoked => "POST", "revoked";
    guest_post_unknown => "POST", "unknown";
    guest_post_federated => "POST", "federated";
    guest_post_missing_token => "POST", "missing-token";
    guest_post_disclosure_false => "POST", "disclosure-false";
    guest_post_password_empty => "POST", "password-empty";
    guest_post_password_policy => "POST", "password-policy";
    guest_post_password_72 => "POST", "password-72";
    guest_post_password_too_long => "POST", "password-too-long";
    guest_post_password_1mib => "POST", "password-1mib";
    guest_post_password_multibyte => "POST", "password-multibyte";
    guest_post_password_nul => "POST", "password-nul";
    guest_post_password_too_long_used => "POST", "password-too-long-used";
    guest_post_unknown_field => "POST", "unknown-field";
    guest_post_trailing_data => "POST", "trailing-data";
    guest_post_oversize => "POST", "oversize";
    guest_post_concurrent => "POST", "concurrent";
    guest_post_rate_limited => "POST", "rate-limited";
    guest_post_ip_blocked => "POST", "ip-blocked";
    guest_post_fault_users_update => "POST", "fault-users-update";
    guest_post_fault_audit_write => "POST", "fault-audit-write";
    guest_post_gateway_cross_site_origin => "POST", "gateway-cross-site-origin";
    guest_post_gateway_guest_bearer => "POST", "gateway-guest-bearer";
    guest_post_gateway_spoofed_xff => "POST", "gateway-spoofed-xff";
}

#[tokio::test]
async fn guest_get_status_mutant() {
    run("GET", "success", true).await.unwrap();
}

#[tokio::test]
async fn guest_post_status_mutant() {
    run("POST", "success", true).await.unwrap();
}

macro_rules! native {
    ($name:ident, $body:ident) => {
        #[tokio::test]
        async fn $name() {
            let _serial = SERIAL.lock().await;
            let Some(ctx) = Ctx::open(stringify!($name)).await.unwrap() else {
                return;
            };
            let result = $body(&ctx).await;
            ctx.close().await.unwrap();
            result.unwrap();
        }
    };
}

native!(guest_terminal_delay_is_bounded, delay_bounded);
native!(
    guest_terminal_reject_releases_locks_before_delay,
    locks_released
);
native!(guest_get_post_wins_race, post_wins);
native!(guest_post_deadline_rolls_back, deadline);
native!(
    guest_post_ca_and_threat_toggles_follow_login,
    toggles_follow_login
);
native!(guest_post_captcha_header_native, captcha_header);
native!(guest_post_threat_username_keys, username_keys);
native!(guest_upgrade_reducers_absent, reducers_absent);
native!(guest_upgrade_worker_without_bypassrls, without_bypassrls);
native!(guest_other_methods_are_405, other_methods);

async fn native_server(ctx: &Ctx) -> Result<Server, Err> {
    Ok(auth_server(Arc::new(load(ctx, false, false).await?), false).await)
}

async fn wait_for_lock(c: &Client, fragment: &str) -> Result<(), Err> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let waiting: bool = c
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND pid <> pg_backend_pid() AND query LIKE '%' || $1 || '%')",
                &[&fragment],
            )
            .await?
            .get(0);
        if waiting {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!("no backend waited on a lock for {fragment}").into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn delay_bounded(ctx: &Ctx) -> Result<(), Err> {
    let server = native_server(ctx).await?;
    let cases = [
        ("GET", "unknown"),
        ("GET", "missing"),
        ("GET", "used"),
        ("GET", "expired"),
        ("GET", "revoked"),
        ("GET", "lifecycle-expired"),
        ("GET", "federated"),
        ("POST", "unknown"),
        ("POST", "missing"),
        ("POST", "used"),
        ("POST", "expired"),
        ("POST", "revoked"),
        ("POST", "lifecycle-expired"),
        ("POST", "federated"),
    ];
    let mut result = Ok(());
    for (i, (method, kind)) in cases.into_iter().enumerate() {
        let fx = seed(&ctx.c, state(method, kind)).await?;
        let token = match kind {
            "unknown" => "guest-invite-token-unknown-absent".to_owned(),
            "missing" => String::new(),
            _ => fx.token.clone(),
        };
        let (target, payload) = if method == "POST" && kind == "missing" {
            shape("POST", "missing-token", "")
        } else {
            shape(method, "terminal", &token)
        };
        let reply = request(
            server.addr,
            Ipv4Addr::new(127, 0, 0, 100 + i as u8),
            method,
            &target,
            payload,
            &[],
        )
        .await?;
        if reply.status != 401
            || reply.body != TERMINAL
            || reply.elapsed < DELAY
            || reply.elapsed >= Duration::from_millis(1600)
        {
            result = Err(format!(
                "{method} {kind}: {} after {:?}: {}",
                reply.status, reply.elapsed, reply.body
            )
            .into());
            break;
        }
    }
    server.close().await;
    result
}

async fn locks_released(ctx: &Ctx) -> Result<(), Err> {
    let fx = seed(&ctx.c, "used").await?;
    let server = native_server(ctx).await?;
    let probe_a = ctx.db.connect().await?;
    let probe_b = ctx.db.connect().await?;
    probe_a.batch_execute("BEGIN").await?;
    probe_a
        .execute(
            "SELECT 1 FROM guest_accounts WHERE user_id=$1 FOR UPDATE",
            &[&fx.guest],
        )
        .await?;
    let (target, payload) = shape("POST", "terminal", &fx.token);
    let addr = server.addr;
    let post = tokio::spawn(async move {
        request(
            addr,
            Ipv4Addr::new(127, 0, 0, 150),
            "POST",
            &target,
            payload,
            &[],
        )
        .await
    });
    wait_for_lock(&ctx.c, "rust_guest_invite_accept_read").await?;
    let guest = fx.guest;
    let waiter = tokio::spawn(async move {
        probe_b
            .execute(
                "UPDATE guest_accounts SET updated_at=updated_at WHERE user_id=$1",
                &[&guest],
            )
            .await
            .map(|_| ())
    });
    wait_for_lock(&ctx.c, "UPDATE guest_accounts SET updated_at=updated_at").await?;
    probe_a.batch_execute("ROLLBACK").await?;
    tokio::time::timeout(Duration::from_secs(5), waiter).await???;
    let held_through_delay = post.is_finished();
    let reply = post.await??;
    server.close().await;
    if held_through_delay {
        return Err("terminal reject held its row locks through the response delay".into());
    }
    if reply.status != 401 || reply.body != TERMINAL {
        return Err(format!("used token: {} {}", reply.status, reply.body).into());
    }
    Ok(())
}

async fn post_wins(ctx: &Ctx) -> Result<(), Err> {
    let fx = seed(&ctx.c, "valid").await?;
    let server = native_server(ctx).await?;
    let probe = ctx.db.connect().await?;
    probe.batch_execute("BEGIN").await?;
    probe
        .execute(
            "UPDATE guest_invites SET used_at=now(), disclosure_accepted_at=now(), terminal_reason='accepted' WHERE id=$1",
            &[&fx.invite],
        )
        .await?;
    probe
        .execute(
            "UPDATE guest_accounts SET status='active' WHERE user_id=$1",
            &[&fx.guest],
        )
        .await?;
    let addr = server.addr;
    let target = format!("{PATH}?token={}", fx.token);
    let get = tokio::spawn(async move {
        request(
            addr,
            Ipv4Addr::new(127, 0, 0, 151),
            "GET",
            &target,
            Vec::new(),
            &[],
        )
        .await
    });
    wait_for_lock(&ctx.c, "rust_guest_invite_disclosure").await?;
    probe.batch_execute("COMMIT").await?;
    let reply = get.await??;
    let version: Option<String> = ctx
        .c
        .query_one(
            "SELECT disclosure_version FROM guest_invites WHERE id=$1",
            &[&fx.invite],
        )
        .await?
        .get(0);
    server.close().await;
    if reply.status != 401 || reply.body != TERMINAL || reply.elapsed < DELAY {
        return Err(format!("stamp-lost GET: {} after {:?}", reply.status, reply.elapsed).into());
    }
    if version.is_some() {
        return Err("a GET that lost the race still stamped the disclosure".into());
    }
    Ok(())
}

async fn deadline(ctx: &Ctx) -> Result<(), Err> {
    let fx = seed(&ctx.c, "valid").await?;
    let worker =
        setjoin_pg::ScopedExecutor::from_dsn_with(&ctx.db.dsn, 2, setjoin_pg::Timeouts::default())
            .unwrap();
    let server = auth_server(
        Arc::new(load(ctx, false, false).await?.with_guest_worker(worker)),
        false,
    )
    .await;
    let receipts = common::receipt_ids(&ctx.c).await;
    let probe = ctx.db.connect().await?;
    probe.batch_execute("BEGIN").await?;
    probe
        .execute(
            "SELECT 1 FROM guest_accounts WHERE user_id=$1 FOR UPDATE",
            &[&fx.guest],
        )
        .await?;
    let (target, payload) = shape("POST", "success", &fx.token);
    let first = request(
        server.addr,
        Ipv4Addr::new(127, 0, 0, 152),
        "POST",
        &target,
        payload.clone(),
        &[],
    )
    .await?;
    probe.batch_execute("ROLLBACK").await?;
    let state = rows(&ctx.c, &fx, "-infinity", PASSWORD).await?;
    let receipts_unchanged = common::receipt_ids(&ctx.c).await.len() == receipts.len();
    let second = request(
        server.addr,
        Ipv4Addr::new(127, 0, 0, 153),
        "POST",
        &target,
        payload,
        &[],
    )
    .await?;
    server.close().await;
    if first.status != 500
        || first.body != INTERNAL
        || first.headers.get("x-operation-id").is_some()
    {
        return Err(format!("deadline: {} {}", first.status, first.body).into());
    }
    if state["guests"][0]["status"] != "invited"
        || state["guests"][0]["invite"]["used"] != false
        || state["audit"].as_array().map_or(1, Vec::len) != 0
        || !receipts_unchanged
    {
        return Err(format!("deadline left a partial write: {state}").into());
    }
    if second.status != 200 {
        return Err(format!(
            "retry after the deadline: {} {}",
            second.status, second.body
        )
        .into());
    }
    Ok(())
}

async fn toggles_follow_login(ctx: &Ctx) -> Result<(), Err> {
    let fx = seed(&ctx.c, "valid").await?;
    let server = native_server(ctx).await?;
    let mut result: Result<(), Err> = Ok(());
    for (i, key) in TOGGLES.into_iter().enumerate() {
        let from = Ipv4Addr::new(127, 0, 0, 160 + i as u8);
        set_toggle(&ctx.c, key, Some(true)).await?;
        let (target, payload) = shape("POST", "success", &fx.token);
        let guest = request(server.addr, from, "POST", &target, payload, &[]).await?;
        let login_body = json!({ "email": "nobody@guestaccept.test", "password": "x" });
        let login = request(
            server.addr,
            from,
            "POST",
            "/auth/login",
            login_body.to_string().into_bytes(),
            &[],
        )
        .await?;
        let get = request(
            server.addr,
            from,
            "GET",
            &format!("{PATH}?token={}", fx.token),
            Vec::new(),
            &[],
        )
        .await?;
        set_toggle(&ctx.c, key, Some(false)).await?;
        if guest.status != 503
            || guest.body != OWNER
            || login.status != 503
            || login.body != OWNER
            || get.status != 200
        {
            result = Err(format!(
                "{key}: guest {} login {} get {}",
                guest.status, login.status, get.status
            )
            .into());
            break;
        }
    }
    let state = rows(&ctx.c, &fx, "-infinity", PASSWORD).await?;
    server.close().await;
    result?;
    if state["guests"][0]["status"] != "invited" {
        return Err("a forwarded POST changed state".into());
    }
    Ok(())
}

async fn captcha_header(ctx: &Ctx) -> Result<(), Err> {
    let fx = seed(&ctx.c, "valid").await?;
    let server = native_server(ctx).await?;
    let (target, payload) = shape("POST", "success", &fx.token);
    let reply = request(
        server.addr,
        Ipv4Addr::new(127, 0, 0, 165),
        "POST",
        &target,
        payload,
        &[("x-captcha-token", "bogus".to_owned())],
    )
    .await?;
    server.close().await;
    if reply.status != 200 {
        return Err(format!(
            "captcha header (ignored like native login): {}",
            reply.status
        )
        .into());
    }
    Ok(())
}

async fn username_keys(ctx: &Ctx) -> Result<(), Err> {
    let fx = seed(&ctx.c, "valid").await?;
    let server = native_server(ctx).await?;
    let since = now_text(&ctx.c).await?;
    let lockouts = "SELECT count(*) FROM auth_lockouts WHERE lockout_key LIKE '%probe@x.test%' OR lockout_key LIKE '%jwt@x.test%'";
    let before: i64 = ctx.c.query_one(lockouts, &[]).await?.get(0);
    let jwt = format!(
        "h.{}.s",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"email":"jwt@x.test"}"#)
    );
    let bodies = [
        json!({ "token": fx.token, "disclosure_accepted": true, "new_password": PASSWORD, "Email": "Probe@X.test" }),
        json!({ "token": fx.token, "disclosure_accepted": true, "new_password": PASSWORD, "REFRESH_TOKEN": jwt }),
    ];
    let mut result: Result<(), Err> = Ok(());
    for (i, body) in bodies.iter().enumerate() {
        let reply = request(
            server.addr,
            Ipv4Addr::new(127, 0, 0, 170 + i as u8),
            "POST",
            PATH,
            body.to_string().into_bytes(),
            &[],
        )
        .await?;
        if reply.status != 400 || reply.body != INVALID_JSON {
            result = Err(format!("username key body {i}: {} {}", reply.status, reply.body).into());
            break;
        }
    }
    server.close().await;
    result?;
    let names: Vec<String> = ctx
        .c
        .query(
            "SELECT target_username FROM auth_attempts WHERE occurred_at >= $1::text::timestamptz AND source_ip IN ('127.0.0.170'::inet, '127.0.0.171'::inet) ORDER BY host(source_ip)",
            &[&since],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    if names != ["Probe@X.test", "jwt@x.test"] {
        return Err(format!("attempt usernames {names:?}").into());
    }
    let after: i64 = ctx.c.query_one(lockouts, &[]).await?.get(0);
    if after != before {
        return Err("native lockout escalation appeared; update residual #346".into());
    }
    Ok(())
}

async fn reducers_absent(ctx: &Ctx) -> Result<(), Err> {
    let fx = seed(&ctx.c, "valid").await?;
    let server = native_server(ctx).await?;
    let probe = setjoin_pg::ScopedExecutor::from_dsn(&ctx.db.dsn, 1).unwrap();
    ctx.c.batch_execute(HIDE_REDUCERS).await?;
    let outcome = async {
        let ready = setjoin_identity::guest_invite::readiness(&probe).await;
        let get = request(
            server.addr,
            Ipv4Addr::new(127, 0, 0, 180),
            "GET",
            &format!("{PATH}?token={}", fx.token),
            Vec::new(),
            &[],
        )
        .await?;
        let (target, payload) = shape("POST", "success", &fx.token);
        let post = request(
            server.addr,
            Ipv4Addr::new(127, 0, 0, 181),
            "POST",
            &target,
            payload,
            &[],
        )
        .await?;
        Ok::<_, Err>((ready, get, post))
    }
    .await;
    ctx.c.batch_execute(FIXTURE_RESET).await?;
    server.close().await;
    let (ready, get, post) = outcome?;
    let state = rows(&ctx.c, &fx, "-infinity", PASSWORD).await?;
    if !ready.as_ref().is_err_and(|e| e.contains("reducers")) {
        return Err(format!("readiness did not report missing reducers: {ready:?}").into());
    }
    if get.status != 500 || get.body != INTERNAL || post.status != 500 || post.body != INTERNAL {
        return Err(format!("absent reducers: get {} post {}", get.status, post.status).into());
    }
    if state["guests"][0]["status"] != "invited"
        || state["guests"][0]["invite"]["disclosure_version"] != Value::Null
    {
        return Err("absent reducers left a write".into());
    }
    Ok(())
}

async fn without_bypassrls(ctx: &Ctx) -> Result<(), Err> {
    let Some(app) = ctx.db.app.clone() else {
        eprintln!("CONFORMANCE-SKIP guest_upgrade_worker_without_bypassrls: DB_APP_DSN unset");
        return Ok(());
    };
    let fx = seed(&ctx.c, "valid").await?;
    let worker = setjoin_pg::ScopedExecutor::from_dsn(&app, 2).unwrap();
    let ready = setjoin_identity::guest_invite::readiness(&worker).await;
    let server = auth_server(
        Arc::new(load(ctx, false, false).await?.with_guest_worker(worker)),
        false,
    )
    .await;
    let get = request(
        server.addr,
        Ipv4Addr::new(127, 0, 0, 185),
        "GET",
        &format!("{PATH}?token={}", fx.token),
        Vec::new(),
        &[],
    )
    .await?;
    let (target, payload) = shape("POST", "success", &fx.token);
    let post = request(
        server.addr,
        Ipv4Addr::new(127, 0, 0, 186),
        "POST",
        &target,
        payload,
        &[],
    )
    .await?;
    server.close().await;
    if !ready.as_ref().is_err_and(|e| e.contains("BYPASSRLS")) {
        return Err(
            format!("DB_APP_DSN must be the non-bypass app role; readiness: {ready:?}").into(),
        );
    }
    if get.status != 401 || get.body != TERMINAL || post.status != 401 || post.body != TERMINAL {
        return Err(format!("no BYPASSRLS: get {} post {}", get.status, post.status).into());
    }
    Ok(())
}

async fn other_methods(ctx: &Ctx) -> Result<(), Err> {
    let server = native_server(ctx).await?;
    let reply = request(
        server.addr,
        Ipv4Addr::new(127, 0, 0, 190),
        "PUT",
        PATH,
        Vec::new(),
        &[],
    )
    .await?;
    server.close().await;
    if reply.status != 405
        || reply.headers["allow"] != "GET, HEAD, POST"
        || reply.body != "Method Not Allowed\n"
    {
        return Err(format!("PUT: {} {}", reply.status, reply.body).into());
    }
    Ok(())
}
