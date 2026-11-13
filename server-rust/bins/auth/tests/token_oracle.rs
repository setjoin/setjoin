//! Frozen Go -> actual Rust front door recording; native replay has no Go upstream.
#[path = "token_oracle/bootstrap.rs"]
mod bootstrap;
mod common;
#[path = "token_oracle/impersonate.rs"]
mod impersonate;
#[path = "token_oracle/stores.rs"]
mod stores;
#[path = "token_oracle/webpush.rs"]
mod webpush;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{Gateway, RouteTable, TrustedProxies};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
type Err = Box<dyn std::error::Error + Send + Sync>;
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
    path: &str,
    payload: String,
    headers: &[(&str, &str)],
) -> Result<(u16, Value, String), Err> {
    let client: hyper_util::client::legacy::Client<_, setjoin_auth::Body> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let mut req = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{path}"))
        .header("host", "auth.idlogin3.test")
        .header("user-agent", "IDLOGIN3 oracle");
    if !headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        req = req.header("content-type", "application/json");
    }
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = client.request(req.body(body(payload))?).await?;
    let status = resp.status().as_u16();
    let mut hs = serde_json::Map::new();
    for name in [
        "content-type",
        "cache-control",
        "set-cookie",
        "x-content-type-options",
        "www-authenticate",
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

struct Seed {
    a: fixture::Account,
    b: fixture::Account,
    email: String,
    foreign: String,
    tou: Option<i64>,
}
impl Seed {
    async fn create(c: &tokio_postgres::Client) -> Result<Self, Err> {
        let a = fixture::account(c, "idlogin3-actor").await?;
        let b = fixture::account(c, "idlogin3-foreign").await?;
        let email = c
            .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
            .await?
            .get(0);
        let foreign = c
            .query_one("SELECT email FROM users WHERE id=$1", &[&b.user])
            .await?
            .get(0);
        for (client, secret) in [
            ("idlogin3-client-a", "secret-a"),
            ("idlogin3-client-b", "secret-b"),
        ] {
            c.execute(
                "INSERT INTO oidc_clients(id,name,secret,redirect_uris) VALUES($1,$1,$2,'{}')",
                &[&client, &bcrypt::hash(secret, 4)?],
            )
            .await?;
        }
        use sha2::{Digest, Sha256};
        for (user, client, token) in [
            (a.user, "idlogin3-client-a", "idlogin3-token-a"),
            (b.user, "idlogin3-client-b", "idlogin3-token-b"),
        ] {
            c.execute("INSERT INTO oauth_tokens(user_id,client_id,token_hash,token_type,scope,issued_at,expires_at) VALUES($1,$2,$3,'access',ARRAY['mail.read','profile'],'2026-01-02T03:04:05Z','2036-01-02T03:04:05Z')",&[&user,&client,&Sha256::digest(token.as_bytes()).to_vec()]).await?;
        }
        Ok(Self {
            a,
            b,
            email,
            foreign,
            tou: None,
        })
    }
    fn normalize_text(&self, s: String) -> String {
        let out = s
            .replace(
                &format!("/auth/admin/users/{}/impersonate", self.a.user),
                "/auth/admin/users/{id}/impersonate",
            )
            .replace(
                &format!("/auth/admin/users/{}/impersonate", self.b.user),
                "/auth/admin/users/{id}/impersonate",
            )
            .replace(&self.email, "actor@idlogin3.test")
            .replace(&self.foreign, "foreign@idlogin3.test")
            .replace(
                &format!("\"sub\":\"{}\"", self.a.user),
                "\"sub\":\"<actor>\"",
            )
            .replace(
                &format!("\"sub\":\"{}\"", self.b.user),
                "\"sub\":\"<foreign>\"",
            );
        let mut out = out;
        for (id, label) in [(self.a.user, "<actor>"), (self.b.user, "<foreign>")] {
            for end in [",", "}"] {
                out = out.replace(
                    &format!("\"user_id\":{id}{end}"),
                    &format!("\"user_id\":\"{label}\"{end}"),
                );
            }
        }
        if let Some(id) = self.tou {
            out.replace(&format!("\"id\":{id},"), "\"id\":\"<tou>\",")
                .replace(&format!("\"tou_id\":{id},"), "\"tou_id\":\"<tou>\",")
        } else {
            out
        }
    }
    async fn effects(&self, c: &tokio_postgres::Client) -> Result<Value, Err> {
        let raw:String=c.query_one("SELECT COALESCE(jsonb_agg(jsonb_build_object('owner',CASE WHEN user_id=$1 THEN 'actor' ELSE 'foreign' END,'client',client_id,'hash',encode(token_hash,'hex'),'revoked',revoked_at IS NOT NULL) ORDER BY user_id,id),'[]')::text FROM oauth_tokens WHERE user_id=ANY($2::bigint[])",&[&self.a.user,&vec![self.a.user,self.b.user]]).await?.get(0);
        Ok(json!({"oauth":serde_json::from_str::<Value>(&raw)?}))
    }
    async fn rows(&self, c: &tokio_postgres::Client) -> Result<Value, Err> {
        let raw:String=c.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY user_id,id),'[]')::text FROM oauth_tokens t WHERE user_id=ANY($1::bigint[])",&[&vec![self.a.user,self.b.user]]).await?.get(0);
        let mut rows: Value = serde_json::from_str(&raw)?;
        for row in rows.as_array_mut().unwrap() {
            let a = row["user_id"] == self.a.user;
            row["user_id"] = json!(if a { "<actor>" } else { "<foreign>" });
            row["id"] = json!(if a { "<token-a>" } else { "<token-b>" });
            if !row["revoked_at"].is_null() {
                row["revoked_at"] = json!("<timestamp>");
            }
        }
        Ok(rows)
    }
    async fn tou_rows(&self, c: &tokio_postgres::Client) -> Result<Value, Err> {
        let raw:String=c.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY user_id,tou_id),'[]')::text FROM terms_of_use_acceptance t WHERE tou_id=$1 AND user_id=ANY($2::bigint[])",&[&self.tou,&vec![self.a.user,self.b.user]]).await?.get(0);
        let mut rows: Value = serde_json::from_str(&raw)?;
        for row in rows.as_array_mut().unwrap() {
            row["user_id"] = json!(if row["user_id"] == self.a.user {
                "<actor>"
            } else {
                "<foreign>"
            });
            row["tou_id"] = json!("<tou>");
            if !row["accepted_at"].is_null() {
                row["accepted_at"] = json!("<timestamp>");
            }
        }
        Ok(rows)
    }
    async fn cleanup(&self, c: &tokio_postgres::Client) -> Result<(), Err> {
        if let Some(id) = self.tou {
            c.execute("DELETE FROM terms_of_use WHERE id=$1", &[&id])
                .await?;
        }
        fixture::remove(c, &self.a).await?;
        fixture::remove(c, &self.b).await?;
        c.execute(
            "DELETE FROM oidc_clients WHERE id IN ('idlogin3-client-a','idlogin3-client-b')",
            &[],
        )
        .await?;
        Ok(())
    }
}
fn corpus() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/identity-token/goldens")
}
async fn run(route: &str, kind: &str, mutant: bool) -> Result<(), Err> {
    run_mode(route, kind, if mutant { Some("status") } else { None }).await
}
async fn run_mode(route: &str, kind: &str, mutation: Option<&str>) -> Result<(), Err> {
    let mutant = mutation == Some("status");
    // Owner-approved security divergences 2026-11-05 (#495): these frozen-Go
    // observations are replaced by reviewed expectations (identity-token/divergences.json).
    let protected = matches!((route, kind), ("bootstrap", "revoked") | ("bootstrap", "bound") | ("impersonate", "domain-scope"));
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDLOGIN3-http").expect("database required");
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    assert!(
        mutation.is_none() || std::env::var_os("GOFREE_RECORD_UPSTREAM").is_none(),
        "mutants cannot record"
    );
    common::signing_key(&c).await;
    let published = route == "version" && kind.starts_with("published");
    if published {
        c.batch_execute("CREATE TABLE client_versions(version text,sha256 text,release_notes text,file_path text,release_date timestamptz,platform text,app text); GRANT SELECT ON client_versions TO setjoin_app; INSERT INTO client_versions VALUES('2.4.1','abc123','Read <this>','installer.zip','2026-01-02T03:04:05Z','oracle','mail')").await?;
    }
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let mut seed = if matches!(
        route,
        "introspect"
            | "revoke"
            | "pending"
            | "accept"
            | "scim"
            | "reload"
            | "impersonate"
            | "bootstrap"
            | "webpush"
    ) {
        Some(Seed::create(&c).await?)
    } else {
        None
    };
    if matches!(route, "pending" | "accept") {
        let s = seed.as_mut().unwrap();
        let id:i64=c.query_one("INSERT INTO terms_of_use(name,body_md) VALUES('idlogin3-policy','# Policy\nRead <this> & agree') RETURNING id",&[]).await?.get(0);
        s.tou = Some(id);
        if kind == "cross-tenant" {
            c.execute(
                "INSERT INTO terms_of_use_acceptance(user_id,tou_id,version) VALUES($1,$2,1)",
                &[&s.b.user, &id],
            )
            .await?;
        }
    }
    if route == "scim" {
        let s = seed.as_ref().unwrap();
        if let Err(error) = s.scim_seed(&c).await {
            s.scim_cleanup(&c).await?;
            s.cleanup(&c).await?;
            return Err(error);
        }
    }
    if route == "impersonate" {
        let s = seed.as_ref().unwrap();
        if let Err(error) = s.impersonation_seed(&c, kind).await {
            s.impersonation_cleanup(&c).await?;
            s.cleanup(&c).await?;
            return Err(error);
        }
    }
    if route == "bootstrap" {
        seed.as_ref().unwrap().bootstrap_seed(&c, &keys).await?;
    }
    if route == "webpush" {
        seed.as_ref().unwrap().webpush_seed(&c).await?;
    }
    let saved_rate = if route == "webpush" {
        let old = c
            .query_opt(
                "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
                &[],
            )
            .await?
            .map(|r| r.get::<_, bool>(0));
        c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
        Some(old)
    } else {
        None
    };
    let old_enc = std::env::var_os("DB_ENCRYPTION_KEY");
    if route == "webpush" {
        std::env::set_var("DB_ENCRYPTION_KEY", "22".repeat(32));
    }
    let mut cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    if seed.is_some() {
        let old = std::env::var_os("JWT_SECRET");
        std::env::set_var("JWT_SECRET", keys["secret"].as_str().unwrap());
        let old_key = std::env::var_os("INTERNAL_API_KEY");
        std::env::set_var("INTERNAL_API_KEY", "idlogin3-internal-test-key");
        cfg = Config::from_env()?;
        if let Some(v) = old {
            std::env::set_var("JWT_SECRET", v);
        } else {
            std::env::remove_var("JWT_SECRET");
        }
        if let Some(v) = old_key {
            std::env::set_var("INTERNAL_API_KEY", v);
        } else {
            std::env::remove_var("INTERNAL_API_KEY");
        }
    }
    if route == "webpush" {
        cfg.threat_controls = [false; 5];
        if let Some(v) = old_enc {
            std::env::set_var("DB_ENCRYPTION_KEY", v);
        } else {
            std::env::remove_var("DB_ENCRYPTION_KEY");
        }
    }
    let reload_env = if route == "reload" {
        let old = (
            std::env::var_os("JWT_SECRET"),
            std::env::var_os("INTERNAL_API_KEY"),
        );
        std::env::set_var("JWT_SECRET", keys["secret"].as_str().unwrap());
        std::env::set_var("INTERNAL_API_KEY", "idlogin3-internal-test-key");
        Some(old)
    } else {
        None
    };
    let operator_file = if route == "reload" && matches!(kind,"rotation"|"failed-config") {
        let old = std::env::var_os("SETJOIN_CONFIG");
        let owned = std::env::var_os("GOFREE_RELOAD_CONFIG").is_none();
        let file = std::env::var_os("GOFREE_RELOAD_CONFIG")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!(
                    "gofree-idlogin3-reload-{}.yaml",
                    uuid::Uuid::new_v4()
                ))
            });
        std::fs::write(&file, "internal:\n  api_key: idlogin3-internal-test-key\n")?;
        std::env::set_var("SETJOIN_CONFIG", &file);
        std::env::remove_var("INTERNAL_API_KEY");
        Some((file, old, owned))
    } else {
        None
    };
    if route == "bootstrap" && kind == "revoked" {
        // The process-local snapshot is read at start, so the revocation must exist first.
        c.execute("INSERT INTO session_revocations(user_id,scope,jti,reason,not_before,expires_at) VALUES($1,'jti','idlogin3-actor','fixture',now(),now()+interval '1 hour')",&[&seed.as_ref().unwrap().a.user]).await?;
    }
    let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
        .map_err(|e| e.0)?;
    let auth = auth_server(Arc::new(AuthServer::load(exec, cfg).await?), mutant).await;
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    assert!(!mutant || record.is_none(), "mutants cannot record");
    let gw = gateway(auth.addr, record.clone()).await;
    if route == "revoke" && !matches!(kind, "client-own" | "client-other" | "internal-other") {
        c.execute(
            "UPDATE oauth_tokens SET client_id=NULL WHERE user_id=$1",
            &[&seed.as_ref().unwrap().a.user],
        )
        .await?;
    }
    let notify_original = if mutation == Some("no-notify") {
        let original: String = c
            .query_one(
                "SELECT pg_get_functiondef('app_notify(text,text)'::regprocedure)",
                &[],
            )
            .await?
            .get(0);
        Some(original)
    } else {
        None
    };
    let before_rows = if route == "webpush" {
        Some(seed.as_ref().unwrap().webpush_rows(&c).await?)
    } else if route == "bootstrap" {
        Some(
            seed.as_ref()
                .unwrap()
                .bootstrap_rows(&c, &keys, None)
                .await?,
        )
    } else if route == "impersonate" {
        Some(seed.as_ref().unwrap().impersonation_rows(&c).await?)
    } else if route == "scim" {
        Some(seed.as_ref().unwrap().stores(&c).await?)
    } else if route == "accept" {
        Some(seed.as_ref().unwrap().tou_rows(&c).await?)
    } else if route == "revoke" {
        Some(seed.as_ref().unwrap().rows(&c).await?)
    } else {
        None
    };
    let mut notified = if matches!(route, "revoke" | "accept" | "scim") {
        Some(db.listen("session_revoke").await?)
    } else {
        None
    };
    let (method, path, mut payload) = match route {
        "discovery" => ("GET", "/.well-known/setjoin".to_owned(), String::new()),
        "version" => ("GET", "/api/v1/version".to_owned(), String::new()),
        "introspect" => (
            "POST",
            "/auth/introspect".to_owned(),
            if kind == "invalid-input" {
                "{}".into()
            } else if kind == "client-basic" {
                "token=idlogin3-token-a".into()
            } else {
                json!({"token":"idlogin3-token-a"}).to_string()
            },
        ),
        "revoke" => (
            "POST",
            "/auth/revoke".to_owned(),
            if kind == "invalid-input" {
                "token=".into()
            } else {
                "token=idlogin3-token-a".into()
            },
        ),
        "impersonate" => (
            "POST",
            format!(
                "/auth/admin/users/{}/impersonate",
                if kind == "invalid-input" {
                    "bad".to_owned()
                } else if kind == "self" {
                    seed.as_ref().unwrap().a.user.to_string()
                } else if kind == "missing" {
                    "99999999".into()
                } else {
                    seed.as_ref().unwrap().b.user.to_string()
                }
            ),
            "{not-json".into(),
        ),
        "bootstrap" => ("POST","/device/register".into(),json!({"fingerprint":"idlogin3-fingerprint-0123456789abcdef","platform":"desktop","os_version":"oracle-os","app_version":"1.2.3","device_name":"Oracle device","user_id":seed.as_ref().unwrap().b.user}).to_string()),
        "webpush" => ("POST","/auth/device/register".into(),json!({"provider":"webpush","push_token":json!({"endpoint":"https://push.idlogin3.test/send","keys":{"auth":"test-auth","p256dh":"test-key"}}).to_string(),"device_name":"Oracle subscription","device_public_key":"ignored-for-webpush","reauth_token":"ignored-for-webpush","user_id":seed.as_ref().unwrap().b.user}).to_string()),
        "pending" => ("GET", "/terms/pending".into(), String::new()),
        "accept" => (
            "POST",
            "/terms/accept".into(),
            if kind == "invalid-input" {
                "{}".into()
            } else {
                json!({"tou_id":seed.as_ref().unwrap().tou.unwrap(),"version":1,"user_id":seed.as_ref().unwrap().b.user}).to_string()
            },
        ),
        "scim" => (
            "POST",
            "/auth/scim/disable".into(),
            if kind == "invalid-input" {
                "{}".into()
            } else {
                json!({"user_id":seed.as_ref().unwrap().a.user}).to_string()
            },
        ),
        "reload" => (
            "POST",
            "/admin/reload".into(),
            if kind == "invalid-input" {
                "{not-json".into()
            } else {
                String::new()
            },
        ),
        _ => panic!("unknown route"),
    };
    if route == "introspect" {
        payload = match kind {
            "client-post" => {
                "token=idlogin3-token-a&client_id=idlogin3-client-a&client_secret=secret-a".into()
            }
            "client-cross" => {
                "token=idlogin3-token-a&client_id=idlogin3-client-b&client_secret=secret-b".into()
            }
            "bad-secret" => {
                "token=idlogin3-token-a&client_id=idlogin3-client-a&client_secret=wrong".into()
            }
            "invalid-form" => "token=%ZZ".into(),
            "json-type" => "{\"token\":42}".into(),
            "duplicate-null" => "{\"TOKEN\":\"idlogin3-token-a\",\"token\":null}".into(),
            "trailing-value" => "{\"token\":\"idlogin3-token-a\"} not-json".into(),
            "unknown-number" => "{\"token\":\"idlogin3-token-a\",\"ignored\":1e10000}".into(),
            "unknown" => "{\"token\":\"unknown\"}".into(),
            _ => payload,
        };
        let uid = seed.as_ref().unwrap().a.user;
        match kind {
            "disabled" => {
                c.execute("UPDATE users SET enabled=false WHERE id=$1", &[&uid])
                    .await?;
            }
            "revoked" => {
                c.execute(
                    "UPDATE oauth_tokens SET revoked_at=now() WHERE user_id=$1",
                    &[&uid],
                )
                .await?;
            }
            "expired" => {
                c.execute(
                    "UPDATE oauth_tokens SET expires_at='2020-01-01' WHERE user_id=$1",
                    &[&uid],
                )
                .await?;
            }
            "app-password" => {
                c.execute("UPDATE oauth_tokens SET token_type='app_password',client_id=NULL,scope='{}',expires_at=NULL WHERE user_id=$1",&[&uid]).await?;
            }
            _ => {}
        }
    }
    if matches!(route, "pending" | "accept") {
        let seed = seed.as_ref().unwrap();
        let tou = seed.tou.unwrap();
        if matches!(kind, "accepted" | "head") {
            c.execute(
                "INSERT INTO terms_of_use_acceptance(user_id,tou_id,version) VALUES($1,$2,1)",
                &[&seed.a.user, &tou],
            )
            .await?;
        }
        if kind == "disabled-tou" {
            c.execute("UPDATE terms_of_use SET enabled=false WHERE id=$1", &[&tou])
                .await?;
        }
        if route == "accept" {
            payload = match kind {
                "stale" => json!({"tou_id":tou,"version":2}).to_string(),
                "missing" => json!({"tou_id":99999999,"version":1}).to_string(),
                "overflow" => json!({"tou_id":tou,"version":9223372036854775807i64}).to_string(),
                "invalid-type" => json!({"tou_id":"bad","version":1}).to_string(),
                _ => payload,
            };
        }
    }
    if route == "scim" {
        payload = match kind {
            "external" => json!({"external_id":"idlogin3-external-a"}).to_string(),
            "external-missing" => json!({"external_id":"unknown"}).to_string(),
            "missing-user" => json!({"user_id":99999999}).to_string(),
            "negative-user" => json!({"user_id":-1}).to_string(),
            "invalid-type" => json!({"user_id":"bad"}).to_string(),
            "precedence" => {
                json!({"user_id":seed.as_ref().unwrap().b.user,"external_id":"idlogin3-external-a"})
                    .to_string()
            }
            _ => payload,
        };
    }
    if route == "webpush" {
        let normal = payload.clone();
        let mut value: Value = serde_json::from_str(&normal)?;
        let mut sub: Value = serde_json::from_str(value["push_token"].as_str().unwrap())?;
        let endpoint = match kind {
            "http" => Some("http://push.idlogin3.test/send"),
            "localhost" => Some("https://api.localhost/send"),
            "private-ip" => Some("https://127.0.0.1/send"),
            "mapped-ip" => Some("https://[::ffff:127.0.0.1]/send"),
            "numeric-host" => Some("https://2130706433/send"),
            "documentation-ip" => Some("https://203.0.113.1/send"),
            "bad-url" => Some("https://push.idlogin3.test/%zz"),
            _ => None,
        };
        if let Some(endpoint) = endpoint {
            sub["endpoint"] = json!(endpoint);
            value["push_token"] = json!(sub.to_string());
        }
        payload = match kind {
            "invalid-input" | "null" => {
                if kind == "null" {
                    "null".into()
                } else {
                    "{}".into()
                }
            }
            "malformed" => "{bad".into(),
            "field-type" => {
                value["provider"] = json!(42);
                value.to_string()
            }
            "provider" => {
                value["provider"] = json!("invalid");
                value.to_string()
            }
            "subscription-json" => {
                value["push_token"] = json!("{bad");
                value.to_string()
            }
            "missing-endpoint" => {
                value["push_token"] = json!("{}");
                value.to_string()
            }
            "subscription-trailing" => {
                value["push_token"] = json!(sub.to_string() + " {}");
                value.to_string()
            }
            "subscription-limit" => {
                value["push_token"] = json!("a".repeat(8193));
                value.to_string()
            }
            "oversized" => {
                value["ignored"] = json!("a".repeat(65536));
                value.to_string()
            }
            "trailing" => normal + " {}",
            _ => value.to_string(),
        };
    }
    if route == "bootstrap" {
        let normal = payload.clone();
        let mut value: Value = serde_json::from_str(&normal)?;
        payload = match kind {
            "invalid-input" => "{}".into(),
            "malformed" => "{bad".into(),
            "unicode-surrogate" => normal.replacen('{', r#"{"ignored":"\ud800","#,1),
            "trailing" => normal + " {}",
            "null" => "null".into(),
            "short-fingerprint" => {
                value["fingerprint"] = json!("short");
                value.to_string()
            }
            "long-fingerprint" => {
                value["fingerprint"] = json!("a".repeat(513));
                value.to_string()
            }
            "field-type" => {
                value["fingerprint"] = json!(123);
                value.to_string()
            }
            "oversized" => {
                value["ignored"] = json!("a".repeat((1 << 20) + 100));
                value.to_string()
            }
            _ => normal,
        };
        if kind == "revoked" && route != "bootstrap" {
            c.execute("INSERT INTO session_revocations(user_id,scope,jti,reason,not_before,expires_at) VALUES($1,'jti','idlogin3-actor','fixture',now(),now()+interval '1 hour')",&[&seed.as_ref().unwrap().a.user]).await?;
        }
    }
    let uri = if published {
        format!(
            "{path}?client={}&platform=oracle&app=mail",
            match kind {
                "published-blocked" => "1.9.0",
                "published-up-to-date" => "3.0.0",
                "published-update-available" => "2.3.7",
                "published-malformed" => "bad",
                _ => "2.2.0",
            }
        )
    } else if kind == "invalid-input" {
        format!("{path}?user_id=not-a-number")
    } else {
        path.clone()
    };
    let path = if route == "impersonate" {
        "/auth/admin/users/{id}/impersonate".to_owned()
    } else {
        path
    };
    let foreign_token=seed.as_ref().map(|s|{
      let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
      let claims=json!({"uid":s.b.user,"email":s.foreign,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600,"jti":"idlogin3-foreign"});
      format!("Bearer {}",setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&claims.to_string()))
    });
    let actor_token=seed.as_ref().map(|s|{
      let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
      let mut claims=json!({"uid":s.a.user,"email":s.email,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600,"jti":"idlogin3-actor"});
      if route=="impersonate" && kind!="non-admin" {claims["admin"]=json!(true);}
      if route=="bootstrap" && kind=="bound"{claims["cnf"]=json!({"jkt":"unproven-device-key"});}
      if kind=="wrong-type"{claims["typ"]=json!("refresh");}
      if kind=="expired-token"{claims["exp"]=json!(now-1);}
      format!("Bearer {}",setjoin_authz::legacy_jwt::sign_hs256(keys["secret"].as_str().unwrap().as_bytes(),&claims.to_string()))
    });
    let cookie = actor_token.as_ref().map(|t| {
        let token = t.strip_prefix("Bearer ").unwrap();
        match kind {
            "quoted-cookie" => format!("access_token=\"{token}\""),
            "duplicate-cookie" => format!("access_token={token}; access_token=invalid"),
            _ => format!("access_token={token}"),
        }
    });
    let headers = if route == "bootstrap" && kind == "cookie" {
        vec![("cookie", cookie.as_deref().unwrap())]
    } else if route == "pending"
        && matches!(
            kind,
            "quoted-cookie" | "duplicate-cookie" | "empty-bearer-cookie"
        )
    {
        let mut h = vec![("cookie", cookie.as_deref().unwrap())];
        if kind == "empty-bearer-cookie" {
            h.push(("authorization", "Bearer "));
        }
        h
    } else if matches!(route, "scim" | "reload") {
        vec![(
            "authorization",
            if kind == "cross-tenant" {
                foreign_token.as_deref().unwrap()
            } else {
                "Bearer idlogin3-internal-test-key"
            },
        )]
    } else if matches!(
        route,
        "pending" | "accept" | "impersonate" | "bootstrap" | "webpush"
    ) {
        let mut h = vec![(
            "authorization",
            if route == "impersonate" && kind == "cross-tenant" {
                foreign_token.as_deref().unwrap()
            } else if kind == "unauthenticated" {
                "Bearer invalid"
            } else {
                actor_token.as_deref().unwrap()
            },
        )];
        if kind == "csrf" {
            h.push(("origin", "https://evil.test"));
        }
        h
    } else if route == "revoke" {
        let mut h = vec![("content-type", "application/x-www-form-urlencoded")];
        if !matches!(kind, "client-own" | "client-other") {
            h.push((
                "authorization",
                if kind == "cross-tenant" {
                    foreign_token.as_deref().unwrap()
                } else {
                    "Bearer idlogin3-internal-test-key"
                },
            ));
        }
        h
    } else if route == "introspect" && kind == "client-basic" {
        vec![
            (
                "authorization",
                "Basic aWRsb2dpbjMtY2xpZW50LWE6c2VjcmV0LWE=",
            ),
            ("content-type", "application/x-www-form-urlencoded"),
        ]
    } else if route == "introspect"
        && matches!(
            kind,
            "client-post" | "client-cross" | "bad-secret" | "invalid-form"
        )
    {
        vec![("content-type", "application/x-www-form-urlencoded")]
    } else if route == "introspect" {
        vec![(
            "authorization",
            if kind == "cross-tenant" {
                foreign_token.as_deref().unwrap()
            } else {
                "Bearer idlogin3-internal-test-key"
            },
        )]
    } else if kind == "cross-tenant" {
        vec![("authorization", "Bearer foreign-invalid-token")]
    } else {
        vec![]
    };
    let request_headers = headers.clone();
    let result=async {
  if let Some((file,_,_))=&operator_file {std::fs::write(file,if kind=="failed-config"{"internal:\n  api_key: idlogin3-rotated-test-key\njwt:\n  expiry: 0s\n"}else{"internal:\n  api_key: idlogin3-rotated-test-key\n"})?;}
  if mutation==Some("no-notify"){c.batch_execute("CREATE OR REPLACE FUNCTION app_notify(p_channel text,p_payload text) RETURNS void LANGUAGE plpgsql AS $$BEGIN RETURN; END;$$").await?;}
  if route=="scim" && kind=="fault" {
      c.batch_execute(&format!("CREATE FUNCTION gofree_idlogin3_scim_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.user_id={} THEN RAISE EXCEPTION 'idlogin3 injected write failure'; END IF; RETURN NEW; END;$$;CREATE TRIGGER gofree_idlogin3_scim_fail BEFORE UPDATE ON oauth_tokens FOR EACH ROW EXECUTE FUNCTION gofree_idlogin3_scim_fail();",seed.as_ref().unwrap().a.user)).await?;
    }
  if route=="bootstrap" && kind=="fault"{c.batch_execute(&format!("CREATE FUNCTION gofree_idlogin3_event_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF EXISTS(SELECT 1 FROM devices WHERE id=NEW.device_id AND user_id={}) THEN RAISE EXCEPTION 'idlogin3 injected event failure'; END IF;RETURN NEW;END;$$;CREATE TRIGGER gofree_idlogin3_event_fail BEFORE INSERT ON device_events FOR EACH ROW EXECUTE FUNCTION gofree_idlogin3_event_fail();",seed.as_ref().unwrap().a.user)).await?;}
  let (status,mut headers,mut raw)=request(gw.addr,if kind=="head"{"HEAD"}else{method},&uri,payload.clone(),&headers).await?;
  let bootstrap_secret=if route=="bootstrap" {seed.as_ref().unwrap().bootstrap_response(&mut raw)?}else{None};
  let token_claims=if route=="impersonate" && headers.get("set-cookie").is_some() {Some(seed.as_ref().unwrap().impersonation_cookie(&mut headers,&keys)?)}else{None};
  let raw=seed.as_ref().map_or_else(||raw.clone(),|s|s.normalize_text(raw.clone()));
  let repeat=if kind=="repeat"{
      let original=if route=="bootstrap"{Some(c.query_one("SELECT hmac_secret_enc FROM devices WHERE user_id=$1",&[&seed.as_ref().unwrap().a.user]).await?.get::<_,Vec<u8>>(0))}else{None};
      let(status,mut headers,mut raw)=request(gw.addr,method,&uri,payload.clone(),&request_headers).await?;
      if route=="impersonate"&&headers.get("set-cookie").is_some(){seed.as_ref().unwrap().impersonation_cookie(&mut headers,&keys)?;}
      if route=="bootstrap" {
          let secret=seed.as_ref().unwrap().bootstrap_response(&mut raw)?.ok_or("repeat did not return registration")?;
          if !secret.is_empty(){return Err("repeat re-emitted the device trust root".into());}
          let after:Vec<u8>=c.query_one("SELECT hmac_secret_enc FROM devices WHERE user_id=$1",&[&seed.as_ref().unwrap().a.user]).await?.get(0);
          if Some(after)!=original{return Err("repeat changed encrypted trust root".into());}
      }
      Some(json!({"status":status,"headers":headers,"body":seed.as_ref().map_or_else(||raw.clone(),|s|s.normalize_text(raw.clone()))}))
  }else{None};
  let mut effects=if let Some(s)=&seed{s.effects(&c).await?}else{json!({})};
  if route=="accept"{effects["acceptance"]=seed.as_ref().unwrap().tou_rows(&c).await?;}
  let mut notify=if let Some(n)=&mut notified{json!(n.drain(&c).await?)}else{json!([])};
  let audit=if route=="scim"{seed.as_ref().unwrap().scim_audit(&c).await?}else{json!([])};
  if route=="scim" {effects=seed.as_ref().unwrap().stores(&c).await?;for payload in notify.as_array_mut().unwrap(){let mut v:Value=serde_json::from_str(payload.as_str().unwrap())?;seed.as_ref().unwrap().normalize_store(&mut v);*payload=json!(v.to_string());}}
  let mut actual=json!({"format":1,"go_source":"d431c0ecdbb362809c3fdba781a395712612bf61","route":format!("{method} {path}"),"case":format!("{route}-{kind}"),"observation":{"request":{"method":method,"path":path,"body":seed.as_ref().map_or_else(||payload.clone(),|s|s.normalize_text(payload.clone()))},"response":{"status":status,"headers":headers,"body":raw},"effects":effects,"audit":audit,"notify":notify}});
  if let Some(claims)=token_claims {actual["observation"]["issued_claims"]=claims;}
  if let Some(repeat)=repeat {actual["observation"]["repeat_response"]=repeat;}
  if operator_file.is_some() {
    let mut probes=Vec::new();
    for (uri,payload,ctype) in [
      ("/auth/introspect","{\"token\":\"idlogin3-token-a\"}","application/json"),
      ("/auth/revoke","token=unknown","application/x-www-form-urlencoded"),
      ("/auth/scim/disable","{\"external_id\":\"unknown\"}","application/json"),
      ("/admin/reload","","application/json")
    ] {
      for (label,key) in [("old","idlogin3-internal-test-key"),("new","idlogin3-rotated-test-key")] {
        let bearer=format!("Bearer {key}");
        let(status,headers,raw)=request(gw.addr,"POST",uri,payload.into(),&[("authorization",&bearer),("content-type",ctype)]).await?;
        probes.push(json!({"path":uri,"key":label,"response":{"status":status,"headers":headers,"body":seed.as_ref().unwrap().normalize_text(raw)}}));
      }
    }
    actual["observation"]["rotation_probes"]=json!(probes);
  }

  if let Some(before)=&before_rows {
    let after=if route=="webpush"{seed.as_ref().unwrap().webpush_rows(&c).await?}else if route=="bootstrap"{seed.as_ref().unwrap().bootstrap_rows(&c,&keys,bootstrap_secret.as_deref()).await?}else if route=="impersonate"{seed.as_ref().unwrap().impersonation_rows(&c).await?}else if route=="scim"{seed.as_ref().unwrap().stores(&c).await?}else if route=="accept"{seed.as_ref().unwrap().tou_rows(&c).await?}else{seed.as_ref().unwrap().rows(&c).await?};
    let effects=if matches!(route,"scim"|"bootstrap"){json!(before.as_object().unwrap().iter().map(|(table,value)|json!({"table":table,"before":value,"after":after[table]})).collect::<Vec<_>>())}else{json!([{"table":if route=="accept"{"terms_of_use_acceptance"}else if route=="impersonate"{"audit_log"}else if route=="webpush"{"push_devices"}else{"oauth_tokens"},"before":before,"after":after}])};
    let rows=json!({"format":1,"go_source":"d431c0ecdbb362809c3fdba781a395712612bf61","route":format!("{method} {path}"),"case":format!("{route}-{kind}-row-effects"),"effects":effects});
    let file=corpus().join(format!("{route}-{kind}-rows.json"));
    if record.is_some()&&!file.exists(){golden::record(&file,&rows)?;}
    let expected:Value=common::expected(&file,protected,&rows);
    golden::compare(&expected,&rows)?;
  }
  if route=="reload"{
    let rows=json!({"format":1,"go_source":"d431c0ecdbb362809c3fdba781a395712612bf61","route":format!("{method} {path}"),"case":format!("{route}-{kind}-row-effects"),"effects":[]});
    let file=corpus().join(format!("{route}-{kind}-rows.json"));if record.is_some()&&!file.exists(){golden::record(&file,&rows)?;}golden::compare(&serde_json::from_str::<Value>(&std::fs::read_to_string(file)?)?,&rows)?;
  }
  let golden=corpus().join(format!("{route}-{kind}.json"));
  if record.is_some()&&!golden.exists(){golden::record(&golden,&actual)?;}
  let expected:Value=common::expected(&golden,protected,&actual);
  if let Some(mutation)=mutation {
   let field=if mutation=="no-notify"{"/observation/notify"}else{"/observation/response/status"};
   let error=golden::compare(&expected,&actual).err().ok_or("planted mutant survived its oracle")?;
   if !error.contains(field){return Err(format!("wrong mutant rejection: {error}").into());}
   println!("MUTANT-REJECTED: {method} {path} :: {mutation}");
  }else{golden::compare(&expected,&actual)?;println!("GOLDEN-REPLAY: {method} {path} :: {route}-{kind}");}
  if record.is_none(){
   let (_,_,metrics)=request(gw.addr,"GET","/_gateway/metrics",String::new(),&[]).await?;
   if !metrics.contains("setjoin_gateway_proxied_to_go_total 0"){return Err(format!("unexpected Go hop: {metrics}").into());}
  }
  Ok::<(),Err>(())
 }.await;
    // A failed HTTP restoration must not skip server, environment or fixture
    // teardown and turn subsequent oracle cases into duplicate-client failures.
    let restoration = async {
        if let Some((file, _, _)) = &operator_file {
            std::fs::write(file, "internal:\n  api_key: idlogin3-internal-test-key\n")?;
            let (status, _, _) = request(
                gw.addr,
                "POST",
                "/admin/reload",
                String::new(),
                &[("authorization", "Bearer idlogin3-rotated-test-key")],
            )
            .await?;
            if !matches!(status, 200 | 401) {
                return Err(format!("operator key restoration failed: {status}").into());
            }
        }
        Ok::<(), Err>(())
    }
    .await;
    gw.close().await;
    auth.close().await;
    if let Some(original) = notify_original {
        c.batch_execute(&original).await?;
    }
    if route == "scim" && kind == "fault" {
        c.batch_execute("DROP TRIGGER IF EXISTS gofree_idlogin3_scim_fail ON oauth_tokens;DROP FUNCTION IF EXISTS gofree_idlogin3_scim_fail()").await?;
    }
    if route == "bootstrap" && kind == "fault" {
        c.batch_execute("DROP TRIGGER IF EXISTS gofree_idlogin3_event_fail ON device_events;DROP FUNCTION IF EXISTS gofree_idlogin3_event_fail()").await?;
    }
    if published {
        c.batch_execute("DROP TABLE client_versions").await?;
    }
    if let Some((file, old, owned)) = operator_file {
        if let Some(v) = old {
            std::env::set_var("SETJOIN_CONFIG", v)
        } else {
            std::env::remove_var("SETJOIN_CONFIG")
        }
        if owned {
            std::fs::remove_file(file)?;
        }
    }
    if let Some((secret, key)) = reload_env {
        if let Some(v) = secret {
            std::env::set_var("JWT_SECRET", v)
        } else {
            std::env::remove_var("JWT_SECRET")
        }
        if let Some(v) = key {
            std::env::set_var("INTERNAL_API_KEY", v)
        } else {
            std::env::remove_var("INTERNAL_API_KEY")
        }
    }
    if let Some(old) = saved_rate {
        if let Some(on) = old {
            c.execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
                &[&on],
            )
            .await?;
        } else {
            c.execute(
                "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
                &[],
            )
            .await?;
        }
    }
    if let Some(s) = seed {
        if route == "webpush" {
            s.webpush_cleanup(&c).await?;
        }
        if route == "bootstrap" {
            s.bootstrap_cleanup(&c).await?;
        }
        if route == "impersonate" {
            s.impersonation_cleanup(&c).await?;
        }
        if route == "scim" {
            s.scim_cleanup(&c).await?;
        }
        s.cleanup(&c).await?;
    }
    c.query_one(
        "SELECT pg_advisory_unlock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    match (result, restoration) {
        (Ok(()), restored) => restored,
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(restoration)) => Err(format!("{error}; {restoration}").into()),
    }
}
macro_rules! cases {
    ($route:literal,$ok:ident,$cross:ident,$invalid:ident,$mutant:ident) => {
        #[tokio::test]
        async fn $ok() {
            run($route, "success", false).await.unwrap();
        }
        #[tokio::test]
        async fn $cross() {
            run($route, "cross-tenant", false).await.unwrap();
        }
        #[tokio::test]
        async fn $invalid() {
            run($route, "invalid-input", false).await.unwrap();
        }
        #[tokio::test]
        async fn $mutant() {
            run($route, "success", true).await.unwrap();
        }
    };
}
cases!(
    "discovery",
    discovery_success,
    discovery_cross_tenant,
    discovery_invalid_input,
    discovery_status_mutant
);

cases!(
    "version",
    version_success,
    version_cross_tenant,
    version_invalid_input,
    version_status_mutant
);

#[tokio::test]
async fn version_published() {
    run("version", "published", false).await.unwrap();
}

#[tokio::test]
async fn version_published_blocked() {
    run("version", "published-blocked", false).await.unwrap();
}
#[tokio::test]
async fn version_published_up_to_date() {
    run("version", "published-up-to-date", false).await.unwrap();
}
#[tokio::test]
async fn version_published_update_available() {
    run("version", "published-update-available", false)
        .await
        .unwrap();
}
#[tokio::test]
async fn version_published_malformed() {
    run("version", "published-malformed", false).await.unwrap();
}

cases!(
    "introspect",
    introspect_success,
    introspect_cross_tenant,
    introspect_invalid_input,
    introspect_status_mutant
);

#[tokio::test]
async fn introspect_client_basic() {
    run("introspect", "client-basic", false).await.unwrap();
}

#[tokio::test]
async fn introspect_client_post() {
    run("introspect", "client-post", false).await.unwrap();
}

#[tokio::test]
async fn introspect_client_cross() {
    run("introspect", "client-cross", false).await.unwrap();
}

#[tokio::test]
async fn introspect_bad_secret() {
    run("introspect", "bad-secret", false).await.unwrap();
}

#[tokio::test]
async fn introspect_invalid_form() {
    run("introspect", "invalid-form", false).await.unwrap();
}

#[tokio::test]
async fn introspect_json_type() {
    run("introspect", "json-type", false).await.unwrap();
}

#[tokio::test]
async fn introspect_duplicate_null() {
    run("introspect", "duplicate-null", false).await.unwrap();
}

#[tokio::test]
async fn introspect_trailing_value() {
    run("introspect", "trailing-value", false).await.unwrap();
}

#[tokio::test]
async fn introspect_unknown_number() {
    run("introspect", "unknown-number", false).await.unwrap();
}

#[tokio::test]
async fn introspect_unknown() {
    run("introspect", "unknown", false).await.unwrap();
}

#[tokio::test]
async fn introspect_disabled() {
    run("introspect", "disabled", false).await.unwrap();
}

#[tokio::test]
async fn introspect_revoked() {
    run("introspect", "revoked", false).await.unwrap();
}

#[tokio::test]
async fn introspect_expired() {
    run("introspect", "expired", false).await.unwrap();
}

#[tokio::test]
async fn introspect_app_password() {
    run("introspect", "app-password", false).await.unwrap();
}

cases!(
    "revoke",
    revoke_success,
    revoke_cross_tenant,
    revoke_invalid_input,
    revoke_status_mutant
);

#[tokio::test]
async fn revoke_repeat() {
    run("revoke", "repeat", false).await.unwrap();
}

#[tokio::test]
async fn revoke_client_own() {
    run("revoke", "client-own", false).await.unwrap();
}

#[tokio::test]
async fn revoke_client_other() {
    run("revoke", "client-other", false).await.unwrap();
}

#[tokio::test]
async fn revoke_internal_other() {
    run("revoke", "internal-other", false).await.unwrap();
}

#[tokio::test]
async fn revoke_unknown() {
    run("revoke", "unknown", false).await.unwrap();
}

cases!(
    "pending",
    pending_success,
    pending_cross_tenant,
    pending_invalid_input,
    pending_status_mutant
);

cases!(
    "accept",
    accept_success,
    accept_cross_tenant,
    accept_invalid_input,
    accept_status_mutant
);
#[tokio::test]
async fn accept_repeat() {
    run("accept", "repeat", false).await.unwrap();
}

#[tokio::test]
async fn pending_accepted() {
    run("pending", "accepted", false).await.unwrap();
}

#[tokio::test]
async fn pending_wrong_type() {
    run("pending", "wrong-type", false).await.unwrap();
}

#[tokio::test]
async fn pending_expired_token() {
    run("pending", "expired-token", false).await.unwrap();
}

#[tokio::test]
async fn pending_unauthenticated() {
    run("pending", "unauthenticated", false).await.unwrap();
}

#[tokio::test]
async fn accept_csrf() {
    run("accept", "csrf", false).await.unwrap();
}

#[tokio::test]
async fn accept_wrong_type() {
    run("accept", "wrong-type", false).await.unwrap();
}

#[tokio::test]
async fn accept_expired_token() {
    run("accept", "expired-token", false).await.unwrap();
}

#[tokio::test]
async fn accept_unauthenticated() {
    run("accept", "unauthenticated", false).await.unwrap();
}

#[tokio::test]
async fn accept_stale() {
    run("accept", "stale", false).await.unwrap();
}

#[tokio::test]
async fn accept_missing() {
    run("accept", "missing", false).await.unwrap();
}

#[tokio::test]
async fn accept_overflow() {
    run("accept", "overflow", false).await.unwrap();
}

#[tokio::test]
async fn accept_invalid_type() {
    run("accept", "invalid-type", false).await.unwrap();
}

#[tokio::test]
async fn accept_disabled_tou() {
    run("accept", "disabled-tou", false).await.unwrap();
}

#[tokio::test]
async fn pending_head() {
    run("pending", "head", false).await.unwrap();
}

cases!(
    "scim",
    scim_success,
    scim_cross_tenant,
    scim_invalid_input,
    scim_status_mutant
);
#[tokio::test]
async fn scim_repeat() {
    run("scim", "repeat", false).await.unwrap();
}

#[tokio::test]
async fn scim_external() {
    run("scim", "external", false).await.unwrap();
}

#[tokio::test]
async fn scim_external_missing() {
    run("scim", "external-missing", false).await.unwrap();
}

#[tokio::test]
async fn scim_missing_user() {
    run("scim", "missing-user", false).await.unwrap();
}

#[tokio::test]
async fn scim_negative_user() {
    run("scim", "negative-user", false).await.unwrap();
}

#[tokio::test]
async fn scim_invalid_type() {
    run("scim", "invalid-type", false).await.unwrap();
}

#[tokio::test]
async fn scim_precedence() {
    run("scim", "precedence", false).await.unwrap();
}

#[tokio::test]
async fn scim_fault() {
    run("scim", "fault", false).await.unwrap();
}

#[tokio::test]
async fn scim_no_notify_mutant() {
    run_mode("scim", "success", Some("no-notify"))
        .await
        .unwrap();
}

cases!(
    "reload",
    reload_success,
    reload_cross_tenant,
    reload_invalid_input,
    reload_status_mutant
);
#[tokio::test]
async fn reload_repeat() {
    run("reload", "repeat", false).await.unwrap();
}

#[tokio::test]
async fn reload_rotation() {
    run("reload", "rotation", false).await.unwrap();
}

#[tokio::test]
async fn reload_restoration_failure_does_not_poison_next_case() {
    // The status mutant also changes the operator-key restoration response.
    // Keep reporting that failure, but the next real HTTP replay must be able
    // to create and use its fixtures without duplicate-client collisions.
    let error = run("reload", "rotation", true).await.unwrap_err();
    assert!(
        error.to_string().contains("operator key restoration failed: 599"),
        "unexpected failure: {error}"
    );
    run("reload", "success", false).await.unwrap();
}

#[tokio::test]
async fn pending_quoted_cookie() {
    run("pending", "quoted-cookie", false).await.unwrap();
}
#[tokio::test]
async fn pending_duplicate_cookie() {
    run("pending", "duplicate-cookie", false).await.unwrap();
}
#[tokio::test]
async fn pending_empty_bearer_cookie() {
    run("pending", "empty-bearer-cookie", false).await.unwrap();
}

#[tokio::test]
async fn impersonate_success() {
    run("impersonate", "success", false).await.unwrap();
}

#[tokio::test]
async fn impersonate_cross_tenant() {
    run("impersonate", "cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn impersonate_invalid_input() {
    run("impersonate", "invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn impersonate_status_mutant() {
    run("impersonate", "success", true).await.unwrap();
}
#[tokio::test]
async fn impersonate_missing_permission() {
    run("impersonate", "missing-permission", false)
        .await
        .unwrap();
}
#[tokio::test]
async fn impersonate_domain_scope() {
    run("impersonate", "domain-scope", false).await.unwrap();
}
#[tokio::test]
async fn impersonate_peer() {
    run("impersonate", "peer", false).await.unwrap();
}
#[tokio::test]
async fn impersonate_self() {
    run("impersonate", "self", false).await.unwrap();
}
#[tokio::test]
async fn impersonate_missing() {
    run("impersonate", "missing", false).await.unwrap();
}
#[tokio::test]
async fn impersonate_expired_grant() {
    run("impersonate", "expired-grant", false).await.unwrap();
}
#[tokio::test]
async fn impersonate_inactive_grant() {
    run("impersonate", "inactive-grant", false).await.unwrap();
}
#[tokio::test]
async fn impersonate_disabled() {
    run("impersonate", "disabled", false).await.unwrap();
}
#[tokio::test]
async fn impersonate_non_admin() {
    run("impersonate", "non-admin", false).await.unwrap();
}
#[tokio::test]
async fn impersonate_csrf() {
    run("impersonate", "csrf", false).await.unwrap();
}
#[tokio::test]
async fn impersonate_wrong_type() {
    run("impersonate", "wrong-type", false).await.unwrap();
}
#[tokio::test]
async fn impersonate_unauthenticated() {
    run("impersonate", "unauthenticated", false).await.unwrap();
}

#[tokio::test]
async fn bootstrap_success() {
    run("bootstrap", "success", false).await.unwrap();
}

#[tokio::test]
async fn bootstrap_cross_tenant() {
    run("bootstrap", "cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn bootstrap_invalid_input() {
    run("bootstrap", "invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn bootstrap_status_mutant() {
    run("bootstrap", "success", true).await.unwrap();
}
#[tokio::test]
async fn bootstrap_repeat() {
    run("bootstrap", "repeat", false).await.unwrap();
}
#[tokio::test]
async fn bootstrap_malformed() {
    run("bootstrap", "malformed", false).await.unwrap();
}
#[tokio::test]
async fn bootstrap_null() {
    run("bootstrap", "null", false).await.unwrap();
}
#[tokio::test]
async fn bootstrap_trailing() {
    run("bootstrap", "trailing", false).await.unwrap();
}
#[tokio::test]
async fn bootstrap_short_fingerprint() {
    run("bootstrap", "short-fingerprint", false).await.unwrap();
}
#[tokio::test]
async fn bootstrap_long_fingerprint() {
    run("bootstrap", "long-fingerprint", false).await.unwrap();
}
#[tokio::test]
async fn bootstrap_field_type() {
    run("bootstrap", "field-type", false).await.unwrap();
}
#[tokio::test]
async fn bootstrap_oversized() {
    run("bootstrap", "oversized", false).await.unwrap();
}
#[tokio::test]
async fn bootstrap_wrong_type() {
    run("bootstrap", "wrong-type", false).await.unwrap();
}
#[tokio::test]
async fn bootstrap_unauthenticated() {
    run("bootstrap", "unauthenticated", false).await.unwrap();
}
#[tokio::test]
async fn bootstrap_cookie() {
    run("bootstrap", "cookie", false).await.unwrap();
}
#[tokio::test]
async fn bootstrap_csrf() {
    run("bootstrap", "csrf", false).await.unwrap();
}
#[tokio::test]
async fn bootstrap_revoked() {
    run("bootstrap", "revoked", false).await.unwrap();
}
#[tokio::test]
async fn bootstrap_bound() {
    run("bootstrap", "bound", false).await.unwrap();
}
#[tokio::test]
async fn bootstrap_fault() {
    run("bootstrap", "fault", false).await.unwrap();
}

#[tokio::test]
async fn webpush_success() {
    run("webpush", "success", false).await.unwrap();
}

#[tokio::test]
async fn webpush_cross_tenant() {
    run("webpush", "cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn webpush_invalid_input() {
    run("webpush", "invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn webpush_status_mutant() {
    run("webpush", "success", true).await.unwrap();
}
#[tokio::test]
async fn webpush_repeat() {
    run("webpush", "repeat", false).await.unwrap();
}
#[tokio::test]
async fn webpush_null() {
    run("webpush", "null", false).await.unwrap();
}
#[tokio::test]
async fn webpush_malformed() {
    run("webpush", "malformed", false).await.unwrap();
}
#[tokio::test]
async fn webpush_field_type() {
    run("webpush", "field-type", false).await.unwrap();
}
#[tokio::test]
async fn webpush_provider() {
    run("webpush", "provider", false).await.unwrap();
}
#[tokio::test]
async fn webpush_subscription_json() {
    run("webpush", "subscription-json", false).await.unwrap();
}
#[tokio::test]
async fn webpush_missing_endpoint() {
    run("webpush", "missing-endpoint", false).await.unwrap();
}
#[tokio::test]
async fn webpush_subscription_trailing() {
    run("webpush", "subscription-trailing", false)
        .await
        .unwrap();
}
#[tokio::test]
async fn webpush_subscription_limit() {
    run("webpush", "subscription-limit", false).await.unwrap();
}
#[tokio::test]
async fn webpush_oversized() {
    run("webpush", "oversized", false).await.unwrap();
}
#[tokio::test]
async fn webpush_trailing() {
    run("webpush", "trailing", false).await.unwrap();
}
#[tokio::test]
async fn webpush_http() {
    run("webpush", "http", false).await.unwrap();
}
#[tokio::test]
async fn webpush_localhost() {
    run("webpush", "localhost", false).await.unwrap();
}
#[tokio::test]
async fn webpush_private_ip() {
    run("webpush", "private-ip", false).await.unwrap();
}
#[tokio::test]
async fn webpush_mapped_ip() {
    run("webpush", "mapped-ip", false).await.unwrap();
}
#[tokio::test]
async fn webpush_numeric_host() {
    run("webpush", "numeric-host", false).await.unwrap();
}
#[tokio::test]
async fn webpush_documentation_ip() {
    run("webpush", "documentation-ip", false).await.unwrap();
}
#[tokio::test]
async fn webpush_bad_url() {
    run("webpush", "bad-url", false).await.unwrap();
}
#[tokio::test]
async fn webpush_csrf() {
    run("webpush", "csrf", false).await.unwrap();
}
#[tokio::test]
async fn webpush_wrong_type() {
    run("webpush", "wrong-type", false).await.unwrap();
}
#[tokio::test]
async fn webpush_unauthenticated() {
    run("webpush", "unauthenticated", false).await.unwrap();
}

#[tokio::test]async fn reload_failed_config(){run("reload","failed-config",false).await.unwrap();}
#[tokio::test]async fn impersonate_repeat(){run("impersonate","repeat",false).await.unwrap();}

#[tokio::test]async fn bootstrap_unicode_surrogate(){run("bootstrap","unicode-surrogate",false).await.unwrap();}
