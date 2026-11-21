//! Runtime-gate integration coverage for #355a native DAV and Drive Basic auth.
mod common;

use base64::{engine::general_purpose::STANDARD, Engine};
use common::BoxError;
use futures_util::FutureExt;
use hmac::{Hmac, Mac};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_config_secret::{seal_column, CryptoProfile};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    caldav::CalDavRoute,
    carddav::CardDavRoute,
    dav_auth::DavBasicAuth,
    drive_native::NativeTokenRoute,
    runtime_access::{RuntimeAccess, RuntimeGate},
    Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::{workers::WorkerDatabase, ScopedExecutor};
use setjoin_threat::{ConnectionMeta, ThreatAction, ThreatGate};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const RUNTIME_FLAGS: [&str; 5] = [
    "feature.cae_runtime",
    "feature.conditional_access",
    "feature.device_trust_enforcement",
    "feature.device_lockdown",
    "feature.token_binding",
];

#[derive(Clone)]
struct AllowThreat {
    intercepts: Arc<Mutex<Vec<ConnectionMeta>>>,
    records: Arc<Mutex<Vec<(ConnectionMeta, bool, i64)>>>,
}

impl AllowThreat {
    fn new() -> Self {
        Self {
            intercepts: Arc::new(Mutex::new(Vec::new())),
            records: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl ThreatGate for AllowThreat {
    fn intercept<'a>(
        &'a self,
        meta: &'a ConnectionMeta,
    ) -> futures_util::future::BoxFuture<'a, (ThreatAction, std::time::Duration)> {
        Box::pin(async move {
            self.intercepts.lock().unwrap().push(meta.clone());
            (ThreatAction::Allow, std::time::Duration::ZERO)
        })
    }

    fn record_result<'a>(
        &'a self,
        meta: &'a ConnectionMeta,
        success: bool,
        user_id: i64,
    ) -> futures_util::future::BoxFuture<'a, ()> {
        Box::pin(async move {
            self.records
                .lock()
                .unwrap()
                .push((meta.clone(), success, user_id));
        })
    }

    fn evaluate_post_auth<'a>(
        &'a self,
        _meta: &'a mut ConnectionMeta,
    ) -> futures_util::future::BoxFuture<'a, (ThreatAction, String)> {
        Box::pin(async move { (ThreatAction::Allow, String::new()) })
    }
}

struct NonDavProbe {
    hits: Arc<AtomicUsize>,
}

impl Intercept for NonDavProbe {
    fn matches(&self, r: &Request<Body>) -> bool {
        r.uri().path() == "/api/admin/conditional-access/break-glass"
    }

    fn handle(&self, _: Request<Body>, _: RequestContext) -> BoxFuture<Response<Body>> {
        self.hits.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Response::new(common::full("non-dav probe ran")) })
    }
}

struct RunningServer {
    addr: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl RunningServer {
    async fn close(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.task).await;
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn basic_header(email: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{email}:{secret}")))
}

fn device_hmac_headers(
    device_id: i64,
    dev_secret: &[u8],
    method: &str,
    inner_uri: &str,
    body: &[u8],
    nonce: &str,
) -> [(&'static str, String); 5] {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let body_hash = hex_lower(&Sha256::digest(body));
    let challenge = format!("{device_id}:{ts}:{method}:{inner_uri}:{body_hash}:{nonce}");
    let mut mac = Hmac::<Sha256>::new_from_slice(dev_secret).unwrap();
    mac.update(challenge.as_bytes());
    let signature = hex_lower(&mac.finalize().into_bytes());
    [
        ("x-device-id", device_id.to_string()),
        ("x-device-timestamp", ts),
        ("x-device-nonce", nonce.to_owned()),
        ("x-device-body-sha256", body_hash),
        ("x-device-hmac", signature),
    ]
}

async fn set_runtime_flags(
    owner: &tokio_postgres::Client,
    enabled: &[&str],
) -> Result<(), BoxError> {
    let list: Vec<String> = enabled.iter().map(|s| (*s).to_owned()).collect();
    for key in RUNTIME_FLAGS {
        let on = list.iter().any(|k| k == key);
        owner
            .execute(
                "INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET enabled=$2",
                &[&key, &on],
            )
            .await?;
    }
    Ok(())
}

async fn spawn_gateway_with_runtime(
    db: &Db,
    exec: &ScopedExecutor,
    keys: Arc<setjoin_authz::jwks::Jwks>,
    chain: Arc<setjoin_authz::auth_chain::Chain>,
    threat: Arc<AllowThreat>,
    drive_secret: &str,
    device_master: Option<Vec<u8>>,
    upstream: Option<SocketAddr>,
    non_dav_hits: Arc<AtomicUsize>,
) -> Result<RunningServer, BoxError> {
    let worker_exec = common::patient_exec(&db.dsn, 2)?;
    let mut runtime = RuntimeAccess::new(exec.clone(), keys.clone(), "mailserver".into())
        .with_workers(worker_exec, WorkerDatabase::new(&db.dsn)?)
        .with_direct(db.direct.clone());
    if let Some(master) = device_master {
        runtime = runtime.with_device_secret(master, CryptoProfile::Standard);
    }
    let runtime = Arc::new(runtime);
    runtime.initialize().await;

    let basic = DavBasicAuth {
        chain: Some(chain),
        password_cache: Arc::new(setjoin_authz::basic::PasswordCache::new()),
        threat: Some(threat),
        runtime: Some(runtime.clone()),
    };
    let caldav = CalDavRoute::new(exec.clone(), keys.clone(), "mailserver".into())
        .await
        .with_basic_auth(basic.clone());
    let carddav = CardDavRoute::new(exec.clone(), keys.clone(), "mailserver".into())
        .with_basic_auth(basic.clone());
    let drive = NativeTokenRoute::new(exec.clone(), keys, "mailserver".into(), Some(drive_secret))
        .with_basic_auth(basic);

    let routes = RouteTable::proxy_all()
        .with(caldav)
        .with(carddav)
        .with(drive)
        .with(NonDavProbe { hits: non_dav_hits })
        .with_runtime(runtime);

    let gateway = Gateway::new(
        Config {
            upstream: upstream.map(|a| format!("http://{a}").parse().unwrap()),
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: std::time::Duration::from_secs(30),
            edge_limit: None,
        },
        routes,
    )?
    .with_inventory(setjoin_gateway::inventory::BUNDLED)?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(gateway.serve_until(listener, async {
        let _ = rx.await;
    }));
    Ok(RunningServer {
        addr,
        stop: Some(tx),
        task,
    })
}

async fn send_request(
    addr: SocketAddr,
    method: &str,
    uri: &str,
    auth: &str,
    body: &[u8],
    device: Option<(i64, &[u8], &str)>,
) -> Result<(u16, Option<String>, Vec<u8>), BoxError> {
    let mut req = Request::builder().method(method).uri(uri);
    if uri == "/api/drive/native-token" {
        req = req
            .header("host", "mail.idlogin3.test")
            .header("origin", "http://mail.idlogin3.test")
            .header("content-type", "application/json");
    }
    req = req.header("authorization", auth);
    if let Some((device_id, secret, nonce)) = device {
        let inner_uri = uri.strip_prefix("/api").unwrap_or(uri);
        for (name, value) in device_hmac_headers(device_id, secret, method, inner_uri, body, nonce)
        {
            req = req.header(name, value);
        }
    }
    let resp = common::send(
        addr,
        req.body(common::full(String::from_utf8_lossy(body).into_owned()))?,
    )
    .await;
    let status = resp.status().as_u16();
    let www = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = common::body_bytes(resp).await.to_vec();
    Ok((status, www, bytes))
}

#[tokio::test]
async fn dav_and_drive_native_basic_auth_runtime_gates() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("dav-basic-runtime-gates") else {
        return Ok(());
    };
    let owner = Arc::new(db.connect().await?);
    let account = fixture::account(&owner, "dav-basic-rt").await?;
    let foreign = fixture::account(&owner, "dav-basic-rt-bg").await?;
    let email: String = owner
        .query_one("SELECT email FROM users WHERE id=$1", &[&account.user])
        .await?
        .get(0);

    let toggle_keys: Vec<String> = [
        "feature.disable_basic_auth",
        "feature.drive",
        "feature.cae_runtime",
        "feature.conditional_access",
        "feature.device_trust_enforcement",
        "feature.device_lockdown",
        "feature.token_binding",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let saved_toggles: Vec<(String, bool)> = owner
        .query(
            "SELECT key,enabled FROM feature_toggles WHERE key=ANY($1)",
            &[&toggle_keys],
        )
        .await?
        .into_iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let saved_bg: Option<String> = owner
        .query_opt(
            "SELECT value::text FROM system_config WHERE key='ca_break_glass_user_ids'",
            &[],
        )
        .await?
        .map(|r| r.get(0));

    let jwks = common::fake_upstream(|_| async {
        Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(common::full(
                include_bytes!("../../../tests/conformance/jmap/test-jwks.json").as_slice(),
            ))
            .unwrap()
    })
    .await;
    let drive_secret = "dav-basic-runtime-drive-secret-32";
    let keys = Arc::new(
        setjoin_authz::jwks::Jwks::new(format!("http://{jwks}/.well-known/jwks.json").parse()?)?
            .with_legacy_keys(setjoin_authz::legacy_jwt::LegacyKeys::new(
                drive_secret.as_bytes(),
                &["authserver-hmac-1", "mailserver-drive-native-1"],
                None,
            )?),
    );
    let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?;

    let res = std::panic::AssertUnwindSafe(async {
        owner
            .execute(
                "INSERT INTO feature_toggles(key,enabled) VALUES('feature.disable_basic_auth',false),('feature.drive',true) ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled",
                &[],
            )
            .await?;
        let app_secret = "dav-basic-rt-app-password";
        let app_hash = hex_lower(&Sha256::digest(app_secret.as_bytes()));
        owner
            .execute(
                "INSERT INTO app_passwords(user_id,name,label,token_hash) VALUES($1,'dav','dav',$2)",
                &[&account.user, &app_hash],
            )
            .await?;
        let chain = Arc::new(setjoin_authz::auth_chain::Chain::default());
        chain.reload(&exec).await.unwrap();
        let auth_ok = basic_header(&email, app_secret);
        let auth_bad = basic_header(&email, "wrong-password-123");

        // 1. device_trust_enforcement blocks claimless Basic proofs with device_compliance_unverifiable.
        set_runtime_flags(&owner, &["feature.device_trust_enforcement"]).await?;
        let srv = spawn_gateway_with_runtime(
            &db,
            &exec,
            keys.clone(),
            chain.clone(),
            Arc::new(AllowThreat::new()),
            drive_secret,
            None,
            None,
            Arc::new(AtomicUsize::new(0)),
        )
        .await?;
        for (method, uri, body) in [
            ("OPTIONS", "/caldav/", b"".as_slice()),
            ("OPTIONS", "/carddav/", b"".as_slice()),
            ("POST", "/api/drive/native-token", b"{}".as_slice()),
        ] {
            let (status, _, bytes) =
                send_request(srv.addr, method, uri, &auth_ok, body, None).await?;
            assert_eq!(status, 403, "device_trust on {method} {uri}");
            let v: Value = serde_json::from_slice(&bytes)?;
            assert_eq!(v["title"], "device_compliance_unverifiable");
        }
        srv.close().await;

        // 2. device_lockdown returns BZ095 without device HMAC and succeeds with enrolled approved device HMAC.
        set_runtime_flags(
            &owner,
            &["feature.conditional_access", "feature.device_lockdown"],
        )
        .await?;
        owner
            .execute(
                "INSERT INTO system_config(key,value) VALUES('ca_break_glass_user_ids',$1::text::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                &[&json!([foreign.user]).to_string()],
            )
            .await?;
        let master = vec![0x2a_u8; 32];
        let dev_secret = b"dav-basic-lockdown-hmac-secret32";
        let sealed = seal_column(dev_secret, &master, CryptoProfile::Standard)?;
        let device_id: i64 = owner
            .query_one(
                "INSERT INTO devices(user_id,fingerprint,hmac_secret_enc,hmac_secret_key_id,enroll_state) VALUES($1,'dav-basic-lockdown-fp',$2,'v1','approved') RETURNING id",
                &[&account.user, &sealed],
            )
            .await?
            .get(0);
        let srv = spawn_gateway_with_runtime(
            &db,
            &exec,
            keys.clone(),
            chain.clone(),
            Arc::new(AllowThreat::new()),
            drive_secret,
            Some(master),
            None,
            Arc::new(AtomicUsize::new(0)),
        )
        .await?;
        for (method, uri, body) in [
            ("OPTIONS", "/caldav/", b"".as_slice()),
            ("OPTIONS", "/carddav/", b"".as_slice()),
            ("POST", "/api/drive/native-token", b"{}".as_slice()),
        ] {
            let (status, _, bytes) =
                send_request(srv.addr, method, uri, &auth_ok, body, None).await?;
            assert_eq!(status, 403, "lockdown missing hmac on {method} {uri}");
            let v: Value = serde_json::from_slice(&bytes)?;
            assert_eq!(v["code"], "BZ095");
            assert_eq!(v["detail"], "device not enrolled — contact your administrator");
        }
        for (idx, (method, uri, body)) in [
            ("OPTIONS", "/caldav/", b"".as_slice()),
            ("OPTIONS", "/carddav/", b"".as_slice()),
            ("POST", "/api/drive/native-token", b"{}".as_slice()),
        ]
        .into_iter()
        .enumerate()
        {
            let nonce = format!("dav-basic-nonce-{idx}");
            let (status, _, bytes) = send_request(
                srv.addr,
                method,
                uri,
                &auth_ok,
                body,
                Some((device_id, dev_secret, &nonce)),
            )
            .await?;
            assert_eq!(status, 200, "lockdown enrolled hmac on {method} {uri}");
            if uri == "/api/drive/native-token" {
                let v: Value = serde_json::from_slice(&bytes)?;
                assert!(v["token"].as_str().is_some());
            }
        }
        srv.close().await;

        // 3. SessionDenylist scope='all' revocation rejects Basic auth even when CAE flag is off.
        set_runtime_flags(&owner, &[]).await?;
        owner
            .execute(
                "INSERT INTO session_revocations(user_id,scope,not_before,reason,expires_at) VALUES($1,'all',now(),'dav-basic-revoke',now()+interval '1 hour')",
                &[&account.user],
            )
            .await?;
        let srv = spawn_gateway_with_runtime(
            &db,
            &exec,
            keys.clone(),
            chain.clone(),
            Arc::new(AllowThreat::new()),
            drive_secret,
            None,
            None,
            Arc::new(AtomicUsize::new(0)),
        )
        .await?;
        for (method, uri, body) in [
            ("OPTIONS", "/caldav/", b"".as_slice()),
            ("OPTIONS", "/carddav/", b"".as_slice()),
            ("POST", "/api/drive/native-token", b"{}".as_slice()),
        ] {
            let (status, _, bytes) =
                send_request(srv.addr, method, uri, &auth_ok, body, None).await?;
            assert_eq!(status, 401, "session revocation on {method} {uri}");
            let v: Value = serde_json::from_slice(&bytes)?;
            assert_eq!(v["detail"], "Session has been revoked. Sign in again.");
        }
        srv.close().await;
        owner
            .execute("DELETE FROM session_revocations WHERE user_id=$1", &[&account.user])
            .await?;

        // 4. cae_runtime + conditional_access policy matching auth_method="basic_auth" blocks Basic.
        set_runtime_flags(
            &owner,
            &["feature.cae_runtime", "feature.conditional_access"],
        )
        .await?;
        owner
            .execute(
                "INSERT INTO conditional_access_policies(name,priority,enabled,state,scope_type,scope_target,conditions,actions) VALUES('dav-basic-ca-block',1,true,'on','user',$1,'{\"auth_method\":\"basic_auth\"}','{\"grants\":[{\"type\":\"block\"}],\"reason\":\"ca basic block\"}')",
                &[&account.user.to_string()],
            )
            .await?;
        let srv = spawn_gateway_with_runtime(
            &db,
            &exec,
            keys.clone(),
            chain.clone(),
            Arc::new(AllowThreat::new()),
            drive_secret,
            None,
            None,
            Arc::new(AtomicUsize::new(0)),
        )
        .await?;
        for (method, uri, body) in [
            ("OPTIONS", "/caldav/", b"".as_slice()),
            ("OPTIONS", "/carddav/", b"".as_slice()),
            ("POST", "/api/drive/native-token", b"{}".as_slice()),
        ] {
            let (status, _, bytes) =
                send_request(srv.addr, method, uri, &auth_ok, body, None).await?;
            assert_eq!(status, 403, "CA auth_method=basic_auth on {method} {uri}");
            let v: Value = serde_json::from_slice(&bytes)?;
            assert_eq!(v["detail"], "ca basic block");
        }
        srv.close().await;
        owner
            .execute("DELETE FROM conditional_access_policies WHERE name='dav-basic-ca-block'", &[])
            .await?;

        // 5, 6, 7: All runtime flags ON ->
        //   5) wrong Basic password on DAV/Drive still returns route 401 with WWW-Authenticate;
        //   6) Basic on non-DAV protected route still gets RuntimeAccess 401 "Authentication required.";
        //   7) Negotiate on DAV/Drive still forwards to Go upstream.
        set_runtime_flags(&owner, &RUNTIME_FLAGS).await?;
        let go_hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = go_hits.clone();
        let go_upstream = common::fake_upstream(move |_| {
            let hits = hits_clone.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                Response::builder()
                    .status(218)
                    .body(common::full("go-negotiate"))
                    .unwrap()
            }
        })
        .await;
        let non_dav_hits = Arc::new(AtomicUsize::new(0));
        let srv = spawn_gateway_with_runtime(
            &db,
            &exec,
            keys,
            chain,
            Arc::new(AllowThreat::new()),
            drive_secret,
            None,
            Some(go_upstream),
            non_dav_hits.clone(),
        )
        .await?;

        for (method, uri, body) in [
            ("OPTIONS", "/caldav/", b"".as_slice()),
            ("OPTIONS", "/carddav/", b"".as_slice()),
            ("POST", "/api/drive/native-token", b"{}".as_slice()),
        ] {
            let (status, www, _) =
                send_request(srv.addr, method, uri, &auth_bad, body, None).await?;
            assert_eq!(status, 401, "wrong password on {method} {uri}");
            assert_eq!(
                www.as_deref(),
                Some("Negotiate, Bearer realm=\"mailserver\""),
                "www-authenticate on {method} {uri}"
            );
        }

        let (status, www, bytes) = send_request(
            srv.addr,
            "GET",
            "/api/admin/conditional-access/break-glass",
            &auth_ok,
            b"",
            None,
        )
        .await?;
        assert_eq!(status, 401);
        assert!(www.is_none(), "unexpected www-authenticate on non-DAV 401");
        let v: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(v["detail"], "Authentication required.");
        assert_eq!(non_dav_hits.load(Ordering::SeqCst), 0);

        for (method, uri, body) in [
            ("OPTIONS", "/caldav/", b"".as_slice()),
            ("OPTIONS", "/carddav/", b"".as_slice()),
            ("POST", "/api/drive/native-token", b"{}".as_slice()),
        ] {
            let (status, _, bytes) =
                send_request(srv.addr, method, uri, "Negotiate YII=", body, None).await?;
            assert_eq!(status, 218, "Negotiate forward on {method} {uri}");
            assert_eq!(bytes, b"go-negotiate");
        }
        assert_eq!(go_hits.load(Ordering::SeqCst), 3);

        srv.close().await;
        Ok::<_, BoxError>(())
    })
    .catch_unwind()
    .await;

    for key in &toggle_keys {
        if let Some((_, on)) = saved_toggles.iter().find(|(k, _)| k == key) {
            owner
                .execute(
                    "INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET enabled=$2",
                    &[key, on],
                )
                .await?;
        } else {
            owner
                .execute("DELETE FROM feature_toggles WHERE key=$1", &[key])
                .await?;
        }
    }
    if let Some(bg) = saved_bg {
        owner
            .execute(
                "INSERT INTO system_config(key,value) VALUES('ca_break_glass_user_ids',$1::text::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                &[&bg],
            )
            .await?;
    } else {
        owner
            .execute(
                "DELETE FROM system_config WHERE key='ca_break_glass_user_ids'",
                &[],
            )
            .await?;
    }
    owner
        .execute(
            "DELETE FROM conditional_access_policies WHERE name='dav-basic-ca-block'",
            &[],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM auth_event_log WHERE user_id=$1 OR lower(email)=lower($2)",
            &[&account.user, &email],
        )
        .await?;
    let _ = owner
        .execute(
            "DELETE FROM device_auth_nonces WHERE device_id IN (SELECT id FROM devices WHERE user_id=$1)",
            &[&account.user],
        )
        .await;
    owner
        .execute("DELETE FROM devices WHERE user_id=$1", &[&account.user])
        .await?;
    owner
        .execute(
            "DELETE FROM app_passwords WHERE user_id=$1",
            &[&account.user],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM session_revocations WHERE user_id=$1",
            &[&account.user],
        )
        .await?;
    fixture::remove(&owner, &foreign).await?;
    fixture::remove(&owner, &account).await?;

    match res {
        Ok(inner) => inner,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
