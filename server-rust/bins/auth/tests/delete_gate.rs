//! #358 DELETE gate, auth half. Every toggle cell x credential shape is sent to a
//! native setjoin-auth whose Go upstream is a counting fake. Each (cell, shape)
//! has a reviewed expected outcome: `Native(status)` (zero Go hits) or
//! `Hop(owner)` (exactly one hit, the fake's 299). EXPECT was reviewed against
//! the hand-off order in bins/auth/src/lib.rs (login: device proof, threat/rate,
//! CA/device trust, credentials, guest scope, admission, DPoP; refresh:
//! threat/rate). A mismatch is a finding: fix the code or get the EXPECT change
//! reviewed. Never copy observed output into EXPECT. The guard pins the Hop cells.
mod common;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, harness::Db};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

type Err = Box<dyn std::error::Error + Send + Sync>;
const SECRET: &str = "delete-gate-matrix-secret-0123456789abcdef";
const PASSWORD: &str = "Password1!";
const GUEST_PASSWORD: &str = "Guest1!pass";
const FAKE_GO_STATUS: u16 = 299;
const TOGGLES: [&str; 4] = [
    "feature.rate_limit",
    "feature.conditional_access",
    "feature.device_trust_enforcement",
    "feature.token_binding",
];

struct Cell {
    name: &'static str,
    threat: [bool; 5],
    toggles: Option<[bool; 4]>,
}
const CELLS: &[Cell] = &[
    Cell {
        name: "default",
        threat: [true; 5],
        toggles: None,
    },
    Cell {
        name: "all-on",
        threat: [true; 5],
        toggles: Some([true; 4]),
    },
    Cell {
        name: "none",
        threat: [false; 5],
        toggles: Some([false; 4]),
    },
    Cell {
        name: "threat-feed",
        threat: [true, false, false, false, false],
        toggles: Some([false; 4]),
    },
    Cell {
        name: "geo-block",
        threat: [false, true, false, false, false],
        toggles: Some([false; 4]),
    },
    Cell {
        name: "spray-detect",
        threat: [false, false, true, false, false],
        toggles: Some([false; 4]),
    },
    Cell {
        name: "captcha",
        threat: [false, false, false, true, false],
        toggles: Some([false; 4]),
    },
    Cell {
        name: "tarpit",
        threat: [false, false, false, false, true],
        toggles: Some([false; 4]),
    },
    Cell {
        name: "rate-limit",
        threat: [false; 5],
        toggles: Some([true, false, false, false]),
    },
    Cell {
        name: "conditional-access",
        threat: [false; 5],
        toggles: Some([false, true, false, false]),
    },
    Cell {
        name: "device-trust",
        threat: [false; 5],
        toggles: Some([false, false, true, false]),
    },
    Cell {
        name: "token-binding",
        threat: [false; 5],
        toggles: Some([false, false, false, true]),
    },
];
const SHAPES: [&str; 6] = [
    "login",
    "login-device",
    "login-captcha",
    "login-dpop",
    "login-guest",
    "refresh",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Hop(&'static str),
    Native(u16),
}
use Outcome::{Hop, Native};

const ALL: &[&str] = &[
    "default",
    "all-on",
    "none",
    "threat-feed",
    "geo-block",
    "spray-detect",
    "captcha",
    "tarpit",
    "rate-limit",
    "conditional-access",
    "device-trust",
    "token-binding",
];
const THREAT: &[&str] = &[
    "default",
    "all-on",
    "threat-feed",
    "geo-block",
    "spray-detect",
    "captcha",
    "tarpit",
    "rate-limit",
];
const CA: &[&str] = &["conditional-access", "device-trust"];
const NONE: &[&str] = &["none"];
const TB: &[&str] = &["token-binding"];
/// Reviewed outcomes. Hop cells only shrink (guard: MATRIX_HOPS = 63).
const EXPECT: &[(&[&str], &str, Outcome)] = &[
    (
        ALL,
        "login-device",
        Hop("#350 device-proof admission (lib.rs:1067)"),
    ),
    (
        THREAT,
        "login",
        Hop("#349 threat/rate admission (lib.rs:1074)"),
    ),
    (
        THREAT,
        "login-captcha",
        Hop("#349 threat/rate admission (lib.rs:1074)"),
    ),
    (
        THREAT,
        "login-dpop",
        Hop("#349 threat/rate admission (lib.rs:1074)"),
    ),
    (
        THREAT,
        "login-guest",
        Hop("#349 threat/rate admission (lib.rs:1074)"),
    ),
    (
        THREAT,
        "refresh",
        Hop("#349 threat/rate admission (lib.rs:674)"),
    ),
    (
        CA,
        "login",
        Hop("#351 conditional access/device trust (lib.rs:1080)"),
    ),
    (
        CA,
        "login-captcha",
        Hop("#351 conditional access/device trust (lib.rs:1080)"),
    ),
    (
        CA,
        "login-dpop",
        Hop("#351 conditional access/device trust (lib.rs:1080)"),
    ),
    (
        CA,
        "login-guest",
        Hop("#351 conditional access/device trust (lib.rs:1080)"),
    ),
    (CA, "refresh", Native(200)),
    (NONE, "login", Native(200)),
    (NONE, "login-captcha", Native(200)),
    (NONE, "login-dpop", Native(200)),
    (NONE, "login-guest", Hop("#353 guest scope (lib.rs:1144)")),
    (NONE, "refresh", Native(200)),
    (TB, "login", Native(200)),
    (TB, "login-captcha", Native(200)),
    (TB, "login-dpop", Hop("#352 DPoP admission (lib.rs:1194)")),
    (TB, "login-guest", Hop("#353 guest scope (lib.rs:1144)")),
    (TB, "refresh", Native(200)),
];

fn expected() -> Result<BTreeMap<(&'static str, &'static str), Outcome>, String> {
    let mut out = BTreeMap::new();
    for (cells, shape, outcome) in EXPECT {
        if !SHAPES.contains(shape) {
            return Err(format!("EXPECT names unknown shape {shape}"));
        }
        for cell in *cells {
            if !CELLS.iter().any(|c| c.name == *cell) {
                return Err(format!("EXPECT names unknown cell {cell}"));
            }
            if out.insert((*cell, *shape), *outcome).is_some() {
                return Err(format!("EXPECT lists cell {cell} shape {shape} twice"));
            }
        }
    }
    for cell in CELLS {
        for shape in SHAPES {
            if !out.contains_key(&(cell.name, shape)) {
                return Err(format!(
                    "EXPECT has no outcome for cell {} shape {shape}",
                    cell.name
                ));
            }
        }
    }
    Ok(out)
}

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
async fn serve(server: Arc<AuthServer>) -> Server {
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
                                Ok::<_, std::convert::Infallible>(
                                    server.handle(req.map(|b| b.map_err(std::io::Error::other).boxed())).await,
                                )
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
async fn fake_go(
    hits: Arc<AtomicUsize>,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), Err> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let hits = hits.clone();
            tokio::spawn(async move {
                let service =
                    hyper::service::service_fn(move |_req: Request<hyper::body::Incoming>| {
                        hits.fetch_add(1, Ordering::SeqCst);
                        async move {
                            let mut r = hyper::Response::new(body("fake-go"));
                            *r.status_mut() = hyper::StatusCode::from_u16(FAKE_GO_STATUS).unwrap();
                            Ok::<_, std::convert::Infallible>(r)
                        }
                    });
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await;
            });
        }
    });
    Ok((addr, task))
}
async fn start(db: &Db, threat: [bool; 5], go: std::net::SocketAddr) -> Result<Server, Err> {
    let mut cfg = Config::for_secret(SECRET.into());
    cfg.threat_controls = threat;
    cfg.go_upstream = Some(format!("http://{go}"));
    let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
        .map_err(|e| e.0)?;
    Ok(serve(Arc::new(AuthServer::load(exec, cfg).await?)).await)
}
async fn post(
    addr: std::net::SocketAddr,
    path: &str,
    payload: String,
    headers: &[(&str, &str)],
) -> Result<(u16, hyper::HeaderMap, String), Err> {
    let client: hyper_util::client::legacy::Client<_, setjoin_auth::Body> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("http://{addr}{path}"))
        .header("host", "auth.delete-gate.test")
        .header("user-agent", "DELETE gate matrix")
        .header("content-type", "application/json");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = client.request(req.body(body(payload))?).await?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let raw = String::from_utf8_lossy(&resp.into_body().collect().await?.to_bytes()).into_owned();
    Ok((status, headers, raw))
}
async fn mint_refresh(addr: std::net::SocketAddr, email: &str) -> Result<String, Err> {
    let (status, headers, raw) = post(
        addr,
        "/auth/login",
        json!({"email": email, "password": PASSWORD}).to_string(),
        &[],
    )
    .await?;
    if status != 200 {
        return Err(format!("native login with every control off returned {status}: {raw}").into());
    }
    if let Some(token) = serde_json::from_str::<Value>(&raw)
        .ok()
        .and_then(|v| v["refresh_token"].as_str().map(str::to_owned))
    {
        return Ok(token);
    }
    for value in headers.get_all("set-cookie") {
        if let Some(rest) = value.to_str()?.strip_prefix("refresh_token=") {
            return Ok(rest.split(';').next().unwrap_or("").to_owned());
        }
    }
    Err("native login returned no refresh token".into())
}
async fn send_shape(
    addr: std::net::SocketAddr,
    shape: &str,
    email: &str,
    guest: &str,
    refresh: &str,
) -> Result<(u16, hyper::HeaderMap, String), Err> {
    let device = [
        ("x-device-id", "delete-gate"),
        ("x-device-hmac", "00"),
        ("x-device-timestamp", "0"),
        ("x-device-nonce", "delete-gate"),
        ("x-device-body-sha256", "00"),
    ];
    // RFC 7517 A.1 P-256 public key: a valid point, so only token binding decides.
    let jwk = json!({"kty": "EC", "crv": "P-256",
                     "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                     "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"});
    let login = json!({"email": email, "password": PASSWORD}).to_string();
    match shape {
        "login" => post(addr, "/auth/login", login, &[]).await,
        "login-device" => post(addr, "/auth/login", login, &device).await,
        "login-captcha" => {
            let b = json!({"email": email, "password": PASSWORD, "captcha_token": "delete-gate"});
            post(addr, "/auth/login", b.to_string(), &[]).await
        }
        "login-dpop" => {
            let b = json!({"email": email, "password": PASSWORD, "dpop_jwk": jwk});
            post(addr, "/auth/login", b.to_string(), &[]).await
        }
        "login-guest" => {
            let b = json!({"email": guest, "password": GUEST_PASSWORD});
            post(addr, "/auth/login", b.to_string(), &[]).await
        }
        "refresh" => {
            post(
                addr,
                "/auth/refresh",
                json!({"refresh_token": refresh}).to_string(),
                &[],
            )
            .await
        }
        other => Err(format!("unknown shape {other}").into()),
    }
}
async fn set_toggle(c: &tokio_postgres::Client, key: &str, on: bool) -> Result<(), Err> {
    c.execute(
        "INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET enabled=$2",
        &[&key, &on],
    )
    .await?;
    Ok(())
}
async fn restore(c: &tokio_postgres::Client, saved: &[(String, Option<bool>)]) -> Result<(), Err> {
    for (key, value) in saved {
        match value {
            Some(on) => set_toggle(c, key, *on).await?,
            None => {
                c.execute("DELETE FROM feature_toggles WHERE key=$1", &[key])
                    .await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn auth_matrix_matches_reviewed_outcomes() -> Result<(), Err> {
    let expect = expected()?;
    let db = Db::for_case("delete-gate-auth").expect("database required");
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let since: String = c
        .query_one("SELECT clock_timestamp()::text", &[])
        .await?
        .get(0);
    let mut saved = Vec::new();
    for key in TOGGLES {
        let v: Option<bool> = c
            .query_opt("SELECT enabled FROM feature_toggles WHERE key=$1", &[&key])
            .await?
            .map(|r| r.get(0));
        saved.push((key.to_string(), v));
    }
    let user = fixture::account(&c, "delete-gate-user").await?;
    c.execute(
        "UPDATE users SET password_hash=$1,mfa_exempt=true WHERE id=$2",
        &[&bcrypt::hash(PASSWORD, 4)?, &user.user],
    )
    .await?;
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&user.user])
        .await?
        .get(0);
    let guest_email = format!(
        "delete-gate-guest-{}@example.test",
        uuid::Uuid::new_v4().simple()
    );
    let guest: i64 = c
        .query_one(
            "INSERT INTO users(username,domain_id,email,display_name,password_hash,mfa_exempt) \
             VALUES($1,(SELECT id FROM domains WHERE name='guest.invalid'),$1,'delete gate guest',$2,true) RETURNING id",
            &[&guest_email, &bcrypt::hash(GUEST_PASSWORD, 4)?],
        )
        .await?
        .get(0);
    c.execute(
        "INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) VALUES($1,$2,'inviter@example.test',$3,'active')",
        &[&guest, &guest_email, &user.domain],
    )
    .await?;
    let hits = Arc::new(AtomicUsize::new(0));
    let (go, fake) = fake_go(hits.clone()).await?;
    let outcome: Result<Vec<String>, Err> = async {
        let mut problems = Vec::new();
        for cell in CELLS {
            for key in TOGGLES {
                set_toggle(&c, key, false).await?;
            }
            let before = hits.load(Ordering::SeqCst);
            let minter = start(&db, [false; 5], go).await?;
            let refresh = mint_refresh(minter.addr, &email).await?;
            minter.close().await;
            if hits.load(Ordering::SeqCst) != before {
                return Err("the all-off mint login reached Go".into());
            }
            match cell.toggles {
                Some(values) => {
                    for (key, on) in TOGGLES.iter().zip(values) {
                        set_toggle(&c, key, on).await?;
                    }
                }
                None => restore(&c, &saved).await?,
            }
            let server = start(&db, cell.threat, go).await?;
            for shape in SHAPES {
                let want = expect[&(cell.name, shape)];
                let before = hits.load(Ordering::SeqCst);
                let (status, _, raw) = send_shape(server.addr, shape, &email, &guest_email, &refresh).await?;
                let hops = hits.load(Ordering::SeqCst) - before;
                let ok = match want {
                    Hop(_) => hops == 1 && status == FAKE_GO_STATUS,
                    Native(code) => hops == 0 && status == code,
                };
                if !ok {
                    problems.push(format!(
                        "cell {} shape {shape}: expected {want:?}, got status {status} with {hops} Go hit(s): {}",
                        cell.name,
                        raw.chars().take(200).collect::<String>()
                    ));
                }
            }
            server.close().await;
        }
        Ok(problems)
    }
    .await;
    restore(&c, &saved).await?;
    c.execute(
        "DELETE FROM auth_event_log WHERE email=ANY($1::text[])",
        &[&vec![email.clone(), guest_email.clone()]],
    )
    .await?;
    c.execute(
        "DELETE FROM login_events WHERE user_id=ANY($1::bigint[]) OR (user_id IS NULL AND source_ip='127.0.0.1' AND occurred_at >= $2::text::timestamptz)",
        &[&vec![user.user, guest], &since],
    )
    .await?;
    c.execute("DELETE FROM guest_accounts WHERE user_id=$1", &[&guest])
        .await?;
    c.execute("DELETE FROM users WHERE id=$1", &[&guest])
        .await?;
    fixture::remove(&c, &user).await?;
    common::restore_receipts(&c, &receipts).await;
    fake.abort();
    let problems = outcome?;
    let hop_cells = expect.values().filter(|o| matches!(o, Hop(_))).count();
    eprintln!(
        "DELETE-GATE-MATRIX auth cells={} shapes={} expected_hop_cells={hop_cells} mismatches={}",
        CELLS.len(),
        SHAPES.len(),
        problems.len()
    );
    assert!(
        problems.is_empty(),
        "{}\nA mismatch is a finding: read the hand-off site in bins/auth/src/lib.rs, then fix the code \
         or get the EXPECT change reviewed. Never copy this output into EXPECT.",
        problems.join("\n")
    );
    Ok(())
}
