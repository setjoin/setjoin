//! #363: the gateway-listener `/terms/pending` and `/terms/accept` rows forward to the real
//! rust-auth server with no Go upstream configured (a Go hop would answer 503). Expected
//! responses are the Go-recorded identity-token goldens (the same authserver handler sits
//! behind Go's gateway `authProxy`); the 429 body is Go's `coreLimit` capture.
mod common;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::jmap::limit::{EdgeLimit, Limiter, RATE_LIMITED_BODY};
use setjoin_gateway::{Gateway, RouteTable, TrustedProxies};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

type Err = Box<dyn std::error::Error + Send + Sync>;

fn golden(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/identity-token/goldens")
        .join(format!("{name}.json"));
    let document: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    document["observation"]["response"].clone()
}

async fn serve_auth(server: Arc<AuthServer>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (stream, peer) = listener.accept().await.unwrap();
            let server = server.clone();
            tokio::spawn(async move {
                let service =
                    hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
                        let server = server.clone();
                        req.extensions_mut()
                            .insert(setjoin_auth::ConnectionMeta { peer, tls: false });
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                server
                                    .handle(req.map(|b| b.map_err(std::io::Error::other).boxed()))
                                    .await,
                            )
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
    (addr, task)
}

/// The bundled gateway-listener terms rows only; `upstream` (Go) and `auth_upstream` stay unset.
async fn gateway(auth: SocketAddr) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let mut inventory: Value = serde_json::from_str(setjoin_gateway::inventory::BUNDLED).unwrap();
    inventory["routes"].as_array_mut().unwrap().retain(|r| {
        r["listener"] == "gateway" && r["path"].as_str().is_some_and(|p| p.starts_with("/terms/"))
    });
    assert_eq!(inventory["routes"].as_array().unwrap().len(), 2);
    for r in inventory["routes"].as_array().unwrap() {
        assert_eq!(
            (r["state"].as_str(), r["upstream"].as_str()),
            (Some("ON"), Some("rust-auth"))
        );
    }
    let gateway = Gateway::new(
        setjoin_gateway::Config {
            upstream: None,
            upstream_header_timeout: std::time::Duration::from_secs(30),
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            edge_limit: Some(EdgeLimit::for_front_door(Limiter::new(60000, 60))),
        },
        RouteTable::proxy_all(),
    )
    .unwrap()
    .with_inventory(&inventory.to_string())
    .unwrap()
    .with_rust_auth_upstream(format!("http://{auth}").parse().unwrap())
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (addr, tokio::spawn(gateway.serve(listener)))
}

async fn call(
    addr: SocketAddr,
    method: &str,
    path: &str,
    payload: &str,
    headers: &[(&str, &str)],
) -> (u16, Value, String) {
    let client: hyper_util::client::legacy::Client<_, setjoin_auth::Body> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let mut req = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{path}"))
        .header("host", "mail.terms363.test")
        .header("content-type", "application/json");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = client
        .request(req.body(body(payload.to_owned())).unwrap())
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let mut hs = serde_json::Map::new();
    for name in ["content-type", "cache-control", "www-authenticate"] {
        if let Some(v) = resp.headers().get(name) {
            hs.insert(name.into(), json!(v.to_str().unwrap()));
        }
    }
    let raw = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    (status, Value::Object(hs), raw)
}

fn matches_golden(got: &(u16, Value, String), expected: &Value, only: &[&str]) {
    assert_eq!(got.0 as u64, expected["status"].as_u64().unwrap());
    assert_eq!(got.2, expected["body"].as_str().unwrap());
    for name in only {
        assert_eq!(
            got.1.get(*name),
            expected["headers"].get(*name),
            "header {name}"
        );
    }
}

#[tokio::test]
async fn gateway_terms_rows_reach_rust_auth_without_go() -> Result<(), Err> {
    let db = Db::for_case("IDLOGIN3-terms-gateway").expect("database required");
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let actor = fixture::account(&c, "terms363-actor").await?;
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let secret = keys["secret"].as_str().unwrap();
    let mut cfg = Config::for_secret(secret.into());
    cfg.dsn = db.dsn.clone();
    cfg.worker_dsn = Some(db.dsn.clone());
    let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
        .map_err(|e| e.0)?;
    let (auth, auth_task) = serve_auth(Arc::new(AuthServer::load(exec, cfg).await?)).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let token = setjoin_authz::legacy_jwt::sign_hs256(
        secret.as_bytes(),
        &json!({"iss":"mailserver","aud":"mailserver-gateway","uid":actor.user,
            "typ":"access","jti":"terms363","iat":now,"exp":now+3600})
        .to_string(),
    );
    let bearer = format!("Bearer {token}");

    // 401 (pending and accept) and CSRF 403 (accept), each equal to Go's recorded bytes.
    let (addr, gw_task) = gateway(auth).await;
    let bad = [("authorization", "Bearer invalid")];
    let got = call(addr, "GET", "/terms/pending", "", &bad).await;
    matches_golden(
        &got,
        &golden("pending-unauthenticated"),
        &["content-type", "cache-control", "www-authenticate"],
    );
    let got = call(
        addr,
        "POST",
        "/terms/accept",
        "{\"tou_id\":1,\"version\":1}",
        &bad,
    )
    .await;
    matches_golden(
        &got,
        &golden("accept-unauthenticated"),
        &["content-type", "cache-control", "www-authenticate"],
    );
    let got = call(
        addr,
        "POST",
        "/terms/accept",
        "{\"tou_id\":1,\"version\":1}",
        &[
            ("authorization", bearer.as_str()),
            ("origin", "https://evil.test"),
        ],
    )
    .await;
    matches_golden(&got, &golden("accept-csrf"), &["content-type"]);
    // A valid session reaches the native handler: Go's pending list for an account with no
    // enabled documents is a 200 (never the 503 an unset Go upstream would answer).
    let got = call(
        addr,
        "GET",
        "/terms/pending",
        "",
        &[("authorization", bearer.as_str())],
    )
    .await;
    assert_eq!(got.0, 200, "{}", got.2);
    gw_task.abort();

    // authLimit: Go's default budget is 20 per 15 minutes per client IP; the 21st is Go's 429.
    let (addr, gw_task) = gateway(auth).await;
    for i in 0..20 {
        let got = call(addr, "GET", "/terms/pending", "", &bad).await;
        assert_eq!(got.0, 401, "request {i}");
    }
    let got = call(addr, "GET", "/terms/pending", "", &bad).await;
    assert_eq!(got.0, 429);
    assert_eq!(got.2, RATE_LIMITED_BODY);
    assert_eq!(got.1["content-type"], "application/problem+json");
    assert_eq!(got.1["cache-control"], "no-store");
    gw_task.abort();

    auth_task.abort();
    fixture::remove(&c, &actor).await?;
    Ok(())
}
