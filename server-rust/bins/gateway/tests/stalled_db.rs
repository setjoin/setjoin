//! Review item 1: a stalled database makes the `/jmap` route fail closed
//! quickly — the request is forwarded to Go within a bound — and requests
//! the route never claims do not wait on the database at all. The database
//! here is a black hole (accepts TCP, never answers), so no schema is needed.
mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use common::{body_bytes, fake_upstream, full, send};
use hyper::{Request, Response};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::SigningKey;
use serde_json::json;
use setjoin_gateway::jmap::jwks::{jwk, Jwks};
use setjoin_gateway::jmap::token::VerifyingKey;
use setjoin_gateway::jmap::{JmapCommands, JmapRoute};
use setjoin_gateway::RouteTable;
use setjoin_pg::ScopedExecutor;
use tokio::net::TcpListener;

async fn black_hole() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    addr
}

const SEEN: &str = r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"1","update":{"11":{"keywords":{"$seen":true}}}},"0"]]}"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_database_forwards_to_go_within_the_bound() {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let upstream = fake_upstream(move |_req| {
        counter.fetch_add(1, Ordering::SeqCst);
        async {
            Response::builder()
                .status(299)
                .body(full("from go"))
                .unwrap()
        }
    })
    .await;
    let db = black_hole().await;
    // Production defaults: the route must not need tuned test values.
    let exec = ScopedExecutor::from_dsn(
        &format!(
            "host={} port={} user=x password=y dbname=z",
            db.ip(),
            db.port()
        ),
        2,
    )
    .unwrap();
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let pub_key =
        VerifyingKey::from_sec1(key.verifying_key().to_sec1_point(false).as_bytes()).unwrap();
    let jwks_doc = json!({ "keys": [jwk("stalled-1", &pub_key)] })
        .to_string()
        .into_bytes();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let h = URL_SAFE_NO_PAD
        .encode(json!({"alg": "ES256", "kid": "stalled-1", "typ": "JWT"}).to_string());
    let p = URL_SAFE_NO_PAD.encode(
        json!({
            "uid": 1, "email": "x@test", "typ": "access", "jti": "stalled-jti",
            "fam": "stalled-fam", "iss": "mailserver", "aud": ["mailserver-gateway"],
            "iat": now - 10, "exp": now + 600,
        })
        .to_string(),
    );
    let sig: p256::ecdsa::Signature = key.sign(format!("{h}.{p}").as_bytes());
    let token = format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));

    let route = JmapRoute(Arc::new(JmapCommands {
        services: None,
        worker: None,
        denylist: None,
        exec,
        keys: Jwks::with_fetch(Box::new(move || {
            let doc = jwks_doc.clone();
            Box::pin(async move { Ok(doc) })
        })),
        issuer: "mailserver".into(),
    }));
    let gw = common::gateway(upstream, "", RouteTable::proxy_all().with(route)).await;

    // Unauthenticated POST /jmap denies natively with 401 before hitting the DB or Go.
    let t = Instant::now();
    let resp = send(
        gw,
        Request::post("/jmap")
            .header("host", "mail.test")
            .body(full(SEEN))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 401);
    assert!(t.elapsed() < Duration::from_millis(500));

    // Authenticated claimed shape: security read stalls, fails closed natively (503) within bound.
    let t = Instant::now();
    let resp = send(
        gw,
        Request::post("/jmap")
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("authorization", format!("Bearer {token}"))
            .body(full(SEEN))
            .unwrap(),
    )
    .await;
    let took = t.elapsed();
    assert_eq!(resp.status().as_u16(), 503);
    assert!(
        took < Duration::from_secs(3),
        "claimed request took {took:?}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    // Non-JMAP path: no database wait at all, forwards directly to Go.
    let t = Instant::now();
    let resp = send(
        gw,
        Request::post("/api/other")
            .header("host", "mail.test")
            .body(full(""))
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 299);
    assert_eq!(&body_bytes(resp).await[..], b"from go");
    assert!(t.elapsed() < Duration::from_millis(500));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}
