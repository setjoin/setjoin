//! Fake upstream and a gateway launcher for the black-box proxy tests.
//!
//! The fake upstream is a plain hyper server whose behaviour per request is a
//! test-supplied closure; the gateway under test is the real
//! `setjoin_gateway::Gateway` bound to an ephemeral loopback port.
#![allow(dead_code)]

pub mod approval_admin;
pub mod approvals;
pub mod boot;
pub mod commit;
pub mod go_oracle;
pub mod golden;
pub mod problem_bytes;
pub mod recovery;
pub mod s3;
pub mod webhook_receiver;

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use tokio::net::TcpListener;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The identity source rows and `feature.identity_*` toggles as a case found them. The AD and
/// LDAP oracles force a paused baseline for their own cases; they must hand the global rows
/// back (the seeded `legacy:ad` is active), or every later suite sees a polluted inventory (#421).
pub async fn identity_baseline_save(
    c: &tokio_postgres::Client,
) -> Result<(String, String), BoxError> {
    let sources: String = c
        .query_one("SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb)::text FROM identity_sources s WHERE source_key LIKE 'legacy:%'", &[])
        .await?
        .get(0);
    let toggles: String = c
        .query_one("SELECT coalesce(jsonb_agg(jsonb_build_object('key',key,'enabled',enabled)),'[]'::jsonb)::text FROM feature_toggles WHERE key LIKE 'feature.identity%'", &[])
        .await?
        .get(0);
    Ok((sources, toggles))
}

pub async fn identity_baseline_restore(
    c: &tokio_postgres::Client,
    saved: &(String, String),
) -> Result<(), BoxError> {
    c.execute(
        "UPDATE identity_sources s SET state=r.state, committed_cursor=r.committed_cursor, committed_cursor_digest=r.committed_cursor_digest, \
         pending_cursor=r.pending_cursor, pending_cursor_digest=r.pending_cursor_digest, last_success_at=r.last_success_at, \
         last_failure_at=r.last_failure_at, last_error_code=r.last_error_code \
         FROM jsonb_populate_recordset(NULL::identity_sources, $1::text::jsonb) r WHERE s.id=r.id",
        &[&saved.0],
    )
    .await?;
    c.execute(
        "UPDATE feature_toggles t SET enabled=(j->>'enabled')::boolean FROM jsonb_array_elements($1::text::jsonb) j WHERE t.key=j->>'key'",
        &[&saved.1],
    )
    .await?;
    Ok(())
}

/// A request executor whose pool/statement deadlines survive a CPU-starved shared host.
/// The adapters' default 1 s pool wait / 2 s statement deadline forwards the request
/// to Go on a loaded host and masquerades as a parity failure (#368, #421). Only the
/// deadlines are widened; every assertion is unchanged.
pub fn patient_exec(dsn: &str, size: usize) -> Result<setjoin_pg::ScopedExecutor, BoxError> {
    let patient = std::time::Duration::from_secs(30);
    Ok(setjoin_pg::ScopedExecutor::from_dsn_with(
        dsn,
        size,
        setjoin_pg::Timeouts {
            pool_wait: patient,
            create: patient,
            statement: patient,
        },
    )
    .map_err(|e| e.0)?)
}

/// Delete only this committed oracle fixture. Release message-partition locks
/// before removing its mailbox/user pair. Those two stay in one transaction
/// because primary-mailbox enforcement is deferred until commit.
pub async fn remove_blob_account(
    owner: &tokio_postgres::Client,
    account: &setjoin_conformance::fixture::Account,
) -> Result<(), BoxError> {
    // Match the conformance harness's narrowly scoped append-only audit cleanup.
    owner
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role=replica; \
         DELETE FROM mailbox_audit_log WHERE mailbox_id={}; COMMIT;",
            account.mailbox
        ))
        .await?;
    owner
        .execute(
            "DELETE FROM messages WHERE mailbox_id=$1",
            &[&account.mailbox],
        )
        .await?;
    owner
        .batch_execute(&format!(
            "DELETE FROM message_trace WHERE details->>'mailbox_id'='{}'",
            account.mailbox
        ))
        .await?;
    owner
        .batch_execute(&format!(
            "BEGIN; DELETE FROM mailboxes WHERE id={}; DELETE FROM users WHERE id={}; COMMIT;",
            account.mailbox, account.user
        ))
        .await?;
    owner
        .execute("DELETE FROM domains WHERE id=$1", &[&account.domain])
        .await?;
    Ok(())
}

pub type TestBody = BoxBody<Bytes, BoxError>;
type Handler = Arc<
    dyn Fn(Request<Incoming>) -> Pin<Box<dyn Future<Output = Response<TestBody>> + Send>>
        + Send
        + Sync,
>;

pub fn full(bytes: impl Into<Bytes>) -> TestBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Starts a fake upstream that answers every request with `handler`.
pub async fn fake_upstream<F, Fut>(handler: F) -> SocketAddr
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response<TestBody>> + Send + 'static,
{
    let handler: Handler = Arc::new(move |req| Box::pin(handler(req)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let handler = handler.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let handler = handler.clone();
                    async move { Ok::<_, Infallible>(handler(req).await) }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .with_upgrades()
                    .await;
            });
        }
    });
    addr
}

/// Starts the real gateway in front of `upstream`.
pub async fn gateway(upstream: SocketAddr, trusted: &str, routes: RouteTable) -> SocketAddr {
    gateway_with(
        upstream,
        trusted,
        routes,
        setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
    )
    .await
}

/// [`gateway`] with an explicit upstream response-header timeout.
pub async fn gateway_with(
    upstream: SocketAddr,
    trusted: &str,
    routes: RouteTable,
    header_timeout: std::time::Duration,
) -> SocketAddr {
    let config = Config {
        upstream: Some(format!("http://{upstream}").parse().unwrap()),
        trusted_proxies: TrustedProxies::parse(trusted).unwrap(),
        upstream_header_timeout: header_timeout,
        edge_limit: None,
    };
    start(config, routes).await
}

/// [`gateway`] with the front-door core budget a Rust route installs.
pub async fn gateway_limited(
    upstream: SocketAddr,
    routes: RouteTable,
    limit: setjoin_gateway::jmap::limit::EdgeLimit,
) -> SocketAddr {
    let config = Config {
        upstream: Some(format!("http://{upstream}").parse().unwrap()),
        trusted_proxies: TrustedProxies::parse("").unwrap(),
        upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
        edge_limit: Some(limit),
    };
    start(config, routes).await
}

async fn start(config: Config, routes: RouteTable) -> SocketAddr {
    let gateway = Gateway::new(config, routes).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(gateway.serve(listener));
    addr
}

/// Sends one request through a fresh client connection and returns the
/// response with its streaming body.
pub async fn send(addr: SocketAddr, req: Request<TestBody>) -> Response<Incoming> {
    within(async move { send_inner(addr, req).await }).await
}

/// Fails the test instead of hanging when the gateway stalls. A guard against a hang,
/// not a latency assertion: generous enough for a CPU-starved shared host.
pub async fn within<T>(fut: impl Future<Output = T>) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(60), fut)
        .await
        .expect("gateway test step timed out")
}

async fn send_inner(addr: SocketAddr, req: Request<TestBody>) -> Response<Incoming> {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender.send_request(req).await.unwrap()
}

/// Unchecked read, for bodies a fake Go upstream replays (not Rust-written).
pub async fn body_bytes_unchecked(resp: Response<Incoming>) -> Bytes {
    resp.into_body().collect().await.unwrap().to_bytes()
}

pub async fn body_bytes(resp: Response<Incoming>) -> Bytes {
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    problem_bytes::check_if_problem(content_type.as_deref(), &bytes);
    bytes
}

/// What the edge limit's "is any Rust route serving" read answers.
#[derive(Clone, Copy, Debug)]
pub enum Flags {
    On,
    Off,
    /// Never answers (a stalled database).
    Stalled,
    /// The read failed: fail closed, i.e. OFF.
    Failed,
}

/// An edge budget of `limit` per hour whose flag read answers `flags`.
pub fn edge(limit: u64, flags: Flags) -> setjoin_gateway::jmap::limit::EdgeLimit {
    use setjoin_gateway::jmap::limit::{EdgeLimit, Limiter};
    EdgeLimit::new(
        Limiter::new(limit, 3600),
        Arc::new(move || -> setjoin_gateway::BoxFuture<bool> {
            Box::pin(async move {
                match flags {
                    Flags::On => true,
                    Flags::Off | Flags::Failed => false,
                    Flags::Stalled => std::future::pending().await,
                }
            })
        }),
    )
}

/// Public fixture key accepted by the covered Go HTTP recorder as well.
pub fn recovery_keys() -> setjoin_gateway::jmap::jwks::Jwks {
    use setjoin_gateway::jmap::jwks::Jwks;
    let doc = include_bytes!("../../../../tests/conformance/jmap/test-jwks.json");
    Jwks::with_fetch(Box::new(move || Box::pin(async move { Ok(doc.to_vec()) })))
}

pub fn recovery_token(user: i64) -> String {
    recovery_token_with(user, serde_json::json!({}))
}

/// A recovery access token whose claims also carry the members of `extra` (e.g. `device`).
pub fn recovery_token_with(user: i64, extra: serde_json::Value) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    use serde_json::json;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let header =
        URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","kid":"test-es256-1","typ":"JWT"}).to_string());
    let mut claims = json!({"uid":user,"email":"x@test","typ":"access","jti":"blobs1-test","fam":"blobs1-test","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600});
    if let (Some(map), Some(more)) = (claims.as_object_mut(), extra.as_object()) {
        map.extend(more.clone());
    }
    let claims = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{header}.{claims}").as_bytes());
    format!(
        "{header}.{claims}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

pub mod approval_submit;

pub mod approval_notify;

pub mod approval_probe;

/// Owner-approved security fixes (2026-11-05): a frozen-Go baseline replaced by a
/// reviewed expectation pinned (path, sha256, reason) in the family's divergences.json.
/// `SECFIX3_WRITE_SECURITY=1` writes the expectation from the actual document for
/// review against the baseline diff; it is never used in CI, and a run that does so always
/// fails (the returned document cannot equal any replay).
#[allow(dead_code)]
pub fn security_expected(
    family: &std::path::Path,
    baseline: &std::path::Path,
    actual: &serde_json::Value,
) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    if std::env::var_os("SECFIX3_WRITE_SECURITY").is_some() {
        std::fs::create_dir_all(family.join("security")).unwrap();
        let text = format!("{}\n", serde_json::to_string_pretty(actual).unwrap());
        std::fs::write(
            family.join("security").join(baseline.file_name().unwrap()),
            text,
        )
        .unwrap();
        // Regenerating must never pass silently: hand back a document no replay can equal, so
        // the run fails (review the written diff, then rerun without the variable).
        return serde_json::json!({"REGENERATED": "SECFIX3_WRITE_SECURITY wrote this expectation: review the diff and rerun without it"});
    }
    let entries: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(family.join("divergences.json")).unwrap())
            .unwrap();
    let relative = baseline.strip_prefix(family).unwrap().to_str().unwrap();
    let entry = entries
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["baseline"] == relative)
        .expect("reviewed security divergence");
    assert_eq!(entry["reviewed"], true);
    assert!(["2026-11-05", "2026-11-06", "2026-11-07"]
        .iter()
        .any(|day| entry["reason"]
            .as_str()
            .unwrap()
            .contains(&format!("owner-approved security fix {day}"))));
    assert_eq!(
        entry["sha256"],
        format!("{:x}", Sha256::digest(std::fs::read(baseline).unwrap()))
    );
    serde_json::from_str(
        &std::fs::read_to_string(family.join(entry["expectation"].as_str().unwrap())).unwrap(),
    )
    .unwrap()
}

/// The document a replay compares with. A baseline pinned in its family's divergences.json
/// (an owner-approved security fix) is compared against the reviewed expectation under
/// `security/`; every other golden stays the immutable frozen-Go recording. `key` is
/// `observation` (response, effects, audit) or `effects` (row-effects file) and `actual`
/// the value the run produced (written out only with `SECFIX3_WRITE_SECURITY=1`).
#[allow(dead_code)]
pub fn is_pinned(baseline: &std::path::Path) -> bool {
    let family = baseline.parent().unwrap().parent().unwrap();
    let relative = baseline.strip_prefix(family).unwrap().to_str().unwrap();
    std::fs::read_to_string(family.join("divergences.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .is_some_and(|entries| {
            entries
                .as_array()
                .is_some_and(|a| a.iter().any(|e| e["baseline"] == relative))
        })
}

#[allow(dead_code)]
pub fn golden_doc(
    baseline: &std::path::Path,
    key: &str,
    actual: &serde_json::Value,
) -> serde_json::Value {
    let family = baseline.parent().unwrap().parent().unwrap();
    let pinned = is_pinned(baseline);
    if pinned {
        let stem = baseline.file_stem().unwrap().to_str().unwrap();
        let mut doc = serde_json::json!({"format": 1, "case": stem});
        doc[key] = actual.clone();
        return security_expected(family, baseline, &doc);
    }
    serde_json::from_slice(&std::fs::read(baseline).unwrap()).unwrap()
}
