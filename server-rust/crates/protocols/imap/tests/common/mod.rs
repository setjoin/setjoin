//! Shared fixtures: server construction, TLS peers and effect snapshots.
#![allow(dead_code)]
use setjoin_imap::{Server, ThreatPolicy, WebhookPolicy};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_postgres::Client;
use tokio_rustls::rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
    ClientConfig, RootCertStore, ServerConfig,
};

pub fn tls_server() -> Arc<ServerConfig> {
    let cert = CertificateDer::pem_slice_iter(include_bytes!(
        "../../../../../tests/conformance/directory-sync/ldap-fixture/server.pem"
    ))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!(
        "../../../../../tests/conformance/directory-sync/ldap-fixture/server.p8"
    ))
    .unwrap();
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert, key)
            .unwrap(),
    )
}

pub async fn tls_client(socket: TcpStream) -> tokio_rustls::client::TlsStream<TcpStream> {
    let ca = CertificateDer::from_pem_slice(include_bytes!(
        "../../../../../tests/conformance/directory-sync/ldap-fixture/ca.pem"
    ))
    .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca).unwrap();
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), socket)
        .await
        .unwrap()
}

pub fn executor(db: &setjoin_conformance::harness::Db) -> setjoin_pg::ScopedExecutor {
    setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap()
}

pub fn server(db: &setjoin_conformance::harness::Db, transport: &str) -> Server {
    let server = Server::new(executor(db), ThreatPolicy::Unwired, WebhookPolicy::Unwired);
    match transport {
        "starttls" => server.with_starttls(tls_server()),
        "tls" => server.with_tls(tls_server()),
        _ => server,
    }
}

/// Every case reseeds and cleans the same fixed `imap1.test` rows, so cases take turns.
/// The turn is held by the test's own thread (a `#[tokio::test]` runtime runs on it)
/// until that thread ends, which spans the case's closing cleanup too.
pub async fn serial() {
    static TURN: std::sync::OnceLock<Arc<tokio::sync::Mutex<()>>> = std::sync::OnceLock::new();
    thread_local! {
        static HELD: std::cell::RefCell<Option<tokio::sync::OwnedMutexGuard<()>>> =
            const { std::cell::RefCell::new(None) };
    }
    if HELD.with(|h| h.borrow().is_some()) {
        return;
    }
    let turn = TURN
        .get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let guard = turn.lock_owned().await;
    HELD.with(|h| *h.borrow_mut() = Some(guard));
}

pub async fn seed(owner: &Client) {
    serial().await;
    owner
        .batch_execute(include_str!("../../oracle/cleanup.sql"))
        .await
        .unwrap();
    owner
        .batch_execute(include_str!("../../oracle/seed.sql"))
        .await
        .unwrap();
}

pub async fn reset_fixture(owner: &Client, hashes: &serde_json::Value) {
    owner
        .batch_execute(
            "DELETE FROM auth_event_log WHERE user_id BETWEEN 9343011 AND 9343019 OR email LIKE '%@imap1.test';
             UPDATE app_passwords SET last_used_at = NULL WHERE user_id BETWEEN 9343011 AND 9343019;
             UPDATE users SET last_login_at = NULL WHERE id BETWEEN 9343011 AND 9343019;",
        )
        .await
        .unwrap();
    let (standard, low) = (
        hashes["standard"].as_str().unwrap(),
        hashes["low"].as_str().unwrap(),
    );
    owner
        .execute(
            "UPDATE users SET password_hash=$1 WHERE id BETWEEN 9343011 AND 9343019",
            &[&standard],
        )
        .await
        .unwrap();
    owner
        .execute(
            "UPDATE users SET password_hash=$1 WHERE id=9343017",
            &[&low],
        )
        .await
        .unwrap();
    let spaced = hashes["spaced"].as_str().unwrap();
    owner
        .execute(
            "UPDATE users SET password_hash=$1 WHERE id=9343019",
            &[&spaced],
        )
        .await
        .unwrap();
}

pub async fn events(owner: &Client) -> Vec<serde_json::Value> {
    owner
        .query(
            "SELECT user_id, event, provider, email, host(ip_address) FROM auth_event_log \
             WHERE user_id BETWEEN 9343011 AND 9343019 OR email LIKE '%@imap1.test' ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| {
            serde_json::json!({
                "user": r.get::<_, Option<i64>>(0), "event": r.get::<_, String>(1),
                "provider": r.get::<_, String>(2), "email": r.get::<_, Option<String>>(3),
                "ip": r.get::<_, Option<String>>(4),
            })
        })
        .collect()
}

/// Compare the recorded effects: audit rows in order, app-password and
/// last-login bookkeeping, and which password hashes changed.
pub async fn assert_effects(
    owner: &Client,
    session: &serde_json::Value,
    hashes: &serde_json::Value,
    name: &str,
) {
    let want = &session["effects"];
    assert_eq!(
        serde_json::Value::Array(events(owner).await),
        want["auth_events"],
        "{name}: auth_event_log"
    );
    let used: Vec<String> = owner
        .query(
            "SELECT name FROM app_passwords WHERE last_used_at IS NOT NULL ORDER BY name",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(
        serde_json::json!(used),
        want["app_passwords_used"],
        "{name}: app passwords"
    );
    let logged: Vec<i64> = owner
        .query(
            "SELECT id FROM users WHERE last_login_at IS NOT NULL AND id BETWEEN 9343011 AND 9343019 ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(
        serde_json::json!(logged),
        want["last_login"],
        "{name}: last_login_at"
    );
    let standard = hashes["standard"].as_str().unwrap();
    let low = hashes["low"].as_str().unwrap();
    let rehashed: Vec<i64> = owner
        .query(
            "SELECT id, password_hash FROM users WHERE id BETWEEN 9343011 AND 9343019 ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .filter(|r| {
            let before = match r.get::<_, i64>(0) {
                9343017 => low,
                9343019 => hashes["spaced"].as_str().unwrap(),
                _ => standard,
            };
            r.get::<_, String>(1) != before
        })
        .map(|r| r.get(0))
        .collect();
    assert_eq!(
        serde_json::json!(rehashed),
        want["rehashed"],
        "{name}: rehashed"
    );
}
