//! #457: `auth.login` / `auth.login_failed` from the Rust IMAP server. Frozen Go's real IMAP
//! server and Dispatcher (overlay `tests/conformance/drain/imap_auth_webhooks_tick_test.go.txt`)
//! play recorded corpus sessions against fake receivers; the Rust server, wired through the
//! gateway's `AuthEvents` sink, plays the same sessions and must deliver the same requests
//! (path, signature, exact body) and leave the same delivery rows. The session scripts and
//! seed are the #343 corpus (`crates/protocols/imap/oracle`).
//! Record: `GOFREE_RECORD_DRAIN=all GOFREE_GO_SOURCE=<sha>`; replay needs no Go.
mod common;
mod drain_oracle;
use common::webhook_receiver::{self as hooks, Seen};
use drain_oracle::{settle, BoxError, GoTick};
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::imap_runtime::AuthEvents;
use setjoin_imap::{Server, ThreatPolicy, WebhookPolicy};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
};

const SESSIONS: [&str; 8] = [
    "login-failures",
    "login-success-forms",
    "login-argument-quirks",
    "login-denials",
    "app-passwords",
    "app-password-authenticate",
    "authenticate-forms",
    "authenticate-authzid-ignored",
];
const ORACLE: &str = "../../crates/protocols/imap/oracle";

/// Plays one recorded session's requests against the Rust server and drains its responses.
async fn play(server: Server, session: &Value) -> Result<(), BoxError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::new(server).serve(listener, rx));
    let mut conns: Vec<Option<TcpStream>> = Vec::new();
    for step in session["steps"].as_array().ok_or("steps")? {
        if let Some(ms) = step["sleep_ms"].as_u64() {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
        let idx = step["conn"].as_u64().unwrap_or(0) as usize;
        while conns.len() <= idx {
            conns.push(None);
        }
        if conns[idx].is_none() {
            conns[idx] = Some(TcpStream::connect(addr).await?);
        }
        let stream = conns[idx].as_mut().unwrap();
        let request = step["request"].as_str().unwrap_or_default();
        if !request.is_empty() {
            let _ = stream.write_all(request.as_bytes()).await;
        }
        let want = step["response"].as_str().unwrap_or_default().len();
        let wait = match step["until"].as_str().unwrap_or_default() {
            "eof" | "none" => Duration::from_millis(1500),
            _ => Duration::from_secs(5),
        };
        let deadline = tokio::time::Instant::now() + wait;
        let (mut got, mut chunk) = (0, [0u8; 8192]);
        while got < want {
            match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => got += n,
            }
        }
    }
    drop(conns);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = stop.send(true);
    let _ = task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_auth_webhooks() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("imap-auth-webhooks") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let oracle = |name: &str| format!("{}/{ORACLE}/{name}", env!("CARGO_MANIFEST_DIR"));
    let read = |name: &str| std::fs::read_to_string(oracle(name));
    let recording = std::env::var_os("GOFREE_RECORD_DRAIN").is_some();
    owner.batch_execute(&read("cleanup.sql")?).await?;
    owner.batch_execute(&read("seed.sql")?).await?;
    let corpus: Value = serde_json::from_str(&read("go-sessions.json")?)?;
    let hashes: Value = serde_json::from_str(&read("password-hashes.json")?)?;
    let seen: Seen = Seen::default();
    let hook = hooks::receiver(seen.clone()).await;
    let result = async {
        let mut observation = serde_json::Map::new();
        for name in SESSIONS {
            let session = corpus
                .as_array()
                .and_then(|all| all.iter().find(|s| s["name"] == name))
                .ok_or(format!("session {name} is not in the corpus"))?;
            owner.batch_execute(
                "DELETE FROM auth_event_log WHERE user_id BETWEEN 9343011 AND 9343019 OR email LIKE '%@imap1.test';
                 UPDATE app_passwords SET last_used_at = NULL WHERE user_id BETWEEN 9343011 AND 9343019;
                 UPDATE users SET last_login_at = NULL WHERE id BETWEEN 9343011 AND 9343019;",
            ).await?;
            for (id, key) in [(None, "standard"), (Some(9343017i64), "low"), (Some(9343019), "spaced")] {
                let hash = hashes[key].as_str().ok_or("hash")?;
                match id {
                    None => owner.execute("UPDATE users SET password_hash=$1 WHERE id BETWEEN 9343011 AND 9343019", &[&hash]).await?,
                    Some(id) => owner.execute("UPDATE users SET password_hash=$1 WHERE id=$2", &[&hash, &id]).await?,
                };
            }
            hooks::clear(&owner).await?;
            for (path, scope, active, types) in [
                ("/auth", "organization", true, r#"["auth.login","auth.login_failed"]"#),
                ("/failed", "organization", true, r#"["auth.login_failed"]"#),
                ("/self", "self", true, r#"["auth.login","auth.login_failed"]"#),
                ("/inactive", "organization", false, r#"["auth.login","auth.login_failed"]"#),
            ] {
                hooks::subscribe(&owner, 9343011, hook, path, types, scope, active).await?;
            }
            seen.lock().unwrap().clear();
            let dispatcher = hooks::unguarded(&db.dsn)?;
            if recording {
                GoTick {
                    package: "internal/imap",
                    overlay: "imap_auth_webhooks_tick_test.go.txt",
                    test: "TestGoFreeIMAPAuthWebhooks",
                    file: "gofree_imap_auth_webhooks_test.go",
                    env: vec![
                        ("GOFREE_DRAIN_DSN".into(), db.dsn.clone()),
                        ("DB_APP_DSN".into(), db.app.clone().unwrap_or_else(|| db.dsn.clone())),
                        ("GOFREE_WEBHOOK_MASTER".into(), hooks::MASTER.into()),
                        ("GOFREE_IMAP_SESSION".into(), name.into()),
                        ("IMAP_ORACLE_DIR".into(), "/src/server-rust/crates/protocols/imap/oracle".into()),
                    ],
                    docker: vec![],
                }
                .run_with(&[("internal/webhook", "gofree_unguarded_export.go", "webhook_unguarded_export.go.txt")])?;
            } else {
                let executor = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).map_err(|e| e.0)?;
                let server = Server::new(
                    executor,
                    ThreatPolicy::Unwired,
                    WebhookPolicy::Wired(Arc::new(AuthEvents(dispatcher.clone()))),
                );
                assert!(server.webhooks_wired());
                play(server, session).await?;
            }
            dispatcher.shutdown().await;
            observation.insert(name.into(), json!({
                "deliveries": hooks::deliveries(&owner).await?,
                "requests": hooks::requests(&seen),
            }));
        }
        settle("imap-auth-webhooks", Value::Object(observation), recording)
    }
    .await;
    let _ = hooks::clear(&owner).await;
    owner.batch_execute(&read("cleanup.sql")?).await?;
    result
}
