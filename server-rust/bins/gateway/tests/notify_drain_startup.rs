//! #408: the executable takes `notify-intent-drain` only once Go's copy is
//! switched off, and with `feature.notify_decouple` ON the events a LISTEN
//! client (the transport under Go's WebSocket/SSE hub) sees come from Rust.
use crate::common::boot::CommandBootExt;
mod common;
use common::BoxError;
use setjoin_conformance::harness::Db;
use std::process::{Command, Stdio};

fn gateway(db: &Db, rust_on: &str, go_off: &str) -> std::io::Result<crate::common::boot::Child> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    command
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in [
        ("GATEWAY_LISTEN", "127.0.0.1:0"),
        ("GATEWAY_ENABLED", "false"),
        // Boot validates the request pool; worker effects still use DB_WORKER_DSN.
        // Use the restricted app role so boot cannot borrow worker authority.
        ("DB_DSN", db.app.as_deref().unwrap_or(&db.dsn)),
        ("DB_WORKER_DSN", db.dsn.as_str()),
        ("RUST_WORKERS_ON", rust_on),
        ("GO_WORKERS_OFF", go_off),
    ] {
        command.env(k, v);
    }
    command.spawn_boot()
}

fn stop(child: &mut crate::common::boot::Child) {
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = child.wait();
}

#[tokio::test]
async fn refuses_without_go_off() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("notify-drain-startup") else {
        return Ok(());
    };
    for (on, off) in [
        ("notify-intent-drain", ""),
        ("notify-intent-drain", "push-intent-drain"),
        ("notify-intent-drain", "notify-intent-drain-other"),
    ] {
        let child = gateway(&db, on, off)?;
        let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await??;
        let err = String::from_utf8_lossy(&out.stderr);
        if out.status.success() || !err.contains("GO_WORKERS_OFF=notify-intent-drain") {
            return Err(
                format!("expected refusal for {off:?}, got {:?}: {err}", out.status).into(),
            );
        }
    }
    println!("GOLDEN-REPLAY: worker notify-intent-drain :: refuses-without-go-off");
    Ok(())
}

/// A LISTEN client sees a decoupled event only because the Rust worker drained
/// the intent; with Rust not enabled the intent stays queued.
#[tokio::test]
async fn decoupled_event_reaches_listeners_through_rust() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("notify-drain-startup") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let channel = "gofree-drain-startup";
    owner
        .batch_execute("DELETE FROM notify_intents; UPDATE feature_toggles SET enabled=true WHERE key='feature.notify_decouple'")
        .await?;
    let mut listener = db.listen(channel).await?;
    // Go's copy off but Rust not enabled: nothing drains.
    let mut idle = gateway(&db, "", "notify-intent-drain")?;
    owner
        .query("SELECT app_notify($1,'decoupled-1')", &[&channel])
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    let queued: i64 = owner
        .query_one(
            "SELECT count(*) FROM notify_intents WHERE channel=$1",
            &[&channel],
        )
        .await?
        .get(0);
    stop(&mut idle);
    let mut child = gateway(&db, "notify-intent-drain", "notify-intent-drain")?;
    let mut seen = Vec::new();
    for _ in 0..60 {
        seen = listener.drain(&owner).await?;
        if !seen.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    stop(&mut child);
    let left: i64 = owner
        .query_one(
            "SELECT count(*) FROM notify_intents WHERE channel=$1",
            &[&channel],
        )
        .await?
        .get(0);
    owner
        .batch_execute("DELETE FROM notify_intents; UPDATE feature_toggles SET enabled=false WHERE key='feature.notify_decouple'")
        .await?;
    assert_eq!(
        queued, 1,
        "without RUST_WORKERS_ON the intent must stay queued"
    );
    assert_eq!(seen, vec!["decoupled-1".to_string()]);
    assert_eq!(left, 0);
    Ok(())
}
