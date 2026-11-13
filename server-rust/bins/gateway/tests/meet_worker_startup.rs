//! #410: the executable takes `meet-reconcile` only once Go's copy is switched
//! off (`GO_WORKERS_OFF=meet-reconcile`), and then keeps running until stopped.
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
        ("S3_ENDPOINT", "http://127.0.0.1:1"),
        ("S3_BUCKET", "mailblobs"),
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
    let Some(db) = Db::for_case("meet-worker-startup") else {
        return Ok(());
    };
    for (on, off) in [
        ("meet-reconcile", ""),
        ("meet-reconcile", "guest-lifecycle"),
        ("meet-reconcile", "meet-reconcile-other"),
    ] {
        let child = gateway(&db, on, off)?;
        let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await??;
        let err = String::from_utf8_lossy(&out.stderr);
        if out.status.success() || !err.contains("GO_WORKERS_OFF=meet-reconcile") {
            return Err(
                format!("expected refusal for {off:?}, got {:?}: {err}", out.status).into(),
            );
        }
    }
    println!("GOLDEN-REPLAY: worker meet-reconcile :: refuses-without-go-off");
    Ok(())
}

#[tokio::test]
async fn starts_with_go_off_and_stops_on_signal() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("meet-worker-startup") else {
        return Ok(());
    };
    let mut child = gateway(&db, "meet-reconcile", "meet-reconcile")?;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let running = child.try_wait()?.is_none();
    stop(&mut child);
    assert!(
        running,
        "the worker must keep the process running once admitted"
    );
    Ok(())
}
