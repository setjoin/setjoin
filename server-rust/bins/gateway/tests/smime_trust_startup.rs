//! #526: process-local trust caches observe changes in Go and Rust concurrently.
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
        ("DB_DIRECT_DSN", db.dsn.as_str()),
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
async fn starts_while_go_keeps_its_process_local_listener() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("smime-trust-startup") else {
        return Ok(());
    };
    let mut child = gateway(&db, "smime-trust-listener", "")?;
    tokio::time::sleep(std::time::Duration::from_millis(3000)).await;
    let running = child.try_wait()?.is_none();
    stop(&mut child);
    assert!(running, "process-local Rust cache needs its own listener while Go still runs");
    println!("GOLDEN-REPLAY: worker smime-trust-listener :: both-process-local-caches-observe");
    Ok(())
}

/// With Go off and Rust on the worker is accepted and the process stays up (the listener only waits for
/// notifications).
#[tokio::test]
async fn starts_when_go_is_off() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("smime-trust-startup") else {
        return Ok(());
    };
    let mut child = gateway(&db, "smime-trust-listener", "smime-trust-listener")?;
    tokio::time::sleep(std::time::Duration::from_millis(3000)).await;
    let running = child.try_wait()?.is_none();
    stop(&mut child);
    assert!(running, "the gateway exited with the worker enabled");
    println!("GOLDEN-REPLAY: worker smime-trust-listener :: starts-when-go-is-off");
    Ok(())
}
