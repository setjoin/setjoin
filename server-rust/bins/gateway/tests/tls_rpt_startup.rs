//! #323: the executable takes `tls-rpt-report` only once Go's copy is switched off.
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
async fn starts_without_go_off() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("tls-rpt-startup") else {
        return Ok(());
    };
    let mut child = gateway(&db, "tls-rpt-report", "")?;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let running = child.try_wait()?.is_none();
    stop(&mut child);
    assert!(running, "tls-rpt-report must start without GO_WORKERS_OFF");
    println!("GOLDEN-REPLAY: worker tls-rpt-report :: starts-without-go-off");
    Ok(())
}

/// With Go off and Rust on the worker is accepted and the process stays up (its first report
/// is ten minutes away, so a seeded yesterday row is untouched).
#[tokio::test]
async fn starts_when_go_is_off() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("tls-rpt-startup") else {
        return Ok(());
    };
    let mut child = gateway(&db, "tls-rpt-report", "tls-rpt-report")?;
    tokio::time::sleep(std::time::Duration::from_millis(3000)).await;
    let running = child.try_wait()?.is_none();
    stop(&mut child);
    assert!(running, "the gateway exited with the worker enabled");
    println!("GOLDEN-REPLAY: worker tls-rpt-report :: starts-when-go-is-off");
    Ok(())
}
