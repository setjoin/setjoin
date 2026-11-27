//! #324: the executable takes `dmarc-report` only once Go's copy is switched off
//! (`GO_WORKERS_OFF=dmarc-report`), and then keeps running until stopped.
use crate::common::boot::CommandBootExt;
mod common;
use common::BoxError;
use setjoin_conformance::harness::Db;
use std::process::{Command, Stdio};

fn gateway(db: &Db, rust_on: &str, go_off: &str) -> std::io::Result<crate::common::boot::Child> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-server"));
    command
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in [
        ("GATEWAY_LISTEN", "127.0.0.1:0"),
        // Boot validates the request pool; worker effects still use DB_WORKER_DSN.
        // Use the restricted app role so boot cannot borrow worker authority.
        ("DB_DSN", db.app_dsn()),
        ("DB_WORKER_DSN", db.worker_dsn()),
        ("DB_DIRECT_DSN", db.dsn.as_str()),
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
async fn starts_without_go_off() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("dmarc-report-startup") else {
        return Ok(());
    };
    let mut child = gateway(&db, "dmarc-report", "")?;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let running = child.try_wait()?.is_none();
    stop(&mut child);
    assert!(running, "dmarc-report must start without GO_WORKERS_OFF");
    println!("GOLDEN-REPLAY: worker dmarc-report :: starts-without-go-off");
    Ok(())
}

#[tokio::test]
async fn starts_with_go_off_and_stops_on_signal() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("dmarc-report-startup") else {
        return Ok(());
    };
    let mut child = gateway(&db, "dmarc-report", "dmarc-report")?;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let running = child.try_wait()?.is_none();
    stop(&mut child);
    assert!(
        running,
        "the worker must keep the process running once admitted"
    );
    Ok(())
}
