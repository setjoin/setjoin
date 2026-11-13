//! #298: the executable takes `calendar-subscription-sync` only once Go's copy is switched off.
use crate::common::boot::CommandBootExt;
mod common;
use common::BoxError;
use setjoin_conformance::harness::Db;
use std::process::{Command, Stdio};

fn gateway(db: &Db, go_off: bool) -> std::io::Result<crate::common::boot::Child> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    command
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in [
        ("GATEWAY_LISTEN", "127.0.0.1:0"),
        ("GATEWAY_ENABLED", "false"),
        ("DB_DSN", db.dsn.as_str()),
        ("RUST_WORKERS_ON", "calendar-subscription-sync"),
    ] {
        command.env(k, v);
    }
    if go_off {
        command.env("GO_WORKERS_OFF", "calendar-subscription-sync");
    }
    command.spawn_boot()
}

#[tokio::test]
async fn refuses_without_go_off() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("calendar-subscription-sync-startup") else {
        return Ok(());
    };
    let child = gateway(&db, false)?;
    let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await??;
    let err = String::from_utf8_lossy(&out.stderr);
    if out.status.success() || !err.contains("GO_WORKERS_OFF=calendar-subscription-sync") {
        return Err(format!("expected refusal, got {:?}: {err}", out.status).into());
    }
    println!("GOLDEN-REPLAY: worker calendar-subscription-sync :: refuses-without-go-off");
    Ok(())
}

#[tokio::test]
async fn runs_once_go_is_off() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("calendar-subscription-sync-startup") else {
        return Ok(());
    };
    let mut child = gateway(&db, true)?;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let alive = child.try_wait()?.is_none();
    let _ = child.kill();
    let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await??;
    if !alive {
        return Err(format!("gateway exited: {}", String::from_utf8_lossy(&out.stderr)).into());
    }
    println!("GOLDEN-REPLAY: worker calendar-subscription-sync :: runs-once-go-is-off");
    Ok(())
}
