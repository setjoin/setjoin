//! #276: the executable only takes `drive-watch` once Go's copy is switched off.
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
    let direct = format!(
        "{}{}application_name=gofree-drive4-startup",
        db.dsn,
        if db.dsn.contains('?') { "&" } else { "?" }
    );
    for (k, v) in [
        ("GATEWAY_LISTEN", "127.0.0.1:0"),
        ("GATEWAY_ENABLED", "false"),
        ("DB_DSN", db.dsn.as_str()),
        ("DB_DIRECT_DSN", direct.as_str()),
        ("RUST_WORKERS_ON", "drive-watch"),
    ] {
        command.env(k, v);
    }
    if go_off {
        command.env("GO_WORKERS_OFF", "drive-watch");
    }
    command.spawn_boot()
}

#[tokio::test]
async fn refuses_without_go_off() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("drive-watch-startup") else {
        return Ok(());
    };
    let child = gateway(&db, false)?;
    let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await??;
    let err = String::from_utf8_lossy(&out.stderr);
    if out.status.success() || !err.contains("GO_WORKERS_OFF=drive-watch") {
        return Err(format!("expected refusal, got {:?}: {err}", out.status).into());
    }
    println!("GOLDEN-REPLAY: worker drive-watch :: refuses-without-go-off");
    Ok(())
}

#[tokio::test]
async fn listens_once_go_is_off() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("drive-watch-startup") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let mut child = gateway(&db, true)?;
    let mut listening = false;
    for _ in 0..100 {
        if child.try_wait()?.is_some() {
            break;
        }
        listening = c.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name='gofree-drive4-startup' AND query LIKE 'LISTEN%')", &[]).await?.get(0);
        if listening {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = tokio::task::spawn_blocking(move || child.wait()).await?;
    if !listening {
        return Err("drive-watch did not LISTEN".into());
    }
    Ok(())
}
