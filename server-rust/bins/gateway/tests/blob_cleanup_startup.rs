//! #411: the executable takes `blob-cleanup` only once Go's copy is switched
//! off (`GO_WORKERS_OFF=blob-cleanup`), needs the object store, and uses the
//! worker credential, never the request DSN.
use crate::common::boot::CommandBootExt;
mod common;
use common::BoxError;
use setjoin_conformance::harness::Db;
use std::process::{Command, Stdio};

fn gateway(
    request_dsn: &str,
    worker_dsn: &str,
    rust_on: &str,
    go_off: &str,
    extra: &[(&str, &str)],
) -> std::io::Result<crate::common::boot::Child> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    command
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in [
        ("GATEWAY_LISTEN", "127.0.0.1:0"),
        ("GATEWAY_ENABLED", "false"),
        ("DB_DSN", request_dsn),
        ("DB_WORKER_DSN", worker_dsn),
        ("RUST_WORKERS_ON", rust_on),
        ("GO_WORKERS_OFF", go_off),
    ]
    .into_iter()
    .chain(extra.iter().copied())
    {
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
    let Some(db) = Db::for_case("blob-cleanup-startup") else {
        return Ok(());
    };
    for off in [
        "",
        "drive-maintenance",
        "blob-cleanup-x",
        "mail-recovery-cleanup",
    ] {
        let child = gateway(&db.dsn, &db.dsn, "blob-cleanup", off, &[])?;
        let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await??;
        let err = String::from_utf8_lossy(&out.stderr);
        if out.status.success() || !err.contains("GO_WORKERS_OFF=blob-cleanup") {
            return Err(
                format!("expected refusal for {off:?}, got {:?}: {err}", out.status).into(),
            );
        }
    }
    println!("GOLDEN-REPLAY: worker blob-cleanup :: refuses-without-go-off");
    Ok(())
}

/// With Go off the executable starts and stops on SIGTERM. Server boot still
/// validates storage when this particular worker is absent.
#[tokio::test]
async fn starts_once_go_is_off_and_stops_on_sigterm() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("blob-cleanup-startup") else {
        return Ok(());
    };
    let s3 = [
        ("S3_ENDPOINT", "http://127.0.0.1:1"),
        ("S3_BUCKET", "mailblobs"),
    ];
    let mut child = gateway(&db.dsn, &db.dsn, "blob-cleanup", "blob-cleanup", &s3)?;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let running = child.try_wait()?.is_none();
    stop(&mut child);
    assert!(running, "blob-cleanup did not stay up with Go off");
    // Not listed: Go keeps the worker; the owned peer still serves server boot.
    let mut child = gateway(&db.dsn, &db.dsn, "", "blob-cleanup", &[])?;
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    let running = child.try_wait()?.is_none();
    stop(&mut child);
    assert!(running, "gateway without the worker should start");
    println!("GOLDEN-REPLAY: worker blob-cleanup :: starts-with-go-off");
    Ok(())
}

#[tokio::test]
async fn boot_refuses_invalid_object_store_before_workers() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("blob-cleanup-startup") else {
        return Ok(());
    };
    let child = gateway(
        &db.dsn,
        &db.dsn,
        "blob-cleanup",
        "blob-cleanup",
        &[("S3_ENDPOINT", "http://user@example.invalid:9000")],
    )?;
    let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await??;
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.code() == Some(0)
            && err.contains("object storage client init failed")
            && !err.contains("server boot checks completed"),
        "expected object-store refusal, got {:?}: {err}",
        out.status
    );
    Ok(())
}

/// Boot validates the restricted request credential; cross-tenant worker work
/// retains the separately configured worker credential.
#[tokio::test]
async fn runs_with_restricted_request_credential() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("blob-cleanup-startup") else {
        return Ok(());
    };
    let mut child = gateway(
        db.app
            .as_deref()
            .expect("restricted request credential required"),
        &db.dsn,
        "blob-cleanup",
        "blob-cleanup",
        &[("S3_ENDPOINT", "http://127.0.0.1:1")],
    )?;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let running = child.try_wait()?.is_none();
    stop(&mut child);
    assert!(
        running,
        "blob-cleanup must start with the restricted request role and separate worker role"
    );
    Ok(())
}
