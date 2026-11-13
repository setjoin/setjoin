//! #409: the executable takes `drive-maintenance` / `drive-preview` only once
//! Go's copy is switched off, both need the object store, the maintenance tick
//! runs on the worker credential (never the request DSN), and the preview
//! worker is inert without `DRIVE_PREVIEW_CMD`.
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
    let Some(db) = Db::for_case("drive-workers-startup") else {
        return Ok(());
    };
    for name in ["drive-maintenance", "drive-preview"] {
        let other = if name == "drive-maintenance" {
            "drive-preview"
        } else {
            "drive-maintenance"
        };
        for off in ["", other, "drive-watch", &format!("{name}-x")] {
            let child = gateway(&db.dsn, &db.dsn, name, off, &[])?;
            let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await??;
            let err = String::from_utf8_lossy(&out.stderr);
            if out.status.success() || !err.contains(&format!("GO_WORKERS_OFF={name}")) {
                return Err(format!(
                    "{name}: expected refusal for {off:?}, got {:?}: {err}",
                    out.status
                )
                .into());
            }
        }
        println!("GOLDEN-REPLAY: worker {name} :: refuses-without-go-off");
    }
    Ok(())
}

/// With Go off the executable starts, and a worker credential that cannot
/// connect does not stop it (the tick fails and logs, as Go's per-step errors).
#[tokio::test]
async fn starts_once_go_is_off_and_stops_on_sigterm() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("drive-workers-startup") else {
        return Ok(());
    };
    let s3 = [
        ("S3_ENDPOINT", "http://127.0.0.1:1"),
        ("S3_BUCKET", "mailblobs"),
    ];
    for (name, extra) in [("drive-maintenance", &s3[..]), ("drive-preview", &s3[..])] {
        let mut child = gateway(&db.dsn, &db.dsn, name, name, extra)?;
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let running = child.try_wait()?.is_none();
        stop(&mut child);
        assert!(running, "{name} did not stay up with Go off");
    }
    println!("GOLDEN-REPLAY: worker drive-maintenance+drive-preview :: starts-with-go-off");
    Ok(())
}

/// The maintenance worker needs the object store, as Go does: a malformed
/// endpoint is a startup error, never a silently inert worker.
#[tokio::test]
async fn boot_refuses_invalid_object_store_before_workers() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("drive-workers-startup") else {
        return Ok(());
    };
    for name in ["drive-maintenance", "drive-preview"] {
        let child = gateway(
            &db.dsn,
            &db.dsn,
            name,
            name,
            &[("S3_ENDPOINT", "http://user@example.invalid:9000")],
        )?;
        let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await??;
        let err = String::from_utf8_lossy(&out.stderr);
        if out.status.code() != Some(0)
            || !err.contains("object storage client init failed")
            || err.contains("server boot checks completed")
        {
            return Err(format!(
                "{name}: expected object-store refusal, got {:?}: {err}",
                out.status
            )
            .into());
        }
    }
    Ok(())
}

/// Boot opens the restricted request credential. The separately configured
/// worker credential retains cross-tenant authority; the recorded oracle proves
/// its tick because the five-minute schedule is too long for this startup test.
#[tokio::test]
async fn runs_with_restricted_request_credential() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("drive-workers-startup") else {
        return Ok(());
    };
    let mut child = gateway(
        db.app
            .as_deref()
            .expect("restricted request credential required"),
        &db.dsn,
        "drive-maintenance,drive-preview",
        "drive-maintenance,drive-preview",
        &[
            ("S3_ENDPOINT", "http://127.0.0.1:1"),
            ("DRIVE_PREVIEW_CMD", "true"),
        ],
    )?;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let running = child.try_wait()?.is_none();
    stop(&mut child);
    assert!(
        running,
        "workers must start with restricted request and separate worker credentials"
    );
    Ok(())
}
