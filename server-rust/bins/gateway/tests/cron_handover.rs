//! #365: per-task cron locks let tasks leave Go one at a time.
use crate::common::boot::CommandBootExt;
mod common;
use chrono::TimeZone;
use common::BoxError;
use setjoin_conformance::harness::Db;
use setjoin_gateway::workers::{go_cron_task_is_off, Action, CronScheduler};
use setjoin_pg::workers::WorkerDatabase;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const TASK: &str = "chat-purge-expired";

fn counting(send: tokio::sync::mpsc::UnboundedSender<&'static str>) -> Action {
    Arc::new(move || {
        let send = send.clone();
        Box::pin(async move {
            send.send("ran").unwrap();
            Ok(())
        })
    })
}

fn at_0250() -> chrono::DateTime<chrono::Local> {
    chrono::Local
        .with_ymd_and_hms(2026, 10, 25, 2, 50, 0)
        .single()
        .unwrap()
}

#[test]
fn go_off_matching_is_exact_per_task_or_whole_scheduler() {
    assert!(go_cron_task_is_off("cron:chat-purge-expired", TASK));
    assert!(go_cron_task_is_off(
        "drive-watch, cron:chat-purge-expired ",
        TASK
    ));
    assert!(go_cron_task_is_off("cron", TASK));
    assert!(!go_cron_task_is_off("cron:chat-chain-anchor", TASK));
    assert!(!go_cron_task_is_off("chat-purge-expired", TASK));
    assert!(!go_cron_task_is_off("cron:chat-purge", TASK));
    assert!(!go_cron_task_is_off("", TASK));
}

#[tokio::test]
async fn rust_runs_a_task_under_its_own_lock_while_go_holds_the_scheduler_lock(
) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("cron-handover-no-double-run") else {
        return Ok(());
    };
    let worker = WorkerDatabase::new(&db.dsn)?;
    // Stand-in for live Go: it holds its lifetime lock for as long as it runs.
    let go = worker
        .try_cron_singleton()
        .await?
        .expect("Go scheduler lock");
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let mut rust = CronScheduler::per_task(worker.clone());
    rust.register_transferred(TASK, counting(send), "cron:chat-purge-expired")
        .await?;
    rust.tick(at_0250()).await?;
    rust.wait_idle().await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), receive.recv()).await?,
        Some("ran")
    );
    assert!(receive.try_recv().is_err(), "exactly one run");
    // Go's lock is untouched by Rust: Go still owns it, and Rust never took it.
    assert!(worker.try_cron_singleton().await?.is_none());
    rust.shutdown().await?;
    go.release().await?;
    Ok(())
}

#[tokio::test]
async fn rust_refuses_a_task_unless_go_lists_its_copy_off() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("cron-handover-guard") else {
        return Ok(());
    };
    let worker = WorkerDatabase::new(&db.dsn)?;
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let mut rust = CronScheduler::per_task(worker.clone());
    for go_off in ["", "cron:chat-chain-anchor", "chat-purge-expired"] {
        let error = rust
            .register_transferred(TASK, counting(send.clone()), go_off)
            .await
            .expect_err("Go copy still on");
        assert!(
            error
                .to_string()
                .contains("GO_WORKERS_OFF=cron:chat-purge-expired"),
            "{error}"
        );
    }
    rust.tick(at_0250()).await?;
    rust.wait_idle().await;
    assert!(receive.try_recv().is_err(), "a refused task never runs");
    // The refusal did not leave a lock behind.
    let lease = worker.try_cron_task_lock(TASK).await?.expect("lock free");
    lease.release().await?;
    rust.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_second_rust_scheduler_cannot_run_the_same_task() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("cron-handover-two-rust") else {
        return Ok(());
    };
    let worker = WorkerDatabase::new(&db.dsn)?;
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let mut first = CronScheduler::per_task(worker.clone());
    first
        .register_transferred(TASK, counting(send.clone()), "cron")
        .await?;
    let mut second = CronScheduler::per_task(worker.clone());
    let error = second
        .register_transferred(TASK, counting(send.clone()), "cron")
        .await
        .expect_err("task lock held");
    assert!(error.to_string().contains("already held"), "{error}");
    // Other tasks have their own lock and are unaffected.
    second
        .register_transferred("chat-chain-anchor", counting(send), "cron")
        .await?;
    second.shutdown().await?;
    first.tick(at_0250()).await?;
    first.wait_idle().await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), receive.recv()).await?,
        Some("ran")
    );
    assert!(receive.try_recv().is_err());
    first.shutdown().await?;
    // Released on shutdown, so the next scheduler may take the task.
    let mut third = CronScheduler::per_task(worker);
    third
        .register_transferred(
            TASK,
            counting(tokio::sync::mpsc::unbounded_channel().0),
            "cron",
        )
        .await?;
    third.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn losing_a_task_lock_connection_stops_the_scheduler() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("cron-handover-lock-loss") else {
        return Ok(());
    };
    let sep = if db.dsn.contains('?') { '&' } else { '?' };
    let worker = WorkerDatabase::new(&format!(
        "{}{sep}application_name=gofree-fix2-cron-task-lock",
        db.dsn
    ))?;
    let (send, _receive) = tokio::sync::mpsc::unbounded_channel();
    let mut rust = CronScheduler::per_task(worker);
    rust.register_transferred(TASK, counting(send), "cron:chat-purge-expired")
        .await?;
    let admin = db.connect().await?;
    let pid: i32 = admin
        .query_one(
            "SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-fix2-cron-task-lock'",
            &[],
        )
        .await?
        .get(0);
    admin
        .query_one("SELECT pg_terminate_backend($1)", &[&pid])
        .await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        rust.tick(at_0250()).await.is_err(),
        "no work after lock loss"
    );
    Ok(())
}

fn gateway(db: &Db, rust_on: &str, go_off: Option<&str>) -> std::io::Result<crate::common::boot::Child> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    command
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in [
        ("GATEWAY_LISTEN", "127.0.0.1:0"),
        ("GATEWAY_ENABLED", "false"),
        ("DB_DSN", db.dsn.as_str()),
        ("RUST_WORKERS_ON", rust_on),
    ] {
        command.env(k, v);
    }
    if let Some(go_off) = go_off {
        command.env("GO_WORKERS_OFF", go_off);
    }
    command.spawn_boot()
}

async fn refused(db: &Db, rust_on: &str, go_off: Option<&str>, want: &str) -> Result<(), BoxError> {
    let child = gateway(db, rust_on, go_off)?;
    let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await??;
    let err = String::from_utf8_lossy(&out.stderr);
    if out.status.success() || !err.contains(want) {
        return Err(format!(
            "expected refusal with {want:?}, got {:?}: {err}",
            out.status
        )
        .into());
    }
    Ok(())
}

#[tokio::test]
async fn executable_refuses_cron_tasks_unless_go_is_off_and_ported() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("cron-handover-startup-refusals") else {
        return Ok(());
    };
    let want = "cron:chat-chain-anchor requires GO_WORKERS_OFF=cron:chat-chain-anchor";
    refused(&db, "cron:chat-chain-anchor", None, want).await?;
    refused(
        &db,
        "cron:chat-chain-anchor",
        Some("cron:chat-purge-expired"),
        want,
    )
    .await?;
    // Every Go task has a Rust callback since #407, so the guard is the only refusal.
    refused(
        &db,
        "cron:prune-spam",
        None,
        "cron:prune-spam requires GO_WORKERS_OFF=cron:prune-spam",
    )
    .await?;
    refused(
        &db,
        "cron:no-such-task",
        Some("cron"),
        "no Rust implementation",
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn executable_holds_only_the_per_task_locks_once_go_is_off() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("cron-handover-startup-lock") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let probe = "SELECT pg_try_advisory_lock(hashtextextended($1, 0))";
    let mut child = gateway(
        &db,
        "cron:chat-chain-anchor,cron:chat-purge-expired",
        Some("cron:chat-chain-anchor,cron:chat-purge-expired"),
    )?;
    // The gateway takes the per-task locks one after the other, so wait for both.
    let mut held = false;
    let mut anchor_held = false;
    for _ in 0..600 {
        if child.try_wait()?.is_some() {
            break;
        }
        for (task, flag) in [
            ("cron-task:chat-purge-expired", &mut held),
            ("cron-task:chat-chain-anchor", &mut anchor_held),
        ] {
            if *flag {
                continue;
            }
            *flag = !c.query_one(probe, &[&task]).await?.get::<_, bool>(0);
            if !*flag {
                c.query_one("SELECT pg_advisory_unlock(hashtextextended($1, 0))", &[&task])
                    .await?;
            }
        }
        if held && anchor_held {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let go_lock_free: bool = c
        .query_one(probe, &[&"cron:scheduler-single-flight"])
        .await?
        .get(0);
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let _ = tokio::task::spawn_blocking(move || child.wait()).await?;
    assert!(held && anchor_held, "both per-task locks held by Rust");
    assert!(go_lock_free, "Rust never takes Go's scheduler lock");
    c.query_one("SELECT pg_advisory_unlock_all()", &[]).await?;
    Ok(())
}
