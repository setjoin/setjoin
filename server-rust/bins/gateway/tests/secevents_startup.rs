//! #304: the executable takes `security-event-delivery` only once Go's copy is
//! switched off, and with no production sink admitted (Go's posture) it stays
//! inert: seeded outbox rows and their attempts are left untouched.
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
    let Some(db) = Db::for_case("secevents-startup") else {
        return Ok(());
    };
    for (on, off) in [
        ("security-event-delivery", ""),
        ("security-event-delivery", "notify-intent-drain"),
        ("security-event-delivery", "security-event-delivery-other"),
    ] {
        let child = gateway(&db, on, off)?;
        let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await??;
        let err = String::from_utf8_lossy(&out.stderr);
        if out.status.success() || !err.contains("GO_WORKERS_OFF=security-event-delivery") {
            return Err(
                format!("expected refusal for {off:?}, got {:?}: {err}", out.status).into(),
            );
        }
    }
    println!("GOLDEN-REPLAY: worker security-event-delivery :: refuses-without-go-off");
    Ok(())
}

/// With Go off and Rust on, the worker runs (the process stays up past a tick)
/// and the nil sink leaves a due pending row, an exhausted row and an old
/// delivered row exactly as seeded; with the worker not enabled nothing differs.
#[tokio::test]
async fn nil_sink_leaves_the_outbox_untouched() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("secevents-startup") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    owner
        .batch_execute(
            "DELETE FROM security_event_outbox;
             INSERT INTO security_event_outbox(event_type,payload,next_attempt_at) VALUES ('sec.ok','{\"label\":\"due\"}',now() - interval '1 hour');
             INSERT INTO security_event_outbox(event_type,payload,attempts,next_attempt_at) VALUES ('sec.ok','{\"label\":\"exhausted\"}',5,now() - interval '1 hour');
             INSERT INTO security_event_outbox(event_type,payload,status,delivered_at) VALUES ('sec.ok','{\"label\":\"old\"}','done',now() - interval '200 days')",
        )
        .await?;
    let snapshot = "SELECT string_agg(concat_ws('|',payload->>'label',status,attempts,claim_generation,coalesce(last_error,'-')), ';' ORDER BY id) FROM security_event_outbox";
    let before: String = owner.query_one(snapshot, &[]).await?.get(0);
    let mut child = gateway(&db, "security-event-delivery", "security-event-delivery")?;
    tokio::time::sleep(std::time::Duration::from_millis(4500)).await;
    let running = child.try_wait()?.is_none();
    stop(&mut child);
    let after: String = owner.query_one(snapshot, &[]).await?.get(0);
    owner
        .batch_execute("DELETE FROM security_event_outbox")
        .await?;
    assert!(running, "the gateway exited with the worker enabled");
    assert_eq!(before, after, "a nil sink must not touch the outbox");
    println!("GOLDEN-REPLAY: worker security-event-delivery :: nil-sink-inert");
    Ok(())
}
