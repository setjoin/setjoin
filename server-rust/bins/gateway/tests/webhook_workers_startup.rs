//! #302: the executable takes `webhook-retry` and `webhook-publications` only once Go's
//! copy is switched off, and then works with the worker credential alone (the request DSN
//! is unreachable). The process's guarded client refuses the loopback receiver, so a
//! settled row proves wiring, credential and guard together without a network peer.
use crate::common::boot::CommandBootExt;
mod common;
use common::BoxError;
use setjoin_conformance::harness::Db;
use std::process::{Command, Stdio};

fn gateway(db: &Db, rust_on: &str, go_off: &str) -> std::io::Result<crate::common::boot::Child> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    command.env_clear().stdout(Stdio::null()).stderr(Stdio::piped());
    for (k, v) in [
        ("GATEWAY_LISTEN", "127.0.0.1:0"),
        ("GATEWAY_ENABLED", "false"),
        ("DB_DSN", db.app.as_deref().unwrap_or(&db.dsn)),
        ("DB_WORKER_DSN", db.dsn.as_str()),
        ("JWT_SECRET", "gofree-startup-master"),
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
    let Some(db) = Db::for_case("webhook-workers-startup") else { return Ok(()) };
    for (on, off, name) in [
        ("webhook-retry", "", "webhook-retry"),
        ("webhook-retry", "webhook-publications", "webhook-retry"),
        ("webhook-publications", "webhook-retry", "webhook-publications"),
        ("webhook-publications,webhook-retry", "webhook-retry", "webhook-publications"),
    ] {
        let child = gateway(&db, on, off)?;
        let out = tokio::task::spawn_blocking(move || child.wait_with_output()).await??;
        let err = String::from_utf8_lossy(&out.stderr);
        if out.status.success() || !err.contains(&format!("GO_WORKERS_OFF={name}")) {
            return Err(format!("expected refusal for {on}/{off}, got {:?}: {err}", out.status).into());
        }
    }
    println!("GOLDEN-REPLAY: worker webhook :: refuses-without-go-off");
    Ok(())
}

#[tokio::test]
async fn both_workers_run_on_the_worker_credential() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("webhook-workers-startup") else { return Ok(()) };
    let owner = db.connect().await?;
    owner.batch_execute("DELETE FROM webhook_deliveries; DELETE FROM webhook_subscriptions; DELETE FROM webhook_publications").await?;
    // The publication needs a subject user; a fresh database has none, so own one.
    let subject = setjoin_conformance::fixture::account(&owner, "webhook-startup").await?;
    let sub: i64 = owner
        .query_one(
            "INSERT INTO webhook_subscriptions(url,secret,event_types,scope) VALUES('http://127.0.0.1:9/hook','5555555555555555555555555555555555555555555555555555555555555555','[\"user.updated\"]'::jsonb,'organization') RETURNING id",
            &[],
        )
        .await?
        .get(0);
    // The publication needs a subject user; a freshly loaded database has none.
    owner.query_one("SELECT mk_account('webhook-startup')", &[]).await?;
    // One residue row for the retry worker, one committed publication for the other.
    owner
        .execute(
            "INSERT INTO webhook_deliveries(subscription_id,event_id,event_type,request_body,attempt,status) VALUES($1,'evt_startup_retry','user.updated','{\"id\":\"evt_startup_retry\"}'::jsonb,0,'pending')",
            &[&sub],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO webhook_publications(event_id,event_type,source,audience,subject_user_id,payload) VALUES('evt_startup_pub','user.updated','mailserver/test','user',$1,'{}'::jsonb)",
            &[&subject.user],
        )
        .await?;
    let mut child = gateway(&db, "webhook-retry,webhook-publications", "webhook-retry,webhook-publications")?;
    let mut settled = false;
    for _ in 0..100 {
        let done: i64 = owner
            .query_one(
                "SELECT (SELECT count(*) FROM webhook_deliveries WHERE event_id IN ('evt_startup_retry','evt_startup_pub') AND status<>'pending' AND attempt>=1 AND lease_owner IS NULL) + (SELECT count(*) FROM webhook_publications WHERE event_id='evt_startup_pub' AND state='delivered')",
                &[],
            )
            .await?
            .get(0);
        if done >= 3 {
            settled = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    stop(&mut child);
    let rows: Vec<(String, String, String)> = owner
        .query("SELECT event_id,status,COALESCE(error_message,'') FROM webhook_deliveries ORDER BY event_id", &[])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect();
    owner.batch_execute("DELETE FROM webhook_deliveries; DELETE FROM webhook_subscriptions; DELETE FROM webhook_publications").await?;
    setjoin_conformance::fixture::remove(&owner, &subject).await?;
    assert!(settled, "both workers should have settled their rows: {rows:?}");
    for (_, _, error) in &rows {
        assert!(error.contains("URL is not allowed"), "the guarded client refused the loopback receiver: {rows:?}");
    }
    Ok(())
}
