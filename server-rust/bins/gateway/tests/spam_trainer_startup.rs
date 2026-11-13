//! Executable handover and direct-LISTEN -> worker-credential write, with Go unset.
mod common;
use common::{boot::CommandBootExt, BoxError};
use setjoin_conformance::{fixture, harness::Db};
use std::os::unix::process::CommandExt;
use std::{
    process::{Command, Stdio},
    time::Duration,
};

fn gateway(db: &Db, off: &str, direct: &str) -> Result<common::boot::Child, BoxError> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    cmd.arg0("gofree-mailsec3b-gateway");
    cmd.env_clear().stdout(Stdio::null()).stderr(Stdio::piped());
    for (key, value) in [
        ("GATEWAY_LISTEN", "127.0.0.1:0"),
        ("GATEWAY_ENABLED", "false"),
        ("DB_DSN", db.app.as_deref().ok_or("DB_APP_DSN required")?),
        ("DB_WORKER_DSN", db.dsn.as_str()),
        ("DB_DIRECT_DSN", direct),
        ("RUST_WORKERS_ON", "spam-trainer"),
        ("GO_WORKERS_OFF", off),
    ] {
        cmd.env(key, value);
    }
    Ok(cmd.spawn_boot()?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_without_exact_go_worker_handover() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("spam-trainer-guard") else {
        return Ok(());
    };
    for off in ["", "dmarc-report", "spam-trainer-other"] {
        let mut child = gateway(&db, off, &db.dsn)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while child.try_wait()?.is_none() {
            if tokio::time::Instant::now() > deadline {
                return Err(
                    format!("gateway started spam-trainer without GO_WORKERS_OFF={off:?}").into(),
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let output = child.wait_with_output()?;
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("GO_WORKERS_OFF=spam-trainer"), "{error}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_notification_trains_on_worker_credential_and_shutdown_joins() -> Result<(), BoxError>
{
    let Some(db) = Db::for_case("spam-trainer-executable") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "mailsec3b-worker").await?;
    // The normal app role can write this table. Make an accidental request-pool
    // save fail here, so a green executable test proves the credential split.
    owner.batch_execute("CREATE FUNCTION gofree_mailsec3b_worker_only() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF current_user='setjoin_app' THEN RAISE EXCEPTION 'request credential used by spam trainer'; END IF; RETURN NEW; END $$; CREATE TRIGGER gofree_mailsec3b_worker_only BEFORE INSERT OR UPDATE ON user_spam_model FOR EACH ROW EXECUTE FUNCTION gofree_mailsec3b_worker_only();").await?;
    let result=async {
  owner.execute("UPDATE messages SET raw_ref='From: sender@example.test\r\n\r\nfree prize' WHERE id=$1 AND mailbox_id=$2",&[&a.two_labels,&a.mailbox]).await?;
  let separator=if db.dsn.contains('?'){"&"}else{"?"};
  let direct=format!("{}{separator}application_name=gofree-mailsec3b-trainer-listener",db.dsn);
  let mut child=gateway(&db,"spam-trainer",&direct)?;
  let deadline=tokio::time::Instant::now()+Duration::from_secs(15);
  loop {
   let ready:bool=owner.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-mailsec3b-trainer-listener' AND query LIKE 'LISTEN%spam_train%')",&[]).await?.get(0);
   if ready {break;}
   if child.try_wait()?.is_some(){let output=child.wait_with_output()?;return Err(String::from_utf8_lossy(&output.stderr).to_string().into());}
   if tokio::time::Instant::now()>deadline{return Err("spam_train direct LISTEN never established".into());}
   tokio::time::sleep(Duration::from_millis(50)).await;
  }
  // Terminate only this child's spam subscription in the assigned database.
  // A subsequent notification must arrive through a newly established LISTEN.
  let previous:i32=owner.query_one("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-mailsec3b-trainer-listener' AND query LIKE 'LISTEN%spam_train%'",&[]).await?.get(0);
  let terminated:bool=owner.query_one("SELECT pg_terminate_backend($1)",&[&previous]).await?.get(0);
  assert!(terminated);
  let deadline=tokio::time::Instant::now()+Duration::from_secs(15);
  loop {
   let ready:bool=owner.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-mailsec3b-trainer-listener' AND pid<>$1 AND query LIKE 'LISTEN%spam_train%')",&[&previous]).await?.get(0);
   if ready {break;}
   if tokio::time::Instant::now()>deadline {return Err("spam_train did not reconnect after its owned backend stopped".into());}
   tokio::time::sleep(Duration::from_millis(50)).await;
  }
  owner.execute("SELECT pg_notify('spam_train',$1)",&[&serde_json::json!({"user_id":a.user,"message_id":a.two_labels,"is_spam":true}).to_string()]).await?;
  let deadline=tokio::time::Instant::now()+Duration::from_secs(50);
  loop {
   let rows=owner.query("SELECT octet_length(model_bytes),sample_count FROM user_spam_model WHERE user_id=$1",&[&a.user]).await?;
   if let Some(row)=rows.first(){assert_eq!(row.get::<_,i32>(0),16+(1<<20)*24);assert_eq!(row.get::<_,i32>(1),1);break;}
   if tokio::time::Instant::now()>deadline{return Err("direct notification never produced a worker-DSN model save".into());}
   tokio::time::sleep(Duration::from_millis(100)).await;
  }
  unsafe{libc::kill(child.id() as i32,libc::SIGTERM);}
  let deadline=tokio::time::Instant::now()+Duration::from_secs(10);
  while child.try_wait()?.is_none(){if tokio::time::Instant::now()>deadline{return Err("worker did not stop on SIGTERM".into());}tokio::time::sleep(Duration::from_millis(50)).await;}
  assert!(child.wait()?.success());
  let remaining:i64=owner.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-mailsec3b-trainer-listener'",&[]).await?.get(0);
  assert_eq!(remaining,0,"direct listener survives shutdown");
  Ok::<_,BoxError>(())
 }.await;
    owner.batch_execute("DROP TRIGGER gofree_mailsec3b_worker_only ON user_spam_model; DROP FUNCTION gofree_mailsec3b_worker_only();").await?;
    fixture::remove(&owner, &a).await?;
    result
}
