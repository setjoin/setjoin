//! #295 worker transfer through the real executable, with Go absent.
use crate::common::boot::CommandBootExt;
use crate::common::boot::Child;
mod common;
#[path = "common/meet_peripherals.rs"]
mod meet_peripherals;
use common::BoxError;
use setjoin_conformance::harness::Db;
use std::{
    io::Read,
    os::unix::process::CommandExt,
    process::{Command, ExitStatus, Stdio},
    time::Duration,
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Process {
    fn start(
        request: &str,
        worker: &str,
        on: &str,
        off: &str,
        extra: &[(&str, &str)],
    ) -> Result<Self, BoxError> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
        command
            .arg0("gofree-mbox4-gateway")
            .env_clear()
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        for (k, v) in [
            ("GATEWAY_LISTEN", "127.0.0.1:0"),
            ("GATEWAY_ENABLED", "false"),
            ("DB_DSN", request),
            ("DB_WORKER_DSN", worker),
            ("RUST_WORKERS_ON", on),
            ("GO_WORKERS_OFF", off),
            ("AUDIT_HMAC_KEY", "gofree-mbox4-audit-hmac"),
        ]
        .into_iter()
        .chain(extra.iter().copied())
        {
            command.env(k, v);
        }
        let process = Self(command.spawn_boot()?);
        if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
            use std::io::Write;
            writeln!(std::fs::OpenOptions::new().append(true).open(path)?,"PID {} gofree-mbox4-gateway; Rust workers {on:?}; owned by mail_workers_startup RAII; SIGTERM then reap, kill/reap on failure",process.0.id())?;
        }
        Ok(process)
    }
    async fn exited(&mut self, limit: Duration) -> Result<Option<ExitStatus>, BoxError> {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(Some(status));
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(None);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    fn stderr(&mut self) -> Result<String, BoxError> {
        let mut out = String::new();
        if let Some(mut pipe) = self.0.stderr.take() {
            pipe.read_to_string(&mut out)?;
        }
        Ok(out)
    }
    async fn stop(&mut self) -> Result<(), BoxError> {
        unsafe {
            libc::kill(self.0.id() as i32, libc::SIGTERM);
        }
        let status = self
            .exited(Duration::from_secs(5))
            .await?
            .ok_or("worker did not stop on SIGTERM")?;
        assert!(
            status.success(),
            "gateway shutdown failed: {}",
            self.stderr()?
        );
        Ok(())
    }
}

#[tokio::test]
async fn refuses_shared_effects_without_go_off() -> Result<(), BoxError> {
    // Each refused boot still runs the startup partition DDL, which locks `tags` before
    // `mailboxes`; a fixture mailbox insert locks them in the opposite order, and on a fresh
    // database the two deadlocked (40P01 in create_system_tags). Serialize with the other cases.
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("mail-worker-startup") else {
        return Ok(());
    };
    for name in ["mail-work", "mailbox-lifecycle"] {
        for off in [
            String::new(),
            format!("{name}-x"),
            name.to_uppercase(),
            if name == "mail-work" {
                "mailbox-lifecycle".into()
            } else {
                "mail-work".into()
            },
        ] {
            let mut process = Process::start(&db.dsn, &db.dsn, name, &off, &[])?;
            let status = process.exited(Duration::from_secs(2)).await?;
            assert!(
                status.is_some(),
                "{name} started with GO_WORKERS_OFF={off:?}"
            );
            assert!(!status.unwrap().success());
            let err = process.stderr()?;
            assert!(
                err.contains(&format!("GO_WORKERS_OFF={name}")),
                "wrong startup refusal: {err}"
            );
        }
    }
    Ok(())
}

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn activates_both_workers_on_worker_credential_and_stops() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("mail-worker-activation") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = setjoin_conformance::fixture::account(&owner, "mbox4-startup").await?;
    let mut notice = db.listen("mailbox_lifecycle").await?;
    let result=async {
        owner.execute("INSERT INTO mail_thread_work_events(id,mailbox_id,thread_id,generation,event_type,actor_user_id,actor_display_snapshot,before_state,after_state,reason,occurred_at) VALUES ('29560000-0000-4000-8000-000000000001',$1,'startup',1,'completed',$2,'Actor','{}','{}','oracle','2026-01-02T12:00:00Z')",&[&a.mailbox,&a.user]).await?;
        owner.batch_execute("INSERT INTO mail_work_outbox(event_id,consumer_kind,dedupe_key,payload) VALUES ('29560000-0000-4000-8000-000000000001','metric','mbox4-startup','{}')").await?;
        owner.execute("INSERT INTO mailbox_lifecycle_operations(operation_id,mailbox_id,action,actor_user_id,expected_generation,request_digest,before_digest,after_digest,result) VALUES ('29561000-0000-4000-8000-000000000001',$1,'suspend',$2,1,repeat('a',64),repeat('b',64),repeat('c',64),'{}')",&[&a.mailbox,&a.user]).await?;
        owner.execute("INSERT INTO mailbox_lifecycle_effects(operation_id,mailbox_id,effect_kind) VALUES ('29561000-0000-4000-8000-000000000001',$1,'notify_clients')",&[&a.mailbox]).await?;
        let mut process=Process::start(db.app.as_deref().expect("restricted boot request role"),&db.dsn," mail-work , mailbox-lifecycle "," mailbox-lifecycle, mail-work ",&[])?;
        let deadline=tokio::time::Instant::now()+Duration::from_secs(10);
        loop {
            if process.0.try_wait()?.is_some() {return Err(format!("worker startup failed: {}",process.stderr()?).into())}
            let work:String=owner.query_one("SELECT state FROM mail_work_outbox WHERE dedupe_key='mbox4-startup'",&[]).await?.get(0);
            let lifecycle:String=owner.query_one("SELECT state FROM mailbox_lifecycle_effects WHERE operation_id='29561000-0000-4000-8000-000000000001'",&[]).await?.get(0);
            if work=="completed" && lifecycle=="completed" {break}
            if tokio::time::Instant::now()>=deadline {return Err(format!("Rust tasks did not drain: mail-work={work}, lifecycle={lifecycle}").into())}
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        // Add new work after the immediate drain: the recurring tasks must run too.
        tokio::time::sleep(Duration::from_millis(150)).await;
        owner.batch_execute("INSERT INTO mail_thread_work_events(id,mailbox_id,thread_id,generation,event_type,actor_user_id,actor_display_snapshot,before_state,after_state,reason,occurred_at) SELECT '29560000-0000-4000-8000-000000000002',mailbox_id,'startup2',generation,event_type,actor_user_id,actor_display_snapshot,before_state,after_state,reason,occurred_at FROM mail_thread_work_events WHERE id='29560000-0000-4000-8000-000000000001'; INSERT INTO mail_work_outbox(event_id,consumer_kind,dedupe_key,payload) VALUES ('29560000-0000-4000-8000-000000000002','metric','mbox4-startup2','{}');").await?;
        owner.execute("INSERT INTO mailbox_lifecycle_operations(operation_id,mailbox_id,action,actor_user_id,expected_generation,request_digest,before_digest,after_digest,result) VALUES ('29561000-0000-4000-8000-000000000002',$1,'resume',$2,1,repeat('a',64),repeat('b',64),repeat('c',64),'{}')",&[&a.mailbox,&a.user]).await?;
        owner.execute("INSERT INTO mailbox_lifecycle_effects(operation_id,mailbox_id,effect_kind) VALUES ('29561000-0000-4000-8000-000000000002',$1,'notify_clients')",&[&a.mailbox]).await?;
        let deadline=tokio::time::Instant::now()+Duration::from_secs(10);
        loop {
            let row=owner.query_one("SELECT (SELECT state FROM mail_work_outbox WHERE dedupe_key='mbox4-startup2'),(SELECT state FROM mailbox_lifecycle_effects WHERE operation_id='29561000-0000-4000-8000-000000000002')",&[]).await?;
            if row.get::<_,String>(0)=="completed" && row.get::<_,String>(1)=="completed" {break}
            if tokio::time::Instant::now()>=deadline {return Err("workers did not process a recurring tick".into())}
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let notifications=notice.drain(&owner).await?;
        if notifications.len()!=2 {return Err("lifecycle immediate and recurring ticks must notify clients".into())}
        let metric:i32=owner.query_one("SELECT completed_count FROM mail_work_metric_daily WHERE mailbox_id=$1",&[&a.mailbox]).await?.get(0);
        if metric!=2 {return Err(format!("expected two completed work metrics, got {metric}").into())}
        process.stop().await
    }.await;
    owner
        .execute(
            "DELETE FROM mailbox_lifecycle_operations WHERE actor_user_id=$1",
            &[&a.user],
        )
        .await?;
    setjoin_conformance::fixture::remove(&owner, &a).await?;
    result
}

/// #457: subscribed events no longer keep a worker on Go. The executable enqueues them
/// durably and its own SSRF-safe executor makes the attempt (a loopback receiver is
/// refused at dial time, recorded on the delivery row).
#[tokio::test]
async fn delivers_webhook_subscribed_events_through_the_dispatcher() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("mail-worker-webhook-delivery") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = setjoin_conformance::fixture::account(&owner, "mbox4-webhook-delivery").await?;
    let result=async {
        let master="mbox4-startup-master";
        let sealed=setjoin_config_secret::seal_column(b"startup-signing-secret-startup-signing-secret",master.as_bytes(),setjoin_config_secret::CryptoProfile::Standard)?;
        owner.batch_execute("DELETE FROM webhook_deliveries; DELETE FROM webhook_subscriptions").await?;
        owner.execute("INSERT INTO webhook_subscriptions(user_id,url,secret_enc,secret_key_id,event_types,scope) VALUES ($1,'http://127.0.0.1:9/hook',$2,'v1','[\"mailwork.completed\",\"mailbox.suspended\"]','organization')",&[&a.user,&sealed]).await?;
        owner.execute("INSERT INTO mail_thread_work_events(id,mailbox_id,thread_id,generation,event_type,actor_user_id,actor_display_snapshot,before_state,after_state,reason,occurred_at) VALUES ('29562000-0000-4000-8000-000000000001',$1,'startup-webhook',1,'completed',$2,'Actor','{}','{}','oracle','2026-01-02T12:00:00Z')",&[&a.mailbox,&a.user]).await?;
        owner.batch_execute("INSERT INTO mail_work_outbox(event_id,consumer_kind,dedupe_key,payload) VALUES ('29562000-0000-4000-8000-000000000001','webhook','mbox4-startup-webhook','{\"eventType\":\"completed\",\"threadId\":\"startup-webhook\"}')").await?;
        owner.execute("INSERT INTO mailbox_lifecycle_operations(operation_id,mailbox_id,action,actor_user_id,expected_generation,request_digest,before_digest,after_digest,result) VALUES ('29562100-0000-4000-8000-000000000001',$1,'suspend',$2,1,repeat('a',64),repeat('b',64),repeat('c',64),'{}')",&[&a.mailbox,&a.user]).await?;
        owner.execute("INSERT INTO mailbox_lifecycle_effects(operation_id,mailbox_id,effect_kind) VALUES ('29562100-0000-4000-8000-000000000001',$1,'lifecycle_webhook')",&[&a.mailbox]).await?;
        owner.execute("INSERT INTO mailbox_lifecycle_outbox(operation_id,event_kind,dedupe_key,payload) VALUES ('29562100-0000-4000-8000-000000000001','mailbox.suspended','mbox4-startup-webhook-lc','{\"event\":\"mailbox.suspended\"}')",&[]).await?;
        let mut process=Process::start(&db.dsn,&db.dsn,"mail-work,mailbox-lifecycle","mail-work,mailbox-lifecycle",&[("JWT_SECRET",master)])?;
        let deadline=tokio::time::Instant::now()+Duration::from_secs(15);
        loop {
            if process.0.try_wait()?.is_some() {return Err(format!("workers refused a subscribed deployment: {}",process.stderr()?).into())}
            let work:String=owner.query_one("SELECT state FROM mail_work_outbox WHERE dedupe_key='mbox4-startup-webhook'",&[]).await?.get(0);
            let lifecycle:String=owner.query_one("SELECT state FROM mailbox_lifecycle_effects WHERE operation_id='29562100-0000-4000-8000-000000000001'",&[]).await?.get(0);
            let attempted:i64=owner.query_one("SELECT count(*) FROM webhook_deliveries WHERE attempt>=1 AND error_message LIKE '%not allowed%'",&[]).await?.get(0);
            if work=="completed" && lifecycle=="completed" && attempted==2 {break}
            if tokio::time::Instant::now()>=deadline {
                let deliveries:String=owner.query_one("SELECT coalesce(jsonb_agg(jsonb_build_object('event',event_type,'status',status,'attempt',attempt,'error',error_message)),'[]')::text FROM webhook_deliveries",&[]).await?.get(0);
                return Err(format!("not delivered through the dispatcher: mail-work={work}, lifecycle={lifecycle}, refused attempts={attempted}; deliveries={deliveries}; worker log: {}",{unsafe{libc::kill(process.0.id() as i32, libc::SIGTERM);}let _=process.0.wait();process.stderr().unwrap_or_default()}).into())
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        process.stop().await
    }.await;
    let _ = owner.batch_execute("DELETE FROM webhook_deliveries; DELETE FROM webhook_subscriptions").await;
    owner.execute("DELETE FROM mailbox_lifecycle_operations WHERE actor_user_id=$1",&[&a.user]).await?;
    setjoin_conformance::fixture::remove(&owner, &a).await?;
    result
}

#[tokio::test]
async fn unrequested_workers_leave_queues_for_go() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("mail-worker-rollback") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = setjoin_conformance::fixture::account(&owner, "mbox4-rollback").await?;
    let result=async {
        owner.execute("INSERT INTO mail_thread_work_events(id,mailbox_id,thread_id,generation,event_type,actor_user_id,actor_display_snapshot,before_state,after_state,reason,occurred_at) VALUES ('29570000-0000-4000-8000-000000000001',$1,'rollback',1,'completed',$2,'Actor','{}','{}','oracle','2026-01-02T12:00:00Z')",&[&a.mailbox,&a.user]).await?;
        owner.batch_execute("INSERT INTO mail_work_outbox(event_id,consumer_kind,dedupe_key,payload) VALUES ('29570000-0000-4000-8000-000000000001','metric','mbox4-rollback','{}')").await?;
        owner.execute("INSERT INTO mailbox_lifecycle_operations(operation_id,mailbox_id,action,actor_user_id,expected_generation,request_digest,before_digest,after_digest,result) VALUES ('29571000-0000-4000-8000-000000000001',$1,'suspend',$2,1,repeat('a',64),repeat('b',64),repeat('c',64),'{}')",&[&a.mailbox,&a.user]).await?;
        owner.execute("INSERT INTO mailbox_lifecycle_effects(operation_id,mailbox_id,effect_kind) VALUES ('29571000-0000-4000-8000-000000000001',$1,'notify_clients')",&[&a.mailbox]).await?;
        owner.execute("INSERT INTO webhook_subscriptions(user_id,url,event_types,scope) VALUES ($1,'http://127.0.0.1:1','[\"mailwork.completed\",\"mailbox.suspended\"]','organization')",&[&a.user]).await?;
        let mut process=Process::start(db.app.as_deref().expect("restricted boot request role"),&db.dsn,"","mail-work,mailbox-lifecycle",&[])?;
        tokio::time::sleep(Duration::from_secs(6)).await;
        if process.0.try_wait()?.is_some() {return Err(format!("unrequested workers affected startup: {}",process.stderr()?).into())}
        let work=owner.query_one("SELECT state,attempts FROM mail_work_outbox WHERE dedupe_key='mbox4-rollback'",&[]).await?;
        let lifecycle=owner.query_one("SELECT state,attempts FROM mailbox_lifecycle_effects WHERE operation_id='29571000-0000-4000-8000-000000000001'",&[]).await?;
        if work.get::<_,String>(0)!="pending" || work.get::<_,i32>(1)!=0 || lifecycle.get::<_,String>(0)!="pending" || lifecycle.get::<_,i32>(1)!=0 {return Err("unrequested Rust workers consumed Go's queues".into())}
        process.stop().await
    }.await;
    owner
        .execute(
            "DELETE FROM mailbox_lifecycle_operations WHERE actor_user_id=$1",
            &[&a.user],
        )
        .await?;
    setjoin_conformance::fixture::remove(&owner, &a).await?;
    result
}

#[tokio::test]
async fn shutdown_cancels_an_established_media_horizon() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("mail-worker-cancellation") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = setjoin_conformance::fixture::account(&owner, "mbox4-cancel").await?;
    let fake = meet_peripherals::Fake::start().await;
    let result=async {
        owner.execute("INSERT INTO mailbox_lifecycle_operations(operation_id,mailbox_id,action,actor_user_id,expected_generation,request_digest,before_digest,after_digest,result) VALUES ('29580000-0000-4000-8000-000000000001',$1,'suspend',$2,1,repeat('a',64),repeat('b',64),repeat('c',64),'{}')",&[&a.mailbox,&a.user]).await?;
        owner.execute("INSERT INTO mailbox_lifecycle_effects(operation_id,mailbox_id,effect_kind) VALUES ('29580000-0000-4000-8000-000000000001',$1,'evict_media')",&[&a.mailbox]).await?;
        owner.batch_execute("INSERT INTO mailbox_lifecycle_effect_targets(operation_id,room_name,identity,evict_until) VALUES ('29580000-0000-4000-8000-000000000001','cancel-room','u:cancel',now()+interval '1 hour')").await?;
        let url=format!("http://{}",fake.addr);
        let mut process=Process::start(db.app.as_deref().expect("restricted boot request role"),&db.dsn,"mailbox-lifecycle","mailbox-lifecycle",&[("LIVEKIT_URL",&url),("LIVEKIT_API_KEY",meet_peripherals::KEY),("LIVEKIT_API_SECRET",meet_peripherals::SECRET)])?;
        let deadline=tokio::time::Instant::now()+Duration::from_secs(10);
        loop {
            let calls=fake.drain();
            if !calls.is_empty() {if calls[0]["grant"]!=serde_json::json!({"room":"cancel-room","roomAdmin":true}) {return Err("startup did not wire the signed LiveKit credentials".into())}break}
            if process.0.try_wait()?.is_some() {return Err(format!("media startup failed: {}",process.stderr()?).into())}
            if tokio::time::Instant::now()>=deadline {return Err("worker never began media eviction".into())}
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        process.stop().await?;
        let row=owner.query_one("SELECT e.state,e.attempts,t.completed_at IS NULL FROM mailbox_lifecycle_effects e JOIN mailbox_lifecycle_effect_targets t USING(operation_id) WHERE operation_id='29580000-0000-4000-8000-000000000001'",&[]).await?;
        if row.get::<_,String>(0)!="claimed" || row.get::<_,i32>(1)!=1 || !row.get::<_,bool>(2) {return Err("cancellation prematurely acknowledged the eviction horizon".into())}
        Ok(())
    }.await;
    owner
        .execute(
            "DELETE FROM mailbox_lifecycle_operations WHERE actor_user_id=$1",
            &[&a.user],
        )
        .await?;
    setjoin_conformance::fixture::remove(&owner, &a).await?;
    result
}
