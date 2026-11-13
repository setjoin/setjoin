use crate::common::boot::CommandBootExt;
mod common;
use http_body_util::BodyExt;

use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::recovery_worker::{ObjectStore, RecoveryCleanup};
use setjoin_pg::workers::WorkerDatabase;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
use tokio_postgres::NoTls;

#[derive(Default)]
struct Store(Mutex<Vec<String>>);
impl ObjectStore for Store {
    fn remove<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.0.lock().unwrap().push(key.to_owned());
            Ok(())
        })
    }
}

#[tokio::test]
async fn expired_recovery_upload_removes_its_chunk_and_acknowledges_it() {
    run_case(false, false).await;
}

#[tokio::test]
async fn executable_cleans_recovery_chunks_with_the_worker_credential() {
    run_case(true, false).await;
}

#[tokio::test]
async fn executable_cleanup_keeps_configured_core_audits_protected() {
    run_case(true, true).await;
}

async fn run_case(executable: bool, protected: bool) {
    let _serial = common::recovery::SERIAL.lock().await;
    let Some(db) = Db::for_case("expired_recovery_upload_removes_its_chunk_and_acknowledges_it")
    else {
        return;
    };
    let dsn = db.dsn;
    let (owner, connection) = tokio_postgres::connect(&dsn, NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    let account = fixture::account(&owner, "recovery-worker").await.unwrap();
    let incident: String = owner
        .query_one("SELECT gen_random_uuid()::text", &[])
        .await
        .unwrap()
        .get(0);
    let session: String = owner
        .query_one("SELECT gen_random_uuid()::text", &[])
        .await
        .unwrap()
        .get(0);
    let key = format!(
        "recovery-quarantine/{incident}/{session}/{}/0-{}",
        "a".repeat(64),
        "b".repeat(64)
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let outcome: Result<_, Box<dyn std::error::Error + Send + Sync>> = async {
    owner.execute("INSERT INTO mail_recovery_incidents (id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,step_up_binding,expires_at,idempotency_key) VALUES ($1::text::uuid,gen_random_uuid(),1,1,'test cleanup',$2,decode(repeat('aa',32),'hex'),now()+interval '1 day',gen_random_uuid())", &[&incident, &account.user]).await?;
    owner.execute("INSERT INTO mail_recovery_upload_sessions (id,incident_id,mailbox_id,uploading_user_id,device_id,artifact_identity,lineage_sha256,raw_mime_sha256,eligibility,declared_size,total_declared_size,receipt,consented_at,expires_at,idempotency_key) VALUES ($1::text::uuid,$2::text::uuid,$3,$4,gen_random_uuid(),decode(repeat('aa',32),'hex'),decode(repeat('bb',32),'hex'),decode(repeat('cc',32),'hex'),'received',1,1,'{}',now(),now()-interval '1 minute',gen_random_uuid())", &[&session, &incident, &account.mailbox, &account.user]).await?;
    owner.execute("INSERT INTO mail_recovery_upload_items (session_id,item_id,role,sha256,declared_size) VALUES ($1::text::uuid,'raw','raw',decode(repeat('aa',32),'hex'),1)", &[&session]).await?;
    owner.execute("INSERT INTO mail_recovery_upload_chunks (session_id,item_id,start_offset,size_bytes,sha256,object_key) VALUES ($1::text::uuid,'raw',0,1,decode(repeat('bb',32),'hex'),$2)", &[&session, &key]).await?;
    let store = Arc::new(Store::default());
    if executable {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        struct Process(crate::common::boot::Child);
        impl Drop for Process {
            fn drop(&mut self) {
                let _ = self.0.kill();
                self.0.wait().expect("reap owned recovery gateway");
            }
        }
        let observed = store.clone();
        let captured = requests.clone();
        let expected_key = key.clone();
        let booted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let endpoint = common::fake_upstream(move |mut req| {
            let observed = observed.clone();
            let captured = captured.clone();
            let expected_key = expected_key.clone();
            let booted = booted.clone();
            async move {
                let bytes = req.body_mut().collect().await.unwrap().to_bytes();
                // The boot client and worker have separate region caches.
                // Preserve the worker-only signed wire golden after boot's ping.
                if !booted.load(std::sync::atomic::Ordering::Acquire) {
                    assert!(matches!(req.uri().path(), "/mailblobs" | "/mailblobs/"));
                    assert!(bytes.is_empty());
                    let body = if req.method() == hyper::Method::HEAD {
                        booted.store(true, std::sync::atomic::Ordering::Release);
                        ""
                    } else if req.uri().query() == Some("location=") {
                        "<LocationConstraint>eu-central-1</LocationConstraint>"
                    } else {
                        assert_eq!(req.method(), hyper::Method::GET);
                        assert!(req.uri().query().unwrap_or("").split('&').any(|p| matches!(p,"uploads"|"uploads=")));
                        "<ListMultipartUploadsResult><Bucket>mailblobs</Bucket><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>"
                    };
                    return hyper::Response::new(common::full(body));
                }
                let mut request = common::s3::observe(&req,&bytes).expect("valid S3 signature");
                if req.method() == hyper::Method::DELETE {
                    assert_eq!(req.uri().path(),format!("/mailblobs/{expected_key}"));
                    request["uri"] = "/mailblobs/<quarantine-key>".into();
                    captured.lock().unwrap().push(request);
                    let key = req.uri().path().strip_prefix("/mailblobs/").unwrap().to_owned();
                    observed.0.lock().unwrap().push(key);
                    hyper::Response::builder().status(204).body(common::full("")).unwrap()
                } else {
                    captured.lock().unwrap().push(request);
                    hyper::Response::new(common::full("<LocationConstraint>eu-central-1</LocationConstraint>"))
                }
            }
        }).await;
        let mut process = Process(Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
            .arg0("gofree-blobs1-recovery-worker")
            .env_clear()
            .env("GATEWAY_LISTEN", "127.0.0.1:0")
            .env("GATEWAY_AUTH_UPSTREAM", "http://127.0.0.1:1")
            .env("RUST_WORKERS_ON", "mail-recovery-cleanup")
            .env("AUDIT_HMAC_KEY", if protected { "blobs1-worker-audit-key" } else { "" })
            .env("DB_DSN", &std::env::var("TEST_DB_DSN").expect("disposable boot database"))
            .env("DB_WORKER_DSN", &dsn)
            .env("DB_DIRECT_DSN", &dsn)
            .env("S3_ENDPOINT", format!("http://{endpoint}"))
            .env("S3_ACCESS_KEY", "test-access")
            .env("S3_SECRET_KEY", "test-secret")
            .stdout(Stdio::null()).stderr(Stdio::piped()).spawn_boot()?);
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if process.0.try_wait().unwrap().is_some() {
                    let mut logs = String::new();
                    use std::io::Read;
                    process.0.stderr.as_mut().unwrap().read_to_string(&mut logs).unwrap();
                    return Err(format!("recovery gateway exited before cleanup: {logs}"));
                }
                let count: i64 = owner.query_one("SELECT count(*) FROM mail_recovery_upload_chunks WHERE session_id=$1::text::uuid", &[&session]).await.unwrap().get(0);
                if count == 0 { return Ok(()); }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }).await.map_err(|_| "startup must run an immediate cleanup tick")??;
    } else {
        RecoveryCleanup::new(WorkerDatabase::new(&dsn).unwrap(), store.clone()).tick().await?;
    }
    let checksum: String = owner.query_one("SELECT checksum FROM admin_audit_log WHERE action='mail_recovery_upload_expire' AND user_id=$1 AND after_state->>'sessionId'=$2", &[&account.user, &session]).await?.get(0);
    if checksum.starts_with("v3:") != protected { return Err("cleanup audit must use the configured Go chain format".into()); }
    let removed = store.0.lock().unwrap().clone();
    let row = owner.query_one("SELECT s.status, i.status, (SELECT count(*) FROM mail_recovery_upload_chunks WHERE session_id=s.id) FROM mail_recovery_upload_sessions s JOIN mail_recovery_upload_items i ON i.session_id=s.id WHERE s.id=$1::text::uuid AND i.item_id='raw'", &[&session]).await?;
    let status = row.get::<_, String>(0);
    let item_status = row.get::<_, String>(1);
    let remaining = row.get::<_, i64>(2);
    Ok((removed, status, item_status, remaining))
    }.await;
    owner
        .execute(
            "DELETE FROM mail_recovery_upload_sessions WHERE id=$1::text::uuid",
            &[&session],
        )
        .await
        .unwrap();
    owner
        .execute(
            "DELETE FROM mail_recovery_incidents WHERE id=$1::text::uuid",
            &[&incident],
        )
        .await
        .unwrap();
    common::remove_blob_account(&owner, &account).await.unwrap();
    drop(owner);
    driver.await.unwrap().unwrap();
    let (removed, status, item_status, remaining) = outcome.unwrap();
    let mut actual = serde_json::json!({
        "session_status": status,
        "item_status": item_status,
        "remaining_chunks": remaining,
        "removed_object": removed == vec![key],
    });
    let golden = if executable {
        actual["requests"] = serde_json::json!(requests.lock().unwrap().clone());
        include_str!("golden/go-recovery-cleanup-http.json")
    } else {
        include_str!("golden/go-recovery-cleanup.json")
    };
    let expected: serde_json::Value = serde_json::from_str(golden).unwrap();
    assert_eq!(actual, expected);
}
