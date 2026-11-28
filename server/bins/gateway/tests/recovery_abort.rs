//! Abort is observed at HTTP, PostgreSQL and S3 boundaries, against frozen Go.
mod common;

use hyper::{Request, Response};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    recovery::{RecoveryCommands, RecoveryRoute},
    Config, Gateway, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn abort_marks_the_session_and_items_and_removes_quarantine_objects(
) -> Result<(), common::BoxError> {
    run_case("success", false).await
}

#[tokio::test]
async fn foreign_abort_preserves_the_upload_and_returns_gos_error() -> Result<(), common::BoxError>
{
    run_case("foreign", false).await
}

#[tokio::test]
async fn invalid_abort_identifier_does_not_touch_the_upload() -> Result<(), common::BoxError> {
    run_case("invalid", false).await
}

struct ChangedStatus<K: setjoin_authz::token::KeySource + 'static>(RecoveryRoute<K>);
impl<K: setjoin_authz::token::KeySource + 'static> setjoin_gateway::Intercept for ChangedStatus<K> {
    fn matches(&self, req: &Request<setjoin_gateway::Body>) -> bool {
        self.0.matches(req)
    }
    fn handle(
        &self,
        req: Request<setjoin_gateway::Body>,
        ctx: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let future = self.0.handle(req, ctx);
        Box::pin(async move {
            let mut response = future.await;
            *response.status_mut() = hyper::StatusCode::ACCEPTED;
            response
        })
    }
}

#[tokio::test]
async fn abort_oracle_rejects_changed_rust_status() -> Result<(), common::BoxError> {
    let error = run_case("success", true)
        .await
        .expect_err("mutant must disagree with Go");
    assert!(error.to_string().contains("/response/status"), "{error}");
    eprintln!("MUTANT-REJECTED: DELETE /recovery/uploads/{{sessionId}} :: changed-status");
    Ok(())
}

#[tokio::test]
async fn terminal_upload_cannot_be_aborted() -> Result<(), common::BoxError> {
    run_case("terminal", false).await
}

async fn run_case(case: &str, status_mutant: bool) -> Result<(), common::BoxError> {
    let _serial = common::recovery::SERIAL.lock().await;
    let Some(db) = Db::for_case("recovery-abort") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "blobs1-abort").await?;
    let foreign = fixture::account(&owner, "blobs1-abort-foreign").await?;
    let ids = owner
        .query_one(
            "SELECT gen_random_uuid()::text,gen_random_uuid()::text",
            &[],
        )
        .await?;
    let incident: String = ids.get(0);
    let session: String = ids.get(1);
    let key = format!(
        "recovery-quarantine/{incident}/{session}/{}/0-{}",
        "a".repeat(64),
        "b".repeat(64)
    );
    let previous: Option<bool> = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.client_recovery_ingest'",
            &[],
        )
        .await?
        .map(|row| row.get(0));
    let outcome = async {
        owner.execute("INSERT INTO feature_toggles(key,enabled) VALUES ('feature.client_recovery_ingest',true) ON CONFLICT(key) DO UPDATE SET enabled=true", &[]).await?;
        owner.execute("INSERT INTO mail_recovery_incidents (id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,step_up_binding,expires_at,idempotency_key) VALUES ($1::text::uuid,gen_random_uuid(),1,1,'test abort',$2,decode(repeat('aa',32),'hex'),now()+interval '1 day',gen_random_uuid())", &[&incident,&account.user]).await?;
        owner.execute("INSERT INTO mail_recovery_upload_sessions (id,incident_id,mailbox_id,uploading_user_id,device_id,artifact_identity,lineage_sha256,raw_mime_sha256,eligibility,declared_size,total_declared_size,receipt,consented_at,expires_at,idempotency_key) VALUES ($1::text::uuid,$2::text::uuid,$3,$4,gen_random_uuid(),decode(repeat('aa',32),'hex'),decode(repeat('bb',32),'hex'),decode(repeat('cc',32),'hex'),'received',1,1,'{}',now(),now()+interval '1 day',gen_random_uuid())", &[&session,&incident,&account.mailbox,&account.user]).await?;
        owner.execute("INSERT INTO mail_recovery_upload_items(session_id,item_id,role,sha256,declared_size) VALUES ($1::text::uuid,'raw','raw',decode(repeat('aa',32),'hex'),1)", &[&session]).await?;
        owner.execute("INSERT INTO mail_recovery_upload_chunks(session_id,item_id,start_offset,size_bytes,sha256,object_key) VALUES ($1::text::uuid,'raw',0,1,decode(repeat('bb',32),'hex'),$2)", &[&session,&key]).await?;
        if case == "terminal" {
            owner.execute("UPDATE mail_recovery_upload_sessions SET status='deduplicated',terminal_reason='already_present' WHERE id=$1::text::uuid", &[&session]).await?;
        }
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let expected_key = key.clone();
        let endpoint = common::fake_upstream(move |mut request| {
            let captured = captured.clone();
            let expected_key = expected_key.clone();
            async move {
                use http_body_util::BodyExt;
                let body = request.body_mut().collect().await.unwrap().to_bytes();
                // Bucket probes and MinIO's multipart maintenance are outside
                // the request's object-deletion observation.
                if request.method() == hyper::Method::DELETE {
                    assert_eq!(request.uri().path(),format!("/mailblobs/{expected_key}"));
                    let mut observed = common::s3::observe(&request,&body)
                        .unwrap_or_else(|error|serde_json::json!({"invalid_signature":error}));
                    observed["uri"] = "/mailblobs/<chunk-key>".into();
                    captured.lock().unwrap().push(observed);
                }
                if request.uri().query() == Some("location=") {
                    Response::new(common::full("<LocationConstraint>eu-central-1</LocationConstraint>"))
                } else { Response::builder().status(204).body(common::full("")).unwrap() }
            }
        }).await;
        let oracle = common::go_oracle::start(&db,endpoint).await?;
        let recording = oracle.is_some();
        let route = RecoveryRoute(Arc::new(RecoveryCommands {
            exec: ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?,
            worker_exec: ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?,
            keys: common::recovery_keys(), issuer: "mailserver".into(), denylist: None, control_plane_ready: true,
            store: Some(Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{endpoint}"),"mailblobs","test-access","test-secret")?)),
        }));
        let mut inventory: serde_json::Value = serde_json::from_str(include_str!("../route-inventory.json"))?;
        let entry = inventory["routes"].as_array_mut().unwrap().iter_mut().find(|entry|entry["method"]=="DELETE" && entry["path"]=="/recovery/uploads/{sessionId}").unwrap();
        entry["state"]="ON".into(); entry["upstream"]="local-rust".into();
        let gateway = Gateway::new(Config {
            upstream: oracle.as_ref().map(|oracle|format!("http://{}",oracle.address).parse()).transpose()?,
            trusted_proxies: TrustedProxies::parse("")?, upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT, edge_limit: None,
        }, if recording { RouteTable::proxy_all() } else if status_mutant { RouteTable::proxy_all().with(ChangedStatus(route)) } else { RouteTable::proxy_all().with(route) })?.with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let caller = if case == "foreign" {foreign.user} else {account.user};
        let target = if case == "invalid" {"not-a-uuid"} else {&session};
        let rows_before = common::recovery::rows(&owner,&session,account.mailbox).await?;
        let mut notifications = db.listen(&format!("tag:{}",account.mailbox)).await?;
        if case=="repeat" {
        let response = common::send(address,Request::delete(format!("/api/recovery/uploads/{target}"))
            .header("host","mail.test").header("origin","http://mail.test")
            .header("x-request-id","blobs1-abort-oracle")
            .header("authorization",format!("Bearer {}",common::recovery_token(caller)))
            .body(common::full(""))?).await;
            let status=response.status();let _=common::body_bytes(response).await;if status!=204{return Err("initial abort failed".into());}
        }
        let response = common::send(address,Request::delete(format!("/api/recovery/uploads/{target}"))
            .header("host","mail.test").header("origin","http://mail.test")
            .header("x-request-id","blobs1-abort-oracle")
            .header("authorization",format!("Bearer {}",common::recovery_token(caller)))
            .body(common::full(""))?).await;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(),serde_json::json!(response.headers().get_all(name).iter().map(|value|if name=="date" {Ok("<timestamp>".to_owned())} else {value.to_str().map(str::to_owned)}).collect::<Result<Vec<_>,_>>()?));
        }
        let mut body = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let raw_size = body.len();
        if let Some(length) = headers.get("content-length") { assert_eq!(length[0].as_str().unwrap().parse::<usize>()?,raw_size); }
        if let Ok(problem) = serde_json::from_str::<serde_json::Value>(&body) {
            if problem["instance"].as_str().is_some_and(|value|!value.is_empty()) {
                assert_eq!(problem["instance"],format!("/recovery/uploads/{target}"));
                body = body.replacen(&format!("\"instance\":\"/recovery/uploads/{target}\""),"\"instance\":\"/recovery/uploads/<session>\"",1);
                if headers.contains_key("content-length") {headers.insert("content-length".into(),serde_json::json!([body.len().to_string()]));}
            }
        }
        server.abort();
        let state = owner.query_one("SELECT s.status,s.terminal_reason,i.status,(SELECT count(*) FROM mail_recovery_upload_chunks WHERE session_id=s.id) FROM mail_recovery_upload_sessions s JOIN mail_recovery_upload_items i ON i.session_id=s.id WHERE s.id=$1::text::uuid", &[&session]).await?;
        let audits = owner.query("SELECT user_id,action,target_type,(after_state-'_checksum')::text AS state FROM admin_audit_log WHERE action='mail_recovery_upload_abort' AND after_state->>'sessionId'=$1 ORDER BY id", &[&session]).await?;
        let mut audit = Vec::new();
        for row in audits {
            let actor: i64 = row.get(0);
            assert_eq!(actor,account.user);
            let state: String = row.get(3);
            let value: serde_json::Value = serde_json::from_str(&state)?;
            assert_eq!(value["incidentId"],incident); assert_eq!(value["sessionId"],session); assert_eq!(value["mailboxId"],account.mailbox.to_string());
            audit.push(serde_json::json!({"actor":"<owner>","action":row.get::<_,String>(1),"resource_type":row.get::<_,String>(2),"state":{"incidentId":"<incident>","sessionId":"<session>","mailboxId":"<mailbox>"}}));
        }
        let observed = serde_json::json!({
            "request":{"method":"DELETE","path":"/recovery/uploads/{sessionId}","case":case},
            "response":{"status":status,"headers":headers,"body":body},
            "effects":{"session_status":state.get::<_,String>(0),"terminal_reason":state.get::<_,Option<String>>(1),"item_status":state.get::<_,String>(2),"remaining_chunks":state.get::<_,i64>(3)},
            "audit":audit,"notify":notifications.drain(&owner).await?,"s3":requests.lock().unwrap().clone(),
        });
        let row_effects = common::recovery::diff(&rows_before,&common::recovery::rows(&owner,&session,account.mailbox).await?,account.user)?;
        let row_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/blobs/goldens/recovery-abort-{case}-row-effects.json"));
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/blobs/goldens/recovery-abort-{case}.json"));
        if recording {
            if path.exists() {
                let golden: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
                setjoin_conformance::golden::compare(&golden["observation"],&observed)?;
            } else {
            setjoin_conformance::golden::record(&path,&serde_json::json!({"format":1,"route":"DELETE /recovery/uploads/{sessionId}","case":case,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"normalization":["fixture ids and token","response date","S3 signed date and signature"],"observation":observed}))?;
            }
            setjoin_conformance::golden::record(&row_path,&serde_json::json!({"format":1,"route":"DELETE /recovery/uploads/{sessionId}","case":format!("{case}-row-effects"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"normalization":["changed update timestamp"],"effects":row_effects}))?;
        } else {
            let row_golden: serde_json::Value = serde_json::from_slice(&std::fs::read(row_path)?)?;
            setjoin_conformance::golden::compare(&row_golden["effects"],&row_effects)?;
            let golden: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
            setjoin_conformance::golden::compare(&golden["observation"],&observed)?;
            eprintln!("GOLDEN-REPLAY: DELETE /recovery/uploads/{{sessionId}} :: {case}");
        }
        Ok::<_,common::BoxError>(())
    }.await;
    owner
        .execute(
            "DELETE FROM mail_recovery_upload_sessions WHERE id=$1::text::uuid",
            &[&session],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM mail_recovery_incidents WHERE id=$1::text::uuid",
            &[&incident],
        )
        .await?;
    if let Some(previous) = previous {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.client_recovery_ingest'",
                &[&previous],
            )
            .await?;
    } else {
        owner
            .execute(
                "DELETE FROM feature_toggles WHERE key='feature.client_recovery_ingest'",
                &[],
            )
            .await?;
    }
    common::remove_blob_account(&owner, &foreign).await?;
    common::remove_blob_account(&owner, &account).await?;
    outcome
}

#[tokio::test]
async fn repeated_abort_preserves_first_audit_and_terminal_state() -> Result<(), common::BoxError> {
    run_case("repeat", false).await
}
