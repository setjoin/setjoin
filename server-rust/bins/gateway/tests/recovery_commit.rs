//! Reassembly and verification are observed through HTTP, DB and S3 state.
mod common;
use hyper::{Request, Response};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    recovery::{RecoveryCommands, RecoveryRoute},
    Config, Gateway, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn complete_recovery_item_is_verified_and_promoted() -> Result<(), common::BoxError> {
    run_case("success", false).await
}

#[tokio::test]
async fn foreign_user_cannot_commit_another_recovery_item() -> Result<(), common::BoxError> {
    run_case("foreign", false).await
}
#[tokio::test]
async fn invalid_commit_identifier_does_not_read_or_write_objects() -> Result<(), common::BoxError>
{
    run_case("invalid", false).await
}
#[tokio::test]
async fn repeated_item_commit_reuses_the_verified_object_without_rewriting(
) -> Result<(), common::BoxError> {
    run_case("repeat", false).await
}
#[tokio::test]
async fn commit_oracle_rejects_a_changed_rust_status() -> Result<(), common::BoxError> {
    let error = run_case("success", true)
        .await
        .expect_err("mutant must disagree with Go");
    assert!(error.to_string().contains("/response/status"), "{error}");
    eprintln!("MUTANT-REJECTED: POST /recovery/uploads/{{sessionId}}/items/{{itemId}}/commit :: changed-status");
    Ok(())
}

struct ChangedStatus<K: setjoin_authz::token::KeySource + 'static>(RecoveryRoute<K>);
impl<K: setjoin_authz::token::KeySource + 'static> setjoin_gateway::Intercept for ChangedStatus<K> {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.0.matches(r)
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let future = self.0.handle(r, c);
        Box::pin(async move {
            let mut response = future.await;
            *response.status_mut() = hyper::StatusCode::CREATED;
            response
        })
    }
}
async fn run_case(case: &str, mutant: bool) -> Result<(), common::BoxError> {
    let _serial = common::recovery::SERIAL.lock().await;
    let Some(db) = Db::for_case("recovery-commit") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "blobs1-commit").await?;
    let foreign = fixture::account(&owner, "blobs1-commit-foreign").await?;
    let ids = owner
        .query_one(
            "SELECT gen_random_uuid()::text,gen_random_uuid()::text",
            &[],
        )
        .await?;
    let incident: String = ids.get(0);
    let session: String = ids.get(1);
    let digest = format!("{:x}", Sha256::digest(b"x"));
    let key = format!(
        "recovery-quarantine/{incident}/{session}/{:x}/0-{digest}",
        Sha256::digest(b"raw")
    );
    let previous: Option<bool> = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.client_recovery_ingest'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
    let result=async {
        owner.execute("INSERT INTO feature_toggles(key,enabled) VALUES ('feature.client_recovery_ingest',true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[]).await?;
        owner.execute("INSERT INTO mail_recovery_incidents(id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,step_up_binding,expires_at,idempotency_key) VALUES($1::text::uuid,gen_random_uuid(),1,1,'test commit',$2,decode(repeat('aa',32),'hex'),now()+interval '1 day',gen_random_uuid())",&[&incident,&account.user]).await?;
        owner.execute("INSERT INTO mail_recovery_upload_sessions(id,incident_id,mailbox_id,uploading_user_id,device_id,artifact_identity,lineage_sha256,raw_mime_sha256,eligibility,declared_size,total_declared_size,next_offset,receipt,consented_at,expires_at,idempotency_key) VALUES($1::text::uuid,$2::text::uuid,$3,$4,gen_random_uuid(),decode(repeat('aa',32),'hex'),decode(repeat('bb',32),'hex'),decode($5,'hex'),'received',1,1,1,'{}',now(),now()+interval '1 day',gen_random_uuid())",&[&session,&incident,&account.mailbox,&account.user,&digest]).await?;
        owner.execute("INSERT INTO mail_recovery_upload_items(session_id,item_id,role,sha256,declared_size,next_offset) VALUES($1::text::uuid,'raw','raw',decode($2,'hex'),1,1)",&[&session,&digest]).await?;
        owner.execute("INSERT INTO mail_recovery_upload_chunks(session_id,item_id,start_offset,size_bytes,sha256,object_key) VALUES($1::text::uuid,'raw',0,1,decode($2,'hex'),$3)",&[&session,&digest,&key]).await?;
        let state=Arc::new(Mutex::new(serde_json::json!({"<quarantine-key>":{"sha256":digest,"length":1,"content_type":"application/octet-stream"}})));
        let writes=Arc::new(Mutex::new(Vec::new()));let captured=state.clone();let events=writes.clone();let quarantine=key.clone();let canonical=digest.clone();
        let endpoint=common::fake_upstream(move |mut request| {
            let captured=captured.clone();let events=events.clone();let quarantine=quarantine.clone();let canonical=canonical.clone();
            async move {
                use http_body_util::BodyExt;
                let body=request.body_mut().collect().await.unwrap().to_bytes();
                if request.uri().query()==Some("location=") {return Response::new(common::full("<LocationConstraint>us-east-1</LocationConstraint>"));}
                let object=request.uri().path().strip_prefix("/mailblobs/").unwrap_or("");
                if object.is_empty() {return Response::new(common::full(""));}
                let observed=common::s3::observe(&request,&body);
                let Ok(observed)=observed else {events.lock().unwrap().push(serde_json::json!({"invalid_signature":observed.unwrap_err()}));return Response::builder().status(403).body(common::full("")).unwrap();};
                if request.method()==hyper::Method::PUT {
                    if object!=canonical {events.lock().unwrap().push(serde_json::json!({"wrong_canonical":object}));}
                    let value=serde_json::json!({"sha256":observed["body"]["sha256"],"length":observed["body"]["length"],"content_type":request.headers()["content-type"].to_str().unwrap()});
                    captured.lock().unwrap()["<canonical-sha>"]=value.clone();events.lock().unwrap().push(serde_json::json!({"put":"<canonical-sha>","object":value}));
                    Response::builder().header("etag","\"test-etag\"").body(common::full("")).unwrap()
                } else if request.method()==hyper::Method::DELETE {
                    if object!=quarantine {events.lock().unwrap().push(serde_json::json!({"wrong_delete":object}));}
                    captured.lock().unwrap().as_object_mut().unwrap().remove("<quarantine-key>");events.lock().unwrap().push(serde_json::json!({"delete":"<quarantine-key>"}));
                    Response::builder().status(204).body(common::full("")).unwrap()
                } else if object==quarantine && captured.lock().unwrap().get("<quarantine-key>").is_some() {
                    Response::builder().header("content-length",1).header("content-type","application/octet-stream").header("etag","\"test-etag\"").header("last-modified","Sat, 31 Oct 2026 00:00:00 GMT")
                        .body(common::full(if request.method()==hyper::Method::HEAD {""} else {"x"})).unwrap()
                } else {Response::builder().status(404).body(common::full("")).unwrap()}
            }
        }).await;
        let oracle=common::go_oracle::start(&db,endpoint).await?;let recording=oracle.is_some();
        let route=RecoveryRoute(Arc::new(RecoveryCommands {exec:ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?,worker_exec:ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?,keys:common::recovery_keys(),issuer:"mailserver".into(),denylist:None,control_plane_ready:true,store:Some(Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{endpoint}"),"mailblobs","test-access","test-secret")?))}));
        let mut inventory:serde_json::Value=serde_json::from_str(include_str!("../route-inventory.json"))?;
        let entry=inventory["routes"].as_array_mut().unwrap().iter_mut().find(|e|e["method"]=="POST" && e["path"]=="/recovery/uploads/{sessionId}/items/{itemId}/commit").unwrap();entry["state"]="ON".into();entry["upstream"]="local-rust".into();
        let routes=if recording {RouteTable::proxy_all()} else if mutant {RouteTable::proxy_all().with(ChangedStatus(route))} else {RouteTable::proxy_all().with(route)};
        let gateway=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},routes)?.with_inventory(&inventory.to_string())?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let server=tokio::spawn(gateway.serve(listener));
        let caller=if case=="foreign" {foreign.user} else {account.user};let target=if case=="invalid" {"not-a-uuid"} else {&session};
        let before=common::recovery::rows(&owner,&session,account.mailbox).await?;let mut notifications=db.listen("mail_recovery_incident_changed").await?;let mut responses=Vec::new();
        for _ in 0..if case=="repeat" {2} else {1} {
            let response=common::send(address,Request::post(format!("/api/recovery/uploads/{target}/items/raw/commit")).header("host","mail.test").header("origin","http://mail.test").header("x-request-id","blobs1-commit-oracle").header("authorization",format!("Bearer {}",common::recovery_token(caller))).body(common::full(""))?).await;
            let status=response.status().as_u16();let mut headers=serde_json::Map::new();for name in response.headers().keys() {headers.insert(name.to_string(),serde_json::json!(response.headers().get_all(name).iter().map(|v|if name=="date" {Ok("<timestamp>".to_owned())} else {v.to_str().map(str::to_owned)}).collect::<Result<Vec<_>,_>>()?));}
            let body=String::from_utf8(common::body_bytes(response).await.to_vec())?;
            if recording && status!=if matches!(case,"foreign"|"invalid") {400} else {200} {return Err(format!("Go did not reach {case}: {status} {body}").into());}
            responses.push(serde_json::json!({"status":status,"headers":headers,"body":body}));
        }
        server.abort();let effects=common::recovery::diff(&before,&common::recovery::rows(&owner,&session,account.mailbox).await?,caller)?;
        let audit_count:i64=owner.query_one("SELECT count(*) FROM admin_audit_log WHERE user_id=$1 AND action LIKE 'mail_recovery_%' AND (after_state->>'sessionId'=$2 OR after_state->>'incidentId'=$3)",&[&caller,&session,&incident]).await?.get(0);
        let observation=serde_json::json!({"request":{"method":"POST","path":"/recovery/uploads/{sessionId}/items/{itemId}/commit","case":case},"response":responses[0],"responses":responses,"effects":effects,"audit":[],"audit_count":audit_count,"notify":notifications.drain(&owner).await?,"objects":state.lock().unwrap().clone(),"storage_writes":writes.lock().unwrap().clone()});
        let base=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/blobs/goldens");let path=base.join(format!("recovery-commit-{case}.json"));let rows_path=base.join(format!("recovery-commit-{case}-row-effects.json"));
        if recording {setjoin_conformance::golden::record(&path,&serde_json::json!({"format":1,"route":"POST /recovery/uploads/{sessionId}/items/{itemId}/commit","case":case,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"normalization":["fixture UUIDs and exact quarantine key","response date","valid S3 signing/framing variants observed as stored bytes"],"observation":observation}))?;setjoin_conformance::golden::record(&rows_path,&serde_json::json!({"format":1,"route":"POST /recovery/uploads/{sessionId}/items/{itemId}/commit","case":format!("{case}-row-effects"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"effects":effects}))?;}
        else {let expected:serde_json::Value=serde_json::from_slice(&std::fs::read(path)?)?;let rows:serde_json::Value=serde_json::from_slice(&std::fs::read(rows_path)?)?;setjoin_conformance::golden::compare(&rows["effects"],&effects)?;setjoin_conformance::golden::compare(&expected["observation"],&observation)?;eprintln!("GOLDEN-REPLAY: POST /recovery/uploads/{{sessionId}}/items/{{itemId}}/commit :: {case}");}
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
    result
}
