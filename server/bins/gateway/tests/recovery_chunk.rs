//! Exact chunk uploads are observed at HTTP, PostgreSQL and the S3 API.
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
async fn owned_recovery_chunk_advances_exactly_one_offset() -> Result<(), common::BoxError> {
    run_case("success", false).await
}

#[tokio::test]
async fn foreign_user_cannot_write_the_recovery_session() -> Result<(), common::BoxError> {
    run_case("foreign", false).await
}
#[tokio::test]
async fn invalid_chunk_range_does_not_write_storage_or_offsets() -> Result<(), common::BoxError> {
    run_case("invalid", false).await
}
#[tokio::test]
async fn identical_chunk_replay_does_not_advance_twice_or_rewrite_storage(
) -> Result<(), common::BoxError> {
    run_case("repeat", false).await
}
#[tokio::test]
async fn chunk_oracle_rejects_a_changed_rust_status() -> Result<(), common::BoxError> {
    let error = run_case("success", true)
        .await
        .expect_err("mutant must disagree with Go");
    assert!(error.to_string().contains("/response/status"), "{error}");
    eprintln!(
        "MUTANT-REJECTED: PUT /recovery/uploads/{{sessionId}}/items/{{itemId}} :: changed-status"
    );
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
    let Some(db) = Db::for_case("recovery-chunk") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "blobs1-chunk").await?;
    let foreign = fixture::account(&owner, "blobs1-chunk-foreign").await?;
    let ids = owner
        .query_one(
            "SELECT gen_random_uuid()::text,gen_random_uuid()::text",
            &[],
        )
        .await?;
    let incident: String = ids.get(0);
    let session: String = ids.get(1);
    let key = format!(
        "recovery-quarantine/{incident}/{session}/{:x}/0-{:x}",
        Sha256::digest(b"raw"),
        Sha256::digest(b"x")
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
        owner.execute("INSERT INTO mail_recovery_incidents(id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,step_up_binding,expires_at,idempotency_key) VALUES($1::text::uuid,gen_random_uuid(),1,1,'test chunk',$2,decode(repeat('aa',32),'hex'),now()+interval '1 day',gen_random_uuid())",&[&incident,&account.user]).await?;
        owner.execute("INSERT INTO mail_recovery_upload_sessions(id,incident_id,mailbox_id,uploading_user_id,device_id,artifact_identity,lineage_sha256,raw_mime_sha256,eligibility,declared_size,total_declared_size,receipt,consented_at,expires_at,idempotency_key) VALUES($1::text::uuid,$2::text::uuid,$3,$4,gen_random_uuid(),decode(repeat('aa',32),'hex'),decode(repeat('bb',32),'hex'),decode(repeat('cc',32),'hex'),'received',1,1,'{}',now(),now()+interval '1 day',gen_random_uuid())",&[&session,&incident,&account.mailbox,&account.user]).await?;
        owner.execute("INSERT INTO mail_recovery_upload_items(session_id,item_id,role,sha256,declared_size) VALUES($1::text::uuid,'raw','raw',decode(repeat('aa',32),'hex'),1)",&[&session]).await?;
        let stored=Arc::new(Mutex::new(Vec::new()));let captured=stored.clone();let expected_key=key.clone();
        let endpoint=common::fake_upstream(move |mut request| {
            let captured=captured.clone();let expected_key=expected_key.clone();
            async move {
                use http_body_util::BodyExt;
                let bytes=request.body_mut().collect().await.unwrap().to_bytes();
                if request.method()==hyper::Method::PUT {
                    let observed=common::s3::observe(&request,&bytes);
                    let value=match observed {
                        Ok(value)=>{
                            if request.uri().path()!=format!("/mailblobs/{expected_key}") {serde_json::json!({"unexpected_key":request.uri().path()})}
                            else {serde_json::json!({"key":"<quarantine-key>","content_type":request.headers().get("content-type").unwrap().to_str().unwrap(),"bytes":value["body"]})}
                        },
                        Err(error)=>serde_json::json!({"invalid_signature":error}),
                    };
                    captured.lock().unwrap().push(value);
                    Response::builder().status(200).header("etag","\"test-etag\"").body(common::full("")).unwrap()
                } else if request.uri().query()==Some("location=") {Response::new(common::full("<LocationConstraint>us-east-1</LocationConstraint>"))}
                else {Response::new(common::full(""))}
            }
        }).await;
        let oracle=common::go_oracle::start(&db,endpoint).await?;let recording=oracle.is_some();
        let route=RecoveryRoute(Arc::new(RecoveryCommands {
            exec:ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?,worker_exec:ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?,
            keys:common::recovery_keys(),issuer:"mailserver".into(),denylist:None,control_plane_ready:true,
            store:Some(Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{endpoint}"),"mailblobs","test-access","test-secret")?)),
        }));
        let mut inventory:serde_json::Value=serde_json::from_str(include_str!("../route-inventory.json"))?;
        let entry=inventory["routes"].as_array_mut().unwrap().iter_mut().find(|e|e["method"]=="PUT" && e["path"]=="/recovery/uploads/{sessionId}/items/{itemId}").unwrap();
        entry["state"]="ON".into();entry["upstream"]="local-rust".into();
        let routes=if recording {RouteTable::proxy_all()} else if mutant {RouteTable::proxy_all().with(ChangedStatus(route))} else {RouteTable::proxy_all().with(route)};
        let gateway=Gateway::new(Config {upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},routes)?.with_inventory(&inventory.to_string())?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let server=tokio::spawn(gateway.serve(listener));
        let caller=if case=="foreign" {foreign.user} else {account.user};let range=if case=="invalid" {"bytes 1-0/1"} else {"bytes 0-0/1"};
        let mut before=common::recovery::rows(&owner,&session,account.mailbox).await?;
        let mut notifications=db.listen("mail_recovery_incident_changed").await?;let mut responses=Vec::new();
        for _ in 0..if case=="repeat" {2} else {1} {
            let response=common::send(address,Request::put(format!("/api/recovery/uploads/{session}/items/raw"))
                .header("host","mail.test").header("origin","http://mail.test").header("x-request-id","blobs1-chunk-oracle")
                .header("content-range",range).header("content-type","application/octet-stream").header("authorization",format!("Bearer {}",common::recovery_token(caller)))
                .body(common::full("x"))?).await;
            let status=response.status().as_u16();let mut headers=serde_json::Map::new();
            for name in response.headers().keys() {
                headers.insert(name.to_string(),serde_json::json!(response.headers().get_all(name).iter().map(|v|if name=="date" {Ok("<timestamp>".to_owned())} else {v.to_str().map(str::to_owned)}).collect::<Result<Vec<_>,_>>()?));
            }
            let body=String::from_utf8(common::body_bytes(response).await.to_vec())?;
            if recording && status!=if matches!(case,"foreign"|"invalid") {400} else {204} {return Err(format!("Go fixture failed to reach {case}: {status} {body}").into());}
            responses.push(serde_json::json!({"status":status,"headers":headers,"body":body}));
        }
        server.abort();
        let mut after=common::recovery::rows(&owner,&session,account.mailbox).await?;
        let old_chunks=before["mail_recovery_upload_chunks"].take();let new_chunks=after["mail_recovery_upload_chunks"].take();
        assert_eq!(old_chunks,serde_json::json!([]));before["mail_recovery_upload_chunks"]=serde_json::json!([]);after["mail_recovery_upload_chunks"]=serde_json::json!([]);
        let mut effects=common::recovery::diff(&before,&after,caller)?.as_array().unwrap().clone();
        for mut chunk in new_chunks.as_array().ok_or("invalid chunk snapshot")?.clone() {
            assert_eq!(chunk["session_id"],session);assert_eq!(chunk["object_key"],key);assert_eq!(chunk["item_id"],"raw");
            if !chunk["created_at"].is_string() {return Err("missing chunk timestamp".into());}
            chunk["session_id"]="<session>".into();chunk["object_key"]="<quarantine-key>".into();chunk["created_at"]="<timestamp>".into();
            effects.push(serde_json::json!({"table":"mail_recovery_upload_chunks","row":"raw:0","change":"insert","after":chunk}));
        }
        if recording {
            let objects=stored.lock().unwrap();
            if objects.len()!=if matches!(case,"foreign"|"invalid") {0} else {1} {return Err("Go fixture reached the wrong object-write branch".into());}
            for object in objects.iter() {
                if object["bytes"]!=serde_json::json!({"length":1,"sha256":format!("{:x}",Sha256::digest(b"x"))}) || object["content_type"]!="application/octet-stream" {
                    return Err(format!("S3 fixture did not accept a correctly signed object: {object}").into());
                }
            }
        }
        let audit_count:i64=owner.query_one("SELECT count(*) FROM admin_audit_log WHERE user_id=$1 AND action LIKE 'mail_recovery_%' AND (after_state->>'sessionId'=$2 OR after_state->>'incidentId'=$3)",&[&caller,&session,&incident]).await?.get(0);
        let observation=serde_json::json!({"request":{"method":"PUT","path":"/recovery/uploads/{sessionId}/items/{itemId}","case":case,"headers":{"content-range":range},"body":"x"},"response":responses[0],"responses":responses,"effects":effects,"audit_count":audit_count,"audit":[],"notify":notifications.drain(&owner).await?,"objects":stored.lock().unwrap().clone()});
        let base=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/blobs/goldens");let path=base.join(format!("recovery-chunk-{case}.json"));let rows_path=base.join(format!("recovery-chunk-{case}-row-effects.json"));
        if recording {
            setjoin_conformance::golden::record(&path,&serde_json::json!({"format":1,"route":"PUT /recovery/uploads/{sessionId}/items/{itemId}","case":case,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"normalization":["fixture UUIDs and exact object key","timestamps","S3 valid signing/framing variants observed as stored object bytes"],"observation":observation}))?;
            setjoin_conformance::golden::record(&rows_path,&serde_json::json!({"format":1,"route":"PUT /recovery/uploads/{sessionId}/items/{itemId}","case":format!("{case}-row-effects"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"effects":effects}))?;
        } else {
            let expected:serde_json::Value=serde_json::from_slice(&std::fs::read(path)?)?;let rows:serde_json::Value=serde_json::from_slice(&std::fs::read(rows_path)?)?;
            setjoin_conformance::golden::compare(&rows["effects"],&serde_json::json!(effects))?;setjoin_conformance::golden::compare(&expected["observation"],&observation)?;
            eprintln!("GOLDEN-REPLAY: PUT /recovery/uploads/{{sessionId}}/items/{{itemId}} :: {case}");
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
    result
}
