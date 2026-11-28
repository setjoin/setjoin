//! Consent is compared through HTTP and committed PostgreSQL effects.
mod common;
use hyper::{Request, Response};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    recovery::{RecoveryCommands, RecoveryRoute},
    Config, Gateway, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

#[tokio::test]
async fn affected_user_consents_to_a_verified_fork() -> Result<(), common::BoxError> {
    run_case("success", false).await
}
#[tokio::test]
async fn foreign_user_cannot_consent_to_the_fork() -> Result<(), common::BoxError> {
    run_case("foreign", false).await
}
#[tokio::test]
async fn invalid_fork_identifier_does_not_consent() -> Result<(), common::BoxError> {
    run_case("invalid", false).await
}
#[tokio::test]
async fn repeated_fork_consent_preserves_the_first_consent_and_audit(
) -> Result<(), common::BoxError> {
    run_case("repeat", false).await
}

#[tokio::test]
async fn fork_request_uses_gos_last_case_insensitive_field_value() -> Result<(), common::BoxError> {
    run_case("duplicate", false).await
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
#[tokio::test]
async fn fork_oracle_rejects_a_changed_rust_status() -> Result<(), common::BoxError> {
    let error = run_case("success", true)
        .await
        .expect_err("mutant must disagree with Go");
    assert!(error.to_string().contains("/response/status"), "{error}");
    eprintln!("MUTANT-REJECTED: POST /recovery/artifacts/{{id}}/fork-consent :: changed-status");
    Ok(())
}

async fn run_case(case: &str, mutant: bool) -> Result<(), common::BoxError> {
    let _serial = common::recovery::SERIAL.lock().await;
    let Some(db) = Db::for_case("recovery-fork") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "blobs1-fork").await?;
    let foreign = fixture::account(&owner, "blobs1-fork-foreign").await?;
    let ids=owner.query_one("SELECT gen_random_uuid()::text,gen_random_uuid()::text,gen_random_uuid()::text,gen_random_uuid()::text",&[]).await?;
    let incident: String = ids.get(0);
    let session: String = ids.get(1);
    let artifact: String = ids.get(2);
    let device: String = ids.get(3);
    let previous: Option<bool> = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.client_recovery_ingest'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
    let result=async {
        owner.execute("INSERT INTO feature_toggles(key,enabled) VALUES ('feature.client_recovery_ingest',true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[]).await?;
        owner.execute("INSERT INTO mail_recovery_incidents(id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,step_up_binding,expires_at,idempotency_key) VALUES($1::text::uuid,gen_random_uuid(),1,1,'test fork',$2,decode(repeat('aa',32),'hex'),now()+interval '1 day',gen_random_uuid())",&[&incident,&account.user]).await?;
        owner.execute("INSERT INTO mail_recovery_upload_sessions(id,incident_id,mailbox_id,uploading_user_id,device_id,artifact_identity,lineage_sha256,raw_mime_sha256,eligibility,declared_size,total_declared_size,receipt,consented_at,expires_at,idempotency_key,status) VALUES($1::text::uuid,$2::text::uuid,$3,$4,$5::text::uuid,decode(repeat('aa',32),'hex'),decode(repeat('bb',32),'hex'),decode(repeat('cc',32),'hex'),'received',1,1,'{}',now(),now()+interval '1 day',gen_random_uuid(),'quarantined')",&[&session,&incident,&account.mailbox,&account.user,&device]).await?;
        owner.execute("INSERT INTO mail_recovery_upload_items(session_id,item_id,role,sha256,declared_size,next_offset,status,object_ref) VALUES($1::text::uuid,'raw','raw',decode(repeat('cc',32),'hex'),1,1,'verified',repeat('c',64))",&[&session]).await?;
        owner.execute("INSERT INTO mail_recovery_quarantine_artifacts(id,session_id,incident_id,mailbox_id,uploading_user_id,device_id,artifact_identity,lineage_sha256,raw_mime_sha256,raw_mime_size,raw_ref,receipt,signed_timeline,signed_boot_epoch,parsed_headers,blob_inventory,malware_status,status) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4,$5,$6::text::uuid,decode(repeat('aa',32),'hex'),decode(repeat('bb',32),'hex'),decode(repeat('cc',32),'hex'),1,repeat('c',64),'{}',1,gen_random_uuid(),'{}','[]','clean','fork_conflict')",&[&artifact,&session,&incident,&account.mailbox,&account.user,&device]).await?;
        let endpoint=common::fake_upstream(|request|async move {
            if request.uri().query()==Some("location=") {Response::new(common::full("<LocationConstraint>us-east-1</LocationConstraint>"))}
            else {Response::new(common::full(""))}
        }).await;
        let oracle=common::go_oracle::start(&db,endpoint).await?;
        let recording=oracle.is_some();
        let route=RecoveryRoute(Arc::new(RecoveryCommands {
            exec:ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?,
            worker_exec:ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?,
            keys:common::recovery_keys(),issuer:"mailserver".into(),denylist:None,control_plane_ready:true,
            store:Some(Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{endpoint}"),"mailblobs","test-access","test-secret")?)),
        }));
        let mut inventory:serde_json::Value=serde_json::from_str(include_str!("../route-inventory.json"))?;
        let entry=inventory["routes"].as_array_mut().unwrap().iter_mut().find(|e|e["method"]=="POST" && e["path"]=="/recovery/artifacts/{id}/fork-consent").unwrap();
        entry["state"]="ON".into();entry["upstream"]="local-rust".into();
        let routes=if recording {RouteTable::proxy_all()} else if mutant {RouteTable::proxy_all().with(ChangedStatus(route))} else {RouteTable::proxy_all().with(route)};
        let gateway=Gateway::new(Config {
            upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,
            trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None,
        },routes)?.with_inventory(&inventory.to_string())?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;
        let server=tokio::spawn(gateway.serve(listener));
        let caller=if case=="foreign" {foreign.user} else {account.user};
        let target=if case=="invalid" {"not-a-uuid"} else {&artifact};
        let path=format!("/api/recovery/artifacts/{target}/fork-consent");
        let before=common::recovery::rows(&owner,&session,account.mailbox).await?;
        let mut notifications=db.listen("mail_recovery_incident_changed").await?;
        let mut responses=Vec::new();
        let request_body=if case=="duplicate" {format!("{{\"deviceId\":\"invalid\",\"DEVICEID\":\"{device}\"}}")}
            else {serde_json::json!({"deviceId":device}).to_string()};
        for _ in 0..if case=="repeat" {2} else {1} {
            let response=common::send(address,Request::post(&path).header("host","mail.test").header("origin","http://mail.test")
                .header("x-request-id","blobs1-fork-oracle").header("content-type","application/json")
                .header("authorization",format!("Bearer {}",common::recovery_token(caller)))
                .body(common::full(request_body.clone()))?).await;
            let status=response.status().as_u16();let original_headers=response.headers().clone();
            let raw=String::from_utf8(common::body_bytes(response).await.to_vec())?;
            let mut body=raw.clone();
            if let Ok(value)=serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(id)=value["id"].as_str() {
                    assert_eq!(id,artifact);
                    let recorded_time:String=owner.query_one("SELECT to_jsonb(fork_consented_at)::text FROM mail_recovery_quarantine_artifacts WHERE id=$1::text::uuid",&[&artifact]).await?.get(0);
                    assert_eq!(serde_json::to_string(&value["consentedAt"])?,recorded_time);
                    body=body.replacen(&format!("\"id\": \"{artifact}\""),"\"id\": \"<artifact>\"",1)
                        .replacen(&format!("\"consentedAt\": {recorded_time}"),"\"consentedAt\": \"<timestamp>\"",1);
                }
                if value["instance"].as_str().is_some_and(|v|!v.is_empty()) {
                    assert_eq!(value["instance"],format!("/recovery/artifacts/{target}/fork-consent"));
                    body=body.replacen(&format!("\"instance\":\"/recovery/artifacts/{target}/fork-consent\""),"\"instance\":\"/recovery/artifacts/<artifact>/fork-consent\"",1);
                }
            }
            let mut headers=serde_json::Map::new();
            for name in original_headers.keys() {
                let values=original_headers.get_all(name).iter().map(|v| {
                    let value=v.to_str()?;
                    if name=="date" {Ok("<timestamp>".to_owned())}
                    else if name=="content-length" {assert_eq!(value.parse::<usize>().unwrap(),raw.len());Ok(body.len().to_string())}
                    else {Ok(value.to_owned())}
                }).collect::<Result<Vec<_>,hyper::header::ToStrError>>()?;
                headers.insert(name.to_string(),serde_json::json!(values));
            }
            responses.push(serde_json::json!({"status":status,"headers":headers,"body":body}));
        }
        server.abort();
        let after=common::recovery::rows(&owner,&session,account.mailbox).await?;
        let effects=common::recovery::diff(&before,&after,caller)?;
        let mut audit=Vec::new();
        for row in owner.query("SELECT user_id,target_type,(after_state-'_checksum')::text FROM admin_audit_log WHERE action='mail_recovery_fork_consent' AND after_state->>'quarantineId'=$1 ORDER BY id",&[&artifact]).await? {
            assert_eq!(row.get::<_,i64>(0),caller);
            let state:serde_json::Value=serde_json::from_str(&row.get::<_,String>(2))?;
            assert_eq!(state["quarantineId"],artifact);assert_eq!(state["deviceId"],device);assert_eq!(state["mailboxId"],account.mailbox.to_string());
            audit.push(serde_json::json!({"actor":"<caller>","action":"mail_recovery_fork_consent","target_type":row.get::<_,String>(1),"state":{"quarantineId":"<artifact>","mailboxId":"<mailbox>","deviceId":"<device>"}}));
        }
        let mut observation=serde_json::json!({"request":{"method":"POST","path":"/recovery/artifacts/{id}/fork-consent","case":case,"body":{"deviceId":"<device>"}},"response":responses[0],"responses":responses,"effects":effects,"audit":audit,"notify":notifications.drain(&owner).await?});
        if case=="duplicate" {observation["request"]["body_raw"]="{\"deviceId\":\"invalid\",\"DEVICEID\":\"<device>\"}".into();}
        let base=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/blobs/goldens");
        let response_path=base.join(format!("recovery-fork-{case}.json"));let row_path=base.join(format!("recovery-fork-{case}-row-effects.json"));
        if recording {
            setjoin_conformance::golden::record(&response_path,&serde_json::json!({"format":1,"route":"POST /recovery/artifacts/{id}/fork-consent","case":case,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"normalization":["fixture identifiers","checked DB consent timestamp","response date and adjusted content-length"],"observation":observation}))?;
            setjoin_conformance::golden::record(&row_path,&serde_json::json!({"format":1,"route":"POST /recovery/artifacts/{id}/fork-consent","case":format!("{case}-row-effects"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"effects":effects}))?;
        } else {
            let golden:serde_json::Value=serde_json::from_slice(&std::fs::read(response_path)?)?;
            let row_golden:serde_json::Value=serde_json::from_slice(&std::fs::read(row_path)?)?;
            setjoin_conformance::golden::compare(&row_golden["effects"],&effects)?;
            setjoin_conformance::golden::compare(&golden["observation"],&observation)?;
            eprintln!("GOLDEN-REPLAY: POST /recovery/artifacts/{{id}}/fork-consent :: {case}");
        }
        Ok::<_,common::BoxError>(())
    }.await;
    owner
        .execute(
            "DELETE FROM mail_recovery_quarantine_artifacts WHERE id=$1::text::uuid",
            &[&artifact],
        )
        .await?;
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
