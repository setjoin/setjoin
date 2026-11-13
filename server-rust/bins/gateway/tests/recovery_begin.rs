//! Signed intake receipt and atomic reservation at the HTTP seam.
mod common;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    recovery::RecoveryCommands,
    recovery_begin::{BeginRoute, ReceiptKeys},
    Config, Gateway, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[tokio::test]
async fn signed_recovery_offer_reserves_the_owned_inventory() -> Result<(), common::BoxError> {
    run_case("success", false).await
}

async fn run_case(case: &str, mutant: bool) -> Result<(), common::BoxError> {
    let _serial = common::recovery::SERIAL.lock().await;
    let Some(db) = Db::for_case("recovery-begin") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "blobs1-begin").await?;
    let foreign = fixture::account(&owner, "blobs1-begin-foreign").await?;
    let ids=owner.query_one("SELECT gen_random_uuid()::text,gen_random_uuid()::text,gen_random_uuid()::text,gen_random_uuid()::text,gen_random_uuid()::text,gen_random_uuid()::text",&[]).await?;
    let incident: String = ids.get(0);
    let session: String = ids.get(1);
    let installation: String = ids.get(2);
    let device: String = ids.get(3);
    let idem: String = ids.get(4);
    let boot: String = ids.get(5);
    let previous: Option<bool> = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.client_recovery_ingest'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
    let result=async {
 owner.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.client_recovery_ingest',true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[]).await?;
 owner.execute("INSERT INTO mail_recovery_incidents(id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,step_up_binding,expires_at,idempotency_key) VALUES($1::text::uuid,$2::text::uuid,1,1,'blobs1 begin',$3,decode(repeat('aa',32),'hex'),now()+interval '1 hour',gen_random_uuid())",&[&incident,&installation,&a.user]).await?;
 owner.execute("INSERT INTO mail_recovery_incident_accounts(incident_id,mailbox_id,evidence_token_sha256) VALUES($1::text::uuid,$2,decode(repeat('aa',32),'hex'))",&[&incident,&a.mailbox]).await?;
 let now=chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();let hash="aa".repeat(32);
 let claims=json!({"v":1,"installationId":installation,"accountId":a.mailbox.to_string(),"originalMessageId":"blobs1-original","eligibility":"received","rawMimeSha256":hash,"rawMimeSize":"1","blobs":[],"timelineGeneration":"1","stateWatermark":"0","bootEpoch":boot,"issuedAt":now,"keyId":"blobs1-test-continuity"});
 let mut canonical=String::from("{");for (i,k) in ["v","installationId","accountId","originalMessageId","eligibility","rawMimeSha256","rawMimeSize","blobs","timelineGeneration","stateWatermark","bootEpoch","issuedAt","keyId"].iter().enumerate(){if i>0{canonical.push(',');}canonical.push_str(&format!("{}:{}",serde_json::to_string(k)?,if *k=="blobs"{"null".into()}else{claims[*k].to_string()}));}canonical.push('}');
 let key=ring::signature::Ed25519KeyPair::from_seed_unchecked(&[0x22;32]).map_err(|_|"test Ed25519 key")?;
 let signature=URL_SAFE_NO_PAD.encode(key.sign(canonical.as_bytes()).as_ref());
 let receipt=json!({"claims":claims,"signature":signature});let artifact=format!("{:x}",Sha256::digest(format!("v1\0{installation}\0{}\0blobs1-original\0{hash}",a.mailbox)));
 let body=json!({"sessionId":if case=="invalid"{"invalid"}else{&session},"incidentId":incident,"accountId":a.mailbox.to_string(),"deviceId":device,"artifactIdentity":artifact,"eligibility":"received","receipt":receipt,"inventory":[{"itemId":"raw","role":"raw","sha256":hash,"size":"1"}],"consentedAt":now,"idempotencyKey":idem}).to_string();
 let body=if case=="mixed-case"{body.replace("\"sessionId\"","\"SeSsIoNiD\"")}else if case=="duplicate-null"{body.replace(&format!("\"sessionId\":\"{session}\""),&format!("\"SESSIONID\":\"invalid\",\"sEsSiOnId\":\"{session}\",\"sessionid\":null"))}else{body};
 let endpoint=common::fake_upstream(|_|async{Response::new(common::full(""))}).await;let oracle=common::go_oracle::start(&db,endpoint).await?;let recording=oracle.is_some();
 use ring::signature::KeyPair;
 let route=BeginRoute(Arc::new(RecoveryCommands{exec:ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?,worker_exec:ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?,keys:common::recovery_keys(),issuer:"mailserver".into(),denylist:None,control_plane_ready:true,store:Some(Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{endpoint}"),"mailblobs","test-access","test-secret")?))}),Arc::new(ReceiptKeys::single("blobs1-test-continuity",key.public_key().as_ref().to_vec())));
 let mut inv:Value=serde_json::from_str(include_str!("../route-inventory.json"))?;let r=inv["routes"].as_array_mut().unwrap().iter_mut().find(|r|r["method"]=="POST"&&r["path"]=="/recovery/uploads").unwrap();r["state"]=json!("ON");r["upstream"]=json!("local-rust");
 let gateway=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},if recording{RouteTable::proxy_all()}else if mutant{RouteTable::proxy_all().with(ChangedStatus(route))}else{RouteTable::proxy_all().with(route)})?.with_inventory(&inv.to_string())?;
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let server=tokio::spawn(gateway.serve(listener));
 let mut notify=db.listen("mail_recovery_incident_changed").await?;
 if case=="repeat" {
 let response=common::send(address,Request::post("/api/recovery/uploads").header("host","mail.test").header("origin","http://mail.test").header("idempotency-key",&idem).header("x-request-id","blobs1-begin-oracle").header("content-type","application/json").header("authorization",format!("Bearer {}",common::recovery_token(if case=="foreign"{foreign.user}else{a.user}))).body(common::full(body.clone()))?).await;
 if response.status()!=201{return Err("initial begin failed".into());}let first=common::body_bytes(response).await;if !String::from_utf8_lossy(&first).contains("\"replayed\": false"){return Err("initial begin replayed unexpectedly".into());}
 }
 let response=common::send(address,Request::post("/api/recovery/uploads").header("host","mail.test").header("origin","http://mail.test").header("idempotency-key",&idem).header("x-request-id","blobs1-begin-oracle").header("content-type","application/json").header("authorization",format!("Bearer {}",common::recovery_token(if case=="foreign"{foreign.user}else{a.user}))).body(common::full(body))?).await;
 let status=response.status().as_u16();let mut headers=serde_json::Map::new();for name in response.headers().keys(){headers.insert(name.to_string(),json!(response.headers().get_all(name).iter().map(|v|if name=="date"{"<timestamp>".to_owned()}else{v.to_str().unwrap().to_owned()}).collect::<Vec<_>>()));}
 let mut body=String::from_utf8(common::body_bytes(response).await.to_vec())?;server.abort();
 let mut effects=Vec::new();for(table,predicate,order)in[("mail_recovery_upload_sessions","id=$1::text::uuid","id"),("mail_recovery_upload_items","session_id=$1::text::uuid","item_id")]{for row in owner.query(&format!("SELECT to_jsonb(t)::text FROM {table} t WHERE {predicate} ORDER BY {order}"),&[&session]).await?{let mut row:Value=serde_json::from_str(&row.get::<_,String>(0))?;if table=="mail_recovery_upload_sessions"{let expiry=row["expires_at"].as_str().ok_or("missing expiry")?;let expiry_value=chrono::DateTime::parse_from_rfc3339(expiry)?;let parsed:Value=serde_json::from_str(&body)?;if chrono::DateTime::parse_from_rfc3339(parsed["expiresAt"].as_str().ok_or("missing response expiry")?)?!=expiry_value{return Err("expiry differs from committed session".into());}body=body.replace(&session,"<session>").replace(parsed["expiresAt"].as_str().unwrap(),"<timestamp>");}
 for(k,v)in row.as_object_mut().unwrap(){if matches!(k.as_str(),"id"|"session_id"){if v!=&session{return Err("session mismatch".into());}*v=json!("<session>");}else if k=="incident_id"{if v!=&incident{return Err("incident mismatch".into());}*v=json!("<incident>");}else if k=="device_id"{if v!=&device{return Err("device mismatch".into());}*v=json!("<device>");}else if k=="idempotency_key"{if v!=&idem{return Err("idempotency mismatch".into());}*v=json!("<idempotency>");}else if k=="mailbox_id"{if v!=a.mailbox{return Err("mailbox mismatch".into());}*v=json!("<mailbox>");}else if k=="uploading_user_id"{if v!=a.user{return Err("actor mismatch".into());}*v=json!("<actor>");}else if k=="receipt"{if v!=&receipt{return Err("receipt mismatch".into());}*v=json!("<verified-receipt>");}else if k=="artifact_identity"{if v.as_str()!=Some(format!("\\x{artifact}").as_str()){return Err("artifact identity mismatch".into());}*v=json!("<artifact-identity>");}else if k=="lineage_sha256"{*v=json!("<lineage>");}else if k.ends_with("_at")&&v.is_string(){chrono::DateTime::parse_from_rfc3339(v.as_str().unwrap())?;*v=json!("<timestamp>");}}
 effects.push(json!({"table":table,"after":row}));}}
 if headers.contains_key("content-length"){headers.insert("content-length".into(),json!([body.len().to_string()]));}
 let audit=owner.query("SELECT user_id,action,(after_state-'_checksum')::text FROM admin_audit_log WHERE action='mail_recovery_upload_consent' AND after_state->>'incidentId'=$1 ORDER BY id",&[&incident]).await?.iter().map(|r|{assert_eq!(r.get::<_,i64>(0),a.user);let mut value:Value=serde_json::from_str(&r.get::<_,String>(2)).unwrap();assert_eq!(value["incidentId"],incident);assert_eq!(value["mailboxId"],a.mailbox.to_string());assert_eq!(value["artifactIdentity"],artifact);assert_eq!(value["deviceId"],device);value["incidentId"]=json!("<incident>");value["mailboxId"]=json!("<mailbox>");value["artifactIdentity"]=json!("<artifact-identity>");value["deviceId"]=json!("<device>");json!({"actor":"<actor>","action":r.get::<_,String>(1),"state":value})}).collect::<Vec<_>>();
 let observation=json!({"request":{"method":"POST","path":"/recovery/uploads"},"response":{"status":status,"headers":headers,"body":body},"effects":effects,"audit":audit,"notify":notify.drain(&owner).await?});
 let base=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/blobs/goldens");let path=base.join(format!("recovery-begin-{case}.json"));let rows=base.join(format!("recovery-begin-{case}-row-effects.json"));
 if recording{if status!=if case=="foreign"{403}else if case=="invalid"{400}else{201}{return Err(format!("Go begin failed: {status}: {body}").into());}let source=std::env::var("GOFREE_GO_SOURCE")?;setjoin_conformance::golden::record(&path,&json!({"format":1,"route":"POST /recovery/uploads","case":case,"go_source":source,"observation":observation}))?;setjoin_conformance::golden::record(&rows,&json!({"format":1,"route":"POST /recovery/uploads","case":format!("{case}-row-effects"),"go_source":source,"effects":effects}))?;}else{let expected:Value=serde_json::from_slice(&std::fs::read(path)?)?;setjoin_conformance::golden::compare(&expected["observation"],&observation)?;eprintln!("GOLDEN-REPLAY: POST /recovery/uploads :: {case}");}
 let _=mutant;Ok::<_,common::BoxError>(())
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
    common::remove_blob_account(&owner, &a).await?;
    common::remove_blob_account(&owner, &foreign).await?;
    if let Some(value) = previous {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.client_recovery_ingest'",
                &[&value],
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
    result
}

#[tokio::test]
async fn signed_offer_cannot_reserve_another_users_mailbox() -> Result<(), common::BoxError> {
    run_case("foreign", false).await
}

#[tokio::test]
async fn invalid_offer_identity_creates_no_reservation() -> Result<(), common::BoxError> {
    run_case("invalid", false).await
}

#[tokio::test]
async fn repeated_offer_reuses_the_reservation_without_second_audit() -> Result<(), common::BoxError>
{
    run_case("repeat", false).await
}

struct ChangedStatus<K: setjoin_authz::token::KeySource + 'static>(BeginRoute<K>);
impl<K: setjoin_authz::token::KeySource + 'static> setjoin_gateway::Intercept for ChangedStatus<K> {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.0.matches(r)
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let f = self.0.handle(r, c);
        Box::pin(async move {
            let mut r = f.await;
            *r.status_mut() = hyper::StatusCode::ACCEPTED;
            r
        })
    }
}
#[tokio::test]
async fn begin_oracle_rejects_changed_status() -> Result<(), common::BoxError> {
    let e = run_case("success", true)
        .await
        .expect_err("mutant must differ");
    assert!(e.to_string().contains("/response/status"), "{e}");
    eprintln!("MUTANT-REJECTED: POST /recovery/uploads :: changed-status");
    Ok(())
}

#[tokio::test]
async fn offer_field_names_follow_go_case_insensitive_decoding() -> Result<(), common::BoxError> {
    run_case("mixed-case", false).await
}

#[tokio::test]
async fn offer_duplicate_fields_follow_wire_order_and_null_preserves_string(
) -> Result<(), common::BoxError> {
    run_case("duplicate-null", false).await
}
