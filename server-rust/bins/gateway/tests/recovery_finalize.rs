//! Full finalization effects plus independently framed ClamAV and S3 peers.
mod common;
use common::BoxError;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    recovery::RecoveryCommands,
    recovery_finalize::{ClamAV, FinalizeRoute},
    Config, Gateway, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
const RAW:&str="From: Sender <sender@example.test>\r\nTo: recipient@example.test\r\nSubject: recovered message\r\nMessage-ID: <blobs1-recovered@example.test>\r\nDate: Fri, 30 Oct 2026 12:00:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nRecovered body\r\n\r\nSecond paragraph.\r\n";
#[tokio::test]
async fn verified_raw_message_is_scanned_and_quarantined() -> Result<(), BoxError> {
    run_case("success", false).await
}

async fn run_case(case: &str, mutant: bool) -> Result<(), BoxError> {
    let _serial = common::recovery::SERIAL.lock().await;
    let Some(db) = Db::for_case("recovery-finalize") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "blobs1-finalize").await?;
    let foreign = fixture::account(&owner, "blobs1-finalize-foreign").await?;
    let ids=owner.query_one("SELECT gen_random_uuid()::text,gen_random_uuid()::text,gen_random_uuid()::text,gen_random_uuid()::text",&[]).await?;
    let incident: String = ids.get(0);
    let session: String = ids.get(1);
    let device: String = ids.get(2);
    let boot: String = ids.get(3);
    let hash = format!("{:x}", Sha256::digest(RAW));
    let identity = format!("{:x}", Sha256::digest(&session));
    let lineage = format!("{:x}", Sha256::digest(format!("{session}:lineage")));
    let previous: Option<bool> = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.client_recovery_ingest'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
    let mut mutant_schema = None;
    let result=async{
 owner.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.client_recovery_ingest',true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[]).await?;
 owner.execute("INSERT INTO mail_recovery_incidents(id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,step_up_binding,expires_at,idempotency_key) VALUES($1::text::uuid,gen_random_uuid(),1,1,'blobs1 finalize',$2,decode(repeat('aa',32),'hex'),now()+interval '1 hour',gen_random_uuid())",&[&incident,&a.user]).await?;
 let receipt=json!({"claims":{"timelineGeneration":"1","bootEpoch":boot}});
 owner.execute("INSERT INTO mail_recovery_upload_sessions(id,incident_id,mailbox_id,uploading_user_id,device_id,artifact_identity,lineage_sha256,raw_mime_sha256,eligibility,declared_size,total_declared_size,receipt,consented_at,expires_at,idempotency_key) VALUES($1::text::uuid,$2::text::uuid,$3,$4,$5::text::uuid,decode($6,'hex'),decode($7,'hex'),decode($8,'hex'),'received',$9,$9,$10::text::jsonb,now(),now()+interval '1 hour',gen_random_uuid())",&[&session,&incident,&a.mailbox,&a.user,&device,&identity,&lineage,&hash,&(RAW.len() as i64),&receipt.to_string()]).await?;
 owner.execute("INSERT INTO mail_recovery_upload_items(session_id,item_id,role,sha256,declared_size,next_offset,object_ref,status) VALUES($1::text::uuid,'raw','raw',decode($2,'hex'),$3,$3,$2,'verified')",&[&session,&hash,&(RAW.len() as i64)]).await?;
 let scans=Arc::new(Mutex::new(Vec::<Value>::new()));let scans_capture=scans.clone();
 let clamd=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let clamd_address=clamd.local_addr()?;
 let scanner_task=tokio::spawn(async move{
  use tokio::io::{AsyncBufReadExt,AsyncReadExt,AsyncWriteExt,BufReader};
  while let Ok((stream,_))=clamd.accept().await{let scans=scans_capture.clone();tokio::spawn(async move{let mut stream=BufReader::new(stream);loop{let mut command=String::new();if stream.read_line(&mut command).await.unwrap_or(0)==0{break;}
    let response=if command=="nINSTREAM\n"{let mut raw=Vec::new();loop{let size=stream.read_u32().await.unwrap() as usize;if size==0{break;}assert!(size<=4096);let start=raw.len();raw.resize(start+size,0);stream.read_exact(&mut raw[start..]).await.unwrap();}assert_eq!(raw,RAW.as_bytes());scans.lock().unwrap().push(json!({"command":"nINSTREAM","length":raw.len(),"sha256":format!("{:x}",Sha256::digest(raw))}));"stream: OK\n"}else if command=="nPING\n"{"PONG\n"}else{"ClamAV 1.5/test\n"};if stream.get_mut().write_all(response.as_bytes()).await.is_err(){break;}
  }});}
 });
 let expected_hash=hash.clone();let reads=Arc::new(Mutex::new(Vec::<Value>::new()));let reads_capture=reads.clone();
 let endpoint=common::fake_upstream(move|r|{let hash=expected_hash.clone();let reads=reads_capture.clone();async move{if r.uri().query()==Some("location="){Response::new(common::full("<LocationConstraint>us-east-1</LocationConstraint>"))}else if r.uri().path()==format!("/mailblobs/{hash}"){if r.method()==hyper::Method::GET{reads.lock().unwrap().push(json!({"key":"<raw-hash>","length":RAW.len()}));}Response::builder().header("content-type","message/rfc822").header("content-length",RAW.len()).header("etag","\"raw-etag\"").header("last-modified","Sat, 31 Oct 2026 00:00:00 GMT").body(common::full(if r.method()==hyper::Method::HEAD{""}else{RAW})).unwrap()}else{Response::new(common::full(""))}}}).await;
 let oracle=common::go_oracle::start_with_clamd(&db,endpoint,Some(clamd_address)).await?;let recording=oracle.is_some();
 let worker_dsn=if matches!(case,"no-audit"|"no-notify"|"double-bump"){let (dsn,schema)=mutant_worker(&owner,&db.dsn,case).await?;mutant_schema=Some(schema);dsn}else{db.dsn.clone()};
 let commands=Arc::new(RecoveryCommands{exec:ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?,worker_exec:ScopedExecutor::from_dsn(&worker_dsn,4).map_err(|e|e.0)?,keys:common::recovery_keys(),issuer:"mailserver".into(),denylist:None,control_plane_ready:true,store:Some(Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{endpoint}"),"mailblobs","test-access","test-secret")?))});
 let route=FinalizeRoute(commands,Some(Arc::new(ClamAV::new(clamd_address.to_string()))));
 let mut inv:Value=serde_json::from_str(include_str!("../route-inventory.json"))?;let r=inv["routes"].as_array_mut().unwrap().iter_mut().find(|r|r["path"]=="/recovery/uploads/{sessionId}/finalize").unwrap();r["state"]=json!("ON");r["upstream"]=json!("local-rust");
 let gateway=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},if recording{RouteTable::proxy_all()}else if mutant{RouteTable::proxy_all().with(ChangedStatus(route))}else{RouteTable::proxy_all().with(route)})?.with_inventory(&inv.to_string())?;
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let server=tokio::spawn(gateway.serve(listener));
 let before=common::recovery::rows(&owner,&session,a.mailbox).await?;let mut notify=db.listen("mail_recovery_incident_changed").await?;
 if case=="repeat" {
 let response=common::send(address,Request::post(format!("/api/recovery/uploads/{}/finalize",if case=="invalid"{"invalid"}else{&session})).header("host","mail.test").header("origin","http://mail.test").header("x-request-id","blobs1-finalize-oracle").header("authorization",format!("Bearer {}",common::recovery_token(if case=="foreign"{foreign.user}else{a.user}))).body(common::full(""))?).await;
 if response.status()!=201{return Err("initial finalization failed".into());}let first=common::body_bytes(response).await;if !String::from_utf8_lossy(&first).contains("\"replayed\":false"){return Err("initial finalize unexpectedly replayed".into());}
 }
 let response=common::send(address,Request::post(format!("/api/recovery/uploads/{}/finalize",if case=="invalid"{"invalid"}else{&session})).header("host","mail.test").header("origin","http://mail.test").header("x-request-id","blobs1-finalize-oracle").header("authorization",format!("Bearer {}",common::recovery_token(if case=="foreign"{foreign.user}else{a.user}))).body(common::full(""))?).await;
 let status=response.status().as_u16();let mut headers=serde_json::Map::new();for name in response.headers().keys(){headers.insert(name.to_string(),json!(response.headers().get_all(name).iter().map(|v|if name=="date"{"<timestamp>".into()}else{v.to_str().unwrap().to_owned()}).collect::<Vec<_>>()));}let mut body=String::from_utf8(common::body_bytes(response).await.to_vec())?;server.abort();scanner_task.abort();
 let mut after=common::recovery::rows(&owner,&session,a.mailbox).await?;let artifacts=after["mail_recovery_quarantine_artifacts"].take();after["mail_recovery_quarantine_artifacts"]=json!([]);let mut effects=common::recovery::diff(&before,&after,a.user)?.as_array().unwrap().clone();
 for mut row in artifacts.as_array().ok_or("missing artifacts")?.clone(){let artifact_id=row["id"].as_str().ok_or("missing artifact ID")?.to_owned();let parsed:Value=serde_json::from_str(&body)?;if parsed["id"]!=artifact_id{return Err("response id differs from committed artifact".into());}body=body.replace(&artifact_id,"<artifact>");
 for(k,v)in row.as_object_mut().unwrap(){match k.as_str(){"id"=>*v=json!("<artifact>"),"session_id"=>{assert_eq!(v,&session);*v=json!("<session>");},"incident_id"=>{assert_eq!(v,&incident);*v=json!("<incident>");},"mailbox_id"=>{assert_eq!(v,&a.mailbox);*v=json!("<mailbox>");},"uploading_user_id"=>{assert_eq!(v,&a.user);*v=json!("<actor>");},"device_id"=>{assert_eq!(v,&device);*v=json!("<device>");},"signed_boot_epoch"=>{assert_eq!(v,&boot);*v=json!("<boot>");},"receipt"=>{assert_eq!(v,&receipt);*v=json!("<receipt>");},"artifact_identity"=>{assert_eq!(v,&format!("\\x{identity}"));*v=json!("<identity>");},"lineage_sha256"=>{assert_eq!(v,&format!("\\x{lineage}"));*v=json!("<lineage>");},_=>{if k.ends_with("_at")&&v.is_string(){chrono::DateTime::parse_from_rfc3339(v.as_str().unwrap())?;*v=json!("<timestamp>");}}}}
 effects.push(json!({"table":"mail_recovery_quarantine_artifacts","after":row}));}
 if headers.contains_key("content-length"){headers.insert("content-length".into(),json!([body.len().to_string()]));}
 let mut audit=Vec::new();for row in owner.query("SELECT user_id,action,(after_state-'_checksum')::text FROM admin_audit_log WHERE action='mail_recovery_artifact_offer' AND after_state->>'incidentId'=$1 ORDER BY id",&[&incident]).await?{assert_eq!(row.get::<_,i64>(0),a.user);let mut state:Value=serde_json::from_str(&row.get::<_,String>(2))?;assert_eq!(state["incidentId"],incident);assert_eq!(state["mailboxId"],a.mailbox.to_string());assert_eq!(state["artifactIdentity"],identity);state["incidentId"]=json!("<incident>");state["mailboxId"]=json!("<mailbox>");state["artifactIdentity"]=json!("<identity>");audit.push(json!({"actor":"<actor>","action":row.get::<_,String>(1),"state":state}));}
 let notifications=notify.drain(&owner).await?.into_iter().map(|s|s.replace(&incident,"<incident>")).collect::<Vec<_>>();
 let observation=json!({"request":{"method":"POST","path":"/recovery/uploads/{sessionId}/finalize"},"response":{"status":status,"headers":headers,"body":body},"effects":effects,"audit":audit,"notify":notifications,"scans":scans.lock().unwrap().clone(),"reads":reads.lock().unwrap().clone()});
 let base=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/blobs/goldens");let golden_case=if matches!(case,"no-audit"|"no-notify"|"double-bump"){"success"}else{case};let path=base.join(format!("recovery-finalize-{golden_case}.json"));let rows=base.join(format!("recovery-finalize-{golden_case}-row-effects.json"));
 if recording{if status!=if matches!(case,"foreign"|"invalid"){400}else{201}{return Err(format!("Go finalize failed: {status}: {body}").into());}let source=std::env::var("GOFREE_GO_SOURCE")?;setjoin_conformance::golden::record(&path,&json!({"format":1,"route":"POST /recovery/uploads/{sessionId}/finalize","case":case,"go_source":source,"observation":observation}))?;setjoin_conformance::golden::record(&rows,&json!({"format":1,"route":"POST /recovery/uploads/{sessionId}/finalize","case":format!("{case}-row-effects"),"go_source":source,"effects":effects}))?;}else{let expected:Value=serde_json::from_slice(&std::fs::read(path)?)?;setjoin_conformance::golden::compare(&expected["observation"],&observation)?;eprintln!("GOLDEN-REPLAY: POST /recovery/uploads/{{sessionId}}/finalize :: {case}");}
 let _=mutant;Ok::<_,BoxError>(())
 }.await;
    if let Some(schema) = mutant_schema {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    owner
        .execute(
            "DELETE FROM mail_recovery_ledger WHERE incident_id=$1::text::uuid",
            &[&incident],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM mail_recovery_quarantine_artifacts WHERE session_id=$1::text::uuid",
            &[&session],
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
async fn foreign_caller_cannot_finalize_another_upload() -> Result<(), BoxError> {
    run_case("foreign", false).await
}

#[tokio::test]
async fn invalid_finalize_identifier_does_not_read_or_scan() -> Result<(), BoxError> {
    run_case("invalid", false).await
}

#[tokio::test]
async fn repeated_finalize_reuses_artifact_without_scan_or_audit() -> Result<(), BoxError> {
    run_case("repeat", false).await
}

struct ChangedStatus<K: setjoin_authz::token::KeySource + 'static>(FinalizeRoute<K>);
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
async fn finalize_oracle_rejects_changed_status() -> Result<(), BoxError> {
    let e = run_case("success", true)
        .await
        .expect_err("mutant must differ");
    assert!(e.to_string().contains("/response/status"), "{e}");
    eprintln!("MUTANT-REJECTED: POST /recovery/uploads/{{sessionId}}/finalize :: changed-status");
    Ok(())
}

#[tokio::test]
async fn finalize_oracle_rejects_missing_audit() -> Result<(), BoxError> {
    let e = run_case("no-audit", false)
        .await
        .expect_err("missing audit mutant must differ");
    assert!(e.to_string().contains("/audit"), "{e}");
    eprintln!("MUTANT-REJECTED: POST /recovery/uploads/{{sessionId}}/finalize :: no-audit");
    Ok(())
}

async fn mutant_worker(
    owner: &tokio_postgres::Client,
    dsn: &str,
    kind: &str,
) -> Result<(String, String), BoxError> {
    let id: String = owner
        .query_one("SELECT replace(gen_random_uuid()::text,'-','')", &[])
        .await?
        .get(0);
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid mutant schema id".into());
    }
    let schema = format!("gofree_blobs1_mutant_{id}");
    let mut definition:String=owner.query_one("SELECT pg_get_functiondef('public.mail_recovery_artifact_quarantine(bigint,uuid,uuid,jsonb,text,text)'::regprocedure)",&[]).await?.get(0);
    let old = "CREATE OR REPLACE FUNCTION public.mail_recovery_artifact_quarantine(";
    if definition.matches(old).count() != 1 {
        return Err("mutant function signature changed".into());
    }
    definition = definition.replacen(
        old,
        &format!("CREATE OR REPLACE FUNCTION {schema}.mail_recovery_artifact_quarantine("),
        1,
    );
    if kind == "no-audit" {
        let start = definition
            .find("PERFORM audit_write(")
            .ok_or("audit call moved")?;
        let end = start
            + definition[start..]
                .find(';')
                .ok_or("audit call incomplete")?
            + 1;
        definition.replace_range(start..end, "NULL;");
    } else if kind == "no-notify" {
        let start = definition
            .find("PERFORM app_notify(")
            .ok_or("notify call moved")?;
        let end = start
            + definition[start..]
                .find(';')
                .ok_or("notify call incomplete")?
            + 1;
        definition.replace_range(start..end, "NULL;");
    } else if kind == "double-bump" {
        let point = "    RETURN jsonb_build_object('id',p_quarantine_id";
        if definition.matches(point).count() != 1 {
            return Err("final return moved".into());
        }
        definition=definition.replacen(point,&format!("    PERFORM bump_email_state(v_session.mailbox_id); PERFORM bump_email_state(v_session.mailbox_id);\n{point}"),1);
    } else {
        return Err("unknown family mutant".into());
    }
    let sql=format!("BEGIN; CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO PUBLIC; {definition}; COMMIT;");
    if let Err(error) = owner.batch_execute(&sql).await {
        let _ = owner.batch_execute("ROLLBACK").await;
        return Err(error.into());
    }
    if dsn.contains("options=") {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
        return Err("mutant DSN already has options".into());
    }
    let dsn = if dsn.starts_with("postgres://") || dsn.starts_with("postgresql://") {
        format!(
            "{dsn}{}options=-csearch_path%3D{schema}%2Cpublic",
            if dsn.contains('?') { '&' } else { '?' }
        )
    } else {
        format!("{dsn} options='-csearch_path={schema},public'")
    };
    Ok((dsn, schema))
}

#[tokio::test]
async fn finalize_oracle_rejects_missing_notify() -> Result<(), BoxError> {
    let e = run_case("no-notify", false)
        .await
        .expect_err("missing notify mutant must differ");
    assert!(e.to_string().contains("/notify"), "{e}");
    eprintln!("MUTANT-REJECTED: POST /recovery/uploads/{{sessionId}}/finalize :: no-notify");
    Ok(())
}

#[tokio::test]
async fn finalize_oracle_rejects_double_state_bump() -> Result<(), BoxError> {
    let e = run_case("double-bump", false)
        .await
        .expect_err("double bump mutant must differ");
    assert!(e.to_string().contains("/effects"), "{e}");
    eprintln!("MUTANT-REJECTED: POST /recovery/uploads/{{sessionId}}/finalize :: double-bump");
    Ok(())
}
