//! Exact scoped bearer download, observed through the real front door.
mod common;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hyper::{Request, Response};
use serde_json::{Value, json};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    Config, Gateway, RouteTable, TrustedProxies,
    attachment::{AttachmentCommands, AttachmentRoute},
    recovery_worker::S3Store,
};
use setjoin_pg::ScopedExecutor;
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[tokio::test]
async fn scoped_attachment_download_rechecks_live_binding() -> Result<(), common::BoxError> {
    run_case("success", false).await
}

async fn run_case(case: &str, mutant: bool) -> Result<(), common::BoxError> {
    let skip_gate = case.ends_with("-gate-mutant");
    let case = case.strip_suffix("-gate-mutant").unwrap_or(case);
    let _serial = common::recovery::SERIAL.lock().await;
    let Some(db) = Db::for_case("attachment-transfer") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "blobs1-attachment").await?;
    let hash = format!("{:x}", Sha256::digest(b"scoped attachment"));
    let foreign = fixture::account(&owner, "blobs1-attachment-foreign").await?;
    let caller = if matches!(case, "foreign" | "condition-foreign") || case.starts_with("delegate-")
    {
        &foreign
    } else {
        &account
    };
    let gated = case.starts_with("gate-");
    let gate_config = owner
        .query(
            "SELECT key,value::text FROM system_config WHERE key=ANY($1)",
            &[&vec!["ca_break_glass_user_ids", "ca_fail_mode"]],
        )
        .await?;
    let flags = owner
        .query(
            "SELECT key,enabled FROM feature_toggles WHERE key=ANY($1)",
            &[&vec![
                "feature.offline_mail",
                "feature.connectivity_aware_sync",
                "feature.cae_runtime",
                "feature.conditional_access",
                "feature.device_trust_enforcement",
                "feature.device_lockdown",
                "feature.token_binding",
            ]],
        )
        .await?;
    let result=async {
 owner.batch_execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.offline_mail',true),('feature.connectivity_aware_sync',true) ON CONFLICT(key) DO UPDATE SET enabled=true").await?;
 let policy:i64=owner.query_one("INSERT INTO offline_policies(name,scope_type,scope_id,enabled,require_approval,connectivity_sync_mode,automatic_network_max) VALUES('blobs1-oracle','user',$1,true,false,'execute','unmetered') RETURNING id",&[&caller.user]).await?.get(0);
 let device:i64=owner.query_one("INSERT INTO user_devices(user_id,device_name,platform,fingerprint_hash,offline_opt_in,offline_approval) VALUES($1,'blobs1-device','desktop',sha256('blobs1-fingerprint'::bytea),true,'approved') RETURNING id",&[&caller.user]).await?.get(0);
 owner.execute("INSERT INTO blobs(sha256,minio_ref,size_bytes,content_type,ref_count) VALUES($1,$1,17,'text/plain',0)",&[&hash]).await?;
 owner.execute("INSERT INTO message_attachments(message_id,received_at,blob_sha256,filename,content_type,disposition,size_bytes) SELECT id,received_at,$1,'x.txt','text/plain','attachment',17 FROM messages WHERE id=$2 AND mailbox_id=$3",&[&hash,&account.two_labels,&account.mailbox]).await?;
 if gated {
   let enabled = match case {
     "gate-revoked-device" | "gate-allow-previous" => vec!["feature.device_trust_enforcement"],
     "gate-lockdown" => vec!["feature.conditional_access", "feature.device_lockdown"],
     "gate-ca-block" | "gate-revoked-session" | "gate-revoked-family" => vec!["feature.cae_runtime", "feature.conditional_access"],
     _ => unreachable!(),
   };
   owner.execute("UPDATE feature_toggles SET enabled=(key=ANY($1)) WHERE key IN ('feature.cae_runtime','feature.conditional_access','feature.device_trust_enforcement','feature.device_lockdown','feature.token_binding')", &[&enabled]).await?;
   if case == "gate-revoked-device" {
     owner.execute("INSERT INTO user_devices(user_id,device_name,platform,fingerprint_hash,offline_approval) VALUES($1,'Revoked sibling','desktop',sha256('blobs1-fingerprint'::bytea),'revoked')", &[&foreign.user]).await?;
   }
   owner.execute("INSERT INTO system_config(key,value) VALUES('ca_break_glass_user_ids',$1::text::jsonb),('ca_fail_mode','\"closed\"'::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value", &[&json!([foreign.user]).to_string()]).await?;
   if case == "gate-ca-block" {
     owner.execute("INSERT INTO conditional_access_policies(name,priority,enabled,state,scope_type,scope_target,conditions,actions) VALUES('authzgates-attachment-block',1,true,'on','user',$1,'{}','{\"grants\":[{\"type\":\"block\"}],\"reason\":\"attachment blocked\"}')", &[&caller.user.to_string()]).await?;
   }
   if matches!(case,"gate-revoked-session" | "gate-revoked-family") {
     owner.execute("INSERT INTO session_revocations(user_id,scope,jti,family_id,reason,expires_at) VALUES($1,$2,'blobs1-derived','blobs1-family','authzgates-test',now()+interval '1 hour')", &[&caller.user,&if case=="gate-revoked-family"{"family"}else{"jti"}]).await?;
   }
 }
 let policy_json:String=owner.query_one("SELECT offline_effective_policy_snapshot($1,$2)::text",&[&caller.mailbox,&device]).await?.get(0);
 // Go hashes json.RawMessage from PostgreSQL (including JSONB's whitespace).
 let generation=format!("{:x}",Sha256::digest(policy_json.as_bytes()));
 let now=chrono::Utc::now().timestamp();
 let target=if case=="owner-other-account"{foreign.mailbox}else if case.starts_with("delegate-")&&case!="delegate-wrong-account"{account.mailbox}else{caller.mailbox};
 let claims=json!({"uid":caller.user,"email":"x@test","typ":"access","scp":"mail-attachment","jti":"blobs1-derived","fam":"blobs1-family","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+300,"device":{"id":"blobs1-fingerprint","platform":"desktop","trust_tier":"trusted","compliance_status":"ok","wipe_requested":false},"attachment":{"sha256":hash,"account_id":target,"mailbox_id":caller.mailbox,"device_id":device,"device_fingerprint":"blobs1-fingerprint","policy_generation":generation,"origin_jti":"blobs1-origin","origin_iat":now-30}});
 let token=sign(&claims);
 if case.starts_with("delegate-")&&case!="delegate-none"{
   let permission=match case {"delegate-send-as"=>"send_as","delegate-send-on-behalf"=>"send_on_behalf","delegate-full"=>"full_access","delegate-calendar"=>"manage_calendar",_=>"read"};
   let grantee=if case=="delegate-other-owner"{account.user}else{foreign.user};
   owner.execute("INSERT INTO mailbox_delegates(mailbox_id,user_id,permission,granted_by) VALUES($1,$2,$3,$4)",&[&account.mailbox,&grantee,&permission,&account.user]).await?;
 }
 let storage_case=case.to_owned();
 let endpoint=common::fake_upstream(move |r|{let case=storage_case.clone();async move{
   if case=="storage-missing"&&r.uri().query()!=Some("location=") {return Response::builder().status(404).header("content-type","application/xml").body(common::full("<Error><Code>NoSuchKey</Code><Message>missing</Message></Error>")).unwrap();}
   attachment_object(r,case=="storage-size").await
 }}).await;
 let oracle=if case=="gate-allow-previous" {
   common::go_oracle::start_named_with_env(&db,endpoint,"gofree-authzgates-attachment",&[("JWT_MAIL_ATTACHMENT_SECRET","rotated-attachment-secret-for-recording".into()),("JWT_MAIL_ATTACHMENT_PREVIOUS_SECRET","blobs1-test-jwt-secret-for-recording".into())]).await?
 }else{common::go_oracle::start(&db,endpoint).await?};let recording=oracle.is_some();
 let shared_store=Arc::new(S3Store::new(&format!("http://{endpoint}"),"mailblobs","test-access","test-secret")?);
 let route=AttachmentRoute(Arc::new(AttachmentCommands{exec:ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?,worker_exec:ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?,issuer:"mailserver".into(),secret:if case=="gate-allow-previous"{b"rotated-attachment-secret-for-recording".to_vec()}else{b"blobs1-test-jwt-secret-for-recording".to_vec()},previous_secret:(case=="gate-allow-previous").then(||b"blobs1-test-jwt-secret-for-recording".to_vec()),store:shared_store.clone()}));
 let mut inv:Value=serde_json::from_str(include_str!("../route-inventory.json"))?;let entry=inv["routes"].as_array_mut().unwrap().iter_mut().find(|r|r["path"]=="/mail-attachment/{sha256}").unwrap();entry["state"]=json!("ON");entry["upstream"]=json!("local-rust");
 let runtime=setjoin_gateway::runtime_access::RuntimeAccess::new(ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?,Arc::new(common::recovery_keys()),"mailserver".into())
    .with_attachment_secrets(if case=="gate-allow-previous"{b"rotated-attachment-secret-for-recording".to_vec()}else{b"blobs1-test-jwt-secret-for-recording".to_vec()},(case=="gate-allow-previous").then(||b"blobs1-test-jwt-secret-for-recording".to_vec()))
    .with_workers(ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?,setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?)
    .with_device_secret(b"blobs1-test-jwt-secret-for-recording".to_vec(),setjoin_config_secret::CryptoProfile::Standard);
 let table=if recording {RouteTable::proxy_all()} else if mutant {RouteTable::proxy_all().with(ChangedStatus(route)).with_runtime(runtime)} else if skip_gate {RouteTable::proxy_all().with(route)} else {RouteTable::proxy_all().with(route).with_runtime(runtime)};
 let table=if recording {table}else{table.with(setjoin_gateway::blobs::BlobRoute(Arc::new(setjoin_gateway::blobs::BlobCommands{
   exec:ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?,worker_exec:ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?,keys:common::recovery_keys(),issuer:"mailserver".into(),store:shared_store,
 })))};
 let g=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},table)?.with_inventory(&inv.to_string())?;
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let server=tokio::spawn(g.serve(listener));
 let audit_start:i64=owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
 if case=="warm-then-attachment"{
   let warm=common::send(address,Request::get(format!("/api/blobs/{hash}")).header("host","mail.test").header("authorization",format!("Bearer {}",common::recovery_token(account.user))).body(common::full(""))?).await;
   assert_eq!(warm.status(),200);assert_eq!(common::body_bytes(warm).await.as_ref(),b"scoped attachment");
 }
 let mut before_revocation=None;
 if case=="delegate-revoked" {
   let response=common::send(address,Request::get(format!("/mail-attachment/{hash}")).header("host","mail.test").header("authorization",format!("Bearer {token}")).body(common::full(""))?).await;
   let status=response.status().as_u16();let body=String::from_utf8(common::body_bytes(response).await.to_vec())?;
   if status!=200||body!="scoped attachment"{server.abort();let _=server.await;return Err(format!("delegate initial read: {status} {body}").into());}
   before_revocation=Some(json!({"status":status,"body":body}));
   owner.execute("DELETE FROM mailbox_delegates WHERE mailbox_id=$1 AND user_id=$2",&[&account.mailbox,&foreign.user]).await?;
 }
 let mut request=Request::builder();
 for (name,value) in read_headers(case,&hash) {request=request.header(name,value);}
 let response=common::send(address,request.method(if case=="gate-allow-previous"||matches!(case,"range-head"|"condition-head"){"HEAD"}else{"GET"}).uri(format!("/mail-attachment/{}",if case=="invalid"{"invalid"}else{&hash})).header("host","mail.test").header("origin","http://mail.test").header("x-request-id","blobs1-attachment-oracle").header(if case=="gate-allow-previous"{"cookie"}else{"authorization"},if case=="gate-allow-previous"{format!("access_token={token}")}else{format!("Bearer {token}")}).body(common::full(""))?).await;
 let status=response.status().as_u16();let boundary=response.headers().get("content-type").and_then(|h|h.to_str().ok()).and_then(|h|h.strip_prefix("multipart/byteranges; boundary=")).map(str::to_owned);
 if let Some(b)=&boundary {assert_eq!(b.len(),60);assert!(b.bytes().all(|c|c.is_ascii_hexdigit()));}
 let mut headers=serde_json::Map::new();for name in response.headers().keys(){headers.insert(name.to_string(),json!(response.headers().get_all(name).iter().map(|v|if name=="date"{"<timestamp>".into()}else if name=="etag"{assert_eq!(v.to_str().unwrap(),format!("\"{hash}\""));"\"<hash>\"".into()}else if name=="content-disposition"{assert_eq!(v.to_str().unwrap(),format!("attachment; filename=\"{hash}\""));"attachment; filename=\"<hash>\"".into()}else if let Some(b)=&boundary{v.to_str().unwrap().replace(b,"<boundary>")}else{v.to_str().unwrap().to_owned()}).collect::<Vec<_>>()));}
 let body=String::from_utf8(common::body_bytes(response).await.to_vec())?;let body=if let Some(b)=&boundary{body.replace(b,"<boundary>")}else{body};
 let metrics=if !recording {
   let response=common::send(address,Request::get("/_gateway/metrics").body(common::full(""))?).await;
   String::from_utf8(common::body_bytes(response).await.to_vec())?
 }else{String::new()};
 server.abort();let _=server.await;
 if !recording && !metrics.lines().any(|l|l=="setjoin_gateway_proxied_to_go_total 0") {return Err(format!("attachment replay forwarded: {metrics}").into());}
 if gated {
   let audit:i64=owner.query_one("SELECT count(*) FROM admin_audit_log WHERE id>$1",&[&audit_start]).await?.get(0);
   if audit!=0 {return Err(format!("unexpected gate audit rows: {audit}").into());}
 }

 let mut observation=json!({"request":{"method":if case=="gate-allow-previous"||matches!(case,"range-head"|"condition-head"){"HEAD"}else{"GET"},"path":"/mail-attachment/{sha256}"},"response":{"status":status,"headers":headers,"body":body},"effects":[],"audit":[],"notify":[]});
 if let Some(before)=before_revocation{observation["before_revocation"]=before;}
 let extra=read_headers(case,"<hash>"); if !extra.is_empty(){observation["request"]["headers"]=json!(extra.into_iter().collect::<std::collections::BTreeMap<_,_>>());}
 let suffix=if matches!(case,"range-head"|"condition-head") {
   observation["request"]["method"]=json!("GET");observation["request"]["external_method"]=json!("HEAD");"-qualified"
 }else{""};
 let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/blobs/goldens/attachment-transfer-{case}{suffix}.json"));
 if recording{if status!=if matches!(case,"foreign"|"condition-foreign"|"storage-missing"|"storage-size"|"delegate-calendar"|"delegate-none"|"delegate-other-owner"|"delegate-wrong-account"|"delegate-revoked"){404}else if case=="invalid"{401}else if matches!(case,"gate-revoked-session"|"gate-revoked-family"){401}else if gated&&case!="gate-allow-previous"{403}else if matches!(case,"conditional-match"|"condition-weak-list"|"condition-head"|"condition-not-modified-range"|"delegate-conditional"){304}else if matches!(case,"condition-if-match-weak"|"condition-precedence"){412}else if matches!(case,"condition-if-range-match"|"delegate-range"){206}else if matches!(case,"range-invalid"|"range-unsatisfiable"){416}else if case.starts_with("range-"){206}else{200}{return Err(format!("Go expected success, got {status}: {body}").into());}let value=json!({"format":1,"route":"GET /mail-attachment/{sha256}","case":case,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}); if path.exists(){let expected:Value=serde_json::from_slice(&std::fs::read(&path)?)?;setjoin_conformance::golden::compare(&expected,&value)?;}else{setjoin_conformance::golden::record(&path,&value)?;}}else{let expected:Value=serde_json::from_slice(&std::fs::read(path)?)?;setjoin_conformance::golden::compare(&expected["observation"],&observation)?;eprintln!("GOLDEN-REPLAY: GET /mail-attachment/{{sha256}} :: {case}");}
 owner.execute("DELETE FROM offline_policies WHERE id=$1",&[&policy]).await?;
 let _=mutant;Ok::<_,common::BoxError>(())
 }.await;
    owner
        .execute(
            "DELETE FROM offline_policies WHERE scope_type='user' AND scope_id=ANY($1)",
            &[&vec![account.user, foreign.user]],
        )
        .await?;
    owner.execute("DELETE FROM conditional_access_policies WHERE name='authzgates-attachment-block' AND scope_target=$1",&[&caller.user.to_string()]).await?;
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM session_revocations WHERE user_id IN ({},{}) AND reason='authzgates-test'; COMMIT;",account.user,foreign.user)).await?;
    common::remove_blob_account(&owner, &account).await?;
    common::remove_blob_account(&owner, &foreign).await?;
    owner
        .execute("DELETE FROM blobs WHERE sha256=$1", &[&hash])
        .await?;
    for key in [
        "feature.offline_mail",
        "feature.connectivity_aware_sync",
        "feature.cae_runtime",
        "feature.conditional_access",
        "feature.device_trust_enforcement",
        "feature.device_lockdown",
        "feature.token_binding",
    ] {
        if let Some(row) = flags.iter().find(|r| r.get::<_, String>(0) == key) {
            owner
                .execute(
                    "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                    &[&key, &row.get::<_, bool>(1)],
                )
                .await?;
        } else {
            owner
                .execute("DELETE FROM feature_toggles WHERE key=$1", &[&key])
                .await?;
        }
    }
    if gated {
        for key in ["ca_break_glass_user_ids", "ca_fail_mode"] {
            if let Some(row) = gate_config.iter().find(|r| r.get::<_, String>(0) == key) {
                owner.execute("INSERT INTO system_config(key,value) VALUES($1,$2::text::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value", &[&key,&row.get::<_,String>(1)]).await?;
            } else {
                owner
                    .execute("DELETE FROM system_config WHERE key=$1", &[&key])
                    .await?;
            }
        }
    }
    result
}
fn sign(claims: &Value) -> String {
    let header = URL_SAFE_NO_PAD
        .encode(r#"{"alg":"HS256","kid":"mailserver-mail-attachment-1","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let prk = ring::hkdf::Salt::new(
        ring::hkdf::HKDF_SHA256,
        b"mailserver-mail-attachment-token-v1",
    )
    .extract(b"blobs1-test-jwt-secret-for-recording");
    let mut key = [0u8; 32];
    prk.expand(&[], ring::hkdf::HKDF_SHA256)
        .unwrap()
        .fill(&mut key)
        .unwrap();
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key);
    let signature = ring::hmac::sign(&key, format!("{header}.{payload}").as_bytes());
    format!(
        "{header}.{payload}.{}",
        URL_SAFE_NO_PAD.encode(signature.as_ref())
    )
}

#[tokio::test]
async fn scoped_token_cannot_read_a_foreign_mailbox_attachment() -> Result<(), common::BoxError> {
    run_case("foreign", false).await
}

#[tokio::test]
async fn scoped_token_rejects_a_different_path_hash() -> Result<(), common::BoxError> {
    run_case("invalid", false).await
}

struct ChangedStatus(AttachmentRoute);
impl setjoin_gateway::Intercept for ChangedStatus {
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
async fn attachment_oracle_rejects_changed_status() -> Result<(), common::BoxError> {
    let e = run_case("success", true)
        .await
        .expect_err("mutant must differ");
    assert!(e.to_string().contains("/response/status"), "{e}");
    eprintln!("MUTANT-REJECTED: GET /mail-attachment/{{sha256}} :: changed-status");
    Ok(())
}

#[tokio::test]
async fn attachment_runtime_refuses_revoked_device() -> Result<(), common::BoxError> {
    run_case("gate-revoked-device", false).await
}

#[tokio::test]
async fn attachment_runtime_refuses_revoked_session() -> Result<(), common::BoxError> {
    run_case("gate-revoked-session", false).await
}
#[tokio::test]
async fn attachment_runtime_refuses_revoked_family() -> Result<(), common::BoxError> {
    run_case("gate-revoked-family", false).await
}
#[tokio::test]
async fn attachment_runtime_enforces_lockdown() -> Result<(), common::BoxError> {
    run_case("gate-lockdown", false).await
}
#[tokio::test]
async fn attachment_runtime_enforces_ca_block() -> Result<(), common::BoxError> {
    run_case("gate-ca-block", false).await
}
#[tokio::test]
async fn attachment_runtime_allows_retiring_secret_cookie_head() -> Result<(), common::BoxError> {
    run_case("gate-allow-previous", false).await
}
#[tokio::test]
async fn attachment_runtime_oracle_rejects_skipped_gate() -> Result<(), common::BoxError> {
    let e = run_case("gate-revoked-device-gate-mutant", false)
        .await
        .expect_err("skipped gate must differ");
    assert!(e.to_string().contains("/response/status"), "{e}");
    eprintln!("MUTANT-REJECTED: GET /mail-attachment/{{sha256}} :: gate-skipped");
    Ok(())
}

#[tokio::test]
async fn attachment_etag_match_returns_not_modified_without_go() -> Result<(), common::BoxError> {
    run_case("conditional-match", false).await
}

fn read_headers(case: &str, hash: &str) -> Vec<(&'static str, String)> {
    match case {
        "delegate-range" => vec![("range", "bytes=2-5".into())],
        "delegate-conditional" | "delegate-none" => vec![("if-none-match", "*".into())],
        "conditional-match" => vec![("if-none-match", format!("\"{hash}\""))],
        "condition-weak-list" => vec![("if-none-match", format!("\"other\", W/\"{hash}\""))],
        "condition-head" => vec![("if-none-match", "*".into())],
        "condition-no-match" => vec![("if-none-match", "\"other\"".into())],
        "condition-if-match" => vec![("if-match", format!("\"{hash}\""))],
        "condition-if-match-weak" => vec![("if-match", format!("W/\"{hash}\""))],
        "condition-if-match-wildcard" => vec![("if-match", "*".into())],
        "condition-precedence" => vec![
            ("if-match", "\"other\"".into()),
            ("if-none-match", format!("\"{hash}\"")),
        ],
        "condition-if-range-match" => vec![
            ("range", "bytes=2-5".into()),
            ("if-range", format!("\"{hash}\"")),
        ],
        "condition-if-range-miss" => vec![
            ("range", "bytes=2-5".into()),
            ("if-range", "\"other\"".into()),
        ],
        "condition-if-range-weak" => vec![
            ("range", "bytes=2-5".into()),
            ("if-range", format!("W/\"{hash}\"")),
        ],
        "condition-if-range-date" => vec![
            ("range", "bytes=2-5".into()),
            ("if-range", "Sat, 31 Oct 2026 00:00:00 GMT".into()),
        ],
        "condition-modified" => vec![("if-modified-since", "Fri, 01 Jan 2100 00:00:00 GMT".into())],
        "condition-unmodified" => vec![(
            "if-unmodified-since",
            "Mon, 01 Jan 1900 00:00:00 GMT".into(),
        )],
        "condition-not-modified-range" => vec![
            ("range", "invalid".into()),
            ("if-none-match", format!("\"{hash}\"")),
        ],
        "condition-foreign" => vec![("if-none-match", "*".into())],
        "range-single" | "range-head" => vec![("range", "bytes=2-5".into())],
        "range-suffix" => vec![("range", "bytes=-5".into())],
        "range-open" => vec![("range", "bytes=12-".into())],
        "range-invalid" => vec![("range", "bytes=wrong".into())],
        "range-unsatisfiable" => vec![("range", "bytes=99-".into())],
        "range-multipart" => vec![("range", "bytes=0-1,14-16".into())],
        _ => vec![],
    }
}

async fn attachment_object(
    r: Request<hyper::body::Incoming>,
    wrong_size: bool,
) -> Response<common::TestBody> {
    if r.uri().query() == Some("location=") {
        return Response::new(common::full(
            "<LocationConstraint>us-east-1</LocationConstraint>",
        ));
    }
    let mut response = Response::builder()
        .header("content-type", "text/plain")
        .header("last-modified", "Sat, 31 Oct 2026 00:00:00 GMT")
        .header("etag", "\"fixture\"");
    let content: &[u8] = if wrong_size {
        b"scoped attachment!"
    } else {
        b"scoped attachment"
    };
    let mut bytes = content;
    if r.method() == hyper::Method::GET {
        if let Some(range) = r.headers().get("range") {
            let (start, end) = range
                .to_str()
                .unwrap()
                .strip_prefix("bytes=")
                .unwrap()
                .split_once('-')
                .unwrap();
            let start = start.parse::<usize>().unwrap();
            let end = if end.is_empty() {
                content.len() - 1
            } else {
                end.parse::<usize>().unwrap()
            };
            bytes = &content[start..=end];
            response = response.status(206).header(
                "content-range",
                format!("bytes {start}-{end}/{}", content.len()),
            );
        }
    }
    response
        .header("content-length", bytes.len())
        .body(common::full(if r.method() == hyper::Method::HEAD {
            Vec::new()
        } else {
            bytes.to_vec()
        }))
        .unwrap()
}

#[tokio::test]
async fn attachment_head_range_matches_go() -> Result<(), common::BoxError> {
    run_case("range-head", false).await
}
#[tokio::test]
async fn attachment_head_etag_matches_go() -> Result<(), common::BoxError> {
    run_case("condition-head", false).await
}

macro_rules! attachment_read_case {
    ($name:ident,$case:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            run_case($case, false).await
        }
    };
}
attachment_read_case!(attachment_range_single, "range-single");
attachment_read_case!(attachment_range_suffix, "range-suffix");
attachment_read_case!(attachment_range_open, "range-open");
attachment_read_case!(attachment_range_invalid, "range-invalid");
attachment_read_case!(attachment_range_unsatisfiable, "range-unsatisfiable");
attachment_read_case!(attachment_range_multipart, "range-multipart");
attachment_read_case!(attachment_condition_weak_list, "condition-weak-list");
attachment_read_case!(attachment_condition_no_match, "condition-no-match");
attachment_read_case!(attachment_condition_if_match, "condition-if-match");
attachment_read_case!(
    attachment_condition_if_match_weak,
    "condition-if-match-weak"
);
attachment_read_case!(
    attachment_condition_if_match_wildcard,
    "condition-if-match-wildcard"
);
attachment_read_case!(attachment_condition_precedence, "condition-precedence");
attachment_read_case!(
    attachment_condition_if_range_match,
    "condition-if-range-match"
);
attachment_read_case!(
    attachment_condition_if_range_miss,
    "condition-if-range-miss"
);
attachment_read_case!(
    attachment_condition_if_range_weak,
    "condition-if-range-weak"
);
attachment_read_case!(
    attachment_condition_if_range_date,
    "condition-if-range-date"
);
attachment_read_case!(attachment_condition_modified, "condition-modified");
attachment_read_case!(attachment_condition_unmodified, "condition-unmodified");
attachment_read_case!(
    attachment_condition_not_modified_range,
    "condition-not-modified-range"
);
attachment_read_case!(attachment_condition_foreign, "condition-foreign");

attachment_read_case!(
    attachment_rechecks_storage_after_blob_cache_warm,
    "warm-then-attachment"
);
attachment_read_case!(
    attachment_missing_storage_uses_go_plain_not_found,
    "storage-missing"
);
attachment_read_case!(
    attachment_wrong_storage_size_uses_go_plain_not_found,
    "storage-size"
);
attachment_read_case!(attachment_delegate_read, "delegate-read");
attachment_read_case!(attachment_delegate_send_as, "delegate-send-as");
attachment_read_case!(
    attachment_delegate_send_on_behalf,
    "delegate-send-on-behalf"
);
attachment_read_case!(attachment_delegate_full, "delegate-full");
attachment_read_case!(attachment_delegate_calendar, "delegate-calendar");
attachment_read_case!(attachment_delegate_none, "delegate-none");
attachment_read_case!(attachment_delegate_other_owner, "delegate-other-owner");
attachment_read_case!(attachment_delegate_wrong_account, "delegate-wrong-account");
attachment_read_case!(attachment_delegate_revoked, "delegate-revoked");
attachment_read_case!(attachment_delegate_range, "delegate-range");
attachment_read_case!(attachment_delegate_conditional, "delegate-conditional");
attachment_read_case!(attachment_owner_other_account, "owner-other-account");
