//! Frozen Go at the HTTP seam, including committed rows and S3 I/O.
mod common;
#[path = "common/office_fixture.rs"]
mod office_fixture;
#[path = "common/office_go.rs"]
mod office_go;
#[path = "common/office_provider.rs"]
mod office_provider;
#[path = "common/office_s3.rs"]
mod office_s3;
use futures_util::FutureExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::sync::{Arc, Mutex};
macro_rules! case {
    ($name:ident,$route:literal,$case:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            run($route, $case, None).await
        }
    };
}
case!(
    wopi_rejects_encoded_id_separator,
    "info",
    "escaped-id-slash"
);
case!(check_file_info_success, "info", "success");
case!(check_file_info_cross_tenant, "info", "foreign");
case!(check_file_info_invalid_input, "info", "invalid");
case!(wopi_requires_provider_proof, "info", "proof-missing");
case!(wopi_unicode_simple_uppercase, "info", "proof-unicode");
case!(wopi_verifies_current_proof, "info", "proof-valid");
case!(wopi_accepts_rotated_key, "info", "proof-rotated");
case!(
    wopi_accepts_current_in_old_header,
    "info",
    "proof-old-header"
);
case!(wopi_rejects_old_in_old_header, "info", "proof-double-old");
case!(wopi_rejects_stale_proof, "info", "proof-stale");
case!(wopi_rejects_future_proof, "info", "proof-future");
case!(wopi_rejects_corrupt_proof, "info", "proof-corrupt");
case!(wopi_reuses_cached_proof_key, "info", "proof-cache");
case!(wopi_decodes_route_segments, "info", "escaped-path");
case!(get_file_head, "get", "head");
case!(wopi_feature_off_is_hidden, "info", "feature-off");
case!(
    wopi_query_fields_preserve_launch_credential,
    "info",
    "query-fields"
);
case!(get_file_success, "get", "success");
case!(get_file_tampered_chunk, "get", "tampered");
case!(wopi_preserves_request_id, "info", "request-id");
case!(get_file_cross_tenant, "get", "foreign");
case!(get_file_invalid_input, "get", "invalid");
case!(lock_unicode_conflict, "lock", "unicode-header");
case!(lock_relock_refresh_unlock, "lock", "lock-operations");
case!(lock_success, "lock", "success");
case!(lock_cross_tenant, "lock", "foreign");
case!(lock_invalid_input, "lock", "invalid");
case!(lock_repeat, "lock", "repeat");
case!(put_file_chunk_quota_rollback, "put", "chunk-quota");
case!(put_file_chunk_permission_rollback, "put", "chunk-forbidden");
case!(put_file_chunk_missing_rollback, "put", "chunk-missing");
case!(put_file_chunk_invalid_rollback, "put", "chunk-invalid");
case!(put_file_chunk_conflict_rollback, "put", "chunk-conflict");
case!(put_file_success, "put", "success");
case!(put_file_cross_tenant, "put", "foreign");
case!(put_file_invalid_input, "put", "invalid");
case!(put_file_repeat, "put", "repeat");
case!(put_file_acl_mode, "put", "acl");

async fn run(route: &str, case: &str, mutation: Option<&str>) -> Result<(), common::BoxError> {
    let _serial = office_fixture::SERIAL.lock().await;
    let mutant = mutation.is_some();
    let Some(db) = Db::for_case("office-wopi") else {
        return Ok(());
    };
    let (c, seed) = office_fixture::seed(&db).await?;
    let fault = if case.starts_with("chunk-") {
        let name = format!("gofree_office1_fault_{}", seed.account.user);
        let code = match case {
            "chunk-quota" => "BZ148",
            "chunk-forbidden" => "BZ140",
            "chunk-missing" => "BZ139",
            "chunk-invalid" => "BZ141",
            _ => "BZ149",
        };
        c.batch_execute(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Office1 planted reducer fault' USING ERRCODE='{code}'; END $$; CREATE TRIGGER {name} BEFORE INSERT OR UPDATE ON drive_upload_claims FOR EACH ROW WHEN (NEW.user_id={}) EXECUTE FUNCTION {name}();",seed.account.user)).await?;
        Some(name)
    } else {
        None
    };
    let mut victim = None;
    let mut owned_schema = None;
    let result=std::panic::AssertUnwindSafe(async{
 let mut target=seed.node.to_string();
 if case=="foreign"{
 let a=setjoin_conformance::fixture::account(&c,"office1-victim").await?;
 let space:i64=c.query_one("SELECT drive_space_create($1,'Office victim','regular')",&[&a.user]).await?.get(0);
 let node:i64=c.query_one("SELECT drive_node_create($1,$2,NULL,'file','victim.docx')",&[&a.user,&space]).await?.get(0);
 let chunk="84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882";
 c.query_one("SELECT drive_chunk_register($1,$2,$3,10)",&[&a.user,&space,&chunk]).await?;
 let manifest=json!([{"sha256":chunk,"size":10}]).to_string();let raw:String=c.query_one("SELECT drive_file_put_version($1,$2,repeat('a',64),10,'application/octet-stream',NULL,$3::text::jsonb,'victim','test')::text",&[&a.user,&node,&manifest]).await?.get(0);let version:Value=serde_json::from_str(&raw)?;let version=version["versionId"].as_i64().ok_or("victim version")?;
 let hash=setjoin_office::token_hash(&format!("office1-victim-token-{}",a.user));c.query_one("SELECT office_launch_begin($1,$2,$3,'office1','victim-device','victim-cohort',$4,3600)",&[&a.user,&node,&version,&hash]).await?;
 target=node.to_string();victim=Some((a,space));
 }else if case=="invalid"&&route!="lock"{target="invalid".into();}
 if case=="proof-missing"{c.batch_execute("UPDATE office_provider_policies SET config=config||'{\"proofMode\":\"required\"}'::jsonb WHERE provider_id='office1'").await?;}
 if case=="feature-off"{c.batch_execute("UPDATE feature_toggles SET enabled=false WHERE key='feature.office_editing'").await?;}
 let provider=if case.starts_with("proof-")&&case!="proof-missing"{Some(office_provider::start_with_document(include_bytes!("../../../tests/conformance/office/provider/discovery-rotation.xml")).await?)}else{None};
 if let Some(provider)=&provider{let config=json!({"proofMode":"required","proofDiscoveryUrl":format!("{}/hosting/discovery",provider.origin),"wopiPublicBaseUrl":if case=="proof-unicode"{"https://mail.test/ᾀß"}else{"https://mail.test"}}).to_string();c.execute("UPDATE office_provider_policies SET config=config||$1::text::jsonb WHERE provider_id='office1'",&[&config]).await?;}
 if case=="acl"{c.execute("UPDATE drive_spaces SET acl_mode='acl' WHERE id=$1",&[&seed.space]).await?;c.batch_execute("UPDATE feature_toggles SET enabled=true WHERE key IN ('feature.drive_node_acl_reads','feature.drive_node_acl_writes')").await?;}
 let io=Arc::new(Mutex::new(Vec::<Value>::new()));let observed=io.clone();let tampered=case=="tampered";
 let s3=common::fake_upstream(move|r|{let observed=observed.clone();async move{
 if r.uri().query()==Some("location="){return Response::new(common::full("<LocationConstraint>us-east-1</LocationConstraint>"));}
 let method=r.method().clone();let copy=r.headers().contains_key("x-amz-copy-source");let object=r.uri().path().starts_with("/mailblobs/drive/")||r.uri().path().starts_with("/mailblobs/tmp/upload/");
 let copy_source=r.headers().get("x-amz-copy-source").and_then(|v|v.to_str().ok()).unwrap_or("").to_owned();
 let content_type=r.headers().get("content-type").and_then(|v|v.to_str().ok()).unwrap_or("").to_owned();
 let uri=r.uri().path().to_owned();let(parts,body)=r.into_parts();let bytes=http_body_util::BodyExt::collect(body).await.unwrap().to_bytes();let request=Request::from_parts(parts,());
 if object{
 let signed=office_s3::observe(&request,&bytes).expect("independently valid S3 signature and body");
 observed.lock().unwrap().push(json!({"method":method.as_str(),"key":normalize_key(&uri),"copy_source":normalize_key(&copy_source),"content_type":content_type,"body":signed["body"],"signature_valid":true}));
 }
 if method==hyper::Method::PUT{return Response::builder().header("etag","\"office1\"").body(common::full(if copy{"<CopyObjectResult><LastModified>2026-10-31T00:00:00.000Z</LastModified><ETag>\"office1\"</ETag></CopyObjectResult>"}else{""})).unwrap();}
 if method==hyper::Method::DELETE{return Response::builder().status(204).body(common::full("")).unwrap();}
 Response::builder().header("content-length","10").header("content-type","application/octet-stream").header("last-modified","Sat, 31 Oct 2026 00:00:00 GMT").header("etag","\"office1\"").body(common::full(if method==hyper::Method::HEAD{""}else if tampered{"xxxxxxxxxx"}else{"0123456789"})).unwrap()
 }}).await;
 let oracle=office_go::start(&db,s3).await?;let recording=oracle.is_some();io.lock().unwrap().clear();
 let command_dsn=if mutation==Some("tenant"){let(dsn,schema)=office_fixture::mutant_dsn(&c,&db,"tenant").await?;owned_schema=Some(schema);dsn}else{db.app.as_deref().unwrap_or(&db.dsn).to_owned()};
 let adapter=setjoin_gateway::office::OfficeRoute::new(setjoin_pg::ScopedExecutor::from_dsn(&command_dsn,4).map_err(|e|e.0)?,Some(Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{s3}"),"mailblobs","test-access","test-secret")?)));
 let adapter=if let Some(provider)=&provider{adapter.with_proof(setjoin_gateway::office_provider::ProofVerifier::with_address(office_provider::address(provider)?))}else{adapter};
 let table=if recording{RouteTable::proxy_all()}else if mutation==Some("status"){RouteTable::proxy_all().with(ChangedStatus(adapter))}else{RouteTable::proxy_all().with(adapter)};
 let mut inventory:Value=serde_json::from_str(setjoin_gateway::inventory::BUNDLED)?;for r in inventory["routes"].as_array_mut().unwrap(){if r["family"]=="F15"{r["state"]="ON".into();r["upstream"]="local-rust".into();}}
 let gateway=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},table)?.with_inventory(&inventory.to_string())?;
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let task=tokio::spawn(gateway.serve(listener));
 let(mut method,pattern)=match route{"get"=>("GET","/office/wopi/files/{id}/contents"),"lock"=>("POST","/office/wopi/files/{id}"),"put"=>("POST","/office/wopi/files/{id}/contents"),_=>("GET","/office/wopi/files/{id}")};
 if case=="head"{method="HEAD";}
 let external=if case=="escaped-id-slash"{format!("/api/office/wopi/files/{target}%2Fcontents?access_token={}",seed.token)}else if case=="escaped-path"{format!("/api/%6fffice/wopi/files/%3{}{}?access_token={}",&target[..1],&target[1..],seed.token)}else if case=="query-fields"{format!("/api{}?foo=1&access_token=%6f{}&extra=2",pattern.replace("{id}",&target),&seed.token[1..])}else{format!("/api{}?access_token={}",pattern.replace("{id}",&target),seed.token)};
 let before=office_fixture::snapshot(&c,&seed).await?;let mut notifications=db.listen("drive").await?;
 let mut step_rows=Vec::new();let mut responses=Vec::new();let count=if case=="lock-operations"{4}else if matches!(case,"repeat"|"proof-cache"|"unicode-header"){2}else{1};
 for index in 0..count{
 if case=="proof-cache"&&index==1{*provider.as_ref().unwrap().document.lock().unwrap()=b"<invalid/>".to_vec();}
 let lock_value=if matches!(case,"unicode-header"|"lock-operations")&&index==0{"Office1-锁🔒"}else if case=="lock-operations"{"Office1-新锁🔑"}else if route=="lock"&&case=="invalid"{""}else{"office1-lock"};
 let override_value=if case=="lock-operations"{["LOCK","UNLOCK_AND_RELOCK","REFRESH_LOCK","UNLOCK"][index]}else{"LOCK"};
 let mut request=Request::builder().method(method).uri(&external).header("host","mail.test").header("x-request-id",if case=="request-id"{"office1-other-request"}else{"office1-oracle"}).header("x-wopi-override",override_value).header("x-wopi-lock",lock_value).header("x-setjoin-operation-key","office1-save");
 if case=="lock-operations"&&index==1{request=request.header("x-wopi-oldlock","Office1-锁🔒");}
 if provider.is_some(){let(timestamp,proof)=signed_proof(&seed.token,external.strip_prefix("/api").unwrap(),case)?;request=request.header("x-wopi-timestamp",timestamp).header(if matches!(case,"proof-old-header"|"proof-double-old"){"x-wopi-proofold"}else{"x-wopi-proof"},proof);}
 let response=common::send(address,request.body(common::full(if route=="put"{"Office1 save"}else{""}))?).await;
 let status=response.status().as_u16();let headers=response.headers().clone();let bytes=common::body_bytes(response).await;
 let expected=if case=="escaped-id-slash"{400}else if case=="unicode-header"&&index==1{409}else if case=="chunk-quota"{507}else if case=="chunk-forbidden"{403}else if case=="chunk-missing"{404}else if case=="chunk-invalid"{422}else if case=="chunk-conflict"{409}else if case=="tampered"{502}else if matches!(case,"foreign"|"proof-missing"|"proof-double-old"|"proof-stale"|"proof-future"|"proof-corrupt"|"feature-off"){404}else if case=="invalid"{400}else{200};if !mutant&&status!=expected{task.abort();return Err(format!("{route}/{case}: expected {expected}, got {status} {bytes:?}").into());}
 let mut body=if headers.get("content-type").is_some_and(|v|v.to_str().unwrap_or("").contains("json")){serde_json::from_slice::<Value>(&bytes)?}else{String::from_utf8(bytes.to_vec())?.into()};
 if status==200&&route=="info"&&!mutant{if body["OwnerId"]!=seed.space.to_string()||body["UserId"]!=seed.account.user.to_string()||body["Version"]!=seed.version.to_string(){task.abort();return Err("wrong CheckFileInfo ownership/version".into());}body["OwnerId"]="<space>".into();body["UserId"]="<actor>".into();body["Version"]="<base-version>".into();}
 if status==200&&route=="put"{if body.get("headVersionId").is_some()&&body["versionId"]!=body["headVersionId"]{task.abort();return Err("save head differs from saved version".into());}for k in ["versionId","headVersionId"]{if body.get(k).is_none(){continue;}if !body[k].is_i64(){return Err("invalid saved version".into());}body[k]="<saved-version>".into();}}
 if let Some(instance)=body.get_mut("instance"){if instance.as_str().is_some_and(|v|!v.is_empty()){*instance=pattern.replace("{id}",if target=="invalid"{"invalid"}else{"{id}"}).into();}}
 let mut normalized=office_fixture::headers(&headers)?;if let Some(version)=normalized.get_mut("x-wopi-itemversion"){let raw=version.as_str().ok_or("version header")?;let current:i64=c.query_one("SELECT base_version_id FROM office_editor_sessions WHERE space_id=$1",&[&seed.space]).await?.get(0);if raw!=current.to_string(){return Err("wrong WOPI version header".into());}*version=if route=="get"{"<base-version>"}else{"<saved-version>"}.into();}
 responses.push(json!({"status":status,"headers":normalized,"body":body}));
 if case=="lock-operations"{step_rows.push(office_fixture::snapshot(&c,&seed).await?);}
 }
 let after=office_fixture::snapshot(&c,&seed).await?;task.abort();let notify:Vec<Value>=notifications.drain(&c).await?.iter().map(|raw|{let mut v:Value=serde_json::from_str(raw).unwrap();if v["spaceId"]==seed.space{v["spaceId"]="<space>".into();}v}).collect();
 let effects=office_fixture::effects(&before,&after);let audit:Vec<_>=after["drive_audit"].as_array().unwrap().iter().filter(|r|!before["drive_audit"].as_array().unwrap().contains(r)).cloned().collect();
 let mut observation=json!({"request":{"method":method,"path":pattern,"external_path":format!("/api{pattern}"),"query":"access_token=<launch-token>","headers":{"x-wopi-override":"LOCK","x-wopi-lock":if route=="lock"&&case=="invalid"{""}else{"office1-lock"},"x-setjoin-operation-key":"office1-save"},"body":if route=="put"{"Office1 save"}else{""}},"response":responses[0],"responses":responses,"effects":effects,"audit":audit,"notify":notify,"storage":*io.lock().unwrap()});
 if case=="escaped-id-slash"{observation["request"]["external_path"]="/api/office/wopi/files/{id}%2Fcontents".into();}
 if matches!(case,"unicode-header"|"lock-operations"){observation["request"]["headers"]["x-wopi-lock"]="Office1-锁🔒".into();observation["lock_requests"]=if case=="unicode-header"{json!([{"override":"LOCK","value":"Office1-锁🔒"},{"override":"LOCK","value":"office1-lock"}])}else{json!([{"override":"LOCK","value":"Office1-锁🔒"},{"override":"UNLOCK_AND_RELOCK","value":"Office1-新锁🔑","old":"Office1-锁🔒"},{"override":"REFRESH_LOCK","value":"Office1-新锁🔑"},{"override":"UNLOCK","value":"Office1-新锁🔑"}])};}if case=="lock-operations"{observation["step_rows"]=step_rows.into();}
 if case.starts_with("proof-")&&!matches!(case,"proof-valid"|"proof-missing"){observation["provider"]=serde_json::to_value(&*provider.as_ref().unwrap().requests.lock().unwrap())?;}
 office_fixture::compare_or_record(&format!("wopi-{route}-{case}-wire-v{}",if route=="put"{3}else{2}),&format!("{method} {pattern}"),case,&observation,recording,route=="lock"||route=="put")?;
 Ok::<_,common::BoxError>(())
 }).catch_unwind().await.unwrap_or_else(|_|Err("HTTP peer aborted before a complete response".into()));
    if let Some(name) = fault {
        c.batch_execute(&format!("DROP FUNCTION {name}() CASCADE"))
            .await?;
    }
    if let Some(schema) = owned_schema {
        c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    if let Some((a, space)) = victim {
        c.execute("DELETE FROM drive_nodes WHERE space_id=$1", &[&space])
            .await?;
        c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM drive_audit_log WHERE space_id={space}; COMMIT;")).await?;
        c.execute("DELETE FROM drive_spaces WHERE id=$1", &[&space])
            .await?;
        common::remove_blob_account(&c, &a).await?;
    }
    if case == "feature-off" {
        c.batch_execute(
            "UPDATE feature_toggles SET enabled=true WHERE key='feature.office_editing'",
        )
        .await?;
    }
    office_fixture::cleanup(&c, &seed).await?;
    result
}
fn normalize_key(raw: &str) -> String {
    let raw = raw.trim_start_matches('/');
    if let Some((prefix, temp)) = raw.split_once("tmp/upload/") {
        if temp.len() == 32 && temp.bytes().all(|b| b.is_ascii_hexdigit()) {
            return format!("{prefix}tmp/upload/<temporary>");
        }
    }
    raw.into()
}
struct ChangedStatus(setjoin_gateway::office::OfficeRoute);
impl setjoin_gateway::Intercept for ChangedStatus {
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

fn signed_proof(token: &str, uri: &str, case: &str) -> Result<(String, String), common::BoxError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut ticks = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos()
        / 100) as u64
        + 621355968000000000;
    if case == "proof-stale" {
        ticks -= 21 * 60 * 10_000_000;
    }
    if case == "proof-future" {
        ticks += 21 * 60 * 10_000_000;
    }
    let mut payload = Vec::new();
    for part in [
        token.as_bytes(),
        if case == "proof-unicode" {
            format!("HTTPS://MAIL.TEST/ᾈß{}", uri.to_ascii_uppercase())
        } else {
            format!("https://mail.test{uri}").to_uppercase()
        }
        .as_bytes(),
    ] {
        payload.extend_from_slice(&(part.len() as u32).to_be_bytes());
        payload.extend_from_slice(part);
    }
    payload.extend_from_slice(&8u32.to_be_bytes());
    payload.extend_from_slice(&ticks.to_be_bytes());
    let pem = if matches!(case, "proof-rotated" | "proof-double-old") {
        include_str!("../../../tests/conformance/office/provider/old-key.pem")
    } else {
        include_str!("../../../tests/conformance/office/provider/key.pem")
    };
    let encoded = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>();
    let der = STANDARD.decode(encoded)?;
    let key = ring::signature::RsaKeyPair::from_pkcs8(&der).map_err(|_| "test RSA key")?;
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        &payload,
        &mut signature,
    )
    .map_err(|_| "test proof signature")?;
    if case == "proof-corrupt" {
        signature[0] ^= 1;
    }
    Ok((ticks.to_string(), STANDARD.encode(signature)))
}

macro_rules! mutant {
    ($name:ident,$route:literal,$pattern:literal,$method:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            let error = run($route, "success", Some("status"))
                .await
                .expect_err("changed HTTP status must fail the Go golden");
            assert!(error.to_string().contains("/response/status"), "{error}");
            eprintln!(
                "MUTANT-REJECTED: {} {} :: changed-status",
                $method, $pattern
            );
            Ok(())
        }
    };
}
mutant!(
    info_oracle_rejects_changed_status,
    "info",
    "/office/wopi/files/{id}",
    "GET"
);
mutant!(
    get_oracle_rejects_changed_status,
    "get",
    "/office/wopi/files/{id}/contents",
    "GET"
);
mutant!(
    lock_oracle_rejects_changed_status,
    "lock",
    "/office/wopi/files/{id}",
    "POST"
);
mutant!(
    put_oracle_rejects_changed_status,
    "put",
    "/office/wopi/files/{id}/contents",
    "POST"
);
#[tokio::test]
async fn family_oracle_rejects_no_tenant_filter() -> Result<(), common::BoxError> {
    let error = run("info", "foreign", Some("tenant"))
        .await
        .expect_err("a removed SQL file predicate must fail the cross-tenant golden");
    assert!(error.to_string().contains("/response/status"), "{error}");
    eprintln!("MUTANT-REJECTED: GET /office/wopi/files/{{id}} :: no-tenant-filter");
    Ok(())
}
