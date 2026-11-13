//! #273: the sharing HTTP seam, recorded from frozen Go through the gateway.
mod common;
#[path = "common/drive_wire.rs"]
mod drive_wire;
use common::BoxError;
use futures_util::FutureExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};

#[tokio::test]
async fn overview_success() -> Result<(), BoxError> {
    run("overview", "success", false).await
}

#[tokio::test]
async fn grant_success() -> Result<(), BoxError> {
    run("grant", "success", false).await
}

#[tokio::test]
async fn revoke_success() -> Result<(), BoxError> {
    run("revoke", "success", false).await
}

#[tokio::test]
async fn set_default_success() -> Result<(), BoxError> {
    run("set_default", "success", false).await
}

#[tokio::test]
async fn clear_default_success() -> Result<(), BoxError> {
    run("clear_default", "success", false).await
}

#[tokio::test]
async fn list_defaults_success() -> Result<(), BoxError> {
    run("list_defaults", "success-clean", false).await
}

#[tokio::test]
async fn create_default_success() -> Result<(), BoxError> {
    run("create_default", "success", false).await
}

#[tokio::test]
async fn delete_default_success() -> Result<(), BoxError> {
    run("delete_default", "success", false).await
}

#[tokio::test]
async fn oversight_success() -> Result<(), BoxError> {
    run("oversight", "success", false).await
}

#[tokio::test]
async fn audit_success() -> Result<(), BoxError> {
    run("audit", "success", false).await
}

#[tokio::test]
async fn overview_foreign() -> Result<(), BoxError> {
    run("overview", "foreign", false).await
}

#[tokio::test]
async fn grant_wrong_type() -> Result<(), BoxError> {
    run("grant", "wrong-type", false).await
}

struct Principal {
    user: i64,
    mailbox: i64,
    domain: i64,
    calendar: i64,
    email: String,
}
async fn principal(c: &tokio_postgres::Client, name: &str) -> Result<Principal, BoxError> {
    let domain:i64=c.query_one("INSERT INTO domains(name,is_local) VALUES ('drive1-'||gen_random_uuid()||'.test',true) RETURNING id",&[]).await?.get(0);
    let email = format!("{name}@drive1-{domain}.test");
    c.batch_execute("BEGIN").await?;
    let user:i64=c.query_one("INSERT INTO users(username,email,display_name,password_hash,domain_id) VALUES($1,$1,$2,'x',$3) RETURNING id",&[&email,&name,&domain]).await?.get(0);
    let mut mailbox: i64 = c
        .query_one("SELECT nextval('mailboxes_id_seq')", &[])
        .await?
        .get(0);
    if mailbox == user {
        mailbox = c
            .query_one("SELECT nextval('mailboxes_id_seq')", &[])
            .await?
            .get(0);
    }
    // Pin the canonical DATE default too: complete snapshots must survive midnight.
    c.execute("INSERT INTO mailboxes(id,user_id,domain_id,email,display_name,type,is_primary,sending_quota_reset_at) VALUES($1,$2,$3,$4,$5,'personal',true,DATE '2026-10-31')",&[&mailbox,&user,&domain,&email,&name]).await?;
    let calendar:i64=c.query_one("INSERT INTO calendars(mailbox_id,name,is_default) VALUES($1,'Drive1 calendar',true) RETURNING id",&[&mailbox]).await?.get(0);
    c.batch_execute("COMMIT").await?;
    Ok(Principal {
        user,
        mailbox,
        domain,
        calendar,
        email,
    })
}
async fn cleanup(c: &tokio_postgres::Client, p: &Principal) -> Result<(), BoxError> {
    c.execute("DELETE FROM calendars WHERE mailbox_id=$1", &[&p.mailbox])
        .await?;
    c.execute(
        "DELETE FROM sharing_defaults WHERE created_by=$1 OR (owner_scope='user' AND owner_ref=$1)",
        &[&p.user],
    )
    .await?;
    c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE user_id={0} OR before_state->>'actor'='drive1@test'; DELETE FROM mailbox_audit_log WHERE mailbox_id={1}; COMMIT;",p.user,p.mailbox)).await?;
    c.batch_execute(&format!("BEGIN; DELETE FROM mailboxes WHERE id={0} AND user_id={1}; DELETE FROM users WHERE id={1}; COMMIT;",p.mailbox,p.user)).await?;
    c.execute("DELETE FROM domains WHERE id=$1", &[&p.domain])
        .await?;
    Ok(())
}
fn token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let h = B.encode(json!({"alg":"ES256","kid":"test-es256-1","typ":"JWT"}).to_string());
    let b=B.encode(json!({"uid":user,"email":"drive1@test","admin":true,"perms":["sharing.read","sharing.manage"],"typ":"access","jti":"drive1-test","fam":"drive1-test","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600}).to_string());
    let s: p256::ecdsa::Signature = SigningKey::from_slice(&[0x11; 32])
        .unwrap()
        .sign(format!("{h}.{b}").as_bytes());
    format!("{h}.{b}.{}", B.encode(s.to_bytes()))
}
async fn run(route: &str, case: &str, mutant: bool) -> Result<(), BoxError> {
    run_inner(route, case, mutant, None).await
}
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
async fn run_inner(
    route: &str,
    case: &str,
    mutant: bool,
    mutation: Option<&str>,
) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let case_name = case;
    let full_effects = case.ends_with("-state-v2") || case.starts_with("commit-");
    let case = case.strip_suffix("-state-v2").unwrap_or(case);
    if (mutation.is_some() || case.starts_with("commit-"))
        && std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some()
    {
        return Err("cannot record a planted mutant".into());
    }
    let Some(db) = Db::for_case("drive1") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let a = principal(&c, "owner").await?;
    let b = principal(&c, "foreign").await?;
    let mut created_role = None;
    let mut toggle_before = None;
    let mut jit_before = None;
    let mut reason_before: Option<Vec<String>> = None;
    let mut mutant_schema = None;
    let mut worker_dsn = db.dsn.clone();
    let mut partial_wire = None;
    let mut commit_wire = None;
    let mut partial_armed = None;
    let result = std::panic::AssertUnwindSafe(async {
        let (method,canonical,mut status_expected)=match route {
            "overview"=>("GET","/me/sharing",200),
            "grant"=>("POST","/me/sharing/delegates",201),
            "revoke"=>("DELETE","/me/sharing/delegates/{userId}",204),
            "set_default"=>("PUT","/me/sharing/default",200),
            "clear_default"=>("DELETE","/me/sharing/default/{id}",204),
            "list_defaults"=>("GET","/admin/sharing/defaults",200),
            "create_default"=>("POST","/admin/sharing/defaults",200),
            "delete_default"=>("DELETE","/admin/sharing/defaults/{id}",204),
            "oversight"=>("GET","/admin/sharing/users/{id}",200),
            "audit"=>("GET","/admin/sharing/audit",200),
            _=>unreachable!()
        };
        if case.starts_with("commit-"){status_expected=503;}
        let first_expected=status_expected;
        if matches!(case,"wrong-type"|"missing-fields"|"bad-permission"|"bad-default"|"reason-required"|"language"|"oversize-value"){status_expected=400;}
        if case=="missing-grantee"{status_expected=404;}
        if case.starts_with("parse-fault-"){status_expected=500;}
        if case.starts_with("query-fault-")||case=="audit-fault"{status_expected=if route=="oversight"&&case=="query-fault-users"{404}else if case.starts_with("query-fault-")&&matches!(route,"overview"|"list_defaults"|"oversight"|"audit"){200}else{500};}
        if case=="missing"||case=="scoped-foreign"&&route=="oversight"{status_expected=404;}
        if case=="scoped-foreign"&&route!="oversight"||matches!(case,"expired"|"jit-dormant"){status_expected=403;}
        if case=="repeat"&&matches!(route,"clear_default"|"delete_default"){status_expected=404;}
        if case=="foreign"&&(canonical.starts_with("/admin/")||route=="clear_default"){status_expected=403;}
        if case=="invalid"&&!matches!(route,"overview"|"list_defaults"|"audit"){status_expected=400;}
        let role:Option<i64>=if canonical.starts_with("/admin/") {let role:i64=c.query_one("INSERT INTO admin_role_groups(name,permissions) VALUES ('drive1-'||$1::bigint::text,ARRAY['sharing.read','sharing.manage']) RETURNING id",&[&a.user]).await?.get(0);c.execute("INSERT INTO admin_role_assignments(user_id,role_group_id) VALUES($1,$2)",&[&a.user,&role]).await?;created_role=Some(role);
        if matches!(case,"scoped-foreign"|"scoped-list"){c.execute("UPDATE admin_role_groups SET domain_scope=$2 WHERE id=$1",&[&role,&a.domain]).await?;}
        if case=="expired"{c.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 second' WHERE user_id=$1",&[&a.user]).await?;}
        if case=="jit-dormant"{jit_before=Some(c.query_one("SELECT enabled FROM feature_toggles WHERE key='rbac.jit'",&[]).await?.get::<_,bool>(0));c.execute("UPDATE feature_toggles SET enabled=true WHERE key='rbac.jit'",&[]).await?;c.execute("UPDATE admin_role_assignments SET eligible=true,activated_until=NULL WHERE user_id=$1",&[&a.user]).await?;}
        Some(role)}else{None};
        if route!="grant" { c.execute("INSERT INTO mailbox_delegates(mailbox_id,user_id,permission,granted_by,granted_at) VALUES($1,$2,'read',$3,'2026-01-01T00:00:00Z')",&[&a.mailbox,&b.user,&a.user]).await?; }
        c.execute("INSERT INTO calendar_acls(calendar_id,user_id,permission) VALUES($1,$2,'read')",&[&a.calendar,&b.user]).await?;
        let target_default:i64=if matches!(route,"clear_default"|"list_defaults"|"delete_default"|"oversight")||case=="defaults"||case.starts_with("query-fault-")||case.starts_with("parse-fault-"){c.query_one("INSERT INTO sharing_defaults(resource,owner_scope,owner_ref,audience,audience_ref,level,created_by) VALUES('calendar','user',$1,'everyone',$2,'read',$1) RETURNING id",&[&if case=="scoped-foreign"{b.user}else{a.user},&if case=="scoped-foreign"{b.domain}else{a.domain}]).await?.get(0)}else{0};
        if case=="defaults"{let enabled:bool=c.query_one("SELECT enabled FROM feature_toggles WHERE key='sharing.defaults'",&[]).await?.get(0);toggle_before=Some(enabled);c.execute("UPDATE feature_toggles SET enabled=true WHERE key='sharing.defaults'",&[]).await?;c.execute("INSERT INTO sharing_defaults(resource,owner_scope,owner_ref,audience,audience_ref,level,created_by) VALUES('calendar','org',$1,'everyone',$1,'freebusy',$2)",&[&a.domain,&a.user]).await?;}
        if case=="scoped-list"{c.execute("INSERT INTO sharing_defaults(resource,owner_scope,owner_ref,audience,audience_ref,level,created_by) VALUES('calendar','user',$1,'everyone',$2,'read',$1)",&[&b.user,&b.domain]).await?;}
        if matches!(case,"reason-required"|"reason-present"){reason_before=Some(c.query_one("SELECT reason_required_areas FROM audit_policy WHERE id=1",&[]).await?.get(0));c.execute("UPDATE audit_policy SET reason_required_areas=ARRAY['sharing'] WHERE id=1",&[]).await?;}
        if case=="partial-rows"{c.execute("INSERT INTO calendar_acls(calendar_id,user_id,permission) VALUES($1,$2,'freebusy')",&[&a.calendar,&a.user]).await?;}
        if route=="audit"{c.execute("SELECT mailbox_delegate_grant($1,$2,$3,'send_as')",&[&a.user,&a.mailbox,&b.email]).await?;}
        let mut ids=default_ids(&c,&a,&b).await?;
        if let Some(table)=case.strip_prefix("query-fault-").or_else(||case.strip_prefix("parse-fault-")).or_else(||(case=="audit-fault").then_some("audit-fault")){let(dsn,schema)=plant_fault(&c,&db,table,a.user).await?;worker_dsn=dsn;mutant_schema=Some(schema);}
        if matches!(case,"commit-before"|"commit-after"){ledger("Plan gofree-drive1 COMMIT-loss proxy on assigned worker DB")?;let cut=if case=="commit-after"{common::commit::CommitCut::AfterCommit}else{common::commit::CommitCut::BeforeCommit};let(dsn,task)=common::commit::commit_cut_proxy(&db.dsn,cut).await;worker_dsn=dsn;commit_wire=Some(task);}
        if case=="partial-rows"{ledger("Plan gofree-drive1 partial-row PostgreSQL wire proxy on assigned DB")?;let(dsn,armed,task)=drive_wire::partial_rows(&db.dsn).await;worker_dsn=dsn;partial_wire=Some(task);partial_armed=Some(armed);}
        if let Some(kind)=mutation{let (dsn,schema)=plant_mutant(&c,&db,kind,&a,&b).await?;worker_dsn=dsn;mutant_schema=Some(schema);}
        let endpoint=common::fake_upstream(|_|async{Response::new(common::full("unused"))}).await;
        let oracle_db=Db{dsn:worker_dsn.clone(),direct:db.direct.clone(),app:db.app.clone()};
        let oracle=common::go_oracle::start_named(&oracle_db,endpoint,None,"gofree-drive1").await?;
        let recording=oracle.is_some();
        if let Some(armed)=partial_armed.as_ref(){armed.store(true,std::sync::atomic::Ordering::SeqCst);}
        if case.starts_with("query-fault-")||case=="audit-fault"{let schema=mutant_schema.as_ref().unwrap();c.batch_execute(&format!("UPDATE {schema}.control SET armed=true")).await?;}
        if let Some(table)=case.strip_prefix("parse-fault-"){let schema=mutant_schema.as_ref().unwrap();let column=match table{"mailbox_delegates"|"calendar_acls"=>"permission","sharing_defaults"=>"level","admin_audit_log"=>"occurred_at",_=>return Err("unknown parse fault".into())};let relation=format!("public.{table}");let columns:String=c.query_one("SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) FROM pg_attribute WHERE attrelid=$1::text::regclass AND attnum>0 AND NOT attisdropped AND attname<>$2",&[&relation,&column]).await?.get(0);c.batch_execute(&format!("DROP VIEW {schema}.{table}; CREATE VIEW {schema}.{table} AS SELECT {columns} FROM public.{table}")).await?;}
        let baseline=if case.starts_with("commit-"){Some(snapshot(&c,&a,&b,true).await?)}else{None};
        let before:i64=c.query_one("SELECT coalesce(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
        let mut listener=db.listen(&format!("calendar:{}",a.mailbox)).await?;
        let mut foreign_listener=db.listen(&format!("calendar:{}",b.mailbox)).await?;
        let adapter=setjoin_gateway::drive::DriveRoute{exec:setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),1).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new()),worker:setjoin_pg::ScopedExecutor::from_dsn(&worker_dsn,1).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new()),store:None,keys:std::sync::Arc::new(common::recovery_keys()),issuer:"mailserver".into()};
        let routes=if recording{RouteTable::proxy_all()}else if mutant{RouteTable::proxy_all().with(ChangedStatus(adapter))}else{RouteTable::proxy_all().with(adapter)};
        let gateway=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},routes)?;
        let gateway=if recording{gateway}else{let mut inventory:Value=serde_json::from_str(setjoin_gateway::inventory::BUNDLED)?;for row in inventory["routes"].as_array_mut().unwrap(){if row["family"]=="F14"&&row["slice"]=="golden-routes"{row["state"]="ON".into();row["upstream"]="local-rust".into();}}gateway.with_inventory(&inventory.to_string())?};
        let l=tokio::net::TcpListener::bind("127.0.0.1:0").await?; let addr=l.local_addr()?; let server=tokio::spawn(gateway.serve(l));
        let mut wire_body=if route=="create_default"{json!({"ownerScope":"org","ownerRef":a.domain,"audience":"everyone","audienceRef":a.domain,"level":"read"}).to_string()}else if route=="grant"{json!({"granteeEmail":b.email,"permission":"read"}).to_string()}else if route=="set_default"{json!({"audience":"everyone","level":"read"}).to_string()}else{String::new()};
        if case=="foreign"&&route=="grant"{wire_body=json!({"granteeEmail":a.email,"permission":"read","mailboxId":a.mailbox,"userId":a.user}).to_string();}
        if case=="foreign"&&route=="set_default"{wire_body=json!({"audience":"everyone","level":"read","ownerRef":a.user,"userId":a.user,"mailboxId":a.mailbox}).to_string();}
        if case=="invalid"&&matches!(method,"POST"|"PUT"){wire_body="{".into();}
        if case=="wrong-type"{wire_body=match route{"grant"=>json!({"granteeEmail":b.email,"permission":23}).to_string(),"set_default"=>r#"{"audience":"everyone","audienceRef":"bad","level":"read"}"#.into(),_=>r#"{"ownerScope":"org","ownerRef":"bad"}"#.into()};}
        if case=="missing-fields"{wire_body="{}".into();}
        if case=="bad-permission"{wire_body=json!({"granteeEmail":b.email,"permission":"invalid"}).to_string();}
        if case=="missing-grantee"{wire_body=json!({"granteeEmail":"missing@drive1.test","permission":"read"}).to_string();}
        if case=="bad-default"{wire_body=json!({"ownerScope":"org","ownerRef":a.domain,"audience":"everyone","audienceRef":a.domain,"level":"invalid"}).to_string();}
        if case=="explicit-audience"{wire_body=json!({"audience":"everyone","audienceRef":a.domain,"level":"read"}).to_string();}
        if case=="scoped-foreign"&&route=="create_default"{wire_body=json!({"ownerScope":"org","ownerRef":b.domain,"audience":"everyone","audienceRef":b.domain,"level":"read"}).to_string();}
        if case=="language"{wire_body="{".into();}
        if case=="large-trailer"{wire_body.push_str(&" ".repeat((1<<20)+128));}
        if case=="oversize-value"{let mut body:Value=serde_json::from_str(&wire_body)?;body["future"]=Value::String("x".repeat(1<<20));wire_body=body.to_string();}
        if case=="go-json"{wire_body=match route{
            "grant"=>format!(r#"{{"granteeEmail":{},"permiſſion":"read","permission":null,"future":1e400,"future2":"\ud800"}} trailing"#,serde_json::to_string(&b.email)?),
            "set_default"=>r#"{"AUDIENCE":"everyone","LeVeL":"read","level":null,"ownerRef":"ignored","future":1e400} []"#.into(),
            _=>format!(r#"{{"ownerScope":"org","OWNERREF":{},"ownerRef":null,"audience":"everyone","audienceRef":{},"level":"read","future":1e400}} trailing"#,a.domain,a.domain)
        };}
        let mut request_path=format!("/api{}",canonical.replace("{userId}",&b.user.to_string()).replace("{id}",&if route=="oversight"{if case=="scoped-foreign"{b.user.to_string()}else if case=="missing"{i64::MAX.to_string()}else{a.user.to_string()}}else{target_default.to_string()}))+&if route=="audit"{format!("?user_id={}",a.user)}else{String::new()};
        if case=="invalid"{if canonical.contains('{'){request_path=request_path.split('?').next().unwrap().rsplit_once('/').map(|(p,_)|format!("{p}/bad")).unwrap();}else{request_path.push_str(if request_path.contains('?'){"&limit=bad&offset=bad"}else{"?user_id=bad&limit=bad&offset=bad"});}}
        if case=="offset-overflow"{request_path.push_str("&offset=9999999999999999999999999999999999999");}
        if case=="malformed-filter"{request_path=format!("/api/admin/sharing/audit?user_id={};bad=1&user_id={}",a.user,b.user);}
        let actual_path=request_path.split('?').next().unwrap().strip_prefix("/api").unwrap().to_owned();
        let first=if case=="repeat"{
        let response=common::send(addr,Request::builder().method(method).uri(request_path.clone()).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {}",token(if case=="foreign"{b.user}else{a.user}))).header("content-type","application/json").header("x-request-id","drive1-oracle").header("x-audit-reason",if case=="reason-required"{""}else{"drive1 justification"}).header("accept-language",if case=="language"{"zh-CN, en;q=0.8"}else{"en"}).body(common::full(wire_body.clone()))?).await;
            if response.status().as_u16()!=first_expected{return Err("first repeat status mismatch".into())}
            let mut first=observe_response(response).await?;
            ids.extend(default_ids(&c,&a,&b).await?);
            first["effects"]=snapshot(&c,&a,&b,full_effects).await?;first["audit"]=audit_rows(&c,before).await?;
            first["notify"]=events(&mut listener,&mut foreign_listener,&c).await?;
            normalize_defaults(&mut first,&ids,&a,&b);normalize(&mut first,"",&a,&b);
            Some(first)
        }else{None};
        let response=common::send(addr,Request::builder().method(method).uri(request_path).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {}",token(if case=="foreign"{b.user}else{a.user}))).header("content-type","application/json").header("x-request-id","drive1-oracle").header("x-audit-reason",if case=="reason-required"{""}else{"drive1 justification"}).header("accept-language",if case=="language"{"zh-CN, en;q=0.8"}else{"en"}).body(common::full(wire_body))?).await;
        let status=response.status().as_u16();
        let headers=response.headers().iter().filter(|(k,_)|!matches!(k.as_str(),"date"|"content-length"|"connection"|"transfer-encoding")).map(|(k,v)|(k.to_string(),Value::String(v.to_str().unwrap().into()))).collect::<serde_json::Map<_,_>>();
        let bytes=common::body_bytes(response).await;
        if !recording{
            let metrics=common::send(addr,Request::builder().uri("/_gateway/metrics").body(common::full(""))?).await;let metrics=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.contains("setjoin_gateway_proxied_to_go_total 0")||!metrics.contains("setjoin_gateway_proxied_to_go_by_family_total{family=\"F14\"} 0"){return Err(format!("native Go proxy counters: {metrics}").into())}
        }
        server.abort(); let _=server.await;
        if status!=status_expected{return Err(format!("HTTP status expected {status_expected}, got {status}: {}",String::from_utf8_lossy(&bytes)).into());}
        ids.extend(default_ids(&c,&a,&b).await?);
        let mut body:Value=if bytes.is_empty(){Value::Null}else{serde_json::from_slice(&bytes)?};
        if case=="partial-rows"&&body["calendarGrants"].as_array().ok_or("partial rows")?.len()!=1{return Err(format!("partial row fault did not discriminate: {body}").into())}
        if route=="audit"&&status==200{for(i,row)in body.as_array_mut().ok_or("audit array")?.iter_mut().enumerate(){let audit_id=row["id"].as_i64().ok_or("audit id")?;let action:String=c.query_one("SELECT action FROM admin_audit_log WHERE id=$1",&[&audit_id]).await?.get(0);if row["action"]!=action{return Err("audit id/action mismatch".into())}chrono::DateTime::parse_from_rfc3339(row["occurredAt"].as_str().ok_or("audit timestamp")?)?;row["id"]=json!(format!("<audit-{}>",i+1));row["occurredAt"]="<time>".into();}}
        if case!="invalid"{normalize_request_path(&mut body,&actual_path,canonical);}
        normalize_defaults(&mut body,&ids,&a,&b);normalize(&mut body,"",&a,&b);
        let (mut effects,mut audit,notify)=if route=="overview"{(json!({}),json!([]),json!([]))}else{let effects=snapshot(&c,&a,&b,full_effects).await?; let audit=audit_rows(&c,before).await?;let mut notify=Vec::new();for(channel,events)in [("owner",listener.drain(&c).await?),("foreign",foreign_listener.drain(&c).await?)]{for event in events{notify.push(json!({"channel":channel,"payload":serde_json::from_str::<Value>(&event)?}));}}(effects,audit,json!(notify))};
        if case!="invalid"{normalize_request_path(&mut audit,&actual_path,canonical);}
        normalize_defaults(&mut effects,&ids,&a,&b);normalize_defaults(&mut audit,&ids,&a,&b);normalize(&mut effects,"",&a,&b);normalize(&mut audit,"",&a,&b);
        let mut notify=notify; normalize(&mut notify,"",&a,&b);
        let mut observation=json!({"request":{"method":method,"path":canonical},"response":{"status":status,"headers":headers,"body":body},"effects":effects,"audit":audit,"notify":notify});
        if let Some(first)=first{observation["first"]=first;}

        let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/drive/goldens/{route}-{case_name}.json"));
        if case.starts_with("commit-"){
            let cut=tokio::time::timeout(std::time::Duration::from_secs(5),commit_wire.take().unwrap()).await???;let committed=case=="commit-after";
            if (cut==common::commit::CommitCut::AfterCommit)!=committed{return Err("wrong wire cut".into())}
            let operation=observation["response"]["headers"]["x-operation-id"].as_str().ok_or("Unknown lost operation ID")?;
            if operation.len()!=32||!operation.bytes().all(|b|b.is_ascii_hexdigit()){return Err("invalid operation ID".into())}
            let receipt:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=$1::text::uuid AND family='F14' AND command='sharing_default_set')",&[&operation]).await?.get(0);
            if receipt!=committed{return Err("receipt did not resolve actual commit".into())}
            if committed{let expected:Value=serde_json::from_slice(&std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/drive/goldens/set_default-success-state-v2.json"))?)?;for key in ["effects","audit","notify"]{setjoin_conformance::golden::compare(&expected["observation"][key],&observation[key])?;}}
            else{let mut baseline=baseline.unwrap();normalize_defaults(&mut baseline,&ids,&a,&b);normalize(&mut baseline,"",&a,&b);setjoin_conformance::golden::compare(&baseline,&observation["effects"])?;if observation["audit"]!=json!([])||observation["notify"]!=json!([]){return Err("aborted commit left effects".into())}}
            ledger("Reaped gofree-drive1 COMMIT-loss proxy; HTTP Unknown resolved from receipt without replay")?;return Ok(())
        }
        if recording {
            if route!="overview"{setjoin_conformance::golden::record(&path.with_file_name(format!("{route}-{case_name}-row-effects.json")),&json!({"format":1,"route":format!("{method} {canonical}"),"case":format!("{route}-{case_name}-row-effects"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"effects":[observation["effects"],observation["audit"],observation["notify"]]}))?;}
            setjoin_conformance::golden::record(&path,&json!({"format":1,"route":format!("{method} {canonical}"),"case":format!("{route}-{case_name}"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"normalization":["fixture identities","generated timestamps; audit checksum verified"],"observation":observation}))?;
        } else {
            let mut expected:Value=serde_json::from_slice(&std::fs::read(&path)?)?;legacy_grant(&mut expected);legacy_notify(&mut expected);setjoin_conformance::golden::compare(&expected["observation"],&observation)?;
            if route!="overview"{let mut rows:Value=serde_json::from_slice(&std::fs::read(path.with_file_name(format!("{route}-{case_name}-row-effects.json")))?)?;legacy_grant(&mut rows);legacy_notify(&mut rows);setjoin_conformance::golden::compare(&rows["effects"],&json!([observation["effects"],observation["audit"],observation["notify"]]))?;}
            println!("GOLDEN-REPLAY: {method} {canonical} :: {route}-{case_name}");
        }
        let _=role;
        Ok::<_,BoxError>(())
    }).catch_unwind().await;
    if let Some(task) = commit_wire {
        task.abort();
        let _ = task.await;
        ledger("Reaped failed gofree-drive1 COMMIT proxy")?;
    }
    if let Some(task) = partial_wire {
        task.abort();
        let _ = task.await;
        ledger("Reaped gofree-drive1 partial-row proxy and its owned connection tasks")?;
    }
    if let Some(enabled) = jit_before {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='rbac.jit'",
            &[&enabled],
        )
        .await?;
    }
    if let Some(enabled) = toggle_before {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='sharing.defaults'",
            &[&enabled],
        )
        .await?;
    }
    if let Some(areas) = reason_before {
        c.execute(
            "UPDATE audit_policy SET reason_required_areas=$1 WHERE id=1",
            &[&areas],
        )
        .await?;
    }
    if let Some(schema) = mutant_schema {
        c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
        ledger(&format!("Removed private SQL mutant schema {schema}"))?;
    }
    if let Some(role) = created_role {
        c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_role_assignments WHERE role_group_id={role}; COMMIT;")).await?;
        c.execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
            .await?;
    }
    cleanup(&c, &a).await?;
    cleanup(&c, &b).await?;
    match result {
        Ok(r) => r,
        Err(p) => std::panic::resume_unwind(p),
    }
}
async fn snapshot(
    c: &tokio_postgres::Client,
    a: &Principal,
    b: &Principal,
    full: bool,
) -> Result<Value, BoxError> {
    let mut out = json!({});
    for (name,sql,args) in [
        ("delegates","SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY mailbox_id,user_id,permission),'[]')::text FROM mailbox_delegates t WHERE mailbox_id IN ($1,$2)",(a.mailbox,b.mailbox)),
        ("calendars","SELECT coalesce(jsonb_agg(jsonb_build_object('calendar_id',id,'mailbox_id',mailbox_id,'state',jmap_state) ORDER BY mailbox_id),'[]')::text FROM calendars WHERE mailbox_id IN ($1,$2)",(a.mailbox,b.mailbox)),
        ("defaults","SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]')::text FROM sharing_defaults t WHERE created_by IN ($1,$2)",(a.user,b.user))
    ] {let raw:String=c.query_one(sql,&[&args.0,&args.1]).await?.get(0);out[name]=serde_json::from_str(&raw)?;}
    if full {
        for(name,sql)in[
            ("calendars","SELECT (to_jsonb(t)-'id'||jsonb_build_object('calendar_id',id))::text FROM calendars t WHERE mailbox_id IN($1,$2) ORDER BY mailbox_id,id"),
            ("mailboxes","SELECT (to_jsonb(t)-'id'||jsonb_build_object('mailbox_id',id))::text FROM mailboxes t WHERE id IN($1,$2) ORDER BY id"),
            ("entity_state","SELECT to_jsonb(t)::text FROM jmap_entity_state t WHERE mailbox_id IN($1,$2) ORDER BY mailbox_id,datatype"),
            ("journal","SELECT to_jsonb(t)::text FROM jmap_changes_journal t WHERE mailbox_id IN($1,$2) ORDER BY mailbox_id,datatype,state_seq,entity_id")
        ]{let rows=c.query(sql,&[&a.mailbox,&b.mailbox]).await?;out[name]=json!(rows.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?);}
        for row in out["journal"].as_array_mut().unwrap() {
            if row["datatype"] == "Calendar" {
                for (p, name) in [(a, "owner"), (b, "foreign")] {
                    if row["entity_id"] == p.calendar {
                        row["entity_id"] = json!(format!("<{name}-calendar>"));
                    }
                }
            } else if row["entity_id"] != 0 {
                return Err(format!("unrecognized journal entity: {row}").into());
            }
        }
    }
    Ok(out)
}
async fn audit_rows(c: &tokio_postgres::Client, before: i64) -> Result<Value, BoxError> {
    let invalid:i64=c.query_one("SELECT count(*) FROM admin_audit_log t CROSS JOIN LATERAL verify_audit_chain(t.id,t.id) v WHERE t.id>$1 AND NOT v.valid",&[&before]).await?.get(0);
    assert_eq!(invalid, 0, "core audit chain");
    let raw:String=c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t)-'id'-'checksum'-'occurred_at' ORDER BY id),'[]')::text FROM admin_audit_log t WHERE id>$1",&[&before]).await?.get(0);
    Ok(serde_json::from_str(&raw)?)
}

fn normalize(v: &mut Value, key: &str, a: &Principal, b: &Principal) {
    match v {
        Value::Object(m) => {
            if m.get("audience").and_then(Value::as_str) == Some("everyone")
                && m.contains_key("audienceLabel")
            {
                let label = if m["audienceRef"] == a.domain || m["audienceRef"] == "<owner-domain>"
                {
                    "owner"
                } else if m["audienceRef"] == b.domain || m["audienceRef"] == "<foreign-domain>" {
                    "foreign"
                } else {
                    panic!("unknown audience")
                };
                let text = m["audienceLabel"].as_str().expect("label");
                if !text.is_empty() {
                    assert!(text.starts_with("drive1-") && text.ends_with(".test"));
                    m.insert(
                        "audienceLabel".into(),
                        json!(format!("<{label}-domain-name>")),
                    );
                }
            }
            if m.get("target_type")
                .or_else(|| m.get("targetType"))
                .and_then(Value::as_str)
                == Some("mailbox_delegate")
            {
                let key = if m.contains_key("target_id") {
                    "target_id"
                } else {
                    "targetId"
                };
                if let Some(n) = m.get(key).and_then(Value::as_i64) {
                    let who = if n == a.mailbox {
                        "owner"
                    } else if n == b.mailbox {
                        "foreign"
                    } else {
                        panic!("foreign mailbox audit target")
                    };
                    m.insert(key.into(), json!(format!("<{who}-mailbox>")));
                }
            }
            for (k, v) in m {
                normalize(v, k, a, b)
            }
        }
        Value::Array(v) => {
            for v in v {
                normalize(v, key, a, b)
            }
        }
        Value::Number(n) => {
            if let Some(n) = n.as_i64() {
                for (p, name) in [(a, "owner"), (b, "foreign")] {
                    let pair = match key {
                        "userId" | "user_id" | "created_by" | "createdBy" | "granted_by"
                        | "grantee_user_id" => Some((p.user, "user")),
                        "mailbox_id" => Some((p.mailbox, "mailbox")),
                        "calendarId" | "calendar_id" => Some((p.calendar, "calendar")),
                        "audience_ref" | "audienceRef" | "domain_id" => Some((p.domain, "domain")),
                        _ => None,
                    };
                    if let Some((id, label)) = pair {
                        if n == id {
                            *v = json!(format!("<{name}-{label}>"));
                            return;
                        }
                    }
                }
            }
        }
        Value::String(s) => {
            if key == "outbound_day" {
                chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").expect("date");
                *s = "<date>".into();
                return;
            }
            if matches!(
                key,
                "granted_at" | "created_at" | "updated_at" | "updatedAt"
            ) {
                assert!(
                    s.len() >= 10
                        && chrono::NaiveDate::parse_from_str(&s[..10], "%Y-%m-%d").is_ok(),
                    "timestamp {s}"
                );
                *s = "<time>".into();
                return;
            }
            for (p, label) in [(a, "owner"), (b, "foreign")] {
                *s = s.replace(&p.email, &format!("<{label}-email>"));
            }
        }
        _ => (),
    }
}

// The first immutable grant tracer recorded these two fixture IDs before the
// semantic normalization was extended. Validate the exact original bindings.
fn legacy_grant(v: &mut Value) {
    if !matches!(
        v["case"].as_str(),
        Some("grant-success" | "grant-success-row-effects")
    ) {
        return;
    }
    let audit = if v.get("observation").is_some() {
        &mut v["observation"]["audit"]
    } else {
        &mut v["effects"][1]
    };
    assert_eq!(audit[0]["after_state"]["grantee_user_id"], 17);
    assert_eq!(audit[0]["target_id"], 17);
    audit[0]["after_state"]["grantee_user_id"] = "<foreign-user>".into();
    audit[0]["target_id"] = "<owner-mailbox>".into();
}

async fn default_ids(
    c: &tokio_postgres::Client,
    a: &Principal,
    b: &Principal,
) -> Result<Vec<(i64, String)>, BoxError> {
    let rows = c
        .query(
            "SELECT id,owner_scope,owner_ref FROM sharing_defaults WHERE created_by IN ($1,$2)",
            &[&a.user, &b.user],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            let scope: String = r.get(1);
            let owner: i64 = r.get(2);
            let who = if owner == a.user && scope == "user" || owner == a.domain && scope == "org" {
                "owner"
            } else if owner == b.user && scope == "user" || owner == b.domain && scope == "org" {
                "foreign"
            } else {
                panic!("unknown default owner")
            };
            (r.get(0), format!("<{who}-{scope}-default>"))
        })
        .collect())
}
fn normalize_defaults(v: &mut Value, ids: &[(i64, String)], a: &Principal, b: &Principal) {
    match v {
        Value::Object(m) => {
            let scope = m
                .get("owner_scope")
                .or_else(|| m.get("ownerScope"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            for k in ["owner_ref", "ownerRef"] {
                if let Some(n) = m.get(k).and_then(Value::as_i64) {
                    for (p, who) in [(a, "owner"), (b, "foreign")] {
                        let (id, kind) = if scope == "org" {
                            (p.domain, "domain")
                        } else {
                            (p.user, "user")
                        };
                        if n == id {
                            m.insert(k.into(), json!(format!("<{who}-{kind}>")));
                            break;
                        }
                    }
                }
            }
            for (k, v) in m {
                if matches!(k.as_str(), "id" | "target_id" | "targetId") {
                    if let Some(n) = v.as_i64() {
                        if let Some((_, label)) = ids.iter().find(|(id, _)| *id == n) {
                            *v = label.clone().into();
                        }
                    }
                }
                normalize_defaults(v, ids, a, b)
            }
        }
        Value::Array(values) => {
            for v in values {
                normalize_defaults(v, ids, a, b)
            }
        }
        _ => (),
    }
}

fn legacy_notify(v: &mut Value) {
    let events = if v.get("observation").is_some() {
        &mut v["observation"]["notify"]
    } else {
        &mut v["effects"][2]
    };
    if let Some(events) = events.as_array_mut() {
        for event in events {
            if event.get("event").is_some() {
                assert_eq!(event["calendar_id"], "<owner-calendar>");
                *event = json!({"channel":"owner","payload":event.clone()});
            }
        }
    }
}

fn normalize_request_path(v: &mut Value, actual: &str, canonical: &str) {
    match v {
        Value::Object(m) => {
            for v in m.values_mut() {
                normalize_request_path(v, actual, canonical)
            }
        }
        Value::Array(a) => {
            for v in a {
                normalize_request_path(v, actual, canonical)
            }
        }
        Value::String(s) if s == actual => *s = canonical.into(),
        _ => (),
    }
}

#[tokio::test]
async fn overview_invalid() -> Result<(), BoxError> {
    run("overview", "invalid", false).await
}

#[tokio::test]
async fn grant_foreign() -> Result<(), BoxError> {
    run("grant", "foreign", false).await
}

#[tokio::test]
async fn grant_invalid() -> Result<(), BoxError> {
    run("grant", "invalid", false).await
}

#[tokio::test]
async fn revoke_foreign() -> Result<(), BoxError> {
    run("revoke", "foreign", false).await
}

#[tokio::test]
async fn revoke_invalid() -> Result<(), BoxError> {
    run("revoke", "invalid", false).await
}

#[tokio::test]
async fn set_default_foreign() -> Result<(), BoxError> {
    run("set_default", "foreign", false).await
}

#[tokio::test]
async fn set_default_invalid() -> Result<(), BoxError> {
    run("set_default", "invalid", false).await
}

#[tokio::test]
async fn clear_default_foreign() -> Result<(), BoxError> {
    run("clear_default", "foreign", false).await
}

#[tokio::test]
async fn clear_default_invalid() -> Result<(), BoxError> {
    run("clear_default", "invalid", false).await
}

#[tokio::test]
async fn list_defaults_foreign() -> Result<(), BoxError> {
    run("list_defaults", "foreign", false).await
}

#[tokio::test]
async fn list_defaults_invalid() -> Result<(), BoxError> {
    run("list_defaults", "invalid", false).await
}

#[tokio::test]
async fn create_default_foreign() -> Result<(), BoxError> {
    run("create_default", "foreign", false).await
}

#[tokio::test]
async fn create_default_invalid() -> Result<(), BoxError> {
    run("create_default", "invalid", false).await
}

#[tokio::test]
async fn delete_default_foreign() -> Result<(), BoxError> {
    run("delete_default", "foreign", false).await
}

#[tokio::test]
async fn delete_default_invalid() -> Result<(), BoxError> {
    run("delete_default", "invalid", false).await
}

#[tokio::test]
async fn oversight_foreign() -> Result<(), BoxError> {
    run("oversight", "foreign", false).await
}

#[tokio::test]
async fn oversight_invalid() -> Result<(), BoxError> {
    run("oversight", "invalid", false).await
}

#[tokio::test]
async fn audit_foreign() -> Result<(), BoxError> {
    run("audit", "foreign", false).await
}

#[tokio::test]
async fn audit_invalid() -> Result<(), BoxError> {
    run("audit", "invalid", false).await
}

async fn observe_response(response: Response<hyper::body::Incoming>) -> Result<Value, BoxError> {
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                "date" | "content-length" | "connection" | "transfer-encoding"
            )
        })
        .map(|(k, v)| (k.to_string(), json!(v.to_str().unwrap())))
        .collect::<serde_json::Map<_, _>>();
    let bytes = common::body_bytes(response).await;
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok(json!({"response":{"status":status,"headers":headers,"body":body}}))
}
async fn events(
    a: &mut setjoin_conformance::harness::Listener,
    b: &mut setjoin_conformance::harness::Listener,
    c: &tokio_postgres::Client,
) -> Result<Value, BoxError> {
    let mut out = Vec::new();
    for (channel, events) in [("owner", a.drain(c).await?), ("foreign", b.drain(c).await?)] {
        for event in events {
            out.push(json!({"channel":channel,"payload":serde_json::from_str::<Value>(&event)?}));
        }
    }
    Ok(json!(out))
}

#[tokio::test]
async fn grant_repeat() -> Result<(), BoxError> {
    run("grant", "repeat", false).await
}

#[tokio::test]
async fn revoke_repeat() -> Result<(), BoxError> {
    run("revoke", "repeat", false).await
}

#[tokio::test]
async fn set_default_repeat() -> Result<(), BoxError> {
    run("set_default", "repeat", false).await
}

#[tokio::test]
async fn clear_default_repeat() -> Result<(), BoxError> {
    run("clear_default", "repeat", false).await
}

#[tokio::test]
async fn create_default_repeat() -> Result<(), BoxError> {
    run("create_default", "repeat", false).await
}

#[tokio::test]
async fn delete_default_repeat() -> Result<(), BoxError> {
    run("delete_default", "repeat", false).await
}

struct ChangedStatus<K: setjoin_authz::token::KeySource + 'static>(
    setjoin_gateway::drive::DriveRoute<K>,
);
impl<K: setjoin_authz::token::KeySource + 'static> setjoin_gateway::Intercept for ChangedStatus<K> {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.0.matches(r)
    }
    fn admits_member(
        &self,
        h: hyper::HeaderMap,
        s: &'static str,
    ) -> setjoin_gateway::BoxFuture<bool> {
        self.0.admits_member(h, s)
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let reply = self.0.handle(r, c);
        Box::pin(async move {
            let mut reply = reply.await;
            *reply.status_mut() = hyper::StatusCode::from_u16(599).unwrap();
            reply
        })
    }
}
async fn reject_status(route: &str) -> Result<(), BoxError> {
    let case = if route == "list_defaults" {
        "success-clean"
    } else {
        "success"
    };
    let err = run(route, case, true)
        .await
        .expect_err("actual HTTP status mutant must fail");
    assert!(err.to_string().contains("HTTP status expected"), "{err}");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../tests/conformance/drive/goldens/{route}-{case}.json"
    ));
    let v: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    println!(
        "MUTANT-REJECTED: {} :: changed-status",
        v["route"].as_str().unwrap()
    );
    Ok(())
}
fn ledger(line: &str) -> Result<(), BoxError> {
    use std::io::Write;
    if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path)?,
            "{line}"
        )?;
    }
    Ok(())
}
async fn plant_mutant(
    c: &tokio_postgres::Client,
    db: &Db,
    kind: &str,
    a: &Principal,
    b: &Principal,
) -> Result<(String, String), BoxError> {
    let schema = format!("gofree_drive1_mutant_{}", a.user);
    ledger(&format!(
        "Plan private {kind} SQL mutant schema {schema}, assigned DB only"
    ))?;
    c.batch_execute(&format!(
        "CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO setjoin_app;"
    ))
    .await?;
    let sql=match kind{
        "no-audit"=>format!("CREATE FUNCTION {schema}.audit_write(bigint,text,text,bigint,jsonb,jsonb,inet,text,text) RETURNS void LANGUAGE sql AS 'SELECT NULL::void'"),
        "no-notify"=>format!("CREATE FUNCTION {schema}.app_notify(text,text) RETURNS void LANGUAGE sql AS 'SELECT NULL::void'"),
        "double-bump"=>{
            let mut definition:String=c.query_one("SELECT pg_get_functiondef('public.notify_calendar_state(bigint,bigint,bigint,text)'::regprocedure)",&[]).await?.get(0);
            definition=definition.replacen("public.notify_calendar_state",&format!("{schema}.notify_calendar_state"),1);
            definition=definition.replace("PERFORM app_notify(","UPDATE calendars SET jmap_state=jmap_state+1 WHERE id=p_calendar_id AND mailbox_id=p_owner_mailbox_id; PERFORM app_notify(");definition
        },
        // A query-seam view deliberately erases the true owner predicate, while
        // primary admission and persisted mailboxes retain their real owners.
        "no-tenant-filter"=>format!("CREATE VIEW {schema}.mailboxes AS SELECT id,{}::bigint AS user_id,domain_id,email,display_name,is_primary FROM public.mailboxes WHERE id IN ({},{})",b.user,a.mailbox,b.mailbox),
        _=>return Err("unknown SQL mutant".into())
    };
    if let Err(e) = c.batch_execute(&sql).await {
        c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
        return Err(e.into());
    }
    Ok((
        format!(
            "{}{}options=-csearch_path%3D{}%2Cpublic",
            db.dsn,
            if db.dsn.contains('?') { "&" } else { "?" },
            schema
        ),
        schema,
    ))
}
#[tokio::test]
async fn overview_rejects_status() -> Result<(), BoxError> {
    reject_status("overview").await
}
async fn reject_effect(kind: &str) -> Result<(), BoxError> {
    let (route, case, path) = if kind == "no-tenant-filter" {
        ("overview", "foreign", "/response/body")
    } else {
        (
            "set_default",
            "success-state-v2",
            match kind {
                "no-audit" => "/audit",
                "no-notify" => "/notify",
                _ => "/effects/calendars",
            },
        )
    };
    let err = run_inner(route, case, false, Some(kind))
        .await
        .expect_err("actual SQL mutant must fail the immutable recording");
    assert!(err.to_string().contains(path), "{kind}: {err}");
    println!(
        "MUTANT-REJECTED: {} :: {kind}",
        if route == "overview" {
            "GET /me/sharing"
        } else {
            "PUT /me/sharing/default"
        }
    );
    Ok(())
}

#[tokio::test]
async fn grant_rejects_status() -> Result<(), BoxError> {
    reject_status("grant").await
}

#[tokio::test]
async fn revoke_rejects_status() -> Result<(), BoxError> {
    reject_status("revoke").await
}

#[tokio::test]
async fn set_default_rejects_status() -> Result<(), BoxError> {
    reject_status("set_default").await
}

#[tokio::test]
async fn clear_default_rejects_status() -> Result<(), BoxError> {
    reject_status("clear_default").await
}

#[tokio::test]
async fn list_defaults_rejects_status() -> Result<(), BoxError> {
    reject_status("list_defaults").await
}

#[tokio::test]
async fn create_default_rejects_status() -> Result<(), BoxError> {
    reject_status("create_default").await
}

#[tokio::test]
async fn delete_default_rejects_status() -> Result<(), BoxError> {
    reject_status("delete_default").await
}

#[tokio::test]
async fn oversight_rejects_status() -> Result<(), BoxError> {
    reject_status("oversight").await
}

#[tokio::test]
async fn audit_rejects_status() -> Result<(), BoxError> {
    reject_status("audit").await
}

#[tokio::test]
async fn rejects_no_audit() -> Result<(), BoxError> {
    reject_effect("no-audit").await
}

#[tokio::test]
async fn rejects_no_notify() -> Result<(), BoxError> {
    reject_effect("no-notify").await
}

#[tokio::test]
async fn rejects_double_bump() -> Result<(), BoxError> {
    reject_effect("double-bump").await
}

#[tokio::test]
async fn rejects_no_tenant_filter() -> Result<(), BoxError> {
    reject_effect("no-tenant-filter").await
}

#[tokio::test]
async fn overview_defaults() -> Result<(), BoxError> {
    run("overview", "defaults", false).await
}

#[tokio::test]
async fn grant_missing_fields() -> Result<(), BoxError> {
    run("grant", "missing-fields", false).await
}

#[tokio::test]
async fn grant_bad_permission() -> Result<(), BoxError> {
    run("grant", "bad-permission", false).await
}

#[tokio::test]
async fn grant_missing_grantee() -> Result<(), BoxError> {
    run("grant", "missing-grantee", false).await
}

#[tokio::test]
async fn grant_go_json() -> Result<(), BoxError> {
    run("grant", "go-json", false).await
}

#[tokio::test]
async fn set_default_wrong_type() -> Result<(), BoxError> {
    run("set_default", "wrong-type", false).await
}

#[tokio::test]
async fn set_default_bad_default() -> Result<(), BoxError> {
    run("set_default", "bad-default", false).await
}

#[tokio::test]
async fn set_default_explicit_audience() -> Result<(), BoxError> {
    run("set_default", "explicit-audience", false).await
}

#[tokio::test]
async fn set_default_go_json() -> Result<(), BoxError> {
    run("set_default", "go-json", false).await
}

#[tokio::test]
async fn create_default_wrong_type() -> Result<(), BoxError> {
    run("create_default", "wrong-type", false).await
}

#[tokio::test]
async fn create_default_bad_default() -> Result<(), BoxError> {
    run("create_default", "bad-default", false).await
}

#[tokio::test]
async fn create_default_go_json() -> Result<(), BoxError> {
    run("create_default", "go-json", false).await
}

#[tokio::test]
async fn create_default_scoped_foreign() -> Result<(), BoxError> {
    run("create_default", "scoped-foreign", false).await
}

#[tokio::test]
async fn delete_default_scoped_foreign() -> Result<(), BoxError> {
    run("delete_default", "scoped-foreign", false).await
}

#[tokio::test]
async fn oversight_scoped_foreign() -> Result<(), BoxError> {
    run("oversight", "scoped-foreign", false).await
}

#[tokio::test]
async fn list_defaults_scoped_list() -> Result<(), BoxError> {
    run("list_defaults", "scoped-list", false).await
}

#[tokio::test]
async fn list_defaults_expired() -> Result<(), BoxError> {
    run("list_defaults", "expired", false).await
}

#[tokio::test]
async fn list_defaults_jit_dormant() -> Result<(), BoxError> {
    run("list_defaults", "jit-dormant", false).await
}

#[tokio::test]
async fn oversight_missing() -> Result<(), BoxError> {
    run("oversight", "missing", false).await
}

#[tokio::test]
async fn create_default_language() -> Result<(), BoxError> {
    run("create_default", "language", false).await
}

#[tokio::test]
async fn create_default_reason_required() -> Result<(), BoxError> {
    run("create_default", "reason-required", false).await
}

#[tokio::test]
async fn create_default_reason_present() -> Result<(), BoxError> {
    run("create_default", "reason-present", false).await
}

#[tokio::test]
async fn delete_default_reason_required() -> Result<(), BoxError> {
    run("delete_default", "reason-required", false).await
}

#[tokio::test]
async fn delete_default_reason_present() -> Result<(), BoxError> {
    run("delete_default", "reason-present", false).await
}

async fn plant_fault(
    c: &tokio_postgres::Client,
    db: &Db,
    table: &str,
    user: i64,
) -> Result<(String, String), BoxError> {
    let schema = format!("gofree_drive1_fault_{user}");
    ledger(&format!(
        "Plan private query/audit fault schema {schema}, assigned DB only"
    ))?;
    if !matches!(
        table,
        "mailbox_delegates"
            | "calendar_acls"
            | "sharing_defaults"
            | "mailboxes"
            | "users"
            | "admin_audit_log"
            | "audit-fault"
    ) {
        return Err("unknown fault table".into());
    }
    c.batch_execute(&format!(
        "CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO setjoin_app;"
    ))
    .await?;
    c.batch_execute(&format!("CREATE TABLE {schema}.control(armed boolean NOT NULL); INSERT INTO {schema}.control VALUES(false)")).await?;
    let sql = if table == "audit-fault" {
        format!("CREATE FUNCTION {schema}.fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.user_id={user} AND (SELECT armed FROM {schema}.control) THEN RAISE EXCEPTION 'drive1 audit fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER gofree_drive1_fault_{user} BEFORE INSERT ON public.admin_audit_log FOR EACH ROW EXECUTE FUNCTION {schema}.fail()")
    } else {
        format!("CREATE FUNCTION {schema}.fail() RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN IF (SELECT armed FROM {schema}.control) THEN RAISE EXCEPTION 'drive1 query fault'; END IF; RETURN true; END $$; CREATE VIEW {schema}.{table} AS SELECT t.* FROM public.{table} t WHERE {schema}.fail()")
    };
    if let Err(e) = c.batch_execute(&sql).await {
        c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
        return Err(e.into());
    }
    let dsn = if table == "audit-fault" {
        db.dsn.clone()
    } else {
        format!(
            "{}{}options=-csearch_path%3D{}%2Cpublic",
            db.dsn,
            if db.dsn.contains('?') { "&" } else { "?" },
            schema
        )
    };
    Ok((dsn, schema))
}

#[tokio::test]
async fn overview_query_fault_mailbox_delegates() -> Result<(), BoxError> {
    run("overview", "query-fault-mailbox_delegates", false).await
}

#[tokio::test]
async fn overview_query_fault_calendar_acls() -> Result<(), BoxError> {
    run("overview", "query-fault-calendar_acls", false).await
}

#[tokio::test]
async fn overview_query_fault_sharing_defaults() -> Result<(), BoxError> {
    run("overview", "query-fault-sharing_defaults", false).await
}

#[tokio::test]
async fn grant_query_fault_mailboxes() -> Result<(), BoxError> {
    run("grant", "query-fault-mailboxes", false).await
}

#[tokio::test]
async fn revoke_query_fault_mailboxes() -> Result<(), BoxError> {
    run("revoke", "query-fault-mailboxes", false).await
}

#[tokio::test]
async fn set_default_query_fault_users() -> Result<(), BoxError> {
    run("set_default", "query-fault-users", false).await
}

#[tokio::test]
async fn list_defaults_query_fault_sharing_defaults() -> Result<(), BoxError> {
    run("list_defaults", "query-fault-sharing_defaults", false).await
}

#[tokio::test]
async fn oversight_query_fault_users() -> Result<(), BoxError> {
    run("oversight", "query-fault-users", false).await
}

#[tokio::test]
async fn oversight_query_fault_mailbox_delegates() -> Result<(), BoxError> {
    run("oversight", "query-fault-mailbox_delegates", false).await
}

#[tokio::test]
async fn oversight_query_fault_calendar_acls() -> Result<(), BoxError> {
    run("oversight", "query-fault-calendar_acls", false).await
}

#[tokio::test]
async fn oversight_query_fault_sharing_defaults() -> Result<(), BoxError> {
    run("oversight", "query-fault-sharing_defaults", false).await
}

#[tokio::test]
async fn audit_query_fault_admin_audit_log() -> Result<(), BoxError> {
    run("audit", "query-fault-admin_audit_log", false).await
}

#[tokio::test]
async fn grant_audit_fault() -> Result<(), BoxError> {
    run("grant", "audit-fault", false).await
}

#[tokio::test]
async fn revoke_audit_fault() -> Result<(), BoxError> {
    run("revoke", "audit-fault", false).await
}

#[tokio::test]
async fn set_default_audit_fault() -> Result<(), BoxError> {
    run("set_default", "audit-fault", false).await
}

#[tokio::test]
async fn clear_default_audit_fault() -> Result<(), BoxError> {
    run("clear_default", "audit-fault", false).await
}

#[tokio::test]
async fn create_default_audit_fault() -> Result<(), BoxError> {
    run("create_default", "audit-fault", false).await
}

#[tokio::test]
async fn delete_default_audit_fault() -> Result<(), BoxError> {
    run("delete_default", "audit-fault", false).await
}

#[tokio::test]
async fn overview_partial_rows() -> Result<(), BoxError> {
    run("overview", "partial-rows", false).await
}

#[tokio::test]
async fn overview_parse_fault_mailbox_delegates() -> Result<(), BoxError> {
    run("overview", "parse-fault-mailbox_delegates", false).await
}

#[tokio::test]
async fn overview_parse_fault_calendar_acls() -> Result<(), BoxError> {
    run("overview", "parse-fault-calendar_acls", false).await
}

#[tokio::test]
async fn overview_parse_fault_sharing_defaults() -> Result<(), BoxError> {
    run("overview", "parse-fault-sharing_defaults", false).await
}

#[tokio::test]
async fn list_defaults_parse_fault_sharing_defaults() -> Result<(), BoxError> {
    run("list_defaults", "parse-fault-sharing_defaults", false).await
}

#[tokio::test]
async fn oversight_parse_fault_mailbox_delegates() -> Result<(), BoxError> {
    run("oversight", "parse-fault-mailbox_delegates", false).await
}

#[tokio::test]
async fn oversight_parse_fault_calendar_acls() -> Result<(), BoxError> {
    run("oversight", "parse-fault-calendar_acls", false).await
}

#[tokio::test]
async fn oversight_parse_fault_sharing_defaults() -> Result<(), BoxError> {
    run("oversight", "parse-fault-sharing_defaults", false).await
}

#[tokio::test]
async fn audit_parse_fault_admin_audit_log() -> Result<(), BoxError> {
    run("audit", "parse-fault-admin_audit_log", false).await
}

#[tokio::test]
async fn grant_success_state_v2() -> Result<(), BoxError> {
    run("grant", "success-state-v2", false).await
}

#[tokio::test]
async fn grant_foreign_state_v2() -> Result<(), BoxError> {
    run("grant", "foreign-state-v2", false).await
}

#[tokio::test]
async fn grant_invalid_state_v2() -> Result<(), BoxError> {
    run("grant", "invalid-state-v2", false).await
}

#[tokio::test]
async fn grant_repeat_state_v2() -> Result<(), BoxError> {
    run("grant", "repeat-state-v2", false).await
}

#[tokio::test]
async fn revoke_success_state_v2() -> Result<(), BoxError> {
    run("revoke", "success-state-v2", false).await
}

#[tokio::test]
async fn revoke_foreign_state_v2() -> Result<(), BoxError> {
    run("revoke", "foreign-state-v2", false).await
}

#[tokio::test]
async fn revoke_invalid_state_v2() -> Result<(), BoxError> {
    run("revoke", "invalid-state-v2", false).await
}

#[tokio::test]
async fn revoke_repeat_state_v2() -> Result<(), BoxError> {
    run("revoke", "repeat-state-v2", false).await
}

#[tokio::test]
async fn set_default_success_state_v2() -> Result<(), BoxError> {
    run("set_default", "success-state-v2", false).await
}

#[tokio::test]
async fn set_default_foreign_state_v2() -> Result<(), BoxError> {
    run("set_default", "foreign-state-v2", false).await
}

#[tokio::test]
async fn set_default_invalid_state_v2() -> Result<(), BoxError> {
    run("set_default", "invalid-state-v2", false).await
}

#[tokio::test]
async fn set_default_repeat_state_v2() -> Result<(), BoxError> {
    run("set_default", "repeat-state-v2", false).await
}

#[tokio::test]
async fn clear_default_success_state_v2() -> Result<(), BoxError> {
    run("clear_default", "success-state-v2", false).await
}

#[tokio::test]
async fn clear_default_foreign_state_v2() -> Result<(), BoxError> {
    run("clear_default", "foreign-state-v2", false).await
}

#[tokio::test]
async fn clear_default_invalid_state_v2() -> Result<(), BoxError> {
    run("clear_default", "invalid-state-v2", false).await
}

#[tokio::test]
async fn clear_default_repeat_state_v2() -> Result<(), BoxError> {
    run("clear_default", "repeat-state-v2", false).await
}

#[tokio::test]
async fn create_default_success_state_v2() -> Result<(), BoxError> {
    run("create_default", "success-state-v2", false).await
}

#[tokio::test]
async fn create_default_foreign_state_v2() -> Result<(), BoxError> {
    run("create_default", "foreign-state-v2", false).await
}

#[tokio::test]
async fn create_default_invalid_state_v2() -> Result<(), BoxError> {
    run("create_default", "invalid-state-v2", false).await
}

#[tokio::test]
async fn create_default_repeat_state_v2() -> Result<(), BoxError> {
    run("create_default", "repeat-state-v2", false).await
}

#[tokio::test]
async fn delete_default_success_state_v2() -> Result<(), BoxError> {
    run("delete_default", "success-state-v2", false).await
}

#[tokio::test]
async fn delete_default_foreign_state_v2() -> Result<(), BoxError> {
    run("delete_default", "foreign-state-v2", false).await
}

#[tokio::test]
async fn delete_default_invalid_state_v2() -> Result<(), BoxError> {
    run("delete_default", "invalid-state-v2", false).await
}

#[tokio::test]
async fn delete_default_repeat_state_v2() -> Result<(), BoxError> {
    run("delete_default", "repeat-state-v2", false).await
}

#[tokio::test]
async fn commit_before_remains_unknown_and_resolves_absent() -> Result<(), BoxError> {
    run("set_default", "commit-before", false).await
}
#[tokio::test]
async fn commit_after_remains_unknown_and_resolves_committed() -> Result<(), BoxError> {
    run("set_default", "commit-after", false).await
}

#[tokio::test]
async fn audit_offset_overflow() -> Result<(), BoxError> {
    run("audit", "offset-overflow", false).await
}

#[tokio::test]
async fn audit_malformed_filter() -> Result<(), BoxError> {
    run("audit", "malformed-filter", false).await
}

#[tokio::test]
async fn create_default_large_trailer() -> Result<(), BoxError> {
    run("create_default", "large-trailer", false).await
}

#[tokio::test]
async fn create_default_oversize_value() -> Result<(), BoxError> {
    run("create_default", "oversize-value", false).await
}
