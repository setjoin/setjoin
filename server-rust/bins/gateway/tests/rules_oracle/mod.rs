//! F09 frozen-Go HTTP observations; ordinary replay has no Go upstream.
mod mask;
mod profiles;
mod templates;
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use sha2::Digest;
use std::sync::Arc;

struct Probe {
    inner: setjoin_gateway::rules::RulesRoute<setjoin_gateway::jmap::jwks::Jwks>,
    fault: Option<String>,
}
impl Intercept for Probe {
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        if self.fault.as_deref() == Some("no-tenant-filter") {
            let (e, w, k, i) = (
                self.inner.exec.clone(),
                self.inner.worker.clone(),
                self.inner.keys.clone(),
                self.inner.issuer.clone(),
            );
            return Box::pin(async move {
                assert!(
                    setjoin_authz::authorize_request(&e, &k, &i, r.headers(), c.identity.proto)
                        .await
                        .is_some(),
                    "mutant must authenticate"
                );
                let body = setjoin_rules::admin_list(&w, None)
                    .await
                    .expect("unscoped read mutant");
                setjoin_gateway::jmap::reply::response(
                    body,
                    c.identity.proto,
                    "gofree-rules1-oracle".into(),
                )
            });
        }
        let f = self.inner.handle(r, c);
        let changed = self.fault.as_deref() == Some("changed-status");
        Box::pin(async move {
            let mut response = f.await;
            if changed {
                *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            response
        })
    }
}

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "personal-list" => ("GET", "/settings/rules-list"),
        "personal-create" => ("POST", "/settings/rules"),
        "personal-update" => ("PUT", "/settings/rules/{id}"),
        "personal-delete" => ("DELETE", "/settings/rules/{id}"),
        "retro-apply" => ("POST", "/settings/rules/{id}/apply"),
        "retro-status" => ("GET", "/settings/rules/apply/{actionId}"),
        "admin-list" => ("GET", "/admin/rules"),
        "admin-get" => ("GET", "/admin/rules/{id}"),
        "admin-create" => ("POST", "/admin/rules"),
        "admin-update" => ("PUT", "/admin/rules/{id}"),
        "admin-delete" => ("DELETE", "/admin/rules/{id}"),
        "admin-test" => ("POST", "/admin/rules/{id}/test"),
        "template-list" => ("GET", "/admin/rule-templates"),
        "template-get" => ("GET", "/admin/rule-templates/{id}"),
        "template-resolve" => ("GET", "/admin/rule-templates/{id}/resolve"),
        "template-create" => ("POST", "/admin/rule-templates"),
        "template-update" => ("PUT", "/admin/rule-templates/{id}"),
        "template-delete" => ("DELETE", "/admin/rule-templates/{id}"),
        "template-visibility-get" => ("GET", "/admin/rule-templates/{id}/visibility"),
        "template-visibility-set" => ("POST", "/admin/rule-templates/{id}/visibility"),
        "template-personal-list" => ("GET", "/settings/rule-templates"),
        _ => panic!("unknown rules action {action}"),
    }
}

pub async fn run(action: &str, label: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_at(action, label, fault, None).await
}

async fn run_at(
    action: &str,
    label: &str,
    fault: Option<&str>,
    record_address: Option<std::net::SocketAddr>,
) -> Result<(), BoxError> {
    let Some(db) = Db::for_case("rules1-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "rules1-actor").await?;
    let b = fixture::account(&owner, "rules1-other").await?;
    let audit_start: i64 = owner
        .query_one("SELECT coalesce(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let mut legacy = false;
    let mut undo = Vec::<String>::new();
    let result=async {
        if fault.is_some() && (record_address.is_some()||std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some()){return Err("mutants must never record Go goldens".into());}
        if (action.starts_with("template-")||label.starts_with("from-template")) && label!="schema-missing" && !label.ends_with("-schema-missing") {templates::seed(&owner,&a).await?;legacy=true;}
        owner.execute("INSERT INTO rules(id,mailbox_id,name,enabled,priority,run_on,conditions,actions,created_at,updated_at) VALUES(961001,$1,'Actor rule',true,1,'server','[]','[]','2026-10-01','2026-10-01'),(961002,$2,'Other rule',true,2,'server','[]','[]','2026-10-01','2026-10-01')",&[&a.mailbox,&b.mailbox]).await?;
        owner.batch_execute("SELECT setval('rules_id_seq',962000)").await?;
        if action=="retro-status" {owner.execute("INSERT INTO scheduled_actions(id,action_kind,mailbox_id,fire_at,payload,status,created_at) VALUES('96100000-0000-4000-8000-000000000001','rules_retro',$1,'2026-10-01','{\"processed\":12,\"truncated\":true}','done','2026-10-01')",&[&if label=="foreign"{b.mailbox}else{a.mailbox}]).await?;}
        let (method,pattern)=route(action);
        let admin=pattern.starts_with("/admin/");
        let role=format!("rules1-role-{}",a.user);
        if admin {
            let (permissions,scoped)=profiles::persona(action,label);
            let domain=if scoped {Some(b.domain)}else{None};
            owner.execute("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3)",&[&role,&permissions,&domain]).await?;
            owner.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) SELECT $1,id,$1,false FROM admin_role_groups WHERE name=$2",&[&a.user,&role]).await?;
        }
        profiles::seed(&owner,&a,&b,action,label).await?;
        let body=if label.starts_with("from-template") {r#"{"word":"status & \"updates\""}"#.into()} else if action=="template-visibility-set" {format!(r#"{{"userId":{},"hidden":true}}"#,b.user)} else if action=="template-update" {r#"{"name":"Renamed template","description":"Changed description","category":"organization","conditions":[],"actions":[],"parameters":[],"enabled":false,"sortOrder":7}"#.into()} else if action=="template-create" {r#"{"name":"Created template","description":"Created description","category":"general","conditions":[],"actions":[{"type":"mark_read"}],"parameters":[],"enabled":false,"sortOrder":4}"#.into()} else if action=="admin-update" {r#"{"name":"Admin renamed rule","enabled":true,"priority":4,"runOn":"client","conditions":[],"actions":[],"stopProcessing":true}"#.into()} else if action=="admin-create" {format!(r#"{{"name":"Admin created rule","enabled":true,"priority":3,"runOn":"server","mailboxId":{},"isTransportRule":false,"conditions":[],"actions":[{{"type":"mark_read"}}],"stopProcessing":true}}"#,a.mailbox)} else if action=="personal-create" {format!(r#"{{"name":"Created rule","enabled":true,"priority":3,"runOn":"both","mailboxId":{},"isTransportRule":true,"conditions":[],"actions":[{{"type":"mark_read"}}],"stopProcessing":true}}"#,b.mailbox)} else if action=="personal-update" {format!(r#"{{"name":"Renamed rule","enabled":true,"priority":4,"runOn":"client","mailboxId":{},"isTransportRule":true,"conditions":[],"actions":[],"stopProcessing":true}}"#,b.mailbox)} else if action=="retro-apply" {r#"{"window":"90d"}"#.into()} else {String::new()};
        let query=if label.starts_with("from-template"){ "?from_template=961011" }else{""}.to_owned();
        let path=pattern.replace("{id}",if action.starts_with("template-"){ "961011" }else{"961001"}).replace("{actionId}","96100000-0000-4000-8000-000000000001");
        let (body,path,query)=profiles::request(action,label,&a,&b,body,path,query);
        if matches!(fault,Some("no-audit"|"double-bump")) {
            let schema=format!("gofree_rules1_fault_{}",a.user);
            let (table,timing,body)=if fault==Some("no-audit"){("admin_audit_log","BEFORE","RETURN NULL;")}else{("rules","AFTER","UPDATE mailboxes SET jmap_email_state=jmap_email_state+1 WHERE id=NEW.mailbox_id; RETURN NEW;")};
            owner.batch_execute(&format!("BEGIN;CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN {body} END $fault$;CREATE TRIGGER {schema} {timing} INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION {schema}.fault();COMMIT;")).await?;
            undo.push(format!("DROP TRIGGER {schema} ON {table};DROP SCHEMA {schema} CASCADE;"));
        }
        let s3=common::fake_upstream(|_| async {Response::new(common::full(""))}).await;
        let go=if record_address.is_none(){common::go_oracle::start_named(&db,s3,None,"gofree-rules1-http").await?}else{None};
        let recording=go.is_some()||record_address.is_some();
        let mut inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"]=="F09" {
                r["state"]=json!(if recording {"OFF"} else {"ON"});
                r["upstream"]=json!(if recording {"go-mail"} else {"local-rust"});
                r["oracle_commands"]=json!([""]);
            }
        }
        let mut request_dsn=db.app.clone().unwrap_or_else(||db.dsn.clone());
        let mut worker_dsn=db.dsn.clone();
        let mut cut_task=None;
        if matches!(fault,Some("commit-before"|"commit-after")) {
            let cut=if fault==Some("commit-after"){common::commit::CommitCut::AfterCommit}else{common::commit::CommitCut::BeforeCommit};
            let worker=action.starts_with("admin-");
            let (dsn,task)=common::commit::commit_cut_proxy(if worker{&worker_dsn}else{&request_dsn},cut).await;
            if worker{worker_dsn=dsn}else{request_dsn=dsn};cut_task=Some(task);
        }
        let gateway=Gateway::new(Config{upstream:record_address.or_else(||go.as_ref().map(|g|g.address)).map(|a|format!("http://{a}").parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},RouteTable::proxy_all().with(Probe{fault:fault.map(str::to_owned),inner:setjoin_gateway::rules::RulesRoute{exec:common::patient_exec(&request_dsn,1)?.with_audit_keys("22".repeat(32),String::new()),worker:common::patient_exec(&worker_dsn,1)?.with_audit_keys("22".repeat(32),String::new()),keys:Arc::new(common::recovery_keys()),issuer:"mailserver".into()}}))?.with_inventory(&inventory.to_string())?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address=listener.local_addr()?;
        let server=tokio::spawn(gateway.serve(listener));
        let token=if admin||label=="admin-view" {mask::admin_token(a.user)} else {common::recovery_token(a.user)};
        let send=|| {
            let request=Request::builder().method(method).uri(format!("/api{path}{query}")).header("content-type","application/json").header("host","mail.test").header("origin","http://mail.test").header("x-request-id","gofree-rules1-oracle").header("authorization",format!("Bearer {token}")).body(common::full(body.clone()));
            async move {Ok::<_,BoxError>(common::send(address,request?).await)}
        };
        if label=="repeat"||label.ends_with("-repeat") {
            let first=send().await?;let status=first.status();let bytes=common::body_bytes(first).await;
            if !status.is_success(){return Err(format!("repeat initial call failed: {status}: {bytes:?}").into());}
        }
        let before=snapshot(&owner,&a,&b,action,label).await?;
        let last:i64=owner.query_one("SELECT coalesce(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
        let mut notifications=db.listen("config_changed").await?;
        let mut tag_a=db.listen(&format!("tag:{}",a.mailbox)).await?;
        let mut tag_b=db.listen(&format!("tag:{}",b.mailbox)).await?;
        let mut alerts=db.listen("admin:alert").await?;
        let response=send().await?;
        let status=response.status().as_u16();
        let mut headers=serde_json::Map::new();
        for name in response.headers().keys() { headers.insert(name.to_string(),json!(response.headers().get_all(name).iter().map(|v|v.to_str().unwrap().to_owned()).collect::<Vec<_>>())); }
        let after=snapshot(&owner,&a,&b,action,label).await?;
        let mut events=Vec::new();
        for (channel,items) in [("config_changed",notifications.drain(&owner).await?),("tag:<mailbox-actor>",tag_a.drain(&owner).await?),("tag:<mailbox-other>",tag_b.drain(&owner).await?),("admin:alert",alerts.drain(&owner).await?)] {
            for payload in items {events.push(json!({"channel":channel,"payload":serde_json::from_str::<Value>(&payload).unwrap_or(json!(payload))}));}
        }
        let raw=String::from_utf8(common::body_bytes(response).await.to_vec())?;
        if !recording {
            let metrics=common::send(address,Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l|l=="setjoin_gateway_proxied_to_go_total 0")||!metrics.lines().any(|l|l=="setjoin_gateway_proxied_to_go_by_family_total{family=\"F09\"} 0"){return Err(format!("replay attempted Go: {metrics}").into());}
        }
        server.abort(); let _=server.await;
        let ids=vec![("MAILBOXID",a.mailbox,"<mailbox-actor>".into()),("MAILBOXID",b.mailbox,"<mailbox-other>".into()),("mailboxId",a.mailbox,"<mailbox-actor>".into()),("mailboxId",b.mailbox,"<mailbox-other>".into()),("mailbox_id",a.mailbox,"<mailbox-actor>".into()),("mailbox_id",b.mailbox,"<mailbox-other>".into()),("user_id",a.user,"<actor>".into()),("actor_id",a.user,"<actor>".into()),("userId",a.user,"<actor>".into()),("user_id",b.user,"<other>".into()),("userId",b.user,"<other>".into())];
        let tidy=|t:&str| {
            let base=mask::mask_timestamps(&mask::mask_ids(t,&ids)).replace(&format!("domain={}",b.domain),"domain=<scope-domain>").replace(&format!("\"mailboxId\":\"{}\"",b.mailbox),"\"mailboxId\":\"<mailbox-other>\"");
            if action.starts_with("retro-") {mask::mask_strings(&base.replace(&format!("rules_retro:{}:",a.mailbox),"rules_retro:<mailbox-actor>:"),&["actionId","id"])}else{base}
        };
        let text=tidy(&raw);
        let mut audit:Vec<Value>=owner.query("SELECT to_jsonb(t)::text FROM admin_audit_log t WHERE id>$1 ORDER BY id",&[&last]).await?.iter().map(|r|serde_json::from_str(&r.get::<_,String>(0))).collect::<Result<_,_>>()?;
        for row in &mut audit {row["id"]=json!("<audit>");for key in ["checksum","prev_checksum"]{if row[key].as_str().is_some_and(|v|!v.is_empty()){row[key]=json!("<checksum>");}}*row=serde_json::from_str(&tidy(&row.to_string()))?;}
        headers.insert("date".into(),json!(["<timestamp>"]));
        if headers.contains_key("content-length") { headers.insert("content-length".into(),json!([text.len().to_string()])); }
        let normalized_body=tidy(&body);
        let shown_body=if body.len()>1024{format!("<{} normalized bytes; sha256={:x}>",normalized_body.len(),sha2::Sha256::digest(normalized_body.as_bytes()))}else{normalized_body};
        let mut shown_request=if body.is_empty(){json!({"method":method,"path":pattern})}else{json!({"method":method,"path":pattern,"body":shown_body})};
        if !query.is_empty(){shown_request["query"]=json!(query.replace(&format!("mailboxId={}",a.mailbox),"mailboxId=<mailbox-actor>").replace(&format!("mailboxId={}",b.mailbox),"mailboxId=<mailbox-other>").replace(&format!("userId={}",b.user),"userId=<other>"));}
        if action.starts_with("template-")||label.starts_with("from-template"){shown_request["fixture"]=json!(if legacy{"legacy-tables"}else{"active-schema"});}
        let observation=json!({"request":shown_request,"response":{"status":status,"headers":headers,"body":text},"effects":[{"table":"rules","before":serde_json::from_str::<Value>(&tidy(&before.to_string()))?,"after":serde_json::from_str::<Value>(&tidy(&after.to_string()))?}],"audit":audit,"notify":serde_json::from_str::<Value>(&tidy(&json!(events).to_string()))?});
        if fault.is_none() && action == "personal-list" && label == "success" && status != 200 { return Err(format!("personal list must answer 200, got {status}: {raw}").into()); }
        let path=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/rules/goldens/{action}-{label}.json"));
        if let Some(mut task)=cut_task {
            let cut=tokio::time::timeout(std::time::Duration::from_secs(5),&mut task).await???;
            assert_eq!(cut==common::commit::CommitCut::AfterCommit,fault==Some("commit-after"));
            assert_eq!(status,503,"COMMIT loss must be ambiguous, not setup failure");
            let operation=observation["response"]["headers"]["x-operation-id"][0].as_str().ok_or("missing ambiguous operation id")?;
            assert_eq!(operation.len(),32);
            let receipt:bool=owner.query_one("SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=$1::text::uuid AND family='F09')",&[&operation]).await?.get(0);
            assert_eq!(receipt,fault==Some("commit-after"),"operation lookup must resolve real commit outcome");
            if receipt {
                let expected:Value=serde_json::from_slice(&std::fs::read(path)?)?;
                for field in ["effects","audit","notify"] {golden::compare(&expected["observation"][field],&observation[field])?;}
            } else {
                assert_eq!(observation["effects"][0]["before"],observation["effects"][0]["after"],"uncommitted command changed data/state");
                assert_eq!(observation["audit"],json!([]));assert_eq!(observation["notify"],json!([]));
            }
            eprintln!("COMMIT-CUT: {method} {pattern} :: {}",fault.unwrap());
            return Ok(());
        }
        if recording {
            std::fs::create_dir_all(path.parent().unwrap())?;
            golden::record(&path,&json!({"format":1,"route":format!("{method} {pattern}"),"case":label,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}))?;
        } else {
            let rows=path.with_file_name(format!("{action}-{label}-rows.json"));
            let expected:Value=serde_json::from_slice(&std::fs::read(path)?)?;
            if rows.exists(){let rows:Value=serde_json::from_slice(&std::fs::read(rows)?)?;golden::compare(&expected["observation"]["effects"],&rows["effects"])?;}
            let compared=golden::compare(&expected["observation"],&observation);
            if let Some(fault)=fault {
                let error=compared.err().ok_or("planted mutant survived")?;
                let wanted=match fault{"changed-status"=>"/response/status","no-audit"=>"/audit","double-bump"=>"/effects/0/after/states","no-tenant-filter"=>"/response/body",_=>return Err("unknown mutant".into())};
                if !error.contains(wanted){return Err(format!("mutant failed outside expected observation: {error}").into());}
                if fault!="changed-status"&&observation["response"]["status"]!=expected["observation"]["response"]["status"]{return Err("family mutant aborted the request instead of changing its effect".into());}
                if fault=="no-tenant-filter"&&!raw.contains("Other rule"){return Err("tenant mutant did not expose the foreign fixture".into());}
                eprintln!("MUTANT-REJECTED: {method} {pattern} :: {fault}");
                return Ok(());
            }
            compared?;
            eprintln!("GOLDEN-REPLAY: {method} {pattern} :: {label}");
        }

        Ok::<_,BoxError>(())
    }.await;
    for statement in &undo {
        owner.batch_execute(statement).await?;
    }
    if legacy {
        templates::remove(&owner).await?;
    }
    owner
        .execute(
            "DELETE FROM scheduled_actions WHERE mailbox_id IN($1,$2)",
            &[&a.mailbox, &b.mailbox],
        )
        .await?;
    owner
        .batch_execute("DELETE FROM rules WHERE id BETWEEN 961001 AND 963000")
        .await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM admin_role_groups WHERE name=$1",
            &[&format!("rules1-role-{}", a.user)],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM rust_operation_receipts WHERE family='F09'",
            &[],
        )
        .await?;
    for account in [&a, &b] {
        common::remove_blob_account(&owner, account).await?;
    }
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
    result
}

async fn snapshot(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
    action: &str,
    label: &str,
) -> Result<Value, BoxError> {
    let rules:Vec<Value>=c.query("SELECT to_jsonb(r)::text FROM rules r WHERE mailbox_id IN($1,$2) OR mailbox_id IS NULL ORDER BY id",&[&a.mailbox,&b.mailbox]).await?.iter().map(|r|serde_json::from_str(&r.get::<_,String>(0))).collect::<Result<_,_>>()?;
    let state:Vec<Value>=c.query("SELECT jsonb_build_object('mailbox_id',id,'email',jmap_email_state,'tag',jmap_mailbox_state)::text FROM mailboxes WHERE id IN($1,$2) ORDER BY id",&[&a.mailbox,&b.mailbox]).await?.iter().map(|r|serde_json::from_str(&r.get::<_,String>(0))).collect::<Result<_,_>>()?;
    let mut snapshot = json!({"rules":rules,"states":state});
    if action.starts_with("retro-") {
        let jobs:Vec<Value>=c.query("SELECT to_jsonb(j)::text FROM scheduled_actions j WHERE mailbox_id IN($1,$2) ORDER BY id",&[&a.mailbox,&b.mailbox]).await?.iter().map(|r|serde_json::from_str(&r.get::<_,String>(0))).collect::<Result<_,_>>()?;
        snapshot["scheduled_actions"] = json!(jobs);
    }
    if label == "all-states" {
        let all:Vec<Value>=c.query("SELECT (jsonb_build_object('mailbox_id',m.id)||(SELECT jsonb_object_agg(key,value) FROM jsonb_each(to_jsonb(m)) WHERE key ~ '^jmap_.*_state$'))::text FROM mailboxes m WHERE id IN($1,$2) ORDER BY id",&[&a.mailbox,&b.mailbox]).await?.iter().map(|r|serde_json::from_str(&r.get::<_,String>(0))).collect::<Result<_,_>>()?;
        snapshot["all_states"] = json!(all);
    }
    if action.starts_with("template-") || label.starts_with("from-template") {
        templates::snapshot(c, &mut snapshot).await?;
    }
    Ok(snapshot)
}

/// The explicit recording driver shares one frozen process; every request still
/// has fresh actors, committed seeds and its own complete observation/cleanup.
pub async fn record_selected(cases: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("rules1-record-batch").ok_or("recording requires disposable DB")?;
    let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
    let go = common::go_oracle::start_named(&db, s3, None, "gofree-rules1-http")
        .await?
        .ok_or("batch recording requires GOFREE_RECORD_GO_BINARY")?;
    for pair in cases.split(',').filter(|s| !s.is_empty()) {
        let (action, label) = pair.split_once(':').ok_or("case must be action:label")?;
        // Fresh process prevents legacy-fixture prepared descriptions leaking into the absent schema.
        let address=if label.ends_with("schema-missing"){None}else{Some(go.address)};
        run_at(action, label, None, address).await?;
        eprintln!("GO-RECORDED: {action} :: {label}");
    }
    Ok(())
}
