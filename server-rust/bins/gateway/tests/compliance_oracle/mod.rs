mod export;
pub mod mutants;
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{compliance::ComplianceRoute, Config, Gateway, RouteTable, TrustedProxies};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
    let fields = source.split('.').collect::<Vec<_>>();
    let mut claims: Value = serde_json::from_slice(&B64.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = json!(true);
    claims["perms"] = json!(["forged.permission"]);
    let payload = B64.encode(claims.to_string());
    let signature: p256::ecdsa::Signature = SigningKey::from_slice(&[0x11; 32])
        .unwrap()
        .sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        fields[0],
        B64.encode(signature.to_bytes())
    )
}
fn mask(v: &mut Value, user: i64) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if [
                    "created_by",
                    "createdBy",
                    "closed_by",
                    "closedBy",
                    "user_id",
                    "actor_id",
                ]
                .contains(&k.as_str())
                    && x.as_i64() == Some(user)
                {
                    *x = json!("<actor>");
                } else {
                    mask(x, user);
                }
            }
        }
        Value::Array(xs) => {
            for x in xs {
                mask(x, user)
            }
        }
        Value::String(s) => {
            let b = s.as_bytes();
            if b.len() > 19
                && b.get(4) == Some(&b'-')
                && b.get(7) == Some(&b'-')
                && b.get(13) == Some(&b':')
            {
                *s = "<timestamp>".into();
            }
        }
        _ => {}
    }
}
async fn snapshot(c: &tokio_postgres::Client, mailbox: Option<i64>) -> Result<Value, BoxError> {
    let mut out = json!({});
    for (table,sql) in [
        ("cases","SELECT to_jsonb(t)::text FROM ediscovery_cases t ORDER BY id"),
        ("searches","SELECT to_jsonb(t)::text FROM ediscovery_searches t ORDER BY id"),
        ("results","SELECT to_jsonb(t)::text FROM ediscovery_search_results t ORDER BY search_id,message_id"),
    ] {
        out[table]=Value::Array(c.query(sql,&[]).await?.iter().map(|r|serde_json::from_str(&r.get::<_,String>(0))).collect::<Result<_,_>>()?);
    }
    if let Some(mailbox) = mailbox {
        out["messages"]=Value::Array(c.query("SELECT jsonb_build_object('id',id,'mailbox_id',mailbox_id,'held',held)::text FROM messages WHERE mailbox_id=$1 ORDER BY id",&[&mailbox]).await?.iter().map(|r|serde_json::from_str(&r.get::<_,String>(0))).collect::<Result<_,_>>()?);
        out["mailbox_state"]=serde_json::from_str(&c.query_one("SELECT jsonb_build_object('email',jmap_email_state,'tag',jmap_tag_state,'thread',jmap_thread_state,'mailbox',jmap_mailbox_state)::text FROM mailboxes WHERE id=$1",&[&mailbox]).await?.get::<_,String>(0))?;
    }
    Ok(out)
}
pub async fn run(action: &str, label: &str) -> Result<(), BoxError> {
    run_with(action, label, "").await
}
pub async fn run_with(action: &str, label: &str, mutant: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("compl1-http").ok_or("DB required")?;
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "compl1-admin").await?;
    let role:i64=owner.query_one("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES ('compl1-oracle',$1,$2) RETURNING id", &[&if label=="denied" {vec!["users.read"]} else {vec!["domains.read","compliance.write","mail.export"]}, &if label=="foreign" {Some(a.domain)} else {None}]).await?.get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(role_group_id,user_id) VALUES ($1,$2)",
            &[&role, &a.user],
        )
        .await?;
    let mailbox_email: String = owner
        .query_one("SELECT email FROM mailboxes WHERE id=$1", &[&a.mailbox])
        .await?
        .get(0);
    let message_scope =
        matches!(action, "hold" | "release" | "start" | "search" | "export").then_some(a.mailbox);
    let result=async {
        if action=="release" {owner.execute("UPDATE messages SET held=true WHERE mailbox_id=$1",&[&a.mailbox]).await?;}
        owner.execute("INSERT INTO ediscovery_cases(id,name,description,created_by) OVERRIDING SYSTEM VALUE VALUES (970001,'Investigation','Scope <42>', $1)",&[&a.user]).await?;
        owner.execute("INSERT INTO ediscovery_cases(id,name,description,status,created_by,closed_by,closed_at,created_at) OVERRIDING SYSTEM VALUE VALUES (970002,'Closed investigation','','closed',$1,$1,now(),'2026-01-01')", &[&a.user]).await?;
        if matches!(label,"large-json"|"large-head") {owner.execute("UPDATE ediscovery_cases SET description=repeat('L',5000) WHERE id=970001",&[]).await?;}
        if label=="null-description" { owner.execute("INSERT INTO ediscovery_cases(id,name,created_by,created_at) OVERRIDING SYSTEM VALUE VALUES (970003,'Null description',$1,'2025-01-01')", &[&a.user]).await?; }
        if action=="associate" {owner.execute("INSERT INTO ediscovery_searches(id,name,created_by,query,status) OVERRIDING SYSTEM VALUE VALUES (980001,'Existing search',$1,'{}','pending')",&[&a.user]).await?;}
        if (action=="delete" && label=="associated") || (action=="get" && label=="with-search") {owner.execute("INSERT INTO ediscovery_searches(id,name,created_by,query,status,result_count,case_id) OVERRIDING SYSTEM VALUE VALUES (980001,'Case search',$1,'{}','complete',5,970001)",&[&a.user]).await?;}
        if matches!(action,"search"|"export") {
            let mut query=json!({"keywords":"oracle","kql":"","fromAddr":"","dateFrom":"","dateTo":"","mailboxIds":[a.mailbox]});
            match label {
                "missing-key"=>query=json!({}),
                "bad-kql"=>query["kql"]=json!("("),
                "fields"=>{query["fromAddr"]=json!("sender@example.test");query["dateFrom"]=json!("2026-01-01");query["dateTo"]=json!("2027-01-01");},
                "mixed-mailboxes"=>query["mailboxIds"]=json!([a.mailbox,"bad",null,1.5]),
                "huge-mailbox"=>query["mailboxIds"]=json!([9223372036854775807_i64]),
                _=>{}
            }
            let query=query.to_string();
            owner.execute("INSERT INTO ediscovery_searches(id,name,created_by,query,status,result_count,case_id) OVERRIDING SYSTEM VALUE VALUES (980001,'Result search',$1,$2::text::jsonb,'complete',2,970001)",&[&a.user,&query]).await?;
            owner.execute("INSERT INTO ediscovery_search_results(search_id,message_id) VALUES (980001,$1),(980001,$2)",&[&a.two_labels,&a.inbox_only]).await?;
            match label {
                "pending"=>{owner.execute("UPDATE ediscovery_searches SET status='pending' WHERE id=980001",&[]).await?;},
                "unbound"=>{owner.execute("UPDATE ediscovery_searches SET case_id=NULL WHERE id=980001",&[]).await?;},
                "zero"=>{owner.execute("UPDATE ediscovery_searches SET result_count=0 WHERE id=980001",&[]).await?;},
                "no-count"=>{owner.execute("UPDATE ediscovery_searches SET result_count=NULL WHERE id=980001",&[]).await?;},
                "empty-binding"=>{owner.execute("DELETE FROM ediscovery_search_results WHERE search_id=980001",&[]).await?;},_=>{}
            }
        }
        if action=="export" {owner.execute("UPDATE messages SET raw_ref=CASE WHEN id=$2 THEN 'compl1/export-a' ELSE 'compl1/export-b' END,from_addr='sender@example.test',subject=CASE WHEN id=$2 THEN 'Exported A' ELSE 'Exported B' END WHERE mailbox_id=$1",&[&a.mailbox,&a.two_labels]).await?;}
        let (s3,s3_calls)=if action=="export" {export::s3(label).await}else{(common::fake_upstream(|_|async{Response::new(common::full("From: sender@example.test\r\n\r\nEvidence\r\n"))}).await,Arc::new(std::sync::Mutex::new(Vec::new())))};
        let go=common::go_oracle::start_named(&db,s3,None,"gofree-compl1").await?;
        let recording=go.is_some();
        let patient=std::time::Duration::from_secs(30);
        let proxy=if mutant=="no-tenant-filter"{Some(mutants::tenant_proxy(db.app.as_deref().unwrap_or(&db.dsn)).await?)}else{None};
        let mut request_dsn=proxy.as_ref().map(|p|p.dsn.clone()).unwrap_or_else(||db.app.clone().unwrap_or_else(||db.dsn.clone()));
        let mut worker_dsn=db.dsn.clone();let mut commit_wire=None;
        if mutant.starts_with("commit-") {
            if recording{return Err("COMMIT fault cannot be Go-recorded".into());}
            let cut=if mutant=="commit-after"{common::commit::CommitCut::AfterCommit}else{common::commit::CommitCut::BeforeCommit};
            let (dsn,task)=common::commit::commit_cut_proxy(if matches!(action,"create"|"close"){&request_dsn}else{&worker_dsn},cut).await;
            if matches!(action,"create"|"close"){request_dsn=dsn;}else{worker_dsn=dsn;}commit_wire=Some(task);
        }
        let exec=ScopedExecutor::from_dsn_with(&request_dsn,1,setjoin_pg::Timeouts{pool_wait:patient,create:patient,statement:patient}).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new());
        let worker=ScopedExecutor::from_dsn_with(&worker_dsn,1,setjoin_pg::Timeouts{pool_wait:patient,create:patient,statement:patient}).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new());
        let jobs=setjoin_gateway::compliance::SearchJobs::new(setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?,2);
        let adapter=ComplianceRoute{store:Some(Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{s3}"),"mailblobs","test-access","test-secret")?)),exec,worker,jobs,keys:Arc::new(common::recovery_keys()),issuer:"mailserver".into()};
        let mut inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().unwrap() {if r["family"]=="F04" && r["slice"]=="ediscovery" { if recording {r["state"]=json!("OFF");r["upstream"]=json!("go-mail");}else{assert_eq!(r["state"],"ON");assert_eq!(r["upstream"],"local-rust");}r["oracle_commands"]=json!([""]); }}
        let gateway=Gateway::new(Config{upstream:go.as_ref().map(|g|format!("http://{}",g.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},RouteTable::proxy_all().with(mutants::Status{inner:adapter,change:mutant=="status"}))?.with_inventory(&inventory.to_string())?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let addr=listener.local_addr()?;
        let server=tokio::spawn(gateway.serve(listener));
        if action=="create" {owner.query_one("SELECT setval('ediscovery_cases_id_seq',970100,true)",&[]).await?;}
        if action=="start" {owner.query_one("SELECT setval('ediscovery_searches_id_seq',980100,true)",&[]).await?;}
        let (mut method,path,body)=match action { "export"=>("GET","/admin/ediscovery/export",""), "start"=>("POST","/admin/ediscovery/search",match label {"kql-unicode"=>r#"{"name":"Error quote","kql":"oracle)\u00a0x","caseId":970001}"#,"kql"=>r#"{"name":"Boolean search","kql":"(oracle AND (subject:\"oracle\" OR body:missing)) AND NOT from:nobody AND date:2020-01-01..2030-01-01","caseId":970001}"#,"mailboxes"=>r#"{"name":"Mailbox filter","keywords":"oracle","mailboxIds":[99999999],"caseId":970001}"#,"date-to"=>r#"{"name":"Date filter","keywords":"oracle","dateTo":"2020-01-01","caseId":970001}"#,"date-from"=>r#"{"name":"Date filter","keywords":"oracle","dateFrom":"2030-01-01","caseId":970001}"#,"from-filter"=>r#"{"name":"From filter","keywords":"oracle","fromAddr":"nobody@test","caseId":970001}"#,_=>r#"{"name":"Search <A>","keywords":"oracle","caseId":970001}"#}), "list"=>("GET","/admin/ediscovery/cases",""), "get"=>("GET","/admin/ediscovery/cases/{id}",""), "search"=>("GET","/admin/ediscovery/{id}",""), "hold"=>("POST","/admin/ediscovery/hold",""), "release"=>("POST","/admin/ediscovery/release",""), "close"=>("POST","/admin/ediscovery/cases/{id}/close",match label {"bad-json"=>"{","typed"=>r#"{"reason":7}"#,"empty"=>"{}","null"=>"null","folded"=>r#"{"REASON":"First","reason":null} trailing"#,_=>r#"{"reason":"Investigation <complete>"}"#}), "associate"=>("POST","/admin/ediscovery/cases/associate",match label {"invalid"=>"{}","bad-json"=>"{","typed"=>r#"{"searchId":"980001","caseId":970001}"#,"missing-search"=>r#"{"searchId":99999999,"caseId":970001}"#,"missing-case"=>r#"{"searchId":980001,"caseId":99999999}"#,"closed"=>r#"{"searchId":980001,"caseId":970002}"#,"folded"=>r#"{"SEARCHID":980001,"CaseId":970001} trailing"#,_=>r#"{"searchId":980001,"caseId":970001}"#}), "delete"=>("DELETE","/admin/ediscovery/cases/{id}",""), "update"=>("PUT","/admin/ediscovery/cases/{id}",match label {"bad-json"=>"{","empty"=>"{}","typed"=>r#"{"description":7}"#,"null"=>r#"{"name":"replacement","name":null}"#,"folded"=>r#"{"NAME":"Folded","description":"x","DESCRIPTION":null} trailing"#,"empty-name"=>r#"{"name":""}"#,"clear"=>r#"{"description":""}"#,_=>r#"{"name":"Renamed <Case>","description":""}"#}), "create"=>("POST","/admin/ediscovery/cases",match label {"invalid"=>"{}","bad-json"=>"{","typed"=>r#"{"name":7}"#,"null"=>"null","folded"=>r#"{"NAME":"Casefold","Description":null,"ignored":true} trailing"#,_=>r#"{"name":"New <Case>","description":"Evidence","createdBy":-42}"#}), _=>panic!("unknown action") };
        let mut body=body.to_owned();
        let mut recorded_body=body.clone();
        if action=="start" {
            let mut query=json!({"name":"Search <A>","keywords":"oracle","caseId":970001});
            let kql=match label {
                "kql-mailbox"=>Some("mailbox:compl1".to_owned()),
                "kql-negated-subject"=>Some("NOT subject:oracle".to_owned()),
                "kql-negated-body"=>Some("NOT body:oracle".to_owned()),
                "kql-mixed"=>Some("oracle AND subject:oracle OR missing".to_owned()),
                "kql-empty"=>Some(" ".to_owned()),
                "kql-depth"=>Some(format!("{}oracle{}","(".repeat(33),")".repeat(33))),
                "kql-terms"=>Some(vec!["oracle";129].join(" ")),
                "kql-length"=>Some("x".repeat(4097)),
                "kql-quote"=>Some("subject:\"oracle\"".to_owned()),
                "kql-date-empty"=>Some("date:\"\"".to_owned()),
                "kql-control"=>Some("oracle)\u{7}".to_owned()),
                "kql-trailing-operator"=>Some("oracle AND".to_owned()),
                "kql-unclosed-quote"=>Some("\"oracle".to_owned()),
                "kql-ignores-filters"=>Some("oracle".to_owned()),
                _=>None
            };
            if let Some(kql)=kql {query["kql"]=json!(kql);query["keywords"]=json!("");if label=="kql-ignores-filters" {query["fromAddr"]=json!("nobody@test");query["dateFrom"]=json!("2030-01-01");query["mailboxIds"]=json!([99999999]);}body=query.to_string();recorded_body=body.clone();}
            match label {
                "invalid"=>query=json!({}),
                "typed"=>query=json!({"keywords":7}),
                "null"=>query=Value::Null,
                "no-case"=>{query.as_object_mut().unwrap().remove("caseId");},
                "missing-case"=>query["caseId"]=json!(99999999),
                "case-zero"=>query["caseId"]=json!(0),
                "from-only"=>{query["keywords"]=json!("");query["fromAddr"]=json!("oracle");},
                "date-invalid"=>query["dateFrom"]=json!("not-a-date"),
                "mailboxes-empty"=>query["mailboxIds"]=json!([]),
                "mailboxes-null-entry"=>query["mailboxIds"]=json!([null]),
                _=>{}
            }
            if matches!(label,"invalid"|"typed"|"null"|"no-case"|"missing-case"|"case-zero"|"from-only"|"date-invalid"|"mailboxes-empty"|"mailboxes-null-entry") {body=query.to_string();recorded_body=body.clone();}
            if label=="bad-json" {body="{".into();recorded_body=body.clone();}
            if label=="folded" {body=r#"{"NAME":"Folded","KEYWORDS":"oracle","caseID":970001,"keywords":null} trailing"#.into();recorded_body=body.clone();}
        }
        if matches!(action,"hold"|"release") {
            let same=|s:&str|(s.to_owned(),s.to_owned());
            (body,recorded_body)=match label {
                "invalid"=>same(r#"{"ids":["bad"]}"#),"empty"=>same("{}"),"null"=>same(r#"{"ids":null}"#),"null-body"=>same("null"),"empty-list"=>same(r#"{"ids":[]}"#),
                "duplicates"=>(format!("{{\"ids\":[{},{}]}}",a.two_labels,a.two_labels),r#"{"ids":["<message-a>","<message-a>"]}"#.into()),
                "mixed"=>(format!("{{\"ids\":[{},99999999]}}",a.two_labels),r#"{"ids":["<message-a>",99999999]}"#.into()),
                "null-entry"=>(format!("{{\"ids\":[null,{}]}}",a.two_labels),r#"{"ids":[null,"<message-a>"]}"#.into()),
                "negative"=>same(r#"{"ids":[-1]}"#),
                "folded"=>(format!("{{\"IDS\":[{}],\"ids\":null}} trailing",a.two_labels),r#"{"IDS":["<message-a>"],"ids":null} trailing"#.into()),
                "huge"=>same(r#"{"ids":[9223372036854775808]}"#),
                _=>(format!("{{\"ids\":[{},{}]}}",a.two_labels,a.inbox_only),r#"{"ids":["<message-a>","<message-b>"]}"#.into())
            };
        }
        let target=match (action,label) {
            ("search", "invalid")=>"bad",
            ("search", "missing")=>"99999999",
            ("search", _) =>"980001",
            (_,label)=>match label {"invalid"=>"bad", "missing"=>"99999999", "null-description"=>"970003","closed"=>"970002",_=>"970001"}};
        let mut external=path.replace("{id}",target)+if action=="list" && label=="invalid" {"?limit=-1&offset=wat"}else{""};
        let mut export_ids=format!("{},{}",a.two_labels,a.inbox_only);
        if action=="export" {
            let case=match label {"missing-case"=>"99999999","closed"=>"970002","invalid"=>"bad",_=>"970001"};
            export_ids=match label {"byte-ids"=>"invalid-byte-ids".into(),"empty-numeric"=>"wat,0,-1".into(),"mixed"=>format!("{},wat",a.two_labels),"duplicates"=>format!("{},{},{}",a.two_labels,a.two_labels,a.inbox_only),"unbound"=>"99999999".into(),"too-many"=>vec!["0";501].join(","),_=>export_ids};
            external+=&match label {"byte-ids"=>"?ids=%ff%e2%82&caseId=970001".into(),"semicolon"=>"?ids=wat;ignored&caseId=970001".into(),"bad-escape"=>"?ids=%ZZ&caseId=970001".into(),"missing-ids"=>"?caseId=970001".into(),"missing-case-id"=>format!("?ids={export_ids}"),_=>format!("?ids={export_ids}&caseId={case}{}",if label=="pst" {"&format=pst"}else{""})};
            if label=="no-completed" {owner.execute("UPDATE ediscovery_searches SET status='pending' WHERE id=980001",&[]).await?;}
            if label=="empty-binding" {owner.execute("DELETE FROM ediscovery_search_results WHERE search_id=980001",&[]).await?;}
            if label=="audit-error" {owner.batch_execute("CREATE OR REPLACE FUNCTION gofree_compl1_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action='ediscovery_export' THEN RAISE EXCEPTION 'compl1 audit failure'; END IF; RETURN NEW; END;$$; CREATE TRIGGER gofree_compl1_audit_fault BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION gofree_compl1_audit_fault();").await?;}
        }
        let head=label.ends_with("head");if head{method="HEAD";}
        let send=||{let external=&external;let body=body.clone();async move {Ok::<_,BoxError>(common::send(addr,Request::builder().method(method).uri(format!("/api{external}")).header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("x-request-id","gofree-compl1-oracle").header("authorization",format!("Bearer {}",token(a.user))).body(common::full(body))?).await)}};
        let head_length=if head{let response=common::send(addr,Request::builder().method("GET").uri(format!("/api{external}")).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {}",token(a.user))).body(common::full(""))?).await;assert_eq!(response.status(),200);Some(common::body_bytes(response).await.len())}else{None};
        if label=="repeat" {let first=send().await?;let status=first.status().as_u16();let bytes=common::body_bytes(first).await;if action=="start" && status==202 {let value:Value=serde_json::from_slice(&bytes)?;wait_search(&owner,value["id"].as_i64().ok_or("repeat search id")?).await?;}if !(200..300).contains(&status){return Err(format!("repeat precondition failed: {status}").into());}}
        if label=="audit-failure" {owner.batch_execute("CREATE FUNCTION gofree_compl1_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'compl1 mandatory audit fault'; END;$$; CREATE TRIGGER gofree_compl1_fault BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION gofree_compl1_fault();").await?;}
        if label=="query-failure" {owner.batch_execute("CREATE FUNCTION gofree_compl1_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'compl1 message update fault'; END;$$; CREATE TRIGGER gofree_compl1_fault BEFORE UPDATE ON messages FOR EACH ROW EXECUTE FUNCTION gofree_compl1_fault();").await?;}
        if mutant=="no-audit" {owner.batch_execute("CREATE FUNCTION gofree_compl1_mutant() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action='ediscovery_hold' THEN RETURN NULL; END IF; RETURN NEW; END;$$; CREATE TRIGGER gofree_compl1_mutant BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION gofree_compl1_mutant();").await?;}
        if mutant=="double-bump" {owner.batch_execute("CREATE FUNCTION gofree_compl1_mutant() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.held IS DISTINCT FROM OLD.held THEN UPDATE mailboxes SET jmap_email_state=jmap_email_state+2 WHERE id=NEW.mailbox_id; END IF; RETURN NEW; END;$$; CREATE TRIGGER gofree_compl1_mutant AFTER UPDATE ON messages FOR EACH ROW EXECUTE FUNCTION gofree_compl1_mutant();").await?;}
        let before=snapshot(&owner,message_scope).await?;
        let s3_start=s3_calls.lock().unwrap().len();
        let mut alerts=db.listen("admin:alert").await?;
        let tag_channel=format!("tag:{}",a.mailbox);
        let mut tags=db.listen(&tag_channel).await?;
        let last:i64=owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
        let response=send().await?;
        let status=response.status().as_u16();
        if recording && label=="success" && status!=match action {"create"=>201,"start"=>202,"update"|"delete"|"associate"|"close"=>204,_=>200} {return Err(format!("Go success must be 200, got {status}").into());}
        let mut headers=serde_json::Map::new(); for name in response.headers().keys() {headers.insert(name.to_string(),json!(response.headers().get_all(name).iter().map(|v|v.to_str().unwrap()).collect::<Vec<_>>()));}
        let raw_bytes=common::body_bytes(response).await;
        let raw=if action=="export" {String::from_utf8_lossy(&raw_bytes).into_owned()}else{String::from_utf8(raw_bytes.to_vec())?};
        if action=="start" && serde_json::from_str::<Value>(&raw).ok().and_then(|v|v["id"].as_i64()).is_some() {let value:Value=serde_json::from_str(&raw)?;wait_search(&owner,value["id"].as_i64().ok_or("search id")?).await?;}
        let mut text=raw.replace(&mailbox_email,"mailbox@test");
        if let Ok(v)=serde_json::from_str::<Value>(&raw) {
            fn replace(text:&mut String,v:&Value,user:i64){match v {
                Value::Object(m)=>for(k,x)in m {if ["createdBy","closedBy"].contains(&k.as_str()) && x.as_i64()==Some(user) { *text=text.replace(&format!("\"{k}\":{user}"),&format!("\"{k}\":\"<actor>\"")); } else {replace(text,x,user)}},
                Value::Array(xs)=>for x in xs {replace(text,x,user)},
                Value::String(s)=>{let b=s.as_bytes();if b.len()>19 && b.get(4)==Some(&b'-') && b.get(7)==Some(&b'-') && b.get(13)==Some(&b':') {*text=text.replace(&serde_json::to_string(s).unwrap(),"\"<timestamp>\"");}},_=>{}
            }}
            replace(&mut text,&v,a.user);
            fn number(text:&mut String,key:&str,n:i64,value:&str){for end in [",","}","]"] {*text=text.replace(&format!("\"{key}\":{n}{end}"),&format!("\"{key}\":\"{value}\"{end}"));}}
            if message_scope.is_some(){
                number(&mut text,"id",a.two_labels,"<message-a>");number(&mut text,"id",a.inbox_only,"<message-b>");
                if let Some(xs)=v["search"]["mailboxIds"].as_array(){let mut fixed=xs.clone();for x in &mut fixed {if x.as_i64()==Some(a.mailbox){*x=json!("<mailbox>")}}text=text.replace(&format!("\"mailboxIds\":{}",serde_json::to_string(xs)?),&format!("\"mailboxIds\":{}",serde_json::to_string(&fixed)?));}
            }
        }
        if let Some(h)=headers.get_mut("date"){*h=json!(["<timestamp>"]);}
        let mut body_value=json!(text);
        if action=="export" && status==200 {body_value=export::normalize(&raw_bytes,&export_ids,a.two_labels,a.inbox_only)?;}
        if let Some(h)=headers.get_mut("content-disposition") {let value=h[0].as_str().ok_or("disposition")?;let date=value.strip_prefix("attachment; filename=ediscovery-").and_then(|s|s.strip_suffix(".mbox")).ok_or("bad export filename")?;chrono::NaiveDateTime::parse_from_str(date,"%Y%m%d-%H%M%S")?;*h=json!(["attachment; filename=ediscovery-<timestamp>.mbox"]);}
        if let Some(h)=headers.get_mut("content-length"){if let Some(length)=head_length {assert!(raw_bytes.is_empty());assert_eq!(h[0],length.to_string());*h=json!(["<head-length>"]);}else{if h[0]!=raw_bytes.len().to_string(){return Err("bad wire body length".into());}let length=body_value.as_str().map_or_else(|| {use base64::{engine::general_purpose::STANDARD,Engine};STANDARD.decode(body_value["base64"].as_str().unwrap()).unwrap().len()},str::len);*h=json!([length.to_string()]);}}
        let mut audit=Value::Array(owner.query("SELECT to_jsonb(t)::text FROM admin_audit_log t WHERE id>$1 ORDER BY id",&[&last]).await?.iter().map(|r|serde_json::from_str(&r.get::<_,String>(0))).collect::<Result<_,_>>()?);
        for r in audit.as_array_mut().unwrap(){r["id"]=json!("<audit>");for k in ["checksum","prev_checksum"]{if r[k].as_str().is_some_and(|s|!s.is_empty()){r[k]=json!("<checksum>");}}}
        for row in audit.as_array_mut().unwrap() { if let Some(detail)=row["before_state"]["missingPermission"].as_str() {let detail=detail.replace(&format!("domain={}",a.domain),"domain=<domain>");row["before_state"]["missingPermission"]=json!(detail);}}
        let mut effects=json!([{"table":"ediscovery_cases","before":before,"after":snapshot(&owner,message_scope).await?}]);mask(&mut effects,a.user);mask(&mut audit,a.user);
        if message_scope.is_some(){
            fn ids(v:&mut Value,a:i64,b:i64,mailbox:i64){match v {Value::Object(m)=>for(k,x)in m {if let Some(n)=x.as_i64() {if ["id","message_id"].contains(&k.as_str()){if n==a {*x=json!("<message-a>")}else if n==b{*x=json!("<message-b>")}}else if k=="mailbox_id" && n==mailbox {*x=json!("<mailbox>")}} else if k=="mailboxIds" {if let Some(xs)=x.as_array_mut(){for x in xs {if x.as_i64()==Some(mailbox){*x=json!("<mailbox>")}}}} else {ids(x,a,b,mailbox)}},Value::Array(xs)=>for x in xs{ids(x,a,b,mailbox)},_=>{}}}
            ids(&mut effects,a.two_labels,a.inbox_only,a.mailbox);
            for row in audit.as_array_mut().unwrap(){if let Some(xs)=row["before_state"].as_array_mut(){for x in xs {if x.as_i64()==Some(a.two_labels)||x.as_str()==Some(a.two_labels.to_string().as_str()){*x=json!("<message-a>")}else if x.as_i64()==Some(a.inbox_only)||x.as_str()==Some(a.inbox_only.to_string().as_str()){*x=json!("<message-b>")}}}}
        }
        let mut notify=Vec::new();
        for event in alerts.drain(&owner).await? {notify.push(json!({"channel":"admin:alert","payload":serde_json::from_str::<Value>(&event)?}));}
        for event in tags.drain(&owner).await? {notify.push(json!({"channel":"tag:<mailbox>","payload":serde_json::from_str::<Value>(&event)?}));}
        let mut observation=json!({"request":{"method":method,"path":path,"body":recorded_body},"response":{"status":status,"headers":headers,"body":body_value},"effects":effects,"audit":audit,"notify":notify});
        if action=="export" {observation["outbound"]=json!(s3_calls.lock().unwrap()[s3_start..]);observation["request"]["query"]=json!(external.split_once('?').map(|(_,q)|q).unwrap_or("").split('&').map(|p|if let Some(ids)=p.strip_prefix("ids="){format!("ids={}",ids.split(',').map(|v|if v==a.two_labels.to_string(){"<message-a>"}else if v==a.inbox_only.to_string(){"<message-b>"}else{v}).collect::<Vec<_>>().join(","))}else{p.to_owned()}).collect::<Vec<_>>().join("&"));}
        if !recording {
            let metrics=common::send(addr,Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l|l=="setjoin_gateway_proxied_to_go_by_family_total{family=\"F04\"} 0") {return Err(format!("native F04 request forwarded: {metrics}").into());}
        }
        server.abort();
        if let Some(task)=commit_wire {
            let cut=tokio::time::timeout(std::time::Duration::from_secs(5),task).await???;
            let committed=mutant=="commit-after";assert_eq!(cut==common::commit::CommitCut::AfterCommit,committed);
            assert_eq!(status,503);let operation=observation["response"]["headers"]["x-operation-id"][0].as_str().ok_or("missing unknown operation ID")?;
            assert_eq!(operation.len(),32);
            let present:bool=owner.query_one("SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=$1::text::uuid AND family='F04')",&[&operation]).await?.get(0);assert_eq!(present,committed);
            if committed {
                let file=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/compliance/goldens/{action}-success.json"));let expected:Value=serde_json::from_slice(&std::fs::read(file)?)?;
                for key in ["effects","audit","notify"]{golden::compare(&expected["observation"][key],&observation[key])?;}
            }else{assert_eq!(observation["effects"][0]["before"],observation["effects"][0]["after"]);assert_eq!(observation["audit"],json!([]));assert_eq!(observation["notify"],json!([]));}
            if action=="export"{assert_eq!(observation["outbound"],json!([]));}
            eprintln!("COMMIT-FAULT: {action} :: {mutant} resolved by receipt, no replay");return Ok(());
        }
        let name=format!("{action}-{label}");let dir=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/compliance/goldens");std::fs::create_dir_all(&dir)?;
        let file=dir.join(format!("{name}.json"));
        if recording && std::env::var("GOFREE_VERIFY_GO").as_deref()!=Ok("1") {let source=std::env::var("GOFREE_GO_SOURCE")?;golden::record(&file,&json!({"format":1,"route":format!("{method} {path}"),"case":label,"go_source":source,"observation":observation}))?;} else {let expected:Value=serde_json::from_slice(&std::fs::read(file)?)?;golden::compare(&expected["observation"],&observation)?;eprintln!("GOLDEN-REPLAY: {method} {path} :: {label}");}
        Ok::<_,BoxError>(())
    }.await;
    if matches!(label, "audit-failure" | "query-failure") {
        owner.batch_execute("DROP TRIGGER IF EXISTS gofree_compl1_fault ON admin_audit_log; DROP TRIGGER IF EXISTS gofree_compl1_fault ON messages; DROP FUNCTION IF EXISTS gofree_compl1_fault();").await?;
    }
    if mutant == "no-audit" || mutant == "double-bump" {
        owner.batch_execute("DROP TRIGGER IF EXISTS gofree_compl1_mutant ON admin_audit_log; DROP TRIGGER IF EXISTS gofree_compl1_mutant ON messages; DROP FUNCTION IF EXISTS gofree_compl1_mutant();").await?;
    }
    if action == "export" && label == "audit-error" {
        owner.batch_execute("DROP TRIGGER IF EXISTS gofree_compl1_audit_fault ON admin_audit_log; DROP FUNCTION IF EXISTS gofree_compl1_audit_fault();").await?;
    }
    owner
        .execute(
            "DELETE FROM ediscovery_searches WHERE created_by=$1",
            &[&a.user],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM ediscovery_cases WHERE created_by=$1",
            &[&a.user],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await?;
    owner.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={};DELETE FROM rust_operation_receipts WHERE family='F04';COMMIT;",a.user)).await?;
    owner
        .execute(
            "UPDATE messages SET held=false WHERE mailbox_id=$1",
            &[&a.mailbox],
        )
        .await?;
    fixture::remove(&owner, &a).await?;
    result
}

async fn wait_search(owner: &tokio_postgres::Client, id: i64) -> Result<(), BoxError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let row = owner
            .query_opt("SELECT status FROM ediscovery_searches WHERE id=$1", &[&id])
            .await?;
        if row.is_some_and(|r| matches!(r.get::<_, String>(0).as_str(), "complete" | "failed")) {
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            return Err("search did not settle in 30s".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// These remain Go-owned shapes. Never feed quoted NUL to the live Go oracle.
pub async fn forwarding() -> Result<(), BoxError> {
    use http_body_util::BodyExt;
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("compl1-forward").ok_or("DB required")?;
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "compl1-forward").await?;
    let role:i64=owner.query_one("INSERT INTO admin_role_groups(name,permissions) VALUES ('compl1-forward','{compliance.write}') RETURNING id",&[]).await?.get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(role_group_id,user_id) VALUES($1,$2)",
            &[&role, &a.user],
        )
        .await?;
    struct Env(Option<std::ffi::OsString>);
    impl Drop for Env {
        fn drop(&mut self) {
            if let Some(value) = &self.0 {
                std::env::set_var("WORM_MODE", value)
            } else {
                std::env::remove_var("WORM_MODE")
            }
        }
    }
    let result=async {
        let _env=Env(std::env::var_os("WORM_MODE"));std::env::remove_var("WORM_MODE");
        let received=Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));let capture=received.clone();
        let upstream=common::fake_upstream(move |r|{let capture=capture.clone();async move {
            let method=r.method().to_string();let path=r.uri().to_string();
            let body=r.into_body().collect().await.unwrap().to_bytes();
            capture.lock().unwrap().push(json!({"method":method,"path":path,"body":String::from_utf8(body.to_vec()).unwrap()}));
            Response::builder().status(299).body(common::full("forwarded\n")).unwrap()
        }}).await;
        let patient=std::time::Duration::from_secs(30);
        let make=|dsn:&str|ScopedExecutor::from_dsn_with(dsn,2,setjoin_pg::Timeouts{pool_wait:patient,create:patient,statement:patient}).map(|e|e.with_audit_keys("22".repeat(32),String::new())).map_err(|e|e.0);
        let adapter=ComplianceRoute{store:None,exec:make(db.app.as_deref().unwrap_or(&db.dsn))?,worker:make(&db.dsn)?,jobs:setjoin_gateway::compliance::SearchJobs::new(setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?,1),keys:Arc::new(common::recovery_keys()),issuer:"mailserver".into()};
        let mut inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().unwrap(){if r["family"]=="F04"&&r["slice"]=="ediscovery" {r["state"]=json!("ON");r["upstream"]=json!("local-rust");r["oracle_commands"]=json!([""]);}}
        let gateway=Gateway::new(Config{upstream:Some(format!("http://{upstream}").parse()?),trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},RouteTable::proxy_all().with(adapter))?.with_inventory(&inventory.to_string())?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let server=tokio::spawn(gateway.serve(listener));
        let nul=r#"{"name":"NUL","keywords":"oracle","kql":"\"a\u0000b\"","createdBy":-42} trailing"#.to_owned();
        // Owner-approved security fix 2026-11-05 (#436): a NUL in the KQL is refused locally with a 400
        // and never reaches an upstream (frozen Go's parser hung on it).
        let refused=common::send(address,Request::post("/api/admin/ediscovery/search").header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("authorization",format!("Bearer {token}",token=token(a.user))).body(common::full(nul))?).await;
        if refused.status().as_u16()!=400{return Err(format!("NUL KQL answered {}",refused.status()).into());}
        let refused_body=String::from_utf8(common::body_bytes(refused).await.to_vec())?;
        if !refused_body.contains("invalid KQL query: query contains a NUL character"){return Err(format!("NUL KQL body: {refused_body}").into());}
        let ids=format!("{{\"ids\":[{}]}}",a.two_labels);
        let mut expected=Vec::new();
        for (path,body,worm) in [("/api/admin/ediscovery/hold",ids.clone(),true),("/api/admin/ediscovery/release",ids,true)] {
            if worm{std::env::set_var("WORM_MODE","governance");}
            let response=common::send(address,Request::post(path).header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("authorization",format!("Bearer {}",token(a.user))).body(common::full(body.clone()))?).await;
            if response.status().as_u16()!=299{return Err("deferred request was served locally".into());}
            if common::body_bytes(response).await.as_ref()!=b"forwarded\n"{return Err("deferred response bytes changed".into());}
            expected.push(json!({"method":"POST","path":path,"body":body}));
        }
        golden::compare(&json!(expected),&json!(*received.lock().unwrap()))?;
        let searches:i64=owner.query_one("SELECT count(*) FROM ediscovery_searches WHERE created_by=$1",&[&a.user]).await?.get(0);
        let held:i64=owner.query_one("SELECT count(*) FROM messages WHERE mailbox_id=$1 AND held",&[&a.mailbox]).await?.get(0);
        if searches!=0||held!=0{return Err("deferred request changed native data".into());}
        let metrics=common::send(address,Request::get("/_gateway/metrics").body(common::full(""))?).await;
        let metrics=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
        if !metrics.lines().any(|l|l=="setjoin_gateway_proxied_to_go_by_family_total{family=\"F04\"} 2"){return Err("deferred requests were not counted as Go traffic".into());}
        server.abort();Ok::<_,BoxError>(())
    }.await;
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await?;
    fixture::remove(&owner, &a).await?;
    result
}

/// Both switches must bypass the actual adapter for every transferred route.
pub async fn kill_switch() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("compl1-kill").ok_or("DB required")?;
    let owner = db.connect().await?;
    let before = snapshot(&owner, None).await?;
    for global in [true, false] {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = calls.clone();
        let upstream = common::fake_upstream(move |r| {
            let capture = capture.clone();
            async move {
                let path = r.uri().to_string();
                capture.lock().unwrap().push((r.method().to_string(), path));
                Response::builder()
                    .status(299)
                    .body(common::full("kill switch\n"))
                    .unwrap()
            }
        })
        .await;
        let exec =
            ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 1).map_err(|e| e.0)?;
        let adapter = ComplianceRoute {
            exec,
            worker: ScopedExecutor::from_dsn(&db.dsn, 1).map_err(|e| e.0)?,
            jobs: setjoin_gateway::compliance::SearchJobs::new(
                setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?,
                1,
            ),
            store: None,
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
        };
        let mut inventory: Value =
            serde_json::from_str(include_str!("../../route-inventory.json"))?;
        let mut routes = Vec::new();
        for r in inventory["routes"].as_array_mut().unwrap() {
            if r["family"] == "F04" && r["slice"] == "ediscovery" {
                routes.push((
                    r["method"].as_str().unwrap().to_owned(),
                    r["path"].as_str().unwrap().replace("{id}", "970001"),
                ));
                if !global {
                    r["state"] = json!("OFF");
                    r["upstream"] = json!("go-mail");
                }
            }
        }
        assert_eq!(routes.len(), 12);
        let gateway = Gateway::new(
            Config {
                upstream: Some(format!("http://{upstream}").parse()?),
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            RouteTable::proxy_all().with(adapter),
        )?
        .with_inventory(&inventory.to_string())?
        .with_enabled(!global);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        for (method, path) in &routes {
            let response = common::send(
                addr,
                Request::builder()
                    .method(method.as_str())
                    .uri(format!("/api{path}"))
                    .header("host", "mail.test")
                    .header("origin", "http://mail.test")
                    .body(common::full("{}"))?,
            )
            .await;
            assert_eq!(response.status().as_u16(), 299, "{method} {path}");
            assert_eq!(
                common::body_bytes(response).await.as_ref(),
                b"kill switch\n"
            );
        }
        let metrics = common::send(
            addr,
            Request::get("/_gateway/metrics").body(common::full(""))?,
        )
        .await;
        let status = metrics.status().as_u16();
        let text = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
        if global {
            // The global switch intentionally bypasses local probes too.
            assert_eq!(status, 299);
            assert_eq!(text, "kill switch\n");
            assert_eq!(
                calls.lock().unwrap().last().unwrap(),
                &("GET".into(), "/_gateway/metrics".into())
            );
        } else {
            assert_eq!(status, 200);
            assert!(
                text.contains("setjoin_gateway_proxied_to_go_by_family_total{family=\"F04\"} 12")
            );
        }
        let actual = calls.lock().unwrap();
        assert_eq!(actual.len(), if global { 13 } else { 12 });
        for ((method, path), (actual_method, actual_path)) in routes.iter().zip(actual.iter()) {
            assert_eq!(method, actual_method);
            assert_eq!(format!("/api{path}"), *actual_path);
        }
        drop(actual);
        assert_eq!(before, snapshot(&owner, None).await?);
        server.abort();
    }
    Ok(())
}
