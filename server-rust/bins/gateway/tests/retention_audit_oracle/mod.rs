mod routing;
pub use routing::{forwarding, switches};
pub mod mutants;
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
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
    let sig: p256::ecdsa::Signature = SigningKey::from_slice(&[0x11; 32])
        .unwrap()
        .sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!("{}.{payload}.{}", fields[0], B64.encode(sig.to_bytes()))
}
pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "purge" => ("POST", "/admin/content-search/delete"),
        "search" => ("POST", "/admin/content-search/search"),
        "audit_verify" => ("GET", "/admin/audit/verify"),
        "audit_csv" => ("GET", "/admin/audit/csv"),
        "audit_list" => ("GET", "/admin/audit"),
        "audit_policy" => ("GET", "/admin/audit/policy"),
        "audit_set" => ("PUT", "/admin/audit/policy"),
        "log_get" => ("GET", "/admin/retention/logs"),
        "log_set" => ("PUT", "/admin/retention/logs"),
        "log_prune" => ("POST", "/admin/retention/prune"),
        "policies" => ("GET", "/admin/retention/policies"),
        "create" => ("POST", "/admin/retention/policies"),
        "update" => ("PUT", "/admin/retention/policies/{id}"),
        "delete" => ("DELETE", "/admin/retention/policies/{id}"),
        _ => panic!("unknown action {action}"),
    }
}
fn normalize(v: &mut Value, user: i64, domain: i64, email: &str) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if ["user_id", "userId", "updated_by", "actor_user_id"].contains(&k.as_str())
                    && x.as_i64() == Some(user)
                {
                    *x = json!("<actor>")
                } else if ["domain_id", "domainId"].contains(&k.as_str())
                    && x.as_i64() == Some(domain)
                {
                    *x = json!("<domain>")
                } else if ["checksum", "prev_checksum"].contains(&k.as_str()) && !x.is_null() {
                    *x = json!("<checksum>")
                } else {
                    normalize(x, user, domain, email)
                }
            }
        }
        Value::Array(xs) => {
            for x in xs {
                normalize(x, user, domain, email)
            }
        }
        Value::String(s) => {
            if !email.is_empty() && s == email {
                *s = "actor@test".into()
            } else if s.len() >= 19
                && s.as_bytes().get(4) == Some(&b'-')
                && s.as_bytes().get(7) == Some(&b'-')
                && s.as_bytes().get(13) == Some(&b':')
            {
                *s = "<timestamp>".into()
            } else {
                *s = s.replace(&format!("domain={domain}"), "domain=<domain>");
            }
        }
        _ => {}
    }
}
async fn snapshot(c: &tokio_postgres::Client, action: &str) -> Result<Value, BoxError> {
    let mut out = json!({});
    for (table, sql) in [(
        "policies",
        "SELECT to_jsonb(t)::text FROM retention_policies t ORDER BY id",
    )] {
        out[table] = json!(c
            .query(sql, &[])
            .await?
            .iter()
            .map(|r| serde_json::from_str::<Value>(&r.get::<_, String>(0)))
            .collect::<Result<Vec<_>, _>>()?);
    }
    if action.starts_with("log_") {
        out["config"]=json!(c.query("SELECT to_jsonb(t)::text FROM system_config t WHERE key LIKE 'log_retention_%' ORDER BY key",&[]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?);
    }
    if action.starts_with("audit_") {
        out["audit_policy"] = json!(c
            .query(
                "SELECT to_jsonb(t)::text FROM audit_policy t ORDER BY id",
                &[]
            )
            .await?
            .iter()
            .map(|r| serde_json::from_str::<Value>(&r.get::<_, String>(0)))
            .collect::<Result<Vec<_>, _>>()?);
    }
    if action == "log_prune" {
        out["traces"]=json!(c.query("SELECT to_jsonb(t)::text FROM message_trace t WHERE message_id='compl2-prune' ORDER BY id",&[]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?);
    }
    Ok(out)
}
pub async fn run(action: &str, label: &str, mutant: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    if !mutant.is_empty() && std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() {
        return Err("Rust qualification must not record Go".into());
    }
    let db = Db::for_case("compl2-http").ok_or("DB required")?;
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "compl2-admin").await?;
    let other = fixture::account(&owner, "compl2-foreign").await?;
    let other_email: String = owner
        .query_one("SELECT email FROM users WHERE id=$1", &[&other.user])
        .await?
        .get(0);
    let email: String = owner
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    let role:i64=owner.query_one("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES ('compl2-oracle',$1,$2) RETURNING id",&[&if label=="read-only"{vec!["audit.read"]}else if label=="denied"||(label=="foreign"&&!matches!(action,"policies"|"create"|"update"|"delete"|"search"|"purge")){vec!["users.read"]}else{vec!["domains.read","compliance.write","audit.read","audit.export"]},&if label=="scoped"{Some(a.domain)}else if matches!(label,"foreign"|"domain-scope"){Some(other.domain)}else{None}]).await?.get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(role_group_id,user_id) VALUES($1,$2)",
            &[&role, &a.user],
        )
        .await?;
    // Save and restore shared singleton settings; only this assigned disposable DB is used.
    let saved = snapshot(&owner, action).await?;
    let saved_cutover = owner
        .query("SELECT to_jsonb(t)::text FROM audit_chain_cutover t", &[])
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    let mut notify_disabled = false;
    let result=async{
        owner.execute("DELETE FROM retention_policies",&[]).await?;
        owner.execute("INSERT INTO retention_policies(id,name,description,retain_days,action,is_default,domain_id,created_at) OVERRIDING SYSTEM VALUE VALUES(960001,'Global <policy>','Forever',NULL,'hold',true,NULL,'2026-01-01'),(960002,'Domain policy','',30,'delete',false,$1,'2026-01-02')",&[&a.domain]).await?;
        if action.starts_with("log_"){for(key,value)in [("message_trace",2),("mailbox_audit",3),("auth_event",4),("webhook_delivery",5)]{owner.execute("INSERT INTO system_config(key,value) VALUES($1,$2::text::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",&[&format!("log_retention_{key}_days"),&value.to_string()]).await?;}}
        if action=="log_prune"{owner.execute("INSERT INTO message_trace(id,message_id,event,from_addr,rcpt_addr,occurred_at) VALUES(940001,'compl2-prune','received','sender@test','recipient@test','2000-01-01')",&[]).await?;}
        if action.starts_with("audit_"){owner.execute("UPDATE audit_policy SET level='lean',reason_required_areas=ARRAY['audit'],updated_by=NULL,updated_at='2026-01-01' WHERE id=1",&[]).await?;}
        if matches!(action,"audit_list"|"audit_csv"|"audit_verify"){
         if label=="keyed"{owner.query_one("SELECT set_config('app.audit_hmac_key',$1,false)",&[&"33".repeat(32)]).await?;}
         // The recorded runs read a log holding only this case's rows; the export and list
         // routes return every row, so residue from earlier suites must go first.
         owner.batch_execute("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log;COMMIT;").await?;
         owner.query_one("SELECT setval('admin_audit_log_id_seq',950100,true)",&[]).await?;
         owner.query_one("SELECT audit_write($1,'compl2.seed','message',42,'{\"old\":1,\"a\":\"<note>\",\"nullable\":null}'::jsonb,'{\"new\":2}'::jsonb,'127.0.0.1','=formula, \"line\"'||chr(10)||'next','core')",&[&a.user]).await?;
         owner.query_one("SELECT audit_write($1,'compl2.null',NULL,NULL,NULL,NULL,NULL,'','core')",&[&a.user]).await?;
        }
        let s3=common::fake_upstream(|_|async{Response::new(common::full(""))}).await;
        if label=="keyed"{owner.query_one("SELECT audit_chain_activate_v3()",&[]).await?;}
        if action=="purge"{owner.execute("UPDATE messages SET held=true WHERE id=$1",&[&a.inbox_only]).await?;}
        let extra=if label=="keyed"{vec![("AUDIT_HMAC_KEY","33".repeat(32))]}else{vec![]};
        let go=common::go_oracle::start_named_with_env(&db,s3,"gofree-compl2",&extra).await?;let recording=go.is_some();
        let tenant=if mutant=="no-tenant-filter"{Some(mutants::tenant_proxy(db.app.as_deref().unwrap_or(&db.dsn)).await?)}else{None};
        let mut request_dsn=tenant.as_ref().map(|p|p.dsn.as_str()).unwrap_or_else(||db.app.as_deref().unwrap_or(&db.dsn)).to_owned();
        let mut worker_dsn=db.dsn.clone();let mut commit_wire=None;
        if mutant.starts_with("commit-"){
         let cut=if mutant=="commit-after"{common::commit::CommitCut::AfterCommit}else{common::commit::CommitCut::BeforeCommit};
         let(dsn,task)=common::commit::commit_cut_proxy(if action=="purge"{&worker_dsn}else{&request_dsn},cut).await;
         if action=="purge"{worker_dsn=dsn}else{request_dsn=dsn}commit_wire=Some(task);
        }
        let make=|dsn:&str|setjoin_pg::ScopedExecutor::from_dsn(dsn,2).map(|e|e.with_audit_keys("22".repeat(32),if label=="keyed"{"33".repeat(32)}else{String::new()})).map_err(|e|e.0);
        let adapter=setjoin_gateway::retention_audit::RetentionAuditRoute{exec:make(&request_dsn)?,worker:make(&worker_dsn)?,keys:Arc::new(common::recovery_keys()),issuer:"mailserver".into()};
        let table=RouteTable::proxy_all().with(mutants::Status{inner:adapter,change:mutant=="status"});
        let mut inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().unwrap(){if r["family"]=="F04"&&r["slice"]=="retention-audit"{
         if recording{r["state"]=json!("OFF");r["upstream"]=json!("go-mail");}
         else if r["state"]!="ON"||r["upstream"]!="local-rust"||r["oracle_commands"]!=json!([""]){return Err(format!("bundled route is not qualified ON: {} {}",r["method"],r["path"]).into());}
        }}
        let gateway=Gateway::new(Config{upstream:go.as_ref().map(|g|format!("http://{}",g.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},table)?.with_inventory(&inventory.to_string())?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let addr=listener.local_addr()?;let server=tokio::spawn(gateway.serve(listener));
        let(method,path)=route(action);let mut external=path.replace("{id}",if label=="invalid"{"bad"}else{"960002"});if label=="bad-query"||(label=="invalid"&&matches!(action,"log_get"|"log_prune")){external+="?limit=-1&offset=wat";}let mut body=if action=="search"{r#"{"keywords":"oracle"}"#}else if action=="audit_set"{r#"{"level":"full","reasonRequiredAreas":["roles","audit"],"reason":"Policy <change>","updatedBy":-42}"#}else if action=="log_set"{r#"{"messageTraceDays":7,"mailboxAuditLogDays":null,"authEventDays":-4,"webhookDeliveryDays":30}"#}else if action=="update"{r#"{"name":"Renamed <policy>","description":"","retainDays":60,"action":"archive","isDefault":true}"#}else if action=="create"{r#"{"name":"New <policy>","description":"Evidence","retainDays":14,"createdBy":-42}"#}else{""}.to_owned();
        if action=="audit_list"{external+=match label{"invalid"=>"?user_id=wat","invalid-utf8"=>"?q=%ff","all"=>"","filter"=>"?target_type=message&q=formula","empty"=>"?action=missing","pagination"=>"?limit=1&offset=1",_=>"?action=compl2.seed"};}
        if action=="audit_csv"&&matches!(label,"invalid"|"ignored-filter"){external+="?action=missing&user_id=wat&limit=-1";}
        if action=="audit_verify"{external+=match label{"invalid"=>"?from_id=wat&to_id=nope","range"=>"?from_id=2&to_id=2","empty"=>"?from_id=99999999",_=>""};}
        if action=="audit_policy"&&label=="invalid"{external+="?level=unknown";}
        if action=="purge"{body=json!({"ids":[a.two_labels,a.inbox_only,other.two_labels,99999999],"reason":"Compliance <purge>","userId":-42}).to_string();}
        if action=="create"{owner.query_one("SELECT setval('retention_policies_id_seq',960100,true)",&[]).await?;}
        if action=="audit_csv"&&label=="rows"{owner.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={} AND action='compl2.null';COMMIT;",a.user)).await?;}
        if label=="null-description"{owner.execute("UPDATE retention_policies SET description=NULL WHERE id=960002",&[]).await?;}
        if matches!(action,"create"|"update"){
          body=match label{
           "invalid"=>"{}".into(),"bad-json"=>"{".into(),"typed"=>r#"{"name":7}"#.into(),"null"=>"null".into(),
           "folded"=>if action=="create"{r#"{"NAME":"Folded","name":null,"retainDays":null} trailing"#.into()}else{r#"{"NAME":"Folded","name":null,"description":"","DESCRIPTION":null} trailing"#.into()},
           "range"=>r#"{"name":"Range","retainDays":-1}"#.into(),
           "foreign" if action=="create"=>r#"{"name":"Foreign","domainId":99999999}"#.into(),_=>body};
        }
        if action=="log_set"{body=match label{"invalid"=>r#"{"messageTraceDays":"bad"}"#.into(),"bad-json"=>"{".into(),"null"=>"null".into(),"folded"=>r#"{"MESSAGETRACEDAYS":5,"messageTraceDays":null} trailing"#.into(),_=>body};}
        if label=="broken-config"{for(key,value)in [("message_trace",r#""7""#),("mailbox_audit","3.0"),("auth_event","-1"),("webhook_delivery","null")]{owner.execute("UPDATE system_config SET value=$2::text::jsonb WHERE key=$1",&[&format!("log_retention_{key}_days"),&value]).await?;}}
        if label=="missing-config"{owner.execute("DELETE FROM system_config WHERE key LIKE 'log_retention_%'",&[]).await?;}
        if action=="log_prune"&&label=="query-failure"{owner.execute("UPDATE system_config SET value='\"bad\"'::jsonb WHERE key='log_retention_message_trace_days'",&[]).await?;}
        if label=="config-failure"{owner.batch_execute("CREATE FUNCTION gofree_compl2_config_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.key='log_retention_auth_event_days' THEN RAISE EXCEPTION 'compl2 config failure';END IF;RETURN NEW;END;$$;CREATE TRIGGER gofree_compl2_config_fault BEFORE INSERT OR UPDATE ON system_config FOR EACH ROW EXECUTE FUNCTION gofree_compl2_config_fault();").await?;}
        if action=="audit_set"{body=match label{"invalid"=>"{".into(),"body-reason"=>r#"{"level":"full"}"#.into(),"level"=>r#"{"level":"invalid","reason":"why"}"#.into(),"typed"=>r#"{"level":7,"reason":"why"}"#.into(),"null"=>"null".into(),"folded"=>r#"{"LEVEL":"full","level":null,"REASON":"folded","reason":null,"reasonRequiredAreas":null} trailing"#.into(),"null-entry"=>r#"{"level":"lean","reason":"null entry","reasonRequiredAreas":[null,"audit"]}"#.into(),_=>body};}
        if label=="missing-policy"{owner.execute("DELETE FROM audit_policy WHERE id=1",&[]).await?;}
        if label=="empty-areas"{owner.execute("UPDATE audit_policy SET reason_required_areas='{}' WHERE id=1",&[]).await?;}
        if label=="tampered"{owner.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;UPDATE admin_audit_log SET notes='tampered' WHERE user_id={} AND action='compl2.seed';COMMIT;",a.user)).await?;}
        if action=="search"{
         body=match label{
          "invalid"=>"{}".into(),"bad-json"=>"{".into(),"typed"=>r#"{"keywords":7}"#.into(),"null"=>"null".into(),"folded"=>r#"{"KEYWORDS":"oracle","keywords":null} trailing"#.into(),
          "from-only"=>r#"{"fromAddr":"oracle@example.test"}"#.into(),"from-filter"=>r#"{"keywords":"oracle","fromAddr":"missing"}"#.into(),"date-from"=>r#"{"keywords":"oracle","dateFrom":"2030-01-01"}"#.into(),"date-to"=>r#"{"keywords":"oracle","dateTo":"2020-01-01"}"#.into(),"date-invalid"=>r#"{"keywords":"oracle","dateFrom":"not-a-date"}"#.into(),
          "mailboxes"=>json!({"keywords":"oracle","mailboxIds":[a.mailbox]}).to_string(),"empty-mailboxes"=>r#"{"keywords":"oracle","mailboxIds":[]}"#.into(),"null-mailbox"=>r#"{"keywords":"oracle","mailboxIds":[null]}"#.into(),
          "kql"=>r#"{"kql":"oracle AND (subject:oracle OR body:missing)"}"#.into(),"kql-mailbox"=>r#"{"kql":"mailbox:compl2"}"#.into(),"kql-negated"=>r#"{"kql":"NOT subject:oracle"}"#.into(),"kql-bad"=>r#"{"kql":"("}"#.into(),"kql-unclosed"=>r#"{"kql":"\"oracle"}"#.into(),"kql-space"=>r#"{"kql":" "}"#.into(),
          "kql-length"=>json!({"kql":"x".repeat(4097)}).to_string(),"kql-depth"=>json!({"kql":format!("{}oracle{}","(".repeat(33),")".repeat(33))}).to_string(),"kql-terms"=>json!({"kql":vec!["oracle";129].join(" ")}).to_string(),
          "body-cap"=>json!({"keywords":"x".repeat(70000)}).to_string(),_=>body};
        }
        if action=="purge"{
         body=match label{
          "invalid"=>r#"{"ids":["bad"],"reason":"Valid reason"}"#.into(),"bad-json"=>"{".into(),"null"=>"null".into(),"empty"=>"{}".into(),"null-ids"=>r#"{"ids":null,"reason":"Valid reason"}"#.into(),"null-entry"=>r#"{"ids":[null],"reason":"Valid reason"}"#.into(),
          "duplicates"=>json!({"ids":[a.two_labels,a.two_labels,a.inbox_only],"reason":"Valid reason"}).to_string(),"missing"=>r#"{"ids":[99999999],"reason":"Valid reason"}"#.into(),"negative"=>r#"{"ids":[-1,0],"reason":"Valid reason"}"#.into(),"short-reason"=>json!({"ids":[a.two_labels],"reason":"short"}).to_string(),"unicode-reason"=>json!({"ids":[a.two_labels],"reason":"猫猫猫猫"}).to_string(),"folded"=>r#"{"IDS":[0,null],"REASON":"Valid reason","reason":null} trailing"#.into(),"too-many"=>json!({"ids":vec![0;501],"reason":"Valid reason"}).to_string(),"body-cap"=>json!({"ids":[a.two_labels],"reason":"x".repeat(70000)}).to_string(),_=>body};
         if label=="mailbox-held"{owner.execute("UPDATE mailboxes SET litigation_hold=true WHERE id=$1",&[&a.mailbox]).await?;}
         if label=="query-failure"{owner.batch_execute(&format!("CREATE FUNCTION gofree_compl2_message_fault() RETURNS trigger LANGUAGE plpgsql AS $$$$BEGIN IF OLD.id={} THEN RAISE EXCEPTION 'compl2 purge failure' USING ERRCODE='22000';END IF;RETURN OLD;END;$$$$;CREATE TRIGGER gofree_compl2_message_fault BEFORE DELETE ON messages FOR EACH ROW EXECUTE FUNCTION gofree_compl2_message_fault();",other.two_labels).replace("$$$$","$$")).await?;}
        }
        if label=="repeat"{let first=common::send(addr,Request::builder().method(method).uri(format!("/api{external}")).header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("x-audit-reason","Header reason").header("authorization",format!("Bearer {}",token(a.user))).body(common::full(body.clone()))?).await;let status=first.status();let _=common::body_bytes(first).await;if !status.is_success(){return Err(format!("repeat precondition {status}").into());}}
        if label=="audit-failure"{owner.batch_execute("CREATE FUNCTION gofree_compl2_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'compl2 audit failure';END;$$;CREATE TRIGGER gofree_compl2_fault BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION gofree_compl2_fault();").await?;}
        if mutant=="no-notify"{
         let mode:String=owner.query_one("SELECT tgenabled::text FROM pg_trigger WHERE tgname='trg_system_config_notify' AND tgrelid='system_config'::regclass",&[]).await?.get(0);if mode!="O"{return Err("config notify fixture must start enabled".into());}
         owner.batch_execute("ALTER TABLE system_config DISABLE TRIGGER trg_system_config_notify").await?;notify_disabled=true;
        }
        if mutant=="double-bump"{owner.batch_execute("CREATE FUNCTION gofree_compl2_mutant_bump() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN UPDATE mailboxes SET jmap_email_state=jmap_email_state+2 WHERE id=OLD.mailbox_id;RETURN OLD;END;$$;CREATE TRIGGER gofree_compl2_mutant_bump AFTER DELETE ON messages FOR EACH ROW EXECUTE FUNCTION gofree_compl2_mutant_bump();").await?;}
        if mutant=="no-audit"{owner.batch_execute("CREATE FUNCTION gofree_compl2_mutant_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NULL;END;$$;CREATE TRIGGER gofree_compl2_mutant_audit BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION gofree_compl2_mutant_audit();").await?;}
        let mut before=snapshot(&owner,action).await?;if matches!(action,"search"|"purge"){before["content"]=content_snapshot(&owner,&a,&other).await?;}
        let last:i64=owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
        let mut alerts=db.listen("admin:alert").await?;
        let mut config=db.listen("config_changed").await?;
        let mut tags_a=db.listen(&format!("tag:{}",a.mailbox)).await?;let mut tags_b=db.listen(&format!("tag:{}",other.mailbox)).await?;
        let response=common::send(addr,Request::builder().method(method).uri(format!("/api{external}")).header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("x-request-id","gofree-compl2-oracle").header("x-audit-reason",if label=="missing-header"{""}else{"Header reason"}).header("authorization",format!("Bearer {}",token(a.user))).body(common::full(body.clone()))?).await;
        let status=response.status().as_u16();let mut headers=serde_json::Map::new();for name in response.headers().keys(){headers.insert(name.to_string(),json!(response.headers().get_all(name).iter().map(|v|v.to_str().unwrap()).collect::<Vec<_>>()));}
        let bytes=common::body_bytes(response).await;let raw=String::from_utf8(bytes.to_vec())?;let mut text=raw.clone();
        if matches!(action,"search"|"purge"){
         text=text.replace(&email,"mailbox-a@test").replace(&other_email,"mailbox-b@test");
         for(n,s)in[(a.two_labels,"<message-a>"),(a.inbox_only,"<message-b>"),(other.two_labels,"<message-c>"),(other.inbox_only,"<message-d>")]{for end in [",","}"]{text=text.replace(&format!("\"id\":{n}{end}"),&format!("\"id\":\"{s}\"{end}"));}}
        }
        if action.starts_with("audit_"){text=text.replace(&email,"actor@test");for end in [",","}"]{text=text.replace(&format!("\"userId\":{}{end}",a.user),&format!("\"userId\":\"<actor>\"{end}"));}}
        if action=="audit_csv"{
         for row in owner.query("SELECT to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM admin_audit_log WHERE user_id=$1",&[&a.user]).await?{text=text.replace(&row.get::<_,String>(0),"<timestamp>");}
         if let Some(h)=headers.get_mut("content-disposition"){let date=h[0].as_str().and_then(|s|s.strip_prefix("attachment; filename=audit-log-")).and_then(|s|s.strip_suffix(".csv")).ok_or("invalid audit CSV disposition")?;chrono::NaiveDate::parse_from_str(date,"%Y%m%d")?;*h=json!(["attachment; filename=audit-log-<date>.csv"]);}
        }
        if let Ok(mut v)=serde_json::from_str::<Value>(&raw){
            fn replacements(v:&Value,values:&mut Vec<String>){match v{Value::Object(m)=>for x in m.values(){replacements(x,values)},Value::Array(xs)=>for x in xs{replacements(x,values)},Value::String(s)=>{if s.len()>=19&&s.as_bytes().get(4)==Some(&b'-')&&s.as_bytes().get(7)==Some(&b'-')&&s.as_bytes().get(13)==Some(&b':'){values.push(s.clone())}},_=>{}}}
            let mut times=Vec::new();replacements(&v,&mut times);for t in times{text=text.replace(&serde_json::to_string(&t)?,"\"<timestamp>\"");}
            normalize(&mut v,a.user,a.domain,&email);
        }
        for end in [",","}"]{text=text.replace(&format!("\"domainId\":{}{end}",a.domain),&format!("\"domainId\":\"<domain>\"{end}"));}
        if let Some(h)=headers.get_mut("date"){*h=json!(["<timestamp>"]);}if let Some(h)=headers.get_mut("content-length"){assert_eq!(h[0],bytes.len().to_string());*h=json!([text.len().to_string()]);}
        let mut audit=json!(owner.query("SELECT to_jsonb(t)::text FROM admin_audit_log t WHERE id>$1 ORDER BY id",&[&last]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?);
        for r in audit.as_array_mut().unwrap(){r["id"]=json!("<audit>");}normalize(&mut audit,a.user,a.domain,&email);
        normalize(&mut audit,-999,other.domain,"");
        let mut after=snapshot(&owner,action).await?;if matches!(action,"search"|"purge"){after["content"]=content_snapshot(&owner,&a,&other).await?;}
        let mut effects=json!([{"table":"retention_policies","before":before,"after":after}]);normalize(&mut effects,a.user,a.domain,&email);
        if matches!(action,"search"|"purge"){content_ids(&mut effects,"",&a,&other);content_ids(&mut audit,"",&a,&other);}
        let mut notify=Vec::new();for e in alerts.drain(&owner).await?{notify.push(json!({"channel":"admin:alert","payload":serde_json::from_str::<Value>(&e)?}));}
        if action.starts_with("log_"){for e in config.drain(&owner).await?{notify.push(json!({"channel":"config_changed","payload":serde_json::from_str::<Value>(&e)?}));}}
        if matches!(action,"search"|"purge"){for(channel,events)in[("tag:<mailbox-a>",tags_a.drain(&owner).await?),("tag:<mailbox-b>",tags_b.drain(&owner).await?)]{for e in events{let mut payload:Value=serde_json::from_str(&e)?;content_ids(&mut payload,"",&a,&other);notify.push(json!({"channel":channel,"payload":payload}));}}}
        let mut recorded_body=body.clone();if matches!(action,"search"|"purge"){if let Ok(mut parsed)=serde_json::from_str::<Value>(&body){content_ids(&mut parsed,"",&a,&other);recorded_body=parsed.to_string();}}
        let observation=json!({"request":{"method":method,"path":path,"body":recorded_body},"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if !recording{let metrics=common::send(addr,Request::get("/_gateway/metrics").body(common::full(""))?).await;let metrics=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;if !metrics.lines().any(|l|l=="setjoin_gateway_proxied_to_go_by_family_total{family=\"F04\"} 0"){return Err(format!("native route proxied: {metrics}").into());}}
        server.abort();let _=server.await;
        if let Some(task)=commit_wire{
         let cut=tokio::time::timeout(std::time::Duration::from_secs(5),task).await???;
         let committed=mutant=="commit-after";
         if (cut==common::commit::CommitCut::AfterCommit)!=committed{return Err("wrong COMMIT cut".into());}
         if status!=503{return Err(format!("COMMIT fault must not report success; got {status}").into());}
         let operation=observation["response"]["headers"]["x-operation-id"][0].as_str().ok_or("missing unknown operation ID")?;
         if operation.len()!=32||!operation.bytes().all(|b|b.is_ascii_hexdigit()){return Err("bad operation ID".into());}
         let present:bool=owner.query_one("SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=$1::text::uuid AND family='F04')",&[&operation]).await?.get(0);
         if present!=committed{return Err("COMMIT receipt disagrees with actual cut".into());}
         if committed{
          let expected:Value=serde_json::from_slice(&std::fs::read(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/retention-audit/goldens/{action}-success.json")))?)?;
          for key in ["effects","audit","notify"]{golden::compare(&expected["observation"][key],&observation[key])?;}
         }else{
          golden::compare(&observation["effects"][0]["before"],&observation["effects"][0]["after"])?;
          golden::compare(&json!([]),&observation["audit"])?;golden::compare(&json!([]),&observation["notify"])?;
         }
         eprintln!("COMMIT-FAULT: {action} :: {mutant} resolved by receipt, no replay");return Ok(());
        }
        if mutant.starts_with("commit-"){return Err("COMMIT cut was not armed".into());}
        let file=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/retention-audit/goldens/{action}-{label}.json"));
        if recording&&std::env::var("GOFREE_VERIFY_GO").as_deref()!=Ok("1"){if label=="success"{assert!((200..300).contains(&status),"{raw}");}golden::record(&file,&json!({"format":1,"route":format!("{method} {path}"),"case":label,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}))?;}else{let expected:Value=common::golden_doc(&file,"observation",&observation);golden::compare(&expected["observation"],&observation)?;eprintln!("GOLDEN-REPLAY: {method} {path} :: {label}");}
        let _=mutant;
        Ok::<_,BoxError>(())
    }.await;
    if notify_disabled {
        owner
            .batch_execute("ALTER TABLE system_config ENABLE TRIGGER trg_system_config_notify")
            .await?;
    }
    owner.batch_execute("DROP TRIGGER IF EXISTS gofree_compl2_mutant_bump ON messages;DROP FUNCTION IF EXISTS gofree_compl2_mutant_bump();DROP TRIGGER IF EXISTS gofree_compl2_mutant_audit ON admin_audit_log;DROP FUNCTION IF EXISTS gofree_compl2_mutant_audit();DROP TRIGGER IF EXISTS gofree_compl2_message_fault ON messages;DROP FUNCTION IF EXISTS gofree_compl2_message_fault();DROP TRIGGER IF EXISTS gofree_compl2_config_fault ON system_config;DROP FUNCTION IF EXISTS gofree_compl2_config_fault();DROP TRIGGER IF EXISTS gofree_compl2_fault ON admin_audit_log;DROP FUNCTION IF EXISTS gofree_compl2_fault();").await?;
    owner
        .execute("DELETE FROM audit_chain_cutover", &[])
        .await?;
    for row in saved_cutover {
        owner.execute("INSERT INTO audit_chain_cutover SELECT (jsonb_populate_record(NULL::audit_chain_cutover,$1::text::jsonb)).*",&[&row]).await?;
    }
    owner
        .execute(
            "DELETE FROM message_trace WHERE message_id='compl2-prune'",
            &[],
        )
        .await?;
    owner.execute("DELETE FROM retention_policies", &[]).await?;
    for row in saved["policies"].as_array().unwrap() {
        owner.execute("INSERT INTO retention_policies SELECT (jsonb_populate_record(NULL::retention_policies,$1::text::jsonb)).*",&[&row.to_string()]).await?;
    }
    if action.starts_with("log_") {
        owner
            .execute(
                "DELETE FROM system_config WHERE key LIKE 'log_retention_%'",
                &[],
            )
            .await?;
        for row in saved["config"].as_array().unwrap() {
            owner.execute("INSERT INTO system_config SELECT (jsonb_populate_record(NULL::system_config,$1::text::jsonb)).*",&[&row.to_string()]).await?;
        }
    }
    if action.starts_with("audit_") {
        owner
            .execute("DELETE FROM audit_policy WHERE id=1", &[])
            .await?;
        for row in saved["audit_policy"].as_array().unwrap() {
            owner.execute("INSERT INTO audit_policy SELECT (jsonb_populate_record(NULL::audit_policy,$1::text::jsonb)).*",&[&row.to_string()]).await?;
        }
    }
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await?;
    owner.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={} OR (action='console.denied' AND notes LIKE '/admin/%');DELETE FROM rust_operation_receipts WHERE family='F04';COMMIT;",a.user)).await?;
    owner
        .execute(
            "UPDATE messages SET held=false WHERE mailbox_id=ANY($1)",
            &[&vec![a.mailbox, other.mailbox]],
        )
        .await?;
    owner
        .execute(
            "UPDATE mailboxes SET litigation_hold=false WHERE id=ANY($1)",
            &[&vec![a.mailbox, other.mailbox]],
        )
        .await?;
    fixture::remove(&owner, &a).await?;
    fixture::remove(&owner, &other).await?;
    result
}

async fn content_snapshot(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<Value, BoxError> {
    let ids = vec![a.mailbox, b.mailbox];
    let tags = vec![a.inbox, a.label, b.inbox, b.label];
    let mut out = json!({});
    for(table,sql)in[
 ("messages","SELECT jsonb_build_object('id',id,'mailbox_id',mailbox_id,'held',held,'subject',subject,'from_addr',from_addr,'received_at',received_at,'size_bytes',size_bytes)::text FROM messages WHERE mailbox_id=ANY($1) ORDER BY id"),
 ("message_tags","SELECT jsonb_build_object('message_id',t.message_id,'tag_id',t.tag_id,'is_primary',t.is_primary,'added_by',t.added_by)::text FROM message_tags t JOIN messages m ON m.id=t.message_id AND m.received_at=t.received_at WHERE m.mailbox_id=ANY($1) ORDER BY t.message_id,t.tag_id"),
 ("mailbox_state","SELECT jsonb_build_object('mailbox_id',id,'email',jmap_email_state,'tag',jmap_tag_state,'thread',jmap_thread_state,'mailbox',jmap_mailbox_state)::text FROM mailboxes WHERE id=ANY($1) ORDER BY id"),
 ("journal","SELECT jsonb_build_object('mailbox_id',mailbox_id,'datatype',datatype,'state_seq',state_seq,'entity_id',entity_id,'op',op)::text FROM jmap_changes_journal WHERE mailbox_id=ANY($1) ORDER BY mailbox_id,state_seq"),
 ("mailbox_audit","SELECT to_jsonb(t)::text FROM mailbox_audit_log t WHERE mailbox_id=ANY($1) ORDER BY id")]{out[table]=json!(c.query(sql,&[&ids]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?);}
    out["tag_counts"]=json!(c.query("SELECT jsonb_build_object('tag_id',id,'mailbox_id',mailbox_id,'total_count',total_count,'unread_count',unread_count,'size_bytes',size_bytes,'jmap_state',jmap_state)::text FROM tags WHERE id=ANY($1) ORDER BY id",&[&tags]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?);
    Ok(out)
}
fn content_ids(v: &mut Value, key: &str, a: &fixture::Account, b: &fixture::Account) {
    let messages = [
        (a.two_labels, "<message-a>"),
        (a.inbox_only, "<message-b>"),
        (b.two_labels, "<message-c>"),
        (b.inbox_only, "<message-d>"),
    ];
    let mailboxes = [(a.mailbox, "<mailbox-a>"), (b.mailbox, "<mailbox-b>")];
    let tags = [
        (a.inbox, "<inbox-a>"),
        (a.label, "<label-a>"),
        (b.inbox, "<inbox-b>"),
        (b.label, "<label-b>"),
    ];
    let mapping: &[(i64, &str)] = match key.to_ascii_lowercase().as_str() {
        "id" | "message_id" | "ids" | "deleted_ids" | "entity_email" => &messages,
        "mailbox_id" | "mailboxids" | "mailbox_ids" => &mailboxes,
        "tag_id" | "entity_tag" => &tags,
        _ => &[],
    };
    if let Some(n) = v
        .as_i64()
        .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
    {
        if let Some((_, s)) = mapping.iter().find(|(id, _)| *id == n) {
            *v = json!(s);
            return;
        }
    }
    match v {
        Value::Object(m) => {
            let datatype = m
                .get("datatype")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            for (k, x) in m {
                content_ids(
                    x,
                    if k == "entity_id" {
                        if datatype == "Email" {
                            "entity_email"
                        } else {
                            "entity_tag"
                        }
                    } else {
                        k
                    },
                    a,
                    b,
                );
            }
        }
        Value::Array(xs) => {
            for x in xs {
                content_ids(x, key, a, b)
            }
        }
        _ => {}
    }
}
