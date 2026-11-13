mod export_fixture;
mod faults;
pub mod qualification;
mod zip;
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "policies" => ("GET", "/admin/chat-retention-policies"),
        "create" => ("POST", "/admin/chat-retention-policies"),
        "update" => ("PUT", "/admin/chat-retention-policies/{id}"),
        "delete" => ("DELETE", "/admin/chat-retention-policies/{id}"),
        "cases" => ("GET", "/admin/chat-ediscovery/cases"),
        "holds" => ("GET", "/admin/chat-ediscovery/holds"),
        "hold" => ("POST", "/admin/chat-ediscovery/holds"),
        "release" => ("POST", "/admin/chat-ediscovery/holds/{id}/release"),
        "search" => ("POST", "/admin/chat-ediscovery/search"),
        "read" => ("GET", "/admin/chat-ediscovery/channels/{id}/messages"),
        "export" => ("GET", "/admin/chat-ediscovery/export"),
        "preview" => ("GET", "/admin/chat-purge/preview"),
        "overview" => ("GET", "/admin/chat-compliance/overview"),
        _ => panic!("unknown route"),
    }
}
fn token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let original = common::recovery_token(user);
    let pieces = original.split('.').collect::<Vec<_>>();
    let mut v: Value = serde_json::from_slice(&B.decode(pieces[1]).unwrap()).unwrap();
    v["admin"] = json!(true);
    v["perms"] = json!([
        "chat.compliance_manage",
        "chat.compliance_view",
        "chat.ediscovery",
        "forged.permission"
    ]);
    v["email"] = json!("compl3@test");
    let payload = B.encode(v.to_string());
    let s: p256::ecdsa::Signature = SigningKey::from_slice(&[0x11; 32])
        .unwrap()
        .sign(format!("{}.{payload}", pieces[0]).as_bytes());
    format!("{}.{payload}.{}", pieces[0], B.encode(s.to_bytes()))
}
fn normalize(v: &mut Value, actor: i64, mailbox: i64) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if ["checksum", "prev_checksum", "_checksum", "_prev"].contains(&k.as_str())
                    && x.is_string()
                {
                    *x = json!("<digest>");
                } else if [
                    "user_id",
                    "userId",
                    "created_by",
                    "createdBy",
                    "executed_by",
                    "exportedBy",
                    "author_id",
                    "authorId",
                    "released_by",
                    "releasedBy",
                    "custodian_user_id",
                    "custodianUserId",
                ]
                .contains(&k.as_str())
                    && x.as_i64() == Some(actor)
                {
                    *x = json!("<actor>");
                } else if k == "mailbox_id" && x.as_i64() == Some(mailbox) {
                    *x = json!("<mailbox>");
                } else {
                    normalize(x, actor, mailbox);
                }
            }
        }
        Value::Array(xs) => {
            for x in xs {
                normalize(x, actor, mailbox)
            }
        }
        Value::String(s) => {
            let b = s.as_bytes();
            if b.len() >= 19
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
async fn snapshot(
    c: &tokio_postgres::Client,
    mailbox: i64,
    content: bool,
) -> Result<Value, BoxError> {
    let valid: bool = c
        .query_one(
            "SELECT coalesce(bool_and(valid),true) FROM verify_chat_audit_chain(961001)",
            &[],
        )
        .await?
        .get(0);
    if !valid {
        return Err("invalid observed chat audit chain".into());
    }
    let mut out = json!({});
    for (name, sql) in [
        (
            "policies",
            "SELECT to_jsonb(t)::text FROM chat_retention_policies t ORDER BY id",
        ),
        (
            "holds",
            "SELECT to_jsonb(t)::text FROM chat_case_holds t ORDER BY id",
        ),
        (
            "coverage",
            "SELECT to_jsonb(t)::text FROM chat_case_hold_channels t ORDER BY hold_id,channel_id",
        ),
        (
            "searches",
            "SELECT to_jsonb(t)::text FROM chat_ediscovery_searches t ORDER BY id",
        ),
        (
            "acts",
            "SELECT to_jsonb(t)::text FROM chat_audit_log t WHERE channel_id=961001 ORDER BY id",
        ),
        (
            "channel",
            "SELECT to_jsonb(t)::text FROM chat_channels t WHERE id=961001",
        ),
    ] {
        out[name] = json!(c
            .query(sql, &[])
            .await?
            .iter()
            .map(|r| serde_json::from_str::<Value>(&r.get::<_, String>(0)))
            .collect::<Result<Vec<_>, _>>()?);
    }
    if content {
        out["messages"] = json!(c
            .query(
                "SELECT CASE WHEN t.payload IS NULL THEN to_jsonb(t) ELSE (to_jsonb(t)-'payload')||jsonb_build_object('payload',t.payload::text) END::text FROM chat_messages t WHERE channel_id=961001 ORDER BY id",
                &[]
            )
            .await?
            .iter()
            .map(|r| serde_json::from_str::<Value>(&r.get::<_, String>(0)))
            .collect::<Result<Vec<_>, _>>()?);
    }
    out["mailbox_state"]=serde_json::from_str(&c.query_one("SELECT jsonb_build_object('email',jmap_email_state,'tag',jmap_tag_state,'thread',jmap_thread_state,'mailbox',jmap_mailbox_state)::text FROM mailboxes WHERE id=$1",&[&mailbox]).await?.get::<_,String>(0))?;
    Ok(out)
}
pub async fn run(action: &str, label: &str, mutant: &str) -> Result<(), BoxError> {
    let _guard = SERIAL.lock().await;
    let db = Db::for_case("compl3-http").ok_or("DB required")?;
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "compl3-admin").await?;
    let permissions = if label == "manage-only" {
        vec!["chat.compliance_manage"]
    } else if matches!(label, "foreign" | "locale-foreign") {
        vec!["users.read"]
    } else {
        vec![
            "chat.compliance_manage",
            "chat.compliance_view",
            "chat.ediscovery",
        ]
    };
    let role:i64=owner.query_one("INSERT INTO admin_role_groups(name,permissions) VALUES ('compl3-oracle',$1) RETURNING id",&[&permissions]).await?.get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(role_group_id,user_id) VALUES ($1,$2)",
            &[&role, &a.user],
        )
        .await?;
    let enabled: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.chat_compliance'",
            &[],
        )
        .await?
        .get(0);
    let result=async {
 owner.execute("UPDATE feature_toggles SET enabled=true WHERE key='feature.chat_compliance'",&[]).await?;
 owner.execute("INSERT INTO ediscovery_cases(id,name,description,created_by) OVERRIDING SYSTEM VALUE VALUES (970001,'Investigation','Chat <evidence>',$1)",&[&a.user]).await?;
 owner.execute("INSERT INTO chat_channels(id,kind,name,created_by) OVERRIDING SYSTEM VALUE VALUES (961001,'channel','compl3-channel',$1)",&[&a.user]).await?;
 owner.execute("INSERT INTO chat_channel_members(channel_id,user_id,role) VALUES (961001,$1,'owner')",&[&a.user]).await?;
 owner.batch_execute("INSERT INTO chat_retention_policies(id,name,applies_to,duration_days,enabled,effective_at,created_at,updated_at) OVERRIDING SYSTEM VALUE VALUES (962001,'Shield <A>','channel',90,true,'2025-01-01','2025-01-01','2025-01-01');").await?;
 if matches!(action,"hold"|"holds"|"release"){owner.batch_execute("SELECT setval('chat_case_holds_id_seq',965100,true)").await?;if matches!(action,"holds"|"release"){owner.query_one("SELECT chat_case_hold_set($1,970001,NULL,961001,'Hold evidence')",&[&a.user]).await?;}}
 if matches!(action,"preview"|"search"|"read"|"export"){owner.execute("INSERT INTO chat_messages(id,channel_id,seq,author_id,body,created_at) OVERRIDING SYSTEM VALUE VALUES (966001,961001,1,$1,'Evidence oracle <A>','2020-01-01')",&[&a.user]).await?;}
 if action=="overview"{owner.batch_execute("UPDATE chat_channels SET legal_hold=true,legal_hold_reason='Matter <O>',retention_days=180 WHERE id=961001").await?;}
 if label=="last-run"{owner.batch_execute("SELECT audit_write(NULL,'chat.purge_run','chat',NULL,NULL,'{\"channels\":2,\"messages\":7,\"drained\":true}'::jsonb,NULL,'compl3-last-run','core')").await?;}
 if matches!(label,"last-null"|"last-invalid"){let data=if label=="last-null"{json!({"channels":null,"messages":0,"drained":true})}else{json!({"channels":"bad","messages":0,"drained":true})};owner.query_one("SELECT audit_write(NULL,'chat.purge_run','chat',NULL,NULL,$1::text::jsonb,NULL,'compl3-last-run','core')",&[&data.to_string()]).await?;}

 if matches!(label,"disabled"|"locale-disabled"){owner.batch_execute("UPDATE feature_toggles SET enabled=false WHERE key='feature.chat_compliance'").await?;}
 if action=="create"{owner.batch_execute("SELECT setval('chat_retention_policies_id_seq',962100,true)").await?;}
 if label=="audit-failure"{owner.batch_execute("CREATE FUNCTION gofree_compl3_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action LIKE 'chat_retention_policy_%' OR NEW.action IN('chat_case_hold_set','chat_case_hold_release','chat_ediscovery_search','chat_ediscovery_read','chat_ediscovery_export') THEN RAISE EXCEPTION 'compl3 audit fault'; END IF; RETURN NEW;END;$$;CREATE TRIGGER gofree_compl3_audit_fault BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION gofree_compl3_audit_fault()").await?;}
 if label=="grace-disable-shield" || (action=="delete" && matches!(label,"exposure"|"confirm"|"wrong-confirm")){owner.batch_execute("INSERT INTO chat_retention_policies(id,name,applies_to,duration_days,enabled,effective_at) OVERRIDING SYSTEM VALUE VALUES (962002,'Short ceiling','all',30,true,'2025-01-01')").await?;}
 if label=="closed"{owner.execute("UPDATE ediscovery_cases SET status='closed',closed_at=now(),closed_by=$1 WHERE id=970001",&[&a.user]).await?;}
 if label=="chain-failure"{owner.batch_execute("CREATE FUNCTION gofree_compl3_chain_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'compl3 mandatory chain fault';END;$$;CREATE TRIGGER gofree_compl3_chain_fault BEFORE INSERT ON chat_audit_log FOR EACH ROW EXECUTE FUNCTION gofree_compl3_chain_fault()").await?;}
 if action=="release" && label=="other-hold"{owner.execute("INSERT INTO ediscovery_cases(id,name,created_by) OVERRIDING SYSTEM VALUE VALUES (970002,'Other matter',$1)",&[&a.user]).await?;owner.query_one("SELECT chat_case_hold_set($1,970002,NULL,961001,'Other matter')",&[&a.user]).await?;}
 if matches!(action,"search"|"read"|"export"){owner.batch_execute("SELECT setval('chat_ediscovery_searches_id_seq',964100,true)").await?;}
 if matches!(label,"han"|"han-mark"){let value=if label=="han"{"机密记录"}else{"々abc"};owner.execute("UPDATE chat_messages SET body=$1 WHERE id=966001",&[&value]).await?;}
 if label=="nonmember"{owner.batch_execute("DELETE FROM chat_channel_members WHERE channel_id=961001").await?;}
 if action=="read" && label=="zero-limit"{owner.execute("INSERT INTO chat_messages(id,channel_id,seq,author_id,body,created_at) OVERRIDING SYSTEM VALUE VALUES (966002,961001,2,$1,'Second oracle','2020-01-01')",&[&a.user]).await?;}
 if label=="huge-json"{owner.batch_execute("UPDATE chat_messages SET payload=jsonb_build_object('enormous',('1'||repeat('0',1000))::numeric) WHERE id=966001").await?;}
 if action=="export" && label=="scheduled" {
 owner.execute("INSERT INTO scheduled_actions(id,action_kind,fire_at,payload,status,mailbox_id) VALUES ('29100000-0000-0000-0000-000000000001','chat_send','2030-01-02T03:04:05.120Z',jsonb_build_object('channelId',961001,'userId',$1::bigint,'body','Pending <A>'),'pending',$2),('29100000-0000-0000-0000-000000000002','chat_send','2030-01-02',jsonb_build_object('channelId',961001),'failed',$2),('29100000-0000-0000-0000-000000000003','chat_send','2030-01-02',jsonb_build_object('channelId',961001),'done',$2)",&[&a.user,&a.mailbox]).await?;
 }
 if action=="export" && matches!(label,"federated-hub"|"federated-spoke"|"federated-empty"|"bad-coverage") {
 owner.batch_execute("UPDATE chat_channels SET federated_room_id='compl3-room' WHERE id=961001;INSERT INTO federation_rooms(room_id,hub_domain,channel_id) VALUES ('compl3-room','hub.example',961001);INSERT INTO federation_room_members(room_id,member_domain,invited_at,left_at,left_reason,coverage_epochs) VALUES ('compl3-room','alpha.example','2020-01-01',NULL,NULL,'[{\"parkedAt\":\"2021-01-01T00:00:00Z\",\"resumedAt\":\"2021-01-02T00:00:00Z\",\"reason\":\"backpressure\"}]'),('compl3-room','beta.example','2020-02-01','2022-03-01','revoked','[{\"parkedAt\":\"2022-03-01T00:00:00Z\",\"reason\":\"revoked\"}]')").await?;
 }
 if label=="federated-spoke"{owner.batch_execute("UPDATE chat_channels SET federated_peer_domain='hub.example' WHERE id=961001").await?;}
 if label=="federated-dm"{owner.batch_execute("UPDATE chat_channels SET kind='dm',federated_peer_domain='peer.example' WHERE id=961001").await?;}
 if label=="federated-empty"{owner.batch_execute("DELETE FROM federation_room_members WHERE room_id='compl3-room'").await?;}
 if label=="bad-coverage"{owner.batch_execute("UPDATE federation_room_members SET coverage_epochs='[{\"parkedAt\":\"bad\"}]' WHERE room_id='compl3-room'").await?;}
 if label=="revisions"{owner.execute("INSERT INTO chat_message_revisions(id,channel_id,message_id,prior_body,edited_by,created_at) OVERRIDING SYSTEM VALUE VALUES(967001,961001,966001,'Prior <A>',$1,'2020-01-01')",&[&a.user]).await?;}
 if label=="scheduled-bad"{owner.batch_execute("INSERT INTO scheduled_actions(id,action_kind,fire_at,payload,status) VALUES('29100000-0000-0000-0000-000000000001','chat_send','2030-01-01','{\"channelId\":961001,\"userId\":\"broken\"}','pending')").await?;}
 if action=="export" && label.starts_with("attachments") {export_fixture::attachments(&owner,a.user).await?;}
 faults::install(&owner,label).await?;
 if matches!(label,"large"|"head-large"){use sha2::{Digest,Sha256};let text=(0..1024).map(|n|format!("{:x}",Sha256::digest(format!("compl3-stream-{n}")))).collect::<String>();owner.execute("UPDATE chat_messages SET body=$1 WHERE id=966001",&[&text]).await?;}
 let s3_calls=std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));let calls=s3_calls.clone();let corrupt=label=="attachments-corrupt";let missing=label=="attachments-missing";let no_modified=label=="attachments-no-modified";
 let s3=common::fake_upstream(move |r|{let calls=calls.clone();async move{if r.uri().query().unwrap_or("").starts_with("location"){return Response::builder().header("content-type","application/xml").body(common::full("<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">us-east-1</LocationConstraint>")).unwrap();}if r.uri().path().starts_with("/mailblobs/compl3-chunk-"){common::s3::observe(&r,&[]).expect("valid signed object request");calls.lock().unwrap().push(format!("{} {}",r.method(),r.uri().path()));}if missing && r.uri().path().ends_with("compl3-chunk-A"){return Response::builder().status(404).body(common::full("<Error><Code>NoSuchKey</Code></Error>")).unwrap();}let data=if r.uri().path().ends_with("compl3-chunk-A"){if corrupt {b"corrupt".as_slice()}else{export_fixture::A}}else if r.uri().path().ends_with("compl3-chunk-B"){export_fixture::B}else{b"evidence"};let builder=Response::builder().header("etag","\"compl3-object\"");let builder=if no_modified{builder}else{builder.header("last-modified","Wed, 01 Jan 2020 00:00:00 GMT")};builder.body(common::full(data)).unwrap()}}).await;
 let go=common::go_oracle::start_named(&db,s3,None,"gofree-compl3").await?;let recording=go.is_some();
 let patient=std::time::Duration::from_secs(30);let ex=|dsn:&str|setjoin_pg::ScopedExecutor::from_dsn_with(dsn,1,setjoin_pg::Timeouts{pool_wait:patient,create:patient,statement:patient}).map(|e|e.with_audit_keys("22".repeat(32),String::new())).map_err(|e|e.0);
 let mut request_dsn=db.app.clone().unwrap_or_else(||db.dsn.clone());let mut worker_dsn=db.dsn.clone();let mut commit_wire=None;
 if mutant.starts_with("commit-"){
  if recording{return Err("COMMIT tests require native replay".into());}
  let cut=if mutant=="commit-after"{common::commit::CommitCut::AfterCommit}else{common::commit::CommitCut::BeforeCommit};
  let request=matches!(action,"create"|"update"|"delete"|"hold"|"release");
  let (dsn,task)=common::commit::commit_cut_proxy(if request{&request_dsn}else{&worker_dsn},cut).await;
  if request{request_dsn=dsn;}else{worker_dsn=dsn;}commit_wire=Some(qualification::Wire{task});
 }
 let exec=ex(&request_dsn)?;let worker=ex(&worker_dsn)?;
 let _=(&exec,&worker);
 let mut inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;
 for r in inventory["routes"].as_array_mut().unwrap(){if r["family"]=="F04" && r["slice"]=="chat-compliance"{if recording{r["state"]=json!("OFF");r["upstream"]=json!("go-mail");}else{assert_eq!(r["state"],"ON");assert_eq!(r["upstream"],"local-rust");}}}
 let adapter=setjoin_gateway::chat_compliance::ChatComplianceRoute {store:Some(std::sync::Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{s3}"),"mailblobs","test-access","test-secret")?)),database:setjoin_pg::workers::WorkerDatabase::new(&db.dsn).unwrap(),exec,worker,keys:std::sync::Arc::new(common::recovery_keys()),issuer:"mailserver".into()};
 let routes=RouteTable::proxy_all().with(qualification::Status{inner:adapter,change:mutant=="status"});
 // Production adapter; ordinary replay has no Go upstream.
 let gateway=Gateway::new(Config{upstream:go.as_ref().map(|g|format!("http://{}",g.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},routes)?.with_inventory(&inventory.to_string())?;
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let task=tokio::spawn(gateway.serve(listener));
 let(method,path)=route(action);let mut external=format!("/api{}{}",path.replace("{id}",if matches!(action,"update"|"delete"|"release") && label=="invalid"{"bad"}else if action=="update" && label=="missing"{"962999"}else if action=="release" && label=="missing"{"965999"}else if action=="release"{"965101"}else if action=="read"{"961001"}else{"962001"}),if label=="invalid"{"?limit=wat&offset=-1"}else{""});if matches!(action,"holds"|"read") && label!="invalid"{external.push_str("?caseId=970001");}if action=="delete" && label=="confirm"{external.push_str("?confirm=DESTROY");}if action=="delete" && label=="wrong-confirm"{external.push_str("?confirm=destroy");}if action=="read"{let base="/api/admin/chat-ediscovery/channels/961001/messages";match label{
 "missing-case"=>external=format!("{base}?caseId=99999999"),"missing-channel"=>external="/api/admin/chat-ediscovery/channels/99999999/messages?caseId=970001".into(),"bad-case"=>external=format!("{base}?caseId=bad"),"bad-before"=>external=format!("{base}?caseId=970001&beforeId=bad"),"bad-limit"=>external=format!("{base}?caseId=970001&limit=bad"),"zero-limit"=>external=format!("{base}?caseId=970001&limit=0"),"before"=>external=format!("{base}?caseId=970001&beforeId=966001"),"encoded-id"=>external="/api/admin/chat-ediscovery/channels/%39%36%31%30%30%31/messages?caseId=970001".into(),"encoded-mount"=>external="/%61pi/admin/chat-ediscovery/channels/961001/messages?caseId=970001".into(),_=>{}}}
if action=="export"{external="/api/admin/chat-ediscovery/export?caseId=970001&channels=961001".into();if label.starts_with("attachments"){external.push_str(if label=="attachments-false"{"&includeAttachments=true"}else{"&includeAttachments=1"});}let query=match label{"invalid"|"locale"=>Some("caseId=bad&channels=961001"),"missing-case"=>Some("caseId=99999999&channels=961001"),"missing-channel"=>Some("caseId=970001&channels=99999999"),"mixed-missing"=>Some("caseId=970001&channels=961001,99999999"),"bad-channel"=>Some("caseId=970001&channels=wat"),"channel-bytes"=>Some("caseId=970001&channels=%FF%ED%A0%80"),"channel-control"=>Some("caseId=970001&channels=%07%0B%00%7F"),"channel-unicode"=>Some("caseId=970001&channels=%E2%80%A8%F3%B0%80%80"),"channel-syntax-after-signed-overflow"=>Some("caseId=970001&channels=9223372036854775808x"),"channel-overflow"=>Some("caseId=970001&channels=9223372036854775808"),"empty-channels"=>Some("caseId=970001&channels=,,%20"),"duplicate-channels"=>Some("caseId=970001&channels=%20,961001,,961001,%20"),_=>None};if let Some(query)=query{external=format!("/api/admin/chat-ediscovery/export?{query}");}}
let body=if action=="search"{r#"{"caseId":970001,"terms":"oracle","channelIds":[961001],"actorId":-1}"#}else if action=="release" && label=="empty-reason"{"{}"}else if action=="release" && label=="null"{"null"}else if action=="release" && label=="bad-json"{"{"}else if action=="release"{r#"{"reason":"Release <evidence>","releasedBy":-1}"#}else if action=="hold" && label=="invalid"{"{}"}else if action=="hold" && label=="bad-json"{"{"}else if action=="hold" && label=="trailing"{r#"{"caseId":970001,"channelId":961001,"reason":"x"} trailing"#}else if action=="hold" && label=="folded"{r#"{"CASEID":970001,"ChannelID":961001,"REASON":"First","reason":null}"#}else if action=="hold" && label=="empty-reason"{r#"{"caseId":970001,"channelId":961001}"#}else if action=="hold" && label=="missing-channel"{r#"{"caseId":970001,"channelId":99999999,"reason":"Missing"}"#}else if action=="hold" && label=="unreachable-custodian"{r#"{"caseId":970001,"custodianUserId":0,"reason":"Not reachable"}"#}else if action=="hold"{r#"{"caseId":970001,"channelId":961001,"reason":"Hold <evidence>","createdBy":-1}"#}else if action=="update" && label=="grace-lengthen"{r#"{"name":"Longer","appliesTo":"channel","durationDays":180,"enabled":true}"#}else if action=="update" && label=="grace-disable-shield"{r#"{"name":"Disabled","appliesTo":"channel","durationDays":90,"enabled":false}"#}else if action=="update"{r#"{"name":"Updated <P>","appliesTo":"channel","durationDays":45,"enabled":true}"#}else if action=="create" && label=="invalid"{"{}"}else if action=="create"{r#"{"name":"Policy <A>","appliesTo":"all","durationDays":30,"enabled":true,"actorId":-1}"#}else{""};
 let body=if action=="hold" && label=="custodian"{json!({"caseId":970001,"custodianUserId":a.user,"reason":"Custodian evidence"}).to_string()}else{body.to_owned()};
 let mut body=body;
 if matches!(action,"create"|"update") {
  if label=="bad-json"{body="{".into();}else{let mut input:Value=serde_json::from_str(&body)?;let changed=match label{"zero-days"=>{input["durationDays"]=json!(0);true},"empty-name"=>{input["name"]=json!("");true},"invalid-kind"=>{input["appliesTo"]=json!("bad");true},_=>false};if changed{body=input.to_string();}}
 }

 if action=="search"{let mut request:Value=serde_json::from_str(&body)?;let changed=match label{
 "invalid"|"locale"|"locale-invalid"=>{request=json!({});true},"locale-reducer"=>{request["caseId"]=json!(99999999);true},"missing-case"=>{request["caseId"]=json!(99999999);true},
 "han"=>{request["terms"]=json!("机");true},"han-mark"=>{request["terms"]=json!("々");true},
 "date-offset24"=>{request["dateFrom"]=json!("2026-01-01T00:00:00+24:00");true},"invalid-date"=>{request["dateFrom"]=json!("not-a-date");true},"date-from"=>{request["dateFrom"]=json!("2021-01-01");true},"date-to"=>{request["dateTo"]=json!("2019-01-01T00:00:00Z");true},
 "null-channels"=>{request["channelIds"]=Value::Null;true},"null-channel-entry"=>{request["channelIds"]=json!([null]);true},"limit-overflow"=>{request["limit"]=json!(2147483648_i64);true},_=>false};
 if changed{body=request.to_string();}if label=="bad-json"{body="{".into();}if label=="folded"{body=r#"{"CASEID":970001,"TERMS":"oracle","terms":null,"CHANNELIDS":[961001]}"#.into();}}
 let wire_method=if label.starts_with("head"){"HEAD"}else{method};
 let recorded_body=if label=="custodian"{body.replace(&format!("\"custodianUserId\":{}",a.user),"\"custodianUserId\":\"<actor>\"")}else{body.clone()};
 let send=||async{Ok::<_,BoxError>(common::send(address,Request::builder().method(wire_method).uri(&external).header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("x-request-id","gofree-compl3-oracle").header("accept-language",if label=="locale-invalid"{"../../badtag;q=1"}else if label.starts_with("locale"){"zh-Hant-TW, en;q=0.5"}else{"en"}).header("authorization",format!("Bearer {}",token(a.user))).body(common::full(body.clone()))?).await)};
 if matches!(label,"repeat"|"grace-repeat"){let first=send().await?;let code=first.status().as_u16();let _=common::body_bytes(first).await;if code>=400{return Err(format!("initial repeat request failed: {code}").into());}}
 let before=snapshot(&owner,a.mailbox,matches!(action,"preview"|"search"|"read"|"export")).await?;let last:i64=owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
 let mut alerts=db.listen("admin:alert").await?;
 let mut chat_events=db.listen(&format!("chat:{}",a.user)).await?;let mut tag_events=db.listen(&format!("tag:{}",a.mailbox)).await?;
 if label=="query-failure"{faults::rename(&owner,action).await?;}
 let response=send().await?;
 let status=response.status().as_u16();let mut headers=json!({});for n in response.headers().keys(){headers[n.as_str()]=json!(response.headers().get_all(n).iter().map(|v|v.to_str().unwrap()).collect::<Vec<_>>());}
 let is_zip=action=="export" && headers["content-type"][0]=="application/zip";
 let bytes=common::body_bytes(response).await;faults::restore(&owner,action,label).await?;let mut text=if is_zip{String::new()}else{String::from_utf8(bytes.to_vec())?};
 if let Ok(v)=serde_json::from_str::<Value>(&text){let mut fixed=v.clone();normalize(&mut fixed,a.user,a.mailbox);fn replace(text:&mut String,v:&Value,f:&Value){match(v,f){(Value::Object(a),Value::Object(b))=>for(k,x)in a{if let Some(y)=b.get(k){if x.is_number() && y.is_string() && x!=y{for end in [",","}","]"]{*text=text.replace(&format!("\"{k}\":{}{end}",x),&format!("\"{k}\":{}{end}",y));}}else{replace(text,x,y);}}},(Value::Array(a),Value::Array(b))=>for(x,y)in a.iter().zip(b){replace(text,x,y)},_=>if v!=f{*text=text.replace(&v.to_string(),&f.to_string())}}}replace(&mut text,&v,&fixed);}
 if serde_json::from_str::<Value>(&text).is_err() && serde_json::from_str::<Box<serde_json::value::RawValue>>(&text).is_ok(){
 for key in ["createdBy","closedBy","authorId","userId","exportedBy","custodianUserId"]{for space in [""," "]{for end in [",","}","]"]{text=text.replace(&format!("\"{key}\":{space}{}{end}",a.user),&format!("\"{key}\":{space}\"<actor>\"{end}"));}}}
 let bytes=text.as_bytes();let(mut i,mut last)=(0,0);let mut fixed=String::new();while i<bytes.len(){if bytes[i]!=b'"'{i+=1;continue;}let start=i;i+=1;while i<bytes.len(){if bytes[i]==b'\\'{i+=2;continue;}if bytes[i]==b'"'{i+=1;break;}i+=1;}let token=&text[start..i];if let Ok(value)=serde_json::from_str::<String>(token){let b=value.as_bytes();if b.len()>=19 && b.get(4)==Some(&b'-') && b.get(7)==Some(&b'-') && b.get(13)==Some(&b':'){fixed.push_str(&text[last..start]);fixed.push_str("\"<timestamp>\"");last=i;}}}fixed.push_str(&text[last..]);text=fixed;
 }
 if !headers["date"].is_null(){headers["date"]=json!(["<timestamp>"]);}if !headers["content-length"].is_null(){if wire_method=="HEAD"{let length=headers["content-length"][0].as_str().ok_or("HEAD length")?.parse::<usize>()?;if length==0{return Err("successful HEAD has zero advertised length".into());}}else{assert_eq!(headers["content-length"][0],bytes.len().to_string());}headers["content-length"]=if wire_method=="HEAD"{json!(["<head-length>"])}else if is_zip{json!(["<zip-length>"])}else{json!([text.len().to_string()])};}
 let mut audit=json!(owner.query("SELECT to_jsonb(t)::text FROM admin_audit_log t WHERE id>$1 ORDER BY id",&[&last]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?);for r in audit.as_array_mut().unwrap(){r["id"]=json!("<audit>");}normalize(&mut audit,a.user,a.mailbox);
 let after=snapshot(&owner,a.mailbox,matches!(action,"preview"|"search"|"read"|"export")).await?;
 let mut clocks=Value::Null;if label.starts_with("grace-"){let old=before["policies"].as_array().unwrap().iter().find(|p|p["id"]==962001).unwrap();let new=after["policies"].as_array().unwrap().iter().find(|p|p["id"]==962001).unwrap();let hours:i32=owner.query_one("SELECT GREATEST(0,ceil(extract(epoch FROM effective_at-clock_timestamp())/3600))::int FROM chat_retention_policies WHERE id=962001",&[]).await?.get(0);clocks=json!({"effectiveChanged":old["effective_at"]!=new["effective_at"],"updatedChanged":old["updated_at"]!=new["updated_at"],"remainingGraceHours":hours});}
 let mut effects=json!([{"table":"chat_compliance","before":before,"after":after}]);normalize(&mut effects,a.user,a.mailbox);
 let mut notify=alerts.drain(&owner).await?;notify.extend(chat_events.drain(&owner).await?);notify.extend(tag_events.drain(&owner).await?);
 let body_value=if wire_method=="HEAD"{if !bytes.is_empty(){return Err("HEAD emitted response bytes".into());}json!("")}else if is_zip{zip::normalize(&bytes,a.user,&owner).await?}else{json!(text)};
 if let Some(disposition)=headers["content-disposition"][0].as_str(){let prefix="attachment; filename=chat-ediscovery-case970001-";let time=disposition.strip_prefix(prefix).and_then(|s|s.strip_suffix(".zip")).ok_or("bad ZIP disposition")?;chrono::NaiveDateTime::parse_from_str(time,"%Y%m%d-%H%M%S")?;headers["content-disposition"]=json!([format!("{prefix}<timestamp>.zip")]);}
 let mut observation=json!({"request":{"method":wire_method,"path":path,"body":recorded_body},"response":{"status":status,"headers":headers,"body":body_value},"effects":effects,"audit":audit,"notify":notify});
 if label.starts_with("attachments"){observation["s3"]=json!(s3_calls.lock().unwrap().clone());}
 if !clocks.is_null(){observation["clocks"]=clocks;}if matches!(action,"read"|"export"){observation["request"]["query"]=json!(external.split_once('?').map(|(_,q)|q).unwrap_or(""));}
 if !recording{let metrics=common::send(address,Request::get("/_gateway/metrics").body(common::full(""))?).await;let text=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;if !text.lines().any(|s|s=="setjoin_gateway_proxied_to_go_by_family_total{family=\"F04\"} 0") || !text.lines().any(|s|s=="setjoin_gateway_proxied_to_go_total 0"){task.abort();let _=task.await;return Err(format!("native F04 request forwarded: {text}").into());}}
 task.abort();let _=task.await;
 if let Some(mut wire)=commit_wire {
  let cut=tokio::time::timeout(std::time::Duration::from_secs(5),&mut wire.task).await???;
  if (cut==common::commit::CommitCut::AfterCommit)!=(mutant=="commit-after"){return Err("wrong COMMIT boundary cut".into());}
  if !s3_calls.lock().unwrap().is_empty(){return Err("ambiguous command caused object I/O".into());}
  return qualification::commit_check(&db,a.user,action,mutant,&observation).await;
 }
 let file=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/chat-compliance/goldens/{action}-{label}.json"));
 if recording && std::env::var("GOFREE_VERIFY_GO").as_deref()!=Ok("1"){if label=="success"{if status!=match action{"create"|"hold"=>201,"delete"|"release"=>204,_=>200}{return Err(format!("Go success status {status}").into());}}golden::record(&file,&json!({"format":1,"route":format!("{method} {path}"),"case":label,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}))?;}else{let expected:Value=serde_json::from_slice(&std::fs::read(file)?)?;golden::compare(&expected["observation"],&observation)?;eprintln!("GOLDEN-REPLAY: {method} {path} :: {label}");}
 Ok::<_,BoxError>(())}.await;
    faults::cleanup(&owner, action, label).await?;
    if label == "chain-failure" {
        owner.batch_execute("DROP TRIGGER IF EXISTS gofree_compl3_chain_fault ON chat_audit_log;DROP FUNCTION IF EXISTS gofree_compl3_chain_fault()").await?;
    }
    if label == "audit-failure" {
        owner.batch_execute("DROP TRIGGER IF EXISTS gofree_compl3_audit_fault ON admin_audit_log;DROP FUNCTION IF EXISTS gofree_compl3_audit_fault()").await?;
    }
    export_fixture::cleanup(&owner).await?;
    owner.batch_execute("DELETE FROM federation_room_members WHERE room_id='compl3-room';DELETE FROM federation_rooms WHERE room_id='compl3-room'").await?;
    owner
        .execute(
            "DELETE FROM scheduled_actions WHERE id::text LIKE '29100000-%'",
            &[],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await?;
    owner.batch_execute("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM chat_case_hold_channels WHERE channel_id=961001;DELETE FROM chat_case_holds WHERE case_id BETWEEN 970000 AND 970999;DELETE FROM chat_ediscovery_searches WHERE case_id BETWEEN 970000 AND 970999;DELETE FROM chat_audit_log WHERE channel_id=961001;DELETE FROM chat_message_revisions WHERE channel_id=961001;DELETE FROM chat_messages WHERE channel_id=961001;DELETE FROM chat_channel_members WHERE channel_id=961001;DELETE FROM chat_channels WHERE id=961001;DELETE FROM chat_retention_policies WHERE id BETWEEN 962000 AND 962999;DELETE FROM ediscovery_cases WHERE id BETWEEN 970000 AND 970999;COMMIT;").await?;
    owner.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={} OR before_state->>'actor'='compl3@test' OR notes='compl3-last-run';DELETE FROM rust_operation_receipts WHERE family='F04';COMMIT;",a.user)).await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.chat_compliance'",
            &[&enabled],
        )
        .await?;
    // Enabling the feature records the audit-chain start floor; a disposable database starts without it.
    owner
        .execute("DELETE FROM system_config WHERE key='chat.compliance_enabled_at'", &[])
        .await?;
    fixture::remove(&owner, &a).await?;
    result
}
