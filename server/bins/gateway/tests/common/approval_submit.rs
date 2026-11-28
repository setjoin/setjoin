//! HR creation at HTTP + committed rows/audit/notification seams.
use super::{body_bytes, full, send, BoxError};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{approvals::ApprovalsRoute, Config, Gateway, RouteTable, TrustedProxies};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;
pub async fn run(kind: &str) -> Result<(), BoxError> {
    probe(kind, false).await
}
pub async fn probe(kind: &str, mutant: bool) -> Result<(), BoxError> {
    let label = kind;
    let kind = kind.strip_suffix("-qualified").unwrap_or(kind);
    let Some(db) = Db::for_case("approval-submit") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "appr1-hr-requester").await?;
    let b = fixture::account(&owner, "appr1-hr-approver").await?;
    let role:i64=owner.query_one("INSERT INTO admin_role_groups(name,permissions) VALUES($1,ARRAY['approvals.manage']) RETURNING id",&[&format!("appr1-hr-{}",a.user)]).await?.get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
    let policy:i64=owner.query_one("INSERT INTO approval_policies(consumer_type,name,enabled,priority,conditions,requires_approval,approver_spec) VALUES('hr.leave',$1,true,1,'{}',true,$2::text::jsonb) RETURNING id",&[&format!("appr1-hr-{}",a.user),&json!({"kind":"named","user_id":b.user}).to_string()]).await?.get(0);
    let toggle: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='approval.hr_leave'",
            &[],
        )
        .await?
        .get(0);
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=true WHERE key='approval.hr_leave'",
            &[],
        )
        .await?;
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F10'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    let caller = if kind == "foreign" { &b } else { &a };
    let body = if kind == "invalid" {
        r#"{"kind":"hr.leave","form":{}}"#.to_string()
    } else {
        json!({"kind":"hr.leave","form":{"leave_type":"annual","start_date":"2026-11-01","end_date":"2026-11-02","days":2,"reason":"Trip <two>"},"requester_user_id":if kind=="foreign"{a.user}else{b.user}}).to_string()
    };
    let mut request_ids = vec![];
    let mut audit_ids: Vec<i64> = vec![];
    let result=async{
  let endpoint=super::fake_upstream(|_|async{hyper::Response::new(full(""))}).await;
  let oracle=super::go_oracle::start_named(&db,endpoint,None,"gofree-appr1-http").await?;let recording=oracle.is_some();
  let route=ApprovalsRoute{exec:ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new()),worker_exec:ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new()),keys:Arc::new(super::recovery_keys()),issuer:"mailserver".into(),secret:b"blobs1-test-jwt-secret-for-recording".to_vec()};
  let mut inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;for r in inventory["routes"].as_array_mut().ok_or("routes")?{if r["family"]=="F10"{r["state"]=json!(if recording{"OFF"}else{"ON"});r["upstream"]=json!(if recording{"go-mail"}else{"local-rust"});r["oracle_commands"]=json!([""]);}}
  let g=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},RouteTable::proxy_all().with(super::approval_probe::Probe{inner:route,changed_status:mutant}))?.with_inventory(&inventory.to_string())?;
  let socket=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let addr=socket.local_addr()?;let server=tokio::spawn(g.serve(socket));
  if kind=="repeat" {
   let response=send(addr,hyper::Request::post("/api/me/approvals/hr").header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {}",super::recovery_token(caller.user))).header("x-request-id","gofree-appr1-oracle").body(full(body.clone()))?).await;let status=response.status();let data=body_bytes(response).await;if status!=201{return Err(format!("initial HR submission {status}: {data:?}").into())}
  }
  let mut before=vec![];for r in owner.query("SELECT to_jsonb(r)::text FROM approval_requests r WHERE requester_user_id=ANY($1) ORDER BY id",&[&vec![a.user,b.user]]).await?{before.push(serde_json::from_str::<Value>(&r.get::<_,String>(0))?);}
  let last:i64=owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log",&[]).await?.get(0);let mut listener=db.listen("approval_created").await?;
  let response=send(addr,hyper::Request::post("/api/me/approvals/hr").header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {}",super::recovery_token(caller.user))).header("x-request-id","gofree-appr1-oracle").body(full(body.clone()))?).await;
  let status=response.status().as_u16();let mut headers=serde_json::Map::new();for name in response.headers().keys(){headers.insert(name.to_string(),json!(response.headers().get_all(name).iter().map(|v|v.to_str().map(str::to_string)).collect::<Result<Vec<_>,_>>()?));}let raw=String::from_utf8(body_bytes(response).await.to_vec())?;
  let mut requests=vec![];for r in owner.query("SELECT id,to_jsonb(r)::text FROM approval_requests r WHERE requester_user_id=ANY($1) ORDER BY id",&[&vec![a.user,b.user]]).await?{request_ids.push(r.get::<_,i64>(0));requests.push(serde_json::from_str::<Value>(&r.get::<_,String>(1))?);}
  let mut audits=vec![];for r in owner.query("SELECT id,to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id",&[&last]).await?{audit_ids.push(r.get(0));audits.push(serde_json::from_str::<Value>(&r.get::<_,String>(1))?);}
  let mut notifications=vec![];for n in listener.drain(&owner).await?{notifications.push(serde_json::from_str::<Value>(&n)?);}
  let mut response_body=raw.clone();for (index,id) in request_ids.iter().enumerate(){response_body=response_body.replace(&format!("\"id\":{id}"),&format!("\"id\":\"{}\"",if index==0{"<request>".into()}else{format!("<request-{}>",index+1)}));}
  super::approval_admin::normalize_headers(&mut headers,&raw,&response_body)?;
  let mut observation=json!({"request":{"method":"POST","path":"/me/approvals/hr","external_path":"/api/me/approvals/hr","body":body.replace(&format!("\"requester_user_id\":{}",if kind=="foreign"{a.user}else{b.user}),"\"requester_user_id\":\"<forged>\"")},"response":{"status":status,"headers":headers,"body":response_body},"effects":if requests.is_empty(){vec![]}else{vec![json!({"table":"approval_requests","before":before,"after":requests})]},"audit":audits,"notify":notifications});
  normalize(&mut observation,&request_ids,policy,&a,&b,"")?;
  if !recording{super::approval_probe::no_go(addr).await?;}
  server.abort();let dir=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/approvals/goldens");let file=dir.join(format!("submit-{label}.json"));let row_file=dir.join(format!("submit-{label}-row-effects.json"));
  if recording{let want=if kind=="invalid"{400}else{201};if status!=want{return Err(format!("Go submit {status}: {raw}").into())}let source=std::env::var("GOFREE_GO_SOURCE")?;golden::record(&file,&json!({"format":1,"route":"POST /me/approvals/hr","case":kind,"go_source":source,"observation":observation}))?;golden::record(&row_file,&json!({"format":1,"route":"POST /me/approvals/hr","case":format!("{kind}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;}else{let expected:Value=serde_json::from_slice(&std::fs::read(file)?)?;golden::compare(&expected["observation"],&observation)?;let rows:Value=serde_json::from_slice(&std::fs::read(row_file)?)?;golden::compare(&rows["effects"],&observation["effects"])?;eprintln!("GOLDEN-REPLAY: POST /me/approvals/hr :: {kind}");}Ok::<_,BoxError>(())
 }.await;
    for row in owner.query("SELECT id FROM admin_audit_log WHERE target_type='approval_request' AND target_id=ANY($1)",&[&request_ids]).await?{audit_ids.push(row.get(0));}
    owner
        .execute(
            "DELETE FROM approval_requests WHERE requester_user_id=ANY($1)",
            &[&vec![a.user, b.user]],
        )
        .await?;
    owner
        .execute("DELETE FROM approval_policies WHERE id=$1", &[&policy])
        .await?;
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica")
        .await?;
    owner
        .execute(
            "DELETE FROM admin_audit_log WHERE id=ANY($1)",
            &[&audit_ids],
        )
        .await?;
    owner.batch_execute("COMMIT").await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='approval.hr_leave'",
            &[&toggle],
        )
        .await?;
    owner.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 second' WHERE role_group_id=$1",&[&role]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&role],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await?;
    for row in owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F10'",
            &[],
        )
        .await?
    {
        let id: String = row.get(0);
        if !receipts.contains(&id) {
            owner
                .execute(
                    "DELETE FROM rust_operation_receipts WHERE operation_id=$1::text::uuid",
                    &[&id],
                )
                .await?;
        }
    }
    super::remove_blob_account(&owner, &a).await?;
    super::remove_blob_account(&owner, &b).await?;
    result
}
fn normalize(
    v: &mut Value,
    request: &[i64],
    policy: i64,
    a: &fixture::Account,
    b: &fixture::Account,
    key: &str,
) -> Result<(), BoxError> {
    match v {
        Value::Object(map) => {
            let audit = map.contains_key("checksum");
            for (k, x) in map {
                if k == "id" && audit {
                    if x.as_i64().is_none_or(|n| n <= 0) {
                        return Err("invalid audit ID".into());
                    }
                    *x = json!("<audit-id>")
                } else {
                    normalize(x, request, policy, a, b, k)?;
                }
            }
        }
        Value::Array(xs) => {
            for x in xs {
                normalize(x, request, policy, a, b, key)?;
            }
        }
        Value::Number(_) => {
            if matches!(key, "id" | "request_id" | "target_id")
                && v.as_i64().is_some_and(|id| request.contains(&id))
            {
                let index = request
                    .iter()
                    .position(|id| Some(*id) == v.as_i64())
                    .unwrap();
                *v = if index == 0 {
                    json!("<request>")
                } else {
                    json!(format!("<request-{}>", index + 1))
                }
            } else if matches!(key, "winner_policy_id" | "policy_id") && *v == policy {
                *v = json!("<policy>")
            } else if matches!(
                key,
                "user_id" | "requester_user_id" | "approver_ref" | "requester"
            ) {
                *v = if *v == a.user {
                    json!("<requester>")
                } else if *v == b.user {
                    json!("<approver>")
                } else {
                    return Err("unrelated actor".into());
                }
            } else if key == "domain_id" {
                *v = if *v == a.domain {
                    json!("<domain>")
                } else if *v == b.domain {
                    json!("<approver-domain>")
                } else {
                    return Err("unexpected domain".into());
                }
            }
        }
        Value::String(s) => {
            if matches!(key, "created_at" | "expires_at" | "occurred_at") {
                chrono::DateTime::parse_from_rfc3339(s)?;
                *s = "<timestamp>".into()
            } else if key == "checksum" {
                if s.is_empty() {
                    return Err("empty audit checksum".into());
                }
                *s = "<checksum>".into()
            }
        }
        _ => {}
    }
    Ok(())
}
