//! Member submission seam: policy-owned approval, no guest credential minted.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{guests::GuestsRoute, Config, Gateway, RouteTable, TrustedProxies};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;
pub async fn run(kind: &str) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let kind = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(db) = Db::for_case("guests-submit") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "guests1-member").await?;
    let b = fixture::account(&owner, "guests1-approver").await?;
    let flags = owner
        .query(
            "SELECT key,enabled FROM feature_toggles WHERE key=ANY($1)",
            &[&vec!["feature.guest_accounts", "approval.guest_invite"]],
        )
        .await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=true WHERE key=ANY($1)",
            &[&vec!["feature.guest_accounts", "approval.guest_invite"]],
        )
        .await?;
    let policy:i64=owner.query_one("INSERT INTO approval_policies(consumer_type,name,priority,conditions,approver_spec) VALUES('guest.invite',$1,9999,jsonb_build_object('host_domain_id',$2::bigint),jsonb_build_object('kind','named','user_id',$3::bigint)) RETURNING id",&[&format!("guests1-{}",a.user),&a.domain,&b.user]).await?.get(0);
    let last: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F11'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    if kind == "off" {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=false WHERE key='approval.guest_invite'",
                &[],
            )
            .await?;
    }
    if kind == "no-policy" {
        owner
            .execute(
                "UPDATE approval_policies SET enabled=false WHERE id=$1",
                &[&policy],
            )
            .await?;
    }
    let result=async{
  let s3=common::fake_upstream(|_|async{Response::new(common::full(""))}).await;
  let go=common::go_oracle::start_named(&db,s3,None,"gofree-guests1-http").await?;let recording=go.is_some();
  let adapter=GuestsRoute{exec:ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new()),worker:ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new()),keys:Arc::new(common::recovery_keys()),issuer:"mailserver".into(),lifecycle:None,delivery:None};
  let mut inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;for route in inventory["routes"].as_array_mut().ok_or("routes")?{if route["family"]=="F11"{route["state"]=json!(if recording{"OFF"}else{"ON"});route["upstream"]=json!(if recording{"go-mail"}else{"local-rust"});route["oracle_commands"]=json!([""]);}}
  let gateway=Gateway::new(Config{upstream:go.as_ref().map(|g|format!("http://{}",g.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},RouteTable::proxy_all().with(super::probe::Probe{inner:adapter,changed_status:mutant,unfiltered:false}))?.with_inventory(&inventory.to_string())?;
  let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let server=tokio::spawn(gateway.serve(listener));
  let foreign:String=owner.query_one("SELECT email FROM users WHERE id=$1",&[&b.user]).await?.get(0);
  let body=if kind=="invalid"{"{\"invitedEmail\":\"bad\"}".into()}else{json!({"invitedEmail":if kind=="foreign"{foreign.as_str()}else{"  New.Guest@Outside.Test  "},"message":"  Please review <guest>  "}).to_string()};
  let body=match kind{"bad-json"=>"{".into(),"trailing"=>format!("{body} {{}}"),_=>body};
  if kind=="repeat"{let response=common::send(address,Request::builder().method("POST").uri("/api/me/guest-invites").header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("authorization",format!("Bearer {}",common::recovery_token(a.user))).body(common::full(body.clone()))?).await;let status=response.status();let _=common::body_bytes(response).await;if status.as_u16()!=201{return Err("initial submit failed".into())}}
  let before=owner.query("SELECT to_jsonb(t)::text FROM approval_requests t WHERE requester_user_id=$1 ORDER BY id",&[&a.user]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?;
  let cursor:i64=owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
  let mut notifications=db.listen("approval_created").await?;
  let response=common::send(address,Request::builder().method("POST").uri("/api/me/guest-invites").header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("x-request-id","gofree-guests1-oracle").header("authorization",format!("Bearer {}",common::recovery_token(a.user))).body(common::full(body.clone()))?).await;
  let status=response.status().as_u16();let mut headers=serde_json::Map::new();for name in response.headers().keys(){headers.insert(name.to_string(),json!(response.headers().get_all(name).iter().map(|v|v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));}
  let raw=String::from_utf8(common::body_bytes(response).await.to_vec())?;
  let wanted=match kind{"bad-json"|"trailing"=>400,"off"=>404,"no-policy"=>422,"foreign"=>409,"invalid"=>400,_=>201};if recording&&status!=wanted{return Err(format!("Go submit expected {wanted}, got {status}: {raw}").into())}
  let rows=owner.query("SELECT to_jsonb(t)::text FROM approval_requests t WHERE requester_user_id=$1 ORDER BY id",&[&a.user]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?;
  let request=rows.last().and_then(|r|r["id"].as_i64()).unwrap_or(0);
  let audit=owner.query("SELECT to_jsonb(t)::text FROM admin_audit_log t WHERE id>$1 ORDER BY id",&[&cursor]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?;
  let notify=notifications.drain(&owner).await?.iter().map(|s|serde_json::from_str::<Value>(s)).collect::<Result<Vec<_>,_>>()?;
  let normalized=raw.replace(&format!("\"requestId\":{request}"),"\"requestId\":\"<request>\"");if let Some(date)=headers.get_mut("date"){chrono::DateTime::parse_from_rfc2822(date[0].as_str().ok_or("date")?)?;*date=json!(["<timestamp>"]);}if let Some(length)=headers.get_mut("content-length"){if length[0]!=raw.len().to_string(){return Err("bad wire length".into())}*length=json!([normalized.len().to_string()]);}
  let mut observation=json!({"request":{"method":"POST","path":"/me/guest-invites","external_path":"/api/me/guest-invites","body":body.replace(&foreign,"approver@host.test")},"response":{"status":status,"headers":headers,"body":normalized},"effects":[{"table":"approval_requests","before":before,"after":rows}],"audit":audit,"notify":notify});
  if kind=="repeat"{let first=observation["effects"][0]["before"][0]["id"].as_i64().ok_or("first request")?;prior_request(&mut observation,"",first);}
  normalize(&mut observation,"",a.user,b.user,a.domain,policy,request)?;
  if !recording{super::probe::no_go(address).await?;}server.abort();let dir=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/guests/goldens");let file=dir.join(format!("submit-{kind}.json"));let row_file=dir.join(format!("submit-{kind}-row-effects.json"));let route="POST /me/guest-invites";
  if recording{let source=std::env::var("GOFREE_GO_SOURCE")?;super::record(&file,&json!({"format":1,"route":route,"case":kind,"go_source":source,"observation":observation}))?;super::record(&row_file,&json!({"format":1,"route":route,"case":format!("{kind}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;}
  else{let expected:Value=serde_json::from_slice(&std::fs::read(file)?)?;if mutant{super::probe::rejected(golden::compare(&expected["observation"],&observation).map_err(Into::into),&route)?;}else{golden::compare(&expected["observation"],&observation)?;}let expected:Value=serde_json::from_slice(&std::fs::read(row_file)?)?;golden::compare(&expected["effects"],&observation["effects"])?;eprintln!("GOLDEN-REPLAY: {route} :: {kind}");}Ok::<_,BoxError>(())
 }.await;
    owner
        .execute(
            "DELETE FROM approval_requests WHERE requester_user_id=$1",
            &[&a.user],
        )
        .await?;
    owner
        .execute("DELETE FROM approval_policies WHERE id=$1", &[&policy])
        .await?;
    owner
        .batch_execute("BEGIN;SET LOCAL session_replication_role=replica")
        .await?;
    owner
        .execute(
            "DELETE FROM admin_audit_log WHERE id>$1 AND user_id=$2",
            &[&last, &a.user],
        )
        .await?;
    owner.batch_execute("COMMIT").await?;
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F11' AND operation_id::text<>ALL($1)",&[&receipts]).await?;
    for row in flags {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                &[&row.get::<_, String>(0), &row.get::<_, bool>(1)],
            )
            .await?;
    }
    common::remove_blob_account(&owner, &b).await?;
    common::remove_blob_account(&owner, &a).await?;
    result
}
fn normalize(
    v: &mut Value,
    key: &str,
    a: i64,
    b: i64,
    d: i64,
    p: i64,
    r: i64,
) -> Result<(), BoxError> {
    match v {
        Value::Object(map) => {
            let audit = map.contains_key("checksum");
            let request = map.contains_key("consumer_type") && map.contains_key("approver_ref");
            for (k, x) in map {
                if k == "id" && audit {
                    if x.as_i64().is_none_or(|n| n <= 0) {
                        return Err("bad audit".into());
                    }
                    *x = json!("<audit>");
                } else if k == "id" && request && *x != "<previous-request>" {
                    if *x != r {
                        return Err("bad request ID".into());
                    }
                    *x = json!("<request>");
                } else {
                    normalize(x, k, a, b, d, p, r)?;
                }
            }
        }
        Value::Array(xs) => {
            for x in xs {
                normalize(x, key, a, b, d, p, r)?;
            }
        }
        Value::Number(_) => {
            let expected = match key {
                "user_id" | "requester_user_id" => Some((a, "<member>")),
                "approver_ref" => Some((b, "<approver>")),
                "domain_id" => Some((d, "<domain>")),
                "policy_id" => Some((p, "<policy>")),
                "target_id" | "requestId" | "request_id" => Some((r, "<request>")),
                _ => None,
            };
            if let Some((n, label)) = expected {
                if *v != n {
                    return Err(format!("unexpected {key}: {v}").into());
                }
                *v = json!(label);
            }
        }
        Value::String(s) => {
            if matches!(
                key,
                "created_at" | "updated_at" | "occurred_at" | "expires_at"
            ) {
                chrono::DateTime::parse_from_rfc3339(s)?;
                *s = "<timestamp>".into();
            } else if key == "checksum" {
                if s.is_empty() {
                    return Err("checksum".into());
                }
                *s = "<checksum>".into();
            }
        }
        _ => {}
    }
    Ok(())
}

fn prior_request(v: &mut Value, key: &str, id: i64) {
    match v {
        Value::Object(xs) => {
            let row = xs.contains_key("approver_ref");
            for (k, v) in xs {
                if k == "id" && row && *v == id {
                    *v = json!("<previous-request>")
                } else {
                    prior_request(v, k, id)
                }
            }
        }
        Value::Array(xs) => {
            for v in xs {
                prior_request(v, key, id)
            }
        }
        Value::Number(_) if matches!(key, "request_id" | "requestId" | "target_id") && *v == id => {
            *v = json!("<previous-request>")
        }
        _ => {}
    }
}
