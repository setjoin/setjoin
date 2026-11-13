//! Organization-wide guest allowlist, through authenticated HTTP and complete row effects.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{guests::GuestsRoute, Config, Gateway, RouteTable, TrustedProxies};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

pub async fn run(action: &str, kind: &str) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let kind = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(db) = Db::for_case("guests-domains") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "guests1-admin").await?;
    let b = fixture::account(&owner, "guests1-other").await?;
    let role:i64=owner.query_one("INSERT INTO admin_role_groups(name,permissions) VALUES($1,ARRAY['guests.view','guests.manage']) RETURNING id",&[&format!("guests1-{}",a.user)]).await?.get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
    let domain = format!("guests1-{}.outside.test", a.user);
    let other_email: String = owner
        .query_one("SELECT email FROM users WHERE id=$1", &[&b.user])
        .await?
        .get(0);
    let email: String = owner
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    let enabled: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'",
            &[],
        )
        .await?
        .get(0);
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=true WHERE key='feature.guest_accounts'",
            &[],
        )
        .await?;
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
    if action == "remove" {
        owner.execute("INSERT INTO guest_invite_domains(domain,host_domain_id,added_by,added_by_email) VALUES($1,$2,$3,$4)",&[&domain,&a.domain,&a.user,&email]).await?;
    }
    if kind == "off" {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=false WHERE key='feature.guest_accounts'",
                &[],
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
  let method=if action=="remove"{"DELETE"}else{"POST"};let pattern=if action=="remove"{"/admin/guest-invite-domains/{domain}"}else{"/admin/guest-invite-domains"};let path=if action=="remove"{format!("/admin/guest-invite-domains/{}",if kind=="invalid"{"-bad.test"}else{&domain})}else{pattern.into()};let body=if kind=="invalid"{json!({"domain":"-bad.test"}).to_string()}else{json!({"domain":format!("  {}  ",domain.to_uppercase())}).to_string()};
  let body=if kind=="bad-json"{"{".into()}else{body};
  if kind=="repeat"{let response=common::send(address,Request::builder().method(method).uri(format!("/api{path}")).header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("authorization",format!("Bearer {}",super::admin_token(a.user))).body(common::full(body.clone()))?).await;let status=response.status();let _=common::body_bytes(response).await;if status.as_u16()!=if action=="remove"{204}else{201}{return Err("initial domain operation failed".into())}}
  let before=rows(&owner,&domain).await?;let state_before=states(&owner,&[a.mailbox,b.mailbox]).await?;
  let cursor:i64=owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
  let response=common::send(address,Request::builder().method(method).uri(format!("/api{path}")).header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("x-request-id","gofree-guests1-oracle").header("authorization",format!("Bearer {}",super::admin_token(if kind=="foreign"{b.user}else{a.user}))).body(common::full(body.clone()))?).await;
  let status=response.status().as_u16();let mut headers=serde_json::Map::new();for name in response.headers().keys(){headers.insert(name.to_string(),json!(response.headers().get_all(name).iter().map(|v|v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));}
  let raw=String::from_utf8(common::body_bytes(response).await.to_vec())?;let after=rows(&owner,&domain).await?;
  let expected=if kind=="off"{404}else if kind=="foreign"{403}else if matches!(kind,"invalid"|"bad-json"){400}else if action=="remove"{204}else{201};
  if recording&&status!=expected{return Err(format!("Go domain {action} expected 201 got {status}: {raw}").into())}
  let audit=owner.query("SELECT to_jsonb(t)::text FROM admin_audit_log t WHERE id>$1 ORDER BY id",&[&cursor]).await?.iter().map(|r|serde_json::from_str(&r.get::<_,String>(0))).collect::<Result<Vec<Value>,_>>()?;
  let normalized=raw.replace(&domain,"invite.test");if let Some(date)=headers.get_mut("date"){chrono::DateTime::parse_from_rfc2822(date[0].as_str().ok_or("date")?)?;*date=json!(["<timestamp>"]);}if let Some(length)=headers.get_mut("content-length"){if length[0]!=raw.len().to_string(){return Err("bad wire length".into())}*length=json!([normalized.len().to_string()]);}
  let mut observation=json!({"request":{"method":method,"path":pattern,"external_path":format!("/api{pattern}"),"body":body.replace(&domain.to_uppercase(),"INVITE.TEST")},"response":{"status":status,"headers":headers,"body":normalized},"effects":[{"table":"guest_invite_domains","before":before,"after":after},{"table":"mailbox_state","before":state_before,"after":states(&owner,&[a.mailbox,b.mailbox]).await?}],"audit":audit,"notify":[]});
  normalize(&mut observation,"",&domain,&email,&a,&b)?;replace(&mut observation,&other_email);
  if !recording{super::probe::no_go(address).await?;}server.abort();let route=format!("{method} {pattern}");let dir=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/guests/goldens");let file=dir.join(format!("domain-{action}-{kind}.json"));let row_file=dir.join(format!("domain-{action}-{kind}-row-effects.json"));
  if recording{let source=std::env::var("GOFREE_GO_SOURCE")?;super::record(&file,&json!({"format":1,"route":route,"case":kind,"go_source":source,"observation":observation}))?;super::record(&row_file,&json!({"format":1,"route":route,"case":format!("{kind}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;}
  else{let expected:Value=serde_json::from_slice(&std::fs::read(file)?)?;if mutant{super::probe::rejected(golden::compare(&expected["observation"],&observation).map_err(Into::into),&route)?;}else{golden::compare(&expected["observation"],&observation)?;}let expected:Value=serde_json::from_slice(&std::fs::read(row_file)?)?;golden::compare(&expected["effects"],&observation["effects"])?;eprintln!("GOLDEN-REPLAY: {route} :: {kind}");}Ok::<_,BoxError>(())
 }.await;
    owner
        .execute(
            "DELETE FROM guest_invite_domains WHERE domain=$1",
            &[&domain],
        )
        .await?;
    owner
        .batch_execute("BEGIN;SET LOCAL session_replication_role=replica")
        .await?;
    owner
        .execute("DELETE FROM admin_audit_log WHERE id>$1", &[&last])
        .await?;
    owner.batch_execute("COMMIT").await?;
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F11' AND operation_id::text<>ALL($1)",&[&receipts]).await?;
    owner.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 hour' WHERE role_group_id=$1",&[&role]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&role],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'",
            &[&enabled],
        )
        .await?;
    common::remove_blob_account(&owner, &b).await?;
    common::remove_blob_account(&owner, &a).await?;
    result
}
async fn rows(c: &tokio_postgres::Client, domain: &str) -> Result<Vec<Value>, BoxError> {
    c.query(
        "SELECT to_jsonb(t)::text FROM guest_invite_domains t WHERE domain=$1",
        &[&domain],
    )
    .await?
    .iter()
    .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
    .collect()
}
async fn states(c: &tokio_postgres::Client, ids: &[i64]) -> Result<Vec<Value>, BoxError> {
    c.query("SELECT jsonb_build_object('mailbox',id,'email',jmap_email_state,'tags',jmap_mailbox_state)::text FROM mailboxes WHERE id=ANY($1) ORDER BY id",&[&ids]).await?.iter().map(|r|serde_json::from_str(&r.get::<_,String>(0)).map_err(Into::into)).collect()
}
fn normalize(
    v: &mut Value,
    key: &str,
    domain: &str,
    email: &str,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<(), BoxError> {
    match v {
        Value::Object(map) => {
            let audit = map.contains_key("checksum");
            for (k, x) in map {
                if k == "id" && audit {
                    if x.as_i64().is_none_or(|n| n <= 0) {
                        return Err("bad audit ID".into());
                    }
                    *x = json!("<audit>");
                } else {
                    normalize(x, k, domain, email, a, b)?;
                }
            }
        }
        Value::Array(xs) => {
            for x in xs {
                normalize(x, key, domain, email, a, b)?;
            }
        }
        Value::Number(_) => {
            if matches!(key, "added_by" | "user_id") {
                if *v != a.user {
                    return Err("forged domain actor".into());
                }
                *v = json!("<admin>");
            } else if key == "host_domain_id" {
                if *v != a.domain {
                    return Err("forged domain owner".into());
                }
                *v = json!("<domain>");
            } else if key == "mailbox" {
                *v = if *v == a.mailbox {
                    json!("<admin-mailbox>")
                } else if *v == b.mailbox {
                    json!("<other-mailbox>")
                } else {
                    return Err("foreign state".into());
                };
            }
        }
        Value::String(s) => {
            if matches!(key, "created_at" | "occurred_at") {
                chrono::DateTime::parse_from_rfc3339(s)?;
                *s = "<timestamp>".into();
            } else if key == "checksum" {
                if s.is_empty() {
                    return Err("empty checksum".into());
                }
                *s = "<checksum>".into();
            } else if key == "added_by_email" {
                if s != email {
                    return Err("unbound actor email".into());
                }
                *s = "admin@host.test".into();
            } else {
                *s = s.replace(domain, "invite.test");
            }
        }
        _ => {}
    }
    Ok(())
}

fn replace(v: &mut Value, email: &str) {
    match v {
        Value::String(s) => *s = s.replace(email, "other@host.test"),
        Value::Object(xs) => {
            for x in xs.values_mut() {
                replace(x, email)
            }
        }
        Value::Array(xs) => {
            for x in xs {
                replace(x, email)
            }
        }
        _ => {}
    }
}
