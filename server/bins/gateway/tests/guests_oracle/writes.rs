//! Observe committed effects at the public HTTP seam, independently of the domain crate.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{guests::GuestsRoute, Config, Gateway, RouteTable, TrustedProxies};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

pub async fn run(action: &str, kind: &str) -> Result<(), BoxError> {
    run_fault(action, kind, None).await
}
pub async fn run_fault(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let kind = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let label = kind;
    let kind = kind.strip_suffix("-qualified").unwrap_or(kind);
    let Some(mut db) = Db::for_case("guests-write") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "guests1-admin").await?;
    let b = fixture::account(&owner, "guests1-other").await?;
    let role:i64=owner.query_one("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,ARRAY['guests.view','guests.manage'],$2) RETURNING id",&[&format!("guests1-{}",a.user),&a.domain]).await?.get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
    let profile:i64=owner.query_one("INSERT INTO guest_profiles(host_domain_id,name,apps,created_at,updated_at) VALUES($1,'Profile <one>',ARRAY['chat'],'2026-10-01T12:00:00Z','2026-10-01T12:00:00Z') RETURNING id",&[&a.domain]).await?.get(0);
    if kind == "foreign" {
        owner
            .execute(
                "UPDATE admin_role_groups SET domain_scope=$2 WHERE id=$1",
                &[&role, &b.domain],
            )
            .await?;
    }
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
    let audit_start: i64 = owner
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
    let schema = format!("gofree_guests1_fault_{}", a.user);
    if let Some(fault) = fault {
        let body=match fault{
            "no-audit"=>format!("IF NEW.user_id={} THEN RETURN NULL; END IF; RETURN NEW;",a.user),
            "double-bump"=>format!("IF NEW.host_domain_id={} THEN UPDATE mailboxes SET jmap_email_state=jmap_email_state+2 WHERE id={}; END IF; RETURN NEW;",a.domain,a.mailbox),
            _=>return Err("unknown profile fault".into()),
        };
        let (table, timing) = if fault == "no-audit" {
            ("admin_audit_log", "BEFORE")
        } else {
            ("guest_profiles", "AFTER")
        };
        owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN {body} END $fault$;CREATE TRIGGER {schema} {timing} INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION {schema}.fault();")).await?;
    }
    if kind == "read-fault" {
        owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.guest_profile_get(bigint,bigint) RETURNS jsonb LANGUAGE plpgsql AS $fault$ BEGIN RAISE EXCEPTION 'private fixture diagnostic' USING ERRCODE='P0001'; END $fault$;")).await?;
        db.dsn.push_str(&format!(
            "{}options=-csearch_path%3D{schema}%2Cpublic",
            if db.dsn.contains('?') { "&" } else { "?" }
        ));
    }
    let result=async {
        let s3=common::fake_upstream(|_|async{Response::new(common::full(""))}).await;
        let go=common::go_oracle::start_named(&db,s3,None,"gofree-guests1-http").await?;
        let recording=go.is_some();
        let exec=ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new());
        let worker=ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new());
        let adapter=GuestsRoute{exec,worker,keys:Arc::new(common::recovery_keys()),issuer:"mailserver".into(),lifecycle:None,delivery:None};
        let mut inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for route in inventory["routes"].as_array_mut().ok_or("routes")? {if route["family"]=="F11"{route["state"]=json!(if recording{"OFF"}else{"ON"});route["upstream"]=json!(if recording{"go-mail"}else{"local-rust"});route["oracle_commands"]=json!([""]);}}
        let gateway=Gateway::new(Config{upstream:go.as_ref().map(|g|format!("http://{}",g.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},RouteTable::proxy_all().with(super::probe::Probe{inner:adapter,changed_status:mutant,unfiltered:false}))?.with_inventory(&inventory.to_string())?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let server=tokio::spawn(gateway.serve(listener));
        let (method,pattern)=if action=="profile-delete"{("DELETE","/admin/guest-profiles/{id}")}else if action=="profile-update"{("PUT","/admin/guest-profiles/{id}")}else{("POST","/admin/guest-profiles")};
        let path=pattern.replace("{id}",&if kind=="invalid"{"bad".into()}else{profile.to_string()});
        let mut body=json!({"hostDomainId":a.domain,"name":"Created <one>","canPost":false,"historyFromJoin":true,"allowDownload":false,"allowMeetCreate":false,"allowMeetHost":false,"canInitiateDm":false,"allowNativeShell":true,"defaultExpiryDays":null,"apps":["chat","meet"]}).to_string();
        if action=="profile-delete"{body.clear();}
        if kind=="invalid"{body="{}".into();}
        match kind{
            "missing-days"=>body=body.replace("\"defaultExpiryDays\":null,",""),
            "missing-apps"=>body=body.replace("\"apps\":[\"chat\",\"meet\"],",""),
            "null-apps"=>body=body.replace("[\"chat\",\"meet\"]","null"),
            "bad-host"=>body=body.replace(&format!("\"hostDomainId\":{}",a.domain),"\"hostDomainId\":0"),
            "bad-apps"=>body=body.replace("[\"chat\",\"meet\"]","42"),
            "surrogate"=>body=body.replace("Created <one>",r"Created \ud800"),
            "raw-days"=>body=body.replace("\"defaultExpiryDays\":null","\"defaultExpiryDays\":1e400"),
            "folded"=>for key in ["hostDomainId","name","canPost","historyFromJoin","allowDownload","allowMeetCreate","allowMeetHost","canInitiateDm","allowNativeShell","defaultExpiryDays","apps"]{body=body.replace(&format!("\"{key}\""),&format!("\"{}\"",key.to_uppercase()));},
            "null-duplicate"=>body=format!("{},\"canPost\":null}}",body.trim_end_matches('}')),
            "primitive-null"=>body=format!("{},\"hostDomainId\":null}}",body.trim_end_matches('}')),
            "trailing"=>body.push_str(" {}"),
            "unknown"=>body=format!("{},\"actorUserId\":424242}}",body.trim_end_matches('}')),
            _=>{}
        }
        if kind=="repeat"{let response=request(address,method,&path,&body,a.user).await?;let status=response.status();let data=common::body_bytes(response).await;if status.as_u16()!=(if action=="profile-create"{201}else if action=="profile-delete"{204}else{200}){return Err(format!("initial {action}: {status} {data:?}").into())}}
        let before=profiles(&owner,a.domain).await?;
        let states_before=states(&owner,&[a.mailbox,b.mailbox]).await?;
        let last:i64=owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
        let mut revoked=db.listen("session_revoke").await?;
        let response=common::send(address,Request::builder().method(method).uri(format!("/api{path}")).header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("x-request-id","gofree-guests1-oracle").header("authorization",format!("Bearer {}",super::admin_token(a.user))).body(common::full(body.clone()))?).await;
        let status=response.status().as_u16();
        let mut headers=serde_json::Map::new();
        for name in response.headers().keys(){headers.insert(name.to_string(),json!(response.headers().get_all(name).iter().map(|v|v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));}
        let raw=String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let after=profiles(&owner,a.domain).await?;
        let new=after.iter().filter_map(|r|r["id"].as_i64()).filter(|n|*n!=profile).collect::<Vec<_>>();
        let wanted=match kind{"read-fault"=>500,"missing-days"|"missing-apps"|"null-apps"|"bad-host"|"bad-apps"|"raw-days"|"null-duplicate"|"trailing"|"unknown"=>400,"foreign"=>404,"invalid"=>400,"repeat" if action=="profile-create"=>422,"repeat" if action=="profile-delete"=>404,_ if action=="profile-create"=>201,_ if action=="profile-delete"=>204,_=>200};
        if recording && status!=wanted{return Err(format!("Go {action} expected {wanted}, got {status}: {raw}").into())}
        if status==201 && serde_json::from_str::<Value>(&raw)?["id"].as_i64()!=new.last().copied(){return Err("profile response is unrelated to committed effect".into())}
        let mut audit=owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id",&[&last]).await?.iter().map(|r|serde_json::from_str(&r.get::<_,String>(0))).collect::<Result<Vec<Value>,_>>()?;
        let after_states=states(&owner,&[a.mailbox,b.mailbox]).await?;
        let mut before=json!(before);let mut after=json!(after);let mut before_states=json!(states_before);let mut after_states=json!(after_states);
        normalize(&mut before,"",profile,&new,&a,&b)?;normalize(&mut after,"",profile,&new,&a,&b)?;
        normalize(&mut before_states,"state",profile,&new,&a,&b)?;normalize(&mut after_states,"state",profile,&new,&a,&b)?;
        for row in &mut audit {normalize(row,"audit",profile,&new,&a,&b)?;}
        let mut normalized_body=raw.replace(&format!("\"id\":{profile}"),"\"id\":\"<profile>\"").replace(&format!("/{profile}\""),"/<profile>\"");
        for n in &new{normalized_body=normalized_body.replace(&format!("\"id\":{n}"),"\"id\":\"<created-profile>\"");}
        normalized_body=normalized_body.replace(&format!("\"hostDomainId\":{}",a.domain),"\"hostDomainId\":\"<domain>\"");
        if let Ok(parsed)=serde_json::from_str::<Value>(&raw){for key in ["createdAt","updatedAt"]{if let Some(value)=parsed[key].as_str(){chrono::DateTime::parse_from_rfc3339(value)?;if !value.starts_with("2026-10-01T12:00:00"){normalized_body=normalized_body.replace(&serde_json::to_string(value)?,"\"<timestamp>\"");}}}}
        if let Some(date)=headers.get_mut("date"){chrono::DateTime::parse_from_rfc2822(date[0].as_str().ok_or("date")?)?;*date=json!(["<timestamp>"]);}
        if let Some(length)=headers.get_mut("content-length"){if length[0]!=raw.len().to_string(){return Err("bad wire length".into())}*length=json!([normalized_body.len().to_string()]);}
        let mut notify=vec![];for event in revoked.drain(&owner).await?{notify.push(json!({"channel":"session_revoke","payload":serde_json::from_str::<Value>(&event)?}));}
        let effects=json!([{"table":"guest_profiles","before":before,"after":after},{"table":"mailbox_state","before":before_states,"after":after_states}]);
        let observation=json!({"request":{"method":method,"path":pattern,"external_path":format!("/api{pattern}"),"body":body.replace(&format!("\"HOSTDOMAINID\":{}",a.domain),"\"HOSTDOMAINID\":\"<domain>\"").replace(&format!("\"hostDomainId\":{}",a.domain),"\"hostDomainId\":\"<domain>\"")},"response":{"status":status,"headers":headers,"body":normalized_body},"effects":effects,"audit":audit,"notify":notify});
        if !recording{super::probe::no_go(address).await?;}server.abort();
        let route=format!("{method} {pattern}");let dir=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/guests/goldens");let file=dir.join(format!("{action}-{label}.json"));let row_file=dir.join(format!("{action}-{label}-row-effects.json"));
        if recording {let source=std::env::var("GOFREE_GO_SOURCE")?;super::record(&file,&json!({"format":1,"route":route,"case":label,"go_source":source,"observation":observation}))?;super::record(&row_file,&json!({"format":1,"route":route,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;}
        else {let expected:Value=serde_json::from_slice(&std::fs::read(file)?)?;if mutant{super::probe::rejected(golden::compare(&expected["observation"],&observation).map_err(Into::into),&route)?;}else{golden::compare(&expected["observation"],&observation)?;}let expected:Value=serde_json::from_slice(&std::fs::read(row_file)?)?;golden::compare(&expected["effects"],&observation["effects"])?;eprintln!("GOLDEN-REPLAY: {route} :: {label}");}
        Ok::<_,BoxError>(())
    }.await;
    if kind == "read-fault" {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    if fault.is_some() {
        let table = if fault == Some("no-audit") {
            "admin_audit_log"
        } else {
            "guest_profiles"
        };
        owner
            .batch_execute(&format!(
                "DROP TRIGGER {schema} ON {table};DROP SCHEMA {schema} CASCADE"
            ))
            .await?;
    }
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica")
        .await?;
    owner
        .execute(
            "DELETE FROM admin_audit_log WHERE id>$1 AND user_id=$2",
            &[&audit_start, &a.user],
        )
        .await?;
    owner.batch_execute("COMMIT").await?;
    owner
        .execute(
            "DELETE FROM guest_profiles WHERE host_domain_id=$1",
            &[&a.domain],
        )
        .await?;
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
    common::remove_blob_account(&owner, &a).await?;
    common::remove_blob_account(&owner, &b).await?;
    result
}
async fn profiles(c: &tokio_postgres::Client, domain: i64) -> Result<Vec<Value>, BoxError> {
    c.query(
        "SELECT to_jsonb(p)::text FROM guest_profiles p WHERE host_domain_id=$1 ORDER BY id",
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
    profile: i64,
    new: &[i64],
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<(), BoxError> {
    match v {
        Value::Object(map) => {
            let audit = map.contains_key("checksum");
            for (k, x) in map {
                if k == "id" && audit {
                    if x.as_i64().is_none_or(|id| id <= 0) {
                        return Err("invalid audit id".into());
                    }
                    *x = json!("<audit>");
                } else {
                    normalize(x, k, profile, new, a, b)?;
                }
            }
        }
        Value::Array(xs) => {
            for x in xs {
                normalize(x, key, profile, new, a, b)?;
            }
        }
        Value::Number(_) => {
            if matches!(key, "id" | "target_id") {
                let id = v.as_i64().ok_or("id")?;
                *v = if id == profile {
                    json!("<profile>")
                } else if new.contains(&id) {
                    json!("<created-profile>")
                } else {
                    return Err(format!("unexpected profile id {id}").into());
                };
            } else if matches!(key, "host_domain_id" | "hostDomainId") {
                if *v != a.domain {
                    return Err("foreign domain effect".into());
                }
                *v = json!("<domain>");
            } else if key == "user_id" {
                if *v != a.user {
                    return Err("forged audit actor".into());
                }
                *v = json!("<admin>");
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
            if matches!(key, "created_at" | "updated_at" | "occurred_at") {
                chrono::DateTime::parse_from_rfc3339(s)?;
                if !s.starts_with("2026-10-01T12:00:00") {
                    *s = "<timestamp>".into();
                }
            } else if matches!(key, "checksum" | "prev_checksum") {
                if s.is_empty() {
                    return Err("empty checksum".into());
                }
                *s = "<checksum>".into();
            }
        }
        _ => {}
    }
    Ok(())
}

async fn request(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: &str,
    user: i64,
) -> Result<Response<hyper::body::Incoming>, BoxError> {
    Ok(common::send(
        address,
        Request::builder()
            .method(method)
            .uri(format!("/api{path}"))
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("content-type", "application/json")
            .header("x-request-id", "gofree-guests1-oracle")
            .header(
                "authorization",
                format!("Bearer {}", super::admin_token(user)),
            )
            .body(common::full(body.to_owned()))?,
    )
    .await)
}
