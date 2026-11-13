//! Public HTTP and committed-effects seam for the approval request lifecycle.
use super::{body_bytes, full, send, BoxError};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{approvals::ApprovalsRoute, Config, Gateway, RouteTable, TrustedProxies};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

pub async fn cancel() -> Result<(), BoxError> {
    cancel_case("success").await
}

pub async fn cancel_case(kind: &str) -> Result<(), BoxError> {
    request_case("cancel", kind).await
}

pub async fn request_case(action: &str, kind: &str) -> Result<(), BoxError> {
    request_probe(action, kind, false).await
}
pub async fn request_probe(action: &str, kind: &str, mutant: bool) -> Result<(), BoxError> {
    request_fault(action, kind, mutant, None).await
}
pub async fn request_fault(
    action: &str,
    kind: &str,
    mutant: bool,
    fault: Option<&str>,
) -> Result<(), BoxError> {
    let Some(db) = Db::for_case("approval-cancel") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "appr1-requester").await?;
    let b = fixture::account(&owner, "appr1-approver").await?;
    let request:i64=owner.query_one("INSERT INTO approval_requests(consumer_type,requester_user_id,subject,payload,approver_kind,approver_ref,created_at,expires_at,domain_id) VALUES('hr.leave',$1,'Leave <one>','{\"reason\":\"trip\"}','user',$2,'2026-10-01T12:00:00Z','2099-11-01T12:00:00Z',$3) RETURNING id",&[&a.user,&b.user,&a.domain]).await?.get(0);
    if kind.starts_with("drive-access-") {
        owner
            .execute(
                "UPDATE approval_requests SET consumer_type='drive.access' WHERE id=$1",
                &[&request],
            )
            .await?;
    }
    if action == "email-post" {
        owner
            .execute(
                "UPDATE approval_requests SET consumer_type='rbac.jit_activation' WHERE id=$1",
                &[&request],
            )
            .await?;
    }
    let consumer = match kind {
        "consumer-rbac-deny" => Some("rbac.jit_activation"),
        "consumer-rbac-revoked" => Some("rbac.jit_activation"),
        "consumer-mail-deny" => Some("mail.external_send"),
        "consumer-group-approve" => Some("mail.group_moderation"),
        "consumer-drive-export" => Some("drive.export"),
        "consumer-drive-share" => Some("drive.share"),
        _ => None,
    };
    let space = if matches!(consumer, Some("drive.export" | "drive.share")) {
        Some(owner.query_one("INSERT INTO drive_spaces(name,owner_user_id) VALUES('appr1 approval space',$1) RETURNING id",&[&a.user]).await?.get::<_,i64>(0))
    } else {
        None
    };
    if let Some(consumer) = consumer {
        let payload = if let Some(space) = space {
            json!({"space_id":space,"version_id":123,"grantee":b.user}).to_string()
        } else {
            "{}".into()
        };
        owner
            .execute(
                "UPDATE approval_requests SET consumer_type=$2,payload=$3::text::jsonb WHERE id=$1",
                &[&request, &consumer, &payload],
            )
            .await?;
    }
    let receipts_before = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F10'",
            &[],
        )
        .await?
        .into_iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<std::collections::BTreeSet<_>>();
    let foreign = if (action == "decide" || action.starts_with("email-"))
        && matches!(kind, "foreign" | "visible-non-approver")
    {
        Some(fixture::account(&owner, "appr1-stranger").await?)
    } else {
        None
    };
    let role = if kind == "visible-non-approver" {
        let c = foreign.as_ref().expect("stranger");
        let id:i64=owner.query_one("INSERT INTO admin_role_groups(name,permissions) VALUES($1,ARRAY['approvals.view']) RETURNING id",&[&format!("appr1-viewer-{}",c.user)]).await?.get(0);
        owner.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$3)",&[&c.user,&id,&a.user]).await?;
        Some(id)
    } else {
        None
    };
    let caller = if kind == "requester-sod" {
        &a
    } else if let Some(c) = foreign.as_ref() {
        c
    } else if action == "decide" || action.starts_with("email-") || kind == "foreign" {
        &b
    } else {
        &a
    };
    let mut mailboxes = vec![a.mailbox, b.mailbox];
    if let Some(c) = foreign.as_ref() {
        mailboxes.push(c.mailbox);
    }
    let pattern = if action.starts_with("email-") {
        "/approvals/email/{token}".into()
    } else {
        format!("/me/approvals/{{id}}/{action}")
    };
    let mut email_token = sign_email(
        request,
        foreign.as_ref().map(|a| a.user).unwrap_or(b.user),
        "deny",
        4097179200,
    );
    if kind == "signature-crlf" {
        email_token.push_str("\r\n");
    }
    if kind == "signature-pad-bits" {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut bytes = email_token.into_bytes();
        let index = bytes.len() - 2;
        let value = alphabet
            .iter()
            .position(|b| *b == bytes[index])
            .ok_or("signature alphabet")?;
        if value % 4 != 0 {
            return Err("canonical signature has nonzero pad bits".into());
        }
        bytes[index] = alphabet[value + 1];
        email_token = String::from_utf8(bytes)?;
    }
    let method = if action == "email-get" { "GET" } else { "POST" };
    let request_body = if matches!(
        kind,
        "consumer-rbac-deny"
            | "consumer-mail-deny"
            | "consumer-drive-export"
            | "consumer-drive-share"
    ) {
        r#"{"decision":"deny","comment":"<trip>"}"#
    } else if kind == "drive-access-deny-missing" {
        r#"{"decision":"deny"}"#
    } else if kind == "null-body" {
        "null"
    } else if kind == "duplicates" {
        r#"{"decision":"deny","decision":"approve","decision":null,"comment":"<trip>"}"#
    } else if kind == "unknown-field" {
        r#"{"decision":"approve","unexpected":1}"#
    } else if kind == "trailing-json" {
        r#"{"decision":"approve"} {}"#
    } else if kind == "unicode-fold" {
        r#"{"deciſion":"approve","comment":"<trip>"}"#
    } else if kind == "folded-fields" {
        r#"{"DECISION":"approve","cOmMeNt":"<trip>"}"#
    } else if kind == "bad-decision" {
        r#"{"decision":"maybe"}"#
    } else if action == "decide" {
        r#"{"decision":"approve","comment":"<trip>"}"#
    } else {
        ""
    };
    let schema = fault.map(|_| format!("gofree_appr1_mutant_{request}"));
    let mut dsn = if matches!(fault, Some("no-tenant-filter" | "owner-baseline")) {
        db.dsn.clone()
    } else {
        db.app.as_deref().unwrap_or(&db.dsn).to_owned()
    };
    if let Some(schema) = &schema {
        let source =
            include_str!("../../../../../mailserver/sql/reducers/approval_request_cancel.sql");
        let mut source = source.replace(
            "FUNCTION approval_request_cancel(",
            &format!("FUNCTION {schema}.approval_request_cancel("),
        );
        match fault {
          Some("no-audit")=>{let start=source.find("  PERFORM audit_write(").ok_or("audit marker")?;let end=start+source[start..].find("  );").ok_or("audit end")?+4;source.replace_range(start..end,"");},
          Some("no-notify")=>{let start=source.find("  PERFORM app_notify(").ok_or("notify marker")?;let end=start+source[start..].find("::text);").ok_or("notify end")?+8;source.replace_range(start..end,"");},
          Some("no-tenant-filter")=>source=source.replace(" AND requester_user_id = p_actor",""),
          Some("double-bump")=>source=source.replace("  RETURN 'cancelled';","  UPDATE mailboxes SET jmap_email_state=jmap_email_state+2 WHERE user_id=p_actor;\n  RETURN 'cancelled';"),
          _=>{},
        }
        owner
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO setjoin_app; {source}"
            ))
            .await?;
        dsn.push_str(&format!(
            "{}options=-csearch_path%3D{schema}%2Cpublic",
            if dsn.contains('?') { "&" } else { "?" }
        ));
    }
    let projection_code = kind.strip_prefix("project-").filter(|s| {
        matches!(
            *s,
            "BZ001" | "BZ008" | "BZ002" | "BZ004" | "BZ141" | "BZ252" | "BZ253" | "BZ254" | "BZ256"
        )
    });
    let projection_schema = if let Some(code) = projection_code {
        let schema = format!("gofree_appr1_projection_{request}");
        let hint = if code == "BZ001" {
            r#"{"type":"over_quota"}"#
        } else {
            "{}"
        };
        owner.batch_execute(&format!("CREATE SCHEMA {schema}; CREATE FUNCTION {schema}.fail_update() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.id=TG_ARGV[0]::bigint THEN RAISE EXCEPTION 'private diagnostic must not reach client' USING ERRCODE=TG_ARGV[1],HINT=TG_ARGV[2]; END IF; RETURN NEW; END; $fault$; CREATE TRIGGER {schema} BEFORE UPDATE ON approval_requests FOR EACH ROW EXECUTE FUNCTION {schema}.fail_update('{request}','{code}','{hint}');")).await?;
        Some(schema)
    } else {
        None
    };
    let mut audit_ids = vec![];
    let result=async {
 let endpoint=super::fake_upstream(|_|async{hyper::Response::new(full(""))}).await;
 let oracle=super::go_oracle::start_named(&db,endpoint,None,"gofree-appr1-http").await?;
 let recording=oracle.is_some();
 let exec=ScopedExecutor::from_dsn(&dsn,4).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new());
 let adapter=ApprovalsRoute{exec,worker_exec:ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new()),keys:Arc::new(super::recovery_keys()),issuer:"mailserver".into(),secret:b"blobs1-test-jwt-secret-for-recording".to_vec()};
 let mut inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;
 for r in inventory["routes"].as_array_mut().ok_or("routes")?{if r["family"]=="F10"{r["state"]=json!(if recording{"OFF"}else{"ON"});r["upstream"]=json!(if recording{"go-mail"}else{"local-rust"});r["oracle_commands"]=json!([""]);}}
 let g=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},RouteTable::proxy_all().with(super::approval_probe::Probe{inner:adapter,changed_status:mutant}))?.with_inventory(&inventory.to_string())?;
 let socket=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let addr=socket.local_addr()?;let server=tokio::spawn(g.serve(socket));
 let path=if action.starts_with("email-"){format!("/approvals/email/{}",if kind=="invalid"{"bad".into()}else{email_token.replace('\r',"%0D").replace('\n',"%0A")})}else if kind=="invalid" {format!("/api/me/approvals/not-id/{action}")}else{format!("/api/me/approvals/{request}/{action}")};
 if kind=="repeat" {
 let initial=send(addr,hyper::Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("x-request-id","gofree-appr1-oracle").header("authorization",format!("Bearer {}",super::recovery_token(caller.user))).body(full(request_body))?).await;
 let initial_status=initial.status();let initial_body=body_bytes(initial).await;if initial_status!=200{return Err(format!("initial cancellation failed: {initial_status}: {initial_body:?}").into());}
 }
 let before=rows(&owner,request,&mailboxes).await?;
 let last:i64=owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
 let mut notifications=db.listen("approval_decided").await?;

 let response=send(addr,hyper::Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("x-request-id","gofree-appr1-oracle").header("authorization",format!("Bearer {}",super::recovery_token(caller.user))).body(full(request_body))?).await;
 let status=response.status().as_u16();let mut headers=serde_json::Map::new();for name in response.headers().keys(){headers.insert(name.to_string(),json!(response.headers().get_all(name).iter().map(|v|v.to_str().map(str::to_string)).collect::<Result<Vec<_>,_>>()?));}
 let raw=String::from_utf8(body_bytes(response).await.to_vec())?;
 let body=raw.replace(&format!("/me/approvals/{request}/{action}"),&pattern).replace(&email_token,"<signed-token>");
 if let Some(date)=headers.get_mut("date"){if date[0].as_str().is_none_or(|s|chrono::DateTime::parse_from_rfc2822(s).is_err()){return Err("invalid HTTP date".into());}*date=json!(["<timestamp>"]);}
 if let Some(length)=headers.get_mut("content-length"){if length[0]!=raw.len().to_string(){return Err("incorrect HTTP content length".into());}*length=json!([body.len().to_string()]);}
 let after=rows(&owner,request,&mailboxes).await?;
 let mut effects=vec![];
 for (table,old) in before.as_object().ok_or("snapshot")?{if old!=&after[table]{effects.push(json!({"table":table,"before":old,"after":after[table]}));}}
 let audit_rows=owner.query("SELECT id,to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id",&[&last]).await?;
 let mut audits=vec![];for row in audit_rows{audit_ids.push(row.get::<_,i64>(0));audits.push(serde_json::from_str::<Value>(&row.get::<_,String>(1))?);}
 let mut notify=vec![];for payload in notifications.drain(&owner).await?{notify.push(serde_json::from_str::<Value>(&payload)?);}
 let mut observation=json!({"request":{"method":method,"path":pattern,"external_path":if action.starts_with("email-"){pattern.clone()}else{format!("/api{pattern}")},"body":request_body},"response":{"status":status,"headers":headers,"body":body},"effects":effects,"audit":audits,"notify":notify});
 if let Some(space)=space {
  let mut audit=vec![];for row in owner.query("SELECT to_jsonb(a)::text FROM drive_audit_log a WHERE space_id=$1 ORDER BY id",&[&space]).await?{let mut value:Value=serde_json::from_str(&row.get::<_,String>(0))?;value["space_id"]=json!("<space>");if value["target_id"]==b.user&&value["target_type"]=="user"{value["target_id"]=json!("<approver>");}audit.push(value);}
  observation["drive_audit"]=json!(audit);
  for effect in observation["effects"].as_array_mut().ok_or("effects")?{if effect["table"]=="approval_requests"{for stage in ["before","after"]{let payload=&mut effect[stage]["payload"];if payload["space_id"]!=space{return Err("unbound drive space".into())}payload["space_id"]=json!("<space>");}}}
 }
 normalize(&mut observation,request,&a,&b)?;
 if !recording{super::approval_probe::no_go(addr).await?;}
 server.abort();
 let dir=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/approvals/goldens");
 let label=if action=="cancel"&&kind=="success" {"success-qualified"}else{kind};let file=dir.join(format!("{action}-{label}.json"));let row_file=dir.join(format!("{action}-{label}-row-effects.json"));
 if recording {if status!=if let Some(code)=projection_code {match code{"BZ002"|"BZ253"=>403,"BZ001"|"BZ004"=>507,"BZ008"=>500,"BZ141"=>422,"BZ252"=>400,_=>409}}else if kind=="consumer-rbac-revoked"{409}else if kind=="drive-access-deny-missing"{500}else if kind=="drive-access-invalid"{422}else if action=="email-post"&&kind=="repeat"{200}else if action.starts_with("email-")&&kind=="foreign"{if action=="email-get"{400}else{200}}else if kind=="visible-non-approver"{403}else if matches!(kind,"repeat"|"requester-sod")&&action=="decide"{409}else if matches!(kind,"foreign"|"repeat"){404}else if matches!(kind,"invalid"|"bad-decision"|"null-body"|"unknown-field"|"trailing-json"){400}else{200}{return Err(format!("Go cancellation status {status}: {raw}").into());}let source=std::env::var("GOFREE_GO_SOURCE")?;golden::record(&file,&json!({"format":1,"route":format!("{method} {pattern}"),"case":kind,"go_source":source,"observation":observation}))?;golden::record(&row_file,&json!({"format":1,"route":format!("{method} {pattern}"),"case":format!("{kind}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
 }else{let expected:Value=serde_json::from_slice(&std::fs::read(file)?)?;golden::compare(&expected["observation"],&observation)?;let rows:Value=serde_json::from_slice(&std::fs::read(row_file)?)?;golden::compare(&rows["effects"],&observation["effects"])?;eprintln!("GOLDEN-REPLAY: {method} {pattern} :: {kind}");}
 Ok::<_,BoxError>(())
 }.await;
    if let Some(schema) = projection_schema {
        owner
            .batch_execute(&format!(
                "DROP TRIGGER {schema} ON approval_requests; DROP SCHEMA {schema} CASCADE"
            ))
            .await?;
    }
    if let Some(schema) = schema {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    owner
        .execute("DELETE FROM approval_requests WHERE id=$1", &[&request])
        .await?;
    for row in owner
        .query(
            "SELECT id FROM admin_audit_log WHERE target_type='approval_request' AND target_id=$1",
            &[&request],
        )
        .await?
    {
        audit_ids.push(row.get(0));
    }
    audit_ids.sort();
    audit_ids.dedup();
    if !audit_ids.is_empty() {
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
    }
    for row in owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F10'",
            &[],
        )
        .await?
    {
        let id: String = row.get(0);
        if !receipts_before.contains(&id) {
            owner
                .execute(
                    "DELETE FROM rust_operation_receipts WHERE operation_id=$1::text::uuid",
                    &[&id],
                )
                .await?;
        }
    }
    if let Some(space) = space {
        owner
            .batch_execute("BEGIN; SET LOCAL session_replication_role=replica")
            .await?;
        owner
            .execute("DELETE FROM drive_audit_log WHERE space_id=$1", &[&space])
            .await?;
        owner.batch_execute("COMMIT").await?;
        owner
            .execute(
                "DELETE FROM drive_spaces WHERE id=$1 AND owner_user_id=$2",
                &[&space, &a.user],
            )
            .await?;
    }
    if let Some(role) = role {
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
    }
    super::remove_blob_account(&owner, &a).await?;
    super::remove_blob_account(&owner, &b).await?;
    if let Some(c) = foreign.as_ref() {
        super::remove_blob_account(&owner, c).await?;
    }
    result
}
async fn rows(c: &tokio_postgres::Client, id: i64, mailboxes: &[i64]) -> Result<Value, BoxError> {
    let request: Value = serde_json::from_str(
        &c.query_one(
            "SELECT to_jsonb(r)::text FROM approval_requests r WHERE id=$1",
            &[&id],
        )
        .await?
        .get::<_, String>(0),
    )?;
    let mut boxes = vec![];
    for row in c
        .query(
            "SELECT to_jsonb(m)::text FROM mailboxes m WHERE id=ANY($1) ORDER BY id",
            &[&mailboxes],
        )
        .await?
    {
        boxes.push(serde_json::from_str::<Value>(&row.get::<_, String>(0))?);
    }
    Ok(json!({"approval_requests":request,"mailboxes":boxes}))
}
fn normalize(
    v: &mut Value,
    request: i64,
    a: &fixture::Account,
    b: &fixture::Account,
) -> Result<(), BoxError> {
    fn walk(
        v: &mut Value,
        key: &str,
        request: i64,
        a: &fixture::Account,
        b: &fixture::Account,
    ) -> Result<(), BoxError> {
        match v {
            Value::Object(map) => {
                let is_audit = map.contains_key("checksum");
                let is_request = map.contains_key("consumer_type");
                let is_mailbox = map.contains_key("jmap_email_state");
                for (k, x) in map {
                    if k == "id" && is_audit {
                        if x.as_i64().is_none_or(|n| n <= 0) {
                            return Err("invalid audit ID".into());
                        }
                        *x = json!("<audit-id>");
                    } else if k == "id" && is_request {
                        if *x != request {
                            return Err("unexpected request ID".into());
                        }
                        *x = json!("<request>");
                    } else if k == "id" && is_mailbox {
                        *x = json!(if *x == a.mailbox {
                            "<requester-mailbox>"
                        } else if *x == b.mailbox {
                            "<approver-mailbox>"
                        } else {
                            return Err("foreign mailbox snapshot".into());
                        });
                    } else {
                        walk(x, k, request, a, b)?;
                    }
                }
            }
            Value::Array(xs) => {
                for x in xs {
                    walk(x, key, request, a, b)?;
                }
            }
            Value::Number(_) => {
                if matches!(key, "request_id" | "target_id") && *v == request {
                    *v = json!("<request>");
                } else if matches!(
                    key,
                    "user_id"
                        | "requester_user_id"
                        | "decided_by_user_id"
                        | "approver_ref"
                        | "requester"
                        | "grantee"
                ) {
                    if *v == a.user {
                        *v = json!("<requester>");
                    } else if *v == b.user {
                        *v = json!("<approver>");
                    } else {
                        return Err(format!("unexpected actor {key}: {v}").into());
                    }
                } else if key == "domain_id" {
                    *v = json!(if *v == a.domain {
                        "<requester-domain>"
                    } else if *v == b.domain {
                        "<approver-domain>"
                    } else {
                        return Err("unexpected domain".into());
                    });
                }
            }
            Value::String(s) => {
                if matches!(key, "checksum" | "prev_checksum" | "_checksum") {
                    if !s.is_empty() {
                        *s = "<checksum>".into();
                    }
                } else if matches!(
                    key,
                    "created_at" | "updated_at" | "decided_at" | "last_login_at" | "occurred_at"
                ) {
                    if s.is_empty() {
                        return Err("empty timestamp".into());
                    }
                    *s = "<timestamp>".into();
                }
            }
            _ => {}
        }
        Ok(())
    }
    walk(v, "", request, a, b)
}

pub fn sign_email(request: i64, user: i64, decision: &str, expiry: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE, Engine};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let payload = URL_SAFE.encode(format!(
        "{{\"r\":{request},\"a\":{user},\"d\":\"{decision}\",\"e\":{expiry}}}"
    ));
    let mut mac = Hmac::<Sha256>::new_from_slice(b"blobs1-test-jwt-secret-for-recording").unwrap();
    mac.update(payload.as_bytes());
    format!("{payload}.{}", URL_SAFE.encode(mac.finalize().into_bytes()))
}
