//! Frozen-Go admin approval HTTP seam, with live governed grants.
use super::{body_bytes, full, send, BoxError};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{approvals::ApprovalsRoute, Config, Gateway, RouteTable, TrustedProxies};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

pub async fn policies_list() -> Result<(), BoxError> {
    policies_case("list", "success").await
}
pub async fn policies_list_case(kind: &str) -> Result<(), BoxError> {
    policies_case("list", kind).await
}

pub async fn policies_case(action: &str, kind: &str) -> Result<(), BoxError> {
    policies_probe(action, kind, false).await
}
pub async fn policies_probe(action: &str, kind: &str, mutant: bool) -> Result<(), BoxError> {
    let label = kind;
    let kind = kind.strip_suffix("-qualified").unwrap_or(kind);
    let Some(db) = Db::for_case("approval-admin") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "appr1-admin").await?;
    let b = fixture::account(&owner, "appr1-member").await?;
    let role: i64 = owner.query_one(
        "INSERT INTO admin_role_groups(name,permissions) VALUES($1,ARRAY['approvals.view','approvals.manage']) RETURNING id",
        &[&format!("appr1-admin-{}", a.user)],
    ).await?.get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
    let spec = json!({"kind":"named","user_id":b.user}).to_string();
    let policy: i64 = owner.query_one(
        "INSERT INTO approval_policies(consumer_type,name,enabled,priority,conditions,requires_approval,approver_spec,created_at,updated_at) VALUES('hr.leave','Policy <one>',true,1,'{}',true,$1::text::jsonb,'2026-10-01T12:00:00Z','2026-10-01T12:00:00Z') RETURNING id", &[&spec],
    ).await?.get(0);
    let audit_request = if action == "audit" {
        owner
            .execute(
                "UPDATE admin_role_groups SET domain_scope=$2 WHERE id=$1",
                &[&role, &a.domain],
            )
            .await?;
        Some(owner.query_one("INSERT INTO approval_requests(consumer_type,requester_user_id,subject,payload,approver_kind,approver_ref,created_at,expires_at,domain_id) VALUES('hr.leave',$1,'Leave <audit>','{}','user',$2,'2026-10-01T12:00:00Z','2099-11-01T12:00:00Z',$3) RETURNING id",&[&a.user,&b.user,&a.domain]).await?.get::<_,i64>(0))
    } else {
        None
    };
    let caller = if kind == "foreign" { &b } else { &a };
    let query = if action == "audit" {
        if kind == "invalid" {
            "limit=bad&offset=-1"
        } else {
            "limit=50&offset=0"
        }
    } else if action != "list" {
        ""
    } else if kind == "invalid" {
        "consumer_type=identity.transition"
    } else {
        "consumer_type=hr.leave"
    };
    let method = match action {
        "create" | "reorder" => "POST",
        "update" => "PUT",
        "delete" => "DELETE",
        _ => "GET",
    };
    let pattern = if matches!(action, "update" | "delete") {
        "/admin/approval-policies/{id}"
    } else if action == "reorder" {
        "/admin/approval-policies/reorder"
    } else if action == "audit" {
        "/admin/approval-requests/audit"
    } else {
        "/admin/approval-policies"
    };
    let external_pattern = pattern.replace(
        "{id}",
        &if kind == "invalid" {
            "bad".into()
        } else {
            policy.to_string()
        },
    );
    let created_name = format!("Created <two> gofree-appr1-{}", a.user);
    let request_body = if action == "create" {
        json!({"consumerType":"hr.leave","name":created_name,"enabled":true,"conditions":{"leave_type":"annual"},"requiresApproval":true,"approverSpec":{"kind":"named","user_id":b.user}}).to_string()
    } else if action == "update" {
        json!({"name":"Policy <updated>","enabled":false}).to_string()
    } else if action == "reorder" {
        json!({"consumerType":if kind=="invalid"{"bad"}else{"hr.leave"},"orderedIds":[policy]})
            .to_string()
    } else {
        String::new()
    };
    let request_body = if action == "create" && kind == "invalid" {
        json!({"consumerType":"hr.leave","name":created_name,"conditions":[],"approverSpec":{}})
            .to_string()
    } else {
        request_body
    };
    let fault_schema = if action == "create" && kind == "priority-conflict" {
        let schema = format!("gofree_appr1_policy_fault_{}", a.user);
        owner.batch_execute(&format!("CREATE SCHEMA {schema}; CREATE FUNCTION {schema}.fail_insert() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.name=TG_ARGV[0] THEN RAISE EXCEPTION 'deterministic concurrent priority collision' USING ERRCODE='23505'; END IF; RETURN NEW; END; $fault$; CREATE TRIGGER {schema} BEFORE INSERT ON approval_policies FOR EACH ROW EXECUTE FUNCTION {schema}.fail_insert('{created_name}');")).await?;
        Some(schema)
    } else {
        None
    };
    let receipts_before = receipt_ids(&owner).await?;
    let mut audit_ids = vec![];
    let result = async {
        let endpoint = super::fake_upstream(|_| async { hyper::Response::new(full("")) }).await;
        let oracle = super::go_oracle::start_named(&db, endpoint, None, "gofree-appr1-http").await?;
        let recording = oracle.is_some();
        let exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).map_err(|e|e.0)?.with_audit_keys("22".repeat(32), String::new());
        let route = ApprovalsRoute { exec, worker_exec: ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new()), keys: Arc::new(super::recovery_keys()), issuer:"mailserver".into(), secret:b"blobs1-test-jwt-secret-for-recording".to_vec() };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? { if r["family"]=="F10" { r["state"]=json!(if recording{"OFF"}else{"ON"}); r["upstream"]=json!(if recording{"go-mail"}else{"local-rust"}); r["oracle_commands"]=json!([""]); } }
        let gateway = Gateway::new(Config { upstream: oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?, trusted_proxies:TrustedProxies::parse("")?, upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT, edge_limit:None }, RouteTable::proxy_all().with(super::approval_probe::Probe{inner:route,changed_status:mutant}))?.with_inventory(&inventory.to_string())?;
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?;
        let server = tokio::spawn(gateway.serve(socket));
        let audit_start:i64=owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
        if kind=="repeat" {
            let first=send(address,hyper::Request::builder().method(method).uri(format!("/api{external_pattern}")).header("host","mail.test").header("origin","http://mail.test").header("x-request-id","gofree-appr1-oracle").header("authorization",format!("Bearer {}",admin_token(caller.user))).body(full(request_body.clone()))?).await;
            let status=first.status();let data=body_bytes(first).await;if status!=(if action=="create"{201}else{204}){return Err(format!("initial policy create failed: {status}: {data:?}").into())}
        }
        let before = policy_rows(&owner,policy,&created_name).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
        let mut created = db.listen("approval_created").await?;
        let mut decided = db.listen("approval_decided").await?;
        let uri = format!("/api{external_pattern}{}{}",if query.is_empty(){""}else{"?"},query);
        let mut builder = hyper::Request::builder().method(method).uri(uri).header("host","mail.test").header("x-request-id","gofree-appr1-oracle").header("authorization",format!("Bearer {}",admin_token(caller.user)));
        if method != "GET" { builder=builder.header("origin","http://mail.test").header("content-type","application/json"); }
        let response = send(address,builder.body(full(request_body.clone()))?).await;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() { headers.insert(name.to_string(),json!(response.headers().get_all(name).iter().map(|v|v.to_str().map(str::to_string)).collect::<Result<Vec<_>,_>>()?)); }
        let raw = String::from_utf8(body_bytes(response).await.to_vec())?;
        let after = policy_rows(&owner,policy,&created_name).await?;
        let new_ids = after.iter().filter_map(|r|r["id"].as_i64()).filter(|id|*id!=policy).collect::<Vec<_>>();
        if status==200 && action=="list" { let parsed:Value=serde_json::from_str(&raw)?; if parsed.as_array().is_none_or(|x|x.len()!=1)||parsed[0]["id"]!=policy||parsed[0]["approverSpec"]["user_id"]!=b.user { return Err(format!("unexpected policy projection: {parsed}").into()) } }
        if status==201 { let parsed:Value=serde_json::from_str(&raw)?; if parsed["id"].as_i64()!=new_ids.last().copied(){return Err("policy create returned an unrelated ID".into())} }
        let mut body=raw.replace(&format!("/api{external_pattern}"),&format!("/api{pattern}")).replace(&external_pattern,pattern).replace(&format!("\"user_id\":{}",b.user),"\"user_id\":\"<approver>\"");
        // Audit rows carry request IDs. Independent policy/request sequences
        // may coincide; never replace an audit request with a policy marker.
        if action != "audit" {
            body=body.replace(&format!("\"id\":{policy}"),"\"id\":\"<policy>\"");
        }
        for (index,id) in new_ids.iter().enumerate() { body=body.replace(&format!("\"id\":{id}"),&format!("\"id\":\"<created-policy-{}>\"",index+1)); }
        if let Some(id)=audit_request {body=body.replace(&format!("\"id\":{id}"),"\"id\":\"<request>\"").replace(&format!("\"requesterUserId\":{}",a.user),"\"requesterUserId\":\"<admin>\"").replace(&format!("\"approverRef\":{}",b.user),"\"approverRef\":\"<approver>\"");}
        normalize_headers(&mut headers,&raw,&body)?;
        let mut audit = vec![];
        for row in owner.query("SELECT id,to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id",&[&last]).await? { audit_ids.push(row.get::<_,i64>(0)); audit.push(serde_json::from_str::<Value>(&row.get::<_,String>(1))?); }
        let effects = if before==after { vec![] } else { vec![json!({"table":"approval_policies","before":before,"after":after})] };
        let mut notify = vec![];
        for (channel,listener) in [("approval_created",&mut created),("approval_decided",&mut decided)] { for payload in listener.drain(&owner).await? { notify.push(json!({"channel":channel,"payload":serde_json::from_str::<Value>(&payload)?})); } }
        let mut request=json!({"method":method,"path":pattern,"external_path":format!("/api{pattern}"),"query":query});
        if !matches!(action,"list"|"audit") { request["body"]=json!(request_body.replace(&format!("\"orderedIds\":[{policy}]"),"\"orderedIds\":[\"<policy>\"]").replace(&created_name,"Created <two>").replace(&format!("\"user_id\":{}",b.user),"\"user_id\":\"<approver>\"")); }
        let mut observation=json!({"request":request,"response":{"status":status,"headers":headers,"body":body},"effects":effects,"audit":audit,"notify":notify});
        for row in owner.query("SELECT id FROM admin_audit_log WHERE id>$1 AND user_id=ANY($2)",&[&audit_start,&vec![a.user,b.user]]).await?{audit_ids.push(row.get(0));}
        audit_ids.sort();audit_ids.dedup();
        normalize(&mut observation,policy,&new_ids,&a,&b,&created_name,"")?;
        if !recording{super::approval_probe::no_go(address).await?;}
        server.abort();
        let dir=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/approvals/goldens");
        let route=format!("{method} {pattern}");
        let file=dir.join(format!("policies-{action}-{label}.json"));
        let row_file=dir.join(format!("policies-{action}-{label}-row-effects.json"));
        if recording {
            let expected=if kind=="priority-conflict"{409}else if kind=="foreign"{403}else if kind=="invalid"&&action!="audit"{400}else if kind=="repeat"&&action=="delete"{404}else if action=="create"{201}else if matches!(action,"update"|"delete"|"reorder"){204}else{200};
            if status!=expected{return Err(format!("Go policy {action} {status}: {raw}").into())}
            let source=std::env::var("GOFREE_GO_SOURCE")?;
            golden::record(&file,&json!({"format":1,"route":route,"case":kind,"go_source":source,"observation":observation}))?;
            if !matches!(action,"list"|"audit") {golden::record(&row_file,&json!({"format":1,"route":route,"case":format!("{kind}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;}
        } else {
            let expected:Value=serde_json::from_slice(&std::fs::read(file)?)?;golden::compare(&expected["observation"],&observation)?;
            if !matches!(action,"list"|"audit") {let rows:Value=serde_json::from_slice(&std::fs::read(row_file)?)?;golden::compare(&rows["effects"],&observation["effects"])?;}
            eprintln!("GOLDEN-REPLAY: {route} :: {}",expected["case"].as_str().ok_or("golden case")?);
        }
        Ok::<_,BoxError>(())
    }.await;
    if let Some(schema) = fault_schema {
        owner
            .batch_execute(&format!(
                "DROP TRIGGER {schema} ON approval_policies; DROP SCHEMA {schema} CASCADE"
            ))
            .await?;
    }
    if let Some(id) = audit_request {
        owner
            .execute("DELETE FROM approval_requests WHERE id=$1", &[&id])
            .await?;
    }
    let ids = policy_rows(&owner, policy, &created_name)
        .await?
        .iter()
        .filter_map(|r| r["id"].as_i64())
        .collect::<Vec<_>>();
    owner
        .execute("DELETE FROM approval_policies WHERE id=ANY($1)", &[&ids])
        .await?;
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
    for id in receipt_ids(&owner).await?.difference(&receipts_before) {
        owner
            .execute(
                "DELETE FROM rust_operation_receipts WHERE operation_id=$1::text::uuid",
                &[&id],
            )
            .await?;
    }
    super::remove_blob_account(&owner, &a).await?;
    super::remove_blob_account(&owner, &b).await?;
    result
}
async fn receipt_ids(
    owner: &tokio_postgres::Client,
) -> Result<std::collections::BTreeSet<String>, BoxError> {
    Ok(owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F10'",
            &[],
        )
        .await?
        .into_iter()
        .map(|r| r.get(0))
        .collect())
}
async fn policy_rows(
    owner: &tokio_postgres::Client,
    policy: i64,
    name: &str,
) -> Result<Vec<Value>, BoxError> {
    owner
        .query(
            "SELECT to_jsonb(p)::text FROM approval_policies p WHERE id=$1 OR name=$2 ORDER BY id",
            &[&policy, &name],
        )
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}
pub(super) fn normalize_headers(
    headers: &mut serde_json::Map<String, Value>,
    raw: &str,
    body: &str,
) -> Result<(), BoxError> {
    if let Some(date) = headers.get_mut("date") {
        if date[0]
            .as_str()
            .is_none_or(|s| chrono::DateTime::parse_from_rfc2822(s).is_err())
        {
            return Err("invalid HTTP date".into());
        }
        *date = json!(["<timestamp>"]);
    }
    if let Some(length) = headers.get_mut("content-length") {
        if length[0] != raw.len().to_string() {
            return Err("invalid HTTP length".into());
        }
        *length = json!([body.len().to_string()]);
    }
    Ok(())
}
fn normalize(
    v: &mut Value,
    policy: i64,
    created: &[i64],
    a: &fixture::Account,
    b: &fixture::Account,
    name: &str,
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
                    *x = json!("<audit-id>");
                } else {
                    normalize(x, policy, created, a, b, name, k)?;
                }
            }
        }
        Value::Array(xs) => {
            for x in xs {
                normalize(x, policy, created, a, b, name, key)?;
            }
        }
        Value::Number(_) => {
            if matches!(key, "id" | "target_id") {
                let id = v.as_i64().ok_or("invalid policy ID")?;
                *v = if id == policy {
                    json!("<policy>")
                } else if let Some(index) = created.iter().position(|i| *i == id) {
                    json!(format!("<created-policy-{}>", index + 1))
                } else {
                    return Err("unexpected policy identity".into());
                };
            } else if key == "orderedIds" {
                if *v != policy {
                    return Err("unexpected reorder ID".into());
                }
                *v = json!("<policy>");
            } else if key == "user_id" {
                *v = if *v == a.user {
                    json!("<admin>")
                } else if *v == b.user {
                    json!("<approver>")
                } else {
                    return Err("unexpected audit actor".into());
                };
            }
        }
        Value::String(s) => {
            if matches!(key, "occurred_at" | "created_at" | "updated_at") {
                if chrono::DateTime::parse_from_rfc3339(s).is_err() {
                    return Err("invalid DB timestamp".into());
                }
                *s = "<timestamp>".into();
            } else if key == "checksum" {
                if s.is_empty() {
                    return Err("empty core checksum".into());
                }
                *s = "<checksum>".into();
            } else if matches!(key, "target" | "notes")
                && s == &format!("/admin/approval-policies/{policy}")
            {
                *s = "/admin/approval-policies/{id}".into();
            } else if s == name {
                *s = "Created <two>".into();
            }
        }
        _ => {}
    }
    Ok(())
}
fn admin_token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = super::recovery_token(user);
    let fields = source.split('.').collect::<Vec<_>>();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = json!(true);
    claims["perms"] = json!(["untrusted.claim"]);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let header = fields[0];
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{header}.{payload}").as_bytes());
    format!(
        "{header}.{payload}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}
