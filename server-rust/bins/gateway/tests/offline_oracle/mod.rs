//! F07 slice `offline` frozen-Go oracle: HTTP wire, committed rows, audit and notifications.
//! Record mode runs the covered Go binary behind the front door; replay serves the
//! same requests from Rust with no Go upstream. Every case builds and removes its own
//! two-domain fixtures and policy maps; `SERIAL` keeps cases from overlapping.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{golden, harness::Db};
use setjoin_gateway::{
    offline::OfflineRoute, Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable,
    TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

pub mod expected;
mod plan;
pub use plan::{plan, Fx};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[path = "../common/drive_commit.rs"]
mod commit_wire;
struct CutTask(tokio::task::JoinHandle<std::io::Result<commit_wire::CommitCut>>);
impl Drop for CutTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Probe {
    inner: OfflineRoute<setjoin_gateway::jmap::jwks::Jwks>,
    changed_status: bool,
}
impl Intercept for Probe {
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let future = self.inner.handle(r, c);
        let changed = self.changed_status;
        Box::pin(async move {
            let mut response = future.await;
            if changed {
                *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            response
        })
    }
}

pub fn admin_token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
    let fields: Vec<&str> = source.split('.').collect();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = json!(true);
    claims["perms"] = json!(["forged.permission"]);
    claims["auth_time"] = json!(claims["iat"].clone());
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        fields[0],
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn timestamp_like(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && (b[10] == b'T' || b[10] == b' ')
        && b[13] == b':'
}

/// Replace run-specific identities: numeric ids by the key that names them (as numbers
/// or strings) and timestamps.
fn mask(v: &mut Value, ids: &[(&str, i64, String)]) {
    match v {
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                let named = |n: i64| {
                    ids.iter()
                        .find(|(key, id, _)| key == k && *id == n)
                        .map(|(_, _, name)| name.clone())
                };
                if let Some(name) = x.as_i64().and_then(named) {
                    *x = json!(name);
                } else if let Some(name) = x
                    .as_str()
                    .and_then(|s| s.parse::<i64>().ok())
                    .and_then(named)
                {
                    *x = json!(name);
                } else {
                    mask(x, ids);
                }
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask(x, ids)),
        Value::String(s) if timestamp_like(s) => *s = "<timestamp>".into(),
        _ => {}
    }
}

async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}

/// Everything the routes of this slice may touch, keyed by names (no ids).
async fn snapshot(c: &tokio_postgres::Client, fx: &Fx, _since: &str) -> Result<Value, BoxError> {
    Ok(json!({
        "policies": rows(c,"SELECT to_jsonb(p)::text FROM offline_policies p ORDER BY id").await?,
        "toggle": rows(c,"SELECT to_jsonb(t)::text FROM feature_toggles t WHERE key='feature.offline_mail'").await?,
        "devices": rows(c,&format!("SELECT to_jsonb(d)::text FROM user_devices d WHERE user_id IN ({},{}) ORDER BY id",fx.a.user,fx.b.user)).await?
    }))
}

async fn prepare_read_fault(
    c: &tokio_postgres::Client,
    schema: &str,
    action: &str,
) -> Result<(), BoxError> {
    c.batch_execute(&format!(
        "CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO PUBLIC;"
    ))
    .await?;
    if action == "enabled" {
        c.batch_execute(&format!("CREATE FUNCTION {schema}.fail_bool(v boolean) RETURNS boolean LANGUAGE plpgsql AS $$BEGIN RETURN v; END$$; CREATE VIEW {schema}.feature_toggles AS SELECT key,CASE WHEN key='feature.offline_mail' THEN {schema}.fail_bool(enabled) ELSE enabled END AS enabled FROM public.feature_toggles; GRANT SELECT ON {schema}.feature_toggles TO PUBLIC")).await?;
    } else {
        c.batch_execute(&format!("CREATE FUNCTION {schema}.fail_text(v text) RETURNS text LANGUAGE plpgsql AS $$BEGIN RETURN v; END$$")).await?;
        let columns=c.query("SELECT attname FROM pg_attribute WHERE attrelid='public.messages'::regclass AND attnum>0 AND NOT attisdropped ORDER BY attnum",&[]).await?.iter().map(|r|r.get::<_,String>(0)).map(|n|if n=="body_text"{format!("{schema}.fail_text(m.body_text) AS body_text")}else{format!("m.\"{}\"",n.replace('"',"\"\""))}).collect::<Vec<_>>().join(",");
        c.batch_execute(&format!("CREATE VIEW {schema}.messages AS SELECT {columns} FROM public.messages m; GRANT SELECT ON {schema}.messages TO PUBLIC")).await?;
    }
    Ok(())
}

async fn arm(
    c: &tokio_postgres::Client,
    action: &str,
    fault: &str,
) -> Result<Option<String>, BoxError> {
    let name = match fault {
        "audit-error" | "no-audit" => "audit_write",
        "notify-error" | "no-notify" => "app_notify",
        "write-error" => "offline_policy_set_v2",
        "no-tenant-filter" => "offline_device_wipe_ack",
        "double-bump" => "rust_offline_command",
        "read-error" => match action {
            "policies" => "offline_policy_list",
            "policy" => "offline_policy_get",
            "pending" => "rust_offline_devices_pending",
            "preview" => "offline_sync_policy_preview",
            _ => return Err("no read fault target".into()),
        },
        _ => return Ok(None),
    };
    let rows=c.query("SELECT pg_get_functiondef(p.oid) FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname=$1",&[&name]).await?;
    if rows.len() != 1 {
        return Err(format!("ambiguous fault function {name}").into());
    }
    let original: String = rows[0].get(0);
    let changed = if fault == "no-tenant-filter" {
        let needle = "AND user_id    = v_user_id";
        if !original.contains(needle) {
            return Err("ack owner predicate moved".into());
        }
        original.replacen(needle, "AND user_id > 0", 1)
    } else if fault == "double-bump" {
        if !original.contains("RETURN v_id::text;") {
            return Err("policy return moved".into());
        }
        original.replacen("RETURN v_id::text;","UPDATE public.offline_policies SET priority=priority+1 WHERE id=v_id; RETURN v_id::text;",1)
    } else {
        let at = original
            .find("AS $function$")
            .ok_or("function definition delimiter changed")?;
        let prefix = original[..at].replace("LANGUAGE sql", "LANGUAGE plpgsql");
        let body = if matches!(fault, "no-audit" | "no-notify") {
            "BEGIN RETURN; END;"
        } else {
            "BEGIN RAISE EXCEPTION 'offline injected fault' USING ERRCODE='22000'; END;"
        };
        format!("{prefix}AS $function${body}$function$;")
    };
    c.batch_execute(&changed).await?;
    Ok(Some(original))
}

pub async fn run(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let fault = fault.or_else(|| match kind {
        "write-error" => Some("write-error"),
        "audit-error" => Some("audit-error"),
        "policy-error" => Some("policy-error"),
        "event-error" => Some("event-error"),
        "notify-error" => Some("notify-error"),
        "read-error" => Some("read-error"),
        "group-read-error" => Some("group-read-error"),
        "resolve-error" => Some("resolve-error"),
        "events-error" => Some("events-error"),
        "scope-error" => Some("scope-error"),
        "evidence-scope-error" => Some("evidence-scope-error"),
        _ => None,
    });
    if std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some()
        && (kind.starts_with("commit-")
            || kind.ends_with("-status-mutant")
            || matches!(
                fault,
                Some("no-audit" | "no-notify" | "no-tenant-filter" | "double-bump")
            ))
    {
        return Err("mutants require Rust replay without Go".into());
    }
    run_inner(action, kind, fault).await
}

async fn run_inner(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let cut = match label {
        "commit-before" => Some(commit_wire::CommitCut::BeforeCommit),
        "commit-after" => Some(commit_wire::CommitCut::AfterCommit),
        _ => None,
    };
    let Some(mut db) = Db::for_case("offline-http") else {
        return Ok(());
    };
    if matches!(action, "approve" | "deny" | "revoke" | "wipe" | "ack") && !label.starts_with("rls")
    {
        db.app = Some(db.dsn.clone());
    }
    let owner = db.connect().await?;
    let fx = Fx::build(&owner, label, action).await?;
    let seeded = fx.seed(&owner, action, label).await;
    let p = plan(action, label, &fx);
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F07'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    // Faults run real mutated database objects against the unchanged expectation.
    let private = label == "read-error" && matches!(action, "enabled" | "size");
    let schema = format!("gofree_dev3_read_{}", fx.a.user);
    let mut worker_dsn = db.dsn.clone();
    let read_setup = if private {
        prepare_read_fault(&owner, &schema, action).await
    } else {
        Ok(())
    };
    if private {
        let extend = |dsn: &str| {
            format!(
                "{dsn}{}options=-csearch_path%3D{schema}%2Cpg_catalog%2Cpublic",
                if dsn.contains('?') { "&" } else { "?" }
            )
        };
        if action == "enabled" {
            db.app = Some(extend(db.app.as_deref().unwrap_or(&db.dsn)));
        } else {
            worker_dsn = extend(&db.dsn);
        }
    }
    let mut restore = None;
    let result = async {
        seeded?;
        read_setup?;

        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named_with_env(&db,s3,"gofree-devices3-http",&[("DB_WORKER_DSN",worker_dsn.clone())]).await?;
        let recording = go.is_some();
        let patient = std::time::Duration::from_secs(30);
        let timeouts = setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient };
        let mut wire=None;
        let request_dsn=if let Some(cut)=cut {
            let (dsn,task)=commit_wire::commit_cut_proxy(db.app.as_deref().unwrap_or(&db.dsn),cut).await;
            wire=Some(CutTask(task)); dsn
        } else { db.app.as_deref().unwrap_or(&db.dsn).to_owned() };
        let exec = ScopedExecutor::from_dsn_with(&request_dsn, if cut.is_some() {1}else{4}, timeouts)
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let adapter = Probe {
            inner: OfflineRoute {
                worker: ScopedExecutor::from_dsn_with(&worker_dsn,4,timeouts).map_err(|e|e.0)?,
                exec,
                keys: Arc::new(common::recovery_keys()),
                issuer: "mailserver".into(),
            },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F07" && r["slice"] == "offline" {
                r["state"] = json!(if recording { "OFF" } else { "ON" });
                r["upstream"] = json!(if recording { "go-mail" } else { "local-rust" });
                r["oracle_commands"] = json!([""]);
            }
        }
        let gateway = Gateway::new(
            Config {
                upstream: go.as_ref().map(|g| format!("http://{}", g.address).parse()).transpose()?,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            RouteTable::proxy_all().with(adapter),
        )?
        .with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let send = |sent: &plan::Plan| {
            let uri = format!("{}{}{}", "/api", sent.path, sent.query);
            let token = if sent.path.starts_with("/admin/") {admin_token(fx.a.user)} else {common::recovery_token(fx.a.user)};
            let method = if sent.head { "HEAD" } else { sent.method };
            let body = sent.body.clone();
            async move {
                let request = Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("host", "mail.test")
                    .header("origin", "http://mail.test")
                    .header("content-type", "application/json")
                    .header("x-request-id", "gofree-devices3-oracle")
                    .header("authorization", format!("Bearer {token}"));
                Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
            }
        };
        if p.repeat {
            let first = send(&p).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && !(200..300).contains(&status) {
                return Err(format!("initial {action}: {status} {data:?}").into());
            }
        }
        let since: String = owner.query_one("SELECT clock_timestamp()::text", &[]).await?.get(0);
        let before = snapshot(&owner, &fx, &since).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut policy_events = db.listen("caps:offline").await?;
        let mut access_events = db.listen(&format!("tag:{}",fx.a.mailbox)).await?;
        let mut other_events = db.listen(&format!("tag:{}",fx.b.mailbox)).await?;
        if private {
           let (function,arg,ret)=if action=="enabled"{("fail_bool","boolean","boolean")}else{("fail_text","text","text")};
           owner.batch_execute(&format!("CREATE OR REPLACE FUNCTION {schema}.{function}(v {arg}) RETURNS {ret} LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'offline injected fault' USING ERRCODE='22000'; END$$")).await?;
        }else if let Some(fault)=fault {restore=arm(&owner,action,fault).await?;}
        let response = send(&p).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let bytes = common::body_bytes(response).await;
        let raw = String::from_utf8(bytes.to_vec())?;
        let after = snapshot(&owner, &fx, &since).await?;
        let wanted = expected::status(action, label);
        if recording && status != wanted {
            return Err(format!("Go {action}/{label}: expected {wanted}, got {status}: {raw}").into());
        }
        let ids = fx.ids();
        let mut audit: Vec<Value> = owner
            .query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last])
            .await?
            .iter()
            .map(|r| serde_json::from_str(&r.get::<_, String>(0)))
            .collect::<Result<_, _>>()?;
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) {
                return Err("invalid audit id".into());
            }
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) {
                    row[key] = json!("<checksum>");
                }
            }
            let text = fx
                .names(&row.to_string())
                .replace(&format!("domain={})", fx.a.domain), "domain=<domain-a>)");
            *row = serde_json::from_str(&text)?;
            mask(row, &ids);
        }
        let mut notify = vec![];
        for event in policy_events.drain(&owner).await? {
            notify.push(json!({"channel":"caps:offline","payload":serde_json::from_str::<Value>(&event)?}));
        }
        for event in access_events.drain(&owner).await? {
            let mut payload: Value = serde_json::from_str(&event)?;
            if payload["at"].is_string() {
                payload["at"] = json!("<timestamp>");
            }
            notify.push(json!({"channel":"tag:<admin-mailbox>","payload":payload}));
        }
        for event in other_events.drain(&owner).await? {
            notify.push(json!({"channel":"tag:<other-mailbox>","payload":serde_json::from_str::<Value>(&event)?}));
        }
        let text = mask_json_text(&fx.names(&raw), &ids);
        if let Some(date) = headers.get_mut("date") {
            *date = json!(["<timestamp>"]);
        }
        if let Some(length) = headers.get_mut("content-length") {
            if p.head {
                // A HEAD answer carries the length a GET would, which varies with the ids.
                *length = json!(["<get-length>"]);
            } else {
                if *length != json!([raw.len().to_string()]) {
                    return Err("bad wire length".into());
                }
                *length = json!([text.len().to_string()]);
            }
        }
        let (before, after) = (mask_all(before, &ids, &fx), mask_all(after, &ids, &fx));
        let effects = json!([{"table":"offline_policies+feature_toggles+user_devices","before":before,"after":after}]);
        let mut request = json!({"method":p.method,"path":p.pattern,"external_path":format!("{}{}","/api",p.pattern)});
        if !p.query.is_empty() {
            request["query"] = json!(fx.names(&p.query).replace(&format!("user_id={}",fx.a.user),"user_id=<admin>").replace(&format!("user_id={}",fx.b.user),"user_id=<other>").replace(&format!("mailbox_id={}",fx.b.mailbox),"mailbox_id=<other-mailbox>"));
        }
        if p.head {
            request["head"] = json!(true);
        }
        if label=="unbounded" {
            if p.body.len()<=16<<20{return Err("unbounded fixture failed to exceed16MiB".into());}
            use sha2::Digest;
            request["body_bytes"]=json!(p.body.len());
            request["body_sha256"]=json!(sha2::Sha256::digest(p.body.as_bytes()).iter().map(|b|format!("{b:02x}")).collect::<String>());
        }
        if !p.recorded_body.is_empty() {
            request["body"] = json!(p.recorded_body.replace(&format!("\"targetUserId\":\"{}\"",fx.a.user),"\"targetUserId\":\"<admin>\""));
        }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if recording && matches!(action,"size"|"ack") {
            let metrics=common::send(address,Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.contains(&format!("setjoin_gateway_proxied_to_go_by_family_total{{family=\"F07\"}} {}",if p.repeat{2}else{1})) {return Err("F07 offline canonical /api request was not counted as F07 while OFF".into());}
        }
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F07\"} 0") {
                return Err(format!("F07 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let name = format!("{action}-{label}");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/offline/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("{name}.json"));
        let row_file = dir.join(format!("{name}-row-effects.json"));
        let route_name = format!("{} {}", p.method, p.pattern);
        if let Some(cut)=cut {
            let actual=tokio::time::timeout(std::time::Duration::from_secs(5),&mut wire.as_mut().ok_or("missing wire proxy")?.0).await???;
            if actual!=cut || status!=503 {return Err(format!("lost COMMIT answered {status}, cut {actual:?}").into());}
            let op=observation["response"]["headers"]["x-operation-id"][0].as_str().ok_or("unknown outcome omitted operation id")?;
            if op.len()!=32 || !op.bytes().all(|b|b.is_ascii_hexdigit()) {return Err("invalid unknown operation id".into());}
            let body:Value=serde_json::from_str(observation["response"]["body"].as_str().ok_or("body")?)?;
            if body["detail"]!="operation outcome unknown" || body["status"]!=503 {return Err("lost COMMIT claimed a known outcome".into());}
            let committed:bool=owner.query_one("SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE family='F07' AND operation_id=$1::text::uuid)",&[&op]).await?.get(0);
            if committed!=(cut==commit_wire::CommitCut::AfterCommit) {return Err("receipt disagrees with actual COMMIT".into());}

            let effect=&observation["effects"][0];
            if committed {
                let success:Value=serde_json::from_slice(&std::fs::read(dir.join(format!("{action}-success.json")))?)?;
                golden::compare(&success["observation"]["effects"][0]["after"],&effect["after"])?;
                golden::compare(&success["observation"]["audit"],&observation["audit"])?;golden::compare(&success["observation"]["notify"],&observation["notify"])?;
            } else {golden::compare(&effect["before"],&effect["after"])?;golden::compare(&json!([]),&observation["audit"])?;golden::compare(&json!([]),&observation["notify"])?;}
            eprintln!("COMMIT-LOSS-VERIFIED: {route_name} :: {label}");
            return Ok(());
        }
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
        } else {
            let expected: Value = common::golden_doc(&file, "observation", &observation);
            let compared = golden::compare(&expected["observation"], &observation);
            if mutant {
                let error = compared.err().ok_or("planted status mutant survived")?;
                if !error.contains("/response/status") {
                    return Err(format!("mutant failed outside response status: {error}").into());
                }
                eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
                return Ok(());
            }
            if let Some(part)=match fault {
                Some("no-audit")=>Some("/audit"),Some("no-notify")=>Some("/notify"),
                Some("no-tenant-filter")=>Some("/effects"),Some("double-bump")=>Some("/effects"),_=>None,
            } {
                let error=compared.err().ok_or("planted family mutant survived")?;
                if status!=expected::status(action,label) || !error.contains(part) {return Err(format!("mutant failed outside {part}: {error}").into());}
                eprintln!("MUTANT-REJECTED: {route_name} :: {}",fault.unwrap());
                return Ok(());
            }
            compared?;
            let expected: Value = common::golden_doc(&row_file, "effects", &observation["effects"]);
            golden::compare(&expected["effects"], &observation["effects"])?;
            eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    // Cleanup runs on every path and touches only this case's rows.
    if private {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    if let Some(original) = restore {
        owner.batch_execute(&original).await?;
    }
    owner
        .execute("DELETE FROM rust_operation_receipts WHERE family='F07' AND operation_id::text<>ALL($1)", &[&receipts])
        .await?;
    fx.remove(&owner).await?;
    owner
        .batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;"))
        .await?;
    result
}

/// JSON text whose key order and spacing are the contract: replace `"key":<id>` values.
fn mask_json_text(text: &str, ids: &[(&'static str, i64, String)]) -> String {
    let mut out = text.to_owned();
    for (key, id, name) in ids {
        let id = id.to_string();
        for sep in [":", ": "] {
            out = out.replace(
                &format!("\"{key}\"{sep}\"{id}\""),
                &format!("\"{key}\"{sep}\"{name}\""),
            );
            out = out.replace(
                &format!("\"{key}\"{sep}{id},"),
                &format!("\"{key}\"{sep}\"{name}\","),
            );
            out = out.replace(
                &format!("\"{key}\"{sep}{id}}}"),
                &format!("\"{key}\"{sep}\"{name}\"}}"),
            );
        }
    }
    // Timestamps inside string values.
    let mut result = String::new();
    let mut i = 0;
    while i < out.len() {
        let rest = &out[i..];
        if rest.starts_with('"')
            && rest.len() > 20
            && rest.is_char_boundary(20)
            && timestamp_like(&rest[1..20])
        {
            if let Some(close) = rest[1..].find('"') {
                result.push_str("\"<timestamp>\"");
                i += close + 2;
                continue;
            }
        }
        let ch = rest.chars().next().unwrap();
        result.push(ch);
        i += ch.len_utf8();
    }
    result
}

fn mask_all(mut v: Value, ids: &[(&'static str, i64, String)], fx: &Fx) -> Value {
    let text = fx.names(&v.to_string());
    v = serde_json::from_str(&text).expect("json");
    mask(&mut v, ids);
    v
}

/// Verification mode compares immutable Go observations instead of rewriting them.
fn record(path: &std::path::Path, value: &Value) -> Result<(), BoxError> {
    if path.exists() || std::env::var_os("GOFREE_VERIFY_GO").is_some() {
        let expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        golden::compare(&expected, value)?;
        Ok(())
    } else {
        golden::record(path, value).map_err(Into::into)
    }
}
