//! F05 slice `mailboxes` frozen-Go oracle: HTTP wire, committed rows and audit.
//! Record mode runs the covered Go binary behind the front door; replay serves
//! the same requests from Rust with no Go upstream.
//!
//! Fixtures: admin `a` (domain A), foreign account `b` (domain B), user `t` in A
//! with a primary mailbox and a secondary mailbox `s` that holds folders, tags,
//! an alias and a message. Every case builds and removes its own fixtures; the
//! shared toggles are restored, and `SERIAL` keeps cases from overlapping.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{golden, harness::Db};
use setjoin_gateway::{
    mailboxes::MailboxesRoute, Body, BoxFuture, Config, Gateway, Intercept, RequestContext,
    RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

pub mod expected;
mod plan;
pub use plan::{plan, Fx};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Probe {
    inner: MailboxesRoute<setjoin_gateway::jmap::jwks::Jwks>,
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
    let fields = source.split('.').collect::<Vec<_>>();
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

fn uuid_like(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && [8, 13, 18, 23].iter().all(|i| b[*i] == b'-')
        && b.iter()
            .enumerate()
            .all(|(i, c)| [8, 13, 18, 23].contains(&i) || c.is_ascii_hexdigit())
}

/// Replace run-specific identities: numeric ids by the key that names them (as numbers or
/// strings), generated UUIDs, timestamps and ids quoted inside prose.
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
        Value::String(s) => {
            if timestamp_like(s) {
                *s = "<timestamp>".into();
            } else if uuid_like(s) && s != plan::KEY && s != plan::KEY2 {
                *s = "<uuid>".into();
            } else if let Some(at) = s.find("mailbox ") {
                let start = at + "mailbox ".len();
                let digits = s[start..].bytes().take_while(u8::is_ascii_digit).count();
                let name = s[start..start + digits]
                    .parse::<i64>()
                    .ok()
                    .and_then(|n| ids.iter().find(|(k, id, _)| *k == "mailboxId" && *id == n));
                if let Some((_, _, name)) = name {
                    s.replace_range(start..start + digits, name);
                }
            }
        }
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
async fn snapshot(c: &tokio_postgres::Client, fx: &Fx) -> Result<Value, BoxError> {
    let doms = format!("({},{})", fx.a.domain, fx.b.domain);
    Ok(json!({
        "mailboxes": rows(c, &format!("SELECT jsonb_build_object('email',m.email,'display_name',m.display_name,'type',m.type,'user',u.email,'is_primary',m.is_primary,'quota_bytes',m.quota_bytes,'used_bytes',m.used_bytes,'enabled',m.enabled,'litigation_hold',m.litigation_hold,'deleted_purge_days',m.deleted_purge_days,'spam_purge_days',m.spam_purge_days,'domain',d.name,'states',jsonb_build_array(m.jmap_email_state,m.jmap_mailbox_state,m.jmap_tag_state))::text FROM mailboxes m JOIN domains d ON d.id=m.domain_id LEFT JOIN users u ON u.id=m.user_id WHERE m.domain_id IN {doms} ORDER BY m.email")).await?,
        "folders": rows(c, &format!("SELECT jsonb_build_object('mailbox',m.email,'name',f.name,'path',f.path,'role',f.role,'parent',pf.name)::text FROM folders f JOIN mailboxes m ON m.id=f.mailbox_id LEFT JOIN folders pf ON pf.id=f.parent_id WHERE m.domain_id IN {doms} ORDER BY m.email,f.path")).await?,
        "tags": rows(c, &format!("SELECT jsonb_build_object('mailbox',m.email,'name',t.name,'parent',pt.name,'type',t.tag_type,'sort_order',t.sort_order,'imap_expose',t.imap_expose,'total',t.total_count)::text FROM tags t JOIN mailboxes m ON m.id=t.mailbox_id LEFT JOIN tags pt ON pt.id=t.parent_id WHERE m.domain_id IN {doms} ORDER BY m.email,t.name")).await?,
        "lifecycle": rows(c, &format!("SELECT jsonb_build_object('mailbox',m.email,'access',l.access_state,'delivery',l.delivery_state,'binding',l.binding_state,'bound_user',bu.email,'was_primary',l.was_primary,'generation',l.generation,'retained',l.retained_at IS NOT NULL,'retention',l.retention_until IS NOT NULL,'reason',l.reason,'updated_by',ub.email,'has_operation',l.last_operation_id IS NOT NULL)::text FROM mailbox_lifecycle l JOIN mailboxes m ON m.id=l.mailbox_id LEFT JOIN users bu ON bu.id=l.bound_user_id LEFT JOIN users ub ON ub.id=l.updated_by WHERE m.domain_id IN {doms} ORDER BY m.email")).await?,
        "operations": rows(c, &format!("SELECT jsonb_build_object('action',o.action,'mailbox',m.email,'actor',au.email,'expected_generation',o.expected_generation,'request_digest',o.request_digest,'before_digest',o.before_digest,'after_digest',o.after_digest,'state',o.state,'error_code',o.error_code,'result',o.result - 'operationId')::text FROM mailbox_lifecycle_operations o JOIN mailboxes m ON m.id=o.mailbox_id LEFT JOIN users au ON au.id=o.actor_user_id WHERE m.domain_id IN {doms} ORDER BY o.created_at,o.action")).await?,
        "effects": rows(c, &format!("SELECT jsonb_build_object('mailbox',m.email,'kinds',(SELECT jsonb_agg(e.effect_kind||':'||e.state ORDER BY e.effect_kind) FROM mailbox_lifecycle_effects e WHERE e.mailbox_id=m.id),'outbox',(SELECT jsonb_agg(x.event_kind||':'||x.state ORDER BY x.event_kind) FROM mailbox_lifecycle_outbox x JOIN mailbox_lifecycle_operations o ON o.operation_id=x.operation_id WHERE o.mailbox_id=m.id),'history',(SELECT jsonb_agg(h.evidence_kind ORDER BY h.id) FROM mailbox_binding_history h WHERE h.mailbox_id=m.id))::text FROM mailboxes m WHERE m.domain_id IN {doms} ORDER BY m.email")).await?,
        "purges": rows(c, &format!("SELECT jsonb_build_object('mailbox',m.email,'state',p.state,'requested_by',rq.email,'approved_by',ap.email,'attempts',p.attempts,'preview_digest',p.preview_digest,'eligible',p.eligible_at<=now(),'generation',p.lifecycle_generation,'approval',a.status)::text FROM mailbox_purge_requests p JOIN mailboxes m ON m.id=p.mailbox_id LEFT JOIN approval_requests a ON a.id=p.approval_request_id LEFT JOIN users rq ON rq.id=p.requested_by LEFT JOIN users ap ON ap.id=p.approved_by WHERE m.domain_id IN {doms} ORDER BY m.email,p.requested_at")).await?,
        "tombstones": rows(c, "SELECT jsonb_build_object('message_count',t.message_count,'blob_count',t.blob_count,'reason',t.reason,'purged_by',u.email,'addresses',jsonb_array_length(t.address_digests))::text FROM mailbox_tombstones t LEFT JOIN users u ON u.id=t.purged_by ORDER BY purged_at").await?,
        "dependents": rows(c, &format!("SELECT jsonb_build_object('mailbox',m.email,'aliases',(SELECT count(*) FROM aliases x WHERE x.mailbox_id=m.id),'messages',(SELECT count(*) FROM messages x WHERE x.mailbox_id=m.id))::text FROM mailboxes m WHERE m.domain_id IN {doms} ORDER BY m.email")).await?,
    }))
}

pub async fn run(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(action, kind, fault).await
}

async fn run_inner(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(db) = Db::for_case("mailboxes-http") else {
        return Ok(());
    };
    let learn = std::env::var_os("GOFREE_ORACLE_LEARN").is_some();
    let owner = db.connect().await?;
    let mut fx = Fx::build(&owner, label, action).await?;
    fx.hide_request_digest =
        action == "purge" || (action == "transition" && label.starts_with("reconnect"));
    let lifecycle_before: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.mailbox_lifecycle_retention'",
            &[],
        )
        .await?
        .get(0);
    // Seeding runs the lifecycle the way an operator would, so the feature is on for it.
    if plan::is_lifecycle(action) {
        owner.execute("UPDATE feature_toggles SET enabled=TRUE WHERE key='feature.mailbox_lifecycle_retention'", &[]).await?;
    }
    let seeded = fx.seed(&owner, action, label).await;
    let p = plan(action, label, &fx);
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.mailbox_lifecycle_retention'",
            &[&p.lifecycle],
        )
        .await?;
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F05'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    // Faults run real mutated database objects against the unchanged expectation.
    let schema = format!("gofree_mbox1_fault_{}", fx.a.user);
    let mut trigger = None;
    let mut private = false;
    let mut notify_swapped = false;
    // A failing setup must still reach the cleanup below.
    let fault_setup: Result<(), BoxError> = async {
    match fault {
        Some("no-audit") => {
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN RETURN NULL; END $fault$;CREATE TRIGGER {schema} BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION {schema}.fault();")).await?;
            trigger = Some("admin_audit_log");
        }
        Some("double-bump") => {
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.id={} THEN UPDATE mailboxes SET jmap_email_state=jmap_email_state+2 WHERE id={}; END IF; RETURN NEW; END $fault$;CREATE TRIGGER {schema} AFTER UPDATE ON mailboxes FOR EACH ROW EXECUTE FUNCTION {schema}.fault();", fx.s, fx.tm)).await?;
            trigger = Some("mailboxes");
        }
        Some("no-notify") => {
            // The reducers are SECURITY DEFINER with a pinned search_path, so the
            // publisher itself is swapped for a no-op and put back afterwards.
            owner.batch_execute("ALTER FUNCTION public.app_notify(text,text) RENAME TO app_notify_mbox1_orig; CREATE FUNCTION public.app_notify(text,text) RETURNS void LANGUAGE sql AS 'SELECT NULL::void'").await?;
            notify_swapped = true;
        }
        Some("no-tenant-filter") => {
            // Private views that pin every row to the other domain.
            let mut statements =
                format!("CREATE SCHEMA {schema};GRANT USAGE ON SCHEMA {schema} TO setjoin_app;");
            for table in ["mailboxes"] {
                let columns: String = owner
                    .query_one("SELECT string_agg(quote_ident(column_name),',' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name<>'domain_id'", &[&table])
                    .await?
                    .get(0);
                statements.push_str(&format!("CREATE VIEW {schema}.{table} AS SELECT {columns},{}::bigint AS domain_id FROM public.{table};GRANT SELECT,UPDATE ON {schema}.{table} TO setjoin_app;", fx.b.domain));
            }
            owner.batch_execute(&statements).await?;
            private = true;
        }
        _ => {}
    }
        Ok(())
    }
    .await;
    let mut db = db;
    if private {
        let base = db.app.clone().unwrap_or_else(|| db.dsn.clone());
        db.app = Some(format!(
            "{base}{}options=-csearch_path%3D{schema}%2Cpublic",
            if base.contains('?') { "&" } else { "?" }
        ));
    }
    let result = async {
        seeded?;
        fault_setup?;
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-mbox1-http").await?;
        let recording = go.is_some();
        let patient = std::time::Duration::from_secs(30);
        let timeouts = setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient };
        let exec = ScopedExecutor::from_dsn_with(db.app.as_deref().unwrap_or(&db.dsn), 4, timeouts)
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let worker = ScopedExecutor::from_dsn_with(&db.dsn, 4, timeouts)
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let adapter = Probe {
            inner: MailboxesRoute { exec, worker, keys: Arc::new(common::recovery_keys()), issuer: "mailserver".into() },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F05" && r["slice"] == "mailboxes" {
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
            let uri = format!("/api{}{}", sent.path, sent.query);
            let token = admin_token(fx.a.user);
            let method = sent.method;
            let body = sent.body.clone();
            let language = sent.language;
            let extra = sent.headers.clone();
            async move {
                let mut request = Request::builder().method(method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("content-type", "application/json").header("x-request-id", "gofree-mbox1-oracle").header("authorization", format!("Bearer {token}"));
                if let Some(l) = language { request = request.header("accept-language", l); }
                for (name, value) in &extra { request = request.header(*name, value.as_str()); }
                Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
            }
        };
        let ids_before = fx.ids(&owner, p.id_is_folder).await?;
        if p.repeat {
            let first = send(&p).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && !(200..300).contains(&status) {
                return Err(format!("initial {action}: {status} {data:?}").into());
            }
        }
        let before = snapshot(&owner, &fx).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut alerts = db.listen("admin:alert").await?;
        let mut lifecycle = db.listen("mailbox_lifecycle").await?;
        let response = send(&p).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        // Go answers an undecodable approval body with two problem documents in one response.
        let two_problems = action == "approval" && matches!(label, "bad-json" | "unknown-field");
        let bytes = if two_problems { common::body_bytes_unchecked(response).await } else { common::body_bytes(response).await };
        let raw = String::from_utf8(bytes.to_vec())?;
        if recording && learn {
            eprintln!("LEARN {action}/{label} {status} {}", raw.chars().take(200).collect::<String>().replace('\n', " "));
            return Ok(());
        }
        let after = snapshot(&owner, &fx).await?;
        let wanted = expected::status(action, label);
        if recording && status != wanted {
            return Err(format!("Go {action}/{label}: expected {wanted}, got {status}: {raw}").into());
        }
        let mut ids = ids_before;
        for entry in fx.ids(&owner, p.id_is_folder).await? {
            if !ids.contains(&entry) {
                ids.push(entry);
            }
        }
        let mut audit: Vec<Value> = owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last]).await?.iter().map(|r| serde_json::from_str(&r.get::<_, String>(0))).collect::<Result<_, _>>()?;
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) { return Err("invalid audit id".into()); }
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) { row[key] = json!("<checksum>"); }
            }
            *row = masked(row.clone(), &ids, &fx)?;
            if row["target_type"] == "approval_request" && row["target_id"].is_number() {
                row["target_id"] = json!("<approval>");
            }
        }
        let mut notify = vec![];
        for (channel, listener) in [("admin:alert", &mut alerts), ("mailbox_lifecycle", &mut lifecycle)] {
            for event in listener.drain(&owner).await? {
                let payload: Value = serde_json::from_str(&event)?;
                notify.push(json!({"channel":channel,"payload":masked(payload, &ids, &fx)?}));
            }
        }
        let text = mask_text(&fx.names(&raw), &ids);
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() { return Err("bad wire length".into()); }
            *length = json!([text.len().to_string()]);
        }
        let (before, after) = (masked(before, &ids, &fx)?, masked(after, &ids, &fx)?);
        let effects = json!([{"table":"mailboxes+folders+tags+dependents+lifecycle","before":before,"after":after}]);
        let mut request = json!({"method":p.method,"path":p.pattern,"external_path":format!("/api{}",p.pattern)});
        if !p.recorded_query.is_empty() { request["query"] = json!(p.recorded_query); }
        if !p.headers.is_empty() { request["headers"] = json!(p.headers.iter().map(|(n, v)| json!([n, v])).collect::<Vec<_>>()); }
        if !p.recorded_body.is_empty() { request["body"] = json!(fx.names(&p.recorded_body)); }
        if let Some(l) = p.language { request["accept_language"] = json!(l); }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F05\"} 0") {
                return Err(format!("F05 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let name = format!("{action}-{label}");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/mailboxes/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("{name}.json"));
        let row_file = dir.join(format!("{name}-row-effects.json"));
        let route_name = format!("{} {}", p.method, p.pattern);
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
        } else {
            let expected: Value = common::golden_doc(&file, "observation", &observation);
            let compared = golden::compare(&expected["observation"], &observation);
            if mutant {
                let error = compared.err().ok_or("planted status mutant survived")?;
                if !error.contains("/response/status") { return Err(format!("mutant failed outside response status: {error}").into()); }
                eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
                return Ok(());
            }
            if let Some(fault) = fault {
                eprintln!("FAULT-OBSERVED {fault}: {status} {}", observation["response"]["body"]);
                compared.err().ok_or("planted family fault survived")?;
                eprintln!("MUTANT-REJECTED: {route_name} :: {fault}");
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
    if let Some(table) = trigger {
        owner
            .batch_execute(&format!("DROP TRIGGER {schema} ON {table}"))
            .await?;
    }
    if notify_swapped {
        owner.batch_execute("DROP FUNCTION public.app_notify(text,text); ALTER FUNCTION public.app_notify_mbox1_orig(text,text) RENAME TO app_notify").await?;
    }
    if fault.is_some() && fault != Some("no-notify") {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    // Retained mailboxes cannot be deleted while the lifecycle feature is on.
    owner
        .execute("UPDATE feature_toggles SET enabled=FALSE WHERE key='feature.mailbox_lifecycle_retention'", &[])
        .await?;
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F05' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    fx.remove(&owner).await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.mailbox_lifecycle_retention'",
            &[&lifecycle_before],
        )
        .await?;
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
    result
}

/// Ids inside request paths (a problem's `instance`, an audit row's target).
fn mask_paths(text: &str, ids: &[(&'static str, i64, String)]) -> String {
    let mut out = text.to_owned();
    for (segment, key) in [
        ("/mailboxes/", "mailboxId"),
        ("/folders/", "parentId"),
        ("/mailbox-purge-approvals/", "approvalRequestId"),
    ] {
        let mut at = 0;
        while let Some(pos) = out[at..].find(segment) {
            let start = at + pos + segment.len();
            let digits = out[start..].bytes().take_while(u8::is_ascii_digit).count();
            let found = out[start..start + digits]
                .parse::<i64>()
                .ok()
                .and_then(|n| ids.iter().find(|(k, id, _)| *k == key && *id == n));
            match found {
                Some((_, _, name)) => {
                    out.replace_range(start..start + digits, name);
                    at = start + name.len();
                }
                None => at = start + digits.max(1),
            }
        }
    }
    out
}

/// Text form of `mask` for bodies whose key order and spacing are part of the
/// contract: ids (as numbers or strings), digests and RFC 3339 timestamps.
fn mask_text(text: &str, ids: &[(&'static str, i64, String)]) -> String {
    let mut out = text.to_owned();
    let replace_values =
        |out: &mut String, key: &str, matches: &dyn Fn(&str) -> bool, name: &str| {
            let needle = format!("\"{key}\":");
            let mut at = 0;
            while let Some(pos) = out[at..].find(&needle) {
                let mut start = at + pos + needle.len();
                if out.as_bytes().get(start) == Some(&b' ') {
                    start += 1;
                }
                let rest = &out[start..];
                let (len, value) = if let Some(quoted) = rest.strip_prefix('"') {
                    match quoted.find('"') {
                        Some(close) => (close + 2, &quoted[..close]),
                        None => break,
                    }
                } else {
                    let n = rest
                        .bytes()
                        .take_while(|b| b.is_ascii_digit() || *b == b'-')
                        .count();
                    (n, &rest[..n])
                };
                if len > 0 && matches(value) {
                    let to = format!("\"{name}\"");
                    out.replace_range(start..start + len, &to);
                    at = start + to.len();
                } else {
                    at = start + len.max(1);
                }
            }
        };
    for (key, id, name) in ids {
        let id = id.to_string();
        replace_values(&mut out, key, &|v| v == id, name);
    }
    for key in [
        "previewDigest",
        "evidenceDigest",
        "preview_digest",
        "before_digest",
        "after_digest",
        "evidence_digest",
    ] {
        replace_values(
            &mut out,
            key,
            &|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()),
            "<sha256>",
        );
    }
    let mut out = mask_paths(&out, ids);
    // Timestamps (RFC 3339) inside string values.
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
        if rest.starts_with('"')
            && rest.len() > 37
            && rest.is_char_boundary(37)
            && uuid_like(&rest[1..37])
            && rest.as_bytes()[37] == b'"'
            && rest[1..37] != *plan::KEY
            && rest[1..37] != *plan::KEY2
        {
            result.push_str("\"<uuid>\"");
            i += 38;
            continue;
        }
        let ch = rest.chars().next().unwrap();
        result.push(ch);
        i += ch.len_utf8();
    }
    result
}

fn mask_digests(v: &mut Value, request: bool) {
    match v {
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                let digest = matches!(
                    k.as_str(),
                    "previewDigest"
                        | "evidenceDigest"
                        | "preview_digest"
                        | "before_digest"
                        | "after_digest"
                        | "evidence_digest"
                ) || (request && k == "request_digest");
                match x {
                    Value::String(s)
                        if digest && s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) =>
                    {
                        *s = "<sha256>".into()
                    }
                    other => mask_digests(other, request),
                }
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask_digests(x, request)),
        _ => {}
    }
}

fn masked(mut v: Value, ids: &[(&'static str, i64, String)], fx: &Fx) -> Result<Value, BoxError> {
    v = serde_json::from_str(&mask_paths(&fx.names(&v.to_string()), ids))?;
    mask(&mut v, ids);
    mask_digests(&mut v, fx.hide_request_digest);
    Ok(v)
}

/// Verification mode compares immutable Go observations instead of rewriting them.
fn record(path: &std::path::Path, value: &Value) -> Result<(), BoxError> {
    if std::env::var_os("GOFREE_VERIFY_GO").is_some() {
        let expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        golden::compare(&expected, value)?;
        Ok(())
    } else {
        golden::record(path, value).map_err(Into::into)
    }
}
