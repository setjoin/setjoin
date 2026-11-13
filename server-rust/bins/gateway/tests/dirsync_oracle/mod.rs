//! F02 slice 1 frozen-Go oracle: HTTP wire, committed rows, audit and NOTIFY.
//! Record mode runs the covered Go binary behind the front door; replay mode
//! serves the same requests from Rust with no Go upstream.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    directory_sync::DirectorySyncRoute, Body, BoxFuture, Config, Gateway, Intercept,
    RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

const REDUCER: &str = include_str!("../../../../../mailserver/sql/reducers/ad_principal_set.sql");

struct Probe {
    inner: DirectorySyncRoute<setjoin_gateway::jmap::jwks::Jwks>,
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

fn admin_token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
    let fields = source.split('.').collect::<Vec<_>>();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = json!(true);
    claims["perms"] = json!(["forged.permission"]);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        fields[0],
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "config" => ("GET", "/admin/ad/config"),
        "sync-log" => ("GET", "/admin/ad/sync-log"),
        "ldap-config" => ("GET", "/admin/ldap/config"),
        "ldap-sync-log" => ("GET", "/admin/ldap/sync-log"),
        "conflicts" => ("GET", "/admin/ad/conflicts"),
        "resolve" => ("POST", "/admin/ad/conflicts/{id}/resolve"),
        "resolve-all" => ("POST", "/admin/ad/conflicts/resolve-all"),
        "policy-get" => ("GET", "/admin/ad/field-policy"),
        "policy-set" => ("PUT", "/admin/ad/field-policy"),
        "principal" => ("POST", "/admin/ad/principal"),
        _ => panic!("unknown F02 action {action}"),
    }
}

fn mask(v: &mut Value, ids: &[(i64, &str)], key: &str) {
    match v {
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                mask(x, ids, k);
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask(x, ids, key)),
        Value::Number(n) => {
            if matches!(
                key,
                "id" | "user_id" | "userId" | "target_id" | "actor_id" | "resolved_by" | "mailbox"
            ) {
                // Users, mailboxes and conflicts draw from separate sequences that
                // can coincide; each key only names its own kind.
                let mailbox = key == "mailbox";
                if let Some(id) = n.as_i64() {
                    if let Some((_, name)) = ids.iter().find(|(i, name)| {
                        *i == id
                            && if mailbox {
                                name.ends_with("-mailbox>")
                            } else {
                                matches!(*name, "<target>" | "<admin>" | "<other>")
                            }
                    }) {
                        *v = json!(name);
                    }
                }
            }
        }
        Value::String(s) => {
            if matches!(
                key,
                "resolved_at" | "set_at" | "occurred_at" | "at" | "updated_at"
            ) && !s.starts_with("2026-10-01")
            {
                *s = "<timestamp>".into();
            } else if matches!(key, "checksum" | "prev_checksum") && !s.is_empty() {
                *s = "<checksum>".into();
            }
        }
        _ => {}
    }
}

/// Conflict and user ids share a number space; name the conflict rows first.
fn name_conflicts(v: &mut Value, conflicts: &[(i64, &str)]) {
    for row in v["conflicts"].as_array_mut().into_iter().flatten() {
        if let Some((_, name)) = conflicts
            .iter()
            .find(|(i, _)| Some(*i) == row["id"].as_i64())
        {
            row["id"] = json!(name);
        }
    }
}

async fn rows(c: &tokio_postgres::Client, sql: &str, ids: &[i64]) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[&ids])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}
async fn snapshot(
    c: &tokio_postgres::Client,
    users: &[i64],
    mailboxes: &[i64],
) -> Result<Value, BoxError> {
    Ok(json!({
        "conflicts": rows(c, "SELECT to_jsonb(s)::text FROM sync_conflicts s WHERE user_id=ANY($1) ORDER BY id", users).await?,
        "policy": rows(c, "SELECT to_jsonb(p)::text FROM field_policy p WHERE user_id=ANY($1) ORDER BY user_id,field", users).await?,
        "principal": rows(c, "SELECT jsonb_build_object('id',id,'krb5',krb5_principal)::text FROM users WHERE id=ANY($1) ORDER BY id", users).await?,
        "state": rows(c, "SELECT jsonb_build_object('mailbox',id,'email',jmap_email_state,'tags',jmap_mailbox_state)::text FROM mailboxes WHERE id=ANY($1) ORDER BY id", mailboxes).await?,
    }))
}

/// Cases share fixed fixture keys and global windows (audit id, receipts), so they run one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn run(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(action, kind, fault).await
}

async fn run_inner(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(mut db) = Db::for_case("dirsync-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "dirsync1-admin").await?;
    let b = fixture::account(&owner, "dirsync1-other").await?;
    let unique: String = owner
        .query_one("SELECT replace(gen_random_uuid()::text,'-','')", &[])
        .await?
        .get(0);
    let target_email = format!(
        "dirsync1-target-{unique}@{}",
        fixture_domain(&owner, a.domain).await?
    );
    let target: i64 = owner
        .query_one(
            "INSERT INTO users(username,email,domain_id,display_name,password_hash) VALUES($1,$1,$2,'Target <one>','x') RETURNING id",
            &[&target_email, &a.domain],
        )
        .await?
        .get(0);
    let domain_a = fixture_domain(&owner, a.domain).await?;
    let domain_b = fixture_domain(&owner, b.domain).await?;
    // Grant shapes: global admin, scoped to the other domain, or revoked.
    let (permissions, scope): (Vec<&str>, Option<i64>) = match (action, label) {
        ("config" | "ldap-config" | "policy-get", "foreign") => (vec![], None),
        (_, "foreign" | "scoped-foreign") => (vec!["users.read", "identity.write"], Some(b.domain)),
        _ => (vec!["users.read", "identity.write"], None),
    };
    let role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3) RETURNING id",
            &[&format!("dirsync1-{}", a.user), &permissions, &scope],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
    // Deterministic rows, removed with the fixture.
    let conflict = |user: i64,
                    source: &'static str,
                    resolved: bool,
                    field: &'static str,
                    detected: &'static str| {
        let query = "INSERT INTO sync_conflicts(user_id,field,local_value,remote_value,source,detected_at,resolved_at,resolution) VALUES($1,$2,'local <v>','remote & v',$3,$5::text::timestamptz,CASE WHEN $4 THEN '2026-10-01T12:30:00Z'::timestamptz END,CASE WHEN $4 THEN 'kept_local' END) RETURNING id";
        let owner = &owner;
        async move {
            Ok::<i64, BoxError>(
                owner
                    .query_one(query, &[&user, &field, &source, &resolved, &detected])
                    .await?
                    .get(0),
            )
        }
    };
    let c1 = conflict(
        target,
        "ad",
        false,
        "displayName",
        "2026-10-01T12:00:01.25Z",
    )
    .await?;
    let c2 = conflict(b.user, "ad", false, "title", "2026-10-01T12:00:02.5Z").await?;
    let c3 = conflict(target, "ad", true, "phone", "2026-10-01T12:00:03Z").await?;
    let c4 = conflict(target, "ldap", false, "mail", "2026-10-01T12:00:04Z").await?;
    owner.execute("INSERT INTO field_policy(user_id,field,policy,set_at) VALUES($1,'title','local_only','2026-10-01T12:00:00Z'),($1,'phone','local_only','2026-10-01T12:00:00Z')", &[&target]).await?;
    owner
        .execute(
            "UPDATE users SET krb5_principal='old@CORP.EXAMPLE' WHERE id=$1",
            &[&target],
        )
        .await?;
    let ledger_swap = action == "ldap-sync-log";
    let logs: Vec<i64> = if action == "sync-log" || ledger_swap {
        let mut out = vec![];
        for (source, checked, error, details, at) in [
            (
                "ad",
                3,
                None,
                r#"{"zeta": "<a&b>", "alpha": [1, 2.50, true], "nested": {"k": null}}"#,
                "2026-10-01T12:00:00.5Z",
            ),
            (
                "ad",
                7,
                Some("boom"),
                r#"{"error": "x"}"#,
                "2026-10-01T11:00:00Z",
            ),
            ("ldap", 9, None, r#"{}"#, "2026-10-01T13:00:00Z"),
        ] {
            // The LDAP ledger case seeds the mirror image: its rows are the LDAP ones.
            let source = if ledger_swap {
                if source == "ad" {
                    "ldap"
                } else {
                    "ad"
                }
            } else {
                source
            };
            out.push(owner.query_one("INSERT INTO identity_sync_log(sync_at,source,users_checked,users_created,users_updated,users_disabled,fields_skipped,duration_ms,error,details) VALUES($4::text::timestamptz,$1,$2,1,2,3,4,2500,$3,$5::text::jsonb) RETURNING id", &[&source, &checked, &error, &at, &details]).await?.get(0));
        }
        out
    } else {
        vec![]
    };
    let ldap = action == "ldap-config";
    let scope_sql = if ldap {
        "key LIKE 'ldap_sync_%'"
    } else {
        "key LIKE 'ad_sync_%' OR key LIKE 'enable_%_reset'"
    };
    let saved_config = owner
        .query(
            &format!("SELECT key,value::text,encrypted,description FROM system_config WHERE {scope_sql}"),
            &[],
        )
        .await?;
    let config_keys: &[&str] = if ldap {
        &[
            "ldap_sync_host",
            "ldap_sync_password_enc",
            "ldap_sync_port",
            "ldap_sync_null",
            "ldap_sync_number",
            "ldap_sync_tls",
        ]
    } else {
        &[
            "ad_sync_domain",
            "ad_sync_password_enc",
            "ad_sync_interval_min",
            "ad_sync_null",
            "ad_sync_number",
            "enable_dirsync1_reset",
        ]
    };
    if action == "config" || ldap {
        owner
            .execute(&format!("DELETE FROM system_config WHERE {scope_sql}"), &[])
            .await?;
        let seed: [(&str, &str, bool); 6] = if ldap {
            [
                ("ldap_sync_host", r#""ldap.<example>""#, false),
                ("ldap_sync_password_enc", r#""v1.ciphertext""#, true),
                ("ldap_sync_port", r#""636""#, false),
                ("ldap_sync_null", "null", false),
                ("ldap_sync_number", "5", false),
                ("ldap_sync_tls", r#""true""#, false),
            ]
        } else {
            [
                ("ad_sync_domain", r#""corp.<example>""#, false),
                ("ad_sync_password_enc", r#""v1.ciphertext""#, true),
                ("ad_sync_interval_min", r#""30""#, false),
                ("ad_sync_null", "null", false),
                ("ad_sync_number", "5", false),
                ("enable_dirsync1_reset", r#""true""#, false),
            ]
        };
        for (key, value, encrypted) in seed {
            owner
                .execute(
                    "INSERT INTO system_config(key,value,encrypted) VALUES($1,$2::text::jsonb,$3)",
                    &[&key, &value, &encrypted],
                )
                .await?;
        }
    }
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F02'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    // Faults run real mutated database objects against the unchanged expectation.
    let schema = format!("gofree_dirsync1_fault_{}", a.user);
    let mut private = false;
    let mut trigger = None;
    match fault {
        Some("no-audit") => {
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.user_id={} THEN RETURN NULL; END IF; RETURN NEW; END $fault$;CREATE TRIGGER {schema} BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION {schema}.fault();", a.user)).await?;
            trigger = Some("admin_audit_log");
        }
        Some("double-bump") => {
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.resolved_at IS NOT NULL AND NEW.user_id={target} THEN UPDATE mailboxes SET jmap_email_state=jmap_email_state+2 WHERE id={}; END IF; RETURN NEW; END $fault$;CREATE TRIGGER {schema} AFTER UPDATE ON sync_conflicts FOR EACH ROW EXECUTE FUNCTION {schema}.fault();", a.mailbox)).await?;
            trigger = Some("sync_conflicts");
        }
        Some("no-notify") => {
            let start = REDUCER
                .find("    PERFORM app_notify(")
                .ok_or("notify call")?;
            let end =
                REDUCER[start..].find("::text);").ok_or("notify end")? + start + "::text);".len();
            let body = format!("{}{}", &REDUCER[..start], &REDUCER[end..]);
            let body = body.replace(
                "CREATE OR REPLACE FUNCTION ad_principal_set(",
                &format!("CREATE FUNCTION {schema}.ad_principal_set("),
            );
            let body = &body[..body
                .find("SELECT apply_worker_ownership(")
                .ok_or("ownership")?];
            owner
                .batch_execute(&format!(
                    "CREATE SCHEMA {schema};GRANT USAGE ON SCHEMA {schema} TO setjoin_app;{body}"
                ))
                .await?;
            private = true;
        }
        Some("no-tenant-filter") => {
            let columns: String = owner
                .query_one("SELECT string_agg(quote_ident(column_name),',' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name<>'domain_id'", &[])
                .await?
                .get(0);
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE VIEW {schema}.users AS SELECT {columns},{} AS domain_id FROM public.users;GRANT USAGE ON SCHEMA {schema} TO setjoin_app;GRANT SELECT ON {schema}.users TO setjoin_app;", b.domain)).await?;
            private = true;
        }
        _ => {}
    }
    if private {
        db.app = Some(format!(
            "{}{}options=-csearch_path%3D{schema}%2Cpublic",
            db.app.as_deref().unwrap_or(&db.dsn),
            if db.app.as_deref().unwrap_or(&db.dsn).contains('?') {
                "&"
            } else {
                "?"
            }
        ));
    }
    let ids: Vec<(i64, &str)> = vec![
        (target, "<target>"),
        (a.user, "<admin>"),
        (b.user, "<other>"),
        (c1, "<conflict-1>"),
        (c2, "<conflict-2>"),
        (c3, "<conflict-3>"),
        (c4, "<conflict-4>"),
        (a.mailbox, "<admin-mailbox>"),
        (b.mailbox, "<other-mailbox>"),
    ];
    let result = async {
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-dirsync1-http").await?;
        let recording = go.is_some();
        let exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let adapter = Probe {
            inner: DirectorySyncRoute { exec, keys: Arc::new(common::recovery_keys()), issuer: "mailserver".into(), ldap: None, ad: None },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            let ldap_read = r["method"] == "GET" && matches!(r["path"].as_str(), Some("/admin/ldap/config" | "/admin/ldap/sync-log"));
            if r["family"] == "F02" && (r["slice"] == "ad-admin" || ldap_read) {
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
        let (method, pattern) = route(action);
        // Request shape per case; mutators repeat the committed request once first.
        let mut path = pattern.replace("{id}", &if label == "invalid" { "bad".into() } else { c1.to_string() });
        let mut query = String::new();
        let mut body = String::new();
        match action {
            "resolve" | "resolve-all" => body = if label == "invalid" && action == "resolve-all" { r#"{"resolution":"nope"}"#.into() } else if label == "bad-resolution" { r#"{"resolution":"merge"}"#.into() } else if label == "accept" { r#"{"resolution":"accept_remote"}"#.into() } else { r#"{"resolution":"keep_local"}"#.into() },
            "policy-set" => body = match label {
                "invalid" => "{\"userId\":".into(),
                "managed" => json!({"userId":target,"field":"title","policy":"ad_managed"}).to_string(),
                "krb5-managed" => json!({"userId":target,"field":"krb5_principal","policy":"ad_managed"}).to_string(),
                "bad-policy" => json!({"userId":target,"field":"title","policy":"nope"}).to_string(),
                "folded" => json!({"USERID":target,"FIELD":"displayName","Policy":"local_only"}).to_string() + " trailing",
                _ => json!({"userId":target,"field":"displayName","policy":"local_only"}).to_string(),
            },
            "principal" => body = match label {
                "invalid" => json!({"userId":0,"krb5Principal":"x@CORP"}).to_string(),
                "blank" => json!({"userId":target,"krb5Principal":" \t "}).to_string(),
                "missing-user" => json!({"userId":99_999_999,"krb5Principal":"x@CORP"}).to_string(),
                _ => json!({"userId":target,"krb5Principal":" alice@CORP.EXAMPLE "}).to_string(),
            },
            "policy-get" => query = if label == "invalid" { String::new() } else { format!("user_id={target}") },
            "sync-log" | "ldap-sync-log" => query = match label { "invalid" => "limit=abc".into(), "limit" => "limit=1".into(), _ => String::new() },
            "conflicts" | "config" | "ldap-config" => query = if label == "invalid" { "x=%zz&limit=abc;1".into() } else { String::new() },
            _ => {}
        }
        if action == "policy-get" && label == "success" { query = format!("user_id={target}"); }
        if !query.is_empty() { path = format!("{path}?{query}"); }
        let send = |body: String| {
            let uri = format!("/api{}", path.replace("{id}", "x"));
            let token = admin_token(a.user);
            async move {
                Ok::<_, BoxError>(common::send(address, Request::builder().method(method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("content-type", "application/json").header("x-request-id", "gofree-dirsync1-oracle").header("authorization", format!("Bearer {token}")).body(common::full(body))?).await)
            }
        };
        if label == "repeat" {
            let first = send(body.clone()).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && status != 204 {
                return Err(format!("initial {action}: {status} {data:?}").into());
            }
        }
        let users = [target, a.user, b.user];
        let mailboxes = [a.mailbox, b.mailbox];
        let before = snapshot(&owner, &users, &mailboxes).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut alerts = db.listen("admin:alert").await?;
        let response = send(body.clone()).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let after = snapshot(&owner, &users, &mailboxes).await?;
        let audit_raw: Vec<Value> = owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last]).await?.iter().map(|r| serde_json::from_str(&r.get::<_, String>(0))).collect::<Result<_, _>>()?;
        let mut audit = audit_raw;
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) { return Err("invalid audit id".into()); }
            row["id"] = json!("<audit>");
            mask(row, &ids, "");
        }
        let mut notify = vec![];
        for event in alerts.drain(&owner).await? {
            let mut payload: Value = serde_json::from_str(&event)?;
            mask(&mut payload, &ids, "");
            notify.push(json!({"channel":"admin:alert","payload":payload}));
        }
        let wanted = match (action, label) {
            ("config" | "ldap-config" | "policy-get", "foreign") => 403,
            ("policy-get", "invalid") => 400,
            ("resolve", "invalid") => 400,
            ("resolve", "foreign" | "repeat") => 404,
            ("resolve" | "resolve-all", "bad-resolution") => 400,
            ("resolve-all", "invalid") => 400,
            ("policy-set", "invalid" | "krb5-managed" | "bad-policy") => 400,
            ("policy-set", "foreign") => 403,
            ("principal", "invalid" | "blank") => 400,
            ("principal", "foreign") => 403,
            ("principal", "missing-user") => 404,
            ("resolve" | "resolve-all" | "policy-set" | "principal", _) => 204,
            _ => 200,
        };
        if recording && status != wanted {
            return Err(format!("Go {action}/{label}: expected {wanted}, got {status}: {raw}").into());
        }
        // Normalize identities that differ per run; fixtures and timestamps are deterministic.
        let mut text = raw.replace(&target_email, "target@host-a.test").replace(&domain_a, "host-a.test").replace(&domain_b, "host-b.test");
        for (id, name) in &ids[..7] {
            if matches!(*name, "<conflict-1>" | "<conflict-2>" | "<conflict-3>" | "<conflict-4>") {
                text = text.replace(&format!("\"id\":{id},"), &format!("\"id\":\"{}\",", name.trim_matches(['<', '>'])));
            }
        }
        // userId is the last key of a conflict object, so the closing brace ends the number.
        text = text.replace(&format!("\"userId\":{target}}}"), "\"userId\":\"target\"}").replace(&format!("\"userId\":{}}}", b.user), "\"userId\":\"other\"}");
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() { return Err("bad wire length".into()); }
            *length = json!([text.len().to_string()]);
        }
        let (mut before, mut after) = (before, after);
        name_conflicts(&mut before, &ids[3..7]);
        name_conflicts(&mut after, &ids[3..7]);
        mask(&mut before, &ids, "");
        mask(&mut after, &ids, "");
        let effects = json!([{"table":"directory","before":before,"after":after}]);
        let mut request = json!({"method":method,"path":pattern,"external_path":format!("/api{pattern}")});
        if !query.is_empty() { request["query"] = json!(query.replace(&target.to_string(), "<target>")); }
        if !body.is_empty() { request["body"] = json!(body.replace(&target.to_string(), "<target>")); }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F02\"} 0") {
                return Err(format!("F02 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let name = format!("{action}-{label}");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/directory-sync/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("{name}.json"));
        let row_file = dir.join(format!("{name}-row-effects.json"));
        let route_name = format!("{method} {pattern}");
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
        } else {
            let expected: Value = common::golden_doc(&file, "observation", &observation);
            let compared = golden::compare(&expected["observation"], &observation);
            if mutant {
                let error = compared.expect_err("planted status mutant survived");
                if !error.contains("/response/status") { return Err(format!("mutant failed outside response status: {error}").into()); }
                eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
                return Ok(());
            }
            if fault.is_some() {
                let error = compared.expect_err("planted family fault survived");
                eprintln!("MUTANT-REJECTED: {route_name} :: {}", fault.unwrap());
                let _ = error;
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
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
    if let Some(table) = trigger {
        owner
            .batch_execute(&format!("DROP TRIGGER {schema} ON {table}"))
            .await?;
    }
    if fault.is_some() {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F02' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    if action == "config" || ldap {
        owner
            .execute(
                "DELETE FROM system_config WHERE key=ANY($1)",
                &[&config_keys
                    .iter()
                    .map(|k| k.to_string())
                    .collect::<Vec<_>>()],
            )
            .await?;
        for row in &saved_config {
            owner.execute("INSERT INTO system_config(key,value,encrypted,description) VALUES($1,$2::text::jsonb,$3,$4) ON CONFLICT (key) DO NOTHING", &[&row.get::<_, String>(0), &row.get::<_, String>(1), &row.get::<_, bool>(2), &row.get::<_, Option<String>>(3)]).await?;
        }
    }
    owner
        .execute("DELETE FROM identity_sync_log WHERE id=ANY($1)", &[&logs])
        .await?;
    owner
        .execute("DELETE FROM users WHERE id=$1", &[&target])
        .await?;
    owner.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 hour' WHERE role_group_id=$1", &[&role]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&role],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await?;
    common::remove_blob_account(&owner, &a).await?;
    common::remove_blob_account(&owner, &b).await?;
    result
}

async fn fixture_domain(c: &tokio_postgres::Client, id: i64) -> Result<String, BoxError> {
    Ok(c.query_one("SELECT name FROM domains WHERE id=$1", &[&id])
        .await?
        .get(0))
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
