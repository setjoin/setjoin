//! F01 slice `users` frozen-Go oracle: HTTP wire, committed rows and audit.
//! Record mode runs the covered Go binary behind the front door; replay mode
//! serves the same requests from Rust with no Go upstream.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    admin_identity::AdminIdentityRoute, Body, BoxFuture, Config, Gateway, Intercept,
    RequestContext, RouteTable, TrustedProxies,
};
use std::sync::Arc;

struct Probe {
    inner: AdminIdentityRoute<setjoin_gateway::jmap::jwks::Jwks>,
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
        "users" => ("GET", "/admin/users"),
        "user" => ("GET", "/admin/users/{id}"),
        "aliases" => ("GET", "/admin/users/{id}/aliases"),
        "alias-add" => ("POST", "/admin/users/{id}/aliases"),
        "alias-remove" => ("DELETE", "/admin/users/{id}/aliases/{aliasId}"),
        "quota" => ("GET", "/admin/users/{id}/quota"),
        "quota-set" => ("PUT", "/admin/users/{id}/quota"),
        "app-passwords" => ("GET", "/admin/users/{id}/app-passwords"),
        "app-access" => ("GET", "/admin/users/{id}/app-access"),
        "app-access-set" => ("PUT", "/admin/users/{id}/app-access/{app}"),
        "sessions" => ("GET", "/admin/users/{id}/sessions"),
        _ => panic!("unknown F01 users action {action}"),
    }
}

fn timestamp_like(s: &str) -> bool {
    s.len() >= 20 && s.as_bytes()[4] == b'-' && s.as_bytes()[10] == b'T'
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
                "user_id" | "target_id" | "actor_id" | "user" | "by" | "mailbox" | "domain"
            ) {
                // Users, mailboxes and domains draw from separate sequences that
                // can coincide; each key only names its own kind.
                let wanted = match key {
                    "mailbox" => "-mailbox>",
                    "domain" => "-domain>",
                    _ => "",
                };
                if let Some(id) = n.as_i64() {
                    if let Some((_, name)) = ids.iter().find(|(i, name)| {
                        *i == id
                            && if wanted.is_empty() {
                                matches!(*name, "<target>" | "<admin>" | "<other>")
                            } else {
                                name.ends_with(wanted)
                            }
                    }) {
                        *v = json!(name);
                    }
                }
            }
        }
        Value::String(s) => {
            if timestamp_like(s) && !s.starts_with("2026-10-01") {
                *s = "<timestamp>".into();
            } else if matches!(key, "checksum" | "prev_checksum") && !s.is_empty() {
                *s = "<checksum>".into();
            }
        }
        _ => {}
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
        "aliases": rows(c, "SELECT jsonb_build_object('mailbox',mailbox_id,'email',email,'primary',is_primary,'domain',domain_id)::text FROM aliases WHERE mailbox_id=ANY($1) ORDER BY email", mailboxes).await?,
        "quota": rows(c, "SELECT jsonb_build_object('mailbox',id,'quota_bytes',quota_bytes,'sending_quota_day',sending_quota_day,'email',jmap_email_state,'tags',jmap_mailbox_state)::text FROM mailboxes WHERE id=ANY($1) ORDER BY id", mailboxes).await?,
        "entitlements": rows(c, "SELECT jsonb_build_object('user',user_id,'app',app,'enabled',enabled,'by',updated_by)::text FROM user_app_entitlements WHERE user_id=ANY($1) ORDER BY user_id,app", users).await?,
        "passwords": rows(c, "SELECT jsonb_build_object('user',user_id,'name',name,'revoked',revoked_at IS NOT NULL)::text FROM app_passwords WHERE user_id=ANY($1) ORDER BY user_id,name", users).await?,
    }))
}

/// Name the target user and alias ids that appear in request paths (`instance`, audit targets).
fn name_paths(text: &str, target: i64, alias: &str) -> String {
    let mut out = text.to_owned();
    for suffix in ["/", "\"", "?", "\\", "|"] {
        out = out.replace(
            &format!("/admin/users/{target}{suffix}"),
            &format!("/admin/users/<target>{suffix}"),
        );
        if !alias.is_empty() {
            out = out.replace(
                &format!("/aliases/{alias}{suffix}"),
                &format!("/aliases/<alias>{suffix}"),
            );
        }
    }
    out
}

/// Replace `"key":N` and `"key":"N"` occurrences for the named ids.
fn name_ids(text: &str, key: &str, ids: &[(i64, String)]) -> String {
    let mut out = text.to_owned();
    for (id, name) in ids {
        out = out
            .replace(
                &format!("\"{key}\":{id},"),
                &format!("\"{key}\":\"{name}\","),
            )
            .replace(
                &format!("\"{key}\":{id}}}"),
                &format!("\"{key}\":\"{name}\"}}"),
            )
            .replace(
                &format!("\"{key}\":\"{id}\""),
                &format!("\"{key}\":\"{name}\""),
            );
    }
    out
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
    let Some(mut db) = Db::for_case("admin1-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "admin1-admin").await?;
    let b = fixture::account(&owner, "admin1-other").await?;
    let t = fixture::account(&owner, "admin1-target").await?;
    let domain_of = |id: i64| {
        let owner = &owner;
        async move {
            Ok::<String, BoxError>(
                owner
                    .query_one("SELECT name FROM domains WHERE id=$1", &[&id])
                    .await?
                    .get(0),
            )
        }
    };
    let (domain_a, domain_b, domain_t) = (
        domain_of(a.domain).await?,
        domain_of(b.domain).await?,
        domain_of(t.domain).await?,
    );
    // Deterministic creation times exercise Go's trimmed RFC 3339 rendering.
    for (user, at) in [
        (a.user, "2026-10-01T12:00:00Z"),
        (b.user, "2026-10-01T12:00:01.5Z"),
        (t.user, "2026-10-01T12:00:02.25Z"),
    ] {
        owner
            .execute(
                "UPDATE users SET created_at=$2::text::timestamptz WHERE id=$1",
                &[&user, &at],
            )
            .await?;
    }
    // Grant shapes: global admin, scoped to the other (or the target's) domain, or none.
    let granted = vec!["users.read", "users.create"];
    let (permissions, scope): (Vec<&str>, Option<i64>) = match label {
        "denied" => (vec![], None),
        "foreign" => (granted, Some(b.domain)),
        "scoped" => (granted, Some(t.domain)),
        _ => (granted, None),
    };
    let role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3) RETURNING id",
            &[&format!("admin1-{}", a.user), &permissions, &scope],
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
    let alt = format!("admin1-alt@{domain_t}");
    owner
        .execute(
            "INSERT INTO aliases(mailbox_id,email,domain_id) VALUES($1,$2,$3)",
            &[&t.mailbox, &alt, &t.domain],
        )
        .await?;
    for (name, last, expires, revoked) in [
        ("laptop", Some("2026-10-01T10:00:00.125Z"), None, None),
        (
            "phone",
            None,
            Some("2027-01-01T00:00:00Z"),
            Some("2026-10-01T11:00:00Z"),
        ),
        ("watch", None, None, None),
    ] {
        owner
            .execute(
                "INSERT INTO app_passwords(user_id,name,token_hash,created_at,last_used_at,expires_at,revoked_at) VALUES($1,$2,$3,'2026-10-01T09:00:00Z',$4::text::timestamptz,$5::text::timestamptz,$6::text::timestamptz)",
                &[&t.user, &name, &format!("admin1-{name}-{}", t.user), &last, &expires, &revoked],
            )
            .await?;
    }
    owner
        .execute(
            "INSERT INTO user_app_entitlements(user_id,app,enabled,updated_by) VALUES($1,'chat',false,$1)",
            &[&t.user],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO sessions(id,user_id,expires_at,last_seen_at,ip,user_agent,auth_method) VALUES('admin1-session',$1,now()+interval '1 day','2026-10-01T10:00:00.9Z','192.0.2.7','Agent <1>','password')",
            &[&t.user],
        )
        .await?;
    let oauth: i64 = owner
        .query_one(
            "INSERT INTO oauth_tokens(user_id,client_id,token_hash,token_type,issued_at,expires_at,last_used_at,last_used_protocol) VALUES($1,'admin1-client',$2,'refresh','2026-10-01T08:00:00Z',now()+interval '1 day',NULL,'imap') RETURNING id",
            &[&t.user, &format!("admin1-oauth-{}", t.user).into_bytes()],
        )
        .await?
        .get(0);
    let aliases: Vec<(i64, String)> = owner
        .query(
            "SELECT id, replace(email,'@'||$2,'@host-t.test') FROM aliases WHERE mailbox_id=$1",
            &[&t.mailbox, &domain_t],
        )
        .await?
        .iter()
        .map(|r| {
            let id: i64 = r.get(0);
            let email: String = r.get(1);
            (id, format!("alias:{email}"))
        })
        .collect();
    let passwords: Vec<(i64, String)> = owner
        .query(
            "SELECT id,name FROM app_passwords WHERE user_id=$1",
            &[&t.user],
        )
        .await?
        .iter()
        .map(|r| (r.get(0), format!("password:{}", r.get::<_, String>(1))))
        .collect();
    // Go's usage recount would otherwise write the fixture's message sizes into the golden.
    for mailbox in [a.mailbox, b.mailbox, t.mailbox] {
        owner
            .execute("DELETE FROM messages WHERE mailbox_id=$1", &[&mailbox])
            .await?;
        owner
            .execute("UPDATE mailboxes SET used_bytes=0 WHERE id=$1", &[&mailbox])
            .await?;
    }
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F01'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    // Faults run real mutated database objects against the unchanged expectation.
    let schema = format!("gofree_admin1_fault_{}", a.user);
    let mut private = false;
    let mut trigger = None;
    match fault {
        Some("no-audit") => {
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.user_id={} THEN RETURN NULL; END IF; RETURN NEW; END $fault$;CREATE TRIGGER {schema} BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION {schema}.fault();", a.user)).await?;
            trigger = Some("admin_audit_log");
        }
        Some("double-bump") => {
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.id={} THEN UPDATE mailboxes SET jmap_email_state=jmap_email_state+2 WHERE id={}; END IF; RETURN NEW; END $fault$;CREATE TRIGGER {schema} AFTER UPDATE ON mailboxes FOR EACH ROW EXECUTE FUNCTION {schema}.fault();", t.mailbox, a.mailbox)).await?;
            trigger = Some("mailboxes");
        }
        Some("no-tenant-filter") => {
            // Private views that pin every row to the scoped admin's domain.
            let mut statements =
                format!("CREATE SCHEMA {schema};GRANT USAGE ON SCHEMA {schema} TO setjoin_app;");
            for table in ["users", "mailboxes"] {
                let columns: String = owner
                    .query_one("SELECT string_agg(quote_ident(column_name),',' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name<>'domain_id'", &[&table])
                    .await?
                    .get(0);
                statements.push_str(&format!("CREATE VIEW {schema}.{table} AS SELECT {columns},{}::bigint AS domain_id FROM public.{table};GRANT SELECT,UPDATE ON {schema}.{table} TO setjoin_app;", b.domain));
            }
            owner.batch_execute(&statements).await?;
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
        (t.user, "<target>"),
        (a.user, "<admin>"),
        (b.user, "<other>"),
        (a.mailbox, "<admin-mailbox>"),
        (b.mailbox, "<other-mailbox>"),
        (t.mailbox, "<target-mailbox>"),
        (a.domain, "<admin-domain>"),
        (b.domain, "<other-domain>"),
        (t.domain, "<target-domain>"),
    ];
    let result = async {
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-admin1-http").await?;
        let recording = go.is_some();
        let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?
            .with_audit_keys("22".repeat(32), String::new());
        let adapter = Probe {
            inner: AdminIdentityRoute { exec, keys: Arc::new(common::recovery_keys()), issuer: "mailserver".into() },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F01" && r["slice"] == "users" {
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
        let user_part = match label {
            "invalid" if !matches!(action, "quota-set" | "alias-add") => "bad".to_string(),
            "zero" => "0".to_string(),
            "missing-user" | "missing" => "99999999".to_string(),
            _ => t.user.to_string(),
        };
        let alias_part = match (action, label) {
            ("alias-remove", "invalid") => "bad".to_string(),
            _ => aliases.iter().find(|(_, n)| n.contains("alt")).map(|(i, _)| i.to_string()).unwrap_or_default(),
        };
        let app_part = match (action, label) {
            ("app-access-set", "bad-app") => "nope".to_string(),
            ("app-access-set", "update") => "chat".to_string(),
            _ => "tasks".to_string(),
        };
        let mut path = pattern.replace("{id}", &user_part).replace("{aliasId}", &alias_part).replace("{app}", &app_part);
        let mut query = String::new();
        let mut body = String::new();
        match (action, label) {
            ("users", "invalid") => query = "limit=abc&offset=-5&q=%zz&x=1;2".into(),
            ("users", "filtered") => query = "q=ADMIN1-oth".into(),
            ("users", "paged") => query = "q=admin1-&limit=1&offset=1".into(),
            ("users", _) => query = "q=admin1-".into(),
            ("alias-add", l) => body = match l {
                "invalid" => "{\"email\":".into(),
                "empty" => json!({"email":""}).to_string(),
                "bad-email" => json!({"email":"not-an-email"}).to_string(),
                "reserved" => json!({"email":format!("postmaster@{domain_t}")}).to_string(),
                "dup" => json!({"email":alt}).to_string(),
                "folded" => json!({"EMAIL":format!(" Admin1-New@{} ", domain_t.to_uppercase())}).to_string() + " trailing",
                _ => json!({"email":format!("Admin1-New@{domain_t}")}).to_string(),
            },
            ("quota-set", l) => body = match l {
                "invalid" => "{}".into(),
                "bad-json" => "{\"quotaBytes\":".into(),
                "partial" => json!({"quotaBytes":5000}).to_string(),
                "nonpositive" => json!({"quotaBytes":-1,"sendingQuotaDay":0}).to_string(),
                "folded" => json!({"QUOTABYTES":4096,"sendingQuotaDay":null}).to_string() + " trailing",
                _ => json!({"quotaBytes":123456789,"sendingQuotaDay":77}).to_string(),
            },
            ("app-access-set", l) => body = match l {
                "bad-body" => json!({"enabled":"yes"}).to_string(),
                "empty" => String::new(),
                "update" => json!({"enabled":true}).to_string(),
                _ => json!({"enabled":false}).to_string(),
            },
            _ => {}
        }
        if !query.is_empty() { path = format!("{path}?{query}"); }
        let send = |body: String| {
            let uri = format!("/api{path}");
            let token = admin_token(a.user);
            async move {
                Ok::<_, BoxError>(common::send(address, Request::builder().method(method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("content-type", "application/json").header("x-request-id", "gofree-admin1-oracle").header("authorization", format!("Bearer {token}")).body(common::full(body))?).await)
            }
        };
        if label == "repeat" {
            let first = send(body.clone()).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && !matches!(status, 201 | 204) {
                return Err(format!("initial {action}: {status} {data:?}").into());
            }
        }
        let users = [t.user, a.user, b.user];
        let mailboxes = [a.mailbox, b.mailbox, t.mailbox];
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
            let text = name_paths(&row.to_string().replace(&domain_a, "host-a.test").replace(&domain_b, "host-b.test").replace(&domain_t, "host-t.test"), t.user, &alias_part)
                .replace(&format!("domain={}", b.domain), "domain=<other-domain>")
                .replace(&format!("domain={}", t.domain), "domain=<target-domain>");
            *row = serde_json::from_str(&text)?;
            mask(row, &ids, "");
        }
        let mut notify = vec![];
        for event in alerts.drain(&owner).await? {
            let mut payload: Value = serde_json::from_str(&event)?;
            mask(&mut payload, &ids, "");
            notify.push(json!({"channel":"admin:alert","payload":payload}));
        }
        let wanted = match (action, label) {
            ("sessions", "foreign" | "scoped") => 403,
            (_, "denied") => 403,
            ("user" | "quota" | "quota-set" | "alias-add", "foreign") => 404,
            ("app-access-set", "foreign" | "missing-user") => 404,
            ("sessions", "missing") => 404,
            ("quota", "missing") => 404,
            ("app-access-set", "bad-app") => 422,
            ("user" | "user-get", "missing") => 404,
            (_, "invalid" | "zero") if action == "alias-add" => 400,
            ("alias-add", "empty" | "bad-email" | "reserved") => 400,
            ("alias-add", "dup" | "repeat") => 409,
            ("alias-add", _) => 201,
            ("quota-set", "invalid" | "bad-json" | "nonpositive") => 400,
            ("app-access-set", "bad-body" | "empty") => 400,
            ("alias-remove", "invalid") => 400,
            ("app-access-set", "invalid") => 400,
            ("aliases", "zero") => 400,
            ("app-access-set" | "quota-set" | "alias-remove", _) => 204,
            ("users" | "aliases" | "app-passwords" | "app-access", "invalid") if action != "users" => 400,
            ("user" | "quota" | "sessions", "invalid") => 400,
            ("user" | "quota" | "sessions", "zero") => 400,
            _ => 200,
        };
        if recording && status != wanted {
            return Err(format!("Go {action}/{label}: expected {wanted}, got {status}: {raw}").into());
        }
        // Normalize identities that differ per run; fixtures are otherwise deterministic.
        let mut text = name_paths(&raw.replace(&domain_a, "host-a.test").replace(&domain_b, "host-b.test").replace(&domain_t, "host-t.test"), t.user, &alias_part);
        let named = |list: &[(i64, &str)]| list.iter().map(|(i, n)| (*i, n.trim_matches(['<', '>']).to_string())).collect::<Vec<_>>();
        text = match action {
            "users" | "user" => {
                let users = named(&ids[..3]);
                let mailboxes = named(&ids[3..6]);
                name_ids(&name_ids(&text, "id", &users), "mailboxId", &mailboxes)
            }
            "aliases" => name_ids(&text, "id", &aliases),
            "app-passwords" => name_ids(&text, "id", &passwords),
            "sessions" => name_ids(&text, "id", &[(oauth, "oauth".to_string())]),
            "alias-add" if status == 201 => {
                let created: i64 = owner.query_one("SELECT id FROM aliases WHERE mailbox_id=$1 AND email=lower($2)", &[&t.mailbox, &format!("Admin1-New@{domain_t}")]).await?.get(0);
                name_ids(&text, "id", &[(created, "new-alias".to_string())])
            }
            _ => text,
        };
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() { return Err("bad wire length".into()); }
            *length = json!([text.len().to_string()]);
        }
        let (mut before, mut after) = (before, after);
        for state in [&mut before, &mut after] {
            let text = state.to_string().replace(&domain_a, "host-a.test").replace(&domain_b, "host-b.test").replace(&domain_t, "host-t.test");
            *state = serde_json::from_str(&text)?;
            mask(state, &ids, "");
        }
        let effects = json!([{"table":"users","before":before,"after":after}]);
        let mut request = json!({"method":method,"path":pattern,"external_path":format!("/api{pattern}")});
        let scrub = |s: &str| s.replace(&domain_t, "host-t.test").replace(&domain_t.to_uppercase(), "HOST-T.TEST");
        if !query.is_empty() { request["query"] = json!(scrub(&query)); }
        if !body.is_empty() { request["body"] = json!(scrub(&body)); }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F01\"} 0") {
                return Err(format!("F01 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let name = format!("{action}-{label}");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/admin-identity/goldens");
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
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F01' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    let all = vec![t.user, a.user, b.user];
    let boxes = vec![a.mailbox, b.mailbox, t.mailbox];
    owner
        .execute(
            "DELETE FROM aliases WHERE mailbox_id=ANY($1) AND NOT is_primary",
            &[&boxes],
        )
        .await?;
    owner
        .execute("DELETE FROM app_passwords WHERE user_id=ANY($1)", &[&all])
        .await?;
    owner
        .execute(
            "DELETE FROM user_app_entitlements WHERE user_id=ANY($1)",
            &[&all],
        )
        .await?;
    owner
        .execute("DELETE FROM sessions WHERE user_id=ANY($1)", &[&all])
        .await?;
    owner
        .execute("DELETE FROM oauth_tokens WHERE user_id=ANY($1)", &[&all])
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
    for account in [&a, &b, &t] {
        common::remove_blob_account(&owner, account).await?;
    }
    result
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
