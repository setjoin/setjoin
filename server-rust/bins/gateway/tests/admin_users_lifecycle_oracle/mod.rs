//! F01 slice `user-lifecycle` frozen-Go oracle: HTTP wire, committed rows, audit,
//! notifications, welcome mail and the authserver revocation call for create,
//! update, delete, password reset, import, secure-account, sign-ins and
//! app-password revocation. Record mode runs the covered Go binary behind the front
//! door; replay serves the same requests from Rust with no Go upstream.
//!
//! Parallel safety: every case shares the global webhook-outbox and mailbox-lifecycle
//! toggles, the common-password list, the admin audit window and the F01 receipts,
//! so each case holds `SERIAL` for its whole run (taken in `run`, not re-entrant).
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    admin_users_lifecycle::AdminUsersLifecycleRoute, Body, BoxFuture, Config, Gateway, Intercept,
    RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::{Arc, Mutex};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const INTERNAL_KEY: &str = "gofree-admin6-internal-key";

struct Probe {
    inner: AdminUsersLifecycleRoute<setjoin_gateway::jmap::jwks::Jwks>,
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
        "create" => ("POST", "/admin/users"),
        "import" => ("POST", "/admin/users/import"),
        "update" => ("PUT", "/admin/users/{id}"),
        "delete" => ("DELETE", "/admin/users/{id}"),
        "password" => ("PUT", "/admin/users/{id}/password"),
        "secure" => ("POST", "/admin/users/{id}/secure-account"),
        "sign-ins" => ("GET", "/admin/users/{id}/sign-ins"),
        "app-password-revoke" => ("DELETE", "/admin/users/{userId}/app-passwords/{apId}"),
        _ => panic!("unknown F01 user-lifecycle action {action}"),
    }
}

// Fixed role ids keep the goldens free of run-specific numbers.
const ROLE: i64 = 950001;
const MISSING: i64 = 99999999;
const PASSWORD: &str = "Str0ng!Passw0rd";

fn timestamp_like(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && (b[10] == b'T' || b[10] == b' ')
        && b[13] == b':'
}

/// Mask run-specific identities by the key that names them.
fn mask(v: &mut Value, users: &[(i64, String)], app_passwords: &[(i64, &str)]) {
    match v {
        Value::Object(map) => {
            let kind = map
                .get("target_type")
                .and_then(Value::as_str)
                .map(str::to_owned);
            for (k, x) in map.iter_mut() {
                if let Some(n) = x.as_i64() {
                    let user = matches!(
                        k.as_str(),
                        "user_id" | "actor_id" | "actor" | "granted_by" | "created_by"
                    ) || (k == "target_id" && kind.as_deref() != Some("app_password"));
                    if user {
                        if let Some((_, name)) = users.iter().find(|(i, _)| *i == n) {
                            *x = json!(name);
                        }
                    }
                    if k == "sessions_revoked" {
                        *x = json!("<revocation>");
                    }
                    if k == "mailbox_id" {
                        *x = json!("<mailbox>");
                    }
                    if k == "domain_id" {
                        *x = json!("<domain>");
                    }
                    if k == "target_id" && kind.as_deref() == Some("app_password") {
                        if let Some((_, name)) = app_passwords.iter().find(|(i, _)| *i == n) {
                            *x = json!(name);
                        }
                    }
                } else {
                    mask(x, users, app_passwords);
                }
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask(x, users, app_passwords)),
        Value::String(s) => {
            if timestamp_like(s) && !s.starts_with("2026-10-01") {
                *s = "<timestamp>".into();
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

/// The committed state this slice can touch, keyed by the fixture email prefix.
async fn snapshot(c: &tokio_postgres::Client) -> Result<Value, BoxError> {
    let mine = "u.email LIKE 'admin6-%'";
    Ok(json!({
        "users": rows(c, &format!("SELECT jsonb_build_object('email',u.email,'username',u.username,'display_name',u.display_name,'enabled',u.enabled,'is_local_admin',u.is_local_admin,'must_change_password',u.must_change_password,'hash',CASE WHEN u.password_hash IS NULL THEN NULL WHEN u.password_hash='x' THEN 'x' WHEN u.password_hash ~ '^\\$2a\\$10\\$[./A-Za-z0-9]{{53}}$' THEN '<bcrypt-2a-10>' ELSE '<other-hash>' END,'domain',d.name,'department',u.department_id IS NOT NULL)::text FROM users u JOIN domains d ON d.id=u.domain_id WHERE {mine} ORDER BY u.email")).await?,
        "mailboxes": rows(c, "SELECT jsonb_build_object('email',m.email,'type',m.type,'primary',m.is_primary,'quota',m.quota_bytes)::text FROM mailboxes m WHERE m.email LIKE 'admin6-%' ORDER BY m.email").await?,
        "sessions": rows(c, &format!("SELECT jsonb_build_object('user',u.email)::text FROM sessions s JOIN users u ON u.id=s.user_id WHERE {mine} ORDER BY u.email,s.id")).await?,
        "oauth_tokens": rows(c, &format!("SELECT jsonb_build_object('user',u.email,'type',t.token_type,'revoked',t.revoked_at IS NOT NULL,'revoked_by',(SELECT email FROM users r WHERE r.id=t.revoked_by))::text FROM oauth_tokens t JOIN users u ON u.id=t.user_id WHERE {mine} ORDER BY u.email,t.id")).await?,
        "app_passwords": rows(c, &format!("SELECT jsonb_build_object('user',u.email,'name',p.name,'revoked',p.revoked_at IS NOT NULL)::text FROM app_passwords p JOIN users u ON u.id=p.user_id WHERE {mine} ORDER BY u.email,p.name")).await?,
        "role_assignments": rows(c, &format!("SELECT jsonb_build_object('user',u.email,'role',g.name)::text FROM admin_role_assignments a JOIN users u ON u.id=a.user_id JOIN admin_role_groups g ON g.id=a.role_group_id WHERE {mine} AND g.id<>{ROLE} ORDER BY u.email,g.name")).await?,
        "publications": rows(c, "SELECT jsonb_build_object('type',p.event_type,'source',p.source,'audience',p.audience,'user',(SELECT email FROM users s WHERE s.id=p.subject_user_id),'payload_keys',(SELECT jsonb_agg(k ORDER BY k) FROM jsonb_object_keys(p.payload) k),'event_prefix',split_part(p.event_id,'-',1))::text FROM webhook_publications p WHERE p.event_id LIKE 'usr%' ORDER BY p.id").await?,
        "welcome": rows(c, "SELECT jsonb_build_object('user',(SELECT email FROM users s WHERE s.id=mb.user_id),'subject',m.subject,'from',m.from_addr,'to',m.to_addrs,'raw_ref',regexp_replace(m.raw_ref,'[0-9]+$','<id>'))::text FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.raw_ref LIKE 'system:welcome:%' AND mb.email LIKE 'admin6-%' ORDER BY mb.email").await?,
    }))
}

pub async fn run(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(action, kind, fault).await
}

fn scoped_label(label: &str) -> bool {
    label.starts_with("scoped") || label == "foreign"
}

/// A multipart form with one part named `field`.
fn form(field: &str, filename: Option<&str>, content: &str) -> String {
    let disposition = match filename {
        Some(name) => format!("form-data; name=\"{field}\"; filename=\"{name}\""),
        None => format!("form-data; name=\"{field}\""),
    };
    format!("--gofree-boundary\r\nContent-Disposition: {disposition}\r\nContent-Type: text/csv\r\n\r\n{content}\r\n--gofree-boundary--\r\n")
}

async fn run_inner(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(db) = Db::for_case("admin6-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "admin6-admin").await?;
    let b = fixture::account(&owner, "admin6-other").await?;
    let t = fixture::account(&owner, "admin6-third").await?;
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
    let domain_names = [
        (domain_a.clone(), "host-a.test"),
        (domain_b.clone(), "host-b.test"),
        (domain_t.clone(), "host-t.test"),
    ];
    let names = |text: &str| {
        let mut out = text.to_owned();
        for (domain, name) in &domain_names {
            out = out.replace(domain.as_str(), name);
        }
        out
    };
    // Extra accounts inside the admin's domain: an ordinary target, a guest, and an
    // account carrying credentials a reset, a secure or a delete must clear.
    let make = |label: &'static str| {
        let owner = &owner;
        let domain_a = domain_a.clone();
        let domain = a.domain;
        async move {
            let email = format!("{label}@{domain_a}");
            let user: i64 = owner
                .query_one(
                    "INSERT INTO users (username, domain_id, email, display_name, password_hash) VALUES ($1,$2,$1,$3,'x') RETURNING id",
                    &[&email, &domain, &label],
                )
                .await?
                .get(0);
            let mut mailbox: i64 = owner
                .query_one("SELECT nextval('mailboxes_id_seq')", &[])
                .await?
                .get(0);
            if mailbox == user {
                mailbox = owner
                    .query_one("SELECT nextval('mailboxes_id_seq')", &[])
                    .await?
                    .get(0);
            }
            owner
                .execute(
                    "INSERT INTO mailboxes (id,user_id,domain_id,email,display_name,type,is_primary) VALUES ($1,$2,$3,$4,$5,'personal',TRUE)",
                    &[&mailbox, &user, &domain, &email, &label],
                )
                .await?;
            Ok::<(i64, i64), BoxError>((user, mailbox))
        }
    };
    let peer = make("admin6-peer").await?;
    let guest = make("admin6-guest").await?;
    owner
        .execute(
            "INSERT INTO guest_accounts(user_id,invited_email,invited_by,invited_by_email,host_domain_id,status) VALUES ($1,'guest@outside.test',$2,'admin6-admin',$3,'active')",
            &[&guest.0, &a.user, &a.domain],
        )
        .await?;
    // Credentials of the ordinary target and of the foreign account.
    for user in [peer.0, b.user] {
        owner
            .execute(
                "INSERT INTO sessions(user_id,expires_at) VALUES($1,now()+interval '1 hour')",
                &[&user],
            )
            .await?;
        owner.execute("INSERT INTO oauth_tokens(user_id,token_hash,token_type) VALUES($1,decode('aa','hex'),'refresh')", &[&user]).await?;
        owner
            .execute(
                "INSERT INTO app_passwords(user_id,name,token_hash) VALUES($1,'laptop','h')",
                &[&user],
            )
            .await?;
    }
    let peer_ap: i64 = owner
        .query_one("SELECT id FROM app_passwords WHERE user_id=$1", &[&peer.0])
        .await?
        .get(0);
    let foreign_ap: i64 = owner
        .query_one("SELECT id FROM app_passwords WHERE user_id=$1", &[&b.user])
        .await?
        .get(0);
    if action == "sign-ins" {
        for (when, ok, reason) in [
            ("0 hours", true, None),
            ("1 hour", false, Some("bad_password")),
        ] {
            owner
                .execute(
                    "INSERT INTO login_events(user_id,success,occurred_at,source_ip,location,device_name,platform,client,protocol,auth_method,fail_reason) VALUES($1,$2,now()-$3::text::interval,'203.0.113.9','Oslo','Laptop','linux','web','http','password',$4)",
                    &[&peer.0, &ok, &when, &reason],
                )
                .await?;
        }
    }
    // The governing role: the four user permissions (plus audit.read for sign-ins), narrowed
    // to the admin's domain for the scoped labels, or something else for denial.
    let permissions: Vec<&str> = if label == "denied" {
        vec!["roles.manage"]
    } else {
        vec![
            "users.create",
            "users.suspend",
            "users.delete",
            "users.password_reset",
            "users.read",
            "audit.read",
        ]
    };
    let domain_scope: Option<i64> = scoped_label(label).then_some(a.domain);
    owner
        .execute(
            "INSERT INTO admin_role_groups(id,name,permissions,domain_scope) OVERRIDING SYSTEM VALUE VALUES($1,'admin6-role',$2,$3)",
            &[&ROLE, &permissions, &domain_scope],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) VALUES($1,$2,$1,false)",
            &[&a.user, &ROLE],
        )
        .await?;
    // Case-specific global state, restored on every path.
    // The outbox toggle has no seeded row (an absent row reads as off): upsert it and
    // put the absence back afterwards.
    let toggle = |key: &'static str| {
        let owner = &owner;
        async move {
            Ok::<Option<bool>, BoxError>(
                owner
                    .query_opt("SELECT enabled FROM feature_toggles WHERE key=$1", &[&key])
                    .await?
                    .map(|r| r.get(0)),
            )
        }
    };
    let outbox_before = toggle("feature.webhook_publication_outbox").await?;
    let lifecycle_before = toggle("feature.mailbox_lifecycle_retention").await?;
    for (key, on) in [
        ("feature.webhook_publication_outbox", label == "outbox"),
        ("feature.mailbox_lifecycle_retention", label == "lifecycle"),
    ] {
        owner
            .execute(
                "INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled",
                &[&key, &on],
            )
            .await?;
    }
    let common_hash = "sha256(convert_to(lower('Common!Passw0rd'),'UTF8'))";
    if label == "common" || label == "common-row" {
        owner
            .batch_execute(&format!(
                "INSERT INTO common_passwords(password_hash) SELECT {common_hash} WHERE NOT EXISTS (SELECT 1 FROM common_passwords WHERE password_hash={common_hash})"
            ))
            .await?;
    }
    let publications_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM webhook_publications", &[])
        .await?
        .get(0);
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
    let schema = format!("gofree_admin6_fault_{}", a.user);
    let mut trigger = None;
    if fault == Some("no-audit") {
        owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.action='app_password_revoke' THEN RETURN NULL; END IF; RETURN NEW; END $fault$;CREATE TRIGGER {schema} BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION {schema}.fault();")).await?;
        trigger = Some("admin_audit_log");
    }
    // The notification fault shadows `app_notify` through a private schema first on the
    // request pool's search path, so `secure_account` publishes nothing.
    let mut exec_dsn = db.app.clone().unwrap_or_else(|| db.dsn.clone());
    if fault == Some("no-notify") {
        owner.batch_execute(&format!("CREATE SCHEMA {schema}; GRANT USAGE ON SCHEMA {schema} TO PUBLIC; CREATE FUNCTION {schema}.app_notify(text,text) RETURNS void LANGUAGE sql AS 'SELECT NULL::void';")).await?;
        exec_dsn = format!(
            "{exec_dsn}{}options=-csearch_path%3D{schema}%2Cpublic",
            if exec_dsn.contains('?') { '&' } else { '?' }
        );
    }
    let mut users: Vec<(i64, String)> = vec![
        (a.user, "<admin>".into()),
        (b.user, "<other>".into()),
        (t.user, "<third>".into()),
        (peer.0, "<peer>".into()),
        (guest.0, "<guest>".into()),
    ];
    let result = async {
        let calls: Arc<Mutex<Vec<Value>>> = Arc::default();
        let sink = calls.clone();
        let authserver = common::fake_upstream(move |req| {
            let sink = sink.clone();
            async move {
                let (parts, body) = req.into_parts();
                use http_body_util::BodyExt;
                let bytes = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                sink.lock().unwrap().push(json!({
                    "method": parts.method.as_str(),
                    "path": parts.uri.path(),
                    "authorization": parts.headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or(""),
                    "content_type": parts.headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or(""),
                    "body": String::from_utf8_lossy(&bytes),
                }));
                Response::new(common::full(""))
            }
        })
        .await;
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named_with_env(
            &db,
            s3,
            "gofree-admin6-http",
            &[
                ("SCIM_AUTHSERVER_URL", format!("http://{authserver}")),
                ("INTERNAL_API_KEY", INTERNAL_KEY.into()),
            ],
        )
        .await?;
        let recording = go.is_some();
        // The adapter and Go must both be given time on a loaded shared host.
        let patient = std::time::Duration::from_secs(30);
        let mk = |dsn: &str| -> Result<ScopedExecutor, BoxError> {
            Ok(ScopedExecutor::from_dsn_with(
                dsn,
                4,
                setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient },
            )
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new()))
        };
        let adapter = Probe {
            inner: AdminUsersLifecycleRoute {
                exec: mk(&exec_dsn)?,
                worker: mk(&db.dsn)?,
                keys: Arc::new(common::recovery_keys()),
                issuer: "mailserver".into(),
                authserver_url: format!("http://{authserver}"),
                internal_key: INTERNAL_KEY.into(),
                dispatcher: setjoin_gateway::webhook::Dispatcher::unguarded_for_tests(
                    setjoin_pg::workers::WorkerDatabase::new(&db.dsn).map_err(|e| e.to_string())?,
                    None,
                ),
            },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F01" && r["slice"] == "user-lifecycle" {
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

        // The target named by the path: an ordinary account, the foreign one, a guest,
        // the caller itself, a missing id or a malformed one.
        let target = match label {
            "foreign" => b.user.to_string(),
            "empty" => b.user.to_string(),
            "missing" => MISSING.to_string(),
            "bad-id" => "bad".to_string(),
            "self" => a.user.to_string(),
            "guest" => guest.0.to_string(),
            _ => peer.0.to_string(),
        };
        let ap = match label {
            "foreign" => foreign_ap.to_string(),
            "missing-ap" => MISSING.to_string(),
            "bad-ap" => "bad".to_string(),
            _ => peer_ap.to_string(),
        };
        let path = pattern
            .replace("{id}", &target)
            .replace("{userId}", &target)
            .replace("{apId}", &ap);
        let new_email = |name: &str, domain: &str| format!("admin6-{name}@{domain}");
        let long_name = "n".repeat(129);
        // `(sent, recorded)`: the recorded form never contains run-specific numbers.
        let same = |text: String| (text.clone(), names(&text));
        let json_body = |v: Value| same(v.to_string());
        let (content_type, body, recorded_body): (&str, String, String) = match (action, label) {
            ("create", l) => {
                let a_domain = domain_a.as_str();
                let (sent, recorded) = match l {
                    "bad-json" => same("{\"email\":".into()),
                    "required" => same("{\"email\":\"admin6-x@host-a.test\"}".into()),
                    "no-email" => json_body(json!({"password": PASSWORD})),
                    "bad-email" => json_body(json!({"email":"not-an-address","password":PASSWORD})),
                    "reserved" => json_body(json!({"email":format!("postmaster@{a_domain}"),"password":PASSWORD})),
                    "display-long" => json_body(json!({"email":new_email("long",a_domain),"displayName":long_name,"password":PASSWORD})),
                    "weak" => json_body(json!({"email":new_email("weak",a_domain),"password":"short"})),
                    "no-upper" => json_body(json!({"email":new_email("upper",a_domain),"password":"alllower1!"})),
                    "too-long" => json_body(json!({"email":new_email("toolong",a_domain),"password":format!("Aa1!{}", "x".repeat(70))})),
                    "contains-email" => json_body(json!({"email":new_email("pwlocal",a_domain),"password":"My-Admin6-PwLocal!9"})),
                    "common" => json_body(json!({"email":new_email("common",a_domain),"password":"Common!Passw0rd"})),
                    "non-local" => json_body(json!({"email":"admin6-new@nowhere.example","password":PASSWORD})),
                    "scoped-foreign" => json_body(json!({"email":new_email("foreign",&domain_b),"password":PASSWORD})),
                    "duplicate" => json_body(json!({"email":format!("admin6-peer@{a_domain}"),"password":PASSWORD})),
                    "derived-name" => json_body(json!({"email":new_email("derived",a_domain),"password":PASSWORD})),
                    "folded" => same(format!("{{\"EMAIL\":\"{}\",\"Password\":\"{PASSWORD}\",\"DISPLAYNAME\":null,\"extra\":[1]}} trailing", new_email("folded", a_domain))),
                    "quoted" => json_body(json!({"email":format!("Admin6-Quoted <admin6-quoted@{a_domain}>"),"password":PASSWORD,"displayName":"  Quoted  "})),
                    "oversize" => (
                        format!("{{\"email\":\"admin6-big@{a_domain}\",\"password\":\"{}\"}}", "x".repeat(1 << 20)),
                        "{\"email\":\"admin6-big@host-a.test\",\"password\":\"<1 MiB of x>\"}".to_string(),
                    ),
                    _ => json_body(json!({"email":new_email("new",a_domain),"displayName":"New Person","password":PASSWORD,"isLocalAdmin":true})),
                };
                ("application/json", sent, recorded)
            }
            ("update", l) => {
                let (sent, recorded) = match l {
                    "bad-json" => same("{\"enabled\":".into()),
                    "disable" | "self" | "guest" | "foreign" | "missing" | "denied" | "bad-id" => json_body(json!({"enabled":false})),
                    "enable" => json_body(json!({"enabled":true})),
                    "no-fields" => same("{}".into()),
                    "empty-name" => json_body(json!({"displayName":""})),
                    "folded" => same("{\"DISPLAYNAME\":\"Folded\",\"ENABLED\":true,\"other\":1} trailing".into()),
                    "typed" => json_body(json!({"enabled":"no"})),
                    "all" => json_body(json!({"displayName":"All Fields","enabled":false,"isLocalAdmin":true})),
                    _ => json_body(json!({"displayName":"Renamed Person","isLocalAdmin":true})),
                };
                ("application/json", sent, recorded)
            }
            ("password", l) => {
                let (sent, recorded) = match l {
                    "bad-json" => same("{\"password\":".into()),
                    "weak" => json_body(json!({"password":"short"})),
                    "empty" => json_body(json!({})),
                    "contains-email" => json_body(json!({"password":"My-Admin6-Peer!9"})),
                    "common" => json_body(json!({"password":"Common!Passw0rd"})),
                    "keep" => json_body(json!({"password":"N3w!Passw0rd","mustChange":false})),
                    "must-change-null" => json_body(json!({"password":"N3w!Passw0rd","mustChange":null})),
                    _ => json_body(json!({"password":"N3w!Passw0rd"})),
                };
                ("application/json", sent, recorded)
            }
            ("import", l) => {
                let a_domain = domain_a.as_str();
                let csv = match l {
                    "success" => format!(
                        "email,password,display_name,is_local_admin,quota_bytes\nadmin6-i1@{a_domain},{PASSWORD},Imported One,true,1048576\n  admin6-i2@{a_domain}  ,  {PASSWORD}  ,,no,0\nadmin6-i3@{a_domain},weak,Weak,,\nadmin6-peer@{a_domain},{PASSWORD},Dup,,\nadmin6-i4@nowhere.example,{PASSWORD},,,\n,{PASSWORD},,,\nnot-an-address,{PASSWORD},,,\npostmaster@{a_domain},{PASSWORD},,,\n"
                    ),
                    "headers-only" => "Email , Password\n".to_string(),
                    "malformed" => format!("email,password\nadmin6-m1@{a_domain},{PASSWORD},extra\nadmin6-m2@{a_domain},\"unterminated\nadmin6-m3@{a_domain},{PASSWORD}\nadmin6-m4@{a_domain},{PASSWORD}\n"),
                    "bare-quote" => format!("email,password\nadmin6-q1@{a_domain},Pa\"ss1!word\nadmin6-q2@{a_domain},{PASSWORD}\n"),
                    "missing-column" => "email,name\nadmin6-x@host-a.test,X\n".to_string(),
                    "missing-email" => "password\nsecret\n".to_string(),
                    "empty-file" => String::new(),
                    "common-row" => format!("email,password\nadmin6-c1@{a_domain},Common!Passw0rd\n"),
                    "scoped" | "scoped-foreign" => format!("email,password\nadmin6-s1@{a_domain},{PASSWORD}\nadmin6-s2@{domain_b},{PASSWORD}\n"),
                    "crlf" => format!("email,password,department_id\r\nadmin6-r1@{a_domain},{PASSWORD},-3\r\nadmin6-r2@{a_domain},{PASSWORD},\"abc\"\r\n"),
                    "blank-lines" => format!("email,password\n\nadmin6-b1@{a_domain},{PASSWORD}\n\n\nadmin6-b2@{a_domain},{PASSWORD}"),
                    _ => format!("email,password\nadmin6-d1@{a_domain},{PASSWORD}\n"),
                };
                match l {
                    "no-file" => ("multipart/form-data; boundary=gofree-boundary", form("other", None, "x"), "other value part".into()),
                    "value-file" => ("multipart/form-data; boundary=gofree-boundary", form("file", None, &csv), "file named without a filename".into()),
                    "not-multipart" => ("application/json", "{\"file\":1}".into(), "{\"file\":1}".into()),
                    "no-boundary" => ("multipart/form-data", "x".into(), "x".into()),
                    "truncated-form" => ("multipart/form-data; boundary=gofree-boundary", "--gofree-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"u.csv\"\r\n\r\nemail,password\r\n".into(), "truncated multipart".into()),
                    _ => ("multipart/form-data; boundary=gofree-boundary", form("file", Some("users.csv"), &csv), names(&csv)),
                }
            }
            _ => ("application/json", String::new(), String::new()),
        };
        let wanted: u16 = match (action, label) {
            (_, "denied") => 403,
            ("sign-ins", "foreign" | "scoped") => 403,
            ("create", "success" | "derived-name" | "folded" | "outbox" | "scoped") => 201,
            ("create", "duplicate" | "repeat") => 409,
            ("create", "scoped-foreign") => 403,
            ("create", _) => 400,
            ("import", "repeat" | "success" | "headers-only" | "malformed" | "bare-quote" | "common-row" | "scoped" | "scoped-foreign" | "crlf" | "blank-lines" | "single-row") => 200,
            ("import", _) => 400,
            ("update", "bad-json" | "bad-id" | "no-fields" | "empty-name" | "typed") => 400,
            ("update", "foreign" | "missing") => 404,
            ("update", "guest") => 409,
            ("update" | "delete", "self") => 403,
            ("delete", "bad-id") => 400,
            ("delete", "foreign") => 404,
            ("delete", "guest" | "lifecycle") => 409,
            ("password", "bad-json" | "bad-id" | "weak" | "empty" | "contains-email" | "common") => 400,
            ("password", "foreign" | "missing") => 404,
            ("password", "guest") => 409,
            ("secure", "bad-id") => 400,
            ("secure", "foreign" | "missing") => 404,
            ("secure", _) => 200,
            ("sign-ins", "bad-id") => 400,
            ("sign-ins", "missing") => 404,
            ("sign-ins", _) => 200,
            ("app-password-revoke", "bad-id" | "bad-ap") => 400,
            ("app-password-revoke", "foreign" | "missing" | "missing-ap" | "repeat") => 404,
            _ => 204,
        };
        let caller = a.user;
        let send = |content_type: &'static str, body: String| {
            let uri = format!("/api{path}");
            let token = admin_token(caller);
            async move {
                let request = Request::builder().method(method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("content-type", content_type).header("x-request-id", "gofree-admin6-oracle").header("authorization", format!("Bearer {token}"));
                Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
            }
        };
        if label == "repeat" {
            let first = send(content_type, body.clone()).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            let first_wanted = match action {
                "create" => 201,
                "import" | "secure" => 200,
                _ => 204,
            };
            if recording && status != first_wanted {
                return Err(format!("initial {action}: {status} {data:?}").into());
            }
        }
        let mut before = snapshot(&owner).await?;
        if label == "repeat" && action == "create" {
            // The initial create's welcome mail is a goroutine in Go (recorded: not yet there when
            // the repeat starts, present afterwards) and a spawned task here; whether it lands
            // before this snapshot is a race. It is asserted in `after`, which waits for it below.
            before["welcome"] = json!([]);
        }
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut alerts = db.listen("admin:alert").await?;
        let response = send(content_type, body.clone()).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        if recording && status != wanted && std::env::var_os("GOFREE_ORACLE_LEARN").is_none() {
            return Err(format!("Go {action}/{label}: expected {wanted}, got {status}: {raw}").into());
        }
        // Go answers before its goroutines finish: wait for the welcome mail of a new
        // account and the revocation call of a suspension, both of which are effects.
        let new_accounts: Vec<i64> = owner.query("SELECT id FROM users WHERE email LIKE 'admin6-%' AND id NOT IN (SELECT unnest($1::bigint[])) ORDER BY id", &[&vec![a.user, b.user, t.user, peer.0, guest.0]]).await?.iter().map(|r| r.get(0)).collect();
        let created_id: Option<i64> = if action == "create" && (status == 201 || label == "repeat") { new_accounts.first().copied() } else { None };
        if let Some(id) = created_id {
            for _ in 0..80 {
                let n: i64 = owner.query_one("SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE mb.user_id=$1 AND m.raw_ref LIKE 'system:welcome:%'", &[&id]).await?.get(0);
                if n > 0 { break; }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
        for (n, id) in new_accounts.iter().enumerate() {
            users.push((*id, format!("<new-{}>", n + 1)));
        }
        if action == "update" && matches!(label, "disable" | "all") {
            for _ in 0..50 {
                if !calls.lock().unwrap().is_empty() { break; }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        } else {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        let after = snapshot(&owner).await?;
        let aps = [(peer_ap, "<peer-app-password>"), (foreign_ap, "<other-app-password>")];
        // The request path with its run-specific ids named, as the problem `instance` and the
        // denial audit rows quote it.
        let masked_path = {
            let mut masked = path.clone();
            if action == "app-password-revoke" {
                masked = masked.replace(&format!("/app-passwords/{ap}"), "/app-passwords/<app-password>");
            }
            match users.iter().find(|(i, _)| i.to_string() == target) {
                Some((_, name)) => masked.replace(&target, name),
                None => masked,
            }
        };
        let mut audit: Vec<Value> = owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last]).await?.iter().map(|r| serde_json::from_str(&r.get::<_, String>(0))).collect::<Result<_, _>>()?;
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) { return Err("invalid audit id".into()); }
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) { row[key] = json!("<checksum>"); }
            }
            let mut text = names(&row.to_string());
            text = text.replace(&format!("domain={}", a.domain), "domain=<domain-a>");
            text = text.replace(&path, &masked_path);
            *row = serde_json::from_str(&text)?;
            mask(row, &users, &aps);
        }
        let mut notify = vec![];
        for event in alerts.drain(&owner).await? {
            let mut payload: Value = serde_json::from_str(&event)?;
            payload = serde_json::from_str(&names(&payload.to_string()))?;
            mask(&mut payload, &users, &aps);
            notify.push(json!({"channel":"admin:alert","payload":payload}));
        }
        let mut revoked = vec![];
        for call in calls.lock().unwrap().iter() {
            let mut call = call.clone();
            let mut inner: Value = serde_json::from_str(call["body"].as_str().unwrap_or("{}")).unwrap_or(json!({}));
            mask(&mut inner, &users, &aps);
            call["body"] = json!(inner.to_string());
            revoked.push(call);
        }
        let mut text = names(&raw);
        // The problem `instance` is the request path: name the target in it.
        text = text.replace(&path, &masked_path);
        if action == "sign-ins" {
            if let Ok(mut v) = serde_json::from_str::<Value>(&text) {
                if let Some(items) = v["items"].as_array_mut() {
                    for item in items { item["id"] = json!("<event>"); }
                    // Go's struct field order is kept by re-rendering through the original text.
                    let mut out = text.clone();
                    let mut from = 0;
                    while let Some(at) = out[from..].find("{\"id\":") {
                        let start = from + at + 6;
                        let end = start + out[start..].find(',').unwrap_or(0);
                        out.replace_range(start..end, "\"<event>\"");
                        from = start;
                    }
                    text = out;
                }
            }
            let mut out = text.clone();
            let mut from = 0;
            while let Some(at) = out[from..].find("\"occurred_at\":\"") {
                let start = from + at + 15;
                let end = start + out[start..].find('"').unwrap_or(0);
                out.replace_range(start..end, "<timestamp>");
                from = start;
            }
            text = out;
        }
        if let Some(id) = created_id {
            text = text.replace(&format!("\"id\":{id}"), "\"id\":\"<new-1>\"");
        }
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() { return Err("bad wire length".into()); }
            *length = json!([text.len().to_string()]);
        }
        let (before, after) = (
            { let mut v = before; v = serde_json::from_str(&names(&v.to_string()))?; mask(&mut v, &users, &aps); v },
            { let mut v = after; v = serde_json::from_str(&names(&v.to_string()))?; mask(&mut v, &users, &aps); v },
        );
        let effects = json!([{"table":"user-lifecycle","before":before,"after":after}]);
        let mut request = json!({"method":method,"path":pattern,"external_path":format!("/api{pattern}")});
        if !recorded_body.is_empty() { request["body"] = json!(recorded_body); }
        if content_type != "application/json" { request["content_type"] = json!(content_type); }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify,"authserver":revoked});
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
        let file = dir.join(format!("lifecycle-{name}.json"));
        let row_file = dir.join(format!("lifecycle-{name}-row-effects.json"));
        let route_name = format!("{method} {pattern}");
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
        } else {
            let expected: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
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
            let expected: Value = serde_json::from_slice(&std::fs::read(row_file)?)?;
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
    if fault.is_some() {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    for (key, value) in [
        ("feature.webhook_publication_outbox", outbox_before),
        ("feature.mailbox_lifecycle_retention", lifecycle_before),
    ] {
        match value {
            Some(value) => {
                owner
                    .execute(
                        "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                        &[&key, &value],
                    )
                    .await?
            }
            None => {
                owner
                    .execute("DELETE FROM feature_toggles WHERE key=$1", &[&key])
                    .await?
            }
        };
    }
    owner
        .batch_execute(&format!(
            "DELETE FROM common_passwords WHERE password_hash={common_hash}"
        ))
        .await?;
    owner
        .execute(
            "DELETE FROM webhook_publications WHERE id>$1",
            &[&publications_start],
        )
        .await?;
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F01' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    owner.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 hour' WHERE role_group_id=$1", &[&ROLE]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&ROLE],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&ROLE])
        .await?;
    // Every account this case made or imported, then the three fixture domains.
    let mine: Vec<i64> = owner
        .query("SELECT id FROM users WHERE email LIKE 'admin6-%'", &[])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    owner
        .execute("DELETE FROM login_events WHERE user_id=ANY($1)", &[&mine])
        .await?;
    owner
        .execute("DELETE FROM sessions WHERE user_id=ANY($1)", &[&mine])
        .await?;
    owner
        .execute("DELETE FROM oauth_tokens WHERE user_id=ANY($1)", &[&mine])
        .await?;
    owner
        .execute("DELETE FROM app_passwords WHERE user_id=ANY($1)", &[&mine])
        .await?;
    owner
        .execute("DELETE FROM guest_accounts WHERE user_id=ANY($1)", &[&mine])
        .await?;
    let mailboxes: Vec<i64> = owner
        .query("SELECT id FROM mailboxes WHERE user_id=ANY($1)", &[&mine])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM mailbox_audit_log WHERE mailbox_id=ANY(ARRAY[{}]::bigint[]); COMMIT;", mailboxes.iter().map(i64::to_string).collect::<Vec<_>>().join(","))).await?;
    owner
        .execute(
            "DELETE FROM messages WHERE mailbox_id=ANY($1)",
            &[&mailboxes],
        )
        .await?;
    // The welcome mail's trace rows land in a partition (or the default one, where they
    // would block creating the month's partition for every later suite).
    let mailbox_texts: Vec<String> = mailboxes.iter().map(i64::to_string).collect();
    owner
        .execute(
            "DELETE FROM message_trace WHERE details->>'mailbox_id'=ANY($1)",
            &[&mailbox_texts],
        )
        .await?;
    // The mailbox and its user go in one transaction: primary-mailbox enforcement is deferred.
    for user in &mine {
        owner.batch_execute(&format!("BEGIN; DELETE FROM mailboxes WHERE user_id={user}; DELETE FROM users WHERE id={user}; COMMIT;")).await?;
    }
    for domain in [a.domain, b.domain, t.domain] {
        owner
            .execute("DELETE FROM domains WHERE id=$1", &[&domain])
            .await?;
    }
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
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
