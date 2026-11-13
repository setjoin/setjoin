//! #380 frozen-Go oracle for the LDAP runtime routes and the `ldap-sync` worker.
//! Record mode runs the covered Go binary behind the front door against an
//! in-process fake LDAP directory; replay serves the same requests from Rust
//! with no Go upstream. Observations carry the HTTP wire, the committed rows
//! and the LDAP operations the directory saw.
mod scenarios;

use crate::common::{self, BoxError};
use hyper::{Request, Response};
use scenarios::{Reach, Scenario, Seed};
use serde_json::{json, Value};
use setjoin_conformance::ldap_fake::{FakeLdap, Transport, CA_PEM};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    directory_sync::DirectorySyncRoute, Body, BoxFuture, Config, Gateway, Intercept,
    RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

pub use scenarios::CASES;

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
    let signed = format!("{}.{payload}", fields[0]);
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(signed.as_bytes());
    format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

const KEY: &str = "22";

fn codec(deployment: &str) -> Result<Arc<setjoin_config_secret::ConfigSecretCodec>, BoxError> {
    let keyring = setjoin_config_secret::keyring_from_lookup(deployment, |name| match name {
        "DB_ENCRYPTION_KEY" => Some(KEY.repeat(32)),
        _ => None,
    })?;
    Ok(Arc::new(setjoin_config_secret::ConfigSecretCodec::new(
        keyring,
    )?))
}

/// Cases share fixed global state (the Go source row, config keys), so they run one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn run(route: &str, case: &str, mutant: Option<&str>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(route, case, mutant, false).await
}

/// Replay one sync case through the Rust worker loop instead of the route.
pub async fn run_worker(route: &str, case: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(route, case, None, true).await
}

async fn rows(
    c: &tokio_postgres::Client,
    sql: &str,
    args: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<Vec<Value>, BoxError> {
    c.query(sql, args)
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}

/// Rows of this case's domain, with every id replaced by a stable name.
/// Config rows; sealed values show the plaintext they open to, so a row that
/// is merely flagged encrypted but holds the wrong secret differs from Go's.
async fn config_rows(
    c: &tokio_postgres::Client,
    codec: &setjoin_config_secret::ConfigSecretCodec,
) -> Result<Vec<Value>, BoxError> {
    let mut out = vec![];
    for row in c.query("SELECT key, value::text, encrypted FROM system_config WHERE key LIKE 'ldap_sync_%' ORDER BY key", &[]).await? {
        let (key, raw, encrypted): (String, String, bool) = (row.get(0), row.get(1), row.get(2));
        let value = if encrypted {
            match codec.decrypt(&key, raw.as_bytes()) {
                Ok(plain) => format!("<sealed:{}>", String::from_utf8_lossy(&plain)),
                Err(_) => "<undecryptable>".to_owned(),
            }
        } else if key == "ldap_sync_last_absence_sweep" {
            "<timestamp>".to_owned()
        } else {
            raw
        };
        out.push(json!({"key": key, "value": value, "encrypted": encrypted}));
    }
    Ok(out)
}

async fn snapshot(
    c: &tokio_postgres::Client,
    codec: &setjoin_config_secret::ConfigSecretCodec,
    domain: i64,
    log_after: i64,
) -> Result<Value, BoxError> {
    Ok(json!({
        "users": rows(c, "SELECT jsonb_build_object('email',u.email,'sync_source',u.sync_source,'enabled',u.enabled,\
            'display_name',u.display_name,'first_name',u.first_name,'last_name',u.last_name,'job_title',u.job_title,\
            'phone',u.phone,'krb5_principal',u.krb5_principal,'ad_upn',u.ad_upn,'username',u.username,\
            'manager',(SELECT m.email FROM users m WHERE m.id=u.manager_id),\
            'department',(SELECT d.path FROM departments d WHERE d.id=u.department_id),\
            'local_overrides',u.local_overrides)::text FROM users u WHERE u.domain_id=$1 ORDER BY u.email", &[&domain]).await?,
        "conflicts": rows(c, "SELECT jsonb_build_object('user',(SELECT email FROM users WHERE id=k.user_id),'field',k.field,\
            'local_value',k.local_value,'remote_value',k.remote_value,'source',k.source,'resolution',k.resolution,\
            'resolved',k.resolved_at IS NOT NULL)::text FROM sync_conflicts k \
            WHERE k.user_id IN (SELECT id FROM users WHERE domain_id=$1) ORDER BY 1", &[&domain]).await?,
        "links": rows(c, "SELECT jsonb_build_object('subject',l.external_subject,'user',u.email,'state',l.state,\
            'purposes',l.purposes)::text FROM user_identity_links l JOIN users u ON u.id=l.user_id \
            WHERE u.domain_id=$1 ORDER BY 1", &[&domain]).await?,
        "departments": rows(c, "SELECT jsonb_build_object('path',path,'ldap_ou',ldap_ou)::text FROM departments \
            WHERE path IN ('Engineering','Ops') ORDER BY 1", &[]).await?,
        "sync_log": rows(c, "SELECT jsonb_build_object('source',source,'checked',users_checked,'created',users_created,\
            'updated',users_updated,'disabled',users_disabled,'skipped',fields_skipped,'error',error,'details',details)::text \
            FROM identity_sync_log WHERE id>$1 AND source='ldap' ORDER BY id", &[&log_after]).await?,
        "source": rows(c, "SELECT jsonb_build_object('state',state,'generation',generation,'cursor',committed_cursor)::text \
            FROM identity_sources WHERE source_key='legacy:ldap'", &[]).await?,
        "quarantine": rows(c, "SELECT jsonb_build_object('object_key',object_key,'reason',reason_code,\
            'occurrences',occurrences)::text FROM identity_source_quarantines q JOIN identity_sources s ON s.id=q.source_id \
            WHERE s.source_key='legacy:ldap' ORDER BY 1", &[]).await?,
        "inbox": rows(c, "SELECT jsonb_build_object('object_key',i.object_key,'state',i.state)::text \
            FROM identity_source_inbox i JOIN identity_sources s ON s.id=i.source_id WHERE s.source_key='legacy:ldap' ORDER BY 1", &[]).await.unwrap_or_default(),
        "config": config_rows(c, codec).await?,
    }))
}

struct Seeded {
    domain: String,
    domain_id: i64,
}

async fn seed_users(
    owner: &tokio_postgres::Client,
    s: &Scenario,
    d: &Seeded,
) -> Result<(), BoxError> {
    let user = |name: &str, source: &str, enabled: bool, display: &str| {
        let email = format!("{name}@{}", d.domain);
        let (source, display, domain) = (source.to_owned(), display.to_owned(), d.domain_id);
        async move {
            owner
                .query_one(
                    "INSERT INTO users(username,email,domain_id,display_name,password_hash,sync_source,enabled) \
                     VALUES($1,$1,$2,$3,'x',$4,$5) RETURNING id",
                    &[&email, &domain, &display, &source, &enabled],
                )
                .await
                .map(|r| r.get::<_, i64>(0))
        }
    };
    match s.seed {
        Seed::Mixed | Seed::Preview => {
            let bob = user("bob", "ldap", true, "Bob Old").await?;
            user("carol", "local", true, "Carol Local").await?;
            user("dave", "ldap", true, "Dave").await?;
            user("hank", "ldap", true, "Hank").await?;
            owner.execute("UPDATE users SET local_overrides='{\"job_title\":\"Local Title\"}'::jsonb, krb5_principal='bob@CORP.EXAMPLE' WHERE id=$1", &[&bob]).await?;
            owner.execute("INSERT INTO field_policy(user_id,field,policy) VALUES($1,'phone','local_only')", &[&bob]).await?;
        }
        Seed::Sweep => {
            user("bob", "ldap", true, "Bob Old").await?;
            user("gone", "ldap", true, "Gone Away").await?;
            user("native", "local", true, "Native").await?;
            user("off", "ldap", false, "Already Off").await?;
        }
        Seed::Conflicts => {
            let bob = user("bob", "ldap", true, "Bob").await?;
            owner.execute("INSERT INTO sync_conflicts(user_id,field,local_value,remote_value,source) VALUES($1,'title','a','b','ldap'),($1,'phone','c','d','ldap'),($1,'title','e','f','ad')", &[&bob]).await?;
            owner.execute("UPDATE sync_conflicts SET resolved_at=now(), resolution='kept_local' WHERE user_id=$1 AND field='phone'", &[&bob]).await?;
            owner.execute("INSERT INTO identity_sync_log(sync_at,source,users_checked,users_created,users_updated,users_disabled,fields_skipped,duration_ms,details) VALUES('2026-10-01T10:00:00Z','ldap',5,1,2,3,4,10,'{}'::jsonb)", &[]).await?;
        }
        Seed::LogError => {
            owner.execute("INSERT INTO identity_sync_log(sync_at,source,users_checked,users_created,users_updated,users_disabled,fields_skipped,duration_ms,error,details) VALUES('2026-10-01T10:00:00Z','ldap',5,1,2,3,4,10,'2 directory entries failed','{}'::jsonb)", &[]).await?;
        }
        Seed::None => {}
    }
    Ok(())
}

async fn run_inner(
    route: &str,
    case: &str,
    mutant: Option<&str>,
    worker: bool,
) -> Result<(), BoxError> {
    std::env::set_var(
        "SSL_CERT_FILE",
        std::env::temp_dir().join("setjoin-ldap-oracle-ca.pem"),
    );
    std::fs::write(
        std::env::temp_dir().join("setjoin-ldap-oracle-ca.pem"),
        CA_PEM,
    )?;
    let status_mutant = mutant == Some("changed-status");
    let s = scenarios::scenario(route, case);
    let Some(db) = Db::for_case("ldap-oracle") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "ldap5-admin").await?;
    let domain: String = owner
        .query_one("SELECT name FROM domains WHERE id=$1", &[&a.domain])
        .await?
        .get(0);
    let seeded = Seeded {
        domain: domain.clone(),
        domain_id: a.domain,
    };
    let permissions: Vec<&str> = if s.revoked {
        vec![]
    } else {
        vec!["users.read", "identity.write"]
    };
    let role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,NULL) RETURNING id",
            &[&format!("ldap5-{}", a.user), &permissions],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
    let transport = if s.tls == "false" {
        Transport::StartTls
    } else {
        Transport::Ldaps
    };
    let fake = FakeLdap::start(transport).await?;
    fake.set_credentials("cn=svc,dc=example,dc=test", "pw");
    fake.set_entries(scenarios::entries(s.dir, &domain));
    fake.fail_search(s.fail_search);
    let port = match s.reach {
        Reach::Down => {
            let spare = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            spare.local_addr()?.port()
        }
        _ => fake.addr.port(),
    };
    let deployment: String = owner
        .query_one(
            "SELECT value #>> '{}' FROM system_config WHERE key='identity.deployment_id'",
            &[],
        )
        .await?
        .get(0);
    let codec = codec(&deployment)?;
    let saved_config = owner
        .query(
            "SELECT key,value::text,encrypted FROM system_config WHERE key LIKE 'ldap_sync_%'",
            &[],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM system_config WHERE key LIKE 'ldap_sync_%'",
            &[],
        )
        .await?;
    if s.configured {
        let password = if s.reach == Reach::BadPassword {
            "wrong"
        } else {
            "pw"
        };
        let sealed = String::from_utf8(codec.encrypt(
            "ldap_sync_password_enc",
            format!("\"{password}\"").as_bytes(),
        )?)?;
        let mut config: Vec<(&str, String, bool)> = vec![
            ("ldap_sync_host", "\"127.0.0.1\"".into(), false),
            ("ldap_sync_port", format!("\"{port}\""), false),
            ("ldap_sync_tls", format!("\"{}\"", s.tls), false),
            (
                "ldap_sync_bind_dn",
                "\"cn=svc,dc=example,dc=test\"".into(),
                false,
            ),
            ("ldap_sync_password_enc", sealed, true),
            ("ldap_sync_base_dn", "\"dc=example,dc=test\"".into(), false),
            ("ldap_sync_enabled", format!("\"{}\"", s.enabled), false),
            (
                "ldap_sync_auto_create_depts",
                format!("\"{}\"", s.auto_depts),
                false,
            ),
        ];
        if !s.subject.is_empty() {
            config.push((
                "ldap_sync_subject_attribute",
                format!("\"{}\"", s.subject),
                false,
            ));
        }
        if !s.filter.is_empty() {
            config.push((
                "ldap_sync_user_filter",
                serde_json::to_string(s.filter)?,
                false,
            ));
        }
        if let Some(h) = s.sweep_hours {
            config.push(("ldap_sync_absence_sweep_hours", format!("\"{h}\""), false));
        }
        if let Some(c) = s.cursor {
            config.push(("ldap_sync_last_cursor", format!("\"{c}\""), false));
        }
        if let Some(t) = s.last_sweep {
            config.push(("ldap_sync_last_absence_sweep", format!("\"{t}\""), false));
        }
        for (key, value, encrypted) in config {
            owner
                .execute(
                    "INSERT INTO system_config(key,value,encrypted) VALUES($1,$2::text::jsonb,$3)",
                    &[&key, &value, &encrypted],
                )
                .await?;
        }
    }
    let body = s.body.replace("{port}", &port.to_string());
    if case == "put-preserve" {
        let sealed = String::from_utf8(codec.encrypt("ldap_sync_password_enc", b"\"pw\"")?)?;
        owner
            .execute("INSERT INTO system_config(key,value,encrypted) VALUES('ldap_sync_password_enc',$1::text::jsonb,true) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value", &[&sealed])
            .await?;
    }
    // Baseline of the seeded schema: the Go source row paused with no cursors, identity v2 writes off.
    let baseline = common::identity_baseline_save(&owner).await?;
    reset_source(&owner).await?;
    if s.activate_source {
        owner
            .execute(
                "UPDATE identity_sources SET state='active' WHERE source_key='legacy:ldap'",
                &[],
            )
            .await?;
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=TRUE WHERE key='feature.identity_model_v2'",
                &[],
            )
            .await?;
    }
    seed_users(&owner, &s, &seeded).await?;
    // Planted faults are real database objects (a private trigger), dropped on every path.
    let fault = mutant.filter(|m| *m != "changed-status");
    match fault {
        Some("drop-conflicts") => owner.batch_execute("CREATE FUNCTION public.ldap5_fault() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RETURN NULL; END $f$; CREATE TRIGGER ldap5_fault BEFORE INSERT ON sync_conflicts FOR EACH ROW EXECUTE FUNCTION public.ldap5_fault();").await?,
        Some("touch-users") => owner.batch_execute("CREATE FUNCTION public.ldap5_fault() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN NEW.job_title := COALESCE(NEW.job_title,'') || '!'; RETURN NEW; END $f$; CREATE TRIGGER ldap5_fault BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION public.ldap5_fault();").await?,
        Some("skip-disable") => owner.batch_execute("CREATE FUNCTION public.ldap5_fault() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN IF NEW.enabled IS FALSE THEN NEW.enabled := TRUE; END IF; RETURN NEW; END $f$; CREATE TRIGGER ldap5_fault BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION public.ldap5_fault();").await?,
        _ => {}
    }
    let log_after: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM identity_sync_log", &[])
        .await?
        .get(0);
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
    let result = async {
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let ca = "SSL_CERT_FILE=/src/server-rust/tests/conformance/directory-sync/ldap-fixture/ca.pem";
        std::env::set_var("GOFREE_ORACLE_EXTRA_ENV", ca);
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-dirsync5-ldap").await?;
        let recording = go.is_some();
        let exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
            .map_err(|e| e.0)?
            .with_audit_keys(KEY.repeat(32), String::new());
        let runtime = Arc::new(setjoin_directory_sync::ldap::runtime::LdapRuntime::with_codec(
            setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?,
            Some(codec.clone()),
        ));
        let adapter = Probe {
            inner: DirectorySyncRoute {
                exec,
                keys: Arc::new(common::recovery_keys()),
                issuer: "mailserver".into(),
                ldap: Some(runtime.clone()),
                ad: None,
            },
            changed_status: status_mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F02" && r["slice"] == "ldap-runtime" {
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
        let uri = format!("/api{}", s.path);
        if s.repeat {
            let first = common::send(address, Request::builder().method(s.method).uri(uri.clone()).header("host", "mail.test").header("origin", "http://mail.test").header("content-type", "application/json").header("x-request-id", "gofree-dirsync5-oracle").header("authorization", format!("Bearer {}", admin_token(a.user))).body(common::full(body.clone()))?).await;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && status != s.expect {
                return Err(format!("initial {route}/{case}: {status} {data:?}").into());
            }
        }
        let before = snapshot(&owner, &codec, a.domain, log_after).await?;
        fake.clear_log();
        let (status, headers, raw);
        if worker {
            // Rust worker loop: one cycle on the seeded state, then shutdown.
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let looped = runtime.clone();
            let task = tokio::spawn(async move { looped.run_until(async move { let _ = stopped.await; }).await });
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            while runtime.cycles.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                if std::time::Instant::now() > deadline { return Err("worker did not finish a cycle".into()); }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            let _ = stop.send(());
            task.await?;
            (status, headers, raw) = (0u16, serde_json::Map::new(), String::new());
        } else {
            let token = admin_token(a.user);
            let response = common::send(address, Request::builder().method(s.method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("content-type", "application/json").header("x-request-id", "gofree-dirsync5-oracle").header("authorization", format!("Bearer {token}")).body(common::full(body.clone()))?).await;
            status = response.status().as_u16();
            let mut h = serde_json::Map::new();
            for name in response.headers().keys() {
                h.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
            }
            headers = h;
            raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        }
        let after = snapshot(&owner, &codec, a.domain, log_after).await?;
        let mut audit: Vec<Value> = owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&audit_start]).await?.iter().map(|r| serde_json::from_str(&r.get::<_, String>(0))).collect::<Result<_, _>>()?;
        for row in &mut audit {
            if let Some(map) = row.as_object_mut() {
                for key in ["id", "checksum", "prev_checksum", "occurred_at", "created_at", "at"] { if map.contains_key(key) { map.insert(key.into(), json!("<masked>")); } }
                for key in ["user_id", "actor_id"] { if map.get(key).and_then(Value::as_i64) == Some(a.user) { map.insert(key.into(), json!("<admin>")); } }
            }
            fixup(row, &domain);
        }
        if recording && !worker && status != s.expect {
            return Err(format!("Go {route}/{case}: expected {}, got {status}: {raw}", s.expect).into());
        }
        let mut text = raw.replace(&domain, "host-a.test").replace(&port.to_string(), "<port>");
        // Durations and timestamps differ per run.
        let mut value: Option<Value> = serde_json::from_str(&text).ok();
        if let Some(v) = value.as_mut() {
            if v.get("duration").is_some() { v["duration"] = json!("<duration>"); }
            if let Some(t) = v.get_mut("lastSync") { if !t.is_null() && !t.as_str().is_some_and(|x| x.starts_with("2026-10-01")) { *t = json!("<timestamp>"); } }
            text = v.to_string();
        }
        let mut headers = headers;
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() { return Err("bad wire length".into()); }
            *length = json!([text.len().to_string()]);
        }
        let fix = |v: &mut Value| fixup(v, &domain);
        let (mut before, mut after) = (before, after);
        fix(&mut before);
        fix(&mut after);
        let ops: Vec<String> = fake.log().iter().map(|l| l.replace(&domain, "host-a.test")).collect();
        let effects = json!([{"table":"ldap","before":before,"after":after,"directory":ops}]);
        let mut request = json!({"method":s.method,"path":s.path.split('?').next().unwrap(),"external_path":format!("/api{}",s.path.split('?').next().unwrap())});
        if let Some(q) = s.path.split_once('?') { request["query"] = json!(q.1); }
        if !body.is_empty() { request["body"] = json!(body.replace(&port.to_string(), "<port>")); }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":[]});
        if !recording && !worker {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F02\"} 0") {
                return Err(format!("F02 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let name = format!("ldap-{route}-{case}");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/directory-sync/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("{name}.json"));
        let row_file = dir.join(format!("{name}-row-effects.json"));
        let route_name = format!("{} {}", s.method, s.path.split('?').next().unwrap());
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":case,"go_source":source,"observation":observation}))?;
            record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{case}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
        } else if worker {
            let expected: Value = serde_json::from_slice(&std::fs::read(row_file)?)?;
            golden::compare(&expected["effects"], &observation["effects"])?;
            eprintln!("GOLDEN-REPLAY: ldap-sync worker :: {route}-{case}");
        } else {
            let expected: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
            let compared = golden::compare(&expected["observation"], &observation);
            if status_mutant {
                let error = compared.expect_err("planted status mutant survived");
                if !error.contains("/response/status") { return Err(format!("mutant failed outside response status: {error}").into()); }
                eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
                return Ok(());
            }
            if let Some(name) = fault {
                let stored: Value = serde_json::from_slice(&std::fs::read(&row_file)?)?;
                let rows = compared.and_then(|_| golden::compare(&stored["effects"], &observation["effects"]));
                rows.expect_err("planted database fault survived");
                eprintln!("MUTANT-REJECTED: {route_name} :: {name}");
                return Ok(());
            }
            compared?;
            let expected: Value = serde_json::from_slice(&std::fs::read(row_file)?)?;
            golden::compare(&expected["effects"], &observation["effects"])?;
            eprintln!("GOLDEN-REPLAY: {route_name} :: {case}");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    // Cleanup touches only this case's rows.
    cleanup(
        &owner,
        &a,
        &seeded,
        log_after,
        audit_start,
        &receipts,
        role,
        &saved_config,
        &baseline,
    )
    .await?;
    result
}

/// Deterministic names for run-specific values inside a snapshot.
fn fixup(v: &mut Value, domain: &str) {
    match v {
        Value::String(s) => {
            *s = s.replace(domain, "host-a.test");
            let inner = s.trim_matches('"');
            if inner.len() >= 4
                && inner.chars().all(|c| c.is_ascii_digit())
                && inner
                    .parse::<u32>()
                    .is_ok_and(|n| (1024..65536).contains(&n))
            {
                *s = s.replace(inner, "<port>");
            }
            if s.starts_with("2026-")
                && s.len() > 18
                && (s.ends_with('Z') || s.ends_with("+00:00"))
                && !s.starts_with("2026-10-01")
            {
                *s = "<timestamp>".into();
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| fixup(x, domain)),
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                if k == "duration_ms" {
                    *x = json!("<ms>");
                } else if k == "batchId" {
                    *x = json!("<uuid>");
                } else if (k.ends_with("_id") || k == "id") && x.is_number() {
                    *x = json!("<id>");
                } else {
                    fixup(x, domain);
                }
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
async fn cleanup(
    owner: &tokio_postgres::Client,
    a: &fixture::Account,
    d: &Seeded,
    log_after: i64,
    audit_start: i64,
    receipts: &[String],
    role: i64,
    saved_config: &[tokio_postgres::Row],
    baseline: &(String, String),
) -> Result<(), BoxError> {
    let ids: Vec<i64> = owner
        .query("SELECT id FROM users WHERE domain_id=$1", &[&d.domain_id])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mailboxes: Vec<i64> = owner
        .query(
            "SELECT id FROM mailboxes WHERE domain_id=$1",
            &[&d.domain_id],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; DELETE FROM mailbox_audit_log WHERE mailbox_id=ANY('{{{}}}'); COMMIT;", mailboxes.iter().map(i64::to_string).collect::<Vec<_>>().join(","))).await?;
    owner.batch_execute("DROP TRIGGER IF EXISTS ldap5_fault ON sync_conflicts; DROP TRIGGER IF EXISTS ldap5_fault ON users; DROP FUNCTION IF EXISTS public.ldap5_fault();").await?;
    owner
        .execute("DELETE FROM sync_conflicts WHERE user_id=ANY($1)", &[&ids])
        .await?;
    owner
        .execute("DELETE FROM field_policy WHERE user_id=ANY($1)", &[&ids])
        .await?;
    owner
        .execute(
            "DELETE FROM identity_sync_log WHERE id>$1 AND source='ldap'",
            &[&log_after],
        )
        .await?;
    owner.execute("DELETE FROM identity_sync_log WHERE source='ldap' AND sync_at < '2026-10-02' AND sync_at >= '2026-10-01'", &[]).await?;
    // Identity rows this case's runs created: children of its links, then of the Go source row.
    let list = ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DO $c$ DECLARE r record; BEGIN \
        FOR r IN SELECT k.conrelid::regclass AS t, a.attname AS c FROM pg_constraint k \
            JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=k.conkey[1] \
            WHERE k.contype='f' AND k.confrelid='user_identity_links'::regclass AND k.conrelid<>'user_identity_links'::regclass LOOP \
          EXECUTE format('DELETE FROM %s WHERE %I IN (SELECT id FROM user_identity_links WHERE user_id = ANY(ARRAY[{list}]::bigint[]))', r.t, r.c); \
        END LOOP; \
        FOR r IN SELECT unnest(ARRAY['identity_source_quarantines','identity_source_leases','identity_source_inbox','identity_source_batches','identity_link_events','identity_source_operations','identity_jobs','identity_transitions','identity_match_candidates','identity_shadow_divergences']) AS t LOOP \
          EXECUTE format('DELETE FROM %I WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key=''legacy:ldap'')', r.t); \
        END LOOP; \
        DELETE FROM user_identity_links WHERE user_id = ANY(ARRAY[{list}]::bigint[]); \
      END $c$; COMMIT;")).await?;
    common::identity_baseline_restore(owner, baseline).await?;
    owner
        .execute(
            "DELETE FROM departments WHERE path IN ('Engineering','Ops')",
            &[],
        )
        .await?;
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F02' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    owner
        .execute(
            "DELETE FROM system_config WHERE key LIKE 'ldap_sync_%'",
            &[],
        )
        .await?;
    for row in saved_config {
        owner.execute("INSERT INTO system_config(key,value,encrypted) VALUES($1,$2::text::jsonb,$3) ON CONFLICT (key) DO NOTHING", &[&row.get::<_, String>(0), &row.get::<_, String>(1), &row.get::<_, bool>(2)]).await?;
    }
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
    owner.batch_execute(&format!("BEGIN; DELETE FROM messages WHERE mailbox_id=ANY('{{{0}}}'); DELETE FROM mailboxes WHERE domain_id={1}; DELETE FROM users WHERE domain_id={1}; COMMIT;", mailboxes.iter().map(i64::to_string).collect::<Vec<_>>().join(","), d.domain_id)).await?;
    owner
        .execute("DELETE FROM domains WHERE id=$1", &[&a.domain])
        .await?;
    Ok(())
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

async fn reset_source(owner: &tokio_postgres::Client) -> Result<(), BoxError> {
    owner.batch_execute("UPDATE identity_sources SET state='paused', committed_cursor=NULL, committed_cursor_digest=NULL, pending_cursor=NULL, pending_cursor_digest=NULL, last_success_at=NULL, last_failure_at=NULL, last_error_code=NULL WHERE source_key='legacy:ldap'; UPDATE feature_toggles SET enabled=FALSE WHERE key='feature.identity_model_v2';").await?;
    Ok(())
}
