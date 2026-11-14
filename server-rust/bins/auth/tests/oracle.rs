//! Frozen Go -> actual Rust front door recording; native replay has no Go upstream.
mod common;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{Gateway, RouteTable, TrustedProxies};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
type Err = Box<dyn std::error::Error + Send + Sync>;

/// #353: new captures stamp the dispatching commit (R0 provenance); replays read it back.
fn recorded_source(golden: &std::path::Path, recording: bool) -> Result<String, Err> {
    if golden.exists() {
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(golden)?)?;
        return Ok(doc["go_source"].as_str().ok_or("golden without go_source")?.to_owned());
    }
    if !recording {
        return Err(format!("missing golden {}", golden.display()).into());
    }
    let source = std::env::var("GOFREE_GO_SOURCE")?;
    if source.len() != 40 || !source.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err("GOFREE_GO_SOURCE must be 40 lowercase hex".into());
    }
    Ok(source)
}

/// Fable 353-2: no case (and above all no Go recording) may run against a
/// replaced is_guest_account. Restore from the reducer source, or fail hard.
async fn guest_function_pristine(c: &tokio_postgres::Client) -> Result<(), Err> {
    async fn def(c: &tokio_postgres::Client) -> Result<String, tokio_postgres::Error> {
        c.query_one("SELECT pg_get_functiondef('is_guest_account(bigint)'::regprocedure)", &[])
            .await
            .map(|r| r.get::<_, String>(0))
    }
    let ok = |d: &str| d.contains("SECURITY DEFINER") && d.contains("public.guest_accounts") && !d.contains("gofree_");
    if ok(&def(c).await?) {
        return Ok(());
    }
    c.batch_execute(include_str!("../../../../mailserver/sql/reducers/guest_account.sql")).await?;
    c.batch_execute("DROP SEQUENCE IF EXISTS gofree_idmfa1_guest_calls; DROP SEQUENCE IF EXISTS gofree_guest353_calls").await?;
    if ok(&def(c).await?) {
        Ok(())
    } else {
        Err("is_guest_account is not pristine after restore; refusing to run".into())
    }
}
struct Server {
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
    addr: std::net::SocketAddr,
}
impl Server {
    async fn close(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.task).await;
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn auth_server(server: Arc<AuthServer>) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let task = tokio::spawn(setjoin_auth::serve_until(server, listener, None, async {
        let _ = rx.await;
    }));
    Server {
        stop: Some(tx),
        task,
        addr,
    }
}
async fn gateway(
    auth: std::net::SocketAddr,
    record: Option<String>,
    default_inventory: bool,
) -> Server {
    let mut inventory: Value = serde_json::from_str(setjoin_gateway::inventory::BUNDLED).unwrap();
    if record.is_some() || !default_inventory {
        inventory["routes"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["listener"] == "auth");
        for r in inventory["routes"].as_array_mut().unwrap() {
            r["state"] = json!(if record.is_some() { "OFF" } else { "ON" });
            r["upstream"] = json!(if record.is_some() {
                "go-auth"
            } else {
                "rust-auth"
            });
        }
    }
    let gw = Gateway::new(
        setjoin_gateway::Config {
            upstream: record.as_ref().map(|u| u.parse().unwrap()),
            upstream_header_timeout: std::time::Duration::from_secs(30),
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            edge_limit: Some(setjoin_gateway::jmap::limit::EdgeLimit::for_front_door(
                setjoin_gateway::jmap::limit::Limiter::new(60000, 60),
            )),
        },
        RouteTable::proxy_all(),
    )
    .unwrap()
    .with_inventory(&inventory.to_string())
    .unwrap();
    let gw = if let Some(url) = record {
        gw.with_auth_upstream(url.parse().unwrap()).unwrap()
    } else {
        gw.with_rust_auth_upstream(format!("http://{auth}").parse().unwrap())
            .unwrap()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let task = tokio::spawn(gw.serve_until(listener, async {
        let _ = rx.await;
    }));
    Server {
        stop: Some(tx),
        task,
        addr,
    }
}
async fn request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    payload: String,
    headers: &[(&str, &str)],
) -> Result<(u16, Value, String), Err> {
    let client: hyper_util::client::legacy::Client<_, setjoin_auth::Body> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let mut req = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{path}"))
        .header("host", "auth.idlogin1.test")
        .header("content-type", "application/json")
        .header("user-agent", "IDLOGIN1 oracle");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = client.request(req.body(body(payload))?).await?;
    let status = resp.status().as_u16();
    let mut hs = serde_json::Map::new();
    for name in [
        "content-type",
        "cache-control",
        "set-cookie",
        "x-content-type-options",
        "www-authenticate",
    ] {
        if let Some(v) = resp.headers().get(name) {
            hs.insert(name.into(), json!(v.to_str()?));
        }
    }
    if method == "HEAD" {
        if let Some(v) = resp.headers().get("content-length") {
            hs.insert("content-length".into(), json!(v.to_str()?));
        }
    }
    let raw = String::from_utf8(resp.into_body().collect().await?.to_bytes().to_vec())?;
    Ok((status, Value::Object(hs), raw))
}
struct Seed {
    a: fixture::Account,
    b: fixture::Account,
    email: String,
    foreign: String,
    flags: String,
    since: String,
    hashes: [String; 2],
}
async fn seed(c: &tokio_postgres::Client, id: &str) -> Result<Seed, Err> {
    common::signing_key(c).await;
    let since: String = c
        .query_one("SELECT clock_timestamp()::text", &[])
        .await?
        .get(0);
    let flags:String=c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM feature_toggles t WHERE key='feature.rate_limit'",&[]).await?.get(0);
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await?;
    // #349: always-mounted reset failures escalate the gateway peer's key.
    c.execute("DELETE FROM auth_lockouts WHERE lockout_key='ip:127.0.0.1' OR lockout_key LIKE 'ip_user:127.0.0.1:%'", &[]).await?;
    let a = fixture::account(c, "idlogin1-actor").await?;
    let b = fixture::account(c, "idlogin1-foreign").await?;
    c.execute(
        "UPDATE users SET password_hash=$1,mfa_exempt=true WHERE id=$2",
        &[&bcrypt::hash("Password1!", 4)?, &a.user],
    )
    .await?;
    c.execute(
        "UPDATE users SET password_hash=$1,mfa_exempt=true WHERE id=$2",
        &[&bcrypt::hash("Foreign1!", 4)?, &b.user],
    )
    .await?;
    c.execute("DELETE FROM guest_accounts WHERE user_id=$1", &[&a.user])
        .await?;
    if id.starts_with("login-guest") {
        c.execute(
            "INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status,expires_at) SELECT id,email,'inviter@idlogin1.test',$2,'active',CASE WHEN $3 THEN now()-interval '1 minute' END FROM users WHERE id=$1",
            &[&a.user, &a.domain, &(id == "login-guest-expired")],
        )
        .await?;
    }
    if id.starts_with("password-connector-") {
        // Frozen authserver warms only the local connector. An AD source row
        // still changes its local credential; CachedGet("ad") is empty.
        c.execute(
            "UPDATE users SET sync_source='ad',ad_object_guid='00000000-0000-0000-0000-000000000337' WHERE id=$1",
            &[&a.user],
        )
        .await?;
    }
    if id == "reset-unicode-email" {
        c.execute(
            "UPDATE users SET email=replace(email,'@','-k@') WHERE id=$1",
            &[&a.user],
        )
        .await?;
    }
    let email = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    let foreign = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&b.user])
        .await?
        .get(0);
    let hashes = [
        c.query_one("SELECT password_hash FROM users WHERE id=$1", &[&a.user])
            .await?
            .get(0),
        c.query_one("SELECT password_hash FROM users WHERE id=$1", &[&b.user])
            .await?
            .get(0),
    ];
    Ok(Seed {
        hashes,
        a,
        b,
        email,
        foreign,
        flags,
        since,
    })
}
async fn cleanup(c: &tokio_postgres::Client, s: &Seed) -> Result<(), Err> {
    c.execute(
        "DELETE FROM auth_event_log WHERE email=ANY($1::text[])",
        &[&vec![
            s.email.clone(),
            s.foreign.clone(),
            "nobody@idlogin1.test".into(),
            "�".into(),
        ]],
    )
    .await?;
    c.execute("DELETE FROM login_events WHERE user_id=ANY($1::bigint[]) OR (user_id IS NULL AND source_ip='127.0.0.1' AND occurred_at >= $2::text::timestamptz)",&[&vec![s.a.user,s.b.user],&s.since]).await?;
    c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE target_type='user' AND target_id IN ({},{});COMMIT;",s.a.user,s.b.user)).await?;
    fixture::remove(c, &s.a).await?;
    fixture::remove(c, &s.b).await?;
    c.execute(
        "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
        &[],
    )
    .await?;
    c.execute("INSERT INTO feature_toggles SELECT * FROM jsonb_populate_recordset(NULL::feature_toggles,$1::text::jsonb)",&[&s.flags]).await?;
    Ok(())
}
async fn snapshot(c: &tokio_postgres::Client, s: &Seed) -> Result<Value, Err> {
    let users = vec![s.a.user, s.b.user];
    let q="SELECT jsonb_build_object('oauth',coalesce((SELECT jsonb_agg(to_jsonb(t)-'created_at'-'last_used_at'-'rotated_at'-'revoked_at' ORDER BY t.user_id,t.id) FROM oauth_tokens t WHERE user_id=ANY($1::bigint[])),'[]'), 'sessions',coalesce((SELECT jsonb_agg(to_jsonb(t)-'created_at'-'last_seen_at' ORDER BY t.user_id,t.id) FROM sessions t WHERE user_id=ANY($1::bigint[])),'[]'),'signins',coalesce((SELECT jsonb_agg(to_jsonb(t)-'occurred_at'-'id' ORDER BY t.user_id,t.id) FROM login_events t WHERE user_id=ANY($1::bigint[]) OR (user_id IS NULL AND occurred_at >= $2::text::timestamptz)),'[]'))::text";
    let raw: String = c.query_one(q, &[&users, &s.since]).await?.get(0);
    let effects: Value = serde_json::from_str(&raw)?;
    let raw:String=c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t)-'id'-'created_at' ORDER BY t.id),'[]')::text FROM auth_event_log t WHERE email=ANY($1::text[])",&[&vec![s.email.clone(),s.foreign.clone(),"nobody@idlogin1.test".into(),"�".into()]]).await?.get(0);
    Ok(json!({"effects":effects,"audit":serde_json::from_str::<Value>(&raw)?,"notify":[]}))
}
fn normalize(v: &mut Value, s: &Seed, tokens: &[(String, String, Value)]) {
    match v {
        Value::Object(m) => {
            let domain_label = match m.get("user_id") {
                Some(v) if *v == s.a.user || v.as_str() == Some("<actor>") => "<actor-domain>",
                Some(v) if *v == s.b.user || v.as_str() == Some("<foreign>") => "<foreign-domain>",
                _ => "<domain>",
            };
            for (k, val) in m.iter_mut() {
                if k == "domain_id" && !val.is_null() {
                    *val = json!(domain_label);
                    continue;
                }
                if matches!(
                    k.as_str(),
                    "created_at"
                        | "not_before"
                        | "expires_at"
                        | "last_seen"
                        | "updated_at"
                        | "occurred_at"
                        | "issued_at"
                ) {
                    if !val.is_null() {
                        *val = json!("<time>");
                    }
                    continue;
                }
                if k == "body" {
                    if let Some(raw) = val.as_str() {
                        if let Ok(profile) = serde_json::from_str::<Value>(raw) {
                            if let Some(uid) = profile.get("user_id").and_then(Value::as_i64) {
                                *val = json!(raw.replace(
                                    &format!("\"user_id\":{uid}"),
                                    "\"user_id\":\"<actor>\""
                                ));
                            }
                        }
                    }
                }
                if k == "password_hash" {
                    if let Some(raw) = val.as_str() {
                        if raw.starts_with("$2") && raw.len() >= 7 {
                            *val = json!(format!("{}<hash>", &raw[..7]));
                        } else if raw.starts_with("$sm3$") {
                            *val = json!(format!(
                                "$sm3${}$<salt>$<hash>",
                                raw.split('$').nth(2).unwrap_or("")
                            ));
                        }
                    }
                    continue;
                }
                if k == "previous_token_hash" && !val.is_null() {
                    *val = json!("<previous-token-hash>");
                    continue;
                }
                if k == "token_hash" {
                    *val = json!("<token-hash>");
                    continue;
                }
                if k == "id"
                    && val
                        .as_str()
                        .is_some_and(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    *val = json!("<jti>");
                    continue;
                }
                if k == "id" && val.is_number() {
                    *val = json!("<row-id>");
                    continue;
                }
                if matches!(k.as_str(), "iat" | "nbf") {
                    *val = json!("<time>");
                    continue;
                }
                if k == "exp" {
                    *val = json!("<expiry>");
                    continue;
                }
                if k == "jti" {
                    *val = json!("<jti>");
                    continue;
                }
                if k == "family_id" || k == "fam" {
                    if !val.is_null() {
                        *val = json!("<family>");
                    }
                    continue;
                }
                normalize(val, s, tokens);
            }
        }
        Value::Array(a) => {
            for x in a.iter_mut() {
                normalize(x, s, tokens);
            }
        }
        Value::Number(n) => {
            if n.as_i64() == Some(s.a.user) {
                *v = json!("<actor>");
            } else if n.as_i64() == Some(s.b.user) {
                *v = json!("<foreign>");
            }
        }
        Value::String(x) => {
            for (field, token, claims) in tokens {
                *x = x.replace(
                    token,
                    &format!(
                        "<{}>",
                        if field == "presented_access_token" {
                            "access_token"
                        } else {
                            field
                        }
                    ),
                );
                if let Some(jti) = claims.get("jti").and_then(Value::as_str) {
                    if x == jti {
                        *x = "<jti>".into();
                    }
                }
            }
            *x = x
                .replace(&s.email, "actor@<domain>")
                .replace(&s.foreign, "foreign@<domain>");
            for domain in [
                s.email.split_once('@').map(|v| v.1),
                s.foreign.split_once('@').map(|v| v.1),
            ]
            .into_iter()
            .flatten()
            {
                *x = x.replace(domain, "<domain>");
            }
            if *x == s.a.user.to_string() {
                *x = "<actor>".into();
            } else if *x == s.b.user.to_string() {
                *x = "<foreign>".into();
            }
        }
        _ => {}
    }
}
#[derive(Clone, Copy)]
enum Mutation {
    Status,
    NoAudit,
    NoTenantFilter,
    DoubleBump,
    NoNotify,
}
async fn run(id: &str) -> Result<(), Err> {
    run_mutated(id, None).await
}
async fn run_mutated(id: &str, mutation: Option<Mutation>) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case(id).unwrap();
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    guest_function_pristine(&c).await?;
    let reset_markers: Vec<String> = c
        .query("SELECT token_hash FROM used_password_reset_tokens", &[])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let receipts = common::receipt_ids(&c).await;
    let s = seed(&c, id).await?;
    let saved_policy:String=c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM system_config t WHERE key='password_min_length'",&[]).await?.get(0);
    let mut mfa_function = None;
    let mut fault_function = None;
    let notify_function = if matches!(mutation, Some(Mutation::NoNotify)) {
        let original: String = c
            .query_one(
                "SELECT pg_get_functiondef('app_notify(text,text)'::regprocedure)",
                &[],
            )
            .await?
            .get(0);
        c.batch_execute("CREATE OR REPLACE FUNCTION app_notify(p_channel text,p_payload text) RETURNS void LANGUAGE plpgsql AS $$BEGIN RETURN; END$$").await?;
        Some(original)
    } else {
        None
    };
    let mut role = None;
    let fault = match id {
        "login-mint-fenced" => Some((
            "identity_auth_local_mint_fence(bigint)",
            "identity_auth_local_mint_fence(p_user_id bigint)",
        )),
        "login-admission-fenced" | "login-admission-unavailable" => Some((
            "identity_transition_admission_allowed(bigint)",
            "identity_transition_admission_allowed(p_user_id bigint)",
        )),
        "login-account-type-mint-unavailable" | "login-account-type-unavailable" => Some((
            "is_guest_account(bigint)",
            "is_guest_account(p_user_id bigint)",
        )),
        "login-scope-unavailable" => Some((
            "admin_assignment_active(boolean,timestamp with time zone)",
            "admin_assignment_active(p_eligible boolean,p_activated_until timestamptz)",
        )),
        _ => None,
    };
    if let Some((signature, definition)) = fault {
        if id == "login-scope-unavailable" {
            let id: i64 = c
                .query_one(
                    "INSERT INTO admin_role_groups(name,domain_scope) VALUES($1,$2) RETURNING id",
                    &[&format!("gofree-idlogin1-{}", s.a.user), &s.a.domain],
                )
                .await?
                .get(0);
            c.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",&[&s.a.user,&id]).await?;
            role = Some(id);
        }
        let original: String = c
            .query_one(
                "SELECT pg_get_functiondef($1::text::regprocedure)",
                &[&signature],
            )
            .await?
            .get(0);
        if id == "login-account-type-mint-unavailable" {
            c.batch_execute("CREATE SEQUENCE gofree_idlogin1_guest_calls;GRANT USAGE ON SEQUENCE gofree_idlogin1_guest_calls TO setjoin_app").await?;
        }
        let branch = if id == "login-mint-fenced" {
            r#"RAISE EXCEPTION 'identity transition security effects are unfinished' USING ERRCODE='BZ235',HINT='{"type":"identity_transition_in_progress","remediation":"wait for mandatory authentication and media revocation effects to converge"}';"#
        } else if id == "login-admission-fenced" {
            "RETURN false;"
        } else if id == "login-account-type-mint-unavailable" {
            "IF nextval('gofree_idlogin1_guest_calls')>1 THEN RAISE EXCEPTION 'gofree-idlogin1 mint guest fault'; END IF; RETURN false;"
        } else {
            "RAISE EXCEPTION 'gofree-idlogin1 admission fault';"
        };
        let returns = if id == "login-mint-fenced" {
            "void"
        } else {
            "boolean"
        };
        c.batch_execute(&format!("CREATE OR REPLACE FUNCTION {definition} RETURNS {returns} LANGUAGE plpgsql AS $$BEGIN {branch} END$$")).await?;
        fault_function = Some(original);
    }

    if id == "policy-bad-config" {
        c.execute("INSERT INTO system_config(key,value) VALUES('password_min_length','\"bad\"'::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",&[]).await?;
    }
    if matches!(id, "login-mfa-unavailable" | "login-credential-changed") {
        let original: String = c
            .query_one(
                "SELECT pg_get_functiondef('mfa_status(bigint)'::regprocedure)",
                &[],
            )
            .await?
            .get(0);
        mfa_function = Some(original);
        if id == "login-credential-changed" {
            let hash = bcrypt::hash("Changed1!", 4)?;
            c.batch_execute(&format!(r#"CREATE OR REPLACE FUNCTION mfa_status(p_user_id bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$BEGIN UPDATE users SET password_hash='{hash}' WHERE id=p_user_id; RETURN '{{"status":"exempt"}}'::jsonb; END$$"#)).await?;
        } else {
            c.batch_execute("CREATE OR REPLACE FUNCTION mfa_status(p_user_id bigint) RETURNS jsonb LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'gofree-idlogin1 MFA fault'; END$$").await?;
        }
    }
    if id == "login-store-fault" {
        c.batch_execute(&format!("CREATE FUNCTION gofree_idlogin1_reject_mint() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'gofree-idlogin1 store fault' USING ERRCODE='23514'; END$$; CREATE TRIGGER gofree_idlogin1_reject_mint BEFORE INSERT ON oauth_tokens FOR EACH ROW WHEN (NEW.user_id={}) EXECUTE FUNCTION gofree_idlogin1_reject_mint()",s.a.user)).await?;
    }
    let result = run_case(id, &db, &c, &s, mutation).await;
    c.execute("DELETE FROM guest_accounts WHERE user_id=$1", &[&s.a.user])
        .await?;
    guest_function_pristine(&c).await?;
    if let Some(original) = notify_function {
        c.batch_execute(&original).await?;
    }
    if let Some(original) = fault_function {
        c.batch_execute(&original).await?;
    }
    if id == "login-account-type-mint-unavailable" {
        c.batch_execute("DROP SEQUENCE gofree_idlogin1_guest_calls")
            .await?;
    }
    if let Some(role) = role {
        c.execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&role],
        )
        .await?;
        c.execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
            .await?;
    }
    if let Some(original) = mfa_function {
        c.batch_execute(&original).await?;
    }
    if id == "login-store-fault" {
        c.batch_execute("DROP TRIGGER gofree_idlogin1_reject_mint ON oauth_tokens;DROP FUNCTION gofree_idlogin1_reject_mint()").await?;
    }
    if id == "policy-bad-config" {
        c.execute(
            "DELETE FROM system_config WHERE key='password_min_length'",
            &[],
        )
        .await?;
        c.execute("INSERT INTO system_config SELECT * FROM jsonb_populate_recordset(NULL::system_config,$1::text::jsonb)",&[&saved_policy]).await?;
    }
    c.execute(
        "DELETE FROM used_password_reset_tokens WHERE token_hash<>ALL($1::text[])",
        &[&reset_markers],
    )
    .await?;
    common::restore_receipts(&c, &receipts).await;
    let cleanup = cleanup(&c, &s).await;
    c.query_one(
        "SELECT pg_advisory_unlock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    result?;
    cleanup?;
    Ok(())
}
async fn run_case(
    id: &str,
    db: &Db,
    c: &tokio_postgres::Client,
    s: &Seed,
    mutation: Option<Mutation>,
) -> Result<(), Err> {
    let before_state = mailbox_state(c, s).await?;
    let mut revocations = db.listen("session_revoke").await?;
    let mut f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    if id.starts_with("password-connector-") {
        f["go_source"] = json!("af212c01cfcb9ed599ea9f7f297f1402682718f4");
    }
    if id.starts_with("login-guest") {
        let golden = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/conformance/identity-login/goldens")
            .join(format!("{id}.json"));
        f["go_source"] = json!(recorded_source(
            &golden,
            std::env::var("GOFREE_RECORD_UPSTREAM").is_ok()
        )?);
    }
    let mut cfg = Config::for_secret(f["secret"].as_str().unwrap().into());
    if id == "login-hybrid" {
        cfg.profile = setjoin_config_secret::CryptoProfile::Hybrid;
        cfg.sm2_pem = Some(f["sm2_pem"].as_str().unwrap().into());
    }
    let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
        .map_err(|e| e.0)?;
    let auth = auth_server(Arc::new(
        AuthServer::load(exec, cfg)
            .await?
            .with_threat_gate(&db.dsn)
            .await?,
    ))
    .await;
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    let gw = gateway(
        auth.addr,
        record.clone(),
        !id.starts_with("login-")
            && !id.starts_with("policy-")
            && !id.starts_with("jwks-")
            && !id.starts_with("health-")
            && !id.starts_with("ready-"),
    )
    .await;
    let (route, uri, mut payload, headers, count) = case(id, s);
    let mut presented_tokens = Vec::new();
    let mut headers_owned: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    if id.starts_with("me-")
        || id.starts_with("session-token-")
        || id.starts_with("logout-")
        || id.starts_with("refresh-")
        || id.starts_with("password-")
        || id.starts_with("reset-")
    {
        let (status, _, raw) = request(
            gw.addr,
            "POST",
            "/auth/login",
            json!({"email":s.email,"password":"Password1!"}).to_string(),
            &[],
        )
        .await?;
        assert_eq!(status, 200, "session fixture login: {raw}");
        let v: Value = serde_json::from_str(&raw)?;
        let mut access = v["access_token"].as_str().unwrap().to_owned();
        if id == "password-legacy-email" {
            let keys = setjoin_authz::legacy_jwt::LegacyKeys::new(
                f["secret"].as_str().unwrap().as_bytes(),
                &["authserver-hmac-1"],
                None,
            )?;
            let mut claims = Value::Object(
                keys.validate(
                    &access,
                    "mailserver",
                    "mailserver-gateway",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs_f64(),
                )
                .ok_or("fixture access token")?,
            );
            claims["email"] = json!(format!("\"Display\" <{}>", s.email.to_uppercase()));
            access = setjoin_authz::legacy_jwt::sign_hs256(
                f["secret"].as_str().unwrap().as_bytes(),
                &claims.to_string(),
            );
        }
        if id.starts_with("refresh-") {
            payload = json!({"refresh_token":v["refresh_token"],"user_id":s.b.user}).to_string();
        }
        for key in ["access_token", "refresh_token"] {
            presented_tokens.push((
                format!("presented_{key}"),
                v[key].as_str().unwrap().to_owned(),
            ));
        }
        if id.starts_with("reset-") {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() as i64;
            let mut claims = json!({"uid":s.a.user,"email":s.email,"typ":"password_reset","jti":format!("{}{}",setjoin_identity::login::random_jti()?,setjoin_identity::login::random_jti()?),"iss":"mailserver","sub":s.a.user.to_string(),"aud":["mailserver-gateway"],"iat":now,"nbf":now,"exp":now+300});
            if id == "reset-wrong-type" {
                claims["typ"] = json!("refresh");
            }
            if id == "reset-expired" {
                claims["iat"] = json!(now - 1000);
                claims["nbf"] = json!(now - 1000);
                claims["exp"] = json!(now - 1);
            }
            let reset = setjoin_authz::legacy_jwt::sign_hs256(
                f["secret"].as_str().unwrap().as_bytes(),
                &claims.to_string(),
            );
            payload=json!({"email":s.email,"reset_token":reset,"new_password":"NewPassword2!","user_id":s.b.user}).to_string();
            presented_tokens.push(("presented_reset_token".into(), reset));
            if id == "reset-cross-tenant" {
                let mut input: Value = serde_json::from_str(&payload)?;
                input["email"] = json!(s.foreign);
                payload = input.to_string();
            }
            if id == "reset-invalid-input" {
                payload = "{".into();
            }
            if id == "reset-policy-consumes-token" {
                let mut input: Value = serde_json::from_str(&payload)?;
                input["new_password"] = json!("short");
                payload = input.to_string();
            }
            if id == "reset-unicode-email" {
                let mut input: Value = serde_json::from_str(&payload)?;
                input["email"] = json!(s.email.replace("-k@", "-K@"));
                payload = input.to_string();
            }
        }
        if id == "refresh-cross-tenant" {
            c.execute(
                "UPDATE oauth_tokens SET user_id=$1 WHERE user_id=$2",
                &[&s.b.user, &s.a.user],
            )
            .await?;
        }
        if id == "refresh-invalid-input" {
            payload = "{".into();
        }
        if matches!(
            id,
            "refresh-late-reuse" | "refresh-revoked-grace" | "refresh-expired-grace"
        ) {
            let (status, _, raw) = request(
                gw.addr,
                "POST",
                "/auth/refresh",
                json!({"refresh_token":v["refresh_token"]}).to_string(),
                &[],
            )
            .await?;
            if status != 200 {
                return Err(format!("refresh prewarm failed: {raw}").into());
            }
            let first: Value = serde_json::from_str(&raw)?;
            presented_tokens.push((
                "rotation_start".into(),
                first["refresh_token"].as_str().unwrap().into(),
            ));
            let sql=match id {"refresh-late-reuse"=>"UPDATE oauth_tokens SET rotated_at=now()-interval '31 seconds' WHERE user_id=$1 AND previous_token_hash IS NULL","refresh-revoked-grace"=>"UPDATE oauth_tokens SET revoked_at=now() WHERE user_id=$1 AND previous_token_hash IS NULL",_=>"UPDATE oauth_tokens SET expires_at=now()-interval '1 second' WHERE user_id=$1 AND previous_token_hash IS NULL"};
            c.execute(sql, &[&s.a.user]).await?;
        }
        headers_owned.push((
            "authorization".into(),
            format!(
                "Bearer {}",
                if (id.starts_with("me-")
                    || id.starts_with("session-token-")
                    || id.starts_with("logout-"))
                    && id.ends_with("-invalid-input")
                {
                    "invalid"
                } else {
                    access.as_str()
                }
            ),
        ));
    }
    if matches!(
        id,
        "session-token-cookie"
            | "session-token-empty-cookie"
            | "session-token-invalid-quote"
            | "session-token-bearer-precedence"
            | "session-token-space-before-equals"
    ) {
        let access = presented_tokens
            .iter()
            .find(|(field, _)| field == "presented_access_token")
            .unwrap()
            .1
            .clone();
        headers_owned.retain(|(k, _)| k != "authorization");
        let cookie = match id {
            "session-token-cookie" => format!("before=x; access_token=\"{access}\"; after=y"),
            "session-token-space-before-equals" => format!("access_token =\"{access}\""),
            "session-token-empty-cookie" => format!("access_token=; access_token={access}"),
            "session-token-invalid-quote" => format!("access_token=\"{access}"),
            _ => format!("access_token={access}"),
        };
        headers_owned.push(("cookie".into(), cookie));
        if id == "session-token-bearer-precedence" {
            headers_owned.push(("authorization".into(), "Bearer invalid".into()));
        }
    }
    let headers: Vec<(&str, &str)> = headers_owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    if id == "login-disabled" {
        c.execute("UPDATE users SET enabled=false WHERE id=$1", &[&s.a.user])
            .await?;
    }
    if id == "login-force-change" {
        c.execute(
            "UPDATE users SET must_change_password=true WHERE id=$1",
            &[&s.a.user],
        )
        .await?;
    }
    let mut responses = Vec::new();
    let mut tokens = Vec::new();
    let keys = setjoin_authz::legacy_jwt::LegacyKeys::new(
        f["secret"].as_str().unwrap().as_bytes(),
        &["authserver-hmac-1"],
        None,
    )?;
    for (field, token) in presented_tokens {
        let claims = keys
            .validate(
                &token,
                "mailserver",
                "mailserver-gateway",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs_f64()
                    - if id == "reset-expired" && field == "presented_reset_token" {
                        1000.0
                    } else {
                        0.0
                    },
            )
            .ok_or("invalid fixture token")?;
        tokens.push((field, token, Value::Object(claims)));
    }
    for index in 0..count {
        let sent = if id == "login-lockout-disabled" && index < count - 1 {
            json!({"email":s.email,"password":"wrong"}).to_string()
        } else {
            payload.clone()
        };
        let (status, headers, raw) = request(
            gw.addr,
            route.split_once(' ').unwrap().0,
            &uri,
            sent,
            &headers,
        )
        .await?;
        let expected_status = if matches!(id, "reset-wrong-type" | "reset-expired") {
            401
        } else if matches!(
            id,
            "session-token-empty-cookie"
                | "session-token-invalid-quote"
                | "session-token-bearer-precedence"
        ) {
            401
        } else if id.starts_with("change-password-") {
            404
        } else if matches!(id, "password-repeat" | "password-connector-repeat") {
            if index == 0 {
                204
            } else {
                403
            }
        } else if id == "reset-repeat" {
            if index == 0 {
                200
            } else {
                401
            }
        } else if id == "reset-policy-consumes-token" {
            if index == 0 {
                400
            } else {
                401
            }
        } else if matches!(id, "password-success" | "password-legacy-email" | "password-connector-success") {
            204
        } else if matches!(id, "password-cross-tenant" | "password-connector-cross-tenant" | "reset-cross-tenant") {
            if id.starts_with("password-") {
                403
            } else {
                401
            }
        } else if matches!(id, "password-invalid-input" | "password-connector-invalid-input" | "reset-invalid-input") {
            400
        } else if matches!(id, "refresh-cross-tenant" | "refresh-late-reuse") {
            401
        } else if id == "refresh-invalid-input" {
            400
        } else if id.starts_with("logout-") {
            if id.ends_with("invalid-input") {
                401
            } else {
                204
            }
        } else if (id.starts_with("me-") || id.starts_with("session-token-"))
            && id.ends_with("-invalid-input")
        {
            401
        } else if id == "login-account-type-unavailable" {
            503
        } else if id.ends_with("-unavailable") && id != "login-mfa-unavailable" {
            500
        } else if id == "policy-head" {
            405
        } else if id == "login-lockout-disabled" && index < count - 1 {
            401
        } else if id == "login-mfa-unavailable" {
            503
        } else if id == "login-store-fault" || id == "policy-bad-config" {
            500
        } else if route.starts_with("GET") {
            200
        } else {
            match id {
                "login-cross-tenant"
                | "login-wrong-password"
                | "login-disabled"
                | "login-unknown-user"
                | "login-null"
                | "login-unicode-replacement" => 401,
                "login-admission-fenced" | "login-mint-fenced" => 409,
                "login-credential-changed" => 401,
                "refresh-revoked-grace" | "refresh-expired-grace" => 401,
                "login-invalid-json" | "login-invalid-type" => 400,
                "login-force-change" | "login-csrf-origin" | "login-csrf-fetch" => 403,
                _ => 200,
            }
        };
        if status != expected_status {
            return Err(format!(
                "{id}: expected frozen handler status {expected_status}, got {status}: {raw}"
            )
            .into());
        }
        if id.starts_with("me-") && status == 200 {
            let v: Value = serde_json::from_str(&raw)?;
            if v["user_id"] != s.a.user || v["email"] != s.email {
                return Err("profile escaped verified principal".into());
            }
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as f64;
        let mut returned = Vec::new();
        if let Ok(value) = serde_json::from_str::<Value>(&raw) {
            for field in ["access_token", "refresh_token", "force_token"] {
                if let Some(token) = value[field].as_str() {
                    let claims = keys
                        .validate(token, "mailserver", "mailserver-gateway", now)
                        .ok_or("unverifiable token")?;
                    let expiry = claims["exp"].as_i64().ok_or("no expiry")?
                        - claims["iat"].as_i64().ok_or("no iat")?;
                    let expected = match field {
                        "access_token" => 3600,
                        "refresh_token" => 2592000,
                        _ => 300,
                    };
                    if expiry != expected {
                        return Err("token lifetime changed".into());
                    }
                    let token = (field.to_owned(), token.to_owned(), Value::Object(claims));
                    returned.push(json!({"field":field,"claims":token.2}));
                    tokens.push(token);
                }
            }
        }
        responses.push(json!({"status":status,"headers":headers,"body":raw,"tokens":returned}));
    }
    let mut credential_checks = Vec::new();
    if id.starts_with("password-") || id.starts_with("reset-") {
        for password in ["Password1!", "NewPassword2!"] {
            let (status, _, _) = request(
                gw.addr,
                "POST",
                "/auth/login",
                json!({"email":s.email,"password":password}).to_string(),
                &[],
            )
            .await?;
            credential_checks.push(status);
        }
        if matches!(id, "password-success" | "password-connector-success" | "reset-success") && credential_checks != [401, 200] {
            return Err(format!(
                "credential change was not observable through login: {credential_checks:?}"
            )
            .into());
        }
    }
    if record.is_none() {
        let (status, _, metrics) = request(
            gw.addr,
            "GET",
            setjoin_gateway::metrics::PATH,
            String::new(),
            &[],
        )
        .await?;
        if status != 200
            || !metrics
                .lines()
                .any(|l| l == "setjoin_gateway_proxied_to_go_total 0")
        {
            return Err("native replay attempted a Go hop".into());
        }
    }
    gw.close().await;
    auth.close().await;
    match mutation {
        Some(Mutation::Status) => responses[0]["status"] = json!(418),
        Some(Mutation::NoAudit) => {
            c.execute("DELETE FROM auth_event_log WHERE email=$1", &[&s.email])
                .await?;
        }
        Some(Mutation::NoTenantFilter) => {
            c.execute(
                "UPDATE oauth_tokens SET user_id=$1 WHERE user_id=$2",
                &[&s.b.user, &s.a.user],
            )
            .await?;
        }
        Some(Mutation::DoubleBump) => {
            c.execute(
                "UPDATE mailboxes SET jmap_email_state=jmap_email_state+1 WHERE id=$1",
                &[&s.a.mailbox],
            )
            .await?;
        }
        Some(Mutation::NoNotify) | None => {}
    }
    let state = state_delta(&before_state, &mailbox_state(c, s).await?);
    let mut obs = snapshot(c, s).await?;
    let notices = revocations.drain(c).await?;
    if id.starts_with("reset-")
        || id.starts_with("password-")
        || id.starts_with("logout-")
        || (id.starts_with("refresh-") && !matches!(id, "refresh-success" | "refresh-repeat"))
    {
        obs["notify"] = json!(notices
            .iter()
            .map(|s| serde_json::from_str::<Value>(s))
            .collect::<Result<Vec<_>, _>>()?);
        let raw:String=c.query_one("SELECT jsonb_build_object('revocations',coalesce((SELECT jsonb_agg(to_jsonb(r)-'id' ORDER BY user_id) FROM session_revocations r WHERE user_id=ANY($1::bigint[])),'[]'),'audit',coalesce((SELECT jsonb_agg(jsonb_build_object('action',action,'user_id',user_id,'target_id',target_id,'target_type',target_type,'after_state',after_state) ORDER BY id) FROM admin_audit_log WHERE target_type='user' AND target_id=ANY($1::bigint[])),'[]'))::text",&[&vec![s.a.user,s.b.user]]).await?.get(0);
        obs["security_effects"] = serde_json::from_str::<Value>(&raw)?;
    }

    if id.starts_with("password-") || id.starts_with("reset-") {
        obs["credential_checks"] = json!(credential_checks);
    }
    // Hash/link assertions are performed before generated secrets are masked.
    use sha2::{Digest, Sha256};
    for (field, token, claims) in &tokens {
        if field == "force_token"
            || field.starts_with("presented_")
            || field == "rotation_start"
            || (id.starts_with("refresh-") && field == "access_token")
        {
            continue;
        }
        let table = if field == "access_token" {
            "sessions"
        } else {
            "oauth"
        };
        let digest = format!(
            "\\x{}",
            Sha256::digest(token.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let row = obs["effects"][table]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["token_hash"].as_str() == Some(&digest))
            .ok_or("returned token has no matching durable hash")?;
        if field == "access_token" {
            if row["id"] != claims["jti"] {
                return Err("session jti link changed".into());
            }
        } else if row["family_id"] != claims["fam"] {
            return Err("refresh family link changed".into());
        }
    }
    obs["request"] = json!({"method":route.split_once(' ').unwrap().0,"path":route.split_once(' ').unwrap().1,"body":payload});
    obs["response"] = responses[0].clone();
    if responses.len() > 1 {
        obs["repeat_response"] = responses[1].clone();
    }
    if responses.len() > 2 {
        obs["responses"] = json!(responses);
    }
    normalize(&mut obs, s, &tokens);
    normalize_request(&mut obs);
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/identity-login/goldens")
        .join(format!("{id}.json"));
    let doc =
        json!({"format":1,"go_source":f["go_source"],"route":route,"case":id,"observation":obs});
    if record.is_some() && !path.exists() {
        std::fs::create_dir_all(path.parent().unwrap())?;
        golden::record(&path, &doc)?;
    } else {
        let protected = matches!(id, "refresh-revoked-grace" | "refresh-expired-grace");
        let mut expected: Value = common::expected(&path, protected, &doc);
        normalize(&mut expected["observation"], s, &[]);
        normalize_request(&mut expected["observation"]);
        golden::compare(&expected["observation"], &doc["observation"])?;
        println!("GOLDEN-REPLAY: {route} :: {id}");
    }
    if record.is_some() && (route.starts_with("POST") || route.starts_with("PUT")) {
        let rows = path.with_file_name(format!("{id}-rows.json"));
        let value = json!({"format":1,"go_source":f["go_source"],"route":route,"case":format!("{id}-row-effects"),"effects":[doc["observation"]["effects"]]});
        if !rows.exists() {
            golden::record(&rows, &value)?;
        } else {
            let mut expected: Value = serde_json::from_slice(&std::fs::read(&rows)?)?;
            normalize(&mut expected, s, &[]);
            golden::compare(&expected, &value)?;
        }
    }
    if id.starts_with("password-") || id.starts_with("reset-") {
        let raw:String=c.query_one("SELECT jsonb_build_object('users',coalesce((SELECT jsonb_agg((to_jsonb(u)-'id')||jsonb_build_object('user_id',u.id) ORDER BY u.id) FROM users u WHERE id=ANY($1::bigint[])),'[]'),'history',coalesce((SELECT jsonb_agg((to_jsonb(h)-'id')||jsonb_build_object('matches_current',h.password_hash=u.password_hash) ORDER BY h.id) FROM password_history h JOIN users u ON u.id=h.user_id WHERE h.user_id=ANY($1::bigint[])),'[]'))::text",&[&vec![s.a.user,s.b.user]]).await?.get(0);
        let mut credentials: Value = serde_json::from_str(&raw)?;
        for row in credentials["users"].as_array_mut().unwrap() {
            let domain = if row["user_id"] == s.a.user {
                s.a.domain
            } else {
                s.b.domain
            };
            if row["domain_id"] != domain {
                return Err("credential mutation moved tenant boundary".into());
            }
            let baseline = if row["user_id"] == s.a.user {
                &s.hashes[0]
            } else {
                &s.hashes[1]
            };
            row["password_changed"] =
                json!(row["password_hash"].as_str() != Some(baseline.as_str()));
        }
        let hashes: Vec<String> = tokens
            .iter()
            .filter(|(name, _, _)| name == "presented_reset_token")
            .map(|(_, token, _)| {
                Sha256::digest(token.as_bytes())
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect()
            })
            .collect();
        let raw:String=c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY token_hash),'[]')::text FROM used_password_reset_tokens t WHERE token_hash=ANY($1::text[])",&[&hashes]).await?.get(0);
        credentials["reset_tokens"] = serde_json::from_str(&raw)?;
        normalize(&mut credentials, s, &tokens);
        let value = json!({"format":1,"go_source":f["go_source"],"route":route,"case":format!("{id}-credentials"),"effects":[credentials]});
        let credential_path = path.with_file_name(format!("{id}-credentials.json"));
        if record.is_some() && !credential_path.exists() {
            golden::record(&credential_path, &value)?;
        } else {
            let expected: Value = serde_json::from_slice(&std::fs::read(credential_path)?)?;
            golden::compare(&expected, &value)?;
        }
    }
    if id.starts_with("refresh-")
        || id.starts_with("logout-")
        || id.starts_with("password-")
        || id.starts_with("reset-")
    {
        let raw:String=c.query_one("SELECT coalesce(jsonb_agg(jsonb_build_object('user_id',user_id,'family_id',family_id,'token_hash',token_hash,'previous_token_hash',previous_token_hash,'rotated',rotated_at IS NOT NULL,'revoked',revoked_at IS NOT NULL) ORDER BY id),'[]')::text FROM oauth_tokens WHERE user_id=ANY($1::bigint[])",&[&vec![s.a.user,s.b.user]]).await?.get(0);
        let mut rotation: Value = serde_json::from_str(&raw)?;
        let digest = |token: &str| {
            format!(
                "\\x{}",
                Sha256::digest(token.as_bytes())
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            )
        };
        let mut previous = tokens
            .iter()
            .find(|(f, _, _)| f == "rotation_start")
            .or_else(|| {
                tokens
                    .iter()
                    .find(|(f, _, _)| f == "presented_refresh_token")
            })
            .map(|(_, t, _)| digest(t));
        for (field, token, claims) in &tokens {
            if field != "refresh_token" {
                continue;
            }
            let hash = digest(token);
            let row = rotation
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["token_hash"].as_str() == Some(&hash))
                .ok_or("missing refresh successor")?;
            if row["previous_token_hash"].as_str() != previous.as_deref()
                || row["user_id"] != claims["uid"]
                || row["family_id"] != claims["fam"]
            {
                return Err("refresh chain lost its verified parent/principal/family".into());
            }
            previous = Some(hash);
        }
        normalize(&mut rotation, s, &tokens);
        let rotation_path = path.with_file_name(format!("{id}-rotation.json"));
        let value = json!({"format":1,"go_source":f["go_source"],"route":route,"case":format!("{id}-rotation"),"rotation":rotation});
        if record.is_some() && !rotation_path.exists() {
            golden::record(&rotation_path, &value)?;
        } else {
            let protected = matches!(id, "refresh-revoked-grace" | "refresh-expired-grace");
            let expected: Value = common::expected(&rotation_path, protected, &value);
            golden::compare(&expected, &value)?;
        }
    }
    let state_path = path.with_file_name(format!("{id}-state.json"));
    let state_doc = json!({"format":1,"go_source":f["go_source"],"route":route,"case":format!("{id}-mailbox-state"),"state":state});
    if record.is_some() && !state_path.exists() {
        golden::record(&state_path, &state_doc)?;
    } else {
        let protected = matches!(id, "refresh-revoked-grace" | "refresh-expired-grace");
        let expected: Value = common::expected(&state_path, protected, &state_doc);
        golden::compare(&expected, &state_doc)?;
    }
    Ok(())
}
#[tokio::test]
async fn login_success() {
    run("login-success").await.unwrap();
}

fn case<'a>(
    id: &str,
    s: &'a Seed,
) -> (
    String,
    String,
    String,
    Vec<(&'static str, &'static str)>,
    usize,
) {
    let mut route = "POST /auth/login".to_owned();
    let mut uri = "/auth/login".to_owned();
    let mut payload = json!({"email":s.email,"password":"Password1!"}).to_string();
    let mut headers = Vec::new();
    let mut count = 1;
    match id {
        "change-password-success"|"change-password-cross-tenant"|"change-password-invalid-input"|"change-password-repeat"=>{route="POST /auth/change-password".into();uri="/auth/change-password".into();payload=if id.ends_with("invalid-input"){"{".into()}else{json!({"user_id":s.b.user}).to_string()};if id.ends_with("repeat"){count=2;}},
        "reset-wrong-type" | "reset-expired" | "reset-success" | "reset-cross-tenant" | "reset-invalid-input" | "reset-unicode-email" | "reset-repeat" | "reset-policy-consumes-token" => {if matches!(id,"reset-repeat"|"reset-policy-consumes-token"){count=2;}route="POST /auth/forgot-password/reset".into();uri="/auth/forgot-password/reset".into();},
        "password-success" | "password-cross-tenant" | "password-invalid-input" | "password-legacy-email" | "password-repeat" | "password-connector-success" | "password-connector-invalid-input" | "password-connector-cross-tenant" | "password-connector-repeat" => {if id.ends_with("repeat"){count=2;}route="PUT /auth/password".into();uri="/auth/password".into();payload=json!({"old_password":if id.ends_with("cross-tenant"){"Foreign1!"}else{"Password1!"},"new_password":"NewPassword2!","user_id":s.b.user}).to_string();if id.ends_with("invalid-input"){payload="{".into();}},
        "refresh-success" | "refresh-repeat" | "refresh-cross-tenant" | "refresh-invalid-input" | "refresh-late-reuse" | "refresh-revoked-grace" | "refresh-expired-grace" => {if id=="refresh-repeat"{count=2;}route="POST /auth/refresh".into();uri="/auth/refresh".into();},
        "logout-success" | "logout-repeat" | "logout-cross-tenant" | "logout-invalid-input" => {if id=="logout-repeat" {count=2;}route="POST /auth/logout".into();uri="/auth/logout".into();payload=json!({"user_id":s.b.user}).to_string();},
        "session-token-success" | "session-token-cross-tenant" | "session-token-invalid-input" | "session-token-cookie" | "session-token-empty-cookie" | "session-token-invalid-quote" | "session-token-bearer-precedence" | "session-token-space-before-equals" => {route="GET /auth/session/token".into();uri=format!("/auth/session/token?user_id={}",s.b.user);payload=String::new();},
        "me-success" | "me-cross-tenant" | "me-invalid-input" => {route="GET /auth/me".into();uri=format!("/auth/me?user_id={}&mailbox_id={}",s.b.user,s.b.mailbox);payload=String::new();},
        "login-cross-tenant"=>payload=json!({"email":s.foreign,"password":"Password1!","uid":s.a.user,"mailbox_id":s.a.mailbox}).to_string(),
        "login-unicode-fold"=>payload=json!({"email":s.email,"paſſword":"Password1!"}).to_string(),
        "login-invalid-json"=>payload="{".into(),
        "login-invalid-type"=>payload=r#"{"email":7,"password":"Password1!"}"#.into(),
        "login-null"=>payload="null".into(),
        "login-unicode-replacement"=>payload=r#"{"email":"\ud800","password":"Password1!"}"#.into(),
        "login-ignored-large-number"=>payload=format!(r#"{{"email":{},"password":"Password1!","huge":1e400}}"#,serde_json::to_string(&s.email).unwrap()),
        "login-unknown-user"=>payload=json!({"email":"nobody@idlogin1.test","password":"Password1!"}).to_string(),
        "login-wrong-password"=>payload=json!({"email":s.email,"password":"wrong"}).to_string(),
        "login-case-fold"=>payload=json!({"EMAIL":s.email.to_uppercase(),"PASSWORD":"Password1!","uid":s.b.user,"mailbox_id":s.b.mailbox}).to_string(),
        "login-trailing-value"=>payload += " {}trailing ignored by first Decode",
        "login-repeat"=>count=2,
        "login-guest-repeat"=>count=2,
        "login-lockout-disabled"=>count=11,
        "login-csrf-origin"=>headers.push(("origin","https://evil.idlogin1.test")),
        "login-csrf-fetch"=>headers.push(("sec-fetch-site","cross-site")),
        "login-secure-cookie"=>headers.push(("origin","http://auth.idlogin1.test")),
        _=>{}
    }
    for (prefix, path) in [
        ("policy-", "/auth/password-policy"),
        ("jwks-", "/.well-known/jwks.json"),
        ("health-", "/health"),
        ("ready-", "/ready"),
    ] {
        if id.starts_with(prefix) {
            route = format!(
                "{} {path}",
                if id.ends_with("-head") { "HEAD" } else { "GET" }
            );
            uri = path.into();
            payload = String::new();
            if id.ends_with("cross-tenant") {
                headers.push(("x-user-id", "forged-other-user"));
                headers.push(("x-mailbox-id", "forged-other-mailbox"));
            }
            if id.ends_with("invalid-input") {
                uri += "?uid=not-an-id&minLength=invalid";
                payload = "{".into();
            }
        }
    }
    (route, uri, payload, headers, count)
}
macro_rules! case_test {
    ($name:ident,$id:literal) => {
        #[tokio::test]
        async fn $name() {
            run($id).await.unwrap();
        }
    };
}
case_test!(login_cross_tenant, "login-cross-tenant");
case_test!(login_invalid_json, "login-invalid-json");
case_test!(login_invalid_type, "login-invalid-type");
case_test!(login_null, "login-null");
case_test!(login_unknown_user, "login-unknown-user");
case_test!(login_wrong_password, "login-wrong-password");
case_test!(login_case_fold, "login-case-fold");
case_test!(login_trailing_value, "login-trailing-value");
case_test!(login_repeat, "login-repeat");
case_test!(login_csrf_origin, "login-csrf-origin");
case_test!(login_csrf_fetch, "login-csrf-fetch");
case_test!(login_disabled, "login-disabled");
case_test!(login_force_change, "login-force-change");
case_test!(guest_login_ok, "login-guest-success");
case_test!(guest_login_repeat, "login-guest-repeat");
case_test!(guest_login_expired, "login-guest-expired");
case_test!(policy_success, "policy-success");
case_test!(policy_cross_tenant, "policy-cross-tenant");
case_test!(policy_invalid_input, "policy-invalid-input");
case_test!(jwks_success, "jwks-success");
case_test!(jwks_cross_tenant, "jwks-cross-tenant");
case_test!(jwks_invalid_input, "jwks-invalid-input");
case_test!(health_success, "health-success");
case_test!(health_cross_tenant, "health-cross-tenant");
case_test!(health_invalid_input, "health-invalid-input");
case_test!(ready_success, "ready-success");
case_test!(ready_cross_tenant, "ready-cross-tenant");
case_test!(ready_invalid_input, "ready-invalid-input");

// Request-owned ids are generated fixture inputs, never response claims.
fn normalize_request(obs: &mut Value) {
    let Some(raw) = obs["request"]["body"].as_str() else {
        return;
    };
    let Ok(Value::Object(mut object)) = serde_json::from_str::<Value>(raw) else {
        return;
    };
    for (k, v) in object.iter_mut() {
        match k.to_ascii_lowercase().as_str() {
            "uid" | "user_id" if v.is_number() => *v = json!("<request-user>"),
            "mailbox_id" if v.is_number() => *v = json!("<request-mailbox>"),
            "email" => {
                if let Some(email) = v.as_str() {
                    let local = email.split('@').next().unwrap_or("");
                    if local.eq_ignore_ascii_case("idlogin1-actor") {
                        *v = json!(if local == local.to_uppercase() {
                            "ACTOR@<domain>"
                        } else {
                            "actor@<domain>"
                        });
                    } else if local.eq_ignore_ascii_case("idlogin1-foreign") {
                        *v = json!("foreign@<domain>");
                    }
                }
            }
            _ => {}
        }
    }
    obs["request"]["body"] = json!(Value::Object(object).to_string());
}

async fn mailbox_state(c: &tokio_postgres::Client, s: &Seed) -> Result<Value, Err> {
    let mut out = serde_json::Map::new();
    for (name, id) in [("actor", s.a.mailbox), ("foreign", s.b.mailbox)] {
        let raw: String = c
            .query_one(
                "SELECT to_jsonb(m)::text FROM mailboxes m WHERE id=$1",
                &[&id],
            )
            .await?
            .get(0);
        let object: serde_json::Map<String, Value> = serde_json::from_str(&raw)?;
        out.insert(
            name.into(),
            Value::Object(
                object
                    .into_iter()
                    .filter(|(k, _)| k.starts_with("jmap_") && k.ends_with("_state"))
                    .collect(),
            ),
        );
    }
    Ok(Value::Object(out))
}
fn state_delta(before: &Value, after: &Value) -> Value {
    let mut out = after.clone();
    for (name, row) in out.as_object_mut().unwrap() {
        for (k, v) in row.as_object_mut().unwrap() {
            *v = json!(v.as_i64().unwrap() - before[name][k].as_i64().unwrap());
        }
    }
    out
}
async fn reject_mutant(id: &str, mutation: Mutation, route: &str, name: &str, field: &str) {
    assert!(
        std::env::var_os("GOFREE_RECORD_UPSTREAM").is_none(),
        "mutants must run against native Rust"
    );
    let error = run_mutated(id, Some(mutation))
        .await
        .expect_err("planted mutant escaped the Go oracle")
        .to_string();
    assert!(
        error.contains(field),
        "mutant failed for another reason: {error}"
    );
    println!("MUTANT-REJECTED: {route} :: {name}");
}
#[tokio::test]
async fn login_status_mutant() {
    reject_mutant(
        "login-success",
        Mutation::Status,
        "POST /auth/login",
        "status",
        "/response/status",
    )
    .await;
}
#[tokio::test]
async fn policy_status_mutant() {
    reject_mutant(
        "policy-success",
        Mutation::Status,
        "GET /auth/password-policy",
        "status",
        "/response/status",
    )
    .await;
}
#[tokio::test]
async fn jwks_status_mutant() {
    reject_mutant(
        "jwks-success",
        Mutation::Status,
        "GET /.well-known/jwks.json",
        "status",
        "/response/status",
    )
    .await;
}
#[tokio::test]
async fn health_status_mutant() {
    reject_mutant(
        "health-success",
        Mutation::Status,
        "GET /health",
        "status",
        "/response/status",
    )
    .await;
}
#[tokio::test]
async fn ready_status_mutant() {
    reject_mutant(
        "ready-success",
        Mutation::Status,
        "GET /ready",
        "status",
        "/response/status",
    )
    .await;
}
#[tokio::test]
async fn no_audit_mutant() {
    reject_mutant(
        "login-success",
        Mutation::NoAudit,
        "POST /auth/login",
        "no-audit",
        "/audit",
    )
    .await;
}
#[tokio::test]
async fn no_tenant_filter_mutant() {
    reject_mutant(
        "login-success",
        Mutation::NoTenantFilter,
        "POST /auth/login",
        "no-tenant-filter",
        "/effects/oauth",
    )
    .await;
}
#[tokio::test]
async fn double_bump_mutant() {
    reject_mutant(
        "login-success",
        Mutation::DoubleBump,
        "POST /auth/login",
        "double-bump",
        "/state/actor/jmap_email_state",
    )
    .await;
}

case_test!(login_unicode_replacement, "login-unicode-replacement");
case_test!(login_ignored_large_number, "login-ignored-large-number");

case_test!(login_hybrid, "login-hybrid");

case_test!(login_lockout_disabled, "login-lockout-disabled");
case_test!(login_mfa_unavailable, "login-mfa-unavailable");
case_test!(login_store_fault, "login-store-fault");
case_test!(policy_bad_config, "policy-bad-config");

#[tokio::test]
async fn public_head_routes_preserve_go_representation_lengths() {
    for id in ["policy-head", "jwks-head", "health-head", "ready-head"] {
        run(id).await.unwrap();
    }
}

case_test!(login_unicode_fold, "login-unicode-fold");

case_test!(login_admission_unavailable, "login-admission-unavailable");
case_test!(
    login_account_type_unavailable,
    "login-account-type-unavailable"
);
case_test!(login_scope_unavailable, "login-scope-unavailable");

case_test!(login_admission_fenced, "login-admission-fenced");

case_test!(
    login_account_type_mint_unavailable,
    "login-account-type-mint-unavailable"
);

case_test!(login_mint_fenced, "login-mint-fenced");

case_test!(login_credential_changed, "login-credential-changed");

case_test!(me_success, "me-success");

case_test!(me_cross_tenant, "me-cross-tenant");
case_test!(me_invalid_input, "me-invalid-input");
case_test!(session_token_success, "session-token-success");

case_test!(logout_success, "logout-success");
case_test!(session_token_cross_tenant, "session-token-cross-tenant");
case_test!(session_token_invalid_input, "session-token-invalid-input");

case_test!(logout_repeat, "logout-repeat");

case_test!(logout_cross_tenant, "logout-cross-tenant");
case_test!(logout_invalid_input, "logout-invalid-input");

case_test!(refresh_success, "refresh-success");

case_test!(refresh_repeat, "refresh-repeat");

case_test!(refresh_cross_tenant, "refresh-cross-tenant");
case_test!(refresh_invalid_input, "refresh-invalid-input");

case_test!(refresh_late_reuse, "refresh-late-reuse");
case_test!(refresh_revoked_grace, "refresh-revoked-grace");
case_test!(refresh_expired_grace, "refresh-expired-grace");

case_test!(password_success, "password-success");
case_test!(password_connector_success, "password-connector-success");
case_test!(password_connector_invalid_input, "password-connector-invalid-input");
case_test!(password_connector_cross_tenant, "password-connector-cross-tenant");
case_test!(password_connector_repeat, "password-connector-repeat");

case_test!(reset_success, "reset-success");

case_test!(password_cross_tenant, "password-cross-tenant");
case_test!(password_invalid_input, "password-invalid-input");
case_test!(reset_cross_tenant, "reset-cross-tenant");
case_test!(reset_invalid_input, "reset-invalid-input");

case_test!(password_legacy_email, "password-legacy-email");
case_test!(reset_unicode_email, "reset-unicode-email");

case_test!(password_repeat, "password-repeat");
case_test!(reset_repeat, "reset-repeat");
case_test!(reset_policy_consumes_token, "reset-policy-consumes-token");

case_test!(change_password_success, "change-password-success");
case_test!(change_password_cross_tenant, "change-password-cross-tenant");
case_test!(
    change_password_invalid_input,
    "change-password-invalid-input"
);
case_test!(change_password_repeat, "change-password-repeat");

case_test!(session_token_cookie, "session-token-cookie");
case_test!(session_token_empty_cookie, "session-token-empty-cookie");
case_test!(session_token_invalid_quote, "session-token-invalid-quote");
case_test!(
    session_token_bearer_precedence,
    "session-token-bearer-precedence"
);

case_test!(
    session_token_space_before_equals,
    "session-token-space-before-equals"
);

case_test!(reset_wrong_type, "reset-wrong-type");
case_test!(reset_expired, "reset-expired");
macro_rules! session_status_mutant {
    ($test:ident,$case:literal,$route:literal) => {
        #[tokio::test]
        async fn $test() {
            reject_mutant(
                $case,
                Mutation::Status,
                $route,
                "status",
                "/response/status",
            )
            .await;
        }
    };
}
session_status_mutant!(me_status_mutant, "me-success", "GET /auth/me");
session_status_mutant!(
    session_token_status_mutant,
    "session-token-success",
    "GET /auth/session/token"
);
session_status_mutant!(logout_status_mutant, "logout-success", "POST /auth/logout");
session_status_mutant!(
    refresh_status_mutant,
    "refresh-success",
    "POST /auth/refresh"
);
session_status_mutant!(
    password_status_mutant,
    "password-success",
    "PUT /auth/password"
);
session_status_mutant!(
    reset_status_mutant,
    "reset-success",
    "POST /auth/forgot-password/reset"
);
session_status_mutant!(
    change_password_status_mutant,
    "change-password-success",
    "POST /auth/change-password"
);
macro_rules! session_notify_mutant {
    ($test:ident,$case:literal,$route:literal) => {
        #[tokio::test]
        async fn $test() {
            reject_mutant($case, Mutation::NoNotify, $route, "no-notify", "/notify").await;
        }
    };
}
session_notify_mutant!(
    logout_no_notify_mutant,
    "logout-success",
    "POST /auth/logout"
);
session_notify_mutant!(
    password_no_notify_mutant,
    "password-success",
    "PUT /auth/password"
);
session_notify_mutant!(
    password_connector_no_notify_mutant,
    "password-connector-success",
    "PUT /auth/password"
);
session_notify_mutant!(
    reset_no_notify_mutant,
    "reset-success",
    "POST /auth/forgot-password/reset"
);
session_notify_mutant!(
    refresh_no_notify_mutant,
    "refresh-late-reuse",
    "POST /auth/refresh"
);

session_notify_mutant!(
    logout_gateway_no_notify_mutant,
    "logout-success",
    "POST /auth/logout"
);
session_notify_mutant!(
    refresh_gateway_no_notify_mutant,
    "refresh-late-reuse",
    "POST /auth/refresh"
);
