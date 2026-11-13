//! #271: frozen-Go parity for F22 (static, health, metrics, telemetry), F20
//! (Assist) and Chat's translate route. One case table drives recording
//! (`GOFREE_RECORD_GO_BINARY`, through the front door with Go as upstream)
//! and replay (Rust adapters, Go out of the path). Cases that Rust hands to Go
//! by design replay against a fake upstream serving the recorded Go answer and
//! must be forwarded exactly once. The case table is generated; see
//! `tests/conformance/static1/README.md`.
mod common;
use common::BoxError;
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

static SERIAL: Mutex<()> = Mutex::new(());
include!("static_oracle/cases.rs");

#[derive(Clone, Copy, PartialEq)]
pub enum Auth {
    None,
    Actor,
    Foreign,
    ActorPerm,
    ActorAdmin,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Cfg {
    Default,
    Website,
    MetricsToken,
    MetricsOpen,
    Hybrid,
    ImapPlain,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Provider {
    None,
    Ok,
    Fail,
    Empty,
    BadUrl,
    Sealed,
}

#[derive(Clone)]
pub struct World {
    pub assist: Option<bool>,
    pub provider: Provider,
    pub compliance: bool,
    pub chat: bool,
    pub toggles: Vec<(&'static str, bool)>,
    pub health: Option<&'static str>,
    pub telemetry: Option<&'static str>,
}

#[derive(Clone)]
pub struct Case {
    pub name: &'static str,
    pub route: &'static str,
    pub kind: &'static str,
    pub method: &'static str,
    pub uri: &'static str,
    pub headers: Vec<(&'static str, &'static str)>,
    pub body: &'static str,
    pub auth: Auth,
    pub cfg: Cfg,
    pub forwarded: bool,
    /// Send the request twice on one connection and observe both answers.
    pub repeat: bool,
    /// Go cannot be recorded for this case (it refuses to start): the case
    /// only proves the whole request is forwarded.
    pub contract: bool,
    pub world: World,
}

#[derive(Clone, Copy, PartialEq)]
enum Mutant {
    None,
    Status,
    /// The adapter skips the identity or domain predicate the case relies on.
    NoFilter,
    NoDeviceProof,
    DoubleReport,
}

fn recording() -> bool {
    std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some()
}

fn extra_env(cfg: Cfg) -> &'static str {
    match cfg {
        Cfg::Default => "",
        Cfg::Website => "WEBSITE_DIR=/evidence/website",
        Cfg::MetricsToken => "METRICS_TOKEN=static1-metrics",
        Cfg::MetricsOpen => "METRICS_ALLOW_UNAUTHENTICATED=1",
        Cfg::Hybrid => "CRYPTO_ALGORITHM_PROFILE=hybrid",
        Cfg::ImapPlain => "IMAP_TLS_ADDR=",
    }
}

fn surface_config(cfg: Cfg) -> setjoin_gateway::surface::SurfaceConfig {
    use setjoin_static::{metrics::MetricsAuth, wellknown::SetJoinConfig};
    let (profile, field, hint) = if cfg == Cfg::Hybrid {
        ("hybrid", "", "")
    } else {
        ("standard", "", "")
    };
    setjoin_gateway::surface::SurfaceConfig {
        network_mode: "airgap".into(),
        website_dir: cfg == Cfg::Website,
        setjoin: SetJoinConfig {
            crypto_profile: profile.into(),
            login_field: field.into(),
            login_domain_hint: hint.into(),
        },
        imap_tls: cfg != Cfg::ImapPlain,
        metrics: match cfg {
            Cfg::MetricsToken => MetricsAuth::from_values("static1-metrics", ""),
            Cfg::MetricsOpen => MetricsAuth::from_values("", "1"),
            _ => MetricsAuth::from_values("", ""),
        },
        probes_configured: false,
    }
}

fn token(user: i64, perms: Option<&[&str]>, admin: bool) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let header =
        URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","kid":"test-es256-1","typ":"JWT"}).to_string());
    let mut claims = json!({"uid":user,"email":"static1@test","admin":admin,"typ":"access","jti":"static1-test","fam":"static1-test","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600});
    if let Some(perms) = perms {
        claims["perms"] = json!(perms);
    }
    let claims = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{header}.{claims}").as_bytes());
    format!(
        "{header}.{claims}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

/// Everything that identifies a run: replaced by stable placeholders.
struct Ids {
    actor_domain: String,
    foreign_domain: String,
    message: Option<i64>,
    device: Option<i64>,
    foreign_device: Option<i64>,
}

fn scrub(text: &str, ids: &Ids) -> String {
    let mut out = text
        .replace(&ids.actor_domain, "<actor-domain>")
        .replace(&ids.foreign_domain, "<foreign-domain>");
    if let Some(message) = ids.message {
        out = out.replace(&format!("/messages/{message}/"), "/messages/<message>/");
    }
    out
}

const PROCESS_LINES: [&str; 8] = [
    "gateway_requests_total ",
    "gateway_request_errors_total ",
    "gateway_request_4xx_total ",
    "gateway_request_5xx_total ",
    "gateway_request_duration_ms_total ",
    "gateway_active_connections ",
    "gateway_memory_alloc_bytes ",
    "gateway_goroutines_total ",
];

/// Process counters differ per process; every other metrics line is compared.
fn blur_metrics(text: &str) -> String {
    text.lines()
        .map(
            |line| match PROCESS_LINES.iter().find(|p| line.starts_with(**p)) {
                Some(prefix) => format!("{prefix}<n>\n"),
                None => format!("{line}\n"),
            },
        )
        .collect()
}

fn observe_response(
    case: &Case,
    status: u16,
    headers: &hyper::HeaderMap,
    body: &[u8],
    ids: &Ids,
) -> Value {
    let mut map = serde_json::Map::new();
    let mut names: Vec<_> = headers.keys().map(|k| k.as_str().to_owned()).collect();
    names.sort();
    names.dedup();
    for name in names {
        if matches!(
            name.as_str(),
            "date" | "content-length" | "transfer-encoding"
        ) {
            continue;
        }
        let values: Vec<_> = headers
            .get_all(name.as_str())
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect();
        map.insert(name, Value::String(scrub(&values.join(", "), ids)));
    }
    let mut observed = json!({"status": status, "headers": map});
    let mut bytes = body.to_vec();
    if case.route == "GET /metrics" && status == 200 {
        bytes = blur_metrics(&String::from_utf8_lossy(&bytes)).into_bytes();
    }
    let text = String::from_utf8(bytes.clone())
        .ok()
        .map(|t| scrub(&t, ids));
    let hashed = text
        .as_ref()
        .map_or(bytes.clone(), |t| t.clone().into_bytes());
    observed["body_sha256"] = format!("{:x}", Sha256::digest(&hashed)).into();
    observed["body_length"] = hashed.len().into();
    if let Some(text) = text.filter(|t| t.len() <= 4096) {
        observed["body_text"] = text.into();
    }
    observed
}

fn golden_path(case: &Case, suffix: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../tests/conformance/static1/goldens/{}{suffix}.json",
        case.name.replace('_', "-")
    ))
}

struct ChangedStatus<R: setjoin_gateway::Intercept>(R);
impl<R: setjoin_gateway::Intercept> setjoin_gateway::Intercept for ChangedStatus<R> {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.0.matches(r)
    }
    fn admits_member(
        &self,
        h: hyper::HeaderMap,
        s: &'static str,
    ) -> setjoin_gateway::BoxFuture<bool> {
        self.0.admits_member(h, s)
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let future = self.0.handle(r, c);
        Box::pin(async move {
            let mut response = future.await;
            *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            response
        })
    }
}

/// Mutant: answers without the identity or domain predicate the case relies on.
struct NoFilter {
    autoconfig: bool,
}
impl setjoin_gateway::Intercept for NoFilter {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        if self.autoconfig {
            r.uri().path().ends_with("/config-v1.1.xml")
        } else {
            r.uri().path().starts_with("/api/assist/")
        }
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let autoconfig = self.autoconfig;
        Box::pin(async move {
            let _ = c;
            let (status, body) = if autoconfig {
                let host = r.headers()["host"].to_str().unwrap().to_owned();
                let domain = setjoin_static::wellknown::autoconfig_domain(&host);
                (
                    200,
                    setjoin_static::wellknown::autoconfig_xml(&domain, false),
                )
            } else {
                (200, "{\"content\":\"unauthenticated\"}\n".to_owned())
            };
            let mut response = Response::new(common::full(body));
            *response.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
            response
        })
    }
}

async fn run(name: &str) -> Result<(), BoxError> {
    run_inner(name, Mutant::None).await
}

/// Sealed provider keys and device proofs open with the oracle's public non-production key
/// material (the same values `common/go_oracle.rs` records with); the lane must not depend on
/// the caller's shell exporting them (#472).
fn oracle_key_material() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::env::set_var("DB_ENCRYPTION_KEY", "22".repeat(32));
        std::env::set_var("JWT_SECRET", "blobs1-test-jwt-secret-for-recording");
    });
}

async fn run_inner(name: &str, mutant: Mutant) -> Result<(), BoxError> {
    oracle_key_material();
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let record = recording();
    if mutant != Mutant::None && record {
        return Err("mutants never record".into());
    }
    let case = cases()
        .into_iter()
        .find(|c| c.name == name)
        .ok_or("unknown case")?;
    let Some(db) = Db::for_case("static1") else {
        return Ok(());
    };
    let owner = Arc::new(db.connect().await?);
    // Go boot migrates legacy secrets using identity.deployment_id. Restore
    // the pair together so a later oracle never inherits mismatched AAD.
    let config_before: Option<String> = if record {
        Some(owner.query_one("SELECT coalesce(jsonb_agg(to_jsonb(s)),'[]'::jsonb)::text FROM system_config s", &[]).await?.get(0))
    } else {
        None
    };
    let actor = setjoin_conformance::fixture::account(&owner, "static1-actor").await?;
    let foreign = setjoin_conformance::fixture::account(&owner, "static1-foreign").await?;
    let domain_of = |id: i64| {
        let owner = owner.clone();
        async move {
            Ok::<String, BoxError>(
                owner
                    .query_one("SELECT name FROM domains WHERE id=$1", &[&id])
                    .await?
                    .get(0),
            )
        }
    };
    let mut ids = Ids {
        actor_domain: domain_of(actor.domain).await?,
        foreign_domain: domain_of(foreign.domain).await?,
        message: None,
        device: None,
        foreign_device: None,
    };
    let mut undo: Vec<(String, Vec<String>)> = Vec::new();
    let result = run_case(
        &case, mutant, record, &db, &owner, &actor, &foreign, &mut ids, &mut undo,
    )
    .await;
    // Restore in reverse order, even when the case failed.
    for (sql, params) in undo.into_iter().rev() {
        let refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = params
            .iter()
            .map(|p| p as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();
        let _ = owner.execute(sql.as_str(), &refs).await;
    }
    if let Some(config) = config_before {
        owner
            .batch_execute("BEGIN; DELETE FROM system_config")
            .await?;
        owner.execute("INSERT INTO system_config SELECT r.* FROM jsonb_populate_recordset(NULL::system_config,$1::text::jsonb) r", &[&config]).await?;
        owner.batch_execute("COMMIT").await?;
    }
    owner.batch_execute("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE action='console.denied' AND before_state->>'actor'='static1@test';COMMIT").await?;
    setjoin_conformance::fixture::remove(&owner, &actor).await?;
    setjoin_conformance::fixture::remove(&owner, &foreign).await?;
    result
}

#[allow(clippy::too_many_arguments)]
async fn run_case(
    case: &Case,
    mutant: Mutant,
    record: bool,
    db: &Db,
    owner: &Arc<tokio_postgres::Client>,
    actor: &setjoin_conformance::fixture::Account,
    foreign: &setjoin_conformance::fixture::Account,
    ids: &mut Ids,
    undo: &mut Vec<(String, Vec<String>)>,
) -> Result<(), BoxError> {
    let world = &case.world;
    let mut toggles: Vec<(&str, bool)> = world.toggles.clone();
    if let Some(on) = world.assist {
        toggles.push(("feature.assist", on));
    }
    if world.chat {
        toggles.push(("feature.chat", true));
    }
    toggles.push(("feature.chat_compliance", world.compliance));
    for (key, on) in toggles {
        let previous: Option<bool> = owner
            .query_opt("SELECT enabled FROM feature_toggles WHERE key=$1", &[&key])
            .await?
            .map(|r| r.get(0));
        owner
            .execute(
                "INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET enabled=excluded.enabled",
                &[&key, &on],
            )
            .await?;
        match previous {
            Some(p) => undo.push((
                "UPDATE feature_toggles SET enabled=($2::text)::boolean WHERE key=$1".into(),
                vec![key.into(), p.to_string()],
            )),
            None => undo.push((
                "DELETE FROM feature_toggles WHERE key=$1".into(),
                vec![key.into()],
            )),
        }
    }
    if let Some(status) = world.health {
        let name = format!("static1-{}", case.name);
        owner
            .execute(
                "INSERT INTO health_history(check_name,status,details) VALUES($1,$2,'static1 oracle')",
                &[&name, &status],
            )
            .await?;
        undo.push((
            "DELETE FROM health_history WHERE check_name=$1".into(),
            vec![name],
        ));
    }
    if world.telemetry.is_some() {
        let envelope = setjoin_config_secret::seal_column(
            b"static2-device-secret",
            b"blobs1-test-jwt-secret-for-recording",
            setjoin_config_secret::CryptoProfile::Standard,
        )?;
        let device: i64 = owner.query_one("INSERT INTO devices(user_id,fingerprint,hmac_secret_enc,hmac_secret_key_id,enroll_state) VALUES($1,'static2-proof',$2,'v1','approved') RETURNING id", &[&actor.user,&envelope]).await?.get(0);
        ids.device = Some(device);
        if world.telemetry == Some("foreign") {
            let envelope = setjoin_config_secret::seal_column(
                b"static2-foreign-secret",
                b"blobs1-test-jwt-secret-for-recording",
                setjoin_config_secret::CryptoProfile::Standard,
            )?;
            ids.foreign_device = Some(owner.query_one("INSERT INTO devices(user_id,fingerprint,hmac_secret_enc,hmac_secret_key_id,enroll_state) VALUES($1,'static2-foreign-proof',$2,'v1','approved') RETURNING id", &[&foreign.user,&envelope]).await?.get(0));
        }
        if world
            .telemetry
            .is_some_and(|mode| mode.starts_with("legacy-"))
        {
            owner.execute("UPDATE devices SET hmac_secret='static2-device-secret',hmac_secret_enc=NULL,hmac_secret_key_id=NULL WHERE id=$1 AND user_id=$2", &[&device,&actor.user]).await?;
        }
    }
    // Provider: a fake OpenAI-compatible endpoint plus the `system_config` rows.
    let seen = Arc::new(Mutex::new(Vec::<Value>::new()));
    let mode = world.provider;
    let provider = if mode == Provider::None {
        None
    } else {
        let seen = seen.clone();
        Some(
            common::fake_upstream(move |request| {
                let seen = seen.clone();
                async move {
                    let uri = request.uri().to_string();
                    let method = request.method().to_string();
                    let authorization = request
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    let content_type = request
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    let bytes = request.into_body().collect().await.unwrap().to_bytes();
                    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                    seen.lock().unwrap().push(json!({"uri":uri,"method":method,"authorization":authorization,"contentType":content_type,"body":body}));
                    let (status, reply) = match mode {
                        Provider::Fail => (500, r#"{"error":"boom"}"#),
                        Provider::Empty => (200, r#"{"choices":[]}"#),
                        _ => (200, r#"{"choices":[{"message":{"content":"Static1 <completion> & more"}}]}"#),
                    };
                    Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(common::full(reply))
                        .unwrap()
                }
            })
            .await,
        )
    };
    if let Some(provider) = provider {
        let url = if mode == Provider::BadUrl {
            "ftp://static1.invalid/v1".to_owned()
        } else {
            format!("http://{provider}/v1")
        };
        let key = if mode == Provider::Sealed {
            {
                let deployment = "static2-deployment";
                let codec = setjoin_config_secret::ConfigSecretCodec::new(
                    setjoin_config_secret::keyring_from_env(deployment)?,
                )?;
                String::from_utf8(codec.encrypt("assist.api_key", br#""static1-key""#)?)?
            }
        } else {
            "\"static1-key\"".to_owned()
        };
        for (name, value) in [
            ("identity.deployment_id", "\"static2-deployment\"".into()),
            ("assist.provider_url", format!("\"{url}\"")),
            ("assist.model", "\"static1-model\"".to_owned()),
            ("assist.api_key", key),
        ] {
            let previous: Option<String> = owner
                .query_opt(
                    "SELECT value::text FROM system_config WHERE key=$1",
                    &[&name],
                )
                .await?
                .map(|r| r.get(0));
            owner
                .execute(
                    "INSERT INTO system_config(key,value) VALUES($1,$2::text::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    &[&name, &value],
                )
                .await?;
            match previous {
                Some(p) => undo.push((
                    "UPDATE system_config SET value=$2::text::jsonb WHERE key=$1".into(),
                    vec![name.into(), p],
                )),
                None => undo.push((
                    "DELETE FROM system_config WHERE key=$1".into(),
                    vec![name.into()],
                )),
            }
        }
    }
    // Chat world: a private channel with one message the actor owns.
    let mut chat = None;
    if world.chat {
        let channel: i64 = owner
            .query_one(
                "INSERT INTO chat_channels(kind,name,visibility,created_by) VALUES('channel',$1,'private',$2) RETURNING id",
                &[&format!("static1-{}-{}", case.name, actor.user), &actor.user],
            )
            .await?
            .get(0);
        owner
            .execute(
                "INSERT INTO chat_channel_members(channel_id,user_id,role) VALUES($1,$2,'owner')",
                &[&channel, &actor.user],
            )
            .await?;
        let raw: String = owner
            .query_one(
                "SELECT chat_message_send($1,$2,'Translate this message',NULL,'{}',NULL,'[]','text',NULL)::text",
                &[&actor.user, &channel],
            )
            .await?
            .get(0);
        let message = serde_json::from_str::<Value>(&raw)?["messageId"]
            .as_i64()
            .ok_or("message ID")?;
        ids.message = Some(message);
        chat = Some((channel, message));
    }
    let result = observe_and_compare(
        case, mutant, record, db, owner, actor, foreign, ids, &seen, chat,
    )
    .await;
    if let Some((channel, _)) = chat {
        owner
            .batch_execute(&format!(
                "BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM chat_audit_log WHERE channel_id={channel};COMMIT"
            ))
            .await?;
        owner
            .execute("DELETE FROM chat_messages WHERE channel_id=$1", &[&channel])
            .await?;
        owner
            .execute(
                "DELETE FROM chat_channels WHERE id=$1 AND created_by=$2",
                &[&channel, &actor.user],
            )
            .await?;
    }
    result
}

async fn chat_state(
    c: &tokio_postgres::Client,
    channel: i64,
    message: i64,
) -> Result<Value, BoxError> {
    let raw: String = c
        .query_one(
            "SELECT jsonb_build_object('body',body,'seq',seq,'changeSeq',(SELECT change_seq FROM chat_channels WHERE id=$2),'chainValid',(SELECT coalesce(bool_and(valid),true) FROM verify_chat_audit_chain($2)))::text FROM chat_messages WHERE id=$1 AND channel_id=$2",
            &[&message, &channel],
        )
        .await?
        .get(0);
    Ok(serde_json::from_str(&raw)?)
}

async fn chat_audit(c: &tokio_postgres::Client, channel: i64) -> Result<Vec<Value>, BoxError> {
    c.query(
        "SELECT jsonb_build_object('action',action,'after',after_state-'_checksum'-'_prev_checksum','targetType',target_type)::text FROM chat_audit_log WHERE channel_id=$1 ORDER BY id",
        &[&channel],
    )
    .await?
    .into_iter()
    .map(|r| serde_json::from_str::<Value>(r.get::<_, &str>(0)).map_err(Into::into))
    .collect()
}

#[allow(clippy::too_many_arguments)]
async fn observe_and_compare(
    case: &Case,
    mutant: Mutant,
    record: bool,
    db: &Db,
    owner: &Arc<tokio_postgres::Client>,
    actor: &setjoin_conformance::fixture::Account,
    foreign: &setjoin_conformance::fixture::Account,
    ids: &Ids,
    seen: &Arc<Mutex<Vec<Value>>>,
    chat: Option<(i64, i64)>,
) -> Result<(), BoxError> {
    let (method, route_name) = case.route.split_once(' ').unwrap();
    let route_path = route_name.split(' ').next().unwrap();
    let uri = case.uri.replace(
        "{message}",
        &ids.message.map(|m| m.to_string()).unwrap_or_default(),
    );
    let fill = |s: &str| {
        s.replace("{domain}", &ids.actor_domain)
            .replace("{DOMAIN}", &ids.actor_domain.to_uppercase())
            .replace("{foreign_user}", &foreign.user.to_string())
            .replace("{device}", &ids.device.unwrap_or(0).to_string())
            .replace(
                "{foreign_device}",
                &ids.foreign_device.unwrap_or(0).to_string(),
            )
    };
    let body = fill(case.body);
    if case.contract && record {
        return Ok(());
    }
    let expected: Option<Value> = if record || case.contract {
        None
    } else {
        Some(serde_json::from_slice(&std::fs::read(golden_path(
            case, "",
        ))?)?)
    };
    let before = match chat {
        Some((channel, message)) => Some(chat_state(owner, channel, message).await?),
        None => None,
    };
    let mut notifications = match chat {
        Some(_) => Some(db.listen(&format!("chat:{}", actor.user)).await?),
        None => None,
    };
    // Go answers for recording and for forwarded cases; in replay a fake
    // upstream serves the recorded Go response and counts the forwards.
    let forwards = Arc::new(Mutex::new(Vec::<Value>::new()));
    let fake_go = {
        let forwards = forwards.clone();
        let reply = expected.clone();
        common::fake_upstream(move |request| {
            let forwards = forwards.clone();
            let reply = reply.clone();
            async move {
                let method = request.method().to_string();
                let uri = request.uri().to_string();
                let raw = request.into_body().collect().await.unwrap().to_bytes();
                forwards
                    .lock()
                    .unwrap()
                    .push(json!({"method":method,"uri":uri,"body":String::from_utf8_lossy(&raw)}));
                let Some(reply) = reply.as_ref() else {
                    return Response::builder()
                        .status(418)
                        .body(common::full("go"))
                        .unwrap();
                };
                let observation = &reply["observation"]["response"];
                let mut response =
                    Response::builder().status(observation["status"].as_u64().unwrap() as u16);
                for (k, v) in observation["headers"].as_object().unwrap() {
                    response = response.header(k, v.as_str().unwrap());
                }
                let text = observation["body_text"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                response.body(common::full(text)).unwrap()
            }
        })
        .await
    };
    let s3 = common::fake_upstream(|_| async {
        Response::builder()
            .header("content-type", "application/xml")
            .body(common::full("<ListMultipartUploadsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>mailblobs</Bucket><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>"))
            .unwrap()
    })
    .await;
    let oracle = if record {
        std::env::set_var("GOFREE_ORACLE_EXTRA_ENV", extra_env(case.cfg));
        if case.route == "GET /metrics" {
            std::env::set_var("GOFREE_ORACLE_KEEP_WORKERS", "identity-metrics");
        }
        let started = common::go_oracle::start_named(db, s3, None, "gofree-static1").await;
        std::env::remove_var("GOFREE_ORACLE_EXTRA_ENV");
        std::env::remove_var("GOFREE_ORACLE_KEEP_WORKERS");
        started?
    } else {
        None
    };
    let upstream = oracle.as_ref().map(|o| o.address).unwrap_or(fake_go);
    let exec = || {
        Ok::<_, BoxError>(
            setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2)
                .map_err(|e| e.0)?
                .with_audit_keys("22".repeat(32), String::new()),
        )
    };
    let table = if record {
        RouteTable::proxy_all()
    } else {
        let surface = || setjoin_gateway::surface::SurfaceRoute {
            discovery: None,
            fallback: None,
            exec: exec().unwrap(),
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
            config: Arc::new(surface_config(case.cfg)),
            health: Arc::new(setjoin_static::health::HealthGate::new(false)),
        };
        let assist = || setjoin_gateway::assist::AssistRoute {
            exec: exec().unwrap(),
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
        };
        let chat_route = || setjoin_gateway::chat_b::ChatBRoute {
            exec: exec().unwrap(),
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
            store: None,
        };
        match mutant {
            Mutant::None => RouteTable::proxy_all()
                .with(surface())
                .with(assist())
                .with(chat_route()),
            Mutant::Status => {
                let table = RouteTable::proxy_all();
                match route_path {
                    p if p.starts_with("/assist/") => table.with(ChangedStatus(assist())),
                    p if p.starts_with("/chat/") => table.with(ChangedStatus(chat_route())),
                    _ => table.with(ChangedStatus(surface())),
                }
            }
            Mutant::DoubleReport => RouteTable::proxy_all().with(DoubleReport {
                inner: Arc::new(surface()),
                db: setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?,
            }),
            Mutant::NoDeviceProof => RouteTable::proxy_all().with(NoDeviceProof {
                db: setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?,
            }),
            Mutant::NoFilter => RouteTable::proxy_all().with(NoFilter {
                autoconfig: route_path.contains("autoconfig"),
            }),
        }
    };
    let table = if !record && case.route.contains("/api/openapi.full.") {
        table.with_admission(
            setjoin_pg::ScopedExecutor::from_dsn(&db.dsn, 2).map_err(|e| e.0)?,
            Arc::new(common::recovery_keys()),
            "mailserver".into(),
            None,
        )
    } else {
        table
    };
    let gateway = Gateway::new(
        Config {
            upstream: if record || case.forwarded || case.contract {
                Some(format!("http://{upstream}").parse()?)
            } else {
                None
            },
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        table,
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(gateway.serve(listener));
    let mut builder = Request::builder().method(case.method).uri(&uri);
    let mut host = "mail.test".to_owned();
    for (name, value) in &case.headers {
        if *name == "host" {
            host = fill(value);
        } else {
            builder = builder.header(*name, fill(value));
        }
    }
    builder = builder
        .header("host", host)
        .header("x-request-id", format!("static1-{}", case.name))
        .header("origin", "http://mail.test");
    match case.auth {
        Auth::None => {}
        Auth::Actor => {
            builder = builder.header(
                "authorization",
                format!("Bearer {}", token(actor.user, None, false)),
            )
        }
        Auth::Foreign => {
            builder = builder.header(
                "authorization",
                format!("Bearer {}", token(foreign.user, None, false)),
            )
        }
        Auth::ActorPerm => {
            builder = builder.header(
                "authorization",
                format!(
                    "Bearer {}",
                    token(actor.user, Some(&["system.config"]), false)
                ),
            )
        }
        Auth::ActorAdmin => {
            builder = builder.header(
                "authorization",
                format!("Bearer {}", token(actor.user, None, true)),
            )
        }
    }
    if let Some(device) = ids.device {
        use hmac::{Hmac, Mac};
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            .to_string();
        let hash = format!(
            "{:x}",
            Sha256::digest(if case.world.telemetry == Some("body-mismatch") {
                b"different".as_slice()
            } else {
                body.as_bytes()
            })
        );
        let nonce = format!("static2-{}", case.name);
        let mut mac = Hmac::<Sha256>::new_from_slice(b"static2-device-secret")?;
        mac.update(format!("{device}:{timestamp}:POST:/telemetry:{hash}:{nonce}").as_bytes());
        let signature: String = if case.world.telemetry == Some("legacy-bad-mac") {
            "invalid".into()
        } else {
            mac.finalize()
                .into_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        };
        builder = builder
            .header("x-device-timestamp", timestamp)
            .header("x-device-body-sha256", hash)
            .header("x-device-nonce", nonce)
            .header("x-device-hmac", signature);
    }
    let request = builder.body(common::full(body.clone()))?;
    let second_request = if case.repeat {
        let mut copy = Request::builder()
            .method(request.method().clone())
            .uri(request.uri().clone());
        for (name, value) in request.headers() {
            copy = copy.header(name, value);
        }
        Some(copy.body(common::full(body.clone()))?)
    } else {
        None
    };
    if record && case.route == "GET /metrics" {
        // Go's identity collector runs once at startup; scrape after it finished.
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    }
    let sent = common::send(address, request).await;
    let status = sent.status().as_u16();
    let headers = sent.headers().clone();
    let response_body = common::body_bytes(sent).await;
    if let Some(path) = std::env::var_os("STATIC1_DUMP") {
        std::fs::write(path, &response_body)?;
    }
    let observed_response = observe_response(case, status, &headers, &response_body, ids);
    let repeated = match second_request {
        Some(second) => {
            let sent = common::send(address, second).await;
            let (status, headers) = (sent.status().as_u16(), sent.headers().clone());
            let bytes = common::body_bytes(sent).await;
            Some(observe_response(case, status, &headers, &bytes, ids))
        }
        None => None,
    };
    let forwarded = forwards.lock().unwrap().clone();
    task.abort();
    let _ = task.await;
    drop(oracle);
    let after = match chat {
        Some((channel, message)) => Some(chat_state(owner, channel, message).await?),
        None => None,
    };
    let audit = match chat {
        Some((channel, _)) => chat_audit(owner, channel).await?,
        None => Vec::new(),
    };
    let notify = match notifications.as_mut() {
        Some(listener) => listener.drain(owner).await?,
        None => Vec::new(),
    };
    let mut observation = json!({
        "request": {"method": method, "path": route_path},
        "response": observed_response,
        "effects": match (before, after) { (Some(b), Some(a)) => json!({"before": b, "after": a}), _ => json!({}) },
        "audit": audit,
        "notify": notify,
        "provider": seen.lock().unwrap().clone(),
    });
    if let Some(device) = ids.device {
        observation["effects"] = telemetry_state(owner, device, b"static2-device-secret").await?;
        if let Some(foreign) = ids.foreign_device {
            observation["effects"]["foreign"] =
                telemetry_state(owner, foreign, b"static2-foreign-secret").await?;
        }
    }
    if let Some(repeated) = repeated {
        observation["repeat"] = repeated;
    }
    // The provider sees only Go-owned stable values.
    if let Some(list) = observation["provider"].as_array_mut() {
        for entry in list {
            entry["uri"] = entry["uri"].as_str().unwrap_or_default().to_owned().into();
        }
    }
    if case.contract {
        let expected_forward = json!({"method": case.method, "uri": uri, "body": body});
        if status != 418 || forwarded != vec![expected_forward] {
            return Err(
                format!("contract case not forwarded intact: {status} {forwarded:?}").into(),
            );
        }
        return Ok(());
    }
    if record {
        setjoin_conformance::golden::record(
            &golden_path(case, ""),
            &json!({"format":1,"route":case.route,"case":case.name.replace('_', "-"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}),
        )?;
        if case.world.telemetry.is_some() {
            setjoin_conformance::golden::record(
                &golden_path(case, "-row-effects"),
                &json!({"format":1,"route":case.route,"case":format!("{}-row-effects",case.name.replace('_',"-")),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"effects":telemetry_rows(&observation["effects"])}),
            )?;
        }
        if case.route.starts_with("POST /chat/") {
            setjoin_conformance::golden::record(
                &golden_path(case, "-row-effects"),
                &json!({"format":1,"route":case.route,"case":format!("{}-row-effects", case.name.replace('_', "-")),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"effects":[{"table":"chat_audit_log","rows":observation["audit"]}]}),
            )?;
        }
        return Ok(());
    }
    let mut expected = expected.unwrap();
    // A golden pinned in static1/divergences.json (owner-approved security fix 2026-11-05) is
    // compared with its reviewed expectation under security/ instead of the Go recording.
    if common::is_pinned(&golden_path(case, "")) {
        expected = common::golden_doc(&golden_path(case, ""), "observation", &observation);
    }
    let comparison = setjoin_conformance::golden::compare(&expected["observation"], &observation);
    if mutant != Mutant::None {
        if comparison.is_ok() {
            return Err("mutant survived".into());
        }
        let label = if mutant == Mutant::Status {
            "changed-status"
        } else if mutant == Mutant::DoubleReport {
            "double-bump"
        } else {
            "no-tenant-filter"
        };
        println!("MUTANT-REJECTED: {} :: {label}", case.route);
        return Ok(());
    }
    comparison?;
    if case.route.starts_with("POST /chat/") {
        let rows: Value =
            serde_json::from_slice(&std::fs::read(golden_path(case, "-row-effects"))?)?;
        setjoin_conformance::golden::compare(
            &rows["effects"],
            &json!([{"table":"chat_audit_log","rows":observation["audit"]}]),
        )?;
    }
    if case.world.telemetry.is_some() {
        let actual = telemetry_rows(&observation["effects"]);
        let rows: Value = common::golden_doc(&golden_path(case, "-row-effects"), "effects", &actual);
        setjoin_conformance::golden::compare(&rows["effects"], &actual)?;
    }
    // Forward accounting: native cases never reach Go; forwarded cases do, once, intact.
    if case.forwarded {
        let expected_forward = json!({"method": case.method, "uri": uri, "body": body});
        if forwarded != vec![expected_forward] {
            return Err(format!("forward mismatch: {forwarded:?}").into());
        }
    } else if !forwarded.is_empty() {
        return Err(format!("served natively but forwarded: {forwarded:?}").into());
    }
    eprintln!(
        "GOLDEN-REPLAY: {} :: {}",
        case.route,
        case.name.replace('_', "-")
    );
    Ok(())
}

fn telemetry_rows(state: &Value) -> Value {
    let mut rows = vec![
        json!({"table":"device_telemetry","rows":state["reports"]}),
        json!({"table":"device_auth_nonces","rows":state["nonces"]}),
        json!({"table":"devices","rows":[state["credential"].clone()]}),
    ];
    if let Some(foreign) = state.get("foreign") {
        rows.extend(
            telemetry_rows(foreign)
                .as_array()
                .unwrap()
                .iter()
                .cloned()
                .map(|mut v| {
                    v["scope"] = "foreign".into();
                    v
                }),
        );
    }
    Value::Array(rows)
}

async fn telemetry_state(
    owner: &tokio_postgres::Client,
    device: i64,
    secret: &[u8],
) -> Result<Value, BoxError> {
    let reports = owner.query("SELECT (to_jsonb(t)-'id'-'device_id'-'reported_at')::text FROM device_telemetry t WHERE device_id=$1 ORDER BY id", &[&device]).await?
        .iter().map(|r| serde_json::from_str::<Value>(r.get::<_,&str>(0))).collect::<Result<Vec<_>,_>>()?;
    let nonces = owner.query("SELECT jsonb_build_object('nonce',nonce,'lifetime',extract(epoch FROM expires_at-claimed_at))::text FROM device_auth_nonces WHERE device_id=$1 ORDER BY nonce", &[&device]).await?
        .iter().map(|r| serde_json::from_str::<Value>(r.get::<_,&str>(0))).collect::<Result<Vec<_>,_>>()?;
    let credential = owner.query_one("SELECT hmac_secret IS NOT NULL,hmac_secret_enc,hmac_secret_key_id FROM devices WHERE id=$1", &[&device]).await?;
    let envelope: Option<Vec<u8>> = credential.get(1);
    let opens = envelope.as_ref().is_some_and(|v| {
        setjoin_config_secret::open_column(v, b"blobs1-test-jwt-secret-for-recording")
            .is_ok_and(|v| v == secret)
    });
    Ok(
        json!({"reports":reports,"nonces":nonces,"credential":{"plaintext":credential.get::<_,bool>(0),"sealed":envelope.is_some(),"key_id":credential.get::<_,Option<String>>(2),"opens":opens}}),
    )
}

/// Planted security mutant: attribute an INSERT directly to the body claim.
/// The immutable foreign-device oracle must reject both the reply and row effect.
struct NoDeviceProof {
    db: setjoin_pg::workers::WorkerDatabase,
}
impl setjoin_gateway::Intercept for NoDeviceProof {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        r.uri().path() == "/api/telemetry"
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let db = self.db.clone();
        Box::pin(async move {
            let id = r.headers()["x-request-id"].to_str().unwrap().to_owned();
            let bytes = r.into_body().collect().await.unwrap().to_bytes();
            let claimed = serde_json::from_slice::<Value>(&bytes).unwrap()["device_id"]
                .as_i64()
                .unwrap();
            db.connect()
                .await
                .unwrap()
                .query(
                    "INSERT INTO device_telemetry(device_id,app_version) VALUES($1,'mutant')",
                    &[(&claimed, setjoin_pg::Type::INT8)],
                )
                .await
                .unwrap();
            let mut response =
                setjoin_gateway::jmap::reply::response(String::new(), c.identity.proto, id);
            *response.status_mut() = hyper::StatusCode::NO_CONTENT;
            response.headers_mut().remove("content-type");
            response
        })
    }
}
#[tokio::test]
async fn telemetry_oracle_rejects_missing_device_proof() -> Result<(), BoxError> {
    run_inner("telemetry_proof_foreign", Mutant::NoDeviceProof).await
}

#[tokio::test]
async fn static_oracle_rejects_missing_tenant_authority() -> Result<(), BoxError> {
    run_inner("autoconfig_foreign", Mutant::NoFilter).await?;
    run_inner("telemetry_proof_foreign", Mutant::NoDeviceProof).await
}

/// Planted state mutant: duplicate the report after the real, proved request.
struct DoubleReport {
    inner: Arc<dyn setjoin_gateway::Intercept>,
    db: setjoin_pg::workers::WorkerDatabase,
}
impl setjoin_gateway::Intercept for DoubleReport {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.inner.matches(r)
    }
    fn handle(
        &self,
        mut r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let (inner, db) = (self.inner.clone(), self.db.clone());
        Box::pin(async move {
            let bytes = r.body_mut().collect().await.unwrap().to_bytes();
            let claimed = serde_json::from_slice::<Value>(&bytes).unwrap()["device_id"]
                .as_i64()
                .unwrap();
            *r.body_mut() = common::full(bytes);
            let response = inner.handle(r, c).await;
            if response.status() == 204 {
                db.connect().await.unwrap().query("INSERT INTO device_telemetry(device_id,app_version,os_version,crash_count,uptime_hours,feature_usage) SELECT device_id,app_version,os_version,crash_count,uptime_hours,feature_usage FROM device_telemetry WHERE device_id=$1",&[(&claimed,setjoin_pg::Type::INT8)]).await.unwrap();
            }
            response
        })
    }
}
#[tokio::test]
async fn telemetry_oracle_rejects_double_report() -> Result<(), BoxError> {
    run_inner("telemetry_proof_success", Mutant::DoubleReport).await
}
