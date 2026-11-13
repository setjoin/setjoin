//! F08 Platform HTTP adapter: the `system-features` slice's routes (see the
//! `setjoin-platform` DOX for the slice map and contract). Every route is gated like
//! Go's `requireSystemPerm` / `requireBackupWrite` from the live governed grants; a
//! refusal writes Go's durable `console.denied` audit row and answers the bare 403.
//! A failed authority read or a missing token forwards the untouched request to Go.
use crate::mailboxes::{bare, unknown_outcome};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use setjoin_authz::token::KeySource;
use setjoin_pg::{CommandOutcome, ScopedExecutor};
use setjoin_platform::{config, system as db};
use setjoin_platform::{features, health, welcome};
use std::sync::Arc;
use std::time::Instant;

pub struct PlatformRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    started: Instant,
    started_at: String,
    overrides: features::Overrides,
    livekit: Option<crate::meet_livekit::LiveKit>,
    health: Arc<HealthState>,
    configuration: Option<Arc<crate::configuration::Runtime>>,
}

/// Go's `health.Handler` verdict cache and admission bucket (process local).
#[derive(Default)]
struct HealthState {
    cache: tokio::sync::Mutex<Option<(Instant, health::Verdict)>>,
    bucket: std::sync::Mutex<health::Bucket>,
    alerts: Option<health::Alerts>,
}

impl<K: KeySource + 'static> PlatformRoute<K> {
    pub fn new(exec: ScopedExecutor, keys: Arc<K>, issuer: String) -> Self {
        Self {
            exec,
            keys,
            issuer,
            started: Instant::now(),
            started_at: chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            overrides: features::Overrides::default(),
            livekit: None,
            health: Arc::new(HealthState::default()),
            configuration: None,
        }
    }
    pub fn with_configuration(mut self, configuration: Arc<crate::configuration::Runtime>) -> Self {
        self.configuration = Some(configuration);
        self
    }
    /// The four toggles Go's gateway pins from its configuration (`toggleOverrides`).
    pub fn with_overrides(mut self, overrides: features::Overrides) -> Self {
        self.overrides = overrides;
        self
    }
    /// Where an ok-to-error transition seen by `/admin/health` raises `system.health_alert`.
    pub fn with_health_alerts(mut self, alerts: health::Alerts) -> Self {
        self.health = Arc::new(HealthState {
            alerts: Some(alerts),
            ..HealthState::default()
        });
        self
    }
    /// The live components `/admin/health` probes, as Go registers them at start-up.
    pub fn with_livekit(mut self, livekit: crate::meet_livekit::LiveKit) -> Self {
        self.livekit = Some(livekit);
        self
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Action {
    Reload,
    Version,
    SchemaVersion,
    Status,
    Health,
    BackupList,
    BackupEnqueue,
    BackupDownload,
    BackupDelete,
    ConfigList,
    ConfigGet,
    ConfigSet,
    ConfigExport,
    ConfigImport,
    AdminHealth,
    FeaturesList,
    FeatureMode,
    FeatureSet,
    FeatureDelete,
    SodGet,
    SodSet,
    WelcomeGet,
    WelcomePut,
    WelcomeTest,
    JitGet,
    JitPut,
    AuthList,
    AuthUpdate,
}

/// Method/pattern table; the first column is the method predicate.
pub(crate) fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let (post, delete) = (*method == Method::POST, *method == Method::DELETE);
    let put = *method == Method::PUT;
    let table: [(bool, &str, Action); 28] = [
        (post, "/api/admin/reload", Action::Reload),
        (reads, "/api/admin/system/version", Action::Version),
        (
            reads,
            "/api/admin/system/schema-version",
            Action::SchemaVersion,
        ),
        (reads, "/api/admin/system/status", Action::Status),
        (reads, "/api/admin/system/health", Action::Health),
        (reads, "/api/admin/system/backup/list", Action::BackupList),
        (post, "/api/admin/system/backup", Action::BackupEnqueue),
        (
            reads,
            "/api/admin/system/backup/download",
            Action::BackupDownload,
        ),
        (delete, "/api/admin/system/backup", Action::BackupDelete),
        (reads, "/api/admin/system/config", Action::ConfigList),
        (reads, "/api/admin/system/config/{key}", Action::ConfigGet),
        (put, "/api/admin/system/config/{key}", Action::ConfigSet),
        (
            reads,
            "/api/admin/system/config/export",
            Action::ConfigExport,
        ),
        (
            post,
            "/api/admin/system/config/import",
            Action::ConfigImport,
        ),
        (reads, "/api/admin/health", Action::AdminHealth),
        (reads, "/api/admin/features", Action::FeaturesList),
        (
            put,
            "/api/admin/features/registry-mode",
            Action::FeatureMode,
        ),
        (put, "/api/admin/features/{key}", Action::FeatureSet),
        (delete, "/api/admin/features/{key}", Action::FeatureDelete),
        (reads, "/api/admin/dengbao/sod-mode", Action::SodGet),
        (put, "/api/admin/dengbao/sod-mode", Action::SodSet),
        (reads, "/api/admin/system/welcome-email", Action::WelcomeGet),
        (put, "/api/admin/system/welcome-email", Action::WelcomePut),
        (
            post,
            "/api/admin/system/welcome-email/test",
            Action::WelcomeTest,
        ),
        (reads, "/api/admin/system/jit-defaults", Action::JitGet),
        (put, "/api/admin/system/jit-defaults", Action::JitPut),
        (reads, "/api/admin/auth/methods", Action::AuthList),
        (put, "/api/admin/auth/methods/{slug}", Action::AuthUpdate),
    ];
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| *action)
}

/// Go sees the `/api`-stripped request path, decoded.
pub(crate) fn segment_path(path: &str) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.strip_prefix("/api").unwrap_or(path),
    ))
}

/// The permission set a route's Go middleware requires (any-of).
fn gate(what: Action) -> &'static [&'static str] {
    match what {
        Action::BackupEnqueue | Action::BackupDelete => &setjoin_platform::BACKUP_WRITE,
        Action::Reload | Action::ConfigSet
        | Action::ConfigImport
        | Action::FeatureMode
        | Action::FeatureSet
        | Action::FeatureDelete
        | Action::WelcomePut
        | Action::WelcomeTest => &setjoin_platform::SYSTEM_CONFIG,
        Action::AdminHealth => &setjoin_platform::MAIL_CONSOLE,
        Action::SodGet | Action::SodSet => &setjoin_platform::SECURITY_WRITE,
        Action::JitGet | Action::JitPut => &setjoin_platform::ROLES_MANAGE,
        Action::AuthList => &setjoin_platform::AUTH_CONSOLE,
        Action::AuthUpdate => &setjoin_platform::IDENTITY_WRITE,
        _ => &setjoin_platform::SYSTEM_CONSOLE,
    }
}

/// Go's `r.PathValue`: the percent-decoded segment at `index` of the full path.
pub(crate) fn segment(path: &str, index: usize) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.split('/').nth(index).unwrap_or(""),
    ))
}

/// Go's `struct{Value json.RawMessage; Encrypted bool}` decoded with `json.Decoder.Decode`:
/// case-folded keys, `null` keeps the zero value (a `null` value is still the raw text
/// `null`), unknown keys ignored, only the first JSON value is read.
#[derive(Default)]
struct SetBody {
    value: Option<String>,
    encrypted: bool,
}
impl<'de> serde::Deserialize<'de> for SetBody {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = SetBody;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<SetBody, E> {
                Ok(SetBody::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<SetBody, M::Error> {
                let mut body = SetBody::default();
                while let Some(key) = map.next_key::<String>()? {
                    match crate::guests_input::fold(&key).as_str() {
                        "value" => {
                            let raw = map.next_value::<Box<serde_json::value::RawValue>>()?;
                            body.value = Some(raw.get().to_owned());
                        }
                        "encrypted" => {
                            if let Some(flag) = map.next_value::<Option<bool>>()? {
                                body.encrypted = flag;
                            }
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}

/// Go's `http.MaxBytesReader(w, r.Body, cap)` plus `Decode`: only the first JSON value is
/// read, and it fails when it does not end within the first `cap` bytes.
pub(crate) async fn json_body<T: serde::de::DeserializeOwned>(
    r: &mut Request<Body>,
    cap: usize,
) -> Result<T, ()> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while bytes.len() < cap {
        let Some(frame) = r.body_mut().frame().await else {
            break;
        };
        if let Ok(data) = frame.map_err(|_| ())?.into_data() {
            bytes.extend_from_slice(&data[..data.len().min(cap - bytes.len())]);
        }
    }
    let fixed = crate::guests_input::go_json_bytes(&bytes);
    match serde_json::Deserializer::from_slice(&fixed)
        .into_iter::<T>()
        .next()
    {
        Some(Ok(value)) => Ok(value),
        _ => Err(()),
    }
}

/// Go's 4 MiB cap and 512 item cap on `POST /admin/system/config/import`.
const IMPORT_BYTES: usize = 4 << 20;
const IMPORT_ITEMS: usize = 512;

/// What a streamed import ended with, mirroring Go's `json.Decoder` Token/More/Decode walk
/// over `http.MaxBytesReader`: an error that needs bytes beyond the cap is a 413, any other
/// decode failure a 400. Items before the failure have already been applied.
enum Import {
    Done { imported: i64, skipped: i64 },
    Refused(Response<Body>),
}

async fn read_capped(r: &mut Request<Body>) -> Result<(Vec<u8>, bool), ()> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while bytes.len() <= IMPORT_BYTES {
        let Some(frame) = r.body_mut().frame().await else {
            break;
        };
        if let Ok(data) = frame.map_err(|_| ())?.into_data() {
            bytes.extend_from_slice(&data[..data.len().min(IMPORT_BYTES + 1 - bytes.len())]);
        }
    }
    let over = bytes.len() > IMPORT_BYTES;
    bytes.truncate(IMPORT_BYTES);
    Ok((bytes, over))
}

fn skip_space(data: &[u8], mut at: usize) -> usize {
    while data
        .get(at)
        .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
    {
        at += 1;
    }
    at
}

#[allow(clippy::too_many_arguments)]
async fn run_import<K: KeySource + 'static>(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    operation: [u8; 16],
    raw: &[u8],
    over: bool,
    c: &RequestContext,
    id: &str,
) -> Import {
    let ended = |over: bool| {
        if over {
            bare(413, "config payload too large", c, id)
        } else {
            bare(400, "invalid JSON", c, id)
        }
    };
    let data = crate::guests_input::go_json_bytes(raw);
    let mut at = skip_space(&data, 0);
    if at >= data.len() {
        return Import::Refused(ended(over));
    }
    if data[at] != b'[' {
        return Import::Refused(bare(400, "invalid JSON", c, id));
    }
    at += 1;
    let (mut imported, mut skipped, mut first) = (0i64, 0i64, true);
    loop {
        at = skip_space(&data, at);
        match data.get(at) {
            None => return Import::Refused(ended(over)),
            Some(b']') => break,
            Some(_) => {}
        }
        if imported + skipped + 1 > IMPORT_ITEMS as i64 {
            return Import::Refused(bare(413, "too many config items", c, id));
        }
        if !first {
            if data[at] != b',' {
                return Import::Refused(bare(400, "invalid JSON", c, id));
            }
            at = skip_space(&data, at + 1);
        }
        first = false;
        let mut stream =
            serde_json::Deserializer::from_slice(&data[at..]).into_iter::<serde_json::Value>();
        let item = match stream.next() {
            Some(Ok(item)) => item,
            None => return Import::Refused(ended(over)),
            Some(Err(e)) if e.is_eof() => return Import::Refused(ended(over)),
            Some(Err(_)) => return Import::Refused(bare(400, "invalid JSON", c, id)),
        };
        at += stream.byte_offset();
        let object = match &item {
            serde_json::Value::Object(map) => map,
            // A `null` element decodes into a nil map: an empty key, skipped silently.
            serde_json::Value::Null => continue,
            _ => return Import::Refused(bare(400, "invalid JSON", c, id)),
        };
        let key = object.get("key").and_then(|v| v.as_str()).unwrap_or("");
        if key.is_empty() {
            continue;
        }
        if !config::WRITABLE.contains(&key) {
            let body = setjoin_platform::done(format!(
                "{{\"error\":{}}}",
                serde_json::to_string(&format!(
                    "config key {} cannot be imported",
                    setjoin_contracts::go_quote::quote(key.as_bytes())
                ))
                .expect("string")
            ));
            let mut response = crate::jmap::reply::response(body, c.identity.proto, id.to_owned());
            *response.status_mut() = hyper::StatusCode::FORBIDDEN;
            return Import::Refused(response);
        }
        let Some(value) = object
            .get("value")
            .and_then(|v| v.as_str())
            .filter(|v| *v != config::REDACTED)
        else {
            skipped += 1;
            continue;
        };
        // pgx cannot encode a non-string, non-null description into a text parameter.
        let description = match object.get("description") {
            None | Some(serde_json::Value::Null) => Some(None),
            Some(serde_json::Value::String(text)) => Some(Some(text.as_str())),
            Some(_) => None,
        };
        let Some(description) = description else {
            skipped += 1;
            continue;
        };
        let mut op = operation;
        op[14..16].copy_from_slice(&((imported + skipped) as u16).to_be_bytes());
        match config::import_item(exec, actor, key, value, description, op).await {
            CommandOutcome::Committed(()) => imported += 1,
            CommandOutcome::RolledBack(_) => skipped += 1,
            CommandOutcome::Unknown { operation } => {
                return Import::Refused(unknown_outcome(operation, c, id))
            }
        }
    }
    Import::Done { imported, skipped }
}

/// Resident set in whole MiB, the closest Rust analogue of Go's `MemStats.Alloc`.
fn memory_mb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|l| l.strip_prefix("VmRSS:"))
                .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        })
        .map_or(0, |kib| kib / 1024)
}

/// The `RequireReason(perm)` middleware a route carries: `(area, permission)`.
fn reason_area(what: Action) -> Option<(&'static str, &'static str)> {
    match what {
        Action::FeatureMode | Action::FeatureSet | Action::FeatureDelete => {
            Some(("system", "system.config"))
        }
        Action::SodSet => Some(("security", "security.write")),
        _ => None,
    }
}

/// The routes of group 1b (#443), served by [`serve_b`].
fn is_group_b(what: Action) -> bool {
    matches!(
        what,
        Action::AdminHealth
            | Action::FeaturesList
            | Action::FeatureMode
            | Action::FeatureSet
            | Action::FeatureDelete
            | Action::SodGet
            | Action::SodSet
            | Action::WelcomeGet
            | Action::WelcomePut
            | Action::WelcomeTest
            | Action::JitGet
            | Action::JitPut
            | Action::AuthList
            | Action::AuthUpdate
    )
}

/// What a group-1b handler needs from the request.
struct Call<'a> {
    exec: &'a ScopedExecutor,
    actor: &'a setjoin_authz::AuthContext,
    operation: [u8; 16],
    c: &'a RequestContext,
    id: &'a str,
    /// Go's `r.URL.Path` (the `/api`-stripped, decoded path).
    path: &'a str,
    lang: &'a str,
    ip: &'a str,
    head: bool,
}

impl Call<'_> {
    /// `WriteJSON`: the body as the encoder wrote it, chunked past net/http's 2 KiB buffer.
    fn json(&self, body: String, status: u16) -> Response<Body> {
        let chunked = body.len() > 2048 && !self.head;
        let mut response =
            crate::jmap::reply::response(body, self.c.identity.proto, self.id.to_owned());
        *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
        if chunked {
            response.headers_mut().insert(
                "transfer-encoding",
                hyper::header::HeaderValue::from_static("chunked"),
            );
        }
        response
    }
    /// `WriteHeader(status)` with no body and no content type.
    fn empty(&self, status: u16) -> Response<Body> {
        let mut response = self.json(String::new(), status);
        response.headers_mut().remove("content-type");
        response
    }
    /// `httputil.WriteError`: the minimal problem.
    fn error(&self, status: u16, detail: &str) -> Response<Body> {
        bare(status, detail, self.c, self.id)
    }
    /// `httputil.WriteProblem`: instance and language included.
    fn problem(&self, problem: crate::problem::Problem<'_>) -> Response<Body> {
        crate::mailboxes::render(
            problem.instance(self.path),
            Some(self.lang),
            self.c,
            self.id,
        )
    }
    fn detail(&self, status: u16, detail: &str) -> Response<Body> {
        self.problem(crate::problem::Problem::new(status, detail))
    }
    /// `httputil.WriteDBErr` / `NewInternalProblem`.
    fn database(&self) -> Response<Body> {
        self.detail(500, "database error")
    }
    fn internal(&self) -> Response<Body> {
        self.problem(
            crate::problem::Problem::new(500, "An unexpected error occurred. Please try again.")
                .kind("https://setjoin.com/errors/internal-error"),
        )
    }
    /// `writeFeatureProblem`.
    fn feature(&self, status: u16, code: &str, detail: &str) -> Response<Body> {
        let kind = format!("https://setjoin.com/problems/feature-registry/{code}");
        self.problem(
            crate::problem::Problem::new(status, detail)
                .kind(&kind)
                .code(code),
        )
    }
    fn unknown(&self, operation: setjoin_contracts::ids::OperationId) -> Response<Body> {
        unknown_outcome(operation, self.c, self.id)
    }
}

fn mapped<T, U, E>(outcome: CommandOutcome<T, E>, f: impl FnOnce(T) -> U) -> CommandOutcome<U, E> {
    match outcome {
        CommandOutcome::Committed(v) => CommandOutcome::Committed(f(v)),
        CommandOutcome::RolledBack(r) => CommandOutcome::RolledBack(r),
        CommandOutcome::Unknown { operation } => CommandOutcome::Unknown { operation },
    }
}

/// Go's `time.Now()` as `encoding/json` writes it (UTC, trimmed fraction).
fn now_rfc3339() -> String {
    let now = chrono::Utc::now();
    let fraction = format!("{:09}", now.timestamp_subsec_nanos());
    let fraction = fraction.trim_end_matches('0');
    let dot = if fraction.is_empty() { "" } else { "." };
    format!("{}{dot}{fraction}Z", now.format("%Y-%m-%dT%H:%M:%S"))
}

/// The live-component probes Go registers at start-up (`sfu`, `egress`, `asr`), each bounded
/// to 2 s.
async fn probes(livekit: Option<&crate::meet_livekit::LiveKit>) -> Vec<health::Probe> {
    let Some(livekit) = livekit else {
        return vec![];
    };
    let bounded = |what: &'static str| (what, std::time::Duration::from_secs(2));
    let mut out = Vec::new();
    if livekit.configured() {
        let (name, limit) = bounded("sfu");
        let result = tokio::time::timeout(limit, livekit.list_rooms()).await;
        out.push(probe(name, result.map(|r| r.map(|_| ()))));
    }
    if livekit.egress() {
        let (name, limit) = bounded("egress");
        let result = tokio::time::timeout(limit, livekit.list_egress()).await;
        out.push(probe(name, result.map(|r| r.map(|_| ()))));
    }
    if livekit.captions_configured() {
        let (name, limit) = bounded("asr");
        let result = tokio::time::timeout(limit, livekit.captions_status()).await;
        out.push(probe(name, result.map(|r| r.map(|_| ()))));
    }
    out
}
/// Whether any live probe of the configured peripherals failed (the public verdict).
pub async fn any_probe_failed(livekit: &crate::meet_livekit::LiveKit) -> bool {
    probes(Some(livekit))
        .await
        .iter()
        .any(|p| p.error.is_some())
}

fn probe(
    name: &'static str,
    result: Result<Result<(), ()>, tokio::time::error::Elapsed>,
) -> health::Probe {
    health::Probe {
        name,
        error: match result {
            Ok(Ok(())) => None,
            Ok(Err(())) => Some("peripheral unreachable".into()),
            Err(_) => Some("context deadline exceeded".into()),
        },
    }
}

/// Go's `serveVerdict`: cached, throttled and serialised.
async fn verdict(
    exec: &ScopedExecutor,
    livekit: Option<&crate::meet_livekit::LiveKit>,
    state: &HealthState,
) -> health::Verdict {
    let admitted = state.bucket.lock().expect("bucket").allow(Instant::now());
    let mut cache = state.cache.lock().await;
    if let Some((at, cached)) = cache.as_ref() {
        if !admitted || at.elapsed() < health::EVAL_TTL {
            return cached.clone();
        }
    }
    if !admitted {
        return health::throttled();
    }
    let probes = probes(livekit).await;
    let fresh = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        health::evaluate(exec, &probes, &now_rfc3339(), state.alerts.as_ref()),
    )
    .await
    .unwrap_or(health::Verdict::Internal);
    *cache = Some((Instant::now(), fresh.clone()));
    fresh
}

/// Go's validated `X-Audit-Reason` (`validatedFeatureReason`): the trimmed value, or the
/// feature problem to answer.
fn feature_reason(r: &Request<Body>) -> Result<String, (&'static str, &'static str)> {
    let raw = r
        .headers()
        .get("x-audit-reason")
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default();
    let reason = raw.trim().to_owned();
    if reason.is_empty() {
        return Err(("reason_required", "X-Audit-Reason is required"));
    }
    if reason.len() > 1024 || reason.chars().any(|c| c.is_control()) {
        return Err((
            "invalid_audit_reason",
            "audit reason must be at most 1024 UTF-8 bytes and contain no control characters",
        ));
    }
    Ok(reason)
}

async fn serve_b(
    what: Action,
    mut r: Request<Body>,
    call: Call<'_>,
    overrides: &features::Overrides,
    livekit: Option<&crate::meet_livekit::LiveKit>,
    health_state: &HealthState,
) -> Response<Body> {
    use crate::platform_input as input;
    let exec = call.exec;
    let actor = call.actor;
    let path = r.uri().path().to_owned();
    match what {
        Action::AdminHealth => match verdict(exec, livekit, health_state).await {
            health::Verdict::Json { status, body } => call.json(body, status),
            health::Verdict::Internal => {
                let mut response = call.json("internal error\n".into(), 500);
                let headers = response.headers_mut();
                headers.insert(
                    "content-type",
                    hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                // `http.Error` adds its own nosniff beside the middleware's.
                headers.append(
                    "x-content-type-options",
                    hyper::header::HeaderValue::from_static("nosniff"),
                );
                response
            }
        },
        Action::FeaturesList => match features::list(exec, overrides).await {
            Ok(body) => call.json(body, 200),
            Err(_) => call.internal(),
        },
        Action::FeatureSet | Action::FeatureDelete | Action::FeatureMode => {
            let is_mode = what == Action::FeatureMode;
            let key = segment(&path, 4);
            if !is_mode {
                if what == Action::FeatureSet && key == "registry-mode" {
                    return call.feature(
                        400,
                        "invalid_feature_key",
                        "registry-mode has a dedicated endpoint",
                    );
                }
                if !features::valid_key(&key) {
                    return call.feature(
                        400,
                        "invalid_feature_key",
                        "feature key must use dotted lowercase segments",
                    );
                }
                if what == Action::FeatureSet && key == features::SOD_MODE_KEY {
                    return call.feature(
                        403,
                        "protected_feature_key",
                        "use the dedicated SoD mode endpoint",
                    );
                }
            }
            let reason = match feature_reason(&r) {
                Ok(reason) => reason,
                Err((code, detail)) => return call.feature(400, code, detail),
            };
            let outcome = match what {
                Action::FeatureSet => {
                    let body = match input::strict::<input::EnabledBody>(&mut r, 8 << 10).await {
                        Ok(body) => body,
                        Err(detail) => return call.feature(400, "invalid_request", detail),
                    };
                    let Some(enabled) = body.enabled else {
                        return call.feature(400, "invalid_request", "enabled is required");
                    };
                    mapped(
                        features::set(exec, actor, &key, enabled, call.ip, &reason, call.operation)
                            .await,
                        |()| None,
                    )
                }
                Action::FeatureDelete => mapped(
                    features::delete_unknown(exec, actor, &key, call.ip, &reason, call.operation)
                        .await,
                    |()| None,
                ),
                _ => {
                    let body = match input::strict::<input::ModeBody>(&mut r, 8 << 10).await {
                        Ok(body) => body,
                        Err(detail) => return call.feature(400, "invalid_request", detail),
                    };
                    if body.mode != "observe" && body.mode != "enforce" {
                        return call.feature(
                            400,
                            "invalid_registry_mode",
                            "mode must be observe or enforce",
                        );
                    }
                    mapped(
                        features::set_registry_mode(
                            exec,
                            actor,
                            &body.mode,
                            call.ip,
                            &reason,
                            call.operation,
                        )
                        .await,
                        Some,
                    )
                }
            };
            match outcome {
                CommandOutcome::Committed(None) => call.empty(204),
                CommandOutcome::Committed(Some(result)) => call.json(
                    setjoin_platform::done(setjoin_platform::config::compact(&result)),
                    200,
                ),
                CommandOutcome::RolledBack(rejection) => {
                    let failure = match &rejection {
                        setjoin_pg::Rejection::Statement(e) | setjoin_pg::Rejection::Body(e) => {
                            Some(e)
                        }
                        _ => None,
                    };
                    match failure.and_then(features::reducer_problem) {
                        Some(p) => call.feature(p.status, &p.kind, p.detail),
                        None => call.internal(),
                    }
                }
                CommandOutcome::Unknown { operation } => call.unknown(operation),
            }
        }
        Action::SodGet => match setjoin_platform::sod::get(exec).await {
            Ok(body) => call.json(body, 200),
            Err(_) => call.internal(),
        },
        Action::SodSet => {
            let Ok(body) = crate::admin_identity_input::first::<input::Sod>(&mut r, 64 << 20).await
            else {
                return call.detail(400, "request body must be JSON with an 'enabled' boolean");
            };
            match setjoin_platform::sod::put(exec, actor, body.enabled, call.ip, call.operation)
                .await
            {
                CommandOutcome::Committed(setjoin_platform::sod::Set::Enabled(enabled)) => {
                    call.json(setjoin_platform::sod::enabled_body(enabled), 200)
                }
                CommandOutcome::Committed(setjoin_platform::sod::Set::Violations(body)) => {
                    call.json(body, 409)
                }
                CommandOutcome::RolledBack(_) => call.internal(),
                CommandOutcome::Unknown { operation } => call.unknown(operation),
            }
        }
        Action::WelcomeGet => match welcome::get(exec).await {
            Ok(welcome::Read::Stored(raw)) => call.json(raw, 200),
            Ok(welcome::Read::Shell(body)) => call.json(body, 200),
            Err(_) => call.error(500, "database error"),
        },
        Action::WelcomePut => {
            let Ok(body) = json_body::<input::WelcomeBody>(&mut r, 1 << 20).await else {
                return call.error(400, "invalid JSON");
            };
            let config = welcome::Config {
                enabled: body.enabled,
                default_locale: body.default_locale,
                locales: body.locales.map(|locales| {
                    locales
                        .into_iter()
                        .map(|(k, l)| {
                            (
                                k,
                                welcome::Locale {
                                    subject: l.subject,
                                    body_text: l.body_text,
                                    body_html: l.body_html,
                                },
                            )
                        })
                        .collect()
                }),
            };
            if let Err(message) = welcome::validate(&config) {
                return call.error(400, &message);
            }
            match welcome::put(exec, actor, &welcome::marshal(&config), call.operation).await {
                CommandOutcome::Committed(()) => call.empty(204),
                CommandOutcome::RolledBack(_) => call.error(500, "database error"),
                CommandOutcome::Unknown { operation } => call.unknown(operation),
            }
        }
        Action::WelcomeTest => {
            let Ok(body) = json_body::<input::WelcomeTest>(&mut r, 1 << 20).await else {
                return call.error(400, "invalid JSON");
            };
            if body.subject.is_empty() || body.body_text.is_empty() {
                return call.error(400, "subject and plain-text body are required");
            }
            match welcome::test_send(
                exec,
                actor,
                &body.subject,
                &body.body_text,
                &body.body_html,
                call.operation,
            )
            .await
            {
                CommandOutcome::Committed(()) => call.empty(202),
                CommandOutcome::RolledBack(_) => call.error(500, "failed to send test email"),
                CommandOutcome::Unknown { operation } => call.unknown(operation),
            }
        }
        Action::JitGet => match setjoin_platform::jit::get(exec).await {
            Ok(body) => call.json(body, 200),
            Err(_) => call.database(),
        },
        Action::JitPut => {
            let Ok(body) = json_body::<input::Jit>(&mut r, 4096).await else {
                return call.detail(400, "invalid JSON");
            };
            if body.minutes <= 0 {
                return call.detail(400, "defaultMaxDurationMinutes must be positive");
            }
            match setjoin_platform::jit::put(
                exec,
                actor,
                body.minutes,
                body.required,
                call.operation,
            )
            .await
            {
                CommandOutcome::Committed(text) => call.json(text, 200),
                CommandOutcome::RolledBack(_) => call.database(),
                CommandOutcome::Unknown { operation } => call.unknown(operation),
            }
        }
        Action::AuthList => match setjoin_platform::auth_methods::list(exec).await {
            Ok(body) => call.json(body, 200),
            Err(_) => call.error(500, "database error"),
        },
        Action::AuthUpdate => {
            let slug = segment(&path, 5);
            let Ok(body) = json_body::<input::AuthPatch>(&mut r, 1 << 20).await else {
                return call.error(400, "invalid JSON");
            };
            if body.enabled.is_none() && body.priority.is_none() && body.config.is_none() {
                return call.error(400, "no fields to update");
            }
            let patch = setjoin_platform::auth_methods::Patch {
                enabled: body.enabled,
                priority: body.priority,
                config: body.config,
            };
            match setjoin_platform::auth_methods::update(exec, actor, &slug, &patch, call.operation)
                .await
            {
                CommandOutcome::Committed(true) => call.empty(204),
                CommandOutcome::Committed(false) => call.error(404, "auth method not found"),
                CommandOutcome::RolledBack(_) => call.error(500, "database error"),
                CommandOutcome::Unknown { operation } => call.unknown(operation),
            }
        }
        _ => call.error(500, "database error"),
    }
}

impl<K: KeySource + 'static> Intercept for PlatformRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        action(r.method(), r.uri().path()).is_some_and(|a| a != Action::Reload || self.configuration.is_some())
    }
    fn admits_member(&self, headers: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_request(&exec, &keys, &issuer, &headers, scheme)
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        let configuration = self.configuration.clone();
        let (started, started_at) = (self.started, self.started_at.clone());
        let (overrides, livekit, health_state) =
            (self.overrides, self.livekit.clone(), self.health.clone());
        Box::pin(async move {
            let Some(what) = action(r.method(), r.uri().path()) else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let Some(auth) = setjoin_authz::authorize_request(
                &exec,
                &keys,
                &issuer,
                r.headers(),
                c.identity.proto,
            )
            .await
            else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let Some(operation) = crate::jmap::random() else {
                return bare(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let actor = auth.context();
            let Ok(authority) = setjoin_platform::authority(&exec, actor).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let go_path = segment_path(r.uri().path());
            let required = gate(what);
            if !authority.allows_any(required) {
                let _ = setjoin_platform::console_denied(
                    &exec,
                    actor,
                    &go_path,
                    &required.join("|"),
                    operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            }
            if authority.refused_for_scope(required) {
                let detail = format!(
                    "{} (domain-scoped principal; org-wide-only surface, domain={})",
                    required.join("|"),
                    authority.domain_scope()
                );
                let _ =
                    setjoin_platform::console_denied(&exec, actor, &go_path, &detail, operation)
                        .await;
                return bare(403, "Forbidden", &c, &id);
            }
            if what == Action::Reload {
                let configuration = configuration
                    .expect("reload is matched only with a configuration runtime");
                let (status, body) = match configuration.reload(Some(&exec)).await {
                    Ok(()) => (200, "{\"status\":\"reloaded\"}\n".to_owned()),
                    Err(error) => (500, format!("{{\"error\":{}}}\n", setjoin_static::wellknown::go_json_string(&format!("config reload failed: {error}")))),
                };
                let mut response = crate::jmap::reply::response(body, c.identity.proto, id);
                *response.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
                return response;
            }
            let ip = c.identity.client_ip.to_string();
            if let Some((area, perm)) = reason_area(what) {
                if setjoin_platform::reason_required(&exec, area).await
                    && r.headers()
                        .get("x-audit-reason")
                        .is_none_or(|v| v.as_bytes().is_empty())
                {
                    setjoin_platform::missing_reason(&exec, actor, &ip, perm, operation).await;
                    return bare(400, "reason_required", &c, &id);
                }
            }
            if is_group_b(what) {
                let call = Call {
                    exec: &exec,
                    actor,
                    operation,
                    c: &c,
                    id: &id,
                    path: &go_path,
                    lang: &crate::mailboxes::language(&r),
                    ip: &ip,
                    head: r.method() == Method::HEAD,
                };
                return serve_b(what, r, call, &overrides, livekit.as_ref(), &health_state).await;
            }
            let head = r.method() == Method::HEAD;
            let reply = |body: String, status: u16| {
                // net/http buffers 2 KiB of a handler's output; a larger single write
                // is flushed before the handler returns and sent chunked.
                let chunked = body.len() > 2048 && !head;
                let mut response = crate::jmap::reply::response(body, c.identity.proto, id.clone());
                *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
                if chunked {
                    response.headers_mut().insert(
                        "transfer-encoding",
                        hyper::header::HeaderValue::from_static("chunked"),
                    );
                }
                response
            };
            let process = || db::Process {
                pid: std::process::id(),
                uptime_sec: started.elapsed().as_secs(),
                tasks: tokio::runtime::Handle::current()
                    .metrics()
                    .num_alive_tasks() as u64,
                memory_mb: memory_mb(),
                started_at: started_at.clone(),
            };
            match what {
                Action::Reload => unreachable!("reload handled before command dispatch"),
                Action::Version => reply(db::version(), 200),
                Action::Status | Action::Health => reply(db::status(&process()), 200),
                Action::SchemaVersion => match db::schema_version(&exec).await {
                    Ok(body) => reply(body, 200),
                    Err(e) => reply(
                        setjoin_platform::done(format!(
                            "{{\"error\":{}}}",
                            serde_json::to_string(&format!(
                                "schema-version query failed: {}",
                                e.message
                            ))
                            .expect("string")
                        )),
                        500,
                    ),
                },
                Action::BackupList => match db::backup_list(&exec).await {
                    Ok(body) => reply(body, 200),
                    Err(_) => bare(500, "failed to list backups", &c, &id),
                },
                Action::BackupEnqueue => match db::backup_enqueue(&exec, actor, operation).await {
                    CommandOutcome::Committed(body) => reply(body, 202),
                    CommandOutcome::RolledBack(_) => bare(500, "failed to enqueue backup", &c, &id),
                    CommandOutcome::Unknown { operation } => unknown_outcome(operation, &c, &id),
                },
                Action::ConfigList => {
                    let prefix =
                        crate::admin_identity_input::query(r.uri(), "prefix").unwrap_or_default();
                    match config::list(&exec, &prefix).await {
                        Ok(body) => reply(body, 200),
                        Err(_) => bare(500, "database error", &c, &id),
                    }
                }
                Action::ConfigGet => {
                    let key = segment(r.uri().path(), 5);
                    match config::get(&exec, &key).await {
                        Ok(Some(body)) => reply(body, 200),
                        Ok(None) => bare(404, "config key not found", &c, &id),
                        Err(_) => bare(500, "database error", &c, &id),
                    }
                }
                Action::ConfigExport => match config::export(&exec).await {
                    Ok(body) => {
                        let mut response = reply(body, 200);
                        response.headers_mut().insert(
                            "content-disposition",
                            hyper::header::HeaderValue::from_static(
                                "attachment; filename=mailserver-config.json",
                            ),
                        );
                        response
                    }
                    Err(_) => bare(500, "query failed", &c, &id),
                },
                Action::ConfigSet => {
                    let key = segment(r.uri().path(), 5);
                    if !config::WRITABLE.contains(&key.as_str()) {
                        return bare(403, "config key is not writable via API", &c, &id);
                    }
                    let Ok(body) = json_body::<SetBody>(&mut r, 1 << 20).await else {
                        return bare(400, "invalid JSON", &c, &id);
                    };
                    if !config::valid_value(&key, body.value.as_deref().unwrap_or("")) {
                        return bare(
                            400,
                            "config value must be a boolean: 1, true, 0 or false",
                            &c,
                            &id,
                        );
                    }
                    match config::set(
                        &exec,
                        actor,
                        &key,
                        body.value.as_deref(),
                        body.encrypted,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(()) => {
                            let mut response = reply(String::new(), 204);
                            response.headers_mut().remove("content-type");
                            response
                        }
                        CommandOutcome::RolledBack(_) => bare(500, "database error", &c, &id),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::ConfigImport => {
                    let Ok((raw, over)) = read_capped(&mut r).await else {
                        return bare(400, "invalid JSON", &c, &id);
                    };
                    match run_import::<K>(&exec, actor, operation, &raw, over, &c, &id).await {
                        Import::Done { imported, skipped } => reply(
                            setjoin_platform::done(format!(
                                "{{\"imported\":{imported},\"skipped\":{skipped}}}"
                            )),
                            200,
                        ),
                        Import::Refused(response) => response,
                    }
                }
                Action::BackupDownload => bare(501, "download not yet implemented", &c, &id),
                Action::BackupDelete => bare(501, "delete not yet implemented", &c, &id),
                _ => bare(500, "database error", &c, &id),
            }
        })
    }
}
