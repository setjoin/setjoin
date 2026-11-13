//! Frozen Go's requireAuth runtime gates. Route permissions/target ownership
//! remain with the concrete adapter; unported credential shapes stay with #406/#420.
use crate::{Body, RequestContext};
use http_body_util::BodyExt;
use hyper::{Request, Response};
use setjoin_authz::{
    device::{DeviceRequest, DeviceResolver},
    dpop,
    geoip::CountryDb,
    runtime::Proof,
    token::KeySource,
};
use setjoin_conditional_access::policy::{
    eval::{text, Context, Engine},
    store,
};
use setjoin_pg::{
    workers::{DirectListener, WorkerDatabase},
    ScopedExecutor, Type,
};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::sync::{watch, Mutex};

pub type Check<'a> = Pin<Box<dyn Future<Output = Option<Response<Body>>> + Send + 'a>>;
pub type Task<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
pub trait RuntimeGate: Send + Sync + 'static {
    fn check<'a>(&'a self, r: &'a mut Request<Body>, c: &'a RequestContext) -> Check<'a>;
    fn initialize(&self) -> Task<'_> {
        Box::pin(async {})
    }
    fn run(&self, stop: watch::Receiver<bool>) -> Task<'_> {
        Box::pin(stopped(stop))
    }
}
pub struct RuntimeAccess<K: KeySource + 'static> {
    exec: ScopedExecutor,
    worker: Option<ScopedExecutor>,
    worker_db: Option<WorkerDatabase>,
    keys: Arc<K>,
    issuer: String,
    attachment_secret: Vec<u8>,
    attachment_previous_secret: Option<Vec<u8>>,
    engine: Arc<Engine>,
    devices: Arc<crate::jmap::device_cache::DeviceCache>,
    sessions: Option<Arc<crate::workers::SessionDenylist>>,
    own_sessions: bool,
    device: Option<DeviceResolver>,
    replay: dpop::ReplayCache,
    geo: Option<CountryDb>,
    direct: String,
    listener: Mutex<Option<DirectListener>>,
}
impl<K: KeySource + 'static> RuntimeAccess<K> {
    pub fn new(exec: ScopedExecutor, keys: Arc<K>, issuer: String) -> Self {
        Self {
            engine: Arc::new(Engine::new(exec.clone())),
            exec,
            keys,
            issuer,
            attachment_secret: Vec::new(),
            attachment_previous_secret: None,
            worker: None,
            worker_db: None,
            devices: Default::default(),
            sessions: None,
            own_sessions: false,
            device: None,
            replay: Default::default(),
            geo: CountryDb::from_env(),
            direct: String::new(),
            listener: Mutex::new(None),
        }
    }
    pub fn with_workers(mut self, exec: ScopedExecutor, db: WorkerDatabase) -> Self {
        self.sessions = Some(Arc::new(crate::workers::SessionDenylist::new(db.clone())));
        self.own_sessions = true;
        self.worker = Some(exec);
        self.worker_db = Some(db);
        self
    }
    pub fn with_attachment_secrets(mut self, current: Vec<u8>, previous: Option<Vec<u8>>) -> Self {
        self.attachment_secret = current;
        self.attachment_previous_secret = previous;
        self
    }
    pub fn with_sessions(mut self, existing: Option<Arc<crate::workers::SessionDenylist>>) -> Self {
        if let Some(existing) = existing {
            self.sessions = Some(existing);
            self.own_sessions = false;
        }
        self
    }
    pub fn with_direct(mut self, direct: String) -> Self {
        self.direct = direct;
        self
    }
    pub fn with_device_secret(
        mut self,
        master: Vec<u8>,
        profile: setjoin_config_secret::CryptoProfile,
    ) -> Self {
        self.device = Some(DeviceResolver::new(self.exec.clone(), master, profile));
        self
    }
    pub fn session_cache(&self) -> Option<Arc<crate::workers::SessionDenylist>> {
        self.sessions.clone()
    }
    pub fn device_cache(&self) -> Arc<crate::jmap::device_cache::DeviceCache> {
        self.devices.clone()
    }
}
async fn stopped(mut stop: watch::Receiver<bool>) {
    while !*stop.borrow() {
        if stop.changed().await.is_err() {
            return;
        }
    }
}
async fn policies(
    engine: Arc<Engine>,
    direct: String,
    mut initial: Option<DirectListener>,
    stop: watch::Receiver<bool>,
) {
    if direct.is_empty() {
        stopped(stop).await;
        return;
    }
    loop {
        let initial_connection = initial.is_some();
        let connected = if let Some(listener) = initial.take() {
            Some(listener)
        } else {
            tokio::select! {_ = stopped(stop.clone())=>return,r=tokio::time::timeout(Duration::from_secs(5),DirectListener::connect(&direct,"conditional_access"))=>r.ok().and_then(Result::ok)}
        };
        if let Some(mut listener) = connected {
            // Subscribe before invalidating: repair events missed during reconnect.
            if !initial_connection {
                engine.invalidate().await;
            }
            loop {
                tokio::select! {
                    _=stopped(stop.clone())=>return,
                    message=listener.recv()=>{if message.is_none(){break;}engine.invalidate().await;}
                }
            }
        }
        tokio::select! {_=stopped(stop.clone())=>return,_=tokio::time::sleep(Duration::from_secs(1))=>{}}
    }
}
fn protected(r: &Request<Body>) -> bool {
    let path = r
        .uri()
        .path()
        .strip_prefix("/api/")
        .map(|s| format!("/{s}"))
        .unwrap_or_else(|| r.uri().path().to_owned());
    include_str!("../../../../mailserver/cmd/mailserverd/testdata/route_inventory.golden")
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .any(|(pattern, chain)| {
            if !chain.split(" > ").any(|m| m == "requireAuth") {
                return false;
            }
            let (method, pattern) = pattern.split_once(' ').unwrap_or(("*", pattern));
            (method == "*"
                || method == r.method().as_str()
                || (method == "GET" && r.method() == hyper::Method::HEAD))
                && crate::inventory::path_score(pattern, &path).is_some()
        })
}
fn reply(
    r: &Request<Body>,
    c: &RequestContext,
    status: u16,
    body: String,
    reauth: bool,
    json: bool,
) -> Response<Body> {
    let id = crate::jmap::reply::request_id(
        r.headers().get("x-request-id"),
        crate::jmap::random().unwrap_or([0; 16]),
    );
    let mut response = crate::jmap::reply::response(body, c.identity.proto, id);
    *response.status_mut() = hyper::StatusCode::from_u16(status).expect("runtime status");
    response.headers_mut().insert(
        "content-type",
        if json {
            "application/json"
        } else {
            "application/problem+json"
        }
        .parse()
        .unwrap(),
    );
    if reauth {
        response
            .headers_mut()
            .insert("www-authenticate", "reauth".parse().unwrap());
    }
    response
}
fn deny(
    r: &Request<Body>,
    c: &RequestContext,
    status: u16,
    title: &str,
    detail: &str,
    reauth: bool,
) -> Response<Body> {
    reply(
        r,
        c,
        status,
        crate::problem::middleware(status, title, detail),
        reauth,
        false,
    )
}
async fn proof_body(r: &mut Request<Body>) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.ok()?;
        if let Some(data) = frame.data_ref() {
            if bytes.len() + data.len() > (1 << 20) {
                return None;
            }
            bytes.extend_from_slice(data);
        }
    }
    *r.body_mut() = http_body_util::Full::new(bytes::Bytes::from(bytes.clone()))
        .map_err(|never| match never {})
        .boxed();
    Some(bytes)
}
fn unavailable(r: &Request<Body>, c: &RequestContext) -> Response<Body> {
    reply(
        r,
        c,
        503,
        crate::problem::Problem::new(503, "Runtime access verification unavailable.").body(),
        false,
        false,
    )
}
fn fingerprint(ua: &str, ip: std::net::IpAddr) -> String {
    let ip = match ip {
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or_else(|| ip.to_string(), |ip| ip.to_string()),
        ip => ip.to_string(),
    };
    let parts: Vec<_> = ip.split('.').collect();
    let masked = if parts.len() == 4 {
        format!("{}.{}.{}.0", parts[0], parts[1], parts[2])
    } else {
        let parts: Vec<_> = ip.split(':').collect();
        if parts.len() > 3 {
            format!("{}::", parts[..3].join(":"))
        } else {
            ip
        }
    };
    format!("{ua}|{masked}")
}
impl<K: KeySource + 'static> RuntimeGate for RuntimeAccess<K> {
    fn initialize(&self) -> Task<'_> {
        Box::pin(async move {
            if !self.direct.is_empty() {
                match DirectListener::connect(&self.direct, "conditional_access").await {
                    Ok(listener) => *self.listener.lock().await = Some(listener),
                    Err(error) => eprintln!("conditional access listener unavailable: {error}"),
                }
            }
            self.engine.initialize().await;
            if let Some(sessions) = &self.sessions {
                if let Err(error) = sessions.refresh_once().await {
                    eprintln!("runtime session verification unavailable: {error}");
                }
            }
        })
    }
    fn run(&self, stop: watch::Receiver<bool>) -> Task<'_> {
        Box::pin(async move {
            let initial = self.listener.lock().await.take();
            let policy = policies(
                self.engine.clone(),
                self.direct.clone(),
                initial,
                stop.clone(),
            );
            let sessions = async {
                if self.own_sessions && !self.direct.is_empty() {
                    if let Some(sessions) = &self.sessions {
                        if let Err(error) = sessions
                            .clone()
                            .run(self.direct.clone(), stopped(stop.clone()))
                            .await
                        {
                            eprintln!("runtime session cache stopped: {error}");
                        }
                        return;
                    }
                }
                stopped(stop).await;
            };
            tokio::join!(policy, sessions);
        })
    }
    fn check<'a>(&'a self, r: &'a mut Request<Body>, c: &'a RequestContext) -> Check<'a> {
        Box::pin(async move {
            if !protected(r) || !setjoin_authz::csrf::allows(r.headers(), c.identity.proto) {
                return None;
            }
            let token = setjoin_authz::token::presented(r.headers());
            if token.is_none() && !r.headers().contains_key(hyper::header::AUTHORIZATION) {
                return None;
            }
            // Read flags before proof selection: an unsupported credential must
            // not turn an enabled gate into silent admission.
            let keys: Vec<String> = [
                "feature.cae_runtime",
                "feature.conditional_access",
                "feature.device_trust_enforcement",
                "feature.device_lockdown",
                "feature.token_binding",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect();
            let flags = match self
                .exec
                .read(
                    "SELECT key,enabled FROM feature_toggles WHERE key=ANY($1::text[])",
                    &[(&keys, Type::TEXT_ARRAY)],
                )
                .await
            {
                Ok(flags) => flags,
                Err(_) => return Some(unavailable(r, c)),
            };

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs_f64();
            let proof = if let Some(token) = token.as_deref() {
                Proof::verify(
                    token,
                    &self.issuer,
                    now,
                    &self.keys,
                    matches!(r.uri().path(), "/drive" | "/api/drive")
                        || r.uri().path().starts_with("/drive/")
                        || r.uri().path().starts_with("/api/drive/"),
                )
                .await
                .or_else(|| {
                    let path = r
                        .uri()
                        .path()
                        .strip_prefix("/api")
                        .unwrap_or(r.uri().path());
                    (matches!(*r.method(), hyper::Method::GET | hyper::Method::HEAD)
                        && path.starts_with("/mail-attachment/"))
                    .then(|| {
                        Proof::attachment(
                            token,
                            &self.issuer,
                            now,
                            &[
                                &self.attachment_secret,
                                self.attachment_previous_secret
                                    .as_deref()
                                    .unwrap_or_default(),
                            ],
                        )
                    })
                    .flatten()
                })
            } else {
                None
            };
            let Some(proof) = proof else {
                return flags.iter().any(|flag| flag.get::<_, bool>(1)).then(|| {
                    reply(
                        r,
                        c,
                        401,
                        crate::problem::Problem::new(401, "Authentication required.").body(),
                        false,
                        false,
                    )
                });
            };
            // The live guest/credential belt still belongs to #406; this is a member proof.
            let guests = match self
                .exec
                .read(
                    "SELECT count(*)::int8 FROM guest_account_status($1)",
                    &[(&proof.user_id(), Type::INT8)],
                )
                .await
            {
                Ok(guests) => guests,
                Err(_) => return Some(unavailable(r, c)),
            };
            if guests[0].get::<_, i64>(0) != 0 {
                return None;
            }
            let on = |key: &str| {
                flags
                    .iter()
                    .any(|v| v.get::<_, String>(0) == key && v.get::<_, bool>(1))
            };
            if on("feature.device_trust_enforcement") {
                if let Some((title, detail)) = proof.compliance_denial() {
                    return Some(deny(r, c, 403, title, detail, false));
                }
                if self
                    .devices
                    .revoked_enabled(self.worker_db.as_ref(), proof.device_id())
                    .await
                {
                    let body = format!(
                        "{{\"detail\":{},\"status\":403,\"title\":\"Forbidden\"}}\n",
                        crate::problem::go_string(
                            "This device's access has been revoked. Contact your administrator."
                        )
                    );
                    return Some(reply(r, c, 403, body, false, true));
                }
            }
            if on("feature.conditional_access") && on("feature.device_lockdown") {
                let bg = store::break_glass(&self.exec).await.unwrap_or_default();
                if !bg.is_empty() && !bg.contains(&proof.user_id()) {
                    let binding = if let Some(resolver) = &self.device {
                        if let Some(body) = proof_body(r).await {
                            let target = r.uri().path_and_query().map_or("/", |v| v.as_str());
                            // http.StripPrefix mutates Go's URL before the device helper.
                            let inner = if target.starts_with("/api/") {
                                &target[4..]
                            } else {
                                target
                            };
                            resolver
                                .resolve(
                                    &proof,
                                    DeviceRequest {
                                        headers: r.headers(),
                                        method: r.method().as_str(),
                                        uri: inner,
                                        body: &body,
                                    },
                                )
                                .await
                        } else {
                            Default::default()
                        }
                    } else {
                        Default::default()
                    };
                    if !binding.bound || binding.enroll_state != "approved" {
                        let body=format!("{{\"code\":\"BZ095\",\"detail\":{},\"status\":403,\"title\":\"Forbidden\"}}\n",crate::problem::go_string("device not enrolled — contact your administrator"));
                        return Some(reply(r, c, 403, body, false, true));
                    }
                }
            }
            let claims = proof.claims();
            if let Some(sessions) = &self.sessions {
                let issued = chrono::DateTime::from_timestamp(
                    claims["iat"].as_i64().unwrap_or(-62_135_596_800),
                    0,
                )?;
                if sessions.is_revoked(
                    proof.user_id(),
                    text(claims, "jti"),
                    text(claims, "fam"),
                    issued,
                ) {
                    return Some(deny(
                        r,
                        c,
                        401,
                        "session_revoked",
                        "Session has been revoked. Sign in again.",
                        false,
                    ));
                }
            }
            if !on("feature.cae_runtime") {
                return None;
            }
            if self.sessions.as_ref().is_none_or(|s| !s.loaded()) {
                return Some(deny(
                    r,
                    c,
                    401,
                    "session_revoked",
                    "Session verification unavailable — re-authenticate.",
                    false,
                ));
            }
            if on("feature.token_binding") && !text(&claims["cnf"], "jkt").is_empty() {
                let uri = format!(
                    "https://{}{}",
                    r.headers()
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or(""),
                    r.uri().path()
                );
                let signed = r
                    .headers()
                    .get("dpop")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if !dpop::verify(
                    signed,
                    r.method().as_str(),
                    &uri,
                    text(&claims["cnf"], "jkt"),
                    now,
                    &self.replay,
                    token.as_deref().unwrap_or(""),
                ) {
                    return Some(reply(
                        r,
                        c,
                        401,
                        crate::problem::runtime_binding(),
                        false,
                        false,
                    ));
                }
            }
            if let Some(sif) = claims["sif"].as_i64() {
                let anchor = claims["auth_time"]
                    .as_i64()
                    .or_else(|| claims["iat"].as_i64());
                if anchor.is_none_or(|anchor| {
                    now - anchor as f64 > sif.wrapping_mul(1_000_000_000) as f64 / 1e9
                }) {
                    return Some(deny(
                        r,
                        c,
                        401,
                        "sign_in_frequency",
                        "Session expired — re-authenticate.",
                        true,
                    ));
                }
            }
            if !on("feature.conditional_access") {
                return None;
            }
            let ua = r
                .headers()
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let ctx = Context {
                user_id: proof.user_id(),
                source_ip: c.identity.client_ip.to_string(),
                protocol: "http".into(),
                auth_method: if text(claims, "auth_method").is_empty() {
                    "jwt_bearer".into()
                } else {
                    text(claims, "auth_method").into()
                },
                current_acr: text(claims, "acr").into(),
                user_agent: ua.into(),
                device_fp: fingerprint(ua, c.identity.client_ip),
                country: self
                    .geo
                    .as_ref()
                    .map_or_else(String::new, |geo| geo.country(c.identity.client_ip)),
                risk_level: text(&claims["risk"], "level").into(),
                request_time: Some(now as i64),
                ..Default::default()
            };
            // Go runtime deliberately leaves ClientType, CompletedFactors and
            // DeviceBound/EnrollState unset, even after a successful lockdown proof.
            let result = self.engine.evaluate(ctx).await;
            match result.decision.as_str() {
                "block" => {
                    if result.remediation == "terms" && result.terms_id != 0 {
                        if let Some(worker) = &self.worker {
                            let rows=worker.read("SELECT EXISTS(SELECT 1 FROM terms_of_use t LEFT JOIN terms_of_use_acceptance a ON a.tou_id=t.id AND a.user_id=$1 AND a.version=t.version WHERE t.id=$2 AND t.enabled AND a.user_id IS NULL)",&[(&proof.user_id(),Type::INT8),(&result.terms_id,Type::INT8)]).await;
                            if rows.is_ok_and(|r| !r[0].get::<_, bool>(0)) {
                                return None;
                            }
                        }
                    }
                    Some(reply(
                        r,
                        c,
                        403,
                        crate::problem::runtime_block(
                            &result.reason,
                            &result.remediation,
                            result.terms_id,
                        ),
                        false,
                        false,
                    ))
                }
                "step_up" => Some(deny(r, c, 401, "step_up_required", &result.reason, true)),
                _ => None, // Go wires no limited_web context projection in mailserverd.
            }
        })
    }
}
