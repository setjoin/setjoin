//! HTTP transport for the standalone identity process. See DOX.md.
mod config;
mod ingress;
mod issuance;
mod revocations;
mod totp;
mod push;
mod recovery;
mod possession;
mod webauthn;
mod oidc;
mod rp;
mod saml;
mod http_threat;
mod guest_invite;
use bytes::Bytes;
pub use config::Config;
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited};
use hyper::body::Body as _;
use hyper::{Method, Request, Response};
use serde::Deserialize;
use serde_json::{json, Value};
use setjoin_identity::login;
use std::sync::Arc;
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Body = BoxBody<Bytes, std::io::Error>;
#[path = "../../gateway/src/problem.rs"]
pub mod problem;
pub fn body(text: impl Into<Bytes>) -> Body {
    Full::new(text.into())
        .map_err(|never| match never {})
        .boxed()
}
type Client =
    hyper_util::client::legacy::Client<hyper_util::client::legacy::connect::HttpConnector, Body>;
/// Request-body cap shared by every JSON route (the mutant restores Go's none for
/// the owner-approved #491 fix test).
fn body_cap() -> usize {
    if setjoin_contracts::mutants::on("unbounded-request-bodies") {
        usize::MAX
    } else {
        1 << 20
    }
}
fn client() -> Client {
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build_http()
}
pub struct AuthServer {
    saml: Option<Arc<setjoin_identity::saml::Registry>>,
    rp: Option<Arc<setjoin_identity::rp::Registry>>,
    oidc_key: Option<setjoin_identity::oidc::SigningKey>,
    oidc_cipher: Option<setjoin_identity::oidc::CodeCipher>,
    webauthn: Option<setjoin_identity::webauthn::RelyingParty>,
    internal_key: std::sync::RwLock<String>,
    client: Client,
    pub exec: setjoin_pg::ScopedExecutor,
    keys: Option<Arc<setjoin_authz::signing_keys::KeySet>>,
    legacy: Option<setjoin_authz::legacy_jwt::LegacyKeys>,
    config: Config,
    revocations: revocations::Revocations,
    dpop_replay: setjoin_authz::dpop::ReplayCache,
    forgot_password: bool,
    recovery_ip: setjoin_identity::push::IpBudget,
    recovery_worker: Option<setjoin_pg::ScopedExecutor>,
    guest_worker: Option<setjoin_pg::ScopedExecutor>,
    geo: Option<Arc<setjoin_authz::geoip::CountryDb>>,
    push_ip: setjoin_identity::push::IpBudget,
    native_push: setjoin_identity::push_delivery::Dispatch,
}
impl AuthServer {
    fn oidc_cors(&self,req:&Request<Body>,mut reply:Response<Body>)->Response<Body> {
        let origin=req.headers().get("origin").and_then(|h|h.to_str().ok()).unwrap_or("");
        let allowed=!origin.is_empty() && (origin.eq_ignore_ascii_case(&format!("https://{}",self.config.oidc_hostname)) || self.config.oidc_origins.split(',').map(|s|s.trim().trim_end_matches('/')).any(|s|s.eq_ignore_ascii_case(origin)));
        let preflight=req.method()==Method::OPTIONS && req.headers().get("access-control-request-method").is_some_and(|h|!h.is_empty());
        if preflight {
            reply=Response::builder().status(204).header("vary","Origin, Access-Control-Request-Method, Access-Control-Request-Headers").body(body("")).unwrap();
            let method=req.headers()["access-control-request-method"].to_str().unwrap_or("");
            let headers_ok=req.headers().get_all("access-control-request-headers").iter().all(|h|h.to_str().is_ok_and(|s|s.split(',').all(|s|matches!(s.trim().to_ascii_lowercase().as_str(),"origin"|"accept"|"accept-language"|"authorization"|"content-type"|"x-requested-with"))));
            if allowed && matches!(method,"GET"|"HEAD"|"POST") && headers_ok {
                reply.headers_mut().insert("access-control-allow-origin",req.headers()["origin"].clone());
                reply.headers_mut().insert("access-control-allow-methods",req.headers()["access-control-request-method"].clone());
                for h in req.headers().get_all("access-control-request-headers") {if !h.is_empty(){reply.headers_mut().append("access-control-allow-headers",h.clone());}}
            }
        } else {
            reply.headers_mut().insert("vary","Origin".parse().unwrap());
            if allowed && matches!(req.method(),&Method::GET|&Method::HEAD|&Method::POST) {
                reply.headers_mut().insert("access-control-allow-origin",req.headers()["origin"].clone());
                reply.headers_mut().insert("access-control-expose-headers","Location, Content-Length".parse().unwrap());
            }
        }
        reply
    }
    pub fn new(exec: setjoin_pg::ScopedExecutor) -> Self {
        Self {
            saml: None,
            rp: None,
            oidc_key: None,
            oidc_cipher: None,
            webauthn:None,
            internal_key: std::sync::RwLock::new(String::new()),
            client: client(),
            exec,
            keys: None,
            legacy: None,
            config: Config::for_secret(String::new()),
            revocations: Default::default(),
            dpop_replay: Default::default(),
            forgot_password: false,
            recovery_ip: Default::default(),
            recovery_worker: None,
            guest_worker: None,
            geo: None,
            push_ip: Default::default(),
            native_push: Default::default(),
        }
    }
    pub async fn load(exec: setjoin_pg::ScopedExecutor, config: Config) -> Result<Self, String> {
        Self::load_with_rp_http(exec,config,Arc::new(setjoin_identity::rp::SafeHttp::new()?)).await
    }
    /// Embedding boundary for external IdP HTTPS only; it carries no identity authority.
    pub async fn load_with_rp_http(exec:setjoin_pg::ScopedExecutor,config:Config,http:Arc<dyn setjoin_identity::rp::Http>)->Result<Self,String>{
        if config.secret.is_empty() || config.issuer.is_empty() {
            return Err("JWT secret and issuer required".into());
        }
        let exec = if !config.db_encryption_key.is_empty() || !config.audit_hmac_key.is_empty() {
            exec.with_audit_keys(
                config.db_encryption_key.clone(),
                config.audit_hmac_key.clone(),
            )
        } else {
            exec
        };
        let pem = if matches!(
            config.profile,
            setjoin_config_secret::CryptoProfile::Smx
                | setjoin_config_secret::CryptoProfile::Hybrid
        ) {
            config.sm2_pem.as_deref()
        } else {
            None
        };
        let legacy = setjoin_authz::legacy_jwt::LegacyKeys::from_pem(
            config.secret.as_bytes(),
            &["authserver-hmac-1"],
            pem,
        )
        .map_err(str::to_owned)?;
        let keys = setjoin_authz::signing_keys::KeySet::load(
            &exec,
            config.secret.as_bytes(),
            config.profile,
        )
        .await?;
        let forgot_password = login::enabled(&exec, "feature.forgot_password")
            .await
            .unwrap_or(false);
        let revocations =
            revocations::Revocations::load(&config.dsn, config.worker_dsn.as_deref()).await;
        let native_push = if config.vapid_private_key.is_empty() {
            Default::default()
        } else {
            setjoin_identity::push_delivery::Dispatch::from_env()
        };
        let recovery_worker = config.worker_dsn.as_deref().filter(|s|!s.is_empty()).or_else(||(!config.dsn.is_empty()).then_some(config.dsn.as_str())).map(|dsn|setjoin_pg::ScopedExecutor::from_dsn(dsn,4).map_err(|e|e.0)).transpose()?;
        // #342: Go's guest-invite workerPool on its own two-connection pool.
        let guest_worker = config
            .worker_dsn
            .as_deref()
            .filter(|s| !s.is_empty())
            .or_else(|| (!config.dsn.is_empty()).then_some(config.dsn.as_str()))
            .map(|dsn| setjoin_pg::ScopedExecutor::from_dsn(dsn, 2).map_err(|e| e.0))
            .transpose()?
            .map(|w| {
                if !config.db_encryption_key.is_empty() || !config.audit_hmac_key.is_empty() {
                    w.with_audit_keys(
                        config.db_encryption_key.clone(),
                        config.audit_hmac_key.clone(),
                    )
                } else {
                    w
                }
            });
        match &guest_worker {
            Some(w) => {
                if let Err(e) = setjoin_identity::guest_invite::readiness(w).await {
                    eprintln!("setjoin-auth: guest invite acceptance degraded: {e}");
                }
            }
            None => eprintln!("setjoin-auth: guest invite acceptance degraded: no worker DSN"),
        }
        let geo = (!config.geoip_path.is_empty())
            .then(|| {
                std::fs::read(&config.geoip_path)
                    .map_err(|e| e.to_string())
                    .and_then(|b| setjoin_authz::geoip::CountryDb::from_bytes(b, false, ""))
            })
            .and_then(Result::ok)
            .map(Arc::new);
        let oidc_key = if config.oidc_enabled {
            let (private,public)=(config.oidc_private_key.clone(),config.oidc_public_key.clone());
            Some(tokio::task::spawn_blocking(move || setjoin_identity::oidc::SigningKey::load(&private,&public)).await.map_err(|_|"OIDC key task failed")??)
        } else {None};
        let saml = if config.saml_enabled && !config.saml_cert_file.is_empty() && !config.saml_key_file.is_empty() {
            match setjoin_identity::saml::Registry::load(exec.clone(), &config.saml_cert_file, &config.saml_key_file, &config.db_encryption_key, http.clone()).await {
                Ok(registry) => Some(registry),
                Err(error) => { eprintln!("SAML registrations failed closed: {error}"); None }
            }
        } else { None };
        let rp=if config.oidc_rp_enabled{Some(setjoin_identity::rp::Registry::load(exec.clone(),config.secret.as_bytes(),http).await)}else{None};
        Ok(Self {
            saml,
            rp,
            oidc_cipher: if config.oidc_enabled {Some(setjoin_identity::oidc::CodeCipher::new(config.secret.as_bytes())?)}else{None},
            oidc_key,
            webauthn: setjoin_identity::webauthn::RelyingParty::new(config.secret.as_bytes(), &config.webauthn_rp_id, &config.webauthn_rp_name, &config.webauthn_rp_origin).ok(),
            internal_key: std::sync::RwLock::new(config.internal_api_key.clone()),
            revocations,
            dpop_replay: Default::default(),
            forgot_password,
            recovery_ip: Default::default(),
            recovery_worker,
            guest_worker,
            geo,
            push_ip: Default::default(),
            native_push,
            client: client(),
            exec,
            keys: Some(Arc::new(keys)),
            legacy: Some(legacy),
            config,
        })
    }
    /// Embedding/test seam (#342): replace the guest-invite worker executor; the
    /// configured audit keys are applied. Grants no identity authority.
    pub fn with_guest_worker(mut self, worker: setjoin_pg::ScopedExecutor) -> Self {
        self.guest_worker = Some(
            if !self.config.db_encryption_key.is_empty() || !self.config.audit_hmac_key.is_empty() {
                worker.with_audit_keys(
                    self.config.db_encryption_key.clone(),
                    self.config.audit_hmac_key.clone(),
                )
            } else {
                worker
            },
        );
        self
    }
    /// Embed a native provider transport without granting it identity authority.
    pub fn with_native_push(
        mut self,
        transport: impl setjoin_identity::push_delivery::NativeDelivery + 'static,
    ) -> Self {
        self.native_push = setjoin_identity::push_delivery::Dispatch::with_transport(transport);
        self
    }
    fn failure(status: u16, detail: &str, path: &str) -> Response<Body> {
        Response::builder()
            .status(status)
            .header("content-type", "application/problem+json")
            .header("cache-control", "no-store")
            .body(body(
                problem::Problem::new(status, detail).instance(path).body(),
            ))
            .unwrap()
    }
    fn json(status: u16, v: Value) -> Response<Body> {
        let text = v
            .to_string()
            .replace('&', "\\u0026")
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029")
            + "\n";
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(body(text))
            .unwrap()
    }
    fn wire_json(status: u16, text: String) -> Response<Body> {
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .header("cache-control", "no-store")
            .body(body(text))
            .unwrap()
    }
    fn client_ip(&self, req: &Request<Body>) -> std::net::IpAddr {
        let peer = req
            .extensions()
            .get::<ConnectionMeta>()
            .map_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), |m| {
                m.peer.ip()
            });
        let trusted = if self.config.client_proxy == peer.to_string() {
            setjoin_authz::clientip::TrustedProxies::parse(&peer.to_string()).unwrap_or_default()
        } else {
            Default::default()
        };
        setjoin_authz::clientip::resolve(peer, req.headers(), &trusted).client_ip
    }
    async fn forward(&self, mut req: Request<Body>) -> Response<Body> {
        let Some(base) = &self.config.go_upstream else {
            return Response::builder()
                .status(503)
                .body(body("auth shape awaits its owner ticket\n"))
                .unwrap();
        };
        let suffix = req.uri().path_and_query().map_or("/", |p| p.as_str());
        let Ok(uri) = format!("{}{suffix}", base.trim_end_matches('/')).parse() else {
            return Self::failure(503, "auth upstream unavailable", req.uri().path());
        };
        let ip = self.client_ip(&req).to_string();
        req.headers_mut().remove("forwarded");
        req.headers_mut().remove("x-real-ip");
        req.headers_mut()
            .insert("x-forwarded-for", ip.parse().expect("IP header"));
        *req.uri_mut() = uri;
        match self.client.request(req).await {
            Ok(r) => r.map(|b| b.map_err(std::io::Error::other).boxed()),
            Err(_) => Self::failure(502, "auth upstream unavailable", ""),
        }
    }
    pub async fn handle(&self, req: Request<Body>) -> Response<Body> {
        if req.uri().path()=="/auth/identity-links" && matches!(req.method(),&Method::GET|&Method::HEAD) {return self.saml_links(req).await;}
        if req.uri().path().starts_with("/auth/identity-links/") && req.method()==Method::DELETE {return self.identity_unlink(req).await;}
        if req.uri().path().starts_with("/auth/saml/") { return self.saml_request(req).await; }
        if req.method()==Method::POST && req.uri().path()=="/auth/oidc/link"{return self.rp_link(req).await;}
        if req.method()==Method::GET && req.uri().path()=="/auth/oidc/link/complete" {return self.rp_link_complete(req).await;}
        if matches!(req.method(), &Method::GET | &Method::HEAD) && req.uri().path()=="/auth/oidc/login" {return self.rp_login(req).await;}
        if matches!(req.method(), &Method::GET | &Method::HEAD) && req.uri().path()=="/auth/oidc/callback" {return self.rp_callback(req).await;}
        if req.uri().path()=="/oauth" && self.config.oidc_enabled{return self.oidc_bare_oauth(&req);}
        if req.uri().path().starts_with("/authorize/")&&req.uri().path()!="/authorize/callback"{return Self::not_found();}
        if req.uri().path().starts_with("/oauth/") || matches!(req.uri().path(),"/userinfo"|"/revoke"|"/end_session") {return self.oidc_oauth(req).await;}
        if req.uri().path()=="/authorize/callback" {return self.oidc_callback(req).await;}
        if req.uri().path()=="/auth/oidc/op/complete" {return self.oidc_complete(req).await;}
        if req.uri().path().starts_with("/auth/oidc/"){return Self::rp_namespace(req);}
        if req.uri().path()=="/authorize" {return self.oidc_authorize(req).await;}
        if matches!(req.method(), &Method::GET | &Method::HEAD) && req.uri().path()=="/.well-known/oauth-authorization-server" {
            let text=setjoin_identity::oidc::metadata(&self.config.oidc_hostname);
            let mut reply=Self::wire_json(200,text.clone());
            if req.method()==Method::HEAD {reply.headers_mut().insert("content-length",text.len().into());*reply.body_mut()=body("");}
            return reply;
        }
        if req.uri().path()=="/keys" {
            return match &self.oidc_key {
                Some(key)=>self.oidc_cors(&req,Response::builder().header("content-type","application/json").body(body(key.jwks())).unwrap()),
                None=>Self::not_found(),
            };
        }
        if req.uri().path()=="/.well-known/openid-configuration" {
            return if self.config.oidc_enabled {
                let text=if req.method()==Method::GET {setjoin_identity::oidc::discovery(&self.config.oidc_hostname)}else{setjoin_identity::oidc::discovery_unwrapped(&self.config.oidc_hostname)};
                let mut reply=Response::builder().header("content-type","application/json").header("vary","Origin");
                if req.method()==Method::HEAD {reply=reply.header("content-length",text.len());}
                self.oidc_cors(&req,reply.body(body(if req.method()==Method::HEAD {String::new()}else{text})).unwrap())
            } else {Self::not_found()};
        }
        if req.uri().path().starts_with("/.well-known/") && !(matches!(req.method(),&Method::GET|&Method::HEAD)&&matches!(req.uri().path(),"/.well-known/setjoin"|"/.well-known/jwks.json")){return if self.config.oidc_enabled{self.oidc_cors(&req,Self::not_found())}else{Self::not_found()};}
        if req.method()==Method::POST && req.uri().path()=="/auth/mfa/possession/webauthn/finish" {return self.possession_webauthn_finish(req).await;}
        if req.method()==Method::POST && req.uri().path()=="/auth/mfa/possession/webauthn/begin" {return self.possession_webauthn_begin(req).await;}
        if req.method() == Method::POST && req.uri().path() == "/auth/forgot-password/verify" {
            return self.recovery_verify(req).await;
        }
        if req.method() == Method::POST && req.uri().path() == "/auth/forgot-password/begin" {
            return self.recovery_begin(req).await;
        }
        if req.method() == Method::POST && req.uri().path() == "/auth/mfa/push/send" {
            return self.push_send(req).await;
        }
        if req.method() == Method::POST && req.uri().path() == "/auth/mfa/approve" {
            return self.push_approve(req).await;
        }
        if req.method() == Method::POST && req.uri().path() == "/auth/push/status" {
            return self.push_status(req).await;
        }
        if req.method() == Method::POST && req.uri().path() == "/auth/push/verify" {
            return self.push_verify(req).await;
        }
        if req.method() == Method::POST && req.uri().path() == "/auth/backup-codes/verify" {
            return self.backup_verify(req).await;
        }
        if req.method() == Method::POST && req.uri().path() == "/auth/backup-codes/generate" {
            return self.generate_backups(req).await;
        }
        if req.method() == Method::POST && req.uri().path() == "/auth/mfa/possession/totp" {
            return self.possession_totp(req).await;
        }
        if req.method() == Method::POST && req.uri().path() == "/auth/mfa/reauth" {
            return self.password_grant(req).await;
        }
        if matches!(req.method(), &Method::GET | &Method::HEAD) && req.uri().path() == "/auth/push/vapid-key" {
            let mut reply = match setjoin_identity::push::vapid_public_key(&self.config.vapid_private_key) {
                Some(key) => Self::wire_json(200, format!("{{\"vapid_public_key\":\"{key}\"}}\n")),
                None => Self::push_named_problem(404, "push not configured", "not-found", req.uri().path()),
            };
            if req.method()==Method::HEAD {
                if let Some(n)=reply.body().size_hint().exact(){reply.headers_mut().insert("content-length",n.to_string().parse().unwrap());}
                *reply.body_mut()=body("");
            }
            return reply;
        }
        if self.config.internal_api_key.is_empty()
            && matches!(req.uri().path(), "/admin/reload" | "/auth/scim/disable")
        {
            return Response::builder()
                .status(404)
                .header("content-type", "text/plain; charset=utf-8")
                .header("x-content-type-options", "nosniff")
                .body(body("404 page not found\n"))
                .unwrap();
        }
        if req.uri().path().starts_with("/auth/push/") || req.uri().path().starts_with("/auth/backup-codes/") {
            return Self::mfa_namespace(req);
        }
        if req.method() == Method::POST && req.uri().path() == "/auth/device/register" {
            return self.webpush(req).await;
        }
        if req.method() == Method::POST && req.uri().path() == "/device/register" {
            return self.bootstrap(req).await;
        }
        if req.method() == Method::POST {
            if let Some(target) = req
                .uri()
                .path()
                .strip_prefix("/auth/admin/users/")
                .and_then(|s| s.strip_suffix("/impersonate"))
                .filter(|s| !s.contains('/'))
            {
                let target = target.to_owned();
                return self.impersonate(req, target).await;
            }
        }
        if req.method() == Method::POST && req.uri().path() == "/auth/introspect" {
            return self.introspect(req).await;
        }
        if req.method() == Method::POST && req.uri().path() == "/auth/revoke" {
            return self.revoke(req).await;
        }
        if matches!(req.method(), &Method::GET | &Method::HEAD)
            && req.uri().path() == "/terms/pending"
        {
            return self.pending(req).await;
        }
        if req.method() == Method::POST && req.uri().path() == "/terms/accept" {
            return self.accept(req).await;
        }
        if req.method() == Method::POST && req.uri().path() == "/auth/scim/disable" {
            return self.scim_disable(req).await;
        }
        if req.method() == Method::POST && req.uri().path() == "/admin/reload" {
            return self.reload_http(req).await;
        }
        if req.method()==Method::DELETE {
            if let Some(id)=req.uri().path().strip_prefix("/auth/webauthn/credential/").filter(|s|!s.is_empty()&&!s.contains('/')) {
                let id=id.to_owned();return self.webauthn_revoke(req,id).await;
            }
        }
        if req.method()==Method::POST && req.uri().path()=="/auth/webauthn/register/finish" { let req=match self.webauthn_ingress(req).await{Ok(r)=>r,Err(r)=>return r}; return self.webauthn_register_finish(req).await; }
        if matches!(req.method(), &Method::GET | &Method::HEAD) && req.uri().path()=="/auth/webauthn/register/begin" { return self.webauthn_register_begin(req).await; }
        if req.method()==Method::POST && req.uri().path()=="/auth/webauthn/login/finish" { return self.webauthn_login_finish(req).await; }
        if matches!(req.method(), &Method::GET | &Method::HEAD) && req.uri().path()=="/auth/webauthn/login/begin" { return self.webauthn_login_begin(req).await; }
        if req.method()==Method::PUT {
            if let Some(id)=req.uri().path().strip_prefix("/auth/webauthn/credential/").and_then(|s|s.strip_suffix("/name")).filter(|s|!s.is_empty()&&!s.contains('/')) {
                let id=id.to_owned();return self.webauthn_name(req,id).await;
            }
        }
        if matches!(req.method(), &Method::GET | &Method::HEAD) && req.uri().path()=="/auth/webauthn/credentials" { return self.webauthn_list(req).await; }
        if req.uri().path().starts_with("/auth/webauthn/") {return Self::webauthn_mux(req);}
        let req = if (req.method()==Method::POST && matches!(req.uri().path(),
            "/auth/totp/confirm"|"/auth/totp/verify"|"/auth/totp/enroll/setup"|"/auth/totp/enroll/confirm")) ||
            (matches!(req.method(),&Method::GET|&Method::HEAD) && req.uri().path()=="/auth/totp/setup") {
            match self.totp_ingress(req).await {Ok(req)=>req,Err(reply)=>return reply}
        } else {req};
        if req.method()==Method::POST && req.uri().path()=="/auth/totp/enroll/confirm" {return self.totp_bootstrap_confirm(req).await;}
        if req.method()==Method::POST && req.uri().path()=="/auth/totp/verify" {return self.totp_verify(req).await;}
        if req.method()==Method::POST && req.uri().path()=="/auth/totp/enroll/setup" {return self.totp_bootstrap_setup(req).await;}
        if req.method()==Method::POST && req.uri().path()=="/auth/totp/confirm" {return self.totp_confirm(req).await;}
        if matches!(req.method(), &Method::GET | &Method::HEAD)
            && req.uri().path() == "/auth/totp/setup"
        {
            return self.totp_setup(req).await;
        }
        if req.method() == Method::POST && req.uri().path() == "/auth/totp/remove/begin" {
            return self.totp_begin(req).await;
        }
        if req.method() == Method::POST && req.uri().path() == "/auth/totp/remove" {
            return self.totp_remove(req).await;
        }
        if req.uri().path().starts_with("/auth/totp/") {
            let allow = match req.uri().path() {
                "/auth/totp/setup" => Some("GET, HEAD"),
                "/auth/totp/confirm" | "/auth/totp/verify" | "/auth/totp/enroll/setup" |
                "/auth/totp/enroll/confirm" | "/auth/totp/remove/begin" | "/auth/totp/remove" => Some("POST"),
                _ => None,
            };
            let text = if allow.is_some() { "Method Not Allowed\n" } else { "404 page not found\n" };
            let mut reply = Response::builder().status(if allow.is_some(){405}else{404})
                .header("content-type","text/plain; charset=utf-8").header("x-content-type-options","nosniff");
            if let Some(allow)=allow {reply=reply.header("allow",allow);}
            if req.method()==Method::HEAD {reply=reply.header("content-length",text.len());}
            return reply.body(body(if req.method()==Method::HEAD{""}else{text})).unwrap();
        }
        if req.uri().path() == "/auth/guest-invite/accept" {
            return self.guest_invite(req).await;
        }
        let head = req.method() == Method::HEAD;
        let path = req.uri().path().to_owned();
        if matches!(req.method(), &Method::GET | &Method::HEAD)
            && matches!(path.as_str(), "/auth/me" | "/auth/session/token")
        {
            return self.session_route(req).await;
        }
        // Frozen gateway alias is forwarded unchanged to an unregistered Go path.
        if req.method() == Method::POST && path == "/auth/change-password" {
            return Self::not_found();
        }
        if req.method() == Method::POST && path == "/auth/forgot-password/reset" {
            return self.reset_password(req).await;
        }
        if req.method() == Method::POST && path == "/auth/refresh" {
            return self.refresh(req).await;
        }
        if req.method() == Method::PUT && path == "/auth/password" {
            return self.session_route(req).await;
        }
        if req.method() == Method::POST && path == "/auth/logout" {
            return self.session_route(req).await;
        }
        if req.method() == Method::POST && path == "/auth/login" {
            return self.login(req).await;
        }
        if matches!(req.method(), &Method::GET | &Method::HEAD) {
            let mut response = match path.as_str() {
                "/api/v1/version" => {
                    let host = req
                        .headers()
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .filter(|s| !s.is_empty())
                        .unwrap_or("localhost");
                    Self::wire_json(
                        200,
                        setjoin_identity::issuance::version(
                            &self.exec,
                            req.uri().query().unwrap_or(""),
                            host,
                        )
                        .await,
                    )
                }
                "/.well-known/setjoin" => {
                    let host = req
                        .headers()
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .filter(|s| !s.is_empty())
                        .unwrap_or("localhost");
                    let mut r = Self::json(
                        200,
                        json!({"version":"2.5.0","jmap_session":format!("https://{host}/jmap/session"),"client_version":format!("https://{host}/api/v1/version"),"clients_base":format!("https://{host}/clients")}),
                    );
                    r.headers_mut().insert(
                        "cache-control",
                        hyper::header::HeaderValue::from_static("no-store"),
                    );
                    r
                }
                "/.well-known/jwks.json" => match &self.keys {
                    Some(keys) => Response::builder()
                        .header("content-type", "application/json")
                        .header("cache-control", "public, max-age=300")
                        .body(body(keys.jwks_json()))
                        .unwrap(),
                    None => Self::failure(503, "signing keys unavailable", &path),
                },
                "/auth/password-policy" if head => Self::failure(405, "Method not allowed", &path),
                "/auth/password-policy" => {
                    match setjoin_identity::password_policy(&self.exec).await {
                        Ok(p) => {
                            let mut r = Self::json(200, p);
                            r.headers_mut().insert(
                                "cache-control",
                                hyper::header::HeaderValue::from_static("no-store"),
                            );
                            r
                        }
                        Err(_) => Self::failure(
                            500,
                            "An internal error occurred. Please try again.",
                            &path,
                        ),
                    }
                }
                "/health" => Response::builder()
                    .header("content-type", "application/json")
                    .body(body(r#"{"status":"ok"}"#))
                    .unwrap(),
                "/ready" => match self.exec.read("SELECT 1", &[]).await {
                    Ok(_) => Response::new(body("")),
                    Err(_) => Response::builder()
                        .status(503)
                        .header("content-type", "text/plain; charset=utf-8")
                        .header("x-content-type-options", "nosniff")
                        .body(body("not ready\n"))
                        .unwrap(),
                },
                _ => return self.forward(req).await,
            };
            if head {
                if let Some(length) = response.body().size_hint().exact().filter(|n| *n > 0) {
                    response
                        .headers_mut()
                        .insert("content-length", length.to_string().parse().unwrap());
                }
                *response.body_mut() = body("");
            }
            return response;
        }
        if req.uri().path().starts_with("/.well-known/"){return if self.config.oidc_enabled{self.oidc_cors(&req,Self::not_found())}else{Self::not_found()};}
        self.forward(req).await
    }
    fn not_found() -> Response<Body> {
        Response::builder()
            .status(404)
            .header("content-type", "text/plain; charset=utf-8")
            .header("x-content-type-options", "nosniff")
            .body(body("404 page not found\n"))
            .unwrap()
    }
    fn json_no_store(status: u16, value: Value) -> Response<Body> {
        let mut r = Self::json(status, value);
        r.headers_mut().insert(
            "cache-control",
            hyper::header::HeaderValue::from_static("no-store"),
        );
        r
    }
    async fn reset_password(&self, req: Request<Body>) -> Response<Body> {
        if !self.forgot_password {
            return Self::not_found();
        }
        if self.config.threat_controls.iter().any(|v| *v)
            || !matches!(
                login::enabled(&self.exec, "feature.rate_limit").await,
                Ok(false)
            )
        {
            return self.forward(req).await;
        } // #420 pre-auth interception.
        let (headers, scheme) = Self::csrf_context(&req);
        if !setjoin_authz::csrf::allows(&headers, scheme) {
            return Response::builder()
                .status(403)
                .header("content-type", "application/problem+json")
                .body(body(problem::middleware(
                    403,
                    "csrf_failed",
                    "CSRF validation failed",
                )))
                .unwrap();
        }
        let raw = match Limited::new(req.into_body(), body_cap()).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return Self::json_no_store(400, json!({"error":"invalid JSON"})),
        };
        let input = match ingress::fields(&raw, &["email", "reset_token", "new_password"]) {
            Ok(v) => v,
            Err(_) => return Self::json_no_store(400, json!({"error":"invalid JSON"})),
        };
        let email = input.get("email").map_or("", String::as_str);
        let token = input.get("reset_token").map_or("", String::as_str);
        let password = input.get("new_password").map_or("", String::as_str);
        if email.is_empty() || token.is_empty() || password.is_empty() {
            return Self::json_no_store(
                400,
                json!({"error":"email, reset_token, and new_password are required"}),
            );
        }
        let legacy = setjoin_authz::legacy_jwt::LegacyKeys::from_pem(
            self.config.secret.as_bytes(),
            &["authserver-hmac-1"],
            self.config.sm2_pem.as_deref(),
        )
        .ok();
        let Some(proof) = legacy
            .as_ref()
            .and_then(|k| {
                setjoin_identity::session::Session::verify(
                    token,
                    self.keys.as_deref(),
                    k,
                    &self.config.issuer,
                )
            })
            .filter(|s| {
                s.text("typ") == "password_reset"
                    && setjoin_authz::address::equal_fold(s.text("email"), email)
            })
        else {
            return Self::json_no_store(401, json!({"error":"invalid or expired reset token"}));
        };
        let op = uuid::Uuid::new_v4();
        match setjoin_identity::password::reset(
            &self.exec,
            &proof,
            password,
            self.config.profile,
            setjoin_contracts::ids::OperationId(*op.as_bytes()),
        )
        .await
        {
            Ok(()) => Self::json_no_store(
                200,
                json!({"message":"Password has been reset. You may now sign in with your new password."}),
            ),
            Err(setjoin_identity::password::Failure::Reply(status, detail)) => {
                Self::json_no_store(status, json!({"error":detail}))
            }
            Err(setjoin_identity::password::Failure::Unknown(_)) => {
                let mut r = Self::json_no_store(500, json!({"error":"internal error"}));
                r.headers_mut()
                    .insert("x-operation-id", op.to_string().parse().unwrap());
                r
            }
        }
    }
    async fn refresh(&self, req: Request<Body>) -> Response<Body> {
        use setjoin_pg::CommandOutcome;
        use sha2::{Digest, Sha256};
        let rate = login::enabled(&self.exec, "feature.rate_limit").await;
        if self.config.threat_controls.iter().any(|v| *v) || !matches!(rate, Ok(false)) {
            return self.forward(req).await;
        } // #420
        let path = req.uri().path().to_owned();
        let (headers, scheme) = Self::csrf_context(&req);
        if !setjoin_authz::csrf::allows(&headers, scheme) {
            return Response::builder()
                .status(403)
                .header("content-type", "application/problem+json")
                .body(body(problem::middleware(
                    403,
                    "csrf_failed",
                    "CSRF validation failed",
                )))
                .unwrap();
        }
        let raw = match Limited::new(req.into_body(), body_cap()).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return Self::failure(400, "invalid JSON", &path),
        };
        let input = match ingress::fields(&raw, &["refresh_token"]) {
            Ok(v) => v,
            Err(_) => return Self::failure(400, "invalid JSON", &path),
        };
        let token = input.get("refresh_token").map_or("", String::as_str);
        let legacy = setjoin_authz::legacy_jwt::LegacyKeys::from_pem(
            self.config.secret.as_bytes(),
            &["authserver-hmac-1"],
            self.config.sm2_pem.as_deref(),
        )
        .ok();
        let Some(session) = legacy
            .as_ref()
            .and_then(|legacy| {
                setjoin_identity::session::Session::verify(
                    token,
                    self.keys.as_deref(),
                    legacy,
                    &self.config.issuer,
                )
            })
            .filter(|s| s.text("typ") == "refresh")
        else {
            return Self::failure(401, "invalid or revoked refresh token", &path);
        };
        let hash = Sha256::digest(token.as_bytes()).to_vec();
        let operation = uuid::Uuid::new_v4();
        let op = setjoin_contracts::ids::OperationId(*operation.as_bytes());
        for _ in 0..8 {
            let context = match session
                .refresh(
                    &self.exec,
                    &hash,
                    None,
                    None,
                    self.config.refresh_seconds,
                    &operation.to_string(),
                    op,
                )
                .await
            {
                CommandOutcome::Committed(c) if c["status"] == "mint" => c,
                CommandOutcome::Unknown { .. } => {
                    let mut r = Self::failure(401, "invalid or revoked refresh token", &path);
                    r.headers_mut()
                        .insert("x-operation-id", operation.to_string().parse().unwrap());
                    return r;
                }
                _ => return Self::failure(401, "invalid or revoked refresh token", &path),
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let family = context["family"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let mut claims = json!({"uid":session.user(),"email":context["email"],"typ":"refresh","fam":family,"iss":self.config.issuer,"sub":session.user().to_string(),"aud":["mailserver-gateway"],"nbf":now,"iat":now,"exp":now+self.config.refresh_seconds});
            for key in ["cnf", "device", "sif", "auth_time"] {
                if let Some(value) = session.claims().get(key).filter(|v| !v.is_null()) {
                    claims[key] = value.clone();
                }
            }
            if !claims["sif"].is_null() && claims["auth_time"].is_null() {
                claims["auth_time"] = json!(now);
            }
            let (Ok(refresh_jti), Ok(access_jti)) = (login::random_jti(), login::random_jti())
            else {
                return Self::failure(401, "invalid or revoked refresh token", &path);
            };
            claims["jti"] = json!(refresh_jti);
            let refresh = match self.sign(&claims) {
                Ok(t) => t,
                Err(_) => return Self::failure(401, "invalid or revoked refresh token", &path),
            };
            claims["jti"] = json!(access_jti);
            claims["typ"] = json!("access");
            claims["exp"] = json!(now + self.config.access_seconds);
            if context["admin"] == true {
                claims["admin"] = json!(true);
            }
            if context["guest"] == true {
                claims["acct"] = json!("guest");
            }
            if let Some(risk) = session.risk(&self.exec).await {
                claims["risk"] = risk;
            }
            let access = match self.sign(&claims) {
                Ok(t) => t,
                Err(_) => return Self::failure(401, "invalid or revoked refresh token", &path),
            };
            let new_hash = Sha256::digest(refresh.as_bytes()).to_vec();
            match session
                .refresh(
                    &self.exec,
                    &hash,
                    Some(&context),
                    Some(&new_hash),
                    self.config.refresh_seconds,
                    &family,
                    op,
                )
                .await
            {
                CommandOutcome::Committed(c) if c["status"] == "retry" => continue,
                CommandOutcome::Committed(c) if c["status"] == "mint" => {
                    return Self::json(
                        200,
                        json!({"access_token":access,"refresh_token":refresh,"expires_in":self.config.access_seconds}),
                    );
                }
                CommandOutcome::Unknown { .. } => {
                    let mut r = Self::failure(401, "invalid or revoked refresh token", &path);
                    r.headers_mut()
                        .insert("x-operation-id", operation.to_string().parse().unwrap());
                    return r;
                }
                _ => return Self::failure(401, "invalid or revoked refresh token", &path),
            }
        }
        Self::failure(401, "invalid or revoked refresh token", &path)
    }
    fn presented_access_token(headers: &hyper::HeaderMap) -> Option<String> {
        if let Some(token) = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .filter(|s| !s.is_empty())
        {
            return Some(token.to_owned());
        }
        for header in headers
            .get_all("cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
        {
            for part in header.split(';') {
                // Go accepts a bare cookie name as an empty value. The first
                // valid access cookie wins, including an empty one.
                if part.trim() == "access_token" {
                    return None;
                }
                let part = part.trim();
                let Some((name, raw_value)) = part.split_once('=') else {
                    continue;
                };
                if name.trim() != "access_token" {
                    continue;
                }
                let Ok(mut cookie) = cookie::Cookie::parse(part) else {
                    continue;
                };
                // net/http trims the name and whole field, preserving value whitespace.
                cookie.set_value(raw_value);
                let value = cookie.value_trimmed();
                if cookie.name() != "access_token"
                    || !value
                        .bytes()
                        .all(|b| (0x20..0x7f).contains(&b) && !matches!(b, b'"' | b';' | b'\\'))
                {
                    continue;
                }
                return (!value.is_empty()).then(|| value.to_owned());
            }
        }
        None
    }
    async fn session_route(&self, req: Request<Body>) -> Response<Body> {
        let recovery = req.uri().path() == "/auth/session/token";
        let presented = Self::presented_access_token(req.headers());
        let legacy = setjoin_authz::legacy_jwt::LegacyKeys::from_pem(
            self.config.secret.as_bytes(),
            &["authserver-hmac-1"],
            self.config.sm2_pem.as_deref(),
        )
        .ok();
        let session = presented.as_deref().and_then(|t| {
            setjoin_identity::session::Session::verify(
                t,
                self.keys.as_deref(),
                legacy.as_ref()?,
                &self.config.issuer,
            )
        });
        let Some(session) = session else {
            let mut r = Self::failure(401, "Unauthorized", "");
            if !recovery {
                r.headers_mut().insert(
                    "www-authenticate",
                    hyper::header::HeaderValue::from_static("Bearer realm=\"authserver\""),
                );
            }
            return r;
        };
        if session.text("typ") != "access" {
            return Self::failure(403, "Invalid token type", "");
        }
        if self.revocations.contains(&session) {
            let mut r = Self::failure(401, "Unauthorized", "");
            if !recovery {
                r.headers_mut().insert(
                    "www-authenticate",
                    hyper::header::HeaderValue::from_static("Bearer realm=\"authserver\""),
                );
            }
            return r;
        }
        if session.bound() {
            return self.forward(req).await;
        } // #405 owns DPoP admission.
        let path = req.uri().path();
        if req.method() == Method::PUT && path == "/auth/password" {
            let (headers, scheme) = Self::csrf_context(&req);
            if !setjoin_authz::csrf::allows(&headers, scheme) {
                return Response::builder()
                    .status(403)
                    .header("content-type", "application/problem+json")
                    .body(body(problem::middleware(
                        403,
                        "csrf_failed",
                        "CSRF validation failed",
                    )))
                    .unwrap();
            }
            // Frozen authserver warms only its local connector. Its post-commit
            // AD write-back cache is empty, including for AD-marked users (#337).
            let path = path.to_owned();
            let raw = match Limited::new(req.into_body(), body_cap()).collect().await {
                Ok(b) => b.to_bytes(),
                Err(_) => return Self::failure(400, "invalid JSON", &path),
            };
            let input = match ingress::fields(&raw, &["old_password", "new_password"]) {
                Ok(v) => v,
                Err(_) => return Self::failure(400, "invalid JSON", &path),
            };
            let old = input.get("old_password").map_or("", String::as_str);
            let new = input.get("new_password").map_or("", String::as_str);
            let op = uuid::Uuid::new_v4();
            return match setjoin_identity::password::change(
                &self.exec,
                &session,
                old,
                new,
                self.config.profile,
                setjoin_contracts::ids::OperationId(*op.as_bytes()),
            )
            .await
            {
                Ok(()) => Response::builder().status(204).body(body("")).unwrap(),
                Err(setjoin_identity::password::Failure::Reply(status, detail)) => {
                    Self::failure(status, &detail, &path)
                }
                Err(setjoin_identity::password::Failure::Unknown(_)) => {
                    let mut r = Self::failure(500, "internal error", &path);
                    r.headers_mut()
                        .insert("x-operation-id", op.to_string().parse().unwrap());
                    r
                }
            };
        }
        if req.method() == Method::POST && path == "/auth/logout" {
            let (headers, scheme) = Self::csrf_context(&req);
            if !setjoin_authz::csrf::allows(&headers, scheme) {
                return Response::builder()
                    .status(403)
                    .header("content-type", "application/problem+json")
                    .body(body(problem::middleware(
                        403,
                        "csrf_failed",
                        "CSRF validation failed",
                    )))
                    .unwrap();
            }
            let op = uuid::Uuid::new_v4();
            let result = session
                .revoke(
                    &self.exec,
                    setjoin_contracts::ids::OperationId(*op.as_bytes()),
                )
                .await;
            return match result {
                setjoin_pg::CommandOutcome::Committed(_) => {
                    Response::builder().status(204).body(body("")).unwrap()
                }
                setjoin_pg::CommandOutcome::Unknown { .. } => {
                    let mut r = Self::failure(503, "session revocation failed", path);
                    r.headers_mut()
                        .insert("x-operation-id", op.to_string().parse().unwrap());
                    r
                }
                _ => Self::failure(503, "session revocation failed", path),
            };
        }
        let mut response = if recovery {
            Self::json(200, json!({"access_token":presented.unwrap()}))
        } else {
            match session.me(&self.exec).await {
                Ok(v) => Self::json(200, v),
                Err(e) => Self::failure(503, e, path),
            }
        };
        if req.method() == Method::HEAD {
            let length = response.body().size_hint().exact().unwrap_or(0);
            response
                .headers_mut()
                .insert("content-length", length.to_string().parse().unwrap());
            *response.body_mut() = body("");
        }
        response
    }
    fn sign(&self, claims: &Value) -> Result<String, String> {
        let text = claims.to_string();
        if self.config.signing_alg == "ES256" {
            return self
                .keys
                .as_ref()
                .ok_or("signing keys unavailable")?
                .sign(&text);
        }
        if self.config.profile == setjoin_config_secret::CryptoProfile::Smx {
            if let Some(pem) = &self.config.sm2_pem {
                return setjoin_authz::legacy_jwt::sign_sm2(pem, &text).map_err(str::to_owned);
            }
        }
        Ok(setjoin_authz::legacy_jwt::sign_hs256(
            self.config.secret.as_bytes(),
            &text,
        ))
    }
    // shared/middleware/csrf.go: malformed proxy values fall back to the
    // actual connection/Host, including a direct TLS deployment.
    fn csrf_context(req: &Request<Body>) -> (hyper::HeaderMap, &'static str) {
        let mut headers = req.headers().clone();
        if let Some(host) = req.headers().get("x-forwarded-host").filter(|v| {
            let b = v.as_bytes();
            !b.is_empty()
                && b.len() <= 255
                && b.iter().all(|c| {
                    c.is_ascii_alphanumeric()
                        || matches!(c, b'.' | b'-' | b'_' | b':' | b'[' | b']')
                })
        }) {
            headers.insert("host", host.clone());
        }
        let proto = req
            .headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .map(str::trim);
        let scheme = match proto {
            Some(p) if p.eq_ignore_ascii_case("http") => "http",
            Some(p) if p.eq_ignore_ascii_case("https") => "https",
            _ if req
                .extensions()
                .get::<ConnectionMeta>()
                .is_some_and(|m| m.tls) =>
            {
                "https"
            }
            _ => "http",
        };
        (headers, scheme)
    }
    async fn login(&self, req: Request<Body>) -> Response<Body> {
        // Device proof consumes replay state in #420 even when CA permits the
        // request. Preserve its original body for that owner's verification.
        if [
            "x-device-id",
            "x-device-hmac",
            "x-device-timestamp",
            "x-device-nonce",
            "x-device-body-sha256",
        ]
        .iter()
        .any(|h| req.headers().contains_key(*h))
        {
            return self.forward(req).await;
        }
        if self.http_threat_pending().await {
            return self.forward(req).await;
        }
        let path = req.uri().path().to_owned();
        let (csrf_headers, scheme) = Self::csrf_context(&req);
        if !setjoin_authz::csrf::allows(&csrf_headers, scheme) {
            return Response::builder()
                .status(403)
                .header("content-type", "application/problem+json")
                .body(body(problem::middleware(
                    403,
                    "csrf_failed",
                    "CSRF validation failed",
                )))
                .unwrap();
        }
        let meta = req.extensions().get::<ConnectionMeta>();
        let trusted = meta.is_some_and(|m| {
            m.peer.ip().is_loopback()
                || self
                    .config
                    .trusted_proxies
                    .iter()
                    .any(|n| n.contains(&m.peer.ip()))
        });
        let secure = self.config.cookie_secure
            || meta.is_some_and(|m| m.tls)
            || ((self.config.trust_proxy || trusted) && scheme == "https");
        let ip = self.client_ip(&req).to_string();
        let agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let (parts, b) = req.into_parts();
        let raw = match Limited::new(b, 1 << 20).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return Self::failure(400, "invalid JSON", &path),
        };
        let decode = ingress::go_decode_bytes(&raw);
        let mut stream = serde_json::Deserializer::from_slice(&decode);
        let input = match ingress::Login::deserialize(&mut stream) {
            Ok(v) => v,
            Err(_) => return Self::failure(400, "invalid JSON", &path),
        };
        if self.config.secret.is_empty() {
            return Self::failure(503, "signing keys unavailable", &path);
        }
        let proof = match login::verify(&self.exec, &input.email, &input.password, self.config.profile).await {
            Ok(Some(p)) => p,
            _ => {
                login::record_failure(&self.exec, &input.email, &ip).await;
                return Self::failure(401, "invalid credentials", &path);
            }
        };
        // Go resolves guest CA context even when CA policies are disabled.
        // Lookup failure must precede force-password/MFA token minting.
        // Go populateGuestCAScope (auth.go:2499): the value only feeds CA, which
        // forwards whole before any effect while on (#351). Guests continue
        // natively (#353); a lookup failure is Go's 503 before any token.
        if login::guest_scope(&self.exec, &proof).await.is_err() {
            return Self::failure(503, "conditional access context unavailable", &path);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if proof.force_change {
            let claims = login::claims(
                &proof,
                "force_pw_change",
                "",
                "",
                &self.config.issuer,
                now,
                300,
                None,
            );
            return match self.sign(&claims) {
                Ok(token) => Self::json(
                    403,
                    json!({"status":"force_password_change","force_password_change":true,"force_token":token,"reason":"Administrator requires a password change before access is granted."}),
                ),
                Err(_) => Self::failure(500, "token issue failed", &path),
            };
        }
        match login::mfa_policy(&self.exec,&proof).await {
            Ok(policy)=>{
                if policy["status"]=="enrollment_required"{return self.totp_login_challenge(&proof,Some(&policy),&path).await;}
                if proof.push{return self.push_login_challenge(&proof,&path).await;}
                if proof.totp{return self.totp_login_challenge(&proof,None,&path).await;}
            },
            Err(_)=>return Self::failure(503,"MFA policy verification unavailable. Please try again.",&path)
        }
        let domain = match login::domain_scope(&self.exec, &proof).await {
            Ok(d) => d,
            Err(_) => return Self::failure(500, "authorization scope resolution failed", &path),
        };
        let guest = match login::admission(&self.exec, &proof).await {
            Ok((true, guest)) => guest,
            Ok((false, _)) => return Response::builder().status(409).header("cache-control","no-store").header("content-type","application/problem+json").body(body(problem::Problem::new(409,"Sign-in is temporarily fenced while identity transition security effects converge.").kind("https://setjoin.com/errors/conflict").instance(&path).body())).unwrap(),
            Err(login::AdmissionFailure::AccountType(_)) => {
                return Self::failure(500, "account type resolution failed", &path)
            }
            Err(_) => {
                return Self::failure(500, "identity transition admission resolution failed", &path)
            }
        };
        if input.dpop.as_object().is_some_and(|v| !v.is_empty())
            && !matches!(
                login::enabled(&self.exec, "feature.token_binding").await,
                Ok(false)
            )
        {
            return self.forward(Request::from_parts(parts, body(raw))).await;
        }
        let family = uuid::Uuid::new_v4().to_string();
        let (jti, refresh_jti) = match (login::random_jti(), login::random_jti()) {
            (Ok(a), Ok(r)) => (a, r),
            _ => return Self::failure(500, "token issue failed", &path),
        };
        let mut access_claims = login::claims(
            &proof,
            "access",
            &jti,
            &family,
            &self.config.issuer,
            now,
            self.config.access_seconds,
            domain,
        );
        if let Some(risk) = login::risk(&self.exec, &proof).await {
            access_claims["risk"] = risk;
        }
        // Go IssueInput.AccountType (auth.go:2005-2012): the access token only.
        if guest {
            access_claims["acct"] = Value::from("guest");
        }
        let refresh_claims = login::claims(
            &proof,
            "refresh",
            &refresh_jti,
            &family,
            &self.config.issuer,
            now,
            self.config.refresh_seconds,
            None,
        );
        let (access, refresh) = match (self.sign(&access_claims), self.sign(&refresh_claims)) {
            (Ok(a), Ok(r)) => (a, r),
            _ => return Self::failure(500, "token issue failed", &path),
        };
        match login::mint(
            &self.exec,
            &proof,
            &refresh,
            self.config.refresh_seconds,
            &family,
        )
        .await
        {
            setjoin_pg::CommandOutcome::Committed(true) => {}
            setjoin_pg::CommandOutcome::Committed(false) => {
                return Self::failure(
                    401,
                    "Credentials changed during sign-in. Please authenticate again.",
                    &path,
                )
            }
            setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(error))
                if error.sqlstate.as_deref() == Some("BZ235") =>
            {
                let hint: Value = error
                    .hint
                    .as_deref()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(Value::Null);
                let remediation = hint["remediation"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("Refresh current state, resolve the conflict, and retry.");
                return Response::builder()
                    .status(409)
                    .header("content-type", "application/problem+json")
                    .header("cache-control", "no-store")
                    .body(body(
                        problem::Problem::new(409, "conflict")
                            .kind("https://setjoin.com/problems/reducer/bz235")
                            .instance(&path)
                            .remediation(remediation)
                            .code("BZ235")
                            .retryable(false)
                            .body(),
                    ))
                    .unwrap();
            }
            setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable) => {
                return Self::failure(503, "identity mint fence unavailable", &path)
            }
            setjoin_pg::CommandOutcome::RolledBack(_) => {
                return Self::failure(500, "An internal error occurred. Please try again.", &path)
            }
            setjoin_pg::CommandOutcome::Unknown { .. } => {
                let mut response = Self::failure(
                    503,
                    "Token issuance outcome unavailable. Look up the operation before retrying.",
                    &path,
                );
                response
                    .headers_mut()
                    .insert("x-operation-id", family.parse().unwrap());
                return response;
            }
        }
        login::record_success(
            &self.exec,
            &proof,
            &access,
            &jti,
            self.config.access_seconds,
            &ip,
            &agent,
        )
        .await;
        let mut response = Self::json(
            200,
            json!({"access_token":access,"refresh_token":refresh,"expires_in":self.config.access_seconds}),
        );
        response.headers_mut().insert(
            "set-cookie",
            format!(
                "access_token={access}; Path=/; Max-Age={}; HttpOnly;{} SameSite=Strict",
                self.config.access_seconds,
                if secure { " Secure;" } else { "" }
            )
            .parse()
            .unwrap(),
        );
        response
    }
}

#[derive(Clone, Copy)]
pub struct ConnectionMeta {
    pub peer: std::net::SocketAddr,
    pub tls: bool,
}

/// Binds one process-local listener, drains connections on shutdown, and owns
/// every connection task. No direct DB connection is repurposed for requests.
pub async fn serve_until(
    server: Arc<AuthServer>,
    listener: tokio::net::TcpListener,
    tls: Option<tokio_rustls::TlsAcceptor>,
    shutdown: impl std::future::Future<Output = ()>,
) {
    let mut tasks = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _=&mut shutdown=>break,
            accepted=listener.accept()=>{
                let Ok((stream,peer))=accepted else{break;};let server=server.clone();let tls=tls.clone();
                tasks.spawn(async move{
                    let meta=ConnectionMeta{peer,tls:tls.is_some()};
                    let stream:Box<dyn Io>=if let Some(tls)=tls{match tokio::time::timeout(std::time::Duration::from_secs(30),tls.accept(stream)).await{Ok(Ok(s))=>Box::new(s),_=>return}}else{Box::new(stream)};
                    let service=hyper::service::service_fn(move|mut req:Request<hyper::body::Incoming>|{
                        let server=server.clone();req.extensions_mut().insert(meta);
                        Box::pin(async move{Ok::<_,std::convert::Infallible>(server.handle(req.map(|b|b.map_err(std::io::Error::other).boxed())).await)}) as std::pin::Pin<Box<dyn std::future::Future<Output=Result<Response<Body>,std::convert::Infallible>>+Send>>
                    });
                    let builder=hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
                    let _=builder.serve_connection(hyper_util::rt::TokioIo::new(stream),service).await;
                });
            },
            _=tasks.join_next(),if !tasks.is_empty()=>{},
        }
    }
    drop(listener);
    // Go bounds shutdown at 30 seconds. Abort/drop every task after draining.
    let drain = async { while tasks.join_next().await.is_some() {} };
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), drain).await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}
trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}
