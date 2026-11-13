//! #334 TOTP HTTP adapter. The verified token alone selects the owner.
use super::*;
use setjoin_identity::{session::Session, totp};
pub(super) enum Admission {
    Denied(Response<Body>),
    Forward,
}
impl AuthServer {
    pub(super) fn totp_session(&self, req: &Request<Body>) -> Result<Session, Admission> {
        let deny = |status, detail| {
            let mut r = Self::failure(status, detail, "");
            if status == 401 {
                r.headers_mut().insert(
                    "www-authenticate",
                    "Bearer realm=\"authserver\"".parse().unwrap(),
                );
            }
            Admission::Denied(r)
        };
        let token =
            Self::presented_access_token(req.headers()).ok_or_else(|| deny(401, "Unauthorized"))?;
        let legacy = self
            .legacy
            .as_ref()
            .ok_or_else(|| deny(401, "Unauthorized"))?;
        let session = Session::verify(&token, self.keys.as_deref(), legacy, &self.config.issuer)
            .ok_or_else(|| deny(401, "Unauthorized"))?;
        if session.text("typ") != "access" {
            return Err(deny(403, "Invalid token type"));
        }
        if self.revocations.contains(&session) {
            return Err(deny(401, "Unauthorized"));
        }
        if session.bound() {
            return Err(Admission::Forward);
        }
        Ok(session)
    }
    pub(super) async fn totp_remove(&self, req: Request<Body>) -> Response<Body> {
        let session = match self.totp_session(&req) {
            Ok(s) => s,
            Err(Admission::Denied(r)) => return r,
            Err(Admission::Forward) => return self.forward(req).await,
        };
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
        if session.claims().get("act").is_some_and(|v| !v.is_null()) {
            return Self::totp_problem(
                403,
                "impersonated sessions may not manage authentication factors",
                Some("impersonation_forbidden"),
                &path,
            );
        }
        let ip = self.client_ip(&req).to_string();
        let raw = Limited::new(req.into_body(), body_cap()).collect().await;
        let fields = raw
            .ok()
            .and_then(|b| ingress::fields(&b.to_bytes(), &["step_up_token", "confirm"]).ok());
        let Some(fields) = fields else {
            totp::audit(
                &self.exec,
                &session,
                &ip,
                "totp_removal_refused",
                "malformed body",
            )
            .await;
            return Self::failure(400, "invalid JSON", &path);
        };
        if fields.get("confirm").map(String::as_str) != Some("REMOVE") {
            totp::audit(
                &self.exec,
                &session,
                &ip,
                "totp_removal_refused",
                "confirmation mismatch",
            )
            .await;
            return Self::failure(400, "type REMOVE to confirm authenticator removal", &path);
        }
        let token = fields.get("step_up_token").map_or("", String::as_str);
        let result = if token.is_empty() {
            setjoin_pg::CommandOutcome::Committed("invalid".to_owned())
        } else {
            totp::remove(&self.exec, &session, token, &ip).await
        };
        match result {
            setjoin_pg::CommandOutcome::Committed(s) if s == "removed" => {
                Response::builder().status(204).body(body("")).unwrap()
            }
            setjoin_pg::CommandOutcome::Committed(s) => {
                let (status, detail, notes) = if s == "not_enabled" {
                    (409, "TOTP is not enabled", "totp not enabled")
                } else {
                    (
                        403,
                        "step-up token invalid or expired",
                        "step-up token invalid, expired, or replayed",
                    )
                };
                totp::audit(&self.exec, &session, &ip, "totp_removal_refused", notes).await;
                Self::failure(status, detail, &path)
            }
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(
                    503,
                    "TOTP removal outcome unavailable. Inspect the operation before retrying.",
                    &path,
                );
                r.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                r
            }
            _ => Self::failure(500, "totp removal failed", &path),
        }
    }
    fn totp_problem(status: u16, detail: &str, code: Option<&str>, path: &str) -> Response<Body> {
        let mut p = problem::Problem::new(status, detail).instance(path);
        if let Some(c) = code {
            p = p.code(c);
        }
        Response::builder()
            .status(status)
            .header("content-type", "application/problem+json")
            .header("cache-control", "no-store")
            .body(body(p.body()))
            .unwrap()
    }
}

impl AuthServer {
    pub(super) async fn totp_begin(&self, req: Request<Body>) -> Response<Body> {
        let session = match self.totp_session(&req) {
            Ok(s) => s,
            Err(Admission::Denied(r)) => return r,
            Err(Admission::Forward) => return self.forward(req).await,
        };
        let path = req.uri().path().to_owned();
        let ip = self.client_ip(&req).to_string();
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
        if session.claims().get("act").is_some_and(|v| !v.is_null()) {
            return Self::totp_problem(
                403,
                "impersonated sessions may not manage authentication factors",
                Some("impersonation_forbidden"),
                &path,
            );
        }
        let raw = Limited::new(req.into_body(), body_cap()).collect().await;
        let fields = raw
            .ok()
            .and_then(|b| ingress::fields(&b.to_bytes(), &["password", "code"]).ok());
        let Some(fields) = fields else {
            totp::audit(
                &self.exec,
                &session,
                &ip,
                "totp_removal_step_up_refused",
                "malformed body",
            )
            .await;
            return Self::failure(400, "invalid JSON", &path);
        };
        let password = fields.get("password").map_or("", String::as_str);
        let code = fields.get("code").map_or("", String::as_str);
        if password.is_empty() || code.is_empty() {
            totp::audit(
                &self.exec,
                &session,
                &ip,
                "totp_removal_step_up_refused",
                "missing password or code",
            )
            .await;
            return Self::failure(400, "password and code are required", &path);
        }
        match totp::begin(&self.exec, &session, password, code).await {
            Ok(token) => {
                totp::audit(
                    &self.exec,
                    &session,
                    &ip,
                    "totp_removal_step_up_authorized",
                    "",
                )
                .await;
                Self::json(200, json!({"expires_in":300,"step_up_token":token}))
            }
            Err(totp::Failure::Reply(status, detail, notes)) => {
                if let Some(notes) = notes {
                    totp::audit(
                        &self.exec,
                        &session,
                        &ip,
                        "totp_removal_step_up_refused",
                        notes,
                    )
                    .await;
                }
                Self::failure(status, detail, &path)
            }
            Err(totp::Failure::Unknown(operation)) => {
                let mut r = Self::failure(
                    503,
                    "TOTP step-up outcome unavailable. Inspect the operation before retrying.",
                    &path,
                );
                r.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                r
            }
        }
    }
}

impl AuthServer {
    /// Frozen threat middleware bounds the complete body before auth/CSRF,
    /// even when disabled policy controls let this shape run natively.
    pub(super) async fn totp_ingress(
        &self,
        req: Request<Body>,
    ) -> Result<Request<Body>, Response<Body>> {
        if self.totp_threat_pending().await {
            return Err(self.forward(req).await);
        }
        let (parts, input) = req.into_parts();
        match Limited::new(input,1<<20).collect().await {
            Ok(raw)=>Ok(Request::from_parts(parts,body(raw.to_bytes()))),
            Err(error) if error.is::<http_body_util::LengthLimitError>()=>Err(Self::totp_body_too_large()),
            Err(_)=>Err(Response::builder().status(400).header("content-type","application/json")
                .header("x-threat-reason","invalid_body").body(body("{\"captcha_prompt\":\"request body could not be read\",\"error\":\"invalid_body\"}\n")).unwrap()),
        }
    }
    pub(super) async fn totp_threat_pending(&self) -> bool {
        self.config.threat_controls.iter().any(|v| *v)
            || !matches!(
                login::enabled(&self.exec, "feature.rate_limit").await,
                Ok(false)
            )
    }
    pub(super) fn totp_reauth(path: &str) -> Response<Body> {
        Response::builder().status(403).header("content-type","application/problem+json").header("cache-control","no-store")
            .body(body(problem::Problem::new(403,"prove possession at /auth/mfa/reauth (or the possession endpoints for C1 accounts) and retry with the issued reauth_token")
                .kind("https://setjoin.com/errors/reauth-required").title("Re-authentication required").instance(path).remediation("reauth").code("reauth_required").body())).unwrap()
    }
    pub(super) async fn totp_setup(&self, req: Request<Body>) -> Response<Body> {
        if self.totp_threat_pending().await {
            return self.forward(req).await;
        } // #420 pre-auth threat/rate owner.
        let session = match self.totp_session(&req) {
            Ok(s) => s,
            Err(Admission::Denied(r)) => return r,
            Err(Admission::Forward) => return self.forward(req).await,
        };
        let path = req.uri().path().to_owned();
        let ip = self.client_ip(&req).to_string();
        let head = req.method() == Method::HEAD;
        if session.claims().get("act").is_some_and(|v| !v.is_null()) {
            return Self::totp_problem(
                403,
                "impersonated sessions may not manage authentication factors",
                Some("impersonation_forbidden"),
                &path,
            );
        }
        let mut token = req
            .headers()
            .get("x-mfa-reauth")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        if token.is_empty() {
            if let Ok(raw) = Limited::new(req.into_body(), body_cap()).collect().await {
                if let Ok(v) = ingress::fields(&raw.to_bytes(), &["reauth_token"]) {
                    token = v.get("reauth_token").cloned().unwrap_or_default();
                }
            }
        }
        let result = totp::setup(&self.exec, &session, &token).await;
        let mut response = match result {
            setjoin_pg::CommandOutcome::Committed(v) => match v["status"].as_str() {
                Some("created" | "resume") => {
                    if v["status"] == "created" {
                        totp::audit(&self.exec, &session, &ip, "totp_setup_initiated", "").await;
                    }
                    Self::json(
                        200,
                        json!({"enrollment_id":v["enrollment_id"],"provisioning_uri":totp::provisioning_uri(v["secret"].as_str().unwrap_or(""),session.text("email"),&self.config.issuer)}),
                    )
                }
                Some("reauth") => {
                    totp::audit(
                        &self.exec,
                        &session,
                        &ip,
                        "mfa_reauth_refused",
                        "totp setup without a valid possession proof",
                    )
                    .await;
                    Self::totp_reauth(&path)
                }
                Some("revoked") => Self::totp_reauth(&path),
                Some("bound") => Self::totp_problem(
                    409,
                    "this proof already authorized a different enrollment; present a fresh proof",
                    Some("proof_already_bound"),
                    &path,
                ),
                Some("internal") => Self::failure(500, "internal error", &path),
                _ => Self::failure(500, "totp setup failed", &path),
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(
                    503,
                    "TOTP setup outcome unavailable. Inspect the operation before retrying.",
                    &path,
                );
                r.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                r
            }
            _ => Self::failure(500, "totp setup failed", &path),
        };
        if head {
            if let Some(n) = response.body().size_hint().exact().filter(|n| *n > 0) {
                response
                    .headers_mut()
                    .insert("content-length", n.to_string().parse().unwrap());
            }
            *response.body_mut() = body("");
        }
        response
    }
}

impl AuthServer {
    pub(super) async fn totp_confirm(&self, req: Request<Body>) -> Response<Body> {
        if self.totp_threat_pending().await {
            return self.forward(req).await;
        } // #420.
        let session = match self.totp_session(&req) {
            Ok(s) => s,
            Err(Admission::Denied(r)) => return r,
            Err(Admission::Forward) => return self.forward(req).await,
        };
        let path = req.uri().path().to_owned();
        let ip = self.client_ip(&req).to_string();
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
        if session.claims().get("act").is_some_and(|v| !v.is_null()) {
            return Self::totp_problem(
                403,
                "impersonated sessions may not manage authentication factors",
                Some("impersonation_forbidden"),
                &path,
            );
        }
        let header = req
            .headers()
            .get("x-mfa-reauth")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let fields = match Limited::new(req.into_body(), body_cap())
            .collect()
            .await
            .ok()
            .and_then(|b| {
                ingress::fields(&b.to_bytes(), &["code", "enrollment_id", "reauth_token"]).ok()
            }) {
            Some(v) => v,
            None => return Self::failure(400, "invalid JSON", &path),
        };
        let code = fields.get("code").map_or("", String::as_str);
        let id = fields.get("enrollment_id").map_or("", String::as_str);
        if code.is_empty() || id.is_empty() {
            return Self::failure(400, "code and enrollment_id are required", &path);
        }
        let token = if header.is_empty() {
            fields.get("reauth_token").map_or("", String::as_str)
        } else {
            &header
        };
        match totp::confirm(&self.exec, &session, token, id, code, &ip).await {
            setjoin_pg::CommandOutcome::Committed(v) => match v["status"].as_str() {
                Some("confirmed") => Response::builder().status(204).body(body("")).unwrap(),
                Some("invalid_code") => Self::failure(401, "invalid code", &path),
                Some("reauth_gate") => {
                    totp::audit(
                        &self.exec,
                        &session,
                        &ip,
                        "mfa_reauth_refused",
                        "totp confirm binding without a valid possession proof",
                    )
                    .await;
                    Self::totp_reauth(&path)
                }
                Some("reauth_binding" | "revoked") => Self::totp_reauth(&path),
                Some("proving_factor") => {
                    totp::audit(
                        &self.exec,
                        &session,
                        &ip,
                        "mfa_reauth_refused",
                        "possession proof refused: proving factor no longer live",
                    )
                    .await;
                    Self::totp_reauth(&path)
                }
                Some("state_changed") => {
                    Self::failure(409, "totp state changed; present a fresh proof", &path)
                }
                Some("internal") => Self::failure(500, "internal error", &path),
                _ => Self::failure(500, "totp confirmation failed", &path),
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(
                    503,
                    "TOTP confirmation outcome unavailable. Inspect the operation before retrying.",
                    &path,
                );
                r.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                r
            }
            _ => Self::failure(500, "totp confirmation failed", &path),
        }
    }
}

impl AuthServer {
    fn totp_body_too_large() -> Response<Body> {
        Response::builder().status(413).header("content-type", "application/json").header("x-threat-reason", "body_too_large")
            .body(body("{\"captcha_prompt\":\"request body exceeds the security limit\",\"error\":\"body_too_large\"}\n")).unwrap()
    }
    pub(super) fn totp_pending(&self, token: &str) -> Option<Session> {
        let s = Session::verify(
            token,
            self.keys.as_deref(),
            self.legacy.as_ref()?,
            &self.config.issuer,
        )?;
        if s.text("typ") != "mfa_pending" {
            return None;
        }
        let c = s.claims();
        if c.get("credential_fence")
            .is_some_and(|v| !v.is_null() && !v.is_string())
        {
            return None;
        }
        if c.get("amr").is_some_and(|v| {
            !v.is_null() && !v.as_array().is_some_and(|a| a.iter().all(Value::is_string))
        }) {
            return None;
        }
        if let Some(f) = c.get("identity_fence").filter(|v| !v.is_null()) {
            if !f.is_object() {
                return None;
            }
            for key in [
                "source_id",
                "source_generation",
                "link_id",
                "link_generation",
            ] {
                if f.get(key)
                    .is_some_and(|v| !v.is_null() && v.as_i64().is_none())
                {
                    return None;
                }
            }
        }
        Some(s)
    }
    pub(super) fn totp_identity_changed(v: &Value, path: &str, detail: &str) -> Response<Body> {
        if v["sqlstate"] == "BZ235" {
            let hint: Value = v["hint"]
                .as_str()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(Value::Null);
            let remediation = hint["remediation"]
                .as_str()
                .filter(|s| !s.is_empty())
                .unwrap_or("Refresh current state, resolve the conflict, and retry.");
            Response::builder()
                .status(409)
                .header("content-type", "application/problem+json")
                .header("cache-control", "no-store")
                .body(body(
                    problem::Problem::new(409, "conflict")
                        .kind("https://setjoin.com/problems/reducer/bz235")
                        .instance(path)
                        .remediation(remediation)
                        .code("BZ235")
                        .retryable(false)
                        .body(),
                ))
                .unwrap()
        } else {
            Self::failure(409, detail, path)
        }
    }
    pub(super) async fn totp_bootstrap_setup(&self, req: Request<Body>) -> Response<Body> {
        if self.totp_threat_pending().await {
            return self.forward(req).await;
        } // #420.
        let path = req.uri().path().to_owned();
        let ip = self.client_ip(&req).to_string();
        let fields = match Limited::new(req.into_body(), body_cap())
            .collect()
            .await
            .ok()
            .and_then(|b| ingress::fields(&b.to_bytes(), &["mfa_token"]).ok())
        {
            Some(v) => v,
            None => return Self::failure(400, "invalid JSON", &path),
        };
        let token = fields.get("mfa_token").map_or("", String::as_str);
        let Some(session) = self.totp_pending(token) else {
            return Self::failure(401, "invalid MFA token", &path);
        };
        if session.claims().get("act").is_some_and(|v| !v.is_null()) {
            return Self::totp_problem(
                403,
                "impersonated sessions may not manage authentication factors",
                Some("impersonation_forbidden"),
                &path,
            );
        }
        match totp::bootstrap_setup(&self.exec,&session,token).await {
            setjoin_pg::CommandOutcome::Committed(v)=>match v["status"].as_str(){
                Some("created"|"resume")=>Self::json(200,json!({"enrollment_id":v["enrollment_id"],"provisioning_uri":totp::provisioning_uri(v["secret"].as_str().unwrap_or(""),session.text("email"),&self.config.issuer)})),
                Some("reauth")=>{totp::audit(&self.exec,&session,&ip,"mfa_reauth_refused","bootstrap enrollment setup without a valid possession proof").await;Self::totp_reauth(&path)},
                Some("revoked")=>Self::totp_reauth(&path),
                Some("identity_changed")=>Self::totp_identity_changed(&v,&path,"authentication identity changed before MFA enrollment"),
                Some("credential_changed")=>Self::failure(401,"Credentials changed during sign-in. Please authenticate again.",&path),
                Some("internal")=>Self::failure(500,"internal error",&path),
                Some("state_changed")=>Self::failure(409,"MFA enrollment state changed; sign in again",&path),
                Some("bound")=>Self::totp_problem(409,"this proof already authorized a different enrollment; sign in again for a fresh proof",Some("proof_already_bound"),&path),
                _=>Self::failure(500,"totp setup failed",&path)
            },
            setjoin_pg::CommandOutcome::Unknown{operation}=>{let mut r=Self::failure(503,"TOTP setup outcome unavailable. Inspect the operation before retrying.",&path);r.headers_mut().insert("x-operation-id",uuid::Uuid::from_bytes(operation.0).to_string().parse().unwrap());r},
            setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable)=>Self::failure(503,"identity mint fence unavailable",&path),
            _=>Self::failure(500,"totp setup failed",&path)
        }
    }
}

#[derive(Clone)]
pub(super) struct MfaTokens {
    pub(super) access: String,
    pub(super) refresh: String,
    pub(super) family: String,
    pub(super) jti: String,
    pub(super) factors: Vec<String>,
}
impl AuthServer {
    pub(super) async fn totp_completion_unported(&self, req: &Request<Body>) -> bool {
        if self.totp_threat_pending().await {
            return true;
        }
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
            return true;
        } // #420.
        for key in [
            "feature.conditional_access",
            "feature.device_trust_enforcement",
        ] {
            if !matches!(login::enabled(&self.exec, key).await, Ok(false)) {
                return true;
            } // #405/#420.
        }
        false
    }
    pub(super) async fn totp_guest(&self, session: &Session) -> bool {
        self.exec
            .read(
                "SELECT is_guest_account($1)",
                &[(&session.user(), setjoin_pg::Type::INT8)],
            )
            .await
            .is_ok_and(|r| r[0].get::<_, bool>(0))
    }
    pub(super) fn totp_secure(&self, req: &Request<Body>) -> bool {
        let (_, scheme) = Self::csrf_context(req);
        let meta = req.extensions().get::<ConnectionMeta>();
        let trusted = meta.is_some_and(|m| {
            m.peer.ip().is_loopback()
                || self
                    .config
                    .trusted_proxies
                    .iter()
                    .any(|n| n.contains(&m.peer.ip()))
        });
        self.config.cookie_secure
            || meta.is_some_and(|m| m.tls)
            || ((self.config.trust_proxy || trusted) && scheme == "https")
    }
    pub(super) async fn mfa_tokens(
        &self,
        user: &totp::CompletionUser,
        pending: &Session,
        path: &str,
        family: Option<String>,
        factors: Option<Vec<String>>,
    ) -> Result<MfaTokens, Response<Body>> {
        self.completion_tokens(user,path,family,factors.unwrap_or_else(||totp::factors(pending))).await
    }
    pub(super) async fn completion_tokens(
        &self,user:&totp::CompletionUser,path:&str,family:Option<String>,factors:Vec<String>,
    )->Result<MfaTokens,Response<Body>> {
        let scope = user
            .scope(&self.exec)
            .await
            .map_err(|_| Self::failure(500, "authorization scope resolution failed", path))?;
        match user.admission(&self.exec).await{
            Ok((true,false))=>{},
            Ok((false,_))=>return Err(Response::builder().status(409).header("content-type","application/problem+json").header("cache-control","no-store").body(body(problem::Problem::new(409,"Sign-in is temporarily fenced while identity transition security effects converge.").kind("https://setjoin.com/errors/conflict").instance(path).body())).unwrap()),
            Ok((_,true))=>return Err(Self::failure(503,"conditional access context unavailable",path)),// #406, preflight normally forwards before effects.
            Err(login::AdmissionFailure::AccountType(_))=>return Err(Self::failure(500,"account type resolution failed",path)),
            _=>return Err(Self::failure(500,"identity transition admission resolution failed",path))
        }
        let family = family.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let jti =
            login::random_jti().map_err(|_| Self::failure(500, "token issue failed", path))?;
        let refresh_jti =
            login::random_jti().map_err(|_| Self::failure(500, "token issue failed", path))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let mut access = user.claims(
            "access",
            &jti,
            &family,
            &self.config.issuer,
            now,
            self.config.access_seconds,
            scope,
            &factors,
        );
        if let Some(risk) = user.risk(&self.exec).await {
            access["risk"] = risk;
        }
        let refresh = user.claims(
            "refresh",
            &refresh_jti,
            &family,
            &self.config.issuer,
            now,
            self.config.refresh_seconds,
            None,
            &[],
        );
        Ok(MfaTokens {
            access: self
                .sign(&access)
                .map_err(|_| Self::failure(500, "token issue failed", path))?,
            refresh: self
                .sign(&refresh)
                .map_err(|_| Self::failure(500, "token issue failed", path))?,
            family,
            jti,
            factors,
        })
    }
    async fn mfa_publish(
        &self,
        user: &totp::CompletionUser,
        tokens: MfaTokens,
        ip: &str,
        agent: &str,
        secure: bool,
    ) -> Response<Body> {
        user.record(
            &self.exec,
            &tokens.access,
            &tokens.jti,
            self.config.access_seconds,
            ip,
            agent,
            &tokens.factors,
        )
        .await;
        self.mfa_response(tokens, secure)
    }
    pub(super) fn mfa_response(&self, tokens: MfaTokens, secure: bool) -> Response<Body> {
        let mut r = Self::json(
            200,
            json!({"access_token":tokens.access,"refresh_token":tokens.refresh,"expires_in":self.config.access_seconds}),
        );
        r.headers_mut().insert(
            "set-cookie",
            format!(
                "access_token={}; Path=/; Max-Age={}; HttpOnly;{} SameSite=Strict",
                tokens.access,
                self.config.access_seconds,
                if secure { " Secure;" } else { "" }
            )
            .parse()
            .unwrap(),
        );
        r
    }
    pub(super) async fn totp_verify(&self, req: Request<Body>) -> Response<Body> {
        if self.totp_completion_unported(&req).await {
            return self.forward(req).await;
        }
        let path = req.uri().path().to_owned();
        let ip = self.client_ip(&req).to_string();
        let secure = self.totp_secure(&req);
        let agent = req
            .headers()
            .get("user-agent")
            .and_then(|s| s.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let (parts, b) = req.into_parts();
        let raw = match Limited::new(b, 1 << 20).collect().await {
            Ok(v) => v.to_bytes(),
            Err(_) => return Self::totp_body_too_large(),
        };
        let input = match ingress::typed_fields(
            &raw,
            &[
                ("mfa_token", ingress::Field::Text),
                ("code", ingress::Field::Text),
                ("dpop_jwk", ingress::Field::Object),
            ],
        ) {
            Ok(v) => v,
            Err(_) => return Self::failure(400, "invalid JSON", &path),
        };
        let token = input.get("mfa_token").and_then(Value::as_str).unwrap_or("");
        let Some(pending) = self.totp_pending(token) else {
            return Self::failure(401, "invalid MFA token", &path);
        };
        if self.totp_guest(&pending).await {
            return self.forward(Request::from_parts(parts, body(raw))).await;
        } // #406 before effects.
        if input
            .get("dpop_jwk")
            .and_then(Value::as_object)
            .is_some_and(|m| !m.is_empty())
            && !matches!(
                login::enabled(&self.exec, "feature.token_binding").await,
                Ok(false)
            )
        {
            return self.forward(Request::from_parts(parts, body(raw))).await;
        } // #405.
        let code = input.get("code").and_then(Value::as_str).unwrap_or("");
        match totp::cycle(&self.exec, &pending, code).await {
            setjoin_pg::CommandOutcome::Committed(s) => match s.as_str() {
                "accepted" => {}
                "locked" => {
                    return Self::failure(
                        429,
                        "account locked due to too many TOTP failures",
                        &path,
                    )
                }
                "invalid" => return Self::failure(401, "invalid TOTP code", &path),
                _ => return Self::failure(500, "internal error", &path),
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(
                    503,
                    "TOTP verification outcome unavailable. Inspect the operation before retrying.",
                    &path,
                );
                r.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                return r;
            }
            _ => return Self::failure(500, "internal error", &path),
        }
        let user = match totp::CompletionUser::load(&self.exec, &pending).await {
            Ok(Some(u)) => u,
            _ => return Self::failure(401, "user not found", &path),
        };
        let tokens = match self.mfa_tokens(&user, &pending, &path, None, None).await {
            Ok(t) => t,
            Err(r) => return r,
        };
        match totp::mint(
            &self.exec,
            &pending,
            &tokens.refresh,
            self.config.refresh_seconds,
            &tokens.family,
        )
        .await
        {
            setjoin_pg::CommandOutcome::Committed(v) => match v["status"].as_str() {
                Some("minted") => {}
                Some("revoked") => return Self::failure(401,"invalid MFA token",&path),
                Some("credential_changed") => {
                    return Self::failure(
                        401,
                        "Credentials changed during sign-in. Please authenticate again.",
                        &path,
                    )
                }
                Some("identity_changed") => {
                    return if v["sqlstate"] == "BZ235" {
                        Self::totp_identity_changed(&v, &path, "")
                    } else {
                        Self::failure(
                            500,
                            "identity transition admission resolution failed",
                            &path,
                        )
                    }
                }
                _ => {
                    return Self::failure(
                        500,
                        "An internal error occurred. Please try again.",
                        &path,
                    )
                }
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(
                    503,
                    "Token issuance outcome unavailable. Look up the operation before retrying.",
                    &path,
                );
                r.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                return r;
            }
            setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable) => {
                return Self::failure(503, "identity mint fence unavailable", &path)
            }
            _ => return Self::failure(500, "An internal error occurred. Please try again.", &path),
        }
        self.mfa_publish(&user, tokens, &ip, &agent, secure).await
    }
}

impl AuthServer {
    pub(super) async fn totp_bootstrap_confirm(&self, req: Request<Body>) -> Response<Body> {
        if self.totp_completion_unported(&req).await {
            return self.forward(req).await;
        }
        let path = req.uri().path().to_owned();
        let ip = self.client_ip(&req).to_string();
        let secure = self.totp_secure(&req);
        let agent = req
            .headers()
            .get("user-agent")
            .and_then(|s| s.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let (parts, b) = req.into_parts();
        let raw = match Limited::new(b, 1 << 20).collect().await {
            Ok(v) => v.to_bytes(),
            Err(_) => return Self::totp_body_too_large(),
        };
        let input = match ingress::typed_fields(
            &raw,
            &[
                ("mfa_token", ingress::Field::Text),
                ("code", ingress::Field::Text),
                ("enrollment_id", ingress::Field::Text),
                ("dpop_jwk", ingress::Field::Object),
            ],
        ) {
            Ok(v) => v,
            Err(_) => return Self::failure(400, "invalid JSON", &path),
        };
        let token = input.get("mfa_token").and_then(Value::as_str).unwrap_or("");
        let Some(pending) = self.totp_pending(token) else {
            return Self::failure(401, "invalid MFA token", &path);
        };
        if pending.claims().get("act").is_some_and(|v| !v.is_null()) {
            return Self::totp_problem(
                403,
                "impersonated sessions may not manage authentication factors",
                Some("impersonation_forbidden"),
                &path,
            );
        }
        let code = input.get("code").and_then(Value::as_str).unwrap_or("");
        let id = input
            .get("enrollment_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        if code.is_empty() || id.is_empty() {
            return Self::failure(400, "code and enrollment_id are required", &path);
        }
        if self.totp_guest(&pending).await {
            return self.forward(Request::from_parts(parts, body(raw))).await;
        } // #406 before effects.
        if input
            .get("dpop_jwk")
            .and_then(Value::as_object)
            .is_some_and(|m| !m.is_empty())
            && !matches!(
                login::enabled(&self.exec, "feature.token_binding").await,
                Ok(false)
            )
        {
            return self.forward(Request::from_parts(parts, body(raw))).await;
        } // #405.
        let signed = !pending.text("credential_fence").is_empty()
            || pending
                .claims()
                .get("identity_fence")
                .is_some_and(|v| !v.is_null());
        let early = if signed {
            match totp::CompletionUser::load(&self.exec, &pending).await {
                Ok(Some(u)) => Some(u),
                _ => return Self::failure(401, "user not found", &path),
            }
        } else {
            None
        };
        let prepared = std::sync::Mutex::<Option<(totp::CompletionUser, MfaTokens)>>::new(None);
        let failed = std::sync::Mutex::<Option<Response<Body>>>::new(None);
        let output = &prepared;
        let failure = &failed;
        let pending_ref = &pending;
        let path_ref = &path;
        let result = totp::bootstrap_confirm(
            &self.exec,
            &pending,
            token,
            id,
            code,
            &ip,
            |family| async move {
                let user = match early {
                    Some(u) => u,
                    None => match totp::CompletionUser::load(&self.exec, pending_ref).await {
                        Ok(Some(u)) => u,
                        _ => {
                            *failure.lock().unwrap() =
                                Some(Self::failure(401, "user not found", path_ref));
                            return Err(json!({"status":"completion_reply"}));
                        }
                    },
                };
                let tokens = match self
                    .mfa_tokens(&user, pending_ref, path_ref, Some(family), None)
                    .await
                {
                    Ok(t) => t,
                    Err(r) => {
                        *failure.lock().unwrap() = Some(r);
                        return Err(json!({"status":"completion_reply"}));
                    }
                };
                let anchor = totp::MfaAnchor {
                    refresh: tokens.refresh.clone(),
                    lifetime: self.config.refresh_seconds,
                };
                *output.lock().unwrap() = Some((user, tokens));
                Ok(anchor)
            },
            |result| {
                let minted = result["status"] == "minted";
                let prepared = if minted {
                    prepared.lock().unwrap().clone()
                } else {
                    None
                };
                let ip = &ip;
                let agent = &agent;
                async move {
                    if let Some((user, tokens)) = prepared {
                        user.record(
                            &self.exec,
                            &tokens.access,
                            &tokens.jti,
                            self.config.access_seconds,
                            ip,
                            agent,
                            &tokens.factors,
                        )
                        .await;
                    }
                }
            },
        )
        .await;
        match result {
            setjoin_pg::CommandOutcome::Committed(v) => match v["status"].as_str() {
                Some("minted") => self.mfa_response(
                    prepared.lock().unwrap().take().expect("minted proposal").1,
                    secure,
                ),
                Some("completion_reply") => {
                    failed.lock().unwrap().take().expect("completion refusal")
                }
                Some("identity_changed") => Self::totp_identity_changed(
                    &v,
                    &path,
                    "authentication identity changed before MFA enrollment",
                ),
                Some("credential_changed") => Self::failure(
                    401,
                    "Credentials changed during sign-in. Please authenticate again.",
                    &path,
                ),
                Some("state_changed") => {
                    Self::failure(409, "MFA enrollment state changed; sign in again", &path)
                }
                Some("revoked" | "reauth_binding") => Self::totp_reauth(&path),
                Some("locked") => {
                    Self::failure(429, "account locked due to too many TOTP failures", &path)
                }
                Some("invalid_code") => Self::failure(401, "invalid TOTP code", &path),
                Some("store_failed") => {
                    Self::failure(500, "An internal error occurred. Please try again.", &path)
                }
                _ => Self::failure(500, "totp confirmation failed", &path),
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(
                    503,
                    "TOTP enrollment outcome unavailable. Inspect the operation before retrying.",
                    &path,
                );
                r.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                r
            }
            setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable) => {
                Self::failure(503, "identity mint fence unavailable", &path)
            }
            _ => Self::failure(500, "totp confirmation failed", &path),
        }
    }
}

impl AuthServer {
    pub(super) async fn totp_login_challenge(
        &self,
        proof: &login::PasswordProof,
        policy: Option<&Value>,
        path: &str,
    ) -> Response<Body> {
        let (token,jti) = match self.password_pending(proof) {
            Ok(value) => value,
            Err(()) => return Self::failure(500,"token issue failed",path),
        };
        if let Some(policy) = policy {
            match login::bootstrap_mfa_grant(&self.exec, proof, &token, &jti).await {
                setjoin_pg::CommandOutcome::Committed(true) => {}
                setjoin_pg::CommandOutcome::Unknown { operation } => {
                    let mut r = Self::failure(
                        503,
                        "MFA challenge outcome unavailable. Inspect the operation before retrying.",
                        path,
                    );
                    r.headers_mut().insert(
                        "x-operation-id",
                        uuid::Uuid::from_bytes(operation.0)
                            .to_string()
                            .parse()
                            .unwrap(),
                    );
                    return r;
                }
                _ => return Self::failure(500, "token issue failed", path),
            }
            let mut out = json!({"status":"mfa_enrollment_required","mfa_required":true,"mfa_token":token,"reason":"enrollment_required"});
            if let Some(message) = policy
                .get("message")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                out["message"] = json!(message);
            }
            return Self::json(403, out);
        }
        Self::json(
            202,
            json!({"status":"mfa_required","mfa_required":true,"mfa_method":"totp","mfa_token":token,"fallback":["backup_codes"]}),
        )
    }
}

impl AuthServer {
    pub(super) async fn backup_verify(&self, req: Request<Body>) -> Response<Body> {
        let req=match self.totp_ingress(req).await{Ok(req)=>req,Err(reply)=>return reply};
        if self.totp_completion_unported(&req).await {
            return self.forward(req).await;
        }
        let path = req.uri().path().to_owned();
        let ip = self.client_ip(&req).to_string();
        let secure = self.totp_secure(&req);
        let agent = req
            .headers()
            .get("user-agent")
            .and_then(|s| s.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let (parts, b) = req.into_parts();
        let raw = match Limited::new(b, 1 << 20).collect().await {
            Ok(v) => v.to_bytes(),
            Err(_) => return Self::totp_body_too_large(),
        };
        let input = match ingress::typed_fields(
            &raw,
            &[
                ("mfa_token", ingress::Field::Text),
                ("code", ingress::Field::Text),
                ("dpop_jwk", ingress::Field::Object),
            ],
        ) {
            Ok(v) => v,
            Err(_) => return Self::failure(400, "invalid JSON", &path),
        };
        let token = input.get("mfa_token").and_then(Value::as_str).unwrap_or("");
        if token.is_empty(){return Self::failure(400,"mfa_token is required",&path);}
        let code=input.get("code").and_then(Value::as_str).unwrap_or("");
        if code.is_empty(){return Self::failure(400,"code is required",&path);}
        let Some(pending) = self.totp_pending(token) else {
            return Self::failure(401, "invalid MFA token", &path);
        };
        if self.totp_guest(&pending).await {
            return self.forward(Request::from_parts(parts, body(raw))).await;
        } // #406 before effects.
        if input
            .get("dpop_jwk")
            .and_then(Value::as_object)
            .is_some_and(|m| !m.is_empty())
            && !matches!(
                login::enabled(&self.exec, "feature.token_binding").await,
                Ok(false)
            )
        {
            return self.forward(Request::from_parts(parts, body(raw))).await;
        } // #405.
        match setjoin_identity::push::consume_backup(&self.exec,&pending,code).await{
            setjoin_pg::CommandOutcome::Committed(true)=>{},
            setjoin_pg::CommandOutcome::Committed(false)=>return Self::failure(401,"invalid or used backup code",&path),
            setjoin_pg::CommandOutcome::Unknown{operation}=>{let mut r=Self::failure(503,"Backup-code verification outcome unavailable. Inspect the operation before retrying.",&path);r.headers_mut().insert("x-operation-id",uuid::Uuid::from_bytes(operation.0).to_string().parse().unwrap());return r;},
            _=>return Self::failure(500,"verification failed",&path)
        }
        self.mfa_finish(pending,path,ip,agent,secure,None,(401,"user not found")).await
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn mfa_finish(&self,pending:Session,path:String,ip:String,agent:String,secure:bool,factors:Option<Vec<String>>,missing:(u16,&str))->Response<Body>{
        let user = match totp::CompletionUser::load(&self.exec, &pending).await {
            Ok(Some(u)) => u,
            _ => return Self::failure(missing.0, missing.1, &path),
        };
        let tokens = match self.mfa_tokens(&user, &pending, &path, None, factors).await {
            Ok(t) => t,
            Err(r) => return r,
        };
        match totp::mint(
            &self.exec,
            &pending,
            &tokens.refresh,
            self.config.refresh_seconds,
            &tokens.family,
        )
        .await
        {
            setjoin_pg::CommandOutcome::Committed(v) => match v["status"].as_str() {
                Some("minted") => {}
                Some("revoked") => return Self::failure(401,"invalid MFA token",&path),
                Some("credential_changed") => {
                    return Self::failure(
                        401,
                        "Credentials changed during sign-in. Please authenticate again.",
                        &path,
                    )
                }
                Some("identity_changed") => {
                    return if v["sqlstate"] == "BZ235" {
                        Self::totp_identity_changed(&v, &path, "")
                    } else {
                        Self::failure(
                            500,
                            "identity transition admission resolution failed",
                            &path,
                        )
                    }
                }
                _ => {
                    return Self::failure(
                        500,
                        "An internal error occurred. Please try again.",
                        &path,
                    )
                }
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(
                    503,
                    "Token issuance outcome unavailable. Look up the operation before retrying.",
                    &path,
                );
                r.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                return r;
            }
            setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable) => {
                return Self::failure(503, "identity mint fence unavailable", &path)
            }
            _ => return Self::failure(500, "An internal error occurred. Please try again.", &path),
        }
        self.mfa_publish(&user, tokens, &ip, &agent, secure).await
    }
}
