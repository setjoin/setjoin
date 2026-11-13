//! #333 HTTP transport. Authority and store projections live in identity.
use super::*;
use base64::Engine;
use setjoin_identity::issuance::{self, ClientProof};
impl AuthServer {
    async fn token_request(
        &self,
        req: Request<Body>,
        allow_json: bool,
    ) -> Result<(ClientProof, String), Response<Body>> {
        let path = req.uri().path().to_owned();
        let ctype = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let json = allow_json && ctype.starts_with("application/json");
        let header = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let key = self.internal_key.read().unwrap().clone();
        let internal = ClientProof::internal(&header, &key);
        if json && internal.is_none() {
            return Err(Self::failure(401, "unauthorized", &path));
        }
        let query = req.uri().query().unwrap_or("").to_owned();
        let raw = if json {
            req.into_body()
                .collect()
                .await
                .map(|b| b.to_bytes())
                .map_err(|_| Self::failure(400, "token is required", &path))?
        } else {
            Limited::new(req.into_body(), 10 << 20)
                .collect()
                .await
                .map(|b| b.to_bytes())
                .map_err(|_| Self::failure(400, "invalid request body", &path))?
        };
        if json {
            let fields = ingress::typed_fields(&raw, &[("token", ingress::Field::Text)])
                .map_err(|_| Self::failure(400, "token is required", &path))?;
            let token = fields.get("token").and_then(Value::as_str).unwrap_or("");
            if token.is_empty() {
                return Err(Self::failure(400, "token is required", &path));
            }
            return Ok((internal.unwrap(), token.into()));
        }
        issuance::form(query.as_bytes())
            .map_err(|_| Self::failure(400, "invalid request body", &path))?;
        let fields = if ctype
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        {
            issuance::form(&raw).map_err(|_| Self::failure(400, "invalid request body", &path))?
        } else {
            Default::default()
        };
        let get = |key| fields.get(key).map(String::as_str).unwrap_or("");
        let caller = if let Some(internal) = internal {
            internal
        } else {
            let basic = header
                .get(..6)
                .filter(|p| p.eq_ignore_ascii_case("Basic "))
                .and_then(|_| {
                    base64::engine::general_purpose::STANDARD
                        .decode(&header[6..])
                        .ok()
                })
                .and_then(|raw| String::from_utf8(raw).ok())
                .and_then(|s| s.split_once(':').map(|(a, b)| (a.to_owned(), b.to_owned())));
            let (id, secret) = basic
                .unwrap_or_else(|| (get("client_id").to_owned(), get("client_secret").to_owned()));
            ClientProof::authenticate(&self.exec, &id, &secret)
                .await
                .ok_or_else(|| Self::failure(401, "unauthorized", &path))?
        };
        if get("token").is_empty() {
            return Err(Self::failure(400, "token is required", &path));
        }
        Ok((caller, get("token").into()))
    }
    pub(super) async fn introspect(&self, req: Request<Body>) -> Response<Body> {
        let (caller, token) = match self.token_request(req, true).await {
            Ok(v) => v,
            Err(r) => return r,
        };
        Self::wire_json(
            200,
            issuance::introspect(&self.exec, &caller, &token, &self.config.issuer).await,
        )
    }
    pub(super) async fn revoke(&self, req: Request<Body>) -> Response<Body> {
        let path = req.uri().path().to_owned();
        let (caller, token) = match self.token_request(req, false).await {
            Ok(v) => v,
            Err(r) => return r,
        };
        match issuance::revoke(&self.exec, &caller, &token).await {
            setjoin_pg::CommandOutcome::Committed(()) => Response::new(body("")),
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(
                    503,
                    "Revocation outcome unavailable. Look up the operation before retrying.",
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
            _ => Self::failure(500, "revocation failed", &path),
        }
    }
}

struct VerifyKeys<'a> {
    keys: &'a setjoin_authz::signing_keys::KeySet,
    legacy: &'a setjoin_authz::legacy_jwt::LegacyKeys,
}
impl setjoin_authz::token::KeySource for VerifyKeys<'_> {
    async fn key(&self, kid: &str) -> Option<setjoin_authz::es256::VerifyingKey> {
        setjoin_authz::token::KeySource::key(self.keys, kid).await
    }
    fn legacy_keys(&self) -> Option<&setjoin_authz::legacy_jwt::LegacyKeys> {
        Some(self.legacy)
    }
}
enum Admission {
    Denied(Response<Body>),
    Forward,
}
impl AuthServer {
    async fn session(&self, req: &Request<Body>) -> Result<issuance::SessionProof, Admission> {
        let deny = |status, detail| {
            let mut r = Self::failure(status, detail, "");
            if status == 401 {
                r.headers_mut().insert(
                    "www-authenticate",
                    hyper::header::HeaderValue::from_static("Bearer realm=\"authserver\""),
                );
            }
            Admission::Denied(r)
        };
        let Some(token) = Self::presented_access_token(req.headers()) else {
            return Err(deny(401, "Unauthorized"));
        };
        let (Some(keys), Some(legacy)) = (&self.keys, &self.legacy) else {
            return Err(deny(401, "Unauthorized"));
        };
        let Some(session) = setjoin_identity::session::Session::verify(
            &token,
            Some(keys.as_ref()),
            legacy,
            &self.config.issuer,
        ) else {
            return Err(deny(401, "Unauthorized"));
        };
        if session.text("typ") != "access" {
            return Err(deny(403, "Invalid token type"));
        }
        if self.revocations.contains(&session) {
            return Err(deny(401, "Unauthorized"));
        }
        match issuance::SessionProof::from_session(&session) {
            Ok(p) => Ok(p),
            Err(issuance::SessionError::WrongType) => Err(deny(403, "Invalid token type")),
            Err(issuance::SessionError::Bound) => Err(Admission::Forward),
            Err(issuance::SessionError::Invalid) => Err(deny(401, "Unauthorized")),
        }
    }
    pub(super) async fn pending(&self, req: Request<Body>) -> Response<Body> {
        let proof = match self.session(&req).await {
            Ok(p) => p,
            Err(Admission::Denied(r)) => return r,
            Err(Admission::Forward) => return self.forward(req).await,
        };
        match proof.pending(&self.exec).await {
            Ok(raw) => {
                let len = raw.len();
                let mut r = Response::builder()
                    .header("content-type", "application/json")
                    .body(body(raw))
                    .unwrap();
                if req.method() == Method::HEAD {
                    r.headers_mut()
                        .insert("content-length", len.to_string().parse().unwrap());
                    *r.body_mut() = body("");
                }
                r
            }
            Err(_) => Self::failure(500, "pending terms read failed", req.uri().path()),
        }
    }
}
impl AuthServer {
    fn csrf_failure(req: &Request<Body>) -> Option<Response<Body>> {
        let mut headers = req.headers().clone();
        if let Some(host) = req.headers().get("x-forwarded-host") {
            headers.insert("host", host.clone());
        }
        let scheme = req
            .headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .filter(|v| v.eq_ignore_ascii_case("https"))
            .map_or("http", |_| "https");
        (!setjoin_authz::csrf::allows(&headers, scheme)).then(|| {
            Response::builder()
                .status(403)
                .header("content-type", "application/problem+json")
                .body(body(problem::middleware(
                    403,
                    "csrf_failed",
                    "CSRF validation failed",
                )))
                .unwrap()
        })
    }
    pub(super) async fn accept(&self, req: Request<Body>) -> Response<Body> {
        let path = req.uri().path().to_owned();
        let proof = match self.session(&req).await {
            Ok(p) => p,
            Err(Admission::Denied(r)) => return r,
            Err(Admission::Forward) => return self.forward(req).await,
        };
        if let Some(r) = Self::csrf_failure(&req) {
            return r;
        }
        let ip = self.client_ip(&req).to_string();
        let raw = match Limited::new(req.into_body(), body_cap()).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return Self::failure(400, "tou_id and version required", &path),
        };
        let fields = match ingress::typed_fields(
            &raw,
            &[
                ("tou_id", ingress::Field::Integer),
                ("version", ingress::Field::Integer),
            ],
        ) {
            Ok(v) => v,
            Err(_) => return Self::failure(400, "tou_id and version required", &path),
        };
        let tou = fields.get("tou_id").and_then(Value::as_i64).unwrap_or(0);
        let version = fields.get("version").and_then(Value::as_i64).unwrap_or(0);
        if tou <= 0 || version <= 0 {
            return Self::failure(400, "tou_id and version required", &path);
        }
        match proof.accept(&self.exec, tou, version, &ip).await {
            setjoin_pg::CommandOutcome::Committed(()) => {
                Response::builder().status(204).body(body("")).unwrap()
            }
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(
                    503,
                    "Acceptance outcome unavailable. Look up the operation before retrying.",
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
            setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e))
                if e.sqlstate.as_deref() == Some("BZ102") =>
            {
                Self::failure(409, e.hint.as_deref().unwrap_or("acceptance failed"), &path)
            }
            _ => Self::failure(500, "acceptance failed", &path),
        }
    }
}
impl AuthServer {
    fn internal(&self, headers: &hyper::HeaderMap) -> Result<ClientProof, Response<Body>> {
        let key = self.internal_key.read().unwrap().clone();
        if key.is_empty() {
            return Err(Self::failure(500, "internal API key not configured", ""));
        }
        let header = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        ClientProof::internal(header, &key).ok_or_else(|| Self::failure(401, "unauthorized", ""))
    }
    pub(super) async fn scim_disable(&self, req: Request<Body>) -> Response<Body> {
        let path = req.uri().path().to_owned();
        let caller = match self.internal(req.headers()) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let raw = match Limited::new(req.into_body(), body_cap()).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return Self::failure(400, "user_id or external_id is required", &path),
        };
        let fields = match ingress::typed_fields(
            &raw,
            &[
                ("user_id", ingress::Field::Integer),
                ("external_id", ingress::Field::Text),
            ],
        ) {
            Ok(v) => v,
            Err(_) => return Self::failure(400, "user_id or external_id is required", &path),
        };
        let user = fields.get("user_id").and_then(Value::as_i64).unwrap_or(0);
        let external = fields
            .get("external_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        if user == 0 && external.is_empty() {
            return Self::failure(400, "user_id or external_id is required", &path);
        }
        match issuance::disable(&self.exec, &caller, user, external).await {
            setjoin_pg::CommandOutcome::Committed(true) => {
                Self::wire_json(200, "{\"revoked\":true}\n".into())
            }
            setjoin_pg::CommandOutcome::Committed(false) => Self::wire_json(
                200,
                "{\"reason\":\"user not found\",\"revoked\":false}\n".into(),
            ),
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r=Self::failure(503,"Session revocation outcome unavailable. Look up the operation before retrying.",&path);
                r.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                r
            }
            _ => Self::failure(500, "session revocation failed", &path),
        }
    }
}
impl AuthServer {
    /// One live internal-key generation is shared by every gate. Signing keys,
    /// pools, threat settings and SSO options remain boot-bound, exactly as Go.
    pub fn reload(&self) -> Result<(), String> {
        let next = Config::from_env()?;
        *self
            .internal_key
            .write()
            .map_err(|_| "config publication unavailable")? = next.internal_api_key;
        Ok(())
    }
    pub(super) async fn reload_http(&self, req: Request<Body>) -> Response<Body> {
        if let Err(r) = self.internal(req.headers()) {
            return r;
        }
        let (status,raw)=match self.reload(){
            Ok(())=>(200,"{\"rearmed\":[\"internal_api_key\"],\"restart_required\":[\"threat_settings\",\"jwt_secret_derived_material\",\"sso_and_authn_boot_options\"]}".into()),
            Err(error)=>(500,format!("{{\"error\":\"config reload failed: {error}\"}}")),
        };
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(body(raw))
            .unwrap()
    }
}

impl AuthServer {
    pub(super) async fn impersonate(&self, req: Request<Body>, target: String) -> Response<Body> {
        let proof = match self.session(&req).await {
            Ok(p) => p,
            Err(Admission::Denied(r)) => return r,
            Err(Admission::Forward) => return self.forward(req).await,
        };
        if let Some(r) = Self::csrf_failure(&req) {
            return r;
        }
        let ip = self.client_ip(&req).to_string();
        let target = match setjoin_identity::impersonation::authorize(
            &self.exec, &proof, &target, &ip,
        )
        .await
        {
            Ok(t) => t,
            Err(e) => {
                return Self::failure(
                    e.status,
                    e.detail,
                    if e.instance { req.uri().path() } else { "" },
                )
            }
        };
        let jti = match setjoin_identity::login::random_jti() {
            Ok(s) => s,
            Err(_) => return Self::failure(500, "token issue failed", req.uri().path()),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let token = match self.sign(&target.claims(&proof, &self.config.issuer, now, &jti)) {
            Ok(t) => t,
            Err(_) => return Self::failure(500, "token issue failed", req.uri().path()),
        };
        setjoin_identity::impersonation::record(&self.exec, &proof, &target, &ip).await;
        let meta = req.extensions().get::<ConnectionMeta>();
        let trusted = meta.is_some_and(|m| {
            self.config
                .trusted_proxies
                .iter()
                .any(|n| n.contains(&m.peer.ip()))
        });
        let secure = self.config.cookie_secure
            || meta.is_some_and(|m| m.tls)
            || ((self.config.trust_proxy || trusted)
                && req
                    .headers()
                    .get("x-forwarded-proto")
                    .is_some_and(|v| v == "https"));
        let mut response = Response::builder()
            .header("content-type", "application/json")
            .body(body(format!(
                "{}\n",
                issuance::object(&[
                    ("expires_in", json!(900)),
                    ("impersonating", json!(true)),
                    ("target_email", json!(target.email()))
                ])
            )))
            .unwrap();
        response.headers_mut().insert(
            "set-cookie",
            format!(
                "access_token={token}; Path=/; Max-Age=900; HttpOnly;{} SameSite=Strict",
                if secure { " Secure;" } else { "" }
            )
            .parse()
            .unwrap(),
        );
        response
    }
}

impl AuthServer {
    fn unauthorized_bearer() -> Response<Body> {
        let mut r = Self::failure(401, "Unauthorized", "");
        r.headers_mut().insert(
            "www-authenticate",
            "Bearer realm=\"authserver\"".parse().unwrap(),
        );
        r
    }
    pub(super) async fn bootstrap(&self, req: Request<Body>) -> Response<Body> {
        let path = req.uri().path().to_owned();
        let token = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        let Some(token) = token else {
            let mut r = Self::failure(401, "Unauthorized", "");
            r.headers_mut().insert(
                "www-authenticate",
                "Bearer realm=\"authserver\"".parse().unwrap(),
            );
            return r;
        };
        let (Some(keys), Some(legacy)) = (&self.keys, &self.legacy) else {
            return Self::failure(401, "Unauthorized", "");
        };
        let proof = match setjoin_identity::bootstrap::Proof::authenticate(
            &VerifyKeys { keys, legacy },
            token,
            &self.config.issuer,
        )
        .await
        {
            Ok(p) => p,
            Err(setjoin_identity::bootstrap::Invalid::Token) => {
                return Self::failure(401, "Unauthorized", "")
            }
            Err(setjoin_identity::bootstrap::Invalid::Type) => {
                return Self::failure(403, "Invalid token type", "")
            }
        };
        // Owner-approved security fix 2026-11-05 (#495): a revoked token gets no
        // device secret, and a sender-constrained (cnf-bound) token needs a valid
        // DPoP proof bound to this exact token, method and URL.
        if self.revocations.contains_claims(proof.claims())
            && !setjoin_contracts::mutants::on("bootstrap-revoked-gets-secret")
        {
            return Self::unauthorized_bearer();
        }
        if let Some(jkt) = proof.bound_jkt() {
            if !setjoin_contracts::mutants::on("bootstrap-bound-no-dpop") {
                let (headers, _) = Self::csrf_context(&req);
                let uri = format!(
                    "https://{}{}",
                    headers
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or(""),
                    req.uri().path()
                );
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0.0, |d| d.as_secs_f64());
                let presented = req
                    .headers()
                    .get("dpop")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if !setjoin_authz::dpop::verify(
                    presented,
                    req.method().as_str(),
                    &uri,
                    jkt,
                    now,
                    &self.dpop_replay,
                    token,
                ) {
                    return Self::unauthorized_bearer();
                }
            }
        }
        if let Some(r) = Self::csrf_failure(&req) {
            return r;
        }
        let raw = match Limited::new(req.into_body(), body_cap()).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return Self::failure(400, "Invalid request body", &path),
        };
        if !ingress::exact(&raw) {
            return Self::failure(400, "Invalid request body", &path);
        }
        let fields = match ingress::typed_fields(
            &raw,
            &[
                ("fingerprint", ingress::Field::Text),
                ("platform", ingress::Field::Text),
                ("os_version", ingress::Field::Text),
                ("app_version", ingress::Field::Text),
                ("device_name", ingress::Field::Text),
            ],
        ) {
            Ok(v) => v,
            Err(_) => return Self::failure(400, "Invalid request body", &path),
        };
        let get = |k| fields.get(k).and_then(Value::as_str).unwrap_or("");
        if get("fingerprint").is_empty() || get("platform").is_empty() {
            return Self::failure(400, "fingerprint and platform are required", &path);
        }
        if !(32..=512).contains(&get("fingerprint").len()) {
            return Self::failure(500, "Device registration failed", &path);
        }
        let secret = match (
            setjoin_identity::login::random_jti(),
            setjoin_identity::login::random_jti(),
        ) {
            (Ok(a), Ok(b)) => a + &b,
            _ => return Self::failure(500, "Device registration failed", &path),
        };
        let enc = match setjoin_config_secret::seal_column(
            secret.as_bytes(),
            self.config.secret.as_bytes(),
            self.config.profile,
        ) {
            Ok(e) => e,
            Err(_) => return Self::failure(500, "Device registration failed", &path),
        };
        match proof
            .register(
                &self.exec,
                get("device_name"),
                get("platform"),
                get("os_version"),
                get("app_version"),
                get("fingerprint"),
                &enc,
            )
            .await
        {
            setjoin_pg::CommandOutcome::Committed((id, created)) => {
                let timestamp = setjoin_identity::issuance::now_rfc3339();
                Response::builder()
                    .status(201)
                    .header("cache-control", "no-store")
                    .header("content-type", "application/json")
                    .body(body(format!(
                        "{}\n",
                        issuance::object(&[
                            ("device_id", json!(id)),
                            (
                                "hmac_secret",
                                json!(if created { secret.as_str() } else { "" })
                            ),
                            ("registered_at", json!(timestamp))
                        ])
                    )))
                    .unwrap()
            }
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r=Self::failure(503,"Device registration outcome unavailable. Look up the operation before retrying.",&path);
                r.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                r
            }
            _ => Self::failure(500, "Device registration failed", &path),
        }
    }
}

impl AuthServer {
    pub(super) async fn webpush(&self, req: Request<Body>) -> Response<Body> {
        // The unported shared threat interceptor (#420) owns the whole request.
        if self.config.threat_controls.iter().any(|on| *on) {
            return self.forward(req).await;
        }
        let path = req.uri().path().to_owned();
        let (parts, body) = req.into_parts();
        let raw = match Limited::new(body, 64 << 10).collect().await {
            Ok(b) => b.to_bytes(),
            Err(error) => {
                let (status,detail)=if error.is::<http_body_util::LengthLimitError>(){(413,"request body too large\n")}else{(400,"invalid request body\n")};
                return Response::builder()
                    .status(status)
                    .header("content-type", "text/plain; charset=utf-8")
                    .header("x-content-type-options", "nosniff")
                    .body(super::body(detail))
                    .unwrap()
            }
        };
        let req = Request::from_parts(parts, super::body(raw.clone()));
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
        let rate=self.exec.read("SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'),true)",&[]).await;
        if !matches!(rate,Ok(ref r) if !r[0].get::<_,bool>(0)) {
            return self.forward(req).await;
        }
        for control in [
            "feature.conditional_access",
            "feature.device_trust_enforcement",
        ] {
            if !matches!(
                setjoin_identity::login::enabled(&self.exec, control).await,
                Ok(false)
            ) {
                return self.forward(req).await;
            }
        }
        let proof = match self.session(&req).await {
            Ok(p) => p,
            Err(Admission::Denied(r)) => return r,
            Err(Admission::Forward) => return self.forward(req).await,
        };
        if let Some(r) = Self::csrf_failure(&req) {
            return r;
        }
        let fields = match ingress::typed_fields(
            &raw,
            &[
                ("provider", ingress::Field::Text),
                ("push_token", ingress::Field::Text),
                ("device_public_key", ingress::Field::Text),
                ("device_name", ingress::Field::Text),
                ("reauth_token", ingress::Field::Text),
            ],
        ) {
            Ok(v) => v,
            Err(_) => return Self::failure(400, "invalid JSON", &path),
        };
        let get = |k| fields.get(k).and_then(Value::as_str).unwrap_or("");
        if get("provider").is_empty() || get("push_token").is_empty() {
            return Self::failure(400, "provider and push_token are required", &path);
        }
        match get("provider") {
            "apns" | "fcm" | "hms" => return self.native_push_register(&proof,&req,&fields).await,
            "webpush" => {}
            _ => return Self::failure(400, "provider must be webpush, apns, fcm or hms", &path),
        }
        let subscription = get("push_token");
        let invalid = if subscription.len() > 8 << 10 {
            Some("push_token exceeds the subscription size bound")
        } else {
            match ingress::typed_fields(
                subscription.as_bytes(),
                &[("endpoint", ingress::Field::Text)],
            ) {
                Err(_) => Some("push_token is not a valid PushSubscription JSON"),
                Ok(sub) if !ingress::exact(subscription.as_bytes()) => {
                    let _ = sub;
                    Some("push_token is not a valid PushSubscription JSON")
                }
                Ok(sub) => {
                    let endpoint = sub.get("endpoint").and_then(Value::as_str).unwrap_or("");
                    if endpoint.is_empty() {
                        Some("push_token is missing the push service endpoint")
                    } else if !setjoin_authz::ssrf::valid_public_http(endpoint)
                        || setjoin_authz::go_url::parse_url_host(endpoint)
                            .is_ok_and(|h| h == "localhost" || h.ends_with(".localhost"))
                    {
                        Some("push service endpoint is not a valid public HTTPS URL")
                    } else {
                        None
                    }
                }
            }
        };
        if let Some(detail) = invalid {
            return Self::failure(400, detail, &path);
        }
        if self.config.db_encryption_key.is_empty() {
            return Self::failure(500, "internal error", &path);
        }
        match proof
            .register_webpush(&self.exec, subscription, get("device_name"))
            .await
        {
            setjoin_pg::CommandOutcome::Committed(()) => Response::builder()
                .status(204)
                .body(super::body(""))
                .unwrap(),
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r=Self::failure(503,"Device registration outcome unavailable. Look up the operation before retrying.",&path);
                r.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                r
            }
            _ => Self::failure(500, "internal error", &path),
        }
    }
}
