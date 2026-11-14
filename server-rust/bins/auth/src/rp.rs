//! OIDC RP HTTP adapter. Provider/session authority stays in the domain.
use super::*;
#[derive(Clone)]
struct ReplaceFlowHeaders;
impl AuthServer {
    pub(super) async fn rp_login(&self, req: Request<Body>) -> Response<Body> {
        // Lax (#548): the IdP's redirect to the callback is a cross-site top-level GET, which a
        // browser does not send SameSite=Strict cookies on. State, nonce and PKCE bind the callback.
        let site = if setjoin_identity::mutants::on("oidc-login-cookies-strict") {
            "Strict"
        } else {
            "Lax"
        };
        self.rp_login_site(req, site).await
    }
    /// `site` is the flow cookies' SameSite. An explicit link uses `Lax` (#547): the IdP's
    /// redirect back to the callback is a cross-site navigation that must carry them.
    async fn rp_login_site(&self, req: Request<Body>, site: &str) -> Response<Body> {
        let Some(registry) = &self.rp else {
            return Self::not_found();
        };
        let query = setjoin_identity::issuance::query(req.uri().query().unwrap_or(""));
        let provider = query.get("provider").map_or("", String::as_str);
        let Some(provider) = registry.provider(provider) else {
            return Self::failure(400, "unknown OIDC provider", req.uri().path());
        };
        let flow = match provider.authorization() {
            Ok(flow) => flow,
            Err(_) => return Self::failure(500, "internal error", req.uri().path()),
        };
        let text = format!(
            "<a href=\"{}\">Found</a>.\n\n",
            flow.url
                .replace('&', "&amp;")
                .replace('\'', "&#39;")
                .replace('"', "&#34;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        );
        let mut reply = Response::builder()
            .status(302)
            .header("location", &flow.url);
        if matches!(req.method(), &Method::GET | &Method::HEAD) {
            reply = reply.header("content-type", "text/html; charset=utf-8");
        }
        for (name, value) in [
            ("oidc_state", flow.state),
            ("oidc_nonce", flow.nonce),
            ("oidc_provider", flow.provider),
            ("oidc_verifier", flow.verifier),
        ] {
            let value = format!(
                "{name}={value}; Max-Age=600; HttpOnly{}; SameSite={site}",
                if self.totp_secure(&req) {
                    "; Secure"
                } else {
                    ""
                }
            );
            reply = reply.header("set-cookie", value);
        }
        reply
            .body(body(if req.method() != Method::GET {
                String::new()
            } else {
                text
            }))
            .unwrap()
    }
}

pub(super) fn cookie_value(headers: &hyper::HeaderMap, name: &str) -> Option<String> {
    for line in headers.get_all("cookie") {
        let text = String::from_utf8_lossy(line.as_bytes());
        for part in text.split(';') {
            let part = part.trim();
            let (key, raw) = part.split_once('=').unwrap_or((part, ""));
            if key.trim() != name {
                continue;
            }
            let value = if raw.len() > 1 && raw.starts_with('"') && raw.ends_with('"') {
                &raw[1..raw.len() - 1]
            } else {
                raw
            };
            if value
                .bytes()
                .all(|b| (0x20..0x7f).contains(&b) && !matches!(b, b'"' | b';' | b'\\'))
            {
                return Some(value.to_owned());
            }
        }
    }
    None
}
impl AuthServer {
    pub(super) async fn rp_callback(&self, req: Request<Body>) -> Response<Body> {
        if self.rp.is_none() {
            return Self::not_found();
        }
        // Login-time CA/device completion remains with #405/#420. Decide
        // before token exchange or any identity/profile write.
        if self.rp_completion_unported(&req).await {
            return self.forward(req).await;
        }
        let query = setjoin_identity::issuance::query(req.uri().query().unwrap_or(""));
        if cookie_value(req.headers(), "oidc_state").as_deref()
            != Some(query.get("state").map_or("", String::as_str))
        {
            return Self::failure(400, "invalid state", req.uri().path());
        }
        let verifier = cookie_value(req.headers(), "oidc_verifier").unwrap_or_default();
        if verifier.is_empty() {
            return Self::failure(400, "missing code verifier", req.uri().path());
        }
        if !setjoin_identity::rp::valid_verifier(&verifier) {
            return Self::failure(400, "invalid code verifier", req.uri().path());
        }
        let Some(name) = cookie_value(req.headers(), "oidc_provider") else {
            return Self::failure(400, "missing provider", req.uri().path());
        };
        let Some(provider) = self.rp.as_ref().and_then(|r| r.provider(&name)) else {
            return Self::failure(400, "unknown OIDC provider", req.uri().path());
        };
        if query
            .get("redirect_uri")
            .is_some_and(|u| !u.is_empty() && u != provider.redirect_uri())
        {
            return Self::failure(400, "redirect_uri mismatch", req.uri().path());
        }
        let code = query.get("code").map_or("", String::as_str);
        let claims = match provider.exchange(code, &verifier).await {
            Ok(claims) => claims,
            Err(_) => {
                return self.rp_clear(
                    Self::failure(401, "token exchange failed", req.uri().path()),
                    &req,
                    false,
                )
            }
        };
        if !claims.nonce_matches(cookie_value(req.headers(), "oidc_nonce").as_deref()) {
            return self.rp_clear(
                Self::failure(400, "invalid nonce", req.uri().path()),
                &req,
                false,
            );
        }
        if !claims.email_verified() {
            return self.rp_clear(
                Self::failure(403, "email not verified by provider", req.uri().path()),
                &req,
                true,
            );
        }
        let assertion = match claims.assertion(
            cookie_value(req.headers(), "oidc_nonce").as_deref(),
            &provider,
        ) {
            Ok(a) => a,
            Err(detail) => {
                return self.rp_clear(
                    Self::failure(
                        if detail == "invalid OIDC group assertion" {
                            401
                        } else {
                            400
                        },
                        detail,
                        req.uri().path(),
                    ),
                    &req,
                    true,
                )
            }
        };
        if let Some(flow) = cookie_value(req.headers(), "identity_link_flow") {
            // The IdP's redirect is cross-site, so the SameSite=Strict session cookie is not
            // sent: hold the verified assertion for the same-site completion request (#547).
            // A request that does carry the session (same-site IdP) completes directly.
            let strict_session = cookie_value(req.headers(), "access_token").is_some_and(|s| !s.is_empty());
            if !strict_session && !setjoin_identity::mutants::on("oidc-link-needs-strict-cookies") {
                let reply = self.rp_link_hold(&req, &assertion, &provider, &name, &flow).await;
                return self.rp_clear(reply, &req, true);
            }
            let mut reply = self
                .rp_link_callback(&req, &assertion, &provider, &flow)
                .await;
            reply.headers_mut().append(
                "set-cookie",
                format!(
                    "identity_link_flow=; Path=/; Max-Age=0; HttpOnly{}; SameSite=Strict",
                    if self.totp_secure(&req) {
                        "; Secure"
                    } else {
                        ""
                    }
                )
                .parse()
                .unwrap(),
            );
            return self.rp_clear(reply, &req, true);
        }
        let worker = self.recovery_worker.as_ref().unwrap_or(&self.exec);
        let response = match assertion.resolve(&self.exec, worker).await {
            Ok(setjoin_identity::rp::Lookup::Missing(miss)) => {
                if provider.jit() || self.config.jit_enabled {
                    match miss.create(&self.exec, worker).await {
                        Ok(resolution) => {
                            self.rp_complete(&req, &assertion, &*provider, &resolution, worker)
                                .await
                        }
                        // identity_auth_jit's soft address collision is a conflict, not a fault (#547).
                        Err(error) if error.message == "explicit account linking is required" => {
                            Self::failure(409, &error.message, req.uri().path())
                        }
                        Err(_) => Self::failure(500, "user creation failed", req.uri().path()),
                    }
                } else {
                    Self::failure(401, "user not found", req.uri().path())
                }
            }
            Err(error) => Self::failure(
                match error.message.as_str() {
                    "explicit account linking is required" => 409,
                    "sso: identity resolves to a guest account" => 401,
                    "account type resolution failed" => 500,
                    _ => 503,
                },
                &error.message,
                req.uri().path(),
            ),
            Ok(setjoin_identity::rp::Lookup::Existing(resolution)) => {
                self.rp_complete(&req, &assertion, &*provider, &resolution, worker)
                    .await
            }
        };
        self.rp_clear(response, &req, true)
    }
}

impl AuthServer {
    fn rp_clear(
        &self,
        mut reply: Response<Body>,
        req: &Request<Body>,
        nonce: bool,
    ) -> Response<Body> {
        if reply.extensions().get::<ReplaceFlowHeaders>().is_some() {
            return reply;
        }
        let names = if nonce {
            &["oidc_state", "oidc_verifier", "oidc_nonce", "oidc_provider"][..]
        } else {
            &["oidc_state", "oidc_verifier"][..]
        };
        let existing = reply
            .headers()
            .get_all("set-cookie")
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        reply.headers_mut().remove("set-cookie");
        // Clear with the same SameSite attribute the flow cookies were set with (Lax, #548).
        // Browsers do store cookies of any SameSite value on a top-level navigation response,
        // so this is consistency, not a requirement.
        let site = if setjoin_identity::mutants::on("oidc-clear-cookies-strict") {
            "Strict"
        } else {
            "Lax"
        };
        for name in names {
            reply.headers_mut().append(
                "set-cookie",
                format!(
                    "{name}=; Max-Age=0; HttpOnly{}; SameSite={site}",
                    if self.totp_secure(req) {
                        "; Secure"
                    } else {
                        ""
                    }
                )
                .parse()
                .unwrap(),
            );
        }
        for value in existing {
            reply.headers_mut().append("set-cookie", value);
        }
        reply
    }
}

impl AuthServer {
    pub(super) async fn rp_complete(
        &self,
        req: &Request<Body>,
        assertion: &setjoin_identity::rp::Assertion,
        provider: &dyn setjoin_identity::rp::Federated,
        resolution: &setjoin_identity::rp::Resolution,
        worker: &setjoin_pg::ScopedExecutor,
    ) -> Response<Body> {
        let path = req.uri().path();
        let user = match assertion
            .settle(
                &self.exec,
                worker,
                provider,
                resolution,
                self.config.sso_allow_super_admin_mapping,
            )
            .await
        {
            Ok(user) => user,
            Err(error) => {
                let mut reply = Self::failure(
                    if error.message.ends_with("reconciliation failed") {
                        409
                    } else {
                        503
                    },
                    &error.message,
                    path,
                );
                if error.message == "SSO entitlement commit failed" {
                    if let Some(op) = error.hint {
                        reply
                            .headers_mut()
                            .insert("x-operation-id", op.parse().unwrap());
                    }
                }
                return reply;
            }
        };
        if resolution.guest_scope(&self.exec).await.is_err() {
            return Self::failure(503, "conditional access context unavailable", path);
        }
        let ip = self.client_ip(req).to_string();
        let agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let prepared = std::sync::Mutex::new(None::<super::totp::MfaTokens>);
        let refusal = std::sync::Mutex::new(None::<Response<Body>>);
        let outcome = if resolution.normalized() {
            resolution
                .mint_normalized(
                    worker,
                    |family| async {
                        match self
                            .completion_tokens(&user, path, Some(family), vec!["pwd".into()], super::totp::GuestMint::Refuse)
                            .await
                        {
                            Ok(tokens) => {
                                let result = (tokens.refresh.clone(), self.config.refresh_seconds);
                                *prepared.lock().unwrap() = Some(tokens);
                                Ok(result)
                            }
                            Err(reply) => {
                                *refusal.lock().unwrap() = Some(reply);
                                Err(json!({"status":"prepare_failed"}))
                            }
                        }
                    },
                    |value| {
                        let tokens = if value["status"] == "minted" {
                            prepared.lock().unwrap().clone()
                        } else {
                            None
                        };
                        let user = &user;
                        let ip = &ip;
                        async move {
                            if let Some(tokens) = tokens {
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
                .await
        } else {
            let tokens = match self
                .completion_tokens(&user, path, None, vec!["pwd".into()], super::totp::GuestMint::Refuse)
                .await
            {
                Ok(t) => t,
                Err(r) => return r,
            };
            let result = resolution
                .mint(
                    &self.exec,
                    &tokens.refresh,
                    self.config.refresh_seconds,
                    &tokens.family,
                )
                .await;
            *prepared.lock().unwrap() = Some(tokens);
            result
        };
        if let Some(reply) = refusal.lock().unwrap().take() {
            return reply;
        }
        match outcome {
            setjoin_pg::CommandOutcome::Committed(v) if v["status"] == "minted" => {}
            setjoin_pg::CommandOutcome::Committed(v) if v["sqlstate"] == "BZ235" => {
                return Self::totp_identity_changed(
                    &v,
                    path,
                    "federated identity changed before SSO settlement",
                )
            }
            setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(error))
                if error.sqlstate.as_deref() == Some("BZ235") =>
            {
                return Self::totp_identity_changed(
                    &json!({"sqlstate":error.sqlstate,"hint":error.hint}),
                    path,
                    "federated identity changed before SSO settlement",
                )
            }
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut reply = Self::failure(503, "identity token commit failed", path);
                reply.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                return reply;
            }
            _ => return Self::failure(500, "An internal error occurred. Please try again.", path),
        }
        let tokens = prepared
            .lock()
            .unwrap()
            .take()
            .expect("committed mint prepared credentials");
        if !resolution.normalized() {
            user.record(
                &self.exec,
                &tokens.access,
                &tokens.jti,
                self.config.access_seconds,
                &ip,
                agent,
                &tokens.factors,
            )
            .await;
        }
        let mut reply = self.mfa_response(tokens, self.totp_secure(req));
        // Frozen deferredTokenResponse.flushTo replaced Set-Cookie wholesale,
        // dropping the callback's four clears on a normalized successful mint, so
        // the single-use flow cookies stayed live for up to 10 minutes. Owner-
        // approved security fix #530: the clears are always sent.
        if resolution.normalized() && setjoin_identity::mutants::on("rp-keeps-flow-cookies") {
            reply.extensions_mut().insert(ReplaceFlowHeaders);
        }
        reply
    }
}

impl AuthServer {
    /// Library embeddings start no config task without both transfer attestations.
    pub async fn start_rp_listener(
        &self,
        rust_on: &str,
        go_off: &str,
    ) -> Result<Option<setjoin_identity::rp::Listener>, String> {
        if !setjoin_identity::rp::admit_worker(rust_on, go_off)? {
            return Ok(None);
        }
        match &self.rp {
            Some(registry) => Ok(Some(registry.listen(&self.config.direct_dsn).await)),
            None => Ok(None),
        }
    }
}

impl AuthServer {
    pub(super) async fn rp_link(&self, req: Request<Body>) -> Response<Body> {
        let session = match self.totp_session(&req) {
            Ok(s) => s,
            Err(super::totp::Admission::Denied(r)) => return r,
            Err(super::totp::Admission::Forward) => return self.forward(req).await,
        };
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
        if !login::enabled(&self.exec, "feature.identity_model_v2")
            .await
            .unwrap_or(false)
        {
            return Self::not_found();
        }
        let query = setjoin_identity::issuance::query(req.uri().query().unwrap_or(""));
        let Some(provider) = self
            .rp
            .as_ref()
            .and_then(|r| r.provider(query.get("provider").map_or("", String::as_str)))
        else {
            return Self::failure(400, "unknown OIDC provider", "");
        };
        let raw = cookie_value(req.headers(), "access_token").unwrap_or_default();
        let Some(flow) = setjoin_identity::rp::LinkFlow::begin(&session, &raw, &provider) else {
            return Self::failure(403, "fresh AAL2 step-up is required before linking", "");
        };
        let worker = self.recovery_worker.as_ref().unwrap_or(&self.exec);
        match flow.persist(worker).await {
            setjoin_pg::CommandOutcome::Committed(_) => {}
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut reply =
                    Self::failure(503, "identity link authorization could not start", "");
                reply.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                return reply;
            }
            _ => return Self::failure(503, "identity link authorization could not start", ""),
        }
        let sealed = match flow.seal(self.config.secret.as_bytes()) {
            Ok(s) => s,
            Err(_) => return Self::failure(500, "identity link flow could not start", ""),
        };
        let site = if setjoin_identity::mutants::on("oidc-link-cookies-strict") {
            "Strict"
        } else {
            "Lax"
        };
        let value = format!(
            "identity_link_flow={sealed}; Path=/; Max-Age=600; HttpOnly{}; SameSite={site}",
            if self.totp_secure(&req) {
                "; Secure"
            } else {
                ""
            }
        );
        let mut reply = self.rp_login_site(req, site).await;
        let rest = reply
            .headers()
            .get_all("set-cookie")
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        reply.headers_mut().remove("set-cookie");
        reply
            .headers_mut()
            .append("set-cookie", value.parse().unwrap());
        for value in rest {
            reply.headers_mut().append("set-cookie", value);
        }
        reply
    }
    pub(super) fn rp_namespace(req: Request<Body>) -> Response<Body> {
        let allow = match req.uri().path() {
            "/auth/oidc/login" | "/auth/oidc/callback" => Some("GET, HEAD"),
            "/auth/oidc/link" => Some("POST"),
            // GET only: a HEAD must not spend the one-use held assertion (#547).
            "/auth/oidc/link/complete" => Some("GET"),
            _ => None,
        };
        let text = if allow.is_some() {
            "Method Not Allowed\n"
        } else {
            "404 page not found\n"
        };
        let mut reply = Response::builder()
            .status(if allow.is_some() { 405 } else { 404 })
            .header("content-type", "text/plain; charset=utf-8")
            .header("x-content-type-options", "nosniff");
        if let Some(allow) = allow {
            reply = reply.header("allow", allow);
        }
        if req.method() == Method::HEAD {
            reply = reply.header("content-length", text.len());
        }
        reply
            .body(body(if req.method() == Method::HEAD {
                ""
            } else {
                text
            }))
            .unwrap()
    }
}

impl AuthServer {
    async fn rp_link_callback(
        &self,
        req: &Request<Body>,
        assertion: &setjoin_identity::rp::Assertion,
        provider: &setjoin_identity::rp::Provider,
        raw_flow: &str,
    ) -> Response<Body> {
        if !login::enabled(&self.exec, "feature.identity_model_v2")
            .await
            .unwrap_or(false)
        {
            return Self::not_found();
        }
        let Some(flow) =
            setjoin_identity::rp::LinkFlow::open(raw_flow, self.config.secret.as_bytes(), provider)
        else {
            return Self::failure(400, "invalid identity link flow", "");
        };
        let Some(raw) = cookie_value(req.headers(), "access_token").filter(|s| !s.is_empty())
        else {
            return Self::failure(401, "linking session expired", "");
        };
        let Some(session) = self.legacy.as_ref().and_then(|legacy| {
            setjoin_identity::session::Session::verify(
                &raw,
                self.keys.as_deref(),
                legacy,
                &self.config.issuer,
            )
        }) else {
            return Self::failure(403, "linking session changed", "");
        };
        let flow = match flow.authorize(&session, &raw, &self.exec).await {
            Ok(f) => f,
            Err(detail) => {
                return Self::failure(
                    if detail == "linking session changed" {
                        403
                    } else {
                        401
                    },
                    detail,
                    "",
                )
            }
        };
        self.rp_link_outcome(
            req,
            flow.finish(
                self.recovery_worker.as_ref().unwrap_or(&self.exec),
                assertion,
                provider,
                self.config.sso_allow_super_admin_mapping,
            )
            .await,
        )
    }
    fn rp_link_outcome(
        &self,
        req: &Request<Body>,
        outcome: setjoin_pg::CommandOutcome<Value, setjoin_pg::StatementFailure>,
    ) -> Response<Body> {
        match outcome {
            setjoin_pg::CommandOutcome::Committed(value) => match value["status"].as_str() {
                Some("linked") => Response::builder()
                    .status(303)
                    .header("location", "/settings?identity=linked")
                    .header("content-type", "text/html; charset=utf-8")
                    .body(body(
                        "<a href=\"/settings?identity=linked\">See Other</a>.\n\n",
                    ))
                    .unwrap(),
                Some("mapping_failed") => {
                    Self::failure(409, "identity link entitlement reconciliation failed", "")
                }
                Some("normalized_failed") => {
                    Self::failure(409, "identity link entitlement reconciliation failed", "")
                }
                _ => Self::rp_classified_link_failure(&value, req.uri().path()),
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut reply = Self::failure(503, "identity link commit failed", "");
                reply.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                reply
            }
            _ => Self::failure(503, "identity link transaction unavailable", ""),
        }
    }
}

impl AuthServer {
    pub(super) async fn rp_completion_unported(&self, req: &Request<Body>) -> bool {
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
        } // #420 native device completion.
        for flag in [
            "feature.conditional_access",
            "feature.device_trust_enforcement",
        ] {
            if !matches!(login::enabled(&self.exec, flag).await, Ok(false)) {
                return true;
            }
        } // #405/#420, before all effects.
        false
    }
}

impl AuthServer {
    pub(super) fn rp_classified_link_failure(value: &Value, path: &str) -> Response<Body> {
        let code = value["sqlstate"].as_str().unwrap_or("");
        let (status, detail, default) = match code {
            "BZ228" | "BZ241" => (
                400,
                "invalidArguments",
                "Correct the request fields and retry.",
            ),
            "BZ236" | "BZ239" => (
                403,
                "forbidden",
                "Complete the required authorization, approval, or recovery step before retrying.",
            ),
            "BZ229" | "BZ230" | "BZ232" | "BZ233" | "BZ234" | "BZ235" | "BZ237" | "BZ238"
            | "BZ240" => (
                409,
                "conflict",
                "Refresh current state, resolve the conflict, and retry.",
            ),
            "BZ231" => (
                422,
                "unprocessable",
                "Correct the requested operation using the documented runbook and retry.",
            ),
            _ => return Self::failure(409, "identity link failed", path),
        };
        let hint: Value = value["hint"]
            .as_str()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(Value::Null);
        let remediation = hint["remediation"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or(default);
        let kind = format!(
            "https://setjoin.com/problems/reducer/{}",
            code.to_ascii_lowercase()
        );
        Response::builder()
            .status(status)
            .header("content-type", "application/problem+json")
            .header("cache-control", "no-store")
            .body(body(
                problem::Problem::new(status, detail)
                    .kind(&kind)
                    .instance(path)
                    .remediation(remediation)
                    .code(code)
                    .retryable(false)
                    .body(),
            ))
            .unwrap()
    }
}

impl AuthServer {
    /// A link-purpose callback that could not carry the session: nothing is linked or minted.
    /// The page sends the browser (same-site, so with its Strict cookies) to the completion route.
    async fn rp_link_hold(
        &self,
        req: &Request<Body>,
        assertion: &setjoin_identity::rp::Assertion,
        provider: &setjoin_identity::rp::Provider,
        name: &str,
        raw_flow: &str,
    ) -> Response<Body> {
        if !login::enabled(&self.exec, "feature.identity_model_v2")
            .await
            .unwrap_or(false)
        {
            return Self::not_found();
        }
        let Some(flow) =
            setjoin_identity::rp::LinkFlow::open(raw_flow, self.config.secret.as_bytes(), provider)
        else {
            return Self::failure(400, "invalid identity link flow", "");
        };
        let worker = self.recovery_worker.as_ref().unwrap_or(&self.exec);
        let Some(token) = flow.hold(worker, assertion).await else {
            return Self::failure(503, "identity link completion could not be held", req.uri().path());
        };
        let next = format!(
            "/auth/oidc/link/complete?provider={}&token={token}",
            percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC)
        );
        let page = format!(
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0;url={next}\"></head><body><a href=\"{next}\">Continue</a></body></html>"
        );
        Response::builder()
            .status(200)
            .header("content-type", "text/html; charset=utf-8")
            .header("cache-control", "no-store")
            .header("referrer-policy", "no-referrer")
            .header("content-security-policy", "default-src 'none'")
            .body(body(page))
            .unwrap()
    }

    /// `GET /auth/oidc/link/complete?provider=..&token=..`: the same-site request that carries the
    /// sealed flow, the exact live session and (through the flow) the one-use elevation. The held
    /// assertion is released once, for that provider and flow only.
    pub(super) async fn rp_link_complete(&self, req: Request<Body>) -> Response<Body> {
        let path = req.uri().path().to_owned();
        if self.rp.is_none() {
            return Self::not_found();
        }
        let query = setjoin_identity::issuance::query(req.uri().query().unwrap_or(""));
        let token = query.get("token").cloned().unwrap_or_default();
        let Some(provider) = self
            .rp
            .as_ref()
            .and_then(|r| r.provider(query.get("provider").map_or("", String::as_str)))
        else {
            return Self::failure(400, "unknown OIDC provider", &path);
        };
        let Some(raw_flow) = cookie_value(req.headers(), "identity_link_flow") else {
            return Self::failure(401, "linking session expired", &path);
        };
        if token.is_empty() {
            return Self::failure(400, "invalid identity link flow", &path);
        }
        let mut reply = self.rp_link_finish_held(&req, &provider, &raw_flow, &token).await;
        reply.headers_mut().append(
            "set-cookie",
            format!(
                "identity_link_flow=; Path=/; Max-Age=0; HttpOnly{}; SameSite=Strict",
                if self.totp_secure(&req) { "; Secure" } else { "" }
            )
            .parse()
            .unwrap(),
        );
        reply.headers_mut().insert("cache-control", "no-store".parse().unwrap());
        reply
    }

    async fn rp_link_finish_held(
        &self,
        req: &Request<Body>,
        provider: &setjoin_identity::rp::Provider,
        raw_flow: &str,
        token: &str,
    ) -> Response<Body> {
        if !login::enabled(&self.exec, "feature.identity_model_v2")
            .await
            .unwrap_or(false)
        {
            return Self::not_found();
        }
        let Some(flow) =
            setjoin_identity::rp::LinkFlow::open(raw_flow, self.config.secret.as_bytes(), provider)
        else {
            return Self::failure(400, "invalid identity link flow", "");
        };
        let Some(raw) = cookie_value(req.headers(), "access_token").filter(|s| !s.is_empty())
        else {
            return Self::failure(401, "linking session expired", "");
        };
        let Some(session) = self.legacy.as_ref().and_then(|legacy| {
            setjoin_identity::session::Session::verify(
                &raw,
                self.keys.as_deref(),
                legacy,
                &self.config.issuer,
            )
        }) else {
            return Self::failure(403, "linking session changed", "");
        };
        let flow = match flow.authorize(&session, &raw, &self.exec).await {
            Ok(f) => f,
            Err(detail) => {
                return Self::failure(
                    if detail == "linking session changed" { 403 } else { 401 },
                    detail,
                    "",
                )
            }
        };
        let worker = self.recovery_worker.as_ref().unwrap_or(&self.exec);
        let Some(assertion) = flow.take_held(worker, token).await else {
            return Self::failure(401, "link completion expired or already used", "");
        };
        self.rp_link_outcome(
            req,
            flow.finish(worker, &assertion, provider, self.config.sso_allow_super_admin_mapping)
                .await,
        )
    }
}
