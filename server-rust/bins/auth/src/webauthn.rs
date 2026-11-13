//! WebAuthn HTTP adapter; the verified session supplies every credential owner.
use super::*;
use setjoin_identity::webauthn;
impl AuthServer {
    pub(super) async fn webauthn_list(&self, req: Request<Body>) -> Response<Body> {
        let session = match self.totp_session(&req) {
            Ok(s) => s,
            Err(totp::Admission::Denied(r)) => return r,
            Err(totp::Admission::Forward) => return self.forward(req).await,
        };
        let mut response = match webauthn::list(&self.exec, &session).await {
            Ok(raw) => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(body(
                    raw.replace('&', "\\u0026")
                        .replace('<', "\\u003c")
                        .replace('>', "\\u003e")
                        .replace('\u{2028}', "\\u2028")
                        .replace('\u{2029}', "\\u2029"),
                ))
                .unwrap(),
            Err(_) => Self::failure(500, "database error", req.uri().path()),
        };
        if req.method() == Method::HEAD {
            if let Some(n) = response.body().size_hint().exact() {
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
    pub(super) async fn webauthn_name(&self, req: Request<Body>, id: String) -> Response<Body> {
        let session = match self.totp_session(&req) {
            Ok(s) => s,
            Err(totp::Admission::Denied(r)) => return r,
            Err(totp::Admission::Forward) => return self.forward(req).await,
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
        let Some(fields) = req
            .into_body()
            .collect()
            .await
            .ok()
            .and_then(|b| ingress::fields(&b.to_bytes(), &["device_name"]).ok())
        else {
            return Self::failure(400, "invalid JSON", &path);
        };
        let name = fields.get("device_name").map_or("", String::as_str);
        if name.is_empty() {
            return Self::failure(400, "device_name required", &path);
        }
        let id = percent_encoding::percent_decode_str(&id)
            .decode_utf8()
            .ok()
            .and_then(|id| webauthn::decode_credential_id(&id));
        let Some(id) = id else {
            return Self::failure(400, "invalid credential id", &path);
        };
        if id.is_empty() {
            return Self::failure(400, "invalid credential id", &path);
        }
        match webauthn::name(&self.exec, &session, &id, name).await {
            setjoin_pg::CommandOutcome::Committed(()) => {
                Response::builder().status(200).body(body("")).unwrap()
            }
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(
                    503,
                    "Credential naming outcome unavailable. Inspect the operation before retrying.",
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
            setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(failure)) => {
                Self::failure(
                    400,
                    &format!("failed: {}", webauthn::statement_error(&failure)),
                    &path,
                )
            }
            _ => Self::failure(400, "failed: database error", &path),
        }
    }
}
impl AuthServer {
    pub(super) async fn webauthn_login_begin(&self, req: Request<Body>) -> Response<Body> {
        let Some(rp) = &self.webauthn else {
            return Self::not_found();
        };
        let email = form_urlencoded_query(req.uri().query().unwrap_or(""), "email");
        let Ok(begin) = rp.begin_login(&self.exec, &email).await else {
            return Self::failure(500, "internal error", req.uri().path());
        };
        let (Ok(session), Ok(uid)) = (
            rp.cookies.seal(&begin.session),
            rp.cookies.seal(begin.user.to_string().as_bytes()),
        ) else {
            return Self::failure(500, "internal error", req.uri().path());
        };
        let mut response = Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(body(begin.options))
            .unwrap();
        for (name, value) in [("wa_login_sess", session), ("wa_login_uid", uid)] {
            response.headers_mut().append(
                "set-cookie",
                format!(
                    "{name}={value}; Max-Age=300; HttpOnly;{} SameSite=Strict",
                    if self.totp_secure(&req) {
                        " Secure;"
                    } else {
                        ""
                    }
                )
                .parse()
                .unwrap(),
            );
        }
        if req.method() == Method::HEAD {
            if let Some(n) = response.body().size_hint().exact() {
                response
                    .headers_mut()
                    .insert("content-length", n.to_string().parse().unwrap());
            }
            *response.body_mut() = body("");
        }
        response
    }
}
fn form_urlencoded_query(query: &str, key: &str) -> String {
    // The domain already uses the maintained form parser; keep URL decoding there.
    setjoin_identity::webauthn::query_value(query, key)
}
impl AuthServer {
    pub(super) async fn webauthn_login_finish(&self, req: Request<Body>) -> Response<Body> {
        let Some(rp) = &self.webauthn else {
            return Self::not_found();
        };
        if self.totp_completion_unported(&req).await {
            return self.forward(req).await;
        }
        let path = req.uri().path().to_owned();
        let Some(session_cookie) = cookie_value(req.headers(), "wa_login_sess") else {
            return Self::failure(400, "missing session cookie", &path);
        };
        let Some(uid_cookie) = cookie_value(req.headers(), "wa_login_uid") else {
            return Self::failure(400, "missing uid cookie", &path);
        };
        let transport = match rp.login_transport(&uid_cookie, &session_cookie) {
            Ok(t) => t,
            Err(detail) => return Self::failure(400, detail, &path),
        };
        // Named unported completion owners are selected before a handle/counter write.
        if let Ok(rows)=self.exec.read("SELECT is_guest_account($1),COALESCE(push_mfa_enabled,FALSE) FROM users WHERE id=$1",&[(&transport.user(),setjoin_pg::Type::INT8)]).await {
            if rows.first().is_some_and(|r|r.get::<_,bool>(0)){return self.forward(req).await;}// #406.
        }
        let ip = self.client_ip(&req).to_string();
        let secure = self.totp_secure(&req);
        let agent = req
            .headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let (parts, b) = req.into_parts();
        let raw = match Limited::new(b, 1 << 20).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return Self::failure(400, "invalid request body", &path),
        };
        if serde_json::from_slice::<Value>(&raw)
            .ok()
            .and_then(|v| v.get("dpop_jwk").cloned())
            .and_then(|v| v.as_object().cloned())
            .is_some_and(|m| !m.is_empty())
            && !matches!(
                login::enabled(&self.exec, "feature.token_binding").await,
                Ok(false)
            )
        {
            return self.forward(Request::from_parts(parts, body(raw))).await;
        } // #405.
        let proof = match rp.finish_login(&self.exec, &transport, &raw).await {
            Ok(p) => p,
            Err(webauthn::LoginFailure::Refused(detail)) => {
                let _=self.exec.protocol_statement("INSERT INTO auth_event_log(event,provider,ip_address) VALUES('login_failed','webauthn',NULLIF($1,'')::inet)",&[(&ip,setjoin_pg::Type::TEXT)]).await;
                return Self::failure(401, &format!("login failed: {detail}"), &path);
            }
            Err(webauthn::LoginFailure::Unknown(operation)) => {
                return Self::webauthn_unknown(operation, "Passkey assertion", &path)
            }
        };
        let user = match proof.completion(&self.exec).await {
            Ok(Some(u)) => u,
            _ => return Self::failure(401, "user not found", &path),
        };
        let (totp, push) = proof.factors(&self.exec).await;
        if totp || push {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let mut claims = user.claims(
                "mfa_pending",
                &match login::random_jti() {
                    Ok(j) => j,
                    Err(_) => return Self::failure(500, "internal error", &path),
                },
                "",
                &self.config.issuer,
                now,
                300,
                None,
                &[],
            );
            claims.as_object_mut().unwrap().remove("fam");
            claims["amr"] = json!(["hwk"]);
            let token = match self.sign(&claims) {
                Ok(t) => t,
                Err(_) => return Self::failure(500, "internal error", &path),
            };
            if push && !self.config.vapid_private_key.is_empty() {
                match proof.push_challenge(&self.exec).await {
                    setjoin_pg::CommandOutcome::Committed(setjoin_identity::push::Generated::Created(challenge))=>{
                        let nonce=challenge.nonce().to_owned();
                        self.native_push.enqueue(self.exec.clone(),challenge);
                        return Self::json(200,json!({"mfa_required":true,"mfa_method":"push","mfa_token":token,"nonce":nonce,"ttl_seconds":120,"fallback":["totp","backup_codes"]}));
                    }
                    setjoin_pg::CommandOutcome::Unknown{operation}=>return Self::webauthn_unknown(operation,"Push challenge",&path),
                    _=>{}
                }
            }
            if !totp {return Self::failure(500,"MFA required but no method available",&path);}
            return Self::json(
                200,
                json!({"mfa_required":true,"mfa_method":"totp","mfa_token":token,"fallback":["backup_codes"]}),
            );
        }
        let scope = match user.scope(&self.exec).await {
            Ok(s) => s,
            Err(_) => return Self::failure(500, "authorization scope resolution failed", &path),
        };
        match user.admission(&self.exec).await{
            Ok((true,false))=>{},
            Ok((false,_))=>return Response::builder().status(409).header("content-type","application/problem+json").header("cache-control","no-store").body(body(problem::Problem::new(409,"Sign-in is temporarily fenced while identity transition security effects converge.").kind("https://setjoin.com/errors/conflict").instance(&path).body())).unwrap(),
            Ok((_,true))=>return Self::failure(503,"conditional access context unavailable",&path),
            Err(login::AdmissionFailure::AccountType(_))=>return Self::failure(500,"account type resolution failed",&path),
            _=>return Self::failure(500,"identity transition admission resolution failed",&path),
        }
        let family = uuid::Uuid::new_v4().to_string();
        let (Ok(jti), Ok(refresh_jti)) = (login::random_jti(), login::random_jti()) else {
            return Self::failure(500, "token issue failed", &path);
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let factors = vec!["hwk".to_owned()];
        let mut claims = user.claims(
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
            claims["risk"] = risk;
        }
        let refresh_claims = user.claims(
            "refresh",
            &refresh_jti,
            &family,
            &self.config.issuer,
            now,
            self.config.refresh_seconds,
            None,
            &[],
        );
        let (Ok(access), Ok(refresh)) = (self.sign(&claims), self.sign(&refresh_claims)) else {
            return Self::failure(500, "token issue failed", &path);
        };
        match proof
            .mint(&self.exec, &refresh, self.config.refresh_seconds, &family)
            .await
        {
            setjoin_pg::CommandOutcome::Committed(v) if v["status"] == "minted" => {}
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                return Self::webauthn_unknown(operation, "Token issuance", &path)
            }
            _ => return Self::failure(500, "An internal error occurred. Please try again.", &path),
        }
        user.record(
            &self.exec,
            &access,
            &jti,
            self.config.access_seconds,
            &ip,
            &agent,
            &factors,
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
    fn webauthn_unknown(
        operation: setjoin_contracts::ids::OperationId,
        action: &str,
        path: &str,
    ) -> Response<Body> {
        let mut r = Self::failure(
            503,
            &format!("{action} outcome unavailable. Inspect the operation before retrying."),
            path,
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
fn cookie_value(headers: &hyper::HeaderMap, name: &str) -> Option<String> {
    for line in headers
        .get_all("cookie")
        .iter()
        .filter_map(|h| h.to_str().ok())
    {
        for part in line.split(';') {
            if let Ok(cookie) = cookie::Cookie::parse(part.trim()) {
                if cookie.name() == name {
                    return Some(cookie.value_trimmed().to_owned());
                }
            }
        }
    }
    None
}
impl AuthServer {
    pub(super) async fn webauthn_register_begin(&self, req: Request<Body>) -> Response<Body> {
        if self.totp_threat_pending().await {
            return self.forward(req).await;
        } // #420.
        let session = match self.totp_session(&req) {
            Ok(s) => s,
            Err(totp::Admission::Denied(r)) => return r,
            Err(totp::Admission::Forward) => return self.forward(req).await,
        };
        let Some(rp) = &self.webauthn else {
            return Self::not_found();
        };
        let path = req.uri().path().to_owned();
        if session.claims().get("act").is_some_and(|v| !v.is_null()) {
            return self.webauthn_impersonated(&path);
        }
        let mut token = req
            .headers()
            .get("x-mfa-reauth")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let ip = self.client_ip(&req).to_string();
        let secure = self.totp_secure(&req);
        let head = req.method() == Method::HEAD;
        if token.is_empty() {
            if let Ok(raw) = Limited::new(req.into_body(), body_cap()).collect().await {
                if let Ok(fields) = ingress::fields(&raw.to_bytes(), &["reauth_token"]) {
                    token = fields.get("reauth_token").cloned().unwrap_or_default();
                }
            }
        }
        let mut response = match rp.begin_registration(&self.exec, &session, &token).await {
            setjoin_pg::CommandOutcome::Committed(v) => match v.outcome["status"].as_str() {
                Some("created") => {
                    let enc = match rp.cookies.seal(v.session.as_deref().unwrap_or_default()) {
                        Ok(s) => s,
                        Err(_) => return Self::failure(500, "internal error", &path),
                    };
                    Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .header(
                            "set-cookie",
                            format!(
                                "wa_reg_sess={enc}; Max-Age=300; HttpOnly;{} SameSite=Strict",
                                if secure { " Secure;" } else { "" }
                            ),
                        )
                        .body(body(
                            v.options
                                .unwrap_or_default()
                                .replace('&', "\\u0026")
                                .replace('<', "\\u003c")
                                .replace('>', "\\u003e"),
                        ))
                        .unwrap()
                }
                Some("bound") => Self::json(200, json!({"status":"bound"})),
                Some("bound_dead") => Self::webauthn_problem(
                    409,
                    "this proof already authorized a different ceremony; present a fresh proof",
                    Some("proof_already_bound"),
                    &path,
                ),
                Some("reauth") => {
                    setjoin_identity::totp::audit(
                        &self.exec,
                        &session,
                        &ip,
                        "mfa_reauth_refused",
                        "webauthn register begin without a valid possession proof",
                    )
                    .await;
                    Self::totp_reauth(&path)
                }
                Some("revoked") => Self::totp_reauth(&path),
                Some("webauthn_error") => Self::failure(
                    500,
                    &format!(
                        "webauthn error: {}",
                        v.outcome["detail"].as_str().unwrap_or("internal error")
                    ),
                    &path,
                ),
                _ => Self::failure(500, "internal error", &path),
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                return Self::webauthn_unknown(operation, "Registration begin", &path)
            }
            _ => Self::failure(500, "internal error", &path),
        };
        if head {
            if let Some(n) = response.body().size_hint().exact() {
                response
                    .headers_mut()
                    .insert("content-length", n.to_string().parse().unwrap());
            }
            *response.body_mut() = body("");
        }
        response
    }
    fn webauthn_problem(
        status: u16,
        detail: &str,
        code: Option<&str>,
        path: &str,
    ) -> Response<Body> {
        let mut p = problem::Problem::new(status, detail).instance(path);
        if let Some(code) = code {
            p = p.code(code);
        }
        Response::builder()
            .status(status)
            .header("content-type", "application/problem+json")
            .header("cache-control", "no-store")
            .body(body(p.body()))
            .unwrap()
    }
    fn webauthn_impersonated(&self, path: &str) -> Response<Body> {
        Self::webauthn_problem(
            403,
            "impersonated sessions may not manage authentication factors",
            Some("impersonation_forbidden"),
            path,
        )
    }
}
impl AuthServer {
    pub(super) async fn webauthn_register_finish(&self, req: Request<Body>) -> Response<Body> {
        if self.totp_threat_pending().await {
            return self.forward(req).await;
        } // #420.
        let session = match self.totp_session(&req) {
            Ok(s) => s,
            Err(totp::Admission::Denied(r)) => return r,
            Err(totp::Admission::Forward) => return self.forward(req).await,
        };
        let Some(rp) = &self.webauthn else {
            return Self::not_found();
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
            return self.webauthn_impersonated(&path);
        }
        let Some(cookie) = cookie_value(req.headers(), "wa_reg_sess") else {
            return Self::failure(400, "missing session cookie", &path);
        };
        if rp.cookies.open(&cookie).is_none() {
            return Self::failure(400, "invalid session cookie", &path);
        }
        let header = req
            .headers()
            .get("x-mfa-reauth")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let ip = self.client_ip(&req).to_string();
        let raw = match Limited::new(req.into_body(), 64 << 10).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return Self::failure(400, "invalid request body", &path),
        };
        let token = if !header.is_empty() {
            header
        } else {
            ingress::fields(&raw, &["reauth_token"])
                .ok()
                .and_then(|v| v.get("reauth_token").cloned())
                .unwrap_or_default()
        };
        match rp
            .finish_registration(&self.exec, &session, &cookie, &raw, &token, &ip)
            .await
        {
            setjoin_pg::CommandOutcome::Committed(v) => match v["status"].as_str() {
                Some("registered") => Response::builder().status(201).body(body("")).unwrap(),
                Some("invalid_cookie") => Self::failure(400, "invalid session cookie", &path),
                Some("revoked" | "reauth_ceremony") => Self::totp_reauth(&path),
                Some("reauth_gate" | "proving_factor") => {
                    let detail = if v["status"] == "proving_factor" {
                        "possession proof refused: proving factor no longer live"
                    } else {
                        "webauthn register finish without a valid possession proof"
                    };
                    setjoin_identity::totp::audit(
                        &self.exec,
                        &session,
                        &ip,
                        "mfa_reauth_refused",
                        detail,
                    )
                    .await;
                    Self::totp_reauth(&path)
                }
                Some("load_error") => Self::failure(
                    400,
                    &format!(
                        "registration failed: {}",
                        v["detail"].as_str().unwrap_or("no rows in result set")
                    ),
                    &path,
                ),
                _ => Self::failure(500, "internal error", &path),
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                Self::webauthn_unknown(operation, "Registration", &path)
            }
            setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(failure))
                if failure.hint.as_deref() == Some("webauthn-verification") =>
            {
                Self::failure(
                    400,
                    &format!("registration failed: {}", failure.message),
                    &path,
                )
            }
            _ => Self::failure(500, "internal error", &path),
        }
    }
}

impl AuthServer {
    pub(super) async fn webauthn_revoke(&self, req: Request<Body>, id: String) -> Response<Body> {
        let session = match self.totp_session(&req) {
            Ok(s) => s,
            Err(totp::Admission::Denied(r)) => return r,
            Err(totp::Admission::Forward) => return self.forward(req).await,
        };
        if self.webauthn.is_none() {
            return Self::not_found();
        }
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
            return self.webauthn_impersonated(&path);
        }
        let id = percent_encoding::percent_decode_str(&id)
            .decode_utf8()
            .ok()
            .and_then(|id| webauthn::decode_credential_id(&id));
        let Some(id) = id else {
            return Self::failure(400, "invalid credential id", &path);
        };
        if id.is_empty() {
            return Self::failure(400, "invalid credential id", &path);
        }
        let header = req
            .headers()
            .get("x-mfa-reauth")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let ip = self.client_ip(&req).to_string();
        let token = if header.is_empty() {
            Limited::new(req.into_body(), body_cap())
                .collect()
                .await
                .ok()
                .and_then(|b| ingress::fields(&b.to_bytes(), &["reauth_token"]).ok())
                .and_then(|v| v.get("reauth_token").cloned())
                .unwrap_or_default()
        } else {
            header
        };
        match webauthn::revoke(&self.exec, &session, &id, &token, &ip).await {
            setjoin_pg::CommandOutcome::Committed(v) => match v["status"].as_str() {
                Some("revoked_credential") => {
                    Response::builder().status(204).body(body("")).unwrap()
                }
                Some("missing") => {
                    Self::failure(400, "credential not found or already revoked", &path)
                }
                Some("update_error") => Self::failure(
                    500,
                    &format!(
                        "failed: {}",
                        v["detail"].as_str().unwrap_or("database error")
                    ),
                    &path,
                ),
                Some("revoked") => Self::totp_reauth(&path),
                Some("reauth_gate" | "proving_factor") => {
                    let detail = if v["status"] == "proving_factor" {
                        "possession proof refused: proving factor no longer live"
                    } else {
                        "webauthn revoke without a valid possession proof"
                    };
                    setjoin_identity::totp::audit(
                        &self.exec,
                        &session,
                        &ip,
                        "mfa_reauth_refused",
                        detail,
                    )
                    .await;
                    Self::totp_reauth(&path)
                }
                _ => Self::failure(500, "internal error", &path),
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                Self::webauthn_unknown(operation, "Credential revocation", &path)
            }
            _ => Self::failure(500, "internal error", &path),
        }
    }
}

impl AuthServer {
    pub(super) async fn webauthn_ingress(
        &self,
        req: Request<Body>,
    ) -> Result<Request<Body>, Response<Body>> {
        let (parts, input) = req.into_parts();
        match Limited::new(input, 64 << 10).collect().await {
            Ok(bytes) => Ok(Request::from_parts(parts, body(bytes.to_bytes()))),
            Err(error) => {
                let (status, text) = if error.is::<http_body_util::LengthLimitError>() {
                    (413, "request body too large\n")
                } else {
                    (400, "invalid request body\n")
                };
                Err(Response::builder()
                    .status(status)
                    .header("content-type", "text/plain; charset=utf-8")
                    .header("x-content-type-options", "nosniff")
                    .body(body(text))
                    .unwrap())
            }
        }
    }
    pub(super) fn webauthn_mux(req: Request<Body>) -> Response<Body> {
        let path = req.uri().path();
        let allow = match path {
            "/auth/webauthn/credentials"
            | "/auth/webauthn/register/begin"
            | "/auth/webauthn/login/begin" => Some("GET, HEAD"),
            "/auth/webauthn/register/finish" | "/auth/webauthn/login/finish" => Some("POST"),
            _ if path
                .strip_prefix("/auth/webauthn/credential/")
                .and_then(|s| s.strip_suffix("/name"))
                .is_some_and(|s| !s.is_empty() && !s.contains('/')) =>
            {
                Some("PUT")
            }
            _ if path
                .strip_prefix("/auth/webauthn/credential/")
                .is_some_and(|s| !s.is_empty() && !s.contains('/')) =>
            {
                Some("DELETE")
            }
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
