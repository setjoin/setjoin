//! #336 possession and push HTTP edges. Identity comes from verified proofs.
use super::*;
use setjoin_identity::{push, totp};
impl AuthServer {
    pub(super) async fn password_grant(&self, req: Request<Body>) -> Response<Body> {
        let req = match self.totp_ingress(req).await {
            Ok(req) => req,
            Err(reply) => return reply,
        };
        let session = match self.totp_session(&req) {
            Ok(s) => s,
            Err(super::totp::Admission::Denied(r)) => return r,
            Err(super::totp::Admission::Forward) => return self.forward(req).await,
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
        let ct = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        if !ct.eq_ignore_ascii_case("application/json") {
            return Response::builder()
                .status(415)
                .header("content-type", "application/problem+json")
                .header("cache-control", "no-store")
                .body(body(
                    problem::Problem::new(
                        415,
                        "this endpoint requires Content-Type: application/json",
                    )
                    .kind("https://setjoin.com/errors/unsupported-media-type")
                    .title("Unsupported media type")
                    .code("unsupported_media_type")
                    .instance(&path)
                    .body(),
                ))
                .unwrap();
        }
        if session.claims().get("act").is_some_and(|v| !v.is_null()) {
            totp::audit(
                &self.exec,
                &session,
                &ip,
                "mfa_reauth_refused",
                "impersonated bearer refused at re-auth issuance",
            )
            .await;
            return Self::push_problem(
                403,
                "impersonated sessions may not manage authentication factors",
                Some("impersonation_forbidden"),
                &path,
            );
        }
        let raw = Limited::new(req.into_body(), body_cap()).collect().await;
        let fields = raw.ok().and_then(|b| {
            ingress::fields(&b.to_bytes(), &["password", "operation", "target_ref"]).ok()
        });
        let Some(fields) = fields else {
            totp::audit(
                &self.exec,
                &session,
                &ip,
                "mfa_reauth_refused",
                "malformed body",
            )
            .await;
            return Self::failure(400, "invalid JSON", &path);
        };
        let get = |k| fields.get(k).map_or("", String::as_str);
        if get("password").is_empty() {
            totp::audit(
                &self.exec,
                &session,
                &ip,
                "mfa_reauth_refused",
                "missing password",
            )
            .await;
            return Self::failure(400, "password is required", &path);
        }
        let target = match Self::possession_target(get("operation"), get("target_ref"), &path) {
            Ok(t) => t,
            Err(r) => {
                totp::audit(
                    &self.exec,
                    &session,
                    &ip,
                    "mfa_reauth_refused",
                    "invalid operation/target at re-auth issuance",
                )
                .await;
                return r;
            }
        };
        match push::password_grant(
            &self.exec,
            &session,
            get("password"),
            get("operation"),
            target,
        )
        .await
        {
            setjoin_pg::CommandOutcome::Committed(v) => match v["status"].as_str() {
                Some("issued") => {
                    totp::audit(&self.exec, &session, &ip, "mfa_reauth_authorized", "").await;
                    Self::json(200, json!({"expires_in":300,"reauth_token":v["token"]}))
                }
                Some("invalid") => {
                    totp::audit(
                        &self.exec,
                        &session,
                        &ip,
                        "mfa_reauth_refused",
                        "invalid password",
                    )
                    .await;
                    Self::failure(403, "invalid password", &path)
                }
                Some("revoked") => {
                    totp::audit(
                        &self.exec,
                        &session,
                        &ip,
                        "mfa_reauth_refused",
                        "session revoked",
                    )
                    .await;
                    Self::totp_reauth(&path)
                }
                Some("possession") => {
                    totp::audit(
                        &self.exec,
                        &session,
                        &ip,
                        "mfa_reauth_refused",
                        "possession-capable account presented a password proof",
                    )
                    .await;
                    Response::builder().status(403).header("content-type","application/problem+json").header("cache-control","no-store").body(body(problem::Problem::new(403,"this account proves possession with a TOTP code at POST /auth/mfa/possession/totp or a user-verified passkey assertion via POST /auth/mfa/possession/webauthn/begin + finish").kind("https://setjoin.com/errors/possession-proof-required").title("Possession proof required").code("possession_proof_required").remediation("possession").instance(&path).body())).unwrap()
                }
                Some("locked") => Self::failure(
                    429,
                    "account locked due to too many failed proof attempts",
                    &path,
                ),
                _ => Self::failure(500, "re-authentication failed", &path),
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(
                    503,
                    "Re-authentication outcome unavailable. Inspect the operation before retrying.",
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
                if e.hint.as_deref() == Some("possession_invalid_target") =>
            {
                totp::audit(
                    &self.exec,
                    &session,
                    &ip,
                    "mfa_reauth_refused",
                    "invalid revoke target at re-auth issuance",
                )
                .await;
                Self::push_problem(400, "invalid target_ref", Some("invalid_target"), &path)
            }
            _ => Self::failure(500, "re-authentication failed", &path),
        }
    }
    pub(super) async fn possession_totp(&self, req: Request<Body>) -> Response<Body> {
        let req = match self.totp_ingress(req).await {
            Ok(req) => req,
            Err(reply) => return reply,
        };
        let session = match self.totp_session(&req) {
            Ok(s) => s,
            Err(super::totp::Admission::Denied(r)) => return r,
            Err(super::totp::Admission::Forward) => return self.forward(req).await,
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
        let ct = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        if !ct.eq_ignore_ascii_case("application/json") {
            return Response::builder()
                .status(415)
                .header("content-type", "application/problem+json")
                .header("cache-control", "no-store")
                .body(body(
                    problem::Problem::new(
                        415,
                        "this endpoint requires Content-Type: application/json",
                    )
                    .kind("https://setjoin.com/errors/unsupported-media-type")
                    .title("Unsupported media type")
                    .code("unsupported_media_type")
                    .instance(&path)
                    .body(),
                ))
                .unwrap();
        }
        if session.claims().get("act").is_some_and(|v| !v.is_null()) {
            return Self::push_problem(
                403,
                "impersonated sessions may not manage authentication factors",
                Some("impersonation_forbidden"),
                &path,
            );
        }
        let raw = Limited::new(req.into_body(), body_cap()).collect().await;
        let fields = raw.ok().and_then(|b| {
            ingress::fields(&b.to_bytes(), &["code", "operation", "target_ref"]).ok()
        });
        let Some(fields) = fields else {
            return Self::failure(400, "invalid JSON", &path);
        };
        let get = |k| fields.get(k).map_or("", String::as_str);
        let target = match Self::possession_target(get("operation"), get("target_ref"), &path) {
            Ok(t) => t,
            Err(r) => {
                return r;
            }
        };
        if get("code").is_empty() {
            return Self::failure(400, "code is required", &path);
        }
        match push::totp_grant(&self.exec, &session, get("code"), get("operation"), target).await {
            setjoin_pg::CommandOutcome::Committed(v) => match v["status"].as_str() {
                Some("issued") => {
                    Self::json(200, json!({"expires_in":300,"reauth_token":v["token"]}))
                }
                Some("invalid") => Self::failure(403, "invalid TOTP code", &path),
                Some("revoked") => Self::totp_reauth(&path),
                Some("password") => Self::push_problem(
                    403,
                    "this account proves with its account password at /auth/mfa/reauth",
                    Some("password_proof_required"),
                    &path,
                ),
                Some("locked") => {
                    Self::failure(429, "account locked due to too many TOTP failures", &path)
                }
                _ => Self::failure(500, "internal error", &path),
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(
                    503,
                    "TOTP possession outcome unavailable. Inspect the operation before retrying.",
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
                if e.hint.as_deref() == Some("possession_invalid_target") =>
            {
                Self::push_problem(400, "invalid target_ref", Some("invalid_target"), &path)
            }
            _ => Self::failure(500, "internal error", &path),
        }
    }
    pub(super) async fn generate_backups(&self, req: Request<Body>) -> Response<Body> {
        let req = match self.totp_ingress(req).await {
            Ok(req) => req,
            Err(reply) => return reply,
        };
        let session = match self.totp_session(&req) {
            Ok(s) => s,
            Err(super::totp::Admission::Denied(r)) => return r,
            Err(super::totp::Admission::Forward) => return self.forward(req).await,
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
            return Self::push_problem(
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
        let proof = if !header.is_empty() {
            header
        } else {
            let raw = Limited::new(req.into_body(), body_cap()).collect().await;
            raw.ok()
                .and_then(|b| {
                    let raw = b.to_bytes();
                    if !ingress::exact(&raw) {
                        return None;
                    }
                    ingress::fields(&raw, &["reauth_token"]).ok()
                })
                .and_then(|mut f| f.remove("reauth_token"))
                .unwrap_or_default()
        };
        match push::generate_backups(&self.exec, &session, &proof, &ip).await {
            setjoin_pg::CommandOutcome::Committed(v) => match v["status"].as_str() {
                Some("generated") => Self::json(200, json!({"backup_codes":v["codes"]})),
                Some("revoked") => Self::totp_reauth(&path),
                Some("reauth") => {
                    totp::audit(
                        &self.exec,
                        &session,
                        &ip,
                        "mfa_reauth_refused",
                        v["notes"].as_str().unwrap_or("possession proof missing"),
                    )
                    .await;
                    Self::totp_reauth(&path)
                }
                _ => Self::failure(500, "internal error", &path),
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(
                    503,
                    "Recovery-code outcome unavailable. Inspect the operation before retrying.",
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
                if e.hint.as_deref() == Some("backup_generation_failed") =>
            {
                Self::failure(500, "generation failed", &path)
            }
            _ => Self::failure(500, "internal error", &path),
        }
    }
    pub(super) async fn native_push_register(
        &self,
        proof: &setjoin_identity::issuance::SessionProof,
        req: &Request<Body>,
        fields: &serde_json::Map<String, Value>,
    ) -> Response<Body> {
        let path = req.uri().path();
        let get = |k| fields.get(k).and_then(Value::as_str).unwrap_or("");
        let key = match push::native_key(get("device_public_key")) {
            Ok(key) => key,
            Err(detail) => return Self::failure(400, detail, path),
        };
        if proof.claims().get("act").is_some_and(|v| !v.is_null()) {
            return Self::push_problem(
                403,
                "impersonated sessions may not manage authentication factors",
                Some("impersonation_forbidden"),
                path,
            );
        }
        let token = req
            .headers()
            .get("x-mfa-reauth")
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| get("reauth_token"));
        let ip = self.client_ip(req).to_string();
        match push::register_native(
            &self.exec,
            proof,
            token,
            get("provider"),
            get("push_token"),
            key,
            get("device_name"),
            &ip,
        )
        .await
        {
            setjoin_pg::CommandOutcome::Committed(v) => match v["status"].as_str() {
                Some("registered") => Response::builder().status(204).body(body("")).unwrap(),
                Some("reauth" | "revoked") => Self::totp_reauth(path),
                _ => Self::failure(500, "internal error", path),
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r=Self::failure(503,"Native device registration outcome unavailable. Inspect the operation before retrying.",path);
                r.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                r
            }
            _ => Self::failure(500, "internal error", path),
        }
    }
    pub(super) async fn push_verify(&self, req: Request<Body>) -> Response<Body> {
        let req = match self.totp_ingress(req).await {
            Ok(req) => req,
            Err(reply) => return reply,
        };
        let path = req.uri().path().to_owned();
        if self.config.vapid_private_key.is_empty() {
            return Self::push_named_problem(404, "push MFA not configured", "not-found", &path);
        }
        let raw = match Limited::new(req.into_body(), body_cap()).collect().await {
            Ok(raw) => raw.to_bytes(),
            Err(_) => return Self::failure(400, "invalid JSON", &path),
        };
        let fields = match ingress::fields(&raw, &["mfa_token", "nonce", "answer"]) {
            Ok(fields) => fields,
            Err(_) => return Self::failure(400, "invalid JSON", &path),
        };
        if self
            .totp_pending(fields.get("mfa_token").map_or("", String::as_str))
            .is_none()
        {
            return Self::push_named_problem(401, "invalid MFA token", "unauthorized", &path);
        }
        Self::failure(
            410,
            "in-band push answer is not accepted; approve the sign-in on your enrolled device",
            &path,
        )
    }
    pub(super) fn push_named_problem(
        status: u16,
        detail: &str,
        kind: &str,
        path: &str,
    ) -> Response<Body> {
        Response::builder()
            .status(status)
            .header("content-type", "application/problem+json")
            .header("cache-control", "no-store")
            .body(body(
                problem::Problem::new(status, detail)
                    .kind(&format!("https://setjoin.com/errors/{kind}"))
                    .instance(path)
                    .body(),
            ))
            .unwrap()
    }
    pub(super) fn push_problem(status: u16, detail: &str, code: Option<&str>, path: &str) -> Response<Body> {
        let p = problem::Problem::new(status, detail).instance(path);
        let p = if let Some(code) = code {
            p.code(code)
        } else {
            p
        };
        Response::builder()
            .status(status)
            .header("content-type", "application/problem+json")
            .header("cache-control", "no-store")
            .body(body(p.body()))
            .unwrap()
    }
    pub(super) fn possession_target(
        operation: &str,
        target: &str,
        path: &str,
    ) -> Result<Option<String>, Response<Body>> {
        if !matches!(
            operation,
            "totp.enroll"
                | "totp.replace"
                | "webauthn.register"
                | "webauthn.revoke"
                | "recovery.regenerate"
                | "device.register.native"
        ) {
            return Err(Self::push_problem(
                400,
                "unknown operation",
                Some("invalid_operation"),
                path,
            ));
        }
        if operation == "webauthn.revoke" {
            if target.is_empty() {
                return Err(Self::push_problem(
                    400,
                    "target_ref is required for webauthn.revoke",
                    Some("invalid_target"),
                    path,
                ));
            }
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            let bytes = URL_SAFE_NO_PAD
                .decode(target.replace(['\r', '\n'], ""))
                .ok()
                .filter(|b| !b.is_empty());
            return bytes
                .map(|b| Some(URL_SAFE_NO_PAD.encode(b)))
                .ok_or_else(|| {
                    Self::push_problem(400, "invalid target_ref", Some("invalid_target"), path)
                });
        }
        if !target.is_empty() {
            return Err(Self::push_problem(
                400,
                "target_ref is only valid for webauthn.revoke",
                Some("invalid_target"),
                path,
            ));
        }
        Ok(None)
    }
}

impl AuthServer {
    pub(super) async fn push_status(&self, req: Request<Body>) -> Response<Body> {
        let path = req.uri().path().to_owned();
        if self.config.vapid_private_key.is_empty() {
            return Self::push_named_problem(404, "push MFA not configured", "not-found", &path);
        }
        if self.totp_completion_unported(&req).await {
            return self.forward(req).await;
        }
        let ip = self.client_ip(&req).to_string();
        let secure = self.totp_secure(&req);
        let agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let (parts, b) = req.into_parts();
        let raw = match Limited::new(b, 1 << 20).collect().await {
            Ok(v) => v.to_bytes(),
            Err(_) => return Self::failure(400, "invalid JSON", &path),
        };
        let fields = match ingress::typed_fields(
            &raw,
            &[
                ("mfa_token", ingress::Field::Text),
                ("nonce", ingress::Field::Text),
                ("dpop_jwk", ingress::Field::Object),
            ],
        ) {
            Ok(v) => v,
            Err(_) => return Self::failure(400, "invalid JSON", &path),
        };
        let nonce = fields.get("nonce").and_then(Value::as_str).unwrap_or("");
        if nonce.is_empty() {
            return Self::failure(400, "nonce is required", &path);
        }
        let token = fields
            .get("mfa_token")
            .and_then(Value::as_str)
            .unwrap_or("");
        let Some(pending) = self.totp_pending(token) else {
            return Self::push_named_problem(401, "invalid MFA token", "unauthorized", &path);
        };
        if self.totp_guest(&pending).await
            || (fields
                .get("dpop_jwk")
                .and_then(Value::as_object)
                .is_some_and(|v| !v.is_empty())
                && !matches!(
                    login::enabled(&self.exec, "feature.token_binding").await,
                    Ok(false)
                ))
        {
            return self.forward(Request::from_parts(parts, body(raw))).await;
        } // #406/#405.
        match push::harvest(&self.exec, &pending, nonce, token).await {
            setjoin_pg::CommandOutcome::Committed(true) => {}
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(
                    503,
                    "Push harvest outcome unavailable. Inspect the operation before retrying.",
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
            _ => return Self::wire_json(200, "{\"approved\":false}\n".into()),
        }
        let factors = push::approval_factors(&pending);
        self.mfa_finish(
            pending,
            path,
            ip,
            agent,
            secure,
            Some(factors),
            (500, "user lookup failed"),
        )
        .await
    }
}

impl AuthServer {
    pub(super) async fn push_approve(&self, req: Request<Body>) -> Response<Body> {
        let req = match self.totp_ingress(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };
        let path = req.uri().path().to_owned();
        let raw = match Limited::new(req.into_body(), body_cap()).collect().await {
            Ok(v) => v.to_bytes(),
            Err(_) => return Self::failure(400, "invalid JSON", &path),
        };
        let fields = match ingress::closed_fields(
            &raw,
            &[
                ("nonce", ingress::Field::Text),
                ("code", ingress::Field::Text),
                ("device_id", ingress::Field::Integer),
                ("decision", ingress::Field::Text),
                ("issued_at", ingress::Field::Integer),
                ("expires_at", ingress::Field::Integer),
                ("signature", ingress::Field::Text),
            ],
        ) {
            Ok(v) => v,
            Err(_) => return Self::failure(400, "invalid JSON", &path),
        };
        let text = |k| {
            fields
                .get(k)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        };
        let integer = |k| fields.get(k).and_then(Value::as_i64).unwrap_or(0);
        let assertion = push::Approval {
            nonce: text("nonce"),
            code: text("code"),
            device: integer("device_id"),
            decision: text("decision"),
            issued: integer("issued_at"),
            expires: integer("expires_at"),
            signature: text("signature"),
        };
        if assertion.nonce_bytes().is_none()
            || assertion.code.is_empty()
            || assertion.device <= 0
            || assertion.decision != "approve"
            || assertion.signature.is_empty()
        {
            return Self::failure(400, "invalid approval assertion", &path);
        }
        if self.config.vapid_private_key.is_empty() {
            return Self::failure(503, "push MFA not configured", &path);
        }
        match push::approve(&self.exec, &assertion).await {
            setjoin_pg::CommandOutcome::Committed(v) if v == "accepted" => {
                Response::builder().status(204).body(body("")).unwrap()
            }
            setjoin_pg::CommandOutcome::Committed(_) => {
                Self::failure(400, "invalid or expired challenge", &path)
            }
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(
                    503,
                    "Push approval outcome unavailable. Inspect the operation before retrying.",
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
            _ => Self::failure(500, "internal error", &path),
        }
    }
}

impl AuthServer {
    pub(super) async fn push_send(&self, req: Request<Body>) -> Response<Body> {
        let req = match self.totp_ingress(req).await {
            Ok(v) => v,
            Err(r) => return r,
        };
        let path = req.uri().path().to_owned();
        if self.config.vapid_private_key.is_empty() {
            return Self::push_named_problem(404, "push MFA not configured", "not-found", &path);
        }
        let ip = self.client_ip(&req).to_string();
        let fields = req
            .into_body()
            .collect()
            .await
            .ok()
            .and_then(|b| ingress::fields(&b.to_bytes(), &["mfa_token"]).ok());
        let token = fields
            .as_ref()
            .and_then(|f| f.get("mfa_token"))
            .map_or("", String::as_str);
        if token.is_empty() {
            return Self::failure(400, "mfa_token is required", &path);
        }
        let Some(pending) = self.totp_pending(token) else {
            return Self::push_named_problem(401, "invalid MFA token", "unauthorized", &path);
        };
        if !self.push_ip.allow(&ip) {
            return Self::failure(
                429,
                "too many push challenges from this client, wait before retrying",
                &path,
            );
        }
        match push::generate_pending(&self.exec, &pending, token).await {
            setjoin_pg::CommandOutcome::Committed(push::Generated::Created(challenge)) => {
                let nonce = challenge.nonce().to_owned();
                self.native_push.enqueue(self.exec.clone(), challenge);
                Self::wire_json(200,json!({"challenge_id":pending.user().to_string(),"mfa_method":"push","nonce":nonce,"ttl_seconds":120,"timeout":120}).to_string()+"\n")
            }
            setjoin_pg::CommandOutcome::Committed(push::Generated::Limited) => {
                Self::failure(429, "too many push challenges, wait before retrying", &path)
            }
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(
                    503,
                    "Push challenge outcome unavailable. Inspect the operation before retrying.",
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
            _ => Self::failure(500, "failed to generate challenge", &path),
        }
    }
}

impl AuthServer {
    pub(super) fn password_pending(
        &self,
        proof: &login::PasswordProof,
    ) -> Result<(String, String), ()> {
        let jti = login::random_jti().map_err(|_| ())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let mut claims = login::claims(
            proof,
            "mfa_pending",
            &jti,
            "",
            &self.config.issuer,
            now,
            300,
            None,
        );
        claims["amr"] = json!(["pwd"]);
        claims["credential_fence"] = json!(proof.credential_fence());
        let token = self.sign(&claims).map_err(|_| ())?;
        Ok((token, jti))
    }
    pub(super) async fn push_login_challenge(
        &self,
        proof: &login::PasswordProof,
        path: &str,
    ) -> Response<Body> {
        if !self.config.vapid_private_key.is_empty() {
            if let Ok((token, _)) = self.password_pending(proof) {
                match push::generate_login(&self.exec, proof, &token).await {
                    setjoin_pg::CommandOutcome::Committed(push::Generated::Created(challenge)) => {
                        let nonce = challenge.nonce().to_owned();
                        self.native_push.enqueue(self.exec.clone(), challenge);
                        return Self::json(
                            202,
                            json!({"status":"mfa_required","mfa_required":true,"mfa_method":"push","mfa_token":token,"nonce":nonce,"ttl_seconds":120,"fallback":["totp","backup_codes"]}),
                        );
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        let mut reply=Self::failure(503,"Push challenge outcome unavailable. Inspect the operation before retrying.",path);
                        reply.headers_mut().insert(
                            "x-operation-id",
                            uuid::Uuid::from_bytes(operation.0)
                                .to_string()
                                .parse()
                                .unwrap(),
                        );
                        return reply;
                    }
                    _ => {}
                }
            }
        }
        if proof.totp {
            return self.totp_login_challenge(proof, None, path).await;
        }
        Self::failure(500, "MFA required but no method available", path)
    }
}

impl AuthServer {
    pub(super) fn mfa_namespace(req:Request<Body>)->Response<Body>{
        let allow=match req.uri().path(){
            "/auth/push/vapid-key"=>Some("GET, HEAD"),
            "/auth/push/verify"|"/auth/push/status"|"/auth/backup-codes/generate"|"/auth/backup-codes/verify"=>Some("POST"),
            _=>None,
        };
        let text=if allow.is_some(){"Method Not Allowed\n"}else{"404 page not found\n"};
        let mut reply=Response::builder().status(if allow.is_some(){405}else{404}).header("content-type","text/plain; charset=utf-8").header("x-content-type-options","nosniff");
        if let Some(allow)=allow{reply=reply.header("allow",allow);}
        if req.method()==Method::HEAD{reply=reply.header("content-length",text.len());}
        reply.body(body(if req.method()==Method::HEAD{""}else{text})).unwrap()
    }
}
