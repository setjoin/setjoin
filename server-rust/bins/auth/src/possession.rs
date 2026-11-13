//! Dual-token possession admission and the WebAuthn management ceremony.
use super::*;
use setjoin_identity::{possession, session::Session};
impl AuthServer {
    fn possession_token(
        &self,
        req: &Request<Body>,
        pending: &str,
    ) -> Result<Session, totp::Admission> {
        let mut cookies = req.headers().clone();
        cookies.remove("authorization");
        let header = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(str::to_owned);
        for token in [header, Self::presented_access_token(&cookies)]
            .into_iter()
            .flatten()
        {
            if let Some(session) = self.legacy.as_ref().and_then(|legacy| {
                Session::verify(&token, self.keys.as_deref(), legacy, &self.config.issuer)
            }) {
                if session.text("typ") == "access" && !self.revocations.contains(&session) {
                    if session.bound() {
                        return Err(totp::Admission::Forward);
                    }
                    return Ok(session);
                }
            }
        }
        if let Some(session) = self.totp_pending(pending) {
            return Ok(session);
        }
        Err(totp::Admission::Denied(Self::push_problem(
            401,
            "invalid MFA token",
            Some("dpop_admission"),
            req.uri().path(),
        )))
    }
    fn possession_media(req: &Request<Body>) -> Result<(), Response<Body>> {
        let (headers, scheme) = Self::csrf_context(req);
        if !setjoin_authz::csrf::allows(&headers, scheme) {
            return Err(Response::builder()
                .status(403)
                .header("content-type", "application/problem+json")
                .body(body(problem::middleware(
                    403,
                    "csrf_failed",
                    "CSRF validation failed",
                )))
                .unwrap());
        }
        let content = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        if !content.eq_ignore_ascii_case("application/json") {
            return Err(Response::builder()
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
                    .instance(req.uri().path())
                    .body(),
                ))
                .unwrap());
        }
        Ok(())
    }
    fn possession_operation(
        session: &Session,
        operation: &str,
        target: &str,
        path: &str,
    ) -> Result<Option<String>, Response<Body>> {
        if session.text("typ") == "mfa_pending" {
            if operation != "bootstrap.totp.enroll" {
                return Err(Self::push_problem(
                    400,
                    "this admission authorizes only bootstrap.totp.enroll",
                    Some("invalid_operation"),
                    path,
                ));
            }
            if !target.is_empty() {
                return Err(Self::push_problem(
                    400,
                    "target_ref is only valid for webauthn.revoke",
                    Some("invalid_target"),
                    path,
                ));
            }
            return Ok(None);
        }
        if operation == "bootstrap.totp.enroll" {
            return Err(Self::push_problem(
                400,
                "bootstrap.totp.enroll requires an mfa_pending admission",
                Some("invalid_operation"),
                path,
            ));
        }
        Self::possession_target(operation, target, path)
    }
    pub(super) async fn possession_webauthn_begin(&self, req: Request<Body>) -> Response<Body> {
        let req = match self.totp_ingress(req).await {
            Ok(req) => req,
            Err(reply) => return reply,
        };
        if let Err(reply) = Self::possession_media(&req) {
            return reply;
        }
        let Some(rp) = &self.webauthn else {
            return Self::not_found();
        };
        let path = req.uri().path().to_owned();
        let (parts, input) = req.into_parts();
        let raw = match input.collect().await {
            Ok(raw) => raw.to_bytes(),
            Err(_) => return Self::failure(400, "invalid JSON", &path),
        };
        let Some(fields) = ingress::fields(&raw, &["operation", "target_ref", "mfa_token"]).ok()
        else {
            return Self::failure(400, "invalid JSON", &path);
        };
        let req = Request::from_parts(parts, body(raw));
        let get = |key| fields.get(key).map_or("", String::as_str);
        let session = match self.possession_token(&req, get("mfa_token")) {
            Ok(s) => s,
            Err(totp::Admission::Denied(reply)) => return reply,
            Err(totp::Admission::Forward) => return self.forward(req).await,
        };
        if session.claims().get("act").is_some_and(|v| !v.is_null()) {
            return Self::push_problem(
                403,
                "impersonated sessions may not manage authentication factors",
                Some("impersonation_forbidden"),
                &path,
            );
        }
        let target = match Self::possession_operation(
            &session,
            get("operation"),
            get("target_ref"),
            &path,
        ) {
            Ok(t) => t,
            Err(reply) => return reply,
        };
        match possession::begin(&self.exec, &session, rp, get("operation"), target).await {
            setjoin_pg::CommandOutcome::Committed(value) => match value["status"].as_str() {
                Some("created") => Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(body(value["options"].as_str().unwrap().to_owned()))
                    .unwrap(),
                Some("revoked") => Self::totp_reauth(&path),
                Some("cohort") => Response::builder()
                    .status(403)
                    .header("content-type", "application/problem+json")
                    .header("cache-control", "no-store")
                    .body(body(
                        problem::Problem::new(
                            403,
                            "no user-verified passkey is enrolled on this account",
                        )
                        .kind("https://setjoin.com/errors/possession-proof-required")
                        .title("Possession proof required")
                        .code("possession_proof_required")
                        .remediation("possession")
                        .instance(&path)
                        .body(),
                    ))
                    .unwrap(),
                Some("locked") => Self::failure(
                    429,
                    "account locked due to too many failed proof attempts",
                    &path,
                ),
                Some("target") => {
                    Self::push_problem(400, "invalid target_ref", Some("invalid_target"), &path)
                }
                _ => Self::failure(500, "internal error", &path),
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut reply=Self::failure(503,"Management ceremony outcome unavailable. Inspect the operation before retrying.",&path);
                reply.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                reply
            }
            _ => Self::failure(500, "internal error", &path),
        }
    }
}

impl AuthServer {
    fn possession_ceremony_required(path: &str) -> Response<Body> {
        Response::builder().status(403).header("content-type","application/problem+json").header("cache-control","no-store").body(body(problem::Problem::new(403,"no live management-assertion ceremony for this session — begin one at POST /auth/mfa/possession/webauthn/begin").kind("https://setjoin.com/errors/reauth-required").title("Re-authentication required").code("reauth_required").remediation("reauth").instance(path).body())).unwrap()
    }
    pub(super) async fn possession_webauthn_finish(&self, req: Request<Body>) -> Response<Body> {
        let req = match self.totp_ingress(req).await {
            Ok(req) => req,
            Err(reply) => return reply,
        };
        if let Err(reply) = Self::possession_media(&req) {
            return reply;
        }
        let Some(rp) = &self.webauthn else {
            return Self::not_found();
        };
        let path = req.uri().path().to_owned();
        let (parts, input) = req.into_parts();
        let raw = match input.collect().await {
            Ok(raw) => raw.to_bytes(),
            Err(_) => return Self::failure(400, "invalid JSON", &path),
        };
        if serde_json::from_slice::<Value>(&raw).is_err() {
            return Self::failure(400, "invalid JSON", &path);
        }
        let Some(fields) = ingress::fields(&raw, &["operation", "target_ref", "mfa_token"]).ok()
        else {
            return Self::failure(400, "invalid JSON", &path);
        };
        let req = Request::from_parts(parts, body(raw.clone()));
        let get = |key| fields.get(key).map_or("", String::as_str);
        let session = match self.possession_token(&req, get("mfa_token")) {
            Ok(s) => s,
            Err(totp::Admission::Denied(reply)) => return reply,
            Err(totp::Admission::Forward) => return self.forward(req).await,
        };
        let ceremony = match possession::peek(&self.exec, &session).await {
            Ok(Some(c)) => c,
            Ok(None) => return Self::possession_ceremony_required(&path),
            Err(_) => return Self::failure(500, "internal error", &path),
        };
        if get("operation").is_empty() || get("operation") != ceremony.operation() {
            return Self::push_problem(
                400,
                "operation does not match the ceremony",
                Some("operation_mismatch"),
                &path,
            );
        }
        if ceremony.target().unwrap_or("") != get("target_ref") {
            return Self::push_problem(
                400,
                "target_ref does not match the ceremony",
                Some("target_mismatch"),
                &path,
            );
        }
        if session.claims().get("act").is_some_and(|v| !v.is_null()) {
            return Self::push_problem(
                403,
                "impersonated sessions may not manage authentication factors",
                Some("impersonation_forbidden"),
                &path,
            );
        }
        match possession::finish(&self.exec, &session, rp, &ceremony, &raw).await {
            setjoin_pg::CommandOutcome::Committed(value) => match value["status"].as_str() {
                Some("issued") => {
                    if value["pending"] == true {
                        Self::json(200, json!({"granted":true}))
                    } else {
                        Self::json(200, json!({"expires_in":300,"reauth_token":value["token"]}))
                    }
                }
                Some("revoked") | Some("reauth") => Self::totp_reauth(&path),
                Some("locked") => Self::failure(
                    429,
                    "account locked due to too many failed proof attempts",
                    &path,
                ),
                Some("target") => {
                    Self::push_problem(400, "invalid target_ref", Some("invalid_target"), &path)
                }
                Some("malformed") => Self::push_problem(
                    400,
                    "malformed assertion body",
                    Some("invalid_request"),
                    &path,
                ),
                Some("invalid") => Self::failure(403, "assertion verification failed", &path),
                _ => Self::failure(500, "internal error", &path),
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut reply = Self::failure(
                    503,
                    "Management proof outcome unavailable. Inspect the operation before retrying.",
                    &path,
                );
                reply.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                reply
            }
            _ => Self::failure(500, "internal error", &path),
        }
    }
}
