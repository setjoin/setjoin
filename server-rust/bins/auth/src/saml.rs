//! SAML HTTP adapter. Inbound XML gains authority only through `saml_acs`: a signature by
//! the registration's pinned key over the element the claims are read from (#546).
use super::*;
impl AuthServer {
    pub(super) async fn saml_request(&self, req: Request<Body>) -> Response<Body> {
        let parts: Vec<_> = req.uri().path().split('/').collect();
        let allow = if parts.len() == 5 {
            match parts[4] {
                "login" | "metadata" => Some("GET, HEAD"),
                "acs" | "link" => Some("POST"),
                _ => None,
            }
        } else {
            None
        };
        if let Some(allow) = allow {
            if !(if allow == "POST" {
                req.method() == Method::POST
            } else {
                matches!(req.method(), &Method::GET | &Method::HEAD)
            }) {
                return Response::builder()
                    .status(405)
                    .header("allow", allow)
                    .header("content-type", "text/plain; charset=utf-8")
                    .header("x-content-type-options", "nosniff")
                    .body(body("Method Not Allowed\n"))
                    .unwrap();
            }
        }
        let idp = parts
            .get(3)
            .and_then(|s| percent_encoding::percent_decode_str(s).decode_utf8().ok())
            .map(|s| s.into_owned())
            .unwrap_or_default();
        if parts.len() == 5 && parts[4] == "link" && req.method() == Method::POST {
            return self.saml_link(req, &idp).await;
        }
        // Same-site completion of a link the ACS held (the IdP's cross-site POST carries
        // no SameSite=Strict cookie, this request does).
        if parts.len() == 6 && parts[4] == "link" && parts[5] == "complete" {
            if req.method() != Method::GET {
                return Response::builder()
                    .status(405)
                    .header("allow", "GET")
                    .header("content-type", "text/plain; charset=utf-8")
                    .header("x-content-type-options", "nosniff")
                    .body(body("Method Not Allowed\n"))
                    .unwrap();
            }
            let Some(reg) = self.saml.as_ref().and_then(|r| r.registration(&idp)) else {
                return Self::not_found();
            };
            return self.saml_link_complete(req, reg).await;
        }
        let Some(reg) = self
            .saml
            .as_ref()
            .filter(|_| parts.len() == 5)
            .and_then(|r| r.registration(&idp))
        else {
            return Self::not_found();
        };
        if parts[4] == "acs" && req.method() == Method::POST {
            return self.saml_acs(req, reg).await;
        }
        if parts[4] == "login" {
            self.saml_login_reply(&req, &reg, "login", None)
        } else {
            Self::not_found()
        }
    }
    fn saml_login_reply(
        &self,
        req: &Request<Body>,
        reg: &setjoin_identity::saml::Registration,
        purpose: &str,
        flow: Option<&str>,
    ) -> Response<Body> {
        if super::rp::cookie_value(req.headers(), "token").is_some_and(|raw| reg.has_session(&raw))
        {
            let text = "<a href=\"/\">Found</a>.\n\n";
            let mut reply = Response::builder().status(302).header("location", "/");
            if matches!(req.method(), &Method::GET | &Method::HEAD) {
                reply = reply.header("content-type", "text/html; charset=utf-8");
            }
            if req.method() == Method::HEAD {
                reply = reply.header("content-length", text.len());
            }
            return reply
                .body(body(if req.method() == Method::GET {
                    text
                } else {
                    ""
                }))
                .unwrap();
        }
        match reg.authorization(req.uri().path_and_query().map_or("/",|v|v.as_str()), purpose, flow) {
            Ok(flow)=>match flow.post {
                Some(html)=>Response::builder().status(200).header("content-type","text/html").header("content-security-policy","default-src; script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; reflected-xss block; referrer no-referrer;").header("set-cookie",flow.cookie).body(body(if req.method()==Method::HEAD{String::new()}else{html})).unwrap(),
                None=>Response::builder().status(302).header("location",flow.location).header("set-cookie",flow.cookie).body(body("")).unwrap(),
            },
            Err(_)=>Self::failure(500,"SAML authentication failed",req.uri().path())
        }
    }
    pub(super) async fn saml_links(&self, req: Request<Body>) -> Response<Body> {
        let session = match self.totp_session(&req) {
            Ok(s) => s,
            Err(super::totp::Admission::Denied(r)) => return r,
            Err(super::totp::Admission::Forward) => return self.forward(req).await,
        };
        if !login::enabled(&self.exec, "feature.identity_model_v2")
            .await
            .unwrap_or(false)
        {
            return Self::not_found();
        }
        match setjoin_identity::identity_links::list(
            self.recovery_worker.as_ref().unwrap_or(&self.exec),
            &session,
        )
        .await
        {
            Ok(value) => Self::json_no_store(200, value),
            Err(_) => Self::failure(503, "identity links unavailable", ""),
        }
    }
    async fn saml_link(&self, req: Request<Body>, idp: &str) -> Response<Body> {
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
        let Some(reg) = self.saml.as_ref().and_then(|r| r.registration(idp)) else {
            return Self::not_found();
        };
        let raw = super::rp::cookie_value(req.headers(), "access_token").unwrap_or_default();
        let Some(flow) = setjoin_identity::rp::LinkFlow::begin_saml(&session, &raw, &reg) else {
            return Self::failure(403, "fresh AAL2 step-up is required before linking", "");
        };
        let worker = self
            .recovery_worker
            .as_ref()
            .unwrap_or(&self.exec)
            .clone()
            .with_audit_keys(
                self.config.db_encryption_key.clone(),
                self.config.audit_hmac_key.clone(),
            );
        match flow.persist(&worker).await {
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
        let cookie = format!(
            "identity_link_flow={sealed}; Path=/; Max-Age=600; HttpOnly{}; SameSite=Strict",
            if self.totp_secure(&req) {
                "; Secure"
            } else {
                ""
            }
        );
        let mut reply = self.saml_login_reply(&req, &reg, "link", Some(flow.flow_id()));
        let later = reply
            .headers()
            .get_all("set-cookie")
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        reply.headers_mut().remove("set-cookie");
        reply
            .headers_mut()
            .append("set-cookie", cookie.parse().unwrap());
        for value in later {
            reply.headers_mut().append("set-cookie", value);
        }
        reply
    }
}

impl AuthServer {
    pub(super) async fn identity_unlink(&self, mut req: Request<Body>) -> Response<Body> {
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
        if !setjoin_identity::identity_links::fresh(&session) {
            return Self::failure(403, "fresh AAL2 step-up is required", "");
        }
        let path = percent_encoding::percent_decode_str(req.uri().path())
            .decode_utf8_lossy()
            .into_owned();
        let link = path
            .strip_prefix("/auth/identity-links/")
            .and_then(|v| v.parse::<i64>().ok());
        let Some(link) = link else {
            return Self::failure(400, "invalid identity unlink", "");
        };
        // Go decodes one JSON value through a 16KiB MaxBytesReader. Return as
        // soon as that value is complete; trailing bytes are never decoded.
        use http_body_util::BodyExt;
        let mut raw = Vec::new();
        let reason = loop {
            match super::ingress::fields(&raw, &["reason"]) {
                Ok(fields) => break fields.get("reason").filter(|s| !s.is_empty()).cloned(),
                Err(e) if !e.is_eof() => break None,
                _ => {}
            }
            if raw.len() == 16 << 10 {
                break None;
            }
            match req.body_mut().frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        raw.extend_from_slice(&data[..data.len().min((16 << 10) - raw.len())]);
                    }
                }
                _ => break None,
            }
        };
        let Some(reason) = reason else {
            return Self::failure(400, "invalid identity unlink", "");
        };
        let worker = self
            .recovery_worker
            .as_ref()
            .unwrap_or(&self.exec)
            .clone()
            .with_audit_keys(
                self.config.db_encryption_key.clone(),
                self.config.audit_hmac_key.clone(),
            );
        match setjoin_identity::identity_links::unlink(&worker, &session, link, &reason).await {
            setjoin_pg::CommandOutcome::Committed(raw) => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(body(raw))
                .unwrap(),
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut reply = Self::failure(503, "identity unlink commit failed", "");
                reply.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0)
                        .to_string()
                        .parse()
                        .unwrap(),
                );
                reply
            }
            setjoin_pg::CommandOutcome::RolledBack(
                setjoin_pg::Rejection::Statement(error) | setjoin_pg::Rejection::Body(error),
            ) if error
                .sqlstate
                .as_deref()
                .is_some_and(|s| s.starts_with("BZ")) =>
            {
                Self::rp_classified_link_failure(
                    &json!({"sqlstate":error.sqlstate,"hint":error.hint}),
                    &path,
                )
            }
            _ => Self::failure(409, "identity unlink failed", ""),
        }
    }
}

impl AuthServer {
    /// Library embeddings must attest both halves of the named task transfer.
    pub async fn start_saml_listener(
        &self,
        rust_on: &str,
        go_off: &str,
    ) -> Result<Option<setjoin_identity::saml::Listener>, String> {
        if !setjoin_identity::saml::admit_worker(rust_on, go_off)? {
            return Ok(None);
        }
        match &self.saml {
            Some(registry) => Ok(Some(registry.listen(&self.config.direct_dsn).await)),
            None => Ok(None),
        }
    }
}

/// Largest ACS form body: a 1 MiB document is 1.4 MiB of base64, which URL-encoding can
/// roughly triple. The decoded XML is separately capped at 1 MiB.
const ACS_BODY: usize = 4 << 20;

impl AuthServer {
    fn acs_cookie_clear(&self, req_secure: bool, reg: &setjoin_identity::saml::Registration, relay: &str) -> String {
        format!(
            "{}=; Path={}; Max-Age=0; HttpOnly{}",
            setjoin_identity::saml::Registration::tracking_cookie(relay),
            reg.acs_path(),
            if req_secure { "; Secure" } else { "" }
        )
    }
    /// One refusal: the audit row for its class, the single-use tracking cookie cleared,
    /// and a body that never says why (no oracle for an attacker iterating a message).
    #[allow(clippy::too_many_arguments)]
    async fn acs_refuse(
        &self,
        reg: &setjoin_identity::saml::Registration,
        status: u16,
        class: &str,
        detail: &str,
        path: &str,
        ip: &str,
        clear: Option<String>,
    ) -> Response<Body> {
        setjoin_identity::saml::audit(&self.exec, reg.id(), class, None, ip, detail).await;
        let mut reply = Self::failure(
            status,
            match status {
                400 => "invalid SAML response",
                413 => "SAML response too large",
                503 => "SAML authentication unavailable",
                _ => "SAML authentication failed",
            },
            path,
        );
        reply.headers_mut().insert("cache-control", "no-store".parse().unwrap());
        if let Some(cookie) = clear {
            reply.headers_mut().append("set-cookie", cookie.parse().unwrap());
        }
        reply
    }
    pub(super) async fn saml_acs(
        &self,
        req: Request<Body>,
        reg: Arc<setjoin_identity::saml::Registration>,
    ) -> Response<Body> {
        use base64::Engine;
        let path = req.uri().path().to_owned();
        let ip = self.client_ip(&req).to_string();
        let secure = self.totp_secure(&req);
        let (parts, incoming) = req.into_parts();
        let form = parts
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            });
        if !form {
            return self.acs_refuse(&reg, 400, "malformed", "not a form post", &path, &ip, None).await;
        }
        let raw = match Limited::new(incoming, ACS_BODY).collect().await {
            Ok(v) => v.to_bytes(),
            Err(_) => return self.acs_refuse(&reg, 413, "oversize", "form too large", &path, &ip, None).await,
        };
        let (mut response, mut relay) = (None::<String>, None::<String>);
        for (key, value) in form_urlencoded::parse(&raw) {
            let slot = match &*key {
                "SAMLResponse" => &mut response,
                "RelayState" => &mut relay,
                _ => continue,
            };
            if slot.replace(value.into_owned()).is_some() {
                return self.acs_refuse(&reg, 400, "malformed", "repeated form field", &path, &ip, None).await;
            }
        }
        let relay = relay.unwrap_or_default();
        let clear = setjoin_identity::saml::valid_relay(&relay)
            .then(|| self.acs_cookie_clear(secure, &reg, &relay));
        let Some(response) = response.filter(|s| !s.is_empty()) else {
            return self.acs_refuse(&reg, 400, "malformed", "no SAMLResponse", &path, &ip, clear).await;
        };
        let encoded: String = response.split_ascii_whitespace().collect();
        if encoded.len() > setjoin_identity::saml_acs::xml::MAX_XML / 3 * 4 + 8 {
            return self.acs_refuse(&reg, 413, "oversize", "SAMLResponse too large", &path, &ip, clear).await;
        }
        let Ok(xml) = base64::engine::general_purpose::STANDARD.decode(encoded.as_bytes()) else {
            return self.acs_refuse(&reg, 400, "malformed", "SAMLResponse is not base64", &path, &ip, clear).await;
        };
        // SP-initiated: the tracking cookie this SP signed for this relay token.
        let tracking = if setjoin_identity::saml::valid_relay(&relay) {
            super::rp::cookie_value(&parts.headers, &setjoin_identity::saml::Registration::tracking_cookie(&relay))
                .and_then(|jwt| reg.open_tracking(&relay, &jwt))
        } else {
            None
        };
        let link_flow = super::rp::cookie_value(&parts.headers, "identity_link_flow");
        if tracking.is_none() && (!reg.idp_initiated() || link_flow.is_some()) {
            let (class, why) = if link_flow.is_some() || reg.idp_initiated() {
                ("tracking", "no valid login-tracking cookie")
            } else {
                ("idp_initiated_refused", "IdP-initiated SSO is not enabled")
            };
            return self.acs_refuse(&reg, 401, class, why, &path, &ip, clear).await;
        }
        let request_id = tracking.as_ref().map(|t| t.request_id.as_str());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let claims = match reg.verify_acs(&xml, request_id, now) {
            Ok(c) => c,
            Err(fail) => {
                return self.acs_refuse(&reg, 401, fail.class, fail.detail, &path, &ip, clear).await;
            }
        };
        let worker = self.recovery_worker.as_ref().unwrap_or(&self.exec);
        match reg.consume(worker, &claims, request_id).await {
            setjoin_identity::saml::Consumed::Fresh => {}
            setjoin_identity::saml::Consumed::Replayed => {
                return self.acs_refuse(&reg, 401, "replay", "assertion or request already used", &path, &ip, clear).await;
            }
            setjoin_identity::saml::Consumed::Failed => {
                return self.acs_refuse(&reg, 503, "replay_unavailable", "replay cache unavailable", &path, &ip, clear).await;
            }
        }
        let groups = match reg.groups(&claims) {
            Ok(g) => g,
            Err(detail) => return self.acs_refuse(&reg, 401, "groups", detail, &path, &ip, clear).await,
        };
        let target = setjoin_identity::saml::relay_target(match &tracking {
            Some(t) => &t.uri,
            None => &relay,
        });
        let unbound = setjoin_identity::mutants::on("saml-purpose-unbound");
        // A link-purpose answer (SP-signed into the tracking cookie) never mints a session and
        // never provisions: it is held for the same session's same-site completion request,
        // because the IdP's cross-site POST carries no SameSite=Strict cookie.
        let link_purpose = if unbound {
            link_flow.is_some()
        } else {
            tracking.as_ref().is_some_and(|t| t.purpose == "link")
        };
        if link_purpose && !unbound && !setjoin_identity::mutants::on("saml-link-purpose-mints") {
            let held = match tracking.as_ref().and_then(|t| t.flow.as_deref()) {
                Some(flow) => reg.hold_link(worker, flow, &claims.name_id, &groups).await,
                None => None,
            };
            let Some(token) = held else {
                return self.acs_refuse(&reg, 503, "link_unavailable", "link completion could not be held", &path, &ip, clear).await;
            };
            setjoin_identity::saml::audit(&self.exec, reg.id(), "link_held", None, &ip, "link").await;
            let next = format!("{}?token={token}", reg.link_complete_path());
            let page = format!(
                "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0;url={next}\"></head><body><a href=\"{next}\">Continue</a></body></html>"
            );
            let mut reply = Response::builder()
                .status(200)
                .header("content-type", "text/html; charset=utf-8")
                .header("cache-control", "no-store")
                .header("referrer-policy", "no-referrer")
                .header("content-security-policy", "default-src 'none'")
                .body(body(page))
                .unwrap();
            if let Some(cookie) = clear {
                reply.headers_mut().append("set-cookie", cookie.parse().unwrap());
            }
            return reply;
        }
        let assertion = reg.assertion(&claims, groups);
        let req = Request::from_parts(parts, body(raw));
        let linking = unbound && link_flow.is_some();
        let (mut reply, actor) = if let (true, Some(flow)) = (linking, link_flow) {
            let (mut reply, actor) = self.saml_link_callback(&req, Some(&assertion), None, &reg, &flow).await;
            reply.headers_mut().append(
                "set-cookie",
                format!(
                    "identity_link_flow=; Path=/; Max-Age=0; HttpOnly{}; SameSite=Strict",
                    if secure { "; Secure" } else { "" }
                )
                .parse()
                .unwrap(),
            );
            (reply, actor)
        } else {
            self.saml_login(&req, &assertion, &reg, &claims, &target).await
        };
        if reply.status().is_redirection() {
            setjoin_identity::saml::audit(
                &self.exec,
                reg.id(),
                "success",
                actor,
                &ip,
                if linking { "link" } else { "login" },
            )
            .await;
        } else {
            setjoin_identity::saml::audit(
                &self.exec,
                reg.id(),
                "refused",
                None,
                &ip,
                &format!("status {}", reply.status().as_u16()),
            )
            .await;
        }
        if let Some(cookie) = clear {
            reply.headers_mut().append("set-cookie", cookie.parse().unwrap());
        }
        reply.headers_mut().insert("cache-control", "no-store".parse().unwrap());
        reply
    }
}

impl AuthServer {
    /// Resolve the verified (registration, NameID) pair, apply the OIDC RP's JIT policy
    /// and mint through the shared session reducers; success is a redirect, not JSON.
    async fn saml_login(
        &self,
        req: &Request<Body>,
        assertion: &setjoin_identity::rp::Assertion,
        reg: &Arc<setjoin_identity::saml::Registration>,
        claims: &setjoin_identity::saml_acs::Claims,
        target: &str,
    ) -> (Response<Body>, Option<i64>) {
        let path = req.uri().path();
        // Completion that Rust cannot yet finish natively stays with its owners.
        if self.rp_completion_unported(req).await {
            return (Self::failure(503, "SAML authentication unavailable", path), None);
        }
        let worker = self.recovery_worker.as_ref().unwrap_or(&self.exec);
        let resolution = match assertion.resolve(&self.exec, worker).await {
            Ok(setjoin_identity::rp::Lookup::Existing(resolution)) => resolution,
            Ok(setjoin_identity::rp::Lookup::Missing(miss)) => {
                // The OIDC RP's provisioning policy, unchanged (#546).
                if !(reg.jit() || self.config.jit_enabled)
                    && !setjoin_identity::mutants::on("saml-jit-always")
                {
                    return (Self::failure(401, "user not found", path), None);
                }
                let Some(email) = reg.email(claims) else {
                    return (Self::failure(400, "SAML authentication failed: no email in assertion", path), None);
                };
                // The address is no proof of identity, but a provisioned user must not collide
                // with one that exists (the legacy JIT does not check aliases).
                let address = setjoin_authz::address::canonical(&email);
                let taken = self
                    .exec
                    .read("SELECT identity_address_claim_count(lower($1))>0", &[(&address.as_str(), setjoin_pg::Type::TEXT)])
                    .await
                    .map(|r| r[0].get::<_, bool>(0));
                if taken.unwrap_or(true) && !setjoin_identity::mutants::on("saml-jit-collision") {
                    return (Self::failure(409, "explicit account linking is required", path), None);
                }
                match miss.create(&self.exec, worker).await {
                    Ok(resolution) => resolution,
                    Err(error) if error.message == "explicit account linking is required" => {
                        return (Self::failure(409, &error.message, path), None)
                    }
                    Err(_) => return (Self::failure(500, "user creation failed", path), None),
                }
            }
            Err(error) => {
                return (
                    Self::failure(
                        match error.message.as_str() {
                            "explicit account linking is required" => 409,
                            "sso: identity resolves to a guest account" => 401,
                            "account type resolution failed" => 500,
                            _ => 503,
                        },
                        &error.message,
                        path,
                    ),
                    None,
                )
            }
        };
        let actor = resolution.user().user();
        let reply = self.rp_complete(req, assertion, &**reg, &resolution, worker).await;
        if reply.status() != 200 {
            return (reply, None);
        }
        let mut redirect = Response::builder()
            .status(303)
            .header("location", target)
            .header("content-type", "text/html; charset=utf-8");
        for cookie in reply.headers().get_all("set-cookie") {
            redirect = redirect.header("set-cookie", cookie);
        }
        (redirect.body(body("")).unwrap(), Some(actor))
    }

    /// Complete a link the user's own session began (`begin_saml`): the sealed flow,
    /// the exact live session, fresh AAL2 and the one-use elevation all still apply.
    async fn saml_link_callback(
        &self,
        req: &Request<Body>,
        assertion: Option<&setjoin_identity::rp::Assertion>,
        held_token: Option<&str>,
        reg: &Arc<setjoin_identity::saml::Registration>,
        raw_flow: &str,
    ) -> (Response<Body>, Option<i64>) {
        if !login::enabled(&self.exec, "feature.identity_model_v2")
            .await
            .unwrap_or(false)
        {
            return (Self::not_found(), None);
        }
        let Some(flow) =
            setjoin_identity::rp::LinkFlow::open_saml(raw_flow, self.config.secret.as_bytes(), reg)
        else {
            return (Self::failure(400, "invalid identity link flow", ""), None);
        };
        let Some(raw) = super::rp::cookie_value(req.headers(), "access_token").filter(|s| !s.is_empty())
        else {
            return (Self::failure(401, "linking session expired", ""), None);
        };
        let Some(session) = self.legacy.as_ref().and_then(|legacy| {
            setjoin_identity::session::Session::verify(&raw, self.keys.as_deref(), legacy, &self.config.issuer)
        }) else {
            return (Self::failure(403, "linking session changed", ""), None);
        };
        let flow = match flow.authorize(&session, &raw, &self.exec).await {
            Ok(f) => f,
            Err(detail) => {
                return (
                    Self::failure(if detail == "linking session changed" { 403 } else { 401 }, detail, ""),
                    None,
                )
            }
        };
        let worker = self
            .recovery_worker
            .as_ref()
            .unwrap_or(&self.exec)
            .clone()
            .with_audit_keys(
                self.config.db_encryption_key.clone(),
                self.config.audit_hmac_key.clone(),
            );
        let held;
        let assertion = match (assertion, held_token) {
            (Some(a), _) => a,
            (None, Some(token)) => {
                // Single use, for this registration and this link flow only.
                let Some((subject, groups)) = reg.take_link(&worker, flow.flow_id(), token).await else {
                    return (Self::failure(401, "link completion expired or already used", ""), None);
                };
                held = reg.held_assertion(subject, groups);
                &held
            }
            (None, None) => return (Self::failure(400, "invalid identity link flow", ""), None),
        };
        let user = session.user();
        let reply = match flow
            .finish(&worker, assertion, &**reg, self.config.sso_allow_super_admin_mapping)
            .await
        {
            setjoin_pg::CommandOutcome::Committed(value) => match value["status"].as_str() {
                Some("linked") => {
                    return (
                        Response::builder()
                            .status(303)
                            .header("location", "/settings?identity=linked")
                            .header("content-type", "text/html; charset=utf-8")
                            .body(body("<a href=\"/settings?identity=linked\">See Other</a>.\n\n"))
                            .unwrap(),
                        Some(user),
                    )
                }
                Some("mapping_failed") | Some("normalized_failed") => {
                    Self::failure(409, "identity link entitlement reconciliation failed", "")
                }
                _ => Self::rp_classified_link_failure(&value, req.uri().path()),
            },
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut reply = Self::failure(503, "identity link commit failed", "");
                reply.headers_mut().insert(
                    "x-operation-id",
                    uuid::Uuid::from_bytes(operation.0).to_string().parse().unwrap(),
                );
                reply
            }
            _ => Self::failure(503, "identity link transaction unavailable", ""),
        };
        (reply, None)
    }
}

impl AuthServer {
    /// The same-site GET the ACS page sends the browser to: it carries the Strict cookies, so
    /// it can prove the held assertion belongs to the live session that started the link.
    async fn saml_link_complete(
        &self,
        req: Request<Body>,
        reg: Arc<setjoin_identity::saml::Registration>,
    ) -> Response<Body> {
        let ip = self.client_ip(&req).to_string();
        let secure = self.totp_secure(&req);
        let token = setjoin_identity::issuance::query(req.uri().query().unwrap_or(""))
            .get("token")
            .cloned()
            .unwrap_or_default();
        let Some(flow) = super::rp::cookie_value(req.headers(), "identity_link_flow") else {
            return Self::failure(401, "linking session expired", req.uri().path());
        };
        if token.is_empty() {
            return Self::failure(400, "invalid identity link flow", req.uri().path());
        }
        let (mut reply, actor) = self.saml_link_callback(&req, None, Some(&token), &reg, &flow).await;
        reply.headers_mut().append(
            "set-cookie",
            format!(
                "identity_link_flow=; Path=/; Max-Age=0; HttpOnly{}; SameSite=Strict",
                if secure { "; Secure" } else { "" }
            )
            .parse()
            .unwrap(),
        );
        if reply.status().is_redirection() {
            setjoin_identity::saml::audit(&self.exec, reg.id(), "success", actor, &ip, "link").await;
        } else {
            setjoin_identity::saml::audit(&self.exec, reg.id(), "refused", None, &ip, &format!("link status {}", reply.status().as_u16())).await;
        }
        reply.headers_mut().insert("cache-control", "no-store".parse().unwrap());
        reply
    }
}
