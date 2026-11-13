//! Thin OP HTTP adapter. The profile/store live in the Identity domain.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use setjoin_identity::oidc;
use setjoin_pg::Type;
fn form_error(raw: &str) -> Option<String> {
    for part in raw.split('&') {
        if part.contains(';') {
            return Some("invalid semicolon separator in query".into());
        }
        let bytes = part.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                if i + 2 >= bytes.len()
                    || !bytes[i + 1].is_ascii_hexdigit()
                    || !bytes[i + 2].is_ascii_hexdigit()
                {
                    return Some(format!(
                        "invalid URL escape {:?}",
                        String::from_utf8_lossy(&bytes[i..bytes.len().min(i + 3)])
                    ));
                }
                i += 3;
            } else {
                i += 1;
            }
        }
    }
    None
}
fn html_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}
fn valid_form(raw:&str)->String{raw.split('&').filter(|part|form_error(part).is_none()).collect::<Vec<_>>().join("&")}
fn basic(req: &Request<Body>) -> Result<Option<(String, String)>, ()> {
    let parsed = (|| {
        let auth = req.headers().get("authorization")?.to_str().ok()?;
        let (scheme, value) = auth.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("Basic") {
            return None;
        }
        let raw = STANDARD.decode(value).ok()?;
        let text = String::from_utf8(raw).unwrap_or_else(|_| "\0:".into());
        let (id, secret) = text.split_once(':')?;
        Some((id.to_owned(), secret.to_owned()))
    })();
    let Some((id, secret)) = parsed else {
        return Ok(None);
    };
    if form_error(&id.replace(';', "%3B")).is_some()
        || form_error(&secret.replace(';', "%3B")).is_some()
    {
        return Err(());
    }
    let decode = |s: &str| {
        percent_encoding::percent_decode_str(&s.replace('+', " "))
            .decode_utf8()
            .map(|s| s.into_owned())
            .map_err(|_| ())
    };
    Ok(Some((decode(&id)?, decode(&secret)?)))
}

impl AuthServer {
    pub(super) fn oidc_bare_oauth(&self, req: &Request<Body>) -> Response<Body> {
        let location = format!(
            "/oauth/{}",
            req.uri()
                .query()
                .map(|s| format!("?{s}"))
                .unwrap_or_default()
        );
        let mut r = Response::builder()
            .status(307)
            .header("location", &location);
        let text = if matches!(req.method(), &Method::GET | &Method::HEAD) {
            r = r.header("content-type", "text/html; charset=utf-8");
            format!(
                "<a href=\"{}\">Temporary Redirect</a>.\n\n",
                location.replace('&', "&amp;").replace('"', "&#34;")
            )
        } else {
            String::new()
        };
        r.body(body(if req.method() == Method::HEAD {
            String::new()
        } else {
            text
        }))
        .unwrap()
    }
    /// RFC 6749 §5.1 (owner-approved security fix 2026-11-05, #523): token
    /// responses, errors included, must never be cached.
    fn oidc_finish(&self, req: &Request<Body>, mut reply: Response<Body>) -> Response<Body> {
        if req.uri().path() == "/oauth/token" && !setjoin_identity::mutants::on("oidc-token-cacheable") {
            reply
                .headers_mut()
                .insert("cache-control", "no-store".parse().unwrap());
            reply
                .headers_mut()
                .insert("pragma", "no-cache".parse().unwrap());
        }
        self.oidc_cors(req, reply)
    }
    fn oidc_error(error: oidc::OAuthError) -> Response<Body> {
        let mut reply = Response::builder()
            .status(error.status())
            .header("content-type", "application/json");
        if let Some(operation) = error.operation {
            reply = reply.header("x-operation-id", setjoin_pg::operation_hex(operation));
        }
        reply.body(body(error.wire())).unwrap()
    }
    pub(super) async fn oidc_oauth(&self, req: Request<Body>) -> Response<Body> {
        if !self.config.oidc_enabled {
            return Self::not_found();
        }
        if req.method() == Method::OPTIONS
            && req.headers().contains_key("access-control-request-method")
        {
            return self.oidc_cors(&req, Response::new(body("")));
        }
        let req = if req.method() == Method::OPTIONS {
            req
        } else {
            match self.totp_ingress(req).await {
                Ok(req) => req,
                Err(reply) => return reply,
            }
        };
        let method = req.method().clone();
        let ip = self.client_ip(&req).to_string();
        let agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let raw_query = req.uri().query().unwrap_or("").to_owned();
        let url_fields = oidc::form_last(&valid_form(&raw_query));
        let mut form_failure = form_error(&raw_query);
        let mut dispatch_grant = setjoin_identity::issuance::query(&valid_form(&raw_query))
            .get("grant_type")
            .cloned();
        let mut fields = std::collections::BTreeMap::new();
        let (parts, input) = req.into_parts();
        let raw = input
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        if matches!(method, Method::POST | Method::PUT | Method::PATCH)
            && parts
                .headers
                .get("content-type")
                .and_then(|s| s.to_str().ok())
                .is_some_and(|s| s.split(';').next() == Some("application/x-www-form-urlencoded"))
        {
            let input = String::from_utf8_lossy(&raw);
            if let Some(error) = form_error(&input) {
                form_failure = Some(error);
            }
            if let Some(grant) = setjoin_identity::issuance::query(&valid_form(&input)).get("grant_type") {
                dispatch_grant = Some(grant.clone());
            }
            fields.extend(oidc::form_last(&valid_form(&input)));
        }
        fields.extend(url_fields);
        let req = Request::from_parts(parts, body(raw));
        if let Some(error) = form_failure.filter(|_|req.uri().path()!="/oauth/token" && !(req.uri().path()=="/userinfo"&&req.headers().get("authorization").and_then(|h|h.to_str().ok()).is_some_and(|h|h.get(..7).is_some_and(|p|p.eq_ignore_ascii_case("Bearer "))))) {
            let reply = match req.uri().path() {
                "/userinfo" => Self::oidc_plain(401, "access token missing"),
                "/oauth/introspect" => Self::oidc_plain(
                    401,
                    &format!(
                        "ErrorType=invalid_request Description=cannot parse form Parent={error}"
                    ),
                ),
                "/end_session" => Self::oidc_plain(
                    500,
                    &format!(
                        "ErrorType=invalid_request Description=error parsing form Parent={error}"
                    ),
                ),
                "/revoke" => Self::oidc_error(oidc::OAuthError::new(
                    "invalid_request",
                    "unable to parse request",
                )),
                _ => Self::oidc_error(oidc::OAuthError::new(
                    "invalid_request",
                    "error parsing form",
                )),
            };
            if method != Method::OPTIONS {
                self.oidc_attempt(&ip, &agent, reply.status().as_u16())
                    .await;
            }
            return self.oidc_finish(&req, reply);
        }
        let credentials = match if req.uri().path()=="/revoke"||req.uri().path()=="/oauth/introspect"||(req.uri().path()=="/oauth/token"&&dispatch_grant.as_deref().is_some_and(|g|matches!(g,"authorization_code"|"refresh_token"))){basic(&req)}else{Ok(None)} {
            Ok(c) => c,
            Err(()) => {
                let reply = if req.uri().path() == "/oauth/introspect" {
                    Self::oidc_plain(
                        401,
                        "ErrorType=invalid_client Parent=invalid basic auth header",
                    )
                } else {
                    Self::oidc_error(oidc::OAuthError::new(
                        "invalid_client",
                        "invalid basic auth header",
                    ))
                };
                if method != Method::OPTIONS {
                    self.oidc_attempt(&ip, &agent, reply.status().as_u16())
                        .await;
                }
                return self.oidc_finish(&req, reply);
            }
        };
        let cipher = self.oidc_cipher.as_ref().expect("enabled OP cipher");
        let issuer = format!("https://{}", self.config.oidc_hostname);
        let key = self.oidc_key.as_ref().expect("enabled OP key");
        let reply = if req.uri().path() == "/oauth/introspect" {
            if let Some((id, password)) = credentials.as_ref() {
                if oidc::authenticate(&self.exec, id, password).await {
                    let access = oidc::access(
                        key,
                        cipher,
                        &issuer,
                        fields.get("token").map(String::as_str).unwrap_or(""),
                    );
                    Response::builder()
                        .header("content-type", "application/json")
                        .body(body(
                            oidc::introspect(&self.exec, access.as_ref(), id).await,
                        ))
                        .unwrap()
                } else {
                    Self::oidc_plain(
                        401,
                        "ErrorType=unauthorized_client Parent=invalid client_id / client_secret",
                    )
                }
            } else {
                Self::oidc_plain(
                    401,
                    "ErrorType=invalid_client Parent=no client credentials provided",
                )
            }
        } else if req.uri().path() == "/userinfo" {
            let token = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .filter(|v| {
                    v.get(..7)
                        .is_some_and(|s| s.eq_ignore_ascii_case("Bearer "))
                })
                .map(|v| &v[7..])
                .unwrap_or_else(|| fields.get("access_token").map(String::as_str).unwrap_or(""));
            match oidc::access(key, cipher, &issuer, token) {
                None => Self::oidc_plain(401, "access token invalid"),
                Some(access) => match oidc::userinfo(&self.exec, &access).await {
                    Some(info) => Response::builder()
                        .header("content-type", "application/json")
                        .body(body(info))
                        .unwrap(),
                    None => Response::builder()
                        .status(403)
                        .header("content-type", "application/json")
                        .body(body("{}\n"))
                        .unwrap(),
                },
            }
        } else if req.uri().path() == "/revoke" {
            match oidc::revoke(
                &self.exec,
                key,
                cipher,
                &issuer,
                &fields,
                credentials.as_ref().map(|(a, b)| (a.as_str(), b.as_str())),
            )
            .await
            {
                Ok(()) => Response::builder()
                    .header("content-type", "application/json")
                    .body(body(""))
                    .unwrap(),
                Err(e) => Self::oidc_error(e),
            }
        } else if req.uri().path() == "/end_session" {
            match oidc::end_session(&self.exec, key, &issuer, &fields).await {
                Ok(location) => Self::oidc_redirect(&method, &location),
                Err(e) => Self::oidc_error(e),
            }
        } else if req.uri().path() != "/oauth/token" {
            Self::not_found()
        } else {
            let assertion = fields
                .get("client_assertion")
                .is_some_and(|s| !s.is_empty()) && fields.get("client_assertion_type").is_some_and(|s|!s.is_empty());
            let form_secret = fields.get("client_id").is_some_and(|s| !s.is_empty())
                && fields.get("client_secret").is_some_and(|s| !s.is_empty());
            if (assertion && form_secret) || (credentials.is_some() && (assertion || form_secret)) {
                let reply = Self::oidc_error(oidc::OAuthError::new(
                    "invalid_request",
                    "client authentication must not use more than one method",
                ));
                if method != Method::OPTIONS {
                    self.oidc_attempt(&ip, &agent, reply.status().as_u16())
                        .await;
                }
                return self.oidc_finish(&req, reply);
            }
            if let Some((id, password)) = credentials.as_ref() {
                fields.insert("client_id".into(), id.clone());
                fields.insert("client_secret".into(), password.clone());
            }
            let grant = dispatch_grant.as_deref().unwrap_or("");
            if grant == "authorization_code" {
                match oidc::code_exchange(
                    &self.exec,
                    self.oidc_key.as_ref().expect("enabled OP key"),
                    &format!("https://{}", self.config.oidc_hostname),
                    &fields,
                )
                .await
                {
                    Ok(tokens) => Response::builder()
                        .header("content-type", "application/json")
                        .body(body(tokens.wire()))
                        .unwrap(),
                    Err(error) => Self::oidc_error(error),
                }
            } else if grant == "refresh_token" {
                match oidc::refresh_exchange(
                    &self.exec,
                    self.oidc_key.as_ref().expect("enabled OP key"),
                    &format!("https://{}", self.config.oidc_hostname),
                    &fields,
                )
                .await
                {
                    Ok(tokens) => Response::builder()
                        .header("content-type", "application/json")
                        .body(body(tokens.wire()))
                        .unwrap(),
                    Err(error) => Self::oidc_error(error),
                }
            } else {
                Self::oidc_error(oidc::OAuthError::new(
                    if grant.is_empty() {
                        "invalid_request"
                    } else {
                        "unsupported_grant_type"
                    },
                    if grant.is_empty() {
                        "grant_type missing".into()
                    } else {
                        format!("{grant} not supported")
                    },
                ))
            }
        };
        if method != Method::OPTIONS {
            self.oidc_attempt(&ip, &agent, reply.status().as_u16())
                .await;
        }
        self.oidc_finish(&req, reply)
    }
    fn oidc_callback_error(
        method: &Method,
        request: &oidc::Authorization,
        kind: &str,
        description: &str,
    ) -> Response<Body> {
        Self::oidc_redirect(
            method,
            &oidc::query_response(
                request.redirect(),
                &[
                    ("error", kind),
                    ("error_description", description),
                    ("state", request.state()),
                ],
                false,
            ),
        )
    }
    pub(super) async fn oidc_callback(&self, req: Request<Body>) -> Response<Body> {
        if !self.config.oidc_enabled {
            return Self::not_found();
        }
        if req.method() == Method::OPTIONS
            && req.headers().contains_key("access-control-request-method")
        {
            return self.oidc_cors(&req, Response::new(body("")));
        }
        let req = if req.method() == Method::OPTIONS {
            req
        } else {
            match self.totp_ingress(req).await {
                Ok(req) => req,
                Err(reply) => return reply,
            }
        };
        // Owner-approved security fix 2026-11-05 (#523): the callback mints the
        // code for the browser session that completed the request, never for an
        // anonymous or foreign caller holding only the request id.
        // Only a real CORS preflight (answered above) is sessionless; any other
        // method, OPTIONS included, must present the bound user's session.
        let session = if (req.method() == Method::OPTIONS && setjoin_identity::mutants::on("oidc-callback-options-bypass")) || setjoin_identity::mutants::on("oidc-callback-anonymous") {
            None
        } else {
            match self.totp_session(&req) {
                Ok(s) => Some(s),
                Err(crate::totp::Admission::Forward) => return self.forward(req).await,
                Err(crate::totp::Admission::Denied(r)) => return r,
            }
        };
        let ip = self.client_ip(&req).to_string();
        let agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let fields = setjoin_identity::issuance::query(req.uri().query().unwrap_or(""));
        let id = fields.get("id").map(String::as_str).unwrap_or("");
        let reply=async {
            if id.is_empty(){return Self::oidc_plain(400,"auth request callback is missing id");}
            let request=match oidc::request(&self.exec,id).await {
                Ok(Some(r))=>r,
                Ok(None)=>return Self::oidc_plain(400,"auth request not found: no rows in result set"),
                Err(_)=>return Self::oidc_plain(400,"auth request not found"),
            };
            if let Some(session)=&session{if request.user()!=Some(session.user()){return Self::oidc_plain(400,"auth request not found: no rows in result set");}}
            if !request.done(){return Self::oidc_callback_error(req.method(),&request,"interaction_required","Unfortunately, the user may be not logged in and/or additional interaction is required.");}
            if let Err(error)=oidc::client(&self.exec,request.client()).await{return Self::oidc_callback_error(req.method(),&request,"server_error",&error);}
            let code=match self.oidc_cipher.as_ref().expect("enabled OP cipher").encrypt(request.id()){Ok(code)=>code,Err(error)=>return Self::oidc_callback_error(req.method(),&request,"server_error",&error)};
            let operation=setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes());
            match oidc::bind_code(&self.exec,&request,&code,operation).await {
                setjoin_pg::CommandOutcome::Committed(true)=>Self::oidc_redirect(req.method(),&oidc::query_response(request.redirect(),&[("code",&code),("state",request.state())],false)),
                setjoin_pg::CommandOutcome::Unknown{operation}=>{
                    let mut reply=Self::oidc_callback_error(req.method(),&request,"server_error","authorization code binding outcome unknown");reply.headers_mut().insert("x-operation-id",setjoin_pg::operation_hex(operation).parse().unwrap());reply
                },
                _=>Self::oidc_callback_error(req.method(),&request,"server_error","authorization request is missing, expired, incomplete, or already has a code"),
            }
        }.await;
        if req.method() != Method::OPTIONS {
            self.oidc_attempt(&ip, agent, reply.status().as_u16()).await;
        }
        self.oidc_cors(&req, reply)
    }
    /// Owner-approved security fix 2026-11-05 (#523): binding an authorization
    /// request to a session is a state change, so a bare GET (a link, an image, a
    /// redirect an attacker can lure the victim into) only renders a consent page;
    /// the bind itself is a same-origin POST carrying an HMAC synchroniser token.
    pub(super) async fn oidc_complete(&self, req: Request<Body>) -> Response<Body> {
        if !self.config.oidc_enabled {
            return Self::not_found();
        }
        let method = req.method().clone();
        if !matches!(method, Method::GET | Method::HEAD | Method::POST) {
            let mut r = Self::oidc_plain(405, "Method Not Allowed");
            r.headers_mut()
                .insert("allow", "GET, HEAD, POST".parse().unwrap());
            return r;
        }
        let browse = matches!(method, Method::GET | Method::HEAD);
        let login = || {
            Self::oidc_redirect(
                &method,
                &oidc::query_response(
                    "/",
                    &[(
                        "continue",
                        req.uri().path_and_query().map_or("/", |v| v.as_str()),
                    )],
                    false,
                ),
            )
        };
        let session = match self.totp_session(&req) {
            Ok(s) => s,
            Err(crate::totp::Admission::Forward) => return self.forward(req).await,
            Err(crate::totp::Admission::Denied(r)) if r.status() == 401 && browse => return login(),
            Err(crate::totp::Admission::Denied(r)) => return r,
        };
        // Go decodes these into typed Claims before middleware accepts them.
        if session
            .claims()
            .get("acr")
            .is_some_and(|v| !v.is_null() && !v.is_string())
            || session.claims().get("amr").is_some_and(|v| {
                !v.is_null() && !v.as_array().is_some_and(|a| a.iter().all(Value::is_string))
            })
            || session
                .claims()
                .get("auth_time")
                .is_some_and(|v| !v.is_null() && v.as_i64().is_none())
        {
            return if browse { login() } else { Self::failure(401, "Unauthorized", "") };
        }
        if session.user() <= 0 {
            return Self::failure(401, "Unauthorized", "");
        }
        let cipher = self.oidc_cipher.as_ref().expect("enabled OP cipher");
        // The session family (stable across refreshes) or, failing that, the jti.
        let binding = |id: &str| {
            let anchor = if session.text("fam").is_empty() { session.text("jti") } else { session.text("fam") };
            format!("op-complete|{}|{anchor}|{id}", session.user())
        };
        let invalid = || Self::failure(400, "Invalid authorization request", "");
        let query = setjoin_identity::issuance::query(req.uri().query().unwrap_or(""));
        if browse {
            let id = query.get("id").map(String::as_str).unwrap_or("");
            if id.is_empty() || id.len() > 256 {
                return invalid();
            }
            if setjoin_identity::mutants::on("oidc-complete-get-bind") {
                return self.oidc_bind(&method, &session, id).await;
            }
            let pending = match oidc::request(&self.exec, id).await {
                Ok(Some(r)) if r.user().is_none() && !r.done() => r,
                _ => return invalid(),
            };
            let page = format!(
                "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Authorize sign-in</title></head><body>\n<form method=\"post\" action=\"/auth/oidc/op/complete\">\n<p>Allow <b>{}</b> to sign you in as {}?</p>\n<input type=\"hidden\" name=\"id\" value=\"{}\">\n<input type=\"hidden\" name=\"csrf\" value=\"{}\">\n<button type=\"submit\">Continue</button>\n</form></body></html>\n",
                html_escape(pending.client()),
                html_escape(session.text("email")),
                html_escape(id),
                cipher.csrf_token(&binding(id)),
            );
            return Response::builder()
                .status(200)
                .header("content-type", "text/html; charset=utf-8")
                .header("cache-control", "no-store")
                .header("x-frame-options", "DENY")
                .header("content-security-policy", "frame-ancestors 'none'; form-action 'self'")
                .header("x-content-type-options", "nosniff")
                .body(body(if method == Method::HEAD { String::new() } else { page }))
                .unwrap();
        }
        let skip = setjoin_identity::mutants::on("oidc-complete-no-csrf");
        let (headers, scheme) = Self::csrf_context(&req);
        if !skip && !setjoin_authz::csrf::allows(&headers, scheme) {
            return Response::builder()
                .status(403)
                .header("content-type", "application/problem+json")
                .body(body(problem::middleware(403, "csrf_failed", "CSRF validation failed")))
                .unwrap();
        }
        let raw = match http_body_util::Limited::new(req.into_body(), 8192).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return invalid(),
        };
        let form = oidc::form_last(&String::from_utf8_lossy(&raw));
        let id = form.get("id").map(String::as_str).unwrap_or("");
        if id.is_empty() || id.len() > 256 {
            return invalid();
        }
        let token = form.get("csrf").map(String::as_str).unwrap_or("");
        if !skip && !cipher.csrf_valid(&binding(id), token) {
            return Response::builder()
                .status(403)
                .header("content-type", "application/problem+json")
                .body(body(problem::middleware(403, "csrf_failed", "CSRF validation failed")))
                .unwrap();
        }
        self.oidc_bind(&method, &session, id).await
    }
    async fn oidc_bind(&self, method: &Method, session: &setjoin_identity::session::Session, id: &str) -> Response<Body> {
        let operation = setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes());
        match oidc::complete_request(&self.exec, session, id, operation).await {
            setjoin_pg::CommandOutcome::Committed(true) => Self::oidc_redirect(
                method,
                &oidc::query_response("/authorize/callback", &[("id", id)], false),
            ),
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = Self::failure(400, "Invalid authorization request", "");
                r.headers_mut().insert(
                    "x-operation-id",
                    setjoin_pg::operation_hex(operation).parse().unwrap(),
                );
                r
            }
            _ => Self::failure(400, "Invalid authorization request", ""),
        }
    }
    fn oidc_plain(status: u16, text: &str) -> Response<Body> {
        Response::builder()
            .status(status)
            .header("content-type", "text/plain; charset=utf-8")
            .header("x-content-type-options", "nosniff")
            .body(body(format!("{text}\n")))
            .unwrap()
    }
    fn oidc_redirect(method: &Method, location: &str) -> Response<Body> {
        let mut reply = Response::builder().status(302).header("location", location);
        let text = if matches!(method, &Method::GET | &Method::HEAD) {
            reply = reply.header("content-type", "text/html; charset=utf-8");
            let escaped = location
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&#34;")
                .replace('\'', "&#39;");
            format!("<a href=\"{escaped}\">Found</a>.\n\n")
        } else {
            String::new()
        };
        reply
            .body(body(if method == Method::HEAD {
                String::new()
            } else {
                text
            }))
            .unwrap()
    }
    async fn oidc_attempt(&self, ip: &str, agent: &str, status: u16) {
        let outcome = if matches!(status, 200 | 204) {
            "success"
        } else {
            "failure"
        };
        let fp = setjoin_threat::fingerprint(agent, ip);
        // Independent Go threat tail. OP does not attach a verified user to
        // this context; no sign-in/device row is invented for the token subject.
        let _=self.exec.protocol_statement("INSERT INTO auth_attempts(source_ip,target_username,protocol,outcome,geo_country,device_fingerprint) VALUES($1::inet,'','http',$2,'',$3)",&[(&ip,Type::TEXT),(&outcome,Type::TEXT),(&fp,Type::TEXT)]).await;
    }
    pub(super) async fn oidc_authorize(&self, req: Request<Body>) -> Response<Body> {
        if !self.config.oidc_enabled {
            return Self::not_found();
        }
        if req.method() == Method::OPTIONS
            && req.headers().contains_key("access-control-request-method")
        {
            return self.oidc_cors(&req, Response::new(body("")));
        }
        let req = if req.method() == Method::OPTIONS {
            req
        } else {
            match self.totp_ingress(req).await {
                Ok(req) => req,
                Err(reply) => return reply,
            }
        };
        let method = req.method().clone();
        let ip = self.client_ip(&req).to_string();
        let agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let raw_query = req.uri().query().unwrap_or("").to_owned();
        let url_fields = oidc::form_last(&valid_form(&raw_query));
        let mut form_failure = form_error(&raw_query);
        let mut dispatch_grant = setjoin_identity::issuance::query(&valid_form(&raw_query))
            .get("grant_type")
            .cloned();
        let mut fields = std::collections::BTreeMap::new();
        let (parts, input) = req.into_parts();
        let raw = input
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        if matches!(method, Method::POST | Method::PUT | Method::PATCH)
            && parts
                .headers
                .get("content-type")
                .and_then(|s| s.to_str().ok())
                .is_some_and(|s| s.split(';').next() == Some("application/x-www-form-urlencoded"))
        {
            let input = String::from_utf8_lossy(&raw);
            if let Some(error) = form_error(&input) {
                form_failure = Some(error);
            }
            if let Some(grant) = setjoin_identity::issuance::query(&valid_form(&input)).get("grant_type") {
                dispatch_grant = Some(grant.clone());
            }
            fields.extend(oidc::form_last(&valid_form(&input)));
        }
        fields.extend(url_fields);
        let req = Request::from_parts(parts, body(raw));
        let get = |k: &str| fields.get(k).map(String::as_str).unwrap_or("");
        let _ = dispatch_grant;
        let reply=async {
            if let Some(error)=form_failure{return Self::oidc_plain(400,&format!("ErrorType=invalid_request Description=cannot parse form Parent={error}"));}
            if fields.get("max_age").is_some_and(|v|v.parse::<u64>().is_err()){return Self::oidc_plain(400,"ErrorType=invalid_request Description=cannot parse auth request Parent=schema: error converting value for \"max_age\"");}
            if get("client_id").is_empty(){return Self::oidc_plain(400,"auth request is missing client_id");}
            if get("redirect_uri").is_empty(){return Self::oidc_plain(400,"auth request is missing redirect_uri");}
            let client=match oidc::client(&self.exec,get("client_id")).await{Ok(c)=>c,Err(_)=>return Self::oidc_plain(400,"unable to retrieve client by id")};
            if let Some(error)=oidc::redirect_error(&client,get("redirect_uri"),get("response_type")){return Self::oidc_plain(400,error);}
            let fail=|kind:&str,description:&str|Self::oidc_redirect(&method,&oidc::query_response(get("redirect_uri"),&[("error",kind),("error_description",description),("state",get("state"))],get("response_mode")=="fragment"));
            if get("prompt").split(' ').any(|p|p=="none")&&get("prompt").split(' ').count()>1{return fail("invalid_request","The prompt parameter `none` must only be used as a single value");}
            if !fields.contains_key("scope") {
                return Self::oidc_redirect(&method,&oidc::query_response(get("redirect_uri"),&[("error","invalid_request"),("error_description","The scope of your request is missing. Please ensure some scopes are requested. If you have any questions, you may contact the administrator of the application."),("state",get("state"))],get("response_mode")=="fragment" || (get("response_mode").is_empty() && matches!(get("response_type"),"id_token"|"id_token token"))));
            }
            let scopes:Vec<String>=get("scope").split(' ').filter(|s|matches!(*s,"openid"|"profile"|"email"|"phone"|"address"|"offline_access") || client.scopes.iter().any(|a|a==s)).map(str::to_owned).collect();
            if get("response_type")!="code" {
                let (kind,description)=if get("response_type").is_empty(){("invalid_request","The response type is missing in your request. If you have any questions, you may contact the administrator of the application.")}else{("unauthorized_client","The requested response type is missing in the client configuration. If you have any questions, you may contact the administrator of the application.")};
                return Self::oidc_redirect(&method,&oidc::query_response(get("redirect_uri"),&[("error",kind),("error_description",description),("state",get("state"))],get("response_mode")=="fragment" || (get("response_mode").is_empty() && matches!(get("response_type"),"id_token"|"id_token token"))));
            }
            // OAuth 2.1 (#523): a confidential client without a PKCE challenge would only get an unredeemable code.
            if !client.public&&get("code_challenge").is_empty()&&!setjoin_identity::mutants::on("oidc-confidential-authorize-no-pkce"){return fail("invalid_request","code_challenge is required: PKCE must be used by every client");}
            if !get("id_token_hint").is_empty()&&!self.oidc_key.as_ref().unwrap().verify(get("id_token_hint")).is_some_and(|c|c["iss"]==format!("https://{}",self.config.oidc_hostname)){return fail("login_required","The id_token_hint is invalid. If you have any questions, you may contact the administrator of the application.");}
            if !get("request").is_empty(){return fail("request_not_supported","");}
            match oidc::create_request(&self.exec,&client,get("redirect_uri"),get("state"),get("nonce"),get("code_challenge"),get("code_challenge_method"),&scopes,setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes())).await {
                setjoin_pg::CommandOutcome::Committed(id)=>Self::oidc_redirect(&method,&format!("/auth/oidc/op/complete?id={id}")),
                setjoin_pg::CommandOutcome::Unknown{operation}=>{let mut r=Self::oidc_plain(500,"unable to save auth request");r.headers_mut().insert("x-operation-id",setjoin_pg::operation_hex(operation).parse().unwrap());r},
                _=>Self::oidc_plain(500,"unable to save auth request"),
            }
        }.await;
        if method != Method::OPTIONS {
            self.oidc_attempt(&ip, &agent, reply.status().as_u16())
                .await;
        }
        self.oidc_cors(&req, reply)
    }
}
