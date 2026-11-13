//! F05 slice `migration` HTTP adapter (#293): job list/get/delete, the global
//! source profiles, job controls, provider connection tests and Microsoft consent
//! callback. All migration shapes are native (#446). Gates mirror Go's chain:
//! `requireMailPerm` (reads) or `requireMailPipeline` (writes and the consent
//! start), then `requireOrgWideSurface`, from the live governed grants.
use crate::admin_identity_input::query;
use crate::mailboxes::{bare, body, json_body, segment, segment_path, unknown_outcome};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use setjoin_authz::token::KeySource;
use setjoin_mailboxes::migration as db;
use setjoin_mailboxes::private_policy;
use setjoin_pg::{CommandOutcome, ScopedExecutor};
use std::fmt;
use std::sync::Arc;

pub struct MigrationRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    /// Raw `DB_ENCRYPTION_KEY`: the root Go derives the `system` key from.
    pub encryption_key: String,
    /// The job runner (#431) and the worker credential its routes read and write
    /// with. Without one the routes that drive it are not matched and stay with Go.
    pub runner: Option<Runner>,
    /// The configured public host (`HOSTNAME`): the only host the M365 consent
    /// `redirect_uri` is ever built from (owner-approved security fix 2026-11-05, #430).
    pub public_host: String,
}

/// Whether `HOSTNAME` names a real public host: set, non-empty and not loopback `localhost`.
pub fn public_host_usable(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.');
    !host.is_empty() && !host.eq_ignore_ascii_case("localhost")
}

/// The Microsoft admin-consent URL. Owner-approved security fix 2026-11-05 (#430): `client_id` is
/// query-escaped and `redirect_uri` is built from the configured public host, never from the
/// client-supplied `Host` header (frozen Go concatenated the stored client id unescaped and
/// trusted the Host header, so a poisoned Host steered the consent to an attacker's host).
pub fn consent_url(
    auth_base: &str,
    client_id: &str,
    public_host: &str,
    request_host: &str,
    token: &str,
) -> String {
    let restored = setjoin_contracts::mutants::on("m365-consent-untrusted");
    let host = if restored { request_host } else { public_host };
    let client = if restored {
        client_id.to_owned()
    } else {
        query_escape(client_id)
    };
    let redirect = format!("https://{host}/admin/migration/m365/callback");
    format!(
        "{auth_base}/organizations/adminconsent?client_id={client}&redirect_uri={}&state={}",
        query_escape(&redirect),
        query_escape(token)
    )
}

#[derive(Clone)]
pub struct Runner {
    pub orchestrator: crate::migration_runner::Orchestrator,
    pub worker: ScopedExecutor,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Action {
    Jobs,
    Job,
    JobDelete,
    SourceGet,
    SourceDelete,
    PutImap,
    PutEws,
    PutM365,
    Connect,
    Callback,
    Start,
    TestConnection,
    Cancel,
    Retry,
    Pause,
    Resume,
}

pub(crate) fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let post = *method == Method::POST;
    let table: [(bool, &str, Action); 16] = [
        (reads, "/api/admin/migration/jobs", Action::Jobs),
        (reads, "/api/admin/migration/jobs/{id}", Action::Job),
        (
            *method == Method::DELETE,
            "/api/admin/migration/jobs/{id}",
            Action::JobDelete,
        ),
        (
            reads,
            "/api/admin/migration/source/{type}",
            Action::SourceGet,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/migration/source/{type}",
            Action::SourceDelete,
        ),
        (
            *method == Method::PUT,
            "/api/admin/migration/source/imap",
            Action::PutImap,
        ),
        (
            *method == Method::PUT,
            "/api/admin/migration/source/ews",
            Action::PutEws,
        ),
        (
            *method == Method::PUT,
            "/api/admin/migration/source/m365",
            Action::PutM365,
        ),
        (reads, "/api/admin/migration/m365/connect", Action::Connect),
        (
            reads,
            "/api/admin/migration/m365/callback",
            Action::Callback,
        ),
        (post, "/api/admin/migration/start", Action::Start),
        (
            post,
            "/api/admin/migration/test-connection",
            Action::TestConnection,
        ),
        (
            post,
            "/api/admin/migration/jobs/{id}/cancel",
            Action::Cancel,
        ),
        (post, "/api/admin/migration/jobs/{id}/retry", Action::Retry),
        (post, "/api/admin/migration/jobs/{id}/pause", Action::Pause),
        (
            post,
            "/api/admin/migration/jobs/{id}/resume",
            Action::Resume,
        ),
    ];
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| *action)
}

body!(ImapBody {
    host: String = "host",
    port: i64 = "port",
    tls_mode: String = "tls_mode",
    private_hosts: Vec<Option<String>> = "private_hosts",
    private_cidrs: Vec<Option<String>> = "private_cidrs"
});
body!(EwsBody {
    url: String = "serverurl",
    username: String = "username",
    password: String = "password",
    auth_mode: String = "authmode",
    insecure: bool = "insecureskipverify",
    private_hosts: Vec<Option<String>> = "privatehosts",
    private_cidrs: Vec<Option<String>> = "privatecidrs"
});
body!(StartTarget {
    source_email: String = "source_email",
    target_email: String = "target_email",
    password: String = "password"
});
body!(StartBody {
    source_type: String = "source_type",
    auth_mode: String = "auth_mode",
    targets: Vec<StartTarget> = "targets",
    imap_host: String = "imap_host",
    imap_port: i64 = "imap_port",
    imap_ssl: Option<bool> = "imap_ssl",
    ews_url: String = "ews_url",
    ews_username: String = "ews_username",
    ews_password: String = "ews_password"
});
body!(TestBody {
    source_type: String = "source_type",
    host: String = "host",
    port: i64 = "port",
    ssl: Option<bool> = "ssl",
    url: String = "url",
    username: String = "username",
    password: String = "password"
});
body!(M365Body {
    client_id: String = "client_id",
    client_secret: String = "client_secret",
    tenant_id: String = "tenant_id",
    cloud: String = "cloud",
    source_email: String = "source_email",
    source_user_id: String = "source_user_id"
});

fn flat(items: Vec<Option<String>>) -> Vec<String> {
    items.into_iter().map(Option::unwrap_or_default).collect()
}

/// Go's `url.QueryEscape`.
fn query_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

/// Go's `http.Error`: plain text with a newline.
fn text_error(status: u16, message: &str, c: &RequestContext, id: &str) -> Response<Body> {
    let mut response =
        crate::jmap::reply::response(format!("{message}\n"), c.identity.proto, id.to_owned());
    *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
    response.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

impl<K: KeySource + 'static> Intercept for MigrationRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool {
        true
    }
    fn matches(&self, r: &Request<Body>) -> bool {
        action(r.method(), r.uri().path()).is_some()
    }
    fn admits_member(&self, headers: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_request(&exec, &keys, &issuer, &headers, scheme)
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer, root) = (
            self.exec.clone(),
            self.keys.clone(),
            self.issuer.clone(),
            self.encryption_key.clone(),
        );
        let runner = self.runner.clone();
        let public_host = self.public_host.clone();
        Box::pin(async move {
            let Some(what) = action(r.method(), r.uri().path()) else {
                return bare(503, "service unavailable", &c, "");
            };
            let Some(auth) = setjoin_authz::authorize_request(
                &exec,
                &keys,
                &issuer,
                r.headers(),
                c.identity.proto,
            )
            .await
            else {
                return bare(401, "Unauthorized", &c, "");
            };
            let Some(operation) = crate::jmap::random() else {
                return bare(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let actor = auth.context();
            let Ok(authority) = setjoin_mailboxes::authority(&exec, actor).await else {
                return bare(503, "service unavailable", &c, "");
            };
            let path = r.uri().path().to_owned();
            let go_path = segment_path(&path);
            let required: &[&str] = match what {
                Action::Jobs | Action::Job | Action::SourceGet => &setjoin_mailboxes::MAIL_CONSOLE,
                _ => &db::PIPELINE,
            };
            if !authority.allows_any(required) {
                let _ = setjoin_mailboxes::console_denied(
                    &exec,
                    actor,
                    &go_path,
                    &required.join("|"),
                    operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            }
            // `requireOrgWideSurface`: a domain-scoped principal is refused, audited.
            if authority.domain_scope() != 0 {
                let detail = format!(
                    "org-wide-only surface (domain-scoped principal; domain={})",
                    authority.domain_scope()
                );
                let _ =
                    setjoin_mailboxes::console_denied(&exec, actor, &go_path, &detail, operation)
                        .await;
                return bare(403, "Forbidden", &c, &id);
            }
            let head = r.method() == Method::HEAD;
            let reply = |body: String| {
                // net/http buffers 2 KiB of a handler's output; a larger single
                // write is flushed before the handler returns and sent chunked.
                let chunked = body.len() > 2048 && !head;
                let mut response = crate::jmap::reply::response(body, c.identity.proto, id.clone());
                if chunked {
                    response.headers_mut().insert(
                        "transfer-encoding",
                        hyper::header::HeaderValue::from_static("chunked"),
                    );
                }
                response
            };
            let problem = |status: u16, detail: &str| bare(status, detail, &c, &id);
            let status_only = |status: u16| {
                let mut response =
                    crate::jmap::reply::response(String::new(), c.identity.proto, id.clone());
                *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
                response.headers_mut().remove("content-type");
                response
            };
            let job_id = || segment(&path, 5).parse::<i64>();
            match what {
                Action::Jobs => {
                    let status = query(r.uri(), "status").unwrap_or_default();
                    let user = query(r.uri(), "user_id").unwrap_or_default();
                    match db::list(&exec, &status, &user).await {
                        Ok(body) => reply(body),
                        Err(_) => problem(500, "query failed"),
                    }
                }
                Action::Job => {
                    let Ok(job) = job_id() else {
                        return problem(400, "invalid job id");
                    };
                    match db::get(&exec, job).await {
                        Some(body) => reply(body),
                        None => problem(404, "job not found"),
                    }
                }
                Action::JobDelete => {
                    let Ok(job) = job_id() else {
                        return problem(400, "invalid job id");
                    };
                    match db::delete(&exec, actor, job, operation).await {
                        CommandOutcome::Committed(true) => status_only(204),
                        CommandOutcome::Committed(false) => problem(404, "job not found"),
                        CommandOutcome::RolledBack(_) => problem(500, "delete failed"),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::SourceGet => {
                    let source = segment(&path, 5);
                    let Some(key) = db::config_key(&source) else {
                        return problem(404, "unknown source type");
                    };
                    let Some((value, encrypted)) = db::config(&exec, key).await else {
                        return problem(404, "config not found");
                    };
                    if source == "imap" && !value.is_empty() {
                        return reply(value);
                    }
                    if encrypted {
                        match db::unseal(&value, &root) {
                            db::Unsealed::BadWrapper => {
                                return problem(500, "invalid encrypted config")
                            }
                            db::Unsealed::BadBase64 => {
                                return problem(500, "invalid encrypted data")
                            }
                            db::Unsealed::Undecryptable => {}
                            db::Unsealed::Plain(plain) => {
                                if source == "ews" {
                                    if let Ok(mut cfg) = db::Ews::from_value(&plain) {
                                        cfg.password.clear();
                                        return reply(with_newline(cfg.json()));
                                    }
                                } else if source == "m365" {
                                    if let Ok(mut cfg) = db::M365::from_value(&plain) {
                                        cfg.client_secret.clear();
                                        return reply(with_newline(cfg.json()));
                                    }
                                }
                            }
                        }
                    }
                    problem(404, "config not found")
                }
                Action::SourceDelete => {
                    let source = segment(&path, 5);
                    let Some(key) = db::config_key(&source) else {
                        return problem(404, "unknown source type");
                    };
                    match db::delete_config(&exec, actor, key, operation).await {
                        CommandOutcome::Committed(()) => status_only(204),
                        CommandOutcome::RolledBack(_) => problem(500, "delete failed"),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::PutImap => {
                    let Ok(body) = json_body::<ImapBody>(&mut r).await else {
                        return problem(400, "invalid JSON body");
                    };
                    if body.host.is_empty() {
                        return problem(400, "host is required");
                    }
                    let port = if body.port == 0 { 993 } else { body.port };
                    let mut tls = body.tls_mode;
                    if tls.is_empty() {
                        tls = "tls".into();
                    }
                    if tls == "ssl" {
                        tls = "tls".into();
                    }
                    let (hosts, cidrs) = (flat(body.private_hosts), flat(body.private_cidrs));
                    if !matches!(tls.as_str(), "tls" | "starttls" | "none") {
                        return problem(
                            400,
                            &format!(
                                "unsupported tls_mode {} (must be tls, starttls, or none)",
                                private_policy::quote(&tls)
                            ),
                        );
                    }
                    if let Err(e) = private_policy::compile_private_policy(&hosts, &cidrs) {
                        return problem(400, &format!("invalid private-network policy: {e}"));
                    }
                    let raw = db::imap_json(&body.host, port, &tls, &hosts, &cidrs);
                    save(
                        &exec,
                        actor,
                        "imap.defaults",
                        &raw,
                        false,
                        operation,
                        &c,
                        &id,
                    )
                    .await
                    .unwrap_or_else(|| status_only(204))
                }
                Action::PutEws => {
                    let Ok(body) = json_body::<EwsBody>(&mut r).await else {
                        return problem(400, "invalid JSON body");
                    };
                    if body.url.is_empty() {
                        return problem(400, "serverURL is required");
                    }
                    if body.username.is_empty() {
                        return problem(400, "username is required");
                    }
                    let (hosts, cidrs) = (flat(body.private_hosts), flat(body.private_cidrs));
                    let cfg = db::Ews {
                        url: body.url,
                        username: body.username,
                        password: body.password,
                        auth_mode: if body.auth_mode.is_empty() {
                            "per_user".into()
                        } else {
                            body.auth_mode
                        },
                        insecure: body.insecure,
                        hosts,
                        cidrs,
                    };
                    if let Err(e) = private_policy::compile_private_policy(&cfg.hosts, &cfg.cidrs) {
                        return problem(400, &format!("invalid private-network policy: {e}"));
                    }
                    if let Err(e) = private_policy::validate_ews_url(&cfg.url, &cfg.hosts) {
                        return problem(400, &format!("invalid serverURL: {e}"));
                    }
                    let Some(wrapped) = seal(&root, &cfg.json()) else {
                        return problem(500, "encryption failed");
                    };
                    save(
                        &exec,
                        actor,
                        "ews.global",
                        &wrapped,
                        true,
                        operation,
                        &c,
                        &id,
                    )
                    .await
                    .unwrap_or_else(|| status_only(204))
                }
                Action::PutM365 => {
                    let Ok(body) = json_body::<M365Body>(&mut r).await else {
                        return problem(400, "invalid JSON body");
                    };
                    if body.client_id.is_empty() {
                        return problem(400, "client_id is required");
                    }
                    if body.client_secret.is_empty() {
                        return problem(400, "client_secret is required");
                    }
                    let cfg = db::M365 {
                        client_id: body.client_id,
                        client_secret: body.client_secret,
                        tenant_id: body.tenant_id,
                        cloud: body.cloud,
                        source_email: body.source_email,
                        source_user_id: body.source_user_id,
                    };
                    let Some(wrapped) = seal(&root, &cfg.json()) else {
                        return problem(500, "encryption failed");
                    };
                    save(&exec, actor, "m365.app", &wrapped, true, operation, &c, &id)
                        .await
                        .unwrap_or_else(|| status_only(204))
                }
                Action::Cancel | Action::Retry | Action::Pause | Action::Resume => {
                    let Some(runner) = &runner else {
                        return bare(503, "service unavailable", &c, "");
                    };
                    let Ok(job) = job_id() else {
                        return problem(400, "invalid job id");
                    };
                    let o = &runner.orchestrator;
                    match what {
                        Action::Cancel => match o.cancel_job(job) {
                            Ok(()) => status_only(204),
                            Err(_) => problem(500, "failed to cancel job"),
                        },
                        Action::Retry => match o.start_job(job) {
                            Ok(()) => status_only(202),
                            Err(_) => problem(500, "failed to retry job"),
                        },
                        Action::Pause => match o.pause_job(job) {
                            Ok(()) => status_only(202),
                            Err(_) => problem(500, "failed to pause job"),
                        },
                        _ => match o.resume_job(job) {
                            Ok(()) => status_only(202),
                            Err(_) => problem(500, "failed to resume job"),
                        },
                    }
                }
                Action::TestConnection => {
                    let Some(runner) = &runner else {
                        return bare(503, "service unavailable", &c, "");
                    };
                    let Ok(body) = buffered::<TestBody>(&mut r).await else {
                        return problem(400, "invalid JSON body");
                    };
                    match body.source_type.as_str() {
                        "imap" => {
                            if body.host.is_empty() {
                                return problem(400, "host is required");
                            }
                            let connector = crate::migration_runner::ImapConnector::new(
                                crate::migration_runner::ImapConfig {
                                    host: body.host.clone(),
                                    port: default_port(body.port),
                                    tls_mode: if body.ssl == Some(false) {
                                        "none"
                                    } else {
                                        "tls"
                                    }
                                    .into(),
                                    username: body.username.clone(),
                                    password: body.password.clone(),
                                    ..Default::default()
                                },
                                runner.orchestrator.dialer(),
                            );
                            let check = async {
                                if body.username.is_empty() {
                                    connector.reachability().await
                                } else {
                                    connector.test_connection().await
                                }
                            };
                            match tokio::time::timeout(std::time::Duration::from_secs(10), check)
                                .await
                            {
                                Ok(Ok(())) => reply("{\"ok\":true}\n".to_owned()),
                                Ok(Err(e)) => problem(502, &format!("connection failed: {e}")),
                                Err(_) => problem(504, "connection test timed out after 10s"),
                            }
                        }
                        "ews" => {
                            if body.url.is_empty() {
                                return problem(400, "url is required");
                            }
                            if let Err(e) = private_policy::validate_ews_url(&body.url, &[]) {
                                return problem(400, e);
                            }
                            let connector = match runner.orchestrator.ews(
                                crate::migration_runner::ews::EwsConfig {
                                    server_url: body.url,
                                    username: body.username,
                                    password: body.password,
                                    ..Default::default()
                                },
                            ) {
                                Ok(c) => c,
                                Err(e) => return problem(502, &format!("connection failed: {e}")),
                            };
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                connector.test_connection(),
                            )
                            .await
                            {
                                Ok(Ok(())) => reply("{\"ok\":true}\n".into()),
                                Ok(Err(e)) => problem(502, &format!("connection failed: {e}")),
                                Err(_) => problem(504, "connection test timed out after 10s"),
                            }
                        }
                        "m365" => {
                            let cfg = match db::config(&runner.worker, "m365.app").await {
                                Some((value, true)) => match db::unseal(&value, &root) {
                                    db::Unsealed::Plain(v) => db::M365::from_value(&v).ok(),
                                    _ => None,
                                },
                                _ => None,
                            };
                            let Some(cfg) = cfg else {
                                return problem(
                                    400,
                                    "M365 config not found — save client ID and secret first",
                                );
                            };
                            let mut connector = match runner.orchestrator.m365(cfg) {
                                Ok(c) => c,
                                Err(e) => return problem(502, &format!("connection failed: {e}")),
                            };
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                connector.test_connection(),
                            )
                            .await
                            {
                                Ok(Ok(())) => reply("{\"ok\":true}\n".into()),
                                Ok(Err(e)) => problem(502, &format!("connection failed: {e}")),
                                Err(_) => problem(504, "connection test timed out after 10s"),
                            }
                        }
                        _ => problem(400, "source_type must be one of imap, ews, m365"),
                    }
                }
                Action::Start => {
                    let Some(runner) = &runner else {
                        return bare(503, "service unavailable", &c, "");
                    };
                    let Ok(body) = buffered::<StartBody>(&mut r).await else {
                        return problem(400, "invalid JSON body");
                    };
                    start(runner, actor, body, operation, &problem, &c, &id).await
                }
                Action::Callback => {
                    callback(&exec, runner.as_ref(), actor, &r, &root, operation, &c, &id).await
                }
                Action::Connect => {
                    // Owner-approved security fix #531 (2026-11-06): with HOSTNAME unset, empty or
                    // "localhost" the consent redirect would be https://localhost (frozen Go
                    // trusted the request Host instead); refuse rather than steer the consent.
                    if !public_host_usable(&public_host)
                        && !setjoin_contracts::mutants::on("m365-connect-localhost")
                    {
                        return text_error(503, "public hostname is not configured", &c, &id);
                    }
                    let cloud = match query(r.uri(), "cloud").unwrap_or_default().as_str() {
                        "" => "global".to_owned(),
                        other => other.to_owned(),
                    };
                    if cloud != "global" && cloud != "china" {
                        return text_error(400, "unknown cloud", &c, &id);
                    }
                    let stored =
                        match db::config(&exec, "m365.app").await {
                            Some((value, true)) => value,
                            _ => return text_error(
                                400,
                                "M365 config not found \u{2014} save client ID and secret first",
                                &c,
                                &id,
                            ),
                        };
                    let cfg = match db::unseal(&stored, &root) {
                        db::Unsealed::BadWrapper => {
                            return text_error(500, "failed to parse M365 config", &c, &id)
                        }
                        db::Unsealed::Plain(plain) => match db::M365::from_value(&plain) {
                            Ok(cfg) => cfg,
                            Err(_) => {
                                return text_error(500, "failed to read M365 config", &c, &id)
                            }
                        },
                        _ => return text_error(500, "failed to read M365 config", &c, &id),
                    };
                    let auth_base = if cloud == "china" {
                        "https://login.chinacloudapi.cn"
                    } else {
                        "https://login.microsoftonline.com"
                    };
                    let (Some(a), Some(b)) = (crate::jmap::random(), crate::jmap::random()) else {
                        return text_error(500, "failed to generate state token", &c, &id);
                    };
                    let token: String = a
                        .iter()
                        .chain(b.iter())
                        .map(|x| format!("{x:02x}"))
                        .collect();
                    let host = r
                        .headers()
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned)
                        .or_else(|| r.uri().authority().map(|a| a.to_string()))
                        .unwrap_or_default();
                    let consent =
                        consent_url(auth_base, &cfg.client_id, &public_host, &host, &token);
                    // hexEscapeNonASCII
                    let mut location = String::new();
                    for b in consent.bytes() {
                        if b >= 0x80 {
                            location.push_str(&format!("%{b:x}"));
                        } else {
                            location.push(b as char);
                        }
                    }
                    let secure = if c.identity.proto == "https" {
                        "; Secure"
                    } else {
                        ""
                    };
                    let cookie = format!(
                        "m365_oauth_state={token}; Path=/admin/migration/m365; Max-Age=600; HttpOnly{secure}; SameSite=Lax"
                    );
                    let (Ok(location_value), Ok(cookie_value)) = (
                        hyper::header::HeaderValue::from_str(&location),
                        hyper::header::HeaderValue::from_str(&cookie),
                    ) else {
                        // A value the header writer would have rewritten: let Go answer.
                        return bare(503, "service unavailable", &c, "");
                    };
                    match db::mint_consent(&exec, actor, &token, &cloud, 600, operation).await {
                        CommandOutcome::Committed(()) => {}
                        CommandOutcome::RolledBack(_) => {
                            return text_error(500, "failed to start consent flow", &c, &id)
                        }
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    }
                    let body = if r.method() == Method::GET {
                        format!("<a href=\"{}\">Found</a>.\n\n", html_escape(&consent))
                    } else {
                        String::new()
                    };
                    let mut response =
                        crate::jmap::reply::response(body, c.identity.proto, id.clone());
                    *response.status_mut() = hyper::StatusCode::FOUND;
                    let headers = response.headers_mut();
                    headers.insert("location", location_value);
                    headers.append("set-cookie", cookie_value);
                    headers.insert(
                        "content-type",
                        hyper::header::HeaderValue::from_static("text/html; charset=utf-8"),
                    );
                    response
                }
            }
        })
    }
}

fn with_newline(text: String) -> String {
    text + "\n"
}

fn seal(root: &str, plaintext: &str) -> Option<String> {
    let key = db::derive_key(root, "system")?;
    Some(db::wrapper(&db::seal(plaintext.as_bytes(), &key)?))
}

#[allow(clippy::too_many_arguments)]
async fn save(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    key: &str,
    value: &str,
    sealed: bool,
    operation: [u8; 16],
    c: &RequestContext,
    id: &str,
) -> Option<Response<Body>> {
    match db::put_config(exec, actor, key, value, sealed, operation).await {
        CommandOutcome::Committed(_) => None,
        CommandOutcome::RolledBack(_) => Some(bare(500, "save failed", c, id)),
        CommandOutcome::Unknown { operation } => Some(unknown_outcome(operation, c, id)),
    }
}

/// Go's `defaultPort`.
fn default_port(p: i64) -> i64 {
    if p == 0 {
        993
    } else {
        p
    }
}

/// Go's `AdminAPI.Start`: one job per target, then each is started.
async fn start(
    runner: &Runner,
    actor: &setjoin_authz::AuthContext,
    body: StartBody,
    operation: [u8; 16],
    problem: &(impl Fn(u16, &str) -> Response<Body> + Sync),
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    match body.source_type.as_str() {
        "imap" => {
            if body.imap_host.is_empty() {
                return problem(400, "imap_host is required");
            }
        }
        "ews" => {
            if body.ews_url.is_empty() {
                return problem(400, "ews_url is required");
            }
            if let Err(e) = private_policy::validate_ews_url(&body.ews_url, &[]) {
                return problem(400, e);
            }
        }
        "m365" => {}
        _ => return problem(400, "source_type must be one of imap, ews, m365"),
    }
    if body.targets.is_empty() {
        return problem(
            400,
            "targets[] is required (at least one source/target pair)",
        );
    }
    if body
        .targets
        .iter()
        .any(|t| t.source_email.is_empty() || t.target_email.is_empty())
    {
        return problem(400, "every target needs source_email and target_email");
    }
    let worker = &runner.worker;
    let use_global = db::has_global(worker, &body.source_type).await;
    if body.source_type == "m365" && !use_global {
        return problem(
            400,
            "M365 global config not found \u{2014} admin must configure it first",
        );
    }
    let Some(key) = runner.orchestrator.encryption_key() else {
        return problem(400, "failed to create any migration jobs");
    };
    let mut ids: Vec<i64> = vec![];
    let mut first_error = String::new();
    for (index, target) in body.targets.iter().enumerate() {
        let mut config = serde_json::json!({
            "use_global_auth": use_global,
            "source_type": body.source_type,
            "self_service": false,
        });
        match body.source_type.as_str() {
            "imap" => {
                config["imap"] = serde_json::json!({
                    "host": body.imap_host,
                    "port": default_port(body.imap_port),
                    "tls_mode": if body.imap_ssl == Some(false) { "none" } else { "tls" },
                    "credentials": {"username": target.source_email, "password": target.password},
                });
            }
            "ews" => {
                let (mut username, mut password, mut impersonate) = (
                    body.ews_username.clone(),
                    body.ews_password.clone(),
                    String::new(),
                );
                if body.auth_mode == "per_user" && !target.password.is_empty() {
                    username = target.source_email.clone();
                    password = target.password.clone();
                } else {
                    impersonate = target.source_email.clone();
                }
                let mut ews = serde_json::json!({
                    "serverURL": body.ews_url, "username": username, "password": password,
                    "insecureSkipVerify": false, "includeMail": false,
                    "includeCalendar": false, "includeContacts": false,
                });
                if !impersonate.is_empty() {
                    ews["impersonateAs"] = impersonate.into();
                }
                config["ews"] = ews;
                config["use_global_auth"] = use_global.into();
            }
            _ => {
                config["use_global_auth"] = true.into();
                config["m365"] = serde_json::json!({
                    "client_id": "", "client_secret": "", "tenant_id": "", "cloud": "",
                    "source_email": target.source_email,
                });
            }
        }
        let Some(sealed) = db::seal(config.to_string().as_bytes(), &key) else {
            continue;
        };
        let Some(mailbox) = db::mailbox_for_email(worker, &target.target_email).await else {
            if first_error.is_empty() {
                first_error = format!("no mailbox found for {}", target.target_email);
            }
            continue;
        };
        // One receipt per job: the request's operation id, varied by target.
        let mut op = operation;
        op[15] = op[15].wrapping_add(index as u8);
        match db::insert_job(worker, actor, &body.source_type, &sealed, mailbox, op).await {
            CommandOutcome::Committed(job) => ids.push(job),
            CommandOutcome::RolledBack(_) => {
                if first_error.is_empty() {
                    first_error = format!("failed to create job for {}", target.target_email);
                }
            }
            CommandOutcome::Unknown { operation } => return unknown_outcome(operation, c, id),
        }
    }
    if ids.is_empty() {
        let mut message = "failed to create any migration jobs".to_owned();
        if !first_error.is_empty() {
            message.push_str(": ");
            message.push_str(&first_error);
        }
        return problem(400, &message);
    }
    for job in &ids {
        if let Err(e) = runner.orchestrator.start_job(*job) {
            eprintln!("start migration job job_id={job} error={e}");
        }
    }
    let list: Vec<String> = ids.iter().map(i64::to_string).collect();
    let mut response = crate::jmap::reply::response(
        format!("{{\"ids\":[{}],\"status\":\"pending\"}}\n", list.join(",")),
        c.identity.proto,
        id.to_owned(),
    );
    *response.status_mut() = hyper::StatusCode::CREATED;
    response
}

/// The first value of a JSON body, read the way Go's decoder does, with the bytes put
/// back so the request can still be forwarded untouched.
async fn buffered<T: serde::de::DeserializeOwned>(r: &mut Request<Body>) -> Result<T, ()> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.map_err(|_| ())?;
        if let Ok(data) = frame.into_data() {
            if data.len() > (1usize << 20).saturating_sub(bytes.len()) {
                return Err(());
            }
            bytes.extend_from_slice(&data);
        }
    }
    let fixed = crate::guests_input::go_json_bytes(&bytes);
    let parsed = match serde_json::Deserializer::from_slice(&fixed)
        .into_iter::<T>()
        .next()
    {
        Some(Ok(value)) => Ok(value),
        _ => Err(()),
    };
    *r.body_mut() = http_body_util::Full::new(bytes::Bytes::from(bytes))
        .map_err(|never| -> crate::BoxError { match never {} })
        .boxed();
    parsed
}

#[allow(clippy::too_many_arguments)]
async fn callback(
    exec: &ScopedExecutor,
    runner: Option<&Runner>,
    actor: &setjoin_authz::AuthContext,
    r: &Request<Body>,
    root: &str,
    operation: [u8; 16],
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    let secure = if c.identity.proto == "https" {
        "; Secure"
    } else {
        ""
    };
    let finish = |mut response: Response<Body>| {
        response.headers_mut().append("set-cookie",format!("m365_oauth_state=; Path=/admin/migration/m365; Max-Age=0; HttpOnly{secure}; SameSite=Lax").parse().unwrap());
        response
    };
    let error = |status, message: &str| finish(text_error(status, message, c, id));
    let state = query(r.uri(), "state").unwrap_or_default();
    let cookie = r
        .headers()
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|part| part.trim().strip_prefix("m365_oauth_state="))
        .unwrap_or("")
        .trim_matches('"');
    if state.is_empty() || cookie != state {
        return error(400, "invalid or expired state");
    }
    let tenant = query(r.uri(), "tenant").unwrap_or_default();
    if query(r.uri(), "admin_consent").as_deref() != Some("True") || tenant.is_empty() {
        let msg = query(r.uri(), "error_description")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Admin consent was not granted".into());
        return error(400, &msg);
    }
    let cloud = match db::consume_consent(exec, actor, &state, operation).await {
        CommandOutcome::Committed(cloud) => cloud,
        CommandOutcome::RolledBack(_) => return error(400, "invalid or expired state"),
        CommandOutcome::Unknown { operation } => return finish(unknown_outcome(operation, c, id)),
    };
    let stored = match db::config(exec, "m365.app").await {
        Some((v, true)) => v,
        _ => return error(400, "M365 config not found"),
    };
    let mut cfg = match db::unseal(&stored, root) {
        db::Unsealed::Plain(v) => match db::M365::from_value(&v) {
            Ok(cfg) => cfg,
            Err(_) => return error(500, "failed to read M365 config"),
        },
        _ => return error(500, "failed to read M365 config"),
    };
    cfg.tenant_id = tenant.clone();
    cfg.cloud = cloud.clone();
    let connector = match runner {
        Some(r) => r.orchestrator.m365(cfg.clone()),
        None => crate::migration_runner::m365::M365Connector::new(cfg.clone()),
    };
    let mut connector = match connector {
        Ok(c) => c,
        Err(e) => return error(500, &format!("M365 test connection failed: {e}")),
    };
    if let Err(e) = connector.test_connection().await {
        return error(500, &format!("M365 test connection failed: {e}"));
    }
    let Some(wrapped) = seal(root, &cfg.json()) else {
        return error(500, "failed to store tenant ID");
    };
    let Some(completion) = crate::jmap::random() else {
        return error(500, "failed to save config");
    };
    match db::complete_consent(
        runner.map(|r| &r.worker).unwrap_or(exec),
        actor,
        &wrapped,
        &format!("tenant={tenant} cloud={cloud}"),
        completion,
    )
    .await
    {
        CommandOutcome::Committed(()) => {}
        CommandOutcome::RolledBack(_) => return error(500, "failed to save config"),
        CommandOutcome::Unknown { operation } => return finish(unknown_outcome(operation, c, id)),
    }
    let body = if r.method() == Method::GET {
        "<a href=\"/admin/migration?m365_connected=true\">Found</a>.\n\n"
    } else {
        ""
    };
    let mut response =
        crate::jmap::reply::response(body.to_owned(), c.identity.proto, id.to_owned());
    *response.status_mut() = hyper::StatusCode::FOUND;
    response.headers_mut().insert(
        "location",
        "/admin/migration?m365_connected=true".parse().unwrap(),
    );
    response
        .headers_mut()
        .insert("content-type", "text/html; charset=utf-8".parse().unwrap());
    finish(response)
}
