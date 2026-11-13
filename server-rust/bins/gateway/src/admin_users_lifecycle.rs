//! F01 slice `user-lifecycle` HTTP adapter: create, update, delete, password reset,
//! CSV import, secure-account, sign-in history and app-password revocation. See the
//! crate DOX for the contract. Create, update and delete run on the worker
//! credential (the webhook publication reducers are worker-only and the delete
//! cascade is a cross-tenant write); every other route runs under the verified actor.
//!
//! Webhook delivery: with the publication outbox off Go hands the event to its
//! in-process dispatcher after the commit; Rust does the same through the shared
//! `webhook::Dispatcher` (#302). When the reducer queued the publication (outbox on)
//! nothing is dispatched here.
use crate::admin_identity_input as input;
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use setjoin_admin_identity::lifecycle as db;
use setjoin_authz::{token::KeySource, AuthContext};
use setjoin_pg::{CommandOutcome, Rejection, ScopedExecutor};
use std::sync::Arc;

pub struct AdminUsersLifecycleRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    /// Go's `scim.RevokeAuthSessions` target; either empty disables the call.
    pub authserver_url: String,
    pub internal_key: String,
    /// Go's `webhook.Dispatcher`: legacy best-effort fan-out after the commit.
    pub dispatcher: crate::webhook::Dispatcher,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Create,
    Import,
    Update,
    Delete,
    Password,
    Secure,
    SignIns,
    RevokeAppPassword,
}

fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let (post, put, delete) = (
        *method == Method::POST,
        *method == Method::PUT,
        *method == Method::DELETE,
    );
    let table: [(bool, &str, Action); 8] = [
        (post, "/api/admin/users", Action::Create),
        (post, "/api/admin/users/import", Action::Import),
        (put, "/api/admin/users/{id}", Action::Update),
        (delete, "/api/admin/users/{id}", Action::Delete),
        (put, "/api/admin/users/{id}/password", Action::Password),
        (post, "/api/admin/users/{id}/secure-account", Action::Secure),
        (reads, "/api/admin/users/{id}/sign-ins", Action::SignIns),
        (
            delete,
            "/api/admin/users/{userId}/app-passwords/{apId}",
            Action::RevokeAppPassword,
        ),
    ];
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| *action)
}

/// Go's `r.PathValue`: the percent-decoded segment at `index` of the full path.
fn segment(path: &str, index: usize) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.split('/').nth(index).unwrap_or(""),
    ))
}

fn segment_path(path: &str) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.strip_prefix("/api").unwrap_or(path),
    ))
}

const GUEST_REFUSED: &str =
    "guest accounts are managed via the guest console (/admin/guests), not the generic user endpoints";

/// Go's `auth.HashPassword`: bcrypt at the default cost, `$2a$` prefix.
async fn hash(password: String) -> Option<String> {
    tokio::task::spawn_blocking(move || {
        bcrypt::hash_with_result(password, 10)
            .ok()
            .map(|parts| parts.format_for_version(bcrypt::Version::TwoA))
    })
    .await
    .ok()
    .flatten()
}

/// Go's best-effort `RevokeAuthSessions`: a bounded POST to the authserver.
fn revoke_sessions(url: &str, key: &str, user: i64) {
    if url.is_empty() || key.is_empty() {
        return;
    }
    let (url, key) = (format!("{url}/auth/scim/disable"), key.to_owned());
    tokio::spawn(async move {
        let Ok(client) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
        else {
            return;
        };
        let _ = client
            .post(url)
            .header("Authorization", format!("Bearer {key}"))
            .header("Content-Type", "application/json")
            .body(format!("{{\"user_id\":{user}}}"))
            .send()
            .await;
    });
}

impl<K: KeySource + 'static> Intercept for AdminUsersLifecycleRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
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
        let (exec, worker, keys, issuer) = (
            self.exec.clone(),
            self.worker.clone(),
            self.keys.clone(),
            self.issuer.clone(),
        );
        let (revoke_url, revoke_key) = (self.authserver_url.clone(), self.internal_key.clone());
        let dispatcher = self.dispatcher.clone();
        Box::pin(async move {
            let Some(what) = action(r.method(), r.uri().path()) else {
                return c.upstream.forward(r, &c.identity).await;
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
                return c.upstream.forward(r, &c.identity).await;
            };
            let Some(operation) = crate::jmap::random() else {
                return bare(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let actor = auth.context();
            let Ok(authority) = setjoin_admin_identity::authority(&exec, actor).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let path = r.uri().path().to_owned();
            let go_path = segment_path(&path);
            let required: &[&str] = match what {
                Action::Create | Action::Import | Action::RevokeAppPassword => {
                    &setjoin_admin_identity::USERS_CREATE
                }
                Action::Update => &db::USERS_SUSPEND,
                Action::Delete => &db::USERS_DELETE,
                Action::Password | Action::Secure => &db::USERS_PASSWORD_RESET,
                Action::SignIns => &setjoin_admin_identity::SIGN_IN,
            };
            if !authority.allows_any(required) {
                let _ = setjoin_admin_identity::console_denied(
                    &exec,
                    actor,
                    &go_path,
                    &required.join("|"),
                    operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            }
            if authority.refused_for_scope(required) {
                let detail = format!(
                    "{} (domain-scoped principal; org-wide-only surface, domain={})",
                    required.join("|"),
                    authority.domain_scope()
                );
                let _ = setjoin_admin_identity::console_denied(
                    &exec, actor, &go_path, &detail, operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            }
            let scope = authority.domain_scope();
            let ip = c.identity.client_ip.to_string();
            let reply =
                |body: String| crate::jmap::reply::response(body, c.identity.proto, id.clone());
            let full = |status: u16, detail: &str| problem(status, detail, &go_path, &c, &id);
            let database = || full(500, "database error");
            let plain = |status: u16, detail: &str| bare(status, detail, &c, &id);
            let status_only = |status: u16| {
                let mut response =
                    crate::jmap::reply::response(String::new(), c.identity.proto, id.clone());
                *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
                response.headers_mut().remove("content-type");
                response
            };
            let created = |status: u16, body: String| {
                let mut response = reply(body);
                *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
                response
            };
            let unknown = |operation| {
                let mut response = bare(503, "operation outcome unknown", &c, &id);
                response.headers_mut().insert(
                    "x-operation-id",
                    setjoin_pg::operation_hex(operation)
                        .parse()
                        .expect("operation"),
                );
                response
            };
            // A refusal decided by a reducer, a protection denial, or the database failing.
            let failed = |error: Rejection<setjoin_pg::StatementFailure>, target: i64| {
                let (exec, c, id, go_path, ip) = (&exec, &c, &id, &go_path, &ip);
                async move {
                    if let Some(p) = db::problem_of(&error) {
                        return problem(p.status, &p.detail, go_path, c, id);
                    }
                    let database = || problem(500, "database error", go_path, c, id);
                    let (Rejection::Statement(e) | Rejection::Body(e)) = &error else {
                        return database();
                    };
                    let remediation = "Complete the required authorization, approval, or recovery step before retrying.";
                    let (status, class, remediation) = match e.sqlstate.as_deref() {
                        Some("BZ064") => (
                            409,
                            "BZ064",
                            "Refresh current state, resolve the conflict, and retry.",
                        ),
                        Some("BZ065") => (403, "BZ065", remediation),
                        Some("BZ066") => (403, "BZ066", remediation),
                        Some("BZ060" | "BZ061") => {
                            return problem(404, "user not found", go_path, c, id)
                        }
                        Some("BZ221") => return problem(409, GUEST_REFUSED, go_path, c, id),
                        _ => return database(),
                    };
                    setjoin_admin_identity::roles::protection_denied(
                        exec, actor, target, class, ip, operation,
                    )
                    .await;
                    reducer(status, class, &e.message, remediation, go_path, c, id)
                }
            };
            // Go's `strconv.ParseInt` on a path value.
            let number = |index: usize| segment(&path, index).parse::<i64>().ok();
            match what {
                Action::Create => {
                    let Ok(req) = input::first::<input::UserCreate>(&mut r, 1 << 20).await else {
                        return full(400, "invalid JSON");
                    };
                    create(
                        &exec, &worker, actor, scope, req, operation, &dispatcher, &full, &reply,
                        &created, &unknown,
                    )
                    .await
                }
                Action::Import => import(&exec, actor, scope, &mut r, &reply, &full, &c).await,
                Action::Update => {
                    let Some(target) = number(4) else {
                        return full(400, "invalid user id");
                    };
                    match db::is_guest(&exec, target).await {
                        Err(_) => return database(),
                        Ok(true) => return full(409, GUEST_REFUSED),
                        Ok(false) => {}
                    }
                    let Ok(req) = input::first::<input::UserUpdate>(&mut r, 1 << 20).await else {
                        return full(400, "invalid JSON");
                    };
                    match db::can_manage(&exec, actor.user_id(), target).await {
                        Err(_) => return database(),
                        Ok(false) => return full(404, "admin user not found"),
                        Ok(true) => {}
                    }
                    // Go's UpdateBuilder: an empty display name is an absent field.
                    let name = req.display_name.filter(|n| !n.is_empty());
                    if name.is_none() && req.enabled.is_none() && req.is_local_admin.is_none() {
                        return full(400, "no fields to update");
                    }
                    let disabling = req.enabled == Some(false);
                    match db::update(
                        &worker,
                        actor,
                        target,
                        scope,
                        name.as_deref(),
                        req.enabled,
                        req.is_local_admin,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(queued) => {
                            if disabling {
                                revoke_sessions(&revoke_url, &revoke_key, target);
                            }
                            if !queued {
                                let event = crate::webhook::CloudEvent::new(
                                    "mailserver/auth",
                                    "user.updated",
                                    serde_json::json!({ "user_id": target }),
                                );
                                dispatcher.dispatch_for_user(target, &event).await;
                            }
                            status_only(204)
                        }
                        CommandOutcome::RolledBack(e) => failed(e, target).await,
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::Delete => {
                    let Some(target) = number(4) else {
                        return full(400, "invalid user id");
                    };
                    match db::is_guest(&exec, target).await {
                        Err(_) => return database(),
                        Ok(true) => return full(409, GUEST_REFUSED),
                        Ok(false) => {}
                    }
                    match db::lifecycle_enabled(&worker).await {
                        Err(_) => return database(),
                        Ok(true) => {
                            return full(
                                409,
                                "direct user deletion is disabled; suspend or detach and retain the mailbox, then use the approved purge workflow",
                            )
                        }
                        Ok(false) => {}
                    }
                    match db::delete(&worker, actor, target, scope, operation).await {
                        CommandOutcome::Committed(queued) => {
                            if !queued {
                                let event = crate::webhook::CloudEvent::new(
                                    "mailserver/auth",
                                    "user.deleted",
                                    serde_json::json!({ "user_id": target }),
                                );
                                dispatcher.dispatch_for_user(target, &event).await;
                            }
                            status_only(204)
                        }
                        CommandOutcome::RolledBack(e) => failed(e, target).await,
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::Password => {
                    let Some(target) = number(4) else {
                        return full(400, "invalid user id");
                    };
                    let Ok(req) = input::first::<input::PasswordReset>(&mut r, 1 << 20).await
                    else {
                        return full(400, "invalid JSON");
                    };
                    match db::can_manage(&exec, actor.user_id(), target).await {
                        Err(_) => return database(),
                        Ok(false) => return full(404, "user not found"),
                        Ok(true) => {}
                    }
                    let email = match db::reset_email(&exec, scope, target).await {
                        Ok(Some(email)) => email,
                        Ok(None) => return full(404, "user not found"),
                        Err(_) => return database(),
                    };
                    // Classified only after the privacy-preserving reach checks above.
                    match db::is_guest(&exec, target).await {
                        Err(_) => return database(),
                        Ok(true) => return full(409, GUEST_REFUSED),
                        Ok(false) => {}
                    }
                    if let Err(message) = admin_password(&exec, &req.password, &email).await {
                        return full(400, message);
                    }
                    let Some(hashed) = hash(req.password).await else {
                        return full(500, "password hashing failed");
                    };
                    match db::reset_password(
                        &exec,
                        actor,
                        target,
                        scope,
                        &hashed,
                        req.must_change.unwrap_or(true),
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(()) => status_only(204),
                        CommandOutcome::RolledBack(e) => failed(e, target).await,
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::Secure | Action::SignIns => {
                    let Some(target) = number(4) else {
                        return plain(400, "bad id");
                    };
                    match db::in_scope(&exec, scope, target).await {
                        Ok(true) => {}
                        _ => return plain(404, "not found"),
                    }
                    if what == Action::SignIns {
                        return match db::sign_ins(&exec, target, scope).await {
                            Ok(body) => reply(body),
                            Err(_) => plain(500, "database error"),
                        };
                    }
                    match db::secure(&exec, actor, target, scope, &ip, operation).await {
                        CommandOutcome::Committed(()) => reply("{\"status\":\"secured\"}\n".into()),
                        CommandOutcome::RolledBack(_) => plain(500, "database error"),
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::RevokeAppPassword => {
                    let Some(user) = number(4) else {
                        return plain(400, "invalid user id");
                    };
                    let Some(app_password) = number(6) else {
                        return plain(400, "invalid app password id");
                    };
                    match db::revoke_app_password(
                        &exec,
                        actor,
                        user,
                        app_password,
                        scope,
                        &ip,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(_) => status_only(204),
                        // Go answers 404 for a miss and for any database failure alike.
                        CommandOutcome::RolledBack(_) => plain(404, "not found"),
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
            }
        })
    }
}

/// Go's `validateAdminPassword`: policy, then the common-password list.
async fn admin_password(
    exec: &ScopedExecutor,
    password: &str,
    email: &str,
) -> Result<(), &'static str> {
    let policy = db::load_policy(exec).await;
    db::validate_password(password, &policy, email)?;
    if db::is_common_password(exec, password).await {
        return Err(db::COMMON_PASSWORD);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn create(
    exec: &ScopedExecutor,
    worker: &ScopedExecutor,
    actor: &AuthContext,
    scope: i64,
    req: input::UserCreate,
    operation: [u8; 16],
    dispatcher: &crate::webhook::Dispatcher,
    full: &(dyn Fn(u16, &str) -> Response<Body> + Sync),
    _reply: &(dyn Fn(String) -> Response<Body> + Sync),
    created: &(dyn Fn(u16, String) -> Response<Body> + Sync),
    unknown: &(dyn Fn(setjoin_contracts::ids::OperationId) -> Response<Body> + Sync),
) -> Response<Body> {
    if req.email.is_empty() || req.password.is_empty() {
        return full(400, "email and password required");
    }
    let display_name = if req.display_name.is_empty() {
        req.email.split('@').next().unwrap_or("").to_owned()
    } else {
        req.display_name.clone()
    };
    let canonical = match input::address(&req.email) {
        Ok(email) => email,
        Err(message) => return full(400, message),
    };
    if let Err(message) = db::validate_display_name(&display_name) {
        return full(400, message);
    }
    if let Err(message) = admin_password(exec, &req.password, &canonical).await {
        return full(400, message);
    }
    let Some(hashed) = hash(req.password.clone()).await else {
        return full(500, "password hashing failed");
    };
    match db::create(
        worker,
        actor,
        &req.email,
        &canonical,
        &display_name,
        &hashed,
        req.is_local_admin,
        scope,
        operation,
    )
    .await
    {
        CommandOutcome::Committed((user, queued)) => {
            if !queued {
                let event = crate::webhook::CloudEvent::new(
                    "mailserver/auth",
                    "user.created",
                    serde_json::json!({"user_id": user, "email": req.email, "created_by": actor.email()}),
                );
                dispatcher.dispatch_for_user(user, &event).await;
            }
            // Go starts the welcome email from a goroutine and answers without it.
            let worker = worker.clone();
            tokio::spawn(
                async move { setjoin_directory_sync::scim::send_welcome(&worker, user).await },
            );
            created(201, format!("{{\"id\":{user}}}\n"))
        }
        CommandOutcome::RolledBack(e) => match db::problem_of(&e) {
            Some(p) => full(p.status, &p.detail),
            None => full(500, "database error"),
        },
        CommandOutcome::Unknown { operation } => unknown(operation),
    }
}

/// Go's `ParseMultipartForm` + `FormFile("file")` over the capped body.
async fn csv_file(r: &mut Request<Body>) -> Result<Option<Vec<u8>>, ()> {
    use http_body_util::BodyExt;
    const CAP: usize = 10 << 20;
    let boundary = r
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| multer::parse_boundary(v).ok())
        .ok_or(())?;
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.map_err(|_| ())?;
        if let Ok(data) = frame.into_data() {
            if data.len() > CAP - bytes.len() {
                return Err(());
            }
            bytes.extend_from_slice(&data);
        }
    }
    let stream = futures_util::stream::once(async move {
        Ok::<_, std::convert::Infallible>(bytes::Bytes::from(bytes))
    });
    let mut form = multer::Multipart::new(stream, boundary);
    let mut file = None;
    while let Some(field) = form.next_field().await.map_err(|_| ())? {
        let named =
            field.name() == Some("file") && field.file_name().is_some_and(|n| !n.is_empty());
        let data = field.bytes().await.map_err(|_| ())?;
        if named && file.is_none() {
            file = Some(data.to_vec());
        }
    }
    Ok(file)
}

async fn import(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    scope: i64,
    r: &mut Request<Body>,
    reply: &(dyn Fn(String) -> Response<Body> + Sync),
    full: &(dyn Fn(u16, &str) -> Response<Body> + Sync),
    _c: &RequestContext,
) -> Response<Body> {
    use crate::admin_users_csv::{parse_bool, Reader, Record};
    let Ok(file) = csv_file(r).await else {
        return full(400, "invalid multipart form");
    };
    let Some(file) = file else {
        return full(400, "file required");
    };
    let mut reader = Reader::new(&file);
    let Record::Fields(headers) = reader.read() else {
        return full(400, "unable to read CSV headers");
    };
    let mut columns = std::collections::HashMap::new();
    for (i, name) in headers.iter().enumerate() {
        columns.insert(name.trim().to_lowercase(), i);
    }
    for required in ["email", "password"] {
        if !columns.contains_key(required) {
            return full(400, &format!("missing required CSV column: {required}"));
        }
    }
    let grant_domain = (scope > 0).then_some(scope);
    let policy = db::load_policy(exec).await;
    let mut created = 0u64;
    let mut failed: Vec<String> = Vec::new();
    let mut row = 1u64;
    let quote = |t: &str| serde_json::to_string(t).expect("string");
    let fail = |failed: &mut Vec<String>, row: u64, email: &str, message: &str| {
        failed.push(format!(
            "{{\"row\":{row},\"email\":{},\"error\":{}}}",
            quote(email),
            quote(message)
        ));
    };
    loop {
        let record = match reader.read() {
            Record::Eof => break,
            Record::Error => {
                row += 1;
                fail(
                    &mut failed,
                    row,
                    "",
                    "Failed to parse CSV row. The file may be malformed.",
                );
                continue;
            }
            Record::Fields(fields) => fields,
        };
        row += 1;
        let cell = |name: &str| record[columns[name]].trim().to_owned();
        let (email, password) = (cell("email"), cell("password"));
        if email.is_empty() || password.is_empty() {
            fail(&mut failed, row, &email, "email and password required");
            continue;
        }
        let canonical = match input::address(&email) {
            Ok(value) => value,
            Err(message) => {
                fail(&mut failed, row, &email, message);
                continue;
            }
        };
        if let Err(message) = db::validate_password(&password, &policy, &canonical) {
            fail(&mut failed, row, &email, message);
            continue;
        }
        if db::is_common_password(exec, &password).await {
            fail(&mut failed, row, &email, db::COMMON_PASSWORD);
            continue;
        }
        let mut display_name = columns
            .get("display_name")
            .map(|_| cell("display_name"))
            .unwrap_or_default();
        let is_local_admin = columns
            .get("is_local_admin")
            .and_then(|_| parse_bool(&cell("is_local_admin")))
            .unwrap_or(false);
        let positive = |name: &str| {
            columns
                .get(name)
                .and_then(|_| cell(name).parse::<i64>().ok())
                .filter(|v| *v > 0)
        };
        let department = positive("department_id");
        if let Some(department) = department {
            if actor.user_id() > 0 {
                match db::department_in_scope(exec, actor.user_id(), department, grant_domain).await
                {
                    Err(_) => {
                        fail(&mut failed, row, &email, "department scope check failed");
                        continue;
                    }
                    Ok(false) => {
                        fail(
                            &mut failed,
                            row,
                            &email,
                            "department not within your administrative scope",
                        );
                        continue;
                    }
                    Ok(true) => {}
                }
            }
        }
        let quota = positive("quota_bytes");
        let Some(hashed) = hash(password).await else {
            fail(&mut failed, row, &email, "password hashing failed");
            continue;
        };
        let Some(domain) = db::local_domain(exec, &email).await else {
            fail(
                &mut failed,
                row,
                &email,
                "email domain is not a local domain",
            );
            continue;
        };
        if scope > 0 && domain != scope {
            fail(
                &mut failed,
                row,
                &email,
                "email domain is not in your domain scope",
            );
            continue;
        }
        if display_name.is_empty() {
            display_name = email.clone();
        }
        let Some(operation) = crate::jmap::random() else {
            fail(&mut failed, row, &email, "database error");
            continue;
        };
        match db::import_row(
            exec,
            actor,
            &canonical,
            &display_name,
            &hashed,
            is_local_admin,
            department,
            quota,
            operation,
        )
        .await
        {
            CommandOutcome::Committed(true) => created += 1,
            CommandOutcome::Committed(false) => {
                fail(&mut failed, row, &email, "user already exists")
            }
            CommandOutcome::RolledBack(e) => {
                let duplicate = matches!(&e,
                    Rejection::Statement(f) | Rejection::Body(f) if f.sqlstate.as_deref() == Some("23505"));
                fail(
                    &mut failed,
                    row,
                    &email,
                    if duplicate {
                        "user already exists"
                    } else {
                        "database error"
                    },
                );
            }
            CommandOutcome::Unknown { .. } => fail(&mut failed, row, &email, "database error"),
        }
    }
    let failed = if failed.is_empty() {
        "null".to_owned()
    } else {
        format!("[{}]", failed.join(","))
    };
    reply(
        setjoin_admin_identity::go_escape(&format!(
            "{{\"created\":{created},\"failed\":{failed}}}"
        )) + "\n",
    )
}

fn render(
    status: u16,
    body: String,
    language: bool,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    let code = hyper::StatusCode::from_u16(status).expect("status");
    let mut r = crate::jmap::reply::response(
        setjoin_admin_identity::go_escape(&body) + "\n",
        c.identity.proto,
        id.to_owned(),
    );
    *r.status_mut() = code;
    r.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/problem+json"),
    );
    if language {
        r.headers_mut().insert(
            "content-language",
            hyper::header::HeaderValue::from_static("en"),
        );
    }
    r
}
fn title(status: u16) -> &'static str {
    crate::problem::title(status)
}
fn quote(text: &str) -> String {
    serde_json::to_string(text).expect("string")
}

/// Go's `WriteProblemStatus`: a minimal problem, empty instance, no language.
fn bare(status: u16, detail: &str, c: &RequestContext, id: &str) -> Response<Body> {
    render(
        status,
        format!(
            "{{\"type\":\"about:blank\",\"title\":{},\"status\":{status},\"detail\":{},\"instance\":\"\"}}",
            quote(title(status)),
            quote(detail)
        ),
        false,
        c,
        id,
    )
}
/// Go's `WriteProblem` with a bare status and detail.
fn problem(status: u16, detail: &str, path: &str, c: &RequestContext, id: &str) -> Response<Body> {
    render(
        status,
        format!(
            "{{\"type\":\"about:blank\",\"title\":{},\"status\":{status},\"detail\":{},\"instance\":{}}}",
            quote(title(status)),
            quote(detail),
            quote(path)
        ),
        true,
        c,
        id,
    )
}
/// Go's `reducererr.WriteClassified` for a known reducer code.
fn reducer(
    status: u16,
    code: &str,
    detail: &str,
    remediation: &str,
    path: &str,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    render(
        status,
        format!(
            "{{\"type\":\"https://setjoin.com/problems/reducer/{}\",\"title\":{},\"status\":{status},\"detail\":{},\"instance\":{},\"remediation\":{},\"code\":{},\"retryable\":false}}",
            code.to_ascii_lowercase(),
            quote(title(status)),
            quote(detail),
            quote(path),
            quote(remediation),
            quote(code)
        ),
        true,
        c,
        id,
    )
}
