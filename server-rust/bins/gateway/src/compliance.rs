//! F04 eDiscovery HTTP adapter; organization-wide permission gates mirror Go.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_compliance as db;
use setjoin_pg::{CommandOutcome, ScopedExecutor};
use std::sync::Arc;

pub struct ComplianceRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker: ScopedExecutor,
    pub jobs: SearchJobs,
    pub store: Option<Arc<crate::recovery_worker::S3Store>>,
    pub keys: Arc<K>,
    pub issuer: String,
}
struct EdiscoveryMatch {
    list: bool,
    get: bool,
    create: bool,
    update: bool,
    delete: bool,
    associate: bool,
    close: bool,
    hold: bool,
    release: bool,
    export: bool,
    start: bool,
    search: bool,
}

impl EdiscoveryMatch {
    fn from(method: &Method, path: &str) -> Self {
        let list = path == "/api/admin/ediscovery/cases";
        let get = crate::inventory::path_score("/api/admin/ediscovery/cases/{id}", path).is_some();
        let create = list && *method == Method::POST;
        let update = get && *method == Method::PUT;
        let delete = get && *method == Method::DELETE;
        let associate = *method == Method::POST && path == "/api/admin/ediscovery/cases/associate";
        let close = *method == Method::POST
            && crate::inventory::path_score("/api/admin/ediscovery/cases/{id}/close", path)
                .is_some();
        let hold = *method == Method::POST && path == "/api/admin/ediscovery/hold";
        let release = *method == Method::POST && path == "/api/admin/ediscovery/release";
        let export =
            matches!(*method, Method::GET | Method::HEAD) && path == "/api/admin/ediscovery/export";
        let start = *method == Method::POST && path == "/api/admin/ediscovery/search";
        let search = matches!(*method, Method::GET | Method::HEAD)
            && crate::inventory::path_score("/api/admin/ediscovery/{id}", path).is_some()
            && !list
            && !export;
        Self {
            list,
            get,
            create,
            update,
            delete,
            associate,
            close,
            hold,
            release,
            export,
            start,
            search,
        }
    }

    fn matched(&self, method: &Method) -> bool {
        self.create
            || self.update
            || self.delete
            || self.associate
            || self.close
            || self.hold
            || self.release
            || self.start
            || self.export
            || self.search
            || (matches!(*method, Method::GET | Method::HEAD) && (self.list || self.get))
    }
}

impl<K: KeySource + 'static> Intercept for ComplianceRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool {
        true
    }
    fn matches(&self, r: &Request<Body>) -> bool {
        EdiscoveryMatch::from(r.method(), r.uri().path()).matched(r.method())
    }
    fn admits_member(&self, h: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_request(&exec, &keys, &issuer, &h, scheme)
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer, worker, jobs, store) = (
            self.exec.clone(),
            self.keys.clone(),
            self.issuer.clone(),
            self.worker.clone(),
            self.jobs.clone(),
            self.store.clone(),
        );
        Box::pin(async move {
            let EdiscoveryMatch {
                list,
                get,
                create,
                update,
                delete,
                associate,
                close,
                hold,
                release,
                export,
                start,
                search,
            } = EdiscoveryMatch::from(r.method(), r.uri().path());
            let verdict =
                crate::deny::admit(&exec, &keys, &issuer, &r, crate::deny::Scope::Member).await;
            let auth = match verdict {
                Ok(auth) => auth,
                Err(refusal) => return crate::deny::answer(refusal, r, &c).await,
            };
            let Some(operation) = crate::jmap::random() else {
                return problem(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let actor = auth.context();
            let path = r.uri().path().trim_start_matches("/api");
            let required: &[&str] =
                if create || update || delete || associate || close || hold || release || start {
                    &["compliance.write"]
                } else if search || export {
                    &["mail.export"]
                } else {
                    &db::MAIL_CONSOLE
                };
            let Some(authority) = db::authority(&exec, actor)
                .await
                .ok()
                .filter(|authority| authority.allows_any(required))
            else {
                let _ =
                    db::console_denied(&exec, actor, path, &required.join("|"), operation).await;
                return problem(403, "Forbidden", &c, &id);
            };
            if authority.domain_scope() > 0 {
                let detail = format!(
                    "org-wide-only surface (domain-scoped principal; domain={})",
                    authority.domain_scope()
                );
                let _ = db::console_denied(&exec, actor, path, &detail, operation).await;
                return problem(403, "Forbidden", &c, &id);
            }
            if export {
                let raw = crate::compliance_export::query_bytes(r.uri(), "ids").unwrap_or_default();
                if raw.is_empty() {
                    return problem(400, "ids required", &c, &id);
                }
                let case =
                    crate::admin_identity_input::query(r.uri(), "caseId").unwrap_or_default();
                if case.is_empty() {
                    return problem(400, "caseId is required", &c, &id);
                }
                let Some(case) = case.parse::<i64>().ok().filter(|n| *n > 0) else {
                    return problem(400, "invalid caseId", &c, &id);
                };
                let original: Vec<String> = raw
                    .split(|b| *b == b',')
                    .map(crate::guests_input::go_utf8)
                    .collect();
                if original.len() > 500 {
                    return problem(400, "1-500 ids required", &c, &id);
                }
                let mut ids = Vec::new();
                for s in &original {
                    if let Ok(n) = s.parse::<i64>() {
                        if n > 0 && !ids.contains(&n) {
                            ids.push(n);
                        }
                    }
                }
                match db::export::authorize(
                    &worker,
                    actor,
                    case,
                    &ids,
                    &original,
                    &c.identity.client_ip.to_string(),
                    operation,
                )
                .await
                {
                    CommandOutcome::Committed(error) if error.is_empty() => {
                        if crate::admin_identity_input::query(r.uri(), "format").as_deref()
                            == Some("pst")
                        {
                            problem(501, "PST export: streaming support pending", &c, &id)
                        } else {
                            crate::compliance_export::response(
                                worker,
                                store,
                                crate::compliance_export::Selection {
                                    head: *r.method() == Method::HEAD,
                                    actor: actor.user_id(),
                                    case,
                                    ids,
                                    original,
                                    raw,
                                },
                                &c,
                                id,
                            )
                            .await
                        }
                    }
                    CommandOutcome::Committed(error) => {
                        let (code, message) = error
                            .split_once(':')
                            .unwrap_or(("500", "export audit could not be persisted"));
                        problem(code.parse().unwrap_or(500), message, &c, &id)
                    }
                    CommandOutcome::Unknown { .. } => unknown(operation, &c, &id),
                    CommandOutcome::RolledBack(_) => {
                        problem(500, "export audit could not be persisted", &c, &id)
                    }
                }
            } else if start {
                let Ok((fields, _original)) = search_fields(&mut r).await else {
                    return problem(400, "invalid request", &c, &id);
                };
                let (
                    Ok(name),
                    Ok(keywords),
                    Ok(kql),
                    Ok(from),
                    Ok(date_from),
                    Ok(date_to),
                    Ok(mailboxes),
                    Ok(case),
                ) = (
                    scalar::<String>(&fields.0, "name"),
                    scalar::<String>(&fields.0, "keywords"),
                    scalar::<String>(&fields.0, "kql"),
                    scalar::<String>(&fields.0, "fromaddr"),
                    scalar::<String>(&fields.0, "datefrom"),
                    scalar::<String>(&fields.0, "dateto"),
                    pointer::<Vec<Option<i64>>>(&fields.0, "mailboxids"),
                    pointer::<i64>(&fields.0, "caseid"),
                )
                else {
                    return problem(400, "invalid request", &c, &id);
                };
                if keywords.is_empty() && from.is_empty() && kql.is_empty() {
                    return json_response(
                        400,
                        "{\"error\":\"keywords, fromAddr, or kql required\"}\n".into(),
                        &c,
                        id,
                    );
                }
                if !kql.is_empty() {
                    if let Err(error) = db::kql::parse(&kql) {
                        return problem(400, &format!("invalid KQL query: {error}"), &c, &id);
                    }
                }
                let mailboxes =
                    mailboxes.map(|xs| xs.into_iter().map(|x| x.unwrap_or(0)).collect::<Vec<_>>());
                let query = serde_json::json!({"keywords":keywords,"kql":kql,"fromAddr":from,"dateFrom":date_from,"dateTo":date_to,"mailboxIds":mailboxes});
                match db::search::start(&worker, actor, &name, &query, case, operation).await {
                    CommandOutcome::Committed(search) => {
                        jobs.launch(actor.user_id(), search);
                        json_response(
                            202,
                            format!("{{\"id\":{search},\"status\":\"pending\"}}\n"),
                            &c,
                            id,
                        )
                    }
                    CommandOutcome::Unknown { .. } => unknown(operation, &c, &id),
                    CommandOutcome::RolledBack(_) => {
                        problem(500, "failed to create search", &c, &id)
                    }
                }
            } else if search {
                let bytes =
                    crate::inventory::unescape(r.uri().path().split('/').nth(4).unwrap_or(""));
                let target = std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);
                match db::get_search(&worker, target).await {
                    Ok(body) => json_response(200, body, &c, id),
                    Err(error) if error.hint.as_deref() == Some("kql-validation") => {
                        problem(400, &error.message, &c, &id)
                    }
                    Err(_) => problem(404, "not found", &c, &id),
                }
            } else if hold || release {
                let Ok(fields) =
                    crate::admin_identity_input::first::<crate::chat::Fields>(&mut r, usize::MAX)
                        .await
                else {
                    return problem(400, "invalid request", &c, &id);
                };
                let Ok(ids) = pointer::<Vec<Option<i64>>>(&fields.0, "ids") else {
                    return problem(400, "invalid request", &c, &id);
                };
                let ids = ids.map(|xs| xs.into_iter().map(|x| x.unwrap_or(0)).collect::<Vec<_>>());
                let total = ids.as_ref().map_or(0, Vec::len);
                match db::hold(
                    &worker,
                    actor,
                    &ids,
                    hold,
                    &c.identity.client_ip.to_string(),
                    operation,
                )
                .await
                {
                    CommandOutcome::Committed(held) => {
                        let legal_hold_objects = if !held.is_empty() && worm_mode_enabled() {
                            apply_legal_hold(
                                &worker,
                                store.as_deref(),
                                &held,
                                hold,
                                worm_legal_hold_enabled(),
                            )
                            .await
                        } else {
                            0
                        };
                        json_response(
                            200,
                            if hold {
                                format!(
                                    "{{\"held\":{},\"legal_hold_objects\":{legal_hold_objects},\"total\":{total}}}\n",
                                    held.len()
                                )
                            } else {
                                format!("{{\"released\":{},\"total\":{total}}}\n", held.len())
                            },
                            &c,
                            id,
                        )
                    }
                    CommandOutcome::Unknown { .. } => unknown(operation, &c, &id),
                    CommandOutcome::RolledBack(_) => problem(500, "database error", &c, &id),
                }
            } else if create {
                let Ok(fields) =
                    crate::admin_identity_input::first::<crate::chat::Fields>(&mut r, usize::MAX)
                        .await
                else {
                    return problem(400, "invalid JSON", &c, &id);
                };
                let (Ok(name), Ok(description)) = (
                    scalar::<String>(&fields.0, "name"),
                    scalar::<String>(&fields.0, "description"),
                ) else {
                    return problem(400, "invalid JSON", &c, &id);
                };
                if name.is_empty() {
                    return problem(400, "name is required", &c, &id);
                }
                match db::create_case(&exec, actor, &name, &description, operation).await {
                    CommandOutcome::Committed(n) => {
                        json_response(201, format!("{{\"id\":{n}}}\n"), &c, id)
                    }
                    CommandOutcome::Unknown { .. } => unknown(operation, &c, &id),
                    CommandOutcome::RolledBack(_) => problem(500, "database error", &c, &id),
                }
            } else if close {
                let Some(target) = case_id(&r) else {
                    return problem(400, "invalid case id", &c, &id);
                };
                let Ok(fields) =
                    crate::admin_identity_input::first::<crate::chat::Fields>(&mut r, usize::MAX)
                        .await
                else {
                    return problem(400, "invalid JSON", &c, &id);
                };
                let Ok(reason) = scalar::<String>(&fields.0, "reason") else {
                    return problem(400, "invalid JSON", &c, &id);
                };
                match db::close_case(
                    &exec,
                    actor,
                    target,
                    &reason,
                    &c.identity.client_ip.to_string(),
                    operation,
                )
                .await
                {
                    CommandOutcome::Committed(true) => empty(&c, id),
                    CommandOutcome::Committed(false) => {
                        problem(404, "case not found or already closed", &c, &id)
                    }
                    CommandOutcome::Unknown { .. } => unknown(operation, &c, &id),
                    CommandOutcome::RolledBack(_) => problem(500, "database error", &c, &id),
                }
            } else if associate {
                let Ok(fields) =
                    crate::admin_identity_input::first::<crate::chat::Fields>(&mut r, usize::MAX)
                        .await
                else {
                    return problem(400, "invalid JSON", &c, &id);
                };
                let (Ok(search), Ok(case)) = (
                    scalar::<i64>(&fields.0, "searchid"),
                    scalar::<i64>(&fields.0, "caseid"),
                ) else {
                    return problem(400, "invalid JSON", &c, &id);
                };
                if search <= 0 || case <= 0 {
                    return problem(400, "searchId and caseId required", &c, &id);
                }
                match db::associate_search(&exec, actor, search, case, operation).await {
                    CommandOutcome::Committed(true) => empty(&c, id),
                    CommandOutcome::Committed(false) => problem(
                        404,
                        "search not found or already associated with a case",
                        &c,
                        &id,
                    ),
                    CommandOutcome::Unknown { .. } => unknown(operation, &c, &id),
                    CommandOutcome::RolledBack(_) => problem(500, "database error", &c, &id),
                }
            } else if delete {
                let Some(target) = case_id(&r) else {
                    return problem(400, "invalid case id", &c, &id);
                };
                match db::delete_case(&exec, actor, target, operation).await {
                    CommandOutcome::Committed(true) => empty(&c, id),
                    CommandOutcome::Committed(false) => {
                        problem(409, "case not found or has associated searches", &c, &id)
                    }
                    CommandOutcome::Unknown { .. } => unknown(operation, &c, &id),
                    CommandOutcome::RolledBack(_) => problem(500, "database error", &c, &id),
                }
            } else if update {
                let Some(target) = case_id(&r) else {
                    return problem(400, "invalid case id", &c, &id);
                };
                let Ok(fields) =
                    crate::admin_identity_input::first::<crate::chat::Fields>(&mut r, usize::MAX)
                        .await
                else {
                    return problem(400, "invalid JSON", &c, &id);
                };
                let (Ok(name), Ok(description)) = (
                    pointer::<String>(&fields.0, "name"),
                    pointer::<String>(&fields.0, "description"),
                ) else {
                    return problem(400, "invalid JSON", &c, &id);
                };
                if name.as_ref().is_none_or(|s| s.is_empty()) && description.is_none() {
                    return problem(400, "no fields to update", &c, &id);
                }
                match db::update_case(
                    &exec,
                    actor,
                    target,
                    name.as_deref(),
                    description.as_deref(),
                    operation,
                )
                .await
                {
                    CommandOutcome::Committed(true) => empty(&c, id),
                    CommandOutcome::Committed(false) => problem(404, "case not found", &c, &id),
                    CommandOutcome::Unknown { .. } => unknown(operation, &c, &id),
                    CommandOutcome::RolledBack(_) => problem(500, "database error", &c, &id),
                }
            } else if list {
                match db::list_cases(&exec).await {
                    Ok(body) => json_response(200, body, &c, id),
                    Err(_) => problem(500, "database error", &c, &id),
                }
            } else {
                let part =
                    crate::inventory::unescape(r.uri().path().split('/').nth(5).unwrap_or(""));
                let target = std::str::from_utf8(&part)
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok());
                let Some(target) = target.filter(|n| *n > 0) else {
                    return problem(400, "invalid case id", &c, &id);
                };
                match db::get_case(&exec, target).await {
                    Ok(body) => json_response(200, body, &c, id),
                    Err(_) => problem(404, "case not found", &c, &id),
                }
            }
        })
    }
}
pub(crate) fn problem(status: u16, detail: &str, c: &RequestContext, id: &str) -> Response<Body> {
    let mut response = json_response(
        status,
        crate::problem::Problem::new(status, detail).body(),
        c,
        id.into(),
    );
    *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
    response.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/problem+json"),
    );
    response
}

pub(crate) fn scalar<T: serde::de::DeserializeOwned + Default>(
    fields: &[(String, Box<serde_json::value::RawValue>)],
    name: &str,
) -> Result<T, ()> {
    let mut value = T::default();
    for (k, v) in fields {
        if crate::guests_input::fold(k) == name && v.get() != "null" {
            value = serde_json::from_str(v.get()).map_err(|_| ())?;
        }
    }
    Ok(value)
}
pub(crate) fn json_response(
    status: u16,
    body: String,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let chunked = body.len() > 2048;
    let mut r = crate::jmap::reply::response(body, c.identity.proto, id);
    if chunked {
        r.headers_mut()
            .insert("transfer-encoding", "chunked".parse().expect("header"));
        use http_body_util::BodyExt;
        let body = std::mem::replace(
            r.body_mut(),
            http_body_util::Empty::<bytes::Bytes>::new()
                .map_err(|never| match never {})
                .boxed(),
        );
        *r.body_mut() = UnknownLength(body).boxed();
    }
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
    r
}
pub(crate) fn unknown(operation: [u8; 16], c: &RequestContext, id: &str) -> Response<Body> {
    let mut r = problem(503, "operation outcome unknown", c, id);
    r.headers_mut().insert(
        "x-operation-id",
        crate::jmap::reply::hex(&operation).parse().expect("hex"),
    );
    r
}

pub(crate) fn pointer<T: serde::de::DeserializeOwned>(
    fields: &[(String, Box<serde_json::value::RawValue>)],
    name: &str,
) -> Result<Option<T>, ()> {
    let mut value = None;
    for (k, v) in fields {
        if crate::guests_input::fold(k) == name {
            value = serde_json::from_str(v.get()).map_err(|_| ())?;
        }
    }
    Ok(value)
}
fn case_id(r: &Request<Body>) -> Option<i64> {
    let part = crate::inventory::unescape(r.uri().path().split('/').nth(5)?);
    std::str::from_utf8(&part)
        .ok()?
        .parse::<i64>()
        .ok()
        .filter(|n| *n > 0)
}
fn empty(c: &RequestContext, id: String) -> Response<Body> {
    let mut r = json_response(204, String::new(), c, id);
    r.headers_mut().remove("content-type");
    r
}

/// Bounded process-local jobs; the routed request chooses the single writer.
#[derive(Clone)]
pub struct SearchJobs {
    database: setjoin_pg::workers::WorkerDatabase,
    slots: Arc<tokio::sync::Semaphore>,
}
impl SearchJobs {
    pub fn new(database: setjoin_pg::workers::WorkerDatabase, maximum: usize) -> Self {
        Self {
            database,
            slots: Arc::new(tokio::sync::Semaphore::new(maximum.max(1))),
        }
    }
    fn launch(&self, actor: i64, id: i64) {
        let jobs = self.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2 * 60 * 60), async move {
                let Ok(_permit) = jobs.slots.acquire().await else {
                    return;
                };
                if let Err(error) = db::search::execute(&jobs.database, actor, id).await {
                    eprintln!("ediscovery search {id} failed: {error}");
                }
            })
            .await;
        });
    }
}

async fn search_fields(r: &mut Request<Body>) -> Result<(crate::chat::Fields, bytes::Bytes), ()> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        if let Ok(data) = frame.map_err(|_| ())?.into_data() {
            bytes.extend_from_slice(&data);
        }
    }
    let original = bytes::Bytes::from(bytes);
    let fixed = crate::guests_input::go_json_bytes(&original);
    let fields = serde_json::Deserializer::from_slice(&fixed)
        .into_iter::<crate::chat::Fields>()
        .next()
        .ok_or(())?
        .map_err(|_| ())?;
    Ok((fields, original))
}

fn worm_mode_enabled() -> bool {
    std::env::var("WORM_MODE").is_ok_and(|mode| !mode.is_empty())
}

fn worm_legal_hold_enabled() -> bool {
    if !worm_mode_enabled() {
        return false;
    }
    match std::env::var("WORM_LEGAL_HOLD_ENABLED") {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "t" | "yes"
        ),
        Err(_) => true,
    }
}

async fn apply_legal_hold(
    worker: &ScopedExecutor,
    store: Option<&crate::recovery_worker::S3Store>,
    msg_ids: &[i64],
    on: bool,
    legal_hold_enabled: bool,
) -> usize {
    let Some(store) = store else {
        return 0;
    };
    let ids = msg_ids.to_vec();
    let rows = match worker
        .read(
            "SELECT DISTINCT blob_sha256 FROM message_attachments WHERE message_id = ANY($1)",
            &[(&ids, setjoin_pg::Type::INT8_ARRAY)],
        )
        .await
    {
        Ok(rows) => rows,
        Err(err) => {
            eprintln!("ediscovery: object legal hold lookup failed: {err:?}");
            return 0;
        }
    };
    let mut n = 0;
    for row in rows {
        let Ok(Some(hash)) = row.try_get::<_, Option<String>>(0) else {
            continue;
        };
        if hash.is_empty() {
            continue;
        }
        if legal_hold_enabled {
            if let Err(err) = store.legal_hold_with_retries(&hash, on).await {
                eprintln!("ediscovery: object legal hold failed key={hash}: {err}");
                continue;
            }
        }
        n += 1;
    }
    n
}

// Go flushes a large single JSON write before completion. Hide the known
// Full length so Hyper also omits Content-Length on HEAD for that response.
struct UnknownLength(Body);
impl hyper::body::Body for UnknownLength {
    type Data = bytes::Bytes;
    type Error = crate::BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<bytes::Bytes>, Self::Error>>> {
        std::pin::Pin::new(&mut self.0).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }
}
