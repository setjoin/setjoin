//! F04 retention/audit adapter; grants are resolved from the verified actor.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;
pub struct RetentionAuditRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
}
impl<K: KeySource + 'static> Intercept for RetentionAuditRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        r.uri().path().starts_with("/api/admin/retention/")
            || r.uri().path().starts_with("/api/admin/audit")
            || r.uri().path().starts_with("/api/admin/content-search/")
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_request(&exec, &keys, &issuer, &h, s)
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer, worker) = (
            self.exec.clone(),
            self.keys.clone(),
            self.issuer.clone(),
            self.worker.clone(),
        );
        Box::pin(async move {
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
            let actor = auth.context();
            let Ok(authority) = setjoin_compliance::authority(&exec, actor).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let Some(op) = crate::jmap::random() else {
                return crate::compliance::problem(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), op);
            let update = *r.method() == hyper::Method::PUT;
            let delete = *r.method() == hyper::Method::DELETE;
            let write = *r.method() == hyper::Method::POST || update || delete;
            let required: &[&str] = if r.uri().path().starts_with("/api/admin/audit") {
                if update || r.uri().path() == "/api/admin/audit/csv" {
                    &["audit.export"]
                } else {
                    &["audit.read"]
                }
            } else if write {
                &["compliance.write"]
            } else {
                &setjoin_compliance::MAIL_CONSOLE
            };
            if !authority.allows_any(required) {
                let _ = setjoin_compliance::console_denied(
                    &exec,
                    actor,
                    r.uri().path().trim_start_matches("/api"),
                    &required.join("|"),
                    op,
                )
                .await;
                return crate::compliance::problem(403, "Forbidden", &c, &id);
            }
            if r.uri().path().starts_with("/api/admin/content-search/") {
                if authority.domain_scope() > 0 {
                    let detail = format!(
                        "org-wide-only surface (domain-scoped principal; domain={})",
                        authority.domain_scope()
                    );
                    let _ = setjoin_compliance::console_denied(
                        &exec,
                        actor,
                        r.uri().path().trim_start_matches("/api"),
                        &detail,
                        op,
                    )
                    .await;
                    return crate::compliance::problem(403, "Forbidden", &c, &id);
                }
                let Ok((fields, _original)) = content_fields(&mut r).await else {
                    return crate::compliance::problem(400, "invalid request", &c, &id);
                };
                if r.uri().path() == "/api/admin/content-search/delete" {
                    let (Ok(ids), Ok(reason)) = (
                        crate::compliance::pointer::<Vec<Option<i64>>>(&fields.0, "ids"),
                        crate::compliance::scalar::<String>(&fields.0, "reason"),
                    ) else {
                        return crate::compliance::problem(400, "invalid request", &c, &id);
                    };
                    let ids = ids
                        .unwrap_or_default()
                        .into_iter()
                        .map(Option::unwrap_or_default)
                        .collect::<Vec<_>>();
                    if ids.is_empty() || ids.len() > 500 {
                        return crate::compliance::problem(400, "1-500 ids required", &c, &id);
                    }
                    if reason.len() < 10 {
                        return crate::compliance::problem(
                            400,
                            "reason required (min 10 chars)",
                            &c,
                            &id,
                        );
                    }
                    return match setjoin_compliance::content::purge(
                        &worker, actor, &ids, &reason, op,
                    )
                    .await
                    {
                        setjoin_pg::CommandOutcome::Committed(body) => {
                            crate::compliance::json_response(200, body, &c, id)
                        }
                        setjoin_pg::CommandOutcome::Unknown { .. } => {
                            crate::compliance::unknown(op, &c, &id)
                        }
                        setjoin_pg::CommandOutcome::RolledBack(_) => {
                            crate::compliance::problem(500, "purge failed", &c, &id)
                        }
                    };
                }
                let (Ok(keywords), Ok(kql), Ok(from), Ok(date_from), Ok(date_to), Ok(mailboxes)) = (
                    crate::compliance::scalar::<String>(&fields.0, "keywords"),
                    crate::compliance::scalar::<String>(&fields.0, "kql"),
                    crate::compliance::scalar::<String>(&fields.0, "fromaddr"),
                    crate::compliance::scalar::<String>(&fields.0, "datefrom"),
                    crate::compliance::scalar::<String>(&fields.0, "dateto"),
                    crate::compliance::pointer::<Vec<Option<i64>>>(&fields.0, "mailboxids"),
                ) else {
                    return crate::compliance::problem(400, "invalid request", &c, &id);
                };
                if kql.is_empty() && keywords.is_empty() && from.is_empty() {
                    return crate::compliance::json_response(
                        400,
                        "{\"error\":\"keywords, fromAddr, or kql required\"}\n".into(),
                        &c,
                        id,
                    );
                }
                let query = setjoin_compliance::content::Query {
                    keywords,
                    kql,
                    from,
                    date_from,
                    date_to,
                    mailboxes: mailboxes
                        .map(|xs| xs.into_iter().map(Option::unwrap_or_default).collect()),
                };
                return match setjoin_compliance::content::search(&worker, &query).await {
                    Ok(body) => crate::compliance::json_response(200, body, &c, id),
                    Err(e) if e.hint.as_deref() == Some("kql-validation") => {
                        crate::compliance::problem(400, &e.message, &c, &id)
                    }
                    Err(_) => crate::compliance::problem(500, "search failed", &c, &id),
                };
            }
            if r.uri().path().starts_with("/api/admin/audit") && authority.domain_scope() > 0 {
                let detail = format!(
                    "{} (domain-scoped principal; org-wide-only surface, domain={})",
                    required.join("|"),
                    authority.domain_scope()
                );
                let _ = setjoin_compliance::console_denied(
                    &exec,
                    actor,
                    r.uri().path().trim_start_matches("/api"),
                    &detail,
                    op,
                )
                .await;
                return crate::compliance::problem(403, "Forbidden", &c, &id);
            }
            if r.uri().path() == "/api/admin/audit/verify" {
                let value = |key: &str| {
                    crate::admin_identity_input::query(r.uri(), key)
                        .and_then(|s| s.parse::<i64>().ok())
                };
                return match setjoin_compliance::audit::verify(
                    &exec,
                    actor,
                    value("from_id"),
                    value("to_id"),
                )
                .await
                {
                    Ok(body) => crate::compliance::json_response(200, body, &c, id),
                    Err(_) => crate::compliance::problem(500, "verification failed", &c, &id),
                };
            }
            if r.uri().path() == "/api/admin/audit/csv" {
                let body = setjoin_compliance::audit::csv(&exec).await;
                let mut response = crate::compliance::json_response(200, body, &c, id);
                response
                    .headers_mut()
                    .insert("content-type", "text/csv".parse().unwrap());
                response.headers_mut().insert(
                    "content-disposition",
                    format!(
                        "attachment; filename=audit-log-{}.csv",
                        chrono::Local::now().format("%Y%m%d")
                    )
                    .parse()
                    .unwrap(),
                );
                return response;
            }
            if r.uri().path() == "/api/admin/audit" {
                for key in ["q", "action", "user_id", "target_type"] {
                    if crate::compliance_export::query_bytes(r.uri(), key)
                        .is_some_and(|v| std::str::from_utf8(&v).is_err())
                    {
                        return crate::compliance::problem(500, "database error", &c, &id);
                    }
                }

                let value = |key: &str| {
                    crate::admin_identity_input::query(r.uri(), key).unwrap_or_default()
                };
                let limit = value("limit")
                    .parse::<i64>()
                    .ok()
                    .filter(|n| *n > 0 && *n <= 100)
                    .unwrap_or(50);
                let offset = value("offset")
                    .parse::<i64>()
                    .unwrap_or(0)
                    .clamp(0, 1_000_000);
                let query = setjoin_compliance::audit::Query {
                    action: value("action"),
                    user: value("user_id"),
                    target: value("target_type"),
                    text: value("q"),
                    limit,
                    offset,
                };
                return match setjoin_compliance::audit::list(&exec, &query).await {
                    Ok(body) => crate::compliance::json_response(200, body, &c, id),
                    Err(_) => crate::compliance::problem(500, "database error", &c, &id),
                };
            }
            if r.uri().path() == "/api/admin/audit/policy" {
                if update {
                    if setjoin_compliance::audit::reason_required(&exec).await
                        && r.headers()
                            .get("x-audit-reason")
                            .is_none_or(|v| v.as_bytes().is_empty())
                    {
                        let _ = setjoin_compliance::audit::missing_reason(
                            &exec,
                            actor,
                            &c.identity.client_ip.to_string(),
                            op,
                        )
                        .await;
                        return crate::compliance::problem(400, "reason_required", &c, &id);
                    }
                    let Ok(fields) = crate::admin_identity_input::first::<crate::chat::Fields>(
                        &mut r,
                        usize::MAX,
                    )
                    .await
                    else {
                        return crate::compliance::problem(400, "invalid JSON", &c, &id);
                    };
                    let (Ok(level), Ok(areas), Ok(reason)) = (
                        crate::compliance::scalar::<String>(&fields.0, "level"),
                        crate::compliance::pointer::<Vec<Option<String>>>(
                            &fields.0,
                            "reasonrequiredareas",
                        ),
                        crate::compliance::scalar::<String>(&fields.0, "reason"),
                    ) else {
                        return crate::compliance::problem(400, "invalid JSON", &c, &id);
                    };
                    if reason.is_empty() {
                        return crate::compliance::problem(400, "reason_required", &c, &id);
                    }
                    if level != "lean" && level != "full" {
                        return crate::compliance::problem(
                            400,
                            "level must be 'lean' or 'full'",
                            &c,
                            &id,
                        );
                    }
                    let areas = areas
                        .unwrap_or_default()
                        .into_iter()
                        .map(|v| v.unwrap_or_default())
                        .collect::<Vec<_>>();
                    return match setjoin_compliance::audit::put(
                        &exec,
                        actor,
                        &level,
                        &areas,
                        &reason,
                        &c.identity.client_ip.to_string(),
                        op,
                    )
                    .await
                    {
                        setjoin_pg::CommandOutcome::Committed(true) => {
                            crate::compliance::json_response(
                                200,
                                setjoin_compliance::audit::policy_body(&level, &areas),
                                &c,
                                id,
                            )
                        }
                        setjoin_pg::CommandOutcome::Unknown { .. } => {
                            crate::compliance::unknown(op, &c, &id)
                        }
                        _ => crate::compliance::problem(500, "database error", &c, &id),
                    };
                }
                return match setjoin_compliance::audit::policy(&exec).await {
                    Ok(body) => crate::compliance::json_response(200, body, &c, id),
                    Err(_) => crate::compliance::problem(500, "database error", &c, &id),
                };
            }
            if r.uri().path() == "/api/admin/retention/logs" {
                if update {
                    let Ok(fields) =
                        crate::admin_identity_input::first::<crate::chat::Fields>(&mut r, 1 << 20)
                            .await
                    else {
                        return request_problem(400, "invalid JSON", &r, &c, &id);
                    };
                    let mut values = Vec::new();
                    for key in [
                        "messagetracedays",
                        "mailboxauditlogdays",
                        "autheventdays",
                        "webhookdeliverydays",
                    ] {
                        let Ok(value) = crate::compliance::pointer::<i64>(&fields.0, key) else {
                            return request_problem(400, "invalid JSON", &r, &c, &id);
                        };
                        values.push(value.unwrap_or(0).max(0));
                    }
                    return match setjoin_compliance::retention::log_set(&exec, actor, &values, op)
                        .await
                    {
                        setjoin_pg::CommandOutcome::Committed(()) => {
                            let mut r =
                                crate::compliance::json_response(204, String::new(), &c, id);
                            r.headers_mut().remove("content-type");
                            r
                        }
                        setjoin_pg::CommandOutcome::Unknown { .. } => {
                            crate::compliance::unknown(op, &c, &id)
                        }
                        setjoin_pg::CommandOutcome::RolledBack(_) => {
                            request_problem(500, "database error", &r, &c, &id)
                        }
                    };
                }
                return match setjoin_compliance::retention::log_get(&exec).await {
                    Ok(body) => crate::compliance::json_response(200, body, &c, id),
                    Err(_) => request_problem(500, "database error", &r, &c, &id),
                };
            }
            if r.uri().path() == "/api/admin/retention/prune" {
                return match setjoin_compliance::retention::prune(&exec, actor, op).await {
                    setjoin_pg::CommandOutcome::Committed(body) => {
                        crate::compliance::json_response(200, body, &c, id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { .. } => {
                        crate::compliance::unknown(op, &c, &id)
                    }
                    setjoin_pg::CommandOutcome::RolledBack(_) => {
                        request_problem(500, "database error", &r, &c, &id)
                    }
                };
            }
            if delete {
                let target =
                    crate::inventory::unescape(r.uri().path().rsplit('/').next().unwrap_or(""));
                let Some(target) = std::str::from_utf8(&target)
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok())
                else {
                    return request_problem(400, "invalid policy id", &r, &c, &id);
                };
                return match setjoin_compliance::retention::delete(
                    &exec,
                    actor,
                    authority.domain_scope(),
                    target,
                    &c.identity.client_ip.to_string(),
                    op,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(true) => {
                        let mut r = crate::compliance::json_response(204, String::new(), &c, id);
                        r.headers_mut().remove("content-type");
                        r
                    }
                    setjoin_pg::CommandOutcome::Committed(false) => {
                        request_problem(404, "policy not found", &r, &c, &id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { .. } => {
                        crate::compliance::unknown(op, &c, &id)
                    }
                    setjoin_pg::CommandOutcome::RolledBack(_) => {
                        request_problem(500, "database error", &r, &c, &id)
                    }
                };
            }
            if update {
                use crate::compliance::pointer;
                let target =
                    crate::inventory::unescape(r.uri().path().rsplit('/').next().unwrap_or(""));
                let Some(target) = std::str::from_utf8(&target)
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok())
                else {
                    return request_problem(400, "invalid policy id", &r, &c, &id);
                };
                let Ok(fields) =
                    crate::admin_identity_input::first::<crate::chat::Fields>(&mut r, 1 << 20)
                        .await
                else {
                    return request_problem(400, "invalid JSON", &r, &c, &id);
                };
                let (Ok(name), Ok(description), Ok(days), Ok(action), Ok(default), Ok(domain)) = (
                    pointer::<String>(&fields.0, "name"),
                    pointer::<String>(&fields.0, "description"),
                    pointer::<i64>(&fields.0, "retaindays"),
                    pointer::<String>(&fields.0, "action"),
                    pointer::<bool>(&fields.0, "isdefault"),
                    pointer::<i64>(&fields.0, "domainid"),
                ) else {
                    return request_problem(400, "invalid JSON", &r, &c, &id);
                };
                if authority.domain_scope() > 0
                    && domain.is_some_and(|n| n != authority.domain_scope())
                {
                    return request_problem(
                        403,
                        "cannot retarget a retention policy to another domain",
                        &r,
                        &c,
                        &id,
                    );
                }
                let mut patch = serde_json::json!({"name":name,"description":description,"retainDays":days,"action":action,"isDefault":default,"domainId":domain});
                patch.as_object_mut().unwrap().retain(|_, v| !v.is_null());
                if patch.as_object().unwrap().is_empty() {
                    return request_problem(400, "no fields to update", &r, &c, &id);
                }
                return match setjoin_compliance::retention::update(
                    &exec,
                    actor,
                    authority.domain_scope(),
                    target,
                    &patch.to_string(),
                    &c.identity.client_ip.to_string(),
                    op,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(true) => {
                        let mut r = crate::compliance::json_response(204, String::new(), &c, id);
                        r.headers_mut().remove("content-type");
                        r
                    }
                    setjoin_pg::CommandOutcome::Committed(false) => {
                        request_problem(404, "policy not found", &r, &c, &id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { .. } => {
                        crate::compliance::unknown(op, &c, &id)
                    }
                    setjoin_pg::CommandOutcome::RolledBack(_) => {
                        request_problem(500, "database error", &r, &c, &id)
                    }
                };
            }
            if write {
                use crate::compliance::{pointer, scalar};
                let Ok(fields) =
                    crate::admin_identity_input::first::<crate::chat::Fields>(&mut r, 1 << 20)
                        .await
                else {
                    return request_problem(400, "invalid JSON", &r, &c, &id);
                };
                let (Ok(name), Ok(description), Ok(days), Ok(mut action), Ok(default), Ok(domain)) = (
                    scalar::<String>(&fields.0, "name"),
                    scalar::<String>(&fields.0, "description"),
                    pointer::<i64>(&fields.0, "retaindays"),
                    scalar::<String>(&fields.0, "action"),
                    scalar::<bool>(&fields.0, "isdefault"),
                    pointer::<i64>(&fields.0, "domainid"),
                ) else {
                    return request_problem(400, "invalid JSON", &r, &c, &id);
                };
                if name.is_empty() {
                    return request_problem(400, "name is required", &r, &c, &id);
                }
                if action.is_empty() {
                    action = "delete".into();
                }
                if action != "delete" && action != "hold" {
                    return request_problem(400, "action must be delete or hold", &r, &c, &id);
                }
                if authority.domain_scope() > 0
                    && domain.is_some_and(|n| n != authority.domain_scope())
                {
                    return request_problem(
                        403,
                        "cannot create a retention policy for another domain",
                        &r,
                        &c,
                        &id,
                    );
                }
                let patch=serde_json::json!({"name":name,"description":description,"retainDays":days,"action":action,"isDefault":default,"domainId":domain}).to_string();
                return match setjoin_compliance::retention::create(
                    &exec,
                    actor,
                    authority.domain_scope(),
                    &patch,
                    &c.identity.client_ip.to_string(),
                    op,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(n) => {
                        crate::compliance::json_response(201, format!("{{\"id\":{n}}}\n"), &c, id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { .. } => {
                        crate::compliance::unknown(op, &c, &id)
                    }
                    setjoin_pg::CommandOutcome::RolledBack(_) => {
                        request_problem(500, "database error", &r, &c, &id)
                    }
                };
            }
            match setjoin_compliance::retention::policies(&exec, authority.domain_scope()).await {
                Ok(body) => crate::compliance::json_response(200, body, &c, id),
                Err(_) => request_problem(500, "database error", &r, &c, &id),
            }
        })
    }
}

fn request_problem(
    status: u16,
    detail: &str,
    r: &Request<Body>,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    let mut response = crate::compliance::json_response(
        status,
        crate::problem::Problem::new(status, detail)
            .instance(r.uri().path().trim_start_matches("/api"))
            .body(),
        c,
        id.into(),
    );
    response
        .headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    response
        .headers_mut()
        .insert("content-language", "en".parse().unwrap());
    response
}

async fn content_fields(r: &mut Request<Body>) -> Result<(crate::chat::Fields, bytes::Bytes), ()> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        if let Ok(data) = frame.map_err(|_| ())?.into_data() {
            if data.len() > 65536usize.saturating_sub(bytes.len()) {
                return Err(());
            }
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
