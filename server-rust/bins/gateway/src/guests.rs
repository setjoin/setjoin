//! F11 HTTP adapter.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;
pub struct GuestsRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    pub delivery: Option<Arc<dyn crate::recovery_worker::ObjectStore>>,
    pub lifecycle: Option<Arc<crate::guest_worker::GuestLifecycle>>,
}
impl<K: KeySource + 'static> Intercept for GuestsRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        let path = canonical_path(r.uri().path());
        path.starts_with("/api/admin/guest") || path == "/api/me/guest-invites"
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
        let (exec, worker, keys, issuer) = (
            self.exec.clone(),
            self.worker.clone(),
            self.keys.clone(),
            self.issuer.clone(),
        );
        let delivery = self.delivery.clone();
        let lifecycle = self.lifecycle.clone();
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
            let id = crate::jmap::reply::request_id(
                r.headers().get("x-request-id"),
                crate::jmap::random().unwrap_or([0; 16]),
            );
            let original_uri = r.uri().clone();
            if r.uri()
                .path()
                .split('/')
                .nth(1)
                .is_some_and(|part| part != "api" && crate::inventory::unescape(part) == b"api")
            {
                let mut response = crate::jmap::reply::response(
                    "404 page not found\n".into(),
                    c.identity.proto,
                    id,
                );
                *response.status_mut() = hyper::StatusCode::NOT_FOUND;
                response.headers_mut().insert(
                    "content-type",
                    hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                return response;
            }
            let canonical = canonical_path(r.uri().path());
            if canonical != r.uri().path() {
                let mut parts = r.uri().clone().into_parts();
                parts.path_and_query = Some(
                    format!(
                        "{}{}",
                        canonical,
                        r.uri().query().map(|q| format!("?{q}")).unwrap_or_default()
                    )
                    .parse()
                    .expect("escaped path"),
                );
                *r.uri_mut() = hyper::Uri::from_parts(parts).expect("original URI parts");
            }
            if !matches!(setjoin_guests::enabled(&exec).await, Ok(true)) {
                return problem(404, "not found", r.uri().path(), &c, id, None);
            }
            if r.method() == hyper::Method::POST && r.uri().path() == "/api/me/guest-invites" {
                if !matches!(setjoin_guests::approval_enabled(&exec).await, Ok(true)) {
                    return problem(404, "not found", r.uri().path(), &c, id, None);
                }
                let body = match crate::guests_input::read::<crate::guests_input::Submission>(
                    &mut r, 4096,
                )
                .await
                {
                    Ok(body) => body,
                    Err(()) => return problem(400, "invalid JSON", r.uri().path(), &c, id, None),
                };
                let email = match crate::guests_input::email(&body.email) {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid email", r.uri().path(), &c, id, None),
                };
                let message = body
                    .message
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let Some(operation) = crate::jmap::random() else {
                    return problem(503, "service unavailable", r.uri().path(), &c, id, None);
                };
                return match setjoin_guests::submit(
                    &worker,
                    auth.context(),
                    &email,
                    message,
                    operation,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(Some(request)) => {
                        let mut response = crate::jmap::reply::response(
                            format!("{{\"requestId\":{request}}}\n"),
                            c.identity.proto,
                            id,
                        );
                        *response.status_mut() = hyper::StatusCode::CREATED;
                        response
                    }
                    setjoin_pg::CommandOutcome::Committed(None) => problem(
                        422,
                        "no guest invite approval policy is configured",
                        r.uri().path(),
                        &c,
                        id,
                        None,
                    ),
                    setjoin_pg::CommandOutcome::RolledBack(e) => {
                        rejection(&e, r.uri().path(), &c, id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        unknown(operation, r.uri().path(), &c, id)
                    }
                };
            }
            if r.uri().path().starts_with("/api/admin/") {
                let write = !matches!(*r.method(), hyper::Method::GET | hyper::Method::HEAD)
                    || r.uri().path().ends_with("/sponsor-options");
                if !matches!(
                    setjoin_guests::allowed(&exec, auth.context(), write).await,
                    Ok(true)
                ) {
                    let decoded =
                        crate::guests_input::go_utf8(&crate::inventory::unescape(r.uri().path()));
                    let path = decoded.strip_prefix("/api").unwrap_or(&decoded);
                    let _ = setjoin_guests::console_denied(
                        &worker,
                        auth.context(),
                        path,
                        if write {
                            "guests.manage"
                        } else {
                            "guests.view|guests.manage"
                        },
                        crate::jmap::random().unwrap_or([0; 16]),
                    )
                    .await;
                    let mut response = problem(403, "Forbidden", "", &c, id, None);
                    response.headers_mut().remove("content-language");
                    return response;
                }
            }
            let create = r.method() == hyper::Method::POST && r.uri().path() == "/api/admin/guests";
            let recovery = r.method() == hyper::Method::POST
                && r.uri()
                    .path()
                    .strip_prefix("/api/admin/guests/")
                    .and_then(|s| s.strip_suffix("/reinvite"))
                    .is_some_and(|s| !s.contains('/'));
            if create || recovery {
                let target = if recovery {
                    match r
                        .uri()
                        .path()
                        .strip_prefix("/api/admin/guests/")
                        .and_then(|s| s.strip_suffix("/reinvite"))
                        .and_then(|s| s.parse::<i64>().ok())
                        .filter(|n| *n > 0)
                    {
                        Some(n) => n,
                        None => return problem(400, "invalid id", r.uri().path(), &c, id, None),
                    }
                } else {
                    0
                };
                let body = if create {
                    match crate::guests_input::read::<crate::guests_input::Invite>(&mut r, 1 << 20)
                        .await
                    {
                        Ok(body) => body,
                        Err(()) => {
                            return problem(400, "invalid JSON body", r.uri().path(), &c, id, None)
                        }
                    }
                } else {
                    match crate::guests_input::read::<crate::guests_input::Reinvite>(
                        &mut r,
                        1 << 20,
                    )
                    .await
                    {
                        Ok(body) => crate::guests_input::Invite {
                            expires: body.value,
                            ..Default::default()
                        },
                        Err(()) => {
                            return problem(400, "invalid JSON body", r.uri().path(), &c, id, None)
                        }
                    }
                };
                let email = if create {
                    match crate::guests_input::email(&body.email) {
                        Ok(v) => v,
                        Err(detail) => return problem(400, detail, r.uri().path(), &c, id, None),
                    }
                } else {
                    String::new()
                };
                if body.profile.is_some_and(|n| n <= 0) {
                    return problem(400, "invalid profileId", r.uri().path(), &c, id, None);
                }
                let Some((token, hash)) = crate::guest_mail::credential() else {
                    return problem(500, "database error", r.uri().path(), &c, id, None);
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(503, "service unavailable", r.uri().path(), &c, id, None);
                };
                let input = if create {
                    setjoin_guests::Invitation::Create {
                        email: &email,
                        name: &body.name,
                        expires: body.expires.as_deref(),
                        profile: body.profile,
                    }
                } else {
                    setjoin_guests::Invitation::Reinvite {
                        guest: target,
                        expires: body.expires.as_deref(),
                    }
                };
                return match setjoin_guests::invite(
                    &worker,
                    auth.context(),
                    input,
                    &hash,
                    operation,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(prepared) => {
                        if recovery {
                            if let Some(worker) = &lifecycle {
                                let _ = tokio::time::timeout(
                                    std::time::Duration::from_secs(5),
                                    worker.drain(Some(prepared.guest)),
                                )
                                .await;
                            }
                        }
                        let delivered = crate::guest_mail::send(
                            &worker,
                            delivery.as_deref(),
                            auth.context(),
                            &prepared,
                            &token,
                        )
                        .await;
                        let value = if delivered {
                            let mut v = serde_json::json!({"guestUserId":prepared.guest,"inviteId":prepared.invite.to_string(),"expiresAt":crate::guest_mail::expiry(&prepared.expires).unwrap_or_default()});
                            if create {
                                v["invitedEmail"] = serde_json::json!(email);
                            }
                            v
                        } else {
                            serde_json::json!({"code":"invite_delivery_unconfirmed","retryable":true,"inviteId":prepared.invite.to_string(),"guestUserId":prepared.guest,"error":"invitation created; email delivery could not be confirmed"})
                        };
                        let mut response = crate::jmap::reply::response(
                            crate::jmap::reply::go_compact(&value.to_string()).unwrap_or_default()
                                + "\n",
                            c.identity.proto,
                            id,
                        );
                        *response.status_mut() = if delivered {
                            hyper::StatusCode::ACCEPTED
                        } else {
                            hyper::StatusCode::SERVICE_UNAVAILABLE
                        };
                        response
                    }
                    setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(e))
                        if e.sqlstate.is_none() && e.message == "allowlist denied" =>
                    {
                        let detail = "invited domain is not in the guest invite allowlist";
                        let mut response = problem(403, detail, r.uri().path(), &c, id, None);
                        let body=format!("{{\"type\":\"BZ218\",\"title\":\"Forbidden\",\"status\":403,\"detail\":{},\"instance\":{}}}\n",serde_json::to_string(detail).unwrap(),serde_json::to_string(r.uri().path().strip_prefix("/api").unwrap_or(r.uri().path())).unwrap());
                        use http_body_util::BodyExt;
                        *response.body_mut() = http_body_util::Full::new(bytes::Bytes::from(body))
                            .map_err(|n| match n {})
                            .boxed();
                        response
                    }
                    setjoin_pg::CommandOutcome::RolledBack(e) => {
                        rejection(&e, r.uri().path(), &c, id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        unknown(operation, r.uri().path(), &c, id)
                    }
                };
            }
            if r.method() == hyper::Method::DELETE {
                if let Some(raw) = r
                    .uri()
                    .path()
                    .strip_prefix("/api/admin/guests/")
                    .and_then(|s| s.strip_suffix("/invite"))
                    .filter(|s| !s.contains('/'))
                {
                    let Some(target) = raw.parse::<i64>().ok().filter(|n| *n > 0) else {
                        return problem(400, "invalid userId", r.uri().path(), &c, id, None);
                    };
                    let value = match crate::guests_input::read::<crate::guests_input::Revoke>(
                        &mut r,
                        1 << 20,
                    )
                    .await
                    {
                        Ok(body) if !body.value.is_empty() => body.value,
                        _ => {
                            return problem(
                                400,
                                "expectedInviteId is required",
                                r.uri().path(),
                                &c,
                                id,
                                None,
                            )
                        }
                    };
                    let Some(invite) = value
                        .parse::<i64>()
                        .ok()
                        .filter(|n| *n > 0 && n.to_string() == value)
                    else {
                        return problem(
                            400,
                            "invalid expectedInviteId",
                            r.uri().path(),
                            &c,
                            id,
                            None,
                        );
                    };
                    let Some(operation) = crate::jmap::random() else {
                        return problem(503, "service unavailable", r.uri().path(), &c, id, None);
                    };
                    return match setjoin_guests::revoke(
                        &worker,
                        auth.context(),
                        target,
                        invite,
                        operation,
                    )
                    .await
                    {
                        setjoin_pg::CommandOutcome::Committed(result) => match result.as_str() {
                            "revoked" => empty(200, &c, id),
                            "not_found" => problem(
                                404,
                                "no pending invite for this guest",
                                r.uri().path(),
                                &c,
                                id,
                                None,
                            ),
                            "stale" => problem(
                                409,
                                "invitation changed; refresh before revoking",
                                r.uri().path(),
                                &c,
                                id,
                                None,
                            ),
                            _ => problem(500, "database error", r.uri().path(), &c, id, None),
                        },
                        setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(e))
                            if e.message == "forbidden" && e.sqlstate.is_none() =>
                        {
                            problem(403, "forbidden", r.uri().path(), &c, id, None)
                        }
                        setjoin_pg::CommandOutcome::RolledBack(e) => {
                            rejection(&e, r.uri().path(), &c, id)
                        }
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, r.uri().path(), &c, id)
                        }
                    };
                }
            }
            if r.method() == hyper::Method::DELETE {
                if let Some(raw) = r
                    .uri()
                    .path()
                    .strip_prefix("/api/admin/guest-invite-domains/")
                    .filter(|s| !s.contains('/'))
                {
                    let domain = crate::guests_input::lower(raw.trim());
                    if crate::guests_input::domain(&domain).is_err() {
                        return problem(400, "invalid domain", r.uri().path(), &c, id, None);
                    }
                    let Some(operation) = crate::jmap::random() else {
                        return problem(503, "service unavailable", r.uri().path(), &c, id, None);
                    };
                    return match setjoin_guests::set_domain(
                        &worker,
                        auth.context(),
                        &domain,
                        true,
                        operation,
                    )
                    .await
                    {
                        setjoin_pg::CommandOutcome::Committed(()) => empty(204, &c, id),
                        setjoin_pg::CommandOutcome::RolledBack(e) => {
                            rejection(&e, r.uri().path(), &c, id)
                        }
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, r.uri().path(), &c, id)
                        }
                    };
                }
            }
            if r.method() == hyper::Method::POST
                && r.uri().path() == "/api/admin/guest-invite-domains"
            {
                let domain =
                    match crate::guests_input::read::<crate::guests_input::Domain>(&mut r, 1 << 20)
                        .await
                    {
                        Ok(body) => crate::guests_input::lower(body.value.trim()),
                        Err(()) => {
                            return problem(400, "domain is required", r.uri().path(), &c, id, None)
                        }
                    };
                if let Err(reason) = crate::guests_input::domain(&domain) {
                    return problem(
                        400,
                        &format!("validation failed for domain: {reason}"),
                        r.uri().path(),
                        &c,
                        id,
                        None,
                    );
                }
                let Some(operation) = crate::jmap::random() else {
                    return problem(503, "service unavailable", r.uri().path(), &c, id, None);
                };
                return match setjoin_guests::set_domain(
                    &worker,
                    auth.context(),
                    &domain,
                    false,
                    operation,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(()) => {
                        let mut response = crate::jmap::reply::response(
                            serde_json::json!({"domain":domain}).to_string() + "\n",
                            c.identity.proto,
                            id,
                        );
                        *response.status_mut() = hyper::StatusCode::CREATED;
                        response
                    }
                    setjoin_pg::CommandOutcome::RolledBack(e) => {
                        rejection(&e, r.uri().path(), &c, id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        unknown(operation, r.uri().path(), &c, id)
                    }
                };
            }
            if r.method() == hyper::Method::PUT {
                if let Some(raw) = r
                    .uri()
                    .path()
                    .strip_prefix("/api/admin/guests/")
                    .and_then(|s| s.strip_suffix("/profile"))
                    .filter(|s| !s.contains('/'))
                {
                    let Some(target) = raw.parse::<i64>().ok().filter(|n| *n > 0) else {
                        return problem(400, "invalid id", r.uri().path(), &c, id, None);
                    };
                    let profile =
                        match crate::guests_input::read::<crate::guests_input::Assignment>(
                            &mut r,
                            1 << 20,
                        )
                        .await
                        {
                            Ok(body) => match body.target() {
                                Ok(id) => id,
                                Err(detail) => {
                                    return problem(400, detail, r.uri().path(), &c, id, None)
                                }
                            },
                            Err(()) => {
                                return problem(
                                    400,
                                    "invalid JSON body",
                                    r.uri().path(),
                                    &c,
                                    id,
                                    None,
                                )
                            }
                        };
                    let Some(operation) = crate::jmap::random() else {
                        return problem(503, "service unavailable", r.uri().path(), &c, id, None);
                    };
                    return match setjoin_guests::assign_profile(
                        &worker,
                        auth.context(),
                        target,
                        profile,
                        operation,
                    )
                    .await
                    {
                        setjoin_pg::CommandOutcome::Committed(()) => empty(204, &c, id),
                        setjoin_pg::CommandOutcome::RolledBack(e) => {
                            rejection(&e, r.uri().path(), &c, id)
                        }
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, r.uri().path(), &c, id)
                        }
                    };
                }
            }
            if r.method() == hyper::Method::POST {
                if let Some(raw) = r
                    .uri()
                    .path()
                    .strip_prefix("/api/admin/guests/")
                    .and_then(|s| s.strip_suffix("/transfer"))
                    .filter(|s| !s.contains('/'))
                {
                    let Some(target) = raw.parse::<i64>().ok().filter(|n| *n > 0) else {
                        return problem(400, "invalid id", r.uri().path(), &c, id, None);
                    };
                    let sponsor = match crate::guests_input::read::<crate::guests_input::Sponsor>(
                        &mut r,
                        1 << 20,
                    )
                    .await
                    {
                        Ok(body) if body.user > 0 => body.user,
                        _ => {
                            return problem(
                                400,
                                "positive sponsorUserId is required",
                                r.uri().path(),
                                &c,
                                id,
                                None,
                            )
                        }
                    };
                    let Some(operation) = crate::jmap::random() else {
                        return problem(503, "service unavailable", r.uri().path(), &c, id, None);
                    };
                    return match setjoin_guests::transfer(
                        &worker,
                        auth.context(),
                        target,
                        sponsor,
                        operation,
                    )
                    .await
                    {
                        setjoin_pg::CommandOutcome::Committed(body) => {
                            crate::jmap::reply::response(
                                crate::jmap::reply::go_compact(&body).unwrap_or_default() + "\n",
                                c.identity.proto,
                                id,
                            )
                        }
                        setjoin_pg::CommandOutcome::RolledBack(e) => {
                            rejection(&e, r.uri().path(), &c, id)
                        }
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, r.uri().path(), &c, id)
                        }
                    };
                }
            }
            if r.method() == hyper::Method::POST {
                if let Some((raw, action)) = r
                    .uri()
                    .path()
                    .strip_prefix("/api/admin/guests/")
                    .and_then(|s| s.rsplit_once('/'))
                    .filter(|(raw, action)| {
                        !raw.contains('/') && matches!(*action, "disable" | "enable" | "extend")
                    })
                {
                    let raw = raw.to_owned();
                    let action = action.to_owned();
                    let expires = if action == "extend" {
                        match crate::guests_input::read::<crate::guests_input::Expires>(
                            &mut r,
                            1 << 20,
                        )
                        .await
                        {
                            Ok(body) => match if body.zero { None } else { body.value } {
                                Some(value) => Some(value),
                                None => {
                                    return problem(
                                        400,
                                        "expiresAt is required",
                                        r.uri().path(),
                                        &c,
                                        id,
                                        None,
                                    )
                                }
                            },
                            Err(()) => {
                                return problem(
                                    400,
                                    "expiresAt is required",
                                    r.uri().path(),
                                    &c,
                                    id,
                                    None,
                                )
                            }
                        }
                    } else {
                        None
                    };
                    let Some(target) = raw.parse::<i64>().ok().filter(|n| *n > 0) else {
                        return problem(400, "invalid id", r.uri().path(), &c, id, None);
                    };
                    let Some(operation) = crate::jmap::random() else {
                        return problem(503, "service unavailable", r.uri().path(), &c, id, None);
                    };
                    return match setjoin_guests::set_status(
                        &worker,
                        auth.context(),
                        target,
                        &action,
                        expires.as_deref(),
                        operation,
                    )
                    .await
                    {
                        setjoin_pg::CommandOutcome::Committed(()) => {
                            if action == "disable" {
                                if let Some(worker) = &lifecycle {
                                    let _ = tokio::time::timeout(
                                        std::time::Duration::from_secs(5),
                                        worker.drain(Some(target)),
                                    )
                                    .await;
                                }
                            }
                            empty(204, &c, id)
                        }
                        setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(e))
                            if e.sqlstate.is_none() && e.message == "guest target not found" =>
                        {
                            problem(404, "guest not found", r.uri().path(), &c, id, None)
                        }
                        setjoin_pg::CommandOutcome::RolledBack(e) => {
                            rejection(&e, r.uri().path(), &c, id)
                        }
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, r.uri().path(), &c, id)
                        }
                    };
                }
            }
            if r.uri().path() == "/api/admin/guests"
                && matches!(*r.method(), hyper::Method::GET | hyper::Method::HEAD)
            {
                return match setjoin_guests::list(&worker, auth.context()).await {
                    Ok(body) => crate::jmap::reply::response(
                        crate::jmap::reply::go_compact(&body).unwrap_or_default() + "\n",
                        c.identity.proto,
                        id,
                    ),
                    Err(e) => db_error(&e, r.uri().path(), &c, id),
                };
            }
            if matches!(*r.method(), hyper::Method::GET | hyper::Method::HEAD) {
                if let Some(raw) = r
                    .uri()
                    .path()
                    .strip_prefix("/api/admin/guests/")
                    .and_then(|s| s.strip_suffix("/sponsor-options"))
                    .filter(|s| !s.contains('/'))
                {
                    let Some(target) = raw.parse::<i64>().ok().filter(|n| *n > 0) else {
                        return problem(400, "invalid id", r.uri().path(), &c, id, None);
                    };
                    let query = match query(&r, "q") {
                        Ok(q) => q,
                        Err(()) => {
                            return problem(500, "database error", r.uri().path(), &c, id, None)
                        }
                    };
                    let query = query.trim();
                    if query.len() > 200 {
                        return problem(400, "q is too long", r.uri().path(), &c, id, None);
                    }
                    return match setjoin_guests::sponsors(&worker, auth.context(), target, query)
                        .await
                    {
                        Ok(body) => crate::jmap::reply::response(
                            crate::jmap::reply::go_compact(&body).unwrap_or_default() + "\n",
                            c.identity.proto,
                            id,
                        ),
                        Err(e) => db_error(&e, r.uri().path(), &c, id),
                    };
                }

                if let Some(raw) = r
                    .uri()
                    .path()
                    .strip_prefix("/api/admin/guests/")
                    .filter(|s| !s.contains('/'))
                {
                    let Some(target) = raw.parse::<i64>().ok().filter(|n| *n > 0) else {
                        return problem(400, "invalid id", r.uri().path(), &c, id, None);
                    };
                    return match setjoin_guests::get(&worker, auth.context(), target).await {
                        Ok(Some(body)) => crate::jmap::reply::response(
                            crate::jmap::reply::go_compact(&body).unwrap_or_default() + "\n",
                            c.identity.proto,
                            id,
                        ),
                        Ok(None) => problem(404, "guest not found", r.uri().path(), &c, id, None),
                        Err(e) => db_error(&e, r.uri().path(), &c, id),
                    };
                }
            }
            if r.uri().path() == "/api/admin/guest-profile-domains" {
                return match setjoin_guests::profile_domains(&worker, auth.context()).await {
                    Ok(body) => crate::jmap::reply::response(
                        crate::jmap::reply::go_compact(&body).unwrap_or_default() + "\n",
                        c.identity.proto,
                        id,
                    ),
                    Err(error) => db_error(&error, r.uri().path(), &c, id),
                };
            }
            if (r.uri().path() == "/api/admin/guest-profiles" && r.method() == hyper::Method::POST)
                || (r.uri().path().starts_with("/api/admin/guest-profiles/")
                    && r.method() == hyper::Method::PUT)
            {
                let profile_id = if r.method() == hyper::Method::PUT {
                    match r
                        .uri()
                        .path()
                        .strip_prefix("/api/admin/guest-profiles/")
                        .and_then(|s| s.parse::<i64>().ok())
                        .filter(|n| *n > 0)
                    {
                        Some(n) => Some(n),
                        None => return problem(400, "invalid id", r.uri().path(), &c, id, None),
                    }
                } else {
                    None
                };
                let body = match crate::guests_input::read::<crate::guests_input::Profile>(
                    &mut r,
                    1 << 20,
                )
                .await
                {
                    Ok(body) => match body.payload() {
                        Ok(value) => value,
                        Err(detail) => return problem(400, detail, r.uri().path(), &c, id, None),
                    },
                    Err(()) => {
                        return problem(400, "invalid JSON body", r.uri().path(), &c, id, None)
                    }
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(503, "service unavailable", r.uri().path(), &c, id, None);
                };
                return match setjoin_guests::save_profile(
                    &worker,
                    auth.context(),
                    profile_id,
                    &body,
                    operation,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(body) => {
                        let mut response = crate::jmap::reply::response(
                            crate::jmap::reply::go_compact(&body).unwrap_or_default() + "\n",
                            c.identity.proto,
                            id,
                        );
                        *response.status_mut() = if profile_id.is_none() {
                            hyper::StatusCode::CREATED
                        } else {
                            hyper::StatusCode::OK
                        };
                        response
                    }
                    setjoin_pg::CommandOutcome::RolledBack(error) => {
                        rejection(&error, r.uri().path(), &c, id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        unknown(operation, r.uri().path(), &c, id)
                    }
                };
            }
            if r.uri().path() == "/api/admin/guest-profiles" {
                return match setjoin_guests::profiles(&worker, auth.context()).await {
                    Ok(body) => crate::jmap::reply::response(
                        crate::jmap::reply::go_compact(&body).unwrap_or_default() + "\n",
                        c.identity.proto,
                        id,
                    ),
                    Err(error) => db_error(&error, r.uri().path(), &c, id),
                };
            }
            if r.method() == hyper::Method::DELETE
                && r.uri().path().starts_with("/api/admin/guest-profiles/")
            {
                let Some(target) = r
                    .uri()
                    .path()
                    .strip_prefix("/api/admin/guest-profiles/")
                    .and_then(|s| s.parse::<i64>().ok())
                    .filter(|n| *n > 0)
                else {
                    return problem(400, "invalid id", r.uri().path(), &c, id, None);
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(503, "service unavailable", r.uri().path(), &c, id, None);
                };
                return match setjoin_guests::delete_profile(
                    &worker,
                    auth.context(),
                    target,
                    operation,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(()) => empty(204, &c, id),
                    setjoin_pg::CommandOutcome::RolledBack(e) => {
                        rejection(&e, r.uri().path(), &c, id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        unknown(operation, r.uri().path(), &c, id)
                    }
                };
            }
            if let Some(target) = r.uri().path().strip_prefix("/api/admin/guest-profiles/") {
                if let Ok(target) = target.parse::<i64>() {
                    return match setjoin_guests::profile(&worker, auth.context(), target).await {
                        Ok(body) => crate::jmap::reply::response(
                            crate::jmap::reply::go_compact(&body).unwrap_or_default() + "\n",
                            c.identity.proto,
                            id,
                        ),
                        Err(error) => db_error(&error, r.uri().path(), &c, id),
                    };
                } else {
                    return problem(400, "invalid id", r.uri().path(), &c, id, None);
                }
            }
            *r.uri_mut() = original_uri;
            c.upstream.forward(r, &c.identity).await
        })
    }
}

fn problem(
    status: u16,
    detail: &str,
    path: &str,
    c: &RequestContext,
    id: String,
    classified: Option<(&str, &str)>,
) -> Response<Body> {
    let decoded = crate::guests_input::go_utf8(&crate::inventory::unescape(path));
    let path = decoded.as_str();
    let code = hyper::StatusCode::from_u16(status).expect("status");
    let mut body = format!(
        "{{\"type\":{},\"title\":{},\"status\":{status},\"detail\":{},\"instance\":{}",
        serde_json::to_string(
            &classified
                .map(|(s, _)| format!(
                    "https://setjoin.com/problems/reducer/{}",
                    s.to_ascii_lowercase()
                ))
                .unwrap_or_else(|| "about:blank".into())
        )
        .unwrap(),
        serde_json::to_string(crate::problem::title(status)).unwrap(),
        serde_json::to_string(detail).unwrap(),
        serde_json::to_string(path.strip_prefix("/api").unwrap_or(path)).unwrap()
    );
    if let Some((code, remediation)) = classified {
        body.push_str(&format!(
            ",\"remediation\":{},\"code\":{},\"retryable\":false",
            serde_json::to_string(remediation).unwrap(),
            serde_json::to_string(code).unwrap()
        ));
    }
    body.push('}');
    let mut response = crate::jmap::reply::response(
        crate::jmap::reply::go_compact(&body).unwrap() + "\n",
        c.identity.proto,
        id,
    );
    *response.status_mut() = code;
    response.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/problem+json"),
    );
    response.headers_mut().insert(
        "content-language",
        hyper::header::HeaderValue::from_static("en"),
    );
    response
}
fn db_error(
    error: &setjoin_pg::StatementFailure,
    path: &str,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    match error.sqlstate.as_deref() {
        Some(code @ ("BZ162" | "BZ224")) => problem(
            422,
            "unprocessable",
            path,
            c,
            id,
            Some((
                code,
                "Correct the requested operation using the documented runbook and retry.",
            )),
        ),
        Some(code @ ("BZ218" | "BZ223" | "BZ002")) => problem(
            403,
            "forbidden",
            path,
            c,
            id,
            Some((
                code,
                "Complete the required authorization, approval, or recovery step before retrying.",
            )),
        ),
        Some("BZ221") => problem(
            409,
            "conflict",
            path,
            c,
            id,
            Some((
                "BZ221",
                "Refresh current state, resolve the conflict, and retry.",
            )),
        ),
        Some("BZ222") => problem(
            400,
            "invalidArguments",
            path,
            c,
            id,
            Some(("BZ222", "Correct the request fields and retry.")),
        ),
        Some("BZ170") => problem(
            404,
            "notFound",
            path,
            c,
            id,
            Some((
                "BZ170",
                "Refresh the target identifier and retry only if the resource still exists.",
            )),
        ),
        _ => problem(500, "database error", path, c, id, None),
    }
}

pub(crate) fn rejection(
    error: &setjoin_pg::Rejection<setjoin_pg::StatementFailure>,
    path: &str,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    match error {
        setjoin_pg::Rejection::Statement(e) | setjoin_pg::Rejection::Body(e) => {
            db_error(e, path, c, id)
        }
        _ => problem(500, "database error", path, c, id, None),
    }
}
fn unknown(
    operation: setjoin_contracts::ids::OperationId,
    path: &str,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let mut response = problem(503, "commit outcome unknown", path, c, id, None);
    response.headers_mut().insert(
        "x-operation-id",
        hyper::header::HeaderValue::from_str(&crate::jmap::reply::hex(&operation.0)).expect("hex"),
    );
    response
}

fn empty(status: u16, c: &RequestContext, id: String) -> Response<Body> {
    let mut response = crate::jmap::reply::response(String::new(), c.identity.proto, id);
    *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
    response.headers_mut().remove("content-type");
    response
}

fn query(r: &Request<Body>, name: &str) -> Result<String, ()> {
    fn decode(s: &str) -> Option<Vec<u8>> {
        let s = s.replace('+', " ");
        let b = s.as_bytes();
        for (i, c) in b.iter().enumerate() {
            if *c == b'%'
                && (i + 2 >= b.len()
                    || !b[i + 1].is_ascii_hexdigit()
                    || !b[i + 2].is_ascii_hexdigit())
            {
                return None;
            }
        }
        Some(crate::inventory::unescape(&s))
    }
    for part in r.uri().query().unwrap_or("").split('&') {
        if part.contains(';') {
            continue;
        }
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        let Some(k) = decode(k) else { continue };
        let Some(v) = decode(v) else { continue };
        if k == name.as_bytes() {
            return String::from_utf8(v).map_err(|_| ());
        }
    }
    Ok(String::new())
}

/// Decode URI components for Go ServeMux matching while keeping a quoted slash
/// inside its original wildcard segment and preserving percent-decoding depth.
fn canonical_path(path: &str) -> String {
    path.split('/')
        .map(|part| {
            let mut out = String::new();
            for byte in crate::inventory::unescape(part) {
                if byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&byte) {
                    out.push(byte as char)
                } else {
                    out.push_str(&format!("%{byte:02X}"));
                }
            }
            out
        })
        .collect::<Vec<_>>()
        .join("/")
}
