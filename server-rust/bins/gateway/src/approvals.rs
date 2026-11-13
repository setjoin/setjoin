//! F10 HTTP boundary shared by executable and replay.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use http_body_util::BodyExt;
use hyper::{Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;
pub struct ApprovalsRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker_exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    pub secret: Vec<u8>,
}
impl<K: KeySource + 'static> Intercept for ApprovalsRoute<K> {
    fn requires_session(&self, r: &Request<Body>) -> bool { email_target(r.uri().path()).is_none() }
    fn matches(&self, r: &Request<Body>) -> bool {
        email_target(r.uri().path()).is_some()
            || r.uri().path() == "/api/me/approvals"
            || r.uri().path() == "/api/me/approvals/hr"
            || cancel_target(r.uri().path()).is_some()
            || decision_target(r.uri().path()).is_some()
            || r.uri().path() == "/api/admin/approval-requests/audit"
            || r.uri().path() == "/api/admin/approval-policies/reorder"
            || policy_target(r.uri().path()).is_some()
            || (r.uri().path() == "/api/admin/approval-policies"
                && matches!(
                    *r.method(),
                    hyper::Method::GET | hyper::Method::HEAD | hyper::Method::POST
                ))
    }
    fn admits_member(&self, headers: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        let exec = self.exec.clone();
        let keys = self.keys.clone();
        let issuer = self.issuer.clone();
        Box::pin(async move {
            setjoin_authz::authorize_request(&exec, &keys, &issuer, &headers, scheme)
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let exec = self.exec.clone();
        let keys = self.keys.clone();
        let issuer = self.issuer.clone();
        let secret = self.secret.clone();
        let worker_exec = self.worker_exec.clone();
        Box::pin(async move {
            if let Some(token) = email_target(r.uri().path()) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let id = crate::jmap::reply::request_id(
                    r.headers().get("x-request-id"),
                    crate::jmap::random().unwrap_or([0; 16]),
                );
                let token =
                    String::from_utf8_lossy(&crate::inventory::unescape(token)).into_owned();
                let Some(cap) = setjoin_approvals::email::Capability::verify(&token, &secret, now)
                else {
                    return html(400, crate::approval_pages::BAD.into(), &c, id);
                };
                let Ok(Some((subject, status, consumer))) = cap.request(&exec).await else {
                    return html(
                        if r.method() == hyper::Method::POST {
                            200
                        } else {
                            400
                        },
                        if r.method() == hyper::Method::POST {
                            crate::approval_pages::INACTIVE
                        } else {
                            crate::approval_pages::BAD
                        }
                        .into(),
                        &c,
                        id,
                    );
                };
                if r.method() == hyper::Method::POST {
                    if !matches!(
                        consumer.as_str(),
                        "rbac.jit_activation"
                            | "drive.export"
                            | "drive.share"
                            | "mail.external_send"
                            | "mail.group_moderation"
                    ) {
                        return html(200, crate::approval_pages::INACTIVE.into(), &c, id);
                    }
                    let Some(operation) = crate::jmap::random() else {
                        return email_error(&c, id);
                    };
                    return match cap.decide(&exec, &worker_exec, &consumer, operation).await {
                        setjoin_pg::CommandOutcome::Committed(status) => {
                            let verb = match cap.decision() {
                                "approve" => "approved",
                                "deny" => "denied",
                                _ => &status,
                            };
                            html(
                                200,
                                crate::approval_pages::RESULT
                                    .replace("%%", "%")
                                    .replace("%s", verb),
                                &c,
                                id,
                            )
                        }
                        setjoin_pg::CommandOutcome::RolledBack(e) => match rejection_code(&e) {
                            Some("BZ108") => {
                                html(200, crate::approval_pages::INACTIVE.into(), &c, id)
                            }
                            Some("BZ107") => html(400, crate::approval_pages::BAD.into(), &c, id),
                            _ => email_error(&c, id),
                        },
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, r.uri().path(), &c, id)
                        }
                    };
                }
                if status != "pending" {
                    return html(200, crate::approval_pages::INACTIVE.into(), &c, id);
                }
                let label = if cap.decision() == "deny" {
                    "Deny"
                } else {
                    "Approve"
                };
                let class = if cap.decision() == "deny" {
                    "btn-deny"
                } else {
                    "btn-approve"
                };
                let template = crate::approval_pages::CONFIRM
                    .replace("%%", "%")
                    .replace("%[4]s", label);
                let mut parts = template.split("%s");
                let page = format!(
                    "{}{}{}{}{}{}{}",
                    parts.next().unwrap_or(""),
                    escape_html(&subject),
                    parts.next().unwrap_or(""),
                    format_args!("/approvals/email/{token}"),
                    parts.next().unwrap_or(""),
                    class,
                    parts.next().unwrap_or("")
                );
                return html(200, page, &c, id);
            }
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
                return problem(
                    503,
                    "service unavailable",
                    r.uri().path(),
                    &c,
                    String::new(),
                );
            };
            let request_id =
                crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            if r.uri().path() == "/api/admin/approval-requests/audit"
                || r.uri().path() == "/api/admin/approval-policies"
                || r.uri().path() == "/api/admin/approval-policies/reorder"
                || policy_target(r.uri().path()).is_some()
            {
                let actor = auth.context();
                if !actor.signed_admin() && !actor.signed_permissions().is_empty() {
                    return c.upstream.forward(r, &c.identity).await;
                }
                let Ok(authority) = setjoin_approvals::admin_authority(&exec, actor).await else {
                    return c.upstream.forward(r, &c.identity).await;
                };
                let manage = !matches!(*r.method(), hyper::Method::GET | hyper::Method::HEAD);
                if !(if manage {
                    authority.can_manage()
                } else {
                    authority.can_view()
                }) {
                    let path = r
                        .uri()
                        .path()
                        .strip_prefix("/api")
                        .unwrap_or(r.uri().path());
                    let _ = setjoin_approvals::console_denied(
                        &exec,
                        actor,
                        path,
                        if manage {
                            "approvals.manage"
                        } else {
                            "approvals.view|approvals.manage"
                        },
                        operation,
                    )
                    .await;
                    let mut response = problem(403, "Forbidden", "", &c, request_id);
                    response.headers_mut().remove("content-language");
                    return response;
                }
                if r.uri().path() == "/api/admin/approval-requests/audit" {
                    let limit = query_value(r.uri(), "limit")
                        .and_then(|s| s.parse::<i64>().ok())
                        .filter(|n| *n > 0 && *n <= 500)
                        .unwrap_or(50);
                    let offset = query_value(r.uri(), "offset")
                        .and_then(|s| s.parse::<i64>().ok())
                        .unwrap_or(0)
                        .clamp(0, 1_000_000);
                    return match setjoin_approvals::audit_requests(
                        &exec,
                        actor,
                        authority.domain_scope(),
                        limit,
                        offset,
                    )
                    .await
                    {
                        Ok(body) => {
                            crate::jmap::reply::response(body, c.identity.proto, request_id)
                        }
                        Err(_) => problem(500, "database error", r.uri().path(), &c, request_id),
                    };
                }
                if r.uri().path() == "/api/admin/approval-policies/reorder" {
                    let Ok(body) = read_one::<CreatePolicyBody>(&mut r, 1 << 20).await else {
                        return problem(400, "invalid JSON", r.uri().path(), &c, request_id);
                    };
                    if !setjoin_approvals::valid_consumer(&body.consumer_type) {
                        return problem(
                            400,
                            "invalid consumerType",
                            r.uri().path(),
                            &c,
                            request_id,
                        );
                    }
                    let payload=serde_json::json!({"consumerType":body.consumer_type,"orderedIds":body.ordered_ids}).to_string();
                    return match setjoin_approvals::reorder_policies(
                        &exec, actor, &payload, operation,
                    )
                    .await
                    {
                        setjoin_pg::CommandOutcome::Committed(_) => {
                            let mut secondary = operation;
                            secondary[15] ^= 0x80;
                            let _ = setjoin_approvals::audit_policy_change(
                                &exec,
                                actor,
                                "approval_policy_reorder",
                                None,
                                Some(&payload),
                                &c.identity.client_ip.to_string(),
                                secondary,
                            )
                            .await;
                            no_content(&c, request_id)
                        }
                        setjoin_pg::CommandOutcome::RolledBack(e) => {
                            if rejection_code(&e) == Some("23505") {
                                conflict(
                                    "priority conflict during reorder",
                                    r.uri().path(),
                                    &c,
                                    request_id,
                                )
                            } else {
                                rejection(&e, r.uri().path(), &c, request_id)
                            }
                        }
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, r.uri().path(), &c, request_id)
                        }
                    };
                }
                if let Some(target) = policy_target(r.uri().path()) {
                    let Some(id) = String::from_utf8(crate::inventory::unescape(target))
                        .ok()
                        .and_then(|s| s.parse::<i64>().ok())
                    else {
                        return problem(400, "invalid policy id", r.uri().path(), &c, request_id);
                    };
                    if r.method() == hyper::Method::DELETE {
                        return match setjoin_approvals::delete_policy(&exec, actor, id, operation)
                            .await
                        {
                            setjoin_pg::CommandOutcome::Committed(0) => {
                                problem(404, "policy not found", r.uri().path(), &c, request_id)
                            }
                            setjoin_pg::CommandOutcome::Committed(_) => {
                                let mut secondary = operation;
                                secondary[15] ^= 0x80;
                                let _ = setjoin_approvals::audit_policy_change(
                                    &exec,
                                    actor,
                                    "approval_policy_delete",
                                    Some(id),
                                    None,
                                    &c.identity.client_ip.to_string(),
                                    secondary,
                                )
                                .await;
                                no_content(&c, request_id)
                            }
                            setjoin_pg::CommandOutcome::RolledBack(e) => {
                                if rejection_code(&e)
                                    .is_some_and(|code| matches!(code, "23503" | "P0001"))
                                {
                                    conflict(
                                        "policy is referenced by existing approval requests",
                                        r.uri().path(),
                                        &c,
                                        request_id,
                                    )
                                } else {
                                    rejection(&e, r.uri().path(), &c, request_id)
                                }
                            }
                            setjoin_pg::CommandOutcome::Unknown { operation } => {
                                unknown(operation, r.uri().path(), &c, request_id)
                            }
                        };
                    }
                    let Ok(body) = read_one::<PatchPolicyBody>(&mut r, 1 << 20).await else {
                        return problem(400, "invalid JSON", r.uri().path(), &c, request_id);
                    };
                    for (field, message) in [
                        ("conditions", "conditions must be a JSON object"),
                        ("approverSpec", "approverSpec must be a JSON object"),
                    ] {
                        if body
                            .fields
                            .get(field)
                            .is_some_and(|v| !v.get().trim_start().starts_with('{'))
                        {
                            return problem(400, message, r.uri().path(), &c, request_id);
                        }
                    }
                    let payload = serde_json::to_string(&body.fields).expect("patch");
                    return match setjoin_approvals::update_policy(
                        &exec, actor, id, &payload, operation,
                    )
                    .await
                    {
                        setjoin_pg::CommandOutcome::Committed(0) => {
                            problem(404, "policy not found", r.uri().path(), &c, request_id)
                        }
                        setjoin_pg::CommandOutcome::Committed(_) => {
                            let mut secondary = operation;
                            secondary[15] ^= 0x80;
                            let name = body.fields.get("name").map(|v| v.get()).unwrap_or("null");
                            let after = format!("{{\"id\":{id},\"name\":{name}}}");
                            let _ = setjoin_approvals::audit_policy_change(
                                &exec,
                                actor,
                                "approval_policy_update",
                                Some(id),
                                Some(&after),
                                &c.identity.client_ip.to_string(),
                                secondary,
                            )
                            .await;
                            no_content(&c, request_id)
                        }
                        setjoin_pg::CommandOutcome::RolledBack(e) => {
                            rejection(&e, r.uri().path(), &c, request_id)
                        }
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, r.uri().path(), &c, request_id)
                        }
                    };
                }
                if manage {
                    let body = read_one::<CreatePolicyBody>(&mut r, 1 << 20).await;
                    let Ok(body) = body else {
                        return problem(400, "invalid JSON", r.uri().path(), &c, request_id);
                    };
                    if !setjoin_approvals::valid_consumer(&body.consumer_type) {
                        return problem(
                            400,
                            "invalid consumerType",
                            r.uri().path(),
                            &c,
                            request_id,
                        );
                    }
                    if body.name.is_empty() {
                        return problem(400, "name is required", r.uri().path(), &c, request_id);
                    }
                    let Some(conditions) = body
                        .conditions
                        .as_ref()
                        .filter(|v| v.get().trim_start().starts_with('{'))
                    else {
                        return problem(
                            400,
                            "conditions must be a JSON object",
                            r.uri().path(),
                            &c,
                            request_id,
                        );
                    };
                    let Some(spec) = body
                        .approver_spec
                        .as_ref()
                        .filter(|v| v.get().trim_start().starts_with('{'))
                    else {
                        return problem(
                            400,
                            "approverSpec must be a JSON object",
                            r.uri().path(),
                            &c,
                            request_id,
                        );
                    };
                    let payload=format!("{{\"consumerType\":{},\"name\":{},\"enabled\":{},\"conditions\":{},\"requiresApproval\":{},\"approverSpec\":{}}}",serde_json::to_string(&body.consumer_type).expect("consumer"),serde_json::to_string(&body.name).expect("name"),body.enabled,conditions.get(),body.requires_approval,spec.get());
                    return match setjoin_approvals::create_policy(&exec, actor, &payload, operation)
                        .await
                    {
                        setjoin_pg::CommandOutcome::Committed(id) => {
                            let mut audit_operation = operation;
                            audit_operation[15] ^= 0x80;
                            let _ = setjoin_approvals::audit_policy_created(
                                &exec,
                                actor,
                                id,
                                &body.consumer_type,
                                &body.name,
                                &c.identity.client_ip.to_string(),
                                audit_operation,
                            )
                            .await;
                            let mut response = crate::jmap::reply::response(
                                format!("{{\"id\":{id}}}\n"),
                                c.identity.proto,
                                request_id,
                            );
                            *response.status_mut() = hyper::StatusCode::CREATED;
                            response
                        }
                        setjoin_pg::CommandOutcome::RolledBack(error) => {
                            if rejection_code(&error) == Some("23505") {
                                conflict(
                                    "priority conflict — try again",
                                    r.uri().path(),
                                    &c,
                                    request_id,
                                )
                            } else {
                                rejection(&error, r.uri().path(), &c, request_id)
                            }
                        }
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            let mut response = problem(
                                503,
                                "approval outcome unknown",
                                r.uri().path(),
                                &c,
                                request_id,
                            );
                            response.headers_mut().insert(
                                "x-operation-id",
                                setjoin_pg::operation_hex(operation)
                                    .parse()
                                    .expect("operation"),
                            );
                            response
                        }
                    };
                }
                let consumer = query_value(r.uri(), "consumer_type").unwrap_or_default();
                if !consumer.is_empty() && !setjoin_approvals::valid_consumer(&consumer) {
                    return problem(400, "invalid consumer_type", r.uri().path(), &c, request_id);
                }
                return match setjoin_approvals::policies(&exec, actor, &consumer).await {
                    Ok(body) => crate::jmap::reply::response(body, c.identity.proto, request_id),
                    Err(_) => problem(500, "database error", r.uri().path(), &c, request_id),
                };
            }
            if r.uri().path() == "/api/me/approvals/hr" {
                let Ok(body) = read_one::<CreatePolicyBody>(&mut r, 1 << 20).await else {
                    return problem(400, "invalid JSON", r.uri().path(), &c, request_id);
                };
                match setjoin_approvals::hr_enabled(&exec, &body.kind).await {
                    Ok(true) => {}
                    Ok(false) => return problem(404, "not found", r.uri().path(), &c, request_id),
                    Err(_) => {
                        return problem(500, "database error", r.uri().path(), &c, request_id)
                    }
                }
                let form = body.form.as_ref().map(|v| v.get()).unwrap_or("null");
                return match setjoin_approvals::submit_hr(
                    &exec,
                    auth.context(),
                    &body.kind,
                    form,
                    operation,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(Some(id)) => {
                        let mut r = crate::jmap::reply::response(
                            format!("{{\"id\":{id}}}\n"),
                            c.identity.proto,
                            request_id,
                        );
                        *r.status_mut() = hyper::StatusCode::CREATED;
                        r
                    }
                    setjoin_pg::CommandOutcome::Committed(None) => problem(
                        422,
                        "no approval policy configured for this request",
                        r.uri().path(),
                        &c,
                        request_id,
                    ),
                    setjoin_pg::CommandOutcome::RolledBack(e) => {
                        rejection(&e, r.uri().path(), &c, request_id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        unknown(operation, r.uri().path(), &c, request_id)
                    }
                };
            }
            if let Some(target) = decision_target(r.uri().path()) {
                let id = String::from_utf8(crate::inventory::unescape(target))
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok());
                let Some(id) = id else {
                    return problem(400, "invalid id", r.uri().path(), &c, request_id);
                };
                let consumer = setjoin_approvals::visible_consumer(&exec, auth.context(), id).await;
                let raw = read_body(&mut r, 4096).await;
                let body = raw
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<Decision>(&bytes).ok());
                let Some(body) = body else {
                    return problem(400, "invalid JSON", r.uri().path(), &c, request_id);
                };
                if !matches!(body.decision.as_str(), "approve" | "deny") {
                    return problem(
                        400,
                        "decision must be \"approve\" or \"deny\"",
                        r.uri().path(),
                        &c,
                        request_id,
                    );
                }
                let consumer = match consumer {
                    Ok(Some(kind)) => kind,
                    Ok(None) => {
                        return problem(
                            404,
                            "approval request not found",
                            r.uri().path(),
                            &c,
                            request_id,
                        )
                    }
                    Err(_) => {
                        return problem(500, "database error", r.uri().path(), &c, request_id)
                    }
                };
                if consumer == "guest.invite" {
                    let credential = if body.decision == "approve" {
                        crate::guest_mail::credential()
                    } else {
                        Some((String::new(), "0".repeat(64)))
                    };
                    let Some((token, hash)) = credential else {
                        return problem(500, "database error", r.uri().path(), &c, request_id);
                    };
                    let outcome = setjoin_guests::invite(
                        &worker_exec,
                        auth.context(),
                        setjoin_guests::Invitation::Approval {
                            request: id,
                            decision: &body.decision,
                            comment: body.comment.as_deref(),
                        },
                        &hash,
                        operation,
                    )
                    .await;
                    return match outcome {
                        setjoin_pg::CommandOutcome::Committed(prepared) => {
                            if prepared.status.as_deref() == Some("applied") {
                                let store = crate::recovery_worker::S3Store::from_env().ok();
                                let _ = crate::guest_mail::send(
                                    &worker_exec,
                                    store
                                        .as_ref()
                                        .map(|s| s as &dyn crate::recovery_worker::ObjectStore),
                                    auth.context(),
                                    &prepared,
                                    &token,
                                )
                                .await;
                            }
                            crate::jmap::reply::response(
                                serde_json::json!({"status":prepared.status.unwrap_or_default()})
                                    .to_string()
                                    + "\n",
                                c.identity.proto,
                                request_id,
                            )
                        }
                        setjoin_pg::CommandOutcome::RolledBack(e) => {
                            if matches!(
                                rejection_code(&e),
                                Some("BZ218" | "BZ221" | "BZ222" | "BZ223" | "BZ162" | "BZ170")
                            ) {
                                crate::guests::rejection(&e, r.uri().path(), &c, request_id)
                            } else {
                                rejection(&e, r.uri().path(), &c, request_id)
                            }
                        }
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, r.uri().path(), &c, request_id)
                        }
                    };
                }
                if consumer == "drive.access" {
                    let epoch = body
                        ._expected_epoch
                        .as_ref()
                        .and_then(|s| s.parse::<i64>().ok())
                        .filter(|n| *n >= 0);
                    if (body.decision == "approve" && epoch.is_none())
                        || (body._expected_epoch.is_some() && epoch.is_none())
                        || body
                            ._expires_at
                            .as_ref()
                            .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_err())
                    {
                        return problem(
                            422,
                            "invalid Drive access decision payload",
                            r.uri().path(),
                            &c,
                            request_id,
                        );
                    }
                    let outcome = setjoin_approvals::decide_drive_access(
                        &exec,
                        auth.context(),
                        id,
                        &body.decision,
                        body.comment.as_deref(),
                        setjoin_approvals::DriveDecision {
                            capabilities: body._capabilities.as_deref(),
                            propagation: body._propagation.as_deref(),
                            expires_at: body._expires_at.as_deref(),
                            max_uses: body._max_uses,
                            expected_epoch: epoch,
                        },
                        operation,
                    )
                    .await;
                    return match outcome {
                        setjoin_pg::CommandOutcome::Committed(status) => {
                            crate::jmap::reply::response(
                                format!(
                                    "{{\"status\":{}}}\n",
                                    serde_json::to_string(&status).expect("status")
                                ),
                                c.identity.proto,
                                request_id,
                            )
                        }
                        setjoin_pg::CommandOutcome::RolledBack(e) => {
                            rejection(&e, r.uri().path(), &c, request_id)
                        }
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, r.uri().path(), &c, request_id)
                        }
                    };
                }
                if !matches!(
                    consumer.as_str(),
                    "hr.leave"
                        | "hr.expense"
                        | "rbac.jit_activation"
                        | "drive.export"
                        | "drive.share"
                        | "mail.external_send"
                        | "mail.group_moderation"
                ) {
                    return problem(
                        501,
                        "consumer type not yet wired",
                        r.uri().path(),
                        &c,
                        request_id,
                    );
                }
                return match setjoin_approvals::decide_consumer(
                    if matches!(
                        consumer.as_str(),
                        "mail.external_send" | "mail.group_moderation"
                    ) {
                        &worker_exec
                    } else {
                        &exec
                    },
                    &setjoin_approvals::scope(auth.context()),
                    &consumer,
                    id,
                    &body.decision,
                    body.comment.as_deref(),
                    operation,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(status) => crate::jmap::reply::response(
                        format!(
                            "{{\"status\":{}}}\n",
                            serde_json::to_string(&status).expect("status")
                        ),
                        c.identity.proto,
                        request_id,
                    ),
                    setjoin_pg::CommandOutcome::RolledBack(error) => {
                        rejection(&error, r.uri().path(), &c, request_id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        let mut response = problem(
                            503,
                            "approval outcome unknown",
                            r.uri().path(),
                            &c,
                            request_id,
                        );
                        response.headers_mut().insert(
                            "x-operation-id",
                            setjoin_pg::operation_hex(operation)
                                .parse()
                                .expect("operation"),
                        );
                        response
                    }
                };
            }
            if let Some(target) = cancel_target(r.uri().path()) {
                let id = String::from_utf8(crate::inventory::unescape(target))
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok());
                let Some(id) = id else {
                    return problem(400, "invalid id", r.uri().path(), &c, request_id);
                };
                return match setjoin_approvals::cancel_request(&exec, auth.context(), id, operation)
                    .await
                {
                    setjoin_pg::CommandOutcome::Committed(status) => crate::jmap::reply::response(
                        format!(
                            "{{\"status\":{}}}\n",
                            serde_json::to_string(&status).expect("status")
                        ),
                        c.identity.proto,
                        request_id,
                    ),
                    setjoin_pg::CommandOutcome::RolledBack(error) => {
                        rejection(&error, r.uri().path(), &c, request_id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        let mut response = problem(
                            503,
                            "approval outcome unknown",
                            r.uri().path(),
                            &c,
                            request_id,
                        );
                        response.headers_mut().insert(
                            "x-operation-id",
                            setjoin_pg::operation_hex(operation)
                                .parse()
                                .expect("operation hex"),
                        );
                        response
                    }
                };
            }
            match setjoin_approvals::my_approvals(&exec, auth.context()).await {
                Ok(body) => crate::jmap::reply::response(body, c.identity.proto, request_id),
                Err(_) => problem(500, "database error", r.uri().path(), &c, request_id),
            }
        })
    }
}
fn cancel_target(path: &str) -> Option<&str> {
    path.strip_prefix("/api/me/approvals/")?
        .strip_suffix("/cancel")
        .filter(|s| !s.is_empty() && !s.contains('/'))
}
fn problem(
    status: u16,
    detail: &str,
    path: &str,
    ctx: &RequestContext,
    id: String,
) -> Response<Body> {
    let code = hyper::StatusCode::from_u16(status).expect("status");
    let title = crate::problem::title(status);
    let instance = path.strip_prefix("/api").unwrap_or(path);
    let body=format!("{{\"type\":\"about:blank\",\"title\":{},\"status\":{status},\"detail\":{},\"instance\":{}}}\n",serde_json::to_string(title).expect("title"),serde_json::to_string(detail).expect("detail"),serde_json::to_string(instance).expect("path"));
    let mut r = crate::jmap::reply::response(
        setjoin_approvals::go_json(&body) + "\n",
        ctx.identity.proto,
        id,
    );
    *r.status_mut() = code;
    r.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/problem+json"),
    );
    r.headers_mut().insert(
        "content-language",
        hyper::header::HeaderValue::from_static("en"),
    );
    r
}

fn rejection(
    error: &setjoin_pg::Rejection<setjoin_pg::StatementFailure>,
    path: &str,
    ctx: &RequestContext,
    id: String,
) -> Response<Body> {
    let failure = match error {
        setjoin_pg::Rejection::Statement(e) | setjoin_pg::Rejection::Body(e) => Some(e),
        _ => None,
    };
    if failure.and_then(|f| f.sqlstate.as_deref()) == Some("BZ008") {
        let instance = path.strip_prefix("/api").unwrap_or(path);
        let body=format!("{{\"type\":\"about:blank\",\"title\":\"Internal Server Error\",\"status\":500,\"detail\":\"request failed\",\"instance\":{},\"remediation\":\"Retry after the service dependency or configuration has recovered.\",\"retryable\":true}}\n",serde_json::to_string(instance).expect("path"));
        let mut r = problem(500, "request failed", path, ctx, id);
        *r.body_mut() =
            http_body_util::Full::new(bytes::Bytes::from(setjoin_approvals::go_json(&body) + "\n"))
                .map_err(|never| match never {})
                .boxed();
        return r;
    }
    let hint = failure
        .and_then(|f| f.hint.as_deref())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
    let (code, status, detail, remediation) = match failure.and_then(|f| f.sqlstate.as_deref()) {
        Some("BZ125") => (
            "BZ125",
            404,
            "notFound",
            "Refresh the target identifier and retry only if the resource still exists.",
        ),
        Some(code @ ("BZ106" | "BZ108" | "BZ110")) => (
            code,
            409,
            failure.expect("classified").message.as_str(),
            "Refresh current state, resolve the conflict, and retry.",
        ),
        Some(code @ ("BZ124" | "BZ126")) => (
            code,
            400,
            failure.expect("classified").message.as_str(),
            "Correct the request fields and retry.",
        ),
        Some("BZ109") => (
            "BZ109",
            422,
            failure.expect("classified").message.as_str(),
            "Correct the requested operation using the documented runbook and retry.",
        ),
        Some("BZ107") => (
            "BZ107",
            403,
            failure.expect("classified").message.as_str(),
            "Complete the required authorization, approval, or recovery step before retrying.",
        ),
        Some("BZ001") if hint.as_ref().and_then(|v| v["type"].as_str()) == Some("over_quota") => (
            "BZ001",
            507,
            "over quota",
            "Reduce usage or raise the applicable quota before retrying.",
        ),
        Some("BZ009") => (
            "BZ009",
            507,
            "over quota",
            "Reduce usage or raise the applicable quota before retrying.",
        ),
        Some("BZ004") => (
            "BZ004",
            507,
            "sending quota exceeded",
            "Reduce usage or raise the applicable quota before retrying.",
        ),
        Some("BZ002") => (
            "BZ002",
            403,
            "access denied",
            "Complete the required authorization, approval, or recovery step before retrying.",
        ),
        Some("BZ003") => (
            "BZ003",
            403,
            "not authorized to send from this address",
            "Complete the required authorization, approval, or recovery step before retrying.",
        ),
        Some("BZ005") => (
            "BZ005",
            403,
            "message blocked by policy",
            "Complete the required authorization, approval, or recovery step before retrying.",
        ),
        Some("BZ006") => (
            "BZ006",
            404,
            "accountId does not match an existing account",
            "Refresh the target identifier and retry only if the resource still exists.",
        ),
        Some("BZ007") => (
            "BZ007",
            404,
            "recipient not found",
            "Refresh the target identifier and retry only if the resource still exists.",
        ),
        Some(code @ "BZ139") => (
            code,
            404,
            "notFound",
            "Refresh the target identifier and retry only if the resource still exists.",
        ),
        Some(code @ ("BZ140" | "BZ253" | "BZ258")) => (
            code,
            403,
            "forbidden",
            "Complete the required authorization, approval, or recovery step before retrying.",
        ),
        Some(code @ ("BZ141" | "BZ144")) => (
            code,
            422,
            "unprocessable",
            "Correct the requested operation using the documented runbook and retry.",
        ),
        Some(
            code @ ("BZ142" | "BZ143" | "BZ145" | "BZ146" | "BZ147" | "BZ149" | "BZ150" | "BZ254"
            | "BZ255" | "BZ256" | "BZ259"),
        ) => (
            code,
            409,
            "conflict",
            "Refresh current state, resolve the conflict, and retry.",
        ),
        Some("BZ148") => (
            "BZ148",
            507,
            "overQuota",
            "Reduce usage or raise the applicable quota before retrying.",
        ),
        Some(code @ ("BZ252" | "BZ257")) => (
            code,
            400,
            "invalidArguments",
            "Correct the request fields and retry.",
        ),
        Some(code @ ("BZ104" | "BZ105")) => (
            code,
            400,
            failure.expect("classified").message.as_str(),
            "Correct the request fields and retry.",
        ),
        _ => return problem(500, "database error", path, ctx, id),
    };
    let instance = path.strip_prefix("/api").unwrap_or(path);
    let title = crate::problem::title(status);
    let remediation = hint
        .as_ref()
        .and_then(|v| v["remediation"].as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(remediation);
    let body=format!("{{\"type\":\"https://setjoin.com/problems/reducer/{}\",\"title\":{},\"status\":{status},\"detail\":{},\"instance\":{},\"remediation\":{},\"code\":\"{code}\",\"retryable\":false}}\n",code.to_ascii_lowercase(),serde_json::to_string(title).expect("title"),serde_json::to_string(detail).expect("detail"),serde_json::to_string(instance).expect("path"),serde_json::to_string(remediation).expect("remediation"));
    let mut response = problem(status, detail, path, ctx, id);
    *response.body_mut() =
        http_body_util::Full::new(bytes::Bytes::from(setjoin_approvals::go_json(&body) + "\n"))
            .map_err(|never| match never {})
            .boxed();
    response
}

fn decision_target(path: &str) -> Option<&str> {
    path.strip_prefix("/api/me/approvals/")?
        .strip_suffix("/decide")
        .filter(|s| !s.is_empty() && !s.contains('/'))
}
#[derive(Default)]
struct Decision {
    decision: String,
    comment: Option<String>,
    _capabilities: Option<Vec<String>>,
    _propagation: Option<String>,
    _expires_at: Option<String>,
    _max_uses: Option<i64>,
    _expected_epoch: Option<String>,
}
impl<'de> serde::Deserialize<'de> for Decision {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = Decision;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an approval decision object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Decision, E> {
                Ok(Decision::default())
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut fields: M,
            ) -> Result<Decision, M::Error> {
                let mut result = Decision::default();
                while let Some(name) = fields.next_key::<String>()? {
                    let folded: String = name
                        .chars()
                        .map(|c| match c {
                            'ſ' => 's',
                            'K' => 'k',
                            _ => c.to_ascii_lowercase(),
                        })
                        .collect();
                    match folded.as_str() {
                        // encoding/json ignores null for non-pointer strings,
                        // including a null that follows an earlier duplicate.
                        "decision" => {
                            let value: Option<String> = fields.next_value()?;
                            if let Some(value) = value {
                                result.decision = value;
                            }
                        }
                        "comment" => result.comment = fields.next_value()?,
                        "capabilities" => result._capabilities = fields.next_value()?,
                        "propagation" => result._propagation = fields.next_value()?,
                        "expiresat" => result._expires_at = fields.next_value()?,
                        "maxuses" => result._max_uses = fields.next_value()?,
                        "expectedepoch" => result._expected_epoch = fields.next_value()?,
                        _ => return Err(serde::de::Error::custom("unknown approval field")),
                    }
                }
                Ok(result)
            }
        }
        decoder.deserialize_any(Fields)
    }
}

async fn read_body(request: &mut Request<Body>, maximum: usize) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    while let Some(frame) = request.body_mut().frame().await {
        let frame = frame.map_err(|_| ())?;
        if let Ok(data) = frame.into_data() {
            if bytes.len().saturating_add(data.len()) > maximum {
                return Err(());
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes)
}

fn query_value(uri: &hyper::Uri, name: &str) -> Option<String> {
    fn decode(value: &str) -> Option<String> {
        let input = value.as_bytes();
        let mut out = Vec::new();
        let mut index = 0;
        while index < input.len() {
            match input[index] {
                b'+' => out.push(b' '),
                b'%' => {
                    let a = (*input.get(index + 1)? as char).to_digit(16)?;
                    let b = (*input.get(index + 2)? as char).to_digit(16)?;
                    out.push((a * 16 + b) as u8);
                    index += 2;
                }
                b => out.push(b),
            }
            index += 1;
        }
        Some(String::from_utf8_lossy(&out).into_owned())
    }
    for pair in uri.query()?.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let Some(key) = decode(key) else { continue };
        let Some(value) = decode(value) else { continue };
        if key == name {
            return Some(value);
        }
    }
    None
}

#[derive(Default)]
struct CreatePolicyBody {
    consumer_type: String,
    ordered_ids: Option<Vec<i64>>,
    kind: String,
    form: Option<Box<serde_json::value::RawValue>>,
    name: String,
    enabled: bool,
    requires_approval: bool,
    conditions: Option<Box<serde_json::value::RawValue>>,
    approver_spec: Option<Box<serde_json::value::RawValue>>,
}
impl<'de> serde::Deserialize<'de> for CreatePolicyBody {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = CreatePolicyBody;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a policy object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(CreatePolicyBody::default())
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut fields: M,
            ) -> Result<Self::Value, M::Error> {
                let mut body = CreatePolicyBody::default();
                while let Some(name) = fields.next_key::<String>()? {
                    let folded: String = name
                        .chars()
                        .map(|c| match c {
                            'ſ' => 's',
                            'K' => 'k',
                            _ => c.to_ascii_lowercase(),
                        })
                        .collect();
                    match folded.as_str() {
                        "kind" => {
                            if let Some(v) = fields.next_value::<Option<String>>()? {
                                body.kind = v;
                            }
                        }
                        "form" => body.form = Some(fields.next_value()?),
                        "orderedids" => body.ordered_ids = fields.next_value()?,
                        "consumertype" => {
                            if let Some(v) = fields.next_value::<Option<String>>()? {
                                body.consumer_type = v;
                            }
                        }
                        "name" => {
                            if let Some(v) = fields.next_value::<Option<String>>()? {
                                body.name = v;
                            }
                        }
                        "enabled" => {
                            if let Some(v) = fields.next_value::<Option<bool>>()? {
                                body.enabled = v;
                            }
                        }
                        "requiresapproval" => {
                            if let Some(v) = fields.next_value::<Option<bool>>()? {
                                body.requires_approval = v;
                            }
                        }
                        "conditions" => body.conditions = Some(fields.next_value()?),
                        "approverspec" => body.approver_spec = Some(fields.next_value()?),
                        _ => {
                            let _: serde::de::IgnoredAny = fields.next_value()?;
                        }
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}
async fn read_one<T: serde::de::DeserializeOwned>(
    request: &mut Request<Body>,
    maximum: usize,
) -> Result<T, ()> {
    let mut bytes = Vec::new();
    let mut ended = false;
    loop {
        let mut decoder = serde_json::Deserializer::from_slice(&bytes);
        match T::deserialize(&mut decoder) {
            Ok(value) => return Ok(value),
            Err(error) if error.is_eof() && !ended && bytes.len() < maximum => {}
            Err(_) => return Err(()),
        }
        match request.body_mut().frame().await {
            None => ended = true,
            Some(Err(_)) => return Err(()),
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    let take = data.len().min(maximum - bytes.len());
                    bytes.extend_from_slice(&data[..take]);
                }
            }
        }
    }
}

fn policy_target(path: &str) -> Option<&str> {
    path.strip_prefix("/api/admin/approval-policies/")
        .filter(|s| !s.is_empty() && !s.contains('/') && *s != "reorder")
}
fn no_content(c: &RequestContext, id: String) -> Response<Body> {
    let mut r = crate::jmap::reply::response(String::new(), c.identity.proto, id);
    *r.status_mut() = hyper::StatusCode::NO_CONTENT;
    r.headers_mut().remove("content-type");
    r
}
fn unknown(
    operation: setjoin_contracts::ids::OperationId,
    path: &str,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let mut r = problem(503, "approval outcome unknown", path, c, id);
    r.headers_mut().insert(
        "x-operation-id",
        setjoin_pg::operation_hex(operation)
            .parse()
            .expect("operation"),
    );
    r
}
#[derive(Default)]
struct PatchPolicyBody {
    fields: std::collections::BTreeMap<String, Box<serde_json::value::RawValue>>,
}
impl<'de> serde::Deserialize<'de> for PatchPolicyBody {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = PatchPolicyBody;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("policy patch")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(PatchPolicyBody::default())
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut body = PatchPolicyBody::default();
                while let Some(key) = map.next_key::<String>()? {
                    let key = key
                        .chars()
                        .map(|c| match c {
                            'ſ' => 's',
                            'K' => 'k',
                            _ => c.to_ascii_lowercase(),
                        })
                        .collect::<String>();
                    let canonical = match key.as_str() {
                        "name" => "name",
                        "enabled" => "enabled",
                        "requiresapproval" => "requiresApproval",
                        "conditions" => "conditions",
                        "approverspec" => "approverSpec",
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                            continue;
                        }
                    };
                    let value: Box<serde_json::value::RawValue> = map.next_value()?;
                    if canonical == "name" {
                        serde_json::from_str::<Option<String>>(value.get())
                            .map_err(serde::de::Error::custom)?;
                    }
                    if matches!(canonical, "enabled" | "requiresApproval") {
                        serde_json::from_str::<Option<bool>>(value.get())
                            .map_err(serde::de::Error::custom)?;
                    }
                    body.fields.insert(canonical.into(), value);
                }
                Ok(body)
            }
        }
        d.deserialize_any(Fields)
    }
}

fn rejection_code(e: &setjoin_pg::Rejection<setjoin_pg::StatementFailure>) -> Option<&str> {
    match e {
        setjoin_pg::Rejection::Statement(e) | setjoin_pg::Rejection::Body(e) => {
            e.sqlstate.as_deref()
        }
        _ => None,
    }
}
fn conflict(detail: &str, path: &str, c: &RequestContext, id: String) -> Response<Body> {
    let mut r = problem(409, detail, path, c, id);
    let body=format!("{{\"type\":\"https://setjoin.com/errors/conflict\",\"title\":\"Conflict\",\"status\":409,\"detail\":{},\"instance\":{}}}\n",serde_json::to_string(detail).expect("detail"),serde_json::to_string(path.strip_prefix("/api").unwrap_or(path)).expect("path"));
    *r.body_mut() =
        http_body_util::Full::new(bytes::Bytes::from(setjoin_approvals::go_json(&body) + "\n"))
            .map_err(|never| match never {})
            .boxed();
    r
}

fn email_target(path: &str) -> Option<&str> {
    path.strip_prefix("/approvals/email/")
        .filter(|s| !s.is_empty() && !s.contains('/'))
}
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&#34;")
        .replace('\'', "&#39;")
}
fn html(status: u16, body: String, c: &RequestContext, id: String) -> Response<Body> {
    let mut r = crate::jmap::reply::response(body, c.identity.proto, id);
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
    r.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    r
}

fn email_error(c: &RequestContext, id: String) -> Response<Body> {
    let mut r = crate::jmap::reply::response(
        "An error occurred. Please try again.\n".into(),
        c.identity.proto,
        id,
    );
    *r.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
    r.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    r
}
