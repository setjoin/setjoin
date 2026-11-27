//! F14 registration, shared by the executable and recorded HTTP replay.
mod acl;
mod b;
mod content;
use crate::{Body, BoxFuture, Intercept, RequestContext};
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;
pub struct DriveRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker: ScopedExecutor,
    pub store: Option<Arc<crate::recovery_worker::S3Store>>,
    pub keys: Arc<K>,
    pub issuer: String,
}
impl<K: KeySource + 'static> Intercept for DriveRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool {
        true
    }
    fn matches(&self, r: &Request<Body>) -> bool {
        b::matches(r)
            || acl::matches(r)
            || (matches!(r.method().as_str(), "GET" | "HEAD")
                && crate::inventory::path_score("/api/me/sharing", r.uri().path()).is_some())
            || (r.method() == hyper::Method::POST
                && crate::inventory::path_score("/api/me/sharing/delegates", r.uri().path())
                    .is_some())
            || (r.method() == hyper::Method::DELETE
                && crate::inventory::path_score(
                    "/api/me/sharing/delegates/{userId}",
                    r.uri().path(),
                )
                .is_some())
            || (r.method() == hyper::Method::PUT
                && crate::inventory::path_score("/api/me/sharing/default", r.uri().path())
                    .is_some())
            || (r.method() == hyper::Method::DELETE
                && crate::inventory::path_score("/api/me/sharing/default/{id}", r.uri().path())
                    .is_some())
            || (matches!(r.method().as_str(), "GET" | "HEAD" | "POST")
                && crate::inventory::path_score("/api/admin/sharing/defaults", r.uri().path())
                    .is_some())
            || (r.method() == hyper::Method::DELETE
                && crate::inventory::path_score("/api/admin/sharing/defaults/{id}", r.uri().path())
                    .is_some())
            || (matches!(r.method().as_str(), "GET" | "HEAD")
                && crate::inventory::path_score("/api/admin/sharing/users/{id}", r.uri().path())
                    .is_some())
            || (matches!(r.method().as_str(), "GET" | "HEAD")
                && crate::inventory::path_score("/api/admin/sharing/audit", r.uri().path())
                    .is_some())
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_drive_user_request(&exec, &keys, &issuer, &h, s, "/api/drive/")
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
        let language = locale(r.headers());
        let store = self.store.clone();
        Box::pin(async move {
            if b::matches(&r) {
                let mut response = b::handle(r, c, exec, worker, keys, issuer, store).await;
                if response.headers().contains_key("content-language") {
                    response.headers_mut().insert(
                        "content-language",
                        language.parse().expect("validated locale"),
                    );
                }
                return response;
            }
            if acl::matches(&r) {
                let mut response = acl::handle(r, c, exec, keys, issuer).await;
                if response.headers().contains_key("content-language") {
                    response.headers_mut().insert(
                        "content-language",
                        language.parse().expect("validated locale"),
                    );
                }
                return response;
            }
            let mut response = async move {
                let verdict =
                    crate::deny::admit(&exec, &keys, &issuer, &r, crate::deny::Scope::DriveUser)
                        .await;
                let auth = match verdict {
                    Ok(auth) => auth,
                    Err(refusal) => return crate::deny::answer(refusal, r, &c).await,
                };
                let mut random = [0; 16];
                if getrandom::getrandom(&mut random).is_err() {
                    let id =
                        crate::jmap::reply::request_id(r.headers().get("x-request-id"), [0; 16]);
                    return problem(503, "service unavailable", None, &c, id);
                }
                let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), random);
                let Some(factory) =
                    crate::policy_composition::tx_factory_from_executors(&exec, Some(&worker))
                else {
                    return problem(503, "service unavailable", None, &c, id);
                };
                let client_ip = c.identity.client_ip.to_string();
                let Ok(user_principal) = factory.mint_user_from_authorized(&auth, &client_ip).await
                else {
                    return problem(500, "database error", None, &c, id);
                };
                if crate::inventory::path_score("/api/admin/sharing/audit", r.uri().path())
                    .is_some()
                {
                    let path = "/admin/sharing/audit";
                    let Some(proof) = sharing_admin_proof(&factory, &auth, &client_ip, false).await
                    else {
                        setjoin_drive::denied(&factory, &user_principal, path, false, random).await;
                        return problem(403, "Forbidden", None, &c, id);
                    };
                    let value = |key: &str| query(&r, key);
                    let user = value("user_id").and_then(|s| s.parse::<i64>().ok());
                    let limit = value("limit")
                        .and_then(|s| s.parse::<i64>().ok())
                        .filter(|v| *v > 0 && *v <= 500)
                        .unwrap_or(50);
                    let offset = value("offset")
                        .map(|s| go_atoi(&s))
                        .unwrap_or(0)
                        .clamp(0, 1_000_000);
                    return match setjoin_drive::audit(&factory, &proof, user, limit, offset).await {
                        Ok(v) => {
                            crate::jmap::reply::response(v.to_string() + "\n", c.identity.proto, id)
                        }
                        Err(_) => problem(500, "database error", Some(path), &c, id),
                    };
                }
                if crate::inventory::path_score("/api/admin/sharing/users/{id}", r.uri().path())
                    .is_some()
                {
                    let path = String::from_utf8_lossy(&crate::inventory::unescape(r.uri().path()))
                        .strip_prefix("/api")
                        .unwrap()
                        .to_owned();
                    let Some(proof) = sharing_admin_proof(&factory, &auth, &client_ip, false).await
                    else {
                        setjoin_drive::denied(&factory, &user_principal, &path, false, random)
                            .await;
                        return problem(403, "Forbidden", None, &c, id);
                    };
                    let value = String::from_utf8_lossy(&crate::inventory::unescape(
                        r.uri().path().rsplit('/').next().unwrap_or(""),
                    ))
                    .into_owned();
                    let Ok(target) = value.parse::<i64>() else {
                        return problem(400, "invalid user id", Some(&path), &c, id);
                    };
                    return match setjoin_drive::oversight(&factory, &proof, target).await {
                        Ok(Some(v)) => {
                            crate::jmap::reply::response(v.to_string() + "\n", c.identity.proto, id)
                        }
                        Ok(None) => problem(404, "user not found", Some(&path), &c, id),
                        Err(_) => problem(500, "database error", Some(&path), &c, id),
                    };
                }
                if r.method() == hyper::Method::DELETE
                    && crate::inventory::path_score(
                        "/api/admin/sharing/defaults/{id}",
                        r.uri().path(),
                    )
                    .is_some()
                {
                    let path = String::from_utf8_lossy(&crate::inventory::unescape(r.uri().path()))
                        .strip_prefix("/api")
                        .unwrap()
                        .to_owned();
                    let Some(proof) = sharing_admin_proof(&factory, &auth, &client_ip, true).await
                    else {
                        setjoin_drive::denied(&factory, &user_principal, &path, true, random).await;
                        return problem(403, "Forbidden", None, &c, id);
                    };
                    if setjoin_drive::reason_required(&factory, &proof).await
                        && r.headers()
                            .get("x-audit-reason")
                            .is_none_or(|v| v.as_bytes().is_empty())
                    {
                        setjoin_drive::missing_reason(
                            &factory,
                            &user_principal,
                            &client_ip,
                            random,
                        )
                        .await;
                        return problem(400, "reason_required", None, &c, id);
                    }
                    let value = String::from_utf8_lossy(&crate::inventory::unescape(
                        r.uri().path().rsplit('/').next().unwrap_or(""),
                    ))
                    .into_owned();
                    let Ok(target) = value.parse::<i64>() else {
                        return problem(400, "invalid id", Some(&path), &c, id);
                    };
                    return match setjoin_drive::delete_default(&factory, &proof, target, random)
                        .await
                    {
                        setjoin_pg::CommandOutcome::Committed(_) => empty(204, &c, id),
                        setjoin_pg::CommandOutcome::RolledBack(ref e) => {
                            rejected(e, Some(&path), &c, id)
                        }
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, &c, id)
                        }
                    };
                }
                if crate::inventory::path_score("/api/admin/sharing/defaults", r.uri().path())
                    .is_some()
                {
                    let path = "/admin/sharing/defaults";
                    let manage = r.method() == hyper::Method::POST;
                    let Some(proof) =
                        sharing_admin_proof(&factory, &auth, &client_ip, manage).await
                    else {
                        setjoin_drive::denied(&factory, &user_principal, path, manage, random)
                            .await;
                        return problem(403, "Forbidden", None, &c, id);
                    };
                    if manage {
                        if setjoin_drive::reason_required(&factory, &proof).await
                            && r.headers()
                                .get("x-audit-reason")
                                .is_none_or(|v| v.as_bytes().is_empty())
                        {
                            setjoin_drive::missing_reason(
                                &factory,
                                &user_principal,
                                &client_ip,
                                random,
                            )
                            .await;
                            return problem(400, "reason_required", None, &c, id);
                        }
                        let bytes = match r.body_mut().collect().await {
                            Ok(b) => b.to_bytes(),
                            Err(_) => return problem(400, "invalid JSON", Some(path), &c, id),
                        };
                        // Go's MaxBytesReader bounds the decoder's reads, not
                        // the full request: a complete first value can precede
                        // an arbitrarily large ignored trailer.
                        let body: Value = match decode_body(
                            &bytes[..bytes.len().min(1 << 20)],
                            &[
                                ("ownerScope", false),
                                ("ownerRef", true),
                                ("audience", false),
                                ("audienceRef", true),
                                ("level", false),
                            ],
                        ) {
                            Ok(v) => v,
                            Err(_) => return problem(400, "invalid JSON", Some(path), &c, id),
                        };
                        let result = setjoin_drive::create_default(
                            &factory,
                            &proof,
                            body["ownerScope"].as_str().unwrap_or(""),
                            body["ownerRef"].as_i64().unwrap_or(0),
                            body["audience"].as_str().unwrap_or(""),
                            body["audienceRef"].as_i64().unwrap_or(0),
                            body["level"].as_str().unwrap_or(""),
                            random,
                        )
                        .await;
                        return match result {
                            setjoin_pg::CommandOutcome::Committed(v) => {
                                crate::jmap::reply::response(
                                    v.to_string() + "\n",
                                    c.identity.proto,
                                    id,
                                )
                            }
                            setjoin_pg::CommandOutcome::RolledBack(ref e) => {
                                rejected(e, Some(path), &c, id)
                            }
                            setjoin_pg::CommandOutcome::Unknown { operation } => {
                                unknown(operation, &c, id)
                            }
                        };
                    }
                    return match setjoin_drive::list_defaults(&factory, &proof).await {
                        Ok(v) => {
                            crate::jmap::reply::response(v.to_string() + "\n", c.identity.proto, id)
                        }
                        Err(_) => problem(500, "database error", Some(path), &c, id),
                    };
                }
                let Some(worker_pool) = worker.try_worker_pool() else {
                    return problem(503, "service unavailable", None, &c, id);
                };
                if r.method() == hyper::Method::PUT {
                    let bytes = match r.body_mut().collect().await {
                        Ok(b) => b.to_bytes(),
                        Err(_) => return problem(400, "invalid JSON", None, &c, id),
                    };
                    let body: Value = match decode_body(
                        &bytes,
                        &[("audience", false), ("audienceRef", true), ("level", false)],
                    ) {
                        Ok(v) => v,
                        Err(_) => return problem(400, "invalid JSON", None, &c, id),
                    };
                    let audience = body["audience"].as_str().unwrap_or("");
                    let mut audience_ref = body["audienceRef"].as_i64().unwrap_or(0);
                    let level = body["level"].as_str().unwrap_or("");
                    if audience == "everyone" && audience_ref == 0 {
                        audience_ref =
                            match sharing_actor_domain(&worker_pool, &user_principal).await {
                                Ok(Some(domain)) => domain,
                                _ => return problem(500, "database error", None, &c, id),
                            };
                    }
                    return match sharing_set_default(
                        &worker_pool,
                        &user_principal,
                        audience,
                        audience_ref,
                        level,
                        random,
                    )
                    .await
                    {
                        setjoin_pg::CommandOutcome::Committed(v) => {
                            crate::jmap::reply::response(v.to_string() + "\n", c.identity.proto, id)
                        }
                        setjoin_pg::CommandOutcome::RolledBack(ref e) => rejected(e, None, &c, id),
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, &c, id)
                        }
                    };
                }
                if r.method() == hyper::Method::DELETE {
                    let value = String::from_utf8_lossy(&crate::inventory::unescape(
                        r.uri().path().rsplit('/').next().unwrap_or(""),
                    ))
                    .into_owned();
                    let is_default = crate::inventory::path_score(
                        "/api/me/sharing/default/{id}",
                        r.uri().path(),
                    )
                    .is_some();
                    let Ok(grantee) = value.parse::<i64>() else {
                        return problem(
                            400,
                            if is_default {
                                "invalid id"
                            } else {
                                "invalid user id"
                            },
                            None,
                            &c,
                            id,
                        );
                    };
                    let outcome = if is_default {
                        sharing_clear_default(&worker_pool, &user_principal, grantee, random).await
                    } else {
                        let mailbox =
                            match sharing_primary_mailbox(&worker_pool, &user_principal).await {
                                Ok(Some(mailbox)) => mailbox,
                                _ => return problem(500, "mailbox not found", None, &c, id),
                            };
                        sharing_revoke(&worker_pool, &user_principal, mailbox, grantee, random)
                            .await
                    };
                    return match outcome {
                        setjoin_pg::CommandOutcome::Committed(_) => empty(204, &c, id),
                        setjoin_pg::CommandOutcome::RolledBack(ref e) => rejected(e, None, &c, id),
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, &c, id)
                        }
                    };
                }
                if r.method() == hyper::Method::POST {
                    let bytes = match r.body_mut().collect().await {
                        Ok(b) => b.to_bytes(),
                        Err(_) => {
                            return problem(
                                400,
                                "granteeEmail and permission are required",
                                None,
                                &c,
                                id,
                            )
                        }
                    };
                    let body: Value = match decode_body(
                        &bytes,
                        &[("granteeEmail", false), ("permission", false)],
                    ) {
                        Ok(v) => v,
                        Err(_) => {
                            return problem(
                                400,
                                "granteeEmail and permission are required",
                                None,
                                &c,
                                id,
                            )
                        }
                    };
                    let email = body["granteeEmail"].as_str().unwrap_or("");
                    let permission = body["permission"].as_str().unwrap_or("");
                    if email.is_empty() {
                        return problem(
                            400,
                            "granteeEmail and permission are required",
                            None,
                            &c,
                            id,
                        );
                    }
                    let mailbox = match sharing_primary_mailbox(&worker_pool, &user_principal).await
                    {
                        Ok(Some(mailbox)) => mailbox,
                        _ => return problem(500, "mailbox not found", None, &c, id),
                    };
                    return match sharing_grant(
                        &worker_pool,
                        &user_principal,
                        mailbox,
                        email,
                        permission,
                        random,
                    )
                    .await
                    {
                        setjoin_pg::CommandOutcome::Committed(_) => empty(201, &c, id),
                        setjoin_pg::CommandOutcome::RolledBack(ref e) => rejected(e, None, &c, id),
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, &c, id)
                        }
                    };
                }
                match sharing_overview(&factory, &worker_pool, &user_principal).await {
                    Ok(v) => {
                        crate::jmap::reply::response(v.to_string() + "\n", c.identity.proto, id)
                    }
                    Err(_) => problem(500, "database error", None, &c, id),
                }
            }
            .await;
            if response.headers().contains_key("content-language") {
                response.headers_mut().insert(
                    "content-language",
                    language.parse().expect("validated locale"),
                );
            }
            response
        })
    }
}
async fn sharing_worker_read_json(
    worker: &setjoin_pg::WorkerPool,
    contract: &'static setjoin_pg::SqlContract,
    values: &[&(dyn setjoin_pg::ToSql + Sync)],
) -> Result<Value, setjoin_pg::StatementFailure> {
    let mut tx = worker.begin_repeatable_read_only().await?;
    let rows = tx.query_iterated_contract(contract, values).await?;
    let _ = tx.commit().await;
    setjoin_drive::decode_json_rows(&rows)
}

async fn sharing_worker_write<T, P>(
    worker: &setjoin_pg::WorkerPool,
    command_name: &'static str,
    contract: &'static setjoin_pg::SqlContract,
    values: &[&(dyn setjoin_pg::ToSql + Sync)],
    operation: [u8; 16],
    project: P,
) -> setjoin_pg::CommandOutcome<T, setjoin_pg::StatementFailure>
where
    P: FnOnce(&[setjoin_pg::Row]) -> Result<T, setjoin_pg::StatementFailure>,
{
    let op = setjoin_contracts::ids::OperationId(operation);
    let mut tx = match worker.begin_read_write().await {
        Ok(tx) => tx,
        Err(e) => {
            return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e))
        }
    };
    let body: Result<T, setjoin_pg::StatementFailure> = async {
        let rows = tx.query_contract(contract, values).await?;
        let value = project(&rows)?;
        tx.record_receipt(
            op,
            setjoin_pg::ReceiptCommand {
                family: "F14",
                command: command_name,
            },
        )
        .await?;
        Ok(value)
    }
    .await;
    match body {
        Ok(value) => match tx.commit().await {
            Ok(()) => setjoin_pg::CommandOutcome::Committed(value),
            Err(e) => {
                if let Some(code) = e.sqlstate.as_deref() {
                    if setjoin_pg::commit_failure_observation(Some(code))
                        == setjoin_contracts::command::CommitObservation::RolledBack
                    {
                        return setjoin_pg::CommandOutcome::RolledBack(
                            setjoin_pg::Rejection::CommitRefused(code.to_owned()),
                        );
                    }
                }
                setjoin_pg::CommandOutcome::Unknown { operation: op }
            }
        },
        Err(f) => {
            let _ = tx.rollback().await;
            setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(f))
        }
    }
}

async fn sharing_primary_mailbox(
    worker: &setjoin_pg::WorkerPool,
    user: &setjoin_authz::principals::UserPrincipal,
) -> Result<Option<i64>, setjoin_pg::StatementFailure> {
    let actor = user.user().get();
    let mut tx = worker.begin_repeatable_read_only().await?;
    let rows = tx
        .query_contract(&setjoin_drive::sql::PRIMARY_MAILBOX, &[&actor])
        .await?;
    let _ = tx.commit().await;
    Ok(rows.first().and_then(|r| r.try_get(0).ok()))
}

async fn sharing_actor_domain(
    worker: &setjoin_pg::WorkerPool,
    user: &setjoin_authz::principals::UserPrincipal,
) -> Result<Option<i64>, setjoin_pg::StatementFailure> {
    let actor = user.user().get();
    let mut tx = worker.begin_repeatable_read_only().await?;
    let rows = tx
        .query_contract(&setjoin_drive::sql::ACTOR_DOMAIN, &[&actor])
        .await?;
    let _ = tx.commit().await;
    Ok(rows.first().and_then(|r| r.try_get(0).ok()))
}

async fn sharing_grant(
    worker: &setjoin_pg::WorkerPool,
    user: &setjoin_authz::principals::UserPrincipal,
    mailbox: i64,
    email: &str,
    permission: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<Value, setjoin_pg::StatementFailure> {
    if mailbox <= 0 {
        return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(
            setjoin_pg::StatementFailure {
                sqlstate: Some("BZ114".into()),
                message: "mailbox not found".into(),
                hint: None,
            },
        ));
    }
    let actor = user.user().get();
    sharing_worker_write(
        worker,
        "mailbox_delegate_grant",
        &setjoin_drive::sql::DELEGATE_GRANT,
        &[&actor, &mailbox, &email, &permission],
        operation,
        |rows| {
            if rows.is_empty() {
                return Err(setjoin_pg::StatementFailure {
                    sqlstate: Some("42501".into()),
                    message: "authority changed".into(),
                    hint: None,
                });
            }
            Ok(Value::Null)
        },
    )
    .await
}

async fn sharing_revoke(
    worker: &setjoin_pg::WorkerPool,
    user: &setjoin_authz::principals::UserPrincipal,
    mailbox: i64,
    grantee: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<Value, setjoin_pg::StatementFailure> {
    if mailbox <= 0 {
        return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(
            setjoin_pg::StatementFailure {
                sqlstate: Some("BZ114".into()),
                message: "mailbox not found".into(),
                hint: None,
            },
        ));
    }
    let actor = user.user().get();
    sharing_worker_write(
        worker,
        "mailbox_delegate_revoke",
        &setjoin_drive::sql::DELEGATE_REVOKE,
        &[&actor, &mailbox, &grantee],
        operation,
        |rows| {
            if rows.is_empty() {
                return Err(setjoin_pg::StatementFailure {
                    sqlstate: Some("42501".into()),
                    message: "authority changed".into(),
                    hint: None,
                });
            }
            Ok(Value::Null)
        },
    )
    .await
}

async fn sharing_set_default(
    worker: &setjoin_pg::WorkerPool,
    user: &setjoin_authz::principals::UserPrincipal,
    audience: &str,
    audience_ref: i64,
    level: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<Value, setjoin_pg::StatementFailure> {
    let actor = user.user().get();
    sharing_worker_write(
        worker,
        "sharing_default_set",
        &setjoin_drive::sql::USER_SET_DEFAULT,
        &[&actor, &audience, &audience_ref, &level],
        operation,
        |rows| {
            let id = rows
                .first()
                .and_then(|row| row.try_get::<_, i64>(0).ok())
                .ok_or_else(|| setjoin_pg::StatementFailure {
                    sqlstate: Some("42501".into()),
                    message: "authority changed".into(),
                    hint: None,
                })?;
            Ok(json!({ "id": id }))
        },
    )
    .await
}

async fn sharing_clear_default(
    worker: &setjoin_pg::WorkerPool,
    user: &setjoin_authz::principals::UserPrincipal,
    id: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<Value, setjoin_pg::StatementFailure> {
    let actor = user.user().get();
    sharing_worker_write(
        worker,
        "sharing_default_clear",
        &setjoin_drive::sql::USER_CLEAR_DEFAULT,
        &[&actor, &id],
        operation,
        |rows| {
            if rows.is_empty() {
                return Err(setjoin_pg::StatementFailure {
                    sqlstate: Some("42501".into()),
                    message: "authority changed".into(),
                    hint: None,
                });
            }
            Ok(Value::Null)
        },
    )
    .await
}

async fn sharing_overview(
    factory: &setjoin_authz::principals::TxFactory,
    worker: &setjoin_pg::WorkerPool,
    user: &setjoin_authz::principals::UserPrincipal,
) -> Result<Value, setjoin_pg::StatementFailure> {
    let uid = user.user().get();
    let delegates =
        sharing_worker_read_json(worker, &setjoin_drive::sql::OVERVIEW_DELEGATES, &[&uid]).await?;
    let grants = sharing_worker_read_json(
        worker,
        &setjoin_drive::sql::OVERVIEW_CALENDAR_GRANTS,
        &[&uid],
    )
    .await?;
    let defaults =
        sharing_worker_read_json(worker, &setjoin_drive::sql::OVERVIEW_DEFAULTS, &[&uid]).await?;
    let enabled = factory
        .run_public_read_contract(&setjoin_drive::sql::SHARING_DEFAULTS_ENABLED, &[])
        .await?
        .first()
        .is_some_and(|r| r.try_get::<_, bool>(0).unwrap_or(false));
    let rows = defaults
        .as_array()
        .ok_or_else(|| setjoin_pg::StatementFailure {
            sqlstate: None,
            hint: None,
            message: "invalid sharing defaults JSON".into(),
        })?;
    let (own, inherited): (Vec<_>, Vec<_>) = rows
        .iter()
        .cloned()
        .partition(|r| r["ownerScope"] == "user");
    Ok(json!({
        "delegates": delegates,
        "calendarGrants": grants,
        "myDefaults": own,
        "inheritedDefaults": inherited,
        "defaultsEnabled": enabled
    }))
}

async fn sharing_admin_proof(
    factory: &setjoin_authz::principals::TxFactory,
    auth: &setjoin_authz::Authorized,
    client_ip: &str,
    manage: bool,
) -> Option<setjoin_authz::principals::AdminPermissionProof> {
    if !auth.context().signed_admin() {
        return None;
    }
    let required: &[&str] = if manage {
        &["sharing.manage"]
    } else {
        &["sharing.manage", "sharing.read"]
    };
    factory
        .mint_admin_from_authorized(auth, client_ip)
        .await
        .ok()
        .and_then(|admin| admin.require_any_permission(required).ok())
}

fn empty(status: u16, c: &RequestContext, id: String) -> Response<Body> {
    let mut r = crate::jmap::reply::response(String::new(), c.identity.proto, id);
    *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
    r.headers_mut().remove("content-type");
    r
}
fn problem(
    status: u16,
    detail: &str,
    path: Option<&str>,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let status = hyper::StatusCode::from_u16(status).unwrap();
    let text = crate::problem::Problem::new(status.as_u16(), detail)
        .instance(path.unwrap_or(""))
        .body();
    let mut r = crate::jmap::reply::response(text, c.identity.proto, id);
    *r.status_mut() = status;
    r.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/problem+json"),
    );
    if path.is_some() {
        r.headers_mut().insert(
            "content-language",
            hyper::header::HeaderValue::from_static("en"),
        );
    }
    r
}
fn rejected(
    e: &setjoin_pg::Rejection<setjoin_pg::StatementFailure>,
    path: Option<&str>,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let f = match e {
        setjoin_pg::Rejection::Statement(f) | setjoin_pg::Rejection::Body(f) => Some(f),
        _ => None,
    };
    let (status, detail) = match f.and_then(|f| f.sqlstate.as_deref()) {
        Some("BZ114") => (404, "notFound"),
        Some("BZ115" | "BZ117") => (400, f.unwrap().message.as_str()),
        Some("BZ116") => (403, f.unwrap().message.as_str()),
        _ => (500, "request failed"),
    };
    let mut r = problem(status, detail, path, c, id);
    if let (Some(path), Some(f)) = (path, f) {
        if let Some(code) = f
            .sqlstate
            .as_deref()
            .filter(|v| matches!(*v, "BZ114" | "BZ115" | "BZ116" | "BZ117"))
        {
            let remediation=match code{"BZ114"=>"Refresh the target identifier and retry only if the resource still exists.","BZ116"=>"Complete the required authorization, approval, or recovery step before retrying.",_=>"Correct the request fields and retry."};
            let kind = format!(
                "https://setjoin.com/problems/reducer/{}",
                code.to_lowercase()
            );
            let raw = crate::problem::Problem::new(status, detail)
                .kind(&kind)
                .instance(path)
                .remediation(remediation)
                .code(code)
                .retryable(false)
                .body();
            crate::problem::set_body(&mut r, raw);
        }
    }
    r
}
fn unknown(
    operation: setjoin_contracts::ids::OperationId,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let hex = setjoin_pg::command::operation_hex(operation);
    let mut r = problem(503, "commit outcome unknown", None, c, id);
    r.headers_mut()
        .insert("x-operation-id", hex.parse().expect("operation hex"));
    r
}

struct Fields(Vec<(String, Box<serde_json::value::RawValue>)>);
impl<'de> serde::Deserialize<'de> for Fields {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Object;
        impl<'de> serde::de::Visitor<'de> for Object {
            type Value = Fields;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object or null")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Fields, E> {
                Ok(Fields(Vec::new()))
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Fields, M::Error> {
                let mut fields = Vec::new();
                while let Some(k) = map.next_key::<String>()? {
                    fields.push((k, map.next_value()?));
                }
                Ok(Fields(fields))
            }
        }
        d.deserialize_any(Object)
    }
}
fn decode_body(bytes: &[u8], known: &[(&str, bool)]) -> Result<Value, ()> {
    use serde::Deserialize;
    let text = go_json_text(bytes);
    let mut decoder = serde_json::Deserializer::from_str(&text);
    let fields = Fields::deserialize(&mut decoder).map_err(|_| ())?;
    let fold = |s: &str| {
        s.chars()
            .map(|c| match c {
                'ſ' => 'S',
                'K' => 'K',
                c => c.to_ascii_uppercase(),
            })
            .collect::<String>()
    };
    let mut out = serde_json::Map::new();
    for (key, raw) in fields.0 {
        if let Some((name, integer)) = known.iter().find(|(name, _)| fold(name) == fold(&key)) {
            if raw.get() == "null" {
                continue;
            }
            let value = if *integer {
                json!(serde_json::from_str::<i64>(raw.get()).map_err(|_| ())?)
            } else {
                json!(serde_json::from_str::<String>(raw.get()).map_err(|_| ())?)
            };
            out.insert((*name).into(), value);
        }
    }
    Ok(Value::Object(out))
}

fn go_json_text(input: &[u8]) -> String {
    let text = go_utf8(input);
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let (mut i, mut quoted) = (0, false);
    let unit = |at: usize| -> Option<u16> {
        if bytes.get(at..at + 2)? != b"\\u" {
            return None;
        }
        let hex = bytes.get(at + 2..at + 6)?;
        let mut n = 0u16;
        for b in hex {
            n = (n << 4) | (*b as char).to_digit(16)? as u16;
        }
        Some(n)
    };
    while i < bytes.len() {
        if quoted && bytes[i] == b'\\' {
            if let Some(n) = unit(i) {
                if (0xd800..=0xdbff).contains(&n)
                    && unit(i + 6).is_some_and(|m| (0xdc00..=0xdfff).contains(&m))
                {
                    out.extend_from_slice(&bytes[i..i + 12]);
                    i += 12;
                    continue;
                }
                if (0xd800..=0xdfff).contains(&n) {
                    out.extend_from_slice(b"\\ufffd");
                    i += 6;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
            if i < bytes.len() {
                out.push(bytes[i]);
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'"' {
            quoted = !quoted;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).expect("UTF-8 preserving JSON escape replacement")
}

fn go_utf8(mut input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());
    loop {
        match std::str::from_utf8(input) {
            Ok(valid) => {
                out.push_str(valid);
                return out;
            }
            Err(error) => {
                let prefix = error.valid_up_to();
                out.push_str(
                    std::str::from_utf8(&input[..prefix]).expect("validated UTF-8 prefix"),
                );
                out.push('\u{fffd}');
                input = &input[prefix + 1..];
            }
        }
    }
}

fn locale(headers: &hyper::HeaderMap) -> String {
    let raw = headers
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split([',', ';'])
        .next()
        .unwrap_or("")
        .trim();
    let mut parts = raw.split('-');
    let first = parts.next().unwrap_or("");
    if first.is_empty()
        || first.len() > 8
        || !first.bytes().all(|b| b.is_ascii_alphabetic())
        || !parts
            .all(|p| !p.is_empty() && p.len() <= 8 && p.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        "en".into()
    } else {
        raw.into()
    }
}

fn go_atoi(value: &str) -> i64 {
    if let Ok(n) = value.parse() {
        return n;
    }
    let (negative, digits) = if let Some(s) = value.strip_prefix('-') {
        (true, s)
    } else {
        (false, value.strip_prefix('+').unwrap_or(value))
    };
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        if negative {
            i64::MIN
        } else {
            i64::MAX
        }
    } else {
        0
    }
}

fn query(r: &Request<Body>, key: &str) -> Option<String> {
    for pair in r.uri().query().unwrap_or("").split('&') {
        if pair.contains(';') {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(k), Some(v)) = (decode_query(k), decode_query(v)) else {
            continue;
        };
        if k == key {
            return Some(v);
        }
    }
    None
}
fn decode_query(value: &str) -> Option<String> {
    let mut out = Vec::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hi = (*bytes.get(i + 1)? as char).to_digit(16)?;
                let lo = (*bytes.get(i + 2)? as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                i += 2
            }
            b => out.push(b),
        }
        i += 1;
    }
    Some(go_utf8(&out))
}

#[path = "drive_core.rs"]
pub mod core;
