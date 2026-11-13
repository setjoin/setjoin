//! F07 offline governance; admin mounts at /api, user mounts at /offline.
use crate::mailboxes::{bare, segment, segment_path, unknown_outcome};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_devices::offline;
use setjoin_pg::{CommandOutcome, Rejection, ScopedExecutor, StatementFailure};
use std::sync::Arc;
pub struct OfflineRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
}
#[derive(Clone, Copy)]
enum Action {
    Policies,
    Policy,
    Enabled,
    Pending,
    Create,
    Update,
    Delete,
    Toggle,
    Preview,
    Size,
    Ack,
    Device(&'static str),
}
fn action(method: &Method, path: &str) -> Option<Action> {
    let read = matches!(*method, Method::GET | Method::HEAD);
    let table = [
        (read, "/api/admin/offline/policies", Action::Policies),
        (read, "/api/admin/offline/policies/{id}", Action::Policy),
        (read, "/api/admin/offline/enabled", Action::Enabled),
        (read, "/api/admin/offline/devices/pending", Action::Pending),
        (
            *method == Method::POST,
            "/api/admin/offline/policies",
            Action::Create,
        ),
        (
            *method == Method::PUT,
            "/api/admin/offline/policies/{id}",
            Action::Update,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/offline/policies/{id}",
            Action::Delete,
        ),
        (
            *method == Method::PUT,
            "/api/admin/offline/enabled",
            Action::Toggle,
        ),
        (
            *method == Method::POST,
            "/api/admin/offline/policy-preview",
            Action::Preview,
        ),
        (
            *method == Method::POST,
            "/api/admin/offline/devices/{id}/approve",
            Action::Device("approve"),
        ),
        (
            *method == Method::POST,
            "/api/admin/offline/devices/{id}/deny",
            Action::Device("deny"),
        ),
        (
            *method == Method::POST,
            "/api/admin/offline/devices/{id}/revoke",
            Action::Device("revoke"),
        ),
        (
            *method == Method::POST,
            "/api/admin/offline/devices/{id}/wipe",
            Action::Device("wipe"),
        ),
        (read, "/api/offline/size-estimate", Action::Size),
        (
            *method == Method::POST,
            "/api/offline/wipe-ack",
            Action::Ack,
        ),
    ];
    table
        .iter()
        .filter(|(ok, p, _)| *ok && crate::inventory::path_score(p, path).is_some())
        .max_by_key(|(_, p, _)| crate::inventory::path_score(p, path))
        .map(|(_, _, a)| *a)
}
async fn read_body(r: &mut Request<Body>, cap: usize) -> Option<Vec<u8>> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while let Some(f) = r.body_mut().frame().await {
        if let Ok(data) = f.ok()?.into_data() {
            if data.len() > cap.saturating_sub(bytes.len()) {
                return None;
            }
            bytes.extend_from_slice(&data);
        }
    }
    Some(bytes)
}
pub(crate) fn classified(
    e: &Rejection<StatementFailure>,
    c: &RequestContext,
    id: &str,
    path: &str,
) -> Option<Response<Body>> {
    let e = match e {
        Rejection::Statement(e) | Rejection::Body(e) => e,
        _ => return None,
    };
    let (status, detail, remediation) = match e.sqlstate.as_deref()? {
        "BZ100" => (
            409,
            e.message.as_str(),
            "Refresh current state, resolve the conflict, and retry.",
        ),
        "BZ002" => (
            403,
            "access denied",
            "Complete the required authorization, approval, or recovery step before retrying.",
        ),
        "BZ099" => {
            if e.hint
                .as_deref()
                .and_then(|h| serde_json::from_str::<serde_json::Value>(h).ok())
                .is_some_and(|v| v["type"] == "last_global")
            {
                (
                    409,
                    e.message.as_str(),
                    "Refresh current state, resolve the conflict, and retry.",
                )
            } else {
                (
                    404,
                    "policy not found",
                    "Refresh the target identifier and retry only if the resource still exists.",
                )
            }
        }
        _ => return None,
    };
    let code = e.sqlstate.as_deref()?;
    let kind = format!(
        "https://setjoin.com/problems/reducer/{}",
        code.to_ascii_lowercase()
    );
    let mut p = crate::problem::Problem::new(status, detail);
    p.kind = &kind;
    p.code = Some(code);
    p.retryable = Some(false);
    p.remediation = Some(remediation);
    p.instance = path;
    Some(crate::mailboxes::render(p, Some("en"), c, id))
}
impl<K: KeySource + 'static> Intercept for OfflineRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        action(r.method(), r.uri().path()).is_some()
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
        let (exec, worker, keys, issuer) = (
            self.exec.clone(),
            self.worker.clone(),
            self.keys.clone(),
            self.issuer.clone(),
        );
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
            if !matches!(what, Action::Size | Action::Ack) {
                let Ok(authority) = setjoin_devices::authority(&exec, actor).await else {
                    return c.upstream.forward(r, &c.identity).await;
                };
                let permission = if matches!(what, Action::Device(_)) {
                    "mam.write"
                } else if matches!(what, Action::Pending) {
                    "mam.read"
                } else {
                    "mail.offline_policy"
                };
                if !authority.allows_any(&[permission]) {
                    let _ = setjoin_devices::console_denied(
                        &exec,
                        actor,
                        &segment_path(r.uri().path()),
                        permission,
                        operation,
                    )
                    .await;
                    return bare(403, "Forbidden", &c, &id);
                }
            }
            let path = r.uri().path().to_owned();
            let head = r.method() == Method::HEAD;
            let reply = |status: u16, body: String| {
                let big = body.len() > 2048;
                let mut out =
                    crate::jmap::reply::response(body.clone(), c.identity.proto, id.clone());
                if big && head {
                    use http_body_util::BodyExt;
                    let stream = futures_util::stream::once(async move {
                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(hyper::body::Frame::data(
                            bytes::Bytes::from(body),
                        ))
                    });
                    *out.body_mut() = http_body_util::StreamBody::new(stream).boxed();
                } else if big {
                    out.headers_mut().insert(
                        "transfer-encoding",
                        hyper::header::HeaderValue::from_static("chunked"),
                    );
                }
                *out.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
                out
            };
            let result = match what {
                Action::Policies => offline::policies(&exec).await,
                Action::Enabled => offline::enabled(&exec).await,
                Action::Pending => offline::pending(&exec, actor).await,
                Action::Policy => {
                    let Ok(policy) = segment(&path, 5).parse::<i64>() else {
                        return bare(400, "invalid id", &c, &id);
                    };
                    match offline::policy(&exec, policy).await {
                        Ok(Some(body)) => Ok(body),
                        Ok(None) => return bare(404, "policy not found", &c, &id),
                        Err(e) => Err(e),
                    }
                }
                Action::Device(name) => {
                    let target = match segment(&path, 5).parse::<i64>() {
                        Ok(n) => n,
                        Err(_) => {
                            return bare(
                                400,
                                if name == "wipe" {
                                    "invalid device id"
                                } else {
                                    "invalid id"
                                },
                                &c,
                                &id,
                            )
                        }
                    };
                    match offline::command(
                        &exec,
                        actor,
                        name,
                        serde_json::json!({"id":target}),
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(_) => {
                            return if name == "wipe" {
                                reply(202,format!("{{\"device_id\":{target},\"status\":\"wipe_requested\"}}\n"))
                            } else {
                                reply(200, "{\"status\":\"ok\"}\n".into())
                            }
                        }
                        CommandOutcome::RolledBack(e) => {
                            if name == "wipe" {
                                if let Rejection::Statement(e) | Rejection::Body(e) = &e {
                                    if e.sqlstate.as_deref() == Some("BZ100") {
                                        return bare(409, &e.message, &c, &id);
                                    }
                                }
                                return bare(500, "wipe failed", &c, &id);
                            }
                            return classified(&e, &c, &id, &segment_path(&path))
                                .unwrap_or_else(|| bare(500, "device action failed", &c, &id));
                        }
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::Size => offline::size(&worker, actor).await,
                Action::Ack => {
                    let Some(bytes) = read_body(&mut r, usize::MAX).await else {
                        return bare(400, "device_id required", &c, &id);
                    };
                    let payload = match offline::ack_input(&bytes) {
                        Ok(v) => v,
                        Err(_) => return bare(400, "device_id required", &c, &id),
                    };
                    match offline::command(&exec, actor, "ack", payload, operation).await {
                        CommandOutcome::Committed(_) => {
                            return reply(200, "{\"status\":\"ok\"}\n".into())
                        }
                        CommandOutcome::RolledBack(e) => {
                            if let Rejection::Statement(e) | Rejection::Body(e) = &e {
                                if e.sqlstate.as_deref() == Some("BZ101") {
                                    return reply(200, "{\"status\":\"ok\"}\n".into());
                                }
                            }
                            return bare(500, "ack failed", &c, &id);
                        }
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::Preview => {
                    let Some(bytes) = read_body(&mut r, 16 << 10).await else {
                        return bare(400, "invalid JSON", &c, &id);
                    };
                    let (target, device) = match offline::preview_input(&bytes) {
                        Ok(v) => v,
                        Err(e) => {
                            return bare(
                                400,
                                if e == "request must contain one JSON object" {
                                    &e
                                } else if e.starts_with("invalid target")
                                    || e.starts_with("invalid device")
                                {
                                    &e
                                } else {
                                    "invalid JSON"
                                },
                                &c,
                                &id,
                            )
                        }
                    };
                    match offline::preview(&exec, actor, target, device).await {
                        Ok(body) => Ok(body),
                        Err(e) => {
                            return classified(
                                &Rejection::Statement(e),
                                &c,
                                &id,
                                &segment_path(&path),
                            )
                            .unwrap_or_else(|| bare(500, "preview failed", &c, &id))
                        }
                    }
                }
                Action::Toggle => {
                    let Some(bytes) = read_body(&mut r, usize::MAX).await else {
                        return bare(400, "invalid JSON", &c, &id);
                    };
                    let payload = match offline::toggle_input(&bytes) {
                        Ok(v) => v,
                        Err(_) => return bare(400, "invalid JSON", &c, &id),
                    };
                    let value = payload["enabled"].as_bool().unwrap_or(false);
                    match offline::command(&exec, actor, "toggle", payload, operation).await {
                        CommandOutcome::Committed(_) => {
                            return reply(200, format!("{{\"enabled\":{value}}}\n"))
                        }
                        CommandOutcome::RolledBack(_) => {
                            return bare(500, "toggle failed", &c, &id)
                        }
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::Create | Action::Update | Action::Delete => {
                    let target = if matches!(what, Action::Create) {
                        None
                    } else {
                        match segment(&path, 5).parse::<i64>() {
                            Ok(n) => Some(n),
                            Err(_) => return bare(400, "invalid id", &c, &id),
                        }
                    };
                    let mut payload = if matches!(what, Action::Delete) {
                        serde_json::json!({})
                    } else {
                        let Some(bytes) = read_body(&mut r, 16 << 10).await else {
                            return bare(400, "invalid JSON", &c, &id);
                        };
                        match offline::policy_input(&bytes) {
                            Ok(v) => v,
                            Err(_) => return bare(400, "invalid JSON", &c, &id),
                        }
                    };
                    payload["id"] = serde_json::json!(target);
                    let name = match what {
                        Action::Create => "create",
                        Action::Update => "update",
                        _ => "delete",
                    };
                    match offline::command(&exec, actor, name, payload, operation).await {
                        CommandOutcome::Committed(value) => {
                            return if matches!(what, Action::Delete) {
                                reply(200, "{\"status\":\"deleted\"}\n".into())
                            } else {
                                reply(
                                    if matches!(what, Action::Create) {
                                        201
                                    } else {
                                        200
                                    },
                                    format!("{{\"id\":{value}}}\n"),
                                )
                            }
                        }
                        CommandOutcome::RolledBack(e) => {
                            return classified(&e, &c, &id, &segment_path(&path)).unwrap_or_else(
                                || {
                                    bare(
                                        if matches!(what, Action::Delete) {
                                            500
                                        } else {
                                            400
                                        },
                                        if matches!(what, Action::Delete) {
                                            "delete failed"
                                        } else {
                                            "failed to save policy"
                                        },
                                        &c,
                                        &id,
                                    )
                                },
                            )
                        }
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    }
                }
            };
            match result {
                Ok(body) => reply(200, body),
                Err(_) => bare(
                    500,
                    if matches!(what, Action::Enabled) {
                        "toggle read failed"
                    } else {
                        "database error"
                    },
                    &c,
                    &id,
                ),
            }
        })
    }
}
