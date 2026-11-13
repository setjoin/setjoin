//! F07 MDM/MAM HTTP adapter (#310–#311): the MDM device and policy console
//! (`/admin/mdm/*`) and the CA-2 device lockdown console (`/admin/devices*`).
//! Gates mirror Go's chain: `requireMamRead`/`requireMamWrite` from the live
//! governed grants, then (MDM policy writes only) `requireOrgWideSurface`.
//! Offline governance and user routes live in the sibling `offline` adapter (#312).
use crate::admin_identity_input::query;
use crate::mailboxes::{bare, parse_uuid, segment, segment_path, unknown_outcome};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_devices::gojson::{self, Kind, V};
use setjoin_devices::{lockdown, mam, mdm};
use setjoin_pg::{CommandOutcome, ScopedExecutor};
use std::sync::Arc;

pub struct DevicesRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Action {
    MamDevices,
    MamEvents,
    MamLock,
    MamUnlock,
    MamDeviceSet,
    MamDeviceDelete,
    MamPolicies,
    MamGlobal,
    MamGroup,
    MamGroupDelete,
    MdmDevices,
    MdmDevice,
    MdmWipe,
    Policies,
    PolicyCreate,
    PolicyReorder,
    PolicyUpdate,
    PolicyDelete,
    Queue,
    DeviceList,
    Transition,
}

pub(crate) fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let table: [(bool, &str, Action); 21] = [
        (
            *method == Method::PUT,
            "/api/admin/mam/policies/group",
            Action::MamGroup,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/mam/policies/group/{type}/{id}/{key}",
            Action::MamGroupDelete,
        ),
        (
            *method == Method::POST,
            "/api/admin/mam/devices/{device_id}/lock",
            Action::MamLock,
        ),
        (
            *method == Method::POST,
            "/api/admin/mam/devices/{device_id}/unlock",
            Action::MamUnlock,
        ),
        (
            reads,
            "/api/admin/mam/devices/{device_id}/events",
            Action::MamEvents,
        ),
        (
            *method == Method::PUT,
            "/api/admin/mam/devices/{device_id}/policy",
            Action::MamDeviceSet,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/mam/devices/{device_id}/policy/{key}",
            Action::MamDeviceDelete,
        ),
        (reads, "/api/admin/mam/devices", Action::MamDevices),
        (reads, "/api/admin/mam/policies", Action::MamPolicies),
        (
            *method == Method::PUT,
            "/api/admin/mam/policies",
            Action::MamGlobal,
        ),
        (reads, "/api/admin/mdm/devices", Action::MdmDevices),
        (
            reads,
            "/api/admin/mdm/devices/{device_id}",
            Action::MdmDevice,
        ),
        (
            *method == Method::POST,
            "/api/admin/mdm/devices/{device_id}/wipe",
            Action::MdmWipe,
        ),
        (reads, "/api/admin/mdm/policies", Action::Policies),
        (
            *method == Method::POST,
            "/api/admin/mdm/policies",
            Action::PolicyCreate,
        ),
        (
            *method == Method::PUT,
            "/api/admin/mdm/policies/reorder",
            Action::PolicyReorder,
        ),
        (
            *method == Method::PUT,
            "/api/admin/mdm/policies/{id}",
            Action::PolicyUpdate,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/mdm/policies/{id}",
            Action::PolicyDelete,
        ),
        (reads, "/api/admin/devices/queue", Action::Queue),
        (reads, "/api/admin/devices", Action::DeviceList),
        (
            *method == Method::POST,
            "/api/admin/devices/{id}/{action}",
            Action::Transition,
        ),
    ];
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| *action)
}

/// The whole request body, up to `cap` bytes (`None` when it is larger or unreadable).
async fn read_body(r: &mut Request<Body>, cap: usize) -> Option<Vec<u8>> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        if let Ok(data) = frame.ok()?.into_data() {
            if data.len() > cap.saturating_sub(bytes.len()) {
                return None;
            }
            bytes.extend_from_slice(&data);
        }
    }
    Some(bytes)
}

fn json_string(text: &str) -> String {
    setjoin_devices::go_escape(&serde_json::to_string(text).expect("string"))
}

impl<K: KeySource + 'static> Intercept for DevicesRoute<K> {
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
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
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
            let Ok(authority) = setjoin_devices::authority(&exec, actor).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let path = r.uri().path().to_owned();
            let go_path = segment_path(&path);
            let write = !matches!(
                what,
                Action::MamEvents
                    | Action::MamDevices
                    | Action::MamPolicies
                    | Action::MdmDevices
                    | Action::MdmDevice
                    | Action::Policies
                    | Action::Queue
                    | Action::DeviceList
            );
            let required: &[&str] = if write {
                &setjoin_devices::MAM_WRITE
            } else {
                &setjoin_devices::MAM_READ
            };
            if !authority.allows_any(required) {
                let _ =
                    setjoin_devices::console_denied(&exec, actor, &go_path, required[0], operation)
                        .await;
                return bare(403, "Forbidden", &c, &id);
            }
            // `requireOrgWideSurface` guards the global policy writes only.
            let org_wide = matches!(
                what,
                Action::PolicyCreate
                    | Action::PolicyReorder
                    | Action::PolicyUpdate
                    | Action::PolicyDelete
            );
            if org_wide && authority.domain_scope() != 0 {
                let detail = format!(
                    "org-wide-only surface (domain-scoped principal; domain={})",
                    authority.domain_scope()
                );
                let _ = setjoin_devices::console_denied(&exec, actor, &go_path, &detail, operation)
                    .await;
                return bare(403, "Forbidden", &c, &id);
            }
            let head = r.method() == Method::HEAD;
            let reply = |status: u16, body: String| {
                // net/http buffers 2 KiB of a handler's output; a larger single
                // write is flushed before the handler returns and sent chunked.
                let big = body.len() > 2048;
                let chunked = big && !head;
                let unsized_body = big && head;
                let mut response =
                    crate::jmap::reply::response(body.clone(), c.identity.proto, id.clone());
                if unsized_body {
                    // Go flushes the copy before the handler returns, so HEAD advertises
                    // neither a synthesized length nor chunking.
                    use http_body_util::BodyExt;
                    let stream = futures_util::stream::once(async move {
                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(hyper::body::Frame::data(
                            bytes::Bytes::from(body),
                        ))
                    });
                    *response.body_mut() = http_body_util::StreamBody::new(stream).boxed();
                }
                *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
                if chunked {
                    response.headers_mut().insert(
                        "transfer-encoding",
                        hyper::header::HeaderValue::from_static("chunked"),
                    );
                }
                response
            };
            let problem = |status: u16, detail: &str| bare(status, detail, &c, &id);
            let scope = authority.domain_scope();
            match what {
                Action::MamGroupDelete => {
                    let group = segment(&path, 6);
                    let key = segment(&path, 8);
                    if group.is_empty() || key.is_empty() {
                        return problem(400, "group_type and key required");
                    }
                    let Ok(group_id) = segment(&path, 7).parse::<i64>() else {
                        return problem(400, "invalid group_id");
                    };
                    match mam::delete_group(&exec, actor, &group, group_id, &key, operation).await {
                        CommandOutcome::Committed(true) => {}
                        CommandOutcome::Committed(false) => {
                            return problem(404, "group policy not found")
                        }
                        CommandOutcome::RolledBack(_) => return problem(500, "database error"),
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    }
                    match mam::notify(&exec, actor, 0, 0, "group_policy_updated", operation).await {
                        CommandOutcome::Committed(()) => {
                            reply(200, "{\"status\":\"removed\"}\n".into())
                        }
                        CommandOutcome::RolledBack(_) => {
                            problem(500, "policy-change notification failed")
                        }
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::MamGroup => {
                    let Some(bytes) = read_body(&mut r, 16 << 20).await else {
                        return problem(400, "invalid JSON");
                    };
                    let Ok((group, group_id, policies)) = mam::group(&bytes) else {
                        return problem(400, "invalid JSON");
                    };
                    if group.is_empty() {
                        return problem(400, "group_type is required");
                    }
                    if !matches!(group.as_str(), "department" | "role" | "domain") {
                        return reply(
                            400,
                            "{\"error\":\"group_type must be department, role, or domain\"}\n"
                                .into(),
                        );
                    }
                    match mam::set_group(&exec, actor, &group, group_id, &policies, operation).await
                    {
                        CommandOutcome::Committed(()) => {}
                        CommandOutcome::RolledBack(_) => return problem(500, "database error"),
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    }
                    match mam::notify(&exec, actor, 0, 0, "group_policy_updated", operation).await {
                        CommandOutcome::Committed(()) => reply(200, "{\"status\":\"ok\"}\n".into()),
                        CommandOutcome::RolledBack(_) => {
                            problem(500, "policy-change notification failed")
                        }
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::MamGlobal => {
                    let Some(bytes) = read_body(&mut r, 16 << 20).await else {
                        return problem(400, "invalid JSON");
                    };
                    let Ok(policies) = mam::policies(&bytes) else {
                        return problem(400, "invalid JSON");
                    };
                    let count = match mam::set_global(&exec, actor, &policies, operation).await {
                        CommandOutcome::Committed(count) => count,
                        CommandOutcome::RolledBack(_) => return problem(500, "database error"),
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    };
                    match mam::notify(&exec, actor, 0, count, "policy_updated", operation).await {
                        CommandOutcome::Committed(()) => reply(200, "{\"status\":\"ok\"}\n".into()),
                        CommandOutcome::RolledBack(_) => {
                            problem(500, "policy-change notification failed")
                        }
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::MamDeviceDelete => {
                    let registry_text = segment(&path, 5);
                    let Ok(registry) = registry_text.parse::<i64>() else {
                        return problem(400, "invalid device_id");
                    };
                    let device = match mam::resolve(&exec, actor, registry, scope).await {
                        Ok(Some(device)) if device != 0 => device,
                        Ok(_) => return problem(404, "device not found"),
                        Err(_) => return problem(500, "database error"),
                    };
                    let key = segment(&path, 7);
                    if key.is_empty() {
                        return problem(400, "policy key required");
                    }
                    match mam::delete_device(&exec, actor, device, scope, &key, operation).await {
                        CommandOutcome::Committed(true) => {}
                        CommandOutcome::Committed(false) => {
                            return problem(404, "policy not found")
                        }
                        CommandOutcome::RolledBack(_) => return problem(500, "database error"),
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    }
                    match mam::notify(&exec, actor, device, 0, "policy_updated", operation).await {
                        CommandOutcome::Committed(()) => reply(
                            200,
                            format!(
                                "{{\"device_id\":{},\"key\":{},\"status\":\"removed\"}}\n",
                                json_string(&registry_text),
                                json_string(&key)
                            ),
                        ),
                        CommandOutcome::RolledBack(_) => {
                            problem(500, "policy-change notification failed")
                        }
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::MamDeviceSet => {
                    let registry_text = segment(&path, 5);
                    let Ok(registry) = registry_text.parse::<i64>() else {
                        return problem(400, "invalid device_id");
                    };
                    let device = match mam::resolve(&exec, actor, registry, scope).await {
                        Ok(Some(device)) if device != 0 => device,
                        Ok(_) => return problem(404, "device not found"),
                        Err(_) => return problem(500, "database error"),
                    };
                    let Some(bytes) = read_body(&mut r, 16 << 20).await else {
                        return problem(400, "invalid JSON");
                    };
                    let Ok(policies) = mam::policies(&bytes) else {
                        return problem(400, "invalid JSON");
                    };
                    match mam::set_device(&exec, actor, device, scope, &policies, operation).await {
                        CommandOutcome::Committed(()) => {}
                        CommandOutcome::RolledBack(ref e) if mam::out_of_scope(e) => {
                            return problem(404, "device not found")
                        }
                        CommandOutcome::RolledBack(_) => return problem(500, "database error"),
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    }
                    let mut evidence_operation = operation;
                    evidence_operation[15] ^= 0x40;
                    match mam::log_event(
                        &exec,
                        actor,
                        device,
                        scope,
                        "policy_applied",
                        "info",
                        &serde_json::json!({"source":"admin","keys":policies}),
                        evidence_operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(true) => {}
                        CommandOutcome::Committed(false) => {
                            return problem(404, "device not found")
                        }
                        CommandOutcome::RolledBack(_) => return problem(500, "database error"),
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    }
                    match mam::notify(&exec, actor, device, 0, "policy_updated", operation).await {
                        CommandOutcome::Committed(()) => reply(
                            200,
                            format!(
                                "{{\"device_id\":{},\"status\":\"ok\"}}\n",
                                json_string(&registry_text)
                            ),
                        ),
                        CommandOutcome::RolledBack(_) => {
                            problem(500, "policy-change notification failed")
                        }
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::MamLock | Action::MamUnlock => {
                    let (event, severity, detail, status) = if what == Action::MamLock {
                        (
                            "device_locked",
                            "warn",
                            serde_json::json!({"locked_by":"admin"}),
                            "locked",
                        )
                    } else {
                        (
                            "device_unlocked",
                            "info",
                            serde_json::json!({"unlocked_by":"admin"}),
                            "unlocked",
                        )
                    };
                    let registry_text = segment(&path, 5);
                    let Ok(registry) = registry_text.parse::<i64>() else {
                        return problem(400, "invalid device_id");
                    };
                    let device = match mam::resolve(&exec, actor, registry, scope).await {
                        Ok(Some(device)) if device != 0 => device,
                        Ok(_) => return problem(404, "device not found"),
                        Err(_) => return problem(500, "database error"),
                    };
                    match mam::log_event(
                        &exec, actor, device, scope, event, severity, &detail, operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(true) => {}
                        CommandOutcome::Committed(false) => {
                            return problem(404, "device not found")
                        }
                        CommandOutcome::RolledBack(_) => return problem(500, "database error"),
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    }
                    match mam::notify(&exec, actor, device, 0, event, operation).await {
                        CommandOutcome::Committed(()) => reply(
                            200,
                            format!(
                                "{{\"device_id\":{},\"status\":{}}}\n",
                                json_string(&registry_text),
                                json_string(status)
                            ),
                        ),
                        CommandOutcome::RolledBack(_) => {
                            problem(500, "policy-change notification failed")
                        }
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::MamEvents => {
                    let Ok(registry) = segment(&path, 5).parse::<i64>() else {
                        return problem(400, "invalid device_id");
                    };
                    let device = match mam::resolve(&exec, actor, registry, scope).await {
                        Ok(Some(device)) => device,
                        Ok(None) => return problem(404, "device not found"),
                        Err(_) => return problem(500, "database error"),
                    };
                    let limit = query(r.uri(), "limit")
                        .and_then(|s| s.parse::<i64>().ok())
                        .filter(|n| *n > 0 && *n <= 200)
                        .unwrap_or(50);
                    match mam::events(&exec, actor, device, limit, scope).await {
                        Ok(body) => reply(200, body),
                        Err(_) => problem(500, "database error"),
                    }
                }
                Action::MamDevices => match mam::list_devices(&exec, actor, scope).await {
                    Ok(body) => reply(200, body),
                    Err(_) => problem(500, "database error"),
                },
                Action::MamPolicies => match mam::list_policies(&exec, actor).await {
                    Ok(body) => reply(200, body),
                    Err(_) => problem(500, "database error"),
                },
                Action::MdmDevices => match mdm::list_devices(&exec, actor, scope).await {
                    Ok(body) => reply(200, body),
                    Err(_) => problem(500, "failed to list devices"),
                },
                Action::MdmDevice => {
                    let Some(device) = parse_uuid(&segment(&path, 5)) else {
                        return problem(400, "invalid device_id");
                    };
                    match mdm::get_device(&exec, actor, &device, scope).await {
                        Some(body) => reply(200, body),
                        None => problem(404, "device not found"),
                    }
                }
                Action::MdmWipe => {
                    let Some(device) = parse_uuid(&segment(&path, 5)) else {
                        return problem(400, "invalid device_id");
                    };
                    let level = match read_body(&mut r, 16 << 20).await {
                        Some(bytes) => gojson::first(&bytes)
                            .ok()
                            .and_then(|v| gojson::fields(&v, &[("level", Kind::Str)], "", "").ok())
                            .map(|mut f| match f.remove(0) {
                                Some(V::Str(s)) => s,
                                _ => String::new(),
                            }),
                        None => None,
                    };
                    let Some(level) = level else {
                        return problem(400, "invalid JSON");
                    };
                    if level != "account" && level != "device" {
                        return problem(400, "level must be 'account' or 'device'");
                    }
                    let ip = c.identity.client_ip.to_string();
                    match mdm::arm_wipe(&exec, actor, &device, &level, scope, &ip, operation).await {
                        CommandOutcome::Committed(()) => reply(
                            202,
                            format!(
                                "{{\"completion\":\"client-attested\",\"device_id\":{},\"level\":{},\"status\":\"pending\"}}\n",
                                json_string(&device),
                                json_string(&level)
                            ),
                        ),
                        CommandOutcome::RolledBack(refusal) => match mdm::wipe_refusal(&refusal) {
                            mdm::WipeRefusal::NotFound => problem(404, "device not found"),
                            mdm::WipeRefusal::Conflict { field, message } => reply(
                                409,
                                format!(
                                    "{{\"error\":{},\"field\":{}}}\n",
                                    json_string(&message),
                                    json_string(field)
                                ),
                            ),
                            mdm::WipeRefusal::Failed => problem(500, "failed to trigger wipe"),
                        },
                        CommandOutcome::Unknown { operation } => unknown_outcome(operation, &c, &id),
                    }
                }
                Action::Policies => match mdm::list_policies(&exec, actor).await {
                    Ok(body) => reply(200, body),
                    Err(_) => problem(500, "failed to list policies"),
                },
                Action::PolicyCreate | Action::PolicyUpdate => {
                    let update = what == Action::PolicyUpdate;
                    let policy_id = if update {
                        match segment(&path, 5).parse::<i64>() {
                            Ok(n) => n,
                            Err(_) => return problem(400, "invalid policy id"),
                        }
                    } else {
                        0
                    };
                    let decoded = match read_body(&mut r, 16 << 20).await {
                        Some(bytes) => mdm::PolicyFields::decode(&bytes),
                        None => Err("http: request body too large".to_owned()),
                    };
                    let fields = match decoded {
                        Ok(f) => f,
                        Err(e) => return problem(400, &format!("invalid JSON: {e}")),
                    };
                    if !update && fields.name.as_deref().is_none_or(str::is_empty) {
                        return problem(400, "name is required");
                    }
                    if let Some((field, message)) = fields.validate() {
                        return reply(
                            400,
                            format!(
                                "{{\"error\":{},\"field\":{}}}\n",
                                json_string(message),
                                json_string(field)
                            ),
                        );
                    }
                    if update {
                        match mdm::update_policy(&exec, actor, policy_id, &fields, operation).await
                        {
                            CommandOutcome::Committed(true) => {
                                reply(200, "{\"message\":\"policy updated\"}\n".into())
                            }
                            CommandOutcome::Committed(false) => problem(404, "policy not found"),
                            CommandOutcome::RolledBack(_) => {
                                problem(500, "failed to update policy")
                            }
                            CommandOutcome::Unknown { operation } => {
                                unknown_outcome(operation, &c, &id)
                            }
                        }
                    } else {
                        match mdm::create_policy(&exec, actor, &fields, operation).await {
                            CommandOutcome::Committed(new_id) => reply(
                                201,
                                format!("{{\"id\":{new_id},\"message\":\"policy created\"}}\n"),
                            ),
                            CommandOutcome::RolledBack(_) => {
                                problem(500, "failed to create policy")
                            }
                            CommandOutcome::Unknown { operation } => {
                                unknown_outcome(operation, &c, &id)
                            }
                        }
                    }
                }
                Action::PolicyDelete => {
                    let Ok(policy) = segment(&path, 5).parse::<i64>() else {
                        return problem(400, "invalid policy id");
                    };
                    match mdm::delete_policy(&exec, actor, policy, operation).await {
                        CommandOutcome::Committed(mdm::Deleted::Done) => {
                            reply(200, "{\"message\":\"policy deleted\"}\n".into())
                        }
                        CommandOutcome::Committed(mdm::Deleted::LastGlobal) => reply(
                            409,
                            "{\"error\":\"cannot delete the last global policy\"}\n".into(),
                        ),
                        CommandOutcome::Committed(mdm::Deleted::Missing) => {
                            problem(404, "policy not found")
                        }
                        CommandOutcome::RolledBack(_) => problem(500, "failed to delete policy"),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::PolicyReorder => {
                    let decoded = match read_body(&mut r, 16 << 20).await {
                        Some(bytes) => {
                            gojson::first(&bytes).and_then(|v| gojson::int_list(&v, "ids"))
                        }
                        None => Err("http: request body too large".to_owned()),
                    };
                    let ids = match decoded {
                        Ok(ids) => ids.unwrap_or_default(),
                        Err(e) => return problem(400, &format!("invalid JSON: {e}")),
                    };
                    if ids.is_empty() {
                        return problem(400, "ids array is required");
                    }
                    match mdm::reorder_policies(&exec, actor, &ids, operation).await {
                        CommandOutcome::Committed(()) => {
                            reply(200, "{\"message\":\"policies reordered\"}\n".into())
                        }
                        CommandOutcome::RolledBack(_) => problem(500, "failed to reorder policies"),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::Queue => {
                    let state = query(r.uri(), "state").unwrap_or_default();
                    let text = query(r.uri(), "q").unwrap_or_default();
                    let limit = query(r.uri(), "limit").unwrap_or_default();
                    // Go keeps the limit only when Atoi succeeds and it is positive.
                    let limit = limit.parse::<i64>().ok().filter(|n| *n > 0).unwrap_or(0);
                    match lockdown::queue(&exec, actor, &state, &text, limit).await {
                        Ok(body) => reply(200, body),
                        Err(_) => problem(500, "database error"),
                    }
                }
                Action::DeviceList => {
                    let user = query(r.uri(), "user_id")
                        .unwrap_or_default()
                        .parse::<i64>()
                        .ok()
                        .filter(|n| *n > 0);
                    let Some(user) = user else {
                        return problem(400, "user_id required");
                    };
                    match lockdown::devices_of(&exec, actor, user).await {
                        Ok(body) => reply(200, body),
                        Err(_) => problem(500, "database error"),
                    }
                }
                Action::Transition => {
                    let to = match segment(&path, 5).as_str() {
                        "enroll" => "enrolled",
                        "approve" => "approved",
                        "revoke" => "revoked",
                        _ => return problem(400, "unknown action; want enroll|approve|revoke"),
                    };
                    let Ok(device) = segment(&path, 4).parse::<i64>() else {
                        return problem(400, "invalid device id");
                    };
                    // The body is optional: any decode error leaves the reason empty.
                    let reason = match read_body(&mut r, 1 << 16).await {
                        Some(bytes) => gojson::first(&bytes)
                            .ok()
                            .and_then(|v| gojson::fields(&v, &[("reason", Kind::Str)], "", "").ok())
                            .and_then(|mut f| match f.remove(0) {
                                Some(V::Str(s)) => Some(s),
                                _ => None,
                            })
                            .unwrap_or_default(),
                        None => String::new(),
                    };
                    match lockdown::transition(&exec, actor, device, to, &reason, operation).await {
                        CommandOutcome::Committed(()) => reply(
                            200,
                            format!("{{\"device_id\":{device},\"state\":\"{to}\"}}\n"),
                        ),
                        CommandOutcome::RolledBack(refusal) => {
                            let (status, detail) = lockdown::transition_refusal(&refusal);
                            problem(status, &detail)
                        }
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
            }
        })
    }
}
