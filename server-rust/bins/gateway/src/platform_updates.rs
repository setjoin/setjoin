//! F08 Platform HTTP adapter for the `updates-deploy` slice (#300): the retired
//! auto-update and gateway-upgrade routes, the upgrade control plane, recovery incidents,
//! client update management and the deploy wizard. A separate intercept from
//! `platform.rs` (the `system-features` slice) so the two slices own disjoint arms.
//! Gates mirror Go's `requireSystemPerm` / `requireSystemUpgrade` / `requireSystemConfig` /
//! `requireSystemRecovery`: a refusal writes Go's durable `console.denied` row and answers
//! the bare 403; a failed authority read or a missing token forwards the request to Go.
use crate::platform_upgrades::{self as upgrades, Kind};
use crate::mailboxes::{bare, language, render, unknown_outcome};
use crate::problem::Problem;
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use serde::de::{MapAccess, Visitor};
use setjoin_pg::{CommandOutcome, ScopedExecutor};
use setjoin_platform::updates;
use std::sync::Arc;

pub struct PlatformUpdatesRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    recovery: Option<crate::platform_recovery_admin::RecoveryAdmin>,
    airgap: Option<Arc<setjoin_platform::airgap::Store>>,
    deploy: Option<Arc<setjoin_platform::deploy::Wizard>>,
}

impl<K: KeySource + 'static> PlatformUpdatesRoute<K> {
    pub fn new(exec: ScopedExecutor, keys: Arc<K>, issuer: String) -> Self {
        Self { exec, keys, issuer, recovery: None, airgap: None, deploy: None }
    }
    pub async fn with_deploy(mut self,worker:ScopedExecutor,config:setjoin_platform::deploy::Config)->Self {self.deploy=Some(Arc::new(setjoin_platform::deploy::Wizard::load(worker,config).await));self}
    pub fn with_airgap(mut self,store:Option<Arc<setjoin_platform::airgap::Store>>)->Self {self.airgap=store;self}
    pub async fn with_recovery(mut self, worker: ScopedExecutor, ready: bool, direct: Option<String>) -> Self {
        self.recovery = Some(crate::platform_recovery_admin::RecoveryAdmin::new(worker, ready, direct).await);
        self
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Action {
    AutoUpdateGet,
    AutoUpdatePut,
    MaintenanceGet,
    MaintenancePut,
    UpgradeCheck,
    UpgradeApply,
    UpgradeRollback,
    UpgradeHistory,
    UpdatesSummary,
    UpdatesDevices,
    UpdatesPush,
    Upgrade(Kind),
    Recovery(crate::platform_recovery_admin::Kind),
    Appcast,
    AirgapFile,
    AirgapUpload,
    DeployStatus,
    DeployStart,
    DeployCancel,
}

/// Method/pattern table; the first column is the method predicate.
pub(crate) fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let (post, put) = (*method == Method::POST, *method == Method::PUT);
    let table: [(bool, &str, Action); 24] = [
        (post, "/api/admin/deploy/start", Action::DeployStart),
        (post, "/api/admin/deploy/cancel", Action::DeployCancel),
        (reads, "/api/admin/deploy/status", Action::DeployStatus),
        (post, "/api/admin/updates/airgap/upload", Action::AirgapUpload),
        (reads, "/api/updates/appcast", Action::Appcast),
        (reads, "/api/updates/{slug}/{filename}", Action::AirgapFile),
        (reads, "/api/admin/system/auto-update", Action::AutoUpdateGet),
        (put, "/api/admin/system/auto-update", Action::AutoUpdatePut),
        (
            reads,
            "/api/admin/system/maintenance-window",
            Action::MaintenanceGet,
        ),
        (
            put,
            "/api/admin/system/maintenance-window",
            Action::MaintenancePut,
        ),
        (post, "/api/admin/system/upgrade/check", Action::UpgradeCheck),
        (post, "/api/admin/system/upgrade/apply", Action::UpgradeApply),
        (
            post,
            "/api/admin/system/upgrade/rollback",
            Action::UpgradeRollback,
        ),
        (
            reads,
            "/api/admin/system/upgrade/status",
            Action::UpgradeHistory,
        ),
        (reads, "/api/admin/system/recovery/incidents", Action::Recovery(crate::platform_recovery_admin::Kind::List)),
        (reads, "/api/admin/system/recovery/signals", Action::Recovery(crate::platform_recovery_admin::Kind::Signals)),
        (reads, "/api/admin/system/recovery/incidents/{id}/artifacts", Action::Recovery(crate::platform_recovery_admin::Kind::Artifacts)),
        (post, "/api/admin/system/recovery/incidents/{id}/approve", Action::Recovery(crate::platform_recovery_admin::Kind::Approve)),
        (post, "/api/admin/system/recovery/incidents/{id}/close", Action::Recovery(crate::platform_recovery_admin::Kind::Close)),
        (post, "/api/admin/system/recovery/artifacts/{id}/accept", Action::Recovery(crate::platform_recovery_admin::Kind::Accept)),
        (post, "/api/admin/system/recovery/incidents", Action::Recovery(crate::platform_recovery_admin::Kind::Open)),
        (reads, "/api/admin/updates/summary", Action::UpdatesSummary),
        (reads, "/api/admin/updates/devices", Action::UpdatesDevices),
        (post, "/api/admin/updates/push", Action::UpdatesPush),
    ];
    let console = upgrades::TABLE.iter().map(|(m, pattern, kind)| {
        let ok = if *m == "GET" { reads } else { post };
        (ok, *pattern, Action::Upgrade(*kind))
    });
    table
        .iter()
        .copied()
        .chain(console)
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| action)
}

/// Go sees the `/api`-stripped request path, decoded.
fn segment_path(path: &str) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.strip_prefix("/api").unwrap_or(path),
    ))
}

/// The permission set a route's Go middleware requires (any-of).
fn gate(what: Action) -> &'static [&'static str] {
    match what {
        Action::Appcast | Action::AirgapFile => &[],
        Action::Recovery(_) => &["system.recovery"],
        Action::AutoUpdatePut | Action::MaintenancePut => &setjoin_platform::SYSTEM_CONFIG,
        Action::UpgradeCheck
        | Action::UpgradeApply
        | Action::UpgradeRollback
        | Action::UpdatesPush
        | Action::AirgapUpload
        | Action::DeployStatus
        | Action::DeployStart
        | Action::DeployCancel
        | Action::Upgrade(_) => &setjoin_platform::SYSTEM_UPGRADE,
        Action::AutoUpdateGet
        | Action::MaintenanceGet
        | Action::UpgradeHistory
        | Action::UpdatesSummary
        | Action::UpdatesDevices => &setjoin_platform::SYSTEM_CONSOLE,
    }
}

impl<K: KeySource + 'static> Intercept for PlatformUpdatesRoute<K> {
    fn shutdown(&self) {if let Some(service)=&self.recovery {service.shutdown();}if let Some(wizard)=&self.deploy{wizard.shutdown();}}
    fn requires_session(&self, req: &Request<Body>) -> bool { !matches!(action(req.method(),req.uri().path()),Some(Action::Appcast|Action::AirgapFile)) }
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
        let recovery = self.recovery.clone();
        let airgap = self.airgap.clone();
        let deploy = self.deploy.clone();
        Box::pin(async move {
            let Some(what) = action(r.method(), r.uri().path()) else {
                return c.upstream.forward(r, &c.identity).await;
            };
            if matches!(what,Action::Appcast|Action::AirgapFile) {
                let Some(operation)=crate::jmap::random()else{return bare(503,"service unavailable",&c,"");};
                let id=crate::jmap::reply::request_id(r.headers().get("x-request-id"),operation);
                if r.method()!=Method::GET{return crate::platform_airgap::plain(405,"method not allowed",&c,&id);}
                let Some(store)=airgap else{return crate::platform_airgap::plain(404,"404 page not found",&c,&id);};
                if what==Action::AirgapFile{return crate::platform_airgap::file(&store,&r,&c,&id).await;}
                return crate::jmap::reply::response(store.appcast(),c.identity.proto,id);
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
                return bare(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let actor = auth.context();
            let Ok(authority) = setjoin_platform::authority(&exec, actor).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let go_path = segment_path(r.uri().path());
            let required = gate(what);
            if !authority.allows_any(required) {
                let _ = setjoin_platform::console_denied(
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
                let _ =
                    setjoin_platform::console_denied(&exec, actor, &go_path, &detail, operation)
                        .await;
                return bare(403, "Forbidden", &c, &id);
            }
            // #542 (owner-approved security fix 2026-11-05): the deploy wizard and the airgap
            // upload are server-wide, so they need an organization-wide system.upgrade grant.
            let org_wide_route = match what {
                Action::DeployStart => Some("deploy-start"),
                Action::DeployCancel => Some("deploy-cancel"),
                Action::DeployStatus => Some("deploy-status"),
                Action::AirgapUpload => Some("airgap-upload"),
                _ => None,
            };
            if let Some(route) = org_wide_route {
                if !matches!(setjoin_platform::upgrade_org_wide(&exec, actor, route).await, Ok(true)) {
                    let detail = format!("{} (organization-wide grant required)", required.join("|"));
                    let _ = setjoin_platform::console_denied(&exec, actor, &go_path, &detail, operation).await;
                    return bare(403, "Forbidden", &c, &id);
                }
            }
            if matches!(what,Action::DeployStart|Action::DeployCancel) {
                let Some(wizard)=deploy else{return bare(500,"Deploy failed. Check the server logs for details.",&c,&id);};
                return crate::platform_deploy::serve(what==Action::DeployStart,&wizard,&mut r,&auth,&c,&id).await;
            }
            if what==Action::DeployStatus {
                let Some(wizard)=deploy else{return bare(500,"Deploy failed. Check the server logs for details.",&c,&id);};
                return crate::jmap::reply::response(wizard.status().await,c.identity.proto,id);
            }
            if what==Action::AirgapUpload {
                let Some(store)=airgap else{return crate::platform_airgap::plain(404,"404 page not found",&c,&id);};
                return crate::platform_airgap::upload(store,&mut r,&c,&id).await;
            }
            if let Action::Recovery(kind) = what {
                if matches!(kind, crate::platform_recovery_admin::Kind::Approve | crate::platform_recovery_admin::Kind::Close | crate::platform_recovery_admin::Kind::Open | crate::platform_recovery_admin::Kind::Accept)
                    && setjoin_platform::upgrades::reason_required(&exec, "system").await
                    && r.headers().get("x-audit-reason").is_none_or(|v| v.as_bytes().is_empty())
                {
                    setjoin_platform::upgrades::missing_reason(&exec, actor, &c.identity.client_ip.to_string(), "system.recovery", operation).await;
                    return bare(400, "reason_required", &c, &id);
                }
                return crate::platform_recovery_admin::serve(kind, recovery.as_ref(), &mut r, &auth, &c, operation, &id).await;
            }
            if let Action::Upgrade(kind) = what {
                // `requireReason(system.upgrade)`: a reason-required area demands the header.
                if upgrades::reason_wrapped(kind)
                    && setjoin_platform::upgrades::reason_required(&exec, "system").await
                    && r.headers()
                        .get("x-audit-reason")
                        .is_none_or(|v| v.as_bytes().is_empty())
                {
                    let ip = c.identity.client_ip.to_string();
                    setjoin_platform::upgrades::missing_reason(
                        &exec,
                        actor,
                        &ip,
                        "system.upgrade",
                        operation,
                    )
                    .await;
                    return bare(400, "reason_required", &c, &id);
                }
                return upgrades::serve(kind, r, &c, &exec, &auth, operation, &id, &go_path).await;
            }
            // #456: a domain-scoped caller sees only the devices of users inside its reach.
            let reach = if authority.domain_scope() > 0 { actor.user_id() } else { 0 };
            let head = r.method() == Method::HEAD;
            let reply = |body: String, status: u16| {
                // net/http buffers 2 KiB of a handler's output; a larger single write
                // is flushed before the handler returns and sent chunked.
                let chunked = body.len() > 2048 && !head;
                let mut response = crate::jmap::reply::response(body, c.identity.proto, id.clone());
                *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
                if chunked {
                    response.headers_mut().insert(
                        "transfer-encoding",
                        hyper::header::HeaderValue::from_static("chunked"),
                    );
                }
                response
            };
            match what {
                Action::UpgradeHistory => reply(updates::history(&exec).await, 200),
                Action::UpdatesSummary => reply(updates::summary(&exec, reach).await, 200),
                Action::UpdatesDevices => {
                    // Go's `ParseLimitOffset(r, 50, 100)`.
                    let number = |name: &str| {
                        crate::admin_identity_input::query(r.uri(), name)
                            .and_then(|v| v.parse::<i64>().ok())
                            .unwrap_or(0)
                    };
                    let limit = number("limit");
                    let limit = if limit <= 0 || limit > 100 { 50 } else { limit };
                    let offset = number("offset").clamp(0, 1_000_000);
                    match updates::devices(&exec, reach, limit, offset).await {
                        Ok(body) => reply(body, 200),
                        Err(_) => bare(500, "database error", &c, &id),
                    }
                }
                Action::UpdatesPush => {
                    let Ok(body) = json_body::<PushBody>(&mut r).await else {
                        return bare(400, "invalid JSON", &c, &id);
                    };
                    if body.device_ids.is_empty() {
                        return bare(400, "device_ids is required", &c, &id);
                    }
                    match updates::push(&exec, actor, body.device_ids.len(), operation).await {
                        CommandOutcome::Committed(()) => {
                            let mut response = reply(String::new(), 204);
                            response.headers_mut().remove("content-type");
                            response
                        }
                        // Go ignores a failed notify and still answers 204.
                        CommandOutcome::RolledBack(_) => {
                            let mut response = reply(String::new(), 204);
                            response.headers_mut().remove("content-type");
                            response
                        }
                        CommandOutcome::Unknown { operation } => unknown_outcome(operation, &c, &id),
                    }
                }
                Action::Appcast | Action::AirgapFile | Action::AirgapUpload | Action::DeployStatus | Action::DeployStart | Action::DeployCancel | Action::Upgrade(_) | Action::Recovery(_) => unreachable!("served above"),
                Action::AutoUpdateGet
                | Action::AutoUpdatePut
                | Action::MaintenanceGet
                | Action::MaintenancePut => retired(
                    "https://setjoin.com/errors/legacy-auto-update-retired",
                    "Legacy auto-update configuration retired",
                    "Path-based auto-update and its separate maintenance-window configuration are retired because they bypass signed releases, application recovery points, and transactional rollback.",
                    &go_path,
                    &r,
                    &c,
                    &id,
                ),
                Action::UpgradeCheck | Action::UpgradeApply | Action::UpgradeRollback => retired(
                    "https://setjoin.com/errors/legacy-upgrade-retired",
                    "Legacy server upgrade retired",
                    "Gateway-managed server upgrades are retired because they cannot provide a complete application recovery point or crash-safe rollback.",
                    &go_path,
                    &r,
                    &c,
                    &id,
                ),
            }
        })
    }
}

const RETIRED_REMEDIATION: &str = "Open /admin/updates/server to preview or schedule a signed release. Use mailctl upgrade status --json for read-only host status and follow docs/guides/UPGRADE.md for operator recovery.";

/// Go's `httputil.WriteProblem` 410 with the retirement type, title and remediation.
fn retired(
    kind: &str,
    title: &str,
    detail: &str,
    path: &str,
    r: &Request<Body>,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    render(
        Problem::new(410, detail)
            .kind(kind)
            .title(title)
            .instance(path)
            .remediation(RETIRED_REMEDIATION),
        Some(&language(r)),
        c,
        id,
    )
}

/// Go's `PushUpdateRequest` decoded with `json.Decoder.Decode`: case-folded keys, `null`
/// keeps the zero value, unknown keys are ignored, a wrongly typed field fails the decode
/// and only the first JSON value is read.
#[derive(Default)]
struct PushBody {
    device_ids: Vec<i64>,
}
impl<'de> serde::Deserialize<'de> for PushBody {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = PushBody;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<PushBody, E> {
                Ok(PushBody::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<PushBody, M::Error> {
                let mut body = PushBody::default();
                while let Some(key) = map.next_key::<String>()? {
                    match crate::guests_input::fold(&key).as_str() {
                        "device_ids" => {
                            // A `null` element is Go's zero id; a `null` list is nil.
                            body.device_ids = map
                                .next_value::<Option<Vec<Option<i64>>>>()?
                                .unwrap_or_default()
                                .into_iter()
                                .map(|id| id.unwrap_or(0))
                                .collect();
                        }
                        "version" | "message" => {
                            let _ = map.next_value::<Option<String>>()?;
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}

/// Go's `json.NewDecoder(r.Body).Decode`: only the first JSON value is read.
async fn json_body<T: serde::de::DeserializeOwned>(r: &mut Request<Body>) -> Result<T, ()> {
    use http_body_util::BodyExt;
    const CAP: usize = 16 << 20;
    let mut bytes = Vec::new();
    while bytes.len() < CAP {
        let Some(frame) = r.body_mut().frame().await else {
            break;
        };
        if let Ok(data) = frame.map_err(|_| ())?.into_data() {
            bytes.extend_from_slice(&data[..data.len().min(CAP - bytes.len())]);
        }
    }
    let fixed = crate::guests_input::go_json_bytes(&bytes);
    match serde_json::Deserializer::from_slice(&fixed)
        .into_iter::<T>()
        .next()
    {
        Some(Ok(value)) => Ok(value),
        _ => Err(()),
    }
}
