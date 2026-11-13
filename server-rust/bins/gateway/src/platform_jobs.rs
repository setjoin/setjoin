//! F08 slice `jobs-storage` HTTP adapter (#301): `/admin/jobs/*` and the storage read
//! models of `/admin/storage/*` (contract in the `setjoin-platform` DOX). Gates mirror
//! Go's middleware: `requireMailPerm` (reads), `requireQueueWrite` (journal retry),
//! `requireRolesManage` (bulk-role detail and retry), `requireSystemConfig` (storage
//! writes). A refusal writes Go's durable `console.denied` row and answers the bare 403.
//! Handler errors are Go's `WriteProblem` (instance is the stripped path).
use crate::admin_identity_input::{atoi, query};
use crate::mailboxes::{bare, unknown_outcome};
use crate::platform::{segment, segment_path};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::{CommandOutcome, ScopedExecutor};
use setjoin_platform::{jobs as jobs_db, storage as storage_db};
use std::sync::Arc;

pub struct PlatformJobsRoute<K: KeySource + 'static> {
    /// Request pool (the verified actor's scoped executor).
    pub exec: ScopedExecutor,
    /// Cross-tenant worker pool (Go's `workerPool`), used by the queue reducers.
    pub worker: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    pub storage: Option<Arc<crate::platform_storage::Runtime>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Action {
    StorageStatus,
    DrReconcile,
    DrScanStart,
    MigrateStart,
    MigrateCancel,
    JobSummary,
    JobList,
    JournalRetry,
    BulkDetail,
    BulkRetry,
    DrScanList,
    DrScanGet,
    MigrateList,
    MigrateStatus,
}

pub(crate) fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let post = *method == Method::POST;
    let table: [(bool, &str, Action); 14] = [
        (
            post,
            "/api/admin/storage/migrate/{id}/cancel",
            Action::MigrateCancel,
        ),
        (post, "/api/admin/storage/migrate", Action::MigrateStart),
        (post, "/api/admin/storage/dr-scan", Action::DrScanStart),
        (
            post,
            "/api/admin/storage/dr-scan/{id}/reconcile",
            Action::DrReconcile,
        ),
        (reads, "/api/admin/storage/status", Action::StorageStatus),
        (reads, "/api/admin/jobs/summary/{queue}", Action::JobSummary),
        (reads, "/api/admin/jobs/{queue}", Action::JobList),
        (
            post,
            "/api/admin/jobs/journal/{id}/retry",
            Action::JournalRetry,
        ),
        (reads, "/api/admin/jobs/bulk_role/{id}", Action::BulkDetail),
        (
            post,
            "/api/admin/jobs/bulk_role/{id}/retry",
            Action::BulkRetry,
        ),
        (reads, "/api/admin/storage/dr-scan", Action::DrScanList),
        (reads, "/api/admin/storage/dr-scan/{id}", Action::DrScanGet),
        (reads, "/api/admin/storage/migrate", Action::MigrateList),
        (
            reads,
            "/api/admin/storage/migrate/{id}",
            Action::MigrateStatus,
        ),
    ];
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| *action)
}

fn gate(what: Action) -> &'static [&'static str] {
    match what {
        Action::DrReconcile
        | Action::DrScanStart
        | Action::MigrateStart
        | Action::MigrateCancel => &setjoin_platform::SYSTEM_CONFIG,
        Action::JournalRetry => &jobs_db::QUEUE_WRITE,
        Action::BulkDetail | Action::BulkRetry => &jobs_db::ROLES_MANAGE,
        _ => &jobs_db::MAIL_CONSOLE,
    }
}

impl<K: KeySource + 'static> Intercept for PlatformJobsRoute<K> {
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
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, worker, keys, issuer) = (
            self.exec.clone(),
            self.worker.clone(),
            self.keys.clone(),
            self.issuer.clone(),
        );
        let storage = self.storage.clone();
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
            // #539 (owner-approved security fix 2026-11-05): server-wide storage scans,
            // reconciliation and migration need an organization-wide system.config grant.
            let server_wide = match what {
                Action::DrScanStart => Some("scan"),
                Action::DrReconcile => Some("reconcile"),
                Action::MigrateStart => Some("migrate"),
                Action::MigrateCancel => Some("cancel"),
                _ => None,
            };
            // #542 (review of #537): the storage read routes keep Go's Mail-console gate but
            // also need an organization-wide grant: they expose server-wide status and history.
            let server_read = match what {
                Action::StorageStatus => Some("status"),
                Action::DrScanList => Some("scan-list"),
                Action::DrScanGet => Some("scan-get"),
                Action::MigrateList => Some("migrate-list"),
                Action::MigrateStatus => Some("migrate-get"),
                _ => None,
            };
            if server_wide.is_some() || server_read.is_some() {
                let allowed = match (server_wide, server_read) {
                    (Some(route), _) => setjoin_platform::storage_org_wide(&exec, actor, route).await,
                    (_, Some(route)) => {
                        setjoin_platform::storage_read_org_wide(&exec, actor, route).await
                    }
                    _ => unreachable!(),
                };
                if !matches!(allowed, Ok(true)) {
                    let detail =
                        format!("{} (organization-wide grant required)", required.join("|"));
                    let _ = setjoin_platform::console_denied(
                        &exec, actor, &go_path, &detail, operation,
                    )
                    .await;
                    return bare(403, "Forbidden", &c, &id);
                }
            }
            let head = r.method() == Method::HEAD;
            let reply = |body: String, status: u16| {
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
            let path = r.uri().path().to_owned();
            // Go's `WriteProblem`: instance is the stripped path, language from the request.
            let problem = |status: u16, detail: &str| {
                crate::mailboxes::render(
                    crate::problem::Problem::new(status, detail).instance(&go_path),
                    Some(&crate::mailboxes::language(&r)),
                    &c,
                    &id,
                )
            };
            let db_error = || problem(500, "database error");
            // `strconv.ParseInt(r.PathValue("id"), 10, 64)`.
            let target = || segment(&path, 5).parse::<i64>().ok();
            match what {
                Action::MigrateCancel => {
                    let Some(migration) = target() else {
                        return problem(400, "invalid migration id");
                    };
                    let Some(storage) = storage else {
                        return db_error();
                    };
                    match storage.cancel_migration(&exec, migration).await {
                        Ok(body) => reply(body, 200),
                        Err(crate::platform_storage::Failure::Problem(status, detail)) => {
                            problem(status, &detail)
                        }
                        Err(crate::platform_storage::Failure::Unknown(operation)) => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::MigrateStart => {
                    let Some(storage) = storage else {
                        return db_error();
                    };
                    let raw = crate::compliance_export::query_bytes(r.uri(), "target")
                        .unwrap_or_default();
                    let requested = match std::str::from_utf8(&raw) {
                        Ok(value) => value,
                        Err(_) => {
                            return problem(
                                500,
                                &format!(
                                    "failed to create target driver: storage: unknown provider {}",
                                    setjoin_contracts::go_quote::quote(&raw)
                                ),
                            )
                        }
                    };
                    match storage
                        .start_migration(&exec, actor, operation, requested)
                        .await
                    {
                        Ok(body) => reply(body, 202),
                        Err(crate::platform_storage::Failure::Problem(status, detail)) => {
                            problem(status, &detail)
                        }
                        Err(crate::platform_storage::Failure::Unknown(operation)) => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::DrScanStart => {
                    let Some(storage) = storage else {
                        return db_error();
                    };
                    match storage.start_scan(&exec, actor, operation).await {
                        Ok(body) => reply(body, 202),
                        Err(crate::platform_storage::Failure::Problem(status, detail)) => {
                            problem(status, &detail)
                        }
                        Err(crate::platform_storage::Failure::Unknown(operation)) => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::DrReconcile => {
                    let Some(scan) = target() else {
                        return problem(400, "invalid scan id");
                    };
                    let Some(storage) = storage else {
                        return db_error();
                    };
                    match storage.reconcile(&exec, actor, scan, operation).await {
                        Ok(body) => reply(body, 200),
                        Err(crate::platform_storage::Failure::Problem(409, detail)) => {
                            crate::mailboxes::render(
                                crate::problem::Problem::new(409, &detail)
                                    .kind("https://setjoin.com/errors/conflict")
                                    .instance(&go_path),
                                Some(&crate::mailboxes::language(&r)),
                                &c,
                                &id,
                            )
                        }
                        Err(crate::platform_storage::Failure::Problem(status, detail)) => {
                            problem(status, &detail)
                        }
                        Err(crate::platform_storage::Failure::Unknown(operation)) => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::StorageStatus => {
                    let Some(storage) = storage else {
                        return problem(503, "Could not reach object storage. The storage service may be restarting.");
                    };
                    match storage.status().await {
                        Ok(body) => reply(body, 200),
                        Err(_) => problem(503, "Could not reach object storage. The storage service may be restarting."),
                    }
                }
                Action::JobSummary | Action::JobList => {
                    let queue = segment(&path, if what == Action::JobSummary { 5 } else { 4 });
                    if !jobs_db::known_queue(&queue) {
                        return problem(400, "unknown queue");
                    }
                    let result = if what == Action::JobSummary {
                        jobs_db::summary(&worker, &queue).await
                    } else {
                        // Go's `ParseLimitOffset(r, 50, 200)`.
                        let mut limit = atoi(&query(r.uri(), "limit").unwrap_or_default());
                        if !(1..=200).contains(&limit) {
                            limit = 50;
                        }
                        let offset =
                            atoi(&query(r.uri(), "offset").unwrap_or_default()).clamp(0, 1_000_000);
                        let status = query(r.uri(), "status").unwrap_or_default();
                        jobs_db::list(&worker, &queue, &status, limit as i32, offset as i32).await
                    };
                    match result {
                        Ok(body) => reply(body, 200),
                        Err(_) => db_error(),
                    }
                }
                Action::JournalRetry => {
                    let Some(job) = target() else {
                        return problem(400, "invalid job id");
                    };
                    match jobs_db::retry_journal(&worker, actor, job, operation).await {
                        CommandOutcome::Committed(true) => no_content(reply(String::new(), 204)),
                        CommandOutcome::Committed(false) => {
                            problem(404, "row not found or not dead-lettered")
                        }
                        CommandOutcome::RolledBack(_) => db_error(),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::BulkDetail => {
                    let Some(job) = target() else {
                        return problem(400, "invalid job id");
                    };
                    match jobs_db::bulk_detail(&exec, job).await {
                        Some(row) => {
                            // Written verbatim: no encoder newline, no HTML escaping.
                            reply(row, 200)
                        }
                        None => problem(404, "job not found"),
                    }
                }
                Action::BulkRetry => {
                    let Some(job) = target() else {
                        return problem(400, "invalid job id");
                    };
                    let ip = c.identity.client_ip.to_string();
                    match jobs_db::bulk_retry(&exec, actor, job, &ip, operation).await {
                        CommandOutcome::Committed(true) => no_content(reply(String::new(), 204)),
                        CommandOutcome::Committed(false) | CommandOutcome::RolledBack(_) => {
                            problem(409, "job not found or not in error state")
                        }
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::DrScanList => match storage_db::dr_scan_list(&exec).await {
                    Ok(body) => reply(body, 200),
                    Err(_) => db_error(),
                },
                Action::DrScanGet => {
                    let Some(scan) = target() else {
                        return problem(400, "invalid scan id");
                    };
                    match storage_db::dr_scan_get(&exec, scan).await {
                        Ok(Some(body)) => reply(body, 200),
                        Ok(None) => problem(404, "scan not found"),
                        Err(_) => db_error(),
                    }
                }
                Action::MigrateList => match storage_db::migrate_list(&exec).await {
                    Ok(body) => reply(body, 200),
                    Err(_) => problem(500, "query failed"),
                },
                Action::MigrateStatus => {
                    let Some(migration) = target() else {
                        return problem(400, "invalid migration id");
                    };
                    match storage_db::migrate_status(&exec, migration).await {
                        Some(body) => reply(body, 200),
                        None => problem(404, "migration not found"),
                    }
                }
            }
        })
    }
}

fn no_content(mut response: Response<Body>) -> Response<Body> {
    response.headers_mut().remove("content-type");
    response
}
