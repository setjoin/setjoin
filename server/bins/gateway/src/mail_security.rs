//! F06 Mail security HTTP adapter. The nine-slice map and each slice's contract live in the
//! `setjoin-mail-security` DOX. Admin routes are gated like Go's `requireMailPerm`,
//! `requireMailExport` and `requireSecurityWrite` from the live governed grants via
//! `AdminPrincipal` / `AdminPermissionProof`: a refusal writes Go's durable `console.denied`
//! audit row and answers the bare 403. A failed admission forwards the untouched request to
//! Go, as every family adapter does, so Go keeps answering 401 and any state it alone can judge.
use crate::admin_identity_input::{atoi, query};
use crate::mailboxes::{bare, unknown_outcome};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_mail_security::dmarc as dmarc_db;
use setjoin_mail_security::quarantine as quarantine_db;
use setjoin_mail_security::queue as queue_db;
use setjoin_mail_security::sql as mailsec_sql;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure};
use std::sync::Arc;

pub struct MailSecurityRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    /// Where `POST /admin/tls/import-cert` writes (`<tls.autocert_cache_dir>/imported`).
    pub import_dir: Option<String>,
    /// The user trace's identity hostnames and loopback JMAP base.
    pub trace: crate::mail_security_trace::TraceConfig,
}

impl<K: KeySource + 'static> MailSecurityRoute<K> {
    pub fn new(exec: ScopedExecutor, worker: ScopedExecutor, keys: Arc<K>, issuer: String) -> Self {
        Self {
            exec,
            worker,
            keys,
            issuer,
            import_dir: crate::mail_security_tls::import_dir_from_env(),
            trace: crate::mail_security_trace::TraceConfig::from_env(),
        }
    }
    pub fn with_trace(mut self, trace: crate::mail_security_trace::TraceConfig) -> Self {
        self.trace = trace;
        self
    }
    pub fn with_import_dir(mut self, import_dir: Option<String>) -> Self {
        self.import_dir = import_dir;
        self
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum Action {
    QuarantineUserList,
    QuarantineUserCount,
    QuarantineUserRelease,
    QuarantineUserReject,
    QuarantineAdminList,
    QuarantineAdminStats,
    QuarantineAdminPreview,
    QuarantineAdminRelease,
    QuarantineAdminReject,
    QueueSummary,
    QueueList,
    QueueRetry,
    QueueBounce,
    SpamDashboard,
    SpamReset,
    SpamDisable,
    SpamEnable,
    SendersGet,
    SendersPut,
    SendersNeverBlock,
    ControlGet,
    ControlAction,
    TrustedList,
    TrustedAdd,
    TrustedRemove,
    ExternalGet,
    ExternalPut,
    Report,
    DmarcLive,
    DmarcFailures,
    DmarcTrend,
    AuthLog,
    TlsStatus,
    TlsConfigGet,
    TlsConfigPut,
    TlsImportCert,
    PolicyGet,
    PolicyPut,
    TraceList,
    TraceExport,
    TraceTimeline,
    MessageTrace,
    SmimeList,
    SmimeImport,
    SmimeDelete,
    CertStatus,
    DlpGet,
    DlpPut,
    AntiPhishGet,
    AntiPhishPut,
    LinkAudit,
    ThreatView,
    IpRulesList,
    IpRuleCreate,
    IpRuleDelete,
}

impl Action {
    /// Routes of the `trace` slice, served by `mail_security_trace`.
    fn is_trace(self) -> bool {
        use Action::*;
        matches!(self, TraceList | TraceExport | TraceTimeline | MessageTrace)
    }
    /// Routes of the `smime` slice, served by `mail_security_smime`.
    fn is_smime(self) -> bool {
        use Action::*;
        matches!(self, SmimeList | SmimeImport | SmimeDelete | CertStatus)
    }
    /// Routes of the `dlp` slice, served by `mail_security_dlp`.
    fn is_dlp(self) -> bool {
        use Action::*;
        matches!(
            self,
            DlpGet | DlpPut | AntiPhishGet | AntiPhishPut | LinkAudit
        )
    }
    /// Routes of the `threat` slice, served by `mail_security_threat`.
    fn is_threat(self) -> bool {
        use Action::*;
        matches!(self, ThreatView | IpRulesList | IpRuleCreate | IpRuleDelete)
    }
    /// Routes of the `tls` slice, served by `mail_security_tls`.
    fn is_tls(self) -> bool {
        use Action::*;
        matches!(
            self,
            TlsStatus | TlsConfigGet | TlsConfigPut | TlsImportCert | PolicyGet | PolicyPut
        )
    }
    /// Routes of the `spam` slice, served by `mail_security_spam`.
    fn is_spam(self) -> bool {
        use Action::*;
        matches!(
            self,
            SpamDashboard
                | SpamReset
                | SpamDisable
                | SpamEnable
                | SendersGet
                | SendersPut
                | SendersNeverBlock
                | ControlGet
                | ControlAction
                | TrustedList
                | TrustedAdd
                | TrustedRemove
                | ExternalGet
                | ExternalPut
                | Report
        )
    }
}

/// Method/pattern table; the first column is the method predicate. Later slices append rows.
pub(crate) fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let post = *method == Method::POST;
    let put = *method == Method::PUT;
    let delete = *method == Method::DELETE;
    if let Some(found) = crate::mail_security_smime::action(method, path) {
        return Some(found);
    }
    let table: [(bool, &str, Action); 51] = [
        (reads, "/api/quarantine", Action::QuarantineUserList),
        (reads, "/api/quarantine/count", Action::QuarantineUserCount),
        (
            post,
            "/api/quarantine/{id}/release",
            Action::QuarantineUserRelease,
        ),
        (
            post,
            "/api/quarantine/{id}/reject",
            Action::QuarantineUserReject,
        ),
        (reads, "/api/admin/quarantine", Action::QuarantineAdminList),
        (
            reads,
            "/api/admin/quarantine/stats",
            Action::QuarantineAdminStats,
        ),
        (
            reads,
            "/api/admin/quarantine/{id}/preview",
            Action::QuarantineAdminPreview,
        ),
        (
            post,
            "/api/admin/quarantine/{id}/release",
            Action::QuarantineAdminRelease,
        ),
        (
            post,
            "/api/admin/quarantine/{id}/reject",
            Action::QuarantineAdminReject,
        ),
        (reads, "/api/admin/queue/summary", Action::QueueSummary),
        (reads, "/api/admin/queue", Action::QueueList),
        (post, "/api/admin/queue/{id}/retry", Action::QueueRetry),
        (post, "/api/admin/queue/{id}/bounce", Action::QueueBounce),
        (reads, "/api/admin/spam", Action::SpamDashboard),
        (delete, "/api/admin/spam/models/{userId}", Action::SpamReset),
        (
            post,
            "/api/admin/spam/models/{userId}/disable",
            Action::SpamDisable,
        ),
        (
            post,
            "/api/admin/spam/models/{userId}/enable",
            Action::SpamEnable,
        ),
        (reads, "/api/settings/senders", Action::SendersGet),
        (put, "/api/settings/senders", Action::SendersPut),
        (
            post,
            "/api/settings/senders/never-block",
            Action::SendersNeverBlock,
        ),
        (reads, "/api/settings/sender-control", Action::ControlGet),
        (
            post,
            "/api/settings/sender-control/actions",
            Action::ControlAction,
        ),
        (reads, "/api/settings/trusted-senders", Action::TrustedList),
        (post, "/api/settings/trusted-senders", Action::TrustedAdd),
        (
            delete,
            "/api/settings/trusted-senders/{sender}",
            Action::TrustedRemove,
        ),
        (reads, "/api/settings/external-sender", Action::ExternalGet),
        (put, "/api/settings/external-sender", Action::ExternalPut),
        (post, "/api/report", Action::Report),
        (reads, "/api/admin/dmarc/live", Action::DmarcLive),
        (reads, "/api/admin/dmarc/failures", Action::DmarcFailures),
        (reads, "/api/admin/dmarc/trend", Action::DmarcTrend),
        (reads, "/api/admin/auth-log", Action::AuthLog),
        (reads, "/api/admin/tls/status", Action::TlsStatus),
        (reads, "/api/admin/tls/config", Action::TlsConfigGet),
        (put, "/api/admin/tls/config", Action::TlsConfigPut),
        (post, "/api/admin/tls/import-cert", Action::TlsImportCert),
        (reads, "/api/admin/outbound-tls-policy", Action::PolicyGet),
        (put, "/api/admin/outbound-tls-policy", Action::PolicyPut),
        (reads, "/api/admin/trace", Action::TraceList),
        (reads, "/api/admin/trace/export", Action::TraceExport),
        (reads, "/api/admin/trace/{messageId}", Action::TraceTimeline),
        (reads, "/api/messages/{emailId}/trace", Action::MessageTrace),
        (reads, "/api/admin/dlp/patterns", Action::DlpGet),
        (put, "/api/admin/dlp/patterns", Action::DlpPut),
        (reads, "/api/admin/anti-phish", Action::AntiPhishGet),
        (put, "/api/admin/anti-phish", Action::AntiPhishPut),
        (reads, "/api/admin/link-protect/audit", Action::LinkAudit),
        (reads, "/api/admin/threat/{view}", Action::ThreatView),
        (reads, "/api/admin/threat/ip-rules", Action::IpRulesList),
        (post, "/api/admin/threat/ip-rules", Action::IpRuleCreate),
        (
            delete,
            "/api/admin/threat/ip-rules/{id}",
            Action::IpRuleDelete,
        ),
    ];
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| *action)
}

/// Go sees the `/api`-stripped request path, decoded.
pub(crate) fn segment_path(path: &str) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.strip_prefix("/api").unwrap_or(path),
    ))
}

/// Go's `r.PathValue`: the percent-decoded segment at `index` of the full path.
pub(crate) fn segment(path: &str, index: usize) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.split('/').nth(index).unwrap_or(""),
    ))
}

/// The admin permission set a route's Go middleware requires (any-of); `None` for the
/// authenticated-user routes, whose only gate is `requireAuth`.
fn gate(what: Action) -> Option<&'static [&'static str]> {
    match what {
        Action::QuarantineUserList
        | Action::QuarantineUserCount
        | Action::QuarantineUserRelease
        | Action::QuarantineUserReject
        | Action::SendersGet
        | Action::SendersPut
        | Action::SendersNeverBlock
        | Action::ControlGet
        | Action::ControlAction
        | Action::TrustedList
        | Action::TrustedAdd
        | Action::TrustedRemove
        | Action::ExternalGet
        | Action::ExternalPut
        | Action::MessageTrace
        | Action::Report
        | Action::CertStatus => None,
        Action::SmimeList => Some(&setjoin_mail_security::MAIL_CONSOLE),
        Action::SmimeImport | Action::SmimeDelete => Some(&setjoin_mail_security::MAIL_SECURITY),
        Action::SpamDashboard
        | Action::DmarcLive
        | Action::DmarcFailures
        | Action::DmarcTrend
        | Action::TlsStatus
        | Action::TlsConfigGet
        | Action::PolicyGet
        | Action::DlpGet
        | Action::AntiPhishGet
        | Action::TraceList
        | Action::TraceTimeline => Some(&setjoin_mail_security::MAIL_CONSOLE),
        Action::AuthLog => Some(&setjoin_mail_security::LOGS_CONSOLE),
        Action::TlsConfigPut | Action::TlsImportCert | Action::PolicyPut | Action::AntiPhishPut => {
            Some(&setjoin_mail_security::SECURITY_WRITE)
        }
        Action::DlpPut => Some(&setjoin_mail_security::MAIL_SECURITY),
        Action::LinkAudit => Some(&setjoin_mail_security::LOGS_CONSOLE),
        Action::SpamReset | Action::SpamDisable | Action::SpamEnable => {
            Some(&setjoin_mail_security::SECURITY_WRITE)
        }
        Action::QuarantineAdminList
        | Action::QuarantineAdminStats
        | Action::QueueSummary
        | Action::QueueList => Some(&setjoin_mail_security::MAIL_CONSOLE),
        Action::QueueRetry | Action::QueueBounce => Some(&setjoin_mail_security::QUEUE_WRITE),
        Action::ThreatView | Action::IpRulesList => Some(&setjoin_mail_security::threat::LOGS),
        Action::IpRuleCreate | Action::IpRuleDelete => Some(&setjoin_mail_security::SECURITY_WRITE),
        Action::TraceExport | Action::QuarantineAdminPreview => {
            Some(&setjoin_mail_security::MAIL_EXPORT)
        }
        Action::QuarantineAdminRelease | Action::QuarantineAdminReject => {
            Some(&setjoin_mail_security::SECURITY_WRITE)
        }
    }
}

/// `strconv.ParseInt(text, 10, 64)`.
fn parse_id(text: &str) -> Option<i64> {
    text.parse::<i64>().ok()
}

/// Execute an RBAC-proved cross-tenant `SqlScope::WorkerBypass` boolean reducer
/// on `WorkerPool` (`BYPASSRLS`) with a durable `rust_operation_receipts` row,
/// for FORCE-RLS admin mutations whose frozen-Go parity contract emits no
/// `admin_audit_log` row.
pub(crate) async fn worker_bool_command(
    worker: &ScopedExecutor,
    contract: &'static setjoin_pg::SqlContract,
    args: &[i64],
    cmd: &'static str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let op = setjoin_contracts::ids::OperationId(operation);
    let Some(pool) = worker.try_worker_pool() else {
        return CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable);
    };
    let mut tx = match pool.begin_read_write().await {
        Ok(tx) => tx,
        Err(e) => return CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e)),
    };
    let op_hex = setjoin_pg::operation_hex(op);
    let body: Result<bool, StatementFailure> = async {
        let rows = match args {
            [a] => tx.query_contract(contract, &[a]).await?,
            [a, b] => tx.query_contract(contract, &[a, b]).await?,
            _ => {
                return Err(StatementFailure {
                    sqlstate: None,
                    hint: None,
                    message: "unexpected worker_bool_command arity".into(),
                });
            }
        };
        let ok: bool = rows
            .first()
            .and_then(|r| r.try_get(0).ok())
            .ok_or_else(|| StatementFailure {
                sqlstate: None,
                hint: None,
                message: "invalid mail security result".into(),
            })?;
        tx.execute(
            "INSERT INTO public.rust_operation_receipts(operation_id, family, command) \
             VALUES ($1::text::uuid, $2, $3)",
            &[
                (&op_hex, setjoin_pg::Type::TEXT),
                (&setjoin_mail_security::FAMILY, setjoin_pg::Type::TEXT),
                (&cmd, setjoin_pg::Type::TEXT),
            ],
        )
        .await?;
        Ok(ok)
    }
    .await;
    match body {
        Ok(ok) => match tx.commit().await {
            Ok(()) => CommandOutcome::Committed(ok),
            Err(e) => {
                if let Some(code) = e.sqlstate.as_deref() {
                    if setjoin_pg::commit_failure_observation(Some(code))
                        == setjoin_contracts::command::CommitObservation::RolledBack
                    {
                        return CommandOutcome::RolledBack(setjoin_pg::Rejection::CommitRefused(
                            code.to_owned(),
                        ));
                    }
                }
                CommandOutcome::Unknown { operation: op }
            }
        },
        Err(e) => {
            let _ = tx.rollback().await;
            CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e))
        }
    }
}

impl<K: KeySource + 'static> Intercept for MailSecurityRoute<K> {
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
        let import_dir = self.import_dir.clone();
        let trace = self.trace.clone();
        Box::pin(async move {
            let what = action(r.method(), r.uri().path()).expect("matched route");
            let verdict =
                crate::deny::admit(&exec, &keys, &issuer, &r, crate::deny::Scope::Member).await;
            let auth = match verdict {
                Ok(auth) => auth,
                Err(refusal) => return crate::deny::answer(refusal, r, &c).await,
            };
            let Some(factory) =
                crate::policy_composition::tx_factory_from_executors(&exec, Some(&worker))
            else {
                return bare(503, "service unavailable", &c, "");
            };
            let Some(operation) = crate::jmap::random() else {
                return bare(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let client_ip = c.identity.client_ip.to_string();
            let Ok(user) = factory.mint_user_from_authorized(&auth, &client_ip).await else {
                return bare(500, "database error", &c, &id);
            };
            let mut admin_proof = None;
            if let Some(required) = gate(what) {
                let admin_opt = if auth.context().signed_admin() {
                    factory
                        .mint_admin_from_authorized(&auth, &client_ip)
                        .await
                        .ok()
                } else {
                    None
                };
                let Some(admin) = admin_opt.filter(|admin| admin.allows_any(required)) else {
                    let _ = setjoin_mail_security::console_denied(
                        &factory,
                        &user,
                        &segment_path(r.uri().path()),
                        &required.join("|"),
                        operation,
                    )
                    .await;
                    return bare(403, "Forbidden", &c, &id);
                };
                let domain_scope = admin.enforced_domain_scope().unwrap_or(0);
                if admin.refused_for_scope(required) {
                    let detail = format!(
                        "{} (domain-scoped principal; org-wide-only surface, domain={})",
                        required.join("|"),
                        domain_scope
                    );
                    let _ = setjoin_mail_security::console_denied(
                        &factory,
                        &user,
                        &segment_path(r.uri().path()),
                        &detail,
                        operation,
                    )
                    .await;
                    return bare(403, "Forbidden", &c, &id);
                }
                let Ok(proof) = admin.require_any_permission(required) else {
                    let _ = setjoin_mail_security::console_denied(
                        &factory,
                        &user,
                        &segment_path(r.uri().path()),
                        &required.join("|"),
                        operation,
                    )
                    .await;
                    return bare(403, "Forbidden", &c, &id);
                };
                admin_proof = Some(proof);
            }
            if what.is_smime() {
                return crate::mail_security_smime::handle(
                    what,
                    r,
                    &c,
                    &id,
                    operation,
                    &factory,
                    &user,
                    admin_proof.as_ref(),
                )
                .await;
            }
            if what.is_dlp() {
                let Some(admin) = admin_proof.as_ref() else {
                    return bare(403, "Forbidden", &c, &id);
                };
                return crate::mail_security_dlp::handle(
                    what, r, &c, &id, operation, &factory, &user, admin, &worker,
                )
                .await;
            }
            if what.is_trace() {
                return crate::mail_security_trace::handle(
                    what,
                    r,
                    &c,
                    &id,
                    &factory,
                    &auth,
                    &client_ip,
                    admin_proof.as_ref(),
                    &trace,
                )
                .await;
            }
            if what.is_tls() {
                let Some(admin) = admin_proof.as_ref() else {
                    return bare(403, "Forbidden", &c, &id);
                };
                return crate::mail_security_tls::handle(
                    what,
                    r,
                    &c,
                    &id,
                    operation,
                    &factory,
                    &user,
                    admin,
                    import_dir.as_deref(),
                )
                .await;
            }
            if what.is_threat() {
                let Some(admin) = admin_proof.as_ref() else {
                    return bare(403, "Forbidden", &c, &id);
                };
                return crate::mail_security_threat::handle(
                    what, r, &c, &id, operation, &factory, admin, &worker,
                )
                .await;
            }
            if what.is_spam() {
                return crate::mail_security_spam::handle(
                    what,
                    r,
                    &c,
                    &id,
                    operation,
                    &factory,
                    &auth,
                    &client_ip,
                    &user,
                    admin_proof.as_ref(),
                    &worker,
                )
                .await;
            }
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
            let path = r.uri().path().to_owned();
            // Go's `WriteProblem`: instance is the stripped path, language from the request.
            let problem = |status: u16, detail: &str| {
                crate::mailboxes::render(
                    crate::problem::Problem::new(status, detail).instance(&segment_path(&path)),
                    Some(&crate::mailboxes::language(&r)),
                    &c,
                    &id,
                )
            };
            match what {
                Action::QueueSummary => {
                    let Some(admin) = admin_proof.as_ref() else {
                        return bare(403, "Forbidden", &c, &id);
                    };
                    match queue_db::summary(&factory, admin).await {
                        Ok(body) => reply(body, 200),
                        Err(_) => problem(500, "database error"),
                    }
                }
                Action::QueueList => {
                    let Some(admin) = admin_proof.as_ref() else {
                        return bare(403, "Forbidden", &c, &id);
                    };
                    let mut limit = atoi(&query(r.uri(), "limit").unwrap_or_default());
                    if !(1..=200).contains(&limit) {
                        limit = 50;
                    }
                    let offset =
                        atoi(&query(r.uri(), "offset").unwrap_or_default()).clamp(0, 1_000_000);
                    let status = query(r.uri(), "status").unwrap_or_default();
                    match queue_db::list(&factory, admin, &status, limit, offset).await {
                        Ok(body) => reply(body, 200),
                        Err(_) => problem(500, "database error"),
                    }
                }
                Action::QueueRetry | Action::QueueBounce => {
                    let Some(_admin) = admin_proof.as_ref() else {
                        return bare(403, "Forbidden", &c, &id);
                    };
                    let bounce = what == Action::QueueBounce;
                    let Some(target) = parse_id(&segment(&path, 4)) else {
                        return problem(400, "invalid queue id");
                    };
                    let (cmd, contract) = if bounce {
                        ("queue.bounce", &mailsec_sql::QUEUE_BOUNCE)
                    } else {
                        ("queue.retry", &mailsec_sql::QUEUE_RETRY)
                    };
                    match worker_bool_command(&worker, contract, &[target], cmd, operation).await {
                        CommandOutcome::Committed(true) => {
                            let mut response = crate::jmap::reply::response(
                                String::new(),
                                c.identity.proto,
                                id.clone(),
                            );
                            *response.status_mut() = hyper::StatusCode::NO_CONTENT;
                            response.headers_mut().remove("content-type");
                            response
                        }
                        CommandOutcome::Committed(false) => problem(
                            404,
                            if bounce {
                                "item not found"
                            } else {
                                "item not found or not retriable"
                            },
                        ),
                        CommandOutcome::RolledBack(_) => problem(500, "database error"),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::QuarantineUserList => {
                    let mut limit = atoi(&query(r.uri(), "limit").unwrap_or_default());
                    let offset = atoi(&query(r.uri(), "offset").unwrap_or_default());
                    if !(1..=50).contains(&limit) {
                        limit = 50;
                    }
                    let Ok(mb) = factory
                        .mint_primary_mailbox_from_authorized(&auth, &client_ip)
                        .await
                    else {
                        return bare(500, "database error", &c, &id);
                    };
                    let Ok(cap) = mb.require_read() else {
                        return bare(403, "Forbidden", &c, &id);
                    };
                    match quarantine_db::user_list(&factory, &cap, limit, offset).await {
                        Ok(body) => reply(body, 200),
                        Err(_) => bare(500, "database error", &c, &id),
                    }
                }
                Action::QuarantineUserCount => {
                    reply(quarantine_db::user_count(&factory, &user).await, 200)
                }
                Action::QuarantineUserRelease | Action::QuarantineUserReject => {
                    let reject = what == Action::QuarantineUserReject;
                    let Some(target) = parse_id(&segment(&path, 3)) else {
                        return bare(400, "invalid id", &c, &id);
                    };
                    let Ok(mb) = factory
                        .mint_primary_mailbox_from_authorized(&auth, &client_ip)
                        .await
                    else {
                        return bare(500, "database error", &c, &id);
                    };
                    let Ok(cap) = mb.require_mutate() else {
                        return bare(403, "Forbidden", &c, &id);
                    };
                    match quarantine_db::user_resolve(&factory, &cap, target, reject, operation)
                        .await
                    {
                        CommandOutcome::Committed(true) => reply(
                            quarantine_db::status_body(if reject {
                                "rejected"
                            } else {
                                "released"
                            }),
                            200,
                        ),
                        CommandOutcome::Committed(false) => bare(
                            403,
                            if reject {
                                "not found or already processed"
                            } else {
                                "not found or already released"
                            },
                            &c,
                            &id,
                        ),
                        CommandOutcome::RolledBack(_) => bare(500, "database error", &c, &id),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::QuarantineAdminList => {
                    let Some(admin) = admin_proof.as_ref() else {
                        return bare(403, "Forbidden", &c, &id);
                    };
                    let status = query(r.uri(), "status").unwrap_or_default();
                    let q = query(r.uri(), "q").unwrap_or_default();
                    let mut limit = atoi(&query(r.uri(), "limit").unwrap_or_default());
                    if !(1..=100).contains(&limit) {
                        limit = 50;
                    }
                    let offset =
                        atoi(&query(r.uri(), "offset").unwrap_or_default()).clamp(0, 1_000_000);
                    match quarantine_db::admin_list(&factory, admin, &status, &q, limit, offset)
                        .await
                    {
                        Ok(body) => reply(body, 200),
                        Err(_) => bare(500, "database error", &c, &id),
                    }
                }
                Action::QuarantineAdminStats => {
                    let Some(admin) = admin_proof.as_ref() else {
                        return bare(403, "Forbidden", &c, &id);
                    };
                    reply(quarantine_db::admin_stats(&factory, admin).await, 200)
                }
                Action::QuarantineAdminPreview => {
                    let Some(admin) = admin_proof.as_ref() else {
                        return bare(403, "Forbidden", &c, &id);
                    };
                    let Some(target) = parse_id(&segment(&path, 4)) else {
                        return bare(400, "invalid id", &c, &id);
                    };
                    match quarantine_db::admin_preview(&factory, admin, target).await {
                        Ok(Some(body)) => reply(body, 200),
                        Ok(None) => bare(404, "not found", &c, &id),
                        Err(_) => bare(500, "database error", &c, &id),
                    }
                }
                Action::QuarantineAdminRelease | Action::QuarantineAdminReject => {
                    let Some(admin) = admin_proof.as_ref() else {
                        return bare(403, "Forbidden", &c, &id);
                    };
                    let reject = what == Action::QuarantineAdminReject;
                    let Some(target) = parse_id(&segment(&path, 4)) else {
                        return bare(400, "invalid id", &c, &id);
                    };
                    let (cmd, contract) = if reject {
                        ("quarantine.reject", &mailsec_sql::QUARANTINE_ADMIN_REJECT)
                    } else {
                        ("quarantine.release", &mailsec_sql::QUARANTINE_ADMIN_RELEASE)
                    };
                    match worker_bool_command(
                        &worker,
                        contract,
                        &[admin.actor().get(), target],
                        cmd,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(true) => reply(
                            quarantine_db::status_body(if reject {
                                "rejected"
                            } else {
                                "released"
                            }),
                            200,
                        ),
                        CommandOutcome::Committed(false) => {
                            bare(404, "not found or already processed", &c, &id)
                        }
                        CommandOutcome::RolledBack(_) => bare(500, "database error", &c, &id),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::DmarcLive => {
                    let Some(admin) = admin_proof.as_ref() else {
                        return bare(403, "Forbidden", &c, &id);
                    };
                    reply(dmarc_db::live(&factory, admin).await, 200)
                }
                Action::DmarcFailures => {
                    let Some(admin) = admin_proof.as_ref() else {
                        return bare(403, "Forbidden", &c, &id);
                    };
                    let mut limit = atoi(&query(r.uri(), "limit").unwrap_or_default());
                    if !(1..=200).contains(&limit) {
                        limit = 100;
                    }
                    match dmarc_db::failures(&factory, admin, limit).await {
                        Ok(body) => reply(body, 200),
                        Err(_) => bare(500, "database error", &c, &id),
                    }
                }
                Action::DmarcTrend => {
                    let Some(admin) = admin_proof.as_ref() else {
                        return bare(403, "Forbidden", &c, &id);
                    };
                    match dmarc_db::trend(&factory, admin).await {
                        Ok(body) => reply(body, 200),
                        Err(_) => bare(500, "database error", &c, &id),
                    }
                }
                Action::AuthLog => {
                    let Some(admin) = admin_proof.as_ref() else {
                        return bare(403, "Forbidden", &c, &id);
                    };
                    let get = |name: &str| query(r.uri(), name).unwrap_or_default();
                    match dmarc_db::auth_log(
                        &factory,
                        admin,
                        &get("provider"),
                        &get("event"),
                        &get("since"),
                        &get("email"),
                        &get("limit"),
                    )
                    .await
                    {
                        Ok(body) => reply(body, 200),
                        Err(_) => bare(500, "query failed", &c, &id),
                    }
                }
                _ => unreachable!("spam and tls actions return above"),
            }
        })
    }
}
