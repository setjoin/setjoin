//! F05 Exchange replacement HTTP adapter (#294).
use crate::{Body, BoxFuture, Intercept, RequestContext};
#[path = "exchange_input.rs"]
mod input;
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use setjoin_pg::{CommandOutcome, Rejection};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub struct ExchangeRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    pub artifacts: Artifacts,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Registry,
    Projects,
    Runs,
    CreateProject,
    CreateRun,
    Transition,
    Attestation,
    Decision,
    Resolve,
    Delete,
    Audit,
    Bundle,
    Publish,
}
fn action(method: &Method, path: &str) -> Option<Action> {
    if *method == Method::POST && path == "/api/admin/exchange-replacement/projects" {
        return Some(Action::CreateProject);
    }
    if *method == Method::POST
        && crate::inventory::path_score(
            "/api/admin/exchange-replacement/projects/{projectId}/runs",
            path,
        )
        .is_some()
    {
        return Some(Action::CreateRun);
    }
    if *method == Method::POST
        && crate::inventory::path_score(
            "/api/admin/exchange-replacement/runs/{runId}/transition",
            path,
        )
        .is_some()
    {
        return Some(Action::Transition);
    }
    if *method == Method::POST
        && crate::inventory::path_score(
            "/api/admin/exchange-replacement/runs/{runId}/attestations",
            path,
        )
        .is_some()
    {
        return Some(Action::Attestation);
    }
    if *method == Method::POST
        && crate::inventory::path_score(
            "/api/admin/exchange-replacement/runs/{runId}/decisions",
            path,
        )
        .is_some()
    {
        return Some(Action::Decision);
    }
    if *method == Method::POST
        && crate::inventory::path_score(
            "/api/admin/exchange-replacement/runs/{runId}/claims/resolve",
            path,
        )
        .is_some()
    {
        return Some(Action::Resolve);
    }
    if *method == Method::POST
        && crate::inventory::path_score(
            "/api/admin/exchange-replacement/projects/{projectId}/deletions",
            path,
        )
        .is_some()
    {
        return Some(Action::Delete);
    }
    if *method == Method::POST
        && crate::inventory::path_score(
            "/api/admin/exchange-replacement/runs/{runId}/publications",
            path,
        )
        .is_some()
    {
        return Some(Action::Publish);
    }
    if *method == Method::PUT
        && crate::inventory::path_score("/api/admin/exchange-replacement/runs/{runId}/bundle", path)
            .is_some()
    {
        return Some(Action::Bundle);
    }
    if !matches!(*method, Method::GET | Method::HEAD) {
        return None;
    }
    [
        (
            "/api/admin/exchange-replacement/runs/{runId}/audit",
            Action::Audit,
        ),
        ("/api/admin/exchange-replacement/registry", Action::Registry),
        ("/api/admin/exchange-replacement/projects", Action::Projects),
        (
            "/api/admin/exchange-replacement/projects/{projectId}/runs",
            Action::Runs,
        ),
    ]
    .into_iter()
    .find(|(pattern, _)| crate::inventory::path_score(pattern, path).is_some())
    .map(|(_, action)| action)
}
impl<K: KeySource + 'static> Intercept for ExchangeRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        action(r.method(), r.uri().path()).is_some()
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
        let artifacts = self.artifacts.clone();
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
            let Some(operation) = crate::jmap::random() else {
                return crate::mailboxes::bare(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let Ok(authority) = setjoin_mailboxes::authority(&exec, auth.context()).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let what = action(r.method(), r.uri().path()).expect("matched route");
            let permission = if what == Action::Publish {
                "exchange.assessment.publish"
            } else if what == Action::Delete {
                "exchange.assessment.delete"
            } else if matches!(what, Action::Resolve | Action::Audit) {
                "exchange.assessment.audit"
            } else if what == Action::Decision {
                "exchange.assessment.decide"
            } else if what == Action::Attestation {
                "exchange.assessment.attest"
            } else if matches!(
                what,
                Action::CreateProject | Action::CreateRun | Action::Transition | Action::Bundle
            ) {
                "exchange.assessment.run"
            } else {
                "exchange.assessment.read"
            };
            if !authority.allows_any(&[permission]) {
                let _ = setjoin_mailboxes::console_denied(
                    &exec,
                    auth.context(),
                    r.uri()
                        .path()
                        .strip_prefix("/api")
                        .unwrap_or(r.uri().path()),
                    permission,
                    operation,
                )
                .await;
                return crate::mailboxes::bare(403, "Forbidden", &c, &id);
            }
            if !matches!(
                what,
                Action::Registry | Action::Projects | Action::Runs | Action::Audit
            ) && setjoin_mailboxes::exchange::reason_required(&exec).await
                && r.headers()
                    .get("x-audit-reason")
                    .is_none_or(|v| v.as_bytes().is_empty())
            {
                setjoin_mailboxes::exchange::missing_reason(
                    &exec,
                    auth.context(),
                    &c.identity.client_ip.to_string(),
                    permission,
                    operation,
                )
                .await;
                return crate::mailboxes::bare(400, "reason_required", &c, &id);
            }
            let path = crate::guests_input::go_utf8(&crate::inventory::unescape(
                r.uri()
                    .path()
                    .strip_prefix("/api")
                    .unwrap_or(r.uri().path()),
            ));
            let lang = language(r.headers());
            let problem = |status, detail: &str| {
                crate::mailboxes::render(
                    crate::problem::Problem::new(status, detail).instance(&path),
                    Some(&lang),
                    &c,
                    &id,
                )
            };
            if what == Action::Publish {
                if !fresh_aal2(&auth) {
                    return problem(403, "fresh AAL2 authority is required");
                }
                return publish(r, auth.context(), &worker, &artifacts, operation, &c, &id).await;
            }
            if what == Action::Bundle {
                if !fresh_aal2(&auth) {
                    return problem(403, "fresh AAL2 authority is required");
                }
                return bundle(r, auth.context(), &worker, &artifacts, operation, &c, &id).await;
            }
            if matches!(
                what,
                Action::CreateProject
                    | Action::CreateRun
                    | Action::Transition
                    | Action::Attestation
                    | Action::Decision
                    | Action::Resolve
                    | Action::Delete
            ) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let amr: std::collections::BTreeSet<_> = auth
                    .amr()
                    .iter()
                    .filter(|s| !s.is_empty())
                    .map(String::as_str)
                    .collect();
                if auth.acr() != "aal2"
                    || auth.token_id().is_empty()
                    || auth.issued_at() > now + 30
                    || now - auth.issued_at() > 300
                    || amr.len() > 16
                    || !amr.contains("mfa")
                    || amr
                        .iter()
                        .filter(|m| matches!(**m, "pwd" | "otp" | "hwk" | "swk"))
                        .count()
                        < 2
                {
                    return problem(403, "fresh AAL2 authority is required");
                }
                let project = if matches!(what, Action::CreateRun | Action::Delete) {
                    match crate::mailboxes::segment(r.uri().path(), 5).parse::<i64>() {
                        Ok(v) => v,
                        Err(_) => return problem(400, "invalid project id"),
                    }
                } else {
                    0
                };
                let run = if matches!(
                    what,
                    Action::Transition | Action::Attestation | Action::Decision | Action::Resolve
                ) {
                    match crate::mailboxes::segment(r.uri().path(), 5).parse::<i64>() {
                        Ok(v) => v,
                        Err(_) => return problem(400, "invalid run id"),
                    }
                } else {
                    0
                };
                let schema = if what == Action::CreateProject {
                    vec![
                        ("domainId", input::Kind::Int),
                        ("name", input::Kind::Text),
                        ("retentionUntil", input::Kind::OptionalText),
                    ]
                } else if what == Action::CreateRun {
                    vec![
                        ("supportCellId", input::Kind::Text),
                        ("supportCellDigest", input::Kind::Text),
                        ("registryVersion", input::Kind::Int),
                        ("registryDigest", input::Kind::Text),
                        ("catalogVersion", input::Kind::Int),
                        ("collectorVersion", input::Kind::Text),
                    ]
                } else if what == Action::Transition {
                    vec![
                        ("expectedGeneration", input::Kind::Int),
                        ("state", input::Kind::Text),
                        ("errorCode", input::Kind::OptionalText),
                    ]
                } else if what == Action::Attestation {
                    vec![
                        ("kind", input::Kind::Text),
                        ("subjectDigest", input::Kind::Text),
                        ("statement", input::Kind::Json),
                    ]
                } else if what == Action::Decision {
                    vec![
                        ("expectedGeneration", input::Kind::Int),
                        ("capabilityId", input::Kind::Text),
                        ("outcomeMapping", input::Kind::Text),
                        ("decision", input::Kind::Text),
                        ("reason", input::Kind::Text),
                        ("waiverExpiresAt", input::Kind::OptionalText),
                    ]
                } else if what == Action::Resolve {
                    vec![("expectedGeneration", input::Kind::Int)]
                } else {
                    vec![
                        ("scope", input::Kind::Text),
                        ("runId", input::Kind::OptionalInt),
                        ("artifactId", input::Kind::OptionalInt),
                        ("reason", input::Kind::Text),
                    ]
                };
                let fields = match input::read(&mut r, &schema).await {
                    Ok(v) => v,
                    Err(detail) => return problem(400, &detail),
                };
                let key = r
                    .headers()
                    .get("idempotency-key")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if matches!(what, Action::CreateProject | Action::CreateRun)
                    && (key.len() != 36
                        || key.bytes().enumerate().any(|(i, b)| {
                            if matches!(i, 8 | 13 | 18 | 23) {
                                b != b'-'
                            } else {
                                !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b)
                            }
                        }))
                {
                    return problem(400, "Idempotency-Key must be one canonical UUID");
                }
                let digest = format!("{:x}", Sha256::digest(fields.canonical().as_bytes()));
                let outcome = if what == Action::CreateProject {
                    setjoin_mailboxes::exchange::create_project(
                        &worker,
                        auth.context(),
                        key,
                        &digest,
                        fields.int("domainId"),
                        fields.text("name"),
                        fields.optional_text("retentionUntil"),
                        operation,
                    )
                    .await
                } else if what == Action::CreateRun {
                    setjoin_mailboxes::exchange::create_run(
                        &worker,
                        auth.context(),
                        &setjoin_mailboxes::exchange::CreateRun {
                            project,
                            key,
                            digest: &digest,
                            cell: fields.text("supportCellId"),
                            cell_digest: fields.text("supportCellDigest"),
                            registry: fields.int("registryVersion"),
                            registry_digest: fields.text("registryDigest"),
                            catalog: fields.int("catalogVersion"),
                            collector: fields.text("collectorVersion"),
                        },
                        operation,
                    )
                    .await
                } else if what == Action::Transition {
                    setjoin_mailboxes::exchange::transition(
                        &worker,
                        auth.context(),
                        run,
                        fields.int("expectedGeneration"),
                        fields.text("state"),
                        fields.optional_text("errorCode"),
                        operation,
                    )
                    .await
                } else if what == Action::Attestation {
                    setjoin_mailboxes::exchange::attest(
                        &worker,
                        auth.context(),
                        run,
                        fields.text("kind"),
                        fields.text("subjectDigest"),
                        fields.raw_json("statement"),
                        operation,
                    )
                    .await
                } else if what == Action::Decision {
                    setjoin_mailboxes::exchange::decide(
                        &worker,
                        auth.context(),
                        &setjoin_mailboxes::exchange::Decision {
                            run,
                            generation: fields.int("expectedGeneration"),
                            capability: fields.text("capabilityId"),
                            mapping: fields.text("outcomeMapping"),
                            decision: fields.text("decision"),
                            reason: fields.text("reason"),
                            expires: fields.optional_text("waiverExpiresAt"),
                        },
                        operation,
                    )
                    .await
                } else if what == Action::Resolve {
                    setjoin_mailboxes::exchange::resolve(
                        &worker,
                        auth.context(),
                        run,
                        fields.int("expectedGeneration"),
                        operation,
                    )
                    .await
                } else {
                    setjoin_mailboxes::exchange::request_deletion(
                        &worker,
                        auth.context(),
                        &setjoin_mailboxes::exchange::Deletion {
                            project,
                            scope: fields.text("scope"),
                            run: fields.optional_int("runId"),
                            artifact: fields.optional_int("artifactId"),
                            reason: fields.text("reason"),
                        },
                        operation,
                    )
                    .await
                };
                match outcome {
                    CommandOutcome::Committed(raw) => {
                        let mut response = json_reply(&raw, r.method() == Method::HEAD, &c, id);
                        *response.status_mut() = if what == Action::Delete {
                            hyper::StatusCode::ACCEPTED
                        } else if matches!(what, Action::Transition | Action::Decision) {
                            hyper::StatusCode::OK
                        } else {
                            hyper::StatusCode::CREATED
                        };
                        return response;
                    }
                    CommandOutcome::Unknown { operation } => {
                        return crate::mailboxes::unknown_outcome(operation, &c, &id)
                    }
                    CommandOutcome::RolledBack(error) => {
                        return refusal(&error, &path, &c, &id, &lang)
                    }
                }
            }
            if what == Action::Audit && !fresh_aal2(&auth) {
                return problem(403, "fresh AAL2 authority is required");
            }
            let result = match what {
                Action::Bundle | Action::Publish => unreachable!(),
                Action::Audit => {
                    let Ok(run) = crate::mailboxes::segment(r.uri().path(), 5).parse::<i64>()
                    else {
                        return problem(400, "invalid run id");
                    };
                    setjoin_mailboxes::exchange::audit(&worker, run, authority.domain_scope()).await
                }
                Action::CreateProject
                | Action::CreateRun
                | Action::Transition
                | Action::Attestation
                | Action::Decision
                | Action::Resolve
                | Action::Delete => unreachable!(),
                Action::Registry => setjoin_mailboxes::exchange::registry(&worker).await,
                Action::Projects => {
                    setjoin_mailboxes::exchange::projects(&worker, authority.domain_scope()).await
                }
                Action::Runs => {
                    let Ok(project) = crate::mailboxes::segment(r.uri().path(), 5).parse::<i64>()
                    else {
                        return crate::mailboxes::render(
                            crate::problem::Problem::new(400, "invalid project id").instance(
                                r.uri()
                                    .path()
                                    .strip_prefix("/api")
                                    .unwrap_or(r.uri().path()),
                            ),
                            Some(&lang),
                            &c,
                            &id,
                        );
                    };
                    setjoin_mailboxes::exchange::runs(&worker, project, authority.domain_scope())
                        .await
                }
            };
            match result {
                Ok(raw) => json_reply(&raw, r.method() == Method::HEAD, &c, id),
                Err(_) => crate::mailboxes::render(
                    crate::problem::Problem::new(500, "database error").instance(
                        r.uri()
                            .path()
                            .strip_prefix("/api")
                            .unwrap_or(r.uri().path()),
                    ),
                    Some(&lang),
                    &c,
                    &id,
                ),
            }
        })
    }
}

fn json_reply(raw: &str, head: bool, c: &RequestContext, id: String) -> Response<Body> {
    let body = setjoin_mailboxes::go_escape(&setjoin_mailboxes::migration::compact(raw)) + "\n";
    let large_head = body.len() > 2048 && head;
    let chunked = body.len() > 2048 && !head;
    let mut response = crate::jmap::reply::response(body, c.identity.proto, id);
    if large_head {
        use http_body_util::BodyExt;
        // Go's net/http only infers Content-Length for its small write buffer.
        // An unknown-length empty body keeps large HEAD responses header-identical.
        *response.body_mut() = http_body_util::StreamBody::new(futures_util::stream::empty::<
            Result<hyper::body::Frame<bytes::Bytes>, std::convert::Infallible>,
        >())
        .map_err(|never|match never {})
        .boxed();
    }
    if chunked {
        response.headers_mut().insert(
            "transfer-encoding",
            hyper::header::HeaderValue::from_static("chunked"),
        );
    }
    response
}
fn refusal(
    error: &Rejection<setjoin_pg::StatementFailure>,
    path: &str,
    c: &RequestContext,
    id: &str,
    lang: &str,
) -> Response<Body> {
    let code = match error {
        Rejection::Body(e) | Rejection::Statement(e) => e.sqlstate.as_deref(),
        _ => None,
    };
    let (status, detail, remediation) = match code {
        Some("BZ316") => (
            400,
            "invalidArguments",
            "Correct the request fields and retry.",
        ),
        Some("BZ317") => (
            404,
            "notFound",
            "Refresh the target identifier and retry only if the resource still exists.",
        ),
        Some("BZ318" | "BZ319") => (
            409,
            "conflict",
            "Refresh current state, resolve the conflict, and retry.",
        ),
        Some("BZ320") => (
            422,
            "unprocessable",
            "Correct the requested operation using the documented runbook and retry.",
        ),
        _ => {
            return crate::mailboxes::render(
                crate::problem::Problem::new(500, "request failed").instance(path),
                Some(lang),
                c,
                id,
            )
        }
    };
    let kind = format!(
        "https://setjoin.com/problems/reducer/{}",
        code.unwrap().to_lowercase()
    );
    crate::mailboxes::render(
        crate::problem::Problem::new(status, detail)
            .instance(path)
            .kind(&kind)
            .code(code.unwrap())
            .retryable(false)
            .remediation(remediation),
        Some(lang),
        c,
        id,
    )
}

fn fresh_aal2(auth: &setjoin_authz::Authorized) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let amr: std::collections::BTreeSet<_> = auth
        .amr()
        .iter()
        .filter(|s| !s.is_empty())
        .map(String::as_str)
        .collect();
    auth.acr() == "aal2"
        && !auth.token_id().is_empty()
        && auth.issued_at() <= now + 30
        && now - auth.issued_at() <= 300
        && amr.len() <= 16
        && amr.contains("mfa")
        && amr
            .iter()
            .filter(|m| matches!(**m, "pwd" | "otp" | "hwk" | "swk"))
            .count()
            >= 2
}

fn language(headers: &hyper::HeaderMap) -> String {
    let tag = headers
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split([',', ';'])
        .next()
        .unwrap_or("")
        .trim();
    let mut parts = tag.split('-');
    let first = parts.next().unwrap_or("");
    if (1..=8).contains(&first.len())
        && first.bytes().all(|b| b.is_ascii_alphabetic())
        && parts.all(|p| (1..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        tag.into()
    } else {
        "en".into()
    }
}

#[derive(Clone)]
pub struct Artifacts {
    pub store: Option<Arc<dyn crate::recovery_worker::ObjectStore>>,
    pub signer: Option<Arc<setjoin_mailboxes::exchange_artifact::ReceiptSigner>>,
    pub master: String,
    pub profile: setjoin_mailboxes::exchange_artifact::Profile,
}
impl Default for Artifacts {
    fn default() -> Self {
        Self {
            signer: None,
            store: None,
            master: String::new(),
            profile: setjoin_mailboxes::exchange_artifact::Profile::Standard,
        }
    }
}
#[allow(clippy::too_many_arguments)]
async fn bundle(
    mut r: Request<Body>,
    actor: &setjoin_authz::AuthContext,
    worker: &ScopedExecutor,
    artifacts: &Artifacts,
    operation: [u8; 16],
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    use http_body_util::BodyExt;
    use setjoin_mailboxes::{exchange as db, exchange_artifact as crypto};
    let path = crate::guests_input::go_utf8(&crate::inventory::unescape(
        r.uri()
            .path()
            .strip_prefix("/api")
            .unwrap_or(r.uri().path()),
    ));
    let lang = language(r.headers());
    let problem = |status, detail: &str| {
        crate::mailboxes::render(
            crate::problem::Problem::new(status, detail).instance(&path),
            Some(&lang),
            c,
            id,
        )
    };
    let Some(store) = artifacts
        .store
        .as_ref()
        .filter(|_| artifacts.master.len() >= 32)
    else {
        return problem(503, "assessment artifact storage is unavailable");
    };
    let Ok(run) = crate::mailboxes::segment(r.uri().path(), 5).parse::<i64>() else {
        return problem(400, "invalid run id");
    };
    let Some(generation) = r
        .headers()
        .get("x-run-generation")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|g| *g > 0)
    else {
        return problem(400, "X-Run-Generation must be a positive integer");
    };
    let declared = r
        .headers()
        .get("x-content-sha256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    if declared.len() != 64 || !declared.bytes().all(|b| b.is_ascii_hexdigit()) {
        return problem(400, "X-Content-SHA256 is required");
    }
    let Some(ctx) = db::upload_context(worker, actor.user_id(), run)
        .await
        .ok()
        .flatten()
    else {
        return problem(404, "assessment run not found");
    };
    match db::bundle_replay(worker, run, &declared, ctx.generation).await {
        Ok(Some(raw)) => return json_reply(&raw, false, c, id.into()),
        Ok(None) => {}
        Err(_) => return problem(500, "database error"),
    }
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        let Ok(frame) = frame else {
            return problem(400, "bundle could not be read");
        };
        if let Ok(data) = frame.into_data() {
            if data.len() > (64usize << 20).saturating_sub(bytes.len()) {
                return problem(413, "bundle exceeds 64 MiB");
            }
            bytes.extend_from_slice(&data);
        }
    }
    if bytes.is_empty() {
        return problem(400, "bundle is empty");
    }
    if format!("{:x}", Sha256::digest(&bytes)) != declared {
        return problem(400, "bundle digest mismatch");
    }
    let binding = crypto::Binding {
        installation_id: &ctx.installation,
        tenant_id: ctx.domain,
        project_id: ctx.project,
        kind: "exchange-assessment-bundle",
        plain_sha256: &declared,
    };
    let Ok(sealed) = crypto::seal(
        &bytes,
        artifacts.master.as_bytes(),
        artifacts.profile,
        binding,
    ) else {
        return problem(500, "artifact encryption failed");
    };
    let Some(mut uuid) = crate::jmap::random() else {
        return problem(500, "artifact encryption failed");
    };
    uuid[6] = (uuid[6] & 15) | 64;
    uuid[8] = (uuid[8] & 63) | 128;
    let hex = setjoin_pg::operation_hex(setjoin_contracts::ids::OperationId(uuid));
    let object_id = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    );
    let key = format!(
        "exchange-assessment/{}/{}/{}/{object_id}.sjae",
        ctx.domain, ctx.project, run
    );
    if store
        .put(
            &key,
            &sealed.bytes,
            "application/vnd.setjoin.exchange-artifact+json",
        )
        .await
        .is_err()
    {
        return problem(503, "artifact storage write failed");
    }
    let commit = db::BundleCommit {
        run,
        generation,
        sha: &declared,
        key: &key,
        profile: artifacts.profile.name(),
        sealed: &sealed,
        retention: ctx.retention.as_deref(),
    };
    match db::commit_bundle(worker, actor, &commit, operation).await {
        CommandOutcome::Committed(raw) => {
            let mut response = json_reply(&raw, false, c, id.into());
            *response.status_mut() = hyper::StatusCode::CREATED;
            response
        }
        CommandOutcome::Unknown { operation } => {
            crate::mailboxes::unknown_outcome(operation, c, id)
        }
        CommandOutcome::RolledBack(error) => {
            let _ = store.remove(&key).await;
            refusal(&error, &path, c, id, &lang)
        }
    }
}

/// Same continuity file contract as recovery's verifier, retaining the signer.
pub fn signer_from_env(
) -> Result<Option<Arc<setjoin_mailboxes::exchange_artifact::ReceiptSigner>>, String> {
    use base64::Engine;
    let Some(path) = std::env::var_os("CONTINUITY_SIGNING_KEY_FILE") else {
        return Ok(None);
    };
    let path = std::path::Path::new(&path);
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err("continuity key must be a clean absolute path".into());
    }
    let pem = zeroize::Zeroizing::new(
        std::fs::read_to_string(path).map_err(|e| format!("continuity key: {e}"))?,
    );
    let encoded = pem
        .strip_prefix("-----BEGIN PRIVATE KEY-----\n")
        .and_then(|p| p.strip_suffix("-----END PRIVATE KEY-----\n"))
        .ok_or("continuity key must be one PKCS#8 PEM block")?;
    let der = zeroize::Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(encoded.split_whitespace().collect::<String>())
            .map_err(|_| "invalid continuity key")?,
    );
    let id = std::env::var("CONTINUITY_SIGNING_KEY_ID").unwrap_or_default();
    Ok(Some(Arc::new(
        setjoin_mailboxes::exchange_artifact::ReceiptSigner::from_pkcs8(&der, &id)
            .map_err(|_| "invalid continuity Ed25519 key or ID")?,
    )))
}
#[allow(clippy::too_many_arguments)]
async fn publish(
    mut r: Request<Body>,
    actor: &setjoin_authz::AuthContext,
    worker: &ScopedExecutor,
    artifacts: &Artifacts,
    operation: [u8; 16],
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    use setjoin_mailboxes::{exchange as db, exchange_artifact as crypto};
    let path = crate::guests_input::go_utf8(&crate::inventory::unescape(
        r.uri()
            .path()
            .strip_prefix("/api")
            .unwrap_or(r.uri().path()),
    ));
    let lang = language(r.headers());
    let problem = |status, detail: &str| {
        crate::mailboxes::render(
            crate::problem::Problem::new(status, detail).instance(&path),
            Some(&lang),
            c,
            id,
        )
    };
    let Ok(run) = crate::mailboxes::segment(r.uri().path(), 5).parse::<i64>() else {
        return problem(400, "invalid run id");
    };
    let fields = match input::read(&mut r, &[("projectionDigest", input::Kind::Text)]).await {
        Ok(v) => v,
        Err(e) => return problem(400, &e),
    };
    let digest = fields.text("projectionDigest");
    let (Some(store), Some(signer)) = (
        artifacts
            .store
            .as_ref()
            .filter(|_| artifacts.master.len() >= 32),
        artifacts.signer.as_ref(),
    ) else {
        return problem(503, "signed publication storage is unavailable");
    };
    let Some(ctx) = db::publication_context(worker, actor.user_id(), run)
        .await
        .ok()
        .flatten()
    else {
        return problem(404, "assessment run not found");
    };
    match db::publication_replay(worker, run, digest).await {
        Ok(Some(raw)) => return json_reply(&raw, false, c, id.into()),
        Ok(None) => {}
        Err(_) => return problem(500, "database error"),
    }
    let issued_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let subject = crypto::ReceiptSubject {
        kind: "publication",
        sha256: digest,
        installation: &ctx.installation,
        tenant: ctx.domain,
        project: ctx.project,
        disposition: "published_evidence_snapshot",
    };
    let Ok(receipt) = signer.sign(subject, &issued_at) else {
        return problem(503, "publication receipt signing is unavailable");
    };
    let sha = format!("{:x}", Sha256::digest(receipt.bytes.as_bytes()));
    let binding = crypto::Binding {
        installation_id: &ctx.installation,
        tenant_id: ctx.domain,
        project_id: ctx.project,
        kind: "exchange-assessment-receipt",
        plain_sha256: &sha,
    };
    let Ok(sealed) = crypto::seal(
        receipt.bytes.as_bytes(),
        artifacts.master.as_bytes(),
        artifacts.profile,
        binding,
    ) else {
        return problem(500, "publication receipt encryption failed");
    };
    let Some(mut uuid) = crate::jmap::random() else {
        return problem(500, "publication receipt encryption failed");
    };
    uuid[6] = (uuid[6] & 15) | 64;
    uuid[8] = (uuid[8] & 63) | 128;
    let hex = setjoin_pg::operation_hex(setjoin_contracts::ids::OperationId(uuid));
    let object_id = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    );
    let key = format!(
        "exchange-assessment/{}/{}/{}/receipts/{object_id}.sjae",
        ctx.domain, ctx.project, run
    );
    if store
        .put(
            &key,
            &sealed.bytes,
            "application/vnd.setjoin.exchange-artifact+json",
        )
        .await
        .is_err()
    {
        return problem(503, "publication receipt storage failed");
    }
    let commit = db::BundleCommit {
        run,
        generation: ctx.generation,
        sha: &sha,
        key: &key,
        profile: artifacts.profile.name(),
        sealed: &sealed,
        retention: None,
    };
    match db::publish(worker, actor, &commit, digest, &receipt, operation).await {
        CommandOutcome::Committed(raw) => {
            let mut response = json_reply(&raw, false, c, id.into());
            *response.status_mut() = hyper::StatusCode::CREATED;
            response
        }
        CommandOutcome::Unknown { operation } => {
            crate::mailboxes::unknown_outcome(operation, c, id)
        }
        CommandOutcome::RolledBack(error) => {
            let _ = store.remove(&key).await;
            refusal(&error, &path, c, id, &lang)
        }
    }
}
