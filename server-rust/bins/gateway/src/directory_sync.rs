//! F02 HTTP adapter: the database-backed AD administration routes (slice 1) and
//! the two worker-independent LDAP reads (slice 2, #284).
//!
//! The LDAP runtime routes (#380) and the four AD runtime routes (#381) are served
//! here when the matching runtime is configured; otherwise they forward to Go.
use crate::directory_sync_input as input;
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_directory_sync::Source;
use setjoin_pg::{CommandOutcome, Rejection, ScopedExecutor};
use std::sync::Arc;

pub struct DirectorySyncRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    /// LDAP runtime (#380): present when Rust owns the LDAP routes and worker;
    /// without it the five runtime routes forward to Go untouched.
    pub ldap: Option<Arc<setjoin_directory_sync::ldap::runtime::LdapRuntime>>,
    /// AD runtime (#381): present when Rust owns the four AD runtime routes and
    /// the `ad-sync` worker; without it they forward to Go untouched.
    pub ad: Option<Arc<setjoin_directory_sync::ad::AdRuntime>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Config,
    SyncLog,
    LdapConfig,
    LdapSyncLog,
    Conflicts,
    Resolve,
    ResolveAll,
    FieldPolicyGet,
    FieldPolicySet,
    Principal,
    LdapPut,
    LdapTest,
    LdapPreview,
    LdapSync,
    LdapHealth,
    AdPut,
    AdTest,
    AdSync,
    AdHealth,
}

fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let table: [(bool, &str, Action); 19] = [
        (
            *method == Method::PUT,
            "/api/admin/ldap/config",
            Action::LdapPut,
        ),
        (
            *method == Method::POST,
            "/api/admin/ldap/test-connection",
            Action::LdapTest,
        ),
        (reads, "/api/admin/ldap/preview", Action::LdapPreview),
        (
            *method == Method::POST,
            "/api/admin/ldap/sync",
            Action::LdapSync,
        ),
        (reads, "/api/admin/ldap/health", Action::LdapHealth),
        (reads, "/api/admin/ldap/config", Action::LdapConfig),
        (reads, "/api/admin/ldap/sync-log", Action::LdapSyncLog),
        (reads, "/api/admin/ad/config", Action::Config),
        (
            *method == Method::PUT,
            "/api/admin/ad/config",
            Action::AdPut,
        ),
        (
            *method == Method::POST,
            "/api/admin/ad/test-connection",
            Action::AdTest,
        ),
        (
            *method == Method::POST,
            "/api/admin/ad/sync",
            Action::AdSync,
        ),
        (reads, "/api/admin/ad/health", Action::AdHealth),
        (reads, "/api/admin/ad/sync-log", Action::SyncLog),
        (reads, "/api/admin/ad/conflicts", Action::Conflicts),
        (
            *method == Method::POST,
            "/api/admin/ad/conflicts/{id}/resolve",
            Action::Resolve,
        ),
        (
            *method == Method::POST,
            "/api/admin/ad/conflicts/resolve-all",
            Action::ResolveAll,
        ),
        (reads, "/api/admin/ad/field-policy", Action::FieldPolicyGet),
        (
            *method == Method::PUT,
            "/api/admin/ad/field-policy",
            Action::FieldPolicySet,
        ),
        (
            *method == Method::POST,
            "/api/admin/ad/principal",
            Action::Principal,
        ),
    ];
    // Go's mux prefers the literal resolve-all over the {id} wildcard.
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| *action)
}

impl<K: KeySource + 'static> Intercept for DirectorySyncRoute<K> {
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
        let ldap_runtime = self.ldap.clone();
        let ad_runtime = self.ad.clone();
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
                return fail(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let actor = auth.context();
            let Ok(authority) = setjoin_directory_sync::authority(&exec, actor).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            if ldap_runtime.is_none()
                && matches!(
                    what,
                    Action::LdapPut
                        | Action::LdapTest
                        | Action::LdapPreview
                        | Action::LdapSync
                        | Action::LdapHealth
                )
            {
                return c.upstream.forward(r, &c.identity).await;
            }
            if ad_runtime.is_none()
                && matches!(
                    what,
                    Action::AdPut | Action::AdTest | Action::AdSync | Action::AdHealth
                )
            {
                return c.upstream.forward(r, &c.identity).await;
            }
            let writes = matches!(
                what,
                Action::Resolve
                    | Action::ResolveAll
                    | Action::FieldPolicySet
                    | Action::Principal
                    | Action::LdapPut
                    | Action::LdapTest
                    | Action::LdapPreview
                    | Action::LdapSync
                    | Action::AdPut
                    | Action::AdTest
                    | Action::AdSync
            );
            let required: &[&str] = if writes {
                &setjoin_directory_sync::IDENTITY_WRITE
            } else {
                &setjoin_directory_sync::AUTH_CONSOLE
            };
            if !authority.allows_any(required) {
                let decoded = crate::guests_input::go_utf8(&crate::inventory::unescape(
                    r.uri()
                        .path()
                        .strip_prefix("/api")
                        .unwrap_or(r.uri().path()),
                ));
                let _ = setjoin_directory_sync::console_denied(
                    &exec,
                    actor,
                    &decoded,
                    &required.join("|"),
                    operation,
                )
                .await;
                return fail(403, "Forbidden", &c, &id);
            }
            let scope = authority.domain_scope();
            let reply =
                |body: String| crate::jmap::reply::response(body, c.identity.proto, id.clone());
            let db_error = |detail: &str| fail(500, detail, &c, &id);
            let unknown = |operation| {
                let mut response = fail(503, "operation outcome unknown", &c, &id);
                response.headers_mut().insert(
                    "x-operation-id",
                    setjoin_pg::operation_hex(operation)
                        .parse()
                        .expect("operation"),
                );
                response
            };
            match what {
                Action::Config | Action::LdapConfig => {
                    let source = if what == Action::Config {
                        Source::Ad
                    } else {
                        Source::Ldap
                    };
                    match setjoin_directory_sync::config(&exec, source).await {
                        Ok(body) => reply(body),
                        Err(_) => db_error("database error"),
                    }
                }
                Action::SyncLog | Action::LdapSyncLog => {
                    let source = if what == Action::SyncLog {
                        Source::Ad
                    } else {
                        Source::Ldap
                    };
                    let limit = input::query(r.uri(), "limit")
                        .map(|v| input::atoi(&v))
                        .filter(|n| *n > 0)
                        .unwrap_or(20);
                    match setjoin_directory_sync::sync_log(&exec, source, scope, limit).await {
                        Ok(body) => reply(body),
                        Err(_) => db_error("database error"),
                    }
                }
                Action::Conflicts => match setjoin_directory_sync::conflicts(&exec, actor).await {
                    Ok(body) => reply(body),
                    Err(_) => db_error("database error"),
                },
                Action::FieldPolicyGet => {
                    let user = input::query(r.uri(), "user_id")
                        .map(|v| input::atoi(&v))
                        .unwrap_or(0);
                    if user == 0 {
                        return fail(400, "user_id required", &c, &id);
                    }
                    // Owner-approved security fix 2026-11-05 (#376): the target must be
                    // within the caller's administrative scope, as for the write.
                    if !setjoin_contracts::mutants::on("fieldpolicy-get-foreign") {
                        match setjoin_directory_sync::reach_perm(
                            &exec,
                            actor,
                            user,
                            &setjoin_directory_sync::AUTH_CONSOLE,
                        )
                        .await
                        {
                            Err(_) => return db_error("db error"),
                            Ok(false) => {
                                return fail(
                                    403,
                                    "target user not within your administrative scope",
                                    &c,
                                    &id,
                                )
                            }
                            Ok(true) => {}
                        }
                    }
                    match setjoin_directory_sync::field_policy(&exec, actor, user).await {
                        Ok(body) => reply(body),
                        Err(_) => db_error("db error"),
                    }
                }
                Action::Resolve | Action::ResolveAll => {
                    let target = if what == Action::Resolve {
                        let segment = r.uri().path().split('/').nth(5).unwrap_or("");
                        let decoded =
                            crate::guests_input::go_utf8(&crate::inventory::unescape(segment));
                        match decoded.parse::<i64>() {
                            Ok(n) if n > 0 => Some(n),
                            _ => return fail(400, "invalid conflict id", &c, &id),
                        }
                    } else {
                        None
                    };
                    let Ok(body) = input::first::<input::Resolution>(&mut r, 8 << 20).await else {
                        return fail(400, "invalid JSON", &c, &id);
                    };
                    let Some(resolution) = setjoin_directory_sync::resolution(&body.resolution)
                    else {
                        return fail(
                            400,
                            "resolution must be keep_local or accept_remote",
                            &c,
                            &id,
                        );
                    };
                    let outcome = match target {
                        Some(conflict) => {
                            setjoin_directory_sync::resolve_conflict(
                                &exec, actor, conflict, resolution, operation,
                            )
                            .await
                        }
                        None => {
                            setjoin_directory_sync::resolve_all(
                                &exec, actor, resolution, operation,
                            )
                            .await
                        }
                    };
                    match outcome {
                        CommandOutcome::Committed(0) if target.is_some() => {
                            fail(404, "conflict not found", &c, &id)
                        }
                        CommandOutcome::Committed(_) => no_content(&c, &id),
                        CommandOutcome::RolledBack(_) => db_error("database error"),
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::FieldPolicySet => {
                    let Ok(body) = input::first::<input::FieldPolicy>(&mut r, 8 << 20).await else {
                        return fail(400, "invalid JSON", &c, &id);
                    };
                    if body.policy != "local_only" && body.policy != "ad_managed" {
                        return fail(400, "policy must be local_only or ad_managed", &c, &id);
                    }
                    if body.policy == "ad_managed" && body.field == "krb5_principal" {
                        return fail(
                            400,
                            "krb5_principal is the SSO identity and is always local-only; directory sync can never manage it",
                            &c,
                            &id,
                        );
                    }
                    match setjoin_directory_sync::reach_perm(
                        &exec,
                        actor,
                        body.user_id,
                        &setjoin_directory_sync::IDENTITY_WRITE,
                    )
                    .await
                    {
                        Err(_) => return db_error("database error"),
                        Ok(false) => {
                            return fail(
                                403,
                                "target user not within your administrative scope",
                                &c,
                                &id,
                            )
                        }
                        Ok(true) => {}
                    }
                    match setjoin_directory_sync::set_field_policy(
                        &exec,
                        actor,
                        body.user_id,
                        &body.field,
                        &body.policy,
                        operation,
                    )
                    .await
                    {
                        // Go ignores the write's error and still answers 204.
                        CommandOutcome::Committed(_) | CommandOutcome::RolledBack(_) => {
                            no_content(&c, &id)
                        }
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::LdapPut => {
                    use setjoin_directory_sync::ldap::admin as ldap_admin;
                    let Some(rt) = ldap_runtime.clone() else {
                        unreachable!()
                    };
                    let Ok(body) =
                        input::first::<Option<serde_json::Map<String, serde_json::Value>>>(
                            &mut r,
                            1 << 20,
                        )
                        .await
                    else {
                        return fail(400, "invalid JSON", &c, &id);
                    };
                    let body = body.unwrap_or_default();
                    if !ldap_admin::validate_config(&body) {
                        return fail(400, "invalid LDAP config", &c, &id);
                    }
                    match ldap_admin::put_config(
                        rt.codec().await,
                        ldap_admin::Kind::Ldap,
                        &exec,
                        actor,
                        &body,
                        operation,
                    )
                    .await
                    {
                        Ok(()) => {}
                        Err(ldap_admin::PutError::Outcome(CommandOutcome::Unknown {
                            operation,
                        })) => return unknown(operation),
                        Err(error) => {
                            eprintln!("setjoin-gateway: ldap config save failed: {error:?}");
                            return fail(500, "failed to save LDAP config", &c, &id);
                        }
                    }
                    match rt.reload().await {
                        Ok(_) => {
                            rt.wake.notify_one();
                            no_content(&c, &id)
                        }
                        Err(error) => {
                            eprintln!("setjoin-gateway: ldap config reload failed: {error}");
                            fail(500, "saved LDAP config but could not activate it", &c, &id)
                        }
                    }
                }
                Action::LdapTest | Action::LdapPreview | Action::LdapSync | Action::LdapHealth => {
                    use setjoin_directory_sync::ldap::admin as ldap_admin;
                    let Some(rt) = ldap_runtime.clone() else {
                        unreachable!()
                    };
                    let loaded = rt.reload().await.unwrap_or(None);
                    let enabled = loaded.as_ref().is_some_and(|l| l.enabled);
                    if what == Action::LdapHealth {
                        return reply(ldap_admin::health(&exec, loaded.is_some()).await);
                    }
                    if what == Action::LdapSync && !enabled {
                        return fail(503, "LDAP sync not enabled", &c, &id);
                    }
                    let Some(loaded) = loaded else {
                        return fail(503, "LDAP sync not configured", &c, &id);
                    };
                    match what {
                        Action::LdapTest => match loaded.worker.dry_run(5).await {
                            Ok(checked) => reply(ldap_admin::dry_run_json(checked)),
                            Err(error) => {
                                eprintln!("setjoin-gateway: ldap test connection failed: {error}");
                                fail(
                                    500,
                                    ldap_admin::conn_error_message(Some(error.class)),
                                    &c,
                                    &id,
                                )
                            }
                        },
                        Action::LdapPreview => {
                            let limit = input::query(r.uri(), "limit")
                                .map(|v| input::atoi(&v))
                                .filter(|n| *n > 0)
                                .unwrap_or(25);
                            match loaded.worker.preview(limit).await {
                                Ok((total, rows)) => reply(ldap_admin::preview_json(total, &rows)),
                                Err(error) => {
                                    eprintln!("setjoin-gateway: ldap preview failed: {error}");
                                    fail(
                                        500,
                                        ldap_admin::conn_error_message(Some(error.class)),
                                        &c,
                                        &id,
                                    )
                                }
                            }
                        }
                        _ => match loaded.worker.sync().await {
                            Ok(result) => reply(ldap_admin::sync_json(&result)),
                            Err(error) => {
                                eprintln!("setjoin-gateway: ldap sync failed: {error}");
                                fail(
                                    500,
                                    "Directory sync failed. Check the server logs for details.",
                                    &c,
                                    &id,
                                )
                            }
                        },
                    }
                }
                Action::AdPut => {
                    use setjoin_directory_sync::ldap::admin as ldap_admin;
                    let Some(rt) = ad_runtime.clone() else {
                        unreachable!()
                    };
                    let Ok(body) =
                        input::first::<Option<serde_json::Map<String, serde_json::Value>>>(
                            &mut r,
                            1 << 20,
                        )
                        .await
                    else {
                        return fail(400, "invalid JSON", &c, &id);
                    };
                    let body = body.unwrap_or_default();
                    if !ldap_admin::validate_prefixed(&body, ldap_admin::Kind::Ad) {
                        return fail(400, "invalid AD config", &c, &id);
                    }
                    match ldap_admin::put_config(
                        rt.codec().await,
                        ldap_admin::Kind::Ad,
                        &exec,
                        actor,
                        &body,
                        operation,
                    )
                    .await
                    {
                        Ok(()) => {}
                        Err(ldap_admin::PutError::Outcome(CommandOutcome::Unknown {
                            operation,
                        })) => return unknown(operation),
                        Err(error) => {
                            eprintln!("setjoin-gateway: ad config save failed: {error:?}");
                            return fail(500, "failed to save AD config", &c, &id);
                        }
                    }
                    match rt.reload().await {
                        Ok(_) => {
                            rt.wake.notify_one();
                            no_content(&c, &id)
                        }
                        Err(error) => {
                            eprintln!("setjoin-gateway: ad config reload failed: {error}");
                            fail(500, "saved AD config but could not activate it", &c, &id)
                        }
                    }
                }
                Action::AdTest | Action::AdSync | Action::AdHealth => {
                    use setjoin_directory_sync::ldap::admin as ldap_admin;
                    let Some(rt) = ad_runtime.clone() else {
                        unreachable!()
                    };
                    let loaded = rt.reload().await.unwrap_or(None);
                    if what == Action::AdHealth {
                        return reply(ldap_admin::health_for(&exec, loaded.is_some(), "ad").await);
                    }
                    let Some(loaded) = loaded else {
                        return fail(503, "AD sync not configured", &c, &id);
                    };
                    if what == Action::AdTest {
                        match loaded.worker.dry_run().await {
                            Ok(checked) => reply(ldap_admin::dry_run_json(checked)),
                            Err(error) => {
                                eprintln!("setjoin-gateway: ad test connection failed: {error}");
                                fail(
                                    500,
                                    "Could not connect to Active Directory. Verify the domain and credentials.",
                                    &c,
                                    &id,
                                )
                            }
                        }
                    } else {
                        match loaded.worker.sync().await {
                            Ok(result) => reply(ldap_admin::sync_json(&result)),
                            Err(error) => {
                                eprintln!("setjoin-gateway: ad sync failed: {error}");
                                fail(
                                    500,
                                    "AD sync failed. Check the server logs for details.",
                                    &c,
                                    &id,
                                )
                            }
                        }
                    }
                }
                Action::Principal => {
                    let Ok(body) = input::first::<input::Principal>(&mut r, 8 << 20).await else {
                        return fail(400, "invalid JSON", &c, &id);
                    };
                    if body.user_id <= 0 {
                        return fail(400, "userId required", &c, &id);
                    }
                    let principal = body.krb5_principal.trim();
                    if principal.is_empty() {
                        return fail(400, "krb5Principal required", &c, &id);
                    }
                    match setjoin_directory_sync::reach(&exec, actor, body.user_id).await {
                        Err(_) => return db_error("database error"),
                        Ok(false) => {
                            return fail(
                                403,
                                "target user not within your administrative scope",
                                &c,
                                &id,
                            )
                        }
                        Ok(true) => {}
                    }
                    let old = match setjoin_directory_sync::principal_current(&exec, body.user_id)
                        .await
                    {
                        Ok(Some(old)) => old,
                        Ok(None) => return fail(404, "user not found", &c, &id),
                        Err(_) => return db_error("database error"),
                    };
                    let ip = c.identity.client_ip.to_string();
                    match setjoin_directory_sync::set_principal(
                        &exec,
                        actor,
                        body.user_id,
                        principal,
                        old.as_deref(),
                        Some(ip.as_str()).filter(|v| !v.is_empty()),
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(result) if result == "applied" => {
                            no_content(&c, &id)
                        }
                        CommandOutcome::Committed(_) => {
                            fail(409, "principal changed concurrently; retry", &c, &id)
                        }
                        CommandOutcome::RolledBack(error) => match code(&error) {
                            Some("BZ060") => fail(404, "user not found", &c, &id),
                            Some("BZ061") => fail(
                                403,
                                "target user not within your administrative scope",
                                &c,
                                &id,
                            ),
                            _ => db_error("database error"),
                        },
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
            }
        })
    }
}

fn code(error: &Rejection<setjoin_pg::StatementFailure>) -> Option<&str> {
    match error {
        Rejection::Statement(e) | Rejection::Body(e) => e.sqlstate.as_deref(),
        _ => None,
    }
}

/// Go's `WriteError`: a minimal problem document, empty instance, no language.
fn fail(status: u16, detail: &str, c: &RequestContext, id: &str) -> Response<Body> {
    let code = hyper::StatusCode::from_u16(status).expect("status");
    let body = format!(
        "{{\"type\":\"about:blank\",\"title\":{},\"status\":{status},\"detail\":{},\"instance\":\"\"}}",
        serde_json::to_string(crate::problem::title(status)).expect("title"),
        serde_json::to_string(detail).expect("detail"),
    );
    let mut r = crate::jmap::reply::response(
        setjoin_directory_sync::go_escape(&body) + "\n",
        c.identity.proto,
        id.to_owned(),
    );
    *r.status_mut() = code;
    r.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/problem+json"),
    );
    r
}
fn no_content(c: &RequestContext, id: &str) -> Response<Body> {
    let mut r = crate::jmap::reply::response(String::new(), c.identity.proto, id.to_owned());
    *r.status_mut() = hyper::StatusCode::NO_CONTENT;
    r.headers_mut().remove("content-type");
    r
}

/// The identity-admin family's runtime projection of an AD/LDAP source as the
/// directory-sync catalog runtime takes it (the family crates cannot see each other).
pub fn source_config(
    c: setjoin_admin_identity::idv2_source::RuntimeConfig,
) -> setjoin_directory_sync::catalog::SourceConfig {
    setjoin_directory_sync::catalog::SourceConfig {
        source_key: c.source_key,
        kind: c.kind,
        host: c.host,
        port: c.port,
        transport: c.transport,
        base_dn: c.base_dn,
        bind_dn: c.bind_dn,
        subject_attribute: c.subject_attribute,
        user_filter: c.user_filter,
        group_filter: c.group_filter,
        password: c.password,
    }
}

/// Go's `probeIdentitySourceRuntime` for the identity source dry run (#400).
pub struct DirectoryProbe(pub setjoin_pg::workers::WorkerDatabase);

impl crate::admin_identity_v2::SourceProbe for DirectoryProbe {
    fn probe<'a>(
        &'a self,
        config: &'a setjoin_admin_identity::idv2_source::RuntimeConfig,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), bool>> + Send + 'a>> {
        Box::pin(async move {
            setjoin_directory_sync::catalog::probe(&self.0, &source_config(config.clone()))
                .await
                .map_err(|failure| failure.credential_rejected)
        })
    }
}
