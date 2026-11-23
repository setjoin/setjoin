//! Native gateway deny-by-default catch-all for `/auth/admin/` (F21, #365).
//!
//! Replaces frozen Go's `d.authLimit(d.requireAuth(d.requireIdentityWrite(d.authProxy)))`
//! fallback under `/auth/admin/` and `/api/auth/admin/` without ever forwarding to Go:
//! - Bare `/auth/admin` and `/api/auth/admin` redirect `307` -> `/auth/admin/` before auth/RBAC.
//! - Subtree requests (excluding `POST /auth/admin/users/{id}/impersonate`, owned by `rust-auth`)
//!   authenticate as a member via `deny::admit` + `deny::native_or_unauthorized` (`401`/`503`).
//! - Live governed permissions require `identity.write` (`403` + durable `console.denied`).
//! - Authorized requests receive Go `authserverd`'s bare `404 page not found\n`.
use crate::mailboxes::bare;
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

pub struct AuthAdminRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
}

impl<K: KeySource + 'static> AuthAdminRoute<K> {
    pub fn new(exec: ScopedExecutor, keys: Arc<K>, issuer: String) -> Self {
        Self { exec, keys, issuer }
    }
}

/// Strip literal `/api` mount prefix only (matching Go's `http.StripPrefix("/api", ...)`).
fn strip_api_mount(path: &str) -> &str {
    path.strip_prefix("/api")
        .filter(|rest| rest.starts_with('/'))
        .unwrap_or(path)
}

fn is_bare(path: &str) -> bool {
    let rest = strip_api_mount(path);
    !rest.ends_with('/')
        && rest.split('/').count() == 3
        && crate::inventory::path_score("/auth/admin/", &format!("{rest}/")).is_some()
}

fn is_impersonate(method: &Method, rest: &str) -> bool {
    *method == Method::POST
        && crate::inventory::path_score("/auth/admin/users/{id}/impersonate", rest).is_some()
}

fn matches_request(method: &Method, path: &str) -> bool {
    let rest = strip_api_mount(path);
    if is_impersonate(method, rest) {
        return false;
    }
    is_bare(path) || crate::inventory::path_score("/auth/admin/", rest).is_some()
}

fn segment_path(path: &str) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(strip_api_mount(path)))
}

fn redirect_location(r: &Request<Body>) -> String {
    match r.uri().query() {
        Some(q) if !q.is_empty() => format!("/auth/admin/?{q}"),
        _ => "/auth/admin/".into(),
    }
}

impl<K: KeySource + 'static> Intercept for AuthAdminRoute<K> {
    fn requires_session(&self, r: &Request<Body>) -> bool {
        !is_bare(r.uri().path())
    }

    fn matches(&self, r: &Request<Body>) -> bool {
        matches_request(r.method(), r.uri().path())
    }

    fn admits_member(&self, headers: hyper::HeaderMap, _scheme: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            // Only return false when a valid token is specifically a guest;
            // invalid/unauthenticated/unavailable must never trigger lib.rs's go_mail fallback.
            !matches!(
                setjoin_authz::admit(
                    &exec,
                    &keys,
                    &issuer,
                    &headers,
                    "GET",
                    "/auth/admin/",
                    setjoin_authz::Scope::Member,
                )
                .await,
                Err(setjoin_authz::Refusal::Guest | setjoin_authz::Refusal::GuestInactive)
            )
        })
    }

    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            if is_bare(r.uri().path()) {
                let location = redirect_location(&r);
                return crate::catchall::redirect(&r, &c, 307, &location);
            }
            let auth =
                match crate::deny::admit(&exec, &keys, &issuer, &r, crate::deny::Scope::Member)
                    .await
                {
                    Ok(auth) => auth,
                    Err(refusal) => {
                        return crate::deny::native_or_unauthorized(refusal, r.headers(), &c)
                    }
                };
            let Some(operation) = crate::jmap::random() else {
                return bare(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let Ok(authority) = setjoin_platform::authority(&exec, auth.context()).await else {
                return bare(503, "service unavailable", &c, &id);
            };
            if !authority.allows_any(&setjoin_platform::IDENTITY_WRITE) {
                let go_path = segment_path(r.uri().path());
                let _ = setjoin_platform::console_denied(
                    &exec,
                    auth.context(),
                    &go_path,
                    "identity.write",
                    operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            }
            crate::catchall::not_found(&r, &c)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_matching_and_session_rules() {
        for (method, path, want_match, want_session) in [
            (Method::GET, "/auth/admin", true, false),
            (Method::HEAD, "/auth/admin", true, false),
            (Method::POST, "/auth/admin", true, false),
            (Method::GET, "/api/auth/admin", true, false),
            (Method::POST, "/api/auth/admin", true, false),
            (Method::GET, "/auth/%61dmin", true, false),
            (Method::GET, "/auth/admin/", true, true),
            (Method::GET, "/auth/admin/unknown", true, true),
            (Method::HEAD, "/auth/admin/unknown", true, true),
            (Method::POST, "/auth/admin/unknown", true, true),
            (Method::GET, "/api/auth/admin/unknown", true, true),
            (Method::POST, "/api/auth/admin/unknown", true, true),
            (Method::GET, "/auth/%61dmin/unknown", true, true),
            (Method::GET, "/auth/admin/users/1/impersonate", true, true),
            (
                Method::GET,
                "/api/auth/admin/users/1/impersonate",
                true,
                true,
            ),
            (
                Method::POST,
                "/auth/admin/users/1/impersonate",
                false,
                false,
            ),
            (
                Method::POST,
                "/api/auth/admin/users/1/impersonate",
                false,
                false,
            ),
            (
                Method::POST,
                "/auth/admin/users/1/2/impersonate",
                true,
                true,
            ),
            (Method::GET, "/a%70i/auth/admin/unknown", false, false),
            (Method::GET, "/auth/admin-extra", false, false),
            (Method::GET, "/auth/login", false, false),
        ] {
            let req = Request::builder()
                .method(method.clone())
                .uri(path)
                .body(crate::proxy::status(hyper::StatusCode::OK, "").into_body())
                .unwrap();
            assert_eq!(
                matches_request(&method, path),
                want_match,
                "{method} {path}"
            );
            if want_match {
                assert_eq!(!is_bare(req.uri().path()), want_session, "{method} {path}");
            }
        }
        assert_eq!(
            segment_path("/api/auth/%61dmin/unknown"),
            "/auth/admin/unknown"
        );
    }
}
