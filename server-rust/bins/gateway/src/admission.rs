//! Final authentication answers for native HTTP routes (#406).
use crate::{Body, BoxFuture, ClientIdentity};
use hyper::{HeaderMap, Method, Response};
use setjoin_authz::token::KeySource;
use std::sync::Arc;

pub(crate) trait Admission: Send + Sync {
    fn check(
        &self,
        headers: HeaderMap,
        method: Method,
        path: String,
        identity: ClientIdentity,
        required: bool,
    ) -> BoxFuture<Option<Response<Body>>>;
}

pub(crate) struct SessionAdmission<K> {
    pub guest: setjoin_pg::ScopedExecutor,
    pub keys: Arc<K>,
    pub denylist: Option<Arc<crate::workers::SessionDenylist>>,
    pub issuer: String,
}
impl<K: KeySource + 'static> Admission for SessionAdmission<K> {
    fn check(
        &self,
        headers: HeaderMap,
        method: Method,
        path: String,
        identity: ClientIdentity,
        required: bool,
    ) -> BoxFuture<Option<Response<Body>>> {
        let (guest, keys, issuer) = (self.guest.clone(), self.keys.clone(), self.issuer.clone());
        let denylist = self.denylist.clone();
        Box::pin(async move {
            if !required && setjoin_authz::token::presented(&headers).is_none() {
                return None;
            }
            // Password and Negotiate strategies have a named owner (#420/#339).
            let alternative = headers.get("authorization").is_some_and(|v| {
                v.as_bytes().starts_with(b"Basic ") || v.as_bytes().starts_with(b"Negotiate ")
            });
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0.0, |d| d.as_secs_f64());
            let claims = if let Some(token) = setjoin_authz::token::presented(&headers) {
                setjoin_authz::token::validate_first_party(&token, &issuer, now, &keys).await
            } else {
                None
            };
            let valid = claims.as_ref().is_some_and(|c| {
                let scope = c.get("scp").and_then(|v| v.as_str()).unwrap_or("");
                c.get("typ").and_then(|v| v.as_str()) == Some("access")
                    && (scope.is_empty()
                        || path == format!("/{scope}")
                        || path.starts_with(&format!("/{scope}/"))
                        || path == format!("/api/{scope}")
                        || path.starts_with(&format!("/api/{scope}/")))
            });
            if valid {
                let claims = claims.unwrap();
                let user = claims.get("uid").and_then(|v| v.as_i64()).unwrap_or(0);
                let rows = tokio::time::timeout(setjoin_authz::precheck_timeout(), guest.read(
                    "SELECT status, expires_at IS NOT NULL AND expires_at < now() FROM guest_account_status($1)",
                    &[(&user,setjoin_pg::Type::INT8)],
                )).await;
                let rows = match rows {
                    Ok(Ok(rows)) => rows,
                    _ => return Some(problem(&headers, &identity, 503, "service unavailable")),
                };
                let claimed_guest = claims.get("acct").and_then(|v| v.as_str()) == Some("guest");
                let inactive = rows.first().map_or(claimed_guest, |r| {
                    r.get::<_, String>(0) != "active" || r.get::<_, bool>(1)
                });
                if inactive {
                    return Some(problem(&headers, &identity, 401, "Unauthorized"));
                }
                if !rows.is_empty() {
                    let flags = tokio::time::timeout(setjoin_authz::precheck_timeout(), guest.read(
                        "SELECT s.mode::text,coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'),false) FROM feature_toggle_registry_state s WHERE s.singleton", &[],
                    )).await;
                    let enabled = match flags {
                        Ok(Ok(rows))
                            if rows.first().is_some_and(|r| {
                                matches!(r.get::<_, String>(0).as_str(), "observe" | "enforce")
                            }) =>
                        {
                            rows[0].get::<_, bool>(1)
                        }
                        _ => return Some(problem(&headers, &identity, 503, "service unavailable")),
                    };
                    if !enabled || !guest_allowed(&method, &path) {
                        return Some(not_found(&headers, &identity));
                    }
                }
                if required {
                    let iat = claims
                        .get("iat")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(-62135596800.0);
                    let jti = claims.get("jti").and_then(|v| v.as_str()).unwrap_or("");
                    let family = claims.get("fam").and_then(|v| v.as_str()).unwrap_or("");
                    let cached = denylist.as_ref().is_some_and(|d| {
                        d.is_revoked(
                            user,
                            jti,
                            family,
                            chrono::DateTime::from_timestamp(iat as i64, 0).unwrap_or_default(),
                        )
                    });
                    let revoked=tokio::time::timeout(setjoin_authz::precheck_timeout(),guest.read(
                        "SELECT EXISTS(SELECT 1 FROM session_revocations WHERE user_id=$1 AND expires_at>now() AND ((scope='all' AND not_before>=to_timestamp($2::float8)) OR (scope='jti' AND $3<>'' AND jti=$3) OR (scope='family' AND $4<>'' AND family_id=$4)))",
                        &[(&user,setjoin_pg::Type::INT8),(&iat,setjoin_pg::Type::FLOAT8),(&jti,setjoin_pg::Type::TEXT),(&family,setjoin_pg::Type::TEXT)]
                    )).await;
                    if cached
                        || revoked
                            .as_ref()
                            .is_ok_and(|r| r.as_ref().is_ok_and(|r| r[0].get::<_, bool>(0)))
                    {
                        return Some(revoked_problem(
                            &headers,
                            &identity,
                            "Session has been revoked. Sign in again.",
                        ));
                    }
                    let cae=tokio::time::timeout(setjoin_authz::precheck_timeout(),guest.read(
                        "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.cae_runtime'),false)",&[])).await;
                    let cae = match cae {
                        Ok(Ok(rows)) => rows[0].get::<_, bool>(0),
                        _ => return Some(problem(&headers, &identity, 503, "service unavailable")),
                    };
                    if cae && denylist.as_ref().is_none_or(|d| !d.loaded()) {
                        return Some(revoked_problem(
                            &headers,
                            &identity,
                            "Session verification unavailable — re-authenticate.",
                        ));
                    }
                }
                return None;
            }
            if !required || alternative {
                return None;
            }
            let mut response = problem(&headers, &identity, 401, "Unauthorized");
            response.headers_mut().insert(
                "www-authenticate",
                "Negotiate, Bearer realm=\"mailserver\"".parse().unwrap(),
            );
            Some(response)
        })
    }
}

pub(crate) fn problem(
    headers: &HeaderMap,
    identity: &ClientIdentity,
    status: u16,
    detail: &str,
) -> Response<Body> {
    let id = crate::jmap::reply::request_id(
        headers.get("x-request-id"),
        crate::jmap::random().unwrap_or([0; 16]),
    );
    let mut response = crate::jmap::reply::response(
        crate::problem::Problem::new(status, detail).body(),
        identity.proto,
        id,
    );
    *response.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
    response
        .headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    response
}

fn not_found(headers: &HeaderMap, identity: &ClientIdentity) -> Response<Body> {
    let mut response = problem(headers, identity, 404, "not found");
    crate::problem::set_body(&mut response, "404 page not found\n".into());
    response
        .headers_mut()
        .insert("content-type", "text/plain; charset=utf-8".parse().unwrap());
    response
}

/// Native data mirrors every rule of frozen Go's guest allowlist.
fn guest_allowed(method: &Method, path: &str) -> bool {
    struct Rule {
        method: &'static str,
        kind: &'static str,
        pattern: &'static str,
        regex: Option<regex::Regex>,
    }
    static RULES: std::sync::OnceLock<Vec<Rule>> = std::sync::OnceLock::new();
    let rules = RULES.get_or_init(|| {
        crate::guest_allowlist::RULES
            .iter()
            .map(|&(method, kind, pattern)| {
                assert!(
                    matches!(kind, "exact" | "prefix" | "root-prefix" | "regex"),
                    "unknown guest rule"
                );
                Rule {
                    method,
                    kind,
                    pattern,
                    regex: (kind == "regex")
                        .then(|| regex::Regex::new(pattern).expect("frozen guest regex")),
                }
            })
            .collect()
    });
    let decoded = String::from_utf8_lossy(&crate::inventory::unescape(path)).into_owned();
    let p = if decoded.starts_with("/api/") {
        &decoded[4..]
    } else {
        &decoded
    };
    rules.iter().any(|r| {
        if !r.method.is_empty() && r.method != method.as_str() {
            return false;
        }
        match r.kind {
            "exact" => p == r.pattern,
            "prefix" => p.starts_with(r.pattern),
            "root-prefix" => decoded.starts_with(r.pattern),
            "regex" => r.regex.as_ref().unwrap().is_match(p),
            _ => false,
        }
    })
}

fn revoked_problem(headers: &HeaderMap, identity: &ClientIdentity, detail: &str) -> Response<Body> {
    let mut response = problem(headers, identity, 401, detail);
    crate::problem::set_body(
        &mut response,
        crate::problem::middleware(401, "session_revoked", detail),
    );
    response
}
