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
            if let Some(claims) = valid_claims(&*keys, &issuer, &headers, &path).await {
                if let Some(response) =
                    check_claims_guest(&guest, &claims, &headers, &method, &path, &identity).await
                {
                    return Some(response);
                }
                let user = claims.get("uid").and_then(|v| v.as_i64()).unwrap_or(0);
                if required {
                    let iat = claims
                        .get("iat")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(-62135596800.0);
                    let jti = claims.get("jti").and_then(|v| v.as_str()).unwrap_or("");
                    let family = claims.get("fam").and_then(|v| v.as_str()).unwrap_or("");
                    let bridge = denylist.as_deref().map(DenylistBridge);
                    let view = bridge
                        .as_ref()
                        .map(|b| b as &dyn setjoin_authz::policy_gate::DenylistView);
                    if let Err(denial) = setjoin_authz::policy_gate::check_session_revocation(
                        &guest, view, user, jti, family, iat,
                    )
                    .await
                    {
                        return Some(match denial {
                            setjoin_authz::policy_gate::GateDenial::SessionRevoked => {
                                revoked_problem(
                                    &headers,
                                    &identity,
                                    "Session has been revoked. Sign in again.",
                                )
                            }
                            setjoin_authz::policy_gate::GateDenial::DenylistUnavailable => {
                                revoked_problem(
                                    &headers,
                                    &identity,
                                    "Session verification unavailable — re-authenticate.",
                                )
                            }
                            _ => problem(&headers, &identity, 503, "service unavailable"),
                        });
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

/// Validates a presented bearer/cookie token and its optional route scope for guest-belt admission.
async fn valid_claims(
    keys: &impl KeySource,
    issuer: &str,
    headers: &HeaderMap,
    path: &str,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64());
    let token = setjoin_authz::token::presented(headers)?;
    let claims = setjoin_authz::token::validate_first_party(&token, issuer, now, keys).await?;
    let scope = claims.get("scp").and_then(|v| v.as_str()).unwrap_or("");
    let decoded = String::from_utf8_lossy(&crate::inventory::unescape(path)).into_owned();
    let ok = claims.get("typ").and_then(|v| v.as_str()) == Some("access")
        && (scope.is_empty()
            || decoded == format!("/{scope}")
            || decoded.starts_with(&format!("/{scope}/"))
            || decoded == format!("/api/{scope}")
            || decoded.starts_with(&format!("/api/{scope}/")));
    ok.then_some(claims)
}

/// Checks guest status, `feature.guest_accounts`, and `guest_allowed` for validated claims.
async fn check_claims_guest(
    guest: &setjoin_pg::ScopedExecutor,
    claims: &serde_json::Map<String, serde_json::Value>,
    headers: &HeaderMap,
    method: &Method,
    path: &str,
    identity: &ClientIdentity,
) -> Option<Response<Body>> {
    let user = claims.get("uid").and_then(|v| v.as_i64()).unwrap_or(0);
    let rows = tokio::time::timeout(
        setjoin_authz::precheck_timeout(),
        guest.read(
            "SELECT status, expires_at IS NOT NULL AND expires_at < now() FROM guest_account_status($1)",
            &[(&user, setjoin_pg::Type::INT8)],
        ),
    )
    .await;
    let rows = match rows {
        Ok(Ok(rows)) => rows,
        _ => return Some(problem(headers, identity, 503, "service unavailable")),
    };
    let claimed_guest = claims.get("acct").and_then(|v| v.as_str()) == Some("guest");
    let inactive = rows.first().map_or(claimed_guest, |r| {
        r.get::<_, String>(0) != "active" || r.get::<_, bool>(1)
    });
    if inactive {
        return Some(problem(headers, identity, 401, "Unauthorized"));
    }
    if !rows.is_empty() {
        let flags = tokio::time::timeout(
            setjoin_authz::precheck_timeout(),
            guest.read(
                "SELECT s.mode::text,coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'),false) FROM feature_toggle_registry_state s WHERE s.singleton",
                &[],
            ),
        )
        .await;
        let enabled = match flags {
            Ok(Ok(rows))
                if rows.first().is_some_and(|r| {
                    matches!(r.get::<_, String>(0).as_str(), "observe" | "enforce")
                }) =>
            {
                rows[0].get::<_, bool>(1)
            }
            _ => return Some(problem(headers, identity, 503, "service unavailable")),
        };
        if !enabled || !guest_allowed(method, path) {
            return Some(not_found(headers, identity));
        }
    }
    None
}

/// Optional-auth guest-belt gate matching `SessionAdmission::check(..., required = false)`.
pub(crate) async fn check_guest_belt(
    guest: &setjoin_pg::ScopedExecutor,
    keys: &impl KeySource,
    issuer: &str,
    headers: &HeaderMap,
    method: &Method,
    path: &str,
    identity: &ClientIdentity,
) -> Option<Response<Body>> {
    let claims = valid_claims(keys, issuer, headers, path).await?;
    check_claims_guest(guest, &claims, headers, method, path, identity).await
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

pub(crate) fn not_found(headers: &HeaderMap, identity: &ClientIdentity) -> Response<Body> {
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

pub(crate) fn revoked_problem(
    headers: &HeaderMap,
    identity: &ClientIdentity,
    detail: &str,
) -> Response<Body> {
    let mut response = problem(headers, identity, 401, detail);
    crate::problem::set_body(
        &mut response,
        crate::problem::middleware(401, "session_revoked", detail),
    );
    response
}

struct DenylistBridge<'a>(&'a crate::workers::SessionDenylist);

impl setjoin_authz::policy_gate::DenylistView for DenylistBridge<'_> {
    fn loaded(&self) -> bool {
        self.0.loaded()
    }
    fn is_revoked(&self, user_id: i64, jti: &str, family: &str, issued_at: i64) -> bool {
        self.0.is_revoked(
            user_id,
            jti,
            family,
            chrono::DateTime::from_timestamp(issued_at, 0).unwrap_or_default(),
        )
    }
}
