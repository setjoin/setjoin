//! Native answers for `setjoin_authz::admit` refusals (#354, #359 Part A).
//! Adapters call [`admit`] and return [`answer`] on refusal; zero Go forwarding
//! remains. Surfaces that must keep strict 401/503 fail-closed behavior (#365
//! AuthAdmin, CalDAV, CardDAV) use [`native_or_unauthorized`].
use crate::routes::RequestContext;
use crate::Body;
use hyper::{HeaderMap, Request, Response};
use setjoin_authz::token::KeySource;
pub(crate) use setjoin_authz::{Refusal, Scope};

pub(crate) async fn admit(
    exec: &setjoin_pg::ScopedExecutor,
    keys: &impl KeySource,
    issuer: &str,
    r: &Request<Body>,
    scope: Scope,
) -> Result<setjoin_authz::Authorized, Refusal> {
    setjoin_authz::admit(
        exec,
        keys,
        issuer,
        r.headers(),
        r.method().as_str(),
        r.uri().path(),
        scope,
    )
    .await
}

pub(crate) async fn admit_console(
    exec: &setjoin_pg::ScopedExecutor,
    keys: &impl KeySource,
    issuer: &str,
    r: &Request<Body>,
    scope: Scope,
) -> Result<setjoin_authz::Authorized, Refusal> {
    setjoin_authz::admit_console(
        exec,
        keys,
        issuer,
        r.headers(),
        r.method().as_str(),
        r.uri().path(),
        scope,
    )
    .await
}

/// Go's RequireAuth 401 (`mailserver/internal/middleware/auth.go:23-28`).
pub(crate) fn unauthorized(headers: &HeaderMap, c: &RequestContext) -> Response<Body> {
    let mut response = crate::admission::problem(headers, &c.identity, 401, "Unauthorized");
    response.headers_mut().insert(
        "www-authenticate",
        hyper::header::HeaderValue::from_static("Negotiate, Bearer realm=\"mailserver\""),
    );
    response
}

/// Native HTTP answer for every `Refusal` class (total — zero Go forwarding).
pub(crate) fn native(refusal: Refusal, headers: &HeaderMap, c: &RequestContext) -> Response<Body> {
    match refusal {
        Refusal::NoCredential | Refusal::InvalidToken => unauthorized(headers, c),
        // Approved divergences (tests/conformance/authz-deny/divergences.json): Go's REST chain
        // accepts these signed tokens; every first-party mint sets iat and uid>0.
        Refusal::MissingIssuedAt | Refusal::UnservedSubject => unauthorized(headers, c),
        // Owner-approved divergence (2026-11-25, non-dav-alternative-credential-401):
        // non-DAV REST routes challenge Basic/Negotiate with RequireAuth 401.
        Refusal::AlternativeCredential => unauthorized(headers, c),
        // Fail-closed if ever constructed (ordinary `admit` admits positive `act` and mailbox-less members).
        Refusal::Impersonation | Refusal::NoPrimaryMailbox => unauthorized(headers, c),
        // Go guestgate.Middleware returns 404 plain text for disallowed guest routes.
        Refusal::Guest => crate::admission::not_found(headers, &c.identity),
        // Go httputil.WriteProblem 403 about:blank for suspended mailboxes.
        Refusal::MailboxBlocked => {
            crate::admission::problem(headers, &c.identity, 403, "mailbox access is suspended")
        }
        Refusal::GuestInactive => {
            crate::admission::problem(headers, &c.identity, 401, "Unauthorized")
        }
        Refusal::Revoked => crate::admission::revoked_problem(
            headers,
            &c.identity,
            "Session has been revoked. Sign in again.",
        ),
        // Approved divergence: Go has no such read; fail closed with guestgate's 503.
        Refusal::Unavailable => {
            crate::admission::problem(headers, &c.identity, 503, "service unavailable")
        }
    }
}

/// Strict 401/503 fail-closed mapping for surfaces that never admit guests or
/// suspended/mailbox-less fallback semantics (#365 AuthAdmin, CalDAV, CardDAV).
pub(crate) fn native_or_unauthorized(
    refusal: Refusal,
    headers: &HeaderMap,
    c: &RequestContext,
) -> Response<Body> {
    match refusal {
        Refusal::Guest
        | Refusal::MailboxBlocked
        | Refusal::NoPrimaryMailbox
        | Refusal::Impersonation
        | Refusal::AlternativeCredential => unauthorized(headers, c),
        other => native(other, headers, c),
    }
}

pub(crate) async fn answer(
    refusal: Refusal,
    r: Request<Body>,
    c: &RequestContext,
) -> Response<Body> {
    native(refusal, r.headers(), c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    const RA_BODY: &str = "{\"type\":\"about:blank\",\"title\":\"Unauthorized\",\"status\":401,\"detail\":\"Unauthorized\",\"instance\":\"\"}\n";
    const CHALLENGE: &str = "Negotiate, Bearer realm=\"mailserver\"";

    fn context() -> RequestContext {
        RequestContext {
            identity: crate::ClientIdentity {
                client_ip: "127.0.0.1".parse().unwrap(),
                proto: "http",
            },
            upstream: crate::proxy::Upstream::new("http://127.0.0.1:9".parse().unwrap()).unwrap(),
        }
    }

    async fn parts(response: Response<Body>) -> (u16, HeaderMap, String) {
        let (head, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        (
            head.status.as_u16(),
            head.headers,
            String::from_utf8(bytes.to_vec()).unwrap(),
        )
    }

    #[tokio::test]
    async fn native_classes_answer_with_go_status_headers_and_body() {
        let c = context();
        let headers = HeaderMap::new();
        for refusal in Refusal::ALL {
            let response = native(refusal, &headers, &c);
            let (status, h, body) = parts(response).await;
            let challenge = h
                .get("www-authenticate")
                .map(|v| v.to_str().unwrap().to_owned());
            let challenged = matches!(
                refusal,
                Refusal::NoCredential
                    | Refusal::InvalidToken
                    | Refusal::MissingIssuedAt
                    | Refusal::UnservedSubject
                    | Refusal::AlternativeCredential
                    | Refusal::Impersonation
                    | Refusal::NoPrimaryMailbox
            );
            assert_eq!(
                challenge.as_deref(),
                challenged.then_some(CHALLENGE),
                "{refusal:?}"
            );
            match refusal {
                Refusal::Guest => {
                    assert_eq!(status, 404, "{refusal:?}");
                    assert_eq!(body, "404 page not found\n", "{refusal:?}");
                    assert_eq!(
                        h.get("content-type").and_then(|v| v.to_str().ok()),
                        Some("text/plain; charset=utf-8"),
                        "{refusal:?}"
                    );
                }
                Refusal::MailboxBlocked => {
                    assert_eq!(status, 403, "{refusal:?}");
                    assert!(
                        body.contains("\"type\":\"about:blank\"")
                            && body.contains("\"detail\":\"mailbox access is suspended\""),
                        "{body}"
                    );
                    assert_eq!(
                        h.get("content-type").and_then(|v| v.to_str().ok()),
                        Some("application/problem+json"),
                        "{refusal:?}"
                    );
                }
                Refusal::Unavailable => {
                    assert_eq!(status, 503, "{refusal:?}");
                    assert!(
                        body.contains("\"title\":\"Service Unavailable\"")
                            && body.contains("\"detail\":\"service unavailable\""),
                        "{body}"
                    );
                    assert_eq!(
                        h.get("content-type").and_then(|v| v.to_str().ok()),
                        Some("application/problem+json"),
                        "{refusal:?}"
                    );
                }
                Refusal::Revoked => {
                    assert_eq!(status, 401);
                    assert!(body.contains("session_revoked"), "{body}");
                    assert_eq!(
                        h.get("content-type").and_then(|v| v.to_str().ok()),
                        Some("application/problem+json"),
                        "{refusal:?}"
                    );
                }
                _ => {
                    assert_eq!(status, 401, "{refusal:?}");
                    assert_eq!(body, RA_BODY, "{refusal:?}");
                    assert_eq!(
                        h.get("content-type").and_then(|v| v.to_str().ok()),
                        Some("application/problem+json"),
                        "{refusal:?}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn the_fail_closed_mapping_answers_401_or_503_for_every_class() {
        let c = context();
        for refusal in Refusal::ALL {
            let (status, _, _) =
                parts(native_or_unauthorized(refusal, &HeaderMap::new(), &c)).await;
            assert!(status == 401 || status == 503, "{refusal:?} gave {status}");
        }
    }
}
