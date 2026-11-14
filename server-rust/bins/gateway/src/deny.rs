//! Native answers for `setjoin_authz::admit` refusals (#354). Adapters call
//! [`admit`] where they used `authorize_*` and return [`answer`] on refusal.
//! Only refusal classes Go would still authenticate or serve reach Go, from this
//! one site; each names its owner. Surfaces that must never reach Go (#365
//! AuthAdmin) use [`native_or_unauthorized`], never [`answer`].
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
    setjoin_authz::admit(exec, keys, issuer, r.headers(), r.uri().path(), scope).await
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

/// Go's bytes for a refusal; `None` = Go would still authenticate or serve it.
pub(crate) fn native(
    refusal: Refusal,
    headers: &HeaderMap,
    c: &RequestContext,
) -> Option<Response<Body>> {
    Some(match refusal {
        Refusal::NoCredential | Refusal::InvalidToken => unauthorized(headers, c),
        // Approved divergences (authz-deny/divergences.json): Go's REST chain
        // accepts these signed tokens; every first-party mint sets iat and uid>0.
        Refusal::MissingIssuedAt | Refusal::UnservedSubject => unauthorized(headers, c),
        Refusal::GuestInactive => crate::admission::problem(headers, &c.identity, 401, "Unauthorized"),
        Refusal::Revoked => crate::admission::revoked_problem(headers, &c.identity, "Session has been revoked. Sign in again."),
        // Approved divergence: Go has no such read; fail closed with guestgate's 503.
        Refusal::Unavailable => crate::admission::problem(headers, &c.identity, 503, "service unavailable"),
        Refusal::AlternativeCredential   // #355 native Basic/Negotiate (reachable unauthenticated)
        | Refusal::Impersonation         // follow-up: native impersonation sessions
        | Refusal::Guest                 // guest-scope owner
        | Refusal::NoPrimaryMailbox      // follow-up: mailbox-less members per family
        | Refusal::MailboxBlocked => return None,
    })
}

/// Fail-closed mapping for surfaces Go must never see (#365 AuthAdmin).
pub(crate) fn native_or_unauthorized(
    refusal: Refusal,
    headers: &HeaderMap,
    c: &RequestContext,
) -> Response<Body> {
    native(refusal, headers, c).unwrap_or_else(|| unauthorized(headers, c))
}

pub(crate) async fn answer(
    refusal: Refusal,
    r: Request<Body>,
    c: &RequestContext,
) -> Response<Body> {
    if let Some(response) = native(refusal, r.headers(), c) {
        return response;
    }
    c.upstream.forward(r, &c.identity).await
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
            let Some(response) = native(refusal, &headers, &c) else {
                continue;
            };
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
            );
            assert_eq!(
                challenge.as_deref(),
                challenged.then_some(CHALLENGE),
                "{refusal:?}"
            );
            match refusal {
                Refusal::Unavailable => {
                    assert_eq!(status, 503, "{refusal:?}");
                    assert!(
                        body.contains("\"title\":\"Service Unavailable\"")
                            && body.contains("\"detail\":\"service unavailable\""),
                        "{body}"
                    );
                }
                Refusal::Revoked => {
                    assert_eq!(status, 401);
                    assert!(body.contains("session_revoked"), "{body}");
                }
                _ => {
                    assert_eq!(status, 401, "{refusal:?}");
                    assert_eq!(body, RA_BODY, "{refusal:?}");
                }
            }
            assert_eq!(
                h.get("content-type").and_then(|v| v.to_str().ok()),
                Some("application/problem+json"),
                "{refusal:?}"
            );
        }
    }

    #[tokio::test]
    async fn only_the_five_owned_classes_are_left_to_go() {
        let c = context();
        let owned: Vec<Refusal> = Refusal::ALL
            .into_iter()
            .filter(|r| native(*r, &HeaderMap::new(), &c).is_none())
            .collect();
        assert_eq!(
            owned,
            vec![
                Refusal::AlternativeCredential,
                Refusal::Impersonation,
                Refusal::Guest,
                Refusal::NoPrimaryMailbox,
                Refusal::MailboxBlocked,
            ]
        );
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
