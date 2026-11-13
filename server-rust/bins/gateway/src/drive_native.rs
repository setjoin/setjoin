//! #333 native Drive token issuance; proof and mint live in shared authz/identity.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use http_body_util::BodyExt;
use hyper::{Request, Response};
fn full(raw: String) -> Body {
    http_body_util::Full::new(bytes::Bytes::from(raw))
        .map_err(|never| match never {})
        .boxed()
}
use setjoin_authz::{push, token::KeySource};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;
pub struct NativeTokenRoute<K: KeySource + 'static> {
    exec: ScopedExecutor,
    keys: Arc<K>,
    issuer: String,
    signer: Option<Arc<setjoin_identity::drive_token::Issuer>>,
    chain: Option<Arc<setjoin_authz::auth_chain::Chain>>,
}
impl<K: KeySource + 'static> NativeTokenRoute<K> {
    pub fn new(exec: ScopedExecutor, keys: Arc<K>, issuer: String, secret: Option<&str>) -> Self {
        let signer = secret.filter(|s| !s.is_empty()).map(|s| {
            Arc::new(setjoin_identity::drive_token::Issuer::new(
                s.as_bytes(),
                issuer.clone(),
            ))
        });
        Self {
            exec,
            keys,
            issuer,
            signer,
            chain: None,
        }
    }
    pub fn with_chain(mut self, chain: Option<Arc<setjoin_authz::auth_chain::Chain>>) -> Self {
        self.chain = chain;
        self
    }
}
fn response(status: u16, raw: String, problem: bool) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(
            "content-type",
            if problem {
                "application/problem+json"
            } else {
                "application/json"
            },
        )
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .body(full(raw))
        .unwrap()
}
fn denied() -> Response<Body> {
    let mut r = response(
        401,
        crate::problem::Problem::new(401, "Unauthorized").body(),
        true,
    );
    r.headers_mut().insert(
        "www-authenticate",
        "Negotiate, Bearer realm=\"mailserver\"".parse().unwrap(),
    );
    r
}
impl<K: KeySource + 'static> Intercept for NativeTokenRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        r.method() == hyper::Method::POST && r.uri().path() == "/api/drive/native-token"
    }
    fn admits_member(&self, h: hyper::HeaderMap, _scheme: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            let Some(t) = setjoin_authz::token::presented(&h) else {
                return false;
            };
            matches!(push::authenticate_drive(&exec,&*keys,&issuer,&t).await,Ok(p) if !p.is_guest())
        })
    }
    fn handle(&self, r: Request<Body>, context: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer, signer, chain) = (
            self.exec.clone(),
            self.keys.clone(),
            self.issuer.clone(),
            self.signer.clone(),
            self.chain.clone(),
        );
        Box::pin(async move {
            if !push::http_admission_allowed(&exec).await {
                return context.upstream.forward(r, &context.identity).await;
            } // shared policy/runtime components #405/#420
            if !matches!(*r.method(),hyper::Method::GET|hyper::Method::HEAD|hyper::Method::OPTIONS)
                && !setjoin_authz::csrf::allows(r.headers(), context.identity.proto) {
                return response(
                    403,
                    crate::problem::middleware(403, "csrf_failed", "CSRF validation failed"),
                    true,
                );
            }
            let source = match setjoin_authz::token::presented(r.headers()) {
                Some(token) => push::authenticate_drive(&exec, &*keys, &issuer, &token)
                    .await
                    .ok(),
                None => None,
            };
            let Some(source) = source else {
                let header = r
                    .headers()
                    .get("authorization")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("");
                if header.starts_with("Basic ") && chain.as_ref().is_none_or(|c| c.basic_allowed())
                {
                    return context.upstream.forward(r, &context.identity).await;
                    // password/threat proof #420
                }
                if header.starts_with("Negotiate ") {
                    return context.upstream.forward(r, &context.identity).await;
                } // Kerberos proof #339
                return denied();
            };
            if source.is_guest() {
                return context.upstream.forward(r, &context.identity).await;
            } // guest program admission #406
            if push::revoked(&exec, &source).await {
                return response(
                    401,
                    crate::problem::middleware(
                        401,
                        "session_revoked",
                        "Session has been revoked. Sign in again.",
                    ),
                    true,
                );
            }
            let Some(signer) = signer else {
                return response(
                    500,
                    crate::problem::Problem::new(500, "native-token minting is not configured")
                        .body(),
                    true,
                );
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            match signer.issue(&source, now) {
                Ok(raw) => response(200, raw, false),
                Err(setjoin_identity::drive_token::Refused::DeviceBound) => response(
                    403,
                    crate::problem::Problem::new(
                        403,
                        "native tokens are unavailable to device-bound sessions",
                    )
                    .body(),
                    true,
                ),
                Err(setjoin_identity::drive_token::Refused::Expired) => response(
                    401,
                    crate::problem::Problem::new(401, "session expired").body(),
                    true,
                ),
            }
        })
    }
}
