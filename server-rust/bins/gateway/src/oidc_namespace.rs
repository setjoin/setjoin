//! Frozen public OP allowlist: unknown protocol children never reach auth/SPA.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
pub struct Namespace;
impl Intercept for Namespace {
    fn matches(&self, req: &Request<Body>) -> bool {
        let p = req.uri().path();
        p == "/oauth"
            || (p.starts_with("/oauth/") && !matches!(p, "/oauth/token" | "/oauth/introspect"))
            || (p.starts_with("/authorize/") && p != "/authorize/callback")
    }
    fn handle(&self, req: Request<Body>, _: RequestContext) -> BoxFuture<Response<Body>> {
        Box::pin(async move {
            let mut r = crate::proxy::status(
                hyper::StatusCode::NOT_FOUND,
                if req.method() == Method::HEAD {
                    ""
                } else {
                    "404 page not found\n"
                },
            );
            r.headers_mut()
                .insert("x-content-type-options", "nosniff".parse().unwrap());
            r.headers_mut().insert("cache-control","no-store".parse().unwrap());
            r
        })
    }
}
