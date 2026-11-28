//! Deliberate adapter fault at the real HTTP boundary, never a rewritten observation.
use hyper::{Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_gateway::{approvals::ApprovalsRoute, Body, BoxFuture, Intercept, RequestContext};
pub struct Probe<K: KeySource + 'static> {
    pub inner: ApprovalsRoute<K>,
    pub changed_status: bool,
}
impl<K: KeySource + 'static> Intercept for Probe<K> {
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let future = self.inner.handle(r, c);
        let changed = self.changed_status;
        Box::pin(async move {
            let mut response = future.await;
            if changed {
                *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            response
        })
    }
}
pub fn rejected(result: Result<(), super::BoxError>, route: &str) -> Result<(), super::BoxError> {
    let error = result
        .expect_err("planted status mutant survived")
        .to_string();
    if !error.contains("/response/status") {
        return Err(format!("mutant failed outside response status: {error}").into());
    }
    eprintln!("MUTANT-REJECTED: {route} :: changed-status");
    Ok(())
}
pub async fn no_go(address: std::net::SocketAddr) -> Result<(), super::BoxError> {
    let response = super::send(
        address,
        Request::get("/_gateway/metrics").body(super::full(""))?,
    )
    .await;
    let body = String::from_utf8(super::body_bytes(response).await.to_vec())?;
    if !body
        .lines()
        .any(|line| line == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F10\"} 0")
    {
        return Err(format!("F10 replay forwarded to Go: {body}").into());
    }
    Ok(())
}
