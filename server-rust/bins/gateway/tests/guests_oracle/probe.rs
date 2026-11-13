//! Deliberate adapter fault at the real HTTP boundary, never a rewritten observation.
use hyper::{Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_gateway::{guests::GuestsRoute, Body, BoxFuture, Intercept, RequestContext};
pub struct Probe<K: KeySource + 'static> {
    pub inner: GuestsRoute<K>,
    pub changed_status: bool,
    pub unfiltered: bool,
}
impl<K: KeySource + 'static> Intercept for Probe<K> {
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        if self.unfiltered {
            let exec = self.inner.exec.clone();
            let worker = self.inner.worker.clone();
            let keys = self.inner.keys.clone();
            let issuer = self.inner.issuer.clone();
            return Box::pin(async move {
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
                let user = auth.context().user_id();
                let source = include_str!("../../../../crates/domains/guests/src/guest_list.sql");
                let guarded="WHERE guest_admin_can_reach_with_permission($1,g.user_id,'guests.view')\n\t\t   OR guest_admin_can_reach_with_permission($1,g.user_id,'guests.manage')";
                assert!(source.contains(guarded));
                let sql = source.replace(guarded, "WHERE $1::bigint>0");
                let rows = worker
                    .read_scoped(
                        &setjoin_guests::scope(auth.context()),
                        &sql,
                        &[(&user, setjoin_pg::Type::INT8)],
                    )
                    .await
                    .expect("unfiltered owner query");
                let body: String = rows[0].get(0);
                let mut response = Response::new(crate::common::full(body + "\n"));
                response.headers_mut().insert(
                    "content-type",
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                return response;
            });
        }
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
pub fn rejected(
    result: Result<(), crate::common::BoxError>,
    route: &str,
) -> Result<(), crate::common::BoxError> {
    let error = result
        .expect_err("planted status mutant survived")
        .to_string();
    if !error.contains("/response/status") {
        return Err(format!("mutant failed outside response status: {error}").into());
    }
    eprintln!("MUTANT-REJECTED: {route} :: changed-status");
    Ok(())
}
pub async fn no_go(address: std::net::SocketAddr) -> Result<(), crate::common::BoxError> {
    let response = crate::common::send(
        address,
        Request::get("/_gateway/metrics").body(crate::common::full(""))?,
    )
    .await;
    let body = String::from_utf8(crate::common::body_bytes(response).await.to_vec())?;
    if !body
        .lines()
        .any(|line| line == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F11\"} 0")
    {
        return Err(format!("F11 replay forwarded to Go: {body}").into());
    }
    Ok(())
}
