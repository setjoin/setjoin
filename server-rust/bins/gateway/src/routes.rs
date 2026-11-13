//! The route table: the one seam where a Rust command takes over a request.
//!
//! Requests assigned to local Rust by the inventory are matched in order;
//! the first route whose [`Intercept::matches`] returns true handles it, and anything
//! unmatched is reverse-proxied to Go unchanged. The default table
//! ([`RouteTable::proxy_all`]) is empty, so the gateway has no business
//! logic of its own (#220).
//!
//! ARCH-029 supersedes ARCH-026/027's rollout defaults: a route enters after
//! parity and defaults ON with a kill switch. The pilot retains its existing
//! command-level flags. A route that decides,
//! after inspecting the request, that it cannot handle it completely must
//! hand the whole request to Go through [`RequestContext::upstream`] — never
//! answer part of it.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use hyper::{Request, Response};

use crate::forwarded::ClientIdentity;
use crate::proxy::Upstream;
use crate::Body;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// What a route receives besides the request.
#[derive(Clone)]
pub struct RequestContext {
    /// Client identity resolved through the trusted-proxy rules.
    pub identity: ClientIdentity,
    /// The Go upstream, for routes that decline after inspecting the body.
    pub upstream: Upstream,
}

/// A request type the gateway serves itself instead of proxying.
pub trait Intercept: Send + Sync + 'static {
    /// Close upgraded/streaming sessions when front-door acceptance stops.
    fn shutdown(&self) {}
    /// Whether Go wraps this matched shape in RequireAuth.
    fn requires_session(&self, _req: &Request<Body>) -> bool { false }
    /// Head-only match (method, URI, headers); the body is not read here.
    fn matches(&self, req: &Request<Body>) -> bool;
    /// Prove Go's guest belt admits this caller before spending a route budget.
    /// The default preserves Go forwarding. Opt-in adapters must verify the
    /// token and current guest/session state; this is not permission to write.
    fn admits_member(&self, _headers: hyper::HeaderMap, _scheme: &'static str) -> BoxFuture<bool> {
        Box::pin(async { false })
    }
    /// Serves the matched request. To decline, forward it with
    /// `ctx.upstream.forward(req, &ctx.identity)`.
    fn handle(&self, req: Request<Body>, ctx: RequestContext) -> BoxFuture<Response<Body>>;
}

#[derive(Clone, Default)]
pub struct RouteTable {
    routes: Vec<Arc<dyn Intercept>>,
    pub(crate) runtime:Option<Arc<dyn crate::runtime_access::RuntimeGate>>,

    pub(crate) admission: Option<Arc<dyn crate::admission::Admission>>,
    pub(crate) catchall: bool,
}

impl RouteTable {
    pub(crate) fn shutdown(&self) {
        for route in &self.routes {
            route.shutdown();
        }
    }
    /// The empty table: every request proxies to Go.
    pub fn proxy_all() -> Self {
        Self::default()
    }

    pub fn with_runtime(mut self,runtime:impl crate::runtime_access::RuntimeGate)->Self{
        self.runtime=Some(Arc::new(runtime));self
    }

    /// Install the deployment-owned verifier for final native HTTP denials.
    pub fn with_admission<K: setjoin_authz::token::KeySource + 'static>(mut self,
        guest: setjoin_pg::ScopedExecutor, keys: Arc<K>, issuer: String,
        denylist:Option<Arc<crate::workers::SessionDenylist>>) -> Self {
        self.admission = Some(Arc::new(crate::admission::SessionAdmission { guest, keys, issuer, denylist }));
        self
    }

    /// Appends a route; earlier routes win.
    pub fn with(mut self, route: impl Intercept) -> Self {
        self.routes.push(Arc::new(route));
        self
    }

    /// Install the final mux/SPA fallback after the family's concrete adapters.
    pub fn with_catchall(mut self, route: impl Intercept) -> Self {
        self.catchall = true;
        self.routes.push(Arc::new(route));
        self
    }

    /// A disabled Go registration falls through to the root mux, even when
    /// the complete route inventory still names its concrete pattern.
    pub(crate) fn mux_fallback(&self) -> Option<Arc<dyn Intercept>> {
        if self.catchall {
            self.routes.last().cloned()
        } else {
            None
        }
    }

    /// The final catch-all, when one is installed and claims the request.
    pub(crate) fn find_catchall(&self, req: &Request<Body>) -> Option<Arc<dyn Intercept>> {
        if !self.catchall {
            return None;
        }
        self.routes.last().filter(|r| r.matches(req)).cloned()
    }

    pub(crate) fn find(&self, req: &Request<Body>) -> Option<Arc<dyn Intercept>> {
        self.routes.iter().find(|r| r.matches(req)).cloned()
    }
}
