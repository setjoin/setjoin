//! One Office family registration shared by the executable and HTTP oracle.
use crate::{
    office::{OfficeAdminRoute, OfficeRoute},
    recovery_worker::S3Store,
    Body, BoxFuture, Intercept, RequestContext,
};
use hyper::{Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;
pub struct F15Config<K: KeySource> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    pub store: Option<Arc<S3Store>>,
}
impl<K: KeySource> F15Config<K> {
    pub fn from_env(exec: ScopedExecutor, keys: Arc<K>, issuer: String) -> Result<Self, String> {
        let configured = ["S3_ENDPOINT", "MINIO_ENDPOINT"]
            .iter()
            .any(|key| std::env::var(key).ok().is_some_and(|v| !v.is_empty()));
        let store = if configured {
            Some(Arc::new(S3Store::from_env()?))
        } else {
            None
        };
        Ok(Self {
            exec,
            keys,
            issuer,
            store,
        })
    }
}
pub struct F15Route<K: KeySource + 'static> {
    wopi: OfficeRoute,
    admin: OfficeAdminRoute<K>,
}
impl<K: KeySource + 'static> F15Route<K> {
    pub fn new(c: F15Config<K>) -> Self {
        Self {
            wopi: OfficeRoute::new(c.exec.clone(), c.store),
            admin: OfficeAdminRoute {
                exec: c.exec,
                keys: c.keys,
                issuer: c.issuer,
                provider_client: None,
            },
        }
    }
}
impl<K: KeySource + 'static> Intercept for F15Route<K> {
    fn requires_session(&self, r: &Request<Body>) -> bool { self.admin.matches(r) }
    fn matches(&self, r: &Request<Body>) -> bool {
        self.wopi.matches(r) || self.admin.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        self.admin.admits_member(h, scheme)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        if self.wopi.matches(&r) {
            self.wopi.handle(r, c)
        } else {
            self.admin.handle(r, c)
        }
    }
}
