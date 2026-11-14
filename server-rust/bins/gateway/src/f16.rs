//! One family registration shared by the executable and black-box HTTP tests.
use crate::{
    attachment::{AttachmentCommands, AttachmentRoute},
    blobs::{BlobCommands, BlobRoute},
    recovery::{RecoveryCommands, RecoveryRoute},
    recovery_begin::{BeginRoute, ReceiptKeys},
    recovery_finalize::{ClamAV, FinalizeRoute, MalwareScanner},
    recovery_worker::S3Store,
    workers::SessionDenylist,
    Body, BoxFuture, Intercept, RequestContext,
};
use hyper::{HeaderMap, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

pub struct F16Config<K: KeySource> {
    pub exec: ScopedExecutor,
    pub worker_exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    pub denylist: Option<Arc<SessionDenylist>>,
    pub store: Arc<S3Store>,
    pub continuity: Option<Arc<ReceiptKeys>>,
    pub scanner: Option<Arc<dyn MalwareScanner>>,
    pub attachment_secret: Vec<u8>,
    pub attachment_previous_secret: Option<Vec<u8>>,
}
impl<K: KeySource> F16Config<K> {
    pub fn from_env(
        exec: ScopedExecutor,
        keys: Arc<K>,
        issuer: String,
        denylist: Option<Arc<SessionDenylist>>,
    ) -> Result<Option<Self>, String> {
        let env = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());
        if env("S3_ENDPOINT")
            .or_else(|| env("MINIO_ENDPOINT"))
            .is_none()
        {
            return Ok(None);
        }
        let store = Arc::new(S3Store::from_env()?);
        let dsn = env("DB_WORKER_DSN")
            .or_else(|| env("DB_DSN"))
            .ok_or("DB_DSN is required for F16")?;
        let worker_exec = ScopedExecutor::from_dsn(&dsn, 8)
            .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
            .with_audit_keys(
                env("DB_ENCRYPTION_KEY").unwrap_or_default(),
                env("AUDIT_HMAC_KEY").unwrap_or_default(),
            );
        let continuity = match ReceiptKeys::from_env() {
            Ok(keys) => keys.map(Arc::new),
            Err(error) => {
                eprintln!("continuity unavailable: {error}; recovery stays with Go");
                None
            }
        };
        let scanner =
            env("CLAMAV_ADDR").map(|addr| Arc::new(ClamAV::new(addr)) as Arc<dyn MalwareScanner>);
        let secret = env("JWT_MAIL_ATTACHMENT_SECRET")
            .or_else(|| env("JWT_SECRET"))
            .unwrap_or_default()
            .into_bytes();
        Ok(Some(Self {
            exec,
            worker_exec,
            keys,
            issuer,
            denylist,
            store,
            continuity,
            scanner,
            attachment_secret: secret,
            attachment_previous_secret: env("JWT_MAIL_ATTACHMENT_PREVIOUS_SECRET")
                .map(String::into_bytes),
        }))
    }
}
pub struct F16Route<K: KeySource + 'static> {
    blobs: BlobRoute<Arc<K>>,
    recovery: RecoveryRoute<Arc<K>>,
    begin: Option<BeginRoute<Arc<K>>>,
    finalize: FinalizeRoute<Arc<K>>,
    attachment: Option<AttachmentRoute>,
}
impl<K: KeySource + 'static> F16Route<K> {
    pub fn new(c: F16Config<K>) -> Self {
        let recovery = Arc::new(RecoveryCommands {
            exec: c.exec.clone(),
            worker_exec: c.worker_exec.clone(),
            keys: c.keys.clone(),
            issuer: c.issuer.clone(),
            denylist: c.denylist,
            control_plane_ready: c.continuity.is_some(),
            store: Some(c.store.clone()),
        });
        let begin = c.continuity.map(|keys| BeginRoute(recovery.clone(), keys));
        let finalize = FinalizeRoute(recovery.clone(), c.scanner);
        let blobs = BlobRoute(Arc::new(BlobCommands {
            exec: c.exec.clone(),
            worker_exec: c.worker_exec.clone(),
            keys: c.keys,
            issuer: c.issuer.clone(),
            store: c.store.clone(),
        }));
        let attachment = (!c.attachment_secret.is_empty()).then(|| {
            AttachmentRoute(Arc::new(AttachmentCommands {
                exec: c.exec,
                worker_exec: c.worker_exec,
                issuer: c.issuer,
                secret: c.attachment_secret,
                previous_secret: c.attachment_previous_secret,
                store: c.store,
            }))
        });
        Self {
            blobs,
            recovery: RecoveryRoute(recovery),
            begin,
            finalize,
            attachment,
        }
    }
    fn adapter(&self, r: &Request<Body>) -> Option<&dyn Intercept> {
        let adapters: [Option<&dyn Intercept>; 5] = [
            Some(&self.blobs),
            Some(&self.recovery),
            self.begin.as_ref().map(|r| r as &dyn Intercept),
            Some(&self.finalize),
            self.attachment.as_ref().map(|r| r as &dyn Intercept),
        ];
        adapters.into_iter().flatten().find(|a| a.matches(r))
    }
}
impl<K: KeySource + 'static> Intercept for F16Route<K> {
    fn requires_session(&self, r: &Request<Body>) -> bool { self.adapter(r).is_some_and(|a| a.requires_session(r)) }
    fn matches(&self, r: &Request<Body>) -> bool {
        self.adapter(r).is_some()
    }
    fn admits_member(&self, h: HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.recovery.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        match self.adapter(&r) {
            Some(adapter) => adapter.handle(r, c),
            // `matches` already declined: never reached through the route table (#357).
            None => {
                let reply = crate::surface::unregistered(&r, c.identity.proto);
                Box::pin(async move { reply })
            }
        }
    }
}
