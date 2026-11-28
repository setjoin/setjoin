//! Explicit seams for behaviour owned by other tickets.
//!
//! The shared interceptor lives in `setjoin-threat` (#420). Its protocol seam
//! is re-exported here so existing callers retain the same API. A server must
//! choose an explicit ThreatPolicy. `Unwired` mirrors Go's nil interceptor for
//! fixtures; gateway activation requires `Enforced` with the real shared gate.
use futures_util::future::BoxFuture;
use std::sync::Arc;

pub use setjoin_threat::{ConnectionMeta, ThreatAction, ThreatGate};

#[derive(Clone)]
pub enum ThreatPolicy {
    Enforced(Arc<dyn ThreatGate>),
    /// Go's nil interceptor. Not an allow-all gate: nothing is consulted or recorded.
    Unwired,
}
impl ThreatPolicy {
    pub fn is_enforced(&self) -> bool {
        matches!(self, Self::Enforced(_))
    }
}

/// `mailserver/auth` CloudEvents the IMAP login dispatches. The gateway's sink
/// hands them to the shared webhook dispatcher (#302/#457); `WebhookPolicy::Unwired`
/// drops them and exists for protocol tests only (activation refuses it, see
/// `Server::webhooks_wired`).
pub trait AuthWebhooks: Send + Sync {
    fn login<'a>(&'a self, email: &'a str, provider: &'a str, ip: &'a str) -> BoxFuture<'a, ()>;
    fn login_failed<'a>(
        &'a self,
        email: &'a str,
        provider: &'a str,
        ip: &'a str,
    ) -> BoxFuture<'a, ()>;
}

#[derive(Clone)]
pub enum WebhookPolicy {
    Wired(Arc<dyn AuthWebhooks>),
    Unwired,
}
