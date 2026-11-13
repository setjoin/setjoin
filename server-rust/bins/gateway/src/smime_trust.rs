//! `smime-trust-listener` (#328): the `smime_trust_changed` config listener. Frozen Go
//! subscribes to the channel on its LISTEN connection and, on every notification (any admin
//! trust-anchor write sends one), clears the per-recipient-domain S/MIME trust pools of each
//! inbound SMTP server (`InvalidateSMIMETrustCache`). The Rust listener clears the shared
//! [`TrustCache`] the same way. The cache is process-local, so both Go and Rust
//! observe changes until Go is deleted. Native SMTP starts this listener; the
//! explicit `RUST_WORKERS_ON=smime-trust-listener` also starts it without SMTP.
//!
//! Go subscribes only while its SMTP inbound server runs and never repairs a notification
//! lost across a reconnect, so a removed anchor could stay trusted until restart. Owner-approved
//! security fix 2026-11-05 (#465): the Rust listener serves no cached pool while its LISTEN
//! connection is down (every lookup reads the database) and clears the cache once the
//! subscription is re-established, so an outage can never leave a removed anchor trusted.
use setjoin_mail_security::smime::trust::TrustCache;
use setjoin_pg::workers::DirectListener;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "oracle-mutants")]
fn mutant(id: &str) -> bool {
    std::env::var("SETJOIN_MAILSEC_MUTANT").is_ok_and(|v| v == id)
}
#[cfg(not(feature = "oracle-mutants"))]
fn mutant(_: &str) -> bool {
    false
}

pub const NAME: &str = "smime-trust-listener";
pub const CHANNEL: &str = "smime_trust_changed";

pub struct SmimeTrustListener {
    cache: Arc<TrustCache>,
    direct_dsn: String,
    listening: AtomicBool,
}

impl SmimeTrustListener {
    pub fn new(cache: Arc<TrustCache>, direct_dsn: String) -> Self {
        // No subscription yet: nothing may be cached until the listener is established.
        cache.set_cached(false);
        Self {
            cache,
            direct_dsn,
            listening: AtomicBool::new(false),
        }
    }

    /// True while the LISTEN connection is established (the oracle waits for it).
    pub fn listening(&self) -> bool {
        self.listening.load(Ordering::SeqCst)
    }

    /// Go's subscription callback.
    pub fn on_notification(&self) {
        self.cache.invalidate();
    }

    async fn listen(&self) {
        let mut backoff = Duration::from_secs(1);
        loop {
            let connection = tokio::time::timeout(
                Duration::from_secs(2),
                DirectListener::connect(&self.direct_dsn, CHANNEL),
            )
            .await;
            let mut listener = match connection {
                Ok(Ok(listener)) => listener,
                _ => {
                    eprintln!("smime trust listener: direct LISTEN unavailable; retrying");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    continue;
                }
            };
            backoff = Duration::from_secs(1);
            if !mutant("smime-no-reconnect-reload") {
                // Anything removed while the subscription was down produced no notification.
                self.cache.invalidate();
            }
            self.cache.set_cached(true);
            self.listening.store(true, Ordering::SeqCst);
            while listener.recv().await.is_some() {
                self.on_notification();
            }
            self.listening.store(false, Ordering::SeqCst);
            if !mutant("smime-no-reconnect-reload") {
                self.cache.set_cached(false);
            }
            let _ = listener.close().await;
            tokio::time::sleep(backoff).await;
        }
    }

    /// Run until `shutdown` resolves.
    pub async fn run_until(self: Arc<Self>, shutdown: impl Future<Output = ()>) {
        tokio::pin!(shutdown);
        tokio::select! {
            _ = &mut shutdown => {}
            _ = self.listen() => {}
        }
    }
}
