//! IMAP listener, slice 1 (#343): greeting, STARTTLS/implicit TLS, LOGIN and
//! AUTHENTICATE PLAIN, SELECT/EXAMINE and the session-level commands of frozen
//! Go's `internal/imap`. The wire contract is Go's bytes (ARCH-029), so the
//! line framing and command parsing are a port of Go's lax parser rather than
//! a strict codec; see DOX.md. Protocols run in the gateway process, never
//! behind a TCP proxy. Commands owned by #344/#345 answer a distinct NO.
mod append;
mod auth;
mod conn;
mod folders;
mod hooks;
mod messages;
mod registry {
    pub use setjoin_threat::registry::*;
}
mod session;
mod tls;
mod tracker {
    pub use setjoin_threat::tracker::*;
}
mod transfer;

pub use hooks::{
    AuthWebhooks, ConnectionMeta, ThreatAction, ThreatGate, ThreatPolicy, WebhookPolicy,
};
pub use registry::{ProtocolSessionRegistry, RevocationRow};
pub use tls::server_config as production_tls;

use std::{io, path::PathBuf, sync::Arc};
use tokio::{net::TcpListener, sync::watch};
use tokio_rustls::rustls::ServerConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlsMode {
    /// No certificate: no STARTTLS, plaintext authentication allowed (Go
    /// without `SetTLS`/`SetSTARTTLS`).
    None,
    Starttls,
    Implicit,
}

pub struct Server {
    pub(crate) db: setjoin_pg::ScopedExecutor,
    pub(crate) tls: Option<Arc<ServerConfig>>,
    /// Certificate files reloaded for every STARTTLS upgrade, as Go does.
    pub(crate) tls_files: Option<(PathBuf, PathBuf)>,
    pub(crate) mode: TlsMode,
    pub(crate) threat: ThreatPolicy,
    pub(crate) webhooks: WebhookPolicy,
    pub(crate) registry: Option<Arc<ProtocolSessionRegistry>>,
    pub(crate) users: tracker::ConnTracker,
    /// Go's 60 s verification cache, bounded and per listener (#355-0).
    pub(crate) passwords: setjoin_authz::basic::PasswordCache,
    max_connections: usize,
}

impl Server {
    /// The threat and webhook seams are explicit arguments so a caller cannot
    /// forget them; see [`ThreatPolicy`].
    pub fn new(
        db: setjoin_pg::ScopedExecutor,
        threat: ThreatPolicy,
        webhooks: WebhookPolicy,
    ) -> Self {
        Self {
            db,
            tls: None,
            tls_files: None,
            mode: TlsMode::None,
            threat,
            webhooks,
            registry: None,
            users: tracker::ConnTracker::default(),
            passwords: setjoin_authz::basic::PasswordCache::new(),
            max_connections: 0,
        }
    }

    /// Implicit TLS (`SetTLS`): plaintext authentication is refused.
    pub fn with_tls(mut self, tls: Arc<ServerConfig>) -> Self {
        self.tls = Some(tls);
        self.mode = TlsMode::Implicit;
        self
    }

    /// Explicit upgrade (`SetSTARTTLS`): authentication is refused until it.
    pub fn with_starttls(mut self, tls: Arc<ServerConfig>) -> Self {
        self.tls = Some(tls);
        self.mode = TlsMode::Starttls;
        self
    }

    /// Production STARTTLS: validates the pair now (Go refuses to start on a bad
    /// pair) and, like Go's `handleStartTLS`, reloads it for every upgrade so a
    /// rotated certificate is picked up without a restart.
    pub fn with_starttls_files(mut self, cert: PathBuf, key: PathBuf) -> Result<Self, String> {
        self.tls = Some(tls::server_config(&cert, &key)?);
        self.tls_files = Some((cert, key));
        self.mode = TlsMode::Starttls;
        Ok(self)
    }

    /// Production implicit TLS: the pair is loaded once at start (Go's `Start`).
    pub fn with_tls_files(mut self, cert: PathBuf, key: PathBuf) -> Result<Self, String> {
        self.tls = Some(tls::server_config(&cert, &key)?);
        self.mode = TlsMode::Implicit;
        Ok(self)
    }

    /// 0 = unlimited. Connections beyond the cap wait to be accepted, as Go's
    /// `LimitListener` does.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Per authenticated user; 0 = unlimited.
    pub fn with_per_user_max(self, max: i64) -> Self {
        self.users.set_max(max);
        self
    }

    pub fn with_session_registry(mut self, registry: Arc<ProtocolSessionRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Live verification-cache entries (test observation of the per-listener cache).
    #[doc(hidden)]
    pub fn cached_passwords(&self) -> usize {
        self.passwords.len()
    }

    /// Verification-cache hits so far (test observation; N2 hit counter).
    #[doc(hidden)]
    pub fn cached_password_hits(&self) -> usize {
        self.passwords.hits()
    }

    pub fn threat_enforced(&self) -> bool {
        self.threat.is_enforced()
    }

    /// Whether `auth.login` / `auth.login_failed` reach a sink. A deployment must not
    /// activate a server that drops them (Go's daemon always has its dispatcher).
    pub fn webhooks_wired(&self) -> bool {
        matches!(self.webhooks, WebhookPolicy::Wired(_))
    }

    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        mut stop: watch::Receiver<bool>,
    ) -> io::Result<()> {
        let mut sessions = tokio::task::JoinSet::new();
        let slots = (self.max_connections > 0)
            .then(|| Arc::new(tokio::sync::Semaphore::new(self.max_connections)));
        loop {
            while sessions.try_join_next().is_some() {}
            let permit = tokio::select! {biased;
                _ = stop.changed() => break,
                p = async { match &slots { Some(s) => s.clone().acquire_owned().await.ok(), None => None } } => p,
            };
            let (socket, _) = tokio::select! {biased;
                _ = stop.changed() => break,
                accepted = listener.accept() => match accepted {
                    Ok(accepted) => accepted,
                    // Go logs and keeps accepting.
                    Err(_) => continue,
                },
            };
            let server = self.clone();
            sessions.spawn(async move {
                let _permit = permit;
                session::handle(server, socket).await;
            });
        }
        sessions.shutdown().await;
        Ok(())
    }
}
