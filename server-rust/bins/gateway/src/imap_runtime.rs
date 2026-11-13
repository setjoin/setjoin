//! The IMAP listener swap (#345): Rust serves IMAP on sockets systemd holds
//! (`FileDescriptorName=imap` for port 143 with STARTTLS, `imaps` for 993
//! implicit TLS), and frozen Go's listeners are off. There is no TCP proxy.
//!
//! Startup refuses (the gateway does not run) rather than serve wrongly:
//! - Go's copy must be off: `GO_LISTENERS_OFF` lists `imap` (two processes would
//!   otherwise contend for one port, or Go would keep serving it).
//! - The shared threat gate (#420) must be wired: an `Unwired` policy is refused,
//!   and no allow-all gate exists to pass instead.
//! - `imaps` needs a certificate pair; a plain `imap` socket needs one too unless
//!   it is a loopback listener (Go's `config.Validate`).
//!
//! Settings (gateway.env): `DB_DSN`, `IMAP_DB_POOL` (default 16),
//! `IMAP_MAX_CONNS` (500) and `IMAP_PER_USER_MAX_CONNS` (10) per listener as in
//! Go's `imap.max_conns`/`imap.per_user_max_conns`, and the certificate pair
//! `IMAP_TLS_CERT_FILE`/`IMAP_TLS_KEY_FILE` (fallback `TLS_CERT_FILE`/`TLS_KEY_FILE`).
use setjoin_imap::{AuthWebhooks, Server, ThreatGate, ThreatPolicy, WebhookPolicy};
use std::{path::PathBuf, sync::Arc};
use tokio::{net::TcpListener, sync::watch};

pub struct ImapRuntime {
    listeners: Vec<(Arc<Server>, TcpListener)>,
    revocations: Arc<crate::workers::SessionDenylist>,
    direct: String,
}

fn listed(get: &dyn Fn(&str) -> Option<String>, var: &str, name: &str) -> bool {
    get(var)
        .unwrap_or_default()
        .split(',')
        .any(|s| s.trim() == name)
}

fn number<T: std::str::FromStr>(
    get: &dyn Fn(&str) -> Option<String>,
    var: &str,
    default: T,
) -> Result<T, String> {
    match get(var).filter(|v| !v.is_empty()) {
        Some(v) => v.trim().parse().map_err(|_| format!("{var}: not a number")),
        None => Ok(default),
    }
}

fn certificate_pair(
    get: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let pick = |a: &str, b: &str| {
        get(a)
            .filter(|v| !v.is_empty())
            .or_else(|| get(b).filter(|v| !v.is_empty()))
    };
    match (
        pick("IMAP_TLS_CERT_FILE", "TLS_CERT_FILE")
            .or_else(|| get("TLS_CERT").filter(|v| !v.is_empty())),
        pick("IMAP_TLS_KEY_FILE", "TLS_KEY_FILE")
            .or_else(|| get("TLS_KEY").filter(|v| !v.is_empty())),
    ) {
        (Some(cert), Some(key)) => Ok(Some((cert.into(), key.into()))),
        (None, None) => Ok(None),
        _ => Err("IMAP TLS needs both a certificate and a key file".into()),
    }
}

/// Build the listeners from the sockets systemd handed over. `None` when none
/// were passed (Go still owns IMAP).
pub fn start(
    plain: Option<TcpListener>,
    implicit: Option<TcpListener>,
    get: &dyn Fn(&str) -> Option<String>,
    gate: Option<Arc<dyn ThreatGate>>,
    webhooks: Option<crate::webhook::Dispatcher>,
) -> Result<Option<ImapRuntime>, String> {
    if plain.is_none() && implicit.is_none() {
        return Ok(None);
    }
    if !listed(get, "GO_LISTENERS_OFF", "imap") {
        return Err(
            "IMAP sockets are activated but GO_LISTENERS_OFF does not list imap: Go's listener must be off first"
                .into(),
        );
    }
    let Some(gate) = gate else {
        return Err(
            "IMAP activation refused: the shared threat gate (#420) is not wired; Rust IMAP does not run without it"
                .into(),
        );
    };
    let Some(webhooks) = webhooks else {
        return Err(
            "IMAP activation refused: the webhook dispatcher is not wired; Rust IMAP would drop auth.login events"
                .into(),
        );
    };
    let dsn = get("DB_DSN")
        .filter(|v| !v.is_empty())
        .ok_or("DB_DSN is required for IMAP")?;
    let pool: usize = number(get, "IMAP_DB_POOL", 16)?;
    let registry = Arc::new(setjoin_imap::ProtocolSessionRegistry::default());
    let worker =
        setjoin_pg::workers::WorkerDatabase::from_dsns(&dsn, get("DB_WORKER_DSN").as_deref())
            .map_err(|e| e.to_string())?;
    let revocations = Arc::new(crate::workers::SessionDenylist::new(worker));
    revocations.attach_imap(registry.clone());
    let direct = get("DB_DIRECT_DSN")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| dsn.clone());
    let max_conns: usize = number(get, "IMAP_MAX_CONNS", 500)?;
    let per_user: i64 = number(get, "IMAP_PER_USER_MAX_CONNS", 10)?;
    let pair = certificate_pair(get)?;
    let executor = setjoin_pg::ScopedExecutor::from_dsn(&dsn, pool)
        .map_err(|e| format!("IMAP DB_DSN: {e:?}"))?;
    let build = |tls: Option<&(PathBuf, PathBuf)>, implicit: bool| -> Result<Server, String> {
        let server = Server::new(
            executor.clone(),
            ThreatPolicy::Enforced(gate.clone()),
            WebhookPolicy::Wired(Arc::new(AuthEvents(webhooks.clone()))),
        )
        .with_session_registry(registry.clone())
        .with_max_connections(max_conns)
        .with_per_user_max(per_user);
        let server = match (tls, implicit) {
            (Some((cert, key)), true) => server.with_tls_files(cert.clone(), key.clone())?,
            (Some((cert, key)), false) => server.with_starttls_files(cert.clone(), key.clone())?,
            (None, _) => server,
        };
        if !server.threat_enforced() {
            return Err("IMAP activation refused: threat policy is not enforced".into());
        }
        if !server.webhooks_wired() {
            return Err("IMAP activation refused: auth webhooks are not wired".into());
        }
        Ok(server)
    };
    let mut listeners = Vec::new();
    if let Some(socket) = plain {
        let addr = socket
            .local_addr()
            .map_err(|e| format!("IMAP socket address: {e}"))?;
        if pair.is_none() && !addr.ip().is_loopback() {
            return Err(format!(
                "IMAP listener {addr} is beyond loopback and has no TLS certificate pair"
            ));
        }
        listeners.push((Arc::new(build(pair.as_ref(), false)?), socket));
    }
    if let Some(socket) = implicit {
        let Some(pair) = pair.as_ref() else {
            return Err(
                "imaps socket is activated but no TLS certificate pair is configured".into(),
            );
        };
        listeners.push((Arc::new(build(Some(pair), true)?), socket));
    }
    Ok(Some(ImapRuntime {
        listeners,
        revocations,
        direct,
    }))
}

impl ImapRuntime {
    /// Serve until `stop` flips; sessions end with the listener.
    pub async fn run(self, mut stop: watch::Receiver<bool>) {
        // A cold registry cannot reject already-revoked password sessions.
        // Retry bounded snapshots before polling any listener, and let shutdown
        // cancel both an in-flight read and the retry delay.
        loop {
            if *stop.borrow() {
                return;
            }
            let loaded = tokio::select! {
                _ = stop.changed() => return,
                result = tokio::time::timeout(std::time::Duration::from_secs(2), self.revocations.refresh_once()) => matches!(result, Ok(Ok(()))),
            };
            if loaded {
                break;
            }
            eprintln!("IMAP revocation snapshot unavailable; retrying before accepting sessions");
            tokio::select! {
                _ = stop.changed() => return,
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {},
            }
        }
        let mut tasks = tokio::task::JoinSet::new();
        let mut revoked_stop = stop.clone();
        tasks.spawn(async move {
            let _ = self
                .revocations
                .run(self.direct, async move {
                    while !*revoked_stop.borrow() {
                        if revoked_stop.changed().await.is_err() {
                            break;
                        }
                    }
                })
                .await;
        });
        for (server, listener) in self.listeners {
            let stop = stop.clone();
            tasks.spawn(async move {
                let _ = server.serve(listener, stop).await;
            });
        }
        while tasks.join_next().await.is_some() {}
    }
}

/// Go's `webhookDispatcher.Dispatch(NewCloudEvent("mailserver/auth", ...))` at each IMAP
/// LOGIN / AUTHENTICATE outcome: a generic event, so only organization subscriptions
/// receive it.
pub struct AuthEvents(pub crate::webhook::Dispatcher);

impl AuthEvents {
    fn event(kind: &str, email: &str, provider: &str, ip: &str) -> crate::webhook::CloudEvent {
        crate::webhook::CloudEvent::new(
            "mailserver/auth",
            kind,
            serde_json::json!({"email": email, "provider": provider, "ip": ip}),
        )
    }
}

impl AuthWebhooks for AuthEvents {
    fn login<'a>(
        &'a self,
        email: &'a str,
        provider: &'a str,
        ip: &'a str,
    ) -> futures_util::future::BoxFuture<'a, ()> {
        Box::pin(async move {
            self.0
                .dispatch(&Self::event("auth.login", email, provider, ip))
                .await
        })
    }

    fn login_failed<'a>(
        &'a self,
        email: &'a str,
        provider: &'a str,
        ip: &'a str,
    ) -> futures_util::future::BoxFuture<'a, ()> {
        Box::pin(async move {
            self.0
                .dispatch(&Self::event("auth.login_failed", email, provider, ip))
                .await
        })
    }
}

/// Load shared policy and subscribe before activating a password listener.
pub async fn security(
    settings: &crate::configuration::Settings,
) -> Result<(Arc<setjoin_threat::Gate>, setjoin_threat::Watchers), String> {
    shared_security(settings, &["imap"]).await
}

/// The one process-wide threat gate for every activated password protocol
/// (IMAP #345, SMTP submission #501): each activated protocol must already be
/// listed in `GO_LISTENERS_OFF`.
pub async fn shared_security(
    settings: &crate::configuration::Settings,
    protocols: &[&str],
) -> Result<(Arc<setjoin_threat::Gate>, setjoin_threat::Watchers), String> {
    let off = std::env::var("GO_LISTENERS_OFF").unwrap_or_default();
    for protocol in protocols {
        if !off.split(',').any(|v| v.trim() == *protocol) {
            return Err(format!(
                "{protocol} sockets require GO_LISTENERS_OFF={protocol} before Rust activation"
            ));
        }
    }
    let request = settings.string("db.dsn");
    if request.is_empty() {
        return Err("DB_DSN is required for the protocol threat gate".into());
    }
    let direct = settings.string("db.direct_dsn");
    let worker = settings.string("db.worker_dsn");
    let exec = setjoin_pg::ScopedExecutor::from_dsn(&request, 4).map_err(|e| e.0)?;
    let worker = setjoin_pg::workers::WorkerDatabase::from_dsns(&request, Some(&worker))
        .map_err(|e| e.to_string())?;
    let config = setjoin_threat::Config::from_lookup(&|_, path| {
        let value = settings.string(path);
        (!value.is_empty()).then_some(value)
    })?;
    let gate = setjoin_threat::Gate::load(
        exec,
        worker,
        config,
        setjoin_authz::geoip::CountryDb::from_env(),
    )
    .await
    .map_err(|e| format!("protocol threat gate initialization failed: {e}"))?;
    let direct = if direct.is_empty() { &request } else { &direct };
    let watchers = setjoin_threat::Watchers::start(
        gate.clone(),
        direct,
        &format!("setjoin-{}-{}", protocols.join("-"), std::process::id()),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok((gate, watchers))
}

impl setjoin_smtp::submission::AuthWebhooks for AuthEvents {
    fn login<'a>(
        &'a self,
        email: &'a str,
        provider: &'a str,
        ip: &'a str,
    ) -> futures_util::future::BoxFuture<'a, ()> {
        Box::pin(async move {
            self.0
                .dispatch(&Self::event("auth.login", email, provider, ip))
                .await
        })
    }

    fn login_failed<'a>(
        &'a self,
        email: &'a str,
        provider: &'a str,
        ip: &'a str,
    ) -> futures_util::future::BoxFuture<'a, ()> {
        Box::pin(async move {
            self.0
                .dispatch(&Self::event("auth.login_failed", email, provider, ip))
                .await
        })
    }
}
