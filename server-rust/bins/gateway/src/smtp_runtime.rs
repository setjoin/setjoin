//! The SMTP listener swap (#501): Rust serves inbound SMTP (`smtp`, :25),
//! the implicit-TLS inbound variant (`smtps`) and submission (`submission`,
//! :587) on sockets systemd holds, and frozen Go's listeners are off. There is no
//! TCP proxy and no runtime switch back to Go.
//!
//! Startup refuses (the gateway does not run) rather than serve wrongly:
//! - Go's copy must be off: `GO_LISTENERS_OFF` lists `smtp` for the inbound and
//!   implicit-TLS sockets and `submission` for the MSA socket.
//! - Submission needs the shared threat gate (#420) and the webhook dispatcher;
//!   there is no allow-all gate to pass instead.
//! - `smtps` needs a certificate pair; submission needs one unless it listens on
//!   loopback (Go's `config.Validate`). Plain `smtp` has no STARTTLS, as in Go.
//!
//! Settings (the dedicated smtp.env, no owner DSNs): `DB_DSN`, `DB_WORKER_DSN`
//! (cross-tenant delivery/send runs on the worker credential, like Go's
//! `workerPool`), `DB_DIRECT_DSN`, the certificate pair `SMTP_TLS_CERT_FILE` /
//! `SMTP_TLS_KEY_FILE` (fallback `TLS_CERT_FILE`/`TLS_KEY_FILE`),
//! `SMTP_INBOUND_MAX_CONNS` (200), `SMTP_SUBMISSION_MAX_CONNS` (200),
//! `SMTP_PER_USER_MAX_CONNS` (5), `SMTP_INBOUND_TLS_ENFORCE`, the S3 settings, and the
//! pre-derived link-protect keys `SMTP_LINK_PROTECT_KEY`, `SMTP_LINK_PROTECT_KEY_PREVIOUS`,
//! `SMTP_LINK_PROTECT_VERSION` (never the master `JWT_SECRET`).
use crate::recovery_worker::{ObjectStore, S3Store};
use futures_util::future::BoxFuture;
use setjoin_smtp::{
    mail_auth::{Features, MailAuth, SystemDns},
    submission::Flags,
    RawBlobs, Server, Submission,
};
use setjoin_threat::{registry::ProtocolSessionRegistry, Gate, ThreatGate};
use std::{path::PathBuf, sync::Arc};
use tokio::{net::TcpListener, sync::watch};

pub struct SmtpRuntime {
    inbound: Vec<(Arc<Server>, TcpListener)>,
    submission: Option<(Arc<Submission>, TcpListener)>,
    /// Sockets whose admin toggle is off: systemd keeps them, every connection is
    /// accepted and closed at once (Go does not bind a disabled listener).
    closed: Vec<TcpListener>,
    revocations: Arc<crate::workers::SessionDenylist>,
    direct: String,
    flags: Arc<dyn Flags>,
}

/// Live `feature_toggles` through the shared gate's authoritative snapshot.
pub struct GateFlags(pub Arc<Gate>);
impl Flags for GateFlags {
    fn enabled(&self, key: &str) -> bool {
        self.0.enabled(key)
    }
}

/// Inbound raw messages go to the content-addressed object store under their
/// reducer-referenced key before the delivery transaction (Go `rawBlobPutter`).
pub struct MessageBlobs(pub S3Store);
impl RawBlobs for MessageBlobs {
    fn put<'a>(&'a self, key: &'a str, data: &'a [u8]) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move { self.0.put(key, data, "message/rfc822").await })
    }
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

fn boolean(get: &dyn Fn(&str) -> Option<String>, var: &str) -> Result<bool, String> {
    match get(var).as_deref().map(str::trim) {
        None | Some("") | Some("false") | Some("0") => Ok(false),
        Some("true") | Some("1") => Ok(true),
        Some(_) => Err(format!("{var} must be true/false or 1/0")),
    }
}

fn inbound_config(
    get: &dyn Fn(&str) -> Option<String>,
    cache: Arc<setjoin_mail_security::smime::trust::TrustCache>,
) -> Result<setjoin_smtp::inbound::Config, String> {
    let csv = |key: &str, default: &str| {
        get(key)
            .unwrap_or_else(|| default.to_owned())
            .split(',')
            .map(|v| v.trim().to_owned())
            .collect::<Vec<_>>()
    };
    let duration = |key: &str, default: &str| -> Result<std::time::Duration, String> {
        let value = get(key)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| default.to_owned());
        if value == "0"
            || value
                .strip_prefix('-')
                .is_some_and(|v| humantime::parse_duration(v).is_ok())
        {
            return Ok(std::time::Duration::ZERO);
        }
        Ok(humantime::parse_duration(&value)
            .unwrap_or_else(|_| humantime::parse_duration(default).expect("constant duration")))
    };
    // SMTP only signs with the already-derived link-protect key; the master JWT_SECRET
    // is never read here and is not rendered into smtp.env.
    let links = crate::link_protect::TokenKeys::from_derived_env(get)?;
    let fail = get("SANDBOX_FAIL_MODE")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "open".into());
    if !matches!(fail.as_str(), "open" | "closed") {
        return Err("SANDBOX_FAIL_MODE must be open or closed".into());
    }
    let sandbox = if boolean(get, "SANDBOX_ENABLED")? {
        get("SANDBOX_CAPE_URL")
            .filter(|s| !s.is_empty())
            .map(|url| -> Result<_, String> {
                Ok(setjoin_smtp::inbound::SandboxConfig {
                    url,
                    api_key: get("SANDBOX_CAPE_API_KEY").unwrap_or_default(),
                    timeout: duration("SANDBOX_TIMEOUT", "120s")?,
                    fail_closed: fail == "closed",
                })
            })
            .transpose()?
    } else {
        None
    };
    let host = get("HOSTNAME")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "localhost".into());
    let threshold = get("ANTIPHISH_NAME_THRESHOLD")
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.85);
    Ok(setjoin_smtp::inbound::Config {
        anti_phish: true,
        clamav_addr: get("CLAMAV_ADDR").filter(|s| !s.is_empty()),
        sandbox,
        links: links.map(|k| setjoin_smtp::inbound::LinkConfig {
            key: k.current_key().to_vec(),
            version: k.version,
            clock_unix: None,
        }),
        trust_cache: cache,
        internal_domains: {
            let configured = get("INTERNAL_DOMAINS").unwrap_or_else(|| "localhost".into());
            let configured = if configured == "localhost" {
                host
            } else {
                configured
            };
            configured.split(',').map(|v| v.trim().to_owned()).collect()
        },
        protected_domains: csv("PROTECTED_DOMAINS", ""),
        name_threshold: threshold,
        user_cache_ttl: duration("ANTIPHISH_USER_CACHE_TTL", "5m")?,
    })
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
        pick("SMTP_TLS_CERT_FILE", "TLS_CERT_FILE")
            .or_else(|| get("TLS_CERT").filter(|v| !v.is_empty())),
        pick("SMTP_TLS_KEY_FILE", "TLS_KEY_FILE")
            .or_else(|| get("TLS_KEY").filter(|v| !v.is_empty())),
    ) {
        (Some(cert), Some(key)) => Ok(Some((cert.into(), key.into()))),
        (None, None) => Ok(None),
        _ => Err("SMTP TLS needs both a certificate and a key file".into()),
    }
}

/// Which `GO_LISTENERS_OFF` names the activated sockets require.
pub fn required_off(inbound: bool, implicit: bool, submission: bool) -> Vec<&'static str> {
    let mut names = Vec::new();
    if inbound || implicit {
        names.push("smtp");
    }
    if submission {
        names.push("submission");
    }
    names
}

/// Build the listeners from the sockets systemd handed over. `None` when none
/// were passed (Go still owns SMTP).
#[allow(clippy::too_many_arguments)]
pub fn start(
    inbound: Option<TcpListener>,
    implicit: Option<TcpListener>,
    submission: Option<TcpListener>,
    get: &dyn Fn(&str) -> Option<String>,
    gate: Option<Arc<Gate>>,
    webhooks: Option<crate::webhook::Dispatcher>,
) -> Result<Option<SmtpRuntime>, String> {
    let cache = Arc::new(setjoin_mail_security::smime::trust::TrustCache::new());
    // Standalone callers have no invalidation listener: never retain stale trust.
    cache.set_cached(false);
    start_with_trust_cache(inbound, implicit, submission, get, gate, webhooks, cache)
}

/// Production shares this cache with its process-local config listener.
#[allow(clippy::too_many_arguments)]
pub fn start_with_trust_cache(
    inbound: Option<TcpListener>,
    implicit: Option<TcpListener>,
    submission: Option<TcpListener>,
    get: &dyn Fn(&str) -> Option<String>,
    gate: Option<Arc<Gate>>,
    webhooks: Option<crate::webhook::Dispatcher>,
    cache: Arc<setjoin_mail_security::smime::trust::TrustCache>,
) -> Result<Option<SmtpRuntime>, String> {
    if inbound.is_none() && implicit.is_none() && submission.is_none() {
        return Ok(None);
    }
    for name in required_off(inbound.is_some(), implicit.is_some(), submission.is_some()) {
        if !listed(get, "GO_LISTENERS_OFF", name) {
            return Err(format!(
                "SMTP sockets are activated but GO_LISTENERS_OFF does not list {name}: Go's listener must be off first"
            ));
        }
    }
    let Some(webhooks) = webhooks else {
        return Err(
            "SMTP activation refused: the webhook dispatcher is not wired; Rust SMTP would drop mail.received/mail.sent/auth events"
                .into(),
        );
    };
    let Some(gate) = gate else {
        return Err(
            "SMTP activation refused: the shared flag/threat gate (#420) is not wired".into(),
        );
    };
    // Go reads feature.smtp_inbound / feature.smtp_submission once at startup and
    // does not bind a disabled listener; the sockets stay but nothing is served.
    let mut closed = Vec::new();
    let (inbound, implicit) = if gate.enabled("feature.smtp_inbound") {
        (inbound, implicit)
    } else {
        eprintln!("SMTP inbound disabled by feature toggle");
        closed.extend(inbound.into_iter().chain(implicit));
        (None, None)
    };
    let submission = if gate.enabled("feature.smtp_submission") {
        submission
    } else {
        eprintln!("SMTP submission disabled by feature toggle");
        closed.extend(submission);
        None
    };
    let dsn = get("DB_DSN")
        .filter(|v| !v.is_empty())
        .ok_or("DB_DSN is required for SMTP")?;
    let worker_dsn = get("DB_WORKER_DSN");
    let db = setjoin_pg::workers::WorkerDatabase::from_dsns(&dsn, worker_dsn.as_deref())
        .map_err(|e| e.to_string())?
        .with_audit_keys(
            get("DB_ENCRYPTION_KEY").unwrap_or_default(),
            get("AUDIT_HMAC_KEY").unwrap_or_default(),
        );
    let direct = get("DB_DIRECT_DSN")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| dsn.clone());
    let pair = certificate_pair(get)?;
    let flags: Arc<dyn Flags> = Arc::new(GateFlags(gate.clone()));
    let inbound_max: usize = number(get, "SMTP_INBOUND_MAX_CONNS", 200)?;
    let submission_max: usize = number(get, "SMTP_SUBMISSION_MAX_CONNS", 200)?;
    let per_user: i64 = number(get, "SMTP_PER_USER_MAX_CONNS", 5)?;
    let enforce = boolean(get, "SMTP_INBOUND_TLS_ENFORCE")?;
    let blobs = Arc::new(MessageBlobs(S3Store::from_env()?));
    let registry = Arc::new(ProtocolSessionRegistry::default());
    let revocations = Arc::new(crate::workers::SessionDenylist::new(db.clone()));
    revocations.attach_protocol(registry.clone());
    let dns = Arc::new(SystemDns::new()?);
    let pipeline = inbound_config(get, cache)?;
    let inbound_server = || -> Server {
        Server::new()
            .with_database(db.clone())
            .with_spam_store(Arc::new(
                setjoin_spam::Store::new(db.clone()).with_stats(setjoin_spam::process_stats()),
            ))
            .with_mail_auth(MailAuth::new(Features::default(), dns.clone()))
            .with_flags(flags.clone())
            .with_inbound_config(pipeline.clone())
            .with_delivery_events(Arc::new(crate::smtp_events::DeliveryEvents(
                webhooks.clone(),
            )))
            .with_blob_store(blobs.clone())
            .with_max_connections(inbound_max)
            .with_tls_enforce(enforce)
    };
    let mut inbound_listeners = Vec::new();
    if let Some(socket) = inbound {
        inbound_listeners.push((Arc::new(inbound_server()), socket));
    }
    if let Some(socket) = implicit {
        let Some((cert, key)) = pair.clone() else {
            return Err(
                "smtps socket is activated but no TLS certificate pair is configured".into(),
            );
        };
        inbound_listeners.push((
            Arc::new(inbound_server().with_tls_files(cert, key)?),
            socket,
        ));
    }
    let mut msa = None;
    if let Some(socket) = submission {
        let addr = socket
            .local_addr()
            .map_err(|e| format!("submission socket address: {e}"))?;
        if pair.is_none() && !addr.ip().is_loopback() {
            return Err(format!(
                "submission listener {addr} is beyond loopback and has no TLS certificate pair"
            ));
        }
        let mut server = Submission::new(db.clone())
            .with_threat_gate(gate.clone() as Arc<dyn ThreatGate>)
            .with_auth_webhooks(Arc::new(crate::imap_runtime::AuthEvents(webhooks.clone())))
            .with_events(Arc::new(crate::smtp_events::SubmissionEvents(
                webhooks.clone(),
            )))
            .with_flags(flags.clone())
            .with_dummy_hash(setjoin_identity::login::dummy_hash(
                setjoin_config_secret::CryptoProfile::parse(
                    &get("CRYPTO_ALGORITHM_PROFILE").unwrap_or_default(),
                ),
            ))
            .with_blob_store(blobs.clone())
            .with_max_connections(submission_max)
            .with_per_user_max(per_user)
            .with_session_registry(registry.clone());
        if let Some((cert, key)) = pair.clone() {
            server = server.with_starttls_files(cert, key)?;
        }
        if !server.threat_enforced() || !server.webhooks_wired() {
            return Err("submission activation refused: threat/webhook policy is not wired".into());
        }
        msa = Some((Arc::new(server), socket));
    }
    Ok(Some(SmtpRuntime {
        inbound: inbound_listeners,
        submission: msa,
        closed,
        revocations,
        direct,
        flags,
    }))
}

impl SmtpRuntime {
    /// Serve until `stop` flips; sessions end with the listener.
    pub async fn run(self, mut stop: watch::Receiver<bool>) {
        // A cold registry cannot reject already-revoked password sessions: load a
        // bounded snapshot before the submission listener accepts (as IMAP does).
        if self.submission.is_some() {
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
                eprintln!(
                    "SMTP revocation snapshot unavailable; retrying before accepting sessions"
                );
                tokio::select! {
                    _ = stop.changed() => return,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {},
                }
            }
        }
        let mut tasks = tokio::task::JoinSet::new();
        if !self.inbound.is_empty() {
            let flags = self.flags.clone();
            let mut stopped = stop.clone();
            tasks.spawn(async move {
                let mut previous=None;
                loop {
                    let current=flags.enabled("feature.spam_model_batch_load");
                    if previous!=Some(current) {
                        if current {
                            eprintln!("SMTP warning: spam model batch loading ENABLED (feature.spam_model_batch_load) — INCREASES MEMORY FOOTPRINT: models for the scoring batch are held resident (~24 MB per user model at the default 2^20 feature size, up to 50 models per active inbound connection); a model trained mid-batch is seen by scoring only after the batch boundary. Disable the toggle to restore per-message model loads");
                        } else {eprintln!("SMTP: spam model batch loading disabled (feature.spam_model_batch_load) — per-message model loads (historical behavior)");}
                        previous=Some(current);
                    }
                    tokio::select! {_=stopped.changed()=>return,_=tokio::time::sleep(std::time::Duration::from_secs(1))=>{}}
                }
            });
        }
        if self.submission.is_some() {
            let mut revoked_stop = stop.clone();
            let revocations = self.revocations.clone();
            let direct = self.direct.clone();
            tasks.spawn(async move {
                let _ = revocations
                    .run(direct, async move {
                        while !*revoked_stop.borrow() {
                            if revoked_stop.changed().await.is_err() {
                                break;
                            }
                        }
                    })
                    .await;
            });
        }
        for (server, listener) in self.inbound {
            let stop = stop.clone();
            tasks.spawn(async move {
                let _ = server.serve(listener, stop).await;
            });
        }
        if let Some((server, listener)) = self.submission {
            let stop = stop.clone();
            tasks.spawn(async move {
                let _ = server.serve(listener, stop).await;
            });
        }
        for listener in self.closed {
            let mut stop = stop.clone();
            tasks.spawn(async move {
                loop {
                    tokio::select! {
                        _ = stop.changed() => return,
                        accepted = listener.accept() => { drop(accepted); }
                    }
                }
            });
        }
        while tasks.join_next().await.is_some() {}
    }
}

/// An SMTP configuration problem (certificates, S3, DNS, gate) never takes the
/// HTTPS front door down: it is logged and SMTP simply is not started. The
/// activated sockets stay with systemd and the Go listeners remain off.
pub fn start_or_log(result: Result<Option<SmtpRuntime>, String>) -> Option<SmtpRuntime> {
    match result {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("SMTP not started: {error}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| map.get(name).cloned()
    }
    fn hooks() -> Option<crate::webhook::Dispatcher> {
        Some(crate::webhook::Dispatcher::new(
            setjoin_pg::workers::WorkerDatabase::new("postgres://nobody@127.0.0.1:9/none").unwrap(),
            None,
        ))
    }
    async fn socket() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").await.unwrap()
    }

    #[test]
    fn inbound_links_use_only_the_derived_key_never_the_master_secret() {
        let cache = || Arc::new(setjoin_mail_security::smime::trust::TrustCache::default());
        let key = "ab".repeat(32);
        let derived = inbound_config(
            &env(&[
                ("SMTP_LINK_PROTECT_KEY", &key),
                ("SMTP_LINK_PROTECT_VERSION", "3"),
            ]),
            cache(),
        )
        .unwrap();
        let links = derived.links.unwrap();
        assert_eq!((links.key, links.version), (vec![0xab; 32], 3));
        // JWT_SECRET alone no longer enables link signing: SMTP never reads it.
        let master =
            inbound_config(&env(&[("JWT_SECRET", "x".repeat(40).as_str())]), cache()).unwrap();
        assert!(master.links.is_none());
        assert!(inbound_config(&env(&[("SMTP_LINK_PROTECT_KEY", "short")]), cache()).is_err());
    }

    #[test]
    fn required_names_follow_the_activated_sockets() {
        assert_eq!(required_off(true, false, false), vec!["smtp"]);
        assert_eq!(required_off(false, true, false), vec!["smtp"]);
        assert_eq!(required_off(false, false, true), vec!["submission"]);
        assert_eq!(required_off(true, true, true), vec!["smtp", "submission"]);
        assert!(required_off(false, false, false).is_empty());
    }

    #[tokio::test]
    async fn no_socket_means_go_still_owns_smtp() {
        let result = start(None, None, None, &env(&[]), None, None);
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn activation_requires_go_to_be_off_for_each_socket() {
        let err = |r: Result<Option<SmtpRuntime>, String>| r.err().expect("refused");
        let e = err(start(
            Some(socket().await),
            None,
            None,
            &env(&[]),
            None,
            hooks(),
        ));
        assert!(e.contains("does not list smtp"), "{e}");
        // `smtp` off does not free submission.
        let e = err(start(
            None,
            None,
            Some(socket().await),
            &env(&[("GO_LISTENERS_OFF", "smtp")]),
            None,
            hooks(),
        ));
        assert!(e.contains("does not list submission"), "{e}");
        let e = err(start(
            Some(socket().await),
            None,
            None,
            &env(&[("GO_LISTENERS_OFF", "imap, submission")]),
            None,
            hooks(),
        ));
        assert!(e.contains("does not list smtp"), "{e}");
    }

    #[tokio::test]
    async fn dispatcher_and_gate_are_mandatory() {
        let off = env(&[
            ("GO_LISTENERS_OFF", "smtp,submission"),
            ("DB_DSN", "postgres://x@127.0.0.1:9/d"),
        ]);
        let e = start(Some(socket().await), None, None, &off, None, None)
            .err()
            .expect("refused");
        assert!(e.contains("webhook dispatcher"), "{e}");
        let e = start(Some(socket().await), None, None, &off, None, hooks())
            .err()
            .expect("refused");
        assert!(e.contains("gate"), "{e}");
    }

    #[tokio::test]
    async fn a_configuration_error_is_logged_and_smtp_stays_down() {
        // Go's listener not off: start() refuses, start_or_log() keeps the process
        // (and its HTTPS front door) alive with no SMTP runtime.
        let refused = start(Some(socket().await), None, None, &env(&[]), None, hooks());
        assert!(refused.is_err());
        assert!(start_or_log(refused).is_none());
        assert!(start_or_log(Ok(None)).is_none());
    }

    #[test]
    fn certificate_pair_needs_both_halves_and_falls_back_to_tls_cert() {
        assert!(certificate_pair(&env(&[])).unwrap().is_none());
        assert!(certificate_pair(&env(&[("SMTP_TLS_CERT_FILE", "/c")])).is_err());
        let (c, k) = certificate_pair(&env(&[("TLS_CERT", "/c"), ("TLS_KEY", "/k")]))
            .unwrap()
            .unwrap();
        assert_eq!((c.to_str(), k.to_str()), (Some("/c"), Some("/k")));
        let (c, _) = certificate_pair(&env(&[
            ("SMTP_TLS_CERT_FILE", "/s"),
            ("SMTP_TLS_KEY_FILE", "/k"),
            ("TLS_CERT", "/c"),
            ("TLS_KEY", "/k"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(c.to_str(), Some("/s"));
    }
}
