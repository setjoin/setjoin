//! Worker builders extracted from `bins/gateway/src/main.rs` (#543).

use std::sync::Arc;

use crate::workers::SessionDenylist;
use setjoin_pg::workers::WorkerDatabase;
use setjoin_pg::ScopedExecutor;

pub(super) fn listed(var: &str, name: &str) -> bool {
    std::env::var(var)
        .unwrap_or_default()
        .split(',')
        .any(|s| s.trim() == name)
}

/// The LDAP runtime (#380): routes and the optional `ldap-sync` worker share
/// it. `RUST_WORKERS_ON=ldap-sync` requires `GO_WORKERS_OFF=ldap-sync` first, so
/// two copies never sync one directory.
pub(super) fn ldap_runtime(
) -> Result<Option<Arc<crate::directory_sync_workers::LdapRuntime>>, String> {
    let Some(request) = std::env::var("DB_DSN").ok().filter(|s| !s.is_empty()) else {
        if listed("RUST_WORKERS_ON", "ldap-sync") {
            return Err("DB_DSN is required for ldap-sync".into());
        }
        return Ok(None);
    };
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?;
    Ok(Some(Arc::new(
        crate::directory_sync_workers::LdapRuntime::from_env(db),
    )))
}

/// Scoped `WEBHOOK_SECRET_KEY`, falling back to `JWT_SECRET` in co-located /
/// legacy deployments (Go's `sharedwebhook.NewSecretCodec`).
pub(super) fn webhook_codec() -> setjoin_platform::webhook_secret::SecretCodec {
    let secret = std::env::var("WEBHOOK_SECRET_KEY")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("JWT_SECRET").ok().filter(|s| !s.is_empty()))
        .unwrap_or_default();
    setjoin_platform::webhook_secret::SecretCodec::new(
        secret.as_bytes(),
        setjoin_config_secret::CryptoProfile::parse(
            &std::env::var("CRYPTO_ALGORITHM_PROFILE").unwrap_or_default(),
        ),
    )
}

/// The AD runtime (#381): the four AD runtime routes and the optional
/// `ad-sync` worker share it. The resolved boot YAML/env pins Go's enable
/// value. Disabled handlers still exist and answer their native auth/config
/// outcomes; only shared-effect workers require the enable value to be true.
pub(super) fn ad_runtime() -> Result<Option<Arc<crate::directory_sync_workers::AdRuntime>>, String>
{
    let wanted = ["ad-sync", "ad-toggle-observer"]
        .iter()
        .any(|name| listed("RUST_WORKERS_ON", name));
    if !crate::directory_sync_workers::ad_runtime::enabled_from_env() {
        if wanted {
            return Err("ad-sync and ad-toggle-observer need AD_SYNC_ENABLED=true in the resolved startup configuration".into());
        }
    }
    let Some(request) = std::env::var("DB_DSN").ok().filter(|s| !s.is_empty()) else {
        if wanted {
            return Err("DB_DSN is required for ad-sync".into());
        }
        return Ok(None);
    };
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?;
    Ok(Some(Arc::new(
        crate::directory_sync_workers::AdRuntime::from_env(db),
    )))
}

/// What the identity workers share: the direct DSN the observers listen on and
/// the coalesced trigger the identity runtime waits on.
pub(super) struct IdentityWorkers {
    pub(super) direct: Option<String>,
    pub(super) trigger: Arc<tokio::sync::Notify>,
    /// The catalog source manager when `identity-source-runtime` is Rust's.
    pub(super) runtime: Option<Arc<crate::directory_sync_workers::IdentitySourceRuntime>>,
}

/// Go's `DecodeIdentitySourceRuntime`, owned by the identity-admin family.
pub(super) fn decode_source(
    codec: Option<&setjoin_config_secret::ConfigSecretCodec>,
    key: &str,
    kind: &str,
    envelope: &[u8],
) -> Result<crate::directory_sync_workers::SourceConfig, String> {
    setjoin_admin_identity::idv2_source::decode_runtime(codec, key, kind, envelope)
        .map(crate::directory_sync::source_config)
}

/// `identity-source-runtime` (#400): Rust starts the catalog manager only with
/// Go's copy off (`GO_WORKERS_OFF`), on the worker credential (`DB_WORKER_DSN`,
/// falling back to `DB_DSN`).
pub(super) fn identity_source_runtime(
) -> Result<Option<Arc<crate::directory_sync_workers::IdentitySourceRuntime>>, String> {
    if !listed("RUST_WORKERS_ON", "identity-source-runtime") {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for identity-source-runtime")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?;
    Ok(Some(Arc::new(
        crate::directory_sync_workers::IdentitySourceRuntime::from_env(db, decode_source),
    )))
}

/// The Admin identity job workers Rust runs (#412): each needs `RUST_WORKERS_ON=<name>`
/// and Go's copy off (`GO_WORKERS_OFF=<name>`), on the worker credential with the
/// deployment audit keys. `identity-transitions` also takes Go's LiveKit settings
/// (`LIVEKIT_API_KEY`, `LIVEKIT_API_SECRET`, `LIVEKIT_URL`); without all three it runs
/// with no SFU, as Go's nil `meetRooms`.
pub(super) struct AdminJobs {
    pub(super) bulk: Option<Arc<crate::admin_job_workers::BulkRoleJobs>>,
    pub(super) eap: Option<Arc<crate::admin_job_workers::EapJobs>>,
    pub(super) operations: Option<Arc<crate::admin_job_workers::IdentityOperations>>,
    pub(super) transitions: Option<Arc<crate::admin_job_workers::IdentityTransitions>>,
}

pub(super) fn admin_job_workers() -> Result<AdminJobs, String> {
    use crate::admin_job_workers as jobs;
    const NAMES: [&str; 4] = [
        "bulk-role-jobs",
        "email-address-policy-jobs",
        "identity-operations",
        "identity-transitions",
    ];
    if !NAMES.iter().any(|name| listed("RUST_WORKERS_ON", name)) {
        return Ok(AdminJobs {
            bulk: None,
            eap: None,
            operations: None,
            transitions: None,
        });
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for the Admin identity job workers")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?
        .with_audit_keys(
            std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
            std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
        );
    let key = std::env::var("LIVEKIT_API_KEY").unwrap_or_default();
    let secret = std::env::var("LIVEKIT_API_SECRET").unwrap_or_default();
    let url = std::env::var("LIVEKIT_URL").unwrap_or_default();
    let rooms = (!key.is_empty() && !secret.is_empty() && !url.is_empty()).then(|| jobs::Rooms {
        endpoint: url,
        key,
        secret,
    });
    Ok(AdminJobs {
        bulk: listed("RUST_WORKERS_ON", "bulk-role-jobs")
            .then(|| Arc::new(jobs::BulkRoleJobs { db: db.clone() })),
        eap: listed("RUST_WORKERS_ON", "email-address-policy-jobs")
            .then(|| Arc::new(jobs::EapJobs::new(db.clone()))),
        operations: listed("RUST_WORKERS_ON", "identity-operations")
            .then(|| Arc::new(jobs::IdentityOperations::new(db.clone()))),
        transitions: listed("RUST_WORKERS_ON", "identity-transitions")
            .then(|| Arc::new(jobs::IdentityTransitions::new(db.clone(), rooms))),
    })
}

pub(super) fn identity_workers() -> Result<IdentityWorkers, String> {
    let observing = ["ad-toggle-observer", "identity-toggle-observer"]
        .iter()
        .any(|name| listed("RUST_WORKERS_ON", name));
    let direct = std::env::var("DB_DIRECT_DSN")
        .ok()
        .filter(|s| !s.is_empty());
    if observing && direct.is_none() {
        return Err("DB_DIRECT_DSN is required for the toggle observers".into());
    }
    let runtime = identity_source_runtime()?;
    // The observer wakes the manager when Rust runs it; otherwise the signal
    // has no consumer and only Go's own manager (30 s poll) reconciles.
    let trigger = runtime
        .as_ref()
        .map(|r| r.trigger.clone())
        .unwrap_or_default();
    Ok(IdentityWorkers {
        direct: direct.filter(|_| observing),
        trigger,
        runtime,
    })
}

pub(super) fn session_worker() -> Result<Option<(Arc<SessionDenylist>, String)>, String> {
    let configured = std::env::var("RUST_WORKERS_ON").unwrap_or_default();
    let names: Vec<_> = configured
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect();
    if names.iter().any(|name| {
        !name.starts_with("cron:")
            && !matches!(
                *name,
                "session-denylist-refresh"
                    | "backup-engine"
                    | "mail-recovery-cleanup"
                    | "approval-notify"
                    | "guest-lifecycle"
                    | "chat-unfurl-reap"
                    | "booking-expiry"
                    | "user-risk"
                    | "mdm-notify"
                    | "calendar-subscription-sync"
                    | "notify-intent-drain"
                    | "security-event-delivery"
                    | "tls-rpt-report"
                    | "smime-trust-listener"
                    | "spam-trainer"
                    | "meet-reconcile"
                    | "dmarc-report"
                    | "push-intent-drain"
                    | "drive-watch"
                    | "drive-maintenance"
                    | "drive-preview"
                    | "blob-cleanup"
                    | "blob-gc"
                    | "exchange-assessment-deletion"
                    | "ldap-sync"
                    | "ad-sync"
                    | "ad-toggle-observer"
                    | "identity-toggle-observer"
                    | "identity-source-runtime"
                    | "identity-metrics"
                    | "bulk-role-jobs"
                    | "email-address-policy-jobs"
                    | "identity-operations"
                    | "identity-transitions"
                    | "mail-work"
                    | "mailbox-lifecycle"
                    | "migration-runner"
                    | "webhook-publications"
                    | "webhook-retry"
                    | "cert-monitor"
                    | "tls-ticket-keys"
                    | "http-tls"
                    | "http-h2c"
                    | "setup-control"
                    | "federation-residue-reap"
                    | "outbound-mail"
                    | "work-queue"
            )
    }) {
        return Err("RUST_WORKERS_ON contains an unknown worker".into());
    }
    if names.contains(&"tls-ticket-keys") {
        eprintln!(
            "setjoin-gateway: RUST_WORKERS_ON contains retired worker `tls-ticket-keys` (#560); ignoring (rustls now manages TLS session tickets in-process; run upgrade.sh refresh-gateway-env to clean config.env)"
        );
    }
    if !names.contains(&"session-denylist-refresh") {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|dsn| !dsn.is_empty())
        .ok_or("DB_DSN is required for workers")?;
    let direct = std::env::var("DB_DIRECT_DSN")
        .ok()
        .filter(|dsn| !dsn.is_empty())
        .ok_or("DB_DIRECT_DSN is required for the session listener")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|err| format!("DB_WORKER_DSN: {err}"))?;
    Ok(Some((Arc::new(SessionDenylist::new(db)), direct)))
}

pub(super) fn recovery_worker(
) -> Result<Option<crate::recovery_worker::RecoveryCleanup<crate::recovery_worker::S3Store>>, String>
{
    use crate::recovery_worker::{RecoveryCleanup, S3Store};
    let configured = std::env::var("RUST_WORKERS_ON").unwrap_or_default();
    if !configured
        .split(',')
        .any(|name| name.trim() == "mail-recovery-cleanup")
    {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN").map_err(|_| "DB_DSN is required for workers")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|err| format!("DB_WORKER_DSN: {err}"))?
        .with_audit_keys(
            std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
            std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
        );
    Ok(Some(RecoveryCleanup::new(
        db,
        Arc::new(S3Store::from_env()?),
    )))
}

pub(super) async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

pub(super) fn approval_worker(
) -> Result<Option<(setjoin_approvals::notify::ApprovalNotify, String)>, String> {
    if !std::env::var("RUST_WORKERS_ON")
        .unwrap_or_default()
        .split(',')
        .any(|s| s.trim() == "approval-notify")
    {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN").map_err(|_| "DB_DSN is required for workers")?;
    let worker = std::env::var("DB_WORKER_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or(request);
    let _ = WorkerDatabase::new(&worker).map_err(|_| "invalid worker DSN")?;
    let direct = std::env::var("DB_DIRECT_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DIRECT_DSN is required for approval-notify")?;
    let _ = WorkerDatabase::new(&direct).map_err(|_| "invalid direct DSN")?;
    let secret = crate::approvals::link_secret_from_env();
    let hostname = std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".into());
    Ok(Some((
        setjoin_approvals::notify::ApprovalNotify::new(
            worker,
            secret,
            format!("https://{hostname}"),
        ),
        direct,
    )))
}

pub(super) fn guest_lifecycle() -> Result<Option<Arc<crate::guest_worker::GuestLifecycle>>, String>
{
    let request = std::env::var("DB_DSN").ok().filter(|s| !s.is_empty());
    let requested = std::env::var("RUST_WORKERS_ON")
        .unwrap_or_default()
        .split(',')
        .any(|s| s.trim() == "guest-lifecycle");
    let Some(request) = request else {
        if requested {
            return Err("DB_DSN is required for guest-lifecycle".into());
        }
        return Ok(None);
    };
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?
        .with_audit_keys(
            std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
            std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
        );
    let key = std::env::var("LIVEKIT_API_KEY").unwrap_or_default();
    let secret = std::env::var("LIVEKIT_API_SECRET").unwrap_or_default();
    let url = std::env::var("LIVEKIT_URL").unwrap_or_default();
    let endpoint = if key.is_empty() || secret.is_empty() || url.is_empty() {
        None
    } else {
        Some(url)
    };
    Ok(Some(Arc::new(crate::guest_worker::GuestLifecycle {
        db,
        endpoint,
        key,
        secret,
    })))
}

/// `RUST_WORKERS_ON=booking-expiry` takes Go's booking sweeper; two sweeps
/// would race on the same rows, so Go must be off first.
pub(super) fn booking_expiry() -> Result<Option<crate::booking_worker::BookingExpiry>, String> {
    if !listed("RUST_WORKERS_ON", "booking-expiry") {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for booking-expiry")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?
        .with_audit_keys(
            std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
            std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
        );
    Ok(Some(crate::booking_worker::BookingExpiry::new(db)))
}

/// `RUST_WORKERS_ON=user-risk` takes Go's user-risk cron (#314); two scorers would run the
/// same reducer per user, so Go must be off first (`GO_WORKERS_OFF=user-risk`).
pub(super) fn user_risk_worker() -> Result<Option<crate::user_risk_worker::UserRisk>, String> {
    if !listed("RUST_WORKERS_ON", "user-risk") {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for user-risk")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?
        .with_audit_keys(
            std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
            std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
        );
    Ok(Some(crate::user_risk_worker::UserRisk::new(db)))
}

/// The process's webhook dispatcher (#302): Rust handlers dispatch through it and the two
/// workers below drive its durable queue. It needs the request DSN (the worker credential
/// falls back to it, as in Go); without one nothing in this process can deliver.
pub(super) fn webhook_dispatcher() -> Result<Option<crate::webhook::Dispatcher>, String> {
    let Some(request) = std::env::var("DB_DSN").ok().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?;
    Ok(Some(crate::webhook::Dispatcher::new(
        db,
        Some(webhook_codec()),
    )))
}

/// `RUST_WORKERS_ON=webhook-publications` and `=webhook-retry` take Go's two durable
/// webhook workers. Both write rows and send HTTP, so a second copy would double every
/// delivery attempt: Go must be off first (leases bound the damage but not the noise).
#[allow(clippy::type_complexity)]
pub(super) fn webhook_workers(
    dispatcher: Option<&crate::webhook::Dispatcher>,
) -> Result<
    (
        Option<crate::webhook::PublicationWorker>,
        Option<crate::webhook::RetryWorker>,
    ),
    String,
> {
    use crate::webhook::{PUBLICATIONS, RETRY};
    let wanted = |name| listed("RUST_WORKERS_ON", name);
    if (wanted(PUBLICATIONS) || wanted(RETRY)) && dispatcher.is_none() {
        return Err("DB_DSN is required for the webhook workers".into());
    }
    Ok((
        dispatcher
            .filter(|_| wanted(PUBLICATIONS))
            .map(|d| crate::webhook::PublicationWorker::new(d.clone())),
        dispatcher
            .filter(|_| wanted(RETRY))
            .map(|d| crate::webhook::RetryWorker::new(d.clone())),
    ))
}

/// `notify-intent-drain` (#408, Wave 2.1 #548): runs unconditionally in
/// `setjoind` (`always_on = true`) whenever `DB_DSN` is present, and in legacy
/// `setjoin-server` when `RUST_WORKERS_ON` lists `notify-intent-drain`.
pub(super) fn notify_drain_worker(
    always_on: bool,
) -> Result<Option<crate::notify_drain::NotifyIntentDrain>, String> {
    use crate::notify_drain::NAME;
    let explicit = listed("RUST_WORKERS_ON", NAME);
    if !explicit && !always_on {
        return Ok(None);
    }
    let Some(request) = std::env::var("DB_DSN").ok().filter(|s| !s.is_empty()) else {
        if explicit {
            return Err("DB_DSN is required for notify-intent-drain".into());
        }
        return Ok(None);
    };
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?;
    Ok(Some(crate::notify_drain::NotifyIntentDrain::new(db)))
}

/// Durable WorkQueue consumer (`work-queue`, Wave 2.1 #548): promotes due
/// `scheduled_actions` to `'enqueued'` and executes `scheduled_action.*` items
/// atomically in one `WorkerTx`. Gated on `RUST_WORKERS_ON=work-queue` or
/// `always_on` (`setjoind` with `subsystems.workers`).
///
/// Verifies that the pool role holds `rolbypassrls OR rolsuper` before
/// activating so constrained-DSN setups never suppress legacy
/// `dispatch-scheduled-actions` without a working WorkQueue consumer.
pub(super) async fn work_queue_worker(
    always_on: bool,
    listen_hub: Option<setjoin_pg::ListenHub>,
) -> Result<Option<setjoin_workqueue::WorkScheduledActionConsumer>, String> {
    let explicit = listed("RUST_WORKERS_ON", "work-queue");
    if !explicit && !always_on {
        return Ok(None);
    }
    let Some(request) = std::env::var("DB_DSN").ok().filter(|s| !s.is_empty()) else {
        if explicit {
            return Err("DB_DSN is required for work-queue".into());
        }
        return Ok(None);
    };
    let worker_dsn = std::env::var("DB_WORKER_DSN")
        .ok()
        .filter(|s| !s.is_empty());
    let dsn = worker_dsn.as_deref().unwrap_or(&request);
    let mut pool = setjoin_pg::WorkerPool::from_dsn(dsn, 8)
        .map_err(|e| format!("work-queue worker pool: {}", e.0))?;
    let (encryption, hmac) = (
        std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
        std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
    );
    if !encryption.is_empty() || !hmac.is_empty() {
        pool = pool.with_audit_keys(encryption, hmac);
    }
    let role_ok = match pool.begin_repeatable_read_only().await {
        Ok(mut tx) => {
            let res = tx
                .query(
                    "SELECT (rolbypassrls OR rolsuper) FROM pg_catalog.pg_roles WHERE rolname = current_user",
                    &[],
                )
                .await;
            let _ = tx.commit().await;
            res.ok()
                .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
                .unwrap_or(false)
        }
        Err(_) => false,
    };
    if !role_ok {
        if explicit {
            return Err(
                "work-queue requires a BYPASSRLS or superuser worker DSN (DB_WORKER_DSN)".into(),
            );
        }
        eprintln!(
            "work-queue: skipping auto-enable because worker DSN lacks BYPASSRLS; keeping legacy dispatch-scheduled-actions"
        );
        return Ok(None);
    }
    let queue = setjoin_workqueue::WorkQueue::new(pool);
    Ok(Some(setjoin_workqueue::WorkScheduledActionConsumer::new(
        queue,
        setjoin_workqueue::WorkConsumerConfig::default(),
        listen_hub,
    )))
}

/// `RUST_WORKERS_ON=security-event-delivery` takes Go's `security-event-delivery`
/// (#304). Go runs it with a nil sink, which is fully inert, and so does this
/// worker: no production sink is admitted. It still refuses to start unless Go's
/// copy is off, so the day a sink is admitted two drainers cannot race. The
/// outbox is FORCE-RLS deny-all: worker credential only.
pub(super) fn secevents_worker() -> Result<Option<crate::secevents::SecurityEventDelivery>, String>
{
    use crate::secevents::NAME;
    if !listed("RUST_WORKERS_ON", NAME) {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for security-event-delivery")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?;
    Ok(Some(crate::secevents::SecurityEventDelivery::new(db, None)))
}

/// `RUST_WORKERS_ON=tls-rpt-report` takes Go's `tls-rpt-report` (#323): the daily TLS-RPT
/// report POSTs to remote reporting endpoints and deletes the sent sessions, so two copies
/// would double both: Go must be off first. The organisation name is Go's `cfg.Hostname`
/// (the `HOSTNAME` environment; a config-file `hostname` cannot be read here).
pub(super) fn tls_rpt_worker() -> Result<Option<Arc<crate::tls_rpt::TlsRptReport>>, String> {
    use crate::tls_rpt::NAME;
    if !listed("RUST_WORKERS_ON", NAME) {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for tls-rpt-report")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?;
    Ok(Some(Arc::new(crate::tls_rpt::TlsRptReport::new(
        db,
        std::env::var("HOSTNAME").unwrap_or_default(),
    ))))
}

/// Every process owning a trust cache needs its own invalidation listener (#526).
/// Native SMTP starts it automatically; the explicit worker name also admits it.
pub(super) fn smime_trust_listener(
    cache: Arc<setjoin_mail_security::smime::trust::TrustCache>,
    smtp_active: bool,
) -> Result<Option<Arc<crate::smime_trust::SmimeTrustListener>>, String> {
    use crate::smime_trust::{SmimeTrustListener, NAME};
    if !smtp_active && !listed("RUST_WORKERS_ON", NAME) {
        cache.set_cached(false);
        return Ok(None);
    }
    let direct = std::env::var("DB_DIRECT_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DIRECT_DSN is required for smime-trust-listener")?;
    Ok(Some(Arc::new(SmimeTrustListener::new(cache, direct))))
}

/// `RUST_WORKERS_ON=meet-reconcile` takes Go's `meet-reconcile` (#410): room,
/// egress, recording, semantic, Drive-History and captions convergence. It
/// writes to the database, calls LiveKit/Egress/the ASR bot and moves objects,
/// so two copies would double every effect: Go must be off first. Worker
/// credential (cross-tenant sweeps) with the audit keys on the session.
pub(super) fn meet_reconcile_worker() -> Result<Option<crate::meet_worker::MeetReconcile>, String> {
    use crate::meet_worker::NAME;
    if !listed("RUST_WORKERS_ON", NAME) {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for meet-reconcile")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?
        .with_audit_keys(
            std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
            std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
        );
    let store = crate::recovery_worker::S3Store::from_env()?;
    Ok(Some(crate::meet_worker::MeetReconcile::new(
        db,
        crate::meet_livekit::LiveKit::from_env(),
        Some(store),
    )))
}

/// `RUST_WORKERS_ON=dmarc-report` takes Go's `dmarc-report` (#324): the daily DMARC aggregate
/// report enqueue. It writes `outbound_queue` and deletes `dmarc_reports`, so two copies would
/// send every report twice: Go must be off first. Go starts the worker only while
/// `feature.dmarc_reporting` is on (default on), read once at start; so does this, and a
/// disabled toggle leaves Rust's worker off as well. Worker credential, cross-tenant by design.
pub(super) async fn dmarc_report_worker() -> Result<Option<crate::dmarc_report::DmarcReport>, String>
{
    use crate::dmarc_report::{DmarcReport, NAME};
    if !listed("RUST_WORKERS_ON", NAME) {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for dmarc-report")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?
        .with_audit_keys(
            std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
            std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
        );
    let enabled = db
        .connect()
        .await
        .map_err(|e| format!("dmarc-report: {e}"))?
        .query(
            "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.dmarc_reporting'),true)",
            &[],
        )
        .await
        .map_err(|e| format!("dmarc-report: {e}"))?
        .first()
        .is_some_and(|r| r.get::<_, bool>(0));
    if !enabled {
        eprintln!("DMARC reporting disabled by feature toggle");
        return Ok(None);
    }
    let hostname = std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "localhost".into());
    Ok(Some(DmarcReport::new(db, hostname)))
}

/// `RUST_WORKERS_ON=push-intent-drain` takes Go's `push-intent-drain` (#408):
/// mail push, chat push and the guest digest. A second drainer would
/// double-dispatch to devices (the claim lease is per row, not per worker
/// kind), so Go must be off first. Worker credential, because the queues and
/// `push_devices` are cross-tenant; the audit keys give the session
/// `app.encryption_key` that `push_decrypt_token` needs. Go refuses to boot
/// without an object store, and so does this: the digest stores its message there.
pub(super) fn push_drain_worker() -> Result<Option<crate::push_drain::PushIntentDrain>, String> {
    use crate::push_drain::{GuestDigest, PushIntentDrain, NAME};
    if !listed("RUST_WORKERS_ON", NAME) {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for push-intent-drain")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?
        .with_audit_keys(
            std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
            std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
        );
    let (providers, statuses) = setjoin_push::build();
    for status in statuses {
        match status.state {
            "configured" => eprintln!(
                "push provider configured: {} {}",
                status.provider, status.detail
            ),
            "absent" => eprintln!("push provider absent: {}", status.provider),
            // The detail is configuration text, never a device token.
            _ => eprintln!(
                "push provider present but INVALID config: {} {}",
                status.provider, status.detail
            ),
        }
    }
    let hostname = std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".into());
    let store = crate::recovery_worker::S3Store::from_env()
        .map_err(|e| format!("push-intent-drain needs the object store: {e}"))?;
    Ok(Some(PushIntentDrain::new(
        db,
        providers,
        Some(GuestDigest {
            store: Arc::new(store),
            from_addr: format!("noreply@{hostname}"),
            from_name: "SetJoin".into(),
            webmail_url: format!("https://{hostname}"),
        }),
    )))
}

/// Worker credential for the Drive workers: the sweep, chunk queue and render
/// queue are cross-tenant by design (Go runs them on `workerPool`).
pub(super) fn drive_worker_database(name: &str) -> Result<WorkerDatabase, String> {
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("DB_DSN is required for {name}"))?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))
}

/// `RUST_WORKERS_ON=drive-maintenance` takes Go's 5-minute Drive sweep, chunk GC,
/// orphan reaper and WORM retry (#409). Both would delete the same rows and
/// objects, so Go must be off first. Go also needs the object store, and so
/// does this; the retention handle is always present (Go leaves it nil only
/// when its own retention driver fails to build).
pub(super) fn drive_maintenance_worker(
) -> Result<Option<crate::drive_workers::DriveMaintenance>, String> {
    use crate::drive_workers::{DriveMaintenance, MAINTENANCE};
    if !listed("RUST_WORKERS_ON", MAINTENANCE) {
        return Ok(None);
    }
    let db = drive_worker_database(MAINTENANCE)?;
    let store = crate::recovery_worker::S3Store::from_env()
        .map_err(|e| format!("drive-maintenance needs the object store: {e}"))?;
    Ok(Some(DriveMaintenance::new(db, Arc::new(store), true)))
}

/// `RUST_WORKERS_ON=drive-preview` takes Go's rendition worker (#409). Inert
/// without `DRIVE_PREVIEW_CMD`, exactly as Go (it still needs Go off, so the
/// Rust copy cannot run beside a Go one once a command appears).
pub(super) fn drive_preview_worker() -> Result<Option<crate::drive_workers::DrivePreview>, String> {
    use crate::drive_workers::{DrivePreview, PREVIEW};
    if !listed("RUST_WORKERS_ON", PREVIEW) {
        return Ok(None);
    }
    let db = drive_worker_database(PREVIEW)?;
    let store = crate::recovery_worker::S3Store::from_env()
        .map_err(|e| format!("drive-preview needs the object store: {e}"))?;
    Ok(Some(DrivePreview::new(
        db,
        Arc::new(store),
        std::env::var("DRIVE_PREVIEW_CMD").unwrap_or_default(),
    )))
}

/// Returns true when `blob-cleanup` (or its Wave 2.4 alias `blob-gc`) is enabled
/// in `RUST_WORKERS_ON` (#411/#551).
pub(super) fn blob_cleanup_enabled() -> bool {
    listed("RUST_WORKERS_ON", crate::blob_cleanup::NAME)
        || listed("RUST_WORKERS_ON", crate::blob_cleanup::ALIAS)
}

/// Resolves the shared S3 store for supervised `blob-cleanup` (Mark-and-Sweep GC)
/// when `blob-cleanup` or `blob-gc` is listed in `RUST_WORKERS_ON` (#551).
pub(super) fn blob_cleanup_store() -> Result<Option<Arc<crate::recovery_worker::S3Store>>, String> {
    if !blob_cleanup_enabled() {
        return Ok(None);
    }
    let store = crate::recovery_worker::S3Store::from_env()
        .map_err(|e| format!("blob-cleanup needs the object store: {e}"))?;
    Ok(Some(Arc::new(store)))
}

/// `RUST_WORKERS_ON=calendar-subscription-sync` takes Go's webcal refresh loop (and
/// the subscribe route's detached first fetch); two sweeps would race on the same
/// rows, so Go must be off first.
pub(super) fn subscription_sync(
) -> Result<Option<Arc<crate::subscription_sync::SubscriptionSync>>, String> {
    if !listed("RUST_WORKERS_ON", "calendar-subscription-sync") {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for calendar-subscription-sync")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?
        .with_audit_keys(
            std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
            std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
        );
    Ok(Some(Arc::new(
        crate::subscription_sync::SubscriptionSync::new(db),
    )))
}

pub(super) fn chat_reaper() -> Result<Option<crate::chat_workers::UnfurlReaper>, String> {
    if !std::env::var("RUST_WORKERS_ON")
        .unwrap_or_default()
        .split(',')
        .any(|name| name.trim() == "chat-unfurl-reap")
    {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN").map_err(|_| "DB_DSN is required for the Chat reaper")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?;
    Ok(Some(crate::chat_workers::UnfurlReaper::new(db)))
}

/// `RUST_WORKERS_ON=drive-watch` takes the Go `drive-watch` fan-out; both would
/// push to the same `drive-watch:<uid>` channels, so Go must be off first.
pub(super) fn drive_watch_worker(
) -> Result<Option<(setjoin_drive::watch::DriveWatch, String)>, String> {
    let listed = |var: &str| {
        std::env::var(var)
            .unwrap_or_default()
            .split(',')
            .any(|s| s.trim() == "drive-watch")
    };
    if !listed("RUST_WORKERS_ON") {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN").map_err(|_| "DB_DSN is required for workers")?;
    let worker = std::env::var("DB_WORKER_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or(request);
    let _ = WorkerDatabase::new(&worker).map_err(|_| "invalid worker DSN")?;
    let direct = std::env::var("DB_DIRECT_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DIRECT_DSN is required for drive-watch")?;
    Ok(Some((
        setjoin_drive::watch::DriveWatch::new(worker),
        direct,
    )))
}

/// `RUST_WORKERS_ON=cron:<task>` takes one Go cron task (#365). Each name needs
/// `GO_WORKERS_OFF=cron:<task>` (or `cron`) first; the scheduler then holds only
/// that task's own lock, never Go's scheduler lock. Only tasks with a Rust
/// callback are accepted, so an unported task cannot be switched off by mistake.
pub(super) async fn cron_scheduler(
    work_queue_active: bool,
) -> Result<Option<crate::workers::CronScheduler>, String> {
    let configured = std::env::var("RUST_WORKERS_ON").unwrap_or_default();
    let tasks: Vec<_> = configured
        .split(',')
        .map(str::trim)
        .filter_map(|name| name.strip_prefix("cron:"))
        // Wave 2.1 (#548): mutual exclusion with WorkQueue scheduled_actions
        // consumer while keeping cron_catalog.rs:34 intact for parity tests.
        .filter(|name| !(work_queue_active && *name == "dispatch-scheduled-actions"))
        .collect();
    if tasks.is_empty() {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for cron tasks")?;
    let worker = std::env::var("DB_WORKER_DSN")
        .ok()
        .filter(|s| !s.is_empty());
    let mut db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?;
    let (encryption, hmac) = (
        std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
        std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
    );
    if !encryption.is_empty() || !hmac.is_empty() {
        db = db.with_audit_keys(encryption.clone(), hmac.clone());
    }
    // Owner credential only for the two statements that need schema ownership.
    let owner_dsn = std::env::var("DB_OWNER_DSN").ok().filter(|s| !s.is_empty());
    let mut owner = WorkerDatabase::from_dsns(
        owner_dsn.as_deref().unwrap_or(&request),
        owner_dsn.as_deref().or(worker.as_deref()),
    )
    .map_err(|e| format!("DB_OWNER_DSN: {e}"))?;
    if !encryption.is_empty() || !hmac.is_empty() {
        owner = owner.with_audit_keys(encryption, hmac);
    }
    let dbs = crate::cron_catalog::CronDatabases {
        worker: db.clone(),
        owner,
    };
    let go_off = std::env::var("GO_WORKERS_OFF").unwrap_or_default();
    let mut scheduler = crate::workers::CronScheduler::per_task(db.clone());
    crate::cron_catalog::register_cron_tasks(&mut scheduler, &tasks, &dbs, &go_off).await?;
    Ok(Some(scheduler))
}

/// #295: shared-effect workers transfer independently by their frozen Go names.
pub(super) async fn mail_worker_adapters(
    dispatcher: Option<&crate::webhook::Dispatcher>,
) -> Result<
    (
        Option<crate::mail_workers::MailWork>,
        Option<crate::mail_workers::MailboxLifecycle>,
    ),
    String,
> {
    use crate::mail_workers::{MailWork, MailboxLifecycle};
    let work = listed("RUST_WORKERS_ON", "mail-work");
    let lifecycle = listed("RUST_WORKERS_ON", "mailbox-lifecycle");
    if !work && !lifecycle {
        return Ok((None, None));
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for mail workers")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?
        .with_audit_keys(
            std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
            std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
        );
    let dispatcher = dispatcher.ok_or("DB_DSN is required for mail workers")?;
    let mail_work = work.then(|| MailWork::new(db.clone()).with_dispatcher(dispatcher.clone()));
    let mailbox_lifecycle = lifecycle.then(|| {
        MailboxLifecycle::new(db)
            .with_dispatcher(dispatcher.clone())
            .with_media(
                &std::env::var("LIVEKIT_URL").unwrap_or_default(),
                &std::env::var("LIVEKIT_API_KEY").unwrap_or_default(),
                &std::env::var("LIVEKIT_API_SECRET").unwrap_or_default(),
            )
    });
    Ok((mail_work, mailbox_lifecycle))
}

/// The migration job runner (#431): Rust runs jobs and serves the routes that drive
/// them only with `RUST_WORKERS_ON=migration-runner`, which needs
/// `GO_WORKERS_OFF=migration-runner` (the operator's attestation that Go's runner
/// serves no start/retry/resume route). Jobs a restart left running are failed here,
/// as Go's `RecoverStuckJobs` does at its own start.
pub(super) async fn migration_runner(
    dispatcher: Option<&crate::webhook::Dispatcher>,
) -> Result<Option<crate::migration::Runner>, String> {
    if !listed("RUST_WORKERS_ON", "migration-runner") {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for the migration runner")?;
    let worker_dsn = std::env::var("DB_WORKER_DSN")
        .ok()
        .filter(|s| !s.is_empty());
    let keys = (
        std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
        std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
    );
    let db = WorkerDatabase::from_dsns(&request, worker_dsn.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?
        .with_audit_keys(keys.0.clone(), keys.1.clone());
    let store = crate::recovery_worker::S3Store::from_env()
        .map_err(|e| format!("migration-runner needs the object store: {e}"))?;
    let orchestrator =
        crate::migration_runner::Orchestrator::new(crate::migration_runner::Config {
            db,
            store: Arc::new(store),
            root: keys.0.clone(),
            dialer: crate::migration_runner::Dialer::system(),
            dispatcher: dispatcher.cloned(),
        });
    let recovered = orchestrator.recover_stuck().await?;
    if recovered > 0 {
        eprintln!("migration recovery: marked {recovered} stuck jobs as failed");
    }
    let worker = ScopedExecutor::from_dsn(worker_dsn.as_deref().unwrap_or(&request), 4)
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(keys.0, keys.1);
    Ok(Some(crate::migration::Runner {
        orchestrator,
        worker,
    }))
}

/// Shared DB/S3 effects: explicit per-worker Go-off prerequisite.
pub(super) fn exchange_deletion_worker(
) -> Result<Option<crate::exchange_deletion::DeletionWorker>, String> {
    use crate::exchange_deletion::{DeletionWorker, NAME};
    if !listed("RUST_WORKERS_ON", NAME) {
        return Ok(None);
    }
    let db = drive_worker_database(NAME)?.with_audit_keys(
        std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
        std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
    );
    let store = crate::recovery_worker::S3Store::from_env()
        .map_err(|e| format!("exchange-assessment-deletion needs the object store: {e}"))?;
    let signer = crate::exchange::signer_from_env()?
        .ok_or("exchange-assessment-deletion needs the continuity signing key")?;
    Ok(Some(DeletionWorker::new(db, Arc::new(store), signer)))
}
/// Shared DB effects: Go's trainer must be stopped before Rust can subscribe.
pub(super) fn spam_trainer_worker(
) -> Result<Option<(crate::spam_trainer::SpamTrainer, String)>, String> {
    use crate::spam_trainer::{SpamTrainer, NAME};
    if !listed("RUST_WORKERS_ON", NAME) {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for spam-trainer")?;
    let direct = std::env::var("DB_DIRECT_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DIRECT_DSN is required for spam-trainer")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?
        .with_audit_keys(
            std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
            std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
        );
    let store = crate::recovery_worker::S3Store::from_env()?;
    Ok(Some((SpamTrainer::new(db, Some(store)), direct)))
}
