//! Reusable server runtime extracted from `bins/gateway/src/main.rs` (#543).
//!
//! Both `setjoin-server` (legacy wrapper) and `setjoind` (unified binary with
//! `--subsystems=all|http,auth,protocols,workers`) execute through
//! [`run_with_options`], parameterized by [`RuntimeOptions`].

pub mod routes;
pub mod workers;

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use setjoin_authz::auth_authority::AuthAuthority;
use setjoin_boot::Subsystems;
use setjoin_pg::workers::WorkerDatabase;
use setjoin_pg::{ListenHub, ScopedExecutor};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::activation::{Activated, SdNotify};
use crate::{Config, Gateway, TrustedProxies};

/// Default unified graceful shutdown drain budget across all active subsystems.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Composition inputs for [`run_with_options`].
pub struct RuntimeOptions {
    pub subsystems: Subsystems,
    pub auth_authority: Option<Arc<dyn AuthAuthority>>,
    pub listen_hub: Option<ListenHub>,
    pub activated: Activated,
    pub sd_notify: SdNotify,
    pub shutdown: CancellationToken,
    pub allow_route_inventory_env: bool,
    /// Permit reading `JWT_SECRET` / `SM2_PRIVATE_KEY_FILE` in legacy JWKS mode.
    /// Set to `false` on non-`auth` `setjoind` nodes (#543).
    pub allow_private_keys: bool,
    pub shared_threat_gate: Option<Arc<setjoin_threat::Gate>>,
    pub reload_auth_on_sighup: bool,
    pub drain_timeout: Duration,
    /// Additional caller-owned tasks (e.g. standalone auth listener) to drain
    /// concurrently inside the single `drain_timeout` window before `listen_hub`
    /// tears down (#543).
    pub extra_tasks: Vec<tokio::task::JoinHandle<()>>,
    /// Start `NotifyIntentDrain` unconditionally when `subsystems.workers` and
    /// `DB_DSN` are configured (true in `setjoind`, false in legacy `setjoin-server`
    /// which gates it on `RUST_WORKERS_ON=notify-intent-drain`).
    pub always_run_notify_drain: bool,
    /// Start the durable WorkQueue scheduled-action consumer automatically under
    /// `subsystems.workers` (false in legacy `setjoin-server` unless opted in via
    /// `RUST_WORKERS_ON=work-queue`).
    pub enable_work_queue: bool,
}

impl RuntimeOptions {
    /// Legacy `setjoin-server` defaults.
    pub fn legacy(activated: Activated, sd_notify: SdNotify) -> Self {
        Self {
            subsystems: Subsystems::ALL,
            auth_authority: None,
            listen_hub: None,
            activated,
            sd_notify,
            shutdown: CancellationToken::new(),
            allow_route_inventory_env: true,
            allow_private_keys: true,
            shared_threat_gate: None,
            reload_auth_on_sighup: false,
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
            extra_tasks: Vec::new(),
            // Wave 2.1 (#548): run NotifyIntentDrain unconditionally in default
            // setjoin-server so app_notify never strands intents; honor the
            // legacy idle matrix (RUST_WORKERS_ON="" + GO_WORKERS_OFF=notify-intent-drain).
            always_run_notify_drain: !(std::env::var("RUST_WORKERS_ON").as_deref() == Ok("")
                && workers::listed("GO_WORKERS_OFF", crate::notify_drain::NAME)),
            enable_work_queue: false,
        }
    }
}

/// Legacy `setjoin-server` binary entry point (preserves 100% of existing
/// `bins/gateway` startup, validation, and CLI contracts).
pub fn run_legacy_cli() -> ExitCode {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--version")) {
        println!("setjoin-server {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let sd_notify = SdNotify::from_env_and_scrub();
    let environment: Vec<(String, String)> = std::env::vars().collect();
    let env_get = |k: &str| {
        environment
            .iter()
            .rev()
            .find(|(name, _)| name == k)
            .map(|(_, value)| value.as_str())
    };
    let explicit_worm_env = environment
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("WORM_MODE") || k.eq_ignore_ascii_case("WORM__MODE"));
    let explicit_storage_env = environment.iter().any(|(k, v)| {
        !v.is_empty()
            && ([
                "S3_ENDPOINT",
                "S3__ENDPOINT",
                "S3_BUCKET",
                "S3__BUCKET",
                "S3_ACCESS_KEY",
                "S3_SECRET_KEY",
            ]
            .iter()
            .any(|name| k.eq_ignore_ascii_case(name))
                || matches!(
                    k.as_str(),
                    "MINIO_ENDPOINT" | "MINIO_BUCKET" | "MINIO_ACCESS_KEY" | "MINIO_SECRET_KEY"
                ))
    });
    let socket_activated = env_get("LISTEN_PID")
        .is_some_and(|pid| pid == std::process::id().to_string())
        && env_get("LISTEN_FDS")
            .and_then(|fds| fds.parse::<usize>().ok())
            .is_some_and(|n| n > 0);
    let settings = match crate::configuration::Settings::load_ordered(&environment) {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("setjoin-gateway: {error}");
            return ExitCode::FAILURE;
        }
    };
    if env_get("SETJOIN_CONFIG").is_some_and(|path| !path.is_empty()) {
        if let Err(error) = settings.validate() {
            eprintln!("setjoin-gateway: {error}");
            return ExitCode::FAILURE;
        }
    }
    settings.install_startup_environment();
    let db_backed = std::env::var("DB_DSN").ok().is_some_and(|s| !s.is_empty());
    if db_backed && socket_activated {
        if !explicit_worm_env {
            eprintln!(
                "setjoin-gateway: systemd-activated gateway requires explicit WORM_MODE (empty when disabled) in gateway.env; run upgrade.sh refresh-gateway-env before activating"
            );
            return ExitCode::FAILURE;
        }
        let worm = crate::compliance::WormConfig::from_settings(&settings);
        if worm.mode_enabled && !explicit_storage_env {
            eprintln!(
                "setjoin-gateway: WORM_MODE is enabled in gateway settings, but no S3_*/MINIO_* storage settings were loaded; run upgrade.sh refresh-gateway-env before activating"
            );
            return ExitCode::FAILURE;
        }
    }
    let configuration = match crate::configuration::Runtime::new_ordered(environment, settings) {
        Ok(configuration) => Arc::new(configuration),
        Err(error) => {
            eprintln!("setjoin-gateway: {error}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("setjoin-gateway: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(refusal) = runtime.block_on(setjoin_boot::run()) {
        return ExitCode::from(refusal.exit_code);
    }
    let activated = match runtime.block_on(async { crate::activation::take_from_env() }) {
        Ok(activated) => activated,
        Err(err) => {
            eprintln!("setjoin-gateway: {err}");
            return ExitCode::FAILURE;
        }
    };
    let options = RuntimeOptions::legacy(activated, sd_notify);
    match runtime.block_on(run_with_options(configuration, options)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("setjoin-gateway: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Run the selected non-standalone-auth subsystems (`http`, `protocols`,
/// `workers`) with shared [`AuthAuthority`], shared [`ListenHub`], socket
/// activation, `sd_notify`, and a unified concurrent graceful drain.
pub async fn run_with_options(
    configuration: Arc<crate::configuration::Runtime>,
    options: RuntimeOptions,
) -> Result<(), String> {
    let subsystems = options.subsystems;
    if subsystems.is_empty() {
        return Err("at least one subsystem must be enabled".into());
    }
    options.activated.validate_for_subsystems(subsystems)?;
    if !options.allow_route_inventory_env
        && std::env::var("GATEWAY_ROUTE_INVENTORY")
            .ok()
            .is_some_and(|v| !v.is_empty())
    {
        return Err(
            "GATEWAY_ROUTE_INVENTORY is retired in setjoind; unified routing is always active"
                .into(),
        );
    }

    let mut reload_signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .map_err(|e| format!("SIGHUP registration: {e}"))?;
    let mut settings = configuration.startup_settings();
    let configuration_exec = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|dsn| ScopedExecutor::from_dsn(&dsn, 2).map_err(|e| e.0))
        .transpose()?;
    configuration
        .refresh_proxies(configuration_exec.as_ref())
        .await;

    let listen = std::env::var("GATEWAY_LISTEN").unwrap_or_else(|_| "127.0.0.1:8090".into());
    if std::env::var("GATEWAY_UPSTREAM")
        .ok()
        .is_some_and(|v| !v.is_empty())
    {
        eprintln!(
            "setjoin-gateway: WARNING: GATEWAY_UPSTREAM is deprecated and ignored (Go mailserver forwarding has been removed)"
        );
    }
    let trusted = std::env::var("GATEWAY_TRUSTED_PROXIES").unwrap_or_default();
    match std::env::var("GATEWAY_ENABLED").as_deref() {
        Err(_) | Ok("") | Ok("true") | Ok("1") => {}
        Ok("false") | Ok("0") => {
            return Err(
                "GATEWAY_ENABLED=false is no longer supported; legacy Go proxy-all mode has been removed"
                    .into(),
            );
        }
        _ => return Err("GATEWAY_ENABLED must be true/false or 1/0".into()),
    }

    let activated = options.activated;
    if subsystems.http {
        crate::tls_runtime::guard_activation(
            &|name| std::env::var(name).ok(),
            activated.https.is_some(),
        )?;
    }
    let tls_frontend = if subsystems.http && activated.https.is_some() {
        let verifier = crate::tls_runtime::client_verifier(configuration_exec.as_ref()).await?;
        Some(
            setjoin_tls::Frontend::from_env_with_client_verifier(
                &|name| std::env::var(name).ok(),
                verifier,
            )?
            .ok_or("the https descriptor requires TLS_CERT/TLS_KEY or TLS_AUTOCERT_DOMAINS")?,
        )
    } else {
        None
    };

    let federation = if subsystems.protocols {
        setjoin_federation::runtime::Runtime::prepare(activated.federation, &|name| {
            std::env::var(name).ok()
        })?
    } else {
        None
    };
    let federation_reaper = if subsystems.workers {
        setjoin_federation::runtime::reaper_from_env(&|name| std::env::var(name).ok())?
    } else {
        None
    };
    let webhook = if subsystems.http || subsystems.protocols || subsystems.workers {
        workers::webhook_dispatcher()?
    } else {
        None
    };
    let outbound = if subsystems.workers {
        crate::smtp_outbound::from_environment().await?
    } else {
        None
    };
    let migration_runner = if subsystems.workers {
        workers::migration_runner(webhook.as_ref()).await?
    } else {
        None
    };
    let session_worker = if subsystems.workers {
        workers::session_worker()?
    } else {
        None
    };
    let backup = if subsystems.workers {
        setjoin_backup::worker::Engine::from_environment()?
    } else {
        None
    };
    let recovery = if subsystems.workers {
        workers::recovery_worker()?
    } else {
        None
    };
    let chat_reaper = if subsystems.workers {
        workers::chat_reaper()?
    } else {
        None
    };
    let booking_expiry = if subsystems.workers {
        workers::booking_expiry()?
    } else {
        None
    };
    let user_risk = if subsystems.workers {
        workers::user_risk_worker()?
    } else {
        None
    };
    let subscription_sync = if subsystems.workers {
        workers::subscription_sync()?
    } else {
        None
    };
    let (webhook_publications, webhook_retry) = if subsystems.workers {
        workers::webhook_workers(webhook.as_ref())?
    } else {
        (None, None)
    };
    let notify_drain = if subsystems.workers || options.always_run_notify_drain {
        workers::notify_drain_worker(options.always_run_notify_drain)?
    } else {
        None
    };
    let work_queue = if subsystems.workers {
        workers::work_queue_worker(options.enable_work_queue, options.listen_hub.clone()).await?
    } else {
        None
    };
    let secevents = if subsystems.workers {
        workers::secevents_worker()?
    } else {
        None
    };
    let tls_rpt = if subsystems.workers {
        workers::tls_rpt_worker()?
    } else {
        None
    };
    let smime_cache = Arc::new(setjoin_mail_security::smime::trust::TrustCache::new());
    let smtp_active =
        subsystems.protocols && (activated.smtp.is_some() || activated.smtps.is_some());
    let smime_trust = if smtp_active || subsystems.workers {
        workers::smime_trust_listener(smime_cache.clone(), smtp_active)?
    } else {
        smime_cache.set_cached(false);
        None
    };
    let spam_trainer = if subsystems.workers {
        workers::spam_trainer_worker()?
    } else {
        None
    };
    let push_drain = if subsystems.workers {
        workers::push_drain_worker()?
    } else {
        None
    };
    let meet_reconcile = if subsystems.workers {
        workers::meet_reconcile_worker()?
    } else {
        None
    };
    let dmarc_report = if subsystems.workers {
        workers::dmarc_report_worker().await?
    } else {
        None
    };
    let approval = if subsystems.workers {
        workers::approval_worker()?
    } else {
        None
    };
    let guests = if subsystems.http || subsystems.workers {
        workers::guest_lifecycle()?
    } else {
        None
    };
    let drive_watch = if subsystems.workers {
        workers::drive_watch_worker()?
    } else {
        None
    };
    let drive_maintenance = if subsystems.workers {
        workers::drive_maintenance_worker()?
    } else {
        None
    };
    let drive_preview = if subsystems.workers {
        workers::drive_preview_worker()?
    } else {
        None
    };
    let blob_cleanup = if subsystems.workers {
        workers::blob_cleanup_worker()?
    } else {
        None
    };
    let (mail_work, mailbox_lifecycle) = if subsystems.workers {
        workers::mail_worker_adapters(webhook.as_ref()).await?
    } else {
        (None, None)
    };
    let exchange_deletion = if subsystems.workers {
        workers::exchange_deletion_worker()?
    } else {
        None
    };
    let cron = if subsystems.workers {
        workers::cron_scheduler(work_queue.is_some()).await?
    } else {
        None
    };
    let ldap = if subsystems.http || subsystems.workers {
        workers::ldap_runtime()?
    } else {
        None
    };
    let ad = if subsystems.http || subsystems.workers {
        workers::ad_runtime()?
    } else {
        None
    };
    let identity_workers = if subsystems.workers {
        Some(workers::identity_workers()?)
    } else {
        None
    };
    let admin_jobs = if subsystems.workers {
        Some(workers::admin_job_workers()?)
    } else {
        None
    };

    let chain = Arc::new(setjoin_authz::auth_chain::Chain::default());
    let chain_config = if subsystems.http {
        std::env::var("DB_DSN")
            .ok()
            .filter(|s| !s.is_empty())
            .and_then(|dsn| {
                let direct = std::env::var("DB_DIRECT_DSN")
                    .ok()
                    .filter(|s| !s.is_empty());
                if options.listen_hub.is_some() || direct.is_some() {
                    Some((dsn, direct.unwrap_or_default()))
                } else {
                    None
                }
            })
    } else {
        None
    };

    if subsystems.http && settings.string("network.mode").is_empty() {
        settings.set_network_mode(crate::configuration::detect_network_mode().await);
    }

    let platform_storage = if subsystems.http || subsystems.workers {
        std::env::var("DB_DSN")
            .ok()
            .filter(|dsn| !dsn.is_empty())
            .map(|dsn| {
                Ok::<_, String>(Arc::new(
                    crate::platform_storage::Runtime::from_env()?.with_database(
                        WorkerDatabase::from_dsns(
                            &dsn,
                            std::env::var("DB_WORKER_DSN").ok().as_deref(),
                        )
                        .map_err(|e| e.to_string())?,
                    ),
                ))
            })
            .transpose()?
    } else {
        None
    };
    if let Some(storage) = &platform_storage {
        storage.recover().await;
    }

    let imap_on = subsystems.protocols && (activated.imap.is_some() || activated.imaps.is_some());
    let smtp_off = if subsystems.protocols {
        crate::smtp_runtime::required_off(
            activated.smtp.is_some(),
            activated.smtps.is_some(),
            activated.submission.is_some(),
        )
    } else {
        Vec::new()
    };
    let mut security_protocols = Vec::new();
    if imap_on {
        security_protocols.push("imap");
    }
    security_protocols.extend(smtp_off);

    let (threat_gate, _threat_watchers) = if let Some(gate) = options.shared_threat_gate {
        (Some(gate), None)
    } else if (subsystems.http || subsystems.protocols)
        && (!security_protocols.is_empty() || !settings.string("db.dsn").is_empty())
    {
        let label = if security_protocols.is_empty() {
            "http".to_owned()
        } else {
            security_protocols.join("-")
        };
        match crate::imap_runtime::load_security_with_hub(
            &settings,
            &label,
            options.listen_hub.as_ref(),
        )
        .await
        {
            Ok((gate, watchers)) => (Some(gate), Some(watchers)),
            Err(error) if !imap_on => {
                eprintln!("threat gate unavailable: {error}");
                (None, None)
            }
            Err(error) => return Err(error),
        }
    } else {
        (None, None)
    };

    let mut gateway_opt = None;
    let mut chain_ready: Option<(ScopedExecutor, String)> = None;
    if subsystems.http {
        let (route_table, edge_limit) = routes::build(
            &settings,
            routes::RouteDeps {
                configuration: configuration.clone(),
                denylist: session_worker.as_ref().map(|(d, _)| d.clone()),
                chain: chain_config.as_ref().map(|_| chain.clone()),
                threat: threat_gate.clone(),
                lifecycle: guests.clone(),
                ldap: ldap.clone(),
                ad: ad.clone(),
                subscription_sync: subscription_sync.clone(),
                migration_runner: migration_runner.clone(),
                webhook: webhook.clone(),
                federation: federation.as_ref().map(|runtime| runtime.service.clone()),
                platform_storage: platform_storage.clone(),
                auth_authority: options.auth_authority.clone(),
                listen_hub: options.listen_hub.clone(),
                allow_private_keys: options.allow_private_keys,
            },
        )
        .await?;

        if let Some((dsn, direct)) = chain_config {
            let exec = ScopedExecutor::from_dsn(&dsn, 2).map_err(|e| e.0)?;
            let registry = exec
                .read(
                    "SELECT mode FROM feature_toggle_registry_state WHERE singleton",
                    &[],
                )
                .await
                .map_err(|_| "feature registry unavailable at startup".to_owned())?;
            if !registry.first().is_some_and(|row| {
                matches!(row.get::<_, String>(0).as_str(), "observe" | "enforce")
            }) {
                return Err("feature registry unavailable at startup".into());
            }
            chain.reload(&exec).await?;
            chain_ready = Some((exec, direct));
        }

        let config = Config {
            upstream: None,
            trusted_proxies: TrustedProxies::parse(&trusted)
                .map_err(|e| format!("GATEWAY_TRUSTED_PROXIES: {e}"))?,
            upstream_header_timeout: match std::env::var("GATEWAY_UPSTREAM_HEADER_TIMEOUT_SECS") {
                Ok(v) if !v.is_empty() => Duration::from_secs(
                    v.parse()
                        .map_err(|e| format!("GATEWAY_UPSTREAM_HEADER_TIMEOUT_SECS: {e}"))?,
                ),
                _ => crate::proxy::DEFAULT_HEADER_TIMEOUT,
            },
            edge_limit,
        };
        let mut http_limits = crate::http_limits::HttpLimits::default();
        if let Ok(value) = std::env::var("GATEWAY_MAX_CONNECTIONS") {
            http_limits.max_connections = value
                .parse()
                .map_err(|e| format!("GATEWAY_MAX_CONNECTIONS: {e}"))?;
        }
        let mut gateway = Gateway::new(config, route_table)?
            .with_http_limits(http_limits)
            .map_err(|e| format!("GATEWAY_MAX_CONNECTIONS: {e}"))?
            .with_configuration(&configuration);
        if let Some(authority) = options.auth_authority.clone() {
            gateway = gateway.with_auth_authority(authority);
        } else {
            let rust_auth = match std::env::var("GATEWAY_RUST_AUTH_UPSTREAM")
                .ok()
                .filter(|v| !v.is_empty())
            {
                Some(auth) => Some(("GATEWAY_RUST_AUTH_UPSTREAM", auth)),
                None => std::env::var("GATEWAY_AUTH_UPSTREAM")
                    .ok()
                    .filter(|v| !v.is_empty())
                    .map(|auth| {
                        eprintln!(
                            "setjoin-gateway: WARNING: GATEWAY_AUTH_UPSTREAM is deprecated; using it as GATEWAY_RUST_AUTH_UPSTREAM until gateway.env is refreshed"
                        );
                        ("GATEWAY_AUTH_UPSTREAM", auth)
                    }),
            };
            if let Some((var, auth)) = rust_auth {
                gateway = gateway
                    .with_rust_auth_upstream(auth.parse().map_err(|e| format!("{var}: {e}"))?)?;
            }
        }
        if options.allow_route_inventory_env {
            if let Ok(path) = std::env::var("GATEWAY_ROUTE_INVENTORY") {
                let json = std::fs::read_to_string(path)
                    .map_err(|e| format!("GATEWAY_ROUTE_INVENTORY: {e}"))?;
                let candidate = crate::inventory::Inventory::parse(&json)?;
                let qualified = crate::inventory::Inventory::parse(crate::inventory::BUNDLED)?;
                candidate.require_qualified(&qualified)?;
                gateway = gateway.with_inventory(&json)?;
            }
        }
        gateway_opt = Some(gateway);
    }

    let mut tls_workers = match tls_frontend.as_ref() {
        Some(frontend) => Some(
            crate::tls_runtime::start(frontend.clone(), &|name| std::env::var(name).ok()).await?,
        ),
        None => None,
    };

    if subsystems.http {
        crate::acme::guard(
            std::env::var("RUST_WORKERS_ON").ok().as_deref(),
            std::env::var("GO_WORKERS_OFF").ok().as_deref(),
            activated.acme.is_some(),
            tls_frontend.is_some(),
            &std::env::var("TLS_AUTOCERT_CHALLENGE").unwrap_or_default(),
        )?;
    }
    let acme_store = setjoin_acme::Http01Store::default();
    let dns_degraded = std::env::var("TLS_AUTOCERT_CHALLENGE").as_deref() == Ok("dns-01");
    let acme_settings = if subsystems.http || subsystems.workers {
        crate::acme::settings(&|name| std::env::var(name).ok()).or_else(|e| {
            if workers::listed("RUST_WORKERS_ON", crate::acme::RENEWAL) && !dns_degraded {
                Err(e)
            } else {
                if workers::listed("RUST_WORKERS_ON", crate::acme::RENEWAL) {
                    eprintln!("TLS: managed ACME client creation failed: {e}");
                }
                Ok(None)
            }
        })?
    } else {
        None
    };
    let acme_hostname = acme_settings
        .as_ref()
        .map(|s| s.hostname.clone())
        .unwrap_or_else(|| std::env::var("HOSTNAME").unwrap_or_default());
    let acme_renewal = if subsystems.http || subsystems.workers {
        acme_settings
            .filter(|_| workers::listed("RUST_WORKERS_ON", crate::acme::RENEWAL))
            .map(|s| {
                crate::acme::Renewal::new(
                    s,
                    acme_store.clone(),
                    tls_frontend.as_ref().map(|f| f.tls_alpn_store()),
                )
            })
            .transpose()
            .or_else(|e| {
                if dns_degraded {
                    eprintln!("TLS: managed ACME client creation failed: {e}");
                    Ok(None)
                } else {
                    Err(e)
                }
            })?
    } else {
        None
    };

    let setup_control_ready = if subsystems.workers
        && workers::listed("RUST_WORKERS_ON", crate::setup_control::NAME)
    {
        let request = std::env::var("DB_DSN")
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or("DB_DSN is required for setup-control")?;
        let worker = std::env::var("DB_WORKER_DSN").ok();
        let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
            .map_err(|e| format!("DB_WORKER_DSN: {e}"))?;
        let path = std::env::var("SETJOIN_CONTROL_SOCKET")
            .map(|s| s.trim().to_owned())
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| crate::setup_control::DEFAULT_SOCKET.into());
        let token = std::env::var("SETJOIN_SETUP_TOKEN")
            .unwrap_or_default()
            .trim()
            .to_owned();
        if token.is_empty() {
            eprintln!("setjoin-gateway: SETJOIN_SETUP_TOKEN is not configured; setup calls are refused until it is set");
        }
        let primary = match crate::setup_control::primary_from_env(&|n| std::env::var(n).ok()) {
            Ok(store) => Some(store),
            Err(e) => {
                eprintln!("setjoin-gateway: setup: primary storage driver init failed, restore unavailable: {e}");
                None
            }
        };
        let path = std::path::PathBuf::from(path);
        let socket = crate::setup_control::bind(&path)
            .map_err(|e| format!("setup control socket unavailable: {e}"))?;
        let control = Arc::new(crate::setup_control::Control { db, primary, token });
        eprintln!(
            "setjoin-gateway: local setup control socket ready path={}",
            path.display()
        );
        Some((socket, path, control))
    } else {
        None
    };

    let imap = if subsystems.protocols {
        crate::imap_runtime::start(
            activated.imap,
            activated.imaps,
            &|name| std::env::var(name).ok(),
            threat_gate
                .clone()
                .map(|gate| gate as Arc<dyn setjoin_imap::ThreatGate>),
            webhook.clone(),
        )?
        .map(|rt| match options.listen_hub.clone() {
            Some(hub) => rt.with_listen_hub(hub),
            None => rt,
        })
    } else {
        None
    };
    let smtp = if subsystems.protocols {
        crate::smtp_runtime::start_or_log(crate::smtp_runtime::start_with_trust_cache(
            activated.smtp,
            activated.smtps,
            activated.submission,
            &|name| std::env::var(name).ok(),
            threat_gate,
            webhook.clone(),
            smime_cache,
        ))
        .map(|rt| match options.listen_hub.clone() {
            Some(hub) => rt.with_listen_hub(hub),
            None => rt,
        })
    } else {
        None
    };

    let http_listener = if subsystems.http {
        let listener = match activated.http {
            Some(listener) => listener,
            None => TcpListener::bind(&listen)
                .await
                .map_err(|e| format!("listen {listen}: {e}"))?,
        };
        let bound = listener
            .local_addr()
            .map_err(|e| format!("listener address: {e}"))?;
        eprintln!("setjoin-gateway: listening on {bound}");
        Some(listener)
    } else {
        None
    };

    // Start identity source runtime initial reconciliation BEFORE spawning loops/ready.
    let source_runtime = match identity_workers.as_ref().and_then(|iw| iw.runtime.clone()) {
        Some(runtime) => {
            runtime.start().await?;
            Some(runtime)
        }
        None => None,
    };

    // Unified root CancellationToken + JoinSet for all background tasks and protocol listeners.
    let root_stop = options.shutdown.clone();
    let mut bg_tasks: JoinSet<(&'static str, Result<(), String>)> = JoinSet::new();
    let (watch_stop_tx, watch_stop_rx) = tokio::sync::watch::channel(false);
    let hub_opt = options.listen_hub.clone();

    if let Some((exec, direct)) = chain_ready {
        let stop = root_stop.clone();
        let hub = hub_opt.clone();
        bg_tasks.spawn(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cancel_bridge = tokio::spawn(async move {
                stop.cancelled().await;
                let _ = tx.send(());
            });
            if let Some(hub) = hub {
                chain.listen_with_hub(exec, hub, rx).await;
            } else {
                chain.listen(exec, direct, rx).await;
            }
            cancel_bridge.abort();
            ("auth-chain", Ok(()))
        });
    }

    if let Some(worker) = acme_renewal {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("acme-renewal", Ok(()))
        });
    }
    if let Some((socket, path, control)) = setup_control_ready {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            crate::setup_control::serve(socket, path, control, stop.cancelled_owned()).await;
            ("setup-control", Ok(()))
        });
    }
    if subsystems.http {
        if let Some(listener) = activated.acme {
            let stop = root_stop.clone();
            let store = acme_store.clone();
            let host = acme_hostname.clone();
            bg_tasks.spawn(async move {
                crate::acme::serve_http80(listener, store, host, stop.cancelled_owned()).await;
                ("acme-http80", Ok(()))
            });
        }
    }

    if let Some((denylist, direct)) = session_worker {
        let stop = root_stop.clone();
        let hub = hub_opt.clone();
        bg_tasks.spawn(async move {
            let res = if let Some(hub) = hub {
                denylist.run_with_hub(hub, stop.cancelled_owned()).await
            } else {
                denylist.run(direct, stop.cancelled_owned()).await
            };
            ("session-worker", res.map_err(|e| e.to_string()))
        });
    }
    if let Some(engine) = backup {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            let res = engine.run(stop.cancelled_owned()).await;
            ("backup-worker", res.map_err(|e| e.to_string()))
        });
    }
    if let Some(worker) = recovery {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("recovery-worker", Ok(()))
        });
    }
    if subsystems.workers {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            crate::mdm_notify::run_until(stop.cancelled_owned()).await;
            ("mdm-notify", Ok(()))
        });
    }
    if let Some(worker) = booking_expiry {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("booking-expiry", Ok(()))
        });
    }
    if let Some(worker) = user_risk {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("user-risk", Ok(()))
        });
    }
    if let Some(worker) = webhook_publications {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("webhook-publications", Ok(()))
        });
    }
    if let Some(worker) = webhook_retry {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("webhook-retry", Ok(()))
        });
    }
    if let Some(worker) = notify_drain {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("notify-intent-drain", Ok(()))
        });
    }
    if let Some(worker) = work_queue {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop).await;
            ("work-queue", Ok(()))
        });
    }
    if let Some(worker) = secevents {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("security-event-delivery", Ok(()))
        });
    }
    if let Some(worker) = dmarc_report {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("dmarc-report", Ok(()))
        });
    }
    if let Some(worker) = outbound {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("outbound-mail", Ok(()))
        });
    }
    if let Some(worker) = tls_rpt {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("tls-rpt-report", Ok(()))
        });
    }
    if let Some(worker) = smime_trust {
        let stop = root_stop.clone();
        let hub = hub_opt.clone();
        bg_tasks.spawn(async move {
            if let Some(hub) = hub {
                worker.run_with_hub(hub, stop.cancelled_owned()).await;
            } else {
                worker.run_until(stop.cancelled_owned()).await;
            }
            ("smime-trust-listener", Ok(()))
        });
    }
    if let Some((worker, direct)) = spam_trainer {
        let stop = root_stop.clone();
        let hub = hub_opt.clone();
        bg_tasks.spawn(async move {
            if let Some(hub) = hub {
                worker.run_with_hub(hub, stop.cancelled_owned()).await;
            } else {
                worker.run_until(direct, stop.cancelled_owned()).await;
            }
            ("spam-trainer", Ok(()))
        });
    }
    if let Some(worker) = meet_reconcile {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("meet-reconcile", Ok(()))
        });
    }
    if let Some(worker) = push_drain {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("push-intent-drain", Ok(()))
        });
    }
    if let Some(worker) = drive_maintenance {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("drive-maintenance", Ok(()))
        });
    }
    if let Some(worker) = drive_preview {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("drive-preview", Ok(()))
        });
    }
    if let Some(worker) = exchange_deletion {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("exchange-deletion", Ok(()))
        });
    }
    if let Some(worker) = blob_cleanup {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("blob-cleanup", Ok(()))
        });
    }
    if let Some(worker) = mail_work {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("mail-work", Ok(()))
        });
    }
    if let Some(worker) = mailbox_lifecycle {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("mailbox-lifecycle", Ok(()))
        });
    }
    if let Some(worker) = subscription_sync {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("calendar-subscription-sync", Ok(()))
        });
    }
    if let Some(worker) = chat_reaper {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("chat-reaper", Ok(()))
        });
    }
    if let Some((worker, direct)) = approval {
        let stop = root_stop.clone();
        let hub = hub_opt.clone();
        bg_tasks.spawn(async move {
            if let Some(hub) = hub {
                worker.run_with_hub(hub, stop.cancelled_owned()).await;
            } else {
                worker.run_until(direct, stop.cancelled_owned()).await;
            }
            ("approval-worker", Ok(()))
        });
    }
    if subsystems.workers {
        if let Some(worker) =
            guests.filter(|_| workers::listed("RUST_WORKERS_ON", "guest-lifecycle"))
        {
            let stop = root_stop.clone();
            bg_tasks.spawn(async move {
                worker.run_until(stop.cancelled_owned()).await;
                ("guest-lifecycle", Ok(()))
            });
        }
    }
    if let Some((worker, direct)) = drive_watch {
        let stop = root_stop.clone();
        let hub = hub_opt.clone();
        bg_tasks.spawn(async move {
            if let Some(hub) = hub {
                worker.run_with_hub(hub, stop.cancelled_owned()).await;
            } else {
                worker.run_until(direct, stop.cancelled_owned()).await;
            }
            ("drive-watch", Ok(()))
        });
    }
    if subsystems.workers {
        if let Some(runtime) = ldap.filter(|_| workers::listed("RUST_WORKERS_ON", "ldap-sync")) {
            let stop = root_stop.clone();
            bg_tasks.spawn(async move {
                runtime.run_until(stop.cancelled_owned()).await;
                ("ldap-sync", Ok(()))
            });
        }
        if let Some(runtime) = ad
            .clone()
            .filter(|_| workers::listed("RUST_WORKERS_ON", "ad-sync"))
        {
            let stop = root_stop.clone();
            bg_tasks.spawn(async move {
                runtime.run_until(stop.cancelled_owned()).await;
                ("ad-sync", Ok(()))
            });
        }
        if let Some(iw) = &identity_workers {
            if let Some((runtime, direct)) = ad
                .filter(|_| workers::listed("RUST_WORKERS_ON", "ad-toggle-observer"))
                .zip(iw.direct.clone())
            {
                let stop = root_stop.clone();
                let hub = hub_opt.clone();
                bg_tasks.spawn(async move {
                    if let Some(hub) = hub {
                        setjoin_directory_sync::observers::run_observer_with_hub(
                            hub,
                            setjoin_directory_sync::observers::touches_ad,
                            move || runtime.wake.notify_one(),
                            stop.cancelled_owned(),
                        )
                        .await;
                    } else {
                        setjoin_directory_sync::observers::run_observer(
                            direct,
                            setjoin_directory_sync::observers::touches_ad,
                            move || runtime.wake.notify_one(),
                            stop.cancelled_owned(),
                        )
                        .await;
                    }
                    ("ad-toggle-observer", Ok(()))
                });
            }
            if let Some(runtime) = source_runtime {
                let stop = root_stop.clone();
                bg_tasks.spawn(async move {
                    runtime.run_until(stop.cancelled_owned()).await;
                    ("identity-source-runtime", Ok(()))
                });
            }
            if let Some(direct) = iw
                .direct
                .clone()
                .filter(|_| workers::listed("RUST_WORKERS_ON", "identity-toggle-observer"))
            {
                let stop = root_stop.clone();
                let trigger = iw.trigger.clone();
                let hub = hub_opt.clone();
                bg_tasks.spawn(async move {
                    if let Some(hub) = hub {
                        setjoin_directory_sync::observers::run_observer_with_hub(
                            hub,
                            setjoin_directory_sync::observers::touches_identity,
                            move || trigger.notify_one(),
                            stop.cancelled_owned(),
                        )
                        .await;
                    } else {
                        setjoin_directory_sync::observers::run_observer(
                            direct,
                            setjoin_directory_sync::observers::touches_identity,
                            move || trigger.notify_one(),
                            stop.cancelled_owned(),
                        )
                        .await;
                    }
                    ("identity-toggle-observer", Ok(()))
                });
            }
        }
    }
    if let Some(scheduler) = cron {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            let res = scheduler.run_until(stop.cancelled_owned()).await;
            ("cron-scheduler", res.map_err(|e| e.to_string()))
        });
    }
    if let Some(admin_jobs) = admin_jobs {
        if let Some(worker) = admin_jobs.bulk {
            let stop = root_stop.clone();
            bg_tasks.spawn(async move {
                worker.run_until(stop.cancelled_owned()).await;
                ("bulk-role-jobs", Ok(()))
            });
        }
        if let Some(worker) = admin_jobs.eap {
            let stop = root_stop.clone();
            bg_tasks.spawn(async move {
                worker.run_until(stop.cancelled_owned()).await;
                ("email-address-policy-jobs", Ok(()))
            });
        }
        if let Some(worker) = admin_jobs.operations {
            let stop = root_stop.clone();
            bg_tasks.spawn(async move {
                worker.run_until(stop.cancelled_owned()).await;
                ("identity-operations", Ok(()))
            });
        }
        if let Some(worker) = admin_jobs.transitions {
            let stop = root_stop.clone();
            bg_tasks.spawn(async move {
                worker.run_until(stop.cancelled_owned()).await;
                ("identity-transitions", Ok(()))
            });
        }
    }
    if let Some(runtime) = federation {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            runtime.run(stop).await;
            ("federation-listener", Ok(()))
        });
    }
    if let Some(worker) = federation_reaper {
        let stop = root_stop.clone();
        bg_tasks.spawn(async move {
            worker.run_until(stop.cancelled_owned()).await;
            ("federation-residue-reap", Ok(()))
        });
    }
    if let Some(runtime) = imap {
        let rx = watch_stop_rx.clone();
        bg_tasks.spawn(async move {
            runtime.run(rx).await;
            ("imap-listener", Ok(()))
        });
    }
    if let Some(runtime) = smtp {
        let rx = watch_stop_rx.clone();
        bg_tasks.spawn(async move {
            runtime.run(rx).await;
            ("smtp-listener", Ok(()))
        });
    }

    // SIGHUP config reload task (reloads gateway config + co-located auth if present).
    {
        let stop = root_stop.clone();
        let reload_authority = options
            .reload_auth_on_sighup
            .then(|| options.auth_authority.clone())
            .flatten();
        bg_tasks.spawn(async move {
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    signal = reload_signal.recv() => {
                        if signal.is_none() {
                            break;
                        }
                        match configuration.reload_for(subsystems, configuration_exec.as_ref()).await {
                            Ok(()) => eprintln!("setjoin-gateway: config reloaded successfully"),
                            Err(error) => eprintln!("setjoin-gateway: config reload failed, keeping old config: {error}"),
                        }
                        if let Some(authority) = &reload_authority {
                            match authority.reload().await {
                                Ok(()) => eprintln!("auth config reload: rearmed=[internal_api_key]"),
                                Err(error) => eprintln!("auth config reload failed: {error}"),
                            }
                        }
                    }
                }
            }
            ("config-reload", Ok(()))
        });
    }

    // All active listeners are bound and initialized; notify systemd READY=1.
    let _ = options.sd_notify.notify_ready();

    // Serve HTTP/HTTPS (or wait for shutdown when HTTP subsystem is disabled).
    let serve_stop = root_stop.clone();
    let serving = async move {
        match (gateway_opt, http_listener, activated.https, tls_frontend) {
            (Some(gateway), Some(listener), Some(https), Some(frontend)) => {
                let tls_gateway = gateway.clone();
                tokio::join!(
                    gateway.serve_until(listener, serve_stop.clone().cancelled_owned()),
                    tls_gateway.serve_tls_until(https, frontend, serve_stop.cancelled_owned()),
                );
            }
            (Some(gateway), Some(listener), _, _) => {
                gateway
                    .serve_until(listener, serve_stop.cancelled_owned())
                    .await;
            }
            _ => {
                serve_stop.cancelled().await;
            }
        }
    };
    tokio::pin!(serving);
    let mut serving_done = false;
    let mut tls_failure = None;
    tokio::select! {
        () = &mut serving => {
            serving_done = true;
            root_stop.cancel();
        },
        () = root_stop.cancelled() => {},
        () = workers::shutdown_signal() => {
            root_stop.cancel();
        },
        error = async {
            match tls_workers.as_mut() {
                Some(workers) => workers.failed().await,
                None => std::future::pending().await,
            }
        } => {
            tls_failure = Some(error);
            root_stop.cancel();
        },
    }

    // Unified concurrent shutdown drain bounded by `options.drain_timeout` (30s).
    let _ = options.sd_notify.notify_stopping();
    let _ = watch_stop_tx.send(true);
    let listen_hub_shutdown = options.listen_hub;
    let mut extra_tasks = options.extra_tasks;
    let drain_result = tokio::time::timeout(options.drain_timeout, async {
        let mut first_error: Option<String> = None;
        let http_drain = async {
            if !serving_done {
                serving.await;
            }
        };
        let bg_drain = async {
            while let Some(joined) = bg_tasks.join_next().await {
                match joined {
                    Ok((_, Ok(()))) => {}
                    Ok((name, Err(err))) => {
                        if first_error.is_none() {
                            first_error = Some(format!("{name}: {err}"));
                        }
                    }
                    Err(err) => {
                        if first_error.is_none() {
                            first_error = Some(format!("background task join error: {err}"));
                        }
                    }
                }
            }
        };
        let extra_drain = async {
            for handle in extra_tasks.iter_mut() {
                let _ = handle.await;
            }
        };
        let storage_drain = async {
            if let Some(storage) = platform_storage {
                storage.shutdown().await;
            }
        };
        let tls_drain = async {
            if let Some(workers) = tls_workers {
                if let Err(err) = workers.shutdown().await {
                    eprintln!("setjoin-gateway: tls worker shutdown error: {err}");
                }
            }
        };
        let webhook_drain = async {
            if let Some(dispatcher) = &webhook {
                dispatcher.shutdown().await;
            }
        };
        tokio::join!(
            http_drain,
            bg_drain,
            extra_drain,
            storage_drain,
            tls_drain,
            webhook_drain
        );
        if let Some(hub) = listen_hub_shutdown {
            hub.shutdown().await;
        }
        first_error
    })
    .await;

    match drain_result {
        Ok(Some(err)) => {
            eprintln!("setjoin-gateway: shutting down (with error: {err})");
            return Err(err);
        }
        Ok(None) => {}
        Err(_) => {
            eprintln!(
                "setjoin-gateway: unified shutdown drain expired after {:?}; aborting remaining tasks",
                options.drain_timeout
            );
            bg_tasks.abort_all();
            while bg_tasks.join_next().await.is_some() {}
            for handle in extra_tasks {
                handle.abort();
                let _ = handle.await;
            }
        }
    }

    eprintln!("setjoin-gateway: shutting down");
    tls_failure.map_or(Ok(()), Err)
}
