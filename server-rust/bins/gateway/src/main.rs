//! `setjoin-gateway` binary. Go configuration uses defaults → SETJOIN_CONFIG YAML
//! → environment (config.env is supplied by systemd). Front-door settings:
//!
//! - `GATEWAY_LISTEN` — listen address (default `127.0.0.1:8090`).
//! - `GATEWAY_MAX_CONNECTIONS` — combined HTTP/HTTPS capacity (default 1024).
//! - `GATEWAY_UPSTREAM` — Go mailserver base, `http://host:port`; when
//!   unset, Go mailserver fallbacks fail with 502.
//! - `GATEWAY_AUTH_UPSTREAM` — direct Go authserver base (required when ON).
//! - `GATEWAY_RUST_AUTH_UPSTREAM` — `setjoin-auth` base (needed for its ON routes).
//! - `GATEWAY_ENABLED` — defaults true; false retains the legacy plain proxy mode.
//! - Activated `https` + `RUST_WORKERS_ON=http-tls` terminate native TLS;
//!   `cert-monitor,tls-ticket-keys` consume the served chain and persisted keys.
//! - `GATEWAY_ROUTE_INVENTORY` — reviewed JSON file (default: bundled inventory).
//! - `GATEWAY_TRUSTED_PROXIES` — comma-separated IPs/CIDRs whose
//!   `X-Forwarded-For`/`X-Forwarded-Proto` are trusted (Go's loopback defaults
//!   initially; `system_config` is refreshed at startup and reload).
//! - `GATEWAY_UPSTREAM_HEADER_TIMEOUT_SECS` — how long Go may take to send
//!   response headers before the client gets `504` (default 120, Go's
//!   `WriteTimeout`).
//!
//! Local application routes need DB_DSN. AUTHSERVER_JWKS_URL enables ES256;
//! configured JWT_SECRET/SM2 keys also work without it, as Go does. Qualified
//! inventory entries default ON, including push:
//!
//! - `DB_DSN` — the same request-pool credential Go uses (`setjoin_app`
//!   behind PgBouncer); `GATEWAY_DB_POOL` — pool size (default 8).
//! - `AUTHSERVER_JWKS_URL` — the authserver first-party JWKS (`http://` only),
//!   the same URL Go's gateway trusts.
//! - `JWT_ISSUER` (default `mailserver`). `CORE_RATE_LIMIT` (default 600
//!   per minute) applies to the enabled front door regardless of whether the
//!   pilot is installed; Rust and Go share the count (see `jmap::limit`).
//! - `RUST_WORKERS_ON=session-denylist-refresh` enables the Rust refresh
//!   worker; `DB_WORKER_DSN` selects its cross-tenant credential
//!   (fallback `DB_DSN`), and `DB_DIRECT_DSN` is required for LISTEN.
//!
//! Exits on SIGINT/SIGTERM after it stops accepting connections.

use std::process::ExitCode;

use std::sync::Arc;
use std::time::Duration;

use setjoin_gateway::jmap::{
    jwks::Jwks,
    limit::{EdgeLimit, Limiter},
    JmapCommands, JmapRoute,
};
use setjoin_gateway::workers::SessionDenylist;
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use setjoin_pg::workers::WorkerDatabase;
use setjoin_pg::ScopedExecutor;
use tokio::net::TcpListener;

fn main() -> ExitCode {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--version")) {
        println!("setjoin-gateway {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let environment = std::env::vars().collect();
    let settings = match setjoin_gateway::configuration::Settings::load(&environment) {
        Ok(settings) => settings,
        Err(error) => { eprintln!("setjoin-gateway: {error}"); return ExitCode::FAILURE; }
    };
    // An explicit Go configuration has the same validation boundary as reload.
    // The bare front-door bootstrap can still run without local application pools.
    if environment.get("SETJOIN_CONFIG").is_some_and(|path| !path.is_empty()) {
        if let Err(error) = settings.validate() {
            eprintln!("setjoin-gateway: {error}");
            return ExitCode::FAILURE;
        }
    }
    // Publish the resolved startup layer before any runtime thread can read env.
    settings.install_startup_environment();
    let configuration = match setjoin_gateway::configuration::Runtime::new(environment, settings) {
        Ok(configuration) => Arc::new(configuration),
        Err(error) => { eprintln!("setjoin-gateway: {error}"); return ExitCode::FAILURE; }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => { eprintln!("setjoin-gateway: {error}"); return ExitCode::FAILURE; }
    };
    if let Err(refusal) = runtime.block_on(setjoin_boot::run()) {
        return ExitCode::from(refusal.exit_code);
    }
    match runtime.block_on(run(configuration)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("setjoin-gateway: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(configuration: Arc<setjoin_gateway::configuration::Runtime>) -> Result<(), String> {
    let mut reload_signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .map_err(|e| format!("SIGHUP registration: {e}"))?;
    let mut settings = configuration.startup_settings();
    let configuration_exec = std::env::var("DB_DSN").ok().filter(|s| !s.is_empty())
        .map(|dsn| ScopedExecutor::from_dsn(&dsn, 2).map_err(|e| e.0)).transpose()?;
    configuration.refresh_proxies(configuration_exec.as_ref()).await;
    let listen = std::env::var("GATEWAY_LISTEN").unwrap_or_else(|_| "127.0.0.1:8090".into());
    let upstream = std::env::var("GATEWAY_UPSTREAM")
        .ok()
        .filter(|v| !v.is_empty());
    let trusted = std::env::var("GATEWAY_TRUSTED_PROXIES").unwrap_or_default();
    let enabled = match std::env::var("GATEWAY_ENABLED").as_deref() {
        Err(_) | Ok("") | Ok("true") | Ok("1") => true,
        Ok("false") | Ok("0") => false,
        _ => return Err("GATEWAY_ENABLED must be true/false or 1/0".into()),
    };
    let activated = setjoin_gateway::activation::take_from_env()?;
    setjoin_gateway::tls_runtime::guard_activation(&|name| std::env::var(name).ok(), activated.https.is_some())?;
    let tls_frontend = if activated.https.is_some() {
        let verifier = setjoin_gateway::tls_runtime::client_verifier(configuration_exec.as_ref()).await?;
        Some(setjoin_tls::Frontend::from_env_with_client_verifier(&|name| std::env::var(name).ok(), verifier)?
            .ok_or("the https descriptor requires TLS_CERT/TLS_KEY or TLS_AUTOCERT_DOMAINS")?)
    } else { None };
    let federation =
        setjoin_federation::runtime::Runtime::prepare(activated.federation, &|name| {
            std::env::var(name).ok()
        })?;
    let federation_reaper =
        setjoin_federation::runtime::reaper_from_env(&|name| std::env::var(name).ok())?;
    require_go_off("mail-work")?;
    require_go_off("mailbox-lifecycle")?;
    require_go_off("migration-runner")?;
    require_go_off(setjoin_smtp::outbound::NAME)?;
    let webhook = webhook_dispatcher()?;
    let outbound = setjoin_gateway::smtp_outbound::from_environment().await?;
    let migration_runner = migration_runner(webhook.as_ref()).await?;
    let worker = session_worker()?;
    let backup = setjoin_backup::worker::Engine::from_environment()?;
    let recovery = recovery_worker()?;
    let chat_reaper = chat_reaper()?;
    let booking_expiry = booking_expiry()?;
    let user_risk = user_risk_worker()?;
    let subscription_sync = subscription_sync()?;
    let (webhook_publications, webhook_retry) = webhook_workers(webhook.as_ref())?;
    let notify_drain = notify_drain_worker()?;
    let secevents = secevents_worker()?;
    let tls_rpt = tls_rpt_worker()?;
    let smime_cache = Arc::new(setjoin_mail_security::smime::trust::TrustCache::new());
    let smime_trust = smime_trust_listener(smime_cache.clone(), activated.smtp.is_some() || activated.smtps.is_some())?;
    let spam_trainer = spam_trainer_worker()?;
    let push_drain = push_drain_worker()?;
    let meet_reconcile = meet_reconcile_worker()?;
    let dmarc_report = dmarc_report_worker().await?;
    let approval = approval_worker()?;
    let guests = guest_lifecycle()?;
    let drive_watch = drive_watch_worker()?;
    let drive_maintenance = drive_maintenance_worker()?;
    let drive_preview = drive_preview_worker()?;
    let blob_cleanup = blob_cleanup_worker()?;
    let (mail_work, mailbox_lifecycle) = mail_worker_adapters(webhook.as_ref()).await?;
    let exchange_deletion = exchange_deletion_worker()?;
    let cron = cron_scheduler().await?;
    let ldap = ldap_runtime()?;
    let ad = ad_runtime()?;
    let identity_workers = identity_workers()?;
    let admin_jobs = admin_job_workers()?;
    let chain=Arc::new(setjoin_authz::auth_chain::Chain::default());
    let chain_config=if enabled {
        std::env::var("DB_DSN").ok().zip(std::env::var("DB_DIRECT_DSN").ok())
    }else{None};
    if settings.string("network.mode").is_empty() {
        settings.set_network_mode(setjoin_gateway::configuration::detect_network_mode().await);
    }
    let platform_storage = if enabled {
        std::env::var("DB_DSN").ok().filter(|dsn| !dsn.is_empty()).map(|dsn| {
            Ok::<_, String>(Arc::new(setjoin_gateway::platform_storage::Runtime::from_env()?.with_database(
                WorkerDatabase::from_dsns(&dsn, std::env::var("DB_WORKER_DSN").ok().as_deref()).map_err(|e| e.to_string())?)))
        }).transpose()?
    } else { None };
    if let Some(storage)=&platform_storage { storage.recover().await; }
    let (routes, edge_limit) = if enabled {
        routes(
            &settings,
            configuration.clone(),
            worker.as_ref().map(|(denylist, _)| denylist.clone()),
            chain_config.as_ref().map(|_|chain.clone()),
            guests.clone(),
            ldap.clone(),
            ad.clone(),
            subscription_sync.clone(),
            migration_runner.clone(),
            webhook.clone(),
            federation.as_ref().map(|runtime| runtime.service.clone()),
            platform_storage.clone(),
        )
        .await?
    } else {
        (RouteTable::proxy_all(), None)
    };
    let chain_task=if let Some((dsn,direct))=chain_config {
        let exec=ScopedExecutor::from_dsn(&dsn,2).map_err(|e|e.0)?;
        let registry=exec.read("SELECT mode FROM feature_toggle_registry_state WHERE singleton",&[])
            .await.map_err(|_|"feature registry unavailable at startup".to_owned())?;
        if !registry.first().is_some_and(|row|matches!(row.get::<_,String>(0).as_str(),"observe"|"enforce")) {
            return Err("feature registry unavailable at startup".into());
        }
        chain.reload(&exec).await?;
        let(stop,stopped)=tokio::sync::oneshot::channel();
        let task=tokio::spawn(chain.listen(exec,direct,stopped));Some((stop,task))
    }else{None};
    let config = Config {
        upstream: upstream
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|e| format!("GATEWAY_UPSTREAM: {e}"))?,
        trusted_proxies: TrustedProxies::parse(&trusted)
            .map_err(|e| format!("GATEWAY_TRUSTED_PROXIES: {e}"))?,
        upstream_header_timeout: match std::env::var("GATEWAY_UPSTREAM_HEADER_TIMEOUT_SECS") {
            Ok(v) if !v.is_empty() => Duration::from_secs(
                v.parse()
                    .map_err(|e| format!("GATEWAY_UPSTREAM_HEADER_TIMEOUT_SECS: {e}"))?,
            ),
            _ => setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
        },
        edge_limit,
    };
    let mut http_limits = setjoin_gateway::http_limits::HttpLimits::default();
    if let Ok(value) = std::env::var("GATEWAY_MAX_CONNECTIONS") {
        http_limits.max_connections = value
            .parse()
            .map_err(|e| format!("GATEWAY_MAX_CONNECTIONS: {e}"))?;
    }
    let mut gateway = Gateway::new(config, routes)?
        .with_http_limits(http_limits)
        .map_err(|e| format!("GATEWAY_MAX_CONNECTIONS: {e}"))?
        .with_configuration(&configuration)
        .with_enabled(enabled);
    if enabled {
        let auth = std::env::var("GATEWAY_AUTH_UPSTREAM")
            .map_err(|_| "GATEWAY_AUTH_UPSTREAM is required when enabled")?;
        gateway = gateway.with_auth_upstream(
            auth.parse()
                .map_err(|e| format!("GATEWAY_AUTH_UPSTREAM: {e}"))?,
        )?;
        if let Ok(auth) = std::env::var("GATEWAY_RUST_AUTH_UPSTREAM") {
            if !auth.is_empty() {
                gateway = gateway.with_rust_auth_upstream(
                    auth.parse()
                        .map_err(|e| format!("GATEWAY_RUST_AUTH_UPSTREAM: {e}"))?,
                )?;
            }
        }
        if let Ok(path) = std::env::var("GATEWAY_ROUTE_INVENTORY") {
            let json = std::fs::read_to_string(path)
                .map_err(|e| format!("GATEWAY_ROUTE_INVENTORY: {e}"))?;
            let candidate = setjoin_gateway::inventory::Inventory::parse(&json)?;
            let qualified =
                setjoin_gateway::inventory::Inventory::parse(setjoin_gateway::inventory::BUNDLED)?;
            candidate.require_qualified(&qualified)?;
            gateway = gateway.with_inventory(&json)?;
        }
    }
    let mut tls_workers = match tls_frontend.as_ref() {
        Some(frontend) => Some(setjoin_gateway::tls_runtime::start(frontend.clone(), &|name| std::env::var(name).ok()).await?),
        None => None,
    };
    // ACME (#305): the :80 descriptor named `acme` and the http-01 renewal worker share one store.
    setjoin_gateway::acme::guard(
        std::env::var("RUST_WORKERS_ON").ok().as_deref(),
        std::env::var("GO_WORKERS_OFF").ok().as_deref(),
        activated.acme.is_some(),
        tls_frontend.is_some(),
        &std::env::var("TLS_AUTOCERT_CHALLENGE").unwrap_or_default(),
    )?;
    let acme_store = setjoin_acme::Http01Store::default();
    let dns_degraded = std::env::var("TLS_AUTOCERT_CHALLENGE").as_deref() == Ok("dns-01");
    let acme_settings =
        setjoin_gateway::acme::settings(&|name| std::env::var(name).ok()).or_else(|e| {
            if listed("RUST_WORKERS_ON", setjoin_gateway::acme::RENEWAL) && !dns_degraded {
                Err(e)
            } else {
                if listed("RUST_WORKERS_ON", setjoin_gateway::acme::RENEWAL) {
                    eprintln!("TLS: managed ACME client creation failed: {e}");
                }
                Ok(None)
            }
        })?;
    let acme_hostname = acme_settings
        .as_ref()
        .map(|s| s.hostname.clone())
        .unwrap_or_else(|| std::env::var("HOSTNAME").unwrap_or_default());
    let acme_renewal = acme_settings
        .filter(|_| listed("RUST_WORKERS_ON", setjoin_gateway::acme::RENEWAL))
        .map(|s| setjoin_gateway::acme::Renewal::new(s, acme_store.clone(), tls_frontend.as_ref().map(|f|f.tls_alpn_store())))
        .transpose()
        .or_else(|e| {
            if dns_degraded {
                // Frozen Go keeps cached/static HTTPS available on DNS setup errors.
                eprintln!("TLS: managed ACME client creation failed: {e}");
                Ok(None)
            } else {
                Err(e)
            }
        })?;
    let acme_renewal_task = acme_renewal.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    // Setup control socket (#305): Rust owns it only with Go's copy off.
    require_go_off(setjoin_gateway::setup_control::NAME)?;
    let setup_control_task = if listed("RUST_WORKERS_ON", setjoin_gateway::setup_control::NAME) {
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
            .unwrap_or_else(|| setjoin_gateway::setup_control::DEFAULT_SOCKET.into());
        let token = std::env::var("SETJOIN_SETUP_TOKEN")
            .unwrap_or_default()
            .trim()
            .to_owned();
        if token.is_empty() {
            eprintln!("setjoin-gateway: SETJOIN_SETUP_TOKEN is not configured; setup calls are refused until it is set");
        }
        let primary = match setjoin_gateway::setup_control::primary_from_env(&|n| {
            std::env::var(n).ok()
        }) {
            Ok(store) => Some(store),
            Err(e) => {
                eprintln!("setjoin-gateway: setup: primary storage driver init failed, restore unavailable: {e}");
                None
            }
        };
        let path = std::path::PathBuf::from(path);
        let socket = setjoin_gateway::setup_control::bind(&path)
            .map_err(|e| format!("setup control socket unavailable: {e}"))?;
        let control = Arc::new(setjoin_gateway::setup_control::Control { db, primary, token });
        eprintln!(
            "setjoin-gateway: local setup control socket ready path={}",
            path.display()
        );
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(setjoin_gateway::setup_control::serve(
            socket,
            path,
            control,
            async move {
                let _ = stopped.await;
            },
        ));
        Some((stop, task))
    } else {
        None
    };
    let acme_http80_task = activated.acme.map(|listener| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(setjoin_gateway::acme::serve_http80(
            listener,
            acme_store.clone(),
            acme_hostname.clone(),
            async move {
                let _ = stopped.await;
            },
        ));
        (stop, task)
    });
    let imap_on = activated.imap.is_some() || activated.imaps.is_some();
    let smtp_off = setjoin_gateway::smtp_runtime::required_off(
        activated.smtp.is_some(),
        activated.smtps.is_some(),
        activated.submission.is_some(),
    );
    let protocol_security = if imap_on || !smtp_off.is_empty() {
        let mut protocols = Vec::new();
        if imap_on {
            protocols.push("imap");
        }
        protocols.extend(smtp_off);
        match setjoin_gateway::imap_runtime::shared_security(&settings, &protocols).await {
            Ok(security) => Some(security),
            // IMAP keeps its refuse-to-start guard; an SMTP-only failure must not
            // take the HTTPS front door down.
            Err(error) if !imap_on => {
                eprintln!("SMTP not started: {error}");
                None
            }
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    let imap = setjoin_gateway::imap_runtime::start(
        activated.imap,
        activated.imaps,
        &|name| std::env::var(name).ok(),
        protocol_security.as_ref().map(|(gate,_)|gate.clone() as Arc<dyn setjoin_imap::ThreatGate>),
        webhook.clone(),
    )?;
    let smtp = setjoin_gateway::smtp_runtime::start_or_log(setjoin_gateway::smtp_runtime::start_with_trust_cache(
        activated.smtp,
        activated.smtps,
        activated.submission,
        &|name| std::env::var(name).ok(),
        protocol_security.as_ref().map(|(gate,_)|gate.clone()),
        webhook.clone(),
        smime_cache,
    ));
    let listener = match activated.http {
        Some(listener) => listener,
        None => TcpListener::bind(&listen)
            .await
            .map_err(|e| format!("listen {listen}: {e}"))?,
    };
    let worker_task = worker.map(|(denylist, direct)| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(denylist.run(direct, async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let backup_task = backup.map(|engine| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(engine.run(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let recovery_task = recovery.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    // Go emits these subscription diagnostics even with its named worker OFF.
    // This observer has no shared effects and lives with the Rust process.
    let mdm_notify_task = {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(setjoin_gateway::mdm_notify::run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    };
    let booking_expiry_task = booking_expiry.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let user_risk_task = user_risk.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let webhook_publications_task = webhook_publications.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let webhook_retry_task = webhook_retry.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let notify_drain_task = notify_drain.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let secevents_task = secevents.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let dmarc_report_task = dmarc_report.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let outbound_task = outbound.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let tls_rpt_task = tls_rpt.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let smime_trust_task = smime_trust.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let spam_trainer_task = spam_trainer.map(|(worker, direct)| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(direct, async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let meet_reconcile_task = meet_reconcile.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let push_drain_task = push_drain.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let drive_maintenance_task = drive_maintenance.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let drive_preview_task = drive_preview.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let exchange_deletion_task = exchange_deletion.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let blob_cleanup_task = blob_cleanup.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let mail_work_task = mail_work.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let mailbox_lifecycle_task = mailbox_lifecycle.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let subscription_sync_task = subscription_sync.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let chat_reaper_task = chat_reaper.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let approval_task = approval.map(|(worker, direct)| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(direct, async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let guest_task = guests
        .filter(|_| {
            std::env::var("RUST_WORKERS_ON")
                .unwrap_or_default()
                .split(',')
                .any(|s| s.trim() == "guest-lifecycle")
        })
        .map(|worker| {
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let task = tokio::spawn(worker.run_until(async move {
                let _ = stopped.await;
            }));
            (stop, task)
        });
    let drive_watch_task = drive_watch.map(|(worker, direct)| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(direct, async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    // `ldap-sync` is a shared-effect worker: Rust runs the periodic cycle only
    // when asked (and Go's copy is off, checked by `ldap_runtime`).
    let ldap_task = ldap
        .clone()
        .filter(|_| listed("RUST_WORKERS_ON", "ldap-sync"))
        .map(|runtime| {
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let task = tokio::spawn(async move {
                runtime
                    .run_until(async move {
                        let _ = stopped.await;
                    })
                    .await
            });
            (stop, task)
        });
    // `ad-sync` is a shared-effect worker like `ldap-sync`; its two observers and
    // the identity observer are listeners on `config_changed`, and
    // `identity-metrics` is derived on every `/metrics` scrape (nothing to run).
    let ad_task = ad
        .clone()
        .filter(|_| listed("RUST_WORKERS_ON", "ad-sync"))
        .map(|runtime| {
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let task = tokio::spawn(async move {
                runtime
                    .run_until(async move {
                        let _ = stopped.await;
                    })
                    .await
            });
            (stop, task)
        });
    let ad_observer_task = ad
        .clone()
        .filter(|_| listed("RUST_WORKERS_ON", "ad-toggle-observer"))
        .zip(identity_workers.direct.clone())
        .map(|(runtime, direct)| {
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let task = tokio::spawn(setjoin_directory_sync::observers::run_observer(
                direct,
                setjoin_directory_sync::observers::touches_ad,
                move || runtime.wake.notify_one(),
                async move {
                    let _ = stopped.await;
                },
            ));
            (stop, task)
        });
    // `identity-source-runtime` (#400): the catalog ldap:/ad: source manager. Go's
    // `Start` failing its first reconciliation ends the process; so does this.
    let source_runtime_task = match identity_workers.runtime.clone() {
        Some(runtime) => {
            runtime.start().await?;
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let task = tokio::spawn(async move {
                runtime
                    .run_until(async move {
                        let _ = stopped.await;
                    })
                    .await
            });
            Some((stop, task))
        }
        None => None,
    };
    let identity_observer_task = identity_workers
        .direct
        .clone()
        .filter(|_| listed("RUST_WORKERS_ON", "identity-toggle-observer"))
        .map(|direct| {
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let trigger = identity_workers.trigger.clone();
            let task = tokio::spawn(setjoin_directory_sync::observers::run_observer(
                direct,
                setjoin_directory_sync::observers::touches_identity,
                move || trigger.notify_one(),
                async move {
                    let _ = stopped.await;
                },
            ));
            (stop, task)
        });
    let cron_task = cron.map(|scheduler| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(scheduler.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    // The four Admin identity job workers (#412); each runs only with `RUST_WORKERS_ON`
    // and Go's copy off (checked by `admin_job_workers`).
    let admin_job_tasks: Vec<(
        &str,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    )> = {
        let mut tasks = Vec::new();
        macro_rules! spawn_job {
            ($name:expr, $worker:expr) => {
                if let Some(worker) = $worker {
                    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
                    let task = tokio::spawn(worker.run_until(async move {
                        let _ = stopped.await;
                    }));
                    tasks.push(($name, stop, task));
                }
            };
        }
        spawn_job!("bulk-role-jobs", admin_jobs.bulk);
        spawn_job!("email-address-policy-jobs", admin_jobs.eap);
        spawn_job!("identity-operations", admin_jobs.operations);
        spawn_job!("identity-transitions", admin_jobs.transitions);
        tasks
    };
    let bound = listener
        .local_addr()
        .map_err(|e| format!("listener address: {e}"))?;
    eprintln!(
        "setjoin-gateway: listening on {bound}, Go upstream {}",
        upstream.as_deref().unwrap_or("unset")
    );
    let federation_stop = tokio_util::sync::CancellationToken::new();
    let federation_task =
        federation.map(|runtime| tokio::spawn(runtime.run(federation_stop.clone())));
    let federation_reap_task = federation_reaper.map(|worker| {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(worker.run_until(async move {
            let _ = stopped.await;
        }));
        (stop, task)
    });
    let (imap_stop, imap_rx) = tokio::sync::watch::channel(false);
    let imap_task = imap.map(|runtime| tokio::spawn(runtime.run(imap_rx)));
    let (smtp_stop, smtp_rx) = tokio::sync::watch::channel(false);
    let smtp_task = smtp.map(|runtime| tokio::spawn(runtime.run(smtp_rx)));
    // Process-local config cache: both copies run until Go is deleted. Tokio's
    // signal stream coalesces pending SIGHUPs just like Go's size-one channel.
    let (reload_stop, mut reload_stopped) = tokio::sync::oneshot::channel::<()>();
    let reload_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut reload_stopped => break,
                signal = reload_signal.recv() => {
                    if signal.is_none() { break; }
                    match configuration.reload(configuration_exec.as_ref()).await {
                        Ok(()) => eprintln!("setjoin-gateway: config reloaded successfully"),
                        Err(error) => eprintln!("setjoin-gateway: config reload failed, keeping old config: {error}"),
                    }
                }
            }
        }
    });
    let transport_stop = tokio_util::sync::CancellationToken::new();
    let stop = transport_stop.clone();
    let serving = async move {
        match (activated.https, tls_frontend) {
            (Some(https), Some(frontend)) => {
                let tls_gateway = gateway.clone();
                tokio::join!(
                    gateway.serve_until(listener, stop.clone().cancelled_owned()),
                    tls_gateway.serve_tls_until(https, frontend, stop.cancelled_owned()),
                );
            }
            _ => gateway.serve_until(listener, stop.cancelled_owned()).await,
        }
    };
    tokio::pin!(serving);
    let mut tls_failure = None;
    tokio::select! {
        () = &mut serving => {},
        () = shutdown_signal() => { transport_stop.cancel(); serving.await; },
        error = async { match tls_workers.as_mut() {Some(workers) => workers.failed().await, None => std::future::pending().await} } => {
            tls_failure = Some(error); transport_stop.cancel(); serving.await;
        },
    }
    if let Some(storage) = platform_storage {
        if tokio::time::timeout(Duration::from_secs(60), storage.shutdown()).await.is_err() {
            eprintln!("storage migration outer drain expired; terminating before dependency closure");
            std::process::exit(1);
        }
    }
    if let Some(workers) = tls_workers { workers.shutdown().await?; }
    let _ = reload_stop.send(());
    tokio::time::timeout(Duration::from_secs(5), reload_task).await
        .map_err(|_| "config reload shutdown timed out")?
        .map_err(|e| format!("config reload task: {e}"))?;
    if let Some((stop,task))=chain_task {let _=stop.send(());tokio::time::timeout(Duration::from_secs(5),task).await.map_err(|_|"auth-chain shutdown timeout")?.map_err(|e|e.to_string())?;}
    federation_stop.cancel();
    if let Some(task) = federation_task {
        task.await
            .map_err(|e| format!("federation listener task: {e}"))?;
    }
    let _ = imap_stop.send(true);
    if let Some(task) = imap_task {
        task.await.map_err(|e| format!("imap listener task: {e}"))?;
    }
    let _ = smtp_stop.send(true);
    if let Some(task) = smtp_task {
        task.await.map_err(|e| format!("smtp listener task: {e}"))?;
    }
    for (name, task) in [
        ("federation-residue-reap", federation_reap_task),
        ("acme-renewal", acme_renewal_task),
        ("acme :80 listener", acme_http80_task),
        ("setup control socket", setup_control_task),
    ] {
        if let Some((stop, task)) = task {
            let _ = stop.send(());
            task.await.map_err(|e| format!("{name} task: {e}"))?;
        }
    }
    for (name, task) in [
        ("identity toggle observer", identity_observer_task),
        ("identity source runtime", source_runtime_task),
        ("ad toggle observer", ad_observer_task),
        ("ad sync worker", ad_task),
    ] {
        if let Some((stop, task)) = task {
            let _ = stop.send(());
            task.await.map_err(|e| format!("{name} task: {e}"))?;
        }
    }
    for (name, task) in [
        ("mail-work", mail_work_task),
        ("mailbox-lifecycle", mailbox_lifecycle_task),
    ] {
        if let Some((stop, task)) = task {
            let _ = stop.send(());
            task.await.map_err(|e| format!("{name} worker task: {e}"))?;
        }
    }
    for (name, stop, task) in admin_job_tasks {
        let _ = stop.send(());
        task.await.map_err(|e| format!("{name} worker task: {e}"))?;
    }
    if let Some((stop, task)) = ldap_task {
        let _ = stop.send(());
        task.await
            .map_err(|e| format!("ldap sync worker task: {e}"))?;
    }
    if let Some((stop, task)) = cron_task {
        let _ = stop.send(());
        task.await
            .map_err(|e| format!("cron scheduler task: {e}"))?
            .map_err(|e| format!("cron scheduler: {e}"))?;
    }
    let (stop, task) = mdm_notify_task;
    let _ = stop.send(());
    task.await.map_err(|e| format!("mdm-notify task: {e}"))?;
    if let Some((stop, task)) = booking_expiry_task {
        let _ = stop.send(());
        task.await
            .map_err(|e| format!("booking expiry task: {e}"))?;
    }
    if let Some((stop, task)) = user_risk_task {
        let _ = stop.send(());
        task.await.map_err(|e| format!("user-risk task: {e}"))?;
    }
    if let Some((stop, task)) = webhook_publications_task {
        let _ = stop.send(());
        task.await
            .map_err(|e| format!("webhook-publications task: {e}"))?;
    }
    if let Some((stop, task)) = webhook_retry_task {
        let _ = stop.send(());
        task.await.map_err(|e| format!("webhook-retry task: {e}"))?;
    }
    if let Some(dispatcher) = &webhook {
        dispatcher.shutdown().await;
    }
    if let Some((stop, task)) = notify_drain_task {
        let _ = stop.send(());
        task.await
            .map_err(|e| format!("notify-intent-drain task: {e}"))?;
    }
    if let Some((stop, task)) = secevents_task {
        let _ = stop.send(());
        task.await
            .map_err(|e| format!("security-event-delivery task: {e}"))?;
    }
    if let Some((stop, task)) = dmarc_report_task {
        let _ = stop.send(());
        task.await.map_err(|e| format!("dmarc-report task: {e}"))?;
    }
    if let Some((stop, task)) = outbound_task {
        let _ = stop.send(());
        task.await.map_err(|e| format!("outbound-mail task: {e}"))?;
    }
    if let Some((stop, task)) = tls_rpt_task {
        let _ = stop.send(());
        task.await
            .map_err(|e| format!("tls-rpt-report task: {e}"))?;
    }
    if let Some((stop, task)) = smime_trust_task {
        let _ = stop.send(());
        task.await
            .map_err(|e| format!("smime-trust-listener task: {e}"))?;
    }
    if let Some((stop, task)) = spam_trainer_task {
        let _ = stop.send(());
        task.await.map_err(|e| format!("spam-trainer task: {e}"))?;
    }
    if let Some((stop, task)) = meet_reconcile_task {
        let _ = stop.send(());
        task.await
            .map_err(|e| format!("meet-reconcile task: {e}"))?;
    }
    if let Some((stop, task)) = push_drain_task {
        let _ = stop.send(());
        task.await
            .map_err(|e| format!("push-intent-drain task: {e}"))?;
    }
    if let Some((stop, task)) = drive_maintenance_task {
        let _ = stop.send(());
        task.await
            .map_err(|e| format!("drive-maintenance task: {e}"))?;
    }
    if let Some((stop, task)) = drive_preview_task {
        let _ = stop.send(());
        task.await.map_err(|e| format!("drive-preview task: {e}"))?;
    }
    if let Some((stop, task)) = exchange_deletion_task {
        let _ = stop.send(());
        task.await
            .map_err(|e| format!("exchange deletion task: {e}"))?;
    }
    if let Some((stop, task)) = blob_cleanup_task {
        let _ = stop.send(());
        task.await.map_err(|e| format!("blob-cleanup task: {e}"))?;
    }
    if let Some((stop, task)) = subscription_sync_task {
        let _ = stop.send(());
        task.await
            .map_err(|e| format!("calendar subscription sync task: {e}"))?;
    }
    if let Some((stop, task)) = chat_reaper_task {
        let _ = stop.send(());
        task.await.map_err(|e| format!("chat reaper task: {e}"))?;
    }
    if let Some((stop, task)) = drive_watch_task {
        let _ = stop.send(());
        task.await
            .map_err(|e| format!("drive watch worker task: {e}"))?;
    }
    if let Some((stop, task)) = guest_task {
        let _ = stop.send(());
        task.await.map_err(|e| format!("guest worker task: {e}"))?;
    }
    if let Some((stop, task)) = approval_task {
        let _ = stop.send(());
        task.await
            .map_err(|e| format!("approval worker task: {e}"))?;
    }
    if let Some((stop, task)) = recovery_task {
        let _ = stop.send(());
        task.await
            .map_err(|err| format!("recovery worker task: {err}"))?;
    }
    if let Some((stop, task)) = worker_task {
        let _ = stop.send(());
        match tokio::time::timeout(Duration::from_secs(5), task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(err))) => return Err(format!("session worker: {err}")),
            Ok(Err(err)) => return Err(format!("session worker task: {err}")),
            Err(_) => return Err("session worker shutdown timed out".into()),
        }
    }
    if let Some((stop, task)) = backup_task {
        let _ = stop.send(());
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .map_err(|_| "backup worker shutdown timed out")?
            .map_err(|e| format!("backup worker task: {e}"))??;
    }
    eprintln!("setjoin-gateway: shutting down");
    tls_failure.map_or(Ok(()), Err)
}

/// The route table and the enabled front door's shared core budget.
async fn routes(
    settings: &setjoin_gateway::configuration::Settings,
    configuration: Arc<setjoin_gateway::configuration::Runtime>,
    denylist: Option<Arc<SessionDenylist>>,
    chain:Option<Arc<setjoin_authz::auth_chain::Chain>>,
    lifecycle: Option<Arc<setjoin_gateway::guest_worker::GuestLifecycle>>,
    ldap: Option<Arc<setjoin_directory_sync::ldap::runtime::LdapRuntime>>,
    ad: Option<Arc<setjoin_directory_sync::ad::AdRuntime>>,
    subscription_sync: Option<Arc<setjoin_gateway::subscription_sync::SubscriptionSync>>,
    migration_runner: Option<setjoin_gateway::migration::Runner>,
    webhook: Option<setjoin_gateway::webhook::Dispatcher>,
    federation: Option<Arc<setjoin_federation::service::Service>>,
    platform_storage: Option<Arc<setjoin_gateway::platform_storage::Runtime>>,
) -> Result<(RouteTable, Option<EdgeLimit>), String> {
    // The final route is the positional catch-all; concrete namespaces must
    // be registered before it in both the public-only and full tables.
    let table = RouteTable::proxy_all().with(setjoin_gateway::oidc_namespace::Namespace);
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    // Go's envutil.ParseInt: an unparsable value keeps the default; a value
    // <= 0 makes Go refuse every request.
    let limit = env("CORE_RATE_LIMIT")
        .and_then(|v| v.parse::<i64>().ok())
        .map_or(600, |n| n.max(0) as u64);
    let edge = EdgeLimit::for_front_door(Limiter::new(limit, 60));
    let website = env("WEBSITE_DIR")
        .map(|root| {
            setjoin_static::website::Website::load(std::path::Path::new(&root)).map(Arc::new)
        })
        .transpose()?;
    let Some(dsn) = env("DB_DSN") else {
        eprintln!(
            "setjoin-gateway: application routes not installed (needs DB_DSN); public catch-alls installed"
        );
        let mut catchall = setjoin_gateway::catchall::CatchallRoute::new();
        catchall.website = website;
        return Ok((table.with_catchall(catchall), Some(edge)));
    };
    let pool = env("GATEWAY_DB_POOL")
        .map_or(Ok(8), |v| v.parse::<usize>())
        .map_err(|e| format!("GATEWAY_DB_POOL: {e}"))?;
    let exec = ScopedExecutor::from_dsn(&dsn, pool)
        .map_err(|e| format!("DB_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        );
    // Go's JWKS setting is optional: JWT_SECRET/SM2 can authenticate without
    // an ES256 provider. An empty source grants no ES256 keys and performs no I/O.
    let mut keys = match env("AUTHSERVER_JWKS_URL") {
        Some(jwks) => Jwks::new(jwks.parse().map_err(|e| format!("AUTHSERVER_JWKS_URL: {e}"))?)?,
        None => Jwks::with_fetch(Box::new(|| Box::pin(async { Ok(br#"{"keys":[]}"#.to_vec()) }))),
    };
    if let Some(secret) = env("JWT_SECRET") {
        let floor=if env("CRYPTO_ALGORITHM_PROFILE").as_deref()==Some("smx"){16}else{32};
        if secret.len()<floor{return Err(format!("JWT_SECRET must be at least {floor} characters"));}
        let sm2_pem = if matches!(
            env("CRYPTO_ALGORITHM_PROFILE").as_deref(),
            Some("smx" | "hybrid")
        ) {
            env("SM2_PRIVATE_KEY_FILE")
                .map(std::fs::read_to_string)
                .transpose()
                .map_err(|_| "SM2_PRIVATE_KEY_FILE: unreadable key")?
        } else {
            None
        };
        if env("CRYPTO_ALGORITHM_PROFILE").as_deref()==Some("smx") && sm2_pem.is_none(){
            return Err("SM2_PRIVATE_KEY_FILE is required for smx".into());
        }
        keys = keys.with_legacy_keys(setjoin_authz::legacy_jwt::LegacyKeys::from_pem(
            secret.as_bytes(),
            &["authserver-hmac-1","mailserver-drive-native-1"],
            sm2_pem.as_deref(),
        )?);
    } else {
        // #356a: without JWT_SECRET every HS256/SM2 credential is refused
        // natively (push, SSE, presence and every other family); nothing is
        // handed to Go. Installs share the authserver's config.env secret.
        eprintln!("setjoin-gateway: JWT_SECRET is unset; HS256/SM2 tokens will be refused (401). Set the authserver's JWT_SECRET in config.env.");
    }
    let keys = Arc::new(keys);
    let issuer = env("JWT_ISSUER").unwrap_or_else(|| "mailserver".into());
    eprintln!(
        "setjoin-gateway: mark-read route installed (serves only while feature.rust_mark_read is ON)"
    );
    let family = setjoin_gateway::f16::F16Config::from_env(
        exec.clone(),
        keys.clone(),
        issuer.clone(),
        denylist.clone(),
    )?;
    let office =
        setjoin_gateway::f15::F15Config::from_env(exec.clone(), keys.clone(), issuer.clone())?;
    let compliance_worker_dsn = env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone());
    let compliance = setjoin_gateway::compliance::ComplianceRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(&compliance_worker_dsn, pool)
            .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
            .with_audit_keys(
                env("DB_ENCRYPTION_KEY").unwrap_or_default(),
                env("AUDIT_HMAC_KEY").unwrap_or_default(),
            ),
        jobs: setjoin_gateway::compliance::SearchJobs::new(
            setjoin_pg::workers::WorkerDatabase::new(&compliance_worker_dsn)
                .map_err(|e| e.to_string())?,
            pool,
        ),
        store: Some(Arc::new(
            setjoin_gateway::recovery_worker::S3Store::from_env()?,
        )),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let chat_compliance = setjoin_gateway::chat_compliance::ChatComplianceRoute {
        exec: exec.clone(),
        worker: compliance.worker.clone(),
        database: WorkerDatabase::new(&compliance_worker_dsn).map_err(|e| e.to_string())?,
        store: compliance.store.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let mail_security = setjoin_gateway::mail_security::MailSecurityRoute::new(
        exec.clone(),
        compliance.worker.clone(),
        keys.clone(),
        issuer.clone(),
    );
    let rules = setjoin_gateway::rules::RulesRoute {
        exec: exec.clone(),
        worker: compliance.worker.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let link_protect =
        setjoin_gateway::link_protect::LinkProtectRoute::from_env(compliance.worker.clone());
    let conditional_access = setjoin_gateway::conditional_access::ConditionalAccessRoute {
        exec: exec.clone(),
        worker: Some(
            ScopedExecutor::from_dsn(&env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()), pool)
                .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
                .with_audit_keys(
                    env("DB_ENCRYPTION_KEY").unwrap_or_default(),
                    env("AUDIT_HMAC_KEY").unwrap_or_default(),
                ),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let retention_audit = setjoin_gateway::retention_audit::RetentionAuditRoute {
        exec: exec.clone(),
        worker: compliance.worker.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let approval = setjoin_gateway::approvals::ApprovalsRoute {
        exec: exec.clone(),
        worker_exec: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
        secret: env("JWT_SECRET").unwrap_or_default().into_bytes(),
    };
    let chat_store = Arc::new(setjoin_gateway::recovery_worker::S3Store::from_env()?);
    let channels = setjoin_gateway::chat_channels::ChannelRoute {
        unfurl: Some(Arc::new(setjoin_gateway::chat_unfurl::Unfurl::production(
            exec.clone(),
            chat_store.clone(),
        ))),
        federation_typing: federation
            .map(|service| Arc::new(setjoin_gateway::federation_typing::Typing::new(service))),
        federation_local_domain: std::env::var("FEDERATION_LOCAL_DOMAIN")
            .unwrap_or_default()
            .trim()
            .to_lowercase(),
        exec: exec.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let chat_b = setjoin_gateway::chat_b::ChatBRoute {
        exec: exec.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
        store: Some(chat_store),
    };
    let chat = setjoin_gateway::chat::ChatRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let guests = setjoin_gateway::guests::GuestsRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
        delivery: Some(Arc::new(
            setjoin_gateway::recovery_worker::S3Store::from_env()?,
        )),
        lifecycle,
    };
    let calendar = setjoin_gateway::calendar::CalendarRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        queue: Some(
            WorkerDatabase::from_dsns(&dsn, env("DB_WORKER_DSN").as_deref())
                .map_err(|e| format!("DB_WORKER_DSN: {e}"))?,
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
        store: Some(Arc::new(
            setjoin_gateway::recovery_worker::S3Store::from_env()?,
        )),
        public_base: format!(
            "https://{}",
            env("HOSTNAME").unwrap_or_else(|| "localhost".into())
        ),
        // The detached first fetch of a new subscription is the
        // calendar-subscription-sync worker's; without it the route stays with Go.
        kick: subscription_sync.map(|sync| {
            Arc::new(setjoin_gateway::subscription_sync::SyncKick::new(sync))
                as Arc<dyn setjoin_gateway::calendar::SubscriptionKick>
        }),
    };
    // Go snapshots feature.caldav while mounting the listener. The process-local
    // timezone cache stays active in both processes until Go is deleted.
    let caldav = if setjoin_calendar::caldav_enabled(&exec)
        .await
        .map_err(|_| "CalDAV boot feature unavailable".to_owned())?
    {
        let route = setjoin_gateway::caldav::CalDavRoute::new(
            exec.clone(),
            keys.clone(),
            issuer.clone(),
        )
        .await;
        if let Some(direct) = env("DB_DIRECT_DSN") {
            route.start_timezone_listener(direct);
        }
        Some(route)
    } else {
        None
    };
    // Like Go, snapshot the bridge registration flag at process startup.
    let carddav = if setjoin_calendar::flag(&exec, "feature.carddav", true)
        .await
        .map_err(|_| "CardDAV boot feature unavailable".to_owned())?
    {
        Some(setjoin_gateway::carddav::CardDavRoute {
            exec: exec.clone(),
            keys: keys.clone(),
            issuer: issuer.clone(),
        })
    } else {
        None
    };
    let contacts = setjoin_gateway::contacts::ContactsRoute {
        exec: exec.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let admin_identity = setjoin_gateway::admin_identity::AdminIdentityRoute {
        exec: exec.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let admin_access_reviews = setjoin_gateway::admin_access_reviews::AdminAccessReviewsRoute {
        exec: exec.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let admin_scope_sets = setjoin_gateway::admin_scope_sets::AdminScopeSetsRoute {
        exec: exec.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let admin_org_policies = setjoin_gateway::admin_org_policies::AdminOrgPoliciesRoute {
        exec: exec.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let admin_sod = setjoin_gateway::admin_sod::AdminSodRoute {
        exec: exec.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    // One ok-to-error tracker for both health verdicts (Go's single `health.Handler`).
    let health_alerts = webhook
        .clone()
        .map(|dispatcher| setjoin_gateway::health_alerts::HealthAlerts::new(dispatcher).observer());
    let mut platform =
        setjoin_gateway::platform::PlatformRoute::new(exec.clone(), keys.clone(), issuer.clone())
            .with_configuration(configuration.clone())
            .with_overrides(setjoin_platform::features::Overrides::from_env(&|name| {
                std::env::var(name).ok()
            }))
            .with_livekit(setjoin_gateway::meet_livekit::LiveKit::from_env());
    if let Some(alerts) = &health_alerts {
        platform = platform.with_health_alerts(alerts.clone());
    }
    let deploy_source = configuration.clone();
    let deploy_config = setjoin_platform::deploy::Config {
        host_key: env("DEPLOY_HOST_KEY").unwrap_or_default(),
        checksum: env("DEPLOY_SEAWEEDFS_SHA256").unwrap_or_default(),
        credentials: Arc::new(move || deploy_source.source_settings().map(|settings| (settings.string("s3.access_key"), settings.string("s3.secret_key"))).unwrap_or_default()),
    };
    let platform_updates = setjoin_gateway::platform_updates::PlatformUpdatesRoute::new(
        exec.clone(),
        keys.clone(),
        issuer.clone(),
    ).with_recovery(
        compliance.worker.clone(),
        family.as_ref().is_some_and(|f| f.continuity.is_some()),
        env("DB_DIRECT_DSN"),
    ).await.with_deploy(compliance.worker.clone(),deploy_config).await.with_airgap(match setjoin_platform::airgap::Store::load("/var/lib/setjoin/updates",env("OFFLINE_UPDATE_TRUST_ROOTS").map(|s|s.trim().to_owned()).filter(|s|!s.is_empty()).unwrap_or_else(||"/etc/setjoin/offline-update-roots.json".into())) {Ok(store)=>Some(Arc::new(store)),Err(error)=>{eprintln!("{error}");None}});
    let platform_jobs = setjoin_gateway::platform_jobs::PlatformJobsRoute {
        exec: exec.clone(),
        worker: compliance.worker.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
        storage: platform_storage,
    };
    let platform_webhooks = setjoin_gateway::platform_webhooks::PlatformWebhooksRoute {
        exec: exec.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
        codec: webhook_codec(),
    };
    let platform_terms = setjoin_gateway::platform_terms::PlatformTermsRoute::new(
        exec.clone(),
        keys.clone(),
        issuer.clone(),
    )
    .with_worker(
        ScopedExecutor::from_dsn(&env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()), pool)
            .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
            .with_audit_keys(
                env("DB_ENCRYPTION_KEY").unwrap_or_default(),
                env("AUDIT_HMAC_KEY").unwrap_or_default(),
            ),
    )
    .with_store(Arc::new(
        setjoin_gateway::recovery_worker::S3Store::from_env()?,
    ));
    let admin_identity_v2 = setjoin_gateway::admin_identity_v2::AdminIdentityV2Route {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
        secrets: setjoin_gateway::admin_identity_v2::SourceSecrets::from_process_env().with_probe(
            Arc::new(setjoin_gateway::directory_sync::DirectoryProbe(
                WorkerDatabase::from_dsns(&dsn, env("DB_WORKER_DSN").as_deref())
                    .map_err(|e| format!("DB_WORKER_DSN: {e}"))?,
            )),
        ),
    };
    let admin_identity_v2_upgrade =
        setjoin_gateway::admin_identity_v2_upgrade::AdminIdentityV2UpgradeRoute {
            exec: exec.clone(),
            worker: ScopedExecutor::from_dsn(
                &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
                pool,
            )
            .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
            .with_audit_keys(
                env("DB_ENCRYPTION_KEY").unwrap_or_default(),
                env("AUDIT_HMAC_KEY").unwrap_or_default(),
            ),
            keys: keys.clone(),
            issuer: issuer.clone(),
            secrets: setjoin_gateway::admin_identity_v2::SourceSecrets::from_process_env(),
            // Go's `IdentityRuntimeReadiness`: each DSN defaults to `DB_DSN`, the
            // authserver URL to a non-empty default.
            runtime: setjoin_admin_identity::idv2_upgrade::Runtime {
                expected_schema: setjoin_schema::MIGRATIONS.last().map_or(0, |m| m.0),
                worker_dsn: env("DB_WORKER_DSN").or_else(|| env("DB_DSN")).is_some(),
                owner_dsn: env("DB_OWNER_DSN").or_else(|| env("DB_DSN")).is_some(),
                direct_dsn: env("DB_DIRECT_DSN").or_else(|| env("DB_DSN")).is_some(),
                authserver: std::env::var("AUTHSERVER_URL").map_or(true, |v| !v.is_empty()),
            },
        };
    let admin_users_lifecycle = setjoin_gateway::admin_users_lifecycle::AdminUsersLifecycleRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
        authserver_url: env("SCIM_AUTHSERVER_URL")
            .unwrap_or_else(|| "http://localhost:8443".into()),
        internal_key: env("INTERNAL_API_KEY").unwrap_or_default(),
        dispatcher: webhook.ok_or("DB_DSN is required for the webhook dispatcher")?,
    };
    let mailboxes = setjoin_gateway::mailboxes::MailboxesRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let mailbox_io = setjoin_gateway::mailbox_io::MailboxIoRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        store: Arc::new(setjoin_gateway::recovery_worker::S3Store::from_env()?),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let exchange = setjoin_gateway::exchange::ExchangeRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
        artifacts: setjoin_gateway::exchange::Artifacts {
            signer: setjoin_gateway::exchange::signer_from_env()?,
            store: Some(Arc::new(
                setjoin_gateway::recovery_worker::S3Store::from_env()?,
            )),
            master: env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            profile: setjoin_mailboxes::exchange_artifact::Profile::parse(
                &env("CRYPTO_ALGORITHM_PROFILE").unwrap_or_default(),
            ),
        },
    };
    let migration = setjoin_gateway::migration::MigrationRoute {
        exec: exec.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
        encryption_key: env("DB_ENCRYPTION_KEY").unwrap_or_default(),
        runner: migration_runner.clone(),
        public_host: env("HOSTNAME").unwrap_or_default(),
    };
    let devices = setjoin_gateway::devices::DevicesRoute {
        exec: exec.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let identity_self_service = setjoin_gateway::identity_self_service::IdentitySelfServiceRoute {
        exec: exec.clone(),
        worker: compliance.worker.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
        webhook_codec: webhook_codec(),
        migration_runner,
        webhook_resolver: std::sync::Arc::new(setjoin_gateway::identity_self_service::SystemResolver),
    };
    let user_settings = setjoin_gateway::user_settings::UserSettingsRoute::new(
        exec.clone(),
        keys.clone(),
        issuer.clone(),
    );
    let offline = setjoin_gateway::offline::OfflineRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?,
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let dirsync = setjoin_gateway::directory_sync::DirectorySyncRoute {
        exec: exec.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
        ldap,
        ad,
    };
    let scim = setjoin_gateway::scim::ScimRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
        authserver_url: env("SCIM_AUTHSERVER_URL")
            .unwrap_or_else(|| "http://localhost:8443".into()),
        internal_key: env("INTERNAL_API_KEY").unwrap_or_default(),
    };
    let runtime=setjoin_gateway::runtime_access::RuntimeAccess::new(exec.clone(),keys.clone(),issuer.clone())
        .with_attachment_secrets(
            env("JWT_MAIL_ATTACHMENT_SECRET")
                .or_else(|| env("JWT_SECRET"))
                .unwrap_or_default()
                .into_bytes(),
            env("JWT_MAIL_ATTACHMENT_PREVIOUS_SECRET").map(String::into_bytes),
        )
        .with_workers(compliance.worker.clone(),WorkerDatabase::from_dsns(&dsn,env("DB_WORKER_DSN").as_deref()).map_err(|e|e.to_string())?)
        .with_sessions(denylist.clone())
        .with_direct(env("DB_DIRECT_DSN").ok_or("DB_DIRECT_DSN required for runtime gates")?)
        .with_device_secret(env("JWT_SECRET").unwrap_or_default().into_bytes(),setjoin_config_secret::CryptoProfile::parse(&env("CRYPTO_ALGORITHM_PROFILE").unwrap_or_default()));
    let denylist=runtime.session_cache();
    let drive_native=setjoin_gateway::drive_native::NativeTokenRoute::new(exec.clone(),keys.clone(),issuer.clone(),env("JWT_SECRET").as_deref()).with_chain(chain);
    let drive = setjoin_gateway::drive::DriveRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        store: Some(Arc::new(
            setjoin_gateway::recovery_worker::S3Store::from_env()?,
        )),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let drive_core = setjoin_gateway::drive::core::CoreRoute {
        exec: exec.clone(),
        worker: drive.worker.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
        store: office.store.clone(),
    };
    let meet = setjoin_gateway::meet::MeetRoute::new(
        exec.clone(),
        keys.clone(),
        issuer.clone(),
        setjoin_gateway::meet_livekit::LiveKit::from_env(),
    )
    .with_worker(
        ScopedExecutor::from_dsn(&env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()), pool)
            .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
            .with_audit_keys(
                env("DB_ENCRYPTION_KEY").unwrap_or_default(),
                env("AUDIT_HMAC_KEY").unwrap_or_default(),
            ),
    );
    // Go registers /rtc only when the LiveKit sidecar is configured, at the
    // fixed loopback signal address.
    let rtc = setjoin_gateway::rtc::RtcRoute::new(
        exec.clone(),
        keys.clone(),
        issuer.clone(),
        setjoin_gateway::meet_livekit::LiveKit::from_env().configured(),
        setjoin_gateway::rtc::SFU_SIGNAL
            .parse()
            .expect("fixed SFU signal address"),
    );
    let (assist_exec, assist_keys, assist_issuer) = (exec.clone(), keys.clone(), issuer.clone());
    let commands = Arc::new(JmapCommands {
        worker: Some(compliance.worker.clone()),
        services: Some(Arc::new(setjoin_gateway::jmap::JmapServices::from_env(
            ScopedExecutor::from_dsn(&env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()), pool)
                .map_err(|e| e.0)?,
        ))),
        exec,
        keys: keys.clone(),
        issuer: issuer.clone(),
        denylist:denylist.clone(),
    });
    let mut push = setjoin_gateway::jmap::push::WebSocketRoute::new(
        commands.clone(),
        env("DB_DIRECT_DSN").unwrap_or_default(),
    ).with_device_cache(runtime.device_cache());
    push.worker = Some(
        WorkerDatabase::from_dsns(&dsn, env("DB_WORKER_DSN").as_deref())
            .map_err(|e| format!("push DB_WORKER_DSN: {e}"))?,
    );
    push.production = env("TLS_CERT_FILE").is_some()
        || env("TLS_AUTOCERT_DOMAINS").is_some()
        || env("HTTP_MODE").as_deref() == Some("proxy");
    let hostname = env("HOSTNAME").unwrap_or_else(|| "localhost".into());
    if push.production && hostname != "localhost" {
        push.allowed_host = hostname;
    }
    let event_source = setjoin_gateway::jmap::sse::EventSourceRoute::new(&push);
    let presence = setjoin_gateway::jmap::presence::PresenceRoute {
        commands: commands.clone(),
        registry: push.registry.clone(),
    };
    let mut table = table
        .with_admission(compliance.worker.clone(), keys.clone(), issuer.clone(), denylist)
        .with(event_source)
        .with(push)
        .with(presence)
        .with(JmapRoute(commands));
    table = table
        .with(compliance)
        .with(chat_compliance)
        .with(retention_audit)
        .with(mail_security)
        .with(rules)
        .with(link_protect)
        .with(conditional_access)
        .with(approval)
        .with(chat)
        .with(chat_b)
        .with(channels)
        .with(guests)
        .with(calendar)
        .with(contacts)
        .with(admin_identity)
        .with(admin_scope_sets)
        .with(admin_org_policies)
        .with(admin_access_reviews)
        .with(admin_sod)
        .with(platform)
        .with(platform_terms)
        .with(platform_updates)
        .with(platform_webhooks)
        .with(platform_jobs)
        .with(admin_identity_v2)
        .with(admin_identity_v2_upgrade)
        .with(admin_users_lifecycle)
        .with(mailboxes)
        .with(mailbox_io)
        .with(migration)
        .with(devices)
        .with(user_settings)
        .with(identity_self_service)
        .with(offline)
        .with(exchange)
        .with(dirsync)
        .with(scim)
        .with(drive_native)
        .with(drive_core)
        .with(drive)
        .with(meet)
        .with(rtc);
    if let Some(caldav) = caldav {
        table = table.with(caldav);
    }
    let mut catchall = setjoin_gateway::catchall::CatchallRoute::new().with_terminal_auth(
        assist_exec.clone(),
        assist_keys.clone(),
        assist_issuer.clone(),
    );
    catchall.meet_configured = setjoin_gateway::meet_livekit::LiveKit::from_env().configured();
    catchall.website = website;
    table = match carddav {
        Some(route) => table.with(route),
        None => table.with(setjoin_gateway::carddav::Unregistered {
            fallback: catchall.clone(),
        }),
    };
    let surface_config = Arc::new(setjoin_gateway::surface::SurfaceConfig::from_settings(settings));
    table = table
        .with(setjoin_gateway::surface::SurfaceRoute {
            discovery: None,
            fallback: Some(Arc::new(catchall.clone())),
            exec: assist_exec.clone(),
            keys: assist_keys.clone(),
            issuer: assist_issuer.clone(),
            health: Arc::new({
                let livekit = setjoin_gateway::meet_livekit::LiveKit::from_env();
                let gate =
                    setjoin_static::health::HealthGate::new(surface_config.probes_configured)
                        .with_probes(Arc::new(move || {
                            let livekit = livekit.clone();
                            Box::pin(async move {
                                setjoin_gateway::platform::any_probe_failed(&livekit).await
                            })
                        }));
                match &health_alerts {
                    Some(alerts) => gate.with_alerts(alerts.clone()),
                    None => gate,
                }
            }),
            config: surface_config,
        })
        .with(setjoin_gateway::assist::AssistRoute {
            exec: assist_exec,
            keys: assist_keys,
            issuer: assist_issuer,
        });
    if let Some(config) = family {
        table = table.with(setjoin_gateway::f16::F16Route::new(config));
    }
    table = table.with(setjoin_gateway::f15::F15Route::new(office));
    Ok((table.with_catchall(catchall).with_runtime(runtime), Some(edge)))
}

fn listed(var: &str, name: &str) -> bool {
    std::env::var(var)
        .unwrap_or_default()
        .split(',')
        .any(|s| s.trim() == name)
}

/// The LDAP runtime (#380): routes and the optional `ldap-sync` worker share
/// it. `RUST_WORKERS_ON=ldap-sync` requires `GO_WORKERS_OFF=ldap-sync` first, so
/// two copies never sync one directory.
fn ldap_runtime() -> Result<Option<Arc<setjoin_directory_sync::ldap::runtime::LdapRuntime>>, String>
{
    if listed("RUST_WORKERS_ON", "ldap-sync") && !listed("GO_WORKERS_OFF", "ldap-sync") {
        return Err(
            "ldap-sync requires GO_WORKERS_OFF=ldap-sync before Rust starts shared effects".into(),
        );
    }
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
        setjoin_directory_sync::ldap::runtime::LdapRuntime::from_env(db),
    )))
}

/// A worker Rust takes over needs Go's copy off first, so two copies never
/// run one effect (the startup guard of #259 for the #381 worker names).
/// Go's `sharedwebhook.NewSecretCodec([]byte(cfg.JWTSecret), cfg.CryptoProfile)`.
fn webhook_codec() -> setjoin_platform::webhook_secret::SecretCodec {
    setjoin_platform::webhook_secret::SecretCodec::new(
        std::env::var("JWT_SECRET").unwrap_or_default().as_bytes(),
        setjoin_config_secret::CryptoProfile::parse(
            &std::env::var("CRYPTO_ALGORITHM_PROFILE").unwrap_or_default(),
        ),
    )
}

fn require_go_off(name: &str) -> Result<(), String> {
    if listed("RUST_WORKERS_ON", name) && !listed("GO_WORKERS_OFF", name) {
        return Err(format!(
            "{name} requires GO_WORKERS_OFF={name} before Rust starts it"
        ));
    }
    Ok(())
}

/// The AD runtime (#381): the four AD runtime routes and the optional
/// `ad-sync` worker share it. The resolved boot YAML/env pins Go's enable
/// value. Disabled handlers still exist and answer their native auth/config
/// outcomes; only shared-effect workers require the enable value to be true.
fn ad_runtime() -> Result<Option<Arc<setjoin_directory_sync::ad::AdRuntime>>, String> {
    for name in ["ad-sync", "ad-toggle-observer"] {
        require_go_off(name)?;
    }
    let wanted = ["ad-sync", "ad-toggle-observer"]
        .iter()
        .any(|name| listed("RUST_WORKERS_ON", name));
    if !setjoin_directory_sync::ad::runtime::enabled_from_env() {
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
        setjoin_directory_sync::ad::AdRuntime::from_env(db),
    )))
}

/// What the identity workers share: the direct DSN the observers listen on and
/// the coalesced trigger the identity runtime waits on.
struct IdentityWorkers {
    direct: Option<String>,
    trigger: Arc<tokio::sync::Notify>,
    /// The catalog source manager when `identity-source-runtime` is Rust's.
    runtime: Option<Arc<setjoin_directory_sync::catalog::IdentitySourceRuntime>>,
}

/// Go's `DecodeIdentitySourceRuntime`, owned by the identity-admin family.
fn decode_source(
    codec: Option<&setjoin_config_secret::ConfigSecretCodec>,
    key: &str,
    kind: &str,
    envelope: &[u8],
) -> Result<setjoin_directory_sync::catalog::SourceConfig, String> {
    setjoin_admin_identity::idv2_source::decode_runtime(codec, key, kind, envelope)
        .map(setjoin_gateway::directory_sync::source_config)
}

/// `identity-source-runtime` (#400): Rust starts the catalog manager only with
/// Go's copy off (`GO_WORKERS_OFF`), on the worker credential (`DB_WORKER_DSN`,
/// falling back to `DB_DSN`).
fn identity_source_runtime(
) -> Result<Option<Arc<setjoin_directory_sync::catalog::IdentitySourceRuntime>>, String> {
    require_go_off("identity-source-runtime")?;
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
        setjoin_directory_sync::catalog::IdentitySourceRuntime::from_env(db, decode_source),
    )))
}

/// The Admin identity job workers Rust runs (#412): each needs `RUST_WORKERS_ON=<name>`
/// and Go's copy off (`GO_WORKERS_OFF=<name>`), on the worker credential with the
/// deployment audit keys. `identity-transitions` also takes Go's LiveKit settings
/// (`LIVEKIT_API_KEY`, `LIVEKIT_API_SECRET`, `LIVEKIT_URL`); without all three it runs
/// with no SFU, as Go's nil `meetRooms`.
struct AdminJobs {
    bulk: Option<Arc<setjoin_gateway::admin_job_workers::BulkRoleJobs>>,
    eap: Option<Arc<setjoin_gateway::admin_job_workers::EapJobs>>,
    operations: Option<Arc<setjoin_gateway::admin_job_workers::IdentityOperations>>,
    transitions: Option<Arc<setjoin_gateway::admin_job_workers::IdentityTransitions>>,
}

fn admin_job_workers() -> Result<AdminJobs, String> {
    use setjoin_gateway::admin_job_workers as jobs;
    const NAMES: [&str; 4] = [
        "bulk-role-jobs",
        "email-address-policy-jobs",
        "identity-operations",
        "identity-transitions",
    ];
    for name in NAMES {
        require_go_off(name)?;
    }
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

fn identity_workers() -> Result<IdentityWorkers, String> {
    for name in ["identity-toggle-observer", "identity-metrics"] {
        require_go_off(name)?;
    }
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

fn session_worker() -> Result<Option<(Arc<SessionDenylist>, String)>, String> {
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
                    | "acme-renewal"
                    | "cert-monitor"
                    | "tls-ticket-keys"
                    | "http-tls"
                    | "http-h2c"
                    | "setup-control"
                    | "federation-residue-reap"
                    | "outbound-mail"
            )
    }) {
        return Err("RUST_WORKERS_ON contains an unknown worker".into());
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

fn recovery_worker() -> Result<
    Option<
        setjoin_gateway::recovery_worker::RecoveryCleanup<
            setjoin_gateway::recovery_worker::S3Store,
        >,
    >,
    String,
> {
    use setjoin_gateway::recovery_worker::{RecoveryCleanup, S3Store};
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

async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

fn approval_worker() -> Result<Option<(setjoin_approvals::notify::ApprovalNotify, String)>, String>
{
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
    let secret = std::env::var("JWT_SECRET").unwrap_or_default().into_bytes();
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

fn guest_lifecycle() -> Result<Option<Arc<setjoin_gateway::guest_worker::GuestLifecycle>>, String> {
    let request = std::env::var("DB_DSN").ok().filter(|s| !s.is_empty());
    let requested = std::env::var("RUST_WORKERS_ON")
        .unwrap_or_default()
        .split(',')
        .any(|s| s.trim() == "guest-lifecycle");
    if requested
        && !std::env::var("GO_WORKERS_OFF")
            .unwrap_or_default()
            .split(',')
            .any(|s| s.trim() == "guest-lifecycle")
    {
        return Err("guest-lifecycle requires GO_WORKERS_OFF=guest-lifecycle before Rust starts shared effects".into());
    }
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
    Ok(Some(Arc::new(
        setjoin_gateway::guest_worker::GuestLifecycle {
            db,
            endpoint,
            key,
            secret,
        },
    )))
}

/// `RUST_WORKERS_ON=booking-expiry` takes Go's booking sweeper; two sweeps
/// would race on the same rows, so Go must be off first.
fn booking_expiry() -> Result<Option<setjoin_gateway::booking_worker::BookingExpiry>, String> {
    require_go_off("booking-expiry")?;
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
    Ok(Some(setjoin_gateway::booking_worker::BookingExpiry::new(
        db,
    )))
}

/// `RUST_WORKERS_ON=user-risk` takes Go's user-risk cron (#314); two scorers would run the
/// same reducer per user, so Go must be off first (`GO_WORKERS_OFF=user-risk`).
fn user_risk_worker() -> Result<Option<setjoin_gateway::user_risk_worker::UserRisk>, String> {
    require_go_off("user-risk")?;
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
    Ok(Some(setjoin_gateway::user_risk_worker::UserRisk::new(db)))
}

/// The process's webhook dispatcher (#302): Rust handlers dispatch through it and the two
/// workers below drive its durable queue. It needs the request DSN (the worker credential
/// falls back to it, as in Go); without one nothing in this process can deliver.
fn webhook_dispatcher() -> Result<Option<setjoin_gateway::webhook::Dispatcher>, String> {
    let Some(request) = std::env::var("DB_DSN").ok().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?;
    Ok(Some(setjoin_gateway::webhook::Dispatcher::new(
        db,
        Some(webhook_codec()),
    )))
}

/// `RUST_WORKERS_ON=webhook-publications` and `=webhook-retry` take Go's two durable
/// webhook workers. Both write rows and send HTTP, so a second copy would double every
/// delivery attempt: Go must be off first (leases bound the damage but not the noise).
#[allow(clippy::type_complexity)]
fn webhook_workers(
    dispatcher: Option<&setjoin_gateway::webhook::Dispatcher>,
) -> Result<
    (
        Option<setjoin_gateway::webhook::PublicationWorker>,
        Option<setjoin_gateway::webhook::RetryWorker>,
    ),
    String,
> {
    use setjoin_gateway::webhook::{PUBLICATIONS, RETRY};
    require_go_off(PUBLICATIONS)?;
    require_go_off(RETRY)?;
    let wanted = |name| listed("RUST_WORKERS_ON", name);
    if (wanted(PUBLICATIONS) || wanted(RETRY)) && dispatcher.is_none() {
        return Err("DB_DSN is required for the webhook workers".into());
    }
    Ok((
        dispatcher
            .filter(|_| wanted(PUBLICATIONS))
            .map(|d| setjoin_gateway::webhook::PublicationWorker::new(d.clone())),
        dispatcher
            .filter(|_| wanted(RETRY))
            .map(|d| setjoin_gateway::webhook::RetryWorker::new(d.clone())),
    ))
}

/// `RUST_WORKERS_ON=notify-intent-drain` takes Go's `notify-intent-drain`
/// (#408). Both would drain one queue (SKIP LOCKED keeps rows single-delivery,
/// but two drainers double the idle DELETEs and race the ordering), so Go must
/// be off first. The queue is cross-tenant: worker credential, never request.
fn notify_drain_worker() -> Result<Option<setjoin_gateway::notify_drain::NotifyIntentDrain>, String>
{
    use setjoin_gateway::notify_drain::NAME;
    require_go_off(NAME)?;
    if !listed("RUST_WORKERS_ON", NAME) {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for notify-intent-drain")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?;
    Ok(Some(setjoin_gateway::notify_drain::NotifyIntentDrain::new(
        db,
    )))
}

/// `RUST_WORKERS_ON=security-event-delivery` takes Go's `security-event-delivery`
/// (#304). Go runs it with a nil sink, which is fully inert, and so does this
/// worker: no production sink is admitted. It still refuses to start unless Go's
/// copy is off, so the day a sink is admitted two drainers cannot race. The
/// outbox is FORCE-RLS deny-all: worker credential only.
fn secevents_worker() -> Result<Option<setjoin_gateway::secevents::SecurityEventDelivery>, String> {
    use setjoin_gateway::secevents::NAME;
    require_go_off(NAME)?;
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
    Ok(Some(
        setjoin_gateway::secevents::SecurityEventDelivery::new(db, None),
    ))
}

/// `RUST_WORKERS_ON=tls-rpt-report` takes Go's `tls-rpt-report` (#323): the daily TLS-RPT
/// report POSTs to remote reporting endpoints and deletes the sent sessions, so two copies
/// would double both: Go must be off first. The organisation name is Go's `cfg.Hostname`
/// (the `HOSTNAME` environment; a config-file `hostname` cannot be read here).
fn tls_rpt_worker() -> Result<Option<Arc<setjoin_gateway::tls_rpt::TlsRptReport>>, String> {
    use setjoin_gateway::tls_rpt::NAME;
    require_go_off(NAME)?;
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
    Ok(Some(Arc::new(setjoin_gateway::tls_rpt::TlsRptReport::new(
        db,
        std::env::var("HOSTNAME").unwrap_or_default(),
    ))))
}

/// Every process owning a trust cache needs its own invalidation listener (#526).
/// Native SMTP starts it automatically; the explicit worker name also admits it.
fn smime_trust_listener(
    cache: Arc<setjoin_mail_security::smime::trust::TrustCache>,
    smtp_active: bool,
) -> Result<Option<Arc<setjoin_gateway::smime_trust::SmimeTrustListener>>, String> {
    use setjoin_gateway::smime_trust::{SmimeTrustListener, NAME};
    if !smtp_active && !listed("RUST_WORKERS_ON", NAME) {
        cache.set_cached(false);
        return Ok(None);
    }
    let direct = std::env::var("DB_DIRECT_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("DB_DIRECT_DSN is required for smime-trust-listener")?;
    Ok(Some(Arc::new(SmimeTrustListener::new(
        cache,
        direct,
    ))))
}

/// `RUST_WORKERS_ON=meet-reconcile` takes Go's `meet-reconcile` (#410): room,
/// egress, recording, semantic, Drive-History and captions convergence. It
/// writes to the database, calls LiveKit/Egress/the ASR bot and moves objects,
/// so two copies would double every effect: Go must be off first. Worker
/// credential (cross-tenant sweeps) with the audit keys on the session.
fn meet_reconcile_worker() -> Result<Option<setjoin_gateway::meet_worker::MeetReconcile>, String> {
    use setjoin_gateway::meet_worker::NAME;
    require_go_off(NAME)?;
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
    let store = setjoin_gateway::recovery_worker::S3Store::from_env()?;
    Ok(Some(setjoin_gateway::meet_worker::MeetReconcile::new(
        db,
        setjoin_gateway::meet_livekit::LiveKit::from_env(),
        Some(store),
    )))
}

/// `RUST_WORKERS_ON=dmarc-report` takes Go's `dmarc-report` (#324): the daily DMARC aggregate
/// report enqueue. It writes `outbound_queue` and deletes `dmarc_reports`, so two copies would
/// send every report twice: Go must be off first. Go starts the worker only while
/// `feature.dmarc_reporting` is on (default on), read once at start; so does this, and a
/// disabled toggle leaves Rust's worker off as well. Worker credential, cross-tenant by design.
async fn dmarc_report_worker() -> Result<Option<setjoin_gateway::dmarc_report::DmarcReport>, String>
{
    use setjoin_gateway::dmarc_report::{DmarcReport, NAME};
    require_go_off(NAME)?;
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
fn push_drain_worker() -> Result<Option<setjoin_gateway::push_drain::PushIntentDrain>, String> {
    use setjoin_gateway::push_drain::{GuestDigest, PushIntentDrain, NAME};
    require_go_off(NAME)?;
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
    let store = setjoin_gateway::recovery_worker::S3Store::from_env()
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
fn drive_worker_database(name: &str) -> Result<WorkerDatabase, String> {
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
fn drive_maintenance_worker(
) -> Result<Option<setjoin_gateway::drive_workers::DriveMaintenance>, String> {
    use setjoin_gateway::drive_workers::{DriveMaintenance, MAINTENANCE};
    require_go_off(MAINTENANCE)?;
    if !listed("RUST_WORKERS_ON", MAINTENANCE) {
        return Ok(None);
    }
    let db = drive_worker_database(MAINTENANCE)?;
    let store = setjoin_gateway::recovery_worker::S3Store::from_env()
        .map_err(|e| format!("drive-maintenance needs the object store: {e}"))?;
    Ok(Some(DriveMaintenance::new(db, Arc::new(store), true)))
}

/// `RUST_WORKERS_ON=drive-preview` takes Go's rendition worker (#409). Inert
/// without `DRIVE_PREVIEW_CMD`, exactly as Go (it still needs Go off, so the
/// Rust copy cannot run beside a Go one once a command appears).
fn drive_preview_worker() -> Result<Option<setjoin_gateway::drive_workers::DrivePreview>, String> {
    use setjoin_gateway::drive_workers::{DrivePreview, PREVIEW};
    require_go_off(PREVIEW)?;
    if !listed("RUST_WORKERS_ON", PREVIEW) {
        return Ok(None);
    }
    let db = drive_worker_database(PREVIEW)?;
    let store = setjoin_gateway::recovery_worker::S3Store::from_env()
        .map_err(|e| format!("drive-preview needs the object store: {e}"))?;
    Ok(Some(DrivePreview::new(
        db,
        Arc::new(store),
        std::env::var("DRIVE_PREVIEW_CMD").unwrap_or_default(),
    )))
}

/// `RUST_WORKERS_ON=blob-cleanup` takes Go's 5-minute `blob.Handler.StartCleanup`
/// (#411): both copies would delete the same rows and objects, so Go must be off
/// first. Needs the object store, as Go does.
fn blob_cleanup_worker() -> Result<Option<setjoin_gateway::blob_cleanup::BlobCleanup>, String> {
    use setjoin_gateway::blob_cleanup::{BlobCleanup, NAME};
    require_go_off(NAME)?;
    if !listed("RUST_WORKERS_ON", NAME) {
        return Ok(None);
    }
    let db = drive_worker_database(NAME)?;
    let store = setjoin_gateway::recovery_worker::S3Store::from_env()
        .map_err(|e| format!("blob-cleanup needs the object store: {e}"))?;
    Ok(Some(BlobCleanup::new(db, Arc::new(store))))
}

/// `RUST_WORKERS_ON=calendar-subscription-sync` takes Go's webcal refresh loop (and
/// the subscribe route's detached first fetch); two sweeps would race on the same
/// rows, so Go must be off first.
fn subscription_sync(
) -> Result<Option<Arc<setjoin_gateway::subscription_sync::SubscriptionSync>>, String> {
    require_go_off("calendar-subscription-sync")?;
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
        setjoin_gateway::subscription_sync::SubscriptionSync::new(db),
    )))
}

fn chat_reaper() -> Result<Option<setjoin_gateway::chat_workers::UnfurlReaper>, String> {
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
    Ok(Some(setjoin_gateway::chat_workers::UnfurlReaper::new(db)))
}

/// `RUST_WORKERS_ON=drive-watch` takes the Go `drive-watch` fan-out; both would
/// push to the same `drive-watch:<uid>` channels, so Go must be off first.
fn drive_watch_worker() -> Result<Option<(setjoin_drive::watch::DriveWatch, String)>, String> {
    let listed = |var: &str| {
        std::env::var(var)
            .unwrap_or_default()
            .split(',')
            .any(|s| s.trim() == "drive-watch")
    };
    if !listed("RUST_WORKERS_ON") {
        return Ok(None);
    }
    if !listed("GO_WORKERS_OFF") {
        return Err(
            "drive-watch requires GO_WORKERS_OFF=drive-watch before Rust starts shared effects"
                .into(),
        );
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
async fn cron_scheduler() -> Result<Option<setjoin_gateway::workers::CronScheduler>, String> {
    let configured = std::env::var("RUST_WORKERS_ON").unwrap_or_default();
    let tasks: Vec<_> = configured
        .split(',')
        .map(str::trim)
        .filter_map(|name| name.strip_prefix("cron:"))
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
    let dbs = setjoin_gateway::cron_catalog::CronDatabases {
        worker: db.clone(),
        owner,
    };
    let go_off = std::env::var("GO_WORKERS_OFF").unwrap_or_default();
    let mut scheduler = setjoin_gateway::workers::CronScheduler::per_task(db.clone());
    for name in tasks {
        let action = setjoin_gateway::cron_catalog::cron_action(name, &dbs)
            .ok_or_else(|| format!("cron:{name} has no Rust implementation yet"))?;
        scheduler
            .register_transferred(name, action, &go_off)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(Some(scheduler))
}

/// #295: shared-effect workers transfer independently by their frozen Go names.
async fn mail_worker_adapters(
    dispatcher: Option<&setjoin_gateway::webhook::Dispatcher>,
) -> Result<
    (
        Option<setjoin_gateway::mail_workers::MailWork>,
        Option<setjoin_gateway::mail_workers::MailboxLifecycle>,
    ),
    String,
> {
    use setjoin_gateway::mail_workers::{MailWork, MailboxLifecycle};
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
async fn migration_runner(
    dispatcher: Option<&setjoin_gateway::webhook::Dispatcher>,
) -> Result<Option<setjoin_gateway::migration::Runner>, String> {
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
    let store = setjoin_gateway::recovery_worker::S3Store::from_env()
        .map_err(|e| format!("migration-runner needs the object store: {e}"))?;
    let orchestrator = setjoin_gateway::migration_runner::Orchestrator::new(
        setjoin_gateway::migration_runner::Config {
            db,
            store: Arc::new(store),
            root: keys.0.clone(),
            dialer: setjoin_gateway::migration_runner::Dialer::system(),
            dispatcher: dispatcher.cloned(),
        },
    );
    let recovered = orchestrator.recover_stuck().await?;
    if recovered > 0 {
        eprintln!("migration recovery: marked {recovered} stuck jobs as failed");
    }
    let worker = ScopedExecutor::from_dsn(worker_dsn.as_deref().unwrap_or(&request), 4)
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(keys.0, keys.1);
    Ok(Some(setjoin_gateway::migration::Runner {
        orchestrator,
        worker,
    }))
}

/// Shared DB/S3 effects: explicit per-worker Go-off prerequisite.
fn exchange_deletion_worker(
) -> Result<Option<setjoin_gateway::exchange_deletion::DeletionWorker>, String> {
    use setjoin_gateway::exchange_deletion::{DeletionWorker, NAME};
    require_go_off(NAME)?;
    if !listed("RUST_WORKERS_ON", NAME) {
        return Ok(None);
    }
    let db = drive_worker_database(NAME)?.with_audit_keys(
        std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
        std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
    );
    let store = setjoin_gateway::recovery_worker::S3Store::from_env()
        .map_err(|e| format!("exchange-assessment-deletion needs the object store: {e}"))?;
    let signer = setjoin_gateway::exchange::signer_from_env()?
        .ok_or("exchange-assessment-deletion needs the continuity signing key")?;
    Ok(Some(DeletionWorker::new(db, Arc::new(store), signer)))
}
/// Shared DB effects: Go's trainer must be stopped before Rust can subscribe.
fn spam_trainer_worker(
) -> Result<Option<(setjoin_gateway::spam_trainer::SpamTrainer, String)>, String> {
    use setjoin_gateway::spam_trainer::{SpamTrainer, NAME};
    require_go_off(NAME)?;
    if !listed("RUST_WORKERS_ON", NAME) {
        return Ok(None);
    }
    let request = std::env::var("DB_DSN").ok().filter(|s| !s.is_empty())
        .ok_or("DB_DSN is required for spam-trainer")?;
    let direct = std::env::var("DB_DIRECT_DSN").ok().filter(|s| !s.is_empty())
        .ok_or("DB_DIRECT_DSN is required for spam-trainer")?;
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let db = WorkerDatabase::from_dsns(&request, worker.as_deref())
        .map_err(|e| format!("DB_WORKER_DSN: {e}"))?
        .with_audit_keys(
            std::env::var("DB_ENCRYPTION_KEY").unwrap_or_default(),
            std::env::var("AUDIT_HMAC_KEY").unwrap_or_default(),
        );
    let store = setjoin_gateway::recovery_worker::S3Store::from_env()?;
    Ok(Some((SpamTrainer::new(db, Some(store)), direct)))
}
