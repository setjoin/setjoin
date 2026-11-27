//! `setjoind` — unified Setjoin server binary (#543).
//!
//! Composes `http`, `auth`, `protocols`, and `workers` in one process (default
//! `--subsystems=all`) or runs any selected subset (`--subsystems=http,protocols,workers`,
//! `--subsystems=auth`, `--subsystems=workers`, etc.) behind a single
//! [`AuthAuthority`] seam, one shared `DB_DIRECT_DSN` [`ListenHub`], strict
//! pre-bind schema verification, hardened systemd socket activation +
//! `sd_notify`, and a unified 30-second concurrent graceful shutdown drain.

use std::ffi::OsStr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use setjoin_auth::{AuthServer, InProcessAuthAuthority};
use setjoin_authz::auth_authority::{AuthAuthority, RemoteAuthAuthority};
use setjoin_authz::legacy_jwt::LegacyKeys;
use setjoin_boot::Subsystems;
use setjoin_gateway::activation::{Activated, SdNotify};
use setjoin_gateway::configuration::{Runtime as ConfigRuntime, Settings};
use setjoin_gateway::runtime::{run_with_options, RuntimeOptions, DEFAULT_DRAIN_TIMEOUT};
use setjoin_pg::{ListenHub, ScopedExecutor};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Exit code for invalid/conflicting CLI flags or subsystem specifications.
pub const EXIT_USAGE: u8 = 2;

/// Parsed CLI command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliAction {
    Version,
    Run(Subsystems),
}

/// Resolve CLI arguments, `SETJOIND_SUBSYSTEMS` env fallback, and `argv[0]`
/// basename fallback.
///
/// Fails closed on:
/// - duplicate or conflicting `--subsystems` flags,
/// - unknown flags or positional arguments,
/// - unknown subsystem names, empty lists, or combining `all` with individual names.
pub fn parse_cli<I, S>(args: I, env_subsystems: Option<&str>) -> Result<CliAction, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut iter = args.into_iter();
    let argv0 = iter
        .next()
        .map(|s| s.as_ref().to_owned())
        .unwrap_or_else(|| "setjoind".into());

    let mut flag_subsystems: Option<Subsystems> = None;
    let mut saw_version = false;

    while let Some(arg) = iter.next() {
        let arg = arg.as_ref();
        match arg {
            "--version" | "-V" => {
                saw_version = true;
            }
            "--subsystems" => {
                if flag_subsystems.is_some() {
                    return Err("duplicate --subsystems flag is not allowed".into());
                }
                let value = iter
                    .next()
                    .ok_or_else(|| "--subsystems requires a value".to_string())?;
                flag_subsystems = Some(Subsystems::parse(value.as_ref())?);
            }
            other if other.starts_with("--subsystems=") => {
                if flag_subsystems.is_some() {
                    return Err("duplicate --subsystems flag is not allowed".into());
                }
                let value = &other["--subsystems=".len()..];
                flag_subsystems = Some(Subsystems::parse(value)?);
            }
            other => {
                return Err(format!("unknown argument: {other:?}"));
            }
        }
    }

    if saw_version {
        if flag_subsystems.is_some() {
            return Err("--version cannot be combined with --subsystems".into());
        }
        return Ok(CliAction::Version);
    }

    if let Some(subsystems) = flag_subsystems {
        return Ok(CliAction::Run(subsystems));
    }

    if let Some(raw_env) = env_subsystems {
        let trimmed = raw_env.trim();
        if !trimmed.is_empty() {
            return Ok(CliAction::Run(Subsystems::parse(trimmed)?));
        }
    }

    Ok(CliAction::Run(default_subsystems_for_argv0(&argv0)))
}

/// Default subsystem selection derived from `argv[0]` basename.
///
/// - `setjoin-server` / `setjoin-gateway` -> `http,protocols,workers` (no `auth`)
/// - `setjoin-auth` -> `auth` only
/// - `setjoind` (or any other name) -> `all`
pub fn default_subsystems_for_argv0(argv0: &str) -> Subsystems {
    let base = Path::new(argv0)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(argv0);
    match base {
        "setjoin-server" | "setjoin-gateway" => Subsystems {
            http: true,
            auth: false,
            protocols: true,
            workers: true,
        },
        "setjoin-auth" => Subsystems {
            http: false,
            auth: true,
            protocols: false,
            workers: false,
        },
        _ => Subsystems::ALL,
    }
}

/// Main process entry point called by `bins/setjoind/src/main.rs`.
pub fn run_cli() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let env_subsystems = std::env::var("SETJOIND_SUBSYSTEMS").ok();
    let subsystems = match parse_cli(&args, env_subsystems.as_deref()) {
        Ok(CliAction::Version) => {
            println!("setjoind {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Ok(CliAction::Run(subsystems)) => subsystems,
        Err(err) => {
            eprintln!("setjoind: {err}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    // Capture and scrub NOTIFY_SOCKET immediately so child processes never inherit it.
    let sd_notify = SdNotify::from_env_and_scrub();

    if std::env::var("GATEWAY_ROUTE_INVENTORY")
        .ok()
        .is_some_and(|v| !v.is_empty())
    {
        eprintln!(
            "setjoind: GATEWAY_ROUTE_INVENTORY is retired in setjoind; unified routing is always active"
        );
        return ExitCode::FAILURE;
    }

    let environment: Vec<(String, String)> = std::env::vars().collect();
    let env_get = |k: &str| {
        environment
            .iter()
            .rev()
            .find(|(name, _)| name == k)
            .map(|(_, value)| value.as_str())
    };
    let settings = match Settings::load_ordered(&environment) {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("setjoind: {error}");
            return ExitCode::FAILURE;
        }
    };
    if env_get("SETJOIN_CONFIG").is_some_and(|path| !path.is_empty()) {
        if let Err(error) = settings.validate_for(subsystems) {
            eprintln!("setjoind: {error}");
            return ExitCode::FAILURE;
        }
    }
    settings.install_startup_environment();

    let configuration = match ConfigRuntime::new_ordered(environment, settings) {
        Ok(configuration) => Arc::new(configuration),
        Err(error) => {
            eprintln!("setjoind: {error}");
            return ExitCode::FAILURE;
        }
    };

    // Atomically capture + FD_CLOEXEC all inherited systemd descriptors BEFORE
    // building the Tokio runtime or running boot/schema checks, so FD 3+ is
    // never Tokio's own epoll/eventfd and any refusal closes every descriptor
    // with zero `accept()` calls.
    let captured = match setjoin_gateway::activation::capture_from_env() {
        Ok(captured) => captured,
        Err(err) => {
            eprintln!("setjoind: {err}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(err) = captured.validate_for_subsystems(subsystems) {
        drop(captured);
        eprintln!("setjoind: {err}");
        return ExitCode::FAILURE;
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            drop(captured);
            eprintln!("setjoind: {error}");
            return ExitCode::FAILURE;
        }
    };

    // Strict pre-bind schema check (`actual == expected`) BEFORE any listener binds.
    let boot_posture = match runtime.block_on(setjoin_boot::run_for_subsystems(subsystems, true)) {
        Ok(posture) => Arc::new(posture),
        Err(refusal) => {
            drop(captured);
            return ExitCode::from(refusal.exit_code);
        }
    };

    let activated = match runtime.block_on(async { captured.into_activated() }) {
        Ok(activated) => activated,
        Err(err) => {
            eprintln!("setjoind: {err}");
            return ExitCode::FAILURE;
        }
    };

    let shutdown = CancellationToken::new();
    match runtime.block_on(run_subsystems(
        subsystems,
        configuration,
        activated,
        sd_notify,
        shutdown,
        boot_posture,
    )) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("setjoind: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Build a [`RemoteAuthAuthority`] for non-`auth` edge nodes.
///
/// Never reads `JWT_SECRET` or `SM2_PRIVATE_KEY_FILE`: only public JWKS,
/// optional `DRIVE_NATIVE_TOKEN_SECRET`, and optional public-only
/// `SM2_PUBLIC_KEY_FILE` (`LegacyKeys::from_sm2_public_pem`).
fn build_remote_auth_authority() -> Result<Option<Arc<dyn AuthAuthority>>, String> {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let base_url = env("GATEWAY_RUST_AUTH_UPSTREAM")
        .or_else(|| env("AUTHSERVER_URL"))
        .or_else(|| env("GATEWAY_AUTH_UPSTREAM"));
    let Some(base_url) = base_url else {
        return Ok(None);
    };
    let jwks_url = env("AUTHSERVER_JWKS_URL");
    let internal_key = env("INTERNAL_API_KEY").unwrap_or_default();
    let profile = env("CRYPTO_ALGORITHM_PROFILE").unwrap_or_default();
    let floor = if profile == "smx" { 16 } else { 32 };
    let drive_secret = env("DRIVE_NATIVE_TOKEN_SECRET").unwrap_or_default();
    if !drive_secret.is_empty() && drive_secret.len() < floor {
        return Err(format!(
            "DRIVE_NATIVE_TOKEN_SECRET must be at least {floor} characters"
        ));
    }
    let sm2_pub_pem = if matches!(profile.as_str(), "smx" | "hybrid") {
        env("SM2_PUBLIC_KEY_FILE")
            .map(std::fs::read_to_string)
            .transpose()
            .map_err(|_| "SM2_PUBLIC_KEY_FILE: unreadable key")?
    } else {
        None
    };
    let legacy = if !drive_secret.is_empty() || sm2_pub_pem.is_some() {
        let kids: &[&str] = if drive_secret.is_empty() {
            &[]
        } else {
            &["mailserver-drive-native-1"]
        };
        Some(LegacyKeys::from_sm2_public_pem(
            drive_secret.as_bytes(),
            kids,
            sm2_pub_pem.as_deref(),
        )?)
    } else {
        None
    };
    let remote = RemoteAuthAuthority::new(&base_url, jwks_url.as_deref(), internal_key, legacy)?;
    Ok(Some(Arc::new(remote)))
}

struct InProcessAuthBundle {
    authority: Arc<dyn AuthAuthority>,
    server: Arc<AuthServer>,
    config_listen: String,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    shared_gate: Arc<setjoin_threat::Gate>,
    _watchers: setjoin_threat::Watchers,
    _saml_listener: Option<setjoin_identity::saml::Listener>,
    _rp_listener: Option<setjoin_identity::rp::Listener>,
    _ca_listener: Option<setjoin_auth::ca::CaListener>,
    _auth_runtime: Option<setjoin_threat::RuntimeHandle>,
}

async fn init_in_process_auth(
    unified_with_http: bool,
    listen_hub: Option<&ListenHub>,
    boot_posture: Arc<setjoin_boot::BootPosture>,
) -> Result<InProcessAuthBundle, String> {
    let config = setjoin_auth::Config::from_env_for(unified_with_http)?;
    let shared_runtime = setjoin_threat::admit_runtime(
        &std::env::var("RUST_WORKERS_ON").unwrap_or_default(),
        &std::env::var("GO_WORKERS_OFF").unwrap_or_default(),
    )?;
    let exec = ScopedExecutor::from_dsn(&config.dsn, 25)
        .map_err(|e| format!("open auth request pool: {}", e.0))?;
    let worker_dsn = config
        .worker_dsn
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(&config.dsn);
    let worker_exec = ScopedExecutor::from_dsn(worker_dsn, 8)
        .map_err(|e| format!("open auth worker pool: {}", e.0))?;

    if let Err(error) =
        setjoin_identity::rp::reseal(&config.dsn, config.secret.as_bytes(), config.profile).await
    {
        eprintln!(
            "OIDC client secret re-seal migration failed; plaintext providers will fail closed: {error}"
        );
    }

    let worker_pools =
        setjoin_threat::WorkerPools::from_dsns(&config.dsn, config.worker_dsn.as_deref())
            .map_err(|e| e.to_string())?;
    let geo = if config.geoip_path.is_empty() {
        None
    } else {
        match std::fs::read(&config.geoip_path)
            .map_err(|e| e.to_string())
            .and_then(|b| setjoin_authz::geoip::CountryDb::from_bytes(b, false, ""))
        {
            Ok(db) => Some(db),
            Err(error) => {
                eprintln!("auth GeoIP not loaded: {error}");
                None
            }
        }
    };
    let gate = setjoin_threat::Gate::load(exec.clone(), worker_pools, config.threat.clone(), geo)
        .await
        .map_err(|e| format!("auth threat gate init failed: {e}"))?;
    let watchers = if let Some(hub) = listen_hub {
        setjoin_threat::Watchers::start_with_hub(gate.clone(), hub)
            .await
            .map_err(|e| format!("auth threat watchers init failed: {e}"))?
    } else {
        setjoin_threat::Watchers::start(
            gate.clone(),
            &config.direct_dsn,
            &format!("setjoind-auth-{}", std::process::id()),
        )
        .await
        .map_err(|e| format!("auth threat watchers init failed: {e}"))?
    };

    let auth_runtime = if shared_runtime {
        let tasks = setjoin_threat::RuntimeTasks::new(&config.dsn, config.worker_dsn.as_deref())
            .map_err(|e| e.to_string())?;
        eprintln!("auth-runtime armed: feed=30m token_gc=1m");
        Some(setjoin_threat::RuntimeHandle(tokio::spawn(async move {
            tasks.run().await
        })))
    } else {
        None
    };

    let config_listen = config.listen.clone();
    let tls_cert = config.tls_cert.clone();
    let tls_key = config.tls_key.clone();

    let server = Arc::new(
        AuthServer::load_shared(exec, Some(worker_exec), config, unified_with_http)
            .await?
            .with_gate(gate.clone())
            .with_boot_posture(boot_posture),
    );
    let (saml_listener, rp_listener, ca_listener) = match listen_hub {
        Some(hub) => (
            server.start_saml_listener_with_hub(hub).await,
            server.start_rp_listener_with_hub(hub).await,
            server.start_ca_listener_with_hub(hub).await,
        ),
        None => (
            server.start_saml_listener().await,
            server.start_rp_listener().await,
            server.start_ca_listener(),
        ),
    };
    let authority: Arc<dyn AuthAuthority> = Arc::new(InProcessAuthAuthority::new(server.clone()));

    Ok(InProcessAuthBundle {
        authority,
        server,
        config_listen,
        tls_cert,
        tls_key,
        shared_gate: gate,
        _watchers: watchers,
        _saml_listener: saml_listener,
        _rp_listener: rp_listener,
        _ca_listener: ca_listener,
        _auth_runtime: auth_runtime,
    })
}

fn build_auth_tls(
    cert_path: Option<&str>,
    key_path: Option<&str>,
) -> Result<Option<tokio_rustls::TlsAcceptor>, String> {
    let (Some(cert), Some(key)) = (cert_path, key_path) else {
        return Ok(None);
    };
    use tokio_rustls::rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
    let certs = CertificateDer::pem_file_iter(cert)
        .map_err(|e| format!("read auth TLS cert: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse auth TLS cert: {e}"))?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("parse auth TLS key: {e}"))?;
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut tls = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("auth TLS protocol config: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("auth TLS cert/key mismatch: {e}"))?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Some(tokio_rustls::TlsAcceptor::from(Arc::new(tls))))
}

async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

/// Compose and execute all enabled subsystems until shutdown.
pub async fn run_subsystems(
    subsystems: Subsystems,
    configuration: Arc<ConfigRuntime>,
    mut activated: Activated,
    sd_notify: SdNotify,
    shutdown: CancellationToken,
    boot_posture: Arc<setjoin_boot::BootPosture>,
) -> Result<(), String> {
    if subsystems.is_empty() {
        return Err("at least one subsystem must be enabled".into());
    }
    activated.validate_for_subsystems(subsystems)?;

    // Spawn ONE shared DB_DIRECT_DSN ListenHub for all subsystems in this process.
    let db_dsn = std::env::var("DB_DSN").ok().filter(|s| !s.is_empty());
    let direct_dsn = std::env::var("DB_DIRECT_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| db_dsn.clone());
    let listen_hub = if let Some(direct) = direct_dsn {
        let hub = ListenHub::spawn(direct, shutdown.clone())
            .map_err(|e| format!("listen hub init failed: {e}"))?;
        let _ = tokio::time::timeout(Duration::from_secs(5), hub.wait_connected()).await;
        Some(hub)
    } else {
        None
    };

    // Auth-only mode (`--subsystems=auth`): bind standalone auth listener or Slot::Auth.
    if subsystems.auth && !subsystems.http && !subsystems.protocols && !subsystems.workers {
        let auth = init_in_process_auth(false, listen_hub.as_ref(), boot_posture.clone()).await?;
        let listener = match activated.auth.take() {
            Some(listener) => listener,
            None => TcpListener::bind(&auth.config_listen)
                .await
                .map_err(|e| format!("auth listen {}: {e}", auth.config_listen))?,
        };
        let tls = build_auth_tls(auth.tls_cert.as_deref(), auth.tls_key.as_deref())?;
        let bound = listener
            .local_addr()
            .map_err(|e| format!("auth listener address: {e}"))?;
        eprintln!("setjoind: auth listening on {bound}");
        let _ = sd_notify.notify_ready();

        let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .map_err(|e| format!("SIGHUP registration: {e}"))?;
        let reload_server = auth.server.clone();
        let stop_sig = shutdown.clone();
        let signal_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_sig.cancelled() => break,
                    _ = shutdown_signal() => {
                        stop_sig.cancel();
                        break;
                    }
                    sig = hup.recv() => {
                        if sig.is_none() {
                            break;
                        }
                        match reload_server.reload() {
                            Ok(()) => eprintln!("auth config reload: rearmed=[internal_api_key]"),
                            Err(error) => eprintln!("setjoind: auth reload failed: {error}"),
                        }
                    }
                }
            }
        });

        let serve_stop = shutdown.clone();
        let notify_stop = sd_notify.clone();
        setjoin_auth::serve_http_until(auth.server.clone(), listener, tls, async move {
            serve_stop.cancelled().await;
            let _ = notify_stop.notify_stopping();
        })
        .await;
        signal_task.abort();
        let _ = signal_task.await;
        drop(auth);
        if let Some(hub) = listen_hub {
            hub.shutdown().await;
        }
        eprintln!("setjoind: shutting down");
        return Ok(());
    }

    // Co-located auth (when `subsystems.auth` is active alongside other subsystems)
    // OR RemoteAuthAuthority (when `subsystems.auth` is false).
    let (auth_bundle, auth_authority, shared_gate, standalone_auth_listener) = if subsystems.auth {
        let bundle =
            init_in_process_auth(subsystems.http, listen_hub.as_ref(), boot_posture.clone())
                .await?;
        let authority = bundle.authority.clone();
        let gate = bundle.shared_gate.clone();
        // In unified mode (`http` + `auth`), `auth` does NOT bind LISTEN_ADDR;
        // only bind standalone auth if `http` is disabled OR systemd explicitly
        // passed a dedicated `Slot::Auth` descriptor.
        let auth_listener = if !subsystems.http {
            Some(match activated.auth.take() {
                Some(l) => l,
                None => TcpListener::bind(&bundle.config_listen)
                    .await
                    .map_err(|e| format!("auth listen {}: {e}", bundle.config_listen))?,
            })
        } else {
            activated.auth.take()
        };
        (Some(bundle), Some(authority), Some(gate), auth_listener)
    } else {
        let remote = if subsystems.http || subsystems.protocols {
            build_remote_auth_authority()?
        } else {
            None
        };
        (None, remote, None, None)
    };

    // If we have an explicit standalone auth listener alongside other subsystems
    // (e.g. `--subsystems=auth,workers` or explicit `Slot::Auth`), bind and build
    // TLS BEFORE `READY=1`, then pass the serve task into `RuntimeOptions::extra_tasks`
    // so it drains concurrently within the single 30-second shutdown budget BEFORE
    // `listen_hub` shuts down.
    let mut extra_tasks = Vec::new();
    if let (Some(bundle), Some(listener)) = (&auth_bundle, standalone_auth_listener) {
        let tls = build_auth_tls(bundle.tls_cert.as_deref(), bundle.tls_key.as_deref())?;
        let bound = listener
            .local_addr()
            .map_err(|e| format!("auth listener address: {e}"))?;
        eprintln!("setjoind: auth listening on {bound}");
        let server = bundle.server.clone();
        let stop = shutdown.clone();
        extra_tasks.push(tokio::spawn(async move {
            setjoin_auth::serve_http_until(server, listener, tls, stop.cancelled_owned()).await;
        }));
    }

    let options = RuntimeOptions {
        subsystems,
        auth_authority,
        listen_hub,
        activated,
        sd_notify,
        shutdown,
        allow_route_inventory_env: false,
        allow_private_keys: subsystems.auth,
        shared_threat_gate: shared_gate,
        reload_auth_on_sighup: subsystems.auth,
        drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        extra_tasks,
        boot_posture,
    };

    let result = run_with_options(configuration, options).await;
    drop(auth_bundle);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_subsystems_flag_equals_and_space_forms() {
        assert_eq!(
            parse_cli(["setjoind", "--subsystems=all"], None).unwrap(),
            CliAction::Run(Subsystems::ALL)
        );
        assert_eq!(
            parse_cli(["setjoind", "--subsystems", "http,protocols,workers"], None).unwrap(),
            CliAction::Run(Subsystems {
                http: true,
                auth: false,
                protocols: true,
                workers: true,
            })
        );
        assert_eq!(
            parse_cli(["setjoind", "--subsystems=auth"], None).unwrap(),
            CliAction::Run(Subsystems {
                http: false,
                auth: true,
                protocols: false,
                workers: false,
            })
        );
        assert_eq!(
            parse_cli(["setjoind", "--version"], None).unwrap(),
            CliAction::Version
        );
        assert_eq!(
            parse_cli(["setjoind", "-V"], None).unwrap(),
            CliAction::Version
        );
    }

    #[test]
    fn cli_env_and_argv0_fallbacks() {
        assert_eq!(
            parse_cli(["setjoind"], Some("workers")).unwrap(),
            CliAction::Run(Subsystems {
                http: false,
                auth: false,
                protocols: false,
                workers: true,
            })
        );
        assert_eq!(
            parse_cli(["/usr/local/bin/setjoin-server"], None).unwrap(),
            CliAction::Run(Subsystems {
                http: true,
                auth: false,
                protocols: true,
                workers: true,
            })
        );
        assert_eq!(
            parse_cli(["/usr/local/bin/setjoin-gateway"], None).unwrap(),
            CliAction::Run(Subsystems {
                http: true,
                auth: false,
                protocols: true,
                workers: true,
            })
        );
        assert_eq!(
            parse_cli(["/usr/local/bin/setjoin-auth"], None).unwrap(),
            CliAction::Run(Subsystems {
                http: false,
                auth: true,
                protocols: false,
                workers: false,
            })
        );
        assert_eq!(
            parse_cli(["/usr/local/bin/setjoind"], None).unwrap(),
            CliAction::Run(Subsystems::ALL)
        );
        // CLI flag overrides env var.
        assert_eq!(
            parse_cli(["setjoind", "--subsystems=http"], Some("workers")).unwrap(),
            CliAction::Run(Subsystems {
                http: true,
                auth: false,
                protocols: false,
                workers: false,
            })
        );
    }

    #[test]
    fn cli_fails_closed_on_duplicate_conflicting_or_unknown_flags() {
        assert!(parse_cli(["setjoind", "--subsystems=http", "--subsystems=auth"], None).is_err());
        assert!(parse_cli(
            ["setjoind", "--subsystems=http", "--subsystems", "http"],
            None
        )
        .is_err());
        assert!(parse_cli(["setjoind", "--subsystems"], None).is_err());
        assert!(parse_cli(["setjoind", "--subsystems=bogus"], None).is_err());
        assert!(parse_cli(["setjoind", "--subsystems=all,http"], None).is_err());
        assert!(parse_cli(["setjoind", "--unknown"], None).is_err());
        assert!(parse_cli(["setjoind", "--version", "--subsystems=all"], None).is_err());
        assert!(parse_cli(["setjoind"], Some("invalid_subsystem")).is_err());
    }
}
