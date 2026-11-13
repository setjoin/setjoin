use setjoin_auth::{AuthServer, Config};
use std::sync::Arc;
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("setjoin-auth: {e}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    setjoin_identity::saml::admit_worker(&std::env::var("RUST_WORKERS_ON").unwrap_or_default(),&std::env::var("GO_WORKERS_OFF").unwrap_or_default())?;
    setjoin_identity::rp::admit_worker(&std::env::var("RUST_WORKERS_ON").unwrap_or_default(),&std::env::var("GO_WORKERS_OFF").unwrap_or_default())?;
    let config = Config::from_env()?;
    let shared_runtime = setjoin_threat::admit_runtime(
        &std::env::var("RUST_WORKERS_ON").unwrap_or_default(),
        &std::env::var("GO_WORKERS_OFF").unwrap_or_default(),
    )?;
    #[cfg(unix)]
    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let exec = setjoin_pg::ScopedExecutor::from_dsn(&config.dsn, 25)
        .map_err(|_| "open auth request pool")?;
    let version: i32 = exec
        .read(
            "SELECT COALESCE(MAX(version),0)::int4 FROM schema_migrations",
            &[],
        )
        .await
        .map_err(|_| "read schema version")?[0]
        .get(0);
    let expected = setjoin_schema::MIGRATIONS
        .last()
        .ok_or("empty migration catalog")?
        .0;
    if version != expected {
        return Err("schema version mismatch".into());
    }
    if let Err(error)=setjoin_identity::rp::reseal(&config.dsn,config.secret.as_bytes(),config.profile).await{
        eprintln!("OIDC client secret re-seal migration failed; plaintext providers will fail closed: {error}");
    }
    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    let tls = match (&config.tls_cert, &config.tls_key) {
        (Some(cert), Some(key)) => {
            use tokio_rustls::rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
            let certs = CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?;
            let key = PrivateKeyDer::from_pem_file(key)?;
            let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
            let mut tls = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(certs, key)?;
            tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Some(tokio_rustls::TlsAcceptor::from(Arc::new(tls)))
        }
        _ => None,
    };
    // The original auth address is bound before any shared task can start:
    // authserverd must have released it in the whole-process swap (#331).
    let worker =
        setjoin_pg::workers::WorkerDatabase::from_dsns(&config.dsn, config.worker_dsn.as_deref())?;
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
    let gate = setjoin_threat::Gate::load(exec.clone(), worker, config.threat.clone(), geo).await?;
    let _watchers = setjoin_threat::Watchers::start(
        gate,
        &config.direct_dsn,
        &format!("setjoin-auth-{}", std::process::id()),
    )
    .await?;
    let _runtime = if shared_runtime {
        let tasks = setjoin_threat::RuntimeTasks::new(&config.dsn, config.worker_dsn.as_deref())?;
        eprintln!("auth-runtime armed: feed=30m token_gc=1m; authserverd retired by process swap");
        Some(setjoin_threat::RuntimeHandle(tokio::spawn(async move {
            tasks.run().await
        })))
    } else {
        None
    };
    let server = Arc::new(AuthServer::load(exec, config).await?);
    let _saml_listener=server.start_saml_listener(&std::env::var("RUST_WORKERS_ON").unwrap_or_default(),&std::env::var("GO_WORKERS_OFF").unwrap_or_default()).await?;
    let _rp_listener=server.start_rp_listener(&std::env::var("RUST_WORKERS_ON").unwrap_or_default(),&std::env::var("GO_WORKERS_OFF").unwrap_or_default()).await?;
    let reload_server = server.clone();
    setjoin_auth::serve_until(server, listener, tls, async move {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break,
                    _ = term.recv() => break,
                    _ = hup.recv() => {
                        match reload_server.reload() {
                            Err(error)=>eprintln!("setjoin-auth: reload: {error}"),
                            Ok(())=>eprintln!("auth config reload: rearmed=[internal_api_key] restart_required=[threat_settings,jwt_secret_derived_material,sso_and_authn_boot_options]"),
                        }
                    }
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    })
    .await;
    Ok(())
}
