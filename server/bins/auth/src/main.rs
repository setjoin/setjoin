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
    let effective_worker_dsn = config.worker_dsn.as_deref().unwrap_or(&config.dsn);
    let dsn_roles = setjoin_pg::rls_preflight::DsnRoleSummary::from_dsns(
        Some(&config.dsn),
        Some(effective_worker_dsn),
        None,
    );
    let rls_report = setjoin_pg::rls_preflight::inspect_rls_posture_executor(
        &exec,
        setjoin_pg::rls_preflight::PostureContext::RuntimeApp,
        Some(dsn_roles),
    )
    .await
    .map_err(|e| format!("native-RLS preflight failed: {e}"))?;
    let rls_errors = rls_report.fail_closed_errors(false);
    if !rls_errors.is_empty() {
        for err in &rls_errors {
            eprintln!("setjoin-auth: ERROR: native-RLS boot check: {err}");
        }
        return Err("native-RLS boot check FAILED — refusing to start".into());
    }
    let boot_posture = Arc::new(setjoin_pg::rls_preflight::BootPosture::from_report(
        rls_report,
        setjoin_pg::rls_preflight::EnforcementMode::FailClosedReleaseNPlus1,
    ));
    if let Err(error)=setjoin_identity::rp::reseal(&config.dsn,config.secret.as_bytes(),config.profile).await{
        eprintln!("OIDC client secret re-seal migration failed; plaintext providers will fail closed: {error}");
    }
    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    let tls = match (&config.tls_cert, &config.tls_key) {
        (Some(cert), Some(key)) => Some(setjoin_auth::load_reloading_tls_config(cert, key)?),
        _ => None,
    };
    // The original auth address is bound before any shared task can start:
    // authserverd must have released it in the whole-process swap (#331).
    let worker = setjoin_threat::WorkerPools::from_dsns(&config.dsn, config.worker_dsn.as_deref())?;
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
        gate.clone(),
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
    let drain_dsn = config.dsn.clone();
    let drain_worker_dsn = config.worker_dsn.clone();
    let server = Arc::new(
        AuthServer::load(exec, config)
            .await?
            .with_gate(gate)
            .with_boot_posture(boot_posture),
    );
    let reload_server = server.clone();
    // Wave 2.1 (#548): run a lightweight notify_intents drain task whenever a
    // worker/DB DSN is available so standalone setjoin-auth never strands
    // session_revoke / identity_link notifications when workers are stopped.
    let (drain_stop_tx, drain_stop_rx) = tokio::sync::oneshot::channel::<()>();
    let drain_task =
        setjoin_pg::workers::WorkerDatabase::from_dsns(&drain_dsn, drain_worker_dsn.as_deref())
            .ok()
            .map(|db| tokio::spawn(run_auth_notify_drain(db, drain_stop_rx)));
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
    let _ = drain_stop_tx.send(());
    if let Some(handle) = drain_task {
        let _ = handle.await;
    }
    Ok(())
}

async fn run_auth_notify_drain(
    db: setjoin_pg::workers::WorkerDatabase,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) {
    const DRAIN_SQL: &str = "WITH batch AS (
        DELETE FROM notify_intents
         WHERE id IN (SELECT id FROM notify_intents ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED)
         RETURNING id, channel, payload
    ),
    emitted AS (
        SELECT pg_notify(channel, payload)
          FROM (SELECT channel, payload FROM batch GROUP BY channel, payload ORDER BY MIN(id)) deduped
    )
    SELECT (SELECT count(*) FROM batch)::bigint, (SELECT count(*) FROM emitted)::bigint";
    const BATCH: i64 = 500;
    let mut conn: Option<setjoin_pg::workers::WorkerConnection> = None;
    let mut ticks = tokio::time::interval(std::time::Duration::from_millis(50));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => return,
            _ = ticks.tick() => {}
        }
        loop {
            let active = match conn.as_ref() {
                Some(c) => c,
                None => {
                    let connected = tokio::select! {
                        biased;
                        _ = &mut stop => return,
                        res = db.connect() => res,
                    };
                    match connected {
                        Ok(c) => conn.insert(c),
                        Err(_) => break,
                    }
                }
            };
            let queried = tokio::select! {
                biased;
                _ = &mut stop => return,
                res = active.query(DRAIN_SQL, &[(&BATCH, setjoin_pg::Type::INT8)]) => res,
            };
            match queried {
                Ok(rows) => {
                    let deleted = rows
                        .first()
                        .and_then(|r| r.try_get::<_, i64>(0).ok())
                        .unwrap_or(0);
                    if deleted < BATCH {
                        break;
                    }
                }
                Err(_) => {
                    conn = None;
                    break;
                }
            }
        }
    }
}
