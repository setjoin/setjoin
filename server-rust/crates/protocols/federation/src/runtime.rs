//! Production federation composition. Native sockets; the existing Go named-worker
//! switch stops the complete Go service, including dialing and accepting.
use crate::{
    db::{FedDb, WorkerPool},
    log::Logger,
    reap::Reaper,
    service::{Config, Service},
    trust::Identity,
};
use setjoin_pg::workers::{DirectListener, WorkerDatabase};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

fn value(get: &dyn Fn(&str) -> Option<String>, key: &str) -> Option<String> {
    get(key).filter(|s| !s.is_empty())
}
fn listed(get: &dyn Fn(&str) -> Option<String>, key: &str, name: &str) -> bool {
    get(key)
        .unwrap_or_default()
        .split(',')
        .any(|s| s.trim() == name)
}
fn database(get: &dyn Fn(&str) -> Option<String>) -> Result<WorkerDatabase, String> {
    let request = value(get, "DB_DSN").ok_or("DB_DSN is required for federation")?;
    WorkerDatabase::from_dsns(&request, value(get, "DB_WORKER_DSN").as_deref())
        .map_err(|e| format!("federation database: {e}"))
}

/// The reaper stays independent of all peering configuration and product toggles.
pub fn reaper_from_env(get: &dyn Fn(&str) -> Option<String>) -> Result<Option<Reaper>, String> {
    if !listed(get, "RUST_WORKERS_ON", crate::reap::NAME) {
        return Ok(None);
    }
    if !listed(get, "GO_WORKERS_OFF", crate::reap::NAME) {
        return Err(
            "federation-residue-reap requires GO_WORKERS_OFF=federation-residue-reap".into(),
        );
    }
    Ok(Some(Reaper::new(Arc::new(WorkerPool::new(database(get)?)))))
}

pub struct Runtime {
    pub service: Arc<Service>,
    listener: TcpListener,
    db: Arc<dyn FedDb>,
    direct: String,
    flags: Arc<AtomicBool>,
}
impl Runtime {
    /// No Rust routing switch. Complete static configuration requires systemd's
    /// `federation` socket and Go's whole service off; absent config stays inert.
    pub fn prepare(
        listener: Option<TcpListener>,
        get: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, String> {
        let domain = value(get, "FEDERATION_LOCAL_DOMAIN")
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        let (Some(cert), Some(key)) = (value(get, "FEDERATION_CERT"), value(get, "FEDERATION_KEY"))
        else {
            return Ok(None);
        };
        if domain.is_empty() {
            return Ok(None);
        }
        let Some(listener) = listener else {
            Logger::stderr().error(
                "federation: activated socket named federation missing — service not started",
            );
            return Ok(None);
        };
        if !listed(get, "GO_WORKERS_OFF", "federation-service") {
            return Err("federation socket activation requires GO_WORKERS_OFF=federation-service: Go's listener and dialers must be off".into());
        }
        let db: Arc<dyn FedDb> = Arc::new(WorkerPool::new(database(get)?));
        let direct = value(get, "DB_DIRECT_DSN")
            .ok_or("DB_DIRECT_DSN is required for federation notifications")?;
        let identity = match Identity::load(&cert, &key) {
            Ok(identity) => identity,
            Err(error) => {
                // Frozen Go logs a bad leaf pair and leaves federation inert;
                // it continues serving the rest of the process.
                eprintln!("federation: load leaf cert/key failed — service not started: {error}");
                return Ok(None);
            }
        };
        let flags = Arc::new(AtomicBool::new(false));
        let mut cfg = Config::new(&domain);
        cfg.direct_dsn = Some(direct.clone());
        cfg.listen_addr = listener
            .local_addr()
            .map_err(|e| e.to_string())?
            .to_string();
        let service = Service::new(cfg, db.clone(), flags.clone(), identity, Logger::stderr())
            .ok_or("federation domain is empty")?;
        Ok(Some(Self {
            service,
            listener,
            db,
            direct,
            flags,
        }))
    }
    pub async fn run(self, ctx: CancellationToken) {
        // Start with feature.federation OFF. A notification outage must not
        // hold startup hostage; only a post-LISTEN read can open admission.
        let cache = tokio::spawn(feature_cache(
            self.db,
            self.direct,
            self.flags,
            self.service.clone(),
            ctx.clone(),
        ));
        self.service
            .run_with_listener(ctx.clone(), self.listener)
            .await;
        ctx.cancel();
        let _ = cache.await;
    }
}

async fn refresh(db: &dyn FedDb, flags: &AtomicBool) {
    // Go's registered default is false; a failed authoritative reload closes admission.
    let enabled=db.query("SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.federation'),false)",&[])
        .await.ok().and_then(|rows| rows.first().and_then(|r|r.try_get::<_,bool>(0).ok())).unwrap_or(false);
    // Go's observer does not wake federation; its existing 20-second
    // reconciliation cadence handles eviction, while admission reads this cache.
    flags.store(enabled, Ordering::Relaxed);
}
async fn feature_cache(
    db: Arc<dyn FedDb>,
    direct: String,
    flags: Arc<AtomicBool>,
    service: Arc<Service>,
    ctx: CancellationToken,
) {
    let mut first_snapshot = true;
    let mut backoff = Duration::from_secs(1);
    loop {
        let connection = tokio::select! {biased; _=ctx.cancelled()=>return, result=DirectListener::connect(&direct,"config_changed")=>result};
        if let Ok(mut listener) = connection {
            backoff = Duration::from_secs(1);
            // LISTEN first, then read: no startup/reconnect invalidation window.
            tokio::select! {biased; _=ctx.cancelled()=>return, _=refresh(db.as_ref(),&flags)=>{}}
            if first_snapshot {
                // Previously startup waited for this read before its first
                // reconcile. Keep prompt initial dialing when it arrives late.
                service.wake();
                first_snapshot = false;
            }
            loop {
                let message = tokio::select! {biased; _=ctx.cancelled()=>return, message=listener.recv()=>message};
                if message.is_none() {
                    break;
                }
                // Every payload is a reload hint, never trusted toggle state.
                tokio::select! {biased; _=ctx.cancelled()=>return, _=tokio::time::sleep(Duration::from_millis(50))=>{}}
                tokio::select! {biased; _=ctx.cancelled()=>return, _=refresh(db.as_ref(),&flags)=>{}}
            }
        } else if let Err(error) = connection {
            Logger::stderr().warn(format!(
                "federation: subscribe config_changed failed error={error} retry_in={}s",
                backoff.as_secs()
            ));
        }
        // A lost notification connection does not invalidate Go's existing
        // snapshot. Only a failed authoritative reload does that (refresh).
        tokio::select! {biased; _=ctx.cancelled()=>return, _=tokio::time::sleep(backoff)=>{}}
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}
