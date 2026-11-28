mod denylist;
pub mod registry;
pub mod tracker;
pub use denylist::AuthDenylist;
mod watchers;
pub use watchers::Watchers;
mod gate;
mod suppressed;
pub use gate::{
    bounded_name, cap_agent, fingerprint, ip_rule_blocked, mask_ip, refusal_budget,
    stored_fingerprint, MAX_STORED_AGENT, MAX_STORED_NAME, REFUSAL_INSERT,
};
pub use gate::{
    CaptchaStep, Config, ConnectionMeta, Decision, Gate, ThreatAction, ThreatGate, WorkerPools,
    RECORD_POOL_SIZE, WORKER_POOL_SIZE,
};
pub use suppressed::note_suppressed_refusal;
// Shared authentication runtime tasks and protocol threat admission (#420).
use setjoin_pg::{workers::WorkerDatabase, Type};
pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct RuntimeTasks {
    db: WorkerDatabase,
}
impl RuntimeTasks {
    pub fn new(request_dsn: &str, worker_dsn: Option<&str>) -> Result<Self, Error> {
        Ok(Self {
            db: WorkerDatabase::from_dsns(request_dsn, worker_dsn)?,
        })
    }
    /// Go's fixed-source HTTP refresh: gzip/system roots, then one atomic swap.
    pub async fn feed_tick(&self, endpoint: &str) -> Result<(), Error> {
        let response = reqwest::Client::builder()
            .user_agent("Go-http-client/1.1")
            .timeout(std::time::Duration::from_secs(30))
            .build()?
            .get(endpoint)
            .header("accept-encoding", "gzip")
            .send()
            .await?;
        let bytes = response.bytes().await?;
        let text = String::from_utf8_lossy(&bytes);
        let mut cidrs = Vec::new();
        for line in text.lines() {
            if line.len() >= 65536 {
                return Err("feed scanner token too long".into());
            }
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') {
                continue;
            }
            let cidr = line
                .split_once(';')
                .map_or_else(|| line.split_once(' ').map_or(line, |v| v.0), |v| v.0)
                .trim();
            if !cidr.is_empty() && cidr.contains('/') {
                cidrs.push(cidr.to_owned());
            }
        }
        if cidrs.is_empty() {
            return Ok(());
        }
        self.db
            .connect()
            .await?
            .query(
                "SELECT rust_threat_feed_replace($1)",
                &[(&cidrs, Type::TEXT_ARRAY)],
            )
            .await?;
        Ok(())
    }
    /// Independent Go autocommit statements; a broken first connection must
    /// not prevent the OIDC pool call from trying a fresh connection.
    pub async fn cleanup_tick(&self) -> Result<(), Error> {
        let rotated = async { self.db.connect().await?.execute("DELETE FROM oauth_tokens WHERE rotated_at IS NOT NULL AND rotated_at < now() - make_interval(secs => $1)", &[(&60_i64, Type::INT8)]).await.map_err(Error::from) }.await;
        let oidc = async { self.db.connect().await?.execute("DELETE FROM oidc_tokens WHERE expires_at < now() - interval '5 minutes' AND (refresh_expires_at IS NULL OR refresh_expires_at < now()) AND (revoked_at IS NULL OR revoked_at < now() - interval '5 minutes')", &[]).await.map_err(Error::from) }.await;
        rotated?;
        oidc?;
        Ok(())
    }
}

/// Shared auth runtime tasks are opt-in via `RUST_WORKERS_ON=auth-runtime`.
pub fn admit_runtime(rust_on: &str, _go_off: &str) -> Result<bool, String> {
    Ok(rust_on.split(',').any(|v| v.trim() == "auth-runtime"))
}
impl RuntimeTasks {
    pub async fn run(&self) {
        self.run_until(std::future::pending()).await
    }

    /// Cooperative graceful-shutdown entrypoint supervised by `setjoind` /
    /// `WorkerSupervisor` (#549).
    pub async fn run_until(&self, stop: impl std::future::Future<Output = ()>) {
        let stop = std::pin::pin!(stop);
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let mut feed_rx = stop_rx.clone();
        let mut gc_rx = stop_rx;
        let feed = async {
            let mut ticks = tokio::time::interval(std::time::Duration::from_secs(1800));
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = feed_rx.changed() => return,
                    _ = ticks.tick() => {}
                }
                tokio::select! {
                    biased;
                    _ = feed_rx.changed() => return,
                    res = self.feed_tick("https://www.spamhaus.org/drop/drop.txt") => {
                        if let Err(error) = res {
                            eprintln!("auth threat feed refresh: {error}");
                        }
                    }
                }
            }
        };
        let gc = async {
            let period = std::time::Duration::from_secs(60);
            let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = gc_rx.changed() => return,
                    _ = ticks.tick() => {}
                }
                tokio::select! {
                    biased;
                    _ = gc_rx.changed() => return,
                    res = self.cleanup_tick() => {
                        if let Err(error) = res {
                            eprintln!("auth token cleanup: {error}");
                        }
                    }
                }
            }
        };
        let stopper = async {
            stop.await;
            let _ = stop_tx.send(true);
        };
        // Independent Go goroutines: a slow feed must not delay retention.
        tokio::join!(stopper, feed, gc);
    }
}
/// Owned process tasks are aborted on every shutdown/error path.
pub struct RuntimeHandle(pub tokio::task::JoinHandle<()>);
impl Drop for RuntimeHandle {
    fn drop(&mut self) {
        self.0.abort()
    }
}
