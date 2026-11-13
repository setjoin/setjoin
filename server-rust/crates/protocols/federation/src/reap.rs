//! Federation transport-residue worker, independent of static config and feature.federation.
use crate::db::FedDb;
use setjoin_pg::Type;
use std::{future::Future, sync::Arc, time::Duration};

pub const NAME: &str = "federation-residue-reap";
pub const INTERVAL: Duration = Duration::from_secs(3600);

pub struct Reaper {
    db: Arc<dyn FedDb>,
}
impl Reaper {
    pub fn new(db: Arc<dyn FedDb>) -> Self {
        Self { db }
    }
    /// One bounded reducer pass on the worker credential, exactly as frozen Go.
    pub async fn tick(&self) -> Result<(), String> {
        self.db
            .query(
                "SELECT federation_reap($1::interval)",
                &[(&"7 days", Type::TEXT)],
            )
            .await?;
        Ok(())
    }
    /// Immediate startup pass, then hourly; a failed pass is logged and retried next hour.
    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) {
        tokio::pin!(stop);
        tokio::select! { biased; _ = &mut stop => return, result = self.tick() => {
            if let Err(error) = result { eprintln!("federation: reap tick failed: {error}"); }
        }}
        let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + INTERVAL, INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! { biased; _ = &mut stop => return, _ = ticks.tick() => {} }
            tokio::select! { biased; _ = &mut stop => return, result = self.tick() => {
                if let Err(error) = result { eprintln!("federation: reap tick failed: {error}"); }
            }}
        }
    }
}
