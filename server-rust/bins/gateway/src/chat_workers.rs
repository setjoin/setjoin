//! Chat maintenance lifetimes. Shared-effect jobs transfer explicitly by name.
use setjoin_pg::workers::WorkerDatabase;
use std::{future::Future, time::Duration};

pub struct UnfurlReaper {
    db: WorkerDatabase,
}
impl UnfurlReaper {
    pub fn new(db: WorkerDatabase) -> Self {
        Self { db }
    }
    /// Frozen Go waits a full hour before its first sweep, then drops missed ticks.
    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) {
        let hour = Duration::from_secs(3600);
        let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + hour, hour);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(stop);
        loop {
            tokio::select! {biased; _=&mut stop=>return,_=ticks.tick()=>{}}
            tokio::select! {biased; _=&mut stop=>return,result=setjoin_chat::workers::reap(&self.db)=>{
                if result.is_err(){eprintln!("chat unfurl worker: TTL eviction failed");}
            }}
        }
    }
}

/// Rust copies of Go's two Chat cron callbacks, by their frozen task names.
/// They run only when registered through `CronScheduler::register_transferred`.
pub fn cron_action(name: &str, db: &WorkerDatabase) -> Option<crate::workers::Action> {
    let db = db.clone();
    match name {
        "chat-chain-anchor" => Some(std::sync::Arc::new(move || {
            let db = db.clone();
            Box::pin(async move { setjoin_chat::workers::chain_anchor(&db).await })
        })),
        "chat-purge-expired" => Some(std::sync::Arc::new(move || {
            let db = db.clone();
            Box::pin(async move { setjoin_chat::workers::purge_expired(&db).await })
        })),
        _ => None,
    }
}
