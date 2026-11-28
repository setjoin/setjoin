//! Chat maintenance lifetimes. Shared-effect jobs transfer explicitly by name.
use setjoin_pg::workers::WorkerDatabase;
use std::{future::Future, time::Duration};

type Error = Box<dyn std::error::Error + Send + Sync>;

/// Frozen Go's complete one-statement transaction. Existing SQL triggers own
/// image reference decrements and deferred object cleanup; no Rust GC loop.
pub async fn reap(db: &WorkerDatabase) -> Result<(), Error> {
    db.connect()
        .await?
        .query(
            "DELETE FROM chat_link_previews WHERE fetched_at < now() - interval '14 days' RETURNING url_hash",
            &[],
        )
        .await
        .map_err(std::io::Error::other)?;
    Ok(())
}

/// Frozen Go's `chat-chain-anchor` cron callback (02:40): exactly its one
/// reducer statement, on the worker credential. Inert until
/// `feature.chat_compliance` is ON, as the reducer itself decides.
pub async fn chain_anchor(db: &WorkerDatabase) -> Result<(), Error> {
    db.run_cron_statement("SELECT chat_chain_anchor()").await
}

/// Frozen Go's `chat-purge-expired` cron callback (02:50): the draining
/// `chat_purge_run()` reducer, same guard and credential as the anchor.
pub async fn purge_expired(db: &WorkerDatabase) -> Result<(), Error> {
    db.run_cron_statement("SELECT chat_purge_run()").await
}

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
            tokio::select! {biased; _=&mut stop=>return,result=reap(&self.db)=>{
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
            Box::pin(async move { chain_anchor(&db).await })
        })),
        "chat-purge-expired" => Some(std::sync::Arc::new(move || {
            let db = db.clone();
            Box::pin(async move { purge_expired(&db).await })
        })),
        _ => None,
    }
}
