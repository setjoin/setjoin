//! Explicit global maintenance uses the worker credential, never an HTTP actor.
use setjoin_pg::workers::WorkerDatabase;
type Error = Box<dyn std::error::Error + Send + Sync>;

/// Frozen Go's complete one-statement transaction. Existing SQL triggers own
/// image reference decrements and deferred object cleanup; no Rust GC loop.
pub async fn reap(db: &WorkerDatabase) -> Result<(), Error> {
    db.connect().await?.query(
        "DELETE FROM chat_link_previews WHERE fetched_at < now() - interval '14 days' RETURNING url_hash",
        &[],
    ).await.map_err(std::io::Error::other)?;
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
