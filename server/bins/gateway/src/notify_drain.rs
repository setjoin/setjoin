//! `notify-intent-drain` (#408, Wave 2.1 #548): drains `notify_intents` into
//! `pg_notify` in deterministic `ORDER BY id` order with transaction-level
//! deduplication, adaptive immediate re-drain when a full batch is drained,
//! 50 ms idle poll cadence, and periodic 24 h stale-row pruning.
//!
//! The queue is cross-tenant (no RLS), so it runs on the worker credential.
//! `SKIP LOCKED` keeps a second replica from double-notifying.
use setjoin_pg::{
    workers::{WorkerConnection, WorkerDatabase},
    Type,
};
use std::{future::Future, time::Duration};

pub const NAME: &str = "notify-intent-drain";
/// Idle poll cadence (Wave 2.1 #548: tightened from 1s to 50ms for wakeup bells).
pub const INTERVAL: Duration = Duration::from_millis(50);
/// Stale retention prune cadence (24h retention ceiling against unbounded bloat).
const PRUNE_INTERVAL: Duration = Duration::from_secs(300);
/// Batch size per drain transaction.
pub const BATCH: i64 = 500;
/// Maximum stale rows pruned per maintenance sweep.
const PRUNE_BATCH: i64 = 1000;

/// DELETE and NOTIFY commit together, so delivery is at-most-once per row.
/// Grouping by `(channel, payload)` ordered by `MIN(id)` preserves first-seen
/// `ORDER BY id` order and deduplicates identical pairs in the batch while
/// returning the **total deleted row count** (`(SELECT count(*) FROM batch)`)
/// so a full 500-row batch with duplicates still loops immediately.
const DRAIN: &str = "
		WITH batch AS (
			DELETE FROM notify_intents
			 WHERE id IN (SELECT id FROM notify_intents
			               ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED)
			 RETURNING id, channel, payload
		),
		emitted AS (
			SELECT pg_notify(channel, payload)
			  FROM (
			    SELECT channel, payload
			      FROM batch
			     GROUP BY channel, payload
			     ORDER BY MIN(id)
			  ) deduped
		)
		SELECT (SELECT count(*) FROM batch)::bigint AS deleted_count,
		       (SELECT count(*) FROM emitted)::bigint AS emitted_count";

/// Prune stale undrained rows older than 24h in bounded batches so an offline
/// consumer or runaway producer cannot grow `notify_intents` without bound.
const PRUNE_STALE: &str = "
		DELETE FROM notify_intents
		 WHERE id IN (
		   SELECT id FROM notify_intents
		    WHERE created_at < now() - interval '24 hours'
		    ORDER BY id
		    LIMIT $1
		    FOR UPDATE SKIP LOCKED
		 )";

pub struct NotifyIntentDrain {
    db: WorkerDatabase,
    connection: tokio::sync::Mutex<Option<WorkerConnection>>,
}

impl NotifyIntentDrain {
    pub fn new(db: WorkerDatabase) -> Self {
        Self {
            db,
            connection: tokio::sync::Mutex::new(None),
        }
    }

    /// One batch: returns the total number of rows deleted from `notify_intents`.
    /// A failed statement drops the session so the next tick reconnects.
    pub async fn drain_once(&self) -> Result<u64, String> {
        let mut slot = self.connection.lock().await;
        let conn = match slot.as_ref() {
            Some(c) => c,
            None => {
                let c = self.db.connect().await.map_err(|e| e.to_string())?;
                slot.insert(c)
            }
        };
        let result = conn.query(DRAIN, &[(&BATCH, Type::INT8)]).await;
        match result {
            Ok(rows) => {
                let deleted = rows
                    .first()
                    .and_then(|r| r.try_get::<_, i64>(0).ok())
                    .unwrap_or(0)
                    .max(0) as u64;
                Ok(deleted)
            }
            Err(err) => {
                *slot = None;
                Err(err)
            }
        }
    }

    /// Prune one bounded batch of undrained `notify_intents` older than 24 hours.
    pub async fn prune_stale_once(&self) -> Result<u64, String> {
        let mut slot = self.connection.lock().await;
        let conn = match slot.as_ref() {
            Some(c) => c,
            None => {
                let c = self.db.connect().await.map_err(|e| e.to_string())?;
                slot.insert(c)
            }
        };
        let result = conn
            .execute(PRUNE_STALE, &[(&PRUNE_BATCH, Type::INT8)])
            .await;
        if result.is_err() {
            *slot = None;
        }
        result
    }

    /// One tick: full batches are drained immediately before waiting for the next tick.
    pub async fn tick(&self) {
        loop {
            match self.drain_once().await {
                Ok(n) if n >= BATCH as u64 => {}
                Ok(_) => return,
                Err(_) => {
                    // Go logs `notifyjobs: drain failed`; the error text can
                    // carry SQL, so only the fact is logged.
                    eprintln!("notifyjobs: drain failed");
                    return;
                }
            }
        }
    }

    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) {
        let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + INTERVAL, INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut prune_ticks =
            tokio::time::interval_at(tokio::time::Instant::now() + PRUNE_INTERVAL, PRUNE_INTERVAL);
        prune_ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(stop);
        loop {
            tokio::select! {
                biased;
                _ = &mut stop => return,
                _ = prune_ticks.tick() => {
                    let _ = self.prune_stale_once().await;
                }
                _ = ticks.tick() => {
                    tokio::select! {
                        biased;
                        _ = &mut stop => return,
                        _ = self.tick() => {}
                    }
                }
            }
        }
    }
}
