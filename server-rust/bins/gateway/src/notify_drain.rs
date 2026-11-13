//! `notify-intent-drain` (#408): drains `notify_intents` into `pg_notify`,
//! mirroring frozen Go's `notifyjobs.Worker` statement for statement.
//!
//! Go runs it unconditionally: with `feature.notify_decouple` OFF every tick is
//! one no-op `DELETE`, and with it ON this is the only NOTIFY emitter, so the
//! webhook, SSE and WebSocket fan-outs depend on it. The queue is cross-tenant
//! (no RLS), so it runs on the worker credential. `SKIP LOCKED` keeps a second
//! replica from double-notifying.
use setjoin_pg::{
    workers::{WorkerConnection, WorkerDatabase},
    Type,
};
use std::{future::Future, time::Duration};

pub const NAME: &str = "notify-intent-drain";
/// Go's `drainInterval`.
pub const INTERVAL: Duration = Duration::from_secs(1);
/// Go's `batchSize`.
pub const BATCH: i64 = 500;

/// DELETE and NOTIFY commit together, so delivery is at-most-once per row;
/// `ORDER BY id` keeps intent order. Identical `(channel, payload)` pairs in
/// one batch collapse into one notification (PostgreSQL transaction dedupe),
/// as in Go.
const DRAIN: &str = "
		WITH batch AS (
			DELETE FROM notify_intents
			 WHERE id IN (SELECT id FROM notify_intents
			               ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED)
			 RETURNING channel, payload
		)
		SELECT pg_notify(channel, payload) FROM batch";

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

    /// One batch: the rows drained. A failed statement drops the session so the
    /// next tick reconnects (Go's pool does the same for a broken connection).
    pub async fn drain_once(&self) -> Result<u64, String> {
        let mut slot = self.connection.lock().await;
        if slot.is_none() {
            *slot = Some(self.db.connect().await.map_err(|e| e.to_string())?);
        }
        let result = slot
            .as_ref()
            .expect("connected above")
            .execute(DRAIN, &[(&BATCH, Type::INT8)])
            .await;
        if result.is_err() {
            *slot = None;
        }
        result
    }

    /// One tick: full batches are drained before waiting for the next tick.
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
        tokio::pin!(stop);
        loop {
            tokio::select! {biased; _ = &mut stop => return, _ = ticks.tick() => {}}
            tokio::select! {biased; _ = &mut stop => return, _ = self.tick() => {}}
        }
    }
}
