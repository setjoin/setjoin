//! The `blob-cleanup` (alias `blob-gc`) supervised worker (#411, upgraded to
//! Mark-and-Sweep GC under `WorkerSupervisor` in Wave 2.4 #551).
//!
//! Legacy `blob_cleanup_queue` / `blobs.ref_count` polling and `reap_candidate`
//! are retired in V293. All canonical blob reclamation, lock-safe prefixed
//! `orphaned_message_blobs` cleanup, and abandoned `tmp/blob-upload/*` staging
//! sweeps execute through [`crate::blob_gc::BlobGcWorker`], scheduled via
//! `WorkerSupervisor`'s distributed `worker_schedules` runner (`safe_to_release = false`).
//!
//! Boot-time `BYPASSRLS` privilege verification is owned fail-closed by
//! `WorkerSupervisor::boot` before `READY=1`.

use crate::blob_gc::{BlobGcWorker, DEFAULT_TICK_BUDGET};
use crate::recovery_worker::{ObjectStore, S3Store};
use setjoin_pg::{workers::WorkerDatabase, WorkerPool};
use std::{future::Future, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

/// Canonical external worker name (preserved for `RUST_WORKERS_ON` & `worker_launch_inventory.golden`).
pub const NAME: &str = "blob-cleanup";
/// Accepted Wave 2.4 alias in `RUST_WORKERS_ON`.
pub const ALIAS: &str = "blob-gc";
/// Default periodic interval (5 minutes; `worker_schedules` `@every 300s`).
pub const INTERVAL: Duration = Duration::from_secs(300);
/// Schedule timeout ceiling (seconds) registered in `worker_schedules` (<= 600s).
pub const SCHEDULE_TIMEOUT_SECS: i32 = 300;

/// Go's `blob.IsInlineMessage`: inline RFC 5322 text, never an object key.
pub fn is_inline_message(raw_ref: &str) -> bool {
    raw_ref.contains(['\r', '\n'])
}

/// Executes one supervised Mark-and-Sweep GC + orphan + staging tick using the
/// supervisor's boot-verified `WorkerPool`.
pub async fn run_supervised_tick<S: ObjectStore>(
    pool: &WorkerPool,
    store: Arc<S>,
    cancel: CancellationToken,
) -> Result<(), String> {
    let db = pool.worker_database()?;
    let gc = BlobGcWorker::new(db, store)
        .with_tick_budget(DEFAULT_TICK_BUDGET)
        .with_cancel(cancel);
    gc.tick().await.map(|_| ())
}

/// Standalone/test driver wrapping [`BlobGcWorker`] for unit and integration tests.
pub struct BlobCleanup<S = S3Store> {
    db: WorkerDatabase,
    store: Arc<S>,
}

impl<S: ObjectStore> BlobCleanup<S> {
    pub fn new(db: WorkerDatabase, store: Arc<S>) -> Self {
        Self { db, store }
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

    /// Executes one Mark-and-Sweep GC + lock-safe orphan + abandoned staging tick.
    /// Honors `BLOB_GC_MODE=off` as an operator emergency kill-switch (never falls
    /// back to retired legacy `ref_count` / `blob_cleanup_queue` logic).
    pub async fn tick(&self) {
        let gc = BlobGcWorker::new(self.db.clone(), self.store.clone());
        if let Err(e) = gc.tick().await {
            eprintln!("blob-cleanup: mark-and-sweep tick failed: {e}");
        }
    }
}
