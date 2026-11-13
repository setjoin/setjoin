//! The `blob-cleanup` worker (#411), mirroring frozen Go's
//! `blob.Handler.StartCleanup` tick: drain `blob_cleanup_queue` and
//! `orphaned_message_blobs` with object-store deletes, then retry the removals
//! that failed after their row was already gone.
//!
//! Runs on the worker credential (cross-tenant by design). It has shared effects
//! (row deletes, S3 deletes), so Go's copy must be off first. The grace window
//! `BLOB_RECLAIM_GRACE_MINUTES` is Go's PUT-time arming (it sets the queue row's
//! `delay_minutes`); the tick itself only honours `scheduled_at + delay_minutes`.
//! Go's second in-memory ledger (WORM retention retries armed by a blob PUT) is
//! `blob_retention`'s ledger: Rust's PUT arms it and the last step of the tick drains it.
use crate::recovery_worker::{ObjectStore, S3Store};
use setjoin_pg::{
    workers::{WorkerConnection, WorkerDatabase},
    Type,
};
use std::{collections::HashSet, future::Future, sync::Arc, time::Duration};

pub const NAME: &str = "blob-cleanup";
/// Go's ticker (first tick after one interval).
pub const INTERVAL: Duration = Duration::from_secs(300);
/// Go's `maxRetryLedger`.
const MAX_RETRY_LEDGER: usize = 1024;

/// Go's `blob.IsInlineMessage`: inline RFC 5322 text, never an object key.
pub fn is_inline_message(raw_ref: &str) -> bool {
    raw_ref.contains(['\r', '\n'])
}

pub struct BlobCleanup<S = S3Store> {
    db: WorkerDatabase,
    store: Arc<S>,
    /// Go's `reapRetries`: shas whose row delete committed but whose storage
    /// removal failed. Process-local and bounded, as in Go.
    reap_retries: std::sync::Mutex<HashSet<String>>,
}

impl<S: ObjectStore> BlobCleanup<S> {
    pub fn new(db: WorkerDatabase, store: Arc<S>) -> Self {
        Self {
            db,
            store,
            reap_retries: std::sync::Mutex::new(HashSet::new()),
        }
    }

    /// Whether the worker credential bypasses row-level security (a role with
    /// `BYPASSRLS`, or a superuser). The tick's safety rests on that: its global
    /// re-checks (`ref_count = 0`, `NOT EXISTS (... messages WHERE raw_ref = $1)`) must see
    /// every tenant's rows. Under a credential that RLS filters they would read "no
    /// reference" for a live object and delete it (owner-approved follow-up #531, F3).
    pub async fn worker_bypasses_rls(&self) -> Result<bool, String> {
        if setjoin_contracts::mutants::on("blob-cleanup-no-bypass-check") {
            return Ok(true);
        }
        let conn = self.db.connect().await.map_err(|e| e.to_string())?;
        let rows = conn
            .query(
                "SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = current_user",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(rows.first().is_some_and(|r| r.get::<_, bool>(0)))
    }

    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) {
        let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + INTERVAL, INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(stop);
        // Checked at startup, before the first tick; a transient failure retries each tick.
        let mut verified = false;
        loop {
            if !verified {
                match self.worker_bypasses_rls().await {
                    Ok(true) => verified = true,
                    Ok(false) => {
                        eprintln!(
                            "blob cleanup: REFUSING to run: the worker credential (DB_WORKER_DSN, \
                             or DB_DSN when unset) does not have BYPASSRLS, so its global \
                             reference re-checks would be filtered by row security"
                        );
                        return;
                    }
                    Err(e) => eprintln!("blob cleanup: worker privilege check failed, retrying: {e}"),
                }
            }
            tokio::select! {biased; _ = &mut stop => return, _ = ticks.tick() => {}}
            if !verified {
                continue;
            }
            tokio::select! {biased; _ = &mut stop => return, _ = self.tick() => {}}
        }
    }

    /// Go's order: cleanup queue, orphaned message blobs, reap retries, retention retries.
    pub async fn tick(&self) {
        let conn = match self.db.connect().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("blob cleanup: worker connection failed: {e}");
                return;
            }
        };
        self.process_cleanup_queue(&conn).await;
        self.process_orphaned_blobs(&conn).await;
        self.retry_failed_reaps(&conn).await;
        crate::blob_retention::retry_failed(&*self.store).await;
    }

    fn note_reap_retry(&self, sha: &str) {
        let mut ledger = self.reap_retries.lock().unwrap();
        if ledger.len() >= MAX_RETRY_LEDGER {
            // Go evicts an arbitrary entry (map iteration order).
            if let Some(evict) = ledger.iter().next().cloned() {
                ledger.remove(&evict);
            }
        }
        ledger.insert(sha.to_owned());
    }

    /// Due, apparently unreferenced blobs: a snapshot only, so the delete
    /// re-checks `ref_count = 0` atomically before touching any bytes.
    async fn process_cleanup_queue(&self, conn: &WorkerConnection) {
        let rows = match conn
            .query(
                "SELECT q.blob_sha256 FROM blob_cleanup_queue q
		 JOIN blobs b ON b.sha256 = q.blob_sha256
		 WHERE q.scheduled_at + make_interval(mins => q.delay_minutes) < now()
		   AND b.ref_count = 0",
                &[],
            )
            .await
        {
            Ok(rows) => rows,
            Err(_) => return, // Go returns no candidates on a query error, silently
        };
        let candidates: Vec<String> = rows.iter().map(|r| r.get(0)).collect();
        for sha in candidates {
            self.reap_candidate(conn, &sha).await;
        }
    }

    /// `DELETE ... WHERE ref_count = 0` gates the row delete and the object
    /// removal on the same instant's read (the queue row cascades away with it;
    /// a lost race leaves it for the zero-ref trigger to re-arm).
    async fn reap_candidate(&self, conn: &WorkerConnection, sha: &str) {
        let deleted = match conn
            .execute(
                "DELETE FROM blobs WHERE sha256 = $1 AND ref_count = 0",
                &[(&sha, Type::TEXT)],
            )
            .await
        {
            Ok(n) => n,
            Err(e) => {
                eprintln!("blob cleanup: row delete failed sha256={sha}: {e}");
                return;
            }
        };
        if deleted == 0 {
            return; // attached since the scan: still referenced
        }
        if let Err(e) = self.store.remove(sha).await {
            eprintln!("blob cleanup: minio remove failed sha256={sha}: {e}");
            self.note_reap_retry(sha);
        }
    }

    /// The sibling queue for message raw bodies. `raw_ref` is an exact object
    /// key (never assumed to be a sha); inline message text is only dequeued.
    async fn process_orphaned_blobs(&self, conn: &WorkerConnection) {
        let rows = match conn
            .query("SELECT raw_ref FROM orphaned_message_blobs", &[])
            .await
        {
            Ok(rows) => rows,
            Err(_) => return,
        };
        let refs: Vec<String> = rows.iter().map(|r| r.get(0)).collect();
        for raw_ref in refs {
            if !is_inline_message(&raw_ref) {
                let still_orphaned = match conn
                    .query(
                        "SELECT NOT EXISTS (SELECT 1 FROM messages WHERE raw_ref = $1)",
                        &[(&raw_ref, Type::TEXT)],
                    )
                    .await
                {
                    Ok(rows) => rows.first().is_some_and(|r| r.get::<_, bool>(0)),
                    Err(_) => continue, // stays queued; retried next tick
                };
                if still_orphaned {
                    if let Err(e) = self.store.remove(&raw_ref).await {
                        eprintln!("orphaned blob cleanup: remove failed raw_ref={raw_ref}: {e}");
                        continue;
                    }
                }
                // else: a new message re-created this key, nothing to delete.
            }
            if let Err(e) = conn
                .execute(
                    "DELETE FROM orphaned_message_blobs WHERE raw_ref = $1",
                    &[(&raw_ref, Type::TEXT)],
                )
                .await
            {
                eprintln!("orphaned blob cleanup: dequeue failed raw_ref={raw_ref}: {e}");
            }
        }
    }

    /// Re-run storage removal for blobs whose row delete already committed.
    async fn retry_failed_reaps(&self, conn: &WorkerConnection) {
        let pending: Vec<String> = self.reap_retries.lock().unwrap().iter().cloned().collect();
        for sha in pending {
            let gone = match conn
                .query(
                    "SELECT NOT EXISTS (SELECT 1 FROM blobs WHERE sha256 = $1)",
                    &[(&sha, Type::TEXT)],
                )
                .await
            {
                Ok(rows) => rows.first().is_some_and(|r| r.get::<_, bool>(0)),
                Err(e) => {
                    eprintln!("blob cleanup retry: existence re-check failed sha256={sha}: {e}");
                    continue;
                }
            };
            if !gone {
                // Re-uploaded: the object is live again; ref_count owns it now.
                self.reap_retries.lock().unwrap().remove(&sha);
                continue;
            }
            if let Err(e) = self.store.remove(&sha).await {
                eprintln!("blob cleanup retry: minio remove still failing sha256={sha}: {e}");
                continue;
            }
            self.reap_retries.lock().unwrap().remove(&sha);
        }
    }
}
