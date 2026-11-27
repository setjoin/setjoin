//! Unified `WorkerSupervisor` (Wave 2.2, #549).
//!
//! Owns the fail-closed boot `BYPASSRLS` check (before `READY=1`), verified
//! `WorkerPool` + optional `owner_pool` context, distributed `SKIP LOCKED`
//! periodic schedule runner, durable S3 WORM arming & reap-retry consumers,
//! legacy ad-hoc job drain-then-retire consumers, and a single absolute
//! 30-second shutdown deadline with safe-effect lease release.

pub mod legacy;
pub mod schedule;
pub mod worm;

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use setjoin_pg::{ListenHub, WorkerPool};
use setjoin_workqueue::{ScheduleStore, WorkQueue};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Default unified graceful shutdown budget for `WorkerSupervisor`.
pub const DEFAULT_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);

/// Boot configuration for [`WorkerSupervisor::boot`].
#[derive(Clone)]
pub struct SupervisorConfig {
    pub worker_dsn: String,
    pub owner_dsn: Option<String>,
    pub encryption_key: String,
    pub audit_hmac_key: String,
    pub node_id: String,
    pub listen_hub: Option<ListenHub>,
    pub drain_timeout: Duration,
    pub pool_size: usize,
}

impl SupervisorConfig {
    pub fn new(worker_dsn: impl Into<String>) -> Self {
        let host = std::env::var("HOSTNAME")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "node".to_owned());
        let mut rand_bytes = [0u8; 4];
        let _ = getrandom::getrandom(&mut rand_bytes);
        let suffix: String = rand_bytes.iter().map(|b| format!("{b:02x}")).collect();
        Self {
            worker_dsn: worker_dsn.into(),
            owner_dsn: None,
            encryption_key: String::new(),
            audit_hmac_key: String::new(),
            node_id: format!("{host}-{}-{suffix}", std::process::id()),
            listen_hub: None,
            drain_timeout: DEFAULT_SHUTDOWN_DEADLINE,
            pool_size: 16,
        }
    }

    pub fn with_owner_dsn(mut self, dsn: Option<String>) -> Self {
        self.owner_dsn = dsn.filter(|s| !s.is_empty());
        self
    }

    pub fn with_audit_keys(mut self, encryption_key: String, audit_hmac_key: String) -> Self {
        self.encryption_key = encryption_key;
        self.audit_hmac_key = audit_hmac_key;
        self
    }

    pub fn with_node_id(mut self, node_id: impl Into<String>) -> Self {
        self.node_id = node_id.into();
        self
    }

    pub fn with_listen_hub(mut self, hub: Option<ListenHub>) -> Self {
        self.listen_hub = hub;
        self
    }

    pub fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }
}

/// Shared registry of active leases whose local execution has known-safe
/// idempotent retry semantics and may be released cleanly if aborted on SIGTERM.
///
/// Ambiguous external-I/O effects (e.g. mid-flight S3 PUTs or remote HTTP
/// webhooks) must NOT register here so their leases expire and reconcile.
#[derive(Clone, Default)]
pub struct SafeLeaseRegistry {
    work_leases: Arc<Mutex<Vec<(i64, i32)>>>,
    schedule_leases: Arc<Mutex<Vec<(String, i64)>>>,
}

impl SafeLeaseRegistry {
    pub fn track_work(&self, id: i64, claim_generation: i32) -> SafeWorkLeaseGuard {
        let mut guard = self
            .work_leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.push((id, claim_generation));
        SafeWorkLeaseGuard {
            registry: self.work_leases.clone(),
            entry: Some((id, claim_generation)),
        }
    }

    pub fn track_schedule(&self, task_name: String, fencing_token: i64) -> SafeScheduleLeaseGuard {
        let mut guard = self
            .schedule_leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.push((task_name.clone(), fencing_token));
        SafeScheduleLeaseGuard {
            registry: self.schedule_leases.clone(),
            entry: Some((task_name, fencing_token)),
        }
    }

    fn take_work_leases(&self) -> Vec<(i64, i32)> {
        let mut guard = self
            .work_leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *guard)
    }

    fn take_schedule_leases(&self) -> Vec<(String, i64)> {
        let mut guard = self
            .schedule_leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *guard)
    }
}

/// RAII handle for a tracked safe-to-release `WorkQueue` lease.
///
/// Call [`Self::disarm`] after normal settlement so shutdown does not attempt to
/// release an already-completed item; if the owning task is cancelled or aborted
/// mid-flight, the entry remains registered for [`WorkerSupervisor::shutdown`].
pub struct SafeWorkLeaseGuard {
    registry: Arc<Mutex<Vec<(i64, i32)>>>,
    entry: Option<(i64, i32)>,
}

impl SafeWorkLeaseGuard {
    pub fn disarm(mut self) {
        if let Some(target) = self.entry.take() {
            let mut guard = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(pos) = guard.iter().position(|e| *e == target) {
                guard.swap_remove(pos);
            }
        }
    }
}

/// RAII handle for a tracked safe-to-release `worker_schedules` lease.
pub struct SafeScheduleLeaseGuard {
    registry: Arc<Mutex<Vec<(String, i64)>>>,
    entry: Option<(String, i64)>,
}

impl SafeScheduleLeaseGuard {
    pub fn disarm(mut self) {
        if let Some(target) = self.entry.take() {
            let mut guard = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(pos) = guard.iter().position(|e| *e == target) {
                guard.swap_remove(pos);
            }
        }
    }
}

/// Verified context handed to every supervised background worker.
#[derive(Clone)]
pub struct TaskCtx {
    /// Cancelled at `T0` (`SIGTERM`/`SIGINT`) to stop all new claims immediately.
    pub cancel: CancellationToken,
    /// Cancelled at `T0 + 25s` (proportional for shorter budgets) to abort stragglers.
    pub abort_inflight: CancellationToken,
    /// Boot-verified `BYPASSRLS` worker pool.
    pub pool: WorkerPool,
    /// Optional schema-owner pool (`DB_OWNER_DSN`) for partition DDL only.
    pub owner_pool: Option<WorkerPool>,
    /// Shared process `ListenHub` (`DB_DIRECT_DSN`).
    pub listen_hub: Option<ListenHub>,
    /// Durable `WorkQueue` handle over `pool`.
    pub work_queue: WorkQueue,
    /// Distributed `worker_schedules` handle over `pool`.
    pub schedule_store: ScheduleStore,
    /// Stable per-process worker owner identity.
    pub node_id: String,
    /// Safe-to-release lease registry for bounded shutdown handoff.
    pub safe_leases: SafeLeaseRegistry,
}

/// Unified supervisor owning boot privilege checks, task spawning, and the
/// single absolute 30-second shutdown deadline.
pub struct WorkerSupervisor {
    ctx: TaskCtx,
    verified_role: String,
    tasks: JoinSet<(&'static str, Result<(), String>)>,
    drain_timeout: Duration,
}

impl WorkerSupervisor {
    /// Verify `BYPASSRLS` / superuser privilege on `config.worker_dsn` BEFORE
    /// spawning any worker task or signalling `READY=1`.
    pub async fn boot(config: SupervisorConfig) -> Result<Self, String> {
        let mut pool = WorkerPool::from_dsn(&config.worker_dsn, config.pool_size.max(2))
            .map_err(|e| format!("worker supervisor pool init failed: {}", e.0))?;
        if !config.encryption_key.is_empty() || !config.audit_hmac_key.is_empty() {
            pool =
                pool.with_audit_keys(config.encryption_key.clone(), config.audit_hmac_key.clone());
        }

        let verified_role = if setjoin_contracts::mutants::on("blob-cleanup-no-bypass-check") {
            "mutant-unchecked".to_owned()
        } else {
            pool.verify_bypassrls().await.map_err(|err| {
                format!(
                    "worker supervisor refusing startup: {} (remediation: mailctl schema provision-roles --write-dsns)",
                    err.message
                )
            })?
        };

        let owner_pool = match &config.owner_dsn {
            Some(dsn) => {
                let mut op = WorkerPool::from_dsn(dsn, 4)
                    .map_err(|e| format!("worker supervisor owner pool init failed: {}", e.0))?;
                if !config.encryption_key.is_empty() || !config.audit_hmac_key.is_empty() {
                    op = op.with_audit_keys(config.encryption_key, config.audit_hmac_key);
                }
                Some(op)
            }
            None => None,
        };

        let work_queue = WorkQueue::new(pool.clone());
        let schedule_store = ScheduleStore::new(pool.clone());
        let ctx = TaskCtx {
            cancel: CancellationToken::new(),
            abort_inflight: CancellationToken::new(),
            pool,
            owner_pool,
            listen_hub: config.listen_hub,
            work_queue,
            schedule_store,
            node_id: config.node_id,
            safe_leases: SafeLeaseRegistry::default(),
        };

        Ok(Self {
            ctx,
            verified_role,
            tasks: JoinSet::new(),
            drain_timeout: config.drain_timeout,
        })
    }

    pub fn ctx(&self) -> &TaskCtx {
        &self.ctx
    }

    pub fn verified_role(&self) -> &str {
        &self.verified_role
    }

    /// Spawn a supervised background task that receives a clone of [`TaskCtx`].
    pub fn spawn<F, Fut>(&mut self, name: &'static str, make: F)
    where
        F: FnOnce(TaskCtx) -> Fut,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let fut = make(self.ctx.clone());
        self.tasks.spawn(async move { (name, fut.await) });
    }

    /// Execute the single-deadline graceful shutdown sequence:
    /// - `T0`: cancel `ctx.cancel` (stop new claims immediately).
    /// - `T0 → T0+25s` (proportional for shorter deadlines): cooperative settle.
    /// - `T0+25s → T0+28s`: cancel `ctx.abort_inflight`, abort + reap remaining
    ///   tasks, and release tracked safe-effect leases via
    ///   `worker_schedule_release` / `work_release`.
    /// - Strictly bounded by `T0 + drain_timeout` (30s default ceiling).
    pub async fn shutdown(mut self) -> Result<(), String> {
        let t0 = Instant::now();
        let hard_deadline = t0 + self.drain_timeout;
        let coop_budget = if self.drain_timeout >= Duration::from_secs(30) {
            Duration::from_secs(25)
        } else {
            self.drain_timeout
                .mul_f64(25.0 / 30.0)
                .max(Duration::from_millis(50))
        };

        // T0: Stop claiming new work/schedules immediately.
        self.ctx.cancel.cancel();

        let mut first_error: Option<String> = None;

        // T0 -> T0 + coop_budget: cooperative join.
        let coop_res = tokio::time::timeout(coop_budget, async {
            while let Some(joined) = self.tasks.join_next().await {
                match joined {
                    Ok((_, Ok(()))) => {}
                    Ok((name, Err(err))) => {
                        if first_error.is_none() {
                            first_error = Some(format!("{name}: {err}"));
                        }
                    }
                    Err(err) if !err.is_cancelled() => {
                        if first_error.is_none() {
                            first_error = Some(format!("supervised task join error: {err}"));
                        }
                    }
                    Err(_) => {}
                }
            }
        })
        .await;

        // T0 + coop_budget: cancel abort_inflight first (giving in-flight tasks a
        // bounded grace slice to exit cleanly BEFORE abort_all). Only release
        // tracked safe-effect leases when tasks exited gracefully without needing
        // `abort_all()`; forced-aborted stragglers leave leases to expire safely.
        let graceful_reaped = if coop_res.is_err() {
            self.ctx.abort_inflight.cancel();
            let reap_budget = hard_deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(2));
            let grace = (reap_budget / 2).min(Duration::from_secs(1));
            let grace_done = tokio::time::timeout(grace, async {
                while self.tasks.join_next().await.is_some() {}
            })
            .await
            .is_ok();
            if !grace_done {
                self.tasks.abort_all();
                let rem_reap = hard_deadline
                    .saturating_duration_since(Instant::now())
                    .min(reap_budget.saturating_sub(grace))
                    .max(Duration::from_millis(50));
                let _ = tokio::time::timeout(rem_reap, async {
                    while self.tasks.join_next().await.is_some() {}
                })
                .await;
                false
            } else {
                true
            }
        } else {
            true
        };

        // T0 + 25s..28s: bounded release of tracked safe-effect leases ONLY when
        // local execution stopped cleanly (`graceful_reaped == true`).
        if graceful_reaped {
            let schedule_leases = self.ctx.safe_leases.take_schedule_leases();
            let work_leases = self.ctx.safe_leases.take_work_leases();
            if !schedule_leases.is_empty() || !work_leases.is_empty() {
                let release_budget = hard_deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(3));
                if !release_budget.is_zero() {
                    let store = self.ctx.schedule_store.clone();
                    let queue = self.ctx.work_queue.clone();
                    let node_id = self.ctx.node_id.clone();
                    let _ = tokio::time::timeout(release_budget, async move {
                        for (task_name, token) in schedule_leases {
                            let _ = store.release(&task_name, token, &node_id).await;
                        }
                        for (id, gen) in work_leases {
                            let _ = queue.release(id, gen, &node_id).await;
                        }
                    })
                    .await;
                }
            }
        }

        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}
