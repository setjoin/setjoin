//! Wave 2.2 (#549) live-DB integration tests:
//! - 4 concurrent supervisors × 30 tasks (zero double-runs, load distributed)
//! - Crash failover (expired lease reclaim) & graceful SIGTERM handoff (≤2s)
//! - Mixed-version rolling-upgrade advisory-lock probe (`cron-task:<name>`)
//! - Fail-closed `WorkerSupervisor::boot` `BYPASSRLS` check before `READY=1`
//! - `WorkerPool::begin_read_write_bounded` >2s query & timeout enforcement
//! - Single-deadline shutdown aborting hung task + safe `work_release` (`attempts` decremented)
//! - Durable WORM arming: restart survival, 404 (absent vs live blobs row), 403 sufficient
//!   retention, `WORM_MODE=invalid`, DLQ gauge + `health_check()` + DLQ replay
//! - Legacy drain-then-retire parity (`bulk_role_jobs`, `eap_apply_jobs`, `guest_notification_intents`)

mod common;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use setjoin_conformance::harness::Db;
use setjoin_gateway::admin_job_workers::{BulkRoleJobs, EapJobs};
use setjoin_gateway::blob_retention::{self, WormArmPayload, WORK_KIND_WORM_ARM};
use setjoin_gateway::recovery_worker::{ObjectRetentionInfo, ObjectStore, RetentionError};
use setjoin_gateway::supervisor::legacy::{
    enqueue_bulk_role_apply, enqueue_eap_apply, LegacyJobDrainConsumer,
};
use setjoin_gateway::supervisor::schedule::{
    ScheduleHandler, ScheduleRunner, ScheduleRunnerConfig, ScheduledTask,
};
use setjoin_gateway::supervisor::worm::WormArmConsumer;
use setjoin_gateway::supervisor::{SupervisorConfig, WorkerSupervisor};
use setjoin_pg::workers::WorkerDatabase;
use setjoin_pg::WorkerPool;
use setjoin_workqueue::{ClaimSpec, ScheduleCredential, ScheduleSpec, WorkQueue, WorkRequest};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct EnvGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);
impl EnvGuard {
    fn set(pairs: &[(&'static str, Option<&str>)]) -> Self {
        let mut prev = Vec::with_capacity(pairs.len());
        for (k, v) in pairs {
            prev.push((*k, std::env::var_os(k)));
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        Self(prev)
    }
}
impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, v) in self.0.drain(..) {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}

#[derive(Default)]
struct MockWormStore {
    retain_results: Mutex<Vec<Result<(), RetentionError>>>,
    get_retention_result: Mutex<Option<Result<Option<ObjectRetentionInfo>, RetentionError>>>,
    retain_calls: AtomicUsize,
    removed: Mutex<Vec<String>>,
}

impl MockWormStore {
    fn with_results(results: Vec<Result<(), RetentionError>>) -> Self {
        Self {
            retain_results: Mutex::new(results),
            get_retention_result: Mutex::new(None),
            retain_calls: AtomicUsize::new(0),
            removed: Mutex::new(Vec::new()),
        }
    }

    fn with_get_retention(self, res: Result<Option<ObjectRetentionInfo>, RetentionError>) -> Self {
        *self.get_retention_result.lock().unwrap() = Some(res);
        self
    }

    fn calls(&self) -> usize {
        self.retain_calls.load(Ordering::SeqCst)
    }
}

impl ObjectStore for MockWormStore {
    fn remove<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        let key = key.to_owned();
        Box::pin(async move {
            self.removed.lock().unwrap().push(key);
            Ok(())
        })
    }

    fn retain_object<'a>(
        &'a self,
        _key: &'a str,
        _mode: &'a str,
        _until: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), RetentionError>> + Send + 'a>> {
        Box::pin(async move {
            self.retain_calls.fetch_add(1, Ordering::SeqCst);
            let mut q = self.retain_results.lock().unwrap();
            if q.is_empty() {
                Ok(())
            } else {
                q.remove(0)
            }
        })
    }

    fn object_retention<'a>(
        &'a self,
        _key: &'a str,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<ObjectRetentionInfo>, RetentionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.get_retention_result
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(Ok(None))
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_supervisors_30_tasks_zero_double_runs_and_distributed() -> Result<(), common::BoxError>
{
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ws-4x30") else {
        return Ok(());
    };
    let admin = db.connect().await?;
    admin
        .batch_execute("DELETE FROM public.worker_schedules WHERE task_name LIKE 'test549-dist-%'")
        .await?;

    let executions: Arc<Mutex<HashMap<String, Vec<String>>>> = Arc::new(Mutex::new(HashMap::new()));
    let total_runs = Arc::new(AtomicUsize::new(0));

    let make_tasks = || -> Vec<ScheduledTask> {
        (0..30)
            .map(|i| {
                let name = format!("test549-dist-{i:02}");
                let executions = executions.clone();
                let total_runs = total_runs.clone();
                ScheduledTask {
                    spec: ScheduleSpec {
                        task_name: name,
                        schedule_spec: "@every 300s".into(),
                        timeout_secs: 30,
                        schedule_tz: "UTC".into(),
                        credential: ScheduleCredential::Worker,
                    },
                    handler: ScheduleHandler::Callback {
                        handler: Arc::new(move |ctx, row, _cancel| {
                            let executions = executions.clone();
                            let total_runs = total_runs.clone();
                            Box::pin(async move {
                                tokio::time::sleep(Duration::from_millis(25)).await;
                                executions
                                    .lock()
                                    .unwrap()
                                    .entry(row.task_name)
                                    .or_default()
                                    .push(ctx.node_id);
                                total_runs.fetch_add(1, Ordering::SeqCst);
                                Ok(())
                            })
                        }),
                        safe_to_release: true,
                    },
                }
            })
            .collect()
    };

    let mut supervisors = Vec::new();
    for idx in 0..4 {
        let mut sup = WorkerSupervisor::boot(
            SupervisorConfig::new(&db.dsn)
                .with_node_id(format!("sup-dist-{idx}"))
                .with_drain_timeout(Duration::from_secs(5)),
        )
        .await?;
        let runner = ScheduleRunner::new(
            make_tasks(),
            ScheduleRunnerConfig {
                lease_secs: 15,
                claim_limit: 2,
                poll_interval: Duration::from_millis(40),
                schedule_tz: "UTC".into(),
                max_concurrent: 2,
            },
        );
        sup.spawn("schedule-runner", move |ctx| runner.run(ctx));
        supervisors.push(sup);
    }

    let start = Instant::now();
    while total_runs.load(Ordering::SeqCst) < 30 && start.elapsed() < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Give a brief quiet period to prove zero duplicate executions occur.
    tokio::time::sleep(Duration::from_millis(250)).await;
    for sup in supervisors {
        sup.shutdown().await?;
    }

    let map = executions.lock().unwrap().clone();
    assert_eq!(map.len(), 30, "all 30 tasks must execute");
    let mut distinct_nodes = HashSet::new();
    for (task, owners) in &map {
        assert_eq!(
            owners.len(),
            1,
            "task {task} must run exactly once, saw {owners:?}"
        );
        distinct_nodes.insert(owners[0].clone());
    }
    assert!(
        distinct_nodes.len() >= 2,
        "load must distribute across multiple supervisors, got {distinct_nodes:?}"
    );

    admin
        .batch_execute("DELETE FROM public.worker_schedules WHERE task_name LIKE 'test549-dist-%'")
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_failover_and_graceful_sigterm_handoff() -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ws-failover") else {
        return Ok(());
    };
    let admin = db.connect().await?;
    admin
        .batch_execute(
            "DELETE FROM public.worker_schedules WHERE task_name IN ('test549-crash', 'test549-handoff')",
        )
        .await?;

    let sup_a = WorkerSupervisor::boot(
        SupervisorConfig::new(&db.dsn)
            .with_node_id("node-crash-a")
            .with_drain_timeout(Duration::from_secs(5)),
    )
    .await?;
    let sup_b = WorkerSupervisor::boot(
        SupervisorConfig::new(&db.dsn)
            .with_node_id("node-crash-b")
            .with_drain_timeout(Duration::from_secs(5)),
    )
    .await?;

    // 1. Crash failover: node-crash-a claims with 1s lease and never heartbeats;
    //    node-crash-b reclaims once lease expires with fencing_token = 2.
    let crash_spec = ScheduleSpec {
        task_name: "test549-crash".into(),
        schedule_spec: "@every 60s".into(),
        timeout_secs: 30,
        schedule_tz: "UTC".into(),
        credential: ScheduleCredential::Worker,
    };
    sup_a.ctx().schedule_store.register(&crash_spec).await?;
    let claimed_a = sup_a
        .ctx()
        .schedule_store
        .claim(&["test549-crash".into()], "node-crash-a", 1, 1)
        .await?;
    assert_eq!(claimed_a.len(), 1);
    assert_eq!(claimed_a[0].fencing_token, 1);

    // Wait for 1s lease expiry (≤2s, representing ≤31s for 30s production lease).
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let claimed_b = sup_b
        .ctx()
        .schedule_store
        .claim(&["test549-crash".into()], "node-crash-b", 30, 1)
        .await?;
    assert_eq!(claimed_b.len(), 1, "peer must reclaim expired lease");
    assert_eq!(claimed_b[0].fencing_token, 2);
    assert_eq!(claimed_b[0].lease_owner.as_deref(), Some("node-crash-b"));

    // 2. Graceful SIGTERM handoff: supervisor holding safe lease shuts down and
    //    peer picks it up in <= 2s.
    let mut sup_term = WorkerSupervisor::boot(
        SupervisorConfig::new(&db.dsn)
            .with_node_id("node-handoff-a")
            .with_drain_timeout(Duration::from_millis(400)),
    )
    .await?;
    let handoff_spec = ScheduleSpec {
        task_name: "test549-handoff".into(),
        schedule_spec: "@every 60s".into(),
        timeout_secs: 30,
        schedule_tz: "UTC".into(),
        credential: ScheduleCredential::Worker,
    };
    sup_term
        .ctx()
        .schedule_store
        .register(&handoff_spec)
        .await?;
    let handoff_claimed = sup_term
        .ctx()
        .schedule_store
        .claim(&["test549-handoff".into()], "node-handoff-a", 60, 1)
        .await?;
    assert_eq!(handoff_claimed.len(), 1);
    let token = handoff_claimed[0].fencing_token;
    sup_term.spawn("slow-safe-schedule", move |ctx| async move {
        let _guard = ctx
            .safe_leases
            .track_schedule("test549-handoff".into(), token);
        // Simulate a task still running past cooperative cancel that exits
        // cleanly when `abort_inflight` fires (leaving _guard armed for release).
        ctx.abort_inflight.cancelled().await;
        Ok(())
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let handoff_start = Instant::now();
    sup_term.shutdown().await?;
    let picked = sup_b
        .ctx()
        .schedule_store
        .claim(&["test549-handoff".into()], "node-crash-b", 30, 1)
        .await?;
    assert_eq!(
        picked.len(),
        1,
        "peer must pick up released schedule immediately"
    );
    assert!(
        handoff_start.elapsed() <= Duration::from_secs(2),
        "graceful handoff exceeded 2s: {:?}",
        handoff_start.elapsed()
    );

    sup_a.shutdown().await?;
    sup_b.shutdown().await?;
    admin
        .batch_execute(
            "DELETE FROM public.worker_schedules WHERE task_name IN ('test549-crash', 'test549-handoff')",
        )
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_version_legacy_advisory_lock_blocks_schedule_claim() -> Result<(), common::BoxError>
{
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ws-mixed-version") else {
        return Ok(());
    };
    let admin = db.connect().await?;
    admin
        .batch_execute("DELETE FROM public.worker_schedules WHERE task_name = 'test549-mixed'")
        .await?;

    let legacy_db = WorkerDatabase::new(&db.dsn)?;
    let legacy_lock = legacy_db
        .try_cron_task_lock("test549-mixed")
        .await?
        .expect("legacy advisory lock acquired");

    let sup = WorkerSupervisor::boot(SupervisorConfig::new(&db.dsn).with_node_id("node-mixed-new"))
        .await?;
    sup.ctx()
        .schedule_store
        .register(&ScheduleSpec {
            task_name: "test549-mixed".into(),
            schedule_spec: "@every 60s".into(),
            timeout_secs: 30,
            schedule_tz: "UTC".into(),
            credential: ScheduleCredential::Worker,
        })
        .await?;

    let blocked = sup
        .ctx()
        .schedule_store
        .claim(&["test549-mixed".into()], "node-mixed-new", 30, 1)
        .await?;
    assert!(
        blocked.is_empty(),
        "worker_schedule_claim must skip task held by legacy cron-task advisory lock"
    );

    legacy_lock.release().await?;

    let claimed = sup
        .ctx()
        .schedule_store
        .claim(&["test549-mixed".into()], "node-mixed-new", 30, 1)
        .await?;
    assert_eq!(
        claimed.len(),
        1,
        "worker_schedule_claim must claim task once legacy advisory lock is released"
    );

    sup.shutdown().await?;
    admin
        .batch_execute("DELETE FROM public.worker_schedules WHERE task_name = 'test549-mixed'")
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_boot_refuses_nobypassrls_and_bounded_tx_exceeds_2s(
) -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ws-bypass-bounded") else {
        return Ok(());
    };
    let app_dsn = db
        .app
        .clone()
        .ok_or("DB_APP_DSN (setjoin_app) is required for BYPASSRLS boot refusal test")?;

    // 1. WorkerSupervisor::boot refuses NOBYPASSRLS role with actionable remediation.
    let err = match WorkerSupervisor::boot(SupervisorConfig::new(&app_dsn)).await {
        Ok(_) => return Err("setjoin_app (NOBYPASSRLS) must be refused at boot".into()),
        Err(err) => err,
    };
    assert!(
        err.contains("BYPASSRLS") && err.contains("mailctl schema provision-roles --write-dsns"),
        "expected BYPASSRLS remediation message, got: {err}"
    );

    // 2. WorkerPool::begin_read_write_bounded allows >2s query (fixing executor's 2s default).
    let pool = WorkerPool::from_dsn(&db.dsn, 4).map_err(|e| e.0)?;
    let role = pool.verify_bypassrls().await.map_err(|e| e.message)?;
    assert!(!role.is_empty());

    let mut tx = pool
        .begin_read_write_bounded(Duration::from_secs(10))
        .await
        .map_err(|e| e.message)?;
    let started = Instant::now();
    tx.query("SELECT pg_sleep(2.3)", &[])
        .await
        .map_err(|e| e.message)?;
    tx.commit().await.map_err(|e| e.message)?;
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "bounded write tx must allow >2s queries cleanly"
    );

    // 3. Tight bounded timeout cancels long query with SQLSTATE 57014.
    let mut short_tx = pool
        .begin_read_write_bounded(Duration::from_millis(200))
        .await
        .map_err(|e| e.message)?;
    let timeout_err = short_tx
        .query("SELECT pg_sleep(2.0)", &[])
        .await
        .expect_err("200ms bounded tx must cancel 2s sleep");
    assert_eq!(
        timeout_err.sqlstate.as_deref(),
        Some("57014"),
        "expected query_canceled 57014, got {timeout_err:?}"
    );
    let _ = short_tx.rollback().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_aborts_hung_task_and_releases_safe_work_lease_within_deadline(
) -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ws-shutdown-release") else {
        return Ok(());
    };
    let admin = db.connect().await?;
    admin
        .batch_execute(
            "DELETE FROM public.work_items WHERE kind IN ('test549.safe_work', 'test549.ambiguous_work')",
        )
        .await?;

    let drain = Duration::from_millis(600);
    let mut sup = WorkerSupervisor::boot(
        SupervisorConfig::new(&db.dsn)
            .with_node_id("node-shut-1")
            .with_drain_timeout(drain),
    )
    .await?;
    let queue = sup.ctx().work_queue.clone();

    let safe_rec = queue
        .enqueue(
            &WorkRequest::new("test549.safe_work", serde_json::json!({"ok": true}))
                .with_max_attempts(3),
        )
        .await?;
    let ambig_rec = queue
        .enqueue(
            &WorkRequest::new("test549.ambiguous_work", serde_json::json!({"io": true}))
                .with_max_attempts(3),
        )
        .await?;

    let claimed = queue
        .claim(
            &ClaimSpec::new(
                "node-shut-1",
                vec!["test549.safe_work".into(), "test549.ambiguous_work".into()],
            )
            .with_batch(2)
            .with_lease_secs(60),
        )
        .await?;
    assert_eq!(claimed.len(), 2);
    let safe_item = claimed
        .iter()
        .find(|i| i.id == safe_rec.id)
        .expect("safe item claimed")
        .clone();
    assert_eq!(safe_item.attempts, 1);

    // Spawn a task running past cooperative cancel that exits cleanly on
    // `abort_inflight` and tracks ONLY the safe item (ambiguous external I/O
    // stays untracked and must remain leased to expire & reconcile).
    sup.spawn("slow-safe-task", move |ctx| async move {
        let _guard = ctx
            .safe_leases
            .track_work(safe_item.id, safe_item.claim_generation);
        ctx.abort_inflight.cancelled().await;
        Ok(())
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let t0 = Instant::now();
    sup.shutdown().await?;
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "shutdown must honor hard deadline, took {elapsed:?}"
    );

    // Safe item was released cleanly: status='pending' and attempts decremented back to 0.
    let safe_row = admin
        .query_one(
            "SELECT status, attempts, locked_by FROM public.work_items WHERE id = $1",
            &[&safe_rec.id],
        )
        .await?;
    assert_eq!(safe_row.get::<_, String>(0), "pending");
    assert_eq!(safe_row.get::<_, i32>(1), 0);
    assert_eq!(safe_row.get::<_, Option<String>>(2), None);

    // Ambiguous external-effect item stayed leased for expiry reconciliation.
    let ambig_row = admin
        .query_one(
            "SELECT status, attempts, locked_by FROM public.work_items WHERE id = $1",
            &[&ambig_rec.id],
        )
        .await?;
    assert_eq!(ambig_row.get::<_, String>(0), "leased");
    assert_eq!(ambig_row.get::<_, i32>(1), 1);
    assert_eq!(
        ambig_row.get::<_, Option<String>>(2).as_deref(),
        Some("node-shut-1")
    );

    // Also prove a truly wedged task ignoring BOTH `cancel` and `abort_inflight`
    // is force-aborted within the deadline and intentionally does NOT release
    // its tracked lease (leaving it leased to expire safely).
    let mut sup_wedged = WorkerSupervisor::boot(
        SupervisorConfig::new(db.dsn.clone())
            .with_node_id("node-shut-wedged")
            .with_drain_timeout(Duration::from_millis(800)),
    )
    .await?;
    let wedged_rec = sup_wedged
        .ctx()
        .work_queue
        .enqueue(
            &WorkRequest::new("test549.wedged_work", serde_json::json!({"stuck": true}))
                .with_max_attempts(3),
        )
        .await?;
    let wedged_claimed = sup_wedged
        .ctx()
        .work_queue
        .claim(
            &ClaimSpec::new("node-shut-wedged", vec!["test549.wedged_work".into()])
                .with_batch(1)
                .with_lease_secs(60),
        )
        .await?;
    assert_eq!(wedged_claimed.len(), 1);
    let wedged_item = wedged_claimed[0].clone();
    sup_wedged.spawn("wedged-ignores-abort-token", move |ctx| async move {
        let _guard = ctx
            .safe_leases
            .track_work(wedged_item.id, wedged_item.claim_generation);
        std::future::pending::<()>().await;
        Ok(())
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let tw = Instant::now();
    sup_wedged.shutdown().await?;
    assert!(
        tw.elapsed() < Duration::from_secs(2),
        "wedged task shutdown must honor hard deadline, took {:?}",
        tw.elapsed()
    );
    let wedged_status: String = admin
        .query_one(
            "SELECT status FROM public.work_items WHERE id = $1",
            &[&wedged_rec.id],
        )
        .await?
        .get(0);
    assert_eq!(
        wedged_status, "leased",
        "force-aborted wedged task must leave lease leased rather than releasing prematurely"
    );

    admin
        .batch_execute(
            "DELETE FROM public.work_items WHERE kind IN ('test549.safe_work', 'test549.ambiguous_work', 'test549.wedged_work')",
        )
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn durable_worm_arming_restart_404_403_invalid_and_dlq_replay() -> Result<(), common::BoxError>
{
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ws-worm") else {
        return Ok(());
    };
    let admin = db.connect().await?;
    admin
        .batch_execute(
            "DELETE FROM public.work_items WHERE kind = 'blob.worm_arm'; \
             DELETE FROM public.work_dead_letters WHERE kind = 'blob.worm_arm'; \
             DELETE FROM public.blobs WHERE sha256 LIKE '549worm%'",
        )
        .await?;

    let pool = WorkerPool::from_dsn(&db.dsn, 4).map_err(|e| e.0)?;
    let queue = WorkQueue::new(pool);

    let make_payload = |sha: &str, days: i64| -> WormArmPayload {
        let until = blob_retention::retain_until(Utc::now(), days);
        WormArmPayload {
            sha256: sha.to_owned(),
            object_key: sha.to_owned(),
            mode: "governance".to_owned(),
            retain_days: days,
            retain_until: until,
            version_id: None,
        }
    };

    // (a) 500 -> simulated restart (brand-new consumer instance) -> 200 applies once & completes.
    {
        let _env = EnvGuard::set(&[
            ("WORM_MODE", Some("governance")),
            ("WORM_RETENTION_DAYS", Some("30")),
        ]);
        let payload = make_payload("549worm_restart", 30);
        let req = WorkRequest::new(WORK_KIND_WORM_ARM, serde_json::to_value(&payload)?)
            .with_idempotency_key(blob_retention::worm_idempotency_key(
                &payload.sha256,
                &payload.retain_until,
            ))
            .with_max_attempts(5);
        let rec = queue.enqueue(&req).await?;

        let store_before = Arc::new(MockWormStore::with_results(vec![Err(
            RetentionError::Transient(500, "boom".into()),
        )]));
        let consumer_before = WormArmConsumer::new(store_before.clone());
        assert_eq!(
            consumer_before
                .drain_once(&queue, "worm-node-1", Some(Duration::ZERO))
                .await?,
            1
        );
        assert_eq!(store_before.calls(), 1);
        drop(consumer_before);

        // Fresh consumer simulates process restart: zero in-memory state needed.
        let store_after = Arc::new(MockWormStore::with_results(vec![Ok(())]));
        let consumer_after = WormArmConsumer::new(store_after.clone());
        assert_eq!(
            consumer_after
                .drain_once(&queue, "worm-node-2", Some(Duration::ZERO))
                .await?,
            1
        );
        assert_eq!(store_after.calls(), 1);
        let remaining: i64 = admin
            .query_one(
                "SELECT count(*) FROM public.work_items WHERE id = $1",
                &[&rec.id],
            )
            .await?
            .get(0);
        assert_eq!(remaining, 0, "work item completed after restart recovery");
    }

    // (b) 404 + absent blobs row -> completes as no-op (crash before promote).
    {
        let _env = EnvGuard::set(&[
            ("WORM_MODE", Some("governance")),
            ("WORM_RETENTION_DAYS", Some("30")),
        ]);
        let payload = make_payload("549worm_404_absent", 30);
        let rec = queue
            .enqueue(
                &WorkRequest::new(WORK_KIND_WORM_ARM, serde_json::to_value(&payload)?)
                    .with_max_attempts(5),
            )
            .await?;
        let store = Arc::new(MockWormStore::with_results(vec![Err(
            RetentionError::NotFound,
        )]));
        let consumer = WormArmConsumer::new(store);
        assert_eq!(
            consumer
                .drain_once(&queue, "worm-node-404a", Some(Duration::ZERO))
                .await?,
            1
        );
        let remaining: i64 = admin
            .query_one(
                "SELECT count(*) FROM public.work_items WHERE id = $1",
                &[&rec.id],
            )
            .await?
            .get(0);
        assert_eq!(
            remaining, 0,
            "404 with missing blobs row must complete as no-op"
        );
    }

    // (c) 404 + LIVE blobs row -> fails transiently as integrity incident (never silently dropped).
    {
        let _env = EnvGuard::set(&[
            ("WORM_MODE", Some("governance")),
            ("WORM_RETENTION_DAYS", Some("30")),
        ]);
        admin
            .execute(
                "INSERT INTO public.blobs (sha256, minio_ref, size_bytes) \
                 VALUES ('549worm_404_live', 'mailblobs/549worm_404_live', 12)",
                &[],
            )
            .await?;
        let payload = make_payload("549worm_404_live", 30);
        let rec = queue
            .enqueue(
                &WorkRequest::new(WORK_KIND_WORM_ARM, serde_json::to_value(&payload)?)
                    .with_max_attempts(3),
            )
            .await?;
        let store = Arc::new(MockWormStore::with_results(vec![Err(
            RetentionError::NotFound,
        )]));
        let consumer = WormArmConsumer::new(store);
        assert_eq!(
            consumer
                .drain_once(&queue, "worm-node-404b", Some(Duration::ZERO))
                .await?,
            1
        );
        let err_text: Option<String> = admin
            .query_one(
                "SELECT last_error FROM public.work_items WHERE id = $1",
                &[&rec.id],
            )
            .await?
            .get(0);
        assert!(
            err_text
                .as_deref()
                .is_some_and(|e| e.contains("integrity incident")),
            "expected integrity incident retry error, got {err_text:?}"
        );
        admin
            .execute("DELETE FROM public.work_items WHERE id = $1", &[&rec.id])
            .await?;
        admin
            .execute(
                "DELETE FROM public.blobs WHERE sha256 = '549worm_404_live'",
                &[],
            )
            .await?;
    }

    // (d) 403 + GetObjectRetention shows upload-time T0 retention (30s earlier than
    //     advancing now+30d) -> completes cleanly instead of looping to DLQ!
    {
        let _env = EnvGuard::set(&[
            ("WORM_MODE", Some("governance")),
            ("WORM_RETENTION_DAYS", Some("30")),
        ]);
        let upload_time_until =
            blob_retention::retain_until(Utc::now() - ChronoDuration::seconds(30), 30);
        let payload = WormArmPayload {
            sha256: "549worm_403_ok".to_owned(),
            object_key: "549worm_403_ok".to_owned(),
            mode: "governance".to_owned(),
            retain_days: 30,
            retain_until: upload_time_until.clone(),
            version_id: None,
        };
        let rec = queue
            .enqueue(
                &WorkRequest::new(WORK_KIND_WORM_ARM, serde_json::to_value(&payload)?)
                    .with_max_attempts(5),
            )
            .await?;
        let store = Arc::new(
            MockWormStore::with_results(vec![Err(RetentionError::Forbidden("403".into()))])
                .with_get_retention(Ok(Some(ObjectRetentionInfo {
                    mode: "governance".into(),
                    retain_until: upload_time_until,
                }))),
        );
        let consumer = WormArmConsumer::new(store);
        assert_eq!(
            consumer
                .drain_once(&queue, "worm-node-403ok", Some(Duration::ZERO))
                .await?,
            1
        );
        let remaining: i64 = admin
            .query_one(
                "SELECT count(*) FROM public.work_items WHERE id = $1",
                &[&rec.id],
            )
            .await?
            .get(0);
        assert_eq!(
            remaining, 0,
            "403 with sufficient upload-time retention must complete cleanly"
        );
    }

    // (e) WORM_MODE=invalid -> fail_transient (never drop queued work).
    {
        let _env = EnvGuard::set(&[
            ("WORM_MODE", Some("bogus-invalid")),
            ("WORM_RETENTION_DAYS", Some("30")),
        ]);
        let payload = make_payload("549worm_invalid", 30);
        let rec = queue
            .enqueue(
                &WorkRequest::new(WORK_KIND_WORM_ARM, serde_json::to_value(&payload)?)
                    .with_max_attempts(5),
            )
            .await?;
        let store = Arc::new(MockWormStore::with_results(vec![Ok(())]));
        let consumer = WormArmConsumer::new(store.clone());
        assert_eq!(
            consumer
                .drain_once(&queue, "worm-node-inv", Some(Duration::ZERO))
                .await?,
            1
        );
        assert_eq!(store.calls(), 0, "must not call S3 when WORM_MODE=invalid");
        let status: String = admin
            .query_one(
                "SELECT status FROM public.work_items WHERE id = $1",
                &[&rec.id],
            )
            .await?
            .get(0);
        assert_eq!(status, "pending", "invalid config must keep item pending");
        admin
            .execute("DELETE FROM public.work_items WHERE id = $1", &[&rec.id])
            .await?;
    }

    // (f) Exhausted retries -> DLQ + gauge + health_check('worm_arm_dead_letters') + DLQ replay.
    {
        let _env = EnvGuard::set(&[
            ("WORM_MODE", Some("governance")),
            ("WORM_RETENTION_DAYS", Some("30")),
        ]);
        let payload = make_payload("549worm_dlq", 30);
        queue
            .enqueue(
                &WorkRequest::new(WORK_KIND_WORM_ARM, serde_json::to_value(&payload)?)
                    .with_max_attempts(2),
            )
            .await?;
        let failing_store = Arc::new(MockWormStore::with_results(vec![
            Err(RetentionError::Forbidden("iam lag".into())),
            Err(RetentionError::Forbidden("iam lag".into())),
        ]));
        let consumer = WormArmConsumer::new(failing_store);
        consumer
            .drain_once(&queue, "worm-node-dlq", Some(Duration::ZERO))
            .await?;
        consumer
            .drain_once(&queue, "worm-node-dlq", Some(Duration::ZERO))
            .await?;

        let dlq_id: i64 = admin
            .query_one(
                "SELECT id FROM public.work_dead_letters \
                 WHERE kind = 'blob.worm_arm' AND replayed_at IS NULL ORDER BY id DESC LIMIT 1",
                &[],
            )
            .await?
            .get(0);
        assert!(
            setjoin_gateway::metrics::WORM_ARM_DEAD_LETTERS.load(Ordering::Relaxed) >= 1,
            "setjoin_worm_arm_dead_letters gauge must reflect DLQ depth"
        );

        admin.execute("SELECT health_check()", &[]).await?;
        let hc_status: String = admin
            .query_one(
                "SELECT status FROM public.health_history \
                 WHERE check_name = 'worm_arm_dead_letters' ORDER BY id DESC LIMIT 1",
                &[],
            )
            .await?
            .get(0);
        assert_eq!(hc_status, "error");

        // Replay from DLQ and complete cleanly with recovered S3.
        admin
            .query_one(
                "SELECT dlq_id, work_item_id FROM public.work_queue_dlq_replay($1, false, false)",
                &[&dlq_id],
            )
            .await?;
        let recovered_store = Arc::new(MockWormStore::with_results(vec![Ok(())]));
        let recovered_consumer = WormArmConsumer::new(recovered_store.clone());
        assert_eq!(
            recovered_consumer
                .drain_once(&queue, "worm-node-replay", Some(Duration::ZERO))
                .await?,
            1
        );
        assert_eq!(recovered_store.calls(), 1);
        assert_eq!(
            setjoin_gateway::metrics::WORM_ARM_DEAD_LETTERS.load(Ordering::Relaxed),
            0
        );
    }

    admin
        .batch_execute(
            "DELETE FROM public.work_items WHERE kind = 'blob.worm_arm'; \
             DELETE FROM public.work_dead_letters WHERE kind = 'blob.worm_arm'",
        )
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_admin_jobs_and_guest_digest_drain_then_retire_parity(
) -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ws-legacy-drain") else {
        return Ok(());
    };
    let admin = db.connect().await?;
    let pool = WorkerPool::from_dsn(&db.dsn, 4).map_err(|e| e.0)?;
    let queue = WorkQueue::new(pool);

    // 1. Prove a peer-owned 'running' bulk_role_jobs row is NEVER clobbered by startup/drain,
    //    while both WorkQueue-triggered and legacy pre-upgrade 'queued' rows drain cleanly.
    let domain_id: i64 = admin
        .query_one(
            "INSERT INTO public.domains (name, is_local) VALUES ('test549-legacy.example', true) \
             ON CONFLICT (name) DO UPDATE SET is_local = true RETURNING id",
            &[],
        )
        .await?
        .get(0);
    let actor_id: i64 = admin
        .query_one(
            "INSERT INTO public.users (username, domain_id, email, display_name, is_local_admin, enabled) \
             VALUES ('test549-admin', $1, 'test549-admin@test549-legacy.example', 'Admin', true, true) \
             ON CONFLICT (username, domain_id) DO UPDATE SET is_local_admin = true RETURNING id",
            &[&domain_id],
        )
        .await?
        .get(0);
    let role_id: i64 = admin
        .query_one(
            "SELECT id FROM public.admin_role_groups ORDER BY id LIMIT 1",
            &[],
        )
        .await?
        .get(0);

    let running_bulk: i64 = admin
        .query_one(
            "INSERT INTO public.bulk_role_jobs (op, role_id, actor_id, user_ids, total, status) \
             VALUES ('assign', $1, $2, ARRAY[$2]::bigint[], 1, 'running') RETURNING id",
            &[&role_id, &actor_id],
        )
        .await?
        .get(0);
    let wq_bulk: i64 = admin
        .query_one(
            "INSERT INTO public.bulk_role_jobs (op, role_id, actor_id, user_ids, total, status) \
             VALUES ('assign', $1, $2, ARRAY[$2]::bigint[], 1, 'queued') RETURNING id",
            &[&role_id, &actor_id],
        )
        .await?
        .get(0);
    let legacy_bulk: i64 = admin
        .query_one(
            "INSERT INTO public.bulk_role_jobs (op, role_id, actor_id, user_ids, total, status) \
             VALUES ('assign', $1, $2, ARRAY[$2]::bigint[], 1, 'queued') RETURNING id",
            &[&role_id, &actor_id],
        )
        .await?
        .get(0);
    enqueue_bulk_role_apply(&queue, wq_bulk).await?;

    let running_eap: i64 = admin
        .query_one(
            "INSERT INTO public.eap_apply_jobs (policy_id, status) VALUES (NULL, 'running') RETURNING id",
            &[],
        )
        .await?
        .get(0);
    let wq_eap: i64 = admin
        .query_one(
            "INSERT INTO public.eap_apply_jobs (policy_id, status) VALUES (NULL, 'queued') RETURNING id",
            &[],
        )
        .await?
        .get(0);
    let legacy_eap: i64 = admin
        .query_one(
            "INSERT INTO public.eap_apply_jobs (policy_id, status) VALUES (NULL, 'queued') RETURNING id",
            &[],
        )
        .await?
        .get(0);
    enqueue_eap_apply(&queue, wq_eap).await?;

    let wdb = WorkerDatabase::new(&db.dsn)?;
    let consumer = LegacyJobDrainConsumer::new(
        Some(Arc::new(BulkRoleJobs { db: wdb.clone() })),
        Some(Arc::new(EapJobs::new(wdb))),
        None,
    );
    let handled = consumer.drain_once(&queue, "legacy-drain-node").await?;
    assert_eq!(handled, 2, "both WorkQueue-triggered admin jobs claimed");

    // Verify peer 'running' rows were NOT clobbered, while queued rows settled.
    let running_bulk_st: String = admin
        .query_one(
            "SELECT status FROM public.bulk_role_jobs WHERE id = $1",
            &[&running_bulk],
        )
        .await?
        .get(0);
    assert_eq!(
        running_bulk_st, "running",
        "peer running bulk_role_jobs row must not be clobbered"
    );
    let running_eap_st: String = admin
        .query_one(
            "SELECT status FROM public.eap_apply_jobs WHERE id = $1",
            &[&running_eap],
        )
        .await?
        .get(0);
    assert_eq!(
        running_eap_st, "running",
        "peer running eap_apply_jobs row must not be clobbered"
    );

    for id in [wq_bulk, legacy_bulk] {
        let st: String = admin
            .query_one(
                "SELECT status FROM public.bulk_role_jobs WHERE id = $1",
                &[&id],
            )
            .await?
            .get(0);
        assert!(
            matches!(st.as_str(), "done" | "error"),
            "bulk_role_jobs {id} must settle, got {st}"
        );
    }
    for id in [wq_eap, legacy_eap] {
        let st: String = admin
            .query_one(
                "SELECT status FROM public.eap_apply_jobs WHERE id = $1",
                &[&id],
            )
            .await?
            .get(0);
        assert!(
            matches!(st.as_str(), "done" | "error"),
            "eap_apply_jobs {id} must settle, got {st}"
        );
    }

    // 2. Prove guest_notification_intent_enqueue coalesces guest.digest_notify onto WorkQueue.
    let prev_guest_toggle: bool = admin
        .query_one(
            "SELECT enabled FROM public.feature_toggles WHERE key = 'feature.guest_accounts'",
            &[],
        )
        .await?
        .get(0);
    admin
        .execute(
            "UPDATE public.feature_toggles SET enabled = true WHERE key = 'feature.guest_accounts'",
            &[],
        )
        .await?;
    let guest_id: i64 = admin
        .query_one(
            "INSERT INTO public.users (username, domain_id, email, display_name, enabled) \
             VALUES ('test549-guest', $1, 'test549-guest@test549-legacy.example', 'Guest', true) \
             ON CONFLICT (username, domain_id) DO UPDATE SET enabled = true RETURNING id",
            &[&domain_id],
        )
        .await?
        .get(0);
    admin
        .execute(
            "INSERT INTO public.guest_accounts (user_id, invited_email, invited_by_email, host_domain_id, status) \
             VALUES ($1, 'test549-guest@test549-legacy.example', 'test549-admin@test549-legacy.example', $2, 'active') \
             ON CONFLICT (user_id) DO UPDATE SET status = 'active'",
            &[&guest_id, &domain_id],
        )
        .await?;
    admin
        .execute(
            "DELETE FROM public.work_items WHERE kind = 'guest.digest_notify' AND idempotency_key = $1",
            &[&format!("guest.digest:{guest_id}")],
        )
        .await?;
    admin
        .execute(
            "SELECT public.guest_notification_intent_enqueue($1, 'mention', '1:100')",
            &[&guest_id],
        )
        .await?;
    admin
        .execute(
            "SELECT public.guest_notification_intent_enqueue($1, 'dm', '2:200')",
            &[&guest_id],
        )
        .await?;
    let wq_guest_count: i64 = admin
        .query_one(
            "SELECT count(*) FROM public.work_items \
             WHERE kind = 'guest.digest_notify' AND idempotency_key = $1",
            &[&format!("guest.digest:{guest_id}")],
        )
        .await?
        .get(0);
    assert_eq!(
        wq_guest_count, 1,
        "multiple guest intents must coalesce into one guest.digest_notify WorkQueue item"
    );

    // Cleanup fixture rows.
    admin
        .execute(
            "UPDATE public.feature_toggles SET enabled = $1 WHERE key = 'feature.guest_accounts'",
            &[&prev_guest_toggle],
        )
        .await?;
    admin
        .execute(
            "DELETE FROM public.work_items WHERE kind IN ('admin.bulk_role_apply', 'admin.eap_apply', 'guest.digest_notify')",
            &[],
        )
        .await?;
    admin
        .execute(
            "DELETE FROM public.guest_notification_intents WHERE user_id = $1",
            &[&guest_id],
        )
        .await?;
    admin
        .execute(
            "DELETE FROM public.guest_accounts WHERE user_id = $1",
            &[&guest_id],
        )
        .await?;
    admin
        .execute(
            "DELETE FROM public.bulk_role_jobs WHERE id = ANY($1)",
            &[&vec![running_bulk, wq_bulk, legacy_bulk]],
        )
        .await?;
    admin
        .execute(
            "DELETE FROM public.eap_apply_jobs WHERE id = ANY($1)",
            &[&vec![running_eap, wq_eap, legacy_eap]],
        )
        .await?;
    admin
        .execute(
            "DELETE FROM public.users WHERE id = ANY($1)",
            &[&vec![actor_id, guest_id]],
        )
        .await?;
    admin
        .execute("DELETE FROM public.domains WHERE id = $1", &[&domain_id])
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_running_worker_sql_heartbeats_freely_and_excludes_legacy_advisory_lock(
) -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ws-long-sql-hb") else {
        return Ok(());
    };
    let admin = db.connect().await?;
    let task_name = "test549_long_sql_hb";
    admin
        .execute(
            "DELETE FROM public.worker_schedules WHERE task_name = $1",
            &[&task_name],
        )
        .await?;

    let mut sup = WorkerSupervisor::boot(
        SupervisorConfig::new(db.dsn.clone())
            .with_node_id("long-sql-node")
            .with_drain_timeout(Duration::from_secs(10)),
    )
    .await?;

    let runner = ScheduleRunner::new(
        vec![ScheduledTask {
            spec: ScheduleSpec {
                task_name: task_name.to_owned(),
                schedule_spec: "@every 3600s".to_owned(),
                timeout_secs: 15,
                schedule_tz: "UTC".to_owned(),
                credential: ScheduleCredential::Worker,
            },
            handler: ScheduleHandler::Sql {
                sql: "SELECT pg_sleep(2.4)",
                credential: ScheduleCredential::Worker,
            },
        }],
        ScheduleRunnerConfig {
            poll_interval: Duration::from_millis(50),
            lease_secs: 2,
            ..ScheduleRunnerConfig::default()
        },
    );
    runner.register_all(&sup.ctx().schedule_store).await?;
    sup.spawn("schedule-runner", move |ctx| runner.run(ctx));

    // Wait until the worker SQL task is actively leased.
    let mut initial_expiry: Option<String> = None;
    for _ in 0..80 {
        let row = admin
            .query_one(
                "SELECT lease_owner, to_char(lease_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
                 FROM public.worker_schedules WHERE task_name = $1",
                &[&task_name],
            )
            .await?;
        let owner: Option<String> = row.get(0);
        let exp: Option<String> = row.get(1);
        if owner.as_deref() == Some("long-sql-node") {
            initial_expiry = exp;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let initial_expiry = initial_expiry.expect("long SQL task should be leased");

    // Probe new-first mixed-version advisory lock exclusion from a separate legacy session
    // AND observe live heartbeat renewal while pg_sleep(2.4) executes.
    let legacy_conn = db.connect().await?;
    let mut saw_legacy_blocked = false;
    let mut saw_heartbeat_renewed = false;
    for _ in 0..40 {
        let adv_acquired: bool = legacy_conn
            .query_one(
                "SELECT pg_try_advisory_lock(hashtextextended('cron-task:' || $1, 0))",
                &[&task_name],
            )
            .await?
            .get(0);
        if !adv_acquired {
            saw_legacy_blocked = true;
        } else {
            legacy_conn
                .execute(
                    "SELECT pg_advisory_unlock(hashtextextended('cron-task:' || $1, 0))",
                    &[&task_name],
                )
                .await?;
        }

        let row = admin
            .query_one(
                "SELECT lease_owner, last_outcome, \
                        to_char(lease_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
                 FROM public.worker_schedules WHERE task_name = $1",
                &[&task_name],
            )
            .await?;
        let owner: Option<String> = row.get(0);
        let outcome: Option<String> = row.get(1);
        let exp: Option<String> = row.get(2);
        if let Some(exp_str) = exp {
            if exp_str > initial_expiry {
                saw_heartbeat_renewed = true;
            }
        }
        if owner.is_none() && outcome.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    sup.shutdown().await?;

    let final_row = admin
        .query_one(
            "SELECT lease_owner, last_outcome, last_error FROM public.worker_schedules WHERE task_name = $1",
            &[&task_name],
        )
        .await?;
    let owner: Option<String> = final_row.get(0);
    let outcome: Option<String> = final_row.get(1);
    let last_error: Option<String> = final_row.get(2);

    assert!(
        saw_heartbeat_renewed,
        "heartbeat must renew lease_expires_at during long worker SQL without FOR UPDATE self-blocking"
    );
    assert!(
        saw_legacy_blocked,
        "legacy pg_try_advisory_lock must be blocked while supervised worker SQL executes"
    );
    assert!(owner.is_none(), "lease must be released on completion");
    assert_eq!(
        outcome.as_deref(),
        Some("ok"),
        "long-running worker SQL must succeed with live heartbeats (err={last_error:?})"
    );

    // After commit, legacy advisory lock is free again.
    let adv_free: bool = legacy_conn
        .query_one(
            "SELECT pg_try_advisory_lock(hashtextextended('cron-task:' || $1, 0))",
            &[&task_name],
        )
        .await?
        .get(0);
    assert!(adv_free, "advisory xact lock must be free after commit");
    legacy_conn
        .execute(
            "SELECT pg_advisory_unlock(hashtextextended('cron-task:' || $1, 0))",
            &[&task_name],
        )
        .await?;

    admin
        .execute(
            "DELETE FROM public.worker_schedules WHERE task_name = $1",
            &[&task_name],
        )
        .await?;
    Ok(())
}
