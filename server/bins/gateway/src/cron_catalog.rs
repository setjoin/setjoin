//! The Rust cron catalog: frozen Go's `AllTasks()` (`mailserver/internal/cron/tasks.go`)
//! plus Rust-only maintenance tasks (`prune-rust-operation-receipts`, #473).
//!
//! Frozen Go tasks run one fixed statement through
//! `WorkerDatabase::run_cron_statement`, exactly as Go's executor runs it. The
//! statements are copied verbatim, including the three `system_config` COALESCE
//! calls and the inline `prune-bulk-role-jobs` DELETE; the reducers stay the
//! business authority. Schedules and timeouts live in `workers::task_spec`.
//! A task runs in Rust only when it is registered through
//! `CronScheduler::register_transferred` (per-task advisory lock).
use crate::workers::{Action, CronScheduler, WorkerError};
use setjoin_pg::workers::WorkerDatabase;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Rust-only retention sweep for `public.rust_operation_receipts` (#473).
pub const PRUNE_RECEIPTS_TASK: &str = "prune-rust-operation-receipts";
const PRUNE_RECEIPTS_BATCH_SIZE: i32 = 5_000;
const PRUNE_RECEIPTS_MAX_BATCHES: usize = 20;
const PRUNE_RECEIPTS_BUDGET: Duration = Duration::from_secs(20);
const PRUNE_RECEIPTS_MAX_BATCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Which credential a task runs on. Per `scripts/provision-roles.sql`,
/// `antiphish_contact_graph` is owned by `setjoin_worker`, so only
/// `create-monthly-partitions` requires the schema-owner credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Credential {
    Worker,
    Owner,
}

/// The worker and owner connections a cron task can run on. Both default to
/// the request DSN until the native-RLS flip, like Go.
#[derive(Clone)]
pub struct CronDatabases {
    pub worker: WorkerDatabase,
    pub owner: WorkerDatabase,
}

/// `(task name, frozen statement, credential)` in Go's `AllTasks()` order.
pub const CATALOG: &[(&str, &str, Credential)] = &[
    ("drain-outbound-hot", "SELECT drain_outbound_hot()", Credential::Worker),
    ("dispatch-scheduled-actions", "SELECT dispatch_scheduled_actions('cron')", Credential::Worker),
    ("scan-due-reminders", "SELECT scan_due_reminders()", Credential::Worker),
    ("retry-outbound-queue", "SELECT drain_outbound_queue(true)", Credential::Worker),
    ("drain-journal-queue", "SELECT drain_journal_queue()", Credential::Worker),
    ("retry-journal-queue", "SELECT drain_journal_queue(100, true)", Credential::Worker),
    ("prune-ws-subscriptions", "SELECT prune_ws_subscriptions()", Credential::Worker),
    ("prune-used-password-reset-tokens", "SELECT prune_used_password_reset_tokens()", Credential::Worker),
    ("approval-expire-due", "SELECT approval_expire_due()", Credential::Worker),
    ("health-check", "SELECT health_check()", Credential::Worker),
    ("refresh-antiphish-contact-graph", "REFRESH MATERIALIZED VIEW antiphish_contact_graph", Credential::Worker),
    ("reset-sending-quotas", "SELECT reset_sending_quotas()", Credential::Worker),
    ("prune-auth-lockouts", "SELECT prune_old_lockouts()", Credential::Worker),
    ("enforce-retention", "SELECT enforce_retention()", Credential::Worker),
    ("purge-deleted-messages", "SELECT purge_deleted_messages()", Credential::Worker),
    ("chat-chain-anchor", "SELECT chat_chain_anchor()", Credential::Worker),
    ("chat-purge-expired", "SELECT chat_purge_run()", Credential::Worker),
    ("prune-dmarc-reports", "SELECT prune_dmarc_reports()", Credential::Worker),
    ("prune-spam", "SELECT prune_spam()", Credential::Worker),
    ("prune-log-tables", "SELECT prune_log_tables()", Credential::Worker),
    ("prune-ca-signin-log", "SELECT ca_signin_log_prune(COALESCE((SELECT (value #>> '{}')::int FROM system_config WHERE key = 'ca_signin_log_retain_days'), 30))", Credential::Worker),
    ("prune-login-events", "SELECT login_events_prune(COALESCE((SELECT (value #>> '{}')::int FROM system_config WHERE key = 'login_events_retain_days'), 180))", Credential::Worker),
    ("prune-session-runtime", "SELECT prune_session_runtime()", Credential::Worker),
    ("prune-changes-journal", "SELECT prune_changes_journal(COALESCE((SELECT MAX(max_offline_days) FROM offline_policies WHERE enabled), 30), COALESCE((SELECT (value #>> '{}')::int FROM system_config WHERE key = 'offline_journal_high_water'), 50000))", Credential::Worker),
    ("prune-bulk-role-jobs", "DELETE FROM bulk_role_jobs WHERE status IN ('done','error') AND updated_at < now() - interval '30 days'", Credential::Worker),
    ("prune-greylist", "SELECT prune_greylist_entries()", Credential::Worker),
    ("prune-health-history", "SELECT prune_health_history()", Credential::Worker),
    ("prune-vacation-replies", "SELECT prune_vacation_replies()", Credential::Worker),
    ("purge-expired-tokens", "SELECT purge_expired_tokens()", Credential::Worker),
    ("purge-saml-assertions", "SELECT purge_saml_assertions()", Credential::Worker),
    ("create-monthly-partitions", "SELECT create_monthly_partitions(1)", Credential::Owner),
    ("prune-rust-operation-receipts", "SELECT prune_rust_operation_receipts(5000)", Credential::Worker),
];

/// The credential `name` runs on, or None for an unknown task.
pub fn credential(name: &str) -> Option<Credential> {
    CATALOG.iter().find(|(n, ..)| *n == name).map(|(.., c)| *c)
}

/// Drain expired `public.rust_operation_receipts` rows in bounded per-batch
/// transactions (#473). Each batch runs in its own transaction with a
/// server-side `SET LOCAL statement_timeout` bounded to remaining budget
/// (`1..=10_000` ms). Breaks on partial batch, `max_batches`, or soft budget
/// exhaustion; propagates any DB/`BZ040` error.
pub async fn drain_rust_operation_receipts(
    db: &WorkerDatabase,
    batch_size: i32,
    max_batches: usize,
    budget: Duration,
) -> Result<u64, WorkerError> {
    let conn = db.connect().await?;
    let started = Instant::now();
    let mut total: u64 = 0;
    let mut batches: usize = 0;
    loop {
        let elapsed = started.elapsed();
        if batches >= max_batches || elapsed >= budget {
            break;
        }
        let remaining = budget.saturating_sub(elapsed);
        let batch_timeout = remaining.min(PRUNE_RECEIPTS_MAX_BATCH_TIMEOUT);
        conn.begin_with_timeout(batch_timeout).await?;
        let rows = conn
            .query(
                "SELECT public.prune_rust_operation_receipts($1)",
                &[(&batch_size, setjoin_pg::Type::INT4)],
            )
            .await?;
        let deleted: i64 = rows
            .first()
            .ok_or("prune_rust_operation_receipts returned no rows")?
            .try_get(0)?;
        conn.batch("COMMIT").await?;
        total = total.saturating_add(u64::try_from(deleted).unwrap_or(0));
        batches += 1;
        if deleted < i64::from(batch_size)
            || batches >= max_batches
            || started.elapsed() >= budget
        {
            break;
        }
    }
    Ok(total)
}

/// The frozen SQL statement for `name`, or None if unknown.
pub fn statement(name: &str) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|(n, ..)| *n == name)
        .map(|(_, sql, _)| *sql)
}

/// All periodic maintenance tasks supervised under `worker_schedules`
/// (`dispatch-scheduled-actions` is superseded by the durable `WorkQueue`
/// promoter from Wave 2.1 #548).
pub fn supervised_tasks() -> Vec<(&'static str, &'static str, Credential)> {
    CATALOG
        .iter()
        .copied()
        .filter(|(name, _, _)| *name != "dispatch-scheduled-actions")
        .collect()
}

/// The Rust callback for cron task `name`, or None when no such task exists.
pub fn cron_action(name: &str, dbs: &CronDatabases) -> Option<Action> {
    if name.starts_with("chat-") {
        // Chat keeps its own callbacks (#365); same statements as the catalog rows.
        return crate::chat_workers::cron_action(name, &dbs.worker);
    }
    if name == PRUNE_RECEIPTS_TASK {
        let db = dbs.worker.clone();
        return Some(Arc::new(move || {
            let db = db.clone();
            Box::pin(async move {
                drain_rust_operation_receipts(
                    &db,
                    PRUNE_RECEIPTS_BATCH_SIZE,
                    PRUNE_RECEIPTS_MAX_BATCHES,
                    PRUNE_RECEIPTS_BUDGET,
                )
                .await
                .map(|_| ())
            })
        }));
    }
    let (_, sql, credential) = CATALOG.iter().find(|(n, ..)| *n == name)?;
    let db = match credential {
        Credential::Worker => dbs.worker.clone(),
        Credential::Owner => dbs.owner.clone(),
    };
    let sql: &'static str = sql;
    Some(Arc::new(move || {
        let db = db.clone();
        Box::pin(async move { db.run_cron_statement(sql).await })
    }))
}

/// Register explicitly listed cron tasks and auto-register
/// `prune-rust-operation-receipts` when `tasks` is non-empty and it was not
/// explicitly listed (#473). Explicit tasks fail fast on lock contention;
/// auto-registration logs and skips when another Rust scheduler already holds
/// `cron-task:prune-rust-operation-receipts`, while still failing on DB/config
/// errors.
pub async fn register_cron_tasks(
    scheduler: &mut CronScheduler,
    tasks: &[&str],
    dbs: &CronDatabases,
    go_off: &str,
) -> Result<(), String> {
    let mut has_prune_receipts = false;
    for &name in tasks {
        if name == PRUNE_RECEIPTS_TASK {
            has_prune_receipts = true;
        }
        let action = cron_action(name, dbs)
            .ok_or_else(|| format!("cron:{name} has no Rust implementation yet"))?;
        scheduler
            .register_transferred(name, action, go_off)
            .await
            .map_err(|e| e.to_string())?;
    }
    if !tasks.is_empty() && !has_prune_receipts {
        let action = cron_action(PRUNE_RECEIPTS_TASK, dbs)
            .ok_or_else(|| format!("cron:{PRUNE_RECEIPTS_TASK} has no Rust implementation yet"))?;
        match scheduler
            .try_register_transferred(PRUNE_RECEIPTS_TASK, action)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                eprintln!(
                    "setjoin-gateway: cron task {PRUNE_RECEIPTS_TASK} is already held by another Rust scheduler; skipping auto-registration"
                );
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}
