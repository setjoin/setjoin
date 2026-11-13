//! The Rust copy of frozen Go's cron catalog (`mailserver/internal/cron/tasks.go`).
//!
//! Every task is one fixed statement run through
//! `WorkerDatabase::run_cron_statement`, exactly as Go's executor runs it. The
//! statements are copied verbatim, including the three `system_config` COALESCE
//! calls and the inline `prune-bulk-role-jobs` DELETE; the reducers stay the
//! business authority. Schedules and timeouts live in `workers::task_spec`.
//! A task runs in Rust only when it is registered through
//! `CronScheduler::register_transferred` (Go's copy off, per-task lock).
use crate::workers::Action;
use setjoin_pg::workers::WorkerDatabase;
use std::sync::Arc;

/// Which credential a task runs on. Go runs every task on its worker pool; the
/// two statements that need schema ownership (`REFRESH MATERIALIZED VIEW`, and
/// partition DDL, which boot also runs on the owner pool) use the owner here.
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
    ("refresh-antiphish-contact-graph", "REFRESH MATERIALIZED VIEW antiphish_contact_graph", Credential::Owner),
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
];

/// The credential `name` runs on, or None for a task Go does not have.
pub fn credential(name: &str) -> Option<Credential> {
    CATALOG.iter().find(|(n, ..)| *n == name).map(|(.., c)| *c)
}

/// The Rust callback for Go cron task `name`, or None when Go has no such task.
pub fn cron_action(name: &str, dbs: &CronDatabases) -> Option<Action> {
    if name.starts_with("chat-") {
        // Chat keeps its own callbacks (#365); same statements as the catalog rows.
        return crate::chat_workers::cron_action(name, &dbs.worker);
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
