//! Platform slice `jobs-storage`, group `jobs`: the Background Jobs console reads and the
//! two retry actions (`/admin/jobs/*`).
//!
//! Go's `JobsHandler` reads the F3 queue reducers on the worker pool (cross-tenant by
//! design); `BulkRoleJobsHandler` reads and updates `bulk_role_jobs` on the request pool.
//! Ownership of every write is the verified actor: the receipt binds the sealed actor and
//! the audit row names it. The bulk-role retry is Go's `UPDATE` plus a best-effort audit
//! write; here both run in one statement (one transaction), so a retry never commits
//! without its audit row.
use super::{command, deadline, done, envelope, invalid, scope};
use crate::config::compact;
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

/// Go's `admin.ConsoleScopes[ConsoleMail]` in registration order (`requireMailPerm`).
pub const MAIL_CONSOLE: [&str; 5] = [
    "domains.read",
    "queue.read",
    "reports.read",
    "mail.pipeline",
    "mail.security",
];
/// `requireQueueWrite`.
pub const QUEUE_WRITE: [&str; 1] = ["queue.write"];
/// `requireRolesManage`.
pub const ROLES_MANAGE: [&str; 1] = ["roles.manage"];

/// Go's `knownQueues`.
pub fn known_queue(queue: &str) -> bool {
    matches!(queue, "journal" | "outbound" | "scheduled" | "bulk_role")
}

/// `GET /admin/jobs/summary/{queue}`: `map[string]int`, so sorted keys.
pub async fn summary(worker: &ScopedExecutor, queue: &str) -> Result<String, StatementFailure> {
    let rows = worker
        .read(
            "SELECT active::bigint, failed::bigint, dead::bigint, done::bigint, total::bigint FROM get_queue_summary($1)",
            &[(&queue, Type::TEXT)],
        )
        .await?;
    let row = rows.first().ok_or_else(invalid)?;
    let n = |i: usize| row.try_get::<_, i64>(i).map_err(|_| invalid());
    Ok(done(format!(
        "{{\"active\":{},\"dead\":{},\"done\":{},\"failed\":{},\"total\":{}}}",
        n(0)?,
        n(2)?,
        n(3)?,
        n(1)?,
        n(4)?
    )))
}

/// `GET /admin/jobs/{queue}`: each `item` is the reducer's jsonb text, compacted and
/// HTML-escaped as `json.Marshal` does a `RawMessage`. Go ignores a row that fails to scan.
pub async fn list(
    worker: &ScopedExecutor,
    queue: &str,
    status: &str,
    limit: i32,
    offset: i32,
) -> Result<String, StatementFailure> {
    let rows = worker
        .read(
            "SELECT item::text FROM list_queue($1, $2, $3, $4)",
            &[
                (&queue, Type::TEXT),
                (&status, Type::TEXT),
                (&limit, Type::INT4),
                (&offset, Type::INT4),
            ],
        )
        .await?;
    let items: Vec<String> = rows
        .iter()
        .filter_map(|r| r.try_get::<_, String>(0).ok())
        .map(|t| compact(&t))
        .collect();
    Ok(done(format!("[{}]", items.join(","))))
}

/// `POST /admin/jobs/journal/{id}/retry`: Go's `SELECT repend_dead_journal_row($1)`;
/// `true` when a dead-lettered row was re-pended.
pub async fn retry_journal(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("jobs.journal_retry"),
        &envelope(&auth, operation, &format!("journal_retry:{id}")),
        &auth,
        deadline(),
        "SELECT repend_dead_journal_row($4::bigint) WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[(&id, Type::INT8)],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get::<_, i32>(0).ok())
                .map(|affected| affected > 0)
                .ok_or_else(invalid)
        },
    )
    .await
}

/// `GET /admin/jobs/bulk_role/{id}`: `row_to_json` bytes, written verbatim. `None` is Go's
/// 404 (no row, or any error).
pub async fn bulk_detail(exec: &ScopedExecutor, id: i64) -> Option<String> {
    let rows = exec
        .read(
            "SELECT row_to_json(b)::text FROM bulk_role_jobs b WHERE id = $1",
            &[(&id, Type::INT8)],
        )
        .await
        .ok()?;
    rows.first()?.try_get::<_, String>(0).ok()
}

/// `POST /admin/jobs/bulk_role/{id}/retry`: re-queue an errored job keeping `processed` and
/// `results`, and write the `bulk_role_job_retry` audit row in the same transaction.
/// `true` when the job was in the error state.
pub async fn bulk_retry(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("jobs.bulk_role_retry"),
        &envelope(&auth, operation, &format!("bulk_role_retry:{id}")),
        &auth,
        deadline(),
        "WITH u AS (UPDATE bulk_role_jobs SET status = 'queued', error = NULL, updated_at = now() \
           WHERE id = $4::bigint AND status = 'error' AND $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING id) \
         SELECT u.id, (SELECT count(*) FROM (SELECT audit_write($2::bigint, 'bulk_role_job_retry', 'bulk_role_job', u.id, NULL, NULL, NULLIF($5::text, '')::inet, '', 'core')) w)::bigint FROM u",
        &[(&id, Type::INT8), (&ip, Type::TEXT)],
        |rows| match rows {
            [] => Ok(false),
            [_] => Ok(true),
            _ => Err(invalid()),
        },
    )
    .await
}
