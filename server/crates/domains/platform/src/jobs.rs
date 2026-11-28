//! Platform slice `jobs-storage`, group `jobs`: the Background Jobs console reads and the
//! two retry actions (`/admin/jobs/*`).
use super::{command, deadline, done, envelope, invalid, sql};
use crate::config::compact;
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

pub const MAIL_CONSOLE: [&str; 5] = [
    "domains.read",
    "queue.read",
    "reports.read",
    "mail.pipeline",
    "mail.security",
];
pub const QUEUE_WRITE: [&str; 1] = ["queue.write"];
pub const ROLES_MANAGE: [&str; 1] = ["roles.manage"];

pub fn known_queue(queue: &str) -> bool {
    matches!(queue, "journal" | "outbound" | "scheduled" | "bulk_role")
}

/// `GET /admin/jobs/summary/{queue}`: `map[string]int`, so sorted keys.
pub async fn summary(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    queue: &str,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::JOBS_SUMMARY, &[&queue])
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

/// `GET /admin/jobs/{queue}`.
pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    queue: &str,
    status: &str,
    limit: i32,
    offset: i32,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::JOBS_LIST, &[&queue, &status, &limit, &offset])
        .await?;
    let items: Vec<String> = rows
        .iter()
        .filter_map(|r| r.try_get::<_, String>(0).ok())
        .map(|t| compact(&t))
        .collect();
    Ok(done(format!("[{}]", items.join(","))))
}

/// `POST /admin/jobs/journal/{id}/retry`.
pub async fn retry_journal(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("journal_retry:{id}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::JOBS_RETRY_JOURNAL,
            &[&id],
            Some(command("jobs.journal_retry")),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get::<_, i32>(0).ok())
                    .map(|affected| affected > 0)
                    .ok_or_else(invalid)
            },
        )
        .await
}

/// `GET /admin/jobs/bulk_role/{id}`: `row_to_json` bytes, written verbatim. `None` is Go's 404.
pub async fn bulk_detail(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
) -> Option<String> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::JOBS_BULK_DETAIL, &[&id])
        .await
        .ok()?;
    rows.first()?.try_get::<_, String>(0).ok()
}

/// `POST /admin/jobs/bulk_role/{id}/retry`: calls owning `rust_admin_bulk_role_job_retry`
/// reducer (`ReducerWritesCoreAudit`), retiring direct cross-domain write to `bulk_role_jobs`.
pub async fn bulk_retry(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("bulk_role_retry:{id}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::JOBS_BULK_RETRY,
            &[&id, &ip],
            Some(command("jobs.bulk_role_retry")),
            |rows, _audited| {
                rows.first()
                    .and_then(|r| r.try_get::<_, bool>(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}
