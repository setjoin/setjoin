//! Platform slice `system-features`, group `system`: version, schema version, process
//! status and the backup run queue (`/admin/system/*`).
use super::{command, deadline, done, envelope, invalid, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

pub fn version() -> String {
    done("{\"version\":\"v2.1.3\"}".into())
}

pub struct Process {
    pub pid: u32,
    pub uptime_sec: u64,
    pub tasks: u64,
    pub memory_mb: u64,
    pub started_at: String,
}

pub fn status(p: &Process) -> String {
    done(format!(
        "{{\"goroutines\":{},\"memory_mb\":{},\"pid\":{},\"started_at\":{},\"status\":\"running\",\"uptime_sec\":{}}}",
        p.tasks,
        p.memory_mb,
        p.pid,
        s(&p.started_at),
        p.uptime_sec
    ))
}

/// `GET /admin/system/schema-version`.
pub async fn schema_version(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let expected = setjoin_schema::MIGRATIONS.last().map_or(0, |m| m.0);
    let current = match factory
        .run_admin_read_contract(admin, &sql::SYSTEM_SCHEMA_VERSION, &[])
        .await
    {
        Ok(rows) => rows
            .first()
            .and_then(|r| r.try_get::<_, i64>(0).ok())
            .ok_or_else(invalid)?,
        Err(e) if e.sqlstate.as_deref() == Some("42P01") => 0,
        Err(e) => return Err(e),
    };
    let pending: Vec<String> = setjoin_schema::MIGRATIONS
        .iter()
        .filter(|m| i64::from(m.0) > current)
        .map(|m| s(m.1))
        .collect();
    Ok(done(format!(
        "{{\"current\":{current},\"expected\":{expected},\"pending\":[{}],\"up_to_date\":{}}}",
        pending.join(","),
        current >= i64::from(expected)
    )))
}

/// `GET /admin/system/backup/list`: the 50 newest runs.
pub async fn backup_list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::SYSTEM_BACKUP_LIST, &[])
        .await?;
    let bad = |_| invalid();
    let int = |v: Option<i64>| v.map_or("null".to_owned(), |n| n.to_string());
    let text = |v: Option<String>| v.map_or("null".to_owned(), |t| s(&t));
    let mut out = Vec::new();
    for r in &rows {
        out.push(format!(
            "{{\"id\":{},\"status\":{},\"blob_count\":{},\"blob_total_size\":{},\"config_size\":{},\"manifest_timestamp\":{},\"blobs_copied\":{},\"blobs_skipped\":{},\"started_at\":{},\"completed_at\":{},\"created_at\":{}}}",
            r.try_get::<_, i64>(0).map_err(bad)?,
            s(&r.try_get::<_, String>(1).map_err(bad)?),
            int(r.try_get(2).map_err(bad)?),
            int(r.try_get(3).map_err(bad)?),
            int(r.try_get(4).map_err(bad)?),
            text(r.try_get(5).map_err(bad)?),
            int(r.try_get(6).map_err(bad)?),
            int(r.try_get(7).map_err(bad)?),
            text(r.try_get(8).map_err(bad)?),
            text(r.try_get(9).map_err(bad)?),
            text(r.try_get(10).map_err(bad)?),
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// `POST /admin/system/backup`: enqueue one pending run (trigger notifies the worker).
pub async fn backup_enqueue(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(user.user(), user.generation(), operation, "backup");
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::SYSTEM_BACKUP_ENQUEUE,
            &[],
            Some(command("backup_enqueue")),
            |rows| match rows.as_slice() {
                [row] => Ok(done(format!(
                    "{{\"run_id\":{},\"status\":\"enqueued\"}}",
                    row.try_get::<_, i64>(0).map_err(|_| invalid())?
                ))),
                _ => Err(invalid()),
            },
        )
        .await
}
