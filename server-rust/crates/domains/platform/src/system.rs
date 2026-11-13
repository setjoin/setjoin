//! Platform slice `system-features`, group `system`: version, schema version, process
//! status and the backup run queue (`/admin/system/*`).
//!
//! Go's `SystemHandler`. `status` and `health` describe the serving process, so the
//! numbers are the Rust process's own (the gateway adapter supplies them). The backup
//! enqueue is Go's whole transaction: one `INSERT` whose trigger notifies the worker, with
//! no other write, audit or state bump, so it stays one receipted statement.
use super::{command, deadline, done, envelope, invalid, nano, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure};

/// `GET /admin/system/version`: Go's constant.
pub fn version() -> String {
    done("{\"version\":\"v2.1.3\"}".into())
}

/// The process facts `status` renders; the caller measures them.
pub struct Process {
    pub pid: u32,
    pub uptime_sec: u64,
    pub tasks: u64,
    pub memory_mb: u64,
    pub started_at: String,
}

/// `GET /admin/system/status` and `/admin/system/health` (Go's map: sorted keys).
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

/// `GET /admin/system/schema-version`. `current` is `MAX(version)` of
/// `schema_migrations`, 0 when the table does not exist (an unbaselined database); any
/// other fault is Go's 500 with an `error` document, carried as `Err`.
pub async fn schema_version(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let expected = setjoin_schema::MIGRATIONS.last().map_or(0, |m| m.0);
    let current = match exec
        .read(
            "SELECT COALESCE(MAX(version), 0)::bigint FROM schema_migrations",
            &[],
        )
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

/// `GET /admin/system/backup/list`: the 50 newest runs. A row that fails to decode is
/// Go's 500, so a decode failure is an error here too.
pub async fn backup_list(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let sql = format!(
        "SELECT id, status, blob_count::bigint, blob_total_size, config_size, manifest_timestamp, \
         blobs_copied::bigint, blobs_skipped::bigint, {}, {}, {} \
         FROM backup_runs ORDER BY created_at DESC, id DESC LIMIT 50",
        nano("started_at"),
        nano("completed_at"),
        nano("created_at")
    );
    let rows = exec.read(&sql, &[]).await?;
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("backup_enqueue"),
        &envelope(&auth, operation, "backup"),
        &auth,
        deadline(),
        "INSERT INTO backup_runs (status) SELECT 'pending' WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING id",
        &[],
        |rows| match rows {
            [row] => Ok(done(format!(
                "{{\"run_id\":{},\"status\":\"enqueued\"}}",
                row.try_get::<_, i64>(0).map_err(|_| invalid())?
            ))),
            _ => Err(invalid()),
        },
    )
    .await
}
