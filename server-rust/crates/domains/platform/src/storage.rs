//! Platform slice `jobs-storage`, group `storage`: the DR scan and migration read models
//! (`/admin/storage/dr-scan*`, `/admin/storage/migrate*`).
//!
//! Go renders these as `map[string]any`, so keys are sorted and numbers are `int64`; the
//! scan `details` column is decoded into `[]map[string]any` and re-marshalled (numbers
//! become float64, non-object elements `null`, anything but an array `null`).
use super::{done, invalid, nano, s};
use crate::config::go_any;
use serde_json::Value;
use setjoin_pg::{ScopedExecutor, StatementFailure, Type};

fn text(v: Option<String>) -> Option<String> {
    v.map(|t| s(&t))
}

/// `GET /admin/storage/dr-scan`: the 100 newest scans; `completedAt` only when set.
pub async fn dr_scan_list(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let sql = format!(
        "SELECT id, status, total_scanned, orphaned_count, missing_count, refcount_drift_count, reimported_count, {}, {} \
         FROM storage_dr_scans ORDER BY started_at DESC LIMIT 100",
        nano("started_at"),
        nano("completed_at")
    );
    let rows = exec.read(&sql, &[]).await?;
    let mut out = Vec::new();
    for r in &rows {
        // Go skips a row that fails to scan.
        let Ok(item) = (|| -> Result<String, StatementFailure> {
            let bad = |_| invalid();
            let mut fields = Vec::new();
            if let Some(done_at) = text(r.try_get(8).map_err(bad)?) {
                fields.push(format!("\"completedAt\":{done_at}"));
            }
            fields.push(format!("\"id\":{}", r.try_get::<_, i64>(0).map_err(bad)?));
            fields.push(format!(
                "\"missingCount\":{}",
                r.try_get::<_, i64>(4).map_err(bad)?
            ));
            fields.push(format!(
                "\"orphanedCount\":{}",
                r.try_get::<_, i64>(3).map_err(bad)?
            ));
            fields.push(format!(
                "\"refcountDriftCount\":{}",
                r.try_get::<_, i64>(5).map_err(bad)?
            ));
            fields.push(format!(
                "\"reimportedCount\":{}",
                r.try_get::<_, i64>(6).map_err(bad)?
            ));
            fields.push(format!(
                "\"startedAt\":{}",
                s(&r.try_get::<_, String>(7).map_err(bad)?)
            ));
            fields.push(format!(
                "\"status\":{}",
                s(&r.try_get::<_, String>(1).map_err(bad)?)
            ));
            fields.push(format!(
                "\"totalScanned\":{}",
                r.try_get::<_, i64>(2).map_err(bad)?
            ));
            Ok(format!("{{{}}}", fields.join(",")))
        })() else {
            continue;
        };
        out.push(item);
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/storage/dr-scan/{id}`; `Ok(None)` is Go's 404.
pub async fn dr_scan_get(
    exec: &ScopedExecutor,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let sql = format!(
        "SELECT id, status, total_scanned, orphaned_count, missing_count, refcount_drift_count, reimported_count, details::text, {}, {} \
         FROM storage_dr_scans WHERE id = $1",
        nano("started_at"),
        nano("completed_at")
    );
    let rows = exec.read(&sql, &[(&id, Type::INT8)]).await?;
    let Some(r) = rows.first() else {
        return Ok(None);
    };
    let bad = |_| invalid();
    let details = match r.try_get::<_, Option<String>>(7).map_err(bad)? {
        Some(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(Value::Array(items)) => format!(
                "[{}]",
                items
                    .iter()
                    .map(|item| if item.is_object() {
                        go_any(item)
                    } else {
                        "null".to_owned()
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            _ => "null".to_owned(),
        },
        None => "null".to_owned(),
    };
    let completed = text(r.try_get(9).map_err(bad)?).unwrap_or_else(|| "null".into());
    Ok(Some(done(format!(
        "{{\"completedAt\":{completed},\"details\":{details},\"id\":{},\"missingCount\":{},\"orphanedCount\":{},\"refcountDriftCount\":{},\"reimportedCount\":{},\"startedAt\":{},\"status\":{},\"totalScanned\":{}}}",
        r.try_get::<_, i64>(0).map_err(bad)?,
        r.try_get::<_, i64>(4).map_err(bad)?,
        r.try_get::<_, i64>(3).map_err(bad)?,
        r.try_get::<_, i64>(5).map_err(bad)?,
        r.try_get::<_, i64>(6).map_err(bad)?,
        s(&r.try_get::<_, String>(8).map_err(bad)?),
        s(&r.try_get::<_, String>(1).map_err(bad)?),
        r.try_get::<_, i64>(2).map_err(bad)?,
    ))))
}

fn progress(migrated: i64, total: i64) -> String {
    go_any(&serde_json::json!(migrated as f64 * 100.0 / total as f64))
}

/// `GET /admin/storage/migrate`: the 20 newest migrations. Any decode failure is Go's
/// 500 `query failed` (`Err`); a NULL start time renders `null`.
pub async fn migrate_list(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let sql = format!(
        "SELECT id, source_driver, target_driver, status, COALESCE(total_blobs, 0), COALESCE(migrated, 0), {}, {} \
         FROM storage_migrations ORDER BY started_at DESC LIMIT 20",
        nano("started_at"),
        nano("completed_at")
    );
    let rows = exec.read(&sql, &[]).await?;
    let bad = |_| invalid();
    let mut out = Vec::new();
    for r in &rows {
        let (total, migrated) = (
            r.try_get::<_, i64>(4).map_err(bad)?,
            r.try_get::<_, i64>(5).map_err(bad)?,
        );
        let mut fields = Vec::new();
        if let Some(c) = text(r.try_get(7).map_err(bad)?) {
            fields.push(format!("\"completed\":{c}"));
        }
        fields.push(format!("\"id\":{}", r.try_get::<_, i64>(0).map_err(bad)?));
        fields.push(format!("\"migrated\":{migrated}"));
        if total > 0 {
            fields.push(format!("\"progress_pct\":{}", progress(migrated, total)));
        }
        fields.push(format!(
            "\"source\":{}",
            s(&r.try_get::<_, String>(1).map_err(bad)?)
        ));
        fields.push(format!(
            "\"started\":{}",
            text(r.try_get(6).map_err(bad)?).unwrap_or_else(|| "null".into())
        ));
        fields.push(format!(
            "\"status\":{}",
            s(&r.try_get::<_, String>(3).map_err(bad)?)
        ));
        fields.push(format!(
            "\"target\":{}",
            s(&r.try_get::<_, String>(2).map_err(bad)?)
        ));
        fields.push(format!("\"total\":{total}"));
        out.push(format!("{{{}}}", fields.join(",")));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/storage/migrate/{id}`: the `Migrator.Status` read model. Go answers 404 for
/// every failure, including a NULL `started_at` (cannot scan into `time.Time`).
pub async fn migrate_status(exec: &ScopedExecutor, id: i64) -> Option<String> {
    let sql = format!(
        "SELECT status, COALESCE(total_blobs, 0), COALESCE(migrated, 0), last_key, {}, {} \
         FROM storage_migrations WHERE id = $1",
        nano("started_at"),
        nano("completed_at")
    );
    let rows = exec.read(&sql, &[(&id, Type::INT8)]).await.ok()?;
    let r = rows.first()?;
    let total: i64 = r.try_get(1).ok()?;
    let migrated: i64 = r.try_get(2).ok()?;
    let mut fields = Vec::new();
    if let Some(c) = text(r.try_get(5).ok()?) {
        fields.push(format!("\"completed\":{c}"));
    }
    fields.push(format!("\"id\":{id}"));
    if let Some(key) = text(r.try_get(3).ok()?) {
        fields.push(format!("\"last_key\":{key}"));
    }
    fields.push(format!("\"migrated\":{migrated}"));
    if total > 0 {
        fields.push(format!("\"progress_pct\":{}", progress(migrated, total)));
    }
    let started: Option<String> = r.try_get(4).ok()?;
    fields.push(format!("\"started\":{}", s(&started?)));
    fields.push(format!(
        "\"status\":{}",
        s(&r.try_get::<_, String>(0).ok()?)
    ));
    fields.push(format!("\"total\":{total}"));
    Some(done(format!("{{{}}}", fields.join(","))))
}

/// The storage catalog is server-wide, gated by the HTTP actor's system.config grant.
/// These are Go's independent autocommit statements, each bound to the sealed actor.
pub async fn reimport_blob(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    operation: [u8; 16],
    sha: &str,
    object_ref: &str,
    size: i64,
    content_type: &str,
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        super::command("storage.reimport_blob"),
        &super::envelope(
            &auth,
            operation,
            &format!("reimport:{sha}:{object_ref}:{size}:{content_type}"),
        ),
        &auth,
        super::deadline(),
        "INSERT INTO blobs(sha256,minio_ref,size_bytes,content_type,ref_count) \
         SELECT $4,$5,$6,$7,0 WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>'' \
         ON CONFLICT(sha256) DO NOTHING",
        &[
            (&sha, Type::TEXT),
            (&object_ref, Type::TEXT),
            (&size, Type::INT8),
            (&content_type, Type::TEXT),
        ],
        |_| Ok(()),
    )
    .await
}

pub async fn reconcile_count(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    operation: [u8; 16],
    id: i64,
    count: i64,
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        super::command("storage.reconcile_count"),
        &super::envelope(&auth, operation, &format!("reconcile:{id}:{count}")),
        &auth,
        super::deadline(),
        "UPDATE storage_dr_scans SET reimported_count=$5 WHERE id=$4 \
         AND $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8), (&count, Type::INT8)],
        |_| Ok(()),
    )
    .await
}

pub async fn reconcile_details(
    exec: &ScopedExecutor,
    id: i64,
) -> Result<Option<(String, Option<String>)>, StatementFailure> {
    let rows = exec
        .read(
            "SELECT status, details::text FROM storage_dr_scans WHERE id=$1",
            &[(&id, Type::INT8)],
        )
        .await?;
    rows.first()
        .map(|r| {
            Ok((
                r.try_get(0).map_err(|_| invalid())?,
                r.try_get(1).map_err(|_| invalid())?,
            ))
        })
        .transpose()
}

pub async fn begin_scan(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(exec, super::command("storage.scan_start"),
        &super::envelope(&auth, operation, "scan_start"), &auth, super::deadline(),
        "INSERT INTO storage_dr_scans(status) SELECT 'running' WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>'' RETURNING id",
        &[], |rows| rows.first().and_then(|r| r.try_get(0).ok()).ok_or_else(invalid)).await
}

/// Explicit server-wide storage maintenance reads on the worker credential.
pub async fn scan_keys(
    db: &setjoin_pg::workers::WorkerConnection,
) -> Result<std::collections::BTreeSet<String>, String> {
    let mut rows = db.rows("SELECT sha256 FROM blobs", &[]).await?;
    let mut keys = std::collections::BTreeSet::new();
    // Frozen Go ignores Rows.Err here; keep every successfully decoded prefix row.
    while let Ok(Some(row)) = rows.next().await {
        if let Ok(key) = row.try_get::<_, String>(0) {
            keys.insert(key);
        }
    }
    Ok(keys)
}
pub async fn scan_drift(
    db: &setjoin_pg::workers::WorkerConnection,
) -> Result<Vec<(String, i64, i64)>, String> {
    let mut rows=db.rows("SELECT b.sha256, b.ref_count::bigint, COUNT(ma.id) FROM blobs b LEFT JOIN message_attachments ma ON ma.blob_sha256=b.sha256 GROUP BY b.sha256,b.ref_count HAVING b.ref_count!=COUNT(ma.id)",&[]).await?;
    let mut drift = vec![];
    while let Ok(Some(row)) = rows.next().await {
        if let (Ok(key), Ok(expected), Ok(actual)) =
            (row.try_get(0), row.try_get(1), row.try_get(2))
        {
            drift.push((key, expected, actual));
        }
    }
    Ok(drift)
}
pub async fn scan_failed(db: &setjoin_pg::workers::WorkerConnection, id: i64) {
    let _ = db
        .execute(
            "UPDATE storage_dr_scans SET status='failed',completed_at=now() WHERE id=$1",
            &[(&id, Type::INT8)],
        )
        .await;
}
pub async fn scan_progress(
    db: &setjoin_pg::workers::WorkerConnection,
    id: i64,
    counts: [i64; 4],
    details: &[Value],
    complete: bool,
) {
    let [total, orphaned, missing, drift] = counts;
    let mut params: Vec<setjoin_pg::Param<'_>> = vec![
        (&total, Type::INT8),
        (&orphaned, Type::INT8),
        (&missing, Type::INT8),
        (&drift, Type::INT8),
        (&id, Type::INT8),
    ];
    let text = if details.is_empty() {
        "null".into()
    } else {
        serde_json::to_string(details).expect("JSON scan details")
    };
    let sql = if complete {
        params.push((&text, Type::TEXT));
        "UPDATE storage_dr_scans SET status='completed',total_scanned=$1,orphaned_count=$2,missing_count=$3,refcount_drift_count=$4,details=COALESCE(details,'[]'::jsonb)||$6::jsonb,completed_at=now() WHERE id=$5"
    } else if details.is_empty() {
        "UPDATE storage_dr_scans SET total_scanned=$1,orphaned_count=$2,missing_count=$3,refcount_drift_count=$4 WHERE id=$5"
    } else {
        params.push((&text, Type::TEXT));
        "UPDATE storage_dr_scans SET total_scanned=$1,orphaned_count=$2,missing_count=$3,refcount_drift_count=$4,details=COALESCE(details,'[]'::jsonb)||$6::jsonb WHERE id=$5"
    };
    if let Err(e) = db.execute(sql, &params).await {
        eprintln!("storage scan {id} progress failed: {e}");
    }
}

pub async fn begin_migration(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    operation: [u8; 16],
    target: &str,
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(exec,super::command("storage.migration_start"),
        &super::envelope(&auth,operation,&format!("migration:{target}")),&auth,super::deadline(),
        "INSERT INTO storage_migrations(source_driver,target_driver,status) SELECT 's3',$4,'dual_write' WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>'' RETURNING id",
        &[(&target,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await
}
pub async fn migration_rows(
    db: &setjoin_pg::workers::WorkerConnection,
) -> Result<setjoin_pg::workers::WorkerRows, String> {
    db.rows(
        "SELECT sha256,size_bytes FROM blobs WHERE ref_count>0 ORDER BY sha256",
        &[],
    )
    .await
}
pub async fn migration_status_write(
    db: &setjoin_pg::workers::WorkerConnection,
    id: i64,
    status: &str,
) -> Result<(), String> {
    let sql = if matches!(status, "failed" | "cancelled" | "completed") {
        "UPDATE storage_migrations SET status=$1,completed_at=now() WHERE id=$2"
    } else {
        "UPDATE storage_migrations SET status=$1 WHERE id=$2"
    };
    db.execute(sql, &[(&status, Type::TEXT), (&id, Type::INT8)])
        .await
        .map(|_| ())
}
pub async fn migration_progress(
    db: &setjoin_pg::workers::WorkerConnection,
    id: i64,
    count: i64,
    last: Option<&str>,
) {
    let result = if let Some(key) = last {
        db.execute(
            "UPDATE storage_migrations SET migrated=$1,last_key=$2 WHERE id=$3",
            &[(&count, Type::INT8), (&key, Type::TEXT), (&id, Type::INT8)],
        )
        .await
    } else {
        // Frozen Go reports total as successful copies, even when objects failed.
        db.execute(
            "UPDATE storage_migrations SET migrated=$1,total_blobs=$1 WHERE id=$2",
            &[(&count, Type::INT8), (&id, Type::INT8)],
        )
        .await
    };
    if let Err(error) = result {
        eprintln!("storage migration {id} progress failed: {error}");
    }
}
pub async fn migration_orphans(
    db: &setjoin_pg::workers::WorkerConnection,
) -> Result<Vec<(i64, String)>, String> {
    Ok(db.query("SELECT id,status FROM storage_migrations WHERE status IN('dual_write','backfill') ORDER BY id",&[]).await?.iter().filter_map(|r|Some((r.try_get(0).ok()?,r.try_get(1).ok()?))).collect())
}

pub async fn migration_row_status(exec: &ScopedExecutor, id: i64) -> Option<String> {
    let rows = exec
        .read(
            "SELECT status FROM storage_migrations WHERE id=$1",
            &[(&id, Type::INT8)],
        )
        .await
        .ok()?;
    rows.first()?.try_get(0).ok()
}
