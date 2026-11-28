//! Platform slice `jobs-storage`, group `storage`: the DR scan and migration read models
//! (`/admin/storage/dr-scan*`, `/admin/storage/migrate*`).
use super::{done, invalid, s, sql};
use crate::config::go_any;
use serde_json::Value;
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

fn text(v: Option<String>) -> Option<String> {
    v.map(|t| s(&t))
}

/// `GET /admin/storage/dr-scan`: the 100 newest scans; `completedAt` only when set.
pub async fn dr_scan_list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::STORAGE_DR_SCAN_LIST, &[])
        .await?;
    let mut out = Vec::new();
    for r in &rows {
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
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::STORAGE_DR_SCAN_GET, &[&id])
        .await?;
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

/// `GET /admin/storage/migrate`: the 20 newest migrations.
pub async fn migrate_list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::STORAGE_MIGRATE_LIST, &[])
        .await?;
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

/// `GET /admin/storage/migrate/{id}`.
pub async fn migrate_status(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
) -> Option<String> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::STORAGE_MIGRATE_STATUS, &[&id])
        .await
        .ok()?;
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

pub async fn reactivate_blob_v2(
    factory: &TxFactory,
    user: &UserPrincipal,
    operation: [u8; 16],
    sha: &str,
    staging_key: Option<&str>,
) -> Result<String, StatementFailure> {
    let env = super::envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("reactivate:{sha}"),
    );
    match factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            super::deadline(),
            &sql::STORAGE_REACTIVATE_BLOB_V2,
            &[&sha, &staging_key],
            None,
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get::<_, String>(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
    {
        CommandOutcome::Committed(raw) => Ok(raw),
        CommandOutcome::RolledBack(_) | CommandOutcome::Unknown { .. } => Err(invalid()),
    }
}

/// Register a reimported blob via `blob_gc_register_and_reactivate`.
#[allow(clippy::too_many_arguments)]
pub async fn reimport_blob(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    operation: [u8; 16],
    sha: &str,
    object_ref: &str,
    size: i64,
    content_type: &str,
) -> CommandOutcome<(), StatementFailure> {
    let env = super::envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("reimport:{sha}:{object_ref}:{size}:{content_type}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            super::deadline(),
            &sql::STORAGE_REIMPORT_BLOB,
            &[&sha, &object_ref, &size, &content_type],
            Some(super::command("storage.reimport_blob")),
            |_| Ok(()),
        )
        .await
}

pub async fn reconcile_count(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    operation: [u8; 16],
    id: i64,
    count: i64,
) -> CommandOutcome<(), StatementFailure> {
    let env = super::envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("reconcile:{id}:{count}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            super::deadline(),
            &sql::STORAGE_RECONCILE_COUNT,
            &[&id, &count],
            Some(super::command("storage.reconcile_count")),
            |_| Ok(()),
        )
        .await
}

pub async fn reconcile_details(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
) -> Result<Option<(String, Option<String>)>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::STORAGE_RECONCILE_DETAILS, &[&id])
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
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let env = super::envelope(user.user(), user.generation(), operation, "scan_start");
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            super::deadline(),
            &sql::STORAGE_BEGIN_SCAN,
            &[],
            Some(super::command("storage.scan_start")),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

pub async fn begin_migration(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    operation: [u8; 16],
    target: &str,
) -> CommandOutcome<i64, StatementFailure> {
    let env = super::envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("migration:{target}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            super::deadline(),
            &sql::STORAGE_BEGIN_MIGRATION,
            &[&target],
            Some(super::command("storage.migration_start")),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

pub async fn migration_row_status(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
) -> Option<String> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::STORAGE_MIGRATION_ROW_STATUS, &[&id])
        .await
        .ok()?;
    rows.first()?.try_get(0).ok()
}
