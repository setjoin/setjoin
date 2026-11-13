//! Platform slice `updates-deploy`, group `updates`: the upgrade history list and the
//! client update management routes (`/admin/updates/*`).
//!
//! Go's `UpgradeHandler.GetUpgradeHistory` and `UpdatesHandler`. Both read org-wide
//! tables (`upgrade_history`, `devices`) for any admin holding a system permission. The device
//! reads are confined to the caller's reach when it is domain scoped (owner-approved security
//! fix 2026-11-05, #456; frozen Go showed every tenant's devices). Go ignores `rows.Scan` errors, and pgx stops a result set at the first scan
//! error, so a NULL column ends the list with a partially filled entry; `devices` can never
//! list more than one row because Go scans `last_seen` into a string, which pgx refuses for
//! every value. The reads mirror that. The push is Go's whole effect: a `pg_notify` (its
//! `notification_queue` insert targets a table the schema does not have and fails).
use super::{command, deadline, done, envelope, invalid, nano, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

/// `GET /admin/system/upgrade/status`: the 50 newest attempts; any query fault is Go's
/// `200 []`.
pub async fn history(exec: &ScopedExecutor) -> String {
    let sql = format!(
        "SELECT id, from_version, to_version, mode, ddl_classification, status, {}, {}, downtime_ms, COALESCE(error_message, '') \
         FROM upgrade_history ORDER BY started_at DESC LIMIT 50",
        nano("started_at"),
        nano("completed_at")
    );
    let Ok(rows) = exec.read(&sql, &[]).await else {
        return done("[]".into());
    };
    let mut out = Vec::new();
    for r in &rows {
        let text = |i: usize| r.try_get::<_, String>(i).map(|t| s(&t)).unwrap_or_else(|_| s(""));
        let completed = r
            .try_get::<_, Option<String>>(7)
            .ok()
            .flatten()
            .map_or("null".to_owned(), |t| s(&t));
        let mut entry = format!(
            "{{\"id\":{},\"from_version\":{},\"to_version\":{},\"mode\":{},\"ddl_classification\":{},\"status\":{},\"started_at\":{},\"completed_at\":{}",
            r.try_get::<_, i64>(0).unwrap_or(0),
            text(1),
            text(2),
            text(3),
            text(4),
            text(5),
            text(6),
            completed,
        );
        // A NULL downtime fails the scan: the entry keeps the zero value and ends the list.
        match r.try_get::<_, Option<i32>>(8) {
            Ok(Some(ms)) => {
                entry += &format!(",\"downtime_ms\":{ms}");
                if let Ok(message) = r.try_get::<_, String>(9) {
                    if !message.is_empty() {
                        entry += &format!(",\"error_message\":{}", s(&message));
                    }
                }
                out.push(entry + "}");
            }
            _ => {
                out.push(entry + ",\"downtime_ms\":0}");
                break;
            }
        }
    }
    done(format!("[{}]", out.join(",")))
}

fn list(items: Vec<String>) -> String {
    if items.is_empty() {
        "null".into()
    } else {
        format!("[{}]", items.join(","))
    }
}

fn effective(reach: i64) -> i64 {
    if setjoin_contracts::mutants::on("updates-devices-unscoped") {
        0
    } else {
        reach
    }
}

/// `GET /admin/updates/summary`: every sub-query fails soft to its zero value.
///
/// Owner-approved security fix 2026-11-05 (#456): `reach` is the caller's user id when the caller is
/// domain scoped and 0 for an organization-wide admin; a scoped caller counts only the devices of users inside
/// its reach (frozen Go showed every tenant's devices to any admin holding a system permission).
pub async fn summary(exec: &ScopedExecutor, reach: i64) -> String {
    let reach = effective(reach);
    let perms: Vec<String> = crate::SYSTEM_CONSOLE.iter().map(|p| p.to_string()).collect();
    let total = match exec
        .read(
            "SELECT COUNT(*)::bigint FROM devices d WHERE ($1::bigint = 0 OR admin_can_reach_perm($1, d.user_id, $2::text[]))",
            &[(&reach, Type::INT8), (&perms, Type::TEXT_ARRAY)],
        )
        .await
    {
        Ok(rows) => rows.first().and_then(|r| r.try_get::<_, i64>(0).ok()).unwrap_or(0),
        Err(_) => 0,
    };
    let mut versions = Vec::new();
    if let Ok(rows) = exec
        .read(
            "SELECT COALESCE(app_version, 'unknown'), COUNT(*)::bigint FROM devices d WHERE ($1::bigint = 0 OR admin_can_reach_perm($1, d.user_id, $2::text[])) GROUP BY app_version ORDER BY COUNT(*) DESC LIMIT 10",
            &[(&reach, Type::INT8), (&perms, Type::TEXT_ARRAY)],
        )
        .await
    {
        for r in &rows {
            versions.push(format!(
                "{{\"version\":{},\"count\":{}}}",
                s(&r.try_get::<_, String>(0).unwrap_or_default()),
                r.try_get::<_, i64>(1).unwrap_or(0)
            ));
        }
    }
    let mut platforms = Vec::new();
    if let Ok(rows) = exec
        .read(
            "SELECT platform, COUNT(*)::bigint FROM devices d WHERE ($1::bigint = 0 OR admin_can_reach_perm($1, d.user_id, $2::text[])) GROUP BY platform ORDER BY COUNT(*) DESC",
            &[(&reach, Type::INT8), (&perms, Type::TEXT_ARRAY)],
        )
        .await
    {
        for r in &rows {
            // A NULL platform fails the scan: a zero entry, then pgx ends the loop.
            match r.try_get::<_, Option<String>>(0) {
                Ok(Some(platform)) => platforms.push(format!(
                    "{{\"platform\":{},\"count\":{}}}",
                    s(&platform),
                    r.try_get::<_, i64>(1).unwrap_or(0)
                )),
                _ => {
                    platforms.push("{\"platform\":\"\",\"count\":0}".into());
                    break;
                }
            }
        }
    }
    done(format!(
        "{{\"total_devices\":{total},\"up_to_date\":{total},\"outdated\":0,\"critical\":0,\"by_version\":{},\"by_platform\":{}}}",
        list(versions),
        list(platforms)
    ))
}

/// `GET /admin/updates/devices`. Go scans the timestamp column into a string, which pgx
/// rejects for every value, so the first row is kept with the columns scanned before the
/// failure (a NULL earlier ends the scan sooner) and the list stops there.
pub async fn devices(
    exec: &ScopedExecutor,
    reach: i64,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let reach = effective(reach);
    let perms: Vec<String> = crate::SYSTEM_CONSOLE.iter().map(|p| p.to_string()).collect();
    let rows = exec
        .read(
            "SELECT d.id, d.device_name, d.platform, d.os_version, d.app_version FROM devices d \
             WHERE ($3::bigint = 0 OR admin_can_reach_perm($3, d.user_id, $4::text[])) \
             ORDER BY d.last_seen DESC NULLS LAST LIMIT $1 OFFSET $2",
            &[(&limit, Type::INT8), (&offset, Type::INT8), (&reach, Type::INT8), (&perms, Type::TEXT_ARRAY)],
        )
        .await?;
    let mut entries = Vec::new();
    if let Some(r) = rows.first() {
        let mut fields = [String::new(), String::new(), String::new(), String::new()];
        for (i, field) in fields.iter_mut().enumerate() {
            match r.try_get::<_, Option<String>>(i + 1) {
                Ok(Some(text)) => *field = text,
                _ => break,
            }
        }
        entries.push(format!(
            "{{\"id\":{},\"name\":{},\"platform\":{},\"os_version\":{},\"app_version\":{},\"last_seen\":\"\",\"status\":\"up_to_date\"}}",
            r.try_get::<_, i64>(0).map_err(|_| invalid())?,
            s(&fields[0]),
            s(&fields[1]),
            s(&fields[2]),
            s(&fields[3]),
        ));
    }
    Ok(done(format!(
        "{{\"devices\":{},\"limit\":{limit},\"offset\":{offset}}}",
        list(entries)
    )))
}

/// `POST /admin/updates/push`: the one effect that lands is `pg_notify('update_available',
/// <count>)`, a single receipted statement.
pub async fn push(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    count: usize,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    let payload = count.to_string();
    setjoin_pg::run_receipted_command(
        exec,
        command("update_push"),
        &envelope(&auth, operation, &payload),
        &auth,
        deadline(),
        "SELECT pg_notify('update_available', $4::text) WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[(&payload, Type::TEXT)],
        |rows| {
            if rows.len() == 1 {
                Ok(())
            } else {
                Err(invalid())
            }
        },
    )
    .await
}
