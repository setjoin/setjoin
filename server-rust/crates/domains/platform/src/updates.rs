//! Platform slice `updates-deploy`, group `updates`: the upgrade history list and the
//! client update management routes (`/admin/updates/*`).
use super::{command, deadline, done, envelope, invalid, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

/// `GET /admin/system/upgrade/status`: the 50 newest attempts; any query fault is Go's `200 []`.
pub async fn history(factory: &TxFactory, admin: &AdminPermissionProof) -> String {
    let Ok(rows) = factory
        .run_admin_read_contract(admin, &sql::UPDATES_HISTORY, &[])
        .await
    else {
        return done("[]".into());
    };
    let mut out = Vec::new();
    for r in &rows {
        let text = |i: usize| {
            r.try_get::<_, String>(i)
                .map(|t| s(&t))
                .unwrap_or_else(|_| s(""))
        };
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
pub async fn summary(factory: &TxFactory, admin: &AdminPermissionProof, reach: i64) -> String {
    let reach = effective(reach);
    let perms: Vec<String> = crate::SYSTEM_CONSOLE
        .iter()
        .map(|p| (*p).to_owned())
        .collect();
    let total = match factory
        .run_admin_read_contract(admin, &sql::UPDATES_DEVICES_TOTAL, &[&reach, &perms])
        .await
    {
        Ok(rows) => rows
            .first()
            .and_then(|r| r.try_get::<_, i64>(0).ok())
            .unwrap_or(0),
        Err(_) => 0,
    };
    let mut versions = Vec::new();
    if let Ok(rows) = factory
        .run_admin_read_contract(admin, &sql::UPDATES_DEVICES_BY_VERSION, &[&reach, &perms])
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
    if let Ok(rows) = factory
        .run_admin_read_contract(admin, &sql::UPDATES_DEVICES_BY_PLATFORM, &[&reach, &perms])
        .await
    {
        for r in &rows {
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

/// `GET /admin/updates/devices`.
pub async fn devices(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    reach: i64,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let reach = effective(reach);
    let perms: Vec<String> = crate::SYSTEM_CONSOLE
        .iter()
        .map(|p| (*p).to_owned())
        .collect();
    let rows = factory
        .run_admin_read_contract(
            admin,
            &sql::UPDATES_DEVICES_LIST,
            &[&limit, &offset, &reach, &perms],
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

/// `POST /admin/updates/push`.
pub async fn push(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    count: usize,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let payload = count.to_string();
    let env = envelope(user.user(), user.generation(), operation, &payload);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::UPDATES_PUSH_NOTIFY,
            &[&payload],
            Some(command("update_push")),
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
