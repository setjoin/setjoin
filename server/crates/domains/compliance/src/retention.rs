//! Retention policy scope and frozen-Go representation via `TxFactory`.
use super::{command, deadline, envelope, finish, invalid, quote, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

pub async fn policies(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    scope: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::RETENTION_POLICIES_LIST, &[&scope])
        .await?;
    let mut entries = Vec::new();
    for r in rows {
        let id: i64 = r.try_get(0).map_err(|_| invalid())?;
        let name: String = r.try_get(1).map_err(|_| invalid())?;
        let description: String = r.try_get(2).map_err(|_| invalid())?;
        let days: Option<i32> = r.try_get(3).map_err(|_| invalid())?;
        let action: String = r.try_get(4).map_err(|_| invalid())?;
        let is_default: bool = r.try_get(5).map_err(|_| invalid())?;
        let domain: Option<i64> = r.try_get(6).map_err(|_| invalid())?;
        let time: String = r.try_get(7).map_err(|_| invalid())?;
        let time = format!("{}Z", time.trim_end_matches('0').trim_end_matches('.'));
        entries.push(format!(
            "{{\"id\":{id},\"name\":{}{description},\"retainDays\":{},\"action\":{},\"isDefault\":{is_default}{domain},\"createdAt\":{}}}",
            quote(&name),
            days.map_or("null".into(), |n| n.to_string()),
            quote(&action),
            quote(&time),
            description = if description.is_empty() {
                String::new()
            } else {
                format!(",\"description\":{}", quote(&description))
            },
            domain = domain.map_or(String::new(), |n| format!(",\"domainId\":{n}"))
        ));
    }
    Ok(finish(format!("[{}]", entries.join(","))))
}

pub async fn create(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    scope: i64,
    patch: &str,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let env = envelope(admin.actor(), admin.generation(), operation, patch);
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::RETENTION_CREATE,
            &[&scope, &patch, &ip],
            Some(command("retention.create")),
            |rows, audited| {
                if audited {
                    rows.first()
                        .and_then(|r| r.try_get(0).ok())
                        .ok_or_else(invalid)
                } else {
                    Err(invalid())
                }
            },
        )
        .await
}

pub async fn update(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    scope: i64,
    id: i64,
    patch: &str,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{scope}:{id}:{patch}:{ip}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::RETENTION_UPDATE,
            &[&scope, &id, &patch, &ip],
            Some(command("retention.update")),
            |rows, audited| {
                if audited {
                    rows.first()
                        .and_then(|r| r.try_get(0).ok())
                        .ok_or_else(invalid)
                } else {
                    Ok(false)
                }
            },
        )
        .await
}

pub async fn delete(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    scope: i64,
    id: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{scope}:{id}:{ip}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::RETENTION_DELETE,
            &[&scope, &id, &ip],
            Some(command("retention.delete")),
            |rows, audited| {
                if audited {
                    rows.first()
                        .and_then(|r| r.try_get(0).ok())
                        .ok_or_else(invalid)
                } else {
                    Ok(false)
                }
            },
        )
        .await
}

/// Each setting is an independent best-effort lookup in frozen Go.
pub async fn log_get(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let mut values = Vec::new();
    for key in [
        "message_trace",
        "mailbox_audit",
        "auth_event",
        "webhook_delivery",
    ] {
        let key = format!("log_retention_{key}_days");
        let value = factory
            .run_admin_read_contract(admin, &sql::RETENTION_LOG_GET, &[&key])
            .await
            .ok()
            .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, String>(0).ok()))
            .and_then(|s| serde_json::from_str::<i64>(&s).ok())
            .filter(|n| *n > 0);
        values.push(value.map_or("null".into(), |n| n.to_string()));
    }
    Ok(format!(
        "{{\"messageTraceDays\":{},\"mailboxAuditLogDays\":{},\"authEventDays\":{},\"webhookDeliveryDays\":{}}}\n",
        values[0], values[1], values[2], values[3]
    ))
}

pub async fn log_set(
    factory: &TxFactory,
    user: &UserPrincipal,
    admin: &AdminPermissionProof,
    values: &[i64],
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor_id = admin.actor().get();
    let vals = values.to_vec();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{values:?}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::RETENTION_LOG_SET,
            &[&actor_id, &vals],
            Some(command("retention.logs.set")),
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

pub async fn prune(
    factory: &TxFactory,
    user: &UserPrincipal,
    admin: &AdminPermissionProof,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor_id = admin.actor().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        "prune_log_tables",
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::RETENTION_LOG_PRUNE,
            &[&actor_id],
            Some(command("retention.prune")),
            |rows| {
                let values = rows
                    .iter()
                    .filter_map(|r| {
                        Some(format!(
                            "{{\"deleted\":{},\"table\":{}}}",
                            r.try_get::<_, i32>(1).ok()?,
                            quote(&r.try_get::<_, String>(0).ok()?)
                        ))
                    })
                    .collect::<Vec<_>>();
                Ok(finish(format!("[{}]", values.join(","))))
            },
        )
        .await
}
