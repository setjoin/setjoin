//! F04 chat-compliance, organization-wide authority rather than channel membership.
use super::{command as receipt_cmd, deadline, envelope, finish, invalid, quote, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

pub async fn policies(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::CHAT_POLICIES_LIST, &[])
        .await?;
    let mut entries = Vec::with_capacity(rows.len());
    for r in rows {
        let id: i64 = r.try_get(0).map_err(|_| invalid())?;
        let name: String = r.try_get(1).map_err(|_| invalid())?;
        let applies_to: String = r.try_get(2).map_err(|_| invalid())?;
        let duration_days: i32 = r.try_get(3).map_err(|_| invalid())?;
        let enabled: bool = r.try_get(4).map_err(|_| invalid())?;
        let effective_at: String = r.try_get(5).map_err(|_| invalid())?;
        let created_at: String = r.try_get(6).map_err(|_| invalid())?;
        let updated_at: String = r.try_get(7).map_err(|_| invalid())?;
        entries.push(format!(
            "{{\"id\":{id},\"name\":{},\"appliesTo\":{},\"durationDays\":{duration_days},\"enabled\":{enabled},\"effectiveAt\":{},\"createdAt\":{},\"updatedAt\":{}}}",
            quote(&name),
            quote(&applies_to),
            quote(&effective_at),
            quote(&created_at),
            quote(&updated_at)
        ));
    }
    Ok(finish(format!("[{}]", entries.join(","))))
}

pub async fn cases(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::CHAT_CASES_LIST, &[])
        .await?;
    let mut entries = Vec::with_capacity(rows.len());
    for r in &rows {
        let id: i64 = r.try_get(0).map_err(|_| invalid())?;
        let name: String = r.try_get(1).map_err(|_| invalid())?;
        let status: String = r.try_get(2).map_err(|_| invalid())?;
        entries.push(format!(
            "{{\"id\":{id},\"name\":{},\"status\":{}}}",
            quote(&name),
            quote(&status)
        ));
    }
    Ok(finish(format!("[{}]", entries.join(","))))
}

/// Organization-wide hold list followed by Go's separate best-effort core audit
/// (a failed hold query writes no audit row, matching frozen Go).
pub async fn holds(
    factory: &TxFactory,
    user: &UserPrincipal,
    admin: &AdminPermissionProof,
    case: i64,
    ip: &str,
    operation: [u8; 16],
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::CHAT_HOLDS_LIST, &[&case])
        .await?;
    let mut out = Vec::new();
    for r in rows {
        let id: i64 = r.try_get(0).map_err(|_| invalid())?;
        let case_id: i64 = r.try_get(1).map_err(|_| invalid())?;
        let mut fields = format!("{{\"id\":{id},\"caseId\":{case_id}");
        for (i, key) in [(2, "custodianUserId"), (3, "channelId")] {
            if let Some(n) = r.try_get::<_, Option<i64>>(i).map_err(|_| invalid())? {
                fields += &format!(",\"{key}\":{n}");
            }
        }
        let reason: String = r.try_get(4).map_err(|_| invalid())?;
        let created_by: i64 = r.try_get(5).map_err(|_| invalid())?;
        let created_at: String = r.try_get(6).map_err(|_| invalid())?;
        fields += &format!(
            ",\"reason\":{},\"createdBy\":{created_by},\"createdAt\":{}",
            quote(&reason),
            quote(&created_at)
        );
        if let Some(t) = r.try_get::<_, Option<String>>(7).map_err(|_| invalid())? {
            fields += &format!(",\"releasedAt\":{}", quote(&t));
        }
        if let Some(n) = r.try_get::<_, Option<i64>>(8).map_err(|_| invalid())? {
            fields += &format!(",\"releasedBy\":{n}");
        }
        let channels: i64 = r.try_get(9).map_err(|_| invalid())?;
        fields += &format!(",\"channels\":{channels}}}");
        out.push(fields);
    }
    let actor_id = admin.actor().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("chat_case_hold_list:{case}"),
    );
    let _ = factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CHAT_HOLDS_AUDIT,
            &[&actor_id, &case, &ip],
            Some(receipt_cmd("chat.audit")),
            |_| Ok(()),
        )
        .await;
    Ok(finish(format!("[{}]", out.join(","))))
}

pub async fn preview(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::CHAT_PURGE_PREVIEW, &[])
        .await?;
    let mut total = 0i64;
    let mut out = Vec::new();
    for r in rows {
        let channel_id: i64 = r.try_get(0).map_err(|_| invalid())?;
        let count: i32 = r.try_get(1).map_err(|_| invalid())?;
        let id_from: i64 = r.try_get(2).map_err(|_| invalid())?;
        let id_to: i64 = r.try_get(3).map_err(|_| invalid())?;
        let retention_days: i32 = r.try_get(4).map_err(|_| invalid())?;
        total += i64::from(count);
        out.push(format!(
            "{{\"channelId\":{channel_id},\"purgedCount\":{count},\"idFrom\":{id_from},\"idTo\":{id_to},\"retentionDays\":{retention_days}}}"
        ));
    }
    Ok(finish(format!(
        "{{\"channels\":[{}],\"totalChannels\":{},\"totalMessages\":{total}}}",
        out.join(","),
        out.len()
    )))
}

pub async fn overview(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    next: &str,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::CHAT_OVERVIEW, &[])
        .await?;
    let r = rows.first().ok_or_else(invalid)?;
    let under_hold: String = r.try_get(0).map_err(|_| invalid())?;
    let gxp: String = r.try_get(1).map_err(|_| invalid())?;
    let overrides: String = r.try_get(2).map_err(|_| invalid())?;
    let last = factory
        .run_admin_read_contract(admin, &sql::CHAT_OVERVIEW_LAST_PURGE, &[])
        .await?;
    let last = if let Some(r) = last.first() {
        let channels: i32 = r.try_get(0).map_err(|_| invalid())?;
        let messages: i32 = r.try_get(1).map_err(|_| invalid())?;
        let drained: bool = r.try_get(2).map_err(|_| invalid())?;
        let occurred_at: String = r.try_get(3).map_err(|_| invalid())?;
        format!(
            "{{\"channels\":{channels},\"drained\":{drained},\"messages\":{messages},\"occurredAt\":{}}}",
            quote(&occurred_at)
        )
    } else {
        "null".into()
    };
    Ok(finish(format!(
        "{{\"channelsUnderHold\":{under_hold},\"channelsWithOverrides\":{overrides},\"gxpChannels\":{gxp},\"lastPurgeRun\":{last},\"nextRunAt\":{}}}",
        quote(next)
    )))
}

/// One reducer owns policy data and Go's best-effort core audit.
#[allow(clippy::too_many_arguments)]
pub async fn policy(
    factory: &TxFactory,
    user: &UserPrincipal,
    admin: &AdminPermissionProof,
    signed_non_admin: bool,
    action: &str,
    id: i64,
    data: &serde_json::Value,
    confirm: &str,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    let actor_id = admin.actor().get();
    let data = data.to_string();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &serde_json::json!([action, id, data, confirm]).to_string(),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CHAT_POLICY_MUTATE,
            &[
                &actor_id,
                &signed_non_admin,
                &action,
                &id,
                &data,
                &confirm,
                &ip,
            ],
            Some(receipt_cmd("chat.policy")),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get::<_, String>(0).ok())
                    .and_then(|raw| serde_json::from_str(&raw).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

/// Decode the JSON verdict returned by [`sql::CHAT_COMMAND`].
pub fn parse_command_result(
    rows: &[setjoin_pg::Row],
) -> Result<serde_json::Value, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .ok_or_else(invalid)
}

/// Case-bound chat oversight command (`hold`, `release`, `search`, `read`, `export`).
/// Calls worker-owned `SECURITY DEFINER` `rust_compliance_chat_command`, which owns
/// live admin-grant fencing and frozen Go's best-effort core audit.
#[allow(clippy::too_many_arguments)]
pub async fn command(
    factory: &TxFactory,
    user: &UserPrincipal,
    admin: &AdminPermissionProof,
    signed_non_admin: bool,
    action: &str,
    data: &serde_json::Value,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    let actor_id = admin.actor().get();
    let data = data.to_string();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &serde_json::json!([action, data]).to_string(),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CHAT_COMMAND,
            &[&actor_id, &signed_non_admin, &action, &data, &ip],
            Some(receipt_cmd("chat.oversight")),
            |rows| parse_command_result(&rows),
        )
        .await
}
