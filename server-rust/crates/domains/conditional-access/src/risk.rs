//! Conditional access (F03) slice `remaining`: the user-risk dashboard routes. Both run on
//! `AdminWorkerPool` via `TxFactory` (`AdminReadTx` / `AdminWriteTx<Unaudited -> Audited>`).
use super::policies::compact;
use super::{command, deadline, done, envelope, invalid, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::{AuditEvent, CommandOutcome, Rejection, StatementFailure};

/// `GET /admin/user-risk?limit=`: elevated rows by score, `limit` default 100, capped at 500.
pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    limit: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::USER_RISK_LIST, &[&limit])
        .await?;
    let bad = |_| invalid();
    let mut out = Vec::new();
    for r in &rows {
        out.push(format!(
            "{{\"user_id\":{},\"email\":{},\"score\":{},\"level\":{},\"signals\":{},\"updated_at\":{}}}",
            r.try_get::<_, i64>(0).map_err(bad)?,
            s(&r.try_get::<_, String>(1).map_err(bad)?),
            r.try_get::<_, i32>(2).map_err(bad)?,
            s(&r.try_get::<_, String>(3).map_err(bad)?),
            compact(&r.try_get::<_, String>(4).map_err(bad)?),
            s(&r.try_get::<_, String>(5).map_err(bad)?),
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// `POST /admin/user-risk/{id}/reset`: `true` when a row was reset (and audited), `false` for
/// Go's 404 `user_risk not found`.
pub async fn reset(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    ip: &str,
    user: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let after = format!("{{\"action\":\"risk_reset\",\"user_id\":{user}}}");
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{ip}:{user}"),
    );
    let mut tx = match factory.begin_admin_write(admin, &env, deadline()).await {
        Ok(tx) => tx,
        Err(r) => return CommandOutcome::RolledBack(r),
    };
    let rows = match tx.query_contract(&sql::USER_RISK_RESET, &[&user]).await {
        Ok(rows) => rows,
        Err(e) => {
            let _ = tx.rollback().await;
            return CommandOutcome::RolledBack(Rejection::Statement(e));
        }
    };
    if rows.is_empty() {
        let _ = tx.rollback().await;
        return CommandOutcome::Committed(false);
    }
    let Ok(mut audit) = AuditEvent::new("user_risk.reset", "user_risk") else {
        let _ = tx.rollback().await;
        return CommandOutcome::RolledBack(Rejection::Body(invalid()));
    };
    audit = audit
        .with_target_id(user)
        .with_after_json(after)
        .with_notes("");
    if !ip.is_empty() {
        audit = audit.with_ip(ip);
    }
    let mut tx = match tx.record_audit(&audit).await {
        Ok(tx) => tx,
        Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
    };
    if let Err(e) = tx.record_receipt(command("user_risk_reset")).await {
        let _ = tx.rollback().await;
        return CommandOutcome::RolledBack(Rejection::Statement(e));
    }
    match tx.commit().await {
        CommandOutcome::Committed(()) => CommandOutcome::Committed(true),
        CommandOutcome::RolledBack(r) => CommandOutcome::RolledBack(r),
        CommandOutcome::Unknown { operation } => CommandOutcome::Unknown { operation },
    }
}
