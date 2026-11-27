//! Shared admin reducer-contract helpers for `setjoin-conditional-access` (F03).
use super::{command, deadline, envelope, invalid, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::{CommandOutcome, Rejection, Row, StatementFailure, ToSql};
use setjoin_sql_catalog::SqlContract;

/// Row/authority lock acquired inside `AdminWriteTx` *before* evaluating the
/// reach/priority precheck contract so concurrent grant revocations or policy
/// retargets cannot race between check and mutation.
pub(crate) enum PolicyLock<'a> {
    /// Acquire `ca_reachability_fence()` (V172/V222 admin-authority advisory lock).
    FenceOnly,
    /// Acquire `ca_reachability_fence()` then `FOR UPDATE` on one policy row.
    Row(i64),
    /// Acquire `ca_reachability_fence()` then `FOR UPDATE` in `ORDER BY id` order.
    Rows(&'a Vec<i64>),
}

/// Run a `ReducerWritesCoreAudit` admin reducer contract through `TxFactory`,
/// binding `$1 = p_actor` from `admin`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_audited<T>(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    name: &'static str,
    operation: [u8; 16],
    payload: &str,
    contract: &'static SqlContract,
    rest_values: &[&(dyn ToSql + Sync)],
    decode: impl FnOnce(&[Row]) -> Result<T, StatementFailure>,
) -> CommandOutcome<T, StatementFailure> {
    let env = envelope(admin.actor(), admin.generation(), operation, payload);
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            contract,
            rest_values,
            Some(command(name)),
            |rows, _audited| decode(&rows),
        )
        .await
}

/// Run an in-transaction lock + reach/priority precheck contract followed by a
/// `ReducerWritesCoreAudit` reducer contract inside the SAME `AdminWriteTx`
/// (preserving R3 atomicity against mid-flight grant revocation and concurrent
/// policy retargeting).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_checked_audited<T>(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    name: &'static str,
    operation: [u8; 16],
    payload: &str,
    lock: PolicyLock<'_>,
    check_contract: &'static SqlContract,
    check_values: &[&(dyn ToSql + Sync)],
    write_contract: &'static SqlContract,
    write_rest_values: &[&(dyn ToSql + Sync)],
    decode: impl FnOnce(&[Row]) -> Result<T, StatementFailure>,
) -> CommandOutcome<T, StatementFailure> {
    let env = envelope(admin.actor(), admin.generation(), operation, payload);
    let mut tx = match factory.begin_admin_write(admin, &env, deadline()).await {
        Ok(tx) => tx,
        Err(r) => return CommandOutcome::RolledBack(r),
    };
    // 1. Serialize against concurrent admin role/grant mutations (V172/V222).
    if let Err(e) = tx.query_contract(&sql::POLICY_LOCK_FENCE, &[]).await {
        let _ = tx.rollback().await;
        return CommandOutcome::RolledBack(Rejection::Statement(e));
    }
    // 2. Lock target policy row(s) FOR UPDATE before evaluating reachability.
    let lock_res = match lock {
        PolicyLock::FenceOnly => Ok(()),
        PolicyLock::Row(id) => tx
            .query_contract(&sql::POLICY_LOCK_ROW, &[&id])
            .await
            .map(|_| ()),
        PolicyLock::Rows(ids) => tx
            .query_contract(&sql::POLICY_LOCK_ROWS, &[ids])
            .await
            .map(|_| ()),
    };
    if let Err(e) = lock_res {
        let _ = tx.rollback().await;
        return CommandOutcome::RolledBack(Rejection::Statement(e));
    }
    // 3. Evaluate reach/priority against locked rows and fenced authority graph.
    let check_rows = match tx.query_contract(check_contract, check_values).await {
        Ok(rows) => rows,
        Err(e) => {
            let _ = tx.rollback().await;
            return CommandOutcome::RolledBack(Rejection::Statement(e));
        }
    };
    let allowed = check_rows
        .first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .unwrap_or(false);
    if !allowed {
        let _ = tx.rollback().await;
        return CommandOutcome::RolledBack(Rejection::Body(invalid()));
    }
    match tx
        .execute_audited_reducer_contract(write_contract, write_rest_values)
        .await
    {
        Ok(setjoin_pg::AdminReducerOutcome::Audited { mut tx, rows }) => {
            let value = match decode(&rows) {
                Ok(v) => v,
                Err(e) => {
                    let _ = tx.rollback().await;
                    return CommandOutcome::RolledBack(Rejection::Body(e));
                }
            };
            if let Err(e) = tx.record_receipt(command(name)).await {
                let _ = tx.rollback().await;
                return CommandOutcome::RolledBack(Rejection::Statement(e));
            }
            match tx.commit().await {
                CommandOutcome::Committed(()) => CommandOutcome::Committed(value),
                CommandOutcome::RolledBack(r) => CommandOutcome::RolledBack(r),
                CommandOutcome::Unknown { operation } => CommandOutcome::Unknown { operation },
            }
        }
        Ok(setjoin_pg::AdminReducerOutcome::NoOp { tx, rows }) => {
            let _ = tx.rollback().await;
            match decode(&rows) {
                Ok(value) => CommandOutcome::Committed(value),
                Err(e) => CommandOutcome::RolledBack(Rejection::Body(e)),
            }
        }
        Err(e) => CommandOutcome::RolledBack(Rejection::Statement(e)),
    }
}

pub(crate) fn one_i64(rows: &[Row]) -> Result<i64, StatementFailure> {
    match rows {
        [row] => row.try_get::<_, i64>(0).map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}

pub(crate) fn one_text(rows: &[Row]) -> Result<String, StatementFailure> {
    match rows {
        [row] => row.try_get::<_, String>(0).map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}

pub(crate) fn one_void(rows: &[Row]) -> Result<(), StatementFailure> {
    if rows.len() == 1 {
        Ok(())
    } else {
        Err(invalid())
    }
}

pub(crate) async fn read_text(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    contract: &'static SqlContract,
    values: &[&(dyn ToSql + Sync)],
) -> Result<String, StatementFailure> {
    one_text(
        &factory
            .run_admin_read_contract(admin, contract, values)
            .await?,
    )
}
