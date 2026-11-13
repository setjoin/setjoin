//! Shared shapes of the `remaining` slice's writes: one receipted command calling a reducer
//! Go calls, with the verified actor as `$2` and the operation text as `$3`. Parameters the
//! caller supplies start at `$4`. Every statement ends in the `WHERE $1 > 0 AND $3 <> ''`
//! guard so the helper-supplied scope and operation id are always consumed.
use super::{command, deadline, envelope, invalid, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, Param, Row, ScopedExecutor, StatementFailure};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run<T>(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    name: &'static str,
    operation: [u8; 16],
    payload: &str,
    sql: &str,
    params: &[Param<'_>],
    decode: impl FnOnce(&[Row]) -> Result<T, StatementFailure>,
) -> CommandOutcome<T, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command(name),
        &envelope(&auth, operation, payload),
        &auth,
        deadline(),
        sql,
        params,
        decode,
    )
    .await
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

/// A void reducer wrapped as `SELECT count(*) FROM (SELECT f(..) WHERE guard) w` must count one row.
pub(crate) fn counted(rows: &[Row]) -> Result<(), StatementFailure> {
    match rows {
        [row] if row.try_get::<_, i64>(0).is_ok_and(|n| n == 1) => Ok(()),
        _ => Err(invalid()),
    }
}

/// A read whose single row has one text column.
pub(crate) async fn read_text(
    exec: &ScopedExecutor,
    sql: &str,
    params: &[Param<'_>],
) -> Result<String, StatementFailure> {
    one_text(&exec.read(sql, params).await?)
}
