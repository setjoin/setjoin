//! Platform slice `system-features`, group `jit-defaults`: the global just-in-time role
//! activation defaults (`/admin/system/jit-defaults`), Go's `JITHandler`.
use super::{command, deadline, done, envelope, invalid, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

/// `GET`: the stored defaults, 480 minutes and `false` when unset.
pub async fn get(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::JIT_DEFAULTS_GET, &[])
        .await?;
    let row = rows.first().ok_or_else(invalid)?;
    let minutes: i64 = row.try_get(0).map_err(|_| invalid())?;
    let required: bool = row.try_get(1).map_err(|_| invalid())?;
    Ok(render(minutes, required))
}

fn render(minutes: i64, required: bool) -> String {
    done(format!(
        "{{\"defaultMaxDurationMinutes\":{minutes},\"defaultRequireJustification\":{required}}}"
    ))
}

/// `PUT` after the edge validation (`minutes > 0`).
pub async fn put(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    minutes: i64,
    required: bool,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{minutes}:{required}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::JIT_DEFAULTS_PUT,
            &[&minutes, &required],
            Some(command("jit_defaults_set")),
            |rows| {
                if rows.len() == 1 {
                    Ok(render(minutes, required))
                } else {
                    Err(invalid())
                }
            },
        )
        .await
}
