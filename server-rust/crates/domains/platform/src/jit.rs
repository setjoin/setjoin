//! Platform slice `system-features`, group `jit-defaults`: the global just-in-time role
//! activation defaults (`/admin/system/jit-defaults`), Go's `JITHandler.GetJITDefaults` and
//! `PutJITDefaults`. Both values live in `system_config`; the write is Go's two
//! `set_system_config` calls in one transaction, one receipted statement.
use super::{command, deadline, done, envelope, invalid, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

/// `GET`: the stored defaults, 480 minutes and `false` when unset.
pub async fn get(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT COALESCE((SELECT (value->>0)::int FROM system_config WHERE key='jit.default_max_minutes'), 480)::bigint, \
             COALESCE((SELECT (value->>0)::bool FROM system_config WHERE key='jit.default_require_justification'), false)",
            &[],
        )
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

/// `PUT` after the edge validation (`minutes > 0`). A value outside int4 fails in the
/// database exactly as pgx refuses to encode it (Go's 500).
pub async fn put(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    minutes: i64,
    required: bool,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("jit_defaults_set"),
        &envelope(&auth, operation, &format!("{minutes}:{required}")),
        &auth,
        deadline(),
        "SELECT (SELECT count(*) FROM public.set_system_config('jit.default_max_minutes', to_jsonb($4::bigint::int))) \
         + (SELECT count(*) FROM public.set_system_config('jit.default_require_justification', to_jsonb($5::bool))) \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[(&minutes, Type::INT8), (&required, Type::BOOL)],
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
