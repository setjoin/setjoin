//! Platform slice `system-features`, group `auth-methods`: the sign-in method catalogue
//! (`/admin/auth/methods*`), Go's `AuthMethodsHandler`.
use super::{command, deadline, done, envelope, invalid, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

/// `GET`: methods by priority; the stored `config_json` re-marshalled compactly.
pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::AUTH_METHODS_LIST, &[])
        .await?;
    let mut out = Vec::new();
    for row in &rows {
        let (Ok(slug), Ok(name), Ok(enabled), Ok(priority), Ok(config)) = (
            row.try_get::<_, String>(0),
            row.try_get::<_, String>(1),
            row.try_get::<_, bool>(2),
            row.try_get::<_, i64>(3),
            row.try_get::<_, String>(4),
        ) else {
            return Err(invalid());
        };
        out.push(format!(
            "{{\"slug\":{},\"name\":{},\"enabled\":{enabled},\"priority\":{priority},\"config\":{}}}",
            s(&slug),
            s(&name),
            super::config::compact(&config)
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// The fields of a `PUT` that were present; `config` is the raw JSON text.
#[derive(Default)]
pub struct Patch {
    pub enabled: Option<bool>,
    pub priority: Option<i64>,
    pub config: Option<String>,
}

/// `PUT /{slug}` after the edge validation (at least one field). `Committed(false)` is Go's
/// zero rows affected.
pub async fn update(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    slug: &str,
    patch: &Patch,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!(
            "{slug}:{:?}:{:?}:{:?}",
            patch.enabled, patch.priority, patch.config
        ),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::AUTH_METHODS_UPDATE,
            &[&patch.enabled, &patch.priority, &patch.config, &slug],
            Some(command("auth_method_update")),
            |rows| match rows.len() {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(invalid()),
            },
        )
        .await
}
