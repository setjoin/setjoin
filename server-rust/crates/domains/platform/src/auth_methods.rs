//! Platform slice `system-features`, group `auth-methods`: the sign-in method catalogue
//! (`/admin/auth/methods*`), Go's `AuthMethodsHandler`. Go also rebuilds its in-process auth
//! chain after an update; the table's own trigger raises `config_changed`, which every chain
//! (Go's, and the Rust one from #333) reloads on.
use super::{command, deadline, done, envelope, invalid, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

/// `GET`: methods by priority; the stored `config_json` re-marshalled compactly.
pub async fn list(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT slug, name, enabled, priority::bigint, config_json::text FROM auth_methods ORDER BY priority ASC",
            &[],
        )
        .await?;
    let mut out = Vec::new();
    for row in &rows {
        // A failed `Scan` closes pgx's rows with that error, which Go then reports as a 500.
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    slug: &str,
    patch: &Patch,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    let mut sets: Vec<String> = Vec::new();
    let mut params: Vec<setjoin_pg::Param<'_>> = Vec::new();
    let mut next = 4;
    if let Some(enabled) = &patch.enabled {
        sets.push(format!("enabled = ${next}::bool"));
        params.push((enabled, Type::BOOL));
        next += 1;
    }
    if let Some(priority) = &patch.priority {
        // pgx refuses an int outside int4 before sending it; the cast fails the same way.
        sets.push(format!("priority = ${next}::bigint::int"));
        params.push((priority, Type::INT8));
        next += 1;
    }
    if let Some(config) = &patch.config {
        sets.push(format!("config_json = ${next}::text::jsonb"));
        params.push((config, Type::TEXT));
        next += 1;
    }
    params.push((&slug, Type::TEXT));
    let sql = format!(
        "UPDATE auth_methods SET {} WHERE slug = ${next}::text AND $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING slug",
        sets.join(", ")
    );
    setjoin_pg::run_receipted_command(
        exec,
        command("auth_method_update"),
        &envelope(
            &auth,
            operation,
            &format!(
                "{slug}:{:?}:{:?}:{:?}",
                patch.enabled, patch.priority, patch.config
            ),
        ),
        &auth,
        deadline(),
        &sql,
        &params,
        |rows| match rows.len() {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid()),
        },
    )
    .await
}
