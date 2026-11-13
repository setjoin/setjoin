//! Platform slice `terms-remaining`, group `branding`: the brand name and logo
//! (`/admin/branding`), Go's `BrandingHandler`.
//!
//! The two config writes are separate statements whose errors Go ignores. Go binds the new
//! value as a string into a `jsonb` parameter, so it must itself be a JSON document: a bare
//! name such as `Acme` fails server-side and is silently not saved, a quoted `"Acme"` is.
use super::{command, deadline, done, envelope, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

/// `GET /admin/branding`: Go ignores a failed read and answers the empty values.
pub async fn get(exec: &ScopedExecutor) -> String {
    let rows = exec
        .read(
            "SELECT COALESCE((SELECT value #>> '{}' FROM system_config WHERE key = 'brand_name'), 'SetJoin'), \
             COALESCE((SELECT value #>> '{}' FROM system_config WHERE key = 'brand_logo_url'), '')",
            &[],
        )
        .await;
    let (name, logo) = match rows.as_deref() {
        Ok([row]) => (
            row.try_get::<_, String>(0).unwrap_or_default(),
            row.try_get::<_, String>(1).unwrap_or_default(),
        ),
        _ => (String::new(), String::new()),
    };
    done(format!(
        "{{\"logoUrl\":{},\"name\":{}}}",
        s(&logo),
        s(&name)
    ))
}

/// One of the two upserts. The failure is returned for the caller to ignore.
pub async fn set(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    key: &str,
    value: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    let (description, name) = if key == "brand_name" {
        ("Brand display name", "brand_name")
    } else {
        ("Brand logo URL", "brand_logo_url")
    };
    setjoin_pg::run_receipted_command(
        exec,
        command("branding_set"),
        &envelope(&auth, operation, &format!("{name}:{value}")),
        &auth,
        deadline(),
        "INSERT INTO system_config (key, value, description, updated_at) \
         SELECT $4::text, $5::text::jsonb, $6::text, now() \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now() \
         RETURNING key",
        &[
            (&name, Type::TEXT),
            (&value, Type::TEXT),
            (&description, Type::TEXT),
        ],
        |_| Ok(()),
    )
    .await
}
