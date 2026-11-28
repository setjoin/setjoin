//! Platform slice `terms-remaining`, group `branding`: the brand name and logo
//! (`/admin/branding`), Go's `BrandingHandler`.
use super::{command, deadline, done, envelope, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

/// `GET /admin/branding`: Go ignores a failed read and answers the empty values.
pub async fn get(factory: &TxFactory, admin: &AdminPermissionProof) -> String {
    let rows = factory
        .run_admin_read_contract(admin, &sql::BRANDING_GET, &[])
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
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    key: &str,
    value: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let (description, name) = if key == "brand_name" {
        ("Brand display name", "brand_name")
    } else {
        ("Brand logo URL", "brand_logo_url")
    };
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{name}:{value}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::BRANDING_SET,
            &[&name, &value, &description],
            Some(command("branding_set")),
            |_| Ok(()),
        )
        .await
}
