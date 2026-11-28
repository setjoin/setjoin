//! Slice `profile` (#309): `POST /user/profile` and `GET /user/quota`.
use super::{command, deadline, done, invalid, s, user_envelope};
use setjoin_authz::principals::{TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

pub const MAX_NAME_RUNES: usize = 255;

pub fn trim(name: &str) -> &str {
    name.trim()
}

pub fn updated_body(name: &str) -> String {
    done(format!("{{\"display_name\":{}}}", s(name)))
}

pub async fn profile_update(
    factory: &TxFactory,
    user: &UserPrincipal,
    name: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    let env = user_envelope(user, operation, name);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::PROFILE_UPDATE,
            &[&uid, &name],
            Some(command("profile.update")),
            |rows| rows.first().map(|_| ()).ok_or_else(invalid),
        )
        .await
}

pub async fn quota_get(factory: &TxFactory, user: &UserPrincipal) -> Option<String> {
    let uid = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &crate::sql::QUOTA_GET, &[&uid])
        .await
        .ok()?;
    let row = rows.first()?;
    let used: i64 = row.try_get::<_, String>(0).ok()?.parse().ok()?;
    let quota: i64 = row.try_get::<_, String>(1).ok()?.parse().ok()?;
    Some(done(format!(
        "{{\"quotaBytes\":{quota},\"usedBytes\":{used}}}"
    )))
}
