//! Slice `profile` (#309): Go's `ProfileHandler.Update` (`POST /user/profile`) and
//! `QuotaHandler.Get` (`GET /user/quota`).
//!
//! The profile write is Go's whole transaction as one statement (one `UPDATE users` with
//! no audit, state bump or notify), so it is one receipted Rust statement with the verified
//! user in its WHERE. The quota read sums only the verified user's own mailboxes; Go scans
//! the numeric sums into `int64`, so a sum beyond `int64` is its 500.
use super::{command, deadline, done, envelope, invalid, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

/// Go's `len([]rune(name)) > 255` bound on the trimmed name.
pub const MAX_NAME_RUNES: usize = 255;

/// Go's `strings.TrimSpace`: Unicode White_Space is exactly `unicode.IsSpace`.
pub fn trim(name: &str) -> &str {
    name.trim()
}

/// `{"display_name": name}` (`WriteJSON` of a `map[string]string`).
pub fn updated_body(name: &str) -> String {
    done(format!("{{\"display_name\":{}}}", s(name)))
}

/// `UPDATE users SET display_name = $1, updated_at = now() WHERE id = $2`.
pub async fn profile_update(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    name: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("profile.update"),
        &envelope(&auth, operation, name),
        &auth,
        deadline(),
        "WITH written AS (UPDATE users SET display_name = $4::text, updated_at = now() WHERE id = $2::bigint AND $1::bigint > 0 AND $3::text <> '' RETURNING 1) \
         SELECT count(*)::bigint FROM written",
        &[(&name, Type::TEXT)],
        |rows| rows.first().map(|_| ()).ok_or_else(invalid),
    )
    .await
}

/// `{"quotaBytes": N, "usedBytes": N}` of the verified user's mailboxes (`None` is Go's 500
/// `database error`: a failed read or a sum Go's `int64` scan rejects).
pub async fn quota_get(exec: &ScopedExecutor, actor: &AuthContext) -> Option<String> {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT COALESCE(SUM(used_bytes), 0)::text, COALESCE(SUM(quota_bytes), 0)::text \
             FROM mailboxes WHERE user_id = $1",
            &[(&user, Type::INT8)],
        )
        .await
        .ok()?;
    let row = rows.first()?;
    let used: i64 = row.try_get::<_, String>(0).ok()?.parse().ok()?;
    let quota: i64 = row.try_get::<_, String>(1).ok()?.parse().ok()?;
    Some(done(format!(
        "{{\"quotaBytes\":{quota},\"usedBytes\":{used}}}"
    )))
}
