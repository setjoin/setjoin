//! Platform slice `terms-remaining`, group `apps`: the curated-application console
//! (`/admin/apps*`), the application half of Go's `OfficeHandler`.
//!
//! Every route is one existing reducer call (`office_app_admin_list`,
//! `office_app_operation_request`, `office_app_operation_recover_request`) that owns the
//! authorization, audit row and notification in its own transaction, so Rust only binds
//! the verified user and the decoded arguments. Replies are the reducer's jsonb text.
use super::{command, deadline, envelope, invalid, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

fn text(rows: &[setjoin_pg::Row]) -> Result<String, StatementFailure> {
    rows.first()
        .filter(|_| rows.len() == 1)
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .ok_or_else(invalid)
}

/// `GET /admin/apps`.
pub async fn list(exec: &ScopedExecutor, actor: &AuthContext) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read(
            "SELECT office_app_admin_list($1)::text",
            &[(&user, Type::INT8)],
        )
        .await?;
    text(&rows)
}

/// `POST /admin/apps/{appId}/operations`.
#[allow(clippy::too_many_arguments)]
pub async fn request(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    kind: &str,
    provider: &str,
    generation: i64,
    key: &str,
    body: &str,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("office_app_operation_request"),
        &envelope(&auth, operation, &format!("{kind}:{provider}:{key}")),
        &auth,
        deadline(),
        "SELECT office_app_operation_request($2, $4, $5, $6, $7::text::uuid, $8::text::jsonb, $9)::text \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&kind, Type::TEXT),
            (&provider, Type::TEXT),
            (&generation, Type::INT8),
            (&key, Type::TEXT),
            (&body, Type::TEXT),
            (&reason, Type::TEXT),
        ],
        text,
    )
    .await
}

/// `POST /admin/apps/{appId}/operations/{operationId}/recover`.
pub async fn recover(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    operation_id: &str,
    generation: i64,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("office_app_operation_recover_request"),
        &envelope(&auth, operation, &format!("recover:{operation_id}")),
        &auth,
        deadline(),
        "SELECT office_app_operation_recover_request($2, $4::text::uuid, $5, $6)::text \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&operation_id, Type::TEXT),
            (&generation, Type::INT8),
            (&reason, Type::TEXT),
        ],
        text,
    )
    .await
}

/// Whether `audit_policy` demands a reason for the `apps` area (Go fails open on a read
/// error).
pub async fn reason_required(exec: &ScopedExecutor) -> bool {
    exec.read(
        "SELECT 'apps' = ANY(reason_required_areas) FROM audit_policy WHERE id=1",
        &[],
    )
    .await
    .ok()
    .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
    .unwrap_or(false)
}

/// The durable `sensitive_action.reason_missing` row of Go's required-reason middleware.
pub async fn reason_missing(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("sensitive_action.reason_missing"),
        &envelope(&auth, operation, "apps.manage"),
        &auth,
        deadline(),
        "SELECT audit_write($2,'sensitive_action.reason_missing','',NULL,NULL,NULL,$4::text::inet,'apps.manage','core') \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&ip, Type::TEXT)],
        |_| Ok(()),
    )
    .await
}

/// Google's `uuid.Parse` forms, normalized to the canonical lower-case text.
pub fn uuid(raw: &str) -> Option<String> {
    if !raw.is_ascii() {
        return None;
    }
    let raw = if raw.len() == 45 && raw[..9].eq_ignore_ascii_case("urn:uuid:") {
        &raw[9..]
    } else if raw.len() == 38 {
        &raw[1..37]
    } else {
        raw
    };
    let hex = if raw.len() == 36 {
        if [8, 13, 18, 23].iter().any(|&i| raw.as_bytes()[i] != b'-') {
            return None;
        }
        raw.replace('-', "")
    } else if raw.len() == 32 {
        raw.to_owned()
    } else {
        return None;
    };
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let h = hex.to_ascii_lowercase();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}
