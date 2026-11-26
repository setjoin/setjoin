//! Platform slice `terms-remaining`, group `apps`: the curated-application console
//! (`/admin/apps*`), the application half of Go's `OfficeHandler`.
use super::{command, deadline, envelope, invalid, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

fn text(rows: &[setjoin_pg::Row]) -> Result<String, StatementFailure> {
    rows.first()
        .filter(|_| rows.len() == 1)
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .ok_or_else(invalid)
}

/// `GET /admin/apps`.
pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let user = admin.actor().get();
    let rows = factory
        .run_admin_read_contract(admin, &sql::APPS_LIST, &[&user])
        .await?;
    text(&rows)
}

/// `POST /admin/apps/{appId}/operations`.
#[allow(clippy::too_many_arguments)]
pub async fn request(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    kind: &str,
    provider: &str,
    generation: i64,
    key: &str,
    body: &str,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{kind}:{provider}:{key}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::APPS_OPERATION_REQUEST,
            &[&kind, &provider, &generation, &key, &body, &reason],
            Some(command("office_app_operation_request")),
            |rows, _audited| text(&rows),
        )
        .await
}

/// `POST /admin/apps/{appId}/operations/{operationId}/recover`.
pub async fn recover(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    operation_id: &str,
    generation: i64,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("recover:{operation_id}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::APPS_OPERATION_RECOVER,
            &[&operation_id, &generation, &reason],
            Some(command("office_app_operation_recover_request")),
            |rows, _audited| text(&rows),
        )
        .await
}

/// Whether `audit_policy` demands a reason for the `apps` area.
pub async fn reason_required(factory: &TxFactory, admin: &AdminPermissionProof) -> bool {
    crate::reason_required(factory, admin, "apps").await
}

/// The durable `sensitive_action.reason_missing` row of Go's required-reason middleware.
pub async fn reason_missing(
    factory: &TxFactory,
    user: &UserPrincipal,
    ip: &str,
    operation: [u8; 16],
) {
    crate::missing_reason(factory, user, ip, "apps.manage", operation).await;
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
