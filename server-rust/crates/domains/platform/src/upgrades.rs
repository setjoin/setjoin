//! Platform slice `updates-deploy`, group `upgrades`: the release-first upgrade control
//! plane (`/admin/system/upgrades/*`).
use super::{command, deadline, envelope, invalid, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

pub type Raw = Option<String>;

pub struct Refusal {
    pub status: u16,
    pub detail: &'static str,
    pub code: String,
    pub remediation: String,
}

fn class_remediation(status: u16) -> &'static str {
    match status {
        409 => "Refresh current state, resolve the conflict, and retry.",
        403 => "Complete the required authorization, approval, or recovery step before retrying.",
        400 => "Correct the request fields and retry.",
        _ => "Correct the requested operation using the documented runbook and retry.",
    }
}

pub fn classify(e: &StatementFailure) -> Option<Refusal> {
    let code = e.sqlstate.as_deref()?;
    let (status, detail) = match code {
        "BZ242" | "BZ243" | "BZ246" | "BZ247" | "BZ248" | "BZ249" => (409, "conflict"),
        "BZ244" | "BZ250" => (403, "forbidden"),
        "BZ245" => (422, "unprocessable"),
        "BZ251" => (400, "invalidArguments"),
        _ => return None,
    };
    let class_text = class_remediation(status);
    let remediation = match e.hint.as_deref().filter(|h| !h.is_empty()) {
        None => class_text.to_owned(),
        Some(hint) => {
            let serde_json::Value::Object(object) = serde_json::from_str(hint).ok()? else {
                return None;
            };
            let found = object.get("remediation").or_else(|| {
                object
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("remediation"))
                    .map(|(_, v)| v)
            });
            match found {
                Some(serde_json::Value::String(text)) if !text.is_empty() => text.clone(),
                None | Some(serde_json::Value::Null) | Some(serde_json::Value::String(_)) => {
                    class_text.to_owned()
                }
                Some(_) => return None,
            }
        }
    };
    Some(Refusal {
        status,
        detail,
        code: code.to_owned(),
        remediation,
    })
}

fn text(rows: &[setjoin_pg::Row]) -> Result<Raw, StatementFailure> {
    match rows {
        [row] => row.try_get::<_, Option<String>>(0).map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}

pub async fn console_read(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<Raw, StatementFailure> {
    let actor = admin.actor().get();
    text(
        &factory
            .run_admin_read_contract(admin, &sql::UPGRADE_CONSOLE_READ, &[&actor])
            .await?,
    )
}

pub async fn recovery_context_read(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<Raw, StatementFailure> {
    let actor = admin.actor().get();
    text(
        &factory
            .run_admin_read_contract(admin, &sql::UPGRADE_RECOVERY_CONTEXT_READ, &[&actor])
            .await?,
    )
}

pub async fn intent_read(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    intent: i64,
) -> Result<Raw, StatementFailure> {
    text(
        &factory
            .run_admin_read_contract(admin, &sql::UPGRADE_INTENT_READ, &[&intent])
            .await?,
    )
}

pub async fn intent_diagnostics(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    intent: i64,
) -> Result<Raw, StatementFailure> {
    let actor = admin.actor().get();
    text(
        &factory
            .run_admin_read_contract(admin, &sql::UPGRADE_INTENT_DIAGNOSTICS, &[&actor, &intent])
            .await?,
    )
}

pub async fn intent_preview(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    release: &str,
    reason: &str,
    schedule: Option<i64>,
) -> Result<Raw, StatementFailure> {
    let actor = admin.actor().get();
    text(
        &factory
            .run_admin_read_contract(
                admin,
                &sql::UPGRADE_INTENT_PREVIEW,
                &[&actor, &release, &reason, &schedule],
            )
            .await?,
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn challenge_complete(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    challenge: &str,
    session: &[u8],
    factor: &[u8],
    amr: &[String],
    acr: &str,
    operation: [u8; 16],
) -> CommandOutcome<Raw, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        "upgrade_challenge_complete",
    );
    let amr_vec = amr.to_vec();
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::UPGRADE_CHALLENGE_COMPLETE,
            &[&challenge, &session, &factor, &amr_vec, &acr],
            Some(command("upgrade_challenge_complete")),
            |rows, _audited| text(&rows),
        )
        .await
}

#[allow(clippy::too_many_arguments)]
pub async fn challenge_issue(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    release: &str,
    reason: &str,
    schedule: Option<i64>,
    digest: &str,
    key: &str,
    operation: [u8; 16],
) -> CommandOutcome<Raw, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        "upgrade_challenge_issue",
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::UPGRADE_CHALLENGE_ISSUE,
            &[&release, &reason, &schedule, &digest, &key],
            Some(command("upgrade_challenge_issue")),
            |rows, _audited| text(&rows),
        )
        .await
}

#[allow(clippy::too_many_arguments)]
pub async fn intent_request(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    release: &str,
    reason: &str,
    schedule: Option<i64>,
    digest: &str,
    elevation: &str,
    key: &str,
    operation: [u8; 16],
) -> CommandOutcome<Raw, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        "upgrade_intent_request",
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::UPGRADE_INTENT_REQUEST,
            &[&release, &reason, &schedule, &digest, &elevation, &key],
            Some(command("upgrade_intent_request")),
            |rows, _audited| text(&rows),
        )
        .await
}

pub async fn intent_cancel(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    intent: i64,
    generation: i64,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<Raw, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        "upgrade_intent_cancel",
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::UPGRADE_INTENT_CANCEL,
            &[&intent, &generation, &reason],
            Some(command("upgrade_intent_cancel")),
            |rows, _audited| text(&rows),
        )
        .await
}

#[allow(clippy::too_many_arguments)]
pub async fn recovery_set_record(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    set_id: &str,
    timeline: &str,
    source: &str,
    schema: i32,
    manifest: &str,
    checks: &str,
    created: i64,
    expires: i64,
    operation: [u8; 16],
) -> CommandOutcome<Raw, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        "upgrade_recovery_set_record",
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::UPGRADE_RECOVERY_SET_RECORD,
            &[
                &set_id, &timeline, &source, &schema, &manifest, &checks, &created, &expires,
            ],
            Some(command("upgrade_recovery_set_record")),
            |rows, _audited| text(&rows),
        )
        .await
}

#[allow(clippy::too_many_arguments)]
pub async fn restore_proof_record(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    proof: &str,
    set_id: &str,
    target: &str,
    checks: &str,
    proved: i64,
    operation: [u8; 16],
) -> CommandOutcome<Raw, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        "upgrade_restore_proof_record",
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::UPGRADE_RESTORE_PROOF_RECORD,
            &[&proof, &set_id, &target, &checks, &proved],
            Some(command("upgrade_restore_proof_record")),
            |rows, _audited| text(&rows),
        )
        .await
}

pub async fn reason_required(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    area: &str,
) -> bool {
    crate::reason_required(factory, admin, area).await
}

pub async fn missing_reason(
    factory: &TxFactory,
    user: &UserPrincipal,
    ip: &str,
    perm: &str,
    operation: [u8; 16],
) {
    crate::missing_reason(factory, user, ip, perm, operation).await;
}
