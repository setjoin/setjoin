//! Admin identity (F01) slice `idv2-upgrade`: the identity v2 upgrade, doctor and
//! diagnostics routes.
use super::{deadline, envelope, invalid, sql, FAMILY};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, ReceiptCommand, StatementFailure};

/// Go's `IdentityRuntimeReadiness`, the facts the preflight and doctor reducers weigh.
#[derive(Clone, Debug)]
pub struct Runtime {
    pub expected_schema: i32,
    pub worker_dsn: bool,
    pub owner_dsn: bool,
    pub direct_dsn: bool,
    pub authserver: bool,
}

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: FAMILY,
        command: name,
    }
}

fn text(rows: &[setjoin_pg::Row]) -> Result<Option<String>, StatementFailure> {
    rows.first()
        .ok_or_else(invalid)?
        .try_get::<_, Option<String>>(0)
        .map_err(|_| invalid())
}

/// `identity_upgrade_status()`.
pub async fn status(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::IDV2_UPGRADE_STATUS, &[])
        .await?;
    Ok(text(&rows)?.unwrap_or_default())
}

/// `identity_upgrade_retirement_check()`.
pub async fn retirement_check(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::IDV2_UPGRADE_RETIREMENT_CHECK, &[])
        .await?;
    Ok(text(&rows)?.unwrap_or_default())
}

/// `identity_upgrade_shadow($1)`.
pub async fn shadow(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    key: &str,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::IDV2_UPGRADE_SHADOW, &[&key])
        .await?;
    Ok(text(&rows)?.unwrap_or_default())
}

/// `identity_upgrade_preflight(...)`, also the backfill `plan` action.
pub async fn preflight(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    rt: &Runtime,
    secrets: bool,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(
            admin,
            &sql::IDV2_UPGRADE_PREFLIGHT,
            &[
                &rt.expected_schema,
                &rt.worker_dsn,
                &rt.owner_dsn,
                &rt.direct_dsn,
                &rt.authserver,
                &secrets,
            ],
        )
        .await?;
    Ok(text(&rows)?.unwrap_or_default())
}

/// `identity_doctor(...)`; `source` is `None` for the whole deployment.
pub async fn doctor(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    rt: &Runtime,
    secrets: bool,
    source: Option<&str>,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(
            admin,
            &sql::IDV2_DOCTOR,
            &[
                &rt.expected_schema,
                &rt.worker_dsn,
                &rt.owner_dsn,
                &rt.direct_dsn,
                &rt.authserver,
                &secrets,
                &source,
            ],
        )
        .await?;
    Ok(text(&rows)?.unwrap_or_default())
}

/// `POST .../upgrade/backfill` with `action: start`.
#[allow(clippy::too_many_arguments)]
pub async fn backfill_start(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    checksum: &str,
    idempotency: &str,
    reason: &str,
    rt: &Runtime,
    secrets: bool,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let actor = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{checksum}:{idempotency}:{reason}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::IDV2_UPGRADE_BACKFILL_START,
            &[
                &actor,
                &checksum,
                &idempotency,
                &reason,
                &rt.expected_schema,
                &rt.worker_dsn,
                &rt.owner_dsn,
                &rt.direct_dsn,
                &rt.authserver,
                &secrets,
            ],
            Some(command("identity_upgrade_backfill_start")),
            |rows| text(&rows),
        )
        .await
}

/// `POST .../upgrade/canary`.
#[allow(clippy::too_many_arguments)]
pub async fn canary(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    key: &str,
    generation: i64,
    enabled: bool,
    users: &Vec<i64>,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let actor = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{key}:{generation}:{enabled}:{users:?}:{reason}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::IDV2_UPGRADE_CANARY,
            &[&actor, &key, &generation, &enabled, users, &reason],
            Some(command("identity_upgrade_canary")),
            |rows| text(&rows),
        )
        .await
}

/// `POST .../upgrade/rollback`.
pub async fn rollback(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let actor = user.user().get();
    let env = envelope(user.user(), user.generation(), operation, reason);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::IDV2_UPGRADE_ROLLBACK,
            &[&actor, &reason],
            Some(command("identity_upgrade_rollback")),
            |rows| text(&rows),
        )
        .await
}

/// `POST .../diagnostics`: `identity_job_create(..., 'diagnostics', ...)`.
#[allow(clippy::too_many_arguments)]
pub async fn diagnostic_create(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    idempotency: &str,
    source: Option<&str>,
    transition: Option<&str>,
    request: &str,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{idempotency}:{source:?}:{transition:?}:{request}:{reason}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::IDV2_DIAGNOSTIC_CREATE,
            &[&idempotency, &source, &transition, &request, &reason],
            Some(command("identity_job_create")),
            |rows, _audited| text(&rows),
        )
        .await
}

/// `DELETE .../diagnostics/{id}`: `identity_diagnostic_delete`.
pub async fn diagnostic_delete(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    job: &str,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{job}:{reason}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::IDV2_DIAGNOSTIC_DELETE,
            &[&job, &reason],
            Some(command("identity_diagnostic_delete")),
            |rows, _audited| {
                rows.first()
                    .and_then(|r| r.try_get::<_, bool>(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

/// The sanitized bundle `identity_diagnostic_download` returns.
pub struct Bundle {
    pub artifact: Vec<u8>,
    pub digest: Vec<u8>,
    pub manifest_version: String,
}

/// `GET .../diagnostics/{id}/download`: the reducer audits the download.
pub async fn diagnostic_download(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    job: &str,
    operation: [u8; 16],
) -> CommandOutcome<Option<Bundle>, StatementFailure> {
    let actor = user.user().get();
    let env = envelope(user.user(), user.generation(), operation, job);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::IDV2_DIAGNOSTIC_DOWNLOAD,
            &[&actor, &job],
            Some(command("identity_diagnostic_download")),
            |rows| match rows.first() {
                None => Ok(None),
                Some(row) => Ok(Some(Bundle {
                    artifact: row.try_get(0).map_err(|_| invalid())?,
                    digest: row.try_get(1).map_err(|_| invalid())?,
                    manifest_version: row.try_get(2).map_err(|_| invalid())?,
                })),
            },
        )
        .await
}

/// Go's `RequireReason(perm)`: whether `area` is a reason-required area.
pub async fn reason_required(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    area: &str,
) -> bool {
    factory
        .run_admin_read_contract(admin, &sql::REASON_REQUIRED_AREA, &[&area])
        .await
        .ok()
        .and_then(|r| r.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
        .unwrap_or(false)
}

/// The durable `sensitive_action.reason_missing` row Go writes before its 400.
pub async fn missing_reason(
    factory: &TxFactory,
    user: &UserPrincipal,
    ip: &str,
    perm: &str,
    operation: [u8; 16],
) {
    let actor = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{ip}:{perm}"),
    );
    let _ = factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MISSING_REASON_AUDIT,
            &[&actor, &ip, &perm],
            Some(command("reason_missing")),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get::<_, i64>(0).ok())
                    .map(|_| ())
                    .ok_or_else(invalid)
            },
        )
        .await;
}
