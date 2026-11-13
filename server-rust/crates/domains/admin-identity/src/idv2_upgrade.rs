//! Admin identity (F01) slice `idv2-upgrade`: the identity v2 upgrade, doctor and
//! diagnostics routes. Every statement is one existing reducer call (Go's `workerPool`
//! call) on the worker executor; the actor comes from the verified context (`$2`),
//! never from the request. Writes carry the foundation receipt.
use super::{deadline, envelope, invalid, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ReceiptCommand, ScopedExecutor, StatementFailure, Type};

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
        family: "F01",
        command: name,
    }
}

/// The jsonb text of a reducer result (`None` is SQL NULL).
fn text(rows: &[setjoin_pg::Row]) -> Result<Option<String>, StatementFailure> {
    rows.first()
        .ok_or_else(invalid)?
        .try_get::<_, Option<String>>(0)
        .map_err(|_| invalid())
}

async fn read_text(
    worker: &ScopedExecutor,
    sql: &str,
    params: &[setjoin_pg::Param<'_>],
) -> Result<String, StatementFailure> {
    let rows = worker.read(sql, params).await?;
    Ok(text(&rows)?.unwrap_or_default())
}

/// `identity_upgrade_status()`.
pub async fn status(worker: &ScopedExecutor) -> Result<String, StatementFailure> {
    read_text(worker, "SELECT identity_upgrade_status()::text", &[]).await
}

/// `identity_upgrade_retirement_check()`.
pub async fn retirement_check(worker: &ScopedExecutor) -> Result<String, StatementFailure> {
    read_text(
        worker,
        "SELECT identity_upgrade_retirement_check()::text",
        &[],
    )
    .await
}

/// `identity_upgrade_shadow($1)`.
pub async fn shadow(worker: &ScopedExecutor, key: &str) -> Result<String, StatementFailure> {
    read_text(
        worker,
        "SELECT identity_upgrade_shadow($1)::text",
        &[(&key, Type::TEXT)],
    )
    .await
}

/// `identity_upgrade_preflight(...)`, also the backfill `plan` action.
pub async fn preflight(
    worker: &ScopedExecutor,
    rt: &Runtime,
    secrets: bool,
) -> Result<String, StatementFailure> {
    read_text(
        worker,
        "SELECT identity_upgrade_preflight($1,$2,$3,$4,$5,$6)::text",
        &[
            (&rt.expected_schema, Type::INT4),
            (&rt.worker_dsn, Type::BOOL),
            (&rt.owner_dsn, Type::BOOL),
            (&rt.direct_dsn, Type::BOOL),
            (&rt.authserver, Type::BOOL),
            (&secrets, Type::BOOL),
        ],
    )
    .await
}

/// `identity_doctor(...)`; `source` is `None` for the whole deployment.
pub async fn doctor(
    worker: &ScopedExecutor,
    rt: &Runtime,
    secrets: bool,
    source: Option<&str>,
) -> Result<String, StatementFailure> {
    read_text(
        worker,
        "SELECT identity_doctor($1,$2,$3,$4,$5,$6,$7)::text",
        &[
            (&rt.expected_schema, Type::INT4),
            (&rt.worker_dsn, Type::BOOL),
            (&rt.owner_dsn, Type::BOOL),
            (&rt.direct_dsn, Type::BOOL),
            (&rt.authserver, Type::BOOL),
            (&secrets, Type::BOOL),
            (&source, Type::TEXT),
        ],
    )
    .await
}

/// `POST .../upgrade/backfill` with `action: start`.
#[allow(clippy::too_many_arguments)]
pub async fn backfill_start(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    checksum: &str,
    idempotency: &str,
    reason: &str,
    rt: &Runtime,
    secrets: bool,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("identity_upgrade_backfill_start"),
        &envelope(&auth, operation, &format!("{checksum}:{idempotency}:{reason}")),
        &auth,
        deadline(),
        "SELECT identity_upgrade_backfill_start($2,$4,$5::text::uuid,$6,$7,$8,$9,$10,$11,$12)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&checksum, Type::TEXT),
            (&idempotency, Type::TEXT),
            (&reason, Type::TEXT),
            (&rt.expected_schema, Type::INT4),
            (&rt.worker_dsn, Type::BOOL),
            (&rt.owner_dsn, Type::BOOL),
            (&rt.direct_dsn, Type::BOOL),
            (&rt.authserver, Type::BOOL),
            (&secrets, Type::BOOL),
        ],
        text,
    )
    .await
}

/// `POST .../upgrade/canary`.
#[allow(clippy::too_many_arguments)]
pub async fn canary(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    key: &str,
    generation: i64,
    enabled: bool,
    users: &Vec<i64>,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("identity_upgrade_canary"),
        &envelope(
            &auth,
            operation,
            &format!("{key}:{generation}:{enabled}:{users:?}:{reason}"),
        ),
        &auth,
        deadline(),
        "SELECT identity_upgrade_canary($2,$4,$5,$6,$7,$8)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&key, Type::TEXT),
            (&generation, Type::INT8),
            (&enabled, Type::BOOL),
            (users, Type::INT8_ARRAY),
            (&reason, Type::TEXT),
        ],
        text,
    )
    .await
}

/// `POST .../upgrade/rollback`.
pub async fn rollback(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("identity_upgrade_rollback"),
        &envelope(&auth, operation, reason),
        &auth,
        deadline(),
        "SELECT identity_upgrade_rollback($2,$4)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&reason, Type::TEXT)],
        text,
    )
    .await
}

/// `POST .../diagnostics`: `identity_job_create(..., 'diagnostics', ...)`.
#[allow(clippy::too_many_arguments)]
pub async fn diagnostic_create(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    idempotency: &str,
    source: Option<&str>,
    transition: Option<&str>,
    request: &str,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("identity_job_create"),
        &envelope(
            &auth,
            operation,
            &format!("{idempotency}:{source:?}:{transition:?}:{request}:{reason}"),
        ),
        &auth,
        deadline(),
        "SELECT identity_job_create($2,'diagnostics',$4::text::uuid,$5,$6::text::uuid,$7::text::jsonb,$8)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&idempotency, Type::TEXT),
            (&source, Type::TEXT),
            (&transition, Type::TEXT),
            (&request, Type::TEXT),
            (&reason, Type::TEXT),
        ],
        text,
    )
    .await
}

/// `DELETE .../diagnostics/{id}`: `identity_diagnostic_delete`.
pub async fn diagnostic_delete(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    job: &str,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("identity_diagnostic_delete"),
        &envelope(&auth, operation, &format!("{job}:{reason}")),
        &auth,
        deadline(),
        "SELECT identity_diagnostic_delete($2,$4::text::uuid,$5) WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&job, Type::TEXT), (&reason, Type::TEXT)],
        |rows| {
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

/// `GET .../diagnostics/{id}/download`: the reducer audits the download, so it is a
/// receipted command; `None` is the reducer returning no row (Go's 404).
pub async fn diagnostic_download(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    job: &str,
    operation: [u8; 16],
) -> CommandOutcome<Option<Bundle>, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("identity_diagnostic_download"),
        &envelope(&auth, operation, job),
        &auth,
        deadline(),
        "SELECT artifact, artifact_sha256, manifest_version FROM identity_diagnostic_download($2,$4::text::uuid) WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&job, Type::TEXT)],
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

/// Go's `RequireReason(perm)`: whether `area` (the permission's first segment) is a
/// reason-required area.
pub async fn reason_required(exec: &ScopedExecutor, area: &str) -> bool {
    exec.read(
        "SELECT $1::text=ANY(reason_required_areas) FROM audit_policy WHERE id=1",
        &[(&area, Type::TEXT)],
    )
    .await
    .ok()
    .and_then(|r| r.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
    .unwrap_or(false)
}

/// The durable `sensitive_action.reason_missing` row (notes name the guarded permission)
/// Go writes before its 400.
pub async fn missing_reason(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    perm: &str,
    operation: [u8; 16],
) {
    let auth = scope(actor);
    let _ = setjoin_pg::run_receipted_command(
        exec,
        command("reason_missing"),
        &envelope(&auth, operation, &format!("{ip}:{perm}")),
        &auth,
        deadline(),
        "SELECT count(*)::bigint FROM (SELECT audit_write($2,'sensitive_action.reason_missing','',NULL,NULL,NULL,NULLIF($5::text,'')::inet,$4::text,'core') \
         WHERE $1::bigint > 0 AND $3::text <> '') w",
        &[(&perm, Type::TEXT), (&ip, Type::TEXT)],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get::<_, i64>(0).ok())
                .map(|_| ())
                .ok_or_else(invalid)
        },
    )
    .await;
}
