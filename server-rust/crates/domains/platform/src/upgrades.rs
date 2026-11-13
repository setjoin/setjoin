//! Platform slice `updates-deploy`, group `upgrades`: the release-first upgrade control
//! plane (`/admin/system/upgrades/*`).
//!
//! Go's `UpgradeHandler` is a thin translator over the `upgrade_*` reducers, which own the
//! authority check (`upgrade_actor_authorized`), the state machine, audit rows and
//! notifications. Every call here passes the verified actor from the sealed auth context
//! (never a request field) and returns the reducer's JSONB verbatim (`::text` is what pgx
//! hands Go's `json.RawMessage`). Writes are one receipted statement each: the reducer is
//! the whole transaction.
use super::{command, deadline, envelope, invalid, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, Param, ScopedExecutor, StatementFailure, Type};

/// The reducer's JSONB as text; `None` is SQL NULL (Go then writes an empty body).
pub type Raw = Option<String>;

/// A refused reducer call projected like `reducererr.WriteClassified`.
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

/// The updater codes BZ242-BZ251 (`reducererr.codeClass`); anything else is unclassified
/// and Go answers its fixed 500.
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
    // A HINT's `remediation` replaces the class text; a malformed HINT is no reducer error.
    let remediation = match e.hint.as_deref().filter(|h| !h.is_empty()) {
        None => class_text.to_owned(),
        Some(hint) => {
            let serde_json::Value::Object(object) = serde_json::from_str(hint).ok()? else {
                return None;
            };
            let found = object
                .get("remediation")
                .or_else(|| {
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

/// A read-only reducer (`STABLE`): console, intent, diagnostics, recovery context.
pub async fn read(
    exec: &ScopedExecutor,
    sql: &str,
    params: &[Param<'_>],
) -> Result<Raw, StatementFailure> {
    text(&exec.read(sql, params).await?)
}

/// A mutating reducer as one receipted statement. `sql` binds the caller's own
/// parameters from `$4` (`$1..$3` are the receipt guard).
pub async fn write(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    name: &'static str,
    sql: &str,
    params: &[Param<'_>],
    operation: [u8; 16],
) -> CommandOutcome<Raw, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command(name),
        &envelope(&auth, operation, name),
        &auth,
        deadline(),
        sql,
        params,
        text,
    )
    .await
}

/// Go's `RequireReason`: whether `area` is a reason-required audit area.
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

/// The durable `sensitive_action.reason_missing` row Go writes before its 400.
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
