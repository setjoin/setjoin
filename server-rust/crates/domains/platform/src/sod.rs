//! Platform slice `system-features`, group `sod-mode`: the 等保三级 separation-of-duties
//! switch (`/admin/dengbao/sod-mode`), Go's `SodModeHandler`.
//!
//! The read renders the toggle and `admin_sod_precheck()` from one statement. The write is
//! Go's precheck, flip and audit transaction, mirrored by the reducer
//! `rust_platform_sod_mode_set`.
use super::{command, deadline, done, envelope, invalid, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

/// Go's `sodViolation`, in its field order.
fn violation(kind: &str, subject: &str, detail: &str) -> String {
    format!(
        "{{\"violationType\":{},\"subject\":{},\"detail\":{}}}",
        s(kind),
        s(subject),
        s(detail)
    )
}

/// `GET`: `{"enabled":..,"violations":[..]}`.
pub async fn get(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'dengbao.sod_mode'), false), \
             v.violation_type, v.subject, v.detail FROM (SELECT 1) one LEFT JOIN admin_sod_precheck() v ON true",
            &[],
        )
        .await?;
    let mut enabled = false;
    let mut out = Vec::new();
    for row in &rows {
        enabled = row.try_get(0).map_err(|_| invalid())?;
        let kind: Option<String> = row.try_get(1).map_err(|_| invalid())?;
        if let Some(kind) = kind {
            let subject: String = row.try_get(2).map_err(|_| invalid())?;
            let detail: String = row.try_get(3).map_err(|_| invalid())?;
            out.push(violation(&kind, &subject, &detail));
        }
    }
    Ok(done(format!(
        "{{\"enabled\":{enabled},\"violations\":[{}]}}",
        out.join(",")
    )))
}

/// What the reducer decided.
pub enum Set {
    Enabled(bool),
    /// Go's 409 body: the precheck found violations and nothing was written.
    Violations(String),
}

/// `PUT` (the caller decoded `enabled`).
pub async fn put(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    enabled: bool,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Set, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("sod_mode_set"),
        &envelope(&auth, operation, &format!("{enabled}")),
        &auth,
        deadline(),
        "SELECT public.rust_platform_sod_mode_set($2::bigint, $4::bool, $5::text)::text \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[(&enabled, Type::BOOL), (&ip, Type::TEXT)],
        |rows| {
            let text: String = rows
                .first()
                .filter(|_| rows.len() == 1)
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid)?;
            let doc: serde_json::Value = serde_json::from_str(&text).map_err(|_| invalid())?;
            if let Some(list) = doc.get("violations").and_then(|v| v.as_array()) {
                let items: Vec<String> = list
                    .iter()
                    .map(|v| {
                        violation(
                            v["violationType"].as_str().unwrap_or(""),
                            v["subject"].as_str().unwrap_or(""),
                            v["detail"].as_str().unwrap_or(""),
                        )
                    })
                    .collect();
                return Ok(Set::Violations(done(format!(
                    "{{\"error\":{},\"violations\":[{}]}}",
                    s("等保三级 SoD mode cannot be enabled: unresolved separation-of-duties violations"),
                    items.join(",")
                ))));
            }
            Ok(Set::Enabled(doc["enabled"].as_bool().ok_or_else(invalid)?))
        },
    )
    .await
}

/// The 200 body of a committed write.
pub fn enabled_body(enabled: bool) -> String {
    done(format!("{{\"enabled\":{enabled}}}"))
}
