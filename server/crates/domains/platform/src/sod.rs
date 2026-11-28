//! Platform slice `system-features`, group `sod-mode`: the 等保三级 separation-of-duties
//! switch (`/admin/dengbao/sod-mode`), Go's `SodModeHandler`.
use super::{command, deadline, done, envelope, invalid, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::{CommandOutcome, StatementFailure};

fn violation(kind: &str, subject: &str, detail: &str) -> String {
    format!(
        "{{\"violationType\":{},\"subject\":{},\"detail\":{}}}",
        s(kind),
        s(subject),
        s(detail)
    )
}

/// `GET`: `{"enabled":..,"violations":[..]}`.
pub async fn get(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::SOD_MODE_GET, &[])
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

pub enum Set {
    Enabled(bool),
    Violations(String),
}

/// `PUT` (the caller decoded `enabled`).
pub async fn put(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    enabled: bool,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Set, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{enabled}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::SOD_MODE_SET,
            &[&enabled, &ip],
            Some(command("sod_mode_set")),
            |rows, _audited| {
                let text: String = rows
                    .first()
                    .filter(|_| rows.len() == 1)
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)?;
                let doc: serde_json::Value =
                    serde_json::from_str(&text).map_err(|_| invalid())?;
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

pub fn enabled_body(enabled: bool) -> String {
    done(format!("{{\"enabled\":{enabled}}}"))
}
