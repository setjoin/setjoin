//! Request-time governed grants; signed permission claims do not replace admin roles.
use super::{invalid, write};
use setjoin_authz::AuthContext;
use setjoin_pg::{ScopedExecutor, StatementFailure, Type};
pub const MAIL_CONSOLE: [&str; 5] = [
    "domains.read",
    "queue.read",
    "reports.read",
    "mail.pipeline",
    "mail.security",
];
pub const PIPELINE: [&str; 1] = ["mail.pipeline"];
pub struct Authority {
    pub permissions: Vec<String>,
    pub domain: Option<i64>,
}
impl Authority {
    pub fn allows(&self, wanted: &[&str]) -> bool {
        wanted
            .iter()
            .any(|v| self.permissions.iter().any(|p| p == v))
    }
}
/// Authority after a failed live lookup. Owner-approved security fix 2026-11-05
/// (#484): frozen Go kept the verified JWT's signed grants here, so a request kept
/// authority the lookup could not confirm. Now no grant survives.
pub fn lookup_failed(a: &AuthContext) -> Authority {
    if setjoin_contracts::mutants::on("authority-lookup-keeps-signed-grants") {
        return Authority {
            permissions: a.signed_permissions().to_vec(),
            domain: a.signed_domain_scope(),
        };
    }
    Authority {
        permissions: Vec::new(),
        domain: None,
    }
}
pub async fn resolve(
    exec: &ScopedExecutor,
    a: &AuthContext,
) -> Result<Authority, StatementFailure> {
    if !a.signed_admin() {
        return Ok(Authority {
            permissions: a.signed_permissions().to_vec(),
            domain: a.signed_domain_scope(),
        });
    }
    let user = a.user_id();
    let rows = exec
        .read(crate::sql::AUTHORITY_RESOLVE.sql, &[(&user, Type::INT8)])
        .await?;
    let r = rows.first().ok_or_else(invalid)?;
    Ok(Authority {
        permissions: r.get(0),
        domain: r.get(1),
    })
}
pub async fn denied(
    exec: &ScopedExecutor,
    a: &AuthContext,
    path: &str,
    detail: &str,
    op: [u8; 16],
) {
    let before =
        serde_json::json!({"actor":a.email(),"target":path,"missingPermission":detail}).to_string();
    let _ = write(
        exec,
        a,
        op,
        "console.denied",
        crate::sql::AUTHORITY_DENIED_AUDIT.sql,
        &[(&before, Type::TEXT), (&path, Type::TEXT)],
    )
    .await;
}
