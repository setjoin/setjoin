//! Request-time governed grants; signed permission claims do not replace admin roles.
use super::{deadline, invalid, project_text0, user_envelope};
use setjoin_authz::{
    principals::{TxFactory, UserPrincipal},
    AuthContext,
};
use setjoin_pg::{ReceiptCommand, StatementFailure};

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

    pub fn first_matching<'a>(&self, wanted: &[&'a str]) -> Option<&'a str> {
        wanted
            .iter()
            .copied()
            .find(|v| self.permissions.iter().any(|p| p == v))
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
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    a: &AuthContext,
) -> Result<Authority, StatementFailure> {
    if !a.signed_admin() {
        return Ok(Authority {
            permissions: a.signed_permissions().to_vec(),
            domain: a.signed_domain_scope(),
        });
    }
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::AUTHORITY_RESOLVE, &[&uid])
        .await?;
    let r = rows.first().ok_or_else(invalid)?;
    Ok(Authority {
        permissions: r.get(0),
        domain: r.get(1),
    })
}

pub async fn denied(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    email: &str,
    path: &str,
    detail: &str,
    op: [u8; 16],
) {
    let before =
        serde_json::json!({"actor":email,"target":path,"missingPermission":detail}).to_string();
    let envelope = user_envelope(user, op, "console.denied", &format!("{before}:{path}"));
    let _ = tx_factory
        .run_user_write_contract_pipelined(
            user,
            &envelope,
            deadline(),
            &crate::sql::AUTHORITY_DENIED_AUDIT,
            &[&before, &path],
            Some(ReceiptCommand {
                family: "F09",
                command: "console.denied",
            }),
            project_text0,
        )
        .await;
}
