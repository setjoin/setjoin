//! Conditional access (F03): policies, named locations, authentication strengths, templates,
//! simulation and import/export routes, and the policy document model. Foundation
//! dependencies only (`authz`, `contracts`, `db`, `pg`) and no other family crate. See DOX.md
//! for the two-slice map and per-slice contracts.
//!
//! The actor comes from the sealed auth context; path ids, query strings and bodies name
//! targets but never grant authority. Permissions and domain scope are resolved live per
//! request, as Go's auth chain does for admin tokens. Responses render in `encoding/json`
//! field order (structs) or sorted key order (maps), HTML-escaped, with the trailing newline
//! of Go's `Encoder`.
#![forbid(unsafe_code)]
mod cmd;
pub mod console;
pub mod exchange;
pub mod locations;
pub mod policies;
pub mod policy;
pub mod risk;
pub mod strengths;
use serde_json::json;
use setjoin_authz::AuthContext;
use setjoin_contracts::{
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, MailboxId, OperationId},
};
use setjoin_pg::{
    CommandOutcome, MailboxAuthContext, ReceiptCommand, Row, ScopedExecutor, StatementFailure, Type,
};
use sha2::{Digest as _, Sha256};

pub const FAMILY: &str = "F03";

/// `requireCAPolicyRead` (`RequirePermAudited(access.policy_read)`).
pub const POLICY_READ: [&str; 1] = ["access.policy_read"];
/// `requireCAPolicyWrite` (`RequirePermAudited(access.policy_write)`).
pub const POLICY_WRITE: [&str; 1] = ["access.policy_write"];
/// Go's `DomainGlobalOnlyScopes`: refused to any domain-scoped principal.
const GLOBAL_ONLY: [&str; 2] = ["audit.read", "audit.export"];

pub fn scope(actor: &AuthContext) -> MailboxAuthContext {
    MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor.user_id()).expect("verified actor"),
        MailboxId::new(actor.mailbox_id()).expect("verified mailbox"),
        Generation(1),
    )
}
pub(crate) fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid conditional access result".into(),
    }
}

/// Live request-time projection of governed grants for a verified admin.
/// Non-admin tokens keep their signed claims, as Go's resolver skips them.
pub struct Authority {
    permissions: Vec<String>,
    domain_scope: i64,
}
impl Authority {
    pub fn allows_any(&self, wanted: &[&str]) -> bool {
        wanted
            .iter()
            .any(|w| self.permissions.iter().any(|p| p == w))
    }
    /// 0 is global, as Go's `DomainScopeFromContext`.
    pub fn domain_scope(&self) -> i64 {
        self.domain_scope
    }
    /// Go's `denyDomainScopedForGlobalOnly`: true when the surface names an
    /// organization-wide-only permission and the principal is domain scoped.
    pub fn refused_for_scope(&self, required: &[&str]) -> bool {
        self.domain_scope > 0 && required.iter().any(|p| GLOBAL_ONLY.contains(p))
    }
}
pub async fn authority(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<Authority, StatementFailure> {
    if !actor.signed_admin() {
        return Ok(Authority {
            permissions: actor.signed_permissions().to_vec(),
            domain_scope: actor.signed_domain_scope().unwrap_or(0),
        });
    }
    let user = actor.user_id();
    let rows = exec
        .read(
            "SELECT COALESCE((SELECT array_agg(DISTINCT p) FROM public.admin_role_assignments ra \
             JOIN public.admin_role_groups rg ON rg.id=ra.role_group_id CROSS JOIN LATERAL unnest(rg.permissions) p \
             WHERE ra.user_id=$1 AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
             AND public.admin_assignment_active(ra.eligible,ra.activated_until)),'{}'::text[]), \
             (SELECT MIN(COALESCE(ra.domain_override,rg.domain_scope)) FROM public.admin_role_assignments ra \
             JOIN public.admin_role_groups rg ON rg.id=ra.role_group_id \
             WHERE ra.user_id=$1 AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
             AND public.admin_assignment_active(ra.eligible,ra.activated_until))",
            &[(&user, Type::INT8)],
        )
        .await?;
    let row = rows.first().ok_or_else(invalid)?;
    Ok(Authority {
        permissions: row.get(0),
        domain_scope: row.get::<_, Option<i64>>(1).unwrap_or(0),
    })
}

pub(crate) fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}
pub(crate) fn envelope(
    auth: &MailboxAuthContext,
    operation: [u8; 16],
    payload: &str,
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(payload.as_bytes()).into()),
        command: (),
    }
}
pub(crate) fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: FAMILY,
        command: name,
    }
}

/// Go writes the same durable console-denial audit row, best effort.
pub async fn console_denied(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    path: &str,
    permission: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let before =
        json!({"actor":actor.email(),"target":path,"missingPermission":permission}).to_string();
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("console.denied"),
        &envelope(&auth, operation, &before),
        &auth,
        deadline(),
        "SELECT audit_write(NULL,'console.denied','console',NULL,$4::text::jsonb,NULL,NULL,$5,'core') WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[(&before, Type::TEXT), (&path, Type::TEXT)],
        |rows| {
            if rows.len() == 1 {
                Ok(())
            } else {
                Err(invalid())
            }
        },
    )
    .await
}

/// encoding/json HTML escaping of an already rendered document.
pub fn go_escape(text: &str) -> String {
    text.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}
pub fn s(text: &str) -> String {
    serde_json::to_string(text).expect("string")
}
/// Go's `Encoder` output: escaped, with the trailing newline.
pub fn done(text: String) -> String {
    go_escape(&text) + "\n"
}
/// RFC 3339 with Go's trimmed fractional seconds (`time.Time` JSON), UTC.
#[allow(dead_code)]
pub(crate) fn nano(column: &str) -> String {
    format!(
        "to_char({column} AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS') || CASE WHEN date_part('microseconds', {column} AT TIME ZONE 'UTC')::bigint % 1000000 = 0 THEN '' ELSE regexp_replace(to_char({column} AT TIME ZONE 'UTC','.US'),'0+$','') END || 'Z'"
    )
}
#[allow(dead_code)]
pub(crate) fn first_i64(rows: &[Row]) -> Result<i64, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .ok_or_else(invalid)
}
