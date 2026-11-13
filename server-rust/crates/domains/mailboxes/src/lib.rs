//! Mailboxes and migration (F05): mailboxes slice.
//!
//! Foundation dependencies only. The actor and mailbox come from the sealed auth
//! context; request ids name targets but never grant authority. Permissions and
//! domain scope are resolved live, as Go's auth chain does for admin tokens.
//! Responses render in `encoding/json` field order, HTML-escaped, with the
//! trailing newline of Go's `Encoder`.
#![forbid(unsafe_code)]
pub mod exchange;
pub mod exchange_artifact;
pub mod lifecycle;
pub mod import_export;
pub mod mailboxes;
pub mod migration;
pub use setjoin_mime as mimeutil;
pub mod private_policy;
pub mod ziparchive;
use serde_json::json;
use setjoin_authz::AuthContext;
use setjoin_contracts::{
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, MailboxId, OperationId},
};
use setjoin_pg::{
    CommandOutcome, MailboxAuthContext, ReceiptCommand, Rejection, Row, ScopedExecutor,
    StatementFailure, Type,
};
use sha2::{Digest as _, Sha256};

pub const FAMILY: &str = "F05";

/// Go's `admin.ConsoleScopes[ConsoleMail]`, in registration order
/// (`requireMailPerm`, any-of).
pub const MAIL_CONSOLE: [&str; 5] = [
    "domains.read",
    "queue.read",
    "reports.read",
    "mail.pipeline",
    "mail.security",
];
pub const USERS_CREATE: [&str; 1] = ["users.create"];
pub const USERS_DELETE: [&str; 1] = ["users.delete"];
pub const MAIL_EXPORT: [&str; 1] = ["mail.export"];

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
        message: "invalid mailboxes result".into(),
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
        ReceiptCommand {
            family: FAMILY,
            command: "console.denied",
        },
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

/// A refusal decided by a reducer, carried through the executor as a rolled-back body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub status: u16,
    pub detail: String,
}
pub fn problem_of(error: &Rejection<StatementFailure>) -> Option<Problem> {
    let (Rejection::Statement(e) | Rejection::Body(e)) = error else {
        return None;
    };
    if e.sqlstate.is_some() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&e.message).ok()?;
    Some(Problem {
        status: v["status"].as_u64()? as u16,
        detail: v["detail"].as_str()?.to_owned(),
    })
}

/// encoding/json HTML escaping of an already rendered document.
pub fn go_escape(text: &str) -> String {
    text.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}
pub(crate) fn s(text: &str) -> String {
    serde_json::to_string(text).expect("string")
}
pub(crate) fn done(text: String) -> String {
    go_escape(&text) + "\n"
}
/// RFC 3339 with Go's trimmed fractional seconds (`time.Time` JSON), UTC.
pub(crate) fn nano(column: &str) -> String {
    format!(
        "to_char({column} AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS') || CASE WHEN date_part('microseconds', {column} AT TIME ZONE 'UTC')::bigint % 1000000 = 0 THEN '' ELSE regexp_replace(to_char({column} AT TIME ZONE 'UTC','.US'),'0+$','') END || 'Z'"
    )
}
pub(crate) fn first_bool(rows: &[Row]) -> Result<bool, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}
