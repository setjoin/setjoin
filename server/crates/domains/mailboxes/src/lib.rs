//! Mailboxes and migration (F05): mailboxes slice.
//!
//! Foundation dependencies only. The actor and mailbox come from sealed
//! principals (`AdminPrincipal` / `AdminPermissionProof` / `UserPrincipal`);
//! request ids name targets but never grant authority. Permissions and domain
//! scope are resolved live from governed grants. Responses render in
//! `encoding/json` field order, HTML-escaped, with the trailing newline of Go's
//! `Encoder`.
#![forbid(unsafe_code)]
pub mod exchange;
pub mod exchange_artifact;
pub mod import_export;
pub mod lifecycle;
pub mod mailboxes;
pub mod migration;
pub use setjoin_mime as mimeutil;
pub mod private_policy;
pub mod sql;
pub mod ziparchive;
pub use sql::SQL_CONTRACTS;

use serde_json::json;
use setjoin_authz::principals::{TxFactory, UserPrincipal};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, OperationId},
};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Rejection, Row, StatementFailure};
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

pub(crate) fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid mailboxes result".into(),
    }
}

pub(crate) fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}

pub(crate) fn envelope(
    actor: ActorId,
    generation: Generation,
    operation: [u8; 16],
    payload: &str,
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: AuthorityKey {
            actor,
            scope: ResourceScope::User(actor),
            generation,
        },
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
    factory: &TxFactory,
    user: &UserPrincipal,
    path: &str,
    permission: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let before = json!({
        "actor": user.audit_meta().email,
        "target": path,
        "missingPermission": permission
    })
    .to_string();
    let env = envelope(user.user(), user.generation(), operation, &before);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CONSOLE_DENIED,
            &[&before, &path],
            Some(command("console.denied")),
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
pub fn first_bool(rows: &[Row]) -> Result<bool, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}
