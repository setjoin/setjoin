//! Mail security (F06): quarantine, queue, spam, TLS, DMARC, DLP, threat, message trace and
//! S/MIME routes. Foundation dependencies only (`authz`, `contracts`, `db`, `pg`, `mime`) and no
//! other family crate. See DOX.md for the nine-slice map and per-slice contracts.
//!
//! The actor and mailbox come from sealed principals (`UserPrincipal`, `MailboxPrincipal`,
//! `AdminPermissionProof`); path ids, query strings and bodies name targets but never grant
//! authority. Permissions and domain scope are resolved live per request via `TxFactory`.
//! Responses render in `encoding/json` field order (structs) or sorted key order (maps),
//! HTML-escaped, with the trailing newline of Go's `Encoder`.
#![forbid(unsafe_code)]
pub mod certificate;
pub mod dlp;
pub mod dmarc;
pub mod quarantine;
pub mod queue;
pub mod received;
pub mod smime;
pub mod spam;
pub mod spam_model;
pub mod sql;
pub mod threat;
pub mod tls;
pub mod trace;

pub use sql::SQL_CONTRACTS;

use serde_json::json;
use setjoin_authz::principals::{TxFactory, UserPrincipal};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, MailboxId, OperationId},
};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Row, StatementFailure};
use sha2::{Digest as _, Sha256};

pub const FAMILY: &str = "F06";

/// Go's `admin.ConsoleScopes[ConsoleMail]` in registration order (`requireMailPerm`, any-of).
pub const MAIL_CONSOLE: [&str; 5] = [
    "domains.read",
    "queue.read",
    "reports.read",
    "mail.pipeline",
    "mail.security",
];
/// Go's `admin.ConsoleScopes[ConsoleLogs]` (`requireLogsPerm`); org-wide only.
pub const LOGS_CONSOLE: [&str; 1] = ["audit.read"];
/// `requireMailSecurity` (`permissions.PermMailSecurity`).
pub const MAIL_SECURITY: [&str; 1] = ["mail.security"];
/// `requireSecurityWrite`.
pub const SECURITY_WRITE: [&str; 1] = ["security.write"];
/// `requireQueueWrite`.
pub const QUEUE_WRITE: [&str; 1] = ["queue.write"];
/// `requireMailExport`.
pub const MAIL_EXPORT: [&str; 1] = ["mail.export"];

pub(crate) fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid mail security result".into(),
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

pub(crate) fn mailbox_envelope(
    actor: ActorId,
    mailbox: MailboxId,
    operation: [u8; 16],
    payload: &str,
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: AuthorityKey {
            actor,
            scope: ResourceScope::Mailbox(mailbox),
            generation: Generation(1),
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
pub(crate) fn first_i64(rows: &[Row]) -> Result<i64, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .ok_or_else(invalid)
}
