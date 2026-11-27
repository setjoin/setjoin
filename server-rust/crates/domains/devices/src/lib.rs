//! Devices (F07): MDM/lockdown (#310), MAM (#311) and offline governance (#312).
//! The gateway hosts the qualified HTTP adapters and dormant MDM observer.
//!
//! Foundation dependencies only. The actor and mailbox come from sealed
//! principals; path ids name targets but never grant authority. Permissions and
//! the domain scope are resolved live from the governed grants via
//! `AdminPrincipal` / `AdminPermissionProof`.
#![forbid(unsafe_code)]
pub mod gojson;
pub mod lockdown;
pub mod mam;
pub mod mdm;
pub mod offline;
pub mod sql;
pub use sql::SQL_CONTRACTS;

use serde_json::json;
use setjoin_authz::principals::{TxFactory, UserPrincipal};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, OperationId},
};
use setjoin_pg::{CommandOutcome, ReceiptCommand, StatementFailure};
use sha2::{Digest as _, Sha256};

pub const FAMILY: &str = "F07";

/// `permissions.PermMAMRead` / `PermMAMWrite`: the MAM console grants that also
/// gate the MDM and device-lockdown routes.
pub const MAM_READ: [&str; 1] = ["mam.read"];
pub const MAM_WRITE: [&str; 1] = ["mam.write"];

pub(crate) fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid devices result".into(),
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
pub(crate) fn opt(v: &Option<String>) -> Option<String> {
    v.as_deref().map(s)
}
