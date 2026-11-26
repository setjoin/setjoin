//! Conditional access (F03): policies, named locations, authentication strengths, templates,
//! simulation and import/export routes, and the policy document model. Foundation
//! dependencies only (`authz`, `contracts`, `db`, `pg`, `sql-catalog`) and no other family
//! crate. See DOX.md for the two-slice map and per-slice contracts.
//!
//! Authority comes from sealed principals (`UserPrincipal`, `AdminPermissionProof`) minted by
//! `TxFactory`; path ids, query strings and bodies name targets but never grant authority.
//! Responses render in `encoding/json` field order (structs) or sorted key order (maps),
//! HTML-escaped, with the trailing newline of Go's `Encoder`.
#![forbid(unsafe_code)]
mod cmd;
pub mod console;
pub mod exchange;
pub mod locations;
pub mod policies;
pub mod policy;
pub mod risk;
pub mod sql;
pub mod strengths;

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

pub const FAMILY: &str = "F03";

/// `requireCAPolicyRead` (`RequirePermAudited(access.policy_read)`).
pub const POLICY_READ: [&str; 1] = ["access.policy_read"];
/// `requireCAPolicyWrite` (`RequirePermAudited(access.policy_write)`).
pub const POLICY_WRITE: [&str; 1] = ["access.policy_write"];

pub(crate) fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid conditional access result".into(),
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

pub fn s(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".into())
}

/// Go's `Encoder` output: escaped, with the trailing newline.
pub fn done(text: String) -> String {
    go_escape(&text) + "\n"
}
