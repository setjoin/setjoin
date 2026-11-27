//! `SetMessageSeen` (`mail.email.set-seen`, sheet [`MARK_SEEN`]): the Rust
//! command for the `$seen` keyword (RP07, #214; reducer call since #224).
//!
//! Runs via [`TxFactory::run_mailbox_write_contract_pipelined`] strictly from a
//! [`MutateCapability`] (`Owner | full_access` ONLY) with one body statement
//! ([`SET_SEEN`]) combining `jmap_email_set_update` and the `mailbox_audit_log`
//! row carrying `details.operation`.
//!
//! [`MARK_SEEN`]: setjoin_contracts::command::MARK_SEEN
use setjoin_authz::principals::{MutateCapability, ReadCapability, TxFactory};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::{CommandEnvelope, OperationResult, SetMessageSeen},
    error::ContractError,
    ids::{Generation, MailboxId, MessageId, OperationId},
};
use setjoin_db::lifecycle::LifecycleError;
pub use setjoin_pg::{operation_hex, OperationLookup};
use setjoin_pg::{CommandOutcome, Rejection, Row, StatementFailure};
use std::time::Instant;

use crate::sql;

/// What a committed set-seen did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeenEffect {
    /// `is_read` changed; the state moved from `old_state` to `email_state`.
    Changed { old_state: i64, email_state: i64 },
    /// `is_read` already had the requested value: no state change emitted.
    Unchanged { email_state: i64 },
    /// No such message in the authenticated mailbox.
    NotFound { email_state: i64 },
    /// The reducer reported a per-item error for the message (its
    /// subtransaction rolled back; no state change). `set_error` is the
    /// reducer's `notUpdated` entry as PostgreSQL's JSONB text, verbatim.
    NotUpdated { email_state: i64, set_error: String },
}

/// The command's answer. `result` is `Accepted` only after a confirmed
/// COMMIT; `Unknown` (commit outcome not observed) is never success — look
/// the operation up under current authority with `operation`.
#[derive(Debug)]
pub struct SetSeenReply {
    pub operation: OperationId,
    pub result: OperationResult<SeenEffect>,
    /// Why the command is known not to have committed. Logs only; never sent
    /// to a client.
    pub rejection: Option<Rejection<StatementFailure>>,
}

/// Run `SetMessageSeen` for the authenticated mailbox in one transaction.
///
/// The command's `mailbox` must equal `mutate`'s; a mismatch is rejected
/// before anything is sent.
pub async fn set_message_seen(
    tx_factory: &TxFactory,
    envelope: &CommandEnvelope<SetMessageSeen>,
    mutate: &MutateCapability,
    deadline: Instant,
) -> SetSeenReply {
    let cmd = envelope.command;
    let authority = AuthorityKey {
        actor: mutate.actor(),
        scope: ResourceScope::Mailbox(mutate.mailbox()),
        generation: Generation(1),
    };
    if let Err(e) = cmd.validate_scope(authority) {
        return reply(
            envelope.operation,
            CommandOutcome::RolledBack(Rejection::Authority(LifecycleError::Contract(e))),
        );
    }
    let mailbox = mutate.mailbox().get();
    let actor = mutate.actor().get();
    let op_hex = operation_hex(envelope.operation);
    let message = cmd.message.get();
    let seen_json = if cmd.seen { "true" } else { "false" };
    let outcome = tx_factory
        .run_mailbox_write_contract_pipelined(
            mutate,
            envelope,
            deadline,
            &sql::SET_SEEN,
            &[&mailbox, &actor, &op_hex, &message, &seen_json],
            None,
            |rows| decode_seen(&rows),
        )
        .await;
    reply(envelope.operation, outcome)
}

/// A recognized empty-string `$seen` value, passed to the same reducer so
/// its per-item error and ownership checks remain authoritative.
#[derive(Clone, Copy, Debug)]
pub struct EmptySeen {
    pub mailbox: MailboxId,
    pub message: MessageId,
}

pub async fn set_message_seen_empty(
    tx_factory: &TxFactory,
    envelope: &CommandEnvelope<EmptySeen>,
    mutate: &MutateCapability,
    deadline: Instant,
) -> SetSeenReply {
    let cmd = envelope.command;
    if mutate.mailbox() != cmd.mailbox {
        return reply(
            envelope.operation,
            CommandOutcome::RolledBack(Rejection::Authority(LifecycleError::Contract(
                ContractError::ScopeMismatch,
            ))),
        );
    }
    let mailbox = mutate.mailbox().get();
    let actor = mutate.actor().get();
    let op_hex = operation_hex(envelope.operation);
    let message = cmd.message.get();
    let seen_json = "\"\"";
    let outcome = tx_factory
        .run_mailbox_write_contract_pipelined(
            mutate,
            envelope,
            deadline,
            &sql::SET_SEEN,
            &[&mailbox, &actor, &op_hex, &message, &seen_json],
            None,
            |rows| decode_seen(&rows),
        )
        .await;
    reply(envelope.operation, outcome)
}

/// Map the executor's terminal observation onto the operation result.
pub fn reply(
    operation: OperationId,
    outcome: CommandOutcome<SeenEffect, StatementFailure>,
) -> SetSeenReply {
    let (result, rejection) = match outcome {
        CommandOutcome::Committed(effect) => (OperationResult::Accepted(effect), None),
        CommandOutcome::RolledBack(r) => (OperationResult::Rejected, Some(r)),
        CommandOutcome::Unknown { .. } => (OperationResult::Unknown, None),
    };
    SetSeenReply {
        operation,
        result,
        rejection,
    }
}

pub const SET_SEEN: &str = sql::SET_SEEN.sql;
pub const LOOKUP: &str = sql::SET_SEEN_LOOKUP.sql;

/// Look up an operation ID returned by an `Unknown` outcome, under the
/// caller's current authority (`recover(Unknown)` = look up under current
/// authority). Waits on the same transaction-scoped operation lock before
/// reading `mailbox_audit_log` in `READ COMMITTED READ ONLY`.
pub async fn lookup_set_seen(
    tx_factory: &TxFactory,
    read: &ReadCapability,
    operation: OperationId,
) -> Result<OperationLookup, StatementFailure> {
    let mailbox = read.mailbox().get();
    let actor = read.actor().get();
    let op_hex = operation_hex(operation);
    let lock = format!("setjoin-command:{mailbox}:{actor}:{op_hex}");
    let mut tx = tx_factory.begin_mailbox_read(read).await?;
    tx.query_contract(&sql::SET_SEEN_LOOKUP_LOCK, &[&lock])
        .await?;
    let rows = tx
        .query_contract(&sql::SET_SEEN_LOOKUP, &[&mailbox, &actor, &op_hex])
        .await?;
    tx.finish().await?;
    match rows.as_slice() {
        [row] if row.len() == 1 => match row.try_get::<_, bool>(0) {
            Ok(true) => Ok(OperationLookup::Committed),
            Ok(false) => Ok(OperationLookup::Absent),
            Err(_) => Err(failure("operation lookup must return one boolean")),
        },
        _ => Err(failure("operation lookup must return one boolean")),
    }
}

/// Every statement the command body sends, in order.
pub const BODY_STATEMENTS: [&str; 1] = [SET_SEEN];

fn decode_seen(rows: &[Row]) -> Result<SeenEffect, StatementFailure> {
    let row = rows
        .first()
        .ok_or_else(|| failure("reducer returned no row"))?;
    let old: Option<i64> = row.get(0);
    let new: Option<i64> = row.get(1);
    let updated: Option<bool> = row.get(2);
    let not_updated_type: Option<String> = row.get(3);
    let not_updated_entry: Option<String> = row.get(4);
    let (Some(old_state), Some(email_state)) = (old, new) else {
        return Err(failure("authenticated mailbox row missing"));
    };
    let not_updated = match (not_updated_type.as_deref(), not_updated_entry.as_deref()) {
        (Some(t), Some(raw)) => Some((t, raw)),
        (None, None) => None,
        _ => return Err(failure("reducer notUpdated entry without a type")),
    };
    classify(old_state, email_state, updated == Some(true), not_updated)
}

fn classify(
    old_state: i64,
    email_state: i64,
    updated: bool,
    not_updated: Option<(&str, &str)>,
) -> Result<SeenEffect, StatementFailure> {
    match (updated, not_updated) {
        (true, None) if email_state == old_state => Ok(SeenEffect::Unchanged { email_state }),
        (true, None) => Ok(SeenEffect::Changed {
            old_state,
            email_state,
        }),
        (false, Some(("notFound", _))) if email_state == old_state => {
            Ok(SeenEffect::NotFound { email_state })
        }
        (false, Some((_, raw))) if email_state == old_state => Ok(SeenEffect::NotUpdated {
            email_state,
            set_error: raw.to_owned(),
        }),
        (_, other) => Err(failure(&format!(
            "reducer result inconsistent (notUpdated type {:?})",
            other.map(|(t, _)| t)
        ))),
    }
}

fn failure(message: &str) -> StatementFailure {
    StatementFailure {
        hint: None,
        sqlstate: None,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OP: OperationId = OperationId([0x42; 16]);

    #[test]
    fn unknown_commit_returns_the_operation_for_lookup_never_success() {
        let r = reply(OP, CommandOutcome::Unknown { operation: OP });
        assert_eq!(r.operation, OP);
        assert_eq!(r.result, OperationResult::Unknown);
        assert!(r.rejection.is_none());
    }

    #[test]
    fn only_a_confirmed_commit_is_accepted() {
        let ok = reply(
            OP,
            CommandOutcome::Committed(SeenEffect::Unchanged { email_state: 3 }),
        );
        assert_eq!(
            ok.result,
            OperationResult::Accepted(SeenEffect::Unchanged { email_state: 3 })
        );
        let rolled = reply(OP, CommandOutcome::RolledBack(Rejection::Unavailable));
        assert_eq!(rolled.result, OperationResult::Rejected);
        assert!(matches!(rolled.rejection, Some(Rejection::Unavailable)));
        assert_eq!(rolled.operation, OP);
    }

    #[test]
    fn classifies_the_reducer_result() {
        assert_eq!(
            classify(4, 5, true, None).unwrap(),
            SeenEffect::Changed {
                old_state: 4,
                email_state: 5
            }
        );
        assert_eq!(
            classify(4, 4, true, None).unwrap(),
            SeenEffect::Unchanged { email_state: 4 }
        );
        let nf = r#"{"type": "notFound"}"#;
        assert_eq!(
            classify(4, 4, false, Some(("notFound", nf))).unwrap(),
            SeenEffect::NotFound { email_state: 4 }
        );
        assert!(classify(4, 4, false, None).is_err());
        assert!(classify(4, 5, false, Some(("notFound", nf))).is_err());
    }

    #[test]
    fn a_reducer_item_error_is_a_committed_not_updated_entry() {
        let raw = r#"{"type": "invalidArguments", "description": "Update failed"}"#;
        assert_eq!(
            classify(4, 4, false, Some(("invalidArguments", raw))).unwrap(),
            SeenEffect::NotUpdated {
                email_state: 4,
                set_error: raw.to_owned()
            }
        );
        assert!(classify(4, 5, false, Some(("invalidArguments", raw))).is_err());
    }

    #[test]
    fn the_audit_row_rides_in_the_reducer_statement() {
        assert_eq!(BODY_STATEMENTS.len(), 1);
        assert!(SET_SEEN.contains("INSERT INTO mailbox_audit_log"));
        assert!(SET_SEEN.contains("jmap_email_set_update("));
    }

    #[test]
    fn no_body_statement_names_a_partitioned_table() {
        for sql in BODY_STATEMENTS {
            let words: Vec<String> = sql
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map(str::to_ascii_lowercase)
                .collect();
            for table in ["messages", "message_tags"] {
                assert!(!words.iter().any(|w| w == table), "{table} in {sql}");
            }
            assert!(setjoin_pg::statement::admit(sql).is_ok(), "{sql}");
        }
    }
}
