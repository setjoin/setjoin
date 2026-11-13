//! General `Email/set` writes (JMAP1, #315): one phase per request, each one
//! reducer call plus Go's `email_set` audit row in the same statement.
//!
//! Go's `emailSet` runs the create, update and destroy phases as separate
//! reducer calls in one transaction, then writes the actor audit row after the
//! commit. Rust serves a request with exactly one phase (update or destroy), so
//! the whole command is one statement: `jmap_email_set_update(mailbox, patches)`
//! or `jmap_email_set_destroy(mailbox, ids)` (the existing reducers own every
//! effect: state bump, journal, counters, notification), with the audit row in
//! a data-modifying CTE of the same statement (the pilot's c=8 reasoning, see
//! `set_seen.rs`). The mailbox and actor are the authenticated ones (R1/R2/R3);
//! the reducers filter every write by that mailbox. The audit row carries
//! `details.operation` as the owner decided for `email_set` on 2026-10-29
//! (Go writes NULL), so an `Unknown` commit can be looked up with
//! [`crate::lookup_set_seen`]. A rolled-back command wrote nothing and either is
//! answered like Go's `mapReducerErr` ([`crate::Failure`]) or forwards.
//!
//! Create stays Go's: its attachment-blob ownership gate, S/MIME signing and
//! multi-reducer batch are not one statement.
use setjoin_contracts::command::CommandEnvelope;
use setjoin_contracts::ids::OperationId;
use setjoin_pg::{
    run_command, CommandOutcome, MailboxAuthContext, Rejection, Row, ScopedExecutor,
    StatementFailure, Type,
};
use std::time::Instant;

use crate::failure::{classify, Failure};

/// The command marker; the mailbox is the authenticated one.
#[derive(Clone, Copy, Debug)]
pub struct EmailSet;

/// What to run. Update is the JSON object text `{"<id>": <patch>, ...}`.
#[derive(Clone, Copy, Debug)]
pub enum SetPhase<'a> {
    Update(&'a str),
    Destroy(&'a [i64]),
}

#[derive(Debug, PartialEq, Eq)]
pub enum SetOutcome {
    /// The reducer's JSONB as text, committed with its audit row.
    Done(String),
    Failed(Failure),
    /// Known not committed and not Rust's to answer: forward to Go.
    Forward,
    /// Commit outcome unknown; never success.
    Unknown {
        operation: OperationId,
    },
}

/// `$1` mailbox, `$2` actor, `$3` operation ID, `$4` the phase argument.
pub const UPDATE: &str = "WITH audit AS ( \
       INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, message_id, details) \
       VALUES ($1, $2, 'email_set', NULL, jsonb_build_object('operation', $3::text)) RETURNING 1) \
     SELECT r::text FROM jmap_email_set_update($1, $4::text::jsonb) AS r, audit";
pub const DESTROY: &str = "WITH audit AS ( \
       INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, message_id, details) \
       VALUES ($1, $2, 'email_set', NULL, jsonb_build_object('operation', $3::text)) RETURNING 1) \
     SELECT r::text FROM jmap_email_set_destroy($1, $4::bigint[]) AS r, audit";

pub async fn email_set(
    exec: &ScopedExecutor,
    envelope: &CommandEnvelope<EmailSet>,
    auth: &MailboxAuthContext,
    deadline: Instant,
    phase: SetPhase<'_>,
) -> SetOutcome {
    let outcome = match phase {
        SetPhase::Update(patches) => {
            run_command(
                exec,
                envelope,
                auth,
                deadline,
                UPDATE,
                &[(&patches, Type::TEXT)],
                decode,
            )
            .await
        }
        SetPhase::Destroy(ids) => {
            let ids = ids.to_vec();
            run_command(
                exec,
                envelope,
                auth,
                deadline,
                DESTROY,
                &[(&ids, Type::INT8_ARRAY)],
                decode,
            )
            .await
        }
    };
    match outcome {
        CommandOutcome::Committed(text) => SetOutcome::Done(text),
        CommandOutcome::RolledBack(Rejection::Statement(failure)) => match classify(&failure) {
            Failure::Forward => SetOutcome::Forward,
            other => SetOutcome::Failed(other),
        },
        CommandOutcome::RolledBack(_) => SetOutcome::Forward,
        CommandOutcome::Unknown { operation } => SetOutcome::Unknown { operation },
    }
}

fn decode(rows: &[Row]) -> Result<String, StatementFailure> {
    rows.first()
        .and_then(|row| row.get::<_, Option<String>>(0))
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "reducer returned no row".into(),
        })
}

/// Every statement the command sends.
pub const BODY_STATEMENTS: [&str; 2] = [UPDATE, DESTROY];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statements_are_admissible_and_name_no_partitioned_table() {
        for sql in BODY_STATEMENTS {
            assert_eq!(setjoin_pg::statement::admit(sql), Ok(()));
            assert!(!sql.contains("messages") && !sql.contains("message_tags"));
        }
    }
}
