//! `Email/recover`, `Email/purge` and the paged reads `Email/deletedQuery`,
//! `Email/bundles`, `Email/nudges` (JMAP1, #315): the reducers Go calls, nothing else.
//!
//! Recover, purge, and nudge-dismiss run via [`TxFactory::run_mailbox_write_contract_pipelined`]
//! strictly from a [`MutateCapability`] (`Owner | full_access` ONLY) together with the
//! operation's durable receipt in `rust_operation_receipts`. The paged reads run via
//! [`TxFactory::run_mailbox_read_contract`] strictly from a [`ReadCapability`].
use setjoin_authz::principals::{MutateCapability, ReadCapability, TxFactory};
use setjoin_contracts::command::CommandEnvelope;
use setjoin_pg::{CommandOutcome, ReceiptCommand, Rejection, Row, StatementFailure};
use std::time::Instant;

use crate::email_set::SetOutcome;
use crate::failure::{classify, Failure};
use crate::sql;

#[derive(Clone, Copy, Debug)]
pub struct EmailBatch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchOp {
    Recover,
    Purge,
}

pub const RECOVER: &str = sql::EMAIL_RECOVER.sql;
pub const PURGE: &str = sql::EMAIL_PURGE.sql;
pub const NUDGE_DISMISS: &str = sql::EMAIL_NUDGE_DISMISS.sql;

const RECOVER_RECEIPT: ReceiptCommand = ReceiptCommand {
    family: "jmap",
    command: "email.recover",
};
const PURGE_RECEIPT: ReceiptCommand = ReceiptCommand {
    family: "jmap",
    command: "email.purge",
};
const NUDGE_RECEIPT: ReceiptCommand = ReceiptCommand {
    family: "jmap",
    command: "email.nudge-dismiss",
};

pub async fn email_batch(
    tx_factory: &TxFactory,
    envelope: &CommandEnvelope<EmailBatch>,
    mutate: &MutateCapability,
    deadline: Instant,
    op: BatchOp,
    ids: &[i64],
) -> SetOutcome {
    let mailbox = mutate.mailbox().get();
    let ids = ids.to_vec();
    let (receipt, contract) = match op {
        BatchOp::Recover => (RECOVER_RECEIPT, &sql::EMAIL_RECOVER),
        BatchOp::Purge => (PURGE_RECEIPT, &sql::EMAIL_PURGE),
    };
    let outcome = tx_factory
        .run_mailbox_write_contract_pipelined(
            mutate,
            envelope,
            deadline,
            contract,
            &[&mailbox, &ids],
            Some(receipt),
            decode,
        )
        .await;
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

fn decode(rows: Vec<Row>) -> Result<String, StatementFailure> {
    rows.first()
        .and_then(|row| row.get::<_, Option<String>>(0))
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "reducer returned no row".into(),
        })
}

/// `Email/nudgeDismiss` with the toggle ON: the reducer appends the thread to
/// the owning user's dismissed list (one statement, one receipt).
pub async fn nudge_dismiss(
    tx_factory: &TxFactory,
    envelope: &CommandEnvelope<EmailBatch>,
    mutate: &MutateCapability,
    deadline: Instant,
    thread_id: &str,
) -> SetOutcome {
    let mailbox = mutate.mailbox().get();
    let outcome = tx_factory
        .run_mailbox_write_contract_pipelined(
            mutate,
            envelope,
            deadline,
            &sql::EMAIL_NUDGE_DISMISS,
            &[&mailbox, &thread_id],
            Some(NUDGE_RECEIPT),
            decode,
        )
        .await;
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

/// The paged reads: one reducer each, `limit` and `position` already clamped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Paged {
    DeletedQuery,
    Bundles,
    Nudges,
}

pub async fn read_paged(
    tx_factory: &TxFactory,
    read: &ReadCapability,
    which: Paged,
    limit: i32,
    position: i32,
) -> Result<String, StatementFailure> {
    let mailbox = read.mailbox().get();
    let contract = match which {
        Paged::DeletedQuery => &sql::EMAIL_DELETED_QUERY,
        Paged::Bundles => &sql::EMAIL_BUNDLES,
        Paged::Nudges => &sql::EMAIL_NUDGES,
    };
    let rows = tx_factory
        .run_mailbox_read_contract(read, contract, &[&mailbox, &limit, &position])
        .await?;
    rows.first()
        .and_then(|row| row.get::<_, Option<String>>(0))
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "reducer returned no row".into(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statements_are_admissible_and_name_no_partitioned_table() {
        for sql in [
            sql::EMAIL_RECOVER.sql,
            sql::EMAIL_PURGE.sql,
            sql::EMAIL_DELETED_QUERY.sql,
            sql::EMAIL_BUNDLES.sql,
            sql::EMAIL_NUDGES.sql,
            sql::EMAIL_NUDGE_DISMISS.sql,
        ] {
            assert_eq!(setjoin_pg::statement::admit(sql), Ok(()));
            assert!(!sql.contains("messages") && !sql.contains("message_tags"));
        }
    }
}
