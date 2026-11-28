//! General `Email/set` writes (JMAP1 #315, Wave 2a #356): multi-phase
//! `create`, `update`, and `destroy` in one locked transaction with the
//! `email_set` audit row, plus per-message `message_snooze` and the R1-scoped
//! attachment-blob ownership decoder.
//!
//! All mutations take a [`MutateCapability`] (`Owner | full_access` ONLY) and
//! execute via [`TxFactory`].
use setjoin_authz::principals::{MutateCapability, TxFactory};
use setjoin_contracts::command::CommandEnvelope;
use setjoin_contracts::ids::OperationId;
use setjoin_pg::{operation_hex, CommandOutcome, Rejection, Row, StatementFailure};
use std::time::Instant;

use crate::failure::{classify, Failure};
use crate::sql;

/// The command marker; the mailbox is the authenticated one.
#[derive(Clone, Copy, Debug)]
pub struct EmailSet;

/// Single-phase input for legacy callers.
#[derive(Clone, Copy, Debug)]
pub enum SetPhase<'a> {
    Update(&'a str),
    Destroy(&'a [i64]),
}

/// Multi-phase input executed in order inside one locked transaction.
#[derive(Clone, Copy, Debug, Default)]
pub struct SetBatch<'a> {
    pub create: Option<&'a str>,
    pub update: Option<&'a str>,
    pub destroy: Option<&'a [i64]>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SetOutcome {
    /// The reducer's JSONB as text, committed with its audit row.
    Done(String),
    Failed(Failure),
    /// Known not committed and not Rust's to answer.
    Forward,
    /// Commit outcome unknown; never success.
    Unknown {
        operation: OperationId,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum SetBatchOutcome {
    /// Each invoked phase's JSONB as text in order (`create`, `update`, `destroy`),
    /// committed atomically with the `email_set` audit row.
    Done(Vec<String>),
    Failed(Failure),
    /// Commit outcome unknown; never success.
    Unknown {
        operation: OperationId,
    },
}

pub const UPDATE: &str = sql::EMAIL_SET_UPDATE.sql;
pub const DESTROY: &str = sql::EMAIL_SET_DESTROY.sql;
pub const CREATE_PHASE: &str = sql::EMAIL_SET_CREATE_PHASE.sql;
pub const UPDATE_PHASE: &str = sql::EMAIL_SET_UPDATE_PHASE.sql;
pub const DESTROY_PHASE: &str = sql::EMAIL_SET_DESTROY_PHASE.sql;
pub const AUDIT: &str = sql::EMAIL_SET_AUDIT.sql;
pub const SNOOZE: &str = sql::EMAIL_SNOOZE.sql;
pub const OWNED_BLOBS: &str = sql::EMAIL_SET_OWNED_BLOBS.sql;

/// Decode rows produced by [`crate::sql::EMAIL_SET_OWNED_BLOBS`].
pub fn decode_owned_blob_set(rows: &[Row]) -> Vec<String> {
    let mut owned = Vec::with_capacity(rows.len());
    for row in rows {
        if let Ok(sha) = row.try_get::<_, String>(0) {
            owned.push(sha);
        }
    }
    owned
}

#[derive(Debug)]
pub enum SnoozeOutcome {
    Committed,
    Failed(StatementFailure),
    Unknown,
}

/// Run `message_snooze` in its own scoped transaction (matching Go `mail.go`).
pub async fn snooze_message(
    tx_factory: &TxFactory,
    envelope: &CommandEnvelope<EmailSet>,
    mutate: &MutateCapability,
    deadline: Instant,
    message_id: i64,
    until_rfc3339: &str,
) -> SnoozeOutcome {
    let mailbox = mutate.mailbox().get();
    let outcome = tx_factory
        .run_mailbox_write_contract_pipelined(
            mutate,
            envelope,
            deadline,
            &sql::EMAIL_SNOOZE,
            &[&mailbox, &message_id, &until_rfc3339],
            None,
            |_| Ok(()),
        )
        .await;
    match outcome {
        CommandOutcome::Committed(()) => SnoozeOutcome::Committed,
        CommandOutcome::RolledBack(Rejection::Statement(failure)) => SnoozeOutcome::Failed(failure),
        CommandOutcome::Unknown { .. } => SnoozeOutcome::Unknown,
        CommandOutcome::RolledBack(_) => SnoozeOutcome::Failed(StatementFailure {
            hint: None,
            sqlstate: None,
            message: "snooze failed".into(),
        }),
    }
}

pub async fn email_set(
    tx_factory: &TxFactory,
    envelope: &CommandEnvelope<EmailSet>,
    mutate: &MutateCapability,
    deadline: Instant,
    phase: SetPhase<'_>,
) -> SetOutcome {
    let mailbox = mutate.mailbox().get();
    let actor = mutate.actor().get();
    let op_hex = operation_hex(envelope.operation);
    let outcome = match phase {
        SetPhase::Update(patches) => {
            tx_factory
                .run_mailbox_write_contract_pipelined(
                    mutate,
                    envelope,
                    deadline,
                    &sql::EMAIL_SET_UPDATE,
                    &[&mailbox, &actor, &op_hex, &patches],
                    None,
                    |rows| decode(&rows),
                )
                .await
        }
        SetPhase::Destroy(ids) => {
            let ids = ids.to_vec();
            tx_factory
                .run_mailbox_write_contract_pipelined(
                    mutate,
                    envelope,
                    deadline,
                    &sql::EMAIL_SET_DESTROY,
                    &[&mailbox, &actor, &op_hex, &ids],
                    None,
                    |rows| decode(&rows),
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

/// Execute any combination of `create`, ordinary `update`, and `destroy` in one
/// locked transaction, always writing one `email_set` audit row carrying
/// `details.operation` (including for snooze-only and zero-phase calls).
pub async fn email_set_batch(
    tx_factory: &TxFactory,
    envelope: &CommandEnvelope<EmailSet>,
    mutate: &MutateCapability,
    deadline: Instant,
    batch: SetBatch<'_>,
) -> SetBatchOutcome {
    let mailbox = mutate.mailbox().get();
    let actor = mutate.actor().get();
    let op_hex = operation_hex(envelope.operation);
    let outcome = match (batch.create, batch.update, batch.destroy) {
        (None, Some(patches), None) => {
            tx_factory
                .run_mailbox_write_contract_pipelined(
                    mutate,
                    envelope,
                    deadline,
                    &sql::EMAIL_SET_UPDATE,
                    &[&mailbox, &actor, &op_hex, &patches],
                    None,
                    |rows| Ok(vec![decode(&rows)?]),
                )
                .await
        }
        (None, None, Some(ids)) => {
            let ids = ids.to_vec();
            tx_factory
                .run_mailbox_write_contract_pipelined(
                    mutate,
                    envelope,
                    deadline,
                    &sql::EMAIL_SET_DESTROY,
                    &[&mailbox, &actor, &op_hex, &ids],
                    None,
                    |rows| Ok(vec![decode(&rows)?]),
                )
                .await
        }
        _ => {
            let create = batch.create.map(str::to_owned);
            let update = batch.update.map(str::to_owned);
            let destroy = batch.destroy.map(<[i64]>::to_vec);
            tx_factory
                .run_mailbox_locked_tx(mutate, envelope, deadline, async move |tx| {
                    let mut parts = Vec::new();
                    if let Some(create) = create {
                        let rows = tx
                            .query_contract(&sql::EMAIL_SET_CREATE_PHASE, &[&mailbox, &create])
                            .await?;
                        parts.push(decode(&rows)?);
                    }
                    if let Some(update) = update {
                        let rows = tx
                            .query_contract(&sql::EMAIL_SET_UPDATE_PHASE, &[&mailbox, &update])
                            .await?;
                        parts.push(decode(&rows)?);
                    }
                    if let Some(ids) = destroy {
                        let rows = tx
                            .query_contract(&sql::EMAIL_SET_DESTROY_PHASE, &[&mailbox, &ids])
                            .await?;
                        parts.push(decode(&rows)?);
                    }
                    tx.execute_contract(&sql::EMAIL_SET_AUDIT, &[&mailbox, &actor, &op_hex])
                        .await?;
                    Ok::<_, StatementFailure>(parts)
                })
                .await
        }
    };
    match outcome {
        CommandOutcome::Committed(parts) => SetBatchOutcome::Done(parts),
        CommandOutcome::RolledBack(Rejection::Statement(failure)) => match classify(&failure) {
            Failure::Forward => SetBatchOutcome::Failed(Failure::ServerFail),
            other => SetBatchOutcome::Failed(other),
        },
        CommandOutcome::RolledBack(_) => SetBatchOutcome::Failed(Failure::ServerFail),
        CommandOutcome::Unknown { operation } => SetBatchOutcome::Unknown { operation },
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
pub const BODY_STATEMENTS: [&str; 7] = [
    UPDATE,
    DESTROY,
    CREATE_PHASE,
    UPDATE_PHASE,
    DESTROY_PHASE,
    AUDIT,
    SNOOZE,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statements_are_admissible_and_name_no_partitioned_table() {
        for sql in BODY_STATEMENTS {
            assert_eq!(setjoin_pg::statement::admit(sql), Ok(()));
            assert!(!sql.contains("messages") && !sql.contains("message_tags"));
        }
        assert_eq!(setjoin_pg::statement::admit(OWNED_BLOBS), Ok(()));
    }
}
