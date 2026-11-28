//! Atomic frozen-Go Mailbox/set phases. No mailbox audit row (Go writes none);
//! the foundation receipt supplies unknown-commit lookup without changing effects.
use crate::{sql, Failure, SetOutcome};
use setjoin_authz::principals::{MutateCapability, TxFactory};
use setjoin_contracts::command::CommandEnvelope;
use setjoin_pg::{CommandOutcome, ReceiptCommand, Rejection, StatementFailure};

pub async fn set(
    tx_factory: &TxFactory,
    mutate: &MutateCapability,
    envelope: &CommandEnvelope<()>,
    create: &Option<String>,
    update: &Option<String>,
    destroy: &Option<Vec<i64>>,
) -> SetOutcome {
    let mailbox = mutate.mailbox().get();
    let outcome = tx_factory
        .run_mailbox_write_contract_pipelined(
            mutate,
            envelope,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
            &sql::MAILBOX_SET,
            &[&mailbox, create, update, destroy],
            Some(ReceiptCommand {
                family: "jmap",
                command: "mailbox.set",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(|| StatementFailure {
                        hint: None,
                        sqlstate: None,
                        message: "missing mailbox set result".into(),
                    })
            },
        )
        .await;
    match outcome {
        CommandOutcome::Committed(raw) => SetOutcome::Done(raw),
        CommandOutcome::Unknown { operation } => SetOutcome::Unknown { operation },
        CommandOutcome::RolledBack(Rejection::Statement(f)) => match crate::classify_failure(&f) {
            Failure::Forward => SetOutcome::Failed(Failure::ServerFail),
            f => SetOutcome::Failed(f),
        },
        CommandOutcome::RolledBack(_) => SetOutcome::Failed(Failure::ServerFail),
    }
}
