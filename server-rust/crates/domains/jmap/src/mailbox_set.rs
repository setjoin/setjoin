//! Atomic frozen-Go Mailbox/set phases. No mailbox audit row (Go writes none);
//! the foundation receipt supplies unknown-commit lookup without changing effects.
use crate::{Failure, SetOutcome};
use setjoin_contracts::command::CommandEnvelope;
use setjoin_pg::{
    CommandOutcome, MailboxAuthContext, ReceiptCommand, Rejection, ScopedExecutor,
    StatementFailure, Type, run_receipted_command,
};

pub async fn set(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    envelope: &CommandEnvelope<()>,
    create: &Option<String>,
    update: &Option<String>,
    destroy: &Option<Vec<i64>>,
) -> SetOutcome {
    let outcome = run_receipted_command(exec, ReceiptCommand { family: "jmap", command: "mailbox.set" }, envelope, auth,
        std::time::Instant::now() + std::time::Duration::from_secs(10),
        "SELECT jmap_mailbox_set_batch($1,$4::text::jsonb,$5::text::jsonb,$6)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[(create, Type::TEXT), (update, Type::TEXT), (destroy, Type::INT8_ARRAY)],
        |rows| rows.first().and_then(|r| r.try_get(0).ok()).ok_or_else(|| StatementFailure { hint: None, sqlstate: None, message: "missing mailbox set result".into() })).await;
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
