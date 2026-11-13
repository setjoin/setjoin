//! `Email/recover`, `Email/purge` and the paged reads `Email/deletedQuery`,
//! `Email/bundles` (JMAP1, #315): the reducers Go calls, nothing else.
//!
//! Recover and purge are one reducer call (`jmap_email_recover`,
//! `jmap_email_purge(ids)` with the default `p_notify`) in a scoped transaction
//! together with the operation's durable receipt ([`run_receipted_command`]):
//! Go writes no audit row for either, so the receipt is a Rust-owned row in
//! `rust_operation_receipts`, never a mailbox audit row. The mailbox is the
//! authenticated one (R1/R3: both reducers filter by it); the reducers own the
//! state bump, location transition, quota, orphaned-blob row and notification.
//! The paged reads are one static `SELECT` each in a `READ ONLY` scoped read.
use setjoin_contracts::command::CommandEnvelope;
use setjoin_pg::{
    run_receipted_command, CommandOutcome, MailboxAuthContext, ReceiptCommand, Rejection, Row,
    ScopedExecutor, StatementFailure, Type,
};
use std::time::Instant;

use crate::email_set::SetOutcome;
use crate::failure::{classify, Failure};

#[derive(Clone, Copy, Debug)]
pub struct EmailBatch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchOp {
    Recover,
    Purge,
}

pub const RECOVER: &str =
    "SELECT jmap_email_recover($1, $4::bigint[])::text WHERE $2::bigint > 0 AND $3::text <> ''";
pub const PURGE: &str =
    "SELECT jmap_email_purge($1, $4::bigint[])::text WHERE $2::bigint > 0 AND $3::text <> ''";

const RECOVER_RECEIPT: ReceiptCommand = ReceiptCommand {
    family: "jmap",
    command: "email.recover",
};
const PURGE_RECEIPT: ReceiptCommand = ReceiptCommand {
    family: "jmap",
    command: "email.purge",
};

pub async fn email_batch(
    exec: &ScopedExecutor,
    envelope: &CommandEnvelope<EmailBatch>,
    auth: &MailboxAuthContext,
    deadline: Instant,
    op: BatchOp,
    ids: &[i64],
) -> SetOutcome {
    let ids = ids.to_vec();
    let (receipt, sql) = match op {
        BatchOp::Recover => (RECOVER_RECEIPT, RECOVER),
        BatchOp::Purge => (PURGE_RECEIPT, PURGE),
    };
    let outcome = run_receipted_command(
        exec,
        receipt,
        envelope,
        auth,
        deadline,
        sql,
        &[(&ids, Type::INT8_ARRAY)],
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

fn decode(rows: &[Row]) -> Result<String, StatementFailure> {
    rows.first()
        .and_then(|row| row.get::<_, Option<String>>(0))
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "reducer returned no row".into(),
        })
}

pub const NUDGE_DISMISS: &str =
    "SELECT nudge_dismiss($1, $4::text)::text WHERE $2::bigint > 0 AND $3::text <> ''";
const NUDGE_RECEIPT: ReceiptCommand = ReceiptCommand {
    family: "jmap",
    command: "email.nudge-dismiss",
};

/// `Email/nudgeDismiss` with the toggle ON: the reducer appends the thread to
/// the owning user's dismissed list (one statement, one receipt).
pub async fn nudge_dismiss(
    exec: &ScopedExecutor,
    envelope: &CommandEnvelope<EmailBatch>,
    auth: &MailboxAuthContext,
    deadline: Instant,
    thread_id: &str,
) -> SetOutcome {
    let outcome = run_receipted_command(
        exec,
        NUDGE_RECEIPT,
        envelope,
        auth,
        deadline,
        NUDGE_DISMISS,
        &[(&thread_id, Type::TEXT)],
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

const DELETED_QUERY: &str = "SELECT jmap_email_query_deleted($1, $2, $3)::text";
const BUNDLES: &str = "SELECT newsletter_bundles_list($1, $2, $3)::text";
const NUDGES: &str = "SELECT stale_thread_nudges_list($1, $2, $3)::text";

pub async fn read_paged(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    which: Paged,
    limit: i32,
    position: i32,
) -> Result<String, StatementFailure> {
    let mailbox = auth.mailbox().get();
    let sql = match which {
        Paged::DeletedQuery => DELETED_QUERY,
        Paged::Bundles => BUNDLES,
        Paged::Nudges => NUDGES,
    };
    let rows = exec
        .read_scoped(
            auth,
            sql,
            &[
                (&mailbox, Type::INT8),
                (&limit, Type::INT4),
                (&position, Type::INT4),
            ],
        )
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
            RECOVER,
            PURGE,
            DELETED_QUERY,
            BUNDLES,
            NUDGES,
            NUDGE_DISMISS,
        ] {
            assert_eq!(setjoin_pg::statement::admit(sql), Ok(()));
            assert!(!sql.contains("messages") && !sql.contains("message_tags"));
        }
    }
}
