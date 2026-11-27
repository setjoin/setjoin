//! EmailSubmission and REST undo/recall (#317). Reducers own their effects.
//!
//! Submission mutations (`cancel`, `undo`) require [`SubmitCapability`]
//! (`Owner | full_access | send_as | send_on_behalf`, distinct from
//! [`setjoin_authz::principals::MutateCapability`]). `recall` requires
//! [`OwnerCapability`] and runs on `AppPool` via worker-owned `SECURITY DEFINER`
//! `recall_message`. Local-recipient fan-out (`SUBMISSION_SET*`) and cross-mailbox
//! recall source lookup (`SUBMISSION_RECALL_SOURCE`) are cataloged with
//! `SqlScope::WorkerBypass` and decoded here.
use setjoin_authz::principals::{
    OwnerCapability, ReadCapability, SubmitCapability, TxFactory, UserPrincipal,
};
use setjoin_contracts::command::CommandEnvelope;
use setjoin_pg::{CommandOutcome, ReceiptCommand, Row, StatementFailure};

use crate::sql;

pub async fn get(
    tx_factory: &TxFactory,
    read: &ReadCapability,
    ids: Option<&[i64]>,
) -> Result<String, StatementFailure> {
    let mailbox = read.mailbox().get();
    let ids = ids.map(<[i64]>::to_vec);
    let rows = tx_factory
        .run_mailbox_read_contract(read, &sql::SUBMISSION_GET, &[&mailbox, &ids])
        .await?;
    decode_submission_result(&rows)
}

/// Go accepts the filter as JSON; the reducer deliberately ignores it.
pub async fn query(
    tx_factory: &TxFactory,
    read: &ReadCapability,
    filter: Option<&str>,
    position: i32,
    limit: i32,
) -> Result<String, StatementFailure> {
    let mailbox = read.mailbox().get();
    let rows = tx_factory
        .run_mailbox_read_contract(
            read,
            &sql::SUBMISSION_QUERY,
            &[&mailbox, &filter, &position, &limit],
        )
        .await?;
    decode_submission_result(&rows)
}

#[derive(Clone, Copy, Debug)]
pub struct Submission;

/// The same sender-scoped reducer Go calls, with a durable transaction receipt.
pub async fn cancel(
    tx_factory: &TxFactory,
    submit: &SubmitCapability,
    envelope: &CommandEnvelope<Submission>,
    deadline: std::time::Instant,
    email_id: i64,
) -> CommandOutcome<String, StatementFailure> {
    let mailbox = submit.mailbox().get();
    tx_factory
        .run_mailbox_submit_contract_pipelined(
            submit,
            envelope,
            deadline,
            &sql::SUBMISSION_CANCEL,
            &[&mailbox, &email_id],
            Some(ReceiptCommand {
                family: "jmap",
                command: "submission.cancel",
            }),
            |rows| decode_submission_result(&rows),
        )
        .await
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessedSize {
    pub creation_id: String,
    pub email_id: i64,
    pub size_bytes: i64,
}

/// Decode a single-column JSONB text result from a submission reducer contract.
pub fn decode_submission_result(rows: &[Row]) -> Result<String, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, Option<String>>(0).ok().flatten())
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "submission reducer returned no row".into(),
        })
}

/// Decode rows produced by [`crate::sql::SUBMISSION_LOCK_DRAFT`].
pub fn decode_draft_lock(rows: &[Row]) -> Result<Option<(String, i64)>, StatementFailure> {
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let orig_ref: String = row.try_get(0).map_err(|_| StatementFailure {
        hint: None,
        sqlstate: None,
        message: "invalid raw_ref".into(),
    })?;
    let orig_size: i64 = row.try_get(1).map_err(|_| StatementFailure {
        hint: None,
        sqlstate: None,
        message: "invalid size_bytes".into(),
    })?;
    Ok(Some((orig_ref, orig_size)))
}

/// Decode rows produced by [`crate::sql::SUBMISSION_SET_WITH_NOT_CREATED`].
pub fn decode_submission_with_not_created(
    rows: &[Row],
) -> Result<(String, Vec<String>), StatementFailure> {
    let row = rows.first().ok_or_else(|| StatementFailure {
        hint: None,
        sqlstate: None,
        message: "submission reducer returned no row".into(),
    })?;
    let res_text: String = row.try_get(0).map_err(|_| StatementFailure {
        hint: None,
        sqlstate: None,
        message: "submission reducer returned null".into(),
    })?;
    let not_created_keys: Vec<String> = row.try_get(1).unwrap_or_default();
    Ok((res_text, not_created_keys))
}

/// Go's undo_send reducer, including its exact queue and tag behavior.
pub async fn undo(
    tx_factory: &TxFactory,
    submit: &SubmitCapability,
    envelope: &CommandEnvelope<Submission>,
    deadline: std::time::Instant,
    email_id: i64,
) -> CommandOutcome<String, StatementFailure> {
    let mailbox = submit.mailbox().get();
    tx_factory
        .run_mailbox_submit_contract_pipelined(
            submit,
            envelope,
            deadline,
            &sql::SUBMISSION_UNDO,
            &[&mailbox, &email_id],
            Some(ReceiptCommand {
                family: "jmap",
                command: "submission.undo",
            }),
            |rows| decode_submission_result(&rows),
        )
        .await
}

pub struct RecallSource {
    pub from: String,
    pub received_at: std::time::SystemTime,
    pub mailbox: i64,
    pub message_id: String,
}

/// Decode rows produced by [`crate::sql::SUBMISSION_RECALL_SOURCE`].
pub fn decode_recall_source(rows: &[Row]) -> Result<Option<RecallSource>, StatementFailure> {
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let invalid = || StatementFailure {
        hint: None,
        sqlstate: None,
        message: "invalid recall metadata".into(),
    };
    Ok(Some(RecallSource {
        from: row.try_get(0).map_err(|_| invalid())?,
        received_at: row.try_get(1).map_err(|_| invalid())?,
        mailbox: row.try_get(2).map_err(|_| invalid())?,
        message_id: row.try_get(3).map_err(|_| invalid())?,
    }))
}

pub async fn sender_alias(tx_factory: &TxFactory, user: &UserPrincipal, from: &str) -> bool {
    let uid = user.user().get();
    tx_factory
        .run_user_read_contract(user, &sql::SUBMISSION_SENDER_ALIAS, &[&uid, &from])
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|row| row.try_get::<_, bool>(0).ok()))
        .unwrap_or(false)
}

/// Auth scope is the mailbox returned by the owner-filtered source lookup.
/// `recall_message` is worker-owned `SECURITY DEFINER` with strict fail-closed
/// GUC binding, so it executes cleanly on `AppPool` via [`TxFactory`].
pub async fn recall(
    tx_factory: &TxFactory,
    owner: &OwnerCapability,
    envelope: &CommandEnvelope<Submission>,
    deadline: std::time::Instant,
    message_id: &str,
) -> CommandOutcome<String, StatementFailure> {
    let actor = owner.actor().get();
    let mailbox = owner.mailbox().get();
    tx_factory
        .run_owner_write_contract_pipelined(
            owner,
            envelope,
            deadline,
            &sql::SUBMISSION_RECALL,
            &[&message_id, &actor, &mailbox],
            Some(ReceiptCommand {
                family: "jmap",
                command: "submission.recall",
            }),
            |rows| {
                rows.first()
                    .and_then(|row| row.try_get::<_, Option<String>>(0).ok().flatten())
                    .ok_or_else(|| StatementFailure {
                        hint: None,
                        sqlstate: None,
                        message: "recall reducer returned no row".into(),
                    })
            },
        )
        .await
}

/// The raw-MIME attachment pass remains the #328 helper. Resolve its draft
/// predicate with the authenticated mailbox before any submission can write.
pub async fn has_attachments(
    tx_factory: &TxFactory,
    read: &ReadCapability,
    ids: &[i64],
) -> Result<bool, StatementFailure> {
    let mailbox = read.mailbox().get();
    let ids = ids.to_vec();
    let rows = tx_factory
        .run_mailbox_read_contract(read, &sql::SUBMISSION_HAS_ATTACHMENTS, &[&mailbox, &ids])
        .await?;
    Ok(rows
        .first()
        .is_some_and(|row| row.try_get::<_, bool>(0).unwrap_or(false)))
}
