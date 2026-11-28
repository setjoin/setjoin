//! The `/messages/{id}/*` REST routes (#469): focus, raw download, attachments
//! zip and one-click unsubscribe. Every statement keys ownership on the
//! verified user (`mb.user_id`), never a request field (R1-R3).
//!
//! Cross-mailbox owner lookups (`MESSAGES_OWNED_MESSAGE`, `MESSAGES_ZIP_SOURCE`,
//! `MESSAGES_UNSUBSCRIBE_SOURCE`) are cataloged with `SqlScope::WorkerBypass`
//! and decoded by the pure helpers here; writes run via [`TxFactory`].
use setjoin_authz::principals::{MutateCapability, TxFactory, UserPrincipal};
use setjoin_contracts::command::CommandEnvelope;
use setjoin_pg::{CommandOutcome, ReceiptCommand, Row, StatementFailure};
use std::time::Instant;

use crate::sql;

/// Go's `OwnedMessage` columns the routes need.
pub struct Owned {
    pub raw_ref: String,
    pub mailbox: i64,
    pub subject: String,
}

fn failure(message: &str) -> StatementFailure {
    StatementFailure {
        hint: None,
        sqlstate: None,
        message: message.into(),
    }
}

/// Decode rows produced by [`crate::sql::MESSAGES_OWNED_MESSAGE`].
pub fn decode_owned_message(rows: &[Row]) -> Result<Option<Owned>, StatementFailure> {
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    Ok(Some(Owned {
        raw_ref: row.try_get(0).map_err(|_| failure("raw_ref"))?,
        mailbox: row.try_get(1).map_err(|_| failure("mailbox"))?,
        subject: row.try_get(2).map_err(|_| failure("subject"))?,
    }))
}

/// `set_message_focus` for a message the verified user owns. Ownership, the
/// owning mailbox and `received_at` come from the same statement as the
/// reducer call (no check-then-mutate). Zero rows (the message vanished since
/// it was resolved) rolls back with the reducer's own `BZ006` not-found.
pub async fn set_focus(
    tx_factory: &TxFactory,
    mutate: &MutateCapability,
    envelope: &CommandEnvelope<()>,
    deadline: Instant,
    id: i64,
    focused: bool,
) -> CommandOutcome<(), StatementFailure> {
    let mailbox = mutate.mailbox().get();
    let actor = mutate.actor().get();
    let operation = envelope.operation;
    tx_factory
        .run_mailbox_write(mutate, envelope, deadline, async move |tx| {
            let rows = tx
                .query_contract(&sql::MESSAGES_SET_FOCUS, &[&mailbox, &actor, &id, &focused])
                .await?;
            if rows.is_empty() {
                return Err(StatementFailure {
                    hint: None,
                    sqlstate: Some("BZ006".into()),
                    message: "message not found".into(),
                });
            }
            tx.record_receipt(
                operation,
                ReceiptCommand {
                    family: "jmap",
                    command: "message.focus",
                },
            )
            .await?;
            Ok(())
        })
        .await
}

/// The non-inline attachments of an owned message in `message_attachments.id`
/// order, and the message subject (`None` when the message has none).
pub struct ZipSource {
    pub entries: Vec<(String, String)>,
    pub subject: Option<String>,
}

/// Decode rows produced by [`crate::sql::MESSAGES_ZIP_SOURCE`].
pub fn decode_zip_source(rows: &[Row]) -> Result<ZipSource, StatementFailure> {
    let mut entries = Vec::new();
    let mut subject = None;
    for (index, row) in rows.iter().enumerate() {
        entries.push((
            row.try_get(0).map_err(|_| failure("blob"))?,
            row.try_get(1).map_err(|_| failure("filename"))?,
        ));
        if index == 0 {
            subject = row
                .try_get::<_, Option<String>>(2)
                .map_err(|_| failure("subject"))?;
        }
    }
    Ok(ZipSource { entries, subject })
}

/// Decode rows produced by [`crate::sql::MESSAGES_UNSUBSCRIBE_SOURCE`].
pub fn decode_unsubscribe_source(
    rows: &[Row],
) -> Result<Option<(String, String)>, StatementFailure> {
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    Ok(Some((
        row.try_get(0).map_err(|_| failure("list_unsubscribe"))?,
        row.try_get(1).map_err(|_| failure("from_addr"))?,
    )))
}

/// Record the unsubscribe routine audit row and sender block via the owning
/// `rust_jmap_unsubscribe_record` PL/pgSQL reducer (retiring direct
/// cross-domain writes to `user_sender_list`, Wave 1.8c #546c).
pub async fn record_unsubscribe(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    envelope: &CommandEnvelope<()>,
    deadline: Instant,
    target: Option<i64>,
    sender: &str,
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            envelope,
            deadline,
            &sql::MESSAGES_RECORD_UNSUBSCRIBE,
            &[&uid, &target, &sender],
            Some(ReceiptCommand {
                family: "jmap",
                command: "message.unsubscribe",
            }),
            |_| Ok(()),
        )
        .await
}
