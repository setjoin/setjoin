//! The `/messages/{id}/*` REST routes (#469): focus, raw download, attachments
//! zip and one-click unsubscribe. Every statement keys ownership on the
//! verified user (`mb.user_id`), never a request field (R1-R3). Reads run on
//! the worker credential because a message may live in any of the user's
//! mailboxes, exactly as frozen Go's `ResolveOwnedMessage` does.
use setjoin_contracts::command::CommandEnvelope;
use setjoin_pg::{
    run_receipted_command, CommandOutcome, MailboxAuthContext, ReceiptCommand, ScopedExecutor,
    StatementFailure, Type,
};
use std::time::Instant;

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

/// `ResolveOwnedMessage`: `None` when the message does not exist or belongs to
/// another user (indistinguishable by design).
pub async fn owned_message(
    exec: &ScopedExecutor,
    user: i64,
    id: i64,
) -> Result<Option<Owned>, StatementFailure> {
    let rows = exec
        .read(
            "SELECT m.raw_ref, m.mailbox_id, COALESCE(m.subject, 'message') FROM messages m \
             JOIN mailboxes mb ON mb.id = m.mailbox_id WHERE m.id = $1 AND mb.user_id = $2",
            &[(&id, Type::INT8), (&user, Type::INT8)],
        )
        .await?;
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
/// reducer call (no check-then-mutate); `auth` is scoped to that mailbox.
/// Zero rows (the message vanished since it was resolved) is the reducer's
/// own `BZ006` not-found.
pub async fn set_focus(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    envelope: &CommandEnvelope<()>,
    deadline: Instant,
    id: i64,
    focused: bool,
) -> CommandOutcome<(), StatementFailure> {
    run_receipted_command(
        exec,
        ReceiptCommand {
            family: "jmap",
            command: "message.focus",
        },
        envelope,
        auth,
        deadline,
        "SELECT set_message_focus(m.id, m.received_at, $5::bool, m.mailbox_id)::text FROM messages m \
         JOIN mailboxes mb ON mb.id = m.mailbox_id \
         WHERE m.id = $4::bigint AND mb.user_id = $2::bigint AND m.mailbox_id = $1::bigint \
         AND $3::text <> ''",
        &[(&id, Type::INT8), (&focused, Type::BOOL)],
        |rows| {
            if rows.is_empty() {
                Err(StatementFailure {
                    hint: None,
                    sqlstate: Some("BZ006".into()),
                    message: "message not found".into(),
                })
            } else {
                Ok(())
            }
        },
    )
    .await
}

/// The non-inline attachments of an owned message in `message_attachments.id`
/// order, and the message subject (`None` when the message has none).
pub struct ZipSource {
    pub entries: Vec<(String, String)>,
    pub subject: Option<String>,
}

pub async fn zip_source(
    exec: &ScopedExecutor,
    user: i64,
    id: i64,
) -> Result<ZipSource, StatementFailure> {
    let rows = exec
        .read(
            "SELECT ma.blob_sha256, COALESCE(ma.filename, 'attachment'), m.subject \
               FROM message_attachments ma \
               JOIN messages m   ON m.id = ma.message_id AND m.received_at = ma.received_at \
               JOIN mailboxes mb ON mb.id = m.mailbox_id \
              WHERE m.id = $1 AND mb.user_id = $2 AND ma.disposition <> 'inline' \
              ORDER BY ma.id",
            &[(&id, Type::INT8), (&user, Type::INT8)],
        )
        .await?;
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

/// The List-Unsubscribe header and From address of an owned message. The id
/// stays text and is cast by PostgreSQL, as pgx hands Go's string to an int8
/// parameter; any error (including a non-numeric id) reads as not found.
pub async fn unsubscribe_source(
    exec: &ScopedExecutor,
    user: i64,
    id: &str,
) -> Result<Option<(String, String)>, StatementFailure> {
    let rows = exec
        .read(
            "SELECT COALESCE(m.list_unsubscribe, ''), COALESCE(m.from_addr, '') FROM messages m \
             JOIN mailboxes mb ON mb.id = m.mailbox_id WHERE m.id = $1::text::bigint AND mb.user_id = $2",
            &[(&id, Type::TEXT), (&user, Type::INT8)],
        )
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    Ok(Some((
        row.try_get(0).map_err(|_| failure("list_unsubscribe"))?,
        row.try_get(1).map_err(|_| failure("from_addr"))?,
    )))
}

/// The unsubscribe audit row and the sender block in one statement (Go writes
/// them as two independent best-effort statements). The block key is the raw
/// `from_addr`, which is what inbound per-user spam matches.
pub async fn record_unsubscribe(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    envelope: &CommandEnvelope<()>,
    deadline: Instant,
    target: Option<i64>,
    sender: &str,
) -> CommandOutcome<(), StatementFailure> {
    run_receipted_command(
        exec,
        ReceiptCommand {
            family: "jmap",
            command: "message.unsubscribe",
        },
        envelope,
        auth,
        deadline,
        "WITH audit AS (SELECT audit_write($2::bigint, 'unsubscribe_newsletter', 'message', $4::bigint, \
             NULL, NULL, NULL, 'List-Unsubscribe POST', 'routine') WHERE $1::bigint > 0 AND $3::text <> ''), \
         blocked AS (INSERT INTO user_sender_list (user_id, sender, list_type) \
             SELECT $2::bigint, $5::text, 'blocked' WHERE $5::text <> '' \
             ON CONFLICT (user_id, sender, list_type) DO NOTHING) \
         SELECT count(*) FROM audit",
        &[(&target, Type::INT8), (&sender, Type::TEXT)],
        |_| Ok(()),
    )
    .await
}
