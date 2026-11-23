//! General `Email/set` writes (JMAP1 #315, Wave 2a #356): multi-phase
//! `create`, `update`, and `destroy` in one locked transaction with the
//! `email_set` audit row, plus per-message `message_snooze` and the R1-scoped
//! attachment-blob ownership check.
//!
//! `jmap_email_set_create`, `jmap_email_set_update`, and
//! `jmap_email_set_destroy` own every mail-table, counter, state, journal, and
//! push effect. The mailbox and actor come from the authenticated context
//! (R1/R2/R3). The audit row carries `details.operation` (owner decision
//! 2026-10-29) inside the same locked transaction (`run_locked_tx`), so an
//! `Unknown` commit can be looked up with [`crate::lookup_set_seen`].
use setjoin_contracts::command::CommandEnvelope;
use setjoin_contracts::ids::OperationId;
use setjoin_pg::{
    operation_hex, run_command, run_locked_tx, CommandOutcome, MailboxAuthContext, Rejection, Row,
    ScopedExecutor, StatementFailure, Type,
};
use std::time::Instant;

use crate::failure::{classify, Failure};

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
    /// Known not committed and not Rust's to answer: forward to Go.
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

/// `$1` mailbox, `$2` actor, `$3` operation ID, `$4` the phase argument.
pub const UPDATE: &str = "WITH audit AS ( \
       INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, message_id, details) \
       VALUES ($1, $2, 'email_set', NULL, jsonb_build_object('operation', $3::text)) RETURNING 1) \
     SELECT r::text FROM jmap_email_set_update($1, $4::text::jsonb) AS r, audit";
pub const DESTROY: &str = "WITH audit AS ( \
       INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, message_id, details) \
       VALUES ($1, $2, 'email_set', NULL, jsonb_build_object('operation', $3::text)) RETURNING 1) \
     SELECT r::text FROM jmap_email_set_destroy($1, $4::bigint[]) AS r, audit";

pub const CREATE_PHASE: &str = "SELECT jmap_email_set_create($1, $2::text::jsonb)::text";
pub const UPDATE_PHASE: &str = "SELECT jmap_email_set_update($1, $2::text::jsonb)::text";
pub const DESTROY_PHASE: &str = "SELECT jmap_email_set_destroy($1, $2::bigint[])::text";
pub const AUDIT: &str = "INSERT INTO mailbox_audit_log \
    (mailbox_id, actor_user_id, action, message_id, details) \
    VALUES ($1, $2, 'email_set', NULL, jsonb_build_object('operation', $3::text))";
pub const SNOOZE: &str = "SELECT message_snooze($1, $2, $3::text::timestamptz)::text";
pub const OWNED_BLOBS: &str = "SELECT q.sha \
    FROM unnest($1::text[]) AS q(sha) \
    WHERE EXISTS ( \
        SELECT 1 FROM blob_user_charges bc \
        WHERE bc.blob_sha256 = q.sha AND bc.user_id = $2 \
    ) OR EXISTS ( \
        SELECT 1 FROM message_attachments ma \
        JOIN messages m ON m.id = ma.message_id \
        JOIN mailboxes mb ON mb.id = m.mailbox_id \
        WHERE ma.blob_sha256 = q.sha AND mb.user_id = $2 \
    )";

/// R1-scoped attachment blob ownership query on the BYPASSRLS worker pool.
/// Returns the subset of `blob_ids` owned by `actor` (uploaded by `actor` or
/// already attached to a message in a mailbox owned by `actor`).
pub async fn owned_blob_set(
    worker: &ScopedExecutor,
    actor: i64,
    blob_ids: &[String],
) -> Result<Vec<String>, StatementFailure> {
    if blob_ids.is_empty() {
        return Ok(Vec::new());
    }
    let ids = blob_ids.to_vec();
    let rows = worker
        .read(
            OWNED_BLOBS,
            &[(&ids, Type::TEXT_ARRAY), (&actor, Type::INT8)],
        )
        .await?;
    let mut owned = Vec::with_capacity(rows.len());
    for row in rows {
        if let Ok(sha) = row.try_get::<_, String>(0) {
            owned.push(sha);
        }
    }
    Ok(owned)
}

#[derive(Debug)]
pub enum SnoozeOutcome {
    Committed,
    Failed(StatementFailure),
    Unknown,
}

/// Run `message_snooze` in its own scoped transaction (matching Go `mail.go`).
pub async fn snooze_message(
    exec: &ScopedExecutor,
    envelope: &CommandEnvelope<EmailSet>,
    auth: &MailboxAuthContext,
    deadline: Instant,
    message_id: i64,
    until_rfc3339: &str,
) -> SnoozeOutcome {
    let mailbox = auth.mailbox().get();
    let until = until_rfc3339.to_owned();
    let outcome = exec
        .run(envelope, auth, deadline, async move |tx| {
            tx.query(
                SNOOZE,
                &[
                    (&mailbox, Type::INT8),
                    (&message_id, Type::INT8),
                    (&until, Type::TEXT),
                ],
            )
            .await?;
            Ok::<_, StatementFailure>(())
        })
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

/// Execute any combination of `create`, ordinary `update`, and `destroy` in one
/// locked transaction, always writing one `email_set` audit row carrying
/// `details.operation` (including for snooze-only and zero-phase calls).
pub async fn email_set_batch(
    exec: &ScopedExecutor,
    envelope: &CommandEnvelope<EmailSet>,
    auth: &MailboxAuthContext,
    deadline: Instant,
    batch: SetBatch<'_>,
) -> SetBatchOutcome {
    let outcome = match (batch.create, batch.update, batch.destroy) {
        (None, Some(patches), None) => {
            run_command(
                exec,
                envelope,
                auth,
                deadline,
                UPDATE,
                &[(&patches, Type::TEXT)],
                |rows| Ok(vec![decode(rows)?]),
            )
            .await
        }
        (None, None, Some(ids)) => {
            let ids = ids.to_vec();
            run_command(
                exec,
                envelope,
                auth,
                deadline,
                DESTROY,
                &[(&ids, Type::INT8_ARRAY)],
                |rows| Ok(vec![decode(rows)?]),
            )
            .await
        }
        _ => {
            let mailbox = auth.mailbox().get();
            let actor = auth.actor().get();
            let op_hex = operation_hex(envelope.operation);
            let create = batch.create.map(str::to_owned);
            let update = batch.update.map(str::to_owned);
            let destroy = batch.destroy.map(<[i64]>::to_vec);
            run_locked_tx(exec, envelope, auth, deadline, async move |tx| {
                let mut parts = Vec::new();
                if let Some(create) = create {
                    let rows = tx
                        .query(
                            CREATE_PHASE,
                            &[(&mailbox, Type::INT8), (&create, Type::TEXT)],
                        )
                        .await?;
                    parts.push(decode(&rows)?);
                }
                if let Some(update) = update {
                    let rows = tx
                        .query(
                            UPDATE_PHASE,
                            &[(&mailbox, Type::INT8), (&update, Type::TEXT)],
                        )
                        .await?;
                    parts.push(decode(&rows)?);
                }
                if let Some(ids) = destroy {
                    let rows = tx
                        .query(
                            DESTROY_PHASE,
                            &[(&mailbox, Type::INT8), (&ids, Type::INT8_ARRAY)],
                        )
                        .await?;
                    parts.push(decode(&rows)?);
                }
                tx.execute(
                    AUDIT,
                    &[
                        (&mailbox, Type::INT8),
                        (&actor, Type::INT8),
                        (&op_hex, Type::TEXT),
                    ],
                )
                .await?;
                Ok(parts)
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
