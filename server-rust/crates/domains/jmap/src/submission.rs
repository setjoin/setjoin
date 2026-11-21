//! EmailSubmission and REST undo/recall (#317). Reducers own their effects.
use setjoin_pg::{MailboxAuthContext, ScopedExecutor, StatementFailure, Type};

pub async fn get(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    ids: Option<&[i64]>,
) -> Result<String, StatementFailure> {
    let mailbox = auth.mailbox().get();
    let ids = ids.map(<[i64]>::to_vec);
    let rows = exec
        .read_scoped(
            auth,
            "SELECT jmap_email_submission_get($1,$2::bigint[])::text",
            &[(&mailbox, Type::INT8), (&ids, Type::INT8_ARRAY)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.get::<_, Option<String>>(0))
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "submission reducer returned no row".into(),
        })
}

/// Go accepts the filter as JSON; the reducer deliberately ignores it.
pub async fn query(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    filter: Option<&str>,
    position: i32,
    limit: i32,
) -> Result<String, StatementFailure> {
    let mailbox = auth.mailbox().get();
    let rows = exec
        .read_scoped(
            auth,
            "SELECT jmap_email_submission_query($1,$2::text::jsonb,$3,$4)::text",
            &[
                (&mailbox, Type::INT8),
                (&filter, Type::TEXT),
                (&position, Type::INT4),
                (&limit, Type::INT4),
            ],
        )
        .await?;
    rows.first()
        .and_then(|r| r.get::<_, Option<String>>(0))
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "submission reducer returned no row".into(),
        })
}

#[derive(Clone, Copy, Debug)]
pub struct Submission;

/// The same sender-scoped reducer Go calls, with a durable transaction receipt.
pub async fn cancel(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    envelope: &setjoin_contracts::command::CommandEnvelope<Submission>,
    deadline: std::time::Instant,
    email_id: i64,
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "jmap",
            command: "submission.cancel",
        },
        envelope,
        auth,
        deadline,
        "SELECT message_cancel($1,$4)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[(&email_id, Type::INT8)],
        |rows| {
            rows.first()
                .and_then(|r| r.get::<_, Option<String>>(0))
                .ok_or_else(|| StatementFailure {
                    hint: None,
                    sqlstate: None,
                    message: "submission reducer returned no row".into(),
                })
        },
    )
    .await
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessedSize {
    pub creation_id: String,
    pub email_id: i64,
    pub size_bytes: i64,
}

/// Fan-out uses the deployment worker credential (BYPASSRLS), while both
/// sender arguments remain from the authenticated context. The existing
/// reducer authorizes each source message and owns the entire send transaction.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    envelope: &setjoin_contracts::command::CommandEnvelope<Submission>,
    deadline: std::time::Instant,
    create: Option<&str>,
    processed_refs: Option<&str>,
    is_encrypted: Option<&str>,
    processed_sizes: &[ProcessedSize],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    if processed_sizes.is_empty() {
        return setjoin_pg::run_receipted_command(
            exec,
            setjoin_pg::ReceiptCommand {
                family: "jmap",
                command: "submission.set",
            },
            envelope,
            auth,
            deadline,
            "SELECT jmap_email_submission_set($1,$2,$4::text::jsonb,$5::text::jsonb,$6::text::jsonb)::text WHERE $3::text<>''",
            &[
                (&create, Type::TEXT),
                (&processed_refs, Type::TEXT),
                (&is_encrypted, Type::TEXT),
            ],
            |rows| {
                rows.first()
                    .and_then(|r| r.get::<_, Option<String>>(0))
                    .ok_or_else(|| StatementFailure {
                        hint: None,
                        sqlstate: None,
                        message: "submission reducer returned no row".into(),
                    })
            },
        )
        .await;
    }

    let mailbox = auth.mailbox().get();
    let actor = auth.actor().get();
    let op_hex = setjoin_pg::operation_hex(envelope.operation);
    setjoin_pg::run_receipted_effect(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "jmap",
            command: "submission.set",
        },
        envelope,
        auth,
        deadline,
        async move |tx| {
            let mut orig_sizes: Vec<(String, i64, String, i64)> = Vec::new();
            for item in processed_sizes {
                let rows = tx
                    .query(
                        "SELECT raw_ref, size_bytes FROM messages WHERE id = $1 AND mailbox_id = $2 FOR UPDATE",
                        &[(&item.email_id, Type::INT8), (&mailbox, Type::INT8)],
                    )
                    .await?;
                if let Some(row) = rows.first() {
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
                    tx.execute(
                        "UPDATE messages SET size_bytes = $1 WHERE id = $2 AND mailbox_id = $3",
                        &[
                            (&item.size_bytes, Type::INT8),
                            (&item.email_id, Type::INT8),
                            (&mailbox, Type::INT8),
                        ],
                    )
                    .await?;
                    orig_sizes.push((item.creation_id.clone(), item.email_id, orig_ref, orig_size));
                }
            }
            let rows = tx
                .query(
                    "SELECT r.res::text, ARRAY(SELECT jsonb_object_keys(COALESCE(r.res->'notCreated', '{}'::jsonb))) \
                     FROM (SELECT jmap_email_submission_set($1,$2,$4::text::jsonb,$5::text::jsonb,$6::text::jsonb) AS res) r \
                     WHERE $3::text<>''",
                    &[
                        (&mailbox, Type::INT8),
                        (&actor, Type::INT8),
                        (&op_hex, Type::TEXT),
                        (&create, Type::TEXT),
                        (&processed_refs, Type::TEXT),
                        (&is_encrypted, Type::TEXT),
                    ],
                )
                .await?;
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
            for (cid, email_id, orig_ref, orig_size) in orig_sizes {
                if not_created_keys.iter().any(|k| k == &cid) {
                    tx.execute(
                        "UPDATE messages SET size_bytes = $1 WHERE id = $2 AND mailbox_id = $3 AND raw_ref = $4",
                        &[
                            (&orig_size, Type::INT8),
                            (&email_id, Type::INT8),
                            (&mailbox, Type::INT8),
                            (&orig_ref, Type::TEXT),
                        ],
                    )
                    .await?;
                }
            }
            Ok(res_text)
        },
    )
    .await
}

/// Go's undo_send reducer, including its exact queue and tag behavior.
pub async fn undo(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    envelope: &setjoin_contracts::command::CommandEnvelope<Submission>,
    deadline: std::time::Instant,
    email_id: i64,
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "jmap",
            command: "submission.undo",
        },
        envelope,
        auth,
        deadline,
        "SELECT undo_send($1,$4)::text WHERE $2::bigint>0 AND $3::text<>''",
        &[(&email_id, Type::INT8)],
        |rows| {
            rows.first()
                .and_then(|r| r.get::<_, Option<String>>(0))
                .ok_or_else(|| StatementFailure {
                    hint: None,
                    sqlstate: None,
                    message: "submission reducer returned no row".into(),
                })
        },
    )
    .await
}

pub struct RecallSource {
    pub from: String,
    pub received_at: std::time::SystemTime,
    pub mailbox: i64,
    pub message_id: String,
}

/// Recall is scoped to any mailbox owned by the verified user, as Go's
/// metadata gate is. The returned mailbox is never taken from the request.
pub async fn recall_source(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    id: i64,
) -> Result<Option<RecallSource>, StatementFailure> {
    let rows=exec.read(
        "SELECT m.from_addr,m.received_at,m.mailbox_id,m.message_id FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.id=$1 AND mb.user_id=$2",
        &[(&id,Type::INT8),(&auth.actor().get(),Type::INT8)]).await?;
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

pub async fn sender_alias(exec: &ScopedExecutor, auth: &MailboxAuthContext, from: &str) -> bool {
    exec.read("SELECT EXISTS(SELECT 1 FROM aliases a JOIN mailboxes mb ON mb.id=a.mailbox_id WHERE mb.user_id=$1 AND a.email=$2)",
        &[(&auth.actor().get(),Type::INT8),(&from,Type::TEXT)]).await
        .ok().and_then(|rows|rows.first().map(|row|row.get::<_,bool>(0))).unwrap_or(false)
}

/// Auth scope is the mailbox returned by the owner-filtered source lookup.
/// The reducer owns recipient fan-out, recall audit and notifications.
pub async fn recall(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    envelope: &setjoin_contracts::command::CommandEnvelope<Submission>,
    deadline: std::time::Instant,
    message_id: &str,
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "jmap",
            command: "submission.recall",
        },
        envelope,
        auth,
        deadline,
        "SELECT recall_message($4,$2,$1,'user')::text WHERE $3::text<>''",
        &[(&message_id, Type::TEXT)],
        |rows| {
            rows.first()
                .and_then(|row| row.get::<_, Option<String>>(0))
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
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    ids: &[i64],
) -> Result<bool, StatementFailure> {
    let mailbox = auth.mailbox().get();
    let ids = ids.to_vec();
    let rows = exec.read_scoped(auth,
        "SELECT EXISTS(SELECT 1 FROM messages WHERE mailbox_id=$1 AND id=ANY($2::bigint[]) AND has_attachments)",
        &[(&mailbox,Type::INT8),(&ids,Type::INT8_ARRAY)]).await?;
    Ok(rows.first().is_some_and(|row| row.get::<_, bool>(0)))
}
