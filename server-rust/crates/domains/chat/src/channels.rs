//! User-scoped Chat reducers. Membership is the authority; mailbox is independent.
use setjoin_authz::AuthContext;
use setjoin_pg::{MailboxAuthContext, ScopedExecutor, StatementFailure, Type};

fn scope(actor: &AuthContext) -> MailboxAuthContext {
    actor.database_scope()
}

pub async fn enabled(exec: &ScopedExecutor) -> Result<bool, StatementFailure> {
    Ok(exec
        .read(
            "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.chat'),false)",
            &[],
        )
        .await?[0]
        .get(0))
}

pub async fn browse(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT chat_browse_channels($1)::text",
            &[(&user, Type::INT8)],
        )
        .await?;
    Ok(rows[0].get(0))
}

pub async fn conversations(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    Ok(exec
        .read_scoped(
            &scope(actor),
            "SELECT chat_conversation_list($1)::text",
            &[(&user, Type::INT8)],
        )
        .await?[0]
        .get(0))
}

pub async fn drive_enabled(exec: &ScopedExecutor) -> Result<bool, StatementFailure> {
    Ok(exec.read("SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.drive'),false)",&[]).await?[0].get(0))
}

pub async fn roster(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    Ok(exec
        .read_scoped(
            &scope(actor),
            "SELECT chat_channel_roster($1,$2)::text",
            &[(&user, Type::INT8), (&channel, Type::INT8)],
        )
        .await?[0]
        .get(0))
}

pub async fn mention_search(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    query: &str,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    Ok(exec
        .read_scoped(
            &scope(actor),
            "SELECT chat_mention_search($1,$2,$3)::text",
            &[
                (&user, Type::INT8),
                (&channel, Type::INT8),
                (&query, Type::TEXT),
            ],
        )
        .await?[0]
        .get(0))
}

pub async fn pins(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    Ok(exec
        .read_scoped(
            &scope(actor),
            "SELECT chat_pins_list($1,$2)::text",
            &[(&user, Type::INT8), (&channel, Type::INT8)],
        )
        .await?[0]
        .get(0))
}

pub async fn readers(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    Ok(exec
        .read_scoped(
            &scope(actor),
            "SELECT chat_channel_readers($1,$2)::text",
            &[(&user, Type::INT8), (&channel, Type::INT8)],
        )
        .await?[0]
        .get(0))
}

pub async fn messages(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    before: Option<i64>,
    limit: Option<i64>,
    around: Option<i64>,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    Ok(exec
        .read_scoped(
            &scope(actor),
            "SELECT chat_messages_list($1,$2,$3,$4::bigint::integer,$5)::text",
            &[
                (&user, Type::INT8),
                (&channel, Type::INT8),
                (&before, Type::INT8),
                (&limit, Type::INT8),
                (&around, Type::INT8),
            ],
        )
        .await?[0]
        .get(0))
}

/// Rows and high-water mark share one MVCC snapshot, including hidden edits.
pub async fn since(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    seq: Option<i64>,
) -> Result<(String, i64), StatementFailure> {
    let user = actor.user_id();
    let rows=exec.read_scoped(&scope(actor),"SELECT chat_messages_since($1,$2,$3)::text,coalesce((SELECT change_seq FROM chat_channels c WHERE c.id=$2 AND EXISTS(SELECT 1 FROM chat_channel_members m WHERE m.channel_id=c.id AND m.user_id=$1)),0)",&[(&user,Type::INT8),(&channel,Type::INT8),(&seq,Type::INT8)]).await?;
    Ok((rows[0].get(0), rows[0].get(1)))
}

async fn mutate<T, D>(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    operation: [u8; 16],
    name: &'static str,
    sql: &'static str,
    params: &[setjoin_pg::Param<'_>],
    decode: D,
) -> setjoin_pg::CommandOutcome<T, StatementFailure>
where
    D: FnOnce(&[setjoin_pg::Row]) -> Result<T, StatementFailure>,
{
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(name.as_bytes()).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "F12",
            command: name,
        },
        &envelope,
        &auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        sql,
        params,
        decode,
    )
    .await
}
fn invalid_result() -> StatementFailure {
    StatementFailure {
        hint: None,
        sqlstate: None,
        message: "invalid chat reducer result".into(),
    }
}
pub async fn create(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    name: &str,
    topic: Option<String>,
    visibility: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "chat_channel_create",
        "SELECT chat_channel_create($2,$4,$5,$6) WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&name, Type::TEXT),
            (&topic, Type::TEXT),
            (&visibility, Type::TEXT),
        ],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid_result)
        },
    )
    .await
}

pub async fn join(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "chat_channel_join",
        "SELECT chat_channel_join($2,$4) WHERE $2::bigint>0 AND $3::text<>''",
        &[(&channel, Type::INT8)],
        |rows| {
            if rows.is_empty() {
                Err(invalid_result())
            } else {
                Ok(())
            }
        },
    )
    .await
}

pub async fn typing(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "chat_typing_signal",
        "SELECT chat_typing_signal($2,$4) WHERE $2::bigint>0 AND $3::text<>''",
        &[(&channel, Type::INT8)],
        |rows| {
            if rows.is_empty() {
                Err(invalid_result())
            } else {
                Ok(())
            }
        },
    )
    .await
}

pub async fn mark_read(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    value: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "chat_mark_read",
        "SELECT chat_mark_read($2,$4,$5) WHERE $2::bigint>0 AND $3::text<>''",
        &[(&channel, Type::INT8), (&value, Type::INT8)],
        |rows| {
            if rows.is_empty() {
                Err(invalid_result())
            } else {
                Ok(())
            }
        },
    )
    .await
}

pub async fn notif(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    value: String,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "chat_member_set_notif",
        "SELECT chat_member_set_notif($2,$4,$5) WHERE $2::bigint>0 AND $3::text<>''",
        &[(&channel, Type::INT8), (&value, Type::TEXT)],
        |rows| {
            if rows.is_empty() {
                Err(invalid_result())
            } else {
                Ok(())
            }
        },
    )
    .await
}

pub async fn add_member(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    value: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "chat_member_add",
        "SELECT chat_member_add($2,$4,$5) WHERE $2::bigint>0 AND $3::text<>''",
        &[(&channel, Type::INT8), (&value, Type::INT8)],
        |rows| {
            if rows.is_empty() {
                Err(invalid_result())
            } else {
                Ok(())
            }
        },
    )
    .await
}

pub struct ChannelPatch {
    pub name: Option<String>,
    pub topic: Option<String>,
    pub archived: Option<bool>,
    pub post_permission: Option<String>,
    pub broadcast_permission: Option<String>,
}
pub async fn update(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    patch: ChannelPatch,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "chat_channel_update",
        "SELECT chat_channel_update($2,$4,$5,$6,$7,$8,$9) WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&channel, Type::INT8),
            (&patch.name, Type::TEXT),
            (&patch.topic, Type::TEXT),
            (&patch.archived, Type::BOOL),
            (&patch.post_permission, Type::TEXT),
            (&patch.broadcast_permission, Type::TEXT),
        ],
        |rows| {
            if rows.is_empty() {
                Err(invalid_result())
            } else {
                Ok(())
            }
        },
    )
    .await
}

pub async fn remove_member(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    target: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "chat_member_remove",
        "SELECT chat_member_remove($2,$4,$5) WHERE $2::bigint>0 AND $3::text<>''",
        &[(&channel, Type::INT8), (&target, Type::INT8)],
        |rows| {
            if rows.is_empty() {
                Err(invalid_result())
            } else {
                Ok(())
            }
        },
    )
    .await
}

pub async fn dm(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    others: Option<Vec<i64>>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "chat_dm_open",
        "SELECT chat_dm_open($2,$4) WHERE $2::bigint>0 AND $3::text<>''",
        &[(&others, Type::INT8_ARRAY)],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid_result)
        },
    )
    .await
}

pub async fn space(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "chat_space_ensure",
        "SELECT chat_space_ensure($2,$4) WHERE $2::bigint>0 AND $3::text<>''",
        &[(&channel, Type::INT8)],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid_result)
        },
    )
    .await
}

pub async fn preview(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    email: &str,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    Ok(exec
        .read_scoped(
            &scope(actor),
            "SELECT chat_guest_preview($1,$2,$3)::text",
            &[
                (&user, Type::INT8),
                (&channel, Type::INT8),
                (&email, Type::TEXT),
            ],
        )
        .await?[0]
        .get(0))
}

#[allow(clippy::too_many_arguments)]
pub async fn send(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    body: String,
    parent: Option<i64>,
    mentions: Vec<i64>,
    broadcast: Option<String>,
    attachments: String,
    msg_type: String,
    payload: Option<String>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(exec,actor,operation,"chat_message_send","SELECT chat_message_send($2,$4,$5,$6,$7,$8,$9::text::jsonb,$10,$11::text::jsonb)::text WHERE $2::bigint>0 AND $3::text<>''",&[(&channel,Type::INT8),(&body,Type::TEXT),(&parent,Type::INT8),(&mentions,Type::INT8_ARRAY),(&broadcast,Type::TEXT),(&attachments,Type::TEXT),(&msg_type,Type::TEXT),(&payload,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid_result)).await
}

#[allow(clippy::too_many_arguments)]
pub async fn poll(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    question: String,
    options: Option<Vec<String>>,
    multi: bool,
    closes: Option<String>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(exec,actor,operation,"chat_poll_create","SELECT chat_poll_create($2,$4,$5,$6,$7,$8::text::timestamptz)::text WHERE $2::bigint>0 AND $3::text<>''",&[(&channel,Type::INT8),(&question,Type::TEXT),(&options,Type::TEXT_ARRAY),(&multi,Type::BOOL),(&closes,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid_result)).await
}

#[allow(clippy::too_many_arguments)]
pub async fn schedule(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    body: String,
    parent: Option<i64>,
    mentions: Vec<i64>,
    broadcast: Option<String>,
    fire: Option<String>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(exec,actor,operation,"chat_schedule_message","SELECT jsonb_build_object('actionId',chat_schedule_message($2,$4,$5,$6,$7,$8,$9::text::timestamptz))::text WHERE $2::bigint>0 AND $3::text<>''",&[(&channel,Type::INT8),(&body,Type::TEXT),(&parent,Type::INT8),(&mentions,Type::INT8_ARRAY),(&broadcast,Type::TEXT),(&fire,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid_result)).await
}

pub async fn federation_enabled(exec: &ScopedExecutor) -> Result<bool, StatementFailure> {
    Ok(exec.read("SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.federation'),false)",&[]).await?[0].get(0))
}
pub async fn federated_dm(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    remote: String,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "federation_dm_ensure",
        "SELECT federation_dm_ensure($2,$4) WHERE $2::bigint>0 AND $3::text<>''",
        &[(&remote, Type::TEXT)],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid_result)
        },
    )
    .await
}

pub async fn federation_bind(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    domain: String,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    mutate(exec,actor,operation,"federation_room_create","SELECT jsonb_build_object('roomId',federation_room_create($2,$4,$5))::text WHERE $2::bigint>0 AND $3::text<>''",&[(&channel,Type::INT8),(&domain,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid_result)).await
}

pub async fn federation_roster(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    Ok(exec
        .read_scoped(
            &scope(actor),
            "SELECT federation_room_roster($1,$2)::text",
            &[(&user, Type::INT8), (&channel, Type::INT8)],
        )
        .await?[0]
        .get(0))
}

pub async fn federation_invite(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    domain: String,
    contact: String,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "federation_room_invite",
        "SELECT federation_room_invite($2,$4,$5,$6) WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&channel, Type::INT8),
            (&domain, Type::TEXT),
            (&contact, Type::TEXT),
        ],
        |rows| {
            if rows.is_empty() {
                Err(invalid_result())
            } else {
                Ok(())
            }
        },
    )
    .await
}

pub async fn federation_remove(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    channel: i64,
    domain: String,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    mutate(
        exec,
        actor,
        operation,
        "federation_room_remove",
        "SELECT federation_room_remove($2,$4,$5) WHERE $2::bigint>0 AND $3::text<>''",
        &[(&channel, Type::INT8), (&domain, Type::TEXT)],
        |rows| {
            if rows.is_empty() {
                Err(invalid_result())
            } else {
                Ok(())
            }
        },
    )
    .await
}
