//! User-scoped Chat reducers. Membership is the authority; mailbox is independent.
use crate::{deadline, envelope, receipt, sql};
use setjoin_authz::principals::{TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, Row, SqlContract, StatementFailure, ToSql};

fn invalid_result() -> StatementFailure {
    StatementFailure {
        hint: None,
        sqlstate: None,
        message: "invalid chat reducer result".into(),
    }
}

fn first_bool(rows: &[Row]) -> Result<bool, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid_result)
}

fn first_string(rows: &[Row]) -> Result<String, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid_result)
}

pub async fn enabled(factory: &TxFactory) -> Result<bool, StatementFailure> {
    let rows = factory
        .run_public_read_contract(&sql::CHAT_ENABLED, &[])
        .await?;
    first_bool(&rows)
}

pub async fn browse(factory: &TxFactory, user: &UserPrincipal) -> Result<String, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::BROWSE_CHANNELS, &[&actor])
        .await?;
    first_string(&rows)
}

pub async fn conversations(
    factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<String, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::CONVERSATION_LIST, &[&actor])
        .await?;
    first_string(&rows)
}

pub async fn drive_enabled(factory: &TxFactory) -> Result<bool, StatementFailure> {
    let rows = factory
        .run_public_read_contract(&sql::DRIVE_ENABLED, &[])
        .await?;
    first_bool(&rows)
}

pub async fn roster(
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
) -> Result<String, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::CHANNEL_ROSTER, &[&actor, &channel])
        .await?;
    first_string(&rows)
}

pub async fn mention_search(
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    query: &str,
) -> Result<String, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::MENTION_SEARCH, &[&actor, &channel, &query])
        .await?;
    first_string(&rows)
}

pub async fn pins(
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
) -> Result<String, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::PINS_LIST, &[&actor, &channel])
        .await?;
    first_string(&rows)
}

pub async fn readers(
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
) -> Result<String, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::CHANNEL_READERS, &[&actor, &channel])
        .await?;
    first_string(&rows)
}

pub async fn messages(
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    before: Option<i64>,
    limit: Option<i64>,
    around: Option<i64>,
) -> Result<String, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(
            user,
            &sql::MESSAGES_LIST,
            &[&actor, &channel, &before, &limit, &around],
        )
        .await?;
    first_string(&rows)
}

/// Rows and high-water mark share one MVCC snapshot, including hidden edits.
pub async fn since(
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    seq: Option<i64>,
) -> Result<(String, i64), StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::MESSAGES_SINCE, &[&actor, &channel, &seq])
        .await?;
    let row = rows.first().ok_or_else(invalid_result)?;
    Ok((
        row.try_get(0).map_err(|_| invalid_result())?,
        row.try_get(1).map_err(|_| invalid_result())?,
    ))
}

async fn mutate<T, D>(
    factory: &TxFactory,
    user: &UserPrincipal,
    operation: [u8; 16],
    name: &'static str,
    contract: &'static SqlContract,
    values: &[&(dyn ToSql + Sync)],
    decode: D,
) -> CommandOutcome<T, StatementFailure>
where
    D: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
{
    let env = envelope(user.user(), user.generation(), operation, name);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            contract,
            values,
            Some(receipt(name)),
            decode,
        )
        .await
}

pub async fn create(
    factory: &TxFactory,
    user: &UserPrincipal,
    name: &str,
    topic: Option<String>,
    visibility: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "chat_channel_create",
        &sql::CHANNEL_CREATE,
        &[&actor, &name, &topic, &visibility],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid_result)
        },
    )
    .await
}

pub async fn join(
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "chat_channel_join",
        &sql::CHANNEL_JOIN,
        &[&actor, &channel],
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
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "chat_typing_signal",
        &sql::TYPING_SIGNAL,
        &[&actor, &channel],
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
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    value: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "chat_mark_read",
        &sql::MARK_READ,
        &[&actor, &channel, &value],
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
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    value: String,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "chat_member_set_notif",
        &sql::MEMBER_SET_NOTIF,
        &[&actor, &channel, &value],
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
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    value: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "chat_member_add",
        &sql::MEMBER_ADD,
        &[&actor, &channel, &value],
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
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    patch: ChannelPatch,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "chat_channel_update",
        &sql::CHANNEL_UPDATE,
        &[
            &actor,
            &channel,
            &patch.name,
            &patch.topic,
            &patch.archived,
            &patch.post_permission,
            &patch.broadcast_permission,
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
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    target: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "chat_member_remove",
        &sql::MEMBER_REMOVE,
        &[&actor, &channel, &target],
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
    factory: &TxFactory,
    user: &UserPrincipal,
    others: Option<Vec<i64>>,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "chat_dm_open",
        &sql::DM_OPEN,
        &[&actor, &others],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid_result)
        },
    )
    .await
}

pub async fn space(
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "chat_space_ensure",
        &sql::SPACE_ENSURE,
        &[&actor, &channel],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid_result)
        },
    )
    .await
}

pub async fn preview(
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    email: &str,
) -> Result<String, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::GUEST_PREVIEW, &[&actor, &channel, &email])
        .await?;
    first_string(&rows)
}

#[allow(clippy::too_many_arguments)]
pub async fn send(
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    body: String,
    parent: Option<i64>,
    mentions: Vec<i64>,
    broadcast: Option<String>,
    attachments: String,
    msg_type: String,
    payload: Option<String>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "chat_message_send",
        &sql::MESSAGE_SEND,
        &[
            &actor,
            &channel,
            &body,
            &parent,
            &mentions,
            &broadcast,
            &attachments,
            &msg_type,
            &payload,
        ],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid_result)
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn poll(
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    question: String,
    options: Option<Vec<String>>,
    multi: bool,
    closes: Option<String>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "chat_poll_create",
        &sql::POLL_CREATE,
        &[&actor, &channel, &question, &options, &multi, &closes],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid_result)
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn schedule(
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    body: String,
    parent: Option<i64>,
    mentions: Vec<i64>,
    broadcast: Option<String>,
    fire: Option<String>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "chat_schedule_message",
        &sql::SCHEDULE_MESSAGE,
        &[
            &actor, &channel, &body, &parent, &mentions, &broadcast, &fire,
        ],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid_result)
        },
    )
    .await
}

pub async fn federation_enabled(factory: &TxFactory) -> Result<bool, StatementFailure> {
    let rows = factory
        .run_public_read_contract(&sql::FEDERATION_ENABLED, &[])
        .await?;
    first_bool(&rows)
}

pub async fn federated_dm(
    factory: &TxFactory,
    user: &UserPrincipal,
    remote: String,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "federation_dm_ensure",
        &sql::FEDERATION_DM_ENSURE,
        &[&actor, &remote],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid_result)
        },
    )
    .await
}

pub async fn federation_bind(
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    domain: String,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "federation_room_create",
        &sql::FEDERATION_ROOM_CREATE,
        &[&actor, &channel, &domain],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid_result)
        },
    )
    .await
}

pub async fn federation_roster(
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
) -> Result<String, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::FEDERATION_ROOM_ROSTER, &[&actor, &channel])
        .await?;
    first_string(&rows)
}

pub async fn federation_invite(
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    domain: String,
    contact: String,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "federation_room_invite",
        &sql::FEDERATION_ROOM_INVITE,
        &[&actor, &channel, &domain, &contact],
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
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    domain: String,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    mutate(
        factory,
        user,
        operation,
        "federation_room_remove",
        &sql::FEDERATION_ROOM_REMOVE,
        &[&actor, &channel, &domain],
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
