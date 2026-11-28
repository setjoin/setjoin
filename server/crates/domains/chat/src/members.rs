//! End-user Chat: verified user identity, request credential and canonical reducers.
use crate::{deadline, envelope, receipt, sql};
use setjoin_authz::principals::{TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, SqlContract, StatementFailure, ToSql};

fn invalid_chat_result() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        message: "invalid Chat result".into(),
        hint: None,
    }
}

fn first_text(rows: &[setjoin_pg::Row]) -> Result<String, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .ok_or_else(invalid_chat_result)
}

pub async fn app_entitled(
    factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<bool, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::APP_ENTITLED, &[&actor])
        .await?;
    Ok(rows
        .first()
        .is_some_and(|r| r.try_get::<_, bool>(0).unwrap_or(false)))
}

pub async fn unfurl_enabled(factory: &TxFactory) -> Result<bool, StatementFailure> {
    let rows = factory
        .run_public_read_contract(&sql::UNFURL_ENABLED, &[])
        .await?;
    Ok(rows
        .first()
        .is_some_and(|r| r.try_get::<_, bool>(0).unwrap_or(false)))
}

pub async fn saves(factory: &TxFactory, user: &UserPrincipal) -> Result<String, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::SAVES_LIST, &[&actor])
        .await?;
    first_text(&rows)
}

async fn member_command(
    factory: &TxFactory,
    user: &UserPrincipal,
    name: &'static str,
    contract: &'static SqlContract,
    values: &[&(dyn ToSql + Sync)],
    operation: [u8; 16],
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    let env = envelope(user.user(), user.generation(), operation, name);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            contract,
            values,
            Some(receipt(name)),
            |rows| {
                let raw = rows
                    .first()
                    .and_then(|r| r.try_get::<_, String>(0).ok())
                    .ok_or_else(|| StatementFailure {
                        sqlstate: None,
                        message: "invalid Chat result".into(),
                        hint: None,
                    })?;
                serde_json::from_str(&raw).map_err(|_| StatementFailure {
                    sqlstate: None,
                    message: "invalid Chat result".into(),
                    hint: None,
                })
            },
        )
        .await
}

/// Personal bookmark toggle. The canonical reducer owns authorization and effects.
pub async fn save(
    factory: &TxFactory,
    user: &UserPrincipal,
    message: i64,
    operation: [u8; 16],
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    let actor = user.user().get();
    member_command(
        factory,
        user,
        "chat_save_toggle",
        &sql::SAVE_TOGGLE,
        &[&actor, &message],
        operation,
    )
    .await
}

pub async fn thread(
    factory: &TxFactory,
    user: &UserPrincipal,
    message: i64,
) -> Result<String, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::THREAD_LIST, &[&actor, &message])
        .await?;
    first_text(&rows)
}

pub async fn my_threads(
    factory: &TxFactory,
    user: &UserPrincipal,
    limit: Option<i64>,
) -> Result<String, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::MY_THREADS, &[&actor, &limit])
        .await?;
    first_text(&rows)
}

pub struct Search<'a> {
    pub query: &'a str,
    pub channel: Option<i64>,
    pub author: Option<i64>,
    pub before: Option<i64>,
    pub has: Option<String>,
    pub han: bool,
}

pub async fn search(
    factory: &TxFactory,
    user: &UserPrincipal,
    search: Search<'_>,
) -> Result<String, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(
            user,
            &sql::SEARCH,
            &[
                &actor,
                &search.query,
                &search.channel,
                &search.author,
                &search.before,
                &search.has,
                &search.han,
            ],
        )
        .await?;
    first_text(&rows)
}

pub async fn edit(
    factory: &TxFactory,
    user: &UserPrincipal,
    message: i64,
    body: &str,
    operation: [u8; 16],
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    let actor = user.user().get();
    member_command(
        factory,
        user,
        "chat_message_edit",
        &sql::MESSAGE_EDIT,
        &[&actor, &message, &body],
        operation,
    )
    .await
}

pub async fn delete(
    factory: &TxFactory,
    user: &UserPrincipal,
    message: i64,
    operation: [u8; 16],
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    let actor = user.user().get();
    member_command(
        factory,
        user,
        "chat_message_delete",
        &sql::MESSAGE_DELETE,
        &[&actor, &message],
        operation,
    )
    .await
}

pub async fn reaction(
    factory: &TxFactory,
    user: &UserPrincipal,
    message: i64,
    emoji: &str,
    operation: [u8; 16],
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    let actor = user.user().get();
    member_command(
        factory,
        user,
        "chat_reaction_toggle",
        &sql::REACTION_TOGGLE,
        &[&actor, &message, &emoji],
        operation,
    )
    .await
}

pub async fn pin(
    factory: &TxFactory,
    user: &UserPrincipal,
    message: i64,
    operation: [u8; 16],
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    let actor = user.user().get();
    member_command(
        factory,
        user,
        "chat_pin_toggle",
        &sql::PIN_TOGGLE,
        &[&actor, &message],
        operation,
    )
    .await
}

/// `translate.egress` intent record, written before message text leaves for
/// the AI provider (frozen Go `translateMessage`, active only while
/// `feature.chat_compliance` is ON). `after` is the JSON text Go marshals.
pub async fn translate_egress(
    factory: &TxFactory,
    user: &UserPrincipal,
    channel: i64,
    message: i64,
    after: &str,
    operation: [u8; 16],
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    let actor = user.user().get();
    member_command(
        factory,
        user,
        "chat_access_audit_translate",
        &sql::TRANSLATE_EGRESS,
        &[&actor, &channel, &message, &after],
        operation,
    )
    .await
}

pub async fn scheduled(
    factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<String, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::SCHEDULED_LIST, &[&actor])
        .await?;
    first_text(&rows)
}

pub async fn cancel(
    factory: &TxFactory,
    user: &UserPrincipal,
    action: &str,
    operation: [u8; 16],
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    let actor = user.user().get();
    member_command(
        factory,
        user,
        "chat_scheduled_cancel",
        &sql::SCHEDULED_CANCEL,
        &[&actor, &action],
        operation,
    )
    .await
}

pub async fn vote(
    factory: &TxFactory,
    user: &UserPrincipal,
    poll: i64,
    option: i64,
    operation: [u8; 16],
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    let actor = user.user().get();
    member_command(
        factory,
        user,
        "chat_poll_vote",
        &sql::POLL_VOTE,
        &[&actor, &poll, &option],
        operation,
    )
    .await
}

pub async fn close(
    factory: &TxFactory,
    user: &UserPrincipal,
    poll: i64,
    operation: [u8; 16],
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    let actor = user.user().get();
    member_command(
        factory,
        user,
        "chat_poll_close",
        &sql::POLL_CLOSE,
        &[&actor, &poll],
        operation,
    )
    .await
}

pub async fn results(
    factory: &TxFactory,
    user: &UserPrincipal,
    poll: i64,
) -> Result<String, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::POLL_RESULTS, &[&actor, &poll])
        .await?;
    first_text(&rows)
}

/// Frozen Go authorizes any successful global preview-cache image. The
/// authenticated Chat-capability gate precedes this explicit shared-cache read.
pub async fn image_type(
    factory: &TxFactory,
    user: &UserPrincipal,
    hash: &str,
) -> Result<Option<String>, StatementFailure> {
    let rows = factory
        .run_user_read_contract(user, &sql::IMAGE_TYPE, &[&hash])
        .await?;
    Ok(rows.first().and_then(|r| r.try_get(0).ok()))
}

/// Go's independent routine denial audit. Failure never changes the denial;
/// the canonical reducer owns audit-policy suppression and the chain row.
pub async fn app_blocked(factory: &TxFactory, user: &UserPrincipal, ip: &str, operation: [u8; 16]) {
    let actor = user.user().get();
    let _ = member_command(
        factory,
        user,
        "app_blocked",
        &sql::APP_BLOCKED,
        &[&actor, &ip],
        operation,
    )
    .await;
}

/// Global URL cache, as in Go. The actor is the committed send's verified actor;
/// URL possession is the cache capability, independent of channel membership.
pub async fn unfurl_lookup(
    factory: &TxFactory,
    user: &UserPrincipal,
    hash: &str,
) -> Result<Option<serde_json::Value>, StatementFailure> {
    let rows = factory
        .run_user_read_contract(user, &sql::UNFURL_LOOKUP, &[&hash])
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, Option<String>>(0).ok().flatten())
        .map(|raw| {
            serde_json::from_str(&raw).map_err(|_| StatementFailure {
                sqlstate: None,
                message: "invalid unfurl cache JSON".into(),
                hint: None,
            })
        })
        .transpose()
}

/// Only a message ID returned by this actor's committed send reaches this seam.
/// The canonical reducer owns gone/GxP checks, provenance and notifications.
pub async fn unfurl_apply(
    factory: &TxFactory,
    user: &UserPrincipal,
    message: i64,
    hash: &str,
    operation: [u8; 16],
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    member_command(
        factory,
        user,
        "chat_message_unfurl_apply",
        &sql::UNFURL_APPLY,
        &[&message, &hash],
        operation,
    )
    .await
}

pub async fn unfurl_claim(
    factory: &TxFactory,
    user: &UserPrincipal,
    hash: &str,
    url: &str,
    operation: [u8; 16],
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    member_command(
        factory,
        user,
        "chat_link_preview_claim",
        &sql::UNFURL_CLAIM,
        &[&hash, &url],
        operation,
    )
    .await
}

pub struct FetchedPreview {
    pub title: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    pub ok: bool,
}

pub async fn unfurl_write(
    factory: &TxFactory,
    user: &UserPrincipal,
    hash: &str,
    preview: &FetchedPreview,
    operation: [u8; 16],
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    let status = if preview.ok { "ok" } else { "error" };
    member_command(
        factory,
        user,
        "chat_link_preview_cache_write",
        &sql::UNFURL_WRITE,
        &[
            &hash,
            &preview.title,
            &preview.description,
            &preview.image,
            &status,
        ],
        operation,
    )
    .await
}

/// Content-addressed blob metadata registration paired with per-sha256 GC advisory lock +
/// reactivation (#550/#551) via `blob_gc_register_and_reactivate`.
#[allow(clippy::too_many_arguments)]
pub async fn unfurl_blob(
    factory: &TxFactory,
    user: &UserPrincipal,
    hash: &str,
    reference: &str,
    size: i64,
    content_type: &str,
    operation: [u8; 16],
) -> CommandOutcome<serde_json::Value, StatementFailure> {
    member_command(
        factory,
        user,
        "chat_unfurl_blob_insert",
        &sql::UNFURL_BLOB,
        &[&hash, &reference, &size, &content_type],
        operation,
    )
    .await
}
