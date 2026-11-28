//! CalDAV's owned-data backend. All caller identity comes from sealed principals;
//! Resource SQL carries the verified user in the same ownership predicate.
use crate::{actor_scoped_op, command, deadline, user_envelope};
use setjoin_authz::principals::{CalendarCapability, TxFactory, UserPrincipal};
use setjoin_contracts::ids::OperationId;
use setjoin_pg::{CommandOutcome, OperationLookup, Row, StatementFailure};

pub struct Calendar {
    pub id: i64,
    pub mailbox: i64,
    pub name: String,
    pub timezone: String,
}

pub async fn calendars(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<Vec<Calendar>, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::DAV_CALENDARS, &[&uid])
        .await?;
    Ok(rows
        .iter()
        .map(|r| Calendar {
            id: r.get(0),
            mailbox: r.get(1),
            name: r.get(2),
            timezone: r.get(3),
        })
        .collect())
}

pub async fn calendar(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
) -> Result<Option<Calendar>, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::DAV_CALENDAR, &[&id, &uid])
        .await?;
    Ok(rows.first().map(|r| Calendar {
        id: r.get(0),
        mailbox: r.get(1),
        name: r.get(2),
        timezone: r.get(3),
    }))
}

/// Resolve the resource master; detached occurrences never own a resource URI.
pub async fn event(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    calendar: i64,
    uid: &str,
) -> Result<Option<String>, StatementFailure> {
    let user_id = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::DAV_EVENT, &[&calendar, &uid, &user_id])
        .await?;
    Ok(rows.first().map(|r| r.get(0)))
}

/// Decode rows returned by `sql::DAV_TIMEZONE_CATALOG`.
pub fn decode_timezone_catalog(rows: &[Row]) -> Vec<(i64, String, String)> {
    rows.iter()
        .filter_map(|r| Some((r.try_get(0).ok()?, r.try_get(1).ok()?, r.try_get(2).ok()?)))
        .collect()
}

/// The non-cache fallback still checks the current authorized collection.
pub async fn owned_timezone(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    calendar: i64,
    tzid: &str,
) -> Result<Option<String>, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(
            user,
            &crate::sql::DAV_OWNED_TIMEZONE,
            &[&calendar, &tzid, &uid],
        )
        .await?;
    Ok(rows.first().and_then(|r| r.get(0)))
}

/// Ordered detached occurrences sharing the master's UID, under the same owner.
pub async fn overrides(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    calendar: i64,
    uid: &str,
) -> Result<Vec<String>, StatementFailure> {
    let user_id = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(
            user,
            &crate::sql::DAV_OVERRIDES,
            &[&calendar, &uid, &user_id],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// Master resources in the collection, preserving Go's start-order and optional
/// PROPFIND limit. Filter bounds are RFC3339 instants decoded by the adapter.
pub async fn events(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    calendar: i64,
    after: &str,
    before: &str,
    limit: Option<i64>,
) -> Result<Vec<String>, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(
            user,
            &crate::sql::DAV_EVENTS,
            &[&calendar, &uid, &after, &before, &limit],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

pub async fn sync(
    tx_factory: &TxFactory,
    cal: &CalendarCapability,
    calendar: i64,
    since: &str,
) -> Result<Option<String>, StatementFailure> {
    let mailbox = cal.mailbox().get();
    let uid = cal.actor().get();
    let rows = tx_factory
        .run_calendar_read_contract(
            cal,
            &crate::sql::DAV_SYNC,
            &[&mailbox, &calendar, &since, &uid],
        )
        .await?;
    Ok(rows.first().map(|r| r.get(0)))
}

pub async fn free_busy(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    caller_mailbox: i64,
    calendar: i64,
    start: &str,
    end: &str,
) -> Result<(), StatementFailure> {
    let uid = user.user().get();
    tx_factory
        .run_user_read_contract(
            user,
            &crate::sql::DAV_FREE_BUSY,
            &[&caller_mailbox, &calendar, &uid, &start, &end],
        )
        .await?;
    Ok(())
}

fn remap_unknown(
    outcome: CommandOutcome<String, StatementFailure>,
    external: OperationId,
) -> CommandOutcome<String, StatementFailure> {
    match outcome {
        CommandOutcome::Unknown { .. } => CommandOutcome::Unknown {
            operation: external,
        },
        other => other,
    }
}

/// One canonical reducer call under user scope with actor-bound durable receipt.
pub async fn create(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    email: &str,
    calendar: i64,
    payload: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    let external = OperationId(operation);
    let scoped = actor_scoped_op(user.user(), external);
    let env = user_envelope(user, scoped, &format!("create:{calendar}:{payload}"));
    remap_unknown(
        tx_factory
            .run_user_write_contract_pipelined(
                user,
                &env,
                deadline(),
                &crate::sql::DAV_CREATE,
                &[&uid, &calendar, &email, &payload],
                Some(command("caldav-put-create")),
                |rows| {
                    Ok(rows
                        .first()
                        .map(|r| r.get(0))
                        .unwrap_or_else(|| "{}".into()))
                },
            )
            .await,
        external,
    )
}

pub async fn event_etag(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::DAV_EVENT_ETAG, &[&id, &uid])
        .await?;
    Ok(rows.first().map(|r| r.get(0)).unwrap_or_default())
}

pub async fn update(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    calendar: i64,
    event: i64,
    payload: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    let external = OperationId(operation);
    let scoped = actor_scoped_op(user.user(), external);
    let env = user_envelope(
        user,
        scoped,
        &format!("update:{calendar}:{event}:{payload}"),
    );
    remap_unknown(
        tx_factory
            .run_user_write_contract_pipelined(
                user,
                &env,
                deadline(),
                &crate::sql::DAV_UPDATE,
                &[&uid, &calendar, &event, &payload],
                Some(command("caldav-put-update")),
                |rows| {
                    Ok(rows
                        .first()
                        .map(|r| r.get(0))
                        .unwrap_or_else(|| "{}".into()))
                },
            )
            .await,
        external,
    )
}

pub async fn occurrence(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    calendar: i64,
    event: i64,
    instant: &str,
    patch: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    let external = OperationId(operation);
    let scoped = actor_scoped_op(user.user(), external);
    let env = user_envelope(
        user,
        scoped,
        &format!("occurrence:{calendar}:{event}:{instant}:{patch}"),
    );
    remap_unknown(
        tx_factory
            .run_user_write_contract_pipelined(
                user,
                &env,
                deadline(),
                &crate::sql::DAV_OCCURRENCE,
                &[&uid, &calendar, &event, &instant, &patch],
                Some(command("caldav-put-occurrence")),
                |rows| {
                    Ok(rows
                        .first()
                        .map(|r| r.get(0))
                        .unwrap_or_else(|| "{}".into()))
                },
            )
            .await,
        external,
    )
}

pub async fn destroy(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    calendar: i64,
    event: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    let external = OperationId(operation);
    let scoped = actor_scoped_op(user.user(), external);
    let env = user_envelope(user, scoped, &format!("destroy:{calendar}:{event}"));
    remap_unknown(
        tx_factory
            .run_user_write_contract_pipelined(
                user,
                &env,
                deadline(),
                &crate::sql::DAV_DESTROY,
                &[&uid, &calendar, &event],
                Some(command("caldav-delete")),
                |rows| {
                    Ok(rows
                        .first()
                        .map(|r| r.get(0))
                        .unwrap_or_else(|| "{}".into()))
                },
            )
            .await,
        external,
    )
}

/// Go RequireApp's independent, best-effort routine denial audit.
pub async fn blocked_audit(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    ip: &str,
) -> Result<(), StatementFailure> {
    let uid = user.user().get();
    let tag = format!("blocked:{uid}:{ip}");
    let mut op_bytes = [0u8; 16];
    op_bytes.copy_from_slice(&<sha2::Sha256 as sha2::Digest>::digest(tag.as_bytes())[..16]);
    op_bytes[0] |= 1;
    let env = user_envelope(user, OperationId(op_bytes), &tag);
    match tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::DAV_BLOCKED_AUDIT,
            &[&uid, &ip],
            None,
            |_| Ok(()),
        )
        .await
    {
        CommandOutcome::Committed(()) => Ok(()),
        CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e))
        | CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(e)) => Err(e),
        _ => Err(crate::invalid()),
    }
}

/// Receipt categories are code-owned; HTTP input cannot choose arbitrary
/// families or receipt names. Lookup requires a freshly verified user proof.
#[derive(Clone, Copy)]
pub enum Operation {
    Create,
    Update,
    Occurrence,
    Delete,
}
impl Operation {
    fn command(self) -> &'static str {
        match self {
            Self::Create => "caldav-put-create",
            Self::Update => "caldav-put-update",
            Self::Occurrence => "caldav-put-occurrence",
            Self::Delete => "caldav-delete",
        }
    }
}

pub async fn lookup_operation(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    operation: OperationId,
    kind: Operation,
) -> Result<bool, StatementFailure> {
    let scoped = actor_scoped_op(user.user(), operation);
    match tx_factory
        .lookup_user_command(user, scoped, command(kind.command()))
        .await?
    {
        OperationLookup::Committed => Ok(true),
        _ => Ok(false),
    }
}
