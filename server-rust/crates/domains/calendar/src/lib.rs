//! Calendar and DAV over HTTP (F17), slice 1: calendar subscriptions, batch
//! free/busy and self-service booking.
//!
//! Foundation dependencies only. The actor and mailbox of every authenticated
//! call come from sealed capability principals; request fields name targets and
//! never grant authority. Canonical PL/pgSQL reducers keep the business logic
//! (`booking_*`, `calendar_free_busy_multi`); this crate only calls them the way
//! frozen Go does and returns their JSON text unchanged.
#![forbid(unsafe_code)]
pub mod carddav;
pub mod contacts;
pub mod dav;
pub mod sql;
pub use sql::SQL_CONTRACTS;

use setjoin_authz::principals::{CalendarCapability, TxFactory, UserPrincipal};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, OperationId},
};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Row, StatementFailure};
use sha2::{Digest as _, Sha256};

/// Go's `maxCalendarSubscriptionsPerUser` (`mailserverd/main.go`).
pub const MAX_SUBSCRIPTIONS_PER_USER: i64 = 25;

/// The SQL of the booking-expiry sweep (Go's `Sweeper`), one fixed statement.
pub const EXPIRE_DUE: &str = sql::BOOKING_EXPIRE_DUE.sql;

pub(crate) fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid calendar result".into(),
    }
}

pub(crate) fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}

pub(crate) fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: "F17",
        command: name,
    }
}

pub(crate) fn calendar_envelope(
    cal: &CalendarCapability,
    operation: [u8; 16],
    payload: &str,
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: AuthorityKey {
            actor: cal.actor(),
            scope: ResourceScope::Mailbox(cal.mailbox()),
            generation: Generation(1),
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(payload.as_bytes()).into()),
        command: (),
    }
}

pub(crate) fn user_envelope(
    user: &UserPrincipal,
    operation: OperationId,
    payload: &str,
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation,
        authority: AuthorityKey {
            actor: user.user(),
            scope: ResourceScope::User(user.user()),
            generation: Generation(1),
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(payload.as_bytes()).into()),
        command: (),
    }
}

/// Derive the actor-bound receipt operation ID so another actor cannot probe
/// whether an operation ID committed for a different user.
pub(crate) fn actor_scoped_op(actor: ActorId, operation: OperationId) -> OperationId {
    let hex = setjoin_pg::operation_hex(operation);
    let digest = Sha256::digest(format!("{hex}:{}", actor.get()).as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    OperationId(bytes)
}

pub fn decode_text0(rows: &[Row]) -> Result<String, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .ok_or_else(invalid)
}

pub fn decode_public_get(rows: &[Row]) -> Result<Option<String>, StatementFailure> {
    let out = decode_text0(rows)?;
    Ok((out != "null").then_some(out))
}

/// A feature toggle row, absent meaning the registry default (`default`).
pub async fn flag(
    tx_factory: &TxFactory,
    key: &str,
    default: bool,
) -> Result<bool, StatementFailure> {
    let rows = tx_factory
        .run_public_read_contract(&sql::FLAG, &[&key])
        .await?;
    Ok(rows.first().map_or(default, |r| r.get(0)))
}

/// `feature.booking_pages` (default OFF).
pub async fn booking_enabled(tx_factory: &TxFactory) -> Result<bool, StatementFailure> {
    flag(tx_factory, "feature.booking_pages", false).await
}

/// `feature.caldav` (default ON): Go mounts free/busy only when it is on.
pub async fn caldav_enabled(tx_factory: &TxFactory) -> Result<bool, StatementFailure> {
    flag(tx_factory, "feature.caldav", true).await
}

/// Go's `RequireApp("calendar")`: `check_user_app_entitlement` on the request pool.
pub async fn entitled(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<bool, StatementFailure> {
    entitled_app(tx_factory, user, "calendar").await
}

/// Go's `RequireApp(app)`: `check_user_app_entitlement` for the verified user.
pub async fn entitled_app(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    app: &str,
) -> Result<bool, StatementFailure> {
    let uid = user.user().get();
    Ok(tx_factory
        .run_user_read_contract(user, &sql::ENTITLED_APP, &[&uid, &app])
        .await?
        .first()
        .is_some_and(|r| r.get(0)))
}

// ---- booking pages: owner surface (mailbox scope) ----

/// `booking_page_list` for the caller's primary mailbox.
pub async fn page_list(
    tx_factory: &TxFactory,
    cal: &CalendarCapability,
) -> Result<String, StatementFailure> {
    let mailbox = cal.mailbox().get();
    decode_text0(
        &tx_factory
            .run_calendar_read_contract(cal, &sql::PAGE_LIST, &[&mailbox])
            .await?,
    )
}

/// `booking_page_upsert(mailbox, page)`: Go's whole transaction is this one
/// reducer call. `page` is the raw request JSON, cast to jsonb by the server.
pub async fn page_upsert(
    tx_factory: &TxFactory,
    cal: &CalendarCapability,
    page: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let mailbox = cal.mailbox().get();
    let env = calendar_envelope(cal, operation, page);
    tx_factory
        .run_calendar_write_contract_pipelined(
            cal,
            &env,
            deadline(),
            &sql::PAGE_UPSERT,
            &[&mailbox, &page],
            Some(command("booking_page_upsert")),
            |rows| decode_text0(&rows),
        )
        .await
}

/// `booking_page_delete(mailbox, id)`.
pub async fn page_delete(
    tx_factory: &TxFactory,
    cal: &CalendarCapability,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let mailbox = cal.mailbox().get();
    let env = calendar_envelope(cal, operation, &id.to_string());
    tx_factory
        .run_calendar_write_contract_pipelined(
            cal,
            &env,
            deadline(),
            &sql::PAGE_DELETE,
            &[&mailbox, &id],
            Some(command("booking_page_delete")),
            |rows| decode_text0(&rows),
        )
        .await
}

// ---- free/busy ----

/// `calendar_free_busy_multi(caller mailbox, calendar ids, start, end)`.
pub async fn free_busy(
    tx_factory: &TxFactory,
    cal: &CalendarCapability,
    ids: &[i64],
    start: &str,
    end: &str,
) -> Result<String, StatementFailure> {
    let mailbox = cal.mailbox().get();
    let ids = ids.to_vec();
    decode_text0(
        &tx_factory
            .run_calendar_read_contract(cal, &sql::FREE_BUSY_MULTI, &[&mailbox, &ids, &start, &end])
            .await?,
    )
}

// ---- calendar subscriptions (user / mailbox scope) ----

/// One row of `GET /calendar/subscriptions`, already in Go's wire types.
pub struct Subscription {
    pub id: i64,
    pub calendar_id: String,
    pub calendar_name: String,
    pub url: String,
    pub last_fetch_at: Option<String>,
    pub last_status: String,
    pub last_error: Option<String>,
    pub refresh_interval_minutes: i32,
}

pub async fn subscriptions(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<Vec<Subscription>, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &sql::SUBSCRIPTIONS_LIST, &[&uid])
        .await?;
    rows.iter()
        .map(|row| {
            Ok(Subscription {
                id: row.try_get(0).map_err(|_| invalid())?,
                calendar_id: row.try_get(1).map_err(|_| invalid())?,
                calendar_name: row.try_get(2).map_err(|_| invalid())?,
                url: row.try_get(3).map_err(|_| invalid())?,
                last_fetch_at: row.try_get(4).map_err(|_| invalid())?,
                last_status: row.try_get(5).map_err(|_| invalid())?,
                last_error: row.try_get(6).map_err(|_| invalid())?,
                refresh_interval_minutes: row.try_get(7).map_err(|_| invalid())?,
            })
        })
        .collect()
}

/// Go's `perUserResourceCap` count. Owner-approved security fix 2026-11-05 (#423): the count runs
/// in the caller's user scope, so under the RLS-bound request credential it sees the caller's
/// own rows (frozen Go counted on the unscoped pool, saw 0 under `setjoin_app`, and the cap
/// never tripped).
pub async fn subscription_count(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<i64, StatementFailure> {
    let uid = user.user().get();
    let rows = if setjoin_contracts::mutants::on("subscription-cap-unscoped") {
        tx_factory
            .run_public_read_contract(&sql::SUBSCRIPTION_COUNT_UNSCOPED_MUTANT, &[&uid])
            .await?
    } else {
        tx_factory
            .run_user_read_contract(user, &sql::SUBSCRIPTION_COUNT, &[&uid])
            .await?
    };
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

/// Create the mirrored calendar and its subscription row: Go's two inserts in
/// one transaction. Returns `(subscription id, calendar id)`.
pub async fn subscribe(
    tx_factory: &TxFactory,
    cal: &CalendarCapability,
    name: &str,
    url: &str,
    operation: [u8; 16],
) -> CommandOutcome<(i64, i64), StatementFailure> {
    let mailbox = cal.mailbox().get();
    let uid = cal.actor().get();
    let env = calendar_envelope(cal, operation, &format!("{name}\n{url}"));
    tx_factory
        .run_calendar_write_contract_pipelined(
            cal,
            &env,
            deadline(),
            &sql::SUBSCRIBE,
            &[&mailbox, &uid, &name, &url],
            Some(command("subscription_create")),
            |rows| match rows.as_slice() {
                [row] => Ok((
                    row.try_get(0).map_err(|_| invalid())?,
                    row.try_get(1).map_err(|_| invalid())?,
                )),
                _ => Err(invalid()),
            },
        )
        .await
}

/// `DELETE /calendar/subscriptions/{id}`: ownership in the same statement. The
/// calendar row cascades through the subscription and its events. `true` when a
/// row was deleted.
pub async fn unsubscribe(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let uid = user.user().get();
    let env = user_envelope(user, OperationId(operation), &id.to_string());
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::UNSUBSCRIBE,
            &[&uid, &id],
            Some(command("subscription_delete")),
            |rows| match rows.as_slice() {
                [row] => Ok(row.try_get::<_, i64>(0).map_err(|_| invalid())? > 0),
                _ => Err(invalid()),
            },
        )
        .await
}
