//! Calendar and DAV over HTTP (F17), slice 1: calendar subscriptions, batch
//! free/busy and self-service booking.
//!
//! Foundation dependencies only. The actor and mailbox of every authenticated
//! call come from the sealed auth context; request fields name targets and never
//! grant authority. Canonical PL/pgSQL reducers keep the business logic
//! (`booking_*`, `calendar_free_busy_multi`); this crate only calls them the way
//! frozen Go does and returns their JSON text unchanged.
#![forbid(unsafe_code)]
pub mod contacts;
pub mod dav;
pub mod carddav;
use setjoin_authz::AuthContext;
use setjoin_contracts::{
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, MailboxId, OperationId},
};
use setjoin_pg::{
    CommandOutcome, MailboxAuthContext, ReceiptCommand, Row, ScopedExecutor, StatementFailure, Type,
};
use sha2::{Digest as _, Sha256};

/// Go's `maxCalendarSubscriptionsPerUser` (`mailserverd/main.go`).
pub const MAX_SUBSCRIPTIONS_PER_USER: i64 = 25;

pub fn scope(actor: &AuthContext) -> MailboxAuthContext {
    MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor.user_id()).expect("verified user"),
        MailboxId::new(actor.mailbox_id()).expect("verified mailbox"),
        Generation(1),
    )
}

fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid calendar result".into(),
    }
}

fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}

fn envelope(auth: &MailboxAuthContext, operation: [u8; 16], payload: &str) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(payload.as_bytes()).into()),
        command: (),
    }
}

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: "F17",
        command: name,
    }
}

fn text0(rows: &[Row]) -> Result<String, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .ok_or_else(invalid)
}

/// A feature toggle row, absent meaning the registry default (`default`).
pub async fn flag(
    exec: &ScopedExecutor,
    key: &str,
    default: bool,
) -> Result<bool, StatementFailure> {
    let rows = exec
        .read(
            "SELECT enabled FROM feature_toggles WHERE key = $1",
            &[(&key, Type::TEXT)],
        )
        .await?;
    Ok(rows.first().map_or(default, |r| r.get(0)))
}

/// `feature.booking_pages` (default OFF).
pub async fn booking_enabled(exec: &ScopedExecutor) -> Result<bool, StatementFailure> {
    flag(exec, "feature.booking_pages", false).await
}

/// `feature.caldav` (default ON): Go mounts free/busy only when it is on.
pub async fn caldav_enabled(exec: &ScopedExecutor) -> Result<bool, StatementFailure> {
    flag(exec, "feature.caldav", true).await
}

/// Go's `RequireApp("calendar")`: `check_user_app_entitlement` on the request pool.
pub async fn entitled(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<bool, StatementFailure> {
    entitled_app(exec, actor, "calendar").await
}

/// Go's `RequireApp(app)`: `check_user_app_entitlement` for the verified user.
pub async fn entitled_app(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    app: &str,
) -> Result<bool, StatementFailure> {
    let user = actor.user_id();
    Ok(exec
        .read(
            "SELECT check_user_app_entitlement($1,$2)",
            &[(&user, Type::INT8), (&app, Type::TEXT)],
        )
        .await?
        .first()
        .is_some_and(|r| r.get(0)))
}

// ---- booking pages: owner surface (mailbox scope, Go's `dbscope.RunScoped`) ----

/// `booking_page_list` for the caller's primary mailbox.
pub async fn page_list(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let mailbox = actor.mailbox_id();
    text0(
        &exec
            .read_scoped(
                &scope(actor),
                "SELECT booking_page_list($1)::text",
                &[(&mailbox, Type::INT8)],
            )
            .await?,
    )
}

/// `booking_page_upsert(mailbox, page)`: Go's whole transaction is this one
/// reducer call. `page` is the raw request JSON, cast to jsonb by the server.
pub async fn page_upsert(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    page: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("booking_page_upsert"),
        &envelope(&auth, operation, page),
        &auth,
        deadline(),
        "SELECT booking_page_upsert($1, $4::text::jsonb)::text WHERE $2::bigint > 0 AND $3::text <> ''",
        &[(&page, Type::TEXT)],
        |rows| text0(rows),
    )
    .await
}

/// `booking_page_delete(mailbox, id)`.
pub async fn page_delete(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("booking_page_delete"),
        &envelope(&auth, operation, &id.to_string()),
        &auth,
        deadline(),
        "SELECT booking_page_delete($1, $4)::text WHERE $2::bigint > 0 AND $3::text <> ''",
        &[(&id, Type::INT8)],
        |rows| text0(rows),
    )
    .await
}

// ---- booking: public surface (worker credential, one autocommit statement) ----
//
// There is no caller identity here: the SECURITY DEFINER reducers self-scope by
// slug and token hash, exactly as Go's worker-pool calls do. No mailbox, no
// receipt.

/// `booking_page_public_get`; `None` is Go's SQL NULL (no such enabled page).
pub async fn public_get(
    exec: &ScopedExecutor,
    slug: &str,
) -> Result<Option<String>, StatementFailure> {
    let rows = exec
        .read(
            "SELECT COALESCE(booking_page_public_get($1), 'null'::jsonb)::text",
            &[(&slug, Type::TEXT)],
        )
        .await?;
    let out = text0(&rows)?;
    Ok((out != "null").then_some(out))
}

pub async fn slots(
    exec: &ScopedExecutor,
    slug: &str,
    from: &str,
    to: &str,
) -> Result<String, StatementFailure> {
    text0(
        &exec
            .read(
                "SELECT booking_slots($1, $2::text::date, $3::text::date)::text",
                &[(&slug, Type::TEXT), (&from, Type::TEXT), (&to, Type::TEXT)],
            )
            .await?,
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn create(
    exec: &ScopedExecutor,
    slug: &str,
    start: &str,
    email: &str,
    name: &str,
    answers: &str,
    token_hash: &str,
    ip: Option<&str>,
) -> Result<String, StatementFailure> {
    text0(
        &exec
            .read(
                "SELECT booking_create($1, $2::text::timestamptz, $3, $4, $5::text::jsonb, $6, $7::text::inet)::text",
                &[
                    (&slug, Type::TEXT),
                    (&start, Type::TEXT),
                    (&email, Type::TEXT),
                    (&name, Type::TEXT),
                    (&answers, Type::TEXT),
                    (&token_hash, Type::TEXT),
                    (&ip, Type::TEXT),
                ],
            )
            .await?,
    )
}

pub async fn confirm(
    exec: &ScopedExecutor,
    verify_hash: &str,
    cancel_hash: &str,
) -> Result<String, StatementFailure> {
    text0(
        &exec
            .read(
                "SELECT booking_confirm($1, $2)::text",
                &[(&verify_hash, Type::TEXT), (&cancel_hash, Type::TEXT)],
            )
            .await?,
    )
}

pub async fn cancel(exec: &ScopedExecutor, cancel_hash: &str) -> Result<String, StatementFailure> {
    text0(
        &exec
            .read(
                "SELECT booking_cancel($1)::text",
                &[(&cancel_hash, Type::TEXT)],
            )
            .await?,
    )
}

/// The SQL of the booking-expiry sweep (Go's `Sweeper`), one fixed statement.
pub const EXPIRE_DUE: &str = "SELECT booking_expire_due()";

// ---- free/busy ----

/// `calendar_free_busy_multi(caller mailbox, calendar ids, start, end)` on the
/// request pool without a tenant GUC, as Go's `h.pool.QueryRow` does. The
/// caller's primary mailbox is the sealed auth context's, never a request field.
pub async fn free_busy(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ids: &[i64],
    start: &str,
    end: &str,
) -> Result<String, StatementFailure> {
    let mailbox = actor.mailbox_id();
    text0(
        &exec
            .read(
                "SELECT calendar_free_busy_multi($1, $2, $3::text::timestamptz, $4::text::timestamptz)::text",
                &[
                    (&mailbox, Type::INT8),
                    (&ids, Type::INT8_ARRAY),
                    (&start, Type::TEXT),
                    (&end, Type::TEXT),
                ],
            )
            .await?,
    )
}

/// Go's per-result email enrichment query (user email, else `<name>@resources`).
pub async fn entity_email(exec: &ScopedExecutor, entity: &str) -> Option<String> {
    let rows = exec
        .read(
            "SELECT COALESCE(\
               (SELECT email FROM users u JOIN mailboxes m ON m.user_id = u.id WHERE m.id = $1::text::bigint),\
               (SELECT name || '@resources' FROM calendars WHERE id = $1::text::bigint))",
            &[(&entity, Type::TEXT)],
        )
        .await
        .ok()?;
    rows.first()?.try_get::<_, Option<String>>(0).ok()?
}

// ---- calendar subscriptions (user scope, Go's `dbscope.RunUserScoped`) ----

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
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<Vec<Subscription>, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT s.id, s.calendar_id::text, c.name, s.url, \
                    to_char(s.last_fetch_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
                    s.last_status, s.last_error, s.refresh_interval_minutes \
               FROM calendar_subscriptions s \
               JOIN calendars c ON c.id = s.calendar_id \
              WHERE s.user_id = $1 \
              ORDER BY s.created_at",
            &[(&user, Type::INT8)],
        )
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<i64, StatementFailure> {
    let user = actor.user_id();
    let sql = "SELECT count(*) FROM calendar_subscriptions WHERE user_id = $1";
    let rows = if setjoin_contracts::mutants::on("subscription-cap-unscoped") {
        exec.read(sql, &[(&user, Type::INT8)]).await?
    } else {
        exec.read_scoped(&scope(actor), sql, &[(&user, Type::INT8)])
            .await?
    };
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

/// Create the mirrored calendar and its subscription row: Go's two inserts in
/// one transaction. Returns `(subscription id, calendar id)`.
pub async fn subscribe(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    name: &str,
    url: &str,
    operation: [u8; 16],
) -> CommandOutcome<(i64, i64), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("subscription_create"),
        &envelope(&auth, operation, &format!("{name}\n{url}")),
        &auth,
        deadline(),
        "SELECT sub_id, calendar_id FROM rust_calendar_subscribe($1, $2, $4, $5) WHERE $3::text <> ''",
        &[(&name, Type::TEXT), (&url, Type::TEXT)],
        |rows| match rows {
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("subscription_delete"),
        &envelope(&auth, operation, &id.to_string()),
        &auth,
        deadline(),
        "WITH gone AS (DELETE FROM calendars c USING calendar_subscriptions s \
          WHERE c.id = s.calendar_id AND s.id = $4 AND s.user_id = $2 \
            AND $1::bigint > 0 AND $3::text <> '' RETURNING c.id) \
         SELECT count(*)::bigint FROM gone",
        &[(&id, Type::INT8)],
        |rows| match rows {
            [row] => Ok(row.try_get::<_, i64>(0).map_err(|_| invalid())? > 0),
            _ => Err(invalid()),
        },
    )
    .await
}
