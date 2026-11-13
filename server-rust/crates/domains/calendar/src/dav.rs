//! CalDAV's owned-data backend. All caller identity is verified by the gateway;
//! Resource SQL carries the verified user in the same ownership predicate.
//! The preserved Go timezone catalog exception is documented below.
use setjoin_pg::{ScopedExecutor, StatementFailure, Type};

pub struct Calendar {
    pub id: i64,
    pub mailbox: i64,
    pub name: String,
    pub timezone: String,
}
pub async fn calendars(
    exec: &ScopedExecutor,
    user: i64,
) -> Result<Vec<Calendar>, StatementFailure> {
    let rows = exec.read("SELECT c.id,c.mailbox_id,c.name,c.timezone FROM calendars c JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE mb.user_id=$1 ORDER BY c.name", &[(&user,Type::INT8)]).await?;
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
    exec: &ScopedExecutor,
    id: i64,
    user: i64,
) -> Result<Option<Calendar>, StatementFailure> {
    let rows=exec.read("SELECT c.id,c.mailbox_id,c.name,c.timezone FROM calendars c JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE c.id=$1 AND mb.user_id=$2",&[(&id,Type::INT8),(&user,Type::INT8)]).await?;
    Ok(rows.first().map(|r| Calendar {
        id: r.get(0),
        mailbox: r.get(1),
        name: r.get(2),
        timezone: r.get(3),
    }))
}

/// Resolve the resource master; detached occurrences never own a resource URI.
pub async fn event(
    exec: &ScopedExecutor,
    calendar: i64,
    uid: &str,
    user: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = exec.read("SELECT to_jsonb(ce)::text FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE ce.calendar_id=$1 AND ce.uid=$2 AND mb.user_id=$3 AND ce.recurrence_override IS NULL", &[(&calendar,Type::INT8),(&uid,Type::TEXT),(&user,Type::INT8)]).await?;
    Ok(rows.first().map(|r| r.get(0)))
}

/// The process-wide timezone catalog, one row per (calendar, TZID). Owner-approved security fix
/// 2026-11-05 (#426/#512): the cache key includes the calendar, so a TZID defined in one
/// calendar never serves another (frozen Go keyed by TZID alone, caldav.go:75-94,254-269).
pub async fn timezone_catalog(
    exec: &ScopedExecutor,
) -> Result<Vec<(i64, String, String)>, StatementFailure> {
    let rows = exec
        .read("SELECT calendar_id,tzid,standard::text FROM vt_timezone", &[])
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| Some((r.try_get(0).ok()?, r.try_get(1).ok()?, r.try_get(2).ok()?)))
        .collect())
}

/// The non-cache fallback still checks the current authorized collection.
pub async fn owned_timezone(
    exec: &ScopedExecutor,
    calendar: i64,
    user: i64,
    tzid: &str,
) -> Result<Option<String>, StatementFailure> {
    let rows=exec.read("SELECT v.standard::text FROM vt_timezone v JOIN calendars c ON c.id=v.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE v.calendar_id=$1 AND v.tzid=$2 AND mb.user_id=$3",&[(&calendar,Type::INT8),(&tzid,Type::TEXT),(&user,Type::INT8)]).await?;
    Ok(rows.first().and_then(|r| r.get(0)))
}

/// Ordered detached occurrences sharing the master's UID, under the same owner.
pub async fn overrides(
    exec: &ScopedExecutor,
    calendar: i64,
    uid: &str,
    user: i64,
) -> Result<Vec<String>, StatementFailure> {
    let rows = exec.read("SELECT to_jsonb(ce)::text FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE ce.calendar_id=$1 AND ce.uid=$2 AND mb.user_id=$3 AND ce.recurrence_override IS NOT NULL ORDER BY ce.recurrence_override", &[(&calendar,Type::INT8),(&uid,Type::TEXT),(&user,Type::INT8)]).await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// Master resources in the collection, preserving Go's start-order and optional
/// PROPFIND limit. Filter bounds are RFC3339 instants decoded by the adapter.
pub async fn events(
    exec: &ScopedExecutor,
    calendar: i64,
    user: i64,
    after: &str,
    before: &str,
    limit: Option<i64>,
) -> Result<Vec<String>, StatementFailure> {
    let rows=exec.read("SELECT to_jsonb(ce)::text FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE ce.calendar_id=$1 AND mb.user_id=$2 AND ce.recurrence_override IS NULL AND (NULLIF($3,'') IS NULL OR ce.end_at>NULLIF($3,'')::timestamptz) AND (NULLIF($4,'') IS NULL OR ce.start_at<NULLIF($4,'')::timestamptz) ORDER BY ce.start_at LIMIT $5", &[(&calendar,Type::INT8),(&user,Type::INT8),(&after,Type::TEXT),(&before,Type::TEXT),(&limit,Type::INT8)]).await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

pub async fn sync(
    exec: &ScopedExecutor,
    user: i64,
    mailbox: i64,
    calendar: i64,
    since: &str,
) -> Result<Option<String>, StatementFailure> {
    use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
    let scope = setjoin_pg::MailboxAuthContext::from_authenticated_session(
        ActorId::new(user).expect("verified user"),
        MailboxId::new(mailbox).expect("owned mailbox"),
        Generation(1),
    );
    let rows=exec.read_scoped(&scope,"SELECT caldav_changes($1,'CalendarEvent',$2,$3)::text WHERE EXISTS(SELECT 1 FROM calendars c JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE c.id=$2 AND c.mailbox_id=$1 AND mb.user_id=$4)", &[(&mailbox,Type::INT8),(&calendar,Type::INT8),(&since,Type::TEXT),(&user,Type::INT8)]).await?;
    Ok(rows.first().map(|r| r.get(0)))
}

pub async fn free_busy(
    exec: &ScopedExecutor,
    user: i64,
    caller_mailbox: i64,
    calendar: i64,
    start: &str,
    end: &str,
) -> Result<(), StatementFailure> {
    exec.read("SELECT calendar_free_busy($1,ARRAY[c.mailbox_id],$4::text::timestamptz,$5::text::timestamptz)::text FROM calendars c JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE c.id=$2 AND mb.user_id=$3", &[(&caller_mailbox,Type::INT8),(&calendar,Type::INT8),(&user,Type::INT8),(&start,Type::TEXT),(&end,Type::TEXT)]).await?;
    Ok(())
}

/// One canonical reducer call; no mailbox GUC, matching Go's Call rather than
/// CallScoped. User scope retains Go's missing journal rows while fencing COMMIT.
pub async fn create(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    calendar: i64,
    payload: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    let user = actor.user_id();
    let email = actor.email();
    exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand{family:"F17",command:"caldav-put-create"}).run_user_command(ActorId::new(user).expect("verified actor"),OperationId(operation),"SELECT jmap_calendar_event_set_create(c.mailbox_id,$1,$3,$4::text::jsonb)::text FROM calendars c JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE c.id=$2 AND mb.user_id=$1", &[(&user,Type::INT8),(&calendar,Type::INT8),(&email,Type::TEXT),(&payload,Type::TEXT)],|rows|Ok(rows.first().map(|r|r.get(0)).unwrap_or_else(||"{}".into()))).await
}

pub async fn event_etag(
    exec: &ScopedExecutor,
    id: i64,
    user: i64,
) -> Result<String, StatementFailure> {
    let rows=exec.read("SELECT ce.etag FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE ce.id=$1 AND mb.user_id=$2", &[(&id,Type::INT8),(&user,Type::INT8)]).await?;
    Ok(rows.first().map(|r| r.get(0)).unwrap_or_default())
}

pub async fn update(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    calendar: i64,
    event: i64,
    payload: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    let user = actor.user_id();
    exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand{family:"F17",command:"caldav-put-update"}).run_user_command(ActorId::new(user).expect("verified actor"),OperationId(operation),"SELECT jmap_calendar_event_set_update(c.mailbox_id,$4::text::jsonb)::text FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE c.id=$2 AND ce.id=$3 AND mb.user_id=$1 AND ce.recurrence_override IS NULL", &[(&user,Type::INT8),(&calendar,Type::INT8),(&event,Type::INT8),(&payload,Type::TEXT)],|rows|Ok(rows.first().map(|r|r.get(0)).unwrap_or_else(||"{}".into()))).await
}

pub async fn occurrence(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    calendar: i64,
    event: i64,
    instant: &str,
    patch: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    let user = actor.user_id();
    exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand{family:"F17",command:"caldav-put-occurrence"}).run_user_command(ActorId::new(user).expect("verified actor"),OperationId(operation),"SELECT jmap_calendar_event_set_occurrence(c.mailbox_id,ce.id,$4::text::timestamptz,'this',$5::text::jsonb)::text FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE c.id=$2 AND ce.id=$3 AND mb.user_id=$1 AND ce.recurrence_override IS NULL", &[(&user,Type::INT8),(&calendar,Type::INT8),(&event,Type::INT8),(&instant,Type::TEXT),(&patch,Type::TEXT)],|rows|Ok(rows.first().map(|r|r.get(0)).unwrap_or_else(||"{}".into()))).await
}

pub async fn destroy(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    calendar: i64,
    event: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    let user = actor.user_id();
    exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand{family:"F17",command:"caldav-delete"}).run_user_command(ActorId::new(user).expect("verified actor"),OperationId(operation),"SELECT jmap_calendar_event_set_destroy(c.mailbox_id,ARRAY[ce.id])::text FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id JOIN mailboxes mb ON mb.id=c.mailbox_id WHERE c.id=$2 AND ce.id=$3 AND mb.user_id=$1 AND ce.recurrence_override IS NULL", &[(&user,Type::INT8),(&calendar,Type::INT8),(&event,Type::INT8)],|rows|Ok(rows.first().map(|r|r.get(0)).unwrap_or_else(||"{}".into()))).await
}

/// Go RequireApp's independent, best-effort routine denial audit.
pub async fn blocked_audit(
    exec: &ScopedExecutor,
    user: i64,
    ip: &str,
) -> Result<(), StatementFailure> {
    exec.read("SELECT audit_write($1,'app_blocked','app',NULL,NULL,NULL,$2::text::inet,'calendar','routine')", &[(&user,Type::INT8),(&ip,Type::TEXT)]).await?;
    Ok(())
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
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    operation: setjoin_contracts::ids::OperationId,
    kind: Operation,
) -> Result<bool, StatementFailure> {
    use setjoin_contracts::ids::ActorId;
    let invalid = || StatementFailure {
        sqlstate: None,
        hint: None,
        message: "CalDAV outcome authority unavailable".into(),
    };
    let user = actor.user_id();
    let op = setjoin_pg::operation_hex(operation);
    let command = kind.command();
    // run_user_command takes the same actor/operation advisory lock as the
    // publisher, then reads its durable receipt without adding a new receipt.
    match exec.run_user_command(ActorId::new(user).map_err(|_|invalid())?,operation,
        "SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=substr(encode(digest($2::text || ':' || $1::text,'sha256'),'hex'),1,32)::uuid AND family='F17' AND command=$3) WHERE EXISTS(SELECT 1 FROM users u WHERE u.id=$1 AND u.enabled AND identity_transition_admission_allowed(u.id))",
        &[(&user,Type::INT8),(&op,Type::TEXT),(&command,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await {
        setjoin_pg::CommandOutcome::Committed(found)=>Ok(found),_=>Err(invalid()),
    }
}
