//! Reducer calls under a resolved [`Scope`] (Go `CallScoped`/`CallScopedBatch`),
//! the closed table of reviewed non-reducer scoped statements
//! ([`ScopedQuery`]), the delegate RSVP, the iMIP egress hop and the closed
//! table of user-keyed worker statements (Go `h.workerPool`).
//!
//! The seam binds these placeholders, never family code: `$1` the scope
//! mailbox, `$2` the verified actor (`scope.auth.actor()`, the session user,
//! the same value the receipted command binds) and, on a write, `$3` the
//! operation. Family params follow them. A reducer parameter that carries the
//! acting user's authority receives `$2` and nothing else
//! (`db::actor_arguments_are_seam_bound`). The registered method selects the
//! reducer-error projection ([`CALENDAR_A3_METHODS`]).
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Instant;

use regex::Regex;
use serde_json::value::RawValue;
use setjoin_contracts::command::CommandEnvelope;
use setjoin_contracts::ids::{Digest, MailboxId, OperationId};
use setjoin_pg::{
    run_receipted_command, run_receipted_effect, CommandOutcome, MailboxAuthContext, Param,
    ReceiptCommand, Rejection, Row, ScopedTx, StatementFailure, Type,
};
use sha2::{Digest as _, Sha256};

use super::{Cx, Scope, CALENDAR_A3_METHODS, WORKER_METHODS};
use crate::jmap::family::{reducer_error, MethodError};
use crate::jmap::imip::Imip;

/// `read_sql!`'s tail: the seam-bound actor guard.
const READ_TAIL: &str = " WHERE $2::bigint>0";
/// `write_sql!`'s tail: the receipt guard ($2 actor, $3 operation).
const WRITE_TAIL: &str = " WHERE $2::bigint>0 AND $3::text<>''";

fn reducer_call() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"^SELECT [a-z_][a-z0-9_]*\((\$1(?:,\$[1-9][0-9]*(?:::[a-z0-9_]+(?:\[\])?)*)*)\)(?:::text)?( WHERE \$2::bigint>0(?: AND \$3::text<>'')?)$",
        )
        .expect("reducer call pattern")
    })
}

/// The seam call a statement is checked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// `read`, `read_rows` and `set_batch`: the seam binds `$1` mailbox and `$2` actor.
    Read,
    /// `write`: the seam binds `$1` mailbox, `$2` actor and `$3` operation.
    Write,
}

impl Shape {
    fn tail(self) -> &'static str {
        match self {
            Shape::Read => READ_TAIL,
            Shape::Write => WRITE_TAIL,
        }
    }

    /// The last placeholder the seam binds; family params follow it.
    fn seam_bound(self) -> usize {
        match self {
            Shape::Read => 2,
            Shape::Write => 3,
        }
    }
}

/// The whole statement is one reducer call (Go `CallScoped`) whose arguments
/// are placeholders only, ending in the shape's tail. A seam-bound placeholder
/// sits only at its own position (`$1` first, the actor `$2` second, a write's
/// operation `$3` third), so a family param never takes the actor's place, and
/// the highest placeholder is the last of the `params` family params. Every
/// other scoped statement is a reviewed [`ScopedQuery`] variant, never free SQL.
fn owner_bound(sql: &str, shape: Shape, params: usize) -> bool {
    let Some(captures) = reducer_call().captures(sql) else {
        return false;
    };
    if &captures[2] != shape.tail() {
        return false;
    }
    let seam = shape.seam_bound();
    let mut highest = seam;
    for (index, argument) in captures[1].split(',').enumerate() {
        let digits: String = argument
            .chars()
            .skip(1)
            .take_while(|ch| ch.is_ascii_digit())
            .collect();
        let Ok(number) = digits.parse::<usize>() else {
            return false;
        };
        if number <= seam && number != index + 1 {
            return false;
        }
        highest = highest.max(number);
    }
    highest == seam + params
}

#[cfg(test)]
thread_local! {
    /// Seam refusals on this thread (the observable boundary for the refusal tests).
    static REFUSALS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn refuse(cx: &Cx<'_>, what: &str) -> MethodError {
    #[cfg(test)]
    REFUSALS.with(|count| count.set(count.get() + 1));
    eprintln!(
        "setjoin-gateway: jmap {} {what} refused by the family seam",
        cx.method.name
    );
    MethodError::server_fail()
}

fn first_text(rows: &[Row]) -> Result<String, StatementFailure> {
    let failure = |message: &str| StatementFailure {
        sqlstate: None,
        message: message.to_owned(),
        hint: None,
    };
    let row = rows
        .first()
        .ok_or_else(|| failure("missing reducer result"))?;
    let value: Option<String> = row
        .try_get(0)
        .map_err(|_| failure("reducer result is not text"))?;
    Ok(value.unwrap_or_else(|| "null".to_owned()))
}

fn envelope(cx: &Cx<'_>, scope: &Scope, operation: [u8; 16]) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: scope.auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(cx.args.as_bytes()).into()),
        command: (),
    }
}

fn settle<T>(
    outcome: CommandOutcome<T, StatementFailure>,
    project: fn(&StatementFailure) -> MethodError,
) -> Result<T, MethodError> {
    match outcome {
        CommandOutcome::Committed(value) => Ok(value),
        CommandOutcome::Unknown { operation } => Err(MethodError::new(
            "serverFail",
            &format!(
                "commit outcome unknown; look up operation {}",
                crate::jmap::reply::hex(&operation.0)
            ),
        )),
        CommandOutcome::RolledBack(Rejection::Statement(failure))
        | CommandOutcome::RolledBack(Rejection::Body(failure)) => Err(project(&failure)),
        CommandOutcome::RolledBack(_) => Err(MethodError::server_fail()),
    }
}

/// Go's reducer-error projection for `method`: `calendarA3Error`
/// (calendar_a3.go:30, any BZ001 is `forbidden`) at the calendar call sites
/// that use it, `mapReducerErr` everywhere else. The registered method selects
/// it, never family code, so no other method can change what an error reveals.
fn projection(method: &str) -> fn(&StatementFailure) -> MethodError {
    if CALENDAR_A3_METHODS.contains(&method) {
        reducer_error::project_calendar
    } else {
        reducer_error::project
    }
}

/// Go `CallScoped` of a read reducer: READ ONLY, `$1` scope mailbox, `$2`
/// verified actor, params from `$3`; the statement is built with `read_sql!`.
pub(crate) async fn read(
    cx: &Cx<'_>,
    scope: &Scope,
    sql: &'static str,
    params: &[Param<'_>],
) -> Result<String, MethodError> {
    if !owner_bound(sql, Shape::Read, params.len()) {
        return Err(refuse(cx, "read"));
    }
    scoped_read(cx, scope, sql, params).await
}

/// A set-returning read reducer (Go `pool.Query` + `rows.Next`): column 0 of
/// every row in order, SQL NULL as `null`; same shape and bindings as [`read`].
pub(crate) async fn read_rows(
    cx: &Cx<'_>,
    scope: &Scope,
    sql: &'static str,
    params: &[Param<'_>],
) -> Result<Vec<String>, MethodError> {
    if !owner_bound(sql, Shape::Read, params.len()) {
        return Err(refuse(cx, "read rows"));
    }
    let rows = scoped_rows(cx, scope, sql, params).await?;
    rows.iter()
        .map(|row| {
            row.try_get::<_, Option<String>>(0)
                .map(|value| value.unwrap_or_else(|| "null".to_owned()))
                .map_err(|_| MethodError::server_fail())
        })
        .collect()
}

/// The rows of one READ ONLY scoped statement with the seam's `$1` and `$2`.
async fn scoped_rows(
    cx: &Cx<'_>,
    scope: &Scope,
    sql: &'static str,
    params: &[Param<'_>],
) -> Result<Vec<Row>, MethodError> {
    let project = projection(cx.method.name);
    let actor = scope.auth.actor().get();
    let mut bindings: Vec<Param<'_>> = vec![(&scope.mailbox, Type::INT8), (&actor, Type::INT8)];
    bindings.extend(params.iter().map(|(value, ty)| (*value, ty.clone())));
    cx.exec
        .read_scoped(&scope.auth, sql, &bindings)
        .await
        .map_err(|failure| project(&failure))
}

/// One READ ONLY scoped statement's single text result.
async fn scoped_read(
    cx: &Cx<'_>,
    scope: &Scope,
    sql: &'static str,
    params: &[Param<'_>],
) -> Result<String, MethodError> {
    let rows = scoped_rows(cx, scope, sql, params).await?;
    first_text(&rows).map_err(|failure| projection(cx.method.name)(&failure))
}

/// Go `CallScoped` of a writing reducer: `$1` mailbox, `$2` actor, `$3`
/// operation (all bound by the executor), params from `$4`; the statement is
/// built with `write_sql!`.
pub(crate) async fn write(
    cx: &Cx<'_>,
    scope: &Scope,
    command: &'static str,
    sql: &'static str,
    params: &[Param<'_>],
) -> Result<String, MethodError> {
    if !owner_bound(sql, Shape::Write, params.len()) {
        return Err(refuse(cx, "write"));
    }
    scoped_write(cx, scope, command, sql, params).await
}

/// One receipted scoped statement with the executor's `$1`, `$2` and `$3`.
async fn scoped_write(
    cx: &Cx<'_>,
    scope: &Scope,
    command: &'static str,
    sql: &'static str,
    params: &[Param<'_>],
) -> Result<String, MethodError> {
    let Some(operation) = crate::jmap::random() else {
        return Err(MethodError::server_fail());
    };
    let envelope = envelope(cx, scope, operation);
    let outcome = run_receipted_command(
        cx.exec,
        ReceiptCommand {
            family: "jmap",
            command,
        },
        &envelope,
        &scope.auth,
        Instant::now() + crate::jmap::COMMAND_DEADLINE,
        sql,
        params,
        first_text,
    )
    .await;
    settle(outcome, projection(cx.method.name))
}

/// Go `dispatchSet` statements; built only by `set_sql!`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetSql {
    create: &'static str,
    update: &'static str,
    destroy: &'static str,
}

impl SetSql {
    pub(in crate::jmap::family) const fn new(
        create: &'static str,
        update: &'static str,
        destroy: &'static str,
    ) -> Self {
        Self {
            create,
            update,
            destroy,
        }
    }
}

/// Go `jsonIsObject`: the first non-whitespace byte is `{`.
fn is_object(raw: &str) -> bool {
    raw.trim_start_matches([' ', '\t', '\n', '\r'])
        .starts_with('{')
}

async fn phase(
    tx: &mut ScopedTx,
    sql: &str,
    params: &[Param<'_>],
) -> Result<String, StatementFailure> {
    let rows = tx.query(sql, params).await?;
    first_text(&rows)
}

/// Go `dispatchSet` (handler.go:1754): present phases in one scoped
/// transaction (create, update, destroy), merged with sorted keys, malformed
/// destroy ids folded into `notDestroyed`. `$1` mailbox, `$2` actor (Go's set
/// reducers do not take it; the tail guards it), payload `$3`.
pub(crate) async fn set_batch(
    cx: &Cx<'_>,
    scope: &Scope,
    sql: SetSql,
    command: &'static str,
    create: Option<&str>,
    update: Option<&str>,
    destroy: Option<&[String]>,
) -> Result<String, MethodError> {
    if ![sql.create, sql.update, sql.destroy]
        .iter()
        .all(|statement| owner_bound(statement, Shape::Read, 1))
    {
        return Err(refuse(cx, "set"));
    }
    let create = create.filter(|raw| is_object(raw)).map(str::to_owned);
    let update = update.filter(|raw| is_object(raw)).map(str::to_owned);
    let (ids, bad) = match destroy {
        Some(ids) if !ids.is_empty() => {
            let (valid, bad) = parse_id_list(ids);
            (Some(valid.unwrap_or_default()), bad)
        }
        _ => (None, Vec::new()),
    };
    if create.is_none() && update.is_none() && ids.is_none() {
        return Ok("{}".to_owned());
    }
    let Some(operation) = crate::jmap::random() else {
        return Err(MethodError::server_fail());
    };
    let envelope = envelope(cx, scope, operation);
    let mailbox = scope.mailbox;
    let actor = scope.auth.actor().get();
    let outcome = run_receipted_effect(
        cx.exec,
        ReceiptCommand {
            family: "jmap",
            command,
        },
        &envelope,
        &scope.auth,
        Instant::now() + crate::jmap::COMMAND_DEADLINE,
        async move |tx: &mut ScopedTx| {
            let mut parts = Vec::new();
            if let Some(create) = &create {
                parts.push(
                    phase(
                        tx,
                        sql.create,
                        &[
                            (&mailbox, Type::INT8),
                            (&actor, Type::INT8),
                            (create, Type::TEXT),
                        ],
                    )
                    .await?,
                );
            }
            if let Some(update) = &update {
                parts.push(
                    phase(
                        tx,
                        sql.update,
                        &[
                            (&mailbox, Type::INT8),
                            (&actor, Type::INT8),
                            (update, Type::TEXT),
                        ],
                    )
                    .await?,
                );
            }
            if let Some(ids) = &ids {
                parts.push(
                    phase(
                        tx,
                        sql.destroy,
                        &[
                            (&mailbox, Type::INT8),
                            (&actor, Type::INT8),
                            (ids, Type::INT8_ARRAY),
                        ],
                    )
                    .await?,
                );
            }
            Ok(parts)
        },
    )
    .await;
    let parts = settle(outcome, projection(cx.method.name))?;
    let mut merged: BTreeMap<String, Box<RawValue>> = BTreeMap::new();
    for part in &parts {
        // Go ignores a phase result that is not an object (mergeSetResults).
        if let Ok(object) = serde_json::from_str::<BTreeMap<String, Box<RawValue>>>(part) {
            merged.extend(object);
        }
    }
    let merged =
        crate::jmap::reply::marshal_sorted(&merged).ok_or_else(MethodError::server_fail)?;
    crate::jmap::set::add_not_destroyed(&merged, &bad).ok_or_else(MethodError::server_fail)
}

/// Calendar/getShared (calendar_a3.go:60): Go's unscoped
/// `Call(jmap_calendar_get_shared, user.UserID, ownerEmail)`. The viewer is
/// the seam-bound actor `$2`; the scope mailbox `$1` only sets the GUC.
const CALENDAR_GET_SHARED: &str =
    "SELECT jmap_calendar_get_shared($2,$3)::text WHERE $1::bigint>0 AND $2::bigint>0";

/// CalendarEvent/getShared (calendar_a3.go:97): Go's unscoped
/// `jmap_calendar_event_get_shared(user.UserID, ownerEmail, after, before)`.
const CALENDAR_EVENT_GET_SHARED: &str = "SELECT jmap_calendar_event_get_shared($2,$3,$4::text::timestamptz,$5::text::timestamptz)::text WHERE $1::bigint>0 AND $2::bigint>0";

/// QuickStep/apply (quicksteps.go:147-165, one `dbscope.RunScoped`
/// transaction): the message lookup in the scope mailbox, then the reducer.
/// NULL when the message is not in the scope mailbox (the family answers Go's
/// `notFound "message not found"`); `''` (void) once the reducer ran.
const QUICK_STEP_APPLY: &str = "SELECT CASE WHEN r.received_at IS NULL THEN NULL ELSE quick_step_apply($1,$4,$5,r.received_at)::text END FROM (SELECT max(received_at) AS received_at FROM messages WHERE mailbox_id = $1 AND id = $5) r WHERE $2::bigint>0 AND $3::text<>''";

/// Reviewed non-reducer scoped statements: Go statements that are not one
/// `CallScoped` reducer call with `$1` first, ported scoped (template
/// requirement 3). Each variant names its method and its exact SQL with `$1` =
/// scope mailbox and `$2` = verified actor (`$3` = operation for a write), and
/// carries only non-identity params. Adding a variant is a seam edit and needs
/// a Fable review; family code passes a variant, never SQL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScopedQuery<'a> {
    /// Calendar/getShared, calendar_a3.go:60 (READ ONLY).
    CalendarGetShared { owner_email: &'a str },
    /// CalendarEvent/getShared, calendar_a3.go:97 (READ ONLY; `None` is NULL).
    CalendarEventGetShared {
        owner_email: &'a str,
        after: Option<&'a str>,
        before: Option<&'a str>,
    },
    /// QuickStep/apply, quicksteps.go:147-165 (receipted write).
    QuickStepApply { id: i64, message: i64 },
}

impl ScopedQuery<'_> {
    /// `(method, receipt command of a write or None for a read, sql)`.
    fn spec(self) -> (&'static str, Option<&'static str>, &'static str) {
        match self {
            ScopedQuery::CalendarGetShared { .. } => {
                ("Calendar/getShared", None, CALENDAR_GET_SHARED)
            }
            ScopedQuery::CalendarEventGetShared { .. } => (
                "CalendarEvent/getShared",
                None,
                CALENDAR_EVENT_GET_SHARED,
            ),
            ScopedQuery::QuickStepApply { .. } => {
                ("QuickStep/apply", Some("quick_step_apply"), QUICK_STEP_APPLY)
            }
        }
    }

    /// Family params after the seam-bound placeholders.
    #[cfg(test)]
    fn arity(self) -> usize {
        match self {
            ScopedQuery::CalendarGetShared { .. } => 1,
            ScopedQuery::CalendarEventGetShared { .. } => 3,
            ScopedQuery::QuickStepApply { .. } => 2,
        }
    }
}

/// Run one reviewed scoped statement under its own method only: READ ONLY for
/// a read, receipted for a write; the seam binds `$1`, `$2` (and `$3`).
pub(crate) async fn query(
    cx: &Cx<'_>,
    scope: &Scope,
    statement: ScopedQuery<'_>,
) -> Result<String, MethodError> {
    let (method, command, sql) = statement.spec();
    if method != cx.method.name {
        return Err(refuse(cx, "scoped query"));
    }
    match (statement, command) {
        (ScopedQuery::CalendarGetShared { owner_email }, None) => {
            scoped_read(cx, scope, sql, &[(&owner_email, Type::TEXT)]).await
        }
        (
            ScopedQuery::CalendarEventGetShared {
                owner_email,
                after,
                before,
            },
            None,
        ) => {
            scoped_read(
                cx,
                scope,
                sql,
                &[
                    (&owner_email, Type::TEXT),
                    (&after, Type::TEXT),
                    (&before, Type::TEXT),
                ],
            )
            .await
        }
        (ScopedQuery::QuickStepApply { id, message }, Some(command)) => {
            scoped_write(
                cx,
                scope,
                command,
                sql,
                &[(&id, Type::INT8), (&message, Type::INT8)],
            )
            .await
        }
        _ => Err(refuse(cx, "scoped query")),
    }
}

/// The manager mailbox the caller may answer for: grant first (recorded
/// security divergence S-2), so an ungranted caller learns neither the mailbox
/// nor its events. `$1` is the session user (user GUC, FORCE RLS).
const DELEGATE_MAILBOX: &str = "SELECT m.id FROM mailboxes m JOIN mailbox_delegates d ON d.mailbox_id = m.id WHERE d.user_id = $1 AND m.email = $2 AND m.is_primary = TRUE AND d.permission IN ('full_access','manage_calendar') ORDER BY m.id LIMIT 1";
/// calendar.go:716: `p_attendee_email` is the manager address, `p_on_behalf_of`
/// the seam-bound actor `$2` (the reducer re-checks the grant, calendar_itip.sql:38).
const DELEGATE_RSVP: &str =
    "SELECT jmap_calendar_event_rsvp($1,$4,$5,$6,$2)::text WHERE $2::bigint>0 AND $3::text<>''";

/// Go's CalendarEvent/rsvp delegate arm (calendar.go:701-720). The manager
/// scope is built here from a grant row the caller holds and never leaves this
/// function; a suspended or detached manager mailbox is not written (Rust-only,
/// recorded divergence).
pub(crate) async fn rsvp_on_behalf(
    cx: &Cx<'_>,
    manager_email: &str,
    event: i64,
    status: &str,
) -> Result<String, MethodError> {
    if cx.method.name != "CalendarEvent/rsvp" {
        return Err(refuse(cx, "rsvp on behalf"));
    }
    let missing = || MethodError::new("notFound", "manager mailbox not found");
    let rows = cx
        .exec
        .read_user_scoped(
            cx.primary.actor(),
            DELEGATE_MAILBOX,
            &[(&cx.user, Type::INT8), (&manager_email, Type::TEXT)],
        )
        .await
        .map_err(|error| {
            eprintln!(
                "setjoin-gateway: jmap CalendarEvent/rsvp manager lookup failed: sqlstate={}",
                error.sqlstate.as_deref().unwrap_or("none")
            );
            missing()
        })?;
    let manager = rows
        .first()
        .and_then(|row| row.try_get::<_, i64>(0).ok())
        .ok_or_else(missing)?;
    let allowed = cx
        .exec
        .read(
            "SELECT mailbox_lifecycle_access_allowed($1)",
            &[(&manager, Type::INT8)],
        )
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|row| row.try_get::<_, bool>(0).ok()));
    if allowed != Some(true) {
        return Err(MethodError::new(
            "forbidden",
            "mailbox access is suspended or detached",
        ));
    }
    let scope = Scope {
        mailbox: manager,
        auth: MailboxAuthContext::from_authenticated_session(
            cx.primary.actor(),
            MailboxId::new(manager).map_err(|_| missing())?,
            crate::jmap::REQUEST_AUTHORITY_GENERATION,
        ),
        delegated: true,
    };
    scoped_write(
        cx,
        &scope,
        "calendar_event.rsvp_on_behalf",
        DELEGATE_RSVP,
        &[
            (&event, Type::INT8),
            (&manager_email, Type::TEXT),
            (&status, Type::TEXT),
        ],
    )
    .await
}

/// iMIP egress for the running method's verified caller. The egress rules
/// live in `crate::jmap::imip` (egress is not a database seam); this hop gates
/// the method, bounds the messages per method call (per `Cx`) and supplies the caller's
/// identity, never a family value. Every drop is logged with its uid.
pub(crate) fn send_imip(cx: &Cx<'_>, mail: Imip) {
    if !crate::jmap::imip::METHODS.contains(&cx.method.name) {
        let _ = refuse(cx, "imip egress");
        return;
    }
    let sent = cx
        .egress
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if sent >= crate::jmap::imip::MAX_MESSAGES_PER_REQUEST {
        crate::jmap::imip::dropped(cx.method.name, &mail.message_id, "per-request message bound");
        return;
    }
    let Some(store) = cx.services.and_then(|services| services.store.clone()) else {
        crate::jmap::imip::dropped(cx.method.name, &mail.message_id, "no object store");
        return;
    };
    crate::jmap::imip::spawn(
        cx.exec.clone(),
        store,
        cx.primary.actor(),
        cx.user,
        cx.method.name,
        mail,
    );
}

/// Go `parseIDList`: `None` (SQL NULL) when there are no valid and no bad ids.
pub(crate) fn parse_id_list(ids: &[String]) -> (Option<Vec<i64>>, Vec<String>) {
    let mut valid = Vec::new();
    let mut bad = Vec::new();
    for id in ids {
        match crate::jmap::get::parse_id(id) {
            Some(value) => valid.push(value),
            None => bad.push(id.clone()),
        }
    }
    if valid.is_empty() && bad.is_empty() {
        (None, bad)
    } else {
        (Some(valid), bad)
    }
}

/// Go `addNotFound`.
pub(crate) fn not_found(raw: &str, bad: &[String]) -> String {
    crate::jmap::get::add_not_found(raw, bad).unwrap_or_else(|| raw.to_owned())
}

/// Go `sinceStateError`.
pub(crate) fn since_state(state: &str) -> Result<(), MethodError> {
    if crate::jmap::changes::since_state_is_well_formed(state) {
        Ok(())
    } else {
        Err(MethodError::new(
            "cannotCalculateChanges",
            "client must resync (malformed sinceState)",
        ))
    }
}

const CALENDAR_DELEGATES: &str = "SELECT coalesce(jsonb_agg(jsonb_build_object('email',x.email,'name',x.name,'permission',x.permission) ORDER BY x.name),'[]'::jsonb)::text FROM (SELECT mb.email::text AS email, COALESCE(u.display_name, mb.email)::text AS name, d.permission FROM mailbox_delegates d JOIN mailboxes mb ON mb.id = d.mailbox_id LEFT JOIN users u ON u.id = mb.user_id WHERE d.user_id = $1 AND d.permission IN ('full_access','manage_calendar')) x";

/// Go `h.workerPool` reads (task_lists.go, calendar_a3.go:197). `$1` is the verified user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkerRead {
    /// TaskList/get, task_lists.go:56.
    TaskListGet,
    /// TaskList/tasks, task_lists.go:228.
    TaskListTasks { list: i64 },
    /// TaskListMember/set, task_lists.go:198.
    TaskListRoster { list: i64 },
    /// TaskAssigned/get, task_lists.go:287.
    TasksAssignedToMe,
    /// Calendar/delegateList, calendar_a3.go:197.
    CalendarDelegates,
}

impl WorkerRead {
    fn spec(self) -> (&'static str, &'static str) {
        match self {
            WorkerRead::TaskListGet => ("TaskList/get", "SELECT task_list_get($1)::text"),
            WorkerRead::TaskListTasks { .. } => {
                ("TaskList/tasks", "SELECT task_list_tasks($1,$2)::text")
            }
            WorkerRead::TaskListRoster { .. } => (
                "TaskListMember/set",
                "SELECT task_list_get_roster($1,$2)::text",
            ),
            WorkerRead::TasksAssignedToMe => {
                ("TaskAssigned/get", "SELECT tasks_assigned_to_me($1)::text")
            }
            WorkerRead::CalendarDelegates => ("Calendar/delegateList", CALENDAR_DELEGATES),
        }
    }

    fn arity(self) -> usize {
        match self {
            WorkerRead::TaskListTasks { .. } | WorkerRead::TaskListRoster { .. } => 2,
            _ => 1,
        }
    }
}

/// Go `h.workerPool` writes (autocommit single statements). `$1` is the verified user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkerWrite<'a> {
    /// TaskList/set create, task_lists.go:90 (`color` is Go's `*string`: `None` binds NULL).
    TaskListCreate {
        name: &'a str,
        color: Option<&'a str>,
    },
    /// TaskList/set update, task_lists.go:114 (`patch` is the JSON patch object).
    TaskListUpdate { list: i64, patch: &'a str },
    /// TaskList/set destroy, task_lists.go:133.
    TaskListDelete { list: i64 },
    /// TaskListMember/set add, task_lists.go:172.
    TaskListAddMember { list: i64, email: &'a str },
    /// TaskListMember/set remove, task_lists.go:185.
    TaskListRemoveMember { list: i64, member: i64 },
    /// TaskList/taskSet, task_lists.go:271 (JSON texts; `None` is NULL).
    TaskListTaskSet {
        list: i64,
        creates: Option<&'a str>,
        updates: Option<&'a str>,
        destroys: Option<&'a str>,
    },
    /// TaskAssigned/setStatus, task_lists.go:310.
    TaskAssigneeSetStatus { task: i64, status: &'a str },
}

impl WorkerWrite<'_> {
    fn spec(self) -> (&'static str, &'static str) {
        match self {
            WorkerWrite::TaskListCreate { .. } => {
                ("TaskList/set", "SELECT task_list_create($1,$2,$3)::text")
            }
            WorkerWrite::TaskListUpdate { .. } => (
                "TaskList/set",
                "SELECT task_list_update($1,$2,$3::text::jsonb)::text",
            ),
            WorkerWrite::TaskListDelete { .. } => {
                ("TaskList/set", "SELECT task_list_delete($1,$2)::text")
            }
            WorkerWrite::TaskListAddMember { .. } => (
                "TaskListMember/set",
                "SELECT task_list_add_member($1,$2,$3)::text",
            ),
            WorkerWrite::TaskListRemoveMember { .. } => (
                "TaskListMember/set",
                "SELECT task_list_remove_member($1,$2,$3)::text",
            ),
            WorkerWrite::TaskListTaskSet { .. } => (
                "TaskList/taskSet",
                "SELECT task_list_task_set($1,$2,$3::text::jsonb,$4::text::jsonb,$5::text::jsonb)::text",
            ),
            WorkerWrite::TaskAssigneeSetStatus { .. } => (
                "TaskAssigned/setStatus",
                "SELECT task_assignee_set_status($1,$2,$3)::text",
            ),
        }
    }

    fn arity(self) -> usize {
        match self {
            WorkerWrite::TaskListDelete { .. } => 2,
            WorkerWrite::TaskListTaskSet { .. } => 5,
            _ => 3,
        }
    }
}

/// A Go worker-pool read: READ ONLY with the user GUC on the worker credential.
pub(crate) async fn worker_read(cx: &Cx<'_>, statement: WorkerRead) -> Result<String, MethodError> {
    let (method, sql) = statement.spec();
    if method != cx.method.name || !WORKER_METHODS.contains(&method) {
        return Err(refuse(cx, "worker read"));
    }
    let Some(services) = cx.services else {
        return Err(MethodError::server_fail());
    };
    let project = projection(cx.method.name);
    let list = match statement {
        WorkerRead::TaskListTasks { list } | WorkerRead::TaskListRoster { list } => Some(list),
        _ => None,
    };
    let mut bindings: Vec<Param<'_>> = vec![(&cx.user, Type::INT8)];
    if let Some(list) = &list {
        bindings.push((list, Type::INT8));
    }
    let rows = services
        .worker
        .read_user_scoped(cx.primary.actor(), sql, &bindings)
        .await
        .map_err(|failure| project(&failure))?;
    first_text(&rows).map_err(|failure| project(&failure))
}

/// A Go worker-pool write: one statement in its own transaction with the user GUC.
pub(crate) async fn worker_write(
    cx: &Cx<'_>,
    statement: WorkerWrite<'_>,
) -> Result<String, MethodError> {
    let (method, sql) = statement.spec();
    if method != cx.method.name || !WORKER_METHODS.contains(&method) {
        return Err(refuse(cx, "worker write"));
    }
    let Some(services) = cx.services else {
        return Err(MethodError::server_fail());
    };
    let Some(operation) = crate::jmap::random() else {
        return Err(MethodError::server_fail());
    };
    let worker = &services.worker;
    let actor = cx.primary.actor();
    let operation = OperationId(operation);
    let user = cx.user;
    let outcome = match statement {
        WorkerWrite::TaskListCreate { name, color } => {
            worker
                .run_user_command(
                    actor,
                    operation,
                    sql,
                    &[
                        (&user, Type::INT8),
                        (&name, Type::TEXT),
                        (&color, Type::TEXT),
                    ],
                    first_text,
                )
                .await
        }
        WorkerWrite::TaskListUpdate { list, patch } => {
            worker
                .run_user_command(
                    actor,
                    operation,
                    sql,
                    &[
                        (&user, Type::INT8),
                        (&list, Type::INT8),
                        (&patch, Type::TEXT),
                    ],
                    first_text,
                )
                .await
        }
        WorkerWrite::TaskListDelete { list } => {
            worker
                .run_user_command(
                    actor,
                    operation,
                    sql,
                    &[(&user, Type::INT8), (&list, Type::INT8)],
                    first_text,
                )
                .await
        }
        WorkerWrite::TaskListAddMember { list, email } => {
            worker
                .run_user_command(
                    actor,
                    operation,
                    sql,
                    &[
                        (&user, Type::INT8),
                        (&list, Type::INT8),
                        (&email, Type::TEXT),
                    ],
                    first_text,
                )
                .await
        }
        WorkerWrite::TaskListRemoveMember { list, member } => {
            worker
                .run_user_command(
                    actor,
                    operation,
                    sql,
                    &[
                        (&user, Type::INT8),
                        (&list, Type::INT8),
                        (&member, Type::INT8),
                    ],
                    first_text,
                )
                .await
        }
        WorkerWrite::TaskListTaskSet {
            list,
            creates,
            updates,
            destroys,
        } => {
            worker
                .run_user_command(
                    actor,
                    operation,
                    sql,
                    &[
                        (&user, Type::INT8),
                        (&list, Type::INT8),
                        (&creates, Type::TEXT),
                        (&updates, Type::TEXT),
                        (&destroys, Type::TEXT),
                    ],
                    first_text,
                )
                .await
        }
        WorkerWrite::TaskAssigneeSetStatus { task, status } => {
            worker
                .run_user_command(
                    actor,
                    operation,
                    sql,
                    &[
                        (&user, Type::INT8),
                        (&task, Type::INT8),
                        (&status, Type::TEXT),
                    ],
                    first_text,
                )
                .await
        }
    };
    settle(outcome, projection(cx.method.name))
}

/// Every worker read variant (tests and the schema guard).
#[cfg(test)]
const WORKER_READS: [WorkerRead; 5] = [
    WorkerRead::TaskListGet,
    WorkerRead::TaskListTasks { list: 1 },
    WorkerRead::TaskListRoster { list: 1 },
    WorkerRead::TasksAssignedToMe,
    WorkerRead::CalendarDelegates,
];

/// Every worker write variant (tests and the schema guard).
#[cfg(test)]
const WORKER_WRITES: [WorkerWrite<'static>; 7] = [
    WorkerWrite::TaskListCreate {
        name: "",
        color: None,
    },
    WorkerWrite::TaskListUpdate {
        list: 1,
        patch: "{}",
    },
    WorkerWrite::TaskListDelete { list: 1 },
    WorkerWrite::TaskListAddMember { list: 1, email: "" },
    WorkerWrite::TaskListRemoveMember { list: 1, member: 1 },
    WorkerWrite::TaskListTaskSet {
        list: 1,
        creates: None,
        updates: None,
        destroys: None,
    },
    WorkerWrite::TaskAssigneeSetStatus {
        task: 1,
        status: "",
    },
];

/// Every scoped query variant (tests and the schema guard).
#[cfg(test)]
const SCOPED_QUERIES: [ScopedQuery<'static>; 3] = [
    ScopedQuery::CalendarGetShared { owner_email: "" },
    ScopedQuery::CalendarEventGetShared {
        owner_email: "",
        after: None,
        before: None,
    },
    ScopedQuery::QuickStepApply { id: 1, message: 1 },
];

/// Test-only scoped read without the shape check (the GUC probe in account.rs).
#[cfg(test)]
pub(super) async fn read_unchecked(
    cx: &Cx<'_>,
    scope: &Scope,
    sql: &'static str,
) -> Result<String, MethodError> {
    let rows = cx
        .exec
        .read_scoped(&scope.auth, sql, &[])
        .await
        .map_err(|failure| reducer_error::project(&failure))?;
    first_text(&rows).map_err(|failure| reducer_error::project(&failure))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
    use setjoin_pg::{MailboxAuthContext, ScopedExecutor};

    use super::*;
    use crate::jmap::family::{always, Gate, Method, Reply};

    const GOLDEN: &str =
        include_str!("../../../../../../../mailserver/internal/jmap/testdata/methods.golden");

    #[test]
    fn owner_bound_accepts_only_anchored_reducer_calls() {
        for (sql, params) in [
            (read_sql!("SELECT reminders_get($1,$3)::text"), 1),
            (read_sql!("SELECT reminder_list($1)::text"), 0),
            (read_sql!("SELECT mail_work_get($1,$2,$3)::text"), 1),
            (
                read_sql!("SELECT mail_draft_get($1,$2,$3::text[]::uuid[])::text"),
                1,
            ),
            (
                read_sql!(
                    "SELECT mail_work_metrics_get($1,$2,$3::text::date,$4::text::date,$5)::text"
                ),
                3,
            ),
        ] {
            assert!(owner_bound(sql, Shape::Read, params), "{sql}");
        }
        for (sql, params) in [
            (
                write_sql!("SELECT reminder_snooze($1,$4,$5::text::timestamptz)::text"),
                2,
            ),
            (write_sql!("SELECT reminder_dismiss_all($1)::text"), 0),
            (write_sql!("SELECT mail_work_set($1,$2,$4)::text"), 1),
            (
                write_sql!("SELECT mail_draft_replace($1,$2,$3::text::uuid,$4)::text"),
                1,
            ),
        ] {
            assert!(owner_bound(sql, Shape::Write, params), "{sql}");
        }
        let set = set_sql!("jmap_task");
        for statement in [set.create, set.update, set.destroy] {
            assert!(owner_bound(statement, Shape::Read, 1), "{statement}");
        }
    }

    #[test]
    fn owner_bound_rejects_everything_else() {
        for (sql, params) in [
            ("SELECT f($1)::text", 0),
            (read_sql!("SELECT f($1) UNION SELECT g($2)"), 0),
            (read_sql!("SELECT f($2,$1)::text"), 0),
            (read_sql!("SELECT f($10)::text"), 0),
            (read_sql!("SELECT f($1,(SELECT 1))::text"), 0),
            ("SELECT f($1)::text WHERE $2::bigint>0; SELECT 1", 0),
            (read_sql!("SELECT x FROM t WHERE mailbox_id=$1"), 0),
            (read_sql!("SELECT f($1,$0)::text"), 0),
            (read_sql!("SELECT f($1,$02)::text"), 0),
            ("SELECT f($1)::text WHERE $2::bigint>0 -- x", 0),
            ("SELECT f($1)::text/* x */ WHERE $2::bigint>0", 0),
            (read_sql!("select f($1)::text"), 0),
            (read_sql!("SELECT public.f($1)::text"), 0),
            (read_sql!("SELECT f($1, $3)::text"), 1),
            ("SELECT f($1)::text WHERE $2::bigint>0 OR TRUE", 0),
            (write_sql!("SELECT f($1)::text"), 0),
        ] {
            assert!(!owner_bound(sql, Shape::Read, params), "{sql}");
        }
        assert!(
            !owner_bound(read_sql!("SELECT f($1)::text"), Shape::Write, 0),
            "a read tail on a write"
        );
        assert!(read_sql!("SELECT f($1)::text").ends_with(READ_TAIL));
        assert!(write_sql!("SELECT f($1)::text").ends_with(WRITE_TAIL));
    }

    /// `$2` is the seam-bound actor and `$1`/`$3` the seam's mailbox and
    /// operation: none of them may move, and the family params are exactly the
    /// placeholders above them. (Which reducer argument is the actor is a
    /// schema fact: `db::actor_arguments_are_seam_bound`.)
    #[test]
    fn the_actor_slot_takes_only_the_seam_actor() {
        for (sql, shape, params) in [
            (read_sql!("SELECT f($1,$3,$2)::text"), Shape::Read, 1),
            (read_sql!("SELECT f($1,$2,$2)::text"), Shape::Read, 0),
            (write_sql!("SELECT f($1,$4,$2)::text"), Shape::Write, 1),
            (read_sql!("SELECT f($1,$2,$1)::text"), Shape::Read, 0),
            (write_sql!("SELECT f($1,$3,$4)::text"), Shape::Write, 1),
            (write_sql!("SELECT f($1,$4,$5,$3)::text"), Shape::Write, 2),
            (read_sql!("SELECT f($1,$2::bigint[])::text"), Shape::Read, 1),
            (read_sql!("SELECT f($1,$3)::text"), Shape::Read, 0),
            (read_sql!("SELECT f($1,$3)::text"), Shape::Read, 2),
            (write_sql!("SELECT f($1,$4)::text"), Shape::Write, 0),
            (write_sql!("SELECT f($1,$2)::text"), Shape::Write, 1),
        ] {
            assert!(
                !owner_bound(sql, shape, params),
                "{sql} ({shape:?}, {params})"
            );
        }
    }

    #[test]
    fn worker_table_is_closed_and_user_keyed() {
        let highest = |sql: &str| {
            Regex::new(r"\$([0-9]+)")
                .expect("placeholder pattern")
                .captures_iter(sql)
                .map(|c| c[1].parse::<usize>().expect("placeholder"))
                .max()
                .unwrap_or(0)
        };
        let user_keyed = |sql: &str| {
            Regex::new(r"^SELECT [a-z_]+\(\$1[,)]")
                .expect("call pattern")
                .is_match(sql)
                || sql.contains("d.user_id = $1")
        };
        let mut methods = BTreeSet::new();
        for statement in WORKER_READS {
            let (method, sql) = statement.spec();
            assert!(user_keyed(sql), "{sql}");
            assert_eq!(highest(sql), statement.arity(), "{sql}");
            methods.insert(method);
        }
        for statement in WORKER_WRITES {
            let (method, sql) = statement.spec();
            assert!(user_keyed(sql), "{sql}");
            assert_eq!(highest(sql), statement.arity(), "{sql}");
            methods.insert(method);
        }
        let expected: BTreeSet<&str> = WORKER_METHODS.iter().copied().collect();
        assert_eq!(methods, expected);
        assert!(
            matches!(
                WORKER_WRITES[0],
                WorkerWrite::TaskListCreate { color: None, .. }
            ),
            "Go's *string color: an absent color binds NULL"
        );
    }

    /// Exhaustive on purpose: a new variant does not compile until it is
    /// numbered here and listed in `SCOPED_QUERIES`.
    fn position(statement: ScopedQuery<'_>) -> usize {
        match statement {
            ScopedQuery::CalendarGetShared { .. } => 0,
            ScopedQuery::CalendarEventGetShared { .. } => 1,
            ScopedQuery::QuickStepApply { .. } => 2,
        }
    }

    #[test]
    fn scoped_queries_are_closed_and_bound() {
        let positions: Vec<usize> = SCOPED_QUERIES
            .iter()
            .map(|statement| position(*statement))
            .collect();
        assert_eq!(positions, (0..SCOPED_QUERIES.len()).collect::<Vec<_>>());
        let placeholder = Regex::new(r"\$([0-9]+)").expect("placeholder pattern");
        let mut methods = BTreeSet::new();
        for statement in SCOPED_QUERIES {
            let (method, command, sql) = statement.spec();
            assert!(methods.insert(method), "{method} has exactly one statement");
            assert!(
                GOLDEN
                    .lines()
                    .any(|line| line.starts_with(&format!("{method}\t"))),
                "{method} is not in methods.golden"
            );
            assert!(!WORKER_METHODS.contains(&method), "{method}");
            let numbers: BTreeSet<usize> = placeholder
                .captures_iter(sql)
                .map(|c| c[1].parse().expect("placeholder"))
                .collect();
            let seam = if command.is_some() { 3 } else { 2 };
            let expected: BTreeSet<usize> = (1..=seam + statement.arity()).collect();
            assert_eq!(
                numbers, expected,
                "{sql}: every seam placeholder and param is referenced"
            );
            if command.is_some() {
                assert!(sql.ends_with(WRITE_TAIL), "{sql}");
            } else {
                assert!(sql.ends_with("$2::bigint>0"), "{sql}");
            }
            assert!(
                !sql.contains(';') && !sql.contains("--") && !sql.contains("/*"),
                "{sql}"
            );
            let upper = sql.to_ascii_uppercase();
            for word in [" OR ", " UNION ", " INTERSECT ", " EXCEPT ", " INTO ", "SET_CONFIG"] {
                assert!(!upper.contains(word), "{sql}: {word}");
            }
            for registered in crate::jmap::family::registered() {
                if registered.name == method {
                    assert_eq!(registered.mutator, command.is_some(), "{method} mutator");
                    assert!(registered.account, "{method} resolves a scope");
                }
            }
        }
        assert!(CALENDAR_GET_SHARED.starts_with("SELECT jmap_calendar_get_shared($2,"));
        assert!(CALENDAR_EVENT_GET_SHARED.starts_with("SELECT jmap_calendar_event_get_shared($2,"));
        assert!(QUICK_STEP_APPLY.contains("FROM messages WHERE mailbox_id = $1 AND id = $5"));
        assert!(QUICK_STEP_APPLY.contains("quick_step_apply($1,$4,$5,r.received_at)"));
        assert!(DELEGATE_RSVP.contains("jmap_calendar_event_rsvp($1,$4,$5,$6,$2)"));
        assert!(DELEGATE_RSVP.ends_with(WRITE_TAIL));
        assert!(DELEGATE_MAILBOX.contains("d.user_id = $1"));
        assert!(DELEGATE_MAILBOX.contains("m.email = $2"));
        assert!(DELEGATE_MAILBOX.contains("m.is_primary = TRUE"));
        assert!(DELEGATE_MAILBOX.contains("d.permission IN ('full_access','manage_calendar')"));
    }

    #[test]
    fn the_method_selects_the_error_projection() {
        let missing = StatementFailure {
            sqlstate: Some("BZ001".to_owned()),
            message: "Calendar not found".to_owned(),
            hint: Some(r#"{"type":"forbidden"}"#.to_owned()),
        };
        let foreign = StatementFailure {
            sqlstate: Some("BZ001".to_owned()),
            message: "Calendar not found in this account".to_owned(),
            hint: Some(r#"{"type":"forbidden","calendar_id":"7"}"#.to_owned()),
        };
        let forbidden = MethodError::new("forbidden", "not authorized for this calendar");
        for method in CALENDAR_A3_METHODS {
            // A missing and a foreign calendar are indistinguishable.
            assert_eq!(projection(method)(&missing), forbidden, "{method}");
            assert_eq!(projection(method)(&foreign), forbidden, "{method}");
        }
        for method in [
            "Calendar/get",
            "Calendar/set",
            "CalendarEvent/rsvp",
            "Reminder/get",
            "QuickStep/apply",
            "TaskList/set",
        ] {
            assert_eq!(
                projection(method)(&missing),
                MethodError::server_fail(),
                "{method}"
            );
            assert_eq!(
                projection(method)(&foreign),
                MethodError::server_fail(),
                "{method}"
            );
        }
    }

    #[test]
    fn id_lists_follow_go() {
        assert_eq!(parse_id_list(&[]), (None, vec![]));
        assert_eq!(
            parse_id_list(&["x".to_owned()]),
            (Some(vec![]), vec!["x".to_owned()])
        );
        assert_eq!(
            parse_id_list(&["5".to_owned(), "0".to_owned()]),
            (Some(vec![5]), vec!["0".to_owned()])
        );
        assert!(since_state("0").is_ok());
        assert_eq!(
            since_state("-1").unwrap_err().kind,
            "cannotCalculateChanges"
        );
    }

    fn run_none<'a>(_: &'a Cx<'a>) -> Reply<'a> {
        Box::pin(async { Err(MethodError::server_fail()) })
    }

    static PROBE: Method = Method {
        name: "Probe/get",
        capability: "urn:test",
        app: "",
        gate: Gate::Personal,
        account: true,
        mutator: true,
        state: false,
        ready: always,
        run: run_none,
    };

    static WORKER_PROBE: Method = Method {
        name: "TaskList/get",
        capability: "urn:test",
        app: "",
        gate: Gate::Personal,
        account: false,
        mutator: false,
        state: false,
        ready: always,
        run: run_none,
    };

    static APPLY_PROBE: Method = Method {
        name: "QuickStep/apply",
        capability: "urn:test",
        app: "",
        gate: Gate::Personal,
        account: true,
        mutator: true,
        state: false,
        ready: always,
        run: run_none,
    };

    static IMIP_PROBE: Method = Method {
        name: "CalendarEvent/counter",
        capability: "urn:test",
        app: "",
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: run_none,
    };

    fn refusals() -> usize {
        REFUSALS.with(|count| count.get())
    }

    fn probe_auth() -> MailboxAuthContext {
        MailboxAuthContext::from_authenticated_session(
            ActorId::new(1).expect("actor"),
            MailboxId::new(2).expect("mailbox"),
            Generation(1),
        )
    }

    /// Each bad statement is stopped by the seam (refusal counted), while a
    /// well-formed one passes it and only then fails on the closed port.
    #[tokio::test]
    async fn the_seam_refuses_before_touching_the_database() {
        let exec = ScopedExecutor::from_dsn("host=127.0.0.1 port=1 user=x dbname=x", 1)
            .expect("lazy pool");
        let auth = probe_auth();
        let cx = Cx::new(&exec, None, &auth, 1, 2, &PROBE, "{}");
        let scope = Scope {
            mailbox: 2,
            auth: probe_auth(),
            delegated: false,
        };
        let ids: Option<Vec<i64>> = None;
        let start = refusals();
        assert!(read(&cx, &scope, read_sql!("SELECT f($2,$1)::text"), &[])
            .await
            .is_err());
        assert_eq!(refusals(), start + 1, "rogue read refused by the seam");
        assert!(read(&cx, &scope, "SELECT f($1)::text", &[]).await.is_err());
        assert_eq!(refusals(), start + 2, "read without the actor tail refused");
        assert!(read(
            &cx,
            &scope,
            read_sql!("SELECT f($1,$2::bigint[])::text"),
            &[(&ids, Type::INT8_ARRAY)]
        )
        .await
        .is_err());
        assert_eq!(
            refusals(),
            start + 3,
            "an unrenumbered read (family param at $2) refused"
        );
        assert!(read(
            &cx,
            &scope,
            read_sql!("SELECT f($1,$3::bigint[])::text"),
            &[(&ids, Type::INT8_ARRAY)]
        )
        .await
        .is_err());
        assert_eq!(refusals(), start + 3, "well-formed read passed the seam");
        assert!(write(&cx, &scope, "probe", "SELECT f($1)::text", &[])
            .await
            .is_err());
        assert_eq!(
            refusals(),
            start + 4,
            "write without the receipt tail refused"
        );
        assert!(
            write(&cx, &scope, "probe", write_sql!("SELECT f($1)::text"), &[])
                .await
                .is_err()
        );
        assert_eq!(refusals(), start + 4, "well-formed write passed the seam");
        let rogue = SetSql::new(
            "SELECT f($2,$1)::text WHERE $2::bigint>0",
            "SELECT g($1,$3::text::jsonb)::text WHERE $2::bigint>0",
            "SELECT h($1,$3::bigint[])::text WHERE $2::bigint>0",
        );
        assert!(
            set_batch(&cx, &scope, rogue, "probe", Some("{}"), None, None)
                .await
                .is_err()
        );
        assert_eq!(refusals(), start + 5, "rogue set statement refused");
        let stale = SetSql::new(
            "SELECT f_set_create($1,$2::text::jsonb)::text",
            "SELECT f_set_update($1,$2::text::jsonb)::text",
            "SELECT f_set_destroy($1,$2::bigint[])::text",
        );
        assert!(
            set_batch(&cx, &scope, stale, "probe", Some("{}"), None, None)
                .await
                .is_err()
        );
        assert_eq!(
            refusals(),
            start + 6,
            "a set statement with the payload at $2 refused"
        );
        assert!(
            set_batch(&cx, &scope, set_sql!("f"), "probe", Some("{}"), None, None)
                .await
                .is_err()
        );
        assert_eq!(refusals(), start + 6, "set_sql! passes the seam");
        assert!(
            query(&cx, &scope, ScopedQuery::QuickStepApply { id: 1, message: 1 })
                .await
                .is_err()
        );
        assert_eq!(
            refusals(),
            start + 7,
            "scoped query under a foreign method refused"
        );
        let apply_cx = Cx::new(&exec, None, &auth, 1, 2, &APPLY_PROBE, "{}");
        assert!(
            query(&apply_cx, &scope, ScopedQuery::QuickStepApply { id: 1, message: 1 })
                .await
                .is_err()
        );
        assert_eq!(refusals(), start + 7, "its own scoped query passes the seam");
        assert!(query(
            &apply_cx,
            &scope,
            ScopedQuery::CalendarGetShared { owner_email: "x@y" }
        )
        .await
        .is_err());
        assert_eq!(
            refusals(),
            start + 8,
            "another method's scoped query refused"
        );
        assert!(worker_read(&cx, WorkerRead::TaskListGet).await.is_err());
        assert_eq!(
            refusals(),
            start + 9,
            "worker read under a foreign method refused"
        );
        assert!(worker_write(&cx, WorkerWrite::TaskListDelete { list: 1 })
            .await
            .is_err());
        assert_eq!(
            refusals(),
            start + 10,
            "worker write under a foreign method refused"
        );
        let worker_cx = Cx::new(&exec, None, &auth, 1, 2, &WORKER_PROBE, "{}");
        assert!(worker_read(&worker_cx, WorkerRead::TaskListGet)
            .await
            .is_err());
        assert_eq!(
            refusals(),
            start + 10,
            "its own worker statement passes the seam (fails only for missing services)"
        );
        assert!(worker_read(&worker_cx, WorkerRead::TasksAssignedToMe)
            .await
            .is_err());
        assert_eq!(
            refusals(),
            start + 11,
            "another method's worker statement refused"
        );
        assert!(
            read_rows(&cx, &scope, "SELECT f($1) UNION SELECT g($1)", &[])
                .await
                .is_err()
        );
        assert_eq!(refusals(), start + 12, "rogue set-returning read refused");
        assert!(read_rows(
            &cx,
            &scope,
            read_sql!("SELECT f($1,$3::bigint[])::text"),
            &[(&ids, Type::INT8_ARRAY)]
        )
        .await
        .is_err());
        assert_eq!(refusals(), start + 12, "well-formed read_rows passed the seam");
        assert!(rsvp_on_behalf(&cx, "o@x.test", 1, "accepted").await.is_err());
        assert_eq!(
            refusals(),
            start + 13,
            "on-behalf RSVP under a foreign method refused"
        );
        send_imip(
            &cx,
            Imip {
                message_id: "u".into(),
                from: "a@x.test".into(),
                recipients: vec!["b@y.test".into()],
                mime: String::new(),
            },
        );
        assert_eq!(refusals(), start + 14, "egress under a foreign method refused");
        assert!(query(
            &cx,
            &scope,
            ScopedQuery::CalendarEventGetShared {
                owner_email: "o@x.test",
                after: None,
                before: None
            }
        )
        .await
        .is_err());
        assert_eq!(
            refusals(),
            start + 15,
            "event getShared under a foreign method refused"
        );
        assert_eq!(cx.email(), "", "Go's zero value until attached");
        let attached = Cx::new(&exec, None, &auth, 1, 2, &PROBE, "{}").with_email("v@x.test");
        assert_eq!(attached.email(), "v@x.test");
    }

    /// F9: at most `MAX_MESSAGES_PER_REQUEST` messages leave per method call (per `Cx`); the
    /// next one is dropped and named, before any store or database use.
    #[tokio::test]
    async fn egress_is_bounded_per_request() {
        let exec = ScopedExecutor::from_dsn("host=127.0.0.1 port=1 user=x dbname=x", 1)
            .expect("lazy pool");
        let auth = probe_auth();
        let cx = Cx::new(&exec, None, &auth, 1, 2, &IMIP_PROBE, "{}");
        let mail = || Imip {
            message_id: "u".into(),
            from: "a@x.test".into(),
            recipients: vec!["b@y.test".into()],
            mime: String::new(),
        };
        let last = || crate::jmap::imip::LAST_DROP.with(|reason| reason.get());
        let start = refusals();
        for _ in 0..crate::jmap::imip::MAX_MESSAGES_PER_REQUEST {
            send_imip(&cx, mail());
            assert_eq!(last(), Some("no object store"));
        }
        send_imip(&cx, mail());
        assert_eq!(last(), Some("per-request message bound"));
        assert_eq!(refusals(), start, "an egress method is never refused");
    }
}

/// Runs on the server-rust lane (nextest profile `lane`, per-test clone,
/// REQUIRE_DB=1: `Db::for_case` panics there instead of skipping).
#[cfg(test)]
mod db {
    use futures_util::FutureExt;
    use serde_json::Value;
    use setjoin_conformance::fixture::{self, Account};
    use setjoin_conformance::harness::Db;
    use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
    use setjoin_pg::{MailboxAuthContext, ScopedExecutor};
    use tokio_postgres::Client;

    use super::super::resolve;
    use super::*;
    use crate::jmap::family::{always, Gate, Method, Reply};

    /// Reducer parameters that carry the acting user's authority. A scoped
    /// statement passes `$2` there and nowhere else; a worker statement `$1`.
    const ACTOR_ARGUMENTS: &[&str] = &[
        "p_actor",
        "p_actor_id",
        "p_actor_user_id",
        "p_caller_id",
        "p_caller_user_id",
        "p_on_behalf_of",
        "p_requester_id",
        "p_user",
        "p_user_id",
        "p_viewer",
        "p_viewer_id",
    ];
    /// Reviewed user-shaped parameters that are not the actor. `p_actor_email`
    /// is the verified token email (`Cx::email`), covered per call site by the
    /// #369 email tests, not by this id guard.
    const NON_ACTOR_ARGUMENTS: &[&str] = &[
        "p_actor_email",
        "p_assignee_user_id",
        "p_handoff_user_id",
        "p_member_user_id",
        "p_mention_user_ids",
        "p_target_user_id",
        "p_user_ids",
    ];
    /// The names a scoped statement's `$1` (the scope mailbox) may land on.
    const MAILBOX_ARGUMENTS: &[&str] = &["p_account_id", "p_mailbox_id"];
    /// Functions a family calls on purpose although no public signature exists
    /// (#370 mirrors Go bug G1, contacts.go:170). Reviewed; must stay missing.
    const KNOWN_MISSING: &[&str] = &[
        "jmap_contactcard_set_create",
        "jmap_contactcard_set_destroy",
        "jmap_contactcard_set_update",
    ];

    fn user_shaped() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| {
            Regex::new(r"user|actor|caller|viewer|requester|principal|delegate|behalf")
                .expect("user-shaped pattern")
        })
    }

    /// `Ok(true)` an actor parameter, `Ok(false)` any other reviewed or
    /// non-user parameter, `Err` a user-shaped name nobody reviewed.
    fn classify(name: &str) -> Result<bool, String> {
        if ACTOR_ARGUMENTS.contains(&name) {
            Ok(true)
        } else if NON_ACTOR_ARGUMENTS.contains(&name) || !user_shaped().is_match(name) {
            Ok(false)
        } else {
            Err(format!("unreviewed user-shaped parameter {name}"))
        }
    }

    /// Input-argument names of every public function called `name`.
    async fn signatures(owner: &Client, name: &str) -> Vec<Vec<String>> {
        owner
            .query(
                "SELECT ARRAY(SELECT a.n FROM unnest(p.proargnames, COALESCE(p.proargmodes, \
                 array_fill('i'::\"char\", ARRAY[cardinality(p.proargnames)]))) AS a(n, m) \
                 WHERE a.m IN ('i', 'b', 'v'))::text[] FROM pg_proc p \
                 WHERE p.proname = $1 AND p.pronamespace = 'public'::regnamespace \
                 AND p.proargnames IS NOT NULL",
                &[&name],
            )
            .await
            .expect("pg_proc")
            .iter()
            .map(|row| row.get::<_, Vec<String>>(0))
            .collect()
    }

    /// Every rule a statement breaks. `actor` is the placeholder holding the
    /// verified user (2 scoped, 1 worker); `scoped` adds the `$1` mailbox rule.
    async fn violations(
        owner: &Client,
        origin: &str,
        sql: &str,
        actor: usize,
        scoped: bool,
    ) -> Vec<String> {
        let call = Regex::new(r"([a-z_][a-z0-9_]*)\(([^()]*)\)").expect("call pattern");
        let placeholder = Regex::new(r"^\$([0-9]+)").expect("placeholder pattern");
        let mut found = Vec::new();
        for captures in call.captures_iter(sql) {
            let function = &captures[1];
            let arguments: Vec<Option<usize>> = captures[2]
                .split(',')
                .map(|argument| {
                    placeholder
                        .captures(argument.trim())
                        .and_then(|number| number[1].parse().ok())
                })
                .collect();
            if arguments.iter().all(Option::is_none) {
                continue;
            }
            let fitting: Vec<Vec<String>> = signatures(owner, function)
                .await
                .into_iter()
                .filter(|names| names.len() >= arguments.len())
                .collect();
            if fitting.is_empty() {
                if !KNOWN_MISSING.contains(&function) {
                    found.push(format!("{origin}: {function} has no public signature"));
                }
                continue;
            }
            for names in &fitting {
                for (index, argument) in arguments.iter().enumerate() {
                    let name = names[index].as_str();
                    let actor_named = match classify(name) {
                        Ok(actor_named) => actor_named,
                        Err(error) => {
                            found.push(format!("{origin}: {function}: {error}"));
                            continue;
                        }
                    };
                    if actor_named != (*argument == Some(actor)) {
                        found.push(format!(
                            "{origin}: {function} argument {} ({name}) is {:?}",
                            index + 1,
                            argument
                        ));
                    }
                    if scoped && *argument == Some(1) && !MAILBOX_ARGUMENTS.contains(&name) {
                        found.push(format!(
                            "{origin}: {function} gets the scope mailbox in {name}"
                        ));
                    }
                }
            }
        }
        found
    }

    /// Statement literals in the family files (the seam excluded) and the
    /// statements their `set_sql!` prefixes expand to. The static guard makes
    /// these the only way SQL reaches the seam (no `concat!`, macros, `leak`).
    fn family_statements() -> Vec<(String, String)> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/jmap/family");
        let literal = Regex::new(r#""(SELECT [^"]*)""#).expect("literal pattern");
        let set = Regex::new(r#"set_sql!\("([a-z_][a-z0-9_]*)"\)"#).expect("set pattern");
        let mut statements = Vec::new();
        for entry in std::fs::read_dir(&root).expect("family directory") {
            let path = entry.expect("family entry").path();
            if path.is_dir() {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("?")
                .to_owned();
            let text = std::fs::read_to_string(&path).expect("family file");
            for captures in literal.captures_iter(&text) {
                statements.push((name.clone(), captures[1].to_owned()));
            }
            for captures in set.captures_iter(&text) {
                for phase in ["create", "update", "destroy"] {
                    statements.push((
                        name.clone(),
                        format!("SELECT {}_set_{phase}($1,$3)", &captures[1]),
                    ));
                }
            }
        }
        statements
    }

    fn worker_statements() -> Vec<(&'static str, &'static str)> {
        WORKER_READS
            .iter()
            .map(|statement| statement.spec())
            .chain(WORKER_WRITES.iter().map(|statement| statement.spec()))
            .collect()
    }

    #[test]
    fn user_shaped_names_are_classified() {
        assert_eq!(classify("p_user_id"), Ok(true));
        assert_eq!(classify("p_on_behalf_of"), Ok(true));
        assert_eq!(classify("p_member_user_id"), Ok(false));
        assert_eq!(classify("p_mailbox_id"), Ok(false));
        assert_eq!(classify("p_ids"), Ok(false));
        for unknown in ["p_delegate_id", "p_sender_user_id", "p_principal", "p_caller"] {
            assert!(classify(unknown).is_err(), "{unknown}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actor_arguments_are_seam_bound() {
        let Some(db) = Db::for_case("actor_arguments_are_seam_bound") else {
            return;
        };
        let owner = db.connect().await.expect("owner connection");
        let mut found = Vec::new();
        for (origin, sql) in family_statements() {
            found.extend(violations(&owner, &origin, &sql, 2, true).await);
        }
        for statement in SCOPED_QUERIES {
            let (method, _, sql) = statement.spec();
            found.extend(violations(&owner, method, sql, 2, true).await);
        }
        found.extend(violations(&owner, "CalendarEvent/rsvp", DELEGATE_RSVP, 2, true).await);
        for (method, sql) in worker_statements() {
            found.extend(violations(&owner, method, sql, 1, false).await);
        }
        assert!(found.is_empty(), "{found:#?}");
        for missing in KNOWN_MISSING {
            assert!(
                signatures(&owner, missing).await.is_empty(),
                "{missing} exists now: remove it from KNOWN_MISSING"
            );
        }
        for (sql, actor, scoped, why) in [
            (
                "SELECT mail_work_get($1,$3,$4)",
                2,
                true,
                "a family param in the actor slot",
            ),
            (
                "SELECT jmap_calendar_get($1,$2)",
                2,
                true,
                "the actor in a non-actor slot",
            ),
            (
                "SELECT jmap_calendar_get_shared($3,$2)",
                2,
                true,
                "the viewer from a family param",
            ),
            (
                "SELECT jmap_calendar_event_rsvp($1,$4,$5,$6,$3)",
                2,
                true,
                "the on-behalf user from a non-actor placeholder",
            ),
            (
                "SELECT no_such_reducer_seam_probe($1,$3)",
                2,
                true,
                "a missing signature",
            ),
            (
                "SELECT quick_step_action_allowed($1)",
                2,
                true,
                "the scope mailbox in a non-mailbox parameter",
            ),
            (
                "SELECT task_list_get($2)",
                1,
                false,
                "a worker user from a family param",
            ),
        ] {
            assert!(
                !violations(&owner, "fixture", sql, actor, scoped)
                    .await
                    .is_empty(),
                "{why}: {sql}"
            );
        }
        assert!(
            violations(
                &owner,
                "fixture",
                "SELECT jmap_contactcard_set_create($1,$3)",
                2,
                true
            )
            .await
            .is_empty(),
            "a reviewed known-missing function"
        );
    }

    fn run_none<'a>(_: &'a Cx<'a>) -> Reply<'a> {
        Box::pin(async { Err(MethodError::server_fail()) })
    }

    const fn probe(name: &'static str, gate: Gate, mutator: bool) -> Method {
        Method {
            name,
            capability: "urn:test",
            app: "",
            gate,
            account: true,
            mutator,
            state: false,
            ready: always,
            run: run_none,
        }
    }

    /// Read gates so a delegated scope can be resolved too.
    static SHARED_PROBE: Method = probe("Calendar/getShared", Gate::Read, false);
    static EVENT_SHARED_PROBE: Method = probe("CalendarEvent/getShared", Gate::Read, false);
    static APPLY_PROBE: Method = probe("QuickStep/apply", Gate::Personal, true);
    static RSVP_PROBE: Method = probe("CalendarEvent/rsvp", Gate::Personal, true);

    async fn email(owner: &Client, mailbox: i64) -> String {
        owner
            .query_one("SELECT email FROM mailboxes WHERE id = $1", &[&mailbox])
            .await
            .expect("mailbox email")
            .get(0)
    }

    async fn grant(owner: &Client, mailbox: &Account, user: &Account, permission: &str) {
        owner
            .execute(
                "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
                 VALUES ($1, $2, $3, $4)",
                &[&mailbox.mailbox, &user.user, &permission, &mailbox.user],
            )
            .await
            .expect("grant");
    }

    async fn revoke(owner: &Client, mailbox: &Account) {
        owner
            .execute(
                "DELETE FROM mailbox_delegates WHERE mailbox_id = $1",
                &[&mailbox.mailbox],
            )
            .await
            .expect("revoke");
    }

    async fn set_suspended(owner: &Client, mailbox: i64, suspended: bool) {
        owner
            .execute(
                "UPDATE mailboxes SET enabled = $2 WHERE id = $1",
                &[&mailbox, &!suspended],
            )
            .await
            .expect("mailbox enabled");
        let state = if suspended { "suspended" } else { "active" };
        owner
            .execute(
                "UPDATE mailbox_lifecycle SET access_state = $2, generation = generation + 1, \
                 updated_at = statement_timestamp() \
                 WHERE mailbox_id = $1 AND binding_state IN ('bound','shared')",
                &[&mailbox, &state],
            )
            .await
            .expect("lifecycle access state");
    }

    async fn quick_step(owner: &Client, mailbox: i64) -> i64 {
        owner
            .query_one(
                "INSERT INTO quick_steps (mailbox_id, name, actions) \
                 VALUES ($1, 'seam', '[{\"type\":\"mark_read\"}]'::jsonb) RETURNING id",
                &[&mailbox],
            )
            .await
            .expect("quick step")
            .get(0)
    }

    async fn message_row(owner: &Client, message: i64) -> String {
        owner
            .query_one(
                "SELECT row_to_json(m)::text FROM messages m WHERE id = $1",
                &[&message],
            )
            .await
            .expect("message row")
            .get(0)
    }

    async fn is_read(owner: &Client, message: i64) -> bool {
        owner
            .query_one("SELECT is_read FROM messages WHERE id = $1", &[&message])
            .await
            .expect("is_read")
            .get(0)
    }

    async fn scoped_query_cases(db: &Db, owner: &Client, a: &Account, f: &Account) {
        let exec =
            ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).expect("executor");
        let primary = MailboxAuthContext::from_authenticated_session(
            ActorId::new(a.user).expect("actor"),
            MailboxId::new(a.mailbox).expect("mailbox"),
            Generation(1),
        );
        let foreign_email = email(owner, f.mailbox).await;
        grant(owner, f, a, "read").await;
        // Both getShared statements: the viewer is the session user on the
        // primary scope and on a delegated one, never the scope's owner.
        for (method, statement) in [
            (
                &SHARED_PROBE,
                ScopedQuery::CalendarGetShared {
                    owner_email: &foreign_email,
                },
            ),
            (
                &EVENT_SHARED_PROBE,
                ScopedQuery::CalendarEventGetShared {
                    owner_email: &foreign_email,
                    after: None,
                    before: None,
                },
            ),
        ] {
            let cx = Cx::new(&exec, None, &primary, a.user, a.mailbox, method, "{}");
            let own = resolve(&cx, &a.mailbox.to_string())
                .await
                .expect("own scope");
            let delegated = resolve(&cx, &f.mailbox.to_string())
                .await
                .expect("delegated scope");
            assert!(!own.delegated() && delegated.delegated());
            for scope in [&own, &delegated] {
                let raw = query(&cx, scope, statement).await.expect("getShared");
                let value: Value = serde_json::from_str(&raw).expect("getShared json");
                assert_eq!(
                    value["accountId"],
                    Value::String(a.user.to_string()),
                    "{}: {raw}",
                    method.name
                );
            }
        }
        revoke(owner, f).await;

        // QuickStep/apply: the lookup and the reducer stay in the scope mailbox.
        let cx = Cx::new(&exec, None, &primary, a.user, a.mailbox, &APPLY_PROBE, "{}");
        let scope = resolve(&cx, &a.mailbox.to_string())
            .await
            .expect("own scope");
        let step = quick_step(owner, a.mailbox).await;
        let foreign_step = quick_step(owner, f.mailbox).await;
        let foreign_before = message_row(owner, f.inbox_only).await;
        assert_eq!(
            query(
                &cx,
                &scope,
                ScopedQuery::QuickStepApply {
                    id: step,
                    message: f.inbox_only
                }
            )
            .await,
            Ok("null".to_owned()),
            "a foreign message is not found"
        );
        assert_eq!(
            message_row(owner, f.inbox_only).await,
            foreign_before,
            "the foreign message is unchanged"
        );
        assert_eq!(
            query(
                &cx,
                &scope,
                ScopedQuery::QuickStepApply {
                    id: foreign_step,
                    message: a.inbox_only
                }
            )
            .await
            .map_err(|error| error.kind),
            Err("notFound".to_owned()),
            "a foreign quick step is not found"
        );
        assert!(
            !is_read(owner, a.inbox_only).await,
            "the refused apply rolled back"
        );
        assert_eq!(
            query(
                &cx,
                &scope,
                ScopedQuery::QuickStepApply {
                    id: step,
                    message: a.inbox_only
                }
            )
            .await,
            Ok(String::new()),
            "the void reducer ran"
        );
        assert!(is_read(owner, a.inbox_only).await, "mark_read committed");
    }

    async fn rsvp_cases(db: &Db, owner: &Client, a: &Account, f: &Account) {
        let exec =
            ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).expect("executor");
        let primary = MailboxAuthContext::from_authenticated_session(
            ActorId::new(a.user).expect("actor"),
            MailboxId::new(a.mailbox).expect("mailbox"),
            Generation(1),
        );
        let cx = Cx::new(&exec, None, &primary, a.user, a.mailbox, &RSVP_PROBE, "{}");
        let manager = email(owner, f.mailbox).await;
        let own = email(owner, a.mailbox).await;
        let missing = MethodError::new("notFound", "manager mailbox not found");
        // No grant, an unknown address and one's own mailbox are identical.
        for address in [manager.as_str(), "nobody@nowhere.invalid", own.as_str()] {
            assert_eq!(
                rsvp_on_behalf(&cx, address, 0, "accepted").await,
                Err(missing.clone()),
                "{address}"
            );
        }
        for permission in ["read", "send_as", "send_on_behalf"] {
            grant(owner, f, a, permission).await;
            assert_eq!(
                rsvp_on_behalf(&cx, &manager, 0, "accepted").await,
                Err(missing.clone()),
                "{permission} is not a calendar-respond grant"
            );
            revoke(owner, f).await;
        }
        for permission in ["manage_calendar", "full_access"] {
            grant(owner, f, a, permission).await;
            let raw = rsvp_on_behalf(&cx, &manager, 0, "accepted")
                .await
                .unwrap_or_else(|error| panic!("{permission}: {error:?}"));
            assert!(raw.contains("Event not found in this account"), "{raw}");
            revoke(owner, f).await;
        }
        grant(owner, f, a, "manage_calendar").await;
        set_suspended(owner, f.mailbox, true).await;
        assert_eq!(
            rsvp_on_behalf(&cx, &manager, 0, "accepted").await,
            Err(MethodError::new(
                "forbidden",
                "mailbox access is suspended or detached"
            )),
            "a suspended manager mailbox is not written"
        );
        set_suspended(owner, f.mailbox, false).await;
        revoke(owner, f).await;
    }

    async fn finish(
        owner: &Client,
        a: &Account,
        f: &Account,
        outcome: std::thread::Result<()>,
    ) {
        let mailboxes = vec![a.mailbox, f.mailbox];
        let _ = owner
            .execute(
                "DELETE FROM mailbox_delegates WHERE mailbox_id = ANY($1)",
                &[&mailboxes],
            )
            .await;
        let _ = owner
            .execute(
                "DELETE FROM quick_steps WHERE mailbox_id = ANY($1)",
                &[&mailboxes],
            )
            .await;
        let _ = owner
            .execute(
                "UPDATE mailboxes SET enabled = true WHERE id = ANY($1)",
                &[&mailboxes],
            )
            .await;
        let _ = owner
            .execute(
                "UPDATE mailbox_lifecycle SET access_state = 'active', generation = generation + 1, \
                 updated_at = statement_timestamp() \
                 WHERE mailbox_id = ANY($1) AND access_state = 'suspended'",
                &[&mailboxes],
            )
            .await;
        fixture::remove(owner, f).await.expect("remove foreign");
        fixture::remove(owner, a).await.expect("remove own");
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scoped_queries_bind_the_session_actor() {
        let Some(db) = Db::for_case("scoped_queries_bind_the_session_actor") else {
            return;
        };
        let owner = db.connect().await.expect("owner connection");
        let a = fixture::account(&owner, "famseamq")
            .await
            .expect("own fixture");
        let f = fixture::account(&owner, "famseamq-foreign")
            .await
            .expect("foreign fixture");
        let outcome = std::panic::AssertUnwindSafe(scoped_query_cases(&db, &owner, &a, &f))
            .catch_unwind()
            .await;
        finish(&owner, &a, &f, outcome).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rsvp_on_behalf_requires_a_calendar_grant() {
        let Some(db) = Db::for_case("rsvp_on_behalf_requires_a_calendar_grant") else {
            return;
        };
        let owner = db.connect().await.expect("owner connection");
        let a = fixture::account(&owner, "famseamr")
            .await
            .expect("own fixture");
        let f = fixture::account(&owner, "famseamr-manager")
            .await
            .expect("manager fixture");
        let outcome = std::panic::AssertUnwindSafe(rsvp_cases(&db, &owner, &a, &f))
            .catch_unwind()
            .await;
        finish(&owner, &a, &f, outcome).await;
    }
}
