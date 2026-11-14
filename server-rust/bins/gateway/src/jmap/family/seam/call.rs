//! Reducer calls under a resolved [`Scope`] (Go `CallScoped`/`CallScopedBatch`)
//! and the closed table of user-keyed worker statements (Go `h.workerPool`).
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Instant;

use regex::Regex;
use serde_json::value::RawValue;
use setjoin_contracts::command::CommandEnvelope;
use setjoin_contracts::ids::{Digest, OperationId};
use setjoin_pg::{
    run_receipted_command, run_receipted_effect, CommandOutcome, Param, ReceiptCommand, Rejection,
    Row, ScopedTx, StatementFailure, Type,
};
use sha2::{Digest as _, Sha256};

use super::{Cx, Scope, WORKER_METHODS};
use crate::jmap::family::{reducer_error, MethodError};

const WRITE_TAIL: &str = " WHERE $2::bigint>0 AND $3::text<>''";

fn reducer_call() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"^SELECT [a-z_][a-z0-9_]*\(\$1(,\$[0-9]+(::[a-z0-9_]+(\[\])?)*)*\)(::text)?( WHERE \$2::bigint>0 AND \$3::text<>'')?$",
        )
        .expect("reducer call pattern")
    })
}

/// The whole statement is one reducer call whose arguments are only
/// placeholders, `$1` (the scope mailbox) first: Go `CallScoped`. Every other
/// scoped statement is a reviewed [`ScopedQuery`] variant, never free SQL.
pub(crate) fn owner_bound(sql: &str) -> bool {
    reducer_call().is_match(sql)
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

/// Go `CallScoped` of a read reducer: READ ONLY, `$1` = scope mailbox, params from `$2`.
pub(crate) async fn read(
    cx: &Cx<'_>,
    scope: &Scope,
    sql: &'static str,
    params: &[Param<'_>],
) -> Result<String, MethodError> {
    if !owner_bound(sql) {
        return Err(refuse(cx, "read"));
    }
    let mut bindings: Vec<Param<'_>> = vec![(&scope.mailbox, Type::INT8)];
    bindings.extend(params.iter().map(|(value, ty)| (*value, ty.clone())));
    let rows = cx
        .exec
        .read_scoped(&scope.auth, sql, &bindings)
        .await
        .map_err(|failure| reducer_error::project(&failure))?;
    first_text(&rows).map_err(|failure| reducer_error::project(&failure))
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
    if !owner_bound(sql) || !sql.ends_with(WRITE_TAIL) {
        return Err(refuse(cx, "write"));
    }
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
    settle(outcome, reducer_error::project)
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
/// destroy ids folded into `notDestroyed`.
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
        .all(|statement| owner_bound(statement))
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
                        &[(&mailbox, Type::INT8), (create, Type::TEXT)],
                    )
                    .await?,
                );
            }
            if let Some(update) = &update {
                parts.push(
                    phase(
                        tx,
                        sql.update,
                        &[(&mailbox, Type::INT8), (update, Type::TEXT)],
                    )
                    .await?,
                );
            }
            if let Some(ids) = &ids {
                parts.push(
                    phase(
                        tx,
                        sql.destroy,
                        &[(&mailbox, Type::INT8), (ids, Type::INT8_ARRAY)],
                    )
                    .await?,
                );
            }
            Ok(parts)
        },
    )
    .await;
    let parts = settle(outcome, reducer_error::project)?;
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

/// Reviewed non-reducer scoped statements: Go `h.pool` queries ported scoped
/// (template requirement 3). Each variant names its method and its exact SQL
/// with `$1` = scope mailbox, and carries only non-identity params. Adding a
/// variant is a seam edit and needs a Fable review; family code passes a
/// variant, never SQL. The table is empty until a family needs one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScopedQuery {}

impl ScopedQuery {
    /// `(method, sql)` of the variant.
    fn spec(self) -> (&'static str, &'static str) {
        match self {}
    }
}

/// Run one reviewed scoped statement (READ ONLY, `$1` = scope mailbox).
pub(crate) async fn query(
    cx: &Cx<'_>,
    scope: &Scope,
    statement: ScopedQuery,
) -> Result<String, MethodError> {
    let (method, _sql) = statement.spec();
    if method != cx.method.name {
        return Err(refuse(cx, "scoped query"));
    }
    let _ = scope;
    match statement {}
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
    /// TaskList/set create, task_lists.go:90.
    TaskListCreate { name: &'a str, color: &'a str },
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
    let project: fn(&StatementFailure) -> MethodError =
        if statement == WorkerRead::CalendarDelegates {
            reducer_error::project_calendar
        } else {
            reducer_error::project
        };
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
    settle(outcome, reducer_error::project)
}

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

    #[test]
    fn owner_bound_accepts_only_anchored_reducer_calls() {
        for sql in [
            "SELECT reminders_get($1,$2)::text",
            write_sql!("SELECT reminder_snooze($1,$4,$5::text::timestamptz)::text"),
            write_sql!("SELECT reminder_dismiss_all($1)::text"),
        ] {
            assert!(owner_bound(sql), "{sql}");
        }
        let set = set_sql!("jmap_task");
        assert!(owner_bound(set.create) && owner_bound(set.update) && owner_bound(set.destroy));
    }

    #[test]
    fn owner_bound_rejects_everything_else() {
        for sql in [
            "SELECT f($1) UNION SELECT g($2)",
            "SELECT f($2,$1)",
            "SELECT f($10)",
            "SELECT f($1,(SELECT 1))",
            "SELECT f($1); SELECT 1",
            "SELECT x FROM t WHERE mailbox_id=$1 OR TRUE",
            "SELECT x FROM t WHERE mailbox_id=$1; SELECT 1",
            "SELECT x FROM t WHERE mailbox_id=$2",
            "SELECT x FROM t WHERE owner=$1",
            "SELECT x FROM t WHERE mailbox_id = $1",
            "SELECT json_agg(c)::text FROM contacts c WHERE EXISTS (SELECT 1 FROM contacts x WHERE mailbox_id=$1)",
            "SELECT x FROM t WHERE mailbox_id=$1+1",
            "SELECT f($1) -- WHERE mailbox_id = $1",
            "SELECT f($1)/* WHERE mailbox_id = $1 */",
            "SELECT f($1,$2)::text WHERE true",
            "select f($1)",
            "SELECT public.f($1)",
            "SELECT f($1, $2)",
        ] {
            assert!(!owner_bound(sql), "{sql}");
        }
        assert!(write_sql!("SELECT f($1)::text").ends_with(WRITE_TAIL));
    }

    #[test]
    fn worker_table_is_closed_and_user_keyed() {
        let reads = [
            WorkerRead::TaskListGet,
            WorkerRead::TaskListTasks { list: 1 },
            WorkerRead::TaskListRoster { list: 1 },
            WorkerRead::TasksAssignedToMe,
            WorkerRead::CalendarDelegates,
        ];
        let writes = [
            WorkerWrite::TaskListCreate {
                name: "",
                color: "",
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
        for statement in reads {
            let (method, sql) = statement.spec();
            assert!(user_keyed(sql), "{sql}");
            assert_eq!(highest(sql), statement.arity(), "{sql}");
            methods.insert(method);
        }
        for statement in writes {
            let (method, sql) = statement.spec();
            assert!(user_keyed(sql), "{sql}");
            assert_eq!(highest(sql), statement.arity(), "{sql}");
            methods.insert(method);
        }
        let expected: BTreeSet<&str> = WORKER_METHODS.iter().copied().collect();
        assert_eq!(methods, expected);
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

    fn refusals() -> usize {
        REFUSALS.with(|count| count.get())
    }

    /// Each bad statement is stopped by the seam (refusal counted), while a
    /// well-formed one passes it and only then fails on the closed port.
    #[tokio::test]
    async fn the_seam_refuses_before_touching_the_database() {
        let exec = ScopedExecutor::from_dsn("host=127.0.0.1 port=1 user=x dbname=x", 1)
            .expect("lazy pool");
        let auth = MailboxAuthContext::from_authenticated_session(
            ActorId::new(1).expect("actor"),
            MailboxId::new(2).expect("mailbox"),
            Generation(1),
        );
        let cx = Cx::new(&exec, None, &auth, 1, 2, &PROBE, "{}");
        let scope = Scope {
            mailbox: 2,
            auth: MailboxAuthContext::from_authenticated_session(
                ActorId::new(1).expect("actor"),
                MailboxId::new(2).expect("mailbox"),
                Generation(1),
            ),
            delegated: false,
        };
        let start = refusals();
        assert!(read(&cx, &scope, "SELECT f($2,$1)::text", &[])
            .await
            .is_err());
        assert_eq!(refusals(), start + 1, "rogue read refused by the seam");
        assert!(read(&cx, &scope, "SELECT f($1)::text", &[]).await.is_err());
        assert_eq!(refusals(), start + 1, "well-formed read passed the seam");
        assert!(write(&cx, &scope, "probe", "SELECT f($1)::text", &[])
            .await
            .is_err());
        assert_eq!(
            refusals(),
            start + 2,
            "write without the receipt tail refused"
        );
        assert!(
            write(&cx, &scope, "probe", write_sql!("SELECT f($1)::text"), &[])
                .await
                .is_err()
        );
        assert_eq!(refusals(), start + 2, "well-formed write passed the seam");
        let rogue = SetSql::new(
            "SELECT f($2,$1)::text",
            "SELECT g($1,$2::text::jsonb)::text",
            "SELECT h($1,$2::bigint[])::text",
        );
        assert!(
            set_batch(&cx, &scope, rogue, "probe", Some("{}"), None, None)
                .await
                .is_err()
        );
        assert_eq!(refusals(), start + 3, "rogue set statement refused");
        assert!(worker_read(&cx, WorkerRead::TaskListGet).await.is_err());
        assert_eq!(
            refusals(),
            start + 4,
            "worker read under a foreign method refused"
        );
        assert!(worker_write(&cx, WorkerWrite::TaskListDelete { list: 1 })
            .await
            .is_err());
        assert_eq!(
            refusals(),
            start + 5,
            "worker write under a foreign method refused"
        );
        let worker_cx = Cx::new(&exec, None, &auth, 1, 2, &WORKER_PROBE, "{}");
        assert!(worker_read(&worker_cx, WorkerRead::TaskListGet)
            .await
            .is_err());
        assert_eq!(
            refusals(),
            start + 5,
            "its own worker statement passes the seam (fails only for missing services)"
        );
        assert!(worker_read(&worker_cx, WorkerRead::TasksAssignedToMe)
            .await
            .is_err());
        assert_eq!(
            refusals(),
            start + 6,
            "another method's worker statement refused"
        );
    }
}
