//! #373 Task/* and TaskComment/* (frozen Go tasks.go).
use super::args::{decode, Kind};
use super::seam::{
    not_found, parse_id_list, read, read_sql, resolve, set_batch, set_sql, since_state, write,
    write_sql, Sql, Type,
};
use super::{always, parse_id, Answer, Cx, Gate, Method, MethodError, Reply};

const GET_SQL: Sql = read_sql!("SELECT jmap_task_get($1,$3::bigint[])::text");
const QUERY_SQL: Sql =
    read_sql!("SELECT jmap_task_query($1,$3::text::jsonb,$4::text::jsonb,$5,$6)::text");
const CHANGES_SQL: Sql = read_sql!("SELECT jmap_task_changes($1,$3)::text");
const COMMENT_GET_SQL: Sql = read_sql!("SELECT task_activity_list($1,$3)::text");
const COMMENT_SET_SQL: Sql =
    write_sql!("SELECT task_comment_create($1,$4,$5,$6::text::jsonb)::text");

pub(super) const METHODS: &[Method] = &[
    Method {
        name: "Task/get",
        capability: "urn:ietf:params:jmap:tasks",
        app: "tasks",
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: task_get,
    },
    Method {
        name: "Task/query",
        capability: "urn:ietf:params:jmap:tasks",
        app: "tasks",
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: task_query,
    },
    Method {
        name: "Task/changes",
        capability: "urn:ietf:params:jmap:tasks",
        app: "tasks",
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: true,
        ready: always,
        run: task_changes,
    },
    Method {
        name: "Task/set",
        capability: "urn:ietf:params:jmap:tasks",
        app: "tasks",
        gate: Gate::Personal,
        account: true,
        mutator: true,
        state: false,
        ready: always,
        run: task_set,
    },
    Method {
        name: "TaskComment/get",
        capability: "urn:ietf:params:jmap:tasks",
        app: "tasks",
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: task_comment_get,
    },
    Method {
        name: "TaskComment/set",
        capability: "urn:ietf:params:jmap:tasks",
        app: "tasks",
        gate: Gate::Personal,
        account: true,
        mutator: true,
        state: false,
        ready: always,
        run: task_comment_set,
    },
];

fn task_get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("ids", Kind::Strings),
                ("properties", Kind::Strings),
            ],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let (ids, bad) = match args.strings("ids") {
            Some(raw) => parse_id_list(raw),
            None => (None, Vec::new()),
        };
        let raw = read(cx, &scope, GET_SQL, &[(&ids, Type::INT8_ARRAY)]).await?;
        Ok(Answer {
            name: "Task/get",
            args: not_found(&raw, &bad),
        })
    })
}

fn task_query<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("filter", Kind::Raw),
                ("sort", Kind::Raw),
                ("position", Kind::Int),
                ("limit", Kind::Int),
            ],
        )?;
        let mut limit = args.int("limit");
        if limit <= 0 || limit > 256 {
            limit = 50;
        }
        let scope = resolve(cx, args.str("accountId")).await?;
        let position =
            i32::try_from(args.int("position")).map_err(|_| MethodError::server_fail())?;
        let limit = limit as i32;
        let filter = args.raw("filter");
        let sort = args.raw("sort");
        let raw = read(
            cx,
            &scope,
            QUERY_SQL,
            &[
                (&filter, Type::TEXT),
                (&sort, Type::TEXT),
                (&position, Type::INT4),
                (&limit, Type::INT4),
            ],
        )
        .await?;
        Ok(Answer {
            name: "Task/query",
            args: raw,
        })
    })
}

fn task_changes<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[("accountId", Kind::Str), ("sinceState", Kind::Str)],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let state = args.str("sinceState");
        since_state(state)?;
        let raw = read(cx, &scope, CHANGES_SQL, &[(&state, Type::TEXT)]).await?;
        Ok(Answer {
            name: "Task/changes",
            args: raw,
        })
    })
}

fn task_set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "SetRequest",
            &[
                ("accountId", Kind::Str),
                ("create", Kind::Raw),
                ("update", Kind::Raw),
                ("destroy", Kind::Strings),
            ],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let raw = set_batch(
            cx,
            &scope,
            set_sql!("jmap_task"),
            "task.set",
            args.raw("create"),
            args.raw("update"),
            args.strings("destroy"),
        )
        .await?;
        Ok(Answer {
            name: "Task/set",
            args: raw,
        })
    })
}

fn task_comment_get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[("accountId", Kind::Str), ("taskId", Kind::Str)],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let task_id = parse_id(args.str("taskId"))
            .ok_or_else(|| MethodError::new("invalidArguments", "invalid taskId"))?;
        let raw = read(cx, &scope, COMMENT_GET_SQL, &[(&task_id, Type::INT8)]).await?;
        Ok(Answer {
            name: "TaskComment/get",
            args: raw,
        })
    })
}

fn task_comment_set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("taskId", Kind::Str),
                ("body", Kind::Str),
                ("mentionedEmails", Kind::Raw),
            ],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let task_id = parse_id(args.str("taskId"))
            .ok_or_else(|| MethodError::new("invalidArguments", "invalid taskId"))?;
        let body = args.str("body");
        let mentions = args.raw("mentionedEmails").unwrap_or("[]");
        let raw = write(
            cx,
            &scope,
            "task.comment.set",
            COMMENT_SET_SQL,
            &[
                (&task_id, Type::INT8),
                (&body, Type::TEXT),
                (&mentions, Type::TEXT),
            ],
        )
        .await?;
        Ok(Answer {
            name: "TaskComment/set",
            args: raw,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn methods_declare_tasks_capability_and_personal_gate() {
        assert_eq!(METHODS.len(), 6);
        for method in METHODS {
            assert_eq!(method.capability, "urn:ietf:params:jmap:tasks");
            assert_eq!(method.app, "tasks");
            assert_eq!(method.gate, Gate::Personal);
            assert!(method.account);
        }
        assert!(
            METHODS
                .iter()
                .find(|m| m.name == "Task/changes")
                .unwrap()
                .state
        );
        assert!(
            METHODS
                .iter()
                .find(|m| m.name == "Task/set")
                .unwrap()
                .mutator
        );
        assert!(
            METHODS
                .iter()
                .find(|m| m.name == "TaskComment/set")
                .unwrap()
                .mutator
        );
    }
}
