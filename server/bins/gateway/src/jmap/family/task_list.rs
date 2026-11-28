//! #373 TaskList/*, TaskListMember/set and TaskAssigned/* (frozen Go task_lists.go; worker statement table).
use std::collections::BTreeMap;

use serde_json::value::RawValue;
use serde_json::Value;

use super::args::{decode, Kind};
use super::seam::{parse_id_list, worker_read, worker_write, WorkerRead, WorkerWrite};
use super::{always, go_map, parse_id, Answer, Cx, Gate, Method, MethodError, Reply};

pub(super) const METHODS: &[Method] = &[
    Method {
        name: "TaskList/get",
        capability: "urn:ietf:params:jmap:tasks",
        app: "tasks",
        gate: Gate::Personal,
        account: false,
        mutator: false,
        state: false,
        ready: always,
        run: task_list_get,
    },
    Method {
        name: "TaskList/set",
        capability: "urn:ietf:params:jmap:tasks",
        app: "tasks",
        gate: Gate::Personal,
        account: false,
        mutator: true,
        state: false,
        ready: always,
        run: task_list_set,
    },
    Method {
        name: "TaskListMember/set",
        capability: "urn:ietf:params:jmap:tasks",
        app: "tasks",
        gate: Gate::Personal,
        account: false,
        mutator: true,
        state: false,
        ready: always,
        run: task_list_member_set,
    },
    Method {
        name: "TaskList/tasks",
        capability: "urn:ietf:params:jmap:tasks",
        app: "tasks",
        gate: Gate::Personal,
        account: false,
        mutator: false,
        state: false,
        ready: always,
        run: task_list_tasks,
    },
    Method {
        name: "TaskList/taskSet",
        capability: "urn:ietf:params:jmap:tasks",
        app: "tasks",
        gate: Gate::Personal,
        account: false,
        mutator: true,
        state: false,
        ready: always,
        run: task_list_task_set,
    },
    Method {
        name: "TaskAssigned/get",
        capability: "urn:ietf:params:jmap:tasks",
        app: "tasks",
        gate: Gate::Personal,
        account: false,
        mutator: false,
        state: false,
        ready: always,
        run: task_assigned_get,
    },
    Method {
        name: "TaskAssigned/setStatus",
        capability: "urn:ietf:params:jmap:tasks",
        app: "tasks",
        gate: Gate::Personal,
        account: false,
        mutator: true,
        state: false,
        ready: always,
        run: task_assigned_set_status,
    },
];

async fn require_shared_task_lists(cx: &Cx<'_>) -> Result<(), MethodError> {
    if cx.toggle("feature.shared_task_lists").await == Some(true) {
        Ok(())
    } else {
        Err(MethodError::new(
            "serverUnavailable",
            "shared task lists are not enabled",
        ))
    }
}

fn is_object(raw: &str) -> bool {
    raw.trim_start_matches([' ', '\t', '\n', '\r'])
        .starts_with('{')
}

fn raw_value(json: String) -> Result<Box<RawValue>, MethodError> {
    RawValue::from_string(json).map_err(|_| MethodError::server_fail())
}

fn json_string(value: &str) -> Result<Box<RawValue>, MethodError> {
    raw_value(crate::problem::go_string(value))
}

fn encode_raw_map(map: &BTreeMap<&str, Box<RawValue>>) -> Result<String, MethodError> {
    serde_json::to_string(map).map_err(|_| MethodError::server_fail())
}

fn wrap_object(field: &str, raw: &str) -> Result<String, MethodError> {
    let mut map = BTreeMap::new();
    map.insert(field, raw_value(raw.to_owned())?);
    encode_raw_map(&map)
}

/// Go `setKeyError` (`task_lists.go:40`): preserve unknown-commit errors
/// fail-closed, otherwise emit `{"description": ..., "type": ...}`.
fn set_key_error(err: MethodError) -> Result<Box<RawValue>, MethodError> {
    if err.kind == "serverFail" && err.detail.starts_with("commit outcome unknown") {
        return Err(err);
    }
    let (kind, desc) = if err.kind == "serverFail" {
        ("invalidArguments", "request failed")
    } else {
        (err.kind.as_str(), err.detail.as_str())
    };
    raw_value(go_map(vec![
        ("description", Value::from(desc)),
        ("type", Value::from(kind)),
    ]))
}

/// Go `addSetErrors(result, "notDestroyed", bad)` (`parse.go:93`).
fn add_not_destroyed(raw: &str, bad: &[String]) -> Result<String, MethodError> {
    if bad.is_empty() {
        return Ok(raw.to_owned());
    }
    let mut object: BTreeMap<String, Box<RawValue>> =
        serde_json::from_str(raw).map_err(|_| MethodError::server_fail())?;
    let mut bucket: BTreeMap<String, Box<RawValue>> = match object.get("notDestroyed") {
        Some(existing) => serde_json::from_str(existing.get()).unwrap_or_default(),
        None => BTreeMap::new(),
    };
    for id in bad {
        bucket.insert(id.clone(), raw_value(r#"{"type":"notFound"}"#.to_owned())?);
    }
    let bucket_json = serde_json::to_string(&bucket).map_err(|_| MethodError::server_fail())?;
    object.insert("notDestroyed".to_owned(), raw_value(bucket_json)?);
    serde_json::to_string(&object).map_err(|_| MethodError::server_fail())
}

fn task_list_get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        require_shared_task_lists(cx).await?;
        let raw = worker_read(cx, WorkerRead::TaskListGet).await?;
        Ok(Answer {
            name: "TaskList/get",
            args: wrap_object("lists", &raw)?,
        })
    })
}

fn task_list_set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        require_shared_task_lists(cx).await?;
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

        let mut created: BTreeMap<String, Box<RawValue>> = BTreeMap::new();
        let mut not_created: BTreeMap<String, Box<RawValue>> = BTreeMap::new();
        if let Some(raw_create) = args.raw("create").filter(|r| *r != "null" && is_object(r)) {
            let entries: BTreeMap<String, Box<RawValue>> = serde_json::from_str(raw_create)
                .map_err(|e| MethodError::new("invalidArguments", &e.to_string()))?;
            let mut items = Vec::with_capacity(entries.len());
            for (key, item_raw) in entries {
                let item = decode(
                    item_raw.get(),
                    "",
                    &[("name", Kind::Str), ("color", Kind::Str)],
                )?;
                items.push((key, item));
            }
            for (key, item) in items {
                let name = item.str("name");
                let color = item.opt_str("color");
                match worker_write(cx, WorkerWrite::TaskListCreate { name, color }).await {
                    Ok(res) => {
                        created.insert(key, raw_value(res)?);
                    }
                    Err(err) => {
                        not_created.insert(key, set_key_error(err)?);
                    }
                }
            }
        }

        let mut updated: Vec<String> = Vec::new();
        let mut not_updated: BTreeMap<String, Box<RawValue>> = BTreeMap::new();
        if let Some(raw_update) = args.raw("update").filter(|r| *r != "null" && is_object(r)) {
            let entries: BTreeMap<String, Box<RawValue>> = serde_json::from_str(raw_update)
                .map_err(|e| MethodError::new("invalidArguments", &e.to_string()))?;
            for (id_str, patch) in entries {
                let Some(list_id) = parse_id(&id_str) else {
                    not_updated.insert(
                        id_str,
                        raw_value(MethodError::new("invalidArguments", "invalid list id").json())?,
                    );
                    continue;
                };
                match worker_write(
                    cx,
                    WorkerWrite::TaskListUpdate {
                        list: list_id,
                        patch: patch.get(),
                    },
                )
                .await
                {
                    Ok(_) => updated.push(id_str),
                    Err(err) => {
                        not_updated.insert(id_str, set_key_error(err)?);
                    }
                }
            }
        }

        let mut destroyed: Vec<String> = Vec::new();
        let mut not_destroyed: BTreeMap<String, Box<RawValue>> = BTreeMap::new();
        if let Some(items) = args.strings("destroy") {
            if !items.is_empty() {
                let (valid, bad) = parse_id_list(items);
                for bad_id in bad {
                    not_destroyed.insert(
                        bad_id,
                        raw_value(MethodError::new("invalidArguments", "invalid list id").json())?,
                    );
                }
                for list_id in valid.unwrap_or_default() {
                    let id_str = list_id.to_string();
                    match worker_write(cx, WorkerWrite::TaskListDelete { list: list_id }).await {
                        Ok(_) => destroyed.push(id_str),
                        Err(err) => {
                            not_destroyed.insert(id_str, set_key_error(err)?);
                        }
                    }
                }
            }
        }

        let mut result: BTreeMap<&str, Box<RawValue>> = BTreeMap::new();
        result.insert(
            "created",
            raw_value(serde_json::to_string(&created).map_err(|_| MethodError::server_fail())?)?,
        );
        result.insert(
            "notCreated",
            raw_value(
                serde_json::to_string(&not_created).map_err(|_| MethodError::server_fail())?,
            )?,
        );
        result.insert(
            "updated",
            if updated.is_empty() {
                raw_value("null".to_owned())?
            } else {
                raw_value(serde_json::to_string(&updated).map_err(|_| MethodError::server_fail())?)?
            },
        );
        result.insert(
            "notUpdated",
            raw_value(
                serde_json::to_string(&not_updated).map_err(|_| MethodError::server_fail())?,
            )?,
        );
        result.insert(
            "destroyed",
            if destroyed.is_empty() {
                raw_value("null".to_owned())?
            } else {
                raw_value(
                    serde_json::to_string(&destroyed).map_err(|_| MethodError::server_fail())?,
                )?
            },
        );
        result.insert(
            "notDestroyed",
            raw_value(
                serde_json::to_string(&not_destroyed).map_err(|_| MethodError::server_fail())?,
            )?,
        );
        Ok(Answer {
            name: "TaskList/set",
            args: encode_raw_map(&result)?,
        })
    })
}

fn task_list_member_set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        require_shared_task_lists(cx).await?;
        let args = decode(
            cx.args(),
            "",
            &[
                ("listId", Kind::Str),
                ("add", Kind::Strings),
                ("remove", Kind::Strings),
            ],
        )?;
        let list_id_str = args.str("listId");
        let list_id = parse_id(list_id_str)
            .ok_or_else(|| MethodError::new("invalidArguments", "invalid listId"))?;

        let mut roster: Option<String> = None;
        let mut not_added: BTreeMap<String, Box<RawValue>> = BTreeMap::new();
        if let Some(add) = args.strings("add") {
            for email in add {
                match worker_write(
                    cx,
                    WorkerWrite::TaskListAddMember {
                        list: list_id,
                        email,
                    },
                )
                .await
                {
                    Ok(raw) => roster = Some(raw),
                    Err(err) => {
                        not_added.insert(email.clone(), set_key_error(err)?);
                    }
                }
            }
        }

        let mut not_removed: BTreeMap<String, Box<RawValue>> = BTreeMap::new();
        if let Some(remove) = args.strings("remove") {
            for uid_str in remove {
                let Some(member_id) = parse_id(uid_str) else {
                    not_removed.insert(
                        uid_str.clone(),
                        raw_value(MethodError::new("invalidArguments", "invalid userId").json())?,
                    );
                    continue;
                };
                match worker_write(
                    cx,
                    WorkerWrite::TaskListRemoveMember {
                        list: list_id,
                        member: member_id,
                    },
                )
                .await
                {
                    Ok(raw) => roster = Some(raw),
                    Err(err) => {
                        not_removed.insert(uid_str.clone(), set_key_error(err)?);
                    }
                }
            }
        }

        let roster = match roster {
            Some(raw) => raw,
            None => worker_read(cx, WorkerRead::TaskListRoster { list: list_id }).await?,
        };

        let mut result: BTreeMap<&str, Box<RawValue>> = BTreeMap::new();
        result.insert("listId", json_string(list_id_str)?);
        result.insert("members", raw_value(roster)?);
        result.insert(
            "notAdded",
            raw_value(serde_json::to_string(&not_added).map_err(|_| MethodError::server_fail())?)?,
        );
        result.insert(
            "notRemoved",
            raw_value(
                serde_json::to_string(&not_removed).map_err(|_| MethodError::server_fail())?,
            )?,
        );
        Ok(Answer {
            name: "TaskListMember/set",
            args: encode_raw_map(&result)?,
        })
    })
}

fn task_list_tasks<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        require_shared_task_lists(cx).await?;
        let args = decode(cx.args(), "", &[("listId", Kind::Str)])?;
        let list_id = parse_id(args.str("listId"))
            .ok_or_else(|| MethodError::new("invalidArguments", "invalid listId"))?;
        let raw = worker_read(cx, WorkerRead::TaskListTasks { list: list_id }).await?;
        Ok(Answer {
            name: "TaskList/tasks",
            args: raw,
        })
    })
}

fn task_list_task_set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        require_shared_task_lists(cx).await?;
        let args = decode(
            cx.args(),
            "",
            &[
                ("listId", Kind::Str),
                ("create", Kind::Raw),
                ("update", Kind::Raw),
                ("destroy", Kind::Strings),
            ],
        )?;
        let list_id = parse_id(args.str("listId"))
            .ok_or_else(|| MethodError::new("invalidArguments", "invalid listId"))?;

        let creates = args.raw("create").filter(|r| *r != "null");
        let updates = args.raw("update").filter(|r| *r != "null");
        let mut bad_destroy: Vec<String> = Vec::new();
        let destroys: Option<String> = match args.strings("destroy") {
            Some(items) if !items.is_empty() => {
                let (valid, bad) = parse_id_list(items);
                bad_destroy = bad;
                let valid = valid.unwrap_or_default();
                if valid.is_empty() {
                    None
                } else {
                    Some(serde_json::to_string(&valid).map_err(|_| MethodError::server_fail())?)
                }
            }
            _ => None,
        };

        let raw = worker_write(
            cx,
            WorkerWrite::TaskListTaskSet {
                list: list_id,
                creates,
                updates,
                destroys: destroys.as_deref(),
            },
        )
        .await?;
        Ok(Answer {
            name: "TaskList/taskSet",
            args: add_not_destroyed(&raw, &bad_destroy)?,
        })
    })
}

fn task_assigned_get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        require_shared_task_lists(cx).await?;
        let raw = worker_read(cx, WorkerRead::TasksAssignedToMe).await?;
        Ok(Answer {
            name: "TaskAssigned/get",
            args: wrap_object("list", &raw)?,
        })
    })
}

fn task_assigned_set_status<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        require_shared_task_lists(cx).await?;
        let args = decode(
            cx.args(),
            "",
            &[("taskId", Kind::Str), ("status", Kind::Str)],
        )?;
        let task_id = parse_id(args.str("taskId"))
            .ok_or_else(|| MethodError::new("invalidArguments", "invalid taskId"))?;
        let status = args.str("status");
        let raw = worker_write(
            cx,
            WorkerWrite::TaskAssigneeSetStatus {
                task: task_id,
                status,
            },
        )
        .await?;
        Ok(Answer {
            name: "TaskAssigned/setStatus",
            args: raw,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn methods_declare_worker_task_posture() {
        assert_eq!(METHODS.len(), 7);
        for method in METHODS {
            assert_eq!(method.capability, "urn:ietf:params:jmap:tasks");
            assert_eq!(method.app, "tasks");
            assert_eq!(method.gate, Gate::Personal);
            assert!(!method.account);
            assert!(!method.state);
        }
    }

    #[test]
    fn set_key_error_projects_like_go_and_fails_closed_on_unknown_commit() {
        let bz = set_key_error(MethodError::new("notFound", "notFound")).unwrap();
        assert_eq!(bz.get(), r#"{"description":"notFound","type":"notFound"}"#);

        let db = set_key_error(MethodError::server_fail()).unwrap();
        assert_eq!(
            db.get(),
            r#"{"description":"request failed","type":"invalidArguments"}"#
        );

        let unknown = MethodError::new(
            "serverFail",
            "commit outcome unknown; look up operation 0102",
        );
        assert_eq!(set_key_error(unknown.clone()).unwrap_err(), unknown);
    }

    #[test]
    fn add_not_destroyed_preserves_valid_and_merges_bad_ids() {
        let unchanged = r#"{"listId":"1","notDestroyed":{}}"#;
        assert_eq!(add_not_destroyed(unchanged, &[]).unwrap(), unchanged);

        let merged = add_not_destroyed(
            r#"{"listId":"1","notDestroyed":{"9":{"type":"notFound"}}}"#,
            &["bad".to_owned()],
        )
        .unwrap();
        assert_eq!(
            merged,
            r#"{"listId":"1","notDestroyed":{"9":{"type":"notFound"},"bad":{"type":"notFound"}}}"#
        );
    }

    #[test]
    fn wrap_object_preserves_inner_json() {
        assert_eq!(
            wrap_object("lists", r#"[{"id":"1","name":"Team"}]"#).unwrap(),
            r#"{"lists":[{"id":"1","name":"Team"}]}"#
        );
    }
}
