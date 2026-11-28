//! User-scoped Drive reducer calls. `UserPrincipal` is the only actor source.
use super::*;

fn invalid_result() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid Drive result".into(),
    }
}

fn first_json(rows: &[setjoin_pg::Row]) -> Result<Value, StatementFailure> {
    let raw = rows
        .first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .ok_or_else(invalid_result)?;
    serde_json::from_str(&raw).map_err(|_| invalid_result())
}

pub async fn activity(
    factory: &TxFactory,
    user: &UserPrincipal,
    space: i64,
    node: Option<i64>,
    max: Option<i64>,
    before: Option<i64>,
) -> Result<Value, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(
            user,
            &sql::ACTIVITY_FEED,
            &[&actor, &space, &node, &max, &before],
        )
        .await?;
    first_json(&rows)
}

pub async fn search(
    factory: &TxFactory,
    user: &UserPrincipal,
    space: Option<i64>,
    q: &str,
    max: Option<i64>,
) -> Result<Value, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::SEARCH_NODES, &[&actor, &space, &q, &max])
        .await?;
    first_json(&rows)
}

pub async fn create_branch(
    factory: &TxFactory,
    user: &UserPrincipal,
    node: i64,
    body: &Value,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    let payload = body.to_string();
    let env = user_envelope(
        user.user(),
        user.generation(),
        operation,
        payload.as_bytes(),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CREATE_BRANCH,
            &[&actor, &node, &payload],
            Some(ReceiptCommand {
                family: "F14",
                command: "drive_branch_create",
            }),
            |rows| first_json(&rows),
        )
        .await
}

pub async fn simple_read(
    factory: &TxFactory,
    user: &UserPrincipal,
    name: &str,
    target: i64,
    body: &Value,
) -> Result<Value, StatementFailure> {
    let actor = user.user().get();
    let payload = body.to_string();
    let rows = match name {
        "list_versions" => {
            let mut tx = factory.begin_user_read(user).await?;
            let rows = tx
                .query_contract(&sql::LIST_VERSIONS, &[&actor, &target])
                .await?;
            let _ = tx.finish().await;
            rows
        }
        "list_branches" => {
            factory
                .run_user_read_contract(user, &sql::LIST_BRANCHES, &[&actor, &target, &payload])
                .await?
        }
        "audit_actions" => {
            factory
                .run_user_read_contract(user, &sql::AUDIT_ACTIONS, &[])
                .await?
        }
        "list_alarms" => {
            factory
                .run_user_read_contract(user, &sql::LIST_ALARMS, &[&actor])
                .await?
        }
        "verify_audit" => {
            factory
                .run_user_read_contract(user, &sql::VERIFY_AUDIT, &[&actor, &target])
                .await?
        }
        "trash" => {
            factory
                .run_user_read_contract(user, &sql::TRASH_ADMIN_LIST, &[&actor, &target])
                .await?
        }
        "office_choices" => {
            factory
                .run_user_read_contract(user, &sql::OFFICE_CHOICES, &[&actor, &target, &payload])
                .await?
        }
        "history" => {
            factory
                .run_user_read_contract(user, &sql::FILE_HISTORY, &[&actor, &target, &payload])
                .await?
        }
        "audit" => {
            factory
                .run_user_read_contract(user, &sql::AUDIT_QUERY, &[&actor, &payload])
                .await?
        }
        _ => {
            return Err(StatementFailure {
                sqlstate: None,
                hint: None,
                message: "unregistered Drive read".into(),
            })
        }
    };
    let raw: Option<String> = rows
        .first()
        .and_then(|r| r.try_get::<_, Option<String>>(0).ok())
        .flatten();
    let raw = raw.ok_or_else(|| StatementFailure {
        sqlstate: Some(
            if matches!(name, "list_alarms" | "verify_audit") {
                "D403"
            } else {
                "D404"
            }
            .into(),
        ),
        hint: None,
        message: match name {
            "list_alarms" => "drive.manage required",
            "verify_audit" => "drive.view required",
            _ => "file not found",
        }
        .into(),
    })?;
    serde_json::from_str(&raw).map_err(|_| invalid_result())
}

async fn run_json_write(
    factory: &TxFactory,
    user: &UserPrincipal,
    command: &'static str,
    contract: &'static SqlContract,
    values: &[&(dyn ToSql + Sync)],
    digest_source: &[u8],
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let env = user_envelope(user.user(), user.generation(), operation, digest_source);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            contract,
            values,
            Some(ReceiptCommand {
                family: "F14",
                command,
            }),
            |rows| first_json(&rows),
        )
        .await
}

async fn run_void_write(
    factory: &TxFactory,
    user: &UserPrincipal,
    command: &'static str,
    contract: &'static SqlContract,
    values: &[&(dyn ToSql + Sync)],
    digest_source: &[u8],
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let env = user_envelope(user.user(), user.generation(), operation, digest_source);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            contract,
            values,
            Some(ReceiptCommand {
                family: "F14",
                command,
            }),
            |_| Ok(Value::Null),
        )
        .await
}

pub async fn simple_write(
    factory: &TxFactory,
    user: &UserPrincipal,
    name: &str,
    target: i64,
    body: &Value,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    let payload = body.to_string();
    let digest = payload.as_bytes();
    match name {
        "set_label" => {
            run_void_write(
                factory,
                user,
                "drive_version_label_set",
                &sql::SET_LABEL,
                &[&actor, &target, &payload],
                digest,
                operation,
            )
            .await
        }
        "remove_label" => {
            run_void_write(
                factory,
                user,
                "drive_version_label_remove",
                &sql::REMOVE_LABEL,
                &[&actor, &target, &payload],
                digest,
                operation,
            )
            .await
        }
        "resolve_branch" => {
            run_json_write(
                factory,
                user,
                "drive_branch_resolve",
                &sql::RESOLVE_BRANCH,
                &[&actor, &target, &payload],
                digest,
                operation,
            )
            .await
        }
        "create_alarm" => {
            run_json_write(
                factory,
                user,
                "drive_alarm_create",
                &sql::CREATE_ALARM,
                &[&actor, &payload],
                digest,
                operation,
            )
            .await
        }
        "delete_alarm" => {
            run_void_write(
                factory,
                user,
                "drive_alarm_delete",
                &sql::DELETE_ALARM,
                &[&actor, &target],
                digest,
                operation,
            )
            .await
        }
        "patch_branch" => {
            let cmd = if body.get("status").is_some() {
                "drive_branch_set_status"
            } else {
                "drive_branch_rename"
            };
            run_void_write(
                factory,
                user,
                cmd,
                &sql::PATCH_BRANCH,
                &[&actor, &target, &payload],
                digest,
                operation,
            )
            .await
        }
        "update_alarm" => {
            run_void_write(
                factory,
                user,
                "drive_alarm_update",
                &sql::UPDATE_ALARM,
                &[&actor, &target, &payload],
                digest,
                operation,
            )
            .await
        }
        "purge_restore" => {
            run_void_write(
                factory,
                user,
                "drive_node_purge_restore",
                &sql::PURGE_RESTORE,
                &[&actor, &target],
                digest,
                operation,
            )
            .await
        }
        "office_local_open" => {
            run_json_write(
                factory,
                user,
                "office_local_open_accept",
                &sql::OFFICE_LOCAL_OPEN,
                &[&actor, &target, &payload],
                digest,
                operation,
            )
            .await
        }
        "office_revoke" => {
            run_json_write(
                factory,
                user,
                "office_launch_revoke",
                &sql::OFFICE_REVOKE,
                &[&actor, &target, &payload],
                digest,
                operation,
            )
            .await
        }
        "put_version" => {
            run_json_write(
                factory,
                user,
                "drive_file_put_version",
                &sql::PUT_VERSION,
                &[&actor, &target, &payload],
                digest,
                operation,
            )
            .await
        }
        "restore_version" => {
            run_json_write(
                factory,
                user,
                "rust_drive_restore_version",
                &sql::RESTORE_VERSION,
                &[&actor, &target, &payload],
                digest,
                operation,
            )
            .await
        }
        "office_launch" => {
            run_json_write(
                factory,
                user,
                "office_launch_begin",
                &sql::OFFICE_LAUNCH,
                &[&actor, &target, &payload],
                digest,
                operation,
            )
            .await
        }
        "request_export" => {
            run_json_write(
                factory,
                user,
                "drive_export_request",
                &sql::REQUEST_EXPORT,
                &[&actor, &payload],
                digest,
                operation,
            )
            .await
        }
        "consume_export" => {
            run_json_write(
                factory,
                user,
                "drive_export_consume",
                &sql::CONSUME_EXPORT,
                &[&actor, &payload],
                digest,
                operation,
            )
            .await
        }
        _ => CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(StatementFailure {
            sqlstate: None,
            hint: None,
            message: "unregistered Drive write".into(),
        })),
    }
}

pub async fn content(
    factory: &TxFactory,
    user: &UserPrincipal,
    version: i64,
) -> Result<Option<Value>, StatementFailure> {
    let actor = user.user().get();
    factory
        .run_user_read_contract(user, &sql::CONTENT_DOWNLOAD_REQUIRE, &[&actor])
        .await?;
    content_metadata(factory, user, version).await
}

pub async fn content_metadata(
    factory: &TxFactory,
    user: &UserPrincipal,
    version: i64,
) -> Result<Option<Value>, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::CONTENT_METADATA, &[&actor, &version])
        .await?;
    rows.first()
        .and_then(|row| row.try_get::<_, Option<String>>(0).ok().flatten())
        .map(|raw| {
            serde_json::from_str(&raw).map_err(|_| StatementFailure {
                sqlstate: None,
                hint: None,
                message: "invalid Drive content metadata".into(),
            })
        })
        .transpose()
}

pub async fn export_name(factory: &TxFactory, user: &UserPrincipal, version: i64) -> String {
    let actor = user.user().get();
    factory
        .run_user_read_contract(user, &sql::EXPORT_NAME, &[&actor, &version])
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, String>(0).ok()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "download".into())
}

pub async fn audit_view(
    factory: &TxFactory,
    user: &UserPrincipal,
    space: i64,
    version: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    let digest = json!({ "version": version }).to_string();
    run_void_write(
        factory,
        user,
        "rust_drive_audit_view",
        &sql::AUDIT_VIEW,
        &[&actor, &space, &version],
        digest.as_bytes(),
        operation,
    )
    .await
}

/// Best-effort post-commit retention lookup, preserving Go's failure behavior.
pub async fn worm_config(factory: &TxFactory, user: &UserPrincipal, node: i64) -> Option<Value> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::WORM_CONFIG, &[&actor, &node])
        .await
        .ok()?;
    let raw = rows.first()?.try_get::<_, String>(0).ok()?;
    serde_json::from_str(&raw).ok()
}
