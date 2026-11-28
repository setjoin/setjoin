//! F14 core statements. The caller identity is always the sealed principal.
use super::*;

fn decode(rows: &[Row]) -> Result<Value, StatementFailure> {
    let raw: String = rows
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(|| StatementFailure {
            sqlstate: None,
            hint: None,
            message: "no rows in result set".into(),
        })?;
    serde_json::from_str(&raw).map_err(|_| StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid Drive projection".into(),
    })
}

fn decode_void(rows: &[Row]) -> Result<Value, StatementFailure> {
    if rows.is_empty() {
        return Err(StatementFailure {
            sqlstate: None,
            hint: None,
            message: "no rows in result set".into(),
        });
    }
    Ok(Value::Null)
}

async fn write_json(
    factory: &TxFactory,
    user: &UserPrincipal,
    name: &'static str,
    contract: &'static SqlContract,
    values: &[&(dyn ToSql + Sync)],
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let env = user_envelope(user.user(), user.generation(), operation, name.as_bytes());
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            contract,
            values,
            Some(ReceiptCommand {
                family: "F14",
                command: name,
            }),
            |rows| decode(&rows),
        )
        .await
}

async fn write_void(
    factory: &TxFactory,
    user: &UserPrincipal,
    name: &'static str,
    contract: &'static SqlContract,
    values: &[&(dyn ToSql + Sync)],
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let env = user_envelope(user.user(), user.generation(), operation, name.as_bytes());
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            contract,
            values,
            Some(ReceiptCommand {
                family: "F14",
                command: name,
            }),
            |rows| decode_void(&rows),
        )
        .await
}

pub async fn list_spaces(
    factory: &TxFactory,
    user: &UserPrincipal,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_json(
        factory,
        user,
        "drive_list_spaces",
        &sql::LIST_SPACES,
        &[&actor],
        operation,
    )
    .await
}

pub async fn create_space(
    factory: &TxFactory,
    user: &UserPrincipal,
    body: &Value,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    let name = body["name"].as_str().unwrap_or("");
    let classification = body["classification"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("regular");
    let personal = body["isPersonal"].as_bool().unwrap_or(false);
    let retention = body["retentionDays"].as_i64();
    let worm = body["wormMode"].as_str();
    let policy = body.get("exportPolicy").unwrap_or(&json!({})).to_string();
    write_json(
        factory,
        user,
        "drive_space_create",
        &sql::CREATE_SPACE,
        &[
            &actor,
            &name,
            &classification,
            &personal,
            &retention,
            &worm,
            &policy,
        ],
        operation,
    )
    .await
}

pub async fn patch_classification(
    factory: &TxFactory,
    user: &UserPrincipal,
    target: i64,
    value: &str,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_void(
        factory,
        user,
        "drive_space_set_classification",
        &sql::PATCH_CLASSIFICATION,
        &[&actor, &target, &value],
        operation,
    )
    .await
}

pub async fn patch_policy(
    factory: &TxFactory,
    user: &UserPrincipal,
    target: i64,
    body: &Value,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    let policy = body.get("exportPolicy").unwrap_or(&json!({})).to_string();
    let retention = body["retentionDays"].as_i64();
    let worm = body["wormMode"].as_str();
    let vault = body["vaultQuotaMb"].as_i64();
    write_void(
        factory,
        user,
        "drive_space_set_policy",
        &sql::PATCH_POLICY,
        &[&actor, &target, &policy, &retention, &worm, &vault],
        operation,
    )
    .await
}

pub async fn members(
    factory: &TxFactory,
    user: &UserPrincipal,
    space: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_json(
        factory,
        user,
        "drive_members",
        &sql::SPACE_MEMBERS,
        &[&actor, &space],
        operation,
    )
    .await
}

pub async fn grant_member(
    factory: &TxFactory,
    user: &UserPrincipal,
    space: i64,
    grantee: i64,
    role: &str,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_json(
        factory,
        user,
        "drive_member_grant",
        &sql::GRANT_MEMBER,
        &[&actor, &space, &grantee, &role],
        operation,
    )
    .await
}

pub async fn revoke_member(
    factory: &TxFactory,
    user: &UserPrincipal,
    space: i64,
    grantee: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_void(
        factory,
        user,
        "drive_member_revoke",
        &sql::REVOKE_MEMBER,
        &[&actor, &space, &grantee],
        operation,
    )
    .await
}

pub async fn tree(
    factory: &TxFactory,
    user: &UserPrincipal,
    space: i64,
    parent: Option<i64>,
    deleted: bool,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_json(
        factory,
        user,
        "drive_tree",
        &sql::SPACE_TREE,
        &[&actor, &space, &parent, &deleted],
        operation,
    )
    .await
}

pub async fn nodes_meta(
    factory: &TxFactory,
    user: &UserPrincipal,
    ids: &[i64],
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    let ids = ids.to_vec();
    write_json(
        factory,
        user,
        "drive_nodes_meta",
        &sql::NODES_META,
        &[&actor, &ids],
        operation,
    )
    .await
}

pub async fn changes(
    factory: &TxFactory,
    user: &UserPrincipal,
    space: i64,
    since: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_json(
        factory,
        user,
        "drive_changes",
        &sql::CHANGES,
        &[&actor, &space, &since],
        operation,
    )
    .await
}

pub async fn access_invalidations(
    factory: &TxFactory,
    user: &UserPrincipal,
    space: i64,
    cursor: Option<&str>,
    max: i32,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_json(
        factory,
        user,
        "drive_access_invalidations",
        &sql::ACCESS_INVALIDATIONS,
        &[&actor, &space, &cursor, &max],
        operation,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn visibility_snapshot(
    factory: &TxFactory,
    user: &UserPrincipal,
    space: i64,
    after: i64,
    epoch: Option<i64>,
    max: i32,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_json(
        factory,
        user,
        "drive_visibility_snapshot",
        &sql::VISIBILITY_SNAPSHOT,
        &[&actor, &space, &after, &epoch, &max],
        operation,
    )
    .await
}

pub async fn allow_name_mutation(
    factory: &TxFactory,
    user: &UserPrincipal,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_json(
        factory,
        user,
        "drive_name_mutation_rate",
        &sql::ALLOW_NAME_MUTATION,
        &[&actor],
        operation,
    )
    .await
}

pub async fn create_node(
    factory: &TxFactory,
    user: &UserPrincipal,
    body: &Value,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    let space = body["spaceId"].as_i64().unwrap_or(0);
    let parent = body["parentId"].as_i64();
    let kind = body["kind"].as_str().unwrap_or("");
    let name = body["name"].as_str().unwrap_or("");
    let content = body["contentType"].as_str();
    write_json(
        factory,
        user,
        "drive_node_create",
        &sql::CREATE_NODE,
        &[&actor, &space, &parent, &kind, &name, &content],
        operation,
    )
    .await
}

pub async fn patch_node(
    factory: &TxFactory,
    user: &UserPrincipal,
    node: i64,
    fields: &Value,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    let rename = fields.get("newName").is_some();
    let name = fields["newName"].as_str().unwrap_or("");
    let moving = fields.get("newParentId").is_some();
    let parent = fields["newParentId"].as_i64();
    write_void(
        factory,
        user,
        "drive_rust_node_patch",
        &sql::PATCH_NODE,
        &[&actor, &node, &rename, &name, &moving, &parent],
        operation,
    )
    .await
}

pub async fn trash_node(
    factory: &TxFactory,
    user: &UserPrincipal,
    node: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_void(
        factory,
        user,
        "drive_node_trash",
        &sql::TRASH_NODE,
        &[&actor, &node],
        operation,
    )
    .await
}

pub async fn restore_node(
    factory: &TxFactory,
    user: &UserPrincipal,
    node: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_void(
        factory,
        user,
        "drive_node_restore",
        &sql::RESTORE_NODE,
        &[&actor, &node],
        operation,
    )
    .await
}

pub async fn destroy_node(
    factory: &TxFactory,
    user: &UserPrincipal,
    node: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_void(
        factory,
        user,
        "drive_node_destroy",
        &sql::DESTROY_NODE,
        &[&actor, &node],
        operation,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn head_chunk(
    factory: &TxFactory,
    user: &UserPrincipal,
    space: i64,
    sha: &str,
    target: Option<i64>,
    epoch: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_json(
        factory,
        user,
        "drive_head_chunk",
        &sql::HEAD_CHUNK,
        &[&actor, &space, &sha, &target, &epoch],
        operation,
    )
    .await
}

pub async fn upload_authority(
    factory: &TxFactory,
    user: &UserPrincipal,
    space: i64,
    target: Option<i64>,
    epoch: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    if let (Some(target), Some(epoch)) = (target, epoch) {
        write_json(
            factory,
            user,
            "drive_upload_authority",
            &sql::UPLOAD_AUTHORITY_BOUND,
            &[&actor, &space, &target, &epoch],
            operation,
        )
        .await
    } else {
        write_json(
            factory,
            user,
            "drive_upload_authority",
            &sql::UPLOAD_AUTHORITY_UNBOUND,
            &[&actor, &space],
            operation,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn commit_chunk<F, Fut>(
    factory: &TxFactory,
    user: &UserPrincipal,
    space: i64,
    target: Option<i64>,
    epoch: Option<i64>,
    sha: &str,
    size: i32,
    operation: [u8; 16],
    promote: F,
) -> CommandOutcome<Value, StatementFailure>
where
    F: FnOnce(String) -> Fut + Send,
    Fut: std::future::Future<Output = Result<(), StatementFailure>> + Send,
{
    let actor = user.user().get();
    let env = user_envelope(user.user(), user.generation(), operation, sha.as_bytes());
    factory
        .run_user_effect_write(
            user,
            ReceiptCommand {
                family: "F14",
                command: "drive_chunk_register",
            },
            &env,
            deadline(),
            async move |tx| {
                let scope: String = if let (Some(target), Some(epoch)) = (target, epoch) {
                    let rows = tx
                        .query_contract(
                            &sql::CHUNK_BOUND_UPLOAD,
                            &[&actor, &space, &target, &epoch],
                        )
                        .await?;
                    rows.first()
                        .and_then(|r| r.try_get(0).ok())
                        .ok_or_else(|| StatementFailure {
                            sqlstate: None,
                            hint: None,
                            message: "no rows in result set".into(),
                        })?
                } else {
                    tx.query_contract(&sql::CHUNK_UPLOAD_REQUIRE, &[&actor, &space])
                        .await?
                        .first()
                        .and_then(|r| r.try_get(0).ok())
                        .ok_or_else(|| StatementFailure {
                            sqlstate: None,
                            hint: None,
                            message: "no rows in result set".into(),
                        })?
                };
                tx.query_contract(&sql::CHUNK_ADVISORY_LOCK, &[&scope, &sha])
                    .await?;
                promote(format!("drive/{scope}/{sha}")).await?;
                if let (Some(target), Some(epoch)) = (target, epoch) {
                    tx.query_contract(
                        &sql::CHUNK_REGISTER_BOUND,
                        &[&actor, &space, &target, &epoch, &sha, &size],
                    )
                    .await?;
                } else {
                    tx.query_contract(&sql::CHUNK_REGISTER, &[&actor, &space, &sha, &size])
                        .await?;
                }
                Ok(Value::Null)
            },
        )
        .await
}

pub async fn preview_query(
    factory: &TxFactory,
    user: &UserPrincipal,
    version: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    let env = user_envelope(
        user.user(),
        user.generation(),
        operation,
        b"drive_preview_query",
    );
    factory
        .run_user_effect_write(
            user,
            ReceiptCommand {
                family: "F14",
                command: "drive_preview_query",
            },
            &env,
            deadline(),
            async |tx| {
                let rows = tx
                    .query_contract(&sql::PREVIEW_QUERY, &[&actor, &version])
                    .await?;
                decode(&rows)
            },
        )
        .await
}

pub async fn preview_request(
    factory: &TxFactory,
    user: &UserPrincipal,
    version: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_json(
        factory,
        user,
        "drive_preview_request",
        &sql::PREVIEW_REQUEST,
        &[&actor, &version],
        operation,
    )
    .await
}

pub async fn preview_audit(
    factory: &TxFactory,
    user: &UserPrincipal,
    space: i64,
    version: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_void(
        factory,
        user,
        "drive_rust_preview_audit",
        &sql::PREVIEW_AUDIT,
        &[&actor, &space, &version],
        operation,
    )
    .await
}

pub async fn patch_quota(
    factory: &TxFactory,
    user: &UserPrincipal,
    target: i64,
    quota: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_void(
        factory,
        user,
        "drive_space_set_quota",
        &sql::PATCH_QUOTA,
        &[&actor, &target, &quota],
        operation,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn folder_grant(
    factory: &TxFactory,
    user: &UserPrincipal,
    space: i64,
    folder: i64,
    grantee: i64,
    role: &str,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_json(
        factory,
        user,
        "drive_folder_member_grant",
        &sql::FOLDER_GRANT,
        &[&actor, &space, &folder, &grantee, &role],
        operation,
    )
    .await
}

pub async fn folder_revoke(
    factory: &TxFactory,
    user: &UserPrincipal,
    space: i64,
    folder: i64,
    grantee: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_void(
        factory,
        user,
        "drive_folder_member_revoke",
        &sql::FOLDER_REVOKE,
        &[&actor, &space, &folder, &grantee],
        operation,
    )
    .await
}

pub async fn admin_read_permission(
    factory: &TxFactory,
    user: &UserPrincipal,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let actor = user.user().get();
    write_json(
        factory,
        user,
        "drive_admin_read_permission",
        &sql::ADMIN_READ_PERMISSION,
        &[&actor],
        operation,
    )
    .await
}

/// Cross-tenant admin spaces metadata read, gated on live `drive.view` proof.
pub async fn admin_spaces(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
) -> Result<Value, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::ADMIN_SPACES, &[])
        .await?;
    let mut out: Vec<Value> = rows
        .iter()
        .map(|r| {
            let raw = r.try_get::<_, String>(0).map_err(|_| StatementFailure {
                sqlstate: None,
                hint: None,
                message: "invalid admin spaces JSON".into(),
            })?;
            serde_json::from_str(&raw).map_err(|_| StatementFailure {
                sqlstate: None,
                hint: None,
                message: "invalid admin spaces JSON".into(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let actor = proof.actor().get();
    if let Ok(rows) = factory
        .run_admin_read_contract(proof, &sql::ADMIN_WORM_PENDING, &[&actor])
        .await
    {
        if let Some(row) = rows.first() {
            if let Ok(raw) = row.try_get::<_, String>(0) {
                if let Ok(Value::Array(pending)) = serde_json::from_str::<Value>(&raw) {
                    for space in &mut out {
                        if let Some(count) = pending
                            .iter()
                            .find(|p| p["spaceId"] == space["id"])
                            .and_then(|p| p["pending"].as_i64())
                            .filter(|n| *n != 0)
                        {
                            space["wormPending"] = count.into();
                        }
                    }
                }
            }
        }
    }
    Ok(Value::Array(out))
}

/// Go reads the manifest in a fresh transaction after metadata admission.
pub async fn preview_manifest(
    factory: &TxFactory,
    user: &UserPrincipal,
    version: i64,
) -> Result<Value, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::PREVIEW_MANIFEST, &[&version, &actor])
        .await?;
    decode(&rows)
}
