//! F14 core statements. The caller identity is always the sealed auth context.
use super::*;
fn decode(rows: &[setjoin_pg::Row]) -> Result<Value, StatementFailure> {
    let raw: String = rows
        .first()
        .ok_or_else(|| StatementFailure {
            sqlstate: None,
            hint: None,
            message: "no rows in result set".into(),
        })?
        .get(0);
    serde_json::from_str(&raw).map_err(|_| StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid Drive projection".into(),
    })
}
pub async fn write(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    name: &'static str,
    sql: &str,
    params: &[Param<'_>],
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let auth = session(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(name.as_bytes()).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F14",
            command: name,
        },
        &envelope,
        &auth,
        Instant::now() + Duration::from_secs(30),
        sql,
        params,
        decode,
    )
    .await
}
pub async fn read(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    sql: &str,
    params: &[Param<'_>],
) -> Result<Value, StatementFailure> {
    decode(&exec.read_scoped(&session(actor), sql, params).await?)
}
pub async fn list_spaces(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(
        exec,
        actor,
        "drive_list_spaces",
        "SELECT drive_rust_list_spaces($2)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL",
        &[],
        operation,
    )
    .await
}

pub async fn create_space(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    body: &Value,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let name = body["name"].as_str().unwrap_or("");
    let classification = body["classification"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("regular");
    let personal = body["isPersonal"].as_bool().unwrap_or(false);
    let retention = body["retentionDays"].as_i64();
    let worm = body["wormMode"].as_str();
    let policy = body.get("exportPolicy").unwrap_or(&json!({})).to_string();
    write(exec,actor,"drive_space_create","SELECT jsonb_build_object('id',drive_space_create($2,$4,$5,$6,$7::bigint::integer,$8,$9::text::jsonb))::text WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[(&name,Type::TEXT),(&classification,Type::TEXT),(&personal,Type::BOOL),(&retention,Type::INT8),(&worm,Type::TEXT),(&policy,Type::TEXT)],operation).await
}

pub async fn patch_classification(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    target: i64,
    value: &str,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(exec,actor,"drive_space_set_classification","SELECT 'null'::text FROM drive_space_set_classification($2,$4,$5) WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[(&target,Type::INT8),(&value,Type::TEXT)],operation).await
}

pub async fn patch_policy(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    target: i64,
    body: &Value,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let policy = body.get("exportPolicy").unwrap_or(&json!({})).to_string();
    let retention = body["retentionDays"].as_i64();
    let worm = body["wormMode"].as_str();
    let vault = body["vaultQuotaMb"].as_i64();
    write(exec,actor,"drive_space_set_policy","SELECT 'null'::text FROM drive_space_set_policy($2,$4,$5::text::jsonb,$6::bigint::integer,$7,$8::bigint::integer) WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[(&target,Type::INT8),(&policy,Type::TEXT),(&retention,Type::INT8),(&worm,Type::TEXT),(&vault,Type::INT8)],operation).await
}

pub async fn members(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    space: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(exec,actor,"drive_members","SELECT coalesce(jsonb_agg(jsonb_build_object('userId',m.user_id,'role',m.role,'email',u.email,'displayName',u.display_name,'grantedAt',to_char(m.granted_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')) ORDER BY m.role,u.display_name),'[]'::jsonb)::text FROM drive_space_members m JOIN users u ON u.id=m.user_id WHERE m.space_id=$4 AND drive_runtime_has_space_root_capability($2,$4,'manage_acl') AND $2::bigint>0 AND $3::text IS NOT NULL",&[(&space,Type::INT8)],operation).await
}

pub async fn grant_member(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    space: i64,
    user: i64,
    role: &str,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(
        exec,
        actor,
        "drive_member_grant",
        "SELECT drive_member_grant($2,$4,$5,$6)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL",
        &[
            (&space, Type::INT8),
            (&user, Type::INT8),
            (&role, Type::TEXT),
        ],
        operation,
    )
    .await
}

pub async fn revoke_member(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    space: i64,
    user: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(exec,actor,"drive_member_revoke","SELECT 'null'::text FROM drive_member_revoke($2,$4,$5) WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[(&space,Type::INT8),(&user,Type::INT8)],operation).await
}

pub async fn tree(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    space: i64,
    parent: Option<i64>,
    deleted: bool,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(
        exec,
        actor,
        "drive_tree",
        TREE,
        &[
            (&space, Type::INT8),
            (&parent, Type::INT8),
            (&deleted, Type::BOOL),
        ],
        operation,
    )
    .await
}
const TREE: &str = r#"SELECT CASE WHEN CASE WHEN $5::bigint IS NULL
 THEN drive_user_has_space_access($2,$4)
 ELSE drive_runtime_has_node_capability($2,$5,'list_children') OR drive_runtime_has_node_capability($2,$5,'traverse') END
 THEN coalesce((SELECT jsonb_agg(
 jsonb_build_object('id',n.id,'parentId',n.parent_id,'kind',n.kind,'name',n.name,'branchCount',coalesce(bc.branch_count,0),
 'lock',CASE WHEN l.holder_id IS NULL THEN NULL ELSE jsonb_build_object('holderId',l.holder_id,'holderName',coalesce(l.holder_name,''),'mode',coalesce(l.mode,''),'branchId',l.branch_id,'acquiredAt',to_char(l.acquired_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),'expiresAt',to_char(l.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) END,
 'capabilities',ARRAY(SELECT capability FROM drive_runtime_capability_sources($2,n.space_id,n.id) ORDER BY capability),
 'traverseOnly',drive_runtime_has_node_capability($2,n.id,'traverse') AND NOT drive_runtime_has_node_capability($2,n.id,'read_metadata'))
 || CASE WHEN f.size_bytes IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('size',f.size_bytes) END
 || CASE WHEN f.content_type IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('contentType',f.content_type) END
 || CASE WHEN f.head_version_id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('headVersionId',f.head_version_id) END
 || CASE WHEN n.deleted_at IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('deletedAt',to_char(n.deleted_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) END
 ORDER BY n.kind DESC,n.name)
 FROM drive_nodes n LEFT JOIN drive_files f ON f.node_id=n.id
 LEFT JOIN LATERAL(SELECT count(*) AS branch_count FROM drive_file_branches b WHERE b.file_node_id=n.id AND b.status IN('open','review'))bc ON true
 LEFT JOIN LATERAL(SELECT lk.user_id AS holder_id,m.display_name AS holder_name,lk.mode,lk.branch_id,lk.acquired_at,lk.expires_at FROM drive_file_locks lk LEFT JOIN mailboxes m ON m.user_id=lk.user_id AND m.is_primary WHERE lk.node_id=n.id AND lk.expires_at>now())l ON true
 WHERE n.space_id=$4 AND n.parent_id IS NOT DISTINCT FROM $5::bigint AND (n.deleted_at IS NOT NULL)=$6
 AND(drive_runtime_has_node_capability($2,n.id,'read_metadata') OR drive_runtime_has_node_capability($2,n.id,'traverse'))),'[]'::jsonb)
 ELSE 'null'::jsonb END::text WHERE $2::bigint>0 AND $3::text IS NOT NULL"#;

pub async fn nodes_meta(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ids: &[i64],
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let ids = ids.to_vec();
    write(
        exec,
        actor,
        "drive_nodes_meta",
        NODES_META,
        &[(&ids, Type::INT8_ARRAY)],
        operation,
    )
    .await
}
const NODES_META: &str = r#"SELECT coalesce(jsonb_agg(jsonb_build_object(
 'nodeId',n.id,'spaceId',n.space_id,'parentId',n.parent_id,'kind',n.kind,'name',n.name,
 'deletedAt',to_char(n.deleted_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
 'headVersionId',f.head_version_id,'contentSha256',v.content_sha256,'sizeBytes',f.size_bytes,'contentType',f.content_type,
 'branchCount',coalesce(bc.branch_count,0),
 'capabilities',ARRAY(SELECT capability FROM drive_runtime_capability_sources($2,n.space_id,n.id) ORDER BY capability),
 'traverseOnly',drive_runtime_has_node_capability($2,n.id,'traverse') AND NOT drive_runtime_has_node_capability($2,n.id,'read_metadata')) ORDER BY n.id),'[]'::jsonb)::text
 FROM drive_nodes n LEFT JOIN drive_files f ON f.node_id=n.id LEFT JOIN drive_file_versions v ON v.id=f.head_version_id
 LEFT JOIN LATERAL(SELECT count(*) AS branch_count FROM drive_file_branches b WHERE b.file_node_id=n.id AND b.status IN('open','review'))bc ON true
 WHERE n.id=ANY($4::bigint[]) AND drive_runtime_has_node_capability($2,n.id,'read_metadata')
 AND(NOT EXISTS(SELECT 1 FROM drive_nodes cn JOIN drive_spaces cs ON cs.id=cn.space_id WHERE cn.id=n.id AND cs.chat_channel_id IS NOT NULL)
 OR EXISTS(SELECT 1 FROM chat_message_attachments cma JOIN chat_messages msg ON msg.id=cma.message_id JOIN chat_channel_members hcm ON hcm.channel_id=msg.channel_id AND hcm.user_id=$2 WHERE cma.file_node_id=n.id AND msg.deleted_at IS NULL AND msg.seq>coalesce(hcm.history_floor_seq,0) AND(hcm.history_floor_seq IS NULL OR msg.created_at>=hcm.joined_at)))
 AND $2::bigint>0 AND $3::text IS NOT NULL"#;

pub async fn changes(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    space: i64,
    since: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(
        exec,
        actor,
        "drive_changes",
        "SELECT drive_changes_since($2,$4,$5)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL",
        &[(&space, Type::INT8), (&since, Type::INT8)],
        operation,
    )
    .await
}

pub async fn access_invalidations(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    space: i64,
    cursor: Option<&str>,
    max: i32,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(exec,actor,"drive_access_invalidations","SELECT drive_access_invalidation_page($2,$4,$5::text::uuid,$6)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[(&space,Type::INT8),(&cursor,Type::TEXT),(&max,Type::INT4)],operation).await
}

pub async fn visibility_snapshot(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    space: i64,
    after: i64,
    epoch: Option<i64>,
    max: i32,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(exec,actor,"drive_visibility_snapshot","SELECT drive_visibility_snapshot_page($2,$4,$5,$6,$7)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[(&space,Type::INT8),(&after,Type::INT8),(&epoch,Type::INT8),(&max,Type::INT4)],operation).await
}

pub async fn allow_name_mutation(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(exec,actor,"drive_name_mutation_rate","SELECT to_jsonb(rate_limit_check('drive:name-mutation:'||$2::text,120,1,5))::text WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[],operation).await
}
pub async fn create_node(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    body: &Value,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let space = body["spaceId"].as_i64().unwrap_or(0);
    let parent = body["parentId"].as_i64();
    let kind = body["kind"].as_str().unwrap_or("");
    let name = body["name"].as_str().unwrap_or("");
    let content = body["contentType"].as_str();
    write(exec,actor,"drive_node_create","SELECT jsonb_build_object('id',drive_node_create($2,$4,$5,$6,$7,$8))::text WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[(&space,Type::INT8),(&parent,Type::INT8),(&kind,Type::TEXT),(&name,Type::TEXT),(&content,Type::TEXT)],operation).await
}

pub async fn patch_node(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    node: i64,
    fields: &Value,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let rename = fields.get("newName").is_some();
    let name = fields["newName"].as_str().unwrap_or("");
    let moving = fields.get("newParentId").is_some();
    let parent = fields["newParentId"].as_i64();
    write(exec,actor,"drive_rust_node_patch","SELECT 'null'::text FROM drive_rust_node_patch($2,$4,$5,$6,$7,$8) WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[(&node,Type::INT8),(&rename,Type::BOOL),(&name,Type::TEXT),(&moving,Type::BOOL),(&parent,Type::INT8)],operation).await
}

pub async fn trash_node(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    node: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(exec,actor,"drive_node_trash","SELECT 'null'::text FROM drive_node_trash($2,$4) WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[(&node,Type::INT8)],operation).await
}

pub async fn restore_node(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    node: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(exec,actor,"drive_node_restore","SELECT 'null'::text FROM drive_node_restore($2,$4) WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[(&node,Type::INT8)],operation).await
}

pub async fn destroy_node(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    node: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(exec,actor,"drive_node_destroy","SELECT 'null'::text FROM drive_node_destroy($2,$4) WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[(&node,Type::INT8)],operation).await
}

pub async fn head_chunk(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    space: i64,
    sha: &str,
    target: Option<i64>,
    epoch: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(
        exec,
        actor,
        "drive_head_chunk",
        HEAD_CHUNK,
        &[
            (&space, Type::INT8),
            (&sha, Type::TEXT),
            (&target, Type::INT8),
            (&epoch, Type::INT8),
        ],
        operation,
    )
    .await
}
const HEAD_CHUNK: &str = r#"SELECT to_jsonb(EXISTS(
 SELECT 1 FROM drive_chunks c WHERE c.scope_key=(SELECT CASE WHEN s.classification='regular' THEN 'g' ELSE 's'||s.id END FROM drive_spaces s WHERE s.id=$4 AND drive_user_has_space_access($2,s.id)) AND c.sha256=$5
 AND(EXISTS(SELECT 1 FROM drive_upload_claims uc JOIN drive_spaces us ON us.id=$4 WHERE us.acl_mode<>'acl' AND uc.scope_key=c.scope_key AND uc.sha256=c.sha256 AND uc.user_id=$2)
 OR EXISTS(SELECT 1 FROM drive_upload_authorizations ua WHERE ua.scope_key=c.scope_key AND ua.sha256=c.sha256 AND ua.user_id=$2 AND ua.space_id=$4 AND ua.expires_at>now() AND($6::bigint IS NULL OR ua.target_node_id=$6) AND($7::bigint IS NULL OR ua.acl_epoch=$7))
 OR EXISTS(SELECT 1 FROM drive_version_chunks vc JOIN drive_file_versions v ON v.id=vc.version_id WHERE vc.scope_key=c.scope_key AND vc.chunk_sha256=c.sha256 AND drive_runtime_has_node_capability($2,v.file_node_id,'download')
 AND(NOT EXISTS(SELECT 1 FROM drive_file_versions cv JOIN drive_spaces cs ON cs.id=cv.space_id WHERE cv.id=v.id AND cs.chat_channel_id IS NOT NULL)
 OR EXISTS(SELECT 1 FROM chat_message_attachments cma JOIN chat_messages msg ON msg.id=cma.message_id JOIN chat_channel_members hcm ON hcm.channel_id=msg.channel_id AND hcm.user_id=$2 WHERE cma.version_id=v.id AND msg.deleted_at IS NULL AND msg.seq>coalesce(hcm.history_floor_seq,0) AND(hcm.history_floor_seq IS NULL OR msg.created_at>=hcm.joined_at)))))))::text WHERE $2::bigint>0 AND $3::text IS NOT NULL"#;

const BOUND_UPLOAD:&str="SELECT CASE WHEN s.classification='regular' THEN 'g' ELSE 's'||s.id END FROM drive_nodes n JOIN drive_spaces s ON s.id=n.space_id JOIN drive_acl_generations g ON g.space_id=s.id WHERE n.id=$3 AND n.space_id=$2 AND s.acl_mode='acl' AND g.epoch=$4 AND drive_runtime_has_node_capability($1,n.id,CASE WHEN n.kind='folder' THEN 'create_child' ELSE 'modify_content' END)";
pub async fn upload_authority(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    space: i64,
    target: Option<i64>,
    epoch: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    if let (Some(target), Some(epoch)) = (target, epoch) {
        write(exec,actor,"drive_upload_authority","SELECT to_jsonb(CASE WHEN s.classification='regular' THEN 'g' ELSE 's'||s.id END)::text FROM drive_nodes n JOIN drive_spaces s ON s.id=n.space_id JOIN drive_acl_generations g ON g.space_id=s.id WHERE n.id=$5 AND n.space_id=$4 AND s.acl_mode='acl' AND g.epoch=$6 AND drive_runtime_has_node_capability($2,n.id,CASE WHEN n.kind='folder' THEN 'create_child' ELSE 'modify_content' END) AND $2::bigint>0 AND $3::text IS NOT NULL",&[(&space,Type::INT8),(&target,Type::INT8),(&epoch,Type::INT8)],operation).await
    } else {
        write(exec,actor,"drive_upload_authority","SELECT to_jsonb(drive_chunk_upload_require($2,$4))::text WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[(&space,Type::INT8)],operation).await
    }
}
pub async fn commit_chunk<F, Fut>(
    exec: &ScopedExecutor,
    actor: &AuthContext,
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
    let auth = session(actor);
    let user = actor.user_id();
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(sha.as_bytes()).into()),
        command: (),
    };
    setjoin_pg::command::run_receipted_effect(
        exec,
        ReceiptCommand {
            family: "F14",
            command: "drive_chunk_register",
        },
        &envelope,
        &auth,
        Instant::now() + Duration::from_secs(30),
        async move |tx: &mut setjoin_pg::ScopedTx| {
            let scope: String = if let (Some(target), Some(epoch)) = (target, epoch) {
                let rows = tx
                    .query(
                        BOUND_UPLOAD,
                        &[
                            (&user, Type::INT8),
                            (&space, Type::INT8),
                            (&target, Type::INT8),
                            (&epoch, Type::INT8),
                        ],
                    )
                    .await?;
                rows.first()
                    .ok_or_else(|| StatementFailure {
                        sqlstate: None,
                        hint: None,
                        message: "no rows in result set".into(),
                    })?
                    .get(0)
            } else {
                tx.query(
                    "SELECT drive_chunk_upload_require($1,$2)",
                    &[(&user, Type::INT8), (&space, Type::INT8)],
                )
                .await?[0]
                    .get(0)
            };
            tx.query(
                "SELECT pg_advisory_xact_lock(hashtextextended('drive-chunk:'||$1||':'||$2,0))",
                &[(&scope, Type::TEXT), (&sha, Type::TEXT)],
            )
            .await?;
            promote(format!("drive/{scope}/{sha}")).await?;
            if let (Some(target), Some(epoch)) = (target, epoch) {
                tx.query(
                    "SELECT drive_chunk_register_bound($1,$2,$3,$4,$5,$6)",
                    &[
                        (&user, Type::INT8),
                        (&space, Type::INT8),
                        (&target, Type::INT8),
                        (&epoch, Type::INT8),
                        (&sha, Type::TEXT),
                        (&size, Type::INT4),
                    ],
                )
                .await?;
            } else {
                tx.query(
                    "SELECT drive_chunk_register($1,$2,$3,$4)",
                    &[
                        (&user, Type::INT8),
                        (&space, Type::INT8),
                        (&sha, Type::TEXT),
                        (&size, Type::INT4),
                    ],
                )
                .await?;
            }
            Ok(Value::Null)
        },
    )
    .await
}

pub async fn preview_query(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    version: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(
        exec,
        actor,
        "drive_preview_query",
        PREVIEW_QUERY,
        &[(&version, Type::INT8)],
        operation,
    )
    .await
}
const PREVIEW_QUERY: &str = r#"SELECT jsonb_build_object('spaceId',v.space_id,'classification',s.classification,'status',v.preview_status,
 'auditReads',coalesce((drive_policy_resolve(v.space_id)->>'audit_reads')::boolean,false))::text
 FROM drive_file_versions v JOIN drive_spaces s ON s.id=v.space_id
 WHERE v.id=$4 AND drive_runtime_has_node_capability($2,v.file_node_id,'preview')
 AND(NOT EXISTS(SELECT 1 FROM drive_file_versions cv JOIN drive_spaces cs ON cs.id=cv.space_id WHERE cv.id=v.id AND cs.chat_channel_id IS NOT NULL)
 OR EXISTS(SELECT 1 FROM chat_message_attachments cma JOIN chat_messages msg ON msg.id=cma.message_id JOIN chat_channel_members hcm ON hcm.channel_id=msg.channel_id AND hcm.user_id=$2 WHERE cma.version_id=v.id AND msg.deleted_at IS NULL AND msg.seq>coalesce(hcm.history_floor_seq,0) AND(hcm.history_floor_seq IS NULL OR msg.created_at>=hcm.joined_at)))
 AND $2::bigint>0 AND $3::text IS NOT NULL"#;

pub async fn patch_quota(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    target: i64,
    quota: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(exec,actor,"drive_space_set_quota","SELECT 'null'::text FROM drive_space_set_quota($2,$4,$5) WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[(&target,Type::INT8),(&quota,Type::INT8)],operation).await
}

pub async fn folder_grant(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    space: i64,
    folder: i64,
    user: i64,
    role: &str,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(exec,actor,"drive_folder_member_grant","SELECT drive_folder_member_grant($2,$4,$5,$6,$7)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[(&space,Type::INT8),(&folder,Type::INT8),(&user,Type::INT8),(&role,Type::TEXT)],operation).await
}
pub async fn folder_revoke(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    space: i64,
    folder: i64,
    user: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    write(exec,actor,"drive_folder_member_revoke","SELECT 'null'::text FROM drive_folder_member_revoke($2,$4,$5,$6) WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[(&space,Type::INT8),(&folder,Type::INT8),(&user,Type::INT8)],operation).await
}

/// Explicit worker metadata read, after live drive.view admission on the app pool.
pub async fn admin_spaces(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<Value, StatementFailure> {
    let rows=exec.read("SELECT (jsonb_build_object('id',s.id,'name',s.name,'isPersonal',s.is_personal,'classification',s.classification,'role','admin','usedBytes',s.used_bytes,'changeSeq',s.change_seq,'aclMode',s.acl_mode,'aclEpoch',g.epoch,'rootCapabilities','[]'::jsonb,'accessGovernanceEnabled',false) || CASE WHEN s.quota_bytes IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('quotaBytes',s.quota_bytes) END)::text FROM drive_spaces s JOIN drive_acl_generations g ON g.space_id=s.id WHERE s.chat_channel_id IS NULL AND s.meeting_id IS NULL ORDER BY s.is_personal DESC,s.name",&[]).await?;
    let mut out: Vec<Value> = rows
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).expect("database JSON"))
        .collect();
    let user = actor.user_id();
    if let Ok(rows) = exec
        .read(
            "SELECT drive_worm_pending($1)::text",
            &[(&user, Type::INT8)],
        )
        .await
    {
        if let Some(row) = rows.first() {
            if let Ok(Value::Array(pending)) =
                serde_json::from_str::<Value>(&row.get::<_, String>(0))
            {
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
    Ok(Value::Array(out))
}

/// Go reads the manifest in a fresh transaction after metadata admission.
pub async fn preview_manifest(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    version: i64,
) -> Result<Value, StatementFailure> {
    let user = actor.user_id();
    read(exec,actor,"SELECT coalesce(jsonb_agg(jsonb_build_object('storageRef',c.storage_ref,'size',c.size_bytes) ORDER BY vc.ordinal),'[]'::jsonb)::text FROM drive_version_chunks vc JOIN drive_chunks c ON c.scope_key=vc.scope_key AND c.sha256=vc.chunk_sha256 JOIN drive_file_versions v ON v.id=vc.version_id WHERE vc.version_id=$1 AND vc.stream='preview' AND (drive_runtime_has_node_capability($2,v.file_node_id,'preview') OR drive_runtime_has_node_capability($2,v.file_node_id,'download'))",&[(&version,Type::INT8),(&user,Type::INT8)]).await
}
