//! User-scoped Drive reducer calls. AuthContext is the only actor source.
use super::*;
pub async fn activity(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    space: i64,
    node: Option<i64>,
    max: Option<i64>,
    before: Option<i64>,
) -> Result<Value, StatementFailure> {
    let rows = exec
        .read_scoped(
            &session(actor),
            "SELECT drive_activity_feed($1,$2,$3,$4::bigint::int,$5)::text",
            &[
                (&actor.user_id(), Type::INT8),
                (&space, Type::INT8),
                (&node, Type::INT8),
                (&max, Type::INT8),
                (&before, Type::INT8),
            ],
        )
        .await?;
    serde_json::from_str(&rows[0].get::<_, String>(0)).map_err(|_| StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid Drive result".into(),
    })
}

pub async fn search(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    space: Option<i64>,
    q: &str,
    max: Option<i64>,
) -> Result<Value, StatementFailure> {
    let rows = exec
        .read_scoped(
            &session(actor),
            "SELECT drive_search_nodes($1,$2,$3,$4::bigint::int)::text",
            &[
                (&actor.user_id(), Type::INT8),
                (&space, Type::INT8),
                (&q, Type::TEXT),
                (&max, Type::INT8),
            ],
        )
        .await?;
    serde_json::from_str(&rows[0].get::<_, String>(0)).map_err(|_| StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid Drive result".into(),
    })
}

pub async fn create_branch(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    node: i64,
    body: &Value,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    mutate(exec,actor,"drive_branch_create","SELECT jsonb_build_object('branchId',drive_branch_create($2,$4,$5::jsonb->>'name',coalesce(($5::jsonb->>'fromVersionId')::bigint,0)))::text WHERE $2::bigint>0 AND $3::text IS NOT NULL",node,body,operation).await
}
async fn mutate(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    name: &'static str,
    sql: &str,
    target: i64,
    body: &Value,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let auth = session(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(body.to_string().as_bytes()).into()),
        command: (),
    };
    let payload = body.to_string();
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
        &[(&target, Type::INT8), (&payload, Type::TEXT)],
        |rows| {
            serde_json::from_str(&rows[0].get::<_, String>(0)).map_err(|_| StatementFailure {
                sqlstate: None,
                hint: None,
                message: "invalid Drive result".into(),
            })
        },
    )
    .await
}

pub async fn simple_read(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    name: &str,
    target: i64,
    body: &Value,
) -> Result<Value, StatementFailure> {
    let sql = match name {
        "list_versions" => {
            r#"SELECT coalesce(jsonb_agg(item ORDER BY id DESC),'[]'::jsonb)::text FROM(SELECT v.id,jsonb_build_object('id',v.id,'parentVersionId',v.parent_version_id,'conflictOf',v.conflict_of,'sha256',v.content_sha256,'size',v.size_bytes,'contentType',v.content_type,'author',v.author_user_id,'deviceLabel',v.device_label,'note',v.note,'previewStatus',v.preview_status,'createdAt',to_char(v.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),'branchId',NULL,'labels','[]'::jsonb) item FROM drive_file_versions v WHERE v.file_node_id=$2 AND drive_runtime_has_node_capability($1,v.file_node_id,'read_metadata')) t WHERE $3::jsonb IS NOT NULL"#
        }
        "list_branches" => {
            r#"SELECT CASE WHEN EXISTS(SELECT 1 FROM drive_nodes n WHERE n.id=$2 AND drive_runtime_has_node_capability($1,n.id,'read_metadata')) THEN coalesce((SELECT jsonb_agg(jsonb_build_object('id',b.id,'name',b.name,'status',b.status,'autoCreated',b.auto_created,'headVersionId',b.head_version_id,'forkedFromVersionId',b.forked_from_version_id,'createdBy',b.created_by,'createdAt',to_char(b.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),'resolvedBy',b.resolved_by,'resolvedAt',to_char(b.resolved_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),'ffEligible',(b.forked_from_version_id=f.head_version_id AND b.status IN('open','review'))) ORDER BY b.created_at DESC) FROM drive_file_branches b JOIN drive_files f ON f.node_id=b.file_node_id WHERE b.file_node_id=$2 AND (coalesce(($3::jsonb->>'all')::boolean,false) OR b.status IN('open','review'))),'[]'::jsonb) END::text"#
        }
        "audit_actions" => {
            // read_scoped binds actor first; only receipted commands have
            // the compatibility mailbox argument before the actor.
            r#"SELECT drive_audit_actions()::text WHERE $1::bigint>0 AND $2::bigint IS NOT NULL AND $3::jsonb IS NOT NULL"#
        }
        "list_alarms" => {
            r#"SELECT CASE WHEN drive_has_admin_perm($1,'drive.manage') THEN coalesce((SELECT jsonb_agg(jsonb_build_object('id',id,'spaceId',space_id,'actionPattern',action_pattern,'threshold',threshold,'windowMinutes',window_minutes,'enabled',enabled,'createdBy',created_by,'createdAt',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) ORDER BY id) FROM drive_audit_alarms),'[]'::jsonb) END::text WHERE $2::bigint IS NOT NULL AND $3::jsonb IS NOT NULL"#
        }
        "verify_audit" => {
            r#"SELECT CASE WHEN drive_has_admin_perm($1,'drive.view') THEN (SELECT jsonb_build_object('checked',count(*),'broken',coalesce(jsonb_agg(row_id ORDER BY row_id) FILTER(WHERE NOT valid),'[]'::jsonb)) FROM verify_drive_audit_chain($2)) END::text WHERE $3::jsonb IS NOT NULL"#
        }
        "trash" => {
            r#"SELECT jsonb_build_object('items',drive_trash_admin_list($1,$2))::text WHERE $3::jsonb IS NOT NULL"#
        }
        "office_choices" => {
            r#"SELECT office_choice_query($1,$2,coalesce($3::jsonb->>'platform','web'))::text"#
        }
        "history" => {
            r#"SELECT drive_file_history_query($1,$2,coalesce(($3::jsonb->>'limit')::int,100),($3::jsonb->>'beforeAt')::timestamptz,($3::jsonb->>'beforeRank')::int,($3::jsonb->>'beforeId')::bigint)::text WHERE $3::jsonb IS NOT NULL"#
        }
        "audit" => {
            r#"SELECT drive_audit_query($1,($3::jsonb->>'space')::bigint,($3::jsonb->>'actor')::bigint,$3::jsonb->>'action',($3::jsonb->>'from')::timestamptz,($3::jsonb->>'to')::timestamptz,$3::jsonb->>'q',($3::jsonb->>'max')::bigint::int,($3::jsonb->>'beforeId')::bigint)::text WHERE $2::bigint IS NOT NULL"#
        }
        // SIMPLE READS
        _ => {
            return Err(StatementFailure {
                sqlstate: None,
                hint: None,
                message: "unregistered Drive read".into(),
            })
        }
    };
    let payload = body.to_string();
    let rows = exec
        .read_scoped(
            &session(actor),
            sql,
            &[
                (&actor.user_id(), Type::INT8),
                (&target, Type::INT8),
                (&payload, Type::TEXT),
            ],
        )
        .await?;
    let raw: Option<String> = rows[0].get(0);
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
    serde_json::from_str(&raw).map_err(|_| StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid Drive result".into(),
    })
}
pub async fn simple_write(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    name: &str,
    target: i64,
    body: &Value,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let (command, sql) = match name {
        "set_label" => (
            "drive_version_label_set",
            r#"SELECT 'null'::text,drive_version_label_set($2,$4,coalesce($5::jsonb->>'label','')) WHERE $2::bigint>0 AND $3::text IS NOT NULL"#,
        ),
        "remove_label" => (
            "drive_version_label_remove",
            r#"SELECT 'null'::text,drive_version_label_remove($2,$4,$5::jsonb->>'label') WHERE $2::bigint>0 AND $3::text IS NOT NULL"#,
        ),
        "resolve_branch" => (
            "drive_branch_resolve",
            r#"SELECT drive_branch_resolve($2,$4,coalesce($5::jsonb->>'verb',''),$5::jsonb->>'newName')::text WHERE $2::bigint>0 AND $3::text IS NOT NULL"#,
        ),
        "create_alarm" => (
            "drive_alarm_create",
            r#"SELECT jsonb_build_object('id',drive_alarm_create($2,($5::jsonb->>'spaceId')::bigint,coalesce($5::jsonb->>'actionPattern',''),($5::jsonb->>'threshold')::int,($5::jsonb->>'windowMinutes')::int))::text WHERE $2::bigint>0 AND $3::text IS NOT NULL AND $4::bigint IS NOT NULL"#,
        ),
        "delete_alarm" => (
            "drive_alarm_delete",
            r#"SELECT 'null'::text,drive_alarm_delete($2,$4) WHERE $2::bigint>0 AND $3::text IS NOT NULL AND $5::jsonb IS NOT NULL"#,
        ),
        "patch_branch" => (
            if body.get("status").is_some() {
                "drive_branch_set_status"
            } else {
                "drive_branch_rename"
            },
            r#"SELECT 'null'::text,CASE WHEN $5::jsonb ? 'name' THEN drive_branch_rename($2,$4,$5::jsonb->>'name') ELSE drive_branch_set_status($2,$4,$5::jsonb->>'status') END WHERE $2::bigint>0 AND $3::text IS NOT NULL"#,
        ),
        "update_alarm" => (
            "drive_alarm_update",
            r#"SELECT 'null'::text,drive_alarm_update($2,$4,($5::jsonb->>'_rawPatch')::jsonb) WHERE $2::bigint>0 AND $3::text IS NOT NULL"#,
        ),
        "purge_restore" => (
            "drive_node_purge_restore",
            r#"SELECT 'null'::text,drive_node_purge_restore($2,$4) WHERE $2::bigint>0 AND $3::text IS NOT NULL AND $5::jsonb IS NOT NULL"#,
        ),
        "office_local_open" => (
            "office_local_open_accept",
            r#"SELECT office_local_open_accept($2,$4,coalesce($5::jsonb->>'appId',''),coalesce($5::jsonb->>'deviceId',''))::text WHERE $2::bigint>0 AND $3::text IS NOT NULL"#,
        ),
        "office_revoke" => (
            "office_launch_revoke",
            r#"SELECT office_launch_revoke($2,$4,($5::jsonb->>'label')::uuid)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL"#,
        ),
        "put_version" => (
            "drive_file_put_version",
            r#"SELECT drive_file_put_version($2,$4,coalesce($5::jsonb->>'contentSha256',''),coalesce(($5::jsonb->>'size')::bigint,0),$5::jsonb->>'contentType',($5::jsonb->>'baseVersionId')::bigint,coalesce($5::jsonb->>'manifestRaw','[]')::jsonb,$5::jsonb->>'note',$5::jsonb->>'deviceLabel',($5::jsonb->>'branchId')::bigint)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL"#,
        ),
        "restore_version" => (
            "rust_drive_restore_version",
            r#"SELECT rust_drive_restore_version($2,$4,$5::jsonb)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL"#,
        ),
        "office_launch" => (
            "office_launch_begin",
            r#"SELECT office_launch_begin($2,$4,coalesce(($5::jsonb->>'baseVersionId')::bigint,0),coalesce($5::jsonb->>'providerId',''),coalesce($5::jsonb->>'deviceId',''),$5::jsonb->>'cohortKey',$5::jsonb->>'tokenHash',28800)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL"#,
        ),
        "request_export" => (
            "drive_export_request",
            r#"SELECT drive_export_request($2,coalesce(($5::jsonb->>'versionId')::bigint,0),coalesce($5::jsonb->>'action',''),$5::jsonb->>'tokenHash',CASE WHEN coalesce(($5::jsonb->>'ttlMinutes')::bigint,0)=0 THEN 60 ELSE ($5::jsonb->>'ttlMinutes')::int END)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL AND $4::bigint IS NOT NULL"#,
        ),
        "consume_export" => (
            "drive_export_consume",
            r#"SELECT drive_export_consume($2,$5::jsonb->>'tokenHash')::text WHERE $2::bigint>0 AND $3::text IS NOT NULL AND $4::bigint IS NOT NULL"#,
        ),
        // SIMPLE WRITES
        _ => {
            return CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(StatementFailure {
                sqlstate: None,
                hint: None,
                message: "unregistered Drive write".into(),
            }))
        }
    };
    mutate(exec, actor, command, sql, target, body, operation).await
}

pub async fn content(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    version: i64,
) -> Result<Option<Value>, StatementFailure> {
    exec.read_scoped(
        &session(actor),
        "SELECT drive_content_download_require($1)",
        &[(&actor.user_id(), Type::INT8)],
    )
    .await?;
    content_metadata(exec, actor, version).await
}
pub async fn content_metadata(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    version: i64,
) -> Result<Option<Value>, StatementFailure> {
    let rows = exec
        .read_scoped(
            &session(actor),
            "SELECT rust_drive_content_meta($1,$2)::text",
            &[(&actor.user_id(), Type::INT8), (&version, Type::INT8)],
        )
        .await?;
    rows.first()
        .and_then(|row| row.get::<_, Option<String>>(0))
        .map(|raw| {
            serde_json::from_str(&raw).map_err(|_| StatementFailure {
                sqlstate: None,
                hint: None,
                message: "invalid Drive content metadata".into(),
            })
        })
        .transpose()
}

pub async fn export_name(exec: &ScopedExecutor, actor: &AuthContext, version: i64) -> String {
    exec.read_scoped(&session(actor),"SELECT n.name FROM drive_nodes n JOIN drive_files f ON f.node_id=n.id JOIN drive_file_versions v ON v.file_node_id=f.node_id WHERE v.id=$2 AND drive_runtime_has_node_capability($1,v.file_node_id,'download')",&[(&actor.user_id(),Type::INT8),(&version,Type::INT8)]).await.ok().and_then(|rows|rows.first().map(|r|r.get::<_,String>(0))).filter(|s|!s.is_empty()).unwrap_or_else(||"download".into())
}

pub async fn audit_view(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    space: i64,
    version: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    mutate(exec,actor,"rust_drive_audit_view","SELECT 'null'::text,rust_drive_audit_view($2,$4,($5::jsonb->>'version')::bigint) WHERE $2::bigint>0 AND $3::text IS NOT NULL",space,&json!({"version":version}),operation).await
}

/// Best-effort post-commit retention lookup, preserving Go's failure behavior.
pub async fn worm_config(exec: &ScopedExecutor, actor: &AuthContext, node: i64) -> Option<Value> {
    let rows=exec.read_scoped(&session(actor),"SELECT jsonb_build_object('scope','s'||s.id,'mode',coalesce(s.worm_mode,'governance'),'days',coalesce(s.retention_days,0))::text FROM drive_nodes n JOIN drive_spaces s ON s.id=n.space_id WHERE n.id=$2 AND s.classification='gxp' AND drive_runtime_has_node_capability($1,n.id,'read_metadata')",&[(&actor.user_id(),Type::INT8),(&node,Type::INT8)]).await.ok()?;
    serde_json::from_str(&rows.first()?.get::<_, String>(0)).ok()
}
pub async fn worm_applied(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    node: i64,
    body: &Value,
    operation: [u8; 16],
) -> bool {
    matches!(mutate(worker,actor,"drive_worm_applied",r#"WITH changed AS(UPDATE drive_chunks c SET worm_applied_until=greatest(coalesce(c.worm_applied_until,'-infinity'),($5::jsonb->>'until')::timestamptz) WHERE c.scope_key=$5::jsonb->>'scope' AND c.sha256=$5::jsonb->>'sha' AND EXISTS(SELECT 1 FROM drive_version_chunks vc JOIN drive_file_versions v ON v.id=vc.version_id WHERE v.file_node_id=$4 AND v.author_user_id=$2 AND vc.scope_key=c.scope_key AND vc.chunk_sha256=c.sha256) RETURNING 1) SELECT 'null'::text,count(*) FROM changed WHERE $2::bigint>0 AND $3::text IS NOT NULL"#,node,body,operation).await,CommandOutcome::Committed(_))
}
