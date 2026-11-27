//! Static typed SQL contract catalog for `setjoin-drive` (F14).
use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};

// ---------------------------------------------------------------------------
// Feature toggles (AuthPreScope)
// ---------------------------------------------------------------------------

pub const FEATURE_ENABLED: SqlContract = SqlContract {
    id: "drive.feature_enabled",
    domain: "drive",
    sql: "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key=$1),false)",
    params: &[Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FEATURE_ANY_ENABLED: SqlContract = SqlContract {
    id: "drive.feature_any_enabled",
    domain: "drive",
    sql: "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key=$1),false) OR coalesce((SELECT enabled FROM feature_toggles WHERE key=$2),false)",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SHARING_DEFAULTS_ENABLED: SqlContract = SqlContract {
    id: "drive.sharing_defaults_enabled",
    domain: "drive",
    sql: "SELECT enabled FROM feature_toggles WHERE key='sharing.defaults'",
    params: &[],
    columns: &[ColumnSpec::named("enabled", Type::BOOL)],
    scope: SqlScope::AuthPreScope,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---------------------------------------------------------------------------
// Sharing self-service and admin sharing (`lib.rs`)
// ---------------------------------------------------------------------------

pub const SHARING_CONSOLE_DENIED: SqlContract = SqlContract {
    id: "drive.sharing_console_denied",
    domain: "drive",
    sql: "SELECT audit_write(NULL,'console.denied','console',NULL,$1::text::jsonb,NULL,NULL,$2,'core')",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SHARING_REASON_REQUIRED: SqlContract = SqlContract {
    id: "drive.sharing_reason_required",
    domain: "drive",
    sql: "SELECT 'sharing'=ANY(reason_required_areas) FROM audit_policy WHERE id=1",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::BOOL)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SHARING_REASON_MISSING: SqlContract = SqlContract {
    id: "drive.sharing_reason_missing",
    domain: "drive",
    sql: "SELECT audit_write($1,'sensitive_action.reason_missing','',NULL,NULL,NULL,$2::text::inet,'sharing.manage','core')",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_LIST_DEFAULTS: SqlContract = SqlContract {
    id: "drive.admin_list_defaults",
    domain: "drive",
    sql: r#"SELECT jsonb_build_object('id',t.id,'resource',t.resource,'ownerScope',t.owner_scope,'ownerRef',t.owner_ref,'ownerLabel',t.owner_label,'audience',t.audience,'audienceRef',t.audience_ref,'audienceLabel',t.audience_label,'level',t.level,'createdBy',t.created_by,'updatedAt',t.updated_at)::text FROM (
	SELECT sd.id, sd.resource, sd.owner_scope, sd.owner_ref,
	       COALESCE(CASE sd.owner_scope
	         WHEN 'org'   THEN (SELECT name  FROM domains             WHERE id = sd.owner_ref)
	         WHEN 'ou'    THEN (SELECT name  FROM departments         WHERE id = sd.owner_ref)
	         WHEN 'group' THEN (SELECT m.email FROM distribution_groups g
	                              JOIN mailboxes m ON m.id = g.mailbox_id WHERE g.id = sd.owner_ref)
	         WHEN 'user'  THEN (SELECT email FROM users               WHERE id = sd.owner_ref)
	       END, '') AS owner_label,
	       sd.audience, sd.audience_ref,
	       COALESCE(CASE sd.audience
	         WHEN 'everyone' THEN (SELECT name  FROM domains             WHERE id = sd.audience_ref)
	         WHEN 'ou'       THEN (SELECT name  FROM departments         WHERE id = sd.audience_ref)
	         WHEN 'group'    THEN (SELECT m.email FROM distribution_groups g
	                                 JOIN mailboxes m ON m.id = g.mailbox_id WHERE g.id = sd.audience_ref)
	       END, '') AS audience_label,
	       sd.level, sd.created_by, sd.updated_at::TEXT AS updated_at
	FROM sharing_defaults sd
	WHERE ($1::bigint = 0
	   OR (sd.owner_scope = 'org'   AND sd.owner_ref = $1)
	   OR (sd.owner_scope = 'ou')
	   OR (sd.owner_scope = 'group' AND EXISTS (
	         SELECT 1 FROM distribution_groups g JOIN mailboxes m ON m.id = g.mailbox_id
	          WHERE g.id = sd.owner_ref AND m.domain_id = $1))
	   OR (sd.owner_scope = 'user'  AND EXISTS (
	         SELECT 1 FROM users u WHERE u.id = sd.owner_ref AND u.domain_id = $1)))
	ORDER BY sd.owner_scope, sd.id) t ORDER BY t.owner_scope,t.id"#,
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_SHARING_AUDIT: SqlContract = SqlContract {
    id: "drive.admin_sharing_audit",
    domain: "drive",
    sql: r#"SELECT item::text FROM (
      SELECT al.occurred_at,jsonb_build_object('id',al.id,'occurredAt',to_char(al.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),'userEmail',coalesce(u.email,'system'),'action',al.action)
      || CASE WHEN al.user_id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('userId',al.user_id) END
      || CASE WHEN al.target_type IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('targetType',al.target_type) END
      || CASE WHEN al.target_id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('targetId',al.target_id) END
      || CASE WHEN al.before_state IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('beforeState',al.before_state) END
      || CASE WHEN al.after_state IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('afterState',al.after_state) END AS item
      FROM admin_audit_log al LEFT JOIN users u ON u.id=al.user_id
      WHERE al.action=ANY(ARRAY['mailbox_delegate_granted','mailbox_delegate_revoked','sharing_default_set','sharing_default_cleared']) AND ($1::bigint IS NULL OR al.user_id=$1)
      ORDER BY al.occurred_at DESC LIMIT $2 OFFSET $3) t ORDER BY occurred_at DESC"#,
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_CREATE_DEFAULT: SqlContract = SqlContract {
    id: "drive.admin_create_default",
    domain: "drive",
    sql: "SELECT sharing_default_set($1,'calendar',$2,$3,$4,$5,$6)",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ADMIN_DELETE_DEFAULT: SqlContract = SqlContract {
    id: "drive.admin_delete_default",
    domain: "drive",
    sql: "SELECT sharing_default_clear($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};

pub const ADMIN_OVERSIGHT_USER: SqlContract = SqlContract {
    id: "drive.admin_oversight_user",
    domain: "drive",
    sql: "SELECT email,display_name FROM users WHERE id=$1 AND ($2::bigint=0 OR domain_id=$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("email", Type::TEXT),
        ColumnSpec::named("display_name", Type::TEXT),
    ],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_OVERSIGHT_DELEGATES: SqlContract = SqlContract {
    id: "drive.admin_oversight_delegates",
    domain: "drive",
    sql: "SELECT jsonb_build_object('userId',u.id,'email',u.email,'name',u.display_name,'permission',md.permission,'grantedAt',md.granted_at::text)::text FROM mailbox_delegates md JOIN mailboxes m ON m.id=md.mailbox_id JOIN users u ON u.id=md.user_id WHERE m.user_id=$1 ORDER BY u.email,md.permission",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_OVERSIGHT_CALENDAR_GRANTS: SqlContract = SqlContract {
    id: "drive.admin_oversight_calendar_grants",
    domain: "drive",
    sql: "SELECT jsonb_build_object('calendarId',c.id,'calendarName',c.name,'userEmail',u.email,'userName',u.display_name,'level',a.permission)::text FROM calendar_acls a JOIN calendars c ON c.id=a.calendar_id JOIN mailboxes m ON m.id=c.mailbox_id JOIN users u ON u.id=a.user_id WHERE m.user_id=$1 ORDER BY c.id,u.email",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_OVERSIGHT_DEFAULTS: SqlContract = SqlContract {
    id: "drive.admin_oversight_defaults",
    domain: "drive",
    sql: r#"SELECT jsonb_build_object('id',t.id,'resource',t.resource,'ownerScope',t.owner_scope,'ownerRef',t.owner_ref,'ownerLabel',t.owner_label,'audience',t.audience,'audienceRef',t.audience_ref,'audienceLabel',t.audience_label,'level',t.level,'createdBy',t.created_by,'updatedAt',t.updated_at)::text FROM (
		SELECT sd.id, sd.resource, sd.owner_scope, sd.owner_ref, '' AS owner_label,
		       sd.audience, sd.audience_ref, '' AS audience_label,
		       sd.level, sd.created_by, sd.updated_at::TEXT AS updated_at
		FROM sharing_defaults sd
		JOIN users u ON u.id = $1
		WHERE sd.resource = 'calendar'
		  AND (   (sd.owner_scope = 'user'  AND sd.owner_ref = u.id)
		       OR (sd.owner_scope = 'org'   AND sd.owner_ref = u.domain_id)
		       OR (sd.owner_scope = 'ou'    AND sd.owner_ref = u.department_id)
		       OR (sd.owner_scope = 'group' AND EXISTS (
		             SELECT 1 FROM distribution_group_members dgm
		             JOIN mailboxes mm ON mm.id = dgm.mailbox_id
		             WHERE dgm.group_id = sd.owner_ref AND mm.user_id = u.id)))
		ORDER BY sd.id) t ORDER BY t.id"#,
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PRIMARY_MAILBOX: SqlContract = SqlContract {
    id: "drive.primary_mailbox",
    domain: "drive",
    sql: "SELECT id FROM mailboxes WHERE user_id=$1 AND is_primary=true LIMIT 1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("id", Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACTOR_DOMAIN: SqlContract = SqlContract {
    id: "drive.actor_domain",
    domain: "drive",
    sql: "SELECT domain_id FROM users WHERE id=$1",
    params: &[Type::INT8],
    columns: &[ColumnSpec::named("domain_id", Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DELEGATE_GRANT: SqlContract = SqlContract {
    id: "drive.delegate_grant",
    domain: "drive",
    sql: "SELECT mailbox_delegate_grant($1,$2,$3,$4) WHERE EXISTS(SELECT 1 FROM mailboxes WHERE id=$2 AND user_id=$1)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DELEGATE_REVOKE: SqlContract = SqlContract {
    id: "drive.delegate_revoke",
    domain: "drive",
    sql: "SELECT mailbox_delegate_revoke($1,$2,$3) WHERE EXISTS(SELECT 1 FROM mailboxes WHERE id=$2 AND user_id=$1)",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_SET_DEFAULT: SqlContract = SqlContract {
    id: "drive.user_set_default",
    domain: "drive",
    sql: "SELECT sharing_default_set($1,'calendar','user',$1,$2,CASE WHEN $2='everyone' AND $3=0 THEN (SELECT domain_id FROM users WHERE id=$1) ELSE $3 END,$4)",
    params: &[Type::INT8, Type::TEXT, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const USER_CLEAR_DEFAULT: SqlContract = SqlContract {
    id: "drive.user_clear_default",
    domain: "drive",
    sql: "SELECT sharing_default_clear($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OVERVIEW_DELEGATES: SqlContract = SqlContract {
    id: "drive.overview_delegates",
    domain: "drive",
    sql: "SELECT jsonb_build_object('userId',u.id,'email',u.email,'name',u.display_name,'permission',md.permission,'grantedAt',md.granted_at::text)::text FROM mailbox_delegates md JOIN mailboxes m ON m.id=md.mailbox_id JOIN users u ON u.id=md.user_id WHERE m.user_id=$1 ORDER BY u.email,md.permission",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OVERVIEW_CALENDAR_GRANTS: SqlContract = SqlContract {
    id: "drive.overview_calendar_grants",
    domain: "drive",
    sql: "SELECT jsonb_build_object('calendarId',c.id,'calendarName',c.name,'userEmail',u.email,'userName',u.display_name,'level',a.permission)::text FROM calendar_acls a JOIN calendars c ON c.id=a.calendar_id JOIN mailboxes m ON m.id=c.mailbox_id JOIN users u ON u.id=a.user_id WHERE m.user_id=$1 ORDER BY c.id,u.email",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OVERVIEW_DEFAULTS: SqlContract = SqlContract {
    id: "drive.overview_defaults",
    domain: "drive",
    sql: "SELECT jsonb_build_object('id',sd.id,'ownerScope',sd.owner_scope,'audience',sd.audience,'audienceRef',sd.audience_ref,'level',sd.level)::text FROM sharing_defaults sd JOIN users me ON me.id=$1 WHERE sd.resource='calendar' AND ((sd.owner_scope='user' AND sd.owner_ref=me.id) OR (sd.owner_scope='org' AND sd.owner_ref=me.domain_id) OR (sd.owner_scope='ou' AND sd.owner_ref=me.department_id) OR (sd.owner_scope='group' AND EXISTS(SELECT 1 FROM distribution_group_members dgm JOIN mailboxes mm ON mm.id=dgm.mailbox_id WHERE dgm.group_id=sd.owner_ref AND mm.user_id=me.id))) ORDER BY sd.id",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---------------------------------------------------------------------------
// Core Drive (`core.rs`)
// ---------------------------------------------------------------------------

pub const LIST_SPACES: SqlContract = SqlContract {
    id: "drive.list_spaces",
    domain: "drive",
    sql: "SELECT drive_rust_list_spaces($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CREATE_SPACE: SqlContract = SqlContract {
    id: "drive.create_space",
    domain: "drive",
    sql: "SELECT jsonb_build_object('id',drive_space_create($1,$2,$3,$4,$5::bigint::integer,$6,$7::text::jsonb))::text",
    params: &[
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::BOOL,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PATCH_CLASSIFICATION: SqlContract = SqlContract {
    id: "drive.patch_classification",
    domain: "drive",
    sql: "SELECT drive_space_set_classification($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PATCH_POLICY: SqlContract = SqlContract {
    id: "drive.patch_policy",
    domain: "drive",
    sql: "SELECT drive_space_set_policy($1,$2,$3::text::jsonb,$4::bigint::integer,$5,$6::bigint::integer)",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPACE_MEMBERS: SqlContract = SqlContract {
    id: "drive.space_members",
    domain: "drive",
    sql: r#"SELECT coalesce(jsonb_agg(jsonb_build_object('userId',m.user_id,'role',m.role,'email',u.email,'displayName',u.display_name,'grantedAt',to_char(m.granted_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) ORDER BY m.role,u.display_name),'[]'::jsonb)::text FROM drive_space_members m JOIN users u ON u.id=m.user_id WHERE m.space_id=$2 AND drive_runtime_has_space_root_capability($1,$2,'manage_acl')"#,
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const GRANT_MEMBER: SqlContract = SqlContract {
    id: "drive.grant_member",
    domain: "drive",
    sql: "SELECT drive_member_grant($1,$2,$3,$4)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REVOKE_MEMBER: SqlContract = SqlContract {
    id: "drive.revoke_member",
    domain: "drive",
    sql: "SELECT drive_member_revoke($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPACE_TREE: SqlContract = SqlContract {
    id: "drive.space_tree",
    domain: "drive",
    sql: r#"SELECT CASE WHEN CASE WHEN $3::bigint IS NULL
 THEN drive_user_has_space_access($1,$2)
 ELSE drive_runtime_has_node_capability($1,$3,'list_children') OR drive_runtime_has_node_capability($1,$3,'traverse') END
 THEN coalesce((SELECT jsonb_agg(
 jsonb_build_object('id',n.id,'parentId',n.parent_id,'kind',n.kind,'name',n.name,'branchCount',coalesce(bc.branch_count,0),
 'lock',CASE WHEN l.holder_id IS NULL THEN NULL ELSE jsonb_build_object('holderId',l.holder_id,'holderName',coalesce(l.holder_name,''),'mode',coalesce(l.mode,''),'branchId',l.branch_id,'acquiredAt',to_char(l.acquired_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),'expiresAt',to_char(l.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) END,
 'capabilities',ARRAY(SELECT capability FROM drive_runtime_capability_sources($1,n.space_id,n.id) ORDER BY capability),
 'traverseOnly',drive_runtime_has_node_capability($1,n.id,'traverse') AND NOT drive_runtime_has_node_capability($1,n.id,'read_metadata'))
 || CASE WHEN f.size_bytes IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('size',f.size_bytes) END
 || CASE WHEN f.content_type IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('contentType',f.content_type) END
 || CASE WHEN f.head_version_id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('headVersionId',f.head_version_id) END
 || CASE WHEN n.deleted_at IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('deletedAt',to_char(n.deleted_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) END
 ORDER BY n.kind DESC,n.name)
 FROM drive_nodes n LEFT JOIN drive_files f ON f.node_id=n.id
 LEFT JOIN LATERAL(SELECT count(*) AS branch_count FROM drive_file_branches b WHERE b.file_node_id=n.id AND b.status IN('open','review'))bc ON true
 LEFT JOIN LATERAL(SELECT lk.user_id AS holder_id,m.display_name AS holder_name,lk.mode,lk.branch_id,lk.acquired_at,lk.expires_at FROM drive_file_locks lk LEFT JOIN mailboxes m ON m.user_id=lk.user_id AND m.is_primary WHERE lk.node_id=n.id AND lk.expires_at>now())l ON true
 WHERE n.space_id=$2 AND n.parent_id IS NOT DISTINCT FROM $3::bigint AND (n.deleted_at IS NOT NULL)=$4
 AND(drive_runtime_has_node_capability($1,n.id,'read_metadata') OR drive_runtime_has_node_capability($1,n.id,'traverse'))),'[]'::jsonb)
 ELSE 'null'::jsonb END::text"#,
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const NODES_META: SqlContract = SqlContract {
    id: "drive.nodes_meta",
    domain: "drive",
    sql: r#"SELECT coalesce(jsonb_agg(jsonb_build_object(
 'nodeId',n.id,'spaceId',n.space_id,'parentId',n.parent_id,'kind',n.kind,'name',n.name,
 'deletedAt',to_char(n.deleted_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
 'headVersionId',f.head_version_id,'contentSha256',v.content_sha256,'sizeBytes',f.size_bytes,'contentType',f.content_type,
 'branchCount',coalesce(bc.branch_count,0),
 'capabilities',ARRAY(SELECT capability FROM drive_runtime_capability_sources($1,n.space_id,n.id) ORDER BY capability),
 'traverseOnly',drive_runtime_has_node_capability($1,n.id,'traverse') AND NOT drive_runtime_has_node_capability($1,n.id,'read_metadata')) ORDER BY n.id),'[]'::jsonb)::text
 FROM drive_nodes n LEFT JOIN drive_files f ON f.node_id=n.id LEFT JOIN drive_file_versions v ON v.id=f.head_version_id
 LEFT JOIN LATERAL(SELECT count(*) AS branch_count FROM drive_file_branches b WHERE b.file_node_id=n.id AND b.status IN('open','review'))bc ON true
 WHERE n.id=ANY($2::bigint[]) AND drive_runtime_has_node_capability($1,n.id,'read_metadata')
 AND(NOT EXISTS(SELECT 1 FROM drive_nodes cn JOIN drive_spaces cs ON cs.id=cn.space_id WHERE cn.id=n.id AND cs.chat_channel_id IS NOT NULL)
 OR EXISTS(SELECT 1 FROM chat_message_attachments cma JOIN chat_messages msg ON msg.id=cma.message_id JOIN chat_channel_members hcm ON hcm.channel_id=msg.channel_id AND hcm.user_id=$1 WHERE cma.file_node_id=n.id AND msg.deleted_at IS NULL AND msg.seq>coalesce(hcm.history_floor_seq,0) AND(hcm.history_floor_seq IS NULL OR msg.created_at>=hcm.joined_at)))"#,
    params: &[Type::INT8, Type::INT8_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHANGES: SqlContract = SqlContract {
    id: "drive.changes",
    domain: "drive",
    sql: "SELECT drive_changes_since($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACCESS_INVALIDATIONS: SqlContract = SqlContract {
    id: "drive.access_invalidations",
    domain: "drive",
    sql: "SELECT drive_access_invalidation_page($1,$2,$3::text::uuid,$4)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const VISIBILITY_SNAPSHOT: SqlContract = SqlContract {
    id: "drive.visibility_snapshot",
    domain: "drive",
    sql: "SELECT drive_visibility_snapshot_page($1,$2,$3,$4,$5)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ALLOW_NAME_MUTATION: SqlContract = SqlContract {
    id: "drive.allow_name_mutation",
    domain: "drive",
    sql: "SELECT to_jsonb(rate_limit_check('drive:name-mutation:'||$1::text,120,1,5))::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CREATE_NODE: SqlContract = SqlContract {
    id: "drive.create_node",
    domain: "drive",
    sql: "SELECT jsonb_build_object('id',drive_node_create($1,$2,$3,$4,$5,$6))::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PATCH_NODE: SqlContract = SqlContract {
    id: "drive.patch_node",
    domain: "drive",
    sql: "SELECT drive_rust_node_patch($1,$2,$3,$4,$5,$6)",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::BOOL,
        Type::TEXT,
        Type::BOOL,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TRASH_NODE: SqlContract = SqlContract {
    id: "drive.trash_node",
    domain: "drive",
    sql: "SELECT drive_node_trash($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RESTORE_NODE: SqlContract = SqlContract {
    id: "drive.restore_node",
    domain: "drive",
    sql: "SELECT drive_node_restore($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DESTROY_NODE: SqlContract = SqlContract {
    id: "drive.destroy_node",
    domain: "drive",
    sql: "SELECT drive_node_destroy($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const HEAD_CHUNK: SqlContract = SqlContract {
    id: "drive.head_chunk",
    domain: "drive",
    sql: r#"SELECT to_jsonb(EXISTS(
 SELECT 1 FROM drive_chunks c WHERE c.scope_key=(SELECT CASE WHEN s.classification='regular' THEN 'g' ELSE 's'||s.id END FROM drive_spaces s WHERE s.id=$2 AND drive_user_has_space_access($1,s.id)) AND c.sha256=$3
 AND(EXISTS(SELECT 1 FROM drive_upload_claims uc JOIN drive_spaces us ON us.id=$2 WHERE us.acl_mode<>'acl' AND uc.scope_key=c.scope_key AND uc.sha256=c.sha256 AND uc.user_id=$1)
 OR EXISTS(SELECT 1 FROM drive_upload_authorizations ua WHERE ua.scope_key=c.scope_key AND ua.sha256=c.sha256 AND ua.user_id=$1 AND ua.space_id=$2 AND ua.expires_at>now() AND($4::bigint IS NULL OR ua.target_node_id=$4) AND($5::bigint IS NULL OR ua.acl_epoch=$5))
 OR EXISTS(SELECT 1 FROM drive_version_chunks vc JOIN drive_file_versions v ON v.id=vc.version_id WHERE vc.scope_key=c.scope_key AND vc.chunk_sha256=c.sha256 AND drive_runtime_has_node_capability($1,v.file_node_id,'download')
 AND(NOT EXISTS(SELECT 1 FROM drive_file_versions cv JOIN drive_spaces cs ON cs.id=cv.space_id WHERE cv.id=v.id AND cs.chat_channel_id IS NOT NULL)
 OR EXISTS(SELECT 1 FROM chat_message_attachments cma JOIN chat_messages msg ON msg.id=cma.message_id JOIN chat_channel_members hcm ON hcm.channel_id=msg.channel_id AND hcm.user_id=$1 WHERE cma.version_id=v.id AND msg.deleted_at IS NULL AND msg.seq>coalesce(hcm.history_floor_seq,0) AND(hcm.history_floor_seq IS NULL OR msg.created_at>=hcm.joined_at)))))))::text"#,
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UPLOAD_AUTHORITY_BOUND: SqlContract = SqlContract {
    id: "drive.upload_authority_bound",
    domain: "drive",
    sql: "SELECT to_jsonb(CASE WHEN s.classification='regular' THEN 'g' ELSE 's'||s.id END)::text FROM drive_nodes n JOIN drive_spaces s ON s.id=n.space_id JOIN drive_acl_generations g ON g.space_id=s.id WHERE n.id=$3 AND n.space_id=$2 AND s.acl_mode='acl' AND g.epoch=$4 AND drive_runtime_has_node_capability($1,n.id,CASE WHEN n.kind='folder' THEN 'create_child' ELSE 'modify_content' END)",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UPLOAD_AUTHORITY_UNBOUND: SqlContract = SqlContract {
    id: "drive.upload_authority_unbound",
    domain: "drive",
    sql: "SELECT to_jsonb(drive_chunk_upload_require($1,$2))::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHUNK_BOUND_UPLOAD: SqlContract = SqlContract {
    id: "drive.chunk_bound_upload",
    domain: "drive",
    sql: "SELECT CASE WHEN s.classification='regular' THEN 'g' ELSE 's'||s.id END FROM drive_nodes n JOIN drive_spaces s ON s.id=n.space_id JOIN drive_acl_generations g ON g.space_id=s.id WHERE n.id=$3 AND n.space_id=$2 AND s.acl_mode='acl' AND g.epoch=$4 AND drive_runtime_has_node_capability($1,n.id,CASE WHEN n.kind='folder' THEN 'create_child' ELSE 'modify_content' END)",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHUNK_UPLOAD_REQUIRE: SqlContract = SqlContract {
    id: "drive.chunk_upload_require",
    domain: "drive",
    sql: "SELECT drive_chunk_upload_require($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHUNK_ADVISORY_LOCK: SqlContract = SqlContract {
    id: "drive.chunk_advisory_lock",
    domain: "drive",
    sql: "SELECT pg_advisory_xact_lock(hashtextextended('drive-chunk:'||$1||':'||$2,0))",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHUNK_REGISTER_BOUND: SqlContract = SqlContract {
    id: "drive.chunk_register_bound",
    domain: "drive",
    sql: "SELECT drive_chunk_register_bound($1,$2,$3,$4,$5,$6)",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT4,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CHUNK_REGISTER: SqlContract = SqlContract {
    id: "drive.chunk_register",
    domain: "drive",
    sql: "SELECT drive_chunk_register($1,$2,$3,$4)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::INT4],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PREVIEW_QUERY: SqlContract = SqlContract {
    id: "drive.preview_query",
    domain: "drive",
    sql: r#"SELECT jsonb_build_object('spaceId',v.space_id,'classification',s.classification,'status',v.preview_status,
 'auditReads',coalesce((drive_policy_resolve(v.space_id)->>'audit_reads')::boolean,false))::text
 FROM drive_file_versions v JOIN drive_spaces s ON s.id=v.space_id
 WHERE v.id=$2 AND drive_runtime_has_node_capability($1,v.file_node_id,'preview')
 AND(NOT EXISTS(SELECT 1 FROM drive_file_versions cv JOIN drive_spaces cs ON cs.id=cv.space_id WHERE cv.id=v.id AND cs.chat_channel_id IS NOT NULL)
 OR EXISTS(SELECT 1 FROM chat_message_attachments cma JOIN chat_messages msg ON msg.id=cma.message_id JOIN chat_channel_members hcm ON hcm.channel_id=msg.channel_id AND hcm.user_id=$1 WHERE cma.version_id=v.id AND msg.deleted_at IS NULL AND msg.seq>coalesce(hcm.history_floor_seq,0) AND(hcm.history_floor_seq IS NULL OR msg.created_at>=hcm.joined_at)))"#,
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PREVIEW_MANIFEST: SqlContract = SqlContract {
    id: "drive.preview_manifest",
    domain: "drive",
    sql: "SELECT coalesce(jsonb_agg(jsonb_build_object('storageRef',c.storage_ref,'size',c.size_bytes) ORDER BY vc.ordinal),'[]'::jsonb)::text FROM drive_version_chunks vc JOIN drive_chunks c ON c.scope_key=vc.scope_key AND c.sha256=vc.chunk_sha256 JOIN drive_file_versions v ON v.id=vc.version_id WHERE vc.version_id=$1 AND vc.stream='preview' AND (drive_runtime_has_node_capability($2,v.file_node_id,'preview') OR drive_runtime_has_node_capability($2,v.file_node_id,'download'))",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PREVIEW_REQUEST: SqlContract = SqlContract {
    id: "drive.preview_request",
    domain: "drive",
    sql: "SELECT to_jsonb(drive_preview_request($1,$2))::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PREVIEW_AUDIT: SqlContract = SqlContract {
    id: "drive.preview_audit",
    domain: "drive",
    sql: "SELECT drive_rust_preview_audit($1,$2,$3,true)",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PATCH_QUOTA: SqlContract = SqlContract {
    id: "drive.patch_quota",
    domain: "drive",
    sql: "SELECT drive_space_set_quota($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FOLDER_GRANT: SqlContract = SqlContract {
    id: "drive.folder_grant",
    domain: "drive",
    sql: "SELECT drive_folder_member_grant($1,$2,$3,$4,$5)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FOLDER_REVOKE: SqlContract = SqlContract {
    id: "drive.folder_revoke",
    domain: "drive",
    sql: "SELECT drive_folder_member_revoke($1,$2,$3,$4)",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_READ_PERMISSION: SqlContract = SqlContract {
    id: "drive.admin_read_permission",
    domain: "drive",
    sql: "SELECT to_jsonb(drive_has_admin_perm($1,'drive.view'))::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_SPACES: SqlContract = SqlContract {
    id: "drive.admin_spaces",
    domain: "drive",
    sql: "SELECT (jsonb_build_object('id',s.id,'name',s.name,'isPersonal',s.is_personal,'classification',s.classification,'role','admin','usedBytes',s.used_bytes,'changeSeq',s.change_seq,'aclMode',s.acl_mode,'aclEpoch',g.epoch,'rootCapabilities','[]'::jsonb,'accessGovernanceEnabled',false) || CASE WHEN s.quota_bytes IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('quotaBytes',s.quota_bytes) END)::text FROM drive_spaces s JOIN drive_acl_generations g ON g.space_id=s.id WHERE s.chat_channel_id IS NULL AND s.meeting_id IS NULL ORDER BY s.is_personal DESC,s.name",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ADMIN_WORM_PENDING: SqlContract = SqlContract {
    id: "drive.admin_worm_pending",
    domain: "drive",
    sql: "SELECT drive_worm_pending($1)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::AdminRead,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---------------------------------------------------------------------------
// Sub-router B (`part_b.rs`)
// ---------------------------------------------------------------------------

pub const ACTIVITY_FEED: SqlContract = SqlContract {
    id: "drive.activity_feed",
    domain: "drive",
    sql: "SELECT drive_activity_feed($1,$2,$3,$4::bigint::int,$5)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SEARCH_NODES: SqlContract = SqlContract {
    id: "drive.search_nodes",
    domain: "drive",
    sql: "SELECT drive_search_nodes($1,$2,$3,$4::bigint::int)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CREATE_BRANCH: SqlContract = SqlContract {
    id: "drive.create_branch",
    domain: "drive",
    sql: "SELECT jsonb_build_object('branchId',drive_branch_create($1,$2,$3::text::jsonb->>'name',coalesce(($3::text::jsonb->>'fromVersionId')::bigint,0)))::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LIST_VERSIONS: SqlContract = SqlContract {
    id: "drive.list_versions",
    domain: "drive",
    sql: r#"SELECT coalesce(jsonb_agg(item ORDER BY id DESC),'[]'::jsonb)::text FROM(SELECT v.id,jsonb_build_object('id',v.id,'parentVersionId',v.parent_version_id,'conflictOf',v.conflict_of,'sha256',v.content_sha256,'size',v.size_bytes,'contentType',v.content_type,'author',v.author_user_id,'deviceLabel',v.device_label,'note',v.note,'previewStatus',v.preview_status,'createdAt',to_char(v.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),'branchId',NULL,'labels','[]'::jsonb) item FROM drive_file_versions v WHERE v.file_node_id=$2 AND drive_runtime_has_node_capability($1,v.file_node_id,'read_metadata')) t"#,
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LIST_BRANCHES: SqlContract = SqlContract {
    id: "drive.list_branches",
    domain: "drive",
    sql: r#"SELECT CASE WHEN EXISTS(SELECT 1 FROM drive_nodes n WHERE n.id=$2 AND drive_runtime_has_node_capability($1,n.id,'read_metadata')) THEN coalesce((SELECT jsonb_agg(jsonb_build_object('id',b.id,'name',b.name,'status',b.status,'autoCreated',b.auto_created,'headVersionId',b.head_version_id,'forkedFromVersionId',b.forked_from_version_id,'createdBy',b.created_by,'createdAt',to_char(b.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),'resolvedBy',b.resolved_by,'resolvedAt',to_char(b.resolved_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),'ffEligible',(b.forked_from_version_id=f.head_version_id AND b.status IN('open','review'))) ORDER BY b.created_at DESC) FROM drive_file_branches b JOIN drive_files f ON f.node_id=b.file_node_id WHERE b.file_node_id=$2 AND (coalesce(($3::text::jsonb->>'all')::boolean,false) OR b.status IN('open','review'))),'[]'::jsonb) END::text"#,
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUDIT_ACTIONS: SqlContract = SqlContract {
    id: "drive.audit_actions",
    domain: "drive",
    sql: "SELECT drive_audit_actions()::text",
    params: &[],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LIST_ALARMS: SqlContract = SqlContract {
    id: "drive.list_alarms",
    domain: "drive",
    sql: r#"SELECT CASE WHEN drive_has_admin_perm($1,'drive.manage') THEN coalesce((SELECT jsonb_agg(jsonb_build_object('id',id,'spaceId',space_id,'actionPattern',action_pattern,'threshold',threshold,'windowMinutes',window_minutes,'enabled',enabled,'createdBy',created_by,'createdAt',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')) ORDER BY id) FROM drive_audit_alarms),'[]'::jsonb) END::text"#,
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const VERIFY_AUDIT: SqlContract = SqlContract {
    id: "drive.verify_audit",
    domain: "drive",
    sql: "SELECT CASE WHEN drive_has_admin_perm($1,'drive.view') THEN (SELECT jsonb_build_object('checked',count(*),'broken',coalesce(jsonb_agg(row_id ORDER BY row_id) FILTER(WHERE NOT valid),'[]'::jsonb)) FROM verify_drive_audit_chain($2)) END::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const TRASH_ADMIN_LIST: SqlContract = SqlContract {
    id: "drive.trash_admin_list",
    domain: "drive",
    sql: "SELECT jsonb_build_object('items',drive_trash_admin_list($1,$2))::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OFFICE_CHOICES: SqlContract = SqlContract {
    id: "drive.office_choices",
    domain: "drive",
    sql: "SELECT office_choice_query($1,$2,coalesce($3::text::jsonb->>'platform','web'))::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FILE_HISTORY: SqlContract = SqlContract {
    id: "drive.file_history",
    domain: "drive",
    sql: "SELECT drive_file_history_query($1,$2,coalesce(($3::text::jsonb->>'limit')::int,100),($3::text::jsonb->>'beforeAt')::timestamptz,($3::text::jsonb->>'beforeRank')::int,($3::text::jsonb->>'beforeId')::bigint)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUDIT_QUERY: SqlContract = SqlContract {
    id: "drive.audit_query",
    domain: "drive",
    sql: "SELECT drive_audit_query($1,($2::text::jsonb->>'space')::bigint,($2::text::jsonb->>'actor')::bigint,$2::text::jsonb->>'action',($2::text::jsonb->>'from')::timestamptz,($2::text::jsonb->>'to')::timestamptz,$2::text::jsonb->>'q',($2::text::jsonb->>'max')::bigint::int,($2::text::jsonb->>'beforeId')::bigint)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SET_LABEL: SqlContract = SqlContract {
    id: "drive.set_label",
    domain: "drive",
    sql: "SELECT drive_version_label_set($1,$2,coalesce($3::text::jsonb->>'label',''))",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REMOVE_LABEL: SqlContract = SqlContract {
    id: "drive.remove_label",
    domain: "drive",
    sql: "SELECT drive_version_label_remove($1,$2,$3::text::jsonb->>'label')",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RESOLVE_BRANCH: SqlContract = SqlContract {
    id: "drive.resolve_branch",
    domain: "drive",
    sql: "SELECT drive_branch_resolve($1,$2,coalesce($3::text::jsonb->>'verb',''),$3::text::jsonb->>'newName')::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CREATE_ALARM: SqlContract = SqlContract {
    id: "drive.create_alarm",
    domain: "drive",
    sql: "SELECT jsonb_build_object('id',drive_alarm_create($1,($2::text::jsonb->>'spaceId')::bigint,coalesce($2::text::jsonb->>'actionPattern',''),($2::text::jsonb->>'threshold')::int,($2::text::jsonb->>'windowMinutes')::int))::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const DELETE_ALARM: SqlContract = SqlContract {
    id: "drive.delete_alarm",
    domain: "drive",
    sql: "SELECT drive_alarm_delete($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PATCH_BRANCH: SqlContract = SqlContract {
    id: "drive.patch_branch",
    domain: "drive",
    sql: "SELECT CASE WHEN $3::text::jsonb ? 'name' THEN drive_branch_rename($1,$2,$3::text::jsonb->>'name') ELSE drive_branch_set_status($1,$2,$3::text::jsonb->>'status') END",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const UPDATE_ALARM: SqlContract = SqlContract {
    id: "drive.update_alarm",
    domain: "drive",
    sql: "SELECT drive_alarm_update($1,$2,($3::text::jsonb->>'_rawPatch')::jsonb)",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PURGE_RESTORE: SqlContract = SqlContract {
    id: "drive.purge_restore",
    domain: "drive",
    sql: "SELECT drive_node_purge_restore($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OFFICE_LOCAL_OPEN: SqlContract = SqlContract {
    id: "drive.office_local_open",
    domain: "drive",
    sql: "SELECT office_local_open_accept($1,$2,coalesce($3::text::jsonb->>'appId',''),coalesce($3::text::jsonb->>'deviceId',''))::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OFFICE_REVOKE: SqlContract = SqlContract {
    id: "drive.office_revoke",
    domain: "drive",
    sql: "SELECT office_launch_revoke($1,$2,($3::text::jsonb->>'label')::uuid)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const PUT_VERSION: SqlContract = SqlContract {
    id: "drive.put_version",
    domain: "drive",
    sql: "SELECT drive_file_put_version($1,$2,coalesce($3::text::jsonb->>'contentSha256',''),coalesce(($3::text::jsonb->>'size')::bigint,0),$3::text::jsonb->>'contentType',($3::text::jsonb->>'baseVersionId')::bigint,coalesce($3::text::jsonb->>'manifestRaw','[]')::jsonb,$3::text::jsonb->>'note',$3::text::jsonb->>'deviceLabel',($3::text::jsonb->>'branchId')::bigint)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const RESTORE_VERSION: SqlContract = SqlContract {
    id: "drive.restore_version",
    domain: "drive",
    sql: "SELECT rust_drive_restore_version($1,$2,$3::text::jsonb)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const OFFICE_LAUNCH: SqlContract = SqlContract {
    id: "drive.office_launch",
    domain: "drive",
    sql: "SELECT office_launch_begin($1,$2,coalesce(($3::text::jsonb->>'baseVersionId')::bigint,0),coalesce($3::text::jsonb->>'providerId',''),coalesce($3::text::jsonb->>'deviceId',''),$3::text::jsonb->>'cohortKey',$3::text::jsonb->>'tokenHash',28800)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const REQUEST_EXPORT: SqlContract = SqlContract {
    id: "drive.request_export",
    domain: "drive",
    sql: "SELECT drive_export_request($1,coalesce(($2::text::jsonb->>'versionId')::bigint,0),coalesce($2::text::jsonb->>'action',''),$2::text::jsonb->>'tokenHash',CASE WHEN coalesce(($2::text::jsonb->>'ttlMinutes')::bigint,0)=0 THEN 60 ELSE ($2::text::jsonb->>'ttlMinutes')::int END)::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONSUME_EXPORT: SqlContract = SqlContract {
    id: "drive.consume_export",
    domain: "drive",
    sql: "SELECT drive_export_consume($1,$2::text::jsonb->>'tokenHash')::text",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONTENT_DOWNLOAD_REQUIRE: SqlContract = SqlContract {
    id: "drive.content_download_require",
    domain: "drive",
    sql: "SELECT drive_content_download_require($1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const CONTENT_METADATA: SqlContract = SqlContract {
    id: "drive.content_metadata",
    domain: "drive",
    sql: "SELECT rust_drive_content_meta($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const EXPORT_NAME: SqlContract = SqlContract {
    id: "drive.export_name",
    domain: "drive",
    sql: "SELECT n.name FROM drive_nodes n JOIN drive_files f ON f.node_id=n.id JOIN drive_file_versions v ON v.file_node_id=f.node_id WHERE v.id=$2 AND drive_runtime_has_node_capability($1,v.file_node_id,'download')",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::named("name", Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const AUDIT_VIEW: SqlContract = SqlContract {
    id: "drive.audit_view",
    domain: "drive",
    sql: "SELECT rust_drive_audit_view($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WORM_CONFIG: SqlContract = SqlContract {
    id: "drive.worm_config",
    domain: "drive",
    sql: "SELECT jsonb_build_object('scope','s'||s.id,'mode',coalesce(s.worm_mode,'governance'),'days',coalesce(s.retention_days,0))::text FROM drive_nodes n JOIN drive_spaces s ON s.id=n.space_id WHERE n.id=$2 AND s.classification='gxp' AND drive_runtime_has_node_capability($1,n.id,'read_metadata')",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WORM_APPLIED: SqlContract = SqlContract {
    id: "drive.worm_applied",
    domain: "drive",
    sql: "UPDATE drive_chunks c SET worm_applied_until=greatest(coalesce(c.worm_applied_until,'-infinity'),$5::text::timestamptz) WHERE c.scope_key=$3 AND c.sha256=$4 AND EXISTS(SELECT 1 FROM drive_version_chunks vc JOIN drive_file_versions v ON v.id=vc.version_id WHERE v.file_node_id=$2 AND v.author_user_id=$1 AND vc.scope_key=c.scope_key AND vc.chunk_sha256=c.sha256)",
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT, Type::TEXT],
    columns: &[],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---------------------------------------------------------------------------
// Sub-router C: ACL, access requests, locks, folder admins, watches, as-of (`part_c.rs`)
// ---------------------------------------------------------------------------

pub const ACL_RATE: SqlContract = SqlContract {
    id: "drive.acl_rate",
    domain: "drive",
    sql: "SELECT rate_limit_check('drive:acl-mutation:'||$1::text,30,1,5)::text",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACL_NODE_DETAIL: SqlContract = SqlContract {
    id: "drive.acl_node_detail",
    domain: "drive",
    sql: "SELECT drive_acl_node_detail($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACL_GRANT_PREVIEW: SqlContract = SqlContract {
    id: "drive.acl_grant_preview",
    domain: "drive",
    sql: "SELECT drive_acl_grant_preview($1,$2,$3,$4,$5,NULL::text[],$6,$7::text::timestamptz,$8::text::timestamptz,$9::bigint::int,$10)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACL_GRANT: SqlContract = SqlContract {
    id: "drive.acl_grant",
    domain: "drive",
    sql: "SELECT drive_acl_grant($1,$2,$3,$4,$5,NULL::text[],$6,$7::text::timestamptz,$8::text::timestamptz,$9::bigint::int,$10,$11,$12)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACL_REVOKE: SqlContract = SqlContract {
    id: "drive.acl_revoke",
    domain: "drive",
    sql: "SELECT drive_acl_revoke($1,$2,$3,$4)::text",
    params: &[Type::INT8, Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACL_INHERITANCE_PREVIEW: SqlContract = SqlContract {
    id: "drive.acl_inheritance_preview",
    domain: "drive",
    sql: "SELECT drive_acl_inheritance_preview($1,$2,$3)::text",
    params: &[Type::INT8, Type::INT8, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACL_INHERITANCE_SET: SqlContract = SqlContract {
    id: "drive.acl_inheritance_set",
    domain: "drive",
    sql: "SELECT drive_acl_inheritance_set($1,$2,$3,$4)::text",
    params: &[Type::INT8, Type::INT8, Type::BOOL, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACL_QUICK_VIEW: SqlContract = SqlContract {
    id: "drive.acl_quick_view",
    domain: "drive",
    sql: "SELECT drive_acl_quick_view($1,$2,$3::bigint::int)::text",
    params: &[Type::INT8, Type::TEXT, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACL_REQUEST_PREVIEW: SqlContract = SqlContract {
    id: "drive.acl_request_preview",
    domain: "drive",
    sql: "SELECT drive_access_request_preview($1,$2,$3,$4,$5,$6,$7::bigint::int,$8::bigint::int,$9,$10,$11)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT_ARRAY,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
        Type::BOOL,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACL_REQUEST_CREATE: SqlContract = SqlContract {
    id: "drive.acl_request_create",
    domain: "drive",
    sql: "SELECT drive_access_request($1,$2,$3,$4,$5,$6,$7::bigint::int,$8::bigint::int,$9,$10,$11,$12)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::TEXT_ARRAY,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
        Type::BOOL,
        Type::TEXT,
        Type::TEXT,
        Type::TEXT,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOCK_LIST: SqlContract = SqlContract {
    id: "drive.lock_list",
    domain: "drive",
    sql: "SELECT drive_lock_list($1,$2)::text",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOCK_PUT: SqlContract = SqlContract {
    id: "drive.lock_put",
    domain: "drive",
    sql: "SELECT drive_file_lock($1,$2,$3,$4,$5,$6,$7::bigint::int)::text",
    params: &[
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
        Type::INT8,
        Type::TEXT,
        Type::INT8,
    ],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const LOCK_DELETE: SqlContract = SqlContract {
    id: "drive.lock_delete",
    domain: "drive",
    sql: "SELECT drive_file_unlock($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::BOOL],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WATCH_PUT: SqlContract = SqlContract {
    id: "drive.watch_put",
    domain: "drive",
    sql: "SELECT drive_watch_set($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::TEXT_ARRAY],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WATCH_DELETE: SqlContract = SqlContract {
    id: "drive.watch_delete",
    domain: "drive",
    sql: "SELECT drive_watch_remove($1,$2)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FOLDER_ADMIN_GRANT: SqlContract = SqlContract {
    id: "drive.folder_admin_grant",
    domain: "drive",
    sql: "SELECT drive_folder_admin_grant($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FOLDER_ADMIN_REVOKE: SqlContract = SqlContract {
    id: "drive.folder_admin_revoke",
    domain: "drive",
    sql: "SELECT drive_folder_admin_revoke($1,$2,$3)",
    params: &[Type::INT8, Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SPACE_AS_OF: SqlContract = SqlContract {
    id: "drive.space_as_of",
    domain: "drive",
    sql: "SELECT drive_space_as_of($1,$2,$3::text::timestamptz)::text",
    params: &[Type::INT8, Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::TEXT)],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const ACL_SUBJECTS: SqlContract = SqlContract {
    id: "drive.acl_subjects",
    domain: "drive",
    sql: r#"SELECT kind,id::text,label,secondary FROM (
              WITH target AS (
                SELECT u.domain_id FROM drive_nodes n JOIN drive_spaces s ON s.id=n.space_id
                JOIN users u ON u.id=s.owner_user_id
                WHERE n.id=$2 AND drive_runtime_has_node_capability($1,n.id,'manage_acl')
              ), candidates AS (
                SELECT 'user'::text kind,u.id,COALESCE(NULLIF(u.display_name,''),u.email) label,u.email secondary
                FROM users u,target t WHERE u.domain_id=t.domain_id AND u.enabled AND u.id<>$1
                  AND (strpos(lower(COALESCE(u.display_name,'')),lower($3))>0
                    OR strpos(lower(u.email),lower($3))>0)
                UNION ALL
                SELECT 'group',g.id,g.name,'' FROM directory_groups g,target t
                WHERE $4 AND g.domain_id=t.domain_id AND g.state='active'
                  AND g.visibility<>'hidden' AND strpos(lower(g.name),lower($3))>0
              )
              SELECT kind,id,label,secondary FROM candidates ORDER BY label,id LIMIT 50) x
              ORDER BY label,id"#,
    params: &[Type::INT8, Type::INT8, Type::TEXT, Type::BOOL],
    columns: &[
        ColumnSpec::named("kind", Type::TEXT),
        ColumnSpec::unnamed(Type::TEXT),
        ColumnSpec::named("label", Type::TEXT),
        ColumnSpec::named("secondary", Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const FOLDER_ADMINS: SqlContract = SqlContract {
    id: "drive.folder_admins",
    domain: "drive",
    sql: r#"SELECT c.can,fa.user_id,fa.display_name,fa.granted_by,fa.granted_at
                 FROM (SELECT EXISTS(SELECT 1 FROM drive_nodes n WHERE n.id=$2 AND drive_runtime_has_node_capability($1,n.id,'manage_acl')) can) c
                 LEFT JOIN LATERAL (
                   SELECT x.user_id,u.display_name,x.granted_by,
                          to_char(x.granted_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"') granted_at,x.granted_at ts
                     FROM drive_folder_admins x JOIN users u ON u.id=x.user_id
                    WHERE x.node_id=$2 AND c.can) fa ON true
                ORDER BY fa.ts"#,
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("can", Type::BOOL),
        ColumnSpec::named("user_id", Type::INT8),
        ColumnSpec::named("display_name", Type::TEXT),
        ColumnSpec::named("granted_by", Type::INT8),
        ColumnSpec::named("granted_at", Type::TEXT),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WATCHES_LIST: SqlContract = SqlContract {
    id: "drive.watches_list",
    domain: "drive",
    sql: "SELECT w.node_id,n.name,n.kind,w.ops FROM drive_watches w JOIN drive_nodes n ON n.id=w.node_id WHERE w.user_id=$1 ORDER BY w.created_at DESC",
    params: &[Type::INT8],
    columns: &[
        ColumnSpec::named("node_id", Type::INT8),
        ColumnSpec::named("name", Type::TEXT),
        ColumnSpec::named("kind", Type::TEXT),
        ColumnSpec::named("ops", Type::TEXT_ARRAY),
    ],
    scope: SqlScope::UserScoped,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

// ---------------------------------------------------------------------------
// Watch worker (`watch.rs`, WorkerBypass)
// ---------------------------------------------------------------------------

pub const WATCH_CHANGE_LOOKUP: SqlContract = SqlContract {
    id: "drive.watch_change_lookup",
    domain: "drive",
    sql: "SELECT node_id, op FROM drive_changes WHERE space_id = $1 AND seq = $2",
    params: &[Type::INT8, Type::INT8],
    columns: &[
        ColumnSpec::named("node_id", Type::INT8),
        ColumnSpec::named("op", Type::TEXT),
    ],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WATCH_MATCHING_USERS: SqlContract = SqlContract {
    id: "drive.watch_matching_users",
    domain: "drive",
    sql: "SELECT DISTINCT wa.user_id FROM drive_nodes n \
          JOIN drive_node_closure c ON c.space_id = n.space_id AND c.descendant_id = n.id \
          JOIN drive_watches wa ON wa.node_id = c.ancestor_id \
          WHERE n.id = $1 AND (wa.ops IS NULL OR $2 = ANY(wa.ops)) \
          AND public.drive_runtime_has_node_capability(wa.user_id, n.id, 'read_metadata')",
    params: &[Type::INT8, Type::TEXT],
    columns: &[ColumnSpec::named("user_id", Type::INT8)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const WATCH_PG_NOTIFY: SqlContract = SqlContract {
    id: "drive.watch_pg_notify",
    domain: "drive",
    sql: "SELECT pg_notify($1, $2)",
    params: &[Type::TEXT, Type::TEXT],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::WorkerBypass,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::Standard,
};

pub const SQL_CONTRACTS: &[SqlContract] = &[
    FEATURE_ENABLED,
    FEATURE_ANY_ENABLED,
    SHARING_DEFAULTS_ENABLED,
    SHARING_CONSOLE_DENIED,
    SHARING_REASON_REQUIRED,
    SHARING_REASON_MISSING,
    ADMIN_LIST_DEFAULTS,
    ADMIN_SHARING_AUDIT,
    ADMIN_CREATE_DEFAULT,
    ADMIN_DELETE_DEFAULT,
    ADMIN_OVERSIGHT_USER,
    ADMIN_OVERSIGHT_DELEGATES,
    ADMIN_OVERSIGHT_CALENDAR_GRANTS,
    ADMIN_OVERSIGHT_DEFAULTS,
    PRIMARY_MAILBOX,
    ACTOR_DOMAIN,
    DELEGATE_GRANT,
    DELEGATE_REVOKE,
    USER_SET_DEFAULT,
    USER_CLEAR_DEFAULT,
    OVERVIEW_DELEGATES,
    OVERVIEW_CALENDAR_GRANTS,
    OVERVIEW_DEFAULTS,
    LIST_SPACES,
    CREATE_SPACE,
    PATCH_CLASSIFICATION,
    PATCH_POLICY,
    SPACE_MEMBERS,
    GRANT_MEMBER,
    REVOKE_MEMBER,
    SPACE_TREE,
    NODES_META,
    CHANGES,
    ACCESS_INVALIDATIONS,
    VISIBILITY_SNAPSHOT,
    ALLOW_NAME_MUTATION,
    CREATE_NODE,
    PATCH_NODE,
    TRASH_NODE,
    RESTORE_NODE,
    DESTROY_NODE,
    HEAD_CHUNK,
    UPLOAD_AUTHORITY_BOUND,
    UPLOAD_AUTHORITY_UNBOUND,
    CHUNK_BOUND_UPLOAD,
    CHUNK_UPLOAD_REQUIRE,
    CHUNK_ADVISORY_LOCK,
    CHUNK_REGISTER_BOUND,
    CHUNK_REGISTER,
    PREVIEW_QUERY,
    PREVIEW_MANIFEST,
    PREVIEW_REQUEST,
    PREVIEW_AUDIT,
    PATCH_QUOTA,
    FOLDER_GRANT,
    FOLDER_REVOKE,
    ADMIN_READ_PERMISSION,
    ADMIN_SPACES,
    ADMIN_WORM_PENDING,
    ACTIVITY_FEED,
    SEARCH_NODES,
    CREATE_BRANCH,
    LIST_VERSIONS,
    LIST_BRANCHES,
    AUDIT_ACTIONS,
    LIST_ALARMS,
    VERIFY_AUDIT,
    TRASH_ADMIN_LIST,
    OFFICE_CHOICES,
    FILE_HISTORY,
    AUDIT_QUERY,
    SET_LABEL,
    REMOVE_LABEL,
    RESOLVE_BRANCH,
    CREATE_ALARM,
    DELETE_ALARM,
    PATCH_BRANCH,
    UPDATE_ALARM,
    PURGE_RESTORE,
    OFFICE_LOCAL_OPEN,
    OFFICE_REVOKE,
    PUT_VERSION,
    RESTORE_VERSION,
    OFFICE_LAUNCH,
    REQUEST_EXPORT,
    CONSUME_EXPORT,
    CONTENT_DOWNLOAD_REQUIRE,
    CONTENT_METADATA,
    EXPORT_NAME,
    AUDIT_VIEW,
    WORM_CONFIG,
    WORM_APPLIED,
    ACL_RATE,
    ACL_NODE_DETAIL,
    ACL_GRANT_PREVIEW,
    ACL_GRANT,
    ACL_REVOKE,
    ACL_INHERITANCE_PREVIEW,
    ACL_INHERITANCE_SET,
    ACL_QUICK_VIEW,
    ACL_REQUEST_PREVIEW,
    ACL_REQUEST_CREATE,
    LOCK_LIST,
    LOCK_PUT,
    LOCK_DELETE,
    WATCH_PUT,
    WATCH_DELETE,
    FOLDER_ADMIN_GRANT,
    FOLDER_ADMIN_REVOKE,
    SPACE_AS_OF,
    ACL_SUBJECTS,
    FOLDER_ADMINS,
    WATCHES_LIST,
    WATCH_CHANGE_LOOKUP,
    WATCH_MATCHING_USERS,
    WATCH_PG_NOTIFY,
];
