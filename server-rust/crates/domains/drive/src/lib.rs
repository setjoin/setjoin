//! F14 Drive and sharing. Identity is always the sealed verified context.
#![forbid(unsafe_code)]
pub mod part_b;
pub mod part_c;
pub mod watch;
use serde_json::{json, Value};
use setjoin_authz::AuthContext;
use setjoin_contracts::{
    command::CommandEnvelope,
    ids::{Digest, OperationId},
};
use setjoin_pg::{CommandOutcome, MailboxAuthContext, ReceiptCommand};
use setjoin_pg::{Param, ScopedExecutor, StatementFailure, Type};
use sha2::{Digest as _, Sha256};
use std::time::{Duration, Instant};

pub struct SharingAuthority {
    actor: AuthContext,
    domain: i64,
}
pub async fn authority(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    manage: bool,
) -> Result<Option<SharingAuthority>, StatementFailure> {
    let (permissions, scope) = if actor.signed_admin() {
        let rows=exec.read("SELECT rg.permissions,COALESCE(ra.domain_override,rg.domain_scope) FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$1 AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)",&[(&actor.user_id(),Type::INT8)]).await?;
        let mut permissions = Vec::new();
        let mut scope: Option<i64> = None;
        for row in rows {
            permissions.extend(row.get::<_, Vec<String>>(0));
            if let Some(s) = row.get::<_, Option<i64>>(1) {
                scope = Some(scope.map_or(s, |v| v.min(s)));
            }
        }
        (permissions, scope)
    } else {
        (
            actor.signed_permissions().to_vec(),
            actor.signed_domain_scope(),
        )
    };
    if !permissions
        .iter()
        .any(|p| p == "sharing.manage" || (!manage && p == "sharing.read"))
    {
        return Ok(None);
    }
    Ok(Some(SharingAuthority {
        actor: actor.clone(),
        domain: scope.unwrap_or(0),
    }))
}
pub async fn denied(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    path: &str,
    manage: bool,
    operation: [u8; 16],
) {
    let before=json!({"actor":actor.email(),"target":path,"missingPermission":if manage{"sharing.manage"}else{"sharing.read|sharing.manage"}}).to_string();
    let _=command(exec,actor,"console.denied","SELECT audit_write(NULL,'console.denied','console',NULL,$4::text::jsonb,NULL,NULL,$5,'core') WHERE $1::bigint IS NOT NULL AND $2::bigint IS NOT NULL AND $3::text IS NOT NULL",&[(&before,Type::TEXT),(&path,Type::TEXT)],operation).await;
}
pub async fn reason_required(exec: &ScopedExecutor) -> bool {
    exec.read(
        "SELECT 'sharing'=ANY(reason_required_areas) FROM audit_policy WHERE id=1",
        &[],
    )
    .await
    .ok()
    .and_then(|r| r.first().map(|r| r.get::<_, bool>(0)))
    .unwrap_or(false)
}
pub async fn missing_reason(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    operation: [u8; 16],
) {
    let _=command(exec,actor,"sensitive_action.reason_missing","SELECT audit_write($2,'sensitive_action.reason_missing','',NULL,NULL,NULL,$4::text::inet,'sharing.manage','core') WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",&[(&ip,Type::TEXT)],operation).await;
}
pub async fn list_defaults(
    exec: &ScopedExecutor,
    scope: &SharingAuthority,
) -> Result<Value, StatementFailure> {
    read_json(exec, LIST_DEFAULTS, &[(&scope.domain, Type::INT8)]).await
}
pub async fn audit(
    exec: &ScopedExecutor,
    _scope: &SharingAuthority,
    user: Option<i64>,
    limit: i64,
    offset: i64,
) -> Result<Value, StatementFailure> {
    read_json(exec,r#"SELECT item::text FROM (
      SELECT al.occurred_at,jsonb_build_object('id',al.id,'occurredAt',to_char(al.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),'userEmail',coalesce(u.email,'system'),'action',al.action)
      || CASE WHEN al.user_id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('userId',al.user_id) END
      || CASE WHEN al.target_type IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('targetType',al.target_type) END
      || CASE WHEN al.target_id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('targetId',al.target_id) END
      || CASE WHEN al.before_state IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('beforeState',al.before_state) END
      || CASE WHEN al.after_state IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('afterState',al.after_state) END AS item
      FROM admin_audit_log al LEFT JOIN users u ON u.id=al.user_id
      WHERE al.action=ANY(ARRAY['mailbox_delegate_granted','mailbox_delegate_revoked','sharing_default_set','sharing_default_cleared']) AND ($1::bigint IS NULL OR al.user_id=$1)
      ORDER BY al.occurred_at DESC LIMIT $2 OFFSET $3) t ORDER BY occurred_at DESC"#,&[(&user,Type::INT8),(&limit,Type::INT8),(&offset,Type::INT8)]).await
}
pub async fn create_default(
    exec: &ScopedExecutor,
    scope: &SharingAuthority,
    owner_scope: &str,
    owner_ref: i64,
    audience: &str,
    audience_ref: i64,
    level: &str,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    command(exec,&scope.actor,"sharing_default_set","SELECT sharing_default_set($2,'calendar',$4,$5,$6,$7,$8) WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",&[(&owner_scope,Type::TEXT),(&owner_ref,Type::INT8),(&audience,Type::TEXT),(&audience_ref,Type::INT8),(&level,Type::TEXT)],operation).await
}
pub async fn delete_default(
    exec: &ScopedExecutor,
    scope: &SharingAuthority,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    clear_default(exec, &scope.actor, id, operation).await
}

pub fn session(actor: &AuthContext) -> MailboxAuthContext {
    actor.database_scope()
}
pub async fn primary_mailbox(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<Option<i64>, StatementFailure> {
    Ok(exec
        .read(
            "SELECT id FROM mailboxes WHERE user_id=$1 AND is_primary=true LIMIT 1",
            &[(&actor.user_id(), Type::INT8)],
        )
        .await?
        .first()
        .map(|r| r.get(0)))
}
pub async fn actor_domain(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<Option<i64>, StatementFailure> {
    Ok(exec
        .read(
            "SELECT domain_id FROM users WHERE id=$1",
            &[(&actor.user_id(), Type::INT8)],
        )
        .await?
        .first()
        .map(|r| r.get(0)))
}
async fn command(
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
        |rows| {
            if rows.is_empty() {
                return Err(StatementFailure {
                    sqlstate: Some("42501".into()),
                    message: "authority changed".into(),
                    hint: None,
                });
            }
            Ok(if name == "sharing_default_set" {
                json!({"id":rows[0].get::<_,i64>(0)})
            } else {
                Value::Null
            })
        },
    )
    .await
}
pub async fn grant(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    email: &str,
    permission: &str,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    command(exec,actor,"mailbox_delegate_grant","SELECT mailbox_delegate_grant($2,$1,$4,$5) WHERE $3::text IS NOT NULL AND EXISTS(SELECT 1 FROM mailboxes WHERE id=$1 AND user_id=$2)",&[(&email,Type::TEXT),(&permission,Type::TEXT)],operation).await
}
pub async fn revoke(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    grantee: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    command(exec,actor,"mailbox_delegate_revoke","SELECT mailbox_delegate_revoke($2,$1,$4) WHERE $3::text IS NOT NULL AND EXISTS(SELECT 1 FROM mailboxes WHERE id=$1 AND user_id=$2)",&[(&grantee,Type::INT8)],operation).await
}
pub async fn set_default(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    audience: &str,
    audience_ref: i64,
    level: &str,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    command(exec,actor,"sharing_default_set","SELECT sharing_default_set($2,'calendar','user',$2,$4,CASE WHEN $4='everyone' AND $5=0 THEN (SELECT domain_id FROM users WHERE id=$2) ELSE $5 END,$6) WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",&[(&audience,Type::TEXT),(&audience_ref,Type::INT8),(&level,Type::TEXT)],operation).await
}
pub async fn clear_default(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    command(
        exec,
        actor,
        "sharing_default_clear",
        "SELECT sharing_default_clear($2,$4) WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",
        &[(&id, Type::INT8)],
        operation,
    )
    .await
}

async fn read_json(
    exec: &ScopedExecutor,
    sql: &str,
    params: &[Param<'_>],
) -> Result<Value, StatementFailure> {
    let rows = exec.read_iterated(sql, params).await?;
    rows.iter()
        .map(|row| {
            serde_json::from_str(&row.get::<_, String>(0)).map_err(|_| StatementFailure {
                sqlstate: None,
                message: "invalid database JSON".into(),
                hint: None,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}
/// Frozen Go's user self-service runs on the explicit worker credential.
/// Every data SELECT remains scoped to the verified actor's user ID.
pub async fn overview(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<Value, StatementFailure> {
    let user = actor.user_id();
    let delegates=read_json(exec,"SELECT jsonb_build_object('userId',u.id,'email',u.email,'name',u.display_name,'permission',md.permission,'grantedAt',md.granted_at::text)::text FROM mailbox_delegates md JOIN mailboxes m ON m.id=md.mailbox_id JOIN users u ON u.id=md.user_id WHERE m.user_id=$1 ORDER BY u.email,md.permission",&[(&user,Type::INT8)]).await?;
    let grants=read_json(exec,"SELECT jsonb_build_object('calendarId',c.id,'calendarName',c.name,'userEmail',u.email,'userName',u.display_name,'level',a.permission)::text FROM calendar_acls a JOIN calendars c ON c.id=a.calendar_id JOIN mailboxes m ON m.id=c.mailbox_id JOIN users u ON u.id=a.user_id WHERE m.user_id=$1 ORDER BY c.id,u.email",&[(&user,Type::INT8)]).await?;
    let defaults=read_json(exec,"SELECT jsonb_build_object('id',sd.id,'ownerScope',sd.owner_scope,'audience',sd.audience,'audienceRef',sd.audience_ref,'level',sd.level)::text FROM sharing_defaults sd JOIN users me ON me.id=$1 WHERE sd.resource='calendar' AND ((sd.owner_scope='user' AND sd.owner_ref=me.id) OR (sd.owner_scope='org' AND sd.owner_ref=me.domain_id) OR (sd.owner_scope='ou' AND sd.owner_ref=me.department_id) OR (sd.owner_scope='group' AND EXISTS(SELECT 1 FROM distribution_group_members dgm JOIN mailboxes mm ON mm.id=dgm.mailbox_id WHERE dgm.group_id=sd.owner_ref AND mm.user_id=me.id))) ORDER BY sd.id",&[(&user,Type::INT8)]).await?;
    let enabled = exec
        .read(
            "SELECT enabled FROM feature_toggles WHERE key='sharing.defaults'",
            &[],
        )
        .await?
        .first()
        .is_some_and(|r| r.get::<_, bool>(0));
    let (own, inherited): (Vec<_>, Vec<_>) = defaults
        .as_array()
        .expect("SQL array")
        .iter()
        .cloned()
        .partition(|r| r["ownerScope"] == "user");
    Ok(
        json!({"delegates":delegates,"calendarGrants":grants,"myDefaults":own,"inheritedDefaults":inherited,"defaultsEnabled":enabled}),
    )
}

const LIST_DEFAULTS: &str = r#"SELECT jsonb_build_object('id',t.id,'resource',t.resource,'ownerScope',t.owner_scope,'ownerRef',t.owner_ref,'ownerLabel',t.owner_label,'audience',t.audience,'audienceRef',t.audience_ref,'audienceLabel',t.audience_label,'level',t.level,'createdBy',t.created_by,'updatedAt',t.updated_at)::text FROM (
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
	ORDER BY sd.owner_scope, sd.id) t ORDER BY t.owner_scope,t.id"#;

pub async fn oversight(
    exec: &ScopedExecutor,
    scope: &SharingAuthority,
    user: i64,
) -> Result<Option<Value>, StatementFailure> {
    let rows = match exec
        .read(
            "SELECT email,display_name FROM users WHERE id=$1 AND ($2::bigint=0 OR domain_id=$2)",
            &[(&user, Type::INT8), (&scope.domain, Type::INT8)],
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => return Ok(None),
    };
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let delegates=read_json(exec,"SELECT jsonb_build_object('userId',u.id,'email',u.email,'name',u.display_name,'permission',md.permission,'grantedAt',md.granted_at::text)::text FROM mailbox_delegates md JOIN mailboxes m ON m.id=md.mailbox_id JOIN users u ON u.id=md.user_id WHERE m.user_id=$1 ORDER BY u.email,md.permission",&[(&user,Type::INT8)]).await?;
    let grants=read_json(exec,"SELECT jsonb_build_object('calendarId',c.id,'calendarName',c.name,'userEmail',u.email,'userName',u.display_name,'level',a.permission)::text FROM calendar_acls a JOIN calendars c ON c.id=a.calendar_id JOIN mailboxes m ON m.id=c.mailbox_id JOIN users u ON u.id=a.user_id WHERE m.user_id=$1 ORDER BY c.id,u.email",&[(&user,Type::INT8)]).await?;
    let defaults = read_json(exec, OVERSIGHT_DEFAULTS, &[(&user, Type::INT8)]).await?;
    Ok(Some(
        json!({"userId":user,"email":row.get::<_,String>(0),"displayName":row.get::<_,String>(1),"delegates":delegates,"calendarGrants":grants,"defaults":defaults}),
    ))
}

const OVERSIGHT_DEFAULTS: &str = r#"SELECT jsonb_build_object('id',t.id,'resource',t.resource,'ownerScope',t.owner_scope,'ownerRef',t.owner_ref,'ownerLabel',t.owner_label,'audience',t.audience,'audienceRef',t.audience_ref,'audienceLabel',t.audience_label,'level',t.level,'createdBy',t.created_by,'updatedAt',t.updated_at)::text FROM (
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
		ORDER BY sd.id) t ORDER BY t.id"#;

pub mod core;
