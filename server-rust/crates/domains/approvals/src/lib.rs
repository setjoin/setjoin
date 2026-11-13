//! Approvals family (F10). Reducers own business authority.
#![forbid(unsafe_code)]
use serde::Serialize;
use setjoin_authz::AuthContext;
use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
use setjoin_pg::{MailboxAuthContext, Row, ScopedExecutor, StatementFailure, Type};

pub fn scope(actor: &AuthContext) -> MailboxAuthContext {
    MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor.user_id()).expect("verified actor"),
        MailboxId::new(actor.mailbox_id()).expect("verified mailbox"),
        Generation(1),
    )
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Item {
    id: i64,
    consumer_type: String,
    subject: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    requester_user_id: Option<i64>,
    approver_kind: String,
    approver_ref: i64,
    created_at: String,
    expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    decided_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decided_by_user_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision_comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<Box<serde_json::value::RawValue>>,
}
fn timestamp(mut value: String) -> String {
    if value.ends_with('Z') && value.contains('.') {
        value.pop();
        while value.ends_with('0') {
            value.pop();
        }
        if value.ends_with('.') {
            value.pop();
        }
        value.push('Z');
    }
    value
}
fn item(r: &Row) -> Result<Item, StatementFailure> {
    let ct: String = r.get(1);
    let payload: Option<Box<serde_json::value::RawValue>> = if matches!(
        ct.as_str(),
        "hr.leave" | "hr.expense" | "guest.invite" | "drive.access"
    ) {
        Some(
            serde_json::value::RawValue::from_string(r.get::<_, String>(12))
                .map_err(|_| invalid())?,
        )
    } else {
        None
    };
    Ok(Item {
        id: r.get(0),
        consumer_type: ct,
        subject: r.get(2),
        status: r.get(3),
        requester_user_id: r.get(4),
        approver_kind: r.get(5),
        approver_ref: r.get(6),
        created_at: timestamp(r.get(7)),
        expires_at: timestamp(r.get(8)),
        decided_at: r.get::<_, Option<String>>(9).map(timestamp),
        decided_by_user_id: r.get(10),
        decision_comment: r.get(11),
        payload,
    })
}
fn invalid() -> StatementFailure {
    StatementFailure {
        hint: None,
        sqlstate: None,
        message: "invalid approval result".into(),
    }
}
const COLS: &str = r#"id,consumer_type,subject,status,requester_user_id,approver_kind,approver_ref,
 to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
 to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
 to_char(decided_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),decided_by_user_id,decision_comment,
 (CASE WHEN consumer_type='drive.access' THEN COALESCE((SELECT jsonb_build_object(
 'nodeId',d.node_id::text,'spaceId',d.space_id::text,'requestedCapabilities',to_jsonb(d.requested_capabilities),
 'requestedPropagation',d.requested_propagation,'requestedExpiresAt',d.requested_expires_at,'requestedMaxUses',d.requested_max_uses,
 'emergency',d.emergency,'reason',d.reason,'expectedEpoch',d.expected_epoch::text,'grantId',CASE WHEN d.grant_id IS NULL THEN NULL ELSE d.grant_id::text END)
 FROM drive_access_request_details d WHERE d.request_id=approval_requests.id),'{}'::jsonb) ELSE payload END)::text"#;

/// Same-statement requester/active approver fence remains effective on owner pools.
pub async fn my_approvals(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let auth = scope(actor);
    let uid = actor.user_id();
    let pending=exec.read_scoped(&auth,&format!("SELECT {COLS} FROM approval_requests WHERE status='pending' AND requester_user_id IS DISTINCT FROM $1 AND (requester_user_id=$1 OR (approver_kind='user' AND approver_ref=$1) OR (approver_kind='role_group' AND EXISTS(SELECT 1 FROM public.admin_role_assignments ara WHERE ara.role_group_id=approval_requests.approver_ref AND ara.user_id=$1 AND (ara.expires_at IS NULL OR ara.expires_at>now()) AND public.admin_assignment_active(ara.eligible,ara.activated_until)))) ORDER BY created_at"),&[(&uid,Type::INT8)]).await?;
    let mine=exec.read_scoped(&auth,&format!("SELECT {COLS} FROM approval_requests WHERE requester_user_id=$1 ORDER BY created_at DESC"),&[(&uid,Type::INT8)]).await?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Lists {
        my_requests: Vec<Item>,
        pending_for_me: Vec<Item>,
    }
    serde_json::to_string(&Lists {
        my_requests: mine.iter().map(item).collect::<Result<_, _>>()?,
        pending_for_me: pending.iter().map(item).collect::<Result<_, _>>()?,
    })
    .map(|s| go_json(&s) + "\n")
    .map_err(|_| invalid())
}
/// encoding/json's HTML escaping, also applied to RawMessage fields.
pub fn go_json(s: &str) -> String {
    let (mut compact, mut quoted, mut escaped) = (String::with_capacity(s.len()), false, false);
    for ch in s.chars() {
        if quoted {
            compact.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
            compact.push(ch);
        } else if !ch.is_ascii_whitespace() {
            compact.push(ch);
        }
    }
    compact
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// Requester-bound cancellation. The existing reducer commits its pending
/// guard, request status, core audit and approval_decided notification together.
pub async fn cancel_request(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    request: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(request.to_be_bytes()).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "F10",
            command: "approval_request_cancel",
        },
        &envelope,
        &auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        "SELECT approval_request_cancel($4,$2) WHERE $1::bigint>0 AND $3::text<>''",
        &[(&request, Type::INT8)],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid)
        },
    )
    .await
}

/// Application fence mirrors approval_requests' user/active-role/admin RLS
/// predicate even when a request pool is configured with an owner credential.
pub async fn visible_consumer(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    request: i64,
) -> Result<Option<String>, StatementFailure> {
    let user = actor.user_id();
    let rows=exec.read_scoped(&scope(actor),"SELECT consumer_type FROM approval_requests r WHERE r.id=$1 AND (r.requester_user_id=$2 OR (r.approver_kind='user' AND r.approver_ref=$2) OR (r.approver_kind='role_group' AND EXISTS(SELECT 1 FROM public.admin_role_assignments a WHERE a.user_id=$2 AND a.role_group_id=r.approver_ref AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until))) OR EXISTS(SELECT 1 FROM public.admin_role_assignments a JOIN public.admin_role_groups g ON g.id=a.role_group_id WHERE a.user_id=$2 AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until) AND (g.permissions && ARRAY['approvals.view','approvals.manage']::text[])))",&[(&request,Type::INT8),(&user,Type::INT8)]).await?;
    Ok(rows.first().map(|r| r.get(0)))
}

pub async fn decide_consumer(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    consumer: &str,
    request: i64,
    decision: &str,
    comment: Option<&str>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let (command,sql)=match consumer {
     "hr.leave"|"hr.expense"=>("hr_approval_decide","SELECT hr_approval_decide($4,$2,$5,$6) WHERE $1::bigint>0 AND $3::text<>''"),
     "rbac.jit_activation"=>("rbac_approval_decide","SELECT rbac_approval_decide($4,$2,$5,$6) WHERE $1::bigint>0 AND $3::text<>''"),
     "drive.export"=>("drive_export_approval_decide","SELECT drive_export_approval_decide($4,$2,$5,$6) WHERE $1::bigint>0 AND $3::text<>''"),
     "drive.share"=>("drive_share_approval_decide","SELECT drive_share_approval_decide($4,$2,$5,$6) WHERE $1::bigint>0 AND $3::text<>''"),
     "mail.external_send"=>("mail_external_approval_decide","SELECT mail_external_approval_decide($4,$2,$5,$6) WHERE $1::bigint>0 AND $3::text<>''"),
     "mail.group_moderation"=>("group_moderation_approval_decide","SELECT group_moderation_approval_decide($4,$2,$5,$6) WHERE $1::bigint>0 AND $3::text<>''"),
     _=>return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(invalid())),
    };
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(format!("{request}:{decision}:{comment:?}")).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "F10",
            command,
        },
        &envelope,
        auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        sql,
        &[
            (&request, Type::INT8),
            (&decision, Type::TEXT),
            (&comment, Type::TEXT),
        ],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid)
        },
    )
    .await
}

/// Live request-time projection, never authority from signed permission claims.
pub struct AdminAuthority {
    manage: bool,
    view: bool,
    domain_scope: Option<i64>,
}
impl AdminAuthority {
    pub fn can_manage(&self) -> bool {
        self.manage
    }
    pub fn can_view(&self) -> bool {
        self.view
    }
    pub fn domain_scope(&self) -> Option<i64> {
        self.domain_scope
    }
}
pub async fn admin_authority(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<AdminAuthority, StatementFailure> {
    if !actor.signed_admin() {
        return Ok(AdminAuthority {
            manage: false,
            view: false,
            domain_scope: None,
        });
    }
    let user = actor.user_id();
    let rows=exec.read("SELECT COALESCE(bool_or('approvals.manage'=ANY(g.permissions)),false), COALESCE(bool_or(g.permissions && ARRAY['approvals.view','approvals.manage']::text[]),false), MIN(COALESCE(a.domain_override,g.domain_scope)) FROM public.admin_role_assignments a JOIN public.admin_role_groups g ON g.id=a.role_group_id WHERE a.user_id=$1 AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until)",&[(&user,Type::INT8)]).await?;
    let row = rows.first().ok_or_else(invalid)?;
    Ok(AdminAuthority {
        manage: row.get(0),
        view: row.get(1),
        domain_scope: row.get(2),
    })
}
pub fn valid_consumer(value: &str) -> bool {
    matches!(
        value,
        "rbac.jit_activation"
            | "mail.external_send"
            | "mail.group_moderation"
            | "hr.leave"
            | "hr.expense"
            | "drive.export"
            | "drive.share"
    )
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Policy {
    id: i64,
    consumer_type: String,
    name: String,
    enabled: bool,
    priority: i32,
    conditions: Box<serde_json::value::RawValue>,
    requires_approval: bool,
    approver_spec: Box<serde_json::value::RawValue>,
    created_at: String,
    updated_at: String,
}
pub async fn policies(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    consumer: &str,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let rows=exec.read_scoped(&scope(actor),"SELECT id,consumer_type,name,enabled,priority,conditions::text,requires_approval,approver_spec::text,created_at::text,updated_at::text FROM approval_policies WHERE ($1::text='' OR consumer_type=$1) AND EXISTS(SELECT 1 FROM public.admin_role_assignments a JOIN public.admin_role_groups g ON g.id=a.role_group_id WHERE a.user_id=$2 AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until) AND g.permissions && ARRAY['approvals.view','approvals.manage']::text[]) ORDER BY consumer_type,priority",&[(&consumer,Type::TEXT),(&user,Type::INT8)]).await?;
    let mut policies = vec![];
    for r in rows {
        policies.push(Policy {
            id: r.get(0),
            consumer_type: r.get(1),
            name: r.get(2),
            enabled: r.get(3),
            priority: r.get(4),
            conditions: serde_json::value::RawValue::from_string(r.get(5))
                .map_err(|_| invalid())?,
            requires_approval: r.get(6),
            approver_spec: serde_json::value::RawValue::from_string(r.get(7))
                .map_err(|_| invalid())?,
            created_at: r.get(8),
            updated_at: r.get(9),
        });
    }
    serde_json::to_string(&policies)
        .map(|s| go_json(&s) + "\n")
        .map_err(|_| invalid())
}

/// Go's permission middleware writes a best-effort SYSTEM audit: actor stays
/// NULL, while the verified display email is inside before_state.
pub async fn console_denied(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    path: &str,
    permission: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let before =
        serde_json::json!({"actor":actor.email(),"target":path,"missingPermission":permission})
            .to_string();
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(before.as_bytes()).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F10",command:"console.denied"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
 "SELECT audit_write(NULL,'console.denied','console',NULL,$4::text::jsonb,NULL,NULL,$5,'core') WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",&[(&before,Type::TEXT),(&path,Type::TEXT)],|rows|if rows.len()==1{Ok(())}else{Err(invalid())}).await
}

pub async fn create_policy(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    body: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(body.as_bytes()).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F10",command:"rust_approval_policy_create"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
 "SELECT rust_approval_policy_create($2,$4::text::jsonb) WHERE $1::bigint>0 AND $3::text<>''",&[(&body,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await
}

/// Preserve Go's independent, best-effort post-commit policy audit.
pub async fn audit_policy_created(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    consumer: &str,
    name: &str,
    ip: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let after = serde_json::json!({"id":id,"consumerType":consumer,"name":name}).to_string();
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(after.as_bytes()).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F10",command:"approval_policy_create_audit"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
 "SELECT audit_write($2,'approval_policy_create','approval_policy',$4,NULL,$5::text::jsonb,NULLIF($6,'')::inet,'','core') WHERE $1::bigint>0 AND $3::text<>''",&[(&id,Type::INT8),(&after,Type::TEXT),(&ip,Type::TEXT)],|rows|if rows.len()==1{Ok(())}else{Err(invalid())}).await
}

/// A static canonical policy command, with no caller-controlled SQL identifiers.
pub async fn update_policy(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    body: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    policy_command(exec,actor,"rust_approval_policy_update","SELECT rust_approval_policy_update($2,$4,$5::text::jsonb) WHERE $1::bigint>0 AND $3::text<>''",id,body,operation).await
}
async fn policy_command(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    command: &'static str,
    sql: &str,
    id: i64,
    body: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(format!("{id}:{body}")).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "F10",
            command,
        },
        &envelope,
        &auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        sql,
        &[(&id, Type::INT8), (&body, Type::TEXT)],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid)
        },
    )
    .await
}
pub async fn audit_policy_change(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    action: &str,
    id: Option<i64>,
    after: Option<&str>,
    ip: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(format!("{action}:{id:?}:{after:?}")).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F10",command:"approval_policy_audit"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
    "SELECT audit_write($2,$4,'approval_policy',$5,NULL,$6::text::jsonb,NULLIF($7,'')::inet,'','core') WHERE $1::bigint>0 AND $3::text<>''",&[(&action,Type::TEXT),(&id,Type::INT8),(&after,Type::TEXT),(&ip,Type::TEXT)],|rows|if rows.len()==1{Ok(())}else{Err(invalid())}).await
}

pub async fn delete_policy(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    policy_command(exec,actor,"rust_approval_policy_delete","SELECT rust_approval_policy_delete($2,$4) WHERE $1::bigint>0 AND $3::text<>'' AND $5::text=''",id,"",operation).await
}

pub async fn reorder_policies(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    body: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    policy_command(exec,actor,"rust_approval_policy_reorder","SELECT rust_approval_policy_reorder($2,$5::text::jsonb) WHERE $1::bigint>0 AND $3::text<>'' AND $4::bigint=0",0,body,operation).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditItem {
    id: i64,
    consumer_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    requester_user_id: Option<i64>,
    subject: String,
    status: String,
    approver_kind: String,
    approver_ref: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    decided_by_user_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decided_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision_comment: Option<String>,
    created_at: String,
    expires_at: String,
}
pub async fn audit_requests(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    domain: Option<i64>,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let domain = domain.unwrap_or(0);
    let rows=exec.read_scoped(&scope(actor),"SELECT id,consumer_type,requester_user_id,subject,status,approver_kind,approver_ref,decided_by_user_id,decided_at::text,decision_comment,created_at::text,expires_at::text FROM approval_requests WHERE ($2::bigint<=0 OR domain_id=$2) AND EXISTS(SELECT 1 FROM public.admin_role_assignments a JOIN public.admin_role_groups g ON g.id=a.role_group_id WHERE a.user_id=$1 AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until) AND g.permissions && ARRAY['approvals.view','approvals.manage']::text[]) ORDER BY created_at DESC LIMIT $3 OFFSET $4",&[(&user,Type::INT8),(&domain,Type::INT8),(&limit,Type::INT8),(&offset,Type::INT8)]).await?;
    let items = rows
        .iter()
        .map(|r| AuditItem {
            id: r.get(0),
            consumer_type: r.get(1),
            requester_user_id: r.get(2),
            subject: r.get(3),
            status: r.get(4),
            approver_kind: r.get(5),
            approver_ref: r.get(6),
            decided_by_user_id: r.get(7),
            decided_at: r.get(8),
            decision_comment: r.get(9),
            created_at: r.get(10),
            expires_at: r.get(11),
        })
        .collect::<Vec<_>>();
    serde_json::to_string(&items)
        .map(|s| go_json(&s) + "\n")
        .map_err(|_| invalid())
}

pub async fn hr_enabled(exec: &ScopedExecutor, kind: &str) -> Result<bool, StatementFailure> {
    let key = match kind {
        "hr.leave" => "approval.hr_leave",
        "hr.expense" => "approval.hr_expense",
        _ => return Ok(false),
    };
    let rows = exec
        .read(
            "SELECT enabled FROM feature_toggles WHERE key=$1",
            &[(&key, Type::TEXT)],
        )
        .await?;
    Ok(rows.first().is_some_and(|r| r.get(0)))
}
pub async fn submit_hr(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    kind: &str,
    form: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<Option<i64>, StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(format!("{kind}:{form}")).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "F10",
            command: "hr_request_create",
        },
        &envelope,
        &auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        "SELECT hr_request_create($2,$4,$5::text::jsonb) WHERE $1::bigint>0 AND $3::text<>''",
        &[(&kind, Type::TEXT), (&form, Type::TEXT)],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid)
        },
    )
    .await
}

pub mod email;
pub mod notify;
/// Go's Drive decision parameters; request defaults are resolved inside the SQL statement.
pub struct DriveDecision<'a> {
    pub capabilities: Option<&'a [String]>,
    pub propagation: Option<&'a str>,
    pub expires_at: Option<&'a str>,
    pub max_uses: Option<i64>,
    pub expected_epoch: Option<i64>,
}
pub async fn decide_drive_access(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    request: i64,
    decision: &str,
    comment: Option<&str>,
    body: DriveDecision<'_>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(
            Sha256::digest(format!(
                "{request}:{decision}:{comment:?}:{:?}:{:?}:{:?}:{:?}:{:?}",
                body.capabilities,
                body.propagation,
                body.expires_at,
                body.max_uses,
                body.expected_epoch
            ))
            .into(),
        ),
        command: (),
    };
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F10",command:"drive_access_approval_decide"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
 "SELECT (drive_access_approval_decide($4,$2,$5,$6,COALESCE($7::text[],d.requested_capabilities),COALESCE($8,d.requested_propagation),COALESCE($9::text::timestamptz,d.requested_expires_at),COALESCE($10::bigint::integer,d.requested_max_uses),$11))->>'status' FROM drive_access_request_details d WHERE d.request_id=$4 AND EXISTS(SELECT 1 FROM approval_requests r WHERE r.id=d.request_id AND (r.requester_user_id=$2 OR (r.approver_kind='user' AND r.approver_ref=$2) OR (r.approver_kind='role_group' AND EXISTS(SELECT 1 FROM public.admin_role_assignments a WHERE a.user_id=$2 AND a.role_group_id=r.approver_ref AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until))) OR EXISTS(SELECT 1 FROM public.admin_role_assignments a JOIN public.admin_role_groups g ON g.id=a.role_group_id WHERE a.user_id=$2 AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until) AND g.permissions && ARRAY['approvals.view','approvals.manage']::text[]))) AND $1::bigint>0 AND $3::text<>''",
 &[(&request,Type::INT8),(&decision,Type::TEXT),(&comment,Type::TEXT),(&body.capabilities,Type::TEXT_ARRAY),(&body.propagation,Type::TEXT),(&body.expires_at,Type::TEXT),(&body.max_uses,Type::INT8),(&body.expected_epoch,Type::INT8)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await
}
