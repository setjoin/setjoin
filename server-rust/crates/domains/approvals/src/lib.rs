//! Approvals family (F10). Reducers own business authority.
#![forbid(unsafe_code)]
pub mod sql;
pub use sql::SQL_CONTRACTS;
use serde::Serialize;
use setjoin_authz::AuthContext;
use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
use setjoin_pg::{MailboxAuthContext, Row, ScopedExecutor, StatementFailure, Type};

pub fn scope(actor: &AuthContext) -> MailboxAuthContext {
    actor.database_scope()
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
/// Same-statement requester/active approver fence remains effective on owner pools.
pub async fn my_approvals(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let auth = scope(actor);
    let uid = actor.user_id();
    let pending = exec
        .read_scoped(&auth, sql::MY_APPROVALS_PENDING.sql, &[(&uid, Type::INT8)])
        .await?;
    let mine = exec
        .read_scoped(&auth, sql::MY_APPROVALS_MINE.sql, &[(&uid, Type::INT8)])
        .await?;
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
        sql::CANCEL_REQUEST.sql,
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
    let rows = exec
        .read_scoped(
            &scope(actor),
            sql::VISIBLE_CONSUMER.sql,
            &[(&request, Type::INT8), (&user, Type::INT8)],
        )
        .await?;
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
    let (command, sql) = match consumer {
        "hr.leave" | "hr.expense" => ("hr_approval_decide", sql::DECIDE_HR.sql),
        "rbac.jit_activation" => ("rbac_approval_decide", sql::DECIDE_RBAC.sql),
        "drive.export" => ("drive_export_approval_decide", sql::DECIDE_DRIVE_EXPORT.sql),
        "drive.share" => ("drive_share_approval_decide", sql::DECIDE_DRIVE_SHARE.sql),
        "mail.external_send" => ("mail_external_approval_decide", sql::DECIDE_MAIL_EXTERNAL.sql),
        "mail.group_moderation" => (
            "group_moderation_approval_decide",
            sql::DECIDE_GROUP_MODERATION.sql,
        ),
        _ => return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(invalid())),
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
fn signed_admin_authority(permissions: &[String], domain_scope: Option<i64>) -> AdminAuthority {
    let manage = permissions.iter().any(|p| p == "approvals.manage");
    let view = manage || permissions.iter().any(|p| p == "approvals.view");
    AdminAuthority {
        manage,
        view,
        domain_scope,
    }
}
pub async fn admin_authority(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<AdminAuthority, StatementFailure> {
    if !actor.signed_admin() {
        return Ok(signed_admin_authority(
            actor.signed_permissions(),
            actor.signed_domain_scope(),
        ));
    }
    let user = actor.user_id();
    let rows = exec
        .read(sql::ADMIN_AUTHORITY.sql, &[(&user, Type::INT8)])
        .await?;
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
    let rows = exec
        .read_scoped(
            &scope(actor),
            sql::POLICIES_LIST.sql,
            &[(&consumer, Type::TEXT), (&user, Type::INT8)],
        )
        .await?;
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
 sql::CONSOLE_DENIED.sql,&[(&before,Type::TEXT),(&path,Type::TEXT)],|rows|if rows.len()==1{Ok(())}else{Err(invalid())}).await
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
 sql::POLICY_CREATE.sql,&[(&body,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await
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
 sql::AUDIT_POLICY_CREATED.sql,&[(&id,Type::INT8),(&after,Type::TEXT),(&ip,Type::TEXT)],|rows|if rows.len()==1{Ok(())}else{Err(invalid())}).await
}

/// A static canonical policy command, with no caller-controlled SQL identifiers.
pub async fn update_policy(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    body: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    policy_command(exec,actor,"rust_approval_policy_update",sql::POLICY_UPDATE.sql,id,body,operation).await
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
    sql::AUDIT_POLICY_CHANGE.sql,&[(&action,Type::TEXT),(&id,Type::INT8),(&after,Type::TEXT),(&ip,Type::TEXT)],|rows|if rows.len()==1{Ok(())}else{Err(invalid())}).await
}

pub async fn delete_policy(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    policy_command(exec,actor,"rust_approval_policy_delete",sql::POLICY_DELETE.sql,id,"",operation).await
}

pub async fn reorder_policies(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    body: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<i64, StatementFailure> {
    policy_command(exec,actor,"rust_approval_policy_reorder",sql::POLICY_REORDER.sql,0,body,operation).await
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
    let rows = exec
        .read_scoped(
            &scope(actor),
            sql::AUDIT_REQUESTS.sql,
            &[
                (&user, Type::INT8),
                (&domain, Type::INT8),
                (&limit, Type::INT8),
                (&offset, Type::INT8),
            ],
        )
        .await?;
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
        .read(sql::HR_ENABLED.sql, &[(&key, Type::TEXT)])
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
        sql::SUBMIT_HR.sql,
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
 sql::DECIDE_DRIVE_ACCESS.sql,
 &[(&request,Type::INT8),(&decision,Type::TEXT),(&comment,Type::TEXT),(&body.capabilities,Type::TEXT_ARRAY),(&body.propagation,Type::TEXT),(&body.expires_at,Type::TEXT),(&body.max_uses,Type::INT8),(&body.expected_epoch,Type::INT8)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await
}

#[cfg(test)]
mod tests {
    use super::signed_admin_authority;

    #[test]
    fn non_admin_authority_reads_signed_permissions_and_domain_scope() {
        let none = signed_admin_authority(&[], None);
        assert!(!none.can_view());
        assert!(!none.can_manage());
        assert_eq!(none.domain_scope(), None);

        let unrelated = signed_admin_authority(&["users.read".into()], Some(7));
        assert!(!unrelated.can_view());
        assert!(!unrelated.can_manage());
        assert_eq!(unrelated.domain_scope(), Some(7));

        let view = signed_admin_authority(&["approvals.view".into()], Some(42));
        assert!(view.can_view());
        assert!(!view.can_manage());
        assert_eq!(view.domain_scope(), Some(42));

        let manage = signed_admin_authority(&["approvals.manage".into()], None);
        assert!(manage.can_view());
        assert!(manage.can_manage());
        assert_eq!(manage.domain_scope(), None);
    }
}
