//! Approvals family (F10). Reducers own business authority.
#![forbid(unsafe_code)]
pub mod email;
pub mod notify;
pub mod sql;
pub use sql::SQL_CONTRACTS;

use serde::Serialize;
use setjoin_authz::{
    principals::{TxFactory, UserPrincipal},
    AuthContext,
};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{Digest, Generation, OperationId},
};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Row, StatementFailure};
use sha2::{Digest as _, Sha256};

fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}

fn envelope(user: &UserPrincipal, operation: [u8; 16], digest_bytes: &[u8]) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: AuthorityKey {
            actor: user.user(),
            scope: ResourceScope::User(user.user()),
            generation: Generation(1),
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(digest_bytes).into()),
        command: (),
    }
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
    tx_factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    let pending = tx_factory
        .run_user_read_contract(user, &sql::MY_APPROVALS_PENDING, &[&uid])
        .await?;
    let mine = tx_factory
        .run_user_read_contract(user, &sql::MY_APPROVALS_MINE, &[&uid])
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
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    request: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    let env = envelope(user, operation, &request.to_be_bytes());
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CANCEL_REQUEST,
            &[&request, &uid],
            Some(ReceiptCommand {
                family: "F10",
                command: "approval_request_cancel",
            }),
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
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    request: i64,
) -> Result<Option<String>, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &sql::VISIBLE_CONSUMER, &[&request, &uid])
        .await?;
    Ok(rows.first().map(|r| r.get(0)))
}

pub async fn decide_consumer(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    consumer: &str,
    request: i64,
    decision: &str,
    comment: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let (command, contract) = match consumer {
        "hr.leave" | "hr.expense" => ("hr_approval_decide", &sql::DECIDE_HR),
        "rbac.jit_activation" => ("rbac_approval_decide", &sql::DECIDE_RBAC),
        "drive.export" => ("drive_export_approval_decide", &sql::DECIDE_DRIVE_EXPORT),
        "drive.share" => ("drive_share_approval_decide", &sql::DECIDE_DRIVE_SHARE),
        "mail.external_send" => ("mail_external_approval_decide", &sql::DECIDE_MAIL_EXTERNAL),
        "mail.group_moderation" => (
            "group_moderation_approval_decide",
            &sql::DECIDE_GROUP_MODERATION,
        ),
        _ => return CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(invalid())),
    };
    let uid = user.user().get();
    let digest = format!("{request}:{decision}:{comment:?}");
    let env = envelope(user, operation, digest.as_bytes());
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            contract,
            &[&request, &uid, &decision, &comment],
            Some(ReceiptCommand {
                family: "F10",
                command,
            }),
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
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    actor: &AuthContext,
) -> Result<AdminAuthority, StatementFailure> {
    if !actor.signed_admin() {
        return Ok(signed_admin_authority(
            actor.signed_permissions(),
            actor.signed_domain_scope(),
        ));
    }
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &sql::ADMIN_AUTHORITY, &[&uid])
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
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    consumer: &str,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &sql::POLICIES_LIST, &[&consumer, &uid])
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
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    email: &str,
    path: &str,
    permission: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let before =
        serde_json::json!({"actor":email,"target":path,"missingPermission":permission}).to_string();
    let env = envelope(user, operation, before.as_bytes());
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CONSOLE_DENIED,
            &[&before, &path],
            Some(ReceiptCommand {
                family: "F10",
                command: "console.denied",
            }),
            |rows| {
                if rows.len() == 1 {
                    Ok(())
                } else {
                    Err(invalid())
                }
            },
        )
        .await
}

pub async fn create_policy(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    body: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let uid = user.user().get();
    let env = envelope(user, operation, body.as_bytes());
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::POLICY_CREATE,
            &[&uid, &body],
            Some(ReceiptCommand {
                family: "F10",
                command: "rust_approval_policy_create",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

/// Preserve Go's independent, best-effort post-commit policy audit.
pub async fn audit_policy_created(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    consumer: &str,
    name: &str,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    let after = serde_json::json!({"id":id,"consumerType":consumer,"name":name}).to_string();
    let env = envelope(user, operation, after.as_bytes());
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::AUDIT_POLICY_CREATED,
            &[&uid, &id, &after, &ip],
            Some(ReceiptCommand {
                family: "F10",
                command: "approval_policy_create_audit",
            }),
            |rows| {
                if rows.len() == 1 {
                    Ok(())
                } else {
                    Err(invalid())
                }
            },
        )
        .await
}

/// A static canonical policy command, with no caller-controlled SQL identifiers.
pub async fn update_policy(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    body: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let uid = user.user().get();
    let digest = format!("{id}:{body}");
    let env = envelope(user, operation, digest.as_bytes());
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::POLICY_UPDATE,
            &[&uid, &id, &body],
            Some(ReceiptCommand {
                family: "F10",
                command: "rust_approval_policy_update",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

pub async fn audit_policy_change(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    action: &str,
    id: Option<i64>,
    after: Option<&str>,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    let digest = format!("{action}:{id:?}:{after:?}");
    let env = envelope(user, operation, digest.as_bytes());
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::AUDIT_POLICY_CHANGE,
            &[&uid, &action, &id, &after, &ip],
            Some(ReceiptCommand {
                family: "F10",
                command: "approval_policy_audit",
            }),
            |rows| {
                if rows.len() == 1 {
                    Ok(())
                } else {
                    Err(invalid())
                }
            },
        )
        .await
}

pub async fn delete_policy(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let uid = user.user().get();
    let env = envelope(user, operation, &id.to_be_bytes());
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::POLICY_DELETE,
            &[&uid, &id],
            Some(ReceiptCommand {
                family: "F10",
                command: "rust_approval_policy_delete",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

pub async fn reorder_policies(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    body: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let uid = user.user().get();
    let env = envelope(user, operation, body.as_bytes());
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::POLICY_REORDER,
            &[&uid, &body],
            Some(ReceiptCommand {
                family: "F10",
                command: "rust_approval_policy_reorder",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
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
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    domain: Option<i64>,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    let domain = domain.unwrap_or(0);
    let rows = tx_factory
        .run_user_read_contract(
            user,
            &sql::AUDIT_REQUESTS,
            &[&uid, &domain, &limit, &offset],
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

pub async fn hr_enabled(tx_factory: &TxFactory, kind: &str) -> Result<bool, StatementFailure> {
    let key = match kind {
        "hr.leave" => "approval.hr_leave",
        "hr.expense" => "approval.hr_expense",
        _ => return Ok(false),
    };
    let rows = tx_factory
        .run_public_read_contract(&sql::HR_ENABLED, &[&key])
        .await?;
    Ok(rows.first().is_some_and(|r| r.get(0)))
}

pub async fn submit_hr(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    kind: &str,
    form: &str,
    operation: [u8; 16],
) -> CommandOutcome<Option<i64>, StatementFailure> {
    let uid = user.user().get();
    let digest = format!("{kind}:{form}");
    let env = envelope(user, operation, digest.as_bytes());
    tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::SUBMIT_HR,
            &[&uid, &kind, &form],
            Some(ReceiptCommand {
                family: "F10",
                command: "hr_request_create",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

/// Go's Drive decision parameters; request defaults are resolved inside the SQL statement.
pub struct DriveDecision<'a> {
    pub capabilities: Option<&'a [String]>,
    pub propagation: Option<&'a str>,
    pub expires_at: Option<&'a str>,
    pub max_uses: Option<i64>,
    pub expected_epoch: Option<i64>,
}

pub async fn decide_drive_access(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    request: i64,
    decision: &str,
    comment: Option<&str>,
    body: DriveDecision<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    let digest = format!(
        "{request}:{decision}:{comment:?}:{:?}:{:?}:{:?}:{:?}:{:?}",
        body.capabilities, body.propagation, body.expires_at, body.max_uses, body.expected_epoch
    );
    let env = envelope(user, operation, digest.as_bytes());
    tx_factory
        .run_user_write(user, &env, deadline(), async |tx| {
            let rows = tx
                .query_contract(
                    &sql::DECIDE_DRIVE_ACCESS,
                    &[
                        &request,
                        &uid,
                        &decision,
                        &comment,
                        &body.capabilities,
                        &body.propagation,
                        &body.expires_at,
                        &body.max_uses,
                        &body.expected_epoch,
                    ],
                )
                .await?;
            let status: String = rows
                .first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid)?;
            tx.record_receipt(
                OperationId(operation),
                ReceiptCommand {
                    family: "F10",
                    command: "drive_access_approval_decide",
                },
            )
            .await?;
            Ok(status)
        })
        .await
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
