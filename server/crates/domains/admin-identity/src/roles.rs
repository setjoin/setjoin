//! Admin identity (F01) slice `roles`: role groups, memberships, the permission
//! catalog and a user's effective permissions.
use super::{count as count_one, deadline, done, envelope, invalid, s, sql, FAMILY};
use serde_json::json;
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Rejection, Row, StatementFailure};

/// `roles.manage`: the only gate of every route in this slice.
pub const ROLES_MANAGE: [&str; 1] = ["roles.manage"];

/// Go's `permissions.AllPermissions`.
pub const ALL_PERMISSIONS: &[&str] = &[
    "users.read",
    "users.delete",
    "users.password_reset",
    "users.impersonate",
    "domains.read",
    "domains.write",
    "audit.read",
    "mam.read",
    "mam.write",
    "queue.read",
    "queue.write",
    "reports.read",
    "security.write",
    "roles.manage",
    "compliance.read",
    "compliance.write",
    "backup.read",
    "backup.write",
    "system.config",
    "system.upgrade",
    "system.recovery",
    "identity.write",
    "users.create",
    "users.suspend",
    "mail.pipeline",
    "mail.security",
    "audit.export",
    "mail.offline_policy",
    "mail.export",
    "access.policy_read",
    "access.policy_write",
    "scope_sets.manage",
    "approvals.view",
    "approvals.manage",
    "sharing.read",
    "sharing.manage",
    "drive.view",
    "drive.manage",
    "office.view",
    "office.manage",
    "apps.view",
    "apps.manage",
    "chat.compliance_view",
    "chat.compliance_manage",
    "chat.ediscovery",
    "federation.manage",
    "guests.view",
    "guests.manage",
    "directory.groups.read",
    "directory.groups.manage",
    "exchange.assessment.read",
    "exchange.assessment.run",
    "exchange.assessment.decide",
    "exchange.assessment.attest",
    "exchange.assessment.audit",
    "exchange.assessment.publish",
    "exchange.assessment.delete",
];

/// Go's `permissions.PermClasses` (等保三级 SoD classes per permission).
const PERM_CLASSES: &[(&str, &[&str])] = &[
    ("users.read", &["system", "security", "audit"]),
    ("users.create", &["system"]),
    ("users.delete", &["system"]),
    ("domains.read", &["system"]),
    ("domains.write", &["system"]),
    ("queue.read", &["system"]),
    ("queue.write", &["system"]),
    ("backup.read", &["system"]),
    ("backup.write", &["system"]),
    ("system.config", &["system"]),
    ("system.upgrade", &["system"]),
    ("mail.pipeline", &["system"]),
    ("mail.offline_policy", &["system"]),
    ("reports.read", &["system"]),
    ("users.suspend", &["security"]),
    ("users.password_reset", &["security"]),
    ("roles.manage", &["security"]),
    ("security.write", &["security"]),
    ("mail.security", &["security"]),
    ("identity.write", &["security"]),
    ("mam.write", &["security"]),
    ("compliance.write", &["security"]),
    ("compliance.read", &["security", "audit"]),
    ("scope_sets.manage", &["security"]),
    ("approvals.view", &["security"]),
    ("approvals.manage", &["security"]),
    ("sharing.read", &["security"]),
    ("sharing.manage", &["security"]),
    ("audit.read", &["audit"]),
    ("audit.export", &["audit"]),
    ("mam.read", &["audit"]),
    ("access.policy_read", &["security"]),
    ("access.policy_write", &["security"]),
    ("exchange.assessment.read", &["system", "security", "audit"]),
    ("exchange.assessment.run", &["system"]),
    ("exchange.assessment.decide", &["security"]),
    ("exchange.assessment.attest", &["audit"]),
    ("exchange.assessment.audit", &["audit"]),
    ("exchange.assessment.publish", &["security"]),
    ("exchange.assessment.delete", &["system"]),
];

fn classes_json() -> String {
    let mut map = serde_json::Map::new();
    for (permission, classes) in PERM_CLASSES.iter() {
        map.insert((*permission).into(), json!(classes));
    }
    serde_json::Value::Object(map).to_string()
}

/// Go's `ConsoleScopes` plus `ConsoleVisibilityScopes`, in declared order.
const CONSOLES: [(&str, &[&str]); 5] = [
    (
        "mail",
        &[
            "domains.read",
            "queue.read",
            "reports.read",
            "mail.pipeline",
            "mail.security",
            "exchange.assessment.read",
            "exchange.assessment.run",
            "exchange.assessment.decide",
            "exchange.assessment.attest",
            "exchange.assessment.audit",
            "exchange.assessment.publish",
            "exchange.assessment.delete",
        ],
    ),
    (
        "system",
        &[
            "system.config",
            "system.upgrade",
            "backup.read",
            "mail.offline_policy",
            "office.view",
            "office.manage",
        ],
    ),
    ("logs", &["audit.read"]),
    (
        "auth",
        &[
            "users.read",
            "identity.write",
            "access.policy_read",
            "access.policy_write",
        ],
    ),
    (
        "access",
        &[
            "roles.manage",
            "sharing.read",
            "chat.compliance_view",
            "chat.compliance_manage",
            "chat.ediscovery",
            "drive.view",
            "federation.manage",
            "system.recovery",
        ],
    ),
];

/// Go's `ConsolesForPerms`: `None` is a nil slice, which Go renders as `null`.
fn consoles(perms: &[String]) -> Option<Vec<&'static str>> {
    let out: Vec<&'static str> = CONSOLES
        .iter()
        .filter(|(_, scopes)| scopes.iter().any(|w| perms.iter().any(|p| p == w)))
        .map(|(id, _)| *id)
        .collect();
    (!out.is_empty()).then_some(out)
}

pub fn is_known(permission: &str) -> bool {
    ALL_PERMISSIONS.contains(&permission)
}

/// Go's `validate.ValidateResourceName`: the reason a name is refused.
pub fn resource_name_problem(raw: &str) -> Option<&'static str> {
    let name = raw.trim();
    if name.is_empty() {
        return Some("resource name must not be empty");
    }
    if name.len() > 128 {
        return Some("resource name exceeds 128 characters");
    }
    for byte in name.bytes() {
        if byte == b'/' || byte == b'\\' || byte == 0 {
            return Some("resource name contains forbidden character");
        }
        if byte < 0x20 || byte == 0x7f {
            return Some("resource name contains control character");
        }
    }
    if name == "." || name == ".." {
        return Some("resource name is reserved");
    }
    let base = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    if [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ]
    .contains(&base.as_str())
    {
        return Some("resource name is a reserved device name");
    }
    if name.ends_with('.') {
        return Some("resource name ends with a dot");
    }
    None
}

/// A Go problem response decided by the database transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub status: u16,
    pub detail: String,
}

/// The reducer's verdict for a committed command.
#[derive(Debug)]
pub struct Reply {
    pub id: Option<i64>,
}

/// A reducer problem carried through the executor as a rolled-back body.
pub fn problem_of(error: &Rejection<StatementFailure>) -> Option<Problem> {
    let (Rejection::Statement(e) | Rejection::Body(e)) = error else {
        return None;
    };
    if e.sqlstate.is_some() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&e.message).ok()?;
    Some(Problem {
        status: v["status"].as_u64()? as u16,
        detail: v["detail"].as_str()?.to_owned(),
    })
}

fn verdict(rows: &[Row], success: u16) -> Result<Reply, StatementFailure> {
    let text: String = rows
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| invalid())?;
    if v["status"].as_u64() == Some(u64::from(success)) {
        return Ok(Reply {
            id: v["id"].as_i64(),
        });
    }
    if v["status"].is_u64() && v["detail"].is_string() {
        return Err(StatementFailure {
            sqlstate: None,
            hint: None,
            message: text,
        });
    }
    Err(invalid())
}

fn text_array(row: &Row, index: usize) -> Option<Vec<String>> {
    row.try_get::<_, Vec<String>>(index).ok()
}
fn list(items: &[String]) -> String {
    format!(
        "[{}]",
        items.iter().map(|i| s(i)).collect::<Vec<_>>().join(",")
    )
}
fn scalar_opt(key: &str, v: Option<i64>) -> String {
    v.map(|n| format!(",\"{key}\":{n}")).unwrap_or_default()
}

struct RoleRow {
    id: i64,
    name: String,
    description: String,
    permissions: Vec<String>,
    scope: Option<i64>,
    builtin: bool,
    members: i64,
    created: String,
    updated: String,
}
fn role_row(row: &Row) -> Option<RoleRow> {
    Some(RoleRow {
        id: row.try_get(0).ok()?,
        name: row.try_get(1).ok()?,
        description: row.try_get(2).ok()?,
        permissions: text_array(row, 3)?,
        scope: row.try_get::<_, Option<i64>>(4).ok()?,
        builtin: row.try_get(5).ok()?,
        members: row.try_get(6).ok()?,
        created: row.try_get(7).ok()?,
        updated: row.try_get(8).ok()?,
    })
}
fn role_json(r: &RoleRow) -> String {
    format!(
        "{{\"id\":{},\"name\":{},\"description\":{},\"permissions\":{}{},\"isBuiltin\":{},\"memberCount\":{},\"createdAt\":{},\"updatedAt\":{}}}",
        r.id,
        s(&r.name),
        s(&r.description),
        list(&r.permissions),
        scalar_opt("domainScope", r.scope),
        r.builtin,
        r.members,
        s(&r.created),
        s(&r.updated)
    )
}

/// `GET /admin/roles`; a row that fails to scan is skipped, as Go does.
pub async fn roles(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::ROLES_LIST, &[&domain_scope])
        .await?;
    let out: Vec<String> = rows
        .iter()
        .filter_map(role_row)
        .map(|r| role_json(&r))
        .collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/roles/{id}`; `None` is Go's 404 (missing or out of scope).
pub async fn role(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    actor: i64,
    domain_scope: i64,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::ROLE_GET, &[&id, &domain_scope])
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let ro = role_row(row).ok_or_else(invalid)?;
    let members = factory
        .run_admin_read_contract(admin, &sql::ROLE_MEMBERS, &[&id, &actor, &domain_scope])
        .await?;
    let items: Vec<String> = members
        .iter()
        .filter_map(|r| {
            let user: i64 = r.try_get(0).ok()?;
            let email: String = r.try_get(1).ok()?;
            let name: String = r.try_get(2).ok()?;
            let over: Option<i64> = r.try_get(3).ok()?;
            let by: i64 = r.try_get(4).ok()?;
            let at: String = r.try_get(5).ok()?;
            let expires: Option<String> = r.try_get(6).ok()?;
            let manageable: bool = r.try_get(7).ok()?;
            let scope_type: Option<String> = r.try_get(8).ok()?;
            let scope_id: Option<i64> = r.try_get(9).ok()?;
            let set_name: Option<String> = r.try_get(10).ok()?;
            Some(format!(
                "{{\"userId\":{user},\"userEmail\":{},\"displayName\":{}{},\"grantedBy\":{by},\"grantedAt\":{}{},\"manageable\":{manageable}{}{}{}}}",
                s(&email),
                s(&name),
                scalar_opt("domainOverride", over),
                s(&at),
                expires
                    .map(|e| format!(",\"expiresAt\":{}", s(&e)))
                    .unwrap_or_default(),
                scope_type
                    .map(|t| format!(",\"scopeType\":{}", s(&t)))
                    .unwrap_or_default(),
                scalar_opt("scopeId", scope_id),
                set_name
                    .map(|n| format!(",\"setName\":{}", s(&n)))
                    .unwrap_or_default(),
            ))
        })
        .collect();
    Ok(Some(done(format!(
        "{{\"members\":[{}],\"role\":{}}}",
        items.join(","),
        role_json(&ro)
    ))))
}

/// `GET /admin/permissions`: every catalog row, "C" collation order.
pub async fn catalog(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::PERMISSIONS_CATALOG, &[])
        .await?;
    let out: Vec<String> = rows
        .iter()
        .filter_map(|r| {
            Some(format!(
                "{{\"key\":{},\"category\":{},\"description\":{},\"isSensitive\":{}}}",
                s(&r.try_get::<_, String>(0).ok()?),
                s(&r.try_get::<_, String>(1).ok()?),
                s(&r.try_get::<_, String>(2).ok()?),
                r.try_get::<_, bool>(3).ok()?
            ))
        })
        .collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/users/{id}/effective-permissions`; `None` is Go's 404 for a
/// target outside a domain-scoped admin's domain.
pub async fn effective_permissions(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    if domain_scope > 0 {
        let rows = factory
            .run_admin_read_contract(admin, &sql::USER_IN_DOMAIN, &[&id, &domain_scope])
            .await;
        let inside = rows
            .ok()
            .and_then(|r| r.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
            .unwrap_or(false);
        if !inside {
            return Ok(None);
        }
    }
    let resolved = factory
        .run_admin_read_contract(admin, &sql::EFFECTIVE_AUTHORITY_ROWS, &[&id])
        .await?;
    let mut perms: Vec<String> = Vec::new();
    let mut narrowest: Option<i64> = None;
    for row in &resolved {
        for p in row.try_get::<_, Vec<String>>(0).map_err(|_| invalid())? {
            if !perms.contains(&p) {
                perms.push(p);
            }
        }
        if let Some(sc) = row.try_get::<_, Option<i64>>(1).map_err(|_| invalid())? {
            narrowest = Some(narrowest.map_or(sc, |n| n.min(sc)));
        }
    }
    let rows = factory
        .run_admin_read_contract(admin, &sql::EFFECTIVE_SOURCES, &[&id])
        .await?;
    let sources: Vec<String> = rows
        .iter()
        .filter_map(|r| {
            Some(format!(
                "{{\"roleGroupId\":{},\"roleName\":{},\"permissions\":{}{}}}",
                r.try_get::<_, i64>(0).ok()?,
                s(&r.try_get::<_, String>(1).ok()?),
                list(&text_array(r, 2)?),
                scalar_opt("effectiveScope", r.try_get::<_, Option<i64>>(3).ok()?)
            ))
        })
        .collect();
    let consoles = match consoles(&perms) {
        Some(ids) => format!(
            "[{}]",
            ids.iter().map(|c| s(c)).collect::<Vec<_>>().join(",")
        ),
        None => "null".into(),
    };
    Ok(Some(done(format!(
        "{{\"permissions\":{}{},\"sources\":[{}],\"consoles\":{consoles}}}",
        list(&perms),
        scalar_opt("domainScope", narrowest),
        sources.join(",")
    ))))
}

/// `SELECT permissions, domain_scope FROM admin_role_groups`: the bulk routes' Rule A and domain-scope input.
pub async fn role_permissions(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
) -> Result<Option<(Vec<String>, Option<i64>)>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::ROLE_PERMISSIONS, &[&id])
        .await?;
    match rows.first() {
        None => Ok(None),
        Some(r) => Ok(Some((
            r.try_get(0).map_err(|_| invalid())?,
            r.try_get(1).map_err(|_| invalid())?,
        ))),
    }
}

/// Whether every target user ID belongs to `domain_scope` (Rule B bulk pre-enqueue gate, #165).
pub async fn users_all_in_domain(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    users: &[i64],
    domain_scope: i64,
) -> Result<bool, StatementFailure> {
    let ids = users.to_vec();
    let rows = factory
        .run_admin_read_contract(admin, &sql::USERS_ALL_IN_DOMAIN, &[&ids, &domain_scope])
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

/// Go's `RequireReason`: whether `roles` is a reason-required audit area.
pub async fn reason_required(factory: &TxFactory, admin: &AdminPermissionProof) -> bool {
    let area = "roles";
    factory
        .run_admin_read_contract(admin, &sql::REASON_REQUIRED_AREA, &[&area])
        .await
        .ok()
        .and_then(|r| r.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
        .unwrap_or(false)
}

/// The durable `sensitive_action.reason_missing` row Go writes before its 400.
pub async fn missing_reason(
    factory: &TxFactory,
    user: &UserPrincipal,
    ip: &str,
    operation: [u8; 16],
) {
    let actor = user.user().get();
    let perm = "roles.manage";
    let env = envelope(user.user(), user.generation(), operation, ip);
    let _ = factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::MISSING_REASON_AUDIT,
            &[&actor, &ip, &perm],
            Some(ReceiptCommand {
                family: FAMILY,
                command: "reason_missing",
            }),
            |rows| count_one(&rows).map(|_| ()),
        )
        .await;
}

/// Go's `mapProtectionErr` audit: autocommit, so it survives the rollback.
pub async fn protection_denied(
    factory: &TxFactory,
    user: &UserPrincipal,
    target: i64,
    code: &str,
    ip: &str,
    operation: [u8; 16],
) {
    let actor = user.user().get();
    let after = json!({"code": code, "actor_id": actor, "target_id": target}).to_string();
    let env = envelope(user.user(), user.generation(), operation, &after);
    let _ = factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::PROTECTION_DENIED_AUDIT,
            &[&actor, &target, &after, &ip],
            Some(ReceiptCommand {
                family: FAMILY,
                command: "admin_protection.denied",
            }),
            |rows| count_one(&rows).map(|_| ()),
        )
        .await;
}

pub struct NewRole<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub permissions: &'a [String],
    pub domain_scope: Option<i64>,
}

/// `POST /admin/roles` after the edge validation; the new role id.
pub async fn create_role(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    role: &NewRole<'_>,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let permissions = role.permissions.to_vec();
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!(
            "{}:{:?}:{:?}",
            role.name, role.permissions, role.domain_scope
        ),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::ROLE_CREATE,
            &[
                &role.name,
                &role.description,
                &permissions,
                &role.domain_scope,
                &ip,
            ],
            Some(ReceiptCommand {
                family: FAMILY,
                command: "role_create",
            }),
            |rows, _audited| match rows.as_slice() {
                [row] => row.try_get::<_, i64>(0).map_err(|_| invalid()),
                _ => Err(invalid()),
            },
        )
        .await
}

/// The decoded `PUT /admin/roles/{id}` patch; absent fields are `None`.
pub struct RolePatch {
    pub name: Option<String>,
    pub description: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub domain_scope: Option<i64>,
    pub sod_class: Option<String>,
    pub problem: Option<Problem>,
}

#[allow(clippy::too_many_arguments)]
pub async fn update_role(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
    id: i64,
    patch: &RolePatch,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Reply, StatementFailure> {
    let status = patch.problem.as_ref().map_or(0i32, |p| i32::from(p.status));
    let detail = patch
        .problem
        .as_ref()
        .map(|p| p.detail.clone())
        .unwrap_or_default();
    let classes = classes_json();
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!(
            "{id}:{domain_scope}:{:?}:{:?}:{:?}:{:?}:{:?}",
            patch.name, patch.description, patch.permissions, patch.domain_scope, patch.sod_class
        ),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::ROLE_UPDATE,
            &[
                &domain_scope,
                &id,
                &patch.name,
                &patch.description,
                &patch.permissions,
                &patch.domain_scope,
                &patch.sod_class,
                &status,
                &detail,
                &classes,
                &ip,
            ],
            Some(ReceiptCommand {
                family: FAMILY,
                command: "role_update",
            }),
            |rows, _audited| verdict(&rows, 204),
        )
        .await
}

pub async fn delete_role(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
    id: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Reply, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{id}:{domain_scope}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::ROLE_DELETE,
            &[&domain_scope, &id, &ip],
            Some(ReceiptCommand {
                family: FAMILY,
                command: "role_delete",
            }),
            |rows, _audited| verdict(&rows, 204),
        )
        .await
}

/// The decoded `POST /admin/roles/{id}/members` body, edge-validated.
pub struct Assignment {
    pub user: i64,
    pub domain_override: Option<i64>,
    pub expires_at: Option<String>,
    pub expires_bad: bool,
    pub scope_type: Option<String>,
    pub scope_id: Option<i64>,
    pub eligible: Option<bool>,
    pub problem: Option<Problem>,
}

#[allow(clippy::too_many_arguments)]
pub async fn assign_member(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
    permissions: &[String],
    role: i64,
    a: &Assignment,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Reply, StatementFailure> {
    let perms = permissions.to_vec();
    let status = a.problem.as_ref().map_or(0i32, |p| i32::from(p.status));
    let detail = a
        .problem
        .as_ref()
        .map(|p| p.detail.clone())
        .unwrap_or_default();
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!(
            "{role}:{}:{domain_scope}:{:?}:{:?}:{:?}:{:?}:{:?}",
            a.user, a.domain_override, a.expires_at, a.scope_type, a.scope_id, a.eligible
        ),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::ROLE_ASSIGN,
            &[
                &domain_scope,
                &perms,
                &role,
                &a.user,
                &a.domain_override,
                &a.expires_at,
                &a.expires_bad,
                &a.scope_type,
                &a.scope_id,
                &a.eligible,
                &status,
                &detail,
                &ip,
            ],
            Some(ReceiptCommand {
                family: FAMILY,
                command: "role_assign",
            }),
            |rows, _audited| verdict(&rows, 201),
        )
        .await
}

#[allow(clippy::too_many_arguments)]
pub async fn remove_member(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
    role: i64,
    user: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Reply, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{role}:{user}:{domain_scope}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::ROLE_REMOVE,
            &[&domain_scope, &role, &user, &ip],
            Some(ReceiptCommand {
                family: FAMILY,
                command: "role_revoke",
            }),
            |rows, _audited| verdict(&rows, 204),
        )
        .await
}

/// A validated bulk job, exactly as Go inserts it.
pub struct BulkJob<'a> {
    pub op: &'static str,
    pub role: i64,
    pub users: &'a [i64],
    pub expires_at: Option<String>,
    pub scope_type: Option<String>,
    pub scope_id: Option<i64>,
    pub eligible: bool,
}

/// Go's one-statement `INSERT INTO bulk_role_jobs`: the job id.
pub async fn enqueue_bulk(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    job: &BulkJob<'_>,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let actor = user.user().get();
    let users = job.users.to_vec();
    let total = job.users.len() as i32;
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!(
            "{}:{}:{:?}:{:?}:{:?}:{:?}:{}",
            job.op, job.role, job.users, job.expires_at, job.scope_type, job.scope_id, job.eligible
        ),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::ROLE_BULK_ENQUEUE,
            &[
                &job.op,
                &job.role,
                &actor,
                &users,
                &job.expires_at,
                &total,
                &job.scope_type,
                &job.scope_id,
                &job.eligible,
            ],
            Some(ReceiptCommand {
                family: FAMILY,
                command: "role_bulk_enqueue",
            }),
            |rows| match rows.as_slice() {
                [row] => row.try_get::<_, i64>(0).map_err(|_| invalid()),
                _ => Err(invalid()),
            },
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_names_follow_go_validation_order() {
        assert_eq!(
            resource_name_problem("  "),
            Some("resource name must not be empty")
        );
        assert_eq!(
            resource_name_problem(&"a".repeat(129)),
            Some("resource name exceeds 128 characters")
        );
        assert_eq!(
            resource_name_problem("a/b"),
            Some("resource name contains forbidden character")
        );
        assert_eq!(
            resource_name_problem("a\tb"),
            Some("resource name contains control character")
        );
        assert_eq!(
            resource_name_problem(".."),
            Some("resource name is reserved")
        );
        assert_eq!(
            resource_name_problem("nul.txt"),
            Some("resource name is a reserved device name")
        );
        assert_eq!(
            resource_name_problem("end."),
            Some("resource name ends with a dot")
        );
        assert_eq!(resource_name_problem(" fine name "), None);
    }

    #[test]
    fn consoles_keep_go_declared_order_and_nil_when_empty() {
        let perms = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(consoles(&perms(&[])), None);
        assert_eq!(
            consoles(&perms(&["roles.manage", "users.read", "queue.read"])),
            Some(vec!["mail", "auth", "access"])
        );
        assert_eq!(consoles(&perms(&["office.view"])), Some(vec!["system"]));
    }

    #[test]
    fn class_map_names_every_classified_permission_once() {
        let json: serde_json::Value = serde_json::from_str(&classes_json()).unwrap();
        assert_eq!(json.as_object().unwrap().len(), PERM_CLASSES.len());
        assert!(ALL_PERMISSIONS.contains(&"roles.manage") && is_known("users.read"));
        assert!(!is_known("nope.nope"));
    }
}
