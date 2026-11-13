//! Admin identity (F01) slice `roles`: role groups, memberships, the permission
//! catalog and a user's effective permissions.
//!
//! Reads are `SELECT`s under the verified actor. Role create, update, delete,
//! assign and remove each call one reducer mirroring Go's whole transaction
//! (`rust_admin_role_*`); the reducer answers `{status,detail,id}` and every
//! status other than the success one rolls the command back, so a problem
//! leaves neither data nor a receipt. Bulk enqueue is Go's single `INSERT`.
use super::{count as count_one, deadline, done, envelope, invalid, s, scope, Authority};
use serde_json::json;
use setjoin_authz::AuthContext;
use setjoin_pg::{
    CommandOutcome, ReceiptCommand, Rejection, Row, ScopedExecutor, StatementFailure, Type,
};

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

impl Authority {
    /// Go's `claims.HasPermission` over the live permission set.
    pub fn holds(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }
    /// The permissions the principal holds right now.
    pub fn permissions(&self) -> &[String] {
        &self.permissions
    }
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

/// A problem decided before the database (Go's validation order) or by it.
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
const ROLE_COLUMNS: &str = "rg.id, rg.name, rg.description, rg.permissions, rg.domain_scope, rg.is_builtin, \
    COALESCE((SELECT COUNT(*) FROM admin_role_assignments WHERE role_group_id = rg.id), 0)::bigint, \
    rg.created_at::TEXT, rg.updated_at::TEXT";

/// `GET /admin/roles`; a row that fails to scan is skipped, as Go does.
pub async fn roles(exec: &ScopedExecutor, domain_scope: i64) -> Result<String, StatementFailure> {
    let sql = format!(
        "SELECT {ROLE_COLUMNS} FROM admin_role_groups rg WHERE ($1::bigint <= 0 OR rg.domain_scope = $1::bigint) \
         ORDER BY rg.is_builtin DESC, rg.name ASC"
    );
    let rows = exec.read(&sql, &[(&domain_scope, Type::INT8)]).await?;
    let out: Vec<String> = rows
        .iter()
        .filter_map(role_row)
        .map(|r| role_json(&r))
        .collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/roles/{id}`; `None` is Go's 404 (missing or out of scope).
pub async fn role(
    exec: &ScopedExecutor,
    actor: i64,
    domain_scope: i64,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let sql = format!(
        "SELECT {ROLE_COLUMNS} FROM admin_role_groups rg WHERE rg.id = $1 AND ($2::bigint <= 0 OR rg.domain_scope = $2::bigint)"
    );
    let rows = exec
        .read(&sql, &[(&id, Type::INT8), (&domain_scope, Type::INT8)])
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let ro = role_row(row).ok_or_else(invalid)?;
    let members = exec
        .read(
            "SELECT ra.user_id, u.email, u.display_name, ra.domain_override, ra.granted_by, ra.granted_at::TEXT, \
             ra.expires_at::TEXT, \
             CASE WHEN act.is_super THEN true \
                  ELSE ea.perms <@ act.perms \
                       AND NOT (cardinality(ea.perms) > 0 AND act.scope IS NOT NULL AND ea.scope IS NULL) \
                       AND (cardinality(act.perms) = 0 OR admin_can_reach($2::bigint, ra.user_id)) \
             END AS manageable, \
             ra.scope_type, ra.scope_id, ss.name \
             FROM admin_role_assignments ra \
             JOIN users u ON u.id = ra.user_id \
             CROSS JOIN LATERAL admin_effective_authority(ra.user_id) AS ea \
             CROSS JOIN (SELECT EXISTS(SELECT 1 FROM admin_role_assignments \
                          WHERE user_id=$2::bigint AND role_group_id=1 \
                          AND (expires_at IS NULL OR expires_at > now())) AS is_super, a0.perms, a0.scope \
                         FROM admin_effective_authority($2::bigint) AS a0) act \
             LEFT JOIN admin_scope_sets ss ON ra.scope_type='set' AND ss.id = ra.scope_id \
             WHERE ra.role_group_id = $1 \
             AND ($3::bigint <= 0 OR EXISTS (SELECT 1 FROM admin_role_groups rg \
                                 WHERE rg.id = ra.role_group_id AND rg.domain_scope = $3::bigint)) \
             ORDER BY u.email",
            &[
                (&id, Type::INT8),
                (&actor, Type::INT8),
                (&domain_scope, Type::INT8),
            ],
        )
        .await?;
    // Go skips a member that fails to scan (a NULL granted_by, for one).
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
pub async fn catalog(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT permission_key, category, description, is_sensitive FROM admin_permissions \
             ORDER BY category COLLATE \"C\", permission_key COLLATE \"C\"",
            &[],
        )
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
    exec: &ScopedExecutor,
    domain_scope: i64,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    if domain_scope > 0 {
        let rows = exec
            .read(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND domain_id = $2)",
                &[(&id, Type::INT8), (&domain_scope, Type::INT8)],
            )
            .await;
        // Go answers 404 for a failed scope query as well.
        let inside = rows
            .ok()
            .and_then(|r| r.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
            .unwrap_or(false);
        if !inside {
            return Ok(None);
        }
    }
    // `permissions.ResolveAuthority`: union in row order, narrowest scope.
    let resolved = exec
        .read(
            "SELECT rg.permissions, COALESCE(ra.domain_override, rg.domain_scope) AS effective_scope \
             FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id = ra.role_group_id \
             WHERE ra.user_id = $1 AND (ra.expires_at IS NULL OR ra.expires_at > now()) \
             AND admin_assignment_active(ra.eligible, ra.activated_until)",
            &[(&id, Type::INT8)],
        )
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
    let rows = exec
        .read(
            "SELECT rg.id, rg.name, rg.permissions, COALESCE(ra.domain_override, rg.domain_scope) \
             FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id = ra.role_group_id \
             WHERE ra.user_id = $1 AND (ra.expires_at IS NULL OR ra.expires_at > now()) \
             ORDER BY rg.name",
            &[(&id, Type::INT8)],
        )
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

/// `SELECT permissions FROM admin_role_groups`: the bulk routes' Rule A input.
pub async fn role_permissions(
    exec: &ScopedExecutor,
    id: i64,
) -> Result<Option<Vec<String>>, StatementFailure> {
    let rows = exec
        .read(
            "SELECT permissions FROM admin_role_groups WHERE id = $1",
            &[(&id, Type::INT8)],
        )
        .await?;
    match rows.first() {
        None => Ok(None),
        Some(r) => Ok(Some(r.try_get(0).map_err(|_| invalid())?)),
    }
}

/// Go's `RequireReason`: whether `roles` is a reason-required audit area.
pub async fn reason_required(exec: &ScopedExecutor) -> bool {
    exec.read(
        "SELECT 'roles'=ANY(reason_required_areas) FROM audit_policy WHERE id=1",
        &[],
    )
    .await
    .ok()
    .and_then(|r| r.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
    .unwrap_or(false)
}

async fn audit_only(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    command: &'static str,
    sql: &str,
    params: &[setjoin_pg::Param<'_>],
    payload: &str,
    operation: [u8; 16],
) {
    let auth = scope(actor);
    let _ = setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F01",
            command,
        },
        &envelope(&auth, operation, payload),
        &auth,
        deadline(),
        sql,
        params,
        count_one,
    )
    .await;
}

/// The durable `sensitive_action.reason_missing` row Go writes before its 400.
pub async fn missing_reason(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    operation: [u8; 16],
) {
    audit_only(
        exec,
        actor,
        "reason_missing",
        "SELECT count(*)::bigint FROM (SELECT audit_write($2,'sensitive_action.reason_missing','',NULL,NULL,NULL,NULLIF($4::text,'')::inet,'roles.manage','core') \
         WHERE $1::bigint > 0 AND $3::text <> '') w",
        &[(&ip, Type::TEXT)],
        ip,
        operation,
    )
    .await;
}

/// Go's `mapProtectionErr` audit: autocommit, so it survives the rollback.
pub async fn protection_denied(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    target: i64,
    code: &str,
    ip: &str,
    operation: [u8; 16],
) {
    let after = json!({"code":code,"actor_id":actor.user_id(),"target_id":target}).to_string();
    audit_only(
        exec,
        actor,
        "admin_protection.denied",
        "SELECT count(*)::bigint FROM (SELECT audit_write($2,'admin_protection.denied','user',$5,NULL,$4::text::jsonb,NULLIF($6::text,'')::inet,'','core') \
         WHERE $1::bigint > 0 AND $3::text <> '') w",
        &[(&after, Type::TEXT), (&target, Type::INT8), (&ip, Type::TEXT)],
        &after,
        operation,
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    role: &NewRole<'_>,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    let permissions = role.permissions.to_vec();
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F01",
            command: "role_create",
        },
        &envelope(
            &auth,
            operation,
            &format!(
                "{}:{:?}:{:?}",
                role.name, role.permissions, role.domain_scope
            ),
        ),
        &auth,
        deadline(),
        "SELECT rust_admin_role_create($2,$4,$5,$6,$7,$8) WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&role.name, Type::TEXT),
            (&role.description, Type::TEXT),
            (&permissions, Type::TEXT_ARRAY),
            (&role.domain_scope, Type::INT8),
            (&ip, Type::TEXT),
        ],
        |rows| match rows {
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
    /// `None` when absent or empty, as Go's `len(req.Permissions) > 0`.
    pub permissions: Option<Vec<String>>,
    pub domain_scope: Option<i64>,
    pub sod_class: Option<String>,
    /// Go's body validation outcome, evaluated after the lock and scope checks.
    pub problem: Option<Problem>,
}

pub async fn update_role(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    domain_scope: i64,
    id: i64,
    patch: &RolePatch,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Reply, StatementFailure> {
    let auth = scope(actor);
    let status = patch.problem.as_ref().map_or(0i32, |p| i32::from(p.status));
    let detail = patch
        .problem
        .as_ref()
        .map(|p| p.detail.clone())
        .unwrap_or_default();
    let classes = classes_json();
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F01",
            command: "role_update",
        },
        &envelope(
            &auth,
            operation,
            &format!(
                "{id}:{domain_scope}:{:?}:{:?}:{:?}:{:?}:{:?}",
                patch.name, patch.description, patch.permissions, patch.domain_scope, patch.sod_class
            ),
        ),
        &auth,
        deadline(),
        "SELECT rust_admin_role_update($2,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::text::jsonb,$14)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&domain_scope, Type::INT8),
            (&id, Type::INT8),
            (&patch.name, Type::TEXT),
            (&patch.description, Type::TEXT),
            (&patch.permissions, Type::TEXT_ARRAY),
            (&patch.domain_scope, Type::INT8),
            (&patch.sod_class, Type::TEXT),
            (&status, Type::INT4),
            (&detail, Type::TEXT),
            (&classes, Type::TEXT),
            (&ip, Type::TEXT),
        ],
        |rows| verdict(rows, 204),
    )
    .await
}

pub async fn delete_role(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    domain_scope: i64,
    id: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Reply, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F01",
            command: "role_delete",
        },
        &envelope(&auth, operation, &format!("{id}:{domain_scope}")),
        &auth,
        deadline(),
        "SELECT rust_admin_role_delete($2,$4,$5,$6)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&domain_scope, Type::INT8),
            (&id, Type::INT8),
            (&ip, Type::TEXT),
        ],
        |rows| verdict(rows, 204),
    )
    .await
}

/// The decoded `POST /admin/roles/{id}/members` body, edge-validated.
pub struct Assignment {
    pub user: i64,
    pub domain_override: Option<i64>,
    /// UTC microsecond text, `None` when absent or empty.
    pub expires_at: Option<String>,
    pub expires_bad: bool,
    pub scope_type: Option<String>,
    pub scope_id: Option<i64>,
    pub eligible: Option<bool>,
    pub problem: Option<Problem>,
}

#[allow(clippy::too_many_arguments)]
pub async fn assign_member(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    authority: &Authority,
    role: i64,
    a: &Assignment,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Reply, StatementFailure> {
    let auth = scope(actor);
    let domain_scope = authority.domain_scope();
    let perms = authority.permissions().to_vec();
    let status = a.problem.as_ref().map_or(0i32, |p| i32::from(p.status));
    let detail = a
        .problem
        .as_ref()
        .map(|p| p.detail.clone())
        .unwrap_or_default();
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F01",
            command: "role_assign",
        },
        &envelope(
            &auth,
            operation,
            &format!(
                "{role}:{}:{domain_scope}:{:?}:{:?}:{:?}:{:?}:{:?}",
                a.user, a.domain_override, a.expires_at, a.scope_type, a.scope_id, a.eligible
            ),
        ),
        &auth,
        deadline(),
        "SELECT rust_admin_role_assign($2,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&domain_scope, Type::INT8),
            (&perms, Type::TEXT_ARRAY),
            (&role, Type::INT8),
            (&a.user, Type::INT8),
            (&a.domain_override, Type::INT8),
            (&a.expires_at, Type::TEXT),
            (&a.expires_bad, Type::BOOL),
            (&a.scope_type, Type::TEXT),
            (&a.scope_id, Type::INT8),
            (&a.eligible, Type::BOOL),
            (&status, Type::INT4),
            (&detail, Type::TEXT),
            (&ip, Type::TEXT),
        ],
        |rows| verdict(rows, 201),
    )
    .await
}

pub async fn remove_member(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    domain_scope: i64,
    role: i64,
    user: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Reply, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F01",
            command: "role_revoke",
        },
        &envelope(&auth, operation, &format!("{role}:{user}:{domain_scope}")),
        &auth,
        deadline(),
        "SELECT rust_admin_role_remove($2,$4,$5,$6,$7)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&domain_scope, Type::INT8),
            (&role, Type::INT8),
            (&user, Type::INT8),
            (&ip, Type::TEXT),
        ],
        |rows| verdict(rows, 204),
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    job: &BulkJob<'_>,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    let users = job.users.to_vec();
    let total = job.users.len() as i32;
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F01",
            command: "role_bulk_enqueue",
        },
        &envelope(
            &auth,
            operation,
            &format!(
                "{}:{}:{:?}:{:?}:{:?}:{:?}:{}",
                job.op, job.role, job.users, job.expires_at, job.scope_type, job.scope_id, job.eligible
            ),
        ),
        &auth,
        deadline(),
        "WITH inserted AS (INSERT INTO bulk_role_jobs (op, role_id, actor_id, user_ids, expires_at, total, scope_type, scope_id, eligible) \
         SELECT $4, $5, $2, $6, $7::text::timestamptz, $8, $9, $10, $11 WHERE $1::bigint > 0 AND $3::text <> '' RETURNING id) \
         SELECT id FROM inserted",
        &[
            (&job.op, Type::TEXT),
            (&job.role, Type::INT8),
            (&users, Type::INT8_ARRAY),
            (&job.expires_at, Type::TEXT),
            (&total, Type::INT4),
            (&job.scope_type, Type::TEXT),
            (&job.scope_id, Type::INT8),
            (&job.eligible, Type::BOOL),
        ],
        |rows| match rows {
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
