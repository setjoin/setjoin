//! Admin identity (F01) slice `org-policies`: departments, email-address policies and
//! the distribution-group picker.
//!
//! Reads are `SELECT`s. Department writes call one reducer each
//! (`rust_admin_department_*`) mirroring Go's whole handler in Go's check order;
//! the reducer answers `{status,detail[,id]}` and every refusal rolls the command
//! back. The one committed non-success verdict is the department update's 500
//! (Go keeps the subtree path rewrite when the field UPDATE then fails). Policy
//! create, update, delete and apply are Go's single write statement, run under
//! the receipt; reorder is `rust_admin_eap_reorder` (Go's per-id loop). Go audits
//! none of these writes.
use super::{deadline, done, envelope, invalid, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{
    CommandOutcome, ReceiptCommand, Rejection, Row, ScopedExecutor, StatementFailure, Type,
};

pub use super::scope_sets::{problem_of, Problem};

/// Go's `ConsoleScopes[ConsoleMail]` (`requireMailPerm`), in declaration order.
pub const MAIL_CONSOLE: [&str; 5] = [
    "domains.read",
    "queue.read",
    "reports.read",
    "mail.pipeline",
    "mail.security",
];
/// `requireIdentityWrite`.
pub const IDENTITY_WRITE: [&str; 1] = ["identity.write"];

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: "F01",
        command: name,
    }
}

// ---------------------------------------------------------------------------
// Departments

struct Department {
    id: i64,
    name: String,
    parent: Option<i64>,
    path: String,
    ou: String,
    sort: i32,
    users: i64,
}

const DEPARTMENT_SELECT: &str =
    "SELECT d.id, d.name, d.parent_id, d.path, d.ldap_ou, d.sort_order, \
     (SELECT COUNT(*) FROM users WHERE department_id = d.id) FROM departments d";

/// Go skips a row that fails to scan.
fn department(row: &Row) -> Option<Department> {
    Some(Department {
        id: row.try_get(0).ok()?,
        name: row.try_get(1).ok()?,
        parent: row.try_get::<_, Option<i64>>(2).ok()?,
        path: row.try_get(3).ok()?,
        ou: row.try_get(4).ok()?,
        sort: row.try_get(5).ok()?,
        users: row.try_get(6).ok()?,
    })
}

impl Department {
    fn json(&self, children: Option<String>) -> String {
        let mut out = format!("{{\"id\":{},\"name\":{}", self.id, s(&self.name));
        if let Some(parent) = self.parent {
            out.push_str(&format!(",\"parentId\":{parent}"));
        }
        out.push_str(&format!(
            ",\"path\":{},\"ldapOu\":{},\"sortOrder\":{},\"userCount\":{}",
            s(&self.path),
            s(&self.ou),
            self.sort,
            self.users
        ));
        if let Some(children) = children {
            out.push_str(&format!(",\"children\":{children}"));
        }
        out.push('}');
        out
    }
}

/// `GET /admin/departments`.
pub async fn departments(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = exec
        .read(&format!("{DEPARTMENT_SELECT} ORDER BY d.path"), &[])
        .await?;
    let out: Vec<String> = rows
        .iter()
        .filter_map(department)
        .map(|d| d.json(None))
        .collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/departments/tree`. Go attaches children from a map walk (random
/// sibling order, and a child copied before its own children lose them); this renders
/// the deterministic reading: query order, fully nested. Leaves answer `"children":null`.
pub async fn department_tree(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            &format!("{DEPARTMENT_SELECT} ORDER BY d.sort_order, d.name"),
            &[],
        )
        .await?;
    let all: Vec<Department> = rows.iter().filter_map(department).collect();
    fn render(all: &[Department], node: &Department) -> String {
        let kids: Vec<String> = all
            .iter()
            .filter(|d| d.parent == Some(node.id) && d.id != node.id)
            .map(|d| render(all, d))
            .collect();
        node.json(Some(if kids.is_empty() {
            "null".to_owned()
        } else {
            format!("[{}]", kids.join(","))
        }))
    }
    let roots: Vec<String> = all
        .iter()
        .filter(|d| d.parent.is_none())
        .map(|d| render(&all, d))
        .collect();
    Ok(done(format!("[{}]", roots.join(","))))
}

fn verdict_json(rows: &[Row]) -> Result<serde_json::Value, StatementFailure> {
    let text: String = rows
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)?;
    serde_json::from_str(&text).map_err(|_| invalid())
}

/// A reducer verdict: `success` statuses commit; any other status rolls the
/// command back carrying Go's problem (`problem_of` reads it back).
fn verdict(rows: &[Row], success: &[u64]) -> Result<serde_json::Value, StatementFailure> {
    let v = verdict_json(rows)?;
    match v["status"].as_u64() {
        Some(status) if success.contains(&status) => Ok(v),
        Some(_) if v["detail"].is_string() => Err(StatementFailure {
            sqlstate: None,
            hint: None,
            message: v.to_string(),
        }),
        _ => Err(invalid()),
    }
}

/// `POST /admin/departments` after the edge validation; the new id.
pub async fn department_create(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    name: &str,
    parent: Option<i64>,
    ldap_ou: &str,
    grant_domain: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("department_create"),
        &envelope(
            &auth,
            operation,
            &format!("{name}:{parent:?}:{ldap_ou}:{grant_domain:?}"),
        ),
        &auth,
        deadline(),
        "SELECT rust_admin_department_create($2,$4,$5,$6,$7)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&name, Type::TEXT),
            (&parent, Type::INT8),
            (&ldap_ou, Type::TEXT),
            (&grant_domain, Type::INT8),
        ],
        |rows| {
            verdict(rows, &[200])?["id"]
                .as_i64()
                .ok_or_else(invalid)
        },
    )
    .await
}

pub struct DepartmentPatch<'a> {
    pub name: &'a str,
    pub parent: Option<i64>,
    pub ldap_ou: &'a str,
    pub sort: Option<i64>,
}

/// `PUT /admin/departments/{id}`: 204, or the committed 500 (status returned).
pub async fn department_update(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    patch: &DepartmentPatch<'_>,
    grant_domain: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<u16, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("department_update"),
        &envelope(
            &auth,
            operation,
            &format!(
                "{id}:{}:{:?}:{}:{:?}:{grant_domain:?}",
                patch.name, patch.parent, patch.ldap_ou, patch.sort
            ),
        ),
        &auth,
        deadline(),
        "SELECT rust_admin_department_update($2,$4,$5,$6,$7,$8,$9)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&id, Type::INT8),
            (&patch.name, Type::TEXT),
            (&patch.parent, Type::INT8),
            (&patch.ldap_ou, Type::TEXT),
            (&patch.sort, Type::INT8),
            (&grant_domain, Type::INT8),
        ],
        |rows| {
            verdict(rows, &[204, 500])?["status"]
                .as_u64()
                .map(|n| n as u16)
                .ok_or_else(invalid)
        },
    )
    .await
}

/// `DELETE /admin/departments/{id}`.
pub async fn department_delete(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    grant_domain: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("department_delete"),
        &envelope(&auth, operation, &format!("{id}:{grant_domain:?}")),
        &auth,
        deadline(),
        "SELECT rust_admin_department_delete($2,$4,$5)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&id, Type::INT8), (&grant_domain, Type::INT8)],
        |rows| verdict(rows, &[204]).map(|_| ()),
    )
    .await
}

/// `POST /admin/departments/assign-user` after the edge validation.
pub async fn department_assign_user(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    user: i64,
    department: Option<i64>,
    grant_domain: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("department_assign_user"),
        &envelope(
            &auth,
            operation,
            &format!("{user}:{department:?}:{grant_domain:?}"),
        ),
        &auth,
        deadline(),
        "SELECT rust_admin_department_assign_user($2,$4,$5,$6)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&user, Type::INT8),
            (&department, Type::INT8),
            (&grant_domain, Type::INT8),
        ],
        |rows| verdict(rows, &[204]).map(|_| ()),
    )
    .await
}

// ---------------------------------------------------------------------------
// Email-address policies

/// Owner-approved security fix 2026-11-05 (#510, #402 review): email-address policies are
/// organization-wide (priorities and templates span every domain), so their writes need a live
/// organization-wide `identity.write` grant; frozen Go gave them to any domain-scoped holder.
pub async fn org_wide(exec: &ScopedExecutor, actor: &AuthContext) -> bool {
    if setjoin_contracts::mutants::on("eap-foreign") {
        return true;
    }
    let user = actor.user_id();
    exec.read(
        "SELECT admin_org_wide_grant($1, '{identity.write}'::text[])",
        &[(&user, Type::INT8)],
    )
    .await
    .ok()
    .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
    .unwrap_or(false)
}

const POLICY_COLUMNS: &str = "id, priority, name, enabled, overwrite_directory_address, \
     cond_department, cond_domain_ids, cond_mailbox_type, cond_ad_ou, \
     primary_template, additional_templates, duplicate_resolution, \
     created_at::text, updated_at::text";

fn strings(row: &Row, index: usize) -> Result<Vec<String>, StatementFailure> {
    Ok(row
        .try_get::<_, Option<Vec<String>>>(index)
        .map_err(|_| invalid())?
        .unwrap_or_default())
}

/// Go's `eapPolicyResponse` (`omitempty` arrays) in field order.
fn policy_json(row: &Row) -> Result<String, StatementFailure> {
    let bad = |_| invalid();
    let list = |name: &str, values: Vec<String>| {
        if values.is_empty() {
            String::new()
        } else {
            let items: Vec<String> = values.iter().map(|v| s(v)).collect();
            format!(",\"{name}\":[{}]", items.join(","))
        }
    };
    let domains = row
        .try_get::<_, Option<Vec<i64>>>(6)
        .map_err(bad)?
        .unwrap_or_default();
    let domains = if domains.is_empty() {
        String::new()
    } else {
        let items: Vec<String> = domains.iter().map(|d| d.to_string()).collect();
        format!(",\"condDomainIds\":[{}]", items.join(","))
    };
    Ok(format!(
        "{{\"id\":{},\"priority\":{},\"name\":{},\"enabled\":{},\"overwriteDirectoryAddress\":{}{}{}{}{},\"primaryTemplate\":{}{},\"duplicateResolution\":{},\"createdAt\":{},\"updatedAt\":{}}}",
        row.try_get::<_, i64>(0).map_err(bad)?,
        row.try_get::<_, i32>(1).map_err(bad)?,
        s(&row.try_get::<_, String>(2).map_err(bad)?),
        row.try_get::<_, bool>(3).map_err(bad)?,
        row.try_get::<_, bool>(4).map_err(bad)?,
        list("condDepartment", strings(row, 5)?),
        domains,
        list("condMailboxType", strings(row, 7)?),
        list("condAdOu", strings(row, 8)?),
        s(&row.try_get::<_, String>(9).map_err(bad)?),
        list("additionalTemplates", strings(row, 10)?),
        s(&row.try_get::<_, String>(11).map_err(bad)?),
        s(&row.try_get::<_, String>(12).map_err(bad)?),
        s(&row.try_get::<_, String>(13).map_err(bad)?),
    ))
}

/// `GET /admin/email-address-policies-list`: a row that fails to scan is skipped.
pub async fn policies(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            &format!("SELECT {POLICY_COLUMNS} FROM email_address_policies ORDER BY priority ASC"),
            &[],
        )
        .await?;
    let out: Vec<String> = rows.iter().filter_map(|r| policy_json(r).ok()).collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// Go's `validateEAPTemplate`.
pub fn template_problem(template: &str) -> Option<String> {
    if !template.contains('@') {
        return Some("template must contain @".into());
    }
    let bytes = template.as_bytes();
    let mut found = false;
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'{' {
            let mut end = at + 1;
            while end < bytes.len() && (bytes[end].is_ascii_lowercase() || bytes[end] == b'_') {
                end += 1;
            }
            if end > at + 1 && end < bytes.len() && bytes[end] == b'}' {
                found = true;
                let name = &template[at + 1..end];
                if !matches!(
                    name,
                    "given_name"
                        | "surname"
                        | "first_initial"
                        | "user_name"
                        | "department"
                        | "domain"
                ) {
                    return Some(format!("unknown variable {{{name}}}"));
                }
                at = end + 1;
                continue;
            }
        }
        at += 1;
    }
    if !found {
        return Some("template must contain at least one {var}".into());
    }
    None
}

/// The request fields of create and update (`None`/empty arrays mean absent).
pub struct PolicyInput<'a> {
    pub priority: Option<i64>,
    pub name: Option<&'a str>,
    pub enabled: Option<bool>,
    pub overwrite: Option<bool>,
    pub departments: Option<Vec<String>>,
    pub domains: Option<Vec<i64>>,
    pub mailbox_types: Option<Vec<String>>,
    pub ad_ous: Option<Vec<String>>,
    pub primary: Option<&'a str>,
    pub additional: Option<Vec<String>>,
    pub duplicate: Option<&'a str>,
}

fn digest(input: &PolicyInput<'_>) -> String {
    format!(
        "{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}",
        input.priority,
        input.name,
        input.enabled,
        input.overwrite,
        input.departments,
        input.domains,
        input.mailbox_types,
        input.ad_ous,
        input.primary,
        input.additional,
        input.duplicate
    )
}

/// `POST /admin/email-address-policies`: the created row's JSON. Go computes the
/// automatic priority in a separate statement; here it is the same INSERT.
pub async fn policy_create(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    input: &PolicyInput<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    let priority = input.priority;
    let enabled = input.enabled.unwrap_or(true);
    let overwrite = input.overwrite.unwrap_or(false);
    let duplicate = input.duplicate.unwrap_or("numeric_suffix");
    let sql = format!(
        "WITH ins AS (INSERT INTO email_address_policies \
         (priority, name, enabled, overwrite_directory_address, cond_department, cond_domain_ids, \
          cond_mailbox_type, cond_ad_ou, primary_template, additional_templates, duplicate_resolution) \
         SELECT COALESCE($4::bigint::integer, (SELECT COALESCE(MAX(priority), 0) + 10 FROM email_address_policies)), \
          $5, $6, $7, $8, $9, $10, $11, $12, $13, $14 \
          WHERE $1::bigint > 0 AND $3::text <> '' RETURNING {POLICY_COLUMNS}) \
         SELECT {POLICY_COLUMNS} FROM ins"
    );
    setjoin_pg::run_receipted_command(
        exec,
        command("eap_create"),
        &envelope(&auth, operation, &digest(input)),
        &auth,
        deadline(),
        &sql,
        &[
            (&priority, Type::INT8),
            (&input.name.unwrap_or(""), Type::TEXT),
            (&enabled, Type::BOOL),
            (&overwrite, Type::BOOL),
            (&input.departments, Type::TEXT_ARRAY),
            (&input.domains, Type::INT8_ARRAY),
            (&input.mailbox_types, Type::TEXT_ARRAY),
            (&input.ad_ous, Type::TEXT_ARRAY),
            (&input.primary.unwrap_or(""), Type::TEXT),
            (&input.additional, Type::TEXT_ARRAY),
            (&duplicate, Type::TEXT),
        ],
        |rows| match rows {
            [row] => policy_json(row).map(done),
            _ => Err(invalid()),
        },
    )
    .await
}

/// `PUT /admin/email-address-policies/{id}`: the patched row's JSON; `None` when no
/// policy has the id (Go's 404).
pub async fn policy_update(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    input: &PolicyInput<'_>,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let auth = scope(actor);
    let sql = format!(
        "WITH upd AS (UPDATE email_address_policies SET \
         priority = COALESCE($5::bigint::integer, priority), \
         name = COALESCE($6, name), \
         enabled = COALESCE($7, enabled), \
         overwrite_directory_address = COALESCE($8, overwrite_directory_address), \
         cond_department = COALESCE($9, cond_department), \
         cond_domain_ids = COALESCE($10, cond_domain_ids), \
         cond_mailbox_type = COALESCE($11, cond_mailbox_type), \
         cond_ad_ou = COALESCE($12, cond_ad_ou), \
         primary_template = COALESCE($13, primary_template), \
         additional_templates = COALESCE($14, additional_templates), \
         duplicate_resolution = COALESCE($15, duplicate_resolution), \
         updated_at = now() \
         WHERE id = $4 AND $1::bigint > 0 AND $3::text <> '' RETURNING {POLICY_COLUMNS}) \
         SELECT {POLICY_COLUMNS} FROM upd"
    );
    setjoin_pg::run_receipted_command(
        exec,
        command("eap_update"),
        &envelope(&auth, operation, &format!("{id}:{}", digest(input))),
        &auth,
        deadline(),
        &sql,
        &[
            (&id, Type::INT8),
            (&input.priority, Type::INT8),
            (&input.name, Type::TEXT),
            (&input.enabled, Type::BOOL),
            (&input.overwrite, Type::BOOL),
            (&input.departments, Type::TEXT_ARRAY),
            (&input.domains, Type::INT8_ARRAY),
            (&input.mailbox_types, Type::TEXT_ARRAY),
            (&input.ad_ous, Type::TEXT_ARRAY),
            (&input.primary, Type::TEXT),
            (&input.additional, Type::TEXT_ARRAY),
            (&input.duplicate, Type::TEXT),
        ],
        |rows| match rows {
            [] => Ok(None),
            [row] => policy_json(row).map(done).map(Some),
            _ => Err(invalid()),
        },
    )
    .await
}

/// `DELETE /admin/email-address-policies/{id}`: whether a row was deleted.
pub async fn policy_delete(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("eap_delete"),
        &envelope(&auth, operation, &id.to_string()),
        &auth,
        deadline(),
        "WITH d AS (DELETE FROM email_address_policies WHERE id = $4 AND $1::bigint > 0 AND $3::text <> '' RETURNING 1) \
         SELECT count(*)::bigint FROM d",
        &[(&id, Type::INT8)],
        |rows| super::count(rows).map(|n| n > 0),
    )
    .await
}

/// `POST /admin/email-address-policies/reorder` (the list is non-empty).
pub async fn policy_reorder(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    order: &[i64],
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    let order = order.to_vec();
    setjoin_pg::run_receipted_command(
        exec,
        command("eap_reorder"),
        &envelope(&auth, operation, &format!("{order:?}")),
        &auth,
        deadline(),
        "SELECT count(*)::bigint FROM (SELECT rust_admin_eap_reorder($4::bigint[]) WHERE $1::bigint > 0 AND $3::text <> '') w",
        &[(&order, Type::INT8_ARRAY)],
        |rows| super::count(rows).map(|_| ()),
    )
    .await
}

/// `POST /admin/email-address-policies/apply`: the queued job id.
pub async fn policy_apply(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    policy: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("eap_apply"),
        &envelope(&auth, operation, &format!("{policy:?}")),
        &auth,
        deadline(),
        "INSERT INTO eap_apply_jobs (policy_id, status) SELECT $4, 'queued' WHERE $1::bigint > 0 AND $3::text <> '' RETURNING id",
        &[(&policy, Type::INT8)],
        |rows| match rows {
            [row] => row.try_get::<_, i64>(0).map_err(|_| invalid()),
            _ => Err(invalid()),
        },
    )
    .await
}

/// `GET /admin/email-address-policies/apply/{jobId}`: `None` is Go's 404 (any failure).
pub async fn apply_status(exec: &ScopedExecutor, job: i64) -> Option<String> {
    let rows = exec
        .read(
            "SELECT status, applied, total, error FROM eap_apply_jobs WHERE id = $1",
            &[(&job, Type::INT8)],
        )
        .await
        .ok()?;
    let row = rows.first()?;
    let status: String = row.try_get(0).ok()?;
    let applied: i32 = row.try_get(1).ok()?;
    let total: Option<i32> = row.try_get(2).ok()?;
    let error: Option<String> = row.try_get(3).ok()?;
    Some(done(format!(
        "{{\"applied\":{applied},\"error\":{},\"status\":{},\"total\":{}}}",
        error.map(|e| s(&e)).unwrap_or_else(|| "null".into()),
        s(&status),
        total
            .map(|t| t.to_string())
            .unwrap_or_else(|| "null".into()),
    )))
}

/// Go's `json.Encoder` over a `json.RawMessage`: the value is compacted (whitespace
/// outside strings removed); HTML escaping is applied by `done`.
fn compact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let (mut quoted, mut escaped) = (false, false);
    for c in text.chars() {
        if quoted {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
            }
        } else if c == '"' {
            quoted = true;
            out.push(c);
        } else if !matches!(c, ' ' | '\t' | '\n' | '\r') {
            out.push(c);
        }
    }
    out
}

/// `POST /admin/email-address-policies/{id}/preview`: the renderer's jsonb, `null`
/// for an unknown policy; any failure is Go's 500.
pub async fn preview(
    exec: &ScopedExecutor,
    policy: i64,
    user: i64,
    mailbox: i64,
) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT email_address_policy_render($1, $2, $3)::text",
            &[
                (&policy, Type::INT8),
                (&user, Type::INT8),
                (&mailbox, Type::INT8),
            ],
        )
        .await?;
    let text: Option<String> = rows
        .first()
        .ok_or_else(invalid)?
        .try_get(0)
        .map_err(|_| invalid())?;
    Ok(done(
        text.map(|t| compact(&t)).unwrap_or_else(|| "null".into()),
    ))
}

/// `POST /admin/email-address-policies/match-count`.
pub async fn match_count(
    exec: &ScopedExecutor,
    departments: &Option<Vec<String>>,
    domains: &Option<Vec<i64>>,
    mailbox_types: &Option<Vec<String>>,
    ad_ous: &Option<Vec<String>>,
) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT email_address_policy_match_count($1, $2, $3, $4)",
            &[
                (departments, Type::TEXT_ARRAY),
                (domains, Type::INT8_ARRAY),
                (mailbox_types, Type::TEXT_ARRAY),
                (ad_ous, Type::TEXT_ARRAY),
            ],
        )
        .await?;
    let n: i32 = rows
        .first()
        .ok_or_else(invalid)?
        .try_get(0)
        .map_err(|_| invalid())?;
    Ok(done(format!("{{\"count\":{n}}}")))
}

// ---------------------------------------------------------------------------
// Distribution groups

/// `GET /admin/distribution-groups`: every group with its eligibility flags; a scan
/// failure is Go's 500.
pub async fn distribution_groups(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT dg.id, mb.display_name, dg.is_dynamic, dg.scim_external_id IS NOT NULL, \
             dg.usable_as_admin_scope, COUNT(dgm.mailbox_id) \
             FROM distribution_groups dg \
             JOIN mailboxes mb ON mb.id = dg.mailbox_id \
             LEFT JOIN distribution_group_members dgm ON dgm.group_id = dg.id \
             GROUP BY dg.id, mb.display_name, dg.is_dynamic, dg.scim_external_id, dg.usable_as_admin_scope \
             ORDER BY mb.display_name",
            &[],
        )
        .await?;
    let bad = |_| invalid();
    let mut out = Vec::new();
    for row in &rows {
        out.push(format!(
            "{{\"id\":{},\"name\":{},\"isDynamic\":{},\"scimSynced\":{},\"usableAsAdminScope\":{},\"memberCount\":{}}}",
            row.try_get::<_, i64>(0).map_err(bad)?,
            s(&row.try_get::<_, String>(1).map_err(bad)?),
            row.try_get::<_, bool>(2).map_err(bad)?,
            row.try_get::<_, bool>(3).map_err(bad)?,
            row.try_get::<_, bool>(4).map_err(bad)?,
            row.try_get::<_, i64>(5).map_err(bad)?,
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// The SQLSTATE of a failed command, for the adapter's unique-violation mapping.
pub fn sqlstate(error: &Rejection<StatementFailure>) -> Option<String> {
    match error {
        Rejection::Statement(e) | Rejection::Body(e) => e.sqlstate.clone(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_follow_go_validation_order() {
        assert_eq!(
            template_problem("a.b"),
            Some("template must contain @".into())
        );
        assert_eq!(
            template_problem("a@b"),
            Some("template must contain at least one {var}".into())
        );
        assert_eq!(
            template_problem("{nope}@{domain}"),
            Some("unknown variable {nope}".into())
        );
        assert_eq!(template_problem("{given_name}.{surname}@{domain}"), None);
        assert_eq!(
            template_problem("{Given}@x"),
            Some("template must contain at least one {var}".into())
        );
    }

    #[test]
    fn compaction_keeps_strings_intact() {
        assert_eq!(
            compact("{\"a\": [1, \"x  y\\\" z\"], \"b\": null}"),
            "{\"a\":[1,\"x  y\\\" z\"],\"b\":null}"
        );
    }
}
