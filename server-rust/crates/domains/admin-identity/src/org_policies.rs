//! Admin identity (F01) slice `org-policies`: departments, email-address policies and
//! the distribution-group picker.
use super::{deadline, done, envelope, invalid, s, sql, FAMILY};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Rejection, Row, StatementFailure};

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
        family: FAMILY,
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
pub async fn departments(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::DEPARTMENTS_LIST, &[])
        .await?;
    let out: Vec<String> = rows
        .iter()
        .filter_map(department)
        .map(|d| d.json(None))
        .collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/departments/tree`.
pub async fn department_tree(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::DEPARTMENTS_TREE, &[])
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

/// Public projection for worker-bypass `sql::DEPARTMENT_CREATE`.
pub fn parse_department_create(rows: &[Row]) -> Result<i64, StatementFailure> {
    verdict(rows, &[200])?["id"].as_i64().ok_or_else(invalid)
}

pub struct DepartmentPatch<'a> {
    pub name: &'a str,
    pub parent: Option<i64>,
    pub ldap_ou: &'a str,
    pub sort: Option<i64>,
}

/// Public projection for worker-bypass `sql::DEPARTMENT_UPDATE` (204 or committed 500).
pub fn parse_department_update(rows: &[Row]) -> Result<u16, StatementFailure> {
    verdict(rows, &[204, 500])?["status"]
        .as_u64()
        .map(|n| n as u16)
        .ok_or_else(invalid)
}

/// Public projection for worker-bypass `sql::DEPARTMENT_DELETE` and
/// `sql::DEPARTMENT_ASSIGN_USER` (204 verdict).
pub fn parse_department_mut(rows: &[Row]) -> Result<(), StatementFailure> {
    verdict(rows, &[204]).map(|_| ())
}

// ---------------------------------------------------------------------------
// Email-address policies

/// Owner-approved security fix 2026-11-05 (#510, #402 review): email-address policies are
/// organization-wide, so their writes need a live organization-wide `identity.write` grant.
pub async fn org_wide(factory: &TxFactory, admin: &AdminPermissionProof) -> bool {
    if setjoin_contracts::mutants::on("eap-foreign") {
        return true;
    }
    let user = admin.actor().get();
    factory
        .run_admin_read_contract(admin, &sql::ORG_WIDE_IDENTITY_WRITE, &[&user])
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
        .unwrap_or(false)
}

fn strings(row: &Row, index: usize) -> Result<Vec<String>, StatementFailure> {
    Ok(row
        .try_get::<_, Option<Vec<String>>>(index)
        .map_err(|_| invalid())?
        .unwrap_or_default())
}

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
pub async fn policies(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::EAP_LIST, &[])
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

/// `POST /admin/email-address-policies`: the created row's JSON.
pub async fn policy_create(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    input: &PolicyInput<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let priority = input.priority;
    let name = input.name.unwrap_or("");
    let enabled = input.enabled.unwrap_or(true);
    let overwrite = input.overwrite.unwrap_or(false);
    let primary = input.primary.unwrap_or("");
    let duplicate = input.duplicate.unwrap_or("numeric_suffix");
    let env = envelope(user.user(), user.generation(), operation, &digest(input));
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::EAP_CREATE,
            &[
                &priority,
                &name,
                &enabled,
                &overwrite,
                &input.departments,
                &input.domains,
                &input.mailbox_types,
                &input.ad_ous,
                &primary,
                &input.additional,
                &duplicate,
            ],
            Some(command("eap_create")),
            |rows| match rows.as_slice() {
                [row] => policy_json(row).map(done),
                _ => Err(invalid()),
            },
        )
        .await
}

/// `PUT /admin/email-address-policies/{id}`: the patched row's JSON; `None` is Go's 404.
pub async fn policy_update(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    id: i64,
    input: &PolicyInput<'_>,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{id}:{}", digest(input)),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::EAP_UPDATE,
            &[
                &id,
                &input.priority,
                &input.name,
                &input.enabled,
                &input.overwrite,
                &input.departments,
                &input.domains,
                &input.mailbox_types,
                &input.ad_ous,
                &input.primary,
                &input.additional,
                &input.duplicate,
            ],
            Some(command("eap_update")),
            |rows| match rows.as_slice() {
                [] => Ok(None),
                [row] => policy_json(row).map(done).map(Some),
                _ => Err(invalid()),
            },
        )
        .await
}

/// `DELETE /admin/email-address-policies/{id}`: whether a row was deleted.
pub async fn policy_delete(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(user.user(), user.generation(), operation, &id.to_string());
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::EAP_DELETE,
            &[&id],
            Some(command("eap_delete")),
            |rows| super::count(&rows).map(|n| n > 0),
        )
        .await
}

/// `POST /admin/email-address-policies/reorder` (the list is non-empty).
pub async fn policy_reorder(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    order: &[i64],
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let order = order.to_vec();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{order:?}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::EAP_REORDER,
            &[&order],
            Some(command("eap_reorder")),
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

/// `POST /admin/email-address-policies/apply`: the queued job id.
pub async fn policy_apply(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    policy: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{policy:?}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::EAP_APPLY,
            &[&policy],
            Some(command("eap_apply")),
            |rows| match rows.as_slice() {
                [row] => row.try_get::<_, i64>(0).map_err(|_| invalid()),
                _ => Err(invalid()),
            },
        )
        .await
}

/// `GET /admin/email-address-policies/apply/{jobId}`: `None` is Go's 404 (any failure).
pub async fn apply_status(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    job: i64,
) -> Option<String> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::EAP_APPLY_STATUS, &[&job])
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

/// `POST /admin/email-address-policies/{id}/preview`.
pub async fn preview(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    policy: i64,
    user: i64,
    mailbox: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::EAP_PREVIEW, &[&policy, &user, &mailbox])
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
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    departments: &Option<Vec<String>>,
    domains: &Option<Vec<i64>>,
    mailbox_types: &Option<Vec<String>>,
    ad_ous: &Option<Vec<String>>,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(
            admin,
            &sql::EAP_MATCH_COUNT,
            &[departments, domains, mailbox_types, ad_ous],
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

/// `GET /admin/distribution-groups`: every group with its eligibility flags.
pub async fn distribution_groups(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::DISTRIBUTION_GROUPS_LIST, &[])
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
            compact("{\"a\": \"x y\", \"b\": [1, 2]}"),
            "{\"a\":\"x y\",\"b\":[1,2]}"
        );
    }
}
