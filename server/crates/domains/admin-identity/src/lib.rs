//! Admin identity (F01): users slice.
//!
//! Foundation dependencies only. The actor and mailbox come from the sealed auth
//! context / capability principals; request ids name targets but never grant
//! authority. Permissions and domain scope are resolved live through `PolicyGate`.
//! Responses are rendered in `encoding/json` field order (structs) or sorted key
//! order (maps), HTML-escaped, with the trailing newline of Go's `Encoder`.
#![forbid(unsafe_code)]
pub mod access_reviews;
pub mod idv2;
pub mod idv2_ops;
pub mod idv2_source;
pub mod idv2_transitions;
pub mod idv2_upgrade;
pub mod idv2_writes;
pub mod lifecycle;
pub mod org_policies;
pub mod roles;
pub mod scope_sets;
pub mod sod;
pub mod sql;

/// Static typed SQL contract catalog for `setjoin-admin-identity` (#546d).
pub use sql::SQL_CONTRACTS;

use serde_json::json;
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, OperationId},
};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Row, StatementFailure};
use sha2::{Digest as _, Sha256};

/// Receipt family identifier for F01 Admin Identity.
pub const FAMILY: &str = "F01";

/// Go's `admin.ConsoleScopes[ConsoleAuth]`, in registration order.
pub const AUTH_CONSOLE: [&str; 4] = [
    "users.read",
    "identity.write",
    "access.policy_read",
    "access.policy_write",
];
/// `requireSignInPerm`: the Auth console scopes followed by the Logs console's.
pub const SIGN_IN: [&str; 5] = [
    "users.read",
    "identity.write",
    "access.policy_read",
    "access.policy_write",
    "audit.read",
];
pub const USERS_CREATE: [&str; 1] = ["users.create"];
pub const APPS: [&str; 7] = [
    "mail", "calendar", "contacts", "tasks", "chat", "drive", "meet",
];

pub(crate) fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid admin identity result".into(),
    }
}

pub(crate) fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}

pub(crate) fn envelope(
    actor: ActorId,
    generation: Generation,
    operation: [u8; 16],
    payload: &str,
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: AuthorityKey {
            scope: ResourceScope::User(actor),
            actor,
            generation,
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(payload.as_bytes()).into()),
        command: (),
    }
}

pub(crate) fn count(rows: &[Row]) -> Result<i64, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

/// Public row-count projection for worker-bypass `F01` commands (`set_quota`,
/// `remove_alias`, `set_app_access`).
pub fn parse_count(rows: &[Row]) -> Result<i64, StatementFailure> {
    count(rows)
}

/// Public alias-id projection for worker-bypass `USER_ALIAS_ADD`.
pub fn parse_alias_id(rows: &[Row]) -> Result<Option<i64>, StatementFailure> {
    match rows {
        [] => Ok(None),
        [row] => row.try_get::<_, Option<i64>>(0).map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}

/// Whether `USER_ALIAS_ADD` enforces that a domain-scoped admin binds only
/// addresses of the mailbox's own domain (#373).
pub fn alias_enforce_domain() -> bool {
    !setjoin_contracts::mutants::on("alias-foreign-domain")
}

/// Go writes the same durable console-denial audit row, best effort.
pub async fn console_denied(
    factory: &TxFactory,
    user: &UserPrincipal,
    path: &str,
    permission: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let before = json!({
        "actor": user.audit_meta().email,
        "target": path,
        "missingPermission": permission
    })
    .to_string();
    let env = envelope(user.user(), user.generation(), operation, &before);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CONSOLE_DENIED,
            &[&before, &path],
            Some(ReceiptCommand {
                family: FAMILY,
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

/// encoding/json HTML escaping of an already rendered document.
pub fn go_escape(text: &str) -> String {
    text.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// Go's `encoding/json` key folding for the characters that fold across ASCII.
pub(crate) fn fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'ſ' => 's',
            '\u{212a}' => 'k',
            _ => c.to_ascii_lowercase(),
        })
        .collect()
}

pub(crate) fn s(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".into())
}

pub(crate) fn done(text: String) -> String {
    go_escape(&text) + "\n"
}

/// Escape LIKE/ILIKE metacharacters (`\`, `%`, `_`) so user queries match literals.
pub(crate) fn escape_like(q: &str) -> String {
    let mut out = String::with_capacity(q.len());
    for ch in q.chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

/// `GET /admin/users`: one page plus Go's best-effort manageable/self flags.
pub async fn users(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    actor: i64,
    domain_scope: i64,
    q: &str,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let pattern = (!q.is_empty()).then(|| format!("%{}%", escape_like(q)));
    let rows = factory
        .run_admin_read_contract(
            admin,
            &sql::USERS_LIST,
            &[&pattern, &domain_scope, &limit, &offset],
        )
        .await?;
    struct Item {
        id: i64,
        text: [String; 3],
        flags: Option<(bool, bool, Option<i64>)>,
        department: Option<i64>,
        enabled: bool,
        admin: bool,
    }
    let mut items = Vec::new();
    for row in &rows {
        // Go skips a row that fails to scan (a NULL in a non-pointer column).
        let (Ok(id), Ok(email), Ok(name), Ok(enabled), Ok(is_admin), Ok(created)) = (
            row.try_get::<_, i64>(0),
            row.try_get::<_, String>(1),
            row.try_get::<_, String>(2),
            row.try_get::<_, bool>(3),
            row.try_get::<_, bool>(4),
            row.try_get::<_, String>(6),
        ) else {
            continue;
        };
        items.push(Item {
            id,
            text: [email, name, created],
            flags: None,
            department: row.try_get::<_, Option<i64>>(5).ok().flatten(),
            enabled,
            admin: is_admin,
        });
    }
    if !items.is_empty() {
        let ids: Vec<i64> = items.iter().map(|i| i.id).collect();
        let flags = factory
            .run_admin_read_contract(admin, &sql::USERS_FLAGS, &[&ids, &actor])
            .await;
        // Go logs and serves the page without flags when this query fails.
        if let Ok(flags) = flags {
            for row in flags {
                let (Ok(id), Ok(is_self), Ok(manageable)) = (
                    row.try_get::<_, i64>(0),
                    row.try_get::<_, bool>(1),
                    row.try_get::<_, bool>(2),
                ) else {
                    continue;
                };
                let mailbox = row.try_get::<_, Option<i64>>(3).ok().flatten();
                if let Some(item) = items.iter_mut().find(|i| i.id == id) {
                    item.flags = Some((is_self, manageable, mailbox));
                }
            }
        }
    }
    let out: Vec<String> = items
        .iter()
        .map(|i| {
            let (is_self, manageable, mailbox) = i.flags.unwrap_or((false, false, None));
            format!(
                "{{\"id\":{},\"email\":{},\"displayName\":{},\"enabled\":{},\"isLocalAdmin\":{}{},\"createdAt\":{}{},\"manageable\":{},\"isSelf\":{}}}",
                i.id,
                s(&i.text[0]),
                s(&i.text[1]),
                i.enabled,
                i.admin,
                i.department
                    .map(|d| format!(",\"departmentId\":{d}"))
                    .unwrap_or_default(),
                s(&i.text[2]),
                mailbox
                    .map(|m| format!(",\"mailboxId\":{m}"))
                    .unwrap_or_default(),
                manageable,
                is_self
            )
        })
        .collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/users/{id}`; `None` is Go's 404 (missing or out of scope).
pub async fn user(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::USER_GET, &[&id, &domain_scope])
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let department = row
        .try_get::<_, Option<i64>>(5)
        .map_err(|_| invalid())?
        .map(|d| format!(",\"departmentId\":{d}"))
        .unwrap_or_default();
    let rendered = format!(
        "{{\"id\":{},\"email\":{},\"displayName\":{},\"enabled\":{},\"isLocalAdmin\":{}{},\"createdAt\":{},\"manageable\":false,\"isSelf\":false}}",
        row.try_get::<_, i64>(0).map_err(|_| invalid())?,
        s(&row.try_get::<_, String>(1).map_err(|_| invalid())?),
        s(&row.try_get::<_, String>(2).map_err(|_| invalid())?),
        row.try_get::<_, bool>(3).map_err(|_| invalid())?,
        row.try_get::<_, bool>(4).map_err(|_| invalid())?,
        department,
        s(&row.try_get::<_, String>(6).map_err(|_| invalid())?),
    );
    Ok(Some(done(rendered)))
}

/// `GET /admin/users/{id}/aliases`: map rows, so keys sort alphabetically.
pub async fn aliases(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
    id: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::USER_ALIASES, &[&id, &domain_scope])
        .await?;
    let out: Vec<String> = rows
        .iter()
        .filter_map(|r| {
            Some(format!(
                "{{\"email\":{},\"id\":{},\"isPrimary\":{}}}",
                s(&r.try_get::<_, String>(1).ok()?),
                r.try_get::<_, i64>(0).ok()?,
                r.try_get::<_, bool>(2).ok()?
            ))
        })
        .collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/users/{id}/quota`; `Ok(None)` is 404 (missing or out of scope), `Err` is 500.
pub async fn quota(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::USER_QUOTA, &[&id, &domain_scope])
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    Ok(Some(done(format!(
        "{{\"quotaBytes\":{},\"usedBytes\":{},\"sendingQuotaDay\":{},\"sendingSentToday\":{}}}",
        row.try_get::<_, i64>(0).map_err(|_| invalid())?,
        row.try_get::<_, i64>(1).map_err(|_| invalid())?,
        row.try_get::<_, i32>(2).map_err(|_| invalid())?,
        row.try_get::<_, i32>(3).map_err(|_| invalid())?
    ))))
}

/// `GET /admin/users/{id}/app-passwords`.
pub async fn app_passwords(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
    id: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::USER_APP_PASSWORDS, &[&id, &domain_scope])
        .await?;
    let out: Vec<String> = rows
        .iter()
        .filter_map(|r| {
            let optional = |i: usize, key: &str| -> Option<String> {
                r.try_get::<_, Option<String>>(i)
                    .ok()?
                    .map(|v| format!(",\"{key}\":{}", s(&v)))
                    .or(Some(String::new()))
            };
            Some(format!(
                "{{\"id\":{},\"name\":{},\"createdAt\":{}{}{}{}}}",
                r.try_get::<_, i64>(0).ok()?,
                s(&r.try_get::<_, String>(1).ok()?),
                s(&r.try_get::<_, String>(2).ok()?),
                optional(3, "lastUsedAt")?,
                optional(4, "expiresAt")?,
                optional(5, "revokedAt")?
            ))
        })
        .collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/users/{id}/app-access`; an error is Go's 500.
pub async fn app_access(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
    id: i64,
) -> Result<String, StatementFailure> {
    let guest_rows = factory
        .run_admin_read_contract(admin, &sql::USER_IS_GUEST_IN_SCOPE, &[&id, &domain_scope])
        .await?;
    let guest: bool = guest_rows
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)?;
    let rows = factory
        .run_admin_read_contract(admin, &sql::USER_APP_ENTITLEMENTS, &[&id, &domain_scope])
        .await?;
    let explicit: Vec<(String, bool)> = rows
        .iter()
        .filter_map(|r| {
            Some((
                r.try_get::<_, String>(0).ok()?,
                r.try_get::<_, bool>(1).ok()?,
            ))
        })
        .collect();
    let out: Vec<String> = APPS
        .iter()
        .map(|app| {
            let enabled = explicit
                .iter()
                .rev()
                .find(|(a, _)| a == app)
                .map(|(_, e)| *e)
                .unwrap_or(!guest);
            format!("{{\"app\":{},\"enabled\":{enabled}}}", s(app))
        })
        .collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/users/{id}/sessions`; the target must exist inside the scope.
pub async fn sessions(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let exists = factory
        .run_admin_read_contract(admin, &sql::USER_EXISTS_IN_SCOPE, &[&id, &domain_scope])
        .await?;
    if !exists
        .first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)?
    {
        return Ok(None);
    }
    let rows = factory
        .run_admin_read_contract(admin, &sql::USER_SESSIONS, &[&id, &domain_scope])
        .await?;
    let out: Vec<String> = rows
        .iter()
        .filter_map(|r| {
            Some(format!(
                "{{\"id\":{},\"kind\":{},\"client_id\":{},\"device\":{},\"location\":{},\"last_used_at\":{},\"auth_method\":{}}}",
                s(&r.try_get::<_, String>(0).ok()?),
                s(&r.try_get::<_, String>(1).ok()?),
                s(&r.try_get::<_, String>(2).ok()?),
                s(&r.try_get::<_, String>(3).ok()?),
                s(&r.try_get::<_, String>(4).ok()?),
                s(&r.try_get::<_, String>(5).ok()?),
                s(&r.try_get::<_, String>(6).ok()?)
            ))
        })
        .collect();
    Ok(Some(done(format!("{{\"sessions\":[{}]}}", out.join(",")))))
}

/// Go's primary-mailbox resolution before an alias insert: `(mailbox, domain)`.
pub async fn primary_mailbox(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
    user: i64,
) -> Option<(i64, i64)> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::USER_PRIMARY_MAILBOX, &[&user, &domain_scope])
        .await
        .ok()?;
    let row = rows.first()?;
    Some((row.try_get(0).ok()?, row.try_get(1).ok()?))
}

/// Owner-approved security fix 2026-11-05 (#373): whether `email` belongs to the domain that
/// owns `mailbox`. A domain-scoped admin (`domain_scope > 0`) may only bind such addresses;
/// the domain is read from the mailbox row, never from the request.
pub async fn alias_domain_allowed(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
    mailbox: i64,
    email: &str,
) -> bool {
    if domain_scope <= 0 || setjoin_contracts::mutants::on("alias-foreign-domain") {
        return true;
    }
    factory
        .run_admin_read_contract(
            admin,
            &sql::ALIAS_DOMAIN_ALLOWED,
            &[&mailbox, &domain_scope, &email],
        )
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::escape_like;

    #[test]
    fn escape_like_escapes_wildcards_and_backslash() {
        assert_eq!(escape_like("alice"), "alice");
        assert_eq!(escape_like("100%_done\\ok"), "100\\%\\_done\\\\ok");
        assert_eq!(escape_like("%%%"), "\\%\\%\\%");
        assert_eq!(escape_like(""), "");
    }
}
