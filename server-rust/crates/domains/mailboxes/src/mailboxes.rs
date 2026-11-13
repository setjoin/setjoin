//! Mailboxes and folders: Go's `MailboxesHandler`.
//!
//! Reads are `SELECT`s on the request credential (Go's `h.pool`). Create and
//! update are one statement under the receipt; delete and the folder writes
//! call reducers that reproduce Go's multi-statement handler
//! (`rust_admin_mailbox_delete`, `rust_admin_folder_*`).
use super::{deadline, done, envelope, invalid, nano, s, scope, FAMILY};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ReceiptCommand, Row, ScopedExecutor, StatementFailure, Type};

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: FAMILY,
        command: name,
    }
}

fn select() -> String {
    format!(
        "SELECT m.id, m.user_id, COALESCE(u.email, ''), m.email, m.display_name, mailbox_effective_type(m.id)::text, \
         m.is_primary, m.quota_bytes, m.used_bytes, m.enabled, {}, d.name \
         FROM mailboxes m LEFT JOIN users u ON u.id = m.user_id JOIN domains d ON d.id = m.domain_id",
        nano("m.created_at")
    )
}

/// One mailbox as Go's `adminMailboxResponse`; `None` when Go's `Scan` fails.
fn mailbox_json(row: &Row) -> Option<String> {
    let user = row.try_get::<_, Option<i64>>(1).ok()?;
    Some(format!(
        "{{\"id\":{},\"userId\":{},\"userEmail\":{},\"email\":{},\"displayName\":{},\"type\":{},\"isPrimary\":{},\"quotaBytes\":{},\"usedBytes\":{},\"enabled\":{},\"createdAt\":{},\"domainName\":{}}}",
        row.try_get::<_, i64>(0).ok()?,
        user.map_or("null".to_owned(), |u| u.to_string()),
        s(&row.try_get::<_, String>(2).ok()?),
        s(&row.try_get::<_, String>(3).ok()?),
        s(&row.try_get::<_, String>(4).ok()?),
        s(&row.try_get::<_, String>(5).ok()?),
        row.try_get::<_, bool>(6).ok()?,
        row.try_get::<_, i64>(7).ok()?,
        row.try_get::<_, i64>(8).ok()?,
        row.try_get::<_, bool>(9).ok()?,
        s(&row.try_get::<_, String>(10).ok()?),
        s(&row.try_get::<_, String>(11).ok()?),
    ))
}

/// How the list is filtered: Go's `user_id` parameter wins over `q`.
pub enum Filter<'a> {
    None,
    /// `user_id` was present; the parsed value (0 when unparsable).
    User(i64),
    Search(&'a str),
}

/// `GET /admin/mailboxes`: rows Go fails to scan are skipped.
pub async fn list(
    exec: &ScopedExecutor,
    domain_scope: i64,
    filter: Filter<'_>,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let pattern;
    let user;
    let mut conditions: Vec<String> = Vec::new();
    let mut params: Vec<setjoin_pg::Param<'_>> = Vec::new();
    match filter {
        Filter::None => {}
        Filter::User(id) => {
            user = id;
            params.push((&user, Type::INT8));
            conditions.push(format!("m.user_id = ${}", params.len()));
        }
        Filter::Search(q) => {
            pattern = format!("%{q}%");
            params.push((&pattern, Type::TEXT));
            conditions.push(format!(
                "(u.email ILIKE ${n} OR m.display_name ILIKE ${n} OR m.email ILIKE ${n})",
                n = params.len()
            ));
        }
    }
    if domain_scope > 0 {
        params.push((&domain_scope, Type::INT8));
        conditions.push(format!("d.id = ${}", params.len()));
    }
    params.push((&limit, Type::INT8));
    let l = params.len();
    params.push((&offset, Type::INT8));
    let o = params.len();
    let wher = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };
    let sql = format!(
        "{}{wher} ORDER BY m.id DESC LIMIT ${l} OFFSET ${o}",
        select()
    );
    let rows = exec.read(&sql, &params).await?;
    let out: Vec<String> = rows.iter().filter_map(mailbox_json).collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/mailboxes/{id}`; `None` is Go's 404 (missing or out of scope).
/// A row Go cannot scan is its 500.
pub async fn get(
    exec: &ScopedExecutor,
    domain_scope: i64,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let sql = format!(
        "{} WHERE m.id = $1 AND ($2::bigint = 0 OR d.id = $2)",
        select()
    );
    let rows = exec
        .read(&sql, &[(&id, Type::INT8), (&domain_scope, Type::INT8)])
        .await?;
    match rows.first() {
        None => Ok(None),
        Some(row) => mailbox_json(row).map(|j| Some(done(j))).ok_or_else(invalid),
    }
}

/// Go's `inDomainScope` lookup: the mailbox's domain, `None` when absent.
pub async fn domain_of(exec: &ScopedExecutor, id: i64) -> Result<Option<i64>, StatementFailure> {
    let rows = exec
        .read(
            "SELECT domain_id FROM mailboxes WHERE id = $1",
            &[(&id, Type::INT8)],
        )
        .await?;
    match rows.first() {
        None => Ok(None),
        Some(row) => row.try_get::<_, i64>(0).map(Some).map_err(|_| invalid()),
    }
}

/// `GET /admin/mailboxes/{id}/folders`. Go skips a folder it cannot scan, and a
/// folder without a role (NULL) is one of them.
pub async fn folders(exec: &ScopedExecutor, mailbox: i64) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT f.id, f.mailbox_id, f.name, f.role, f.path, \
             COALESCE(t.total_count, 0)::bigint, COALESCE(t.unread_count, 0)::bigint \
             FROM folders f LEFT JOIN tags t ON t.mailbox_id = f.mailbox_id AND t.name = f.name \
             WHERE f.mailbox_id = $1 ORDER BY f.path",
            &[(&mailbox, Type::INT8)],
        )
        .await?;
    let out: Vec<String> = rows
        .iter()
        .filter_map(|row| {
            Some(format!(
                "{{\"id\":{},\"mailboxId\":{},\"name\":{},\"role\":{},\"path\":{},\"totalCount\":{},\"unreadCount\":{}}}",
                row.try_get::<_, i64>(0).ok()?,
                row.try_get::<_, i64>(1).ok()?,
                s(&row.try_get::<_, String>(2).ok()?),
                s(&row.try_get::<_, String>(3).ok()?),
                s(&row.try_get::<_, String>(4).ok()?),
                row.try_get::<_, i64>(5).ok()?,
                row.try_get::<_, i64>(6).ok()?,
            ))
        })
        .collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// Go's `is_guest_account` pre-check for create.
pub async fn is_guest(exec: &ScopedExecutor, user: i64) -> Result<bool, StatementFailure> {
    let rows = exec
        .read("SELECT is_guest_account($1)", &[(&user, Type::INT8)])
        .await?;
    super::first_bool(&rows)
}

/// The user's domain, `None` when the user does not exist.
pub async fn user_domain(
    exec: &ScopedExecutor,
    user: i64,
) -> Result<Option<i64>, StatementFailure> {
    let rows = exec
        .read(
            "SELECT domain_id FROM users WHERE id = $1",
            &[(&user, Type::INT8)],
        )
        .await?;
    match rows.first() {
        None => Ok(None),
        Some(row) => row.try_get::<_, i64>(0).map(Some).map_err(|_| invalid()),
    }
}

/// `POST /admin/mailboxes`: Go's INSERT (the user's domain and the admin's
/// domain scope ride in the same statement). `quota` is NULL unless positive,
/// as Go binds it, so an absent quota meets the column's NOT NULL.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    user: i64,
    email: &str,
    display_name: &str,
    quota: Option<i64>,
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<Option<i64>, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("mailbox.create"),
        &envelope(&auth, operation, &format!("{user}:{email}:{display_name}:{quota:?}")),
        &auth,
        deadline(),
        "INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary, quota_bytes) \
         SELECT u.id, u.domain_id, $5, $6, 'personal', FALSE, $7::bigint FROM users u \
         WHERE u.id = $4 AND ($8::bigint = 0 OR u.domain_id = $8) \
         AND $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING id",
        &[
            (&user, Type::INT8),
            (&email, Type::TEXT),
            (&display_name, Type::TEXT),
            (&quota, Type::INT8),
            (&domain_scope, Type::INT8),
        ],
        |rows| match rows {
            [] => Ok(None),
            [row] => row.try_get::<_, i64>(0).map(Some).map_err(|_| invalid()),
            _ => Err(invalid()),
        },
    )
    .await
}

/// Optional fields of `PUT /admin/mailboxes/{id}`.
pub struct Patch<'a> {
    pub display_name: Option<&'a str>,
    pub quota_bytes: Option<i64>,
    pub enabled: Option<bool>,
    pub litigation_hold: Option<bool>,
    pub deleted_purge_days: Option<i32>,
    pub spam_purge_days: Option<i32>,
}

/// `PUT /admin/mailboxes/{id}`: `Committed(false)` is Go's 404.
pub async fn update(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    domain_scope: i64,
    patch: &Patch<'_>,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("mailbox.update"),
        &envelope(&auth, operation, &format!("{id}:{domain_scope}")),
        &auth,
        deadline(),
        "WITH u AS (UPDATE mailboxes SET display_name = COALESCE($6::text, display_name), \
         quota_bytes = COALESCE($7::bigint, quota_bytes), enabled = COALESCE($8::boolean, enabled), \
         litigation_hold = COALESCE($9::boolean, litigation_hold), deleted_purge_days = $10::integer, \
         spam_purge_days = $11::integer, updated_at = now() \
         WHERE id = $4 AND ($5::bigint = 0 OR domain_id = $5) \
         AND $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING 1) SELECT count(*)::bigint FROM u",
        &[
            (&id, Type::INT8),
            (&domain_scope, Type::INT8),
            (&patch.display_name, Type::TEXT),
            (&patch.quota_bytes, Type::INT8),
            (&patch.enabled, Type::BOOL),
            (&patch.litigation_hold, Type::BOOL),
            (&patch.deleted_purge_days, Type::INT4),
            (&patch.spam_purge_days, Type::INT4),
        ],
        |rows| match rows {
            [row] => row
                .try_get::<_, i64>(0)
                .map(|n| n > 0)
                .map_err(|_| invalid()),
            _ => Err(invalid()),
        },
    )
    .await
}

/// Go's `mailbox_lifecycle_enabled()` gate, on the worker credential.
pub async fn lifecycle_enabled(worker: &ScopedExecutor) -> Result<bool, StatementFailure> {
    let rows = worker
        .read("SELECT mailbox_lifecycle_enabled()", &[])
        .await?;
    super::first_bool(&rows)
}

/// `DELETE /admin/mailboxes/{id}` on the worker credential. `false` means the
/// scoped actor cannot reach the mailbox (nothing was changed).
pub async fn delete(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("mailbox.delete"),
        &envelope(&auth, operation, &format!("{id}:{domain_scope}")),
        &auth,
        deadline(),
        "SELECT rust_admin_mailbox_delete($4,$5) WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[(&id, Type::INT8), (&domain_scope, Type::INT8)],
        super::first_bool,
    )
    .await
}

fn verdict(rows: &[Row], success: &[u64]) -> Result<serde_json::Value, StatementFailure> {
    let text: String = rows
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| invalid())?;
    match v["status"].as_u64() {
        Some(status) if success.contains(&status) => Ok(v),
        Some(_) if v["detail"].is_string() => Err(StatementFailure {
            sqlstate: None,
            hint: None,
            message: text,
        }),
        _ => Err(invalid()),
    }
}

/// `POST /admin/mailboxes/{id}/folders`: the new folder id. A reducer refusal
/// (parent not found, scope) is a rolled-back body for `problem_of`.
pub async fn folder_create(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    mailbox: i64,
    domain_scope: i64,
    parent: Option<i64>,
    name: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("folder.create"),
        &envelope(&auth, operation, &format!("{mailbox}:{parent:?}:{name}")),
        &auth,
        deadline(),
        "SELECT rust_admin_folder_create($4,$5,$6,$7)::text WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[
            (&mailbox, Type::INT8),
            (&domain_scope, Type::INT8),
            (&parent, Type::INT8),
            (&name, Type::TEXT),
        ],
        |rows| {
            verdict(rows, &[201])?["id"]
                .as_i64()
                .ok_or_else(invalid)
        },
    )
    .await
}

pub async fn folder_update(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    mailbox: i64,
    domain_scope: i64,
    folder: i64,
    name: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("folder.update"),
        &envelope(&auth, operation, &format!("{mailbox}:{folder}:{name}")),
        &auth,
        deadline(),
        "SELECT rust_admin_folder_update($4,$5,$6,$7)::text WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[
            (&mailbox, Type::INT8),
            (&domain_scope, Type::INT8),
            (&folder, Type::INT8),
            (&name, Type::TEXT),
        ],
        |rows| verdict(rows, &[204]).map(|_| ()),
    )
    .await
}

pub async fn folder_delete(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    mailbox: i64,
    domain_scope: i64,
    folder: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("folder.delete"),
        &envelope(&auth, operation, &format!("{mailbox}:{folder}")),
        &auth,
        deadline(),
        "SELECT rust_admin_folder_delete($4,$5,$6)::text WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[
            (&mailbox, Type::INT8),
            (&domain_scope, Type::INT8),
            (&folder, Type::INT8),
        ],
        |rows| verdict(rows, &[204]).map(|_| ()),
    )
    .await
}
