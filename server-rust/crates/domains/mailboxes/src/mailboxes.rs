//! Mailboxes and folders: Go's `MailboxesHandler`.
//!
//! Reads execute through capability-gated `TxFactory` contracts; create and
//! update are one statement under the receipt; delete and the folder writes
//! call reducers that reproduce Go's multi-statement handler
//! (`rust_admin_mailbox_delete`, `rust_admin_folder_*`).
use super::{done, invalid, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{Row, StatementFailure};

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
    factory: &TxFactory,
    user: &UserPrincipal,
    domain_scope: i64,
    filter: Filter<'_>,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let (user_filter, search_pattern) = match filter {
        Filter::None => (None, None),
        Filter::User(id) => (Some(id), None),
        Filter::Search(q) => (None, Some(format!("%{q}%"))),
    };
    let rows = factory
        .run_user_read_contract(
            user,
            &sql::MAILBOXES_LIST,
            &[
                &domain_scope,
                &user_filter,
                &search_pattern,
                &limit,
                &offset,
            ],
        )
        .await?;
    let out: Vec<String> = rows.iter().filter_map(mailbox_json).collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/mailboxes/{id}`; `None` is Go's 404 (missing or out of scope).
/// A row Go cannot scan is its 500.
pub async fn get(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    domain_scope: i64,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::MAILBOX_GET, &[&id, &domain_scope])
        .await?;
    match rows.first() {
        None => Ok(None),
        Some(row) => mailbox_json(row).map(|j| Some(done(j))).ok_or_else(invalid),
    }
}

/// Go's `inDomainScope` lookup: the mailbox's domain, `None` when absent.
pub async fn domain_of(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    id: i64,
) -> Result<Option<i64>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::MAILBOX_DOMAIN_OF, &[&id])
        .await?;
    match rows.first() {
        None => Ok(None),
        Some(row) => row.try_get::<_, i64>(0).map(Some).map_err(|_| invalid()),
    }
}

/// `GET /admin/mailboxes/{id}/folders`. Go skips a folder it cannot scan, and a
/// folder without a role (NULL) is one of them.
pub async fn folders(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    mailbox: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::MAILBOX_FOLDERS, &[&mailbox])
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
pub async fn is_guest(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    user: i64,
) -> Result<bool, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::IS_GUEST_ACCOUNT, &[&user])
        .await?;
    super::first_bool(&rows)
}

/// The user's domain, `None` when the user does not exist.
pub async fn user_domain(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    user: i64,
) -> Result<Option<i64>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::USER_DOMAIN, &[&user])
        .await?;
    match rows.first() {
        None => Ok(None),
        Some(row) => row.try_get::<_, i64>(0).map(Some).map_err(|_| invalid()),
    }
}

/// Decode the `RETURNING id` row of `sql::MAILBOX_CREATE`.
pub fn parse_created_id(rows: &[Row]) -> Result<Option<i64>, StatementFailure> {
    match rows {
        [] => Ok(None),
        [row] => row.try_get::<_, i64>(0).map(Some).map_err(|_| invalid()),
        _ => Err(invalid()),
    }
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

/// Parse the `MAILBOX_UPDATE` row count into Go's found boolean.
pub fn parse_updated(rows: &[Row]) -> Result<bool, StatementFailure> {
    match rows {
        [row] => row
            .try_get::<_, i64>(0)
            .map(|n| n > 0)
            .map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}

/// Go's `mailbox_lifecycle_enabled()` gate.
pub async fn lifecycle_enabled(factory: &TxFactory) -> Result<bool, StatementFailure> {
    let rows = factory
        .run_public_read_contract(&sql::LIFECYCLE_ENABLED, &[])
        .await?;
    super::first_bool(&rows)
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

/// Decode the reducer JSON verdict returned by [`sql::FOLDER_CREATE`].
pub fn folder_create_verdict(rows: &[Row]) -> Result<i64, StatementFailure> {
    verdict(rows, &[201])?["id"].as_i64().ok_or_else(invalid)
}

/// Decode the reducer JSON verdict returned by [`sql::FOLDER_UPDATE`] or
/// [`sql::FOLDER_DELETE`].
pub fn folder_mut_verdict(rows: &[Row]) -> Result<(), StatementFailure> {
    verdict(rows, &[204]).map(|_| ())
}
