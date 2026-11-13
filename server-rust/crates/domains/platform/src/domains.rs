//! Platform slice `terms-remaining`, group `domains`: the admin email-domain editor
//! (`/admin/domains*`), Go's `DomainsHandler`.
//!
//! Go writes through the pool with one statement per request and no audit row, so each
//! write is one receipted statement. The domain scope of the verified principal both gates
//! the handler (as Go) and rides in the write's WHERE (R3).
use super::{command, deadline, done, envelope, invalid, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

const COLUMNS: &str = "id, name, is_primary, is_local, catch_all_mailbox_id, dkim_selector, \
    dkim_key_expires_at::TEXT, spf_record, dmarc_policy, dmarc_rua, dmarc_ruf, mta_sts_policy, \
    max_message_bytes, quota_bytes, created_at::TEXT";

/// One `domainResponse` row; Go's `omitempty` fields are skipped when empty.
fn render(row: &setjoin_pg::Row, strict: bool) -> Result<String, StatementFailure> {
    let bad = |_| invalid();
    let id: i64 = row.try_get(0).map_err(bad)?;
    let name: String = row.try_get(1).map_err(bad)?;
    let primary: bool = row.try_get(2).map_err(bad)?;
    let local: bool = row.try_get(3).map_err(bad)?;
    let catch_all: Option<i64> = row.try_get(4).map_err(bad)?;
    let text = |index: usize| -> Result<Option<String>, StatementFailure> {
        let value: Option<String> = row.try_get(index).map_err(bad)?;
        // Go's `Get` scans these straight into `string`: pgx refuses a NULL there.
        if strict && value.is_none() && matches!(index, 5 | 7 | 9 | 10) {
            return Err(invalid());
        }
        Ok(value)
    };
    let (selector, expires, spf) = (text(5)?, text(6)?, text(7)?);
    let dmarc: String = row.try_get(8).map_err(bad)?;
    let (rua, ruf) = (text(9)?, text(10)?);
    let mta: String = row.try_get(11).map_err(bad)?;
    let max: i64 = row.try_get(12).map_err(bad)?;
    let quota: Option<i64> = row.try_get(13).map_err(bad)?;
    let created: String = row.try_get(14).map_err(bad)?;
    let mut out = format!(
        "{{\"id\":{id},\"name\":{},\"isPrimary\":{primary},\"isLocal\":{local}",
        s(&name)
    );
    if let Some(n) = catch_all {
        out += &format!(",\"catchAllMailboxId\":{n}");
    }
    fn optional(out: &mut String, key: &str, value: &Option<String>) {
        if let Some(v) = value.as_ref().filter(|v| !v.is_empty()) {
            *out += &format!(",\"{key}\":{}", s(v));
        }
    }
    optional(&mut out, "dkimSelector", &selector);
    if let Some(v) = &expires {
        out += &format!(",\"dkimKeyExpiresAt\":{}", s(v));
    }
    optional(&mut out, "spfRecord", &spf);
    out += &format!(",\"dmarcPolicy\":{}", s(&dmarc));
    optional(&mut out, "dmarcRua", &rua);
    optional(&mut out, "dmarcRuf", &ruf);
    out += &format!(",\"mtaStsPolicy\":{},\"maxMessageBytes\":{max}", s(&mta));
    if let Some(n) = quota {
        out += &format!(",\"quotaBytes\":{n}");
    }
    out += &format!(",\"createdAt\":{}}}", s(&created));
    Ok(out)
}

/// `GET /admin/domains`: every domain, or the principal's own when domain scoped. A row
/// that fails to scan is skipped, as Go does.
pub async fn list(exec: &ScopedExecutor, domain_scope: i64) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            &format!(
                "SELECT {COLUMNS} FROM domains WHERE ($1::bigint = 0 OR id = $1::bigint) \
                 ORDER BY is_primary DESC, name ASC"
            ),
            &[(&domain_scope, Type::INT8)],
        )
        .await?;
    let items: Vec<String> = rows.iter().filter_map(|r| render(r, false).ok()).collect();
    Ok(done(format!("[{}]", items.join(","))))
}

/// `GET /admin/domains/{id}`: `None` is Go's 404; a NULL text column is Go's 500.
pub async fn get(exec: &ScopedExecutor, id: i64) -> Result<Option<String>, StatementFailure> {
    let rows = exec
        .read(
            &format!("SELECT {COLUMNS} FROM domains WHERE id = $1::bigint"),
            &[(&id, Type::INT8)],
        )
        .await?;
    match rows.first() {
        None => Ok(None),
        Some(row) => Ok(Some(done(render(row, true)?))),
    }
}

/// A decoded create body.
pub struct New {
    pub name: String,
    pub is_local: bool,
    pub is_primary: bool,
    pub dmarc_policy: String,
    pub mta_sts_policy: String,
    pub max_message_bytes: i64,
    pub quota_bytes: Option<i64>,
}

/// What a create decided.
pub enum Created {
    Id(i64),
    Conflict,
}

pub async fn create(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    d: &New,
    operation: [u8; 16],
) -> CommandOutcome<Created, StatementFailure> {
    let auth = scope(actor);
    let payload = format!("create:{}", d.name);
    let outcome = setjoin_pg::run_receipted_command(
        exec,
        command("domain_create"),
        &envelope(&auth, operation, &payload),
        &auth,
        deadline(),
        "INSERT INTO domains (name, is_local, is_primary, dmarc_policy, mta_sts_policy, max_message_bytes, quota_bytes) \
         SELECT $4::text, $5::bool, $6::bool, $7::text, $8::text, $9::bigint, $10::bigint \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING id",
        &[
            (&d.name, Type::TEXT),
            (&d.is_local, Type::BOOL),
            (&d.is_primary, Type::BOOL),
            (&d.dmarc_policy, Type::TEXT),
            (&d.mta_sts_policy, Type::TEXT),
            (&d.max_message_bytes, Type::INT8),
            (&d.quota_bytes, Type::INT8),
        ],
        |rows| {
            if rows.len() == 1 {
                rows[0].try_get::<_, i64>(0).map_err(|_| invalid())
            } else {
                Err(invalid())
            }
        },
    )
    .await;
    match outcome {
        CommandOutcome::Committed(id) => CommandOutcome::Committed(Created::Id(id)),
        // Go: SQLSTATE 23505 is the only error with its own answer (409).
        CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e))
            if e.sqlstate.as_deref() == Some("23505") =>
        {
            CommandOutcome::Committed(Created::Conflict)
        }
        CommandOutcome::RolledBack(e) => CommandOutcome::RolledBack(e),
        CommandOutcome::Unknown { operation } => CommandOutcome::Unknown { operation },
    }
}

/// The patch Go's `UpdateBuilder` assembles; `None` fields are not written.
#[derive(Default)]
pub struct Patch {
    pub name: Option<String>,
    pub is_local: Option<bool>,
    pub is_primary: Option<bool>,
    pub catch_all_mailbox_id: Option<i64>,
    pub dmarc_policy: Option<String>,
    pub mta_sts_policy: Option<String>,
    pub max_message_bytes: Option<i64>,
    pub quota_bytes: Option<i64>,
}

impl Patch {
    /// Go's `ErrNoFields`: `SetStr` skips an empty string.
    pub fn is_empty(&self) -> bool {
        let text = |v: &Option<String>| v.as_ref().is_some_and(|t| !t.is_empty());
        !(text(&self.name)
            || text(&self.dmarc_policy)
            || text(&self.mta_sts_policy)
            || self.is_local.is_some()
            || self.is_primary.is_some()
            || self.catch_all_mailbox_id.is_some()
            || self.max_message_bytes.is_some()
            || self.quota_bytes.is_some())
    }
}

/// `PUT`: `Ok(true)` when a row matched. Columns appear in Go's order; `SetStr` skips an
/// empty string. The caller has already refused an empty patch.
pub async fn update(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    domain_scope: i64,
    p: &Patch,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    let mut sets: Vec<String> = Vec::new();
    let mut params: Vec<setjoin_pg::Param<'_>> = Vec::new();
    fn push<'a>(
        params: &mut Vec<setjoin_pg::Param<'a>>,
        sets: &mut Vec<String>,
        column: &str,
        cast: &str,
        param: setjoin_pg::Param<'a>,
    ) {
        params.push(param);
        sets.push(format!("{column} = ${}::{cast}", params.len() + 3));
    }
    fn non_empty(v: &Option<String>) -> Option<&String> {
        v.as_ref().filter(|t| !t.is_empty())
    }
    if let Some(v) = non_empty(&p.name) {
        push(&mut params, &mut sets, "name", "text", (v, Type::TEXT));
    }
    if let Some(v) = &p.is_local {
        push(&mut params, &mut sets, "is_local", "bool", (v, Type::BOOL));
    }
    if let Some(v) = &p.is_primary {
        push(
            &mut params,
            &mut sets,
            "is_primary",
            "bool",
            (v, Type::BOOL),
        );
    }
    if let Some(v) = &p.catch_all_mailbox_id {
        push(
            &mut params,
            &mut sets,
            "catch_all_mailbox_id",
            "bigint",
            (v, Type::INT8),
        );
    }
    if let Some(v) = non_empty(&p.dmarc_policy) {
        push(
            &mut params,
            &mut sets,
            "dmarc_policy",
            "text",
            (v, Type::TEXT),
        );
    }
    if let Some(v) = non_empty(&p.mta_sts_policy) {
        push(
            &mut params,
            &mut sets,
            "mta_sts_policy",
            "text",
            (v, Type::TEXT),
        );
    }
    if let Some(v) = &p.max_message_bytes {
        push(
            &mut params,
            &mut sets,
            "max_message_bytes",
            "bigint",
            (v, Type::INT8),
        );
    }
    if let Some(v) = &p.quota_bytes {
        push(
            &mut params,
            &mut sets,
            "quota_bytes",
            "bigint",
            (v, Type::INT8),
        );
    }
    let at = params.len() + 4;
    params.push((&id, Type::INT8));
    params.push((&domain_scope, Type::INT8));
    let sql = format!(
        "UPDATE domains SET {}, updated_at = now() WHERE id = ${at}::bigint \
         AND (${}::bigint = 0 OR id = ${}::bigint) \
         AND $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING id",
        sets.join(", "),
        at + 1,
        at + 1
    );
    let payload = format!("update:{id}:{}", sets.join(","));
    setjoin_pg::run_receipted_command(
        exec,
        command("domain_update"),
        &envelope(&auth, operation, &payload),
        &auth,
        deadline(),
        &sql,
        &params,
        |rows| match rows.len() {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid()),
        },
    )
    .await
}

/// `DELETE`: Go answers 204 whether or not a row matched.
pub async fn delete(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("domain_delete"),
        &envelope(&auth, operation, &format!("delete:{id}")),
        &auth,
        deadline(),
        "DELETE FROM domains WHERE id = $4::bigint AND ($5::bigint = 0 OR id = $5::bigint) \
         AND $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING id",
        &[(&id, Type::INT8), (&domain_scope, Type::INT8)],
        |_| Ok(()),
    )
    .await
}
