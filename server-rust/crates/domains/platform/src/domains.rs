//! Platform slice `terms-remaining`, group `domains`: the admin email-domain editor
//! (`/admin/domains*`), Go's `DomainsHandler`.
use super::{command, deadline, done, envelope, invalid, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

fn render(row: &setjoin_pg::Row, strict: bool) -> Result<String, StatementFailure> {
    let bad = |_| invalid();
    let id: i64 = row.try_get(0).map_err(bad)?;
    let name: String = row.try_get(1).map_err(bad)?;
    let primary: bool = row.try_get(2).map_err(bad)?;
    let local: bool = row.try_get(3).map_err(bad)?;
    let catch_all: Option<i64> = row.try_get(4).map_err(bad)?;
    let text = |index: usize| -> Result<Option<String>, StatementFailure> {
        let value: Option<String> = row.try_get(index).map_err(bad)?;
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

/// `GET /admin/domains`: every domain, or the principal's own when domain scoped.
pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::DOMAINS_LIST, &[&domain_scope])
        .await?;
    let items: Vec<String> = rows.iter().filter_map(|r| render(r, false).ok()).collect();
    Ok(done(format!("[{}]", items.join(","))))
}

/// `GET /admin/domains/{id}`: `None` is Go's 404; a NULL text column is Go's 500.
pub async fn get(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::DOMAINS_GET, &[&id])
        .await?;
    match rows.first() {
        None => Ok(None),
        Some(row) => Ok(Some(done(render(row, true)?))),
    }
}

pub struct New {
    pub name: String,
    pub is_local: bool,
    pub is_primary: bool,
    pub dmarc_policy: String,
    pub mta_sts_policy: String,
    pub max_message_bytes: i64,
    pub quota_bytes: Option<i64>,
}

pub enum Created {
    Id(i64),
    Conflict,
}

pub async fn create(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    d: &New,
    operation: [u8; 16],
) -> CommandOutcome<Created, StatementFailure> {
    let payload = format!("create:{}", d.name);
    let env = envelope(user.user(), user.generation(), operation, &payload);
    let outcome = factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::DOMAINS_CREATE,
            &[
                &d.name,
                &d.is_local,
                &d.is_primary,
                &d.dmarc_policy,
                &d.mta_sts_policy,
                &d.max_message_bytes,
                &d.quota_bytes,
            ],
            Some(command("domain_create")),
            |rows| {
                rows.first()
                    .filter(|_| rows.len() == 1)
                    .and_then(|r| r.try_get::<_, i64>(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await;
    match outcome {
        CommandOutcome::Committed(id) => CommandOutcome::Committed(Created::Id(id)),
        CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e))
            if e.sqlstate.as_deref() == Some("23505") =>
        {
            CommandOutcome::Committed(Created::Conflict)
        }
        CommandOutcome::RolledBack(e) => CommandOutcome::RolledBack(e),
        CommandOutcome::Unknown { operation } => CommandOutcome::Unknown { operation },
    }
}

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

/// `PUT`: `Ok(true)` when a row matched. `SetStr` skips empty strings.
pub async fn update(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    id: i64,
    domain_scope: i64,
    p: &Patch,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let name: Option<&str> = p.name.as_deref().filter(|t| !t.is_empty());
    let dmarc: Option<&str> = p.dmarc_policy.as_deref().filter(|t| !t.is_empty());
    let mta: Option<&str> = p.mta_sts_policy.as_deref().filter(|t| !t.is_empty());
    let payload = format!("update:{id}:{name:?}:{dmarc:?}:{mta:?}");
    let env = envelope(user.user(), user.generation(), operation, &payload);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::DOMAINS_UPDATE,
            &[
                &name,
                &p.is_local,
                &p.is_primary,
                &p.catch_all_mailbox_id,
                &dmarc,
                &mta,
                &p.max_message_bytes,
                &p.quota_bytes,
                &id,
                &domain_scope,
            ],
            Some(command("domain_update")),
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
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    id: i64,
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("delete:{id}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::DOMAINS_DELETE,
            &[&id, &domain_scope],
            Some(command("domain_delete")),
            |_| Ok(()),
        )
        .await
}
