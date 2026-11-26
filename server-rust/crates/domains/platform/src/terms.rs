//! Platform slice `terms-remaining`, group `terms`: the admin terms-of-use editor
//! (`/admin/terms-of-use`), Go's `ToUHandler`.
use super::{command, deadline, done, envelope, invalid, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::{CommandOutcome, StatementFailure};

pub fn limit(raw: Option<&str>) -> i64 {
    let n = raw
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(100);
    n.min(500)
}

/// `GET /admin/terms-of-use`.
pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    limit: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::TERMS_LIST, &[&limit])
        .await?;
    let bad = |_| invalid();
    let mut out = Vec::new();
    for r in &rows {
        out.push(format!(
            "{{\"id\":{},\"name\":{},\"version\":{},\"body_md\":{},\"lang\":{},\"require_scroll\":{},\"enabled\":{},\"created_at\":{}}}",
            r.try_get::<_, i64>(0).map_err(bad)?,
            s(&r.try_get::<_, String>(1).map_err(bad)?),
            r.try_get::<_, i64>(2).map_err(bad)?,
            s(&r.try_get::<_, String>(3).map_err(bad)?),
            s(&r.try_get::<_, String>(4).map_err(bad)?),
            r.try_get::<_, bool>(5).map_err(bad)?,
            r.try_get::<_, bool>(6).map_err(bad)?,
            s(&r.try_get::<_, String>(7).map_err(bad)?),
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

pub struct Document {
    pub name: String,
    pub version: i64,
    pub body_md: String,
    pub lang: String,
    pub require_scroll: bool,
    pub enabled: bool,
}
impl Document {
    pub fn valid(&self) -> bool {
        !self.name.is_empty() && !self.body_md.is_empty() && self.version >= 1
    }
    fn lang(&self) -> &str {
        if self.lang.is_empty() {
            "en"
        } else {
            &self.lang
        }
    }
}

pub enum Done {
    Created(i64),
    Updated,
    NotFound,
}

fn status_of(rows: &[setjoin_pg::Row]) -> Result<serde_json::Value, StatementFailure> {
    let text: String = rows
        .first()
        .filter(|_| rows.len() == 1)
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)?;
    serde_json::from_str(&text).map_err(|_| invalid())
}

/// `POST`: insert and audit.
pub async fn create(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    doc: &Document,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Done, StatementFailure> {
    let payload = format!("create:{}:{}", doc.name, doc.version);
    let env = envelope(admin.actor(), admin.generation(), operation, &payload);
    let lang = doc.lang();
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::TERMS_CREATE,
            &[
                &doc.name,
                &doc.version,
                &doc.body_md,
                &lang,
                &doc.require_scroll,
                &doc.enabled,
                &ip,
            ],
            Some(command("tou_create")),
            |rows, _audited| {
                let doc = status_of(&rows)?;
                Ok(Done::Created(doc["id"].as_i64().ok_or_else(invalid)?))
            },
        )
        .await
}

/// `PUT`: update and audit; a missing id writes nothing.
pub async fn update(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
    doc: &Document,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Done, StatementFailure> {
    let payload = format!("update:{id}:{}:{}", doc.name, doc.version);
    let env = envelope(admin.actor(), admin.generation(), operation, &payload);
    let lang = doc.lang();
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::TERMS_UPDATE,
            &[
                &id,
                &doc.name,
                &doc.version,
                &doc.body_md,
                &lang,
                &doc.require_scroll,
                &doc.enabled,
                &ip,
            ],
            Some(command("tou_update")),
            |rows, _audited| outcome(&status_of(&rows)?),
        )
        .await
}

/// `DELETE`: capture, delete and audit; a missing id writes nothing.
pub async fn delete(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Done, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("delete:{id}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::TERMS_DELETE,
            &[&id, &ip],
            Some(command("tou_delete")),
            |rows, _audited| outcome(&status_of(&rows)?),
        )
        .await
}

fn outcome(doc: &serde_json::Value) -> Result<Done, StatementFailure> {
    match doc["status"].as_i64() {
        Some(204) => Ok(Done::Updated),
        Some(404) => Ok(Done::NotFound),
        _ => Err(invalid()),
    }
}
