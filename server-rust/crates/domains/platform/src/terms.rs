//! Platform slice `terms-remaining`, group `terms`: the admin terms-of-use editor
//! (`/admin/terms-of-use`), Go's `ToUHandler`.
//!
//! The list is one read. Create, update and delete are each Go's whole transaction (the
//! row write plus the core audit row), mirrored by the `rust_platform_tou_*` reducers; the
//! actor is the verified token's user and the path id only names the target.
use super::{command, deadline, done, envelope, invalid, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

/// Go's `parseTouLimit`: `?limit=` clamped to `[1, 500]`, 100 by default.
pub fn limit(raw: Option<&str>) -> i64 {
    let n = raw
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(100);
    n.min(500)
}

/// `GET /admin/terms-of-use`: documents ordered by name. `created_at` renders as Postgres'
/// own text, exactly like Go's `created_at::text`.
pub async fn list(exec: &ScopedExecutor, limit: i64) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT id, name, version::bigint, body_md, lang, require_scroll, enabled, created_at::text \
             FROM terms_of_use ORDER BY name ASC LIMIT $1",
            &[(&limit, Type::INT8)],
        )
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

/// A decoded create/update body (Go's `touRequest`).
pub struct Document {
    pub name: String,
    pub version: i64,
    pub body_md: String,
    pub lang: String,
    pub require_scroll: bool,
    pub enabled: bool,
}
impl Document {
    /// Go's `touCreateValid`.
    pub fn valid(&self) -> bool {
        !self.name.is_empty() && !self.body_md.is_empty() && self.version >= 1
    }
    /// An empty language defaults to `en`.
    fn lang(&self) -> &str {
        if self.lang.is_empty() {
            "en"
        } else {
            &self.lang
        }
    }
}

/// What a reducer decided.
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    doc: &Document,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Done, StatementFailure> {
    let auth = scope(actor);
    let payload = format!("create:{}:{}", doc.name, doc.version);
    setjoin_pg::run_receipted_command(
        exec,
        command("tou_create"),
        &envelope(&auth, operation, &payload),
        &auth,
        deadline(),
        "SELECT public.rust_platform_tou_create($2::bigint, $4::text, $5::bigint, $6::text, $7::text, $8::bool, $9::bool, $10::text)::text \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[
            (&doc.name, Type::TEXT),
            (&doc.version, Type::INT8),
            (&doc.body_md, Type::TEXT),
            (&doc.lang(), Type::TEXT),
            (&doc.require_scroll, Type::BOOL),
            (&doc.enabled, Type::BOOL),
            (&ip, Type::TEXT),
        ],
        |rows| {
            let doc = status_of(rows)?;
            Ok(Done::Created(doc["id"].as_i64().ok_or_else(invalid)?))
        },
    )
    .await
}

/// `PUT`: update and audit; a missing id writes nothing.
pub async fn update(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    doc: &Document,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Done, StatementFailure> {
    let auth = scope(actor);
    let payload = format!("update:{id}:{}:{}", doc.name, doc.version);
    setjoin_pg::run_receipted_command(
        exec,
        command("tou_update"),
        &envelope(&auth, operation, &payload),
        &auth,
        deadline(),
        "SELECT public.rust_platform_tou_update($2::bigint, $4::bigint, $5::text, $6::bigint, $7::text, $8::text, $9::bool, $10::bool, $11::text)::text \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[
            (&id, Type::INT8),
            (&doc.name, Type::TEXT),
            (&doc.version, Type::INT8),
            (&doc.body_md, Type::TEXT),
            (&doc.lang(), Type::TEXT),
            (&doc.require_scroll, Type::BOOL),
            (&doc.enabled, Type::BOOL),
            (&ip, Type::TEXT),
        ],
        |rows| outcome(&status_of(rows)?),
    )
    .await
}

/// `DELETE`: capture, delete and audit; a missing id writes nothing.
pub async fn delete(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<Done, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("tou_delete"),
        &envelope(&auth, operation, &format!("delete:{id}")),
        &auth,
        deadline(),
        "SELECT public.rust_platform_tou_delete($2::bigint, $4::bigint, $5::text)::text \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[(&id, Type::INT8), (&ip, Type::TEXT)],
        |rows| outcome(&status_of(rows)?),
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
