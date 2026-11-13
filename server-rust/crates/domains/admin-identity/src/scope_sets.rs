//! Admin identity (F01) slice `scope-sets`: named governed scope containers.
//!
//! Reads are `SELECT`s under the verified actor. Each write calls one reducer
//! mirroring Go's whole handler (`rust_admin_scope_set_*`): the mutation and its
//! audit row commit together (Go audits in a second autocommit). Reducers answer
//! `{status,detail}`; every status other than the success one rolls the command
//! back, so a refusal leaves neither data nor a receipt. Duplicate names raise
//! 23505 for the adapter to answer Go's 409.
use super::{count as _count, deadline, done, envelope, invalid, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{
    CommandOutcome, ReceiptCommand, Rejection, Row, ScopedExecutor, StatementFailure, Type,
};

/// `scope_sets.manage`: the only gate of every route in this slice.
pub const SCOPE_SETS_MANAGE: [&str; 1] = ["scope_sets.manage"];

/// A refusal decided by a reducer, carried through the executor as a rolled-back body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub status: u16,
    pub detail: String,
}

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

/// Go's `%q` for the duplicate-name message: a double-quoted Go string literal.
pub fn go_quote(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            '\u{fffd}' => out.push('\u{fffd}'),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if is_printable(c) => out.push(c),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push('"');
    out
}

/// A close approximation of Go's `strconv.IsPrint` for `%q`: graphic characters
/// and the ASCII space; format, separator, private-use and unassigned code
/// points are escaped.
fn is_printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    if c.is_control() || c.is_whitespace() {
        return false;
    }
    let u = c as u32;
    !matches!(u,
        0x80..=0x9f | 0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x8e2
        | 0x180e | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x206f
        | 0xe000..=0xf8ff | 0xfeff | 0xfff9..=0xfffb | 0xf0000..=0x10ffff)
}

const SET_COLUMNS: &str =
    "id, name, domain_id, COALESCE(description,''), created_by, created_at::TEXT, updated_at::TEXT";

fn set_json(row: &Row) -> Result<String, StatementFailure> {
    let bad = |_| invalid();
    let domain = row.try_get::<_, Option<i64>>(2).map_err(bad)?;
    let by = row.try_get::<_, Option<i64>>(4).map_err(bad)?;
    Ok(format!(
        "{{\"id\":{},\"name\":{}{},\"description\":{}{},\"createdAt\":{},\"updatedAt\":{}}}",
        row.try_get::<_, i64>(0).map_err(bad)?,
        s(&row.try_get::<_, String>(1).map_err(bad)?),
        domain
            .map(|d| format!(",\"domainId\":{d}"))
            .unwrap_or_default(),
        s(&row.try_get::<_, String>(3).map_err(bad)?),
        by.map(|d| format!(",\"createdBy\":{d}"))
            .unwrap_or_default(),
        s(&row.try_get::<_, String>(5).map_err(bad)?),
        s(&row.try_get::<_, String>(6).map_err(bad)?),
    ))
}

/// SQL for the caller's domain restriction (`$1` is the actor): 0 for a live organization-wide
/// `scope_sets.manage` grant, a domain id, or -1 (no usable grant, matches nothing). Owner-approved
/// security fix 2026-11-05 (#384, #510): a domain-scoped admin sees and changes only the sets owned
/// by its own domain; frozen Go applied no tenant filter. Derived from grants that carry the
/// permission, never from a Rust-computed scope; the reducers compute the same value themselves.
fn restriction_sql() -> &'static str {
    if setjoin_contracts::mutants::on("scopeset-unscoped") {
        "0::bigint"
    } else {
        "admin_domain_restriction($1, '{scope_sets.manage}'::text[])"
    }
}

/// `GET /admin/scope-sets`: a scan failure is Go's 500.
pub async fn list(exec: &ScopedExecutor, actor: &AuthContext) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read(
            &format!("SELECT {SET_COLUMNS} FROM admin_scope_sets WHERE (({r}) = 0 OR domain_id = ({r})) ORDER BY name", r = restriction_sql()),
            &[(&user, Type::INT8)],
        )
        .await?;
    let out = rows.iter().map(set_json).collect::<Result<Vec<_>, _>>()?;
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/scope-sets/{id}`; `None` is Go's 404. Members come with a label
/// resolved per type (department name, group display name, user email).
pub async fn get(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read(
            &format!("SELECT {SET_COLUMNS} FROM admin_scope_sets WHERE id = $2 AND (({r}) = 0 OR domain_id = ({r}))", r = restriction_sql()),
            &[(&user, Type::INT8), (&id, Type::INT8)],
        )
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let set = set_json(row)?;
    let members = exec
        .read(
            "SELECT m.member_type, m.member_id, m.added_by, m.added_at::TEXT, \
             CASE m.member_type WHEN 'ou' THEN d.name WHEN 'group' THEN mb.display_name WHEN 'user' THEN u.email END AS label \
             FROM admin_scope_set_members m \
             LEFT JOIN departments d ON m.member_type = 'ou' AND d.id = m.member_id \
             LEFT JOIN distribution_groups dg ON m.member_type = 'group' AND dg.id = m.member_id \
             LEFT JOIN mailboxes mb ON m.member_type = 'group' AND mb.id = dg.mailbox_id \
             LEFT JOIN users u ON m.member_type = 'user' AND u.id = m.member_id \
             WHERE m.set_id = $1 ORDER BY m.member_type, m.member_id",
            &[(&id, Type::INT8)],
        )
        .await?;
    let bad = |_| invalid();
    let mut out = Vec::new();
    for m in &members {
        let by = m.try_get::<_, Option<i64>>(2).map_err(bad)?;
        let label = m.try_get::<_, Option<String>>(4).map_err(bad)?;
        out.push(format!(
            "{{\"memberType\":{},\"memberId\":{}{},\"addedAt\":{}{}}}",
            s(&m.try_get::<_, String>(0).map_err(bad)?),
            m.try_get::<_, i64>(1).map_err(bad)?,
            by.map(|b| format!(",\"addedBy\":{b}")).unwrap_or_default(),
            s(&m.try_get::<_, String>(3).map_err(bad)?),
            label
                .map(|l| format!(",\"label\":{}", s(&l)))
                .unwrap_or_default(),
        ));
    }
    Ok(Some(done(format!(
        "{{\"members\":[{}],\"set\":{set}}}",
        out.join(",")
    ))))
}

/// Go's `RequireReason`: whether `scope_sets` is a reason-required audit area.
pub async fn reason_required(exec: &ScopedExecutor) -> bool {
    exec.read(
        "SELECT 'scope_sets'=ANY(reason_required_areas) FROM audit_policy WHERE id=1",
        &[],
    )
    .await
    .ok()
    .and_then(|r| r.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
    .unwrap_or(false)
}

/// The durable `sensitive_action.reason_missing` row Go writes before its 400.
pub async fn missing_reason(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    operation: [u8; 16],
) {
    let auth = scope(actor);
    let _ = setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F01",
            command: "reason_missing",
        },
        &envelope(&auth, operation, ip),
        &auth,
        deadline(),
        "SELECT count(*)::bigint FROM (SELECT audit_write($2,'sensitive_action.reason_missing','',NULL,NULL,NULL,NULLIF($4::text,'')::inet,'scope_sets.manage','core') \
         WHERE $1::bigint > 0 AND $3::text <> '') w",
        &[(&ip, Type::TEXT)],
        _count,
    )
    .await;
}

/// The reducer verdict of a committed command: success statuses commit, any
/// other status rolls the command back carrying Go's problem.
fn verdict(rows: &[Row], success: &[u64]) -> Result<u16, StatementFailure> {
    let text: String = rows
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| invalid())?;
    match v["status"].as_u64() {
        Some(status) if success.contains(&status) => Ok(status as u16),
        Some(_) if v["detail"].is_string() => Err(StatementFailure {
            sqlstate: None,
            hint: None,
            message: text,
        }),
        _ => Err(invalid()),
    }
}

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: "F01",
        command: name,
    }
}

/// `POST /admin/scope-sets` after the edge validation; the new set id.
pub async fn create(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    name: &str,
    domain: Option<i64>,
    description: &str,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("scope_set_create"),
        &envelope(&auth, operation, &format!("{name}:{domain:?}:{description}")),
        &auth,
        deadline(),
        "SELECT rust_admin_scope_set_create($2,$4,$5,$6,$7) WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&name, Type::TEXT),
            (&domain, Type::INT8),
            (&description, Type::TEXT),
            (&ip, Type::TEXT),
        ],
        |rows| match rows {
            [row] => match row.try_get::<_, Option<i64>>(0).map_err(|_| invalid())? {
                Some(id) => Ok(id),
                // A restricted actor may only create a set owned by its own domain.
                None => Err(StatementFailure {
                    sqlstate: None,
                    hint: None,
                    message: "{\"status\":403,\"detail\":\"scope set domain is outside your administrative scope\"}".into(),
                }),
            },
            _ => Err(invalid()),
        },
    )
    .await
}

/// `PUT /admin/scope-sets/{id}`: a missing set is Go's 404 (`Committed(false)` never occurs).
pub async fn update(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    name: Option<&str>,
    description: Option<&str>,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("scope_set_update"),
        &envelope(&auth, operation, &format!("{id}:{name:?}:{description:?}")),
        &auth,
        deadline(),
        "SELECT json_build_object('status',CASE WHEN rust_admin_scope_set_update($2,$4,$5,$6,$7) THEN 204 ELSE 404 END,'detail','scope set not found')::text \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&id, Type::INT8),
            (&name, Type::TEXT),
            (&description, Type::TEXT),
            (&ip, Type::TEXT),
        ],
        |rows| verdict(rows, &[204]).map(|_| ()),
    )
    .await
}

pub async fn delete(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("scope_set_delete"),
        &envelope(&auth, operation, &id.to_string()),
        &auth,
        deadline(),
        "SELECT rust_admin_scope_set_delete($2,$4,$5)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&id, Type::INT8), (&ip, Type::TEXT)],
        |rows| verdict(rows, &[204]).map(|_| ()),
    )
    .await
}

/// `POST /admin/scope-sets/{id}/members`: 201 added, 200 already a member.
pub async fn add_member(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    set: i64,
    member_type: &str,
    member: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<u16, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("scope_set_member_add"),
        &envelope(&auth, operation, &format!("{set}:{member_type}:{member}")),
        &auth,
        deadline(),
        "SELECT rust_admin_scope_set_member_add($2,$4,$5,$6,$7)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&set, Type::INT8),
            (&member_type, Type::TEXT),
            (&member, Type::INT8),
            (&ip, Type::TEXT),
        ],
        |rows| verdict(rows, &[200, 201]),
    )
    .await
}

pub async fn remove_member(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    set: i64,
    member_type: &str,
    member: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("scope_set_member_remove"),
        &envelope(&auth, operation, &format!("{set}:{member_type}:{member}")),
        &auth,
        deadline(),
        "SELECT rust_admin_scope_set_member_remove($2,$4,$5,$6,$7)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&set, Type::INT8),
            (&member_type, Type::TEXT),
            (&member, Type::INT8),
            (&ip, Type::TEXT),
        ],
        |rows| verdict(rows, &[204]).map(|_| ()),
    )
    .await
}
