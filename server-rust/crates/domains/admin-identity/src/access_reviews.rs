//! Admin identity (F01) slice `access-reviews`: recertification campaigns.
//!
//! Reads are `SELECT`s that repeat Go's queries. Every write calls the existing
//! `access_review_*` reducer exactly as Go does (the reducers already commit data
//! and audit in one statement, so no new reducer is needed); the receipt joins
//! the same transaction. A reducer `BZ0xx` exception rolls the command back and
//! is projected by the adapter like Go's `reducererr.WriteClassified`.
use super::{count as _count, deadline, envelope, invalid, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{
    CommandOutcome, ReceiptCommand, Rejection, ScopedExecutor, StatementFailure, Type,
};

/// `roles.manage`: the only gate of every route in this slice (Go's `requireRolesManage`).
pub const ROLES_MANAGE: [&str; 1] = ["roles.manage"];

/// One reducer exception as Go's `WriteClassified` projects it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reducer {
    pub status: u16,
    pub code: String,
    pub detail: String,
    pub remediation: &'static str,
}

const NOT_FOUND: &str =
    "Refresh the target identifier and retry only if the resource still exists.";
const FORBIDDEN: &str =
    "Complete the required authorization, approval, or recovery step before retrying.";
const CONFLICT: &str = "Refresh current state, resolve the conflict, and retry.";

/// The reducer codes these routes can raise (campaign guard, SoD, close-time
/// deletes guarded by the admin protection triggers). Messages pass through.
pub fn reducer_of(error: &Rejection<StatementFailure>) -> Option<Reducer> {
    let (Rejection::Statement(e) | Rejection::Body(e)) = error else {
        return None;
    };
    let code = e.sqlstate.as_deref()?;
    let (status, remediation) = match code {
        "BZ060" => (404, NOT_FOUND),
        "BZ061" | "BZ065" | "BZ066" | "BZ069" => (403, FORBIDDEN),
        "BZ062" | "BZ063" | "BZ064" => (409, CONFLICT),
        _ => return None,
    };
    Some(Reducer {
        status,
        code: code.to_owned(),
        detail: e.message.clone(),
        remediation,
    })
}

#[allow(clippy::too_many_arguments)]
/// Go's `campaignRow`: `closedBy` and `closedAt` are omitted when null.
fn campaign_json(
    id: i64,
    name: &str,
    status: &str,
    counts: (i32, i32),
    created_by: &str,
    created_at: &str,
    closed_by: Option<String>,
    closed_at: Option<String>,
) -> String {
    format!(
        "{{\"id\":{id},\"name\":{},\"status\":{},\"reviewed\":{},\"total\":{},\"createdBy\":{},\"createdAt\":{}{}{}}}",
        s(name),
        s(status),
        counts.0,
        counts.1,
        s(created_by),
        s(created_at),
        closed_by
            .map(|v| format!(",\"closedBy\":{}", s(&v)))
            .unwrap_or_default(),
        closed_at
            .map(|v| format!(",\"closedAt\":{}", s(&v)))
            .unwrap_or_default(),
    )
}

/// `GET /admin/access-reviews`: the caller's in-scope campaigns, open first.
pub async fn list(exec: &ScopedExecutor, domain_scope: i64) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT c.id, c.name, c.status, \
             COUNT(i.id) FILTER (WHERE i.decision <> 'undecided')::int, COUNT(i.id)::int, \
             u.email, c.created_at::text, cu.email, c.closed_at::text \
             FROM access_review_campaigns c \
             JOIN users u ON u.id = c.created_by \
             LEFT JOIN users cu ON cu.id = c.closed_by \
             LEFT JOIN access_review_items i ON i.campaign_id = c.id \
             WHERE $1 <= 0 OR c.domain_scope = $1 \
             GROUP BY c.id, u.email, cu.email \
             ORDER BY (c.status='open') DESC, c.created_at DESC",
            &[(&domain_scope, Type::INT8)],
        )
        .await?;
    let bad = |_| invalid();
    let mut out = Vec::new();
    for r in &rows {
        out.push(campaign_json(
            r.try_get(0).map_err(bad)?,
            &r.try_get::<_, String>(1).map_err(bad)?,
            &r.try_get::<_, String>(2).map_err(bad)?,
            (r.try_get(3).map_err(bad)?, r.try_get(4).map_err(bad)?),
            &r.try_get::<_, String>(5).map_err(bad)?,
            &r.try_get::<_, String>(6).map_err(bad)?,
            r.try_get(7).map_err(bad)?,
            r.try_get(8).map_err(bad)?,
        ));
    }
    Ok(super::done(format!("[{}]", out.join(","))))
}

/// `GET /admin/access-reviews/{id}`; `None` is Go's 404 (missing or out of scope).
/// Go scans a NULL email, role name or self flag (a deleted user or role) into a
/// plain value, which fails the whole request with its 500.
pub async fn get(
    exec: &ScopedExecutor,
    actor: i64,
    domain_scope: i64,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = exec
        .read(
            "SELECT c.id, c.name, c.status, u.email, c.created_at::text, cu.email, c.closed_at::text \
             FROM access_review_campaigns c \
             JOIN users u ON u.id = c.created_by \
             LEFT JOIN users cu ON cu.id = c.closed_by \
             WHERE c.id = $1 AND ($2 <= 0 OR c.domain_scope = $2)",
            &[(&id, Type::INT8), (&domain_scope, Type::INT8)],
        )
        .await?;
    let bad = |_| invalid();
    let Some(r) = rows.first() else {
        return Ok(None);
    };
    // Go's Get leaves `reviewed` and `total` at zero: only the list counts items.
    let campaign = campaign_json(
        r.try_get(0).map_err(bad)?,
        &r.try_get::<_, String>(1).map_err(bad)?,
        &r.try_get::<_, String>(2).map_err(bad)?,
        (0, 0),
        &r.try_get::<_, String>(3).map_err(bad)?,
        &r.try_get::<_, String>(4).map_err(bad)?,
        r.try_get(5).map_err(bad)?,
        r.try_get(6).map_err(bad)?,
    );
    let rows = exec
        .read(
            "SELECT i.id, u.email, rg.name, COALESCE(i.domain_override, rg.domain_scope), \
             i.granted_at::text, gb.email, i.is_sso, (i.user_id = $2), i.decision, i.applied_at::text \
             FROM access_review_items i \
             LEFT JOIN users u ON u.id = i.user_id \
             LEFT JOIN admin_role_groups rg ON rg.id = i.role_group_id \
             LEFT JOIN users gb ON gb.id = i.granted_by \
             WHERE i.campaign_id = $1 \
             ORDER BY (i.decision='undecided') DESC, u.email",
            &[(&id, Type::INT8), (&actor, Type::INT8)],
        )
        .await?;
    let mut items = Vec::new();
    for r in &rows {
        let scope: Option<i64> = r.try_get(3).map_err(bad)?;
        let granted_at: Option<String> = r.try_get(4).map_err(bad)?;
        let granted_by: Option<String> = r.try_get(5).map_err(bad)?;
        let applied_at: Option<String> = r.try_get(9).map_err(bad)?;
        let null = || "null".to_owned();
        items.push(format!(
            "{{\"id\":{},\"userEmail\":{},\"roleName\":{},\"scope\":{},\"grantedAt\":{}{},\"isSso\":{},\"isSelf\":{},\"decision\":{},\"appliedAt\":{}}}",
            r.try_get::<_, i64>(0).map_err(bad)?,
            s(&r.try_get::<_, String>(1).map_err(bad)?),
            s(&r.try_get::<_, String>(2).map_err(bad)?),
            scope.map(|v| v.to_string()).unwrap_or_else(null),
            granted_at.map(|v| s(&v)).unwrap_or_else(null),
            granted_by
                .map(|v| format!(",\"grantedBy\":{}", s(&v)))
                .unwrap_or_default(),
            r.try_get::<_, bool>(6).map_err(bad)?,
            r.try_get::<_, bool>(7).map_err(bad)?,
            s(&r.try_get::<_, String>(8).map_err(bad)?),
            applied_at.map(|v| s(&v)).unwrap_or_else(null),
        ));
    }
    Ok(Some(super::done(format!(
        "{{\"campaign\":{campaign},\"items\":[{}]}}",
        items.join(",")
    ))))
}

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: "F01",
        command: name,
    }
}

/// `POST /admin/access-reviews`: the new campaign id.
pub async fn start(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    name: &str,
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("access_review_start"),
        &envelope(&auth, operation, &format!("{name}:{domain_scope}")),
        &auth,
        deadline(),
        "SELECT access_review_start($2,$4,$5) WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&name, Type::TEXT), (&domain_scope, Type::INT8)],
        |rows| match rows {
            [row] => row.try_get::<_, i64>(0).map_err(|_| invalid()),
            _ => Err(invalid()),
        },
    )
    .await
}

/// `PUT /admin/access-reviews/{id}/items/{itemId}`.
#[allow(clippy::too_many_arguments)]
pub async fn decide(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    campaign: i64,
    item: i64,
    decision: &str,
    note: Option<&str>,
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("access_review_decide"),
        &envelope(
            &auth,
            operation,
            &format!("{campaign}:{item}:{decision}:{note:?}:{domain_scope}"),
        ),
        &auth,
        deadline(),
        "SELECT count(*)::bigint FROM (SELECT access_review_decide($2,$4,$5,$6,$7,$8) \
         WHERE $1::bigint > 0 AND $3::text <> '') w",
        &[
            (&campaign, Type::INT8),
            (&item, Type::INT8),
            (&decision, Type::TEXT),
            (&note, Type::TEXT),
            (&domain_scope, Type::INT8),
        ],
        |rows| _count(rows).map(|_| ()),
    )
    .await
}

/// `PUT /admin/access-reviews/{id}/items`: the reducer's `{applied, skipped}` JSON,
/// written verbatim by Go (jsonb text, no trailing newline).
pub async fn decide_bulk(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    campaign: i64,
    items: &Vec<i64>,
    decision: &str,
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("access_review_decide_bulk"),
        &envelope(
            &auth,
            operation,
            &format!("{campaign}:{items:?}:{decision}:{domain_scope}"),
        ),
        &auth,
        deadline(),
        "SELECT access_review_decide_bulk($2,$4,$5,$6,$7)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&campaign, Type::INT8),
            (items, Type::INT8_ARRAY),
            (&decision, Type::TEXT),
            (&domain_scope, Type::INT8),
        ],
        |rows| match rows {
            [row] => row.try_get::<_, String>(0).map_err(|_| invalid()),
            _ => Err(invalid()),
        },
    )
    .await
}

/// `POST /admin/access-reviews/{id}/close`.
pub async fn close(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    campaign: i64,
    ip: &str,
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("access_review_close"),
        &envelope(&auth, operation, &format!("{campaign}:{ip}:{domain_scope}")),
        &auth,
        deadline(),
        "SELECT count(*)::bigint FROM (SELECT access_review_close($2,$4,$5::text::inet,$6) \
         WHERE $1::bigint > 0 AND $3::text <> '') w",
        &[
            (&campaign, Type::INT8),
            (&ip, Type::TEXT),
            (&domain_scope, Type::INT8),
        ],
        |rows| _count(rows).map(|_| ()),
    )
    .await
}
