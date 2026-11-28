//! Admin identity (F01) slice `access-reviews`: recertification campaigns.
use super::{deadline, envelope, invalid, s, sql, FAMILY};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Rejection, StatementFailure};

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
pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::ACCESS_REVIEWS_LIST, &[&domain_scope])
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
pub async fn get(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    actor: i64,
    domain_scope: i64,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::ACCESS_REVIEW_GET, &[&id, &domain_scope])
        .await?;
    let bad = |_| invalid();
    let Some(r) = rows.first() else {
        return Ok(None);
    };
    let item_rows = factory
        .run_admin_read_contract(admin, &sql::ACCESS_REVIEW_ITEMS, &[&id, &actor])
        .await?;
    let mut items = Vec::with_capacity(item_rows.len());
    let mut reviewed: i32 = 0;
    for ir in &item_rows {
        let user_email = ir
            .try_get::<_, Option<String>>(1)
            .map_err(bad)?
            .unwrap_or_default();
        let role_name = ir
            .try_get::<_, Option<String>>(2)
            .map_err(bad)?
            .unwrap_or_default();
        let scope: Option<i64> = ir.try_get(3).map_err(bad)?;
        let granted_at: Option<String> = ir.try_get(4).map_err(bad)?;
        let granted_by: Option<String> = ir.try_get(5).map_err(bad)?;
        let decision: String = ir.try_get(8).map_err(bad)?;
        if decision != "undecided" {
            reviewed = reviewed.saturating_add(1);
        }
        let applied_at: Option<String> = ir.try_get(9).map_err(bad)?;
        let null = || "null".to_owned();
        items.push(format!(
            "{{\"id\":{},\"userEmail\":{},\"roleName\":{},\"scope\":{},\"grantedAt\":{}{},\"isSso\":{},\"isSelf\":{},\"decision\":{},\"appliedAt\":{}}}",
            ir.try_get::<_, i64>(0).map_err(bad)?,
            s(&user_email),
            s(&role_name),
            scope.map(|v| v.to_string()).unwrap_or_else(null),
            granted_at.map(|v| s(&v)).unwrap_or_else(null),
            granted_by
                .map(|v| format!(",\"grantedBy\":{}", s(&v)))
                .unwrap_or_default(),
            ir.try_get::<_, bool>(6).map_err(bad)?,
            ir.try_get::<_, bool>(7).map_err(bad)?,
            s(&decision),
            applied_at.map(|v| s(&v)).unwrap_or_else(null),
        ));
    }
    let total = i32::try_from(items.len()).unwrap_or(i32::MAX);
    let campaign = campaign_json(
        r.try_get(0).map_err(bad)?,
        &r.try_get::<_, String>(1).map_err(bad)?,
        &r.try_get::<_, String>(2).map_err(bad)?,
        (reviewed, total),
        &r.try_get::<_, String>(3).map_err(bad)?,
        &r.try_get::<_, String>(4).map_err(bad)?,
        r.try_get(5).map_err(bad)?,
        r.try_get(6).map_err(bad)?,
    );
    Ok(Some(super::done(format!(
        "{{\"campaign\":{campaign},\"items\":[{}]}}",
        items.join(",")
    ))))
}

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: FAMILY,
        command: name,
    }
}

/// `POST /admin/access-reviews`: the new campaign id.
pub async fn start(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    name: &str,
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{name}:{domain_scope}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::ACCESS_REVIEW_START,
            &[&name, &domain_scope],
            Some(command("access_review_start")),
            |rows, _audited| match rows.as_slice() {
                [row] => row.try_get::<_, i64>(0).map_err(|_| invalid()),
                _ => Err(invalid()),
            },
        )
        .await
}

/// `PUT /admin/access-reviews/{id}/items/{itemId}`.
#[allow(clippy::too_many_arguments)]
pub async fn decide(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    campaign: i64,
    item: i64,
    decision: &str,
    note: Option<&str>,
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{campaign}:{item}:{decision}:{note:?}:{domain_scope}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::ACCESS_REVIEW_DECIDE,
            &[&campaign, &item, &decision, &note, &domain_scope],
            Some(command("access_review_decide")),
            |rows, _audited| {
                if rows.len() == 1 {
                    Ok(())
                } else {
                    Err(invalid())
                }
            },
        )
        .await
}

/// `PUT /admin/access-reviews/{id}/items`: the reducer's `{applied, skipped}` JSON.
#[allow(clippy::too_many_arguments)]
pub async fn decide_bulk(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    campaign: i64,
    items: &Vec<i64>,
    decision: &str,
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{campaign}:{items:?}:{decision}:{domain_scope}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::ACCESS_REVIEW_DECIDE_BULK,
            &[&campaign, items, &decision, &domain_scope],
            Some(command("access_review_decide_bulk")),
            |rows, _audited| match rows.as_slice() {
                [row] => row.try_get::<_, String>(0).map_err(|_| invalid()),
                _ => Err(invalid()),
            },
        )
        .await
}

/// `POST /admin/access-reviews/{id}/close`.
pub async fn close(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    campaign: i64,
    ip: &str,
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{campaign}:{ip}:{domain_scope}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::ACCESS_REVIEW_CLOSE,
            &[&campaign, &ip, &domain_scope],
            Some(command("access_review_close")),
            |rows, _audited| {
                if rows.len() == 1 {
                    Ok(())
                } else {
                    Err(invalid())
                }
            },
        )
        .await
}
