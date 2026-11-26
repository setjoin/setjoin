//! Conditional access (F03) slice `remaining`: console reads and small writes (principal
//! resolution, break-glass, sign-in log, why-lookup, session revocation and its log, templates,
//! coverage, doctor, impact, import). Reads run via `AdminReadTx`; writes run via `AdminWriteTx`
//! (`ReducerWritesCoreAudit`).
use super::cmd::{
    one_i64, one_text, one_void, read_text, run_audited, run_checked_audited, PolicyLock,
};
use super::policies::compact;
use super::{done, invalid, s, sql};
use serde_json::Value;
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::{CommandOutcome, StatementFailure};

fn bad<E>(_: E) -> StatementFailure {
    invalid()
}

fn render_users(rows: &[setjoin_pg::Row]) -> Result<String, StatementFailure> {
    let mut out = Vec::new();
    for r in rows {
        out.push(format!(
            "{{\"display_name\":{},\"email\":{},\"id\":{}}}",
            s(&r.try_get::<_, String>(2).map_err(bad)?),
            s(&r.try_get::<_, String>(1).map_err(bad)?),
            r.try_get::<_, i64>(0).map_err(bad)?
        ));
    }
    Ok(format!("[{}]", out.join(",")))
}

/// `GET .../resolve-principals`: users and groups by id, in the database's row order.
pub async fn principals(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    users: &[i64],
    groups: &[i64],
) -> Result<String, StatementFailure> {
    let users_json = if users.is_empty() {
        "[]".to_string()
    } else {
        let ids = users.to_vec();
        let rows = factory
            .run_admin_read_contract(admin, &sql::USERS_BY_IDS, &[&ids])
            .await?;
        render_users(&rows)?
    };
    let groups_json = if groups.is_empty() {
        "[]".to_string()
    } else {
        let ids = groups.to_vec();
        let rows = factory
            .run_admin_read_contract(admin, &sql::GROUPS_BY_IDS, &[&ids])
            .await?;
        let mut out = Vec::new();
        for r in &rows {
            out.push(format!(
                "{{\"id\":{},\"name\":{}}}",
                r.try_get::<_, i64>(0).map_err(bad)?,
                s(&r.try_get::<_, String>(1).map_err(bad)?)
            ));
        }
        format!("[{}]", out.join(","))
    };
    Ok(done(format!(
        "{{\"groups\":{groups_json},\"users\":{users_json}}}"
    )))
}

/// `GET .../break-glass`: an absent key, an unreadable value or an empty set is `{"admins":[]}`
/// (Go swallows the read error too); only the user lookup can fail the request.
pub async fn break_glass(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let empty = || done("{\"admins\":[]}".to_string());
    let Ok(rows) = factory
        .run_admin_read_contract(admin, &sql::BREAK_GLASS_GET, &[])
        .await
    else {
        return Ok(empty());
    };
    let Some(raw) = rows.first().and_then(|r| r.try_get::<_, String>(0).ok()) else {
        return Ok(empty());
    };
    let ids = match serde_json::from_str::<Option<Vec<Option<i64>>>>(&raw) {
        Ok(Some(ids)) if !ids.is_empty() => {
            ids.into_iter().map(|i| i.unwrap_or(0)).collect::<Vec<_>>()
        }
        _ => return Ok(empty()),
    };
    let rows = factory
        .run_admin_read_contract(admin, &sql::USERS_BY_IDS, &[&ids])
        .await?;
    Ok(done(format!("{{\"admins\":{}}}", render_users(&rows)?)))
}

/// `PUT .../break-glass`: `ca_break_glass_set(actor, ip, ids)`.
pub async fn set_break_glass(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    ip: &str,
    ids: &Vec<i64>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    run_audited(
        factory,
        admin,
        "ca_break_glass_set",
        operation,
        &format!("{ip}:{ids:?}"),
        &sql::BREAK_GLASS_SET,
        &[&ip, ids],
        one_void,
    )
    .await
}

fn signin_row(r: &setjoin_pg::Row) -> Result<String, StatementFailure> {
    let text = |index: usize| -> Result<String, StatementFailure> {
        Ok(r.try_get::<_, Option<String>>(index)
            .map_err(bad)?
            .map_or("null".to_string(), |v| s(&v)))
    };
    let number = |index: usize| -> Result<String, StatementFailure> {
        Ok(r.try_get::<_, Option<i64>>(index)
            .map_err(bad)?
            .map_or("null".to_string(), |v| v.to_string()))
    };
    Ok(format!(
        "{{\"client_type\":{},\"correlation_id\":{},\"country\":{},\"decision\":{},\"device_fp\":{},\"evaluated\":{},\"id\":{},\"matched_policy_id\":{},\"occurred_at\":{},\"protocol\":{},\"report_only\":{},\"source_ip\":{},\"user_id\":{},\"would_decision\":{}}}",
        text(5)?,
        text(12)?,
        text(7)?,
        text(9)?,
        text(6)?,
        compact(&r.try_get::<_, String>(13).map_err(bad)?),
        r.try_get::<_, i64>(0).map_err(bad)?,
        number(8)?,
        s(&r.try_get::<_, String>(1).map_err(bad)?),
        text(4)?,
        r.try_get::<_, bool>(11).map_err(bad)?,
        text(3)?,
        number(2)?,
        text(10)?,
    ))
}

fn signin_rows(rows: &[setjoin_pg::Row]) -> Result<Vec<String>, StatementFailure> {
    rows.iter().map(signin_row).collect()
}

/// `GET .../signin-log?correlation_id=|user_id=&limit=`: `{"rows":[...]}`.
pub async fn signin_log(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    correlation: Option<&str>,
    user: Option<i64>,
    limit: i64,
) -> Result<String, StatementFailure> {
    let rows = if let Some(corr) = correlation {
        factory
            .run_admin_read_contract(admin, &sql::SIGNIN_LOG_BY_CORRELATION, &[&corr, &limit])
            .await?
    } else {
        factory
            .run_admin_read_contract(admin, &sql::SIGNIN_LOG_BY_USER, &[&user, &limit])
            .await?
    };
    Ok(done(format!(
        "{{\"rows\":[{}]}}",
        signin_rows(&rows)?.join(",")
    )))
}

pub enum Why {
    NotFound,
    Found(String),
}

/// `GET .../why-lookup`: resolves the user (numeric id first, then lower-cased email) and reads
/// the window's rows.
pub async fn why(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    user: &str,
    correlation: &str,
    since_seconds: i64,
) -> Result<Why, StatementFailure> {
    let mut user_id = 0i64;
    if !user.is_empty() {
        if let Ok(id) = user.parse::<i64>() {
            let found = factory
                .run_admin_read_contract(admin, &sql::USER_EXISTS, &[&id])
                .await
                .ok()
                .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
                .unwrap_or(false);
            if !found {
                return Ok(Why::NotFound);
            }
            user_id = id;
        } else {
            let lowered = go_lower(user);
            let rows = factory
                .run_admin_read_contract(admin, &sql::USER_ID_BY_EMAIL, &[&lowered])
                .await?;
            match rows.first() {
                None => return Ok(Why::NotFound),
                Some(row) => user_id = row.try_get::<_, i64>(0).map_err(bad)?,
            }
        }
    }
    let rows = if !correlation.is_empty() && user_id == 0 {
        factory
            .run_admin_read_contract(
                admin,
                &sql::WHY_BY_CORRELATION,
                &[&correlation, &since_seconds],
            )
            .await?
    } else if !correlation.is_empty() {
        factory
            .run_admin_read_contract(
                admin,
                &sql::WHY_BY_USER_AND_CORRELATION,
                &[&user_id, &correlation, &since_seconds],
            )
            .await?
    } else {
        factory
            .run_admin_read_contract(admin, &sql::WHY_BY_USER, &[&user_id, &since_seconds])
            .await?
    };
    Ok(Why::Found(done(format!(
        "{{\"found\":true,\"rows\":[{}],\"user_id\":{user_id}}}",
        signin_rows(&rows)?.join(",")
    ))))
}

/// Go's `strings.ToLower` (full Unicode case mapping).
pub fn go_lower(text: &str) -> String {
    text.to_lowercase()
}

/// Rule B reach check of `POST .../sessions/{userId}/revoke`.
pub async fn can_reach(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    target: i64,
) -> Result<bool, StatementFailure> {
    let actor = admin.actor().get();
    let contract = if setjoin_contracts::mutants::on("ca-revoke-any-grant") {
        &sql::CAN_REACH_ANY
    } else {
        &sql::CAN_REACH_PERM
    };
    let rows = factory
        .run_admin_read_contract(admin, contract, &[&actor, &target])
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

/// `rust_ca_revoke_user_sessions(actor, target)`: the revocation id.
pub async fn revoke_sessions(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    target: i64,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    run_audited(
        factory,
        admin,
        "revoke_user_sessions",
        operation,
        &target.to_string(),
        &sql::REVOKE_USER_SESSIONS,
        &[&target],
        one_i64,
    )
    .await
}

/// `GET .../sessions/log`: the latest 200 revocations reachable by the caller.
pub async fn sessions_log(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let actor = admin.actor().get();
    let open_flag = crate::policies::open();
    let rows = factory
        .run_admin_read_contract(admin, &sql::SESSIONS_LOG, &[&actor, &open_flag])
        .await?;
    let mut out = Vec::new();
    for r in &rows {
        out.push(format!(
            "{{\"id\":{},\"user_id\":{},\"scope\":{},\"reason\":{},\"created_by\":{},\"created_at\":{}}}",
            r.try_get::<_, i64>(0).map_err(bad)?,
            r.try_get::<_, i64>(1).map_err(bad)?,
            s(&r.try_get::<_, String>(2).map_err(bad)?),
            s(&r.try_get::<_, String>(3).map_err(bad)?),
            r.try_get::<_, Option<i64>>(4)
                .map_err(bad)?
                .map_or("null".to_string(), |v| v.to_string()),
            s(&r.try_get::<_, String>(5).map_err(bad)?),
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET .../templates-list`.
pub async fn templates(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::TEMPLATES_LIST, &[])
        .await?;
    let mut out = Vec::new();
    for r in &rows {
        out.push(format!(
            "{{\"actions\":{},\"conditions\":{},\"created_at\":{},\"description\":{},\"id\":{},\"name\":{},\"scope_target\":{},\"scope_type\":{},\"slug\":{},\"suggested_priority\":{}}}",
            compact(&r.try_get::<_, String>(7).map_err(bad)?),
            compact(&r.try_get::<_, String>(6).map_err(bad)?),
            s(&r.try_get::<_, String>(9).map_err(bad)?),
            s(&r.try_get::<_, String>(3).map_err(bad)?),
            r.try_get::<_, i64>(0).map_err(bad)?,
            s(&r.try_get::<_, String>(2).map_err(bad)?),
            s(&r.try_get::<_, String>(5).map_err(bad)?),
            s(&r.try_get::<_, String>(4).map_err(bad)?),
            s(&r.try_get::<_, String>(1).map_err(bad)?),
            r.try_get::<_, i32>(8).map_err(bad)?,
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// `rust_ca_template_instantiate(actor, slug)`: the new policy's id.
pub async fn instantiate(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    slug: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let actor_id = admin.actor().get();
    let open_flag = crate::policies::open();
    run_checked_audited(
        factory,
        admin,
        "ca_template_instantiate",
        operation,
        slug,
        PolicyLock::FenceOnly,
        &sql::ORG_WIDE_WRITE_CHECK,
        &[&actor_id, &open_flag],
        &sql::TEMPLATE_INSTANTIATE,
        &[&slug],
        one_i64,
    )
    .await
}

/// The read-back of the instantiated policy, jsonb text verbatim (`to_jsonb(c) - 'enabled'`).
pub async fn instantiated(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
) -> Result<String, StatementFailure> {
    read_text(factory, admin, &sql::POLICY_INSTANTIATED_GET, &[&id]).await
}

/// `ca_coverage_report()` as jsonb text.
pub async fn coverage(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    read_text(factory, admin, &sql::COVERAGE_REPORT, &[]).await
}

/// `ca_policy_impact(id, window, list)` as jsonb text.
pub async fn impact(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    policy: i64,
    window: &str,
    list: Option<&str>,
) -> Result<String, StatementFailure> {
    let user = admin.actor().get();
    let open_flag = crate::policies::open();
    read_text(
        factory,
        admin,
        &sql::POLICY_IMPACT,
        &[&policy, &window, &list, &user, &open_flag],
    )
    .await
}

/// `POST .../import?mode=`: `rust_ca_policy_import(actor, doc, mode)` summary, jsonb text verbatim.
pub async fn import(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    document: &str,
    mode: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor_id = admin.actor().get();
    let open_flag = crate::policies::open();
    run_checked_audited(
        factory,
        admin,
        "ca_policy_import",
        operation,
        &format!("{mode}:{document}"),
        PolicyLock::FenceOnly,
        &sql::ORG_WIDE_WRITE_CHECK,
        &[&actor_id, &open_flag],
        &sql::POLICY_IMPORT,
        &[&document, &mode],
        one_text,
    )
    .await
}

fn one_bool(rows: &[setjoin_pg::Row]) -> Result<bool, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

/// `GET .../doctor`: four health checks, the stale report-only scan and time-to-first-policy,
/// rendered with `SetIndent("", "  ")`.
pub async fn doctor(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let feature = one_bool(
        &factory
            .run_admin_read_contract(admin, &sql::DOCTOR_FEATURE_ON, &[])
            .await?,
    )?;
    let break_glass = one_bool(
        &factory
            .run_admin_read_contract(admin, &sql::DOCTOR_BREAK_GLASS, &[])
            .await?,
    )?;
    let report_only = one_bool(
        &factory
            .run_admin_read_contract(admin, &sql::DOCTOR_REPORT_ONLY, &[])
            .await?,
    )?;
    let coverage = coverage(factory, admin).await?;
    let no_gaps = match serde_json::from_str::<Value>(&coverage) {
        Ok(Value::Object(map)) => match map.get("gaps") {
            Some(Value::Array(gaps)) => gaps.is_empty(),
            Some(Value::Null) | None => true,
            _ => return Err(invalid()),
        },
        _ => return Err(invalid()),
    };
    let stale = factory
        .run_admin_read_contract(admin, &sql::DOCTOR_STALE_REPORT_ONLY, &[])
        .await?;
    let ttfp = time_to_first_policy(factory, admin).await?;
    let checks: [(&str, bool, &str); 4] = [
        (
            "feature_on",
            feature,
            "Enable feature.conditional_access in feature toggles",
        ),
        (
            "break_glass_configured",
            break_glass,
            "Set break-glass users via `mailctl ca` or the admin console to prevent lockout",
        ),
        (
            "has_report_only_policy",
            report_only,
            "Create at least one report_only policy to test coverage before enforcing",
        ),
        (
            "no_coverage_gaps",
            no_gaps,
            "Run `mailctl ca coverage` to see gaps; create policies to cover flagged protocols",
        ),
    ];
    let score = checks.iter().filter(|c| c.1).count();
    let mut out = String::from("{\n");
    out.push_str(&format!(
        "  \"score\": {score},\n  \"total\": 4,\n  \"checks\": [\n"
    ));
    let rendered: Vec<String> = checks
        .iter()
        .map(|(name, passed, action)| {
            if *passed {
                format!(
                    "    {{\n      \"name\": {},\n      \"passed\": true\n    }}",
                    s(name)
                )
            } else {
                format!(
                    "    {{\n      \"name\": {},\n      \"passed\": false,\n      \"next_action\": {}\n    }}",
                    s(name),
                    s(action)
                )
            }
        })
        .collect();
    out.push_str(&rendered.join(",\n"));
    out.push_str("\n  ],\n  \"hygiene\": {\n    \"stale_report_only\": ");
    if stale.is_empty() {
        out.push_str("[]");
    } else {
        let mut items = Vec::new();
        for r in &stale {
            let days = r.try_get::<_, i64>(3).map_err(bad)?;
            let mut item = format!(
                "      {{\n        \"id\": {},\n        \"name\": {},\n        \"state\": {}",
                r.try_get::<_, i64>(0).map_err(bad)?,
                s(&r.try_get::<_, String>(1).map_err(bad)?),
                s(&r.try_get::<_, String>(2).map_err(bad)?)
            );
            if days != 0 {
                item.push_str(&format!(",\n        \"days_since_created\": {days}"));
            }
            item.push_str("\n      }");
            items.push(item);
        }
        out.push_str(&format!("[\n{}\n    ]", items.join(",\n")));
    }
    out.push_str("\n  },\n  \"time_to_first_policy_sec\": ");
    out.push_str(&ttfp.map_or("null".to_string(), |v| v.to_string()));
    out.push_str("\n}\n");
    Ok(super::go_escape(&out))
}

/// First `ca_policy_create` to first `ca_policy_promote`, whole seconds, only when the promote
/// is strictly later.
async fn time_to_first_policy(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<Option<i64>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::DOCTOR_TIME_TO_FIRST_POLICY, &[])
        .await?;
    rows.first()
        .map(|r| r.try_get::<_, Option<i64>>(0).map_err(bad))
        .transpose()
        .map(Option::flatten)
}
