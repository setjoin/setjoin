//! Conditional access (F03) slice `remaining`: console reads and the small writes (principal
//! resolution, break-glass, sign-in log, why-lookup, session revocation and its log, templates,
//! coverage, doctor, impact, export, import, diff). Reads repeat Go's queries; every write
//! calls the reducer Go calls inside one receipted command.
use super::cmd::{one_i64, one_text, read_text, run};
use super::policies::compact;
use super::{done, invalid, nano, s};
use serde_json::Value;
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

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

const USERS: &str =
    "SELECT id, COALESCE(email,''), COALESCE(display_name,'') FROM users WHERE id = ANY($1)";

/// `GET .../resolve-principals`: users and groups by id, in the database's row order.
pub async fn principals(
    exec: &ScopedExecutor,
    users: &[i64],
    groups: &[i64],
) -> Result<String, StatementFailure> {
    let users_json = if users.is_empty() {
        "[]".to_string()
    } else {
        let rows = exec
            .read(USERS, &[(&users.to_vec(), Type::INT8_ARRAY)])
            .await?;
        render_users(&rows)?
    };
    let groups_json = if groups.is_empty() {
        "[]".to_string()
    } else {
        let rows = exec
            .read(
                "SELECT id, COALESCE(name,'') FROM user_groups WHERE id = ANY($1)",
                &[(&groups.to_vec(), Type::INT8_ARRAY)],
            )
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
pub async fn break_glass(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let empty = || done("{\"admins\":[]}".to_string());
    let Ok(rows) = exec
        .read(
            "SELECT value::text FROM system_config WHERE key = 'ca_break_glass_user_ids'",
            &[],
        )
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
    let rows = exec.read(USERS, &[(&ids, Type::INT8_ARRAY)]).await?;
    Ok(done(format!("{{\"admins\":{}}}", render_users(&rows)?)))
}

/// `PUT .../break-glass`: `ca_break_glass_set(actor, ip, ids)`.
pub async fn set_break_glass(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    ids: &Vec<i64>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    run(
        exec,
        actor,
        "ca_break_glass_set",
        operation,
        &format!("{ip}:{ids:?}"),
        "SELECT count(*)::bigint FROM (SELECT ca_break_glass_set($2,$4::text::inet,$5) \
         WHERE $1::bigint > 0 AND $3::text <> '') w",
        &[(&ip, Type::TEXT), (ids, Type::INT8_ARRAY)],
        super::cmd::counted,
    )
    .await
}

/// Go's `caSignInLogSelect` projected into the JSON of `scanCASignInLogRow` (map keys sorted).
fn signin_select() -> String {
    format!(
        "SELECT id, {}, user_id, {}, protocol, client_type, device_fp, country, matched_policy_id, \
         decision, would_decision, report_only, correlation_id, evaluated::text FROM ca_signin_log",
        nano("occurred_at"),
        SOURCE_IP
    )
}

/// How Go's `*string` scan renders `source_ip`: NULL is the empty string (not null), a host
/// address has no mask (`inet_out`), a network keeps it.
const SOURCE_IP: &str = "CASE WHEN source_ip IS NULL THEN '' \
    WHEN masklen(source_ip) = (CASE family(source_ip) WHEN 4 THEN 32 ELSE 128 END) THEN host(source_ip) \
    ELSE source_ip::text END";

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

/// Rows that fail to scan are skipped by Go; none can here.
fn signin_rows(rows: &[setjoin_pg::Row]) -> Result<Vec<String>, StatementFailure> {
    rows.iter().map(signin_row).collect()
}

/// `GET .../signin-log?correlation_id=|user_id=&limit=`: `{"rows":[...]}`.
pub async fn signin_log(
    exec: &ScopedExecutor,
    correlation: Option<&str>,
    user: Option<i64>,
    limit: i64,
) -> Result<String, StatementFailure> {
    let rows = if let Some(corr) = correlation {
        exec.read(
            &format!(
                "{} WHERE correlation_id = $1 ORDER BY occurred_at DESC LIMIT $2",
                signin_select()
            ),
            &[(&corr, Type::TEXT), (&limit, Type::INT8)],
        )
        .await?
    } else {
        exec.read(
            &format!(
                "{} WHERE user_id = $1 ORDER BY occurred_at DESC LIMIT $2",
                signin_select()
            ),
            &[(&user, Type::INT8), (&limit, Type::INT8)],
        )
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
    exec: &ScopedExecutor,
    user: &str,
    correlation: &str,
    since_seconds: i64,
) -> Result<Why, StatementFailure> {
    let mut user_id = 0i64;
    if !user.is_empty() {
        if let Ok(id) = user.parse::<i64>() {
            let found = exec
                .read(
                    "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)",
                    &[(&id, Type::INT8)],
                )
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
            let rows = exec
                .read(
                    "SELECT id FROM users WHERE email = $1",
                    &[(&lowered, Type::TEXT)],
                )
                .await?;
            match rows.first() {
                None => return Ok(Why::NotFound),
                Some(row) => user_id = row.try_get::<_, i64>(0).map_err(bad)?,
            }
        }
    }
    let select = signin_select();
    let cutoff = format!("now() - make_interval(secs => {since_seconds})");
    let rows = if !correlation.is_empty() && user_id == 0 {
        exec.read(
            &format!("{select} WHERE correlation_id = $1 AND occurred_at >= {cutoff} ORDER BY occurred_at DESC"),
            &[(&correlation, Type::TEXT)],
        )
        .await?
    } else if !correlation.is_empty() {
        exec.read(
            &format!("{select} WHERE user_id = $1 AND correlation_id = $2 AND occurred_at >= {cutoff} ORDER BY occurred_at DESC"),
            &[(&user_id, Type::INT8), (&correlation, Type::TEXT)],
        )
        .await?
    } else {
        exec.read(
            &format!("{select} WHERE user_id = $1 AND occurred_at >= {cutoff} ORDER BY occurred_at DESC LIMIT 200"),
            &[(&user_id, Type::INT8)],
        )
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

/// Rule B reach check of `POST .../sessions/{userId}/revoke`. The route needs
/// `access.policy_write`, so only grants carrying it reach the target: frozen Go used the
/// any-grant `admin_can_reach`, letting a domain-wide grant of an unrelated permission extend
/// the reach of a CA writer (owner-approved security fix #529, 2026-11-06).
pub async fn can_reach(
    exec: &ScopedExecutor,
    actor: i64,
    target: i64,
) -> Result<bool, StatementFailure> {
    let rows = exec
        .read(
            if setjoin_contracts::mutants::on("ca-revoke-any-grant") {
                "SELECT admin_can_reach($1, $2)"
            } else {
                "SELECT admin_can_reach_perm($1, $2, '{access.policy_write}'::text[])"
            },
            &[(&actor, Type::INT8), (&target, Type::INT8)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

/// `revoke_user_sessions(target, 'all', 'admin_revoke_all', actor, NULL, NULL)`: the revocation id.
pub async fn revoke_sessions(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    target: i64,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    run(
        exec,
        actor,
        "revoke_user_sessions",
        operation,
        &target.to_string(),
        "SELECT revoke_user_sessions($4, 'all', 'admin_revoke_all', $2, NULL, NULL) \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&target, Type::INT8)],
        one_i64,
    )
    .await
}

/// `GET .../sessions/log` on the worker credential: the latest 200 revocations.
pub async fn sessions_log(
    worker: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    // Owner-approved security fix 2026-11-05 (#467, #510): the worker credential bypasses row
    // security, so the caller's reach is applied here: org-wide grant, or the revoked user is in
    // reach through an access.policy_* grant.
    let admin = actor.user_id();
    let rows = worker
        .read(
            &format!(
                "SELECT id, user_id, scope, reason, created_by, created_at::text \
                 FROM session_revocations \
                 WHERE {open} OR admin_org_wide_grant($1, {perms}) OR admin_can_reach_perm($1, user_id, {perms}) \
                 ORDER BY created_at DESC LIMIT 200",
                open = crate::policies::open(),
                perms = crate::policies::READ_PERMS
            ),
            &[(&admin, Type::INT8)],
        )
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
pub async fn templates(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT id, slug, name, description, scope_type, scope_target, conditions::text, actions::text, \
             suggested_priority, created_at::text FROM ca_templates ORDER BY suggested_priority ASC",
            &[],
        )
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

/// `ca_template_instantiate(slug, actor)`: the new policy's id.
pub async fn instantiate(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    slug: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    run(
        exec,
        actor,
        "ca_template_instantiate",
        operation,
        slug,
        "SELECT ca_template_instantiate($4,$2) WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&slug, Type::TEXT)],
        one_i64,
    )
    .await
}

/// The read-back of the instantiated policy, jsonb text verbatim (`to_jsonb(c) - 'enabled'`).
pub async fn instantiated(exec: &ScopedExecutor, id: i64) -> Result<String, StatementFailure> {
    read_text(
        exec,
        "SELECT (to_jsonb(c) - 'enabled')::text FROM conditional_access_policies c WHERE id = $1",
        &[(&id, Type::INT8)],
    )
    .await
}

/// `ca_coverage_report()` as jsonb text.
pub async fn coverage(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    read_text(exec, "SELECT ca_coverage_report()::text", &[]).await
}

/// `ca_policy_impact(id, window, list)` as jsonb text.
pub async fn impact(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    policy: i64,
    window: &str,
    list: Option<&str>,
) -> Result<String, StatementFailure> {
    // Owner-approved security fix 2026-11-05 (#467): only a policy in the caller's reach.
    let user = actor.user_id();
    read_text(
        exec,
        &format!(
            "SELECT ca_policy_impact($1, $2, $3::text)::text \
             WHERE {open} OR COALESCE(rust_ca_policy_row_reach($4, $1, {perms}), true)",
            open = crate::policies::open(),
            perms = crate::policies::READ_PERMS
        ),
        &[
            (&policy, Type::INT8),
            (&window, Type::TEXT),
            (&list, Type::TEXT),
            (&user, Type::INT8),
        ],
    )
    .await
}

/// `POST .../import?mode=`: `ca_policy_import(doc, actor, mode)` summary, jsonb text verbatim.
pub async fn import(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    document: &str,
    mode: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    run(
        exec,
        actor,
        "ca_policy_import",
        operation,
        &format!("{mode}:{document}"),
        "SELECT ca_policy_import($4::text::jsonb,$2,$5)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&document, Type::TEXT), (&mode, Type::TEXT)],
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
pub async fn doctor(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let feature = one_bool(
        &exec
            .read(
                "SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key = 'feature.conditional_access'), false)",
                &[],
            )
            .await?,
    )?;
    let break_glass = one_bool(
        &exec
            .read(
                "SELECT EXISTS (SELECT 1 FROM system_config WHERE key = 'ca_break_glass_user_ids' \
                 AND jsonb_array_length(value) > 0)",
                &[],
            )
            .await?,
    )?;
    let report_only = one_bool(
        &exec
            .read(
                "SELECT EXISTS (SELECT 1 FROM conditional_access_policies \
                 WHERE state = 'report_only' AND deleted_at IS NULL)",
                &[],
            )
            .await?,
    )?;
    let coverage = coverage(exec).await?;
    let no_gaps = match serde_json::from_str::<Value>(&coverage) {
        Ok(Value::Object(map)) => match map.get("gaps") {
            Some(Value::Array(gaps)) => gaps.is_empty(),
            Some(Value::Null) | None => true,
            _ => return Err(invalid()),
        },
        _ => return Err(invalid()),
    };
    let stale = exec
        .read(
            "SELECT id, name, state, EXTRACT(DAY FROM now() - created_at)::bigint AS days_since \
             FROM conditional_access_policies WHERE state = 'report_only' AND deleted_at IS NULL \
             AND created_at < now() - INTERVAL '30 days' ORDER BY created_at",
            &[],
        )
        .await?;
    let ttfp = time_to_first_policy(exec).await?;
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
                format!("    {{\n      \"name\": {},\n      \"passed\": true\n    }}", s(name))
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
    Ok(go_escape_indented(&out))
}

fn go_escape_indented(text: &str) -> String {
    super::go_escape(text)
}

/// First `ca_policy_create` to first `ca_policy_promote`, whole seconds, only when the promote
/// is strictly later.
async fn time_to_first_policy(exec: &ScopedExecutor) -> Result<Option<i64>, StatementFailure> {
    let rows = exec
        .read(
            "SELECT CASE WHEN c IS NOT NULL AND p IS NOT NULL AND p > c \
             THEN floor(extract(epoch FROM (p - c)))::bigint END \
             FROM (SELECT (SELECT MIN(occurred_at) FROM admin_audit_log WHERE action = 'ca_policy_create') AS c, \
             (SELECT MIN(occurred_at) FROM admin_audit_log WHERE action = 'ca_policy_promote') AS p) t",
            &[],
        )
        .await?;
    rows.first()
        .map(|r| r.try_get::<_, Option<i64>>(0).map_err(bad))
        .transpose()
        .map(Option::flatten)
}
