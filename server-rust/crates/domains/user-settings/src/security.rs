//! Slice `settings-c` (#308): the seven self-service session and account-security routes of Go's
//! `SessionsHandler`, `DevicesHandler.ListDevices`, `LoginHistoryHandler.ListLoginHistory`,
//! `SecureAccountHandler` and `SecurityScoreHandler`.
//!
//! Reads render Go's structs (declaration order) and maps (sorted keys). Writes are Go's whole
//! transaction as one reducer call keyed by the verified user (`rust_session_revoke_one`,
//! `rust_sessions_revoke_all`, `rust_secure_account_self`): each composes the existing
//! `revoke_user_sessions` / `secure_account` reducers, so denylist rows, audit and notifications
//! are Go's. Device and login-event reads run under the user GUC like Go's `RunUserScoped`.
use super::{command, deadline, done, envelope, invalid, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, Row, ScopedExecutor, StatementFailure, Type};

/// `GET /user/sessions`: live oauth refresh families and web sessions of the caller. A row whose
/// scan fails is skipped in Go; no selected column can be NULL, so none is. `jti` marks the
/// presenting web session `current`.
pub async fn sessions_list(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    jti: &str,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(
            &scope(actor),
            crate::sql::SESSIONS_LIST.sql,
            &[(&user, Type::INT8), (&jti, Type::TEXT)],
        )
        .await?;
    let render = |r: &Row| -> Option<String> {
        Some(format!(
            "{{\"id\":{},\"kind\":{},\"client_id\":{},\"device\":{},\"location\":{},\"last_used_at\":{},\"auth_method\":{},\"current\":{}}}",
            s(&r.try_get::<_, String>(0).ok()?),
            s(&r.try_get::<_, String>(1).ok()?),
            s(&r.try_get::<_, String>(2).ok()?),
            s(&r.try_get::<_, String>(3).ok()?),
            s(&r.try_get::<_, String>(4).ok()?),
            s(&r.try_get::<_, String>(5).ok()?),
            s(&r.try_get::<_, String>(6).ok()?),
            r.try_get::<_, bool>(7).ok()?
        ))
    };
    let items: Vec<String> = rows.iter().filter_map(render).collect();
    Ok(done(format!("{{\"sessions\":[{}]}}", items.join(","))))
}

/// `GET /user/devices`. Go answers `{"devices":[]}` for ANY query error and skips a row whose
/// scan fails (none can: every projected column is non-null).
pub async fn devices_list(exec: &ScopedExecutor, actor: &AuthContext) -> String {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(
            &scope(actor),
            crate::sql::DEVICES_LIST.sql,
            &[(&user, Type::INT8)],
        )
        .await
        .unwrap_or_default();
    let render = |r: &Row| -> Option<String> {
        Some(format!(
            "{{\"device_fingerprint\":{},\"device_name\":{},\"platform\":{},\"last_seen\":{},\"trust_tier\":{},\"created_at\":{},\"has_active_session\":false,\"is_current_device\":false}}",
            s(&r.try_get::<_, String>(0).ok()?),
            s(&r.try_get::<_, String>(1).ok()?),
            s(&r.try_get::<_, String>(2).ok()?),
            s(&r.try_get::<_, String>(3).ok()?),
            s(&r.try_get::<_, String>(4).ok()?),
            s(&r.try_get::<_, String>(5).ok()?)
        ))
    };
    let items: Vec<String> = rows.iter().filter_map(render).collect();
    done(format!("{{\"devices\":[{}]}}", items.join(",")))
}

/// `GET /user/login-history`: `limit`/`offset` are already Go's `ParseLimitOffset` result.
/// `outcome == ""` lists everything, `"success"` successes, anything else failures.
pub async fn login_history(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    jti: &str,
    outcome: &str,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let auth = scope(actor);
    let rows = exec
        .read_scoped(
            &auth,
            crate::sql::LOGIN_HISTORY.sql,
            &[
                (&user, Type::INT8),
                (&limit, Type::INT8),
                (&offset, Type::INT8),
                (&jti, Type::TEXT),
                (&outcome, Type::TEXT),
            ],
        )
        .await?;
    let mut total = 0_i64;
    let mut items = vec![];
    for r in &rows {
        let one = || -> Option<(String, i64)> {
            let reason = r.try_get::<_, String>(10).ok()?;
            Some((
                format!(
                    "{{\"id\":{},\"occurred_at\":{},\"source_ip\":{},\"location\":{},\"device_name\":{},\"platform\":{},\"client\":{},\"protocol\":{},\"auth_method\":{},\"success\":{}{},\"current\":{}}}",
                    r.try_get::<_, i64>(0).ok()?,
                    s(&r.try_get::<_, String>(1).ok()?),
                    s(&r.try_get::<_, String>(2).ok()?),
                    s(&r.try_get::<_, String>(3).ok()?),
                    s(&r.try_get::<_, String>(4).ok()?),
                    s(&r.try_get::<_, String>(5).ok()?),
                    s(&r.try_get::<_, String>(6).ok()?),
                    s(&r.try_get::<_, String>(7).ok()?),
                    s(&r.try_get::<_, String>(8).ok()?),
                    r.try_get::<_, bool>(9).ok()?,
                    if reason.is_empty() {
                        String::new()
                    } else {
                        format!(",\"fail_reason\":{}", s(&reason))
                    },
                    r.try_get::<_, bool>(11).ok()?
                ),
                r.try_get::<_, i64>(12).ok()?,
            ))
        };
        if let Some((text, count)) = one() {
            total = count;
            items.push(text);
        }
    }
    let row = exec
        .read_scoped(
            &auth,
            crate::sql::LOGIN_HISTORY_SUMMARY.sql,
            &[(&user, Type::INT8)],
        )
        .await?
        .into_iter()
        .next()
        .ok_or_else(invalid)?;
    Ok(done(format!(
        "{{\"failed_distinct\":{{\"count\":{},\"locations\":{},\"since\":{}}},\"items\":[{}],\"total\":{total}}}",
        row.try_get::<_, i64>(0).map_err(|_| invalid())?,
        row.try_get::<_, i64>(1).map_err(|_| invalid())?,
        s(&row.try_get::<_, String>(2).map_err(|_| invalid())?),
        items.join(",")
    )))
}

async fn one_value<T>(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    sql: &str,
    get: impl Fn(&Row) -> Option<T>,
) -> Option<T> {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(&scope(actor), sql, &[(&user, Type::INT8)])
        .await
        .ok()?;
    rows.first().and_then(get)
}

/// `GET /user/security-score`: a 50 baseline plus four checks. Go treats a failed read as
/// "check not met"; the same happens here.
pub async fn security_score(exec: &ScopedExecutor, actor: &AuthContext) -> String {
    let mut score = 50;
    let mut checks: Vec<String> = vec![];
    let totp = one_value(
        exec,
        actor,
        crate::sql::SECURITY_SCORE_TOTP.sql,
        |r| r.try_get::<_, bool>(0).ok(),
    )
    .await
    .unwrap_or(false);
    if totp {
        score += 20;
        checks.push("{\"name\":\"TOTP enabled\",\"pass\":true,\"points\":20}".into());
    } else {
        checks.push("{\"action\":\"Enable two-factor authentication\",\"name\":\"TOTP enabled\",\"pass\":false,\"points\":0}".into());
    }
    let backup = one_value(
        exec,
        actor,
        crate::sql::SECURITY_SCORE_BACKUP_CODES.sql,
        |r| r.try_get::<_, i32>(0).ok(),
    )
    .await
    .unwrap_or(0);
    if backup > 0 {
        score += 15;
        checks.push(format!(
            "{{\"name\":\"Backup codes\",\"pass\":true,\"points\":15,\"remaining\":{backup}}}"
        ));
    } else {
        checks.push("{\"action\":\"Generate backup codes\",\"name\":\"Backup codes\",\"pass\":false,\"points\":0}".into());
    }
    let fails = one_value(
        exec,
        actor,
        crate::sql::SECURITY_SCORE_FAILED_LOGINS.sql,
        |r| r.try_get::<_, i64>(0).ok(),
    )
    .await
    .unwrap_or(0);
    if fails == 0 {
        score += 10;
        checks.push("{\"name\":\"No recent failed logins\",\"pass\":true,\"points\":10}".into());
    } else {
        checks.push(format!("{{\"name\":\"No recent failed logins\",\"pass\":false,\"points\":0,\"recent_fails\":{fails}}}"));
    }
    let devices = one_value(
        exec,
        actor,
        crate::sql::SECURITY_SCORE_DEVICE_COUNT.sql,
        |r| r.try_get::<_, i64>(0).ok(),
    )
    .await
    .unwrap_or(0);
    if devices <= 5 {
        score += 5;
        checks.push(format!("{{\"device_count\":{devices},\"name\":\"Device count \\u003c= 5\",\"pass\":true,\"points\":5}}"));
    } else {
        checks.push(format!("{{\"action\":\"Review and remove unused devices\",\"device_count\":{devices},\"name\":\"Device count \\u003c= 5\",\"pass\":false,\"points\":0}}"));
    }
    done(format!(
        "{{\"checks\":[{}],\"score\":{}}}",
        checks.join(","),
        score.min(100)
    ))
}

/// What `DELETE /user/sessions/{id}` found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Revoked {
    Revoked,
    NotFound,
}

/// Go's `Revoke`: the web session arm, then the oauth family (or lone token) arm, in one
/// transaction.
pub async fn session_revoke(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: &str,
    operation: [u8; 16],
) -> CommandOutcome<Revoked, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("session.revoke"),
        &envelope(&auth, operation, &format!("session.revoke:{id}")),
        &auth,
        deadline(),
        crate::sql::SESSION_REVOKE_ONE.sql,
        &[(&id, Type::TEXT)],
        |rows| match rows
            .first()
            .and_then(|r| r.try_get::<_, String>(0).ok())
            .as_deref()
        {
            Some("revoked") => Ok(Revoked::Revoked),
            Some("not_found") => Ok(Revoked::NotFound),
            _ => Err(invalid()),
        },
    )
    .await
}

/// Go's `RevokeAll`.
pub async fn sessions_revoke_all(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("sessions.revoke_all"),
        &envelope(&auth, operation, "sessions.revoke_all"),
        &auth,
        deadline(),
        crate::sql::SESSIONS_REVOKE_ALL.sql,
        &[],
        |rows| rows.first().map(|_| ()).ok_or_else(invalid),
    )
    .await
}

/// Go's `Secure` ("This wasn't me"): `ip` is the resolved client address.
pub async fn secure_account(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("account.secure"),
        &envelope(&auth, operation, &format!("account.secure:{ip}")),
        &auth,
        deadline(),
        crate::sql::SECURE_ACCOUNT_SELF.sql,
        &[(&ip, Type::TEXT)],
        |rows| rows.first().map(|_| ()).ok_or_else(invalid),
    )
    .await
}
