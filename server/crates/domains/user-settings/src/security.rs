//! Slice `settings-c` (#308): self-service session and account-security routes.
use super::{command, deadline, done, invalid, s, user_envelope};
use setjoin_authz::principals::{TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, Row, SqlContract, StatementFailure};

pub async fn sessions_list(
    factory: &TxFactory,
    user: &UserPrincipal,
    jti: &str,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &crate::sql::SESSIONS_LIST, &[&uid, &jti])
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

pub async fn devices_list(factory: &TxFactory, user: &UserPrincipal) -> String {
    let uid = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &crate::sql::DEVICES_LIST, &[&uid])
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

pub async fn login_history(
    factory: &TxFactory,
    user: &UserPrincipal,
    jti: &str,
    outcome: &str,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    let rows = factory
        .run_user_read_contract(
            user,
            &crate::sql::LOGIN_HISTORY,
            &[&uid, &limit, &offset, &jti, &outcome],
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
    let row = factory
        .run_user_read_contract(user, &crate::sql::LOGIN_HISTORY_SUMMARY, &[&uid])
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
    factory: &TxFactory,
    user: &UserPrincipal,
    contract: &'static SqlContract,
    get: impl Fn(&Row) -> Option<T>,
) -> Option<T> {
    let uid = user.user().get();
    let rows = factory
        .run_user_read_contract(user, contract, &[&uid])
        .await
        .ok()?;
    rows.first().and_then(get)
}

pub async fn security_score(factory: &TxFactory, user: &UserPrincipal) -> String {
    let mut score = 50;
    let mut checks: Vec<String> = vec![];
    let totp = one_value(factory, user, &crate::sql::SECURITY_SCORE_TOTP, |r| {
        r.try_get::<_, bool>(0).ok()
    })
    .await
    .unwrap_or(false);
    if totp {
        score += 20;
        checks.push("{\"name\":\"TOTP enabled\",\"pass\":true,\"points\":20}".into());
    } else {
        checks.push("{\"action\":\"Enable two-factor authentication\",\"name\":\"TOTP enabled\",\"pass\":false,\"points\":0}".into());
    }
    let backup = one_value(
        factory,
        user,
        &crate::sql::SECURITY_SCORE_BACKUP_CODES,
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
        factory,
        user,
        &crate::sql::SECURITY_SCORE_FAILED_LOGINS,
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
        factory,
        user,
        &crate::sql::SECURITY_SCORE_DEVICE_COUNT,
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Revoked {
    Revoked,
    NotFound,
}

pub async fn session_revoke(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: &str,
    operation: [u8; 16],
) -> CommandOutcome<Revoked, StatementFailure> {
    let uid = user.user().get();
    let env = user_envelope(user, operation, &format!("session.revoke:{id}"));
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::SESSION_REVOKE_ONE,
            &[&uid, &id],
            Some(command("session.revoke")),
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

pub async fn sessions_revoke_all(
    factory: &TxFactory,
    user: &UserPrincipal,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    let env = user_envelope(user, operation, "sessions.revoke_all");
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::SESSIONS_REVOKE_ALL,
            &[&uid],
            Some(command("sessions.revoke_all")),
            |rows| rows.first().map(|_| ()).ok_or_else(invalid),
        )
        .await
}

pub async fn secure_account(
    factory: &TxFactory,
    user: &UserPrincipal,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let uid = user.user().get();
    let env = user_envelope(user, operation, &format!("account.secure:{ip}"));
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::SECURE_ACCOUNT_SELF,
            &[&uid, &ip],
            Some(command("account.secure")),
            |rows| rows.first().map(|_| ()).ok_or_else(invalid),
        )
        .await
}
