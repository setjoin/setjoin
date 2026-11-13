//! Conditional access (F03) slice `remaining`: the user-risk dashboard routes. Both run on the
//! worker credential, as Go does (`user_risk` has FORCE RLS); `reset` is one receipted statement
//! carrying Go's whole transaction (the update and its audit row).
use super::cmd::run;
use super::policies::compact;
use super::{done, invalid, s};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

/// `GET /admin/user-risk?limit=`: elevated rows by score, `limit` default 100, capped at 500.
pub async fn list(worker: &ScopedExecutor, limit: i64) -> Result<String, StatementFailure> {
    let rows = worker
        .read(
            "SELECT r.user_id, COALESCE(u.email, ''), r.score::int, r.level, r.signals::text, r.updated_at::text \
             FROM user_risk r JOIN users u ON u.id = r.user_id \
             WHERE r.level != 'none' ORDER BY r.score DESC LIMIT $1",
            &[(&limit, Type::INT8)],
        )
        .await?;
    let bad = |_| invalid();
    let mut out = Vec::new();
    for r in &rows {
        out.push(format!(
            "{{\"user_id\":{},\"email\":{},\"score\":{},\"level\":{},\"signals\":{},\"updated_at\":{}}}",
            r.try_get::<_, i64>(0).map_err(bad)?,
            s(&r.try_get::<_, String>(1).map_err(bad)?),
            r.try_get::<_, i32>(2).map_err(bad)?,
            s(&r.try_get::<_, String>(3).map_err(bad)?),
            compact(&r.try_get::<_, String>(4).map_err(bad)?),
            s(&r.try_get::<_, String>(5).map_err(bad)?),
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// `POST /admin/user-risk/{id}/reset`: `true` when a row was reset (and audited), `false` for
/// Go's 404 `user_risk not found`.
pub async fn reset(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    user: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let after = format!("{{\"action\":\"risk_reset\",\"user_id\":{user}}}");
    run(
        worker,
        actor,
        "user_risk_reset",
        operation,
        &format!("{ip}:{user}"),
        "WITH r AS (UPDATE user_risk SET score=0, level='none', signals='[]'::jsonb, \
         remediated_at=now(), updated_at=now() WHERE user_id=$4 RETURNING user_id), \
         a AS (SELECT audit_write($2,'user_risk.reset','user_risk',$4,NULL,$5::text::jsonb,$6::text::inet,'','core') FROM r) \
         SELECT (SELECT count(*) FROM r)::bigint, (SELECT count(*) FROM a)::bigint \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&user, Type::INT8), (&after, Type::TEXT), (&ip, Type::TEXT)],
        |rows| match rows {
            [row] => {
                let reset = row.try_get::<_, i64>(0).map_err(|_| invalid())?;
                let audited = row.try_get::<_, i64>(1).map_err(|_| invalid())?;
                if reset == audited && reset <= 1 {
                    Ok(reset == 1)
                } else {
                    Err(invalid())
                }
            }
            _ => Err(invalid()),
        },
    )
    .await
}
