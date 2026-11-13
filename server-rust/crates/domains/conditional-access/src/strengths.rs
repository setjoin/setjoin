//! Conditional access (F03) slice `remaining`: authentication strengths. Reads repeat Go's
//! query; writes call `ca_auth_strength_set`, which commits data, audit and the notify together.
use super::cmd::{counted, one_i64, run};
use super::policies::compact;
use super::{done, invalid, nano, s};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

/// `GET .../auth-strengths-list`: built-ins first, then by name.
pub async fn list(exec: &ScopedExecutor) -> Result<String, StatementFailure> {
    let sql = format!(
        "SELECT id, slug, name, description, requirement::text, min_acr, builtin, {}, {} \
         FROM auth_strengths ORDER BY builtin DESC, name ASC",
        nano("created_at"),
        nano("updated_at")
    );
    let rows = exec.read(&sql, &[]).await?;
    let bad = |_| invalid();
    let mut out = Vec::new();
    for r in &rows {
        out.push(format!(
            "{{\"builtin\":{},\"created_at\":{},\"description\":{},\"id\":{},\"min_acr\":{},\"name\":{},\"requirement\":{},\"slug\":{},\"updated_at\":{}}}",
            r.try_get::<_, bool>(6).map_err(bad)?,
            s(&r.try_get::<_, String>(7).map_err(bad)?),
            s(&r.try_get::<_, String>(3).map_err(bad)?),
            r.try_get::<_, i64>(0).map_err(bad)?,
            s(&r.try_get::<_, String>(5).map_err(bad)?),
            s(&r.try_get::<_, String>(2).map_err(bad)?),
            compact(&r.try_get::<_, String>(4).map_err(bad)?),
            s(&r.try_get::<_, String>(1).map_err(bad)?),
            s(&r.try_get::<_, String>(8).map_err(bad)?),
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

pub struct Strength<'a> {
    pub slug: &'a str,
    pub name: &'a str,
    /// The raw `combinations` document when the body carried one (`null` included).
    pub combinations: Option<&'a str>,
    pub min_acr: &'a str,
}

/// Create (`id` 0) or update: `ca_auth_strength_set(id, slug, name, combinations, min_acr,
/// false, actor, ip)`.
pub async fn save(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    id: i64,
    strength: &Strength<'_>,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let combinations = strength.combinations.map(compact);
    run(
        exec,
        actor,
        if id == 0 {
            "ca_auth_strength_create"
        } else {
            "ca_auth_strength_update"
        },
        operation,
        &format!(
            "{id}:{ip}:{}:{}:{combinations:?}:{}",
            strength.slug, strength.name, strength.min_acr
        ),
        "SELECT ca_auth_strength_set($4,$5,$6,$7::text::jsonb,$8,false,$2,$9::text::inet) \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&id, Type::INT8),
            (&strength.slug, Type::TEXT),
            (&strength.name, Type::TEXT),
            (&combinations, Type::TEXT),
            (&strength.min_acr, Type::TEXT),
            (&ip, Type::TEXT),
        ],
        one_i64,
    )
    .await
}

/// `DELETE .../auth-strengths/{id}`: `ca_auth_strength_set(id, NULL, NULL, NULL, NULL, true, ..)`.
pub async fn delete(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    run(
        exec,
        actor,
        "ca_auth_strength_delete",
        operation,
        &format!("{id}:{ip}"),
        "SELECT count(*)::bigint FROM (SELECT ca_auth_strength_set($4,NULL,NULL,NULL,NULL,true,$2,$5::text::inet) \
         WHERE $1::bigint > 0 AND $3::text <> '') w",
        &[(&id, Type::INT8), (&ip, Type::TEXT)],
        counted,
    )
    .await
}
