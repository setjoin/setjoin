//! Conditional access (F03) slice `remaining`: named locations. Reads repeat Go's query; every
//! write calls `ca_named_location_set|restore`, which commit data, audit and the single
//! `ca_notify_policy_change` together.
use super::cmd::{counted, one_i64, run};
use super::policies::compact;
use super::{done, invalid, nano, s};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

/// `GET .../named-locations`: Go's `[]map[string]any`, keys in sorted order, `ip_ranges` and
/// `countries` jsonb compacted like a `json.RawMessage`.
pub async fn list(
    exec: &ScopedExecutor,
    include_deleted: bool,
) -> Result<String, StatementFailure> {
    let sql = format!(
        "SELECT id, name, description, ip_ranges::text, countries::text, is_trusted, \
         {}, {}, CASE WHEN deleted_at IS NULL THEN NULL ELSE {} END \
         FROM named_locations{} ORDER BY name ASC",
        nano("created_at"),
        nano("updated_at"),
        nano("deleted_at"),
        if include_deleted {
            ""
        } else {
            " WHERE deleted_at IS NULL"
        }
    );
    let rows = exec.read(&sql, &[]).await?;
    let bad = |_| invalid();
    let mut out = Vec::new();
    for r in &rows {
        let deleted: Option<String> = r.try_get(8).map_err(bad)?;
        out.push(format!(
            "{{\"countries\":{},\"created_at\":{},\"deleted_at\":{},\"description\":{},\"id\":{},\"ip_ranges\":{},\"is_trusted\":{},\"name\":{},\"updated_at\":{}}}",
            compact(&r.try_get::<_, String>(4).map_err(bad)?),
            s(&r.try_get::<_, String>(6).map_err(bad)?),
            deleted.map_or("null".to_string(), |d| s(&d)),
            s(&r.try_get::<_, String>(2).map_err(bad)?),
            r.try_get::<_, i64>(0).map_err(bad)?,
            compact(&r.try_get::<_, String>(3).map_err(bad)?),
            r.try_get::<_, bool>(5).map_err(bad)?,
            s(&r.try_get::<_, String>(1).map_err(bad)?),
            s(&r.try_get::<_, String>(7).map_err(bad)?),
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

pub struct Location<'a> {
    pub name: &'a str,
    pub description: &'a str,
    /// `None` is Go's nil slice: SQL NULL.
    pub cidrs: Option<&'a [String]>,
    pub countries: Option<&'a [String]>,
    pub trusted: bool,
}

/// Create (`id` 0) or update: Go's `ca_named_location_set(id, name, description, cidrs,
/// countries, trusted, false, actor, ip)`; the answer is the row id.
pub async fn save(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    id: i64,
    location: &Location<'_>,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let cidrs: Option<Vec<String>> = location.cidrs.map(<[String]>::to_vec);
    let countries: Option<Vec<String>> = location.countries.map(<[String]>::to_vec);
    run(
        exec,
        actor,
        if id == 0 {
            "ca_named_location_create"
        } else {
            "ca_named_location_update"
        },
        operation,
        &format!(
            "{id}:{ip}:{}:{}:{cidrs:?}:{countries:?}:{}",
            location.name, location.description, location.trusted
        ),
        "SELECT ca_named_location_set($4,$5,$6,$7::text[]::cidr[],$8::text[],$9,false,$2,$10::text::inet) \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&id, Type::INT8),
            (&location.name, Type::TEXT),
            (&location.description, Type::TEXT),
            (&cidrs, Type::TEXT_ARRAY),
            (&countries, Type::TEXT_ARRAY),
            (&location.trusted, Type::BOOL),
            (&ip, Type::TEXT),
        ],
        one_i64,
    )
    .await
}

/// `DELETE .../named-locations/{id}`: the soft-delete path of the same reducer.
pub async fn soft_delete(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    run(
        exec,
        actor,
        "ca_named_location_delete",
        operation,
        &format!("{id}:{ip}"),
        "SELECT count(*)::bigint FROM (SELECT ca_named_location_set($4,NULL,NULL,NULL,NULL,NULL,true,$2,$5::text::inet) \
         WHERE $1::bigint > 0 AND $3::text <> '') w",
        &[(&id, Type::INT8), (&ip, Type::TEXT)],
        counted,
    )
    .await
}

/// `POST .../named-locations/{id}/restore`.
pub async fn restore(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    run(
        exec,
        actor,
        "ca_named_location_restore",
        operation,
        &format!("{id}:{ip}"),
        "SELECT ca_named_location_restore($4,$2,$5::text::inet) WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&id, Type::INT8), (&ip, Type::TEXT)],
        one_i64,
    )
    .await
}
