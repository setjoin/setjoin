//! Conditional access (F03) slice `remaining`: authentication strengths. Reads run via
//! `AdminReadTx`; writes call `rust_ca_auth_strength_set` via `AdminWriteTx`
//! (`ReducerWritesCoreAudit`), committing data, audit and the notify together.
use super::cmd::{one_i64, run_audited};
use super::policies::compact;
use super::{done, invalid, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::{CommandOutcome, StatementFailure};

/// `GET .../auth-strengths-list`: built-ins first, then by name.
pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::STRENGTHS_LIST, &[])
        .await?;
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

/// Create (`id` 0) or update: `rust_ca_auth_strength_set`.
pub async fn save(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    ip: &str,
    id: i64,
    strength: &Strength<'_>,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let combinations = strength.combinations.map(compact);
    let delete = false;
    run_audited(
        factory,
        admin,
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
        &sql::STRENGTH_SET,
        &[
            &id,
            &strength.slug,
            &strength.name,
            &combinations,
            &strength.min_acr,
            &delete,
            &ip,
        ],
        one_i64,
    )
    .await
}

/// `DELETE .../auth-strengths/{id}`: `rust_ca_auth_strength_set(..., delete = true)`.
pub async fn delete(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    ip: &str,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let none_text: Option<&str> = None;
    let delete = true;
    run_audited(
        factory,
        admin,
        "ca_auth_strength_delete",
        operation,
        &format!("{id}:{ip}"),
        &sql::STRENGTH_SET,
        &[
            &id, &none_text, &none_text, &none_text, &none_text, &delete, &ip,
        ],
        |rows| {
            if rows.len() == 1 {
                Ok(())
            } else {
                Err(invalid())
            }
        },
    )
    .await
}
