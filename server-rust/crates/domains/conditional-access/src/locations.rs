//! Conditional access (F03) slice `remaining`: named locations. Reads run via `AdminReadTx`;
//! every write calls `rust_ca_named_location_set|restore` via `AdminWriteTx`
//! (`ReducerWritesCoreAudit`), committing data, core audit and `ca_notify_policy_change` together.
use super::cmd::{one_i64, run_audited};
use super::policies::compact;
use super::{done, invalid, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::{CommandOutcome, StatementFailure};

/// `GET .../named-locations`: Go's `[]map[string]any`, keys in sorted order, `ip_ranges` and
/// `countries` jsonb compacted like a `json.RawMessage`.
pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    include_deleted: bool,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::LOCATIONS_LIST, &[&include_deleted])
        .await?;
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

/// Create (`id` 0) or update: `rust_ca_named_location_set`; the answer is the row id.
pub async fn save(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    ip: &str,
    id: i64,
    location: &Location<'_>,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let cidrs: Option<Vec<String>> = location.cidrs.map(<[String]>::to_vec);
    let countries: Option<Vec<String>> = location.countries.map(<[String]>::to_vec);
    let delete = false;
    run_audited(
        factory,
        admin,
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
        &sql::LOCATION_SET,
        &[
            &id,
            &location.name,
            &location.description,
            &cidrs,
            &countries,
            &location.trusted,
            &delete,
            &ip,
        ],
        one_i64,
    )
    .await
}

/// `DELETE .../named-locations/{id}`: the soft-delete path of the same reducer.
pub async fn soft_delete(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    ip: &str,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let none_text: Option<&str> = None;
    let none_arr: Option<Vec<String>> = None;
    let none_bool: Option<bool> = None;
    let delete = true;
    run_audited(
        factory,
        admin,
        "ca_named_location_delete",
        operation,
        &format!("{id}:{ip}"),
        &sql::LOCATION_SET,
        &[
            &id, &none_text, &none_text, &none_arr, &none_arr, &none_bool, &delete, &ip,
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

/// `POST .../named-locations/{id}/restore`.
pub async fn restore(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    ip: &str,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    run_audited(
        factory,
        admin,
        "ca_named_location_restore",
        operation,
        &format!("{id}:{ip}"),
        &sql::LOCATION_RESTORE,
        &[&id, &ip],
        one_i64,
    )
    .await
}
