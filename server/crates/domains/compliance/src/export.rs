//! Case-bound organization-wide export: read-only rows via `AdminReadTx` after
//! `sql::EXPORT_AUTHORIZE` commits the mandatory `ediscovery_export` core audit row.
use super::sql;
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};

pub async fn messages(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    ids: &Vec<i64>,
) -> Vec<(i64, String, String, String, String)> {
    let actor = admin.actor().get();
    let Ok(mut tx) = factory.begin_admin_read(admin).await else {
        return Vec::new();
    };
    let rows = tx
        .query_iterated_contract(&sql::EXPORT_MESSAGES, &[ids, &actor])
        .await
        .unwrap_or_default();
    let _ = tx.finish().await;
    rows.iter()
        .filter_map(|r| {
            Some((
                r.try_get(0).ok()?,
                r.try_get(1).ok()?,
                r.try_get(2).ok()?,
                r.try_get(3).ok()?,
                r.try_get(4).ok()?,
            ))
        })
        .collect()
}
