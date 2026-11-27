//! Platform slice `terms-remaining`, group `federation`: the admin federation allow-list
//! console (`/admin/federation/peers*`), Go's `FederationHandler`.
use super::{command, deadline, done, envelope, invalid, s, sql};
use serde_json::Value;
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

/// `GET /admin/federation/peers`: rows by domain with each peer's transport health.
pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::FEDERATION_LIST, &[])
        .await?;
    fn bad<E>(_: E) -> StatementFailure {
        invalid()
    }
    let mut out = Vec::new();
    for row in &rows {
        let domain: String = row.try_get(0).map_err(bad)?;
        let health = factory
            .run_admin_read_contract(admin, &sql::FEDERATION_PEER_HEALTH, &[&domain])
            .await?;
        let mut item = format!(
            "{{\"peerDomain\":{},\"scope\":{},\"enabled\":{},\"createdAt\":{},\"updatedAt\":{}",
            s(&domain),
            s(&row.try_get::<_, String>(1).map_err(bad)?),
            row.try_get::<_, bool>(2).map_err(bad)?,
            s(&row.try_get::<_, String>(3).map_err(bad)?),
            s(&row.try_get::<_, String>(4).map_err(bad)?),
        );
        let text: Option<String> = health
            .first()
            .ok_or_else(invalid)?
            .try_get(0)
            .map_err(bad)?;
        if let Some(text) = text {
            let value: Value = serde_json::from_str(&text).map_err(bad)?;
            let object = value.as_object().ok_or_else(invalid)?;
            let number = |key: &str| -> Result<i64, StatementFailure> {
                let found = object
                    .iter()
                    .find(|(k, _)| crate::fold_key(k) == crate::fold_key(key))
                    .map(|(_, v)| v);
                match found {
                    None | Some(Value::Null) => Ok(0),
                    Some(Value::Number(n)) => n.as_i64().ok_or_else(invalid),
                    Some(_) => Err(invalid()),
                }
            };
            item += &format!(
                ",\"unackedDepth\":{},\"lastAckAgeSeconds\":{}",
                number("unackedDepth")?,
                number("lastAckAgeSeconds")?
            );
        }
        item.push('}');
        out.push(item);
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// The audited read: Go writes `federation_peers_list` after the reads and ignores a failure.
pub async fn audit_list(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor_id = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        "federation_peers_list",
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::FEDERATION_AUDIT_LIST,
            &[&actor_id, &ip],
            Some(command("federation_peers_list")),
            |_| Ok(()),
        )
        .await
}

/// The stored anchor of a peer, `None` when the peer does not exist.
pub async fn anchor(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain: &str,
) -> Result<Option<String>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::FEDERATION_ANCHOR, &[&domain])
        .await?;
    match rows.first() {
        None => Ok(None),
        Some(row) => Ok(Some(row.try_get(0).map_err(|_| invalid())?)),
    }
}

/// `POST`: upsert one peer (the reducer audits and wakes the reconcile loop).
pub async fn set(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain: &str,
    anchor: &str,
    scope_name: &str,
    enabled: bool,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("set:{domain}:{scope_name}:{enabled}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::FEDERATION_PEER_SET,
            &[&domain, &anchor, &scope_name, &enabled],
            Some(command("federation_peer_set")),
            |rows, _audited| {
                if rows.len() == 1 {
                    Ok(())
                } else {
                    Err(invalid())
                }
            },
        )
        .await
}

/// `DELETE`: `true` when a (disabled) peer was removed.
pub async fn delete(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("delete:{domain}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::FEDERATION_PEER_DELETE,
            &[&domain],
            Some(command("federation_peer_delete")),
            |rows, _audited| {
                rows.first()
                    .filter(|_| rows.len() == 1)
                    .and_then(|r| r.try_get::<_, bool>(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}
