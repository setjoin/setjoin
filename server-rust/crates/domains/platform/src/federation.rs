//! Platform slice `terms-remaining`, group `federation`: the admin federation allow-list
//! console (`/admin/federation/peers*`), Go's `FederationHandler`.
//!
//! `federation_allowlist` is deny-all row-level security for the request role, so reads run
//! on the worker credential; writes are the existing SECURITY DEFINER reducers
//! `federation_peer_set` and `federation_peer_delete` (one reducer call each), run as the
//! verified actor. The list is an audited read, written best effort after the reads.
use super::{command, deadline, done, envelope, invalid, s, scope};
use serde_json::Value;
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

/// `GET /admin/federation/peers`: rows by domain with each peer's transport health. Go
/// answers any read or decode failure with a database error.
pub async fn list(worker: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = worker
        .read(
            "SELECT peer_domain, scope, enabled, created_at::TEXT, updated_at::TEXT \
             FROM federation_allowlist ORDER BY peer_domain",
            &[],
        )
        .await?;
    fn bad<E>(_: E) -> StatementFailure {
        invalid()
    }
    let mut out = Vec::new();
    for row in &rows {
        let domain: String = row.try_get(0).map_err(bad)?;
        let health = worker
            .read(
                "SELECT federation_peer_health($1)::text",
                &[(&domain, Type::TEXT)],
            )
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
            // `json.Unmarshal` into two int64 fields: absent or null keeps zero, a
            // non-integer number or another type fails.
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("federation_peers_list"),
        &envelope(&auth, operation, "federation_peers_list"),
        &auth,
        deadline(),
        "SELECT audit_write($2,'federation_peers_list','federation_peer',NULL,NULL,NULL,$4::text::inet,'','core') \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&ip, Type::TEXT)],
        |_| Ok(()),
    )
    .await
}

/// The stored anchor of a peer, `None` when the peer does not exist.
pub async fn anchor(
    worker: &ScopedExecutor,
    domain: &str,
) -> Result<Option<String>, StatementFailure> {
    let rows = worker
        .read(
            "SELECT peer_anchor FROM federation_allowlist WHERE peer_domain = $1",
            &[(&domain, Type::TEXT)],
        )
        .await?;
    match rows.first() {
        None => Ok(None),
        Some(row) => Ok(Some(row.try_get(0).map_err(|_| invalid())?)),
    }
}

/// `POST`: upsert one peer (the reducer audits and wakes the reconcile loop).
pub async fn set(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    domain: &str,
    anchor: &str,
    scope_name: &str,
    enabled: bool,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("federation_peer_set"),
        &envelope(&auth, operation, &format!("set:{domain}:{scope_name}:{enabled}")),
        &auth,
        deadline(),
        "SELECT federation_peer_set($2, $4, $5, $6, $7)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&domain, Type::TEXT),
            (&anchor, Type::TEXT),
            (&scope_name, Type::TEXT),
            (&enabled, Type::BOOL),
        ],
        |rows| if rows.len() == 1 { Ok(()) } else { Err(invalid()) },
    )
    .await
}

/// `DELETE`: `true` when a (disabled) peer was removed.
pub async fn delete(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    domain: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("federation_peer_delete"),
        &envelope(&auth, operation, &format!("delete:{domain}")),
        &auth,
        deadline(),
        "SELECT federation_peer_delete($2, $4) WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&domain, Type::TEXT)],
        |rows| {
            rows.first()
                .filter(|_| rows.len() == 1)
                .and_then(|r| r.try_get::<_, bool>(0).ok())
                .ok_or_else(invalid)
        },
    )
    .await
}
