//! Shared OIDC/SAML link management. Only a verified session supplies the owner.
use crate::session::Session;
use serde_json::{json, Value};
use setjoin_pg::{AuthDb, StatementFailure, Type};

pub fn fresh(session: &Session) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i128;
    matches!(session.text("acr"), "aal2" | "aal3")
        && session
            .claims()
            .get("iat")
            .and_then(Value::as_i64)
            .is_some_and(|iat| now - iat as i128 <= 300)
}

pub async fn unlink(
    exec: &AuthDb,
    session: &Session,
    link: i64,
    reason: &str,
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    // Signature validation preserves Go's raw uid claim. A nonpositive owner
    // cannot enter a typed user command; Go's owned reducer returns BZ234.
    let actor = match setjoin_contracts::ids::ActorId::new(session.user()) {
        Ok(actor) => actor,
        Err(_) => {
            return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(
                StatementFailure {
                    sqlstate: Some("BZ234".into()),
                    hint: None,
                    message: "identity link not found".into(),
                },
            ))
        }
    };
    let operation = setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes());
    exec.clone()
        .with_user_receipt(setjoin_pg::ReceiptCommand {
            family: "F21",
            command: "identity-unlink",
        })
        .run_user_command_contract(
            actor,
            operation,
            &crate::sql::IDENTITY_LINKS_L48,
            &[
                (&session.user(), Type::INT8),
                (&link, Type::INT8),
                (&reason, Type::TEXT),
            ],
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(|| StatementFailure {
                        sqlstate: None,
                        hint: None,
                        message: "invalid identity unlink result".into(),
                    })
            },
        )
        .await
}

pub async fn list(exec: &AuthDb, session: &Session) -> Result<Value, StatementFailure> {
    let Ok(actor) = setjoin_contracts::ids::ActorId::new(session.user()) else {
        return Ok(json!([]));
    };
    // Frozen Go ignores a late Rows.Err; a Scan/type failure is still fatal.
    let rows = exec
        .read_user_scoped_iterated_contract(
            actor,
            &crate::sql::IDENTITY_LINKS_L69,
            &[(&session.user(), Type::INT8)],
        )
        .await?;
    let mut items = Vec::new();
    for row in rows {
        let decode = || -> Result<Value, StatementFailure> {
            let error = || StatementFailure {
                sqlstate: None,
                hint: None,
                message: "identity links unavailable".into(),
            };
            let id: String = row.try_get(0).map_err(|_| error())?;
            let kind: String = row.try_get(1).map_err(|_| error())?;
            let name: String = row.try_get(2).map_err(|_| error())?;
            let state: String = row.try_get(3).map_err(|_| error())?;
            let seen: String = row.try_get(4).map_err(|_| error())?;
            Ok(
                json!({"id":id,"kind":kind,"displayName":name,"state":state,"lastSeenAt":format!("{}Z",seen.trim_end_matches('0').trim_end_matches('.'))}),
            )
        };
        items.push(decode()?);
    }
    Ok(json!({"items":items}))
}
