//! Session- or pending-token-bound management assertions. HTTP cannot supply ownership.
use crate::{session::Session, webauthn::RelyingParty};
use serde_json::Value;
use setjoin_contracts::ids::{ActorId, OperationId};
use setjoin_pg::{AuthDb, CommandOutcome, StatementFailure, Type};
use sha2::{Digest, Sha256};
/// The reducer's JSON text is the first row's column. A missing row, NULL, wrong type or
/// bad JSON rejects the statement with the function's existing failure.
fn json_row(rows: &[setjoin_pg::Row], message: &str) -> Result<Value, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .ok_or_else(|| StatementFailure {
            sqlstate: None,
            hint: None,
            message: message.into(),
        })
}
pub async fn begin(
    exec: &AuthDb,
    session: &Session,
    rp: &RelyingParty,
    operation: &str,
    target: Option<String>,
) -> CommandOutcome<Value, StatementFailure> {
    let Ok(actor) = ActorId::new(session.user()) else {
        return CommandOutcome::Committed(serde_json::json!({"status":"internal"}));
    };
    let Ok(challenge) = rp.management_challenge() else {
        return CommandOutcome::Committed(serde_json::json!({"status":"internal"}));
    };
    let hash = format!("{:x}", Sha256::digest(challenge.as_bytes()));
    let claims = Value::Object(session.claims().clone()).to_string();
    let exec = exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand {
        family: "F21",
        command: "mfa-webauthn-possession-begin",
    });
    exec.run_user_command_contract(
        actor,
        OperationId(*uuid::Uuid::new_v4().as_bytes()),
        &crate::sql::POSSESSION_L41,
        &[
            (&session.user(), Type::INT8),
            (&claims, Type::TEXT),
            (&operation, Type::TEXT),
            (&target, Type::TEXT),
            (&hash, Type::TEXT),
        ],
        |rows| {
            let mut value: Value = json_row(rows, "ceremony JSON row")?;
            if value["status"] == "created" {
                let options = rp.management_options(&value, &challenge)?;
                value["options"] = serde_json::json!(options);
            }
            Ok(value)
        },
    )
    .await
}

/// A peeked owned ceremony supplies operation equality, never caller-owned identity.
pub struct Ceremony {
    hash: String,
    operation: String,
    target: Option<String>,
}
impl Ceremony {
    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }
}
pub async fn peek(exec: &AuthDb, session: &Session) -> Result<Option<Ceremony>, StatementFailure> {
    let Ok(actor) = ActorId::new(session.user()) else {
        return Ok(None);
    };
    let scope = if session.text("typ") == "mfa_pending" {
        "mfa_pending"
    } else {
        "session"
    };
    let rows = exec
        .read_user_scoped_contract(
            actor,
            &crate::sql::POSSESSION_L87,
            &[
                (&session.user(), Type::INT8),
                (&scope, Type::TEXT),
                (&session.text("jti"), Type::TEXT),
            ],
        )
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let bad = || StatementFailure {
        sqlstate: None,
        hint: None,
        message: "ceremony row".into(),
    };
    Ok(Some(Ceremony {
        hash: row.try_get(0).map_err(|_| bad())?,
        operation: row.try_get(1).map_err(|_| bad())?,
        target: row.try_get(2).map_err(|_| bad())?,
    }))
}
pub async fn finish(
    exec: &AuthDb,
    session: &Session,
    rp: &RelyingParty,
    ceremony: &Ceremony,
    raw: &[u8],
) -> CommandOutcome<Value, StatementFailure> {
    use crate::webauthn::ManagementResult;
    use setjoin_pg::ProvenContract;
    let Ok(actor) = ActorId::new(session.user()) else {
        return CommandOutcome::Committed(serde_json::json!({"status":"internal"}));
    };
    let pending = session.text("typ") == "mfa_pending";
    let (Ok(first), Ok(second)) = (crate::login::random_jti(), crate::login::random_jti()) else {
        return CommandOutcome::Committed(serde_json::json!({"status":"internal"}));
    };
    let token = format!("{first}{second}");
    let grant_hash = if pending {
        session
            .token_hash()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    } else {
        format!("{:x}", Sha256::digest(token.as_bytes()))
    };
    let claims = Value::Object(session.claims().clone()).to_string();
    let exec = exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand {
        family: "F21",
        command: "mfa-webauthn-possession-finish",
    });
    exec.run_user_proof_command_contract(
        actor,
        OperationId(*uuid::Uuid::new_v4().as_bytes()),
        &crate::sql::POSSESSION_L134,
        &[
            (&session.user(), Type::INT8),
            (&claims, Type::TEXT),
            (&ceremony.hash, Type::TEXT),
        ],
        |rows| {
            let value: Value = json_row(rows, "management snapshot row")?;
            if value["status"] != "ready" {
                return Ok(
                    ProvenContract::new(&crate::sql::ECHO_TEXT).bind(value.to_string(), Type::TEXT)
                );
            }
            let (verdict, factor) = match rp.management_verify(&value, &ceremony.hash, raw) {
                ManagementResult::Malformed => ("malformed", None),
                ManagementResult::Rejected => ("invalid", None),
                ManagementResult::Accepted(id) => ("accepted", Some(id)),
            };
            Ok(ProvenContract::new(&crate::sql::POSSESSION_L139)
                .bind(session.user(), Type::INT8)
                .bind(claims.clone(), Type::TEXT)
                .bind(ceremony.hash.clone(), Type::TEXT)
                .bind(verdict.to_owned(), Type::TEXT)
                .bind(factor, Type::BYTEA)
                .bind(grant_hash, Type::TEXT))
        },
        |rows| {
            let mut value: Value = json_row(rows, "management result row")?;
            if value["status"] == "issued" {
                value["pending"] = serde_json::json!(pending);
                if !pending {
                    value["token"] = serde_json::json!(token);
                }
            }
            Ok(value)
        },
    )
    .await
}
