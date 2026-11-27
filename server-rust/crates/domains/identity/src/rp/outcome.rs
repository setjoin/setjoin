//! Opaque commit inspection requires fresh verified authority and the original
//! actor/operation lock. Correlation UUIDs and request identity fields confer none.
use super::*;
use crate::session::Session;
use setjoin_contracts::ids::{ActorId, OperationId};
use setjoin_pg::{CommandOutcome, StatementFailure, Type};
#[derive(Clone, Copy)]
pub enum Operation {
    Settle,
    Mint,
    LinkBegin,
    LinkFinish,
    SamlLinkBegin,
    SamlLinkFinish,
    Unlink,
}
impl Operation {
    fn command(self) -> &'static str {
        match self {
            Self::Settle => "rp-settle",
            Self::Mint => "rp-mint",
            Self::LinkBegin => "rp-link-begin",
            Self::LinkFinish => "rp-link-finish",
            Self::SamlLinkBegin => "saml-link-begin",
            Self::SamlLinkFinish => "saml-link-finish",
            Self::Unlink => "identity-unlink",
        }
    }
}
fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "OIDC operation lookup authority unavailable".into(),
    }
}
pub async fn lookup_assertion(
    exec: &AuthDb,
    worker: &AuthDb,
    assertion: &Assertion,
    operation: OperationId,
    kind: Operation,
) -> Result<bool, StatementFailure> {
    if !matches!(kind, Operation::Settle | Operation::Mint) {
        return Err(invalid());
    }
    let Lookup::Existing(resolution) = assertion.resolve(exec, worker).await? else {
        return Err(invalid());
    };
    let user = resolution.user.user;
    let actor = ActorId::new(user).map_err(|_| invalid())?;
    let op = setjoin_pg::operation_hex(operation);
    let normalized = resolution.normalized();
    let result = worker
        .run_user_command_contract(
            actor,
            operation,
            &crate::sql::USER_OPERATION_LOOKUP,
            &[
                (&user, Type::INT8),
                (&op, Type::TEXT),
                (&kind.command(), Type::TEXT),
                (&assertion.subject, Type::TEXT),
                (&assertion.issuer, Type::TEXT),
                (&normalized, Type::BOOL),
            ],
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await;
    match result {
        CommandOutcome::Committed(v) => Ok(v),
        _ => Err(invalid()),
    }
}
pub async fn lookup_session(
    exec: &AuthDb,
    session: &Session,
    operation: OperationId,
    kind: Operation,
) -> Result<bool, StatementFailure> {
    if !matches!(
        kind,
        Operation::LinkBegin
            | Operation::LinkFinish
            | Operation::SamlLinkBegin
            | Operation::SamlLinkFinish
            | Operation::Unlink
    ) || session.text("typ") != "access"
        || session.bound()
    {
        return Err(invalid());
    }
    let user = session.user();
    let actor = ActorId::new(user).map_err(|_| invalid())?;
    let op = setjoin_pg::operation_hex(operation);
    let claims = serde_json::Value::Object(session.claims().clone()).to_string();
    let hash = session.token_hash().to_vec();
    let result = exec
        .run_user_command_contract(
            actor,
            operation,
            &crate::sql::USER_OPERATION_LOOKUP,
            &[
                (&user, Type::INT8),
                (&op, Type::TEXT),
                (&kind.command(), Type::TEXT),
                (&claims, Type::TEXT),
                (&hash, Type::BYTEA),
            ],
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await;
    match result {
        CommandOutcome::Committed(v) => Ok(v),
        _ => Err(invalid()),
    }
}
