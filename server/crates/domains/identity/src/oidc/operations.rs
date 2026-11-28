//! Commit metadata may be observed only after fresh current credential proof.
use super::*;
use setjoin_contracts::ids::{ActorId, OperationId};
use setjoin_pg::{CommandOutcome, StatementFailure};
#[derive(Clone, Copy)]
pub enum Operation {
    Complete,
    Code,
    Consume,
    Access,
    RefreshAttach,
    Rotate,
    RefreshReuse,
    Revoke,
    EndSession,
}
impl Operation {
    fn command(self) -> &'static str {
        match self {
            Self::Complete => "oidc-complete",
            Self::Code => "oidc-code",
            Self::Consume => "oidc-consume",
            Self::Access => "oidc-access",
            Self::RefreshAttach => "oidc-refresh-attach",
            Self::Rotate => "oidc-rotate",
            Self::RefreshReuse => "oidc-refresh-reuse",
            Self::Revoke => "oidc-revoke",
            Self::EndSession => "oidc-end-session",
        }
    }
}
pub async fn lookup_operation(
    exec: &AuthDb,
    session: &crate::session::Session,
    operation: OperationId,
    kind: Operation,
) -> Result<bool, StatementFailure> {
    let invalid = || StatementFailure {
        sqlstate: None,
        hint: None,
        message: "OIDC operation lookup authority unavailable".into(),
    };
    if session.text("typ") != "access" || session.bound() {
        return Err(invalid());
    }
    let actor = ActorId::new(session.user()).map_err(|_| invalid())?;
    let op = setjoin_pg::operation_hex(operation);
    let claims = serde_json::Value::Object(session.claims().clone()).to_string();
    let result = exec
        .run_user_command_contract(
            actor,
            operation,
            &crate::sql::USER_OPERATION_LOOKUP,
            &[
                (&session.user(), Type::INT8),
                (&op, Type::TEXT),
                (&kind.command(), Type::TEXT),
                (&claims, Type::TEXT),
            ],
            |r| {
                r.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await;
    match result {
        CommandOutcome::Committed(found) => Ok(found),
        _ => Err(invalid()),
    }
}
pub async fn lookup_authorization(
    exec: &AuthDb,
    id: &str,
    operation: OperationId,
) -> Result<bool, StatementFailure> {
    client(exec, id).await.map_err(|e| StatementFailure {
        sqlstate: None,
        hint: None,
        message: e,
    })?;
    exec.lookup_protocol_operation(
        &format!("oidc-client:{id}"),
        operation,
        setjoin_pg::ReceiptCommand {
            family: "F21",
            command: "oidc-authorize",
        },
    )
    .await
}
