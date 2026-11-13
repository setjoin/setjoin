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
    exec: &ScopedExecutor,
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
    let result=exec.run_user_command(actor,operation,
  "SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=substr(encode(digest($2::text || ':' || $1::text,'sha256'),'hex'),1,32)::uuid AND family='F21' AND command=$3) WHERE EXISTS(SELECT 1 FROM users u WHERE u.id=$1 AND u.enabled AND identity_transition_admission_allowed(u.id) AND (COALESCE($4::text::jsonb->>'credential_fence','')='' OR rtrim(translate(encode(digest(u.password_hash,'sha256'),'base64'),'+/','-_'),'=')=$4::text::jsonb->>'credential_fence')) AND NOT EXISTS(SELECT 1 FROM session_revocations WHERE user_id=$1 AND (expires_at IS NULL OR expires_at>now()) AND ((scope='jti' AND jti=COALESCE($4::text::jsonb->>'jti','')) OR (scope='family' AND family_id=COALESCE($4::text::jsonb->>'fam','')) OR (scope='all' AND to_timestamp(COALESCE(($4::text::jsonb->>'iat')::double precision,0))<=not_before)))",
  &[(&session.user(),Type::INT8),(&op,Type::TEXT),(&kind.command(),Type::TEXT),(&claims,Type::TEXT)],|r|r.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await;
    match result {
        CommandOutcome::Committed(found) => Ok(found),
        _ => Err(invalid()),
    }
}
pub async fn lookup_authorization(
    exec: &ScopedExecutor,
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
