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
    exec: &ScopedExecutor,
    worker: &ScopedExecutor,
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
    let result=worker.run_user_command(actor,operation,
        "SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=substr(encode(digest($2::text || ':' || $1::text,'sha256'),'hex'),1,32)::uuid AND family='F21' AND command=$3) WHERE EXISTS(SELECT 1 FROM users u WHERE u.id=$1 AND u.enabled AND NOT is_guest_account(u.id) AND identity_transition_admission_allowed(u.id) AND ((NOT $6 AND u.oidc_subject=$4 AND u.oidc_issuer=$5) OR ($6 AND EXISTS(SELECT 1 FROM user_identity_links l JOIN identity_sources s ON s.id=l.source_id WHERE l.user_id=u.id AND l.external_subject=$4 AND l.state='active' AND 'authenticate'=ANY(l.purposes) AND s.state='active' AND s.kind='oidc' AND s.source_key='oidc:'||substr(encode(digest($5,'sha256'),'hex'),1,48)))))",
        &[(&user,Type::INT8),(&op,Type::TEXT),(&kind.command(),Type::TEXT),(&assertion.subject,Type::TEXT),(&assertion.issuer,Type::TEXT),(&normalized,Type::BOOL)],
        |rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await;
    match result {
        CommandOutcome::Committed(v) => Ok(v),
        _ => Err(invalid()),
    }
}
pub async fn lookup_session(
    exec: &ScopedExecutor,
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
    let result=exec.run_user_command(actor,operation,
        "SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=substr(encode(digest($2::text || ':' || $1::text,'sha256'),'hex'),1,32)::uuid AND family='F21' AND command=$3) WHERE EXISTS(SELECT 1 FROM users u JOIN sessions s ON s.user_id=u.id WHERE u.id=$1 AND u.enabled AND s.user_id=$1 AND s.token_hash=$5 AND s.expires_at>now() AND identity_transition_admission_allowed(u.id)) AND NOT EXISTS(SELECT 1 FROM session_revocations WHERE user_id=$1 AND (expires_at IS NULL OR expires_at>now()) AND ((scope='jti' AND jti=COALESCE($4::text::jsonb->>'jti','')) OR (scope='family' AND family_id=COALESCE($4::text::jsonb->>'fam','')) OR (scope='all' AND to_timestamp(COALESCE(($4::text::jsonb->>'iat')::double precision,0))<=not_before)))",
        &[(&user,Type::INT8),(&op,Type::TEXT),(&kind.command(),Type::TEXT),(&claims,Type::TEXT),(&hash,Type::BYTEA)],
        |rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await;
    match result {
        CommandOutcome::Committed(v) => Ok(v),
        _ => Err(invalid()),
    }
}
