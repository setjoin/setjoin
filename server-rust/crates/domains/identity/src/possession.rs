//! Session- or pending-token-bound management assertions. HTTP cannot supply ownership.
use crate::{session::Session, webauthn::RelyingParty};
use serde_json::Value;
use setjoin_contracts::ids::{ActorId, OperationId};
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};
use sha2::{Digest, Sha256};
pub async fn begin(
    exec: &ScopedExecutor,
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
    exec.run_user_command(
        actor,
        OperationId(*uuid::Uuid::new_v4().as_bytes()),
        "SELECT rust_identity_possession_webauthn_begin($1,$2::text::jsonb,$3,$4,$5)::text",
        &[
            (&session.user(), Type::INT8),
            (&claims, Type::TEXT),
            (&operation, Type::TEXT),
            (&target, Type::TEXT),
            (&hash, Type::TEXT),
        ],
        |rows| {
            let mut value: Value =
                serde_json::from_str(&rows[0].get::<_, String>(0)).expect("ceremony JSON");
            if value["status"] == "created" {
                value["options"] = serde_json::json!(rp.management_options(&value, &challenge));
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
pub async fn peek(
    exec: &ScopedExecutor,
    session: &Session,
) -> Result<Option<Ceremony>, StatementFailure> {
    let Ok(actor) = ActorId::new(session.user()) else {
        return Ok(None);
    };
    let scope = if session.text("typ") == "mfa_pending" {
        "mfa_pending"
    } else {
        "session"
    };
    let rows=exec.read_user_scoped(actor,"SELECT challenge_hash,operation,target_ref FROM webauthn_ceremonies WHERE user_id=$1 AND kind='management_assertion' AND token_scope=$2 AND session_jti=$3 AND expires_at>now() ORDER BY created_at DESC LIMIT 1",&[(&session.user(),Type::INT8),(&scope,Type::TEXT),(&session.text("jti"),Type::TEXT)]).await?;
    Ok(rows.first().map(|row| Ceremony {
        hash: row.get(0),
        operation: row.get(1),
        target: row.get(2),
    }))
}
pub async fn finish(
    exec: &ScopedExecutor,
    session: &Session,
    rp: &RelyingParty,
    ceremony: &Ceremony,
    raw: &[u8],
) -> CommandOutcome<Value, StatementFailure> {
    use crate::webauthn::ManagementResult;
    use setjoin_pg::ProvenStatement;
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
    exec.run_user_proof_command(actor,OperationId(*uuid::Uuid::new_v4().as_bytes()),
  "SELECT rust_identity_possession_webauthn_read($1,$2::text::jsonb,$3)::text",&[(&session.user(),Type::INT8),(&claims,Type::TEXT),(&ceremony.hash,Type::TEXT)],
  |rows|{
   let value:Value=serde_json::from_str(&rows[0].get::<_,String>(0)).expect("management snapshot");
   if value["status"]!="ready"{return Ok(ProvenStatement::new("SELECT $1::text").bind(value.to_string(),Type::TEXT));}
   let (verdict,factor)=match rp.management_verify(&value,&ceremony.hash,raw){ManagementResult::Malformed=>("malformed",None),ManagementResult::Rejected=>("invalid",None),ManagementResult::Accepted(id)=>("accepted",Some(id))};
   Ok(ProvenStatement::new("SELECT rust_identity_possession_webauthn_finish($1,$2::text::jsonb,$3,$4,$5,$6)::text").bind(session.user(),Type::INT8).bind(claims.clone(),Type::TEXT).bind(ceremony.hash.clone(),Type::TEXT).bind(verdict.to_owned(),Type::TEXT).bind(factor,Type::BYTEA).bind(grant_hash,Type::TEXT))
  },|rows|{let mut value:Value=serde_json::from_str(&rows[0].get::<_,String>(0)).expect("management result");if value["status"]=="issued"{value["pending"]=serde_json::json!(pending);if !pending{value["token"]=serde_json::json!(token);}}Ok(value)}).await
}
