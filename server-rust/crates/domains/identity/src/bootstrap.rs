//! Device bootstrap uses Go's explicit access-Bearer signature seam. It does
//! not borrow full-session revocation/DPoP admission that Go omits here.
use serde_json::Value;
use setjoin_pg::{ScopedExecutor, Type};
pub struct Proof {
    user: i64,
    claims: serde_json::Map<String, Value>,
}
pub enum Invalid {
    Token,
    Type,
}
impl Proof {
    pub async fn authenticate(
        keys: &impl setjoin_authz::token::KeySource,
        token: &str,
        issuer: &str,
    ) -> Result<Self, Invalid> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Invalid::Token)?
            .as_secs_f64();
        let c = setjoin_authz::token::validate_first_party(token, issuer, now, keys)
            .await
            .ok_or(Invalid::Token)?;
        if c.get("typ").and_then(Value::as_str) != Some("access") {
            return Err(Invalid::Type);
        }
        let user = c
            .get("uid")
            .and_then(Value::as_i64)
            .filter(|u| *u > 0)
            .ok_or(Invalid::Token)?;
        Ok(Self { user, claims: c })
    }
    pub fn user(&self) -> i64 {
        self.user
    }
    /// Signed claims, for the caller's revocation and sender-binding checks.
    pub fn claims(&self) -> &serde_json::Map<String, Value> {
        &self.claims
    }
    /// `cnf.jkt` of a sender-constrained token.
    pub fn bound_jkt(&self) -> Option<&str> {
        self.claims
            .get("cnf")
            .and_then(|v| v.get("jkt"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    }
    pub async fn register(
        &self,
        exec: &ScopedExecutor,
        name: &str,
        platform: &str,
        os: &str,
        app: &str,
        fp: &str,
        enc: &[u8],
    ) -> setjoin_pg::CommandOutcome<(i64, bool), setjoin_pg::StatementFailure> {
        exec.run_user_command(
            setjoin_contracts::ids::ActorId::new(self.user).expect("verified user"),
            setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes()),
            "SELECT * FROM rust_identity_device_register($1,$2,$3,$4,$5,$6,$7)",
            &[
                (&self.user, Type::INT8),
                (&name, Type::TEXT),
                (&platform, Type::TEXT),
                (&os, Type::TEXT),
                (&app, Type::TEXT),
                (&fp, Type::TEXT),
                (&enc, Type::BYTEA),
            ],
            |rows| Ok((rows[0].get(0), rows[0].get(1))),
        )
        .await
    }
}
