//! Signed approval-email capability. Identity is sealed after HMAC verification.
use base64::{engine::general_purpose::URL_SAFE, Engine};
use hmac::{Hmac, Mac};
use setjoin_authz::principals::{TxFactory, UserPrincipal};
use setjoin_contracts::ids::ActorId;
use setjoin_pg::{CommandOutcome, StatementFailure};
use sha2::Sha256;

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct Claims {
    r: i64,
    a: i64,
    d: String,
    e: i64,
}

pub struct Capability {
    claims: Claims,
}

impl Capability {
    pub fn verify(token: &str, secret: &[u8], now: i64) -> Option<Self> {
        let (payload, sig) = token.split_once('.')?;
        let sig = decode_go_url(sig)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).ok()?;
        mac.update(payload.as_bytes());
        mac.verify_slice(&sig).ok()?;
        let claims: Claims = serde_json::from_slice(&decode_go_url(payload)?).ok()?;
        if now > claims.e {
            return None;
        }
        Some(Self { claims })
    }

    pub fn request_id(&self) -> i64 {
        self.claims.r
    }

    pub fn decision(&self) -> &str {
        &self.claims.d
    }

    pub fn actor_user_id(&self) -> Option<ActorId> {
        ActorId::new(self.claims.a).ok()
    }

    pub async fn decide(
        &self,
        tx_factory: &TxFactory,
        user: &UserPrincipal,
        consumer: &str,
        operation: [u8; 16],
    ) -> CommandOutcome<String, StatementFailure> {
        crate::decide_consumer(
            tx_factory,
            user,
            consumer,
            self.claims.r,
            &self.claims.d,
            None,
            operation,
        )
        .await
    }

    pub async fn request(
        &self,
        tx_factory: &TxFactory,
        user: &UserPrincipal,
    ) -> Result<Option<(String, String, String)>, StatementFailure> {
        let uid = user.user().get();
        let id = self.claims.r;
        let rows = tx_factory
            .run_user_read_contract(user, &crate::sql::EMAIL_REQUEST, &[&id, &uid])
            .await?;
        Ok(rows.first().map(|r| (r.get(0), r.get(1), r.get(2))))
    }
}

/// Issued only by the system notifier from database-owned request/approver data.
pub fn sign(request: i64, user: i64, decision: &str, expiry: i64, secret: &[u8]) -> String {
    let payload = URL_SAFE.encode(format!(
        "{{\"r\":{request},\"a\":{user},\"d\":{},\"e\":{expiry}}}",
        serde_json::to_string(decision).expect("decision")
    ));
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key");
    mac.update(payload.as_bytes());
    format!("{payload}.{}", URL_SAFE.encode(mac.finalize().into_bytes()))
}

// encoding/base64.URLEncoding ignores CR/LF and accepts nonzero trailing pad
// bits. Those encodings still authenticate the same signature bytes in Go.
fn decode_go_url(s: &str) -> Option<Vec<u8>> {
    let clean = s
        .bytes()
        .filter(|b| !matches!(b, b'\r' | b'\n'))
        .collect::<Vec<_>>();
    base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true),
    )
    .decode(clean)
    .ok()
}
