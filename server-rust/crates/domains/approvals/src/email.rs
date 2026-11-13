//! Signed approval-email capability. Identity is sealed after HMAC verification.
use crate::{
    invalid, ActorId, Generation, MailboxAuthContext, MailboxId, ScopedExecutor, StatementFailure,
    Type,
};
use base64::{engine::general_purpose::URL_SAFE, Engine};
use hmac::{Hmac, Mac};
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
    pub fn decision(&self) -> &str {
        &self.claims.d
    }
    async fn scope(&self, exec: &ScopedExecutor) -> Result<MailboxAuthContext, StatementFailure> {
        let user = self.claims.a;
        let rows = exec
            .read(
                "SELECT id FROM mailboxes WHERE user_id=$1 AND is_primary=true LIMIT 1",
                &[(&user, Type::INT8)],
            )
            .await?;
        let mailbox = rows
            .first()
            .map(|r| r.get::<_, i64>(0))
            .ok_or_else(invalid)?;
        Ok(MailboxAuthContext::from_authenticated_session(
            ActorId::new(user).map_err(|_| invalid())?,
            MailboxId::new(mailbox).map_err(|_| invalid())?,
            Generation(1),
        ))
    }
    pub async fn decide(
        &self,
        exec: &ScopedExecutor,
        worker: &ScopedExecutor,
        consumer: &str,
        operation: [u8; 16],
    ) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
        let scope = match self.scope(exec).await {
            Ok(a) => a,
            Err(e) => {
                return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(e))
            }
        };
        crate::decide_consumer(
            if matches!(consumer, "mail.external_send" | "mail.group_moderation") {
                worker
            } else {
                exec
            },
            &scope,
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
        exec: &ScopedExecutor,
    ) -> Result<Option<(String, String, String)>, StatementFailure> {
        let user = self.claims.a;
        let id = self.claims.r;
        let rows=exec.read_scoped(&self.scope(exec).await?,"SELECT subject,status,consumer_type FROM approval_requests r WHERE id=$1 AND (requester_user_id=$2 OR (approver_kind='user' AND approver_ref=$2) OR (approver_kind='role_group' AND EXISTS(SELECT 1 FROM public.admin_role_assignments a WHERE a.user_id=$2 AND a.role_group_id=r.approver_ref AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until))) OR EXISTS(SELECT 1 FROM public.admin_role_assignments a JOIN public.admin_role_groups g ON g.id=a.role_group_id WHERE a.user_id=$2 AND (a.expires_at IS NULL OR a.expires_at>now()) AND public.admin_assignment_active(a.eligible,a.activated_until) AND g.permissions && ARRAY['approvals.view','approvals.manage']::text[]))",&[(&id,Type::INT8),(&user,Type::INT8)]).await?;
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
