//! Authserver's independent 30-second positive-match snapshot (no NOTIFY).
use setjoin_pg::workers::{SessionRevocation, WorkerDatabase};
use std::sync::RwLock;
#[derive(Default)]
pub struct AuthDenylist(RwLock<Vec<SessionRevocation>>);
impl AuthDenylist {
    pub async fn refresh(&self, db: &WorkerDatabase) -> Result<(), crate::Error> {
        let rows = db.active_session_revocations().await?;
        *self.0.write().unwrap() = rows;
        Ok(())
    }
    pub fn contains(&self, user: i64, iat: i128, jti: &str, family: &str) -> bool {
        self.0.read().unwrap().iter().any(|r| {
            r.user_id == user
                && match r.scope.as_str() {
                    "all" => iat <= r.not_before_nanos,
                    "jti" => !jti.is_empty() && r.jti == jti,
                    "family" => !family.is_empty() && r.family == family,
                    _ => false,
                }
        })
    }
}
