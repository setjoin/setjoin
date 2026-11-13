//! Frozen authserver's process-local positive-match mirror: seed, then 30s polls.
//! This cache has no shared effects and runs on both sides during the transfer.
use setjoin_identity::session::Session;
use setjoin_pg::workers::WorkerDatabase;
use setjoin_threat::AuthDenylist;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
#[derive(Default)]
pub struct Revocations {
    rows: Arc<AuthDenylist>,
    /// Set by the first successful list load. Until then every token is treated
    /// as revoked (owner-approved security fix 2026-11-05, #491): an empty,
    /// never-loaded list must not admit revoked access tokens.
    loaded: Arc<AtomicBool>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl Revocations {
    pub async fn load(request_dsn: &str, worker_dsn: Option<&str>) -> Self {
        let fallback = std::env::var("DB_DSN").unwrap_or_default();
        let dsn = if request_dsn.is_empty() {
            fallback.as_str()
        } else {
            request_dsn
        };
        let Ok(db) = WorkerDatabase::from_dsns(dsn, worker_dsn) else {
            return Self::default();
        };
        let rows = Arc::new(AuthDenylist::default());
        let loaded = Arc::new(AtomicBool::new(rows.refresh(&db).await.is_ok()));
        let state = rows.clone();
        let ready = loaded.clone();
        let task = tokio::spawn(async move {
            let period = std::time::Duration::from_secs(30);
            let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticks.tick().await;
                match state.refresh(&db).await {
                    Ok(()) => ready.store(true, Ordering::Release),
                    Err(error) => {
                        eprintln!("auth denylist: refresh failed; prior snapshot retained: {error}")
                    }
                }
            }
        });
        Self {
            rows,
            loaded,
            task: Some(task),
        }
    }
    pub fn contains(&self, session: &Session) -> bool {
        self.contains_claims(session.claims())
    }
    /// Same projection for sealed claims that did not come from a `Session`.
    pub fn contains_claims(&self, claims: &serde_json::Map<String, serde_json::Value>) -> bool {
        if !self.loaded.load(Ordering::Acquire)
            && !setjoin_contracts::mutants::on("revocations-fail-open")
        {
            return true;
        }
        let text = |key: &str| claims.get(key).and_then(serde_json::Value::as_str).unwrap_or("");
        let iat = (claims
            .get("iat")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.)
            .floor()
            * 1_000_000_000.) as i128;
        self.rows.contains(
            claims.get("uid").and_then(serde_json::Value::as_i64).unwrap_or(0),
            iat,
            text("jti"),
            text("fam"),
        )
    }
}
impl Drop for Revocations {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
