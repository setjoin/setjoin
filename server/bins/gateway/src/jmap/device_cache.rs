//! Go's process-local 5 s device denylist. Global reads use only the explicitly
//! supplied worker credential; the request pool is used only for the toggle.
use setjoin_pg::{workers::WorkerDatabase, ScopedExecutor};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
#[derive(Default)]
pub struct DeviceCache(Mutex<Option<(Instant, HashSet<Vec<u8>>)>>);
impl DeviceCache {
    pub async fn revoked(
        &self,
        exec: &ScopedExecutor,
        worker: Option<&WorkerDatabase>,
        fingerprint: &str,
    ) -> bool {
        if fingerprint.is_empty() {
            return false;
        }
        if !exec.read("SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.device_trust_enforcement'),false)",&[]).await.is_ok_and(|r|r[0].get::<_,bool>(0)) {return false}
        self.revoked_enabled(worker, fingerprint).await
    }

    /// The caller already checked device-trust enforcement for this request.
    /// Reuse that decision: a second toggle lookup must not erase it on error.
    pub async fn revoked_enabled(
        &self,
        worker: Option<&WorkerDatabase>,
        fingerprint: &str,
    ) -> bool {
        if fingerprint.is_empty() {
            return false;
        }
        let mut cached = self.0.lock().await;
        if cached
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() >= Duration::from_secs(5))
        {
            if let Some(worker) = worker {
                let loaded=async {
                    let connection=worker.connect().await?;
                    let rows=connection.query("SELECT fingerprint_hash FROM user_devices WHERE fingerprint_hash IS NOT NULL AND (wipe_requested=true OR offline_approval='revoked')",&[]).await?;
                    Ok::<_,Box<dyn std::error::Error+Send+Sync>>(rows.into_iter().map(|r|r.get::<_,Vec<u8>>(0)).collect())
                }.await;
                if let Ok(set) = loaded {
                    *cached = Some((Instant::now(), set));
                }
            }
        }
        use sha2::Digest;
        let hash = sha2::Sha256::digest(fingerprint.as_bytes()).to_vec();
        cached.as_ref().is_none_or(|(_, set)| set.contains(&hash))
    }
}
