//! `mailserver/internal/health`: the public `/health` verdict and `/ready`.
//!
//! Go evaluates `health_history` (latest row per check) plus live component
//! probes behind a 5 s verdict cache, a global token bucket and a one-at-a-time
//! evaluation lock, and dispatches a webhook on every ok-to-error transition.
//! The Rust verdict mirrors the cache, bucket and aggregation, and reports every
//! checked row to an [`Alerts`] observer (the gateway's webhook dispatcher) so
//! `system.health_alert` is raised in Rust. The SFU/egress/ASR probes run through an
//! optional [`Probes`] runner; a deployment with those sidecars configured and no
//! runner is left to Go ([`Outcome::Defer`]).
use setjoin_pg::ScopedExecutor;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const EVAL_TTL: Duration = Duration::from_secs(5);
const BURST: f64 = 30.0;
const RATE_PER_SEC: f64 = 10.0;
const EVAL_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// `httputil.WriteJSON(status, {"status": overall})`.
    Json { status: u16, overall: &'static str },
    /// Go's `http.Error(w, "internal error", 500)` (query failed).
    Internal,
    /// Leave the whole request to Go (live probes are configured).
    Defer,
}

/// Runs the live component probes (Go's registered `sfu`, `egress` and `asr`) and
/// answers whether any of them failed: the public verdict names no checks.
pub type Probes = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>;

/// Receives the latest `(check_name, status)` rows of each full evaluation, in check-name
/// order, after the verdict is computed (Go dispatches inside the loop; the order and the
/// per-row transition rule are the same).
pub type Alerts =
    Arc<dyn Fn(Vec<(String, String)>) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

struct Bucket {
    tokens: f64,
    last: Option<Instant>,
}

impl Bucket {
    fn allow(&mut self, now: Instant) -> bool {
        match self.last {
            None => self.tokens = BURST,
            Some(last) => {
                self.tokens =
                    (self.tokens + now.duration_since(last).as_secs_f64() * RATE_PER_SEC).min(BURST)
            }
        }
        self.last = Some(now);
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

pub struct HealthGate {
    /// SFU, egress or ASR probes would be registered in this deployment.
    probes_configured: bool,
    bucket: Mutex<Bucket>,
    cache: Mutex<Option<(Instant, Outcome)>>,
    evaluating: tokio::sync::Mutex<()>,
    alerts: Option<Alerts>,
    probes: Option<Probes>,
}

impl HealthGate {
    pub fn new(probes_configured: bool) -> Self {
        Self {
            probes_configured,
            bucket: Mutex::new(Bucket {
                tokens: 0.0,
                last: None,
            }),
            cache: Mutex::new(None),
            evaluating: tokio::sync::Mutex::new(()),
            alerts: None,
            probes: None,
        }
    }

    /// Run the live probes in each full evaluation instead of leaving the request to Go.
    pub fn with_probes(mut self, probes: Probes) -> Self {
        self.probes = Some(probes);
        self
    }

    /// Raise `system.health_alert` through `alerts` on ok-to-error transitions.
    pub fn with_alerts(mut self, alerts: Alerts) -> Self {
        self.alerts = Some(alerts);
        self
    }

    /// `PublicCheck`: the redacted verdict.
    pub async fn public(&self, exec: &ScopedExecutor) -> Outcome {
        if self.probes_configured && self.probes.is_none() {
            return Outcome::Defer;
        }
        let admitted = self.bucket.lock().expect("bucket").allow(Instant::now());
        let _one = self.evaluating.lock().await;
        let cached = self.cache.lock().expect("cache").clone();
        if let Some((at, outcome)) = cached {
            if !admitted || at.elapsed() < EVAL_TTL {
                return outcome;
            }
        }
        if !admitted {
            return Outcome::Json {
                status: 503,
                overall: "error",
            };
        }
        let outcome = tokio::time::timeout(
            EVAL_TIMEOUT,
            evaluate(exec, self.alerts.as_ref(), self.probes.as_ref()),
        )
        .await
        .unwrap_or(Outcome::Internal);
        *self.cache.lock().expect("cache") = Some((Instant::now(), outcome.clone()));
        outcome
    }
}

async fn evaluate(
    exec: &ScopedExecutor,
    alerts: Option<&Alerts>,
    probes: Option<&Probes>,
) -> Outcome {
    let rows = exec
        .read(
            "SELECT DISTINCT ON (check_name) check_name, status FROM health_history ORDER BY check_name, checked_at DESC",
            &[],
        )
        .await;
    let Ok(rows) = rows else {
        return Outcome::Internal;
    };
    let mut overall = "ok";
    let mut checked = Vec::with_capacity(rows.len());
    for row in rows {
        let (name, status) = (row.get::<_, String>(0), row.get::<_, String>(1));
        match status.as_str() {
            "error" => overall = "error",
            "warn" if overall != "error" => overall = "warn",
            _ => {}
        }
        checked.push((name, status));
    }
    if let Some(alerts) = alerts {
        alerts(checked).await;
    }
    // Live probes are synchronous and bounded, never DB-backed; a failed one is `error`.
    if let Some(probes) = probes {
        if probes().await {
            overall = "error";
        }
    }
    Outcome::Json {
        status: if overall == "error" { 503 } else { 200 },
        overall,
    }
}

/// `Ready`: the pool answers a ping.
pub async fn ready(exec: &ScopedExecutor) -> bool {
    exec.read("SELECT 1", &[]).await.is_ok()
}
