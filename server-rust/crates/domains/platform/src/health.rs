//! Platform slice `system-features`, group `health`: the bounded shared health verdict
//! (`GET /admin/health`).
//!
//! Go's `health.Handler.Check`: the latest `health_history` row per check plus every
//! registered live component probe, behind a 5 s verdict cache, a global token bucket and a
//! one-evaluation concurrency bound. The ok-to-error alert is raised through an optional
//! [`Alerts`] observer (the gateway's webhook dispatcher), which receives every checked row.
use super::{config::go_f64, done, s};
use setjoin_pg::ScopedExecutor;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Receives the latest `(check_name, status)` rows of an evaluation, in check-name order.
pub type Alerts =
    Arc<dyn Fn(Vec<(String, String)>) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Go's `healthEvalTTL`.
pub const EVAL_TTL: Duration = Duration::from_secs(5);
const BURST: f64 = 30.0;
const RATE_PER_SEC: f64 = 10.0;

/// Go's `tokenBucket`.
pub struct Bucket {
    tokens: f64,
    last: Option<Instant>,
}
impl Default for Bucket {
    fn default() -> Self {
        Self {
            tokens: 0.0,
            last: None,
        }
    }
}
impl Bucket {
    pub fn allow(&mut self, now: Instant) -> bool {
        match self.last {
            None => {
                self.tokens = BURST;
            }
            Some(last) => {
                self.tokens += now.saturating_duration_since(last).as_secs_f64() * RATE_PER_SEC;
                if self.tokens > BURST {
                    self.tokens = BURST;
                }
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

/// What one evaluation answered, replayed byte for byte while cached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// `WriteJSON(status, {"checks":..,"status":..})`.
    Json { status: u16, body: String },
    /// `http.Error(w, "internal error", 500)`.
    Internal,
}

/// The cold-start flood corner: nothing to replay, so fail closed.
pub fn throttled() -> Verdict {
    Verdict::Json {
        status: 503,
        body: done("{\"checks\":[],\"status\":\"error\"}".into()),
    }
}

/// One live component probe's outcome (`error` carries `err.Error()`).
pub struct Probe {
    pub name: &'static str,
    pub error: Option<String>,
}

/// The query of Go's `runEvaluation`, with the numeric columns as float8 (pgx scans them
/// into `*float64`).
const LATEST: &str = "SELECT DISTINCT ON (check_name) check_name, status, value::float8, threshold::float8, details, \
     to_char(checked_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS') || CASE WHEN date_part('microseconds', checked_at AT TIME ZONE 'UTC')::bigint % 1000000 = 0 THEN '' ELSE regexp_replace(to_char(checked_at AT TIME ZONE 'UTC','.US'),'0+$','') END || 'Z' \
     FROM health_history ORDER BY check_name, checked_at DESC";

/// A full evaluation. `now` renders the probes' `checked_at`.
pub async fn evaluate(
    exec: &ScopedExecutor,
    probes: &[Probe],
    now: &str,
    alerts: Option<&Alerts>,
) -> Verdict {
    let Ok(rows) = exec.read(LATEST, &[]).await else {
        return Verdict::Internal;
    };
    let mut results: Vec<String> = Vec::new();
    let mut checked: Vec<(String, String)> = Vec::new();
    let mut overall = "ok";
    for row in &rows {
        // A row pgx cannot scan (a NULL `details`) ends Go's iteration with the scan error,
        // which `rows.Err()` then reports: the whole verdict is its internal error.
        let (Ok(name), Ok(status), Ok(value), Ok(threshold), Ok(Some(details)), Ok(at)) = (
            row.try_get::<_, String>(0),
            row.try_get::<_, String>(1),
            row.try_get::<_, Option<f64>>(2),
            row.try_get::<_, Option<f64>>(3),
            row.try_get::<_, Option<String>>(4),
            row.try_get::<_, String>(5),
        ) else {
            // Go has already dispatched for the rows before the one it could not scan.
            if let Some(alerts) = alerts {
                alerts(checked).await;
            }
            return Verdict::Internal;
        };
        checked.push((name.clone(), status.clone()));
        if status == "error" {
            overall = "error";
        } else if status == "warn" && overall != "error" {
            overall = "warn";
        }
        let mut item = format!("{{\"check_name\":{},\"status\":{}", s(&name), s(&status));
        if let Some(v) = value {
            item += &format!(",\"value\":{}", go_f64(v));
        }
        if let Some(v) = threshold {
            item += &format!(",\"threshold\":{}", go_f64(v));
        }
        item += &format!(",\"details\":{},\"checked_at\":{}}}", s(&details), s(&at));
        results.push(item);
    }
    if let Some(alerts) = alerts {
        alerts(checked).await;
    }
    for probe in probes {
        let (status, details) = match &probe.error {
            None => ("ok", "reachable".to_owned()),
            Some(error) => {
                overall = "error";
                ("error", error.clone())
            }
        };
        results.push(format!(
            "{{\"check_name\":{},\"status\":{},\"details\":{},\"checked_at\":{}}}",
            s(probe.name),
            s(status),
            s(&details),
            s(now)
        ));
    }
    Verdict::Json {
        status: if overall == "error" { 503 } else { 200 },
        body: done(format!(
            "{{\"checks\":[{}],\"status\":{}}}",
            results.join(","),
            s(overall)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_admits_a_burst_then_refills() {
        let start = Instant::now();
        let mut bucket = Bucket::default();
        assert!((0..30).all(|_| bucket.allow(start)));
        assert!(!bucket.allow(start));
        assert!(bucket.allow(start + Duration::from_millis(150)));
    }

    #[test]
    fn throttled_verdict_is_the_json_vocabulary() {
        assert_eq!(
            throttled(),
            Verdict::Json {
                status: 503,
                body: "{\"checks\":[],\"status\":\"error\"}\n".into()
            }
        );
    }
}
