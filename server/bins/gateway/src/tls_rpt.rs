//! `tls-rpt-report` (#323): the daily TLS-RPT (RFC 8460) report worker, mirroring frozen
//! Go's `smtp.TLSRPTWorker` statement for statement.
//!
//! Go waits ten minutes, then every 24 hours reads yesterday's `tls_rpt_sessions` rows,
//! builds one report per (policy domain, report URI) pair and, for an `https://` report URI,
//! POSTs it through the SSRF-guarded client and then deletes that domain's sessions for the
//! date, whatever the status of the answer. A `mailto:` URI, an empty URI or any other scheme
//! sends nothing and keeps the rows; a failed POST keeps them too. Go only launches the
//! worker when `feature.tls_rpt` is enabled (default ON).
use serde_json::{json, Value};
use setjoin_pg::{workers::WorkerDatabase, Type};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

pub const NAME: &str = "tls-rpt-report";
/// Go's `initialDelay`.
pub const INITIAL_DELAY: Duration = Duration::from_secs(10 * 60);
/// The interval between reports.
pub const INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const POST_TIMEOUT: Duration = Duration::from_secs(10);

/// Go's `featureToggles.IsEnabled(toggle.FeatureTlsRpt)`: a stored row wins, the default is ON.
pub async fn enabled(db: &WorkerDatabase) -> bool {
    let Ok(connection) = db.connect().await else {
        return false;
    };
    connection
        .query(
            "SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.tls_rpt'), true)",
            &[],
        )
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
        .unwrap_or(false)
}

pub struct TlsRptReport {
    db: WorkerDatabase,
    hostname: String,
    client: reqwest::Client,
    guard_literals: bool,
    /// Go's `mu`: one report run at a time.
    running: tokio::sync::Mutex<()>,
}

/// One aggregated `tls_rpt_sessions` row of the report date.
struct Session {
    mx_host: String,
    mx_ip: String,
    result: String,
    failure: String,
    count: i32,
}

/// Go's `parseRUA`: the first `mailto:` entry's address, size suffix stripped.
fn parse_rua(rua: &str) -> String {
    for entry in rua.split(',') {
        let entry = entry.trim();
        if let Some(email) = entry.strip_prefix("mailto:") {
            return email.split('!').next().unwrap_or("").to_owned();
        }
    }
    String::new()
}

impl TlsRptReport {
    /// Production worker: SSRF-guarded client (Go's `ssrf.SafeHTTPClient(10s)`).
    pub fn new(db: WorkerDatabase, hostname: String) -> Self {
        Self::with_client(
            db,
            hostname,
            crate::webhook::safe_http_client(POST_TIMEOUT),
            true,
        )
    }

    /// Test seam: the client may dial loopback receivers (the oracle's fakes).
    pub fn unguarded_for_tests(db: WorkerDatabase, hostname: String) -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .danger_accept_invalid_certs(true)
            .timeout(POST_TIMEOUT)
            .build()
            .expect("tls-rpt client");
        Self::with_client(db, hostname, client, false)
    }

    fn with_client(
        db: WorkerDatabase,
        hostname: String,
        client: reqwest::Client,
        guard_literals: bool,
    ) -> Self {
        Self {
            db,
            hostname,
            client,
            guard_literals,
            running: tokio::sync::Mutex::new(()),
        }
    }

    /// Go's `Run`: first report after ten minutes, then daily; stop cancels the wait.
    pub async fn run_until(self: Arc<Self>, stop: impl Future<Output = ()> + Send) {
        if !enabled(&self.db).await {
            // Go does not launch the worker at all when `feature.tls_rpt` is off.
            eprintln!("tls-rpt: disabled by feature toggle");
            stop.await;
            return;
        }
        eprintln!("tls-rpt: worker starting initial_delay={INITIAL_DELAY:?}");
        let worker = self.clone();
        let loop_ = async move {
            tokio::time::sleep(INITIAL_DELAY).await;
            loop {
                worker.tick().await;
                tokio::time::sleep(INTERVAL).await;
            }
        };
        tokio::pin!(loop_);
        tokio::pin!(stop);
        tokio::select! {
            _ = &mut loop_ => {}
            _ = &mut stop => {}
        }
        eprintln!("tls-rpt: worker stopped");
    }

    /// Go's `sendReports` for the current UTC day: the oracle seam.
    pub async fn tick(&self) {
        let _guard = self.running.lock().await;
        let yesterday = (chrono::Utc::now() - chrono::Duration::days(1))
            .format("%Y-%m-%d")
            .to_string();
        let Ok(connection) = self.db.connect().await else {
            return;
        };
        let pairs: Vec<(String, String)> = match connection
            .query(
                "SELECT DISTINCT policy_domain, COALESCE(report_uri, '') FROM tls_rpt_sessions \
                 WHERE report_date = $1::text::date",
                &[(&yesterday, Type::TEXT)],
            )
            .await
        {
            Ok(rows) => rows
                .iter()
                .filter_map(|r| Some((r.try_get(0).ok()?, r.try_get(1).ok()?)))
                .collect(),
            Err(_) => return,
        };
        for (domain, uri) in pairs {
            let Some(report) = self.build_report(&connection, &domain, &yesterday).await else {
                continue;
            };
            self.submit(&connection, &domain, &uri, report, &yesterday)
                .await;
        }
    }

    async fn build_report(
        &self,
        connection: &setjoin_pg::workers::WorkerConnection,
        domain: &str,
        date: &str,
    ) -> Option<String> {
        let rows = connection
            .query(
                "SELECT mx_host, COALESCE(mx_ip,''), result, COALESCE(failure_reason,''), session_count \
                 FROM tls_rpt_sessions WHERE policy_domain = $1 AND report_date = $2::text::date",
                &[(&domain, Type::TEXT), (&date, Type::TEXT)],
            )
            .await
            .ok()?;
        let sessions: Vec<Session> = rows
            .iter()
            .filter_map(|r| {
                Some(Session {
                    mx_host: r.try_get(0).ok()?,
                    mx_ip: r.try_get(1).ok()?,
                    result: r.try_get(2).ok()?,
                    failure: r.try_get(3).ok()?,
                    count: r.try_get(4).ok()?,
                })
            })
            .collect();
        if sessions.is_empty() {
            return None;
        }
        let (mut success, mut failure) = (0i64, 0i64);
        let mut failures: Vec<Value> = vec![];
        for s in &sessions {
            if s.result == "success" {
                success += i64::from(s.count);
            } else {
                failure += i64::from(s.count);
                failures.push(json!({
                    "result-type": s.result,
                    "sending-mta-ip": "0.0.0.0",
                    "receiving-mx-hostname": s.mx_host,
                    "receiving-ip": s.mx_ip,
                    "failed-session-count": s.count,
                    "additional-information": s.failure,
                }));
            }
        }
        let day = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()?;
        let start = day.and_hms_opt(0, 0, 0)?;
        let rfc = |t: chrono::NaiveDateTime| t.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let report = json!({
            "organization-name": self.hostname,
            "date-range": {
                "start-datetime": rfc(start),
                "end-datetime": rfc(start + chrono::Duration::days(1)),
            },
            "contact-info": format!("tls-rpt@{}", self.hostname),
            "report-id": format!("{}.{}", day.format("%Y%m%d"), domain),
            "policies": [{
                "policy": {
                    "policy-type": "sts",
                    "policy-string": format!(r#""version":"STSv1","mode":"testing","mx":"*.{domain}""#),
                },
                "summary": {
                    "total-successful-session-count": success,
                    "total-failure-session-count": failure,
                },
                // A nil Go slice marshals as null.
                "failure-details": if failures.is_empty() { Value::Null } else { Value::Array(failures) },
            }],
        });
        // json.MarshalIndent: sorted keys (serde's map), two-space indent, HTML escapes.
        Some(setjoin_mail_security::go_escape(
            &serde_json::to_string_pretty(&report).ok()?,
        ))
    }

    async fn submit(
        &self,
        connection: &setjoin_pg::workers::WorkerConnection,
        domain: &str,
        uri: &str,
        data: String,
        date: &str,
    ) {
        if uri.is_empty() {
            return;
        }
        if !parse_rua(uri).is_empty() {
            eprintln!("tls-rpt: submitting via SMTP domain={domain}");
            return;
        }
        if !uri.starts_with("https://") {
            return;
        }
        let Ok(request) = self
            .client
            .post(uri)
            .header("Content-Type", "application/tlsrpt+json")
            .body(data)
            .build()
        else {
            eprintln!("tls-rpt: HTTPS POST failed uri={uri}");
            return;
        };
        let refused = self.guard_literals
            && match request.url().host() {
                Some(url::Host::Ipv4(ip)) => crate::ssrf::blocked(std::net::IpAddr::V4(ip)),
                Some(url::Host::Ipv6(ip)) => crate::ssrf::blocked(std::net::IpAddr::V6(ip)),
                _ => false,
            };
        if refused || self.client.execute(request).await.is_err() {
            eprintln!("tls-rpt: HTTPS POST failed uri={uri}");
            return;
        }
        // Any answer, whatever its status, clears the date's sessions for the domain.
        let _ = connection
            .execute(
                "DELETE FROM tls_rpt_sessions WHERE policy_domain = $1 AND report_date = $2::text::date",
                &[(&domain, Type::TEXT), (&date, Type::TEXT)],
            )
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::parse_rua;

    #[test]
    fn rua_mailto_is_recognised_like_go() {
        assert_eq!(parse_rua("mailto:a@x.test!10m"), "a@x.test");
        assert_eq!(parse_rua("https://x.test/r, mailto:b@x.test"), "b@x.test");
        assert_eq!(parse_rua("https://x.test/r"), "");
    }
}
