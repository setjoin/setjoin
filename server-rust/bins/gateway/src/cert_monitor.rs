//! Certificate-expiry monitoring of the certificate chain actually served by TLS.

use chrono::{DateTime, Utc};
use setjoin_pg::cert_monitor::CertMonitorDatabase;
use std::future::Future;
use std::time::Duration;

/// Metadata supplied by the TLS certificate selector for its first usable SNI.
#[derive(Clone)]
pub struct Certificate {
    pub not_after: DateTime<Utc>,
    pub common_name: String,
    pub dns_names: Vec<String>,
}

pub struct CertMonitor {
    database: CertMonitorDatabase,
}

impl CertMonitor {
    pub fn new(database: CertMonitorDatabase) -> Self {
        Self { database }
    }

    /// Go checks immediately, then on a ticker created at startup. The source
    /// is evaluated each time so renewal is observed without a restart.
    pub async fn run_until<F, S>(&self, source: F, interval: Duration, shutdown: S)
    where
        F: Fn() -> Vec<Certificate>,
        S: Future<Output = ()>,
    {
        let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(shutdown);
        loop {
            let certs = source();
            let (status, days, details) = describe(&certs, Utc::now());
            match self
                .database
                .record_until(status, days, &details, &mut shutdown)
                .await
            {
                Ok(true) => return,
                Ok(false) => {}
                Err(err) => eprintln!("cert monitor: failed to record health: {err}"),
            }
            tokio::select! {
                () = &mut shutdown => return,
                _ = ticker.tick() => {}
            }
        }
    }
}

fn describe(certs: &[Certificate], now: DateTime<Utc>) -> (&'static str, i32, String) {
    let Some(cert) = certs.iter().min_by_key(|cert| cert.not_after) else {
        return ("error", 0, "no TLS certificates loaded".into());
    };
    // Go's int conversion truncates towards zero, including expired certs.
    let days = (cert.not_after.signed_duration_since(now).num_seconds() / 86_400) as i32;
    let subject = if cert.common_name.is_empty() {
        cert.dns_names.first().map_or("", String::as_str)
    } else {
        &cert.common_name
    };
    let date = cert.not_after.format("%Y-%m-%d");
    if days <= 0 {
        (
            "error",
            days,
            format!("TLS certificate for {subject} has EXPIRED ({date}). Mail delivery impaired."),
        )
    } else if days <= 7 {
        ("error", days, format!("TLS certificate for {subject} expires in {days} days ({date}). Immediate action required."))
    } else if days <= 14 {
        (
            "warn",
            days,
            format!(
                "TLS certificate for {subject} expires in {days} days ({date}). Prepare renewal."
            ),
        )
    } else if days <= 30 {
        (
            "warn",
            days,
            format!("TLS certificate for {subject} expires in {days} days ({date})."),
        )
    } else {
        (
            "ok",
            days,
            format!("TLS certificate for {subject} valid until {date} ({days} days)."),
        )
    }
}
