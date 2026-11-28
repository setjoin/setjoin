//! Telemetry report data shape (DB ingest lives in `bins/gateway/src/telemetry.rs`).
use std::collections::BTreeMap;

pub struct Report {
    pub app_version: String,
    pub os_version: String,
    pub crash_count: i64,
    pub uptime_hours: i64,
    pub feature_usage: BTreeMap<String, i64>,
}
