//! Frozen telemetry.PGStore: one autocommit INSERT, with device authority from
//! the shared HMAC verifier rather than any request-owned identity field.
use setjoin_authz::device::VerifiedDevice;
use setjoin_pg::{workers::WorkerDatabase, Type};
use std::collections::BTreeMap;

pub struct Report {
    pub app_version: String,
    pub os_version: String,
    pub crash_count: i64,
    pub uptime_hours: i64,
    pub feature_usage: BTreeMap<String, i64>,
}

pub async fn insert(
    db: &WorkerDatabase,
    device: &VerifiedDevice,
    report: &Report,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let usage = serde_json::to_string(&report.feature_usage)?;
    db.connect().await?.query(
        "INSERT INTO device_telemetry(device_id,app_version,os_version,crash_count,uptime_hours,feature_usage) VALUES($1,$2,$3,$4,$5,$6::text::jsonb)",
        &[(&device.id(),Type::INT8),(&report.app_version,Type::TEXT),(&report.os_version,Type::TEXT),(&report.crash_count,Type::INT8),(&report.uptime_hours,Type::INT8),(&usage,Type::TEXT)],
    ).await?;
    Ok(())
}
