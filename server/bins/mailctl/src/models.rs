//! Wire shapes are ordered like Go's structs, including zero fields and nil slices.
use serde::{Deserialize, Serialize};
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Sync {
    pub checked: i64,
    pub created: i64,
    pub updated: i64,
    pub disabled: i64,
    pub skipped: i64,
    pub errors: i64,
    pub duration: String,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SyncLog {
    pub source: String,
    pub checked: i64,
    pub created: i64,
    pub updated: i64,
    pub disabled: i64,
    pub skipped: i64,
    pub errors: i64,
    pub duration_seconds: i64,
    pub synced_at: String,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DirectoryHealth {
    pub last_sync: Option<String>,
    pub status: String,
    pub checked: i64,
    pub created: i64,
    pub updated: i64,
    pub disabled: i64,
    pub skipped: i64,
    pub errors: i64,
    pub pending_conflicts: i64,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Spam {
    pub enabled: bool,
    pub total_models: i64,
    pub total_samples: i64,
    #[serde(serialize_with = "float")]
    pub avg_samples: f64,
    pub active_week: i64,
    pub disabled_users: i64,
    pub total_fp: i64,
    pub total_classified: i64,
    #[serde(serialize_with = "float")]
    pub fp_rate: f64,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Tls {
    pub enabled: bool,
    pub challenge: String,
    pub domains: Option<Vec<String>>,
    pub email: String,
    pub dns_provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_info: Option<Certificate>,
    pub cache_dir: String,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub days_left: i64,
}

pub(super) fn float<S: serde::Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    if v.fract() == 0.0 && v.abs() < i64::MAX as f64 {
        s.serialize_i64(*v as i64)
    } else {
        s.serialize_f64(*v)
    }
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Feature {
    pub key: String,
    pub enabled: bool,
    pub description: String,
    pub change_mode: String,
    pub disable_behavior: String,
    pub dependencies: Option<Vec<String>>,
    pub confirmation_required: bool,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Quarantine {
    pub id: i64,
    pub message_id: i64,
    pub mailbox_id: i64,
    pub subject: String,
    pub from_addr: String,
    pub original_tag: String,
    pub reason: String,
    pub reason_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virus_name: Option<String>,
    pub preview_token: String,
    pub quarantined_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub released_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub released_by: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_by: Option<i64>,
    pub size_bytes: i64,
    pub recipient: String,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Eap {
    pub id: i64,
    pub priority: i64,
    pub name: String,
    pub enabled: bool,
    pub overwrite_directory_address: bool,
    pub primary_template: String,
    pub duplicate_resolution: String,
    pub updated_at: String,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Ca {
    pub id: i64,
    pub priority: i64,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub scope_type: String,
    pub scope_target: String,
    pub updated_at: String,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CaDoctor {
    pub score: i64,
    pub total: i64,
    pub checks: Option<Vec<CaCheck>>,
    pub hygiene: CaHygiene,
    pub time_to_first_policy_sec: Option<i64>,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CaCheck {
    pub name: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub next_action: String,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CaHygiene {
    pub stale_report_only: Option<Vec<CaStale>>,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CaStale {
    pub id: i64,
    pub name: String,
    pub state: String,
    pub days_since_created: i64,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct QuarantinePreview {
    pub html: String,
    pub subject: String,
    pub from_addr: String,
    pub quarantined_at: String,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct AuditChain {
    pub chain: Option<Vec<AuditRow>>,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AuditRow {
    pub id: i64,
    pub valid: bool,
    pub occurred_at: String,
    pub action: String,
}

// encoding/json leaves non-pointer fields at their zero value for JSON null.
pub(super) fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}
