#[derive(Debug, Clone, uniffi::Record, serde::Serialize)]
pub struct TotpAccount {
    pub id: String,
    pub label: String, // "GitHub:alice@example.com"
    pub issuer: String,
    pub icon: String, // domain for favicon, empty if unknown
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct TotpCode {
    pub code: String,     // 6 or 8 digits
    pub valid_until: i64, // Unix timestamp when this code expires
    pub period: u32,      // seconds per code (usually 30)
}

/// Fields authenticated by a native device when approving a push challenge.
/// Keeping the closed protocol envelope in one record prevents the exported
/// API from growing a positional parameter list whose order can drift across
/// generated language bindings.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PushApprovalAssertion {
    pub nonce: String,
    pub code: String,
    pub device_id: i64,
    pub user_id: i64,
    pub session_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
}
