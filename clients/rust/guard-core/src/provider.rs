// provider.rs — MAM policy snapshot cached by guard-core.
//
// guard-core caches the MAM policy in memory for the C2 `mam.rs` lifecycle;
// the device checkin that produces it is HTTP owned by the platform bridge,
// not this crate.

/// Snapshot of the current MAM policy, cached locally and refreshed
/// from authserver on checkin or token refresh (by the platform bridge).
#[derive(Debug, Clone, Default)]
pub struct MamPolicy {
    pub policy_version: i64,
    pub copy_paste: String,     // "allow" | "block_external" | "block"
    pub screen_capture: String, // "allow" | "block"
    pub encryption: String,     // "required" | "optional"
    pub watermark: bool,
    pub notification_profile: String, // "push" | "batch" | "silent"
    pub max_offline_days: i32,
}
