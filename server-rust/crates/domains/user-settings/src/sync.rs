//! `PUT /user/offline/sync-preferences` (#307): frozen Go's JMAP-handler route. Go answers a bare
//! `404 page not found` while the offline-mail or connectivity-aware-sync toggle is OFF, the
//! caller has no primary mailbox, the token's device fingerprint is not a registered device or
//! the winning policy's `syncQoS.mode` is `off`. Otherwise it calls
//! `offline_device_set_preferences` and answers the refreshed effective capabilities.
use super::{command, deadline, envelope, invalid, scope};
use serde_json::{json, Value};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

/// The validated request (Go's `syncPreferencesRequest`).
pub struct SyncPut {
    pub opt_in: bool,
    pub window_days: i64,
    pub background: bool,
    pub network: String,
    pub prefetch: String,
}

/// Go's `decodeSyncPreferences` validation, applied after decoding.
pub fn valid(p: &SyncPut) -> bool {
    p.window_days >= 0
        && matches!(p.network.as_str(), "never" | "unmetered" | "any")
        && matches!(p.prefetch.as_str(), "never" | "unmetered" | "always")
}

/// `(offline_mail, connectivity_aware_sync, biometric_unlock, windows_sso_unlock)`; every
/// registry default is OFF, so an absent row is OFF.
pub async fn toggles(exec: &ScopedExecutor) -> Result<[bool; 4], StatementFailure> {
    let rows = exec
        .read(
            "SELECT \
             COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.offline_mail'), false), \
             COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.connectivity_aware_sync'), false), \
             COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.biometric_unlock'), false), \
             COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.windows_sso_unlock'), false)",
            &[],
        )
        .await?;
    let row = rows.first().ok_or_else(invalid)?;
    let get = |i| row.try_get::<_, bool>(i).map_err(|_| invalid());
    Ok([get(0)?, get(1)?, get(2)?, get(3)?])
}

/// Go reads these on the request pool with no user GUC.
pub async fn primary_mailbox(exec: &ScopedExecutor, user: i64) -> Option<i64> {
    exec.read(
        "SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1",
        &[(&user, Type::INT8)],
    )
    .await
    .ok()?
    .first()?
    .try_get(0)
    .ok()
}

/// `registeredOfflineDeviceID`: the user's oldest device whose fingerprint hash matches.
pub async fn device(exec: &ScopedExecutor, user: i64, fingerprint: &str) -> Option<i64> {
    if fingerprint.is_empty() {
        return None;
    }
    let bytes = fingerprint.as_bytes();
    let id: i64 = exec
        .read(
            "SELECT id FROM user_devices WHERE user_id = $1 AND fingerprint_hash = sha256($2::bytea) ORDER BY id ASC LIMIT 1",
            &[(&user, Type::INT8), (&bytes, Type::BYTEA)],
        )
        .await
        .ok()?
        .first()?
        .try_get(0)
        .ok()?;
    (id > 0).then_some(id)
}

/// Go's `effectiveCapabilitiesDefault`.
fn default_capabilities() -> Value {
    json!({
        "apps": {"mail": false, "calendar": false, "contacts": false, "tasks": false,
                 "approvals": false, "drive": false, "chat": false, "meet": false},
        "features": {"assist": false, "bundles": false, "external_labels": false,
                     "guest_accounts": false, "guest_invite": false, "mail_search_builder": false,
                     "sender_control_center": false, "shared_mail_work": false,
                     "shared_mail_comments": false},
        "offline": {"allowed": false, "approvalState": "pending", "maxOfflineDays": 0,
                    "wipeOnLogout": "admin_default", "requireApproval": true,
                    "biometricUnlock": false, "windowsSsoUnlock": false}
    })
}

/// `effectiveCapabilitiesWithDevice`: the reducer result with the two Go-side unlock toggles
/// folded into the offline block; any failure is the all-false default.
pub async fn capabilities(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    mailbox: i64,
    device: i64,
    unlock: [bool; 2],
) -> Value {
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT effective_capabilities($1, $2)::text",
            &[(&mailbox, Type::INT8), (&device, Type::INT8)],
        )
        .await;
    let parsed = rows
        .ok()
        .and_then(|r| r.first().and_then(|row| row.try_get::<_, String>(0).ok()))
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    match parsed {
        Some(Value::Object(mut map)) => {
            if let Some(Value::Object(offline)) = map.get_mut("offline") {
                offline.insert("biometricUnlock".into(), unlock[0].into());
                offline.insert("windowsSsoUnlock".into(), unlock[1].into());
            }
            Value::Object(map)
        }
        _ => default_capabilities(),
    }
}

/// `syncQoSMode`: `""` when absent.
pub fn mode(capabilities: &Value) -> &str {
    capabilities["offline"]["syncQoS"]["mode"]
        .as_str()
        .unwrap_or("")
}

/// Go's `CallScoped(offline_device_set_preferences, ...)` on the caller's own device.
pub async fn put(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    device: i64,
    p: &SyncPut,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("sync.put"),
        &envelope(
            &auth,
            operation,
            &format!(
                "sync.put:{device}:{}:{}:{}:{}:{}",
                p.opt_in, p.window_days, p.background, p.network, p.prefetch
            ),
        ),
        &auth,
        deadline(),
        "SELECT rust_offline_device_set_preferences((SELECT id FROM mailboxes WHERE user_id = $2::bigint AND is_primary = TRUE LIMIT 1), \
         $4::bigint, $5::boolean, $6::int, $7::boolean, $8::text, $9::text)::text \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&device, Type::INT8),
            (&p.opt_in, Type::BOOL),
            (&(p.window_days as i32), Type::INT4),
            (&p.background, Type::BOOL),
            (&p.network, Type::TEXT),
            (&p.prefetch, Type::TEXT),
        ],
        |rows| rows.first().map(|_| ()).ok_or_else(invalid),
    )
    .await
}
