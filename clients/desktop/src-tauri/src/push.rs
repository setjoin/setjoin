//! Push registration (APNs / FCM) → device-token upload.
//!
//! C2 cfg(mobile) — target-checked post-init: this module is compiled only for
//! the mobile targets. The platform token capture lives in the generated
//! Xcode/Gradle projects (APNs `didRegisterForRemoteNotificationsWithDeviceToken`,
//! FCM `FirebaseMessagingService`); this is the Rust-side entry the `push_register`
//! bridge command calls.
//!
//! DEVICE-GATED STUB — out of scope here. Real APNs/FCM capture needs an Apple
//! Developer / Firebase account plus a committed Tauri push plugin, none of
//! which exist in this repo, so `register_and_upload` returns `None` and the
//! SPA glue (`registerNativePush` in webmail) skips registration when the token
//! is null. The webmail SPA — not this module — owns the actual upload:
//! `POST /auth/device/register` with `{ provider, push_token, device_public_key,
//! device_name }` (see `mailserver/webmail/src/lib/push/subscribe.ts` and
//! `authserver/internal/handlers/device.go`). This function only needs to return
//! the captured OS token once a plugin provides it.

use tauri::AppHandle;

/// Request notification permission and capture the APNs/FCM token, returning it
/// so the webmail SPA can register the device via `POST /auth/device/register`.
/// Returns `None` if the user denied permission or (today) because token capture
/// is a device-gated stub — see the module doc.
pub async fn register_and_upload(_app: &AppHandle) -> Result<Option<String>, String> {
    // A platform push plugin's delegate captures the OS token and this returns
    // it; the webmail SPA then POSTs it to /auth/device/register. Stub until
    // that plugin + an Apple/Firebase account are wired (device-gated).
    Ok(None)
}
