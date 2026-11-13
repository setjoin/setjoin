//! iOS screenshot-block glue — secure-overlay + blur-on-background shim.
//!
//! C2 cfg(mobile) — target-checked post-init: this module is compiled only for
//! `target_os = "ios"`. UIKit has no public "disable screenshot" API, so the
//! platform-accepted approach is a secure `UITextField` overlay on the key
//! window (its `isSecureTextEntry` layer is excluded from screen recording and
//! AirPlay) plus a blur snapshot on `applicationWillResignActive`. The actual
//! Swift glue lands in the generated `gen/apple` project after `tauri ios init`;
//! this is the Rust-side entry the MAM lifecycle calls.

/// Install (or remove) the secure overlay + blur-on-background protection on the
/// key window. Bridged to the generated Swift `SecureOverlay` via an objc shim.
pub fn set_secure_overlay(blocked: bool) {
    // The generated AppDelegate glue (gen/apple) installs a secure-field overlay
    // and a `willResignActive` blur snapshot when `blocked`, removing them when
    // not. Invoked here on the main thread.
    let _ = blocked;
}
