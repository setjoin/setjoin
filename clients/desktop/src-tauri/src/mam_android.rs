//! Android screenshot-block glue — JNI shim for `WindowManager.LayoutParams.FLAG_SECURE`.
//!
//! C2 cfg(mobile) — target-checked post-init: this module is compiled only for
//! `target_os = "android"`. DESKTOP-007 replaces the compiled no-op with a real
//! JNI dispatch: `set_flag_secure` posts to wry's Android main-pipe, which runs
//! the closure on the activity's thread with the live `MainActivity` object and
//! invokes its `setFlagSecure` shim (adds/clears
//! `WindowManager.LayoutParams.FLAG_SECURE` = 0x2000 on the window). The
//! decision of *when* to toggle lives in the pure `mam_lifecycle` flag logic;
//! this module only executes it and reports whether it actually happened.
//!
//! ## Tracked Kotlin source (DESKTOP-007 r2)
//!
//! The `setFlagSecure` Kotlin implementation is authored in the TRACKED,
//! generated-output-free source location
//! `src-tauri/android-integration/src/com/setjoin/desktop/MainActivity.kt` and
//! injected into the gitignored `gen/android` project by
//! `src-tauri/android-integration/apply-android-integration.sh` (idempotent,
//! template-drift guarded; run after `tauri android init`, before
//! `tauri android build` — see that script's header and clients/DOX.md). A
//! fresh checkout that follows the documented steps produces the method this
//! module calls; without the injection step the JNI call fails honestly as
//! [`SetFlagSecureError::Jni`] instead of being silently dropped.
//!
//! ## Acknowledged application (DESKTOP-007 r2, r4, r5)
//!
//! `set_flag_secure` reports its conclusion as a typed
//! [`FlagSecureApply`]: `Completed(Ok(()))` only when the JNI call actually
//! succeeded on the activity thread (the closure sends the outcome back over
//! a bounded channel and this thread waits, bounded by
//! [`FLAG_SECURE_ACK_TIMEOUT`] — the same request/response pattern wry itself
//! uses for eval). A refused post, null activity handle, or JNI error is
//! definitive; an unresponsive main loop is reported as `Ambiguous` (r4) —
//! the closure is still queued and may execute late, so the caller cannot
//! treat the window state as known. The completion is handed to the driver
//! LOSSLESSLY either way (r5): the closure persists its real outcome into the
//! driver's late-ack sink (keyed by the dispatch's op identity) BEFORE
//! attempting the channel signal, and the driver consumes that sink record by
//! op id when the signal IS received — so a completion landing in the
//! post-timeout/pre-drop window still reaches the next drive's drain instead
//! of vanishing with the dropped receiver. `mam.rs` converges the tracker on
//! the next drive. The caller keeps the desired state pending on every
//! non-success so the next eligible lifecycle tick retries. This module never
//! decides policy; it refuses to lie.

use std::sync::mpsc;
use std::time::Duration;

use jni::objects::JValue;
use tauri::wry::prelude::dispatch;

use crate::mam::FlagSecureLateAcks;
use crate::mam_lifecycle::{FlagSecureApply, LateFlagSecureAck};

/// How long to wait for the activity thread to acknowledge the JNI call.
/// wry's own main-pipe round trips use a 10s bound; the flag toggle is a
/// single method call, so 3s is a generous ceiling that still fails honestly
/// (and retries later) if the main loop is wedged.
const FLAG_SECURE_ACK_TIMEOUT: Duration = Duration::from_secs(3);

/// Add or clear `FLAG_SECURE` (0x2000) on the current activity window so the
/// OS excludes the app from screenshots, screen recording, and the recents
/// preview. Calls into the Kotlin activity's `setFlagSecure` shim (tracked in
/// `android-integration/`, injected into the generated project — see the
/// module docs) via JNI on the activity's thread, and returns only after the
/// activity thread acknowledges the outcome.
///
/// Returns the dispatch's CONCLUSION (DESKTOP-007 r4), which the driver's
/// status mapping distinguishes by honesty requirements:
/// - [`FlagSecureApply::Completed`] — the JNI call finished (success or
///   definitive failure); nothing is left queued and the window state is
///   known. A definitive failure covers a null activity handle and a JNI
///   error (e.g. the Kotlin shim is missing from a fresh checkout that
///   skipped the tracked injection step).
/// - [`FlagSecureApply::Refused`] — the dispatch could not even be posted (no
///   activity registered with wry yet); nothing can execute late.
/// - [`FlagSecureApply::Ambiguous`] — the acknowledgment did not arrive
///   within [`FLAG_SECURE_ACK_TIMEOUT`]: the closure is STILL queued on the
///   activity thread and may execute late, so the window state is unknown.
///   The completion is handed to the driver losslessly regardless (r5): the
///   closure persists its outcome into `late_acks` (keyed by the dispatch's
///   `op` identity) BEFORE attempting the channel signal, and the driver
///   consumes that record by op id when the signal arrives through the
///   channel — so a completion that lands after the timeout but before the
///   dropped receiver destroys the channel still reaches the next drive's
///   drain, and channel receipt and sink drain never double-count one
///   execution.
///
/// On every non-`Completed(Ok)` conclusion the MAM tracker in `mam.rs` holds
/// the desired state pending so the next lifecycle tick retries.
pub fn set_flag_secure(
    blocked: bool,
    op: u64,
    late_acks: &FlagSecureLateAcks,
) -> FlagSecureApply {
    let (ack_tx, ack_rx) = mpsc::channel();
    // `move` is required: the dispatch closure is `'static`, and `blocked`/
    // `op`/the sink clone are `Copy`/owned locals — by-ref capture would not
    // outlive this function. The closure reports the real JNI outcome on the
    // channel; DESKTOP-007 r5 makes the handoff lossless by persisting the
    // outcome into the late-ack sink FIRST (see the closure body).
    let late_acks = late_acks.clone();
    let post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        dispatch(move |env, activity, _webview| {
            let outcome = if activity.is_null() {
                Err("activity handle is null".to_string())
            } else {
                // `call_method` returns the receiver-style JValue on success;
                // the flag shim returns void — normalize to ().
                env.call_method(
                    activity,
                    "setFlagSecure",
                    "(Z)V",
                    &[JValue::Bool(u8::from(blocked))],
                )
                .map(|_void| ())
                .map_err(|error| format!("JNI setFlagSecure({blocked}) failed: {error}"))
            };
            let succeeded = outcome.is_ok();
            // DESKTOP-007 r5 — lossless completion handoff: persist FIRST.
            // Every execution records exactly one sink record before any
            // channel signal, so the record exists whether or not the
            // still-waiting driver receives the signal. The pre-r5 ordering
            // (record only when the send FAILED) lost completions landing in
            // the post-timeout/pre-drop window: `recv_timeout` had given up
            // but the receiver was still alive, so the send SUCCEEDED, no
            // record existed, and the outcome vanished when the dropped
            // receiver destroyed the channel. `drive_flag_secure` consumes
            // the record by op id when the signal IS received, so a
            // completion is acknowledged exactly once (channel receipt OR
            // sink drain, never both).
            late_acks.record(LateFlagSecureAck {
                op,
                desired: blocked,
                succeeded,
            });
            // Best-effort immediate delivery to the still-waiting driver.
            // Failure (driver already gone) is fine — the sink record above
            // is the durable copy the next drive converges from.
            let _ = ack_tx.send(outcome);
        });
    }));
    // wry's `dispatch` panics via `first_activity_id().expect(...)` when no
    // activity is registered yet (e.g. a policy enforcement that races app
    // startup). Convert that panic into an honest refusal so the state machine
    // retries on the next tick instead of unwinding a worker thread.
    if post.is_err() {
        return FlagSecureApply::Refused(
            "no Android activity is registered with wry yet; \
             FLAG_SECURE dispatch refused (will retry)"
                .to_string(),
        );
    }
    match ack_rx.recv_timeout(FLAG_SECURE_ACK_TIMEOUT) {
        // Definitive: the JNI call finished within the bound.
        Ok(outcome) => FlagSecureApply::Completed(outcome),
        // Ambiguous: timeout (main loop wedged — the closure is still queued
        // and may execute late) or a dropped channel (the closure died before
        // sending — whether it executed is unknown). Either way the window
        // state is unknown, which the driver must report as unconfirmed.
        Err(wait_error) => FlagSecureApply::Ambiguous(format!(
            "activity thread did not acknowledge setFlagSecure({blocked}) (op {op}) \
             within {}ms: {wait_error}",
            FLAG_SECURE_ACK_TIMEOUT.as_millis()
        )),
    }
}
