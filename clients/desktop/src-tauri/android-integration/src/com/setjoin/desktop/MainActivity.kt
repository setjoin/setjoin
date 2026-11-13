/**
 * SetJoin MainActivity — TRACKED source of truth (DESKTOP-007).
 * ==========================================================================
 *
 * Tauri 2's Android project (`src-tauri/gen/android`) is generated output and
 * is gitignored in this repo (clients/desktop/.gitignore), so a fresh checkout
 * regenerates a MainActivity WITHOUT the MAM screen-capture shim — which is
 * exactly the fail-open gap Astra review flagged (DESKTOP-007 r2, Finding 1).
 * The authoritative Kotlin therefore lives HERE, in tracked source, and is
 * injected into the generated project by the scripted, idempotent,
 * template-drift-guarded step:
 *
 *     clients/desktop/src-tauri/android-integration/apply-android-integration.sh
 *
 * That script is wired into the build via `build.beforeBuildCommand` /
 * `build.beforeDevCommand` in `src-tauri/tauri.conf.json`, so every
 * `tauri android build` / `tauri android dev` re-applies and re-verifies the
 * injection BEFORE gradle compiles Kotlin (on desktop targets the script
 * detects the missing `gen/android` and skips). Fresh-checkout reproduction
 * is therefore: `npx tauri android init` (generates gen/android) followed by
 * the documented build (`npx tauri android build`) — the method below is
 * present before javac/kotlinc ever runs.
 *
 * The `>>> DESKTOP-007:FLAG_SECURE ... <<<` marker comments delimit the ONLY
 * regions the injector manages; they let the script strip and re-apply its
 * patch idempotently while preserving any unrelated generated content, and
 * make a manual foreign edit detectable (the script refuses to clobber a
 * `setFlagSecure` it did not inject).
 *
 * JNI contract (consumed by src-tauri/src/mam_android.rs): the shell calls
 * `env.call_method(activity, "setFlagSecure", "(Z)V", [bool])` on the
 * activity's thread, so `setFlagSecure` MUST remain an instance method on
 * this class with the exact name and `(Z)V` signature (a Kotlin `extension
 * function` compiles to a static method and would NOT be visible to JNI).
 * `setFlagSecure` is the JNI entry; `clearFlagSecure` is the explicit clear
 * for readability at call sites that do not go through JNI.
 *
 * BUILD-GATED HONESTY NOTE (2026-09-16, r2): the Rust side compiles and its
 * unit tests run on host, but THIS FILE has not been compiled in this task —
 * there is no Android/Gradle toolchain run here. The next
 * `npx tauri android build` (or the orchestrator's device-verified phase)
 * is the gate that proves the Kotlin compiles; until then this file's
 * syntax/API usage (WindowManager.LayoutParams.FLAG_SECURE, runOnUiThread)
 * is reviewed-by-inspection only and is unchanged in substance from the
 * previously device-reviewed shim.
 */

package com.setjoin.desktop

import android.os.Bundle
// >>> DESKTOP-007:FLAG_SECURE:IMPORT >>> (injected region — managed by apply-android-integration.sh)
import android.view.WindowManager
// <<< DESKTOP-007:FLAG_SECURE:IMPORT <<<

import androidx.activity.enableEdgeToEdge

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
  }

  // >>> DESKTOP-007:FLAG_SECURE:METHODS >>> (injected region — managed by apply-android-integration.sh)

  /**
   * MAM screen-capture control (DESKTOP-007): invoked over JNI from the Rust
   * shell (src-tauri/src/mam_android.rs, signature `(Z)V`) when the webview
   * shows sensitive content (chat conversations, email bodies, quarantined
   * message previews) or when the device policy blocks screen capture.
   * FLAG_SECURE makes the OS exclude this window from screenshots, screen
   * recording, and the recents/task-switcher preview. Runs through
   * `runOnUiThread` defensively — the JNI dispatch already targets the
   * activity thread, but window flag mutation must own the UI thread
   * regardless of future callers. mam_android.rs waits for the JNI call's
   * outcome and reports failure to the MAM state machine (which retries);
   * keep this method cheap and synchronous for that acknowledgment to be
   * meaningful.
   */
  fun setFlagSecure(on: Boolean) {
    runOnUiThread {
      if (on) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
      } else {
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
      }
    }
  }

  /**
   * Explicit clear form of [setFlagSecure]: removes FLAG_SECURE so the window
   * is capturable again (screenshots, recording, recents preview). Only
   * meaningful when the MAM policy allows capture AND the current surface is
   * non-sensitive — the decision lives in Rust (`mam_lifecycle`); this is
   * pure platform execution.
   */
  fun clearFlagSecure() {
    setFlagSecure(false)
  }

  // <<< DESKTOP-007:FLAG_SECURE:METHODS <<<
}
