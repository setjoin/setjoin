# App Store / Play Store viability — mobile shell submission notes

**Date:** 2026-07-04
**Status:** C2 Task 4. Written against the Tauri 2 Mobile shells (`clients/desktop/src-tauri/`, mobile cfg) built C2 Tasks 1–3, 5–6.

## The risk this addresses

Both stores reject a bare URL-wrapper: **App Store Guideline 4.2** ("Minimum Functionality") is the live risk named by the platform-support spec (`retired-docs:superpowers/specs/2026-06-23-platform-support-guomi-compliance-design.md` §12) — a review that reads "a website in a Home-Screen icon" gets rejected. Play's bar is lower but the same shape of finding (a "WebView wrapper" listing) invites removal/demotion.

The mitigation is not cosmetic chrome on top of the WebView — it's **real native capability the browser cannot provide**, wired through `window.setjoinNative` (`mailserver/webmail/src/lib/native/types.ts`). Reviewers see an app that happens to render its UI in a system WebView, not a bookmark.

## What the shell ships beyond the WebView (native-value checklist)

| Capability | Native mechanism | Where |
|---|---|---|
| Biometric-gated vault | `tauri-plugin-biometric` — Face ID / Touch ID / Android `BiometricPrompt`, real device enrollment check (`vault.isEnrolled`) | `bridge.rs` `biometric_unlock`/`biometric_status`, `bridge_js.rs` |
| Native push | APNs (iOS) / FCM (Android) device-token registration + upload to `POST /api/device/token`; push-MFA payload decrypt via `guard-core` ECDH | `push.rs`, `bridge.rs` `push_register` |
| Offline mail (native SQLCipher, not WebView storage) | Per-app encrypted store (`offline-core`), key provisioned in-process from the `guard-core` vault, never crossing into JS | `bridge.rs` `db_*`, `clients/rust/offline-core/` |
| Native share sheet | `tauri-plugin-share` — OS share sheet for attachments, not a copy-to-clipboard shim | `bridge.rs` `share` |
| Native OS notifications | `tauri-plugin-notification` | `bridge.rs` `notify` |
| Device-trust / MAM lifecycle | HMAC-signed device checkin, remote wipe, screenshot block (`FLAG_SECURE` / iOS secure-overlay) — an MDM capability no plain web page can have | `mam.rs`, `mam_android.rs`, `mam_ios.rs` |
| Native file picker | OS file/document picker, not an `<input type=file>` | `bridge.rs` `pick_file` |
| Deep links | `tauri-plugin-deep-link` (URL-scheme handler; see TODOS for the `setjoin://` scheme decision) | `main.rs` |

Every row above is a bridge command a plain mobile browser tab cannot invoke — this is the concrete evidence for the "not a wrapper" argument in a 4.2 appeal or a Play Data Safety review.

## Distribution posture (per platform-support spec §12)

- **Public store:** App Review (iOS) / Play (Android) with **ABM custom/unlisted** or **EMM managed-Play** for the org-managed fleet; Play **Data Safety** form completed against the actual `window.setjoinNative` data flows (secureStore/vault/db are on-device only — no data leaves the device via the bridge itself); **`ITSAppUsesNonExemptEncryption`** declared (the app does standard TLS + an on-device SQLCipher store) plus the **French encryption declaration** where applicable. Note: an SM4/国密 build variant may be **export-controlled** — file the crypto declaration for that variant separately from the AES-default build.
- **Air-gapped / 信创:** no store at runtime. Self-hosted appcast + MDM/sideload, verified through the same Ed25519-signed-manifest path as desktop (ARCH-013) once the mobile updater is wired — not yet built for mobile in this slice (desktop-only today; see TODOS).

## What review should see (submission checklist)

- [ ] Screenshots/App Store description show the biometric unlock gate and native push notification, not just the webmail chrome.
- [ ] Privacy manifest / Play Data Safety form lists exactly what `window.setjoinNative` capabilities touch (secureStore, vault, db, deviceProof — all on-device; push token + MAM checkin — sent to the customer's own server, never a third party).
- [ ] `ITSAppUsesNonExemptEncryption` set correctly for the build variant (AES-default vs SM4/国密).
- [ ] The app is **not** listed as a "webview wrapper" category — submit under Productivity/Business Mail, matching Outlook/Gmail's own category.

## Explicitly not claimed here

This note documents *capability*, not a completed store submission — no App Store Connect / Play Console listing has been created. **Update (2026-07-04, device-gated verification):** the Task 1 decision gate (does the Tauri 2 Mobile webview actually render + round-trip the bridge on a real simulator/device) is now **verified PASS** on both an iOS Simulator (iPhone 17, iOS 26.5) and an Android emulator (Pixel 6, API 34 arm64) — see `clients/AGENTS.md`'s Mobile shell section and TODOS.md for the four real bugs found+fixed to get there. What remains unclaimed: real-device (not simulator/emulator) soak time, and the actual store listings/submissions.
