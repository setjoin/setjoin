# Enhanced Mobile MDM — Design Spec

> **Target:** Roadmap 3.6. Builds on Stage 1 native apps (Phase 12). ~4 weeks.

**Goal:** Built-in mobile device management matching Gmail Endpoint Management without a separate license (EXO requires Intune). Four capabilities: (1) remote wipe — account-level (corporate data) and device-level (factory reset); (2) PIN/passcode enforcement with complexity requirements (numeric, alphanumeric, complex), max age, history, and auto-wipe after N failed attempts; (3) app-level policies — block cross-app copy/paste, block screenshots, require device encryption, minimum OS version; (4) jailbreak/root detection with conditional access integration (block, warn-and-log, or quarantine). MDM engine on gateway; native clients check in on app launch and configurable heartbeat.

**Architecture:**
```
Admin UI ──→ gateway/internal/mdm/engine.go ──→ PostgreSQL (policies + device_state)
Native clients ──→ POST /api/v1/mdm/checkin ──→ gateway/internal/mdm/checkin.go
    ├── iOS: MDMProfileManager.swift
    └── Android: MdmPolicyEnforcer.kt
```
Three layers: (1) Policy definition and device state in PostgreSQL, managed via admin REST API and SvelteKit UI. (2) `/api/v1/mdm/checkin` endpoint (Bearer auth) — clients POST device status (passcode, encryption, jailbreak, OS version); server responds with policy config, compliance verdict, required actions, and any pending wipe command. (3) Native client enforcement hooks that read the policy response and apply OS-level restrictions. Heartbeat defaults to 3600s, configurable per policy; clients use iOS `BGAppRefreshTask` / Android `WorkManager`. Non-compliant devices receive `required_actions` array; quarantined devices have JMAP/SMTP/IMAP rejected by `RequireAuth` middleware.

**Policy schema:** `mdm_policies` table holds policy definitions (passcode_min_length, passcode_complexity, passcode_max_age_days, passcode_history_count, max_failed_attempts, inactivity_lock_mins, block_screenshots, block_copy_paste, require_device_encryption, jailbreak_action, min_os_version). `mdm_device_state` table tracks per-device compliance (device_id, platform, os_version, passcode_compliant, encryption_enabled, jailbroken, compliance_status, wipe_requested, wipe_status). Policies assigned at user/group/global levels; highest priority wins. Admin pages at `/admin/mdm/` (device list, policy editor, wipe trigger).

**Remote wipe:** Two levels. Account wipe: client deletes local SQLite cache, attachments, settings; app resets to login screen. Device wipe: iOS `DeviceLock` + `EraseDevice`; Android `DevicePolicyManager.wipeData(0)`. Admin triggers from UI → gateway sets `wipe_requested = 'pending'`. Client acknowledges on next check-in (`wipe_ack: true`), then executes. Server records `wipe_status = 'acknowledged'` before wipe; prevents lost-command race.

**iOS enforcement (MDMProfileManager.swift):** Passcode via `LAContext.canEvaluatePolicy(.deviceOwnerAuthentication)` + `UserDefaults` age tracking; complexity enforced by refusing to operate with `required_actions`. Screenshots via `userDidTakeScreenshotNotification` alert (true OS-level blocking requires MDM profile — deferred). Copy/paste via `UIPasteboard.general.items` guard. Encryption via `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`. Jailbreak via Cydia/Sileo/Substrate/Frida/`fork()` checks at launch and heartbeat.

**Android enforcement (MdmPolicyEnforcer.kt):** Passcode via `KeyguardManager.isDeviceSecure()` + `DevicePolicyManager.setPasswordQuality()` (requires Device Admin activation). Screenshots via `FLAG_SECURE` on all app windows. Copy/paste via `ClipboardManager.OnPrimaryClipChangedListener` clearing on cross-app paste. Encryption via `DevicePolicyManager.getStorageEncryptionStatus()`. Root via `su` binary, Magisk, SuperSU, `test-keys` build tag; uses root-only on HMS/China flavor (no SafetyNet).

**Conditional access integration:** New step 9 ("mdm_compliance") added to authserver's 8-step threat pipeline. After authentication but before token issuance, checks `mdm_device_state.compliance_status`. Quarantined devices rejected with `WWW-Authenticate` error `mdm_required` + human-readable fix description. Non-MDM auth paths (basic, Kerberos) unaffected. Per-policy grace period: N hours before quarantine after violation detected.

**MDM profile delivery (deferred):** True system-level enforcement (silent passcode complexity, silent app install, OS-level screenshot blocking) requires Apple MDM Protocol or Android Managed Profile. This spec delivers app-level MDM via Device Admin (Android) and in-app guards (iOS). Full profile delivery deferred to Stage 3.x with Apple Business Manager / Android Enterprise integration.

**Files:**
| File | Purpose |
|------|---------|
| `mailserver/gateway/internal/mdm/engine.go` | Policy resolution, check-in handler, wipe orchestrator |
| `mailserver/gateway/internal/mdm/checkin.go` | `/api/v1/mdm/checkin` HTTP handler |
| `mailserver/gateway/internal/mdm/policy.go` | Policy CRUD + assignment resolver |
| `mailserver/gateway/internal/mdm/conditional_access.go` | Step 9 threat pipeline hook |
| `mailserver/gateway/internal/handlers/admin_mdm.go` | Admin REST API: devices, policies, wipe |
| `mailserver/gateway/internal/middleware/auth.go` | Extend RequireAuth for quarantine check |
| `clients/apple/Mail/Managers/MDMProfileManager.swift` | iOS enforcement |
| `clients/android/.../MdmPolicyEnforcer.kt` | Android enforcement |
| `mailserver/sql/migrations/V???__mdm_schema.sql` | Tables + indexes |
| `mailserver/webmail/src/routes/admin/mdm/` | Admin SvelteKit pages |

**Key decisions:** (1) MDM engine on gateway, not authserver — check-in is user-scoped. (2) Device Admin, not full Android Enterprise — AE requires managed Google Play, incompatible with air-gap and HMS. (3) Policy JSON over JMAP — single request/response, simpler than a JMAP method. (4) `device_id` is client-generated UUID v4, stable per install — server can't generate for offline-first. (5) Wipe ACK before execution — prevents lost-command race. (6) Grace period before quarantine — avoids lockout for transient states. (7) No push for wipe — picked up on next check-in; push can force immediate check-in for emergencies.

**Dependencies:** Phase 12 native apps (spec exists) — MDM hooks are a feature of the apps. Auth token introspection (done). Conditional access policy engine (Roadmap 3.5, spec needed) — MDM provides device-state input. Admin web UI shell (done).

**Effort:** Schema + models (2d), policy engine (3d), admin API + UI (4d), iOS hooks (4d), Android hooks (4d), conditional access integration (2d), testing (3d). **Total: ~4 weeks (22 days).**

**Competitive context:** EXO requires Intune license for MDM. Gmail has built-in Endpoint Management. DingTalk has partial device controls (password enforcement, login device management). NetEase/Lark/Tencent lack dedicated MDM. Our built-in MDM + air-gap capability + no per-seat license = unique in both Western and Chinese markets.
