# MAM/MDM Platform Support Matrix

Last updated: 2026-06-05

Legend: ✅ Enforced · ⚠️ Best-effort (log only) · ❌ Not supported · — Not applicable

---

## Policy Enforcement by Platform

### Security Policies

| Policy | iOS | Android (GMS) | Android (China) | macOS Desktop | Windows Desktop | Linux Desktop | Webmail |
|--------|-----|---------------|-----------------|---------------|-----------------|---------------|---------|
| `require_pin` | ✅ LocalAuthentication | ✅ BiometricPrompt | ✅ BiometricPrompt | ✅ Keychain | ✅ Credential Manager | ✅ libsecret | — |
| `require_biometric` | ✅ Face ID / Touch ID | ✅ Fingerprint / Face | ✅ Fingerprint / Face | ✅ Touch ID | ✅ Windows Hello | ⚠️ No standard API | — |
| `block_screenshots` | ⚠️ UIScreen.isCaptured | ✅ FLAG_SECURE | ✅ FLAG_SECURE | ❌ No OS API | ❌ No OS API | ❌ No OS API | ⚠️ Screen Capture API |
| `block_copy_paste` | ⚠️ UIPasteboard monitor | ✅ ClipboardManager | ✅ ClipboardManager | ✅ Rust arboard | ✅ Rust arboard | ✅ Rust arboard | ⚠️ JS paste interceptor |
| `block_file_export` | ⚠️ UIActivityViewController | ⚠️ Intent filter | ⚠️ Intent filter | ⚠️ File dialog hook | ⚠️ File dialog hook | ⚠️ File dialog hook | — |
| `block_keyboards` | — | ✅ InputMethodManager | ✅ InputMethodManager | — | — | — | — |
| `min_os_version` | ✅ ProcessInfo | ✅ Build.VERSION | ✅ Build.VERSION | ✅ OS version | ✅ OS version | ✅ OS version | — |
| `require_encryption` | ✅ guard-core AES/SM4 | ✅ guard-core AES/SM4 | ✅ guard-core AES/SM4 | ✅ guard-core AES/SM4 | ✅ guard-core AES/SM4 | ✅ guard-core AES/SM4 | — |
| `crypto_profile` | ✅ Auto-negotiate | ✅ Auto-negotiate | ✅ Auto-negotiate | ✅ Auto-negotiate | ✅ Auto-negotiate | ✅ Auto-negotiate | — |

### Device Integrity

| Policy | iOS | Android (GMS) | Android (China) | macOS Desktop | Windows Desktop | Linux Desktop | Webmail |
|--------|-----|---------------|-----------------|---------------|-----------------|---------------|---------|
| `jailbreak_detect` | ⚠️ Cydia/Substrate check | ⚠️ SafetyNet / Play Integrity | ⚠️ Magisk/su binary check | ⚠️ SIP status | ⚠️ Secure Boot status | ⚠️ Kernel taint check | — |
| `root_detect` | — | ⚠️ su + ro.debuggable | ⚠️ su + ro.debuggable | ⚠️ Root user check | ⚠️ Admin check | ⚠️ Root user check | — |
| `debugger_detect` | ✅ sysctl PT_DENY_ATTACH | ✅ Debug.isDebuggerConnected | ✅ Debug.isDebuggerConnected | ✅ ptrace PT_DENY_ATTACH | ✅ IsDebuggerPresent | ✅ ptrace PT_DENY_ATTACH | — |
| `vpn_detect` | ✅ NWPathMonitor | ✅ NetworkCapabilities | ✅ NetworkCapabilities | ⚠️ routing table | ⚠️ routing table | ⚠️ routing table | — |
| `emulator_detect` | — | ✅ Build.FINGERPRINT | ✅ Build.FINGERPRINT | — | — | — | — |

### Remote Actions

| Action | iOS | Android (GMS) | Android (China) | macOS Desktop | Windows Desktop | Linux Desktop | Webmail |
|--------|-----|---------------|-----------------|---------------|-----------------|---------------|---------|
| `remote_wipe` | ✅ Delete keychain entries | ✅ Delete Keystore entries | ✅ Delete SharedPreferences | ✅ Delete keychain entries | ✅ Delete Credential Manager entries | ✅ Delete libsecret entries | ✅ Clear localStorage |
| `device_lock` | ✅ Block Face ID, require PIN | ✅ BiometricPrompt re-auth | ✅ BiometricPrompt re-auth | ✅ Keychain re-auth | ✅ Credential Manager re-auth | ✅ libsecret re-auth | — |
| `device_unlock` | ✅ Push → clear lock | ✅ Push → clear lock | ✅ Push → clear lock | ✅ Push → clear lock | ✅ Push → clear lock | ✅ Push → clear lock | — |
| `policy_sync` | ✅ WebSocket push | ✅ WebSocket push | ✅ WebSocket push | ✅ WebSocket push | ✅ WebSocket push | ✅ WebSocket push | ✅ On page load |
| `rekey` | ✅ On profile change | ✅ On profile change | ✅ On profile change | ✅ On profile change | ✅ On profile change | ✅ On profile change | — |

---

## Notification Delivery

Three notification profiles, auto-adjusted per platform. See `docs/design/security/mam-and-encryption-platform.md#notification-profile-policy` for full details.

| Platform | `hybrid` (default) | `push_only` | `websocket_only` |
|----------|-------------------|-------------|-----------------|
| iOS | APNs + WebSocket | APNs only | ❌ Not possible (Apple restriction) |
| Android (GMS) | FCM + WebSocket | FCM only | Foreground service |
| Android (Huawei/NEXT) | HMS + WebSocket | HMS only | Foreground service |
| Android (no push) | WebSocket | ❌ No push service | Foreground service |
| macOS Desktop | WebSocket | ❌ No push service | WebSocket |
| Windows Desktop | WebSocket | ❌ No push service | WebSocket |
| Linux Desktop | WebSocket | ❌ No push service | WebSocket |
| Webmail | On page load | On page load | On page load |

**Shared push relay** (`push.setjoin.com`): Free opt-in. One HTTPS POST from on-premise server → relay forwards to APNs/FCM/HMS. Zero customer credential setup. Payload encrypted at app layer (relay sees only opaque bytes).

**iOS air-gap limitation**: Apple allows zero background wake-up mechanisms except APNs. If APNs is unreachable (air-gap), iOS cannot receive background push notifications. This is an Apple architectural limitation, not a SetJoin limitation. The app syncs on open. All other platforms work without cloud push via WebSocket foreground service.

---

## Platform Support Summary

### First-Class Platforms (full enforcement + push)

| Platform | Enforcement | Push | Remote Wipe | Crypto Agility |
|----------|------------|------|-------------|----------------|
| iOS 18+ | ✅ Full | ✅ APNs | ✅ | ✅ |
| iPadOS 18+ | ✅ Full | ✅ APNs | ✅ | ✅ |
| macOS 15+ (Tauri) | ✅ Full | ⚠️ Poll | ✅ | ✅ |
| Android 12+ (GMS) | ✅ Full | ✅ FCM | ✅ | ✅ |

### Supported with Limitations

| Platform | Limitations |
|----------|------------|
| Android (China, no GMS) | ⚠️ No FCM — WebSocket keepalive only. Push latency up to 30s. |
| Android (Huawei with HMS) | ✅ Push via HMS dispatcher. Full enforcement. |
| Android (Xiaomi/Oppo/Vivo) | ⚠️ No push service. WebSocket keepalive. Policy polling every 30 min when in background. |
| Windows Desktop (Tauri) | ⚠️ No push service. No screenshot blocking API. WebSocket keepalive only. |
| Linux Desktop (Tauri) | ⚠️ No push service. No screenshot blocking API. Biometric support varies by DE. WebSocket keepalive only. |

### Detection-Only (no enforcement possible)

| Platform | Why |
|----------|-----|
| Webmail (any browser) | Browser sandbox prevents all file system, clipboard, screenshot enforcement. Policies are informational only. Server-side auth revocation is the real security. |

### Not Supported

| Platform | Reason |
|----------|--------|
| HarmonyOS NEXT | APK cannot run. Native HarmonyOS port planned. See `docs/design/clients/harmonyos-next-port.md`. |
| iOS < 18 | `UIScreen.isCaptured`, `LocalAuthentication` require iOS 14+. App minimum is iOS 18. |
| Android < 12 | `FLAG_SECURE` works back to API 1. BiometricPrompt requires API 23. App minimum is API 26. |
| Windows 10 (before 22H2) | Credential Manager API changed. Tauri minimum is Windows 10 1809+. |

---

## MDM Integration (Additive, Not Required)

SetJoin MAM works standalone. For organizations that also use MDM, these additional capabilities are available:

| MDM Capability | iOS (User Enrollment) | Android (Work Profile) |
|---------------|----------------------|------------------------|
| Managed App Configuration | ✅ Plist via MDM profile | ✅ XML via Managed Configurations |
| App-config-based account provisioning | ✅ Auto-configure server URL + account | ✅ Auto-configure server URL + account |
| Per-app VPN | ✅ via MDM profile | ✅ via Always-on VPN |
| OS-level data separation | ✅ Cryptographic APFS partition | ✅ Work profile |
| Prevent uninstall | ✅ MDM-restricted | ✅ Work profile |
| OS-level screen capture block | ✅ MDM supervised mode | ✅ Work profile |
| Certificate-based auth | ✅ via MDM profile | ✅ via Managed Certificates |

When MDM is present, the app reads the Managed App Configuration on first launch, auto-provisions the account, and applies both MAM policies (from our server) and MDM policies (from the OS). The two layers are additive — neither replaces the other.

---

## Key: Best-Effort vs Enforced

- **✅ Enforced**: The policy is applied at the OS or application level and cannot be bypassed without compromising the OS security model.
- **⚠️ Best-effort**: The policy is applied at the application level but has known bypass vectors (e.g., hardware screenshot capture, custom ROM, external HDMI recorder). Detection events are logged and can trigger admin alerts or conditional access blocks.
- **❌ Not supported**: The platform has no API for this capability. No detection, no enforcement.
- **— Not applicable**: The capability is meaningless on this platform (e.g., keyboard blocking on desktop).
