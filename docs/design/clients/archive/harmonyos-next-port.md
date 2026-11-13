# HarmonyOS NEXT Client — Design Spec

Date: 2026-06-05
Status: Design (planned post-Phase 12, depends on Rust-to-Harmony toolchain maturity)

## Goal

Port the SetJoin mail client to Huawei HarmonyOS NEXT, which cannot run Android APKs. Reuse the Rust mail-core and guard-core crates as the backend via C FFI (NAPI), build the UI in ArkTS (TypeScript-based HarmonyOS native framework).

## Why This Matters

| Metric | Value |
|--------|-------|
| NEXT devices shipped | 52M+ (growing rapidly) |
| Native NEXT apps | 350K+ |
| Chinese government procurement | HarmonyOS-only starting 2026 |
| APK compatibility | **Zero** — AOSP layer completely removed |

The Chinese government is mandating HarmonyOS for new procurement. Without a NEXT app, SetJoin cannot sell into Chinese government/SOE accounts on the primary mobile platform.

## Architecture

```
┌─ HarmonyOS HAP ─────────────────────────────────────┐
│                                                     │
│  ArkTS UI Layer (new)                               │
│  ├─ MailApp (Navigation, TabBar)                    │
│  ├─ InboxPage, ComposePage, CalendarPage            │
│  ├─ SettingsPage, AdminPage                         │
│  └─ Theme (Liquid Glass tokens → ArkTS)             │
│                                                     │
│  NAPI Bridge (new)                                  │
│  ├─ mail_core_napi.cpp     — C FFI wrappers         │
│  └─ guard_core_napi.cpp    — C FFI wrappers         │
│                                                     │
│  Rust Core (existing, recompiled)                   │
│  ├─ libmail_core.so        — compiled for aarch64-harmonyos
│  └─ libguard_core.so       — compiled for aarch64-harmonyos
└─────────────────────────────────────────────────────┘
```

### What Can Be Reused

| Component | Reuse | Notes |
|-----------|-------|-------|
| `mail-core` (JMAP client, SQLite cache, sync engine) | ✅ 100% | Recompile for `aarch64-harmonyos` target |
| `guard-core` (TOTP, ECDH, vault, encryption) | ✅ 100% | Recompile for `aarch64-harmonyos` target |
| Liquid Glass design tokens | ✅ 100% | Port to ArkTS color/radius/spacing constants |
| MAM policy engine | ✅ 100% | Same JSON endpoint, same enforcement |
| Server-side infrastructure | ✅ 100% | Zero server changes needed |
| UniFFI | ❌ Cannot use | UniFFI has no ArkTS/Kotlin-for-NEXT support |
| Compose/Kotlin UI | ❌ Cannot use | NEXT has no ART/Dalvik runtime |

### What Must Be New

| Component | Effort | Notes |
|-----------|--------|-------|
| ArkTS UI framework | 4 weeks | 12-15 screens (inbox, compose, settings, admin) |
| NAPI bridge (C to ArkTS) | 2 weeks | hand-written C wrappers for mail-core/guard-core APIs |
| HMS Push integration | 1 week | Native NEXT push, replaces APNs/FCM/HMS Android |
| HAP packaging + signing | 1 week | Huawei AppGallery Connect, HarmonyOS certificate |
| Platform-specific MAM enforcement | 1 week | ArkTS equivalents of iOS/Android detection APIs |

### Technical Approach: NAPI Bridge

Since UniFFI doesn't target HarmonyOS, we write a thin NAPI (Native API) bridge:

```cpp
// mail_core_napi.cpp — called from ArkTS via NAPI
#include <napi/native_api.h>
#include "mail_core.h"  // Rust cdylib header

static napi_value MailCoreNew(napi_env env, napi_callback_info info) {
    // Parse ArkTS args (db_path, server_url, access_token)
    // Call Rust function
    // Return MailCore handle as napi_external
}

NAPI_MODULE_INIT() {
    napi_property_descriptor desc[] = {
        {"mailCoreNew", nullptr, MailCoreNew, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"mailCoreSync", nullptr, MailCoreSync, nullptr, nullptr, nullptr, napi_default, nullptr},
        // ... all MailCore methods
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
```

The ArkTS code calls it like:

```typescript
import mailCore from 'libmail_core_napi.so';

let core = mailCore.mailCoreNew(dbPath, serverUrl, token);
let result = mailCore.mailCoreSync(core);
let mailboxes = mailCore.mailCoreListMailboxes(core);
```

### MAM Enforcement on HarmonyOS

| Policy | HarmonyOS API | Status |
|--------|--------------|--------|
| `require_pin` | `@ohos.userIAM.userAuth` (BiometricAuth) | ✅ Native API |
| `block_screenshots` | `window.setWindowPrivacyMode(true)` | ✅ Native API |
| `block_copy_paste` | `@ohos.pasteboard` listener | ✅ Native API |
| `require_encryption` | guard-core AES/SM4 (via NAPI) | ✅ Reuses Rust |
| `remote_wipe` | Delete HAP sandbox data + keychain | ✅ Native API |
| `jailbreak_detect` | `@ohos.deviceInfo` + system integrity check | ✅ Native API |
| `device_lock` | `@ohos.userIAM.userAuth` challenge | ✅ Native API |
| Push notification | `@ohos.push` (HMS Push Kit) | ✅ Native, no FCM needed |

### Build Pipeline

```
1. Rust cross-compile for aarch64-harmonyos:
   cargo build -p mail-core -p guard-core --target aarch64-harmonyos

2. Build NAPI bridge:
   hvigor build (HarmonyOS SDK) → libmail_core_napi.so + libguard_core_napi.so

3. Build ArkTS UI:
   hvigor assembleHap → mail.hap

4. Sign + publish:
   Huawei AppGallery Connect → signed .app for distribution
```

The Rust target `aarch64-harmonyos` is available in Rust 1.85+ (January 2025). No NDK needed — the HarmonyOS SDK provides the toolchain.

### Per-Platform Support Matrix Addition

| Capability | HarmonyOS NEXT |
|-----------|---------------|
| Native app | ✅ HAP (ArkTS + Cangjie) |
| JMAP client | ✅ mail-core via NAPI |
| Encryption | ✅ guard-core via NAPI |
| Push notifications | ✅ HMS Push Kit (native to NEXT) |
| MAM policy enforcement | ✅ Full (all policies enforced) |
| MDM integration | ❌ No HarmonyOS MDM API exists yet |
| Crypto agility | ✅ Same as Android |
| SMx crypto | ✅ guard-core smx feature |
| Biometric gate | ✅ @ohos.userIAM.userAuth |

---

## Effort Estimate

| Phase | Description | Weeks |
|-------|------------|-------|
| 1 | Recompile Rust crates for HarmonyOS target | 1 |
| 2 | Build NAPI bridge (C wrappers for mail-core + guard-core) | 2 |
| 3 | ArkTS UI (12-15 screens, Liquid Glass design tokens) | 4 |
| 4 | HMS Push + MAM enforcement + biometric gate | 2 |
| 5 | HAP packaging, signing, AppGallery submission | 1 |
| **Total** | | **10 weeks** |

## Dependencies

- **Rust 1.85+** (aarch64-harmonyos target) — ✅ Available
- **HarmonyOS SDK** — ✅ Available on macOS (DevEco Studio)
- **ArkTS developer** — ❌ New skill needed (not Kotlin/Swift)
- **Huawei Developer Account** — Required for AppGallery publishing

## Alternatives Considered

| Alternative | Why Rejected |
|-------------|-------------|
| Use Android APK via virtualized container (卓易通) | Deprecated in HarmonyOS 7.0. 8GB RAM overhead. Not viable long-term. |
| Use React Native / Flutter HarmonyOS port | Both are experimental on NEXT. Not production-ready for 2026. |
| PWA-only (no native app) | Government procurement requires native app in AppGallery. PWA cannot meet 等保 requirements. |
| Cross-compile Kotlin to HarmonyOS | No Kotlin-to-ArkTS transpiler exists (though Huawei is working on one). Not ready. |

## References

- HarmonyOS NEXT Developer Guide: https://developer.huawei.com/consumer/en/harmonyos
- NAPI Documentation: https://developer.huawei.com/consumer/en/doc/harmonyos-guides/napi-guidelines
- Rust harmonyos target: https://doc.rust-lang.org/nightly/rustc/platform-support/harmonyos.html
- HMS Push Kit (HarmonyOS): https://developer.huawei.com/consumer/en/hms/hms-pushkit
