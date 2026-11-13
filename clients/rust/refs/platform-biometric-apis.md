# Platform biometric key-custody APIs — curated cheatsheet

Offline reference for the `SecureStore` per-platform impls (biometric-gated KEK that
releases the vault key). Distilled from the vendored crates in this dir + the
official docs (linked for refresh — those are proprietary HTML, not clonable).
HarmonyOS/HUKS docs are vendored separately at `clients/harmonyos/refs/openharmony-docs/`.

Load-bearing binding decision (from the /autoplan review, C1): **the unwrap ACL must
be biometry-ONLY, no device-credential fallback** — else a passcode holder unwraps
without enrolling a biometric and the new-enrollment invalidation never fires.

---

## iOS / macOS — Keychain + Secure Enclave + LocalAuthentication

Vendored binding: `clients/rust/refs/ios-security-framework/` (kornelski/rust-security-framework)
— see `src/access_control.rs` (`SecAccessControl`), `src/key.rs`, `src/passwords*.rs`.
Prompt surface: `clients/rust/refs/tauri-plugin-biometric/ios/Sources/BiometricPlugin.swift` (LAContext).

**Access control (the ACL on the KEK keychain item / Secure Enclave key):**
- `SecAccessControlCreateFlags.biometryCurrentSet` — **USE THIS.** Item becomes permanently
  inaccessible (SE discards the key) when the Face/Touch enrollment set changes. This is the
  control C1 depends on. `.biometryAny` skips invalidation — do NOT use.
- Do **not** OR in `.devicePasscode` / do not use `.userPresence` (accepts passcode → routes
  around invalidation).
- Docs: https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset

**Accessibility class (backup/migration — binding M1):**
- `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` — **USE THIS.** Not migratable, excluded
  from encrypted backups, requires a device passcode set. `biometryCurrentSet` governs *release*,
  NOT device-binding — the accessibility class is a separate axis and must be `*ThisDeviceOnly`.
- Docs: https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly

**Secure Enclave key wrap (the canonical KEK pattern, per 1Password):**
- `kSecAttrTokenIDSecureEnclave` P-256 keypair; seal the master key with `SecKeyCreateEncryptedData`
  (ECIES); key never leaves hardware. Docs: https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave
- `LAContext` / `LAError`: userCancel, biometryNotAvailable, biometryNotEnrolled, biometryLockout,
  appCancel, systemCancel, passcodeNotSet — map to SecureStoreError {Cancelled, Unavailable, Failed}.
  Docs: https://developer.apple.com/documentation/localauthentication/laerror

**Testable:** iOS Simulator — Features → Face ID/Touch ID → Enrolled, then Matching/Non-matching (⌘⇧M). Scriptable.

---

## Android — Keystore + BiometricPrompt

Prompt surface: `clients/rust/refs/tauri-plugin-biometric/android/src/main/java/BiometricActivity.kt`
+ `BiometricPlugin.kt` (the real BiometricPrompt wiring we build on).

**KeyGenParameterSpec (the Keystore KEK):**
- `setUserAuthenticationRequired(true)` — key usable only after a fresh auth.
- `setInvalidatedByBiometricEnrollment(true)` — **USE THIS (default true, set explicitly).** Key
  irreversibly invalidated on new/removed biometric enrollment (the Android analogue of
  `biometryCurrentSet`). Omitting it lets an attacker enroll their own print and unlock.
- `setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)` — **biometric STRONG
  only, do NOT OR in `AUTH_DEVICE_CREDENTIAL`** (that's the C1 device-credential hole).
- `setIsStrongBoxBacked(true)` — best-effort hardware (StrongBox); catch StrongBoxUnavailableException → TEE fallback.
- Docs: https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder

**BiometricPrompt + CryptoObject:**
- Auth releases a `Cipher` bound to the Keystore key via `BiometricPrompt.CryptoObject`; use it to
  unwrap the master key. `AuthenticationCallback.onAuthenticationError` codes: ERROR_USER_CANCELED,
  ERROR_NEGATIVE_BUTTON, ERROR_LOCKOUT / ERROR_LOCKOUT_PERMANENT, ERROR_NO_BIOMETRICS,
  ERROR_HW_UNAVAILABLE, ERROR_TIMEOUT → map to SecureStoreError. `KeyPermanentlyInvalidatedException`
  on getCipher = the invalidation signal → SecureStoreError::BiometricInvalidated.
- Docs: https://developer.android.com/training/sign-in/biometric-auth ,
  https://developer.android.com/reference/androidx/biometric/BiometricPrompt

**Keystore keys are inherently non-exportable/device-bound** (the M1 backup concern is a no-op here).

**Testable:** emulator — enroll screen-lock+fingerprint in Settings, then `adb -e emu finger touch <id>`. Scriptable.

---

## HarmonyOS NEXT — HUKS + userIAM

Full vendored docs: `clients/harmonyos/refs/openharmony-docs/` (HUKS = `security/UniversalKeystoreKit/`,
auth = `security/UserAuthenticationKit/`, API = `reference/apis-universal-keystore-kit/`).

- HUKS key with `HuksAuthAccessType.HUKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL` (invalidate on new
  enrollment) + `HuksUserAuthType.HUKS_USER_AUTH_TYPE_FINGERPRINT | _FACE` — **never `_PIN`** (C1).
- `@kit.UniversalKeystoreKit` (huks.generateKeyItem) + `@kit.UserAuthenticationKit` (userIAM).
- **Device-gated** — no emulator biometric; real-hardware sign-off required (design §8).

---

## Electron desktop — OUT (per design)

No comparable hardware key-release. `systemPreferences.promptTouchID()` (macOS gate-only, no key
binding) + `safeStorage` (DPAPI/Keychain string enc, not per-call biometric) = the "Bitwarden Heist"
app-level-wrap pitfall. Windows Hello has no first-class Electron binding. Passphrase-only on desktop.
