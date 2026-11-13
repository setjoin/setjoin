# ARCH-016 — Offline vault key custody: OS-keystore/TPM-held key (Model M), not passphrase-derived

Status: Accepted (2026-07-08)
Supersedes the passphrase-derived offline-vault assumption in the biometric-unlock spec (`retired-docs:superpowers/specs/2026-07-08-biometric-unlock-spec.md`) and the `guard-core new(passphrase)`-derives-the-store-key model for the offline mail cache.

## Context
setjoin's offline mail cache is a local **SQLCipher** store (`clients/rust/offline-core`), whose key is currently derived from a user **passphrase** via Argon2id in `guard-core` — a password-manager (zero-knowledge-at-rest) model. Designing biometric unlock surfaced three tensions that all trace to that one choice:
- **Passwordless / SSO login exists** (WebAuthn — `auth.ts:377`; Kerberos/SPNEGO — `KERBEROS_ENABLED`, AD connector; OIDC/SAML federation). If the user never types a password, there is no secret to derive an offline-vault key from.
- **Forgot-passphrase = permanent offline lockout** (no recovery), and biometric habituation breeds the amnesia.
- Enterprise buyers run **domain-joined machines** and expect Outlook-style unified login (no second secret).

Mainstream mail clients (Outlook desktop/mobile, Gmail, Apple Mail) do NOT use an app passphrase: the local cache key is a random key held in the **OS keystore** (Windows DPAPI / macOS Keychain / Android Keystore / iOS Data Protection / TPM), released by device unlock / OS login, with at-rest protection from **full-disk encryption** (BitLocker/FileVault). Server auth rides the OS token broker (SSO). Password managers (1Password/Bitwarden) keep the user-secret model but pay for it with an explicit account-recovery/recovery-key flow.

Offline mail has **no production on-switch yet** (`featureEnabled` is never set true in shipped code) — so changing the key source now carries **no user migration**.

## Decision
Adopt **Model M** for the offline vault: the SQLCipher store is keyed by a **random 32-byte key generated once at provisioning and held WRAPPED in the platform OS keystore / TPM**, released by one of **three tiers** (`KeyTier{DeviceUnlock, Biometric, DomainSso}`):
- **Device-unlock tier (default, Outlook-style):** key released whenever the OS user is logged in / device unlocked (Keychain `WhenUnlockedThisDeviceOnly` / Android Keystore no-auth / DPAPI user scope). No prompt — offline mail just opens. This is the SSO-native, zero-friction default; at-rest protection = OS keystore + FDE.
- **Biometric/app-lock tier (opt-in — `feature.biometric_unlock`):** an ADDITIONAL biometric-gated wrap over the always-present device-unlock wrap (**design B**, decided 2026-07-08). Secure Enclave `biometryCurrentSet` / Android CryptoObject STRONG / Windows Hello-gated TPM / HUKS. On biometric-enrolment invalidation the open **falls back silently to the device-unlock wrap** — no data loss (the TOTP authenticator / ECDH key never orphan) — and offers re-enrol. Because a device-unlock wrap always survives, biometric is a *convenience gate that caps the frictionless window*, not a hard within-OS-session boundary (accepted — matches the convenience-not-auth threat model). The rejected alternative (biometric REPLACES the device wrap = a hard boundary) was dropped because a routine fingerprint-add would then destroy the user's authenticator.
- **Domain-SSO tier (opt-in, Windows — `feature.windows_sso_unlock`):** a TPM KEK bound to Windows-Hello-for-Business / the domain login; no prompt (SSO) but domain-attested. The ONE tier that **replaces** the device wrap (intentional off-domain lockout); recovery from leaving the domain is admin-driven `reprovision` (fresh key + re-sync).

There is **NO user vault passphrase**, hence **no "forgot vault passphrase" and no reset-offline-vault flow**. Losing the OS-keystore key (device reset / keychain wipe) simply re-provisions a new random key and re-syncs the cache. The **account login stays entirely separate** (password / WebAuthn / Kerberos-SSO + the existing `forgot_password.go`), governing server auth, not the local cache.

The `SecureStore` trait + P0–P4 platform work from the biometric spec still apply, but they now wrap a **provisioning-time random key** (not a copy of a passphrase-derived key), and the **device-unlock tier is the default** with biometric as the opt-in gate.

## Consequences
- **+** Domain-joined SSO unified login works natively (offline cache opens under the OS session; server auth via Kerberos/SSO) — the enterprise expectation.
- **+** No forgot-passphrase lockout, no separate secret, no reset flow. Simpler UX.
- **+** Biometric becomes a clean optional app-lock over an OS-keystore key (the industry pattern), not a passphrase wrapper.
- **−** Drops **zero-knowledge-at-rest** for the local cache: at-rest security becomes "OS keystore + full-disk encryption," the accepted enterprise norm (what Outlook/Gmail provide). **Mitigation:** document FDE (BitLocker/FileVault) as a deployment requirement; an optional passphrase tier can be added later for a zero-knowledge customer without changing this default.
- **−** Re-architects the current passphrase-derived offline key source. **Low risk:** no shipped offline users (no migration).
- **Model M extends to guard-core's `self.key` itself (decided 2026-07-08, grilled against code).** guard-core is a *single vault*: TOTP seeds, the ECDH push key, AND the offline store key (`provision_store_key`'s HKDF) all derive from ONE `self.key`, today Argon2id-from-passphrase (`guard-core/src/lib.rs:67`). `decrypt_push_challenge` (`:155`) and `generate_totp` (`:100`) both need `self.key` resident — the same passwordless-login moments where no passphrase exists to derive it. So the whole vault shares the offline store's custody problem, and the clean fix is to **change where `self.key` is born**: a random 32-byte key generated once and held WRAPPED in the OS keystore (`new_with_keystore()`), released by the device-unlock / biometric tiers — replacing `new(passphrase)` as the default. Everything downstream of `self.key` (HKDF subkeys, TOTP/ECDH stores, the `mark_wiped` durable latch) is UNCHANGED. Consequences: TOTP seeds become device-bound/non-exportable (the modern-authenticator norm; re-enroll via the existing server-side account flow on device loss); push-challenge decryption rides the device-unlock tier (no biometric prompt needed merely to decrypt — the approval gesture lives at the UI layer). An **optional passphrase tier** remains a future add for a zero-knowledge customer (same hook as the offline store), not a default.

## Alternatives rejected
- **Model P (keep passphrase vault):** zero-knowledge, but breaks SSO/passwordless, needs a recovery-key flow, and mismatches enterprise UX.
- **Hybrid (SQLCipher + OS-keystore key + optional passphrase):** viable and this decision is a subset of it — we ship Model M now and leave the optional-passphrase tier as a future add for zero-knowledge customers.
</content>
