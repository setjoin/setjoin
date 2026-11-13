# ADR: ARCH-015 — Platform client crypto: SM4 via SQLCipher C/Rust provider, hardware-backed key custody, GM/T 0028 Level-2 ceiling

**Status:** Accepted
**Date:** 2026-06-23
**Source:** Platform-shell + offline-store crypto research + locked user decision 2026-06-23. Fixes a wiring bug in the offline plans (which named the Go `emmansun/gmsm` library as the client SM4 source — it cannot link into the Rust+C offline-core/SQLCipher). Companion to [ARCH-012](ARCH-012-offline-core-app-agnostic-store.md) (the store substrate) and [ARCH-014](ARCH-014-guomi-tls-edge-proxy-posture.md) (transport). The Go **server**-side SM-suite (`emmansun/gmsm`) is unchanged — this ADR is about **client offline-store** crypto only.

## Context

[ARCH-012](ARCH-012-offline-core-app-agnostic-store.md) makes `offline-core` (a Rust + C crate over SQLCipher) the one encrypted offline store for the native shells, keyed by a secret minted by guard-core. Two crypto questions were open:

1. **国密 SM4 at rest.** 党政/信创 deployments want the offline DB encrypted with SM4 rather than AES. The offline plans named **`emmansun/gmsm`** as the SM4 source — but **gmsm is a Go library** and **cannot link into the Rust + C offline-core / SQLCipher**. That is a real bug in those plans.
2. **Where the SQLCipher key lives.** A page-level DB key derived from a passphrase alone is only as strong as the passphrase and is recoverable from a stolen, unlocked device image. 密评 / 等保 expect hardware-backed key custody.

## Decision

**1. SM4 cipher = a C/Rust SM4 wired into SQLCipher via `SQLCIPHER_CRYPTO_CUSTOM`.**
Use a native SM4 implementation linkable into the Rust+C crate — the RustCrypto **`sm4`** crate, or a C lib (**GmSSL** / **Tongsuo**) — registered as SQLCipher's custom crypto provider. **Not** `emmansun/gmsm` (Go-only; it stays on the server side per ARCH-014). Cipher mode = **SM4-GCM or SM4-XTS** (authenticated / length-preserving) — **never raw SM4-CBC**. AES-256 stays the default cipher; SM4 is the 国密 variant build.

- **Validation:** SM2/SM3/SM4 must be checked against **GM/T 0002 / 0003 / 0004** known-answer-test vectors in CI.
- **Keys/IV** from an OS/hardware-seeded CSPRNG.
- **Password stretching = Argon2id**; **SM3** as the integrity / HMAC hash in the 国密 profile.

**2. Key custody = hardware-backed, biometric-gated unwrap.**
guard-core mints the SQLCipher key and **wraps it** with the platform hardware key store; offline-core receives the unwrapped key in-process and applies it as `PRAGMA key` (it never crosses the bridge into JS — per ARCH-012).

| Platform | Wrapping store | Biometric gate / invalidation |
|----------|----------------|-------------------------------|
| iOS | Secure Enclave | `.biometryCurrentSet` (invalidate on enrollment change) |
| Android | StrongBox (or TEE) Keystore | handle `KeyPermanentlyInvalidatedException` on enrollment change |
| HarmonyOS | HUKS | `@ohos.userIAM.userAuth` gate |
| 信创 desktop | freedesktop Secret Service / Kylin DBus biometric | Argon2id passphrase fallback |

On desktop where no hardware store is available, an **Argon2id passphrase** is the fallback unwrap.

**3. Assurance ceiling: pure-software modules cap at GM/T 0028 安全二级 (Level 2).**
A pure-software crypto module (RustCrypto/GmSSL-in-process, no certified hardware module) cannot exceed **GM/T 0028 安全二级**. For **等保三级**, server *important* keys must go through a 密码机 / **SDF (GM/T 0018)** HSM. Offer a **certified-密码模块 (SKF / SDF) build variant** if a contract demands it — do not bake it into the default build.

**4. 国密 library honesty (so non-密评 customers aren't over-engineered).**
Using SM2/SM3/SM4 *as a library* is **legally fine** post-2023 商用密码管理条例 (product cert is voluntary except for catalog products). The binding 密评 constraints are **key custody (this ADR) + transport ([ARCH-014](ARCH-014-guomi-tls-edge-proxy-posture.md))**, not the library choice. Non-密评 customers get the software SM4 + hardware-wrapped key (Level 2) without the SDF appliance.

## Considered options

- **Use `emmansun/gmsm` for client SM4 (as the offline plans said).** Rejected — it is Go; it cannot link into the Rust+C offline-core/SQLCipher. This ADR exists to correct that. gmsm remains the server-side SM source.
- **Raw SM4-CBC for the DB cipher.** Rejected: unauthenticated, malleable; use SM4-GCM (authenticated) or SM4-XTS (length-preserving disk encryption).
- **Passphrase-only key (no hardware wrap).** Rejected: recoverable from a stolen unlocked device, fails 密评 custody expectations. Hardware-wrap + biometric gate is the baseline; Argon2id passphrase is only the no-hardware desktop fallback.
- **Claim 等保三级 from the software module.** Rejected as dishonest: software caps at GM/T 0028 Level 2; Level 3 needs an SDF/密码机 — offered as a build variant, not asserted by default.

## Consequences

- `offline-core` registers an SM4 (RustCrypto `sm4` or GmSSL/Tongsuo C) provider via `SQLCIPHER_CRYPTO_CUSTOM` for the 国密 variant; AES-256 default otherwise. GM/T 0002/0003/0004 KATs run in CI.
- guard-core's key-minting export (ARCH-012) wraps the key in Secure Enclave / StrongBox-or-TEE / HUKS / Secret Service before handoff; biometric-gated unwrap with the platform-specific invalidation handling above.
- A documented **SKF/SDF certified-module build variant** exists for 等保三级 contracts; the default build is software (GM/T 0028 Level 2).
- The offline plans that named gmsm for client SM4 are corrected by this ADR; update them when next touched.
- **Reversibility:** moderate. Swapping the SM4 provider (RustCrypto ↔ GmSSL ↔ Tongsuo) is a provider-registration change behind `SQLCIPHER_CRYPTO_CUSTOM`; the custody design (hardware-wrap + biometric unwrap) is the durable contract guard-core implements.
