# windows-tpm — reference for the Windows Hello-gated decrypt path

Reference pointer only. Upstream is GPL-3.0 and our crates are not, so the file is NOT
redistributed in this repository. Read it at the pinned commit:
`https://raw.githubusercontent.com/sirAndros/KeePassWinHello/57c6dda73646dc2845280944d923f231a46053d4/src/AuthProviders/WinHelloProvider.cs`

- `WinHelloProvider.cs` — from **sirAndros/KeePassWinHello**
  - Source: https://github.com/sirAndros/KeePassWinHello/blob/master/src/AuthProviders/WinHelloProvider.cs
  - Pinned commit: `57c6dda73646dc2845280944d923f231a46053d4`
  - Fetched: 2026-07-07

## Why this file

It is a real, shipping worked example of the *secure* Windows Hello vault-unlock
path our feasibility doc recommends (`retired-docs:superpowers/plans/archive/2026-07-07-desktop-tpm-biometric-feasibility.md`).
It proves the key claim that Windows Hello can **decrypt** (not just sign):

- Opens the **`Microsoft Passport Key Storage Provider`** (NGC) via CNG NCrypt
  (`NCryptOpenStorageProvider`), line ~14.
- `NCryptCreatePersistedKey` with key-usage `NCRYPT_ALLOW_DECRYPT_FLAG | NCRYPT_ALLOW_SIGNING_FLAG`
  (line ~459) — an NGC key that can decrypt.
- Sets `NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY` (line ~354) so **every use forces
  a fresh Hello gesture** — this is the hardware gate, not an app-logic prompt.
- Encrypts/decrypts the KEK with `NCryptEncrypt` / `NCryptDecrypt` + PKCS1 padding
  (lines ~327/360).

**TPM residency is NOT proven by this reference** (attestation-claim correction):
nothing here verifies where NGC materialized the key. On machines without a
TPM (or with vTPM disabled), NGC provisions *software* keys, and this file
performs no residency or attestation check. What the reference actually
demonstrates — and `VerifyPersistentKeyIntegrity` (line ~417) enforces — is a
**non-importable** (`NCRYPT_ALLOW_KEY_IMPORT_FLAG` rejection), gesture-gated
(`NgcCacheType` mandatory-auth) decrypt key: a materially strong posture even
without TPM residency. Any implementation derived from this reference must add
an explicit residency/attestation check before making a TPM claim.

## Non-inheritable caveats (reference-legacy crypto patterns)

The pinned file is upstream code — read, don't copy; these caveats are recorded
here (not as in-file edits) so the pinned-commit fidelity stays intact:

- **PKCS#1 v1.5 padding** (`NCRYPT_PAD_PKCS1_FLAG`, line ~27; used at
  ~327/330/360) is legacy. OAEP is preferred for new designs; note NGC may only
  support PKCS1 on this key path (unverified upstream). The exposure here is
  bounded: the PKCS#1 decryption oracle runs locally against a random
  Hello-gated KEK, with every use behind a gesture and the provider's own
  retry/rate limits — it is NOT a pattern for attacker-reachable bulk crypto.
- **Plaintext key material in managed buffers**: the decrypted KEK lives in a
  plain `byte[]` (line ~358), is resized after decrypt (line ~362, upstream
  `TODO: secure resize`), and .NET strings/buffers are copy-prone — plaintext
  lingers until GC. Derived implementations must use protect-then-clear /
  fixed pinned buffers and zeroize every copy.
- `VerifyPersistentKeyIntegrity` (line ~417) partially compensates for the
  dual-use key-usage grant (decrypt+sign, line ~459) by rejecting importable
  keys; it does not substitute for residency attestation.

The equivalent from Rust is the identical NCrypt call sequence via the `windows` crate
(`windows::Win32::Security::Cryptography::{NCryptOpenStorageProvider, NCryptCreatePersistedKey,
NCryptSetProperty, NCryptEncrypt, NCryptDecrypt}`) — all confirmed present in windows-rs
(see the doc's "Live-verified" section).

The alternative route (raw TPM key via `MS_PLATFORM_CRYPTO_PROVIDER` + `NCRYPT_UI_POLICY`/
`NCRYPT_UI_PROTECT_FLAG`) is not shown here; this file is the simpler, proven NGC path.
