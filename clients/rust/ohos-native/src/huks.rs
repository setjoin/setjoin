// clients/rust/ohos-native/src/huks.rs
//! HUKS-backed `SecureStore` skeleton (OHOS-003; triage row
//! D-CLIENTS-RUST-OHOS-NATIVE-003, disposition **hardening**,
//! SEC-KEYSTORE-MISSING / CWE-311). Roadmap P2: HarmonyOS hardware key
//! custody for Model M (guard-core's `SecureStore`, ARCH-015 decision 2).
//!
//! # What exists here
//!
//! `guard_core::{SecureStore, KeyTier, SecureStoreError}` (the trait, its
//! tier vocabulary and its error contract) is defined once in
//! `clients/rust/guard-core/src/securestore/mod.rs` and re-exported public —
//! this crate implements it for [`HuksSecureStore`]; no second trait exists.
//! The shape mirrors the Apple backend (`guard-core/src/securestore/apple.rs`):
//! the keystore holds a per-alias symmetric KEK, `wrap` encrypts the 32-byte
//! vault key under it, `unwrap` decrypts through the keystore so the raw KEK
//! never leaves the secure environment, and the wrapped blob is stored by
//! guard-core in vault `meta` (Model M design B — the blob's home does not
//! change per platform).
//!
//! # Fidelity of the skeleton (compile-checked, NOT device-tested)
//!
//! Every FFI declaration, tag/enum constant, error code and call sequence is
//! transcribed from the VENDORED OpenHarmony docs in this repo —
//! `clients/harmonyos/refs/openharmony-docs/` (UniversalKeystoreKit NDK
//! guides + `reference/apis-universal-keystore-kit/capi-native-huks-*.md`) —
//! so the API shape is the real `libhuks_ndk.z.so` surface. r2 (Astra
//! review pass): every tag-type discriminator, tag index and error code was
//! re-checked line-by-line against those references, and each r2 fix cites
//! the justifying reference line at the constant or function it corrects.
//! r3 (Astra delta re-review): `clear` now deletes through the KEK's ECE
//! storage-domain selector (a null delete param set targets the CE default
//! — capi-native-huks-api-h.md L199), and the T6 test-plan claim was
//! narrowed to the exact-length guards the code actually enforces.
//! What is NOT
//! claimed: no statement here has been executed against HUKS. The crate is a
//! cdylib with `lib.test = false` (host has no ArkTS/Node-API symbols), so
//! verification is compile-check only:
//!
//! - host: `cargo check -p ohos-native` — type-checks the policy layer
//!   (this file's framing, tier-param policy and error classification are
//!   compiled on EVERY target; only the `extern` block and its call sites
//!   are `#[cfg(target_env = "ohos")]`). Config trap: the OpenHarmony
//!   triples report `target_os = "linux"` with `target_env = "ohos"`
//!   (`rustc --target aarch64-unknown-linux-ohos --print cfg`), so every
//!   gate here keys on `target_env`, never `target_os`.
//! - ohos target: `cargo check --target aarch64-unknown-linux-ohos -p
//!   ohos-native` — type-checks the cfg'd FFI half without linking anything
//!   (`-lhuks_ndk.z` is not needed until the HAP build). Note a plain
//!   `cargo build --target …` DOES link the cdylib; on the current build
//!   host that link stalls on an unrelated SDK-tool quarantine issue (see
//!   `HUKS_SECURESTORE.md`, gate G1b) — the check gates are the honest
//!   verification this environment can provide.
//! - device: the first REAL gate is the HAP build (links `libhuks_ndk.z.so`
//!   from the OHOS SDK sysroot) plus the device test plan in
//!   `HUKS_SECURESTORE.md` — several assumptions that cannot be confirmed by
//!   any compile are marked `SPIKE-TODO(device)` inline.
//!
//! # Fail-loud posture (the triage row's whole point)
//!
//! Nothing in this module fakes custody. There is no software fallback, no
//! in-memory stand-in, and no honest-looking `Ok` without a real HUKS round
//! trip behind it: on non-ohos targets `available()` is `false` for every
//! tier, the biometric tier stays `false` until its UserIAM round trip is
//! implemented and device-verified, and every raw FFI failure maps to a
//! `SecureStoreError` — never a synthesized key. `FakeSecureStore` remains
//! `#[cfg(test)]`-gated in guard-core and is untouched.
//!
//! # Wiring status (behavior remains OFF)
//!
//! This module is NOT wired into the vault path. The shell's vault still
//! opens by passphrase (`GuardCore::new` in the shared
//! `native_impl.rs`); `vault.unlockBiometric()` stays honestly `false`.
//! Wiring means calling `GuardCore::new_with_keystore(db,
//! &HuksSecureStore::new(), reason)` from the ohos vault-open seam — the
//! integration path (and why it touches the byte-shared `native_impl.rs`)
//! is documented in `HUKS_SECURESTORE.md`. Until that lands, this module is
//! inert: no `#[napi]` export references it.

use guard_core::{KeyTier, SecureStore, SecureStoreError};

// ---------------------------------------------------------------------------
// Policy constants — transcribed from the vendored C API reference
// (capi-native-huks-type-h.md). Compiled on ALL targets so the policy layer
// below is type-checked (and linted) by the plain host `cargo check`.
// ---------------------------------------------------------------------------
mod consts {
    // OH_Huks_TagType discriminators (capi-native-huks-type-h.md L449-454):
    // tags are `type | index`; INVALID=0<<28 (L449), INT=1<<28 (L450),
    // UINT=2<<28 (L451), ULONG=3<<28 (L452), BOOL=4<<28 (L453),
    // BYTES=5<<28 (L454). r2 review fix: BYTES was mistyped as 3<<28 — that
    // is ULONG, and it corrupted every BYTES tag value below (NONCE, AAD,
    // AE_TAG, AUTH_TOKEN).
    pub const OH_HUKS_TAG_TYPE_UINT: u32 = 2 << 28; // L451
    pub const OH_HUKS_TAG_TYPE_BOOL: u32 = 4 << 28; // L453
    pub const OH_HUKS_TAG_TYPE_BYTES: u32 = 5 << 28; // L454

    // Tag indices line-checked against the same table
    // (capi-native-huks-type-h.md): ALGORITHM L640, PURPOSE L641, KEY_SIZE
    // L642, PADDING L644, BLOCK_MODE L645, ASSOCIATED_DATA L647, NONCE
    // L648, USER_AUTH_TYPE L667, AUTH_TIMEOUT L668, AUTH_TOKEN L669,
    // KEY_AUTH_ACCESS_TYPE L670, CHALLENGE_TYPE L672, AUTH_STORAGE_LEVEL
    // L675, KEY_OVERRIDE L682, IS_DEVICE_PASSWORD_SET L695, AE_TAG L696.
    pub const OH_HUKS_TAG_ALGORITHM: u32 = OH_HUKS_TAG_TYPE_UINT | 1;
    pub const OH_HUKS_TAG_PURPOSE: u32 = OH_HUKS_TAG_TYPE_UINT | 2;
    pub const OH_HUKS_TAG_KEY_SIZE: u32 = OH_HUKS_TAG_TYPE_UINT | 3;
    pub const OH_HUKS_TAG_PADDING: u32 = OH_HUKS_TAG_TYPE_UINT | 5;
    pub const OH_HUKS_TAG_BLOCK_MODE: u32 = OH_HUKS_TAG_TYPE_UINT | 6;
    pub const OH_HUKS_TAG_ASSOCIATED_DATA: u32 = OH_HUKS_TAG_TYPE_BYTES | 8;
    pub const OH_HUKS_TAG_NONCE: u32 = OH_HUKS_TAG_TYPE_BYTES | 9;
    /// Declared now, consumed by the biometric device phase (the
    /// UserIAM-produced auth token rides on FinishSession's param set).
    #[allow(dead_code)]
    pub const OH_HUKS_TAG_AUTH_TOKEN: u32 = OH_HUKS_TAG_TYPE_BYTES | 306;
    pub const OH_HUKS_TAG_USER_AUTH_TYPE: u32 = OH_HUKS_TAG_TYPE_UINT | 304;
    pub const OH_HUKS_TAG_AUTH_TIMEOUT: u32 = OH_HUKS_TAG_TYPE_UINT | 305;
    pub const OH_HUKS_TAG_KEY_AUTH_ACCESS_TYPE: u32 = OH_HUKS_TAG_TYPE_UINT | 307;
    pub const OH_HUKS_TAG_CHALLENGE_TYPE: u32 = OH_HUKS_TAG_TYPE_UINT | 309;
    /// Storage security level for the generated key
    /// (OH_Huks_AuthStorageLevel, capi-native-huks-type-h.md L512-514).
    pub const OH_HUKS_TAG_AUTH_STORAGE_LEVEL: u32 = OH_HUKS_TAG_TYPE_UINT | 316;
    /// Whether GenerateKeyItem may overwrite an existing alias; `false`
    /// makes an alias conflict return an error instead
    /// (capi-native-huks-type-h.md L682, Since 20; vendored
    /// huks-key-generation-overview.md L15 — HUKS overwrites BY DEFAULT).
    pub const OH_HUKS_TAG_KEY_OVERRIDE: u32 = OH_HUKS_TAG_TYPE_BOOL | 520;
    /// `true`: the key can be generated and used only when a lock screen
    /// password is set (capi-native-huks-type-h.md L695).
    pub const OH_HUKS_TAG_IS_DEVICE_PASSWORD_SET: u32 = OH_HUKS_TAG_TYPE_BOOL | 1012;
    pub const OH_HUKS_TAG_AE_TAG: u32 = OH_HUKS_TAG_TYPE_BYTES | 10009;

    // OH_Huks_KeyAlg / KeyPurpose / KeySize / KeyPadding / CipherMode
    pub const OH_HUKS_ALG_AES: u32 = 20;
    pub const OH_HUKS_KEY_PURPOSE_ENCRYPT: u32 = 1;
    pub const OH_HUKS_KEY_PURPOSE_DECRYPT: u32 = 2;
    pub const OH_HUKS_AES_KEY_SIZE_256: u32 = 256;
    pub const OH_HUKS_PADDING_NONE: u32 = 0;
    pub const OH_HUKS_MODE_GCM: u32 = 32;

    // OH_Huks_UserAuthType / AuthAccessType / ChallengeType (biometric tier)
    pub const OH_HUKS_USER_AUTH_TYPE_FINGERPRINT: u32 = 1 << 0;
    pub const OH_HUKS_USER_AUTH_TYPE_FACE: u32 = 1 << 1;
    pub const OH_HUKS_USER_AUTH_TYPE_PIN: u32 = 1 << 2;
    /// The biometric-set analog of Apple's `biometryCurrentSet`: HUKS
    /// permanently invalidates the key when a NEW biometric template is
    /// enrolled (deleting one does not). Maps to `SecureStoreError::
    /// Invalidated` -> guard-core's design-B device-wrap fallback.
    pub const OH_HUKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL: u32 = 1 << 1;
    pub const OH_HUKS_CHALLENGE_TYPE_NORMAL: u32 = 0;

    // OH_Huks_AuthStorageLevel (capi-native-huks-type-h.md L512-514; same
    // table in vendored huks-key-generation-overview.md L29-33): DE=0
    // "only after the device is started", CE=1 "only after the first
    // unlock", ECE=2 "only when the device is unlocked". The default since
    // API 11 is CE (generation-overview.md L27), which REMAINS accessible
    // in later lock states — not the DeviceUnlock tier's promise.
    pub const OH_HUKS_AUTH_STORAGE_LEVEL_ECE: u32 = 2;

    // OH_Huks_ErrCode (capi-native-huks-type-h.md L405, L409-433): 8-digit
    // values (12 + 6 digits). r2 review fix: these were mistyped as
    // 6-digit 120_0xx values.
    pub const OH_HUKS_SUCCESS: i32 = 0; // L405
    pub const OH_HUKS_ERR_CODE_KEY_AUTH_PERMANENTLY_INVALIDATED: i32 = 12000007; // L415
    pub const OH_HUKS_ERR_CODE_KEY_AUTH_VERIFY_FAILED: i32 = 12000008; // L416
    pub const OH_HUKS_ERR_CODE_KEY_AUTH_TIME_OUT: i32 = 12000009; // L417
    pub const OH_HUKS_ERR_CODE_ITEM_NOT_EXIST: i32 = 12000011; // L419
    pub const OH_HUKS_ERR_CODE_CREDENTIAL_NOT_EXIST: i32 = 12000013; // L421
    pub const OH_HUKS_ERR_CODE_DEVICE_PASSWORD_UNSET: i32 = 12000016; // L424
    /// Returned by GenerateKeyItem when OH_HUKS_TAG_KEY_OVERRIDE is `false`
    /// and the alias already exists ("cannot be overwritten" —
    /// capi-native-huks-type-h.md L425; errorcode-huks.md "12000017
    /// Duplicate Key Alias").
    pub const OH_HUKS_ERR_CODE_KEY_ALREADY_EXIST: i32 = 12000017; // L425

    /// AES-GCM nonce length HUKS expects for `OH_HUKS_MODE_GCM` (the NDK
    /// sample uses 12 bytes; `OH_HUKS_AE_NONCE_LEN` is the C constant).
    pub const NONCE_LEN: usize = 12;
    /// GCM authentication tag length HUKS appends to ciphertext (the NDK
    /// AES/GCM sample slices a 16-byte `AE_TAG` off the end).
    pub const GCM_TAG_LEN: usize = 16;
    /// Vault-key length fixed by the `SecureStore` trait signature
    /// (`wrap(&[u8; 32])` / `unwrap -> [u8; 32]`).
    pub const KEY_LEN: usize = 32;
    /// Exact `ct || tag` payload of a v1 wrap frame over one 32-byte key;
    /// any other length is not a blob this backend produced.
    pub const WRAP_CT_TAG_LEN: usize = KEY_LEN + GCM_TAG_LEN;
}
use consts::*;

// ---------------------------------------------------------------------------
// Policy layer — pure, compiled on every target.
// ---------------------------------------------------------------------------

/// One intended HUKS parameter, in target-independent form so the tier
/// policy is expressible (and lint/type-checked) off-device. The ohos-only
/// `raw::build_param_set` translates these into `OH_Huks_Param` records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParamSpec {
    U32 { tag: u32, value: u32 },
    Bool { tag: u32, value: bool },
    Blob { tag: u32, value: Vec<u8> },
}

/// Cipher-suite parameters shared by key generation and both session
/// directions: AES-256-GCM, no padding. GCM NONCE/AAD are session params.
fn push_aes_gcm_suite(out: &mut Vec<ParamSpec>) {
    out.push(ParamSpec::U32 { tag: OH_HUKS_TAG_ALGORITHM, value: OH_HUKS_ALG_AES });
    out.push(ParamSpec::U32 { tag: OH_HUKS_TAG_KEY_SIZE, value: OH_HUKS_AES_KEY_SIZE_256 });
    out.push(ParamSpec::U32 { tag: OH_HUKS_TAG_PADDING, value: OH_HUKS_PADDING_NONE });
    out.push(ParamSpec::U32 { tag: OH_HUKS_TAG_BLOCK_MODE, value: OH_HUKS_MODE_GCM });
}

/// The storage domain every KEK of this backend lives in: ECE ("only when
/// the device is unlocked" — capi-native-huks-type-h.md L514). Single
/// source of truth for generation, both session directions AND deletion,
/// so the domain selected at generation is exactly the one every later op
/// targets (r3 review fix: deletion must re-select it — see
/// `delete_key_params`).
pub(crate) fn kek_storage_level() -> u32 {
    OH_HUKS_AUTH_STORAGE_LEVEL_ECE
}

/// Access-control tags carried by EVERY operation that touches the
/// per-alias KEK — generation AND both session directions — so the
/// restriction set cannot drift between the op that creates the key and
/// the ops that use it (r2 review fix; previously generation carried no
/// access-control tags at all).
///
/// The DeviceUnlock tier's promise is "the KEK is usable only while the
/// device is unlocked, and only when a lock screen password exists":
///
/// - `OH_HUKS_TAG_AUTH_STORAGE_LEVEL = ECE` — the API-11+ default is CE
///   ("only after the FIRST unlock", which HUKS keeps serving in later
///   lock states — vendored huks-key-generation-overview.md L27, L32);
///   ECE is "only when the device is unlocked" (L33 /
///   capi-native-huks-type-h.md L514).
/// - `OH_HUKS_TAG_IS_DEVICE_PASSWORD_SET = true` — "the key can be
///   generated and used only when a password is set"; password enforcement
///   needs this explicit tag (capi-native-huks-type-h.md L695).
///
/// The biometric tier inherits the same storage posture (it additionally
/// carries its user-auth tag set below). SPIKE-TODO(device): confirm HUKS
/// accepts the generation-shaped tags re-specified on session param sets
/// (test plan T8) — a rejection here must surface as a loud failure, not
/// be papered over by dropping the tags.
fn push_kek_access_controls(out: &mut Vec<ParamSpec>) {
    out.push(ParamSpec::U32 {
        tag: OH_HUKS_TAG_AUTH_STORAGE_LEVEL,
        value: kek_storage_level(),
    });
    out.push(ParamSpec::Bool { tag: OH_HUKS_TAG_IS_DEVICE_PASSWORD_SET, value: true });
}

/// Key-generation parameters for the per-alias KEK at `tier`. A HUKS key can
/// carry only one purpose *set* at generation and it must match the purpose
/// used at session time (vendored huks-key-generation-ndk.md NOTE), so the
/// key is generated with ENCRYPT|DECRYPT up front.
///
/// Generation is NON-OVERRIDING: `OH_HUKS_TAG_KEY_OVERRIDE = false` makes
/// an alias conflict return `KEY_ALREADY_EXIST` instead of silently
/// replacing the existing key (HUKS overwrites BY DEFAULT — vendored
/// huks-key-generation-overview.md L15), which would strand every blob
/// already wrapped under the old KEK. `raw::generate_key_never_override`
/// handles that conflict as success-with-existing.
///
/// DeviceUnlock: the access-control posture is the ECE + password-required
/// pair from `push_kek_access_controls` — release is gated by the device
/// lock state, not by a per-use prompt. This is the Model M recovery-root
/// tier (guard-core always keeps a device-tier wrap).
///
/// Biometric: adds the user-auth tags (fingerprint|face|PIN,
/// INVALID_NEW_BIO_ENROLL invalidation, normal challenge). Today the tier is
/// gated OFF in `available()` because the unwrap half also needs the UserIAM
/// challenge/token round trip; the tags are still encoded here so the device
/// phase only has to flip the gate and add the auth-token param.
pub(crate) fn gen_key_params(tier: KeyTier) -> Vec<ParamSpec> {
    let mut out = Vec::new();
    push_aes_gcm_suite(&mut out);
    out.push(ParamSpec::U32 {
        tag: OH_HUKS_TAG_PURPOSE,
        value: OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT,
    });
    push_kek_access_controls(&mut out);
    out.push(ParamSpec::Bool { tag: OH_HUKS_TAG_KEY_OVERRIDE, value: false });
    if tier == KeyTier::Biometric {
        out.push(ParamSpec::U32 {
            tag: OH_HUKS_TAG_USER_AUTH_TYPE,
            value: OH_HUKS_USER_AUTH_TYPE_FINGERPRINT
                | OH_HUKS_USER_AUTH_TYPE_FACE
                | OH_HUKS_USER_AUTH_TYPE_PIN,
        });
        out.push(ParamSpec::U32 {
            tag: OH_HUKS_TAG_KEY_AUTH_ACCESS_TYPE,
            value: OH_HUKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL,
        });
        out.push(ParamSpec::U32 {
            tag: OH_HUKS_TAG_AUTH_TIMEOUT,
            value: 30, // seconds; short window, one unlock per vault open
        });
        out.push(ParamSpec::U32 {
            tag: OH_HUKS_TAG_CHALLENGE_TYPE,
            value: OH_HUKS_CHALLENGE_TYPE_NORMAL,
        });
    }
    out
}

/// Session parameters for one Init/Finish round at `purpose` (ENCRYPT or
/// DECRYPT). `aad` binds every blob to its alias, so a blob stored under one
/// vault alias cannot be unwrapped under another (HUKS would fail the GCM
/// tag). `ae_tag` is `Some` only for DECRYPT: HUKS expects the split-off GCM
/// tag instead of recomputing it into the output.
///
/// The KEK access-control tags ride on every session too
/// (`push_kek_access_controls`) — same restriction set as generation, on
/// every op that uses the key (r2 review fix).
pub(crate) fn session_params(
    purpose: u32,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ae_tag: Option<&[u8]>,
) -> Vec<ParamSpec> {
    let mut out = Vec::new();
    push_aes_gcm_suite(&mut out);
    out.push(ParamSpec::U32 { tag: OH_HUKS_TAG_PURPOSE, value: purpose });
    out.push(ParamSpec::Blob { tag: OH_HUKS_TAG_NONCE, value: nonce.to_vec() });
    out.push(ParamSpec::Blob { tag: OH_HUKS_TAG_ASSOCIATED_DATA, value: aad.to_vec() });
    push_kek_access_controls(&mut out);
    if let Some(tag) = ae_tag {
        out.push(ParamSpec::Blob { tag: OH_HUKS_TAG_AE_TAG, value: tag.to_vec() });
    }
    out
}

/// Deletion parameters for the per-alias KEK (r3 review fix): the
/// storage-domain selector alone. The vendored reference makes the storage
/// level part of the delete's key identification — a null param set does
/// NOT mean "any domain", it selects CE ("Pointer to the parameters for
/// deleting the key. By default, this parameter is a null pointer. The
/// default key storage level is OH_HUKS_AUTH_STORAGE_LEVEL_CE",
/// capi-native-huks-api-h.md L199; the ArkTS API spells the selector out:
/// "If HuksAuthStorageLevel is used to specify the security level of the
/// key to be deleted, this parameter can be left empty. If the API version
/// is 12 or later, the default value CE is passed in", js-apis-huks.md
/// deleteKeyItem L361). Deleting without it would look in CE, miss the ECE
/// KEK, and `ITEM_NOT_EXIST`-as-idempotent would paper over the miss.
/// Only the storage level rides here: it is the one tag the delete
/// references name as the key selector (no cipher/purpose/access tags are
/// documented delete-time identification).
pub(crate) fn delete_key_params() -> Vec<ParamSpec> {
    vec![ParamSpec::U32 {
        tag: OH_HUKS_TAG_AUTH_STORAGE_LEVEL,
        value: kek_storage_level(),
    }]
}

/// Map a HUKS status code onto the trait's error vocabulary (the same
/// four-state contract apple.rs maps CFErrors onto). Numeric codes are safe
/// to carry (no key material); HUKS's `errorMsg` char* is NEVER copied —
/// like Apple's CFError text it may echo call parameters, and the trait
/// contract (`SecureStoreError` Display/Debug) hides `Failed`'s payload.
pub(crate) fn classify(code: i32) -> SecureStoreError {
    match code {
        // KEK gone / permanently dead -> re-wrap required (guard-core falls
        // back to the device-tier wrap or re-provisions).
        OH_HUKS_ERR_CODE_ITEM_NOT_EXIST | OH_HUKS_ERR_CODE_KEY_AUTH_PERMANENTLY_INVALIDATED => {
            SecureStoreError::Invalidated
        }
        // Auth present but not satisfied / timed out — nearest trait state
        // is "the user did not complete the prompt".
        OH_HUKS_ERR_CODE_KEY_AUTH_VERIFY_FAILED | OH_HUKS_ERR_CODE_KEY_AUTH_TIME_OUT => {
            SecureStoreError::Cancelled
        }
        // The tier cannot be served at all right now.
        OH_HUKS_ERR_CODE_CREDENTIAL_NOT_EXIST | OH_HUKS_ERR_CODE_DEVICE_PASSWORD_UNSET => {
            SecureStoreError::Unavailable
        }
        _ => SecureStoreError::Failed(format!("huks errorCode {code}")),
    }
}

/// Wrapped-blob framing, versioned so the format can evolve without
/// re-wrapping existing vaults silently: `"sj-huks-v1" || nonce(12) || ct`.
/// `ct` is HUKS's GCM output = ciphertext (key length) || tag (16). AAD is
/// NOT in the frame — it is re-derived from the alias at unwrap time.
const FRAMING_MAGIC: &[u8; 10] = b"sj-huks-v1";

pub(crate) fn frame_blob(nonce: &[u8; NONCE_LEN], ct_tag: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAMING_MAGIC.len() + NONCE_LEN + ct_tag.len());
    out.extend_from_slice(FRAMING_MAGIC);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ct_tag);
    out
}

pub(crate) fn unframe_blob(blob: &[u8]) -> Result<([u8; NONCE_LEN], &[u8]), SecureStoreError> {
    if blob.len() < FRAMING_MAGIC.len() + NONCE_LEN + GCM_TAG_LEN
        || &blob[..FRAMING_MAGIC.len()] != FRAMING_MAGIC
    {
        return Err(SecureStoreError::Failed(
            "huks blob: bad framing (wrong magic or truncated)".into(),
        ));
    }
    let rest = &blob[FRAMING_MAGIC.len()..];
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&rest[..NONCE_LEN]);
    Ok((nonce, &rest[NONCE_LEN..]))
}

// ---------------------------------------------------------------------------
// Raw FFI half — ohos only. Host builds type-check the policy layer above
// and see the fail-loud stubs below; nothing here links on the host.
// ---------------------------------------------------------------------------
#[cfg(target_env = "ohos")]
mod raw {
    #![allow(non_snake_case)] // C names preserved for line-by-line doc diffs
    // Declared-API surface (union variants, result fields, AbortSession,
    // IsKeyItemExist, AUTH_TOKEN tag) is intentionally complete even where
    // the DeviceUnlock-tier paths don't consume every piece yet.
    #![allow(dead_code)]
    use super::classify;
    use super::consts::*;
    use super::{ParamSpec, SecureStoreError};
    use zeroize::Zeroizing;

    // --- types (capi-hukstypeapi-*.md) ----------------------------------

    /// `struct OH_Huks_Blob { uint32_t size; uint8_t *data; }`
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct OH_Huks_Blob {
        pub size: u32,
        pub data: *mut u8,
    }

    /// `struct OH_Huks_Result { int32_t errorCode; const char *errorMsg;
    ///  uint8_t *data; }` — `errorMsg` is never dereferenced (see `classify`).
    #[repr(C)]
    pub struct OH_Huks_Result {
        pub errorCode: i32,
        pub errorMsg: *const core::ffi::c_char,
        pub data: *mut u8,
    }

    /// Anonymous union of `struct OH_Huks_Param` (boolParam / int32Param /
    /// uint32Param / uint64Param / blob). Written, never read back.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub union OH_Huks_ParamValue {
        pub boolParam: bool,
        pub int32Param: i32,
        pub uint32Param: u32,
        pub uint64Param: u64,
        pub blob: OH_Huks_Blob,
    }

    /// `struct OH_Huks_Param { uint32_t tag; union {...}; }` — repr(C)
    /// reproduces the C layout (tag, padding, 8-aligned union).
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct OH_Huks_Param {
        pub tag: u32,
        pub value: OH_Huks_ParamValue,
    }

    /// `struct OH_Huks_ParamSet` — opaque here; only ever handed back to the
    /// HUKS functions that create/free/consume it.
    #[repr(C)]
    pub struct OH_Huks_ParamSet {
        _opaque: [u8; 0],
    }

    // --- libhuks_ndk.z.so (capi-native-huks-api-h.md) --------------------
    // Linked by the HAP build from the OHOS SDK sysroot; compile-checks
    // never link (cdylib-only crate, `lib.test = false`).
    #[link(name = "huks_ndk.z", kind = "dylib")]
    extern "C" {
        fn OH_Huks_InitParamSet(paramSet: *mut *mut OH_Huks_ParamSet) -> OH_Huks_Result;
        fn OH_Huks_AddParams(
            paramSet: *mut OH_Huks_ParamSet,
            params: *const OH_Huks_Param,
            paramCount: u32,
        ) -> OH_Huks_Result;
        fn OH_Huks_BuildParamSet(paramSet: *mut *mut OH_Huks_ParamSet) -> OH_Huks_Result;
        fn OH_Huks_FreeParamSet(paramSet: *mut *mut OH_Huks_ParamSet);
        fn OH_Huks_GenerateKeyItem(
            keyAlias: *const OH_Huks_Blob,
            paramSetIn: *const OH_Huks_ParamSet,
            paramSetOut: *mut OH_Huks_ParamSet,
        ) -> OH_Huks_Result;
        fn OH_Huks_IsKeyItemExist(
            keyAlias: *const OH_Huks_Blob,
            paramSet: *const OH_Huks_ParamSet,
        ) -> OH_Huks_Result;
        fn OH_Huks_DeleteKeyItem(
            keyAlias: *const OH_Huks_Blob,
            paramSet: *const OH_Huks_ParamSet,
        ) -> OH_Huks_Result;
        fn OH_Huks_InitSession(
            keyAlias: *const OH_Huks_Blob,
            paramSet: *const OH_Huks_ParamSet,
            handle: *mut OH_Huks_Blob,
            token: *mut OH_Huks_Blob,
        ) -> OH_Huks_Result;
        fn OH_Huks_FinishSession(
            handle: *const OH_Huks_Blob,
            paramSet: *const OH_Huks_ParamSet,
            inData: *const OH_Huks_Blob,
            outData: *mut OH_Huks_Blob,
        ) -> OH_Huks_Result;
        fn OH_Huks_AbortSession(
            handle: *const OH_Huks_Blob,
            paramSet: *const OH_Huks_ParamSet,
        ) -> OH_Huks_Result;
    }

    fn blob_of(bytes: &[u8]) -> OH_Huks_Blob {
        OH_Huks_Blob { size: bytes.len() as u32, data: bytes.as_ptr() as *mut u8 }
    }

    fn check(r: OH_Huks_Result) -> Result<i32, SecureStoreError> {
        if r.errorCode == OH_HUKS_SUCCESS {
            Ok(r.errorCode)
        } else {
            Err(classify(r.errorCode))
        }
    }

    /// RAII owner of one `OH_Huks_ParamSet` (FreeParamSet on drop, matching
    /// every vendored sample's `OH_Huks_FreeParamSet(&ps)` tail).
    pub(crate) struct ParamSet(*mut OH_Huks_ParamSet);

    impl Drop for ParamSet {
        fn drop(&mut self) {
            // SAFETY: `self.0` came from OH_Huks_InitParamSet and is freed
            // exactly once here.
            unsafe { OH_Huks_FreeParamSet(&mut self.0) };
        }
    }

    /// InitParamSet -> AddParams -> BuildParamSet, the vendored sample's
    /// `InitParamSet` helper as RAII. `specs` outlives the call; AddParams
    /// copies values into the set (SPIKE-TODO(device): confirm HUKS keeps
    /// its own copy and does not retain caller pointers — the sample code's
    /// static arrays cannot distinguish the two; this builder keeps `specs`
    /// alive until after BuildParamSet either way, and all session calls
    /// take the built set, not the specs).
    pub(crate) fn build_param_set(specs: &[ParamSpec]) -> Result<ParamSet, SecureStoreError> {
        let mut ps: *mut OH_Huks_ParamSet = core::ptr::null_mut();
        // SAFETY: ps is a valid out-pointer; on failure the set is either
        // untouched or freed by us below.
        check(unsafe { OH_Huks_InitParamSet(&mut ps) })?;
        let built = (|| {
            // Transient translation records: the blobs must outlive the
            // OH_Huks_Param array handed to AddParams, hence the scoped vecs.
            let mut blob_store: Vec<Vec<u8>> = Vec::with_capacity(specs.len());
            let mut params: Vec<OH_Huks_Param> = Vec::with_capacity(specs.len());
            for spec in specs {
                match spec {
                    ParamSpec::U32 { tag, value } => params.push(OH_Huks_Param {
                        tag: *tag,
                        value: OH_Huks_ParamValue { uint32Param: *value },
                    }),
                    ParamSpec::Bool { tag, value } => params.push(OH_Huks_Param {
                        tag: *tag,
                        value: OH_Huks_ParamValue { boolParam: *value },
                    }),
                    ParamSpec::Blob { tag, value } => {
                        blob_store.push(value.clone());
                        let b = blob_store.last().expect("just pushed");
                        params.push(OH_Huks_Param {
                            tag: *tag,
                            value: OH_Huks_ParamValue { blob: blob_of(b) },
                        });
                    }
                }
            }
            // SAFETY: ps is the live set from InitParamSet; params is a
            // contiguous OH_Huks_Param array of exactly paramCount records.
            check(unsafe { OH_Huks_AddParams(ps, params.as_ptr(), params.len() as u32) })?;
            // SAFETY: ps is the live set from InitParamSet.
            check(unsafe { OH_Huks_BuildParamSet(&mut ps) })
        })();
        if let Err(e) = built {
            drop(ParamSet(ps)); // free the half-built set
            return Err(e);
        }
        Ok(ParamSet(ps))
    }

    /// Provision the per-alias KEK WITHOUT ever overwriting it. `specs`
    /// must carry `OH_HUKS_TAG_KEY_OVERRIDE = false` (they come from
    /// `gen_key_params`, which always appends it): HUKS overwrites an
    /// existing alias BY DEFAULT (vendored huks-key-generation-overview.md
    /// L15 — "the existing key will be overwritten by default"; the tag is
    /// what turns a conflict into an error), so a separate
    /// check-then-generate is both racy AND the overwrite hazard itself:
    /// two concurrent first wraps can both observe "absent", and the loser
    /// of the race would silently replace the winner's KEK, stranding every
    /// blob wrapped under it. Instead: generate non-overriding, and treat
    /// `OH_HUKS_ERR_CODE_KEY_ALREADY_EXIST` (capi-native-huks-type-h.md
    /// L425; errorcode-huks.md "12000017 Duplicate Key Alias" — "cannot be
    /// overwritten") as success-with-existing. Returns `true` when a fresh
    /// key was created, `false` when the existing KEK was kept.
    pub(crate) fn generate_key_never_override(
        alias: &str,
        specs: &[ParamSpec],
    ) -> Result<bool, SecureStoreError> {
        debug_assert!(specs.iter().any(|s| matches!(
            s,
            ParamSpec::Bool { tag: OH_HUKS_TAG_KEY_OVERRIDE, value: false }
        )));
        let alias_blob = blob_of(alias.as_bytes());
        let ps = build_param_set(specs)?;
        // SAFETY: alias_blob + ps.0 are live for the call; no out set needed
        // (vendored samples pass nullptr for paramSetOut).
        match unsafe { OH_Huks_GenerateKeyItem(&alias_blob, ps.0, core::ptr::null_mut()) }
            .errorCode
        {
            OH_HUKS_SUCCESS => Ok(true),
            OH_HUKS_ERR_CODE_KEY_ALREADY_EXIST => Ok(false), // existing KEK kept
            code => Err(classify(code)),
        }
    }

    /// Delete the per-alias KEK in the storage domain `specs` selects (the
    /// ECE selector from `delete_key_params`; r3 review fix — a null param
    /// set targets the CE default per capi-native-huks-api-h.md L199, which
    /// would "succeed" while an ECE KEK survived). Idempotent:
    /// `ITEM_NOT_EXIST` (capi-native-huks-type-h.md L419) with the selector
    /// attached means the alias is already absent in the right domain.
    pub(crate) fn delete_key(alias: &str, specs: &[ParamSpec]) -> Result<(), SecureStoreError> {
        let alias_blob = blob_of(alias.as_bytes());
        let ps = build_param_set(specs)?;
        // SAFETY: alias_blob points at live bytes; ps is the live built set
        // carrying the storage-level selector (the delete paramSet selects
        // the key's storage domain — capi-native-huks-api-h.md L199,
        // js-apis-huks.md deleteKeyItem L361).
        match unsafe { OH_Huks_DeleteKeyItem(&alias_blob, ps.0) }.errorCode {
            OH_HUKS_SUCCESS | OH_HUKS_ERR_CODE_ITEM_NOT_EXIST => Ok(()), // idempotent
            code => Err(classify(code)),
        }
    }

    /// One InitSession -> FinishSession round. GCM output length equals
    /// input length (encrypt appends `GCM_TAG_LEN`; decrypt was handed the
    /// tag separately), so `expected_out` is exact — the buffer is
    /// caller-allocated per the C API (outData is an in-out capacity/length
    /// blob; SPIKE-TODO(device): confirm HUKS writes the true length back
    /// into `.size` on success — the code below REQUIRES exactly
    /// `expected_out` and rejects anything else, including 0, so a
    /// zero-filled synthetic key can never be mistaken for a real one; if a
    /// device ever reports success with an unwritten `.size`, that is a new
    /// device finding to resolve, not something to accept).
    /// The output buffer is zeroized on every path that does not return it.
    pub(crate) fn cipher_session(
        alias: &str,
        specs: &[ParamSpec],
        input: &[u8],
        expected_out: usize,
    ) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        // r2 review fix: a zero-length expectation is never valid here — a
        // caller passing 0 would make `n == expected_out` accept HUKS
        // reporting an unwritten/empty `.size` (0) and hand back the
        // pre-zeroed buffer as if it were key material. Callers pass real
        // frame constants (WRAP_CT_TAG_LEN / KEY_LEN); this guard keeps the
        // reject-zero property local to the session, not just to the callers.
        if expected_out == 0 {
            return Err(SecureStoreError::Failed(
                "huks session: zero-length output expectation".into(),
            ));
        }
        let alias_blob = blob_of(alias.as_bytes());
        let in_blob = blob_of(input);
        let ps = build_param_set(specs)?;

        let mut handle_bytes = [0u8; 8]; // uint64_t session handle
        let mut handle = OH_Huks_Blob { size: 8, data: handle_bytes.as_mut_ptr() };
        // SAFETY: all pointers reference live locals for the call; token
        // (challenge out-param) is null — DeviceUnlock keys carry no auth.
        check(unsafe {
            OH_Huks_InitSession(&alias_blob, ps.0, &mut handle, core::ptr::null_mut())
        })?;

        let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; expected_out]);
        let mut out_blob =
            OH_Huks_Blob { size: expected_out as u32, data: out.as_mut_ptr() };
        // SAFETY: handle references the local handle blob from InitSession;
        // in_blob/out_blob reference live buffers for the call.
        if let Err(e) =
            check(unsafe { OH_Huks_FinishSession(&handle, ps.0, &in_blob, &mut out_blob) })
        {
            // A failed Finish may leave the session open — abort it
            // best-effort (vendored OH_Huks_AbortSession), then surface the
            // classification. `out` (zeroizing) drops unreturned.
            // SAFETY: same live handle blob as the Finish call above.
            unsafe { OH_Huks_AbortSession(&handle, ps.0) };
            return Err(e);
        }
        match out_blob.size as usize {
            // HUKS must report the produced length in `.size`; anything
            // else — a zero (unwritten/empty output), a short or a long
            // write — means the session lied about the output shape, and
            // returning the pre-zeroed buffer would be a synthetic key
            // (r2 review fix: 0 used to be accepted here).
            n if n == expected_out => Ok(out),
            other => Err(SecureStoreError::Failed(format!(
                "huks session: unexpected output length {other} (expected {expected_out})"
            ))),
        }
    }

    /// Fresh GCM nonce (ohos-only `rand` dep; same family as guard-core).
    pub(crate) fn random_nonce() -> [u8; NONCE_LEN] {
        use rand::Rng;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        nonce
    }
}

/// Fail-loud host twin of the `raw` module: identical call signatures so the
/// `SecureStore` impl below is ONE copy on every target, but every entry
/// point refuses — there is no host keystore, and pretending otherwise is
/// exactly the "silent fake custody" the triage row forbids.
#[cfg(not(target_env = "ohos"))]
mod raw {
    use super::consts::NONCE_LEN;
    use super::{ParamSpec, SecureStoreError};
    use zeroize::Zeroizing;

    const NO_HUKS: &str = "HUKS backend only exists on OHOS targets (compile-checked skeleton, not wired — see HUKS_SECURESTORE.md)";

    pub(crate) fn generate_key_never_override(
        _alias: &str,
        _specs: &[ParamSpec],
    ) -> Result<bool, SecureStoreError> {
        Err(SecureStoreError::Failed(NO_HUKS.into()))
    }
    pub(crate) fn delete_key(
        _alias: &str,
        _specs: &[ParamSpec],
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::Failed(NO_HUKS.into()))
    }
    pub(crate) fn cipher_session(
        _alias: &str,
        _specs: &[ParamSpec],
        _input: &[u8],
        _expected_out: usize,
    ) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        Err(SecureStoreError::Failed(NO_HUKS.into()))
    }
    pub(crate) fn random_nonce() -> [u8; NONCE_LEN] {
        [0u8; NONCE_LEN]
    }
}

// ---------------------------------------------------------------------------
// The backend
// ---------------------------------------------------------------------------

/// HarmonyOS HUKS-backed `SecureStore` (DeviceUnlock tier implemented
/// against the FFI; biometric gated off pending its UserIAM round trip —
/// see the module docs and `HUKS_SECURESTORE.md`). Stateless: HUKS owns the
/// key material, guard-core owns the wrapped blobs in vault `meta`.
pub struct HuksSecureStore;

impl HuksSecureStore {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HuksSecureStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureStore for HuksSecureStore {
    /// Wrap the 32-byte vault key under the per-alias HUKS KEK
    /// (AES-256-GCM, AAD = alias). No prompt on any tier this backend
    /// currently serves.
    fn wrap(
        &self,
        alias: &str,
        key: &[u8; 32],
        tier: KeyTier,
    ) -> Result<Vec<u8>, SecureStoreError> {
        if !self.available(tier) {
            return Err(SecureStoreError::Unavailable);
        }
        // Provision-or-reuse, NON-overriding (r2 review fix): the old
        // check-then-generate had a race — two concurrent first wraps could
        // both observe "absent" and the second GenerateKeyItem would
        // silently OVERWRITE the KEK (documented HUKS default,
        // huks-key-generation-overview.md L15), stranding every blob already
        // wrapped under it. KEY_OVERRIDE=false + already-exists-as-success
        // means an existing KEK is never replaced.
        raw::generate_key_never_override(alias, &gen_key_params(tier))?;
        let nonce = raw::random_nonce();
        let specs = session_params(OH_HUKS_KEY_PURPOSE_ENCRYPT, &nonce, alias.as_bytes(), None);
        // GCM output: 32-byte ciphertext + 16-byte appended tag, exact.
        let ct_tag = raw::cipher_session(alias, &specs, key, WRAP_CT_TAG_LEN)?;
        Ok(frame_blob(&nonce, &ct_tag))
    }

    /// Unwrap through HUKS. `reason` is unused on this backend today: the
    /// implemented tier (DeviceUnlock) never prompts (`KeyTier::prompts()`
    /// is false), and the prompting tier is gated off in `available()`.
    fn unwrap(
        &self,
        alias: &str,
        blob: &[u8],
        tier: KeyTier,
        _reason: &str,
    ) -> Result<[u8; 32], SecureStoreError> {
        if !self.available(tier) {
            return Err(SecureStoreError::Unavailable);
        }
        let (nonce, ct_tag) = unframe_blob(blob)?;
        // The v1 frame carries exactly one wrapped vault key: 32 ct + 16
        // GCM tag. Reject ANY other length BEFORE the session (r2 review
        // fix) — handing HUKS a padded/truncated "ciphertext" would make
        // even a successful GCM round meaningless, and its output would not
        // be 32 bytes either.
        if ct_tag.len() != WRAP_CT_TAG_LEN {
            return Err(SecureStoreError::Failed(format!(
                "huks blob: wrap payload is {} bytes (expected {WRAP_CT_TAG_LEN})",
                ct_tag.len()
            )));
        }
        let (ct, tag) = ct_tag.split_at(KEY_LEN);
        let specs = session_params(
            OH_HUKS_KEY_PURPOSE_DECRYPT,
            &nonce,
            alias.as_bytes(),
            Some(tag),
        );
        // cipher_session already enforces the exact 32-byte plaintext; the
        // copy below only converts the zeroizing buffer to the array shape.
        let plain = raw::cipher_session(alias, &specs, ct, KEY_LEN)?;
        if plain.len() != KEY_LEN {
            return Err(SecureStoreError::Failed("unexpected unwrap length".into()));
        }
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(&plain);
        Ok(out) // `plain` (Zeroizing) scrubs on drop
    }

    /// Delete the per-alias HUKS KEK. Idempotent: an absent alias is `Ok`
    /// (matches the trait contract and apple.rs/FakeSecureStore). The
    /// delete carries the KEK's storage-domain selector (`delete_key_params`,
    /// r3 review fix): with a null param set HUKS defaults to the CE domain
    /// (capi-native-huks-api-h.md L199), so a bare delete could report
    /// success while the ECE KEK survived.
    fn clear(&self, alias: &str) -> Result<(), SecureStoreError> {
        raw::delete_key(alias, &delete_key_params())
    }

    /// Whether the OS keystore can serve `tier`.
    /// - DeviceUnlock: true on ohos targets (HUKS is a guaranteed system
    ///   service there); false everywhere else so a host build can never
    ///   claim hardware custody it does not have.
    /// - Biometric: false — SPIKE-TODO(device): stays false until the
    ///   UserIAM challenge/token round trip (OH_Huks_InitSession's token
    ///   out-blob -> UserAuthKit authenticate -> OH_HUKS_TAG_AUTH_TOKEN on
    ///   FinishSession) is implemented AND device-verified. guard-core's
    ///   orchestration therefore never selects this tier against this
    ///   backend; behavior stays OFF until separately admitted.
    /// - DomainSso: false — Windows-only concept, N/A on OHOS (mirrors
    ///   apple.rs).
    fn available(&self, tier: KeyTier) -> bool {
        match tier {
            KeyTier::DeviceUnlock => cfg!(target_env = "ohos"),
            KeyTier::Biometric => false,
            KeyTier::DomainSso => false,
        }
    }
}

// Compile-check-only unit tests (this crate is `lib.test = false`: nothing
// here RUNS on the host — the cdylib cannot link without ArkTS/Node-API
// symbols; same posture as the unit tests inside the shared native_impl.rs,
// compile-checked via `cargo build --target aarch64-unknown-linux-ohos
// --tests -p ohos-native`, runnable only where that links).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_round_trips() {
        let nonce = [7u8; NONCE_LEN];
        let ct_tag: Vec<u8> = (0..48).collect(); // 32 ct + 16 tag
        let blob = frame_blob(&nonce, &ct_tag);
        let (nonce2, ct_tag2) = unframe_blob(&blob).unwrap();
        assert_eq!(nonce2, nonce);
        assert_eq!(ct_tag2, &ct_tag[..]);
    }

    #[test]
    fn unframe_rejects_truncated_and_foreign_blobs() {
        assert!(unframe_blob(b"short").is_err());
        let mut bad = frame_blob(&[0u8; NONCE_LEN], &[0u8; 32 + GCM_TAG_LEN]);
        bad[0] = b'X'; // wrong magic
        assert!(unframe_blob(&bad).is_err());
    }

    #[test]
    fn device_tier_gen_params_have_no_auth_tags() {
        let specs = gen_key_params(KeyTier::DeviceUnlock);
        assert!(specs.iter().all(|s| match s {
            ParamSpec::U32 { tag, .. } => {
                *tag != OH_HUKS_TAG_USER_AUTH_TYPE && *tag != OH_HUKS_TAG_KEY_AUTH_ACCESS_TYPE
            }
            _ => true,
        }));
        // purpose set covers both directions; suite is AES-256-GCM/NONE
        assert!(specs.contains(&ParamSpec::U32 {
            tag: OH_HUKS_TAG_PURPOSE,
            value: OH_HUKS_KEY_PURPOSE_ENCRYPT | OH_HUKS_KEY_PURPOSE_DECRYPT,
        }));
        assert!(specs.contains(&ParamSpec::U32 {
            tag: OH_HUKS_TAG_ALGORITHM,
            value: OH_HUKS_ALG_AES,
        }));
        assert!(specs.contains(&ParamSpec::U32 {
            tag: OH_HUKS_TAG_BLOCK_MODE,
            value: OH_HUKS_MODE_GCM,
        }));
    }

    #[test]
    fn biometric_tier_gen_params_carry_auth_tags() {
        let specs = gen_key_params(KeyTier::Biometric);
        assert!(specs.contains(&ParamSpec::U32 {
            tag: OH_HUKS_TAG_USER_AUTH_TYPE,
            value: OH_HUKS_USER_AUTH_TYPE_FINGERPRINT
                | OH_HUKS_USER_AUTH_TYPE_FACE
                | OH_HUKS_USER_AUTH_TYPE_PIN,
        }));
        assert!(specs.contains(&ParamSpec::U32 {
            tag: OH_HUKS_TAG_KEY_AUTH_ACCESS_TYPE,
            value: OH_HUKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL,
        }));
    }

    #[test]
    fn decrypt_session_params_carry_split_tag() {
        let specs = session_params(OH_HUKS_KEY_PURPOSE_DECRYPT, &[1u8; NONCE_LEN], b"alias", Some(&[9u8; GCM_TAG_LEN]));
        assert!(specs.contains(&ParamSpec::Blob {
            tag: OH_HUKS_TAG_AE_TAG,
            value: vec![9u8; GCM_TAG_LEN],
        }));
        assert!(specs.contains(&ParamSpec::Blob {
            tag: OH_HUKS_TAG_NONCE,
            value: vec![1u8; NONCE_LEN],
        }));
        // encrypt params carry no AE_TAG
        let enc = session_params(OH_HUKS_KEY_PURPOSE_ENCRYPT, &[1u8; NONCE_LEN], b"alias", None);
        assert!(!enc.iter().any(|s| matches!(s, ParamSpec::Blob { tag, .. } if *tag == OH_HUKS_TAG_AE_TAG)));
    }

    #[test]
    fn error_classification_maps_documented_codes() {
        assert!(matches!(
            classify(OH_HUKS_ERR_CODE_ITEM_NOT_EXIST),
            SecureStoreError::Invalidated
        ));
        assert!(matches!(
            classify(OH_HUKS_ERR_CODE_KEY_AUTH_PERMANENTLY_INVALIDATED),
            SecureStoreError::Invalidated
        ));
        assert!(matches!(
            classify(OH_HUKS_ERR_CODE_KEY_AUTH_VERIFY_FAILED),
            SecureStoreError::Cancelled
        ));
        assert!(matches!(
            classify(OH_HUKS_ERR_CODE_CREDENTIAL_NOT_EXIST),
            SecureStoreError::Unavailable
        ));
        assert!(matches!(
            classify(OH_HUKS_ERR_CODE_DEVICE_PASSWORD_UNSET),
            SecureStoreError::Unavailable
        ));
        assert!(matches!(classify(42), SecureStoreError::Failed(_)));
    }

    #[test]
    fn tag_discriminators_match_vendored_reference() {
        // r2: capi-native-huks-type-h.md L451/L453/L454 — 3<<28 is ULONG
        // (L452), not BYTES; every BYTES tag rides 5<<28.
        assert_eq!(OH_HUKS_TAG_TYPE_UINT, 2 << 28);
        assert_eq!(OH_HUKS_TAG_TYPE_BOOL, 4 << 28);
        assert_eq!(OH_HUKS_TAG_TYPE_BYTES, 5 << 28);
        assert_eq!(OH_HUKS_TAG_ASSOCIATED_DATA, (5 << 28) | 8);
        assert_eq!(OH_HUKS_TAG_NONCE, (5 << 28) | 9);
        assert_eq!(OH_HUKS_TAG_AE_TAG, (5 << 28) | 10009);
        assert_eq!(OH_HUKS_TAG_IS_DEVICE_PASSWORD_SET, (4 << 28) | 1012);
        assert_eq!(OH_HUKS_TAG_KEY_OVERRIDE, (4 << 28) | 520);
        // UINT tags stay on 2<<28 (L451).
        assert_eq!(OH_HUKS_TAG_USER_AUTH_TYPE, (2 << 28) | 304);
    }

    #[test]
    fn error_codes_are_reference_values() {
        // r2: capi-native-huks-type-h.md L405-L425 — 8-digit codes.
        assert_eq!(OH_HUKS_SUCCESS, 0);
        assert_eq!(OH_HUKS_ERR_CODE_KEY_AUTH_PERMANENTLY_INVALIDATED, 12000007);
        assert_eq!(OH_HUKS_ERR_CODE_KEY_AUTH_VERIFY_FAILED, 12000008);
        assert_eq!(OH_HUKS_ERR_CODE_KEY_AUTH_TIME_OUT, 12000009);
        assert_eq!(OH_HUKS_ERR_CODE_ITEM_NOT_EXIST, 12000011);
        assert_eq!(OH_HUKS_ERR_CODE_CREDENTIAL_NOT_EXIST, 12000013);
        assert_eq!(OH_HUKS_ERR_CODE_DEVICE_PASSWORD_UNSET, 12000016);
        assert_eq!(OH_HUKS_ERR_CODE_KEY_ALREADY_EXIST, 12000017);
    }

    #[test]
    fn kek_access_controls_and_never_override_on_every_op() {
        // r2: the restriction set (ECE storage + password-required) must
        // ride on generation AND both session directions; generation must
        // never overwrite an existing alias.
        for tier in [KeyTier::DeviceUnlock, KeyTier::Biometric] {
            let gen = gen_key_params(tier);
            assert!(gen.contains(&ParamSpec::U32 {
                tag: OH_HUKS_TAG_AUTH_STORAGE_LEVEL,
                value: OH_HUKS_AUTH_STORAGE_LEVEL_ECE,
            }));
            assert!(gen.contains(&ParamSpec::Bool {
                tag: OH_HUKS_TAG_IS_DEVICE_PASSWORD_SET,
                value: true,
            }));
            assert!(gen.contains(&ParamSpec::Bool {
                tag: OH_HUKS_TAG_KEY_OVERRIDE,
                value: false,
            }));
            for purpose in [OH_HUKS_KEY_PURPOSE_ENCRYPT, OH_HUKS_KEY_PURPOSE_DECRYPT] {
                let sess = session_params(purpose, &[0u8; NONCE_LEN], b"a", None);
                assert!(sess.contains(&ParamSpec::U32 {
                    tag: OH_HUKS_TAG_AUTH_STORAGE_LEVEL,
                    value: OH_HUKS_AUTH_STORAGE_LEVEL_ECE,
                }));
                assert!(sess.contains(&ParamSpec::Bool {
                    tag: OH_HUKS_TAG_IS_DEVICE_PASSWORD_SET,
                    value: true,
                }));
            }
        }
    }

    #[test]
    fn delete_params_select_the_kek_storage_domain() {
        // r3: a null/empty delete param set selects the CE storage domain
        // (capi-native-huks-api-h.md L199; js-apis-huks.md deleteKeyItem
        // L361), so clear() must send the SAME storage-level tag/value the
        // KEK was generated with — otherwise the delete misses the ECE key
        // and ITEM_NOT_EXIST-as-idempotent hides the miss.
        assert_eq!(
            delete_key_params(),
            vec![ParamSpec::U32 {
                tag: OH_HUKS_TAG_AUTH_STORAGE_LEVEL,
                value: OH_HUKS_AUTH_STORAGE_LEVEL_ECE,
            }]
        );
        // Drift guard: the deletion selector equals the storage domain
        // every tier's generation (and, via push_kek_access_controls, both
        // session directions) actually selects.
        for tier in [KeyTier::DeviceUnlock, KeyTier::Biometric] {
            assert!(gen_key_params(tier).contains(&ParamSpec::U32 {
                tag: OH_HUKS_TAG_AUTH_STORAGE_LEVEL,
                value: kek_storage_level(),
            }));
        }
    }

    #[test]
    fn tier_availability_is_fail_loud() {
        let s = HuksSecureStore::new();
        // Biometric/DomainSso are hard-off everywhere (see available() doc).
        assert!(!s.available(KeyTier::Biometric));
        assert!(!s.available(KeyTier::DomainSso));
        // DeviceUnlock is true only where HUKS exists; the wrap path must
        // refuse with Unavailable (not fake a blob) wherever it is false.
        let avail = s.available(KeyTier::DeviceUnlock);
        assert_eq!(avail, cfg!(target_env = "ohos"));
        if !avail {
            let err = s.wrap("alias", &[0u8; 32], KeyTier::DeviceUnlock).unwrap_err();
            assert!(matches!(err, SecureStoreError::Unavailable));
        }
    }
}
