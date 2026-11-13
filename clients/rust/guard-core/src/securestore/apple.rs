// clients/rust/guard-core/src/securestore/apple.rs
//! F10 (iOS spike) + F13/P2 (macOS) — Apple `SecureStore` backend, Secure
//! Enclave-based, consolidated into one module (F18).
//!
//! Model M / design B: the Secure Enclave holds an EC P-256 keypair per alias
//! (it cannot store the raw 32-byte vault key directly). `wrap` ECIES-encrypts
//! the key under the SE public key (no prompt); `unwrap` decrypts with the SE
//! private key, which the OS gates on Face ID / Touch ID via the key's access
//! control (`biometryCurrentSet`).
//!
//! Everything in this file is shared between the two targets EXCEPT the SE
//! keychain access itself, which is isolated behind three cfg'd private
//! helpers (`find_private_key`, `generate_se_key`, `delete_se_key`) — the
//! `SecureStore` trait impl, the ECIES wrap/unwrap, the `LAContext` ObjC shim,
//! and the CFError -> `SecureStoreError` classification are one copy:
//!
//! - **iOS**: raw Core Foundation FFI. Why raw FFI instead of the vendored
//!   `security-framework` crate's convenience builder
//!   (`GenerateKeyOptions::to_dictionary()`): that helper only pushes the
//!   `kSecPrivateKeyAttrs` sub-dictionary (which carries `kSecAttrIsPermanent`
//!   + `kSecAttrAccessControl`) under `#[cfg(target_os = "macos")]` — see
//!   `clients/rust/refs/ios-security-framework/src/key.rs` around line 468.
//!   On iOS that whole block is compiled out, so a key built through it is
//!   neither permanent nor ACL-protected. Everything else in that crate
//!   (`SecKey`, `SecAccessControl`, `SecKeyCreateEncryptedData`/
//!   `SecKeyCreateDecryptedData` wrappers) is NOT gated and is reused below;
//!   only the attribute-dictionary construction and the keychain lookup are
//!   done by hand. This half is COMPILE-CHECKED ONLY (`aarch64-apple-ios` /
//!   `aarch64-apple-ios-sim`, real linking against the Security.framework /
//!   LocalAuthentication.framework in the Xcode SDK on this machine) — there
//!   is no Secure Enclave in CI or the Simulator, so no test here exercises
//!   real iOS hardware. See the device sign-off checklist in the F10 spike
//!   report.
//! - **macOS**: the higher-level `security-framework` crate throughout
//!   (`GenerateKeyOptions`/`ItemSearchOptions`) — on macOS the builder's
//!   `kSecPrivateKeyAttrs` push is NOT cfg'd away, so the safe API works.
//!   F7: macOS defaults to the legacy FILE keychain, which does not honour
//!   biometric ACLs the way the DATA-PROTECTION keychain does. Every keygen +
//!   search here forces `Location::DataProtectionKeychain` /
//!   `ignore_legacy_keychains()` (`kSecUseDataProtectionKeychain=true`) so the
//!   SE key actually lands where `biometryCurrentSet` release semantics
//!   apply. F7/F13 spike finding (confirmed empirically by the tests below):
//!   the DataProtectionKeychain requires the calling binary to be codesigned
//!   with a `keychain-access-groups` entitlement. An unsigned `cargo test`
//!   binary may be refused with `errSecMissingEntitlement`/
//!   `errSecNotAvailable`/`errSecInteractionNotAllowed`.
//!
//! F18: this used to be two files (`ios.rs` + `macos.rs`) with the ECIES
//! wrap/unwrap, the `LAContext` shim, and the error mapping duplicated
//! byte-for-byte. Folded into one module; only the keychain-access primitives
//! above stay `#[cfg]`'d per OS since their underlying mechanisms are
//! genuinely different (raw dictionary + `SecItemCopyMatching`/
//! `SecItemDelete` on iOS vs `ItemSearchOptions`/`SecKey::delete` on macOS).

use super::{KeyTier, SecureStore, SecureStoreError};
use core_foundation::error::CFError;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::key::{Algorithm, SecKey};
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage,
};
use security_framework_sys::base::{errSecAuthFailed, errSecItemNotFound};
use zeroize::Zeroize;

#[cfg(target_os = "ios")]
use core_foundation::base::{TCFType, ToVoid};
#[cfg(target_os = "ios")]
use core_foundation::boolean::CFBoolean;
#[cfg(target_os = "ios")]
use core_foundation::data::CFData;
#[cfg(target_os = "ios")]
use core_foundation::dictionary::CFMutableDictionary;
#[cfg(target_os = "ios")]
use core_foundation::number::CFNumber;
#[cfg(target_os = "ios")]
use core_foundation_sys::base::CFTypeRef;
#[cfg(target_os = "ios")]
use core_foundation_sys::string::CFStringRef;
#[cfg(target_os = "ios")]
use security_framework_sys::base::SecKeyRef;
#[cfg(target_os = "ios")]
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyClassPrivate,
    kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID,
    kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey, kSecPrivateKeyAttrs, kSecReturnRef,
    kSecUseAuthenticationContext,
};
#[cfg(target_os = "ios")]
use security_framework_sys::key::SecKeyCreateRandomKey;
#[cfg(target_os = "ios")]
use security_framework_sys::keychain_item::{SecItemCopyMatching, SecItemDelete};
#[cfg(target_os = "ios")]
use std::os::raw::c_void;
#[cfg(target_os = "ios")]
use std::ptr;

#[cfg(target_os = "macos")]
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Limit, Location, Reference, SearchResult,
};
#[cfg(target_os = "macos")]
use security_framework::key::{GenerateKeyOptions, KeyType, Token};

// security-framework-sys's build script already emits `-framework Security`.
// LocalAuthentication is never called through a `-sys` binding here (we talk
// to it purely via the ObjC runtime — see `mod la`), so nothing forces the
// linker to pull it in on its own; without this, `objc_getClass("LAContext")`
// would compile fine but resolve to NULL at runtime because the framework
// image was never loaded. Link it explicitly.
#[link(name = "LocalAuthentication", kind = "framework")]
extern "C" {}

// ---------------------------------------------------------------------------
// Symbols the vendored `security-framework-sys` 2.17 does not expose on iOS.
// Verified present + linkable against the real SDK on this machine:
//   $(xcrun --sdk iphoneos --show-sdk-path)/.../Security.framework/Headers/SecItem.h
// kSecAttrApplicationTag: available since iOS 2.0, never deprecated.
// kSecMatchLimitOne: available since iOS 2.0, never deprecated.
// ---------------------------------------------------------------------------
#[cfg(target_os = "ios")]
extern "C" {
    static kSecAttrApplicationTag: CFStringRef;
    static kSecMatchLimit: CFStringRef;
    static kSecMatchLimitOne: CFStringRef;
}

/// `errSecUserCanceled` (a.k.a. classic `userCanceledErr`) — not in the sys
/// crate's `errSec*` const list; it's a plain `OSStatus` value (-128), stable
/// since Carbon, no `extern` needed.
const ERR_SEC_USER_CANCELED: i32 = -128;

/// F7 entitlement-wall probe constants (not in `security-framework-sys`'s
/// `errSec*` list). Documented Apple `SecBase.h` values:
/// `errSecMissingEntitlement` = -34018 (binary lacks the required
/// entitlement); `errSecNotAvailable` = -25291 ("No keychain is available");
/// `errSecInteractionNotAllowed` = -25308. Any of these on an unsigned
/// `cargo test` binary confirms the F7/F13 codesign gate. macOS-only: this is
/// the DataProtectionKeychain entitlement wall the macOS test probes; not
/// applicable to iOS, which is always DataProtectionKeychain.
#[cfg(target_os = "macos")]
#[allow(dead_code)]
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;
#[cfg(target_os = "macos")]
#[allow(dead_code)]
const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
#[cfg(target_os = "macos")]
#[allow(dead_code)]
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

const ALGO: Algorithm = Algorithm::ECIESEncryptionCofactorX963SHA256AESGCM;

/// Apple (iOS + macOS) `SecureStore`: Secure Enclave-backed for
/// `KeyTier::Biometric`. `DeviceUnlock`/`DomainSso` are out of scope for this
/// spike (see module docs on the `wrap`/`unwrap` impls below).
pub struct AppleSecureStore;

impl AppleSecureStore {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AppleSecureStore {
    fn default() -> Self {
        Self::new()
    }
}

// --- raw ObjC runtime shim for LAContext -----------------------------------
// LocalAuthentication has no C API; `LAContext` is Objective-C-only. Rather
// than pull in an `objc`/`objc2` dependency for two selectors, this hand-rolls
// the message send (the same technique those crates use internally): declare
// `objc_msgSend` with no signature, then `transmute` it to the exact call
// shape needed at each site. This is the standard, if blunt, raw-FFI idiom for
// talking to Objective-C from C-level bindings. Identical on iOS and macOS —
// LocalAuthentication is Objective-C on both, and the LAPolicy value for
// biometrics is the same constant.
mod la {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_void};

    #[allow(non_camel_case_types)]
    type Id = *mut c_void;
    #[allow(non_camel_case_types)]
    type Sel = *mut c_void;

    extern "C" {
        fn objc_getClass(name: *const c_char) -> Id;
        fn sel_registerName(name: *const c_char) -> Sel;
        fn objc_msgSend();
    }

    /// `LAPolicyDeviceOwnerAuthenticationWithBiometrics` (LAPublicDefines.h: `1`).
    const LA_POLICY_BIOMETRICS: i64 = 1;

    unsafe fn send_id(recv: Id, sel: Sel) -> Id {
        let f: unsafe extern "C" fn(Id, Sel) -> Id =
            std::mem::transmute(objc_msgSend as *const c_void);
        f(recv, sel)
    }
    unsafe fn send_id_ptr(recv: Id, sel: Sel, arg: *const c_char) -> Id {
        let f: unsafe extern "C" fn(Id, Sel, *const c_char) -> Id =
            std::mem::transmute(objc_msgSend as *const c_void);
        f(recv, sel, arg)
    }
    unsafe fn send_id_id(recv: Id, sel: Sel, arg: Id) -> Id {
        let f: unsafe extern "C" fn(Id, Sel, Id) -> Id =
            std::mem::transmute(objc_msgSend as *const c_void);
        f(recv, sel, arg)
    }
    /// `canEvaluatePolicy:error:` — `-(BOOL)canEvaluatePolicy:(NSInteger)policy
    /// error:(NSError **)error`. BOOL is `bool` (1 byte) on the arm64 ABI.
    unsafe fn send_can_evaluate(recv: Id, sel: Sel, policy: i64, err_out: *mut Id) -> bool {
        let f: unsafe extern "C" fn(Id, Sel, i64, *mut Id) -> u8 =
            std::mem::transmute(objc_msgSend as *const c_void);
        f(recv, sel, policy, err_out) != 0
    }

    /// A live `LAContext*`, optionally carrying a custom prompt reason.
    /// SPIKE-TODO(device): retain/release is manual (no ARC in a cdylib built
    /// this way); this type's `Drop` releases exactly the one reference it
    /// owns (`alloc`+`init` returns +1). Never verified against the real
    /// runtime — only symbol/selector shape is checked here.
    pub struct LaContext(Id);

    impl LaContext {
        pub fn new() -> Option<Self> {
            unsafe {
                let cls_name = CString::new("LAContext").ok()?;
                let cls = objc_getClass(cls_name.as_ptr());
                if cls.is_null() {
                    return None;
                }
                let alloc_sel = sel_registerName(CString::new("alloc").ok()?.as_ptr());
                let init_sel = sel_registerName(CString::new("init").ok()?.as_ptr());
                let obj = send_id(cls, alloc_sel);
                if obj.is_null() {
                    return None;
                }
                let obj = send_id(obj, init_sel);
                if obj.is_null() {
                    None
                } else {
                    Some(Self(obj))
                }
            }
        }

        /// `self.localizedReason = reason` — customizes the biometric sheet text.
        pub fn set_localized_reason(&self, reason: &str) {
            unsafe {
                let ns_string_cls_name = match CString::new("NSString") {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let ns_string_cls = objc_getClass(ns_string_cls_name.as_ptr());
                let from_utf8_sel = match CString::new("stringWithUTF8String:") {
                    Ok(v) => sel_registerName(v.as_ptr()),
                    Err(_) => return,
                };
                let reason_c = match CString::new(reason) {
                    Ok(v) => v,
                    Err(_) => return, // embedded NUL: skip the custom prompt, keep the OS default
                };
                let ns_reason = send_id_ptr(ns_string_cls, from_utf8_sel, reason_c.as_ptr());
                if ns_reason.is_null() {
                    return;
                }
                let setter_sel = match CString::new("setLocalizedReason:") {
                    Ok(v) => sel_registerName(v.as_ptr()),
                    Err(_) => return,
                };
                let _ = send_id_id(self.0, setter_sel, ns_reason);
            }
        }

        /// `canEvaluatePolicy:error:` for `.DeviceOwnerAuthenticationWithBiometrics`.
        pub fn can_evaluate_biometrics(&self) -> bool {
            unsafe {
                let sel_name = match CString::new("canEvaluatePolicy:error:") {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                let sel = sel_registerName(sel_name.as_ptr());
                let mut err: Id = std::ptr::null_mut();
                send_can_evaluate(self.0, sel, LA_POLICY_BIOMETRICS, &mut err)
            }
        }

        /// Raw object pointer, for embedding as a keychain query/search
        /// authentication context (NSObject<->CFTypeRef is toll-free bridged,
        /// so this is a legitimate `CFTypeRef`). `*mut c_void` matches
        /// `security_framework::item::ItemSearchOptions::authentication_context`'s
        /// parameter type directly (macOS); the iOS raw-dictionary call site
        /// casts to `*const c_void` for its `CFMutableDictionary` pairs.
        pub fn as_cftype_ptr(&self) -> *mut c_void {
            self.0
        }
    }

    impl Drop for LaContext {
        fn drop(&mut self) {
            unsafe {
                if let Ok(sel_name) = CString::new("release") {
                    let sel = sel_registerName(sel_name.as_ptr());
                    let _ = send_id(self.0, sel);
                }
            }
        }
    }
}

// --- per-OS keychain access --------------------------------------------------
// The only genuinely platform-specific code: iOS builds its keychain queries
// as a raw CFDictionary (see the module doc), macOS goes through the
// higher-level `security-framework` item/key builders. Both sides expose the
// same signatures so `wrap`/`unwrap`/`clear` below are one shared copy.

/// Builds the query dict to look up the SE-resident private key for `alias`.
/// Fetching a *reference* never authenticates — only using the key for
/// sign/decrypt does — so this is safe to call from `wrap` (no-prompt path).
#[cfg(target_os = "ios")]
fn find_query(alias: &str, ctx: Option<&la::LaContext>) -> CFMutableDictionary {
    let tag = CFData::from_buffer(alias.as_bytes());
    let mut pairs: Vec<(*const c_void, *const c_void)> = vec![
        (
            unsafe { kSecClass }.to_void(),
            unsafe { kSecClassKey }.to_void(),
        ),
        (
            unsafe { kSecAttrKeyType }.to_void(),
            unsafe { kSecAttrKeyTypeECSECPrimeRandom }.to_void(),
        ),
        (
            unsafe { kSecAttrKeyClass }.to_void(),
            unsafe { kSecAttrKeyClassPrivate }.to_void(),
        ),
        (unsafe { kSecAttrApplicationTag }.to_void(), tag.to_void()),
        (
            unsafe { kSecReturnRef }.to_void(),
            CFBoolean::true_value().to_void(),
        ),
        (
            unsafe { kSecMatchLimit }.to_void(),
            unsafe { kSecMatchLimitOne }.to_void(),
        ),
    ];
    if let Some(ctx) = ctx {
        // Attaching the (reason-bearing) LAContext to the *fetch* query is the
        // documented way to have its `localizedReason` shown when the
        // returned key is later used (kSecUseOperationPrompt's replacement).
        pairs.push((
            unsafe { kSecUseAuthenticationContext }.to_void(),
            ctx.as_cftype_ptr() as *const c_void,
        ));
    }
    // `tag` must outlive the CFDictionaryCreate call inside from_CFType_pairs;
    // it does, since `pairs` (built from it) is consumed synchronously below
    // and CFDictionaryCreate retains its values.
    CFMutableDictionary::from_CFType_pairs(&pairs)
}

#[cfg(target_os = "ios")]
fn find_private_key(
    alias: &str,
    ctx: Option<&la::LaContext>,
) -> Result<Option<SecKey>, SecureStoreError> {
    let query = find_query(alias, ctx);
    let mut result: CFTypeRef = ptr::null();
    let status =
        unsafe { SecItemCopyMatching(query.to_immutable().as_concrete_TypeRef(), &mut result) };
    if status == security_framework_sys::base::errSecSuccess {
        if result.is_null() {
            return Ok(None);
        }
        // Create-rule: SecItemCopyMatching's kSecReturnRef result is +1 owned.
        Ok(Some(unsafe {
            SecKey::wrap_under_create_rule(result as SecKeyRef)
        }))
    } else if status == errSecItemNotFound {
        Ok(None)
    } else {
        Err(SecureStoreError::Failed("keychain lookup failed".into()))
    }
}

/// Looks up the SE-resident private key labelled `alias` in the
/// DataProtectionKeychain. Fetching a *reference* never authenticates — only
/// using the key for decrypt does — so this is safe to call from `wrap`
/// (no-prompt path) with `ctx: None`.
#[cfg(target_os = "macos")]
fn find_private_key(
    alias: &str,
    ctx: Option<&la::LaContext>,
) -> Result<Option<SecKey>, SecureStoreError> {
    let mut opts = ItemSearchOptions::new();
    opts.class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(alias)
        .load_refs(true)
        .limit(Limit::Max(1))
        .ignore_legacy_keychains();
    if let Some(ctx) = ctx {
        // Attaching the (reason-bearing) LAContext to the *fetch* is the
        // documented way to have its `localizedReason` shown when the
        // returned key is later used for decrypt.
        #[allow(deprecated)]
        unsafe {
            opts.authentication_context(ctx.as_cftype_ptr());
        }
    }
    match opts.search() {
        Ok(results) => {
            for r in results {
                if let SearchResult::Ref(Reference::Key(k)) = r {
                    return Ok(Some(k));
                }
            }
            Ok(None)
        }
        Err(e) if e.code() == security_framework_sys::base::errSecItemNotFound => Ok(None),
        Err(_) => Err(SecureStoreError::Failed("keychain lookup failed".into())),
    }
}

/// Raw CFDictionary for `SecKeyCreateRandomKey` — built by hand (not via the
/// vendored crate's `GenerateKeyOptions::to_dictionary()`, see module docs).
#[cfg(target_os = "ios")]
fn generate_se_key(alias: &str) -> Result<SecKey, SecureStoreError> {
    let access = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        kSecAccessControlBiometryCurrentSet | kSecAccessControlPrivateKeyUsage,
    )
    .map_err(|_| SecureStoreError::Failed("access control create failed".into()))?;

    let tag = CFData::from_buffer(alias.as_bytes());
    let priv_attrs = CFMutableDictionary::from_CFType_pairs(&[
        (
            unsafe { kSecAttrIsPermanent }.to_void(),
            CFBoolean::true_value().to_void(),
        ),
        (unsafe { kSecAttrApplicationTag }.to_void(), tag.to_void()),
        (unsafe { kSecAttrAccessControl }.to_void(), access.to_void()),
    ]);

    let size = CFNumber::from(256i32);
    let top = CFMutableDictionary::from_CFType_pairs(&[
        (
            unsafe { kSecAttrKeyType }.to_void(),
            unsafe { kSecAttrKeyTypeECSECPrimeRandom }.to_void(),
        ),
        (unsafe { kSecAttrKeySizeInBits }.to_void(), size.to_void()),
        (
            unsafe { kSecAttrTokenID }.to_void(),
            unsafe { kSecAttrTokenIDSecureEnclave }.to_void(),
        ),
        (
            unsafe { kSecPrivateKeyAttrs }.to_void(),
            priv_attrs.to_void(),
        ),
    ]);

    let mut error: core_foundation_sys::error::CFErrorRef = ptr::null_mut();
    let key_ref =
        unsafe { SecKeyCreateRandomKey(top.to_immutable().as_concrete_TypeRef(), &mut error) };
    if !error.is_null() {
        let _ = unsafe { CFError::wrap_under_create_rule(error) }; // dropped: no key material in it, just don't leak text
        return Err(SecureStoreError::Failed(
            "Secure Enclave keygen failed".into(),
        ));
    }
    Ok(unsafe { SecKey::wrap_under_create_rule(key_ref) })
}

/// Generates (does not look up) a fresh SE keypair labelled `alias` in the
/// DataProtectionKeychain, ACL'd to `biometryCurrentSet | privateKeyUsage`.
/// Returns the raw `CFError` (rather than `SecureStoreError`) so callers —
/// notably the entitlement-wall test below — can inspect the exact
/// `OSStatus`; production callers go through `generate_se_key` (below), which
/// maps it.
#[cfg(target_os = "macos")]
fn generate_se_key_raw(alias: &str) -> Result<SecKey, CFError> {
    // `create_with_protection` only builds an in-memory CFDictionary flags
    // object — it never touches the keychain/Secure Enclave, so it can't hit
    // the F7 entitlement wall. Failure here would mean the static flag
    // combination below is invalid, which is a coding-time invariant, not a
    // hardware/entitlement condition — hence `expect`, not another `Result`
    // arm that would blur the two failure classes together for the caller.
    let access = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        kSecAccessControlBiometryCurrentSet | kSecAccessControlPrivateKeyUsage,
    )
    .expect("static access-control flags must be valid");

    // `GenerateKeyOptions` defaults `key_type` to RSA when unset, and
    // RSA + `Token::SecureEnclave` is invalid (the SE only holds EC P-256
    // keys) — omitting this line is what produced the misleading generic
    // errSecParam(-50) during the spike, masking the real entitlement-wall
    // status the raw-FFI probe below uncovered.
    let mut opts = GenerateKeyOptions::default();
    #[allow(deprecated)]
    opts.set_key_type(KeyType::ec_sec_prime_random())
        .set_token(Token::SecureEnclave)
        .set_location(Location::DataProtectionKeychain)
        .set_label(alias)
        .set_access_control(access);
    SecKey::new(&opts)
}

/// Production entry point: `generate_se_key_raw` + error classification. Kept
/// as a thin wrapper (rather than folding the mapping into `wrap()`) so the
/// iOS and macOS sides present the identical `Result<SecKey, SecureStoreError>`
/// signature to the shared `SecureStore::wrap` impl below.
#[cfg(target_os = "macos")]
fn generate_se_key(alias: &str) -> Result<SecKey, SecureStoreError> {
    generate_se_key_raw(alias).map_err(classify_keygen_error)
}

#[cfg(target_os = "macos")]
fn classify_keygen_error(_err: CFError) -> SecureStoreError {
    // Never leak the CFError's text (may echo back attributes); see #12 /
    // SecureStoreError::Failed's contract. The exact OSStatus is only
    // surfaced to the direct `generate_se_key_raw` probe in tests, not
    // through the trait.
    SecureStoreError::Failed("Secure Enclave keygen failed".into())
}

/// Deletes the SE-resident key for `alias`. Idempotent: absent alias is `Ok`.
/// iOS deletes by re-issuing the tag-scoped query against `SecItemDelete`;
/// macOS looks the key up (label-scoped, DataProtectionKeychain) and calls
/// `SecKey::delete` on the result — same effect, different underlying API
/// shape, so kept as the one remaining OS split alongside keygen/lookup.
#[cfg(target_os = "ios")]
fn delete_se_key(alias: &str) -> Result<(), SecureStoreError> {
    let tag = CFData::from_buffer(alias.as_bytes());
    let query = CFMutableDictionary::from_CFType_pairs(&[
        (
            unsafe { kSecClass }.to_void(),
            unsafe { kSecClassKey }.to_void(),
        ),
        (
            unsafe { kSecAttrKeyType }.to_void(),
            unsafe { kSecAttrKeyTypeECSECPrimeRandom }.to_void(),
        ),
        (unsafe { kSecAttrApplicationTag }.to_void(), tag.to_void()),
    ]);
    let status = unsafe { SecItemDelete(query.to_immutable().as_concrete_TypeRef()) };
    if status == security_framework_sys::base::errSecSuccess || status == errSecItemNotFound {
        Ok(())
    } else {
        Err(SecureStoreError::Failed("keychain delete failed".into()))
    }
}

#[cfg(target_os = "macos")]
fn delete_se_key(alias: &str) -> Result<(), SecureStoreError> {
    match find_private_key(alias, None)? {
        None => Ok(()), // idempotent: nothing to delete
        Some(key) => key
            .delete()
            .map_err(|_| SecureStoreError::Failed("keychain delete failed".into())),
    }
}

fn classify_cferror(err: CFError) -> SecureStoreError {
    match err.code() as i32 {
        ERR_SEC_USER_CANCELED => SecureStoreError::Cancelled,
        c if c == errSecAuthFailed => SecureStoreError::Invalidated,
        c if c == errSecItemNotFound => SecureStoreError::Invalidated,
        _ => SecureStoreError::Failed("Secure Enclave operation failed".into()),
    }
}

impl SecureStore for AppleSecureStore {
    fn wrap(
        &self,
        alias: &str,
        key: &[u8; 32],
        tier: KeyTier,
    ) -> Result<Vec<u8>, SecureStoreError> {
        if !matches!(tier, KeyTier::Biometric) {
            // SPIKE-TODO(device): DeviceUnlock (frictionless Keychain tier, no
            // SE key) and DomainSso (not applicable on Apple platforms) are
            // out of scope for this spike — only the Biometric/SE path is
            // implemented.
            return Err(SecureStoreError::Unavailable);
        }
        let existing = find_private_key(alias, None)?;
        let priv_key = match existing {
            Some(k) => k,
            None => generate_se_key(alias)?,
        };
        let pub_key = priv_key.public_key().ok_or_else(|| {
            SecureStoreError::Failed("no public key for Secure Enclave keypair".into())
        })?;
        let blob = pub_key
            .encrypt_data(ALGO, key)
            .map_err(|_| SecureStoreError::Failed("ECIES wrap failed".into()))?;
        Ok(blob)
    }

    fn unwrap(
        &self,
        alias: &str,
        blob: &[u8],
        tier: KeyTier,
        reason: &str,
    ) -> Result<[u8; 32], SecureStoreError> {
        if !matches!(tier, KeyTier::Biometric) {
            return Err(SecureStoreError::Unavailable);
        }
        let ctx = la::LaContext::new();
        if let Some(ctx) = &ctx {
            ctx.set_localized_reason(reason);
        }
        // SPIKE-TODO(device): if `ctx` is None (LAContext alloc/init failed —
        // shouldn't happen on real hardware), we still attempt the fetch
        // without a custom reason rather than failing outright; the OS falls
        // back to a generic prompt string.
        let priv_key = match find_private_key(alias, ctx.as_ref())? {
            Some(k) => k,
            None => return Err(SecureStoreError::Invalidated),
        };
        let mut plain = priv_key
            .decrypt_data(ALGO, blob)
            .map_err(classify_cferror)?;
        if plain.len() != 32 {
            plain.zeroize();
            return Err(SecureStoreError::Failed("unexpected unwrap length".into()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&plain);
        plain.zeroize();
        Ok(out)
    }

    fn clear(&self, alias: &str) -> Result<(), SecureStoreError> {
        delete_se_key(alias)
    }

    fn available(&self, tier: KeyTier) -> bool {
        match tier {
            // ponytail: DeviceUnlock is the frictionless Keychain tier —
            // always true; refine if/when that tier is wired up.
            KeyTier::DeviceUnlock => true,
            KeyTier::Biometric => la::LaContext::new()
                .map(|c| c.can_evaluate_biometrics())
                .unwrap_or(false),
            KeyTier::DomainSso => false, // Windows-only concept, N/A on Apple platforms
        }
    }
}

// Tests below exercise the real Secure Enclave / DataProtectionKeychain and
// were only ever validated on macOS (Touch ID + a real Secure Enclave on this
// machine); iOS has no Secure Enclave in CI or the Simulator (see module
// docs), so — same as before the F18 merge — no test attempts to run there.
#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// Per-test-run alias so repeated `cargo test` invocations don't collide
    /// with a leftover SE key from a previous run on this machine.
    fn test_alias(name: &str) -> String {
        format!("setjoin.guard-core.test.{name}.{}", std::process::id())
    }

    // --- non-interactive: safe to run headless, never prompts -------------

    #[test]
    fn available_device_unlock_is_always_true() {
        let store = AppleSecureStore::new();
        assert!(store.available(KeyTier::DeviceUnlock));
    }

    #[test]
    fn available_domain_sso_is_false_on_macos() {
        let store = AppleSecureStore::new();
        assert!(!store.available(KeyTier::DomainSso));
    }

    #[test]
    fn available_biometric_reflects_real_touch_id_enrollment() {
        // This machine has Touch ID + a real Secure Enclave (per the task
        // brief), so on real hardware this should be true. Printed either way
        // so a future run against different hardware documents itself.
        let store = AppleSecureStore::new();
        let avail = store.available(KeyTier::Biometric);
        eprintln!("[macos SE] available(Biometric) = {avail}");
    }

    #[test]
    fn wrap_non_biometric_tier_is_unavailable() {
        let store = AppleSecureStore::new();
        let key = [1u8; 32];
        let err = store
            .wrap("unused-alias", &key, KeyTier::DeviceUnlock)
            .unwrap_err();
        assert!(matches!(err, SecureStoreError::Unavailable));
    }

    #[test]
    fn clear_of_absent_alias_is_ok() {
        let store = AppleSecureStore::new();
        let alias = test_alias("absent");
        assert!(store.clear(&alias).is_ok());
    }

    /// THE spike result: does an unsigned `cargo test` binary get to create a
    /// Secure Enclave key in the DataProtectionKeychain at all? Either
    /// outcome is valid and asserted precisely — see the module doc for the
    /// F7/F13 background. Never calls `unwrap` (no prompt).
    #[test]
    fn keygen_wrap_and_clear_unsigned_hardware_probe() {
        let alias = test_alias("keygen-probe");
        let store = AppleSecureStore::new();
        let _ = store.clear(&alias); // clean slate from a prior failed run

        match generate_se_key_raw(&alias) {
            Ok(priv_key) => {
                eprintln!("[macos SE] unsigned keygen SUCCEEDED for alias {alias:?}");
                // Prove it's a real, usable SE key: derive the public key and
                // ECIES-wrap a vault key with it (no prompt — encrypt only).
                let pub_key = priv_key
                    .public_key()
                    .expect("SE keypair must expose a public key");
                let vault_key = [9u8; 32];
                let blob = pub_key
                    .encrypt_data(ALGO, &vault_key)
                    .expect("ECIES wrap with the fresh SE public key must succeed");
                assert!(!blob.is_empty());

                // wrap() through the trait should now find the just-created
                // key rather than generating a second one, and clear() must
                // remove it.
                let blob2 = store
                    .wrap(&alias, &vault_key, KeyTier::Biometric)
                    .expect("wrap() should reuse the existing SE key");
                assert!(!blob2.is_empty());
                store
                    .clear(&alias)
                    .expect("clear() must succeed after keygen");
                assert!(
                    matches!(find_private_key(&alias, None), Ok(None)),
                    "key must be gone after clear()"
                );
            }
            Err(e) => {
                let code = e.code() as i32;
                eprintln!(
                    "[macos SE] unsigned keygen FAILED: OSStatus {code} ({})",
                    e.description()
                );
                // Document the *exact* failure rather than leaving this red:
                // an unsigned test binary hitting the DataProtectionKeychain
                // entitlement wall must land on one of these three known
                // codes (F7/F13). Any other code is a genuinely new failure
                // mode worth investigating, so it still fails the test.
                assert!(
                    matches!(
                        code,
                        ERR_SEC_MISSING_ENTITLEMENT | ERR_SEC_NOT_AVAILABLE | ERR_SEC_INTERACTION_NOT_ALLOWED
                    ),
                    "unexpected OSStatus {code} from unsigned SE keygen (not a known entitlement-wall code)"
                );
            }
        }
    }

    /// Independent cross-check for `keygen_wrap_and_clear_unsigned_hardware_probe`:
    /// bypasses `GenerateKeyOptions` and builds the raw CFDictionary by hand
    /// (the iOS side's technique + the macOS-only `kSecUseDataProtectionKeychain`
    /// flag). Confirms the OS-level result (entitlement wall or success) is
    /// real and not an artifact of how the higher-level builder assembles its
    /// dictionary — this is how a first pass caught a missing
    /// `set_key_type(ec_sec_prime_random)` (defaulted to RSA, which the
    /// Secure Enclave rejects with a generic errSecParam(-50) that masked the
    /// actual entitlement status).
    #[test]
    fn raw_ffi_keygen_probe() {
        use core_foundation::base::{TCFType, ToVoid};
        use core_foundation::boolean::CFBoolean;
        use core_foundation::dictionary::CFMutableDictionary;
        use core_foundation::number::CFNumber;
        use security_framework_sys::item::{
            kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeySizeInBits, kSecAttrKeyType,
            kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel, kSecAttrTokenID,
            kSecAttrTokenIDSecureEnclave, kSecPrivateKeyAttrs, kSecUseDataProtectionKeychain,
        };
        use security_framework_sys::key::SecKeyCreateRandomKey;

        let alias = test_alias("raw-ffi-probe");
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
            kSecAccessControlBiometryCurrentSet | kSecAccessControlPrivateKeyUsage,
        )
        .expect("static flags valid");

        let label = core_foundation::string::CFString::new(&alias);
        let priv_attrs = CFMutableDictionary::from_CFType_pairs(&[
            (
                unsafe { kSecAttrIsPermanent }.to_void(),
                CFBoolean::true_value().to_void(),
            ),
            (unsafe { kSecAttrAccessControl }.to_void(), access.to_void()),
        ]);
        let size = CFNumber::from(256i32);
        let top = CFMutableDictionary::from_CFType_pairs(&[
            (
                unsafe { kSecAttrKeyType }.to_void(),
                unsafe { kSecAttrKeyTypeECSECPrimeRandom }.to_void(),
            ),
            (unsafe { kSecAttrKeySizeInBits }.to_void(), size.to_void()),
            (
                unsafe { kSecAttrTokenID }.to_void(),
                unsafe { kSecAttrTokenIDSecureEnclave }.to_void(),
            ),
            (unsafe { kSecAttrLabel }.to_void(), label.to_void()),
            (
                unsafe { kSecUseDataProtectionKeychain }.to_void(),
                CFBoolean::true_value().to_void(),
            ),
            (
                unsafe { kSecPrivateKeyAttrs }.to_void(),
                priv_attrs.to_void(),
            ),
        ]);
        let mut error: core_foundation_sys::error::CFErrorRef = std::ptr::null_mut();
        let key_ref =
            unsafe { SecKeyCreateRandomKey(top.to_immutable().as_concrete_TypeRef(), &mut error) };
        if error.is_null() {
            eprintln!("[macos SE raw-ffi probe] SUCCEEDED");
            let key = unsafe { SecKey::wrap_under_create_rule(key_ref) };
            let _ = key.delete();
        } else {
            let e = unsafe { CFError::wrap_under_create_rule(error) };
            eprintln!(
                "[macos SE raw-ffi probe] FAILED: OSStatus {} ({})",
                e.code(),
                e.description()
            );
        }
    }

    // --- interactive: DO NOT run in CI/headless, prompts Touch ID ----------

    /// manual: needs a human Touch ID touch. Only runs with
    /// `cargo test -- --ignored`; asserts the full wrap->unwrap round trip.
    #[test]
    #[ignore = "manual: needs a human Touch ID touch"]
    fn wrap_then_unwrap_round_trip_prompts_touch_id() {
        let store = AppleSecureStore::new();
        let alias = test_alias("roundtrip");
        let _ = store.clear(&alias);
        let key = [42u8; 32];

        let blob = store
            .wrap(&alias, &key, KeyTier::Biometric)
            .expect("wrap should not prompt");
        let recovered = store
            .unwrap(
                &alias,
                &blob,
                KeyTier::Biometric,
                "setjoin: unlock your vault (P2 manual test)",
            )
            .expect("unwrap should succeed after a real Touch ID touch");
        assert_eq!(recovered, key);
        store.clear(&alias).expect("clear should succeed");
    }
}
