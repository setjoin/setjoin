// clients/rust/guard-core/src/securestore/mod.rs
//! Per-platform hardware key-custody abstraction for Model M (ARCH-016).
//! The vault key is a random 32-byte key wrapped here under a hardware KEK at a
//! chosen `KeyTier`. Real impls (Secure Enclave / Keychain / TPM-DPAPI /
//! Android Keystore / HUKS) land in P1–P4; `FakeSecureStore` (fake.rs) backs
//! the P0 core tests.

#[cfg(test)]
pub mod fake;

/// Secure Enclave backend (F10 iOS spike + F13/P2 macOS, consolidated F18).
/// Host build never sees this module on non-Apple targets — gated on the
/// target OS, not a feature flag, so it can't leak into the desktop/Android
/// builds by omission. iOS uses raw Core Foundation FFI for the keychain
/// access (see module doc); macOS uses the higher-level `security-framework`
/// builders; everything else (the `SecureStore` impl, ECIES wrap/unwrap, the
/// `LAContext` shim, error classification) is one shared copy.
#[cfg(any(target_os = "ios", target_os = "macos"))]
#[allow(dead_code)]
// consumed when AppleSecureStore is wired into the vault open path (P1 iOS / P2 macOS)
pub mod apple;
#[cfg(any(target_os = "ios", target_os = "macos"))]
#[allow(unused_imports)] // public API surface, consumed when wired in P1
pub use apple::AppleSecureStore;

/// How the OS keystore gates release of the wrapped vault key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyTier {
    /// Default, Outlook-style: released while the OS user is logged in / device
    /// unlocked. No prompt. (Keychain WhenUnlockedThisDeviceOnly / DPAPI user /
    /// Android Keystore no-auth.)
    DeviceUnlock,
    /// Opt-in app-lock (`feature.biometric_unlock`): release requires a biometric
    /// gesture. (Secure Enclave biometryCurrentSet / Android CryptoObject STRONG /
    /// Windows Hello-gated TPM.)
    Biometric,
    /// Opt-in on domain-joined Windows (`feature.windows_sso_unlock`): the KEK is
    /// TPM-bound to the Windows-Hello-for-Business / domain login — released on
    /// SSO with no prompt but cryptographically bound to the domain identity.
    DomainSso,
}

impl KeyTier {
    /// Persisted tag in `meta['kek_tier']` (plaintext — read before the key exists).
    pub fn as_tag(self) -> &'static str {
        match self {
            Self::DeviceUnlock => "device",
            Self::Biometric => "biometric",
            Self::DomainSso => "domain",
        }
    }
    pub fn from_tag(s: &str) -> Option<Self> {
        match s {
            "device" => Some(Self::DeviceUnlock),
            "biometric" => Some(Self::Biometric),
            "domain" => Some(Self::DomainSso),
            _ => None,
        }
    }
    /// Whether unwrap at this tier shows an interactive OS prompt.
    pub fn prompts(self) -> bool {
        matches!(self, Self::Biometric)
    }
}

/// A hardware-backed key-encryption store. `wrap` is the enrol side (no prompt);
/// `unwrap` prompts iff `tier.prompts()`.
pub trait SecureStore: Send + Sync {
    /// Wrap 32 bytes under a hardware KEK bound to `alias` at `tier`. No prompt.
    fn wrap(&self, alias: &str, key: &[u8; 32], tier: KeyTier)
        -> Result<Vec<u8>, SecureStoreError>;
    /// Unwrap the blob for `alias` at `tier` (`reason` shown iff the tier prompts).
    fn unwrap(
        &self,
        alias: &str,
        blob: &[u8],
        tier: KeyTier,
        reason: &str,
    ) -> Result<[u8; 32], SecureStoreError>;
    /// Delete the hardware KEK for `alias`. Idempotent: absent alias returns `Ok(())`.
    fn clear(&self, alias: &str) -> Result<(), SecureStoreError>;
    /// Whether the OS keystore can serve `tier` (e.g. Biometric needs enrolled biometrics).
    fn available(&self, tier: KeyTier) -> bool;
}

pub enum SecureStoreError {
    /// The requested tier is not usable (no biometric enrolled, no TPM, not domain-joined).
    Unavailable,
    /// User cancelled / dismissed the prompt.
    Cancelled,
    /// The KEK was invalidated (biometric set changed) — re-wrap required.
    Invalidated,
    /// Any other backend failure. MUST NOT contain key material.
    Failed(String),
}

// Display AND Debug are hand-written so NEITHER can print `Failed`'s inner string
// (a derived Debug would — and a backend might format key bytes into it). #12.
impl core::fmt::Display for SecureStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unavailable => write!(f, "secure store unavailable"),
            Self::Cancelled => write!(f, "unlock cancelled"),
            Self::Invalidated => write!(f, "secure store invalidated"),
            Self::Failed(_) => write!(f, "secure store backend error"), // never leak the inner string
        }
    }
}
impl core::fmt::Debug for SecureStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f) // Debug == Display: no inner string, ever
    }
}
