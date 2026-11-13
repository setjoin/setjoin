// clients/rust/guard-core/src/securestore/fake.rs
use super::{KeyTier, SecureStore, SecureStoreError};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// In-memory SecureStore for tests. The "wrap" is identity (stores the raw bytes
/// under the alias) — fidelity is in the lifecycle (tier availability / invalidate
/// / clear), which is what the core orchestration must handle.
pub struct FakeSecureStore {
    kek: Mutex<HashMap<String, [u8; 32]>>,
    unavailable: Mutex<HashSet<&'static str>>, // tiers made unavailable
    invalidated: Mutex<bool>,
}

impl FakeSecureStore {
    pub fn new() -> Self {
        Self {
            kek: Mutex::new(HashMap::new()),
            unavailable: Mutex::new(HashSet::new()),
            invalidated: Mutex::new(false),
        }
    }
    /// Toggle a tier's availability (e.g. no biometric enrolled).
    pub fn set_available(&self, tier: KeyTier, v: bool) {
        let mut u = self.unavailable.lock().unwrap();
        if v {
            u.remove(tier.as_tag());
        } else {
            u.insert(tier.as_tag());
        }
    }
    /// Simulate a biometric-set change: the stored KEK becomes permanently unusable.
    pub fn invalidate(&self) {
        *self.invalidated.lock().unwrap() = true;
    }
}

impl Default for FakeSecureStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureStore for FakeSecureStore {
    fn wrap(
        &self,
        alias: &str,
        key: &[u8; 32],
        tier: KeyTier,
    ) -> Result<Vec<u8>, SecureStoreError> {
        if !self.available(tier) {
            return Err(SecureStoreError::Unavailable);
        }
        self.kek.lock().unwrap().insert(alias.to_string(), *key);
        Ok(format!("fake:{}:{}", alias, tier.as_tag()).into_bytes())
    }
    fn unwrap(
        &self,
        alias: &str,
        _blob: &[u8],
        tier: KeyTier,
        _reason: &str,
    ) -> Result<[u8; 32], SecureStoreError> {
        if tier.prompts() && *self.invalidated.lock().unwrap() {
            return Err(SecureStoreError::Invalidated);
        }
        if !self.available(tier) {
            return Err(SecureStoreError::Unavailable);
        }
        self.kek
            .lock()
            .unwrap()
            .get(alias)
            .copied()
            .ok_or(SecureStoreError::Invalidated)
    }
    fn clear(&self, alias: &str) -> Result<(), SecureStoreError> {
        self.kek.lock().unwrap().remove(alias); // idempotent
        Ok(())
    }
    fn available(&self, tier: KeyTier) -> bool {
        !self.unavailable.lock().unwrap().contains(tier.as_tag())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrap_then_unwrap_roundtrips() {
        let s = FakeSecureStore::new();
        let k = [7u8; 32];
        let blob = s.wrap("v1", &k, KeyTier::DeviceUnlock).unwrap();
        assert_eq!(
            s.unwrap("v1", &blob, KeyTier::DeviceUnlock, "unlock")
                .unwrap(),
            k
        );
    }
    #[test]
    fn biometric_invalidate_makes_unwrap_fail() {
        let s = FakeSecureStore::new();
        let blob = s.wrap("v1", &[7u8; 32], KeyTier::Biometric).unwrap();
        s.invalidate();
        assert!(matches!(
            s.unwrap("v1", &blob, KeyTier::Biometric, "x"),
            Err(SecureStoreError::Invalidated)
        ));
    }
    #[test]
    fn device_tier_ignores_biometric_invalidation() {
        let s = FakeSecureStore::new();
        let blob = s.wrap("v1", &[7u8; 32], KeyTier::DeviceUnlock).unwrap();
        s.invalidate(); // biometric set changed — device tier unaffected
        assert!(s.unwrap("v1", &blob, KeyTier::DeviceUnlock, "x").is_ok());
    }
    #[test]
    fn unavailable_tier_errors() {
        let s = FakeSecureStore::new();
        s.set_available(KeyTier::Biometric, false);
        assert!(matches!(
            s.wrap("v1", &[0u8; 32], KeyTier::Biometric),
            Err(SecureStoreError::Unavailable)
        ));
    }
    #[test]
    fn clear_is_idempotent() {
        let s = FakeSecureStore::new();
        assert!(s.clear("absent").is_ok());
    }
}
