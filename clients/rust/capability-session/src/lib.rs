//! Native capability session authority shared by desktop and Harmony adapters.
//!
//! The session owns the security guard and the lazily-created offline engine.
//! Runtime adapters supply paths and marshal errors; keys never cross this API.

use guard_core::GuardCore;
use offline_core::OfflineCore;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("vault locked")]
    Locked,
    #[error(transparent)]
    Guard(#[from] guard_core::GuardError),
    #[error(transparent)]
    Offline(#[from] offline_core::OfflineError),
}

/// Normalize the bridge's intentionally small crypto-profile vocabulary.
/// Unknown profiles pass through so `OfflineCore` remains the cipher authority.
pub fn normalize_profile(profile: Option<&str>) -> String {
    match profile.unwrap_or_default() {
        "" => "standard".into(),
        "SMx" => "smx".into(),
        value => value.into(),
    }
}

#[derive(Default)]
pub struct CapabilitySession {
    guard: Option<Arc<GuardCore>>,
    offline: Option<Arc<OfflineCore>>,
}

impl CapabilitySession {
    /// Unlock replaces the complete capability generation. A failed attempt is
    /// fail-closed and cannot leave an older unlocked core reachable.
    pub fn unlock(&mut self, db_path: String, passphrase: String) -> bool {
        self.offline = None;
        self.guard = None;
        match GuardCore::new(db_path, passphrase) {
            Ok(core) => {
                self.guard = Some(core);
                true
            }
            Err(_) => false,
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.guard.is_some()
    }

    /// Trusted native capabilities such as TOTP, push, and MAM may borrow the
    /// guard without receiving any key material.
    pub fn guard_core(&self) -> Result<Arc<GuardCore>, SessionError> {
        self.guard.clone().ok_or(SessionError::Locked)
    }

    /// Null form used only by operations whose established locked contract is
    /// an absent result rather than an exception.
    pub fn guard_core_if_unlocked(&self) -> Option<Arc<GuardCore>> {
        self.guard.clone()
    }

    pub fn offline_core(&mut self) -> Result<Arc<OfflineCore>, SessionError> {
        if let Some(core) = &self.offline {
            return Ok(core.clone());
        }
        let guard = self.guard_core()?;
        let core = OfflineCore::new(guard);
        self.offline = Some(core.clone());
        Ok(core)
    }

    pub fn secure_get(&self, key: String) -> Result<Option<String>, SessionError> {
        let Some(core) = self.guard_core_if_unlocked() else {
            return Ok(None);
        };
        core.meta_get(key).map_err(SessionError::Guard)
    }

    pub fn secure_set(&self, key: String, value: String) -> Result<(), SessionError> {
        self.guard_core()?
            .meta_set(key, value)
            .map_err(SessionError::Guard)
    }

    pub fn secure_remove(&self, key: String) -> Result<(), SessionError> {
        self.guard_core()?
            .meta_delete(key)
            .map_err(SessionError::Guard)
    }

    pub fn open_store(
        &mut self,
        app_key: String,
        db_path: String,
        profile: Option<&str>,
    ) -> Result<(), SessionError> {
        self.offline_core()?
            .open_store(app_key, db_path, normalize_profile(profile))
            .map_err(map_offline)
    }

    pub fn is_store_open(&mut self, app_key: String) -> Result<bool, SessionError> {
        Ok(self.offline_core()?.is_open(app_key))
    }

    pub fn exec(
        &mut self,
        app_key: String,
        sql: String,
        params_json: String,
    ) -> Result<u64, SessionError> {
        self.offline_core()?
            .exec(app_key, sql, params_json)
            .map_err(map_offline)
    }

    pub fn query(
        &mut self,
        app_key: String,
        sql: String,
        params_json: String,
    ) -> Result<String, SessionError> {
        self.offline_core()?
            .query(app_key, sql, params_json)
            .map_err(map_offline)
    }

    pub fn wipe_store(&mut self, app_key: String) -> Result<(), SessionError> {
        self.offline_core()?.wipe(app_key).map_err(map_offline)
    }

    /// E4-I authorized atomic job batch: validate + execute ONE bounded batch
    /// in ONE native transaction (`statements_json` = array of {sql, params?};
    /// `budget_json` = {maxStatements, maxParamBytes}). Returns total rows
    /// changed; the batch commits entirely or applies nothing.
    pub fn transaction_batch(
        &mut self,
        app_key: String,
        statements_json: String,
        budget_json: String,
    ) -> Result<u64, SessionError> {
        self.offline_core()?
            .transaction_batch(app_key, statements_json, budget_json)
            .map_err(map_offline)
    }

    /// E4-I versioned store migration: drive the bundled per-app manifest to
    /// `target_version`; each step commits atomically with its version row.
    /// Returns the resulting schema version.
    pub fn migrate_store(
        &mut self,
        app_key: String,
        target_version: i64,
    ) -> Result<i64, SessionError> {
        self.offline_core()?
            .migrate_store(app_key, target_version)
            .map_err(map_offline)
    }

    pub fn recovery_write_begin(
        &mut self,
        app_key: String,
        sha256: String,
        size: u64,
    ) -> Result<String, SessionError> {
        self.offline_core()?
            .blob_write_begin(app_key, sha256, size)
            .map_err(map_offline)
    }

    pub fn recovery_write_chunk(
        &mut self,
        app_key: String,
        handle: String,
        offset: u64,
        bytes: Vec<u8>,
    ) -> Result<u64, SessionError> {
        self.offline_core()?
            .blob_write_chunk(app_key, handle, offset, bytes)
            .map_err(map_offline)
    }

    pub fn recovery_write_commit(
        &mut self,
        app_key: String,
        handle: String,
    ) -> Result<String, SessionError> {
        self.offline_core()?
            .blob_write_commit(app_key, handle)
            .map_err(map_offline)
    }

    pub fn recovery_write_abort(
        &mut self,
        app_key: String,
        handle: String,
    ) -> Result<(), SessionError> {
        self.offline_core()?
            .blob_write_abort(app_key, handle)
            .map_err(map_offline)
    }

    pub fn recovery_read_open(
        &mut self,
        app_key: String,
        sha256: String,
    ) -> Result<String, SessionError> {
        self.offline_core()?
            .blob_read_open(app_key, sha256)
            .map_err(map_offline)
    }

    pub fn recovery_read_chunk(
        &mut self,
        app_key: String,
        handle: String,
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>, SessionError> {
        self.offline_core()?
            .blob_read_chunk(app_key, handle, offset, length)
            .map_err(map_offline)
    }

    pub fn recovery_read_close(
        &mut self,
        app_key: String,
        handle: String,
    ) -> Result<(), SessionError> {
        self.offline_core()?
            .blob_read_close(app_key, handle)
            .map_err(map_offline)
    }

    pub fn recovery_ref(&mut self, app_key: String, sha256: String) -> Result<u64, SessionError> {
        self.offline_core()?
            .blob_ref(app_key, sha256)
            .map_err(map_offline)
    }

    pub fn recovery_unref(&mut self, app_key: String, sha256: String) -> Result<u64, SessionError> {
        self.offline_core()?
            .blob_unref(app_key, sha256)
            .map_err(map_offline)
    }
}

fn map_offline(error: offline_core::OfflineError) -> SessionError {
    SessionError::Offline(error)
}
