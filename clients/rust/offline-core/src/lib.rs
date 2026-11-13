// ponytail: uniffi scaffolding included so OfflineError derives uniffi::Error
// correctly and the mobile/HarmonyOS bindings (Task 6) have a stable base.
uniffi::setup_scaffolding!();

pub mod blob;
pub mod cipher;
pub mod drive;
pub mod migrations;
pub mod schema;
pub mod store;

pub use store::OfflineError;

use guard_core::GuardCore;
use rusqlite::Connection;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// Per-appKey SQLCipher store engine.
///
/// Holds one open, keyed Connection per appKey ('mail', 'drive', …). The key
/// is applied as PRAGMA key IN-PROCESS from guard-core and never returned to
/// JS or over the bridge (§11 / ARCH-013 decision 4).
///
/// Schema is not created here — the TS layer sends DDL through
/// `exec_schema_init()` on first open (Task 8 bridge migrations): the
/// authorized one-shot batch path (med-offcore-sqlguard-001). Ordinary
/// `exec()` runs single allowlisted statements only. `wipe()` closes +
/// deletes only the named appKey's file; other stores are unaffected.
#[derive(uniffi::Object)]
pub struct OfflineCore {
    guard: Arc<GuardCore>,
    // appKey -> (open connection, db_path). pub(crate): drive.rs (ARCH-017)
    // reaches open connections directly for the byte-plane import/fetch/push/
    // serve paths — it never re-keys or re-opens, only reads/writes rows.
    pub(crate) stores: Mutex<HashMap<String, (Connection, String)>>,
    /// Loopback render servers, one per app_key (drive.rs, ARCH-017). pub(crate).
    pub(crate) serves: Mutex<HashMap<String, drive::ServeHandle>>,
}

#[uniffi::export]
impl OfflineCore {
    /// Create the engine with a pre-opened GuardCore for key provisioning.
    #[uniffi::constructor]
    pub fn new(guard: Arc<GuardCore>) -> Arc<Self> {
        Arc::new(Self {
            guard,
            stores: Mutex::new(HashMap::new()),
            serves: Mutex::new(HashMap::new()),
        })
    }

    /// Open (or create) the SQLCipher store for `app_key` at `db_path`.
    ///
    /// `profile` selects the cipher: `"standard"` (AES-256, default) or
    /// `"smx"` (SM4 page cipher — requires `sm4-page-cipher` feature and a
    /// custom SQLCipher build; see cipher.rs).
    ///
    /// Key comes from guard-core's `provision_store_key` (HKDF subkey of the
    /// vault root) and is applied as PRAGMA key IN-PROCESS. The key never
    /// crosses the bridge. A wrong passphrase/key fails here with Crypto error.
    ///
    /// Idempotent: second open of the same appKey with the same profile is a
    /// no-op. If `profile` differs from the currently-open profile, the
    /// existing connection is closed, the DB file is wiped, and a fresh store
    /// is created under the new cipher (decision 3: profile flip = data loss).
    ///
    /// On first open, `schema::apply_generic` creates oc_meta / oc_outbound /
    /// oc_sync_issues inside the encrypted store. The mail app schema is applied
    /// by the TS layer via `exec_schema_init()`.
    pub fn open_store(
        &self,
        app_key: String,
        db_path: String,
        profile: String,
    ) -> Result<(), OfflineError> {
        let mut stores = self
            .stores
            .lock()
            .map_err(|_| OfflineError::Database("lock poisoned".into()))?;

        // Idempotent if the same app_key is already open with the same profile.
        // Profile flip: evict + wipe + reopen under the new cipher.
        if stores.contains_key(&app_key) {
            let same_profile = {
                let (conn, _) = stores.get(&app_key).unwrap();
                conn.query_row(
                    "SELECT value FROM oc_meta WHERE key = 'cryptoProfile'",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .map(|p| p == profile)
                .unwrap_or(false)
            };
            if same_profile {
                return Ok(());
            }
            // Profile changed: close the open connection and wipe the file.
            if let Some((conn, path)) = stores.remove(&app_key) {
                drop(conn);
                wipe_db_files(&path)?;
            }
        }

        let key = Zeroizing::new(
            self.guard
                .provision_store_key(&app_key)
                .map_err(|e| OfflineError::Guard(format!("{e:?}")))?,
        );
        // Zeroizing: the derived subkey's owning buffer is scrubbed on drop —
        // including the `?` early-return path below (OFFSTORE-KEY-ZEROIZE-GAP).
        let conn = open_cipher_init(&db_path, &profile, &key)?;
        stores.insert(app_key, (conn, db_path));
        Ok(())
    }

    pub fn is_open(&self, app_key: String) -> bool {
        self.stores
            .lock()
            .map(|s| s.contains_key(&app_key))
            .unwrap_or(false)
    }

    pub fn exec(
        &self,
        app_key: String,
        sql: String,
        params_json: String,
    ) -> Result<u64, OfflineError> {
        let guard = self
            .stores
            .lock()
            .map_err(|_| OfflineError::Database("lock poisoned".into()))?;
        let (conn, _) = guard
            .get(&app_key)
            .ok_or_else(|| OfflineError::Database(format!("store '{app_key}' not open")))?;
        store::exec(conn, &sql, &params_json)
    }

    /// The authorized schema-initialization path — the ONLY way a
    /// multi-statement batch executes (med-offcore-sqlguard-001). Ordinary
    /// `exec` refuses multi-statement payloads unconditionally; a batch sent
    /// here is validated statement-by-statement FIRST (per-statement allowlist;
    /// PRAGMA/ATTACH/DETACH/VACUUM, reads and transaction control are never
    /// batch-valid) and nothing executes unless the whole batch validates.
    ///
    /// One-shot per store connection: the first SUCCESSFUL batch consumes the
    /// connection's gate in native process memory; every later batch is
    /// refused. `open_store` creates a fresh connection per session, so the TS
    /// layer's idempotent re-init on reopen lands on a fresh gate. A REJECTED
    /// batch consumes nothing (the store stays initializable).
    pub fn exec_schema_init(&self, app_key: String, sql: String) -> Result<u64, OfflineError> {
        let guard = self
            .stores
            .lock()
            .map_err(|_| OfflineError::Database("lock poisoned".into()))?;
        let (conn, _) = guard
            .get(&app_key)
            .ok_or_else(|| OfflineError::Database(format!("store '{app_key}' not open")))?;
        store::exec_schema_init(conn, &sql)
    }

    pub fn query(
        &self,
        app_key: String,
        sql: String,
        params_json: String,
    ) -> Result<String, OfflineError> {
        let guard = self
            .stores
            .lock()
            .map_err(|_| OfflineError::Database("lock poisoned".into()))?;
        let (conn, _) = guard
            .get(&app_key)
            .ok_or_else(|| OfflineError::Database(format!("store '{app_key}' not open")))?;
        store::query(conn, &sql, &params_json)
    }

    /// E4-I authorized atomic job batch (connectivity-native-transaction-
    /// freeze): the ONLY entry besides `exec_schema_init` that may run a
    /// multi-statement payload, and the ONLY one owning transaction control.
    /// `statements_json` is a JSON array of `{sql, params?}`; `budget_json` is
    /// `{maxStatements, maxParamBytes}`. Every statement (parameterized
    /// reads/DML only — transaction control, DDL and side-effecting classes
    /// are refused) and the aggregate budget validate BEFORE the transaction
    /// opens; the batch then executes in ONE transaction on the store's single
    /// connection — no second caller interleaves it — and either commits
    /// entirely or applies nothing. Returns the total changed-row count.
    pub fn transaction_batch(
        &self,
        app_key: String,
        statements_json: String,
        budget_json: String,
    ) -> Result<u64, OfflineError> {
        let statements: Vec<store::BatchStatementDto> = serde_json::from_str(&statements_json)
            .map_err(|e| OfflineError::Database(format!("batch rejected: bad statements JSON: {e}")))?;
        let budget: store::BatchBudgetDto = serde_json::from_str(&budget_json)
            .map_err(|e| OfflineError::Database(format!("batch rejected: bad budget JSON: {e}")))?;
        let guard = self
            .stores
            .lock()
            .map_err(|_| OfflineError::Database("lock poisoned".into()))?;
        let (conn, _) = guard
            .get(&app_key)
            .ok_or_else(|| OfflineError::Database(format!("store '{app_key}' not open")))?;
        store::exec_transaction_batch(conn, &statements, &budget)
    }

    /// E4-I versioned store migration entry (registered migrations, not caller
    /// registration): drives the BUNDLED per-app manifest
    /// (`migrations.rs`, the installer/application-update trust-path copy —
    /// never a caller-supplied manifest). Refuses apps the manifest does not
    /// cover and unknown/ahead/downgrade targets, then commits each declared
    /// transactional step plus its version row atomically under the same
    /// per-store serialization as every other entry. Returns the resulting
    /// schema version.
    pub fn migrate_store(&self, app_key: String, target_version: i64) -> Result<i64, OfflineError> {
        let guard = self
            .stores
            .lock()
            .map_err(|_| OfflineError::Database("lock poisoned".into()))?;
        let (conn, _) = guard
            .get(&app_key)
            .ok_or_else(|| OfflineError::Database(format!("store '{app_key}' not open")))?;
        migrations::apply_migrations(conn, &app_key, target_version)
    }

    /// Close + delete this appKey's store file (+ -wal/-shm/-journal).
    ///
    /// Only the named appKey's file is touched; other stores are unaffected.
    /// An interrupted wipe still leaves only SQLCipher ciphertext on disk.
    /// Deletion failures are surfaced (OFFSTORE-WIPE-INCOMPLETE): a wipe that
    /// could not remove a file reports an error rather than success.
    pub fn wipe(&self, app_key: String) -> Result<(), OfflineError> {
        // Stop any loopback render server BEFORE taking the stores lock (a wiped
        // vault must not keep serving, drive.rs/ARCH-017). Ordering is load-bearing:
        // drive_serve_stop() joins the serve thread, and an in-flight request on
        // that thread calls read_chunk(), which itself takes self.stores.lock() —
        // taking that lock here first would deadlock waiting for a join that can
        // never finish (batch-1 correction #6).
        self.drive_serve_stop(app_key.clone()).ok();
        let mut guard = self
            .stores
            .lock()
            .map_err(|_| OfflineError::Database("lock poisoned".into()))?;
        if let Some((conn, path)) = guard.remove(&app_key) {
            drop(conn); // close before deleting
            wipe_db_files(&path)?;
        }
        Ok(())
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Delete the store file and its sidecars. The crash-window hot journal
/// ("-journal") is included with WAL's "-wal"/"-shm" (OFFSTORE-WIPE-INCOMPLETE:
/// it can exist between a failed open and the journal-mode switch). Missing
/// files are success (ENOENT); any other deletion failure is returned — never
/// swallowed — so `wipe()`/`open_store` cannot report success on a partial wipe.
fn wipe_db_files(path: &str) -> Result<(), OfflineError> {
    let mut first_err: Option<std::io::Error> = None;
    for suffix in ["", "-wal", "-shm", "-journal"] {
        if let Err(e) = std::fs::remove_file(format!("{path}{suffix}")) {
            if e.kind() != std::io::ErrorKind::NotFound && first_err.is_none() {
                first_err = Some(e);
            }
        }
    }
    match first_err {
        None => Ok(()),
        Some(e) => Err(OfflineError::Database(format!(
            "wipe: could not delete store file '{path}': {e}"
        ))),
    }
}

// ── Test-only helper (deliberately OUTSIDE the #[uniffi::export] block, so it
//    can never become a bridge method; production code never calls it) ────────
impl OfflineCore {
    /// TEST-ONLY (doc-hidden): drop the one-shot schema-init marker for the
    /// named appKey's live connection. Mirrors
    /// `store::__reset_schema_init_gate_for_tests` at the OfflineCore layer so
    /// integration tests can drive the real application path
    /// (`open_store` → `exec_schema_init`) deterministically: a dropped prior
    /// connection's consumed gate could otherwise be inherited by a fresh
    /// connection via allocator address reuse (fail-closed flakiness). Its
    /// only effect is permitting the FIRST authorized init of THIS store's
    /// connection — it cannot widen the batch validator or any other gate.
    #[doc(hidden)]
    pub fn __reset_schema_init_gate_for_tests(&self, app_key: &str) {
        if let Ok(stores) = self.stores.lock() {
            if let Some((conn, _)) = stores.get(app_key) {
                store::__reset_schema_init_gate_for_tests(conn);
            }
        }
    }
}

/// Open a SQLCipher connection, apply the cipher, create the generic schema,
/// and write (or verify) `cryptoProfile` in `oc_meta`.
///
/// On a profile-label mismatch in oc_meta (same cipher, different stored name),
/// wipes the file and recreates. On a cipher-level failure (`apply_cipher` Err),
/// the error propagates immediately — no wipe.
fn open_cipher_init(
    db_path: &str,
    profile: &str,
    key: &[u8; 32],
) -> Result<Connection, OfflineError> {
    let conn = Connection::open(db_path)?;
    cipher::apply_cipher(&conn, profile, key)?;
    schema::apply_generic(&conn)?;

    // Check stored profile; wipe + recreate on label mismatch.
    let stored: Result<String, rusqlite::Error> = conn.query_row(
        "SELECT value FROM oc_meta WHERE key = 'cryptoProfile'",
        [],
        |r| r.get(0),
    );

    let conn = match stored {
        Ok(p) if p != profile => {
            // Stored profile label differs (e.g. "smx-v1" → "smx-v2" on same cipher):
            // wipe and recreate under the requested profile.
            // ponytail: this path is speculative for A1 (only "standard" works today);
            // it's the correct behaviour when SM4 profile names evolve.
            drop(conn);
            wipe_db_files(db_path)?;
            let fresh = Connection::open(db_path)?;
            cipher::apply_cipher(&fresh, profile, key)?;
            schema::apply_generic(&fresh)?;
            fresh.execute(
                "INSERT OR REPLACE INTO oc_meta(key,value) VALUES('cryptoProfile',?1)",
                [profile],
            )?;
            fresh
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            // New DB: write the profile for future mismatch detection.
            conn.execute(
                "INSERT OR REPLACE INTO oc_meta(key,value) VALUES('cryptoProfile',?1)",
                [profile],
            )?;
            conn
        }
        Ok(_) => conn, // profile matches; nothing to do
        Err(e) => return Err(e.into()),
    };

    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
    Ok(conn)
}
