// SHARED NATIVE-SHIM IMPLEMENTATION — included verbatim by BOTH
// `desktop-native` (napi-rs / Electron) and `ohos-native` (napi-ohos / HarmonyOS).
//
// This file is `include!`d, NOT a crate: napi-rs `#[napi]` registration must live
// in the final cdylib, so a shared dependency crate would not export. Each crate
// root brings the right runtime into scope as `napi` (desktop: the real `napi`
// crate; ohos: `use napi_ohos as napi;`) and the right derive macro (`use
// napi_derive::napi;` / `use napi_derive_ohos::napi;`), then includes this file.
// Everything below is runtime-agnostic: it references only `napi::` + `#[napi]`.
//
// A THIRD consumer compiles this file WITHOUT linking it into any cdylib: the
// `native-shared` test crate (same directory) include!s it against the
// host-linkable desktop runtime purely to execute the cfg(test) bodies on the
// build host — the executed test lane for this security surface, since
// `ohos-native` cannot host-link its napi-ohos registration
// (D-CLIENTS-RUST-OHOS-NATIVE-002). It adds no code to the contract below.
//
// Edit the native contract HERE, once — both shells stay in lock-step.

use std::sync::{Arc, Mutex, OnceLock};

use capability_session::{CapabilitySession, SessionError};
use guard_core::{GuardCore, MamPolicy};
use napi::bindgen_prelude::Buffer;
use offline_core::OfflineCore;
use zeroize::{Zeroize, Zeroizing};
// ── Process-global capability session ─────────────────────────────────────

static SESSION: OnceLock<Mutex<CapabilitySession>> = OnceLock::new();

fn session_slot() -> &'static Mutex<CapabilitySession> {
    SESSION.get_or_init(|| Mutex::new(CapabilitySession::default()))
}

fn poisoned() -> napi::Error {
    napi::Error::from_reason("native lock poisoned")
}

fn locked() -> napi::Error {
    napi::Error::from_reason("vault locked")
}

/// The unlocked vault, or a "vault locked" JS error. Used by every path that
/// requires an unlocked vault (mirrors `bridge.rs`'s `.ok_or("vault locked")`).
fn session_guard() -> napi::Result<Arc<GuardCore>> {
    session_slot()
        .lock()
        .map_err(|_| poisoned())?
        .guard_core()
        .map_err(|_| locked())
}

/// Borrow the session-owned lazy OfflineCore and marshal lock/session errors.
fn session_offline() -> napi::Result<Arc<OfflineCore>> {
    session_slot()
        .lock()
        .map_err(|_| poisoned())?
        .offline_core()
        .map_err(|error| napi::Error::from_reason(error.to_string()))
}

// ── Vault (guard-core) ──────────────────────────────────────────────────────

/// Open or create the vault with `passphrase`. Returns `false` (not an error) on
/// a wrong passphrase / open failure — mirrors `bridge.rs::vault_unlock`.
///
/// Zeroization (NATIVE-SECRET-NOT-ZEROIZED): this boundary's copy of the
/// passphrase is scrubbed on drop on every path. The clone handed to
/// capability-session is that crate's boundary; the JS-side string is
/// GC-managed and inherently unscrubbable from Rust (documented residual).
#[napi]
pub fn vault_unlock(db_path: String, passphrase: String) -> napi::Result<bool> {
    let passphrase = Zeroizing::new(passphrase);
    let mut session = session_slot().lock().map_err(|_| poisoned())?;
    Ok(session.unlock(db_path, (*passphrase).clone()))
}

/// Whether the vault is currently unlocked this session.
#[napi]
pub fn vault_is_unlocked() -> napi::Result<bool> {
    let session = session_slot().lock().map_err(|_| poisoned())?;
    Ok(session.is_unlocked())
}

/// A TOTP account surfaced to the bridge (`{ id, label, issuer }` — `icon` is
/// dropped, not in the contract).
#[napi(object)]
pub struct TotpEntry {
    pub id: String,
    pub label: String,
    pub issuer: String,
}

/// List stored TOTP accounts (no secrets). Throws "vault locked" when locked —
/// callers must unlock first (mirrors `bridge.rs::vault_list_totp`).
#[napi]
pub fn vault_list_totp() -> napi::Result<Vec<TotpEntry>> {
    let core = session_guard()?;
    let accounts = core
        .list_accounts()
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    Ok(accounts
        .into_iter()
        .map(|a| TotpEntry {
            id: a.id,
            label: a.label,
            issuer: a.issuer,
        })
        .collect())
}

/// Generate the current TOTP code for `id` (digits only). Throws when locked.
#[napi]
pub fn vault_generate_totp(id: String) -> napi::Result<String> {
    let core = session_guard()?;
    core.generate_totp(id)
        .map(|c| c.code)
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

// ── Push MFA device key (guard-core ECDH) ───────────────────────────────────

/// The device's ECDH public key as raw 65-byte uncompressed SEC1 (0x04‖X‖Y),
/// hex-encoded — POSTed as `device_public_key` to `/auth/device/register` so the
/// server can ECIES-encrypt push-MFA challenges only this device's guard-core
/// key can decrypt. Lazily generates + persists the keypair on first call.
/// Throws "vault locked" when locked (see `docs/standards/PUSH_ECIES_CONTRACT.md`).
#[napi]
pub fn push_device_public_key() -> napi::Result<String> {
    let core = session_guard()?;
    core.push_registration_public_key_hex()
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

// ── Secure store (vault-backed key/value) ───────────────────────────────────

/// Read a secure-store value. Returns `null` when locked or absent (NOT an
/// error) — mirrors `bridge.rs::secure_store_get`'s `Ok(None)`.
#[napi]
pub fn secure_store_get(key: String) -> napi::Result<Option<String>> {
    session_slot()
        .lock()
        .map_err(|_| poisoned())?
        .secure_get(key)
        .map_err(|error| napi::Error::from_reason(error.to_string()))
}

/// Write a secure-store value. Throws when locked (mirrors `secure_store_set`).
///
/// The boundary copy of `value` is zeroized on drop on every path (including
/// the locked-error return); the clone passed into capability-session is that
/// crate's boundary. The JS-side string remains outside Rust's control.
#[napi]
pub fn secure_store_set(key: String, value: String) -> napi::Result<()> {
    let value = Zeroizing::new(value);
    session_slot()
        .lock()
        .map_err(|_| poisoned())?
        .secure_set(key, (*value).clone())
        .map_err(|error| napi::Error::from_reason(error.to_string()))
}

/// Remove a secure-store value. Throws when locked (mirrors `secure_store_remove`).
#[napi]
pub fn secure_store_remove(key: String) -> napi::Result<()> {
    session_slot()
        .lock()
        .map_err(|_| poisoned())?
        .secure_remove(key)
        .map_err(|error| napi::Error::from_reason(error.to_string()))
}

// ── Offline encrypted store (window.setjoinNative.db, generic per-appKey) ────
//
// Trust boundary (corrected per NATIVE-STALE-TRUST-BOUNDARY-DOC — the old note
// understated the native floor as "allowlist + path resolution live in the TS
// layer"): the SQL statement allowlist is NOT TS-only. offline-core (`store.rs`,
// med-offcore-sqlguard-001 r2/r3) natively enforces a first-keyword allowlist,
// refuses multi-statement payloads in `exec`/`query` unconditionally, and admits
// batches ONLY through the authorized one-shot `db_exec_schema_init` seam below.
// The TS/ArkTS layers stack their own (redundant) checks on top of that floor.
// This crate only transports open/exec/query/wipe plus the schema-init seam;
// `db_path` is caller-supplied (each shell resolves its own private storage
// directory) and no path authorization happens in this crate.

/// Open (or create) the SQLCipher store for `app_key` at `db_path`. The key is
/// provisioned by guard-core in-process — it never crosses the bridge. Throws
/// "vault locked" via the shared session when locked.
#[napi]
pub fn db_open(db_path: String, app_key: String, profile: String) -> napi::Result<()> {
    session_slot()
        .lock()
        .map_err(|_| poisoned())?
        .open_store(app_key, db_path, Some(&profile))
        .map_err(session_err)
}

/// Whether the named store is currently open.
#[napi]
pub fn db_is_open(app_key: String) -> napi::Result<bool> {
    session_slot()
        .lock()
        .map_err(|_| poisoned())?
        .is_store_open(app_key)
        .map_err(|error| napi::Error::from_reason(error.to_string()))
}

/// Execute a mutating SQL statement (`params_json` is a JSON array string).
/// Returns the count of rows changed.
#[napi]
pub fn db_exec(app_key: String, sql: String, params_json: String) -> napi::Result<f64> {
    // ponytail: rows-affected as f64 keeps a plain JS `number` (i64 would map to
    // BigInt); exact for a local cache's counts (< 2^53). Upgrade to BigInt only
    // if a single statement ever changes > 9e15 rows.
    session_slot()
        .lock()
        .map_err(|_| poisoned())?
        .exec(app_key, sql, params_json)
        .map(|n| n as f64)
        .map_err(session_err)
}

/// Run a SELECT, returning a JSON array-of-objects string (`params_json` is a
/// JSON array string).
#[napi]
pub fn db_query(app_key: String, sql: String, params_json: String) -> napi::Result<String> {
    session_slot()
        .lock()
        .map_err(|_| poisoned())?
        .query(app_key, sql, params_json)
        .map_err(session_err)
}

/// Authorized schema-initialization seam (med-offcore-sqlguard-001 r3): the
/// ONLY way a multi-statement batch executes. Ordinary `db_exec` refuses
/// multi-statement payloads unconditionally; a batch sent here is validated
/// statement-by-statement INSIDE offline-core (per-statement allowlist;
/// PRAGMA/ATTACH/DETACH/VACUUM, reads and transaction control are never
/// batch-valid) and nothing executes unless the whole batch validates — the
/// native validator is the authority, so this export deliberately carries no
/// TS-side keyword copy (a per-shell allowlist duplicate is exactly the
/// divergence the r2 contract rejected). One-shot per open store connection:
/// the first SUCCESSFUL batch consumes the connection's gate; replaying this
/// seam on an initialized store is refused. Returns rows changed (0 for DDL)
/// as `f64`, mirroring `db_exec`.
#[napi]
pub fn db_exec_schema_init(app_key: String, sql: String) -> napi::Result<f64> {
    session_offline()?
        .exec_schema_init(app_key, sql)
        .map(|n| n as f64)
        .map_err(|e| session_err(SessionError::Offline(e)))
}

/// E4-I native transaction freeze (docs/verification/
/// 2026-09-08-connectivity-native-transaction-freeze.md): the authorized
/// atomic job batch — the ONLY entry besides `db_exec_schema_init` that may
/// run a multi-statement payload, and the ONLY one that owns transaction
/// control. `statements_json` is a JSON array of `{sql, params?}`;
/// `budget_json` is `{maxStatements, maxParamBytes}`. Every statement
/// (parameterized reads/DML only) and the aggregate budget are validated
/// INSIDE offline-core before the transaction opens — empty batches, budget
/// overflows, multi-statement smuggling, transaction control, schema DDL and
/// side-effecting statements are refused with no database effects — then the
/// batch executes in ONE transaction on the store's single connection
/// (the session lock holds for the whole call, so no second caller
/// interleaves it) and either commits entirely or applies nothing. Returns
/// the total changed-row count as `f64`, mirroring `db_exec`. The TS layer
/// (`$lib/offline/nativeBatch`) pre-admits the same contract; this native
/// validator is the authority, so the floor holds without any TS keyword copy.
#[napi]
pub fn db_transaction_batch(
    app_key: String,
    statements_json: String,
    budget_json: String,
) -> napi::Result<f64> {
    session_offline()?
        .transaction_batch(app_key, statements_json, budget_json)
        .map(|n| n as f64)
        .map_err(|e| session_err(SessionError::Offline(e)))
}

/// E4-I versioned store migration entry ("registered migrations, not caller
/// registration"): drives the offline-core BUNDLED per-app migration manifest
/// (`offline_core::migrations` — the installer/application-update trust-path
/// copy compiled into the artifact; there is no runtime register entry).
/// Refuses apps the manifest does not cover and unknown/ahead/downgrade
/// targets, then commits each declared transactional step plus its version
/// row atomically under the same per-store serialization as every other
/// entry; an interrupted step rolls back and can retry. Returns the resulting
/// version as a `{"version":N}` JSON string, mirroring `db_query`'s
/// JSON-string convention (the shell bridge parses before resolving).
#[napi]
pub fn db_migrate_store(app_key: String, target_version: i64) -> napi::Result<String> {
    session_offline()?
        .migrate_store(app_key, target_version)
        .map(|version| format!(r#"{{"version":{version}}}"#))
        .map_err(|e| session_err(SessionError::Offline(e)))
}

/// Close + delete this appKey's store file (+ WAL/SHM). Used on logout.
#[napi]
pub fn db_wipe(app_key: String) -> napi::Result<()> {
    session_slot()
        .lock()
        .map_err(|_| poisoned())?
        .wipe_store(app_key)
        .map_err(session_err)
}

// ── Generic recovery blob plane (offline-core blob.rs) ────────────────────────
//
// Every call is bounded to one 256 KiB chunk or a small handle/metadata value.
// Mail policy stays in TypeScript; this layer only transports generic
// content-addressed bytes. The shell hard-binds app_key to "mail" so web
// content cannot use this plane to reach another app's encrypted store.

fn session_err(error: capability_session::SessionError) -> napi::Error {
    // Display-only (SEC-ERR-DETAIL-DISCLOSURE): every plane maps errors through
    // `error.to_string()` — no Debug-formatted internal state crosses to JS.
    napi::Error::from_reason(error.to_string())
}

#[napi]
pub fn recovery_blob_write_begin(
    app_key: String,
    sha256: String,
    size: i64,
) -> napi::Result<String> {
    if size <= 0 {
        return Err(napi::Error::from_reason("blob size must be positive"));
    }
    session_slot().lock().map_err(|_| poisoned())?
        .recovery_write_begin(app_key, sha256, size as u64)
        .map_err(session_err)
}

#[napi]
pub fn recovery_blob_write_chunk(
    app_key: String,
    handle: String,
    offset: i64,
    bytes: Buffer,
) -> napi::Result<f64> {
    if offset < 0 {
        return Err(napi::Error::from_reason("blob offset must be non-negative"));
    }
    session_slot().lock().map_err(|_| poisoned())?
        .recovery_write_chunk(app_key, handle, offset as u64, bytes.to_vec())
        .map(|next| next as f64)
        .map_err(session_err)
}

#[napi]
pub fn recovery_blob_write_commit(app_key: String, handle: String) -> napi::Result<String> {
    session_slot().lock().map_err(|_| poisoned())?
        .recovery_write_commit(app_key, handle)
        .map_err(session_err)
}

#[napi]
pub fn recovery_blob_write_abort(app_key: String, handle: String) -> napi::Result<()> {
    session_slot().lock().map_err(|_| poisoned())?
        .recovery_write_abort(app_key, handle).map_err(session_err)
}

#[napi]
pub fn recovery_blob_read_open(app_key: String, sha256: String) -> napi::Result<String> {
    session_slot().lock().map_err(|_| poisoned())?
        .recovery_read_open(app_key, sha256).map_err(session_err)
}

#[napi]
pub fn recovery_blob_read_chunk(
    app_key: String,
    handle: String,
    offset: i64,
    length: u32,
) -> napi::Result<Buffer> {
    if offset < 0 {
        return Err(napi::Error::from_reason("blob offset must be non-negative"));
    }
    session_slot().lock().map_err(|_| poisoned())?
        .recovery_read_chunk(app_key, handle, offset as u64, length)
        .map(Buffer::from)
        .map_err(session_err)
}

#[napi]
pub fn recovery_blob_read_close(app_key: String, handle: String) -> napi::Result<()> {
    session_slot().lock().map_err(|_| poisoned())?
        .recovery_read_close(app_key, handle).map_err(session_err)
}

#[napi]
pub fn recovery_blob_ref(app_key: String, sha256: String) -> napi::Result<f64> {
    session_slot().lock().map_err(|_| poisoned())?
        .recovery_ref(app_key, sha256)
        .map(|refs| refs as f64)
        .map_err(session_err)
}

#[napi]
pub fn recovery_blob_unref(app_key: String, sha256: String) -> napi::Result<f64> {
    session_slot().lock().map_err(|_| poisoned())?
        .recovery_unref(app_key, sha256)
        .map(|refs| refs as f64)
        .map_err(session_err)
}

// ── MAM device-trust value cache (guard-core) ───────────────────────────────
//
// The HTTP checkin + HMAC computation live in TS (`mam.ts`); this crate only
// wraps guard-core's in-memory value cache + durable wipe latch.

/// Serializable projection of `MamPolicy` — the guard-core type is not
/// `Serialize` and is owned by that crate, so we round-trip a local DTO of the
/// same field shape as `mam.rs::MamPolicyDto`.
#[derive(serde::Serialize, serde::Deserialize)]
struct MamPolicyDto {
    policy_version: i64,
    copy_paste: String,
    screen_capture: String,
    encryption: String,
    watermark: bool,
    notification_profile: String,
    max_offline_days: i32,
}

impl From<MamPolicy> for MamPolicyDto {
    fn from(p: MamPolicy) -> Self {
        MamPolicyDto {
            policy_version: p.policy_version,
            copy_paste: p.copy_paste,
            screen_capture: p.screen_capture,
            encryption: p.encryption,
            watermark: p.watermark,
            notification_profile: p.notification_profile,
            max_offline_days: p.max_offline_days,
        }
    }
}

impl From<MamPolicyDto> for MamPolicy {
    fn from(d: MamPolicyDto) -> Self {
        MamPolicy {
            policy_version: d.policy_version,
            copy_paste: d.copy_paste,
            screen_capture: d.screen_capture,
            encryption: d.encryption,
            watermark: d.watermark,
            notification_profile: d.notification_profile,
            max_offline_days: d.max_offline_days,
        }
    }
}

/// Cache the resolved device id (guard-core `store_device_id`). Throws when locked.
#[napi]
pub fn mam_store_device_id(device_id: String) -> napi::Result<()> {
    let core = session_guard()?;
    core.store_device_id(device_id);
    Ok(())
}

/// Cache the resolved MAM policy (guard-core `store_mam_policy`). `policy_json`
/// is a `MamPolicyDto`-shaped JSON object. Throws when locked or on bad JSON.
#[napi]
pub fn mam_store_policy(policy_json: String) -> napi::Result<()> {
    let core = session_guard()?;
    let dto: MamPolicyDto = serde_json::from_str(&policy_json)
        .map_err(|e| napi::Error::from_reason(format!("mam_store_policy: bad policy JSON: {e}")))?;
    core.store_mam_policy(dto.into());
    Ok(())
}

/// Read the cached MAM policy as JSON, or `null` when no policy is cached / the
/// vault is locked (mirrors `mam.rs::mam_get_policy`'s `Ok(None)`).
///
/// State semantics (SEC-STATE-FAILOPEN, v1 shape kept — shell parity is
/// contractual): a locked vault reports `null`, which is UNKNOWN state, NOT an
/// authoritative "no policy" compliance answer. `null`/`false` from these
/// projections must not be treated as policy compliance; enforcement and any
/// mutation go through `session_guard`-guarded exports (`mam_store_*`,
/// `mam_mark_wiped`), which throw "vault locked" on a locked vault.
#[napi]
pub fn mam_get_policy() -> napi::Result<Option<String>> {
    let session = session_slot().lock().map_err(|_| poisoned())?;
    let Some(core) = session.guard_core_if_unlocked() else {
        return Ok(None);
    };
    match core.get_mam_policy() {
        Some(policy) => {
            let dto: MamPolicyDto = policy.into();
            serde_json::to_string(&dto)
                .map(Some)
                .map_err(|e| napi::Error::from_reason(format!("mam_get_policy: {e}")))
        }
        None => Ok(None),
    }
}

/// Latch a remote wipe (guard-core `mark_wiped`). Throws when locked.
#[napi]
pub fn mam_mark_wiped() -> napi::Result<()> {
    let core = session_guard()?;
    core.mark_wiped()
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

/// Whether a remote wipe has been latched. Returns `false` when locked
/// (mirrors `mam.rs::mam_is_wiped`).
///
/// State semantics (SEC-STATE-FAILOPEN, v1 shape kept — shell parity is
/// contractual): when locked, `false` means UNKNOWN, not "verified not wiped".
/// Consult this only after unlock (enforcement paths throw "vault locked" via
/// `session_guard`; `mam_mark_wiped` itself throws when locked).
#[napi]
pub fn mam_is_wiped() -> napi::Result<bool> {
    let session = session_slot().lock().map_err(|_| poisoned())?;
    Ok(session
        .guard_core_if_unlocked()
        .map(|core| core.is_wiped())
        .unwrap_or(false))
}

/// Clear the wipe latch after a successful re-enrolment (guard-core
/// `clear_wiped`). Throws when locked.
#[napi]
pub fn mam_clear_wiped() -> napi::Result<()> {
    let core = session_guard()?;
    core.clear_wiped()
        .map_err(|e| napi::Error::from_reason(e.to_string()))
}

// ── Drive byte plane (offline-core drive.rs; ARCH-017) ──────────────────────
//
// Metadata/control only crosses this boundary — paths, URLs, hashes, tickets.
// The SQLCipher vault key never does (session discipline above). The four fns
// that stream a whole file/chunk over disk or
// network (`drive_import_file`, `drive_fetch_chunk`, `drive_push_chunk`,
// `drive_serve_start`) run as napi `AsyncTask`s on the libuv threadpool, NOT
// sync on the JS main thread — a sync call here would freeze the Electron
// renderer for the duration of a multi-chunk transfer (a 1 GiB pin = 256
// sequential blocking calls otherwise). The remaining 5 (in-memory ticket
// bookkeeping / a single row lookup) stay plain sync `#[napi]` fns, matching
// `db_*`'s genre above.
//
// Confinement (deep-scan package desktop-drive-bridge-unconfined): every
// `drive_import_file` / `drive_fetch_chunk` / `drive_push_chunk` call is
// bounded INSIDE offline-core (`drive.rs`) — src_path must be an absolute,
// traversal-free, regular, non-symlink file, and chunk URLs must be absolute
// http(s) with cleartext http loopback-only. Because this file `include!`s the
// same implementation, BOTH shells (desktop-native AND ohos-native) inherit
// that floor byte-identically; the approved-origin / import-root POLICY on top
// of it lives in each shell's trusted layer (Electron `handlers/drive.ts`,
// HarmonyOS `BridgeProxy.ets`), enforced before these exports are reached.
use napi::bindgen_prelude::AsyncTask;
use napi::{Env, Task};

/// Install the TRUSTED shell confinement policy (replaces any previous
/// policy): `import_roots` are the only directories `drive_import_file`
/// src_paths may resolve inside (empty = deny ALL imports), and
/// `approved_origins` (exact http(s) origins) are the only origins chunk
/// fetch/push URLs may belong to (empty = deny all chunk network I/O).
/// Fail-closed default. Astra desktop-drive-bridge-unconfined r2 item 1:
/// this export lives in the SHARED implementation — both napi twins
/// (`desktop-native` for Electron, `ohos-native` for HarmonyOS) expose it, so
/// each shell's composition root (main.ts / BridgeProxy.ets via
/// NativeBinding.ets) can install its trusted policy natively through a
/// REQUIRED binding member, not an optional projection. Renderer content
/// cannot reach this export: it is not on any bridge method list; only the
/// trusted shell layers call it.
#[napi]
pub fn drive_set_confinement(import_roots: Vec<String>, approved_origins: Vec<String>) {
    offline_core::drive::drive_set_confinement(import_roots, approved_origins);
}

/// Keep the typed prefix ("tls:"/"integrity:"/"http:") — the TS bridge
/// classifies on it (grill G surfaces `drive.sync.tlsUntrusted` from "tls:").
fn drive_err(e: offline_core::OfflineError) -> napi::Error {
    napi::Error::from_reason(e.to_string())
}

pub struct DriveImportFileTask {
    app_key: String,
    src_path: String,
}
impl Task for DriveImportFileTask {
    type Output = String;
    type JsValue = String;
    fn compute(&mut self) -> napi::Result<Self::Output> {
        session_offline()?
            .drive_import_file(self.app_key.clone(), self.src_path.clone())
            .map_err(drive_err)
    }
    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

/// Import a local plaintext file into the vault (stream-read, split at 4 MiB,
/// per-chunk SHA-256). Returns the manifest JSON. Async — see the module note.
#[napi]
pub fn drive_import_file(app_key: String, src_path: String) -> AsyncTask<DriveImportFileTask> {
    AsyncTask::new(DriveImportFileTask { app_key, src_path })
}

pub struct DriveFetchChunkTask {
    app_key: String,
    url: String,
    bearer: String,
    sha256: String,
    size: u64,
}
impl Task for DriveFetchChunkTask {
    type Output = ();
    type JsValue = ();
    fn compute(&mut self) -> napi::Result<Self::Output> {
        let result = session_offline()?
            .drive_fetch_chunk(
                self.app_key.clone(),
                self.url.clone(),
                self.bearer.clone(),
                self.sha256.clone(),
                self.size,
            )
            .map_err(drive_err);
        self.bearer.zeroize(); // scrub the task's bearer copy after use
        result
    }
    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

/// Native GET `url` (Bearer `bearer`) → verify sha256/size → insert into the
/// vault. Idempotent (already-present chunk = no network). Async.
///
/// The boundary copy of `bearer` is zeroized on drop (NATIVE-SECRET-NOT-ZEROIZED);
/// the task's copy is scrubbed at the end of `compute`.
#[napi]
pub fn drive_fetch_chunk(
    app_key: String,
    url: String,
    bearer: String,
    sha256: String,
    size: i64,
) -> AsyncTask<DriveFetchChunkTask> {
    let bearer = Zeroizing::new(bearer);
    AsyncTask::new(DriveFetchChunkTask {
        app_key,
        url,
        bearer: (*bearer).clone(),
        sha256,
        size: size as u64,
    })
}

pub struct DrivePushChunkTask {
    app_key: String,
    url: String,
    bearer: String,
    sha256: String,
}
impl Task for DrivePushChunkTask {
    type Output = u32;
    type JsValue = u32;
    fn compute(&mut self) -> napi::Result<Self::Output> {
        let result = session_offline()?
            .drive_push_chunk(
                self.app_key.clone(),
                self.url.clone(),
                self.bearer.clone(),
                self.sha256.clone(),
            )
            .map(|status| status as u32)
            .map_err(drive_err);
        self.bearer.zeroize(); // scrub the task's bearer copy after use
        result
    }
    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

/// Native PUT of the vault's `sha256` chunk to `url` (Bearer `bearer`).
/// Resolves to the HTTP status (a gateway idempotent-re-PUT is success, like
/// the web path). Async.
///
/// The boundary copy of `bearer` is zeroized on drop (NATIVE-SECRET-NOT-ZEROIZED);
/// the task's copy is scrubbed at the end of `compute`.
#[napi]
pub fn drive_push_chunk(
    app_key: String,
    url: String,
    bearer: String,
    sha256: String,
) -> AsyncTask<DrivePushChunkTask> {
    let bearer = Zeroizing::new(bearer);
    AsyncTask::new(DrivePushChunkTask {
        app_key,
        url,
        bearer: (*bearer).clone(),
        sha256,
    })
}

/// Whether `sha256` is already in the vault. Fast in-memory/row lookup — sync.
#[napi]
pub fn drive_has_chunk(app_key: String, sha256: String) -> napi::Result<bool> {
    session_offline()?.drive_has_chunk(app_key, sha256).map_err(drive_err)
}

/// Eviction primitive (LRU/pin POLICY lives in TS; deletion is native). Returns
/// the count of rows deleted as `f64` (mirrors `db_exec`'s BigInt-avoidance —
/// a chunk count never approaches 2^53). Sync — in-process deletes only.
#[napi]
pub fn drive_delete_chunks(app_key: String, sha256s_json: String) -> napi::Result<f64> {
    session_offline()?
        .drive_delete_chunks(app_key, sha256s_json)
        .map(|n| n as f64)
        .map_err(drive_err)
}

pub struct DriveServeStartTask {
    app_key: String,
}
impl Task for DriveServeStartTask {
    type Output = String;
    type JsValue = String;
    fn compute(&mut self) -> napi::Result<Self::Output> {
        let eng = session_offline()?;
        offline_core::OfflineCore::drive_serve_start(eng, self.app_key.clone()).map_err(drive_err)
    }
    fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(output)
    }
}

/// Bind the 127.0.0.1 loopback render server (idempotent per app_key). Returns
/// `{"port":N}` JSON. Async — shares the "drive I/O never blocks JS" contract
/// with its siblings even though the bind itself is quick.
#[napi]
pub fn drive_serve_start(app_key: String) -> AsyncTask<DriveServeStartTask> {
    AsyncTask::new(DriveServeStartTask { app_key })
}

/// Register a one-open ticket for a manifest against a running loopback
/// server. Returns the ticket path `"/t/<hex>"`. Sync — in-memory bookkeeping.
#[napi]
pub fn drive_serve_grant(app_key: String, manifest_json: String) -> napi::Result<String> {
    session_offline()?
        .drive_serve_grant(app_key, manifest_json)
        .map_err(drive_err)
}

/// Revoke a loopback ticket. Sync — in-memory bookkeeping.
#[napi]
pub fn drive_serve_revoke(app_key: String, ticket: String) -> napi::Result<()> {
    session_offline()?
        .drive_serve_revoke(app_key, ticket)
        .map_err(drive_err)
}

/// Stop the loopback listener + revoke all its tickets. Idempotent. Sync.
#[napi]
pub fn drive_serve_stop(app_key: String) -> napi::Result<()> {
    session_offline()?.drive_serve_stop(app_key).map_err(drive_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The MAM policy DTO must survive a JSON round-trip byte-for-byte on every
    /// field — this is what `mamStorePolicy` (TS → Rust) and `mamGetPolicy`
    /// (Rust → TS) rely on. A field rename or type drift fails here, not at a
    /// silently-dropped policy field in production.
    #[test]
    fn mam_policy_dto_json_round_trip() {
        let original = MamPolicy {
            policy_version: 99,
            copy_paste: "block_external".into(),
            screen_capture: "block".into(),
            encryption: "required".into(),
            watermark: true,
            notification_profile: "silent".into(),
            max_offline_days: 7,
        };

        let json = serde_json::to_string(&MamPolicyDto::from(original.clone())).unwrap();
        let dto: MamPolicyDto = serde_json::from_str(&json).unwrap();
        let back: MamPolicy = dto.into();

        assert_eq!(back.policy_version, original.policy_version);
        assert_eq!(back.copy_paste, original.copy_paste);
        assert_eq!(back.screen_capture, original.screen_capture);
        assert_eq!(back.encryption, original.encryption);
        assert_eq!(back.watermark, original.watermark);
        assert_eq!(back.notification_profile, original.notification_profile);
        assert_eq!(back.max_offline_days, original.max_offline_days);
    }

    /// The serialized JSON keys must match the shape the TS side ports from
    /// `policyFromMap` — snake_case, all seven keys present.
    #[test]
    fn mam_policy_dto_json_keys_are_stable() {
        let json = serde_json::to_string(&MamPolicyDto::from(MamPolicy::default())).unwrap();
        for key in [
            "policy_version",
            "copy_paste",
            "screen_capture",
            "encryption",
            "watermark",
            "notification_profile",
            "max_offline_days",
        ] {
            assert!(json.contains(key), "missing key {key} in {json}");
        }
    }
}
