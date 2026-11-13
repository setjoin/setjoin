//! Native bridge command handlers.
//!
//! Each `#[tauri::command]` wraps one native capability that the webmail's
//! `window.setjoinNative` facade (see `bridge_js.rs`) invokes. The contract
//! shape is owned by `mailserver/webmail/src/lib/native/types.ts`
//! (`SetjoinNativeBridge`); the command names here must match the `invoke()`
//! calls in `bridge_js::bridge_init_js()`.
//!
//! A shared [`CapabilityState`] owns guard-core plus the lazy offline-core;
//! adapters only resolve paths and marshal command inputs/errors.

use std::sync::{Arc, Mutex};

use capability_session::{CapabilitySession, SessionError};
use guard_core::GuardCore;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_opener::OpenerExt;

/// Single native capability authority shared by bridge commands and MAM.
#[derive(Default)]
pub struct CapabilityState(pub Mutex<CapabilitySession>);

impl CapabilityState {
    pub fn guard_if_unlocked(&self) -> Option<Arc<GuardCore>> {
        self.0
            .lock()
            .ok()
            .and_then(|session| session.guard_core_if_unlocked())
    }
}

fn session_debug_error(error: SessionError) -> String {
    match error {
        SessionError::Locked => "vault locked".into(),
        SessionError::Guard(error) => format!("{error:?}"),
        SessionError::Offline(error) => format!("{error:?}"),
    }
}

/// Resolve (and create) the on-disk vault path inside the app data dir.
fn vault_db_path(app: &AppHandle) -> Result<String, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("guard.db").to_string_lossy().into_owned())
}

/// A TOTP account surfaced to the bridge (mirrors `VaultBridge.listTotp`'s
/// `{ id, label, issuer }` element shape; `icon` is dropped — not in contract).
#[derive(serde::Serialize)]
pub struct TotpEntry {
    pub id: String,
    pub label: String,
    pub issuer: String,
}

// ── Vault (guard-core) ──────────────────────────────────────────────────

/// Open or create the vault with `passphrase`. Returns `true` on success,
/// `false` on a wrong passphrase / locked vault (so the JS `unlock` resolves
/// to a boolean rather than rejecting).
#[tauri::command]
pub fn vault_unlock(
    app: AppHandle,
    state: State<'_, CapabilityState>,
    passphrase: String,
) -> Result<bool, String> {
    let path = vault_db_path(&app)?;
    let mut session = state.0.lock().map_err(|e| e.to_string())?;
    Ok(session.unlock(path, passphrase))
}

/// Whether the vault is currently unlocked this session.
#[tauri::command]
pub fn vault_is_unlocked(state: State<'_, CapabilityState>) -> Result<bool, String> {
    let session = state.0.lock().map_err(|e| e.to_string())?;
    Ok(session.is_unlocked())
}

/// List stored TOTP accounts (no secrets) — empty if the vault is locked is
/// not allowed; callers must unlock first, hence an error when locked.
#[tauri::command]
pub fn vault_list_totp(state: State<'_, CapabilityState>) -> Result<Vec<TotpEntry>, String> {
    let session = state.0.lock().map_err(|e| e.to_string())?;
    let core = session.guard_core().map_err(|e| e.to_string())?;
    let accounts = core.list_accounts().map_err(|e| e.to_string())?;
    Ok(accounts
        .into_iter()
        .map(|a| TotpEntry {
            id: a.id,
            label: a.label,
            issuer: a.issuer,
        })
        .collect())
}

/// Generate the current TOTP code for `id`. Returns the digits only (the
/// bridge contract is `Promise<string>`).
#[tauri::command]
pub fn vault_generate_totp(
    state: State<'_, CapabilityState>,
    id: String,
) -> Result<String, String> {
    let session = state.0.lock().map_err(|e| e.to_string())?;
    let core = session.guard_core().map_err(|e| e.to_string())?;
    core.generate_totp(id)
        .map(|c| c.code)
        .map_err(|e| e.to_string())
}

// ── OS capabilities ─────────────────────────────────────────────────────

/// Show an OS notification.
#[tauri::command]
pub fn notify(app: AppHandle, title: String, body: Option<String>) -> Result<(), String> {
    app.notification()
        .builder()
        .title(title)
        .body(body.unwrap_or_default())
        .show()
        .map_err(|e| e.to_string())
}

/// Open the native file picker. Returns the chosen path as a string, or `None`
/// if the user cancelled.
#[tauri::command]
pub async fn pick_file(app: AppHandle) -> Result<Option<String>, String> {
    let file = app.dialog().file().blocking_pick_file();
    Ok(file.map(|p| p.to_string()))
}

/// Schemes the desktop shell is willing to hand to the OS opener. Restricting to
/// these stops a caller (e.g. app code following an email-derived link) from
/// making the OS open a local `file://` path or launch a native handler for an
/// arbitrary URI scheme (`smb:`, `ms-excel:`, `javascript:`, …) with
/// attacker-influenced arguments. Defence-in-depth over the plugin's own deny list.
const ALLOWED_EXTERNAL_SCHEMES: &[&str] = &["https", "http", "mailto"];

/// True when `url`'s scheme is one the shell will open externally. Scheme
/// comparison is case-insensitive (RFC 3986 schemes are); a URL with no scheme
/// is rejected. Pure + unit-tested; `open_external` is the thin command wrapper.
pub fn external_url_allowed(url: &str) -> bool {
    match url.split_once(':') {
        Some((scheme, _)) => {
            ALLOWED_EXTERNAL_SCHEMES.contains(&scheme.to_ascii_lowercase().as_str())
        }
        None => false,
    }
}

/// Open a URL in the user's default browser / handler. Refuses any scheme
/// outside the http/https/mailto allowlist (see `external_url_allowed`).
#[tauri::command]
pub fn open_external(app: AppHandle, url: String) -> Result<(), String> {
    if !external_url_allowed(&url) {
        return Err("open_external: URL scheme not allowed (only http/https/mailto)".to_string());
    }
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|e| e.to_string())
}

// ── Secure store (vault-backed key/value) ───────────────────────────────
//
// Small key/values persisted AES-256-GCM-encrypted in the guard-core vault
// when unlocked. `get` returns `null` when locked (the webmail then keeps its
// own store, matching web behaviour); `set`/`remove` require an unlocked vault.

/// Read a secure-store value. `Ok(None)` when locked or absent.
#[tauri::command]
pub fn secure_store_get(
    state: State<'_, CapabilityState>,
    key: String,
) -> Result<Option<String>, String> {
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .secure_get(key)
        .map_err(|e| e.to_string())
}

/// Write a secure-store value. Errors if the vault is locked.
#[tauri::command]
pub fn secure_store_set(
    state: State<'_, CapabilityState>,
    key: String,
    value: String,
) -> Result<(), String> {
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .secure_set(key, value)
        .map_err(|e| e.to_string())
}

/// Remove a secure-store value. Errors if the vault is locked.
#[tauri::command]
pub fn secure_store_remove(state: State<'_, CapabilityState>, key: String) -> Result<(), String> {
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .secure_remove(key)
        .map_err(|e| e.to_string())
}

// ── Offline encrypted store (window.setjoinNative.db, generic per-appKey) ──
//
// open(appKey) requires an unlocked vault — the SQLCipher PRAGMA key is
// provisioned by guard-core IN offline-core and never reaches JS.
// exec/query are statement-allowlisted SQL over the named store; wipe deletes
// that appKey's file on logout. App schema is applied via TS migrations.

/// Resolve (and create) the on-disk SQLCipher store path for `app_key` inside
/// the app data dir. One file per app: 'mail' → mail-cache.db.
/// Separate from the vault (guard.db). Rejects unknown appKeys (forward-compat
/// allowlist — add 'drive'/'calendar'/'contacts' here as those apps ship).
fn store_db_path(app: &AppHandle, app_key: &str) -> Result<String, String> {
    let file = match app_key {
        "mail" => "mail-cache.db",
        // ponytail: allowlist ceiling — add appKeys as feature modules ship.
        _ => return Err(format!("unknown appKey: {app_key}")),
    };
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join(file).to_string_lossy().into_owned())
}

/// Statement allowlist: the WebView may only run SQL whose leading keyword is
/// in this set, against its own appKey's store. Blocks arbitrary cross-app SQL,
/// ATTACH, and PRAGMA key probing from the JS layer. CREATE is allowed so TS
/// migrations can apply the per-app schema on first open.
pub(crate) fn check_stmt_allowed(sql: &str) -> Result<(), String> {
    // Delegate to offline-core's authoritative gate rather than keeping a second
    // copy of the keyword list: one source of truth (store::STMT_ALLOWED_KWS), so
    // this first-line bridge check can never advertise a keyword the store will
    // reject. Defense-in-depth: store.rs re-checks every exec/query regardless,
    // and its multi-statement PRAGMA/ATTACH/DETACH scan is stricter than this
    // leading-keyword check. BEGIN/COMMIT/ROLLBACK pass (F5 transactional outbox).
    if offline_core::store::stmt_is_allowed(sql) {
        Ok(())
    } else {
        let head = sql
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        Err(format!("statement not allowed: {head}"))
    }
}

/// Open (or create) the SQLCipher store for `app_key`. The key is provisioned
/// by guard-core in-process — it never crosses the bridge.
/// `profile` selects the cipher: `"standard"` (AES-256, default) or `"smx"`
/// (SM4 page cipher — requires the `sm4-page-cipher` feature; see cipher.rs).
#[tauri::command]
pub fn db_open(
    app: AppHandle,
    state: State<'_, CapabilityState>,
    app_key: String,
    profile: Option<String>,
) -> Result<(), String> {
    let path = store_db_path(&app, &app_key)?;
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .open_store(app_key, path, profile.as_deref())
        .map_err(session_debug_error)
}

/// Whether the named store is currently open.
#[tauri::command]
pub fn db_is_open(state: State<'_, CapabilityState>, app_key: String) -> Result<bool, String> {
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .is_store_open(app_key)
        .map_err(|e| e.to_string())
}

/// Execute a mutating SQL statement (allowlist-checked; params JSON array).
/// Returns the count of rows changed.
///
/// `params` is deserialized natively by Tauri (no JS JSON.stringify needed) and
/// re-serialized once at the UniFFI String boundary — eliminates the double
/// stringify/parse hop the previous `params: String` design required.
#[tauri::command]
pub fn db_exec(
    state: State<'_, CapabilityState>,
    app_key: String,
    sql: String,
    params: serde_json::Value,
) -> Result<u64, String> {
    check_stmt_allowed(&sql)?;
    // ponytail: to_string() re-serializes once for the String-typed UniFFI boundary;
    // upgrade store::exec to accept &[Value] directly if the extra alloc matters.
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .exec(app_key, sql, params.to_string())
        .map_err(session_debug_error)
}

/// Run a SELECT and return results as a JSON array-of-objects string
/// (allowlist-checked; params JSON array).
///
/// `params` is deserialized natively by Tauri (no JS JSON.stringify needed) and
/// re-serialized once at the UniFFI String boundary.
#[tauri::command]
pub fn db_query(
    state: State<'_, CapabilityState>,
    app_key: String,
    sql: String,
    params: serde_json::Value,
) -> Result<String, String> {
    check_stmt_allowed(&sql)?;
    // ponytail: same single-alloc re-serialize as db_exec.
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .query(app_key, sql, params.to_string())
        .map_err(session_debug_error)
}

/// Close + delete this appKey's store file (+ WAL/SHM). Used on logout.
/// Other stores are unaffected.
#[tauri::command]
pub fn db_wipe(state: State<'_, CapabilityState>, app_key: String) -> Result<(), String> {
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .wipe_store(app_key)
        .map_err(session_debug_error)
}

// ── Recovery blob plane (hard-bound to the mail vault) ──────────────────

const RECOVERY_BLOB_APP: &str = "mail";

#[tauri::command]
pub fn recovery_blob_write_begin(
    state: State<'_, CapabilityState>,
    sha256: String,
    size: u64,
) -> Result<String, String> {
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .recovery_write_begin(RECOVERY_BLOB_APP.to_string(), sha256, size)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn recovery_blob_write_chunk(
    state: State<'_, CapabilityState>,
    handle: String,
    offset: u64,
    bytes: Vec<u8>,
) -> Result<u64, String> {
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .recovery_write_chunk(RECOVERY_BLOB_APP.to_string(), handle, offset, bytes)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn recovery_blob_write_commit(
    state: State<'_, CapabilityState>,
    handle: String,
) -> Result<String, String> {
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .recovery_write_commit(RECOVERY_BLOB_APP.to_string(), handle)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn recovery_blob_write_abort(
    state: State<'_, CapabilityState>,
    handle: String,
) -> Result<(), String> {
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .recovery_write_abort(RECOVERY_BLOB_APP.to_string(), handle)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn recovery_blob_read_open(
    state: State<'_, CapabilityState>,
    sha256: String,
) -> Result<String, String> {
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .recovery_read_open(RECOVERY_BLOB_APP.to_string(), sha256)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn recovery_blob_read_chunk(
    state: State<'_, CapabilityState>,
    handle: String,
    offset: u64,
    length: u32,
) -> Result<Vec<u8>, String> {
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .recovery_read_chunk(RECOVERY_BLOB_APP.to_string(), handle, offset, length)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn recovery_blob_read_close(
    state: State<'_, CapabilityState>,
    handle: String,
) -> Result<(), String> {
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .recovery_read_close(RECOVERY_BLOB_APP.to_string(), handle)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn recovery_blob_ref(state: State<'_, CapabilityState>, sha256: String) -> Result<u64, String> {
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .recovery_ref(RECOVERY_BLOB_APP.to_string(), sha256)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn recovery_blob_unref(
    state: State<'_, CapabilityState>,
    sha256: String,
) -> Result<u64, String> {
    state
        .0
        .lock()
        .map_err(|e| e.to_string())?
        .recovery_unref(RECOVERY_BLOB_APP.to_string(), sha256)
        .map_err(|e| e.to_string())
}

/// Queue B #6 mobile-runtime e2e harness only. Writes the injected probe
/// script's round-trip result (JSON) to `<app_data_dir>/e2e-probe-result.json`
/// so `clients/desktop/scripts/mobile-e2e.sh` can read it via the simulator's
/// host-visible container (iOS) or `adb ... run-as` (Android) — no
/// WebDriver/CDP dependency. Compiled only when the `mobile-e2e-probe`
/// feature is enabled; never present in a shipped build.
#[cfg(feature = "mobile-e2e-probe")]
#[tauri::command]
pub fn e2e_probe_report(app: AppHandle, msg: String) -> Result<(), String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("e2e-probe-result.json"), msg).map_err(|e| e.to_string())
}

// ── Mobile-only bridge commands (biometric / share / push) ──────────────
//
// C2 cfg(mobile) — target-checked post-init: these wrap the iOS/Android Tauri 2
// plugins and compile only for those targets; the orchestrator compile-checks
// them after `tauri ios/android init`. Desktop advertises neither `push` nor
// `biometric` and reaches `share` via the `open_external`/mailto fallback in
// bridge_js.

/// Mobile biometric unlock (Face/Touch ID, Android BiometricPrompt) via
/// `tauri-plugin-biometric`. Returns `true` on success, `false` on
/// cancel/failure so the JS resolves to a boolean rather than rejecting.
///
/// C2 cfg(mobile) — target-checked post-init.
#[cfg(any(target_os = "ios", target_os = "android"))]
#[tauri::command]
pub async fn biometric_unlock(app: AppHandle, reason: String) -> Result<bool, String> {
    use tauri_plugin_biometric::{AuthOptions, BiometricExt};
    let opts = AuthOptions {
        allow_device_credential: true,
        ..Default::default()
    };
    match app.biometric().authenticate(reason, opts) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Real device biometric-enrollment check (Face/Touch ID, Android BiometricPrompt)
/// via `tauri-plugin-biometric`'s `status()`. Backs `vault.isEnrolled()` — unlike
/// `vault.unlockBiometric()` (below), this is honestly answerable without a
/// stored passphrase: it only asks "does this device have biometric hardware
/// enrolled and ready", not "can biometric success unlock the vault key".
///
/// C2 cfg(mobile) — target-checked post-init.
#[cfg(any(target_os = "ios", target_os = "android"))]
#[tauri::command]
pub fn biometric_status(app: AppHandle) -> Result<bool, String> {
    use tauri_plugin_biometric::BiometricExt;
    Ok(app
        .biometric()
        .status()
        .map(|s| s.is_available)
        .unwrap_or(false))
}

/// Mobile native share sheet via `tauri-plugin-share` — hands the OS a file by
/// path (e.g. share a mail attachment to another app). `tauri-plugin-share`
/// shares files, so plain text/URL sharing uses the `openExternal`/mailto
/// fallback instead.
///
/// C2 cfg(mobile) — target-checked post-init.
#[cfg(any(target_os = "ios", target_os = "android"))]
#[tauri::command]
pub async fn share(app: AppHandle, path: String, mime: Option<String>) -> Result<(), String> {
    use tauri_plugin_share::ShareExt;
    app.share_file()
        .share_file(tauri_plugin_share::ShareRequest {
            path: Some(path),
            mime,
            group: None,
        })
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Mobile push registration (APNs/FCM): requests notification permission and
/// returns the captured device token to the SPA, which registers it via
/// `POST /auth/device/register`. The platform token capture lives in the
/// generated Xcode/Gradle projects (`push::register_and_upload`); this command
/// is the bridge entry. Returns the token, or `None` if denied / not yet
/// captured (device-gated stub — see `push.rs`).
///
/// C2 cfg(mobile) — target-checked post-init.
#[cfg(any(target_os = "ios", target_os = "android"))]
#[tauri::command]
pub async fn push_register(app: AppHandle) -> Result<Option<String>, String> {
    // Platform code (gen/apple APNs delegate, gen/android FirebaseMessagingService)
    // captures the OS token; the webmail SPA then POSTs it to
    // /auth/device/register. Device-gated stub today (returns None) — see push.rs.
    crate::push::register_and_upload(&app).await
}

// ── Capability advertisement ────────────────────────────────────────────

/// Capabilities the desktop shell advertises. A subset of C0's
/// `NATIVE_CAPABILITIES`: desktop has no mobile push, and biometric unlock is
/// the OS login + vault passphrase rather than a platform biometric API — so
/// `push` and `biometric` are intentionally absent.
///
/// C2 cfg(mobile) — target-checked post-init: the mobile build advertises the
/// 10-cap superset (adds `push`, `biometric`); the desktop build keeps these 8.
#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub const NATIVE_CAPABILITIES: &[&str] = &[
    "secureStore",
    "vault",
    "share",
    "pickFile",
    "notify",
    "openExternal",
    "mailDb",
    "deviceProof",
    "recoveryBlob",
];

/// Mobile capability superset: the desktop 8 plus real `push` + `biometric`.
///
/// C2 cfg(mobile) — target-checked post-init.
#[cfg(any(target_os = "ios", target_os = "android"))]
pub const NATIVE_CAPABILITIES: &[&str] = &[
    "push",
    "biometric",
    "secureStore",
    "vault",
    "share",
    "pickFile",
    "notify",
    "openExternal",
    "mailDb",
    "deviceProof",
    "recoveryBlob",
];

/// Back-compat alias for the desktop capability set name used by existing
/// tests / call sites. On desktop this is the 8-cap list; on mobile it is the
/// 10-cap superset. (Kept as `DESKTOP_CAPABILITIES` so the C0-parity test and
/// `bridge_js` need no rename.)
pub const DESKTOP_CAPABILITIES: &[&str] = NATIVE_CAPABILITIES;

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirror of `NATIVE_CAPABILITIES` in
    /// `mailserver/webmail/src/lib/native/types.ts`. If C0 adds a capability,
    /// this list must be updated in lock-step — the parity test below proves
    /// the desktop set is a strict subset of the contract.
    const C0_NATIVE_CAPABILITIES: &[&str] = &[
        "push",
        "biometric",
        "secureStore",
        "vault",
        "share",
        "pickFile",
        "notify",
        "openExternal",
        "mailDb",
        "deviceProof",
        "recoveryBlob",
    ];

    #[test]
    fn capabilities_are_a_subset_of_the_c0_contract() {
        for cap in DESKTOP_CAPABILITIES {
            assert!(
                C0_NATIVE_CAPABILITIES.contains(cap),
                "DESKTOP_CAPABILITIES advertises {cap:?} which is not in C0's NATIVE_CAPABILITIES"
            );
        }
    }

    #[test]
    fn capabilities_include_mail_db() {
        assert!(DESKTOP_CAPABILITIES.contains(&"mailDb"));
    }

    #[test]
    fn stmt_allowlist_permits_transaction_keywords() {
        // F5 transactional outbox: BEGIN/COMMIT/ROLLBACK must pass the allowlist so
        // the optimistic cache-write + queue-write commit atomically on one conn.
        for kw in ["BEGIN", "COMMIT", "ROLLBACK"] {
            assert!(
                super::check_stmt_allowed(kw).is_ok(),
                "{kw} must be allowed"
            );
        }
        assert!(
            super::check_stmt_allowed("ATTACH DATABASE 'x'").is_err(),
            "ATTACH stays blocked"
        );
    }

    #[test]
    fn stmt_allowlist_blocks_pragma() {
        // PRAGMA is not in the allowlist — check_stmt_allowed rejects it as the
        // leading keyword, covering single-statement PRAGMA probes.
        assert!(
            super::check_stmt_allowed("PRAGMA key").is_err(),
            "PRAGMA must be blocked"
        );
        assert!(
            super::check_stmt_allowed("pragma key").is_err(),
            "pragma (lower) must be blocked"
        );
        assert!(
            super::check_stmt_allowed("PRAGMA rekey=\"newkey\"").is_err(),
            "PRAGMA rekey must be blocked"
        );
    }

    #[test]
    fn capabilities_have_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for cap in DESKTOP_CAPABILITIES {
            assert!(seen.insert(*cap), "duplicate capability {cap:?}");
        }
    }

    #[test]
    fn external_url_allows_web_and_mailto() {
        assert!(external_url_allowed("https://example.com/x?y=1"));
        assert!(external_url_allowed("http://example.com"));
        assert!(external_url_allowed("mailto:a@b.com?subject=hi"));
        assert!(external_url_allowed("HTTPS://EXAMPLE.COM")); // scheme is case-insensitive
    }

    #[test]
    fn external_url_rejects_dangerous_or_schemeless() {
        assert!(!external_url_allowed("file:///etc/passwd"));
        assert!(!external_url_allowed("smb://host/share"));
        assert!(!external_url_allowed("javascript:alert(1)"));
        assert!(!external_url_allowed("ms-excel:ofe|u|https://x"));
        assert!(!external_url_allowed("/no/scheme"));
        assert!(!external_url_allowed(""));
    }
}
