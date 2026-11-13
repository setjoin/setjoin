//! Drive byte plane (ARCH-017; spec §3.6 — locked signatures). Rust owns ONLY
//! dc_chunks bytes + streams; all metadata/sync/policy/pin DECISIONS stay TS via
//! the generic exec/query bridge. This module knowingly amends ARCH-012's
//! "no new Rust for future apps" — see the ADR; the mail-core lesson still holds:
//! no protocol, no sync engine, no app logic here.
//!
//! Key custody (load-bearing, ARCH-016 Model M): every function below operates
//! on an already-open, already-keyed `rusqlite::Connection` from `OfflineCore.
//! stores` — the SQLCipher key was applied as `PRAGMA key` in-process at
//! `open_store` time (lib.rs / store.rs). This module never receives, returns,
//! re-derives, or logs the key; it has no parameter or return path for key
//! material at all.
use crate::store::{classify_transport, OfflineError};
use crate::OfflineCore;
use rand::Rng;
use rusqlite::Connection;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap as StdHashMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub(crate) const CHUNK: usize = 4 * 1024 * 1024;

/// Rust-owned DDL (bytes are Rust's). Idempotent; run on first touch so call
/// order vs the TS metadata migrations never matters.
const DC_CHUNKS_DDL: &str = "CREATE TABLE IF NOT EXISTS dc_chunks (
    sha256 TEXT NOT NULL PRIMARY KEY,
    size INTEGER NOT NULL,
    bytes BLOB NOT NULL,
    pinned_at INTEGER,
    last_read INTEGER)";

/// One chunk reference inside a serve-grant manifest (§3.6).
#[derive(Deserialize, Clone)]
pub(crate) struct ChunkRef {
    pub sha256: String,
}

/// The byte-range shape handed to `drive_serve_grant` — reshaped by the TS/
/// napi caller from whatever it tracks; Rust only needs size/type/chunk order.
#[derive(Deserialize, Clone)]
pub(crate) struct Manifest {
    pub size: u64,
    #[serde(default)]
    #[serde(rename = "contentType")]
    pub content_type: Option<String>,
    pub chunks: Vec<ChunkRef>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl OfflineCore {
    /// Run `f` against the open store for `app_key`, ensuring dc_chunks exists.
    /// Holds the stores lock for the duration of `f` — callers keep `f` to ONE
    /// chunk's work so the loopback thread and the JS bridge interleave fairly.
    /// ponytail: per-chunk stores-lock; a dedicated read connection per serve
    /// if lock contention shows up under load.
    pub(crate) fn with_drive_conn<T>(
        &self,
        app_key: &str,
        f: impl FnOnce(&Connection) -> Result<T, OfflineError>,
    ) -> Result<T, OfflineError> {
        let guard = self
            .stores
            .lock()
            .map_err(|_| OfflineError::Database("lock poisoned".into()))?;
        let (conn, _) = guard
            .get(app_key)
            .ok_or_else(|| OfflineError::Database(format!("store '{app_key}' not open")))?;
        conn.execute(DC_CHUNKS_DDL, [])?;
        f(conn)
    }

    fn insert_chunk(&self, app_key: &str, sha256: &str, bytes: &[u8]) -> Result<(), OfflineError> {
        self.with_drive_conn(app_key, |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO dc_chunks (sha256, size, bytes, last_read) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![sha256, bytes.len() as i64, bytes, now_ms()],
            )?;
            Ok(())
        })
    }

    /// Read one chunk's bytes from the vault (open connection only — see the
    /// module-level key-custody note). Bumps `last_read` for LRU eviction (the
    /// eviction POLICY itself is TS; this is just the bookkeeping write).
    pub(crate) fn read_chunk(&self, app_key: &str, sha256: &str) -> Result<Vec<u8>, OfflineError> {
        self.with_drive_conn(app_key, |conn| {
            let bytes: Vec<u8> = conn
                .query_row(
                    "SELECT bytes FROM dc_chunks WHERE sha256 = ?1",
                    [sha256],
                    |r| r.get(0),
                )
                .map_err(|_| OfflineError::Database(format!("chunk {sha256} not in vault")))?;
            conn.execute(
                "UPDATE dc_chunks SET last_read = ?1 WHERE sha256 = ?2",
                rusqlite::params![now_ms(), sha256],
            )?;
            Ok(bytes)
        })
    }
}

/// Shared HTTP agent — rustls + the OS platform verifier (locked, ARCH-017).
/// Built once: loading the platform verifier is not free.
/// GRILL G: a private on-prem CA MUST be installed in the OS trust store or every
/// vault transfer fails with OfflineError::Tls (deliberate — same contract as the
/// WebView; never bypass, never pin here).
fn http_agent() -> Result<&'static ureq::Agent, OfflineError> {
    static AGENT: OnceLock<Result<ureq::Agent, String>> = OnceLock::new();
    AGENT
        .get_or_init(|| {
            use rustls_platform_verifier::ConfigVerifierExt;
            // rustls-platform-verifier 0.7 made with_platform_verifier() fallible
            // (Result, not the plan draft's infallible 0.3 form) — a build/platform
            // init failure here is a programming/environment bug, not a per-request
            // transport error. It is surfaced as OfflineError::Tls on every vault
            // transfer instead of panicking across the FFI boundary (a native
            // abort is not observable to the shell as a typed failure); the
            // direction stays fail-closed: never downgrade transport security,
            // every transfer fails until the platform verifier initializes.
            match rustls::ClientConfig::with_platform_verifier() {
                Ok(tls) => Ok(ureq::AgentBuilder::new()
                    .tls_config(std::sync::Arc::new(tls))
                    .timeout(std::time::Duration::from_secs(120)) // one 4 MiB chunk, on-prem LAN
                    // Astra desktop-drive-bridge-unconfined item 5 (r2): ureq follows
                    // redirects by default (up to 5), and `ensure_chunk_origin_allowed`
                    // validates only the INITIAL URL — a compromised/approved-adjacent
                    // endpoint could 302 the credentialed GET/PUT to an unapproved
                    // origin or port. redirects(0) makes ureq return the 3xx response
                    // as-is instead of dialing ANY hop (unit.rs short-circuits before
                    // redirect processing), so the approved-origin allowlist bounds the
                    // actual destination. fetch treats a 3xx as the size/hash mismatch
                    // it is; push surfaces the 3xx status to the TS caller.
                    .redirects(0)
                    .build()),
                Err(e) => Err(format!(
                    "rustls platform verifier failed to initialize: {e}"
                )),
            }
        })
        .as_ref()
        .map_err(|msg| {
            OfflineError::Tls(format!(
                "drive transport unavailable: {msg}"
            ))
        })
}

fn map_ureq(e: ureq::Error) -> OfflineError {
    match e {
        ureq::Error::Status(code, _) => OfflineError::Http(format!("HTTP {code}")),
        ureq::Error::Transport(t) => classify_transport(&t.to_string(), true),
    }
}

// ── Native confinement floor (deep-scan package desktop-drive-bridge-────────
// unconfined). The shell layers (Electron `handlers/drive.ts`, HarmonyOS
// `BridgeProxy.ets`) own the ORIGIN policy: import-root membership for
// `drive_import_file` and an approved-origin allowlist for chunk fetch/push.
// THIS layer owns a transport/path floor AND the trusted mirror-index policy
// that every native consumer inherits — desktop-native and ohos-native via
// `include!`, and the UniFFI mobile bindings — so the credentialed
// file/network sinks stay bounded even if a shell layer is ever bypassed or
// mis-wired:
//   - a chunk URL must be an absolute http(s) URL, and cleartext http is
//     loopback-only (the drive bearer must never leave the box unencrypted);
//     its parsed origin must additionally be in the TRUSTED approved-origin
//     allowlist installed by the shell (`drive_set_confinement`) — default
//     empty = deny all chunk network I/O (fail-closed);
//   - an import src_path must be absolute, traversal-free (`..` rejected
//     lexically — callers send resolved paths), must exist, must be a regular
//     file, and its FINAL component must not be a symlink. Trusted mirror
//     authorization (Astra item 2, r2) is bound to the REQUESTED FILE, not its
//     bytes: at least one import root MUST be installed (absent roots = deny —
//     the default policy is fail-closed, not "content-membership alone"), the
//     file's CANONICAL location must lie inside a trusted root, and the
//     mirror index (`dc_mirror` of the same SQLCipher store) must hold a row
//     for THAT path (root-relative) recorded with EXACTLY these bytes — a
//     duplicate-content copy at an unregistered path is rejected even though
//     its sha matches some registered row. Authorization and reading share
//     ONE confined file handle (Astra item 3, r2): the authorizing hash and
//     the imported bytes come from the same open file description, so a path
//     swap after authorization cannot substitute different bytes, and an
//     in-place rewrite between the hash and read passes is caught by the
//     final imported-content verification (the just-imported chunks are
//     removed again). Default (no roots, no matching row) = deny all imports.
// Rejections carry a stable "drive: ... rejected" message prefix.

/// Shell-installed confinement policy (Astra desktop-drive-bridge-unconfined
/// #1/#2). The composition root of each shell owns the trusted values — the
/// mirror base dir and the configured server origin — and installs them ONCE
/// via `drive_set_confinement`. The renderer cannot reach this seam: no
/// IPC/bridge channel forwards to it, and renderer-writable SQL (the db_exec
/// keyword allowlist) cannot alter it — it lives in native memory, not in a
/// table. Default is the empty policy: every import and every chunk
/// fetch/push is denied until the shell widens it (fail-closed, preserved per
/// the Astra adjudication).
#[derive(Debug, Default, Clone)]
pub struct DriveConfinement {
    /// Absolute directories a `drive_import_file` src_path must resolve
    /// inside. Empty = deny ALL imports (fail-closed; Astra item 2, r2 —
    /// absent roots no longer fall back to a content-membership gate).
    pub import_roots: Vec<String>,
    /// Exact http(s) origins (`scheme://host[:port]`) a chunk fetch/push URL
    /// must belong to. Empty = deny all chunk network I/O.
    pub approved_origins: Vec<String>,
}

static DRIVE_CONFINEMENT: OnceLock<Mutex<DriveConfinement>> = OnceLock::new();

fn drive_confinement_slot() -> &'static Mutex<DriveConfinement> {
    DRIVE_CONFINEMENT.get_or_init(|| Mutex::new(DriveConfinement::default()))
}

/// Install the TRUSTED shell confinement policy (replaces any previous
/// policy). Process-wide by design: each shell session owns exactly one
/// OfflineCore, and a static keeps this delta inside drive.rs (the struct's
/// fields live in lib.rs). Call it from the composition root — never from
/// anything renderer-reachable.
#[uniffi::export]
pub fn drive_set_confinement(import_roots: Vec<String>, approved_origins: Vec<String>) {
    let mut policy = drive_confinement_slot()
        .lock()
        .expect("drive confinement lock poisoned");
    policy.import_roots = import_roots;
    policy.approved_origins = approved_origins;
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    host == "127.0.0.1" || host == "::1" || host == "localhost" || host.ends_with(".localhost")
}

/// Pure transport floor for chunk URLs: absolute http(s) only; http only for
/// loopback hosts. Returns `Err` with the rejection message otherwise. The
/// trusted approved-ORIGIN allowlist is enforced separately (see
/// `ensure_chunk_origin_allowed`) so the scheme/transport floor stays pure.
fn ensure_chunk_url_transport_allowed(url: &str) -> Result<(), OfflineError> {
    let reject = |why: String| OfflineError::Http(format!("drive: url rejected: {why}"));
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| reject(format!("not an absolute http(s) URL: {url}")))?;
    if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("http") {
        return Err(reject(format!("scheme '{scheme}:' is not http(s)")));
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    // Strip userinfo (everything up to the LAST '@' — '@' may appear in userinfo).
    let host_port = match authority.rsplit_once('@') {
        Some((_, h)) => h,
        None => authority,
    };
    // Strip the port. A bracketed IPv6 literal keeps its colons: split inside
    // the brackets only after the closing ']' has ended the literal.
    let host = if let Some(literal) = host_port.strip_prefix('[') {
        match literal.split_once(']') {
            Some((h, _)) => h,
            None => host_port, // malformed; the loopback/empty checks reject below
        }
    } else {
        match host_port.rsplit_once(':') {
            Some((h, _port)) => h,
            None => host_port,
        }
    };
    if host.is_empty() {
        return Err(reject("empty host".into()));
    }
    if scheme.eq_ignore_ascii_case("http") && !is_loopback_host(host) {
        return Err(reject(
            "cleartext http is loopback-only — the drive bearer must not leave the box unencrypted"
                .into(),
        ));
    }
    Ok(())
}

/// Pure path floor for `drive_import_file`. See the module comment above for
/// the enforced shape and the division of labor with the shell layers.
fn ensure_import_path_constrained(src_path: &str) -> Result<(), OfflineError> {
    let reject = |why: String| OfflineError::Integrity(format!("drive: src_path rejected: {why}"));
    let path = std::path::Path::new(src_path);
    if !path.is_absolute() {
        return Err(reject("path is not absolute".into()));
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(reject(
            "`..` traversal components are not accepted (send a resolved path)".into(),
        ));
    }
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| reject(format!("cannot stat {src_path}: {e}")))?;
    if meta.file_type().is_symlink() {
        return Err(reject("final path component is a symlink".into()));
    }
    if !meta.is_file() {
        return Err(reject("not a regular file".into()));
    }
    Ok(())
}

/// Split an absolute http(s) URL into its parsed-origin triple: lowercased
/// scheme, lowercased host (userinfo stripped, IPv6 literal unbracketed), and
/// the EFFECTIVE port (explicit, or the scheme default — `https://gw` and
/// `https://gw:443` are the same origin, `https://gw:8443` is not). Anything
/// that is not an absolute http(s) URL with a non-empty host parses as `Err`.
fn parse_http_origin(url: &str) -> Result<(String, String, u16), ()> {
    let (scheme_raw, rest) = url.split_once("://").ok_or(())?;
    let scheme = scheme_raw.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => 443u16,
        "http" => 80u16,
        _ => return Err(()),
    };
    let authority = rest.split(['/', '?', '#']).next().ok_or(())?;
    // Strip userinfo (everything up to the LAST '@' — '@' may appear in it).
    let host_port = match authority.rsplit_once('@') {
        Some((_, h)) => h,
        None => authority,
    };
    let (host_raw, port) = if let Some(literal) = host_port.strip_prefix('[') {
        match literal.split_once(']') {
            Some((h, after)) => {
                let port = match after.strip_prefix(':') {
                    Some(p) => p.parse::<u16>().map_err(|_| ())?,
                    None if after.is_empty() => default_port,
                    None => return Err(()),
                };
                (h, port)
            }
            None => return Err(()), // unterminated IPv6 literal
        }
    } else {
        match host_port.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().map_err(|_| ())?),
            None => (host_port, default_port),
        }
    };
    if host_raw.is_empty() {
        return Err(());
    }
    Ok((scheme, host_raw.to_ascii_lowercase(), port))
}

/// Trusted approved-origin policy at the native boundary (Astra item 2): the
/// chunk URL's parsed origin must equal one of the shell-installed origins —
/// before ANY network activity (DNS included). Empty allowlist = deny
/// everything (fail-closed). Runs after the transport floor, before vault
/// bookkeeping and the dial.
fn ensure_chunk_origin_allowed(url: &str) -> Result<(), OfflineError> {
    let reject = |why: String| OfflineError::Http(format!("drive: url rejected: {why}"));
    let (scheme, host, port) = parse_http_origin(url)
        .map_err(|()| reject(format!("not an absolute http(s) URL: {url}")))?;
    let policy = drive_confinement_slot()
        .lock()
        .map_err(|_| OfflineError::Database("drive confinement lock poisoned".into()))?;
    if policy.approved_origins.is_empty() {
        return Err(reject(
            "no approved chunk origins are configured (fail-closed; the shell must install \
             the trusted server origin)"
                .into(),
        ));
    }
    for allowed in &policy.approved_origins {
        if let Ok((s, h, p)) = parse_http_origin(allowed) {
            if s == scheme && h == host && p == port {
                return Ok(());
            }
        }
    }
    Err(reject(format!(
        "origin {scheme}://{host}:{port} is not approved"
    )))
}

/// Stream the whole-file SHA-256 from an ALREADY-OPEN handle (one chunk-sized
/// buffer, single pass). The import loop re-reads the SAME handle afterwards,
/// so an import costs two passes — acceptable: imports are rare, human-
/// initiated, and local disk reads. Hashing the handle (not the path) is the
/// TOCTOU half of Astra item 3, r2: the authorizing hash describes the file
/// description every later read of this import sees.
fn whole_handle_sha256(file: &mut std::fs::File) -> Result<String, OfflineError> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| OfflineError::Database(format!("read: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Trusted mirror-INDEX membership at the native read boundary (Astra item 2,
/// r2): authorization is bound to the REQUESTED FILE — the mirror index must
/// hold a row for this path (root-relative, web-style separators) recorded
/// with EXACTLY these bytes: `dc_mirror.rel_path = ?1 AND disk_sha256 = ?2`
/// of the SAME store the import targets. Content equality alone is NOT
/// membership: an unindexed duplicate of a registered file's bytes is
/// rejected because its path has no row. `dc_mirror` is the disk-index the TS
/// mirror layer maintains (webmail sync schema.ts). A missing table means the
/// mirror layer never ran → nothing is registered → deny (fail-closed).
fn import_membership_registered(
    conn: &Connection,
    rel_path: &str,
    sha: &str,
) -> Result<bool, OfflineError> {
    match conn.query_row(
        "SELECT 1 FROM dc_mirror WHERE rel_path = ?1 AND disk_sha256 = ?2 LIMIT 1",
        [rel_path, sha],
        |_| Ok(()),
    ) {
        Ok(()) => Ok(true),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) if e.to_string().contains("no such table") => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Trusted import-root membership at the native read boundary (Astra item 2,
/// r2): at least one import root MUST be installed — absent roots are a
/// REJECTION, not a fallback (the default import policy is fail-closed
/// outright). When roots are installed, the file's CANONICAL location must
/// lie strictly inside one (canonicalize on BOTH sides, so a legal ancestor
/// symlink such as macOS /tmp → /private/tmp keeps working while a symlinked
/// ancestor escaping the root resolves outside and is rejected). Returns the
/// file's path relative to the matched root ('/'-separated) — the path half
/// of the mirror-index authorization.
fn trusted_import_rel_path(canonical: &std::path::Path) -> Result<String, OfflineError> {
    let policy = drive_confinement_slot()
        .lock()
        .map_err(|_| OfflineError::Database("drive confinement lock poisoned".into()))?;
    if policy.import_roots.is_empty() {
        return Err(OfflineError::Integrity(
            "drive: src_path rejected: no trusted import roots are configured (fail-closed)".into(),
        ));
    }
    for root in &policy.import_roots {
        if let Ok(real_root) = std::fs::canonicalize(root) {
            if canonical != real_root {
                if let Ok(rel) = canonical.strip_prefix(&real_root) {
                    let rel = rel
                        .components()
                        .map(|c| c.as_os_str().to_string_lossy())
                        .collect::<Vec<_>>()
                        .join("/");
                    if !rel.is_empty() {
                        return Ok(rel);
                    }
                }
            }
        }
    }
    Err(OfflineError::Integrity(format!(
        "drive: src_path rejected: resolves outside every trusted import root: {}",
        canonical.display()
    )))
}

#[uniffi::export]
impl OfflineCore {
    /// Native GET → SHA-256/size verify → single-txn insert. Idempotent
    /// (existing row = Ok, no network). Hash/size mismatch ⇒ Integrity, nothing stored.
    pub fn drive_fetch_chunk(
        &self,
        app_key: String,
        url: String,
        bearer: String,
        sha256: String,
        size: u64,
    ) -> Result<(), OfflineError> {
        ensure_chunk_url_transport_allowed(&url)?;
        ensure_chunk_origin_allowed(&url)?; // trusted origin policy, pre-DNS
        if size as usize > CHUNK {
            return Err(OfflineError::Integrity(format!(
                "chunk size {size} exceeds 4 MiB"
            )));
        }
        if self.drive_has_chunk(app_key.clone(), sha256.clone())? {
            return Ok(()); // idempotent — spec §3.6
        }
        let resp = http_agent()?
            .get(&url)
            .set("Authorization", &format!("Bearer {bearer}"))
            .call()
            .map_err(map_ureq)?;
        // stream into ONE chunk-sized buffer (peak memory = one chunk, R1)
        let mut body = Vec::with_capacity(size as usize);
        resp.into_reader()
            .take(size + 1) // +1 detects an oversized body without buffering it
            .read_to_end(&mut body)
            .map_err(|e| OfflineError::Http(format!("body read: {e}")))?;
        if body.len() as u64 != size {
            return Err(OfflineError::Integrity(format!(
                "size mismatch: expected {size}, got {}",
                body.len()
            )));
        }
        let got = hex::encode(Sha256::digest(&body));
        if got != sha256 {
            return Err(OfflineError::Integrity(format!(
                "sha256 mismatch for {url}"
            )));
        }
        self.insert_chunk(&app_key, &sha256, &body)
    }

    /// Native PUT of dc_chunks[sha256]. Returns the HTTP status (the caller/TS
    /// treats the gateway's idempotent re-PUT as success like the web path does).
    pub fn drive_push_chunk(
        &self,
        app_key: String,
        url: String,
        bearer: String,
        sha256: String,
    ) -> Result<u16, OfflineError> {
        ensure_chunk_url_transport_allowed(&url)?;
        ensure_chunk_origin_allowed(&url)?; // trusted origin policy, pre-DNS
        let bytes = self.read_chunk(&app_key, &sha256)?;
        match http_agent()?
            .put(&url)
            .set("Authorization", &format!("Bearer {bearer}"))
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&bytes)
        {
            Ok(resp) => Ok(resp.status()),
            Err(ureq::Error::Status(code, _)) => Ok(code), // status IS the answer (spec: returns HTTP status)
            Err(e) => Err(map_ureq(e)),
        }
    }
}

#[uniffi::export]
impl OfflineCore {
    /// Import a local plaintext file: stream-read, split at 4 MiB, per-chunk
    /// SHA-256, INSERT OR IGNORE. Returns the manifest JSON (§3.6). Plaintext
    /// source deletion is the CALLER's decision — this function never deletes
    /// `src_path`.
    ///
    /// Native confinement floor (see `ensure_import_path_constrained` and the
    /// module comment): only absolute, traversal-free, regular, non-symlink
    /// files are readable here, AND the trusted mirror policy applies — at
    /// least one import root must be installed (Astra item 2, r2), the file
    /// must resolve inside one, and the mirror index must hold a row for its
    /// root-relative PATH recorded with exactly its bytes. Authorization and
    /// import read ONE confined handle (Astra item 3, r2), and the imported
    /// content is verified against the authorizing hash before the manifest
    /// is returned. The shell layers stack their own membership checks on top
    /// of this floor.
    pub fn drive_import_file(
        &self,
        app_key: String,
        src_path: String,
    ) -> Result<String, OfflineError> {
        ensure_import_path_constrained(&src_path)?;
        // Trusted import-root membership (Astra item 2, r2): roots are
        // REQUIRED (absent roots deny), and the matched root yields the
        // root-relative path that binds the mirror-index authorization to
        // THIS file — not merely to this content. Canonicalize on both sides
        // so a symlinked ANCESTOR escaping the root resolves outside and is
        // rejected.
        let canonical = std::fs::canonicalize(&src_path).map_err(|e| {
            OfflineError::Integrity(format!(
                "drive: src_path rejected: cannot resolve {src_path}: {e}"
            ))
        })?;
        let rel_path = trusted_import_rel_path(&canonical)?;
        // ONE confined handle for authorization AND import (Astra item 3,
        // r2): the authorizing hash and the imported bytes both come from this
        // open file description, so swapping the file at `src_path` after this
        // point cannot change what is read.
        let mut file = std::fs::File::open(&src_path)
            .map_err(|e| OfflineError::Database(format!("open {src_path}: {e}")))?;
        let authorized_sha = whole_handle_sha256(&mut file)?;
        let registered = self.with_drive_conn(&app_key, |conn| {
            import_membership_registered(conn, &rel_path, &authorized_sha)
        })?;
        if !registered {
            return Err(OfflineError::Integrity(format!(
                "drive: src_path rejected: not a registered mirrored file (mirror-index \
                 membership required): {src_path}"
            )));
        }
        self.drive_import_verified_from_handle(&app_key, &mut file, &authorized_sha)
    }

    pub fn drive_has_chunk(&self, app_key: String, sha256: String) -> Result<bool, OfflineError> {
        self.with_drive_conn(&app_key, |conn| {
            Ok(conn
                .query_row(
                    "SELECT 1 FROM dc_chunks WHERE sha256 = ?1",
                    [&sha256],
                    |_| Ok(()),
                )
                .is_ok())
        })
    }

    /// Eviction primitive — LRU/pin POLICY is TS; deletion is native (§3.6).
    pub fn drive_delete_chunks(
        &self,
        app_key: String,
        sha256s_json: String,
    ) -> Result<u64, OfflineError> {
        let shas: Vec<String> = serde_json::from_str(&sha256s_json)?;
        self.with_drive_conn(&app_key, |conn| {
            let mut n = 0u64;
            for sha in &shas {
                n += conn.execute("DELETE FROM dc_chunks WHERE sha256 = ?1", [sha])? as u64;
            }
            Ok(n)
        })
    }
}

impl OfflineCore {
    /// Second pass of the confined import (Astra item 3, r2): stream the
    /// ALREADY-AUTHORIZED open file handle into the vault, then VERIFY the
    /// imported content against the authorized hash before returning the
    /// manifest. Authorization (`drive_import_file`'s hash + mirror-index
    /// membership) and reading are bound to the SAME file description: a path
    /// swap after authorization cannot substitute different bytes, and an
    /// in-place rewrite between the hash and read passes is caught here — the
    /// chunks this call inserted are removed again before failing.
    ///
    /// Deliberately NOT `#[uniffi::export]`ed (a `File` parameter cannot cross
    /// the UniFFI/JS boundary): this is `pub` for the offline-core integration
    /// tests that pin the TOCTOU verification, not a binding surface.
    pub fn drive_import_verified_from_handle(
        &self,
        app_key: &str,
        file: &mut std::fs::File,
        authorized_sha256: &str,
    ) -> Result<String, OfflineError> {
        use std::io::Seek;
        file.rewind()
            .map_err(|e| OfflineError::Database(format!("rewind: {e}")))?;
        let mut whole = Sha256::new();
        let mut total: u64 = 0;
        let mut chunks_json = Vec::new();
        let mut inserted: Vec<String> = Vec::new();
        let mut buf = vec![0u8; CHUNK];
        loop {
            // fill up to CHUNK (Read::read may return short counts on any source)
            let mut filled = 0;
            while filled < CHUNK {
                let n = file
                    .read(&mut buf[filled..])
                    .map_err(|e| OfflineError::Database(format!("read: {e}")))?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                break;
            }
            let chunk = &buf[..filled];
            whole.update(chunk);
            total += filled as u64;
            let sha = hex::encode(Sha256::digest(chunk));
            // Track only chunks THIS import actually added, so a verification
            // failure rolls the import back without evicting a pre-existing
            // identical chunk another fetch/import legitimately stored.
            if !self.drive_has_chunk(app_key.to_string(), sha.clone())? {
                self.insert_chunk(app_key, &sha, chunk)?;
                inserted.push(sha.clone());
            }
            chunks_json.push(serde_json::json!({ "sha256": sha, "size": filled }));
            if filled < CHUNK {
                break;
            }
        }
        let imported_sha = hex::encode(whole.finalize());
        if imported_sha != authorized_sha256 {
            for sha in &inserted {
                self.with_drive_conn(app_key, |conn| {
                    conn.execute("DELETE FROM dc_chunks WHERE sha256 = ?1", [sha])?;
                    Ok(())
                })?;
            }
            return Err(OfflineError::Integrity(
                "drive: import rejected: file changed during import (imported content does \
                 not match the authorized hash)"
                    .into(),
            ));
        }
        Ok(serde_json::json!({
            "contentSha256": imported_sha,
            "size": total,
            "chunks": chunks_json,
        })
        .to_string())
    }
}

// ── Loopback render server (Range-capable, ticketed) ────────────────────────
//
// Binds 127.0.0.1 only, ephemeral port, 128-bit random tickets, single-manifest
// per ticket, `Cache-Control: no-store`. The ticket IS the capability — no auth
// cookie, no CORS header. One blocking thread per app_key (a viewer serves one
// user at a time — ADR-017).

pub(crate) struct ServeHandle {
    port: u16,
    tickets: Arc<Mutex<StdHashMap<String, Manifest>>>,
    stop: Arc<AtomicBool>,
    server: Arc<tiny_http::Server>,
    join: Option<std::thread::JoinHandle<()>>,
}

/// Parse one satisfiable byte-range (`bytes=start-end` / `bytes=start-` /
/// `bytes=-suffixLen`). Multi-range and unsatisfiable ranges return `None`
/// (caller maps that to 416, per the single-range scope of this server).
fn parse_range(header: &str, total: u64) -> Option<(u64, u64)> {
    let spec = header.strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    } // multi-range: fall back to 200 full
    if let Some(n) = spec.strip_prefix('-') {
        let n: u64 = n.parse().ok()?;
        if n == 0 || total == 0 {
            return None;
        }
        return Some((total.saturating_sub(n), total - 1));
    }
    let (a, b) = spec.split_once('-')?;
    let start: u64 = a.parse().ok()?;
    if start >= total {
        return None;
    }
    let end = if b.is_empty() {
        total - 1
    } else {
        b.parse::<u64>().ok()?.min(total - 1)
    };
    if end < start {
        return None;
    }
    Some((start, end))
}

/// Streams `[start, start+len)` of a manifest by walking chunks. Reads ONE chunk
/// from SQLCipher at a time (fixed 4 MiB ⇒ ordinal = pos / CHUNK, O(1) seek) and
/// serves slices from a small cache — peak memory: one chunk.
struct ManifestReader {
    core: Arc<OfflineCore>,
    app_key: String,
    chunks: Vec<ChunkRef>,
    pos: u64,
    remaining: u64,
    cached: Option<(usize, Vec<u8>)>, // (ordinal, bytes)
}

impl Read for ManifestReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let ordinal = (self.pos / CHUNK as u64) as usize;
        let offset = (self.pos % CHUNK as u64) as usize;
        if self.cached.as_ref().map(|(o, _)| *o) != Some(ordinal) {
            let sha = &self
                .chunks
                .get(ordinal)
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "past manifest")
                })?
                .sha256;
            let bytes = self
                .core
                .read_chunk(&self.app_key, sha)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()))?;
            self.cached = Some((ordinal, bytes));
        }
        let (_, chunk) = self.cached.as_ref().unwrap();
        let avail = chunk.len().saturating_sub(offset);
        let n = out.len().min(avail).min(self.remaining as usize);
        if n == 0 {
            return Ok(0);
        }
        out[..n].copy_from_slice(&chunk[offset..offset + n]);
        self.pos += n as u64;
        self.remaining -= n as u64;
        Ok(n)
    }
}

fn respond(
    req: tiny_http::Request,
    core: &Arc<OfflineCore>,
    app_key: &str,
    tickets: &Arc<Mutex<StdHashMap<String, Manifest>>>,
) {
    let url = req.url().to_string();
    let Some(ticket) = url.strip_prefix("/t/") else {
        let _ = req.respond(tiny_http::Response::empty(404));
        return;
    };
    let Some(m) = tickets.lock().ok().and_then(|t| t.get(ticket).cloned()) else {
        let _ = req.respond(tiny_http::Response::empty(404));
        return;
    };
    let range = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Range"))
        .map(|h| h.value.as_str().to_string());
    let hdr = |k: &str, v: &str| tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap();
    let ct = m
        .content_type
        .clone()
        .unwrap_or_else(|| "application/octet-stream".into());
    let common = [
        hdr("Cache-Control", "no-store"),
        hdr("Accept-Ranges", "bytes"),
        hdr("Content-Type", &ct),
    ];
    let (status, start, len, extra) = match range.as_deref().map(|r| parse_range(r, m.size)) {
        Some(Some((s, e))) => (
            206,
            s,
            e - s + 1,
            Some(hdr("Content-Range", &format!("bytes {s}-{e}/{}", m.size))),
        ),
        Some(None) => {
            let mut resp = tiny_http::Response::empty(416)
                .with_header(hdr("Content-Range", &format!("bytes */{}", m.size)));
            for h in common {
                resp.add_header(h);
            }
            let _ = req.respond(resp);
            return;
        }
        None => (200, 0, m.size, None),
    };
    let reader = ManifestReader {
        core: core.clone(),
        app_key: app_key.to_string(),
        chunks: m.chunks.clone(),
        pos: start,
        remaining: len,
        cached: None,
    };
    let mut resp = tiny_http::Response::new(
        tiny_http::StatusCode(status),
        Vec::new(),
        reader,
        Some(len as usize),
        None,
    );
    for h in common {
        resp.add_header(h);
    }
    if let Some(h) = extra {
        resp.add_header(h);
    }
    let _ = req.respond(resp);
}

#[uniffi::export]
impl OfflineCore {
    /// Bind 127.0.0.1 on an ephemeral port; one blocking thread (a viewer serves
    /// one user — ADR-017). Returns `{"port":N}`. Idempotent per app_key.
    ///
    /// OFFSTORE-SERVE-START-TOCTOU: the serves mutex is held across the
    /// idempotence check, the bind, the thread spawn, AND the insert. The old
    /// check-then-act (drop the lock between `get` and `insert`) let two
    /// concurrent starts for the same app_key each bind a listener, and the
    /// second `insert` orphan the first — an unstoppable listener outside
    /// stop/revoke/wipe. No lock-ordering hazard: every other path takes the
    /// serves lock alone (grant/revoke/stop) or serves-then-stores without
    /// nesting (`wipe`), and the serve thread takes only the stores lock.
    pub fn drive_serve_start(self: Arc<Self>, app_key: String) -> Result<String, OfflineError> {
        let mut serves = self
            .serves
            .lock()
            .map_err(|_| OfflineError::Database("lock poisoned".into()))?;
        if let Some(h) = serves.get(&app_key) {
            return Ok(serde_json::json!({ "port": h.port }).to_string());
        }
        // Fail fast if the store isn't open (don't serve a vault that can't decrypt).
        self.with_drive_conn(&app_key, |_| Ok(()))?;
        let server = Arc::new(
            tiny_http::Server::http("127.0.0.1:0")
                .map_err(|e| OfflineError::Database(format!("loopback bind: {e}")))?,
        );
        let port = match server.server_addr() {
            tiny_http::ListenAddr::IP(a) => a.port(),
            _ => return Err(OfflineError::Database("loopback: non-IP addr".into())),
        };
        let tickets: Arc<Mutex<StdHashMap<String, Manifest>>> =
            Arc::new(Mutex::new(StdHashMap::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (core, key, srv, tks, stp) = (
            self.clone(),
            app_key.clone(),
            server.clone(),
            tickets.clone(),
            stop.clone(),
        );
        let join = std::thread::Builder::new()
            .name(format!("drive-serve-{app_key}"))
            .spawn(move || loop {
                match srv.recv() {
                    Ok(req) => respond(req, &core, &key, &tks),
                    Err(_) => {
                        if stp.load(Ordering::SeqCst) {
                            break;
                        }
                    }
                }
            })
            .map_err(|e| OfflineError::Database(format!("serve thread: {e}")))?;
        serves.insert(
            app_key,
            ServeHandle {
                port,
                tickets,
                stop,
                server,
                join: Some(join),
            },
        );
        Ok(serde_json::json!({ "port": port }).to_string())
    }

    /// Register a one-open ticket for a manifest. Returns "/t/<32-hex>". Fails at
    /// grant time (not first byte) if any referenced chunk is missing from the
    /// vault — every chunk must already be imported/fetched.
    pub fn drive_serve_grant(
        &self,
        app_key: String,
        manifest_json: String,
    ) -> Result<String, OfflineError> {
        let m: Manifest = serde_json::from_str(&manifest_json)?;
        for c in &m.chunks {
            if !self.drive_has_chunk(app_key.clone(), c.sha256.clone())? {
                return Err(OfflineError::Database(format!(
                    "chunk {} not in vault",
                    c.sha256
                )));
            }
        }
        let mut b = [0u8; 16];
        rand::rng().fill_bytes(&mut b); // 128-bit random ticket (spec §3.6)
        let ticket = hex::encode(b);
        let serves = self
            .serves
            .lock()
            .map_err(|_| OfflineError::Database("lock poisoned".into()))?;
        let h = serves
            .get(&app_key)
            .ok_or_else(|| OfflineError::Database("serve not started".into()))?;
        h.tickets
            .lock()
            .map_err(|_| OfflineError::Database("lock poisoned".into()))?
            .insert(ticket.clone(), m);
        Ok(format!("/t/{ticket}"))
    }

    pub fn drive_serve_revoke(&self, app_key: String, ticket: String) -> Result<(), OfflineError> {
        let serves = self
            .serves
            .lock()
            .map_err(|_| OfflineError::Database("lock poisoned".into()))?;
        if let Some(h) = serves.get(&app_key) {
            h.tickets
                .lock()
                .map_err(|_| OfflineError::Database("lock poisoned".into()))?
                .remove(ticket.trim_start_matches("/t/"));
        }
        Ok(())
    }

    /// Stop the listener + revoke all tickets. Idempotent. Also called by `wipe()`
    /// (BEFORE it takes the stores lock — see the ordering note there).
    pub fn drive_serve_stop(&self, app_key: String) -> Result<(), OfflineError> {
        let handle = {
            let mut serves = self
                .serves
                .lock()
                .map_err(|_| OfflineError::Database("lock poisoned".into()))?;
            serves.remove(&app_key)
        };
        if let Some(mut h) = handle {
            h.stop.store(true, Ordering::SeqCst);
            h.server.unblock();
            if let Some(j) = h.join.take() {
                let _ = j.join();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod confinement_tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn chunk_url_floor_accepts_https_anywhere_and_loopback_http() {
        for url in [
            "https://gateway.corp.example/api/drive/chunks/abc",
            "https://127.0.0.1:9/ch",
            "http://127.0.0.1:8080/ch",
            "http://localhost:5173/ch",
            "http://[::1]:9000/ch",
            "http://build.localhost/ch",
        ] {
            assert!(
                ensure_chunk_url_transport_allowed(url).is_ok(),
                "must pass the transport floor: {url}"
            );
        }
    }

    #[test]
    fn chunk_url_floor_rejects_cleartext_nonloopback_and_non_http() {
        for url in [
            "http://gateway.corp.example/api/drive/chunks/abc", // cleartext off-box
            "http://192.168.1.5/ch",
            "http://127.0.0.1.evil.example/ch", // loopback lookalike is NOT loopback
            "http://0x7f000001/ch",
            "file:///etc/passwd",
            "ftp://gateway/ch",
            "data:text/plain,hi",
            "/api/drive/chunks/abc?space=1", // relative — would fail in ureq anyway
            "not a url",
            "https://", // empty host
        ] {
            assert!(
                ensure_chunk_url_transport_allowed(url).is_err(),
                "must be rejected by the transport floor: {url}"
            );
        }
    }

    #[test]
    fn chunk_url_floor_strips_userinfo_and_ipv6_ports() {
        // userinfo must not mask the real host
        assert!(ensure_chunk_url_transport_allowed("http://user@127.0.0.1/ch").is_ok());
        assert!(ensure_chunk_url_transport_allowed("http://user@evil.example/ch").is_err());
        // bracketed IPv6 with port: the port split must not mangle the host
        assert!(ensure_chunk_url_transport_allowed("http://[::1]:8080/ch").is_ok());
        assert!(ensure_chunk_url_transport_allowed("http://[fe80::1]:8080/ch").is_err());
        assert!(ensure_chunk_url_transport_allowed("https://[fe80::1]:8080/ch").is_ok());
    }

    #[test]
    fn parse_http_origin_normalizes_scheme_host_and_effective_port() {
        let (s, h, p) = parse_http_origin("HTTPS://Gw.Example:443/api/x").unwrap();
        assert_eq!((s.as_str(), h.as_str(), p), ("https", "gw.example", 443));
        // default ports are elided: explicit 443 == no port
        assert_eq!(
            parse_http_origin("https://gw.example/api/x").unwrap(),
            parse_http_origin("https://gw.example:443/api/x").unwrap()
        );
        assert_eq!(
            parse_http_origin("http://gw.example/x").unwrap(),
            parse_http_origin("http://gw.example:80/x").unwrap()
        );
        // an explicit non-default port is part of the origin
        let (_, _, p) = parse_http_origin("https://gw.example:8443/x").unwrap();
        assert_eq!(p, 8443);
        // userinfo and paths never contaminate the host
        assert_eq!(
            parse_http_origin("https://u:p@gw.example:8443/a?b#c").unwrap(),
            ("https".into(), "gw.example".into(), 8443)
        );
        // IPv6 literals keep their host, drop their brackets
        assert_eq!(
            parse_http_origin("http://[::1]:9000/x").unwrap(),
            ("http".into(), "::1".into(), 9000)
        );
        // malformed shapes parse as Err
        for bad in [
            "ftp://gw.example/x",
            "file:///etc/passwd",
            "/relative/path",
            "https://",
            "https://gw.example:notaport/x",
            "https://[::1/x",
        ] {
            assert!(parse_http_origin(bad).is_err(), "must not parse: {bad}");
        }
    }

    #[test]
    fn import_path_floor_accepts_plain_absolute_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("src.bin");
        std::fs::File::create(&p).unwrap().write_all(b"x").unwrap();
        let src = p.to_string_lossy().to_string();
        assert!(ensure_import_path_constrained(&src).is_ok());
    }

    #[test]
    fn import_path_floor_rejects_relative_traversal_and_missing() {
        assert!(ensure_import_path_constrained("relative/src.bin").is_err());
        assert!(ensure_import_path_constrained("/abs/../../etc/passwd").is_err());
        assert!(ensure_import_path_constrained("/definitely/missing/file.bin").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn import_path_floor_rejects_symlinked_file_and_directory() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("src.bin");
        std::fs::File::create(&real)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let link = dir.path().join("link.bin");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(ensure_import_path_constrained(&link.to_string_lossy()).is_err());
        // a directory is not a regular file
        assert!(ensure_import_path_constrained(&dir.path().to_string_lossy()).is_err());
    }
}
