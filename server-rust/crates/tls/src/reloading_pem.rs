//! Pure-rustls, DoS-resistant, non-blocking PEM certificate hot-reloader (#559).
//!
//! `ReloadingPem` loads a PEM certificate chain and private key from disk at
//! startup (failing closed on missing, corrupt, oversized, non-regular, or
//! mismatched files) and watches for on-disk updates using subsecond file
//! metadata signatures (`std::fs::metadata`, which follows symlinks such as
//! `/etc/letsencrypt/live/...`).
//!
//! Concurrency and availability invariants:
//! - Disk I/O and PEM parsing NEVER run while holding the `RwLock` write lock.
//! - At most one thread reloads at a time (`reloading: Mutex<()>` via `try_lock`);
//!   concurrent handshakes immediately receive the last-known-good `Arc<CertifiedKey>`.
//! - Stat calls are debounced by `check_interval` (default `1s`).
//! - Repeated failures on the exact same `(cert_sig, key_sig)` pair are throttled
//!   by `failure_cooldown` (default `3s`), while ANY new `FileSig` on either file
//!   triggers an immediate reload attempt so two-file rotations recover on the very
//!   next handshake.
//! - Reads are verified against regular files (`metadata.is_file()`) and bounded
//!   to `1 MiB` (`Read::take((1 << 20) + 1)`) so misconfigured FIFOs, devices, or
//!   oversized files can never hang or OOM a handshake thread.

use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    sign::CertifiedKey,
};
use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock, TryLockError,
    },
    time::{Duration, Instant},
};

/// Maximum accepted PEM file size (1 MiB). Reads take `(1 << 20) + 1` bytes so
/// files strictly larger than 1 MiB are detected and rejected without reading
/// unbounded data into memory.
const MAX_PEM_BYTES: usize = 1 << 20;

/// Default stat debounce window between metadata checks on active listeners.
pub const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Default cooldown before retrying the exact same failing `(cert_sig, key_sig)`.
pub const DEFAULT_FAILURE_COOLDOWN: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileSig {
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    len: u64,
}

impl FileSig {
    #[cfg(unix)]
    fn from_metadata(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            len: meta.len(),
        }
    }

    #[cfg(not(unix))]
    fn from_metadata(meta: &std::fs::Metadata) -> Self {
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .unwrap_or_default();
        Self {
            dev: 0,
            ino: 0,
            mtime: modified.as_secs() as i64,
            mtime_nsec: modified.subsec_nanos() as i64,
            ctime: 0,
            ctime_nsec: 0,
            len: meta.len(),
        }
    }

    fn read(path: &Path) -> io::Result<Self> {
        let meta = std::fs::metadata(path)?;
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        Ok(Self::from_metadata(&meta))
    }
}

fn read_bounded_pem(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{label} {}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{label} {}: not a regular file", path.display()));
    }
    let file = File::open(path).map_err(|e| format!("{label} {}: {e}", path.display()))?;
    let fmeta = file
        .metadata()
        .map_err(|e| format!("{label} {}: {e}", path.display()))?;
    if !fmeta.is_file() {
        return Err(format!("{label} {}: not a regular file", path.display()));
    }
    let mut buf = Vec::new();
    file.take((1u64 << 20) + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{label} {}: {e}", path.display()))?;
    if buf.len() > MAX_PEM_BYTES {
        return Err(format!(
            "{label} {}: exceeds {} byte limit",
            path.display(),
            MAX_PEM_BYTES
        ));
    }
    Ok(buf)
}

fn load_pair(cert_path: &Path, key_path: &Path) -> Result<Arc<CertifiedKey>, String> {
    let cert_bytes = read_bounded_pem(cert_path, "TLS certificate")?;
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("TLS certificate {}: {e}", cert_path.display()))?;
    if chain.is_empty() {
        return Err(format!(
            "TLS certificate {}: no certificate",
            cert_path.display()
        ));
    }
    let key_bytes = read_bounded_pem(key_path, "TLS key")?;
    let key = PrivateKeyDer::from_pem_slice(&key_bytes)
        .map_err(|e| format!("TLS key {}: {e}", key_path.display()))?;
    let certified = CertifiedKey::from_der(chain, key, &rustls::crypto::ring::default_provider())
        .map_err(|e| format!("TLS certificate/key pair: {e}"))?;
    certified
        .keys_match()
        .map_err(|e| format!("TLS certificate/key pair: {e}"))?;
    Ok(Arc::new(certified))
}

struct State {
    certified: Arc<CertifiedKey>,
    cert_sig: FileSig,
    key_sig: FileSig,
    last_checked: Instant,
    last_failed: Option<(FileSig, FileSig, Instant)>,
}

/// Hot-reloading PEM server/client certificate resolver backed by pure `rustls`.
pub struct ReloadingPem {
    cert_path: PathBuf,
    key_path: PathBuf,
    check_interval: Duration,
    failure_cooldown: Duration,
    state: RwLock<State>,
    reloading: Mutex<()>,
    reload_attempts: AtomicU64,
}

impl std::fmt::Debug for ReloadingPem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReloadingPem")
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .field("check_interval", &self.check_interval)
            .field("failure_cooldown", &self.failure_cooldown)
            .finish()
    }
}

impl ReloadingPem {
    /// Load and validate a certificate chain and private key with production
    /// debounce (`1s`) and failure cooldown (`3s`).
    pub fn load(
        cert_path: impl Into<PathBuf>,
        key_path: impl Into<PathBuf>,
    ) -> Result<Self, String> {
        Self::load_with_intervals(
            cert_path,
            key_path,
            DEFAULT_CHECK_INTERVAL,
            DEFAULT_FAILURE_COOLDOWN,
        )
    }

    /// Load and validate a certificate chain and private key with explicit
    /// stat-debounce and failure-cooldown intervals (e.g. `Duration::ZERO` in
    /// deterministic tests).
    pub fn load_with_intervals(
        cert_path: impl Into<PathBuf>,
        key_path: impl Into<PathBuf>,
        check_interval: Duration,
        failure_cooldown: Duration,
    ) -> Result<Self, String> {
        let cert_path = cert_path.into();
        let key_path = key_path.into();
        let cert_sig = FileSig::read(&cert_path)
            .map_err(|e| format!("TLS certificate {}: {e}", cert_path.display()))?;
        let key_sig =
            FileSig::read(&key_path).map_err(|e| format!("TLS key {}: {e}", key_path.display()))?;
        let certified = load_pair(&cert_path, &key_path)?;
        Ok(Self {
            cert_path,
            key_path,
            check_interval,
            failure_cooldown,
            state: RwLock::new(State {
                certified,
                cert_sig,
                key_sig,
                last_checked: Instant::now(),
                last_failed: None,
            }),
            reloading: Mutex::new(()),
            reload_attempts: AtomicU64::new(0),
        })
    }

    /// Return the currently active `CertifiedKey`, transparently reloading from
    /// disk when the debounce window has elapsed and either file's metadata
    /// signature changed. Never blocks concurrent callers on disk I/O and
    /// always retains the last-known-good key on transient or corrupt updates.
    pub fn current(&self) -> Arc<CertifiedKey> {
        let now = Instant::now();
        let fallback = {
            let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
            if now.duration_since(guard.last_checked) < self.check_interval {
                return Arc::clone(&guard.certified);
            }
            Arc::clone(&guard.certified)
        };

        let _reload_guard = match self.reloading.try_lock() {
            Ok(g) => g,
            Err(TryLockError::WouldBlock) => return fallback,
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
        };

        let now = Instant::now();
        let (cur_cert_sig, cur_key_sig, last_failed) = {
            let guard = self.state.read().unwrap_or_else(|e| e.into_inner());
            if now.duration_since(guard.last_checked) < self.check_interval {
                return Arc::clone(&guard.certified);
            }
            (guard.cert_sig, guard.key_sig, guard.last_failed)
        };

        let (Ok(new_cert_sig), Ok(new_key_sig)) = (
            FileSig::read(&self.cert_path),
            FileSig::read(&self.key_path),
        ) else {
            let mut w = self.state.write().unwrap_or_else(|e| e.into_inner());
            w.last_checked = Instant::now();
            return Arc::clone(&w.certified);
        };

        if new_cert_sig == cur_cert_sig && new_key_sig == cur_key_sig {
            let mut w = self.state.write().unwrap_or_else(|e| e.into_inner());
            w.last_checked = Instant::now();
            return Arc::clone(&w.certified);
        }

        if let Some((fail_c, fail_k, fail_at)) = last_failed {
            if fail_c == new_cert_sig
                && fail_k == new_key_sig
                && now.duration_since(fail_at) < self.failure_cooldown
            {
                let mut w = self.state.write().unwrap_or_else(|e| e.into_inner());
                w.last_checked = Instant::now();
                return Arc::clone(&w.certified);
            }
        }

        self.reload_attempts.fetch_add(1, Ordering::Relaxed);
        match load_pair(&self.cert_path, &self.key_path) {
            Ok(new_certified) => {
                let mut w = self.state.write().unwrap_or_else(|e| e.into_inner());
                w.certified = Arc::clone(&new_certified);
                w.cert_sig = new_cert_sig;
                w.key_sig = new_key_sig;
                w.last_checked = Instant::now();
                w.last_failed = None;
                new_certified
            }
            Err(err) => {
                eprintln!(
                    "setjoin-tls: PEM hot-reload failed, retaining previous certificate: {err}"
                );
                let mut w = self.state.write().unwrap_or_else(|e| e.into_inner());
                let failed_at = Instant::now();
                w.last_checked = failed_at;
                w.last_failed = Some((new_cert_sig, new_key_sig, failed_at));
                Arc::clone(&w.certified)
            }
        }
    }

    /// The currently served certificate chain (including any rotated leaf).
    pub fn served_chain(&self) -> Vec<CertificateDer<'static>> {
        self.current().cert.clone()
    }

    /// Number of disk reload attempts performed since startup (diagnostics / tests).
    pub fn reload_attempts(&self) -> u64 {
        self.reload_attempts.load(Ordering::Relaxed)
    }
}

impl rustls::server::ResolvesServerCert for ReloadingPem {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

impl rustls::client::ResolvesClientCert for ReloadingPem {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        let key = self.current();
        key.key.choose_scheme(sigschemes).map(|_| key)
    }

    fn has_certs(&self) -> bool {
        true
    }
}
