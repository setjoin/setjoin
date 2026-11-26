//! Configuration and hard memory/concurrency bounds for `setjoin-search` (#556).

use crate::model::SearchError;
use ring::rand::{SecureRandom, SystemRandom};
use std::path::PathBuf;
use std::time::Duration;

/// Default private local search index root (strictly outside `PGDATA` and `pg_dump`).
pub const DEFAULT_INDEX_DIR: &str = "/var/lib/setjoin/search";

/// Minimum Tantivy single-thread writer arena budget (15 MB).
pub const MIN_WRITER_HEAP_BYTES: usize = 15_000_000;

/// Default Tantivy single-thread writer arena budget (32 MB).
pub const DEFAULT_WRITER_HEAP_BYTES: usize = 32_000_000;

/// Hard upper cap for Tantivy writer heap budget (50 MB, non-negotiable).
pub const MAX_WRITER_HEAP_BYTES: usize = 50_000_000;

/// Default maximum concurrent blocking Tantivy search tasks.
pub const DEFAULT_MAX_CONCURRENT_SEARCHES: usize = 4;

/// Default wall-clock budget for a Tier-2 candidate search before Tier-1 fallback.
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_millis(250);

/// Maximum documents accepted in a single ingest batch.
pub const MAX_INFLIGHT_DOCS: usize = 2_000;

/// Maximum aggregate text bytes accepted in a single ingest batch (16 MB).
pub const MAX_INFLIGHT_BYTES: usize = 16_000_000;

/// Maximum per-document body text bytes indexed into Tantivy (512 KB).
pub const MAX_DOC_BODY_BYTES: usize = 512_000;

/// Clamp any requested writer heap budget strictly into `[15 MB, 50 MB]`.
#[must_use]
pub const fn clamp_writer_heap_bytes(requested: usize) -> usize {
    if requested < MIN_WRITER_HEAP_BYTES {
        MIN_WRITER_HEAP_BYTES
    } else if requested > MAX_WRITER_HEAP_BYTES {
        MAX_WRITER_HEAP_BYTES
    } else {
        requested
    }
}

/// Runtime configuration for the two-tier search subsystem.
#[derive(Clone, Debug)]
pub struct SearchConfig {
    /// Opt-in gate for Tier-2 Tantivy indexing & routing (default: `false`).
    /// Controlled via `SETJOIN_SEARCH_TIER2_ENABLED=true` (zero `feature_toggles` churn).
    pub tier2_enabled: bool,
    /// Private local root for `CURRENT`, `rebuild.lock`, and `epochs/index-vNNNNNN/`.
    pub index_dir: PathBuf,
    /// Clamped writer heap budget in `[15_000_000, 50_000_000]` bytes (default 32 MB).
    pub writer_heap_bytes: usize,
    /// Bounded semaphore permits for `spawn_blocking` Tantivy searches (default 4).
    pub max_concurrent_searches: usize,
    /// Per-query Tier-2 timeout before transparent Tier-1 fallback (default 250ms).
    pub query_timeout: Duration,
    /// Optional external MIT Jieba dictionary path (e.g. `/usr/share/setjoin/dicts/jieba.txt`).
    pub zh_dict_path: Option<PathBuf>,
    /// Secret key for HMAC-SHA256 binding of opaque continuation cursors.
    pub cursor_secret: Vec<u8>,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            tier2_enabled: false,
            index_dir: PathBuf::from(DEFAULT_INDEX_DIR),
            writer_heap_bytes: DEFAULT_WRITER_HEAP_BYTES,
            max_concurrent_searches: DEFAULT_MAX_CONCURRENT_SEARCHES,
            query_timeout: DEFAULT_QUERY_TIMEOUT,
            zh_dict_path: None,
            // Fail closed (empty secret -> cursor mint/verify returns Unavailable) if OS CSPRNG fails.
            cursor_secret: generate_cursor_secret()
                .map(|k| k.to_vec())
                .unwrap_or_default(),
        }
    }
}

impl SearchConfig {
    /// Construct a default configuration, failing closed if the OS CSPRNG is unavailable.
    pub fn try_default() -> Result<Self, SearchError> {
        Ok(Self {
            cursor_secret: generate_cursor_secret()?.to_vec(),
            ..Self::default()
        })
    }
    /// Load configuration from process environment variables.
    ///
    /// - `SETJOIN_SEARCH_TIER2_ENABLED`: `"true"` or `"1"` enables Tier-2 (default OFF).
    /// - `SETJOIN_SEARCH_INDEX_DIR`: local search directory (default `/var/lib/setjoin/search`).
    /// - `SETJOIN_SEARCH_WRITER_HEAP_BYTES`: clamped to `[15_000_000, 50_000_000]` (default `32_000_000`).
    /// - `SETJOIN_SEARCH_MAX_CONCURRENCY`: clamped to `[1, 16]` (default `4`).
    /// - `SETJOIN_SEARCH_QUERY_TIMEOUT_MS`: clamped to `[25, 2_000]` (default `250`).
    /// - `SETJOIN_SEARCH_ZH_DICT_PATH`: optional external Jieba dictionary file.
    /// - `SETJOIN_SEARCH_CURSOR_KEY`: optional HMAC key for opaque cursors.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(&|name| std::env::var(name).ok())
    }

    /// Load configuration from an explicit key-value lookup closure (deterministic in tests).
    #[must_use]
    pub fn from_lookup(get: &dyn Fn(&str) -> Option<String>) -> Self {
        let tier2_enabled = get("SETJOIN_SEARCH_TIER2_ENABLED")
            .as_deref()
            .is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1");

        let index_dir = get("SETJOIN_SEARCH_INDEX_DIR")
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_INDEX_DIR));

        let writer_heap_bytes = get("SETJOIN_SEARCH_WRITER_HEAP_BYTES")
            .and_then(|s| s.trim().parse::<usize>().ok())
            .map(clamp_writer_heap_bytes)
            .unwrap_or(DEFAULT_WRITER_HEAP_BYTES);

        let max_concurrent_searches = get("SETJOIN_SEARCH_MAX_CONCURRENCY")
            .and_then(|s| s.trim().parse::<usize>().ok())
            .map(|n| n.clamp(1, 16))
            .unwrap_or(DEFAULT_MAX_CONCURRENT_SEARCHES);

        let query_timeout = get("SETJOIN_SEARCH_QUERY_TIMEOUT_MS")
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|ms| Duration::from_millis(ms.clamp(25, 2_000)))
            .unwrap_or(DEFAULT_QUERY_TIMEOUT);

        let zh_dict_path = get("SETJOIN_SEARCH_ZH_DICT_PATH")
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from);

        let cursor_secret = get("SETJOIN_SEARCH_CURSOR_KEY")
            .filter(|s| !s.is_empty())
            .map(|s| s.into_bytes())
            .unwrap_or_else(|| {
                generate_cursor_secret()
                    .map(|k| k.to_vec())
                    .unwrap_or_default()
            });

        Self {
            tier2_enabled,
            index_dir,
            writer_heap_bytes,
            max_concurrent_searches,
            query_timeout,
            zh_dict_path,
            cursor_secret,
        }
    }

    /// Return a copy with the requested writer heap clamped to `[15 MB, 50 MB]`.
    #[must_use]
    pub fn with_writer_heap_bytes(mut self, requested: usize) -> Self {
        self.writer_heap_bytes = clamp_writer_heap_bytes(requested);
        self
    }

    /// Effective writer heap budget, guaranteed `<= MAX_WRITER_HEAP_BYTES`.
    #[must_use]
    pub const fn effective_writer_heap_bytes(&self) -> usize {
        clamp_writer_heap_bytes(self.writer_heap_bytes)
    }
}

/// Generate a 32-byte cursor HMAC secret from the OS CSPRNG (fails closed on RNG failure).
pub fn generate_cursor_secret() -> Result<[u8; 32], SearchError> {
    let mut key = [0u8; 32];
    SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| SearchError::Unavailable("CSPRNG unavailable for cursor secret".to_owned()))?;
    Ok(key)
}
