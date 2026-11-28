//! Per-recipient-domain S/MIME trust cache (Go's `InboundServer.smimeDomainPools`).
//!
//! A pool is the set of admin-imported anchors a recipient domain trusts: deployment-wide rows
//! (`domain_id IS NULL`) plus that domain's rows, each authorized by exactly one fingerprint
//! (`smime.BuildTrustPool`: only certificates whose DER fingerprint equals the row's are
//! loaded, so an unfingerprinted certificate inside a stored bundle never enters a pool).
//! Go adds its embedded Mozilla bundle to every pool; a Rust verifier consults the bundle
//! separately, so a pool here holds only the database part. Pools are built lazily, cached per
//! domain (0 is no or an unknown domain) and cleared on `smime_trust_changed`.
use setjoin_pg::{workers::WorkerConnection, ScopedExecutor, Type};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// The database-backed anchors one domain trusts, by DER fingerprint.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TrustPool {
    fingerprints: BTreeMap<String, String>,
}

impl TrustPool {
    pub fn trusts(&self, fingerprint: &str) -> bool {
        self.fingerprints.contains_key(fingerprint)
    }
    pub fn fingerprints(&self) -> impl Iterator<Item = &str> {
        self.fingerprints.keys().map(String::as_str)
    }
    /// Canonical, fingerprint-authorized PEM certificates for the verifier.
    pub fn certificates(&self) -> impl Iterator<Item = &str> {
        self.fingerprints.values().map(String::as_str)
    }
    /// `BuildTrustPool` over `(stored PEM, authorizing fingerprint)` rows.
    pub fn build<'a>(rows: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut fingerprints = BTreeMap::new();
        for (pem, fingerprint) in rows {
            // An unparseable row is skipped: it never breaks a pool and never grants trust.
            let Ok(certs) = super::parse_chain(pem.as_bytes()) else {
                continue;
            };
            for cert in certs {
                if !fingerprint.is_empty() && cert.fingerprint == fingerprint {
                    fingerprints.insert(cert.fingerprint, cert.pem);
                }
            }
        }
        Self { fingerprints }
    }
}

/// Test-only: restores the frozen-Go defect named by `SETJOIN_MAILSEC_MUTANT`
/// (owner-approved security fix 2026-11-05, #465).
#[cfg(feature = "oracle-mutants")]
fn mutant(id: &str) -> bool {
    std::env::var("SETJOIN_MAILSEC_MUTANT").is_ok_and(|v| v == id)
}
#[cfg(not(feature = "oracle-mutants"))]
fn mutant(_: &str) -> bool {
    false
}

#[derive(Default)]
pub struct TrustCache {
    pools: RwLock<HashMap<i64, Arc<TrustPool>>>,
    /// Bumped by every invalidation: a pool read from the database before an
    /// invalidation must never be cached after it.
    generation: AtomicU64,
    /// Set while a change listener cannot be trusted to deliver notifications.
    uncached: AtomicBool,
}

impl TrustCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// `smimeRootsForDomain`: the cached pool, or one built from the database. A failed read
    /// leaves an empty pool (Go: bundle only), which is cached like any other.
    pub async fn pool_for(&self, worker: &ScopedExecutor, domain: i64) -> Arc<TrustPool> {
        self.load(domain, async {
            worker.read(
                "SELECT cert_pem, fingerprint FROM smime_trust_anchors WHERE domain_id IS NULL OR domain_id=$1::bigint",
                &[(&domain, Type::INT8)],
            ).await.unwrap_or_default().iter().filter_map(|r|Some((r.try_get(0).ok()?,r.try_get(1).ok()?))).collect()
        }).await
    }

    /// Same worker-only authority for a dedicated SMTP delivery connection.
    pub async fn pool_for_session(&self, worker: &WorkerConnection, domain: i64) -> Arc<TrustPool> {
        self.load(domain, async {
            worker.query(
                "SELECT cert_pem, fingerprint FROM smime_trust_anchors WHERE domain_id IS NULL OR domain_id=$1::bigint",
                &[(&domain, Type::INT8)],
            ).await.unwrap_or_default().iter().filter_map(|r|Some((r.try_get(0).ok()?,r.try_get(1).ok()?))).collect()
        }).await
    }

    async fn load(
        &self,
        domain: i64,
        rows: impl std::future::Future<Output = Vec<(String, String)>>,
    ) -> Arc<TrustPool> {
        let uncached = self.uncached.load(Ordering::SeqCst) && !mutant("smime-cache-while-deaf");
        if !uncached {
            if let Some(pool) = self.pools.read().expect("trust cache").get(&domain) {
                return pool.clone();
            }
        }
        let generation = self.generation.load(Ordering::SeqCst);
        let rows = rows.await;
        let pool = TrustPool::build(rows.iter().map(|(p, f)| (p.as_str(), f.as_str())));
        let pool = Arc::new(pool);
        if !uncached {
            let mut pools = self.pools.write().expect("trust cache");
            // An invalidation that raced this read wins: the rows may predate it.
            if self.generation.load(Ordering::SeqCst) == generation {
                pools.insert(domain, pool.clone());
            }
        }
        pool
    }

    /// `InvalidateSMIMETrustCache`.
    pub fn invalidate(&self) {
        let mut pools = self.pools.write().expect("trust cache");
        self.generation.fetch_add(1, Ordering::SeqCst);
        pools.clear();
    }

    /// While `false`, every lookup reads the database and nothing is cached. The change
    /// listener turns this off whenever its LISTEN connection is down (a removal
    /// notification could be lost) and on again after it re-established the
    /// subscription and invalidated the cache.
    pub fn set_cached(&self, cached: bool) {
        self.uncached.store(!cached, Ordering::SeqCst);
        if !cached {
            self.invalidate();
        }
    }

    pub fn cached_domains(&self) -> usize {
        self.pools.read().expect("trust cache").len()
    }
}
