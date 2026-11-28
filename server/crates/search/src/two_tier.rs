//! Two-tier routing (`TwoTierSearchEngine`), fail-closed freshness fencing (`FreshnessFence`),
//! and optional gateway startup runtime (`SearchRuntime`).

use crate::config::SearchConfig;
use crate::model::{
    BoxFuture, CandidateBatch, CandidateQuery, DocCorpus, EngineHealth, SearchEngine, SearchError,
    SearchTier,
};
use crate::tantivy_engine::TantivySearchEngine;
use crate::tier1_pg::PgSearchCapabilities;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Fail-closed deadline-enforced gate controlling whether this node holds an active,
/// unexpired HA single-writer search leader lease for `/_internal/search/*` RPCs.
///
/// Defaults to **inactive** (`active = false`, `deadline_unix_ms = 0`) so stateless
/// HTTP-only nodes and un-elected worker nodes automatically return `503`. Even if a
/// heartbeat task stalls under DB partition or scheduler lag, [`Self::is_active`]
/// flips to `false` automatically as soon as `now_unix_ms() >= deadline_unix_ms`.
#[derive(Debug)]
pub struct LeaderLeaseGate {
    active: AtomicBool,
    deadline_unix_ms: AtomicU64,
}

impl LeaderLeaseGate {
    #[must_use]
    pub const fn inactive() -> Self {
        Self {
            active: AtomicBool::new(false),
            deadline_unix_ms: AtomicU64::new(0),
        }
    }

    /// Activate leadership strictly until the given UTC epoch-millisecond deadline.
    pub fn set_active_until_unix_ms(&self, deadline_ms: u64) {
        self.deadline_unix_ms.store(deadline_ms, Ordering::Release);
        self.active.store(true, Ordering::Release);
    }

    /// Activate leadership for `ttl` from now (conservative lease window).
    pub fn set_active_for(&self, ttl: std::time::Duration) {
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        self.set_active_until_unix_ms(now_unix_ms().saturating_add(ttl_ms));
    }

    /// Unbounded toggle (intended for single-node local tests); `false` demotes immediately.
    pub fn set_active_unbounded(&self, active: bool) {
        if active {
            self.deadline_unix_ms.store(u64::MAX, Ordering::Release);
            self.active.store(true, Ordering::Release);
        } else {
            self.demote();
        }
    }

    /// Immediately revoke leadership so `/_internal/search/*` returns `503`.
    pub fn demote(&self) {
        self.active.store(false, Ordering::Release);
        self.deadline_unix_ms.store(0, Ordering::Release);
    }

    /// Return `true` ONLY if leadership is active AND the conservative local lease deadline
    /// has not yet elapsed.
    #[must_use]
    pub fn is_active(&self) -> bool {
        if !self.active.load(Ordering::Acquire) {
            return false;
        }
        let deadline = self.deadline_unix_ms.load(Ordering::Acquire);
        if deadline == u64::MAX {
            return true;
        }
        now_unix_ms() < deadline
    }
}

/// Verified watermark snapshot for one corpus (`search_index_watermarks` + `search_dirty_keys`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatermarkSnapshot {
    pub generation: u64,
    pub dirty_count: u64,
}

/// Freshness fence consulted before serving a corpus from Tier-2 Tantivy.
///
/// If a corpus has an unset watermark, unindexed dirty keys (`dirty_count > 0`),
/// or a generation mismatch (`loaded_generation != watermark.generation`), the fence
/// fails closed and returns `false` so [`TwoTierSearchEngine`] degrades cleanly to Tier-1 PG.
pub trait FreshnessFence: Send + Sync {
    fn is_corpus_fresh<'a>(
        &'a self,
        corpus: DocCorpus,
        loaded_generation: u64,
    ) -> BoxFuture<'a, bool>;
}

/// Opt-in test/static fence that treats any loaded epoch as fresh.
/// Never used as the default in [`SearchRuntime`] (which fails closed).
#[derive(Clone, Copy, Debug, Default)]
pub struct AlwaysFresh;

impl FreshnessFence for AlwaysFresh {
    fn is_corpus_fresh<'a>(
        &'a self,
        _corpus: DocCorpus,
        _loaded_generation: u64,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async { true })
    }
}

/// Fail-closed per-corpus watermark freshness fence.
///
/// Requires `snapshot.generation == watermark.generation && watermark.dirty_count == 0`.
/// Any missing/unset watermark, dirty key backlog, or generation skew returns `false`
/// (failing closed to Tier-1 PG).
#[derive(Clone, Debug, Default)]
pub struct SnapshotFreshnessFence {
    watermarks: Arc<RwLock<HashMap<DocCorpus, WatermarkSnapshot>>>,
}

impl SnapshotFreshnessFence {
    /// Create a fail-closed fence with no watermarks published yet.
    #[must_use]
    pub fn unset() -> Self {
        Self::default()
    }

    /// Create a fence pre-populated with one corpus watermark.
    #[must_use]
    pub fn with_corpus(corpus: DocCorpus, generation: u64, dirty_count: u64) -> Self {
        let fence = Self::unset();
        fence.set_watermark(corpus, generation, dirty_count);
        fence
    }

    /// Publish or update the verified watermark snapshot for `corpus`.
    pub fn set_watermark(&self, corpus: DocCorpus, generation: u64, dirty_count: u64) {
        if let Ok(mut guard) = self.watermarks.write() {
            guard.insert(
                corpus,
                WatermarkSnapshot {
                    generation,
                    dirty_count,
                },
            );
        }
    }

    /// Clear a corpus watermark so subsequent queries fail closed to Tier-1.
    pub fn clear_corpus(&self, corpus: DocCorpus) {
        if let Ok(mut guard) = self.watermarks.write() {
            guard.remove(&corpus);
        }
    }

    /// Clear ALL corpus watermarks so subsequent queries fail closed to Tier-1
    /// (used immediately on HA leader lease loss / expiry).
    pub fn clear_all(&self) {
        if let Ok(mut guard) = self.watermarks.write() {
            guard.clear();
        }
    }

    /// Advance the recorded generation for every corpus ALREADY present in this fence,
    /// preserving each corpus's existing `dirty_count` and NEVER marking an unset corpus
    /// fresh (`dirty_count = 0`).
    pub fn advance_existing_corpora(&self, generation: u64) {
        if let Ok(mut guard) = self.watermarks.write() {
            for wm in guard.values_mut() {
                wm.generation = wm.generation.max(generation);
            }
        }
    }

    /// Inspect the currently recorded watermark for `corpus`.
    #[must_use]
    pub fn watermark(&self, corpus: DocCorpus) -> Option<WatermarkSnapshot> {
        self.watermarks
            .read()
            .ok()
            .and_then(|guard| guard.get(&corpus).copied())
    }
}

impl FreshnessFence for SnapshotFreshnessFence {
    fn is_corpus_fresh<'a>(
        &'a self,
        corpus: DocCorpus,
        loaded_generation: u64,
    ) -> BoxFuture<'a, bool> {
        let fresh = self
            .watermarks
            .read()
            .ok()
            .and_then(|guard| guard.get(&corpus).copied())
            .is_some_and(|wm| wm.dirty_count == 0 && loaded_generation == wm.generation);
        Box::pin(async move { fresh })
    }
}

/// Coordinator routing candidate searches between Tier-2 Tantivy and Tier-1 PG.
///
/// Routing policy:
/// 1. Disabled (`!config.tier2_enabled`), `metadata_only`, or `calculate_total`:
///    serve directly from Tier-1 (`degraded = false`).
/// 2. Tier-2 missing or unhealthy/corrupt:
///    serve transparently from Tier-1 (`degraded = true`).
/// 3. Load ONE atomic `(reader, generation)` snapshot from Tier-2 and check the
///    fail-closed [`FreshnessFence`] against that exact snapshot's generation.
///    If unset/dirty/mismatched, serve transparently from Tier-1 (`degraded = true`).
/// 4. Execute Tier-2 against that exact snapshot; any timeout, panic, corrupt, or
///    unavailable error degrades transparently to Tier-1 (`degraded = true`).
pub struct TwoTierSearchEngine {
    config: SearchConfig,
    tier1: Arc<dyn SearchEngine>,
    local_tier2: Option<Arc<TantivySearchEngine>>,
    remote_tier2: Option<Arc<dyn SearchEngine>>,
    freshness: Arc<dyn FreshnessFence>,
}

impl TwoTierSearchEngine {
    /// Construct a `TwoTierSearchEngine` with a fail-closed [`SnapshotFreshnessFence::unset`]
    /// by default (callers must publish verified watermarks or supply an explicit fence).
    #[must_use]
    pub fn new(
        config: SearchConfig,
        tier1: Arc<dyn SearchEngine>,
        tier2: Option<Arc<TantivySearchEngine>>,
    ) -> Self {
        Self {
            config,
            tier1,
            local_tier2: tier2,
            remote_tier2: None,
            freshness: Arc::new(SnapshotFreshnessFence::unset()),
        }
    }

    /// Construct a `TwoTierSearchEngine` backed by a remote HA Tier-2 [`SearchEngine`]
    /// (e.g. [`crate::ha_rpc::RemoteSearchEngine`] on stateless HTTP follower nodes).
    #[must_use]
    pub fn with_remote_tier2(
        config: SearchConfig,
        tier1: Arc<dyn SearchEngine>,
        remote_tier2: Arc<dyn SearchEngine>,
    ) -> Self {
        Self {
            config,
            tier1,
            local_tier2: None,
            remote_tier2: Some(remote_tier2),
            freshness: Arc::new(SnapshotFreshnessFence::unset()),
        }
    }

    /// Attach a remote HA Tier-2 fallback/follower engine alongside or instead of a local index.
    #[must_use]
    pub fn with_remote_engine(mut self, remote_tier2: Arc<dyn SearchEngine>) -> Self {
        self.remote_tier2 = Some(remote_tier2);
        self
    }

    #[must_use]
    pub fn with_freshness_fence(mut self, freshness: Arc<dyn FreshnessFence>) -> Self {
        self.freshness = freshness;
        self
    }

    #[must_use]
    pub const fn config(&self) -> &SearchConfig {
        &self.config
    }

    #[must_use]
    pub fn tier2(&self) -> Option<&Arc<TantivySearchEngine>> {
        self.local_tier2.as_ref()
    }

    #[must_use]
    pub fn remote_tier2(&self) -> Option<&Arc<dyn SearchEngine>> {
        self.remote_tier2.as_ref()
    }

    async fn run_tier1_degraded(
        &self,
        query: &CandidateQuery,
        degraded: bool,
    ) -> Result<CandidateBatch, SearchError> {
        let mut batch = self.tier1.candidates(query).await?;
        batch.tier = SearchTier::Tier1Pg;
        batch.degraded = degraded || batch.degraded;
        Ok(batch)
    }
}

impl SearchEngine for TwoTierSearchEngine {
    fn candidates<'a>(
        &'a self,
        query: &'a CandidateQuery,
    ) -> BoxFuture<'a, Result<CandidateBatch, SearchError>> {
        Box::pin(async move {
            // 1. Default-OFF gate, metadata-only queries, or exact total counts route directly to Tier-1 PG.
            if !self.config.tier2_enabled || query.metadata_only || query.calculate_total {
                return self.run_tier1_degraded(query, false).await;
            }

            // 2. Prefer local Tantivy snapshot when healthy and fresh.
            if let Some(tier2) = self.local_tier2.as_ref() {
                let snapshot = tier2.load_snapshot();
                if let Some(loaded) = snapshot.as_ref().as_ref() {
                    let loaded_gen = loaded.manifest.generation;
                    if self
                        .freshness
                        .is_corpus_fresh(query.corpus, loaded_gen)
                        .await
                    {
                        match tier2.candidates_on_snapshot(snapshot, query).await {
                            Ok(batch) if !batch.degraded => return Ok(batch),
                            Err(SearchError::InvalidCursor) => {
                                return Err(SearchError::InvalidCursor);
                            }
                            Ok(_) | Err(_) => {
                                // Fall through to remote leader or Tier-1 PG.
                            }
                        }
                    }
                }
            }

            // 3. Follower path: query remote HA single-writer leader via authenticated RPC.
            if let Some(remote) = self.remote_tier2.as_ref() {
                match remote.candidates(query).await {
                    Ok(batch) if !batch.degraded => return Ok(batch),
                    Err(SearchError::InvalidCursor) => return Err(SearchError::InvalidCursor),
                    Ok(_) | Err(_) => return self.run_tier1_degraded(query, true).await,
                }
            }

            // 4. Transparent fail-closed fallback to Tier-1 PG.
            self.run_tier1_degraded(query, true).await
        })
    }

    fn tier(&self) -> SearchTier {
        if self.config.tier2_enabled
            && (self
                .local_tier2
                .as_ref()
                .is_some_and(|e| e.health().is_healthy())
                || self
                    .remote_tier2
                    .as_ref()
                    .is_some_and(|e| e.health().is_healthy()))
        {
            SearchTier::Tier2Tantivy
        } else {
            SearchTier::Tier1Pg
        }
    }

    fn health(&self) -> EngineHealth {
        if !self.config.tier2_enabled {
            return EngineHealth::Disabled;
        }
        if let Some(t2) = self.local_tier2.as_ref() {
            let h = t2.health();
            if h.is_healthy() {
                return h;
            }
            if let Some(remote) = self.remote_tier2.as_ref() {
                return remote.health();
            }
            return h;
        }
        match self.remote_tier2.as_ref() {
            Some(remote) => remote.health(),
            None => EngineHealth::Degraded {
                reason: "tier-2 search engine not initialized".to_owned(),
            },
        }
    }
}

/// Gateway startup handle for the optional two-tier search runtime (#556).
///
/// When `SETJOIN_SEARCH_TIER2_ENABLED` is unset or false (the default), this
/// performs zero disk I/O and never initializes the lazy Jieba dictionary.
/// Its default freshness fence fails closed until verified watermarks are published.
#[derive(Clone)]
pub struct SearchRuntime {
    config: SearchConfig,
    capabilities: PgSearchCapabilities,
    tier2: Option<Arc<TantivySearchEngine>>,
    remote_tier2: Option<Arc<dyn SearchEngine>>,
    freshness: Arc<SnapshotFreshnessFence>,
    leader_gate: Arc<LeaderLeaseGate>,
}

impl SearchRuntime {
    /// Initialize from environment variables and probed PostgreSQL search capabilities.
    ///
    /// Never fails gateway startup: if Tier-2 is enabled but the index directory
    /// is unbuilt or corrupt, starts cleanly in degraded Tier-1 fallback mode.
    #[must_use]
    pub fn from_env(capabilities: PgSearchCapabilities) -> Self {
        Self::from_config(SearchConfig::from_env(), capabilities)
    }

    /// Initialize from an explicit [`SearchConfig`] and probed PostgreSQL capabilities.
    ///
    /// Starts strictly with [`LeaderLeaseGate::inactive()`] so HTTP-only follower nodes
    /// and un-elected nodes return `503` on `/_internal/search/*` until leadership is acquired.
    #[must_use]
    pub fn from_config(config: SearchConfig, capabilities: PgSearchCapabilities) -> Self {
        let tier2 = if config.tier2_enabled {
            Some(Arc::new(TantivySearchEngine::open_or_degraded(
                config.clone(),
            )))
        } else {
            None
        };
        Self {
            config,
            capabilities,
            tier2,
            remote_tier2: None,
            freshness: Arc::new(SnapshotFreshnessFence::unset()),
            leader_gate: Arc::new(LeaderLeaseGate::inactive()),
        }
    }

    /// Attach a remote HA leader [`SearchEngine`] for stateless HTTP follower reads.
    #[must_use]
    pub fn with_remote_tier2(mut self, remote: Arc<dyn SearchEngine>) -> Self {
        self.remote_tier2 = Some(remote);
        self
    }

    #[must_use]
    pub const fn config(&self) -> &SearchConfig {
        &self.config
    }

    #[must_use]
    pub const fn capabilities(&self) -> PgSearchCapabilities {
        self.capabilities
    }

    #[must_use]
    pub fn tier2(&self) -> Option<&Arc<TantivySearchEngine>> {
        self.tier2.as_ref()
    }

    #[must_use]
    pub fn remote_tier2(&self) -> Option<&Arc<dyn SearchEngine>> {
        self.remote_tier2.as_ref()
    }

    #[must_use]
    pub fn freshness_fence(&self) -> &Arc<SnapshotFreshnessFence> {
        &self.freshness
    }

    /// Update whether this node currently holds the active HA single-writer search
    /// leader lease (unbounded toggle for single-node/local tests; `false` demotes immediately).
    pub fn set_leader_active(&self, active: bool) {
        self.leader_gate.set_active_unbounded(active);
    }

    /// Activate HA leadership strictly until `ttl` elapses from now.
    pub fn set_leader_active_for(&self, ttl: std::time::Duration) {
        self.leader_gate.set_active_for(ttl);
    }

    /// Return `true` ONLY when this node holds an active, unexpired HA leader lease
    /// permitted to serve `/_internal/search/*` RPCs.
    #[must_use]
    pub fn is_leader_active(&self) -> bool {
        self.leader_gate.is_active()
    }

    /// Shared deadline-enforced gate controlling active HA leadership.
    #[must_use]
    pub fn leader_gate(&self) -> Arc<LeaderLeaseGate> {
        Arc::clone(&self.leader_gate)
    }

    #[must_use]
    pub fn health(&self) -> EngineHealth {
        if !self.config.tier2_enabled {
            return EngineHealth::Disabled;
        }
        if let Some(engine) = self.tier2.as_ref() {
            let h = engine.health();
            if h.is_healthy() {
                return h;
            }
            if let Some(remote) = self.remote_tier2.as_ref() {
                return remote.health();
            }
            return h;
        }
        match self.remote_tier2.as_ref() {
            Some(remote) => remote.health(),
            None => EngineHealth::Disabled,
        }
    }

    /// Build a [`TwoTierSearchEngine`] pairing the runtime's optional Tier-2
    /// engine (local and/or remote HA leader), fail-closed watermark fence,
    /// and a caller-supplied Tier-1 engine.
    #[must_use]
    pub fn engine(&self, tier1: Arc<dyn SearchEngine>) -> TwoTierSearchEngine {
        let mut eng = TwoTierSearchEngine::new(self.config.clone(), tier1, self.tier2.clone())
            .with_freshness_fence(Arc::clone(&self.freshness) as Arc<dyn FreshnessFence>);
        if let Some(remote) = self.remote_tier2.as_ref() {
            eng = eng.with_remote_engine(Arc::clone(remote));
        }
        eng
    }
}
