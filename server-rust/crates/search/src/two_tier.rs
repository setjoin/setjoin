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
use std::sync::{Arc, RwLock};

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
    tier2: Option<Arc<TantivySearchEngine>>,
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
            tier2,
            freshness: Arc::new(SnapshotFreshnessFence::unset()),
        }
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
        self.tier2.as_ref()
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

            // 2. Load ONE atomic (reader, generation) snapshot from Tier-2.
            let Some(tier2) = self.tier2.as_ref() else {
                return self.run_tier1_degraded(query, true).await;
            };
            let snapshot = tier2.load_snapshot();
            let Some(loaded) = snapshot.as_ref().as_ref() else {
                return self.run_tier1_degraded(query, true).await;
            };
            let loaded_gen = loaded.manifest.generation;

            // 3. Check fail-closed freshness fence against that EXACT snapshot generation.
            if !self
                .freshness
                .is_corpus_fresh(query.corpus, loaded_gen)
                .await
            {
                return self.run_tier1_degraded(query, true).await;
            }

            // 4. Execute Tier-2 on that EXACT snapshot; any runtime error / timeout / panic /
            //    corrupt index degrades cleanly to Tier-1.
            match tier2.candidates_on_snapshot(snapshot, query).await {
                Ok(batch) if !batch.degraded => Ok(batch),
                Ok(_) => self.run_tier1_degraded(query, true).await,
                Err(SearchError::InvalidCursor) => Err(SearchError::InvalidCursor),
                Err(_) => self.run_tier1_degraded(query, true).await,
            }
        })
    }

    fn tier(&self) -> SearchTier {
        if self.config.tier2_enabled && self.tier2.as_ref().is_some_and(|e| e.health().is_healthy())
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
        match self.tier2.as_ref() {
            Some(t2) => t2.health(),
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
    freshness: Arc<SnapshotFreshnessFence>,
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
            freshness: Arc::new(SnapshotFreshnessFence::unset()),
        }
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
    pub fn freshness_fence(&self) -> &Arc<SnapshotFreshnessFence> {
        &self.freshness
    }

    #[must_use]
    pub fn health(&self) -> EngineHealth {
        if !self.config.tier2_enabled {
            return EngineHealth::Disabled;
        }
        match self.tier2.as_ref() {
            Some(engine) => engine.health(),
            None => EngineHealth::Disabled,
        }
    }

    /// Build a [`TwoTierSearchEngine`] pairing the runtime's optional Tier-2
    /// engine, fail-closed watermark fence, and a caller-supplied Tier-1 engine.
    #[must_use]
    pub fn engine(&self, tier1: Arc<dyn SearchEngine>) -> TwoTierSearchEngine {
        TwoTierSearchEngine::new(self.config.clone(), tier1, self.tier2.clone())
            .with_freshness_fence(Arc::clone(&self.freshness) as Arc<dyn FreshnessFence>)
    }
}
