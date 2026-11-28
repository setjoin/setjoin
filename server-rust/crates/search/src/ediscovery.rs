//! `WorkQueue`-backed deterministic eDiscovery completeness executor (`#558`)
//! and lawful purge eviction payload codecs.
//!
//! Algorithm:
//! 1. Snapshot `(epoch, generation, indexed_outbox_seq)` for BOTH `mail` AND
//!    `mail_attachment` from `public.search_index_watermarks` and compare against
//!    the Tier-2 engine's `(epoch, generation)`. Fail closed to full Tier-1
//!    PostgreSQL whenever degraded, rebuilding, unhealthy, missing/unbuilt watermark,
//!    or epoch/generation misaligned.
//! 2. When healthy & aligned: pin ONE atomic Tier-2 snapshot (via `TantivySearchEngine`
//!    `load_snapshot` + `candidates_on_snapshot` when local, and strict generation
//!    invariance verification across every page), query BOTH `SearchVisibility::Live`
//!    and `SearchVisibility::ComplianceOnly` (`Mail` + `MailAttachment`), AND run a
//!    PG tail scan over `public.search_index_outbox` (`processed_at IS NULL OR seq > min_wm_seq`)
//!    + `public.search_dirty_keys`, unioning and deduplicating candidates deterministically.
//! 3. Re-authorize & re-verify tokenized keyword + compliance metadata predicates on
//!    every unioned candidate in PostgreSQL (so edited messages or stale hits never
//!    produce false positives, and multi-word attachment matches behave consistently
//!    across Tier-2, PG tail, and Tier-1 fallback).
//! 4. For KQL queries (`!parsed.kql.is_empty()`), compile the AST via the configured
//!    KQL compiler callback and settle atomically via `search_ediscovery_complete_kql_atomic`.
//! 5. Compute honest [`ExtractionStatusSummary`] across attachments in the searched scope
//!    (counting `smime-encrypted` message attachments honestly under `encrypted`, never
//!    `extracted`), and commit results + `search_provenance` + core `admin_audit_log`
//!    atomically in ONE PostgreSQL transaction via `search_ediscovery_complete_atomic`
//!    (idempotent on WorkQueue retry).

use crate::model::{
    CandidateQuery, DocCorpus, DocumentKey, EngineHealth, NormalizedQuery, ScopeHint, SearchEngine,
    SearchError, SearchTier, SearchVisibility, MAX_CANDIDATE_LIMIT,
};
use crate::pipeline::SearchPipelineDb;
use crate::tantivy_engine::TantivySearchEngine;
use crate::tier1_pg::escape_like_pattern;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use setjoin_pg::{Param, Row, Type};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

/// Durable `WorkQueue` kind for deterministic watermark-backed eDiscovery searches.
pub const WORK_KIND_SEARCH_EDISCOVERY: &str = "search.ediscovery";

/// Durable `WorkQueue` kind for lawful compliance purge physical eviction & segment compaction.
pub const WORK_KIND_SEARCH_PURGE_EVICT: &str = "search.purge_evict";

/// Maximum persisted result bindings matching `rust_compliance_search_complete` (`LIMIT 500`).
const MAX_PERSISTED_RESULTS: usize = 500;

/// Maximum Tier-2 pages drained per `(corpus, visibility)` before falling back to Tier-1 PG.
const MAX_EDISCOVERY_T2_PAGES: usize = 4;

/// Callback compiling a validated compliance KQL string into `(sql_predicate, bound_values)`.
pub type KqlCompiler = Arc<dyn Fn(&str) -> Result<(String, Vec<String>), String> + Send + Sync>;

/// Payload for `"search.ediscovery"` `WorkQueue` items.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchEdiscoveryPayload {
    pub search_id: i64,
    pub actor_id: i64,
}

/// Wire payload for `"search.purge_evict"` `WorkQueue` items.
///
/// Accepts EITHER a batch payload `{"keys": [DocumentKey, ...]}` OR a single-key
/// SQL trigger/helper payload `{"corpus": "mail", "scope_id": ..., "entity_id": ..., "sub_id": ..., "received_at": ...}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SearchPurgeEvictPayload {
    Batch {
        keys: Vec<DocumentKey>,
    },
    Single {
        corpus: String,
        scope_id: i64,
        entity_id: i64,
        #[serde(default)]
        sub_id: i64,
        #[serde(default)]
        received_at: Option<DateTime<Utc>>,
    },
}

impl SearchPurgeEvictPayload {
    /// Convert payload into concrete [`DocumentKey`]s for physical eviction & compaction.
    pub fn into_document_keys(self) -> Result<Vec<DocumentKey>, SearchError> {
        match self {
            Self::Batch { keys } => Ok(keys),
            Self::Single {
                corpus,
                scope_id,
                entity_id,
                sub_id,
                received_at,
            } => {
                let parsed = DocCorpus::parse(&corpus).ok_or_else(|| {
                    SearchError::Internal(format!("unknown purge corpus {corpus:?}"))
                })?;
                let key = match parsed {
                    DocCorpus::Mail => {
                        let ts = received_at.ok_or_else(|| {
                            SearchError::Internal(
                                "mail purge payload missing received_at".to_owned(),
                            )
                        })?;
                        DocumentKey::Mail {
                            mailbox_id: scope_id,
                            id: entity_id,
                            received_at: ts,
                        }
                    }
                    DocCorpus::MailAttachment => {
                        let ts = received_at.ok_or_else(|| {
                            SearchError::Internal(
                                "mail_attachment purge payload missing received_at".to_owned(),
                            )
                        })?;
                        DocumentKey::MailAttachment {
                            mailbox_id: scope_id,
                            id: entity_id,
                            received_at: ts,
                            sub_id,
                        }
                    }
                    DocCorpus::Chat => DocumentKey::Chat {
                        channel_id: scope_id,
                        id: entity_id,
                    },
                    DocCorpus::Drive => DocumentKey::Drive {
                        space_id: scope_id,
                        id: entity_id,
                    },
                    DocCorpus::DriveFile => DocumentKey::DriveFile {
                        space_id: scope_id,
                        id: entity_id,
                        sub_id,
                    },
                };
                Ok(vec![key])
            }
        }
    }
}

/// Honest per-status extraction visibility counts across attachments / Drive file
/// versions in an eDiscovery search scope.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractionStatusSummary {
    pub extracted: u64,
    pub encrypted: u64,
    pub unsupported: u64,
    pub truncated_limit: u64,
    pub failed: u64,
    pub pending_extraction: u64,
}

impl ExtractionStatusSummary {
    /// Total attachment / file objects accounted for in the scope.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.extracted
            + self.encrypted
            + self.unsupported
            + self.truncated_limit
            + self.failed
            + self.pending_extraction
    }
}

/// Immutable eDiscovery search provenance persisted to both
/// `ediscovery_searches.search_provenance` and `admin_audit_log`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdiscoveryProvenance {
    /// `"tier2_tantivy_plus_pg_tail"` or `"tier1_pg_fallback"`.
    pub engine_tier: String,
    pub epoch: Option<u64>,
    pub generation: Option<u64>,
    pub indexed_outbox_seq: Option<i64>,
    pub tail_rows_scanned: u64,
    pub degraded_reason: Option<String>,
    pub extraction_status_counts: ExtractionStatusSummary,
    pub result_count: i64,
}

#[derive(Clone, Debug, Default)]
struct ParsedEdiscoveryQuery {
    keywords: String,
    kql: String,
    from_addr: Option<String>,
    date_from: Option<DateTime<Utc>>,
    date_to: Option<DateTime<Utc>>,
    mailbox_ids: Option<Vec<i64>>,
}

#[derive(Clone, Debug)]
struct WatermarkRow {
    epoch: u64,
    generation: u64,
    indexed_outbox_seq: i64,
}

/// Deterministic watermark-backed eDiscovery executor.
pub struct EdiscoverySearchExecutor {
    db: Arc<dyn SearchPipelineDb>,
    engine: Option<Arc<dyn SearchEngine>>,
    local_tantivy: Option<Arc<TantivySearchEngine>>,
    kql_compiler: Option<KqlCompiler>,
}

impl EdiscoverySearchExecutor {
    #[must_use]
    pub fn new(db: Arc<dyn SearchPipelineDb>, engine: Option<Arc<dyn SearchEngine>>) -> Self {
        Self {
            db,
            engine,
            local_tantivy: None,
            kql_compiler: None,
        }
    }

    /// Attach a local [`TantivySearchEngine`] so multi-page eDiscovery reads pin ONE
    /// atomic `(reader, generation)` snapshot across all corpora & visibility legs.
    #[must_use]
    pub fn with_local_tantivy(mut self, local: Arc<TantivySearchEngine>) -> Self {
        if self.engine.is_none() {
            self.engine = Some(Arc::clone(&local) as Arc<dyn SearchEngine>);
        }
        self.local_tantivy = Some(local);
        self
    }

    /// Attach the compliance KQL AST compiler (`setjoin_compliance::kql::parse`) so
    /// KQL eDiscovery searches execute their exact AST predicate atomically.
    #[must_use]
    pub fn with_kql_compiler(mut self, compiler: KqlCompiler) -> Self {
        self.kql_compiler = Some(compiler);
        self
    }

    /// Execute eDiscovery search `search_id` created by `actor_id`, persist results
    /// and provenance, and record an immutable core audit entry in `admin_audit_log`
    /// atomically in one PostgreSQL transaction.
    pub async fn execute(
        &self,
        search_id: i64,
        actor_id: i64,
    ) -> Result<EdiscoveryProvenance, SearchError> {
        let outcome = self.execute_inner(search_id, actor_id).await;
        if outcome.is_err() {
            let params: [Param<'_>; 2] = [(&search_id, Type::INT8), (&actor_id, Type::INT8)];
            let _ = self
                .db
                .query_typed(
                    "UPDATE public.ediscovery_searches \
                        SET status = 'failed', completed_at = now() \
                      WHERE id = $1 AND created_by = $2 AND status <> 'complete'",
                    &params,
                )
                .await;
        }
        outcome
    }

    async fn execute_inner(
        &self,
        search_id: i64,
        actor_id: i64,
    ) -> Result<EdiscoveryProvenance, SearchError> {
        let start_params: [Param<'_>; 2] = [(&search_id, Type::INT8), (&actor_id, Type::INT8)];
        let rows = self
            .db
            .query_typed(
                "UPDATE public.ediscovery_searches \
                    SET status = CASE WHEN status = 'complete' THEN status ELSE 'running' END, \
                        started_at = COALESCE(started_at, now()) \
                  WHERE id = $1 AND created_by = $2 \
                  RETURNING query::text, status, search_provenance::text",
                &start_params,
            )
            .await?;
        let Some(row) = rows.first() else {
            return Err(SearchError::Database(format!(
                "ediscovery search {search_id} not found for actor {actor_id}"
            )));
        };
        let query_text: String = col(row, 0)?;
        let current_status: String = col(row, 1)?;
        let existing_prov: Option<String> = col(row, 2)?;
        if current_status == "complete" {
            if let Some(raw_prov) = existing_prov {
                if let Ok(parsed_prov) = serde_json::from_str::<EdiscoveryProvenance>(&raw_prov) {
                    return Ok(parsed_prov);
                }
            }
        }

        let query_json: serde_json::Value = serde_json::from_str(&query_text)
            .map_err(|e| SearchError::Internal(format!("invalid ediscovery query json: {e}")))?;
        let parsed = parse_ediscovery_query(&query_json)?;

        // KQL queries execute their exact validated AST predicate atomically via
        // `search_ediscovery_complete_kql_atomic` — NEVER falling back to an unfiltered scan.
        if !parsed.kql.is_empty() {
            let compiler = self.kql_compiler.as_ref().ok_or_else(|| {
                SearchError::Internal(
                    "KQL eDiscovery query requires configured KQL compiler".to_owned(),
                )
            })?;
            let (predicate, values) = compiler(&parsed.kql)
                .map_err(|e| SearchError::Internal(format!("invalid KQL query: {e}")))?;
            let extraction_status_counts = self.compute_extraction_status_summary(&parsed).await?;
            let mut prov = EdiscoveryProvenance {
                engine_tier: "tier1_pg_fallback".to_owned(),
                epoch: None,
                generation: None,
                indexed_outbox_seq: None,
                tail_rows_scanned: 0,
                degraded_reason: Some("kql_requires_tier1_pg".to_owned()),
                extraction_status_counts,
                result_count: 0,
            };
            let count = self
                .complete_kql_atomic(search_id, actor_id, &predicate, &values, &prov)
                .await?;
            prov.result_count = count;
            return Ok(prov);
        }

        let extraction_status_counts = self.compute_extraction_status_summary(&parsed).await?;

        let (matched_ids, total_count, provenance) = match self.try_tier2_plus_tail(&parsed).await {
            Ok(Some((ids, total, mut prov))) => {
                prov.extraction_status_counts = extraction_status_counts;
                prov.result_count = total;
                (ids, total, prov)
            }
            Ok(None) => {
                let (ids, total) = self.run_tier1_pg_search(&parsed).await?;
                let prov = EdiscoveryProvenance {
                    engine_tier: "tier1_pg_fallback".to_owned(),
                    epoch: None,
                    generation: None,
                    indexed_outbox_seq: None,
                    tail_rows_scanned: 0,
                    degraded_reason: Some("tier2_not_eligible_or_disabled".to_owned()),
                    extraction_status_counts,
                    result_count: total,
                };
                (ids, total, prov)
            }
            Err(reason) => {
                let (ids, total) = self.run_tier1_pg_search(&parsed).await?;
                let prov = EdiscoveryProvenance {
                    engine_tier: "tier1_pg_fallback".to_owned(),
                    epoch: None,
                    generation: None,
                    indexed_outbox_seq: None,
                    tail_rows_scanned: 0,
                    degraded_reason: Some(reason),
                    extraction_status_counts,
                    result_count: total,
                };
                (ids, total, prov)
            }
        };

        self.persist_results_and_audit_atomic(
            search_id,
            actor_id,
            &matched_ids,
            total_count,
            &provenance,
        )
        .await?;
        Ok(provenance)
    }

    async fn try_tier2_plus_tail(
        &self,
        parsed: &ParsedEdiscoveryQuery,
    ) -> Result<Option<(Vec<i64>, i64, EdiscoveryProvenance)>, String> {
        let Some(engine) = self.engine.as_ref() else {
            return Err("tier2_engine_unconfigured".to_owned());
        };
        if !parsed.kql.is_empty() {
            return Err("kql_requires_tier1_pg".to_owned());
        }
        let keywords = parsed.keywords.trim();
        if keywords.is_empty() {
            return Err("metadata_only_query_uses_tier1_pg".to_owned());
        }
        let norm = NormalizedQuery::parse(keywords).map_err(|e| format!("query_validation:{e}"))?;

        // Pin ONE local Tantivy snapshot when available so multi-page/multi-leg reads
        // cannot drift across concurrent commits or epoch swaps.
        let pinned_local_snap = self.local_tantivy.as_ref().map(|t| t.load_snapshot());
        let (engine_epoch, engine_gen) = if let Some(ref snap) = pinned_local_snap {
            match snap.as_ref().as_ref() {
                Some(loaded) => (loaded.manifest.epoch, loaded.manifest.generation),
                None => return Err("tier2_local_epoch_unloaded".to_owned()),
            }
        } else {
            match engine.health() {
                EngineHealth::Healthy { epoch, generation } => (epoch, generation),
                EngineHealth::Disabled => return Err("tier2_engine_disabled".to_owned()),
                EngineHealth::Degraded { reason } => {
                    return Err(format!("tier2_engine_degraded:{reason}"));
                }
            }
        };

        if has_websearch_boolean_syntax(&parsed.keywords) {
            return Err("websearch_boolean_syntax_defer_tier1".to_owned());
        }

        // Require BOTH mail and mail_attachment watermarks to be present, built (epoch > 0),
        // epoch-aligned, and no newer than the pinned engine generation.
        let mail_wm = self
            .load_watermark(DocCorpus::Mail)
            .await
            .map_err(|e| format!("watermark_read_error:{e}"))?
            .ok_or_else(|| "mail_watermark_missing".to_owned())?;
        let att_wm = self
            .load_watermark(DocCorpus::MailAttachment)
            .await
            .map_err(|e| format!("att_watermark_read_error:{e}"))?
            .ok_or_else(|| "mail_attachment_watermark_missing".to_owned())?;

        if mail_wm.epoch == 0 || mail_wm.epoch != engine_epoch {
            return Err(format!(
                "epoch_mismatch:engine={engine_epoch},watermark={}",
                mail_wm.epoch
            ));
        }
        if att_wm.epoch == 0 || att_wm.epoch != engine_epoch {
            return Err(format!(
                "attachment_epoch_mismatch:engine={engine_epoch},watermark={}",
                att_wm.epoch
            ));
        }
        let required_gen = mail_wm.generation.max(att_wm.generation);
        if engine_gen < required_gen {
            return Err(format!(
                "generation_behind:engine={engine_gen},required_watermark={required_gen},mail={},att={}",
                mail_wm.generation, att_wm.generation
            ));
        }

        let scope_hint = match parsed.mailbox_ids.as_deref() {
            Some([single]) => ScopeHint::Mailbox(*single),
            _ => ScopeHint::GlobalCompliance,
        };

        // 1. Collect Tier-2 candidates across BOTH Live and ComplianceOnly for Mail & MailAttachment,
        //    asserting generation invariance across every page.
        let mut pinned_gen: Option<u64> = None;
        let mut t2_msg_ids: HashSet<i64> = HashSet::new();
        for corpus in [DocCorpus::Mail, DocCorpus::MailAttachment] {
            for visibility in [SearchVisibility::Live, SearchVisibility::ComplianceOnly] {
                let mut cursor = None;
                for page_idx in 0..MAX_EDISCOVERY_T2_PAGES {
                    let q = CandidateQuery {
                        corpus,
                        scope_hint: scope_hint.clone(),
                        terms: norm.clone(),
                        visibility,
                        limit: MAX_CANDIDATE_LIMIT,
                        continuation: cursor,
                        metadata_only: false,
                        calculate_total: false,
                    };
                    let batch = match (&self.local_tantivy, &pinned_local_snap) {
                        (Some(local), Some(snap)) => local
                            .candidates_on_snapshot(Arc::clone(snap), &q)
                            .await
                            .map_err(|e| format!("tier2_query_error:{e}"))?,
                        _ => engine
                            .candidates(&q)
                            .await
                            .map_err(|e| format!("tier2_query_error:{e}"))?,
                    };
                    if batch.tier != SearchTier::Tier2Tantivy || batch.degraded {
                        return Err("tier2_returned_degraded_or_tier1".to_owned());
                    }
                    if let Some(expected_gen) = pinned_gen {
                        if batch.generation != expected_gen {
                            return Err(format!(
                                "tier2_generation_drift:expected={expected_gen},got={}",
                                batch.generation
                            ));
                        }
                    } else {
                        if batch.generation < mail_wm.generation
                            || batch.generation < att_wm.generation
                        {
                            return Err(format!(
                                "tier2_batch_generation_behind:batch={},mail={},att={}",
                                batch.generation, mail_wm.generation, att_wm.generation
                            ));
                        }
                        pinned_gen = Some(batch.generation);
                    }
                    for key in batch.keys {
                        match key {
                            DocumentKey::Mail { id, .. }
                            | DocumentKey::MailAttachment { id, .. }
                                if id > 0 =>
                            {
                                t2_msg_ids.insert(id);
                            }
                            _ => {}
                        }
                    }
                    match batch.continuation {
                        Some(next) if page_idx + 1 < MAX_EDISCOVERY_T2_PAGES => {
                            cursor = Some(next);
                        }
                        Some(_) => {
                            // Truncated Tier-2 result set -> fall back to full Tier-1 PG for exact completeness!
                            return Err("tier2_candidate_cap_exceeded".to_owned());
                        }
                        None => break,
                    }
                }
            }
        }

        // 2. Deterministic per-corpus PG tail scan over ALL unindexed / post-watermark outbox rows
        //    (`mail` > `mail_wm.indexed_outbox_seq`, `mail_attachment` > `att_wm.indexed_outbox_seq`)
        //    plus any pending `search_dirty_keys` for `mail`/`mail_attachment`.
        let mail_wm_seq = mail_wm.indexed_outbox_seq;
        let att_wm_seq = att_wm.indexed_outbox_seq;
        let min_watermark_seq = mail_wm_seq.min(att_wm_seq);
        let tail_params: [Param<'_>; 2] = [(&mail_wm_seq, Type::INT8), (&att_wm_seq, Type::INT8)];
        let tail_rows = self
            .db
            .query_typed(
                "SELECT DISTINCT o.entity_id \
                   FROM public.search_index_outbox o \
                  WHERE o.entity_id > 0 \
                    AND ( \
                        (o.corpus = 'mail' AND (o.processed_at IS NULL OR o.seq > $1)) \
                        OR (o.corpus = 'mail_attachment' AND (o.processed_at IS NULL OR o.seq > $2)) \
                    ) \
                 UNION \
                 SELECT DISTINCT d.doc_id \
                   FROM public.search_dirty_keys d \
                  WHERE d.corpus IN ('mail', 'mail_attachment') \
                    AND d.doc_id > 0",
                &tail_params,
            )
            .await
            .map_err(|e| format!("tail_scan_error:{e}"))?;

        let mut tail_msg_ids: Vec<i64> = Vec::with_capacity(tail_rows.len());
        for row in &tail_rows {
            let id: i64 = col(row, 0).map_err(|e| format!("tail_decode:{e}"))?;
            if id > 0 {
                tail_msg_ids.push(id);
            }
        }
        let tail_rows_scanned = u64::try_from(tail_msg_ids.len()).unwrap_or(0);

        // 3. Union & deduplicate Tier-2 + PG tail IDs, then re-authorize AND re-verify
        //    tokenized keyword + attachment + compliance metadata predicates in ONE PG query
        //    so edited/stale Tier-2 hits never produce false positives.
        for id in &tail_msg_ids {
            t2_msg_ids.insert(*id);
        }
        let all_candidates: Vec<i64> = t2_msg_ids.into_iter().collect();
        let mut union_by_id: BTreeMap<i64, DateTime<Utc>> = BTreeMap::new();
        if !all_candidates.is_empty() {
            let valid = self
                .filter_candidate_ids_in_pg(&all_candidates, parsed)
                .await
                .map_err(|e| format!("pg_reauth_error:{e}"))?;
            for (id, ts) in valid {
                union_by_id.insert(id, ts);
            }
        }

        // Deterministic sort: received_at DESC, id DESC.
        let mut sorted: Vec<(i64, DateTime<Utc>)> = union_by_id.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));
        let total = i64::try_from(sorted.len()).unwrap_or(i64::MAX);
        let top_ids: Vec<i64> = sorted
            .into_iter()
            .take(MAX_PERSISTED_RESULTS)
            .map(|(id, _)| id)
            .collect();

        Ok(Some((
            top_ids,
            total,
            EdiscoveryProvenance {
                engine_tier: "tier2_tantivy_plus_pg_tail".to_owned(),
                epoch: Some(engine_epoch),
                generation: Some(pinned_gen.unwrap_or(engine_gen)),
                indexed_outbox_seq: Some(min_watermark_seq),
                tail_rows_scanned,
                degraded_reason: None,
                extraction_status_counts: ExtractionStatusSummary::default(),
                result_count: total,
            },
        )))
    }

    async fn load_watermark(&self, corpus: DocCorpus) -> Result<Option<WatermarkRow>, SearchError> {
        let corpus_str = corpus.as_str();
        let params: [Param<'_>; 1] = [(&corpus_str, Type::TEXT)];
        let rows = self
            .db
            .query_typed(
                "SELECT epoch, generation, indexed_outbox_seq \
                   FROM public.search_index_watermarks \
                  WHERE corpus = $1",
                &params,
            )
            .await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let epoch_i64: i64 = col(row, 0)?;
        let gen_i64: i64 = col(row, 1)?;
        let seq: i64 = col(row, 2)?;
        Ok(Some(WatermarkRow {
            epoch: u64::try_from(epoch_i64).unwrap_or(0),
            generation: u64::try_from(gen_i64).unwrap_or(0),
            indexed_outbox_seq: seq,
        }))
    }

    async fn filter_candidate_ids_in_pg(
        &self,
        ids: &[i64],
        parsed: &ParsedEdiscoveryQuery,
    ) -> Result<Vec<(i64, DateTime<Utc>)>, SearchError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids_vec = ids.to_vec();
        let from_pat = parsed
            .from_addr
            .as_deref()
            .map(|s| escape_like_pattern(s).to_lowercase());
        let date_from = parsed.date_from;
        let date_to = parsed.date_to;
        let mailbox_ids = parsed.mailbox_ids.clone();
        let raw_kw = parsed.keywords.trim().to_owned();
        let has_boolean_syntax = has_websearch_boolean_syntax(&raw_kw);
        let token_pats = if has_boolean_syntax {
            Vec::new()
        } else {
            tokenized_like_patterns(&raw_kw)
        };
        let has_kw = !raw_kw.is_empty();
        let use_token_like = !has_boolean_syntax && !token_pats.is_empty();

        // Matching: when websearch boolean/phrase/negation syntax (`OR`, `"..."`, `-term`) is
        // present, evaluate PostgreSQL `websearch_to_tsquery('simple', $7)` faithfully (including
        // non-sealed attachment filename/extracted text); otherwise require EVERY parsed token to
        // match across envelope, non-sealed body, or non-sealed attachments.
        let sql = "SELECT m.id, m.received_at \
                     FROM public.messages m \
                    WHERE m.id = ANY($1::bigint[]) \
                      AND ($2::text IS NULL OR lower(coalesce(m.from_addr, '')) LIKE $2 ESCAPE '\\') \
                      AND ($3::timestamptz IS NULL OR m.received_at >= $3) \
                      AND ($4::timestamptz IS NULL OR m.received_at <= $4) \
                      AND ($5::bigint[] IS NULL OR m.mailbox_id = ANY($5::bigint[])) \
                      AND ($6::boolean = false OR ( \
                          m.subject_tsv @@ websearch_to_tsquery('simple', $7) \
                          OR m.from_tsv @@ websearch_to_tsquery('simple', $7) \
                          OR (m.crypto_type IS DISTINCT FROM 'smime-encrypted' \
                              AND m.body_tsv @@ websearch_to_tsquery('simple', $7)) \
                          OR (m.crypto_type IS DISTINCT FROM 'smime-encrypted' AND EXISTS ( \
                              SELECT 1 FROM public.message_attachments ma \
                              LEFT JOIN public.search_extracted_text et \
                                ON et.content_sha256 = ma.blob_sha256 \
                               WHERE ma.message_id = m.id AND ma.received_at = m.received_at \
                                 AND (to_tsvector('simple', coalesce(ma.filename, '')) @@ websearch_to_tsquery('simple', $7) \
                                      OR to_tsvector('simple', coalesce(et.extracted_text, '')) @@ websearch_to_tsquery('simple', $7)))) \
                          OR ($9::boolean AND NOT EXISTS ( \
                              SELECT 1 FROM unnest($8::text[]) AS tok(pat) \
                               WHERE NOT ( \
                                   lower(coalesce(m.subject, '')) LIKE tok.pat ESCAPE '\\' \
                                   OR lower(coalesce(m.from_addr, '')) LIKE tok.pat ESCAPE '\\' \
                                   OR (m.crypto_type IS DISTINCT FROM 'smime-encrypted' \
                                       AND lower(coalesce(m.body_text, '')) LIKE tok.pat ESCAPE '\\') \
                                   OR (m.crypto_type IS DISTINCT FROM 'smime-encrypted' AND EXISTS ( \
                                       SELECT 1 FROM public.message_attachments ma \
                                       LEFT JOIN public.search_extracted_text et \
                                         ON et.content_sha256 = ma.blob_sha256 \
                                        WHERE ma.message_id = m.id AND ma.received_at = m.received_at \
                                          AND (lower(coalesce(ma.filename, '')) LIKE tok.pat ESCAPE '\\' \
                                               OR lower(coalesce(et.extracted_text, '')) LIKE tok.pat ESCAPE '\\'))) \
                               ) \
                          )) \
                      ))";

        let params: [Param<'_>; 9] = [
            (&ids_vec, Type::INT8_ARRAY),
            (&from_pat, Type::TEXT),
            (&date_from, Type::TIMESTAMPTZ),
            (&date_to, Type::TIMESTAMPTZ),
            (&mailbox_ids, Type::INT8_ARRAY),
            (&has_kw, Type::BOOL),
            (&raw_kw, Type::TEXT),
            (&token_pats, Type::TEXT_ARRAY),
            (&use_token_like, Type::BOOL),
        ];
        let rows = self.db.query_typed(sql, &params).await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push((col(row, 0)?, col(row, 1)?));
        }
        Ok(out)
    }

    async fn run_tier1_pg_search(
        &self,
        parsed: &ParsedEdiscoveryQuery,
    ) -> Result<(Vec<i64>, i64), SearchError> {
        let raw_kw = parsed.keywords.trim().to_owned();
        let has_boolean_syntax = has_websearch_boolean_syntax(&raw_kw);
        let token_pats = if has_boolean_syntax {
            Vec::new()
        } else {
            tokenized_like_patterns(&raw_kw)
        };
        let has_kw = !raw_kw.is_empty();
        let use_token_like = !has_boolean_syntax && !token_pats.is_empty();
        let from_pat = parsed
            .from_addr
            .as_deref()
            .map(|s| escape_like_pattern(s).to_lowercase());
        let date_from = parsed.date_from;
        let date_to = parsed.date_to;
        let mailbox_ids = parsed.mailbox_ids.clone();

        let where_clause = "WHERE ($1::boolean = false OR ( \
                m.subject_tsv @@ websearch_to_tsquery('simple', $2) \
                OR m.from_tsv @@ websearch_to_tsquery('simple', $2) \
                OR (m.crypto_type IS DISTINCT FROM 'smime-encrypted' \
                    AND m.body_tsv @@ websearch_to_tsquery('simple', $2)) \
                OR (m.crypto_type IS DISTINCT FROM 'smime-encrypted' AND EXISTS ( \
                    SELECT 1 FROM public.message_attachments ma \
                    LEFT JOIN public.search_extracted_text et \
                      ON et.content_sha256 = ma.blob_sha256 \
                     WHERE ma.message_id = m.id AND ma.received_at = m.received_at \
                       AND (to_tsvector('simple', coalesce(ma.filename, '')) @@ websearch_to_tsquery('simple', $2) \
                            OR to_tsvector('simple', coalesce(et.extracted_text, '')) @@ websearch_to_tsquery('simple', $2)))) \
                OR ($8::boolean AND NOT EXISTS ( \
                    SELECT 1 FROM unnest($3::text[]) AS tok(pat) \
                     WHERE NOT ( \
                         lower(coalesce(m.subject, '')) LIKE tok.pat ESCAPE '\\' \
                         OR lower(coalesce(m.from_addr, '')) LIKE tok.pat ESCAPE '\\' \
                         OR (m.crypto_type IS DISTINCT FROM 'smime-encrypted' \
                             AND lower(coalesce(m.body_text, '')) LIKE tok.pat ESCAPE '\\') \
                         OR (m.crypto_type IS DISTINCT FROM 'smime-encrypted' AND EXISTS ( \
                             SELECT 1 FROM public.message_attachments ma \
                             LEFT JOIN public.search_extracted_text et \
                               ON et.content_sha256 = ma.blob_sha256 \
                              WHERE ma.message_id = m.id AND ma.received_at = m.received_at \
                                AND (lower(coalesce(ma.filename, '')) LIKE tok.pat ESCAPE '\\' \
                                     OR lower(coalesce(et.extracted_text, '')) LIKE tok.pat ESCAPE '\\'))) \
                     ) \
                )) \
            )) \
            AND ($4::text IS NULL OR lower(coalesce(m.from_addr, '')) LIKE $4 ESCAPE '\\') \
            AND ($5::timestamptz IS NULL OR m.received_at >= $5) \
            AND ($6::timestamptz IS NULL OR m.received_at <= $6) \
            AND ($7::bigint[] IS NULL OR m.mailbox_id = ANY($7::bigint[]))";

        let params: [Param<'_>; 8] = [
            (&has_kw, Type::BOOL),
            (&raw_kw, Type::TEXT),
            (&token_pats, Type::TEXT_ARRAY),
            (&from_pat, Type::TEXT),
            (&date_from, Type::TIMESTAMPTZ),
            (&date_to, Type::TIMESTAMPTZ),
            (&mailbox_ids, Type::INT8_ARRAY),
            (&use_token_like, Type::BOOL),
        ];

        let count_sql = format!("SELECT count(*)::bigint FROM public.messages m {where_clause}");
        let count_rows = self.db.query_typed(&count_sql, &params).await?;
        let total: i64 = count_rows
            .first()
            .map(|r| col(r, 0))
            .transpose()?
            .unwrap_or(0);

        let ids_sql = format!(
            "SELECT m.id FROM public.messages m {where_clause} ORDER BY m.received_at DESC, m.id DESC LIMIT {MAX_PERSISTED_RESULTS}"
        );
        let id_rows = self.db.query_typed(&ids_sql, &params).await?;
        let mut ids = Vec::with_capacity(id_rows.len());
        for row in &id_rows {
            ids.push(col(row, 0)?);
        }
        Ok((ids, total))
    }

    async fn compute_extraction_status_summary(
        &self,
        parsed: &ParsedEdiscoveryQuery,
    ) -> Result<ExtractionStatusSummary, SearchError> {
        let from_pat = parsed
            .from_addr
            .as_deref()
            .map(|s| escape_like_pattern(s).to_lowercase());
        let date_from = parsed.date_from;
        let date_to = parsed.date_to;
        let mailbox_ids = parsed.mailbox_ids.clone();

        // S/MIME encrypted messages (V029 C7) NEVER have attachment plaintext searched by
        // either Tier-2 or Tier-1; report their attachments honestly as `'encrypted'`.
        let sql = "SELECT CASE \
                            WHEN m.crypto_type = 'smime-encrypted' THEN 'encrypted' \
                            ELSE COALESCE(et.extraction_status, 'pending_extraction') \
                          END AS st, \
                          count(*)::bigint \
                     FROM public.message_attachments ma \
                     JOIN public.messages m \
                       ON m.id = ma.message_id AND m.received_at = ma.received_at \
                     LEFT JOIN public.search_extracted_text et \
                       ON et.content_sha256 = ma.blob_sha256 \
                    WHERE ($1::text IS NULL OR lower(coalesce(m.from_addr, '')) LIKE $1 ESCAPE '\\') \
                      AND ($2::timestamptz IS NULL OR m.received_at >= $2) \
                      AND ($3::timestamptz IS NULL OR m.received_at <= $3) \
                      AND ($4::bigint[] IS NULL OR m.mailbox_id = ANY($4::bigint[])) \
                    GROUP BY 1";
        let params: [Param<'_>; 4] = [
            (&from_pat, Type::TEXT),
            (&date_from, Type::TIMESTAMPTZ),
            (&date_to, Type::TIMESTAMPTZ),
            (&mailbox_ids, Type::INT8_ARRAY),
        ];
        let rows = self.db.query_typed(sql, &params).await?;
        let mut summary = ExtractionStatusSummary::default();
        for row in &rows {
            let status: String = col(row, 0)?;
            let count_i64: i64 = col(row, 1)?;
            let count = u64::try_from(count_i64).unwrap_or(0);
            match status.as_str() {
                "extracted" => summary.extracted = summary.extracted.saturating_add(count),
                "encrypted" => summary.encrypted = summary.encrypted.saturating_add(count),
                "unsupported" => summary.unsupported = summary.unsupported.saturating_add(count),
                "truncated_limit" => {
                    summary.truncated_limit = summary.truncated_limit.saturating_add(count);
                }
                "failed" => summary.failed = summary.failed.saturating_add(count),
                _ => {
                    summary.pending_extraction = summary.pending_extraction.saturating_add(count);
                }
            }
        }
        Ok(summary)
    }

    async fn persist_results_and_audit_atomic(
        &self,
        search_id: i64,
        actor_id: i64,
        matched_ids: &[i64],
        total_count: i64,
        provenance: &EdiscoveryProvenance,
    ) -> Result<(), SearchError> {
        let ids_vec = matched_ids.to_vec();
        let prov_json = serde_json::to_string(provenance)
            .map_err(|e| SearchError::Internal(format!("serialize provenance: {e}")))?;
        let params: [Param<'_>; 5] = [
            (&actor_id, Type::INT8),
            (&search_id, Type::INT8),
            (&ids_vec, Type::INT8_ARRAY),
            (&total_count, Type::INT8),
            (&prov_json, Type::TEXT),
        ];
        let _ = self
            .db
            .query_typed(
                "SELECT public.search_ediscovery_complete_atomic($1, $2, $3, $4, $5::text::jsonb)",
                &params,
            )
            .await?;
        Ok(())
    }

    async fn complete_kql_atomic(
        &self,
        search_id: i64,
        actor_id: i64,
        predicate: &str,
        values: &[String],
        provenance: &EdiscoveryProvenance,
    ) -> Result<i64, SearchError> {
        let pred_owned = predicate.to_owned();
        let values_vec = values.to_vec();
        let prov_json = serde_json::to_string(provenance)
            .map_err(|e| SearchError::Internal(format!("serialize kql provenance: {e}")))?;
        let params: [Param<'_>; 5] = [
            (&actor_id, Type::INT8),
            (&search_id, Type::INT8),
            (&pred_owned, Type::TEXT),
            (&values_vec, Type::TEXT_ARRAY),
            (&prov_json, Type::TEXT),
        ];
        let rows = self
            .db
            .query_typed(
                "SELECT public.search_ediscovery_complete_kql_atomic($1, $2, $3, $4, $5::text::jsonb)",
                &params,
            )
            .await?;
        let count: i64 = rows.first().map(|r| col(r, 0)).transpose()?.unwrap_or(0);
        Ok(count)
    }
}

fn tokenized_like_patterns(raw_kw: &str) -> Vec<String> {
    if let Ok(norm) = NormalizedQuery::parse(raw_kw) {
        let mut out = Vec::with_capacity(norm.terms().len());
        for term in norm.terms() {
            let trimmed = term.trim().trim_matches('"');
            if !trimmed.is_empty() {
                out.push(escape_like_pattern(trimmed).to_lowercase());
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    raw_kw
        .split_whitespace()
        .map(|s| s.trim_matches('"'))
        .filter(|s| !s.is_empty())
        .map(|s| escape_like_pattern(s).to_lowercase())
        .collect()
}

fn parse_ediscovery_query(val: &serde_json::Value) -> Result<ParsedEdiscoveryQuery, SearchError> {
    let keywords = val
        .get("keywords")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();
    let kql = val
        .get("kql")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();
    let from_addr = val
        .get("fromAddr")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let date_from = val
        .get("dateFrom")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| SearchError::Internal(format!("invalid dateFrom {s:?}: {e}")))
        })
        .transpose()?;
    let date_to = val
        .get("dateTo")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| SearchError::Internal(format!("invalid dateTo {s:?}: {e}")))
        })
        .transpose()?;
    let mailbox_ids = val
        .get("mailboxIds")
        .and_then(serde_json::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    v.as_i64()
                        .or_else(|| v.as_f64().map(|f| f as i64))
                        .filter(|n| *n > 0)
                })
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty());

    Ok(ParsedEdiscoveryQuery {
        keywords,
        kql,
        from_addr,
        date_from,
        date_to,
        mailbox_ids,
    })
}

fn has_websearch_boolean_syntax(keywords: &str) -> bool {
    if keywords.contains('"') {
        return true;
    }
    keywords
        .split_whitespace()
        .any(|tok| tok.eq_ignore_ascii_case("or") || (tok.starts_with('-') && tok.len() > 1))
}

fn col<T: for<'a> tokio_postgres::types::FromSql<'a>>(
    row: &Row,
    idx: usize,
) -> Result<T, SearchError> {
    row.try_get(idx)
        .map_err(|e| SearchError::Database(format!("ediscovery column {idx} decode failed: {e}")))
}
