//! Tier-1 PostgreSQL baseline search engine and startup `pg_bigm` / `pg_trgm` capability probe.
//!
//! Never requires `pg_bigm` to be installed (preserving Xinchuang and managed-PG compatibility).
//! All tenant queries execute strictly inside `MailboxTx<ReadOnly>` or `UserTx<ReadOnly>`
//! (`AppPool`, `setjoin_app`, `NOBYPASSRLS`) with explicit R1 ownership predicates.

use crate::model::{
    BoxFuture, CandidateBatch, CandidateQuery, DocCorpus, DocumentKey, EngineHealth, ScopeHint,
    SearchEngine, SearchError, SearchTier, SearchVisibility, MAX_SCOPE_IDS,
};
use chrono::{DateTime, Utc};
use setjoin_pg::{MailboxTx, Param, ReadOnly, Row, ScopedExecutor, Type, UserTx};
use std::sync::Arc;

/// Probed PostgreSQL search extension & valid expression-matched `gin_bigm_ops` index capabilities.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PgSearchCapabilities {
    pub has_pg_bigm: bool,
    pub has_pg_trgm: bool,
    pub has_bigm_messages_idx: bool,
    pub has_bigm_chat_idx: bool,
    pub has_bigm_drive_idx: bool,
}

const CAPABILITY_PROBE_SQL: &str = "SELECT \
    EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_bigm'), \
    EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'), \
    EXISTS( \
        SELECT 1 \
          FROM pg_index ix \
          JOIN pg_class tbl ON tbl.oid = ix.indrelid \
          JOIN pg_namespace ns ON ns.oid = tbl.relnamespace \
          JOIN pg_opclass opc ON opc.oid = ANY(ix.indclass::oid[]) \
         WHERE ns.nspname = 'public' AND tbl.relname = 'messages' \
           AND ix.indisvalid AND ix.indisready AND opc.opcname = 'gin_bigm_ops' \
           AND lower(pg_get_indexdef(ix.indexrelid)) LIKE '%lower(coalesce(subject, ''''::text))%gin_bigm_ops%' \
    ), \
    EXISTS( \
        SELECT 1 \
          FROM pg_index ix \
          JOIN pg_class tbl ON tbl.oid = ix.indrelid \
          JOIN pg_namespace ns ON ns.oid = tbl.relnamespace \
          JOIN pg_opclass opc ON opc.oid = ANY(ix.indclass::oid[]) \
         WHERE ns.nspname = 'public' AND tbl.relname = 'chat_messages' \
           AND ix.indisvalid AND ix.indisready AND opc.opcname = 'gin_bigm_ops' \
           AND lower(pg_get_indexdef(ix.indexrelid)) LIKE '%lower(body)%gin_bigm_ops%' \
    ), \
    EXISTS( \
        SELECT 1 \
          FROM pg_index ix \
          JOIN pg_class tbl ON tbl.oid = ix.indrelid \
          JOIN pg_namespace ns ON ns.oid = tbl.relnamespace \
          JOIN pg_opclass opc ON opc.oid = ANY(ix.indclass::oid[]) \
         WHERE ns.nspname = 'public' AND tbl.relname = 'drive_nodes' \
           AND ix.indisvalid AND ix.indisready AND opc.opcname = 'gin_bigm_ops' \
           AND lower(pg_get_indexdef(ix.indexrelid)) LIKE '%lower(name)%gin_bigm_ops%' \
    )";

fn decode_capabilities_row(row: &Row) -> Result<PgSearchCapabilities, SearchError> {
    Ok(PgSearchCapabilities {
        has_pg_bigm: row
            .try_get::<_, bool>(0)
            .map_err(|e| SearchError::Database(format!("decode has_pg_bigm: {e}")))?,
        has_pg_trgm: row
            .try_get::<_, bool>(1)
            .map_err(|e| SearchError::Database(format!("decode has_pg_trgm: {e}")))?,
        has_bigm_messages_idx: row
            .try_get::<_, bool>(2)
            .map_err(|e| SearchError::Database(format!("decode has_bigm_messages_idx: {e}")))?,
        has_bigm_chat_idx: row
            .try_get::<_, bool>(3)
            .map_err(|e| SearchError::Database(format!("decode has_bigm_chat_idx: {e}")))?,
        has_bigm_drive_idx: row
            .try_get::<_, bool>(4)
            .map_err(|e| SearchError::Database(format!("decode has_bigm_drive_idx: {e}")))?,
    })
}

/// Probe `pg_extension` and valid expression-matched `gin_bigm_ops` indexes via a [`ScopedExecutor`].
pub async fn probe_pg_capabilities_exec(
    exec: &ScopedExecutor,
) -> Result<PgSearchCapabilities, SearchError> {
    let rows = exec
        .read(CAPABILITY_PROBE_SQL, &[])
        .await
        .map_err(|e| SearchError::Database(format!("pg search capability probe: {e:?}")))?;
    let Some(row) = rows.first() else {
        return Ok(PgSearchCapabilities::default());
    };
    decode_capabilities_row(row)
}

/// Probe `pg_extension` and valid expression-matched `gin_bigm_ops` indexes via a direct `tokio_postgres::Client`.
pub async fn probe_pg_capabilities_client(
    client: &tokio_postgres::Client,
) -> Result<PgSearchCapabilities, SearchError> {
    let row = client
        .query_one(CAPABILITY_PROBE_SQL, &[])
        .await
        .map_err(|e| SearchError::Database(format!("pg search capability probe: {e}")))?;
    decode_capabilities_row(&row)
}

/// Escape `LIKE` / `ILIKE` metacharacters (`\`, `%`, `_`) and wrap as `%<escaped>%`.
#[must_use]
pub fn escape_like_pattern(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 4);
    out.push('%');
    for ch in raw.chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out.push('%');
    out
}

fn reject_compliance_visibility(visibility: SearchVisibility) -> Result<(), SearchError> {
    if visibility == SearchVisibility::ComplianceOnly {
        return Err(SearchError::Unavailable(
            "compliance_only visibility is not permitted on user-scoped Tier-1 search".to_owned(),
        ));
    }
    Ok(())
}

/// Tier-1 PG baseline mail candidate search executed strictly inside `MailboxTx<ReadOnly>`
/// (`AppPool`, `setjoin_app`, `NOBYPASSRLS`).
///
/// Enforces:
/// - Rejects `SearchVisibility::ComplianceOnly` on user-scoped Tier-1.
/// - R1 explicit `m.mailbox_id = $1` + native RLS backstop (`app.current_mailbox_id`).
/// - `m.is_deleted = false` (excludes soft-deleted and held-deleted compliance tombstones).
/// - S/MIME `V029` C7 boundary (`crypto_type IS DISTINCT FROM 'smime-encrypted'` for body matching).
/// - Works with or without `pg_bigm` installed (Xinchuang-safe).
pub async fn tier1_mail_candidates(
    tx: &mut MailboxTx<ReadOnly>,
    query: &CandidateQuery,
    caps: PgSearchCapabilities,
) -> Result<CandidateBatch, SearchError> {
    reject_compliance_visibility(query.visibility)?;
    let mailbox_id = tx.mailbox().get();
    if let ScopeHint::Mailbox(hint_id) = query.scope_hint {
        if hint_id != mailbox_id {
            return Ok(CandidateBatch {
                keys: Vec::new(),
                generation: 0,
                continuation: None,
                tier: SearchTier::Tier1Pg,
                degraded: false,
            });
        }
    }

    let raw_query = query.terms.raw().to_owned();
    let like_pat = escape_like_pattern(&raw_query).to_lowercase();
    let limit = i64::try_from(query.effective_limit()).unwrap_or(500);

    let use_bigm_only = caps.has_pg_bigm && caps.has_bigm_messages_idx && query.terms.has_cjk();
    let rows = if use_bigm_only {
        let sql = "SELECT m.mailbox_id, m.id, m.received_at \
                   FROM public.messages m \
                   WHERE m.mailbox_id = $1 \
                     AND m.is_deleted = false \
                     AND ( \
                       lower(coalesce(m.subject, '')) LIKE $2 ESCAPE '\\' \
                       OR lower(coalesce(m.from_addr, '')) LIKE $2 ESCAPE '\\' \
                       OR lower(coalesce(m.from_name, '')) LIKE $2 ESCAPE '\\' \
                       OR (m.crypto_type IS DISTINCT FROM 'smime-encrypted' \
                           AND lower(coalesce(m.body_text, '')) LIKE $2 ESCAPE '\\') \
                     ) \
                   ORDER BY m.received_at DESC, m.id DESC \
                   LIMIT $3";
        let params: [Param<'_>; 3] = [
            (&mailbox_id, Type::INT8),
            (&like_pat, Type::TEXT),
            (&limit, Type::INT8),
        ];
        tx.query(sql, &params)
            .await
            .map_err(|e| SearchError::Database(format!("tier1 mail bigm query: {e:?}")))?
    } else {
        let sql = "SELECT m.mailbox_id, m.id, m.received_at \
                   FROM public.messages m \
                   WHERE m.mailbox_id = $1 \
                     AND m.is_deleted = false \
                     AND ( \
                       m.subject_tsv @@ websearch_to_tsquery('simple', $2) \
                       OR m.from_tsv @@ websearch_to_tsquery('simple', $2) \
                       OR (m.crypto_type IS DISTINCT FROM 'smime-encrypted' \
                           AND m.body_tsv @@ websearch_to_tsquery('simple', $2)) \
                       OR lower(coalesce(m.subject, '')) LIKE $3 ESCAPE '\\' \
                       OR lower(coalesce(m.from_addr, '')) LIKE $3 ESCAPE '\\' \
                       OR lower(coalesce(m.from_name, '')) LIKE $3 ESCAPE '\\' \
                       OR (m.crypto_type IS DISTINCT FROM 'smime-encrypted' \
                           AND lower(coalesce(m.body_text, '')) LIKE $3 ESCAPE '\\') \
                     ) \
                   ORDER BY m.received_at DESC, m.id DESC \
                   LIMIT $4";
        let params: [Param<'_>; 4] = [
            (&mailbox_id, Type::INT8),
            (&raw_query, Type::TEXT),
            (&like_pat, Type::TEXT),
            (&limit, Type::INT8),
        ];
        tx.query(sql, &params)
            .await
            .map_err(|e| SearchError::Database(format!("tier1 mail query: {e:?}")))?
    };

    let mut keys = Vec::with_capacity(rows.len());
    for row in &rows {
        let mb: i64 = row
            .try_get(0)
            .map_err(|e| SearchError::Database(format!("decode mail mailbox_id: {e}")))?;
        let id: i64 = row
            .try_get(1)
            .map_err(|e| SearchError::Database(format!("decode mail id: {e}")))?;
        let received_at: DateTime<Utc> = row
            .try_get(2)
            .map_err(|e| SearchError::Database(format!("decode mail received_at: {e}")))?;
        keys.push(DocumentKey::Mail {
            mailbox_id: mb,
            id,
            received_at,
        });
    }

    Ok(CandidateBatch {
        keys,
        generation: 0,
        continuation: None,
        tier: SearchTier::Tier1Pg,
        degraded: false,
    })
}

/// Tier-1 PG baseline chat candidate search executed strictly inside `UserTx<ReadOnly>`
/// (`AppPool`, `setjoin_app`, `NOBYPASSRLS`).
///
/// Enforces:
/// - Rejects `SearchVisibility::ComplianceOnly` on user-scoped Tier-1.
/// - Preserves `ScopeHint::Channels(ids)` filtering (empty list returns empty immediately).
/// - Live `chat_channel_members` membership, `deleted_at IS NULL`, `GUEST_HISTORY_FLOOR`,
///   and parent message history floor.
/// - Preserves the ASCII full-text (`search_tsv`) branch even when `pg_bigm` is installed
///   (using `pg_bigm` LIKE-only strictly for CJK/non-ASCII queries).
pub async fn tier1_chat_candidates(
    tx: &mut UserTx<ReadOnly>,
    query: &CandidateQuery,
    _caps: PgSearchCapabilities,
) -> Result<CandidateBatch, SearchError> {
    reject_compliance_visibility(query.visibility)?;

    let channel_filter: Option<Vec<i64>> = match &query.scope_hint {
        ScopeHint::Channels(ids) => {
            if ids.is_empty() {
                return Ok(CandidateBatch {
                    keys: Vec::new(),
                    generation: 0,
                    continuation: None,
                    tier: SearchTier::Tier1Pg,
                    degraded: false,
                });
            }
            Some(ids.iter().take(MAX_SCOPE_IDS).copied().collect())
        }
        _ => None,
    };

    let user_id = tx.actor().get();
    let raw_query = query.terms.raw().to_owned();
    let like_pat = escape_like_pattern(&raw_query).to_lowercase();
    let limit = i64::try_from(query.effective_limit()).unwrap_or(500);

    let non_ascii_or_cjk = query.terms.has_cjk() || !raw_query.is_ascii();
    let rows = if non_ascii_or_cjk {
        let sql = "SELECT m.channel_id, m.id \
                   FROM public.chat_messages m \
                   JOIN public.chat_channel_members cm \
                     ON cm.channel_id = m.channel_id AND cm.user_id = $1 \
                   WHERE m.deleted_at IS NULL \
                     AND ($4::bigint[] IS NULL OR m.channel_id = ANY($4::bigint[])) \
                     AND m.seq > COALESCE(cm.history_floor_seq, 0) \
                     AND (cm.history_floor_seq IS NULL OR m.created_at >= cm.joined_at) \
                     AND (m.parent_message_id IS NULL OR EXISTS ( \
                           SELECT 1 FROM public.chat_messages parent \
                            WHERE parent.id = m.parent_message_id \
                              AND parent.seq > COALESCE(cm.history_floor_seq, 0) \
                              AND (cm.history_floor_seq IS NULL OR parent.created_at >= cm.joined_at))) \
                     AND lower(m.body) LIKE $2 ESCAPE '\\' \
                   ORDER BY m.id DESC \
                   LIMIT $3";
        let params: [Param<'_>; 4] = [
            (&user_id, Type::INT8),
            (&like_pat, Type::TEXT),
            (&limit, Type::INT8),
            (&channel_filter, Type::INT8_ARRAY),
        ];
        tx.query(sql, &params)
            .await
            .map_err(|e| SearchError::Database(format!("tier1 chat like query: {e:?}")))?
    } else {
        let sql = "SELECT m.channel_id, m.id \
                   FROM public.chat_messages m \
                   JOIN public.chat_channel_members cm \
                     ON cm.channel_id = m.channel_id AND cm.user_id = $1 \
                   WHERE m.deleted_at IS NULL \
                     AND ($5::bigint[] IS NULL OR m.channel_id = ANY($5::bigint[])) \
                     AND m.seq > COALESCE(cm.history_floor_seq, 0) \
                     AND (cm.history_floor_seq IS NULL OR m.created_at >= cm.joined_at) \
                     AND (m.parent_message_id IS NULL OR EXISTS ( \
                           SELECT 1 FROM public.chat_messages parent \
                            WHERE parent.id = m.parent_message_id \
                              AND parent.seq > COALESCE(cm.history_floor_seq, 0) \
                              AND (cm.history_floor_seq IS NULL OR parent.created_at >= cm.joined_at))) \
                     AND (m.search_tsv @@ plainto_tsquery('simple', $2) \
                          OR lower(m.body) LIKE $3 ESCAPE '\\') \
                   ORDER BY m.id DESC \
                   LIMIT $4";
        let params: [Param<'_>; 5] = [
            (&user_id, Type::INT8),
            (&raw_query, Type::TEXT),
            (&like_pat, Type::TEXT),
            (&limit, Type::INT8),
            (&channel_filter, Type::INT8_ARRAY),
        ];
        tx.query(sql, &params)
            .await
            .map_err(|e| SearchError::Database(format!("tier1 chat fts query: {e:?}")))?
    };

    let mut keys = Vec::with_capacity(rows.len());
    for row in &rows {
        let channel_id: i64 = row
            .try_get(0)
            .map_err(|e| SearchError::Database(format!("decode chat channel_id: {e}")))?;
        let id: i64 = row
            .try_get(1)
            .map_err(|e| SearchError::Database(format!("decode chat id: {e}")))?;
        keys.push(DocumentKey::Chat { channel_id, id });
    }

    Ok(CandidateBatch {
        keys,
        generation: 0,
        continuation: None,
        tier: SearchTier::Tier1Pg,
        degraded: false,
    })
}

/// Tier-1 PG baseline Drive node candidate search executed strictly inside `UserTx<ReadOnly>`
/// (`AppPool`, `setjoin_app`, `NOBYPASSRLS`).
///
/// Enforces:
/// - Rejects `SearchVisibility::ComplianceOnly` on user-scoped Tier-1.
/// - Preserves `ScopeHint::Spaces(ids)` filtering (empty list returns empty immediately).
/// - `deleted_at IS NULL AND purged_at IS NULL` + batched
///   `drive_runtime_capability_sources_set(user_id, space_id, node_ids, 'read_metadata')`.
pub async fn tier1_drive_candidates(
    tx: &mut UserTx<ReadOnly>,
    query: &CandidateQuery,
    _caps: PgSearchCapabilities,
) -> Result<CandidateBatch, SearchError> {
    reject_compliance_visibility(query.visibility)?;

    let space_filter: Option<Vec<i64>> = match &query.scope_hint {
        ScopeHint::Spaces(ids) => {
            if ids.is_empty() {
                return Ok(CandidateBatch {
                    keys: Vec::new(),
                    generation: 0,
                    continuation: None,
                    tier: SearchTier::Tier1Pg,
                    degraded: false,
                });
            }
            Some(ids.iter().take(MAX_SCOPE_IDS).copied().collect())
        }
        _ => None,
    };

    let user_id = tx.actor().get();
    let like_pat = escape_like_pattern(query.terms.raw()).to_lowercase();
    let limit = i64::try_from(query.effective_limit()).unwrap_or(500);

    let sql = "SELECT n.space_id, n.id \
                 FROM ( \
                   SELECT DISTINCT c.space_id, x.node_id \
                     FROM ( \
                       SELECT n2.space_id, array_agg(n2.id ORDER BY n2.id) AS node_ids \
                         FROM public.drive_nodes n2 \
                        WHERE n2.deleted_at IS NULL AND n2.purged_at IS NULL \
                          AND ($4::bigint[] IS NULL OR n2.space_id = ANY($4::bigint[])) \
                          AND lower(n2.name) LIKE $2 ESCAPE '\\' \
                        GROUP BY n2.space_id \
                     ) c \
                     CROSS JOIN LATERAL public.drive_runtime_capability_sources_set( \
                       $1, c.space_id, c.node_ids, 'read_metadata') x \
                 ) r \
                 JOIN public.drive_nodes n \
                   ON n.space_id = r.space_id AND n.id = r.node_id \
                ORDER BY lower(n.name), n.id \
                LIMIT $3";

    let params: [Param<'_>; 4] = [
        (&user_id, Type::INT8),
        (&like_pat, Type::TEXT),
        (&limit, Type::INT8),
        (&space_filter, Type::INT8_ARRAY),
    ];
    let rows = tx
        .query(sql, &params)
        .await
        .map_err(|e| SearchError::Database(format!("tier1 drive query: {e:?}")))?;

    let mut keys = Vec::with_capacity(rows.len());
    for row in &rows {
        let space_id: i64 = row
            .try_get(0)
            .map_err(|e| SearchError::Database(format!("decode drive space_id: {e}")))?;
        let id: i64 = row
            .try_get(1)
            .map_err(|e| SearchError::Database(format!("decode drive id: {e}")))?;
        keys.push(DocumentKey::Drive { space_id, id });
    }

    Ok(CandidateBatch {
        keys,
        generation: 0,
        continuation: None,
        tier: SearchTier::Tier1Pg,
        degraded: false,
    })
}

/// Callback type supplying Tier-1 PG candidate results when invoked via the
/// object-safe [`SearchEngine`] seam.
pub type Tier1Resolver = Arc<
    dyn Fn(&CandidateQuery) -> BoxFuture<'_, Result<CandidateBatch, SearchError>> + Send + Sync,
>;

/// Tier-1 PostgreSQL [`SearchEngine`] adapter wrapping probed capabilities and a
/// scoped PG candidate resolver.
#[derive(Clone)]
pub struct Tier1PgSearchEngine {
    capabilities: PgSearchCapabilities,
    resolver: Tier1Resolver,
}

impl Tier1PgSearchEngine {
    #[must_use]
    pub fn new(capabilities: PgSearchCapabilities, resolver: Tier1Resolver) -> Self {
        Self {
            capabilities,
            resolver,
        }
    }

    #[must_use]
    pub const fn capabilities(&self) -> PgSearchCapabilities {
        self.capabilities
    }

    /// Returns `true` when `pg_bigm` is installed and has a valid expression-matched
    /// `gin_bigm_ops` index for the target corpus.
    #[must_use]
    pub const fn has_bigm_for(&self, corpus: DocCorpus) -> bool {
        if !self.capabilities.has_pg_bigm {
            return false;
        }
        match corpus {
            DocCorpus::Mail | DocCorpus::MailAttachment => self.capabilities.has_bigm_messages_idx,
            DocCorpus::Chat => self.capabilities.has_bigm_chat_idx,
            DocCorpus::Drive | DocCorpus::DriveFile => self.capabilities.has_bigm_drive_idx,
        }
    }
}

impl SearchEngine for Tier1PgSearchEngine {
    fn candidates<'a>(
        &'a self,
        query: &'a CandidateQuery,
    ) -> BoxFuture<'a, Result<CandidateBatch, SearchError>> {
        (self.resolver)(query)
    }

    fn tier(&self) -> SearchTier {
        SearchTier::Tier1Pg
    }

    fn health(&self) -> EngineHealth {
        EngineHealth::Healthy {
            epoch: 0,
            generation: 0,
        }
    }
}
