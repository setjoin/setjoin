//! Mandatory PostgreSQL candidate re-authorization helpers (R1–R4) and bounded
//! overfetch pagination (`overfetch = clamp(limit * 3, 64, 500)`, `MAX_ROUNDS = 4`,
//! strict total candidate cap `<= 1500`).
//!
//! Every Tier-2 candidate batch MUST pass through these helpers inside a scoped
//! `MailboxTx<ReadOnly>` or `UserTx<ReadOnly>` (`AppPool`, `setjoin_app`, `NOBYPASSRLS`)
//! before any hit is returned to a caller.

use crate::model::{
    CandidateQuery, DocumentKey, SearchEngine, SearchError, SearchTier, SearchVisibility,
};
use chrono::{DateTime, Utc};
use setjoin_pg::{MailboxTx, Param, ReadOnly, Type, UserTx};
use std::future::Future;

/// Maximum overfetch rounds before falling back to Tier-1 PG for a conclusive page.
pub const MAX_OVERFETCH_ROUNDS: usize = 4;

/// Maximum total Tier-2 candidates hydrated across all rounds for a single page.
pub const MAX_OVERFETCH_CANDIDATES: usize = 1_500;

/// Compute the bounded Tier-2 candidate overfetch limit for a requested page size:
/// `clamp(limit * 3, 64, 500)`.
#[must_use]
pub fn overfetch_limit(page_limit: u16) -> u16 {
    let tripled = u32::from(page_limit).saturating_mul(3);
    let clamped = tripled.clamp(64, 500);
    u16::try_from(clamped).unwrap_or(500)
}

/// Optional domain filters applied during mandatory PG mail re-authorization.
#[derive(Clone, Debug, Default)]
pub struct MailReauthFilter {
    pub folder_id: Option<i64>,
    pub tag_id: Option<i64>,
    /// When `true`, also exclude messages with `held = true` (live non-compliance views
    /// always exclude `is_deleted = true`, including held-deleted tombstones).
    pub exclude_held: bool,
}

/// Authorized mail hit hydrated from PostgreSQL under `MailboxTx<ReadOnly>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedMailHit {
    pub mailbox_id: i64,
    pub id: i64,
    pub received_at: DateTime<Utc>,
    pub subject: String,
    pub from_addr: String,
    pub crypto_sealed: bool,
}

/// Authorized chat hit hydrated from PostgreSQL under `UserTx<ReadOnly>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedChatHit {
    pub channel_id: i64,
    pub id: i64,
    pub author_id: i64,
    pub body: String,
}

/// Authorized drive hit hydrated from PostgreSQL under `UserTx<ReadOnly>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedDriveHit {
    pub space_id: i64,
    pub id: i64,
    pub kind: String,
    pub name: String,
}

/// Re-authorize and hydrate Tier-2 mail candidates inside a single `MailboxTx<ReadOnly>`
/// (`AppPool`, `setjoin_app`, `NOBYPASSRLS`).
///
/// Enforces:
/// - Strict candidate mailbox binding (`key.mailbox_id == tx.mailbox().get()`) before querying PG.
/// - R1 explicit `m.mailbox_id = $1` + R4 native RLS (`app.current_mailbox_id`).
/// - Composite partitioned primary key `(m.id, m.received_at)` (`V283`).
/// - For [`DocumentKey::MailAttachment`], verifies `EXISTS` in `public.message_attachments`
///   bound to `(ma.id = sub_id, ma.message_id = m.id, ma.received_at = m.received_at)`.
/// - `m.is_deleted = false` (excludes soft-deleted and held-deleted `compliance_only` rows).
/// - Optional `folder_id`, `tag_id`, and `exclude_held` filters.
/// - Preserves candidate ordering via `WITH ORDINALITY`.
pub async fn reauthorize_mail_candidates(
    tx: &mut MailboxTx<ReadOnly>,
    candidates: &[DocumentKey],
    filter: &MailReauthFilter,
) -> Result<Vec<AuthorizedMailHit>, SearchError> {
    let mailbox_id = tx.mailbox().get();
    let mut ids: Vec<i64> = Vec::with_capacity(candidates.len());
    let mut received_ats: Vec<DateTime<Utc>> = Vec::with_capacity(candidates.len());
    let mut sub_ids: Vec<i64> = Vec::with_capacity(candidates.len());
    for key in candidates {
        match key {
            DocumentKey::Mail {
                mailbox_id: key_mb,
                id,
                received_at,
            } if *key_mb == mailbox_id => {
                ids.push(*id);
                received_ats.push(*received_at);
                sub_ids.push(0);
            }
            DocumentKey::MailAttachment {
                mailbox_id: key_mb,
                id,
                received_at,
                sub_id,
            } if *key_mb == mailbox_id && *sub_id > 0 => {
                ids.push(*id);
                received_ats.push(*received_at);
                sub_ids.push(*sub_id);
            }
            _ => {}
        }
    }
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let folder_id = filter.folder_id;
    let tag_id = filter.tag_id;
    let exclude_held = filter.exclude_held;

    let sql = "SELECT m.mailbox_id, m.id, m.received_at, \
                      coalesce(m.subject, ''), m.from_addr, \
                      coalesce(m.crypto_type = 'smime-encrypted', false) \
                 FROM unnest($2::bigint[], $3::timestamptz[], $4::bigint[]) \
                      WITH ORDINALITY AS cand(id, received_at, sub_id, ord) \
                 JOIN public.messages m \
                   ON m.id = cand.id AND m.received_at = cand.received_at \
                WHERE m.mailbox_id = $1 \
                  AND m.is_deleted = false \
                  AND (cand.sub_id = 0 OR EXISTS ( \
                        SELECT 1 FROM public.message_attachments ma \
                         WHERE ma.id = cand.sub_id \
                           AND ma.message_id = m.id \
                           AND ma.received_at = m.received_at)) \
                  AND ($5::boolean = false OR m.held = false) \
                  AND ($6::bigint IS NULL OR m.folder_id = $6) \
                  AND ($7::bigint IS NULL OR EXISTS ( \
                        SELECT 1 FROM public.message_tags mt \
                         WHERE mt.message_id = m.id \
                           AND mt.received_at = m.received_at \
                           AND mt.tag_id = $7)) \
                ORDER BY cand.ord";

    let params: [Param<'_>; 7] = [
        (&mailbox_id, Type::INT8),
        (&ids, Type::INT8_ARRAY),
        (&received_ats, Type::TIMESTAMPTZ_ARRAY),
        (&sub_ids, Type::INT8_ARRAY),
        (&exclude_held, Type::BOOL),
        (&folder_id, Type::INT8),
        (&tag_id, Type::INT8),
    ];

    let rows = tx
        .query(sql, &params)
        .await
        .map_err(|e| SearchError::Database(format!("reauthorize_mail_candidates: {e:?}")))?;

    let mut hits = Vec::with_capacity(rows.len());
    for row in &rows {
        hits.push(AuthorizedMailHit {
            mailbox_id: row
                .try_get(0)
                .map_err(|e| SearchError::Database(format!("decode mail mailbox_id: {e}")))?,
            id: row
                .try_get(1)
                .map_err(|e| SearchError::Database(format!("decode mail id: {e}")))?,
            received_at: row
                .try_get(2)
                .map_err(|e| SearchError::Database(format!("decode mail received_at: {e}")))?,
            subject: row
                .try_get(3)
                .map_err(|e| SearchError::Database(format!("decode mail subject: {e}")))?,
            from_addr: row
                .try_get(4)
                .map_err(|e| SearchError::Database(format!("decode mail from_addr: {e}")))?,
            crypto_sealed: row
                .try_get(5)
                .map_err(|e| SearchError::Database(format!("decode mail crypto_sealed: {e}")))?,
        });
    }
    Ok(hits)
}

/// Re-authorize and hydrate Tier-2 chat candidates inside a single `UserTx<ReadOnly>`
/// (`AppPool`, `setjoin_app`, `NOBYPASSRLS`).
///
/// Enforces live `chat_channel_members` membership, `m.deleted_at IS NULL`,
/// `GUEST_HISTORY_FLOOR`, and parent message history floor.
pub async fn reauthorize_chat_candidates(
    tx: &mut UserTx<ReadOnly>,
    candidates: &[DocumentKey],
    channel_filter: Option<i64>,
) -> Result<Vec<AuthorizedChatHit>, SearchError> {
    let mut ids: Vec<i64> = Vec::with_capacity(candidates.len());
    let mut channel_ids: Vec<i64> = Vec::with_capacity(candidates.len());
    for key in candidates {
        if let DocumentKey::Chat { channel_id, id } = key {
            ids.push(*id);
            channel_ids.push(*channel_id);
        }
    }
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let user_id = tx.actor().get();
    let sql = "SELECT m.channel_id, m.id, m.author_id, m.body \
                 FROM unnest($2::bigint[], $3::bigint[]) WITH ORDINALITY AS cand(id, channel_id, ord) \
                 JOIN public.chat_messages m \
                   ON m.id = cand.id AND m.channel_id = cand.channel_id \
                 JOIN public.chat_channel_members cm \
                   ON cm.channel_id = m.channel_id AND cm.user_id = $1 \
                WHERE m.deleted_at IS NULL \
                  AND m.seq > COALESCE(cm.history_floor_seq, 0) \
                  AND (cm.history_floor_seq IS NULL OR m.created_at >= cm.joined_at) \
                  AND (m.parent_message_id IS NULL OR EXISTS ( \
                        SELECT 1 FROM public.chat_messages parent \
                         WHERE parent.id = m.parent_message_id \
                           AND parent.seq > COALESCE(cm.history_floor_seq, 0) \
                           AND (cm.history_floor_seq IS NULL OR parent.created_at >= cm.joined_at))) \
                  AND ($4::bigint IS NULL OR m.channel_id = $4) \
                ORDER BY cand.ord";

    let params: [Param<'_>; 4] = [
        (&user_id, Type::INT8),
        (&ids, Type::INT8_ARRAY),
        (&channel_ids, Type::INT8_ARRAY),
        (&channel_filter, Type::INT8),
    ];

    let rows = tx
        .query(sql, &params)
        .await
        .map_err(|e| SearchError::Database(format!("reauthorize_chat_candidates: {e:?}")))?;

    let mut hits = Vec::with_capacity(rows.len());
    for row in &rows {
        hits.push(AuthorizedChatHit {
            channel_id: row
                .try_get(0)
                .map_err(|e| SearchError::Database(format!("decode chat channel_id: {e}")))?,
            id: row
                .try_get(1)
                .map_err(|e| SearchError::Database(format!("decode chat id: {e}")))?,
            author_id: row
                .try_get(2)
                .map_err(|e| SearchError::Database(format!("decode chat author_id: {e}")))?,
            body: row
                .try_get(3)
                .map_err(|e| SearchError::Database(format!("decode chat body: {e}")))?,
        });
    }
    Ok(hits)
}

/// Re-authorize and hydrate Tier-2 Drive node candidates inside a single `UserTx<ReadOnly>`
/// (`AppPool`, `setjoin_app`, `NOBYPASSRLS`).
///
/// Enforces `n.deleted_at IS NULL AND n.purged_at IS NULL` + batched
/// `drive_runtime_capability_sources_set(user_id, space_id, node_ids, 'read_metadata')`.
pub async fn reauthorize_drive_candidates(
    tx: &mut UserTx<ReadOnly>,
    candidates: &[DocumentKey],
    space_filter: Option<i64>,
) -> Result<Vec<AuthorizedDriveHit>, SearchError> {
    let mut ids: Vec<i64> = Vec::with_capacity(candidates.len());
    let mut space_ids: Vec<i64> = Vec::with_capacity(candidates.len());
    for key in candidates {
        match key {
            DocumentKey::Drive { space_id, id } | DocumentKey::DriveFile { space_id, id, .. } => {
                ids.push(*id);
                space_ids.push(*space_id);
            }
            _ => {}
        }
    }
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let user_id = tx.actor().get();
    let sql = "SELECT n.space_id, n.id, n.kind, n.name \
                 FROM unnest($2::bigint[], $3::bigint[]) WITH ORDINALITY AS cand(id, space_id, ord) \
                 JOIN ( \
                   SELECT DISTINCT l.space_id, x.node_id \
                     FROM ( \
                       SELECT n2.space_id, array_agg(n2.id ORDER BY n2.id) AS node_ids \
                         FROM unnest($2::bigint[], $3::bigint[]) AS c2(id, space_id) \
                         JOIN public.drive_nodes n2 \
                           ON n2.id = c2.id AND n2.space_id = c2.space_id \
                        WHERE n2.deleted_at IS NULL AND n2.purged_at IS NULL \
                          AND ($4::bigint IS NULL OR n2.space_id = $4) \
                        GROUP BY n2.space_id \
                     ) l \
                     CROSS JOIN LATERAL public.drive_runtime_capability_sources_set( \
                       $1, l.space_id, l.node_ids, 'read_metadata') x \
                 ) r ON r.space_id = cand.space_id AND r.node_id = cand.id \
                 JOIN public.drive_nodes n ON n.space_id = r.space_id AND n.id = r.node_id \
                ORDER BY cand.ord";

    let params: [Param<'_>; 4] = [
        (&user_id, Type::INT8),
        (&ids, Type::INT8_ARRAY),
        (&space_ids, Type::INT8_ARRAY),
        (&space_filter, Type::INT8),
    ];

    let rows = tx
        .query(sql, &params)
        .await
        .map_err(|e| SearchError::Database(format!("reauthorize_drive_candidates: {e:?}")))?;

    let mut hits = Vec::with_capacity(rows.len());
    for row in &rows {
        hits.push(AuthorizedDriveHit {
            space_id: row
                .try_get(0)
                .map_err(|e| SearchError::Database(format!("decode drive space_id: {e}")))?,
            id: row
                .try_get(1)
                .map_err(|e| SearchError::Database(format!("decode drive id: {e}")))?,
            kind: row
                .try_get(2)
                .map_err(|e| SearchError::Database(format!("decode drive kind: {e}")))?,
            name: row
                .try_get(3)
                .map_err(|e| SearchError::Database(format!("decode drive name: {e}")))?,
        });
    }
    Ok(hits)
}

/// Result of bounded overfetch pagination across Tier-2 candidates + mandatory PG re-auth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedPage<T> {
    pub items: Vec<T>,
    pub tier: SearchTier,
    pub degraded: bool,
    pub rounds: usize,
    pub inspected_candidates: usize,
}

/// Execute bounded overfetch pagination (`overfetch = clamp(limit * 3, 64, 500)`,
/// up to `MAX_OVERFETCH_ROUNDS = 4` and strict `MAX_OVERFETCH_CANDIDATES = 1500`):
/// - Clamps every round's request `limit` to `remaining = MAX_OVERFETCH_CANDIDATES - inspected`
///   so total hydrated candidates NEVER exceed `1500`.
/// - Stops once `page_limit` authorized items are collected or Tier-2 exhausts cleanly.
/// - If Tier-2 is unavailable/degraded, returns `Tier1Pg`, or exhausts the overfetch
///   budget without producing a conclusive page, transparently runs `tier1_fallback`.
pub async fn execute_overfetch_page<T, ReauthFn, ReauthFut, FallbackFn, FallbackFut>(
    engine: &dyn SearchEngine,
    base_query: &CandidateQuery,
    page_limit: u16,
    mut reauthorize: ReauthFn,
    tier1_fallback: FallbackFn,
) -> Result<AuthorizedPage<T>, SearchError>
where
    ReauthFn: FnMut(Vec<DocumentKey>) -> ReauthFut,
    ReauthFut: Future<Output = Result<Vec<T>, SearchError>>,
    FallbackFn: FnOnce() -> FallbackFut,
    FallbackFut: Future<Output = Result<Vec<T>, SearchError>>,
{
    let target = usize::from(page_limit.max(1));
    if base_query.visibility == SearchVisibility::Live
        && (base_query.metadata_only || base_query.calculate_total)
    {
        let items = tier1_fallback().await?;
        return Ok(AuthorizedPage {
            items,
            tier: SearchTier::Tier1Pg,
            degraded: false,
            rounds: 0,
            inspected_candidates: 0,
        });
    }

    let batch_limit = overfetch_limit(page_limit);
    let mut query = base_query.clone();

    let mut collected: Vec<T> = Vec::with_capacity(target);
    let mut inspected = 0usize;
    let mut rounds = 0usize;

    while rounds < MAX_OVERFETCH_ROUNDS && inspected < MAX_OVERFETCH_CANDIDATES {
        let remaining = MAX_OVERFETCH_CANDIDATES.saturating_sub(inspected);
        if remaining == 0 {
            break;
        }
        let round_cap = u16::try_from(remaining).unwrap_or(u16::MAX);
        query.limit = batch_limit.min(round_cap).max(1);
        rounds += 1;

        let batch = match engine.candidates(&query).await {
            Ok(b) => b,
            Err(SearchError::InvalidCursor) => return Err(SearchError::InvalidCursor),
            Err(_) => {
                let items = tier1_fallback().await?;
                return Ok(AuthorizedPage {
                    items,
                    tier: SearchTier::Tier1Pg,
                    degraded: true,
                    rounds,
                    inspected_candidates: inspected,
                });
            }
        };

        if batch.tier == SearchTier::Tier1Pg || batch.degraded {
            let items = tier1_fallback().await?;
            return Ok(AuthorizedPage {
                items,
                tier: SearchTier::Tier1Pg,
                degraded: batch.degraded,
                rounds,
                inspected_candidates: inspected,
            });
        }

        let allowed = MAX_OVERFETCH_CANDIDATES.saturating_sub(inspected);
        let mut keys = batch.keys;
        if keys.len() > allowed {
            keys.truncate(allowed);
        }
        inspected = inspected.saturating_add(keys.len());
        let next_cursor = batch.continuation;

        if !keys.is_empty() {
            let authorized = reauthorize(keys).await?;
            for item in authorized {
                collected.push(item);
                if collected.len() >= target {
                    return Ok(AuthorizedPage {
                        items: collected,
                        tier: SearchTier::Tier2Tantivy,
                        degraded: false,
                        rounds,
                        inspected_candidates: inspected,
                    });
                }
            }
        }

        match next_cursor {
            Some(cursor) => query.continuation = Some(cursor),
            None => {
                // Conclusive exhaustion of Tier-2 index for this query.
                return Ok(AuthorizedPage {
                    items: collected,
                    tier: SearchTier::Tier2Tantivy,
                    degraded: false,
                    rounds,
                    inspected_candidates: inspected,
                });
            }
        }
    }

    // Overfetch budget exhausted without filling a conclusive page -> rerun full page in Tier-1 PG.
    let items = tier1_fallback().await?;
    Ok(AuthorizedPage {
        items,
        tier: SearchTier::Tier1Pg,
        degraded: true,
        rounds,
        inspected_candidates: inspected,
    })
}
