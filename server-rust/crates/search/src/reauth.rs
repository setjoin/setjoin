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
use crate::pipeline::{chat_revision_doc_id, scheduled_action_doc_id};
use crate::tier1_pg::escape_like_pattern;
use chrono::{DateTime, Utc};
use setjoin_pg::{AdminReadTx, MailboxTx, Param, ReadOnly, Standard, Type, UserTx};
use std::collections::{HashMap, HashSet};
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
    /// When `true` and `tag_id` is `Some`, applies canonical `jmap_email_query`
    /// snooze exclusion whenever the queried tag belongs to `exclusive_group = 'location'`.
    pub enforce_jmap_snooze_exclusion: bool,
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
    pub pinned_at: Option<DateTime<Utc>>,
}

/// Authorized chat hit hydrated from PostgreSQL under `UserTx<ReadOnly>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedChatHit {
    pub channel_id: i64,
    pub id: i64,
    pub author_id: i64,
    pub body: String,
}

/// Authorized drive hit hydrated from PostgreSQL under `UserTx<ReadOnly>`
/// matching canonical `drive_search_nodes` 8-field projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedDriveHit {
    pub space_id: i64,
    pub id: i64,
    pub parent_id: Option<i64>,
    pub kind: String,
    pub name: String,
    pub size_bytes: Option<i64>,
    pub content_type: Option<String>,
    pub created_at: DateTime<Utc>,
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
    let enforce_snooze = filter.enforce_jmap_snooze_exclusion;

    let sql = "SELECT m.mailbox_id, m.id, m.received_at, \
                      coalesce(m.subject, ''), m.from_addr, \
                      coalesce(m.crypto_type = 'smime-encrypted', false), \
                      m.pinned_at \
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
                  AND ($8::boolean = false OR $7::bigint IS NULL \
                       OR (SELECT t.exclusive_group FROM public.tags t WHERE t.id = $7) IS DISTINCT FROM 'location' \
                       OR NOT EXISTS ( \
                            SELECT 1 FROM public.message_tags ms \
                            JOIN public.tags ts ON ts.id = ms.tag_id \
                             WHERE ms.message_id = m.id \
                               AND ms.received_at = m.received_at \
                               AND ts.exclusive_group = 'snooze')) \
                ORDER BY cand.ord";

    let params: [Param<'_>; 8] = [
        (&mailbox_id, Type::INT8),
        (&ids, Type::INT8_ARRAY),
        (&received_ats, Type::TIMESTAMPTZ_ARRAY),
        (&sub_ids, Type::INT8_ARRAY),
        (&exclude_held, Type::BOOL),
        (&folder_id, Type::INT8),
        (&tag_id, Type::INT8),
        (&enforce_snooze, Type::BOOL),
    ];

    let rows = tx
        .query(sql, &params)
        .await
        .map_err(|e| SearchError::Database(format!("reauthorize_mail_candidates: {e:?}")))?;

    // Deduplicate overlapping Mail + MailAttachment candidates preserving first-seen order.
    let mut seen: HashSet<(i64, DateTime<Utc>)> = HashSet::with_capacity(rows.len());
    let mut hits = Vec::with_capacity(rows.len());
    for row in &rows {
        let id: i64 = row
            .try_get(1)
            .map_err(|e| SearchError::Database(format!("decode mail id: {e}")))?;
        let received_at: DateTime<Utc> = row
            .try_get(2)
            .map_err(|e| SearchError::Database(format!("decode mail received_at: {e}")))?;
        if !seen.insert((id, received_at)) {
            continue;
        }
        hits.push(AuthorizedMailHit {
            mailbox_id: row
                .try_get(0)
                .map_err(|e| SearchError::Database(format!("decode mail mailbox_id: {e}")))?,
            id,
            received_at,
            subject: row
                .try_get(3)
                .map_err(|e| SearchError::Database(format!("decode mail subject: {e}")))?,
            from_addr: row
                .try_get(4)
                .map_err(|e| SearchError::Database(format!("decode mail from_addr: {e}")))?,
            crypto_sealed: row
                .try_get(5)
                .map_err(|e| SearchError::Database(format!("decode mail crypto_sealed: {e}")))?,
            pinned_at: row
                .try_get(6)
                .map_err(|e| SearchError::Database(format!("decode mail pinned_at: {e}")))?,
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
    let mut seen_keys: HashSet<(i64, i64)> = HashSet::with_capacity(candidates.len());
    for key in candidates {
        match key {
            DocumentKey::Drive { space_id, id } | DocumentKey::DriveFile { space_id, id, .. }
                if seen_keys.insert((*space_id, *id)) =>
            {
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
    let sql = "SELECT n.space_id, n.id, n.parent_id, n.kind, n.name, \
                      f.size_bytes, f.content_type, n.created_at \
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
                 LEFT JOIN public.drive_files f ON f.node_id = n.id \
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

    let mut seen_out: HashSet<(i64, i64)> = HashSet::with_capacity(rows.len());
    let mut hits = Vec::with_capacity(rows.len());
    for row in &rows {
        let space_id: i64 = row
            .try_get(0)
            .map_err(|e| SearchError::Database(format!("decode drive space_id: {e}")))?;
        let id: i64 = row
            .try_get(1)
            .map_err(|e| SearchError::Database(format!("decode drive id: {e}")))?;
        if !seen_out.insert((space_id, id)) {
            continue;
        }
        hits.push(AuthorizedDriveHit {
            space_id,
            id,
            parent_id: row
                .try_get(2)
                .map_err(|e| SearchError::Database(format!("decode drive parent_id: {e}")))?,
            kind: row
                .try_get(3)
                .map_err(|e| SearchError::Database(format!("decode drive kind: {e}")))?,
            name: row
                .try_get(4)
                .map_err(|e| SearchError::Database(format!("decode drive name: {e}")))?,
            size_bytes: row
                .try_get(5)
                .map_err(|e| SearchError::Database(format!("decode drive size_bytes: {e}")))?,
            content_type: row
                .try_get(6)
                .map_err(|e| SearchError::Database(format!("decode drive content_type: {e}")))?,
            created_at: row
                .try_get(7)
                .map_err(|e| SearchError::Database(format!("decode drive created_at: {e}")))?,
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

/// Optional compliance scope filters applied during mandatory PG admin mail re-authorization.
#[derive(Clone, Debug, Default)]
pub struct AdminMailReauthFilter {
    pub mailbox_ids: Option<Vec<i64>>,
    pub from_addr: Option<String>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    /// Include soft-deleted & legally-held messages (`ComplianceOnly` visibility).
    pub include_deleted: bool,
}

/// Optional compliance scope filters applied during mandatory PG admin chat re-authorization.
#[derive(Clone, Debug, Default)]
pub struct AdminChatReauthFilter {
    pub channel_ids: Option<Vec<i64>>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    /// Include soft-deleted messages, historical `chat_message_revisions`, and scheduled actions.
    pub include_deleted: bool,
}

/// Optional compliance scope filters applied during mandatory PG admin drive re-authorization.
#[derive(Clone, Debug, Default)]
pub struct AdminDriveReauthFilter {
    pub space_ids: Option<Vec<i64>>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    /// Include soft-trashed (`deleted_at IS NOT NULL`) nodes (never hard-purged `purged_at IS NOT NULL`).
    pub include_trashed: bool,
}

/// Authorized compliance/eDiscovery mail hit hydrated from PG under `AdminReadTx<Standard>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedAdminMailHit {
    pub mailbox_id: i64,
    pub id: i64,
    pub received_at: DateTime<Utc>,
    pub subject: String,
    pub from_addr: String,
    pub is_deleted: bool,
    pub held: bool,
    pub is_scheduled: bool,
    pub action_id: Option<String>,
}

/// Authorized compliance/eDiscovery chat hit hydrated from PG under `AdminReadTx<Standard>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedAdminChatHit {
    pub channel_id: i64,
    pub id: i64,
    pub author_id: Option<i64>,
    pub body: String,
    pub is_deleted: bool,
    pub is_revision: bool,
    pub is_scheduled: bool,
    pub action_id: Option<String>,
}

/// Authorized compliance/eDiscovery drive hit hydrated from PG under `AdminReadTx<Standard>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedAdminDriveHit {
    pub space_id: i64,
    pub id: i64,
    pub version_id: Option<i64>,
    pub kind: String,
    pub name: String,
    pub is_trashed: bool,
}

/// Re-authorize and hydrate compliance/admin mail candidates (`Live` + `ComplianceOnly`,
/// including held/soft-deleted messages, `MailAttachment` bindings, and pending/enqueued/
/// processing/failed `scheduled_actions`) inside `AdminReadTx<Standard>` (`BEGIN READ ONLY`).
pub async fn reauthorize_admin_mail_candidates(
    tx: &mut AdminReadTx<Standard>,
    candidates: &[DocumentKey],
    filter: &AdminMailReauthFilter,
) -> Result<Vec<AuthorizedAdminMailHit>, SearchError> {
    let mut msg_ids: Vec<i64> = Vec::new();
    let mut msg_received_ats: Vec<DateTime<Utc>> = Vec::new();
    let mut msg_sub_ids: Vec<i64> = Vec::new();
    let mut msg_ords: Vec<i64> = Vec::new();
    let mut neg_candidates: HashMap<i64, usize> = HashMap::new();

    for (ord, key) in candidates.iter().enumerate() {
        match key {
            DocumentKey::Mail {
                id, received_at, ..
            } if *id > 0 => {
                msg_ids.push(*id);
                msg_received_ats.push(*received_at);
                msg_sub_ids.push(0);
                msg_ords.push(i64::try_from(ord).unwrap_or(i64::MAX));
            }
            DocumentKey::Mail { id, .. } if *id < 0 => {
                neg_candidates.entry(*id).or_insert(ord);
            }
            DocumentKey::MailAttachment {
                id,
                received_at,
                sub_id,
                ..
            } if *id > 0 && *sub_id > 0 => {
                msg_ids.push(*id);
                msg_received_ats.push(*received_at);
                msg_sub_ids.push(*sub_id);
                msg_ords.push(i64::try_from(ord).unwrap_or(i64::MAX));
            }
            _ => {}
        }
    }

    let mut ordered_hits: Vec<(usize, AuthorizedAdminMailHit)> = Vec::new();

    if !msg_ids.is_empty() {
        let mailbox_ids = filter
            .mailbox_ids
            .as_ref()
            .filter(|ids| !ids.is_empty())
            .cloned();
        let from_pat = filter
            .from_addr
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| escape_like_pattern(s).to_lowercase());
        let date_from = filter.date_from;
        let date_to = filter.date_to;
        let include_deleted = filter.include_deleted;

        let sql = "SELECT cand.ord, m.mailbox_id, m.id, m.received_at, \
                          coalesce(m.subject, ''), m.from_addr, m.is_deleted, m.held \
                     FROM unnest($1::bigint[], $2::timestamptz[], $3::bigint[], $4::bigint[]) \
                          AS cand(id, received_at, sub_id, ord) \
                     JOIN public.messages m \
                       ON m.id = cand.id AND m.received_at = cand.received_at \
                    WHERE ($5::boolean = true OR m.is_deleted = false) \
                      AND (cand.sub_id = 0 OR EXISTS ( \
                            SELECT 1 FROM public.message_attachments ma \
                             WHERE ma.id = cand.sub_id \
                               AND ma.message_id = m.id \
                               AND ma.received_at = m.received_at)) \
                      AND ($6::bigint[] IS NULL OR m.mailbox_id = ANY($6::bigint[])) \
                      AND ($7::text IS NULL OR lower(coalesce(m.from_addr, '')) LIKE $7 ESCAPE '\\') \
                      AND ($8::timestamptz IS NULL OR m.received_at >= $8) \
                      AND ($9::timestamptz IS NULL OR m.received_at <= $9) \
                    ORDER BY cand.ord";

        let params: [Param<'_>; 9] = [
            (&msg_ids, Type::INT8_ARRAY),
            (&msg_received_ats, Type::TIMESTAMPTZ_ARRAY),
            (&msg_sub_ids, Type::INT8_ARRAY),
            (&msg_ords, Type::INT8_ARRAY),
            (&include_deleted, Type::BOOL),
            (&mailbox_ids, Type::INT8_ARRAY),
            (&from_pat, Type::TEXT),
            (&date_from, Type::TIMESTAMPTZ),
            (&date_to, Type::TIMESTAMPTZ),
        ];
        let rows = tx.query(sql, &params).await.map_err(|e| {
            SearchError::Database(format!("reauthorize_admin_mail_candidates: {e:?}"))
        })?;

        let mut seen_msgs: HashSet<(i64, i64)> = HashSet::new();
        for row in &rows {
            let ord_i64: i64 = row
                .try_get(0)
                .map_err(|e| SearchError::Database(format!("decode admin mail ord: {e}")))?;
            let mailbox_id: i64 = row
                .try_get(1)
                .map_err(|e| SearchError::Database(format!("decode admin mail mailbox_id: {e}")))?;
            let id: i64 = row
                .try_get(2)
                .map_err(|e| SearchError::Database(format!("decode admin mail id: {e}")))?;
            if !seen_msgs.insert((mailbox_id, id)) {
                continue;
            }
            let received_at: DateTime<Utc> = row.try_get(3).map_err(|e| {
                SearchError::Database(format!("decode admin mail received_at: {e}"))
            })?;
            let subject: String = row
                .try_get(4)
                .map_err(|e| SearchError::Database(format!("decode admin mail subject: {e}")))?;
            let from_addr: String = row
                .try_get(5)
                .map_err(|e| SearchError::Database(format!("decode admin mail from_addr: {e}")))?;
            let is_deleted: bool = row
                .try_get(6)
                .map_err(|e| SearchError::Database(format!("decode admin mail is_deleted: {e}")))?;
            let held: bool = row
                .try_get(7)
                .map_err(|e| SearchError::Database(format!("decode admin mail held: {e}")))?;
            ordered_hits.push((
                usize::try_from(ord_i64).unwrap_or(usize::MAX),
                AuthorizedAdminMailHit {
                    mailbox_id,
                    id,
                    received_at,
                    subject,
                    from_addr,
                    is_deleted,
                    held,
                    is_scheduled: false,
                    action_id: None,
                },
            ));
        }
    }

    if !neg_candidates.is_empty() {
        let mailbox_ids = filter
            .mailbox_ids
            .as_ref()
            .filter(|ids| !ids.is_empty())
            .cloned();
        let date_from = filter.date_from;
        let date_to = filter.date_to;
        let sql = "SELECT id::text, action_kind, fire_at, payload::text, mailbox_id \
                     FROM public.scheduled_actions \
                    WHERE status IN ('pending', 'enqueued', 'processing', 'failed') \
                      AND ($1::bigint[] IS NULL OR mailbox_id = ANY($1::bigint[])) \
                      AND ($2::timestamptz IS NULL OR fire_at >= $2) \
                      AND ($3::timestamptz IS NULL OR fire_at <= $3)";
        let params: [Param<'_>; 3] = [
            (&mailbox_ids, Type::INT8_ARRAY),
            (&date_from, Type::TIMESTAMPTZ),
            (&date_to, Type::TIMESTAMPTZ),
        ];
        let rows = tx.query(sql, &params).await.map_err(|e| {
            SearchError::Database(format!(
                "reauthorize_admin_mail_candidates scheduled: {e:?}"
            ))
        })?;
        let from_needle = filter
            .from_addr
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase);
        for row in &rows {
            let action_id: String = row
                .try_get(0)
                .map_err(|e| SearchError::Database(format!("decode scheduled id: {e}")))?;
            let doc_id = scheduled_action_doc_id(&action_id);
            let Some(&ord) = neg_candidates.get(&doc_id) else {
                continue;
            };
            let action_kind: String = row
                .try_get(1)
                .map_err(|e| SearchError::Database(format!("decode scheduled kind: {e}")))?;
            let fire_at: DateTime<Utc> = row
                .try_get(2)
                .map_err(|e| SearchError::Database(format!("decode scheduled fire_at: {e}")))?;
            let payload_text: String = row
                .try_get(3)
                .map_err(|e| SearchError::Database(format!("decode scheduled payload: {e}")))?;
            let mb: Option<i64> = row
                .try_get(4)
                .map_err(|e| SearchError::Database(format!("decode scheduled mailbox_id: {e}")))?;
            let payload_json: serde_json::Value =
                serde_json::from_str(&payload_text).unwrap_or(serde_json::Value::Null);
            let subject = payload_json
                .get("subject")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(&action_kind)
                .to_owned();
            let from_addr = payload_json
                .get("from")
                .or_else(|| payload_json.get("from_addr"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_owned();
            if let Some(ref needle) = from_needle {
                if !from_addr.to_lowercase().contains(needle) {
                    continue;
                }
            }
            ordered_hits.push((
                ord,
                AuthorizedAdminMailHit {
                    mailbox_id: mb.unwrap_or(0),
                    id: doc_id,
                    received_at: fire_at,
                    subject,
                    from_addr,
                    is_deleted: false,
                    held: false,
                    is_scheduled: true,
                    action_id: Some(action_id),
                },
            ));
        }
    }

    ordered_hits.sort_by_key(|(ord, _)| *ord);
    Ok(ordered_hits.into_iter().map(|(_, hit)| hit).collect())
}

/// Re-authorize and hydrate compliance/admin chat candidates (`Live` + `ComplianceOnly`,
/// including soft-deleted messages, historical `chat_message_revisions`, and pending/
/// enqueued/processing/failed chat `scheduled_actions`) inside `AdminReadTx<Standard>`.
pub async fn reauthorize_admin_chat_candidates(
    tx: &mut AdminReadTx<Standard>,
    candidates: &[DocumentKey],
    filter: &AdminChatReauthFilter,
) -> Result<Vec<AuthorizedAdminChatHit>, SearchError> {
    let mut pos_ids: Vec<i64> = Vec::new();
    let mut pos_channels: Vec<i64> = Vec::new();
    let mut pos_ords: Vec<i64> = Vec::new();
    let mut neg_candidates: HashMap<i64, usize> = HashMap::new();

    for (ord, key) in candidates.iter().enumerate() {
        if let DocumentKey::Chat { channel_id, id } = key {
            if *id > 0 {
                pos_ids.push(*id);
                pos_channels.push(*channel_id);
                pos_ords.push(i64::try_from(ord).unwrap_or(i64::MAX));
            } else if *id < 0 {
                neg_candidates.entry(*id).or_insert(ord);
            }
        }
    }

    let mut ordered_hits: Vec<(usize, AuthorizedAdminChatHit)> = Vec::new();
    let channel_ids = filter
        .channel_ids
        .as_ref()
        .filter(|ids| !ids.is_empty())
        .cloned();
    let date_from = filter.date_from;
    let date_to = filter.date_to;
    let include_deleted = filter.include_deleted;

    if !pos_ids.is_empty() {
        let sql = "SELECT cand.ord, m.channel_id, m.id, m.author_id, m.body, \
                          (m.deleted_at IS NOT NULL) \
                     FROM unnest($1::bigint[], $2::bigint[], $3::bigint[]) \
                          AS cand(id, channel_id, ord) \
                     JOIN public.chat_messages m \
                       ON m.id = cand.id AND m.channel_id = cand.channel_id \
                    WHERE ($4::boolean = true OR m.deleted_at IS NULL) \
                      AND ($5::bigint[] IS NULL OR m.channel_id = ANY($5::bigint[])) \
                      AND ($6::timestamptz IS NULL OR m.created_at >= $6) \
                      AND ($7::timestamptz IS NULL OR m.created_at <= $7) \
                    ORDER BY cand.ord";
        let params: [Param<'_>; 7] = [
            (&pos_ids, Type::INT8_ARRAY),
            (&pos_channels, Type::INT8_ARRAY),
            (&pos_ords, Type::INT8_ARRAY),
            (&include_deleted, Type::BOOL),
            (&channel_ids, Type::INT8_ARRAY),
            (&date_from, Type::TIMESTAMPTZ),
            (&date_to, Type::TIMESTAMPTZ),
        ];
        let rows = tx.query(sql, &params).await.map_err(|e| {
            SearchError::Database(format!("reauthorize_admin_chat_candidates: {e:?}"))
        })?;
        for row in &rows {
            let ord_i64: i64 = row
                .try_get(0)
                .map_err(|e| SearchError::Database(format!("decode admin chat ord: {e}")))?;
            ordered_hits.push((
                usize::try_from(ord_i64).unwrap_or(usize::MAX),
                AuthorizedAdminChatHit {
                    channel_id: row.try_get(1).map_err(|e| {
                        SearchError::Database(format!("decode admin chat channel_id: {e}"))
                    })?,
                    id: row
                        .try_get(2)
                        .map_err(|e| SearchError::Database(format!("decode admin chat id: {e}")))?,
                    author_id: Some(row.try_get(3).map_err(|e| {
                        SearchError::Database(format!("decode admin chat author_id: {e}"))
                    })?),
                    body: row.try_get(4).map_err(|e| {
                        SearchError::Database(format!("decode admin chat body: {e}"))
                    })?,
                    is_deleted: row.try_get(5).map_err(|e| {
                        SearchError::Database(format!("decode admin chat is_deleted: {e}"))
                    })?,
                    is_revision: false,
                    is_scheduled: false,
                    action_id: None,
                },
            ));
        }
    }

    if !neg_candidates.is_empty() && include_deleted {
        // 1. Historical edited chat revisions (`chat_message_revisions`)
        let rev_sql = "SELECT r.channel_id, r.message_id, r.prior_body, m.author_id, \
                              (m.deleted_at IS NOT NULL) \
                         FROM public.chat_message_revisions r \
                         JOIN public.chat_messages m ON m.id = r.message_id \
                        WHERE ($1::bigint[] IS NULL OR r.channel_id = ANY($1::bigint[])) \
                          AND ($2::timestamptz IS NULL OR r.created_at >= $2) \
                          AND ($3::timestamptz IS NULL OR r.created_at <= $3) \
                        ORDER BY r.id ASC";
        let rev_params: [Param<'_>; 3] = [
            (&channel_ids, Type::INT8_ARRAY),
            (&date_from, Type::TIMESTAMPTZ),
            (&date_to, Type::TIMESTAMPTZ),
        ];
        let rev_rows = tx.query(rev_sql, &rev_params).await.map_err(|e| {
            SearchError::Database(format!(
                "reauthorize_admin_chat_candidates revisions: {e:?}"
            ))
        })?;
        struct GroupedRevision {
            ord: usize,
            channel_id: i64,
            author_id: Option<i64>,
            is_deleted: bool,
            parts: Vec<String>,
        }
        let mut grouped_revs: HashMap<i64, GroupedRevision> = HashMap::new();
        for row in &rev_rows {
            let ch_id: i64 = row
                .try_get(0)
                .map_err(|e| SearchError::Database(format!("decode rev channel_id: {e}")))?;
            let msg_id: i64 = row
                .try_get(1)
                .map_err(|e| SearchError::Database(format!("decode rev message_id: {e}")))?;
            let rev_doc_id = chat_revision_doc_id(msg_id);
            let Some(&ord) = neg_candidates.get(&rev_doc_id) else {
                continue;
            };
            let prior_body: String = row
                .try_get(2)
                .map_err(|e| SearchError::Database(format!("decode rev prior_body: {e}")))?;
            let author_id: i64 = row
                .try_get(3)
                .map_err(|e| SearchError::Database(format!("decode rev author_id: {e}")))?;
            let is_deleted: bool = row
                .try_get(4)
                .map_err(|e| SearchError::Database(format!("decode rev is_deleted: {e}")))?;
            grouped_revs
                .entry(rev_doc_id)
                .or_insert_with(|| GroupedRevision {
                    ord,
                    channel_id: ch_id,
                    author_id: Some(author_id),
                    is_deleted,
                    parts: Vec::new(),
                })
                .parts
                .push(prior_body);
        }
        for (rev_doc_id, rev) in grouped_revs {
            ordered_hits.push((
                rev.ord,
                AuthorizedAdminChatHit {
                    channel_id: rev.channel_id,
                    id: rev_doc_id,
                    author_id: rev.author_id,
                    body: rev.parts.join("\n"),
                    is_deleted: rev.is_deleted,
                    is_revision: true,
                    is_scheduled: false,
                    action_id: None,
                },
            ));
        }

        // 2. Pending / enqueued / processing / failed scheduled chat sends
        let sched_sql = "SELECT id::text, action_kind, fire_at, payload::text \
                           FROM public.scheduled_actions \
                          WHERE status IN ('pending', 'enqueued', 'processing', 'failed') \
                            AND ($1::timestamptz IS NULL OR fire_at >= $1) \
                            AND ($2::timestamptz IS NULL OR fire_at <= $2)";
        let sched_params: [Param<'_>; 2] = [
            (&date_from, Type::TIMESTAMPTZ),
            (&date_to, Type::TIMESTAMPTZ),
        ];
        let sched_rows = tx.query(sched_sql, &sched_params).await.map_err(|e| {
            SearchError::Database(format!(
                "reauthorize_admin_chat_candidates scheduled: {e:?}"
            ))
        })?;
        for row in &sched_rows {
            let action_id: String = row
                .try_get(0)
                .map_err(|e| SearchError::Database(format!("decode sched chat id: {e}")))?;
            let doc_id = scheduled_action_doc_id(&action_id);
            let Some(&ord) = neg_candidates.get(&doc_id) else {
                continue;
            };
            let _action_kind: String = row
                .try_get(1)
                .map_err(|e| SearchError::Database(format!("decode sched chat kind: {e}")))?;
            let _fire_at: DateTime<Utc> = row
                .try_get(2)
                .map_err(|e| SearchError::Database(format!("decode sched chat fire_at: {e}")))?;
            let payload_text: String = row
                .try_get(3)
                .map_err(|e| SearchError::Database(format!("decode sched chat payload: {e}")))?;
            let payload_json: serde_json::Value =
                serde_json::from_str(&payload_text).unwrap_or(serde_json::Value::Null);
            let ch_id = payload_json
                .get("channelId")
                .or_else(|| payload_json.get("channel_id"))
                .and_then(|v| {
                    v.as_i64()
                        .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
                })
                .unwrap_or(0);
            if let Some(ref allowed) = channel_ids {
                if !allowed.contains(&ch_id) {
                    continue;
                }
            }
            let body = payload_json
                .get("body")
                .or_else(|| payload_json.get("text"))
                .or_else(|| payload_json.get("message"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or(&payload_text)
                .to_owned();
            ordered_hits.push((
                ord,
                AuthorizedAdminChatHit {
                    channel_id: ch_id,
                    id: doc_id,
                    author_id: None,
                    body,
                    is_deleted: false,
                    is_revision: false,
                    is_scheduled: true,
                    action_id: Some(action_id),
                },
            ));
        }
    }

    ordered_hits.sort_by_key(|(ord, _)| *ord);
    Ok(ordered_hits.into_iter().map(|(_, hit)| hit).collect())
}

/// Re-authorize and hydrate compliance/admin Drive candidates (`Live` + `ComplianceOnly`,
/// including soft-trashed nodes `deleted_at IS NOT NULL` when `include_trashed` is true,
/// while always excluding hard-purged `purged_at IS NOT NULL`) inside `AdminReadTx<Standard>`.
pub async fn reauthorize_admin_drive_candidates(
    tx: &mut AdminReadTx<Standard>,
    candidates: &[DocumentKey],
    filter: &AdminDriveReauthFilter,
) -> Result<Vec<AuthorizedAdminDriveHit>, SearchError> {
    let mut ids: Vec<i64> = Vec::with_capacity(candidates.len());
    let mut space_ids: Vec<i64> = Vec::with_capacity(candidates.len());
    let mut sub_ids: Vec<i64> = Vec::with_capacity(candidates.len());

    for key in candidates {
        match key {
            DocumentKey::Drive { space_id, id } => {
                ids.push(*id);
                space_ids.push(*space_id);
                sub_ids.push(0);
            }
            DocumentKey::DriveFile {
                space_id,
                id,
                sub_id,
            } => {
                ids.push(*id);
                space_ids.push(*space_id);
                sub_ids.push(*sub_id);
            }
            _ => {}
        }
    }
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let space_filter = filter.space_ids.as_ref().filter(|v| !v.is_empty()).cloned();
    let date_from = filter.date_from;
    let date_to = filter.date_to;
    let include_trashed = filter.include_trashed;

    let sql = "SELECT n.space_id, n.id, NULLIF(cand.sub_id, 0), n.kind, n.name, \
                      (n.deleted_at IS NOT NULL) \
                 FROM unnest($1::bigint[], $2::bigint[], $3::bigint[]) \
                      WITH ORDINALITY AS cand(id, space_id, sub_id, ord) \
                 JOIN public.drive_nodes n \
                   ON n.id = cand.id AND n.space_id = cand.space_id \
                WHERE n.purged_at IS NULL \
                  AND ($4::boolean = true OR n.deleted_at IS NULL) \
                  AND (cand.sub_id = 0 OR EXISTS ( \
                        SELECT 1 FROM public.drive_file_versions dfv \
                         WHERE dfv.id = cand.sub_id \
                           AND dfv.file_node_id = n.id \
                           AND dfv.space_id = n.space_id)) \
                  AND ($5::bigint[] IS NULL OR n.space_id = ANY($5::bigint[])) \
                  AND ($6::timestamptz IS NULL OR n.created_at >= $6) \
                  AND ($7::timestamptz IS NULL OR n.created_at <= $7) \
                ORDER BY cand.ord";

    let params: [Param<'_>; 7] = [
        (&ids, Type::INT8_ARRAY),
        (&space_ids, Type::INT8_ARRAY),
        (&sub_ids, Type::INT8_ARRAY),
        (&include_trashed, Type::BOOL),
        (&space_filter, Type::INT8_ARRAY),
        (&date_from, Type::TIMESTAMPTZ),
        (&date_to, Type::TIMESTAMPTZ),
    ];

    let rows = tx
        .query(sql, &params)
        .await
        .map_err(|e| SearchError::Database(format!("reauthorize_admin_drive_candidates: {e:?}")))?;

    let mut hits = Vec::with_capacity(rows.len());
    for row in &rows {
        hits.push(AuthorizedAdminDriveHit {
            space_id: row
                .try_get(0)
                .map_err(|e| SearchError::Database(format!("decode admin drive space_id: {e}")))?,
            id: row
                .try_get(1)
                .map_err(|e| SearchError::Database(format!("decode admin drive id: {e}")))?,
            version_id: row.try_get(2).map_err(|e| {
                SearchError::Database(format!("decode admin drive version_id: {e}"))
            })?,
            kind: row
                .try_get(3)
                .map_err(|e| SearchError::Database(format!("decode admin drive kind: {e}")))?,
            name: row
                .try_get(4)
                .map_err(|e| SearchError::Database(format!("decode admin drive name: {e}")))?,
            is_trashed: row.try_get(5).map_err(|e| {
                SearchError::Database(format!("decode admin drive is_trashed: {e}"))
            })?,
        });
    }
    Ok(hits)
}
