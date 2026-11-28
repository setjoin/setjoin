//! Gateway two-tier search facade (`#558`):
//! - Authenticated internal HA search leader RPC handler (`POST /_internal/search/candidates`
//!   and `GET /_internal/search/health`), strictly gated on `SETJOIN_SEARCH_TIER2_ENABLED=true`,
//!   active HA leadership (`SearchRuntime::is_leader_active()` -> `503` on demotion/expiry),
//!   HMAC-SHA256 (`X-Setjoin-Search-Ts` + `X-Setjoin-Search-Sig`, `±30s` replay window),
//!   and `<= 64 KiB` body cap.
//! - Mandatory PostgreSQL ACL re-authorization wiring for gateway Mail (`Email/query`),
//!   Chat (`/api/chat/search`), and Drive (`/api/drive/search`) search surfaces under
//!   scoped `AppPool` (`setjoin_app`, `NOBYPASSRLS`) `MailboxTx<ReadOnly>` / `UserTx<ReadOnly>`
//!   handles, returning 100% canonical reducer wire contracts (`jmap_email_query`,
//!   `chat_search`, `drive_search_nodes`) and transparently deferring to canonical
//!   Tier-1 PG reducers with ZERO double PG queries whenever Tier-2 is disabled,
//!   unfresh, truncated, or degraded.

use crate::Body;
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode};
use serde_json::{json, Value};
use setjoin_authz::AuthContext;
use setjoin_contracts::ids::{ActorId, Generation};
use setjoin_pg::{AppPool, MailboxAuthContext, Param, Type};
use setjoin_search::{
    reauthorize_drive_candidates, reauthorize_mail_candidates, verify_rpc_request, BoxFuture,
    CandidateBatch, CandidateQuery, DocCorpus, DocumentKey, EngineHealth, MailReauthFilter,
    NormalizedQuery, RpcCandidateRequest, RpcCandidateResponse, RpcHealthResponse, ScopeHint,
    SearchEngine, SearchError, SearchRuntime, SearchTier, SearchVisibility, HEADER_SEARCH_SIG,
    HEADER_SEARCH_TS, INTERNAL_SEARCH_CANDIDATES_PATH, INTERNAL_SEARCH_HEALTH_PATH,
    MAX_OVERFETCH_CANDIDATES, MAX_OVERFETCH_ROUNDS, MAX_RPC_BODY_BYTES,
};
use std::collections::HashSet;
use std::sync::Arc;

/// Fail-closed Tier-1 stub passed to `SearchRuntime::engine(...)` inside `GatewaySearchFacade`.
///
/// Whenever `TwoTierSearchEngine` cannot serve a fresh Tier-2 batch, returning `Err(Unavailable)`
/// causes `try_*` to immediately return `None`, letting the gateway handler run the canonical
/// Tier-1 SQL reducer ONCE without executing a redundant double PG query.
struct FailClosedTier1Stub;

impl SearchEngine for FailClosedTier1Stub {
    fn candidates<'a>(
        &'a self,
        _query: &'a CandidateQuery,
    ) -> BoxFuture<'a, Result<CandidateBatch, SearchError>> {
        Box::pin(async {
            Err(SearchError::Unavailable(
                "defer to canonical gateway Tier-1 reducer".to_owned(),
            ))
        })
    }

    fn tier(&self) -> SearchTier {
        SearchTier::Tier1Pg
    }

    fn health(&self) -> EngineHealth {
        EngineHealth::Degraded {
            reason: "gateway facade delegates Tier-1 fallback directly to canonical SQL reducer"
                .to_owned(),
        }
    }
}

/// Handle internal HA search leader RPC requests (`/_internal/search/candidates` and
/// `/_internal/search/health`).
///
/// Returns `404` when Tier-2 search is disabled (`SETJOIN_SEARCH_TIER2_ENABLED=false`),
/// `503` if `SETJOIN_SEARCH_RPC_SECRET` is unset or this node is NOT the active HA search
/// leader (`!rt.is_leader_active()`), `413` if body exceeds `64 KiB`, and `403` on
/// missing/expired/invalid HMAC-SHA256 signatures.
pub async fn handle_internal_search_rpc(
    runtime: Option<&SearchRuntime>,
    mut req: Request<Body>,
) -> Response<Body> {
    let Some(rt) = runtime.filter(|r| r.config().tier2_enabled) else {
        return json_reply(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#.to_owned());
    };

    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    if path == INTERNAL_SEARCH_HEALTH_PATH && !matches!(method, Method::GET | Method::HEAD) {
        return json_reply(
            StatusCode::METHOD_NOT_ALLOWED,
            r#"{"error":"method not allowed"}"#.to_owned(),
        );
    }
    if path == INTERNAL_SEARCH_CANDIDATES_PATH && method != Method::POST {
        return json_reply(
            StatusCode::METHOD_NOT_ALLOWED,
            r#"{"error":"method not allowed"}"#.to_owned(),
        );
    }

    let ts_header = req
        .headers()
        .get(HEADER_SEARCH_TS)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let sig_header = req
        .headers()
        .get(HEADER_SEARCH_SIG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let body = match read_bounded_body(req.body_mut(), MAX_RPC_BODY_BYTES).await {
        Ok(b) => b,
        Err(BodyReadError::TooLarge) => {
            return json_reply(
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"error":"payload too large"}"#.to_owned(),
            );
        }
        Err(BodyReadError::ReadFailed) => {
            return json_reply(
                StatusCode::BAD_REQUEST,
                r#"{"error":"failed to read body"}"#.to_owned(),
            );
        }
    };

    let now_secs = Utc::now().timestamp();
    if let Err(auth_err) = verify_rpc_request(
        &rt.config().rpc_secret,
        method.as_str(),
        &path,
        ts_header.as_deref(),
        sig_header.as_deref(),
        &body,
        now_secs,
    ) {
        let status = StatusCode::from_u16(auth_err.status_code()).unwrap_or(StatusCode::FORBIDDEN);
        return json_reply(status, format!(r#"{{"error":"{auth_err:?}"}}"#));
    }

    // Fence demoted or lease-expired leaders strictly with 503 so followers fail over to Tier-1 PG.
    if !rt.is_leader_active() {
        return json_reply(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"not active search leader"}"#.to_owned(),
        );
    }

    if path == INTERNAL_SEARCH_HEALTH_PATH {
        let payload = RpcHealthResponse::from_health(&rt.health());
        let text =
            serde_json::to_string(&payload).unwrap_or_else(|_| r#"{"healthy":false}"#.to_owned());
        return json_reply(StatusCode::OK, text);
    }

    // POST /_internal/search/candidates
    let Some(engine) = rt.tier2() else {
        return json_reply(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"tier2 engine unavailable"}"#.to_owned(),
        );
    };
    let req_dto: RpcCandidateRequest = match serde_json::from_slice(&body) {
        Ok(dto) => dto,
        Err(_) => {
            return json_reply(
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid search rpc request"}"#.to_owned(),
            );
        }
    };
    let query = match req_dto.into_query() {
        Ok(q) => q,
        Err(_) => {
            return json_reply(
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid search query"}"#.to_owned(),
            );
        }
    };

    match engine
        .candidates_if_fresh(&query, rt.freshness_fence().as_ref())
        .await
    {
        Ok(batch) => {
            let resp = RpcCandidateResponse {
                keys: batch.keys,
                generation: batch.generation,
                continuation: batch.continuation,
                degraded: batch.degraded,
            };
            let text = serde_json::to_string(&resp)
                .unwrap_or_else(|_| r#"{"keys":[],"generation":0,"degraded":true}"#.to_owned());
            json_reply(StatusCode::OK, text)
        }
        Err(SearchError::InvalidCursor) => json_reply(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid cursor"}"#.to_owned(),
        ),
        Err(_) => json_reply(
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"search index unavailable or unfresh"}"#.to_owned(),
        ),
    }
}

enum BodyReadError {
    TooLarge,
    ReadFailed,
}

async fn read_bounded_body(body: &mut Body, max_bytes: usize) -> Result<Vec<u8>, BodyReadError> {
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| BodyReadError::ReadFailed)?;
        if let Some(data) = frame.data_ref() {
            if out.len().saturating_add(data.len()) > max_bytes {
                return Err(BodyReadError::TooLarge);
            }
            out.extend_from_slice(data);
        }
    }
    Ok(out)
}

fn json_reply(status: StatusCode, body: String) -> Response<Body> {
    let boxed: Body = Full::new(Bytes::from(body))
        .map_err(|never| match never {})
        .boxed();
    let mut resp = Response::new(boxed);
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    resp
}

/// Drain bounded complete Tier-2 candidate keys across one or more corpora using
/// `FailClosedTier1Stub`. Returns `None` whenever Tier-2 is unavailable, degraded,
/// unfresh, or exceeds the bounded candidate cap (so the caller cleanly runs canonical Tier-1).
async fn drain_complete_tier2_candidates(
    runtime: &SearchRuntime,
    corpora: &[DocCorpus],
    scope_hint: ScopeHint,
    terms: NormalizedQuery,
) -> Option<Vec<DocumentKey>> {
    let engine = runtime.engine(Arc::new(FailClosedTier1Stub));
    let mut all_keys: Vec<DocumentKey> = Vec::new();
    let mut total_inspected = 0usize;

    for &corpus in corpora {
        let mut cursor = None;
        let mut pinned_gen: Option<u64> = None;
        for round in 0..MAX_OVERFETCH_ROUNDS {
            let remaining = MAX_OVERFETCH_CANDIDATES.saturating_sub(total_inspected);
            if remaining == 0 {
                return None;
            }
            let req_limit = u16::try_from(remaining.min(500)).unwrap_or(500);
            let q = CandidateQuery {
                corpus,
                scope_hint: scope_hint.clone(),
                terms: terms.clone(),
                visibility: SearchVisibility::Live,
                limit: req_limit,
                continuation: cursor,
                metadata_only: false,
                calculate_total: false,
            };
            let batch = engine.candidates(&q).await.ok()?;
            if batch.tier != SearchTier::Tier2Tantivy || batch.degraded {
                return None;
            }
            if let Some(expected_gen) = pinned_gen {
                if batch.generation != expected_gen {
                    return None;
                }
            } else {
                pinned_gen = Some(batch.generation);
            }
            total_inspected = total_inspected.saturating_add(batch.keys.len());
            all_keys.extend(batch.keys);
            match batch.continuation {
                Some(next) if round + 1 < MAX_OVERFETCH_ROUNDS => {
                    cursor = Some(next);
                }
                Some(_) => {
                    // Truncated at bounded cap -> defer to canonical Tier-1 PG for exact total/ordering.
                    return None;
                }
                None => break,
            }
        }
    }

    Some(all_keys)
}

/// Gateway facade pairing [`SearchRuntime`] with a scoped [`AppPool`] (`setjoin_app`,
/// `NOBYPASSRLS`) for mandatory PostgreSQL ACL re-authorization on Mail, Chat, and Drive
/// Tier-2 searches.
#[derive(Clone)]
pub struct GatewaySearchFacade {
    runtime: Arc<SearchRuntime>,
    app_pool: AppPool,
}

impl GatewaySearchFacade {
    #[must_use]
    pub fn new(runtime: Arc<SearchRuntime>, app_pool: AppPool) -> Self {
        Self { runtime, app_pool }
    }

    #[must_use]
    pub fn tier2_enabled(&self) -> bool {
        self.runtime.config().tier2_enabled
    }

    #[must_use]
    pub fn runtime(&self) -> &Arc<SearchRuntime> {
        &self.runtime
    }

    /// Attempt Tier-2 Mail search with mandatory `MailboxTx<ReadOnly>` PG ACL re-authorization,
    /// returning the exact canonical `jmap_email_query` JSON shape (`accountId`, `state`,
    /// `canCalculateChanges`, `position`, `total`, `ids`).
    ///
    /// Returns `Some(json)` ONLY when Tier-2 is enabled, healthy, fresh, and exhausted the
    /// candidate set within bounds (guaranteeing exact `total` and consistent deterministic
    /// `(pinned_at IS NOT NULL DESC, received_at DESC, id DESC)` paging). Returns `None` on
    /// any unsupported filter/sort, truncation, degradation, or fallback so the caller executes
    /// canonical Tier-1 `jmap_email_query` ONCE.
    pub async fn try_mail_query(
        &self,
        auth: &MailboxAuthContext,
        filter_json: Option<&str>,
        sort_json: Option<&str>,
        position: i32,
        limit: i32,
    ) -> Option<String> {
        if !self.tier2_enabled() || position < 0 || limit <= 0 {
            return None;
        }
        // Only accelerate default sort (BM25 relevance) or explicit receivedAt DESC;
        // custom sorts defer cleanly to canonical Tier-1 PG `jmap_email_query`.
        let mut explicit_received_at_desc = false;
        if let Some(sort_raw) = sort_json {
            let trimmed = sort_raw.trim();
            if !trimmed.is_empty() && trimmed != "null" && trimmed != "[]" {
                let parsed_sort: Value = serde_json::from_str(trimmed).ok()?;
                let arr = parsed_sort.as_array()?;
                if arr.len() > 1 {
                    return None;
                }
                if let Some(first) = arr.first() {
                    let prop = first.get("property").and_then(Value::as_str).unwrap_or("");
                    let asc = first
                        .get("isAscending")
                        .and_then(Value::as_bool)
                        .unwrap_or(true);
                    if prop != "receivedAt" || asc {
                        return None;
                    }
                    explicit_received_at_desc = true;
                }
            }
        }
        let filter_raw = filter_json?.trim();
        if filter_raw.is_empty() || filter_raw == "null" {
            return None;
        }
        let filter_val: Value = serde_json::from_str(filter_raw).ok()?;
        let obj = filter_val.as_object()?;
        // Only accelerate { "text": ..., optional "inMailbox": <numeric tag_id> } filters;
        // any additional JMAP filter predicate (or non-numeric sentinel) defers to Tier-1 PG.
        let mut raw_text: Option<&str> = None;
        let mut tag_id: Option<i64> = None;
        for (k, v) in obj {
            match k.as_str() {
                "text" => {
                    raw_text = v.as_str().map(str::trim).filter(|s| !s.is_empty());
                }
                "inMailbox" => {
                    let raw_id = v.as_str()?;
                    if !raw_id.bytes().all(|b| b.is_ascii_digit()) || raw_id.is_empty() {
                        return None;
                    }
                    tag_id = Some(raw_id.parse::<i64>().ok()?);
                }
                _ => return None,
            }
        }
        let raw_text = raw_text?;
        let terms = NormalizedQuery::parse(raw_text).ok()?;

        let mailbox_id = auth.mailbox().get();
        let candidates = drain_complete_tier2_candidates(
            &self.runtime,
            &[DocCorpus::Mail, DocCorpus::MailAttachment],
            ScopeHint::Mailbox(mailbox_id),
            terms,
        )
        .await?;

        // Re-authorize ALL candidates AND read authoritative `mailboxes.jmap_email_state`
        // inside ONE `MailboxTx<ReadOnly>` (`setjoin_app`, `NOBYPASSRLS`).
        let principal = setjoin_pg::mint::mailbox(auth.actor(), auth.mailbox(), Generation(1));
        let reauth_filter = MailReauthFilter {
            folder_id: None,
            tag_id,
            enforce_jmap_snooze_exclusion: true,
            exclude_held: false,
        };
        let mut tx = self.app_pool.begin_mailbox_read(&principal).await.ok()?;
        let state_rows = tx
            .query(
                "SELECT jmap_email_state::text FROM public.mailboxes WHERE id = $1",
                &[(&mailbox_id, Type::INT8)],
            )
            .await
            .ok()?;
        let Some(state_str) = state_rows
            .first()
            .and_then(|r| r.try_get::<_, Option<String>>(0).ok())
            .flatten()
        else {
            let _ = tx.finish().await;
            return None;
        };

        let mut hits = reauthorize_mail_candidates(&mut tx, &candidates, &reauth_filter)
            .await
            .ok()?;
        let _ = tx.finish().await;

        // Preserve canonical `jmap_email_query` ordering:
        // - Explicit `sort: [{"property":"receivedAt","isAscending":false}]` -> `(received_at DESC, id DESC)`.
        // - Default text query without explicit sort (`jmap_email.sql:189-203`) -> relevance rank
        //   (Tantivy BM25 candidate rank order) with `(received_at DESC, id DESC)` tie-break, NOT pin-first.
        if explicit_received_at_desc {
            hits.sort_by(|a, b| {
                b.received_at
                    .cmp(&a.received_at)
                    .then_with(|| b.id.cmp(&a.id))
            });
        } else {
            let mut rank_by_id: std::collections::HashMap<i64, usize> =
                std::collections::HashMap::with_capacity(candidates.len());
            for (idx, key) in candidates.iter().enumerate() {
                match key {
                    DocumentKey::Mail { id, .. } | DocumentKey::MailAttachment { id, .. }
                        if *id > 0 =>
                    {
                        rank_by_id.entry(*id).or_insert(idx);
                    }
                    _ => {}
                }
            }
            hits.sort_by(|a, b| {
                let ra = rank_by_id.get(&a.id).copied().unwrap_or(usize::MAX);
                let rb = rank_by_id.get(&b.id).copied().unwrap_or(usize::MAX);
                ra.cmp(&rb)
                    .then_with(|| b.received_at.cmp(&a.received_at))
                    .then_with(|| b.id.cmp(&a.id))
            });
        }

        let total = hits.len();
        let pos_usize = usize::try_from(position).unwrap_or(0);
        let lim_usize = usize::try_from(limit).unwrap_or(50);
        let ids: Vec<String> = hits
            .into_iter()
            .skip(pos_usize)
            .take(lim_usize)
            .map(|h| h.id.to_string())
            .collect();

        let reply = json!({
            "accountId": mailbox_id.to_string(),
            "state": state_str,
            "canCalculateChanges": false,
            "position": position,
            "total": total,
            "ids": ids,
        });
        serde_json::to_string(&reply).ok()
    }

    /// Attempt Tier-2 Chat search with mandatory single-transaction `UserTx<ReadOnly>`
    /// PG ACL re-authorization + `chat_message_to_json(m, $1)` hydration, returning the
    /// exact canonical bare JSON array of `chat_search` (`chat_search.sql:43-71`).
    ///
    /// Enforces live `chat_channel_members`, `deleted_at IS NULL`, full `GUEST_HISTORY_FLOOR`
    /// (`m.seq > COALESCE(cm.history_floor_seq, 0) AND (cm.history_floor_seq IS NULL OR m.created_at >= cm.joined_at)`),
    /// parent-message history floor, and `m.id DESC LIMIT 50` ordering.
    pub async fn try_chat_search(
        &self,
        actor: &AuthContext,
        raw_query: &str,
        channel: Option<i64>,
        author: Option<i64>,
        before: Option<i64>,
        has: Option<&str>,
    ) -> Option<String> {
        let actor_id = ActorId::new(actor.user_id()).ok()?;
        self.try_chat_search_actor(actor_id, raw_query, channel, author, before, has)
            .await
    }

    /// Actor-scoped variant of [`Self::try_chat_search`].
    pub async fn try_chat_search_actor(
        &self,
        actor_id: ActorId,
        raw_query: &str,
        channel: Option<i64>,
        author: Option<i64>,
        before: Option<i64>,
        has: Option<&str>,
    ) -> Option<String> {
        if !self.tier2_enabled() || author.is_some() || before.is_some() || has.is_some() {
            return None;
        }
        let terms = NormalizedQuery::parse(raw_query).ok()?;
        let user_id = actor_id.get();
        let principal = setjoin_pg::mint::user(actor_id, Generation(1));

        // Resolve coarse member channel scope inside UserTx<ReadOnly>.
        // If the user belongs to >= 256 channels, defer to Tier-1 `chat_search` rather than truncating.
        let channel_ids: Vec<i64> = {
            let mut tx = self.app_pool.begin_user_read(&principal).await.ok()?;
            let rows = tx
                .query(
                    "SELECT channel_id FROM public.chat_channel_members \
                      WHERE user_id = $1 AND ($2::bigint IS NULL OR channel_id = $2) \
                      ORDER BY channel_id LIMIT 256",
                    &[(&user_id, Type::INT8), (&channel, Type::INT8)],
                )
                .await
                .ok()?;
            let _ = tx.finish().await;
            rows.iter()
                .filter_map(|r| r.try_get::<_, i64>(0).ok())
                .collect()
        };
        if channel_ids.is_empty() {
            return Some("[]".to_owned());
        }
        if channel_ids.len() >= 256 {
            return None;
        }

        let candidates = drain_complete_tier2_candidates(
            &self.runtime,
            &[DocCorpus::Chat],
            ScopeHint::Channels(channel_ids),
            terms,
        )
        .await?;

        let mut cand_ids: Vec<i64> = Vec::with_capacity(candidates.len());
        let mut cand_chans: Vec<i64> = Vec::with_capacity(candidates.len());
        let mut seen: HashSet<(i64, i64)> = HashSet::with_capacity(candidates.len());
        for key in candidates {
            if let DocumentKey::Chat { channel_id, id } = key {
                if id > 0 && seen.insert((channel_id, id)) {
                    cand_ids.push(id);
                    cand_chans.push(channel_id);
                }
            }
        }
        if cand_ids.is_empty() {
            return Some("[]".to_owned());
        }

        // Single-transaction ACL re-authorization + canonical `chat_message_to_json(m, $1)`
        // hydration inside ONE `UserTx<ReadOnly>` (eliminates TOCTOU and matches `chat_search.sql`).
        let mut tx = self.app_pool.begin_user_read(&principal).await.ok()?;
        let sql = "SELECT COALESCE( \
                     (SELECT jsonb_agg(public.chat_message_to_json(m, $1) ORDER BY m.id DESC) \
                        FROM ( \
                          SELECT m.* \
                            FROM unnest($2::bigint[], $3::bigint[]) AS cand(id, channel_id) \
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
                           ORDER BY m.id DESC \
                           LIMIT 50 \
                        ) m), \
                     '[]'::jsonb \
                   )::text";
        let params: [Param<'_>; 4] = [
            (&user_id, Type::INT8),
            (&cand_ids, Type::INT8_ARRAY),
            (&cand_chans, Type::INT8_ARRAY),
            (&channel, Type::INT8),
        ];
        let rows = tx.query(sql, &params).await.ok()?;
        let _ = tx.finish().await;
        rows.first().and_then(|r| r.try_get::<_, String>(0).ok())
    }

    /// Attempt Tier-2 Drive search with mandatory `UserTx<ReadOnly>` PG ACL re-authorization
    /// (`drive_runtime_capability_sources_set`, `deleted_at IS NULL AND purged_at IS NULL`),
    /// returning the exact 8-field `drive_search_nodes` JSON array (`id`, `spaceId`,
    /// `parentId`, `kind`, `name`, `sizeBytes`, `contentType`, `createdAt`).
    pub async fn try_drive_search(
        &self,
        actor: &AuthContext,
        space: Option<i64>,
        raw_query: &str,
        max: Option<i64>,
    ) -> Option<Value> {
        let actor_id = ActorId::new(actor.user_id()).ok()?;
        self.try_drive_search_actor(actor_id, space, raw_query, max)
            .await
    }

    /// Actor-scoped variant of [`Self::try_drive_search`].
    pub async fn try_drive_search_actor(
        &self,
        actor_id: ActorId,
        space: Option<i64>,
        raw_query: &str,
        max: Option<i64>,
    ) -> Option<Value> {
        if !self.tier2_enabled() || raw_query.trim().is_empty() {
            return None;
        }
        let terms = NormalizedQuery::parse(raw_query).ok()?;
        let user_id = actor_id.get();
        let principal = setjoin_pg::mint::user(actor_id, Generation(1));
        // Exact page-size clamping matching `drive_search_nodes.sql:53`.
        let limit = usize::try_from(max.unwrap_or(100).clamp(1, 500)).unwrap_or(100);

        let scope_hint = match space {
            Some(sid) => ScopeHint::Spaces(vec![sid]),
            None => {
                // Collect ALL spaces reachable via space membership, ownership, OR active
                // node-level ACL grants (direct user or directory group per `drive_effective_access.sql`).
                let mut tx = self.app_pool.begin_user_read(&principal).await.ok()?;
                let rows = tx
                    .query(
                        "SELECT space_id FROM ( \
                           SELECT space_id FROM public.drive_space_members WHERE user_id = $1 \
                           UNION \
                           SELECT id AS space_id FROM public.drive_spaces WHERE owner_user_id = $1 \
                           UNION \
                           SELECT g.space_id \
                             FROM public.drive_acl_grants g \
                            WHERE g.state = 'active' \
                              AND (g.starts_at IS NULL OR g.starts_at <= now()) \
                              AND (g.expires_at IS NULL OR g.expires_at > now()) \
                              AND (g.max_uses IS NULL OR g.used_count < g.max_uses) \
                              AND ( \
                                (g.subject_kind = 'user' AND g.subject_user_id = $1) \
                                OR (g.subject_kind = 'group' \
                                    AND COALESCE((SELECT enabled FROM public.feature_toggles \
                                                  WHERE key = 'feature.directory_group_authority'), false) \
                                    AND public.directory_group_effective_member($1, g.subject_group_id)) \
                              ) \
                         ) accessible \
                         ORDER BY space_id LIMIT 256",
                        &[(&user_id, Type::INT8)],
                    )
                    .await
                    .ok()?;
                let _ = tx.finish().await;
                let sids: Vec<i64> = rows
                    .iter()
                    .filter_map(|r| r.try_get::<_, i64>(0).ok())
                    .collect();
                if sids.is_empty() {
                    return Some(Value::Array(Vec::new()));
                }
                if sids.len() >= 256 {
                    return None;
                }
                ScopeHint::Spaces(sids)
            }
        };

        let candidates = drain_complete_tier2_candidates(
            &self.runtime,
            &[DocCorpus::Drive, DocCorpus::DriveFile],
            scope_hint,
            terms,
        )
        .await?;

        if candidates.is_empty() {
            return Some(Value::Array(Vec::new()));
        }

        let mut tx = self.app_pool.begin_user_read(&principal).await.ok()?;
        let mut hits = reauthorize_drive_candidates(&mut tx, &candidates, space)
            .await
            .ok()?;
        let _ = tx.finish().await;

        // Exact ordering matching `drive_search_nodes.sql:52`: `lower(n.name), n.id`.
        hits.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.id.cmp(&b.id))
        });
        hits.truncate(limit);

        let items: Vec<Value> = hits
            .into_iter()
            .map(|h| {
                json!({
                    "id": h.id,
                    "spaceId": h.space_id,
                    "parentId": h.parent_id,
                    "kind": h.kind,
                    "name": h.name,
                    "sizeBytes": h.size_bytes,
                    "contentType": h.content_type,
                    "createdAt": h.created_at,
                })
            })
            .collect();
        Some(Value::Array(items))
    }
}
