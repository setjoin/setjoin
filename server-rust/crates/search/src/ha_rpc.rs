//! Authenticated internal HA single-writer search leader RPC adapter (`#558`)
//! and PostgreSQL `SKIP LOCKED` leader lease helpers.
//!
//! Security boundary:
//! - Every internal RPC request is authenticated with HMAC-SHA256 over
//!   `method\0path\0ts_secs\0body` carried in `X-Setjoin-Search-Ts` and
//!   `X-Setjoin-Search-Sig`.
//! - Verified strictly in constant time via `ring::constant_time::verify_slices_are_equal`
//!   with a `±30s` replay window and `<= 64 KiB` body cap.
//! - Fails closed when `SETJOIN_SEARCH_RPC_SECRET` is unset/empty.
//! - On ANY leader unavailability, timeout, HTTP error, or degraded leader response,
//!   [`RemoteSearchEngine`] returns `Err(SearchError::Unavailable(..))` so
//!   [`crate::TwoTierSearchEngine`] transparently degrades to Tier-1 PostgreSQL.

use crate::model::{
    BoxFuture, CandidateBatch, CandidateQuery, DocCorpus, DocumentKey, EngineHealth,
    NormalizedQuery, OpaqueCursor, ScopeHint, SearchEngine, SearchError, SearchTier,
    SearchVisibility,
};
use crate::pipeline::SearchPipelineDb;
use chrono::{DateTime, Utc};
use ring::hmac::{Key, HMAC_SHA256};
use serde::{Deserialize, Serialize};
use setjoin_pg::{Param, Row, Type};
use std::sync::Arc;
use std::time::Duration;

/// Internal leader candidate-search HTTP path.
pub const INTERNAL_SEARCH_CANDIDATES_PATH: &str = "/_internal/search/candidates";

/// Internal leader health probe HTTP path.
pub const INTERNAL_SEARCH_HEALTH_PATH: &str = "/_internal/search/health";

/// Request header carrying Unix epoch seconds timestamp.
pub const HEADER_SEARCH_TS: &str = "x-setjoin-search-ts";

/// Request header carrying lowercase hex HMAC-SHA256 signature.
pub const HEADER_SEARCH_SIG: &str = "x-setjoin-search-sig";

/// Maximum request body size accepted by internal HA search RPC (`64 KiB`).
pub const MAX_RPC_BODY_BYTES: usize = 64 * 1024;

/// Maximum clock skew / replay window in seconds (`±30s`).
pub const MAX_RPC_CLOCK_SKEW_SECS: i64 = 30;

/// Authentication/validation rejection reasons for internal HA search RPC requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpcAuthError {
    SecretNotConfigured,
    BodyTooLarge,
    MissingTimestamp,
    InvalidTimestamp,
    TimestampOutOfWindow,
    MissingSignature,
    InvalidSignature,
}

impl RpcAuthError {
    /// HTTP status code matching fail-closed internal RPC semantics.
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        match self {
            Self::SecretNotConfigured => 503,
            Self::BodyTooLarge => 413,
            Self::MissingTimestamp
            | Self::InvalidTimestamp
            | Self::TimestampOutOfWindow
            | Self::MissingSignature
            | Self::InvalidSignature => 403,
        }
    }
}

fn rpc_signing_input(method: &str, path: &str, ts_secs: i64, body: &[u8]) -> Vec<u8> {
    let ts_str = ts_secs.to_string();
    let mut msg = Vec::with_capacity(24 + method.len() + path.len() + ts_str.len() + body.len());
    msg.extend_from_slice(b"setjoin-search-rpc-v1\0");
    msg.extend_from_slice(method.as_bytes());
    msg.push(0);
    msg.extend_from_slice(path.as_bytes());
    msg.push(0);
    msg.extend_from_slice(ts_str.as_bytes());
    msg.push(0);
    msg.extend_from_slice(body);
    msg
}

/// Compute lowercase hex HMAC-SHA256 signature over `method\0path\0ts_secs\0body`.
pub fn sign_rpc_request(
    secret: &[u8],
    method: &str,
    path: &str,
    ts_secs: i64,
    body: &[u8],
) -> Result<String, SearchError> {
    if secret.is_empty() {
        return Err(SearchError::Unavailable(
            "SETJOIN_SEARCH_RPC_SECRET is not configured".to_owned(),
        ));
    }
    let key = Key::new(HMAC_SHA256, secret);
    let msg = rpc_signing_input(method, path, ts_secs, body);
    let tag = ring::hmac::sign(&key, &msg);
    Ok(hex::encode(tag.as_ref()))
}

/// Verify timestamped HMAC-SHA256 authentication on an internal HA search RPC request
/// using constant-time verification (`ring::hmac::verify`).
pub fn verify_rpc_request(
    secret: &[u8],
    method: &str,
    path: &str,
    ts_header: Option<&str>,
    sig_header: Option<&str>,
    body: &[u8],
    now_secs: i64,
) -> Result<(), RpcAuthError> {
    if secret.is_empty() {
        return Err(RpcAuthError::SecretNotConfigured);
    }
    if body.len() > MAX_RPC_BODY_BYTES {
        return Err(RpcAuthError::BodyTooLarge);
    }
    let ts_raw = ts_header
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(RpcAuthError::MissingTimestamp)?;
    let ts_secs = ts_raw
        .parse::<i64>()
        .map_err(|_| RpcAuthError::InvalidTimestamp)?;
    if now_secs.saturating_sub(ts_secs).abs() > MAX_RPC_CLOCK_SKEW_SECS {
        return Err(RpcAuthError::TimestampOutOfWindow);
    }
    let sig_raw = sig_header
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(RpcAuthError::MissingSignature)?;
    let provided_bytes = hex::decode(sig_raw).map_err(|_| RpcAuthError::InvalidSignature)?;
    let key = Key::new(HMAC_SHA256, secret);
    let msg = rpc_signing_input(method, path, ts_secs, body);
    ring::hmac::verify(&key, &msg, &provided_bytes).map_err(|_| RpcAuthError::InvalidSignature)
}

/// Serializable wire request for `POST /_internal/search/candidates`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcCandidateRequest {
    pub corpus: DocCorpus,
    pub scope_hint: ScopeHint,
    pub raw_query: String,
    pub visibility: SearchVisibility,
    pub limit: u16,
    #[serde(default)]
    pub continuation: Option<OpaqueCursor>,
    #[serde(default)]
    pub metadata_only: bool,
    #[serde(default)]
    pub calculate_total: bool,
}

impl RpcCandidateRequest {
    #[must_use]
    pub fn from_query(q: &CandidateQuery) -> Self {
        Self {
            corpus: q.corpus,
            scope_hint: q.scope_hint.clone(),
            raw_query: q.terms.raw().to_owned(),
            visibility: q.visibility,
            limit: q.limit,
            continuation: q.continuation.clone(),
            metadata_only: q.metadata_only,
            calculate_total: q.calculate_total,
        }
    }

    pub fn into_query(self) -> Result<CandidateQuery, SearchError> {
        let terms = NormalizedQuery::parse(&self.raw_query)?;
        Ok(CandidateQuery {
            corpus: self.corpus,
            scope_hint: self.scope_hint,
            terms,
            visibility: self.visibility,
            limit: self.limit,
            continuation: self.continuation,
            metadata_only: self.metadata_only,
            calculate_total: self.calculate_total,
        })
    }
}

/// Serializable wire response for `POST /_internal/search/candidates`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcCandidateResponse {
    pub keys: Vec<DocumentKey>,
    pub generation: u64,
    #[serde(default)]
    pub continuation: Option<OpaqueCursor>,
    pub degraded: bool,
}

/// Serializable wire response for `GET /_internal/search/health`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcHealthResponse {
    pub healthy: bool,
    pub epoch: Option<u64>,
    pub generation: Option<u64>,
    pub reason: Option<String>,
}

impl RpcHealthResponse {
    #[must_use]
    pub fn from_health(health: &EngineHealth) -> Self {
        match health {
            EngineHealth::Healthy { epoch, generation } => Self {
                healthy: true,
                epoch: Some(*epoch),
                generation: Some(*generation),
                reason: None,
            },
            EngineHealth::Disabled => Self {
                healthy: false,
                epoch: None,
                generation: None,
                reason: Some("disabled".to_owned()),
            },
            EngineHealth::Degraded { reason } => Self {
                healthy: false,
                epoch: None,
                generation: None,
                reason: Some(reason.clone()),
            },
        }
    }
}

/// Snapshot of the currently active HA single-writer search leader lease from PG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaderLeaseState {
    pub holder_node_id: String,
    pub rpc_url: String,
    pub epoch: u64,
    pub generation: u64,
    pub fencing_token: i64,
    pub leased_until: DateTime<Utc>,
}

/// Result of `search_leader_try_acquire(...)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaderAcquireResult {
    pub acquired: bool,
    pub holder_node_id: String,
    pub rpc_url: String,
    pub fencing_token: i64,
    pub leased_until: DateTime<Utc>,
}

/// Attempt to acquire or renew the `SKIP LOCKED` `'search_writer'` leader lease.
pub async fn try_acquire_search_leader(
    db: &dyn SearchPipelineDb,
    node_id: &str,
    rpc_url: &str,
    lease_secs: i32,
) -> Result<LeaderAcquireResult, SearchError> {
    let params: [Param<'_>; 3] = [
        (&node_id, Type::TEXT),
        (&rpc_url, Type::TEXT),
        (&lease_secs, Type::INT4),
    ];
    let rows = db
        .query_typed(
            "SELECT acquired, holder_node_id, rpc_url, fencing_token, leased_until \
               FROM public.search_leader_try_acquire($1, $2, $3)",
            &params,
        )
        .await?;
    let Some(row) = rows.first() else {
        return Err(SearchError::Database(
            "search_leader_try_acquire returned no rows".to_owned(),
        ));
    };
    Ok(LeaderAcquireResult {
        acquired: col(row, 0)?,
        holder_node_id: col(row, 1)?,
        rpc_url: col(row, 2)?,
        fencing_token: col(row, 3)?,
        leased_until: col(row, 4)?,
    })
}

/// Heartbeat an active search leader lease with strict fencing-token check.
pub async fn heartbeat_search_leader(
    db: &dyn SearchPipelineDb,
    node_id: &str,
    fencing_token: i64,
    epoch: u64,
    generation: u64,
    lease_secs: i32,
) -> Result<bool, SearchError> {
    let epoch_i64 = i64::try_from(epoch).unwrap_or(i64::MAX);
    let gen_i64 = i64::try_from(generation).unwrap_or(i64::MAX);
    let params: [Param<'_>; 5] = [
        (&node_id, Type::TEXT),
        (&fencing_token, Type::INT8),
        (&epoch_i64, Type::INT8),
        (&gen_i64, Type::INT8),
        (&lease_secs, Type::INT4),
    ];
    let rows = db
        .query_typed(
            "SELECT public.search_leader_heartbeat($1, $2, $3, $4, $5)",
            &params,
        )
        .await?;
    rows.first()
        .map(|r| col::<bool>(r, 0))
        .transpose()
        .map(|opt| opt.unwrap_or(false))
}

/// Gracefully release the search leader lease on shutdown.
pub async fn release_search_leader(
    db: &dyn SearchPipelineDb,
    node_id: &str,
    fencing_token: i64,
) -> Result<bool, SearchError> {
    let params: [Param<'_>; 2] = [(&node_id, Type::TEXT), (&fencing_token, Type::INT8)];
    let rows = db
        .query_typed("SELECT public.search_leader_release($1, $2)", &params)
        .await?;
    rows.first()
        .map(|r| col::<bool>(r, 0))
        .transpose()
        .map(|opt| opt.unwrap_or(false))
}

/// Resolve the currently active (non-expired) HA search leader lease from PG.
pub async fn current_search_leader(
    db: &dyn SearchPipelineDb,
) -> Result<Option<LeaderLeaseState>, SearchError> {
    let rows = db
        .query_typed(
            "SELECT holder_node_id, rpc_url, epoch, generation, fencing_token, leased_until \
               FROM public.search_leader_current()",
            &[],
        )
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let epoch_i64: i64 = col(row, 2)?;
    let gen_i64: i64 = col(row, 3)?;
    Ok(Some(LeaderLeaseState {
        holder_node_id: col(row, 0)?,
        rpc_url: col(row, 1)?,
        epoch: u64::try_from(epoch_i64).unwrap_or(0),
        generation: u64::try_from(gen_i64).unwrap_or(0),
        fencing_token: col(row, 4)?,
        leased_until: col(row, 5)?,
    }))
}

/// Strategy for resolving the active HA single-writer search leader's internal HTTP URL.
pub trait LeaderResolver: Send + Sync {
    fn resolve_leader_url<'a>(&'a self) -> BoxFuture<'a, Result<Option<String>, SearchError>>;
}

/// Static URL resolver (used when `SETJOIN_SEARCH_LEADER_URL` override is configured).
#[derive(Clone, Debug)]
pub struct StaticLeaderResolver {
    url: String,
}

impl StaticLeaderResolver {
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into().trim().trim_end_matches('/').to_owned(),
        }
    }
}

impl LeaderResolver for StaticLeaderResolver {
    fn resolve_leader_url<'a>(&'a self) -> BoxFuture<'a, Result<Option<String>, SearchError>> {
        Box::pin(async move {
            if self.url.is_empty() {
                Ok(None)
            } else {
                Ok(Some(self.url.clone()))
            }
        })
    }
}

/// PostgreSQL-backed leader URL resolver querying `public.search_leader_current()`.
pub struct DbLeaderResolver {
    db: Arc<dyn SearchPipelineDb>,
}

impl DbLeaderResolver {
    #[must_use]
    pub fn new(db: Arc<dyn SearchPipelineDb>) -> Self {
        Self { db }
    }
}

impl LeaderResolver for DbLeaderResolver {
    fn resolve_leader_url<'a>(&'a self) -> BoxFuture<'a, Result<Option<String>, SearchError>> {
        Box::pin(async move {
            let leader = current_search_leader(self.db.as_ref()).await?;
            Ok(leader
                .map(|l| l.rpc_url.trim().trim_end_matches('/').to_owned())
                .filter(|u| !u.is_empty()))
        })
    }
}

/// Stateless HTTP follower [`SearchEngine`] forwarding candidate queries over
/// HMAC-SHA256 authenticated internal RPC to the active HA single-writer search leader.
pub struct RemoteSearchEngine {
    client: reqwest::Client,
    resolver: Arc<dyn LeaderResolver>,
    rpc_secret: Vec<u8>,
    query_timeout: Duration,
}

impl RemoteSearchEngine {
    /// Construct a new remote follower search client.
    pub fn new(
        resolver: Arc<dyn LeaderResolver>,
        rpc_secret: Vec<u8>,
        query_timeout: Duration,
    ) -> Result<Self, SearchError> {
        let client = reqwest::Client::builder()
            .timeout(query_timeout)
            .connect_timeout(query_timeout)
            .build()
            .map_err(|e| SearchError::Internal(format!("build search rpc http client: {e}")))?;
        Ok(Self {
            client,
            resolver,
            rpc_secret,
            query_timeout,
        })
    }

    async fn execute_rpc(&self, query: &CandidateQuery) -> Result<CandidateBatch, SearchError> {
        if self.rpc_secret.is_empty() {
            return Err(SearchError::Unavailable(
                "SETJOIN_SEARCH_RPC_SECRET unset for remote search RPC".to_owned(),
            ));
        }
        let base_url = self
            .resolver
            .resolve_leader_url()
            .await?
            .ok_or_else(|| SearchError::Unavailable("no active HA search leader".to_owned()))?;
        let url = format!("{base_url}{INTERNAL_SEARCH_CANDIDATES_PATH}");
        let req_dto = RpcCandidateRequest::from_query(query);
        let body = serde_json::to_vec(&req_dto)
            .map_err(|e| SearchError::Internal(format!("serialize search rpc request: {e}")))?;
        if body.len() > MAX_RPC_BODY_BYTES {
            return Err(SearchError::Unavailable(
                "search rpc request exceeds 64 KiB cap".to_owned(),
            ));
        }
        let ts = Utc::now().timestamp();
        let sig = sign_rpc_request(
            &self.rpc_secret,
            "POST",
            INTERNAL_SEARCH_CANDIDATES_PATH,
            ts,
            &body,
        )?;

        let resp = tokio::time::timeout(
            self.query_timeout,
            self.client
                .post(&url)
                .header("content-type", "application/json")
                .header(HEADER_SEARCH_TS, ts.to_string())
                .header(HEADER_SEARCH_SIG, sig)
                .body(body)
                .send(),
        )
        .await
        .map_err(|_| SearchError::Unavailable("search leader RPC timed out".to_owned()))?
        .map_err(|e| SearchError::Unavailable(format!("search leader RPC send failed: {e}")))?;

        let status = resp.status();
        if status.as_u16() == 400 {
            return Err(SearchError::InvalidCursor);
        }
        if !status.is_success() {
            return Err(SearchError::Unavailable(format!(
                "search leader RPC returned HTTP {}",
                status.as_u16()
            )));
        }

        let resp_bytes = tokio::time::timeout(self.query_timeout, resp.bytes())
            .await
            .map_err(|_| SearchError::Unavailable("search leader RPC body timed out".to_owned()))?
            .map_err(|e| SearchError::Unavailable(format!("search leader RPC read body: {e}")))?;
        let dto: RpcCandidateResponse = serde_json::from_slice(&resp_bytes).map_err(|e| {
            SearchError::Unavailable(format!("invalid search leader RPC JSON: {e}"))
        })?;
        if dto.degraded {
            return Err(SearchError::Unavailable(
                "search leader reported degraded response".to_owned(),
            ));
        }

        Ok(CandidateBatch {
            keys: dto.keys,
            generation: dto.generation,
            continuation: dto.continuation,
            tier: SearchTier::Tier2Tantivy,
            degraded: false,
        })
    }
}

impl SearchEngine for RemoteSearchEngine {
    fn candidates<'a>(
        &'a self,
        query: &'a CandidateQuery,
    ) -> BoxFuture<'a, Result<CandidateBatch, SearchError>> {
        Box::pin(async move { self.execute_rpc(query).await })
    }

    fn tier(&self) -> SearchTier {
        SearchTier::Tier2Tantivy
    }

    fn health(&self) -> EngineHealth {
        if self.rpc_secret.is_empty() {
            EngineHealth::Degraded {
                reason: "SETJOIN_SEARCH_RPC_SECRET not configured".to_owned(),
            }
        } else {
            EngineHealth::Healthy {
                epoch: 0,
                generation: 0,
            }
        }
    }
}

fn col<T: for<'a> tokio_postgres::types::FromSql<'a>>(
    row: &Row,
    idx: usize,
) -> Result<T, SearchError> {
    row.try_get(idx)
        .map_err(|e| SearchError::Database(format!("ha_rpc column {idx} decode failed: {e}")))
}
