//! Domain-agnostic search contracts, typed document keys, query normalization,
//! HMAC-bound opaque cursors, and object-safe `SearchEngine` / `SearchIndexer` traits.

use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::future::Future;
use std::pin::Pin;

/// Maximum UTF-8 byte length of a user search query (DoS bound).
pub const MAX_QUERY_BYTES: usize = 256;

/// Maximum term count of a user search query (DoS bound).
pub const MAX_QUERY_TERMS: usize = 32;

/// Maximum candidate keys requested in a single batch.
pub const MAX_CANDIDATE_LIMIT: u16 = 500;

/// Maximum scope IDs in a single `ScopeHint::Channels` or `ScopeHint::Spaces`.
pub const MAX_SCOPE_IDS: usize = 256;

/// Maximum encoded byte length accepted for an untrusted [`OpaqueCursor`] token.
pub const MAX_CURSOR_TOKEN_BYTES: usize = 512;

/// Maximum candidate offset permitted in an [`OpaqueCursor`] (aligned with overfetch budget).
pub const MAX_CURSOR_OFFSET: usize = 1_500;

type HmacSha256 = Hmac<Sha256>;

/// Heap-allocated `Send` future used by the object-safe search traits.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Indexed corpus discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocCorpus {
    Mail,
    Chat,
    Drive,
    MailAttachment,
    DriveFile,
}

impl DocCorpus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mail => "mail",
            Self::Chat => "chat",
            Self::Drive => "drive",
            Self::MailAttachment => "mail_attachment",
            Self::DriveFile => "drive_file",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "mail" => Some(Self::Mail),
            "chat" => Some(Self::Chat),
            "drive" => Some(Self::Drive),
            "mail_attachment" => Some(Self::MailAttachment),
            "drive_file" => Some(Self::DriveFile),
            _ => None,
        }
    }
}

/// Visibility partition of an indexed document.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchVisibility {
    /// Normal active rows visible to authorized tenant users.
    #[default]
    Live,
    /// Compliance/legal-hold tombstones visible only to eDiscovery workflows.
    ComplianceOnly,
}

impl SearchVisibility {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::ComplianceOnly => "compliance_only",
        }
    }
}

/// Execution tier that produced a candidate batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchTier {
    Tier1Pg,
    Tier2Tantivy,
}

/// Health snapshot reported by an engine implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineHealth {
    Healthy { epoch: u64, generation: u64 },
    Disabled,
    Degraded { reason: String },
}

impl EngineHealth {
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy { .. })
    }
}

/// Typed composite document keys preserving `V283` partitioned mail `(id, received_at)`
/// and Wave 3.2 attachment/file `sub_id`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DocumentKey {
    Mail {
        mailbox_id: i64,
        id: i64,
        received_at: DateTime<Utc>,
    },
    Chat {
        channel_id: i64,
        id: i64,
    },
    Drive {
        space_id: i64,
        id: i64,
    },
    MailAttachment {
        mailbox_id: i64,
        id: i64,
        received_at: DateTime<Utc>,
        sub_id: i64,
    },
    DriveFile {
        space_id: i64,
        id: i64,
        sub_id: i64,
    },
}

impl DocumentKey {
    #[must_use]
    pub const fn corpus(&self) -> DocCorpus {
        match self {
            Self::Mail { .. } => DocCorpus::Mail,
            Self::Chat { .. } => DocCorpus::Chat,
            Self::Drive { .. } => DocCorpus::Drive,
            Self::MailAttachment { .. } => DocCorpus::MailAttachment,
            Self::DriveFile { .. } => DocCorpus::DriveFile,
        }
    }

    /// Coarse pre-filter scope key stored in Tantivy (NEVER an authorization authority).
    #[must_use]
    pub fn scope_key(&self) -> String {
        match self {
            Self::Mail { mailbox_id, .. } | Self::MailAttachment { mailbox_id, .. } => {
                format!("mail:{mailbox_id}")
            }
            Self::Chat { channel_id, .. } => format!("chat:{channel_id}"),
            Self::Drive { space_id, .. } | Self::DriveFile { space_id, .. } => {
                format!("drive:{space_id}")
            }
        }
    }

    /// Lossless canonical key string stored in Tantivy's `doc_key` field.
    #[must_use]
    pub fn encode_doc_key(&self) -> String {
        match self {
            Self::Mail {
                mailbox_id,
                id,
                received_at,
            } => format!("mail:{mailbox_id}:{id}:{}", received_at.timestamp_micros()),
            Self::Chat { channel_id, id } => format!("chat:{channel_id}:{id}"),
            Self::Drive { space_id, id } => format!("drive:{space_id}:{id}"),
            Self::MailAttachment {
                mailbox_id,
                id,
                received_at,
                sub_id,
            } => format!(
                "mail_attachment:{mailbox_id}:{id}:{}:{sub_id}",
                received_at.timestamp_micros()
            ),
            Self::DriveFile {
                space_id,
                id,
                sub_id,
            } => format!("drive_file:{space_id}:{id}:{sub_id}"),
        }
    }

    /// Decode a canonical `doc_key` back into a typed [`DocumentKey`].
    #[must_use]
    pub fn decode_doc_key(raw: &str) -> Option<Self> {
        let mut parts = raw.split(':');
        let kind = parts.next()?;
        match kind {
            "mail" => {
                let mailbox_id = parts.next()?.parse::<i64>().ok()?;
                let id = parts.next()?.parse::<i64>().ok()?;
                let micros = parts.next()?.parse::<i64>().ok()?;
                if parts.next().is_some() {
                    return None;
                }
                let received_at = Utc.timestamp_micros(micros).single()?;
                Some(Self::Mail {
                    mailbox_id,
                    id,
                    received_at,
                })
            }
            "chat" => {
                let channel_id = parts.next()?.parse::<i64>().ok()?;
                let id = parts.next()?.parse::<i64>().ok()?;
                if parts.next().is_some() {
                    return None;
                }
                Some(Self::Chat { channel_id, id })
            }
            "drive" => {
                let space_id = parts.next()?.parse::<i64>().ok()?;
                let id = parts.next()?.parse::<i64>().ok()?;
                if parts.next().is_some() {
                    return None;
                }
                Some(Self::Drive { space_id, id })
            }
            "mail_attachment" => {
                let mailbox_id = parts.next()?.parse::<i64>().ok()?;
                let id = parts.next()?.parse::<i64>().ok()?;
                let micros = parts.next()?.parse::<i64>().ok()?;
                let sub_id = parts.next()?.parse::<i64>().ok()?;
                if parts.next().is_some() {
                    return None;
                }
                let received_at = Utc.timestamp_micros(micros).single()?;
                Some(Self::MailAttachment {
                    mailbox_id,
                    id,
                    received_at,
                    sub_id,
                })
            }
            "drive_file" => {
                let space_id = parts.next()?.parse::<i64>().ok()?;
                let id = parts.next()?.parse::<i64>().ok()?;
                let sub_id = parts.next()?.parse::<i64>().ok()?;
                if parts.next().is_some() {
                    return None;
                }
                Some(Self::DriveFile {
                    space_id,
                    id,
                    sub_id,
                })
            }
            _ => None,
        }
    }
}

/// Coarse scope hint narrowing candidate lookup before mandatory PG re-authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeHint {
    Mailbox(i64),
    Channels(Vec<i64>),
    Spaces(Vec<i64>),
    /// Compliance/eDiscovery org-wide search; must still be authorized by PG/admin gate.
    GlobalCompliance,
}

impl ScopeHint {
    /// Return a normalized copy with `Channels`/`Spaces` deduplicated, sorted, and
    /// capped to [`MAX_SCOPE_IDS`] (`256`) so duplicate IDs never distort scoring.
    #[must_use]
    pub fn normalized(&self) -> Self {
        match self {
            Self::Mailbox(id) => Self::Mailbox(*id),
            Self::Channels(ids) => Self::Channels(dedup_cap_ids(ids)),
            Self::Spaces(ids) => Self::Spaces(dedup_cap_ids(ids)),
            Self::GlobalCompliance => Self::GlobalCompliance,
        }
    }

    /// Deterministic canonical string used to bind [`OpaqueCursor`] HMACs.
    #[must_use]
    pub fn canonical_scope(&self) -> String {
        match self {
            Self::Mailbox(id) => format!("mail:{id}"),
            Self::Channels(ids) => {
                let joined = dedup_cap_ids(ids)
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                format!("chat:[{joined}]")
            }
            Self::Spaces(ids) => {
                let joined = dedup_cap_ids(ids)
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                format!("drive:[{joined}]")
            }
            Self::GlobalCompliance => "global:compliance".to_owned(),
        }
    }

    /// Deduplicated, capped `scope_key` term values to match in Tantivy (`None` means global compliance).
    #[must_use]
    pub fn tantivy_scope_keys(&self) -> Option<Vec<String>> {
        match self {
            Self::Mailbox(id) => Some(vec![format!("mail:{id}")]),
            Self::Channels(ids) => Some(
                dedup_cap_ids(ids)
                    .into_iter()
                    .map(|id| format!("chat:{id}"))
                    .collect(),
            ),
            Self::Spaces(ids) => Some(
                dedup_cap_ids(ids)
                    .into_iter()
                    .map(|id| format!("drive:{id}"))
                    .collect(),
            ),
            Self::GlobalCompliance => None,
        }
    }
}

fn dedup_cap_ids(ids: &[i64]) -> Vec<i64> {
    let mut out: Vec<i64> = Vec::with_capacity(ids.len().min(MAX_SCOPE_IDS));
    for &id in ids {
        if !out.contains(&id) {
            out.push(id);
            if out.len() >= MAX_SCOPE_IDS {
                break;
            }
        }
    }
    out.sort_unstable();
    out
}

/// Errors returned when validating a user search query against DoS limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryValidationError {
    Empty,
    TooLong { bytes: usize, max: usize },
    TooManyTerms { terms: usize, max: usize },
    LeadingWildcard,
    RegexNotAllowed,
    ControlCharacter,
}

impl fmt::Display for QueryValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("search query must not be empty"),
            Self::TooLong { bytes, max } => {
                write!(f, "search query exceeds {max} byte limit ({bytes} bytes)")
            }
            Self::TooManyTerms { terms, max } => {
                write!(f, "search query exceeds {max} term limit ({terms} terms)")
            }
            Self::LeadingWildcard => {
                f.write_str("leading wildcard queries (*foo / ?foo) are not allowed")
            }
            Self::RegexNotAllowed => f.write_str("user regex queries (/.../) are not allowed"),
            Self::ControlCharacter => f.write_str("control characters are not allowed in queries"),
        }
    }
}

impl std::error::Error for QueryValidationError {}

/// Validated, normalized query enforcing DoS bounds (`<= 256` bytes, `<= 32` terms,
/// no leading wildcards, no user regexes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedQuery {
    raw: String,
    terms: Vec<String>,
    query_hash: String,
    has_cjk: bool,
}

impl NormalizedQuery {
    /// Parse and validate raw user query text against DoS bounds.
    pub fn parse(input: &str) -> Result<Self, QueryValidationError> {
        if input.len() > MAX_QUERY_BYTES {
            return Err(QueryValidationError::TooLong {
                bytes: input.len(),
                max: MAX_QUERY_BYTES,
            });
        }
        if input
            .bytes()
            .any(|b| b == 0 || (b < 0x20 && !b.is_ascii_whitespace()))
        {
            return Err(QueryValidationError::ControlCharacter);
        }
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(QueryValidationError::Empty);
        }
        if trimmed.len() > MAX_QUERY_BYTES {
            return Err(QueryValidationError::TooLong {
                bytes: trimmed.len(),
                max: MAX_QUERY_BYTES,
            });
        }

        let mut terms = Vec::new();
        for tok in trimmed.split_whitespace() {
            if tok.starts_with('*') || tok.starts_with('?') {
                return Err(QueryValidationError::LeadingWildcard);
            }
            if tok.len() >= 2 && tok.starts_with('/') && tok.ends_with('/') {
                return Err(QueryValidationError::RegexNotAllowed);
            }
            // Also guard regex syntax with trailing flags like `/foo/i` or `/foo/gim`,
            // while allowing filesystem paths such as `/var/lib/setjoin`.
            if let Some(rest) = tok.strip_prefix('/') {
                if let Some(end_slash) = rest.rfind('/') {
                    let flags = &rest[end_slash + 1..];
                    if !flags.is_empty()
                        && flags.len() <= 7
                        && flags
                            .chars()
                            .all(|c| matches!(c, 'i' | 'm' | 's' | 'u' | 'v' | 'x' | 'g'))
                    {
                        return Err(QueryValidationError::RegexNotAllowed);
                    }
                }
            }
            terms.push(tok.to_lowercase());
            if terms.len() > MAX_QUERY_TERMS {
                return Err(QueryValidationError::TooManyTerms {
                    terms: terms.len(),
                    max: MAX_QUERY_TERMS,
                });
            }
        }

        if terms.is_empty() {
            return Err(QueryValidationError::Empty);
        }

        let canonical = terms.join(" ");
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let query_hash = hex::encode(hasher.finalize());
        let has_cjk = trimmed.chars().any(crate::tokenizers::is_cjk_char);

        Ok(Self {
            raw: trimmed.to_owned(),
            terms,
            query_hash,
            has_cjk,
        })
    }

    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    #[must_use]
    pub fn terms(&self) -> &[String] {
        &self.terms
    }

    #[must_use]
    pub fn query_hash(&self) -> &str {
        &self.query_hash
    }

    #[must_use]
    pub const fn has_cjk(&self) -> bool {
        self.has_cjk
    }
}

/// HMAC-SHA256 continuation cursor bound strictly to
/// `(corpus, visibility, scope, query_hash, generation, offset)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueCursor {
    token: String,
}

#[derive(Serialize, Deserialize)]
struct CursorPayload {
    generation: u64,
    offset: usize,
    mac: String,
}

/// Binding context required when minting or verifying an [`OpaqueCursor`].
#[derive(Clone, Copy, Debug)]
pub struct CursorBinding<'a> {
    pub corpus: DocCorpus,
    pub visibility: SearchVisibility,
    pub scope_key: &'a str,
    pub query_hash: &'a str,
    pub generation: u64,
}

impl OpaqueCursor {
    /// Mint a new cursor bound to `(corpus, visibility, scope_key, query_hash, generation, offset)`.
    pub fn mint(
        secret: &[u8],
        binding: CursorBinding<'_>,
        offset: usize,
    ) -> Result<Self, SearchError> {
        if secret.is_empty() {
            return Err(SearchError::Unavailable(
                "cursor HMAC secret unavailable".to_owned(),
            ));
        }
        if offset > MAX_CURSOR_OFFSET {
            return Err(SearchError::InvalidCursor);
        }
        let mac = compute_cursor_mac(secret, binding, offset)?;
        let payload = CursorPayload {
            generation: binding.generation,
            offset,
            mac: hex::encode(mac),
        };
        let encoded = serde_json::to_vec(&payload)
            .map_err(|e| SearchError::Internal(format!("cursor encode: {e}")))?;
        let token = hex::encode(encoded);
        if token.len() > MAX_CURSOR_TOKEN_BYTES {
            return Err(SearchError::Internal(
                "minted cursor exceeded MAX_CURSOR_TOKEN_BYTES".to_owned(),
            ));
        }
        Ok(Self { token })
    }

    /// Verify a cursor against `(corpus, visibility, scope_key, query_hash, generation)`
    /// and extract its bounded offset (`<= MAX_CURSOR_OFFSET`).
    pub fn verify(&self, secret: &[u8], binding: CursorBinding<'_>) -> Result<usize, SearchError> {
        if secret.is_empty() {
            return Err(SearchError::Unavailable(
                "cursor HMAC secret unavailable".to_owned(),
            ));
        }
        if self.token.len() > MAX_CURSOR_TOKEN_BYTES {
            return Err(SearchError::InvalidCursor);
        }
        let raw = hex::decode(&self.token).map_err(|_| SearchError::InvalidCursor)?;
        let payload: CursorPayload =
            serde_json::from_slice(&raw).map_err(|_| SearchError::InvalidCursor)?;
        if payload.generation != binding.generation || payload.offset > MAX_CURSOR_OFFSET {
            return Err(SearchError::InvalidCursor);
        }
        let provided_mac = hex::decode(&payload.mac).map_err(|_| SearchError::InvalidCursor)?;
        let mut verifier = HmacSha256::new_from_slice(secret)
            .map_err(|e| SearchError::Internal(format!("cursor hmac init: {e}")))?;
        update_cursor_mac(&mut verifier, binding, payload.offset);
        verifier
            .verify_slice(&provided_mac)
            .map_err(|_| SearchError::InvalidCursor)?;
        Ok(payload.offset)
    }

    /// Raw opaque token string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.token
    }

    /// Wrap an untrusted opaque token string for later verification.
    #[must_use]
    pub fn from_raw(token: String) -> Self {
        Self { token }
    }
}

fn compute_cursor_mac(
    secret: &[u8],
    binding: CursorBinding<'_>,
    offset: usize,
) -> Result<Vec<u8>, SearchError> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| SearchError::Internal(format!("cursor hmac init: {e}")))?;
    update_cursor_mac(&mut mac, binding, offset);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn update_cursor_mac(mac: &mut HmacSha256, binding: CursorBinding<'_>, offset: usize) {
    mac.update(b"setjoin-cursor-v2\0");
    mac.update(binding.corpus.as_str().as_bytes());
    mac.update(b"\0");
    mac.update(binding.visibility.as_str().as_bytes());
    mac.update(b"\0");
    mac.update(binding.scope_key.as_bytes());
    mac.update(b"\0");
    mac.update(binding.query_hash.as_bytes());
    mac.update(b"\0");
    mac.update(&binding.generation.to_le_bytes());
    mac.update(&(offset as u64).to_le_bytes());
}

/// Candidate-key search request.
#[derive(Clone, Debug)]
pub struct CandidateQuery {
    pub corpus: DocCorpus,
    pub scope_hint: ScopeHint,
    pub terms: NormalizedQuery,
    pub visibility: SearchVisibility,
    pub limit: u16,
    pub continuation: Option<OpaqueCursor>,
    /// True when the query has no full-text predicate (routes straight to Tier-1 PG).
    pub metadata_only: bool,
    /// True when exact total count is required (e.g. JMAP `calculateTotal == true`; routes to Tier-1 PG).
    pub calculate_total: bool,
}

impl CandidateQuery {
    #[must_use]
    pub fn effective_limit(&self) -> usize {
        usize::from(self.limit.clamp(1, MAX_CANDIDATE_LIMIT))
    }
}

/// Candidate-key search output (private ranking; zero plaintext bodies).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateBatch {
    pub keys: Vec<DocumentKey>,
    pub generation: u64,
    pub continuation: Option<OpaqueCursor>,
    pub tier: SearchTier,
    pub degraded: bool,
}

/// Write-side document payload ingested into `SearchIndexer`.
///
/// S/MIME encryption boundary (`V029` C7): when `crypto_sealed == true`, `body` is
/// strictly omitted and NEVER tokenized or stored; only cleartext envelope headers
/// (`title` / `subject`, `headers` / `from` / recipients, `identifiers`) are indexed.
#[derive(Clone, Debug)]
pub struct IndexDocument {
    pub key: DocumentKey,
    pub visibility: SearchVisibility,
    pub title: String,
    pub body: Option<String>,
    pub headers: Vec<String>,
    pub identifiers: Vec<String>,
    pub sort_i64: i64,
    pub sort_name: String,
    pub crypto_sealed: bool,
}

/// Unified error type for `setjoin-search`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchError {
    Validation(QueryValidationError),
    InvalidCursor,
    StaleEpoch { expected: u64, on_disk: u64 },
    Unavailable(String),
    Timeout,
    CorruptIndex(String),
    Io(String),
    Database(String),
    Internal(String),
}

impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(e) => write!(f, "invalid query: {e}"),
            Self::InvalidCursor => f.write_str("invalid or expired continuation cursor"),
            Self::StaleEpoch { expected, on_disk } => write!(
                f,
                "stale search epoch: loaded epoch {expected} does not match on-disk epoch {on_disk}"
            ),
            Self::Unavailable(msg) => write!(f, "search engine unavailable: {msg}"),
            Self::Timeout => f.write_str("search query exceeded timeout budget"),
            Self::CorruptIndex(msg) => write!(f, "corrupt search index: {msg}"),
            Self::Io(msg) => write!(f, "search storage I/O error: {msg}"),
            Self::Database(msg) => write!(f, "search database error: {msg}"),
            Self::Internal(msg) => write!(f, "internal search error: {msg}"),
        }
    }
}

impl std::error::Error for SearchError {}

impl From<QueryValidationError> for SearchError {
    fn from(value: QueryValidationError) -> Self {
        Self::Validation(value)
    }
}

/// Object-safe read-side candidate generator seam.
///
/// Implementations generate candidate [`DocumentKey`]s ONLY; they NEVER act as an
/// authorization authority and NEVER return hydrated plaintext bodies.
pub trait SearchEngine: Send + Sync {
    fn candidates<'a>(
        &'a self,
        query: &'a CandidateQuery,
    ) -> BoxFuture<'a, Result<CandidateBatch, SearchError>>;

    fn tier(&self) -> SearchTier;

    fn health(&self) -> EngineHealth;
}

/// Report returned after physical lawful-purge eviction and segment compaction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgeCompactionReport {
    pub evicted_keys: usize,
    pub segments_merged: usize,
    pub epoch: u64,
    pub generation: u64,
}

/// Object-safe write-side ingestion seam (consumed by Wave 3.2 `WorkQueue` and Wave 3.3 RPC leader).
pub trait SearchIndexer: Send + Sync {
    fn upsert_batch<'a>(
        &'a self,
        docs: &'a [IndexDocument],
    ) -> BoxFuture<'a, Result<usize, SearchError>>;

    fn delete_batch<'a>(
        &'a self,
        keys: &'a [DocumentKey],
    ) -> BoxFuture<'a, Result<usize, SearchError>>;

    fn commit_generation<'a>(&'a self) -> BoxFuture<'a, Result<u64, SearchError>>;

    /// Lease-fenced variant of [`Self::upsert_batch`]: checks `lease_lost`
    /// inside the critical commit/publication section before mutating on-disk state.
    fn upsert_batch_checked<'a>(
        &'a self,
        docs: &'a [IndexDocument],
        lease_lost: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> BoxFuture<'a, Result<usize, SearchError>> {
        if lease_lost
            .as_deref()
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::Acquire))
        {
            return Box::pin(async {
                Err(SearchError::Unavailable(
                    "workqueue lease lost before search upsert".to_owned(),
                ))
            });
        }
        self.upsert_batch(docs)
    }

    /// Lease-fenced variant of [`Self::delete_batch`]: checks `lease_lost`
    /// inside the critical commit/publication section before mutating on-disk state.
    fn delete_batch_checked<'a>(
        &'a self,
        keys: &'a [DocumentKey],
        lease_lost: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> BoxFuture<'a, Result<usize, SearchError>> {
        if lease_lost
            .as_deref()
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::Acquire))
        {
            return Box::pin(async {
                Err(SearchError::Unavailable(
                    "workqueue lease lost before search delete".to_owned(),
                ))
            });
        }
        self.delete_batch(keys)
    }

    /// Lease-fenced variant of [`Self::commit_generation`]: checks `lease_lost`
    /// inside the critical commit/publication section before publishing a new generation.
    fn commit_generation_checked<'a>(
        &'a self,
        lease_lost: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> BoxFuture<'a, Result<u64, SearchError>> {
        if lease_lost
            .as_deref()
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::Acquire))
        {
            return Box::pin(async {
                Err(SearchError::Unavailable(
                    "workqueue lease lost before search commit".to_owned(),
                ))
            });
        }
        self.commit_generation()
    }

    /// Physically evict purged document keys and compact segments so purged bytes
    /// are overwritten/removed from disk rather than lingering in unmerged segments.
    fn evict_and_compact<'a>(
        &'a self,
        keys: &'a [DocumentKey],
    ) -> BoxFuture<'a, Result<PurgeCompactionReport, SearchError>> {
        self.evict_and_compact_checked(keys, None)
    }

    /// Lease-fenced variant of [`Self::evict_and_compact`].
    fn evict_and_compact_checked<'a>(
        &'a self,
        keys: &'a [DocumentKey],
        lease_lost: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> BoxFuture<'a, Result<PurgeCompactionReport, SearchError>> {
        Box::pin(async move {
            let deleted = self.delete_batch_checked(keys, lease_lost.clone()).await?;
            let generation = self.commit_generation_checked(lease_lost).await?;
            Ok(PurgeCompactionReport {
                evicted_keys: deleted,
                segments_merged: 0,
                epoch: 0,
                generation,
            })
        })
    }

    /// Reload `CURRENT` on disk if an external process (e.g. online `mailctl search rebuild`)
    /// atomically published a strictly newer epoch.
    fn reload_if_disk_epoch_advanced(&self) -> Result<bool, SearchError> {
        Ok(false)
    }
}
