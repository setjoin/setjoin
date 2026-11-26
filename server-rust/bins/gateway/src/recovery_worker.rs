//! Cleanup of expired and terminal client-assisted recovery uploads.
use setjoin_pg::workers::WorkerDatabase;
use std::{future::Future, pin::Pin, sync::Arc};

/// Current S3 Object Lock retention metadata returned by `GetObjectRetention`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectRetentionInfo {
    /// Lowercase mode: `"governance"` or `"compliance"`.
    pub mode: String,
    /// RFC 3339 retain-until timestamp.
    pub retain_until: String,
}

/// Typed outcome for S3 Object Lock retention calls (`PutObjectRetention` / `GetObjectRetention`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetentionError {
    Transient(u16, String),
    NotFound,
    Forbidden(String),
    Invalid(String),
}

impl std::fmt::Display for RetentionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transient(status, msg) => {
                write!(f, "transient S3 retention error ({status}): {msg}")
            }
            Self::NotFound => write!(f, "S3 object not found (404)"),
            Self::Forbidden(msg) => write!(f, "S3 retention forbidden (403): {msg}"),
            Self::Invalid(msg) => write!(f, "invalid S3 retention request: {msg}"),
        }
    }
}

impl std::error::Error for RetentionError {}

/// Single entry returned by `GET /<bucket>?versions&prefix=<key>` (#551).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectVersionEntry {
    pub key: String,
    pub version_id: String,
    pub is_delete_marker: bool,
    pub last_modified_unix: i64,
}

/// Result of querying object versions for a key or prefix (#551).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionListing {
    /// Bucket supports versioning (enabled or suspended); contains all matching
    /// concrete versions (including `"null"` if present) and delete markers.
    Versioned(Vec<ObjectVersionEntry>),
    /// Backend does not expose object versions (`404`/`501`/`NotImplemented`,
    /// `<ListBucketResult>`, or AWS S3 unversioned `"null"`-only exact listing).
    Unversioned,
}

/// Typed result of deleting a single object or object version (#551).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeleteVersionOutcome {
    Deleted,
    /// A bare `DELETE` on a versioned bucket created a delete marker (`x-amz-delete-marker: true`).
    DeleteMarkerCreated,
    /// Permanent S3 Object Lock / WORM retention rejection (HTTP 403), carrying
    /// the observed unexpired `RetainUntilDate` when confirmed via `GetObjectRetention`.
    WormLocked403 {
        detail: String,
        retain_until: Option<String>,
    },
    /// Conditional `If-Match` failed (`412 Precondition Failed`): object changed concurrently.
    PreconditionFailed,
    Error(String),
}

/// Typed outcome of permanent version-aware S3 blob deletion (#551).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlobDeleteOutcome {
    Deleted,
    WormLocked403 {
        detail: String,
        retain_until: Option<String>,
    },
}

/// The quarantine object-store boundary. Removal of a missing object succeeds.
pub trait ObjectStore: Send + Sync {
    fn read<'a>(
        &'a self,
        _key: &'a str,
        _maximum: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async { Err("object store does not accept reads".into()) })
    }
    fn put_file<'a>(
        &'a self,
        _key: &'a str,
        _path: &'a std::path::Path,
        _size: u64,
        _content_type: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async { Err("object store does not accept file uploads".into()) })
    }
    fn put<'a>(
        &'a self,
        _key: &'a str,
        _bytes: &'a [u8],
        _content_type: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async { Err("object store does not accept writes".into()) })
    }
    fn remove<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
    /// Bounded-timeout removal used by Mark-and-Sweep Tx 2B (#550) so HTTP/TCP
    /// abort fires strictly before PG's `idle_in_transaction_session_timeout`.
    fn remove_with_timeout<'a>(
        &'a self,
        key: &'a str,
        _timeout: std::time::Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        self.remove(key)
    }
    /// Version-aware permanent deletion used by Mark-and-Sweep GC Tx 2B,
    /// staging cleanup, orphan cleanup, and legacy reap-retry drain (#551).
    ///
    /// On versioned/suspended buckets, deletes every concrete version and delete
    /// marker (stopping immediately on Object Lock 403). On unversioned buckets,
    /// uses `HEAD` ETag + `If-Match` when supported by the backend.
    fn delete_blob_checked<'a>(
        &'a self,
        key: &'a str,
        timeout: std::time::Duration,
    ) -> Pin<Box<dyn Future<Output = Result<BlobDeleteOutcome, String>> + Send + 'a>> {
        Box::pin(async move {
            match self.remove_with_timeout(key, timeout).await {
                Ok(()) => Ok(BlobDeleteOutcome::Deleted),
                Err(err) if is_strict_object_lock_error_msg(&err) => {
                    Ok(BlobDeleteOutcome::WormLocked403 {
                        detail: err,
                        retain_until: None,
                    })
                }
                Err(err) => Err(err),
            }
        })
    }
    /// Server-side copy from `from` staging key to canonical `to` key (#551).
    fn promote_object<'a>(
        &'a self,
        _from: &'a str,
        _to: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async { Err("object store does not support promote_object".into()) })
    }
    /// Checks whether `key` currently exists (`HEAD` 200 vs 404) (#551).
    fn object_exists<'a>(
        &'a self,
        _key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async { Ok(true) })
    }
    /// Lists `(key, last_modified_unix_secs)` under `prefix` for abandoned staging sweeps (#551).
    fn list_prefix_with_modified<'a>(
        &'a self,
        _prefix: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<(String, i64)>, String>> + Send + 'a>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    /// `PutObjectRetention` (WORM, #301/#549): mode `governance|compliance`, RFC 3339 `until`.
    fn retain_object<'a>(
        &'a self,
        _key: &'a str,
        _mode: &'a str,
        _until: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), RetentionError>> + Send + 'a>> {
        Box::pin(async {
            Err(RetentionError::Invalid(
                "object store does not accept retention".into(),
            ))
        })
    }
    /// `GetObjectRetention` (WORM, #549): inspect existing retention on `key`.
    fn object_retention<'a>(
        &'a self,
        _key: &'a str,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<ObjectRetentionInfo>, RetentionError>> + Send + 'a>,
    > {
        Box::pin(async {
            Err(RetentionError::Invalid(
                "object store does not support object_retention".into(),
            ))
        })
    }
}

pub struct RecoveryCleanup<S> {
    db: WorkerDatabase,
    store: Arc<S>,
}

impl<S: ObjectStore> RecoveryCleanup<S> {
    pub fn new(db: WorkerDatabase, store: Arc<S>) -> Self {
        Self { db, store }
    }

    /// Go runs immediately, then hourly, independently of the intake flag.
    /// Dropping the tick on shutdown cancels pending database and storage I/O.
    pub async fn run_until(self, stop: impl Future<Output = ()>) {
        let mut ticks = tokio::time::interval(std::time::Duration::from_secs(3600));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(stop);
        loop {
            tokio::select! {
                biased;
                _ = &mut stop => return,
                _ = ticks.tick() => {},
            }
            tokio::select! {
                biased;
                _ = &mut stop => return,
                result = self.tick() => {
                    if let Err(error) = result {
                        eprintln!("recovery upload cleanup failed: {error}");
                    }
                }
            }
        }
    }

    /// One bounded pass; failed deletes remain in PostgreSQL for the next pass.
    pub async fn tick(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for item in self.db.recovery_cleanup_batch().await? {
            if let Err(error) = self.store.remove(&item.key).await {
                eprintln!("recovery chunk cleanup deferred: {error}");
                continue;
            }
            if let Err(error) = self.db.acknowledge_recovery_chunk(&item).await {
                eprintln!("recovery chunk cleanup acknowledgement failed: {error}");
            }
        }
        Ok(())
    }
}

/// S3 quarantine store; bucket location is discovered just as in Go's MinIO client.
pub struct S3Store {
    bucket: Box<s3::Bucket>,
    endpoint: String,
    unsigned: Option<reqwest::Client>,
    no_redirect: reqwest::Client,
    request_timeout: Option<std::time::Duration>,
    region: tokio::sync::Mutex<Option<String>>,
    small_cache: std::sync::Mutex<SmallCache>,
    /// 0 = unprobed, 1 = backend enforces `If-Match` on `DELETE`, 2 = unsupported.
    conditional_delete_supported: std::sync::atomic::AtomicU8,
}

pub(crate) enum BlobReadError {
    /// Bucket discovery or object stat failed before consuming object data.
    Unavailable,
    /// A streamed or ranged read failed after headers (surfaces as a body error, as in Go).
    Incomplete,
}

pub(crate) enum BlobDownload {
    Buffered {
        bytes: Vec<u8>,
        content_type: String,
        cached: bool,
    },
    Streaming {
        size: u64,
        content_type: String,
        modified: Option<String>,
    },
}

/// The storage client stream is Send; a mutex gives the HTTP Body its required
/// Sync boundary without a producer task or unbounded buffering. Dropping the
/// response drops the storage stream. Never emit beyond the stat'ed size.
struct BlobStream {
    stream: std::sync::Mutex<s3::request::DataStream>,
    remaining: u64,
}

impl hyper::body::Body for BlobStream {
    type Data = bytes::Bytes;
    type Error = crate::BoxError;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;
        let body = self.get_mut();
        if body.remaining == 0 {
            return Poll::Ready(None);
        }
        let stream = body.stream.get_mut().expect("stream polled exclusively");
        match stream.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(mut bytes))) => {
                bytes.truncate(usize::try_from(body.remaining).unwrap_or(usize::MAX));
                body.remaining -= bytes.len() as u64;
                Poll::Ready(Some(Ok(hyper::body::Frame::data(bytes))))
            }
            Poll::Ready(result) => {
                body.remaining = 0;
                let error = match result {
                    Some(Err(error)) => std::io::Error::other(error.to_string()),
                    _ => std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "object body ended early",
                    ),
                };
                Poll::Ready(Some(Err(error.into())))
            }
        }
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.remaining)
    }
    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }
}

#[derive(Default)]
struct SmallCache {
    bytes: usize,
    entries: std::collections::HashMap<String, SmallBlob>,
}
struct SmallBlob {
    bytes: Vec<u8>,
    content_type: String,
    expires: std::time::Instant,
}

#[derive(Default, serde::Deserialize)]
#[serde(default)]
struct LocationReply {
    #[serde(rename = "$text", default)]
    region: String,
}

#[derive(Default, serde::Deserialize)]
struct LocationError {
    #[serde(rename = "Code", default)]
    code: String,
    #[serde(rename = "Region", default)]
    region: String,
}

impl S3Store {
    /// Match an explicitly configured MinIO region without a location probe.
    /// With no explicit region the existing lazy discovery remains authoritative.
    pub fn with_region(mut self, region: String) -> Self {
        *self.region.get_mut() = Some(region);
        self
    }
    /// Override the per-request HTTP timeout on no-redirect requests (tests).
    pub fn with_request_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.request_timeout = Some(timeout);
        self
    }
    /// Stream `key` from S3 and compute its SHA-256 hex digest and byte length
    /// without buffering the object body, aborting immediately if it exceeds `max_bytes`.
    pub async fn digest_object(&self, key: &str, max_bytes: u64) -> Result<(u64, String), String> {
        use futures_util::StreamExt;
        use sha2::{Digest, Sha256};
        if key.is_empty() {
            return Err("recovery object unavailable".into());
        }
        let bucket = self.bucket().await?;
        let mut response = bucket
            .get_object_stream(key)
            .await
            .map_err(|error| error.to_string())?;
        if response.status_code != 200 {
            return Err(format!("S3 get returned HTTP {}", response.status_code));
        }
        let mut total = 0u64;
        let mut hasher = Sha256::new();
        while let Some(chunk) = response.bytes.next().await {
            let chunk = chunk.map_err(|error| error.to_string())?;
            total = total
                .checked_add(chunk.len() as u64)
                .filter(|n| *n <= max_bytes)
                .ok_or_else(|| "recovery object exceeds limit".to_owned())?;
            hasher.update(&chunk);
        }
        let digest = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        Ok((total, digest))
    }

    /// Frozen outbound GetObject + ReadAll. A missing object's XML Message is
    /// retained in the queue error, rather than replaced by an HTTP status.
    pub(crate) async fn smtp_raw(&self, key: &str) -> Result<Vec<u8>, String> {
        let bucket = self.bucket().await?;
        let response = bucket.get_object(key).await.map_err(|e| e.to_string())?;
        let status = response.status_code();
        if status != 200 {
            #[derive(serde::Deserialize)]
            struct ErrorBody {
                #[serde(rename = "Message")]
                message: String,
            }
            let message = quick_xml::de::from_reader::<_, ErrorBody>(response.as_slice())
                .ok()
                .map(|e| e.message)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("S3 get returned HTTP {status}"));
            return Err(message);
        }
        let headers = response.headers();
        let modified = headers
            .get("last-modified")
            .or_else(|| headers.get("Last-Modified"))
            .map(String::as_str)
            .unwrap_or_default();
        let valid = [
            "%a, %-d %b %Y %H:%M:%S GMT",
            "%a, %e %b %Y %H:%M:%S GMT",
            "%a, %e %b %y %H:%M:%S GMT",
        ]
        .iter()
        .any(|format| chrono::NaiveDateTime::parse_from_str(modified, format).is_ok());
        if !valid {
            return Err(format!("Last-Modified time format is invalid, failed with unable to parse {modified} in any of the input formats: [Mon, 2 Jan 2006 15:04:05 GMT Mon, _2 Jan 2006 15:04:05 GMT Mon, _2 Jan 06 15:04:05 GMT]"));
        }
        Ok(response.to_vec())
    }
    /// Cached unfurl assets use a fresh object GET, never the mail download
    /// cache or ServeContent/range behavior. Go's fetch path bounds images.
    pub(crate) async fn unfurl_image(&self, key: &str) -> Result<Vec<u8>, String> {
        let bucket = self.bucket().await?;
        use futures_util::StreamExt;
        let mut response = bucket
            .get_object_stream(key)
            .await
            .map_err(|e| e.to_string())?;
        if response.status_code != 200 {
            return Err("unfurl object unavailable".into());
        }
        let mut copied = Vec::new();
        while let Some(chunk) = response.bytes.next().await {
            match chunk {
                Ok(bytes) => copied.extend_from_slice(&bytes),
                Err(_) => break,
            }
        }
        // Go ignores io.Copy's error after forwarding its successfully read prefix.
        Ok(copied)
    }

    pub fn new(endpoint: &str, bucket: &str, access: &str, secret: &str) -> Result<Self, String> {
        if endpoint.is_empty() || bucket.is_empty() {
            return Err("object storage endpoint and bucket are required".into());
        }
        // The frozen Go storage resolver permits plaintext only on loopback.
        let uri: hyper::Uri = endpoint
            .parse()
            .map_err(|_| "invalid object storage endpoint")?;
        let host = uri.host().ok_or("object storage endpoint has no host")?;
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        if uri.authority().is_none_or(|a| a.as_str().contains('@'))
            || uri.query().is_some()
            || !matches!(uri.path(), "" | "/")
            || !matches!(uri.scheme_str(), Some("https") | Some("http"))
            || (uri.scheme_str() == Some("http") && !loopback)
        {
            return Err("invalid or insecure object storage endpoint".into());
        }
        let anonymous = access.is_empty() || secret.is_empty();
        let creds = if anonymous {
            s3::creds::Credentials::anonymous()
        } else {
            s3::creds::Credentials::new(Some(access), Some(secret), None, None, None)
        }
        .map_err(|error| error.to_string())?;
        let unsigned = if anonymous {
            Some(
                reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .map_err(|error| error.to_string())?,
            )
        } else {
            None
        };
        let no_redirect = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| error.to_string())?;
        let region = s3::Region::Custom {
            region: "us-east-1".into(),
            endpoint: endpoint.into(),
        };
        let bucket = s3::Bucket::new(bucket, region, creds)
            .map_err(|e| e.to_string())?
            .with_path_style();
        Ok(Self {
            bucket,
            endpoint: endpoint.into(),
            unsigned,
            no_redirect,
            request_timeout: None,
            region: tokio::sync::Mutex::new(s3_region_from_url(endpoint)),
            small_cache: std::sync::Mutex::new(SmallCache::default()),
            conditional_delete_supported: std::sync::atomic::AtomicU8::new(0),
        })
    }

    /// Go buffers small non-ranged cache misses; other objects retain stat
    /// metadata for streaming, while cache hits retain ServeContent semantics.
    pub(crate) async fn download(
        &self,
        key: &str,
        buffer: bool,
    ) -> Result<BlobDownload, BlobReadError> {
        use futures_util::StreamExt;
        {
            let cache = self
                .small_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(blob) = cache
                .entries
                .get(key)
                .filter(|blob| std::time::Instant::now() < blob.expires)
            {
                return Ok(BlobDownload::Buffered {
                    bytes: blob.bytes.clone(),
                    content_type: blob.content_type.clone(),
                    cached: true,
                });
            }
        }
        let bucket = self
            .bucket()
            .await
            .map_err(|_| BlobReadError::Unavailable)?;
        let (head, status) = bucket
            .head_object(key)
            .await
            .map_err(|_| BlobReadError::Unavailable)?;
        if status != 200 {
            return Err(BlobReadError::Unavailable);
        }
        let size = head
            .content_length
            .filter(|size| *size >= 0)
            .ok_or(BlobReadError::Unavailable)?;
        let content_type = head.content_type.unwrap_or_default();
        let modified = head.last_modified;
        if !buffer || size == 0 || size >= 10 << 20 {
            return Ok(BlobDownload::Streaming {
                size: size as u64,
                content_type,
                modified,
            });
        }
        // Go's first S3 call is minio-go's lazy GET (`obj.Stat()`): a failed or non-200
        // GET is Go's `blob not found` (handler.go:574-583).
        let Ok(mut response) = bucket.get_object_stream(key).await else {
            return Err(BlobReadError::Unavailable);
        };
        if response.status_code != 200 {
            return Err(BlobReadError::Unavailable);
        }
        // Go's io.ReadFull fills exactly `size` bytes; a short or failed body falls
        // through to http.ServeContent, which streams the object again (writeBlobContent).
        let mut bytes = Vec::with_capacity(size as usize);
        while bytes.len() < size as usize {
            match response.bytes.next().await {
                Some(Ok(chunk)) => {
                    let take = chunk.len().min(size as usize - bytes.len());
                    bytes.extend_from_slice(&chunk[..take]);
                }
                Some(Err(_)) | None => {
                    return Ok(BlobDownload::Streaming {
                        size: size as u64,
                        content_type,
                        modified,
                    });
                }
            }
        }
        {
            let mut cache = self
                .small_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while cache.bytes + bytes.len() > 512 << 20 && !cache.entries.is_empty() {
                let oldest = cache
                    .entries
                    .iter()
                    .min_by_key(|(_, blob)| blob.expires)
                    .map(|(key, _)| key.clone())
                    .unwrap();
                let removed = cache.entries.remove(&oldest).unwrap();
                cache.bytes -= removed.bytes.len();
            }
            cache.entries.insert(
                key.into(),
                SmallBlob {
                    bytes: bytes.clone(),
                    content_type: content_type.clone(),
                    expires: std::time::Instant::now() + std::time::Duration::from_secs(600),
                },
            );
            // Match Go's accounting even when an expired entry is overwritten.
            cache.bytes += bytes.len();
        }
        Ok(BlobDownload::Buffered {
            bytes,
            content_type,
            cached: false,
        })
    }

    pub(crate) async fn stream_blob(
        &self,
        key: &str,
        size: u64,
        range: Option<(u64, u64)>,
    ) -> Result<crate::Body, BlobReadError> {
        use http_body_util::BodyExt;
        let mut bucket = self
            .bucket()
            .await
            .map_err(|_| BlobReadError::Unavailable)?;
        if let Some((start, end)) = range {
            bucket.extra_headers.insert(
                "range",
                format!("bytes={start}-{end}")
                    .parse()
                    .map_err(|_| BlobReadError::Incomplete)?,
            );
        }
        let response = bucket
            .get_object_stream(key)
            .await
            .map_err(|_| BlobReadError::Incomplete)?;
        if response.status_code != if range.is_some() { 206 } else { 200 } {
            return Err(BlobReadError::Incomplete);
        }
        Ok(BlobStream {
            stream: std::sync::Mutex::new(response.bytes),
            remaining: size,
        }
        .boxed())
    }

    /// Frozen Drive's unknown-length staging uses one multipart part within
    /// its 4 MiB cap. Temporary cleanup remains with the request's owner.
    pub async fn stage_drive_chunk<F>(&self, key: &str, read: F) -> Result<Vec<u8>, u16>
    where
        F: std::future::Future<Output = Result<Vec<u8>, u16>>,
    {
        use s3::{
            command::{Command, Multipart},
            request::{tokio_backend::ReqwestRequest, Request},
            serde_types::Part,
        };
        let bucket = self.bucket().await.map_err(|_| 500u16)?;
        let upload = bucket
            .initiate_multipart_upload(key, "application/octet-stream")
            .await
            .map_err(|_| 500u16)?;
        let id = upload.upload_id;
        let result = async {
            let bytes = read.await?;
            let request = ReqwestRequest::new(
                &bucket,
                key,
                Command::PutObject {
                    content: &bytes,
                    multipart: Some(Multipart::new(1, &id)),
                    custom_headers: None,
                    content_type: "",
                },
            )
            .await
            .map_err(|_| 500u16)?;
            let part = request.response_data(true).await.map_err(|_| 500u16)?;
            if part.status_code() != 200 {
                return Err(500u16);
            }
            let etag = part
                .as_str()
                .map_err(|_| 500u16)?
                .trim_matches('"')
                .to_owned();
            let result = bucket
                .complete_multipart_upload(
                    key,
                    &id,
                    vec![Part {
                        part_number: 1,
                        etag,
                    }],
                )
                .await
                .map_err(|_| 500u16)?;
            if result.status_code() != 200 {
                return Err(500u16);
            }
            Ok(bytes)
        }
        .await;
        if result.is_err() {
            let _ = bucket.abort_upload(key, &id).await;
        }
        result
    }

    /// Drive's synchronous best-effort GXP retention after metadata commit.
    pub(crate) async fn retain(&self, key: &str, mode: &str, until: &str) -> Result<(), String> {
        match self.retain_attempt(key, mode, until).await? {
            200..=299 => Ok(()),
            _ => Err("object retention failed".into()),
        }
    }

    /// Typed `PutObjectRetention` with minio-go retry policy for transient statuses (#301/#549).
    pub(crate) async fn retain_with_retries(
        &self,
        key: &str,
        mode: &str,
        until: &str,
    ) -> Result<(), RetentionError> {
        const RETRYABLE: [u16; 8] = [408, 429, 499, 500, 502, 503, 504, 520];
        let mut last = RetentionError::Transient(0, "object retention failed".into());
        for attempt in 0..10u32 {
            if attempt > 0 {
                let wait = (200u64 << (attempt - 1).min(3)).min(1000);
                tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
            }
            match self.retain_attempt(key, mode, until).await {
                Ok(200..=299) => return Ok(()),
                Ok(404) => return Err(RetentionError::NotFound),
                Ok(403) => {
                    return Err(RetentionError::Forbidden(
                        "object retention failed (403)".into(),
                    ))
                }
                Ok(status) if RETRYABLE.contains(&status) => {
                    last = RetentionError::Transient(
                        status,
                        format!("object retention failed ({status})"),
                    );
                }
                Ok(status) => {
                    return Err(RetentionError::Invalid(format!(
                        "object retention failed ({status})"
                    )));
                }
                Err(e) => {
                    if e == "invalid retention mode" {
                        return Err(RetentionError::Invalid(e));
                    }
                    last = RetentionError::Transient(0, e);
                }
            }
        }
        Err(last)
    }

    /// `GetObjectRetention` (`GET ?retention=`): inspects existing S3 Object Lock
    /// retention so 403 replies on already-retained objects can be classified cleanly.
    pub(crate) async fn get_object_retention(
        &self,
        key: &str,
    ) -> Result<Option<ObjectRetentionInfo>, RetentionError> {
        use s3::{
            command::Command,
            request::{tokio_backend::ReqwestRequest, Request},
        };
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct RetentionReply {
            mode: String,
            retain_until_date: String,
        }
        let mut bucket = self
            .bucket()
            .await
            .map_err(|e| RetentionError::Transient(0, e))?;
        bucket.add_query("retention", "");
        let response = ReqwestRequest::new(&bucket, key, Command::GetObject)
            .await
            .map_err(|e| RetentionError::Transient(0, e.to_string()))?
            .response_data(false)
            .await;
        match response {
            Ok(resp) => {
                let status = resp.status_code();
                if status == 200 {
                    let parsed: RetentionReply = quick_xml::de::from_reader(resp.as_slice())
                        .map_err(|e| {
                            RetentionError::Invalid(format!("parse GetObjectRetention XML: {e}"))
                        })?;
                    return Ok(Some(ObjectRetentionInfo {
                        mode: parsed.mode.to_ascii_lowercase(),
                        retain_until: parsed.retain_until_date,
                    }));
                }
                if status == 404 {
                    let body = String::from_utf8_lossy(resp.as_slice());
                    if body.contains("NoSuchObjectLockConfiguration")
                        || body.contains("InvalidRequest")
                    {
                        return Ok(None);
                    }
                    return Err(RetentionError::NotFound);
                }
                if status == 403 {
                    return Err(RetentionError::Forbidden(
                        "GetObjectRetention returned 403".into(),
                    ));
                }
                Err(RetentionError::Transient(
                    status,
                    format!("GetObjectRetention returned HTTP {status}"),
                ))
            }
            Err(s3::error::S3Error::HttpFailWithBody(404, body)) => {
                if body.contains("NoSuchObjectLockConfiguration") || body.contains("InvalidRequest")
                {
                    Ok(None)
                } else {
                    Err(RetentionError::NotFound)
                }
            }
            Err(s3::error::S3Error::HttpFailWithBody(403, body)) => {
                Err(RetentionError::Forbidden(body))
            }
            Err(s3::error::S3Error::HttpFailWithBody(status, body)) => {
                Err(RetentionError::Transient(status, body))
            }
            Err(e) => Err(RetentionError::Transient(0, e.to_string())),
        }
    }

    /// One `PUT ?retention` request; the status of any HTTP answer.
    async fn retain_attempt(&self, key: &str, mode: &str, until: &str) -> Result<u16, String> {
        use s3::{
            command::Command,
            request::{tokio_backend::ReqwestRequest, Request},
        };
        let mut bucket = self.bucket().await?;
        bucket.add_query("retention", "");
        let mode = match mode {
            "governance" => "GOVERNANCE",
            "compliance" => "COMPLIANCE",
            _ => return Err("invalid retention mode".into()),
        };
        let xml=format!("<Retention xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Mode>{mode}</Mode><RetainUntilDate>{until}</RetainUntilDate></Retention>");
        let response = ReqwestRequest::new(
            &bucket,
            key,
            Command::PutObject {
                content: xml.as_bytes(),
                content_type: "application/xml",
                custom_headers: None,
                multipart: None,
            },
        )
        .await
        .map_err(|e| e.to_string())?
        .response_data(false)
        .await;
        match response {
            Ok(response) => Ok(response.status_code()),
            Err(s3::error::S3Error::HttpFailWithBody(status, _)) => Ok(status),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Sets (`on = true`, `"ON"`) or clears (`on = false`, `"OFF"`) an S3 Object Lock legal
    /// hold (`PUT ?legal-hold`) with minio-go's retry policy (#289).
    pub(crate) async fn legal_hold_with_retries(&self, key: &str, on: bool) -> Result<(), String> {
        const RETRYABLE: [u16; 8] = [408, 429, 499, 500, 502, 503, 504, 520];
        let mut last = String::from("object legal hold failed");
        for attempt in 0..10u32 {
            if attempt > 0 {
                let wait = (200u64 << (attempt - 1).min(3)).min(1000);
                tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
            }
            match self.legal_hold_attempt(key, on).await {
                Ok(reply) if matches!(reply.status, 200 | 204) => return Ok(()),
                Ok(reply) => {
                    let reported_region = reply.region.as_deref().map(normalize_s3_region);
                    let changed_region = reported_region
                        .as_ref()
                        .is_some_and(|r| r.as_str() != reply.signed_region.as_str());
                    let is_region_error = changed_region
                        && (matches!(reply.status, 301 | 307)
                            || matches!(
                                reply.code.as_deref(),
                                Some(
                                    "AccessDenied"
                                        | "InvalidRegion"
                                        | "AuthorizationHeaderMalformed"
                                        | "PermanentRedirect"
                                        | "TemporaryRedirect"
                                )
                            ));
                    if is_region_error {
                        *self.region.lock().await = reported_region;
                        last = format!("object legal hold failed ({})", reply.status);
                    } else if RETRYABLE.contains(&reply.status)
                        || reply.code.as_deref().is_some_and(is_retryable_s3_code)
                    {
                        last = format!("object legal hold failed ({})", reply.status);
                    } else {
                        return Err(format!("object legal hold failed ({})", reply.status));
                    }
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// One `PUT ?legal-hold` request; returns status, signed region, S3 error code, and reported region.
    async fn legal_hold_attempt(&self, key: &str, on: bool) -> Result<LegalHoldReply, String> {
        use s3::{
            command::Command,
            request::{tokio_backend::ReqwestRequest, Request},
        };
        let mut bucket = self.bucket().await?;
        let signed_region = match &bucket.region {
            s3::Region::Custom { region, .. } => region.clone(),
            other => normalize_s3_region(&other.to_string()),
        };
        bucket.add_query("legal-hold", "");
        let (xml, md5) = if on {
            (
                "<LegalHold><Status>ON</Status></LegalHold>",
                "oK1+ndJbG6HuGA87LDxznw==",
            )
        } else {
            (
                "<LegalHold><Status>OFF</Status></LegalHold>",
                "An8G3mv4SfhAibzslQjGDw==",
            )
        };
        bucket
            .extra_headers
            .insert("content-md5", md5.parse().unwrap());
        let request = ReqwestRequest::new(
            &bucket,
            key,
            Command::PutObject {
                content: xml.as_bytes(),
                content_type: "application/xml",
                custom_headers: None,
                multipart: None,
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        let url = request.url().map_err(|e| e.to_string())?;
        let signed = request.headers().await.map_err(|e| e.to_string())?;
        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value) in &signed {
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
                reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
            ) {
                headers.append(name, value);
            }
        }
        let mut builder = self
            .no_redirect
            .put(url.as_str())
            .headers(headers)
            .body(xml.as_bytes().to_vec());
        if let Some(timeout) = self.request_timeout.or_else(|| bucket.request_timeout()) {
            builder = builder.timeout(timeout);
        }
        let mut response = builder.send().await.map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        if matches!(status, 200 | 204) {
            return Ok(LegalHoldReply {
                status,
                signed_region,
                code: None,
                region: None,
            });
        }
        let header_str = |name: &str| -> Option<String> {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
        };
        let header_code = header_str("x-minio-error-code");
        let header_region = header_str("x-amz-bucket-region");
        const MAX_ERROR_BODY: usize = 5 * 1024 * 1024;
        let mut body_bytes = Vec::new();
        while body_bytes.len() < MAX_ERROR_BODY {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    let take = chunk.len().min(MAX_ERROR_BODY - body_bytes.len());
                    body_bytes.extend_from_slice(&chunk[..take]);
                }
                Ok(None) | Err(_) => break,
            }
        }
        let body = String::from_utf8_lossy(&body_bytes);
        let parsed_xml = quick_xml::de::from_str::<LocationError>(&body).ok();
        let xml_code = parsed_xml
            .as_ref()
            .map(|e| e.code.trim())
            .filter(|v| !v.is_empty())
            .map(str::to_owned);
        let xml_region = parsed_xml
            .as_ref()
            .map(|e| e.region.trim())
            .filter(|v| !v.is_empty())
            .map(str::to_owned);
        Ok(LegalHoldReply {
            status,
            signed_region,
            code: header_code.or(xml_code).or_else(|| match status {
                403 => Some("AccessDenied".to_owned()),
                301 => Some("PermanentRedirect".to_owned()),
                307 => Some("TemporaryRedirect".to_owned()),
                _ => None,
            }),
            region: xml_region.or(header_region),
        })
    }

    /// Same environment names and defaults as Go's primary object store.
    pub fn blob_reference(&self, hash: &str) -> String {
        format!("{}/{hash}", self.bucket.name())
    }

    pub async fn promote(&self, from: &str, to: &str) -> Result<(), String> {
        let code = self
            .bucket()
            .await?
            .copy_object_internal(from, to)
            .await
            .map_err(|e| e.to_string())?;
        if code == 200 {
            Ok(())
        } else {
            Err(format!("S3 copy returned HTTP {code}"))
        }
    }

    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Resolve S3/MinIO settings matching Go's `config.go` precedence (`MINIO_ENDPOINT`
    /// overrides default `127.0.0.1:9000`, `MINIO_BUCKET` overrides default `mailblobs`,
    /// `MINIO_SECURE` overrides when non-empty).
    pub(crate) fn from_lookup<F>(lookup: F) -> Result<Self, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let get = |name: &str| lookup(name).filter(|s| !s.is_empty());
        let mut endpoint = lookup("S3_ENDPOINT").unwrap_or_else(|| "127.0.0.1:9000".into());
        if endpoint == "127.0.0.1:9000" {
            if let Some(v) = get("MINIO_ENDPOINT") {
                endpoint = v;
            }
        }
        let access = get("S3_ACCESS_KEY")
            .or_else(|| get("MINIO_ACCESS_KEY"))
            .unwrap_or_default();
        let secret = get("S3_SECRET_KEY")
            .or_else(|| get("MINIO_SECRET_KEY"))
            .unwrap_or_default();
        let mut bucket = lookup("S3_BUCKET").unwrap_or_else(|| "mailblobs".into());
        if bucket == "mailblobs" {
            if let Some(v) = get("MINIO_BUCKET") {
                bucket = v;
            }
        }
        let secure = if let Some(v) = get("MINIO_SECURE") {
            parse_go_bool(&v).ok_or_else(|| "MINIO_SECURE must be a boolean".to_owned())?
        } else if let Some(v) = get("S3_SECURE") {
            parse_go_bool(&v).unwrap_or(false)
        } else {
            false
        };
        let endpoint = endpoint.trim();
        let endpoint = if endpoint.contains("://") {
            let lower = endpoint.to_ascii_lowercase();
            if (lower.starts_with("https://") && !secure)
                || (lower.starts_with("http://") && secure)
            {
                return Err("S3_SECURE conflicts with S3_ENDPOINT".into());
            }
            endpoint.to_owned()
        } else {
            format!("{}://{endpoint}", if secure { "https" } else { "http" })
        };
        Self::new(&endpoint, &bucket, &access, &secret)
    }

    fn object_url(&self, key: &str) -> Result<reqwest::Url, String> {
        let mut url = reqwest::Url::parse(&self.endpoint).map_err(|error| error.to_string())?;
        {
            let mut parts = url
                .path_segments_mut()
                .map_err(|()| "storage endpoint has no path")?;
            parts.clear().push(&self.bucket.name());
            for part in key.split('/') {
                parts.push(part);
            }
        }
        Ok(url)
    }

    pub(crate) fn bucket_name(&self) -> String {
        self.bucket.name()
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) async fn bucket(&self) -> Result<s3::Bucket, String> {
        use s3::{
            command::Command,
            request::{tokio_backend::ReqwestRequest, Request},
        };
        let mut cached = self.region.lock().await;
        if cached.is_none() {
            let (status, body, headers) = if let Some(client) = &self.unsigned {
                let mut url = self.object_url("")?;
                url.query_pairs_mut().append_pair("location", "");
                let response = client
                    .get(url)
                    .send()
                    .await
                    .map_err(|error| error.to_string())?;
                let status = response.status().as_u16();
                let headers = response
                    .headers()
                    .iter()
                    .filter_map(|(name, value)| {
                        value
                            .to_str()
                            .ok()
                            .map(|value| (name.as_str().to_owned(), value.to_owned()))
                    })
                    .collect::<std::collections::HashMap<_, _>>();
                let body = String::from_utf8(
                    response
                        .bytes()
                        .await
                        .map_err(|error| error.to_string())?
                        .to_vec(),
                )
                .map_err(|error| error.to_string())?;
                (status, body, headers)
            } else {
                // rust-s3 percent-encodes the path; attach location as a query and reuse no_redirect.
                let mut location_bucket = (*self.bucket).clone();
                location_bucket.add_query("location", "");
                let request = ReqwestRequest::new(&location_bucket, "", Command::GetBucketLocation)
                    .await
                    .map_err(|error| error.to_string())?;
                let url = request.url().map_err(|error| error.to_string())?;
                let signed = request.headers().await.map_err(|error| error.to_string())?;
                let mut req_headers = reqwest::header::HeaderMap::new();
                for (name, value) in &signed {
                    if let (Ok(name), Ok(value)) = (
                        reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
                        reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
                    ) {
                        req_headers.append(name, value);
                    }
                }
                let mut builder = self.no_redirect.get(url.as_str()).headers(req_headers);
                if let Some(timeout) = self
                    .request_timeout
                    .or_else(|| location_bucket.request_timeout())
                {
                    builder = builder.timeout(timeout);
                }
                let response = builder.send().await.map_err(|error| error.to_string())?;
                let status = response.status().as_u16();
                let headers = response
                    .headers()
                    .iter()
                    .filter_map(|(name, value)| {
                        value
                            .to_str()
                            .ok()
                            .map(|value| (name.as_str().to_owned(), value.to_owned()))
                    })
                    .collect::<std::collections::HashMap<_, _>>();
                let body = String::from_utf8(
                    response
                        .bytes()
                        .await
                        .map_err(|error| error.to_string())?
                        .to_vec(),
                )
                .map_err(|error| error.to_string())?;
                (status, body, headers)
            };
            let region = if status == 200 {
                let parsed: LocationReply =
                    quick_xml::de::from_str(&body).map_err(|e| e.to_string())?;
                parsed.region
            } else {
                let mut parsed: LocationError = quick_xml::de::from_str(&body).unwrap_or_default();
                if let Some(code) = headers.get("x-minio-error-code").filter(|v| !v.is_empty()) {
                    parsed.code.clone_from(code);
                } else if parsed.code.is_empty() {
                    match status {
                        403 => parsed.code = "AccessDenied".into(),
                        301 => parsed.code = "PermanentRedirect".into(),
                        307 => parsed.code = "TemporaryRedirect".into(),
                        _ => {}
                    }
                }
                if parsed.region.is_empty() {
                    parsed.region = headers
                        .get("x-amz-bucket-region")
                        .cloned()
                        .unwrap_or_default();
                }
                match parsed.code.as_str() {
                    "AccessDenied"
                    | "AuthorizationHeaderMalformed"
                    | "InvalidRegion"
                    | "NoSuchBucket" => parsed.region,
                    "PermanentRedirect" | "TemporaryRedirect" => {
                        if parsed.region.is_empty() {
                            return Err(format!(
                                "S3 bucket location redirect ({status} {}) missing bucket region",
                                parsed.code
                            ));
                        }
                        parsed.region
                    }
                    "NotImplemented"
                        if headers.get("server").is_some_and(|s| s == "AmazonSnowball") =>
                    {
                        "snowball".into()
                    }
                    "NotImplemented"
                        if headers.get("server").is_some_and(|s| s == "cloudflare") =>
                    {
                        "us-east-1".into()
                    }
                    _ if status == 404 => String::new(),
                    _ => return Err(format!("S3 bucket location failed: {}", parsed.code)),
                }
            };
            *cached = Some(normalize_s3_region(&region));
        }
        let region = cached.as_ref().unwrap().clone();
        let endpoint = regional_s3_endpoint(&self.endpoint, &region);
        let mut bucket = (*self.bucket).clone();
        bucket.region = s3::Region::Custom { region, endpoint };
        Ok(bucket)
    }
}

impl ObjectStore for S3Store {
    fn read<'a>(
        &'a self,
        key: &'a str,
        maximum: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            use futures_util::StreamExt;
            let bucket = self.bucket().await?;
            let mut response = bucket
                .get_object_stream(key)
                .await
                .map_err(|error| error.to_string())?;
            if response.status_code != 200 {
                return Err(format!("S3 get returned HTTP {}", response.status_code));
            }
            let mut result = Vec::new();
            while let Some(bytes) = response.bytes.next().await {
                let bytes = bytes.map_err(|error| error.to_string())?;
                if result.len() + bytes.len() > maximum {
                    return Err("object exceeds read bound".into());
                }
                result.extend_from_slice(&bytes);
            }
            Ok(result)
        })
    }
    fn put_file<'a>(
        &'a self,
        key: &'a str,
        path: &'a std::path::Path,
        size: u64,
        content_type: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let bucket = self.bucket().await?;
            let mut file = tokio::fs::File::open(path)
                .await
                .map_err(|error| error.to_string())?;
            let result = bucket
                .put_object_stream_with_content_type(&mut file, key, content_type)
                .await
                .map_err(|error| error.to_string())?;
            if result.status_code() == 200 && result.uploaded_bytes() as u64 == size {
                Ok(())
            } else {
                Err("object upload was incomplete".into())
            }
        })
    }
    fn put<'a>(
        &'a self,
        key: &'a str,
        bytes: &'a [u8],
        content_type: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let bucket = self.bucket().await?;
            let response = bucket
                .put_object_with_content_type(key, bytes, content_type)
                .await
                .map_err(|error| error.to_string())?;
            if response.status_code() == 200 {
                Ok(())
            } else {
                Err(format!("S3 put returned HTTP {}", response.status_code()))
            }
        })
    }
    fn retain_object<'a>(
        &'a self,
        key: &'a str,
        mode: &'a str,
        until: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), RetentionError>> + Send + 'a>> {
        Box::pin(async move { self.retain_with_retries(key, mode, until).await })
    }
    fn object_retention<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<ObjectRetentionInfo>, RetentionError>> + Send + 'a>,
    > {
        Box::pin(async move { self.get_object_retention(key).await })
    }
    fn remove<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { self.remove_inner(key, None).await })
    }
    fn remove_with_timeout<'a>(
        &'a self,
        key: &'a str,
        timeout: std::time::Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { self.remove_inner(key, Some(timeout)).await })
    }
    fn delete_blob_checked<'a>(
        &'a self,
        key: &'a str,
        timeout: std::time::Duration,
    ) -> Pin<Box<dyn Future<Output = Result<BlobDeleteOutcome, String>> + Send + 'a>> {
        Box::pin(async move { self.delete_blob_checked_inner(key, timeout).await })
    }
    fn promote_object<'a>(
        &'a self,
        from: &'a str,
        to: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { self.promote(from, to).await })
    }
    fn object_exists<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move { self.stat_size(key).await.map(|s| s.is_some()) })
    }
    fn list_prefix_with_modified<'a>(
        &'a self,
        prefix: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<(String, i64)>, String>> + Send + 'a>> {
        Box::pin(async move {
            self.list_with_modified_including_versions(
                prefix,
                crate::blob_gc::DEFAULT_S3_HTTP_TIMEOUT,
            )
            .await
        })
    }
}

#[derive(Default, serde::Deserialize)]
#[serde(default)]
struct S3XmlError {
    #[serde(rename = "Code", default)]
    code: String,
    #[serde(rename = "Message", default)]
    message: String,
}

#[derive(Default, Debug, PartialEq, Eq)]
struct ParsedListVersions {
    is_list_versions_result: bool,
    is_truncated: bool,
    next_key_marker: String,
    next_version_id_marker: String,
    entries: Vec<ObjectVersionEntry>,
}

/// Streaming `quick_xml::Reader` parser for S3 `ListObjectVersions` XML (#551).
/// Handles arbitrarily interleaved `<Version>` and `<DeleteMarker>` elements
/// without `quick_xml::de`'s `overlapped-lists` limitation.
fn parse_list_versions_xml(xml: &str) -> Result<ParsedListVersions, String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Container {
        Root,
        Version,
        DeleteMarker,
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Field {
        None,
        IsTruncated,
        NextKeyMarker,
        NextVersionIdMarker,
        Key,
        VersionId,
        LastModified,
    }

    let mut reader = Reader::from_str(xml);
    let mut out = ParsedListVersions::default();
    let mut container = Container::Root;
    let mut field = Field::None;
    let mut cur_key = String::new();
    let mut cur_vid = String::new();
    let mut cur_mod = String::new();
    let mut root_seen = false;
    let mut saw_root_end = false;
    let mut depth = 0usize;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                depth += 1;
                let local = e.local_name();
                let name = local.as_ref();
                if !root_seen {
                    root_seen = true;
                    out.is_list_versions_result = name == b"ListVersionsResult";
                    if !out.is_list_versions_result {
                        return Ok(out);
                    }
                    continue;
                }
                match (container, depth, name) {
                    (Container::Root, 2, b"Version") => {
                        container = Container::Version;
                        cur_key.clear();
                        cur_vid.clear();
                        cur_mod.clear();
                        field = Field::None;
                    }
                    (Container::Root, 2, b"DeleteMarker") => {
                        container = Container::DeleteMarker;
                        cur_key.clear();
                        cur_vid.clear();
                        cur_mod.clear();
                        field = Field::None;
                    }
                    (Container::Root, 2, b"IsTruncated") => field = Field::IsTruncated,
                    (Container::Root, 2, b"NextKeyMarker") => field = Field::NextKeyMarker,
                    (Container::Root, 2, b"NextVersionIdMarker") => {
                        field = Field::NextVersionIdMarker
                    }
                    (Container::Version | Container::DeleteMarker, 3, b"Key") => field = Field::Key,
                    (Container::Version | Container::DeleteMarker, 3, b"VersionId") => {
                        field = Field::VersionId
                    }
                    (Container::Version | Container::DeleteMarker, 3, b"LastModified") => {
                        field = Field::LastModified
                    }
                    _ => field = Field::None,
                }
            }
            Ok(Event::Empty(e)) => {
                if !root_seen {
                    out.is_list_versions_result = e.local_name().as_ref() == b"ListVersionsResult";
                    return Ok(out);
                }
            }
            Ok(Event::Text(e)) => {
                let text = e
                    .xml10_content()
                    .map_err(|err| format!("decode ListObjectVersions XML text: {err}"))?;
                match field {
                    Field::IsTruncated => {
                        if text.trim().eq_ignore_ascii_case("true") {
                            out.is_truncated = true;
                        }
                    }
                    Field::NextKeyMarker => out.next_key_marker.push_str(&text),
                    Field::NextVersionIdMarker => out.next_version_id_marker.push_str(&text),
                    Field::Key => cur_key.push_str(&text),
                    Field::VersionId => cur_vid.push_str(&text),
                    Field::LastModified => cur_mod.push_str(&text),
                    Field::None => {}
                }
            }
            Ok(Event::GeneralRef(e)) => {
                let resolved = if let Some(ch) = e
                    .resolve_char_ref()
                    .map_err(|err| format!("resolve XML char ref: {err}"))?
                {
                    ch.to_string()
                } else {
                    let name = e
                        .xml10_content()
                        .map_err(|err| format!("decode XML entity ref: {err}"))?;
                    quick_xml::escape::resolve_xml_entity(&name)
                        .map(str::to_owned)
                        .unwrap_or_else(|| format!("&{name};"))
                };
                match field {
                    Field::NextKeyMarker => out.next_key_marker.push_str(&resolved),
                    Field::NextVersionIdMarker => out.next_version_id_marker.push_str(&resolved),
                    Field::Key => cur_key.push_str(&resolved),
                    Field::VersionId => cur_vid.push_str(&resolved),
                    Field::LastModified => cur_mod.push_str(&resolved),
                    Field::IsTruncated | Field::None => {}
                }
            }
            Ok(Event::CData(e)) => {
                let text = String::from_utf8_lossy(e.as_ref());
                match field {
                    Field::IsTruncated => {
                        if text.trim().eq_ignore_ascii_case("true") {
                            out.is_truncated = true;
                        }
                    }
                    Field::NextKeyMarker => out.next_key_marker.push_str(&text),
                    Field::NextVersionIdMarker => out.next_version_id_marker.push_str(&text),
                    Field::Key => cur_key.push_str(&text),
                    Field::VersionId => cur_vid.push_str(&text),
                    Field::LastModified => cur_mod.push_str(&text),
                    Field::None => {}
                }
            }
            Ok(Event::End(e)) => {
                let local = e.local_name();
                let name = local.as_ref();
                if depth == 2
                    && matches!(
                        (container, name),
                        (Container::Version, b"Version")
                            | (Container::DeleteMarker, b"DeleteMarker")
                    )
                {
                    let last_modified_unix = chrono::DateTime::parse_from_rfc3339(cur_mod.trim())
                        .map(|t| t.timestamp())
                        .unwrap_or(0);
                    out.entries.push(ObjectVersionEntry {
                        key: std::mem::take(&mut cur_key),
                        version_id: std::mem::take(&mut cur_vid),
                        is_delete_marker: container == Container::DeleteMarker,
                        last_modified_unix,
                    });
                    cur_mod.clear();
                    container = Container::Root;
                }
                if depth == 1 && name == b"ListVersionsResult" {
                    saw_root_end = true;
                }
                field = Field::None;
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Eof) => break,
            Err(err) => return Err(format!("parse ListObjectVersions XML: {err}")),
            _ => {}
        }
    }
    if out.is_list_versions_result && !saw_root_end {
        return Err("truncated ListVersionsResult XML".into());
    }
    Ok(out)
}

/// Parses an RFC 3339 `RetainUntilDate` and returns `Some(raw)` ONLY when the
/// timestamp is strictly in the future (`> Utc::now()`). An expired retention
/// record is NOT active Object Lock protection.
fn parse_unexpired_retain_until(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let parsed = chrono::DateTime::parse_from_rfc3339(trimmed)
        .ok()?
        .with_timezone(&chrono::Utc);
    if parsed > chrono::Utc::now() {
        Some(trimmed.to_owned())
    } else {
        None
    }
}

/// Strict error-code / message classifier for Object Lock 403 strings (fallback
/// for trait mocks that only return `Err(String)` via `remove_with_timeout`).
pub fn is_strict_object_lock_error_msg(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("object lock")
        || lower.contains("objectlock")
        || lower.contains("retainuntil")
        || lower.contains("worm")
        || lower.contains("immutable")
        || (lower.contains("accessdenied") && lower.contains("retain"))
}

fn is_object_lock_xml_error(code: &str, message: &str) -> bool {
    let lc = code.to_ascii_lowercase();
    let lm = message.to_ascii_lowercase();
    lc.contains("objectlock")
        || lm.contains("object lock")
        || lm.contains("objectlock")
        || lm.contains("retainuntil")
        || lm.contains("retention")
        || lm.contains("worm")
        || lm.contains("immutable")
        || lm.contains("legal hold")
}

fn is_non_worm_auth_403_code(code: &str) -> bool {
    matches!(
        code,
        "InvalidAccessKeyId"
            | "SignatureDoesNotMatch"
            | "ExpiredToken"
            | "ExpiredTokenException"
            | "AccountProblem"
            | "AllAccessDisabled"
            | "InvalidToken"
            | "RequestTimeTooSkewed"
    )
}

impl S3Store {
    async fn send_signed_or_unsigned(
        &self,
        method: reqwest::Method,
        key: &str,
        query: &[(&str, &str)],
        extra_headers: &[(&str, &str)],
        timeout: std::time::Duration,
    ) -> Result<(u16, reqwest::header::HeaderMap, Vec<u8>), String> {
        use s3::{
            command::Command,
            request::{tokio_backend::ReqwestRequest, Request},
        };
        if let Some(client) = &self.unsigned {
            let _ = self.bucket().await?;
            let mut url = self.object_url(key)?;
            if !query.is_empty() {
                let mut pairs = url.query_pairs_mut();
                for (k, v) in query {
                    pairs.append_pair(k, v);
                }
            }
            let mut req = client.request(method, url).timeout(timeout);
            for (k, v) in extra_headers {
                req = req.header(*k, *v);
            }
            let resp = req.send().await.map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            let body = resp.bytes().await.map_err(|e| e.to_string())?.to_vec();
            return Ok((status, headers, body));
        }

        let mut bucket = self.bucket().await?;
        for (k, v) in query {
            bucket.add_query(k, v);
        }
        for (k, v) in extra_headers {
            if let (Ok(name), Ok(val)) = (
                hyper::header::HeaderName::from_bytes(k.as_bytes()),
                hyper::header::HeaderValue::from_str(v),
            ) {
                bucket.extra_headers.insert(name, val);
            }
        }
        let cmd = match method {
            reqwest::Method::GET => Command::GetObject,
            reqwest::Method::DELETE => Command::DeleteObject,
            reqwest::Method::HEAD => Command::HeadObject,
            _ => return Err(format!("unsupported S3 HTTP method {method}")),
        };
        let signed_req = ReqwestRequest::new(&bucket, key, cmd)
            .await
            .map_err(|e| e.to_string())?;
        let url = signed_req.url().map_err(|e| e.to_string())?;
        let signed_headers = signed_req.headers().await.map_err(|e| e.to_string())?;
        let mut req_headers = reqwest::header::HeaderMap::new();
        for (name, value) in &signed_headers {
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
                reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
            ) {
                req_headers.append(name, value);
            }
        }
        let resp = self
            .no_redirect
            .request(method, url.as_str())
            .headers(req_headers)
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = resp.bytes().await.map_err(|e| e.to_string())?.to_vec();
        Ok((status, headers, body))
    }

    async fn list_object_versions_raw(
        &self,
        prefix: &str,
        exact_key: Option<&str>,
        timeout: std::time::Duration,
    ) -> Result<VersionListing, String> {
        let mut entries = Vec::new();
        let mut key_marker: Option<String> = None;
        let mut version_id_marker: Option<String> = None;

        for _page in 0..256u32 {
            let mut query: Vec<(&str, &str)> = vec![("versions", ""), ("prefix", prefix)];
            if let Some(km) = key_marker.as_deref() {
                if !km.is_empty() {
                    query.push(("key-marker", km));
                }
            }
            if let Some(vm) = version_id_marker.as_deref() {
                if !vm.is_empty() {
                    query.push(("version-id-marker", vm));
                }
            }
            let (status, _headers, body) = self
                .send_signed_or_unsigned(reqwest::Method::GET, "", &query, &[], timeout)
                .await?;
            if status == 404 || status == 501 {
                return Ok(VersionListing::Unversioned);
            }
            let body_str = String::from_utf8_lossy(&body);
            if status != 200 {
                let err: S3XmlError = quick_xml::de::from_str(&body_str).unwrap_or_default();
                if matches!(
                    err.code.as_str(),
                    "NotImplemented" | "InvalidRequest" | "NoSuchVersion"
                ) {
                    return Ok(VersionListing::Unversioned);
                }
                return Err(format!(
                    "S3 ListObjectVersions returned HTTP {status} ({} {})",
                    err.code, err.message
                ));
            }
            let parsed = parse_list_versions_xml(&body_str)?;
            // Unversioned S3 gateways that ignore `?versions` return `<ListBucketResult>`
            // instead of `<ListVersionsResult>`. Treat anything other than a genuine
            // ListVersionsResult as unversioned so we never mistake 0 parsed versions for
            // an already-absent object and skip deleting it.
            if !parsed.is_list_versions_result {
                return Ok(VersionListing::Unversioned);
            }
            for entry in parsed.entries {
                if exact_key.is_none_or(|k| entry.key == k) {
                    entries.push(entry);
                }
            }
            if !parsed.is_truncated {
                // AWS S3 unversioned buckets return a single `<Version>` with
                // `VersionId == "null"` (no real non-"null" versions and no delete
                // markers). Take the unversioned path on exact-key deletes so
                // `probe_unversioned_conditional_delete` and `If-Match` are exercised!
                // (If a suspended-versioning bucket creates a delete marker on bare
                // DELETE, `DeleteMarkerCreated` re-lists and sees the delete marker.)
                if exact_key.is_some()
                    && !entries.is_empty()
                    && entries.iter().all(|e| {
                        !e.is_delete_marker && (e.version_id.is_empty() || e.version_id == "null")
                    })
                {
                    return Ok(VersionListing::Unversioned);
                }
                return Ok(VersionListing::Versioned(entries));
            }
            if parsed.next_key_marker.is_empty() && parsed.next_version_id_marker.is_empty() {
                return Err("S3 ListObjectVersions truncated without next markers".into());
            }
            key_marker = Some(parsed.next_key_marker);
            version_id_marker = Some(parsed.next_version_id_marker);
        }
        Err("S3 ListObjectVersions exceeded 256 page safety bound".into())
    }

    /// Paginated `GET /<bucket>?versions&prefix=<key>` returning ALL exact-key
    /// concrete versions and delete markers (#551).
    pub async fn list_object_versions_exact(
        &self,
        key: &str,
        timeout: std::time::Duration,
    ) -> Result<VersionListing, String> {
        self.list_object_versions_raw(key, Some(key), timeout).await
    }

    /// Paginated `GET /<bucket>?versions&prefix=<prefix>` returning ALL concrete
    /// versions and delete markers under `prefix` (#551).
    pub async fn list_object_versions_prefix(
        &self,
        prefix: &str,
        timeout: std::time::Duration,
    ) -> Result<VersionListing, String> {
        self.list_object_versions_raw(prefix, None, timeout).await
    }

    /// Lists `(key, max_last_modified_unix)` under `prefix`, enumerating hidden
    /// versions and delete markers via `list_object_versions_prefix` when the
    /// backend supports versioning and falling back to `list_with_modified` on
    /// unversioned gateways (#551).
    pub async fn list_with_modified_including_versions(
        &self,
        prefix: &str,
        timeout: std::time::Duration,
    ) -> Result<Vec<(String, i64)>, String> {
        match self.list_object_versions_prefix(prefix, timeout).await? {
            VersionListing::Versioned(entries) => {
                let mut by_key: std::collections::BTreeMap<String, i64> =
                    std::collections::BTreeMap::new();
                for entry in entries {
                    by_key
                        .entry(entry.key)
                        .and_modify(|ts| {
                            if entry.last_modified_unix > *ts {
                                *ts = entry.last_modified_unix;
                            }
                        })
                        .or_insert(entry.last_modified_unix);
                }
                Ok(by_key.into_iter().collect())
            }
            VersionListing::Unversioned => self.list_with_modified(prefix).await,
        }
    }

    async fn get_object_retention_version(
        &self,
        key: &str,
        version_id: Option<&str>,
        timeout: std::time::Duration,
    ) -> Result<Option<ObjectRetentionInfo>, RetentionError> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct RetentionReply {
            mode: String,
            retain_until_date: String,
        }
        let mut query = vec![("retention", "")];
        if let Some(vid) = version_id.filter(|v| !v.is_empty()) {
            query.push(("versionId", vid));
        }
        let (status, _headers, body) = self
            .send_signed_or_unsigned(reqwest::Method::GET, key, &query, &[], timeout)
            .await
            .map_err(|e| RetentionError::Transient(0, e))?;
        let body_str = String::from_utf8_lossy(&body);
        match status {
            200 => {
                let parsed: RetentionReply = quick_xml::de::from_str(&body_str).map_err(|e| {
                    RetentionError::Invalid(format!("parse GetObjectRetention XML: {e}"))
                })?;
                Ok(Some(ObjectRetentionInfo {
                    mode: parsed.mode.to_ascii_lowercase(),
                    retain_until: parsed.retain_until_date,
                }))
            }
            404 => {
                if body_str.contains("NoSuchObjectLockConfiguration")
                    || body_str.contains("InvalidRequest")
                {
                    Ok(None)
                } else {
                    Err(RetentionError::NotFound)
                }
            }
            403 => Err(RetentionError::Forbidden(body_str.into_owned())),
            other => Err(RetentionError::Transient(
                other,
                format!("GetObjectRetention returned HTTP {other}"),
            )),
        }
    }

    /// Sends `DELETE /<bucket>/<key>` with optional `?versionId=<vid>` and
    /// optional `If-Match: <etag>`, inspecting status, `x-amz-delete-marker`,
    /// XML `<Code>`, and `GetObjectRetention` for accurate 403 classification (#551).
    pub async fn delete_object_version(
        &self,
        key: &str,
        version_id: Option<&str>,
        if_match: Option<&str>,
        timeout: std::time::Duration,
    ) -> Result<DeleteVersionOutcome, String> {
        let mut query: Vec<(&str, &str)> = Vec::new();
        if let Some(vid) = version_id.filter(|v| !v.is_empty()) {
            query.push(("versionId", vid));
        }
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(etag) = if_match.filter(|e| !e.is_empty()) {
            headers.push(("if-match", etag));
        }
        let (status, resp_headers, body) = self
            .send_signed_or_unsigned(reqwest::Method::DELETE, key, &query, &headers, timeout)
            .await?;
        match status {
            200..=299 => {
                let is_dm = resp_headers
                    .get("x-amz-delete-marker")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.eq_ignore_ascii_case("true"));
                if version_id.is_none() && is_dm {
                    Ok(DeleteVersionOutcome::DeleteMarkerCreated)
                } else {
                    Ok(DeleteVersionOutcome::Deleted)
                }
            }
            404 => Ok(DeleteVersionOutcome::Deleted),
            412 => Ok(DeleteVersionOutcome::PreconditionFailed),
            403 => {
                let body_str = String::from_utf8_lossy(&body);
                let parsed: S3XmlError = quick_xml::de::from_str(&body_str).unwrap_or_default();
                let detail = if parsed.code.is_empty() && parsed.message.is_empty() {
                    format!("S3 delete returned HTTP 403 ({body_str})")
                } else {
                    format!("HTTP 403 {}: {}", parsed.code, parsed.message)
                };
                if is_non_worm_auth_403_code(&parsed.code) {
                    return Ok(DeleteVersionOutcome::Error(detail));
                }
                if is_object_lock_xml_error(&parsed.code, &parsed.message) {
                    let observed_until = self
                        .get_object_retention_version(key, version_id, timeout)
                        .await
                        .ok()
                        .flatten()
                        .and_then(|info| parse_unexpired_retain_until(&info.retain_until));
                    return Ok(DeleteVersionOutcome::WormLocked403 {
                        detail,
                        retain_until: observed_until,
                    });
                }
                // MinIO/AWS frequently return generic `AccessDenied` on Object Lock
                // protected version DELETEs: confirm via GetObjectRetention AND require
                // an unexpired `RetainUntilDate > now()` so credential/policy 403s or
                // expired retention records are NOT misclassified as active WORM locks.
                match self
                    .get_object_retention_version(key, version_id, timeout)
                    .await
                {
                    Ok(Some(info)) => match parse_unexpired_retain_until(&info.retain_until) {
                        Some(until) => Ok(DeleteVersionOutcome::WormLocked403 {
                            detail: format!(
                                "{detail} (confirmed Object Lock retention mode={} until={until})",
                                info.mode
                            ),
                            retain_until: Some(until),
                        }),
                        None => Ok(DeleteVersionOutcome::Error(format!(
                            "{detail} (Object Lock retention expired or unparseable: {})",
                            info.retain_until
                        ))),
                    },
                    Ok(None) => Ok(DeleteVersionOutcome::Error(format!(
                        "{detail} (no Object Lock retention present)"
                    ))),
                    Err(_) => {
                        // Unable to confirm retention (e.g. policy denied GET ?retention too):
                        // treat as transient error rather than silently reverting non-WORM 403.
                        Ok(DeleteVersionOutcome::Error(detail))
                    }
                }
            }
            other => {
                let body_str = String::from_utf8_lossy(&body);
                let parsed: S3XmlError = quick_xml::de::from_str(&body_str).unwrap_or_default();
                Ok(DeleteVersionOutcome::Error(format!(
                    "S3 delete returned HTTP {other} ({} {})",
                    parsed.code, parsed.message
                )))
            }
        }
    }

    async fn head_etag_with_timeout(
        &self,
        key: &str,
        timeout: std::time::Duration,
    ) -> Result<Option<Option<String>>, String> {
        let (status, headers, _body) = self
            .send_signed_or_unsigned(reqwest::Method::HEAD, key, &[], &[], timeout)
            .await?;
        match status {
            200 => {
                let etag = headers
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                Ok(Some(etag))
            }
            404 => Ok(None),
            other => Err(format!("S3 head returned HTTP {other}")),
        }
    }

    /// Probes once whether an unversioned backend enforces `If-Match` on `DELETE`
    /// (`PUT` probe -> `DELETE` with mismatched `If-Match` expecting `412`) (#551).
    pub async fn probe_unversioned_conditional_delete(&self, timeout: std::time::Duration) -> bool {
        use std::sync::atomic::Ordering;
        match self.conditional_delete_supported.load(Ordering::Relaxed) {
            1 => return true,
            2 => return false,
            _ => {}
        }
        let suffix = crate::jmap::random()
            .map(|b| crate::jmap::reply::hex(&b))
            .unwrap_or_else(|| "probe".to_owned());
        let probe_key = format!("tmp/blob-upload/.cond-delete-probe-{suffix}");
        let supported = if self
            .put(&probe_key, b"probe", "application/octet-stream")
            .await
            .is_ok()
        {
            match self
                .delete_object_version(
                    &probe_key,
                    None,
                    Some("\"00000000000000000000000000000000\""),
                    timeout,
                )
                .await
            {
                Ok(DeleteVersionOutcome::PreconditionFailed) => {
                    let _ = self.remove_inner(&probe_key, Some(timeout)).await;
                    true
                }
                _ => {
                    let _ = self.remove_inner(&probe_key, Some(timeout)).await;
                    false
                }
            }
        } else {
            false
        };
        let code = if supported { 1 } else { 2 };
        let _ = self.conditional_delete_supported.compare_exchange(
            0,
            code,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        if !supported {
            eprintln!(
                "blob-gc: unversioned S3 backend does not enforce If-Match on DELETE; relying on proactive purging_at blob.promote_verify fencing"
            );
        }
        supported
    }

    async fn delete_all_versions_entries(
        &self,
        entries: Vec<ObjectVersionEntry>,
        timeout: std::time::Duration,
    ) -> Result<BlobDeleteOutcome, String> {
        // Delete concrete versions first, then delete markers so a WORM-locked
        // concrete version aborts immediately before removing markers or blobs row.
        let mut versions = Vec::new();
        let mut markers = Vec::new();
        for entry in entries {
            if entry.is_delete_marker {
                markers.push(entry);
            } else {
                versions.push(entry);
            }
        }
        for entry in versions.into_iter().chain(markers.into_iter()) {
            let vid = (!entry.version_id.is_empty()).then_some(entry.version_id.as_str());
            match self
                .delete_object_version(&entry.key, vid, None, timeout)
                .await?
            {
                DeleteVersionOutcome::Deleted => {}
                DeleteVersionOutcome::WormLocked403 {
                    detail,
                    retain_until,
                } => {
                    return Ok(BlobDeleteOutcome::WormLocked403 {
                        detail,
                        retain_until,
                    });
                }
                DeleteVersionOutcome::DeleteMarkerCreated => {
                    return Err(format!(
                        "unexpected delete marker while deleting version {:?} of {}",
                        vid, entry.key
                    ));
                }
                DeleteVersionOutcome::PreconditionFailed => {
                    return Err(format!(
                        "unexpected 412 while deleting version of {}",
                        entry.key
                    ));
                }
                DeleteVersionOutcome::Error(err) => return Err(err),
            }
        }
        Ok(BlobDeleteOutcome::Deleted)
    }

    async fn delete_blob_checked_inner(
        &self,
        key: &str,
        timeout: std::time::Duration,
    ) -> Result<BlobDeleteOutcome, String> {
        match self.list_object_versions_exact(key, timeout).await? {
            VersionListing::Versioned(entries) => {
                if entries.is_empty() {
                    return Ok(BlobDeleteOutcome::Deleted);
                }
                self.delete_all_versions_entries(entries, timeout).await
            }
            VersionListing::Unversioned => {
                let etag_owned = if self.probe_unversioned_conditional_delete(timeout).await {
                    match self.head_etag_with_timeout(key, timeout).await? {
                        Some(etag) => etag,
                        None => return Ok(BlobDeleteOutcome::Deleted),
                    }
                } else {
                    None
                };
                match self
                    .delete_object_version(key, None, etag_owned.as_deref(), timeout)
                    .await?
                {
                    DeleteVersionOutcome::Deleted => Ok(BlobDeleteOutcome::Deleted),
                    DeleteVersionOutcome::WormLocked403 {
                        detail,
                        retain_until,
                    } => Ok(BlobDeleteOutcome::WormLocked403 {
                        detail,
                        retain_until,
                    }),
                    DeleteVersionOutcome::DeleteMarkerCreated => {
                        // Bucket actually has versioning enabled; permanently delete every
                        // concrete version and delete marker instead of accepting a delete marker.
                        match self.list_object_versions_exact(key, timeout).await? {
                            VersionListing::Versioned(entries) if !entries.is_empty() => {
                                self.delete_all_versions_entries(entries, timeout).await
                            }
                            _ => Err(format!(
                                "S3 returned x-amz-delete-marker=true for {key} but version listing returned no entries"
                            )),
                        }
                    }
                    DeleteVersionOutcome::PreconditionFailed => Err(format!(
                        "S3 conditional DELETE precondition failed (ETag changed concurrently) for {key}"
                    )),
                    DeleteVersionOutcome::Error(err) => Err(err),
                }
            }
        }
    }
}

impl S3Store {
    async fn remove_inner(
        &self,
        key: &str,
        timeout: Option<std::time::Duration>,
    ) -> Result<(), String> {
        if let Some(client) = &self.unsigned {
            let _ = self.bucket().await?;
            let mut req = client.delete(self.object_url(key)?);
            if let Some(t) = timeout {
                req = req.timeout(t);
            }
            let response = req.send().await.map_err(|error| error.to_string())?;
            return if response.status().is_success() {
                Ok(())
            } else {
                Err(format!("S3 delete returned HTTP {}", response.status()))
            };
        }

        let mut bucket = self.bucket().await?;
        if let Some(t) = timeout {
            bucket.set_request_timeout(Some(t));
        }
        let response = bucket.delete_object(key).await.map_err(|e| e.to_string())?;
        if (200..300).contains(&response.status_code()) {
            Ok(())
        } else {
            Err(format!(
                "S3 delete returned HTTP {}",
                response.status_code()
            ))
        }
    }
    /// Office's CopyN boundary: read at most the manifest length and ignore
    /// trailing object bytes, as frozen Go does when it closes that chunk.
    pub(crate) async fn read_prefix(&self, key: &str, length: usize) -> Result<Vec<u8>, String> {
        use futures_util::StreamExt;
        let bucket = self.bucket().await?;
        let mut response = bucket
            .get_object_stream(key)
            .await
            .map_err(|e| e.to_string())?;
        if response.status_code != 200 {
            return Err(format!("S3 get returned HTTP {}", response.status_code));
        }
        let mut bytes = Vec::with_capacity(length.min(4 << 20));
        while bytes.len() < length {
            let Some(chunk) = response.bytes.next().await else {
                break;
            };
            let chunk = chunk.map_err(|e| e.to_string())?;
            bytes.extend_from_slice(&chunk[..chunk.len().min(length - bytes.len())]);
        }
        Ok(bytes)
    }
}

impl S3Store {
    /// Size of one object, `None` when it does not exist (`StatObject`).
    pub async fn stat_size(&self, key: &str) -> Result<Option<u64>, String> {
        let (head, code) = self
            .bucket()
            .await?
            .head_object(key)
            .await
            .map_err(|e| e.to_string())?;
        match code {
            200 => Ok(Some(head.content_length.unwrap_or(0).max(0) as u64)),
            404 => Ok(None),
            other => Err(format!("S3 head returned HTTP {other}")),
        }
    }

    /// `(key, last-modified unix seconds)` of every object under `prefix`.
    pub async fn list_with_modified(&self, prefix: &str) -> Result<Vec<(String, i64)>, String> {
        let pages = self
            .bucket()
            .await?
            .list(prefix.to_owned(), None)
            .await
            .map_err(|e| e.to_string())?;
        Ok(pages
            .into_iter()
            .flat_map(|p| p.contents)
            .map(|o| {
                let at = chrono::DateTime::parse_from_rfc3339(&o.last_modified)
                    .map(|t| t.timestamp())
                    .unwrap_or(0);
                (o.key, at)
            })
            .collect())
    }

    /// Bytes `[start, start+len)` of an object.
    pub async fn read_range(&self, key: &str, start: u64, len: u64) -> Result<Vec<u8>, String> {
        let response = self
            .bucket()
            .await?
            .get_object_range(key, start, Some(start + len - 1))
            .await
            .map_err(|e| e.to_string())?;
        if !(200..300).contains(&response.status_code()) {
            return Err(format!("S3 get returned HTTP {}", response.status_code()));
        }
        Ok(response.to_vec())
    }

    /// Store `bytes` under a temporary key (`PutObject`, not multipart).
    pub async fn put_temp(&self, key: &str, bytes: &[u8]) -> Result<(), String> {
        use crate::recovery_worker::ObjectStore as _;
        self.put(key, bytes, "application/octet-stream").await
    }
}

/// One key of a bucket listing: the key and its `LastModified` (`None` when the
/// store sent none or one that does not parse, which Go reads as a zero time).
pub(crate) struct ListedObject {
    pub key: String,
    pub modified: Option<chrono::DateTime<chrono::Utc>>,
}

impl S3Store {
    /// One ListObjectsV2 page (Go's minio `ListObjects` issues the same
    /// requests: `start-after` on the first, the continuation token after).
    /// Returns the next continuation token while the listing is truncated.
    pub(crate) async fn list_page(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        token: Option<String>,
        max_keys: Option<usize>,
    ) -> Result<(Vec<ListedObject>, Option<String>), String> {
        let (page, status) = self
            .bucket()
            .await?
            .list_page(
                prefix.to_owned(),
                None,
                token,
                start_after.filter(|s| !s.is_empty()).map(str::to_owned),
                max_keys,
            )
            .await
            .map_err(|e| e.to_string())?;
        if status != 200 {
            return Err(format!("S3 list returned HTTP {status}"));
        }
        let objects = page
            .contents
            .into_iter()
            .map(|o| ListedObject {
                modified: chrono::DateTime::parse_from_rfc3339(&o.last_modified)
                    .ok()
                    .map(|t| t.with_timezone(&chrono::Utc)),
                key: o.key,
            })
            .collect();
        Ok((
            objects,
            page.next_continuation_token.filter(|_| page.is_truncated),
        ))
    }
}

impl S3Store {
    /// MinIO's export GetObject checks HTTP status and Last-Modified before
    /// exposing bytes. Signing stays in rust-s3; chunks remain bounded.
    pub(crate) async fn compliance_copy(
        &self,
        key: &str,
        sink: &mut crate::compliance_export::Writer,
    ) -> Result<(), String> {
        let mut response = self.compliance_object(key).await?;
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            sink.write(chunk).await?;
        }
        Ok(())
    }
    pub(crate) async fn compliance_object(&self, key: &str) -> Result<reqwest::Response, String> {
        let response = self.blob_object(key).await?;
        let modified = response
            .headers()
            .get("last-modified")
            .and_then(|h| h.to_str().ok())
            .ok_or("missing Last-Modified")?;
        chrono::DateTime::parse_from_rfc2822(modified).map_err(|e| e.to_string())?;
        Ok(response)
    }
    /// A signed GetObject whose body the caller streams in bounded chunks (#469).
    pub(crate) async fn blob_object(&self, key: &str) -> Result<reqwest::Response, String> {
        use s3::request::Request;
        let bucket = self.bucket().await?;
        let response = if let Some(client) = &self.unsigned {
            client
                .get(self.object_url(key)?)
                .send()
                .await
                .map_err(|e| e.to_string())?
        } else {
            s3::request::tokio_backend::ReqwestRequest::new(
                &bucket,
                key,
                s3::command::Command::GetObject,
            )
            .await
            .map_err(|e| e.to_string())?
            .response()
            .await
            .map_err(|e| e.to_string())?
        };
        if !response.status().is_success() {
            return Err("object unavailable".into());
        }
        Ok(response)
    }
}

struct LegalHoldReply {
    status: u16,
    signed_region: String,
    code: Option<String>,
    region: Option<String>,
}

fn parse_go_bool(v: &str) -> Option<bool> {
    match v {
        "true" | "True" | "TRUE" | "1" | "t" | "T" => Some(true),
        "false" | "False" | "FALSE" | "0" | "f" | "F" => Some(false),
        _ => None,
    }
}

fn normalize_s3_region(region: &str) -> String {
    match region {
        "" => "us-east-1".to_owned(),
        "EU" => "eu-west-1".to_owned(),
        _ => region.to_owned(),
    }
}

fn is_valid_aws_region_label(s: &str) -> bool {
    !s.is_empty()
        && !s.contains('.')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_excluded_s3_prefix(rest: &str) -> bool {
    rest.starts_with("website")
        || rest.starts_with("control")
        || rest.starts_with("accelerate")
        || rest.starts_with("outposts")
        || rest.starts_with("fips")
        || rest.starts_with("dualstack")
        || rest.starts_with("xpress-")
}

fn is_amazon_elb_host(lower: &str) -> bool {
    lower
        .strip_suffix(".amazonaws.com")
        .or_else(|| lower.strip_suffix(".amazonaws.com.cn"))
        .is_some_and(|prefix| prefix.contains("elb"))
}

fn amazon_privatelink_region(lower: &str) -> Option<&str> {
    let body = lower
        .strip_prefix("bucket.vpce-")
        .or_else(|| lower.strip_prefix("accesspoint.vpce-"))?
        .strip_suffix(".vpce.amazonaws.com")?;
    let (_, region) = body.split_once(".s3.")?;
    is_valid_aws_region_label(region).then_some(region)
}

fn amazon_outposts_region(lower: &str) -> Option<&str> {
    let body = lower.strip_suffix(".amazonaws.com")?;
    let (prefix, region) = body.rsplit_once(".s3-outposts.")?;
    (!prefix.is_empty() && is_valid_aws_region_label(region)).then_some(region)
}

fn amazon_express_region(lower: &str) -> Option<&str> {
    let body = lower.strip_suffix(".amazonaws.com")?;
    let (head, region) = body.split_once('.')?;
    if !is_valid_aws_region_label(region) {
        return None;
    }
    if head == "s3express-control" {
        return Some(region);
    }
    let az = head.strip_prefix("s3express-")?;
    let (zone_id, az_num) = az.rsplit_once("-az")?;
    let valid_zone = (3..=7).contains(&zone_id.len())
        && zone_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let valid_num = az_num.len() == 1 && matches!(az_num.as_bytes()[0], b'1'..=b'6');
    (valid_zone && valid_num).then_some(region)
}

fn amazon_cn_region(prefix: &str) -> Option<&str> {
    let region = prefix
        .strip_prefix("s3.dualstack.")
        .or_else(|| prefix.strip_prefix("s3."))?;
    (region.starts_with("cn") && is_valid_aws_region_label(region)).then_some(region)
}

/// Extracts an explicit AWS region from Amazon S3 endpoint hosts matching
/// `minio-go` v7.2.1 `s3utils.GetRegionFromURL` (including FIPS, PrivateLink,
/// Outposts, Express, China, dual-stack, and legacy `s3-<region>` hosts).
fn s3_region_from_url(endpoint: &str) -> Option<String> {
    let url = reqwest::Url::parse(endpoint).ok()?;
    let lower = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "s3.amazonaws.com" | "s3-external-1.amazonaws.com" | "s3.dualstack.amazonaws.com"
    ) || is_amazon_elb_host(&lower)
    {
        return None;
    }
    if let Some(prefix) = lower.strip_suffix(".amazonaws.com.cn") {
        return amazon_cn_region(prefix).map(str::to_owned);
    }
    if let Some(region) = amazon_privatelink_region(&lower) {
        return Some(region.to_owned());
    }
    if let Some(region) = amazon_express_region(&lower) {
        return Some(region.to_owned());
    }
    if let Some(region) = amazon_outposts_region(&lower) {
        return Some(region.to_owned());
    }
    let prefix = lower.strip_suffix(".amazonaws.com")?;
    if let Some(region) = prefix
        .strip_prefix("s3-fips.dualstack.")
        .or_else(|| prefix.strip_prefix("s3-fips."))
        .or_else(|| prefix.strip_prefix("s3.dualstack."))
    {
        return (is_valid_aws_region_label(region) && !is_excluded_s3_prefix(region))
            .then(|| region.to_owned());
    }
    if prefix.starts_with("s3-fips-") {
        if let Some(region) = prefix.strip_prefix("s3-") {
            return is_valid_aws_region_label(region).then(|| region.to_owned());
        }
    }
    if let Some(region) = prefix
        .strip_prefix("s3-")
        .or_else(|| prefix.strip_prefix("s3."))
    {
        return (is_valid_aws_region_label(region) && !is_excluded_s3_prefix(region))
            .then(|| region.to_owned());
    }
    None
}

/// Returns true only when `minio-go` v7.2.1 `makeTargetURL` rewrites the host
/// to `s3.dualstack.<region>.<domain>` (excludes FIPS, PrivateLink, Outposts,
/// Express, website, control, accelerate, ELB, and non-AWS hosts).
fn is_amazon_s3_rewrite_host(host: &str) -> bool {
    let lower = host.trim_end_matches('.').to_ascii_lowercase();
    if is_amazon_elb_host(&lower) {
        return false;
    }
    if matches!(
        lower.as_str(),
        "s3.amazonaws.com" | "s3-external-1.amazonaws.com" | "s3.dualstack.amazonaws.com"
    ) {
        return true;
    }
    if let Some(prefix) = lower.strip_suffix(".amazonaws.com.cn") {
        return amazon_cn_region(prefix).is_some();
    }
    let Some(prefix) = lower.strip_suffix(".amazonaws.com") else {
        return false;
    };
    let Some(region) = prefix
        .strip_prefix("s3.dualstack.")
        .or_else(|| prefix.strip_prefix("s3."))
        .or_else(|| prefix.strip_prefix("s3-"))
    else {
        return false;
    };
    is_valid_aws_region_label(region) && !is_excluded_s3_prefix(region)
}

/// Derives the dual-stack AWS regional S3 endpoint matching `minio-go` v7.2.1
/// (`s3DualstackEnabled = true` in `makeTargetURL`), leaving FIPS, PrivateLink,
/// Outposts, website, and non-AWS endpoints untouched.
fn regional_s3_endpoint(endpoint: &str, region: &str) -> String {
    if region.is_empty() {
        return endpoint.to_owned();
    }
    let Ok(mut url) = reqwest::Url::parse(endpoint) else {
        return endpoint.to_owned();
    };
    let Some(host) = url.host_str() else {
        return endpoint.to_owned();
    };
    if !is_amazon_s3_rewrite_host(host) {
        return endpoint.to_owned();
    }
    let domain = if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else {
        "amazonaws.com"
    };
    let regional_host = format!("s3.dualstack.{region}.{domain}");
    if url.set_host(Some(&regional_host)).is_err() {
        return endpoint.to_owned();
    }
    if !endpoint.ends_with('/') {
        url.as_str().trim_end_matches('/').to_owned()
    } else {
        url.to_string()
    }
}

fn is_retryable_s3_code(code: &str) -> bool {
    matches!(
        code,
        "RequestError"
            | "RequestTimeout"
            | "Throttling"
            | "ThrottlingException"
            | "RequestLimitExceeded"
            | "RequestThrottled"
            | "InternalError"
            | "ExpiredToken"
            | "ExpiredTokenException"
            | "SlowDown"
            | "SlowDownWrite"
            | "SlowDownRead"
    )
}

#[cfg(test)]
mod tests {
    use super::S3Store;
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::{service::service_fn, Response};
    use hyper_util::rt::TokioIo;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    struct AbortServer(tokio::task::JoinHandle<()>);
    impl Drop for AbortServer {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    #[tokio::test]
    async fn legal_hold_403_retries_against_signed_region_after_concurrent_cache_refresh() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let auths: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let hits = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let entered_s = entered.clone();
        let release_s = release.clone();
        let auths_s = auths.clone();
        let hits_s = hits.clone();
        let _server = AbortServer(tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (entered_c, release_c, auths_c, hits_c) = (
                    entered_s.clone(),
                    release_s.clone(),
                    auths_s.clone(),
                    hits_s.clone(),
                );
                tokio::spawn(async move {
                    let svc = service_fn(move |req| {
                        let (entered_r, release_r, auths_r, hits_r) = (
                            entered_c.clone(),
                            release_c.clone(),
                            auths_c.clone(),
                            hits_c.clone(),
                        );
                        async move {
                            let auth = req
                                .headers()
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_owned();
                            auths_r.lock().unwrap().push(auth);
                            let n = hits_r.fetch_add(1, Ordering::SeqCst);
                            let resp = if n == 0 {
                                entered_r.notify_one();
                                release_r.notified().await;
                                Response::builder()
                                    .status(403)
                                    .header("x-amz-bucket-region", "eu-west-1")
                                    .header("content-type", "application/xml")
                                    .body(Full::new(Bytes::from_static(
                                        b"<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
                                    )))
                                    .unwrap()
                            } else {
                                Response::builder()
                                    .status(204)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap()
                            };
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        }));

        let store =
            Arc::new(S3Store::new(&format!("http://{addr}"), "mailblobs", "ak", "sk").unwrap());
        *store.region.lock().await = Some("us-east-1".into());

        let caller = store.clone();
        let handle =
            tokio::spawn(async move { caller.legal_hold_with_retries("key-a", true).await });
        entered.notified().await;
        // Simulate another request refreshing the cached region while attempt 0 is in flight.
        *store.region.lock().await = Some("eu-west-1".into());
        release.notify_one();

        let res = handle.await.unwrap();
        assert!(
            res.is_ok(),
            "expected retry after 403 signed-region mismatch: {res:?}"
        );
        let recorded = auths.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert!(recorded[0].contains("/us-east-1/s3/aws4_request"));
        assert!(recorded[1].contains("/eu-west-1/s3/aws4_request"));
    }

    #[tokio::test]
    async fn legal_hold_403_same_region_access_denied_is_terminal() {
        let hits = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits_s = hits.clone();
        let _server = AbortServer(tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let hits_c = hits_s.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |_req| {
                        let hits_r = hits_c.clone();
                        async move {
                            hits_r.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(403)
                                    .header("x-amz-bucket-region", "eu-west-1")
                                    .header("content-type", "application/xml")
                                    .body(Full::new(Bytes::from_static(
                                        b"<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
                                    )))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        }));

        let store = S3Store::new(&format!("http://{addr}"), "mailblobs", "ak", "sk").unwrap();
        *store.region.lock().await = Some("eu-west-1".into());

        let err = store
            .legal_hold_with_retries("key-b", false)
            .await
            .unwrap_err();
        assert!(
            err.contains("403"),
            "expected terminal 403 error, got {err}"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn legal_hold_403_same_region_with_retryable_code_retries() {
        let hits = Arc::new(AtomicUsize::new(0));
        let auths: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits_s = hits.clone();
        let auths_s = auths.clone();
        let _server = AbortServer(tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (hits_c, auths_c) = (hits_s.clone(), auths_s.clone());
                tokio::spawn(async move {
                    let svc = service_fn(move |req| {
                        let (hits_r, auths_r) = (hits_c.clone(), auths_c.clone());
                        async move {
                            let auth = req
                                .headers()
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_owned();
                            auths_r.lock().unwrap().push(auth);
                            let n = hits_r.fetch_add(1, Ordering::SeqCst);
                            let resp = if n == 0 {
                                Response::builder()
                                    .status(403)
                                    .header("x-amz-bucket-region", "eu-west-1")
                                    .header("content-type", "application/xml")
                                    .body(Full::new(Bytes::from_static(
                                        b"<Error><Code>SlowDownWrite</Code><Message>Slow down</Message></Error>",
                                    )))
                                    .unwrap()
                            } else {
                                Response::builder()
                                    .status(204)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap()
                            };
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        }));

        let store = S3Store::new(&format!("http://{addr}"), "mailblobs", "ak", "sk").unwrap();
        *store.region.lock().await = Some("eu-west-1".into());

        let res = store.legal_hold_with_retries("key-c", true).await;
        assert!(res.is_ok(), "expected 403 SlowDownWrite to retry: {res:?}");
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        let recorded = auths.lock().unwrap();
        assert!(recorded[0].contains("/eu-west-1/s3/aws4_request"));
        assert!(recorded[1].contains("/eu-west-1/s3/aws4_request"));
    }

    #[test]
    fn from_lookup_matches_go_minio_overrides() {
        let lookup = |pairs: &[(&str, &str)]| {
            let entries: Vec<(String, String)> = pairs
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect();
            S3Store::from_lookup(move |k| {
                entries
                    .iter()
                    .find(|(name, _)| name == k)
                    .map(|(_, v)| v.clone())
            })
        };
        let store = lookup(&[
            ("S3_ENDPOINT", "127.0.0.1:9000"),
            ("MINIO_ENDPOINT", "127.0.0.1:9100"),
            ("S3_BUCKET", "mailblobs"),
            ("MINIO_BUCKET", "custom-bucket"),
            ("S3_SECURE", "bogus"),
            ("MINIO_SECURE", "true"),
        ])
        .unwrap();
        assert_eq!(store.bucket_name(), "custom-bucket");
        assert_eq!(store.endpoint(), "https://127.0.0.1:9100");

        let err = lookup(&[("MINIO_SECURE", "maybe")]).err().unwrap();
        assert!(err.contains("MINIO_SECURE"), "unexpected err: {err}");

        assert!(lookup(&[("S3_ENDPOINT", ""), ("MINIO_ENDPOINT", "127.0.0.1:9100")]).is_err());
        assert!(lookup(&[("S3_BUCKET", ""), ("MINIO_BUCKET", "custom-bucket")]).is_err());
        assert!(lookup(&[
            ("S3_ENDPOINT", "HTTP://127.0.0.1:9000"),
            ("S3_SECURE", "true")
        ])
        .is_err());

        let store = lookup(&[("S3_SECURE", " true ")]).unwrap();
        assert_eq!(store.bucket_name(), "mailblobs");
        assert_eq!(store.endpoint(), "http://127.0.0.1:9000");
    }

    #[tokio::test]
    async fn legal_hold_terminal_region_errors_do_not_retry() {
        use bytes::Bytes;
        use http_body_util::Full;
        use hyper::{service::service_fn, Response};
        use hyper_util::rt::TokioIo;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        async fn run_case(status: u16, header_region: Option<&'static str>, body: &'static [u8]) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let hits = Arc::new(AtomicUsize::new(0));
            let hits_s = hits.clone();

            let srv = AbortServer(tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let hits_c = hits_s.clone();
                    tokio::spawn(async move {
                        let svc = service_fn(move |_req| {
                            let hits_r = hits_c.clone();
                            async move {
                                hits_r.fetch_add(1, Ordering::SeqCst);
                                let mut builder = Response::builder()
                                    .status(status)
                                    .header("content-type", "application/xml");
                                if let Some(region) = header_region {
                                    builder = builder.header("x-amz-bucket-region", region);
                                }
                                let resp =
                                    builder.body(Full::new(Bytes::from_static(body))).unwrap();
                                Ok::<_, std::convert::Infallible>(resp)
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            }));

            let store = S3Store::new(&format!("http://{addr}"), "mailblobs", "ak", "sk").unwrap();
            *store.region.lock().await = Some("eu-west-1".into());

            let res = store.legal_hold_with_retries("key-d", true).await;
            drop(srv);
            assert!(res.is_err(), "expected terminal {status} error");
            assert_eq!(hits.load(Ordering::SeqCst), 1);
            assert_eq!(store.region.lock().await.as_deref(), Some("eu-west-1"));
        }

        // AuthorizationHeaderMalformed without region
        run_case(
            400,
            None,
            b"<Error><Code>AuthorizationHeaderMalformed</Code><Message>Malformed</Message></Error>",
        )
        .await;
        // AuthorizationHeaderMalformed with same region as signed request
        run_case(
            400,
            Some("eu-west-1"),
            b"<Error><Code>AuthorizationHeaderMalformed</Code><Message>Same region</Message><Region>eu-west-1</Region></Error>",
        )
        .await;
        // InvalidRegion without region
        run_case(
            400,
            None,
            b"<Error><Code>InvalidRegion</Code><Message>Invalid</Message></Error>",
        )
        .await;
        // Unrelated terminal 403 or same-region 301 must not retry or mutate cache.
        run_case(
            403,
            Some("ap-southeast-1"),
            b"<Error><Code>AccountProblem</Code><Message>Account problem</Message></Error>",
        )
        .await;
        run_case(
            301,
            Some("eu-west-1"),
            b"<Error><Code>PermanentRedirect</Code><Message>Same region</Message></Error>",
        )
        .await;
    }

    #[tokio::test]
    async fn legal_hold_and_bucket_location_retry_301_307_without_following_redirect() {
        use bytes::Bytes;
        use http_body_util::Full;
        use hyper::{service::service_fn, Response};
        use hyper_util::rt::TokioIo;
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        };

        async fn run_redirect_hold(status: u16, target_region: &'static str) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let hits = Arc::new(AtomicUsize::new(0));
            let auths = Arc::new(Mutex::new(Vec::<String>::new()));
            let hits_s = hits.clone();
            let auths_s = auths.clone();

            let srv = AbortServer(tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let hits_c = hits_s.clone();
                    let auths_c = auths_s.clone();
                    tokio::spawn(async move {
                        let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                            let hits_r = hits_c.clone();
                            let auths_r = auths_c.clone();
                            async move {
                                let auth = req
                                    .headers()
                                    .get("authorization")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                                    .to_owned();
                                auths_r.lock().unwrap().push(auth);
                                let n = hits_r.fetch_add(1, Ordering::SeqCst);
                                let resp = if n == 0 {
                                    Response::builder()
                                        .status(status)
                                        .header(
                                            "location",
                                            "http://127.0.0.1:9/redirected-never-follow",
                                        )
                                        .header("x-amz-bucket-region", target_region)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap()
                                } else {
                                    Response::builder()
                                        .status(204)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap()
                                };
                                Ok::<_, std::convert::Infallible>(resp)
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            }));

            let store = S3Store::new(&format!("http://{addr}"), "mailblobs", "ak", "sk").unwrap();
            *store.region.lock().await = Some("eu-west-1".into());
            let res = store.legal_hold_with_retries("key-redir", true).await;
            drop(srv);
            assert!(
                res.is_ok(),
                "expected empty {status} region redirect to retry: {res:?}"
            );
            assert_eq!(hits.load(Ordering::SeqCst), 2);
            assert_eq!(store.region.lock().await.as_deref(), Some(target_region));
            let recorded = auths.lock().unwrap();
            assert!(recorded[0].contains("/eu-west-1/s3/aws4_request"));
            assert!(recorded[1].contains(&format!("/{target_region}/s3/aws4_request")));
        }

        run_redirect_hold(301, "ap-southeast-1").await;
        run_redirect_hold(307, "us-west-2").await;

        // Cold-cache GET ?location on 307 must not follow Location and must cache x-amz-bucket-region.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_s = hits.clone();
        let srv = AbortServer(tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let hits_c = hits_s.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |_req| {
                        let hits_r = hits_c.clone();
                        async move {
                            hits_r.fetch_add(1, Ordering::SeqCst);
                            let resp = Response::builder()
                                .status(307)
                                .header("location", "http://127.0.0.1:9/redirected-never-follow")
                                .header("x-amz-bucket-region", "eu-west-1")
                                .body(Full::new(Bytes::new()))
                                .unwrap();
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        }));
        let store = S3Store::new(&format!("http://{addr}"), "mailblobs", "ak", "sk").unwrap();
        assert!(store.bucket().await.is_ok());
        drop(srv);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(store.region.lock().await.as_deref(), Some("eu-west-1"));

        // Cold-cache GET ?location on 307 WITHOUT region hint must fail instead of caching us-east-1.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = AbortServer(tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let svc = service_fn(move |_req| async move {
                        let resp = Response::builder()
                            .status(307)
                            .header("location", "http://127.0.0.1:9/redirected-never-follow")
                            .body(Full::new(Bytes::new()))
                            .unwrap();
                        Ok::<_, std::convert::Infallible>(resp)
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        }));
        let store = S3Store::new(&format!("http://{addr}"), "mailblobs", "ak", "sk").unwrap();
        assert!(store.bucket().await.is_err());
        drop(srv);
        assert_eq!(*store.region.lock().await, None);
    }

    #[tokio::test]
    async fn regional_s3_endpoint_and_url_region_extraction_match_minio_go() {
        use super::{regional_s3_endpoint, s3_region_from_url};
        assert_eq!(
            regional_s3_endpoint("https://s3.amazonaws.com", "us-west-2"),
            "https://s3.dualstack.us-west-2.amazonaws.com"
        );
        assert_eq!(
            regional_s3_endpoint("https://s3-external-1.amazonaws.com", "us-east-1"),
            "https://s3.dualstack.us-east-1.amazonaws.com"
        );
        assert_eq!(
            regional_s3_endpoint("https://s3-eu-west-1.amazonaws.com", "eu-west-1"),
            "https://s3.dualstack.eu-west-1.amazonaws.com"
        );
        assert_eq!(
            regional_s3_endpoint("https://s3.dualstack.amazonaws.com", "eu-west-1"),
            "https://s3.dualstack.eu-west-1.amazonaws.com"
        );
        assert_eq!(
            regional_s3_endpoint("https://s3.amazonaws.com", "cn-north-1"),
            "https://s3.dualstack.cn-north-1.amazonaws.com.cn"
        );
        assert_eq!(
            regional_s3_endpoint("https://s3-fips.us-east-1.amazonaws.com", "us-west-2"),
            "https://s3-fips.us-east-1.amazonaws.com"
        );
        assert_eq!(
            regional_s3_endpoint(
                "https://s3-fips.dualstack.us-gov-west-1.amazonaws.com",
                "us-gov-east-1"
            ),
            "https://s3-fips.dualstack.us-gov-west-1.amazonaws.com"
        );
        assert_eq!(
            regional_s3_endpoint(
                "https://bucket.vpce-1234.s3.us-west-2.vpce.amazonaws.com",
                "us-east-1"
            ),
            "https://bucket.vpce-1234.s3.us-west-2.vpce.amazonaws.com"
        );
        assert_eq!(
            regional_s3_endpoint("https://s3-website-us-east-1.amazonaws.com", "us-west-2"),
            "https://s3-website-us-east-1.amazonaws.com"
        );
        assert_eq!(
            regional_s3_endpoint("https://s3-website.us-east-2.amazonaws.com", "us-west-2"),
            "https://s3-website.us-east-2.amazonaws.com"
        );
        assert_eq!(
            regional_s3_endpoint(
                "https://my-outpost.s3-outposts.us-east-1.amazonaws.com",
                "us-west-2"
            ),
            "https://my-outpost.s3-outposts.us-east-1.amazonaws.com"
        );
        assert_eq!(
            regional_s3_endpoint("http://127.0.0.1:9000", "us-west-2"),
            "http://127.0.0.1:9000"
        );

        assert_eq!(s3_region_from_url("https://s3.amazonaws.com"), None);
        assert_eq!(
            s3_region_from_url("https://s3-external-1.amazonaws.com"),
            None
        );
        assert_eq!(
            s3_region_from_url("https://s3-website-us-east-1.amazonaws.com"),
            None
        );
        assert_eq!(
            s3_region_from_url("https://s3-website.us-east-2.amazonaws.com"),
            None
        );
        assert_eq!(
            s3_region_from_url("https://s3-us-west-2.amazonaws.com").as_deref(),
            Some("us-west-2")
        );
        assert_eq!(
            s3_region_from_url("https://s3.dualstack.eu-central-1.amazonaws.com").as_deref(),
            Some("eu-central-1")
        );
        assert_eq!(
            s3_region_from_url("https://s3-fips.us-east-1.amazonaws.com").as_deref(),
            Some("us-east-1")
        );
        assert_eq!(
            s3_region_from_url("https://s3-fips-us-gov-west-1.amazonaws.com").as_deref(),
            Some("fips-us-gov-west-1")
        );
        assert_eq!(
            regional_s3_endpoint(
                "https://s3-fips-us-gov-west-1.amazonaws.com",
                "us-gov-east-1"
            ),
            "https://s3-fips-us-gov-west-1.amazonaws.com"
        );
        assert_eq!(
            s3_region_from_url("https://s3-fips.dualstack.us-gov-west-1.amazonaws.com").as_deref(),
            Some("us-gov-west-1")
        );
        assert_eq!(
            s3_region_from_url("https://bucket.vpce-1234.s3.us-west-2.vpce.amazonaws.com")
                .as_deref(),
            Some("us-west-2")
        );
        assert_eq!(
            s3_region_from_url("https://accesspoint.vpce-abcd.s3.eu-central-1.vpce.amazonaws.com")
                .as_deref(),
            Some("eu-central-1")
        );
        assert_eq!(
            s3_region_from_url("https://my-outpost.s3-outposts.us-east-1.amazonaws.com").as_deref(),
            Some("us-east-1")
        );

        let regional_store = S3Store::new(
            "https://s3-us-west-2.amazonaws.com",
            "mailblobs",
            "ak",
            "sk",
        )
        .unwrap();
        assert_eq!(
            regional_store.region.lock().await.as_deref(),
            Some("us-west-2")
        );
    }

    #[tokio::test]
    async fn legal_hold_empty_403_and_xml_region_precedence_match_minio_go() {
        async fn run_retry_case(
            status: u16,
            header_region: &'static str,
            body: &'static [u8],
            expected_second_region: &'static str,
        ) {
            let hits = Arc::new(AtomicUsize::new(0));
            let auths: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let hits_s = hits.clone();
            let auths_s = auths.clone();
            let _server = AbortServer(tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let (hits_c, auths_c) = (hits_s.clone(), auths_s.clone());
                    tokio::spawn(async move {
                        let svc = service_fn(move |req| {
                            let (hits_r, auths_r) = (hits_c.clone(), auths_c.clone());
                            async move {
                                let auth = req
                                    .headers()
                                    .get("authorization")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                                    .to_owned();
                                auths_r.lock().unwrap().push(auth);
                                let n = hits_r.fetch_add(1, Ordering::SeqCst);
                                let resp = if n == 0 {
                                    Response::builder()
                                        .status(status)
                                        .header("x-amz-bucket-region", header_region)
                                        .header("content-type", "application/xml")
                                        .body(Full::new(Bytes::from_static(body)))
                                        .unwrap()
                                } else {
                                    Response::builder()
                                        .status(204)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap()
                                };
                                Ok::<_, std::convert::Infallible>(resp)
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            }));

            let store = S3Store::new(&format!("http://{addr}"), "mailblobs", "ak", "sk").unwrap();
            *store.region.lock().await = Some("us-east-1".into());
            let res = store.legal_hold_with_retries("key-e", true).await;
            assert!(res.is_ok(), "expected region retry to succeed: {res:?}");
            assert_eq!(hits.load(Ordering::SeqCst), 2);
            let recorded = auths.lock().unwrap();
            assert!(recorded[0].contains("/us-east-1/s3/aws4_request"));
            assert!(recorded[1].contains(&format!("/{expected_second_region}/s3/aws4_request")));
        }

        // Empty 403 defaults to AccessDenied and retries with header region.
        run_retry_case(403, "eu-west-1", b"", "eu-west-1").await;
        // Truncated undecodable 403 XML falls back to AccessDenied + header region.
        run_retry_case(
            403,
            "eu-west-1",
            b"<Error><Code>InvalidAccessKeyId</Code><Region>wrong-region</Region>",
            "eu-west-1",
        )
        .await;
        // Complete XML <Region> takes precedence over conflicting x-amz-bucket-region header.
        run_retry_case(
            400,
            "ap-south-1",
            b"<Error><Code>AuthorizationHeaderMalformed</Code><Region>eu-central-1</Region></Error>",
            "eu-central-1",
        )
        .await;
    }

    #[test]
    fn location_reply_parses_empty_and_regional_seaweedfs_xml() {
        use super::{normalize_s3_region, LocationReply};
        let empty: LocationReply = quick_xml::de::from_str(
            r#"<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>"#,
        )
        .unwrap();
        assert_eq!(normalize_s3_region(&empty.region), "us-east-1");

        let blank: LocationReply = quick_xml::de::from_str(
            r#"<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>"#,
        )
        .unwrap();
        assert_eq!(normalize_s3_region(&blank.region), "us-east-1");

        let named: LocationReply = quick_xml::de::from_str(
            r#"<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">eu-west-1</LocationConstraint>"#,
        )
        .unwrap();
        assert_eq!(normalize_s3_region(&named.region), "eu-west-1");
    }

    #[test]
    fn streaming_list_versions_parser_handles_interleaved_versions_and_delete_markers() {
        use super::parse_list_versions_xml;
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>mailblobs</Name>
  <IsTruncated>true</IsTruncated>
  <NextKeyMarker>tmp/blob-upload/next</NextKeyMarker>
  <NextVersionIdMarker>v-next</NextVersionIdMarker>
  <Version>
    <Key>tmp/blob-upload/aaa</Key>
    <VersionId>v1</VersionId>
    <LastModified>2026-01-01T00:00:00.000Z</LastModified>
  </Version>
  <DeleteMarker>
    <Key>tmp/blob-upload/aaa</Key>
    <VersionId>dm1</VersionId>
    <LastModified>2026-01-02T00:00:00.000Z</LastModified>
  </DeleteMarker>
  <Version>
    <Key>tmp/blob-upload/bbb</Key>
    <VersionId>v2</VersionId>
    <LastModified>2026-01-03T00:00:00.000Z</LastModified>
  </Version>
  <DeleteMarker>
    <Key>tmp/blob-upload/bbb</Key>
    <VersionId>dm2</VersionId>
    <LastModified>2026-01-04T00:00:00.000Z</LastModified>
  </DeleteMarker>
</ListVersionsResult>"#;
        let parsed = parse_list_versions_xml(xml).expect("interleaved XML must parse");
        assert!(parsed.is_list_versions_result);
        assert!(parsed.is_truncated);
        assert_eq!(parsed.next_key_marker, "tmp/blob-upload/next");
        assert_eq!(parsed.next_version_id_marker, "v-next");
        assert_eq!(parsed.entries.len(), 4);
        assert!(!parsed.entries[0].is_delete_marker);
        assert_eq!(parsed.entries[0].version_id, "v1");
        assert!(parsed.entries[1].is_delete_marker);
        assert_eq!(parsed.entries[1].version_id, "dm1");
        assert!(!parsed.entries[2].is_delete_marker);
        assert_eq!(parsed.entries[2].version_id, "v2");
        assert!(parsed.entries[3].is_delete_marker);
        assert_eq!(parsed.entries[3].version_id, "dm2");
        assert!(parsed.entries[1].last_modified_unix > parsed.entries[0].last_modified_unix);

        let bucket_list =
            parse_list_versions_xml("<ListBucketResult><Name>mailblobs</Name></ListBucketResult>")
                .expect("ListBucketResult parses");
        assert!(!bucket_list.is_list_versions_result);

        let truncated = parse_list_versions_xml(
            "<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>k</Key>",
        );
        assert!(
            truncated.is_err_and(|e| e.contains("truncated")),
            "truncated ListVersionsResult XML must fail closed"
        );
    }

    #[tokio::test]
    async fn aws_unversioned_null_version_takes_if_match_path_and_expired_403_is_error() {
        use super::{BlobDeleteOutcome, DeleteVersionOutcome};
        let seen_if_match = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen_if_match_s = seen_if_match.clone();
        let future_until = (chrono::Utc::now() + chrono::Duration::days(10)).to_rfc3339();
        let future_until_s = future_until.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _server = AbortServer(tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let seen_c = seen_if_match_s.clone();
                let future_c = future_until_s.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req| {
                        let seen_r = seen_c.clone();
                        let future_r = future_c.clone();
                        async move {
                            let method = req.method().clone();
                            let path = req.uri().path().to_owned();
                            let query = req.uri().query().unwrap_or("").to_owned();
                            let if_match = req
                                .headers()
                                .get("if-match")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned);

                            let resp = if method == hyper::Method::GET && query.contains("versions")
                            {
                                // AWS S3 unversioned bucket: single concrete VersionId="null"
                                let xml = r#"<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>null-key</Key><VersionId>null</VersionId><LastModified>2026-01-01T00:00:00.000Z</LastModified></Version></ListVersionsResult>"#;
                                Response::builder()
                                    .status(200)
                                    .body(Full::new(Bytes::from(xml)))
                                    .unwrap()
                            } else if method == hyper::Method::PUT {
                                Response::builder()
                                    .status(200)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap()
                            } else if method == hyper::Method::HEAD && path.ends_with("/null-key") {
                                Response::builder()
                                    .status(200)
                                    .header("etag", "\"etag-null-key\"")
                                    .body(Full::new(Bytes::new()))
                                    .unwrap()
                            } else if method == hyper::Method::DELETE
                                && path.contains(".cond-delete-probe-")
                            {
                                let status = if if_match.is_some() { 412 } else { 204 };
                                Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap()
                            } else if method == hyper::Method::DELETE && path.ends_with("/null-key")
                            {
                                if let Some(im) = if_match {
                                    seen_r.lock().unwrap().push(im);
                                }
                                Response::builder()
                                    .status(204)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap()
                            } else if method == hyper::Method::DELETE
                                && (path.ends_with("/expired-403") || path.ends_with("/active-403"))
                            {
                                let xml = "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>";
                                Response::builder()
                                    .status(403)
                                    .body(Full::new(Bytes::from(xml)))
                                    .unwrap()
                            } else if method == hyper::Method::GET
                                && query.contains("retention")
                                && path.ends_with("/expired-403")
                            {
                                let xml = "<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2020-01-01T00:00:00Z</RetainUntilDate></Retention>";
                                Response::builder()
                                    .status(200)
                                    .body(Full::new(Bytes::from(xml)))
                                    .unwrap()
                            } else if method == hyper::Method::GET
                                && query.contains("retention")
                                && path.ends_with("/active-403")
                            {
                                let xml = format!(
                                    "<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>{future_r}</RetainUntilDate></Retention>"
                                );
                                Response::builder()
                                    .status(200)
                                    .body(Full::new(Bytes::from(xml)))
                                    .unwrap()
                            } else {
                                Response::builder()
                                    .status(404)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap()
                            };
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        }));

        let store = S3Store::new(&format!("http://{addr}"), "mailblobs", "", "").unwrap();
        *store.region.lock().await = Some("us-east-1".into());
        let timeout = std::time::Duration::from_secs(3);

        // 1. AWS unversioned `"null"` version takes unversioned path and sends If-Match ETag
        let res = store
            .delete_blob_checked_inner("null-key", timeout)
            .await
            .expect("delete_blob_checked null-key");
        assert_eq!(res, BlobDeleteOutcome::Deleted);
        assert_eq!(
            seen_if_match.lock().unwrap().as_slice(),
            &["\"etag-null-key\"".to_owned()],
            "AWS unversioned null-only listing must exercise If-Match conditional delete"
        );

        // 2. Expired GetObjectRetention on generic 403 must NOT classify as WormLocked403
        let expired = store
            .delete_object_version("expired-403", Some("v1"), None, timeout)
            .await
            .expect("delete_object_version expired-403");
        assert!(
            matches!(expired, DeleteVersionOutcome::Error(_)),
            "expired retention must be treated as transient/IAM Error, got {expired:?}"
        );

        // 3. Unexpired GetObjectRetention on generic 403 returns WormLocked403 with exact retain_until
        let active = store
            .delete_object_version("active-403", Some("v1"), None, timeout)
            .await
            .expect("delete_object_version active-403");
        match active {
            DeleteVersionOutcome::WormLocked403 { retain_until, .. } => {
                assert_eq!(retain_until.as_deref(), Some(future_until.as_str()));
            }
            other => panic!("expected WormLocked403 with observed retain_until, got {other:?}"),
        }
    }
}
