//! Cleanup of expired and terminal client-assisted recovery uploads.
use setjoin_pg::workers::WorkerDatabase;
use std::{future::Future, pin::Pin, sync::Arc};

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
    /// `PutObjectRetention` (WORM, #301): mode `governance|compliance`, RFC 3339 `until`.
    fn retain_object<'a>(
        &'a self,
        _key: &'a str,
        _mode: &'a str,
        _until: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async { Err("object store does not accept retention".into()) })
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
    region: tokio::sync::Mutex<Option<String>>,
    small_cache: std::sync::Mutex<SmallCache>,
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

#[derive(serde::Deserialize)]
struct LocationReply {
    #[serde(rename = "$value", default)]
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
                    .build()
                    .map_err(|error| error.to_string())?,
            )
        } else {
            None
        };
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
            region: tokio::sync::Mutex::new(None),
            small_cache: std::sync::Mutex::new(SmallCache::default()),
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
        if !buffer || size == 0 || size >= 10 << 20 {
            return Ok(BlobDownload::Streaming {
                size: size as u64,
                content_type: head.content_type.unwrap_or_default(),
                modified: head.last_modified,
            });
        }
        let content_type = head.content_type.unwrap_or_default();
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
                        modified: head.last_modified,
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

    /// minio-go's `executeMethod` loop for `PutObjectRetention` (blob PUT, #301): up to ten
    /// attempts, 200 ms doubling to a 1 s cap, retrying transport failures and the
    /// statuses minio-go treats as retryable.
    pub(crate) async fn retain_with_retries(
        &self,
        key: &str,
        mode: &str,
        until: &str,
    ) -> Result<(), String> {
        const RETRYABLE: [u16; 8] = [408, 429, 499, 500, 502, 503, 504, 520];
        let mut last = String::from("object retention failed");
        for attempt in 0..10u32 {
            if attempt > 0 {
                let wait = (200u64 << (attempt - 1).min(3)).min(1000);
                tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
            }
            match self.retain_attempt(key, mode, until).await {
                Ok(200..=299) => return Ok(()),
                Ok(status) if RETRYABLE.contains(&status) => {
                    last = format!("object retention failed ({status})")
                }
                Ok(status) => return Err(format!("object retention failed ({status})")),
                Err(e) => last = e,
            }
        }
        Err(last)
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
        let value = |name: &str, legacy: &str, default: &str| {
            std::env::var(name)
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| std::env::var(legacy).ok().filter(|s| !s.is_empty()))
                .unwrap_or_else(|| default.into())
        };
        let endpoint = value("S3_ENDPOINT", "MINIO_ENDPOINT", "127.0.0.1:9000");
        let secure = match value("S3_SECURE", "MINIO_SECURE", "false").as_str() {
            "true" | "True" | "TRUE" | "1" | "t" | "T" => true,
            "false" | "False" | "FALSE" | "0" | "f" | "F" => false,
            _ => return Err("S3_SECURE must be a boolean".into()),
        };
        let endpoint = endpoint.trim();
        let endpoint = if endpoint.contains("://") {
            if (endpoint.starts_with("https://") && !secure)
                || (endpoint.starts_with("http://") && secure)
            {
                return Err("S3_SECURE conflicts with S3_ENDPOINT".into());
            }
            endpoint.to_owned()
        } else {
            format!("{}://{endpoint}", if secure { "https" } else { "http" })
        };
        Self::new(
            &endpoint,
            &value("S3_BUCKET", "MINIO_BUCKET", "mailblobs"),
            &value("S3_ACCESS_KEY", "MINIO_ACCESS_KEY", ""),
            &value("S3_SECRET_KEY", "MINIO_SECRET_KEY", ""),
        )
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

    pub(crate) fn bucket_name(&self) -> String { self.bucket.name() }

    pub(crate) fn endpoint(&self) -> &str { &self.endpoint }

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
                // rust-s3 percent-encodes the path; attach location as a query.
                let mut location_bucket = (*self.bucket).clone();
                location_bucket.add_query("location", "");
                let response =
                    ReqwestRequest::new(&location_bucket, "", Command::GetBucketLocation)
                        .await
                        .map_err(|error| error.to_string())?
                        .response_data(false)
                        .await
                        .map_err(|error| error.to_string())?;
                (
                    response.status_code(),
                    response
                        .as_str()
                        .map_err(|error| error.to_string())?
                        .to_owned(),
                    response.headers(),
                )
            };
            let region = if status == 200 {
                let parsed: LocationReply =
                    quick_xml::de::from_str(&body).map_err(|e| e.to_string())?;
                parsed.region
            } else {
                let mut parsed: LocationError = quick_xml::de::from_str(&body).unwrap_or_default();
                if let Some(code) = headers.get("x-minio-error-code").filter(|v| !v.is_empty()) {
                    parsed.code.clone_from(code);
                } else if parsed.code.is_empty() && status == 403 {
                    parsed.code = "AccessDenied".into();
                }
                if parsed.region.is_empty() {
                    parsed.region = headers
                        .get("x-amz-bucket-region")
                        .cloned()
                        .unwrap_or_default();
                }
                match parsed.code.as_str() {
                    "AccessDenied" | "AuthorizationHeaderMalformed" | "InvalidRegion" => {
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
                    _ => return Err(format!("S3 bucket location failed: {}", parsed.code)),
                }
            };
            let region = match region.as_str() {
                "" => "us-east-1",
                "EU" => "eu-west-1",
                _ => &region,
            };
            *cached = Some(region.to_owned());
        }
        let mut bucket = (*self.bucket).clone();
        bucket.region = s3::Region::Custom {
            region: cached.as_ref().unwrap().clone(),
            endpoint: self.endpoint.clone(),
        };
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
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { self.retain_with_retries(key, mode, until).await })
    }
    fn remove<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(client) = &self.unsigned {
                let _ = self.bucket().await?;
                let response = client
                    .delete(self.object_url(key)?)
                    .send()
                    .await
                    .map_err(|error| error.to_string())?;
                return if response.status().is_success() {
                    Ok(())
                } else {
                    Err(format!("S3 delete returned HTTP {}", response.status()))
                };
            }

            let response = self
                .bucket()
                .await?
                .delete_object(key)
                .await
                .map_err(|e| e.to_string())?;
            if (200..300).contains(&response.status_code()) {
                Ok(())
            } else {
                Err(format!(
                    "S3 delete returned HTTP {}",
                    response.status_code()
                ))
            }
        })
    }
}

impl S3Store {
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
