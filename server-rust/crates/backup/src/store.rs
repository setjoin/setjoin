//! Streaming S3 requests; authenticated independently by the process oracle.
use crate::{digest, hex, hmac};
use reqwest::{Client, Method, Response};
use std::path::Path;
#[derive(Clone)]
pub struct Store {
    client: Client,
    local: Option<crate::local::Local>,
    oss: bool,
    minio: bool,
    aws_operation_query: bool,
    endpoint: url::Url,
    bucket: String,
    region: String,
    access: String,
    secret: String,
}
impl Store {
    pub fn new(
        endpoint: &str,
        region: &str,
        bucket: &str,
        access: &str,
        secret: &str,
    ) -> Result<Self, String> {
        let endpoint = if endpoint.is_empty() {
            if region.is_empty() {
                "https://s3.amazonaws.com".into()
            } else {
                format!("https://s3.{region}.amazonaws.com")
            }
        } else if endpoint.contains("://") {
            endpoint.into()
        } else {
            format!("https://{endpoint}")
        };
        let endpoint = url::Url::parse(&endpoint).map_err(|e| format!("parse endpoint: {e}"))?;
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(1800))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            client,
            local: None,
            oss: false,
            minio: true,
            aws_operation_query: false,
            endpoint,
            bucket: bucket.into(),
            region: if region.is_empty() {
                "us-east-1".into()
            } else {
                region.into()
            },
            access: access.into(),
            secret: secret.into(),
        })
    }
    /// Worker factories honor Go's provider and transport policy. The standalone
    /// CLI deliberately uses S3 regardless of its informational provider flag.
    pub fn driver(
        provider: &str,
        endpoint: &str,
        region: &str,
        bucket: &str,
        access: &str,
        secret: &str,
    ) -> Result<Self, String> {
        if !matches!(provider, "" | "s3" | "backup_s3" | "oss" | "posix") {
            return Err(format!("storage: unknown provider {provider:?}"));
        }
        if provider == "posix" {
            let mut store = Self::new("https://localhost", region, bucket, access, secret)?;
            store.local = Some(crate::local::Local::new(bucket)?);
            return Ok(store);
        }
        let endpoint = endpoint.trim();
        let normalized = if endpoint.is_empty() {
            if matches!(provider, "s3" | "") {
                return Err("storage: s3 endpoint is required".into());
            }
            if provider == "oss" {
                format!("https://oss-{region}.aliyuncs.com")
            } else {
                String::new()
            }
        } else {
            let explicit = endpoint.contains("://");
            let parsed = url::Url::parse(&if explicit {
                endpoint.into()
            } else {
                format!("http://{endpoint}")
            })
            .map_err(|e| e.to_string())?;
            let local = parsed.host_str().is_some_and(|s| {
                s.eq_ignore_ascii_case("localhost")
                    || s.trim_matches(['[', ']'])
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
            if parsed.scheme() != "https" && !(parsed.scheme() == "http" && local) {
                return Err("storage: insecure endpoint requires explicit https:// (http:// is loopback-only)".into());
            }
            parsed.to_string().trim_end_matches('/').to_owned()
        };
        let mut store = Self::new(&normalized, region, bucket, access, secret)?;
        store.oss = provider == "oss";
        store.minio = matches!(provider, "s3" | "");
        Ok(store)
    }
    /// Preserve the Go AWS SDK's optional operation query tags for a caller
    /// whose recorded transport contract includes them.
    pub fn with_aws_operation_query(mut self) -> Self {
        self.aws_operation_query = true;
        self
    }
    /// An explicit profile may require an empty signing region (Go OSS).
    pub fn with_signing_region(mut self, region: String) -> Self {
        self.region = region;
        self
    }
    pub(crate) fn needs_source_metadata(&self) -> bool {
        self.local.is_none()
    }
    fn request(
        &self,
        method: Method,
        key: &str,
        payload: &str,
    ) -> Result<reqwest::RequestBuilder, String> {
        let mut url = self.endpoint.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| "invalid object store endpoint")?;
            segments.clear().push(&self.bucket);
            for part in key.split('/') {
                segments.push(part);
            }
        }
        if self.aws_operation_query {
            let operation = match method {
                Method::GET => "GetObject",
                Method::HEAD => "HeadObject",
                Method::PUT => "PutObject",
                Method::DELETE => "DeleteObject",
                _ => return Err("unsupported S3 migration operation".into()),
            };
            url.query_pairs_mut().append_pair("x-id", operation);
        }
        if self.oss {
            return self.oss_request(method, url);
        }
        let now = chrono::Utc::now();
        let date = now.format("%Y%m%d").to_string();
        let time = now.format("%Y%m%dT%H%M%SZ").to_string();
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let host = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap()),
            None => url.host_str().unwrap().into(),
        };
        let signed = "host;x-amz-content-sha256;x-amz-date";
        let headers = format!("host:{host}\nx-amz-content-sha256:{payload}\nx-amz-date:{time}\n");
        let query = if self.aws_operation_query {
            url.query().unwrap_or("")
        } else {
            ""
        };
        let canonical = format!(
            "{}\n{}\n{query}\n{headers}\n{signed}\n{payload}",
            method.as_str(),
            url.path()
        );
        let key = hmac(
            &hmac(
                &hmac(
                    &hmac(format!("AWS4{}", self.secret).as_bytes(), date.as_bytes()),
                    self.region.as_bytes(),
                ),
                b"s3",
            ),
            b"aws4_request",
        );
        let signature = hex(&hmac(
            &key,
            format!(
                "AWS4-HMAC-SHA256\n{time}\n{scope}\n{}",
                digest(canonical.as_bytes())
            )
            .as_bytes(),
        ));
        Ok(self.client.request(method,url).header("x-amz-date",time).header("x-amz-content-sha256",payload).header("Authorization",format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",self.access)))
    }
    fn oss_request(
        &self,
        method: Method,
        url: url::Url,
    ) -> Result<reqwest::RequestBuilder, String> {
        let now = chrono::Utc::now();
        let date = now.format("%Y%m%d").to_string();
        let time = now.format("%Y%m%dT%H%M%SZ").to_string();
        let payload = "UNSIGNED-PAYLOAD";
        let scope = format!("{date}/{}/oss/aliyun_v4_request", self.region);
        let content = if method == Method::PUT {
            "content-type:application/octet-stream\n"
        } else {
            ""
        };
        let headers = format!("{content}x-oss-content-sha256:{payload}\nx-oss-date:{time}\n");
        let canonical = format!(
            "{}\n{}\n\n{headers}\n\n{payload}",
            method.as_str(),
            url.path()
        );
        let key = hmac(
            &hmac(
                &hmac(
                    &hmac(
                        format!("aliyun_v4{}", self.secret).as_bytes(),
                        date.as_bytes(),
                    ),
                    self.region.as_bytes(),
                ),
                b"oss",
            ),
            b"aliyun_v4_request",
        );
        let signature = hex(&hmac(
            &key,
            format!(
                "OSS4-HMAC-SHA256\n{time}\n{scope}\n{}",
                digest(canonical.as_bytes())
            )
            .as_bytes(),
        ));
        Ok(self
            .client
            .request(method, url)
            .header("x-oss-date", time)
            .header("x-oss-content-sha256", payload)
            .header(
                "Authorization",
                format!(
                    "OSS4-HMAC-SHA256 Credential={}/{scope},Signature={signature}",
                    self.access
                ),
            ))
    }
    async fn checked(
        &self,
        response: Result<Response, reqwest::Error>,
        key: &str,
    ) -> Result<Response, String> {
        let response = response.map_err(|e| format!("object store request: {e}"))?;
        if response.status().is_success() {
            Ok(response)
        } else {
            let status = response.status();
            let message = response.text().await.unwrap_or_default();
            Err(format!(
                "s3://{}/{key}: HTTP {}: {}",
                self.bucket,
                status.as_u16(),
                message.trim()
            ))
        }
    }
    pub async fn put_file(&self, key: &str, path: &Path) -> Result<(), String> {
        if let Some(local) = &self.local {
            let stage = local.stage(key)?;
            tokio::fs::copy(path, &stage.temp)
                .await
                .map_err(|e| e.to_string())?;
            return stage.commit().await;
        }
        let owned = path.to_owned();
        let (hash, size) = tokio::task::spawn_blocking(move || crate::file_digest(&owned))
            .await
            .map_err(|e| e.to_string())??;
        let file = tokio::fs::File::open(path)
            .await
            .map_err(|e| e.to_string())?;
        let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file));
        self.checked(
            self.request(Method::PUT, key, &hash)?
                .header("Content-Type", "application/octet-stream")
                .header("Content-Length", size)
                .body(body)
                .send()
                .await,
            key,
        )
        .await?;
        Ok(())
    }
    pub async fn put(&self, key: &str, data: Vec<u8>) -> Result<(), String> {
        if let Some(local) = &self.local {
            use tokio::io::AsyncWriteExt;
            let mut stage = local.stage(key)?;
            stage
                .file
                .write_all(&data)
                .await
                .map_err(|e| e.to_string())?;
            return stage.commit().await;
        }
        self.checked(
            self.request(Method::PUT, key, &digest(&data))?
                .header("Content-Type", "application/octet-stream")
                .body(data)
                .send()
                .await,
            key,
        )
        .await?;
        Ok(())
    }
    pub async fn get_file(&self, key: &str, path: &Path) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;
        if let Some(local) = &self.local {
            tokio::fs::copy(local.path(key, true)?, path)
                .await
                .map_err(|e| e.to_string())?;
            return tokio::fs::File::open(path)
                .await
                .map_err(|e| e.to_string())?
                .sync_all()
                .await
                .map_err(|e| e.to_string());
        }
        let mut response = self
            .checked(
                self.request(Method::GET, key, &digest(b""))?.send().await,
                key,
            )
            .await?;
        let mut out = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .await
            .map_err(|e| e.to_string())?;
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            out.write_all(&chunk).await.map_err(|e| e.to_string())?;
        }
        out.sync_all().await.map_err(|e| e.to_string())
    }
    pub async fn get(&self, key: &str, limit: usize) -> Result<Vec<u8>, String> {
        if let Some(local) = &self.local {
            use tokio::io::AsyncReadExt;
            let file = tokio::fs::File::open(local.path(key, true)?)
                .await
                .map_err(|e| e.to_string())?;
            let mut data = vec![];
            file.take((limit as u64).saturating_add(1))
                .read_to_end(&mut data)
                .await
                .map_err(|e| e.to_string())?;
            if data.len() > limit {
                return Err("recovery component exceeds size limit".into());
            }
            return Ok(data);
        }
        let mut response = self
            .checked(
                self.request(Method::GET, key, &digest(b""))?.send().await,
                key,
            )
            .await?;
        let mut data = vec![];
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if chunk.len() > limit.saturating_sub(data.len()) {
                return Err("recovery component exceeds size limit".into());
            }
            data.extend_from_slice(&chunk);
        }
        Ok(data)
    }
    pub async fn head(&self, key: &str) -> Result<u64, String> {
        if let Some(local) = &self.local {
            return tokio::fs::metadata(local.path(key, true)?)
                .await
                .map(|m| m.len())
                .map_err(|e| e.to_string());
        }
        let r = self
            .checked(
                self.request(Method::HEAD, key, &digest(b""))?.send().await,
                key,
            )
            .await?;
        r.headers()
            .get("Content-Length")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok())
            .ok_or("object size unavailable".into())
    }
    /// Stream a primary object directly to its destination. Integrity is checked
    /// by re-reading the committed content-addressed object before publication.
    pub async fn copy_from(&self, source: &Self, key: &str, size: u64) -> Result<(), String> {
        if let Some(local) = &self.local {
            let stage = local.stage(key)?;
            source.get_file(key, &stage.temp).await?;
            return stage.commit().await;
        }
        if let Some(local) = &source.local {
            return self.put_file(key, &local.path(key, true)?).await;
        }
        // Frozen aws-sdk-go-v2 hashes a seekable source before rewinding it
        // for upload. Keep that streamed pre-read, without a spool or buffer.
        let payload = if !self.minio && !self.oss {
            source.body_digest(key).await?.0
        } else {
            "UNSIGNED-PAYLOAD".into()
        };
        let response = source
            .checked(
                source.request(Method::GET, key, &digest(b""))?.send().await,
                key,
            )
            .await?;
        let body = reqwest::Body::wrap_stream(response.bytes_stream());
        self.checked(
            self.request(Method::PUT, key, &payload)?
                .header("Content-Type", "application/octet-stream")
                .header("Content-Length", size)
                .body(body)
                .send()
                .await,
            key,
        )
        .await?;
        Ok(())
    }
    pub async fn body_digest(&self, key: &str) -> Result<(String, u64), String> {
        use sha2::{Digest, Sha256};
        if let Some(local) = &self.local {
            let path = local.path(key, true)?;
            return tokio::task::spawn_blocking(move || crate::file_digest(&path))
                .await
                .map_err(|e| e.to_string())?;
        }
        let mut response = self
            .checked(
                self.request(Method::GET, key, &digest(b""))?.send().await,
                key,
            )
            .await?;
        let mut hash = Sha256::new();
        let mut size = 0;
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            size += chunk.len() as u64;
            hash.update(&chunk);
        }
        Ok((hex(&hash.finalize()), size))
    }
    pub async fn delete(&self, key: &str) -> Result<(), String> {
        if let Some(local) = &self.local {
            return match tokio::fs::remove_file(local.path(key, true)?).await {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.to_string()),
            };
        }
        self.checked(
            self.request(Method::DELETE, key, &digest(b""))?
                .send()
                .await,
            key,
        )
        .await?;
        Ok(())
    }
}
