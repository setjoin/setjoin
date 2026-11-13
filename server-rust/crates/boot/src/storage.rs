//! Boot-time S3 operations use rust-s3's maintained SigV4 client.
use s3::{
    command::Command,
    request::{tokio_backend::ReqwestRequest, Request},
};

pub(crate) struct Store {
    bucket: Box<s3::Bucket>,
    endpoint: String,
    region: tokio::sync::OnceCell<String>,
}
impl Store {
    pub fn from_env() -> Result<Self, String> {
        let configured = setting("S3_ENDPOINT", "MINIO_ENDPOINT", "127.0.0.1:9000");
        let endpoint = configured.trim();
        let secure = setting("S3_SECURE", "MINIO_SECURE", "false");
        let secure = secure == "true" || secure == "1";
        // Go's blob.NewMinIOClient first resolves transport, then hands a
        // scheme-less host to MinIO. cfg.S3Secure is an explicit bool there.
        let lower = endpoint.to_ascii_lowercase();
        let host = if lower.starts_with("https://") {
            if !secure {
                return Err("https endpoint conflicts with S3_SECURE=false".into());
            }
            &endpoint[8..]
        } else if lower.starts_with("http://") {
            if secure {
                return Err("http endpoint conflicts with S3_SECURE=true".into());
            }
            &endpoint[7..]
        } else {
            endpoint
        };
        let scheme = if secure { "https" } else { "http" };
        let parsed = reqwest::Url::parse(&format!("{scheme}://{host}"))
            .map_err(|error| error.to_string())?;
        if parsed.host_str().is_none()
            || !matches!(parsed.path(), "" | "/")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err("Endpoint url cannot have fully qualified paths.".into());
        }
        let hostname = parsed.host_str().unwrap().trim_matches(['[', ']']);
        let loopback = hostname.eq_ignore_ascii_case("localhost")
            || hostname
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| match ip {
                    std::net::IpAddr::V4(ip) => ip.is_loopback(),
                    std::net::IpAddr::V6(ip) => {
                        ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
                    }
                });
        if !secure && !loopback {
            return Err("plaintext storage requires a loopback peer".into());
        }
        let endpoint = format!("{scheme}://{host}");
        let access = setting("S3_ACCESS_KEY", "MINIO_ACCESS_KEY", "");
        let secret = setting("S3_SECRET_KEY", "MINIO_SECRET_KEY", "");
        let creds = if access.is_empty() && secret.is_empty() {
            s3::creds::Credentials::anonymous()
        } else {
            s3::creds::Credentials::new(Some(&access), Some(&secret), None, None, None)
        }
        .map_err(|e| e.to_string())?;
        let bucket = s3::Bucket::new(
            &setting("S3_BUCKET", "MINIO_BUCKET", "mailblobs"),
            s3::Region::Custom {
                region: "us-east-1".into(),
                endpoint: endpoint.clone(),
            },
            creds,
        )
        .map_err(|e| e.to_string())?
        .with_path_style();
        Ok(Self {
            bucket,
            endpoint,
            region: tokio::sync::OnceCell::new(),
        })
    }
    async fn located(&self) -> Result<s3::Bucket, String> {
        let region = self
            .region
            .get_or_try_init(|| async {
                #[derive(serde::Deserialize, Default)]
                #[serde(default)]
                struct Location {
                    #[serde(rename = "$text")]
                    region: String,
                }
                #[derive(serde::Deserialize, Default)]
                #[serde(default, rename_all = "PascalCase")]
                struct ErrorBody {
                    code: String,
                    region: String,
                }
                let mut location_bucket = (*self.bucket).clone();
                location_bucket.add_query("location", "");
                let response =
                    ReqwestRequest::new(&location_bucket, "", Command::GetBucketLocation)
                        .await
                        .map_err(|e| e.to_string())?
                        .response_data(false)
                        .await
                        .map_err(|e| e.to_string())?;
                let region = if response.status_code() == 200 {
                    quick_xml::de::from_reader::<_, Location>(response.as_slice())
                        .map_err(|e| e.to_string())?
                        .region
                } else {
                    let headers = response.headers();
                    let mut error = quick_xml::de::from_reader::<_, ErrorBody>(response.as_slice())
                        .unwrap_or_default();
                    if error.region.is_empty() {
                        error.region = headers
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-bucket-region"))
                            .map(|(_, v)| v.clone())
                            .unwrap_or_default();
                    }
                    let code = if error.code.is_empty() && response.status_code() == 403 {
                        "AccessDenied"
                    } else {
                        &error.code
                    };
                    match code {
                        "AccessDenied"
                        | "AuthorizationHeaderMalformed"
                        | "InvalidRegion"
                        | "NoSuchBucket" => error.region,
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
                        _ if response.status_code() == 404 => String::new(),
                        _ => return Err(format!("S3 bucket location failed: {code}")),
                    }
                };
                Ok::<_, String>(match region.as_str() {
                    "" => "us-east-1".into(),
                    "EU" => "eu-west-1".into(),
                    _ => region,
                })
            })
            .await?;
        let mut bucket = (*self.bucket).clone();
        bucket.region = s3::Region::Custom {
            region: region.clone(),
            endpoint: self.endpoint.clone(),
        };
        Ok(bucket)
    }
    async fn exists(&self) -> Result<bool, String> {
        let bucket = self.located().await?;
        let response = ReqwestRequest::new(&bucket, "", Command::HeadObject)
            .await
            .map_err(|e| e.to_string())?
            .response_data(false)
            .await
            .map_err(|e| e.to_string())?;
        match response.status_code() {
            200 => Ok(true),
            404 => Ok(false),
            status => Err(format!("S3 bucket probe returned {status}")),
        }
    }
    async fn create(&self, lock: bool) -> Result<(), String> {
        let mut bucket = self.located().await?;
        if lock {
            bucket
                .extra_headers
                .insert("x-amz-bucket-object-lock-enabled", "true".parse().unwrap());
        }
        let response = ReqwestRequest::new(
            &bucket,
            "",
            Command::CreateBucket {
                config: s3::BucketConfiguration::default(),
            },
        )
        .await
        .map_err(|e| e.to_string())?
        .response_data(false)
        .await
        .map_err(|e| e.to_string())?;
        if (200..300).contains(&response.status_code()) {
            Ok(())
        } else {
            Err(format!(
                "S3 bucket create returned {}",
                response.status_code()
            ))
        }
    }
    pub async fn ensure_worm_bucket(&self) -> Result<(), String> {
        if !self.exists().await? {
            crate::log(
                "INFO",
                "WORM-configured first boot: creating blob bucket with Object Lock enabled",
            );
            self.create(true).await?;
        }
        Ok(())
    }
    pub async fn abort_stale(&self) -> Result<(), String> {
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(1);
        let bucket = self.located().await?;
        let pages = bucket
            .list_multiparts_uploads(None, None)
            .await
            .map_err(|e| e.to_string())?;
        let mut aborted = 0;
        for page in pages {
            for upload in page.uploads {
                let initiated = chrono::DateTime::parse_from_rfc3339(&upload.initiated)
                    .map_err(|e| e.to_string())?;
                if initiated >= cutoff {
                    continue;
                }
                // Go RemoveIncompleteUpload finds ALL IDs for this exact key,
                // including recent ones. Preserve that frozen behavior.
                let removal = async {
                    let matches = bucket
                        .list_multiparts_uploads(Some(&upload.key), None)
                        .await
                        .map_err(|e| e.to_string())?;
                    for page in matches {
                        for item in page
                            .uploads
                            .into_iter()
                            .filter(|item| item.key == upload.key)
                        {
                            bucket
                                .abort_upload(&item.key, &item.id)
                                .await
                                .map_err(|e| e.to_string())?;
                        }
                    }
                    Ok::<_, String>(())
                }
                .await;
                if removal.is_err() {
                    crate::log("WARN", "failed to abort stale multipart upload");
                    continue;
                }
                aborted += 1;
                crate::log("INFO", "aborted stale multipart upload");
            }
        }
        if aborted > 0 {
            crate::log("INFO", "startup: aborted stale MinIO multipart uploads");
        }
        Ok(())
    }
    pub async fn ping(&self, db: &setjoin_pg::workers::WorkerConnection) {
        use setjoin_pg::Type;
        let name = self.bucket.name();
        let result = self.exists().await;
        let mut status = "ok";
        let mut details = format!("MinIO reachable, bucket {name:?} exists");
        match result {
            Ok(true) => {}
            Ok(false) => {
                crate::log("INFO", "blob bucket missing, creating");
                if let Err(error) = self.create(false).await {
                    status = "error";
                    details =
                        format!("MinIO reachable but bucket {name:?} creation failed: {error}");
                } else {
                    details = format!("MinIO reachable, bucket {name:?} created on first run");
                }
            }
            Err(error) => {
                status = "error";
                details = format!("MinIO ping failed: {error}");
            }
        }
        if db
            .execute(
                "INSERT INTO health_history (check_name,status,details) VALUES ($1,$2,$3)",
                &[
                    (&"minio_connectivity", Type::TEXT),
                    (&status, Type::TEXT),
                    (&details, Type::TEXT),
                ],
            )
            .await
            .is_err()
        {
            crate::log(
                "WARN",
                "failed to record MinIO health check in health_history",
            );
        }
        if status == "error" {
            crate::log(
                "WARN",
                "startup: MinIO ping failed — blobs unavailable until MinIO is reachable",
            );
        } else {
            crate::log("INFO", "MinIO startup check passed");
        }
    }
    pub async fn init_worm(&self, mode: &str, days: i64) -> Result<(), String> {
        use base64::Engine;
        use md5::{Digest, Md5};
        if mode.is_empty() {
            crate::log("INFO", "WORM immutability: disabled (WORM_MODE not set)");
            return Ok(());
        }
        if !matches!(mode, "compliance" | "governance") || days < 1 {
            crate::log("ERROR", "WORM configuration invalid");
            return Err("invalid WORM mode/retention".into());
        }
        let xml = format!("<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>{}</Mode><Days>{days}</Days></DefaultRetention></Rule></ObjectLockConfiguration>",mode.to_ascii_uppercase());
        let applied = async {
            let mut bucket = self.located().await?;
            bucket
                .extra_query
                .insert("object-lock".into(), String::new());
            bucket.extra_headers.insert(
                "content-md5",
                base64::engine::general_purpose::STANDARD
                    .encode(Md5::digest(xml.as_bytes()))
                    .parse()
                    .unwrap(),
            );
            let response = ReqwestRequest::new(
                &bucket,
                "",
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
            .await
            .map_err(|e| e.to_string())?;
            if (200..300).contains(&response.status_code()) {
                Ok(())
            } else {
                Err(format!(
                    "S3 object-lock policy returned {}",
                    response.status_code()
                ))
            }
        }
        .await;
        if let Err(error) = applied {
            crate::log(
                "ERROR",
                "WORM startup check failed — gateway cannot start without compliant storage",
            );
            return Err(error);
        }
        if days < 2557 {
            crate::log("WARN", "WORM retention is below the regulatory minimum of 2557 days (7 years) — this may not satisfy SEC 17a-4(f) / FINRA 4511(c) requirements");
        }
        crate::log("INFO", "WORM immutability: active");
        Ok(())
    }
}

fn setting(primary: &str, legacy: &str, default: &str) -> String {
    std::env::var(primary)
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var(legacy).ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| default.into())
}
