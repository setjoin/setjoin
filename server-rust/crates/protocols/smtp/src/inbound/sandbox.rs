//! CAPE's HTTP adapter. A pipeline deadline includes submission and every poll.
use serde_json::Value;
use std::time::Duration;

#[derive(Clone)]
pub struct Config {
    pub url: String,
    pub api_key: String,
    pub timeout: Duration,
    pub fail_closed: bool,
}
pub(crate) struct Cape {
    config: Config,
    client: Result<reqwest::Client, reqwest::Error>,
}
impl Cape {
    pub fn new(mut config: Config) -> Self {
        config.url = config.url.trim_end_matches('/').to_owned();
        let client = reqwest::Client::builder().timeout(config.timeout).build();
        Self { config, client }
    }
    fn request(&self, method: reqwest::Method, path: &str) -> Result<reqwest::RequestBuilder, ()> {
        Ok(self
            .client
            .as_ref()
            .map_err(|_| ())?
            .request(method, format!("{}{path}", self.config.url))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Token {}", self.config.api_key),
            ))
    }
    pub async fn health(&self) {
        if let Ok(request) = self.request(reqwest::Method::GET, "/apiv2/tasks/status/health/") {
            // Like Go, an unhealthy startup does not remove the analyzer.
            let _ = request.send().await;
        }
    }
    /// None is clean, false is suspicious, true is malicious (including fail-closed).
    pub async fn analyze(&self, data: &[u8]) -> Option<(bool, String)> {
        match tokio::time::timeout(self.config.timeout, self.run(data)).await {
            Ok(Ok(verdict)) => verdict,
            _ if self.config.fail_closed => Some((true, String::new())),
            _ => None,
        }
    }
    async fn run(&self, data: &[u8]) -> Result<Option<(bool, String)>, ()> {
        let file = reqwest::multipart::Part::bytes(data.to_vec())
            .file_name("attachment.bin")
            .mime_str("application/octet-stream")
            .map_err(|_| ())?;
        let response = self
            .request(reqwest::Method::POST, "/apiv2/tasks/create/file/")?
            .multipart(reqwest::multipart::Form::new().part("file", file))
            .send()
            .await
            .map_err(|_| ())?;
        if response.status().as_u16() >= 300 {
            return Err(());
        }
        let body: Value =
            serde_json::from_slice(&response.bytes().await.map_err(|_| ())?).map_err(|_| ())?;
        object(&body)?;
        let id = field(&body, "task_id")
            .as_i64()
            .filter(|id| *id != 0)
            .ok_or(())?;
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(3),
            Duration::from_secs(3),
        );
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let response = self
                .request(reqwest::Method::GET, &format!("/apiv2/tasks/view/{id}"))?
                .send()
                .await
                .map_err(|_| ())?;
            // Frozen Go decodes view bodies without checking the HTTP status.
            let body: Value =
                serde_json::from_slice(&response.bytes().await.map_err(|_| ())?).map_err(|_| ())?;
            object(&body)?;
            let task = field(&body, "task");
            let info = field(&body, "info");
            object(task)?;
            object(info)?;
            let status = string(field(task, "status"))?;
            let id = field(task, "id");
            if !id.is_null() && id.as_i64().is_none() {
                return Err(());
            }
            let score = field(info, "score");
            let score = if score.is_null() {
                0.0
            } else {
                score.as_f64().ok_or(())?
            };
            let signatures = field(info, "signatures");
            let mut family = "";
            if !signatures.is_null() {
                for value in signatures.as_array().ok_or(())? {
                    family = string(value)?;
                }
            }
            match status {
                "reported" | "completed" => {
                    return Ok(if score <= 3.0 {
                        None
                    } else {
                        Some((score >= 7.0, family.to_owned()))
                    })
                }
                "failed_analysis" | "failed_processing" | "failed_reporting" => return Err(()),
                _ => {}
            }
        }
    }
}
fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    value
        .get(name)
        .or_else(|| {
            value
                .as_object()?
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v)
        })
        .unwrap_or(&Value::Null)
}
fn object(value: &Value) -> Result<(), ()> {
    if value.is_null() || value.is_object() {
        Ok(())
    } else {
        Err(())
    }
}
fn string(value: &Value) -> Result<&str, ()> {
    if value.is_null() {
        Ok("")
    } else {
        value.as_str().ok_or(())
    }
}

pub(crate) fn risky(data: &[u8]) -> bool {
    const TYPES: &[&str] = &[
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument",
        "application/vnd.ms-",
        "application/x-msdownload",
        "application/x-dosexec",
        "application/x-mach-binary",
        "application/x-elf",
        "application/x-executable",
        "application/zip",
        "application/x-rar-compressed",
        "application/x-7z-compressed",
        "application/x-tar",
        "application/gzip",
        "application/x-bzip2",
        "application/x-iso9660-image",
        "application/x-ole-storage",
        "application/x-java-archive",
    ];
    let lower = setjoin_mime::go_lossy(data).to_lowercase();
    let mut rest = lower.as_str();
    while let Some((_, tail)) = rest.split_once("content-type:") {
        let value = tail.trim_start_matches([' ', '\t']);
        let end = value.find(['\r', '\n', ';']).unwrap_or(value.len());
        if TYPES.iter().any(|t| value[..end].trim().starts_with(t)) {
            return true;
        }
        rest = if end < value.len() {
            &value[end + 1..]
        } else {
            ""
        };
    }
    false
}
