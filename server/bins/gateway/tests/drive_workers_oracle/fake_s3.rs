//! A stateful in-memory fake S3 for the Drive worker oracle (#409). It answers
//! bucket-location probes, ListObjectsV2 (prefix, start-after, max-keys,
//! continuation token, `encoding-type=url`), object GET/PUT/DELETE and
//! `PUT ?retention`, and logs every request that is not a location probe.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct State {
    objects: BTreeMap<String, (Vec<u8>, String)>,
    log: Vec<Value>,
    reject_delete: Vec<String>,
    reject_put: bool,
    /// `key -> remaining refusals`: the first N deletes of a key fail.
    flaky_delete: BTreeMap<String, u32>,
    reject_retention: Vec<String>,
    deny_list: bool,
}

pub struct DriveS3 {
    pub addr: std::net::SocketAddr,
    state: Arc<Mutex<State>>,
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&text[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_pairs(query: &str) -> BTreeMap<String, String> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (percent_decode(k), percent_decode(&v.replace('+', " ")))
        })
        .collect()
}

fn url_encode(key: &str) -> String {
    key.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn xml(status: u16, body: String) -> hyper::Response<crate::common::TestBody> {
    hyper::Response::builder()
        .status(status)
        .header("Content-Type", "application/xml")
        .body(crate::common::full(body))
        .unwrap()
}

fn error(status: u16, code: &str) -> hyper::Response<crate::common::TestBody> {
    xml(
        status,
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{code}</Message><Resource>/</Resource><RequestId>fake</RequestId></Error>"),
    )
}

/// Payload of an `aws-chunked` upload.
fn dechunk(mut framed: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(line_end) = framed.windows(2).position(|w| w == b"\r\n") {
        let header = String::from_utf8_lossy(&framed[..line_end]).into_owned();
        let size = usize::from_str_radix(header.split(';').next().unwrap_or("0"), 16).unwrap_or(0);
        framed = &framed[line_end + 2..];
        if size == 0 || framed.len() < size {
            break;
        }
        out.extend_from_slice(&framed[..size]);
        framed = framed.get(size + 2..).unwrap_or_default();
    }
    out
}

impl DriveS3 {
    pub async fn start() -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        let shared = state.clone();
        let addr = crate::common::fake_upstream(move |request| {
            let state = shared.clone();
            async move {
                use http_body_util::BodyExt;
                let (parts, body) = request.into_parts();
                let bytes = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                let query = parts.uri.query().unwrap_or("").to_owned();
                let pairs = query_pairs(&query);
                let path = percent_decode(parts.uri.path());
                let trimmed = path.trim_start_matches('/');
                let (bucket, key) = trimmed.split_once('/').unwrap_or((trimmed, ""));
                let _ = bucket;
                let mut s = state.lock().unwrap();
                if parts.method == hyper::Method::GET && pairs.contains_key("location") {
                    return xml(200, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">us-east-1</LocationConstraint>".into());
                }
                let mut entry = json!({"method": parts.method.as_str(), "path": path});
                if !pairs.is_empty() {
                    entry["query"] = json!(pairs);
                }
                if parts.method == hyper::Method::GET && key.is_empty() {
                    s.log.push(entry);
                    if s.deny_list {
                        return error(403, "AccessDenied");
                    }
                    let prefix = pairs.get("prefix").cloned().unwrap_or_default();
                    let after = pairs
                        .get("continuation-token")
                        .or_else(|| pairs.get("start-after"))
                        .cloned()
                        .unwrap_or_default();
                    let max: usize = pairs
                        .get("max-keys")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(1000);
                    let encode = pairs.get("encoding-type").is_some_and(|v| v == "url");
                    let matching: Vec<_> = s
                        .objects
                        .iter()
                        .filter(|(k, _)| k.starts_with(&prefix) && k.as_str() > after.as_str())
                        .collect();
                    let truncated = matching.len() > max;
                    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>mailblobs</Name><Prefix></Prefix>");
                    out.push_str(&format!("<KeyCount>{}</KeyCount><MaxKeys>{max}</MaxKeys><IsTruncated>{truncated}</IsTruncated>", matching.len().min(max)));
                    if encode {
                        out.push_str("<EncodingType>url</EncodingType>");
                    }
                    let page: Vec<_> = matching.into_iter().take(max).collect();
                    for (k, (body, modified)) in &page {
                        let shown = if encode { url_encode(k) } else { (*k).clone() };
                        out.push_str(&format!("<Contents><Key>{shown}</Key><LastModified>{modified}</LastModified><ETag>&quot;fake&quot;</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>", body.len()));
                    }
                    if truncated {
                        if let Some((last, _)) = page.last() {
                            out.push_str(&format!("<NextContinuationToken>{last}</NextContinuationToken>"));
                        }
                    }
                    out.push_str("</ListBucketResult>");
                    return xml(200, out);
                }
                match parts.method {
                    hyper::Method::GET | hyper::Method::HEAD => {
                        s.log.push(entry);
                        match s.objects.get(key) {
                            Some((body, modified)) => hyper::Response::builder()
                                .status(200)
                                .header("Content-Length", body.len())
                                .header("ETag", "\"fake\"")
                                .header("Last-Modified", chrono::DateTime::parse_from_rfc3339(modified).map(|t| t.with_timezone(&chrono::Utc).format("%a, %d %b %Y %H:%M:%S GMT").to_string()).unwrap_or_default())
                                .body(if parts.method == hyper::Method::HEAD { crate::common::full("") } else { crate::common::full(body.clone()) })
                                .unwrap(),
                            None => error(404, "NoSuchKey"),
                        }
                    }
                    hyper::Method::DELETE => {
                        s.log.push(entry);
                        if s.reject_delete.iter().any(|k| k == key) {
                            return error(403, "AccessDenied");
                        }
                        if let Some(left) = s.flaky_delete.get_mut(key).filter(|n| **n > 0) {
                            *left -= 1;
                            return error(403, "AccessDenied");
                        }
                        s.objects.remove(key);
                        hyper::Response::builder().status(204).body(crate::common::full("")).unwrap()
                    }
                    hyper::Method::PUT => {
                        let streaming = parts
                            .headers
                            .get("x-amz-content-sha256")
                            .is_some_and(|v| v == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
                        let body = if streaming { dechunk(&bytes) } else { bytes.to_vec() };
                        if pairs.contains_key("retention") {
                            entry["body"] = json!(String::from_utf8_lossy(&body));
                            s.log.push(entry);
                            if s.reject_retention.iter().any(|k| k == key) {
                                return error(403, "AccessDenied");
                            }
                            return hyper::Response::builder().status(200).body(crate::common::full("")).unwrap();
                        }
                        entry["content_type"] = json!(parts.headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or(""));
                        entry["body_sha256"] = json!(format!("{:x}", Sha256::digest(&body)));
                        entry["body_len"] = json!(body.len());
                        s.log.push(entry);
                        if s.reject_put { return error(403,"AccessDenied"); }
                        s.objects.insert(key.to_owned(), (body, chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)));
                        hyper::Response::builder().status(200).header("ETag", "\"fake\"").body(crate::common::full("")).unwrap()
                    }
                    _ => error(405, "MethodNotAllowed"),
                }
            }
        })
        .await;
        Self { addr, state }
    }

    pub fn reset(&self) {
        *self.state.lock().unwrap() = State::default();
    }

    /// Add an object last modified `age_secs` ago.
    pub fn put(&self, key: &str, body: &[u8], age_secs: i64) {
        let modified = (chrono::Utc::now() - chrono::Duration::seconds(age_secs))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.state
            .lock()
            .unwrap()
            .objects
            .insert(key.to_owned(), (body.to_vec(), modified));
    }

    pub fn reject_put(&self) {
        self.state.lock().unwrap().reject_put = true;
    }

    pub fn reject_delete(&self, key: &str) {
        self.state
            .lock()
            .unwrap()
            .reject_delete
            .push(key.to_owned());
    }
    /// The first `times` deletes of `key` fail with a 500, later ones succeed.
    pub fn flaky_delete(&self, key: &str, times: u32) {
        self.state
            .lock()
            .unwrap()
            .flaky_delete
            .insert(key.to_owned(), times);
    }
    pub fn reject_retention(&self, key: &str) {
        self.state
            .lock()
            .unwrap()
            .reject_retention
            .push(key.to_owned());
    }
    pub fn deny_list(&self) {
        self.state.lock().unwrap().deny_list = true;
    }

    /// Requests since the last call, in arrival order.
    pub fn take_log(&self) -> Vec<Value> {
        std::mem::take(&mut self.state.lock().unwrap().log)
    }

    /// Keys still stored, sorted.
    pub fn keys(&self) -> Vec<String> {
        self.state.lock().unwrap().objects.keys().cloned().collect()
    }
}
