//! Owned loopback peers for the push-drain oracle: the Python push/OAuth peer
//! (a child process) and an in-process fake object store.
use crate::drain_oracle::{self, BoxError};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

pub struct PushPeer {
    child: std::process::Child,
    dir: std::path::PathBuf,
    pub port: u16,
}

impl PushPeer {
    pub fn start() -> Result<Self, BoxError> {
        let root = drain_oracle::repo_root()?;
        let dir = root.join(format!(
            "test-results/gofree-drainw/peer-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)?;
        let child = std::process::Command::new("python3")
            .arg("-I")
            .arg(root.join("server-rust/tests/conformance/drain/push_peer.py"))
            .arg(&dir)
            .spawn()?;
        let mut peer = Self {
            child,
            dir,
            port: 0,
        };
        for _ in 0..100 {
            if let Ok(text) = std::fs::read_to_string(peer.dir.join("ready.json")) {
                peer.port = serde_json::from_str::<Value>(&text)?["port"]
                    .as_u64()
                    .ok_or("peer port")? as u16;
                return Ok(peer);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Err("push peer did not start".into())
    }
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
    /// Requests since the last call, in arrival order.
    pub fn take(&self) -> Result<Vec<Value>, BoxError> {
        let path = self.dir.join("requests.jsonl");
        let text = std::fs::read_to_string(&path)?;
        std::fs::write(&path, "")?;
        text.lines()
            .map(|line| Ok(serde_json::from_str(line)?))
            .collect()
    }
}

impl Drop for PushPeer {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A fake S3 that accepts bucket-location probes and object PUTs and records
/// each PUT (path, content type, body).
pub struct FakeS3 {
    pub addr: std::net::SocketAddr,
    puts: Arc<Mutex<Vec<Value>>>,
    reject: Arc<std::sync::atomic::AtomicBool>,
}

impl FakeS3 {
    pub async fn start() -> Self {
        let puts = Arc::new(Mutex::new(Vec::new()));
        let seen = puts.clone();
        let reject = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let rejecting = reject.clone();
        let addr = crate::common::fake_upstream(move |request| {
            let seen = seen.clone();
            let rejecting = rejecting.clone();
            async move {
                use http_body_util::BodyExt;
                let (parts, body) = request.into_parts();
                let bytes = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                let query = parts.uri.query().unwrap_or("");
                if parts.method == hyper::Method::GET && query.starts_with("location") {
                    return hyper::Response::builder()
                        .status(200)
                        .body(crate::common::full(
                            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">us-east-1</LocationConstraint>",
                        ))
                        .unwrap();
                }
                if parts.method == hyper::Method::PUT {
                    let content_type = parts
                        .headers
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    let streaming = parts
                        .headers
                        .get("x-amz-content-sha256")
                        .is_some_and(|v| v == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
                    let bytes = if streaming { dechunk(&bytes) } else { bytes.to_vec() };
                    seen.lock().unwrap().push(json!({
                        "path": parts.uri.path(),
                        "content_type": content_type,
                        "body": String::from_utf8_lossy(&bytes),
                    }));
                    if rejecting.load(std::sync::atomic::Ordering::Relaxed) {
                        return hyper::Response::builder()
                            .status(403)
                            .body(crate::common::full(
                                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>AccessDenied</Code><Message>denied</Message></Error>",
                            ))
                            .unwrap();
                    }
                    return hyper::Response::builder()
                        .status(200)
                        .header("ETag", "\"fake\"")
                        .body(crate::common::full(""))
                        .unwrap();
                }
                hyper::Response::builder()
                    .status(404)
                    .body(crate::common::full(""))
                    .unwrap()
            }
        })
        .await;
        Self { addr, puts, reject }
    }
    /// Answer every object PUT with 403 AccessDenied (the PUT is still recorded).
    pub fn reject_puts(&self, reject: bool) {
        self.reject
            .store(reject, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn take(&self) -> Vec<Value> {
        std::mem::take(&mut self.puts.lock().unwrap())
    }
}

/// Payload of an `aws-chunked` upload (Go's MinIO client signs streaming
/// bodies; the framing is a transport detail, the object bytes are compared).
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
