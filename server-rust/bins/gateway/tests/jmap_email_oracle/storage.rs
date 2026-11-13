//! Stateful S3 seam; independently verifies Go/Rust SigV4 before applying effects.
use super::common;
use http_body_util::BodyExt;
use hyper::{Method, Response};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
#[path = "../common/office_s3.rs"]
mod signature;
#[derive(Default)]
struct State {
    objects: BTreeMap<String, Vec<u8>>,
    log: Vec<Value>,
    errors: Vec<String>,
}
pub struct Storage {
    pub addr: SocketAddr,
    state: Arc<Mutex<State>>,
}
impl Storage {
    pub async fn start() -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        let shared = state.clone();
        let addr=common::fake_upstream(move |request| {let state=shared.clone();async move {
            let (parts,body)=request.into_parts();let bytes=body.collect().await.unwrap().to_bytes();
            let request=hyper::Request::from_parts(parts,());
            let observed=signature::observe(&request,&bytes);
            let mut s=state.lock().unwrap();
            if let Err(e)=observed {s.errors.push(e);return error(403,"SignatureDoesNotMatch");}
            if request.uri().query()==Some("location=") {return Response::builder().header("content-type","application/xml").body(common::full("<LocationConstraint>us-east-1</LocationConstraint>")).unwrap();}
            let path=String::from_utf8_lossy(&unescape(request.uri().path())).into_owned();
            let key=path.strip_prefix("/mailblobs/").unwrap_or(&path);
            let named=if key.starts_with("tmp/upload/"){"<temporary>"}else{key};
            match *request.method() {
                Method::PUT=>{
                    if let Some(source)=request.headers().get("x-amz-copy-source").and_then(|v|v.to_str().ok()) {
                        let source=String::from_utf8_lossy(&unescape(source)).into_owned();
                        let source=source.trim_start_matches('/').strip_prefix("mailblobs/").unwrap_or(&source);
                        let Some(body)=s.objects.get(source).cloned() else{return error(404,"NoSuchKey");};
                        s.objects.insert(key.into(),body);
                        s.log.push(json!({"operation":"promote","key":named,"source":"<temporary>"}));
                        return Response::builder().header("content-type","application/xml").body(common::full("<CopyObjectResult><LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>\"fake\"</ETag></CopyObjectResult>")).unwrap();
                    }
                    let body=if request.headers().get("x-amz-content-sha256").is_some_and(|v|v=="STREAMING-AWS4-HMAC-SHA256-PAYLOAD") {dechunk(&bytes)}else{bytes.to_vec()};
                    s.log.push(json!({"operation":"put","key":named,"size":body.len(),"sha256":format!("{:x}",Sha256::digest(&body)),"type":request.headers().get("content-type").and_then(|v|v.to_str().ok()).unwrap_or("")}));
                    s.objects.insert(key.into(),body);
                    Response::builder().header("etag","\"fake\"").body(common::full("")).unwrap()
                }
                Method::DELETE=>{s.objects.remove(key);s.log.push(json!({"operation":"delete","key":named}));Response::builder().status(204).body(common::full("")).unwrap()}
                Method::GET|Method::HEAD=>{
                    let Some(body)=s.objects.get(key) else{return error(404,"NoSuchKey");};
                    let len=body.len();let mut start=0;let mut end=len;let mut status=200;
                    if let Some(range)=request.headers().get("range").and_then(|v|v.to_str().ok()).and_then(|v|v.strip_prefix("bytes=")) {
                        if let Some((a,b))=range.split_once('-') {start=if a.is_empty(){len.saturating_sub(b.parse::<usize>().unwrap())}else{a.parse().unwrap()};end=if b.is_empty() || a.is_empty(){len}else{(b.parse::<usize>().unwrap()+1).min(len)};status=206;}
                    }
                    let mut r=Response::builder().status(status).header("content-length",end-start).header("etag","\"fake\"").header("last-modified","Thu, 01 Jan 2026 00:00:00 GMT");
                    if status==206 {r=r.header("content-range",format!("bytes {start}-{}/{len}",end-1));}
                    r.body(if request.method()==Method::HEAD {common::full("")}else{common::full(body[start..end].to_vec())}).unwrap()
                }
                _=>error(405,"MethodNotAllowed")
            }
        }}).await;
        Self { addr, state }
    }
    pub fn clear_log(&self) {
        let mut s = self.state.lock().unwrap();
        s.log.clear();
        s.errors.clear();
    }
    pub fn put(&self, key: &str, bytes: &[u8]) {
        self.state
            .lock()
            .unwrap()
            .objects
            .insert(key.into(), bytes.to_vec());
    }
    pub fn observe(&self) -> Result<Value, super::BoxError> {
        let s = self.state.lock().unwrap();
        if !s.errors.is_empty() {
            return Err(format!("invalid S3 request: {:?}", s.errors).into());
        }
        Ok(
            json!({"writes":s.log,"objects":s.objects.iter().map(|(key,body)|json!({"key":if key.starts_with("tmp/upload/"){"<temporary>"}else{key},"size":body.len(),"sha256":format!("{:x}",Sha256::digest(body))})).collect::<Vec<_>>()}),
        )
    }
}
fn error(status: u16, code: &str) -> Response<setjoin_gateway::Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/xml")
        .body(common::full(format!("<Error><Code>{code}</Code></Error>")))
        .unwrap()
}
fn dechunk(mut wire: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let end = wire.windows(2).position(|v| v == b"\r\n").unwrap();
        let line = std::str::from_utf8(&wire[..end]).unwrap();
        let size = usize::from_str_radix(line.split(';').next().unwrap(), 16).unwrap();
        wire = &wire[end + 2..];
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&wire[..size]);
        wire = &wire[size + 2..];
    }
}

fn unescape(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}
