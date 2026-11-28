//! F13 sub-router-a peripherals for the oracle: a fake LiveKit/Egress twirp
//! endpoint that records every call frozen Go (protobuf) or Rust (JSON) makes,
//! plus the LiveKit HS256 token helpers the tests sign and decode with.
#![allow(dead_code)]
use super::common;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64},
    Engine,
};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use hyper::Response;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

pub const KEY: &str = "meet2-key";
pub const SECRET: &str = "meet2-secret-meet2-secret-meet2-secret";

pub fn sign(claims: &Value, secret: &str) -> String {
    let head = B64.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let body = B64.encode(claims.to_string());
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{head}.{body}").as_bytes());
    format!("{head}.{body}.{}", B64.encode(mac.finalize().into_bytes()))
}

/// Verifies the signature and returns the claims, or None.
pub fn verify(token: &str, secret: &str) -> Option<Value> {
    let parts: Vec<&str> = token.split('.').collect();
    let [head, body, sig] = parts[..] else {
        return None;
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(format!("{head}.{body}").as_bytes());
    mac.verify_slice(&B64.decode(sig).ok()?).ok()?;
    serde_json::from_slice(&B64.decode(body).ok()?).ok()
}

/// A webhook token as LiveKit sends it: the bare JWT with the body digest.
pub fn webhook_token(body: &[u8], key: &str, secret: &str, offset: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + offset;
    sign(
        &json!({"iss":key,"nbf":now-5,"exp":now+600,"sha256":STANDARD.encode(Sha256::digest(body))}),
        secret,
    )
}

/// Replaces a minted join token by its verified, time-independent claims.
pub fn decode_join_token(token: &str) -> Value {
    let Some(mut claims) = verify(token, SECRET) else {
        return json!({"invalid-token": token});
    };
    let o = claims.as_object_mut().unwrap();
    let (iat, nbf, exp) = (o.remove("iat"), o.remove("nbf"), o.remove("exp"));
    let (iat, nbf, exp) = (
        iat.and_then(|v| v.as_i64()).unwrap_or(0),
        nbf.and_then(|v| v.as_i64()).unwrap_or(0),
        exp.and_then(|v| v.as_i64()).unwrap_or(0),
    );
    o.insert("ttl".into(), json!(exp - nbf));
    o.insert("iat_equals_nbf".into(), json!(iat == nbf));
    let header = token.split('.').next().unwrap();
    json!({"header": serde_json::from_slice::<Value>(&B64.decode(header).unwrap()).unwrap(), "claims": claims})
}

/// Walks a response body replacing every `token` by its decoded claims.
pub fn decode_tokens(value: &mut Value) {
    match value {
        Value::Object(o) => {
            for (k, v) in o.iter_mut() {
                if k == "token" && v.is_string() {
                    *v = decode_join_token(v.as_str().unwrap());
                } else {
                    decode_tokens(v);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(decode_tokens),
        _ => {}
    }
}

#[derive(Clone)]
pub struct Fake {
    pub addr: SocketAddr,
    calls: Arc<Mutex<Vec<Value>>>,
    fail: Arc<Mutex<Option<String>>>,
    code: Arc<Mutex<(u16, String)>>,
}

/// The egress id the fake answers a recording start with.
pub const FAKE_EGRESS: &str = "EG_meet3_fake";

impl Fake {
    /// Makes the next calls of `method` answer a twirp `not_found` error.
    pub fn fail(&self, method: Option<&str>) {
        *self.fail.lock().unwrap() = method.map(str::to_owned);
        *self.code.lock().unwrap() = (404, "not_found".into());
    }

    /// Makes the next calls of `method` answer the given twirp error.
    pub fn fail_with(&self, method: &str, status: u16, code: &str) {
        *self.fail.lock().unwrap() = Some(method.to_owned());
        *self.code.lock().unwrap() = (status, code.to_owned());
    }

    /// Everything recorded since the last drain, in arrival order.
    pub fn drain(&self) -> Vec<Value> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }

    pub async fn start() -> Fake {
        let calls: Arc<Mutex<Vec<Value>>> = Arc::default();
        let fail: Arc<Mutex<Option<String>>> = Arc::default();
        let code: Arc<Mutex<(u16, String)>> = Arc::new(Mutex::new((404, "not_found".into())));
        let (c2, f2, k2) = (calls.clone(), fail.clone(), code.clone());
        let addr = common::fake_upstream(move |req| {
            let (calls, fail, code) = (c2.clone(), f2.clone(), k2.clone());
            async move {
                let path = req.uri().path().to_owned();
                let protobuf = req
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.contains("protobuf"));
                let auth = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .map(str::to_owned);
                let body = req.into_body().collect().await.unwrap().to_bytes();
                let method = path.rsplit('/').next().unwrap_or("").to_owned();
                let service = path.split('/').nth(2).unwrap_or("").to_owned();
                let recorded = matches!(
                    method.as_str(),
                    "CreateRoom"
                        | "RemoveParticipant"
                        | "DeleteRoom"
                        | "StopEgress"
                        | "StartRoomCompositeEgress"
                );
                if recorded {
                    let grant = match auth.as_deref().and_then(|t| verify(t, SECRET)) {
                        Some(claims) => {
                            assert_eq!(claims["iss"], KEY, "peripheral token issuer");
                            claims["video"].clone()
                        }
                        None => json!("invalid-token"),
                    };
                    let decoded = if protobuf {
                        proto_body(&method, &body)
                    } else {
                        let mut v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                        if let Value::Object(o) = &mut v {
                            o.retain(|_, v| {
                                !matches!(v, Value::Number(n) if n.as_i64() == Some(0))
                                    && v.as_str() != Some("")
                            });
                        }
                        v
                    };
                    let mut decoded = decoded;
                    // The sink's secret is a test credential, not a lobby secret:
                    // keep it visible to the oracle under its own name.
                    if let Some(files) =
                        decoded.get_mut("fileOutputs").and_then(Value::as_array_mut)
                    {
                        for file in files {
                            if let Some(s3) = file.get_mut("s3").and_then(Value::as_object_mut) {
                                if let Some(secret) = s3.remove("secret") {
                                    s3.insert("secretKey".into(), secret);
                                }
                            }
                        }
                    }
                    calls.lock().unwrap().push(json!({
                        "service": service, "method": method, "grant": grant, "body": decoded,
                    }));
                }
                let failing = recorded && fail.lock().unwrap().as_deref() == Some(method.as_str());
                let mut builder = Response::builder();
                if failing {
                    let (status, twirp) = code.lock().unwrap().clone();
                    builder = builder
                        .status(status)
                        .header("content-type", "application/json");
                    return builder
                        .body(common::full(
                            json!({"code":twirp,"msg":"injected"}).to_string(),
                        ))
                        .unwrap();
                }
                if method == "StartRoomCompositeEgress" {
                    // EgressInfo{egress_id = 1}
                    return if protobuf {
                        let mut info = vec![0x0a, FAKE_EGRESS.len() as u8];
                        info.extend_from_slice(FAKE_EGRESS.as_bytes());
                        builder
                            .header("content-type", "application/protobuf")
                            .body(common::full(info))
                            .unwrap()
                    } else {
                        builder
                            .header("content-type", "application/json")
                            .body(common::full(json!({"egressId":FAKE_EGRESS}).to_string()))
                            .unwrap()
                    };
                }
                if protobuf {
                    builder
                        .header("content-type", "application/protobuf")
                        .body(common::full(""))
                        .unwrap()
                } else {
                    builder
                        .header("content-type", "application/json")
                        .body(common::full("{}"))
                        .unwrap()
                }
            }
        })
        .await;
        Fake {
            addr,
            calls,
            fail,
            code,
        }
    }
}

fn varint(b: &[u8], i: &mut usize) -> u64 {
    let (mut v, mut shift) = (0u64, 0);
    while *i < b.len() {
        let byte = b[*i];
        *i += 1;
        v |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    v
}

/// The fields of the four mutating requests, zero values omitted as protobuf
/// (and protojson) omit them.
fn proto_body(method: &str, b: &[u8]) -> Value {
    if method == "StartRoomCompositeEgress" {
        return message(b, ROOM_COMPOSITE);
    }
    let names: &[(u64, &str)] = match method {
        "CreateRoom" => &[(1, "name"), (2, "emptyTimeout"), (10, "departureTimeout")],
        "DeleteRoom" => &[(1, "room")],
        "RemoveParticipant" => &[(1, "room"), (2, "identity")],
        "StopEgress" => &[(1, "egressId")],
        _ => &[],
    };
    let mut out = serde_json::Map::new();
    let mut i = 0;
    while i < b.len() {
        let tag = varint(b, &mut i);
        let (field, wire) = (tag >> 3, tag & 7);
        let value = match wire {
            0 => json!(varint(b, &mut i)),
            2 => {
                let n = varint(b, &mut i) as usize;
                let s = String::from_utf8_lossy(&b[i..i + n]).into_owned();
                i += n;
                json!(s)
            }
            _ => return json!("unsupported-wire-type"),
        };
        if let Some((_, name)) = names.iter().find(|(f, _)| *f == field) {
            if value != json!(0) && value != json!("") {
                out.insert((*name).into(), value);
            }
        }
    }
    Value::Object(out)
}

/// A message schema: field number, JSON name, and how to render the value.
enum Kind {
    Text,
    Flag,
    /// Enum with its names by number.
    Enum(&'static [&'static str]),
    Message(&'static [(u64, &'static str, Kind)]),
}
const S3: &[(u64, &str, Kind)] = &[
    (1, "accessKey", Kind::Text),
    (2, "secret", Kind::Text),
    (3, "region", Kind::Text),
    (4, "endpoint", Kind::Text),
    (5, "bucket", Kind::Text),
    (6, "forcePathStyle", Kind::Flag),
];
const FILE_OUTPUT: &[(u64, &str, Kind)] = &[
    (
        1,
        "fileType",
        Kind::Enum(&["DEFAULT_FILETYPE", "MP4", "OGG", "MP3"]),
    ),
    (2, "filepath", Kind::Text),
    (3, "s3", Kind::Message(S3)),
];
const ROOM_COMPOSITE: &[(u64, &str, Kind)] = &[
    (1, "roomName", Kind::Text),
    (2, "layout", Kind::Text),
    (11, "fileOutputs", Kind::Message(FILE_OUTPUT)),
];

/// Decodes a protobuf message into protojson-shaped JSON; every field the
/// schema does not name is reported by number so a drift cannot hide.
fn message(b: &[u8], schema: &[(u64, &str, Kind)]) -> Value {
    let mut out = serde_json::Map::new();
    let mut i = 0;
    while i < b.len() {
        let tag = varint(b, &mut i);
        let (field, wire) = (tag >> 3, tag & 7);
        let raw = match wire {
            0 => Err(varint(b, &mut i)),
            2 => {
                let n = varint(b, &mut i) as usize;
                let bytes = &b[i..i + n];
                i += n;
                Ok(bytes)
            }
            _ => return json!("unsupported-wire-type"),
        };
        let Some((_, name, kind)) = schema.iter().find(|(f, _, _)| *f == field) else {
            out.insert(format!("unknown-field-{field}"), json!(true));
            continue;
        };
        let value = match (kind, raw) {
            (Kind::Text, Ok(bytes)) => json!(String::from_utf8_lossy(bytes)),
            (Kind::Flag, Err(v)) => json!(v != 0),
            (Kind::Enum(names), Err(v)) => json!(names.get(v as usize).copied().unwrap_or("?")),
            (Kind::Message(inner), Ok(bytes)) => message(bytes, inner),
            _ => json!("wire-type-mismatch"),
        };
        let zero =
            value == json!("") || value == json!(false) || value == json!("DEFAULT_FILETYPE");
        if zero {
            continue;
        }
        // Repeated message fields collect into arrays.
        if matches!(kind, Kind::Message(_)) && *name == "fileOutputs" {
            out.entry(name.to_string())
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .unwrap()
                .push(value);
        } else {
            out.insert(name.to_string(), value);
        }
    }
    Value::Object(out)
}

/// A fake ASR bot control API: records every call with its bearer token and
/// answers 200, or the injected failure.
#[derive(Clone)]
pub struct Asr {
    pub addr: SocketAddr,
    calls: Arc<Mutex<Vec<Value>>>,
    mode: Arc<Mutex<u16>>,
}

pub const ASR_TOKEN: &str = "meet3-asr";

impl Asr {
    /// 200 (default), 409 (busy) or 500 for the next calls.
    pub fn answer(&self, status: u16) {
        *self.mode.lock().unwrap() = status;
    }

    pub fn drain(&self) -> Vec<Value> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }

    pub async fn start() -> Asr {
        let calls: Arc<Mutex<Vec<Value>>> = Arc::default();
        let mode = Arc::new(Mutex::new(200u16));
        let (c2, m2) = (calls.clone(), mode.clone());
        let addr = common::fake_upstream(move |req| {
            let (calls, mode) = (c2.clone(), m2.clone());
            async move {
                let (method, path) = (req.method().to_string(), req.uri().path().to_owned());
                let auth = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| {
                        if v == format!("Bearer {ASR_TOKEN}") {
                            "Bearer <asr-token>".to_owned()
                        } else {
                            v.to_owned()
                        }
                    });
                let body = req.into_body().collect().await.unwrap().to_bytes();
                let mut decoded: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                decode_tokens(&mut decoded);
                if path != "/status" {
                    calls.lock().unwrap().push(
                        json!({"method":method,"path":path,"authorization":auth,"body":decoded}),
                    );
                }
                let status = *mode.lock().unwrap();
                let body = match (path.as_str(), status) {
                    ("/status", _) => r#"{"rooms":[]}"#.to_owned(),
                    (_, 409) => r#"{"error":"busy"}"#.to_owned(),
                    _ => "{}".to_owned(),
                };
                Response::builder()
                    .status(if path == "/status" { 200 } else { status })
                    .header("content-type", "application/json")
                    .body(common::full(body))
                    .unwrap()
            }
        })
        .await;
        Asr { addr, calls, mode }
    }
}
