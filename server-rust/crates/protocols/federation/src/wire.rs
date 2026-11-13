//! The s2s wire: a 4-byte big-endian length prefix followed by a JSON frame
//! (`{"kind":..,"stanzaId":..,"payload":..}`), 16 MiB at most. Encoding and
//! decoding follow Go's `encoding/json` so frames are byte-identical.

use crate::gojson::{self, JsonError};
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const KIND_HELLO: &str = "hello";
pub const KIND_MSG: &str = "msg";
pub const KIND_RECEIPT: &str = "receipt";
pub const KIND_ACK: &str = "ack";
pub const KIND_REPLAY_REQ: &str = "replay_req";
pub const KIND_EPHEMERAL: &str = "ephemeral";

pub const MAX_FRAME_LEN: usize = 16 << 20;

#[derive(Debug)]
pub enum WireError {
    Io(std::io::Error),
    TooLong(usize),
    Json(JsonError),
}
impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Io(e) => write!(f, "federation: wire io: {e}"),
            WireError::TooLong(n) => {
                write!(
                    f,
                    "federation: frame length {n} exceeds max {MAX_FRAME_LEN}"
                )
            }
            WireError::Json(e) => write!(f, "federation: unmarshal frame: {e}"),
        }
    }
}
impl std::error::Error for WireError {}
impl From<std::io::Error> for WireError {
    fn from(e: std::io::Error) -> Self {
        WireError::Io(e)
    }
}
impl From<JsonError> for WireError {
    fn from(e: JsonError) -> Self {
        WireError::Json(e)
    }
}

/// The wire envelope. `payload` is the raw JSON bytes (`None` when absent).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Frame {
    pub kind: String,
    pub stanza_id: String,
    pub payload: Option<Vec<u8>>,
}

impl Frame {
    pub fn new(kind: &str, stanza_id: &str, payload: Option<Vec<u8>>) -> Self {
        Frame {
            kind: kind.to_string(),
            stanza_id: stanza_id.to_string(),
            payload,
        }
    }

    /// Go `json.Marshal(Frame)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.payload.as_ref().map_or(0, Vec::len));
        out.extend_from_slice(b"{\"kind\":");
        gojson::push_string(&mut out, &self.kind);
        if !self.stanza_id.is_empty() {
            out.extend_from_slice(b",\"stanzaId\":");
            gojson::push_string(&mut out, &self.stanza_id);
        }
        if let Some(p) = self.payload.as_ref().filter(|p| !p.is_empty()) {
            out.extend_from_slice(b",\"payload\":");
            out.extend_from_slice(&gojson::compact_escape(p));
        }
        out.push(b'}');
        out
    }

    /// Go `json.Unmarshal(body, &Frame{})`.
    pub fn decode(body: &[u8]) -> Result<Frame, JsonError> {
        let mut f = Frame::default();
        let Some(members) = gojson::object_members(body)? else {
            return Ok(f);
        };
        let mut first_err: Option<JsonError> = None;
        for m in members {
            if gojson::key_matches(&m.key, "kind") {
                match gojson::field_string(m.value) {
                    Ok(Some(s)) => f.kind = s,
                    Ok(None) => {}
                    Err(e) => first_err = first_err.or(Some(e)),
                }
            } else if gojson::key_matches(&m.key, "stanzaId") {
                match gojson::field_string(m.value) {
                    Ok(Some(s)) => f.stanza_id = s,
                    Ok(None) => {}
                    Err(e) => first_err = first_err.or(Some(e)),
                }
            } else if gojson::key_matches(&m.key, "payload") {
                f.payload = Some(m.value.to_vec());
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(f),
        }
    }
}

/// Write one length-prefixed frame (a single write so a frame is never
/// interleaved by a concurrent writer that holds the stream lock).
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, f: &Frame) -> Result<(), WireError> {
    if let Some(payload) = f.payload.as_ref().filter(|p| !p.is_empty()) {
        gojson::validate(payload)?;
    }
    let body = f.encode();
    if body.len() > MAX_FRAME_LEN {
        return Err(WireError::TooLong(body.len()));
    }
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(&body);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Frame, WireError> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).await?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n > MAX_FRAME_LEN {
        return Err(WireError::TooLong(n));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await?;
    Ok(Frame::decode(&body)?)
}

/// The first frame of every stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hello {
    pub from_domain: String,
    pub ver: i64,
    pub caps: Vec<String>,
    pub resume_from_seq: i64,
}

impl Hello {
    pub fn new(from_domain: &str) -> Self {
        Hello {
            from_domain: from_domain.to_string(),
            ver: 1,
            ..Default::default()
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = b"{\"fromDomain\":".to_vec();
        gojson::push_string(&mut o, &self.from_domain);
        o.extend_from_slice(format!(",\"ver\":{}", self.ver).as_bytes());
        if !self.caps.is_empty() {
            o.extend_from_slice(b",\"caps\":[");
            for (i, c) in self.caps.iter().enumerate() {
                if i > 0 {
                    o.push(b',');
                }
                gojson::push_string(&mut o, c);
            }
            o.push(b']');
        }
        o.extend_from_slice(format!(",\"resumeFromSeq\":{}}}", self.resume_from_seq).as_bytes());
        o
    }
    pub fn frame(&self) -> Frame {
        Frame::new(KIND_HELLO, "", Some(self.encode()))
    }
    /// Go `json.Unmarshal(payload, &Hello{})`; a missing payload is Go's
    /// "unexpected end of JSON input".
    pub fn decode(payload: Option<&[u8]>) -> Result<Hello, JsonError> {
        let Some(p) = payload else {
            return Err(JsonError("unexpected end of JSON input".into()));
        };
        let mut h = Hello::default();
        let Some(members) = gojson::object_members(p)? else {
            return Ok(h);
        };
        let mut first_err: Option<JsonError> = None;
        for m in members {
            let r: Result<(), JsonError> = (|| {
                if gojson::key_matches(&m.key, "fromDomain") {
                    if let Some(s) = gojson::field_string(m.value)? {
                        h.from_domain = s;
                    }
                } else if gojson::key_matches(&m.key, "ver") {
                    if let Some(v) = gojson::field_i64(m.value)? {
                        h.ver = v;
                    }
                } else if gojson::key_matches(&m.key, "caps") {
                    h.caps = gojson::field_string_array(m.value)?.unwrap_or_default();
                } else if gojson::key_matches(&m.key, "resumeFromSeq") {
                    if let Some(v) = gojson::field_i64(m.value)? {
                        h.resume_from_seq = v;
                    }
                }
                Ok(())
            })();
            if let Err(e) = r {
                first_err = first_err.or(Some(e));
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(h),
        }
    }
}

/// The `msg` payload: the per-peer sequence number plus opaque content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MsgEnvelope {
    pub peer_seq: i64,
    pub content_type: String,
    pub payload: Option<Vec<u8>>,
}

impl MsgEnvelope {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = format!("{{\"peerSeq\":{},\"contentType\":", self.peer_seq).into_bytes();
        gojson::push_string(&mut o, &self.content_type);
        o.extend_from_slice(b",\"payload\":");
        match self.payload.as_ref().filter(|p| !p.is_empty()) {
            Some(p) => o.extend_from_slice(&gojson::compact_escape(p)),
            None => o.extend_from_slice(b"null"),
        }
        o.push(b'}');
        o
    }
    pub fn decode(payload: Option<&[u8]>) -> Result<MsgEnvelope, JsonError> {
        let Some(p) = payload else {
            return Err(JsonError("unexpected end of JSON input".into()));
        };
        let mut e = MsgEnvelope::default();
        let Some(members) = gojson::object_members(p)? else {
            return Ok(e);
        };
        let mut first_err: Option<JsonError> = None;
        for m in members {
            let r: Result<(), JsonError> = (|| {
                if gojson::key_matches(&m.key, "peerSeq") {
                    if let Some(v) = gojson::field_i64(m.value)? {
                        e.peer_seq = v;
                    }
                } else if gojson::key_matches(&m.key, "contentType") {
                    if let Some(s) = gojson::field_string(m.value)? {
                        e.content_type = s;
                    }
                } else if gojson::key_matches(&m.key, "payload") {
                    e.payload = Some(m.value.to_vec());
                }
                Ok(())
            })();
            if let Err(er) = r {
                first_err = first_err.or(Some(er));
            }
        }
        match first_err {
            Some(er) => Err(er),
            None => Ok(e),
        }
    }
}

/// `{"peerSeq":N}`: the ack / replay_req / receipt payload.
pub fn encode_seq(peer_seq: i64) -> Vec<u8> {
    format!("{{\"peerSeq\":{peer_seq}}}").into_bytes()
}

pub fn decode_seq(payload: Option<&[u8]>) -> Result<i64, JsonError> {
    let Some(p) = payload else {
        return Err(JsonError("unexpected end of JSON input".into()));
    };
    let mut seq = 0;
    let mut first_err: Option<JsonError> = None;
    if let Some(members) = gojson::object_members(p)? {
        for m in members {
            if gojson::key_matches(&m.key, "peerSeq") {
                match gojson::field_i64(m.value) {
                    Ok(Some(v)) => seq = v,
                    Ok(None) => {}
                    Err(e) => first_err = first_err.or(Some(e)),
                }
            }
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(seq),
    }
}

/// The content-free stand-in stored for payloads that must never be kept.
pub fn encode_redacted(content_type: &str, bytes: usize) -> Vec<u8> {
    let mut o = b"{\"redacted\":true,\"contentType\":".to_vec();
    gojson::push_string(&mut o, content_type);
    o.extend_from_slice(format!(",\"bytes\":{bytes}}}").as_bytes());
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn malformed_raw_payload_is_rejected_before_writing() {
        // Go WriteFrame's json.Marshal rejects malformed RawMessage before
        // touching the transport. Observe only the public writer and bytes.
        let mut bytes = Vec::new();
        let result = write_frame(
            &mut bytes,
            &Frame::new(KIND_MSG, "bad", Some(b"{".to_vec())),
        )
        .await;
        assert!(result.is_err());
        assert!(bytes.is_empty());
    }

    #[test]
    fn frames_encode_like_go() {
        let f = Frame::new(KIND_ACK, "s<1>", Some(encode_seq(3)));
        assert_eq!(
            String::from_utf8(f.encode()).unwrap(),
            r#"{"kind":"ack","stanzaId":"s\u003c1\u003e","payload":{"peerSeq":3}}"#
        );
        assert_eq!(
            String::from_utf8(Hello::new("a.test").frame().encode()).unwrap(),
            r#"{"kind":"hello","payload":{"fromDomain":"a.test","ver":1,"resumeFromSeq":0}}"#
        );
    }

    #[test]
    fn frame_decode_matches_go_leniency() {
        let f = Frame::decode(br#"{"KIND":"msg","stanzaId":null,"payload": {"a": 1},"extra":1}"#)
            .unwrap();
        assert_eq!(f.kind, "msg");
        assert_eq!(f.payload.as_deref(), Some(&b"{\"a\": 1}"[..]));
        assert_eq!(Frame::decode(b"null").unwrap(), Frame::default());
        assert!(Frame::decode(b"[1]").is_err());
        assert!(Frame::decode(br#"{"kind":1}"#).is_err());
    }

    #[test]
    fn missing_or_null_payloads() {
        assert!(Hello::decode(None).is_err());
        assert_eq!(Hello::decode(Some(b"null")).unwrap(), Hello::default());
        let e = MsgEnvelope::decode(Some(br#"{"peerSeq":2,"payload":null}"#)).unwrap();
        assert_eq!(e.payload.as_deref(), Some(&b"null"[..]));
        assert!(MsgEnvelope::decode(Some(br#"{"peerSeq":1.5}"#)).is_err());
    }
}
