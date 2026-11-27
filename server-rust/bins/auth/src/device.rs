//! #341 native device trust accept side: `GET /device/policy` and
//! `POST /device/checkin` (frozen authserver/internal/device auth.go
//! RequireDeviceHMAC + checkin.go). Contract: DOX.md.
use super::{body, ingress, AuthServer, Body};
use http_body_util::BodyExt;
use hyper::body::Body as _;
use hyper::{HeaderMap, Method, Request, Response};
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Value};
use setjoin_authz::device::{DeviceRequest, VerifiedDevice};
use setjoin_identity::device_trust::{self, CheckinError, Event};

/// deviceIDFromBody reads at most this prefix and restores only the prefix.
const GUARD_PREFIX: usize = 64 << 10;
/// shared/device.MaxChallengeBodyBytes plus the one byte proving it was exceeded.
const CHALLENGE_READ: usize = (1 << 20) + 1;
const WIPE_REASON: &str = "Administrator requested remote wipe";

impl AuthServer {
    /// Go mounts exactly `GET /device/policy` (GET also serves HEAD) and
    /// `POST /device/checkin`; any other method is the mux's 405.
    pub(super) async fn device_trust(&self, req: Request<Body>) -> Response<Body> {
        let policy = req.uri().path() == "/device/policy";
        let head = req.method() == Method::HEAD;
        if policy && (head || req.method() == Method::GET) {
            return self.device_policy(req, head).await;
        }
        if !policy && req.method() == Method::POST {
            return self.device_checkin(req).await;
        }
        let text = "Method Not Allowed\n";
        let mut reply = Response::builder()
            .status(405)
            .header("allow", if policy { "GET, HEAD" } else { "POST" })
            .header("content-type", "text/plain; charset=utf-8")
            .header("x-content-type-options", "nosniff");
        if head {
            reply = reply.header("content-length", text.len());
        }
        reply.body(body(if head { "" } else { text })).unwrap()
    }

    async fn device_policy(&self, req: Request<Body>, head: bool) -> Response<Body> {
        const ROUTE: &str = "/device/policy";
        let query = setjoin_identity::issuance::query(req.uri().query().unwrap_or(""));
        let Some(id) = query
            .get("device_id")
            .map(String::as_str)
            .and_then(scan_decimal)
            .filter(|id| *id > 0)
        else {
            return failure(400, "device_id is required", head);
        };
        // Go checks these headers before reading any body (same 401 bytes).
        if !proof_headers_present(req.headers()) {
            return refused(ROUTE, id, "missing-proof-headers", head);
        }
        let uri = request_uri(&req);
        let (parts, incoming) = req.into_parts();
        // verifyBodyHash: an empty read is evidence only for NoBody / Content-Length: 0.
        let provably_empty = incoming.size_hint().exact() == Some(0);
        let Some(raw) = read_prefix(incoming, CHALLENGE_READ).await else {
            return refused(ROUTE, id, "body-unreadable", head);
        };
        if raw.is_empty() && !provably_empty {
            return refused(ROUTE, id, "body-unobservable", head);
        }
        let Some(device) = self
            .prove(id, &parts.headers, parts.method.as_str(), &uri, &raw)
            .await
        else {
            return refused(ROUTE, id, "proof-rejected", head);
        };
        // The guard has already claimed the nonce; Go's handler then refuses HEAD.
        if head {
            return failure(405, "method not allowed", true);
        }
        let Some(policy) = device_trust::effective_policy(&self.auth_db, &device).await else {
            return failure(500, "internal error", false);
        };
        let version = policy.version();
        if not_modified(&parts.headers, version) {
            return Response::builder().status(304).body(body("")).unwrap();
        }
        // map[string]any: encoding/json sorts the keys.
        let text = format!(
            "{{\"device_id\":{},\"policies\":{},\"policy_version\":{version},\"updated_at\":{},\"wipe_requested\":{}}}\n",
            device.id(),
            json!(policy.policies),
            json!(device_trust::go_now()),
            policy.wipe_requested
        );
        cached(go_escape(text), version)
    }

    async fn device_checkin(&self, req: Request<Body>) -> Response<Body> {
        const ROUTE: &str = "/device/checkin";
        let uri = request_uri(&req);
        let (parts, incoming) = req.into_parts();
        let Some(raw) = read_prefix(incoming, GUARD_PREFIX).await else {
            return failure(400, "device_id is required", false);
        };
        let Some(id) = guard_device_id(&raw).filter(|id| *id > 0) else {
            return failure(400, "device_id is required", false);
        };
        // Owner-approved security fix (#341): bound the effect before any proof
        // work, nonce claim or write. A malformed body keeps Go's order below.
        let decoded = decode_checkin(&raw);
        if decoded
            .as_ref()
            .is_ok_and(|c| c.events.len() > device_trust::EVENT_CAP)
        {
            return failure(400, "too many events", false);
        }
        let Some(device) = self.prove(id, &parts.headers, "POST", &uri, &raw).await else {
            return refused(ROUTE, id, "proof-rejected", false);
        };
        // Frozen order: the guard's proof (and committed nonce) precede the
        // handler's full decode, so a type error after a valid proof spends it.
        let Ok(checkin) = decoded else {
            return failure(400, "invalid request body", false);
        };
        let policy = match device_trust::checkin(&self.auth_db, &device, &checkin.events).await {
            Ok(policy) => policy,
            Err(CheckinError::Failed) => return failure(500, "internal error", false),
        };
        let version = policy.version();
        // 304 only after the effects (D-AUTHSERVER-INTERNAL-DEVICE-007).
        if not_modified(&parts.headers, version) {
            return Response::builder().status(304).body(body("")).unwrap();
        }
        let mut fields = vec![
            ("policy_version", json!(version)),
            (
                "policy",
                if checkin.policy_version == version {
                    Value::Null
                } else {
                    json!(policy.policies)
                },
            ),
            ("wipe_requested", json!(policy.wipe_requested)),
        ];
        if policy.wipe_requested {
            fields.push(("wipe_reason", json!(WIPE_REASON)));
        }
        cached(
            format!("{}\n", setjoin_identity::issuance::object(&fields)),
            version,
        )
    }

    async fn prove(
        &self,
        id: i64,
        headers: &HeaderMap,
        method: &str,
        uri: &str,
        raw: &[u8],
    ) -> Option<VerifiedDevice> {
        // Go: shareddevice.NewSecretCodec([]byte(cfg.JWTSecret), cfg.CryptoProfile).
        self.device_resolver
            .verify_request(
                id,
                DeviceRequest {
                    headers,
                    method,
                    uri,
                    body: raw,
                },
            )
            .await
    }
}

/// One warn line per refused proof; never the HMAC, nonce, timestamp or secret.
fn refused(route: &str, id: i64, reason: &str, head: bool) -> Response<Body> {
    eprintln!("setjoin-auth: device proof refused route={route} device_id={id} reason={reason}");
    failure(401, "device authentication failed", head)
}

/// VerifyDeviceRequest's pre-body checks: HMAC present, nonce 1..=128 bytes,
/// body hash 64 lowercase hex.
fn proof_headers_present(headers: &HeaderMap) -> bool {
    let get = |k| headers.get(k).map(|v| v.as_bytes()).unwrap_or(b"");
    let nonce = get("x-device-nonce");
    let hash = get("x-device-body-sha256");
    !get("x-device-hmac").is_empty()
        && !nonce.is_empty()
        && nonce.len() <= 128
        && hash.len() == 64
        && hash
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

/// requestURIOf: path and query exactly as this listener received them.
fn request_uri(req: &Request<Body>) -> String {
    req.uri()
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned()
}

async fn read_prefix(mut incoming: Body, cap: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    while out.len() < cap {
        let Some(frame) = incoming.frame().await else {
            break;
        };
        if let Ok(data) = frame.ok()?.into_data() {
            out.extend_from_slice(&data);
        }
    }
    out.truncate(cap);
    Some(out)
}

/// fmt.Sscanf("%d"): skip spaces (a newline fails), optional sign, decimal
/// digits, trailing text ignored, int64 overflow fails.
fn scan_decimal(raw: &str) -> Option<i64> {
    let mut s = raw;
    while let Some(c) = s.chars().next() {
        if c == '\n' || s.starts_with("\r\n") {
            return None;
        }
        if !c.is_whitespace() {
            break;
        }
        s = &s[c.len_utf8()..];
    }
    let sign = usize::from(s.starts_with(['+', '-']));
    let digits = s[sign..].bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    s[..sign + digits].parse().ok()
}

/// deviceIDFromBody: json.Unmarshal of the prefix into {DeviceID int64}.
fn guard_device_id(raw: &[u8]) -> Option<i64> {
    if !ingress::exact(&ingress::go_decode_bytes(raw)) {
        return None;
    }
    let fields = ingress::typed_fields(raw, &[("device_id", ingress::Field::Integer)]).ok()?;
    Some(fields.get("device_id").and_then(Value::as_i64).unwrap_or(0))
}

#[derive(Default)]
struct Checkin {
    policy_version: i64,
    events: Vec<Event>,
}

/// Go's Decoder.Decode into CheckinRequest: folded names, unknown fields
/// skipped unconverted, null scalars keep earlier values, null events is nil,
/// a null element keeps the reused slot, wrong types fail.
fn decode_checkin(raw: &[u8]) -> Result<Checkin, serde_json::Error> {
    struct Top;
    impl<'de> Visitor<'de> for Top {
        type Value = Checkin;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("check-in object or null")
        }
        fn visit_unit<E: de::Error>(self) -> Result<Checkin, E> {
            Ok(Checkin::default())
        }
        fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<Checkin, M::Error> {
            let mut out = Checkin::default();
            while let Some(key) = m.next_key::<String>()? {
                match ingress::fold_name(&key).as_str() {
                    "device_id" => {
                        m.next_value::<Option<i64>>()?;
                    }
                    "policy_version" => {
                        if let Some(v) = m.next_value::<Option<i64>>()? {
                            out.policy_version = v;
                        }
                    }
                    "events" => {
                        let previous = std::mem::take(&mut out.events);
                        out.events = m.next_value_seed(Events(previous))?;
                    }
                    _ => {
                        m.next_value::<de::IgnoredAny>()?;
                    }
                }
            }
            Ok(out)
        }
    }
    let view = ingress::go_decode_bytes(raw);
    let mut d = serde_json::Deserializer::from_slice(&view);
    serde::Deserializer::deserialize_any(&mut d, Top)
}

struct Events(Vec<Event>);
impl<'de> DeserializeSeed<'de> for Events {
    type Value = Vec<Event>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Vec<Event>, D::Error> {
        struct V(Vec<Event>);
        impl<'de> Visitor<'de> for V {
            type Value = Vec<Event>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("event array or null")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Vec<Event>, E> {
                Ok(Vec::new())
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut s: S) -> Result<Vec<Event>, S::Error> {
                let mut out = Vec::new();
                while let Some(e) =
                    s.next_element_seed(One(self.0.get(out.len()).cloned().unwrap_or_default()))?
                {
                    out.push(e);
                }
                Ok(out)
            }
        }
        d.deserialize_any(V(self.0))
    }
}

struct One(Event);
impl<'de> DeserializeSeed<'de> for One {
    type Value = Event;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Event, D::Error> {
        struct V(Event);
        impl<'de> Visitor<'de> for V {
            type Value = Event;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("event object or null")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Event, E> {
                Ok(self.0)
            }
            fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<Event, M::Error> {
                let mut event = self.0;
                while let Some(key) = m.next_key::<String>()? {
                    let field = ingress::fold_name(&key);
                    if !matches!(field.as_str(), "type" | "timestamp" | "data") {
                        m.next_value::<de::IgnoredAny>()?;
                        continue;
                    }
                    let Some(value) = m.next_value::<Option<String>>()? else {
                        continue;
                    };
                    match field.as_str() {
                        "type" => event.kind = value,
                        "data" => event.data = value,
                        _ => {}
                    }
                }
                Ok(event)
            }
        }
        d.deserialize_any(V(self.0))
    }
}

/// Header.Get("If-None-Match") == fmt.Sprintf("%d", version), byte-exact.
fn not_modified(headers: &HeaderMap, version: i64) -> bool {
    headers
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|tag| tag == version.to_string())
}

/// httputil.WriteJSON map error body (no-store unless already set).
fn failure(status: u16, message: &str, head: bool) -> Response<Body> {
    let text = format!("{{\"error\":{}}}\n", json!(message));
    let mut reply = Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store");
    if head {
        reply = reply.header("content-length", text.len());
    }
    reply
        .body(body(if head { String::new() } else { text }))
        .unwrap()
}

fn cached(text: String, version: i64) -> Response<Body> {
    Response::builder()
        .header("cache-control", "private, max-age=300")
        .header("content-type", "application/json")
        .header("etag", version.to_string())
        .body(body(text))
        .unwrap()
}

/// encoding/json's HTML-safe escaping (only string content can contain these).
fn go_escape(text: String) -> String {
    text.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_id_follows_fmt_sscanf_decimal() {
        assert_eq!(scan_decimal("42"), Some(42));
        assert_eq!(scan_decimal(" +42abc"), Some(42));
        assert_eq!(scan_decimal("-7"), Some(-7));
        assert_eq!(scan_decimal(""), None);
        assert_eq!(scan_decimal("abc"), None);
        assert_eq!(scan_decimal("\n5"), None);
        assert_eq!(scan_decimal("9223372036854775808"), None);
    }
    #[test]
    fn guard_reads_device_id_like_json_unmarshal() {
        assert_eq!(guard_device_id(br#"{"device_id":5}"#), Some(5));
        assert_eq!(
            guard_device_id(br#"{"DEVICE_ID":5,"device_id":null}"#),
            Some(5)
        );
        assert_eq!(
            guard_device_id(br#"{"device_id":7,"device_id":5}"#),
            Some(5)
        );
        assert_eq!(guard_device_id(b"null"), Some(0));
        assert_eq!(guard_device_id(br#"{"device_id":"5"}"#), None);
        assert_eq!(guard_device_id(br#"{"device_id":5} {}"#), None);
        assert_eq!(guard_device_id(b"[5]"), None);
        assert_eq!(guard_device_id(br#"{"device_id":1.0}"#), None);
        assert_eq!(guard_device_id(br#"{"device_id":5,"x":1e999}"#), Some(5));
    }
    #[test]
    fn checkin_decode_follows_encoding_json() {
        let c = decode_checkin(br#"{"device_id":1,"Events":[null,{"TYPE":"crash","data":null,"Data":"x"}],"policy_version":7,"POLICY_VERSION":null}"#).unwrap();
        assert_eq!(c.policy_version, 7);
        assert_eq!(
            c.events,
            vec![
                Event::default(),
                Event {
                    kind: "crash".into(),
                    data: "x".into()
                }
            ]
        );
        assert!(decode_checkin(br#"{"events":"x"}"#).is_err());
        assert!(decode_checkin(br#"{"events":[1]}"#).is_err());
        assert!(decode_checkin(br#"{"events":[{"timestamp":5}]}"#).is_err());
        assert!(decode_checkin(br#"{"policy_version":"1"}"#).is_err());
        assert!(
            decode_checkin(br#"{"events":[{"type":"a"}],"events":null}"#)
                .unwrap()
                .events
                .is_empty()
        );
    }
    #[test]
    fn proof_header_precheck_matches_verify_order() {
        let mut h = HeaderMap::new();
        assert!(!proof_headers_present(&h));
        h.insert("x-device-hmac", "aa".parse().unwrap());
        h.insert("x-device-nonce", "n".repeat(128).parse().unwrap());
        h.insert("x-device-body-sha256", "e".repeat(64).parse().unwrap());
        assert!(proof_headers_present(&h));
        h.insert("x-device-nonce", "n".repeat(129).parse().unwrap());
        assert!(!proof_headers_present(&h));
        h.insert("x-device-nonce", "n".parse().unwrap());
        h.insert("x-device-body-sha256", "E".repeat(64).parse().unwrap());
        assert!(!proof_headers_present(&h));
    }
}
