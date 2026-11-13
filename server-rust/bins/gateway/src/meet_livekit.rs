//! F13 peripherals (#286): LiveKit access tokens, RoomService and Egress calls,
//! and webhook verification. LiveKit, Egress and the ASR bot are never
//! authority stores: every call here follows a committed reducer decision and
//! a failure is reported, never allowed to roll the decision back.
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Go's `authenticatedAdmissionTTL`: a second cap at the sole JWT mint seam.
const AUTHENTICATED_TTL: i64 = 60;
/// Go's `tokenLeeway` for webhook token validation.
const LEEWAY: u64 = 60;
/// Go's `webhookMaxBodyBytes`.
pub const WEBHOOK_MAX_BODY: usize = 1 << 20;

/// Go's `meet.Config` read from the process environment.
#[derive(Clone)]
pub struct LiveKit {
    key: String,
    secret: String,
    url: String,
    egress_enabled: bool,
    captions_configured: bool,
    asr_url: String,
    asr_token: String,
    s3: EgressS3,
    client: reqwest::Client,
}

/// Go's `meet.EgressS3`: the staging sink the recording start embeds
/// per request. `endpoint` carries its scheme exactly as Go composes it.
#[derive(Clone, Default)]
pub struct EgressS3 {
    access_key: String,
    secret_key: String,
    endpoint: String,
    bucket: String,
}

impl EgressS3 {
    /// Go's `scheme + cfg.S3Endpoint` composition (the endpoint is used as
    /// configured, even when it already names a scheme).
    pub fn from_values(
        endpoint: &str,
        secure: bool,
        access_key: &str,
        secret_key: &str,
        bucket: &str,
    ) -> Self {
        Self {
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            endpoint: format!("{}{endpoint}", if secure { "https://" } else { "http://" }),
            bucket: bucket.into(),
        }
    }

    /// `S3_*` with the legacy `MINIO_*` fallback and Go's defaults.
    pub fn from_env() -> Self {
        let value = |name: &str, legacy: &str, default: &str| {
            std::env::var(name)
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| std::env::var(legacy).ok().filter(|s| !s.is_empty()))
                .unwrap_or_else(|| default.into())
        };
        let secure = matches!(
            value("S3_SECURE", "MINIO_SECURE", "false").as_str(),
            "true" | "True" | "TRUE" | "1" | "t" | "T"
        );
        Self::from_values(
            &value("S3_ENDPOINT", "MINIO_ENDPOINT", "127.0.0.1:9000"),
            secure,
            &value("S3_ACCESS_KEY", "MINIO_ACCESS_KEY", ""),
            &value("S3_SECRET_KEY", "MINIO_SECRET_KEY", ""),
            &value("S3_BUCKET", "MINIO_BUCKET", "mailblobs"),
        )
    }
}

/// How an Egress or ASR call failed; `Busy` is the capacity refusal Go
/// surfaces as its own problem type.
#[derive(Debug, PartialEq)]
pub enum PeripheralError {
    Busy,
    Failed,
}

impl LiveKit {
    pub fn new(
        key: &str,
        secret: &str,
        url: &str,
        egress_enabled: bool,
        captions_configured: bool,
    ) -> Self {
        Self {
            key: key.into(),
            secret: secret.into(),
            url: url.into(),
            egress_enabled,
            captions_configured,
            asr_url: String::new(),
            asr_token: String::new(),
            s3: EgressS3::default(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("static HTTP client"),
        }
    }

    pub fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).unwrap_or_default();
        Self::new(
            &get("LIVEKIT_API_KEY"),
            &get("LIVEKIT_API_SECRET"),
            &get("LIVEKIT_URL"),
            get("MEET_EGRESS_ENABLED") == "true",
            !get("ASR_URL").is_empty(),
        )
        .with_s3(EgressS3::from_env())
        .with_asr_if_set(&get("ASR_URL"), &get("ASR_TOKEN"))
    }

    pub fn with_s3(mut self, s3: EgressS3) -> Self {
        self.s3 = s3;
        self
    }

    /// The asrbot control API (Go's `ASR_URL` and `ASR_TOKEN`).
    pub fn with_asr(mut self, url: &str, token: &str) -> Self {
        self.asr_url = url.trim_end_matches('/').into();
        self.asr_token = token.into();
        self.captions_configured = true;
        self
    }

    fn with_asr_if_set(self, url: &str, token: &str) -> Self {
        if url.is_empty() {
            self
        } else {
            self.with_asr(url, token)
        }
    }

    pub fn unconfigured() -> Self {
        Self::new("", "", "", false, false)
    }

    /// Go's `Config.Configured()`: all three LIVEKIT_* values are set.
    pub fn configured(&self) -> bool {
        !self.key.is_empty() && !self.secret.is_empty() && !self.url.is_empty()
    }

    /// Go builds an `EgressController` only when configured and enabled.
    pub fn egress(&self) -> bool {
        self.configured() && self.egress_enabled
    }

    /// Go's `h.captions != nil`.
    pub fn captions_configured(&self) -> bool {
        self.captions_configured
    }

    fn http_url(&self) -> String {
        if let Some(rest) = self.url.strip_prefix("wss://") {
            format!("https://{rest}")
        } else if let Some(rest) = self.url.strip_prefix("ws://") {
            format!("http://{rest}")
        } else {
            self.url.clone()
        }
    }

    fn sign(&self, claims: &Value) -> Result<String, ()> {
        if self.key.is_empty() || self.secret.is_empty() {
            return Err(());
        }
        let head = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let body = URL_SAFE_NO_PAD.encode(claims.to_string());
        let mut mac = HmacSha256::new_from_slice(self.secret.as_bytes()).map_err(|_| ())?;
        mac.update(format!("{head}.{body}").as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        Ok(format!("{head}.{body}.{sig}"))
    }

    fn registered(&self, subject: &str, valid_for: i64) -> serde_json::Map<String, Value> {
        let now = now();
        let mut m = serde_json::Map::new();
        m.insert("iss".into(), json!(self.key));
        if !subject.is_empty() {
            m.insert("sub".into(), json!(subject));
        }
        m.insert("iat".into(), json!(now));
        m.insert("nbf".into(), json!(now));
        m.insert("exp".into(), json!(now + valid_for));
        m
    }

    /// Go's `MintToken`: the reducer-composed grant spec translated to a
    /// LiveKit join token. `roomCreate` and `recorder` cannot be expressed.
    pub fn mint(&self, spec: &GrantSpec) -> Result<(String, String), ()> {
        let mut ttl = spec.ttl_seconds;
        if spec.identity.starts_with("u:") {
            ttl = ttl.min(AUTHENTICATED_TTL);
        }
        if ttl < 1 {
            return Err(());
        }
        let mut claims = self.registered(&spec.identity, ttl);
        if !spec.identity.is_empty() {
            claims.insert("identity".into(), json!(spec.identity));
        }
        if !spec.name.is_empty() {
            claims.insert("name".into(), json!(spec.name));
        }
        let mut video = serde_json::Map::new();
        video.insert("roomJoin".into(), json!(true));
        if !spec.room.is_empty() {
            video.insert("room".into(), json!(spec.room));
        }
        video.insert("canPublish".into(), json!(spec.can_publish));
        video.insert("canSubscribe".into(), json!(spec.can_subscribe));
        video.insert("canPublishData".into(), json!(spec.can_publish_data));
        // Pinned false: a participant can never rewrite the trust label.
        video.insert("canUpdateOwnMetadata".into(), json!(false));
        if spec.room_admin {
            video.insert("roomAdmin".into(), json!(true));
        }
        if spec.hidden {
            video.insert("hidden".into(), json!(true));
        }
        claims.insert("video".into(), Value::Object(video));
        if spec.external {
            claims.insert("attributes".into(), json!({"setjoin.external":"true"}));
        }
        let token = self.sign(&Value::Object(claims))?;
        Ok((token, expires_at(ttl)))
    }

    async fn twirp(
        &self,
        service: &str,
        method: &str,
        grant: Value,
        body: Value,
    ) -> Result<(), ()> {
        self.twirp_call(service, method, grant, body)
            .await
            .map(|_| ())
            .map_err(|_| ())
    }

    /// One JSON twirp call; the error says whether the service reported
    /// capacity exhaustion (the twirp `resource_exhausted`/`unavailable` codes).
    async fn twirp_call(
        &self,
        service: &str,
        method: &str,
        grant: Value,
        body: Value,
    ) -> Result<Value, PeripheralError> {
        let mut claims = self.registered("", 6 * 3600);
        claims.insert("video".into(), grant);
        let token = self
            .sign(&Value::Object(claims))
            .map_err(|()| PeripheralError::Failed)?;
        let response = self
            .client
            .post(format!(
                "{}/twirp/livekit.{service}/{method}",
                self.http_url().trim_end_matches('/')
            ))
            .bearer_auth(token)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|_| PeripheralError::Failed)?;
        let status = response.status();
        let json = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("json"));
        let bytes = response
            .bytes()
            .await
            .map_err(|_| PeripheralError::Failed)?;
        if status.is_success() {
            return Ok(serde_json::from_slice(&bytes).unwrap_or(Value::Null));
        }
        Err(twirp_error(status.as_u16(), json, &bytes))
    }

    /// Go's `StartRoomComposite`: one grid-layout MP4 file output to the
    /// staging S3 sink. Returns the egress id.
    pub async fn start_room_composite(
        &self,
        room: &str,
        staging_key: &str,
    ) -> Result<String, PeripheralError> {
        let out = self
            .twirp_call(
                "Egress",
                "StartRoomCompositeEgress",
                json!({"roomRecord":true}),
                json!({
                    "roomName": room,
                    "layout": "grid",
                    "fileOutputs": [{
                        "fileType": "MP4",
                        "filepath": staging_key,
                        "s3": {
                            "accessKey": self.s3.access_key,
                            "secret": self.s3.secret_key,
                            "region": "us-east-1",
                            "endpoint": self.s3.endpoint,
                            "bucket": self.s3.bucket,
                            "forcePathStyle": true,
                        }
                    }]
                }),
            )
            .await?;
        Ok(out
            .get("egressId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned())
    }

    async fn asr(&self, path: &str, body: Value) -> Result<u16, ()> {
        let mut request = self
            .client
            .post(format!("{}{path}", self.asr_url))
            .header("content-type", "application/json")
            .body(body.to_string());
        if !self.asr_token.is_empty() {
            request = request.bearer_auth(&self.asr_token);
        }
        request
            .send()
            .await
            .map(|r| r.status().as_u16())
            .map_err(|_| ())
    }

    /// Go's `captions.Start`: 409 is the bot's capacity refusal.
    pub async fn captions_start(&self, room: &str, token: &str) -> Result<(), PeripheralError> {
        match self.asr("/start", json!({"room":room,"token":token})).await {
            Ok(200) => Ok(()),
            Ok(409) => Err(PeripheralError::Busy),
            _ => Err(PeripheralError::Failed),
        }
    }

    /// Go's `captions.Stop`.
    pub async fn captions_stop(&self, room: &str) -> Result<(), ()> {
        match self.asr("/stop", json!({"room":room})).await {
            Ok(200) => Ok(()),
            _ => Err(()),
        }
    }

    /// Idempotently pre-creates a room (auto-create is off in livekit.yaml).
    pub async fn create_room(&self, room: &str, empty: u32, departure: u32) -> Result<(), ()> {
        self.twirp(
            "RoomService",
            "CreateRoom",
            json!({"roomCreate":true}),
            json!({"name":room,"emptyTimeout":empty,"departureTimeout":departure}),
        )
        .await
    }

    /// The kick/assign eviction call.
    pub async fn remove_participant(&self, room: &str, identity: &str) -> Result<(), ()> {
        self.twirp(
            "RoomService",
            "RemoveParticipant",
            json!({"roomAdmin":true,"room":room}),
            json!({"room":room,"identity":identity}),
        )
        .await
    }

    /// The end/close eviction call (Go's SDK signs it with `roomCreate`).
    pub async fn delete_room(&self, room: &str) -> Result<(), ()> {
        self.twirp(
            "RoomService",
            "DeleteRoom",
            json!({"roomCreate":true}),
            json!({"room":room}),
        )
        .await
    }

    pub async fn stop_egress(&self, egress_id: &str) -> Result<(), ()> {
        self.twirp(
            "Egress",
            "StopEgress",
            json!({"roomRecord":true}),
            json!({"egressId":egress_id}),
        )
        .await
    }

    /// Go's `ListRooms`: every room name live on the SFU.
    pub async fn list_rooms(&self) -> Result<Vec<String>, ()> {
        let out = self
            .twirp_call(
                "RoomService",
                "ListRooms",
                json!({"roomList":true}),
                json!({}),
            )
            .await
            .map_err(|_| ())?;
        Ok(names(&out, "rooms", "name"))
    }

    /// Go's `ListParticipants`: identities connected to one room.
    pub async fn list_participants(&self, room: &str) -> Result<Vec<String>, ()> {
        let out = self
            .twirp_call(
                "RoomService",
                "ListParticipants",
                json!({"roomAdmin":true,"room":room}),
                json!({"room":room}),
            )
            .await
            .map_err(|_| ())?;
        Ok(names(&out, "participants", "identity"))
    }

    /// Go's `ListEgress` projection: `(egress id, active, start unix ns)`. The
    /// start falls back to `updatedAt` while the pipeline has not gone active.
    pub async fn list_egress(&self) -> Result<Vec<(String, bool, i64)>, ()> {
        let out = self
            .twirp_call(
                "Egress",
                "ListEgress",
                json!({"roomRecord":true}),
                json!({}),
            )
            .await
            .map_err(|_| ())?;
        let number = |v: &Value| match v {
            Value::String(s) => s.parse::<i64>().unwrap_or(0),
            other => other.as_i64().unwrap_or(0),
        };
        Ok(out
            .get("items")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|it| {
                        let status = it
                            .get("status")
                            .cloned()
                            .unwrap_or(json!("EGRESS_STARTING"));
                        let active = match &status {
                            Value::String(s) => {
                                matches!(
                                    s.as_str(),
                                    "EGRESS_STARTING" | "EGRESS_ACTIVE" | "EGRESS_ENDING"
                                )
                            }
                            other => matches!(other.as_i64().unwrap_or(0), 0..=2),
                        };
                        let mut started = it.get("startedAt").map_or(0, number);
                        if started == 0 {
                            started = it.get("updatedAt").map_or(0, number);
                        }
                        (
                            it.get("egressId")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned(),
                            active,
                            started,
                        )
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Go's `httpCaptionsClient.Status`: rooms the bot is captioning.
    pub async fn captions_status(&self) -> Result<Vec<String>, ()> {
        let mut request = self.client.get(format!("{}/status", self.asr_url));
        if !self.asr_token.is_empty() {
            request = request.bearer_auth(&self.asr_token);
        }
        let response = request.send().await.map_err(|_| ())?;
        if response.status().as_u16() != 200 {
            return Err(());
        }
        let bytes = response.bytes().await.map_err(|_| ())?;
        let v: Value = serde_json::from_slice(&bytes).map_err(|_| ())?;
        Ok(v.get("rooms")
            .and_then(Value::as_array)
            .map(|r| {
                r.iter()
                    .filter_map(|x| x.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Go's `webhook.Receive`: HS256 token from the configured key pair
    /// (issuer match, one minute of leeway) whose `sha256` claim is the
    /// base64 digest of the exact body.
    pub fn verify_webhook(&self, authorization: Option<&str>, body: &[u8]) -> bool {
        let Some(raw) = authorization.filter(|v| !v.is_empty()) else {
            return false;
        };
        if self.secret.is_empty() {
            return false;
        }
        let parts: Vec<&str> = raw.split('.').collect();
        let [head, payload, signature] = parts[..] else {
            return false;
        };
        let decode = |s: &str| URL_SAFE_NO_PAD.decode(s).ok();
        let (Some(head_raw), Some(payload_raw), Some(signature_raw)) =
            (decode(head), decode(payload), decode(signature))
        else {
            return false;
        };
        let Ok(header) = serde_json::from_slice::<Value>(&head_raw) else {
            return false;
        };
        if header.get("alg").and_then(Value::as_str) != Some("HS256") {
            return false;
        }
        let Ok(claims) = serde_json::from_slice::<Value>(&payload_raw) else {
            return false;
        };
        if claims.get("iss").and_then(Value::as_str) != Some(self.key.as_str()) {
            return false;
        }
        let Ok(mut mac) = HmacSha256::new_from_slice(self.secret.as_bytes()) else {
            return false;
        };
        mac.update(format!("{head}.{payload}").as_bytes());
        if mac.verify_slice(&signature_raw).is_err() {
            return false;
        }
        let at = now() as u64;
        let numeric = |name: &str| -> Result<Option<f64>, ()> {
            match claims.get(name) {
                None | Some(Value::Null) => Ok(None),
                Some(v) => v.as_f64().map(Some).ok_or(()),
            }
        };
        let (Ok(exp), Ok(nbf)) = (numeric("exp"), numeric("nbf")) else {
            return false;
        };
        if exp.is_some_and(|e| (at.saturating_sub(LEEWAY) as f64) >= e) {
            return false;
        }
        if nbf.is_some_and(|n| ((at + LEEWAY) as f64) < n) {
            return false;
        }
        let digest = STANDARD.encode(Sha256::digest(body));
        let claimed = claims.get("sha256").and_then(Value::as_str).unwrap_or("");
        // Equal-length comparison without early exit; the digest is public.
        claimed.len() == digest.len()
            && claimed
                .bytes()
                .zip(digest.bytes())
                .fold(0u8, |a, (x, y)| a | (x ^ y))
                == 0
    }
}

/// The twirp client's error classification: a JSON body naming a valid twirp
/// code wins, otherwise the HTTP status is mapped as an intermediary's.
fn twirp_error(status: u16, json: bool, body: &[u8]) -> PeripheralError {
    const CODES: [&str; 18] = [
        "canceled",
        "unknown",
        "invalid_argument",
        "malformed",
        "deadline_exceeded",
        "not_found",
        "bad_route",
        "already_exists",
        "permission_denied",
        "unauthenticated",
        "resource_exhausted",
        "failed_precondition",
        "aborted",
        "out_of_range",
        "unimplemented",
        "internal",
        "unavailable",
        "dataloss",
    ];
    let named = json
        .then(|| serde_json::from_slice::<Value>(body).ok())
        .flatten()
        .and_then(|v| v.get("code").and_then(Value::as_str).map(str::to_owned));
    let busy = match named {
        Some(code) if CODES.contains(&code.as_str()) => {
            code == "resource_exhausted" || code == "unavailable"
        }
        Some(_) => false,
        None => matches!(status, 429 | 502 | 503 | 504),
    };
    if busy {
        PeripheralError::Busy
    } else {
        PeripheralError::Failed
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Go's `time.Time` JSON: RFC 3339 with trailing zeros of the fraction trimmed.
fn expires_at(ttl: i64) -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        + Duration::from_secs(ttl as u64);
    let base = chrono::DateTime::from_timestamp(d.as_secs() as i64, 0)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string();
    let nanos = format!("{:09}", d.subsec_nanos());
    let fraction = nanos.trim_end_matches('0');
    if fraction.is_empty() {
        format!("{base}Z")
    } else {
        format!("{base}.{fraction}Z")
    }
}

/// The reducer-composed grant spec (Go's `grantSpec`); case-insensitive keys
/// and last-duplicate-wins are `encoding/json` behaviour the reducer's fixed
/// camelCase output never exercises.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct GrantSpec {
    pub room: String,
    pub identity: String,
    pub name: String,
    pub can_publish: bool,
    pub can_subscribe: bool,
    pub can_publish_data: bool,
    pub room_admin: bool,
    pub hidden: bool,
    pub ttl_seconds: i64,
    pub external: bool,
    pub recording_active: bool,
}

/// Facts Go's receiver reads from a verified webhook (the rest of the
/// `WebhookEvent` message is discarded, as `DiscardUnknown` does).
pub struct WebhookEvent {
    pub event: String,
    pub room: String,
    /// `Some` when the participant message is present, even with no identity.
    pub participant: Option<String>,
    pub egress: Option<EgressInfo>,
}

pub struct EgressInfo {
    pub egress_id: String,
    pub room_name: String,
    /// protojson of the fields the recording reducer reads.
    pub info_json: String,
}

type Pairs = Vec<(String, Box<serde_json::value::RawValue>)>;

fn object(raw: &str) -> Result<Option<Pairs>, ()> {
    if raw == "null" {
        return Ok(None);
    }
    let mut d = serde_json::Deserializer::from_str(raw);
    struct Strict;
    impl<'de> serde::de::Visitor<'de> for Strict {
        type Value = Pairs;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an object")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Pairs, M::Error> {
            let mut out = Vec::new();
            while let Some(k) = map.next_key::<String>()? {
                out.push((k, map.next_value()?));
            }
            Ok(out)
        }
    }
    let pairs = serde::Deserializer::deserialize_map(&mut d, Strict).map_err(|_| ())?;
    d.end().map_err(|_| ())?;
    Ok(Some(pairs))
}

/// Looks a field up by its JSON or proto name; two spellings of one field,
/// or one repeated, are protojson's "duplicate field" error.
fn field<'a>(pairs: &'a Pairs, json_name: &str, proto_name: &str) -> Result<Option<&'a str>, ()> {
    let mut found = None;
    for (k, v) in pairs {
        if k == json_name || k == proto_name {
            if found.is_some() {
                return Err(());
            }
            found = Some(v.get());
        }
    }
    Ok(found)
}

fn text(raw: Option<&str>) -> Result<String, ()> {
    match raw {
        None | Some("null") => Ok(String::new()),
        Some(v) => serde_json::from_str::<String>(v).map_err(|_| ()),
    }
}

fn int64(raw: Option<&str>) -> Result<i64, ()> {
    let integral = |f: f64| {
        (f.fract() == 0.0 && f >= -9.223372036854776e18 && f < 9.223372036854776e18)
            .then_some(f as i64)
            .ok_or(())
    };
    match raw {
        None | Some("null") => Ok(0),
        Some(v) => match serde_json::from_str::<Value>(v).map_err(|_| ())? {
            Value::Number(n) => n
                .as_i64()
                .map_or_else(|| integral(n.as_f64().ok_or(())?), Ok),
            Value::String(s) => s
                .parse::<i64>()
                .or_else(|_| integral(s.parse::<f64>().map_err(|_| ())?)),
            _ => Err(()),
        },
    }
}

/// Go's `ReceiveWebhookEvent` decode step for the fields the receiver uses.
/// A body protojson would refuse (bad JSON, wrong types, duplicates) is an
/// error, which Go reports as an invalid signature.
pub fn parse_webhook(body: &[u8]) -> Result<WebhookEvent, ()> {
    let text_body = std::str::from_utf8(body).map_err(|_| ())?;
    let root = object(text_body.trim())?.unwrap_or_default();
    let event = text(field(&root, "event", "event")?)?;
    let room = match field(&root, "room", "room")? {
        Some(raw) => match object(raw)? {
            Some(pairs) => text(field(&pairs, "name", "name")?)?,
            None => String::new(),
        },
        None => String::new(),
    };
    let participant = match field(&root, "participant", "participant")? {
        Some(raw) => object(raw)?
            .map(|pairs| text(field(&pairs, "identity", "identity")?))
            .transpose()?,
        None => None,
    };
    let egress = match field(&root, "egressInfo", "egress_info")? {
        Some(raw) => object(raw)?.map(|p| egress_info(&p)).transpose()?,
        None => None,
    };
    Ok(WebhookEvent {
        event,
        room,
        participant,
        egress,
    })
}

const STATUS: [&str; 7] = [
    "EGRESS_STARTING",
    "EGRESS_ACTIVE",
    "EGRESS_ENDING",
    "EGRESS_COMPLETE",
    "EGRESS_FAILED",
    "EGRESS_ABORTED",
    "EGRESS_LIMIT_REACHED",
];

fn egress_info(pairs: &Pairs) -> Result<EgressInfo, ()> {
    let egress_id = text(field(pairs, "egressId", "egress_id")?)?;
    let room_name = text(field(pairs, "roomName", "room_name")?)?;
    let error = text(field(pairs, "error", "error")?)?;
    // Enum: name or number; the default (STARTING) is omitted by protojson.
    let status = match field(pairs, "status", "status")? {
        None | Some("null") => None,
        Some(raw) => match serde_json::from_str::<Value>(raw).map_err(|_| ())? {
            Value::String(name) => match STATUS.iter().position(|s| *s == name) {
                Some(0) => None,
                Some(n) => Some(json!(STATUS[n])),
                None => return Err(()),
            },
            Value::Number(n) => {
                let n = n.as_i64().filter(|n| i32::try_from(*n).is_ok()).ok_or(())?;
                match n {
                    0 => None,
                    1..=6 => Some(json!(STATUS[n as usize])),
                    other => Some(json!(other)),
                }
            }
            _ => return Err(()),
        },
    };
    let mut results = Vec::new();
    match field(pairs, "fileResults", "file_results")? {
        None | Some("null") => {}
        Some(raw) => {
            let items: Vec<Box<serde_json::value::RawValue>> =
                serde_json::from_str(raw).map_err(|_| ())?;
            for item in items {
                let file = object(item.get())?.ok_or(())?;
                let mut entry = serde_json::Map::new();
                for (name, key) in [("size", "size"), ("duration", "duration")] {
                    let n = int64(field(&file, name, key)?)?;
                    if n != 0 {
                        entry.insert(name.into(), json!(n.to_string()));
                    }
                }
                results.push(Value::Object(entry));
            }
        }
    }
    let mut info = serde_json::Map::new();
    if !egress_id.is_empty() {
        info.insert("egressId".into(), json!(egress_id));
    }
    if !room_name.is_empty() {
        info.insert("roomName".into(), json!(room_name));
    }
    if let Some(status) = status {
        info.insert("status".into(), status);
    }
    if !error.is_empty() {
        info.insert("error".into(), json!(error));
    }
    if !results.is_empty() {
        info.insert("fileResults".into(), Value::Array(results));
    }
    Ok(EgressInfo {
        egress_id,
        room_name,
        info_json: Value::Object(info).to_string(),
    })
}

/// `google/uuid.Parse`: canonical, `urn:uuid:` prefixed, braced or 32 plain
/// hex digits. Returns the canonical lower-case form.
pub fn parse_uuid(raw: &str) -> Option<String> {
    let hex = match raw.len() {
        36 => raw,
        45 => raw.strip_prefix("urn:uuid:")?,
        38 => raw.strip_prefix('{')?.strip_suffix('}')?,
        32 => {
            return raw.bytes().all(|b| b.is_ascii_hexdigit()).then(|| {
                let l = raw.to_ascii_lowercase();
                format!(
                    "{}-{}-{}-{}-{}",
                    &l[..8],
                    &l[8..12],
                    &l[12..16],
                    &l[16..20],
                    &l[20..]
                )
            })
        }
        _ => return None,
    };
    let b = hex.as_bytes();
    if b.len() != 36 || [8, 13, 18, 23].iter().any(|i| b[*i] != b'-') {
        return None;
    }
    hex.bytes()
        .enumerate()
        .all(|(i, c)| [8, 13, 18, 23].contains(&i) || c.is_ascii_hexdigit())
        .then(|| hex.to_ascii_lowercase())
}

fn names(v: &Value, list: &str, field: &str) -> Vec<String> {
    v.get(list)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| {
                    x.get(field)
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned()
                })
                .collect()
        })
        .unwrap_or_default()
}
