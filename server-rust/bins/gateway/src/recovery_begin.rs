//! Signed recovery offers. Signature, scope and inventory precede reservation.
use crate::{
    recovery::{problem, rejection_response, RecoveryCommands},
    Body, BoxFuture, Intercept, RequestContext,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use http_body_util::BodyExt;
use hyper::{Method, Request, Response};
use serde::{Deserialize, Serialize};
use setjoin_authz::token::KeySource;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, sync::Arc};

pub struct ReceiptKeys {
    key_id: String,
    public: Vec<u8>,
}
impl ReceiptKeys {
    pub fn single(key_id: &str, public: Vec<u8>) -> Self {
        Self {
            key_id: key_id.into(),
            public,
        }
    }
    pub fn from_env() -> Result<Option<Self>, String> {
        use ring::signature::KeyPair;
        let Some(path) = std::env::var_os("CONTINUITY_SIGNING_KEY_FILE") else {
            return Ok(None);
        };
        let path = std::path::Path::new(&path);
        if !path.is_absolute()
            || path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err("continuity key must be a clean absolute path".into());
        }
        let pem = std::fs::read_to_string(path).map_err(|e| format!("continuity key: {e}"))?;
        let encoded = pem
            .strip_prefix("-----BEGIN PRIVATE KEY-----\n")
            .and_then(|p| p.strip_suffix("-----END PRIVATE KEY-----\n"))
            .ok_or("continuity key must be one PKCS#8 PEM block")?;
        let der = STANDARD
            .decode(encoded.split_whitespace().collect::<String>())
            .map_err(|_| "invalid continuity key")?;
        let key = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der)
            .map_err(|_| "continuity key must be Ed25519")?;
        let id = std::env::var("CONTINUITY_SIGNING_KEY_ID").unwrap_or_default();
        if !identifier(&id, 64) {
            return Err("invalid continuity key ID".into());
        }
        Ok(Some(Self::single(&id, key.public_key().as_ref().to_vec())))
    }
    fn verify(&self, receipt: &Receipt, account: &str) -> bool {
        let c = &receipt.claims;
        let canonical = c.canonical();
        let Ok(canonical) = canonical else {
            return false;
        };
        let Ok(signature) = URL_SAFE_NO_PAD.decode(&receipt.signature) else {
            return false;
        };
        let Ok(issued) = chrono::DateTime::parse_from_rfc3339(&c.issued_at) else {
            return false;
        };
        let now = chrono::Utc::now();
        c.key_id == self.key_id
            && c.account_id == account
            && issued <= now + chrono::Duration::minutes(5)
            && issued >= now - chrono::Duration::days(180) - chrono::Duration::minutes(5)
            && ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &self.public)
                .verify(&canonical, &signature)
                .is_ok()
    }
}

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct BlobDigest {
    blob_id: String,
    sha256: String,
    size: String,
}
#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Claims {
    #[serde(rename = "v")]
    version: i32,
    installation_id: String,
    account_id: String,
    original_message_id: String,
    eligibility: String,
    raw_mime_sha256: String,
    raw_mime_size: String,
    blobs: Option<Vec<BlobDigest>>,
    timeline_generation: String,
    state_watermark: String,
    boot_epoch: String,
    issued_at: String,
    key_id: String,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Receipt {
    claims: Claims,
    signature: String,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Item {
    item_id: String,
    role: String,
    sha256: String,
    size: String,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Offer {
    session_id: String,
    incident_id: String,
    account_id: String,
    device_id: String,
    artifact_identity: String,
    eligibility: String,
    receipt: Receipt,
    inventory: Vec<Item>,
    consented_at: String,
    idempotency_key: String,
}
fn decimal(s: &str) -> Option<i64> {
    let n = s.parse::<i64>().ok()?;
    (n >= 0 && n.to_string() == s).then_some(n)
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identifier(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

impl Claims {
    fn canonical(&self) -> Result<Vec<u8>, ()> {
        let uuid = |s: &str| {
            setjoin_blobs::recovery_uuid(s).is_some() || s == "00000000-0000-0000-0000-000000000000"
        };
        let positive = |s: &str| decimal(s).is_some_and(|n| n > 0);
        let time = chrono::DateTime::parse_from_rfc3339(&self.issued_at).map_err(|_| ())?;
        if self.version != 1
            || !uuid(&self.installation_id)
            || !uuid(&self.boot_epoch)
            || !positive(&self.account_id)
            || !identifier(&self.original_message_id, 256)
            || !matches!(self.eligibility.as_str(), "received" | "sent-terminal")
            || !digest(&self.raw_mime_sha256)
            || !positive(&self.raw_mime_size)
            || !positive(&self.timeline_generation)
            || decimal(&self.state_watermark).is_none()
            || !identifier(&self.key_id, 64)
            || time
                .with_timezone(&chrono::Utc)
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string()
                != self.issued_at
        {
            return Err(());
        }
        let mut canonical = self.clone();
        let mut blobs = canonical.blobs.take().unwrap_or_default();
        if blobs.len() > 4096 {
            return Err(());
        }
        blobs.sort_by(|a, b| a.blob_id.cmp(&b.blob_id));
        let mut seen = HashSet::new();
        for blob in &blobs {
            if !identifier(&blob.blob_id, 256)
                || !digest(&blob.sha256)
                || decimal(&blob.size).is_none()
                || !seen.insert(&blob.blob_id)
            {
                return Err(());
            }
        }
        canonical.blobs = if blobs.is_empty() { None } else { Some(blobs) };
        serde_json::to_vec(&canonical)
            .map(|v| {
                String::from_utf8(v)
                    .expect("JSON UTF8")
                    .replace('<', "\\u003c")
                    .replace('>', "\\u003e")
                    .replace('&', "\\u0026")
                    .replace('\u{2028}', "\\u2028")
                    .replace('\u{2029}', "\\u2029")
                    .into_bytes()
            })
            .map_err(|_| ())
    }
}
pub struct BeginRoute<K: KeySource + 'static>(pub Arc<RecoveryCommands<K>>, pub Arc<ReceiptKeys>);
impl<K: KeySource + 'static> Intercept for BeginRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        r.method() == Method::POST && r.uri().path() == "/api/recovery/uploads"
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        let c = self.0.clone();
        Box::pin(async move { c.authorize(&h, s).await.is_some() })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let commands = self.0.clone();
        let keys = self.1.clone();
        Box::pin(async move {
            let Some(a) = commands.authorize(r.headers(), c.identity.proto).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let operation = crate::jmap::random().expect("OS randomness");
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let fail = |status, detail| problem(status, detail, c.identity.proto, id.clone());
            let mut bytes = Vec::new();
            while let Some(frame) = r.body_mut().frame().await {
                let Ok(frame) = frame else {
                    return fail(400, "invalid recovery request");
                };
                if let Ok(data) = frame.into_data() {
                    if bytes.len() + data.len() > 1 << 20 {
                        return fail(400, "invalid recovery request");
                    }
                    bytes.extend_from_slice(&data);
                }
            }
            let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
            let Ok(GoValue(value)) = GoValue::deserialize(&mut deserializer) else {
                return fail(400, "invalid recovery request");
            };
            let offer = if value.is_null() {
                Offer::default()
            } else {
                match serde_json::from_value::<Offer>(value) {
                    Ok(offer) => offer,
                    Err(_) => return fail(400, "invalid recovery request"),
                }
            };
            if deserializer.end().is_err() {
                return fail(400, "recovery request must contain exactly one JSON object");
            }
            let header = r
                .headers()
                .get("idempotency-key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .trim();
            if offer.idempotency_key.is_empty() || header != offer.idempotency_key {
                return fail(
                    400,
                    "body idempotencyKey must exactly match Idempotency-Key",
                );
            }
            let idem = setjoin_blobs::recovery_uuid(&offer.idempotency_key);
            if idem.is_none() {
                return fail(400, "invalid recovery idempotency key");
            }
            let (Some(session), Some(incident), Some(device), Some(mailbox)) = (
                setjoin_blobs::recovery_uuid(&offer.session_id),
                setjoin_blobs::recovery_uuid(&offer.incident_id),
                setjoin_blobs::recovery_uuid(&offer.device_id),
                decimal(&offer.account_id).filter(|n| *n > 0),
            ) else {
                return fail(400, "invalid recovery upload identity");
            };
            if !matches!(offer.eligibility.as_str(), "received" | "sent-terminal") {
                return fail(400, "invalid recovery upload identity");
            }
            if !keys.verify(&offer.receipt, &offer.account_id) {
                return fail(403, "recovery receipt verification failed");
            }
            let claims = &offer.receipt.claims;
            if offer.eligibility != claims.eligibility {
                return fail(400, "recovery eligibility does not match signed receipt");
            }
            let expected = format!(
                "{:x}",
                Sha256::digest(format!(
                    "v1\0{}\0{}\0{}\0{}",
                    claims.installation_id,
                    claims.account_id,
                    claims.original_message_id,
                    claims.raw_mime_sha256
                ))
            );
            if offer.artifact_identity != expected {
                return fail(400, "recovery artifact identity mismatch");
            }
            if let Err(detail) = inventory(claims, &offer.inventory) {
                return fail(400, detail);
            }
            let Ok(consented) = chrono::DateTime::parse_from_rfc3339(&offer.consented_at) else {
                return fail(400, "invalid recovery request");
            };
            let receipt = serde_json::to_string(&offer.receipt).expect("receipt JSON");
            let items = serde_json::to_string(&offer.inventory).expect("inventory JSON");
            match setjoin_blobs::begin_upload(
                &commands.worker_exec,
                a.context(),
                setjoin_blobs::BeginUpload {
                    session: &session,
                    incident: &incident,
                    mailbox,
                    device: &device,
                    artifact: &offer.artifact_identity,
                    eligibility: &offer.eligibility,
                    receipt: &receipt,
                    inventory: &items,
                    consented: consented.with_timezone(&chrono::Utc).to_rfc3339(),
                    idempotency: idem.as_deref().unwrap(),
                },
                operation,
            )
            .await
            {
                setjoin_pg::CommandOutcome::Committed(raw) => {
                    let mut response = crate::jmap::reply::response(raw, c.identity.proto, id);
                    *response.status_mut() = hyper::StatusCode::CREATED;
                    response
                }
                setjoin_pg::CommandOutcome::RolledBack(error) => {
                    rejection_response(&error, &r, &c, id, "recovery control operation failed", 500)
                }
                setjoin_pg::CommandOutcome::Unknown { operation } => {
                    let mut response = fail(503, "recovery upload outcome unknown");
                    response.headers_mut().insert(
                        "x-operation-id",
                        setjoin_pg::operation_hex(operation).parse().expect("hex"),
                    );
                    response
                }
            }
        })
    }
}
fn inventory(claims: &Claims, items: &[Item]) -> Result<(), &'static str> {
    let blobs = claims.blobs.as_deref().unwrap_or_default();
    if items.len() != blobs.len() + 1 || items.len() > 4097 {
        return Err("recovery inventory cardinality mismatch");
    }
    let mut signed: std::collections::HashMap<_, _> =
        blobs.iter().map(|b| (&b.blob_id, b)).collect();
    let mut seen = HashSet::new();
    let mut raw = 0;
    let mut total = 0i64;
    for item in items {
        if item.item_id.is_empty()
            || item.item_id.len() > 256
            || item.item_id.contains(['/', '\0', '\r', '\n'])
        {
            return Err("invalid recovery inventory item");
        }
        if !seen.insert(&item.item_id) {
            return Err("duplicate recovery inventory item");
        }
        let Some(size) = decimal(&item.size).filter(|v| *v > 0 && *v <= 8 << 30) else {
            return Err("invalid recovery inventory size");
        };
        if item.sha256.len() != 64 || !item.sha256.bytes().all(|v| v.is_ascii_hexdigit()) {
            return Err("invalid recovery inventory digest");
        }
        match item.role.as_str() {
            "raw" => {
                raw += 1;
                if item.item_id != "raw"
                    || item.sha256 != claims.raw_mime_sha256
                    || item.size != claims.raw_mime_size
                    || size > 50 << 20
                {
                    return Err("raw MIME inventory differs from receipt");
                }
            }
            "attachment" | "inline" => {
                let Some(blob) = signed.remove(&item.item_id) else {
                    return Err("blob inventory differs from receipt");
                };
                if blob.sha256 != item.sha256 || blob.size != item.size {
                    return Err("blob inventory differs from receipt");
                }
            }
            _ => return Err("invalid recovery inventory role"),
        }
        if total > (8 << 30) - size {
            return Err("recovery artifact exceeds size limit");
        }
        total += size;
    }
    if raw != 1 || !signed.is_empty() {
        return Err("recovery inventory is incomplete");
    }
    Ok(())
}

// encoding/json matches struct fields case-insensitively in wire order.
// Preserve that order while folding keys, including Go's two ASCII-equivalent
// Unicode folds. String/struct nulls leave an earlier value unchanged.
struct GoValue(serde_json::Value);
impl<'de> Deserialize<'de> for GoValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = GoValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<GoValue, E> {
                Ok(GoValue(serde_json::Value::Null))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<GoValue, E> {
                Ok(GoValue(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<GoValue, E> {
                Ok(GoValue(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<GoValue, E> {
                Ok(GoValue(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<GoValue, E> {
                serde_json::Number::from_f64(v)
                    .map(|v| GoValue(v.into()))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<GoValue, E> {
                Ok(GoValue(v.into()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<GoValue, E> {
                Ok(GoValue(v.into()))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<GoValue, A::Error> {
                let mut items = Vec::new();
                while let Some(GoValue(v)) = a.next_element()? {
                    items.push(v);
                }
                Ok(GoValue(items.into()))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<GoValue, A::Error> {
                const NAMES: &[&str] = &[
                    "sessionId",
                    "incidentId",
                    "accountId",
                    "deviceId",
                    "artifactIdentity",
                    "eligibility",
                    "receipt",
                    "inventory",
                    "consentedAt",
                    "idempotencyKey",
                    "claims",
                    "signature",
                    "v",
                    "installationId",
                    "originalMessageId",
                    "rawMimeSha256",
                    "rawMimeSize",
                    "blobs",
                    "timelineGeneration",
                    "stateWatermark",
                    "bootEpoch",
                    "issuedAt",
                    "keyId",
                    "blobId",
                    "itemId",
                    "role",
                    "sha256",
                    "size",
                ];
                let mut fields = serde_json::Map::new();
                while let Some(raw) = a.next_key::<String>()? {
                    let folded: String = raw
                        .chars()
                        .map(|c| match c {
                            '\u{212a}' => 'k',
                            '\u{017f}' => 's',
                            _ => c.to_ascii_lowercase(),
                        })
                        .collect();
                    let known = NAMES
                        .iter()
                        .find(|name| name.to_ascii_lowercase() == folded)
                        .copied();
                    let key = known.unwrap_or(&raw).to_owned();
                    let GoValue(value) = a.next_value()?;
                    if value.is_null()
                        && known.is_some()
                        && !matches!(key.as_str(), "inventory" | "blobs")
                    {
                        continue;
                    }
                    if matches!(key.as_str(), "receipt" | "claims") && value.is_object() {
                        if let Some(old) = fields.get_mut(&key) {
                            merge_struct(old, value);
                            continue;
                        }
                    }
                    fields.insert(key, value);
                }
                Ok(GoValue(fields.into()))
            }
        }
        d.deserialize_any(Visitor)
    }
}
fn merge_struct(old: &mut serde_json::Value, new: serde_json::Value) {
    if let (Some(old), Some(new)) = (old.as_object_mut(), new.as_object()) {
        for (key, value) in new {
            if key == "claims" {
                if let Some(previous) = old.get_mut(key) {
                    merge_struct(previous, value.clone());
                    continue;
                }
            }
            old.insert(key.clone(), value.clone());
        }
    } else {
        *old = new;
    }
}
