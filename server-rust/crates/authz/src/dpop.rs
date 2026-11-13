//! Frozen Go VerifyDPoP (runtime's non-ath variant), using ring for ES256.
use base64::{
    alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    Engine,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
};
const URL: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);
/// Entries live at least the whole acceptance window of a proof (`iat` within 60 s
/// either way, so 120 s end to end); 300 s keeps clear margin for clock skew.
const RETAIN_SECS: f64 = 300.0;
const DEFAULT_CAPACITY: usize = 65536;
pub struct ReplayCache {
    seen: Mutex<(HashMap<String, f64>, VecDeque<String>)>,
    capacity: usize,
}
impl Default for ReplayCache {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}
impl ReplayCache {
    pub fn with_capacity(capacity: usize) -> Self {
        Self { seen: Mutex::default(), capacity }
    }
    /// Claim `jti` once. Owner-approved security fix 2026-11-05 (#499): a live entry
    /// is never evicted to make room; a full cache refuses the new proof instead
    /// (frozen Go evicted the oldest entry, so a flood could replay a live proof).
    pub fn add(&self, jti: &str, now: f64) -> bool {
        let mut cache = self.seen.lock().expect("DPoP replay cache");
        while let Some(first) = cache.1.front() {
            if cache.0.get(first).is_none_or(|at| now - *at > RETAIN_SECS) {
                let first = cache.1.pop_front().expect("front");
                cache.0.remove(&first);
            } else {
                break;
            }
        }
        if cache.0.contains_key(jti) {
            return false;
        }
        if cache.0.len() >= self.capacity {
            if !setjoin_contracts::mutants::on("dpop-replay-evicts-live") {
                return false;
            }
            if let Some(first) = cache.1.pop_front() {
                cache.0.remove(&first);
            }
        }
        cache.0.insert(jti.into(), now);
        cache.1.push_back(jti.into());
        true
    }
}
fn coordinate(raw: &str) -> Option<[u8; 32]> {
    let bytes = URL.decode(raw).ok()?;
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let bytes = &bytes[first..];
    if bytes.len() > 32 {
        return None;
    }
    let mut out = [0; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Some(out)
}
/// `cnf.jkt` is the RFC7638 digest of only crv,kty,x,y, in that order.
pub fn thumbprint(jwk: &Value) -> Option<String> {
    if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
        return None;
    }
    let x = jwk["x"].as_str().filter(|s| !s.is_empty())?;
    let y = jwk["y"].as_str().filter(|s| !s.is_empty())?;
    URL.decode(x).ok()?;
    URL.decode(y).ok()?;
    let canonical = json!({"crv":"P-256","kty":"EC","x":x,"y":y}).to_string();
    Some(URL.encode(Sha256::digest(canonical.as_bytes())))
}
/// RFC 9449 `ath`: the unpadded base64url SHA-256 of the access token.
pub fn access_token_hash(access_token: &str) -> String {
    URL.encode(Sha256::digest(access_token.as_bytes()))
}
/// Verifies a DPoP proof for `access_token`. Owner-approved security fix
/// 2026-11-05 (#499): the proof must carry `ath` equal to the access token's
/// hash. Frozen Go's runtime verifier omitted it, so a proof captured for any
/// request was accepted with any token bound to the same key.
pub fn verify(
    proof: &str,
    method: &str,
    uri: &str,
    expected_jkt: &str,
    now: f64,
    replay: &ReplayCache,
    access_token: &str,
) -> bool {
    checked(proof, method, uri, expected_jkt, now, replay, access_token).is_some()
}
fn checked(
    proof: &str,
    method: &str,
    uri: &str,
    expected_jkt: &str,
    now: f64,
    replay: &ReplayCache,
    access_token: &str,
) -> Option<()> {
    let mut parts = proof.split('.');
    let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let header: Value = serde_json::from_slice(&URL.decode(h).ok()?).ok()?;
    if header["alg"] != "ES256" || header["typ"] != "dpop+jwt" {
        return None;
    }
    let jwk = &header["jwk"];
    let x = coordinate(jwk["x"].as_str()?)?;
    let y = coordinate(jwk["y"].as_str()?)?;
    let key = crate::es256::VerifyingKey::from_affine(&x, &y)?;
    if !key.verify(format!("{h}.{p}").as_bytes(), &URL.decode(s).ok()?) {
        return None;
    }
    if thumbprint(jwk)?.as_str() != expected_jkt {
        return None;
    }
    let claims: Value = serde_json::from_slice(&URL.decode(p).ok()?).ok()?;
    claims.as_object()?;
    // jwt.MapClaims validates registered exp/nbf when nonzero, without requiring exp.
    for (field, expiry) in [("exp", true), ("nbf", false)] {
        if let Some(value) = claims.get(field).filter(|v| !v.is_null()) {
            let time = value.as_f64()?;
            if time != 0.0 && ((expiry && now >= time) || (!expiry && now < time)) {
                return None;
            }
        }
    }
    if claims["htm"] != method || claims["htu"] != uri {
        return None;
    }
    if !setjoin_contracts::mutants::on("dpop-without-ath")
        && claims["ath"].as_str() != Some(access_token_hash(access_token).as_str())
    {
        return None;
    }
    let iat = claims["iat"].as_f64().unwrap_or(0.0) as i64;
    if (now - iat as f64).abs() > 60.0 {
        return None;
    }
    let jti = claims["jti"].as_str().filter(|s| !s.is_empty())?;
    if !replay.add(jti, now) {
        return None;
    }
    Some(())
}
