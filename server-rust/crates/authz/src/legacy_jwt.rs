//! First-party HS256/SM2 signature and registered-claim verification (#331).
//! Keys come from deployment configuration only; alg/kid never choose an
//! embedded key or turn an EC key into an HMAC secret. Guest admission is #406.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::hmac;
use serde_json::{Map, Value};
use sm2::dsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sm3::{Digest, Sm3};

pub struct LegacyKeys {
    hmac: hmac::Key,
    hmac_kids: Vec<String>,
    sm2: Option<VerifyingKey>,
    configured: bool,
}
impl LegacyKeys {
    pub fn from_pem(secret: &[u8], kids: &[&str], pem: Option<&str>) -> Result<Self, &'static str> {
        let signer = pem.map(sm2_signer).transpose()?;
        let point = signer.as_ref().map(|s| s.verifying_key().to_sec1_bytes());
        Self::new(secret, kids, point.as_deref())
    }

    pub fn new(
        secret: &[u8],
        kids: &[&str],
        sm2_point: Option<&[u8]>,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            hmac: hmac::Key::new(hmac::HMAC_SHA256, secret),
            hmac_kids: kids.iter().map(|s| (*s).to_owned()).collect(),
            // The distinguishing id is unused by verify_prehash: Go signs
            // SM3(JWS signing input) directly, with no ZA prefix.
            sm2: sm2_point
                .map(|p| VerifyingKey::from_sec1_bytes("1234567812345678", p))
                .transpose()
                .map_err(|_| "invalid SM2 point")?,
            configured: !secret.is_empty(),
        })
    }
    pub fn verify_signature(&self, token: &str) -> Option<Map<String, Value>> {
        if !self.configured {
            return None;
        }
        let mut parts = token.split('.');
        let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let header: Value = serde_json::from_slice(&decode(h)?).ok()?;
        let kid = header["kid"].as_str()?;
        let sig = decode(s)?;
        let signed = &token[..h.len() + 1 + p.len()];
        match header["alg"].as_str()? {
            "HS256" if self.hmac_kids.iter().any(|k| k == kid) => {
                hmac::verify(&self.hmac, signed.as_bytes(), &sig).ok()?
            }
            "SM2" if kid == "authserver-sm2-1" => {
                let sig = Signature::from_der(&sig).ok()?;
                self.sm2
                    .as_ref()?
                    .verify_prehash(&Sm3::digest(signed.as_bytes()), &sig)
                    .ok()?;
            }
            _ => return None,
        }
        serde_json::from_slice::<Value>(&decode(p)?)
            .ok()?
            .as_object()
            .cloned()
    }
    pub fn validate(
        &self,
        token: &str,
        issuer: &str,
        audience: &str,
        now: f64,
    ) -> Option<Map<String, Value>> {
        let claims = self.verify_signature(token)?;
        registered(&claims, issuer, audience, now).then_some(claims)
    }
}
fn decode(s: &str) -> Option<Vec<u8>> {
    // Go RawURLEncoding ignores CR/LF and noncanonical trailing pad bits.
    use base64::{
        alphabet,
        engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    };
    let engine = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    );
    engine.decode(s.replace(['\r', '\n'], "")).ok()
}
pub fn registered(c: &Map<String, Value>, issuer: &str, audience: &str, now: f64) -> bool {
    if issuer.is_empty()
        || audience.is_empty()
        || c.get("iss").and_then(Value::as_str) != Some(issuer)
    {
        return false;
    }
    let aud = match c.get("aud") {
        Some(Value::String(a)) => a == audience,
        Some(Value::Array(a)) => {
            a.iter().all(Value::is_string) && a.iter().any(|a| a.as_str() == Some(audience))
        }
        _ => false,
    };
    // NumericDate accepts fractional JSON numbers; iat is not validated by Go.
    aud && c
        .get("exp")
        .and_then(Value::as_f64)
        .is_some_and(|e| now < e.floor())
        && c.get("nbf")
            .filter(|v| !v.is_null())
            .is_none_or(|v| v.as_f64().is_some_and(|n| now >= n.floor()))
}
/// Standard-profile issuance. The caller owns the typed claims and lifetime.
pub fn sign_hs256(secret: &[u8], claims_json: &str) -> String {
    let header =
        URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","kid":"authserver-hmac-1","typ":"JWT"}"#);
    let signed = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims_json));
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    format!(
        "{signed}.{}",
        URL_SAFE_NO_PAD.encode(hmac::sign(&key, signed.as_bytes()).as_ref())
    )
}

fn sm2_signer(pem: &str) -> Result<sm2::dsa::SigningKey, &'static str> {
    use sm2::pkcs8::DecodePrivateKey;
    let key = if pem.contains("BEGIN EC PRIVATE KEY") {
        sm2::SecretKey::from_sec1_pem(pem).map_err(|_| "invalid SM2 SEC1 key")?
    } else {
        sm2::SecretKey::from_pkcs8_pem(pem).map_err(|_| "invalid SM2 PKCS8 key")?
    };
    sm2::dsa::SigningKey::new("1234567812345678", &key).map_err(|_| "invalid SM2 signing key")
}
pub fn sign_sm2(pem: &str, claims_json: &str) -> Result<String, &'static str> {
    use sm2::dsa::signature::hazmat::PrehashSigner;
    let key = sm2_signer(pem)?;
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"SM2","kid":"authserver-sm2-1","typ":"JWT"}"#);
    let signed = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims_json));
    let sig: Signature = key
        .sign_prehash(&Sm3::digest(signed.as_bytes()))
        .map_err(|_| "SM2 signing failed")?;
    Ok(format!(
        "{signed}.{}",
        URL_SAFE_NO_PAD.encode(sig.to_der().as_bytes())
    ))
}
