//! Frozen authserver DB-backed ES256 snapshot. No rotation at cutover (#331).
//! PKCS#8 is opened with the existing EK01 codec; ring signs JWS r||s.
use super::{es256::VerifyingKey, legacy_jwt::registered};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use serde_json::{json, Map, Value};
use setjoin_config_secret::{open_column, seal_column, CryptoProfile};
use setjoin_pg::{ScopedExecutor, Type};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

struct Key {
    alg: String,
    signer: EcdsaKeyPair,
    public: VerifyingKey,
}
pub struct KeySet {
    active: String,
    keys: BTreeMap<String, Key>,
}
impl KeySet {
    pub async fn load(
        exec: &ScopedExecutor,
        secret: &[u8],
        profile: CryptoProfile,
    ) -> Result<Self, String> {
        let mut keys = Self::read(exec, secret).await?;
        if keys.active.is_empty() {
            let rng = SystemRandom::new();
            let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .map_err(|_| "generate ES256 key")?;
            let signer =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der.as_ref(), &rng)
                    .map_err(|_| "parse generated key")?;
            let public = VerifyingKey::from_sec1(signer.public_key().as_ref())
                .ok_or("invalid generated public key")?;
            let public_der = p256::PublicKey::from_sec1_bytes(public.sec1())
                .map_err(|_| "invalid public key")?
                .to_public_key_der()
                .map_err(|_| "marshal SPKI")?;
            let hash = Sha256::digest(public_der.as_bytes());
            let kid = format!(
                "es256-{}",
                hash[..8]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            let jwk = jwk(&kid, "ES256", public).to_string();
            let enc = seal_column(der.as_ref(), secret, profile).map_err(|_| "seal signing key")?;
            exec.protocol_statement("INSERT INTO signing_keys(kid,alg,public_jwk,private_key_enc,status) VALUES($1,'ES256',$2::text::jsonb,$3,'active') ON CONFLICT DO NOTHING",&[(&kid,Type::TEXT),(&jwk,Type::TEXT),(&enc,Type::BYTEA)]).await.map_err(|_| "store signing key")?;
            keys = Self::read(exec, secret).await?;
        }
        if keys.active.is_empty() {
            return Err("keystore has no active key after generation".into());
        }
        Ok(keys)
    }
    async fn read(exec: &ScopedExecutor, secret: &[u8]) -> Result<Self, String> {
        let rows=exec.read("SELECT kid,alg,private_key_enc,status FROM signing_keys WHERE status IN ('active','retiring')",&[]).await.map_err(|_| "read signing keys")?;
        let mut keys = BTreeMap::new();
        let mut active = String::new();
        for row in rows {
            let kid: String = row.get(0);
            let alg: String = row.get(1);
            let enc: Vec<u8> = row.get(2);
            let status: String = row.get(3);
            let der =
                zeroize::Zeroizing::new(open_column(&enc, secret).map_err(|_| "open signing key")?);
            // Go x509 emits PKCS#8 v1. Decode with RustCrypto then give ring
            // the private scalar and the matching public point, both validated.
            let private =
                p256::SecretKey::from_pkcs8_der(&der).map_err(|_| "parse signing PKCS8")?;
            let public_der = private
                .public_key()
                .to_public_key_der()
                .map_err(|_| "marshal signing public key")?;
            let public_key = p256::PublicKey::from_public_key_der(public_der.as_bytes())
                .map_err(|_| "parse signing public key")?;
            use p256::elliptic_curve::sec1::ToSec1Point;
            let point = public_key.to_sec1_point(false);
            let public =
                VerifyingKey::from_sec1(point.as_bytes()).ok_or("invalid signing public point")?;
            let signer = EcdsaKeyPair::from_private_key_and_public_key(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                private.to_bytes().as_slice(),
                public.sec1(),
                &SystemRandom::new(),
            )
            .map_err(|_| "invalid ES256 signer")?;
            if status == "active" {
                active = kid.clone();
            }
            keys.insert(
                kid,
                Key {
                    alg,
                    signer,
                    public,
                },
            );
        }
        Ok(Self { active, keys })
    }
    pub fn active_kid(&self) -> &str {
        &self.active
    }
    pub fn jwks(&self) -> Value {
        json!({"keys":self.keys.iter().map(|(kid,k)|jwk(kid,&k.alg,k.public)).collect::<Vec<_>>()})
    }
    pub fn jwks_json(&self) -> String {
        let s = |v: &str| serde_json::to_string(v).unwrap();
        let keys = self
            .keys
            .iter()
            .map(|(kid, k)| {
                format!(
                    r#"{{"use":"sig","kty":"EC","kid":{},"crv":"P-256","alg":{},"x":{},"y":{}}}"#,
                    s(kid),
                    s(&k.alg),
                    s(&URL_SAFE_NO_PAD.encode(k.public.x())),
                    s(&URL_SAFE_NO_PAD.encode(k.public.y()))
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!("{{\"keys\":[{keys}]}}")
    }
    pub fn sign(&self, claims: &str) -> Result<String, String> {
        let key = self.keys.get(&self.active).ok_or("no active signer")?;
        let header = format!(
            r#"{{"alg":"ES256","kid":{},"typ":"JWT"}}"#,
            serde_json::to_string(&self.active).unwrap()
        );
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let sig = key
            .signer
            .sign(&SystemRandom::new(), signed.as_bytes())
            .map_err(|_| "ES256 signing failed")?;
        Ok(format!("{signed}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref())))
    }
    pub fn validate(&self, token: &str, issuer: &str, now: f64) -> Option<Map<String, Value>> {
        let mut parts = token.split('.');
        let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).ok()?).ok()?;
        if header["alg"] != "ES256" {
            return None;
        }
        let key = self.keys.get(header["kid"].as_str()?)?;
        if key.alg != "ES256"
            || !key.public.verify(
                token[..h.len() + 1 + p.len()].as_bytes(),
                &URL_SAFE_NO_PAD.decode(s).ok()?,
            )
        {
            return None;
        }
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).ok()?).ok()?;
        let claims = claims.as_object()?;
        registered(claims, issuer, "mailserver-gateway", now).then(|| claims.clone())
    }
}
fn jwk(kid: &str, alg: &str, k: VerifyingKey) -> Value {
    json!({"use":"sig","kty":"EC","kid":kid,"crv":"P-256","alg":alg,"x":URL_SAFE_NO_PAD.encode(k.x()),"y":URL_SAFE_NO_PAD.encode(k.y())})
}
impl super::token::KeySource for KeySet {
    async fn key(&self, kid: &str) -> Option<VerifyingKey> {
        self.keys
            .get(kid)
            .filter(|k| k.alg == "ES256")
            .map(|k| k.public)
    }
}
