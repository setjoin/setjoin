//! The access token Go would authenticate a request with, verified the
//! way Go verifies first-party tokens (`shared/jwtutil.Verifier`, ARCH-005), plus
//! the claim checks Go's chain applies before a JMAP method runs.
//!
//! Every function here answers "may Rust serve this?", never "reject": a
//! token Rust cannot verify (unconfigured HS256/SM2 material; an
//! unknown kid; a malformed or expired token) makes the route forward the
//! request so Go authenticates — and rejects — it exactly as today.

pub use crate::es256::VerifyingKey;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hyper::header::{HeaderMap, AUTHORIZATION, COOKIE};
use serde_json::{Map, Value};

/// Go's gateway audience (`mailserver/internal/auth/jwt.go`).
pub const AUDIENCE: &str = "mailserver-gateway";
const ACCESS_COOKIE: &str = "access_token";

/// Resolves an ES256 verification key by `kid` (the JWKS client).
pub trait KeySource: Send + Sync {
    fn legacy_keys(&self) -> Option<&crate::legacy_jwt::LegacyKeys> {
        None
    }
    fn key(&self, kid: &str) -> impl std::future::Future<Output = Option<VerifyingKey>> + Send;
}

/// The claims the route acts on, from a verified access token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub(crate) user_id: i64,
    pub(crate) email: String,
    /// `iat` (seconds), required: the revocation watermark compares it.
    pub(crate) issued_at: i64,
    pub(crate) jti: String,
    pub(crate) family: String,
    pub(crate) domain_scope: Option<i64>,
    pub(crate) admin: bool,
    pub(crate) permissions: Vec<String>,
    /// `auth_time` (seconds), Go's `claims.SessionAuthTime`; absent when unsigned.
    pub(crate) auth_time: Option<i64>,
    /// Signed `acr` and `amr` claims (empty when absent), for step-up bindings.
    pub(crate) acr: String,
    pub(crate) amr: Vec<String>,
    /// Signed `device.id` (Go's `Claims.Device.ID`), empty when the token carries no device.
    pub(crate) device_id: String,
}

/// The token Go's `jwt_bearer` method reads: `Authorization: Bearer <t>`
/// when that header has the `Bearer ` prefix, else the `access_token` cookie.
/// Ambiguity Go might resolve differently (several Authorization headers or
/// access_token cookies, non-ASCII headers) yields `None`.
pub fn extract(headers: &HeaderMap) -> Option<String> {
    let mut auth = headers.get_all(AUTHORIZATION).iter();
    match (auth.next(), auth.next()) {
        (Some(_), Some(_)) => return None,
        (Some(v), None) => {
            if let Some(token) = v.to_str().ok()?.strip_prefix("Bearer ") {
                return token_chars(token).then(|| token.to_owned());
            }
        }
        _ => {}
    }
    let mut found = None;
    for line in headers.get_all(COOKIE) {
        for pair in line.to_str().ok()?.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name.trim() == ACCESS_COOKIE {
                if found.is_some() {
                    return None;
                }
                found = Some(value.trim().to_owned());
            }
        }
    }
    found.filter(|t| token_chars(t))
}

fn token_chars(t: &str) -> bool {
    !t.is_empty()
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Verifies `token` as an ES256 first-party access token and applies the
/// conservative claim checks for the pilot routes; `None` = let Go decide.
///
/// Mirrors `jwtutil.Verifier.Validate` for the ES256 branch: header `alg`
/// exactly `ES256`, non-empty `kid` resolved only through `keys` (never
/// `jku`/`x5u`/`jwk`), signature over `header.payload`, `iss` equal to
/// `issuer`, `aud` containing [`AUDIENCE`], `exp` required and in the
/// future, `nbf` (if any) not in the future. Then `chain.go`/`RequireAuth`:
/// `typ` = `access`, no `scp` (a scoped mirror never authenticates
/// `/jmap`). Beyond Go, conservatively: `uid` > 0, `iat` present (the
/// revocation watermark compares it), no guest `acct`, no impersonation
/// `act`, and every claim Go decodes has the JSON type Go expects.
pub async fn verify(token:&str,issuer:&str,now_unix:f64,keys:&impl KeySource)->Option<Session>{verify_scope(token,issuer,now_unix,keys,false).await}
/// Drive adapters only: the ordinary guard still refuses every scoped mirror.
pub async fn verify_drive(token:&str,issuer:&str,now_unix:f64,keys:&impl KeySource)->Option<Session>{verify_scope(token,issuer,now_unix,keys,true).await}
async fn verify_scope(token:&str,issuer:&str,now_unix:f64,keys:&impl KeySource,drive:bool)->Option<Session>{
    let claims = signed_claims(token, keys).await?;
    let claims = &claims;
    claims_shape_ok(claims)?;

    if claims.get("iss")?.as_str()? != issuer || issuer.is_empty() {
        return None;
    }
    let audience_ok = match claims.get("aud")? {
        Value::String(a) => a == AUDIENCE,
        Value::Array(list) => list.iter().any(|a| a.as_str() == Some(AUDIENCE)),
        _ => false,
    };
    if !audience_ok {
        return None;
    }
    let exp = claims.get("exp")?.as_i64()?;
    if now_unix >= exp as f64 {
        return None;
    }
    if let Some(nbf) = claims.get("nbf").filter(|v| !v.is_null()) {
        if now_unix < nbf.as_i64()? as f64 {
            return None;
        }
    }
    if claims.get("typ")?.as_str()? != "access" {
        return None;
    }
    let scope=str_claim(claims,"scp");
    if (!scope.is_empty() && !(drive && scope=="drive")) || str_claim(claims,"acct")=="guest" {
        return None;
    }
    if claims.get("act").is_some_and(|v| !v.is_null()) {
        return None;
    }
    let user_id = claims.get("uid")?.as_i64().filter(|u| *u > 0)?;
    let issued_at = claims.get("iat")?.as_i64()?;
    Some(Session {
        user_id,
        email: str_claim(claims, "email").to_owned(),
        issued_at,
        jti: str_claim(claims, "jti").to_owned(),
        family: str_claim(claims, "fam").to_owned(),
        domain_scope: claims.get("domain").and_then(Value::as_i64),
        auth_time: claims.get("auth_time").and_then(Value::as_i64),
        admin: claims
            .get("admin")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        acr: str_claim(claims, "acr").to_owned(),
        device_id: claims
            .get("device")
            .and_then(Value::as_object)
            .map_or("", |device| str_claim(device, "id"))
            .to_owned(),
        amr: claims
            .get("amr")
            .and_then(Value::as_array)
            .map_or_else(Vec::new, |values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            }),
        permissions: claims.get("perms").and_then(Value::as_array).map_or_else(
            Vec::new,
            |values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            },
        ),
    })
}

/// The ES256 signature layer of [`verify`]: three segments, header `alg`
/// exactly `ES256`, a non-empty `kid` resolved only through `keys`, a valid
/// signature over `header.payload`, and a JSON-object payload. No claim is
/// checked here; `None` = let Go decide.
pub(crate) async fn signed_claims(
    token: &str,
    keys: &impl KeySource,
) -> Option<Map<String, Value>> {
    let mut parts = token.split('.');
    let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).ok()?).ok()?;
    let header = header.as_object()?;
    if header.get("alg")?.as_str()? != "ES256" {
        return keys.legacy_keys()?.verify_signature(token);
    }
    let kid = header.get("kid")?.as_str()?;
    if kid.is_empty() {
        return None;
    }
    let signature = URL_SAFE_NO_PAD.decode(s).ok()?;
    if signature.len() != crate::es256::SIGNATURE_LEN {
        return None;
    }
    let key = keys.key(kid).await?;
    let signed = &token[..h.len() + 1 + p.len()];
    if !key.verify(signed.as_bytes(), &signature) {
        return None;
    }

    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).ok()?).ok()?;
    match claims {
        Value::Object(claims) => Some(claims),
        _ => None,
    }
}

fn str_claim<'a>(claims: &'a Map<String, Value>, key: &str) -> &'a str {
    claims.get(key).and_then(Value::as_str).unwrap_or("")
}

#[derive(Clone, Copy)]
enum Kind {
    Str,
    Bool,
    Int,
    StrList,
    Object,
    Audience,
}

/// Every claim `jwtutil.Claims` decodes, with the JSON type Go expects.
const KNOWN: [(&str, Kind); 29] = [
    ("uid", Kind::Int),
    ("email", Kind::Str),
    ("admin", Kind::Bool),
    ("perms", Kind::StrList),
    ("domain", Kind::Int),
    ("typ", Kind::Str),
    ("jti", Kind::Str),
    ("fam", Kind::Str),
    ("act", Kind::Int),
    ("acct", Kind::Str),
    ("acr", Kind::Str),
    ("amr", Kind::StrList),
    ("auth_method", Kind::Str),
    ("device", Kind::Object),
    ("mam", Kind::Object),
    ("risk", Kind::Object),
    ("cnf", Kind::Object),
    ("sif", Kind::Int),
    ("auth_time", Kind::Int),
    ("identity_fence", Kind::Object),
    ("credential_fence", Kind::Str),
    ("scp", Kind::Str),
    ("attachment", Kind::Object),
    ("iss", Kind::Str),
    ("sub", Kind::Str),
    ("aud", Kind::Audience),
    ("exp", Kind::Int),
    ("nbf", Kind::Int),
    ("iat", Kind::Int),
];

/// Go's `encoding/json` matches keys case-insensitively and fails the whole
/// token on a type mismatch. Rust serves only tokens where neither question
/// arises: each known claim spelled exactly and typed as Go expects (null is
/// Go's zero value). Runtime-consumed nested claims also retain Go's field types.
pub(crate) fn claims_shape_ok(claims: &Map<String, Value>) -> Option<()> {
    for (key, value) in claims {
        let lower = key.to_ascii_lowercase();
        let Some((name, kind)) = KNOWN.iter().find(|(n, _)| *n == lower) else {
            continue;
        };
        if name != key {
            return None;
        }
        let ok = value.is_null()
            || match kind {
                Kind::Str => value.is_string(),
                Kind::Bool => value.is_boolean(),
                Kind::Int => value.is_i64(),
                Kind::Object => value.is_object(),
                Kind::StrList => value
                    .as_array()
                    .is_some_and(|l| l.iter().all(Value::is_string)),
                Kind::Audience => {
                    value.is_string()
                        || value
                            .as_array()
                            .is_some_and(|l| l.iter().all(Value::is_string))
                }
            };
        if !ok {
            return None;
        }
    }
    for (name, fields) in [
        ("device", &[("id",Kind::Str),("trust_tier",Kind::Str),("compliance_status",Kind::Str),("wipe_requested",Kind::Bool)][..]),
        ("risk", &[("user_score",Kind::Int),("level",Kind::Str),("requires_mfa",Kind::Bool),("signals",Kind::StrList)][..]),
        ("cnf", &[("jkt",Kind::Str),("x5t#s256",Kind::Str)][..]),
    ] {
        if let Some(object)=claims.get(name).and_then(Value::as_object) {
            for (key,value) in object {
                if let Some((known,kind))=fields.iter().find(|(n,_)|*n==key.to_ascii_lowercase()) {
                    if key!=known && !(name=="cnf" && key=="x5t#S256") {return None;}
                    let valid=value.is_null()||match kind {
                        Kind::Str=>value.is_string(),Kind::Bool=>value.is_boolean(),Kind::Int=>value.is_i64(),
                        Kind::StrList=>value.as_array().is_some_and(|a|a.iter().all(Value::is_string)),_=>false,
                    };
                    if !valid{return None;}
                }
            }
        }
    }
    Some(())
}

/// Dedicated Go attachment-token verifier. This narrow kid never authenticates
/// an ordinary route; retiring secrets verify only this five-minute scope.
pub(crate) fn attachment(
    token: &str,
    issuer: &str,
    now: f64,
    secrets: &[&[u8]],
) -> Option<(Session, Value)> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let parts: Vec<_> = token.split('.').collect();
    let [h, p, s] = parts.as_slice() else {
        return None;
    };
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).ok()?).ok()?;
    if header["alg"] != "HS256" || header["kid"] != "mailserver-mail-attachment-1" {
        return None;
    }
    let signature = URL_SAFE_NO_PAD.decode(s).ok()?;
    let signed = format!("{h}.{p}");
    let valid = secrets.iter().filter(|s| !s.is_empty()).any(|secret| {
        // RFC 5869, no info, 32 bytes; Go cryptokey domain separation.
        let mut extract = Hmac::<Sha256>::new_from_slice(b"mailserver-mail-attachment-token-v1")
            .expect("HMAC key");
        extract.update(secret);
        let prk = extract.finalize().into_bytes();
        let mut expand = Hmac::<Sha256>::new_from_slice(&prk).expect("HMAC key");
        expand.update(&[1]);
        let key = expand.finalize().into_bytes();
        let mut verifier = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC key");
        verifier.update(signed.as_bytes());
        verifier.verify_slice(&signature).is_ok()
    });
    if !valid {
        return None;
    }
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).ok()?).ok()?;
    let object = claims.as_object()?;
    claims_shape_ok(object)?;
    if claims["iss"].as_str() != Some(issuer)
        || issuer.is_empty()
        || claims["typ"] != "access"
        || claims["scp"] != "mail-attachment"
        || claims["acct"] == "guest"
        || !claims["act"].is_null()
    {
        return None;
    }
    let audience = match &claims["aud"] {
        Value::String(v) => v == AUDIENCE,
        Value::Array(v) => v.iter().any(|x| x == AUDIENCE),
        _ => false,
    };
    if !audience
        || now >= claims["exp"].as_i64()? as f64
        || claims["nbf"].as_i64().is_some_and(|nbf| now < nbf as f64)
    {
        return None;
    }
    Some((
        Session {
            user_id: claims["uid"].as_i64().filter(|v| *v > 0)?,
            email: str_claim(object, "email").to_owned(),
            issued_at: claims["iat"].as_i64()?,
            jti: str_claim(object, "jti").into(),
            family: str_claim(object, "fam").into(),
            domain_scope: None,
            auth_time: None,
            admin: false,
            permissions: Vec::new(),
            acr: String::new(),
            amr: Vec::new(),
            device_id: String::new(),
        },
        claims,
    ))
}

impl<K: KeySource> KeySource for std::sync::Arc<K> {
    fn legacy_keys(&self)->Option<&crate::legacy_jwt::LegacyKeys>{self.as_ref().legacy_keys()}

    async fn key(&self, kid: &str) -> Option<VerifyingKey> {
        self.as_ref().key(kid).await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use serde_json::json;

    pub(crate) struct OneKey(pub &'static str, pub VerifyingKey);
    impl KeySource for OneKey {
        async fn key(&self, kid: &str) -> Option<VerifyingKey> {
            (kid == self.0).then_some(self.1)
        }
    }

    pub(crate) fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    /// The production key type for a test signer (RustCrypto signs, `ring`
    /// verifies: a cross-implementation check).
    pub(crate) fn public_key(key: &SigningKey) -> VerifyingKey {
        VerifyingKey::from_sec1(key.verifying_key().to_sec1_point(false).as_bytes()).unwrap()
    }

    pub(crate) fn sign(key: &SigningKey, header: &Value, claims: &Value) -> String {
        let h = URL_SAFE_NO_PAD.encode(header.to_string());
        let p = URL_SAFE_NO_PAD.encode(claims.to_string());
        let sig: Signature = key.sign(format!("{h}.{p}").as_bytes());
        format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    const NOW: f64 = 1_800_000_000.0;

    fn claims() -> Value {
        json!({"uid": 7, "email": "a@x.test", "typ": "access", "jti": "j1", "fam": "f1",
               "iss": "mailserver", "aud": ["mailserver-gateway"],
               "iat": 1_799_999_000, "exp": 1_800_000_900})
    }

    async fn check(header: Value, claims: Value) -> Option<Session> {
        let key = signing_key(1);
        let token = sign(&key, &header, &claims);
        verify(&token, "mailserver", NOW, &OneKey("k1", public_key(&key))).await
    }

    fn es256() -> Value {
        json!({"alg": "ES256", "kid": "k1", "typ": "JWT"})
    }

    #[tokio::test]
    async fn a_valid_es256_access_token_yields_its_session() {
        assert_eq!(
            check(es256(), claims()).await,
            Some(Session {
                user_id: 7,
                email: "a@x.test".into(),
                issued_at: 1_799_999_000,
                jti: "j1".into(),
                family: "f1".into(),
                domain_scope: None,
                auth_time: None,
                admin: false,
                permissions: vec![],
                acr: String::new(),
                amr: vec![],
                device_id: String::new(),
            })
        );
    }

    #[tokio::test]
    async fn tokens_go_would_reject_or_rust_cannot_verify_are_not_served() {
        let with = |k: &str, v: Value| {
            let mut c = claims();
            c[k] = v;
            c
        };
        let without = |k: &str| {
            let mut c = claims();
            c.as_object_mut().unwrap().remove(k);
            c
        };
        let cases: Vec<(&str, Value, Value)> = vec![
            ("expired", es256(), with("exp", json!(1_800_000_000))),
            ("no exp", es256(), without("exp")),
            ("not yet valid", es256(), with("nbf", json!(1_800_000_100))),
            ("wrong issuer", es256(), with("iss", json!("other"))),
            ("wrong audience", es256(), with("aud", json!("other"))),
            ("refresh token", es256(), with("typ", json!("refresh"))),
            ("mfa pending", es256(), with("typ", json!("mfa_pending"))),
            ("scoped mirror", es256(), with("scp", json!("drive"))),
            ("guest claim", es256(), with("acct", json!("guest"))),
            ("impersonation", es256(), with("act", json!(3))),
            ("no iat", es256(), without("iat")),
            ("uid as string", es256(), with("uid", json!("7"))),
            ("case variant", es256(), with("UID", json!(9))),
            ("float exp", es256(), with("exp", json!(1_800_000_900.5))),
            (
                "hs256",
                json!({"alg": "HS256", "kid": "authserver-hmac-1"}),
                claims(),
            ),
            (
                "unknown kid",
                json!({"alg": "ES256", "kid": "k2"}),
                claims(),
            ),
            ("no kid", json!({"alg": "ES256"}), claims()),
            ("none", json!({"alg": "none", "kid": "k1"}), claims()),
        ];
        for (name, header, claims) in cases {
            assert_eq!(check(header, claims).await, None, "{name}");
        }
    }

    #[tokio::test]
    async fn a_token_signed_by_another_key_is_not_served() {
        let token = sign(&signing_key(2), &es256(), &claims());
        let trusted = public_key(&signing_key(1));
        assert_eq!(
            verify(&token, "mailserver", NOW, &OneKey("k1", trusted)).await,
            None
        );
        let mut tampered = sign(&signing_key(1), &es256(), &claims());
        tampered.replace_range(tampered.len() - 2.., "AA");
        assert_eq!(
            verify(&tampered, "mailserver", NOW, &OneKey("k1", trusted)).await,
            None
        );
    }

    #[test]
    fn the_token_comes_from_bearer_else_the_access_cookie() {
        let mut h = HeaderMap::new();
        h.insert(
            COOKIE,
            HeaderValue::from_static("a=b; access_token=c.o.okie"),
        );
        assert_eq!(extract(&h).as_deref(), Some("c.o.okie"));
        h.insert(AUTHORIZATION, HeaderValue::from_static("Bearer b.e.arer"));
        assert_eq!(extract(&h).as_deref(), Some("b.e.arer"));
        // Basic is not the JWT method: Go's jwt_bearer then reads the cookie.
        h.insert(AUTHORIZATION, HeaderValue::from_static("Basic eDp5"));
        assert_eq!(extract(&h).as_deref(), Some("c.o.okie"));
        h.append(COOKIE, HeaderValue::from_static("access_token=second"));
        assert_eq!(extract(&h), None, "two access_token cookies are ambiguous");
        assert_eq!(extract(&HeaderMap::new()), None);
    }

    /// The P-256 group order n, big-endian (SEC 2, public constant).
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];

    /// `n - v` for a test scalar `0 < v < n` (public test data only).
    fn order_minus(v: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = i16::from(ORDER[i]) - i16::from(v[i]) - borrow;
            borrow = i16::from(d < 0);
            out[i] = d.rem_euclid(256) as u8;
        }
        out
    }

    fn with_signature(token: &str, signature: &[u8]) -> String {
        let cut = token.rfind('.').unwrap();
        format!("{}.{}", &token[..cut], URL_SAFE_NO_PAD.encode(signature))
    }

    fn signature_of(token: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(&token[token.rfind('.').unwrap() + 1..])
            .unwrap()
    }

    struct Counting(VerifyingKey, std::sync::atomic::AtomicUsize);
    impl KeySource for Counting {
        async fn key(&self, _kid: &str) -> Option<VerifyingKey> {
            self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(self.0)
        }
    }

    /// Go's `crypto/ecdsa` (and RFC 7518) accepts either `s` or `n - s`; so
    /// must Rust, or a Go-valid token would be forwarded instead of served.
    #[tokio::test]
    async fn a_high_s_signature_go_accepts_is_served() {
        let key = signing_key(1);
        let token = sign(&key, &es256(), &claims());
        let sig = signature_of(&token);
        let mut flipped = sig[..32].to_vec();
        flipped.extend(order_minus(&sig[32..]));
        let token2 = with_signature(&token, &flipped);
        let keys = OneKey("k1", public_key(&key));
        let a = verify(&token, "mailserver", NOW, &keys).await;
        assert!(a.is_some());
        assert_eq!(verify(&token2, "mailserver", NOW, &keys).await, a);
    }

    /// Signatures outside Go's `crypto/ecdsa` domain are never served:
    /// wrong length (rejected before any key lookup), and `r`/`s` of zero or
    /// at least the group order.
    #[tokio::test]
    async fn malformed_signatures_are_not_served() {
        let key = signing_key(1);
        let token = sign(&key, &es256(), &claims());
        let sig = signature_of(&token);
        let keys = Counting(public_key(&key), Default::default());
        for len in [0, 63, 65, 72] {
            let mut bad = sig.clone();
            bad.resize(len, 0);
            assert_eq!(
                signed_claims(&with_signature(&token, &bad), &keys).await,
                None
            );
        }
        assert_eq!(keys.1.load(std::sync::atomic::Ordering::SeqCst), 0);
        let zero = [0u8; 32];
        let mut big = ORDER.to_vec();
        let cases = [
            [&zero[..], &sig[32..]].concat(),
            [&sig[..32], &zero[..]].concat(),
            [&ORDER[..], &sig[32..]].concat(),
            [&sig[..32], &ORDER[..]].concat(),
            {
                big[31] += 1;
                [&big[..], &sig[32..]].concat()
            },
            [0xffu8; 64].to_vec(),
        ];
        for (i, bad) in cases.iter().enumerate() {
            assert_eq!(
                signed_claims(&with_signature(&token, bad), &keys).await,
                None,
                "case {i}"
            );
        }
        assert!(signed_claims(&token, &keys).await.is_some());
    }

    /// The frozen-Go `jwtutil` vectors (#262): the signature layer accepts
    /// exactly the ES256 tokens Go accepts, with Go's claims; every other
    /// token (Go-invalid, or HS256/SM2 that Rust holds no key for) is not served.
    #[tokio::test]
    async fn go_recorded_jwtutil_vectors_verify_only_their_es256_signatures() {
        use setjoin_conformance::shared_vectors::load_vectors;
        struct Keyed(String, VerifyingKey);
        impl KeySource for Keyed {
            async fn key(&self, kid: &str) -> Option<VerifyingKey> {
                (kid == self.0).then_some(self.1)
            }
        }
        let hex = |v: &Value| -> Vec<u8> {
            let s = v.as_str().unwrap();
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let raw = include_bytes!("../../../tests/conformance/shared-vectors/goldens/jwtutil.json");
        let (mut accepted, mut rejected) = (0, 0);
        for case in load_vectors(raw, "jwtutil").unwrap() {
            let input = &case.input;
            let jwk = json!({"keys": [{
                "kty": "EC", "crv": "P-256", "kid": "k",
                "x": URL_SAFE_NO_PAD.encode(hex(&input["es256_public_x"])),
                "y": URL_SAFE_NO_PAD.encode(hex(&input["es256_public_y"])),
            }]});
            let key = crate::jwks::parse(jwk.to_string().as_bytes()).unwrap()["k"];
            let keys = Keyed(input["es256_kid"].as_str().unwrap().into(), key);
            let token = input["token"].as_str().unwrap();
            let alg = token
                .split('.')
                .next()
                .and_then(|h| URL_SAFE_NO_PAD.decode(h).ok())
                .and_then(|h| serde_json::from_slice::<Value>(&h).ok())
                .and_then(|h| h["alg"].as_str().map(str::to_owned));
            let expected =
                (case.output["valid"] == true && alg.as_deref() == Some("ES256")).then(|| {
                    serde_json::from_str::<Value>(case.output["claims_json"].as_str().unwrap())
                        .unwrap()
                });
            if alg.as_deref() == Some("ES256") {
                if expected.is_some() {
                    accepted += 1;
                } else {
                    rejected += 1;
                }
            }
            let got = signed_claims(token, &keys).await.map(Value::Object);
            assert_eq!(got, expected, "{}", case.name);
        }
        assert!(
            accepted > 0 && rejected > 0,
            "{accepted} accepted, {rejected} rejected"
        );
    }
}

/// Authserver's first-party signature/registered-claim boundary. This does not
/// impose the gateway's mailbox, guest, scope or access-type admission rules.
/// Callers must still apply the exact endpoint's access/revocation/DPoP guard.
pub async fn validate_first_party(token:&str,issuer:&str,now:f64,keys:&impl KeySource)->Option<Map<String,Value>>{
    let claims=signed_claims(token,keys).await?;
    claims_shape_ok(&claims)?;
    crate::legacy_jwt::registered(&claims,issuer,AUDIENCE,now).then_some(claims)
}

/// Authserver PresentedAccessToken: first Bearer header, then first valid named
/// cookie. The gateway's conservative extractor deliberately declines these
/// ambiguous shapes; a native auth endpoint must make Go's final decision.
pub fn presented(headers: &hyper::HeaderMap) -> Option<String> {
    if let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .filter(|s| !s.is_empty())
    {
        return Some(token.to_owned());
    }
    for line in headers.get_all("cookie") {
        let Ok(line) = line.to_str() else { continue };
        for pair in line.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name.trim() != "access_token" {
                continue;
            }
            let value = value.trim();
            let value = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
                &value[1..value.len() - 1]
            } else {
                value
            };
            if !value
                .bytes()
                .all(|b| (0x20..0x7f).contains(&b) && !matches!(b, b'"' | b';' | b'\\'))
            {
                continue;
            }
            return (!value.is_empty()).then(|| value.to_owned());
        }
    }
    None
}
