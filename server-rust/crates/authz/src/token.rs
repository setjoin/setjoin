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

/// Go's `pathWithinScope` (chain.go:453-456) over the `r.URL.Path` the handler sees
/// (see [`crate::go_url::mailserver_handler_path`]): a token with a non-empty `scp`
/// is accepted only when that path is `/<scp>` or under `/<scp>/`. Bytes, as Go compares.
pub(crate) fn path_within_scope(path:&[u8],scope:&str)->bool{
    path.strip_prefix(b"/").and_then(|p|p.strip_prefix(scope.as_bytes())).is_some_and(|rest|rest.is_empty()||rest.starts_with(b"/"))
}
/// Scope containment (chain.go:434): empty scope, the Drive adapters' drive
/// surface, or a handler path the scope names. `None` path = no request path known
/// (or Go would not reach a handler), so a scoped token is not admitted.
fn scope_admits(scope:&str,drive:bool,path:Option<&[u8]>)->bool{
    scope.is_empty()||(drive&&scope=="drive")||path.is_some_and(|p|path_within_scope(p,scope))
}
/// Drive adapters only: the ordinary guard still refuses every scoped mirror.
pub async fn verify_drive(token:&str,issuer:&str,now_unix:f64,keys:&impl KeySource)->Option<Session>{verify_scope(token,issuer,now_unix,keys,true).await}

/// [`verify`]/[`verify_drive`] with the refusal class kept (#354); one signature
/// check. A token Go's registered-claim boundary rejects is `InvalidToken`; a
/// token Go accepts but Rust does not serve is named by the first rule it trips.
#[cfg(test)]
pub(crate) async fn verify_detailed(token:&str,issuer:&str,now_unix:f64,keys:&impl KeySource,drive:bool,path:Option<&[u8]>)
    ->Result<Session,crate::Refusal>{
    let claims=decoded_claims(token,keys).await.ok_or(crate::Refusal::InvalidToken)?;
    session_detailed(&claims,issuer,now_unix,drive,path)
}

/// Signature-checked claims with `exp`/`nbf`/`iat` decoded exactly as Go's
/// `jwt.NumericDate` decodes them ([`crate::numeric_date`]); `None` = Go rejects.
pub(crate) async fn decoded_claims(token:&str,keys:&impl KeySource)->Option<Map<String,Value>>{
    let mut claims=signed_claims(token,keys).await?;
    crate::numeric_date::normalize_token_claims(token,&mut claims)?;
    Some(claims)
}

/// Go's claim acceptance (chain.go jwt_bearer + pathWithinScope): shape, registered
/// claims, `typ` access and scope containment. Accepted tokens may still be unserved.
pub(crate) fn go_accepts(claims:&Map<String,Value>,issuer:&str,now_unix:f64,drive:bool,path:Option<&[u8]>)->bool{
    claims_shape_ok(claims).is_some() && crate::legacy_jwt::registered(claims,issuer,AUDIENCE,now_unix)
        && str_claim(claims,"typ")=="access" && scope_admits(str_claim(claims,"scp"),drive,path)
}

/// The refusal class `admit` reports for [`decoded_claims`] (Go rule order).
pub(crate) fn session_detailed(claims:&Map<String,Value>,issuer:&str,now_unix:f64,drive:bool,path:Option<&[u8]>)
    ->Result<Session,crate::Refusal>{
    use crate::Refusal;
    if let Some(session)=session_from(claims,issuer,now_unix,drive,path){return Ok(session);}
    if !go_accepts(claims,issuer,now_unix,drive,path) {
        return Err(Refusal::InvalidToken);
    }
    if claims.get("act").is_some_and(|v|!v.is_null()) {return Err(Refusal::Impersonation);}
    if claims.get("iat").is_none_or(Value::is_null) {return Err(Refusal::MissingIssuedAt);}
    if claims.get("uid").and_then(Value::as_i64).is_none_or(|u|u<=0) {return Err(Refusal::UnservedSubject);}
    if str_claim(claims,"acct")=="guest" {return Err(Refusal::Guest);}
    Err(Refusal::InvalidToken)
}
async fn verify_scope(token:&str,issuer:&str,now_unix:f64,keys:&impl KeySource,drive:bool)->Option<Session>{
    let claims = decoded_claims(token, keys).await?;
    session_from(&claims, issuer, now_unix, drive, None)
}

/// The claim rules of [`verify`] over already signature-checked claims.
fn session_from(claims: &Map<String, Value>, issuer: &str, now_unix: f64, drive: bool, path: Option<&[u8]>) -> Option<Session> {
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
    if crate::numeric_date::expired(now_unix, claims.get("exp")?.as_i64()?) {
        return None;
    }
    if let Some(nbf) = claims.get("nbf").filter(|v| !v.is_null()) {
        if crate::numeric_date::not_yet_valid(now_unix, nbf.as_i64()?) {
            return None;
        }
    }
    if claims.get("typ")?.as_str()? != "access" {
        return None;
    }
    let scope=str_claim(claims,"scp");
    if !scope_admits(scope, drive, path) || str_claim(claims,"acct")=="guest" {
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
    let claims=decoded_claims(token,keys).await?;
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
    presented_cookie(headers)
}

/// The cookie Go's `r.Cookie("access_token")` returns (net/http `readCookies`, Go 1.26):
/// lines of all `Cookie` headers in order, pairs split on `;`, pair and name trimmed of
/// space/tab/CR/LF (`textproto.TrimString`), a pair with no `=` is a cookie with an empty
/// value, one pair of surrounding double quotes is stripped, a value with a byte outside
/// 0x20..0x7e or one of `"` `;` `\` is skipped, the value is otherwise kept verbatim
/// (leading space included). The FIRST matching cookie wins even when its value is empty
/// (Go then has no token; chain.go:525). More than 3000 cookie slots yield none.
pub(crate) fn presented_cookie(headers: &hyper::HeaderMap) -> Option<String> {
    fn trim(mut b: &[u8]) -> &[u8] {
        let space = |c: &u8| matches!(c, b' ' | b'\t' | b'\r' | b'\n');
        while b.first().is_some_and(space) { b = &b[1..]; }
        while b.last().is_some_and(space) { b = &b[..b.len() - 1]; }
        b
    }
    let lines: Vec<&[u8]> = headers.get_all("cookie").iter().map(|v| v.as_bytes()).collect();
    let slots: usize = lines.iter().map(|l| l.iter().filter(|b| **b == b';').count() + 1).sum();
    if slots > 3000 {
        return None;
    }
    for line in lines {
        for part in trim(line).split(|b| *b == b';') {
            let part = trim(part);
            if part.is_empty() {
                continue;
            }
            let (name, value) = match part.iter().position(|b| *b == b'=') {
                Some(i) => (&part[..i], &part[i + 1..]),
                None => (part, &part[part.len()..]),
            };
            if trim(name) != b"access_token" {
                continue;
            }
            let value = if value.len() > 1 && value[0] == b'"' && value[value.len() - 1] == b'"' {
                &value[1..value.len() - 1]
            } else {
                value
            };
            if !value
                .iter()
                .all(|b| (0x20..0x7f).contains(b) && !matches!(b, b'"' | b';' | b'\\'))
            {
                continue;
            }
            return (!value.is_empty()).then(|| String::from_utf8_lossy(value).into_owned());
        }
    }
    None
}

#[cfg(test)]
mod verify_detailed_tests {
    use super::tests::{public_key, sign, signing_key, OneKey};
    use super::*;
    use crate::Refusal;
    use serde_json::json;

    const NOW: f64 = 1_800_000_000.0;

    fn claims() -> Value {
        json!({"uid": 7, "email": "a@x.test", "typ": "access", "jti": "j1", "fam": "f1",
               "iss": "mailserver", "aud": ["mailserver-gateway"],
               "iat": 1_799_999_000, "exp": 1_800_000_900})
    }

    fn es256() -> Value {
        json!({"alg": "ES256", "kid": "k1", "typ": "JWT"})
    }

    fn with(k: &str, v: Value) -> Value {
        let mut c = claims();
        c[k] = v;
        c
    }

    fn without(k: &str) -> Value {
        let mut c = claims();
        c.as_object_mut().unwrap().remove(k);
        c
    }

    async fn detailed(claims: Value, header: Value, drive: bool) -> Result<(), Refusal> {
        detailed_at(claims, header, drive, "/x").await
    }

    /// `path` is the raw request path; Go's handler path is derived from it as `admit` does.
    async fn detailed_at(claims: Value, header: Value, drive: bool, path: &str) -> Result<(), Refusal> {
        let path = crate::go_url::mailserver_handler_path("GET", path);
        let key = signing_key(1);
        let token = sign(&key, &header, &claims);
        verify_detailed(&token, "mailserver", NOW, &OneKey("k1", public_key(&key)), drive, path.as_deref())
            .await
            .map(|_| ())
    }

    #[tokio::test]
    async fn verify_detailed_names_the_refusal_class_in_go_rule_order() {
        let act_without_iat = {
            let mut c = without("iat");
            c["act"] = json!(3);
            c
        };
        let guest_without_iat = {
            let mut c = without("iat");
            c["acct"] = json!("guest");
            c
        };
        let guest_uid_zero = {
            let mut c = with("uid", json!(0));
            c["acct"] = json!("guest");
            c
        };
        let cases: Vec<(&str, Value, Value, bool, Result<(), Refusal>)> = vec![
            ("valid", claims(), es256(), false, Ok(())),
            ("act", with("act", json!(3)), es256(), false, Err(Refusal::Impersonation)),
            ("act without iat", act_without_iat, es256(), false, Err(Refusal::Impersonation)),
            ("no iat", without("iat"), es256(), false, Err(Refusal::MissingIssuedAt)),
            ("acct guest", with("acct", json!("guest")), es256(), false, Err(Refusal::Guest)),
            ("acct guest without iat", guest_without_iat, es256(), false, Err(Refusal::MissingIssuedAt)),
            ("acct guest with uid 0", guest_uid_zero, es256(), false, Err(Refusal::UnservedSubject)),
            ("uid 0", with("uid", json!(0)), es256(), false, Err(Refusal::UnservedSubject)),
            ("uid absent", without("uid"), es256(), false, Err(Refusal::UnservedSubject)),
            ("refresh typ", with("typ", json!("refresh")), es256(), false, Err(Refusal::InvalidToken)),
            ("mfa_pending typ", with("typ", json!("mfa_pending")), es256(), false, Err(Refusal::InvalidToken)),
            ("drive scope off a drive path", with("scp", json!("drive")), es256(), false, Err(Refusal::InvalidToken)),
            ("drive scope on a drive path", with("scp", json!("drive")), es256(), true, Ok(())),
            ("expired", with("exp", json!(1_800_000_000)), es256(), false, Err(Refusal::InvalidToken)),
            ("wrong audience", with("aud", json!("other")), es256(), false, Err(Refusal::InvalidToken)),
            ("unknown kid", claims(), json!({"alg": "ES256", "kid": "k2"}), false, Err(Refusal::InvalidToken)),
        ];
        for (name, claims, header, drive, expected) in cases {
            assert_eq!(detailed(claims, header, drive).await, expected, "{name}");
        }
    }

    #[tokio::test]
    async fn scoped_token_is_admitted_only_on_its_own_path_like_go() {
        let scoped = |scp: &str| with("scp", json!(scp));
        // Raw request paths; Go strips `/api` (main.go:5069-5093) and decodes like
        // url.URL.Path before chain.go:434 compares.
        // Bare paths reach a handler only under apiPinnedPrefixes; unclean paths redirect.
        let cases: &[(&str, &str, bool)] = &[
            ("admin", "/admin", false),
            ("admin", "/admin/users", false),
            ("jmap", "/jmap", true),
            ("jmap", "/jmap/x", true),
            ("admin", "/admin/migration/m365", true),
            ("admin", "/api/x/../admin/users", false),
            ("admin", "/api//admin/users", false),
            ("admin", "/api%2Fadmin/users", false),
            ("docs", "/api/docs", false),
            ("admin", "/api/admin/users", true),
            ("api/admin", "/api/admin/users", false),
            ("admin", "/api/admin", true),
            ("admin", "/api/admin/users/", true),
            ("admin", "/admin/", false),
            ("admin", "/administrator", false),
            ("admin", "/api/administrator", false),
            ("admin", "/api/adm%69n/users", true),
            ("admin", "/api/admin%2Fusers", true),
            ("admin%2F", "/api/admin%2F", false),
            ("admin", "/%61pi/admin/users", false),
            ("admin", "/api/adm%zzin", false),
            ("admin", "/", false),
            ("admin", "/x/admin", false),
            ("api/admin", "/api/admin2", false),
            ("api/openapi.full.yaml", "/api/openapi.full.yaml", true),
            ("openapi.full.yaml", "/api/openapi.full.yaml", false),
        ];
        for &(scp, path, ok) in cases {
            let want = if ok { Ok(()) } else { Err(Refusal::InvalidToken) };
            assert_eq!(detailed_at(scoped(scp), es256(), false, path).await, want, "{scp} {path}");
        }
        // The unscoped token never depends on the path.
        assert_eq!(detailed_at(claims(), es256(), false, "/anything").await, Ok(()));
    }

    #[test]
    fn cookie_name_is_trimmed_like_go() {
        // Go 1.26 readCookies: `name = textproto.TrimString(name)` (net/http/cookie.go:400).
        let get = |c: &str| {
            let mut h = hyper::HeaderMap::new();
            h.insert("cookie", c.parse().unwrap());
            presented_cookie(&h)
        };
        assert_eq!(get("access_token=abc"), Some("abc".to_owned()));
        assert_eq!(get("a=1; access_token=abc"), Some("abc".to_owned()));
        assert_eq!(get("access_token =abc"), Some("abc".to_owned()));
        assert_eq!(get("access_token2=x; access_token=abc"), Some("abc".to_owned()));
        // The value is not trimmed after `=` (only the whole pair is).
        assert_eq!(get("access_token= abc"), Some(" abc".to_owned()));
        assert_eq!(get("access_token=abc  "), Some("abc".to_owned()));
        // A bare name is a cookie with an empty value and wins over a later one.
        assert_eq!(get("access_token; access_token=abc"), None);
        assert_eq!(get("access_token=; access_token=abc"), None);
        // Invalid pairs are skipped; quotes are stripped once.
        assert_eq!(get("access_token=a\\b; access_token=abc"), Some("abc".to_owned()));
        assert_eq!(get("access_token=\"abc\""), Some("abc".to_owned()));
        assert_eq!(get("access_token=\"a\"b\"; access_token=abc"), Some("abc".to_owned()));
        // A non-ASCII byte in another cookie does not hide this one.
        let mut h = hyper::HeaderMap::new();
        h.insert("cookie", hyper::header::HeaderValue::from_bytes(b"x=\xff; access_token=abc").unwrap());
        assert_eq!(presented_cookie(&h), Some("abc".to_owned()));
        // Over 3000 slots, Go returns no cookies.
        let many = format!("{}access_token=abc", "a=1; ".repeat(3000));
        assert_eq!(get(&many), None);
    }

    #[tokio::test]
    async fn fractional_numeric_dates_are_floored_like_go() {
        // verify_detailed `NOW` is 1_800_000_000.0; claims() exp is 1_800_000_900.
        let ok = |c: Value| async move { detailed(c, es256(), false).await };
        assert_eq!(ok(with("exp", json!(1_800_000_900.9))).await, Ok(()));
        assert_eq!(ok(with("iat", json!(1_799_999_000.5))).await, Ok(()));
        assert_eq!(ok(with("nbf", json!(1_799_999_999.9))).await, Ok(()));
        // 1_800_000_000.9 floors to 1_800_000_000 == now: expired (no leeway).
        assert_eq!(ok(with("exp", json!(1_800_000_000.9))).await, Err(Refusal::InvalidToken));
        // A future nbf is refused, fractional or not.
        assert_eq!(ok(with("nbf", json!(1_800_000_001.5))).await, Err(Refusal::InvalidToken));
        assert_eq!(ok(with("nbf", json!(1_800_000_001))).await, Err(Refusal::InvalidToken));
        // jwt/v5 decodes a NumericDate through json.Number: a JSON string holding a
        // valid JSON number is accepted (decode.go:957-961); any other string is not.
        assert_eq!(ok(with("exp", json!("1800000900"))).await, Ok(()));
        assert_eq!(ok(with("exp", json!("1800000900.5"))).await, Ok(()));
        assert_eq!(ok(with("iat", json!("1799999000"))).await, Ok(()));
        assert_eq!(ok(with("nbf", json!("1.7e9"))).await, Ok(()));
        for bad in [json!("abc"), json!(""), json!(" 1800000900"), json!("+1800000900"), json!("01800000900"), json!(true)] {
            assert_eq!(ok(with("exp", bad.clone())).await, Err(Refusal::InvalidToken), "exp {bad}");
        }
        // Go on amd64: exp 9.2233720368547e18 wraps the internal seconds and is expired;
        // nbf 1e19 converts to i64::MIN and is in the past (crate::numeric_date).
        assert_eq!(ok(with("exp", json!(9.2233720368547e18))).await, Err(Refusal::InvalidToken));
        assert_eq!(ok(with("exp", json!(9.21e18))).await, Ok(()));
        assert_eq!(ok(with("nbf", json!(1e19))).await, Ok(()));
    }

    struct Counted(VerifyingKey, std::sync::atomic::AtomicUsize);
    impl KeySource for Counted {
        async fn key(&self, _kid: &str) -> Option<VerifyingKey> {
            self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(self.0)
        }
    }

    #[tokio::test]
    async fn a_failed_token_costs_exactly_one_key_lookup() {
        let key = signing_key(1);
        let token = sign(&key, &es256(), &with("exp", json!(1_800_000_000)));
        let keys = Counted(public_key(&key), Default::default());
        let got = verify_detailed(&token, "mailserver", NOW, &keys, false, Some(&b"/x"[..])).await;
        assert_eq!(got.map(|_| ()), Err(Refusal::InvalidToken));
        assert_eq!(keys.1.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
