//! Five-minute, one-blob credentials. ring owns HKDF and HMAC; the verified
//! parent supplies identity/origin. No refresh, authority or signing-key API.
use super::{
    JmapCommands, reply,
    token::{self, KeySource},
};
use crate::{Body, RequestContext};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, Visitor},
};
use serde_json::{Value, json};
use setjoin_pg::MailboxAuthContext;
use sha2::{Digest, Sha256};

pub struct Signer {
    key: ring::hmac::Key,
}
impl Signer {
    pub fn from_master(master: &[u8]) -> Result<Self, &'static str> {
        let salt = ring::hkdf::Salt::new(
            ring::hkdf::HKDF_SHA256,
            b"mailserver-mail-attachment-token-v1",
        );
        let prk = salt.extract(master);
        let info: [&[u8]; 0] = [];
        let expanded = prk
            .expand(&info, ring::hkdf::HKDF_SHA256)
            .map_err(|_| "attachment key expansion")?;
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        expanded
            .fill(&mut *key)
            .map_err(|_| "attachment key size")?;
        Ok(Self {
            key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &*key),
        })
    }
    pub(super) fn from_env() -> Option<Self> {
        let master = zeroize::Zeroizing::new(
            std::env::var("MAIL_ATTACHMENT_TOKEN_SECRET")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| std::env::var("JWT_SECRET").ok())
                .filter(|s| !s.is_empty())?,
        );
        Self::from_master(master.as_bytes()).ok()
    }
    fn sign(&self, claims: &Claims<'_>) -> Option<String> {
        let header = URL_SAFE_NO_PAD
            .encode(br#"{"alg":"HS256","kid":"mailserver-mail-attachment-1","typ":"JWT"}"#);
        let raw = reply::go_compact(&serde_json::to_string(claims).ok()?)?;
        let data = format!("{header}.{}", URL_SAFE_NO_PAD.encode(raw));
        let sig = ring::hmac::sign(&self.key, data.as_bytes());
        Some(format!("{data}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref())))
    }
}
#[derive(Default, Deserialize, Serialize)]
struct Device {
    #[serde(default)]
    id: String,
    #[serde(default)]
    platform: String,
    #[serde(default)]
    trust_tier: String,
    #[serde(default)]
    compliance_status: String,
    #[serde(default)]
    wipe_requested: bool,
}
#[derive(Default, Deserialize)]
struct Parent {
    #[serde(default)]
    acct: String,
    #[serde(default)]
    device: Option<Device>,
    #[serde(default)]
    scp: String,
    #[serde(default)]
    attachment: Option<Value>,
    #[serde(default)]
    iat: Option<Value>,
}
#[derive(Serialize)]
struct Binding<'a> {
    sha256: &'a str,
    account_id: i64,
    mailbox_id: i64,
    device_id: i64,
    device_fingerprint: &'a str,
    policy_generation: &'a str,
    origin_jti: &'a str,
    origin_iat: i64,
}
#[derive(Serialize)]
struct Claims<'a> {
    uid: i64,
    email: &'a str,
    typ: &'a str,
    jti: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    fam: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    acct: &'a str,
    device: &'a Device,
    scp: &'a str,
    attachment: Binding<'a>,
    iss: &'a str,
    aud: [&'a str; 1],
    exp: i64,
    iat: i64,
}
#[derive(Serialize)]
struct Reply {
    token: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
    path: String,
    sha256: String,
    size: String,
    etag: String,
}
#[derive(Default)]
struct Args {
    account: String,
    hash: String,
}
impl<'de> Deserialize<'de> for Args {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Args;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("attachment transfer request")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Args, M::Error> {
                let mut args = Args::default();
                while let Some(key) = map.next_key::<String>()? {
                    // Go's EqualFold has two non-ASCII folds into ASCII.
                    let folded = key.replace('ſ', "s").replace('K', "k");
                    let field = if folded.eq_ignore_ascii_case("accountId") {
                        &mut args.account
                    } else if folded.eq_ignore_ascii_case("sha256") {
                        &mut args.hash
                    } else {
                        return Err(de::Error::unknown_field(&key, &["accountId", "sha256"]));
                    };
                    // JSON null leaves a Go scalar field unchanged; later duplicates win.
                    if let Some(value) = map.next_value::<Option<String>>()? {
                        *field = value;
                    }
                }
                Ok(args)
            }
        }
        d.deserialize_map(Fields)
    }
}
impl<K: KeySource> JmapCommands<K> {
    pub(super) async fn mint_transfer(
        &self,
        req: &mut Request<Body>,
        ctx: &RequestContext,
        auth: &MailboxAuthContext,
        authorized: &setjoin_authz::Authorized,
        id: &str,
    ) -> Response<Body> {
        let services = self.services.as_ref().unwrap();
        let fail = |s, d| problem(s, d, ctx, id);
        if req.uri().path() != "/api/mail/attachment-transfer-token" {
            return plain404(ctx, id);
        }
        if super::gates::toggle_state(&self.exec, "feature.offline_mail").await != Some(true)
            || super::gates::toggle_state(&self.exec, "feature.connectivity_aware_sync").await
                != Some(true)
        {
            return plain404(ctx, id);
        }
        // These bytes came through authorize_request with these same immutable headers.
        let parent = token::extract(req.headers())
            .and_then(|t| {
                t.split('.')
                    .nth(1)
                    .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
            })
            .and_then(|p| serde_json::from_slice::<Parent>(&p).ok());
        let Some(parent) = parent else {
            return fail(403, "normal native access session required");
        };
        let Some(device) = parent
            .device
            .as_ref()
            .filter(|_| parent.scp.is_empty() && parent.attachment.is_none())
        else {
            return fail(403, "normal native access session required");
        };
        let Some(signer) = &services.attachment_signer else {
            return fail(503, "attachment transfer unavailable");
        };
        let mut bytes = Vec::new();
        while let Some(frame) = req.body_mut().frame().await {
            let Ok(frame) = frame else {
                return fail(400, "invalid attachment transfer request");
            };
            if let Ok(data) = frame.into_data() {
                if bytes.len().saturating_add(data.len()) > 4096 {
                    return fail(400, "invalid attachment transfer request");
                }
                bytes.extend_from_slice(&data);
            }
        }
        let Some(args) = serde_json::from_slice::<Option<Args>>(&bytes)
            .ok()
            .flatten()
        else {
            return fail(400, "invalid attachment transfer request");
        };
        let account = args
            .account
            .parse::<i64>()
            .ok()
            .filter(|n| *n > 0 && n.to_string() == args.account);
        if account.is_none()
            || args.hash.len() != 64
            || !args
                .hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return fail(400, "invalid attachment transfer request");
        }
        let Some(device_id) = setjoin_jmap::http_blob::transfer_device(
            &services.worker,
            auth,
            &device.id,
            &device.platform,
        )
        .await
        .ok()
        .flatten() else {
            return fail(403, "approved native device required");
        };
        let raw = setjoin_jmap::http_blob::transfer_policy(&services.worker, auth, device_id)
            .await
            .unwrap_or_default();
        let policy = serde_json::from_str::<Value>(&raw).unwrap_or(json!({}));
        if policy["syncQoS"]["mode"] == "off" {
            return plain404(ctx, id);
        }
        if policy["allowed"] != true
            || policy["syncQoS"]["mode"] != "execute"
            || policy["syncQoS"]["effective"]["automaticNetwork"] == "never"
        {
            return fail(403, "attachment transfer is not allowed by current policy");
        }
        let generation = format!("{:x}", Sha256::digest(raw.as_bytes()));
        if !setjoin_jmap::http_blob::download_allowed(
            &services.worker,
            auth,
            &args.account,
            &args.hash,
        )
        .await
        .unwrap_or(false)
        {
            return plain404(ctx, id);
        }
        let Some((size, _)) = setjoin_jmap::http_blob::metadata(&services.worker, &args.hash)
            .await
            .ok()
            .flatten()
            .filter(|(n, _)| (0..=8i64 << 30).contains(n))
        else {
            return plain404(ctx, id);
        };
        if authorized.token_id().is_empty() || parent.iat.is_none() {
            return fail(401, "session cannot mint attachment transfer");
        }
        let iat = chrono::Utc::now().timestamp();
        let exp = iat + 300;
        let Some(jti) = super::http::uuid() else {
            return fail(500, "attachment transfer unavailable");
        };
        let claims = Claims {
            uid: auth.actor().get(),
            email: authorized.context().email(),
            typ: "access",
            jti,
            fam: authorized.token_family(),
            acct: &parent.acct,
            device,
            scp: "mail-attachment",
            attachment: Binding {
                sha256: &args.hash,
                account_id: account.unwrap(),
                mailbox_id: auth.mailbox().get(),
                device_id,
                device_fingerprint: &device.id,
                policy_generation: &generation,
                origin_jti: authorized.token_id(),
                origin_iat: authorized.issued_at(),
            },
            iss: &self.issuer,
            aud: ["mailserver-gateway"],
            exp,
            iat,
        };
        let Some(token) = signer.sign(&claims) else {
            return fail(500, "attachment transfer unavailable");
        };
        let result = Reply {
            token,
            expires_at: chrono::DateTime::from_timestamp(exp, 0)
                .unwrap()
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string(),
            path: format!("/mail-attachment/{}", args.hash),
            etag: format!("\"{}\"", args.hash),
            sha256: args.hash,
            size: size.to_string(),
        };
        let mut r = reply::response(
            reply::go_compact(&serde_json::to_string(&result).unwrap()).unwrap() + "\n",
            ctx.identity.proto,
            id.into(),
        );
        r.headers_mut()
            .insert("pragma", "no-cache".parse().unwrap());
        r
    }
}
fn problem(status: u16, detail: &str, ctx: &RequestContext, id: &str) -> Response<Body> {
    let mut r = reply::response(
        crate::problem::Problem::new(status, detail).body(),
        ctx.identity.proto,
        id.into(),
    );
    *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
    r.headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    r
}
fn plain404(ctx: &RequestContext, id: &str) -> Response<Body> {
    let mut r = reply::response("404 page not found\n".into(), ctx.identity.proto, id.into());
    *r.status_mut() = hyper::StatusCode::NOT_FOUND;
    r.headers_mut()
        .insert("content-type", "text/plain; charset=utf-8".parse().unwrap());
    r
}
