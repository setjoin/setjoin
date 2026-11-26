//! Co-located or remote authentication authority seam (#543).
//!
//! Zero domain-crate dependencies live here. Callers depend only on
//! [`AuthAuthority`] and [`AuthKeySource`] so HTTP routes, protocol listeners,
//! and workers can run identically whether `auth` is co-located in-process
//! (`setjoind`) or split across a remote HTTP/HTTPS boundary
//! ([`RemoteAuthAuthority`]).

use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode, Uri};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::es256::VerifyingKey;
use crate::jwks::{is_loopback_uri, Jwks};
use crate::legacy_jwt::LegacyKeys;
use crate::token::KeySource;

/// Boxed error matching the front-door HTTP body error type.
pub type AuthBoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Streaming HTTP body across the [`AuthAuthority`] boundary.
pub type AuthBody = BoxBody<Bytes, AuthBoxError>;

/// Object-safe boxed future returned by [`AuthAuthority`] methods.
pub type AuthFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

const REMOTE_CALL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REMOTE_BODY: usize = 1 << 20;

/// Transport metadata supplied by the front-door listener when dispatching an
/// HTTP request to an [`AuthAuthority`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRequestMeta {
    /// Resolved client IP after trusted-proxy evaluation.
    pub client_ip: IpAddr,
    /// Effective scheme (`"http"` or `"https"`).
    pub proto: &'static str,
    /// Direct TCP peer address of the incoming connection.
    pub peer: SocketAddr,
    /// True when the incoming connection terminated TLS directly on this node.
    pub tls: bool,
    /// True when the front-door router already verified method-aware CSRF.
    pub csrf_verified: bool,
}

/// Target user for SCIM / administrative session revocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisableTarget {
    UserId(i64),
    ExternalId(String),
}

/// Outcome of [`AuthAuthority::disable_user_sessions`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisableOutcome {
    /// Matching user found and active sessions revoked.
    Disabled,
    /// No matching user found (idempotent SCIM no-op).
    NotFound,
}

/// Verified caller inputs for minting a scoped Drive native token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriveTokenRequest {
    pub user_id: i64,
    pub email: String,
    pub jti: String,
    pub family: String,
    pub account_type: String,
    pub actor_id: Option<i64>,
    pub expires_at: Option<i64>,
    pub device_bound: bool,
}

/// Minted Drive native token response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriveTokenResponse {
    pub token: String,
    pub expires_at: String,
    pub raw_json: String,
}

/// Errors returned by [`AuthAuthority`] control-plane operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthAuthorityError {
    /// Caller or session was rejected (401/403-class refusal).
    Unauthorized(String),
    /// Session is device-bound and cannot mint a native Drive token (403).
    DeviceBound,
    /// Parent session already expired (401).
    Expired,
    /// Incoming request body exceeded the authority transport limit (413).
    PayloadTooLarge,
    /// Auth authority endpoint or backend is temporarily unreachable (503).
    Unavailable(String),
    /// Operation is not configured or unsupported on this authority.
    Unconfigured(String),
    /// Internal or unexpected failure (500).
    Internal(String),
}

impl fmt::Display for AuthAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized(msg) => write!(f, "unauthorized: {msg}"),
            Self::DeviceBound => {
                f.write_str("native tokens are unavailable to device-bound sessions")
            }
            Self::Expired => f.write_str("session expired"),
            Self::PayloadTooLarge => f.write_str("auth authority request body too large"),
            Self::Unavailable(msg) => write!(f, "auth authority unavailable: {msg}"),
            Self::Unconfigured(msg) => write!(f, "auth authority unconfigured: {msg}"),
            Self::Internal(msg) => write!(f, "auth authority internal error: {msg}"),
        }
    }
}

impl std::error::Error for AuthAuthorityError {}

/// Single abstraction separating identity authority (signing keys, auth HTTP
/// routes, token introspection/revocation, SCIM session disable) from callers.
pub trait AuthAuthority: Send + Sync {
    /// Handle an HTTP request targeting the auth surface.
    fn handle_http<'a>(
        &'a self,
        req: Request<AuthBody>,
        meta: AuthRequestMeta,
    ) -> AuthFuture<'a, Result<Response<AuthBody>, AuthAuthorityError>>;

    /// Resolve a first-party ES256 verifying key by `kid`.
    fn verifying_key<'a>(&'a self, kid: &'a str) -> AuthFuture<'a, Option<VerifyingKey>>;

    /// Optional deployment-owned legacy verifier (HS256 and/or public-only SM2).
    fn legacy_verifier(&self) -> Option<&LegacyKeys> {
        None
    }

    /// Return the serialized public JWKS JSON document.
    fn jwks_json<'a>(&'a self) -> AuthFuture<'a, Result<String, AuthAuthorityError>>;

    /// Revoke all sessions for the targeted user (SCIM deprovisioning / admin).
    fn disable_user_sessions<'a>(
        &'a self,
        target: DisableTarget,
    ) -> AuthFuture<'a, Result<DisableOutcome, AuthAuthorityError>>;

    /// Introspect an opaque OAuth token (RFC 7662).
    fn introspect_token<'a>(
        &'a self,
        token: &'a str,
    ) -> AuthFuture<'a, Result<Value, AuthAuthorityError>>;

    /// Revoke an opaque OAuth token (RFC 7009).
    fn revoke_token<'a>(&'a self, token: &'a str)
        -> AuthFuture<'a, Result<(), AuthAuthorityError>>;

    /// Mint a scoped Drive native token for an already-verified non-guest caller.
    fn mint_drive_token<'a>(
        &'a self,
        req: DriveTokenRequest,
    ) -> AuthFuture<'a, Result<DriveTokenResponse, AuthAuthorityError>>;

    /// Trigger a live configuration/key reload of the auth authority.
    fn reload<'a>(&'a self) -> AuthFuture<'a, Result<(), AuthAuthorityError>>;

    /// True when the authority runs in-process without a network hop.
    fn is_in_process(&self) -> bool;
}

/// Blanket [`KeySource`] adapter backed by any `Arc<dyn AuthAuthority>`.
#[derive(Clone)]
pub struct AuthKeySource(pub Arc<dyn AuthAuthority>);

impl AuthKeySource {
    pub fn new(authority: Arc<dyn AuthAuthority>) -> Self {
        Self(authority)
    }

    pub fn authority(&self) -> &Arc<dyn AuthAuthority> {
        &self.0
    }
}

impl KeySource for AuthKeySource {
    fn legacy_keys(&self) -> Option<&LegacyKeys> {
        self.0.legacy_verifier()
    }

    async fn key(&self, kid: &str) -> Option<VerifyingKey> {
        self.0.verifying_key(kid).await
    }
}

/// Remote HTTP/HTTPS [`AuthAuthority`] client for split-subsystem deployments
/// (`--subsystems=http` talking to a separate `--subsystems=auth` node).
pub struct RemoteAuthAuthority {
    base_url: String,
    jwks_url: String,
    jwks: Jwks,
    legacy: Option<LegacyKeys>,
    internal_api_key: Zeroizing<String>,
    client: reqwest::Client,
}

impl RemoteAuthAuthority {
    /// Build a remote authority targeting `base_url` (`https://`, or loopback
    /// `http://` only). When `jwks_url` is `None`, defaults to
    /// `{base_url}/.well-known/jwks.json`.
    pub fn new(
        base_url: &str,
        jwks_url: Option<&str>,
        internal_api_key: impl Into<String>,
        legacy: Option<LegacyKeys>,
    ) -> Result<Self, String> {
        let base_trimmed = base_url.trim_end_matches('/');
        let parsed_base: Uri = base_trimmed
            .parse()
            .map_err(|e| format!("invalid auth base URL {base_url:?}: {e}"))?;
        let base_scheme = parsed_base.scheme_str();
        if !matches!(base_scheme, Some("http" | "https")) || parsed_base.authority().is_none() {
            return Err(format!(
                "auth base URL must be https:// or loopback http://host[:port], got {base_url}"
            ));
        }
        if base_scheme == Some("http") && !is_loopback_uri(&parsed_base) {
            return Err(format!(
                "auth base URL refuses plaintext http:// for non-loopback host: {base_url}"
            ));
        }
        let jwks_str = jwks_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{base_trimmed}/.well-known/jwks.json"));
        let jwks_uri: Uri = jwks_str
            .parse()
            .map_err(|e| format!("invalid JWKS URL {jwks_str:?}: {e}"))?;
        let jwks = Jwks::new(jwks_uri)?;
        let client = reqwest::Client::builder()
            .timeout(REMOTE_CALL_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("remote auth client init failed: {e}"))?;
        Ok(Self {
            base_url: base_trimmed.to_owned(),
            jwks_url: jwks_str,
            jwks,
            legacy,
            internal_api_key: Zeroizing::new(internal_api_key.into()),
            client,
        })
    }

    fn require_internal_key(&self) -> Result<&str, AuthAuthorityError> {
        if self.internal_api_key.is_empty() {
            return Err(AuthAuthorityError::Unconfigured(
                "INTERNAL_API_KEY is not configured".into(),
            ));
        }
        Ok(self.internal_api_key.as_str())
    }
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn is_untrusted_forwarding_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host" | "x-real-ip"
    )
}

fn connection_nominated_headers(headers: &HeaderMap) -> HashSet<String> {
    let mut nominated = HashSet::new();
    for value in headers.get_all(hyper::header::CONNECTION) {
        if let Ok(text) = value.to_str() {
            for token in text.split(',') {
                let name = token.trim().to_ascii_lowercase();
                if !name.is_empty() {
                    nominated.insert(name);
                }
            }
        }
    }
    nominated
}

fn reqwest_connection_nominated(headers: &reqwest::header::HeaderMap) -> HashSet<String> {
    let mut nominated = HashSet::new();
    for value in headers.get_all(reqwest::header::CONNECTION) {
        if let Ok(text) = value.to_str() {
            for token in text.split(',') {
                let name = token.trim().to_ascii_lowercase();
                if !name.is_empty() {
                    nominated.insert(name);
                }
            }
        }
    }
    nominated
}

async fn collect_bounded_body(mut body: AuthBody) -> Result<Bytes, AuthAuthorityError> {
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| AuthAuthorityError::Internal(e.to_string()))?;
        if let Some(data) = frame.data_ref() {
            if out.len().saturating_add(data.len()) > MAX_REMOTE_BODY {
                return Err(AuthAuthorityError::PayloadTooLarge);
            }
            out.extend_from_slice(data);
        }
    }
    Ok(Bytes::from(out))
}

async fn read_bounded(mut resp: reqwest::Response) -> Result<Vec<u8>, AuthAuthorityError> {
    let mut out = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| AuthAuthorityError::Unavailable(e.to_string()))?
    {
        if out.len().saturating_add(chunk.len()) > MAX_REMOTE_BODY {
            return Err(AuthAuthorityError::Internal(
                "auth authority response exceeds size limit".into(),
            ));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

impl AuthAuthority for RemoteAuthAuthority {
    fn handle_http<'a>(
        &'a self,
        req: Request<AuthBody>,
        meta: AuthRequestMeta,
    ) -> AuthFuture<'a, Result<Response<AuthBody>, AuthAuthorityError>> {
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let path_and_query = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
            let target = format!("{}{}", self.base_url, path_and_query);
            let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
                .map_err(|e| AuthAuthorityError::Internal(e.to_string()))?;
            let collected = collect_bounded_body(body).await?;

            let nominated = connection_nominated_headers(&parts.headers);
            let forwarded_host = parts
                .headers
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok())
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .or_else(|| parts.uri.authority().map(|a| a.as_str().to_owned()));

            let mut builder = self.client.request(method, &target).body(collected);
            for (name, value) in &parts.headers {
                if name == hyper::header::HOST
                    || is_hop_by_hop(name)
                    || is_untrusted_forwarding_header(name)
                    || nominated.contains(name.as_str())
                {
                    continue;
                }
                builder = builder.header(name.as_str(), value.as_bytes());
            }
            builder = builder
                .header("x-forwarded-for", meta.client_ip.to_string())
                .header("x-forwarded-proto", meta.proto);
            if let Some(host) = forwarded_host {
                builder = builder.header("x-forwarded-host", host);
            }
            let upstream = builder
                .send()
                .await
                .map_err(|e| AuthAuthorityError::Unavailable(e.to_string()))?;
            let status = StatusCode::from_u16(upstream.status().as_u16())
                .map_err(|e| AuthAuthorityError::Internal(e.to_string()))?;
            let resp_nominated = reqwest_connection_nominated(upstream.headers());
            let mut reply = Response::builder().status(status);
            for (name, value) in upstream.headers() {
                if let (Ok(hname), Ok(hval)) = (
                    HeaderName::from_bytes(name.as_str().as_bytes()),
                    HeaderValue::from_bytes(value.as_bytes()),
                ) {
                    if !is_hop_by_hop(&hname) && !resp_nominated.contains(hname.as_str()) {
                        reply = reply.header(hname, hval);
                    }
                }
            }
            let bytes = read_bounded(upstream).await?;
            let body: AuthBody = Full::new(Bytes::from(bytes))
                .map_err(|never| match never {})
                .boxed();
            reply
                .body(body)
                .map_err(|e| AuthAuthorityError::Internal(e.to_string()))
        })
    }

    fn verifying_key<'a>(&'a self, kid: &'a str) -> AuthFuture<'a, Option<VerifyingKey>> {
        Box::pin(async move { self.jwks.key(kid).await })
    }

    fn legacy_verifier(&self) -> Option<&LegacyKeys> {
        self.legacy.as_ref()
    }

    fn jwks_json<'a>(&'a self) -> AuthFuture<'a, Result<String, AuthAuthorityError>> {
        Box::pin(async move {
            let resp = self
                .client
                .get(&self.jwks_url)
                .header("accept", "application/json")
                .send()
                .await
                .map_err(|e| AuthAuthorityError::Unavailable(e.to_string()))?;
            if resp.status() != StatusCode::OK {
                return Err(AuthAuthorityError::Unavailable(format!(
                    "jwks status {}",
                    resp.status()
                )));
            }
            let raw = read_bounded(resp).await?;
            // Validate public-only EC JWKS before returning to callers.
            crate::jwks::parse(&raw).map_err(AuthAuthorityError::Internal)?;
            String::from_utf8(raw).map_err(|e| AuthAuthorityError::Internal(e.to_string()))
        })
    }

    fn disable_user_sessions<'a>(
        &'a self,
        target: DisableTarget,
    ) -> AuthFuture<'a, Result<DisableOutcome, AuthAuthorityError>> {
        Box::pin(async move {
            let key = self.require_internal_key()?;
            let body = match target {
                DisableTarget::UserId(user_id) => serde_json::json!({ "user_id": user_id }),
                DisableTarget::ExternalId(external_id) => {
                    serde_json::json!({ "external_id": external_id })
                }
            };
            let resp = self
                .client
                .post(format!("{}/auth/scim/disable", self.base_url))
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(body.to_string())
                .send()
                .await
                .map_err(|e| AuthAuthorityError::Unavailable(e.to_string()))?;
            match resp.status().as_u16() {
                200..=299 => Ok(DisableOutcome::Disabled),
                404 => Ok(DisableOutcome::NotFound),
                401 | 403 => Err(AuthAuthorityError::Unauthorized(format!(
                    "scim disable refused ({})",
                    resp.status()
                ))),
                503 => Err(AuthAuthorityError::Unavailable(
                    "scim disable unavailable".into(),
                )),
                code => Err(AuthAuthorityError::Internal(format!(
                    "scim disable unexpected status {code}"
                ))),
            }
        })
    }

    fn introspect_token<'a>(
        &'a self,
        token: &'a str,
    ) -> AuthFuture<'a, Result<Value, AuthAuthorityError>> {
        Box::pin(async move {
            let key = self.require_internal_key()?;
            let resp = self
                .client
                .post(format!("{}/auth/introspect", self.base_url))
                .header("authorization", format!("Bearer {key}"))
                .form(&[("token", token)])
                .send()
                .await
                .map_err(|e| AuthAuthorityError::Unavailable(e.to_string()))?;
            match resp.status().as_u16() {
                200 => {
                    let bytes = read_bounded(resp).await?;
                    serde_json::from_slice(&bytes)
                        .map_err(|e| AuthAuthorityError::Internal(e.to_string()))
                }
                401 | 403 => Err(AuthAuthorityError::Unauthorized(format!(
                    "introspect refused ({})",
                    resp.status()
                ))),
                code => Err(AuthAuthorityError::Unavailable(format!(
                    "introspect status {code}"
                ))),
            }
        })
    }

    fn revoke_token<'a>(
        &'a self,
        token: &'a str,
    ) -> AuthFuture<'a, Result<(), AuthAuthorityError>> {
        Box::pin(async move {
            let key = self.require_internal_key()?;
            let resp = self
                .client
                .post(format!("{}/auth/revoke", self.base_url))
                .header("authorization", format!("Bearer {key}"))
                .form(&[("token", token)])
                .send()
                .await
                .map_err(|e| AuthAuthorityError::Unavailable(e.to_string()))?;
            match resp.status().as_u16() {
                200..=299 => Ok(()),
                401 | 403 => Err(AuthAuthorityError::Unauthorized(format!(
                    "revoke refused ({})",
                    resp.status()
                ))),
                code => Err(AuthAuthorityError::Unavailable(format!(
                    "revoke status {code}"
                ))),
            }
        })
    }

    fn mint_drive_token<'a>(
        &'a self,
        _req: DriveTokenRequest,
    ) -> AuthFuture<'a, Result<DriveTokenResponse, AuthAuthorityError>> {
        Box::pin(async {
            Err(AuthAuthorityError::Unconfigured(
                "remote auth authority does not mint Drive native tokens; configure DRIVE_NATIVE_TOKEN_SECRET on HTTP nodes or use co-located auth".into(),
            ))
        })
    }

    fn reload<'a>(&'a self) -> AuthFuture<'a, Result<(), AuthAuthorityError>> {
        Box::pin(async move {
            let key = self.require_internal_key()?;
            let resp = self
                .client
                .post(format!("{}/admin/reload", self.base_url))
                .header("authorization", format!("Bearer {key}"))
                .send()
                .await
                .map_err(|e| AuthAuthorityError::Unavailable(e.to_string()))?;
            match resp.status().as_u16() {
                200..=299 => Ok(()),
                401 | 403 => Err(AuthAuthorityError::Unauthorized(format!(
                    "reload refused ({})",
                    resp.status()
                ))),
                code => Err(AuthAuthorityError::Unavailable(format!(
                    "reload status {code}"
                ))),
            }
        })
    }

    fn is_in_process(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::tests::{public_key, sign, signing_key};
    use serde_json::json;

    struct StubAuthority {
        kid: &'static str,
        key: VerifyingKey,
        legacy: Option<LegacyKeys>,
    }

    impl AuthAuthority for StubAuthority {
        fn handle_http<'a>(
            &'a self,
            _req: Request<AuthBody>,
            _meta: AuthRequestMeta,
        ) -> AuthFuture<'a, Result<Response<AuthBody>, AuthAuthorityError>> {
            Box::pin(async {
                let body: AuthBody = Full::new(Bytes::from_static(b"ok"))
                    .map_err(|never| match never {})
                    .boxed();
                Ok(Response::new(body))
            })
        }

        fn verifying_key<'a>(&'a self, kid: &'a str) -> AuthFuture<'a, Option<VerifyingKey>> {
            let found = (kid == self.kid).then_some(self.key);
            Box::pin(async move { found })
        }

        fn legacy_verifier(&self) -> Option<&LegacyKeys> {
            self.legacy.as_ref()
        }

        fn jwks_json<'a>(&'a self) -> AuthFuture<'a, Result<String, AuthAuthorityError>> {
            let doc = json!({ "keys": [crate::jwks::jwk(self.kid, &self.key)] }).to_string();
            Box::pin(async move { Ok(doc) })
        }

        fn disable_user_sessions<'a>(
            &'a self,
            _target: DisableTarget,
        ) -> AuthFuture<'a, Result<DisableOutcome, AuthAuthorityError>> {
            Box::pin(async { Ok(DisableOutcome::Disabled) })
        }

        fn introspect_token<'a>(
            &'a self,
            _token: &'a str,
        ) -> AuthFuture<'a, Result<Value, AuthAuthorityError>> {
            Box::pin(async { Ok(json!({ "active": true })) })
        }

        fn revoke_token<'a>(
            &'a self,
            _token: &'a str,
        ) -> AuthFuture<'a, Result<(), AuthAuthorityError>> {
            Box::pin(async { Ok(()) })
        }

        fn mint_drive_token<'a>(
            &'a self,
            _req: DriveTokenRequest,
        ) -> AuthFuture<'a, Result<DriveTokenResponse, AuthAuthorityError>> {
            Box::pin(async {
                Ok(DriveTokenResponse {
                    token: "tok".into(),
                    expires_at: "2099-01-01T00:00:00Z".into(),
                    raw_json: "{\"token\":\"tok\",\"expiresAt\":\"2099-01-01T00:00:00Z\"}\n".into(),
                })
            })
        }

        fn reload<'a>(&'a self) -> AuthFuture<'a, Result<(), AuthAuthorityError>> {
            Box::pin(async { Ok(()) })
        }

        fn is_in_process(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn auth_key_source_verifies_es256_and_legacy_tokens_via_trait() {
        let sk = signing_key(7);
        let pk = public_key(&sk);
        let secret = b"auth-authority-test-secret-32-bytes!!";
        let legacy = LegacyKeys::new(secret, &["authserver-hmac-1"], None).unwrap();
        let authority: Arc<dyn AuthAuthority> = Arc::new(StubAuthority {
            kid: "k-es256",
            key: pk,
            legacy: Some(legacy),
        });
        assert!(authority.is_in_process());
        let source = AuthKeySource::new(authority);

        let claims = json!({
            "uid": 9,
            "email": "u@example.test",
            "typ": "access",
            "jti": "j1",
            "fam": "f1",
            "iss": "mailserver",
            "aud": ["mailserver-gateway"],
            "iat": 1_799_999_000,
            "exp": 1_800_000_900,
        });
        let es_tok = sign(
            &sk,
            &json!({"alg": "ES256", "kid": "k-es256", "typ": "JWT"}),
            &claims,
        );
        let session = crate::token::verify(&es_tok, "mailserver", 1_800_000_000.0, &source)
            .await
            .expect("ES256 verified through AuthKeySource");
        assert_eq!(session.user_id, 9);

        let hs_tok = crate::legacy_jwt::sign_hs256(secret, &claims.to_string());
        let hs_session = crate::token::verify(&hs_tok, "mailserver", 1_800_000_000.0, &source)
            .await
            .expect("HS256 verified through AuthKeySource legacy_verifier");
        assert_eq!(hs_session.user_id, 9);
    }

    #[test]
    fn remote_auth_authority_accepts_https_and_loopback_http_and_rejects_remote_http() {
        assert!(RemoteAuthAuthority::new("http://127.0.0.1:8443", None, "k", None).is_ok());
        assert!(RemoteAuthAuthority::new("http://[::1]:8443", None, "k", None).is_ok());
        assert!(RemoteAuthAuthority::new("http://localhost:8443", None, "k", None).is_ok());
        assert!(RemoteAuthAuthority::new(
            "https://auth.internal.example:8443",
            Some("https://auth.internal.example:8443/.well-known/jwks.json"),
            "k",
            None,
        )
        .is_ok());
        // Non-loopback plaintext http:// MUST be refused for both base URL and JWKS URL.
        assert!(
            RemoteAuthAuthority::new("http://auth.internal.example:8443", None, "k", None).is_err()
        );
        assert!(RemoteAuthAuthority::new("http://10.0.0.5:8443", None, "k", None).is_err());
        assert!(RemoteAuthAuthority::new(
            "https://auth.internal.example:8443",
            Some("http://auth.internal.example:8443/.well-known/jwks.json"),
            "k",
            None,
        )
        .is_err());
        assert!(RemoteAuthAuthority::new("ftp://auth.example", None, "k", None).is_err());
        assert!(RemoteAuthAuthority::new("https:///missing-host", None, "k", None).is_err());
    }

    #[tokio::test]
    async fn remote_handle_http_strips_spoofed_headers_forwards_host_and_caps_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
            let _ = tx.send(raw);
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        });

        let authority =
            RemoteAuthAuthority::new(&format!("http://{addr}"), None, "secret-key", None).unwrap();
        let meta = AuthRequestMeta {
            client_ip: "203.0.113.42".parse().unwrap(),
            proto: "https",
            peer: "127.0.0.1:54321".parse().unwrap(),
            tls: true,
            csrf_verified: true,
        };

        // 1. Oversized body (> MAX_REMOTE_BODY) is rejected with PayloadTooLarge before network I/O.
        let oversized_body: AuthBody = Full::new(Bytes::from(vec![b'x'; MAX_REMOTE_BODY + 1]))
            .map_err(|never| match never {})
            .boxed();
        let oversized_req = Request::builder()
            .method("POST")
            .uri("/auth/login")
            .body(oversized_body)
            .unwrap();
        assert_eq!(
            authority
                .handle_http(oversized_req, meta.clone())
                .await
                .unwrap_err(),
            AuthAuthorityError::PayloadTooLarge
        );

        // 2. Spoofed forwarding/hop-by-hop headers are stripped; Host -> X-Forwarded-Host.
        let ok_body: AuthBody = Full::new(Bytes::from_static(b"{}"))
            .map_err(|never| match never {})
            .boxed();
        let req = Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header("host", "mail.example.com")
            .header("x-forwarded-for", "198.51.100.99")
            .header("x-forwarded-proto", "http")
            .header("x-real-ip", "198.51.100.99")
            .header("proxy-connection", "keep-alive")
            .header("connection", "x-hop-secret, x-second-hop")
            .header("x-hop-secret", "must-not-forward")
            .header("x-second-hop", "also-stripped")
            .header("x-custom-ok", "kept")
            .body(ok_body)
            .unwrap();
        let resp = authority.handle_http(req, meta).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let captured = rx.await.unwrap();
        let lower = captured.to_ascii_lowercase();
        assert!(
            lower.contains("x-forwarded-for: 203.0.113.42\r\n"),
            "{captured}"
        );
        assert!(lower.contains("x-forwarded-proto: https\r\n"), "{captured}");
        assert!(
            lower.contains("x-forwarded-host: mail.example.com\r\n"),
            "{captured}"
        );
        assert!(lower.contains("x-custom-ok: kept\r\n"), "{captured}");
        assert!(!lower.contains("198.51.100.99"), "{captured}");
        assert!(!lower.contains("x-real-ip"), "{captured}");
        assert!(!lower.contains("proxy-connection"), "{captured}");
        assert!(!lower.contains("x-hop-secret"), "{captured}");
        assert!(!lower.contains("x-second-hop"), "{captured}");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn remote_handle_http_h2_ignores_spoofed_x_forwarded_host() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
            let _ = tx.send(raw);
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        });

        let authority =
            RemoteAuthAuthority::new(&format!("http://{addr}"), None, "secret-key", None).unwrap();
        let meta = AuthRequestMeta {
            client_ip: "203.0.113.42".parse().unwrap(),
            proto: "https",
            peer: "127.0.0.1:54321".parse().unwrap(),
            tls: true,
            csrf_verified: true,
        };
        let body: AuthBody = Full::new(Bytes::from_static(b"{}"))
            .map_err(|never| match never {})
            .boxed();
        // Simulate HTTP/2 where hyper places :authority in URI authority and omits Host header.
        let req = Request::builder()
            .method("POST")
            .uri("https://real.example.com/auth/login")
            .header("x-forwarded-host", "attacker.invalid")
            .body(body)
            .unwrap();
        let resp = authority.handle_http(req, meta).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let captured = rx.await.unwrap().to_ascii_lowercase();
        assert!(
            captured.contains("x-forwarded-host: real.example.com\r\n"),
            "{captured}"
        );
        assert!(!captured.contains("attacker.invalid"), "{captured}");
        server.await.unwrap();
    }
}
