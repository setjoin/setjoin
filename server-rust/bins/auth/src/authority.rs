//! In-process [`AuthAuthority`] implementation wrapping [`AuthServer`] (#543).
//!
//! Gated behind the `in-process-authority` Cargo feature, which CI restricts
//! exclusively to `setjoin-auth` and `setjoind` (`scripts/check-rust-family-isolation.py`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use http_body_util::{BodyExt, Limited};
use hyper::{Request, Response};
use serde_json::Value;
use setjoin_authz::auth_authority::{
    AuthAuthority, AuthAuthorityError, AuthBody, AuthBoxError, AuthFuture, AuthRequestMeta,
    DisableOutcome, DisableTarget, DriveTokenRequest, DriveTokenResponse,
};
use setjoin_authz::es256::VerifyingKey;
use setjoin_authz::legacy_jwt::LegacyKeys;
use setjoin_identity::drive_token::{Issuer as DriveTokenIssuer, Refused as DriveTokenRefused};
use setjoin_identity::issuance::{self, ClientProof};
use setjoin_pg::CommandOutcome;

use crate::{AuthServer, Body, ConnectionMeta};

/// Paths owned by `AuthServer` that are strictly internal (`INTERNAL_API_KEY`)
/// and must NEVER be exposed on the public unified HTTP listener.
const INTERNAL_ONLY_PATHS: [&str; 2] = ["/auth/scim/disable", "/admin/reload"];

/// Default in-process request body cap (1 MiB), matching auth's per-route cap.
const DEFAULT_BODY_CAP: usize = 1 << 20;

/// SAML ACS request body cap (4 MiB), preserving `saml::ACS_BODY`.
const SAML_BODY_CAP: usize = 4 << 20;

/// Forwarding headers stripped before in-process dispatch; client IP and scheme
/// come exclusively from the gateway-resolved [`AuthRequestMeta`].
const UNTRUSTED_FORWARD_HEADERS: [&str; 4] = [
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-real-ip",
];

/// Normalize a request path for security checks: percent-decode, collapse
/// repeated slashes (`//` -> `/`), and trim trailing slashes (preserving `/`).
pub(crate) fn normalize_path(raw: &str) -> String {
    let decoded = percent_encoding::percent_decode_str(raw).decode_utf8_lossy();
    let mut collapsed = String::with_capacity(decoded.len());
    let mut prev_slash = false;
    for ch in decoded.chars() {
        if ch == '/' {
            if !prev_slash {
                collapsed.push('/');
            }
            prev_slash = true;
        } else {
            collapsed.push(ch);
            prev_slash = false;
        }
    }
    while collapsed.len() > 1 && collapsed.ends_with('/') {
        collapsed.pop();
    }
    collapsed
}

fn is_internal_only_path(raw: &str) -> bool {
    let normalized = normalize_path(raw);
    INTERNAL_ONLY_PATHS
        .iter()
        .any(|blocked| normalized.eq_ignore_ascii_case(blocked))
}

fn body_cap_for_path(normalized_path: &str) -> usize {
    if normalized_path.starts_with("/auth/saml/") || normalized_path == "/auth/saml" {
        SAML_BODY_CAP
    } else {
        DEFAULT_BODY_CAP
    }
}

/// Co-located in-process [`AuthAuthority`] backed directly by [`AuthServer`].
///
/// Zero loopback HTTP hop: `handle_http` streams directly through
/// `AuthServer::handle`, `verifying_key` reads the in-memory ES256 [`KeySet`],
/// and privileged control-plane methods (`disable_user_sessions`,
/// `introspect_token`, `revoke_token`) authenticate via the feature-sealed
/// [`ClientProof::in_process()`].
pub struct InProcessAuthAuthority {
    server: Arc<AuthServer>,
    legacy: Option<LegacyKeys>,
    drive_issuer: Option<DriveTokenIssuer>,
    block_internal_routes: bool,
}

impl InProcessAuthAuthority {
    /// Wrap an initialized [`AuthServer`] for unified in-process dispatch.
    ///
    /// Internal-only routes (`/auth/scim/disable`, `/admin/reload`) are blocked
    /// with 404 on [`Self::handle_http`] by default so the public listener can
    /// never expose them.
    pub fn new(server: Arc<AuthServer>) -> Self {
        let drive_secret = std::env::var("DRIVE_NATIVE_TOKEN_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| server.config.secret.clone());
        let drive_issuer = (!drive_secret.is_empty())
            .then(|| DriveTokenIssuer::new(drive_secret.as_bytes(), server.config.issuer.clone()));
        let legacy = build_combined_legacy(&server, &drive_secret);
        Self {
            server,
            legacy,
            drive_issuer,
            block_internal_routes: true,
        }
    }

    /// Underlying [`AuthServer`] handle.
    pub fn server(&self) -> &Arc<AuthServer> {
        &self.server
    }

    /// Build a bounded streaming request body adapter (`AuthBody` -> `auth::Body`)
    /// that enforces `cap` bytes on chunked/streaming bodies and sets `overflowed`
    /// if the limit is exceeded.
    fn adapt_req_body(body: AuthBody, cap: usize, overflowed: Arc<AtomicBool>) -> Body {
        Limited::new(body, cap)
            .map_err(move |err| {
                if err.is::<http_body_util::LengthLimitError>() {
                    overflowed.store(true, Ordering::Release);
                }
                std::io::Error::other(err)
            })
            .boxed()
    }

    /// Build a thin streaming response body adapter (`auth::Body` -> `AuthBody`).
    fn adapt_resp_body(body: Body) -> AuthBody {
        body.map_err(|err| Box::new(err) as AuthBoxError).boxed()
    }
}

fn build_combined_legacy(server: &AuthServer, drive_secret: &str) -> Option<LegacyKeys> {
    if server.config.secret.is_empty() {
        return None;
    }
    let pem = if matches!(
        server.config.profile,
        setjoin_config_secret::CryptoProfile::Smx | setjoin_config_secret::CryptoProfile::Hybrid
    ) {
        server.config.sm2_pem.as_deref()
    } else {
        None
    };
    let mut legacy = LegacyKeys::from_pem(
        server.config.secret.as_bytes(),
        &["authserver-hmac-1", "mailserver-drive-native-1"],
        pem,
    )
    .ok()?;
    if !drive_secret.is_empty() && drive_secret != server.config.secret {
        legacy = legacy.with_hmac_kid("mailserver-drive-native-1", drive_secret.as_bytes());
    }
    Some(legacy)
}

impl AuthAuthority for InProcessAuthAuthority {
    fn handle_http<'a>(
        &'a self,
        mut req: Request<AuthBody>,
        meta: AuthRequestMeta,
    ) -> AuthFuture<'a, Result<Response<AuthBody>, AuthAuthorityError>> {
        Box::pin(async move {
            let normalized = normalize_path(req.uri().path());
            if self.block_internal_routes && is_internal_only_path(req.uri().path()) {
                return Ok(AuthServer::not_found().map(Self::adapt_resp_body));
            }
            let cap = body_cap_for_path(&normalized);
            if let Some(val) = req.headers().get(hyper::header::CONTENT_LENGTH) {
                if let Ok(text) = val.to_str() {
                    if let Ok(len) = text.trim().parse::<u64>() {
                        if len > cap as u64 {
                            return Err(AuthAuthorityError::PayloadTooLarge);
                        }
                    }
                }
            }
            if hyper::body::Body::size_hint(req.body()).lower() > cap as u64 {
                return Err(AuthAuthorityError::PayloadTooLarge);
            }
            for header in UNTRUSTED_FORWARD_HEADERS {
                req.headers_mut().remove(header);
            }
            let conn_meta = ConnectionMeta {
                peer: meta.peer,
                tls: meta.tls,
            };
            let overflowed = Arc::new(AtomicBool::new(false));
            let mut adapted = req.map(|b| Self::adapt_req_body(b, cap, overflowed.clone()));
            adapted.extensions_mut().insert(conn_meta);
            adapted.extensions_mut().insert(meta);
            let reply = self.server.handle(adapted).await;
            if overflowed.load(Ordering::Acquire) {
                return Err(AuthAuthorityError::PayloadTooLarge);
            }
            Ok(reply.map(Self::adapt_resp_body))
        })
    }

    fn verifying_key<'a>(&'a self, kid: &'a str) -> AuthFuture<'a, Option<VerifyingKey>> {
        Box::pin(async move {
            let keys = self.server.keys.as_ref()?;
            setjoin_authz::token::KeySource::key(keys.as_ref(), kid).await
        })
    }

    fn legacy_verifier(&self) -> Option<&LegacyKeys> {
        self.legacy.as_ref().or(self.server.legacy.as_ref())
    }

    fn jwks_json<'a>(&'a self) -> AuthFuture<'a, Result<String, AuthAuthorityError>> {
        Box::pin(async move {
            self.server
                .keys
                .as_ref()
                .map(|keys| keys.jwks_json())
                .ok_or_else(|| AuthAuthorityError::Unavailable("signing keys unavailable".into()))
        })
    }

    fn disable_user_sessions<'a>(
        &'a self,
        target: DisableTarget,
    ) -> AuthFuture<'a, Result<DisableOutcome, AuthAuthorityError>> {
        Box::pin(async move {
            let caller = ClientProof::in_process();
            let (user_id, external_id) = match &target {
                DisableTarget::UserId(id) => (*id, ""),
                DisableTarget::ExternalId(ext) => (0, ext.as_str()),
            };
            match issuance::disable(self.server.auth_db(), &caller, user_id, external_id).await {
                CommandOutcome::Committed(true) => Ok(DisableOutcome::Disabled),
                CommandOutcome::Committed(false) => Ok(DisableOutcome::NotFound),
                CommandOutcome::Unknown { .. } => Err(AuthAuthorityError::Unavailable(
                    "session revocation outcome unavailable".into(),
                )),
                CommandOutcome::RolledBack(_) => Err(AuthAuthorityError::Internal(
                    "session revocation failed".into(),
                )),
            }
        })
    }

    fn introspect_token<'a>(
        &'a self,
        token: &'a str,
    ) -> AuthFuture<'a, Result<Value, AuthAuthorityError>> {
        Box::pin(async move {
            let caller = ClientProof::in_process();
            let raw = issuance::introspect(
                self.server.auth_db(),
                &caller,
                token,
                &self.server.config.issuer,
            )
            .await;
            serde_json::from_str(&raw).map_err(|e| AuthAuthorityError::Internal(e.to_string()))
        })
    }

    fn revoke_token<'a>(
        &'a self,
        token: &'a str,
    ) -> AuthFuture<'a, Result<(), AuthAuthorityError>> {
        Box::pin(async move {
            let caller = ClientProof::in_process();
            match issuance::revoke(self.server.auth_db(), &caller, token).await {
                CommandOutcome::Committed(()) => Ok(()),
                CommandOutcome::Unknown { .. } => Err(AuthAuthorityError::Unavailable(
                    "revocation outcome unavailable".into(),
                )),
                CommandOutcome::RolledBack(_) => {
                    Err(AuthAuthorityError::Internal("revocation failed".into()))
                }
            }
        })
    }

    fn mint_drive_token<'a>(
        &'a self,
        req: DriveTokenRequest,
    ) -> AuthFuture<'a, Result<DriveTokenResponse, AuthAuthorityError>> {
        Box::pin(async move {
            let issuer = self.drive_issuer.as_ref().ok_or_else(|| {
                AuthAuthorityError::Unconfigured("native-token minting is not configured".into())
            })?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            issuer.issue_request(&req, now).map_err(|e| match e {
                DriveTokenRefused::DeviceBound => AuthAuthorityError::DeviceBound,
                DriveTokenRefused::Expired => AuthAuthorityError::Expired,
            })
        })
    }

    fn reload<'a>(&'a self) -> AuthFuture<'a, Result<(), AuthAuthorityError>> {
        Box::pin(async move { self.server.reload().map_err(AuthAuthorityError::Internal) })
    }

    fn is_in_process(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::body::{Body as HttpBody, Frame, SizeHint};
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct ChunkedBody(VecDeque<Bytes>);

    impl HttpBody for ChunkedBody {
        type Data = Bytes;
        type Error = AuthBoxError;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.0.pop_front().map(|b| Ok(Frame::data(b))))
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::new()
        }
    }

    fn test_authority() -> InProcessAuthAuthority {
        let exec = setjoin_pg::ScopedExecutor::from_dsn("postgres://mail@127.0.0.1:1/unused", 1)
            .expect("lazy pool");
        let server = Arc::new(AuthServer::new(exec));
        InProcessAuthAuthority::new(server)
    }

    fn test_meta() -> AuthRequestMeta {
        AuthRequestMeta {
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            proto: "http",
            peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            tls: false,
            csrf_verified: true,
        }
    }

    fn full_body(bytes: Vec<u8>) -> AuthBody {
        Full::new(Bytes::from(bytes))
            .map_err(|never| match never {})
            .boxed()
    }

    #[tokio::test]
    async fn handle_http_caps_content_length_and_streaming_bodies() {
        let auth = test_authority();

        // 1. Normal GET /health succeeds.
        let ok_req = Request::builder()
            .method("GET")
            .uri("/health")
            .body(full_body(Vec::new()))
            .unwrap();
        let resp = auth.handle_http(ok_req, test_meta()).await.unwrap();
        assert_eq!(resp.status(), 200);

        // 2. Oversized Content-Length on default route (>1 MiB) -> PayloadTooLarge.
        let cl_req = Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header("content-length", (DEFAULT_BODY_CAP + 1).to_string())
            .body(full_body(Vec::new()))
            .unwrap();
        assert!(matches!(
            auth.handle_http(cl_req, test_meta()).await,
            Err(AuthAuthorityError::PayloadTooLarge)
        ));

        // 3. Oversized Content-Length on SAML route (>4 MiB) -> PayloadTooLarge.
        let saml_over = Request::builder()
            .method("POST")
            .uri("/auth/saml/acs")
            .header("content-length", (SAML_BODY_CAP + 1).to_string())
            .body(full_body(Vec::new()))
            .unwrap();
        assert!(matches!(
            auth.handle_http(saml_over, test_meta()).await,
            Err(AuthAuthorityError::PayloadTooLarge)
        ));

        // 4. Multi-chunk streaming body without Content-Length exceeding 1 MiB -> PayloadTooLarge.
        let stream_body: AuthBody = ChunkedBody(VecDeque::from([
            Bytes::from(vec![b'a'; 600 * 1024]),
            Bytes::from(vec![b'b'; 600 * 1024]),
        ]))
        .boxed();
        let stream_req = Request::builder()
            .method("POST")
            .uri("/auth/guest-invite/accept")
            .header("host", "localhost")
            .body(stream_body)
            .unwrap();
        assert!(matches!(
            auth.handle_http(stream_req, test_meta()).await,
            Err(AuthAuthorityError::PayloadTooLarge)
        ));
    }

    #[tokio::test]
    async fn handle_http_normalizes_and_blocks_internal_only_paths() {
        let auth = test_authority();
        for path in [
            "/auth/scim/disable",
            "/auth/scim/%64isable",
            "//auth/scim/disable",
            "/auth/scim/disable/",
            "/admin/reload",
            "/admin/reload/",
            "//admin/%72eload/",
        ] {
            let req = Request::builder()
                .method("POST")
                .uri(path)
                .body(full_body(Vec::new()))
                .unwrap();
            let resp = auth.handle_http(req, test_meta()).await.unwrap();
            assert_eq!(resp.status(), 404, "expected 404 for {path}");
        }
    }

    #[tokio::test]
    async fn handle_http_strips_untrusted_forwarding_headers() {
        let auth = test_authority();
        // Verify a request carrying spoofed x-forwarded-* headers still dispatches
        // cleanly using AuthRequestMeta instead of trusting forwarding headers.
        let req = Request::builder()
            .method("GET")
            .uri("/health")
            .header("x-forwarded-for", "203.0.113.99")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-host", "evil.example")
            .header("x-real-ip", "203.0.113.99")
            .body(full_body(Vec::new()))
            .unwrap();
        let resp = auth.handle_http(req, test_meta()).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[test]
    fn normalize_path_and_body_cap_helpers() {
        assert_eq!(normalize_path("/auth/scim/%64isable"), "/auth/scim/disable");
        assert_eq!(
            normalize_path("//auth//scim/disable///"),
            "/auth/scim/disable"
        );
        assert_eq!(normalize_path("/admin/reload/"), "/admin/reload");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(body_cap_for_path("/auth/saml/acs"), SAML_BODY_CAP);
        assert_eq!(body_cap_for_path("/auth/login"), DEFAULT_BODY_CAP);
    }
}
