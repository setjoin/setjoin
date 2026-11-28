//! #333 native Drive token issuance; proof and mint live in shared authz/identity.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use http_body_util::BodyExt;
use hyper::{Request, Response};
fn full(raw: String) -> Body {
    http_body_util::Full::new(bytes::Bytes::from(raw))
        .map_err(|never| match never {})
        .boxed()
}
use setjoin_authz::{
    auth_authority::{AuthAuthority, AuthAuthorityError, DriveTokenRequest},
    push,
    token::KeySource,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

/// Scoped Drive native-token HMAC secret (`DRIVE_NATIVE_TOKEN_SECRET`), falling
/// back to `JWT_SECRET` in co-located / legacy deployments.
pub fn drive_native_secret_from_env() -> Option<String> {
    std::env::var("DRIVE_NATIVE_TOKEN_SECRET")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("JWT_SECRET").ok().filter(|s| !s.is_empty()))
}

pub struct NativeTokenRoute<K: KeySource + 'static> {
    exec: ScopedExecutor,
    keys: Arc<K>,
    issuer: String,
    signer: Option<Arc<setjoin_identity::drive_token::Issuer>>,
    authority: Option<Arc<dyn AuthAuthority>>,
    basic: crate::dav_auth::DavBasicAuth,
}
impl<K: KeySource + 'static> NativeTokenRoute<K> {
    pub fn new(exec: ScopedExecutor, keys: Arc<K>, issuer: String, secret: Option<&str>) -> Self {
        let signer = secret.filter(|s| !s.is_empty()).map(|s| {
            Arc::new(setjoin_identity::drive_token::Issuer::new(
                s.as_bytes(),
                issuer.clone(),
            ))
        });
        Self {
            exec,
            keys,
            issuer,
            signer,
            authority: None,
            basic: crate::dav_auth::DavBasicAuth::default(),
        }
    }
    /// Delegate Drive native-token minting to an [`AuthAuthority`] when no
    /// local signing secret is configured on this HTTP node.
    pub fn with_authority(mut self, authority: Arc<dyn AuthAuthority>) -> Self {
        self.authority = Some(authority);
        self
    }
    pub fn with_chain(mut self, chain: Option<Arc<setjoin_authz::auth_chain::Chain>>) -> Self {
        self.basic.chain = chain;
        self
    }
    pub fn with_basic_auth(mut self, basic: crate::dav_auth::DavBasicAuth) -> Self {
        self.basic = basic;
        self
    }
}
fn response(status: u16, raw: String, problem: bool) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(
            "content-type",
            if problem {
                "application/problem+json"
            } else {
                "application/json"
            },
        )
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .body(full(raw))
        .unwrap()
}
fn denied() -> Response<Body> {
    let mut r = response(
        401,
        crate::problem::Problem::new(401, "Unauthorized").body(),
        true,
    );
    r.headers_mut().insert(
        "www-authenticate",
        "Negotiate, Bearer realm=\"mailserver\"".parse().unwrap(),
    );
    r
}
impl<K: KeySource + 'static> Intercept for NativeTokenRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool {
        true
    }
    fn matches(&self, r: &Request<Body>) -> bool {
        r.method() == hyper::Method::POST && r.uri().path() == "/api/drive/native-token"
    }
    fn admits_member(&self, h: hyper::HeaderMap, _scheme: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            let Some(t) = setjoin_authz::token::presented(&h) else {
                return false;
            };
            matches!(push::authenticate_drive(&exec,&*keys,&issuer,&t).await,Ok(p) if !p.is_guest())
        })
    }
    fn handle(&self, mut r: Request<Body>, context: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer, signer, authority, basic) = (
            self.exec.clone(),
            self.keys.clone(),
            self.issuer.clone(),
            self.signer.clone(),
            self.authority.clone(),
            self.basic.clone(),
        );
        Box::pin(async move {
            if !push::http_admission_allowed(&exec).await {
                return response(
                    503,
                    crate::problem::Problem::new(503, "service unavailable").body(),
                    true,
                );
            } // shared policy/runtime components #405/#420
            if !matches!(
                *r.method(),
                hyper::Method::GET | hyper::Method::HEAD | hyper::Method::OPTIONS
            ) && !setjoin_authz::csrf::allows(r.headers(), context.identity.proto)
            {
                return response(
                    403,
                    crate::problem::middleware(403, "csrf_failed", "CSRF validation failed"),
                    true,
                );
            }
            let source = match setjoin_authz::token::presented(r.headers()) {
                Some(token) => push::authenticate_drive(&exec, &*keys, &issuer, &token)
                    .await
                    .ok(),
                None => None,
            };
            let source = match source {
                Some(source) => source,
                None if crate::dav_auth::has_scheme(r.headers(), b"Basic ") => {
                    match basic.authenticate(&exec, &mut r, &context).await {
                        Ok(user) => push::PushIdentity::from_basic(user.user_id, user.email),
                        Err(resp) => return resp,
                    }
                }
                None if crate::dav_auth::has_scheme(r.headers(), b"Negotiate ") => {
                    match basic.authenticate_negotiate(&exec, &mut r, &context).await {
                        Ok(user) => push::PushIdentity::from_basic(user.user_id, user.email),
                        Err(resp) => return resp,
                    }
                }
                None => return denied(),
            };
            if source.is_guest() {
                return crate::admission::not_found(r.headers(), &context.identity);
            } // guest program admission #406
            if push::revoked(&exec, &source).await {
                return response(
                    401,
                    crate::problem::middleware(
                        401,
                        "session_revoked",
                        "Session has been revoked. Sign in again.",
                    ),
                    true,
                );
            }
            if let Some(signer) = signer {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                return match signer.issue(&source, now) {
                    Ok(raw) => response(200, raw, false),
                    Err(setjoin_identity::drive_token::Refused::DeviceBound) => response(
                        403,
                        crate::problem::Problem::new(
                            403,
                            "native tokens are unavailable to device-bound sessions",
                        )
                        .body(),
                        true,
                    ),
                    Err(setjoin_identity::drive_token::Refused::Expired) => response(
                        401,
                        crate::problem::Problem::new(401, "session expired").body(),
                        true,
                    ),
                };
            }
            if let Some(authority) = authority {
                let req = DriveTokenRequest {
                    user_id: source.user_id(),
                    email: source.email().to_owned(),
                    jti: source.token_id().to_owned(),
                    family: source.token_family().to_owned(),
                    account_type: source.account_type().to_owned(),
                    actor_id: source.act(),
                    expires_at: source.expires_at(),
                    device_bound: source.has_device_binding(),
                };
                return match authority.mint_drive_token(req).await {
                    Ok(minted) => response(200, minted.raw_json, false),
                    Err(AuthAuthorityError::DeviceBound) => response(
                        403,
                        crate::problem::Problem::new(
                            403,
                            "native tokens are unavailable to device-bound sessions",
                        )
                        .body(),
                        true,
                    ),
                    Err(AuthAuthorityError::Expired) => response(
                        401,
                        crate::problem::Problem::new(401, "session expired").body(),
                        true,
                    ),
                    Err(AuthAuthorityError::Unavailable(_)) => response(
                        503,
                        crate::problem::Problem::new(503, "service unavailable").body(),
                        true,
                    ),
                    Err(_) => response(
                        500,
                        crate::problem::Problem::new(500, "native-token minting is not configured")
                            .body(),
                        true,
                    ),
                };
            }
            response(
                500,
                crate::problem::Problem::new(500, "native-token minting is not configured").body(),
                true,
            )
        })
    }
}
