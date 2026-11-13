//! OIDC relying party. External HTTP supplies no user/database authority.
mod outcome;
pub use outcome::{lookup_assertion, lookup_session, Operation};
mod secret;
pub use secret::reseal;
mod link;
pub use link::LinkFlow;
mod listener;
pub use listener::{admit_worker, Listener};
mod account;
pub use account::{Assertion, Federated, Lookup, Resolution};
use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreJsonWebKeySet},
    AuthUrl, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet, IssuerUrl, Nonce,
    PkceCodeChallenge, RedirectUrl, Scope, TokenUrl,
};
use serde::Deserialize;
use setjoin_pg::ScopedExecutor;
use std::{
    collections::BTreeMap,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, RwLock},
    time::Duration,
};

pub type HttpFuture<'a> =
    Pin<Box<dyn Future<Output = Result<openidconnect::HttpResponse, io::Error>> + Send + 'a>>;
/// The external discovery/JWKS/token boundary; never selects an account or a DB.
pub trait Http: Send + Sync {
    fn send(&self, request: openidconnect::HttpRequest) -> HttpFuture<'_>;
}
struct PublicDns;
impl reqwest::dns::Resolve for PublicDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let name = name.as_str().to_owned();
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .filter(|a| !setjoin_authz::ssrf::blocked(a.ip()))
                .collect();
            if addresses.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unsafe OIDC destination",
                )
                .into());
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}
pub struct SafeHttp(reqwest::Client);
impl SafeHttp {
    pub fn new() -> Result<Self, String> {
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::new(PublicDns))
            .timeout(Duration::from_secs(10))
            .user_agent("Go-http-client/1.1")
            .build()
            .map(Self)
            .map_err(|e| e.to_string())
    }
}
impl Http for SafeHttp {
    fn send(&self, request: openidconnect::HttpRequest) -> HttpFuture<'_> {
        Box::pin(async move {
            let url = url::Url::parse(&request.uri().to_string()).map_err(io::Error::other)?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || url
                    .host_str()
                    .and_then(|h| h.trim_matches(['[', ']']).parse().ok())
                    .is_some_and(setjoin_authz::ssrf::blocked)
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unsafe OIDC destination",
                ));
            }
            let (parts, data) = request.into_parts();
            let response = self
                .0
                .request(parts.method, url)
                .headers(parts.headers)
                .body(data)
                .send()
                .await
                .map_err(io::Error::other)?;
            let mut result = openidconnect::http::Response::builder().status(response.status());
            *result.headers_mut().unwrap() = response.headers().clone();
            let mut data = Vec::new();
            let mut response = response;
            while let Some(chunk) = response.chunk().await.map_err(io::Error::other)? {
                if data.len() + chunk.len() > MAX_IDP_BODY {
                    return Err(too_large());
                }
                data.extend_from_slice(&chunk);
            }
            result.body(data).map_err(io::Error::other)
        })
    }
}
/// An IdP document (discovery, JWKS, token response) never legitimately
/// approaches this size; security fix (#530, owner-approved 2026-11-06): frozen
/// Go read IdP bodies without a cap, bounded only by its 10 s timeout.
pub const MAX_IDP_BODY: usize = 1 << 20;
fn too_large() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "OIDC IdP response too large")
}
#[derive(Clone)]
struct Transport(Arc<dyn Http>);
impl Transport {
    fn capped(&self, request: openidconnect::HttpRequest) -> HttpFuture<'_> {
        let sent = self.0.send(request);
        Box::pin(async move {
            let response = sent.await?;
            if response.body().len() > MAX_IDP_BODY && !crate::mutants::on("rp-body-uncapped") {
                return Err(too_large());
            }
            Ok(response)
        })
    }
}
impl<'a> openidconnect::AsyncHttpClient<'a> for Transport {
    type Error = io::Error;
    type Future = HttpFuture<'a>;
    fn call(&'a self, request: openidconnect::HttpRequest) -> Self::Future {
        self.capped(request)
    }
}
#[derive(Clone, Default, Deserialize, serde::Serialize)]
#[serde(default)]
pub struct Mapping {
    pub idp_group: String,
    pub distribution_group_id: Option<i64>,
    pub admin_role: Option<String>,
    pub department_id: Option<i64>,
}
#[derive(Default, Deserialize)]
#[serde(default)]
struct Config {
    name: String,
    provider_url: String,
    client_id: String,
    client_secret: String,
    redirect_url: String,
    enabled: bool,
    jit_enabled: bool,
    group_claim: String,
    group_mappings: Vec<Mapping>,
}
#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    id_token_signing_alg_values_supported: Option<Vec<String>>,
}
/// ID-token algorithms the provider may sign with: the discovery list (RS256
/// when absent, OIDC Discovery 3), asymmetric only. A public-key verifier must
/// never be steered to HMAC or `none` (security fix #530).
pub fn id_token_algs(advertised: Option<&[String]>) -> Vec<openidconnect::core::CoreJwsSigningAlgorithm> {
    use openidconnect::core::CoreJwsSigningAlgorithm as A;
    let default = ["RS256".to_owned()];
    advertised
        .unwrap_or(&default)
        .iter()
        .filter_map(|name| serde_json::from_value::<A>(serde_json::Value::String(name.clone())).ok())
        .filter(|alg| {
            !matches!(
                alg,
                A::HmacSha256 | A::HmacSha384 | A::HmacSha512 | A::None
            )
        })
        .collect()
}
type Client = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
    EndpointNotSet,
>;
pub struct Provider {
    config: Config,
    discovery: Discovery,
    algs: Vec<openidconnect::core::CoreJwsSigningAlgorithm>,
    transport: Transport,
    keys: tokio::sync::Mutex<CoreJsonWebKeySet>,
    auth_style: std::sync::atomic::AtomicU8,
}
impl Provider {
    pub fn key(&self) -> String {
        format!("oidc:{}", self.config.name)
    }
    pub fn jit(&self) -> bool {
        self.config.jit_enabled
    }
    pub fn redirect_uri(&self) -> &str {
        &self.config.redirect_url
    }

    fn client(&self, keys: CoreJsonWebKeySet, basic: bool) -> Result<Client, String> {
        let mut client = CoreClient::new(
            ClientId::new(self.config.client_id.clone()),
            IssuerUrl::new(self.config.provider_url.clone()).map_err(|e| e.to_string())?,
            keys,
        )
        .set_auth_uri(
            AuthUrl::new(self.discovery.authorization_endpoint.clone())
                .map_err(|e| e.to_string())?,
        )
        .set_token_uri(
            TokenUrl::new(self.discovery.token_endpoint.clone()).map_err(|e| e.to_string())?,
        );
        if basic || !self.config.client_secret.is_empty() {
            client = client.set_client_secret(ClientSecret::new(self.config.client_secret.clone()));
        }
        client = client.set_auth_type(if basic {
            openidconnect::AuthType::BasicAuth
        } else {
            openidconnect::AuthType::RequestBody
        });
        if !self.config.redirect_url.is_empty() {
            client = client.set_redirect_uri(
                RedirectUrl::new(self.config.redirect_url.clone()).map_err(|e| e.to_string())?,
            );
        }
        Ok(client)
    }
    /// OIDC client owns PKCE generation/challenge and authorization request shape.
    pub fn authorization(&self) -> Result<Authorization, String> {
        use ring::rand::{SecureRandom, SystemRandom};
        let mut state = [0; 16];
        let mut nonce = [0; 16];
        SystemRandom::new()
            .fill(&mut state)
            .map_err(|_| "state RNG failed")?;
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| "nonce RNG failed")?;
        let state = URL_SAFE.encode(state);
        let nonce = URL_SAFE.encode(nonce);
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let csrf = CsrfToken::new(state.clone());
        let oidc_nonce = Nonce::new(nonce.clone());
        let (mut url, _, _) = self
            .client(CoreJsonWebKeySet::new(Vec::new()), true)?
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                move || csrf,
                move || oidc_nonce,
            )
            .add_scope(Scope::new("email".into()))
            .add_scope(Scope::new("profile".into()))
            .add_scope(Scope::new("groups".into()))
            .set_pkce_challenge(challenge)
            .url();
        let mut pairs: Vec<_> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        let query = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        url.set_query(Some(&query));
        Ok(Authorization {
            url: url.into(),
            state,
            nonce,
            verifier: verifier.secret().clone(),
            provider: self.config.name.clone(),
        })
    }
}
pub struct Authorization {
    pub url: String,
    pub state: String,
    pub nonce: String,
    pub verifier: String,
    pub provider: String,
}
pub struct Registry {
    exec: ScopedExecutor,
    master: Vec<u8>,
    transport: Transport,
    reload: tokio::sync::Mutex<()>,
    providers: RwLock<BTreeMap<String, Arc<Provider>>>,
}
impl Registry {
    pub async fn load(exec: ScopedExecutor, master: &[u8], http: Arc<dyn Http>) -> Arc<Self> {
        let registry = Arc::new(Self {
            exec,
            master: master.to_vec(),
            transport: Transport(http),
            reload: tokio::sync::Mutex::new(()),
            providers: RwLock::new(BTreeMap::new()),
        });
        if let Err(error) = registry.reload().await {
            eprintln!("OIDC reload failed: {error}");
        }
        registry
    }
    pub fn provider(&self, name: &str) -> Option<Arc<Provider>> {
        self.providers.read().unwrap().get(name).cloned()
    }
    /// Atomically replace the complete authoritative healthy subset, even on error.
    pub async fn reload(&self) -> Result<(), String> {
        let _guard = self.reload.lock().await;
        let rows=match self.exec.read("SELECT key,value::text,encrypted FROM system_config WHERE key LIKE 'oidc_provider_%_config' ORDER BY key",&[]).await{
            Ok(rows)=>rows,Err(e)=>{self.providers.write().unwrap().clear();return Err(e.message);}
        };
        let mut providers = BTreeMap::new();
        let mut errors = Vec::new();
        for row in rows {
            let key: String = row.get(0);
            let raw: String = row.get(1);
            let load = async {
                let mut config: Config = serde_json::from_str(&raw)
                    .map_err(|_| "invalid provider configuration".to_owned())?;
                if !config.enabled {
                    return Ok(None);
                }
                config.client_secret = open_secret(&config.client_secret, &self.master)?;
                let provider_key = format!("oidc:{}", config.name);
                if !(3..=255).contains(&provider_key.len())
                    || provider_key.trim() != provider_key
                    || provider_key.chars().any(|c| c < ' ' || c == '\u{7f}')
                    || config.group_mappings.len() > 100
                    || config.group_mappings.iter().any(|m| {
                        m.idp_group.trim().is_empty()
                            || m.idp_group.len() > 1024
                            || m.idp_group.chars().any(char::is_control)
                    })
                {
                    return Err("invalid provider name or group mappings".into());
                }
                let issuer =
                    url::Url::parse(&config.provider_url).map_err(|_| "invalid issuer URL")?;
                if issuer.scheme() != "https" || issuer.host_str().is_none() {
                    return Err("OIDC discovery requires https".into());
                }
                let request = openidconnect::http::Request::builder()
                    .uri(format!(
                        "{}/.well-known/openid-configuration",
                        config
                            .provider_url
                            .strip_suffix('/')
                            .unwrap_or(&config.provider_url)
                    ))
                    .body(Vec::new())
                    .map_err(|e| e.to_string())?;
                let response = self
                    .transport
                    .capped(request)
                    .await
                    .map_err(|e| e.to_string())?;
                if response.status() != 200 {
                    return Err("OIDC discovery failed".into());
                }
                let discovery: Discovery = serde_json::from_slice(response.body())
                    .map_err(|_| "invalid discovery document")?;
                if discovery.issuer != config.provider_url {
                    return Err("discovery issuer mismatch".into());
                }
                // Only the issuer used to be forced to https; the token and key
                // endpoints carry the code, verifier, client secret and the
                // signing keys, so they must be https as well (security fix #530).
                if !crate::mutants::on("rp-http-endpoints")
                    && [&discovery.token_endpoint, &discovery.jwks_uri]
                        .iter()
                        .any(|u| !url::Url::parse(u).is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some()))
                {
                    return Err("OIDC discovery endpoints require https".into());
                }
                let algs = id_token_algs(discovery.id_token_signing_alg_values_supported.as_deref());
                if algs.is_empty() {
                    return Err("OIDC provider advertises no asymmetric ID token algorithm".into());
                }
                Ok::<_, String>(Some(Provider {
                    config,
                    discovery,
                    algs,
                    transport: self.transport.clone(),
                    keys: tokio::sync::Mutex::new(CoreJsonWebKeySet::new(Vec::new())),
                    auth_style: std::sync::atomic::AtomicU8::new(0),
                }))
            }
            .await;
            match load {
                Ok(Some(provider)) => {
                    providers.insert(provider.config.name.clone(), Arc::new(provider));
                }
                Ok(None) => {}
                Err(error) => errors.push(format!("{key}: {error}")),
            }
        }
        *self.providers.write().unwrap() = providers;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}
fn open_secret(raw: &str, master: &[u8]) -> Result<String, String> {
    if raw.is_empty() {
        return Ok(String::new());
    }
    let envelope = decode_secret(raw).ok_or("client secret is not sealed")?;
    String::from_utf8(
        setjoin_config_secret::open_column(&envelope, master)
            .map_err(|_| "client secret decryption failed")?,
    )
    .map_err(|_| "client secret is not UTF-8".into())
}

fn decode_secret(raw: &str) -> Option<Vec<u8>> {
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    let clean = raw.replace(['\r', '\n'], "");
    let unpadded = GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireNone),
    );
    let standard = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    unpadded
        .decode(&clean)
        .or_else(|_| standard.decode(&clean))
        .ok()
}

/// RFC7636 grammar, before any provider lookup or network request (frozen Go).
pub fn valid_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

/// Cryptographically verified provider claims; no user writes accept this type.
/// The callback still owes its flow nonce and email/group validation.
pub struct VerifiedClaims {
    raw: serde_json::Value,
    email_verified: bool,
}
impl VerifiedClaims {
    pub fn nonce_matches(&self, cookie: Option<&str>) -> bool {
        // An empty cookie against a nonce-less token used to agree (security fix #530).
        let claim = self.raw["nonce"].as_str().unwrap_or("");
        crate::mutants::on("rp-empty-nonce") && cookie == Some(claim)
            || cookie.is_some_and(|cookie| !cookie.is_empty() && cookie == claim)
    }
    pub fn email_verified(&self) -> bool {
        self.email_verified
    }
}
fn ignore_nonce(_: Option<&Nonce>) -> Result<(), String> {
    Ok(())
}
fn verify_id_token(
    token: &openidconnect::core::CoreIdToken,
    config: &Config,
    algs: &[openidconnect::core::CoreJwsSigningAlgorithm],
    keys: CoreJsonWebKeySet,
) -> Result<openidconnect::core::CoreIdTokenClaims, openidconnect::ClaimsVerificationError> {
    let verifier = openidconnect::core::CoreIdTokenVerifier::new_public_client(
        ClientId::new(config.client_id.clone()),
        IssuerUrl::new(config.provider_url.clone()).expect("validated issuer"),
        keys,
    );
    let verifier = if crate::mutants::on("rp-alg-unpinned") {
        verifier.allow_any_alg()
    } else {
        verifier.set_allowed_algs(algs.iter().cloned())
    }
    .allow_all_jose_types()
    .set_other_audience_verifier_fn(|_| true)
    .set_time_fn(|| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        chrono::DateTime::from_timestamp(now.as_secs() as i64 + 1, now.subsec_nanos()).unwrap()
    })
    .set_issue_time_verifier_fn(|issued| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        if issued.timestamp() > (now + 1.0).round() as i64 {
            Err("ID token issued in the future".into())
        } else {
            Ok(())
        }
    });
    token.claims(&verifier, ignore_nonce).cloned()
}
impl Provider {
    pub async fn exchange(&self, code: &str, verifier: &str) -> Result<VerifiedClaims, String> {
        use openidconnect::{
            AuthorizationCode, OAuth2TokenResponse, PkceCodeVerifier, TokenResponse,
        };
        if !valid_verifier(verifier) {
            return Err("invalid verifier".into());
        }
        let request = |post: bool| async move {
            let client = self.client(CoreJsonWebKeySet::new(Vec::new()), !post)?;
            client
                .exchange_code(AuthorizationCode::new(code.into()))
                .set_pkce_verifier(PkceCodeVerifier::new(verifier.into()))
                .request_async(&self.transport)
                .await
                .map_err(|_| "OIDC token exchange failed".to_owned())
        };
        let style = self.auth_style.load(std::sync::atomic::Ordering::Relaxed);
        let (tokens, chosen) = match request(style == 2).await {
            Ok(tokens) => (tokens, if style == 2 { 2 } else { 1 }),
            Err(_) if style == 0 => (request(true).await?, 2),
            Err(error) => return Err(error),
        };
        if style == 0 {
            self.auth_style
                .store(chosen, std::sync::atomic::Ordering::Relaxed);
        }
        let token = tokens.id_token().ok_or("missing ID token")?;
        let wire = token.to_string();
        // Parsing here may only reject input. No principal escapes until the
        // unmodified library verifier has checked the original signed bytes.
        let raw: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(wire.split('.').nth(1).ok_or("invalid ID token")?)
                .map_err(|_| "invalid ID token")?,
        )
        .map_err(|_| "invalid ID token")?;
        if raw["iss"].as_str() != Some(self.config.provider_url.as_str()) {
            return Err("invalid ID token issuer".into());
        }
        if raw["sub"].as_str().is_none_or(str::is_empty) {
            return Err("missing ID token subject".into());
        }
        let azp = raw["azp"].as_str().unwrap_or("");
        if (!azp.is_empty() && azp != self.config.client_id)
            || (raw["aud"].as_array().is_some_and(|a| a.len() > 1) && azp.is_empty())
        {
            return Err("invalid authorized party".into());
        }
        let mut keys = self.keys.lock().await;
        let first = verify_id_token(token, &self.config, &self.algs, keys.clone());
        let claims = match first {
            Err(openidconnect::ClaimsVerificationError::SignatureVerification(
                openidconnect::SignatureVerificationError::NoMatchingKey
                | openidconnect::SignatureVerificationError::AmbiguousKeyId(_),
            )) => {
                *keys = CoreJsonWebKeySet::fetch_async(
                    &openidconnect::JsonWebKeySetUrl::new(self.discovery.jwks_uri.clone())
                        .map_err(|_| "invalid JWKS URL")?,
                    &self.transport,
                )
                .await
                .map_err(|_| "OIDC JWKS fetch failed")?;
                verify_id_token(token, &self.config, &self.algs, keys.clone())
                    .map_err(|_| "ID token verification failed")?
            }
            Ok(claims) => claims,
            Err(_) => return Err("ID token verification failed".into()),
        };
        if let Some(expected) = claims
            .access_token_hash()
            .filter(|h| !h.as_str().is_empty())
        {
            use subtle::ConstantTimeEq;
            let verifier = openidconnect::core::CoreIdTokenVerifier::new_public_client(
                ClientId::new(self.config.client_id.clone()),
                IssuerUrl::new(self.config.provider_url.clone()).unwrap(),
                keys.clone(),
            )
            .allow_any_alg()
            .allow_all_jose_types();
            let actual = openidconnect::AccessTokenHash::from_token(
                tokens.access_token(),
                token
                    .signing_alg()
                    .map_err(|_| "invalid signing algorithm")?,
                token
                    .signing_key(&verifier)
                    .map_err(|_| "invalid signing key")?,
            )
            .map_err(|_| "invalid access token hash")?;
            if !bool::from(
                actual
                    .as_str()
                    .as_bytes()
                    .ct_eq(expected.as_str().as_bytes()),
            ) {
                return Err("invalid access token hash".into());
            }
        }
        Ok(VerifiedClaims {
            raw,
            email_verified: claims.email_verified().unwrap_or(false),
        })
    }
}
