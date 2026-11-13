//! An external HTTPS IdP, with real library signatures and one-time PKCE codes.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Mutex};
pub(super) const ISSUER: &str = "https://idp.idfed2.test:19440";
pub(super) const CLIENT: &str = "setjoin-client-340";
pub(super) const REDIRECT: &str = "https://auth.idfed2.test/auth/oidc/callback";
pub(super) struct State {
    pub calls: Mutex<Vec<Value>>,
    pub codes: Mutex<BTreeMap<String, (String, String, Value)>>,
    /// Test-only overrides merged into the discovery document (#530 fixes).
    pub discovery: Mutex<Value>,
    key: setjoin_identity::oidc::SigningKey,
}
pub(super) struct Idp {
    pub state: Arc<State>,
    server: Server,
}
impl Idp {
    pub async fn start() -> Result<Self, Err> {
        use tokio_rustls::rustls::{
            self,
            pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
        };
        let op = corpus().with_file_name("identity-oidc");
        let state = Arc::new(State {
            calls: Mutex::new(Vec::new()),
            codes: Mutex::new(BTreeMap::new()),
            discovery: Mutex::new(json!({})),
            key: setjoin_identity::oidc::SigningKey::load(
                op.join("op-private.pem").to_str().unwrap(),
                op.join("op-public.pem").to_str().unwrap(),
            )?,
        });
        let certs = CertificateDer::pem_file_iter(corpus().join("idp-cert.pem"))?
            .collect::<Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_file(corpus().join("idp-key.pem"))?;
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
        let tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:19440").await?;
        let addr = listener.local_addr()?;
        let (tx, rx) = oneshot::channel();
        let shared = state.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            tokio::pin!(rx);
            loop {
                tokio::select! {
                    _=&mut rx=>break,
                    accepted=listener.accept()=>{
                        let (stream,_)=accepted.unwrap();let tls=tls.clone();let state=shared.clone();
                        connections.spawn(async move {
                            let Ok(stream)=tls.accept(stream).await else{return};
                            let service=hyper::service::service_fn(move |req:Request<hyper::body::Incoming>|{let state=state.clone();async move{Ok::<_,std::convert::Infallible>(state.handle(req).await)}});
                            let _=hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream),service).await;
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Ok(Self {
            state,
            server: Server {
                stop: Some(tx),
                task,
                addr,
            },
        })
    }
    pub async fn close(self) {
        self.server.close().await;
    }
}
impl State {
    pub fn code(&self, verifier: &str, nonce: &str, claims: Value) -> String {
        let code = format!("code-{}", uuid::Uuid::new_v4());
        self.codes.lock().unwrap().insert(
            code.clone(),
            (
                B64.encode(Sha256::digest(verifier.as_bytes())),
                nonce.into(),
                claims,
            ),
        );
        code
    }
    async fn handle(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> hyper::Response<setjoin_auth::Body> {
        let method = req.method().to_string();
        let path = req.uri().path().to_owned();
        let authorization = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let raw = req.into_body().collect().await.unwrap().to_bytes();
        let mut fields = setjoin_identity::issuance::query(&String::from_utf8_lossy(&raw));
        let reply = match path.as_str() {
            "/.well-known/openid-configuration" => {
                let mut doc=json!({"issuer":ISSUER,"authorization_endpoint":format!("{ISSUER}/authorize"),"token_endpoint":format!("{ISSUER}/token"),"jwks_uri":format!("{ISSUER}/keys"),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"token_endpoint_auth_methods_supported":["client_secret_basic"],"code_challenge_methods_supported":["S256"]});
                for (k,v) in self.discovery.lock().unwrap().as_object().unwrap(){doc[k]=v.clone();}
                doc
            }
            "/keys" => serde_json::from_str(&self.key.jwks()).unwrap(),
            "/token" => {
                let code = fields.get("code").cloned().unwrap_or_default();
                let entry = self.codes.lock().unwrap().remove(&code);
                let out = match entry {
                    Some((challenge, nonce, extra))
                        if fields.get("code_verifier").is_some_and(|v| {
                            B64.encode(Sha256::digest(v.as_bytes())) == challenge
                        }) =>
                    {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        let mut claims = json!({"iss":ISSUER,"sub":"actor-subject","aud":CLIENT,"iat":now,"exp":now+300,"nonce":nonce,"email":"actor@idfed2.test","email_verified":true,"groups":["engineering"]});
                        if let Some(extra) = extra.as_object() {
                            for (k, v) in extra {
                                if !k.starts_with("_oracle_") {
                                    claims[k] = v.clone();
                                }
                            }
                        }
                        let mut token = self.key.sign(&claims).unwrap();
                        if extra["_oracle_bad_signature"] == true {
                            let (prefix, signature) = token.rsplit_once('.').unwrap();
                            let mut signature = B64.decode(signature).unwrap();
                            signature[0] ^= 1;
                            token = format!("{prefix}.{}", B64.encode(signature));
                        }
                        let access=match extra["_oracle_pad"].as_u64(){Some(n)=>"a".repeat(n as usize),None=>"upstream-access".into()};
                        json!({"access_token":access,"token_type":"Bearer","expires_in":300,"id_token":token})
                    }
                    _ => json!({"error":"invalid_grant"}),
                };
                fields
                    .entry("code".into())
                    .and_modify(|v| *v = "_code".into());
                if let Some(verifier) = fields.get_mut("code_verifier") {
                    *verifier = "_verifier".into();
                }
                out
            }
            _ => json!({"error":"not_found"}),
        };
        self.calls
            .lock()
            .unwrap()
            .push(json!({"method":method,"path":path,"authorization":authorization,"form":fields}));
        let status = if reply.get("error").is_some() {
            400
        } else {
            200
        };
        hyper::Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(body(reply.to_string()))
            .unwrap()
    }
}

struct PinnedHttp {
    fixture: reqwest::Client,
    safe: setjoin_identity::rp::SafeHttp,
}
impl setjoin_identity::rp::Http for PinnedHttp {
    fn send(&self, request: hyper::Request<Vec<u8>>) -> setjoin_identity::rp::HttpFuture<'_> {
        if request.uri().host() != Some("idp.idfed2.test") {
            return self.safe.send(request);
        }
        Box::pin(async move {
            let (parts, data) = request.into_parts();
            let response = self
                .fixture
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(data)
                .send()
                .await
                .map_err(std::io::Error::other)?;
            let mut result = hyper::Response::builder().status(response.status());
            *result.headers_mut().unwrap() = response.headers().clone();
            result
                .body(
                    response
                        .bytes()
                        .await
                        .map_err(std::io::Error::other)?
                        .to_vec(),
                )
                .map_err(std::io::Error::other)
        })
    }
}
pub(super) fn http() -> Result<Arc<dyn setjoin_identity::rp::Http>, Err> {
    let ca = reqwest::Certificate::from_pem(&std::fs::read(corpus().join("ca-cert.pem"))?)?;
    Ok(Arc::new(PinnedHttp {
        fixture: reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .resolve("idp.idfed2.test", "127.0.0.1:19440".parse()?)
            .add_root_certificate(ca)
            .build()?,
        safe: setjoin_identity::rp::SafeHttp::new()?,
    }))
}
