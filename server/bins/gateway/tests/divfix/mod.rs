//! #468 HTTP transport metadata oracle; ordinary replay never launches Go.
use crate::{common, drain_oracle};
use common::BoxError;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::mail_security::MailSecurityRoute;
use setjoin_gateway::{
    Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio_rustls::rustls::pki_types::CertificateDer;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// The HTTP seam supplies transport metadata, as Go's r.TLS does. A separate TLS
// socket case exercises the production handshake-to-request plumbing.
struct Transport {
    route: MailSecurityRoute<setjoin_gateway::jmap::jwks::Jwks>,
    leaf: Option<setjoin_tls::PeerCertificate>,
}
impl Intercept for Transport {
    fn matches(&self, r: &Request<Body>) -> bool {
        self.route.matches(r)
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        if let Some(leaf) = &self.leaf {
            r.extensions_mut().insert(leaf.clone());
        }
        self.route.handle(r, c)
    }
}
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/mail-security/divfix")
}
fn normalize(mut response: Value, expires: &str) -> Value {
    if !expires.is_empty() {
        if let Some(body) = response["body"].as_str() {
            response["body"] = json!(body.replace(expires, "<expires-at>"));
        }
    }
    response
}
fn certificate(case: &str) -> Result<String, BoxError> {
    Ok(match case {
        "valid" => {
            include_str!("../../../../tests/conformance/mail-security/smime-certs/a.pem").into()
        }
        "expired" => {
            include_str!("../../../../tests/conformance/mail-security/smime-certs/old.pem").into()
        }
        "future" => {
            include_str!("../../../../tests/conformance/mail-security/smime-certs/future.pem")
                .into()
        }
        "none" => String::new(),
        "expiring" | "expires-today" | "valid-31days" => {
            let hours = match case {
                "expiring" => 30 * 24 + 12,
                "expires-today" => 12,
                _ => 31 * 24 + 12,
            };
            let now = SystemTime::now();
            let mut params = rcgen::CertificateParams::new(vec![])?;
            params.not_before = (now - Duration::from_secs(86400)).into();
            params.not_after = (now + Duration::from_secs(hours * 3600)).into();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "DIVFIX <&> client");
            params.self_signed(&rcgen::KeyPair::generate()?)?.pem()
        }
        _ => return Err(format!("unknown certificate status case {case}").into()),
    })
}
struct File(PathBuf);
impl Drop for File {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub async fn status(case: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("divfix-status") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "divfix-status").await?;
    let result = async {
        let pem = certificate(case)?;
        let (leaf, expires) = if pem.is_empty() {
            (None, String::new())
        } else {
            let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes())?;
            let (_, cert) = x509_parser::parse_x509_certificate(&block.contents)?;
            // Go's RFC3339 UTC output has whole seconds and Z, independent of the
            // fixture library's Display formatting.
            let t = cert.validity().not_after.to_datetime();
            let expires = format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", t.year(), u8::from(t.month()), t.day(), t.hour(), t.minute(), t.second());
            (Some(setjoin_tls::PeerCertificate(CertificateDer::from(block.contents))), expires)
        };
        let exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).map_err(|e| e.0)?;
        let worker = ScopedExecutor::from_dsn(&db.dsn, 2).map_err(|e| e.0)?;
        let route = MailSecurityRoute::new(exec, worker, Arc::new(common::recovery_keys()), "mailserver".into());
        let recording = std::env::var_os("GOFREE_RECORD_DIVFIX").is_some();
        let upstream_addr = setjoin_conformance::ports::address();
        let gateway = Gateway::new(Config {
            upstream: recording.then(|| format!("http://{upstream_addr}").parse().unwrap()),
            trusted_proxies: TrustedProxies::default(),
            upstream_header_timeout: Duration::from_secs(30), edge_limit: None,
        }, if recording { RouteTable::proxy_all() } else { RouteTable::proxy_all().with(Transport { route, leaf }) })?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(gateway.serve_until(listener, async { let _ = stopped.await; }));
        let response = if recording {
            let folder = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../test-results/gofree-divfix");
            std::fs::create_dir_all(&folder)?;
            let cert_file = File(folder.join(format!("status-{}.pem", a.user)));
            let result_file = File(folder.join(format!("status-{}.json", a.user)));
            std::fs::write(&cert_file.0, &pem)?;
            let tick = drain_oracle::GoTick {
                package: "cmd/mailserverd", overlay: "divfix_status_test.go.txt", test: "TestGoFreeDIVFIXStatus", file: "gofree_divfix_status_test.go",
                env: vec![
                    ("GOFREE_DIVFIX_UPSTREAM".into(), upstream_addr.to_string()),
                    ("GOFREE_DIVFIX_EDGE".into(), format!("http://{addr}")),
                    ("GOFREE_DIVFIX_CERT".into(), if pem.is_empty() { String::new() } else { format!("/src/test-results/gofree-divfix/status-{}.pem", a.user) }),
                    ("GOFREE_DIVFIX_RESULT".into(), format!("/src/test-results/gofree-divfix/status-{}.json", a.user)),
                ], docker: vec![],
            };
            let result = tokio::task::spawn_blocking(move || tick.run()).await?;
            let _ = stop.send(()); server.await?;
            result?;
            serde_json::from_slice(&std::fs::read(&result_file.0)?)?
        } else {
            let response = common::send(addr, Request::get("/api/user/cert-status")
                .header("authorization", format!("Bearer {}", common::recovery_token(a.user)))
                .body(common::full(""))?).await;
            let status = response.status().as_u16();
            let content_type = response.headers()["content-type"].to_str()?.to_owned();
            let body = String::from_utf8(common::body_bytes(response).await.to_vec())?;
            let _ = stop.send(()); server.await?;
            json!({"status": status, "content_type": content_type, "body": body})
        };
        let response = normalize(response, &expires);
        let observation = json!({"request": {"method": "GET", "path": "/user/cert-status"}, "response": response, "effects": [], "audit": [], "notify": []});
        let path = root().join(format!("status-{case}.json"));
        if recording {
            std::fs::create_dir_all(root())?;
            golden::record(&path, &json!({"format": 1, "route": "GET /user/cert-status", "case": format!("tls-{case}"), "go_source": std::env::var("GOFREE_GO_SOURCE")?, "observation": observation}))?;
        } else {
            let expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
            golden::compare(&expected["observation"], &observation)?;
            eprintln!("GOLDEN-REPLAY: GET /user/cert-status :: tls-{case}");
        }
        Ok::<_, BoxError>(())
    }.await;
    fixture::remove(&owner, &a).await?;
    result
}

/// A real optional-client-auth handshake must supply the leaf to the HTTP route.
pub async fn tls_peer_status(configured: bool) -> Result<(), BoxError> {
    tls_peer_status_with_roots(configured, false).await
}
pub async fn tls_without_client_roots() -> Result<(), BoxError> {
    tls_peer_status_with_roots(true, true).await
}
// Tests run serially. Restore the native-root loader's environment even on error.
struct RootEnvironment(Vec<(&'static str, Option<std::ffi::OsString>)>);
impl RootEnvironment {
    fn empty(folder: &std::path::Path) -> std::io::Result<Self> {
        let file = folder.join("empty-roots.pem");
        let dir = folder.join("empty-roots");
        std::fs::write(&file, "")?;
        std::fs::create_dir(&dir)?;
        let mut saved = Self(Vec::new());
        for (name, value) in [("SSL_CERT_FILE", file), ("SSL_CERT_DIR", dir)] {
            saved.0.push((name, std::env::var_os(name)));
            std::env::set_var(name, value);
        }
        Ok(saved)
    }
}
impl Drop for RootEnvironment {
    fn drop(&mut self) {
        for (key, value) in self.0.drain(..) {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}
async fn tls_peer_status_with_roots(configured: bool, empty_roots: bool) -> Result<(), BoxError> {
    use http_body_util::BodyExt;
    use hyper_util::rt::TokioIo;
    use tokio_rustls::rustls::{
        self,
        pki_types::{PrivatePkcs8KeyDer, ServerName},
    };
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("divfix-tls-peer") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "divfix-tls-peer").await?;
    let folder = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../test-results/gofree-divfix")
        .join(format!("tls-{}", a.user));
    std::fs::create_dir_all(&folder)?;
    let prior = if configured {
        owner.query_opt("SELECT enabled,config_json::text,updated_at::text FROM auth_methods WHERE slug='certificate'", &[]).await?
    } else {
        None
    };
    let result = async {
        let key = rcgen::KeyPair::generate()?;
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()])?;
        params.distinguished_name.push(rcgen::DnType::CommonName, "DIVFIX TLS client");
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth, rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.self_signed(&key)?;
        std::fs::write(folder.join("cert.pem"), cert.pem())?;
        std::fs::write(folder.join("key.pem"), key.serialize_pem())?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone())?;
        let verifier = if configured {
            let config = json!({"ca_bundle_path": folder.join(if empty_roots { "missing-ca.pem" } else { "cert.pem" }), "crl_paths": []}).to_string();
            owner.execute("INSERT INTO auth_methods(slug,name,enabled,config_json) VALUES('certificate','DIVFIX test',true,$1::text::jsonb) ON CONFLICT(slug) DO UPDATE SET enabled=true,config_json=excluded.config_json", &[&config]).await?;
            let exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).map_err(|e| e.0)?;
            let _environment = if empty_roots { Some(RootEnvironment::empty(&folder)?) } else { None };
            setjoin_gateway::tls_runtime::client_verifier(Some(&exec)).await?
        } else {
            rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots.clone()), Arc::new(rustls::crypto::ring::default_provider())).allow_unauthenticated().build()?
        };
        let frontend = setjoin_tls::Frontend::from_env_with_client_verifier(&|name| match name {
            "TLS_CERT_FILE" => Some(folder.join("cert.pem").display().to_string()),
            "TLS_KEY_FILE" => Some(folder.join("key.pem").display().to_string()),
            _ => None,
        }, verifier)?.ok_or("missing TLS frontend")?;
        let exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).map_err(|e| e.0)?;
        let worker = ScopedExecutor::from_dsn(&db.dsn, 2).map_err(|e| e.0)?;
        let route = MailSecurityRoute::new(exec, worker, Arc::new(common::recovery_keys()), "mailserver".into());
        let gateway = Gateway::new(Config { upstream: None, trusted_proxies: TrustedProxies::default(), upstream_header_timeout: Duration::from_secs(30), edge_limit: None }, RouteTable::proxy_all().with(route))?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(gateway.serve_tls_until(listener, frontend, async { let _ = stopped.await; }));
        let result = async {
            for with_cert in if empty_roots { [false, true] } else { [true, false] } {
                let builder = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                    .with_safe_default_protocol_versions()?.with_root_certificates(roots.clone());
                let config = if with_cert {
                    builder.with_client_auth_cert(vec![cert.der().clone()], PrivatePkcs8KeyDer::from(key.serialize_der()).into())?
                } else { builder.with_no_client_auth() };
                let stream = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(ServerName::try_from("localhost")?, tokio::net::TcpStream::connect(addr).await?).await;
                let stream = match stream {
                    Err(_) if empty_roots && with_cert => continue,
                    value => value?,
                };
                let (mut sender, driver) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
                let driver = tokio::spawn(driver);
                let response = sender.send_request(Request::get("/api/user/cert-status")
                    .header("host", "localhost")
                    .header("authorization", format!("Bearer {}", common::recovery_token(a.user)))
                    // Neither this spoof nor proxy identity headers supply TLS metadata.
                    .header("x-ssl-client-cert", "forged client")
                    .header("x-forwarded-client-cert", "forged client")
                    .body(common::full(""))?).await;
                if empty_roots && with_cert {
                    let rejected = response.is_err();
                    drop(sender);
                    let _ = driver.await?;
                    if !rejected { return Err("untrusted peer accepted with an empty root pool".into()) }
                    continue;
                }
                let response = response?;
                if response.status() != 200 { return Err(format!("unexpected TLS HTTP status {}", response.status()).into()); }
                let body = String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
                let parsed: Value = serde_json::from_str(&body)?;
                if with_cert {
                    if parsed["status"] != "valid" || parsed["subject_cn"] != "DIVFIX TLS client" { return Err(format!("peer leaf disappeared: {body}").into()); }
                } else {
                    let expected: Value = serde_json::from_slice(&std::fs::read(root().join("status-none.json"))?)?;
                    if body != expected["observation"]["response"]["body"].as_str().ok_or("no none body")? { return Err(format!("certificate header spoof accepted: {body}").into()); }
                }
                drop(sender);
                driver.await??;
            }
            Ok::<_, BoxError>(())
        }.await;
        let _ = stop.send(());
        server.await?;
        result
    }.await;
    if configured {
        if let Some(row) = prior {
            let enabled: bool = row.get(0);
            let config: String = row.get(1);
            let updated: String = row.get(2);
            owner.execute("UPDATE auth_methods SET enabled=$1,config_json=$2::text::jsonb,updated_at=$3::text::timestamptz WHERE slug='certificate'", &[&enabled,&config,&updated]).await?;
        } else {
            owner
                .execute("DELETE FROM auth_methods WHERE slug='certificate'", &[])
                .await?;
        }
    }
    std::fs::remove_dir_all(&folder)?;
    fixture::remove(&owner, &a).await?;
    result
}
