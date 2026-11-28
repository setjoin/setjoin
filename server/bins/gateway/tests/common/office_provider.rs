#![allow(dead_code)] // Shared across independent Office HTTP test binaries.
use crate::common::{full, BoxError};
use hyper::{server::conn::http1, service::service_fn, Response};
use hyper_util::rt::TokioIo;
use std::sync::{Arc, Mutex};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    },
    TlsAcceptor,
};
pub struct Provider {
    pub origin: String,
    pub requests: Arc<Mutex<Vec<serde_json::Value>>>,
    pub document: Arc<Mutex<Vec<u8>>>,
    task: tokio::task::JoinHandle<()>,
    previous_ca: Option<std::ffi::OsString>,
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(value) = &self.previous_ca {
            std::env::set_var("SSL_CERT_FILE", value);
        } else {
            std::env::remove_var("SSL_CERT_FILE");
        }
    }
}
pub async fn start() -> Result<Provider, BoxError> {
    start_with_document(include_bytes!(
        "../../../../tests/conformance/office/provider/discovery.xml"
    ))
    .await
}
pub async fn start_with_document(doc: &[u8]) -> Result<Provider, BoxError> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/office/provider");
    let previous_ca = std::env::var_os("SSL_CERT_FILE");
    std::env::set_var("SSL_CERT_FILE", root.join("ca.pem"));
    let certs = CertificateDer::pem_slice_iter(include_bytes!(
        "../../../../tests/conformance/office/provider/cert.pem"
    ))
    .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(include_bytes!(
        "../../../../tests/conformance/office/provider/key.pem"
    ))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let document = Arc::new(Mutex::new(doc.to_vec()));
    let served = document.clone();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
    let port = listener.local_addr()?.port();
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("192.0.2.1:9")?;
    let ip = socket.local_addr()?.ip();
    let host = std::env::var("GOFREE_OFFICE_PROVIDER_HOST")
        .unwrap_or_else(|_| format!("{}.nip.io", ip.to_string().replace('.', "-")));
    let origin = format!("https://{host}:{port}");
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let doc = served.clone();
            let observed = observed.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(move |r: hyper::Request<hyper::body::Incoming>| {
                    let doc = doc.clone();
                    let observed = observed.clone();
                    async move {
                        observed.lock().unwrap().push(serde_json::json!({"method":r.method().as_str(),"path":r.uri().path(),"accept":r.headers().get("accept").and_then(|v|v.to_str().ok()).unwrap_or("")}));
                        let response = if r.uri().path() == "/hosting/discovery" {
                            Response::builder()
                                .header("content-type", "application/xml")
                                .body(full(doc.lock().unwrap().clone()))
                                .unwrap()
                        } else {
                            Response::new(full(""))
                        };
                        Ok::<_, std::convert::Infallible>(response)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Ok(Provider {
        origin,
        requests,
        document,
        task,
        previous_ca,
    })
}
pub fn client(provider: &Provider) -> Result<reqwest::Client, BoxError> {
    let url = reqwest::Url::parse(&provider.origin)?;
    Ok(reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(12))
        .resolve(
            url.host_str().unwrap(),
            std::net::SocketAddr::from(([127, 0, 0, 1], url.port().unwrap())),
        )
        .build()?)
}

pub fn address(provider: &Provider) -> Result<std::net::SocketAddr, BoxError> {
    Ok(std::net::SocketAddr::from((
        [127, 0, 0, 1],
        reqwest::Url::parse(&provider.origin)?
            .port()
            .ok_or("test provider port")?,
    )))
}
