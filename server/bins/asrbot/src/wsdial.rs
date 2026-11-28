//! Outbound WebSocket dial for `ws://` and `wss://` (FunASR and the LiveKit
//! signalling socket). TLS uses the platform roots with the ring provider.

use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::WebSocketStream;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub type Socket = WebSocketStream<Box<dyn Io>>;

/// What Go's `net/http` client adds to every upgrade request. Preserved so the sidecar's
/// outbound requests stay identical to the frozen binary's (server logs keyed on them keep working).
pub const GO_USER_AGENT: &str = "Go-http-client/1.1";

/// `coder/websocket` dials through `http.Client`, which also asks for gzip.
pub const GO_HTTP_HEADERS_WITH_GZIP: [(&str, &str); 2] =
    [("user-agent", GO_USER_AGENT), ("accept-encoding", "gzip")];

/// Go `coder/websocket`'s default read limit.
pub const READ_LIMIT: usize = 32768;

#[derive(Debug)]
pub struct DialError(pub String);

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DialError {}

fn fail<E: std::fmt::Display>(e: E) -> DialError {
    DialError(e.to_string())
}

/// Dial `url`, sending `bearer` as `Authorization: Bearer <token>` when given.
pub async fn dial(
    url: &str,
    headers: &[(&str, &str)],
    read_limit: Option<usize>,
) -> Result<Socket, DialError> {
    let mut request = url.into_client_request().map_err(fail)?;
    for (name, value) in headers {
        request.headers_mut().insert(
            tokio_tungstenite::tungstenite::http::HeaderName::from_bytes(name.as_bytes())
                .map_err(fail)?,
            value.parse().map_err(fail)?,
        );
    }
    let uri = request.uri().clone();
    let tls = match uri.scheme_str() {
        Some("ws") => false,
        Some("wss") => true,
        other => return Err(DialError(format!("unsupported scheme {other:?}"))),
    };
    let host = uri
        .host()
        .ok_or_else(|| DialError("missing host".into()))?
        .trim_matches(['[', ']'])
        .to_owned();
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(fail)?;
    let _ = tcp.set_nodelay(true);
    let stream: Box<dyn Io> = if tls {
        let mut roots = rustls_native_certs::load_native_certs().certs;
        let mut store = tokio_rustls::rustls::RootCertStore::empty();
        for cert in roots.drain(..) {
            let _ = store.add(cert);
        }
        let config = tokio_rustls::rustls::ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(fail)?
        .with_root_certificates(store)
        .with_no_client_auth();
        let name =
            tokio_rustls::rustls::pki_types::ServerName::try_from(host.clone()).map_err(fail)?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
            .map_err(fail)?;
        Box::new(tls)
    } else {
        Box::new(tcp)
    };
    let mut config = WebSocketConfig::default();
    if let Some(limit) = read_limit {
        config = config
            .max_message_size(Some(limit))
            .max_frame_size(Some(limit));
    }
    let (socket, _response) =
        tokio_tungstenite::client_async_with_config(request, stream, Some(config))
            .await
            .map_err(fail)?;
    Ok(socket)
}

/// TLS over `tcp` with the platform roots and the ring provider.
pub async fn tls_connect(host: &str, tcp: TcpStream) -> Result<Box<dyn Io>, DialError> {
    let mut store = tokio_rustls::rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = store.add(cert);
    }
    let config = tokio_rustls::rustls::ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(fail)?
    .with_root_certificates(store)
    .with_no_client_auth();
    let name =
        tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(fail)?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(fail)?;
    Ok(Box::new(tls))
}
