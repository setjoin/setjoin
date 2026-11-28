//! One mutually certificate-authenticated s2s stream: the dial and accept
//! handshakes, the bounded accept loop, and the stream handle. A stream is a
//! dumb transport; every authority decision is a reducer call elsewhere.

use crate::{
    db::{is_code, BoxFut, FedDb},
    error::FedError,
    flags::Flags,
    log::Logger,
    trust::{verify_against_anchor, Anchor, Identity},
    wire::{self, Frame, Hello, WireError, KIND_HELLO},
};
use setjoin_pg::Type;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{timeout, timeout_at, Instant},
};
use tokio_rustls::{rustls, TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

/// Accept-loop resource bounds (ops tunables; tests shrink them).
#[derive(Clone, Debug)]
pub struct Bounds {
    /// TLS handshake of an inbound connection.
    pub handshake_timeout: Duration,
    /// Post-handshake hello read, plus the outbound hello write.
    pub hello_read_timeout: Duration,
    /// Anchor lookup and `federation_peer_authorize`, by deadline: local
    /// database calls never touch the socket, so a socket deadline would not
    /// bound them.
    pub lookup_authorize_timeout: Duration,
    pub accept_retry_backoff: Duration,
    /// Connections inside the unauthenticated window; excess are closed.
    pub max_in_flight_handshakes: usize,
    /// All live inbound connections, accepted streams included.
    pub max_concurrent_streams: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Bounds {
            handshake_timeout: Duration::from_secs(10),
            hello_read_timeout: Duration::from_secs(10),
            lookup_authorize_timeout: Duration::from_secs(10),
            accept_retry_backoff: Duration::from_millis(100),
            max_in_flight_handshakes: 64,
            max_concurrent_streams: 256,
        }
    }
}

type Reader = Box<dyn AsyncRead + Send + Unpin>;
type Writer = Box<dyn AsyncWrite + Send + Unpin>;

/// A live, authenticated stream to one peer domain.
pub struct PeerStream {
    /// The peer's asserted and verified domain.
    pub domain: String,
    /// The peer's hello frame.
    pub hello: Hello,
    reader: tokio::sync::Mutex<Reader>,
    writer: tokio::sync::Mutex<Writer>,
    closed: CancellationToken,
    slot: Mutex<Option<OwnedSemaphorePermit>>,
}

impl PeerStream {
    pub fn new(
        domain: &str,
        hello: Hello,
        reader: impl AsyncRead + Send + Unpin + 'static,
        writer: impl AsyncWrite + Send + Unpin + 'static,
    ) -> Self {
        PeerStream {
            domain: domain.to_string(),
            hello,
            reader: tokio::sync::Mutex::new(Box::new(reader)),
            writer: tokio::sync::Mutex::new(Box::new(writer)),
            closed: CancellationToken::new(),
            slot: Mutex::new(None),
        }
    }

    fn from_tls<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
        domain: &str,
        hello: Hello,
        s: S,
    ) -> Self {
        let (r, w) = tokio::io::split(s);
        Self::new(domain, hello, r, w)
    }

    /// Single reader only (as in Go): a second concurrent caller waits.
    pub async fn read_frame(&self) -> Result<Frame, WireError> {
        let mut r = self.reader.lock().await;
        tokio::select! {
            _ = self.closed.cancelled() => Err(WireError::Io(std::io::ErrorKind::ConnectionAborted.into())),
            f = wire::read_frame(&mut *r) => f,
        }
    }

    pub async fn write_frame(&self, f: &Frame) -> Result<(), WireError> {
        let mut w = self.writer.lock().await;
        self.write_locked(&mut w, f).await
    }

    async fn write_locked(
        &self,
        w: &mut tokio::sync::MutexGuard<'_, Writer>,
        f: &Frame,
    ) -> Result<(), WireError> {
        if self.closed.is_cancelled() {
            return Err(WireError::Io(std::io::ErrorKind::ConnectionAborted.into()));
        }
        wire::write_frame(&mut **w, f).await
    }

    /// Fire-and-forget write: dropped (Ok(false)) when another writer holds the
    /// stream; bounded by `deadline` while writing (Ok(false) on expiry too).
    pub async fn try_write_frame(&self, f: &Frame, deadline: Duration) -> Result<bool, WireError> {
        let Ok(mut w) = self.writer.try_lock() else {
            return Ok(false);
        };
        match timeout(deadline, self.write_locked(&mut w, f)).await {
            Ok(r) => r.map(|_| true),
            Err(_) => Ok(false),
        }
    }

    /// Close the transport; a blocked reader wakes with an error.
    pub fn close(&self) {
        self.closed.cancel();
        self.slot.lock().unwrap().take();
        if let Ok(mut w) = self.writer.try_lock() {
            let w: &mut Writer = &mut w;
            // Best effort: flush a TLS close_notify if the write side is idle.
            let _ = futures_now_or_never(w.shutdown());
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    fn attach_slot(&self, p: OwnedSemaphorePermit) {
        *self.slot.lock().unwrap() = Some(p);
    }
}

/// Poll a future once, ignoring its output (used for a best-effort shutdown).
fn futures_now_or_never<F: std::future::Future>(f: F) -> Option<F::Output> {
    use std::task::{Context, Poll, Waker};
    let mut f = std::pin::pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// A resolved federation peer endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerEndpoint {
    pub domain: String,
    pub target: String,
    pub port: u16,
}

/// Resolves a peer domain's pinned anchor (a federation_allowlist read).
pub type AnchorLookup =
    Arc<dyn Fn(String) -> BoxFut<'static, Result<Option<Anchor>, FedError>> + Send + Sync>;

async fn read_hello<R: AsyncRead + Unpin>(r: &mut R) -> Result<Hello, FedError> {
    let f = wire::read_frame(r)
        .await
        .map_err(|e| FedError::other(format!("read hello: {e}")))?;
    if f.kind != KIND_HELLO {
        return Err(FedError::other(format!(
            "expected hello frame, got {:?}",
            f.kind
        )));
    }
    Hello::decode(f.payload.as_deref())
        .map_err(|e| FedError::other(format!("unmarshal hello: {e}")))
}

/// `federation_peer_authorize`: the local allow-list and scope gate, run after
/// anchor validation. BZ203 is a refusal; anything else is an infra failure.
pub async fn authorize_peer(
    db: &dyn FedDb,
    peer_domain: &str,
    scope: &str,
) -> Result<(), FedError> {
    match db
        .query(
            "SELECT federation_peer_authorize($1,$2)",
            &[(&peer_domain, Type::TEXT), (&scope, Type::TEXT)],
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(e) if is_code(&e, "BZ203") => Err(FedError::NotAuthorized(format!(
            "{peer_domain} (scope {scope})"
        ))),
        Err(e) => Err(FedError::other(format!(
            "federation: authorize peer {peer_domain}: {e}"
        ))),
    }
}

/// Listen-side handshake: TLS, hello, anchor validation, local authorization,
/// and only then our hello. No non-hello frame can flow before that.
#[allow(clippy::too_many_arguments)]
pub async fn accept_stream(
    conn: TcpStream,
    tls: Arc<rustls::ServerConfig>,
    lookup: &AnchorLookup,
    hello: &Hello,
    db: &dyn FedDb,
    scope: &str,
    bounds: &Bounds,
) -> Result<PeerStream, FedError> {
    let mut tls_conn = timeout(
        bounds.handshake_timeout,
        TlsAcceptor::from(tls).accept(conn),
    )
    .await
    .map_err(|_| FedError::other("federation: listen: TLS handshake: i/o timeout"))?
    .map_err(|e| FedError::other(format!("federation: listen: TLS handshake: {e}")))?;

    let hello_deadline = Instant::now() + bounds.hello_read_timeout;
    let auth_deadline = Instant::now() + bounds.lookup_authorize_timeout;

    let dialer_hello = timeout_at(hello_deadline, read_hello(&mut tls_conn))
        .await
        .map_err(|_| FedError::other("federation: listen: read hello: i/o timeout"))?
        .map_err(|e| FedError::other(format!("federation: listen: {e}")))?;
    let peer = dialer_hello.from_domain.clone();

    let anchor = match timeout_at(auth_deadline, lookup(peer.clone())).await {
        Err(_) => {
            return Err(FedError::other(format!(
                "federation: listen: anchor lookup for {peer}: context deadline exceeded"
            )))
        }
        Ok(Err(e)) => {
            return Err(FedError::other(format!(
                "federation: listen: anchor lookup for {peer}: {e}"
            )))
        }
        Ok(Ok(None)) => {
            return Err(FedError::AnchorMismatch(format!(
                "federation: peer certificate does not chain to the pinned trust anchor: no allow-list row for {peer}"
            )))
        }
        Ok(Ok(Some(a))) => a,
    };

    let certs: Vec<Vec<u8>> = tls_conn
        .get_ref()
        .1
        .peer_certificates()
        .map(|c| c.iter().map(|x| x.as_ref().to_vec()).collect())
        .unwrap_or_default();
    let raw: Vec<&[u8]> = certs.iter().map(Vec::as_slice).collect();
    verify_against_anchor(&raw, &anchor, &peer)?;

    match timeout_at(auth_deadline, authorize_peer(db, &peer, scope)).await {
        Err(_) => {
            return Err(FedError::other(
                "federation: authorize peer: context deadline exceeded",
            ))
        }
        Ok(r) => r?,
    }

    timeout_at(
        hello_deadline,
        wire::write_frame(&mut tls_conn, &hello.frame()),
    )
    .await
    .map_err(|_| FedError::other("federation: listen: send hello: i/o timeout"))?
    .map_err(|e| FedError::other(format!("federation: listen: send hello: {e}")))?;

    Ok(PeerStream::from_tls(&peer, dialer_hello, tls_conn))
}

/// Dial-side handshake. The server leaf is verified against the peer's pinned
/// anchor inside the TLS handshake (never a shared root bundle).
pub async fn dial(
    ctx: &CancellationToken,
    flags: &dyn Flags,
    endpoint: &PeerEndpoint,
    identity: &Identity,
    anchor: Anchor,
    hello: &Hello,
    connect_timeout: Duration,
) -> Result<PeerStream, FedError> {
    if !flags.federation_enabled() {
        return Err(FedError::Disabled);
    }
    let cfg = identity
        .client_config(anchor, &endpoint.domain)
        .map_err(FedError::Other)?;
    let name = rustls_pki_types::ServerName::try_from(endpoint.target.clone())
        .map_err(|e| FedError::other(format!("federation: dial: server name: {e}")))?;
    let connect = async {
        let tcp = TcpStream::connect((endpoint.target.as_str(), endpoint.port)).await?;
        TlsConnector::from(cfg).connect(name, tcp).await
    };
    let mut conn = tokio::select! {
        _ = ctx.cancelled() => return Err(FedError::other("federation: dial: context canceled")),
        r = timeout(connect_timeout, connect) => match r {
            Err(_) => return Err(FedError::other("federation: dial: i/o timeout")),
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return Err(map_tls_error(e)),
        },
    };
    // Go bounds only the TCP+TLS leg; the hello exchange waits for the peer
    // (here it is at least cancellable).
    let exchange = async {
        wire::write_frame(&mut conn, &hello.frame())
            .await
            .map_err(|e| FedError::other(format!("federation: dial: send hello: {e}")))?;
        read_hello(&mut conn)
            .await
            .map_err(|e| FedError::other(format!("federation: dial: {e}")))
    };
    let peer_hello = tokio::select! {
        _ = ctx.cancelled() => return Err(FedError::other("federation: dial: context canceled")),
        r = exchange => r?,
    };
    if peer_hello.from_domain != endpoint.domain {
        return Err(FedError::DomainMismatch(format!(
            "federation: peer domain does not match the asserted/expected identity: expected {}, got {}",
            endpoint.domain, peer_hello.from_domain
        )));
    }
    Ok(PeerStream::from_tls(&endpoint.domain, peer_hello, conn))
}

fn map_tls_error(e: std::io::Error) -> FedError {
    if let Some(rustls::Error::General(m)) =
        e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>())
    {
        if let Some(fe) = FedError::from_wire_tag(m) {
            return fe;
        }
    }
    FedError::Other(e.to_string())
}

fn is_transient_accept_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        Interrupted | WouldBlock | TimedOut | ConnectionAborted
    ) || matches!(e.raw_os_error(), Some(4 | 11 | 103 | 24 | 23))
}

/// Accept s2s connections until `ctx` ends, handshaking each through
/// [`accept_stream`] and handing authenticated, authorized streams to
/// `on_stream`. Rejections are closed and logged; none reaches `on_stream`.
/// Excess connections are dropped at accept, never queued.
#[allow(clippy::too_many_arguments)]
pub async fn listen(
    ctx: CancellationToken,
    flags: Arc<dyn Flags>,
    ln: &TcpListener,
    tls: Arc<rustls::ServerConfig>,
    lookup: AnchorLookup,
    hello: Hello,
    db: Arc<dyn FedDb>,
    scope: String,
    bounds: Bounds,
    log: Logger,
    on_stream: Arc<dyn Fn(PeerStream) + Send + Sync>,
) -> Result<(), FedError> {
    if !flags.federation_enabled() {
        return Err(FedError::Disabled);
    }
    let handshake_slots = Arc::new(Semaphore::new(bounds.max_in_flight_handshakes));
    let conn_slots = Arc::new(Semaphore::new(bounds.max_concurrent_streams));
    loop {
        let accepted: std::io::Result<(TcpStream, SocketAddr)> = tokio::select! {
            _ = ctx.cancelled() => return Ok(()),
            r = ln.accept() => r,
        };
        let conn = match accepted {
            Ok((c, _)) => c,
            Err(e) => {
                if ctx.is_cancelled() {
                    return Ok(());
                }
                if is_transient_accept_error(&e) {
                    log.warn(format!(
                        "federation: transient accept error — retrying: {e}"
                    ));
                    tokio::select! {
                        _ = ctx.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(bounds.accept_retry_backoff) => {}
                    }
                    continue;
                }
                return Err(FedError::other(format!("federation: accept: {e}")));
            }
        };
        let Ok(hs) = handshake_slots.clone().try_acquire_owned() else {
            drop(conn);
            log.warn("federation: in-flight handshake bound reached — dropping connection");
            continue;
        };
        let Ok(cs) = conn_slots.clone().try_acquire_owned() else {
            drop(hs);
            drop(conn);
            log.warn("federation: concurrent connection bound reached — dropping connection");
            continue;
        };
        let (tls, lookup, hello, db, scope, bounds, log, on_stream) = (
            tls.clone(),
            lookup.clone(),
            hello.clone(),
            db.clone(),
            scope.clone(),
            bounds.clone(),
            log.clone(),
            on_stream.clone(),
        );
        tokio::spawn(async move {
            let _hs = hs;
            match accept_stream(conn, tls, &lookup, &hello, db.as_ref(), &scope, &bounds).await {
                Ok(stream) => {
                    stream.attach_slot(cs);
                    on_stream(stream);
                }
                Err(e) => log.warn(format!("federation: inbound stream rejected: {e}")),
            }
        });
    }
}
