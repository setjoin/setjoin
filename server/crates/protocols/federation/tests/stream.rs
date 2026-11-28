//! Handshake and admission behaviour of the dial and accept sides, without a
//! database: identities come from the committed fixture CAs and the reducer
//! calls are stubbed. (Wire parity with the frozen Go listener lives in
//! tests/replay.rs.)
mod common;
use common::*;
use setjoin_federation::{
    db::{BoxFut, FedDb},
    error::FedError,
    flags::Flags,
    log::Logger,
    stream::{accept_stream, dial, listen, AnchorLookup, Bounds, PeerEndpoint, PeerStream},
    trust::Anchor,
    wire::{read_frame, write_frame, Hello},
};
use setjoin_pg::{Param, Row};
use std::{
    sync::{atomic::AtomicBool, Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;

/// Authorizes every peer unless `refuse` is set (BZ203).
struct StubDb {
    refuse: bool,
}
impl FedDb for StubDb {
    fn query<'a>(
        &'a self,
        _sql: &'a str,
        _p: &'a [Param<'a>],
    ) -> BoxFut<'a, Result<Vec<Row>, String>> {
        Box::pin(async move {
            if self.refuse {
                Err("ERROR: refused (SQLSTATE BZ203)".to_string())
            } else {
                Ok(vec![])
            }
        })
    }
}

fn anchor(name: &str) -> Anchor {
    Anchor::from_pem(&ca_pem(name)).unwrap()
}

fn lookup_of(pairs: Vec<(&'static str, &'static str)>) -> AnchorLookup {
    Arc::new(move |domain: String| {
        let found = pairs
            .iter()
            .find(|(d, _)| *d == domain)
            .map(|(_, ca)| anchor(ca));
        Box::pin(async move { Ok(found) })
    })
}

struct Harness {
    addr: std::net::SocketAddr,
    ctx: CancellationToken,
    streams: Arc<Mutex<Vec<Arc<PeerStream>>>>,
    flags: Arc<AtomicBool>,
}

async fn serve(lookup: AnchorLookup, bounds: Bounds, refuse: bool) -> Harness {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let ctx = CancellationToken::new();
    let streams: Arc<Mutex<Vec<Arc<PeerStream>>>> = Default::default();
    let flags = Arc::new(AtomicBool::new(true));
    let sink = streams.clone();
    let c2 = ctx.clone();
    let f2 = flags.clone();
    tokio::spawn(async move {
        let _ = listen(
            c2,
            f2 as Arc<dyn Flags>,
            &ln,
            identity("zulu").server_config().unwrap(),
            lookup,
            Hello::new("zulu.test"),
            Arc::new(StubDb { refuse }),
            "dm".into(),
            bounds,
            Logger::discard(),
            Arc::new(move |s| sink.lock().unwrap().push(Arc::new(s))),
        )
        .await;
    });
    Harness {
        addr,
        ctx,
        streams,
        flags,
    }
}

fn endpoint(addr: std::net::SocketAddr, domain: &str) -> PeerEndpoint {
    PeerEndpoint {
        domain: domain.into(),
        target: "127.0.0.1".into(),
        port: addr.port(),
    }
}

async fn dial_as(
    h: &Harness,
    who: &str,
    domain: &str,
    anchor_ca: &str,
) -> Result<PeerStream, FedError> {
    dial(
        &CancellationToken::new(),
        h.flags.as_ref(),
        &endpoint(h.addr, domain),
        &identity(who),
        anchor(anchor_ca),
        &Hello::new(&format!("{who}.test")),
        Duration::from_secs(5),
    )
    .await
}

async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

fn small_bounds() -> Bounds {
    Bounds {
        handshake_timeout: Duration::from_millis(400),
        hello_read_timeout: Duration::from_millis(400),
        lookup_authorize_timeout: Duration::from_millis(400),
        ..Bounds::default()
    }
}

#[tokio::test]
async fn handshake_happy_path_both_directions() {
    let h = serve(
        lookup_of(vec![("alpha.test", "alpha")]),
        Bounds::default(),
        false,
    )
    .await;
    let s = dial_as(&h, "alpha", "zulu.test", "zulu").await.unwrap();
    assert_eq!(s.domain, "zulu.test");
    assert_eq!(s.hello.from_domain, "zulu.test");
    assert!(eventually(|| h.streams.lock().unwrap().len() == 1).await);
    let srv = h.streams.lock().unwrap()[0].clone();
    assert_eq!(srv.domain, "alpha.test");
    assert_eq!(srv.hello.from_domain, "alpha.test");
    // The established stream carries frames both ways.
    s.write_frame(&setjoin_federation::wire::Frame::new(
        "ack",
        "",
        Some(b"{\"peerSeq\":1}".to_vec()),
    ))
    .await
    .unwrap();
    assert_eq!(srv.read_frame().await.unwrap().kind, "ack");
    h.ctx.cancel();
}

#[tokio::test]
async fn dial_rejects_wrong_trust_anchor() {
    let h = serve(
        lookup_of(vec![("alpha.test", "alpha")]),
        Bounds::default(),
        false,
    )
    .await;
    let e = dial_as(&h, "alpha", "zulu.test", "bravo")
        .await
        .err()
        .unwrap();
    assert!(matches!(e, FedError::AnchorMismatch(_)), "{e}");
    h.ctx.cancel();
}

#[tokio::test]
async fn dial_rejects_server_san_mismatch() {
    let h = serve(
        lookup_of(vec![("alpha.test", "alpha")]),
        Bounds::default(),
        false,
    )
    .await;
    let e = dial_as(&h, "alpha", "bravo.test", "zulu")
        .await
        .err()
        .unwrap();
    assert!(matches!(e, FedError::DomainMismatch(_)), "{e}");
    h.ctx.cancel();
}

#[tokio::test]
async fn listen_rejects_client_under_wrong_anchor_and_unknown_peer() {
    // alpha's row pins bravo's CA: alpha's genuine cert must not validate.
    let h = serve(
        lookup_of(vec![("alpha.test", "bravo")]),
        Bounds::default(),
        false,
    )
    .await;
    let r = dial_as(&h, "alpha", "zulu.test", "zulu").await;
    assert!(r.is_err());
    // No row at all.
    let r = dial_as(&h, "bravo", "zulu.test", "zulu").await;
    assert!(r.is_err());
    assert!(h.streams.lock().unwrap().is_empty());
    h.ctx.cancel();
}

#[tokio::test]
async fn listen_refuses_locally_unauthorized_peer() {
    let h = serve(
        lookup_of(vec![("alpha.test", "alpha")]),
        Bounds::default(),
        true,
    )
    .await;
    assert!(dial_as(&h, "alpha", "zulu.test", "zulu").await.is_err());
    assert!(h.streams.lock().unwrap().is_empty());
    h.ctx.cancel();
}

#[tokio::test]
async fn disabled_feature_is_a_noop_for_dial_and_listen() {
    let h = serve(lookup_of(vec![]), Bounds::default(), false).await;
    h.flags.store(false, std::sync::atomic::Ordering::Relaxed);
    let e = dial_as(&h, "alpha", "zulu.test", "zulu")
        .await
        .err()
        .unwrap();
    assert_eq!(e, FedError::Disabled);
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let r = listen(
        CancellationToken::new(),
        h.flags.clone() as Arc<dyn Flags>,
        &ln,
        identity("zulu").server_config().unwrap(),
        lookup_of(vec![]),
        Hello::new("zulu.test"),
        Arc::new(StubDb { refuse: false }),
        "dm".into(),
        Bounds::default(),
        Logger::discard(),
        Arc::new(|_| {}),
    )
    .await;
    assert_eq!(r.err().unwrap(), FedError::Disabled);
    h.ctx.cancel();
}

/// True when the server closes the connection within `within`.
async fn closed_by_server(c: &mut TcpStream, within: Duration) -> bool {
    let mut b = [0u8; 1];
    matches!(
        tokio::time::timeout(within, c.read(&mut b)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

#[tokio::test]
async fn slowloris_is_dropped_by_the_handshake_deadline_without_starving() {
    let h = serve(
        lookup_of(vec![("alpha.test", "alpha")]),
        small_bounds(),
        false,
    )
    .await;
    let mut stalled = TcpStream::connect(h.addr).await.unwrap();
    assert!(closed_by_server(&mut stalled, Duration::from_secs(3)).await);
    assert!(dial_as(&h, "alpha", "zulu.test", "zulu").await.is_ok());
    h.ctx.cancel();
}

#[tokio::test]
async fn handshake_bound_drops_excess_and_recovers() {
    let mut b = small_bounds();
    b.max_in_flight_handshakes = 2;
    b.handshake_timeout = Duration::from_millis(1500);
    let h = serve(lookup_of(vec![("alpha.test", "alpha")]), b, false).await;
    let mut a = TcpStream::connect(h.addr).await.unwrap();
    let mut c = TcpStream::connect(h.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut excess = TcpStream::connect(h.addr).await.unwrap();
    assert!(
        closed_by_server(&mut excess, Duration::from_millis(800)).await,
        "excess must be closed at accept"
    );
    assert!(closed_by_server(&mut a, Duration::from_secs(4)).await);
    assert!(closed_by_server(&mut c, Duration::from_secs(4)).await);
    assert!(
        dial_as(&h, "alpha", "zulu.test", "zulu").await.is_ok(),
        "admission recovers"
    );
    h.ctx.cancel();
}

#[tokio::test]
async fn concurrent_stream_bound_tracks_stream_lifetime() {
    let b = Bounds {
        max_concurrent_streams: 1,
        ..Bounds::default()
    };
    let h = serve(lookup_of(vec![("alpha.test", "alpha")]), b, false).await;
    let first = dial_as(&h, "alpha", "zulu.test", "zulu").await.unwrap();
    assert!(eventually(|| h.streams.lock().unwrap().len() == 1).await);
    // The only slot is held by the live stream: the next connection is dropped.
    assert!(dial_as(&h, "alpha", "zulu.test", "zulu").await.is_err());
    // Closing the server-side stream frees the slot.
    h.streams.lock().unwrap()[0].close();
    drop(first);
    let mut ok = false;
    for _ in 0..40 {
        if dial_as(&h, "alpha", "zulu.test", "zulu").await.is_ok() {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ok, "slot must free when the stream closes");
    h.ctx.cancel();
}

#[tokio::test]
async fn stalled_lookup_is_dropped_by_the_deadline_and_admission_recovers() {
    let stall = Arc::new(AtomicBool::new(true));
    let s2 = stall.clone();
    let lookup: AnchorLookup = Arc::new(move |domain: String| {
        let stall = s2.clone();
        Box::pin(async move {
            if stall.load(std::sync::atomic::Ordering::Relaxed) {
                std::future::pending::<()>().await;
            }
            Ok((domain == "alpha.test").then(|| anchor("alpha")))
        })
    });
    let mut b = small_bounds();
    b.max_in_flight_handshakes = 1;
    let h = serve(lookup, b, false).await;
    let started = std::time::Instant::now();
    assert!(dial_as(&h, "alpha", "zulu.test", "zulu").await.is_err());
    assert!(started.elapsed() < Duration::from_secs(5));
    stall.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(dial_as(&h, "alpha", "zulu.test", "zulu").await.is_ok());
    h.ctx.cancel();
}

#[tokio::test]
async fn dial_side_hello_with_wrong_domain_is_a_mismatch() {
    // A raw peer that completes TLS with zulu's identity but answers hello as someone else.
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let cfg = identity("zulu").server_config().unwrap();
    tokio::spawn(async move {
        let (s, _) = ln.accept().await.unwrap();
        let mut t = tokio_rustls::TlsAcceptor::from(cfg)
            .accept(s)
            .await
            .unwrap();
        let _ = read_frame(&mut t).await;
        let _ = write_frame(&mut t, &Hello::new("mallory.test").frame()).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let flags = AtomicBool::new(true);
    let e = dial(
        &CancellationToken::new(),
        &flags,
        &endpoint(addr, "zulu.test"),
        &identity("alpha"),
        anchor("zulu"),
        &Hello::new("alpha.test"),
        Duration::from_secs(5),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(e, FedError::DomainMismatch(_)), "{e}");
    let _ = accept_stream; // the accept half is exercised through listen above
}
