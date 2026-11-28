//! A minimal LiveKit participant: the subscribe-and-publish-data client the
//! captions bot needs (Go uses `server-sdk-go` v2.18.1; this speaks the same
//! signalling protocol 17 in dual peer-connection mode).
//!
//! What it does, in Go's order: dial `/rtc` with the room token, read the
//! `JoinResponse`, build the publisher and subscriber peer connections from its
//! ICE servers, answer the server's subscriber offers, trickle ICE both ways,
//! surface subscribed audio tracks, and publish data packets on the publisher's
//! `_lossy` channel (negotiating the publisher lazily on the first publish when
//! the subscriber is primary). What it does not do: resume/reconnect (a lost
//! signal socket or failed peer connection ends the session), publish media,
//! E2EE, region discovery.

use crate::log::{self, s};
use crate::worker::RtpReader;
use crate::wsdial::{self, Socket};
use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use livekit_protocol as lk;
use livekit_protocol::signal_request::Message as Req;
use livekit_protocol::signal_response::Message as Resp;
use prost::Message as _;
use rtc::data_channel::RTCDataChannelInit;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch, Notify};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::media_stream::track_remote::{TrackRemote, TrackRemoteEvent};
use webrtc::peer_connection::{
    register_default_interceptors, MediaEngine, PeerConnection, PeerConnectionBuilder,
    PeerConnectionEventHandler, RTCConfigurationBuilder, RTCIceCandidateInit, RTCIceServer,
    RTCPeerConnectionIceEvent, RTCPeerConnectionState, RTCSdpType, RTCSessionDescription, Registry,
    SettingEngineBuilder,
};

/// The Go SDK identity this client reproduces on the wire.
pub const SDK_VERSION: &str = "2.18.1";
pub const PROTOCOL: u32 = 17;
/// `ConnectTimeout` of the Go SDK's default join options.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const VALIDATE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct LkError(pub String);

impl std::fmt::Display for LkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LkError {}

fn err<E: std::fmt::Display>(e: E) -> LkError {
    LkError(e.to_string())
}

/// Wiring that tests override; production uses `Options::default()`.
#[derive(Clone)]
pub struct Options {
    /// Local UDP addresses for ICE (`0.0.0.0:0` binds every non-loopback interface).
    pub udp_bind: Vec<String>,
    pub include_loopback: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            udp_bind: vec!["0.0.0.0:0".into()],
            include_loopback: false,
        }
    }
}

#[async_trait]
pub trait RoomEvents: Send + Sync + 'static {
    /// A remote audio track is subscribed and delivering RTP.
    async fn on_track_subscribed(&self, identity: String, track: Box<dyn RtpReader>);
    /// The room ended (server leave, signal loss or peer-connection failure).
    fn on_disconnected(&self);
}

/// `ws[s]://` form of `url` (Go `ToWebsocketURL`).
pub fn to_websocket_url(url: &str) -> String {
    if url.starts_with("http") {
        url.replacen("http", "ws", 1)
    } else {
        url.to_owned()
    }
}

/// `http[s]://` form of `url` (Go `ToHttpURL`).
pub fn to_http_url(url: &str) -> String {
    if url.starts_with("ws") {
        url.replacen("ws", "http", 1)
    } else {
        url.to_owned()
    }
}

/// Go's `ConnectQueryParams` for a fresh join (the odd `&&` is preserved).
pub fn connect_query() -> String {
    format!("version={SDK_VERSION}&protocol={PROTOCOL}&&auto_subscribe=1&sdk=go&os=linux")
}

/// Handle to a joined room.
pub struct Room {
    inner: Arc<Inner>,
}

struct Inner {
    signal: SignalSink,
    publisher: Arc<dyn PeerConnection>,
    subscriber: Arc<dyn PeerConnection>,
    subscriber_primary: bool,
    connected: [Arc<AtomicBool>; 2], // [publisher, subscriber]
    lossy: Arc<dyn DataChannel>,
    lossy_open: watch::Receiver<bool>,
    reliable_open: watch::Receiver<bool>,
    negotiated: AtomicBool,
    negotiate_lock: tokio::sync::Mutex<()>,
    closed: CancellationToken,
    events: Arc<dyn RoomEvents>,
}

type Sink = futures_util::stream::SplitSink<Socket, Message>;

#[derive(Clone)]
struct SignalSink(Arc<tokio::sync::Mutex<Sink>>);

impl SignalSink {
    async fn send(&self, message: Req) -> Result<(), LkError> {
        let request = lk::SignalRequest {
            message: Some(message),
        };
        self.0
            .lock()
            .await
            .send(Message::binary(request.encode_to_vec()))
            .await
            .map_err(err)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Publisher,
    Subscriber,
}

enum PcEvent {
    Candidate(Target, RTCIceCandidateInit),
    State(Target, RTCPeerConnectionState),
    Track(Arc<dyn TrackRemote>),
}

struct Handler {
    target: Target,
    tx: mpsc::UnboundedSender<PcEvent>,
}

#[async_trait]
impl PeerConnectionEventHandler for Handler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        if let Ok(init) = event.candidate.to_json() {
            let _ = self.tx.send(PcEvent::Candidate(self.target, init));
        }
    }
    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        let _ = self.tx.send(PcEvent::State(self.target, state));
    }
    async fn on_track(&self, track: Arc<dyn TrackRemote>) {
        let _ = self.tx.send(PcEvent::Track(track));
    }
}

async fn build_pc(
    ice: &[lk::IceServer],
    target: Target,
    tx: mpsc::UnboundedSender<PcEvent>,
    options: &Options,
) -> Result<Arc<dyn PeerConnection>, LkError> {
    let mut media = MediaEngine::default();
    media.register_default_codecs().map_err(err)?;
    let registry = register_default_interceptors(Registry::new(), &mut media).map_err(err)?;
    let servers: Vec<RTCIceServer> = ice
        .iter()
        .map(|s| RTCIceServer {
            urls: s.urls.clone(),
            username: s.username.clone(),
            credential: s.credential.clone(),
        })
        .collect();
    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(servers)
        .build();
    let setting = SettingEngineBuilder::new()
        .with_include_loopback_candidate(options.include_loopback)
        .build();
    let pc = PeerConnectionBuilder::new()
        .with_configuration(config)
        .with_media_engine(media)
        .with_setting_engine(setting)
        .with_interceptor_registry(registry)
        .with_handler(Arc::new(Handler { target, tx }))
        .with_udp_addrs(options.udp_bind.clone())
        .build()
        .await
        .map_err(err)?;
    Ok(Arc::new(pc))
}

fn decode_signal(message: Message) -> Option<Result<lk::SignalResponse, LkError>> {
    match message {
        Message::Binary(bytes) => Some(lk::SignalResponse::decode(bytes.as_ref()).map_err(err)),
        Message::Text(text) => Some(serde_json::from_str(text.as_str()).map_err(err)),
        _ => None,
    }
}

impl Room {
    /// Join `room_url` with `token`. Everything (dial, join response, peer
    /// connection up) must finish within `CONNECT_TIMEOUT`.
    pub async fn connect(
        room_url: &str,
        token: &str,
        events: Arc<dyn RoomEvents>,
        options: Options,
    ) -> Result<Room, LkError> {
        // A half-built room (sockets, peer connections, the read loop) is torn down on every
        // failure path, including the timeout that drops the join future.
        let started: Arc<Mutex<Option<Arc<Inner>>>> = Arc::new(Mutex::new(None));
        let outcome = tokio::time::timeout(
            CONNECT_TIMEOUT,
            Self::join(room_url, token, events, options, started.clone()),
        )
        .await;
        let failure = match outcome {
            Ok(Ok(room)) => return Ok(room),
            Ok(Err(first)) => first,
            Err(_) => LkError("could not connect: timed out".into()),
        };
        let half_built = started.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(inner) = half_built {
            inner.shutdown().await;
        }
        Err(Self::diagnose(room_url, token, failure).await)
    }

    /// After a failed join Go GETs `/rtc/validate` to say why.
    async fn diagnose(room_url: &str, token: &str, cause: LkError) -> LkError {
        match tokio::time::timeout(VALIDATE_TIMEOUT, validate(room_url, token)).await {
            Ok(Err(verr)) => verr,
            _ => cause,
        }
    }

    async fn join(
        room_url: &str,
        token: &str,
        events: Arc<dyn RoomEvents>,
        options: Options,
        started: Arc<Mutex<Option<Arc<Inner>>>>,
    ) -> Result<Room, LkError> {
        if room_url.is_empty() {
            return Err(LkError("url not provided".into()));
        }
        let url = format!("{}/rtc?{}", to_websocket_url(room_url), connect_query());
        let bearer = format!("Bearer {token}");
        let socket = wsdial::dial(
            &url,
            &[
                ("user-agent", wsdial::GO_USER_AGENT),
                ("authorization", bearer.as_str()),
            ],
            None,
        )
        .await
        .map_err(err)?;
        let (sink, mut stream) = socket.split();
        let signal = SignalSink(Arc::new(tokio::sync::Mutex::new(sink)));

        // The server sends the join response as soon as the socket is up.
        let join = loop {
            let message = stream
                .next()
                .await
                .ok_or_else(|| LkError("signal closed before join".into()))?
                .map_err(err)?;
            if let Some(decoded) = decode_signal(message) {
                break decoded?;
            }
        };
        let Some(Resp::Join(join)) = join.message else {
            return Err(LkError("unexpected first signal message".into()));
        };

        let (pc_tx, pc_rx) = mpsc::unbounded_channel();
        let publisher = build_pc(
            &join.ice_servers,
            Target::Publisher,
            pc_tx.clone(),
            &options,
        )
        .await?;
        let subscriber = build_pc(&join.ice_servers, Target::Subscriber, pc_tx, &options).await?;

        // The lossy channel is created first, then the reliable one, as in Go.
        let lossy = publisher
            .create_data_channel(
                "_lossy",
                Some(RTCDataChannelInit {
                    ordered: false,
                    max_retransmits: Some(1),
                    ..Default::default()
                }),
            )
            .await
            .map_err(err)?;
        let reliable = publisher
            .create_data_channel("_reliable", None)
            .await
            .map_err(err)?;
        let (lossy_open, reliable_open) = (watch_open(lossy.clone()), watch_open(reliable.clone()));

        let closed = CancellationToken::new();
        let inner = Arc::new(Inner {
            signal,
            publisher,
            subscriber,
            subscriber_primary: join.subscriber_primary,
            connected: [
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
            ],
            lossy,
            lossy_open,
            reliable_open,
            negotiated: AtomicBool::new(false),
            negotiate_lock: tokio::sync::Mutex::new(()),
            closed: closed.clone(),
            events,
        });

        let participants = Arc::new(Participants::default());
        for p in &join.other_participants {
            participants.update(p);
        }
        *started.lock().unwrap_or_else(|e| e.into_inner()) = Some(inner.clone());
        tokio::spawn(run_loop(inner.clone(), stream, pc_rx, participants));

        if !join.subscriber_primary || join.fast_publish {
            inner.negotiate().await?;
        }
        inner
            .wait_connected(if join.subscriber_primary { 1 } else { 0 })
            .await?;
        Ok(Room { inner })
    }

    /// Publish one data packet the way `LocalParticipant.PublishDataPacket(UserData(p))` does:
    /// a `User` packet on the lossy channel, no topic, no destinations.
    pub async fn publish_data(&self, payload: &[u8]) -> Result<(), String> {
        let packet = lk::DataPacket {
            value: Some(lk::data_packet::Value::User(lk::UserPacket {
                payload: payload.to_vec(),
                ..Default::default()
            })),
            ..Default::default()
        };
        self.inner
            .ensure_publisher_connected()
            .await
            .map_err(|e| e.0)?;
        self.inner
            .lossy
            .send(BytesMut::from(packet.encode_to_vec().as_slice()))
            .await
            .map_err(|e| e.to_string())
    }

    /// Leave the room (client initiated) and tear everything down.
    pub async fn disconnect(&self) {
        let leave = Req::Leave(lk::LeaveRequest {
            reason: lk::DisconnectReason::ClientInitiated as i32,
            ..Default::default()
        });
        let _ = self.inner.signal.send(leave).await;
        self.inner.shutdown().await;
    }
}

fn watch_open(dc: Arc<dyn DataChannel>) -> watch::Receiver<bool> {
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        while let Some(event) = dc.poll().await {
            match event {
                DataChannelEvent::OnOpen => {
                    let _ = tx.send(true);
                }
                DataChannelEvent::OnClose => {
                    let _ = tx.send(false);
                }
                _ => {}
            }
        }
        let _ = tx.send(false);
    });
    rx
}

impl Inner {
    /// Negotiate the publisher once (nothing is ever added to it afterwards); concurrent
    /// first publishes serialise on the lock and the later ones find it done.
    async fn negotiate(&self) -> Result<(), LkError> {
        let _guard = self.negotiate_lock.lock().await;
        if self.negotiated.load(Ordering::SeqCst) {
            return Ok(());
        }
        let offer = self.publisher.create_offer(None).await.map_err(err)?;
        self.publisher
            .set_local_description(offer.clone())
            .await
            .map_err(err)?;
        let local = self.publisher.local_description().await.unwrap_or(offer);
        self.negotiated.store(true, Ordering::SeqCst);
        self.signal
            .send(Req::Offer(session_description(&local)))
            .await
    }

    async fn wait_connected(&self, which: usize) -> Result<(), LkError> {
        let flag = self.connected[which].clone();
        for _ in 0..500 {
            if flag.load(Ordering::SeqCst) {
                return Ok(());
            }
            if self.closed.is_cancelled() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err(LkError("could not establish peer connection".into()))
    }

    /// Go's `ensurePublisherConnected(true)`.
    async fn ensure_publisher_connected(&self) -> Result<(), LkError> {
        if !self.subscriber_primary {
            return self.wait_connected(0).await;
        }
        let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
        let mut negotiated = false;
        while tokio::time::Instant::now() < deadline && !self.closed.is_cancelled() {
            if self.connected[0].load(Ordering::SeqCst)
                && *self.lossy_open.borrow()
                && *self.reliable_open.borrow()
            {
                return Ok(());
            }
            if !negotiated && !self.negotiated.load(Ordering::SeqCst) {
                negotiated = true;
                self.negotiate().await?;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err(LkError("could not ensure publisher connected".into()))
    }

    async fn shutdown(&self) {
        if self.closed.is_cancelled() {
            return;
        }
        self.closed.cancel();
        let _ = self.signal.0.lock().await.close().await;
        let _ = self.publisher.close().await;
        let _ = self.subscriber.close().await;
    }
}

fn session_description(desc: &RTCSessionDescription) -> lk::SessionDescription {
    let kind = match desc.sdp_type {
        RTCSdpType::Offer => "offer",
        RTCSdpType::Answer => "answer",
        RTCSdpType::Pranswer => "pranswer",
        RTCSdpType::Rollback => "rollback",
        _ => "",
    };
    lk::SessionDescription {
        r#type: kind.into(),
        sdp: desc.sdp.clone(),
        id: 0,
        mid_to_track_id: HashMap::new(),
    }
}

fn trickle(target: Target, init: &RTCIceCandidateInit) -> Req {
    Req::Trickle(lk::TrickleRequest {
        candidate_init: serde_json::to_string(init).unwrap_or_default(),
        target: match target {
            Target::Publisher => lk::SignalTarget::Publisher as i32,
            Target::Subscriber => lk::SignalTarget::Subscriber as i32,
        },
        r#final: false,
    })
}

/// sid -> identity of every other participant, with a wake-up for late tracks.
#[derive(Default)]
struct Participants {
    by_sid: Mutex<HashMap<String, String>>,
    changed: Notify,
}

impl Participants {
    fn update(&self, info: &lk::ParticipantInfo) {
        let mut map = self.by_sid.lock().unwrap_or_else(|e| e.into_inner());
        if info.state == lk::participant_info::State::Disconnected as i32 {
            map.remove(&info.sid);
        } else {
            map.insert(info.sid.clone(), info.identity.clone());
        }
        drop(map);
        self.changed.notify_waiters();
    }

    fn identity(&self, sid: &str) -> Option<String> {
        self.by_sid
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(sid)
            .cloned()
    }
}

/// Pending remote candidates per peer connection until its remote description exists.
#[derive(Default)]
struct Pending {
    publisher: Vec<RTCIceCandidateInit>,
    subscriber: Vec<RTCIceCandidateInit>,
    publisher_ready: bool,
    subscriber_ready: bool,
}

async fn run_loop(
    inner: Arc<Inner>,
    mut stream: futures_util::stream::SplitStream<Socket>,
    mut pc_rx: mpsc::UnboundedReceiver<PcEvent>,
    participants: Arc<Participants>,
) {
    let mut pending = Pending::default();
    let mut server_left = false;
    loop {
        tokio::select! {
            _ = inner.closed.cancelled() => break,
            message = stream.next() => {
                let Some(Ok(message)) = message else { break };
                if matches!(message, Message::Close(_)) {
                    break;
                }
                let Some(Ok(response)) = decode_signal(message) else { continue };
                if handle_signal(&inner, &participants, &mut pending, response).await && !server_left {
                    // The server ended the room. Go keeps the signal socket open so its
                    // own `Disconnect` can still send the client `Leave`; the owner's
                    // `disconnect()` closes it.
                    server_left = true;
                    inner.events.on_disconnected();
                    let _ = inner.publisher.close().await;
                    let _ = inner.subscriber.close().await;
                }
            }
            event = pc_rx.recv() => {
                let Some(event) = event else { break };
                match event {
                    PcEvent::Candidate(target, init) => {
                        let _ = inner.signal.send(trickle(target, &init)).await;
                    }
                    PcEvent::State(target, state) => {
                        let index = usize::from(target == Target::Subscriber);
                        match state {
                            RTCPeerConnectionState::Connected => inner.connected[index].store(true, Ordering::SeqCst),
                            RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                                inner.connected[index].store(false, Ordering::SeqCst);
                                if state == RTCPeerConnectionState::Failed {
                                    break;
                                }
                            }
                            _ => inner.connected[index].store(false, Ordering::SeqCst),
                        }
                    }
                    PcEvent::Track(track) => spawn_track(&inner, &participants, track),
                }
            }
        }
    }
    let was_open = !inner.closed.is_cancelled();
    inner.shutdown().await;
    if was_open && !server_left {
        inner.events.on_disconnected();
    }
}

/// Returns true when the room is over.
async fn handle_signal(
    inner: &Arc<Inner>,
    participants: &Arc<Participants>,
    pending: &mut Pending,
    response: lk::SignalResponse,
) -> bool {
    match response.message {
        Some(Resp::Offer(offer)) => {
            let Ok(desc) = RTCSessionDescription::offer(offer.sdp) else {
                return false;
            };
            if inner.subscriber.set_remote_description(desc).await.is_err() {
                log::warn("subscriber set_remote_description failed", &[]);
                return false;
            }
            pending.subscriber_ready = true;
            for init in pending.subscriber.drain(..) {
                let _ = inner.subscriber.add_ice_candidate(init).await;
            }
            match inner.subscriber.create_answer(None).await {
                Ok(answer) => {
                    if inner
                        .subscriber
                        .set_local_description(answer.clone())
                        .await
                        .is_ok()
                    {
                        let local = inner.subscriber.local_description().await.unwrap_or(answer);
                        let _ = inner
                            .signal
                            .send(Req::Answer(session_description(&local)))
                            .await;
                    }
                }
                Err(e) => log::warn(
                    "subscriber create_answer failed",
                    &[("err", s(e.to_string()))],
                ),
            }
        }
        Some(Resp::Answer(answer)) => {
            let Ok(desc) = RTCSessionDescription::answer(answer.sdp) else {
                return false;
            };
            if inner.publisher.set_remote_description(desc).await.is_ok() {
                pending.publisher_ready = true;
                for init in pending.publisher.drain(..) {
                    let _ = inner.publisher.add_ice_candidate(init).await;
                }
            }
        }
        Some(Resp::Trickle(t)) => {
            let Ok(init) = serde_json::from_str::<RTCIceCandidateInit>(&t.candidate_init) else {
                return false;
            };
            if t.target == lk::SignalTarget::Publisher as i32 {
                if pending.publisher_ready {
                    let _ = inner.publisher.add_ice_candidate(init).await;
                } else {
                    pending.publisher.push(init);
                }
            } else if pending.subscriber_ready {
                let _ = inner.subscriber.add_ice_candidate(init).await;
            } else {
                pending.subscriber.push(init);
            }
        }
        Some(Resp::Update(update)) => {
            for p in &update.participants {
                participants.update(p);
            }
        }
        Some(Resp::Leave(leave)) => {
            // Only a plain disconnect ends the session; Go resumes/reconnects on the other actions.
            let _ = leave;
            return true;
        }
        _ => {}
    }
    false
}

fn spawn_track(inner: &Arc<Inner>, participants: &Arc<Participants>, track: Arc<dyn TrackRemote>) {
    let (inner, participants) = (inner.clone(), participants.clone());
    tokio::spawn(async move {
        if track.kind().await != RtpCodecKind::Audio {
            return;
        }
        let stream_id = track.stream_id().await.to_string();
        let track_id = track.track_id().await.to_string();
        let sid = stream_id.split('|').next().unwrap_or_default().to_owned();
        // A track can arrive before its participant's info: wait for it (Go defers).
        let identity = loop {
            let notified = participants.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(identity) = participants.identity(&sid) {
                break identity;
            }
            tokio::select! {
                _ = notified => {}
                _ = inner.closed.cancelled() => return,
            }
        };
        let (tx, rx) = mpsc::channel::<Vec<u8>>(512);
        let closed = inner.closed.clone();
        let pump = track.clone();
        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    event = pump.poll() => event,
                    _ = closed.cancelled() => None,
                };
                match event {
                    Some(TrackRemoteEvent::OnRtpPacket(packet)) => {
                        // A full queue drops the packet: media never back-pressures the driver.
                        let _ = tx.try_send(packet.payload.to_vec());
                    }
                    Some(_) => {}
                    None => return,
                }
            }
        });
        inner
            .events
            .on_track_subscribed(identity, Box::new(TrackReader { id: track_id, rx }))
            .await;
    });
}

struct TrackReader {
    id: String,
    rx: mpsc::Receiver<Vec<u8>>,
}

#[async_trait]
impl RtpReader for TrackReader {
    fn id(&self) -> String {
        self.id.clone()
    }
    async fn read_rtp(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}

/// Go's `RTCEngine.validate`: GET `/rtc/validate` with the token to explain a failed join.
async fn validate(room_url: &str, token: &str) -> Result<(), LkError> {
    use http_body_util::{BodyExt, Empty};
    let url = format!("{}/rtc/validate?{}", to_http_url(room_url), connect_query());
    let uri: hyper::Uri = url.parse().map_err(err)?;
    let tls = uri.scheme_str() == Some("https");
    let host = uri
        .host()
        .ok_or_else(|| LkError("missing host".into()))?
        .to_owned();
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .map_err(err)?;
    let stream: Box<dyn wsdial::Io> = if tls {
        wsdial::tls_connect(&host, tcp).await.map_err(err)?
    } else {
        Box::new(tcp)
    };
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(err)?;
    tokio::spawn(conn);
    let request = hyper::Request::builder()
        .uri(uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"))
        .header("host", uri.authority().map(|a| a.as_str()).unwrap_or(""))
        .header("user-agent", wsdial::GO_USER_AGENT)
        .header("accept-encoding", "gzip")
        .header("authorization", format!("Bearer {token}"))
        .body(Empty::<bytes::Bytes>::new())
        .map_err(err)?;
    let response = sender.send_request(request).await.map_err(err)?;
    let status = response.status();
    if status == hyper::StatusCode::OK {
        return Ok(());
    }
    let body = response
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let mut text = match status.as_u16() {
        401 => "unauthorized: ".to_owned(),
        404 => "not found".to_owned(),
        503 => "unavailable: ".to_owned(),
        _ => String::new(),
    };
    if status.as_u16() != 404 {
        text.push_str(&String::from_utf8_lossy(&body));
    }
    Err(LkError(text))
}
