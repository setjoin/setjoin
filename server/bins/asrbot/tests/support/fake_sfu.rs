//! A LiveKit SFU peripheral for hermetic bot tests: speaks signalling protocol
//! 17 over `/rtc`, offers a subscriber peer connection carrying one Opus
//! "speaker" track, answers the bot's publisher offer, and records everything
//! the bot sends (upgrade request, signal requests, data-channel packets).

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use livekit_protocol as lk;
use livekit_protocol::signal_request::Message as Req;
use livekit_protocol::signal_response::Message as Resp;
use prost::Message as _;
use rtc::media_stream::MediaStreamTrack;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::Message;
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::media_stream::track_local::static_rtp::TrackLocalStaticRTP;
use webrtc::media_stream::track_local::TrackLocal;
use webrtc::peer_connection::{
    register_default_interceptors, MediaEngine, PeerConnection, PeerConnectionBuilder,
    PeerConnectionEventHandler, RTCConfigurationBuilder, RTCIceCandidateInit,
    RTCPeerConnectionIceEvent, RTCPeerConnectionState, RTCSessionDescription, Registry,
    SettingEngineBuilder,
};

pub const SPEAKER_IDENTITY: &str = "alice";
pub const SPEAKER_PARTICIPANT_SID: &str = "PA_alice";
pub const SPEAKER_TRACK_SID: &str = "TR_alice_mic";
pub const BOT_IDENTITY: &str = "cc:meeting-1";

#[derive(Debug, Clone, PartialEq)]
pub enum SignalObs {
    Offer(String),
    Answer(String),
    Trickle {
        target: i32,
    },
    Leave {
        reason: i32,
        action: i32,
        can_reconnect: bool,
    },
    Other(String),
}

#[derive(Debug, Clone, Default)]
pub struct Upgrade {
    pub path_and_query: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DataObs {
    pub channel: String,
    /// The decoded `DataPacket`: (has user packet, payload, topic, kind field, sequence).
    pub payload: Vec<u8>,
    pub kind: i32,
    pub sequence: u32,
    pub topic: Option<String>,
    pub destinations: usize,
}

#[derive(Debug, Clone, Default)]
pub struct DcObs {
    pub label: String,
    pub ordered: bool,
    pub max_retransmits: Option<u16>,
}

#[derive(Default)]
pub struct Observed {
    pub upgrade: Option<Upgrade>,
    pub signals: Vec<SignalObs>,
    pub data: Vec<DataObs>,
    pub channels: Vec<DcObs>,
    pub subscriber_connected: bool,
    pub publisher_connected: bool,
    pub left: bool,
}

pub struct FakeSfu {
    pub addr: SocketAddr,
    pub observed: Arc<Mutex<Observed>>,
}

#[derive(Clone)]
pub struct SfuOptions {
    /// Where the SFU's peer connections bind (the bot must be able to reach it).
    pub udp_bind: String,
    /// Speech frames (20 ms) sent, then this many silence frames.
    pub speech_frames: usize,
    pub silence_frames: usize,
    /// Send a plain `Leave` (disconnect) after the audio, if set.
    pub leave_after_audio: bool,
    /// Send the speaker's track before announcing the participant (late participant info).
    pub late_participant_info: bool,
}

impl Default for SfuOptions {
    fn default() -> Self {
        Self {
            udp_bind: "127.0.0.1:0".into(),
            speech_frames: 40,
            silence_frames: 60,
            leave_after_audio: false,
            late_participant_info: false,
        }
    }
}

impl FakeSfu {
    pub async fn start(options: SfuOptions) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind sfu");
        let addr = listener.local_addr().expect("addr");
        let observed = Arc::new(Mutex::new(Observed::default()));
        let shared = observed.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (shared, options) = (shared.clone(), options.clone());
                tokio::spawn(async move { serve_connection(stream, shared, options).await });
            }
        });
        Self { addr, observed }
    }

    pub fn url(&self) -> String {
        format!("ws://{}", self.addr)
    }
}

enum Event {
    Candidate(bool, RTCIceCandidateInit),
    State(bool, RTCPeerConnectionState),
    DataChannel(Arc<dyn DataChannel>),
}

struct Handler {
    subscriber: bool,
    tx: mpsc::UnboundedSender<Event>,
}

#[async_trait]
impl PeerConnectionEventHandler for Handler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        if let Ok(init) = event.candidate.to_json() {
            let _ = self.tx.send(Event::Candidate(self.subscriber, init));
        }
    }
    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        let _ = self.tx.send(Event::State(self.subscriber, state));
    }
    async fn on_data_channel(&self, data_channel: Arc<dyn DataChannel>) {
        let _ = self.tx.send(Event::DataChannel(data_channel));
    }
}

async fn build_pc(
    subscriber: bool,
    tx: mpsc::UnboundedSender<Event>,
    bind: &str,
) -> Arc<dyn PeerConnection> {
    let mut media = MediaEngine::default();
    media.register_default_codecs().expect("codecs");
    let registry =
        register_default_interceptors(Registry::new(), &mut media).expect("interceptors");
    let setting = SettingEngineBuilder::new()
        .with_include_loopback_candidate(true)
        .build();
    let pc = PeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_media_engine(media)
        .with_setting_engine(setting)
        .with_interceptor_registry(registry)
        .with_handler(Arc::new(Handler { subscriber, tx }))
        .with_udp_addrs(vec![bind.to_owned()])
        .build()
        .await
        .expect("sfu pc");
    Arc::new(pc)
}

fn desc(kind: &str, sdp: String) -> lk::SessionDescription {
    lk::SessionDescription {
        r#type: kind.into(),
        sdp,
        id: 0,
        mid_to_track_id: Default::default(),
    }
}

fn signal(message: Resp) -> Message {
    Message::binary(
        lk::SignalResponse {
            message: Some(message),
        }
        .encode_to_vec(),
    )
}

fn participant(sid: &str, identity: &str, tracks: Vec<lk::TrackInfo>) -> lk::ParticipantInfo {
    lk::ParticipantInfo {
        sid: sid.into(),
        identity: identity.into(),
        state: lk::participant_info::State::Active as i32,
        tracks,
        ..Default::default()
    }
}

async fn serve_connection(
    stream: tokio::net::TcpStream,
    shared: Arc<Mutex<Observed>>,
    options: SfuOptions,
) {
    let capture = shared.clone();
    let callback = move |request: &Request, response: Response| {
        let headers = request
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
            .collect();
        capture.lock().unwrap().upgrade = Some(Upgrade {
            path_and_query: request
                .uri()
                .path_and_query()
                .map(|p| p.as_str().to_owned())
                .unwrap_or_default(),
            headers,
        });
        Ok(response)
    };
    let Ok(ws) = tokio_tungstenite::accept_hdr_async(stream, callback).await else {
        return;
    };
    let (mut sink, mut stream) = ws.split();

    let (tx, mut rx) = mpsc::unbounded_channel();
    let subscriber = build_pc(true, tx.clone(), &options.udp_bind).await;
    let publisher = build_pc(false, tx, &options.udp_bind).await;

    // The speaker's Opus track rides the subscriber peer connection.
    let ssrc = 0x5eed_0001u32;
    let track = Arc::new(TrackLocalStaticRTP::new(MediaStreamTrack::new(
        format!("{SPEAKER_PARTICIPANT_SID}|{SPEAKER_TRACK_SID}"),
        SPEAKER_TRACK_SID.into(),
        "mic".into(),
        RtpCodecKind::Audio,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type: "audio/opus".into(),
                clock_rate: 48000,
                channels: 2,
                sdp_fmtp_line: "minptime=10;useinbandfec=1".into(),
                rtcp_feedback: vec![],
            },
            ..Default::default()
        }],
    )));
    subscriber
        .add_track(track.clone() as Arc<dyn TrackLocal>)
        .await
        .expect("add track");

    let speaker = participant(
        SPEAKER_PARTICIPANT_SID,
        SPEAKER_IDENTITY,
        vec![lk::TrackInfo {
            sid: SPEAKER_TRACK_SID.into(),
            r#type: lk::TrackType::Audio as i32,
            ..Default::default()
        }],
    );
    let join = lk::JoinResponse {
        room: Some(lk::Room {
            sid: "RM_test".into(),
            name: "meeting-1".into(),
            ..Default::default()
        }),
        participant: Some(participant("PA_bot", BOT_IDENTITY, vec![])),
        other_participants: if options.late_participant_info {
            vec![]
        } else {
            vec![speaker.clone()]
        },
        server_version: "fake".into(),
        subscriber_primary: true,
        ..Default::default()
    };
    if sink.send(signal(Resp::Join(join))).await.is_err() {
        return;
    }
    let offer = subscriber.create_offer(None).await.expect("offer");
    subscriber
        .set_local_description(offer)
        .await
        .expect("set local");
    let local = subscriber.local_description().await.expect("local");
    let _ = sink
        .send(signal(Resp::Offer(desc("offer", local.sdp))))
        .await;
    if options.late_participant_info {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = sink
            .send(signal(Resp::Update(lk::ParticipantUpdate {
                participants: vec![speaker],
            })))
            .await;
    }

    let mut audio_started = false;
    let (leave_tx, mut leave_rx) = mpsc::unbounded_channel::<()>();
    loop {
        tokio::select! {
            Some(()) = leave_rx.recv() => {
                let _ = sink.send(leave_message()).await;
            }
            message = stream.next() => {
                let Some(Ok(message)) = message else { break };
                let Message::Binary(bytes) = message else {
                    if matches!(message, Message::Close(_)) { break; }
                    continue;
                };
                let Ok(request) = lk::SignalRequest::decode(bytes.as_ref()) else { continue };
                match request.message {
                    Some(Req::Offer(offer)) => {
                        shared.lock().unwrap().signals.push(SignalObs::Offer(offer.r#type.clone()));
                        publisher.set_remote_description(RTCSessionDescription::offer(offer.sdp).expect("offer")).await.expect("pub remote");
                        let answer = publisher.create_answer(None).await.expect("answer");
                        publisher.set_local_description(answer).await.expect("pub local");
                        let local = publisher.local_description().await.expect("local");
                        let _ = sink.send(signal(Resp::Answer(desc("answer", local.sdp)))).await;
                    }
                    Some(Req::Answer(answer)) => {
                        shared.lock().unwrap().signals.push(SignalObs::Answer(answer.r#type.clone()));
                        subscriber.set_remote_description(RTCSessionDescription::answer(answer.sdp).expect("answer")).await.expect("sub remote");
                    }
                    Some(Req::Trickle(trickle)) => {
                        shared.lock().unwrap().signals.push(SignalObs::Trickle { target: trickle.target });
                        if let Ok(init) = serde_json::from_str::<RTCIceCandidateInit>(&trickle.candidate_init) {
                            let pc = if trickle.target == lk::SignalTarget::Publisher as i32 { &publisher } else { &subscriber };
                            let _ = pc.add_ice_candidate(init).await;
                        }
                    }
                    Some(Req::Leave(leave)) => {
                        let mut o = shared.lock().unwrap();
                        o.signals.push(SignalObs::Leave { reason: leave.reason, action: leave.action, can_reconnect: leave.can_reconnect });
                        o.left = true;
                        break;
                    }
                    other => shared.lock().unwrap().signals.push(SignalObs::Other(format!("{other:?}").chars().take(40).collect())),
                }
            }
            event = rx.recv() => {
                match event {
                    Some(Event::Candidate(is_subscriber, init)) => {
                        let target = if is_subscriber { lk::SignalTarget::Subscriber } else { lk::SignalTarget::Publisher } as i32;
                        let trickle = lk::TrickleRequest { candidate_init: serde_json::to_string(&init).unwrap(), target, r#final: false };
                        let _ = sink.send(signal(Resp::Trickle(trickle))).await;
                    }
                    Some(Event::State(is_subscriber, state)) => {
                        let connected = state == RTCPeerConnectionState::Connected;
                        {
                            let mut o = shared.lock().unwrap();
                            if is_subscriber { o.subscriber_connected = connected } else { o.publisher_connected = connected }
                        }
                        if is_subscriber && connected && !audio_started {
                            audio_started = true;
                            let (track, options, shared, leave_tx) = (track.clone(), options.clone(), shared.clone(), leave_tx.clone());
                            tokio::spawn(async move {
                                let leave = options.leave_after_audio;
                                send_audio(track, ssrc, options, shared).await;
                                if leave {
                                    tokio::time::sleep(Duration::from_millis(800)).await;
                                    let _ = leave_tx.send(());
                                }
                            });
                        }
                    }
                    Some(Event::DataChannel(dc)) => {
                        let shared = shared.clone();
                        tokio::spawn(async move { capture_channel(dc, shared).await });
                    }
                    None => break,
                }
            }
        }
    }
    let _ = publisher.close().await;
    let _ = subscriber.close().await;
}

async fn capture_channel(dc: Arc<dyn DataChannel>, shared: Arc<Mutex<Observed>>) {
    let label = dc.label().await.unwrap_or_default();
    let obs = DcObs {
        label: label.clone(),
        ordered: dc.ordered().await.unwrap_or(true),
        max_retransmits: dc.max_retransmits().await.ok().flatten(),
    };
    shared.lock().unwrap().channels.push(obs);
    while let Some(event) = dc.poll().await {
        if let DataChannelEvent::OnMessage(message) = event {
            if let Ok(packet) = lk::DataPacket::decode(message.data.as_ref()) {
                let (payload, topic) = match packet.value {
                    Some(lk::data_packet::Value::User(user)) => (user.payload, user.topic),
                    _ => (Vec::new(), None),
                };
                shared.lock().unwrap().data.push(DataObs {
                    channel: label.clone(),
                    payload,
                    #[allow(deprecated)]
                    kind: packet.kind,
                    sequence: packet.sequence,
                    topic,
                    destinations: packet.destination_identities.len(),
                });
            }
        }
    }
}

/// Opus-encode a 440 Hz tone (speech) or digital silence, one 20 ms frame at 48 kHz mono.
pub fn opus_frames(speech_frames: usize, silence_frames: usize) -> Vec<Vec<u8>> {
    use unsafe_libopus::{opus_encode, opus_encoder_create, opus_encoder_destroy};
    // SAFETY: plain C-shaped calls with valid pointers and lengths; the encoder is destroyed once.
    unsafe {
        let mut error = 0i32;
        let encoder =
            opus_encoder_create(48000, 1, 2048 /* OPUS_APPLICATION_VOIP */, &mut error);
        assert!(error == 0 && !encoder.is_null(), "opus encoder");
        let mut frames = Vec::new();
        for n in 0..(speech_frames + silence_frames) {
            let pcm: Vec<i16> = (0..960)
                .map(|i| {
                    if n < speech_frames {
                        let t = (n * 960 + i) as f64 / 48000.0;
                        ((t * 440.0 * std::f64::consts::TAU).sin() * 12000.0) as i16
                    } else {
                        0
                    }
                })
                .collect();
            let mut out = vec![0u8; 1500];
            let len = opus_encode(
                encoder,
                pcm.as_ptr(),
                960,
                out.as_mut_ptr(),
                out.len() as i32,
            );
            assert!(len > 0, "opus_encode {len}");
            out.truncate(len as usize);
            frames.push(out);
        }
        opus_encoder_destroy(encoder);
        frames
    }
}

async fn send_audio(
    track: Arc<TrackLocalStaticRTP>,
    ssrc: u32,
    options: SfuOptions,
    shared: Arc<Mutex<Observed>>,
) {
    use rtc::rtp::header::Header;
    use rtc::rtp::packet::Packet;
    let frames = opus_frames(options.speech_frames, options.silence_frames);
    let mut ticker = tokio::time::interval(Duration::from_millis(20));
    for (n, payload) in frames.into_iter().enumerate() {
        ticker.tick().await;
        let packet = Packet {
            header: Header {
                version: 2,
                payload_type: 111,
                sequence_number: n as u16,
                timestamp: (n as u32) * 960,
                ssrc,
                marker: n == 0,
                ..Default::default()
            },
            payload: Bytes::from(payload),
        };
        if track.write_rtp(packet).await.is_err() {
            return;
        }
    }
    let _ = (&shared, BytesMut::new());
}

fn leave_message() -> Message {
    signal(Resp::Leave(lk::LeaveRequest {
        can_reconnect: false,
        reason: lk::DisconnectReason::RoomDeleted as i32,
        action: lk::leave_request::Action::Disconnect as i32,
        regions: None,
    }))
}
