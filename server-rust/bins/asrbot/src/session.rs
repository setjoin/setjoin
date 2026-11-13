//! The real `RoomRunner`: one per bot process, connecting each admitted room
//! to its subscribe/decode/ASR/publish pipeline (Go `bot.Sessions`).

use crate::config::Config;
use crate::funasr::{Client, Recognizer};
use crate::livekit::{Options, Room, RoomEvents};
use crate::log::{self, s};
use crate::opus;
use crate::registry::RoomRunner;
use crate::vad::Manager;
use crate::worker::{
    publish_heartbeats, redact_token, track_admission_bound, PcmDecoder, Publish, RoomPipeline,
    RtpReader, TrackAdmission, HB_INTERVAL, VAD_HANGOVER_FRAMES, VAD_THRESHOLD,
};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

pub struct Sessions {
    livekit_url: String,
    max_active_tracks: i64,
    recognizer: Arc<dyn Recognizer>,
    options: Options,
}

impl Sessions {
    pub fn new(cfg: &Config) -> Self {
        Self {
            livekit_url: cfg.livekit_url.clone(),
            max_active_tracks: cfg.max_active_tracks,
            recognizer: Arc::new(Client::new(&cfg.funasr_url)),
            options: Options::default(),
        }
    }

    /// Test seam: a different ICE bind, recognizer or LiveKit URL.
    pub fn with_parts(
        livekit_url: &str,
        max_active_tracks: i64,
        recognizer: Arc<dyn Recognizer>,
        options: Options,
    ) -> Self {
        Self {
            livekit_url: livekit_url.to_owned(),
            max_active_tracks,
            recognizer,
            options,
        }
    }
}

/// Where the room connection stands. A track that was already in the room at join time can be
/// subscribed (and its first caption recognized) before `Room::connect` returns; Go drops that
/// caption (`publisher.publish`), Rust waits for the connect instead (#472: the dropped partial
/// made `room_session` flaky under load).
/// How long a publish waits for the connect. Kept below `RESULT_DRAIN_TIMEOUT`: the stream drain
/// gives up on a result task after that long, and a publish that outlived it could land after
/// the next stream's partials. A connect slower than this loses the early caption, as in Go.
const PUBLISH_CONNECT_WAIT: std::time::Duration = std::time::Duration::from_secs(4);
const _: () = assert!(PUBLISH_CONNECT_WAIT.as_millis() < crate::worker::RESULT_DRAIN_TIMEOUT.as_millis());

#[derive(Clone)]
enum Conn {
    Connecting,
    Up(Arc<Room>),
    Failed,
}

struct Events {
    pipeline: RoomPipeline,
    cancel: CancellationToken,
    disconnected: CancellationToken,
}

#[async_trait]
impl RoomEvents for Events {
    async fn on_track_subscribed(&self, identity: String, track: Box<dyn RtpReader>) {
        self.pipeline
            .subscribe_audio_track(&self.cancel, &identity, track);
    }

    fn on_disconnected(&self) {
        self.disconnected.cancel();
    }
}

#[async_trait]
impl RoomRunner for Sessions {
    /// Blocks until the room disconnects, connection fails, or `cancel` fires.
    async fn run(&self, cancel: CancellationToken, room: String, token: String) {
        if cancel.is_cancelled() {
            return;
        }
        let (slot, watcher) = watch::channel(Conn::Connecting);
        let publish: Publish = Arc::new(move |payload: Vec<u8>| {
            let mut watcher = watcher.clone();
            Box::pin(async move {
                let settled = tokio::time::timeout(
                    PUBLISH_CONNECT_WAIT,
                    async {
                        match watcher.wait_for(|c| !matches!(c, Conn::Connecting)).await {
                            Ok(c) => c.clone(),
                            Err(_) => Conn::Failed,
                        }
                    },
                )
                .await;
                let current = settled.unwrap_or(Conn::Failed);
                match current {
                    Conn::Up(room) => room.publish_data(&payload).await,
                    _ => Err("asrbot: publish before livekit connect completed".to_owned()),
                }
            })
        });
        let disconnected = CancellationToken::new();
        let events = Arc::new(Events {
            pipeline: RoomPipeline {
                room: room.clone(),
                vad: Arc::new(Manager::new(
                    self.max_active_tracks,
                    VAD_THRESHOLD,
                    VAD_HANGOVER_FRAMES,
                )),
                recognizer: self.recognizer.clone(),
                publish: publish.clone(),
                admission: Arc::new(TrackAdmission::new(track_admission_bound(
                    self.max_active_tracks,
                ))),
                new_decoder: Arc::new(|| {
                    opus::Decoder::new().map(|d| Box::new(d) as Box<dyn PcmDecoder>)
                }),
            },
            cancel: cancel.clone(),
            disconnected: disconnected.clone(),
        });

        // Not cancellable, as in Go: a stop that lands during the join leaves the identity
        // admitted until the connect finishes (bounded by `CONNECT_TIMEOUT`), then the room
        // is left at once. The registry's drain contract depends on it.
        let connected =
            Room::connect(&self.livekit_url, &token, events, self.options.clone()).await;
        let lk_room = match connected {
            Ok(room) => Arc::new(room),
            Err(err) => {
                // The error can embed the dial URL, token included: redact, never log it raw.
                log::error(
                    "livekit connect failed",
                    &[
                        ("room", s(&room)),
                        ("err", s(redact_token(&err.to_string()))),
                    ],
                );
                let _ = slot.send(Conn::Failed);
                return;
            }
        };
        let _ = slot.send(Conn::Up(lk_room.clone()));

        // hb keepalive: stops on an explicit stop AND on a natural disconnect.
        let hb_cancel = cancel.child_token();
        tokio::spawn(publish_heartbeats(
            hb_cancel.clone(),
            publish,
            room.clone(),
            HB_INTERVAL,
        ));

        tokio::select! {
            _ = cancel.cancelled() => {}
            _ = disconnected.cancelled() => {}
        }
        hb_cancel.cancel();
        lk_room.disconnect().await;
    }
}
