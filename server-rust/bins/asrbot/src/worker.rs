//! One subscribed audio track's pipeline and the room-level admission gate
//! (Go `bot/session.go`'s `trackWorker`, `trackAdmission`, heartbeats and
//! `redactToken`). Everything with a branch lives here behind four narrow
//! seams so it is testable with no LiveKit, FunASR or libopus.

use crate::funasr::{FunResult, Recognizer, StreamHandle};
use crate::gojson;
use crate::log::{self, s};
use crate::opus;
use crate::vad::{self, TrackArbiter};
use async_trait::async_trait;
use futures_util::future::BoxFuture;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Energy-VAD tuning: mean absolute int16 amplitude; hangover counted in Opus
/// frames (~20 ms each, so 25 is ~500 ms of grace).
pub const VAD_THRESHOLD: f64 = 500.0;
pub const VAD_HANGOVER_FRAMES: i64 = 25;
/// How long a released slot waits for its result channel before moving on.
pub const RESULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
pub const HB_INTERVAL: Duration = Duration::from_secs(5);
/// Exactly `{"t":"cc","hb":true}`: a reset-only keepalive, never a transcript line.
pub const HB_FRAME_PAYLOAD: &[u8] = br#"{"t":"cc","hb":true}"#;
/// Fixed multiple of the F10 slot cap bounding a room's concurrent track pipelines.
pub const TRACK_ADMISSION_HEADROOM: i64 = 8;

/// The audio-track side of a LiveKit subscription.
#[async_trait]
pub trait RtpReader: Send + 'static {
    fn id(&self) -> String;
    /// The next RTP payload; `None` once the track ended.
    async fn read_rtp(&mut self) -> Option<Vec<u8>>;
}

pub trait PcmDecoder: Send + 'static {
    fn decode(&mut self, payload: &[u8]) -> Result<Vec<i16>, String>;
}

impl PcmDecoder for opus::Decoder {
    fn decode(&mut self, payload: &[u8]) -> Result<Vec<i16>, String> {
        opus::Decoder::decode(self, payload)
    }
}

/// Publishes one data-channel payload.
pub type Publish = Arc<dyn Fn(Vec<u8>) -> BoxFuture<'static, Result<(), String>> + Send + Sync>;

pub fn track_admission_bound(max_active_tracks: i64) -> usize {
    if max_active_tracks <= 0 {
        return TRACK_ADMISSION_HEADROOM as usize;
    }
    (TRACK_ADMISSION_HEADROOM * max_active_tracks) as usize
}

/// The per-room gate applied BEFORE any decoder/task allocation: a refused
/// track costs a log line and nothing else.
pub struct TrackAdmission {
    bound: usize,
    active: Mutex<HashSet<String>>,
}

impl TrackAdmission {
    pub fn new(bound: usize) -> Self {
        Self {
            bound,
            active: Mutex::new(HashSet::new()),
        }
    }

    /// One live pipeline per track, fail-closed.
    pub fn admit(&self, track_id: &str) -> bool {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if active.contains(track_id) || active.len() >= self.bound {
            return false;
        }
        active.insert(track_id.to_owned());
        true
    }

    pub fn release(&self, track_id: &str) {
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(track_id);
    }

    pub fn active_count(&self) -> usize {
        self.active.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// Everything one track needs from its room.
pub struct RoomPipeline {
    pub room: String,
    pub vad: Arc<dyn TrackArbiter>,
    pub recognizer: Arc<dyn Recognizer>,
    pub publish: Publish,
    pub admission: Arc<TrackAdmission>,
    pub new_decoder: Arc<dyn Fn() -> Result<Box<dyn PcmDecoder>, String> + Send + Sync>,
}

impl RoomPipeline {
    /// Audio-track intake: admission first, then the decoder, then the worker task.
    pub fn subscribe_audio_track(
        &self,
        cancel: &CancellationToken,
        identity: &str,
        track: Box<dyn RtpReader>,
    ) {
        let track_id = track.id();
        if !self.admission.admit(&track_id) {
            log::warn(
                "audio track refused at admission",
                &[
                    ("room", s(&self.room)),
                    ("identity", s(identity)),
                    ("track", s(&track_id)),
                    ("active", self.admission.active_count().into()),
                ],
            );
            return;
        }
        let decoder = match (self.new_decoder)() {
            Ok(decoder) => decoder,
            Err(err) => {
                self.admission.release(&track_id);
                log::error(
                    "opus decoder init failed",
                    &[
                        ("room", s(&self.room)),
                        ("identity", s(identity)),
                        ("err", s(err)),
                    ],
                );
                return;
            }
        };
        let admission = self.admission.clone();
        let release_id = track_id.clone();
        let worker = TrackWorker {
            room: self.room.clone(),
            identity: identity.to_owned(),
            decoder,
            vad: self.vad.clone(),
            recognizer: self.recognizer.clone(),
            publish: self.publish.clone(),
            release: Some(Box::new(move || admission.release(&release_id))),
            slot: None,
        };
        let cancel = cancel.clone();
        tokio::spawn(async move { worker.run(cancel, track).await });
    }
}

struct Slot {
    sender: crate::funasr::StreamSender,
    closer: crate::funasr::StreamCloser,
    drain: tokio::task::JoinHandle<()>,
}

/// Owns one subscribed track's full pipeline: continuous RTP read + Opus
/// decode (VAD needs real PCM energy) -> VAD arbiter (F10) -> a FunASR stream
/// opened only while holding a slot -> published `{t:'cc',...}` results.
pub struct TrackWorker {
    pub room: String,
    pub identity: String,
    pub decoder: Box<dyn PcmDecoder>,
    pub vad: Arc<dyn TrackArbiter>,
    pub recognizer: Arc<dyn Recognizer>,
    pub publish: Publish,
    /// Frees the session-level admission slot when the worker exits.
    pub release: Option<Box<dyn FnOnce() + Send>>,
    slot: Option<Slot>,
}

impl TrackWorker {
    pub fn new(
        room: &str,
        identity: &str,
        decoder: Box<dyn PcmDecoder>,
        vad: Arc<dyn TrackArbiter>,
        recognizer: Arc<dyn Recognizer>,
        publish: Publish,
    ) -> Self {
        Self {
            room: room.to_owned(),
            identity: identity.to_owned(),
            decoder,
            vad,
            recognizer,
            publish,
            release: None,
            slot: None,
        }
    }

    pub async fn run(mut self, cancel: CancellationToken, mut track: Box<dyn RtpReader>) {
        let track_id = track.id();
        loop {
            if cancel.is_cancelled() {
                break;
            }
            let payload = tokio::select! {
                payload = track.read_rtp() => payload,
                _ = cancel.cancelled() => None,
            };
            // Track ended: unsubscribed, participant left, or session torn down.
            let Some(payload) = payload else { break };
            let pcm = match self.decoder.decode(&payload) {
                Ok(pcm) => pcm,
                Err(err) => {
                    log::warn(
                        "opus decode failed",
                        &[
                            ("room", s(&self.room)),
                            ("identity", s(&self.identity)),
                            ("err", s(err)),
                        ],
                    );
                    continue;
                }
            };
            let holds = self.vad.update(&track_id, vad::energy(&pcm));
            match (holds, self.slot.is_some()) {
                (true, false) => self.acquire_slot(&cancel, &track_id),
                (false, true) => self.release_slot().await,
                _ => {}
            }
            if let Some(slot) = &self.slot {
                slot.sender.send(opus::pcm16le(&pcm)).await;
            }
        }
        self.release_slot().await;
        self.vad.remove(&track_id);
        if let Some(release) = self.release.take() {
            release();
        }
    }

    fn acquire_slot(&mut self, cancel: &CancellationToken, track_id: &str) {
        let StreamHandle {
            sender,
            results,
            closer,
        } = self
            .recognizer
            .stream(cancel.clone(), i64::from(opus::SAMPLE_RATE), track_id);
        let drain = tokio::spawn(read_results(
            results,
            self.publish.clone(),
            self.room.clone(),
            self.identity.clone(),
            track_id.to_owned(),
        ));
        self.slot = Some(Slot {
            sender,
            closer,
            drain,
        });
    }

    /// Close FunASR and wait for the result channel before another speech
    /// stream can open, so an old utterance's final cannot publish behind the
    /// next one. A timeout degrades with a warning rather than hanging.
    async fn release_slot(&mut self) {
        let Some(slot) = self.slot.take() else { return };
        slot.closer.close();
        let mut drain = slot.drain;
        if tokio::time::timeout(RESULT_DRAIN_TIMEOUT, &mut drain)
            .await
            .is_err()
        {
            log::warn(
                "funasr final drain timed out",
                &[("room", s(&self.room)), ("identity", s(&self.identity))],
            );
        }
    }
}

async fn read_results(
    mut results: tokio::sync::mpsc::Receiver<FunResult>,
    publish: Publish,
    room: String,
    identity: String,
    track_id: String,
) {
    while let Some(result) = results.recv().await {
        if result.degraded {
            log::warn(
                "funasr session degraded, reconnecting",
                &[("room", s(&room)), ("identity", s(&identity))],
            );
            continue;
        }
        if result.text.is_empty() {
            continue;
        }
        let payload = cc_payload(&track_id, &identity, &result.text, result.is_final);
        if let Err(err) = publish(payload.into_bytes()).await {
            log::warn("cc publish failed", &[("room", s(&room)), ("err", s(err))]);
        }
    }
}

/// `{t:'cc', sid, p, text, final}`: the envelope webmail's room store parses.
/// `sid` is the LiveKit track id; `p` the speaking participant's identity.
pub fn cc_payload(sid: &str, identity: &str, text: &str, is_final: bool) -> String {
    format!(
        "{{\"t\":\"cc\",\"sid\":{},\"p\":{},\"text\":{},\"final\":{}}}",
        gojson::encode_string(sid),
        gojson::encode_string(identity),
        gojson::encode_string(text),
        is_final
    )
}

/// Publish `HB_FRAME_PAYLOAD` every `interval` until `cancel` fires.
pub async fn publish_heartbeats(
    cancel: CancellationToken,
    publish: Publish,
    room: String,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = ticker.tick() => {
                if let Err(err) = publish(HB_FRAME_PAYLOAD.to_vec()).await {
                    log::warn("hb publish failed", &[("room", s(&room)), ("err", s(err))]);
                }
            }
        }
    }
}

/// Scrub any base64url JWT (`eyJ...`, up to three dot-joined segments) from `text`:
/// a connect-failure error can stringify the full dial URL, token included.
pub fn redact_token(text: &str) -> String {
    let bytes = text.as_bytes();
    let token_char = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut copied = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"eyJ") && bytes.get(i + 3).is_some_and(|b| token_char(*b)) {
            let mut end = i + 3;
            while bytes.get(end).is_some_and(|b| token_char(*b)) {
                end += 1;
            }
            while bytes.get(end) == Some(&b'.')
                && bytes.get(end + 1).is_some_and(|b| token_char(*b))
            {
                end += 1;
                while bytes.get(end).is_some_and(|b| token_char(*b)) {
                    end += 1;
                }
            }
            out.push_str(&text[copied..i]);
            out.push_str("[redacted]");
            i = end;
            copied = end;
        } else {
            i += 1;
        }
    }
    out.push_str(&text[copied..]);
    out
}

#[cfg(test)]
mod tests;
