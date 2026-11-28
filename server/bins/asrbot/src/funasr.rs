//! The FunASR streaming-ASR WebSocket seam (Go `internal/funasr`).
//!
//! One initial JSON config frame (`2pass` streaming mode), then binary PCM16LE
//! frames, results as JSON on the same connection. A dropped connection emits a
//! degraded result and reconnects after a fixed backoff; it never returns an
//! error to the caller. Closing sends `{"is_speaking":false}` and keeps reading
//! (bounded by `FINAL_DRAIN_GRACE`) for the 2pass final the server flushes
//! about 400 ms later, then closes itself.

use crate::gojson;
use crate::log::{self, s};
use crate::wsdial::{self, Socket};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

pub const RECONNECT_BACKOFF: Duration = Duration::from_millis(500);
pub const FINAL_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// One recognition update. `degraded` is a synthetic marker (no text) emitted
/// when the connection to the runtime drops.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FunResult {
    pub text: String,
    pub is_final: bool,
    pub degraded: bool,
}

/// What a worker holds for one open stream.
pub struct StreamHandle {
    pub sender: StreamSender,
    pub results: mpsc::Receiver<FunResult>,
    pub closer: StreamCloser,
}

#[derive(Clone)]
pub struct StreamSender {
    tx: mpsc::Sender<Vec<u8>>,
    closed: CancellationToken,
    cancel: CancellationToken,
}

impl StreamSender {
    /// Queue PCM; gives up when the stream is closed or its context ends.
    pub async fn send(&self, pcm: Vec<u8>) {
        tokio::select! {
            _ = self.tx.send(pcm) => {}
            _ = self.closed.cancelled() => {}
            _ = self.cancel.cancelled() => {}
        }
    }
}

#[derive(Clone)]
pub struct StreamCloser(CancellationToken);

impl StreamCloser {
    /// Idempotent.
    pub fn close(&self) {
        self.0.cancel();
    }
}

#[async_trait]
pub trait Recognizer: Send + Sync + 'static {
    fn stream(&self, cancel: CancellationToken, sample_rate: i64, wav_name: &str) -> StreamHandle;
}

pub struct Client {
    url: String,
}

impl Client {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
        }
    }
}

#[async_trait]
impl Recognizer for Client {
    fn stream(&self, cancel: CancellationToken, sample_rate: i64, wav_name: &str) -> StreamHandle {
        let (send_tx, send_rx) = mpsc::channel::<Vec<u8>>(32);
        let (results_tx, results_rx) = mpsc::channel::<FunResult>(16);
        let closed = CancellationToken::new();
        let run = Run {
            url: self.url.clone(),
            sample_rate,
            wav_name: wav_name.to_owned(),
            cancel: cancel.clone(),
            closed: closed.clone(),
            results: results_tx,
        };
        let keep_open = send_tx.clone();
        tokio::spawn(async move {
            run.run(send_rx).await;
            drop(keep_open);
        });
        StreamHandle {
            sender: StreamSender {
                tx: send_tx,
                closed: closed.clone(),
                cancel,
            },
            results: results_rx,
            closer: StreamCloser(closed),
        }
    }
}

struct Run {
    url: String,
    sample_rate: i64,
    wav_name: String,
    cancel: CancellationToken,
    closed: CancellationToken,
    results: mpsc::Sender<FunResult>,
}

impl Run {
    async fn run(self, mut send_rx: mpsc::Receiver<Vec<u8>>) {
        loop {
            match wsdial::dial(
                &self.url,
                &wsdial::GO_HTTP_HEADERS_WITH_GZIP,
                Some(wsdial::READ_LIMIT),
            )
            .await
            {
                Err(err) => {
                    log::warn(
                        "funasr dial failed",
                        &[("wav_name", s(&self.wav_name)), ("err", s(err.to_string()))],
                    );
                    if !self.emit_degraded().await || !self.sleep_or_done(RECONNECT_BACKOFF).await {
                        return;
                    }
                }
                Ok(socket) => {
                    if !self.run_session(socket, &mut send_rx).await {
                        return;
                    }
                    if !self.emit_degraded().await || !self.sleep_or_done(RECONNECT_BACKOFF).await {
                        return;
                    }
                }
            }
        }
    }

    /// Drive one live connection; true means reconnect (a genuine drop).
    async fn run_session(&self, socket: Socket, send_rx: &mut mpsc::Receiver<Vec<u8>>) -> bool {
        let (mut sink, mut stream) = socket.split();
        let config = format!(
            "{{\"mode\":\"2pass\",\"chunk_size\":[5,10,5],\"chunk_interval\":10,\"wav_name\":{},\"wav_format\":\"pcm\",\"audio_fs\":{},\"is_speaking\":true}}",
            gojson::encode_string(&self.wav_name),
            self.sample_rate
        );
        if let Err(err) = sink.send(Message::text(config)).await {
            log::warn(
                "funasr config send failed",
                &[("wav_name", s(&self.wav_name)), ("err", s(err.to_string()))],
            );
            return true;
        }

        // The reader keeps forwarding results past a requested close: the 2pass
        // final arrives after close was requested and the consumer drains.
        let (read_end_tx, mut read_end_rx) = mpsc::channel::<String>(1);
        let (results, cancel) = (self.results.clone(), self.cancel.clone());
        let reader = tokio::spawn(async move {
            loop {
                let message = match stream.next().await {
                    Some(Ok(message)) => message,
                    Some(Err(err)) => {
                        let _ = read_end_tx.send(err.to_string()).await;
                        return;
                    }
                    None => {
                        let _ = read_end_tx.send(String::new()).await;
                        return;
                    }
                };
                let Message::Text(text) = message else {
                    if matches!(message, Message::Close(_)) {
                        let _ = read_end_tx.send(String::new()).await;
                        return;
                    }
                    continue;
                };
                let Some(result) = decode_result(text.as_bytes()) else {
                    log::warn("funasr result decode failed", &[]);
                    continue;
                };
                tokio::select! {
                    _ = results.send(result) => {}
                    _ = cancel.cancelled() => return,
                }
            }
        });

        let reconnect = loop {
            tokio::select! {
                Some(pcm) = send_rx.recv() => {
                    if let Err(err) = sink.send(Message::binary(pcm)).await {
                        log::warn("funasr frame send failed", &[("wav_name", s(&self.wav_name)), ("err", s(err.to_string()))]);
                        break true;
                    }
                }
                end = read_end_rx.recv() => {
                    if let Some(err) = end.filter(|e| !e.is_empty()) {
                        log::warn("funasr connection dropped", &[("wav_name", s(&self.wav_name)), ("err", s(err))]);
                    }
                    break true; // a clean remote close is treated as a drop too
                }
                _ = self.closed.cancelled() => {
                    let _ = sink.send(Message::text(r#"{"is_speaking":false}"#)).await;
                    tokio::select! {
                        _ = read_end_rx.recv() => {}
                        _ = self.cancel.cancelled() => {}
                        _ = tokio::time::sleep(FINAL_DRAIN_GRACE) => {}
                    }
                    break false;
                }
                _ = self.cancel.cancelled() => break false,
            }
        };
        let _ = sink
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "".into(),
            })))
            .await;
        reader.abort();
        reconnect
    }

    async fn emit_degraded(&self) -> bool {
        tokio::select! {
            sent = self.results.send(FunResult { degraded: true, ..FunResult::default() }) => sent.is_ok(),
            _ = self.closed.cancelled() => false,
            _ = self.cancel.cancelled() => false,
        }
    }

    async fn sleep_or_done(&self, d: Duration) -> bool {
        tokio::select! {
            _ = tokio::time::sleep(d) => true,
            _ = self.closed.cancelled() => false,
            _ = self.cancel.cancelled() => false,
        }
    }
}

/// FunASR's streaming-result frame as `json.Unmarshal` into `{text, is_final}`
/// reads it: case-insensitive keys, `null` ignored, wrong types drop the frame.
fn decode_result(data: &[u8]) -> Option<FunResult> {
    let value: serde_json::Value = serde_json::from_slice(data).ok()?;
    let object = match value {
        serde_json::Value::Null => return Some(FunResult::default()),
        serde_json::Value::Object(object) => object,
        _ => return None,
    };
    let mut result = FunResult::default();
    for (key, value) in object {
        match (key.to_lowercase().as_str(), value) {
            ("text", serde_json::Value::String(text)) => result.text = text,
            ("is_final", serde_json::Value::Bool(flag)) => result.is_final = flag,
            ("text" | "is_final", serde_json::Value::Null) => {}
            ("text" | "is_final", _) => return None,
            _ => {}
        }
    }
    Some(result)
}

pub type SharedRecognizer = Arc<dyn Recognizer>;

impl StreamSender {
    #[doc(hidden)]
    pub fn for_test(
        tx: mpsc::Sender<Vec<u8>>,
        closed: CancellationToken,
        cancel: CancellationToken,
    ) -> Self {
        Self { tx, closed, cancel }
    }
}

impl StreamCloser {
    #[doc(hidden)]
    pub fn for_test(token: CancellationToken) -> Self {
        Self(token)
    }
}
