use super::*;
use crate::funasr::{StreamCloser, StreamSender};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::mpsc;

struct FakeReader {
    id: String,
    packets: VecDeque<Vec<u8>>,
}

#[async_trait]
impl RtpReader for FakeReader {
    fn id(&self) -> String {
        self.id.clone()
    }
    async fn read_rtp(&mut self) -> Option<Vec<u8>> {
        self.packets.pop_front()
    }
}

fn reader(id: &str, packets: &[&str]) -> Box<FakeReader> {
    Box::new(FakeReader {
        id: id.into(),
        packets: packets.iter().map(|p| p.as_bytes().to_vec()).collect(),
    })
}

struct FakeDecoder {
    failed_payload: &'static str,
    decoded: Arc<AtomicUsize>,
}

impl PcmDecoder for FakeDecoder {
    fn decode(&mut self, payload: &[u8]) -> Result<Vec<i16>, String> {
        if payload == self.failed_payload.as_bytes() {
            return Err("decode failed".into());
        }
        self.decoded.fetch_add(1, Ordering::SeqCst);
        Ok(vec![1000, -1000])
    }
}

struct FakeArbiter {
    holds: Mutex<VecDeque<bool>>,
    removed: Mutex<Vec<String>>,
}

impl FakeArbiter {
    fn new(holds: &[bool]) -> Arc<Self> {
        Arc::new(Self {
            holds: Mutex::new(holds.iter().copied().collect()),
            removed: Mutex::new(Vec::new()),
        })
    }
}

impl TrackArbiter for FakeArbiter {
    fn update(&self, _id: &str, _energy: f64) -> bool {
        self.holds.lock().unwrap().pop_front().unwrap_or(false)
    }
    fn remove(&self, id: &str) {
        self.removed.lock().unwrap().push(id.to_owned());
    }
}

/// A scripted recognizer: each stream replays its queued results and closes
/// its channel when the worker closes the stream.
struct FakeRecognizer {
    scripts: Mutex<VecDeque<Vec<FunResult>>>,
    opened: AtomicUsize,
    sends: Arc<AtomicUsize>,
    closes: Arc<AtomicUsize>,
}

impl FakeRecognizer {
    fn new(scripts: Vec<Vec<FunResult>>) -> Arc<Self> {
        Arc::new(Self {
            scripts: Mutex::new(scripts.into()),
            opened: AtomicUsize::new(0),
            sends: Arc::new(AtomicUsize::new(0)),
            closes: Arc::new(AtomicUsize::new(0)),
        })
    }
}

impl Recognizer for FakeRecognizer {
    fn stream(&self, cancel: CancellationToken, _rate: i64, _wav: &str) -> StreamHandle {
        self.opened.fetch_add(1, Ordering::SeqCst);
        let script = self.scripts.lock().unwrap().pop_front().unwrap_or_default();
        let (results_tx, results_rx) = mpsc::channel(16);
        let (send_tx, mut send_rx) = mpsc::channel::<Vec<u8>>(32);
        let closed = CancellationToken::new();
        let sends = self.sends.clone();
        tokio::spawn(async move {
            while send_rx.recv().await.is_some() {
                sends.fetch_add(1, Ordering::SeqCst);
            }
        });
        let (closes, watch) = (self.closes.clone(), closed.clone());
        tokio::spawn(async move {
            for result in script {
                let _ = results_tx.send(result).await;
            }
            watch.cancelled().await;
            closes.fetch_add(1, Ordering::SeqCst);
            drop(results_tx);
        });
        StreamHandle {
            sender: StreamSender::for_test(send_tx, closed.clone(), cancel),
            results: results_rx,
            closer: StreamCloser::for_test(closed),
        }
    }
}

fn collector() -> (Publish, Arc<Mutex<Vec<String>>>) {
    let frames = Arc::new(Mutex::new(Vec::new()));
    let sink = frames.clone();
    let publish: Publish = Arc::new(move |payload| {
        let sink = sink.clone();
        Box::pin(async move {
            sink.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&payload).into_owned());
            Ok(())
        })
    });
    (publish, frames)
}

fn res(text: &str, is_final: bool) -> FunResult {
    FunResult {
        text: text.into(),
        is_final,
        degraded: false,
    }
}

#[tokio::test]
async fn worker_owns_decode_vad_stream_drain_and_publish() {
    let decoded = Arc::new(AtomicUsize::new(0));
    let arbiter = FakeArbiter::new(&[true, true, false]);
    let recognizer = FakeRecognizer::new(vec![vec![
        FunResult {
            degraded: true,
            ..FunResult::default()
        },
        res("partial", false),
        res("final", true),
    ]]);
    let (publish, frames) = collector();
    let worker = TrackWorker::new(
        "room-a",
        "alice",
        Box::new(FakeDecoder {
            failed_payload: "bad",
            decoded: decoded.clone(),
        }),
        arbiter.clone(),
        recognizer.clone(),
        publish,
    );
    worker
        .run(
            CancellationToken::new(),
            reader("track-1", &["bad", "one", "two", "silence"]),
        )
        .await;

    assert_eq!(
        decoded.load(Ordering::SeqCst),
        3,
        "three decodes after one recoverable failure"
    );
    assert_eq!(recognizer.sends.load(Ordering::SeqCst), 2);
    assert_eq!(recognizer.closes.load(Ordering::SeqCst), 1);
    assert_eq!(*arbiter.removed.lock().unwrap(), vec!["track-1".to_owned()]);
    let frames = frames.lock().unwrap().clone();
    assert_eq!(
        frames,
        vec![
            r#"{"t":"cc","sid":"track-1","p":"alice","text":"partial","final":false}"#.to_owned(),
            r#"{"t":"cc","sid":"track-1","p":"alice","text":"final","final":true}"#.to_owned(),
        ]
    );
}

#[tokio::test]
async fn silence_and_pre_cancel_never_open_a_recognizer() {
    for cancelled in [false, true] {
        let arbiter = FakeArbiter::new(&[false]);
        let recognizer = FakeRecognizer::new(vec![]);
        let (publish, _) = collector();
        let worker = TrackWorker::new(
            "room",
            "alice",
            Box::new(FakeDecoder {
                failed_payload: "",
                decoded: Arc::default(),
            }),
            arbiter.clone(),
            recognizer.clone(),
            publish,
        );
        let cancel = CancellationToken::new();
        if cancelled {
            cancel.cancel();
        }
        worker.run(cancel, reader("silent", &["one"])).await;
        assert_eq!(
            recognizer.opened.load(Ordering::SeqCst),
            0,
            "cancelled={cancelled}"
        );
        assert_eq!(
            arbiter.removed.lock().unwrap().len(),
            1,
            "cancelled={cancelled}"
        );
    }
}

#[tokio::test]
async fn speech_restart_drains_finals_and_publish_failure_is_non_terminal() {
    let recognizer = FakeRecognizer::new(vec![
        vec![
            res("", false),
            FunResult {
                text: "ignored".into(),
                is_final: false,
                degraded: true,
            },
            res("first final", true),
        ],
        vec![res("second final", true)],
    ]);
    let arbiter = FakeArbiter::new(&[true, false, true, false]);
    let attempts = Arc::new(Mutex::new(Vec::<String>::new()));
    let log = attempts.clone();
    let publish: Publish = Arc::new(move |payload| {
        let log = log.clone();
        Box::pin(async move {
            let mut log = log.lock().unwrap();
            log.push(String::from_utf8_lossy(&payload).into_owned());
            if log.len() == 1 {
                return Err("transient publish failure".into());
            }
            Ok(())
        })
    });
    let worker = TrackWorker::new(
        "room",
        "alice",
        Box::new(FakeDecoder {
            failed_payload: "",
            decoded: Arc::default(),
        }),
        arbiter,
        recognizer.clone(),
        publish,
    );
    worker
        .run(
            CancellationToken::new(),
            reader("restart", &["a", "b", "c", "d"]),
        )
        .await;
    let attempts = attempts.lock().unwrap().clone();
    assert_eq!(attempts.len(), 2);
    assert_eq!(
        (
            recognizer.closes.load(Ordering::SeqCst),
            recognizer.sends.load(Ordering::SeqCst)
        ),
        (2, 2)
    );
    assert!(attempts[0].contains("first final") && attempts[1].contains("second final"));
}

#[test]
fn redact_token_scrubs_the_whole_jwt() {
    let (header, payload, sig) = (
        "eyJhbGciOiJIUzI1NiJ9",
        "eyJyb29tIjoiYWJjIn0",
        "c2lnbmF0dXJl",
    );
    let token = format!("{header}.{payload}.{sig}");
    let raw = format!("dial ws://127.0.0.1:7880/rtc?access_token={token}: connection refused");
    assert_eq!(
        redact_token(&raw),
        "dial ws://127.0.0.1:7880/rtc?access_token=[redacted]: connection refused"
    );
    let plain = "dial tcp 127.0.0.1:7880: connection refused";
    assert_eq!(redact_token(plain), plain);
    // "eyJ" with nothing after it is not a token; a trailing dot stays.
    assert_eq!(redact_token("eyJ and eyJabc. x"), "eyJ and [redacted]. x");
    assert_eq!(
        redact_token("a eyJa.b.c.d! eyJz"),
        "a [redacted]! [redacted]"
    );
}

#[tokio::test(start_paused = true)]
async fn heartbeats_publish_on_cadence_and_stop_with_the_session() {
    let (publish, frames) = collector();
    let cancel = CancellationToken::new();
    let task = tokio::spawn(publish_heartbeats(
        cancel.clone(),
        publish,
        "room-a".into(),
        Duration::from_secs(5),
    ));
    tokio::time::sleep(Duration::from_millis(27_000)).await;
    cancel.cancel();
    task.await.unwrap();
    let frames = frames.lock().unwrap().clone();
    assert_eq!(frames.len(), 5, "ticks at 5s,10s,15s,20s,25s");
    assert!(frames.iter().all(|f| f == r#"{"t":"cc","hb":true}"#));
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert_eq!(frames.len(), 5);
}

#[test]
fn admission_bound_pins_the_headroom() {
    assert_eq!(track_admission_bound(4), 32);
    assert_eq!(track_admission_bound(1), 8);
    assert_eq!(track_admission_bound(0), 8);
    assert_eq!(track_admission_bound(-3), 8);
}

fn pipeline(bound: usize, decoder_fails: bool) -> (RoomPipeline, Arc<AtomicUsize>) {
    let built = Arc::new(AtomicUsize::new(0));
    let counter = built.clone();
    let (publish, _) = collector();
    let pipeline = RoomPipeline {
        room: "room".into(),
        vad: FakeArbiter::new(&[]),
        recognizer: FakeRecognizer::new(vec![]),
        publish,
        admission: Arc::new(TrackAdmission::new(bound)),
        new_decoder: Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            if decoder_fails {
                return Err("no libopus".into());
            }
            Ok(Box::new(FakeDecoder {
                failed_payload: "",
                decoded: Arc::default(),
            }) as Box<dyn PcmDecoder>)
        }),
    };
    (pipeline, built)
}

/// A reader that stays open until released, so the slot stays admitted.
struct HeldReader(String, mpsc::Receiver<()>);

#[async_trait]
impl RtpReader for HeldReader {
    fn id(&self) -> String {
        self.0.clone()
    }
    async fn read_rtp(&mut self) -> Option<Vec<u8>> {
        self.1.recv().await;
        None
    }
}

#[tokio::test]
async fn admission_refuses_tracks_before_decoder_allocation_and_duplicates() {
    let (pipeline, built) = pipeline(2, false);
    let cancel = CancellationToken::new();
    let mut gates = Vec::new();
    for id in ["t1", "t2", "t3", "t1"] {
        let (tx, rx) = mpsc::channel(1);
        gates.push(tx);
        pipeline.subscribe_audio_track(&cancel, "alice", Box::new(HeldReader(id.into(), rx)));
    }
    assert_eq!(
        built.load(Ordering::SeqCst),
        2,
        "refused tracks never allocate a decoder"
    );
    assert_eq!(pipeline.admission.active_count(), 2);
    for gate in &gates {
        let _ = gate.send(()).await;
    }
    for _ in 0..50 {
        if pipeline.admission.active_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        pipeline.admission.active_count(),
        0,
        "a worker exit frees its slot"
    );
}

#[tokio::test]
async fn decoder_failure_releases_the_slot() {
    let (pipeline, built) = pipeline(1, true);
    pipeline.subscribe_audio_track(&CancellationToken::new(), "alice", reader("t1", &["x"]));
    assert_eq!(built.load(Ordering::SeqCst), 1);
    assert_eq!(pipeline.admission.active_count(), 0);
    assert!(pipeline.admission.admit("t1"));
}

#[test]
fn cc_payload_escapes_like_go() {
    assert_eq!(
        cc_payload("s", "p<1>", "a&b \"q\"", true),
        r#"{"t":"cc","sid":"s","p":"p\u003c1\u003e","text":"a\u0026b \"q\"","final":true}"#
    );
}
