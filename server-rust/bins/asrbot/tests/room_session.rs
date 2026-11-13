//! The bot against fake LiveKit and FunASR peripherals (no real service is contacted).

mod support;

use setjoin_asrbot::funasr::Client;
use setjoin_asrbot::livekit::Options;
use setjoin_asrbot::registry::RoomRegistry;
use setjoin_asrbot::session::Sessions;
use std::sync::Arc;
use std::time::{Duration, Instant};
use support::fake_funasr::{FakeFunasr, Frame};
use support::fake_sfu::{FakeSfu, SfuOptions, SignalObs};

async fn wait_for(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn loopback_options() -> Options {
    Options {
        udp_bind: vec!["127.0.0.1:0".into()],
        include_loopback: true,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bot_joins_the_room_transcribes_the_speaker_and_publishes_captions() {
    let funasr = FakeFunasr::start("ni hao", "ni hao.").await;
    let sfu = FakeSfu::start(SfuOptions::default()).await;
    let sessions = Sessions::with_parts(
        &sfu.url(),
        4,
        Arc::new(Client::new(&funasr.url())),
        loopback_options(),
    );
    let rooms = RoomRegistry::new(2, Arc::new(sessions));

    assert!(rooms.start("meeting-1", "room-token"));
    assert_eq!(rooms.rooms(), vec!["meeting-1".to_owned()]);

    wait_for("a final caption", || {
        sfu.observed
            .lock()
            .unwrap()
            .data
            .iter()
            .any(|d| String::from_utf8_lossy(&d.payload).contains("\"final\":true"))
    })
    .await;
    rooms.stop("meeting-1");
    wait_for("the room leave", || sfu.observed.lock().unwrap().left).await;
    wait_for("release", || rooms.rooms().is_empty()).await;

    let o = sfu.observed.lock().unwrap();
    let upgrade = o.upgrade.clone().expect("upgrade recorded");
    assert_eq!(
        upgrade.path_and_query,
        "/rtc?version=2.18.1&protocol=17&&auto_subscribe=1&sdk=go&os=linux"
    );
    assert!(upgrade
        .headers
        .iter()
        .any(|(k, v)| k == "authorization" && v == "Bearer room-token"));

    // Publisher data channels: lossy (unordered) and reliable (ordered). The accepting side of
    // webrtc-rs does not surface the DCEP retransmit limit, so only `ordered` is observable.
    let mut labels: Vec<_> = o
        .channels
        .iter()
        .map(|c| (c.label.as_str(), c.ordered))
        .collect();
    labels.sort();
    assert_eq!(labels, vec![("_lossy", false), ("_reliable", true)]);

    // Every packet is a plain user packet on the lossy channel.
    assert!(!o.data.is_empty());
    for d in &o.data {
        assert_eq!(
            (
                d.channel.as_str(),
                d.kind,
                d.sequence,
                d.topic.clone(),
                d.destinations
            ),
            ("_lossy", 0, 0, None, 0)
        );
    }
    let frames: Vec<String> = o
        .data
        .iter()
        .map(|d| String::from_utf8_lossy(&d.payload).into_owned())
        .collect();
    let cc: Vec<&String> = frames.iter().filter(|f| !f.contains("\"hb\"")).collect();
    assert_eq!(
        cc,
        vec![
            r#"{"t":"cc","sid":"TR_alice_mic","p":"alice","text":"ni hao","final":false}"#,
            r#"{"t":"cc","sid":"TR_alice_mic","p":"alice","text":"ni hao.","final":true}"#,
        ]
    );

    // Signalling order: subscriber answer + trickles, a publisher offer on first publish, then leave.
    assert!(o
        .signals
        .iter()
        .any(|s| matches!(s, SignalObs::Answer(k) if k == "answer")));
    assert!(o
        .signals
        .iter()
        .any(|s| matches!(s, SignalObs::Offer(k) if k == "offer")));
    assert!(matches!(
        o.signals.last(),
        Some(SignalObs::Leave {
            reason: 1,
            action: 0,
            can_reconnect: false
        })
    ));

    // FunASR saw the config frame, PCM, and the closing frame, on one connection.
    let f = funasr.observed.lock().unwrap();
    assert_eq!(f.connections, 1);
    let texts: Vec<&str> = f
        .frames
        .iter()
        .filter_map(|(_, fr)| {
            if let Frame::Text(t) = fr {
                Some(t.as_str())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        texts,
        vec![
            r#"{"mode":"2pass","chunk_size":[5,10,5],"chunk_interval":10,"wav_name":"TR_alice_mic","wav_format":"pcm","audio_fs":16000,"is_speaking":true}"#,
            r#"{"is_speaking":false}"#,
        ]
    );
    assert!(
        f.frames
            .iter()
            .any(|(_, fr)| matches!(fr, Frame::Binary(n) if *n == 640)),
        "20 ms of 16 kHz PCM16 is 640 bytes"
    );
}
