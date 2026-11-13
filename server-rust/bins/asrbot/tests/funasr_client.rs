//! The FunASR client against the in-process fake runtime.

mod support;

use setjoin_asrbot::funasr::{Client, FunResult, Recognizer};
use std::time::Duration;
use support::fake_funasr::{FakeFunasr, Frame};
use tokio_util::sync::CancellationToken;

async fn recv(results: &mut tokio::sync::mpsc::Receiver<FunResult>) -> Option<FunResult> {
    tokio::time::timeout(Duration::from_secs(10), results.recv())
        .await
        .expect("a result within 10s")
}

#[tokio::test]
async fn stream_sends_config_then_pcm_and_delivers_partial_then_the_final_after_close() {
    let fake = FakeFunasr::start("partial text", "final text.").await;
    let client = Client::new(&fake.url());
    let mut stream = client.stream(CancellationToken::new(), 16000, "track-1");

    for _ in 0..3 {
        stream.sender.send(vec![1u8; 640]).await;
    }
    let partial = recv(&mut stream.results).await.expect("partial");
    assert_eq!(
        partial,
        FunResult {
            text: "partial text".into(),
            is_final: false,
            degraded: false
        }
    );

    stream.closer.close();
    stream.closer.close(); // idempotent
    let last = recv(&mut stream.results)
        .await
        .expect("final arrives after the close request");
    assert_eq!(
        last,
        FunResult {
            text: "final text.".into(),
            is_final: true,
            degraded: false
        }
    );
    assert!(
        recv(&mut stream.results).await.is_none(),
        "the results channel closes once the session ends"
    );

    let frames = fake.observed.lock().unwrap().frames.clone();
    let texts: Vec<_> = frames
        .iter()
        .filter_map(|(_, f)| {
            if let Frame::Text(t) = f {
                Some(t.as_str())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        texts,
        vec![
            r#"{"mode":"2pass","chunk_size":[5,10,5],"chunk_interval":10,"wav_name":"track-1","wav_format":"pcm","audio_fs":16000,"is_speaking":true}"#,
            r#"{"is_speaking":false}"#,
        ]
    );
    assert_eq!(
        frames
            .iter()
            .filter(|(_, f)| matches!(f, Frame::Binary(640)))
            .count(),
        3
    );
}

#[tokio::test]
async fn a_dropped_connection_emits_degraded_and_reconnects_with_a_new_config_frame() {
    let fake = FakeFunasr::start_with("p", "f", Some(2)).await;
    let client = Client::new(&fake.url());
    let mut stream = client.stream(CancellationToken::new(), 16000, "track-2");
    for _ in 0..2 {
        stream.sender.send(vec![0u8; 640]).await;
    }
    // Drain results until the degraded marker shows the drop was noticed.
    let mut saw_degraded = false;
    for _ in 0..4 {
        if recv(&mut stream.results).await.expect("result").degraded {
            saw_degraded = true;
            break;
        }
    }
    assert!(
        saw_degraded,
        "a drop is reported as a degraded result, never an error"
    );
    // After the fixed backoff the client dials again and re-sends the config.
    for _ in 0..40 {
        if fake.observed.lock().unwrap().connections >= 2 {
            break;
        }
        stream.sender.send(vec![0u8; 640]).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(fake.observed.lock().unwrap().connections, 2);
    stream.closer.close();
    let frames = fake.observed.lock().unwrap().frames.clone();
    let configs = frames
        .iter()
        .filter(|(_, f)| matches!(f, Frame::Text(t) if t.contains("\"mode\":\"2pass\"")))
        .count();
    assert_eq!(configs, 2, "one config frame per connection");
}

#[tokio::test(start_paused = true)]
async fn an_unreachable_runtime_degrades_and_retries_until_closed() {
    // Port 1 refuses connections: every attempt is a degraded result, 500 ms apart.
    let client = Client::new("ws://127.0.0.1:1");
    let mut stream = client.stream(CancellationToken::new(), 16000, "track-3");
    for _ in 0..3 {
        let r = stream.results.recv().await.expect("degraded");
        assert!(r.degraded && r.text.is_empty() && !r.is_final);
    }
    stream.closer.close();
    // Closing ends the retry loop and closes the channel.
    let mut ended = false;
    for _ in 0..4 {
        if stream.results.recv().await.is_none() {
            ended = true;
            break;
        }
    }
    assert!(ended);
}

#[tokio::test]
async fn cancelling_the_context_ends_the_stream() {
    let fake = FakeFunasr::start("p", "f").await;
    let cancel = CancellationToken::new();
    let mut stream = Client::new(&fake.url()).stream(cancel.clone(), 16000, "track-4");
    stream.sender.send(vec![0u8; 640]).await;
    let _ = recv(&mut stream.results).await;
    cancel.cancel();
    loop {
        if recv(&mut stream.results).await.is_none() {
            break;
        }
    }
}
