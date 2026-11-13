//! Outbound-interaction oracle: the bot process (frozen Go, or the Rust binary on replay)
//! driven through `/start` against the fake LiveKit and FunASR peripherals; what it sent to
//! each peripheral is normalised and compared with the Go recording.
//!
//! Record: GOFREE_RECORD_ASRBOT_GO_BINARY=<asrbotd> cargo test -p setjoin-asrbot --test outbound_oracle -- --test-threads=1

mod support;

use serde_json::{json, Value};
use std::time::{Duration, Instant};
use support::backend::{free_port, spawn, wait_ready, Backend};
use support::fake_funasr::{FakeFunasr, Frame};
use support::fake_sfu::{FakeSfu, SfuOptions, SignalObs};
use support::raw_http::{self, Request};

const TOKEN: &str = "oracle-token";
const ROOM_TOKEN: &str = "room-token-for-the-oracle";

async fn wait_for(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(45);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn control(port: u16, method: &str, path: &str, body: &str) -> u16 {
    let headers = [("Authorization", "Bearer oracle-token")];
    let request = Request {
        method,
        path,
        headers: &headers,
        body: body.as_bytes(),
    };
    raw_http::send(port, &request)
        .await
        .expect("control request")
        .status
}

fn golden(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/goldens")
        .join(format!("{name}.json"))
}

fn check(backend: &Backend, name: &str, actual: Value) {
    let path = golden(name);
    if backend.recording() {
        let text = serde_json::to_string_pretty(&actual).expect("json") + "\n";
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap_or_else(|e| panic!("{}: goldens are exclusive-create: {e}", path.display()));
        std::io::Write::write_all(&mut file, text.as_bytes()).expect("write");
        return;
    }
    let want: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("golden"))
        .expect("golden json");
    assert_eq!(
        want, actual,
        "{name}: outbound interactions differ from the Go recording"
    );
    println!("GOLDEN-REPLAY: asrbot outbound :: {name}");
}

fn normalise(sfu: &FakeSfu, funasr: &FakeFunasr) -> Value {
    let o = sfu.observed.lock().unwrap();
    let upgrade = o.upgrade.clone().expect("the bot dialled /rtc");
    // Names are the contract; values are run-specific except the bearer token and the query.
    let mut header_names: Vec<String> = upgrade
        .headers
        .iter()
        .map(|(k, _)| k.to_ascii_lowercase())
        .collect();
    header_names.sort();
    let authorization: Vec<&String> = upgrade
        .headers
        .iter()
        .filter(|(k, _)| k == "authorization")
        .map(|(_, v)| v)
        .collect();

    // Signalling: the ordered non-trickle messages, and which trickle targets appeared.
    let mut ordered = Vec::new();
    let mut targets = std::collections::BTreeSet::new();
    for s in &o.signals {
        match s {
            SignalObs::Trickle { target } => {
                targets.insert(*target);
            }
            other => ordered.push(format!("{other:?}")),
        }
    }
    let mut channels: Vec<(String, bool)> = o
        .channels
        .iter()
        .map(|c| (c.label.clone(), c.ordered))
        .collect();
    channels.sort();
    let packets: Vec<Value> = o
        .data
        .iter()
        .map(|d| json!({ "channel": d.channel, "kind": d.kind, "sequence": d.sequence, "topic": d.topic, "destinations": d.destinations }))
        .collect();
    let mut distinct_packet_shapes: Vec<Value> = Vec::new();
    for p in packets {
        if !distinct_packet_shapes.contains(&p) {
            distinct_packet_shapes.push(p);
        }
    }
    let frames: Vec<String> = o
        .data
        .iter()
        .map(|d| String::from_utf8_lossy(&d.payload).into_owned())
        .filter(|f| !f.contains("\"hb\""))
        .collect();

    let f = funasr.observed.lock().unwrap();
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
    let mut binary_sizes: Vec<usize> = f
        .frames
        .iter()
        .filter_map(|(_, fr)| {
            if let Frame::Binary(n) = fr {
                Some(*n)
            } else {
                None
            }
        })
        .collect();
    binary_sizes.sort_unstable();
    binary_sizes.dedup();

    let funasr_upgrades: Vec<Value> = f
        .upgrades
        .iter()
        .map(|(target, headers)| {
            let mut names: Vec<String> = headers
                .iter()
                .map(|(k, _)| k.to_ascii_lowercase())
                .collect();
            names.sort();
            let agent: Vec<&String> = headers
                .iter()
                .filter(|(k, _)| k == "user-agent")
                .map(|(_, v)| v)
                .collect();
            json!({ "target": target, "header_names": names, "user_agent": agent })
        })
        .collect();
    let livekit_agent: Vec<&String> = upgrade
        .headers
        .iter()
        .filter(|(k, _)| k == "user-agent")
        .map(|(_, v)| v)
        .collect();

    json!({
        "livekit": {
            "upgrade": { "path_and_query": upgrade.path_and_query, "header_names": header_names, "authorization": authorization, "user_agent": livekit_agent },
            "signals": ordered,
            "trickle_targets": targets,
            "data_channels": channels,
            "data_packet_shapes": distinct_packet_shapes,
            "caption_frames": frames,
        },
        "funasr": { "connections": f.connections, "upgrades": funasr_upgrades, "text_frames": texts, "binary_frame_sizes": binary_sizes },
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bot_process_interactions_match_recorded_go() {
    let backend = Backend::from_env();
    let funasr = FakeFunasr::start("ni hao", "ni hao.").await;
    let sfu = FakeSfu::start(SfuOptions::default()).await;
    let port = free_port();
    let env = vec![
        ("ASR_LISTEN".to_owned(), format!("127.0.0.1:{port}")),
        ("ASR_TOKEN".to_owned(), TOKEN.to_owned()),
        ("LIVEKIT_URL".to_owned(), sfu.url()),
        ("FUNASR_URL".to_owned(), funasr.url()),
    ];
    let proc = spawn(&backend, &env);
    wait_ready(port).await;

    assert_eq!(
        control(
            port,
            "POST",
            "/start",
            &format!("{{\"room\":\"meeting-1\",\"token\":\"{ROOM_TOKEN}\"}}")
        )
        .await,
        200
    );
    wait_for("a final caption", || {
        sfu.observed
            .lock()
            .unwrap()
            .data
            .iter()
            .any(|d| String::from_utf8_lossy(&d.payload).contains("\"final\":true"))
    })
    .await;
    assert_eq!(
        control(port, "POST", "/stop", "{\"room\":\"meeting-1\"}").await,
        200
    );
    wait_for("the room leave", || sfu.observed.lock().unwrap().left).await;
    wait_for("the room to release", || {
        // Polled below; a blocking status read is not available here.
        true
    })
    .await;
    // The room is released once the runner returns; allow the leave to drain.
    for _ in 0..100 {
        let headers = [("Authorization", "Bearer oracle-token")];
        let request = Request {
            method: "GET",
            path: "/status",
            headers: &headers,
            body: b"",
        };
        let status = raw_http::send(port, &request).await.expect("status");
        if status.body.contains("\"rooms\":[]") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    proc.kill().await;
    check(&backend, "outbound-captions", normalise(&sfu, &funasr));
}

// ---- further scenarios, each recorded from Go ----

/// Start the bot process, run `/start`, wait for `done`, stop it and return its status polling result.
struct Run {
    port: u16,
    proc: Option<support::backend::Proc>,
}

impl Run {
    async fn start(backend: &Backend, livekit_url: String, funasr_url: String) -> Self {
        let port = free_port();
        let env = vec![
            ("ASR_LISTEN".to_owned(), format!("127.0.0.1:{port}")),
            ("ASR_TOKEN".to_owned(), TOKEN.to_owned()),
            ("LIVEKIT_URL".to_owned(), livekit_url),
            ("FUNASR_URL".to_owned(), funasr_url),
        ];
        let proc = spawn(backend, &env);
        wait_ready(port).await;
        Self {
            port,
            proc: Some(proc),
        }
    }

    async fn rooms(&self) -> String {
        let headers = [("Authorization", "Bearer oracle-token")];
        let request = Request {
            method: "GET",
            path: "/status",
            headers: &headers,
            body: b"",
        };
        raw_http::send(self.port, &request)
            .await
            .expect("status")
            .body
    }

    async fn wait_released(&self) {
        for _ in 0..200 {
            if self.rooms().await.contains("\"rooms\":[]") {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the room was never released");
    }

    async fn finish(mut self) -> Vec<String> {
        let proc = self.proc.take().expect("proc");
        proc.kill().await;
        Vec::new()
    }
}

fn caption_frames(sfu: &FakeSfu) -> Vec<String> {
    let o = sfu.observed.lock().unwrap();
    o.data
        .iter()
        .map(|d| String::from_utf8_lossy(&d.payload).into_owned())
        .filter(|f| !f.contains("\"hb\""))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_participant_info_defers_the_track_until_the_speaker_is_known() {
    let backend = Backend::from_env();
    let funasr = FakeFunasr::start("ni hao", "ni hao.").await;
    let sfu = FakeSfu::start(SfuOptions {
        late_participant_info: true,
        ..SfuOptions::default()
    })
    .await;
    let run = Run::start(&backend, sfu.url(), funasr.url()).await;
    assert_eq!(
        control(
            run.port,
            "POST",
            "/start",
            &format!("{{\"room\":\"meeting-1\",\"token\":\"{ROOM_TOKEN}\"}}")
        )
        .await,
        200
    );
    wait_for("a final caption", || {
        caption_frames(&sfu)
            .iter()
            .any(|f| f.contains("\"final\":true"))
    })
    .await;
    assert_eq!(
        control(run.port, "POST", "/stop", "{\"room\":\"meeting-1\"}").await,
        200
    );
    wait_for("the room leave", || sfu.observed.lock().unwrap().left).await;
    run.wait_released().await;
    run.finish().await;
    check(
        &backend,
        "outbound-late-participant",
        normalise(&sfu, &funasr),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_initiated_leave_releases_the_room_without_a_client_leave() {
    let backend = Backend::from_env();
    let funasr = FakeFunasr::start("ni hao", "ni hao.").await;
    let sfu = FakeSfu::start(SfuOptions {
        leave_after_audio: true,
        ..SfuOptions::default()
    })
    .await;
    let run = Run::start(&backend, sfu.url(), funasr.url()).await;
    assert_eq!(
        control(
            run.port,
            "POST",
            "/start",
            &format!("{{\"room\":\"meeting-1\",\"token\":\"{ROOM_TOKEN}\"}}")
        )
        .await,
        200
    );
    wait_for("a final caption", || {
        caption_frames(&sfu)
            .iter()
            .any(|f| f.contains("\"final\":true"))
    })
    .await;
    // No /stop: the server ended the room, and the bot's registry entry must clear by itself.
    run.wait_released().await;
    run.finish().await;
    check(&backend, "outbound-server-leave", normalise(&sfu, &funasr));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn funasr_drop_reconnects_with_a_fresh_config_frame() {
    let backend = Backend::from_env();
    let funasr = FakeFunasr::start_with("ni hao", "ni hao.", Some(10)).await;
    let sfu = FakeSfu::start(SfuOptions::default()).await;
    let run = Run::start(&backend, sfu.url(), funasr.url()).await;
    assert_eq!(
        control(
            run.port,
            "POST",
            "/start",
            &format!("{{\"room\":\"meeting-1\",\"token\":\"{ROOM_TOKEN}\"}}")
        )
        .await,
        200
    );
    wait_for("a final caption", || {
        caption_frames(&sfu)
            .iter()
            .any(|f| f.contains("\"final\":true"))
    })
    .await;
    assert_eq!(
        control(run.port, "POST", "/stop", "{\"room\":\"meeting-1\"}").await,
        200
    );
    wait_for("the room leave", || sfu.observed.lock().unwrap().left).await;
    run.wait_released().await;
    run.finish().await;
    let mut actual = normalise(&sfu, &funasr);
    // Which connection carried how many frames depends on timing; the contract is the
    // sequence of config/closing frames and that audio continued on the new connection.
    let f = funasr.observed.lock().unwrap();
    let per_connection: Vec<Value> = (1..=f.connections)
        .map(|c| {
            let texts: Vec<&str> = f
                .frames
                .iter()
                .filter(|(i, _)| *i == c)
                .filter_map(|(_, fr)| {
                    if let Frame::Text(t) = fr {
                        Some(t.as_str())
                    } else {
                        None
                    }
                })
                .collect();
            let has_audio = f
                .frames
                .iter()
                .any(|(i, fr)| *i == c && matches!(fr, Frame::Binary(_)));
            json!({ "text_frames": texts, "has_audio": has_audio })
        })
        .collect();
    actual["funasr"]["per_connection"] = json!(per_connection);
    check(&backend, "outbound-funasr-reconnect", actual);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_livekit_join_is_diagnosed_with_a_validate_request() {
    let backend = Backend::from_env();
    let livekit =
        support::refusing_livekit::RefusingLiveKit::start("401 Unauthorized", "invalid token")
            .await;
    let funasr = FakeFunasr::start("ni hao", "ni hao.").await;
    let run = Run::start(&backend, livekit.url(), funasr.url()).await;
    assert_eq!(
        control(
            run.port,
            "POST",
            "/start",
            &format!("{{\"room\":\"meeting-1\",\"token\":\"{ROOM_TOKEN}\"}}")
        )
        .await,
        200
    );
    run.wait_released().await;
    let proc = run.proc;
    let seen = livekit.seen.lock().unwrap().clone();
    let (code_and_lines, _) = match proc {
        Some(mut p) => {
            p.terminate().await;
            let (code, lines) = p.finish(Duration::from_secs(30)).await;
            ((code, lines), ())
        }
        None => unreachable!(),
    };
    let failure_logs: Vec<String> = code_and_lines
        .1
        .into_iter()
        .filter(|l| l.contains("livekit connect failed"))
        .map(|l| l.replace(ROOM_TOKEN, "<room-token>"))
        .collect();
    let requests: Vec<Value> = seen
        .iter()
        .map(|s| json!({ "method": s.method, "target": s.target, "header_names": s.header_names, "authorization": s.authorization, "user_agent": s.user_agent }))
        .collect();
    check(
        &backend,
        "outbound-livekit-refused",
        json!({ "requests": requests, "failure_logs": failure_logs }),
    );
}
