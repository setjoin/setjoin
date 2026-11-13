//! Recorded-oracle tests for the control API and process lifecycle.
//!
//! Recording (frozen Go in the CI image, exclusive-create goldens):
//!   GOFREE_RECORD_ASRBOT_GO_BINARY=<path to asrbotd> cargo test -p setjoin-asrbot --test control_oracle -- --test-threads=1
//! Replay (default) runs the Rust `asrbotd` through the same steps and compares byte for byte
//! (status, every header but `Date`, body). `docs`: asrbot/DOX.md and the crate DOX.md.

mod support;

use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;
use support::backend::{free_port, spawn, strip_time, wait_ready, Backend};
use support::hold_ws::HoldWs;
use support::raw_http::{self, Request};

const TOKEN: &str = "oracle-token";

enum Body {
    None,
    Text(&'static str),
    Bytes(Vec<u8>),
}

struct Http {
    name: &'static str,
    method: &'static str,
    path: &'static str,
    headers: Vec<(&'static str, String)>,
    body: Body,
}

fn bearer() -> (&'static str, String) {
    ("Authorization", format!("Bearer {TOKEN}"))
}

fn post(name: &'static str, path: &'static str, body: &'static str) -> Http {
    Http {
        name,
        method: "POST",
        path,
        headers: vec![bearer()],
        body: Body::Text(body),
    }
}

fn get(name: &'static str, path: &'static str) -> Http {
    Http {
        name,
        method: "GET",
        path,
        headers: vec![bearer()],
        body: Body::None,
    }
}

fn with(method: &'static str, name: &'static str, path: &'static str) -> Http {
    Http {
        name,
        method,
        path,
        headers: vec![bearer()],
        body: Body::None,
    }
}

enum Step {
    Http(Http),
    Sleep(u64),
}

struct Scenario {
    name: &'static str,
    max_meetings: &'static str,
    hold_ms: u64,
    steps: Vec<Step>,
}

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/goldens")
        .join(format!("{name}.json"))
}

fn scenarios() -> Vec<Scenario> {
    use Step::{Http as H, Sleep};
    let big_valid = format!(
        "{{\"room\":\"big\",\"token\":\"t\"}}{}",
        " ".repeat(8192 - 25)
    );
    let big_value = format!("{{\"room\":\"big2\",\"token\":\"{}\"}}", "x".repeat(9000));
    let trailing = format!(
        "{{\"room\":\"trail\",\"token\":\"t\"}} {}",
        "garbage".repeat(4000)
    );
    let deep_ok = format!(
        "{{\"room\":\"deep\",\"token\":\"t\",\"x\":{}{}}}",
        "[".repeat(4000),
        "]".repeat(4000)
    );
    let deep_too = format!(
        "{{\"room\":\"deep2\",\"token\":\"t\",\"x\":{}{}}}",
        "[".repeat(5000),
        "]".repeat(5000)
    );
    let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
    vec![
        Scenario {
            name: "auth",
            max_meetings: "2",
            hold_ms: 1500,
            steps: vec![
                H(Http {
                    name: "healthz-no-auth",
                    method: "GET",
                    path: "/healthz",
                    headers: vec![],
                    body: Body::None,
                }),
                H(Http {
                    name: "status-no-auth",
                    method: "GET",
                    path: "/status",
                    headers: vec![],
                    body: Body::None,
                }),
                H(Http {
                    name: "start-no-auth",
                    method: "POST",
                    path: "/start",
                    headers: vec![],
                    body: Body::Text(r#"{"room":"a","token":"t"}"#),
                }),
                H(Http {
                    name: "stop-no-auth",
                    method: "POST",
                    path: "/stop",
                    headers: vec![],
                    body: Body::Text(r#"{"room":"a"}"#),
                }),
                H(Http {
                    name: "status-wrong-token",
                    method: "GET",
                    path: "/status",
                    headers: vec![("Authorization", "Bearer wrong".into())],
                    body: Body::None,
                }),
                H(Http {
                    name: "status-raw-token-no-prefix",
                    method: "GET",
                    path: "/status",
                    headers: vec![("Authorization", TOKEN.into())],
                    body: Body::None,
                }),
                H(Http {
                    name: "status-two-spaces",
                    method: "GET",
                    path: "/status",
                    headers: vec![("Authorization", format!("Bearer  {TOKEN}"))],
                    body: Body::None,
                }),
                H(Http {
                    name: "status-lowercase-scheme",
                    method: "GET",
                    path: "/status",
                    headers: vec![("Authorization", format!("bearer {TOKEN}"))],
                    body: Body::None,
                }),
                H(Http {
                    name: "status-bearer-only",
                    method: "GET",
                    path: "/status",
                    headers: vec![("Authorization", "Bearer ".into())],
                    body: Body::None,
                }),
                H(Http {
                    name: "status-token-prefix-of-real",
                    method: "GET",
                    path: "/status",
                    headers: vec![("Authorization", "Bearer oracle".into())],
                    body: Body::None,
                }),
                H(Http {
                    name: "status-ok",
                    method: "GET",
                    path: "/status",
                    headers: vec![bearer()],
                    body: Body::None,
                }),
                H(Http {
                    name: "unauthorized-before-body",
                    method: "POST",
                    path: "/start",
                    headers: vec![],
                    body: Body::Text("not json"),
                }),
            ],
        },
        Scenario {
            name: "mux",
            max_meetings: "2",
            hold_ms: 1500,
            steps: vec![
                H(get("double-slash", "//status")),
                H(get("dot-dot", "/a/../status")),
                H(get("dot", "/./status")),
                H(get("trailing-slash", "/status/")),
                H(get("healthz-trailing-slash", "/healthz/")),
                H(get("root", "/")),
                H(get("unknown", "/nope")),
                H(get("case", "/STATUS")),
                H(get("query", "/status?x=1")),
                H(get("redirect-keeps-query", "//status?x=1&y=2")),
                H(get("percent-encoded-letter", "/st%61tus")),
                H(get("percent-encoded-slash", "/status%2F")),
                H(get("bad-percent", "/st%zz")),
                H(with("POST", "post-redirect", "//start")),
                H(with("HEAD", "head-redirect", "//status")),
                H(with("POST", "post-status", "/status")),
                H(with("GET", "get-start", "/start")),
                H(with("DELETE", "delete-healthz", "/healthz")),
                H(with("OPTIONS", "options-start", "/start")),
                H(with("PUT", "put-stop", "/stop")),
                H(with("GET", "get-stop", "/stop")),
                H(with("HEAD", "head-healthz", "/healthz")),
                H(with("HEAD", "head-status", "/status")),
                H(Http {
                    name: "head-status-no-auth",
                    method: "HEAD",
                    path: "/status",
                    headers: vec![],
                    body: Body::None,
                }),
                H(Http {
                    name: "options-no-auth",
                    method: "OPTIONS",
                    path: "/status",
                    headers: vec![],
                    body: Body::None,
                }),
                H(get("healthz", "/healthz")),
            ],
        },
        Scenario {
            name: "start-body",
            max_meetings: "40",
            hold_ms: 1500,
            steps: vec![
                H(post("empty-body", "/start", "")),
                H(post("empty-object", "/start", "{}")),
                H(post("room-only", "/start", r#"{"room":"a"}"#)),
                H(post("token-only", "/start", r#"{"token":"t"}"#)),
                H(post(
                    "null-values",
                    "/start",
                    r#"{"room":null,"token":null}"#,
                )),
                H(post("top-level-null", "/start", "null")),
                H(post("array", "/start", "[]")),
                H(post("number-room", "/start", r#"{"room":5,"token":"t"}"#)),
                H(post(
                    "object-token",
                    "/start",
                    r#"{"room":"a","token":{"x":1}}"#,
                )),
                H(post("bool-token", "/start", r#"{"room":"a","token":true}"#)),
                H(post("empty-strings", "/start", r#"{"room":"","token":""}"#)),
                H(post("invalid-json", "/start", r#"{"room":"a","token":"t""#)),
                H(post(
                    "trailing-comma",
                    "/start",
                    r#"{"room":"a","token":"t",}"#,
                )),
                H(post(
                    "bad-escape",
                    "/start",
                    r#"{"room":"a\x","token":"t"}"#,
                )),
                H(post(
                    "syntax-error-after-fields",
                    "/start",
                    r#"{"room":"a","token":"t","x":}"#,
                )),
                H(post(
                    "control-char-in-string",
                    "/start",
                    "{\"room\":\"a\nb\",\"token\":\"t\"}",
                )),
                H(post("single-quotes", "/start", "{'room':'a','token':'t'}")),
                H(post(
                    "ok-case-insensitive-keys",
                    "/start",
                    r#"{"ROOM":"upper","Token":"t"}"#,
                )),
                H(post(
                    "ok-last-duplicate-wins",
                    "/start",
                    r#"{"room":"first","room":"dup","token":"t"}"#,
                )),
                H(post(
                    "ok-unknown-keys",
                    "/start",
                    r#"{"room":"extra","token":"t","x":[1,2.5e3,true,null,{"y":"z"}]}"#,
                )),
                H(post(
                    "ok-html-chars-in-room",
                    "/start",
                    r#"{"room":"r<1>& end","token":"t"}"#,
                )),
                H(post(
                    "ok-unicode-room",
                    "/start",
                    r#"{"room":"café-😀","token":"t"}"#,
                )),
                H(post(
                    "ok-lone-surrogate",
                    "/start",
                    r#"{"room":"sur\ud800rogate","token":"t"}"#,
                )),
                H(Http {
                    name: "ok-invalid-utf8-room",
                    method: "POST",
                    path: "/start",
                    headers: vec![bearer()],
                    body: Body::Bytes(b"{\"room\":\"bad\xffbyte\",\"token\":\"t\"}".to_vec()),
                }),
                H(post(
                    "ok-kelvin-sign-key",
                    "/start",
                    "{\"room\":\"kelvin\",\"to\u{212A}en\":\"t\"}",
                )),
                H(post(
                    "ok-escaped-quote-room",
                    "/start",
                    r#"{"room":"q\"uote\\back","token":"t"}"#,
                )),
                H(Http {
                    name: "ok-8192-bytes",
                    method: "POST",
                    path: "/start",
                    headers: vec![bearer()],
                    body: Body::Bytes(big_valid.into_bytes()),
                }),
                H(Http {
                    name: "value-spans-limit",
                    method: "POST",
                    path: "/start",
                    headers: vec![bearer()],
                    body: Body::Bytes(big_value.into_bytes()),
                }),
                H(Http {
                    name: "ok-trailing-garbage-over-limit",
                    method: "POST",
                    path: "/start",
                    headers: vec![bearer()],
                    body: Body::Bytes(trailing.into_bytes()),
                }),
                H(Http {
                    name: "ok-deep-nesting",
                    method: "POST",
                    path: "/start",
                    headers: vec![bearer()],
                    body: Body::Text(leak(deep_ok)),
                }),
                H(Http {
                    name: "too-deep-nesting-over-limit",
                    method: "POST",
                    path: "/start",
                    headers: vec![bearer()],
                    body: Body::Text(leak(deep_too)),
                }),
                H(post("stop-empty", "/stop", "")),
                H(post("stop-no-room", "/stop", r#"{"token":"x"}"#)),
                H(post("stop-room-number", "/stop", r#"{"room":5}"#)),
                H(post("stop-null-room", "/stop", r#"{"room":null}"#)),
                H(post(
                    "stop-unknown-room",
                    "/stop",
                    r#"{"room":"never-started"}"#,
                )),
                H(post(
                    "stop-unknown-keys-ok",
                    "/stop",
                    r#"{"ROOM":"never","extra":1}"#,
                )),
                H(get("status-sorted-rooms", "/status")),
                Sleep(2800),
                H(get("status-after-connect-failures", "/status")),
            ],
        },
        Scenario {
            name: "capacity",
            max_meetings: "1",
            hold_ms: 1500,
            steps: vec![
                H(post(
                    "start-a",
                    "/start",
                    r#"{"room":"room-a","token":"t"}"#,
                )),
                H(post(
                    "start-b-busy",
                    "/start",
                    r#"{"room":"room-b","token":"t"}"#,
                )),
                H(post(
                    "start-a-idempotent",
                    "/start",
                    r#"{"room":"room-a","token":"other"}"#,
                )),
                H(get("status-a", "/status")),
                H(post(
                    "bad-body-not-admitted",
                    "/start",
                    r#"{"room":"room-c"}"#,
                )),
                H(post("stop-a", "/stop", r#"{"room":"room-a"}"#)),
                H(get("status-stopping-keeps-room", "/status")),
                H(post(
                    "start-a-while-stopping",
                    "/start",
                    r#"{"room":"room-a","token":"t"}"#,
                )),
                H(post(
                    "start-b-while-stopping",
                    "/start",
                    r#"{"room":"room-b","token":"t"}"#,
                )),
                H(post("stop-a-again", "/stop", r#"{"room":"room-a"}"#)),
                Sleep(2800),
                H(get("status-drained", "/status")),
                H(post(
                    "start-b-after-drain",
                    "/start",
                    r#"{"room":"room-b","token":"t"}"#,
                )),
                H(get("status-b", "/status")),
            ],
        },
        Scenario {
            name: "zero-capacity",
            max_meetings: "0",
            hold_ms: 1500,
            steps: vec![
                H(post(
                    "start-refused",
                    "/start",
                    r#"{"room":"a","token":"t"}"#,
                )),
                H(get("status-empty", "/status")),
            ],
        },
    ]
}

async fn run_scenario(backend: &Backend, scenario: &Scenario) -> Value {
    let hold = HoldWs::start(Duration::from_millis(scenario.hold_ms)).await;
    let port = free_port();
    let env = vec![
        ("ASR_LISTEN".to_owned(), format!("127.0.0.1:{port}")),
        ("ASR_TOKEN".to_owned(), TOKEN.to_owned()),
        ("LIVEKIT_URL".to_owned(), hold.url()),
        (
            "ASR_MAX_MEETINGS".to_owned(),
            scenario.max_meetings.to_owned(),
        ),
        ("FUNASR_URL".to_owned(), "ws://127.0.0.1:1".to_owned()),
    ];
    let proc = spawn(backend, &env);
    wait_ready(port).await;
    let mut recorded = Vec::new();
    for step in &scenario.steps {
        match step {
            Step::Sleep(ms) => tokio::time::sleep(Duration::from_millis(*ms)).await,
            Step::Http(http) => {
                let headers: Vec<(&str, &str)> =
                    http.headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
                let body: &[u8] = match &http.body {
                    Body::None => b"",
                    Body::Text(text) => text.as_bytes(),
                    Body::Bytes(bytes) => bytes,
                };
                let request = Request {
                    method: http.method,
                    path: http.path,
                    headers: &headers,
                    body,
                };
                let response = raw_http::send(port, &request)
                    .await
                    .unwrap_or_else(|e| panic!("{}: {e}", http.name));
                recorded.push(json!({
                    "name": http.name,
                    "request": { "method": http.method, "path": http.path, "headers": http.headers, "body_len": body.len() },
                    "response": { "status": response.status, "headers": response.headers, "body": response.body },
                }));
            }
        }
    }
    proc.kill().await;
    json!({ "scenario": scenario.name, "max_meetings": scenario.max_meetings, "steps": recorded })
}

fn compare_or_record(backend: &Backend, name: &str, actual: Value) {
    let path = golden_path(name);
    if backend.recording() {
        let text = serde_json::to_string_pretty(&actual).expect("json") + "\n";
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap_or_else(|e| panic!("{}: goldens are exclusive-create: {e}", path.display()));
        std::io::Write::write_all(&mut file, text.as_bytes()).expect("write golden");
        return;
    }
    let golden: Value = serde_json::from_str(
        &std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
    )
    .expect("golden json");
    let (want, got) = (
        golden["steps"].as_array().expect("steps"),
        actual["steps"].as_array().expect("steps"),
    );
    assert_eq!(want.len(), got.len(), "{name}: step count");
    for (w, g) in want.iter().zip(got) {
        assert_eq!(
            w["request"], g["request"],
            "{name}/{}: request definition drifted",
            w["name"]
        );
        let (mut want_response, mut got_response) = (w["response"].clone(), g["response"].clone());
        // Documented framing divergence: Go answers a malformed request target close-delimited
        // (no length); hyper frames the same bytes as chunked, which the client decodes.
        if w["name"] == "bad-percent" {
            for response in [&mut want_response, &mut got_response] {
                if let Some(headers) = response["headers"].as_array_mut() {
                    headers.retain(|h| h[0] != "content-length");
                }
            }
        }
        assert_eq!(
            want_response, got_response,
            "{name}/{}: response differs from recorded Go",
            w["name"]
        );
    }
    println!("GOLDEN-REPLAY: asrbot control :: {name}");
}

/// One test per scenario so each replay is selectable (and receipted) on its own.
async fn replay(name: &str) {
    let backend = Backend::from_env();
    let scenario = scenarios()
        .into_iter()
        .find(|s| s.name == name)
        .expect("scenario");
    let actual = run_scenario(&backend, &scenario).await;
    compare_or_record(&backend, &format!("control-{name}"), actual);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_auth_matches_recorded_go() {
    replay("auth").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_mux_matches_recorded_go() {
    replay("mux").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_start_body_matches_recorded_go() {
    replay("start-body").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_capacity_matches_recorded_go() {
    replay("capacity").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_zero_capacity_matches_recorded_go() {
    replay("zero-capacity").await;
}

// ---- process lifecycle: startup refusals, listen failure, graceful stop ----

struct Startup {
    name: &'static str,
    env: Vec<(&'static str, String)>,
}

fn startups(busy_port: u16) -> Vec<Startup> {
    let base = |listen: &str, token: &str| -> Vec<(&'static str, String)> {
        vec![
            ("ASR_LISTEN", listen.to_owned()),
            ("ASR_TOKEN", token.to_owned()),
            ("LIVEKIT_URL", "ws://127.0.0.1:1".into()),
        ]
    };
    vec![
        Startup {
            name: "refuse-non-loopback",
            env: base("0.0.0.0:7890", "t"),
        },
        Startup {
            name: "refuse-wildcard-host",
            env: base(":7890", "t"),
        },
        Startup {
            name: "refuse-hostname",
            env: base("example.com:7890", "t"),
        },
        Startup {
            name: "refuse-missing-port",
            env: base("127.0.0.1", "t"),
        },
        Startup {
            name: "refuse-too-many-colons",
            env: base("::1:7890", "t"),
        },
        Startup {
            name: "refuse-empty-token",
            env: base("127.0.0.1:7890", ""),
        },
        Startup {
            name: "listen-conflict",
            env: base(&format!("127.0.0.1:{busy_port}"), "t"),
        },
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_refusals_and_listen_failure_match_recorded_go() {
    let backend = Backend::from_env();
    let busy = std::net::TcpListener::bind("127.0.0.1:0").expect("busy port");
    let busy_port = busy.local_addr().unwrap().port();
    let mut recorded = Vec::new();
    for startup in startups(busy_port) {
        let env: Vec<(String, String)> = startup
            .env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect();
        let (code, lines) = spawn(&backend, &env).finish(Duration::from_secs(60)).await;
        // The conflicting port number is run-specific.
        let lines: Vec<String> = lines
            .into_iter()
            .map(|l| l.replace(&busy_port.to_string(), "<busy-port>"))
            .collect();
        recorded.push(json!({ "name": startup.name, "exit_code": code, "stdout": lines }));
    }
    drop(busy);
    compare_or_record(
        &backend,
        "startup",
        json!({ "scenario": "startup", "steps": startup_steps(&recorded) }),
    );
}

fn startup_steps(recorded: &[Value]) -> Vec<Value> {
    recorded.iter().map(|r| json!({ "name": r["name"], "request": { "env": r["name"] }, "response": { "exit_code": r["exit_code"], "stdout": r["stdout"] } })).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn graceful_stop_logs_match_recorded_go() {
    let backend = Backend::from_env();
    let port = free_port();
    let env = vec![
        ("ASR_LISTEN".to_owned(), format!("127.0.0.1:{port}")),
        ("ASR_TOKEN".to_owned(), "t".to_owned()),
        (
            "LIVEKIT_URL".to_owned(),
            "ws://livekit.example:7880".to_owned(),
        ),
        (
            "FUNASR_URL".to_owned(),
            "ws://funasr.example:10096".to_owned(),
        ),
        ("ASR_MAX_MEETINGS".to_owned(), "3".to_owned()),
        ("ASR_MAX_ACTIVE_TRACKS".to_owned(), "5".to_owned()),
    ];
    let mut proc = spawn(&backend, &env);
    wait_ready(port).await;
    proc.terminate().await;
    let (code, lines) = proc.finish(Duration::from_secs(30)).await;
    let lines: Vec<String> = lines
        .into_iter()
        .map(|l| l.replace(&port.to_string(), "<port>"))
        .collect();
    let actual = json!({ "scenario": "graceful-stop", "steps": [ { "name": "sigterm", "request": { "env": "listening" }, "response": { "exit_code": code, "stdout": lines } } ] });
    compare_or_record(&backend, "graceful-stop", actual);
    let _ = strip_time("{}");
}

// ---- mutant self-tests: the replay comparison must reject a wrong status per route ----

/// Flip the status of the first recorded success of `method path` and require the comparison to fail.
fn status_mutant_is_rejected(method: &str, path: &str) {
    for scenario in ["auth", "mux", "start-body", "capacity"] {
        let name = format!("control-{scenario}");
        let golden: Value =
            serde_json::from_str(&std::fs::read_to_string(golden_path(&name)).expect("golden"))
                .expect("json");
        let mut actual = golden.clone();
        let steps = actual["steps"].as_array_mut().expect("steps");
        let Some(step) = steps.iter_mut().find(|s| {
            s["request"]["method"] == method
                && s["request"]["path"] == path
                && s["response"]["status"] == 200
        }) else {
            continue;
        };
        step["response"]["status"] = json!(500);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            compare_or_record(&Backend::Rust, &name, actual)
        }));
        assert!(
            outcome.is_err(),
            "{method} {path}: a status mutant must be rejected by the replay comparison"
        );
        println!("MUTANT-REJECTED: {method} {path} :: status");
        return;
    }
    panic!("no recorded success for {method} {path}");
}

#[test]
fn status_mutant_get_healthz() {
    status_mutant_is_rejected("GET", "/healthz");
}

#[test]
fn status_mutant_get_status() {
    status_mutant_is_rejected("GET", "/status");
}

#[test]
fn status_mutant_post_start() {
    status_mutant_is_rejected("POST", "/start");
}

#[test]
fn status_mutant_post_stop() {
    status_mutant_is_rejected("POST", "/stop");
}
