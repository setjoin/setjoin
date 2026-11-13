//! Frozen-Go handshake recordings plus live Go/Rust session interchange at the TLS socket.
#[path = "../../../tests/conformance/tlsfront/peer.rs"]
mod peer;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use setjoin_tls::Frontend;
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::Duration,
};
use tokio::io::AsyncWriteExt;

struct Work(PathBuf);
impl Work {
    fn new(case: &str) -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        let dir = root
            .join("test-results/gofree-tlsfront")
            .join(format!("{case}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let recorded = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/conformance/tlsfront/tls13-resumed.json");
        if let Ok(bytes) = std::fs::read(recorded) {
            let saved: Value = serde_json::from_slice(&bytes).unwrap();
            std::fs::write(
                dir.join("cert.pem"),
                saved["certificate_pem"].as_str().unwrap(),
            )
            .unwrap();
            std::fs::write(
                dir.join("key.pem"),
                saved["public_test_key_pem"].as_str().unwrap(),
            )
            .unwrap();
            return Self(dir);
        }
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        params.not_after = rcgen::date_time_ymd(2037, 1, 1);
        let cert = params.self_signed(&key).unwrap();
        std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();
        Self(dir)
    }
    fn config(&self) -> Value {
        let keys = std::fs::read(self.0.join("keys.json"))
            .ok()
            .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap())
            .unwrap_or_else(|| json!([STANDARD.encode([7; 32])]));
        json!({"Cert":self.0.join("cert.pem"),"Key":self.0.join("key.pem"),"Raw":true,"Keys":keys})
    }
    fn rust(&self) -> Arc<Frontend> {
        let frontend = Frontend::from_env(&|name| match name {
            "TLS_CERT_FILE" => Some(self.0.join("cert.pem").display().to_string()),
            "TLS_KEY_FILE" => Some(self.0.join("key.pem").display().to_string()),
            _ => None,
        })
        .unwrap()
        .unwrap();
        frontend.set_ticket_keys([7; 32], None);
        frontend
    }
}
impl Drop for Work {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}
struct GoServer(peer::Server, String);
impl GoServer {
    async fn start(work: &Work) -> Self {
        let _ = std::fs::remove_file(work.0.join("ready"));
        let mut config = work.config();
        config["Mode"] = json!("server");
        config["Listen"] = json!("127.0.0.1:0");
        config["Ready"] = json!(work.0.join("ready"));
        config["Dump"] = json!(work.0.join("go-dump.json"));
        let child = peer::Server::spawn(&repo_root(), &config, &work.0.join("server.log"));
        let mut server = Self(child, String::new());
        for _ in 0..250 {
            if let Ok(addr) = std::fs::read_to_string(work.0.join("ready")) {
                server.1 = addr;
                return server;
            }
            assert!(
                server.0.try_wait().unwrap().is_none(),
                "Go server exited: {}",
                std::fs::read_to_string(work.0.join("server.log")).unwrap()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("Go peer did not start");
    }
}

fn probe(work: &Work, addr: &str, version: u16, session: &str, out: &str) -> Value {
    let mut config = work.config();
    config["Mode"] = json!("probe");
    config["Listen"] = json!(addr);
    config["SNI"] = json!("localhost");
    config["ALPN"] = json!("http/1.1");
    config["Version"] = json!(version);
    config["Session"] = json!(work.0.join(session));
    config["Out"] = json!(work.0.join(out));
    let output = peer::run(&repo_root(), &config);
    assert!(
        output.status.success(),
        "Go probe: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&std::fs::read(work.0.join(out)).unwrap()).unwrap()
}
async fn rust_server(frontend: Arc<Frontend>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = frontend.accept(stream).await.unwrap();
        tls.write_all(b"ok\n").await.unwrap();
        tls.shutdown().await.unwrap();
    });
    (addr, task)
}

fn recording_path(version: u16) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../tests/conformance/tlsfront/tls{}-resumed.json",
        if version == 0x304 { 13 } else { 12 }
    ))
}

// Retarget only volatile timestamps, then authenticate the same recorded Go
// state with the public fixture key using audited primitives. Expected behavior
// and the PSK/certificate are never regenerated from Rust's implementation.
fn seed_recorded_session(work: &Work, recorded: &Value) {
    seed_session_with_age(work, recorded, 0);
}
fn seed_session_with_age(work: &Work, recorded: &Value, age: u64) {
    use aes::cipher::{KeyIvInit, StreamCipher};
    use sha2::{Digest, Sha512};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut plain = STANDARD
        .decode(recorded["server_state"]["plain"].as_str().unwrap())
        .unwrap();
    assert_eq!(plain[0], 3);
    assert_eq!(plain[2], 1);
    plain[5..13].copy_from_slice(&now.saturating_sub(age).to_be_bytes());
    let expanded = Sha512::digest([7; 32]);
    let iv = [91; 16]; // test-only retargeting under a public fixture key
    let mut ticket = iv.to_vec();
    ticket.extend_from_slice(&plain);
    ctr::Ctr128BE::<aes::Aes128>::new_from_slices(&expanded[16..32], &iv)
        .unwrap()
        .apply_keystream(&mut ticket[16..]);
    let mac = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &expanded[32..48]),
        &ticket,
    );
    ticket.extend_from_slice(mac.as_ref());
    let mut session = recorded["client_session"].clone();
    let mut state = STANDARD.decode(session["State"].as_str().unwrap()).unwrap();
    assert_eq!(state[0], 3);
    assert_eq!(state[2], 2);
    state[5..13].copy_from_slice(&now.to_be_bytes());
    if state[1] == 4 {
        let end = state.len();
        state[end - 12..end - 4].copy_from_slice(&(now + 7 * 86400).to_be_bytes());
    }
    session["State"] = json!(STANDARD.encode(state));
    session["Ticket"] = json!(STANDARD.encode(ticket));
    std::fs::write(
        work.0.join("session"),
        serde_json::to_vec(&session).unwrap(),
    )
    .unwrap();
}

async fn replay_go_session(version: u16) {
    let work = Work::new(&format!("go-to-rust-{version}"));
    if std::env::var_os("GOFREE_RECORD_TLSFRONT").is_some() {
        let go = GoServer::start(&work).await;
        let full = probe(&work, &go.1, version, "session", "first.json");
        assert_eq!(full["resumed"], false);
        let resumed = probe(&work, &go.1, version, "session", "go-resumed.json");
        assert_eq!(resumed["resumed"], true);
        let source = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        let dump: Value =
            serde_json::from_slice(&std::fs::read(work.0.join("go-dump.json")).unwrap()).unwrap();
        let session: Value =
            serde_json::from_slice(&std::fs::read(work.0.join("session")).unwrap()).unwrap();
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(recording_path(version))
            .expect("recordings are immutable; choose a new case instead of overwriting");
        file.write_all(&serde_json::to_vec_pretty(&json!({"format":1,"go_source":String::from_utf8(source.stdout).unwrap().trim(),"observation":[full,resumed],"server_state":dump,"client_session":session,"certificate_pem":std::fs::read_to_string(work.0.join("cert.pem")).unwrap(),"public_test_key_pem":std::fs::read_to_string(work.0.join("key.pem")).unwrap()})).unwrap()).unwrap();
    }
    let recorded: Value = serde_json::from_slice(
        &std::fs::read(recording_path(version)).expect("record the frozen-Go case first"),
    )
    .unwrap();
    seed_recorded_session(&work, &recorded);
    let (addr, server) = rust_server(work.rust()).await;
    let actual = probe(&work, &addr, version, "session", "rust-resumed.json");
    server.await.unwrap();
    assert_eq!(
        actual, recorded["observation"][1],
        "Go's recorded client session must survive the Go-to-Rust swap"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_issued_tls13_ticket_resumes_on_rust() {
    replay_go_session(0x304).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_issued_tls12_ticket_resumes_on_rust() {
    replay_go_session(0x303).await;
}

fn inspect(work: &Work) -> Value {
    let mut config = work.config();
    config["Mode"] = json!("inspect");
    config["Session"] = json!(work.0.join("session"));
    config["Out"] = json!(work.0.join("inspect.json"));
    let output = peer::run(&repo_root(), &config);
    assert!(
        output.status.success(),
        "Go consumer: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&std::fs::read(work.0.join("inspect.json")).unwrap()).unwrap()
}
async fn check_native_format(version: u16) {
    let work = Work::new(&format!("rust-to-go-format-{version}"));
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../tests/conformance/tlsfront/tls{}-session-metadata.json",
        if version == 0x304 { 13 } else { 12 }
    ));
    if std::env::var_os("GOFREE_RECORD_TLSFRONT").is_some() {
        let go = GoServer::start(&work).await;
        probe(&work, &go.1, version, "session", "go-full.json");
        let expected = inspect(&work);
        assert_eq!(expected["accepted"], true);
        let source = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&serde_json::to_vec_pretty(&json!({"format":1,"go_source":String::from_utf8(source.stdout).unwrap().trim(),"observation":expected})).unwrap()).unwrap();
        std::fs::remove_file(work.0.join("session")).unwrap();
    }
    let (addr, server) = rust_server(work.rust()).await;
    probe(&work, &addr, version, "session", "rust-full.json");
    server.await.unwrap();
    let actual = inspect(&work);
    let recorded: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(actual, recorded["observation"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_issued_ticket_is_go_compatible_encrypted_session_state() {
    check_native_format(0x304).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_issued_tls12_ticket_is_go_compatible() {
    check_native_format(0x303).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ticket_rotation_and_rejections_match_recorded_go() {
    let work = Work::new("ticket-generations");
    let session: Value =
        serde_json::from_slice(&std::fs::read(recording_path(0x304)).unwrap()).unwrap();
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/tlsfront/ticket-generations.json");
    let cases = [
        ("current", 7, None, 0, false),
        ("previous", 9, Some(7), 0, false),
        ("older-rejected", 9, Some(8), 0, false),
        ("bad-mac", 7, None, 0, true),
        ("expired", 7, None, 8 * 86400, false),
    ];
    let prepare = |current: u8, previous: Option<u8>, age: u64, tamper: bool| {
        let mut keys = vec![STANDARD.encode([current; 32])];
        if let Some(p) = previous {
            keys.push(STANDARD.encode([p; 32]));
        }
        std::fs::write(work.0.join("keys.json"), serde_json::to_vec(&keys).unwrap()).unwrap();
        seed_session_with_age(&work, &session, age);
        if tamper {
            let mut state: Value =
                serde_json::from_slice(&std::fs::read(work.0.join("session")).unwrap()).unwrap();
            let mut ticket = STANDARD.decode(state["Ticket"].as_str().unwrap()).unwrap();
            *ticket.last_mut().unwrap() ^= 1;
            state["Ticket"] = json!(STANDARD.encode(ticket));
            std::fs::write(work.0.join("session"), serde_json::to_vec(&state).unwrap()).unwrap();
        }
    };
    if std::env::var_os("GOFREE_RECORD_TLSFRONT").is_some() {
        let mut observations = Vec::new();
        for (case, current, previous, age, tamper) in cases {
            prepare(current, previous, age, tamper);
            let go = GoServer::start(&work).await;
            observations.push(
                json!({"case":case,"observation":probe(&work,&go.1,0x304,"session","go.json")}),
            );
        }
        use std::io::Write;
        let source = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        out.write_all(&serde_json::to_vec_pretty(&json!({"format":1,"go_source":String::from_utf8(source.stdout).unwrap().trim(),"observation":observations})).unwrap()).unwrap();
    }
    let recorded: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    for (index, (case, current, previous, age, tamper)) in cases.into_iter().enumerate() {
        prepare(current, previous, age, tamper);
        let frontend = work.rust();
        frontend.set_ticket_keys([current; 32], previous.map(|p| [p; 32]));
        let (addr, server) = rust_server(frontend).await;
        let actual = probe(&work, &addr, 0x304, "session", "rust.json");
        server.await.unwrap();
        assert_eq!(
            actual, recorded["observation"][index]["observation"],
            "{case}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ticket_key_mutant_is_rejected_by_the_oracle() {
    let work = Work::new("ticket-mutant");
    let recorded: Value =
        serde_json::from_slice(&std::fs::read(recording_path(0x304)).unwrap()).unwrap();
    seed_recorded_session(&work, &recorded);
    let frontend = work.rust();
    frontend.set_ticket_keys([8; 32], None);
    let (addr, server) = rust_server(frontend).await;
    let actual = probe(&work, &addr, 0x304, "session", "rust.json");
    server.await.unwrap();
    assert_ne!(
        actual, recorded["observation"][1],
        "oracle accepted a broken ticket-key consumer"
    );
    assert_eq!(actual["resumed"], false);
}
