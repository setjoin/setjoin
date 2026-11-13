use guard_core::GuardCore;
use offline_core::OfflineCore;
use serde_json::Value;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};

/// Serializes tests that install the process-global confinement policy
/// (set-then-act must be atomic against the parallel tests in this binary).
static POLICY_LOCK: Mutex<()> = Mutex::new(());

fn policy_guard() -> MutexGuard<'static, ()> {
    match POLICY_LOCK.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(), // a prior panic must not cascade
    }
}

fn core(dir: &tempfile::TempDir) -> Arc<OfflineCore> {
    let vault = dir.path().join("guard.db").to_string_lossy().to_string();
    let guard = GuardCore::new(vault, "pw".into()).expect("vault");
    let c = OfflineCore::new(guard);
    let db = dir
        .path()
        .join("drive-vault.db")
        .to_string_lossy()
        .to_string();
    c.open_store("drive".into(), db, "standard".into())
        .expect("open drive store");
    c
}

// ── trusted-confinement test wiring (Astra desktop-drive-bridge-unconfined) ──
//
// offline-core now enforces the trusted mirror-index + approved-origin policy
// natively (fail-closed when unset), so the happy-path tests install the same
// policy a real composition root would: the file's content is REGISTERED in
// the mirror index (dc_mirror, applied via exec() exactly like the TS mirror
// layer applies it) and the trusted roots/origins lists are widened.

/// The dc_* disk-index the TS mirror layer owns (webmail sync schema.ts).
const DC_MIRROR_DDL: &str = "CREATE TABLE IF NOT EXISTS dc_mirror (
    node_id INTEGER PRIMARY KEY, space_id INTEGER NOT NULL, rel_path TEXT NOT NULL,
    disk_sha256 TEXT, disk_size INTEGER, disk_mtime_ms INTEGER,
    base_version_id INTEGER, materialized_of_version INTEGER)";

fn file_sha256(path: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path).expect("open for sha");
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).expect("read for sha");
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    hex::encode(hasher.finalize())
}

/// Register `src` in the mirror index under its real root-relative PATH (the
/// r2 membership check binds rel_path AND content — a row for some other path
/// would not authorize this file) and install the file's directory as the
/// trusted import root, with `origins` as the chunk allowlist
/// (drive_set_confinement replaces the whole policy — each test installs
/// exactly what it needs before acting).
fn register_mirror_file(c: &OfflineCore, dir: &tempfile::TempDir, src: &str, origins: &[String]) {
    c.exec("drive".into(), DC_MIRROR_DDL.into(), "[]".into())
        .expect("apply dc_mirror DDL");
    let sha = file_sha256(src);
    let rel = std::path::Path::new(src)
        .file_name()
        .expect("src has a file name")
        .to_string_lossy()
        .to_string();
    c.exec(
        "drive".into(),
        "INSERT INTO dc_mirror (node_id, space_id, rel_path, disk_sha256) \
         VALUES ((SELECT COALESCE(MAX(node_id), 0) + 1 FROM dc_mirror), 1, ?1, ?2)"
            .into(),
        format!("[\"{rel}\",\"{sha}\"]"),
    )
    .expect("register mirror content");
    offline_core::drive::drive_set_confinement(
        vec![dir.path().to_string_lossy().to_string()],
        origins.to_vec(),
    );
}

/// Approve `origin` for chunk fetch/push (empty roots — chunk-only tests).
fn approve_chunk_origin(origin: &str) {
    offline_core::drive::drive_set_confinement(vec![], vec![origin.to_string()]);
}

/// A distinctive plaintext marker long enough to never occur in ciphertext by chance.
const MARKER: &[u8] = b"SETJOIN-P3-PLAINTEXT-CANARY-0123456789-ABCDEFGHIJKLMNOPQRSTUV";

fn write_src(dir: &tempfile::TempDir, len: usize) -> String {
    // Deterministic but non-trivial content, with the canary embedded mid-file.
    let mut buf = vec![0u8; len];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    if len > MARKER.len() + 100 {
        buf[100..100 + MARKER.len()].copy_from_slice(MARKER);
    }
    let p = dir.path().join("src.bin");
    std::fs::File::create(&p).unwrap().write_all(&buf).unwrap();
    p.to_string_lossy().to_string()
}

#[test]
fn import_splits_at_4mib_and_hashes_correctly() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let src = write_src(&dir, 4 * 1024 * 1024 + 4096 + 1); // 4 MiB + 4 KiB + 1 → 2 chunks
    register_mirror_file(&c, &dir, &src, &[]);
    let m: Value =
        serde_json::from_str(&c.drive_import_file("drive".into(), src.clone()).unwrap()).unwrap();
    assert_eq!(m["size"], 4 * 1024 * 1024 + 4096 + 1);
    let chunks = m["chunks"].as_array().unwrap();
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0]["size"], 4 * 1024 * 1024);
    assert_eq!(chunks[1]["size"], 4096 + 1);
    // whole-file sha256 matches an independent computation
    use sha2::{Digest, Sha256};
    let want = hex::encode(Sha256::digest(std::fs::read(&src).unwrap()));
    assert_eq!(m["contentSha256"].as_str().unwrap(), want);
    // both chunks present + sizes round-trip through has/dc_chunks
    for ch in chunks {
        assert!(c
            .drive_has_chunk("drive".into(), ch["sha256"].as_str().unwrap().into())
            .unwrap());
    }
}

#[test]
fn import_empty_file_yields_empty_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let src = write_src(&dir, 0);
    register_mirror_file(&c, &dir, &src, &[]);
    let m: Value =
        serde_json::from_str(&c.drive_import_file("drive".into(), src).unwrap()).unwrap();
    assert_eq!(m["size"], 0);
    assert_eq!(m["chunks"].as_array().unwrap().len(), 0);
    assert_eq!(
        m["contentSha256"],
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn import_is_idempotent_insert_or_ignore() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let src = write_src(&dir, 8192);
    register_mirror_file(&c, &dir, &src, &[]);
    let m1 = c.drive_import_file("drive".into(), src.clone()).unwrap();
    let m2 = c.drive_import_file("drive".into(), src).unwrap();
    assert_eq!(m1, m2);
    let rows = c
        .query(
            "drive".into(),
            "SELECT COUNT(*) AS n FROM dc_chunks".into(),
            "[]".into(),
        )
        .unwrap();
    assert!(
        rows.contains("\"n\":1"),
        "re-import must not duplicate rows: {rows}"
    );
}

#[test]
fn delete_chunks_removes_and_reports_count() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let src = write_src(&dir, 8192);
    register_mirror_file(&c, &dir, &src, &[]);
    let m: Value =
        serde_json::from_str(&c.drive_import_file("drive".into(), src).unwrap()).unwrap();
    let sha = m["chunks"][0]["sha256"].as_str().unwrap().to_string();
    let n = c
        .drive_delete_chunks("drive".into(), format!("[\"{sha}\"]"))
        .unwrap();
    assert_eq!(n, 1);
    assert!(!c.drive_has_chunk("drive".into(), sha).unwrap());
    assert_eq!(
        c.drive_delete_chunks("drive".into(), "[\"deadbeef\"]".into())
            .unwrap(),
        0
    ); // idempotent
}

/// THE I-11(a) gate at the layer that owns bytes: after import into the vault,
/// no file on disk (except the caller-owned source) contains the plaintext canary —
/// SQLCipher pages are ciphertext, -wal included.
#[test]
fn no_plaintext_on_disk_after_import() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let src = write_src(&dir, 2 * 1024 * 1024);
    register_mirror_file(&c, &dir, &src, &[]);
    c.drive_import_file("drive".into(), src.clone()).unwrap();
    // flush WAL content to whatever files exist right now
    c.exec("drive".into(), "COMMIT".into(), "[]".into()).ok(); // no open txn — best-effort
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let p = entry.unwrap().path();
        if p.to_string_lossy() == src {
            continue;
        } // the plaintext source is the CALLER's to delete (§3.6)
        let bytes = std::fs::read(&p).unwrap_or_default();
        assert!(
            bytes.windows(MARKER.len()).all(|w| w != MARKER),
            "plaintext canary found in {p:?} — vault leaked plaintext to disk"
        );
    }
}

// ── drive_fetch_chunk / drive_push_chunk ───────────────────────────────────

/// (method, auth header, body) captured off the one-shot server below.
type CapturedRequest = std::sync::Arc<std::sync::Mutex<Option<(String, String, Vec<u8>)>>>;

/// One-shot local HTTP server: records the request (method, auth header, body),
/// replies with `status` + `body`. Returns (url, captured) where captured fills in
/// after the request lands.
fn one_shot_server(status: u16, body: Vec<u8>) -> (String, CapturedRequest) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}/chunk", server.server_addr());
    let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
    let cap = captured.clone();
    std::thread::spawn(move || {
        if let Ok(mut req) = server.recv() {
            let auth = req
                .headers()
                .iter()
                .find(|h| h.field.equiv("Authorization"))
                .map(|h| h.value.as_str().to_string())
                .unwrap_or_default();
            let mut reqbody = Vec::new();
            req.as_reader().read_to_end(&mut reqbody).unwrap();
            *cap.lock().unwrap() = Some((req.method().as_str().to_string(), auth, reqbody));
            let resp = tiny_http::Response::from_data(body).with_status_code(status);
            let _ = req.respond(resp);
        }
    });
    (url, captured)
}

#[test]
fn fetch_chunk_streams_verifies_and_stores() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let payload = vec![7u8; 5000];
    use sha2::{Digest, Sha256};
    let sha = hex::encode(Sha256::digest(&payload));
    let (url, cap) = one_shot_server(200, payload.clone());
    approve_chunk_origin(&url);
    c.drive_fetch_chunk("drive".into(), url, "tok123".into(), sha.clone(), 5000)
        .unwrap();
    assert!(c.drive_has_chunk("drive".into(), sha).unwrap());
    let (method, auth, _) = cap.lock().unwrap().clone().unwrap();
    assert_eq!(method, "GET");
    assert_eq!(auth, "Bearer tok123");
}

#[test]
fn fetch_chunk_hash_mismatch_is_integrity_and_stores_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let (url, _) = one_shot_server(200, vec![7u8; 5000]);
    approve_chunk_origin(&url);
    let wrong = "0".repeat(64);
    let e = c
        .drive_fetch_chunk("drive".into(), url, "t".into(), wrong.clone(), 5000)
        .unwrap_err();
    assert!(
        matches!(e, offline_core::OfflineError::Integrity(_)),
        "got {e:?}"
    );
    assert!(!c.drive_has_chunk("drive".into(), wrong).unwrap());
}

#[test]
fn fetch_chunk_size_mismatch_is_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let payload = vec![7u8; 5000];
    use sha2::{Digest, Sha256};
    let sha = hex::encode(Sha256::digest(&payload));
    let (url, _) = one_shot_server(200, payload);
    approve_chunk_origin(&url);
    let e = c
        .drive_fetch_chunk("drive".into(), url, "t".into(), sha, 4999)
        .unwrap_err();
    assert!(matches!(e, offline_core::OfflineError::Integrity(_)));
}

#[test]
fn fetch_chunk_existing_row_is_ok_without_network() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let src = write_src(&dir, 4096);
    register_mirror_file(&c, &dir, &src, &["http://127.0.0.1:1".to_string()]);
    let m: Value =
        serde_json::from_str(&c.drive_import_file("drive".into(), src).unwrap()).unwrap();
    let sha = m["chunks"][0]["sha256"].as_str().unwrap().to_string();
    // dead URL — must NOT be contacted for an already-present chunk (idempotency, §3.6)
    c.drive_fetch_chunk(
        "drive".into(),
        "http://127.0.0.1:1/x".into(),
        "t".into(),
        sha,
        4096,
    )
    .unwrap();
}

#[test]
fn fetch_chunk_http_error_status_maps_to_http_variant() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let (url, _) = one_shot_server(503, b"nope".to_vec());
    approve_chunk_origin(&url);
    let e = c
        .drive_fetch_chunk("drive".into(), url, "t".into(), "0".repeat(64), 4)
        .unwrap_err();
    assert!(
        matches!(e, offline_core::OfflineError::Http(_)),
        "got {e:?}"
    );
}

#[test]
fn push_chunk_uploads_bytes_and_returns_status() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let src = write_src(&dir, 4096);
    register_mirror_file(&c, &dir, &src, &[]);
    let m: Value =
        serde_json::from_str(&c.drive_import_file("drive".into(), src.clone()).unwrap()).unwrap();
    let sha = m["chunks"][0]["sha256"].as_str().unwrap().to_string();
    let (url, cap) = one_shot_server(201, Vec::new());
    approve_chunk_origin(&url);
    let status = c
        .drive_push_chunk("drive".into(), url, "tok".into(), sha)
        .unwrap();
    assert_eq!(status, 201);
    let (method, auth, body) = cap.lock().unwrap().clone().unwrap();
    assert_eq!(method, "PUT");
    assert_eq!(auth, "Bearer tok");
    assert_eq!(body, std::fs::read(&src).unwrap());
}

#[test]
fn push_chunk_missing_from_vault_errors() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    approve_chunk_origin("http://127.0.0.1:1");
    let e = c
        .drive_push_chunk(
            "drive".into(),
            "http://127.0.0.1:1/x".into(),
            "t".into(),
            "0".repeat(64),
        )
        .unwrap_err();
    assert!(matches!(e, offline_core::OfflineError::Database(_)));
}

// ── loopback render server ──────────────────────────────────────────────────

fn import_and_grant(
    dir: &tempfile::TempDir,
    c: &Arc<OfflineCore>,
    len: usize,
) -> (u16, String, Vec<u8>) {
    let src = write_src(dir, len);
    register_mirror_file(c, dir, &src, &[]);
    let manifest = c.drive_import_file("drive".into(), src.clone()).unwrap();
    let port: Value =
        serde_json::from_str(&c.clone().drive_serve_start("drive".into()).unwrap()).unwrap();
    let port = port["port"].as_u64().unwrap() as u16;
    // grant expects {"chunks":[…],"size":N,"contentType":"…"} — reshape the import manifest
    let m: Value = serde_json::from_str(&manifest).unwrap();
    let grant = serde_json::json!({
        "chunks": m["chunks"], "size": m["size"], "contentType": "video/mp4"
    });
    let ticket = c
        .drive_serve_grant("drive".into(), grant.to_string())
        .unwrap();
    (port, ticket, std::fs::read(&src).unwrap())
}

fn http_get(port: u16, path: &str, range: Option<&str>) -> (u16, Vec<u8>, Vec<(String, String)>) {
    let mut req = ureq::agent().get(&format!("http://127.0.0.1:{port}{path}"));
    if let Some(r) = range {
        req = req.set("Range", r);
    }
    match req.call() {
        Ok(resp) | Err(ureq::Error::Status(_, resp)) => {
            let status = resp.status();
            let headers: Vec<(String, String)> = resp
                .headers_names()
                .iter()
                .map(|n| (n.clone(), resp.header(n).unwrap_or("").to_string()))
                .collect();
            let mut body = Vec::new();
            resp.into_reader().read_to_end(&mut body).unwrap();
            (status, body, headers)
        }
        Err(e) => panic!("transport: {e}"),
    }
}

#[test]
fn serve_full_body_roundtrips_across_chunk_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let (port, ticket, want) = import_and_grant(&dir, &c, 9 * 1024 * 1024); // 3 chunks
    let (status, body, headers) = http_get(port, &ticket, None);
    assert_eq!(status, 200);
    assert_eq!(body, want);
    let h = |n: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.clone())
    };
    assert_eq!(h("Cache-Control").as_deref(), Some("no-store"));
    assert_eq!(h("Content-Type").as_deref(), Some("video/mp4"));
    assert_eq!(h("Accept-Ranges").as_deref(), Some("bytes"));
}

#[test]
fn serve_range_seek_mid_file_is_exact() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let (port, ticket, want) = import_and_grant(&dir, &c, 9 * 1024 * 1024);
    // a range crossing the chunk-1/chunk-2 boundary — the video-seek case
    let (start, end) = (4 * 1024 * 1024 - 100, 4 * 1024 * 1024 + 99);
    let (status, body, headers) = http_get(port, &ticket, Some(&format!("bytes={start}-{end}")));
    assert_eq!(status, 206);
    assert_eq!(body, want[start..=end]);
    let cr = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Range"))
        .unwrap()
        .1
        .clone();
    assert_eq!(cr, format!("bytes {start}-{end}/{}", want.len()));
}

#[test]
fn serve_open_ended_and_suffix_ranges() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let (port, ticket, want) = import_and_grant(&dir, &c, 5 * 1024 * 1024);
    let (s, body, _) = http_get(port, &ticket, Some("bytes=5242000-"));
    assert_eq!(s, 206);
    assert_eq!(body, want[5242000..]);
    let (s, body, _) = http_get(port, &ticket, Some("bytes=-1000")); // last 1000 bytes
    assert_eq!(s, 206);
    assert_eq!(body, want[want.len() - 1000..]);
    let (s, _, _) = http_get(port, &ticket, Some("bytes=999999999-")); // out of range
    assert_eq!(s, 416);
}

#[test]
fn unknown_and_revoked_tickets_404_and_tickets_are_random() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let (port, ticket, _) = import_and_grant(&dir, &c, 4096);
    let (s, _, _) = http_get(port, "/t/00000000000000000000000000000000", None);
    assert_eq!(s, 404);
    // a second grant gets a DIFFERENT ticket (128-bit random, single-manifest)
    let m = serde_json::json!({ "chunks": [], "size": 0, "contentType": "text/plain" });
    let t2 = c.drive_serve_grant("drive".into(), m.to_string()).unwrap();
    assert_ne!(ticket, t2);
    c.drive_serve_revoke("drive".into(), ticket.trim_start_matches("/t/").into())
        .unwrap();
    let (s, _, _) = http_get(port, &ticket, None);
    assert_eq!(s, 404, "revoked ticket must 404");
}

#[test]
fn serve_stop_and_wipe_kill_the_listener() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let (port, _ticket, _) = import_and_grant(&dir, &c, 4096);
    c.drive_serve_stop("drive".into()).unwrap();
    assert!(
        ureq::agent()
            .get(&format!("http://127.0.0.1:{port}/t/x"))
            .call()
            .is_err(),
        "stopped server must refuse connections"
    );
    // restart, then wipe must also stop it (a wiped vault may not keep serving)
    let (port2, _t, _) = import_and_grant(&dir, &c, 4096);
    c.wipe("drive".into()).unwrap();
    assert!(ureq::agent()
        .get(&format!("http://127.0.0.1:{port2}/t/x"))
        .call()
        .is_err());
}

#[test]
fn serve_start_is_idempotent_per_app_key() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let _policy = policy_guard();
    let p1 = c.clone().drive_serve_start("drive".into()).unwrap();
    let p2 = c.clone().drive_serve_start("drive".into()).unwrap();
    assert_eq!(p1, p2);
}
