//! End-to-end confinement tests for the Drive byte plane (deep-scan package
//! desktop-drive-bridge-unconfined). Complements `drive_test.rs` (which pins
//! the happy paths): every test here proves a REJECTION happens at the
//! offline-core boundary — before any file read, vault mutation, or network
//! dial — for both `drive_import_file` (file subvector) and
//! `drive_fetch_chunk`/`drive_push_chunk` (network subvector). These tests
//! exercise the SHARED implementation both napi twins inherit via `include!`
//! (`native_impl.rs`), plus the UniFFI mobile path.
//!
//! Two layers are pinned here:
//!   - the policy-free transport/path floor (unchanged), and
//!   - the TRUSTED shell-installed policy (Astra desktop-drive-bridge-
//!     unconfined #1/#2): mirror-index membership + import roots for imports,
//!     and the approved-origin allowlist for chunk URLs — installed via
//!     `drive_set_confinement`, empty-by-default = fail-closed.
//!
//! The policy is process-global (each test binary owns one), so every policy-
//! mutating test holds `POLICY_LOCK` for its whole body.

use offline_core::OfflineCore;
use sha2::Digest;
use std::io::Write;
use std::sync::{Mutex, MutexGuard};

/// Serializes tests that install a confinement policy (the policy is
/// process-global by design — one shell session, one OfflineCore).
static POLICY_LOCK: Mutex<()> = Mutex::new(());

fn policy_guard() -> MutexGuard<'static, ()> {
    match POLICY_LOCK.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(), // a prior panic must not cascade
    }
}

fn core(dir: &tempfile::TempDir) -> std::sync::Arc<OfflineCore> {
    let vault = dir.path().join("guard.db").to_string_lossy().to_string();
    let guard = guard_core::GuardCore::new(vault, "pw".into()).expect("vault");
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

fn marker_file(dir: &tempfile::TempDir) -> String {
    let p = dir.path().join("mirror-file.bin");
    std::fs::File::create(&p)
        .unwrap()
        .write_all(b"importable")
        .unwrap();
    p.to_string_lossy().to_string()
}

/// The dc_* disk-index the TS mirror layer owns (webmail sync schema.ts's
/// dc_mirror — the columns the membership query reads). Applied via exec(),
/// exactly how the TS layer applies it in production.
const DC_MIRROR_DDL: &str = "CREATE TABLE IF NOT EXISTS dc_mirror (
    node_id INTEGER PRIMARY KEY, space_id INTEGER NOT NULL, rel_path TEXT NOT NULL,
    disk_sha256 TEXT, disk_size INTEGER, disk_mtime_ms INTEGER,
    base_version_id INTEGER, materialized_of_version INTEGER)";

fn file_sha256(path: &str) -> String {
    let bytes = std::fs::read(path).expect("read file for sha");
    hex::encode(sha2::Sha256::digest(&bytes))
}

/// Register `src`'s content in the mirror index (a synced node's recorded
/// bytes) and install `root` as the trusted import root — the trusted wiring a
/// real composition root performs. Registers an EMPTY origin list: imports and
/// chunk I/O are independent.
fn register_mirror_file(c: &OfflineCore, root: &str, src: &str) {
    c.exec("drive".into(), DC_MIRROR_DDL.into(), "[]".into())
        .expect("apply dc_mirror DDL");
    let sha = file_sha256(src);
    c.exec(
        "drive".into(),
        "INSERT OR REPLACE INTO dc_mirror (node_id, space_id, rel_path, disk_sha256) \
         VALUES (1, 1, 'mirror-file.bin', ?1)"
            .into(),
        format!("[\"{sha}\"]"),
    )
    .expect("register mirror content");
    offline_core::drive::drive_set_confinement(vec![root.to_string()], vec![]);
}

// ── FILE subvector: non-mirror src_path rejected natively ────────────────────

#[test]
fn import_rejects_relative_paths_before_opening_anything() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let err = c
        .drive_import_file("drive".into(), "relative/mirror-file.bin".into())
        .expect_err("relative src_path must be rejected");
    assert!(err.to_string().contains("src_path rejected"), "{err}");
}

#[test]
fn import_rejects_parent_traversal_lexically() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    // Resolves (lexically) to a REAL file — still rejected: callers send
    // resolved paths, `..` is a traversal shape, not a filename.
    let sneaky = dir.path().join("sub").join("..").join("mirror-file.bin");
    std::fs::create_dir_all(dir.path().join("sub")).unwrap();
    std::fs::File::create(&sneaky)
        .unwrap()
        .write_all(b"x")
        .unwrap();
    let err = c
        .drive_import_file("drive".into(), sneaky.to_string_lossy().to_string())
        .expect_err("`..` components must be rejected");
    assert!(err.to_string().contains("src_path rejected"), "{err}");
    // And the vault must hold nothing from the attempt.
    assert!(!c
        .drive_has_chunk(
            "drive".into(),
            hex::encode(sha2::Sha256::digest(b"importable"))
        )
        .unwrap());
}

#[test]
fn import_rejects_missing_paths() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let err = c
        .drive_import_file("drive".into(), "/definitely/not/here.bin".into())
        .expect_err("missing src_path must be rejected");
    assert!(err.to_string().contains("src_path rejected"), "{err}");
}

#[test]
fn import_rejects_directories() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let err = c
        .drive_import_file("drive".into(), dir.path().to_string_lossy().to_string())
        .expect_err("directory src_path must be rejected");
    assert!(err.to_string().contains("src_path rejected"), "{err}");
}

#[cfg(unix)]
#[test]
fn import_rejects_symlinked_final_component() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let link = dir.path().join("link.bin");
    std::os::unix::fs::symlink("/etc/passwd", &link).unwrap();
    let err = c
        .drive_import_file("drive".into(), link.to_string_lossy().to_string())
        .expect_err("symlinked src_path must be rejected");
    assert!(err.to_string().contains("symlink"), "{err}");
}

// ── FILE subvector: trusted mirror-index membership (Astra item 1) ───────────

#[test]
fn import_is_fail_closed_without_a_confinement_policy() {
    let _policy = policy_guard();
    offline_core::drive::drive_set_confinement(vec![], vec![]);
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let src = marker_file(&dir);
    // The plain absolute regular file the old floor accepted is now denied:
    // with NO trusted import roots installed nothing imports, whatever its
    // shape (Astra item 2, r2 — absent roots are a rejection, not a fallback).
    let err = c
        .drive_import_file("drive".into(), src)
        .expect_err("an empty policy must reject every import");
    assert!(err.to_string().contains("no trusted import roots"), "{err}");
    assert!(!c
        .drive_has_chunk(
            "drive".into(),
            hex::encode(sha2::Sha256::digest(b"importable"))
        )
        .unwrap());
}

#[test]
fn import_rejects_even_registered_content_without_import_roots() {
    let _policy = policy_guard();
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let src = marker_file(&dir);
    // The content IS registered in dc_mirror — and the policy is still empty.
    // The r1 fallback ("content-membership gate alone applies") is gone:
    // absent import roots deny outright (Astra item 2, r2).
    c.exec("drive".into(), DC_MIRROR_DDL.into(), "[]".into())
        .unwrap();
    let sha = file_sha256(&src);
    c.exec(
        "drive".into(),
        "INSERT OR REPLACE INTO dc_mirror (node_id, space_id, rel_path, disk_sha256) \
         VALUES (1, 1, 'mirror-file.bin', ?1)"
            .into(),
        format!("[\"{sha}\"]"),
    )
    .unwrap();
    offline_core::drive::drive_set_confinement(vec![], vec![]);
    let err = c
        .drive_import_file("drive".into(), src)
        .expect_err("registered content without trusted roots must still be denied");
    assert!(err.to_string().contains("no trusted import roots"), "{err}");
    assert!(!c.drive_has_chunk("drive".into(), sha).unwrap());
}

#[test]
fn import_accepts_a_registered_file_inside_a_trusted_root() {
    let _policy = policy_guard();
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let src = marker_file(&dir);
    let root = dir.path().to_string_lossy().to_string();
    register_mirror_file(&c, &root, &src);
    // Ancestor-symlink layout tolerance (macOS /tmp → /private/tmp): both
    // sides are canonicalized, so configuring the root via a NON-canonical
    // path that reaches the same directory keeps the legitimate import working.
    c.drive_import_file("drive".into(), src)
        .expect("registered mirror file inside the trusted root must import");
}

#[test]
fn import_rejects_an_unindexed_file_inside_the_root() {
    let _policy = policy_guard();
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let src = marker_file(&dir);
    let root = dir.path().to_string_lossy().to_string();
    // Root installed, but the index has NO row for this file's content.
    c.exec("drive".into(), DC_MIRROR_DDL.into(), "[]".into())
        .unwrap();
    offline_core::drive::drive_set_confinement(vec![root], vec![]);
    let err = c
        .drive_import_file("drive".into(), src)
        .expect_err("unindexed file inside the root must be rejected");
    assert!(
        err.to_string().contains("not a registered mirrored file"),
        "{err}"
    );
}

#[test]
fn import_rejects_duplicate_content_at_an_unregistered_path() {
    let _policy = policy_guard();
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let src = marker_file(&dir);
    let root = dir.path().to_string_lossy().to_string();
    register_mirror_file(&c, &root, &src);
    // A byte-identical copy INSIDE the trusted root at a DIFFERENT path: the
    // r1 content-only membership (`WHERE disk_sha256 = ?1`) approved exactly
    // this file. Authorization is now bound to the requested path —
    // `duplicate.bin` has no dc_mirror row, so its sha matching a registered
    // row must not rescue it (Astra item 2, r2).
    let duplicate = dir.path().join("duplicate.bin");
    std::fs::copy(&src, &duplicate).unwrap();
    let err = c
        .drive_import_file("drive".into(), duplicate.to_string_lossy().to_string())
        .expect_err("duplicate content at an unregistered path must be rejected");
    assert!(
        err.to_string().contains("not a registered mirrored file"),
        "{err}"
    );
    assert!(!c
        .drive_has_chunk("drive".into(), file_sha256(&src))
        .unwrap());
    // Control: the same content at the REGISTERED path still imports.
    c.drive_import_file("drive".into(), src)
        .expect("the registered path itself must keep importing");
}

#[test]
fn import_rejects_a_registered_file_that_resolves_outside_the_root() {
    let _policy = policy_guard();
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let src = marker_file(&dir);
    let root = dir.path().to_string_lossy().to_string();
    register_mirror_file(&c, &root, &src);
    // Byte-identical COPY outside every trusted root: content membership alone
    // must not rescue it once roots are installed.
    let outside_dir = tempfile::tempdir().unwrap();
    let copy = outside_dir.path().join("elsewhere.bin");
    std::fs::copy(&src, &copy).unwrap();
    let err = c
        .drive_import_file("drive".into(), copy.to_string_lossy().to_string())
        .expect_err("registered content outside the trusted root must be rejected");
    assert!(err.to_string().contains("trusted import root"), "{err}");
}

#[cfg(unix)]
#[test]
fn import_rejects_an_ancestor_symlink_escape() {
    let _policy = policy_guard();
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let src = marker_file(&dir);
    let root = dir.path().to_string_lossy().to_string();
    register_mirror_file(&c, &root, &src);
    // A directory symlink INSIDE the root pointing OUT of it: the requested
    // path stays "inside" lexically but resolves outside via its ancestor.
    let escape = dir.path().join("escape-dir");
    std::os::unix::fs::symlink("/etc", &escape).unwrap();
    let through = escape.join("passwd");
    let err = c
        .drive_import_file("drive".into(), through.to_string_lossy().to_string())
        .expect_err("ancestor-symlink escape must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("trusted import root") || msg.contains("not a registered mirrored file"),
        "{msg}"
    );
    assert!(!c
        .drive_has_chunk("drive".into(), file_sha256("/etc/passwd"))
        .unwrap());
}

#[test]
fn import_fails_closed_when_the_mirror_index_does_not_exist() {
    let _policy = policy_guard();
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let src = marker_file(&dir);
    let root = dir.path().to_string_lossy().to_string();
    // Root installed but NO dc_mirror table (the mirror layer never ran).
    offline_core::drive::drive_set_confinement(vec![root], vec![]);
    let err = c
        .drive_import_file("drive".into(), src)
        .expect_err("a missing mirror index must deny, not crash");
    assert!(
        err.to_string().contains("not a registered mirrored file"),
        "{err}"
    );
}

// ── NETWORK subvector: non-approved-transport URLs rejected before dialing ───

#[test]
fn fetch_rejects_cleartext_nonloopback_urls_before_any_network_or_vault_effect() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let err = c
        .drive_fetch_chunk(
            "drive".into(),
            "http://attacker.example/api/drive/chunks/x".into(),
            "bearer-token".into(),
            "cafebabe".into(),
            4,
        )
        .expect_err("cleartext non-loopback URL must be rejected");
    assert!(err.to_string().contains("drive: url rejected"), "{err}");
}

#[test]
fn fetch_rejects_non_http_schemes_and_relative_urls() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    for url in [
        "file:///etc/passwd",
        "ftp://attacker.example/x",
        "/api/drive/chunks/x?space=1",
    ] {
        let err = c
            .drive_fetch_chunk(
                "drive".into(),
                url.into(),
                "bearer-token".into(),
                "cafebabe".into(),
                4,
            )
            .expect_err("non-http(s) URL must be rejected");
        assert!(err.to_string().contains("drive: url rejected"), "{err}");
    }
    // Nothing was inserted by any rejected attempt.
    assert!(
        !c.drive_has_chunk("drive".into(), "cafebabe".into())
            .unwrap(),
        "rejected fetches must store nothing"
    );
}

#[test]
fn push_rejects_bad_urls_before_reading_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let err = c
        .drive_push_chunk(
            "drive".into(),
            "http://attacker.example/api/drive/chunks/x".into(),
            "bearer-token".into(),
            "cafebabe".into(),
        )
        .expect_err("cleartext non-loopback push URL must be rejected");
    assert!(err.to_string().contains("drive: url rejected"), "{err}");
}

// ── NETWORK subvector: trusted approved-origin policy (Astra item 2) ─────────

/// Small local HTTP server replying `status` with `body` to the first
/// `requests` incoming requests; returns its loopback URL (used as BOTH the
/// approved origin and the target). Enough slots for every request the test
/// will make — an un-answered request would hang until ureq's 120s timeout.
fn one_shot_server(status: u16, body: Vec<u8>) -> (String, std::sync::Arc<tiny_http::Server>) {
    one_shot_server_n(status, body, 2)
}

fn one_shot_server_n(
    status: u16,
    body: Vec<u8>,
    requests: usize,
) -> (String, std::sync::Arc<tiny_http::Server>) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}/chunk", server.server_addr());
    let server = std::sync::Arc::new(server);
    let srv = server.clone();
    std::thread::spawn(move || {
        for _ in 0..requests {
            match srv.recv() {
                Ok(req) => {
                    let _ = req.respond(
                        tiny_http::Response::from_data(body.clone()).with_status_code(status),
                    );
                }
                Err(_) => break,
            }
        }
    });
    (url, server)
}

#[test]
fn fetch_rejects_every_origin_while_the_policy_is_empty() {
    let _policy = policy_guard();
    offline_core::drive::drive_set_confinement(vec![], vec![]);
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    for url in [
        "https://attacker.example/api/drive/chunks/x", // HTTPS attacker origin
        "https://gateway.setjoin.example/api/drive/chunks/x",
    ] {
        let err = c
            .drive_fetch_chunk(
                "drive".into(),
                url.into(),
                "bearer-token".into(),
                "cafebabe".into(),
                4,
            )
            .expect_err("empty origin policy must deny HTTPS origins too");
        let msg = err.to_string();
        assert!(msg.contains("no approved chunk origins"), "{msg}");
    }
    assert!(
        !c.drive_has_chunk("drive".into(), "cafebabe".into())
            .unwrap(),
        "origin-rejected fetches must store nothing"
    );
}

#[test]
fn fetch_and_push_reject_attacker_origins_and_port_mismatches() {
    let _policy = policy_guard();
    offline_core::drive::drive_set_confinement(vec![], vec!["https://gw.example:8443".into()]);
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    for url in [
        "https://attacker.example/api/drive/chunks/x", // HTTPS attacker origin
        "https://gw.example.attacker.example/api/drive/chunks/x", // suffix lookalike
        "https://gw.example/api/drive/chunks/x",       // default 443 ≠ 8443
        "https://gw.example:8444/api/drive/chunks/x",  // wrong explicit port
        "http://gw.example:8443/api/drive/chunks/x",   // scheme downgrade
        "http://gw.example/api/drive/chunks/x",        // cleartext off-box
        "https://gw.example:8443.evil.example/api/drive/chunks/x", // port-prefix host
    ] {
        let err = c
            .drive_fetch_chunk(
                "drive".into(),
                url.into(),
                "bearer-token".into(),
                "cafebabe".into(),
                4,
            )
            .expect_err("unapproved origin must be rejected before network access");
        let msg = err.to_string();
        assert!(
            msg.contains("not approved")
                || msg.contains("loopback-only")
                || msg.contains("not an absolute http(s) URL"),
            "url {url}: {msg}"
        );
        let err = c
            .drive_push_chunk(
                "drive".into(),
                url.into(),
                "bearer-token".into(),
                "cafebabe".into(),
            )
            .expect_err("unapproved origin must be rejected for push too");
        let msg = err.to_string();
        assert!(
            msg.contains("not approved")
                || msg.contains("loopback-only")
                || msg.contains("not an absolute http(s) URL"),
            "url {url}: {msg}"
        );
    }
    assert!(
        !c.drive_has_chunk("drive".into(), "cafebabe".into())
            .unwrap(),
        "origin-rejected fetches must store nothing"
    );
}

#[test]
fn fetch_and_push_allow_the_exact_approved_origin() {
    let _policy = policy_guard();
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let payload = vec![7u8; 64];
    let sha = hex::encode(sha2::Sha256::digest(&payload));
    let (url, _srv) = one_shot_server(200, payload);
    // Only the live server's exact origin is approved; imports stay denied.
    offline_core::drive::drive_set_confinement(vec![], vec![url.clone()]);
    c.drive_fetch_chunk("drive".into(), url.clone(), "tok".into(), sha.clone(), 64)
        .expect("the exact approved origin must fetch");
    c.drive_push_chunk("drive".into(), url, "tok".into(), sha)
        .expect("the exact approved origin must push");
}

#[test]
fn rejections_are_independent_of_vault_lock_state() {
    let _policy = policy_guard();
    offline_core::drive::drive_set_confinement(vec![], vec![]);
    // The floor is a transport/path bound, not an authorization check: it must
    // reject identically whether or not a store is open. Here a fresh engine
    // without any open store must reject the same way (and NOT with "store not
    // open") — the URL checks run first.
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("guard.db").to_string_lossy().to_string();
    let guard = guard_core::GuardCore::new(vault, "pw".into()).expect("vault");
    let c = OfflineCore::new(guard);
    let err = c
        .drive_fetch_chunk(
            "drive".into(),
            "http://attacker.example/x".into(),
            "bearer-token".into(),
            "cafebabe".into(),
            4,
        )
        .expect_err("must be rejected");
    assert!(err.to_string().contains("drive: url rejected"), "{err}");
}

// ── TOCTOU: authorization and reading bound to ONE confined handle (Astra ────
// item 3, r2) + imported-content verification.

#[test]
fn verified_import_from_handle_matches_the_authorized_manifest() {
    let _policy = policy_guard();
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let src = marker_file(&dir);
    let root = dir.path().to_string_lossy().to_string();
    register_mirror_file(&c, &root, &src);
    let authorized = file_sha256(&src);
    let mut handle = std::fs::File::open(&src).unwrap();
    let manifest = c
        .drive_import_verified_from_handle("drive", &mut handle, &authorized)
        .expect("an unchanged handle must import cleanly");
    let m: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    assert_eq!(m["contentSha256"], authorized.as_str());
    assert_eq!(m["size"], "importable".len() as u64);
    assert!(c.drive_has_chunk("drive".into(), authorized).unwrap());
}

#[test]
fn verified_import_catches_an_in_place_rewrite_between_hash_and_read() {
    let _policy = policy_guard();
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let src = marker_file(&dir); // b"importable" — 10 bytes
    let root = dir.path().to_string_lossy().to_string();
    register_mirror_file(&c, &root, &src);
    let authorized = file_sha256(&src);
    // Authorization would have hashed THIS open description...
    let mut handle = std::fs::File::open(&src).unwrap();
    // ...and the TOCTOU window is an in-place, same-length rewrite before the
    // read pass. The r1 code re-opened the path here and imported whatever it
    // found; the handle-bound import sees the new bytes through the SAME
    // description and must catch the divergence from the authorized hash.
    let mut evil = std::fs::OpenOptions::new().write(true).open(&src).unwrap();
    evil.write_all(b"IMPORTABLE").unwrap(); // same length, different bytes
    evil.sync_all().unwrap();
    drop(evil);
    let err = c
        .drive_import_verified_from_handle("drive", &mut handle, &authorized)
        .expect_err("a rewrite between hash and read must be caught by the verification");
    let msg = err.to_string();
    assert!(msg.contains("changed during import"), "{msg}");
    // The tampered content never stays in the vault — the import is rolled
    // back, and neither the tampered chunk nor the authorized one is stored.
    assert!(!c
        .drive_has_chunk(
            "drive".into(),
            hex::encode(sha2::Sha256::digest(b"IMPORTABLE"))
        )
        .unwrap());
    assert!(!c.drive_has_chunk("drive".into(), authorized).unwrap());
}

// ── NETWORK subvector: redirects never escape the approved origin (Astra ─────
// item 5, r2 — the agent dials with redirects disabled).

#[test]
fn fetch_does_not_follow_a_redirect_off_the_approved_origin() {
    let _policy = policy_guard();
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir);
    let payload = vec![9u8; 64];
    let sha = hex::encode(sha2::Sha256::digest(&payload));
    // The redirect TARGET: a second loopback server that would happily serve
    // the chunk. With ureq's default redirect following the r1 code dialed it;
    // it must now receive nothing.
    let target = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let target_url = format!("http://{}/chunk", target.server_addr());
    let target = std::sync::Arc::new(target);
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let srv = target.clone();
    let counter = hits.clone();
    let target_payload = payload.clone();
    std::thread::spawn(move || loop {
        match srv.recv() {
            Ok(req) => {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = req.respond(tiny_http::Response::from_data(target_payload.clone()));
            }
            Err(_) => break,
        }
    });
    // The APPROVED origin answers the first request with a 302 to the target.
    let redirector = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}/chunk", redirector.server_addr());
    let redirector = std::sync::Arc::new(redirector);
    let srv = redirector.clone();
    let location = target_url.clone();
    std::thread::spawn(move || {
        if let Ok(req) = srv.recv() {
            let location =
                tiny_http::Header::from_bytes(b"Location".as_slice(), location.as_bytes()).unwrap();
            let _ = req.respond(tiny_http::Response::empty(302).with_header(location));
        }
    });
    offline_core::drive::drive_set_confinement(vec![], vec![url.clone()]);
    // The 302 comes back as-is (no hop dialed), so the "body" is not the
    // expected chunk and the fetch fails closed.
    let err = c
        .drive_fetch_chunk("drive".into(), url, "tok".into(), sha.clone(), 64)
        .expect_err("a redirect response must not satisfy the fetch");
    let msg = err.to_string();
    assert!(
        msg.contains("size mismatch") || msg.contains("sha256 mismatch") || msg.contains("HTTP"),
        "unexpected error for redirect response: {msg}"
    );
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the redirect target must never be dialed"
    );
    assert!(
        !c.drive_has_chunk("drive".into(), sha).unwrap(),
        "redirect responses must store nothing"
    );
}
