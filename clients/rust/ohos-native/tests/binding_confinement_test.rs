//! Binding-level confinement tests for the OHOS napi seam (deep-scan package
//! med-shard2-013, D-CLIENTS-RUST-OHOS-NATIVE-001 r2 evidence).
//!
//! What is MACHINE-RUN here: the shared offline-core floor functions that the
//! `#[napi]` wrappers in `clients/rust/native-shared/native_impl.rs` delegate
//! to — `drive_set_confinement` (a one-line delegation to
//! `offline_core::drive::drive_set_confinement`) and the
//! `OfflineCore::{drive_import_file, drive_fetch_chunk, drive_push_chunk}`
//! methods those wrappers call. `ohos-native/src/lib.rs` `include!`s that same
//! shared file, so the ArkTS-facing exports (reached via `NativeBinding.ets`
//! and driven by `BridgeProxy.ets`'s `forwardDriveConfinementToNative`) run
//! exactly this code against exactly this process-global policy.
//!
//! What is INSPECTION-ONLY: executing the true `#[napi]` symbols requires a
//! real OHOS/ArkWeb process (this crate's Cargo.toml sets `lib.test = false`
//! — Node-API host symbols exist only inside the ArkTS runtime). The
//! ArkTS-layer negative checks (private-store/vault import denial, `mam:*`
//! secure-store renderer denial, persisted HTTP-anchor rejection) are
//! inspection-checked `.ets` artifacts kept beside this file under
//! `tests/arkts/`; each states its own status in its header.

use guard_core::GuardCore;
use offline_core::drive::drive_set_confinement;
use offline_core::OfflineCore;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

/// The confinement policy is process-global (one shell session, one policy —
/// `drive.rs`'s `DRIVE_CONFINEMENT` static); tests that touch it hold this
/// lock for their whole body and reset the policy at entry.
static POLICY_LOCK: Mutex<()> = Mutex::new(());

fn policy_guard() -> MutexGuard<'static, ()> {
    match POLICY_LOCK.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(), // a prior panic must not cascade
    }
}

/// std-only temp fixture (this crate deliberately carries no dev-dependencies;
/// the directory is removed on drop).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "ohos-binding-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).expect("create temp dir");
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl TempDir {
    fn path(&self) -> String {
        self.0.to_string_lossy().to_string()
    }
}

/// One OfflineCore with its drive store open — the state the ArkTS shell holds
/// for a session (vault + keyed SQLCipher store), built through the same
/// public API the shell composition uses.
fn core(dir: &TempDir) -> Arc<OfflineCore> {
    let vault = format!("{}/guard.db", dir.path());
    let guard = GuardCore::new(vault, "pw".into()).expect("vault open");
    let c = OfflineCore::new(guard);
    let db = format!("{}/drive-vault.db", dir.path());
    c.open_store("drive".into(), db, "standard".into())
        .expect("open drive store");
    c
}

/// Deny-by-default: before the composition installs any policy (empty import
/// roots + empty approved origins — the state every process starts in), every
/// chunk fetch/push and every import is refused at the native floor.
/// `BridgeProxy.ets` mirrors the empty-default at the ArkTS layer; this pins
/// the native half of the seam.
#[test]
fn deny_by_default_before_any_policy_is_installed() {
    let _policy = policy_guard();
    drive_set_confinement(vec![], vec![]); // the process default, installed explicitly
    let dir = TempDir::new("deny-default");
    let c = core(&dir);

    let https = "https://drive.example.org/v1/chunks/aa";
    let err = c
        .drive_fetch_chunk("drive".into(), https.into(), "b".into(), "aa".into(), 1)
        .expect_err("fetch must be denied");
    assert!(
        err.to_string().contains("no approved chunk origins"),
        "deny-by-default origins must refuse fetch: {err}"
    );
    let err = c
        .drive_push_chunk("drive".into(), https.into(), "b".into(), "aa".into())
        .expect_err("push must be denied");
    assert!(
        err.to_string().contains("no approved chunk origins"),
        "deny-by-default origins must refuse push: {err}"
    );

    // An absolute, existing, regular file outside any trusted import root.
    let src = dir.0.join("unregistered.bin");
    std::fs::write(&src, b"importable").unwrap();
    let err = c
        .drive_import_file("drive".into(), src.to_string_lossy().to_string())
        .expect_err("import must be denied");
    assert!(
        err.to_string().contains("no trusted import roots"),
        "deny-by-default import roots must refuse import: {err}"
    );
}

/// Unapproved import root: even with a designated root installed, a file that
/// resolves inside a sibling directory no composition approved is refused —
/// the native floor re-validates every src_path against the trusted roots
/// (what `BridgeProxy.ets`'s in-sandbox allowlist forwards natively via
/// `driveSetConfinement`).
#[test]
fn import_denied_for_unapproved_import_root() {
    let _policy = policy_guard();
    let dir = TempDir::new("import-root");
    let c = core(&dir);

    // The designated import root holds its own (unused) file; the probed file
    // lives in a sibling directory that was never approved.
    let approved = dir.0.join("imports");
    let outside = dir.0.join("elsewhere");
    std::fs::create_dir_all(&approved).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let planted = approved.join("mirror-file.bin");
    std::fs::write(&planted, b"approved root content").unwrap();
    let f = outside.join("sensitive.bin");
    std::fs::write(&f, b"never importable").unwrap();

    drive_set_confinement(vec![approved.to_string_lossy().to_string()], vec![]);
    let err = c
        .drive_import_file("drive".into(), f.to_string_lossy().to_string())
        .expect_err("import outside every trusted root must be denied");
    assert!(
        err.to_string()
            .contains("resolves outside every trusted import root"),
        "unapproved import root must be refused: {err}"
    );
}

/// Cleartext chunk URL: the native transport floor refuses plain http to any
/// non-loopback host EVEN when its origin was approved by the composition —
/// matching the byte-mirrored `driveChunkUrlAllowed` rule in
/// `BridgeProxy.ets` (the drive bearer must never leave the box unencrypted).
#[test]
fn cleartext_http_chunk_url_is_rejected_even_when_its_origin_is_approved() {
    let _policy = policy_guard();
    let dir = TempDir::new("cleartext");
    let c = core(&dir);

    drive_set_confinement(vec![], vec!["http://10.0.0.8:80".into()]);
    let url = "http://10.0.0.8/v1/chunks/aa";
    let err = c
        .drive_fetch_chunk("drive".into(), url.into(), "b".into(), "aa".into(), 1)
        .expect_err("cleartext non-loopback chunk URL must be denied");
    assert!(
        err.to_string().contains("cleartext http is loopback-only"),
        "transport floor must refuse cleartext http fetch: {err}"
    );
    let err = c
        .drive_push_chunk("drive".into(), url.into(), "b".into(), "aa".into())
        .expect_err("cleartext non-loopback push must be denied");
    assert!(
        err.to_string().contains("cleartext http is loopback-only"),
        "transport floor must refuse cleartext http push: {err}"
    );
}

/// The approved seam still WORKS: an approved loopback origin passes the
/// transport floor AND the origin allowlist (pre-DNS), and the call proceeds
/// to the network layer, where it fails cleanly (no listener on the discard
/// port) with an error that is NOT a URL rejection — proving the installed
/// policy opens exactly the approved path and nothing else.
#[test]
fn approved_loopback_origin_passes_the_gate_and_fails_cleanly_at_the_network() {
    let _policy = policy_guard();
    let dir = TempDir::new("approved-origin");
    let c = core(&dir);

    drive_set_confinement(vec![], vec!["http://127.0.0.1:9".into()]);
    let err = c
        .drive_fetch_chunk(
            "drive".into(),
            "http://127.0.0.1:9/v1/chunks/aa".into(),
            "b".into(),
            "aa".into(),
            1,
        )
        .expect_err("approved-origin URL must pass the gate; failure comes from the network");
    assert!(
        !err.to_string().contains("url rejected"),
        "an approved origin must not be rejected by the gate: {err}"
    );
}
