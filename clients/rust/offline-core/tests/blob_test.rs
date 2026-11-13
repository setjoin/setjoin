use guard_core::GuardCore;
use offline_core::blob::MAX_BLOB_SIZE;
use offline_core::OfflineCore;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const TEST_PASSPHRASE: &str = "passphrase";

fn mail_db_path(dir: &tempfile::TempDir) -> String {
    dir.path().join("mail.db").to_string_lossy().into_owned()
}

fn open_core(dir: &tempfile::TempDir) -> Arc<OfflineCore> {
    let guard = GuardCore::new(
        dir.path().join("guard.db").to_string_lossy().into(),
        TEST_PASSPHRASE.into(),
    )
    .unwrap();
    let core = OfflineCore::new(guard);
    core.open_store("mail".into(), mail_db_path(dir), "standard".into())
        .unwrap();
    core
}

fn core() -> (tempfile::TempDir, Arc<OfflineCore>) {
    let dir = tempfile::tempdir().unwrap();
    let core = open_core(&dir);
    (dir, core)
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn begin_write(core: &OfflineCore, sha256: &str, size: u64) -> serde_json::Value {
    serde_json::from_str(
        &core
            .blob_write_begin("mail".into(), sha256.to_string(), size)
            .unwrap(),
    )
    .unwrap()
}

fn raw_disk_bytes(path: &str) -> Vec<u8> {
    let mut disk = std::fs::read(path).unwrap();
    for suffix in ["-wal", "-shm"] {
        if let Ok(extra) = std::fs::read(format!("{path}{suffix}")) {
            disk.extend(extra);
        }
    }
    disk
}

fn assert_marker_absent(path: &str, marker: &[u8]) {
    assert!(
        !raw_disk_bytes(path)
            .windows(marker.len())
            .any(|window| window == marker),
        "blob marker must not appear in raw encrypted mail.db bytes"
    );
}

#[test]
fn blob_write_begin_enforces_exact_eight_gib_bound_without_payload_allocation() {
    let (_dir, core) = core();
    let sha = "11".repeat(32);

    let begin = begin_write(&core, &sha, MAX_BLOB_SIZE);
    let handle = begin["handle"].as_str().unwrap().to_string();
    assert_eq!(begin["nextOffset"], 0);
    assert!(
        core.blob_write_begin("mail".into(), sha.clone(), MAX_BLOB_SIZE + 1)
            .is_err(),
        "8 GiB + 1 must be rejected"
    );
    assert!(
        core.blob_write_begin("mail".into(), sha, 0).is_err(),
        "zero-sized blobs must be rejected"
    );
    core.blob_write_abort("mail".into(), handle).unwrap();
}

#[test]
fn interleaved_blob_transfers_keep_handles_and_offsets_independent() {
    let (_dir, core) = core();
    let bytes_a = b"alpha transfer";
    let bytes_b = b"bravo transfer";
    let sha_a = digest(bytes_a);
    let sha_b = digest(bytes_b);
    let begin_a = begin_write(&core, &sha_a, bytes_a.len() as u64);
    let begin_b = begin_write(&core, &sha_b, bytes_b.len() as u64);
    let handle_a = begin_a["handle"].as_str().unwrap().to_string();
    let handle_b = begin_b["handle"].as_str().unwrap().to_string();
    assert_ne!(handle_a, handle_b);
    assert_eq!(begin_a["nextOffset"], 0);
    assert_eq!(begin_b["nextOffset"], 0);

    assert_eq!(
        core.blob_write_chunk("mail".into(), handle_a.clone(), 0, bytes_a[..6].to_vec())
            .unwrap(),
        6
    );
    assert_eq!(
        core.blob_write_chunk("mail".into(), handle_b.clone(), 0, bytes_b[..5].to_vec())
            .unwrap(),
        5
    );

    let resumed_a = begin_write(&core, &sha_a, bytes_a.len() as u64);
    let resumed_b = begin_write(&core, &sha_b, bytes_b.len() as u64);
    assert_eq!(resumed_a["handle"], handle_a);
    assert_eq!(resumed_a["nextOffset"], 6);
    assert_eq!(resumed_b["handle"], handle_b);
    assert_eq!(resumed_b["nextOffset"], 5);

    core.blob_write_chunk("mail".into(), handle_a.clone(), 6, bytes_a[6..].to_vec())
        .unwrap();
    assert_eq!(
        core.blob_write_commit("mail".into(), handle_a).unwrap(),
        sha_a
    );

    let still_partial_b = begin_write(&core, &sha_b, bytes_b.len() as u64);
    assert_eq!(still_partial_b["handle"], handle_b);
    assert_eq!(still_partial_b["nextOffset"], 5);
    core.blob_write_chunk("mail".into(), handle_b.clone(), 5, bytes_b[5..].to_vec())
        .unwrap();
    assert_eq!(
        core.blob_write_commit("mail".into(), handle_b).unwrap(),
        sha_b
    );
}

#[test]
fn interrupted_blob_transfer_resumes_after_reopening_with_same_key() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = b"resume this transfer after reopening";
    let sha = digest(bytes);
    let core = open_core(&dir);
    let begin = begin_write(&core, &sha, bytes.len() as u64);
    let handle = begin["handle"].as_str().unwrap().to_string();
    let split = 10;
    assert_eq!(
        core.blob_write_chunk("mail".into(), handle.clone(), 0, bytes[..split].to_vec())
            .unwrap(),
        split as u64
    );
    drop(core);

    let reopened = open_core(&dir);
    let resumed = begin_write(&reopened, &sha, bytes.len() as u64);
    assert_eq!(resumed["handle"], handle);
    assert_eq!(resumed["nextOffset"], split);
    reopened
        .blob_write_chunk(
            "mail".into(),
            handle.clone(),
            split as u64,
            bytes[split..].to_vec(),
        )
        .unwrap();
    assert_eq!(
        reopened.blob_write_commit("mail".into(), handle).unwrap(),
        sha
    );
}

#[test]
fn blob_marker_is_absent_from_raw_mail_db_before_and_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = mail_db_path(&dir);
    let marker = b"setjoin-e3-sqlcipher-plaintext-regression-marker-7c5a";
    let sha = digest(marker);
    let core = open_core(&dir);
    let begin = begin_write(&core, &sha, marker.len() as u64);
    let handle = begin["handle"].as_str().unwrap().to_string();
    core.blob_write_chunk("mail".into(), handle.clone(), 0, marker.to_vec())
        .unwrap();
    core.blob_write_commit("mail".into(), handle).unwrap();
    assert_marker_absent(&db_path, marker);
    drop(core);
    assert_marker_absent(&db_path, marker);

    let reopened = open_core(&dir);
    assert_marker_absent(&db_path, marker);
    let opened: serde_json::Value =
        serde_json::from_str(&reopened.blob_read_open("mail".into(), sha).unwrap()).unwrap();
    let read_handle = opened["handle"].as_str().unwrap().to_string();
    assert_eq!(
        reopened
            .blob_read_chunk("mail".into(), read_handle.clone(), 0, marker.len() as u32)
            .unwrap(),
        marker
    );
    reopened
        .blob_read_close("mail".into(), read_handle)
        .unwrap();
}

#[test]
fn bounded_stream_roundtrip_resume_replay_and_refcount() {
    let (_dir, core) = core();
    let bytes = vec![7u8; 600_000];
    let sha = hex::encode(Sha256::digest(&bytes));
    let begin: serde_json::Value = serde_json::from_str(
        &core
            .blob_write_begin("mail".into(), sha.clone(), bytes.len() as u64)
            .unwrap(),
    )
    .unwrap();
    let handle = begin["handle"].as_str().unwrap().to_string();
    let first = bytes[..262_144].to_vec();
    assert_eq!(
        core.blob_write_chunk("mail".into(), handle.clone(), 0, first.clone())
            .unwrap(),
        262_144
    );
    assert_eq!(
        core.blob_write_chunk("mail".into(), handle.clone(), 0, first)
            .unwrap(),
        262_144
    );
    assert!(core
        .blob_write_chunk("mail".into(), handle.clone(), 300_000, vec![1])
        .is_err());
    let resumed: serde_json::Value = serde_json::from_str(
        &core
            .blob_write_begin("mail".into(), sha.clone(), bytes.len() as u64)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(resumed["handle"], handle);
    assert_eq!(resumed["nextOffset"], 262_144);
    core.blob_write_chunk(
        "mail".into(),
        handle.clone(),
        262_144,
        bytes[262_144..524_288].to_vec(),
    )
    .unwrap();
    core.blob_write_chunk(
        "mail".into(),
        handle.clone(),
        524_288,
        bytes[524_288..].to_vec(),
    )
    .unwrap();
    assert_eq!(core.blob_write_commit("mail".into(), handle).unwrap(), sha);
    assert_eq!(core.blob_ref("mail".into(), sha.clone()).unwrap(), 1);
    let opened: serde_json::Value =
        serde_json::from_str(&core.blob_read_open("mail".into(), sha.clone()).unwrap()).unwrap();
    let read_handle = opened["handle"].as_str().unwrap().to_string();
    let mut got = Vec::new();
    let mut offset = 0u64;
    loop {
        let chunk = core
            .blob_read_chunk("mail".into(), read_handle.clone(), offset, 131_072)
            .unwrap();
        if chunk.is_empty() {
            break;
        }
        offset += chunk.len() as u64;
        got.extend(chunk);
    }
    core.blob_read_close("mail".into(), read_handle).unwrap();
    assert_eq!(got, bytes);
    assert_eq!(core.blob_unref("mail".into(), sha.clone()).unwrap(), 0);
    assert!(core.blob_read_open("mail".into(), sha).is_err());
}

#[test]
fn wrong_hash_never_publishes_and_abort_is_idempotent() {
    let (_dir, core) = core();
    let begin: serde_json::Value = serde_json::from_str(
        &core
            .blob_write_begin("mail".into(), "00".repeat(32), 3)
            .unwrap(),
    )
    .unwrap();
    let handle = begin["handle"].as_str().unwrap().to_string();
    core.blob_write_chunk("mail".into(), handle.clone(), 0, b"bad".to_vec())
        .unwrap();
    assert!(core
        .blob_write_commit("mail".into(), handle.clone())
        .is_err());
    core.blob_write_abort("mail".into(), handle.clone())
        .unwrap();
    core.blob_write_abort("mail".into(), handle).unwrap();
}
