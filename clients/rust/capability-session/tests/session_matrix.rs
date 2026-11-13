use capability_session::{normalize_profile, CapabilitySession, SessionError};
use sha2::{Digest, Sha256};

const PASSPHRASE: &str = "correct horse battery staple";

fn paths(dir: &tempfile::TempDir) -> (String, String) {
    (
        dir.path().join("guard.db").to_string_lossy().into_owned(),
        dir.path().join("mail.db").to_string_lossy().into_owned(),
    )
}

#[test]
fn unlock_matrix_is_fail_closed_and_replaces_derived_engine() {
    let dir = tempfile::tempdir().unwrap();
    let (guard_path, mail_path) = paths(&dir);
    let mut initialized = CapabilitySession::default();
    assert!(initialized.unlock(guard_path.clone(), PASSPHRASE.into()));
    drop(initialized);
    let mut session = CapabilitySession::default();

    assert!(!session.unlock(guard_path.clone(), "wrong".into()));
    assert!(!session.is_unlocked());
    assert_eq!(session.secure_get("missing".into()).unwrap(), None);
    assert!(matches!(
        session.secure_set("key".into(), "value".into()),
        Err(SessionError::Locked)
    ));

    assert!(session.unlock(guard_path.clone(), PASSPHRASE.into()));
    session.open_store("mail".into(), mail_path, None).unwrap();
    let first = session.offline_core().unwrap();
    assert!(session.unlock(guard_path.clone(), PASSPHRASE.into()));
    let second = session.offline_core().unwrap();
    assert!(!std::sync::Arc::ptr_eq(&first, &second));
    assert!(!session.is_store_open("mail".into()).unwrap());
    assert!(!session.unlock(guard_path, "wrong".into()));
    assert!(!session.is_unlocked());
    assert_eq!(session.secure_get("missing".into()).unwrap(), None);
}

#[test]
fn secure_kv_preserves_locked_null_and_error_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let (guard_path, _) = paths(&dir);
    let mut session = CapabilitySession::default();

    assert_eq!(session.secure_get("k".into()).unwrap(), None);
    assert!(matches!(
        session.secure_remove("k".into()),
        Err(SessionError::Locked)
    ));
    assert!(session.unlock(guard_path, PASSPHRASE.into()));
    assert_eq!(session.secure_get("k".into()).unwrap(), None);
    session.secure_set("k".into(), "v".into()).unwrap();
    assert_eq!(session.secure_get("k".into()).unwrap(), Some("v".into()));
    session.secure_remove("k".into()).unwrap();
    assert_eq!(session.secure_get("k".into()).unwrap(), None);
}

#[test]
fn every_engine_and_recovery_operation_rejects_while_locked() {
    let mut session = CapabilitySession::default();
    assert!(matches!(session.offline_core(), Err(SessionError::Locked)));
    assert!(matches!(
        session.open_store("mail".into(), "unused".into(), None),
        Err(SessionError::Locked)
    ));
    assert!(matches!(
        session.is_store_open("mail".into()),
        Err(SessionError::Locked)
    ));
    assert!(matches!(
        session.exec("mail".into(), "SELECT 1".into(), "[]".into()),
        Err(SessionError::Locked)
    ));
    assert!(matches!(
        session.query("mail".into(), "SELECT 1".into(), "[]".into()),
        Err(SessionError::Locked)
    ));
    assert!(matches!(
        session.wipe_store("mail".into()),
        Err(SessionError::Locked)
    ));
    assert!(matches!(
        session.recovery_write_begin("mail".into(), "00".repeat(32), 1),
        Err(SessionError::Locked)
    ));
    assert!(matches!(
        session.recovery_write_chunk("mail".into(), "h".into(), 0, vec![1]),
        Err(SessionError::Locked)
    ));
    assert!(matches!(
        session.recovery_write_commit("mail".into(), "h".into()),
        Err(SessionError::Locked)
    ));
    assert!(matches!(
        session.recovery_write_abort("mail".into(), "h".into()),
        Err(SessionError::Locked)
    ));
    assert!(matches!(
        session.recovery_read_open("mail".into(), "00".repeat(32)),
        Err(SessionError::Locked)
    ));
    assert!(matches!(
        session.recovery_read_chunk("mail".into(), "h".into(), 0, 1),
        Err(SessionError::Locked)
    ));
    assert!(matches!(
        session.recovery_read_close("mail".into(), "h".into()),
        Err(SessionError::Locked)
    ));
    assert!(matches!(
        session.recovery_ref("mail".into(), "00".repeat(32)),
        Err(SessionError::Locked)
    ));
    assert!(matches!(
        session.recovery_unref("mail".into(), "00".repeat(32)),
        Err(SessionError::Locked)
    ));
}

#[test]
fn profile_open_query_and_wipe_are_session_owned() {
    assert_eq!(normalize_profile(None), "standard");
    assert_eq!(normalize_profile(Some("")), "standard");
    assert_eq!(normalize_profile(Some("SMx")), "smx");
    assert_eq!(normalize_profile(Some("smx")), "smx");
    assert_eq!(normalize_profile(Some("future")), "future");

    let dir = tempfile::tempdir().unwrap();
    let (guard_path, mail_path) = paths(&dir);
    let mut session = CapabilitySession::default();
    assert!(session.unlock(guard_path, PASSPHRASE.into()));
    session
        .open_store("mail".into(), mail_path.clone(), None)
        .unwrap();
    session
        .exec(
            "mail".into(),
            "CREATE TABLE sample(value TEXT NOT NULL)".into(),
            "[]".into(),
        )
        .unwrap();
    session
        .exec(
            "mail".into(),
            "INSERT INTO sample(value) VALUES(?)".into(),
            r#"["one"]"#.into(),
        )
        .unwrap();
    let rows: serde_json::Value = serde_json::from_str(
        &session
            .query(
                "mail".into(),
                "SELECT value FROM sample".into(),
                "[]".into(),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(rows[0]["value"], "one");
    assert!(session.is_store_open("mail".into()).unwrap());
    session.wipe_store("mail".into()).unwrap();
    assert!(!session.is_store_open("mail".into()).unwrap());
    assert!(!std::path::Path::new(&mail_path).exists());
}

#[test]
fn recovery_streaming_delegates_without_exposing_keys() {
    let dir = tempfile::tempdir().unwrap();
    let (guard_path, mail_path) = paths(&dir);
    let mut session = CapabilitySession::default();
    assert!(session.unlock(guard_path, PASSPHRASE.into()));
    session
        .open_store("mail".into(), mail_path, Some("standard"))
        .unwrap();

    let aborted = session
        .recovery_write_begin("mail".into(), "00".repeat(32), 3)
        .unwrap();
    let aborted: serde_json::Value = serde_json::from_str(&aborted).unwrap();
    session
        .recovery_write_abort("mail".into(), aborted["handle"].as_str().unwrap().into())
        .unwrap();

    let bytes = b"bounded recovery payload".to_vec();
    let sha = hex::encode(Sha256::digest(&bytes));
    let begin: serde_json::Value = serde_json::from_str(
        &session
            .recovery_write_begin("mail".into(), sha.clone(), bytes.len() as u64)
            .unwrap(),
    )
    .unwrap();
    let handle = begin["handle"].as_str().unwrap().to_string();
    assert_eq!(
        session
            .recovery_write_chunk("mail".into(), handle.clone(), 0, bytes.clone())
            .unwrap(),
        bytes.len() as u64
    );
    assert_eq!(
        session
            .recovery_write_commit("mail".into(), handle)
            .unwrap(),
        sha
    );
    assert_eq!(session.recovery_ref("mail".into(), sha.clone()).unwrap(), 1);

    let opened: serde_json::Value = serde_json::from_str(
        &session
            .recovery_read_open("mail".into(), sha.clone())
            .unwrap(),
    )
    .unwrap();
    let read_handle = opened["handle"].as_str().unwrap().to_string();
    assert_eq!(
        session
            .recovery_read_chunk("mail".into(), read_handle.clone(), 0, 1024)
            .unwrap(),
        bytes
    );
    session
        .recovery_read_close("mail".into(), read_handle)
        .unwrap();
    assert_eq!(session.recovery_unref("mail".into(), sha).unwrap(), 0);
}
