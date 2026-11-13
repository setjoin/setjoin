use guard_core::GuardCore;

#[test]
fn test_provision_store_key_deterministic_and_distinct() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("guard.db").to_string_lossy().to_string();
    let gc = GuardCore::new(db_path, "passphrase".into()).expect("open guard");

    let k_mail = gc.provision_store_key("mail").expect("mail key");
    let k_drive = gc.provision_store_key("drive").expect("drive key");

    assert_eq!(k_mail.len(), 32, "key must be 32 bytes");
    assert_eq!(k_drive.len(), 32, "key must be 32 bytes");
    assert_ne!(
        k_mail, k_drive,
        "distinct app_keys must yield distinct store keys"
    );

    // Deterministic: same app_key → same derived key.
    let k_mail2 = gc.provision_store_key("mail").expect("mail key again");
    assert_eq!(k_mail, k_mail2, "provision must be deterministic");
}
