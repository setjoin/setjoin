use guard_core::GuardCore;

// Remote wipe must IRREVERSIBLY destroy the vault secrets AND latch durably
// across a reopen — a force-quit + relaunch must not resurrect access.
//
// Regression guard for the C2 MAM wipe bug: mark_wiped() used to only flip an
// in-memory flag (rebuilt false on every GuardCore::new) and never touched the
// encrypted SQLite vault, so the TOTP seeds / ECDH push key / secure-store
// secrets survived and a force-quit fully defeated the "remote wipe".
#[test]
fn test_remote_wipe_destroys_secrets_and_is_durable() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("guard.db").to_string_lossy().to_string();
    let pass = "test-passphrase".to_string();

    // ── Populate secrets, then wipe ──
    {
        let core = GuardCore::new(db_path.clone(), pass.clone()).unwrap();
        core.add_totp_account(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example".to_string(),
        )
        .unwrap();
        core.meta_set("ss:mam:hmac_secret".to_string(), "super-secret".to_string())
            .unwrap();
        let pk = core.get_or_create_ecdh_public_key().unwrap();
        assert!(!pk.is_empty());

        assert_eq!(core.list_accounts().unwrap().len(), 1);
        assert_eq!(
            core.meta_get("ss:mam:hmac_secret".to_string()).unwrap(),
            Some("super-secret".to_string())
        );
        assert!(!core.is_wiped());

        core.mark_wiped().expect("mark_wiped");

        // Secrets are gone immediately and the latch is set.
        assert!(
            core.is_wiped(),
            "is_wiped must be true right after mark_wiped"
        );
        assert!(
            core.list_accounts().unwrap().is_empty(),
            "TOTP seeds must be destroyed by the wipe"
        );
        assert_eq!(
            core.meta_get("ss:mam:hmac_secret".to_string()).unwrap(),
            None,
            "secure-store secret must be destroyed by the wipe"
        );
    } // drop → simulate app exit / force-quit

    // ── Reopen the SAME db: destruction + latch must persist ──
    {
        let core = GuardCore::new(db_path.clone(), pass.clone()).unwrap();
        assert!(
            core.is_wiped(),
            "wipe latch must survive a reopen (a force-quit must not defeat the wipe)"
        );
        assert!(
            core.list_accounts().unwrap().is_empty(),
            "secrets must stay gone after a reopen"
        );
        assert_eq!(
            core.meta_get("ss:mam:hmac_secret".to_string()).unwrap(),
            None
        );

        // A successful re-enrolment clears the latch (so a recovered device works again).
        core.clear_wiped().expect("clear_wiped");
        assert!(!core.is_wiped(), "clear_wiped must un-latch the device");
    }

    // ── The cleared state is durable too ──
    {
        let core = GuardCore::new(db_path, pass).unwrap();
        assert!(!core.is_wiped(), "a cleared latch must survive a reopen");
    }
}

// A logical DELETE on a WAL SQLite DB leaves the ciphertext on free pages and in
// the -wal until overwritten, so a disk image taken after a "remote wipe" could
// recover it. mark_wiped must scrub it: secure_delete zeroes the freed rows,
// VACUUM rebuilds the file, and wal_checkpoint(TRUNCATE) drops the -wal frames.
// This asserts the actual at-rest seed ciphertext bytes are gone from the file.
#[test]
fn test_wipe_scrubs_ciphertext_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("guard.db").to_string_lossy().to_string();
    let pass = "wipe-pass".to_string();

    let seed_blob: Vec<u8> = {
        let core = GuardCore::new(db_path.clone(), pass.clone()).unwrap();
        core.add_totp_account(
            "otpauth://totp/Bank:alice@bank.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Bank".to_string(),
        )
        .unwrap();
        core.meta_set("ss:probe".to_string(), "secret-store-marker".to_string())
            .unwrap();
        // Capture the encrypted seed exactly as stored — these bytes must not survive.
        let raw = rusqlite::Connection::open(&db_path).unwrap();
        raw.query_row("SELECT seed_enc FROM totp_accounts LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap()
    };
    assert!(seed_blob.len() >= 28, "seed ciphertext must be nonce+ct");

    {
        let core = GuardCore::new(db_path.clone(), pass).unwrap();
        core.mark_wiped().expect("mark_wiped");
    } // drop → close the connection

    let mut disk = std::fs::read(&db_path).unwrap();
    for ext in ["-wal", "-shm"] {
        if let Ok(extra) = std::fs::read(format!("{db_path}{ext}")) {
            disk.extend(extra);
        }
    }
    let survived = disk
        .windows(seed_blob.len())
        .any(|w| w == seed_blob.as_slice());
    assert!(
        !survived,
        "encrypted TOTP seed must be scrubbed from disk after wipe (secure_delete + VACUUM + WAL truncate)"
    );
}
