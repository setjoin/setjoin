use guard_core::{GuardCore, PushApprovalAssertion};

#[test]
fn test_guard_core_new_and_list_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("guard.db").to_string_lossy().to_string();

    let core = GuardCore::new(db_path, "test-passphrase".to_string())
        .expect("GuardCore::new should succeed");

    // On a fresh DB, list_accounts should return an empty vector
    let accounts = core.list_accounts().expect("list_accounts");
    assert!(accounts.is_empty(), "fresh DB should have 0 accounts");

    // get_or_create_ecdh_public_key should return a non-empty DER
    let pk_der = core
        .get_or_create_ecdh_public_key()
        .expect("get_or_create_ecdh_public_key");
    assert!(!pk_der.is_empty(), "public key DER must not be empty");
}

// The registration key the device POSTs to /auth/device/register must be the
// raw 65-byte uncompressed SEC1 point (0x04‖X‖Y) hex, NOT the SPKI/DER that
// get_or_create_ecdh_public_key returns — the server's EncryptECIES parses it
// with ecdh.P256().NewPublicKey (raw-65 only) and does no DER→raw65 conversion.
#[test]
fn test_push_registration_public_key_is_raw65_sec1() {
    use p256::pkcs8::DecodePublicKey;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("guard.db").to_string_lossy().to_string();
    let core = GuardCore::new(db_path, "pw".to_string()).unwrap();

    let hex1 = core.push_registration_public_key_hex().unwrap();
    let raw = (0..hex1.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex1[i..i + 2], 16).unwrap())
        .collect::<Vec<u8>>();

    assert_eq!(raw.len(), 65, "must be a raw 65-byte SEC1 point");
    assert_eq!(raw[0], 0x04, "must be uncompressed (0x04 prefix)");

    // The raw-65 form must describe the SAME key the DER getter returns, and be
    // a valid P-256 point the server's ecdh.P256().NewPublicKey would accept.
    let from_raw = p256::PublicKey::from_sec1_bytes(&raw).expect("valid uncompressed point");
    let from_der =
        p256::PublicKey::from_public_key_der(&core.get_or_create_ecdh_public_key().unwrap())
            .unwrap();
    assert_eq!(
        from_raw, from_der,
        "raw65 and DER must be the same public key"
    );

    // Stable across calls (same persisted private key).
    assert_eq!(hex1, core.push_registration_public_key_hex().unwrap());
}

#[test]
fn test_push_approval_accepts_one_closed_assertion_record() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("guard.db").to_string_lossy().to_string();
    let core = GuardCore::new(db_path, "pw".to_string()).unwrap();
    let assertion = PushApprovalAssertion {
        nonce: "nonce-1".to_string(),
        code: "123456".to_string(),
        device_id: 7,
        user_id: 11,
        session_id: "session-1".to_string(),
        issued_at: 1_700_000_000,
        expires_at: 1_700_000_120,
    };

    let missing_key = core.sign_push_approval(assertion.clone()).unwrap_err();
    assert!(missing_key.to_string().contains("no push device key"));

    core.get_or_create_ecdh_public_key().unwrap();
    let signature = core.sign_push_approval(assertion).unwrap();
    assert_eq!(URL_SAFE_NO_PAD.decode(signature).unwrap().len(), 64);
}

#[test]
fn test_secure_store_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("guard.db").to_string_lossy().to_string();

    let core = GuardCore::new(db_path, "test-passphrase".to_string())
        .expect("GuardCore::new should succeed");

    // Absent key returns None.
    assert_eq!(core.meta_get("token".to_string()).unwrap(), None);

    // Set then get round-trips.
    core.meta_set("token".to_string(), "abc123".to_string())
        .unwrap();
    assert_eq!(
        core.meta_get("token".to_string()).unwrap(),
        Some("abc123".to_string())
    );

    // Overwrite.
    core.meta_set("token".to_string(), "xyz789".to_string())
        .unwrap();
    assert_eq!(
        core.meta_get("token".to_string()).unwrap(),
        Some("xyz789".to_string())
    );

    // Delete clears it.
    core.meta_delete("token".to_string()).unwrap();
    assert_eq!(core.meta_get("token".to_string()).unwrap(), None);
}

#[test]
fn test_secure_store_does_not_collide_with_internal_meta() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("guard.db").to_string_lossy().to_string();

    let core = GuardCore::new(db_path, "test-passphrase".to_string())
        .expect("GuardCore::new should succeed");

    // Establish the ECDH key (writes meta 'ecdh_sk_enc') and a secure-store value.
    let pk1 = core.get_or_create_ecdh_public_key().unwrap();
    core.meta_set("kdf_params".to_string(), "user-value".to_string())
        .unwrap();

    // The user's 'kdf_params' secure-store entry is namespaced and must NOT
    // clobber the internal KDF params or the ECDH key.
    assert_eq!(
        core.meta_get("kdf_params".to_string()).unwrap(),
        Some("user-value".to_string())
    );
    let pk2 = core.get_or_create_ecdh_public_key().unwrap();
    assert_eq!(pk1, pk2, "ECDH key must survive secure-store writes");
}

// The vault is a plaintext SQLite file; metadata must be column-encrypted so an
// attacker with the file can't enumerate which services a user holds 2FA for.
#[test]
fn test_totp_metadata_encrypted_at_rest() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("guard.db").to_string_lossy().to_string();

    let core = GuardCore::new(db_path.clone(), "pw".to_string()).unwrap();
    core.add_totp_account(
        "otpauth://totp/AcmeBankXYZ:alice@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=AcmeBankXYZ".to_string(),
    )
    .unwrap();

    // The API still returns cleartext label/issuer.
    let accts = core.list_accounts().unwrap();
    assert_eq!(accts.len(), 1);
    assert_eq!(accts[0].issuer, "AcmeBankXYZ");
    assert_eq!(accts[0].label, "AcmeBankXYZ:alice@example.com");
    drop(core);

    // ...but the cleartext issuer must NOT appear anywhere in the raw file/WAL.
    let mut disk = std::fs::read(&db_path).unwrap();
    for ext in ["-wal", "-shm"] {
        if let Ok(extra) = std::fs::read(format!("{db_path}{ext}")) {
            disk.extend(extra);
        }
    }
    assert!(
        !disk.windows(11).any(|w| w == b"AcmeBankXYZ"),
        "issuer must be column-encrypted at rest, not cleartext"
    );
}

// Pre-encryption builds stored label/issuer in cleartext. Opening the DB must
// upgrade those rows in place (idempotent, flag-gated) without losing data.
#[test]
fn test_legacy_plaintext_metadata_migrated_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("guard.db").to_string_lossy().to_string();

    {
        // Faithful pre-A2 shape: label/issuer are legacy cleartext, but
        // seed_enc/uri_enc were ALWAYS genuine AES-256-GCM ciphertext
        // (insert_totp has encrypted them since the columns existed). Persist
        // the KDF params, then encrypt the seed/uri under the key "pw" will
        // derive, via the public kdf/store API. (Placeholder zero bytes would
        // authenticate under no key and now — correctly — fail closed at open
        // as an unrecognized ciphertext shape, bricking the migration.)
        use guard_core::vault::kdf::{derive_key, KdfParams};
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        guard_core::db::schema::apply_migrations(&conn).unwrap();
        let params = KdfParams::default();
        // serde default struct JSON, as new() parses it back via serde_json.
        conn.execute(
            "INSERT INTO meta (key,value) VALUES ('kdf_params',?1)",
            rusqlite::params![format!(
                "{{\"m_cost\":{},\"t_cost\":{},\"p_cost\":{},\"salt\":\"{}\"}}",
                params.m_cost, params.t_cost, params.p_cost, params.salt
            )],
        )
        .unwrap();
        let key = derive_key("pw", &params).unwrap();
        conn.execute(
            "INSERT INTO totp_accounts (id,label,issuer,seed_enc,uri_enc) \
             VALUES ('id1','LegacyCorp:bob@old.test','LegacyCorp',?1,?2)",
            rusqlite::params![
                guard_core::db::store::encrypt(&key, b"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").unwrap(),
                guard_core::db::store::encrypt(
                    &key,
                    b"otpauth://totp/LegacyCorp:bob@old.test?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
                )
                .unwrap()
            ],
        )
        .unwrap();
    }

    {
        let core = GuardCore::new(db_path.clone(), "pw".to_string()).unwrap();
        let accts = core.list_accounts().unwrap();
        assert_eq!(accts.len(), 1);
        assert_eq!(accts[0].issuer, "LegacyCorp");
        assert_eq!(accts[0].label, "LegacyCorp:bob@old.test");
    }

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let raw_issuer: String = conn
        .query_row("SELECT issuer FROM totp_accounts WHERE id='id1'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_ne!(
        raw_issuer, "LegacyCorp",
        "issuer column must be encrypted after migration"
    );
    let flag: String = conn
        .query_row("SELECT value FROM meta WHERE key='metadata_enc'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(flag, "1", "migration must set the metadata_enc flag");
}

// ── med-shard3-004 r2: unrecognized ciphertext shape fails closed ────────────
//
// A sentinel-less vault holding a TOTP row whose `seed_enc` is TEXT (an
// unrecognized/corrupt shape — insert_totp has always stored a raw
// AES-256-GCM blob) beside an INTACT encrypted `uri_enc` used to be treated
// as EMPTY: the `if let Ok(blob)` probe swallowed the column-type error, fell
// through to `Ok(())`, and `new` provisioned `kek_check` under the WRONG
// passphrase — permanently locking out the right one. The probe must
// distinguish missing rows (QueryReturnedNoRows → absent, move on) from
// errors (→ fail-closed refusal); emptiness must be PROVEN before
// provisioning.
#[test]
fn unrecognized_shape_text_seed_enc_with_intact_uri_enc_refuses_provisioning() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("guard.db").to_string_lossy().to_string();
    let uri_enc_before: Vec<u8> = {
        let core = GuardCore::new(db_path.clone(), "right-pw".to_string()).unwrap();
        core.add_totp_account(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string(),
        )
        .unwrap();
        drop(core); // release the SQLite handle before surgery
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        // Corrupt the shape: TEXT storage in the BLOB-affinity column (SQLite
        // stores TEXT verbatim); uri_enc stays genuine ciphertext.
        conn.execute("UPDATE totp_accounts SET seed_enc='not-a-blob'", [])
            .unwrap();
        conn.execute(
            "DELETE FROM meta WHERE key IN ('kek_check','metadata_enc')",
            [],
        )
        .unwrap();
        conn.query_row("SELECT uri_enc FROM totp_accounts LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap()
    };

    // A wrong passphrase must NOT see an empty vault: the open fails closed
    // (probe error, not WrongPassphrase) and never provisions the sentinel.
    assert!(
        matches!(
            GuardCore::new(db_path.clone(), "wrong-pw".to_string()),
            Err(guard_core::GuardError::Database(_))
        ),
        "unrecognized shape must fail closed as a probe error, not provision a wrong-key sentinel"
    );
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        assert!(
            conn.query_row("SELECT value FROM meta WHERE key='kek_check'", [], |r| {
                r.get::<_, String>(0)
            })
            .is_err(),
            "a failed open on an unrecognized shape must not provision kek_check"
        );
    }

    // Fail-closed is universal: even the RIGHT passphrase cannot prove
    // emptiness against an unrecognized shape, so provisioning is refused for
    // every key (an unrecognized shape needs repair, not a guessed sentinel).
    assert!(
        matches!(
            GuardCore::new(db_path.clone(), "right-pw".to_string()),
            Err(guard_core::GuardError::Database(_))
        ),
        "the unrecognized shape refuses provisioning even for the right passphrase"
    );

    // The refusal is about the SHAPE, not data loss: the vault was not
    // mutated by either refused open — the intact uri_enc ciphertext is
    // byte-identical and the row is still there.
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let uri_enc_after: Vec<u8> = conn
            .query_row("SELECT uri_enc FROM totp_accounts LIMIT 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            uri_enc_after, uri_enc_before,
            "refused opens must not mutate the vault"
        );
        assert!(
            conn.query_row("SELECT value FROM meta WHERE key='kek_check'", [], |r| {
                r.get::<_, String>(0)
            })
            .is_err(),
            "still no sentinel provisioned after the refused right-passphrase open"
        );
    }
}
