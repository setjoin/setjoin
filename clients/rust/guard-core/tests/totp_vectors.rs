// RFC 6238 Appendix B test vectors (SHA-1, time T=0..59/1111111109/...)
// Using secret "12345678901234567890" (ASCII)

fn make_totp(secret_ascii: &str, digits: usize, step: u64) -> totp_rs::TOTP {
    use totp_rs::{Algorithm, Secret, TOTP};
    TOTP::new(
        Algorithm::SHA1,
        digits,
        1,
        step,
        Secret::Raw(secret_ascii.as_bytes().to_vec())
            .to_bytes()
            .unwrap(),
        None,
        "test".to_string(),
    )
    .unwrap()
}

#[test]
fn rfc6238_sha1_vectors() {
    // From RFC 6238 Appendix B
    let totp = make_totp("12345678901234567890", 8, 30);
    let cases: &[(u64, &str)] = &[
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ];
    for (ts, expected) in cases {
        let code = totp.generate(*ts);
        assert_eq!(&code, expected, "time={ts}");
    }
}

#[test]
fn add_and_generate_via_guardcore() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("g.db").to_string_lossy().to_string();
    let core = guard_core::GuardCore::new(path, "passphrase".to_string()).unwrap();

    // The base32 secret must be >= 128 bits. Use a 256-bit base32 secret.
    // GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ is the RFC 6238 SHA-256 test secret.
    let uri = "otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&digits=6";
    let id = core.add_totp_account(uri.to_string()).unwrap();

    let accounts = core.list_accounts().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id, id);

    let code = core.generate_totp(id.clone()).unwrap();
    assert_eq!(code.code.len(), 6);
    println!("generated code: {}", code.code);

    core.remove_account(id).unwrap();
    assert!(core.list_accounts().unwrap().is_empty());
}
