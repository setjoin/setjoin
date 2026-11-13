use guard_core::totp::parser::parse_otpauth_uri;

#[test]
fn test_parse_otpauth_uri_label() {
    // Base32 secret must be >= 128 bits (16 bytes, ~26 base32 chars).
    // JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP = 32 base32 chars = 160 bits.
    let uri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example";
    let parsed = parse_otpauth_uri(uri).expect("should parse valid URI");
    assert_eq!(parsed.label, "Example:alice@example.com");
    assert_eq!(parsed.issuer, "Example");
}
