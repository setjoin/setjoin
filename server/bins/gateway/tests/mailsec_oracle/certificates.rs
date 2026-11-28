//! Published input bytes for the strict Go X.509 parsing profile (#468).
use serde::Deserialize;
use std::path::PathBuf;
#[derive(Deserialize)]
pub struct Case {
    pub name: String,
    pub rejected: bool,
    pub sha256: String,
}
pub fn cases() -> Vec<Case> {
    serde_json::from_str(include_str!(
        "../../../../tests/conformance/mail-security/smime-certs/strict-cases.json"
    ))
    .expect("strict certificate case table")
}
pub fn pem(name: &str) -> String {
    use sha2::{Digest, Sha256};
    let case = cases()
        .into_iter()
        .find(|c| c.name == name)
        .expect("known certificate fixture");
    let file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/mail-security/smime-certs")
        .join(format!("{name}.pem"));
    let pem = std::fs::read_to_string(file).expect("certificate fixture");
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("PEM framing");
    assert_eq!(
        format!("{:x}", Sha256::digest(&parsed.contents)),
        case.sha256,
        "fixture changed after Go recording"
    );
    pem
}
