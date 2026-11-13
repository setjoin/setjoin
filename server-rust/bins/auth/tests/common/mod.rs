//! Family seed: the immutable Go-recorded synthetic key, independent of test order.
//! Caller holds the family owner-connection advisory lock for the whole case.
pub async fn signing_key(c: &tokio_postgres::Client) {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let raw = f["envelope"].as_str().unwrap();
    let envelope: Vec<u8> = (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
        .collect();
    c.execute("DELETE FROM signing_keys", &[]).await.unwrap();
    c.execute("INSERT INTO signing_keys(kid,alg,public_jwk,private_key_enc,status) VALUES($1,'ES256',$2::text::jsonb,$3,'active')",&[&f["kid"].as_str().unwrap(),&f["jwks"]["keys"][0].to_string(),&envelope]).await.unwrap();
}

pub async fn receipt_ids(c: &tokio_postgres::Client) -> Vec<String> {
    c.query(
        "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F21'",
        &[],
    )
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect()
}
pub async fn restore_receipts(c: &tokio_postgres::Client, before: &[String]) {
    c.execute("DELETE FROM rust_operation_receipts WHERE family='F21' AND operation_id::text<>ALL($1::text[])",&[&before]).await.unwrap();
}

/// Security expectations are authored from the owner decision; immutable Go
/// captures remain hash-pinned and are never rewritten from Rust responses.
#[allow(dead_code)]
pub fn security_expectation(baseline: &std::path::Path) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    let family=baseline.parent().unwrap().parent().unwrap();
    let entries:serde_json::Value=serde_json::from_str(&std::fs::read_to_string(family.join("divergences.json")).unwrap()).unwrap();
    let relative=baseline.strip_prefix(family).unwrap().to_str().unwrap();
    let entry=entries.as_array().unwrap().iter().find(|e|e["baseline"]==relative).expect("reviewed security divergence");
    assert_eq!(entry["reviewed"],true);
    assert!(entry["reason"].as_str().unwrap().contains("owner-approved security fix 2026-11-05"));
    assert_eq!(entry["sha256"],format!("{:x}",Sha256::digest(std::fs::read(baseline).unwrap())));
    serde_json::from_str(&std::fs::read_to_string(family.join(entry["expectation"].as_str().unwrap())).unwrap()).unwrap()
}

/// Expected document for `baseline`. A protected case (an owner-approved security
/// divergence) is compared with its reviewed expectation instead of the frozen-Go
/// baseline; `SECFIX3_WRITE_SECURITY=1` writes the expectation from the actual
/// document (for human review against the baseline diff) and is never used in CI.
#[allow(dead_code)]
pub fn expected(baseline: &std::path::Path, protected: bool, actual: &serde_json::Value) -> serde_json::Value {
    if !protected {
        return serde_json::from_slice(&std::fs::read(baseline).unwrap()).unwrap();
    }
    if std::env::var_os("SECFIX3_WRITE_SECURITY").is_some() {
        let family = baseline.parent().unwrap().parent().unwrap();
        let dir = family.join("security");
        std::fs::create_dir_all(&dir).unwrap();
        let mut text = serde_json::to_string_pretty(actual).unwrap();
        text.push('\n');
        std::fs::write(dir.join(baseline.file_name().unwrap()), text).unwrap();
        return actual.clone();
    }
    security_expectation(baseline)
}
