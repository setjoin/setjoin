//! Immutable toggle-ON SMTP stimuli and frozen-Go observations.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

#[test]
fn enabled_inbound_receipt_pins_frozen_go_and_every_recorded_corpus() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let receipt: Value =
        serde_json::from_str(include_str!("../oracle/security-recording.json")).unwrap();
    for files in std::iter::once(&receipt["go_runtime_sha256"]).chain(
        receipt["corpora"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| &c["sha256"]),
    ) {
        for (file, digest) in files.as_object().unwrap() {
            assert_eq!(
                format!(
                    "{:x}",
                    Sha256::digest(std::fs::read(root.join(file)).unwrap())
                ),
                digest.as_str().unwrap(),
                "recorded input changed: {file}"
            );
        }
    }
    for c in receipt["corpora"].as_array().unwrap() {
        let path = root.join(format!(
            "server-rust/crates/protocols/smtp/oracle/{}",
            c["name"].as_str().unwrap()
        ));
        let read = |kind: &str| -> Vec<Value> {
            serde_json::from_slice(
                &std::fs::read(format!("{}-{kind}.json", path.display())).unwrap(),
            )
            .unwrap()
        };
        let requests = read("requests");
        let goldens = read("go");
        assert_eq!(goldens.len(), c["cases"].as_u64().unwrap() as usize);
        assert_eq!(requests.len(), goldens.len());
        for (request, golden) in requests.iter().zip(goldens.iter()) {
            input_is_preserved(request, golden);
        }
    }
}
fn input_is_preserved(request: &Value, golden: &Value) {
    match request {
        Value::Object(fields) => {
            for (key, value) in fields {
                input_is_preserved(value, &golden[key]);
            }
        }
        Value::Array(items) => {
            let recorded = golden.as_array().unwrap();
            assert_eq!(items.len(), recorded.len());
            for (item, observed) in items.iter().zip(recorded) {
                input_is_preserved(item, observed);
            }
        }
        _ => assert_eq!(request, golden, "recorded stimulus changed"),
    }
}

/// `auth-recording.json` hand-pins (`sha256`) must match the files on disk; a refresh script that
/// moves a recorded corpus has to re-pin it (the pins went stale once after the 2100 DKIM refresh).
#[test]
fn auth_recording_pins_match_the_files_on_disk() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let receipt: Value =
        serde_json::from_str(include_str!("../oracle/auth-recording.json")).unwrap();
    let pins = receipt["sha256"].as_object().unwrap();
    assert!(pins.contains_key("server-rust/crates/protocols/smtp/oracle/dkim-go.json"));
    for (file, digest) in pins {
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(std::fs::read(root.join(file)).unwrap())
            ),
            digest.as_str().unwrap(),
            "auth-recording.json pin is stale: {file}"
        );
    }
}
