//! Integrity of immutable external-Go observations and their replay stimuli.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

#[test]
fn outbound_receipt_pins_go_sources_stimuli_and_observations() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
    let receipt: Value =
        serde_json::from_str(include_str!("../oracle/outbound-recording.json")).unwrap();
    let verify = |files: &Value| {
        for (file, digest) in files.as_object().unwrap() {
            let bytes = std::fs::read(root.join(file)).unwrap();
            assert_eq!(
                format!("{:x}", Sha256::digest(bytes)),
                digest.as_str().unwrap(),
                "recorded input changed: {file}"
            );
        }
    };
    for key in [
        "go_runtime_sha256",
        "recorder_files",
        "current_fixture_sha256",
    ] {
        verify(&receipt[key]);
    }
    for corpus in receipt["corpora"].as_array().unwrap() {
        let files = corpus["sha256"].as_object().unwrap();
        // Historical recorder/cleanup digests are bound to inputs_commit;
        // current sources/fixtures are checked separately above.
        let immutable: serde_json::Map<String, Value> = files
            .iter()
            .filter(|(file, _)| file.ends_with("-go.json") || file.ends_with("-requests.json"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        verify(&Value::Object(immutable));
        let base = format!(
            "server-rust/crates/protocols/smtp/oracle/{}",
            corpus["name"].as_str().unwrap()
        );
        let goldens: Value =
            serde_json::from_slice(&std::fs::read(root.join(format!("{base}-go.json"))).unwrap())
                .unwrap();
        let stimuli: Value = serde_json::from_slice(
            &std::fs::read(root.join(format!("{base}-requests.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            goldens.as_array().unwrap().len() as u64,
            corpus["cases"].as_u64().unwrap()
        );
        assert_eq!(
            goldens.as_array().unwrap().len(),
            stimuli.as_array().unwrap().len()
        );
        for (golden, stimulus) in goldens
            .as_array()
            .unwrap()
            .iter()
            .zip(stimuli.as_array().unwrap())
        {
            for (key, value) in stimulus.as_object().unwrap() {
                // Go's DNS field has omitempty: an explicitly empty fixture map
                // serializes as an absent property. Other values remain exact.
                let expected = if key == "dns" && value.as_object().is_some_and(|m| m.is_empty()) {
                    &Value::Null
                } else {
                    value
                };
                assert_eq!(
                    &golden["case"][key], expected,
                    "stimulus differs from recorded input: {base} {key}"
                );
            }
        }
    }
}
