//! Immutable frozen-Go Model load/train/save/score vectors. Entire sealed blobs compare.
use base64::{engine::general_purpose::STANDARD, Engine};
use flate2::read::GzDecoder;
use serde_json::Value;
use setjoin_mail_security::spam_model::Model;
use std::{io::Read, path::PathBuf};

fn blob(root: &std::path::Path, name: &str, phase: &str) -> Vec<u8> {
    let mut data = Vec::new();
    GzDecoder::new(std::fs::File::open(root.join(format!("{name}-{phase}.gz"))).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    data
}

#[test]
fn frozen_go_sealed_model_bytes_after_training() {
    replay("models.json");
}

#[test]
fn frozen_go_tokenizer_compatibility_bytes() {
    replay("compat.json");
}

fn replay(manifest: &str) {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/conformance/spam-trainer");
    let cases: Value =
        serde_json::from_slice(&std::fs::read(root.join(manifest)).unwrap()).unwrap();
    for c in cases["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let raw = STANDARD.decode(c["raw"].as_str().unwrap()).unwrap();
        let mut model =
            Model::load(c["user"].as_i64().unwrap(), &blob(&root, name, "before")).unwrap();
        assert_eq!(
            format!("{:016x}", model.score(&raw).to_bits()),
            c["score_bits"],
            "{name} probability"
        );
        for n in 0..c["steps"].as_u64().unwrap() {
            model.train(&raw, n % 3 != 0);
        }
        let got = model.save();
        let want = blob(&root, name, "after");
        assert_eq!(got.len(), want.len(), "{name}");
        assert!(
            got == want,
            "{name}: first differing byte {:?}",
            got.iter().zip(&want).position(|(a, b)| a != b)
        );
    }
}
