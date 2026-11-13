use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use ring::signature::Ed25519KeyPair;
use serde_json::Value;
use setjoin_release_format::{Manifest, Purpose, TrustStore, TrustedKey, VerifyOptions};

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/conformance/shared-vectors/goldens/release.json"
    ))
    .unwrap()
}

#[test]
fn rust_signs_byte_identically_to_frozen_go() {
    let vectors = vectors();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "sign_manifest")
        .unwrap();
    let input = &case["input"];
    let mut manifest = Manifest::parse(input["document"].as_str().unwrap().as_bytes()).unwrap();
    let key = Ed25519KeyPair::from_seed_unchecked(input["seed_utf8"].as_str().unwrap().as_bytes())
        .unwrap();
    manifest
        .sign_with(input["key_id"].as_str().unwrap(), |bytes| {
            Ok(key.sign(bytes).as_ref().to_vec())
        })
        .unwrap();
    assert_eq!(
        String::from_utf8(manifest.marshal().unwrap()).unwrap(),
        case["output"]["document"]
    );
}

#[test]
fn go_release_vectors_verify_and_reject() {
    for case in vectors()["cases"].as_array().unwrap() {
        let input = &case["input"];
        if input["operation"] != "verify_manifest" {
            continue;
        }
        let key = TrustedKey {
            id: input["key_id"].as_str().unwrap().into(),
            purpose: Purpose::Release,
            public_key: STANDARD_NO_PAD
                .decode(input["public_key_base64"].as_str().unwrap())
                .unwrap(),
            test_only: false,
            organization_artifact_set: Default::default(),
        };
        let store = TrustStore::new(vec![key], false).unwrap();
        let options = VerifyOptions {
            now: chrono::DateTime::parse_from_rfc3339(input["now"].as_str().unwrap())
                .unwrap()
                .into(),
            minimum_threshold: input["minimum_threshold"].as_u64().unwrap() as usize,
            ..Default::default()
        };
        let result =
            store.verify_manifest(input["document"].as_str().unwrap().as_bytes(), &options);
        assert_eq!(
            result.is_ok(),
            case["output"]["accepted"],
            "{}: {result:?}",
            case["name"]
        );
        if let Ok(verified) = result {
            assert_eq!(
                String::from_utf8(verified.canonical_bytes).unwrap(),
                case["output"]["canonical"]
            );
            assert_eq!(verified.digest, case["output"]["sha256"]);
            assert_eq!(
                serde_json::to_value(verified.signer_key_ids).unwrap(),
                case["output"]["signer_key_ids"]
            );
        }
    }
}

#[test]
fn updater_fixture_manifests_verify_and_resign_byte_for_byte() {
    let fixtures: Value =
        serde_json::from_str(include_str!("goldens/updater-fixtures.json")).unwrap();
    for sample in fixtures["samples"].as_array().unwrap() {
        let bytes = serde_json::to_vec(&sample["manifest"]).unwrap();
        let mut manifest = Manifest::parse(&bytes).unwrap();
        let key = TrustedKey {
            id: sample["key_id"].as_str().unwrap().into(),
            purpose: Purpose::Release,
            public_key: STANDARD_NO_PAD
                .decode(sample["public_key"].as_str().unwrap())
                .unwrap(),
            test_only: sample["test_only"].as_bool().unwrap(),
            organization_artifact_set: Default::default(),
        };
        let mut keys = vec![key.clone()];
        if sample["name"] == "optional-multisig" {
            let mut second = key.clone();
            second.id = "key-z".into();
            keys.push(second);
        }
        let options = VerifyOptions {
            now: chrono::DateTime::parse_from_rfc3339(fixtures["now"].as_str().unwrap())
                .unwrap()
                .into(),
            ..Default::default()
        };
        let verified = TrustStore::new(keys.clone(), true)
            .unwrap()
            .verify_manifest(&bytes, &options)
            .unwrap();
        assert_eq!(
            String::from_utf8(verified.canonical_bytes).unwrap(),
            sample["canonical"]
        );
        if key.test_only {
            assert!(TrustStore::new(keys, false).is_err());
        }
        if sample["name"] == "optional-multisig" {
            manifest.signatures = None;
            let pair =
                Ed25519KeyPair::from_seed_unchecked(b"0123456789abcdef0123456789abcdef").unwrap();
            for id in ["key-z", "key-a"] {
                manifest
                    .sign_with(id, |b| Ok(pair.sign(b).as_ref().to_vec()))
                    .unwrap();
            }
            assert_eq!(
                serde_json::from_slice::<Value>(&manifest.marshal().unwrap()).unwrap(),
                sample["manifest"]
            );
        }
    }
}

#[test]
fn artifact_size_and_digest_rejections_match_go_vectors() {
    for case in vectors()["cases"].as_array().unwrap() {
        let input = &case["input"];
        if input["operation"] != "verify_artifact" {
            continue;
        }
        let artifact = setjoin_release_format::Artifact {
            id: "fixture".into(),
            size: input["size"].as_u64().unwrap(),
            sha256: input["sha256"].as_str().unwrap().into(),
            ..Default::default()
        };
        let result = setjoin_release_format::verify_artifact(
            input["content_utf8"].as_str().unwrap().as_bytes(),
            &artifact,
        );
        assert_eq!(
            result.is_ok(),
            case["output"]["accepted"],
            "{}",
            case["name"]
        );
        if let Err(error) = result {
            assert_eq!(
                error.to_string(),
                case["output"]["error"],
                "{}",
                case["name"]
            );
        }
    }
}

#[test]
fn json_parsing_matches_recorded_go_edge_cases() {
    let corpus: Value = serde_json::from_str(include_str!("goldens/edge-cases.json")).unwrap();
    for edge in corpus["edges"].as_array().unwrap() {
        let input = STANDARD_NO_PAD
            .decode(edge["input_base64"].as_str().unwrap())
            .unwrap();
        let result = Manifest::parse(&input);
        assert_eq!(
            result.is_ok(),
            edge["accepted"],
            "{}: {result:?}",
            edge["name"]
        );
        if let Ok(m) = result {
            assert_eq!(
                String::from_utf8(m.canonical().unwrap()).unwrap(),
                edge["canonical"],
                "{}",
                edge["name"]
            );
        }
    }
}

#[test]
fn case_distinct_struct_fields_merge_and_null_scalars_keep_the_previous_value() {
    let vectors = vectors();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "sign_manifest")
        .unwrap();
    let raw = case["input"]["document"].as_str().unwrap();
    let merged = raw.replace(
        "\"signing\":{\"threshold\":1}",
        "\"signing\":{\"threshold\":1},\"SIGNING\":{\"rotation_key_ids\":[\"key-a\"]}",
    );
    let parsed = Manifest::parse(merged.as_bytes()).unwrap();
    assert_eq!(parsed.signing.threshold, 1);
    assert_eq!(parsed.signing.rotation_key_ids.unwrap(), ["key-a"]);
    let null = raw.replace(
        "\"metadata_version\":7",
        "\"metadata_version\":7,\"METADATA_VERSION\":null",
    );
    assert_eq!(
        Manifest::parse(null.as_bytes()).unwrap().metadata_version,
        7
    );
}
