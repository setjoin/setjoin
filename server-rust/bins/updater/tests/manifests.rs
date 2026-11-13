use serde_json::{json, Value};
use std::{fs, process::Command};

#[test]
fn updater_accepts_and_rejects_recorded_go_manifests() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/shared-vectors/goldens/release.json"
    ))
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    for case in corpus["cases"].as_array().unwrap() {
        let i = &case["input"];
        if i["operation"] != "verify_manifest" {
            continue;
        }
        fs::write(
            temp.path().join("manifest.json"),
            i["document"].as_str().unwrap(),
        )
        .unwrap();
        let roots = json!({"schema_version":1,"purpose":"release","keys":[{
            "id":i["key_id"],"algorithm":"ed25519","public_key":i["public_key_base64"]
        }]});
        fs::write(temp.path().join("roots.json"), roots.to_string()).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_setjoin-updater"))
            .args(["verify", "--manifest"])
            .arg(temp.path().join("manifest.json"))
            .arg("--trust-roots")
            .arg(temp.path().join("roots.json"))
            .arg("--now")
            .arg(i["now"].as_str().unwrap())
            .arg("--minimum-threshold")
            .arg(i["minimum_threshold"].to_string())
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            case["output"]["accepted"].as_bool().unwrap(),
            "{}: {}",
            case["name"],
            String::from_utf8_lossy(&output.stderr)
        );
        if output.status.success() {
            let actual: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(actual["sha256"], case["output"]["sha256"]);
            assert_eq!(actual["canonical"], case["output"]["canonical"]);
            assert_eq!(actual["signer_key_ids"], case["output"]["signer_key_ids"]);
            // The same signed bytes under a different trust root must fail.
            let wrong = roots
                .to_string()
                .replace(i["key_id"].as_str().unwrap(), "wrong-key");
            fs::write(temp.path().join("roots.json"), wrong).unwrap();
            assert!(!Command::new(env!("CARGO_BIN_EXE_setjoin-updater"))
                .args(["verify", "--manifest"])
                .arg(temp.path().join("manifest.json"))
                .arg("--trust-roots")
                .arg(temp.path().join("roots.json"))
                .arg("--now")
                .arg(i["now"].as_str().unwrap())
                .args(["--minimum-threshold", "1"])
                .output()
                .unwrap()
                .status
                .success());
        }
    }
}

#[test]
fn updater_manifest_policy_matches_frozen_go_wrong_keys_and_rollback() {
    let corpus: Value = serde_json::from_str(include_str!("goldens/manifest-policy.json")).unwrap();
    let temp = tempfile::tempdir().unwrap();
    for case in corpus["cases"].as_array().unwrap() {
        fs::write(
            temp.path().join("manifest.json"),
            case["manifest"].to_string(),
        )
        .unwrap();
        fs::write(temp.path().join("roots.json"), case["roots"].to_string()).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-updater"));
        command
            .args(["verify", "--manifest"])
            .arg(temp.path().join("manifest.json"))
            .arg("--trust-roots")
            .arg(temp.path().join("roots.json"));
        for flag in case["flags"].as_array().unwrap() {
            command.arg(flag.as_str().unwrap());
        }
        let output = command.output().unwrap();
        assert_eq!(
            output.status.success(),
            case["output"]["accepted"].as_bool().unwrap(),
            "{}: {}",
            case["name"],
            String::from_utf8_lossy(&output.stderr)
        );
        if output.status.success() {
            let result: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result, case["output"], "{}", case["name"]);
        } else {
            assert_eq!(
                String::from_utf8(output.stderr).unwrap().trim(),
                case["output"]["error"].as_str().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
}
