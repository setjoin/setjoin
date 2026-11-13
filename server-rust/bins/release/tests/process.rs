use serde_json::Value;
use std::{fs, process::Command};

fn vector() -> Value {
    let v: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/shared-vectors/goldens/release.json"
    ))
    .unwrap();
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "sign_manifest")
        .unwrap()
        .clone()
}
#[test]
fn signer_helper_receives_go_canonical_bytes_and_outputs_identical_manifest() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::Builder::new()
        .prefix("gofree-rel1-sign-")
        .tempdir()
        .unwrap();
    let v = vector();
    fs::write(
        dir.path().join("manifest"),
        v["input"]["document"].as_str().unwrap(),
    )
    .unwrap();
    let signed = v["output"]["document"].as_str().unwrap();
    let m: Value = serde_json::from_str(signed).unwrap();
    let signature = m["signatures"][0]["value"].as_str().unwrap();
    let helper = dir.path().join("helper");
    fs::write(&helper, format!("#!/bin/sh\n[ \"$1 $2 $3\" = 'sign --key-id fixture-key' ] || exit 5\ncat > '{}'/payload\nprintf '%s\\n' '{}'\n", dir.path().display(), signature)).unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_setjoin-release"))
        .args(["manifest", "sign", "--manifest"])
        .arg(dir.path().join("manifest"))
        .arg("--signer-helper")
        .arg(&helper)
        .args(["--key-id", "fixture-key", "--output"])
        .arg(dir.path().join("signed"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert_eq!(
        fs::read(dir.path().join("signed")).unwrap(),
        signed.as_bytes()
    );
    let expected = v["input"]["document"]
        .as_str()
        .unwrap()
        .replace("\"signatures\":[]", "\"signatures\":null");
    assert_eq!(
        fs::read(dir.path().join("payload")).unwrap(),
        expected.as_bytes()
    );
}

#[test]
fn build_hashes_inventory_and_migration_identically_to_go() {
    let dir = tempfile::Builder::new()
        .prefix("gofree-rel1-build-")
        .tempdir()
        .unwrap();
    let v = vector();
    let mut m: Value = serde_json::from_str(v["input"]["document"].as_str().unwrap()).unwrap();
    for a in m["artifacts"].as_array_mut().unwrap() {
        fs::write(dir.path().join(a["id"].as_str().unwrap()), b"abc").unwrap();
        a["size"] = 0.into();
        a["sha256"] = "".into();
    }
    for a in m["migrations"].as_array_mut().unwrap() {
        a["sha256"] = "".into();
    }
    fs::write(dir.path().join("draft"), serde_json::to_vec(&m).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_setjoin-release"))
        .args(["manifest", "build", "--draft"])
        .arg(dir.path().join("draft"))
        .arg("--artifacts-dir")
        .arg(dir.path())
        .arg("--output")
        .arg(dir.path().join("built"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(dir.path().join("built")).unwrap(),
        include_bytes!("goldens/go-built.json")
    );
}

#[test]
fn build_rejects_symlinked_artifact_and_preserves_output() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::Builder::new()
        .prefix("gofree-rel1-symlink-")
        .tempdir()
        .unwrap();
    let manifest: Value = serde_json::from_slice(include_bytes!("goldens/go-built.json")).unwrap();
    for a in manifest["artifacts"].as_array().unwrap() {
        fs::write(dir.path().join(a["id"].as_str().unwrap()), b"abc").unwrap();
    }
    fs::write(
        dir.path().join("draft"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    fs::write(dir.path().join("published"), b"previous published bytes").unwrap();
    let artifact = dir.path().join("mailserverd");
    fs::rename(&artifact, dir.path().join("outside-inventory")).unwrap();
    symlink("outside-inventory", &artifact).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_setjoin-release"))
        .args(["manifest", "build", "--draft"])
        .arg(dir.path().join("draft"))
        .arg("--artifacts-dir")
        .arg(dir.path())
        .arg("--output")
        .arg(dir.path().join("published"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        fs::read(dir.path().join("published")).unwrap(),
        b"previous published bytes"
    );
}

#[test]
fn offline_verify_enforces_dual_control_and_artifact_bytes() {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let dir = tempfile::Builder::new()
        .prefix("gofree-rel1-verify-")
        .tempdir()
        .unwrap();
    let key1 = Ed25519KeyPair::from_seed_unchecked(&[17; 32]).unwrap();
    let key2 = Ed25519KeyPair::from_seed_unchecked(&[29; 32]).unwrap();
    let mut manifest =
        setjoin_release_format::Manifest::parse(include_bytes!("goldens/go-built.json")).unwrap();
    let now = chrono::Utc::now();
    manifest.published_at = (now - chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    manifest.expires_at = (now + chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    for a in manifest.artifacts.as_ref().unwrap() {
        fs::write(dir.path().join(&a.id), b"abc").unwrap();
    }
    manifest
        .sign_with("key-a", |b| Ok(key1.sign(b).as_ref().to_vec()))
        .unwrap();
    manifest
        .sign_with("key-b", |b| Ok(key2.sign(b).as_ref().to_vec()))
        .unwrap();
    let roots = serde_json::json!({"schema_version":1,"purpose":"release","keys":[
        {"id":"key-a","algorithm":"ed25519","public_key":STANDARD_NO_PAD.encode(key1.public_key().as_ref())},
        {"id":"key-b","algorithm":"ed25519","public_key":STANDARD_NO_PAD.encode(key2.public_key().as_ref())}
    ]});
    fs::write(
        dir.path().join("roots"),
        serde_json::to_vec(&roots).unwrap(),
    )
    .unwrap();
    fs::write(dir.path().join("manifest"), manifest.marshal().unwrap()).unwrap();
    let verify = || {
        Command::new(env!("CARGO_BIN_EXE_setjoin-release"))
            .args(["manifest", "verify", "--offline", "--manifest"])
            .arg(dir.path().join("manifest"))
            .arg("--artifacts-dir")
            .arg(dir.path())
            .arg("--trust-roots")
            .arg(dir.path().join("roots"))
            .args(["--channel", "community", "--current-version", "2.0.5"])
            .output()
            .unwrap()
    };
    let output = verify();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "verified release release-2.1.0 digest {}\n",
            setjoin_release_format::sha256(&manifest.canonical().unwrap())
        )
    );
    fs::write(dir.path().join("mailserverd"), b"abd").unwrap();
    assert!(!verify().status.success());
    fs::write(dir.path().join("mailserverd"), b"abc").unwrap();
    manifest.signatures.as_mut().unwrap().pop();
    fs::write(dir.path().join("manifest"), manifest.marshal().unwrap()).unwrap();
    let output = verify();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("threshold"));
}

#[test]
fn inspect_matches_go_operator_output() {
    let dir = tempfile::Builder::new()
        .prefix("gofree-rel1-inspect-")
        .tempdir()
        .unwrap();
    fs::write(
        dir.path().join("manifest"),
        include_bytes!("goldens/go-built.json"),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_setjoin-release"))
        .args(["manifest", "inspect", "--manifest"])
        .arg(dir.path().join("manifest"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"{\n  \"releaseId\": \"release-2.1.0\",\n  \"version\": \"2.1.0\",\n  \"channel\": \"community\",\n  \"metadataVersion\": 7,\n  \"schemaFrom\": 177,\n  \"schemaTo\": 178,\n  \"artifactCount\": 8,\n  \"signatureKeyIds\": []\n}\n");
}

#[test]
fn signing_pipeline_runs_rust_build_sign_verify_before_publishing_manifest() {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::Builder::new()
        .prefix("gofree-rel1-pipeline-")
        .tempdir()
        .unwrap();
    let root = dir.path();
    let mut m: Value = serde_json::from_slice(include_bytes!("goldens/go-built.json")).unwrap();
    let now = chrono::Utc::now();
    m["published_at"] = (now - chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
        .into();
    m["expires_at"] = (now + chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
        .into();
    for a in m["artifacts"].as_array_mut().unwrap() {
        fs::write(root.join(a["id"].as_str().unwrap()), b"abc").unwrap();
        a["size"] = 0.into();
        a["sha256"] = "".into();
    }
    for a in m["migrations"].as_array_mut().unwrap() {
        a["sha256"] = "".into();
    }
    fs::write(root.join("draft"), serde_json::to_vec(&m).unwrap()).unwrap();
    let pair = Ed25519KeyPair::from_seed_unchecked(&[17; 32]).unwrap();
    let pair2 = Ed25519KeyPair::from_seed_unchecked(&[29; 32]).unwrap();
    // A test helper invokes this test executable in its separate helper-only mode.
    let helper = root.join("helper");
    let roots = serde_json::json!({"schema_version":1,"purpose":"release","keys":[
        {"id":"key-a","algorithm":"ed25519","public_key":STANDARD_NO_PAD.encode(pair.public_key().as_ref())},
        {"id":"key-b","algorithm":"ed25519","public_key":STANDARD_NO_PAD.encode(pair2.public_key().as_ref())}
    ]});
    fs::write(root.join("roots"), serde_json::to_vec(&roots).unwrap()).unwrap();
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../scripts/sign-server-release.sh");
    // Helper stdout must contain only the signature; a sed adapter strips the
    // libtest framing. Key material stays public and test-only.
    fs::write(&helper, format!("#!/bin/sh\nexport REL1_HELPER_KEY=\"$3\"\n'{}' --exact pipeline_fixture_helper --nocapture | sed -n 's/.*REL1_SIGNATURE://p'\n", std::env::current_exe().unwrap().display())).unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new("bash")
        .arg(&script)
        .args([
            root.join("draft"),
            root.to_path_buf(),
            root.join("roots"),
            helper.clone(),
            root.join("published"),
        ])
        .args(["community", "2.0.5", "linux", "amd64", "key-a", "key-b"])
        .env("SETJOIN_RELEASE_BIN", env!("CARGO_BIN_EXE_setjoin-release"))
        .env("REL1_HELPER_MODE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let signed =
        setjoin_release_format::Manifest::parse(&fs::read(root.join("published")).unwrap())
            .unwrap();
    assert_eq!(
        signed
            .signatures
            .unwrap()
            .iter()
            .map(|s| s.key_id.as_str())
            .collect::<Vec<_>>(),
        ["key-a", "key-b"]
    );
    // An output directory must not be treated as a request to move the file inside it.
    let directory = root.join("directory");
    fs::create_dir(&directory).unwrap();
    let output = Command::new("bash")
        .arg(&script)
        .args([
            root.join("draft"),
            root.to_path_buf(),
            root.join("roots"),
            helper.clone(),
            directory.clone(),
        ])
        .args(["community", "2.0.5", "linux", "amd64", "key-a", "key-b"])
        .env("SETJOIN_RELEASE_BIN", env!("CARGO_BIN_EXE_setjoin-release"))
        .env("REL1_HELPER_MODE", "1")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read_dir(directory).unwrap().count(), 0);
    // A failed verification must preserve an already published manifest.
    fs::write(root.join("roots"), b"{}").unwrap();
    let before = fs::read(root.join("published")).unwrap();
    let output = Command::new("bash")
        .arg(&script)
        .args([
            root.join("draft"),
            root.to_path_buf(),
            root.join("roots"),
            helper,
            root.join("published"),
        ])
        .args(["community", "2.0.5", "linux", "amd64", "key-a", "key-b"])
        .env("SETJOIN_RELEASE_BIN", env!("CARGO_BIN_EXE_setjoin-release"))
        .env("REL1_HELPER_MODE", "1")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read(root.join("published")).unwrap(), before);
}

#[test]
fn pipeline_fixture_helper() {
    if std::env::var("REL1_HELPER_MODE").as_deref() != Ok("1") {
        return;
    }
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    use std::io::Read;
    let mut payload = Vec::new();
    std::io::stdin().read_to_end(&mut payload).unwrap();
    let seed = if std::env::var("REL1_HELPER_KEY").as_deref() == Ok("key-b") {
        [29; 32]
    } else {
        [17; 32]
    };
    let key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    println!(
        "REL1_SIGNATURE:{}",
        STANDARD_NO_PAD.encode(key.sign(&payload).as_ref())
    );
}

#[test]
fn failed_malformed_or_oversized_helper_preserves_output_and_reveals_no_stderr() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::Builder::new()
        .prefix("gofree-rel1-helper-fail-")
        .tempdir()
        .unwrap();
    fs::write(
        dir.path().join("manifest"),
        vector()["input"]["document"].as_str().unwrap(),
    )
    .unwrap();
    let helper = dir.path().join("helper");
    let output_path = dir.path().join("signed");
    for script in [
        "echo PRIVATE-HELPER-ERROR >&2; exit 42",
        "printf invalid",
        "head -c 1025 /dev/zero",
        "printf AA",
    ] {
        fs::write(&helper, format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&output_path, b"previous published bytes").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_setjoin-release"))
            .args(["manifest", "sign", "--manifest"])
            .arg(dir.path().join("manifest"))
            .arg("--signer-helper")
            .arg(&helper)
            .args(["--key-id", "fixture-key", "--output"])
            .arg(&output_path)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{script}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE-HELPER-ERROR"));
        assert_eq!(fs::read(&output_path).unwrap(), b"previous published bytes");
        assert!(fs::read_dir(dir.path()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
    }
}

#[test]
fn signer_deadline_kills_and_reaps_the_helper() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::Builder::new()
        .prefix("gofree-rel1-timeout-")
        .tempdir()
        .unwrap();
    fs::write(
        dir.path().join("manifest"),
        vector()["input"]["document"].as_str().unwrap(),
    )
    .unwrap();
    let helper = dir.path().join("helper");
    fs::write(
        &helper,
        format!(
            "#!/bin/sh\necho $$ > '{}'\nexec sleep 60\n",
            dir.path().join("pid").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_setjoin-release"))
        .args(["manifest", "sign", "--manifest"])
        .arg(dir.path().join("manifest"))
        .arg("--signer-helper")
        .arg(&helper)
        .args(["--key-id", "fixture-key", "--output"])
        .arg(dir.path().join("signed"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("signer helper failed"));
    assert!(!dir.path().join("signed").exists());
    let pid = fs::read_to_string(dir.path().join("pid")).unwrap();
    assert!(
        !std::path::Path::new("/proc").join(pid.trim()).exists(),
        "helper was not reaped"
    );
}
