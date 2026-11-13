use std::process::Command;
#[test]
fn immutable_layout_adoption_matches_recorded_go() {
    let output = Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/adoption.py"))
        .arg(env!("CARGO_BIN_EXE_setjoin-updater"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// #506: Go's managed-adoption gap is closed; the tampered tree is refused and the
/// install aborts before any `*.prev` is quarantined. The frozen-Go recording of the
/// gap was removed with the behaviour it recorded.
#[test]
fn existing_managed_adoption_refuses_tampered_content() {
    let output = Command::new("python3")
        .env("REL3_ADOPTION_CASE", "adoption-managed-tamper")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/adoption.py"))
        .arg(env!("CARGO_BIN_EXE_setjoin-updater"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

mod managed {
    use base64::{engine::general_purpose::STANDARD_NO_PAD as B64, Engine};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::Value;
    use setjoin_release_format::{hash_artifact, sha256, Manifest};
    use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

    fn write(path: &Path, raw: &[u8], mode: u32) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        fs::write(path, raw).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    fn digest_tree(dir: &Path) -> String {
        fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
            for e in fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                out.push(p.clone());
                if p.is_dir() {
                    walk(&p, out);
                }
            }
        }
        let mut paths = Vec::new();
        walk(dir, &mut paths);
        paths.sort();
        let mut bytes = Vec::new();
        for p in paths {
            let rel = p.strip_prefix(dir).unwrap().to_str().unwrap().to_owned();
            if rel == "installed.evidence.json" {
                continue;
            }
            if p.is_dir() {
                bytes.extend(format!("d\0{rel}\0\0").into_bytes());
            } else {
                let h = hash_artifact(fs::File::open(&p).unwrap()).unwrap().1;
                bytes.extend(format!("f\0{rel}\0{h}\0").into_bytes());
            }
        }
        sha256(&bytes)
    }
    fn arch() -> &'static str {
        match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "loongarch64" => "loong64",
            v => v,
        }
    }
    struct Keys(Vec<(String, Ed25519KeyPair)>);
    fn keys(n: usize) -> Keys {
        Keys(
            (0..n)
                .map(|i| {
                    let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
                    (format!("fixture-key-{i}"), Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap())
                })
                .collect(),
        )
    }
    fn roots_doc(k: &Keys) -> String {
        let keys: Vec<_> = k
            .0
            .iter()
            .map(|(id, p)| serde_json::json!({"id":id,"algorithm":"ed25519","public_key":B64.encode(p.public_key().as_ref())}))
            .collect();
        serde_json::json!({"schema_version":1,"purpose":"release","keys":keys}).to_string()
    }
    struct Fixture {
        _tmp: tempfile::TempDir,
        install: std::path::PathBuf,
        release: std::path::PathBuf,
        config: std::path::PathBuf,
        roots: std::path::PathBuf,
        quarantine: std::path::PathBuf,
        keys: Keys,
    }
    const FILES: [(&str, &str, u32); 7] = [
        ("mailserverd", "core_mailserverd", 0o555),
        ("authserverd", "core_authserverd", 0o555),
        ("mailctl", "core_mailctl", 0o555),
        ("setjoin-gateway", "core_setjoin_gateway", 0o555),
        ("share/docs/UPGRADE_RECOVERY.md", "recovery_guide", 0o444),
        ("share/evidence/sbom.json", "release_sbom", 0o444),
        ("share/evidence/provenance.json", "release_provenance", 0o444),
    ];
    /// Sign `release/manifest.json` content for the artifacts as installed now.
    fn signed_manifest(release: &Path, id: &str, k: &Keys, threshold: i64) -> (Vec<u8>, String) {
        let doc: Value = serde_json::from_str(include_str!(
            "../../../crates/release-format/tests/goldens/updater-fixtures.json"
        ))
        .unwrap();
        let value = doc["samples"][0]["manifest"].clone();
        let mut m = Manifest::parse(value.to_string().as_bytes()).unwrap();
        m.release_id = id.into();
        m.platforms = Some(vec![std::env::consts::OS.into()]);
        m.architectures = Some(vec![arch().into()]);
        m.signing.threshold = threshold;
        for a in m.artifacts.as_mut().unwrap() {
            a.platform = std::env::consts::OS.into();
            a.architecture = arch().into();
            if let Some((rel, _, _)) = FILES.iter().find(|(_, t, _)| *t == a.target) {
                let bytes = fs::read(release.join(rel)).unwrap();
                a.size = bytes.len() as u64;
                a.sha256 = sha256(&bytes);
                if a.target == "recovery_guide" {
                    a.media_type = "text/markdown".into();
                }
            }
        }
        m.signatures = None;
        for (kid, pair) in &k.0 {
            m.sign_with(kid, |msg| Ok(pair.sign(msg).as_ref().to_vec())).unwrap();
        }
        let digest = sha256(&m.canonical().unwrap());
        (m.marshal().unwrap(), digest)
    }
    /// Rewrite digest/evidence so every local self-consistency check passes.
    fn reseal(release: &Path, id: &str, manifest: &[u8], digest: &str) {
        write(&release.join("manifest.json"), manifest, 0o444);
        write(&release.join("manifest.digest"), format!("{digest}\n").as_bytes(), 0o444);
        let evidence = serde_json::json!({"schema_version":1,"release_id":id,
            "manifest_sha256":digest,"content_sha256":digest_tree(release)});
        write(&release.join("installed.evidence.json"), evidence.to_string().as_bytes(), 0o444);
    }
    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let install = tmp.path().join("install");
        let id = "managed-fixture";
        let release = install.join("releases").join(id);
        for (rel, _, mode) in FILES {
            write(&release.join(rel), format!("content of {rel}").as_bytes(), mode);
        }
        write(&release.join("webmail/index.html"), b"webmail", 0o444);
        let k = keys(2);
        let (manifest, digest) = signed_manifest(&release, id, &k, 2);
        reseal(&release, id, &manifest, &digest);
        std::os::unix::fs::symlink(format!("releases/{id}"), install.join("current")).unwrap();
        for n in ["mailserverd", "authserverd", "mailctl"] {
            write(&install.join(format!("{n}.prev")), b"prior", 0o755);
        }
        let config = tmp.path().join("config.env");
        write(&config, b"SECRET=fixture\n", 0o600);
        let roots = tmp.path().join("release-roots.json");
        write(&roots, roots_doc(&k).as_bytes(), 0o644);
        let f = Fixture { quarantine: tmp.path().join("quarantine"), install, release, config, roots, keys: k, _tmp: tmp };
        lock(&f);
        f
    }
    fn lock(f: &Fixture) {
        let mut dirs: Vec<_> = walkdirs(&f.release);
        dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
        for d in dirs {
            fs::set_permissions(&d, fs::Permissions::from_mode(0o555)).unwrap();
        }
        fs::set_permissions(&f.release, fs::Permissions::from_mode(0o755)).unwrap();
        for d in [f.install.join("releases"), f.install.clone()] {
            fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    fn walkdirs(root: &Path) -> Vec<std::path::PathBuf> {
        let mut out = vec![root.to_path_buf()];
        for e in fs::read_dir(root).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                out.extend(walkdirs(&p));
            }
        }
        out
    }
    fn unlock(f: &Fixture) {
        for d in walkdirs(&f.release) {
            fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    fn adopt(f: &Fixture) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_setjoin-updater"))
            .args(["adopt-current-layout", "--install-root"])
            .arg(&f.install)
            .arg("--config-file")
            .arg(&f.config)
            .arg("--quarantine-dir")
            .arg(&f.quarantine)
            .arg("--trust-roots")
            .arg(&f.roots)
            .output()
            .unwrap()
    }
    fn refused(f: &Fixture, why: &str) {
        let out = adopt(f);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "tampered release was adopted: {err}");
        assert!(
            err.contains("refusing to adopt") && err.contains(why),
            "tampered release was adopted or refused for the wrong reason: {err}"
        );
        assert!(f.install.join("mailserverd.prev").exists(), "aborted install must not quarantine");
        assert!(!f.quarantine.exists());
    }
    fn id() -> &'static str {
        "managed-fixture"
    }

    #[test]
    fn signed_verified_managed_release_is_adopted_and_prev_files_quarantined() {
        let f = fixture();
        let out = adopt(&f);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert!(!f.install.join("mailserverd.prev").exists());
        assert!(f.quarantine.join("mailserverd.prev").exists());
    }
    #[test]
    fn changed_artifact_is_refused() {
        let f = fixture();
        unlock(&f);
        write(&f.release.join("mailserverd"), b"tampered", 0o555);
        refused(&f, "installed content evidence differs");
    }
    #[test]
    fn added_file_is_refused() {
        let f = fixture();
        unlock(&f);
        write(&f.release.join("webmail/evil.js"), b"x", 0o444);
        refused(&f, "installed content evidence differs");
    }
    #[test]
    fn wrong_manifest_digest_is_refused() {
        let f = fixture();
        unlock(&f);
        write(&f.release.join("manifest.digest"), b"bad digest\n", 0o444);
        refused(&f, "installed digest differs");
    }
    #[test]
    fn rewritten_evidence_with_wrong_content_digest_is_refused() {
        let f = fixture();
        unlock(&f);
        let mut e: Value =
            serde_json::from_slice(&fs::read(f.release.join("installed.evidence.json")).unwrap()).unwrap();
        e["content_sha256"] = "0".repeat(64).into();
        write(&f.release.join("installed.evidence.json"), e.to_string().as_bytes(), 0o444);
        refused(&f, "installed content evidence differs");
    }
    #[test]
    fn self_consistent_forgery_with_recomputed_evidence_is_refused() {
        // The attacker replaces a binary and recomputes digest and evidence locally.
        let f = fixture();
        unlock(&f);
        write(&f.release.join("mailserverd"), b"backdoored", 0o555);
        let manifest = fs::read(f.release.join("manifest.json")).unwrap();
        let digest = sha256(&Manifest::parse(&manifest).unwrap().canonical().unwrap());
        reseal(&f.release, id(), &manifest, &digest);
        refused(&f, "differs from the signed manifest");
    }
    #[test]
    fn self_signed_forgery_under_other_keys_is_refused() {
        // A fully self-consistent release signed with the attacker's own keys.
        let f = fixture();
        unlock(&f);
        write(&f.release.join("mailserverd"), b"backdoored", 0o555);
        let attacker = keys(2);
        let (manifest, digest) = signed_manifest(&f.release, id(), &attacker, 2);
        reseal(&f.release, id(), &manifest, &digest);
        refused(&f, "release signature threshold not met");
    }
    #[test]
    fn manifest_edited_after_signing_is_refused() {
        let f = fixture();
        unlock(&f);
        let mut m = Manifest::parse(&fs::read(f.release.join("manifest.json")).unwrap()).unwrap();
        m.version = "9.9.9".into();
        let digest = sha256(&m.canonical().unwrap());
        reseal(&f.release, id(), &m.marshal().unwrap(), &digest);
        refused(&f, "threshold not met");
    }
    #[test]
    fn single_signature_below_the_floor_is_refused() {
        let f = fixture();
        unlock(&f);
        let one = Keys(vec![keys(1).0.remove(0)]);
        write(&f.roots, roots_doc(&one).as_bytes(), 0o644);
        let (manifest, digest) = signed_manifest(&f.release, id(), &one, 1);
        reseal(&f.release, id(), &manifest, &digest);
        refused(&f, "threshold not met");
        let _ = &f.keys;
    }
    #[test]
    fn missing_trust_roots_refuse_adoption_with_recovery_hint() {
        let f = fixture();
        fs::remove_file(&f.roots).unwrap();
        refused(&f, "release trust roots");
    }
    #[test]
    fn stray_adoption_json_cannot_divert_to_the_self_hashed_path() {
        let f = fixture();
        unlock(&f);
        write(&f.release.join("mailserverd"), b"backdoored", 0o555);
        let manifest = fs::read(f.release.join("manifest.json")).unwrap();
        let digest = sha256(&Manifest::parse(&manifest).unwrap().canonical().unwrap());
        reseal(&f.release, id(), &manifest, &digest);
        let mut artifacts = serde_json::Map::new();
        for n in ["mailserverd", "authserverd", "mailctl"] {
            artifacts.insert(n.into(), hash_artifact(fs::File::open(f.release.join(n)).unwrap()).unwrap().1.into());
        }
        artifacts.insert("webmail".into(), "0".repeat(64).into());
        write(
            &f.release.join("adoption.json"),
            serde_json::json!({"schema_version":1,"release_id":id(),"database_schema":178,
                "config_sha256":"a".repeat(64),"artifacts":artifacts}).to_string().as_bytes(),
            0o444,
        );
        refused(&f, "carries both adoption.json and manifest.json");
    }
    #[test]
    fn file_or_directory_owned_by_another_user_is_refused() {
        assert_eq!(unsafe { libc::geteuid() }, 0, "tests run as root");
        for rel in ["mailserverd", "webmail"] {
            let f = fixture();
            std::os::unix::fs::lchown(f.release.join(rel), Some(65534), Some(65534)).unwrap();
            refused(&f, "owner must be root");
        }
    }

    /// Runs the installer's real roots helper (mailserver/deploy/scripts/lib-release-roots.sh).
    fn helper(src: &Path, dest: &Path, install: &Path) -> std::process::Output {
        let lib = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../mailserver/deploy/scripts/lib-release-roots.sh"
        );
        Command::new("bash")
            .arg("-c")
            .arg(r#"die() { echo "die: $*" >&2; exit 1; }; info() { echo "$*"; }
                    source "$1"; install_release_roots "$2" "$3" "$4""#)
            .arg("_")
            .arg(lib)
            .arg(src)
            .arg(dest)
            .arg(install)
            .output()
            .unwrap()
    }
    #[test]
    fn installer_delivers_roots_so_signed_upgrade_is_adopted_and_tampered_is_refused() {
        // Package copy -> /etc/setjoin/release-roots.json (root-owned 0644) -> adoption.
        for tamper in [false, true] {
            let f = fixture();
            let config_dir = f.roots.parent().unwrap().join("etc-setjoin");
            let dest = config_dir.join("release-roots.json");
            let out = helper(&f.roots, &dest, &f.install);
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
            let meta = fs::metadata(&dest).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o644);
            assert_eq!(std::os::unix::fs::MetadataExt::uid(&meta), 0);
            let mut f = f;
            f.roots = dest;
            if tamper {
                unlock(&f);
                write(&f.release.join("mailserverd"), b"backdoored", 0o555);
                let manifest = fs::read(f.release.join("manifest.json")).unwrap();
                let digest = sha256(&Manifest::parse(&manifest).unwrap().canonical().unwrap());
                reseal(&f.release, id(), &manifest, &digest);
                refused(&f, "differs from the signed manifest");
            } else {
                let out = adopt(&f);
                assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
            }
        }
    }
    #[test]
    fn installer_fails_clearly_without_roots_on_a_managed_install_only() {
        let f = fixture();
        let dest = f.roots.parent().unwrap().join("etc-setjoin/release-roots.json");
        let missing = f.roots.parent().unwrap().join("no-package-copy.json");
        let out = helper(&missing, &dest, &f.install);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success());
        assert!(err.contains("release-roots.json") && err.contains("SETJOIN_RELEASE_TRUST_ROOTS"), "{err}");
        // A flat first install (no `current`) needs no roots.
        let empty = tempfile::tempdir().unwrap();
        let out = helper(&missing, &dest, empty.path());
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        // Operator-provisioned roots are accepted in place.
        let out = helper(&missing, &f.roots, &f.install);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
}
