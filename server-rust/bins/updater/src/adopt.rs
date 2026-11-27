//! Initial immutable cohort capture; orphaned flat *.prev files are evidence only.
use crate::{files::*, stage};
#[cfg(not(feature = "oracle-mutants"))]
use anyhow::Context;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use setjoin_release_format::{hash_artifact, sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    schema_version: u8,
    release_id: String,
    database_schema: i32,
    config_sha256: String,
    artifacts: BTreeMap<String, String>,
}
fn inspect(root: &Path) -> Result<BTreeMap<String, String>> {
    let exists = |name: &str| {
        !fs::symlink_metadata(root.join(name))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    };
    let mut artifacts = BTreeMap::new();
    let has_setjoind = exists("setjoind");
    let has_server = exists("setjoin-server");
    let has_auth = exists("setjoin-auth");
    if has_setjoind || has_server {
        for legacy in ["authserverd", "mailserverd", "setjoin-gateway"] {
            ensure!(
                !exists(legacy),
                "mixed legacy ({legacy}) and post-#142 binaries in install root"
            );
        }
        if has_setjoind {
            ensure!(
                has_server == has_auth,
                "half-shim install root: setjoind requires both setjoin-server and setjoin-auth or neither"
            );
            let names: &[&str] = if has_server {
                &["mailctl", "setjoin-auth", "setjoin-server", "setjoind"]
            } else {
                &["mailctl", "setjoind"]
            };
            for name in names {
                artifacts.insert(
                    (*name).into(),
                    hash_artifact(open(&root.join(name), false)?)?.1,
                );
            }
        } else {
            for name in ["mailctl", "setjoin-auth", "setjoin-server"] {
                artifacts.insert(
                    name.into(),
                    hash_artifact(open(&root.join(name), false)?)?.1,
                );
            }
        }
    } else {
        for name in [
            "authserverd",
            "mailctl",
            "mailserverd",
            "setjoin-auth",
            "setjoin-gateway",
        ] {
            if matches!(name, "setjoin-auth" | "setjoin-gateway") && !exists(name) {
                continue;
            }
            artifacts.insert(
                name.into(),
                hash_artifact(open(&root.join(name), false)?)?.1,
            );
        }
    }
    existing_dir(&root.join("webmail"))?;
    artifacts.insert("webmail".into(), tree_digest(&root.join("webmail"), "")?);
    Ok(artifacts)
}
fn copy(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    use std::{io::Read, os::unix::fs::PermissionsExt};
    let mut raw = Vec::new();
    open(source, false)?.read_to_end(&mut raw)?;
    write_new(destination, &raw, mode)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(mode))?;
    Ok(())
}
fn quarantine(root: &Path, dir: &Path) -> Result<()> {
    for name in [
        "authserverd.prev",
        "mailctl.prev",
        "mailserverd.prev",
        "setjoin-auth.prev",
        "setjoin-gateway.prev",
        "setjoin-server.prev",
        "setjoind.prev",
        "webmail.prev",
    ] {
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            result => {
                result?;
            }
        }
        secure_dir(dir, 0o700)?;
        ensure!(
            fs::symlink_metadata(dir.join(name))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "legacy quarantine destination already exists for {name}"
        );
        fs::rename(path, dir.join(name))?;
        sync_dir(dir)?;
        sync_dir(root)?;
    }
    Ok(())
}
pub fn execute(mut flags: BTreeMap<String, String>) -> Result<()> {
    let root = PathBuf::from(
        flags
            .remove("--install-root")
            .unwrap_or_else(|| "/opt/setjoin".into()),
    );
    let config = PathBuf::from(
        flags
            .remove("--config-file")
            .unwrap_or_else(|| "/etc/setjoin/config.env".into()),
    );
    let roots = PathBuf::from(
        flags
            .remove("--trust-roots")
            .unwrap_or_else(|| "/etc/setjoin/release-roots.json".into()),
    );
    let quarantine_dir = PathBuf::from(
        flags
            .remove("--quarantine-dir")
            .unwrap_or_else(|| "/var/lib/setjoin-updater/legacy-prev".into()),
    );
    ensure!(
        flags.is_empty()
            && root.is_absolute()
            && config.is_absolute()
            && quarantine_dir.is_absolute()
            && roots.is_absolute(),
        "adoption paths must be absolute"
    );
    secure_dir(&root, 0o755)?;
    match fs::symlink_metadata(root.join("current")) {
        Ok(_) => {
            let id = stage::active(&root, "current")?;
            let dir = root.join("releases").join(&id);
            let has_manifest = entry_exists(&dir.join("manifest.json"))?;
            #[cfg(not(feature = "oracle-mutants"))]
            ensure!(
                !(has_manifest && entry_exists(&dir.join("adoption.json"))?),
                "current release carries both adoption.json and manifest.json; refusing to adopt"
            );
            let adopted_path = if has_manifest && cfg!(not(feature = "oracle-mutants")) {
                dir.join("no-adoption-for-managed")
            } else {
                dir.join("adoption.json")
            };
            match fs::symlink_metadata(&adopted_path) {
                Ok(_) => {
                    let _: Evidence =
                        serde_json::from_slice(&read(&dir.join("adoption.json"), 1 << 20, false)?)?;
                    stage::validate_adopted(&root, &id)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // #506 (owner-approved security fix 2026-11-05): frozen Go parses
                    // only the manifest here. Adoption runs the same verification as
                    // activation: manifest.digest, canonical identity and the
                    // installed.evidence.json content digest. A tampered managed
                    // `current` aborts before any `*.prev` is quarantined.
                    #[cfg(not(feature = "oracle-mutants"))]
                    stage::validate_managed(&root, &id).context(
                        "managed current release failed content verification; refusing to adopt",
                    )?;
                    #[cfg(not(feature = "oracle-mutants"))]
                    stage::verify_authentic(&dir, &id, &roots)
                        .context("managed current release is not authenticated by the signed manifest; refusing to adopt")?;
                    let m = setjoin_release_format::Manifest::parse(&read(
                        &dir.join("manifest.json"),
                        1 << 20,
                        false,
                    )?)?;
                    ensure!(
                        m.release_id == id,
                        "managed release manifest identity is invalid"
                    );
                    inspect(&dir)?;
                    hash_artifact(open(&config, false)?)?;
                }
                Err(e) => return Err(e.into()),
            }
            quarantine(&root, &quarantine_dir)?;
            println!("adopted release {id}");
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let artifacts = inspect(&root)?;
    let config_sha256 = hash_artifact(open(&config, false)?)?.1;
    let mut content = Vec::new();
    for (name, digest) in &artifacts {
        content.extend_from_slice(format!("{name}\0{digest}\0").as_bytes());
    }
    content.extend_from_slice(format!("config\0{config_sha256}\0").as_bytes());
    let id = format!("legacy-adopted-{}", sha256(&content));
    let releases = root.join("releases");
    secure_dir(&releases, 0o755)?;
    let target = releases.join(&id);
    if fs::symlink_metadata(&target).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        let staging = releases.join(format!(".staging-{id}"));
        remove_tree(&staging)?;
        secure_dir(&staging, 0o700)?;
        let result = (|| {
            for name in artifacts.keys().filter(|s| *s != "webmail") {
                copy(&root.join(name), &staging.join(name), 0o500)?;
            }
            secure_dir(&staging.join("webmail"), 0o700)?;
            let source = root.join("webmail");
            for path in tree_entries(&source)? {
                let dest = staging.join("webmail").join(path.strip_prefix(&source)?);
                if path.is_dir() {
                    secure_dir(&dest, 0o700)?;
                } else {
                    copy(&path, &dest, 0o600)?;
                }
            }
            let evidence = Evidence {
                schema_version: 1,
                release_id: id.clone(),
                database_schema: setjoin_schema::MIGRATIONS.last().unwrap().0,
                config_sha256,
                artifacts,
            };
            let raw = serde_json::to_string_pretty(&evidence)? + "\n";
            write_new(&staging.join("adoption.json"), raw.as_bytes(), 0o400)?;
            immutable(&staging)?;
            fs::rename(&staging, &target)?;
            sync_dir(&releases)?;
            Ok::<_, anyhow::Error>(())
        })();
        if result.is_err() {
            let _ = remove_tree(&staging);
        }
        result?;
    }
    stage::validate_adopted(&root, &id)?;
    let temp = root.join(".current.new");
    if fs::symlink_metadata(&temp).is_ok() {
        fs::remove_file(&temp)?;
    }
    std::os::unix::fs::symlink(format!("releases/{id}"), &temp)?;
    fs::rename(temp, root.join("current"))?;
    sync_dir(&root)?;
    quarantine(&root, &quarantine_dir)?;
    println!("adopted release {id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_file(path: &Path, data: &[u8], mode: u32) {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).unwrap();
            fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::write(path, data).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn post_142_inspect_quarantine_and_mixed_rejection() {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let root = tmp.path().join("install");
        write_file(&root.join("setjoin-server"), b"server", 0o500);
        write_file(&root.join("setjoin-auth"), b"auth", 0o500);
        write_file(&root.join("mailctl"), b"mailctl", 0o500);
        write_file(&root.join("webmail/index.html"), b"webmail", 0o400);

        let inspected = inspect(&root).expect("post-#142 inspect passes");
        let keys: Vec<_> = inspected.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec!["mailctl", "setjoin-auth", "setjoin-server", "webmail"]
        );

        // Quarantine moves setjoin-server.prev and setjoin-auth.prev.
        write_file(&root.join("setjoin-server.prev"), b"prev-server", 0o500);
        write_file(&root.join("setjoin-auth.prev"), b"prev-auth", 0o500);
        let qdir = tmp.path().join("quarantine");
        quarantine(&root, &qdir).expect("quarantine passes");
        assert!(!root.join("setjoin-server.prev").exists());
        assert!(!root.join("setjoin-auth.prev").exists());
        assert!(qdir.join("setjoin-server.prev").exists());
        assert!(qdir.join("setjoin-auth.prev").exists());

        // Mixing legacy setjoin-gateway alongside setjoin-server fails closed.
        write_file(&root.join("setjoin-gateway"), b"legacy", 0o500);
        let err = inspect(&root).unwrap_err().to_string();
        assert!(err.contains("mixed legacy"), "{err}");
    }

    #[test]
    fn setjoind_expand_contract_half_shim_and_quarantine() {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();

        // 1. Release N expand (setjoind + both shims + mailctl + webmail)
        let expand = tmp.path().join("expand");
        write_file(&expand.join("setjoind"), b"setjoind", 0o500);
        write_file(&expand.join("setjoin-server"), b"server-shim", 0o500);
        write_file(&expand.join("setjoin-auth"), b"auth-shim", 0o500);
        write_file(&expand.join("mailctl"), b"mailctl", 0o500);
        write_file(&expand.join("webmail/index.html"), b"webmail", 0o400);
        let keys: Vec<_> = inspect(&expand)
            .expect("Release N expand inspect passes")
            .into_keys()
            .collect();
        assert_eq!(
            keys,
            vec![
                "mailctl",
                "setjoin-auth",
                "setjoin-server",
                "setjoind",
                "webmail"
            ]
        );

        // 2. Release N+1 unified contract (setjoind + mailctl + webmail)
        let unified = tmp.path().join("unified");
        write_file(&unified.join("setjoind"), b"setjoind", 0o500);
        write_file(&unified.join("mailctl"), b"mailctl", 0o500);
        write_file(&unified.join("webmail/index.html"), b"webmail", 0o400);
        let keys: Vec<_> = inspect(&unified)
            .expect("Release N+1 unified inspect passes")
            .into_keys()
            .collect();
        assert_eq!(keys, vec!["mailctl", "setjoind", "webmail"]);

        // 3. Quarantine moves setjoind.prev
        write_file(&unified.join("setjoind.prev"), b"prev-setjoind", 0o500);
        let qdir = tmp.path().join("quarantine");
        quarantine(&unified, &qdir).expect("quarantine setjoind.prev passes");
        assert!(!unified.join("setjoind.prev").exists());
        assert!(qdir.join("setjoind.prev").exists());

        // 4. Half-shim layout MUST fail closed
        let half = tmp.path().join("half");
        write_file(&half.join("setjoind"), b"setjoind", 0o500);
        write_file(&half.join("setjoin-server"), b"server-shim", 0o500);
        write_file(&half.join("mailctl"), b"mailctl", 0o500);
        write_file(&half.join("webmail/index.html"), b"webmail", 0o400);
        let err = inspect(&half).unwrap_err().to_string();
        assert!(err.contains("half-shim"), "{err}");
    }
}
