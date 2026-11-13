use crate::files::*;
use anyhow::{bail, ensure, Context, Result};
use chrono::{DateTime, Utc};
use serde_json::json;
use setjoin_release_format::{sha256, verify_artifact, Artifact, Manifest};
use std::{
    collections::BTreeSet,
    fs,
    io::Seek,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

pub fn verify_tree(store: &Path, id: &str, digest_value: &str) -> Result<Manifest> {
    ensure!(
        identifier(id) && digest(digest_value),
        "invalid release identity"
    );
    existing_dir(store)?;
    ensure!(
        fs::symlink_metadata(store)?.uid() == 0,
        "release store owner must be root"
    );
    let dir = store.join(id);
    existing_dir(&dir)?;
    ensure!(
        fs::symlink_metadata(&dir)?.uid() == 0,
        "release tree owner must be root"
    );
    let path = dir.join("manifest.json");
    let file = open(&path, false)?;
    ensure!(file.metadata()?.uid() == 0, "manifest owner must be root");
    let m = Manifest::parse(&read(&path, 1 << 20, false)?)?;
    ensure!(
        m.release_id == id && sha256(&m.canonical()?) == digest_value,
        "canonical manifest identity differs"
    );
    let now = Utc::now();
    ensure!(
        now >= DateTime::parse_from_rfc3339(&m.published_at)?
            && now < DateTime::parse_from_rfc3339(&m.expires_at)?,
        "release metadata is expired or not yet valid"
    );
    Ok(m)
}
fn target(a: &Artifact) -> Result<PathBuf> {
    Ok(match a.target.as_str() {
        "core_mailserverd" => "mailserverd".into(),
        "core_authserverd" => "authserverd".into(),
        "core_mailctl" => "mailctl".into(),
        "core_setjoin_gateway" => "setjoin-gateway".into(),
        "core_migrations" => {
            ensure!(
                a.media_type == "application/sql",
                "invalid migration media type"
            );
            format!("share/migrations/{}.sql", a.id).into()
        }
        "recovery_guide" => {
            ensure!(
                a.media_type == "text/markdown",
                "invalid recovery guide media type"
            );
            "share/docs/UPGRADE_RECOVERY.md".into()
        }
        "release_sbom" => "share/evidence/sbom.json".into(),
        "release_provenance" => "share/evidence/provenance.json".into(),
        "compatible_sidecar" => format!("sidecars/{}", a.id).into(),
        other => bail!("unsupported install target {other}"),
    })
}
pub fn stage(store: &Path, root: &Path, id: &str, digest_value: &str) -> Result<PathBuf> {
    let m = verify_tree(store, id, digest_value)?;
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "loongarch64" => "loong64",
        v => v,
    };
    let platform = std::env::consts::OS;
    let selected: Vec<_> = m
        .artifacts
        .iter()
        .flatten()
        .filter(|a| a.platform == platform && a.architecture == arch)
        .collect();
    for required in [
        "core_mailserverd",
        "core_authserverd",
        "core_mailctl",
        "core_webmail",
        "recovery_guide",
        "release_sbom",
        "release_provenance",
        "core_setjoin_gateway",
    ] {
        ensure!(
            selected.iter().filter(|a| a.target == required).count() == 1,
            "target {required} must have exactly one artifact"
        );
    }
    let dir = store.join(id);
    let mut want: BTreeSet<_> = m
        .artifacts
        .iter()
        .flatten()
        .map(|a| a.id.as_str())
        .collect();
    want.insert("manifest.json");
    let entries: Vec<_> = fs::read_dir(&dir)?.collect::<std::io::Result<_>>()?;
    ensure!(entries.len() == want.len(), "release inventory differs");
    for entry in entries {
        ensure!(
            want.contains(entry.file_name().to_str().unwrap_or("")),
            "undeclared release file"
        );
        let f = open(&entry.path(), false)?;
        ensure!(f.metadata()?.uid() == 0, "inventory owner differs");
    }
    secure_dir(root, 0o755)?;
    let releases = root.join("releases");
    secure_dir(&releases, 0o755)?;
    let final_dir = releases.join(id);
    if final_dir.try_exists()? {
        verify_installed(&final_dir, id, digest_value)?;
        return Ok(final_dir);
    }
    let required = selected.iter().try_fold(0u64, |sum, a| {
        sum.checked_add(a.size)
            .filter(|s| *s <= 16 << 30)
            .ok_or_else(|| anyhow::anyhow!("declared release exceeds limit"))
    })?;
    let required = required
        .checked_add(m.recovery.minimum_free_bytes)
        .ok_or_else(|| anyhow::anyhow!("free-space overflow"))?;
    let path = std::ffi::CString::new(root.as_os_str().as_encoded_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: valid NUL-terminated path and writable output; read only on success.
    let free = unsafe {
        ensure!(
            libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) == 0,
            "statvfs failed"
        );
        let s = stat.assume_init();
        s.f_bavail.saturating_mul(s.f_frsize)
    };
    ensure!(free >= required, "insufficient release staging space");
    let staging = releases.join(format!(".staging-{id}"));
    remove_tree(&staging)?;
    secure_dir(&staging, 0o700)?;
    let result = (|| {
        for a in selected {
            let mut file = open(&dir.join(&a.id), false)?;
            verify_artifact(&mut file, a)?;
            file.rewind()?;
            if a.target == "core_webmail" {
                extract_webmail(file, &staging.join("webmail"), a)?;
            } else {
                let dest = staging.join(target(a)?);
                if let Some(p) = dest.parent() {
                    fs::create_dir_all(p)?;
                }
                let executable = matches!(
                    a.target.as_str(),
                    "core_mailserverd"
                        | "core_authserverd"
                        | "core_mailctl"
                        | "core_setjoin_gateway"
                        | "compatible_sidecar"
                );
                let mut out = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&dest)?;
                std::io::copy(&mut file, &mut out)?;
                out.sync_all()?;
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    dest,
                    fs::Permissions::from_mode(if executable { 0o500 } else { 0o400 }),
                )?;
            }
        }
        write_new(
            &staging.join("manifest.json"),
            &read(&dir.join("manifest.json"), 1 << 20, false)?,
            0o444,
        )?;
        write_new(
            &staging.join("manifest.digest"),
            format!("{digest_value}\n").as_bytes(),
            0o400,
        )?;
        let evidence = json!({"schema_version":1,"release_id":id,"manifest_sha256":digest_value,"content_sha256":tree_digest(&staging,"installed.evidence.json")?});
        write_new(
            &staging.join("installed.evidence.json"),
            &serde_json::to_vec_pretty(&evidence)?,
            0o400,
        )?;
        immutable(&staging)?;
        fs::rename(&staging, &final_dir)?;
        sync_dir(&releases)?;
        Ok(final_dir)
    })();
    if result.is_err() {
        let _ = remove_tree(&staging);
    }
    result
}
fn extract_webmail(file: fs::File, dest: &Path, a: &Artifact) -> Result<()> {
    ensure!(
        a.media_type == "application/vnd.setjoin.webmail.tar",
        "unsupported webmail media type"
    );
    fs::create_dir_all(dest)?;
    let mut archive = tar::Archive::new(file);
    let mut expanded = 0u64;
    for (i, entry) in archive.entries()?.enumerate() {
        ensure!(i < 100_000, "too many webmail entries");
        let mut entry = entry?;
        expanded = expanded
            .checked_add(entry.size())
            .ok_or_else(|| anyhow::anyhow!("archive size overflow"))?;
        ensure!(expanded <= 2 << 30, "archive expansion limit");
        let mut clean = PathBuf::new();
        for component in entry.path()?.components() {
            match component {
                Component::Normal(v) => clean.push(v),
                Component::CurDir => (),
                Component::ParentDir => ensure!(clean.pop(), "archive traversal"),
                _ => bail!("absolute archive path"),
            }
        }
        ensure!(!clean.as_os_str().is_empty(), "empty archive path");
        let path = dest.join(clean);
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            fs::create_dir_all(path)?;
        } else if kind.is_file() {
            ensure!(
                entry.header().mode()? & 0o7000 == 0,
                "privileged archive mode"
            );
            if let Some(p) = path.parent() {
                fs::create_dir_all(p)?;
            }
            let mut out = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?;
            std::io::copy(&mut entry, &mut out)?;
            out.sync_all()?;
        } else {
            bail!("archive links and special nodes are forbidden");
        }
    }
    ensure!(dest.join("index.html").exists(), "webmail lacks index.html");
    Ok(())
}
pub fn verify_installed(dir: &Path, id: &str, digest_value: &str) -> Result<()> {
    existing_dir(dir)?;
    ensure!(
        String::from_utf8(read(&dir.join("manifest.digest"), 1024, false)?)?.trim() == digest_value,
        "installed digest differs"
    );
    for name in [
        "mailserverd",
        "authserverd",
        "mailctl",
        "webmail/index.html",
        "share/docs/UPGRADE_RECOVERY.md",
    ] {
        open(&dir.join(name), false)?;
    }
    let m = Manifest::parse(&read(&dir.join("manifest.json"), 1 << 20, false)?)?;
    ensure!(
        m.release_id == id && sha256(&m.canonical()?) == digest_value,
        "installed manifest identity differs"
    );
    let e: serde_json::Value =
        serde_json::from_slice(&read(&dir.join("installed.evidence.json"), 1 << 20, false)?)?;
    ensure!(
        e["schema_version"] == 1
            && e["release_id"] == id
            && e["manifest_sha256"] == digest_value
            && e["content_sha256"] == tree_digest(dir, "installed.evidence.json")?,
        "installed content evidence differs"
    );
    Ok(())
}
pub fn active(root: &Path, name: &str) -> Result<String> {
    let target = fs::read_link(root.join(name))?;
    let id = target.file_name().and_then(|v| v.to_str()).unwrap_or("");
    ensure!(
        target.parent() == Some(Path::new("releases")) && identifier(id),
        "unsafe release symlink"
    );
    ensure!(
        fs::symlink_metadata(root.join(&target))?.is_dir(),
        "release target unavailable"
    );
    Ok(id.into())
}
fn switch(root: &Path, name: &str, id: &str) -> Result<()> {
    ensure!(identifier(id), "invalid release id");
    let temp = root.join(format!(".{name}.new"));
    if temp.symlink_metadata().is_ok() {
        fs::remove_file(&temp)?;
    }
    std::os::unix::fs::symlink(format!("releases/{id}"), &temp)?;
    fs::rename(temp, root.join(name))?;
    sync_dir(root)
}
pub fn validate_managed(root: &Path, id: &str) -> Result<()> {
    validate_cohort(root, id, true)
}
pub fn validate_adopted(root: &Path, id: &str) -> Result<()> {
    validate_cohort(root, id, false)
}
fn validate_cohort(root: &Path, id: &str, require_index: bool) -> Result<()> {
    let dir = root.join("releases").join(id);
    existing_dir(&dir)?;
    let adopted = entry_exists(&dir.join("adoption.json"))?;
    let managed = entry_exists(&dir.join("manifest.json"))?;
    // #507: a stray adoption.json must never divert a managed release onto the
    // weaker self-hashed path.
    #[cfg(not(feature = "oracle-mutants"))]
    ensure!(
        !(adopted && managed),
        "release carries both adoption.json and manifest.json"
    );
    if adopted && !(managed && cfg!(not(feature = "oracle-mutants"))) {
        let e: serde_json::Value =
            serde_json::from_slice(&read(&dir.join("adoption.json"), 1 << 20, false)?)?;
        ensure!(
            e["schema_version"] == 1
                && e["release_id"] == id
                && e["database_schema"].as_i64().unwrap_or(0) > 0
                && e["config_sha256"].as_str().is_some_and(digest),
            "invalid adoption evidence"
        );
        let map = e["artifacts"]
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("missing adoption artifacts"))?;
        ensure!((4..=5).contains(&map.len()), "invalid adoption inventory");
        ensure!(
            fs::read_dir(&dir)?.count() == map.len() + 1,
            "adoption inventory differs"
        );
        for name in ["mailserverd", "authserverd", "mailctl", "webmail"] {
            ensure!(map.contains_key(name), "adoption missing {name}");
        }
        for (name, hash) in map {
            ensure!(
                matches!(
                    name.as_str(),
                    "mailserverd" | "authserverd" | "mailctl" | "setjoin-gateway" | "webmail"
                ),
                "unknown adoption artifact"
            );
            let actual = if name == "webmail" {
                tree_digest(&dir.join(name), "")?
            } else {
                setjoin_release_format::hash_artifact(open(&dir.join(name), false)?)?.1
            };
            ensure!(hash == &actual, "adoption content differs");
        }
        if require_index {
            open(&dir.join("webmail/index.html"), false)?;
        }
        return Ok(());
    }
    let m = Manifest::parse(&read(&dir.join("manifest.json"), 1 << 20, false)?)?;
    verify_installed(&dir, id, &sha256(&m.canonical()?))
}
/// Adoption authenticity (#507): the stored manifest must carry a valid signature
/// quorum from the operator's release trust roots (freshness is not re-judged: the
/// clock is the manifest's own published_at), and every installed core file must
/// match its signed artifact size and SHA-256. Local `manifest.digest` and
/// `installed.evidence.json` are only self-consistency and prove nothing alone.
pub fn verify_authentic(dir: &Path, id: &str, roots: &Path) -> Result<()> {
    use setjoin_release_format::{
        Purpose, TrustStore, VerifyOptions, MIN_VERIFICATION_THRESHOLD,
    };
    let raw = read(&dir.join("manifest.json"), 1 << 20, false)?;
    let roots_raw = read(roots, 1 << 20, false).with_context(|| {
        format!(
            "release trust roots {} are required to adopt a managed release; install the vendor release-roots.json (root-owned) or pass --trust-roots",
            roots.display()
        )
    })?;
    let store = TrustStore::parse_roots(&roots_raw, Purpose::Release, false)?;
    let unsigned = Manifest::parse(&raw)?;
    let options = VerifyOptions {
        now: DateTime::parse_from_rfc3339(&unsigned.published_at)?.into(),
        minimum_threshold: MIN_VERIFICATION_THRESHOLD,
        ..Default::default()
    };
    let verified = store.verify_manifest(&raw, &options)?;
    ensure!(verified.manifest.release_id == id, "signed release identity differs");
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "loongarch64" => "loong64",
        v => v,
    };
    let mut checked = 0;
    for a in verified
        .manifest
        .artifacts
        .iter()
        .flatten()
        .filter(|a| a.platform == std::env::consts::OS && a.architecture == arch)
        .filter(|a| a.target != "core_webmail")
    {
        let mut file = open(&dir.join(target(a)?), false)?;
        verify_artifact(&mut file, a).with_context(|| format!("installed {} differs from the signed manifest", a.id))?;
        checked += 1;
    }
    ensure!(checked > 0, "signed manifest lists no installable artifact for this host");
    Ok(())
}
pub fn activate(root: &Path, id: &str) -> Result<()> {
    validate_managed(root, id)?;
    let current = active(root, "current")?;
    if current == id {
        return Ok(());
    }
    switch(root, "previous", &current)?;
    switch(root, "current", id)
}
pub fn previous(root: &Path, failed: &str) -> Result<()> {
    validate_managed(root, failed)?;
    let current = active(root, "current")?;
    let old = active(root, "previous")?;
    if current != failed {
        if old == failed {
            return Ok(());
        }
        ensure!(old == current, "rollback layout differs");
        return switch(root, "previous", failed);
    }
    ensure!(old != failed, "previous equals failed release");
    validate_managed(root, &old)?;
    switch(root, "current", &old)?;
    switch(root, "previous", failed)
}
