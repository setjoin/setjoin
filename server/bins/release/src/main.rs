//! CI publisher; signing keys remain behind a protected provider helper.
use anyhow::{bail, ensure, Context, Result};
use setjoin_release_format::{decode_base64, Manifest, MAX_DOCUMENT_BYTES};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
fn run(args: Vec<String>) -> Result<()> {
    ensure!(
        args.len() >= 2 && args[0] == "manifest",
        "usage: setjoin-release manifest build|sign|verify|inspect [flags]"
    );
    match args[1].as_str() {
        "build" => {
            let flags = flags(&args[2..], &["draft", "artifacts-dir", "output"], &[])?;
            let mut manifest = Manifest::parse_draft(&read_bounded(required(&flags, "draft")?)?)?;
            let root = Path::new(required(&flags, "artifacts-dir")?);
            let output = required(&flags, "output")?;
            for artifact in manifest.artifacts.iter_mut().flatten() {
                let file = regular_artifact(root, &artifact.id)?;
                (artifact.size, artifact.sha256) = setjoin_release_format::hash_artifact(file)?;
            }
            for migration in manifest.migrations.iter_mut().flatten() {
                let artifact = manifest
                    .artifacts
                    .iter()
                    .flatten()
                    .find(|a| a.id == migration.id && a.class == "migration")
                    .context("migration has no matching inventory artifact")?;
                migration.sha256 = artifact.sha256.clone();
            }
            atomic_write(Path::new(output), &manifest.marshal()?)
        }
        "sign" => {
            let flags = flags(
                &args[2..],
                &["manifest", "signer-helper", "key-id", "output"],
                &[],
            )?;
            let mut manifest = Manifest::parse(&read_bounded(required(&flags, "manifest")?)?)?;
            let helper = required(&flags, "signer-helper")?;
            let id = required(&flags, "key-id")?;
            let output = required(&flags, "output")?;
            manifest.sign_with(id, |payload| sign_helper(helper, id, payload))?;
            atomic_write(Path::new(output), &manifest.marshal()?)
        }
        "inspect" => {
            let flags = flags(&args[2..], &["manifest"], &[])?;
            let m = Manifest::parse(&read_bounded(required(&flags, "manifest")?)?)?;
            #[derive(serde::Serialize)]
            #[serde(rename_all = "camelCase")]
            struct Inspection<'a> {
                release_id: &'a str,
                version: &'a str,
                channel: &'a str,
                metadata_version: u64,
                schema_from: i64,
                schema_to: i64,
                artifact_count: usize,
                signature_key_ids: Vec<&'a str>,
            }
            let view = Inspection {
                release_id: &m.release_id,
                version: &m.version,
                channel: &m.channel,
                metadata_version: m.metadata_version,
                schema_from: m.schema_from,
                schema_to: m.schema_to,
                artifact_count: m.artifacts.as_deref().unwrap_or_default().len(),
                signature_key_ids: m
                    .signatures
                    .iter()
                    .flatten()
                    .map(|s| s.key_id.as_str())
                    .collect(),
            };
            let pretty = serde_json::to_string_pretty(&view)?
                .replace('&', "\\u0026")
                .replace('<', "\\u003c")
                .replace('>', "\\u003e");
            println!("{pretty}");
            Ok(())
        }
        "verify" => {
            use setjoin_release_format::{
                Purpose, TrustStore, VerifyOptions, MIN_VERIFICATION_THRESHOLD,
            };
            let flags = flags(
                &args[2..],
                &[
                    "manifest",
                    "artifacts-dir",
                    "trust-roots",
                    "channel",
                    "current-version",
                    "platform",
                    "arch",
                ],
                &["offline"],
            )?;
            ensure!(
                matches!(
                    flags.get("offline").map(String::as_str),
                    Some("true" | "1" | "t" | "T" | "TRUE" | "True")
                ),
                "offline verification is required"
            );
            let bytes = read_bounded(required(&flags, "manifest")?)?;
            let roots = TrustStore::parse_roots(
                &read_bounded(required(&flags, "trust-roots")?)?,
                Purpose::Release,
                false,
            )?;
            let root = Path::new(required(&flags, "artifacts-dir")?);
            let options = VerifyOptions {
                channel: required(&flags, "channel")?.into(),
                current_version: required(&flags, "current-version")?.into(),
                platform: flags
                    .get("platform")
                    .cloned()
                    .unwrap_or_else(|| "linux".into()),
                architecture: flags.get("arch").cloned().unwrap_or_else(|| "amd64".into()),
                minimum_threshold: MIN_VERIFICATION_THRESHOLD,
                ..Default::default()
            };
            let verified = roots.verify_manifest(&bytes, &options)?;
            for a in verified.manifest.artifacts.iter().flatten() {
                setjoin_release_format::verify_artifact(regular_artifact(root, &a.id)?, a)?;
            }
            println!(
                "verified release {} digest {}",
                verified.manifest.release_id, verified.digest
            );
            Ok(())
        }
        other => bail!("unknown manifest action {other:?}"),
    }
}
fn flags(args: &[String], allowed: &[&str], booleans: &[&str]) -> Result<BTreeMap<String, String>> {
    let mut flags = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        ensure!(
            arg.starts_with('-') && arg != "-",
            "unexpected argument {arg:?}"
        );
        if arg == "--" {
            ensure!(i + 1 == args.len(), "unexpected positional arguments");
            break;
        }
        let raw = arg
            .strip_prefix("--")
            .or_else(|| arg.strip_prefix('-'))
            .unwrap();
        let (name, value) = raw
            .split_once('=')
            .map_or((raw, None), |(k, v)| (k, Some(v.to_string())));
        ensure!(
            allowed.contains(&name) || booleans.contains(&name),
            "flag provided but not defined: -{name}"
        );
        let value = if let Some(v) = value {
            v
        } else if booleans.contains(&name) {
            "true".into()
        } else {
            i += 1;
            args.get(i).context("flag needs an argument")?.clone()
        };
        flags.insert(name.into(), value);
        i += 1;
    }
    Ok(flags)
}
fn required<'a>(flags: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    flags
        .get(name)
        .map(String::as_str)
        .filter(|v| !v.is_empty())
        .with_context(|| format!("missing --{name}"))
}
fn read_bounded(path: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_DOCUMENT_BYTES,
        "{path} exceeds {MAX_DOCUMENT_BYTES} bytes"
    );
    Ok(bytes)
}
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temp = tempfile::Builder::new()
        .prefix(".setjoin-release-")
        .suffix(".tmp")
        .tempfile_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))?;
    }
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn sign_helper(path: &str, id: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let mut child = Command::new(path)
        .args(["sign", "--key-id", id])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("signer helper failed")?;
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let payload = payload.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&payload));
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(1025).read_to_end(&mut bytes).map(|_| bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(anyhow::anyhow!("signer helper failed"));
            }
        }
    };
    let written = writer.join();
    let output = reader.join();
    ensure!(status?.success(), "signer helper failed");
    written.map_err(|_| anyhow::anyhow!("signer helper failed"))??;
    let bytes = output.map_err(|_| anyhow::anyhow!("signer helper failed"))??;
    ensure!(bytes.len() <= 1024, "signer helper failed");
    let signature = decode_base64(std::str::from_utf8(&bytes)?.trim())
        .context("signer helper returned invalid signature")?;
    Ok(signature)
}

fn regular_artifact(root: &Path, id: &str) -> Result<File> {
    let path = root.join(id);
    // Check the descriptor we hash, so a rename between stat and open cannot
    // substitute a symlink. NONBLOCK also lets us reject a FIFO without waiting.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        file.metadata()?.file_type().is_file(),
        "artifact {id:?} is missing or unsafe"
    );
    Ok(file)
}
