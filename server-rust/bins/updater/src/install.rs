//! Inactive-only Go → Rust journal and executable handover.
use crate::{control::Connection, files::*, host, journal, legacy};
use anyhow::{ensure, Context, Result};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

fn local_inactive(state: &Path) -> Result<Option<legacy::Event>> {
    if legacy::present(state)? {
        ensure!(
            !entry_exists(&state.join("rust-tip.json"))?
                && !entry_exists(&state.join("rust-events.jsonl"))?,
            "mixed Go/Rust journals; repair the interrupted handover before installation"
        );
        return legacy::inactive(state);
    }
    let journal = journal::Journal::inspect(state)?;
    if let Some(last) = journal.events.last() {
        ensure!(legacy::inactive_state(&last.state) && journal.reconciled,
            "update is in progress (Rust journal state={}, reconciliation required); finish or recover it before swapping", last.state);
    }
    Ok(None)
}
fn option(f: &mut BTreeMap<String, String>, key: &str, default: &str) -> PathBuf {
    PathBuf::from(f.remove(key).unwrap_or_else(|| default.into()))
}
fn atomic_mode(path: &Path, raw: &[u8], mode: u32) -> Result<()> {
    let temporary = path.with_file_name(format!(".install-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        write_new(&temporary, raw, 0o600)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
        fs::File::open(&temporary)?.sync_all()?;
        fs::rename(&temporary, path)?;
        sync_dir(path.parent().unwrap())
    })();
    if temporary.try_exists()? {
        fs::remove_file(temporary)?;
    }
    result
}
fn replace(path: &Path, raw: &[u8], mode: u32) -> Result<()> {
    if path.try_exists()? {
        let prior = read(path, 1 << 30, false)?;
        if prior == raw {
            return Ok(());
        }
        let previous = path.with_file_name(format!(
            "{}.prev",
            path.file_name().unwrap().to_string_lossy()
        ));
        atomic_mode(
            &previous,
            &prior,
            fs::symlink_metadata(path)?.permissions().mode() & 0o777,
        )?;
    }
    atomic_mode(path, raw, mode)
}
struct Replacement<'a> {
    path: PathBuf,
    raw: &'a [u8],
    mode: u32,
    prior: Option<(Vec<u8>, u32)>,
}
impl<'a> Replacement<'a> {
    fn new(path: PathBuf, raw: &'a [u8], mode: u32) -> Result<Self> {
        let prior = match fs::symlink_metadata(&path) {
            Ok(m) => Some((read(&path, 1 << 30, false)?, m.permissions().mode() & 0o777)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let previous = path.with_file_name(format!(
            "{}.prev",
            path.file_name().unwrap().to_string_lossy()
        ));
        match fs::symlink_metadata(&previous) {
            Ok(_) => {
                read(&previous, 1 << 30, false)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        Ok(Self {
            path,
            raw,
            mode,
            prior,
        })
    }
    fn restore(&self) -> Result<()> {
        if let Some((raw, mode)) = &self.prior {
            return atomic_mode(&self.path, raw, *mode);
        }
        match fs::symlink_metadata(&self.path) {
            Ok(_) => {
                ensure!(
                    read(&self.path, 1 << 30, false)? == self.raw,
                    "partial installation changed unexpectedly; restore matching *.prev manually"
                );
                fs::remove_file(&self.path)?;
                sync_dir(self.path.parent().unwrap())?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }
}
async fn active() -> Result<bool> {
    let output = tokio::process::Command::new(host::executable("systemctl")?)
        .args(["is-active", "--quiet", "setjoin-updater"])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(Duration::from_secs(30), output).await??;
    ensure!(
        matches!(output.status.code(), Some(0 | 3 | 4)),
        "cannot establish updater service state"
    );
    Ok(output.status.success())
}
pub async fn execute(mut f: BTreeMap<String, String>) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "updater installation must run as root"
    );
    let state = option(&mut f, "--state-dir", "/var/lib/setjoin-updater/journal");
    let lock = journal::local_lock(&state)?;
    local_inactive(&state)?;
    let binary = option(&mut f, "--binary", "");
    let libexec = option(&mut f, "--libexec-dir", "/usr/libexec");
    let units = option(&mut f, "--systemd-dir", "/etc/systemd/system");
    let unit = option(&mut f, "--unit-source", "");
    let dsn_path = option(&mut f, "--dsn-file", "/etc/setjoin-updater/updater-dsn");
    let office = f.remove("--office-runner").map(PathBuf::from);
    ensure!(f.is_empty(), "unknown installer options");
    let binary_raw = read(&binary, 1 << 30, false).context("read Rust updater artifact")?;
    ensure!(
        binary_raw.starts_with(b"\x7fELF"),
        "updater must be a native ELF binary"
    );
    let unit_raw = read(&unit, 1 << 20, false)?;
    let office_raw = office
        .as_ref()
        .map(|p| read(p, 1 << 30, false))
        .transpose()?;
    secure_dir(&libexec, 0o755)?;
    secure_dir(&units, 0o755)?;
    let installed = libexec.join("setjoin-updater");
    let mut replacements = Vec::new();
    if let Some(raw) = &office_raw {
        replacements.push(Replacement::new(
            libexec.join("setjoin-office-app-runner"),
            raw,
            0o755,
        )?);
    }
    replacements.push(Replacement::new(installed.clone(), &binary_raw, 0o755)?);
    replacements.push(Replacement::new(
        libexec.join("setjoin-recovery"),
        RECOVERY_WRAPPER,
        0o755,
    )?);
    replacements.push(Replacement::new(
        units.join("setjoin-updater.service"),
        &unit_raw,
        0o644,
    )?);
    let mut replacements_started = false;
    let mut db_guard = None;
    let was_active = installed.try_exists()? && active().await?;
    if was_active {
        host::fixed("systemctl", &["stop", "setjoin-updater"]).await?;
    }
    let result = async {
        let legacy_last = local_inactive(&state)?;
        // A first-ever install has neither an updater nor a control credential.
        // Every re-run needs the restricted DB credential, even with an empty log.
        let control = if installed.try_exists()? || dsn_path.try_exists()? || legacy_last.is_some() {
            let c = Connection::connect(&credential(&dsn_path).context("cannot establish inactive DB state; updater credential required")?).await?;
            c.lock().await?;
            if let Some(remote) = c.latest().await? {
                ensure!(legacy::inactive_state(&remote.state), "update is in progress (database state={}); finish or recover it before swapping journal formats", remote.state);
                if let Some(local) = &legacy_last {
                    ensure!(remote.id.to_string() == local.intent_id && remote.release_id == local.release_id
                        && remote.manifest_digest == local.manifest_digest && remote.generation == local.state_generation
                        && remote.state == local.state, "Go journal and DB differ; reconcile with the installed updater before swapping");
                }
            } else { ensure!(legacy_last.is_none(), "Go journal has no matching DB transaction"); }
            Some(c)
        } else { None };
        db_guard = control; // Hold through replacement and any rollback.
        if legacy::present(&state)? {
            let archive = state.join("go-terminal");
            secure_dir(&archive, 0o700)?;
            for name in ["events.jsonl", "snapshot.json", "last-terminal.json"] {
                let source = state.join(name);
                if entry_exists(&source)? {
                    let raw = read(&source, 64 << 20, true)?;
                    let destination = archive.join(name);
                    if destination.try_exists()? { ensure!(read(&destination, 64 << 20, true)? == raw, "prior Go archive differs"); }
                    else { write_new(&destination, &raw, 0o600)?; }
                }
            }
            sync_dir(&archive)?;
            // Copy+fsync the complete archive before unlinking any old journal file.
            for name in ["events.jsonl", "snapshot.json", "last-terminal.json"] {
                if entry_exists(&state.join(name))? { fs::remove_file(state.join(name))?; }
            }
            sync_dir(&state)?;
        }
        replacements_started=true;
        for r in &replacements { replace(&r.path,r.raw,r.mode)?; }
        Ok::<_, anyhow::Error>(())
    }.await;
    if let Err(cause) = &result {
        if replacements_started {
            let mut errors = Vec::new();
            for r in replacements.iter().rev() {
                if let Err(e) = r.restore() {
                    errors.push(format!("{}: {e:#}", r.path.display()));
                }
            }
            ensure!(
                errors.is_empty(),
                "installation failed: {}; restore matching *.prev manually; rollback errors: {}",
                cause,
                errors.join("; ")
            );
        }
    }
    drop(db_guard);
    drop(lock);
    if result.is_err() && was_active {
        host::fixed("systemctl", &["start", "setjoin-updater"])
            .await
            .context("restart updater after refused installation")?;
    }
    result?;
    println!("Rust updater/recovery installed; prior executables and unit preserved as *.prev; updater remains stopped for installer restart");
    Ok(())
}

pub async fn check(mut f: BTreeMap<String, String>) -> Result<()> {
    let state = option(&mut f, "--state-dir", "/var/lib/setjoin-updater/journal");
    let dsn = option(&mut f, "--dsn-file", "/etc/setjoin-updater/updater-dsn");
    ensure!(f.is_empty(), "unknown swap-check options");
    let _lock = journal::local_lock(&state)?;
    let last = local_inactive(&state)?;
    if dsn.try_exists()?
        || Path::new("/usr/libexec/setjoin-updater").try_exists()?
        || last.is_some()
    {
        let c =
            Connection::connect(&credential(&dsn).context("cannot establish inactive DB state")?)
                .await?;
        if let Some(remote) = c.latest().await? {
            ensure!(legacy::inactive_state(&remote.state), "update is in progress (database state={}); finish or recover it before swapping journal formats",remote.state);
        }
    }
    println!("updater swap preflight: inactive");
    Ok(())
}

/// #506: the wrapper never derives the updater from `$0` (a symlink or copy placed
/// elsewhere could redirect the root recovery entrypoint to another binary).
#[cfg(not(feature = "oracle-mutants"))]
pub const RECOVERY_WRAPPER: &[u8] =
    b"#!/bin/sh\nexec /usr/libexec/setjoin-updater recover \"$@\"\n";
#[cfg(feature = "oracle-mutants")]
pub const RECOVERY_WRAPPER: &[u8] = b"#!/bin/sh\nexec \"${0%/*}/setjoin-updater\" recover \"$@\"\n";
