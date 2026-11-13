//! Operator recovery at the standalone process boundary. Journal formats remain distinct.
use crate::{files::*, host, journal::Journal, stage};
use anyhow::{ensure, Result};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Status {
    current: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    previous: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    intent_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    intent_state: String,
    recovery_required: bool,
    database_reconciliation_required: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    journal_hash: String,
}
fn status(root: &Path, journal: &Journal) -> Result<Status> {
    let previous = match stage::active(root, "previous") {
        Ok(id) => id,
        Err(_)
            if std::fs::symlink_metadata(root.join("previous"))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            String::new()
        }
        Err(e) => return Err(e),
    };
    let last = journal.events.last();
    Ok(Status {
        current: stage::active(root, "current")?,
        previous,
        intent_id: last.map_or(String::new(), |e| e.intent_id.to_string()),
        intent_state: last.map_or(String::new(), |e| e.state.clone()),
        recovery_required: last.is_some_and(|e| e.state == "recovery_required"),
        database_reconciliation_required: last.is_some_and(|e| {
            e.state == "rolled_back" && e.step == "break_glass_reconciled" && !journal.reconciled
        }),
        journal_hash: last.map_or(String::new(), |e| e.hash.clone()),
    })
}
#[derive(Serialize)]
struct Evidence<'a> {
    schema_version: u8,
    recorded_at: String,
    phase: &'a str,
    reason: &'a str,
    forced: bool,
    status: &'a Status,
    units: BTreeMap<&'static str, String>,
}
async fn evidence(
    dir: &Path,
    phase: &str,
    reason: &str,
    forced: bool,
    status: &Status,
) -> Result<PathBuf> {
    secure_dir(dir, 0o700)?;
    let mut units = BTreeMap::new();
    for unit in ["setjoin-auth", "setjoin", "setjoin-updater"] {
        let state = if let Ok(exe) = host::executable("systemctl") {
            match tokio::process::Command::new(exe)
                .args(["is-active", unit])
                .env_clear()
                .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                .env("LANG", "C")
                .kill_on_drop(true)
                .output()
                .await
            {
                Ok(output) if output.status.success() => {
                    let state = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                    if !state.is_empty() && state.len() <= 32 {
                        state
                    } else {
                        "unknown".into()
                    }
                }
                _ => "unknown".into(),
            }
        } else {
            "unknown".into()
        };
        units.insert(unit, state);
    }
    let now = chrono::Utc::now();
    let value = Evidence {
        schema_version: 1,
        recorded_at: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        phase,
        reason,
        forced,
        status,
        units,
    };
    let raw = serde_json::to_string_pretty(&value)?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
        + "\n";
    let name = format!(
        "recovery-{}-{phase}-{}.json",
        now.format("%Y%m%dT%H%M%SZ"),
        &setjoin_release_format::sha256(raw.as_bytes())[..12]
    );
    let path = dir.join(name);
    match write_new(&path, raw.as_bytes(), 0o600) {
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) =>
        {
            ensure!(
                read(&path, 1 << 20, true)? == raw.as_bytes(),
                "evidence content differs"
            )
        }
        result => result?,
    }
    sync_dir(dir)?;
    Ok(path)
}
fn reason(value: &str) -> Result<()> {
    ensure!(
        (8..=1024).contains(&value.len()) && value.trim() == value,
        "recovery reason must be 8..1024 trimmed bytes"
    );
    ensure!(
        !value.chars().any(char::is_control),
        "recovery reason contains control characters"
    );
    Ok(())
}
#[derive(Debug)]
pub struct Usage;
impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,"usage: setjoin-recovery status [--json] | evidence [--reason TEXT] | activate-previous --reason TEXT [--force]")
    }
}
impl std::error::Error for Usage {}
fn action_options(args: &[String], action: &str) -> Result<(Option<String>, bool)> {
    let mut reason = None;
    let mut boolean = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let flag = arg
            .strip_prefix("--")
            .or_else(|| arg.strip_prefix('-'))
            .ok_or(Usage)?;
        let (key, value) = flag
            .split_once('=')
            .map_or((flag, None), |(k, v)| (k, Some(v)));
        match (action, key) {
            ("evidence" | "activate-previous", "reason") => {
                reason = Some(
                    value
                        .map(str::to_owned)
                        .or_else(|| args.next().cloned())
                        .ok_or(Usage)?,
                )
            }
            ("status", "json") | ("activate-previous", "force") => {
                boolean = match value.unwrap_or("true") {
                    "1" | "t" | "T" | "TRUE" | "true" | "True" => true,
                    "0" | "f" | "F" | "FALSE" | "false" | "False" => false,
                    _ => return Err(Usage.into()),
                };
            }
            _ => return Err(Usage.into()),
        }
    }
    Ok((reason, boolean))
}
pub async fn execute(args: &[String]) -> Result<()> {
    let mut args = args.iter().peekable();
    let mut f = BTreeMap::new();
    while args.peek().is_some_and(|s| s.starts_with("--")) {
        let key = args.next().unwrap().clone();
        let value = args
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing value for {key}"))?
            .clone();
        ensure!(f.insert(key, value).is_none(), "duplicate recovery option");
    }
    let root = PathBuf::from(
        f.remove("--install-root")
            .unwrap_or_else(|| "/opt/setjoin".into()),
    );
    let state = PathBuf::from(
        f.remove("--state-dir")
            .unwrap_or_else(|| "/var/lib/setjoin-updater/journal".into()),
    );
    let dir = PathBuf::from(
        f.remove("--evidence-dir")
            .unwrap_or_else(|| "/var/lib/setjoin-updater/recovery-evidence".into()),
    );
    let dsn = PathBuf::from(
        f.remove("--dsn-file")
            .unwrap_or_else(|| "/etc/setjoin-updater/updater-dsn".into()),
    );
    ensure!(f.is_empty(), "unknown recovery options");
    let action = args.next().map(String::as_str).unwrap_or("");
    let action_args: Vec<_> = args.cloned().collect();
    ensure!(
        matches!(action, "status" | "evidence" | "activate-previous"),
        Usage
    );
    let (text, boolean) = action_options(&action_args, action)?;
    if action == "activate-previous" && text.as_deref().is_none_or(|s| s.trim().is_empty()) {
        return Err(Usage.into());
    }
    let journal = Journal::inspect(&state)?;
    let s = status(&root, &journal)?;
    match action {
        "status" => {
            if !boolean {
                println!("current={} previous={} intent={} state={} recovery_required={} database_reconciliation_required={}", s.current, s.previous, s.intent_id, s.intent_state, s.recovery_required, s.database_reconciliation_required);
            } else {
                println!("{}", serde_json::to_string(&s)?);
            }
        }
        "evidence" => {
            let text = text.as_deref().unwrap_or("operator evidence snapshot");
            reason(text)?;
            println!(
                "{}",
                evidence(&dir, "operator_snapshot", text, false, &s)
                    .await?
                    .display()
            );
        }
        "activate-previous" => {
            let text = text.as_deref().unwrap();
            let force = boolean;
            reason(text)?;
            ensure!(
                unsafe { libc::geteuid() } == 0,
                "activate-previous must run as root"
            );
            drop(journal);
            let path = activate(&root, &state, &dir, &dsn, text, force).await?;
            println!("previous release verified; evidence={}", path.display());
        }
        _ => unreachable!(),
    }
    Ok(())
}

async fn restart_updater() -> Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        host::fixed("systemctl", &["start", "setjoin-updater"]),
    )
    .await??;
    Ok(())
}
async fn activate(
    root: &Path,
    state: &Path,
    dir: &Path,
    dsn: &Path,
    reason: &str,
    force: bool,
) -> Result<PathBuf> {
    let initial = Journal::inspect(state)?;
    let s = status(root, &initial)?;
    if s.intent_state == "rolled_back" && !s.database_reconciliation_required {
        if let Some(last) = initial
            .events
            .last()
            .filter(|e| e.step == "break_glass_reconciled")
        {
            if let Some(name) = last.evidence["evidence_file"].as_str() {
                if Path::new(name).file_name().and_then(|v| v.to_str()) == Some(name) {
                    let path = dir.join(name);
                    if read(&path, 1 << 20, true).is_ok() {
                        restart_updater().await.map_err(|e| {
                            anyhow::anyhow!(
                                "recovery is reconciled but updater restart failed: {e:#}"
                            )
                        })?;
                        return Ok(path);
                    }
                }
            }
        }
    }
    let tty = stdin_is_terminal();
    ensure!(
        s.recovery_required || s.database_reconciliation_required || force && tty,
        "break-glass recovery is not authorized"
    );
    let control = if s.recovery_required || s.database_reconciliation_required {
        Some(crate::control::Connection::connect(&credential(dsn)?).await?)
    } else {
        None
    };
    let never_activated = s.recovery_required
        && initial
            .events
            .last()
            .is_some_and(|e| e.release_id != s.current);
    ensure!(
        s.database_reconciliation_required
            || never_activated
            || !s.previous.is_empty() && s.previous != s.current,
        "no distinct complete previous release is available"
    );
    let before = evidence(dir, "before", reason, force, &s).await?;
    drop(initial);
    host::fixed("systemctl", &["stop", "setjoin-updater"]).await?;
    let result = async {
        let mut journal = Journal::open(state)?;
        ensure!(
            status(root, &journal)? == s,
            "recovery state changed while acquiring the execution boundary"
        );
        if let Some(control) = &control {
            control.lock().await?;
            let last = journal.events.last().unwrap();
            let remote = control
                .latest()
                .await?
                .ok_or_else(|| anyhow::anyhow!("database and local recovery transaction differ"))?;
            ensure!(
                remote.id == last.intent_id,
                "database and local recovery transaction differ"
            );
            if s.recovery_required {
                ensure!(
                    remote.state == "recovery_required" && remote.generation == last.generation,
                    "database and local recovery transaction differ"
                );
            }
            if s.database_reconciliation_required {
                control.recover(last).await?;
                journal.compact()?;
                return evidence(
                    dir,
                    "database_reconciled",
                    reason,
                    force,
                    &status(root, &journal)?,
                )
                .await;
            }
        }
        let failed = journal
            .events
            .last()
            .filter(|_| s.recovery_required)
            .map_or_else(|| s.current.clone(), |e| e.release_id.clone());
        host::stop().await?;
        if s.current == failed {
            stage::previous(root, &failed)?;
        }
        host::start().await?;
        host::readiness().await?;
        let after = status(root, &journal)?;
        let path = evidence(dir, "verified_previous", reason, force, &after).await?;
        if s.recovery_required {
            let recovered = journal.next(
                "rolled_back",
                "break_glass_reconciled",
                serde_json::json!({
                    "rollback":"verified", "reason":reason, "previous_release":after.current,
                    "evidence_file":path.file_name().unwrap().to_string_lossy(),
                }),
            )?;
            control.as_ref().unwrap().recover(&recovered).await?;
            journal.compact()?;
        }
        Ok(path)
    }
    .await;
    let restarted = restart_updater().await;
    match (result, restarted) {
        (Ok(path), Ok(())) => Ok(path),
        (Err(e), Ok(())) => Err(e.context(format!("recovery evidence={}", before.display()))),
        (result, Err(e)) => Err(anyhow::anyhow!(
            "{}; restart updater after recovery attempt: {e:#}",
            result.err().map_or(String::new(), |e| format!("{e:#}"))
        )),
    }
}

/// #506: a real terminal, not merely a character device. `/dev/null`, `/dev/zero`
/// and other non-tty character devices (systemd, cron, `ssh -n`) are refused.
fn stdin_is_terminal() -> bool {
    #[cfg(feature = "oracle-mutants")]
    {
        // Restored Go bug: any character device on fd 0 counts.
        use std::os::unix::fs::FileTypeExt;
        return std::fs::metadata("/proc/self/fd/0").is_ok_and(|m| m.file_type().is_char_device());
    }
    #[cfg(not(feature = "oracle-mutants"))]
    {
        // SAFETY: isatty only inspects descriptor 0 and has no memory effects.
        unsafe { libc::isatty(0) == 1 }
    }
}
