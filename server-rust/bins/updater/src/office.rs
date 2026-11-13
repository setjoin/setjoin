//! Temporary forwarding of the unported managed Office app shape, owned by #300.
//! This companion has no core-update, release-store or migration-owner arguments.
use crate::files::open;
use anyhow::{ensure, Context, Result};
use std::{
    collections::BTreeMap, future::Future, os::unix::fs::MetadataExt, path::Path, time::Duration,
};

pub struct Office {
    args: Vec<String>,
}
impl Office {
    pub fn take(f: &mut BTreeMap<String, String>) -> Result<Option<Self>> {
        let enabled = f.remove("--office-app-execution").is_some();
        let mut args = vec!["--office-app-only".into(), "--office-app-execution".into()];
        for (key, default) in [
            (
                "--office-app-worker-dsn-file",
                "/run/credentials/setjoin-updater.service/app-worker-dsn",
            ),
            (
                "--office-app-manifest",
                "/etc/setjoin/office-managed-app-v1.json",
            ),
            (
                "--office-app-state-dir",
                "/var/lib/setjoin-updater/appmarket/collabora-code",
            ),
        ] {
            args.extend([key.into(), f.remove(key).unwrap_or_else(|| default.into())]);
        }
        for (key, default) in [
            ("--executor-id", "setjoin-updater"),
            ("--poll-interval", "15s"),
        ] {
            args.extend([
                key.into(),
                f.get(key).cloned().unwrap_or_else(|| default.into()),
            ]);
        }
        if f.contains_key("--once") {
            args.push("--once".into());
        }
        Ok(enabled.then_some(Self { args }))
    }
    fn spawn(&self) -> Result<tokio::process::Child> {
        let path = Path::new("/usr/libexec/setjoin-office-app-runner");
        let file = open(path, false)
            .context("managed Office runner remains with #300; install its fixed companion")?;
        ensure!(
            file.metadata()?.uid() == 0 && file.metadata()?.mode() & 0o111 != 0,
            "Office runner must be root-owned and executable"
        );
        Ok(tokio::process::Command::new(path)
            .args(&self.args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C")
            .kill_on_drop(true)
            .spawn()?)
    }
    pub async fn once(&self) -> Result<()> {
        let status = self.spawn()?.wait().await?;
        ensure!(status.success(), "managed Office runner failed: {status}");
        Ok(())
    }
    pub async fn supervise<F: Future<Output = Result<()>>>(&self, core: F) -> Result<()> {
        let mut child = self.spawn()?;
        let result = tokio::select! {
            result = core => result,
            status = child.wait() => { let status=status?; anyhow::bail!("managed Office runner stopped: {status}"); }
        };
        if let Some(pid) = child.id() {
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }
        if tokio::time::timeout(Duration::from_secs(30), child.wait())
            .await
            .is_err()
        {
            child.kill().await?;
            child.wait().await?;
        }
        result
    }
}
