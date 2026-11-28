//! Rust-only durable journal. Appended effects precede DB acknowledgments.
use crate::files::*;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use setjoin_release_format::sha256;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub sequence: u64,
    pub intent_id: i64,
    pub release_id: String,
    pub manifest_digest: String,
    pub recovery_set_id: String,
    pub recovery_set_digest: String,
    pub lease_id: uuid::Uuid,
    pub executor_id: String,
    pub generation: i64,
    pub state: String,
    pub step: String,
    pub evidence: Value,
    pub previous_hash: String,
    pub hash: String,
}
impl Event {
    fn checksum(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.hash.clear();
        Ok(sha256(&serde_json::to_vec(&unsigned)?))
    }
    pub fn terminal(&self) -> bool {
        matches!(
            self.state.as_str(),
            "verified" | "rolled_back" | "failed" | "recovery_required" | "cancelled" | "expired"
        )
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    format: String,
    last: Event,
    reconciled: bool,
}
pub struct Journal {
    pub dir: PathBuf,
    pub events: Vec<Event>,
    pub reconciled: bool,
    _lock: Option<File>,
}
impl Journal {
    pub fn open(dir: &Path) -> Result<Self> {
        Self::load(dir, true)
    }
    pub fn inspect(dir: &Path) -> Result<Self> {
        Self::load(dir, false)
    }
    fn load(dir: &Path, exclusive: bool) -> Result<Self> {
        secure_dir(dir, 0o700)?;
        ensure!(
            fs::symlink_metadata(dir)?.permissions().mode() & 0o077 == 0,
            "journal must be private"
        );
        let lock = if exclusive {
            let lock = local_lock(dir)?;
            Some(lock)
        } else {
            None
        };
        ensure!(
            !crate::legacy::present(dir)?,
            "Go journal present: swap requires no update in progress (#359)"
        );
        let mut j = Self {
            dir: dir.into(),
            events: Vec::new(),
            reconciled: false,
            _lock: lock,
        };
        if entry_exists(&dir.join("rust-tip.json"))? {
            let s: Snapshot =
                serde_json::from_slice(&read(&dir.join("rust-tip.json"), 1 << 20, true)?)?;
            ensure!(
                s.format == "setjoin-rust-updater-v1" && s.reconciled && s.last.terminal(),
                "invalid journal snapshot"
            );
            j.validate(&s.last, None)?;
            j.events.push(s.last);
            j.reconciled = true;
        }
        if entry_exists(&dir.join("rust-events.jsonl"))? {
            let raw = read(&dir.join("rust-events.jsonl"), 64 << 20, true)?;
            ensure!(
                raw.is_empty() || raw.ends_with(b"\n"),
                "upgrade journal has a torn write"
            );
            for line in raw.split(|b| *b == b'\n').filter(|b| !b.is_empty()) {
                ensure!(line.len() <= 1 << 20, "oversized journal record");
                let e: Event = serde_json::from_slice(line)?;
                if j.events
                    .last()
                    .is_some_and(|last| e.sequence <= last.sequence)
                {
                    let last = j.events.last().unwrap();
                    ensure!(
                        j.reconciled && (e.sequence < last.sequence || e.hash == last.hash),
                        "snapshot/log conflict"
                    );
                    continue;
                }
                j.validate(&e, j.events.last())?;
                j.events.push(e);
                j.reconciled = false;
            }
        }
        Ok(j)
    }
    fn validate(&self, e: &Event, last: Option<&Event>) -> Result<()> {
        ensure!(
            e.intent_id > 0
                && e.generation > 0
                && e.sequence > 0
                && identifier(&e.release_id)
                && identifier(&e.executor_id)
                && identifier(&e.step)
                && digest(&e.manifest_digest)
                && digest(&e.recovery_set_digest)
                && uuid::Uuid::parse_str(&e.recovery_set_id).is_ok()
                && !e.lease_id.is_nil()
                && e.evidence.is_object()
                && serde_json::to_vec(&e.evidence)?.len() <= 65536,
            "invalid upgrade journal event"
        );
        ensure!(e.hash == e.checksum()?, "upgrade journal checksum mismatch");
        if let Some(last) = last {
            ensure!(
                e.sequence == last.sequence + 1
                    && e.previous_hash == last.hash
                    && e.intent_id == last.intent_id
                    && e.release_id == last.release_id
                    && e.manifest_digest == last.manifest_digest
                    && e.lease_id == last.lease_id
                    && e.executor_id == last.executor_id
                    && e.recovery_set_id == last.recovery_set_id
                    && e.recovery_set_digest == last.recovery_set_digest
                    && e.generation == last.generation + 1,
                "journal sequence or authority mismatch"
            );
        } else {
            ensure!(
                e.sequence == 1 || e.terminal(),
                "journal missing initial event"
            );
        }
        Ok(())
    }
    pub fn append(&mut self, mut event: Event) -> Result<Event> {
        event.sequence = self.events.last().map_or(1, |e| e.sequence + 1);
        event.previous_hash = self.events.last().map_or(String::new(), |e| e.hash.clone());
        event.hash = event.checksum()?;
        self.validate(&event, self.events.last())?;
        let path = self.dir.join("rust-events.jsonl");
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        ensure!(f.metadata()?.len() < 64 << 20, "journal exceeds limit");
        let mut line = serde_json::to_vec(&event)?;
        line.push(b'\n');
        f.write_all(&line)?;
        f.sync_all()?;
        sync_dir(&self.dir)?;
        self.events.push(event.clone());
        self.reconciled = false;
        Ok(event)
    }
    pub fn next(&mut self, state: &str, step: &str, evidence: Value) -> Result<Event> {
        let mut e = self
            .events
            .last()
            .ok_or_else(|| anyhow::anyhow!("empty journal"))?
            .clone();
        e.generation = e
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("generation overflow"))?;
        e.state = state.into();
        e.step = step.into();
        e.evidence = evidence;
        self.append(e)
    }
    pub fn compact(&mut self) -> Result<()> {
        let last = self
            .events
            .last()
            .ok_or_else(|| anyhow::anyhow!("empty journal"))?
            .clone();
        ensure!(last.terminal(), "compaction requires terminal state");
        atomic(
            &self.dir.join("rust-tip.json"),
            &serde_json::to_vec(&Snapshot {
                format: "setjoin-rust-updater-v1".into(),
                last: last.clone(),
                reconciled: true,
            })?,
        )?;
        let path = self.dir.join("rust-events.jsonl");
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        f.sync_all()?;
        sync_dir(&self.dir)?;
        self.events = vec![last];
        self.reconciled = true;
        Ok(())
    }
    pub fn archive(&mut self) -> Result<()> {
        ensure!(
            self.reconciled && self.events.last().is_some_and(Event::terminal),
            "cannot rotate active journal"
        );
        atomic(
            &self.dir.join("rust-last-terminal.json"),
            &read(&self.dir.join("rust-tip.json"), 1 << 20, true)?,
        )?;
        fs::remove_file(self.dir.join("rust-tip.json"))?;
        sync_dir(&self.dir)?;
        self.events.clear();
        self.reconciled = false;
        Ok(())
    }
}

pub fn local_lock(dir: &Path) -> Result<File> {
    secure_dir(dir, 0o700)?;
    ensure!(
        fs::symlink_metadata(dir)?.permissions().mode() & 0o077 == 0,
        "journal must be private"
    );
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join("executor.lock"))?;
    ensure!(lock.metadata()?.is_file(), "unsafe lock file");
    lock.try_lock()
        .map_err(|_| anyhow::anyhow!("another setjoin updater owns the local execution lock"))?;
    Ok(lock)
}
