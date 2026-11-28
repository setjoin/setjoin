//! Read-only validation of frozen Go journals for inactive installation handover.
//! Never resumes a Go transaction or translates it into a Rust journal.
use crate::files::*;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::path::Path;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    version: u8,
    sequence: u64,
    occurred_at: String,
    pub intent_id: String,
    pub release_id: String,
    pub manifest_digest: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    recovery_set_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    recovery_set_digest: String,
    lease_id: String,
    executor_id: String,
    pub state_generation: i64,
    pub state: String,
    step: String,
    evidence: Box<RawValue>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    previous_hash: String,
    #[serde(skip_serializing)]
    hash: String,
}
impl Event {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && self.sequence > 0
                && self.state_generation > 0
                && identifier(&self.intent_id)
                && identifier(&self.release_id)
                && identifier(&self.executor_id)
                && identifier(&self.step)
                && digest(&self.manifest_digest)
                && digest(&self.hash)
                && (self.previous_hash.is_empty() || digest(&self.previous_hash))
                && uuid::Uuid::parse_str(&self.lease_id).is_ok()
                && self.evidence.get().len() <= 1 << 20
                && self.evidence.get().starts_with('{'),
            "invalid Go journal event"
        );
        chrono::DateTime::parse_from_rfc3339(&self.occurred_at)?;
        ensure!(
            matches!(
                self.state.as_str(),
                "awaiting_approval"
                    | "approved"
                    | "scheduled"
                    | "claimed"
                    | "preflight"
                    | "recovery_point"
                    | "staged"
                    | "maintenance"
                    | "migrations"
                    | "switched"
                    | "readiness"
                    | "committed"
                    | "verified"
                    | "cancel_requested"
                    | "rolling_back"
                    | "rolled_back"
                    | "failed"
                    | "recovery_required"
                    | "cancelled"
                    | "expired"
            ),
            "unknown Go journal state"
        );
        ensure!(
            self.recovery_set_id.is_empty() && self.recovery_set_digest.is_empty()
                || uuid::Uuid::parse_str(&self.recovery_set_id).is_ok()
                    && digest(&self.recovery_set_digest),
            "invalid Go recovery identity"
        );
        ensure!(
            setjoin_release_format::sha256(&setjoin_release_format::marshal_go(self)?) == self.hash,
            "Go journal checksum mismatch"
        );
        Ok(())
    }
    fn follows(&self, prior: &Self) -> Result<()> {
        ensure!(
            self.sequence == prior.sequence + 1
                && self.previous_hash == prior.hash
                && self.state_generation == prior.state_generation + 1
                && self.intent_id == prior.intent_id
                && self.release_id == prior.release_id
                && self.manifest_digest == prior.manifest_digest
                && self.lease_id == prior.lease_id
                && self.executor_id == prior.executor_id
                && self.recovery_set_id == prior.recovery_set_id
                && self.recovery_set_digest == prior.recovery_set_digest,
            "Go journal sequence or authority mismatch"
        );
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u8,
    last: Event,
    reconciled: bool,
}
pub fn present(dir: &Path) -> Result<bool> {
    Ok(entry_exists(&dir.join("events.jsonl"))? || entry_exists(&dir.join("snapshot.json"))?)
}
pub fn inactive(dir: &Path) -> Result<Option<Event>> {
    let snapshot: Option<Snapshot> = if entry_exists(&dir.join("snapshot.json"))? {
        let s: Snapshot =
            serde_json::from_slice(&read(&dir.join("snapshot.json"), 1 << 20, true)?)?;
        ensure!(s.version == 1, "unknown Go journal snapshot version");
        s.last.validate()?;
        Some(s)
    } else {
        None
    };
    let mut last = snapshot.as_ref().map(|s| s.last.clone());
    let mut overlap: Option<Event> = None;
    let mut unreconciled = false;
    if entry_exists(&dir.join("events.jsonl"))? {
        let raw = read(&dir.join("events.jsonl"), 64 << 20, true)?;
        ensure!(
            raw.is_empty() || raw.ends_with(b"\n"),
            "Go journal has a torn write"
        );
        for line in raw
            .strip_suffix(b"\n")
            .unwrap_or(&raw)
            .split(|b| *b == b'\n')
            .filter(|_| !raw.is_empty())
        {
            ensure!(line.len() <= 1 << 20, "oversized Go journal record");
            let event: Event = serde_json::from_slice(line)?;
            event.validate()?;
            if snapshot
                .as_ref()
                .is_some_and(|s| event.sequence <= s.last.sequence)
            {
                if let Some(prior) = &overlap {
                    event.follows(prior)?;
                } else {
                    ensure!(
                        event.sequence == 1 && event.previous_hash.is_empty(),
                        "Go journal missing prefix"
                    );
                }
                if event.sequence == snapshot.as_ref().unwrap().last.sequence {
                    ensure!(
                        event.hash == snapshot.as_ref().unwrap().last.hash,
                        "Go snapshot/log conflict"
                    );
                }
                overlap = Some(event);
            } else {
                if let Some(prior) = &last {
                    event.follows(prior)?;
                } else {
                    ensure!(
                        event.sequence == 1 && event.previous_hash.is_empty(),
                        "Go journal missing prefix"
                    );
                }
                last = Some(event);
                unreconciled = true;
            }
        }
    }
    if let Some(last) = &last {
        ensure!(inactive_state(&last.state) && snapshot.as_ref().is_some_and(|s| s.reconciled) && !unreconciled,
            "update is in progress (Go journal state={}, reconciliation required); finish or recover it with the installed updater before swapping journal formats", last.state);
    }
    Ok(last)
}
pub fn inactive_state(state: &str) -> bool {
    matches!(
        state,
        "verified" | "rolled_back" | "failed" | "cancelled" | "expired"
    )
}
