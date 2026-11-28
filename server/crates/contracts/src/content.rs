//! C02: verified manifest, upload proof, repeat-safe reference and reclamation contracts.
use crate::{
    error::{ContractError, DomainError},
    ids::*,
};
pub const CHUNK_BYTES: u64 = 4 * 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestChunk {
    pub sha256: Digest,
    pub bytes: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub whole_sha256: Digest,
    pub bytes: u64,
    pub chunks: Vec<ManifestChunk>,
}
impl Manifest {
    /// Shape only. Does not pretend to hash bytes or prove possession.
    pub fn validate_shape(&self) -> Result<(), DomainError> {
        if self.bytes > i64::MAX as u64 {
            return Err(DomainError::InvalidManifest);
        }
        if self.bytes == 0 && !self.chunks.is_empty() {
            return Err(DomainError::InvalidManifest);
        }
        let mut total = 0u64;
        for (index, chunk) in self.chunks.iter().enumerate() {
            if chunk.bytes == 0
                || chunk.bytes > CHUNK_BYTES
                || (index + 1 < self.chunks.len() && chunk.bytes != CHUNK_BYTES)
            {
                return Err(DomainError::InvalidManifest);
            }
            total = total
                .checked_add(chunk.bytes)
                .ok_or(DomainError::InvalidManifest)?;
        }
        if total != self.bytes {
            return Err(DomainError::InvalidManifest);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DedupScope {
    GlobalRegular,
    Protected(SpaceId),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AclUploadProof {
    pub actor: ActorId,
    pub space: SpaceId,
    pub target: NodeId,
    pub scope: DedupScope,
    pub sha256: Digest,
    pub acl_generation: Generation,
    pub expires_at_micros: i64,
}
impl AclUploadProof {
    pub fn matches(self, requested: Self, now_micros: i64) -> bool {
        self.actor == requested.actor
            && self.space == requested.space
            && self.target == requested.target
            && self.scope == requested.scope
            && self.sha256 == requested.sha256
            && self.acl_generation == requested.acl_generation
            && self.expires_at_micros > now_micros
    }
}
/// Data returned by the content verifier; callers MUST obtain it from their trusted
/// content store. This DTO alone is not an unforgeable proof or credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedContentReceipt {
    pub space: SpaceId,
    pub owner: ActorId,
    pub manifest_digest: Digest,
    pub whole_sha256: Digest,
    pub bytes: u64,
    pub verification_generation: Generation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceState {
    pub revision: Generation,
    pub attached: bool,
    pub shared_count: u64,
    pub held: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceIntent {
    Attach,
    Detach,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceDecision {
    NoChange,
    Replace(ReferenceState),
}
impl ReferenceState {
    /// Locked reference identity + global count must be read/written atomically by RP10.
    /// Replays do not increment/decrement again. A hold preserves the actual reference.
    pub fn plan(
        self,
        expected: Generation,
        intent: ReferenceIntent,
    ) -> Result<ReferenceDecision, ContractError> {
        if self.revision != expected {
            return Err(ContractError::StaleReference);
        }
        let attach = intent == ReferenceIntent::Attach;
        if self.attached == attach {
            return Ok(ReferenceDecision::NoChange);
        }
        if !attach && self.held {
            return Err(ContractError::Held);
        }
        let shared_count = if attach {
            self.shared_count.checked_add(1)
        } else {
            self.shared_count.checked_sub(1)
        }
        .ok_or(ContractError::Arithmetic)?;
        let revision = Generation(
            self.revision
                .0
                .checked_add(1)
                .ok_or(ContractError::Arithmetic)?,
        );
        Ok(ReferenceDecision::Replace(Self {
            revision,
            attached: attach,
            shared_count,
            held: self.held,
        }))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReclamationFacts {
    pub referenced: bool,
    pub held: bool,
    pub retained_until_micros: Option<i64>,
    pub queue_verdict_observed: bool,
    pub metadata_delete_committed: bool,
    pub row_absent_under_chunk_lock: bool,
}
impl ReclamationFacts {
    /// No physical delete permission until the SECOND locked absence check.
    /// The consumer must hold the same producer chunk lock through storage deletion.
    pub fn may_remove_bytes(self, now: i64) -> bool {
        !self.referenced
            && !self.held
            && self.retained_until_micros.is_none_or(|t| t <= now)
            && self.queue_verdict_observed
            && self.metadata_delete_committed
            && self.row_absent_under_chunk_lock
    }
}
