//! C03 publication boundary. The plan is consumed by one RP05 transaction;
//! no node, version, reference, ready state, audit or event is committed alone.
use crate::{
    authority::{AuthorityKey, ResourceScope},
    content::VerifiedContentReceipt,
    error::ContractError,
    ids::*,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordingState {
    Requested,
    Active,
    Stopping,
    PendingIngest,
    Ready,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Publication {
    pub recording: RecordingId,
    pub node: NodeId,
    pub version: VersionId,
    pub content: VerifiedContentReceipt,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordingFacts {
    pub recording: RecordingId,
    pub meeting: MeetingId,
    pub owner: ActorId,
    pub space: SpaceId,
    pub capture_generation: Generation,
    pub participant_generation: Generation,
    pub state: RecordingState,
    pub accepted: Option<Publication>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishRecording {
    pub meeting: MeetingId,
    pub publication: Publication,
    pub authority: AuthorityKey,
    pub capture_generation: Generation,
    pub participant_generation: Generation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationDecision {
    AtomicPublish(Publication),
    AlreadyAccepted(Publication),
}
impl PublishRecording {
    /// `facts`, `current`, and `verified` must be fresh trusted reads at the
    /// declared transaction boundary. Equality never substitutes for byte verification.
    pub fn plan(
        self,
        facts: RecordingFacts,
        current: AuthorityKey,
        verified: VerifiedContentReceipt,
    ) -> Result<PublicationDecision, ContractError> {
        self.authority.check_current(current)?;
        if self.meeting != facts.meeting
            || self.publication.recording != facts.recording
            || current.scope != ResourceScope::Drive(facts.space)
        {
            return Err(ContractError::ScopeMismatch);
        }
        if current.actor != facts.owner {
            return Err(ContractError::ActorMismatch);
        }
        if self.capture_generation != facts.capture_generation
            || self.participant_generation != facts.participant_generation
        {
            return Err(ContractError::StaleGeneration);
        }
        if verified != self.publication.content
            || verified.space != facts.space
            || verified.owner != facts.owner
            || verified.bytes > i64::MAX as u64
        {
            return Err(ContractError::UnverifiedContent);
        }
        match (facts.state, facts.accepted) {
            (RecordingState::Ready, Some(accepted)) if accepted == self.publication => {
                Ok(PublicationDecision::AlreadyAccepted(accepted))
            }
            (RecordingState::Ready, _) => Err(ContractError::ConflictingReplay),
            (RecordingState::PendingIngest, None) => {
                Ok(PublicationDecision::AtomicPublish(self.publication))
            }
            _ => Err(ContractError::InvalidState),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagingDisposition {
    Keep,
    RemoveAfterAcceptedCommit,
    RemoveAfterDiagnosticGrace,
}
pub fn staging_disposition(
    state: RecordingState,
    accepted_commit_known: bool,
    diagnostic_grace_elapsed: bool,
) -> StagingDisposition {
    match state {
        RecordingState::Ready if accepted_commit_known => {
            StagingDisposition::RemoveAfterAcceptedCommit
        }
        RecordingState::Failed if diagnostic_grace_elapsed => {
            StagingDisposition::RemoveAfterDiagnosticGrace
        }
        _ => StagingDisposition::Keep,
    }
}
