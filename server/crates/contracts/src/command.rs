//! CON-01/02: operation recovery does not infer rollback from a missing response.
use crate::{authority::AuthorityKey, error::ContractError, ids::*};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractBinding {
    pub major: u16,
    pub definition: Digest,
    pub fixtures: Digest,
}
impl ContractBinding {
    pub fn require_exact(self, accepted: Self) -> Result<(), ContractError> {
        if self.major != accepted.major {
            return Err(ContractError::UnsupportedVersion);
        }
        if self != accepted {
            return Err(ContractError::ContractDrift);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandEnvelope<T> {
    pub operation: OperationId,
    pub authority: AuthorityKey,
    pub binding: ContractBinding,
    pub payload_digest: Digest,
    pub command: T,
}
impl<T> CommandEnvelope<T> {
    pub fn validate(
        &self,
        current: AuthorityKey,
        accepted: ContractBinding,
    ) -> Result<(), ContractError> {
        self.binding.require_exact(accepted)?;
        self.authority.check_current(current)?;
        if self.operation.0 == [0; 16] {
            return Err(ContractError::InvalidEnvelope);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitObservation {
    Committed,
    RolledBack,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalEffectState {
    NotIssued,
    Accepted,
    Failed,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationResult<T> {
    Pending,
    Accepted(T),
    Rejected,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationRecord<T> {
    pub operation: OperationId,
    pub authority: AuthorityKey,
    pub payload_digest: Digest,
    pub result: OperationResult<T>,
}
impl<T> OperationRecord<T> {
    /// The lookup authority is re-read now. A receipt is not a lasting read capability.
    /// Generation on the record is historical; current caller generation is validated.
    pub fn lookup<'a>(
        &'a self,
        request: &CommandEnvelope<()>,
        current: AuthorityKey,
        accepted: ContractBinding,
    ) -> Result<&'a OperationResult<T>, ContractError> {
        request.validate(current, accepted)?;
        if self.authority.actor != current.actor {
            return Err(ContractError::ActorMismatch);
        }
        if self.authority.scope != current.scope {
            return Err(ContractError::ScopeMismatch);
        }
        if self.operation != request.operation || self.payload_digest != request.payload_digest {
            return Err(ContractError::ConflictingReplay);
        }
        Ok(&self.result)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    ReadAcceptedResult,
    ReturnRejected,
    LookupUnderCurrentAuthority,
}
pub fn recover(observation: CommitObservation) -> RecoveryAction {
    match observation {
        CommitObservation::Committed => RecoveryAction::ReadAcceptedResult,
        CommitObservation::RolledBack => RecoveryAction::ReturnRejected,
        CommitObservation::Unknown => RecoveryAction::LookupUnderCurrentAuthority,
    }
}
/// Scoped plaintext pilot only; this is NOT all of Email/set or broad Email/get.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetMessageSeen {
    pub mailbox: MailboxId,
    pub message: MessageId,
    pub seen: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionOwner {
    MailEmailSet,
    RecordingPublication,
    ContentReference,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectRequirement {
    AtomicState,
    AtomicJournal,
    RequiredActorAudit,
    TransactionalNotification,
    RetainedDelivery,
    PostCommitStagingCleanup,
    AcceptedOperationResult,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SavepointPolicy {
    ItemFailureOnly,
    WholeCommand,
}
pub struct CommandSheet {
    pub name: &'static str,
    pub owner: TransactionOwner,
    pub savepoints: SavepointPolicy,
    pub participants: &'static [&'static str],
    pub lock_order: &'static [&'static str],
    pub effects: &'static [EffectRequirement],
    pub recovery_owner: &'static str,
}
pub const MARK_SEEN: CommandSheet = CommandSheet {
    name: "mail.email.set-seen",
    owner: TransactionOwner::MailEmailSet,
    savepoints: SavepointPolicy::ItemFailureOnly,
    participants: &[
        "scoped message flags",
        "mailbox states/counters",
        "change journal",
        "actor audit",
        "operation result",
    ],
    lock_order: &[
        "current mailbox authority",
        "message ownership/row",
        "affected tag rows",
        "affected mailbox state rows",
    ],
    effects: &[
        EffectRequirement::AtomicState,
        EffectRequirement::AtomicJournal,
        EffectRequirement::RequiredActorAudit,
        EffectRequirement::TransactionalNotification,
        EffectRequirement::RetainedDelivery,
        EffectRequirement::AcceptedOperationResult,
    ],
    recovery_owner: "RP07 command through RP05 current-authority operation lookup",
};
pub const RECORDING_PUBLICATION: CommandSheet = CommandSheet {
    name: "meet.recording.publish-drive",
    owner: TransactionOwner::RecordingPublication,
    savepoints: SavepointPolicy::WholeCommand,
    participants: &[
        "recording",
        "Drive node/version/manifest references",
        "quota",
        "audit",
        "change events",
        "operation result",
    ],
    lock_order: &[
        "recording and capture generation",
        "current target space authority/classification",
        "target reference",
        "quota/state",
    ],
    effects: &[
        EffectRequirement::AtomicState,
        EffectRequirement::AtomicJournal,
        EffectRequirement::RequiredActorAudit,
        EffectRequirement::TransactionalNotification,
        EffectRequirement::PostCommitStagingCleanup,
        EffectRequirement::AcceptedOperationResult,
    ],
    recovery_owner: "RP11 recording drain with RP10 reference/reclamation owner",
};
impl SetMessageSeen {
    pub fn validate_scope(self, authority: AuthorityKey) -> Result<(), ContractError> {
        if authority.scope != crate::authority::ResourceScope::Mailbox(self.mailbox) {
            return Err(ContractError::ScopeMismatch);
        }
        Ok(())
    }
}
/// Exact infrastructural statements for the selected future executor. These
/// constants do not admit domain reducers, generated SQL, arbitrary SET or SET ROLE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InfrastructureStatement {
    MailboxScope,
    ActorScope,
    ChunkLock,
}
impl InfrastructureStatement {
    pub const fn sql(self) -> &'static str {
        match self {
            Self::MailboxScope => "SELECT set_config('app.current_mailbox_id', $1, true)",
            Self::ActorScope => "SELECT set_config('app.current_user_id', $1, true)",
            Self::ChunkLock => "SELECT pg_advisory_xact_lock(hashtextextended('drive-chunk:' || $1::text || ':' || $2::text, 0))",
        }
    }
}
