//! Conservative transaction completion and authenticated recovery decisions.
use setjoin_contracts::{
    authority::AuthorityKey,
    command::{
        CommandEnvelope, CommitObservation, ContractBinding, OperationRecord, OperationResult,
    },
    error::ContractError,
    ids::Digest,
};
use std::time::Instant;

/// Exact formatted successor accepted by this consumer. Not the historical binding.
pub fn accepted_contract() -> ContractBinding {
    ContractBinding {
        major: 1,
        definition: Digest([
            0x33, 0x2b, 0x05, 0xbd, 0x4b, 0xa4, 0x04, 0x7f, 0xdd, 0xe6, 0xaf, 0xc7, 0xe7, 0xaf,
            0x0b, 0x8f, 0xe5, 0xb0, 0xf2, 0xb1, 0xdb, 0xb9, 0x51, 0x21, 0x4e, 0x82, 0xea, 0x1f,
            0x7d, 0xdf, 0x44, 0x68,
        ]),
        fixtures: Digest([
            0x11, 0x40, 0x1b, 0xc5, 0xed, 0xf4, 0x10, 0x25, 0xb2, 0xf9, 0xa8, 0x5d, 0x99, 0x98,
            0x94, 0xdb, 0x79, 0xaf, 0xea, 0x4b, 0xee, 0xfa, 0x2f, 0xd1, 0x48, 0x68, 0x81, 0xd6,
            0x27, 0xf8, 0xe8, 0xbc,
        ]),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleError {
    Contract(ContractError),
    DeadlineElapsed,
    InvalidTransition,
}
impl From<ContractError> for LifecycleError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Active,
    CommitPending,
    RollbackPending,
    Terminal(CommitObservation),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionDisposition {
    /// An open transaction or outstanding response must not return to the pool.
    Retain,
    /// A known terminal response is necessary but not sufficient for pool reuse.
    VerifyDriverReset,
    /// The old connection is never reusable by this lifecycle, even after lookup.
    Quarantine,
}

/// Observation from the selected driver's command response, not a timeout inference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RollbackObservation {
    Acknowledged,
    Unknown,
}

/// No Clone: one owner tracks a connection's transaction lifecycle.
#[derive(Debug)]
pub struct TransactionLifecycle {
    identity: CommandEnvelope<()>,
    deadline: Instant,
    phase: Phase,
    quarantined: bool,
}
impl TransactionLifecycle {
    /// Validate immutable request identity before it is used. This constructor does
    /// not acquire a connection, begin a transaction, or authorize any SQL.
    /// A future driver owns cleanup on every error before/after calling this core.
    pub fn new<T>(request: &CommandEnvelope<T>, deadline: Instant) -> Result<Self, LifecycleError> {
        // Comparing a key to itself validates only binding/envelope shape here.
        request.validate(request.authority, accepted_contract())?;
        Ok(Self {
            identity: CommandEnvelope {
                operation: request.operation,
                authority: request.authority,
                binding: request.binding,
                payload_digest: request.payload_digest,
                command: (),
            },
            deadline,
            phase: Phase::Active,
            quarantined: false,
        })
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn connection_disposition(&self) -> ConnectionDisposition {
        if self.quarantined {
            return ConnectionDisposition::Quarantine;
        }
        match self.phase {
            Phase::Terminal(CommitObservation::Committed | CommitObservation::RolledBack) => {
                ConnectionDisposition::VerifyDriverReset
            }
            Phase::Terminal(CommitObservation::Unknown) => ConnectionDisposition::Quarantine,
            _ => ConnectionDisposition::Retain,
        }
    }

    /// Called under the actual transaction's current-authority/entitlement fence
    /// immediately before a statement, and again immediately before COMMIT.
    /// Matching keys do not grant entitlement. The driver must separately enforce
    /// capability, parameterized ownership predicates, role and lock ordering.
    pub fn check_current_key(
        &mut self,
        current: AuthorityKey,
        now: Instant,
    ) -> Result<(), LifecycleError> {
        if self.phase != Phase::Active {
            return Err(LifecycleError::InvalidTransition);
        }
        if now >= self.deadline {
            self.phase = Phase::RollbackPending;
            return Err(LifecycleError::DeadlineElapsed);
        }
        if let Err(error) = self.identity.validate(current, accepted_contract()) {
            self.phase = Phase::RollbackPending;
            return Err(error.into());
        }
        Ok(())
    }

    /// Marks intent BEFORE the driver may send COMMIT. A lost send/response then
    /// cannot be mistaken for a safely uncommitted transaction or blind retry.
    pub fn request_commit(
        &mut self,
        current: AuthorityKey,
        now: Instant,
    ) -> Result<(), LifecycleError> {
        self.check_current_key(current, now)?;
        self.phase = Phase::CommitPending;
        Ok(())
    }

    pub fn observe_commit(&mut self, observation: CommitObservation) -> Result<(), LifecycleError> {
        if self.phase != Phase::CommitPending {
            return Err(LifecycleError::InvalidTransition);
        }
        self.finish(observation);
        Ok(())
    }

    /// Before commit intent, cancellation requests rollback and retains the lease.
    /// During commit intent it is ambiguous; no late response rehabilitates this
    /// connection. Lookup through a separate clean connection resolves the result.
    pub fn cancel(&mut self) -> Result<(), LifecycleError> {
        match self.phase {
            Phase::Active => self.phase = Phase::RollbackPending,
            Phase::RollbackPending => {}
            Phase::CommitPending => self.finish(CommitObservation::Unknown),
            Phase::Terminal(_) => return Err(LifecycleError::InvalidTransition),
        }
        Ok(())
    }

    /// Authority/audit/command failure must abort the whole command. A business
    /// item error is handled by the future savepoint owner, not passed here as a
    /// fake successful rollback. Infrastructure ambiguity uses connection_lost.
    pub fn request_rollback(&mut self) -> Result<(), LifecycleError> {
        match self.phase {
            Phase::Active => self.phase = Phase::RollbackPending,
            Phase::RollbackPending => {}
            _ => return Err(LifecycleError::InvalidTransition),
        }
        Ok(())
    }

    pub fn observe_rollback(
        &mut self,
        observation: RollbackObservation,
    ) -> Result<(), LifecycleError> {
        if self.phase != Phase::RollbackPending {
            return Err(LifecycleError::InvalidTransition);
        }
        self.finish(match observation {
            RollbackObservation::Acknowledged => CommitObservation::RolledBack,
            RollbackObservation::Unknown => CommitObservation::Unknown,
        });
        Ok(())
    }

    /// A connection/driver failure always prevents reuse. A previously received
    /// terminal outcome remains known; otherwise this core refuses to infer it.
    pub fn connection_lost(&mut self) {
        self.quarantined = true;
        if !matches!(self.phase, Phase::Terminal(_)) {
            self.phase = Phase::Terminal(CommitObservation::Unknown);
        }
    }

    fn finish(&mut self, observation: CommitObservation) {
        self.phase = Phase::Terminal(observation);
        if observation == CommitObservation::Unknown {
            self.quarantined = true;
        }
    }
}

/// Read-only recovery advice: deliberately no "retry" or "execute" variant.
#[derive(Debug, PartialEq, Eq)]
pub enum LookupDecision<'a, T> {
    Accepted(&'a T),
    Rejected,
    Reconcile,
}

/// All reads, including a missing row, require fresh caller comparison first.
/// The driver must execute the scoped lookup under actual current entitlement.
/// A historical receipt generation may differ after valid reauthorization, but
/// operation, actor, typed scope and payload must match the frozen RP02 contract.
pub fn resolve_lookup<'a, T>(
    request: &CommandEnvelope<()>,
    current: AuthorityKey,
    record: Option<&'a OperationRecord<T>>,
) -> Result<LookupDecision<'a, T>, ContractError> {
    request.validate(current, accepted_contract())?;
    let Some(record) = record else {
        return Ok(LookupDecision::Reconcile);
    };
    Ok(
        match record.lookup(request, current, accepted_contract())? {
            OperationResult::Accepted(value) => LookupDecision::Accepted(value),
            OperationResult::Rejected => LookupDecision::Rejected,
            OperationResult::Pending | OperationResult::Unknown => LookupDecision::Reconcile,
        },
    )
}
