//! Recording-specific transaction wrapper; does not use TransactionLifecycle's
//! unrelated hard-pinned command binding. No driver or external effects.
use setjoin_contracts::{
    authority::AuthorityKey,
    command::CommitObservation,
    content::{ReferenceDecision, ReferenceIntent, ReferenceState, VerifiedContentReceipt},
    error::ContractError,
    ids::*,
    recording::{
        staging_disposition, Publication, PublicationDecision, PublishRecording, RecordingFacts,
        RecordingState, StagingDisposition,
    },
};
use setjoin_db::lifecycle::ConnectionDisposition;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationKey {
    pub operation: OperationId,
    pub recording: RecordingId,
    pub intent: Digest,
    pub issuance: Generation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub key: OperationKey,
    pub publish: PublishRecording,
    pub reference_revision: Generation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Journal {
    pub input: Request,
    pub publication: Publication,
    pub at_micros: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Publish,
    Lookup,
    Observe,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Contract(ContractError),
    Conflict,
    Missing,
    Forbidden,
    InvalidGeneration,
    Storage,
}
impl From<ContractError> for Error {
    fn from(e: ContractError) -> Self {
        Self::Contract(e)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub key: OperationKey,
    pub digest: Digest,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Staged {
    Receipt(Journal),
    Reconcile,
    EvidenceRetained,
}
/// Store's response is trusted driver data, never caller-provided credentials.
pub struct Completion {
    pub observation: CommitObservation,
    pub staged: Result<Staged, Error>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub connection: ConnectionDisposition,
    pub receipt: Option<Journal>,
    pub staging: StagingDisposition,
    pub reconcile: bool,
    pub error: Option<Error>,
}

/// Implementations MUST begin a clean transaction and hold operation/recording
/// locks through commit. Errors roll back ALL writes. Final authorization/fence
/// must remain valid through commit; unknown outcomes quarantine the connection.
/// Acknowledged terminal responses require verified reset before pool reuse.
/// No external effect may be issued inside this interface.
pub trait RecordingStore {
    fn transact<F>(&mut self, key: OperationKey, f: F) -> Completion
    where
        F: FnOnce(&mut dyn RecordingTx) -> Result<Staged, Error>;
}
pub trait RecordingTx {
    /// Lookup by operation ID first; return original immutable full key. A changed
    /// digest/recording must not turn an existing operation into a missing row.
    fn operation(&mut self) -> Result<OperationKey, Error>;
    fn facts(&mut self) -> Result<RecordingFacts, Error>;
    /// Performs real current action authorization, then returns comparison key.
    /// Must not implement permission as self-equality or a public Boolean.
    fn authorize(&mut self, action: Action) -> Result<AuthorityKey, Error>;
    fn trusted_time(&mut self) -> Result<i64, Error>;
    fn journal(&mut self) -> Result<Option<Journal>, Error>;
    /// Persisted reconciliation flag under the same lock through commit. No
    /// implicit clearing; unresolved evidence suppresses publication and replay.
    fn reconciliation_required(&mut self) -> Result<bool, Error>;
    /// Trusted exact publication/issuance/actor/scope verification plus holds policy.
    fn verify_content(&mut self, request: Request) -> Result<VerifiedContentReceipt, Error>;
    /// Locked exact immutable reference identity and aggregate count.
    fn reference(&mut self, publication: Publication) -> Result<ReferenceState, Error>;
    /// Stage node/version/reference/Ready/journal/audit/event atomically. Any
    /// failure must abort the entire transaction, including intermediate writes.
    fn stage_publication(
        &mut self,
        journal: Journal,
        reference: ReferenceDecision,
    ) -> Result<(), Error>;
    /// Append immutable trusted evidence, preserving contradictory observations;
    /// set reconciliation-required and never auto-clear or settle publication.
    fn retain_evidence(&mut self, evidence: Evidence) -> Result<(), Error>;
    /// Rechecks current role, authority and capture/participant generations and
    /// holds the same fence through commit. Lookup checks authorization only.
    fn commit_fence(&mut self, request: Request, action: Action) -> Result<(), Error>;
}
fn validate(q: Request) -> Result<(), Error> {
    if q.key.operation.0 == [0; 16] || q.key.issuance.0 == 0 {
        return Err(Error::InvalidGeneration);
    }
    if q.key.recording != q.publish.publication.recording
        || q.key.issuance != q.publish.capture_generation
    {
        return Err(Error::Conflict);
    }
    for g in [
        q.key.issuance,
        q.publish.participant_generation,
        q.publish.authority.generation,
        q.publish.publication.content.verification_generation,
        q.reference_revision,
    ] {
        if g.0 > i64::MAX as u64 {
            return Err(Error::InvalidGeneration);
        }
    }
    Ok(())
}
fn finish(c: Completion) -> Outcome {
    let unknown = c.observation == CommitObservation::Unknown;
    let mut out = Outcome {
        connection: if unknown {
            ConnectionDisposition::Quarantine
        } else {
            ConnectionDisposition::VerifyDriverReset
        },
        receipt: None,
        staging: StagingDisposition::Keep,
        reconcile: unknown,
        error: None,
    };
    match c.observation {
        CommitObservation::Committed => match c.staged {
            Ok(Staged::Receipt(j)) => {
                out.receipt = Some(j);
                out.staging = staging_disposition(RecordingState::Ready, true, false);
            }
            Ok(Staged::Reconcile | Staged::EvidenceRetained) => out.reconcile = true,
            Err(e) => {
                out.error = Some(e);
                out.reconcile = true;
            }
        },
        CommitObservation::RolledBack => out.error = Some(c.staged.err().unwrap_or(Error::Storage)),
        CommitObservation::Unknown => {} // do not leak staged data or infer abort
    }
    out
}
fn execute<S: RecordingStore>(
    store: &mut S,
    q: Request,
    action: Action,
    evidence: Option<Evidence>,
) -> Outcome {
    finish(store.transact(q.key, |tx| {
        validate(q)?;
        let current = tx.authorize(action)?;
        q.publish.authority.check_current(current)?;
        match tx.operation() {
            Ok(key) if key == q.key => {}
            Err(Error::Missing) if action == Action::Lookup => {
                tx.commit_fence(q, action)?;
                return Ok(Staged::Reconcile);
            }
            Err(e) => return Err(e),
            _ => return Err(Error::Conflict),
        }
        if action == Action::Observe {
            let e = evidence.ok_or(Error::Missing)?;
            if e.key != q.key {
                return Err(Error::Conflict);
            }
            tx.retain_evidence(e)?;
            tx.commit_fence(q, action)?;
            return Ok(Staged::EvidenceRetained);
        }
        if tx.reconciliation_required()? {
            tx.commit_fence(q, action)?;
            return Ok(Staged::Reconcile);
        }
        let prior = tx.journal()?;
        if let Some(j) = prior {
            if j.input != q || j.publication != q.publish.publication {
                return Err(Error::Conflict);
            }
            tx.commit_fence(q, action)?;
            return Ok(Staged::Receipt(j));
        }
        if action == Action::Lookup {
            tx.commit_fence(q, action)?;
            return Ok(Staged::Reconcile);
        }
        let facts = tx.facts()?;
        let verified = tx.verify_content(q)?;
        match q.publish.plan(facts, current, verified)? {
            PublicationDecision::AlreadyAccepted(_) => {
                // Never synthesize a lost original receipt or reattach a reference.
                tx.commit_fence(q, action)?;
                Ok(Staged::Reconcile)
            }
            PublicationDecision::AtomicPublish(publication) => {
                let state = tx.reference(publication)?;
                let reference = state.plan(q.reference_revision, ReferenceIntent::Attach)?;
                if let ReferenceDecision::Replace(next) = reference {
                    if next.revision.0 > i64::MAX as u64 || next.shared_count > i64::MAX as u64 {
                        return Err(Error::InvalidGeneration);
                    }
                }
                let j = Journal {
                    input: q,
                    publication,
                    at_micros: tx.trusted_time()?,
                };
                tx.stage_publication(j, reference)?;
                tx.commit_fence(q, action)?;
                Ok(Staged::Receipt(j))
            }
        }
    }))
}
pub fn publish<S: RecordingStore>(store: &mut S, request: Request) -> Outcome {
    execute(store, request, Action::Publish, None)
}
/// Always uses a new clean transaction. Missing receipt is not resend permission.
pub fn lookup<S: RecordingStore>(store: &mut S, request: Request) -> Outcome {
    execute(store, request, Action::Lookup, None)
}
pub fn observe<S: RecordingStore>(store: &mut S, request: Request, evidence: Evidence) -> Outcome {
    execute(store, request, Action::Observe, Some(evidence))
}
