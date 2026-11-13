use super::accepted_drain_adapter::*;
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommitObservation,
    content::{ReferenceDecision, ReferenceState, VerifiedContentReceipt},
    ids::*,
    recording::{
        Publication, PublishRecording, RecordingFacts, RecordingState, StagingDisposition,
    },
};
use setjoin_db::lifecycle::ConnectionDisposition;
#[derive(Clone)]
struct Tx {
    q: Request,
    facts: RecordingFacts,
    journal: Option<Journal>,
    reference: ReferenceState,
    missing: bool,
    allowed: bool,
    commit_allowed: bool,
    stale_commit: bool,
    verified: VerifiedContentReceipt,
    held_policy: bool,
    fail_at: usize,
    writes: Vec<&'static str>,
    evidence: Vec<Evidence>,
    reconcile: bool,
}
struct Store {
    tx: Tx,
    observation: CommitObservation,
    persist_unknown: bool,
    transactions: usize,
}
fn fixture() -> (Store, Request) {
    let actor = ActorId::new(1).unwrap();
    let space = SpaceId::new(2).unwrap();
    let recording = RecordingId::new(3).unwrap();
    let meeting = MeetingId::new(4).unwrap();
    let content = VerifiedContentReceipt {
        space,
        owner: actor,
        manifest_digest: Digest([1; 32]),
        whole_sha256: Digest([2; 32]),
        bytes: 9,
        verification_generation: Generation(1),
    };
    let publication = Publication {
        recording,
        node: NodeId::new(5).unwrap(),
        version: VersionId::new(6).unwrap(),
        content,
    };
    let q = Request {
        key: OperationKey {
            operation: OperationId([1; 16]),
            recording,
            intent: Digest([3; 32]),
            issuance: Generation(2),
        },
        publish: PublishRecording {
            meeting,
            publication,
            authority: AuthorityKey {
                actor,
                scope: ResourceScope::Drive(space),
                generation: Generation(3),
            },
            capture_generation: Generation(2),
            participant_generation: Generation(4),
        },
        reference_revision: Generation(0),
    };
    let tx = Tx {
        q,
        facts: RecordingFacts {
            recording,
            meeting,
            owner: actor,
            space,
            capture_generation: Generation(2),
            participant_generation: Generation(4),
            state: RecordingState::PendingIngest,
            accepted: None,
        },
        journal: None,
        reference: ReferenceState {
            revision: Generation(0),
            attached: false,
            shared_count: 0,
            held: false,
        },
        missing: false,
        allowed: true,
        commit_allowed: true,
        stale_commit: false,
        verified: content,
        held_policy: false,
        fail_at: usize::MAX,
        writes: vec![],
        evidence: vec![],
        reconcile: false,
    };
    (
        Store {
            tx,
            observation: CommitObservation::Committed,
            persist_unknown: false,
            transactions: 0,
        },
        q,
    )
}
impl RecordingTx for Tx {
    fn operation(&mut self) -> Result<OperationKey, Error> {
        if self.missing {
            Err(Error::Missing)
        } else {
            Ok(self.q.key)
        }
    }
    fn facts(&mut self) -> Result<RecordingFacts, Error> {
        Ok(self.facts)
    }
    fn authorize(&mut self, _: Action) -> Result<AuthorityKey, Error> {
        if self.allowed {
            Ok(self.q.publish.authority)
        } else {
            Err(Error::Forbidden)
        }
    }
    fn trusted_time(&mut self) -> Result<i64, Error> {
        Ok(123)
    }
    fn journal(&mut self) -> Result<Option<Journal>, Error> {
        Ok(self.journal)
    }
    fn reconciliation_required(&mut self) -> Result<bool, Error> {
        Ok(self.reconcile)
    }
    fn verify_content(&mut self, q: Request) -> Result<VerifiedContentReceipt, Error> {
        if self.held_policy || q.key != self.q.key {
            Err(Error::Forbidden)
        } else {
            Ok(self.verified)
        }
    }
    fn reference(&mut self, p: Publication) -> Result<ReferenceState, Error> {
        if p != self.q.publish.publication {
            Err(Error::Conflict)
        } else {
            Ok(self.reference)
        }
    }
    fn stage_publication(&mut self, j: Journal, r: ReferenceDecision) -> Result<(), Error> {
        for (i, name) in [
            "node",
            "version",
            "reference",
            "ready",
            "journal",
            "audit",
            "event",
        ]
        .into_iter()
        .enumerate()
        {
            self.writes.push(name);
            match name {
                "reference" => {
                    if let ReferenceDecision::Replace(n) = r {
                        self.reference = n
                    }
                }
                "ready" => {
                    self.facts.state = RecordingState::Ready;
                    self.facts.accepted = Some(j.publication)
                }
                "journal" => self.journal = Some(j),
                _ => {}
            }
            if self.fail_at == i {
                return Err(Error::Storage);
            }
        }
        Ok(())
    }
    fn retain_evidence(&mut self, e: Evidence) -> Result<(), Error> {
        if !self.evidence.contains(&e) {
            self.evidence.push(e)
        }
        self.reconcile = true;
        Ok(())
    }
    fn commit_fence(&mut self, q: Request, action: Action) -> Result<(), Error> {
        if !self.commit_allowed {
            return Err(Error::Forbidden);
        }
        if self.stale_commit {
            return Err(Error::Contract(
                setjoin_contracts::error::ContractError::StaleGeneration,
            ));
        }
        q.publish
            .authority
            .check_current(self.q.publish.authority)?;
        if action == Action::Publish
            && (q.publish.capture_generation != self.facts.capture_generation
                || q.publish.participant_generation != self.facts.participant_generation)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
impl RecordingStore for Store {
    fn transact<F>(&mut self, _: OperationKey, f: F) -> Completion
    where
        F: FnOnce(&mut dyn RecordingTx) -> Result<Staged, Error>,
    {
        self.transactions += 1;
        let mut staged = self.tx.clone();
        let result = f(&mut staged);
        if result.is_err() {
            return Completion {
                observation: CommitObservation::RolledBack,
                staged: result,
            };
        }
        if self.observation == CommitObservation::Committed
            || (self.observation == CommitObservation::Unknown && self.persist_unknown)
        {
            self.tx = staged
        }
        Completion {
            observation: self.observation,
            staged: result,
        }
    }
}
#[test]
fn known_commit_publishes_atomic_bundle_and_requires_reset() {
    let (mut s, q) = fixture();
    let o = publish(&mut s, q);
    assert_eq!(o.receipt.unwrap().publication, q.publish.publication);
    assert_eq!(o.connection, ConnectionDisposition::VerifyDriverReset);
    assert_eq!(o.staging, StagingDisposition::RemoveAfterAcceptedCommit);
    assert_eq!(s.tx.writes.len(), 7);
    assert_eq!(s.tx.reference.shared_count, 1);
}
#[test]
fn known_abort_suppresses_output_and_rolls_back() {
    let (mut s, q) = fixture();
    s.observation = CommitObservation::RolledBack;
    let o = publish(&mut s, q);
    assert!(o.receipt.is_none());
    assert!(!o.reconcile);
    assert_eq!(o.staging, StagingDisposition::Keep);
    assert_eq!(o.connection, ConnectionDisposition::VerifyDriverReset);
    assert!(s.tx.writes.is_empty());
}
#[test]
fn unknown_commit_both_persistence_outcomes_require_clean_lookup() {
    for persisted in [false, true] {
        let (mut s, q) = fixture();
        s.observation = CommitObservation::Unknown;
        s.persist_unknown = persisted;
        let o = publish(&mut s, q);
        assert!(o.receipt.is_none() && o.reconcile);
        assert_eq!(o.staging, StagingDisposition::Keep);
        assert_eq!(o.connection, ConnectionDisposition::Quarantine);
        s.observation = CommitObservation::Committed;
        let recovered = lookup(&mut s, q);
        assert_eq!(s.transactions, 2);
        assert_eq!(recovered.receipt.is_some(), persisted);
        assert_eq!(recovered.reconcile, !persisted);
        assert_eq!(s.tx.writes.len(), if persisted { 7 } else { 0 });
    }
}
#[test]
fn changed_input_and_original_operation_key_refused() {
    let (mut s, q) = fixture();
    publish(&mut s, q);
    for kind in 0..3 {
        let mut bad = q;
        match kind {
            0 => bad.key.intent = Digest([9; 32]),
            1 => bad.publish.publication.version = VersionId::new(88).unwrap(),
            _ => bad.reference_revision = Generation(8),
        }
        let o = publish(&mut s, bad);
        assert!(o.receipt.is_none() && o.error.is_some());
    }
    assert_eq!(s.tx.journal.unwrap().input, q);
    assert_eq!(s.tx.reference.shared_count, 1);
}
#[test]
fn lookup_revocation_refuses_original_receipt() {
    let (mut s, q) = fixture();
    publish(&mut s, q);
    s.tx.allowed = false;
    let o = lookup(&mut s, q);
    assert!(o.receipt.is_none());
    assert_eq!(o.error, Some(Error::Forbidden));
}
#[test]
fn current_role_and_generation_rechecked_at_commit() {
    for stale in [false, true] {
        let (mut s, q) = fixture();
        s.tx.commit_allowed = stale;
        s.tx.stale_commit = stale;
        let o = publish(&mut s, q);
        assert!(o.error.is_some() && o.receipt.is_none());
        assert!(s.tx.writes.is_empty());
        assert_eq!(s.tx.facts.state, RecordingState::PendingIngest);
    }
}
#[test]
fn each_partial_mutation_audit_event_failure_rolls_back_everything() {
    for point in 0..7 {
        let (mut s, q) = fixture();
        s.tx.fail_at = point;
        let o = publish(&mut s, q);
        assert!(o.error.is_some());
        assert!(s.tx.writes.is_empty());
        assert!(s.tx.journal.is_none());
        assert_eq!(s.tx.reference.shared_count, 0);
        assert_eq!(s.tx.facts.state, RecordingState::PendingIngest);
    }
}
#[test]
fn mismatched_verification_scope_actor_generations_and_hold_refused() {
    for kind in 0..7 {
        let (mut s, q) = fixture();
        match kind {
            0 => s.tx.verified.bytes += 1,
            1 => s.tx.facts.space = SpaceId::new(90).unwrap(),
            2 => s.tx.facts.owner = ActorId::new(90).unwrap(),
            3 => s.tx.facts.capture_generation = Generation(91),
            4 => s.tx.facts.participant_generation = Generation(91),
            5 => s.tx.held_policy = true,
            _ => s.tx.reference.revision = Generation(91),
        }
        assert!(publish(&mut s, q).receipt.is_none());
        assert!(s.tx.writes.is_empty());
    }
}
#[test]
fn accepted_replay_never_reattaches_or_reverifies() {
    let (mut s, q) = fixture();
    let original = publish(&mut s, q).receipt;
    s.tx.held_policy = true;
    let replay = publish(&mut s, q);
    assert_eq!(replay.receipt, original);
    assert_eq!(s.tx.reference.shared_count, 1);
    assert_eq!(s.tx.writes.len(), 7);
}
#[test]
fn ready_without_original_journal_requires_reconciliation() {
    let (mut s, q) = fixture();
    s.tx.facts.state = RecordingState::Ready;
    s.tx.facts.accepted = Some(q.publish.publication);
    let o = publish(&mut s, q);
    assert!(o.reconcile && o.receipt.is_none());
    assert!(s.tx.writes.is_empty());
}
#[test]
fn contradictory_evidence_retained_without_settlement_or_new_issuance() {
    let (mut s, q) = fixture();
    for n in [1, 2, 1] {
        let o = observe(
            &mut s,
            q,
            Evidence {
                key: q.key,
                digest: Digest([n; 32]),
            },
        );
        assert!(o.reconcile && o.receipt.is_none());
        assert_eq!(o.staging, StagingDisposition::Keep);
    }
    assert_eq!(s.tx.evidence.len(), 2);
    assert!(s.tx.reconcile);
    assert!(s.tx.writes.is_empty());
    assert_eq!(s.tx.facts.state, RecordingState::PendingIngest);
}
#[test]
fn foreign_evidence_and_bigint_overflow_fail_closed() {
    let (mut s, q) = fixture();
    let mut key = q.key;
    key.issuance = Generation(99);
    assert!(observe(
        &mut s,
        q,
        Evidence {
            key,
            digest: Digest([1; 32])
        }
    )
    .error
    .is_some());
    let mut bad = q;
    bad.reference_revision = Generation(u64::MAX);
    assert_eq!(publish(&mut s, bad).error, Some(Error::InvalidGeneration));
    assert!(s.tx.evidence.is_empty() && s.tx.writes.is_empty());
}

#[test]
fn missing_operation_lookup_is_authorized_reconciliation() {
    let (mut s, q) = fixture();
    s.tx.missing = true;
    let o = lookup(&mut s, q);
    assert!(o.reconcile && o.receipt.is_none());
    s.tx.allowed = false;
    assert_eq!(lookup(&mut s, q).error, Some(Error::Forbidden));
}

#[test]
fn contradiction_before_publication_blocks_publish_and_lookup() {
    let (mut s, q) = fixture();
    for n in [1, 2] {
        observe(
            &mut s,
            q,
            Evidence {
                key: q.key,
                digest: Digest([n; 32]),
            },
        );
    }
    for o in [publish(&mut s, q), lookup(&mut s, q)] {
        assert!(o.reconcile && o.receipt.is_none());
        assert_eq!(o.staging, StagingDisposition::Keep);
    }
    assert!(s.tx.writes.is_empty() && s.tx.journal.is_none());
    assert_eq!(s.tx.evidence.len(), 2);
    assert!(s.tx.reconcile);
}
#[test]
fn contradiction_after_acceptance_preserves_receipt_but_suppresses_replay_cleanup() {
    let (mut s, q) = fixture();
    let original = publish(&mut s, q).receipt;
    for n in [1, 2] {
        observe(
            &mut s,
            q,
            Evidence {
                key: q.key,
                digest: Digest([n; 32]),
            },
        );
    }
    for o in [publish(&mut s, q), lookup(&mut s, q)] {
        assert!(o.reconcile && o.receipt.is_none());
        assert_eq!(o.staging, StagingDisposition::Keep);
    }
    assert_eq!(s.tx.journal, original);
    assert_eq!(s.tx.facts.state, RecordingState::Ready);
    assert_eq!(s.tx.reference.shared_count, 1);
    assert_eq!(s.tx.evidence.len(), 2);
    assert_eq!(s.tx.writes.len(), 7);
}
#[test]
fn ambiguous_evidence_flag_commit_tracks_both_persistence_outcomes() {
    for persisted in [false, true] {
        let (mut s, q) = fixture();
        publish(&mut s, q);
        s.observation = CommitObservation::Unknown;
        s.persist_unknown = persisted;
        let o = observe(
            &mut s,
            q,
            Evidence {
                key: q.key,
                digest: Digest([9; 32]),
            },
        );
        assert!(o.reconcile && o.receipt.is_none());
        assert_eq!(o.connection, ConnectionDisposition::Quarantine);
        assert_eq!(s.tx.reconcile, persisted);
        assert_eq!(s.tx.evidence.len(), usize::from(persisted));
        s.observation = CommitObservation::Committed;
        let o = lookup(&mut s, q);
        assert_eq!(o.reconcile, persisted);
        assert_eq!(o.receipt.is_some(), !persisted);
    }
}
#[test]
fn evidence_and_flag_rollback_together_on_abort_and_fence_failure() {
    for fence in [false, true] {
        let (mut s, q) = fixture();
        publish(&mut s, q);
        if fence {
            s.tx.commit_allowed = false
        } else {
            s.observation = CommitObservation::RolledBack
        }
        let o = observe(
            &mut s,
            q,
            Evidence {
                key: q.key,
                digest: Digest([9; 32]),
            },
        );
        assert!(o.receipt.is_none() && o.error.is_some());
        assert!(!s.tx.reconcile && s.tx.evidence.is_empty());
        assert!(s.tx.journal.is_some());
    }
}
#[test]
fn zero_operation_and_zero_original_issuance_refused() {
    for zero_operation in [false, true] {
        let (mut s, mut q) = fixture();
        if zero_operation {
            q.key.operation = OperationId([0; 16])
        } else {
            q.key.issuance = Generation(0);
            q.publish.capture_generation = Generation(0)
        }
        s.tx.q = q;
        assert_eq!(publish(&mut s, q).error, Some(Error::InvalidGeneration));
        assert!(s.tx.writes.is_empty());
    }
}
