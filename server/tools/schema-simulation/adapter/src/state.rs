//! Synthetic, pure coordinator/startup model. All effects are descriptions only.
//! No credentials, I/O, runtime admission constructor or schema downgrade exists.
use schema_assessor::Identity;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationProvenance {
    Synthetic,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationGate {
    Open,
    Closed,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationObservation {
    Confirmed,
    Denied,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationAck {
    Committed,
    NotCommitted,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationKind {
    Update,
    ExecutableRollback,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationPhase {
    Stable,
    ClosePending,
    Closing,
    Quiescent,
    Migrating,
    Sealed,
    RollbackClosing,
    RollbackQuiescent,
    RollbackSealed,
    RecoveryRequired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationCode {
    Progress,
    Idempotent,
    StateTransitionInvalid,
    ReconciliationRequired,
    GenerationExhausted,
    ClosingOutcomeUnknown,
    ActorsNotQuiescent,
    OwnerConnectionOpen,
    OwnerConnectionUnknown,
    QualificationUnresolved,
    PublicationOutcomeUnknown,
    RecoveryRequired,
    RecoveryAuthorizationRequired,
    ObservationGenerationMismatch,
    EvidenceBindingMismatch,
    PostureUnknown,
    CompatiblePendingFence,
    FenceRetry,
    FenceRetryExhausted,
    StartupCancelled,
    SimulatedAdmissionOnly,
    GenerationChanged,
    EffectSimulatedOnly,
    AdvisoryReassessAtSafeBoundary,
}
impl SimulationCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Progress => "SIMULATION_PROGRESS",
            Self::Idempotent => "SIMULATION_IDEMPOTENT",
            Self::StateTransitionInvalid => "STATE_TRANSITION_INVALID",
            Self::ReconciliationRequired => "RECONCILIATION_REQUIRED",
            Self::GenerationExhausted => "GENERATION_EXHAUSTED",
            Self::ClosingOutcomeUnknown => "CLOSING_OUTCOME_UNKNOWN",
            Self::ActorsNotQuiescent => "ACTORS_NOT_QUIESCENT",
            Self::OwnerConnectionOpen => "OWNER_CONNECTION_OPEN",
            Self::OwnerConnectionUnknown => "OWNER_CONNECTION_UNKNOWN",
            Self::QualificationUnresolved => "QUALIFICATION_UNRESOLVED",
            Self::PublicationOutcomeUnknown => "PUBLICATION_OUTCOME_UNKNOWN",
            Self::RecoveryRequired => "RECOVERY_REQUIRED",
            Self::RecoveryAuthorizationRequired => "RECOVERY_AUTHORIZATION_REQUIRED",
            Self::ObservationGenerationMismatch => "OBSERVATION_GENERATION_MISMATCH",
            Self::EvidenceBindingMismatch => "EVIDENCE_BINDING_MISMATCH",
            Self::PostureUnknown => "POSTURE_UNKNOWN",
            Self::CompatiblePendingFence => "COMPATIBLE_PENDING_FENCE",
            Self::FenceRetry => "FENCE_RETRY",
            Self::FenceRetryExhausted => "FENCE_RETRY_EXHAUSTED",
            Self::StartupCancelled => "STARTUP_CANCELLED",
            Self::SimulatedAdmissionOnly => "SIMULATED_ADMISSION_ONLY",
            Self::GenerationChanged => "GENERATION_CHANGED",
            Self::EffectSimulatedOnly => "EFFECT_SIMULATED_ONLY",
            Self::AdvisoryReassessAtSafeBoundary => "ADVISORY_REASSESS_AT_SAFE_BOUNDARY",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationStateSnapshot {
    pub provenance: SimulationProvenance,
    pub phase: SimulationPhase,
    /// Authoritative generation; ClosePending keeps the source generation here.
    pub generation: u64,
    pub operation: Option<Identity>,
    pub seal: Identity,
    pub schema: Identity,
    pub binary: Identity,
    pub requested_gate: SimulationGate,
    pub observed_gate: SimulationGate,
    pub owner_closed: SimulationObservation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationGuard {
    pub provenance: SimulationProvenance,
    pub phase: SimulationPhase,
    pub generation: u64,
    pub operation: Option<Identity>,
}
impl SimulationStateSnapshot {
    pub fn guard(self) -> SimulationGuard {
        SimulationGuard {
            provenance: SimulationProvenance::Synthetic,
            phase: self.phase,
            generation: self.generation,
            operation: self.operation,
        }
    }
}
/// An injected approval fixture, never a claim of authenticated runtime authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationOperationApproval {
    pub provenance: SimulationProvenance,
    pub operation: Identity,
    pub decision_digest: Identity,
    pub kind: SimulationKind,
    pub target_binary: Identity,
    pub target_schema: Identity,
    pub target_seal: Identity,
    pub qualification: SimulationObservation,
    /// Rollback from recovery additionally needs exact prior reconciliation.
    pub source_reconciled: SimulationObservation,
}
/// Durable publication eligibility, persisted before emitting any close transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationClosePublication {
    Initial,
    PendingUnknown { event_digest: Identity },
    ProvenNotCommitted { event_digest: Identity },
}
impl SimulationClosePublication {
    pub fn event_digest(self) -> Option<Identity> {
        match self {
            Self::Initial => None,
            Self::PendingUnknown { event_digest } | Self::ProvenNotCommitted { event_digest } => {
                Some(event_digest)
            }
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationCloseEvidence {
    pub readback: SimulationReadback,
    pub publication_digest: Option<Identity>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationCloseIntent {
    pub provenance: SimulationProvenance,
    pub source: SimulationStateSnapshot,
    pub reserved_generation: u64,
    pub approval: SimulationOperationApproval,
    pub publication: SimulationClosePublication,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationReadback {
    Unknown,
    Conflicting,
    /// Exact equality includes operation, phase, generation, identities and gate intent.
    Committed(SimulationStateSnapshot),
    /// The unchanged predecessor AND authoritative absence of this operation/event.
    NotCommitted {
        predecessor: SimulationStateSnapshot,
        operation_absent: SimulationObservation,
    },
    /// A positively observed foreign state; enter recovery at that generation.
    Foreign(SimulationStateSnapshot),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationPublicationEvidence {
    pub provenance: SimulationProvenance,
    pub readback: SimulationReadback,
    pub event_digest: Identity,
    pub effect: SimulationEffect,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationSealProof {
    pub provenance: SimulationProvenance,
    pub generation: u64,
    pub operation: Identity,
    pub seal: Identity,
    pub schema: Identity,
    pub binary: Identity,
    pub descriptors: SimulationObservation,
    pub observations: SimulationObservation,
    pub ledger: SimulationObservation,
    pub qualification: SimulationObservation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationHealthProof {
    pub provenance: SimulationProvenance,
    pub generation: u64,
    pub operation: Identity,
    pub seal: Identity,
    pub fixed_cohort: Identity,
    pub fresh_admission: SimulationObservation,
    pub readiness: SimulationObservation,
    pub data_contract: SimulationObservation,
    pub postcommit: SimulationObservation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationRecoveryApproval {
    pub provenance: SimulationProvenance,
    pub operation: Identity,
    pub decision_digest: Identity,
    pub reconciliation: SimulationObservation,
    pub stopped_actors: SimulationObservation,
    pub owner_closed: SimulationObservation,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimulationCommand {
    Begin(SimulationOperationApproval),
    ObserveHostClosure(SimulationObservation),
    PublishClose(SimulationAck),
    ReconcileClose(SimulationCloseEvidence),
    ObserveDrain {
        actor_inventory: Identity,
        stop_receipts: Identity,
        result: SimulationObservation,
    },
    BeginMigration {
        approved_step: Identity,
    },
    MigrationStep {
        approved_step: Identity,
        ack: SimulationAck,
    },
    Seal {
        proof: SimulationSealProof,
        ack: SimulationAck,
    },
    ObserveOwnerClosed(SimulationObservation),
    StartCore {
        fixed_cohort: Identity,
    },
    Health(SimulationHealthProof),
    PublishStable(SimulationAck),
    SelectRollbackPointer {
        binary: Identity,
        profile: Identity,
        qualified: SimulationObservation,
        ack: SimulationAck,
    },
    SealRollback {
        proof: SimulationSealProof,
        ack: SimulationAck,
    },
    ReconcilePublication(Box<SimulationPublicationEvidence>),
    ResumeSealed {
        approval: SimulationRecoveryApproval,
        observed: SimulationStateSnapshot,
    },
    FailRequiredObservation,
    Cancel,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationEvent {
    pub provenance: SimulationProvenance,
    pub operation: Identity,
    pub event_id: Identity,
    pub event_digest: Identity,
    pub expected: SimulationGuard,
    pub command: SimulationCommand,
}
/// Audit-only retirement of an old publication under an injected, separately
/// approved source-reconciliation decision. This is not a fabricated commit ack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationPublicationRetirement {
    pub before: SimulationStateSnapshot,
    pub target: SimulationStateSnapshot,
    pub event_digest: Identity,
    pub effect: SimulationEffect,
    pub reconciled_source: SimulationStateSnapshot,
    pub successor_approval: SimulationOperationApproval,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimulationEffect {
    RetireReconciledPublication(Box<SimulationPublicationRetirement>),
    PersistCloseIntent(Box<SimulationCloseIntent>),
    RequestHostGateClosed,
    PublishControlExclusive {
        generation: u64,
        phase: SimulationPhase,
        operation: Identity,
    },
    ObserveOriginalCohort,
    BeginOwnerMigration {
        generation: u64,
        approved_step: Identity,
    },
    ApplyExpandOnlyStep {
        generation: u64,
        approved_step: Identity,
    },
    PublishOwnerSeal {
        generation: u64,
        seal: Identity,
    },
    SelectRetainedBinary {
        generation: u64,
        binary: Identity,
        profile: Identity,
    },
    StartIsolatedCore {
        generation: u64,
        seal: Identity,
        fixed_cohort: Identity,
    },
    RequestPublicGateOpen,
    StopOwnedCandidates,
    ReconcileExactOperation,
    BusinessSqlEffect {
        generation: u64,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationTransition {
    pub provenance: SimulationProvenance,
    pub code: SimulationCode,
    pub stage: &'static str,
    pub snapshot: SimulationStateSnapshot,
    pub close_intent: Option<SimulationCloseIntent>,
    pub effects: Vec<SimulationEffect>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingKind {
    Seal,
    Stable,
    Pointer,
    Migration,
}
#[derive(Clone, Debug)]
struct PendingPublication {
    before: SimulationStateSnapshot,
    target: SimulationStateSnapshot,
    kind: PendingKind,
    effect: SimulationEffect,
    event_digest: Identity,
}
/// All state is task-local model memory. Persistence effects must not be executed.
#[derive(Clone, Debug)]
pub struct SimulationCoordinator {
    snapshot: SimulationStateSnapshot,
    close_intent: Option<SimulationCloseIntent>,
    approval: Option<SimulationOperationApproval>,
    pending: Option<PendingPublication>,
    retry: Option<PendingPublication>,
    seen: BTreeMap<(Identity, Identity), SimulationEvent>,
    drain: Option<(Identity, Identity)>,
    cohort: Option<Identity>,
    healthy: bool,
    pointer_selected: bool,
}
impl SimulationCoordinator {
    /// A synthetic provisioned initial state; never infer this from missing rows.
    pub fn from_simulation_snapshot(
        snapshot: SimulationStateSnapshot,
    ) -> Result<Self, SimulationCode> {
        if snapshot.generation == 0
            || zero(snapshot.seal)
            || zero(snapshot.schema)
            || zero(snapshot.binary)
            || !matches!(
                snapshot.phase,
                SimulationPhase::Stable | SimulationPhase::RecoveryRequired
            )
            || (snapshot.phase == SimulationPhase::RecoveryRequired
                && (snapshot.requested_gate != SimulationGate::Closed
                    || snapshot.observed_gate == SimulationGate::Open))
        {
            return Err(SimulationCode::StateTransitionInvalid);
        }
        Ok(Self {
            snapshot,
            close_intent: None,
            approval: None,
            pending: None,
            retry: None,
            seen: BTreeMap::new(),
            drain: None,
            cohort: None,
            healthy: false,
            pointer_selected: false,
        })
    }
    /// Restart from a synthetic durable intent. No Stable/gate-open inference is allowed.
    pub fn from_simulation_close_intent(
        intent: SimulationCloseIntent,
        observed_gate: SimulationGate,
    ) -> Result<Self, SimulationCode> {
        if observed_gate == SimulationGate::Open
            || intent.source.generation.checked_add(1) != Some(intent.reserved_generation)
        {
            return Err(SimulationCode::StateTransitionInvalid);
        }
        let mut model = Self::from_simulation_snapshot(intent.source)?;
        let result = model.apply_command(
            &SimulationCommand::Begin(intent.approval),
            intent.approval.operation,
            intent.approval.decision_digest,
        );
        let initial_intent = SimulationCloseIntent {
            publication: SimulationClosePublication::Initial,
            ..intent
        };
        if result.close_intent != Some(initial_intent)
            || intent.publication.event_digest().is_some_and(zero)
        {
            return Err(SimulationCode::StateTransitionInvalid);
        }
        model.close_intent = Some(intent);
        model.snapshot.observed_gate = observed_gate;
        Ok(model)
    }
    pub fn simulation_snapshot(&self) -> SimulationStateSnapshot {
        self.snapshot
    }
    pub fn simulation_close_intent(&self) -> Option<SimulationCloseIntent> {
        self.close_intent
    }
    fn output(
        &self,
        code: SimulationCode,
        stage: &'static str,
        effects: Vec<SimulationEffect>,
    ) -> SimulationTransition {
        SimulationTransition {
            provenance: SimulationProvenance::Synthetic,
            code,
            stage,
            snapshot: self.snapshot,
            close_intent: self.close_intent,
            effects,
        }
    }
    fn invalid(&self) -> SimulationTransition {
        self.output(
            SimulationCode::StateTransitionInvalid,
            "coordinator.guard",
            vec![],
        )
    }
    fn recover(&mut self, code: SimulationCode) -> SimulationTransition {
        self.snapshot.phase = SimulationPhase::RecoveryRequired;
        self.snapshot.requested_gate = SimulationGate::Closed;
        // An unobserved close must never be fabricated here.
        self.cohort = None;
        self.healthy = false;
        self.output(
            code,
            "coordinator.recovery",
            vec![
                SimulationEffect::RequestHostGateClosed,
                SimulationEffect::StopOwnedCandidates,
                SimulationEffect::ReconcileExactOperation,
            ],
        )
    }
    /// Recovery changes only phase and requested gate. Pending state is usable
    /// only while that exact predecessor still owns the current generation.
    fn publication_is_current(&self, publication: &PendingPublication, recovery: bool) -> bool {
        let mut predecessor = publication.before;
        if recovery {
            predecessor.phase = SimulationPhase::RecoveryRequired;
            predecessor.requested_gate = SimulationGate::Closed;
        }
        predecessor == self.snapshot
            && self.approval.is_some_and(|approval| {
                Some(approval.operation) == self.snapshot.operation
                    && publication.before.operation == Some(approval.operation)
                    && publication.target.operation == Some(approval.operation)
            })
            && publication.before.generation == self.snapshot.generation
            && publication.target.generation == self.snapshot.generation
    }
    fn publish(
        &mut self,
        target: SimulationStateSnapshot,
        ack: SimulationAck,
        kind: PendingKind,
        effect: SimulationEffect,
        event_digest: Identity,
    ) -> SimulationTransition {
        if self.pending.is_some()
            || target.operation != self.snapshot.operation
            || target.generation != self.snapshot.generation
            || !self
                .approval
                .is_some_and(|approval| Some(approval.operation) == self.snapshot.operation)
        {
            return self.invalid();
        }
        if let Some(retry) = self.retry.as_ref()
            && (!self.publication_is_current(retry, false)
                || retry.before != self.snapshot
                || retry.target != target
                || retry.kind != kind
                || retry.effect != effect
                || retry.event_digest != event_digest)
        {
            return self.invalid();
        }
        self.retry = None;
        match ack {
            SimulationAck::Committed => {
                self.snapshot = target;
                let mut effects = vec![effect];
                if kind == PendingKind::Stable {
                    effects.push(SimulationEffect::RequestPublicGateOpen);
                }
                self.output(SimulationCode::Progress, "coordinator.publication", effects)
            }
            SimulationAck::NotCommitted | SimulationAck::Unknown => {
                self.pending = Some(PendingPublication {
                    before: self.snapshot,
                    target,
                    kind,
                    effect: effect.clone(),
                    event_digest,
                });
                let mut result = self.recover(SimulationCode::PublicationOutcomeUnknown);
                // Even a negative receipt requires exact reconciliation before retry.
                result.effects.insert(0, effect);
                result
            }
        }
    }
    /// Repeated identical events return no new effect, even after later transitions.
    /// Digest equality alone is insufficient: the entire persisted event must match.
    pub fn apply_simulation(&mut self, event: SimulationEvent) -> SimulationTransition {
        let key = (event.operation, event.event_id);
        if let Some(previous) = self.seen.get(&key) {
            return self.output(
                if previous == &event {
                    SimulationCode::Idempotent
                } else {
                    SimulationCode::ReconciliationRequired
                },
                "coordinator.idempotency",
                vec![],
            );
        }
        if zero(event.operation)
            || zero(event.event_id)
            || zero(event.event_digest)
            || event.expected != self.snapshot.guard()
            || (!matches!(&event.command, SimulationCommand::Begin(_))
                && self.snapshot.operation != Some(event.operation))
        {
            return self.invalid();
        }
        let result = self.apply_command(&event.command, event.operation, event.event_digest);
        // Denied/no-progress inputs are not acknowledgements and can be corrected.
        if !matches!(
            result.code,
            SimulationCode::StateTransitionInvalid
                | SimulationCode::OwnerConnectionOpen
                | SimulationCode::OwnerConnectionUnknown
                | SimulationCode::QualificationUnresolved
                | SimulationCode::RecoveryAuthorizationRequired
                | SimulationCode::GenerationExhausted
                | SimulationCode::ActorsNotQuiescent
        ) {
            self.seen.insert(key, event);
        }
        result
    }
    fn apply_command(
        &mut self,
        command: &SimulationCommand,
        operation: Identity,
        event_digest: Identity,
    ) -> SimulationTransition {
        use SimulationCommand as C;
        use SimulationPhase as P;
        match command.clone() {
            C::Begin(approval) => {
                if approval.operation != operation
                    || zero(approval.decision_digest)
                    || zero(approval.target_binary)
                    || zero(approval.target_schema)
                    || zero(approval.target_seal)
                    || !matches!(self.snapshot.phase, P::Stable | P::RecoveryRequired)
                    || (self.snapshot.phase == P::RecoveryRequired
                        && approval.kind != SimulationKind::ExecutableRollback)
                {
                    return self.invalid();
                }
                if approval.kind == SimulationKind::ExecutableRollback {
                    if approval.qualification != SimulationObservation::Confirmed {
                        return self.output(
                            SimulationCode::QualificationUnresolved,
                            "coordinator.rollback",
                            vec![],
                        );
                    }
                    if approval.target_schema != self.snapshot.schema {
                        return self.invalid();
                    }
                    if self.snapshot.phase == P::RecoveryRequired
                        && approval.source_reconciled != SimulationObservation::Confirmed
                    {
                        return self.output(
                            SimulationCode::RecoveryAuthorizationRequired,
                            "coordinator.rollback",
                            vec![],
                        );
                    }
                }
                let Some(reserved_generation) = self.snapshot.generation.checked_add(1) else {
                    return self.output(
                        SimulationCode::GenerationExhausted,
                        "coordinator.allocate",
                        vec![],
                    );
                };
                // A confirmed source reconciliation is the existing synthetic
                // authority for rollback from recovery. Retain an explicit audit
                // record; never carry an old executable pending/retry into the new op.
                let mut effects = vec![];
                for prior in self.pending.iter().chain(self.retry.iter()) {
                    if self.snapshot.phase != P::RecoveryRequired
                        || approval.kind != SimulationKind::ExecutableRollback
                        || approval.source_reconciled != SimulationObservation::Confirmed
                        || !self.publication_is_current(prior, true)
                    {
                        return self.output(
                            SimulationCode::ReconciliationRequired,
                            "coordinator.rollback",
                            vec![],
                        );
                    }
                    effects.push(SimulationEffect::RetireReconciledPublication(Box::new(
                        SimulationPublicationRetirement {
                            before: prior.before,
                            target: prior.target,
                            event_digest: prior.event_digest,
                            effect: prior.effect.clone(),
                            reconciled_source: self.snapshot,
                            successor_approval: approval,
                        },
                    )));
                }
                self.pending = None;
                self.retry = None;
                let intent = SimulationCloseIntent {
                    provenance: SimulationProvenance::Synthetic,
                    source: self.snapshot,
                    reserved_generation,
                    approval,
                    publication: SimulationClosePublication::Initial,
                };
                self.close_intent = Some(intent);
                self.approval = Some(approval);
                self.snapshot.phase = P::ClosePending;
                self.snapshot.operation = Some(operation);
                self.snapshot.requested_gate = SimulationGate::Closed;
                self.snapshot.observed_gate = SimulationGate::Unknown;
                self.drain = None;
                self.cohort = None;
                self.healthy = false;
                self.pointer_selected = false;
                effects.push(SimulationEffect::PersistCloseIntent(Box::new(intent)));
                effects.push(SimulationEffect::RequestHostGateClosed);
                self.output(
                    SimulationCode::ClosingOutcomeUnknown,
                    "coordinator.close",
                    effects,
                )
            }
            C::ObserveHostClosure(observation) if self.snapshot.phase == P::ClosePending => {
                self.snapshot.observed_gate = if observation == SimulationObservation::Confirmed {
                    SimulationGate::Closed
                } else {
                    SimulationGate::Unknown
                };
                self.output(
                    SimulationCode::ClosingOutcomeUnknown,
                    "coordinator.close",
                    vec![],
                )
            }
            C::PublishClose(ack) if self.snapshot.phase == P::ClosePending => {
                if self.snapshot.observed_gate != SimulationGate::Closed {
                    return self.invalid();
                }
                let Some(intent) = self.close_intent else {
                    return self.invalid();
                };
                match intent.publication {
                    SimulationClosePublication::PendingUnknown { .. } => {
                        return self.output(
                            SimulationCode::ClosingOutcomeUnknown,
                            "coordinator.close",
                            vec![],
                        );
                    }
                    SimulationClosePublication::ProvenNotCommitted {
                        event_digest: exact,
                    } if exact != event_digest => {
                        return self.invalid();
                    }
                    _ => {}
                }
                let attempted = SimulationCloseIntent {
                    publication: SimulationClosePublication::PendingUnknown { event_digest },
                    ..intent
                };
                self.close_intent = Some(attempted);
                let durable = SimulationEffect::PersistCloseIntent(Box::new(attempted));
                let target = self.close_target(intent);
                let effect = SimulationEffect::PublishControlExclusive {
                    generation: target.generation,
                    phase: target.phase,
                    operation,
                };
                if ack == SimulationAck::Committed {
                    self.snapshot = target;
                    self.close_intent = None;
                    self.output(
                        SimulationCode::Progress,
                        "coordinator.close",
                        vec![durable, effect, SimulationEffect::ObserveOriginalCohort],
                    )
                } else {
                    self.output(
                        SimulationCode::ClosingOutcomeUnknown,
                        "coordinator.close",
                        vec![durable, effect],
                    )
                }
            }
            C::ReconcileClose(evidence) if self.snapshot.phase == P::ClosePending => {
                let Some(intent) = self.close_intent else {
                    return self.invalid();
                };
                if evidence.publication_digest != intent.publication.event_digest() {
                    return self.invalid();
                }
                match evidence.readback {
                    SimulationReadback::Committed(observed)
                        if intent.publication.event_digest().is_some()
                            && observed == self.close_target(intent)
                            && self.snapshot.observed_gate == SimulationGate::Closed =>
                    {
                        self.snapshot = observed;
                        self.close_intent = None;
                        self.output(
                            SimulationCode::Progress,
                            "coordinator.close",
                            vec![SimulationEffect::ObserveOriginalCohort],
                        )
                    }
                    SimulationReadback::NotCommitted {
                        predecessor,
                        operation_absent,
                    } if predecessor == intent.source
                        && operation_absent == SimulationObservation::Confirmed =>
                    {
                        // Only authoritative absence releases this exact publication for retry.
                        let mut effects = vec![];
                        if let Some(event_digest) = intent.publication.event_digest() {
                            let retry = SimulationCloseIntent {
                                publication: SimulationClosePublication::ProvenNotCommitted {
                                    event_digest,
                                },
                                ..intent
                            };
                            self.close_intent = Some(retry);
                            effects.push(SimulationEffect::PersistCloseIntent(Box::new(retry)));
                        }
                        self.output(
                            SimulationCode::ClosingOutcomeUnknown,
                            "coordinator.close",
                            effects,
                        )
                    }
                    SimulationReadback::Foreign(observed)
                        if observed.generation >= intent.source.generation
                            && observed.generation != 0
                            && observed.phase != P::ClosePending
                            && !zero(observed.seal)
                            && !zero(observed.schema)
                            && !zero(observed.binary) =>
                    {
                        self.snapshot = observed;
                        self.snapshot.observed_gate = SimulationGate::Unknown;
                        self.close_intent = None;
                        self.approval = None;
                        self.pending = None;
                        self.retry = None;
                        self.recover(SimulationCode::RecoveryRequired)
                    }
                    _ => {
                        let mut effects = vec![];
                        if let SimulationClosePublication::ProvenNotCommitted { event_digest } =
                            intent.publication
                        {
                            let unresolved = SimulationCloseIntent {
                                publication: SimulationClosePublication::PendingUnknown {
                                    event_digest,
                                },
                                ..intent
                            };
                            self.close_intent = Some(unresolved);
                            effects
                                .push(SimulationEffect::PersistCloseIntent(Box::new(unresolved)));
                        }
                        self.output(
                            SimulationCode::ClosingOutcomeUnknown,
                            "coordinator.close",
                            effects,
                        )
                    }
                }
            }
            C::ObserveDrain {
                actor_inventory,
                stop_receipts,
                result,
            } if matches!(self.snapshot.phase, P::Closing | P::RollbackClosing) => {
                if result != SimulationObservation::Confirmed
                    || zero(actor_inventory)
                    || zero(stop_receipts)
                {
                    return self.output(
                        SimulationCode::ActorsNotQuiescent,
                        "coordinator.drain",
                        vec![],
                    );
                }
                self.drain = Some((actor_inventory, stop_receipts));
                self.snapshot.phase = if self.snapshot.phase == P::Closing {
                    P::Quiescent
                } else {
                    P::RollbackQuiescent
                };
                self.output(SimulationCode::Progress, "coordinator.drain", vec![])
            }
            C::BeginMigration { approved_step } if self.snapshot.phase == P::Quiescent => {
                if self.drain.is_none() || zero(approved_step) {
                    return self.invalid();
                }
                self.snapshot.phase = P::Migrating;
                self.snapshot.owner_closed = SimulationObservation::Denied;
                self.output(
                    SimulationCode::Progress,
                    "coordinator.migration",
                    vec![SimulationEffect::BeginOwnerMigration {
                        generation: self.snapshot.generation,
                        approved_step,
                    }],
                )
            }
            C::MigrationStep { approved_step, ack } if self.snapshot.phase == P::Migrating => {
                if zero(approved_step) {
                    return self.invalid();
                }
                self.publish(
                    self.snapshot,
                    ack,
                    PendingKind::Migration,
                    SimulationEffect::ApplyExpandOnlyStep {
                        generation: self.snapshot.generation,
                        approved_step,
                    },
                    event_digest,
                )
            }
            C::Seal { proof, ack } if self.snapshot.phase == P::Migrating => {
                if !self.valid_proof(proof) {
                    return self.recover(SimulationCode::QualificationUnresolved);
                }
                let target = self.sealed_target(proof, P::Sealed);
                self.publish(
                    target,
                    ack,
                    PendingKind::Seal,
                    SimulationEffect::PublishOwnerSeal {
                        generation: self.snapshot.generation,
                        seal: proof.seal,
                    },
                    event_digest,
                )
            }
            C::ObserveOwnerClosed(observed)
                if matches!(self.snapshot.phase, P::Sealed | P::RollbackSealed) =>
            {
                self.snapshot.owner_closed = observed;
                self.output(
                    match observed {
                        SimulationObservation::Confirmed => SimulationCode::Progress,
                        SimulationObservation::Denied => SimulationCode::OwnerConnectionOpen,
                        SimulationObservation::Unknown => SimulationCode::OwnerConnectionUnknown,
                    },
                    "coordinator.owner",
                    vec![],
                )
            }
            C::StartCore { fixed_cohort }
                if matches!(self.snapshot.phase, P::Sealed | P::RollbackSealed) =>
            {
                if self.snapshot.owner_closed != SimulationObservation::Confirmed {
                    return self.output(
                        if self.snapshot.owner_closed == SimulationObservation::Denied {
                            SimulationCode::OwnerConnectionOpen
                        } else {
                            SimulationCode::OwnerConnectionUnknown
                        },
                        "coordinator.owner",
                        vec![],
                    );
                }
                if zero(fixed_cohort) || self.cohort.is_some() {
                    return self.invalid();
                }
                self.cohort = Some(fixed_cohort);
                self.output(
                    SimulationCode::Progress,
                    "coordinator.health",
                    vec![SimulationEffect::StartIsolatedCore {
                        generation: self.snapshot.generation,
                        seal: self.snapshot.seal,
                        fixed_cohort,
                    }],
                )
            }
            C::Health(proof) if matches!(self.snapshot.phase, P::Sealed | P::RollbackSealed) => {
                if proof.generation != self.snapshot.generation
                    || Some(proof.operation) != self.snapshot.operation
                    || proof.seal != self.snapshot.seal
                    || Some(proof.fixed_cohort) != self.cohort
                    || [
                        proof.fresh_admission,
                        proof.readiness,
                        proof.data_contract,
                        proof.postcommit,
                    ]
                    .iter()
                    .any(|v| *v != SimulationObservation::Confirmed)
                {
                    return self.recover(SimulationCode::RecoveryRequired);
                }
                self.healthy = true;
                self.output(SimulationCode::Progress, "coordinator.health", vec![])
            }
            C::PublishStable(ack)
                if matches!(self.snapshot.phase, P::Sealed | P::RollbackSealed) =>
            {
                if !self.healthy || self.snapshot.owner_closed != SimulationObservation::Confirmed {
                    return self.invalid();
                }
                let mut target = self.snapshot;
                target.phase = P::Stable;
                target.requested_gate = SimulationGate::Open;
                // This is only an open request; no invented observed gate acknowledgement.
                self.publish(
                    target,
                    ack,
                    PendingKind::Stable,
                    SimulationEffect::PublishControlExclusive {
                        generation: self.snapshot.generation,
                        phase: P::Stable,
                        operation,
                    },
                    event_digest,
                )
            }
            C::SelectRollbackPointer {
                binary,
                profile,
                qualified,
                ack,
            } if self.snapshot.phase == P::RollbackQuiescent => {
                let Some(approval) = self.approval else {
                    return self.invalid();
                };
                if binary != approval.target_binary
                    || zero(profile)
                    || qualified != SimulationObservation::Confirmed
                {
                    return self.recover(SimulationCode::QualificationUnresolved);
                }
                let result = self.publish(
                    self.snapshot,
                    ack,
                    PendingKind::Pointer,
                    SimulationEffect::SelectRetainedBinary {
                        generation: self.snapshot.generation,
                        binary,
                        profile,
                    },
                    event_digest,
                );
                if result.code == SimulationCode::Progress && ack == SimulationAck::Committed {
                    self.pointer_selected = true;
                }
                result
            }
            C::SealRollback { proof, ack } if self.snapshot.phase == P::RollbackQuiescent => {
                if !self.pointer_selected
                    || !self.valid_proof(proof)
                    || proof.schema != self.snapshot.schema
                    || self.snapshot.owner_closed != SimulationObservation::Confirmed
                {
                    return self.recover(SimulationCode::QualificationUnresolved);
                }
                let target = self.sealed_target(proof, P::RollbackSealed);
                self.publish(
                    target,
                    ack,
                    PendingKind::Seal,
                    SimulationEffect::PublishControlExclusive {
                        generation: self.snapshot.generation,
                        phase: P::RollbackSealed,
                        operation,
                    },
                    event_digest,
                )
            }
            C::ReconcilePublication(evidence) if self.snapshot.phase == P::RecoveryRequired => {
                let Some(pending) = self.pending.clone() else {
                    return self.output(
                        SimulationCode::RecoveryRequired,
                        "coordinator.reconcile",
                        vec![],
                    );
                };
                if !self.publication_is_current(&pending, true)
                    || evidence.event_digest != pending.event_digest
                    || evidence.effect != pending.effect
                {
                    return self.output(
                        SimulationCode::RecoveryRequired,
                        "coordinator.reconcile",
                        vec![],
                    );
                }
                match evidence.readback {
                    SimulationReadback::Committed(observed) if observed == pending.target => {
                        self.snapshot = observed;
                        self.pending = None;
                        if pending.kind == PendingKind::Pointer {
                            self.pointer_selected = true;
                        }
                        // Sealed reconciliation does not restore stale startup/health receipts.
                        self.cohort = None;
                        self.healthy = false;
                        let effects = if pending.kind == PendingKind::Stable {
                            vec![SimulationEffect::RequestPublicGateOpen]
                        } else {
                            vec![]
                        };
                        self.output(SimulationCode::Progress, "coordinator.reconcile", effects)
                    }
                    SimulationReadback::NotCommitted {
                        predecessor,
                        operation_absent,
                    } if predecessor == pending.before
                        && operation_absent == SimulationObservation::Confirmed =>
                    {
                        self.snapshot = pending.before;
                        self.pending = None;
                        self.retry = Some(pending);
                        // Retrying Stable still needs fresh startup/health after recovery.
                        self.cohort = None;
                        self.healthy = false;
                        self.output(SimulationCode::Progress, "coordinator.reconcile", vec![])
                    }
                    _ => self.output(
                        SimulationCode::RecoveryRequired,
                        "coordinator.reconcile",
                        vec![],
                    ),
                }
            }
            C::ResumeSealed { approval, observed }
                if self.snapshot.phase == P::RecoveryRequired =>
            {
                let Some(target) = self.approval else {
                    return self.invalid();
                };
                if approval.operation != operation
                    || zero(approval.decision_digest)
                    || [
                        approval.reconciliation,
                        approval.stopped_actors,
                        approval.owner_closed,
                    ]
                    .iter()
                    .any(|v| *v != SimulationObservation::Confirmed)
                {
                    return self.output(
                        SimulationCode::RecoveryAuthorizationRequired,
                        "coordinator.recovery",
                        vec![],
                    );
                }
                let phase = if target.kind == SimulationKind::Update {
                    P::Sealed
                } else {
                    P::RollbackSealed
                };
                if observed.phase != phase
                    || observed.generation != self.snapshot.generation
                    || observed.operation != Some(operation)
                    || observed.seal != target.target_seal
                    || observed.schema != target.target_schema
                    || observed.binary != target.target_binary
                    || observed.owner_closed != SimulationObservation::Confirmed
                    || observed.requested_gate != SimulationGate::Closed
                    || observed.observed_gate != SimulationGate::Closed
                {
                    return self.output(
                        SimulationCode::RecoveryRequired,
                        "coordinator.recovery",
                        vec![],
                    );
                }
                self.snapshot = observed;
                self.pending = None;
                self.retry = None;
                self.cohort = None;
                self.healthy = false;
                self.output(SimulationCode::Progress, "coordinator.recovery", vec![])
            }
            C::FailRequiredObservation | C::Cancel => {
                if self.snapshot.phase == P::ClosePending {
                    // Local pending uncertainty keeps source/reservation, not guessed recovery g.
                    return self.output(
                        SimulationCode::ClosingOutcomeUnknown,
                        "coordinator.close",
                        vec![],
                    );
                }
                if self.snapshot.phase == P::Stable {
                    return self.invalid();
                }
                self.recover(if matches!(command, C::Cancel) {
                    SimulationCode::StartupCancelled
                } else {
                    SimulationCode::RecoveryRequired
                })
            }
            _ => self.invalid(),
        }
    }
    fn close_target(&self, intent: SimulationCloseIntent) -> SimulationStateSnapshot {
        let mut target = intent.source;
        target.phase = if intent.approval.kind == SimulationKind::Update {
            SimulationPhase::Closing
        } else {
            SimulationPhase::RollbackClosing
        };
        target.generation = intent.reserved_generation;
        target.operation = Some(intent.approval.operation);
        target.requested_gate = SimulationGate::Closed;
        target.observed_gate = SimulationGate::Closed;
        target
    }
    fn valid_proof(&self, proof: SimulationSealProof) -> bool {
        let Some(approval) = self.approval else {
            return false;
        };
        proof.generation == self.snapshot.generation
            && Some(proof.operation) == self.snapshot.operation
            && proof.seal == approval.target_seal
            && proof.schema == approval.target_schema
            && proof.binary == approval.target_binary
            && [
                proof.descriptors,
                proof.observations,
                proof.ledger,
                proof.qualification,
            ]
            .iter()
            .all(|v| *v == SimulationObservation::Confirmed)
    }
    fn sealed_target(
        &self,
        proof: SimulationSealProof,
        phase: SimulationPhase,
    ) -> SimulationStateSnapshot {
        let mut target = self.snapshot;
        target.phase = phase;
        target.schema = proof.schema;
        target.binary = proof.binary;
        target.seal = proof.seal;
        target
    }
}
fn zero(identity: Identity) -> bool {
    identity == [0; 32]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SimulationRole {
    Application,
    Worker,
    Coordinator,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationEnvelope {
    pub provenance: SimulationProvenance,
    pub installation: Identity,
    pub timeline: Identity,
    pub release_epoch: Identity,
    pub generation: u64,
    pub seal: Identity,
    pub attempt: u8,
    pub role: SimulationRole,
    pub source_contract: Identity,
}
impl SimulationEnvelope {
    fn same_attempt(self, other: Self) -> bool {
        self.installation == other.installation
            && self.timeline == other.timeline
            && self.release_epoch == other.release_epoch
            && self.generation == other.generation
            && self.seal == other.seal
            && self.attempt == other.attempt
            && self.source_contract == other.source_contract
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationRoleObservation {
    pub provenance: SimulationProvenance,
    pub before: SimulationEnvelope,
    pub after: SimulationEnvelope,
    pub complete: SimulationObservation,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationObservationBundle {
    pub provenance: SimulationProvenance,
    pub expected: SimulationEnvelope,
    pub required_roles: BTreeSet<SimulationRole>,
    pub observations: Vec<SimulationRoleObservation>,
}
/// A private model receipt. It has no runtime serialization or authority conversion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationAdmissionReceipt {
    provenance: SimulationProvenance,
    generation: u64,
    seal: Identity,
    installation: Identity,
    isolated_health_only: bool,
}
impl SimulationAdmissionReceipt {
    pub fn simulation_generation(self) -> u64 {
        self.generation
    }
    pub fn simulation_provenance(self) -> SimulationProvenance {
        self.provenance
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationStartupPhase {
    Cold,
    Probe,
    Assessed,
    PendingFence,
    SimulatedAdmitted,
    Cancelled,
    Exhausted,
    Refused,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationStartupResult {
    pub provenance: SimulationProvenance,
    pub code: SimulationCode,
    pub phase: SimulationStartupPhase,
    pub attempt: u8,
    pub elapsed_ms: u64,
    pub retained_observations: usize,
    pub receipt: Option<SimulationAdmissionReceipt>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationFenceObservation {
    pub provenance: SimulationProvenance,
    pub envelope: SimulationEnvelope,
    pub snapshot: SimulationStateSnapshot,
    pub shared_lock: SimulationObservation,
    pub evidence_current: SimulationObservation,
    pub observation_origin: SimulationObservation,
}
#[derive(Clone, Debug)]
pub struct SimulationStartup {
    phase: SimulationStartupPhase,
    attempt: u8,
    elapsed_ms: u64,
    attempt_elapsed_ms: u64,
    expected: Option<SimulationEnvelope>,
    fixed_roles: BTreeSet<SimulationRole>,
    observations: Vec<SimulationRoleObservation>,
    receipt: Option<SimulationAdmissionReceipt>,
    refusal: Option<SimulationCode>,
}
impl Default for SimulationStartup {
    fn default() -> Self {
        Self {
            phase: SimulationStartupPhase::Cold,
            attempt: 0,
            elapsed_ms: 0,
            attempt_elapsed_ms: 0,
            expected: None,
            fixed_roles: BTreeSet::new(),
            observations: vec![],
            receipt: None,
            refusal: None,
        }
    }
}
impl SimulationStartup {
    fn result(&self, code: SimulationCode) -> SimulationStartupResult {
        SimulationStartupResult {
            provenance: SimulationProvenance::Synthetic,
            code,
            phase: self.phase,
            attempt: self.attempt,
            elapsed_ms: self.elapsed_ms,
            retained_observations: self.observations.len(),
            receipt: self.receipt,
        }
    }
    fn terminal(&self) -> Option<SimulationCode> {
        match self.phase {
            SimulationStartupPhase::Cancelled => Some(SimulationCode::StartupCancelled),
            SimulationStartupPhase::Exhausted => Some(SimulationCode::FenceRetryExhausted),
            SimulationStartupPhase::Refused => self.refusal,
            _ => None,
        }
    }
    fn clear_facts(&mut self) {
        self.observations.clear();
        self.expected = None;
        self.receipt = None;
    }
    fn refuse(&mut self, code: SimulationCode) -> SimulationStartupResult {
        self.clear_facts();
        self.phase = SimulationStartupPhase::Refused;
        self.refusal = Some(code);
        self.result(code)
    }
    pub fn begin_simulation_attempt(
        &mut self,
        mut expected: SimulationEnvelope,
        required_roles: BTreeSet<SimulationRole>,
    ) -> SimulationStartupResult {
        if let Some(code) = self.terminal() {
            return self.result(code);
        }
        if self.phase != SimulationStartupPhase::Cold {
            return self.result(SimulationCode::StateTransitionInvalid);
        }
        if self.attempt >= 3 || self.elapsed_ms >= 15_000 {
            self.clear_facts();
            self.phase = SimulationStartupPhase::Exhausted;
            return self.result(SimulationCode::FenceRetryExhausted);
        }
        if expected.generation == 0
            || zero(expected.seal)
            || zero(expected.installation)
            || zero(expected.timeline)
            || zero(expected.release_epoch)
            || zero(expected.source_contract)
            || required_roles.is_empty()
            || (!self.fixed_roles.is_empty() && required_roles != self.fixed_roles)
        {
            return self.result(SimulationCode::StateTransitionInvalid);
        }
        self.attempt += 1;
        expected.attempt = self.attempt;
        self.attempt_elapsed_ms = 0;
        self.expected = Some(expected);
        self.fixed_roles = required_roles;
        self.observations.clear();
        self.phase = SimulationStartupPhase::Probe;
        self.result(SimulationCode::Progress)
    }
    /// Charges monotonic modeled time; no sleeping or wall clock is used.
    pub fn advance_simulation_time(&mut self, delta_ms: u64) -> SimulationStartupResult {
        if let Some(code) = self.terminal() {
            return self.result(code);
        }
        if matches!(
            self.phase,
            SimulationStartupPhase::Cold | SimulationStartupPhase::SimulatedAdmitted
        ) {
            return self.result(SimulationCode::StateTransitionInvalid);
        }
        let total = self.elapsed_ms.checked_add(delta_ms);
        let attempt = self.attempt_elapsed_ms.checked_add(delta_ms);
        self.elapsed_ms = total.unwrap_or(u64::MAX);
        self.attempt_elapsed_ms = attempt.unwrap_or(u64::MAX);
        if self.elapsed_ms >= 15_000 {
            self.clear_facts();
            self.phase = SimulationStartupPhase::Exhausted;
            return self.result(SimulationCode::FenceRetryExhausted);
        }
        if self.attempt_elapsed_ms > 5_000 {
            return self.retry_simulation();
        }
        self.result(SimulationCode::Progress)
    }
    pub fn collect_simulation(
        &mut self,
        bundle: SimulationObservationBundle,
    ) -> SimulationStartupResult {
        if let Some(code) = self.terminal() {
            return self.result(code);
        }
        if self.phase != SimulationStartupPhase::Probe {
            return self.result(SimulationCode::StateTransitionInvalid);
        }
        let Some(expected) = self.expected else {
            return self.result(SimulationCode::StateTransitionInvalid);
        };
        let binding_bad = |value: SimulationEnvelope| {
            value.installation != expected.installation
                || value.timeline != expected.timeline
                || value.release_epoch != expected.release_epoch
                || value.source_contract != expected.source_contract
        };
        let mut seen = BTreeSet::new();
        let code = if binding_bad(bundle.expected)
            || bundle
                .observations
                .iter()
                .any(|value| binding_bad(value.before) || binding_bad(value.after))
        {
            Some(SimulationCode::EvidenceBindingMismatch)
        } else if !expected.same_attempt(bundle.expected)
            || bundle.observations.iter().any(|value| {
                !expected.same_attempt(value.before)
                    || !expected.same_attempt(value.after)
                    || value.before.role != value.after.role
            })
        {
            Some(SimulationCode::ObservationGenerationMismatch)
        } else if bundle.required_roles != self.fixed_roles
            || bundle.observations.iter().any(|value| {
                !seen.insert(value.before.role)
                    || value.complete != SimulationObservation::Confirmed
            })
            || seen != self.fixed_roles
        {
            Some(SimulationCode::PostureUnknown)
        } else {
            None
        };
        if let Some(code) = code {
            if code == SimulationCode::ObservationGenerationMismatch {
                let retried = self.retry_simulation();
                return if retried.code == SimulationCode::FenceRetryExhausted {
                    retried
                } else {
                    self.result(code)
                };
            }
            return self.refuse(code);
        }
        self.observations = bundle.observations;
        self.phase = SimulationStartupPhase::Assessed;
        self.result(SimulationCode::CompatiblePendingFence)
    }
    /// A compatibility assessor success is injected; it never substitutes for fence proof.
    pub fn assess_simulation(
        &mut self,
        compatibility: SimulationObservation,
    ) -> SimulationStartupResult {
        if let Some(code) = self.terminal() {
            return self.result(code);
        }
        if self.phase != SimulationStartupPhase::Assessed {
            return self.result(SimulationCode::StateTransitionInvalid);
        }
        if compatibility != SimulationObservation::Confirmed {
            return self.refuse(SimulationCode::QualificationUnresolved);
        }
        self.phase = SimulationStartupPhase::PendingFence;
        self.result(SimulationCode::CompatiblePendingFence)
    }
    pub fn fence_simulation(
        &mut self,
        fence: Option<SimulationFenceObservation>,
    ) -> SimulationStartupResult {
        if let Some(code) = self.terminal() {
            return self.result(code);
        }
        if self.phase != SimulationStartupPhase::PendingFence {
            return self.result(SimulationCode::StateTransitionInvalid);
        }
        let Some(fence) = fence else {
            return self.result(SimulationCode::CompatiblePendingFence);
        };
        let Some(expected) = self.expected else {
            return self.result(SimulationCode::StateTransitionInvalid);
        };
        if fence.envelope.installation != expected.installation
            || fence.envelope.timeline != expected.timeline
            || fence.envelope.release_epoch != expected.release_epoch
            || fence.envelope.source_contract != expected.source_contract
        {
            return self.refuse(SimulationCode::EvidenceBindingMismatch);
        }
        if fence.shared_lock != SimulationObservation::Confirmed
            || !expected.same_attempt(fence.envelope)
            || fence.snapshot.generation != expected.generation
            || fence.snapshot.seal != expected.seal
        {
            return self.retry_simulation();
        }
        if fence.evidence_current != SimulationObservation::Confirmed
            || fence.observation_origin != SimulationObservation::Confirmed
        {
            return self.refuse(SimulationCode::QualificationUnresolved);
        }
        if fence.snapshot.owner_closed != SimulationObservation::Confirmed {
            return self.refuse(
                if fence.snapshot.owner_closed == SimulationObservation::Denied {
                    SimulationCode::OwnerConnectionOpen
                } else {
                    SimulationCode::OwnerConnectionUnknown
                },
            );
        }
        if !matches!(
            fence.snapshot.phase,
            SimulationPhase::Stable | SimulationPhase::Sealed | SimulationPhase::RollbackSealed
        ) {
            return self.refuse(SimulationCode::StateTransitionInvalid);
        }
        self.phase = SimulationStartupPhase::SimulatedAdmitted;
        self.receipt = Some(SimulationAdmissionReceipt {
            provenance: SimulationProvenance::Synthetic,
            generation: expected.generation,
            seal: expected.seal,
            installation: expected.installation,
            isolated_health_only: fence.snapshot.phase != SimulationPhase::Stable,
        });
        self.result(SimulationCode::SimulatedAdmissionOnly)
    }
    /// Only contention/generation change call this; failed evidence is not retried here.
    pub fn retry_simulation(&mut self) -> SimulationStartupResult {
        if let Some(code) = self.terminal() {
            return self.result(code);
        }
        if matches!(
            self.phase,
            SimulationStartupPhase::Cold | SimulationStartupPhase::SimulatedAdmitted
        ) {
            return self.result(SimulationCode::StateTransitionInvalid);
        }
        self.clear_facts();
        if self.attempt >= 3 || self.elapsed_ms >= 15_000 {
            self.phase = SimulationStartupPhase::Exhausted;
            self.result(SimulationCode::FenceRetryExhausted)
        } else {
            self.phase = SimulationStartupPhase::Cold;
            self.result(SimulationCode::FenceRetry)
        }
    }
    pub fn cancel_simulation(&mut self) -> SimulationStartupResult {
        self.clear_facts();
        self.phase = SimulationStartupPhase::Cancelled;
        self.result(SimulationCode::StartupCancelled)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationBusinessRequest {
    pub provenance: SimulationProvenance,
    pub receipt: SimulationAdmissionReceipt,
    pub current: SimulationStateSnapshot,
    pub installation: Identity,
    pub shared_lock: SimulationObservation,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationBusinessResult {
    pub provenance: SimulationProvenance,
    pub code: SimulationCode,
    pub effects: Vec<SimulationEffect>,
}
pub fn simulation_business_effect(request: SimulationBusinessRequest) -> SimulationBusinessResult {
    let code = if request.receipt.generation != request.current.generation
        || request.receipt.seal != request.current.seal
    {
        SimulationCode::GenerationChanged
    } else if request.receipt.installation != request.installation {
        SimulationCode::EvidenceBindingMismatch
    } else if request.shared_lock != SimulationObservation::Confirmed
        || request.receipt.isolated_health_only
        || request.current.phase != SimulationPhase::Stable
        || request.current.requested_gate != SimulationGate::Open
    {
        SimulationCode::StateTransitionInvalid
    } else {
        SimulationCode::EffectSimulatedOnly
    };
    SimulationBusinessResult {
        provenance: SimulationProvenance::Synthetic,
        code,
        effects: if code == SimulationCode::EffectSimulatedOnly {
            vec![SimulationEffect::BusinessSqlEffect {
                generation: request.current.generation,
            }]
        } else {
            vec![]
        },
    }
}
pub fn simulation_active_policy_withdrawal(
    _receipt: SimulationAdmissionReceipt,
) -> SimulationBusinessResult {
    SimulationBusinessResult {
        provenance: SimulationProvenance::Synthetic,
        code: SimulationCode::AdvisoryReassessAtSafeBoundary,
        effects: vec![],
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationRecoveryAccess {
    NoAuthorization,
    StatusOnly,
    EvidenceSnapshotAuthorized,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationActivationDecision {
    pub provenance: SimulationProvenance,
    pub separately_approved: SimulationObservation,
    pub root_and_reason: SimulationObservation,
    pub force_and_tty_policy: SimulationObservation,
    pub reconciliation: SimulationObservation,
    pub retained_binary: SimulationObservation,
    pub exact_profile: SimulationObservation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationRecoveryEligibility {
    pub provenance: SimulationProvenance,
    pub status_callable: bool,
    pub evidence_eligible: bool,
    pub evidence_is_write: bool,
    pub activation_eligible: bool,
    pub activation_grants_business_admission: bool,
}
/// Business outcome is intentionally irrelevant to independent local recovery access.
pub fn simulation_recovery_eligibility(
    _business_code: SimulationCode,
    access: SimulationRecoveryAccess,
    activation: Option<SimulationActivationDecision>,
) -> SimulationRecoveryEligibility {
    let evidence_eligible = access == SimulationRecoveryAccess::EvidenceSnapshotAuthorized;
    let activation_eligible = activation.is_some_and(|value| {
        [
            value.separately_approved,
            value.root_and_reason,
            value.force_and_tty_policy,
            value.reconciliation,
            value.retained_binary,
            value.exact_profile,
        ]
        .iter()
        .all(|v| *v == SimulationObservation::Confirmed)
    });
    SimulationRecoveryEligibility {
        provenance: SimulationProvenance::Synthetic,
        status_callable: true,
        evidence_eligible,
        evidence_is_write: evidence_eligible,
        activation_eligible,
        activation_grants_business_admission: false,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SimulationReportOutcome {
    SimulationOnly,
    SimulatedAdmissionOnly,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationReport {
    pub provenance: SimulationProvenance,
    pub code: SimulationCode,
    outcome: SimulationReportOutcome,
    pub database_generation: Option<u64>,
    pub admission: Option<SimulationAdmissionReceipt>,
}
impl SimulationReport {
    pub fn build_only(code: SimulationCode) -> Self {
        Self {
            provenance: SimulationProvenance::Synthetic,
            code,
            outcome: SimulationReportOutcome::SimulationOnly,
            database_generation: None,
            admission: None,
        }
    }
    pub fn from_simulation_startup(result: &SimulationStartupResult) -> Self {
        Self {
            provenance: SimulationProvenance::Synthetic,
            code: result.code,
            outcome: if result.receipt.is_some() {
                SimulationReportOutcome::SimulatedAdmissionOnly
            } else {
                SimulationReportOutcome::SimulationOnly
            },
            database_generation: result.receipt.map(|v| v.generation),
            admission: result.receipt,
        }
    }
    /// Fixed values only: no supplied debug string is emitted by this projection.
    pub fn simulation_projection(&self) -> String {
        format!(
            "provenance=synthetic;code={};outcome={}",
            self.code.as_str(),
            match self.outcome {
                SimulationReportOutcome::SimulationOnly => "simulation_only",
                SimulationReportOutcome::SimulatedAdmissionOnly => "SIMULATED_ADMISSION_ONLY",
            }
        )
    }
}
