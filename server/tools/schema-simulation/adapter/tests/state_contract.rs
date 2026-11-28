//! Independently written transition expectations for STATE.md. Source only until
//! root admits a frozen execution recipe; every input here is explicitly synthetic.
use schema_adapter_simulation::state::*;
use std::collections::BTreeSet;

const S: SimulationProvenance = SimulationProvenance::Synthetic;
const YES: SimulationObservation = SimulationObservation::Confirmed;
const NO: SimulationObservation = SimulationObservation::Denied;
const UNKNOWN: SimulationObservation = SimulationObservation::Unknown;
const OP: [u8; 32] = [31; 32];
const OP2: [u8; 32] = [32; 32];
const SEAL1: [u8; 32] = [11; 32];
const SEAL2: [u8; 32] = [12; 32];
const S1: [u8; 32] = [21; 32];
const S2: [u8; 32] = [22; 32];
const B1: [u8; 32] = [41; 32];
const B2: [u8; 32] = [42; 32];
const COHORT: [u8; 32] = [61; 32];

fn initial(generation: u64) -> SimulationStateSnapshot {
    SimulationStateSnapshot {
        provenance: S,
        phase: SimulationPhase::Stable,
        generation,
        operation: None,
        seal: SEAL1,
        schema: S1,
        binary: B1,
        requested_gate: SimulationGate::Open,
        observed_gate: SimulationGate::Open,
        owner_closed: YES,
    }
}
fn update() -> SimulationOperationApproval {
    SimulationOperationApproval {
        provenance: S,
        operation: OP,
        decision_digest: [51; 32],
        kind: SimulationKind::Update,
        target_binary: B2,
        target_schema: S2,
        target_seal: SEAL2,
        qualification: YES,
        source_reconciled: YES,
    }
}
fn rollback(schema: [u8; 32]) -> SimulationOperationApproval {
    SimulationOperationApproval {
        provenance: S,
        operation: OP2,
        decision_digest: [52; 32],
        kind: SimulationKind::ExecutableRollback,
        target_binary: B1,
        target_schema: schema,
        target_seal: [13; 32],
        qualification: YES,
        source_reconciled: YES,
    }
}
struct Driver {
    model: SimulationCoordinator,
    serial: u8,
    publication: Option<([u8; 32], SimulationEffect)>,
}
impl Driver {
    fn new(g: u64) -> Self {
        Self {
            model: SimulationCoordinator::from_simulation_snapshot(initial(g)).unwrap(),
            serial: 80,
            publication: None,
        }
    }
    fn snapshot(&self) -> SimulationStateSnapshot {
        self.model.simulation_snapshot()
    }
    fn event(&mut self, command: SimulationCommand) -> SimulationEvent {
        self.serial += 1;
        let state = self.snapshot();
        let effect = match command {
            SimulationCommand::PublishClose(_) if state.phase == SimulationPhase::ClosePending => {
                let intent = self.model.simulation_close_intent().unwrap();
                Some(SimulationEffect::PublishControlExclusive {
                    generation: intent.reserved_generation,
                    phase: if intent.approval.kind == SimulationKind::Update {
                        SimulationPhase::Closing
                    } else {
                        SimulationPhase::RollbackClosing
                    },
                    operation: intent.approval.operation,
                })
            }
            SimulationCommand::MigrationStep { approved_step, .. }
                if state.phase == SimulationPhase::Migrating =>
            {
                Some(SimulationEffect::ApplyExpandOnlyStep {
                    generation: state.generation,
                    approved_step,
                })
            }
            SimulationCommand::Seal { proof, .. } if state.phase == SimulationPhase::Migrating => {
                Some(SimulationEffect::PublishOwnerSeal {
                    generation: state.generation,
                    seal: proof.seal,
                })
            }
            SimulationCommand::PublishStable(_)
                if matches!(
                    state.phase,
                    SimulationPhase::Sealed | SimulationPhase::RollbackSealed
                ) =>
            {
                Some(SimulationEffect::PublishControlExclusive {
                    generation: state.generation,
                    phase: SimulationPhase::Stable,
                    operation: state.operation.unwrap(),
                })
            }
            SimulationCommand::SelectRollbackPointer {
                binary, profile, ..
            } if state.phase == SimulationPhase::RollbackQuiescent => {
                Some(SimulationEffect::SelectRetainedBinary {
                    generation: state.generation,
                    binary,
                    profile,
                })
            }
            SimulationCommand::SealRollback { .. }
                if state.phase == SimulationPhase::RollbackQuiescent =>
            {
                Some(SimulationEffect::PublishControlExclusive {
                    generation: state.generation,
                    phase: SimulationPhase::RollbackSealed,
                    operation: state.operation.unwrap(),
                })
            }
            _ => None,
        };
        let event_digest = if let Some(effect) = effect {
            let digest = self
                .publication
                .as_ref()
                .filter(|(_, previous)| previous == &effect)
                .map(|v| v.0)
                .unwrap_or([self.serial; 32]);
            self.publication = Some((digest, effect));
            digest
        } else {
            [self.serial; 32]
        };
        SimulationEvent {
            provenance: S,
            operation: match &command {
                SimulationCommand::Begin(a) => a.operation,
                _ => self.snapshot().operation.unwrap_or(OP),
            },
            event_id: [self.serial; 32],
            event_digest,
            expected: self.snapshot().guard(),
            command,
        }
    }
    fn reconcile_close(&self, readback: SimulationReadback) -> SimulationCommand {
        SimulationCommand::ReconcileClose(SimulationCloseEvidence {
            readback,
            publication_digest: self
                .model
                .simulation_close_intent()
                .unwrap()
                .publication
                .event_digest(),
        })
    }
    fn reconcile(&self, readback: SimulationReadback) -> SimulationCommand {
        let (event_digest, effect) = self.publication.as_ref().unwrap();
        SimulationCommand::ReconcilePublication(Box::new(SimulationPublicationEvidence {
            provenance: S,
            readback,
            event_digest: *event_digest,
            effect: effect.clone(),
        }))
    }
    fn act(&mut self, command: SimulationCommand) -> SimulationTransition {
        let event = self.event(command);
        self.model.apply_simulation(event)
    }
    fn close(&mut self, approval: SimulationOperationApproval) {
        assert_eq!(
            self.act(SimulationCommand::Begin(approval)).code,
            SimulationCode::ClosingOutcomeUnknown
        );
        self.act(SimulationCommand::ObserveHostClosure(YES));
        assert_eq!(
            self.act(SimulationCommand::PublishClose(SimulationAck::Committed))
                .code,
            SimulationCode::Progress
        );
    }
    fn drain(&mut self) {
        assert_eq!(
            self.act(SimulationCommand::ObserveDrain {
                actor_inventory: [71; 32],
                stop_receipts: [72; 32],
                result: YES
            })
            .code,
            SimulationCode::Progress
        );
    }
    fn migrate(&mut self) {
        self.close(update());
        self.drain();
        assert_eq!(
            self.act(SimulationCommand::BeginMigration {
                approved_step: [73; 32]
            })
            .code,
            SimulationCode::Progress
        );
    }
    fn seal(&mut self) {
        self.migrate();
        assert_eq!(
            self.act(SimulationCommand::MigrationStep {
                approved_step: [74; 32],
                ack: SimulationAck::Committed
            })
            .code,
            SimulationCode::Progress
        );
        assert_eq!(
            self.act(SimulationCommand::Seal {
                proof: seal_proof(self.snapshot(), update()),
                ack: SimulationAck::Committed
            })
            .code,
            SimulationCode::Progress
        );
    }
    fn health(&mut self) {
        assert_eq!(
            self.act(SimulationCommand::StartCore {
                fixed_cohort: COHORT
            })
            .code,
            SimulationCode::Progress
        );
        let p = health_proof(self.snapshot());
        assert_eq!(
            self.act(SimulationCommand::Health(p)).code,
            SimulationCode::Progress
        );
    }
}
fn seal_proof(
    snapshot: SimulationStateSnapshot,
    approval: SimulationOperationApproval,
) -> SimulationSealProof {
    SimulationSealProof {
        provenance: S,
        generation: snapshot.generation,
        operation: approval.operation,
        seal: approval.target_seal,
        schema: approval.target_schema,
        binary: approval.target_binary,
        descriptors: YES,
        observations: YES,
        ledger: YES,
        qualification: YES,
    }
}
fn health_proof(snapshot: SimulationStateSnapshot) -> SimulationHealthProof {
    SimulationHealthProof {
        provenance: S,
        generation: snapshot.generation,
        operation: snapshot.operation.unwrap(),
        seal: snapshot.seal,
        fixed_cohort: COHORT,
        fresh_admission: YES,
        readiness: YES,
        data_contract: YES,
        postcommit: YES,
    }
}
fn assert_no_open_or_start(result: &SimulationTransition) {
    assert!(
        !result.effects.iter().any(|effect| matches!(
            effect,
            SimulationEffect::RequestPublicGateOpen
                | SimulationEffect::StartIsolatedCore { .. }
                | SimulationEffect::BeginOwnerMigration { .. }
                | SimulationEffect::ApplyExpandOnlyStep { .. }
                | SimulationEffect::SelectRetainedBinary { .. }
        )),
        "uncertainty cannot authorize next effect"
    );
    assert_ne!(
        result.snapshot.requested_gate,
        SimulationGate::Open,
        "ST08 requested gate must stay closed"
    );
}

#[test]
fn sealed_to_stable() {
    let mut d = Driver::new(1);
    d.seal();
    assert_eq!(d.snapshot().phase, SimulationPhase::Sealed);
    assert_eq!(d.snapshot().generation, 2);
    assert_eq!(d.snapshot().schema, S2);
    assert_eq!(d.snapshot().owner_closed, NO);
    let denied = d.act(SimulationCommand::StartCore {
        fixed_cohort: COHORT,
    });
    assert_eq!(
        denied.code,
        SimulationCode::OwnerConnectionOpen,
        "ST01 owner-open must forbid StartCore"
    );
    assert!(
        denied.effects.is_empty(),
        "ST01 owner-open must emit no StartCore"
    );
    d.act(SimulationCommand::ObserveOwnerClosed(UNKNOWN));
    assert_eq!(
        d.act(SimulationCommand::StartCore {
            fixed_cohort: COHORT
        })
        .code,
        SimulationCode::OwnerConnectionUnknown
    );
    d.act(SimulationCommand::ObserveOwnerClosed(YES));
    assert!(
        d.act(SimulationCommand::PublishStable(SimulationAck::Committed))
            .effects
            .is_empty(),
        "ST01 health is mandatory"
    );
    d.health();
    let stable = d.act(SimulationCommand::PublishStable(SimulationAck::Committed));
    assert_eq!(stable.snapshot.phase, SimulationPhase::Stable);
    assert_eq!(stable.snapshot.generation, 2);
    assert_eq!(
        stable.effects,
        vec![
            SimulationEffect::PublishControlExclusive {
                generation: 2,
                phase: SimulationPhase::Stable,
                operation: OP
            },
            SimulationEffect::RequestPublicGateOpen
        ]
    );
    assert_eq!(
        stable.snapshot.owner_closed, YES,
        "control publication never reopens owner"
    );
    assert_eq!(
        stable.snapshot.observed_gate,
        SimulationGate::Closed,
        "open request is not observed open"
    );
}

#[test]
fn recovery_and_rollback() {
    let mut d = Driver::new(1);
    d.migrate();
    let lost = d.act(SimulationCommand::MigrationStep {
        approved_step: [74; 32],
        ack: SimulationAck::Unknown,
    });
    assert_eq!(lost.snapshot.phase, SimulationPhase::RecoveryRequired);
    assert_eq!(lost.snapshot.generation, 2);
    assert_eq!(
        d.act(SimulationCommand::MigrationStep {
            approved_step: [74; 32],
            ack: SimulationAck::Committed
        })
        .code,
        SimulationCode::StateTransitionInvalid,
        "ST02 no blind migration replay"
    );
    assert_no_open_or_start(&d.act(d.reconcile(SimulationReadback::Unknown)));
    let mut observed = d.snapshot();
    observed.phase = SimulationPhase::Sealed;
    observed.schema = S2;
    observed.binary = B2;
    observed.seal = SEAL2;
    observed.owner_closed = YES;
    observed.observed_gate = SimulationGate::Closed;
    let authorization = SimulationRecoveryApproval {
        provenance: S,
        operation: OP,
        decision_digest: [53; 32],
        reconciliation: YES,
        stopped_actors: YES,
        owner_closed: YES,
    };
    let mut absent = authorization;
    absent.reconciliation = UNKNOWN;
    assert_eq!(
        d.act(SimulationCommand::ResumeSealed {
            approval: absent,
            observed
        })
        .code,
        SimulationCode::RecoveryAuthorizationRequired
    );
    assert_eq!(
        d.act(SimulationCommand::ResumeSealed {
            approval: authorization,
            observed
        })
        .snapshot
        .phase,
        SimulationPhase::Sealed
    );
    assert!(
        d.act(SimulationCommand::PublishStable(SimulationAck::Committed))
            .effects
            .is_empty(),
        "fresh health required after resume"
    );
    d.health();
    d.act(SimulationCommand::PublishStable(SimulationAck::Committed));
    let approval = rollback(S2);
    d.close(approval);
    assert_eq!(d.snapshot().phase, SimulationPhase::RollbackClosing);
    assert_eq!(d.snapshot().generation, 3);
    d.drain();
    assert_eq!(d.snapshot().phase, SimulationPhase::RollbackQuiescent);
    let pointer = d.act(SimulationCommand::SelectRollbackPointer {
        binary: B1,
        profile: [54; 32],
        qualified: YES,
        ack: SimulationAck::Committed,
    });
    assert_eq!(
        pointer.effects,
        vec![SimulationEffect::SelectRetainedBinary {
            generation: 3,
            binary: B1,
            profile: [54; 32]
        }]
    );
    let seal = d.act(SimulationCommand::SealRollback {
        proof: seal_proof(d.snapshot(), approval),
        ack: SimulationAck::Committed,
    });
    assert_eq!(seal.snapshot.phase, SimulationPhase::RollbackSealed);
    assert_eq!(seal.snapshot.schema, S2, "forward schema is retained");
    assert!(
        !seal.effects.iter().any(|e| matches!(
            e,
            SimulationEffect::BeginOwnerMigration { .. }
                | SimulationEffect::ApplyExpandOnlyStep { .. }
                | SimulationEffect::PublishOwnerSeal { .. }
        )),
        "rollback is control-only, no migration"
    );
    d.health();
    let stable = d.act(SimulationCommand::PublishStable(SimulationAck::Committed));
    assert_eq!(stable.snapshot.phase, SimulationPhase::Stable);
    assert_eq!(stable.snapshot.generation, 3);
    assert_eq!(stable.snapshot.schema, S2);
    assert_eq!(stable.snapshot.binary, B1);
}

#[test]
fn rollback_requires_exact_retained_profile_and_forward_schema() {
    let mut d = Driver::new(4);
    let mut bad = rollback(S1);
    bad.qualification = UNKNOWN;
    assert_eq!(
        d.act(SimulationCommand::Begin(bad)).code,
        SimulationCode::QualificationUnresolved
    );
    assert_eq!(d.snapshot(), initial(4));
    bad = rollback(S2);
    assert_eq!(
        d.act(SimulationCommand::Begin(bad)).code,
        SimulationCode::StateTransitionInvalid,
        "no schema downgrade/change"
    );
    let good = rollback(S1);
    d.close(good);
    d.drain();
    assert_eq!(
        d.act(SimulationCommand::BeginMigration {
            approved_step: [73; 32]
        })
        .code,
        SimulationCode::StateTransitionInvalid
    );
    let missing = d.act(SimulationCommand::SelectRollbackPointer {
        binary: B1,
        profile: [54; 32],
        qualified: UNKNOWN,
        ack: SimulationAck::Committed,
    });
    assert_eq!(missing.snapshot.phase, SimulationPhase::RecoveryRequired);
    assert_eq!(missing.code, SimulationCode::QualificationUnresolved);
    assert!(
        !missing
            .effects
            .iter()
            .any(|e| matches!(e, SimulationEffect::SelectRetainedBinary { .. }))
    );
}

#[test]
fn generation_exhaustion() {
    let mut d = Driver::new(u64::MAX);
    let exhausted = d.act(SimulationCommand::Begin(update()));
    assert_eq!(
        exhausted.code,
        SimulationCode::GenerationExhausted,
        "ST04 checked generation exhaustion preserves stable cohort"
    );
    assert_eq!(exhausted.snapshot, initial(u64::MAX));
    assert!(
        exhausted.effects.is_empty(),
        "ST04 exhaustion must not close original stable cohort"
    );
    let mut last = Driver::new(u64::MAX - 1);
    last.close(update());
    assert_eq!(last.snapshot().generation, u64::MAX);
    let mut recovered = initial(u64::MAX);
    recovered.phase = SimulationPhase::RecoveryRequired;
    recovered.requested_gate = SimulationGate::Closed;
    recovered.observed_gate = SimulationGate::Closed;
    let mut model = SimulationCoordinator::from_simulation_snapshot(recovered).unwrap();
    let request = SimulationEvent {
        provenance: S,
        operation: OP2,
        event_id: [81; 32],
        event_digest: [82; 32],
        expected: recovered.guard(),
        command: SimulationCommand::Begin(rollback(S1)),
    };
    let result = model.apply_simulation(request);
    assert_eq!(result.code, SimulationCode::GenerationExhausted);
    assert_eq!(result.snapshot, recovered);
    assert!(result.effects.is_empty());
    assert!(
        SimulationCoordinator::from_simulation_snapshot(initial(0)).is_err(),
        "no missing-row/bootstrap inference"
    );
}

#[test]
fn drain_and_cancel() {
    let mut d = Driver::new(1);
    d.close(update());
    for result in [UNKNOWN, NO] {
        let timeout = d.act(SimulationCommand::ObserveDrain {
            actor_inventory: [71; 32],
            stop_receipts: [72; 32],
            result,
        });
        assert_eq!(
            timeout.code,
            SimulationCode::ActorsNotQuiescent,
            "ST06 timeout cannot prove drain"
        );
        assert_eq!(timeout.snapshot.phase, SimulationPhase::Closing);
        assert!(timeout.effects.is_empty());
        assert!(
            d.act(SimulationCommand::BeginMigration {
                approved_step: [73; 32]
            })
            .effects
            .is_empty(),
            "ST06 timeout cannot prove drain"
        );
    }
    d.drain();
    assert_eq!(d.snapshot().phase, SimulationPhase::Quiescent);
    let cancelled = d.act(SimulationCommand::Cancel);
    assert_eq!(cancelled.code, SimulationCode::StartupCancelled);
    assert_eq!(cancelled.snapshot.phase, SimulationPhase::RecoveryRequired);
    assert!(
        d.act(SimulationCommand::BeginMigration {
            approved_step: [73; 32]
        })
        .effects
        .is_empty()
    );
    let mut lost = Driver::new(1);
    lost.migrate();
    lost.act(SimulationCommand::MigrationStep {
        approved_step: [74; 32],
        ack: SimulationAck::Unknown,
    });
    let cancelled = lost.act(SimulationCommand::Cancel);
    assert_eq!(
        cancelled.snapshot.phase,
        SimulationPhase::RecoveryRequired,
        "cancel does not undo unknown commit"
    );
    assert_eq!(cancelled.snapshot.generation, 2);
}

#[test]
fn operation_state_guards_and_exact_event_idempotency() {
    let mut d = Driver::new(1);
    let event = d.event(SimulationCommand::Begin(update()));
    let first = d.model.apply_simulation(event.clone());
    assert_eq!(first.code, SimulationCode::ClosingOutcomeUnknown);
    let repeat = d.model.apply_simulation(event.clone());
    assert_eq!(repeat.code, SimulationCode::Idempotent);
    assert!(repeat.effects.is_empty());
    let mut conflict = event.clone();
    conflict.command = SimulationCommand::Cancel;
    assert_eq!(
        d.model.apply_simulation(conflict).code,
        SimulationCode::ReconciliationRequired,
        "same digest with changed event is conflicting"
    );
    let mut conflict = event.clone();
    conflict.event_digest = [99; 32];
    assert_eq!(
        d.model.apply_simulation(conflict).code,
        SimulationCode::ReconciliationRequired
    );
    let mut wrong = d.event(SimulationCommand::ObserveHostClosure(YES));
    wrong.operation = OP2;
    assert_eq!(
        d.model.apply_simulation(wrong).code,
        SimulationCode::StateTransitionInvalid
    );
    let mut wrong = d.event(SimulationCommand::ObserveHostClosure(YES));
    wrong.expected.generation = 2;
    assert_eq!(
        d.model.apply_simulation(wrong).code,
        SimulationCode::StateTransitionInvalid
    );
    d.act(SimulationCommand::ObserveHostClosure(YES));
    d.act(SimulationCommand::PublishClose(SimulationAck::Committed));
    assert_eq!(
        d.model.apply_simulation(event).code,
        SimulationCode::Idempotent,
        "acknowledged old event remains exact-idempotent"
    );
}

#[test]
fn closing_publication_reconciliation() {
    for kind in [SimulationKind::Update, SimulationKind::ExecutableRollback] {
        for boundary in 0..4 {
            let mut d = Driver::new(10);
            let approval = if kind == SimulationKind::Update {
                update()
            } else {
                rollback(S1)
            };
            let source = d.snapshot();
            let begin = d.act(SimulationCommand::Begin(approval));
            assert_no_open_or_start(&begin);
            assert_eq!(begin.snapshot.generation, 10);
            assert_eq!(
                begin.snapshot.observed_gate,
                SimulationGate::Unknown,
                "ST08 no fabricated close receipt"
            );
            assert_eq!(
                begin.effects[0],
                SimulationEffect::PersistCloseIntent(Box::new(SimulationCloseIntent {
                    provenance: S,
                    source,
                    reserved_generation: 11,
                    approval,
                    publication: SimulationClosePublication::Initial,
                }))
            );
            if boundary == 0 {
                assert!(
                    d.act(SimulationCommand::PublishClose(SimulationAck::Unknown))
                        .effects
                        .is_empty(),
                    "DB close forbidden before observed host closure"
                );
            } else {
                d.act(SimulationCommand::ObserveHostClosure(YES));
                if boundary >= 2 {
                    d.act(SimulationCommand::PublishClose(SimulationAck::Unknown));
                }
            }
            let pending = d.snapshot();
            for readback in [SimulationReadback::Unknown, SimulationReadback::Conflicting] {
                let result = d.act(d.reconcile_close(readback));
                assert_eq!(result.snapshot, pending);
                assert_no_open_or_start(&result);
                assert_eq!(result.stage, "coordinator.close");
                assert_eq!(result.close_intent.unwrap().reserved_generation, 11);
            }
            let absent = d.act(d.reconcile_close(SimulationReadback::NotCommitted {
                predecessor: source,
                operation_absent: YES,
            }));
            assert_eq!(absent.snapshot, pending);
            assert_no_open_or_start(&absent);
            assert!(
                d.act(SimulationCommand::BeginMigration {
                    approved_step: [73; 32]
                })
                .effects
                .is_empty()
            );
            assert!(
                d.act(SimulationCommand::SelectRollbackPointer {
                    binary: B1,
                    profile: [54; 32],
                    qualified: YES,
                    ack: SimulationAck::Committed
                })
                .effects
                .is_empty()
            );
            assert!(
                d.act(SimulationCommand::StartCore {
                    fixed_cohort: COHORT
                })
                .effects
                .is_empty()
            );
            if boundary == 0 {
                d.act(SimulationCommand::ObserveHostClosure(YES));
            }
            let mut committed = source;
            committed.generation = 11;
            committed.phase = if kind == SimulationKind::Update {
                SimulationPhase::Closing
            } else {
                SimulationPhase::RollbackClosing
            };
            committed.operation = Some(approval.operation);
            committed.requested_gate = SimulationGate::Closed;
            committed.observed_gate = SimulationGate::Closed;
            // Committed readback must refer to an actual durable publication identity.
            if boundary < 2 {
                d.act(SimulationCommand::PublishClose(SimulationAck::Unknown));
            }
            let reconcile = d.act(d.reconcile_close(SimulationReadback::Committed(committed)));
            assert_eq!(
                reconcile.snapshot, committed,
                "ST08 exact committed readback adopts reserved generation"
            );
            assert_eq!(
                reconcile.effects,
                vec![SimulationEffect::ObserveOriginalCohort]
            );
            assert_eq!(reconcile.close_intent, None);
            assert!(
                d.act(SimulationCommand::BeginMigration {
                    approved_step: [73; 32]
                })
                .effects
                .is_empty(),
                "host closure is not drain"
            );
            d.drain();
            assert_eq!(d.snapshot().generation, 11, "no second allocation");
            assert_eq!(
                d.snapshot().phase,
                if kind == SimulationKind::Update {
                    SimulationPhase::Quiescent
                } else {
                    SimulationPhase::RollbackQuiescent
                }
            );
        }
    }
}

#[test]
fn closing_foreign_state_enters_recovery_without_overwrite() {
    let mut d = Driver::new(10);
    d.act(SimulationCommand::Begin(update()));
    let mut foreign = initial(15);
    foreign.operation = Some([33; 32]);
    let result = d.act(d.reconcile_close(SimulationReadback::Foreign(foreign)));
    assert_eq!(result.snapshot.generation, 15);
    assert_eq!(result.snapshot.operation, foreign.operation);
    assert_eq!(result.snapshot.phase, SimulationPhase::RecoveryRequired);
    assert_eq!(result.snapshot.seal, foreign.seal);
    assert_eq!(result.snapshot.observed_gate, SimulationGate::Unknown);
    assert_eq!(result.close_intent, None);
    assert_no_open_or_start(&result);
    assert!(
        d.act(SimulationCommand::PublishClose(SimulationAck::Committed))
            .effects
            .is_empty()
    );
}

#[test]
fn close_not_committed_retries_same_reservation() {
    let mut d = Driver::new(10);
    let source = d.snapshot();
    d.act(SimulationCommand::Begin(update()));
    d.act(SimulationCommand::ObserveHostClosure(YES));
    d.act(SimulationCommand::PublishClose(SimulationAck::NotCommitted));
    let mut wrong = source;
    wrong.generation = 9;
    assert_eq!(
        d.act(d.reconcile_close(SimulationReadback::NotCommitted {
            predecessor: wrong,
            operation_absent: YES
        }))
        .snapshot
        .phase,
        SimulationPhase::ClosePending
    );
    let result = d.act(d.reconcile_close(SimulationReadback::NotCommitted {
        predecessor: source,
        operation_absent: YES,
    }));
    assert_eq!(result.close_intent.unwrap().reserved_generation, 11);
    let retry = d.act(SimulationCommand::PublishClose(SimulationAck::Committed));
    assert_eq!(retry.snapshot.generation, 11);
    assert_eq!(retry.snapshot.phase, SimulationPhase::Closing);
    assert!(
        retry
            .effects
            .iter()
            .any(|e| matches!(e, SimulationEffect::PersistCloseIntent(_)))
    );
}

#[test]
fn publication_ack_reconciliation() {
    let mut d = Driver::new(1);
    d.seal();
    d.act(SimulationCommand::ObserveOwnerClosed(YES));
    d.health();
    let predecessor = d.snapshot();
    let lost = d.act(SimulationCommand::PublishStable(SimulationAck::Unknown));
    assert_eq!(lost.snapshot.phase, SimulationPhase::RecoveryRequired);
    assert_no_open_or_start(&lost);
    assert_eq!(lost.snapshot.generation, 2);
    assert_eq!(lost.snapshot.operation, Some(OP));
    assert_no_open_or_start(&d.act(d.reconcile(SimulationReadback::Unknown)));
    let mut target = predecessor;
    target.phase = SimulationPhase::Stable;
    target.requested_gate = SimulationGate::Open;
    let readback = d.event(d.reconcile(SimulationReadback::Committed(target)));
    let success = d.model.apply_simulation(readback.clone());
    assert_eq!(success.snapshot, target);
    assert_eq!(
        success.effects,
        vec![SimulationEffect::RequestPublicGateOpen]
    );
    let duplicate = d.model.apply_simulation(readback);
    assert_eq!(duplicate.code, SimulationCode::Idempotent);
    assert!(duplicate.effects.is_empty(), "ST07 open happens once");
    let mut seal_unknown = Driver::new(1);
    seal_unknown.migrate();
    let before = seal_unknown.snapshot();
    let proof = seal_proof(before, update());
    let lost = seal_unknown.act(SimulationCommand::Seal {
        proof,
        ack: SimulationAck::Unknown,
    });
    assert_eq!(lost.snapshot.phase, SimulationPhase::RecoveryRequired);
    assert_no_open_or_start(&lost);
    let mut sealed = before;
    sealed.phase = SimulationPhase::Sealed;
    sealed.schema = S2;
    sealed.binary = B2;
    sealed.seal = SEAL2;
    let read = seal_unknown.act(seal_unknown.reconcile(SimulationReadback::Committed(sealed)));
    assert_eq!(read.snapshot, sealed);
    assert!(read.effects.is_empty());
    assert_eq!(
        seal_unknown
            .act(SimulationCommand::StartCore {
                fixed_cohort: COHORT
            })
            .code,
        SimulationCode::OwnerConnectionOpen
    );
}

#[test]
fn pointer_ack_reconciliation_never_replays_unknown_selection() {
    let mut d = Driver::new(1);
    let approval = rollback(S1);
    d.close(approval);
    d.drain();
    let before = d.snapshot();
    let lost = d.act(SimulationCommand::SelectRollbackPointer {
        binary: B1,
        profile: [54; 32],
        qualified: YES,
        ack: SimulationAck::Unknown,
    });
    assert_eq!(lost.snapshot.phase, SimulationPhase::RecoveryRequired);
    assert_eq!(
        d.act(SimulationCommand::SelectRollbackPointer {
            binary: B1,
            profile: [54; 32],
            qualified: YES,
            ack: SimulationAck::Committed
        })
        .code,
        SimulationCode::StateTransitionInvalid
    );
    assert_no_open_or_start(&d.act(d.reconcile(SimulationReadback::Unknown)));
    let read = d.act(d.reconcile(SimulationReadback::NotCommitted {
        predecessor: before,
        operation_absent: YES,
    }));
    assert_eq!(read.snapshot, before);
    assert!(read.effects.is_empty());
    let retry = d.act(SimulationCommand::SelectRollbackPointer {
        binary: B1,
        profile: [54; 32],
        qualified: YES,
        ack: SimulationAck::Committed,
    });
    assert_eq!(retry.effects.len(), 1);
    assert_eq!(
        d.act(SimulationCommand::SealRollback {
            proof: seal_proof(d.snapshot(), approval),
            ack: SimulationAck::Committed
        })
        .snapshot
        .phase,
        SimulationPhase::RollbackSealed
    );
}

fn roles() -> BTreeSet<SimulationRole> {
    [
        SimulationRole::Application,
        SimulationRole::Worker,
        SimulationRole::Coordinator,
    ]
    .into_iter()
    .collect()
}
fn envelope(attempt: u8) -> SimulationEnvelope {
    SimulationEnvelope {
        provenance: S,
        installation: [91; 32],
        timeline: [92; 32],
        release_epoch: [93; 32],
        generation: 2,
        seal: SEAL2,
        attempt,
        role: SimulationRole::Application,
        source_contract: [94; 32],
    }
}
fn bundle(attempt: u8) -> SimulationObservationBundle {
    let expected = envelope(attempt);
    SimulationObservationBundle {
        provenance: S,
        expected,
        required_roles: roles(),
        observations: roles()
            .into_iter()
            .map(|role| {
                let value = SimulationEnvelope { role, ..expected };
                SimulationRoleObservation {
                    provenance: S,
                    before: value,
                    after: value,
                    complete: YES,
                }
            })
            .collect(),
    }
}
fn fence(attempt: u8) -> SimulationFenceObservation {
    let mut snapshot = initial(2);
    snapshot.seal = SEAL2;
    SimulationFenceObservation {
        provenance: S,
        envelope: envelope(attempt),
        snapshot,
        shared_lock: YES,
        evidence_current: YES,
        observation_origin: YES,
    }
}
fn pending(attempt: u8, startup: &mut SimulationStartup) {
    let started = startup.begin_simulation_attempt(envelope(attempt), roles());
    assert_eq!(started.attempt, attempt);
    assert_eq!(started.phase, SimulationStartupPhase::Probe);
    assert_eq!(
        startup.collect_simulation(bundle(attempt)).code,
        SimulationCode::CompatiblePendingFence
    );
    assert_eq!(
        startup.assess_simulation(YES).code,
        SimulationCode::CompatiblePendingFence
    );
}
fn receipt() -> SimulationAdmissionReceipt {
    let mut startup = SimulationStartup::default();
    pending(1, &mut startup);
    startup.fence_simulation(Some(fence(1))).receipt.unwrap()
}

#[test]
fn observations_are_one_generation() {
    for fault in 0..6 {
        let mut startup = SimulationStartup::default();
        startup.begin_simulation_attempt(envelope(1), roles());
        let mut mixed = bundle(1);
        let member = &mut mixed.observations[1];
        match fault {
            0 => member.before.generation = 1,
            1 => member.after.seal = SEAL1,
            2 => member.before.attempt = 2,
            3 => member.after.installation = [95; 32],
            4 => member.after.source_contract = [95; 32],
            5 => member.after.timeline = [95; 32],
            _ => unreachable!(),
        }
        let result = startup.collect_simulation(mixed);
        assert_eq!(
            result.code,
            if fault < 3 {
                SimulationCode::ObservationGenerationMismatch
            } else {
                SimulationCode::EvidenceBindingMismatch
            }
        );
        assert_eq!(
            result.retained_observations, 0,
            "ST03 no tainted fact survives"
        );
        assert_eq!(result.receipt, None);
        let mut startup = SimulationStartup::default();
        startup.begin_simulation_attempt(envelope(1), roles());
        assert_eq!(
            startup.collect_simulation(bundle(1)).code,
            SimulationCode::CompatiblePendingFence
        );
        startup.assess_simulation(YES);
        assert_eq!(
            startup.fence_simulation(None).code,
            SimulationCode::CompatiblePendingFence
        );
        let mut changed = fence(1);
        changed.snapshot.generation = 3;
        let retry = startup.fence_simulation(Some(changed));
        assert_eq!(
            retry.code,
            SimulationCode::FenceRetry,
            "ST03 final generation must deny admission"
        );
        assert_eq!(retry.retained_observations, 0);
        assert_eq!(retry.receipt, None);
        startup.begin_simulation_attempt(envelope(2), roles());
        assert_eq!(
            startup.collect_simulation(bundle(1)).code,
            SimulationCode::ObservationGenerationMismatch,
            "old attempt cannot contribute a fact"
        );
        startup.begin_simulation_attempt(envelope(3), roles());
        assert_eq!(
            startup.collect_simulation(bundle(3)).code,
            SimulationCode::CompatiblePendingFence
        );
        startup.assess_simulation(YES);
        assert_eq!(
            startup.fence_simulation(Some(fence(3))).code,
            SimulationCode::SimulatedAdmissionOnly
        );
    }
}

#[test]
fn observation_inventory_is_fixed_and_complete() {
    for fault in 0..3 {
        let mut startup = SimulationStartup::default();
        startup.begin_simulation_attempt(envelope(1), roles());
        let mut bad = bundle(1);
        match fault {
            0 => {
                bad.observations.pop();
            }
            1 => bad.observations.push(bad.observations[0]),
            2 => bad.observations[0].complete = UNKNOWN,
            _ => unreachable!(),
        }
        let result = startup.collect_simulation(bad);
        assert_eq!(result.code, SimulationCode::PostureUnknown);
        assert_eq!(result.retained_observations, 0);
        assert_eq!(
            startup.begin_simulation_attempt(envelope(2), roles()).code,
            SimulationCode::PostureUnknown
        );
        let mut restored = SimulationStartup::default();
        restored.begin_simulation_attempt(envelope(1), roles());
        assert_eq!(
            restored.collect_simulation(bundle(1)).code,
            SimulationCode::CompatiblePendingFence
        );
    }
    let mut startup = SimulationStartup::default();
    pending(1, &mut startup);
    startup.retry_simulation();
    let short = [SimulationRole::Application].into_iter().collect();
    assert_eq!(
        startup.begin_simulation_attempt(envelope(2), short).code,
        SimulationCode::StateTransitionInvalid
    );
}

#[test]
fn fence_retry_budget() {
    let mut startup = SimulationStartup::default();
    for attempt in 1..=3 {
        pending(attempt, &mut startup);
        assert_eq!(
            startup.advance_simulation_time(4_999).code,
            SimulationCode::Progress
        );
        if attempt < 3 {
            let mut contended = fence(attempt);
            contended.shared_lock = UNKNOWN;
            let retry = startup.fence_simulation(Some(contended));
            assert_eq!(retry.code, SimulationCode::FenceRetry);
            assert_eq!(
                retry.retained_observations, 0,
                "ST05 retry discards prior observations"
            );
            assert_eq!(
                startup.collect_simulation(bundle(attempt)).code,
                SimulationCode::StateTransitionInvalid
            );
        } else {
            let success = startup.fence_simulation(Some(fence(attempt)));
            assert_eq!(success.elapsed_ms, 14_997);
            assert_eq!(success.code, SimulationCode::SimulatedAdmissionOnly);
        }
    }
    let mut exhausted = SimulationStartup::default();
    for attempt in 1..=3 {
        pending(attempt, &mut exhausted);
        let retry = exhausted.retry_simulation();
        assert_eq!(
            retry.code,
            if attempt == 3 {
                SimulationCode::FenceRetryExhausted
            } else {
                SimulationCode::FenceRetry
            }
        );
        assert_eq!(retry.retained_observations, 0);
    }
    assert_eq!(
        exhausted
            .begin_simulation_attempt(envelope(4), roles())
            .code,
        SimulationCode::FenceRetryExhausted
    );
    let mut deadline = SimulationStartup::default();
    for attempt in 1..=3 {
        pending(attempt, &mut deadline);
        let charged = deadline.advance_simulation_time(5_000);
        if attempt < 3 {
            assert_eq!(charged.code, SimulationCode::Progress);
            deadline.retry_simulation();
        } else {
            assert_eq!(charged.code, SimulationCode::FenceRetryExhausted);
            assert_eq!(charged.elapsed_ms, 15_000);
        }
    }
    let mut per_attempt = SimulationStartup::default();
    pending(1, &mut per_attempt);
    let timeout = per_attempt.advance_simulation_time(5_001);
    assert_eq!(timeout.code, SimulationCode::FenceRetry);
    assert_eq!(timeout.retained_observations, 0);
}

#[test]
fn cancellation_is_terminal_before_next_startup_event() {
    for before in 0..4 {
        let mut startup = SimulationStartup::default();
        if before >= 1 {
            startup.begin_simulation_attempt(envelope(1), roles());
        }
        if before >= 2 {
            startup.collect_simulation(bundle(1));
        }
        if before >= 3 {
            startup.assess_simulation(YES);
        }
        let cancelled = startup.cancel_simulation();
        assert_eq!(cancelled.code, SimulationCode::StartupCancelled);
        assert_eq!(cancelled.retained_observations, 0);
        assert_eq!(
            startup.begin_simulation_attempt(envelope(1), roles()).code,
            SimulationCode::StartupCancelled
        );
        assert_eq!(
            startup.collect_simulation(bundle(1)).code,
            SimulationCode::StartupCancelled
        );
        assert_eq!(
            startup.assess_simulation(YES).code,
            SimulationCode::StartupCancelled
        );
        assert_eq!(
            startup.fence_simulation(Some(fence(1))).code,
            SimulationCode::StartupCancelled
        );
        assert_eq!(
            startup.advance_simulation_time(1).code,
            SimulationCode::StartupCancelled
        );
    }
}

#[test]
fn startup_fence_requires_owner_current_origin_and_closed_state_rules() {
    for phase in [
        SimulationPhase::ClosePending,
        SimulationPhase::Closing,
        SimulationPhase::Quiescent,
        SimulationPhase::Migrating,
        SimulationPhase::RecoveryRequired,
        SimulationPhase::RollbackClosing,
        SimulationPhase::RollbackQuiescent,
    ] {
        let mut startup = SimulationStartup::default();
        pending(1, &mut startup);
        let mut closed = fence(1);
        closed.snapshot.phase = phase;
        assert_eq!(
            startup.fence_simulation(Some(closed)).code,
            SimulationCode::StateTransitionInvalid
        );
    }
    for missing in [NO, UNKNOWN] {
        let mut startup = SimulationStartup::default();
        pending(1, &mut startup);
        let mut open = fence(1);
        open.snapshot.owner_closed = missing;
        assert_eq!(
            startup.fence_simulation(Some(open)).code,
            if missing == NO {
                SimulationCode::OwnerConnectionOpen
            } else {
                SimulationCode::OwnerConnectionUnknown
            }
        );
        assert_eq!(
            startup.fence_simulation(Some(fence(1))).phase,
            SimulationStartupPhase::Refused
        );
        let mut restored = SimulationStartup::default();
        pending(1, &mut restored);
        assert_eq!(
            restored.fence_simulation(Some(fence(1))).code,
            SimulationCode::SimulatedAdmissionOnly
        );
    }
    for fault in 0..2 {
        let mut startup = SimulationStartup::default();
        pending(1, &mut startup);
        let mut bad = fence(1);
        if fault == 0 {
            bad.evidence_current = UNKNOWN;
        } else {
            bad.observation_origin = UNKNOWN;
        }
        let result = startup.fence_simulation(Some(bad));
        assert_eq!(result.code, SimulationCode::QualificationUnresolved);
        assert_eq!(result.retained_observations, 0);
    }
}

#[test]
fn business_effects_check_generation_and_withdrawal_is_advisory() {
    let admitted = receipt();
    let current = fence(1).snapshot;
    let request = SimulationBusinessRequest {
        provenance: S,
        receipt: admitted,
        current,
        installation: [91; 32],
        shared_lock: YES,
    };
    let positive = simulation_business_effect(request);
    assert_eq!(positive.code, SimulationCode::EffectSimulatedOnly);
    assert_eq!(
        positive.effects,
        vec![SimulationEffect::BusinessSqlEffect { generation: 2 }]
    );
    let mut changed = request;
    changed.current.generation = 3;
    let mismatch = simulation_business_effect(changed);
    assert_eq!(mismatch.code, SimulationCode::GenerationChanged);
    assert!(mismatch.effects.is_empty());
    let mut unlocked = request;
    unlocked.shared_lock = UNKNOWN;
    assert!(simulation_business_effect(unlocked).effects.is_empty());
    let withdrawal = simulation_active_policy_withdrawal(admitted);
    assert_eq!(
        withdrawal.code,
        SimulationCode::AdvisoryReassessAtSafeBoundary
    );
    assert!(
        withdrawal.effects.is_empty(),
        "no shutdown/restore from withdrawal alone"
    );
    assert_eq!(
        simulation_business_effect(request).code,
        SimulationCode::EffectSimulatedOnly
    );
    let mut health_only = SimulationStartup::default();
    pending(1, &mut health_only);
    let mut sealed = fence(1);
    sealed.snapshot.phase = SimulationPhase::Sealed;
    let receipt = health_only.fence_simulation(Some(sealed)).receipt.unwrap();
    assert!(
        simulation_business_effect(SimulationBusinessRequest { receipt, ..request })
            .effects
            .is_empty(),
        "isolated seal health does not grant public effects"
    );
}

#[test]
fn recovery_is_independent() {
    let refusals = [
        SimulationCode::StateTransitionInvalid,
        SimulationCode::ReconciliationRequired,
        SimulationCode::GenerationExhausted,
        SimulationCode::ClosingOutcomeUnknown,
        SimulationCode::ActorsNotQuiescent,
        SimulationCode::OwnerConnectionOpen,
        SimulationCode::OwnerConnectionUnknown,
        SimulationCode::QualificationUnresolved,
        SimulationCode::PublicationOutcomeUnknown,
        SimulationCode::RecoveryRequired,
        SimulationCode::RecoveryAuthorizationRequired,
        SimulationCode::ObservationGenerationMismatch,
        SimulationCode::EvidenceBindingMismatch,
        SimulationCode::PostureUnknown,
        SimulationCode::CompatiblePendingFence,
        SimulationCode::FenceRetry,
        SimulationCode::FenceRetryExhausted,
        SimulationCode::StartupCancelled,
        SimulationCode::GenerationChanged,
    ];
    let decision = SimulationActivationDecision {
        provenance: S,
        separately_approved: YES,
        root_and_reason: YES,
        force_and_tty_policy: YES,
        reconciliation: YES,
        retained_binary: YES,
        exact_profile: YES,
    };
    for business in refusals {
        let status = simulation_recovery_eligibility(
            business,
            SimulationRecoveryAccess::NoAuthorization,
            None,
        );
        assert!(
            status.status_callable,
            "REC01 status independent of business refusal"
        );
        assert!(!status.evidence_eligible);
        assert!(!status.activation_eligible);
        let evidence = simulation_recovery_eligibility(
            business,
            SimulationRecoveryAccess::EvidenceSnapshotAuthorized,
            None,
        );
        assert!(evidence.status_callable);
        assert!(
            evidence.evidence_eligible,
            "REC01 authorized evidence eligibility"
        );
        assert!(evidence.evidence_is_write);
        assert!(
            !evidence.activation_eligible,
            "evidence access cannot activate"
        );
        let activation = simulation_recovery_eligibility(
            business,
            SimulationRecoveryAccess::StatusOnly,
            Some(decision),
        );
        assert!(activation.activation_eligible);
        assert!(!activation.activation_grants_business_admission);
        assert!(
            !activation.evidence_eligible,
            "activation does not grant unrelated evidence writes"
        );
        for missing in 0..6 {
            let mut denied = decision;
            match missing {
                0 => denied.separately_approved = UNKNOWN,
                1 => denied.root_and_reason = NO,
                2 => denied.force_and_tty_policy = NO,
                3 => denied.reconciliation = UNKNOWN,
                4 => denied.retained_binary = UNKNOWN,
                5 => denied.exact_profile = UNKNOWN,
                _ => unreachable!(),
            }
            let result = simulation_recovery_eligibility(
                business,
                SimulationRecoveryAccess::EvidenceSnapshotAuthorized,
                Some(denied),
            );
            assert!(!result.activation_eligible);
            assert!(result.status_callable);
            assert!(result.evidence_eligible);
        }
    }
}

#[test]
fn reports_remain_synthetic() {
    let build = SimulationReport::build_only(SimulationCode::QualificationUnresolved);
    assert_eq!(build.provenance, S);
    assert_eq!(build.database_generation, None);
    assert_eq!(build.admission, None);
    assert_eq!(
        build.simulation_projection(),
        "provenance=synthetic;code=QUALIFICATION_UNRESOLVED;outcome=simulation_only"
    );
    let mut startup = SimulationStartup::default();
    pending(1, &mut startup);
    let pending = startup.fence_simulation(None);
    let pending_report = SimulationReport::from_simulation_startup(&pending);
    assert_eq!(pending_report.code, pending.code);
    assert_eq!(pending_report.database_generation, None);
    let success = startup.fence_simulation(Some(fence(1)));
    let report = SimulationReport::from_simulation_startup(&success);
    assert_eq!(report.code, SimulationCode::SimulatedAdmissionOnly);
    assert_eq!(report.provenance, S);
    assert_eq!(report.database_generation, Some(2));
    assert_eq!(report.admission.unwrap().simulation_provenance(), S);
    assert_eq!(
        report.simulation_projection(),
        "provenance=synthetic;code=SIMULATED_ADMISSION_ONLY;outcome=SIMULATED_ADMISSION_ONLY",
        "REP01 synthetic projection cannot claim runtime admission"
    );
    assert!(
        !report.simulation_projection().contains("outcome=admitted"),
        "REP01 no runtime admission projection"
    );
    assert!(
        !report
            .simulation_projection()
            .contains("authenticated_runtime")
    );
}

#[test]
fn qualification_refusal_is_terminal_and_cannot_consume_a_retry() {
    for fault in 0..3 {
        let mut startup = SimulationStartup::default();
        startup.begin_simulation_attempt(envelope(1), roles());
        startup.collect_simulation(bundle(1));
        let denied = if fault == 0 {
            startup.assess_simulation(NO)
        } else {
            startup.assess_simulation(YES);
            let mut evidence = fence(1);
            if fault == 1 {
                evidence.evidence_current = NO;
            } else {
                evidence.observation_origin = UNKNOWN;
            }
            startup.fence_simulation(Some(evidence))
        };
        assert_eq!(denied.phase, SimulationStartupPhase::Refused);
        assert_eq!(denied.retained_observations, 0);
        assert_eq!(denied.receipt, None);
        assert_eq!(
            startup.begin_simulation_attempt(envelope(2), roles()).code,
            SimulationCode::QualificationUnresolved
        );
        assert_eq!(
            startup.retry_simulation().code,
            SimulationCode::QualificationUnresolved
        );
        assert_eq!(
            startup.collect_simulation(bundle(1)).code,
            SimulationCode::QualificationUnresolved
        );
        assert_eq!(
            startup.fence_simulation(Some(fence(1))).code,
            SimulationCode::QualificationUnresolved
        );
    }
}

#[test]
fn durable_close_intent_restart_is_fail_closed() {
    for kind in [SimulationKind::Update, SimulationKind::ExecutableRollback] {
        let mut d = Driver::new(8);
        let approval = if kind == SimulationKind::Update {
            update()
        } else {
            rollback(S1)
        };
        let intent = d
            .act(SimulationCommand::Begin(approval))
            .close_intent
            .unwrap();
        // Only Initial can publish after closure on restart. An attempted transaction
        // must use the durable PendingUnknown record and reconcile (C1 tests below).
        assert_eq!(intent.publication, SimulationClosePublication::Initial);
        for observed in [SimulationGate::Unknown, SimulationGate::Closed] {
            let model =
                SimulationCoordinator::from_simulation_close_intent(intent, observed).unwrap();
            let mut restarted = Driver {
                model,
                serial: 80,
                publication: None,
            };
            assert_eq!(restarted.snapshot().phase, SimulationPhase::ClosePending);
            assert_eq!(restarted.snapshot().generation, 8);
            assert_eq!(restarted.snapshot().requested_gate, SimulationGate::Closed);
            assert_eq!(restarted.snapshot().observed_gate, observed);
            assert_eq!(restarted.model.simulation_close_intent(), Some(intent));
            assert!(
                restarted
                    .act(SimulationCommand::StartCore {
                        fixed_cohort: COHORT
                    })
                    .effects
                    .is_empty()
            );
            assert!(
                restarted
                    .act(SimulationCommand::BeginMigration {
                        approved_step: [73; 32]
                    })
                    .effects
                    .is_empty()
            );
            if observed == SimulationGate::Unknown {
                assert!(
                    restarted
                        .act(SimulationCommand::PublishClose(SimulationAck::Committed))
                        .effects
                        .is_empty()
                );
                restarted.act(SimulationCommand::ObserveHostClosure(YES));
            }
            assert_eq!(
                restarted
                    .act(SimulationCommand::PublishClose(SimulationAck::Committed))
                    .snapshot
                    .generation,
                9
            );
        }
        assert!(
            SimulationCoordinator::from_simulation_close_intent(intent, SimulationGate::Open)
                .is_err()
        );
    }
}

#[test]
fn publication_readback_binds_event_digest_and_exact_effect() {
    let mut d = Driver::new(1);
    d.close(rollback(S1));
    d.drain();
    let before = d.snapshot();
    d.act(SimulationCommand::SelectRollbackPointer {
        binary: B1,
        profile: [54; 32],
        qualified: YES,
        ack: SimulationAck::Unknown,
    });
    let command = d.reconcile(SimulationReadback::Committed(before));
    let SimulationCommand::ReconcilePublication(exact) = &command else {
        unreachable!()
    };
    for fault in 0..3 {
        let mut wrong = exact.clone();
        match fault {
            0 => wrong.event_digest = [99; 32],
            1 => {
                wrong.effect = SimulationEffect::SelectRetainedBinary {
                    generation: 2,
                    binary: B2,
                    profile: [54; 32],
                }
            }
            2 => {
                wrong.effect = SimulationEffect::SelectRetainedBinary {
                    generation: 2,
                    binary: B1,
                    profile: [55; 32],
                }
            }
            _ => unreachable!(),
        }
        let rejected = d.act(SimulationCommand::ReconcilePublication(wrong));
        assert_eq!(rejected.snapshot.phase, SimulationPhase::RecoveryRequired);
        assert!(
            rejected.effects.is_empty(),
            "snapshot alone never proves pointer selection"
        );
    }
    let accepted = d.act(command);
    assert_eq!(accepted.snapshot.phase, SimulationPhase::RollbackQuiescent);
    assert!(
        accepted.effects.is_empty(),
        "exact committed pointer readback does not replay selection"
    );
}

#[test]
fn not_committed_publication_allows_only_exact_approved_retry() {
    let mut d = Driver::new(1);
    d.close(rollback(S1));
    d.drain();
    let before = d.snapshot();
    let pointer = SimulationCommand::SelectRollbackPointer {
        binary: B1,
        profile: [54; 32],
        qualified: YES,
        ack: SimulationAck::Unknown,
    };
    d.act(pointer);
    d.act(d.reconcile(SimulationReadback::NotCommitted {
        predecessor: before,
        operation_absent: YES,
    }));
    let good = d.event(SimulationCommand::SelectRollbackPointer {
        binary: B1,
        profile: [54; 32],
        qualified: YES,
        ack: SimulationAck::Committed,
    });
    let mut wrong = good.clone();
    wrong.event_digest = [99; 32];
    let rejected = d.model.apply_simulation(wrong);
    assert_eq!(rejected.code, SimulationCode::StateTransitionInvalid);
    assert!(
        rejected.effects.is_empty(),
        "same reservation cannot authorize a different publication digest"
    );
    let accepted = d.model.apply_simulation(good);
    assert_eq!(accepted.code, SimulationCode::Progress);
    assert_eq!(
        accepted.effects,
        vec![SimulationEffect::SelectRetainedBinary {
            generation: 2,
            binary: B1,
            profile: [54; 32]
        }]
    );
}

#[test]
fn seal_and_health_proofs_bind_exact_operation_generation_and_target() {
    for fault in 0..8 {
        let mut d = Driver::new(1);
        d.migrate();
        let mut proof = seal_proof(d.snapshot(), update());
        match fault {
            0 => proof.generation = 1,
            1 => proof.operation = OP2,
            2 => proof.schema = S1,
            3 => proof.binary = B1,
            4 => proof.seal = SEAL1,
            5 => proof.descriptors = UNKNOWN,
            6 => proof.observations = UNKNOWN,
            7 => proof.ledger = UNKNOWN,
            _ => unreachable!(),
        }
        let rejected = d.act(SimulationCommand::Seal {
            proof,
            ack: SimulationAck::Committed,
        });
        assert_eq!(rejected.snapshot.phase, SimulationPhase::RecoveryRequired);
        assert!(
            !rejected
                .effects
                .iter()
                .any(|e| matches!(e, SimulationEffect::PublishOwnerSeal { .. }))
        );
    }
    for fault in 0..8 {
        let mut d = Driver::new(1);
        d.seal();
        d.act(SimulationCommand::ObserveOwnerClosed(YES));
        d.act(SimulationCommand::StartCore {
            fixed_cohort: COHORT,
        });
        let mut proof = health_proof(d.snapshot());
        match fault {
            0 => proof.generation = 1,
            1 => proof.operation = OP2,
            2 => proof.seal = SEAL1,
            3 => proof.fixed_cohort = [62; 32],
            4 => proof.fresh_admission = UNKNOWN,
            5 => proof.readiness = NO,
            6 => proof.data_contract = NO,
            7 => proof.postcommit = UNKNOWN,
            _ => unreachable!(),
        }
        let rejected = d.act(SimulationCommand::Health(proof));
        assert_eq!(rejected.snapshot.phase, SimulationPhase::RecoveryRequired);
        assert_no_open_or_start(&rejected);
        assert!(
            d.act(SimulationCommand::PublishStable(SimulationAck::Committed))
                .effects
                .is_empty()
        );
    }
    let mut restored = Driver::new(1);
    restored.seal();
    restored.act(SimulationCommand::ObserveOwnerClosed(YES));
    restored.health();
    assert_eq!(
        restored
            .act(SimulationCommand::PublishStable(SimulationAck::Committed))
            .snapshot
            .phase,
        SimulationPhase::Stable
    );
}

fn close_event(d: &mut Driver, digest: [u8; 32], ack: SimulationAck) -> SimulationTransition {
    let mut event = d.event(SimulationCommand::PublishClose(ack));
    event.event_digest = digest;
    d.model.apply_simulation(event)
}

#[test]
fn close_unknown_requires_exact_reconciliation_across_restart() {
    for approval in [update(), rollback(S1)] {
        for ack in [SimulationAck::Unknown, SimulationAck::NotCommitted] {
            for restart in [false, true] {
                let mut d = Driver::new(10);
                let source = d.snapshot();
                d.act(SimulationCommand::Begin(approval));
                d.act(SimulationCommand::ObserveHostClosure(YES));
                let attempted = close_event(&mut d, [90; 32], ack);
                let intent = attempted.close_intent.unwrap();
                assert_eq!(
                    intent.publication,
                    SimulationClosePublication::PendingUnknown {
                        event_digest: [90; 32],
                    }
                );
                assert_eq!(
                    attempted.effects[0],
                    SimulationEffect::PersistCloseIntent(Box::new(intent))
                );
                assert!(matches!(
                    attempted.effects[1],
                    SimulationEffect::PublishControlExclusive { generation: 11, .. }
                ));
                if restart {
                    d.model = SimulationCoordinator::from_simulation_close_intent(
                        intent,
                        SimulationGate::Closed,
                    )
                    .unwrap();
                }
                let pending = d.snapshot();
                for readback in [
                    None,
                    Some(SimulationReadback::Unknown),
                    Some(SimulationReadback::Conflicting),
                ] {
                    if let Some(readback) = readback {
                        d.act(d.reconcile_close(readback));
                    }
                    for digest in [[90; 32], [91; 32]] {
                        let rejected = close_event(&mut d, digest, SimulationAck::Committed);
                        assert_eq!(
                            rejected.code,
                            SimulationCode::ClosingOutcomeUnknown,
                            "C1 unresolved close cannot republish"
                        );
                        assert!(
                            rejected.effects.is_empty(),
                            "C1 unresolved close emits zero effects"
                        );
                        assert_eq!(rejected.snapshot, pending);
                        assert_eq!(rejected.close_intent, Some(intent));
                    }
                }
                let mut target = source;
                target.generation = 11;
                target.phase = if approval.kind == SimulationKind::Update {
                    SimulationPhase::Closing
                } else {
                    SimulationPhase::RollbackClosing
                };
                target.operation = Some(approval.operation);
                target.requested_gate = SimulationGate::Closed;
                target.observed_gate = SimulationGate::Closed;
                for fault in 0..5 {
                    let mut wrong = target;
                    let mut digest = Some([90; 32]);
                    match fault {
                        0 => digest = Some([91; 32]),
                        1 => digest = None,
                        2 => wrong.generation = 12,
                        3 => wrong.operation = Some([99; 32]),
                        4 => wrong.seal = [99; 32],
                        _ => unreachable!(),
                    }
                    let denied =
                        d.act(SimulationCommand::ReconcileClose(SimulationCloseEvidence {
                            readback: SimulationReadback::Committed(wrong),
                            publication_digest: digest,
                        }));
                    assert!(
                        denied.effects.is_empty(),
                        "C1 close readback must bind digest/op/g/seal"
                    );
                    assert_eq!(denied.snapshot, pending);
                }
                let recovered = simulation_recovery_eligibility(
                    SimulationCode::ClosingOutcomeUnknown,
                    SimulationRecoveryAccess::StatusOnly,
                    None,
                );
                assert!(recovered.status_callable);
                assert!(!recovered.activation_grants_business_admission);
                let committed = d.act(d.reconcile_close(SimulationReadback::Committed(target)));
                assert_eq!(committed.snapshot, target);
                assert_eq!(
                    committed.effects,
                    vec![SimulationEffect::ObserveOriginalCohort],
                    "C1 committed readback never republishes"
                );
                assert_eq!(committed.close_intent, None);
            }
        }
    }
}

#[test]
fn close_proven_absent_allows_only_exact_retry_across_restart() {
    for approval in [update(), rollback(S1)] {
        for ack in [SimulationAck::Unknown, SimulationAck::NotCommitted] {
            for restart in [false, true] {
                let mut d = Driver::new(10);
                let source = d.snapshot();
                d.act(SimulationCommand::Begin(approval));
                d.act(SimulationCommand::ObserveHostClosure(YES));
                close_event(&mut d, [90; 32], ack);
                let pending = d.snapshot();
                for fault in 0..3 {
                    let mut predecessor = source;
                    if fault == 0 {
                        predecessor.generation = 9;
                    }
                    let denied =
                        d.act(SimulationCommand::ReconcileClose(SimulationCloseEvidence {
                            readback: SimulationReadback::NotCommitted {
                                predecessor,
                                operation_absent: if fault == 1 { UNKNOWN } else { YES },
                            },
                            publication_digest: Some(if fault == 2 { [91; 32] } else { [90; 32] }),
                        }));
                    assert!(denied.effects.is_empty());
                    assert_eq!(denied.snapshot, pending);
                    assert!(
                        close_event(&mut d, [90; 32], SimulationAck::Committed)
                            .effects
                            .is_empty(),
                        "C1 invalid absence must not authorize retry"
                    );
                }
                let absence = SimulationReadback::NotCommitted {
                    predecessor: source,
                    operation_absent: YES,
                };
                let proven = d.act(d.reconcile_close(absence));
                let intent = proven.close_intent.unwrap();
                assert_eq!(
                    intent.publication,
                    SimulationClosePublication::ProvenNotCommitted {
                        event_digest: [90; 32]
                    }
                );
                assert_eq!(
                    proven.effects,
                    vec![SimulationEffect::PersistCloseIntent(Box::new(intent))]
                );
                if restart {
                    d.model = SimulationCoordinator::from_simulation_close_intent(
                        intent,
                        SimulationGate::Closed,
                    )
                    .unwrap();
                }
                for readback in [SimulationReadback::Unknown, SimulationReadback::Conflicting] {
                    d.act(d.reconcile_close(readback));
                    assert!(
                        close_event(&mut d, [90; 32], SimulationAck::Committed)
                            .effects
                            .is_empty(),
                        "C1 later uncertainty revokes retry eligibility"
                    );
                    d.act(d.reconcile_close(absence));
                }
                let wrong = close_event(&mut d, [91; 32], SimulationAck::Committed);
                assert_eq!(wrong.code, SimulationCode::StateTransitionInvalid);
                assert!(
                    wrong.effects.is_empty(),
                    "C1 retry must preserve exact publication digest"
                );
                assert_eq!(wrong.snapshot, pending);
                // A retried lost/negative acknowledgement consumes the absence proof again.
                let retried = close_event(&mut d, [90; 32], ack);
                assert_eq!(
                    retried.close_intent.unwrap().publication,
                    SimulationClosePublication::PendingUnknown {
                        event_digest: [90; 32]
                    }
                );
                assert_eq!(retried.snapshot, pending);
                assert!(
                    close_event(&mut d, [90; 32], SimulationAck::Committed)
                        .effects
                        .is_empty()
                );
                d.act(d.reconcile_close(absence));
                let committed = close_event(&mut d, [90; 32], SimulationAck::Committed);
                assert_eq!(committed.code, SimulationCode::Progress);
                assert_eq!(committed.snapshot.generation, 11);
                assert_eq!(committed.snapshot.operation, Some(approval.operation));
                assert_eq!(committed.snapshot.requested_gate, SimulationGate::Closed);
                assert_eq!(committed.snapshot.schema, source.schema);
                assert_eq!(committed.effects.len(), 3);
                assert!(matches!(
                    committed.effects[0],
                    SimulationEffect::PersistCloseIntent(_)
                ));
                assert!(matches!(
                    committed.effects[1],
                    SimulationEffect::PublishControlExclusive { generation: 11, .. }
                ));
                assert_eq!(
                    committed.effects[2],
                    SimulationEffect::ObserveOriginalCohort
                );
            }
        }
    }
}

#[test]
fn reconciled_rollback_retires_prior_publication_without_generation_rewind() {
    for retry_state in [false, true] {
        for read_committed in [false, true] {
            let mut d = Driver::new(1);
            d.migrate();
            let before = d.snapshot();
            d.act(SimulationCommand::MigrationStep {
                approved_step: [74; 32],
                ack: SimulationAck::Unknown,
            });
            let (old_digest, old_effect) = d.publication.clone().unwrap();
            let absence = SimulationReadback::NotCommitted {
                predecessor: before,
                operation_absent: YES,
            };
            let stale = if read_committed {
                SimulationReadback::Committed(before)
            } else {
                absence
            };
            if retry_state {
                let restored = d.act(d.reconcile(absence));
                assert_eq!(restored.snapshot, before);
                d.act(SimulationCommand::Cancel);
            }
            let recovery_source = d.snapshot();
            for source_reconciled in [NO, UNKNOWN] {
                let mut unconfirmed = rollback(S1);
                unconfirmed.source_reconciled = source_reconciled;
                let denied = d.act(SimulationCommand::Begin(unconfirmed));
                assert_eq!(denied.code, SimulationCode::RecoveryAuthorizationRequired);
                assert_eq!(denied.snapshot, recovery_source);
                assert!(
                    denied.effects.is_empty(),
                    "C2 no silent retirement without reconciliation authority"
                );
            }
            // A denied successor must not destroy valid same-operation recovery.
            let mut control = Driver {
                model: d.model.clone(),
                serial: d.serial,
                publication: d.publication.clone(),
            };
            if retry_state {
                let mut sealed = recovery_source;
                sealed.phase = SimulationPhase::Sealed;
                sealed.schema = S2;
                sealed.binary = B2;
                sealed.seal = SEAL2;
                sealed.owner_closed = YES;
                let resumed = control.act(SimulationCommand::ResumeSealed {
                    approval: SimulationRecoveryApproval {
                        provenance: S,
                        operation: OP,
                        decision_digest: [53; 32],
                        reconciliation: YES,
                        stopped_actors: YES,
                        owner_closed: YES,
                    },
                    observed: sealed,
                });
                assert_eq!(resumed.snapshot, sealed);
                control.health();
                assert_eq!(
                    control
                        .act(SimulationCommand::PublishStable(SimulationAck::Committed))
                        .code,
                    SimulationCode::Progress,
                    "C2 authorized resume retires old retry before Stable"
                );
                assert_eq!(
                    control.act(SimulationCommand::Begin(rollback(S2))).code,
                    SimulationCode::ClosingOutcomeUnknown
                );
            } else {
                let reconciled = control.act(control.reconcile(stale));
                assert_eq!(
                    reconciled.code,
                    SimulationCode::Progress,
                    "C2 same operation reconciliation remains valid"
                );
                assert_eq!(reconciled.snapshot, before);
                assert!(reconciled.effects.is_empty());
                if !read_committed {
                    assert_eq!(
                        control
                            .act(SimulationCommand::MigrationStep {
                                approved_step: [74; 32],
                                ack: SimulationAck::Committed
                            })
                            .code,
                        SimulationCode::Progress,
                        "C2 same operation exact retry remains valid"
                    );
                }
            }
            let successor = rollback(S1);
            assert_ne!(successor.operation, before.operation.unwrap());
            let accepted = d.act(SimulationCommand::Begin(successor));
            assert_eq!(accepted.code, SimulationCode::ClosingOutcomeUnknown);
            assert_eq!(accepted.snapshot.generation, recovery_source.generation);
            assert_eq!(
                accepted.effects[0],
                SimulationEffect::RetireReconciledPublication(Box::new(
                    SimulationPublicationRetirement {
                        before,
                        target: before,
                        event_digest: old_digest,
                        effect: old_effect.clone(),
                        reconciled_source: recovery_source,
                        successor_approval: successor,
                    }
                )),
                "C2 prior publication retirement must retain exact authority and identity"
            );
            d.act(SimulationCommand::ObserveHostClosure(YES));
            let closed = d.act(SimulationCommand::PublishClose(SimulationAck::Committed));
            assert_eq!(closed.snapshot.generation, 3);
            assert_eq!(closed.snapshot.operation, Some(OP2));
            d.drain();
            let pointer = d.act(SimulationCommand::SelectRollbackPointer {
                binary: B1,
                profile: [54; 32],
                qualified: YES,
                ack: SimulationAck::Committed,
            });
            assert_eq!(
                pointer.code,
                SimulationCode::Progress,
                "C2 retired publication cannot block successor effects"
            );
            assert_eq!(
                pointer.effects,
                vec![SimulationEffect::SelectRetainedBinary {
                    generation: 3,
                    binary: B1,
                    profile: [54; 32]
                }]
            );
            d.act(SimulationCommand::FailRequiredObservation);
            let current = d.snapshot();
            let stale_event = d.event(SimulationCommand::ReconcilePublication(Box::new(
                SimulationPublicationEvidence {
                    provenance: S,
                    readback: stale,
                    event_digest: old_digest,
                    effect: old_effect,
                },
            )));
            assert_eq!(stale_event.operation, OP2);
            assert_eq!(stale_event.expected, current.guard());
            let rejected = d.model.apply_simulation(stale_event);
            assert_eq!(
                rejected.code,
                SimulationCode::RecoveryRequired,
                "C2 stale publication must not restore a prior operation"
            );
            assert_eq!(
                rejected.snapshot, current,
                "C2 generation must never rewind on stale readback"
            );
            assert!(
                rejected.effects.is_empty(),
                "C2 stale readback authorizes zero effects"
            );
            assert_eq!(rejected.snapshot.generation, 3);
            assert_eq!(rejected.snapshot.operation, Some(OP2));
        }
    }
}
