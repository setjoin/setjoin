use crate::lifecycle::*;
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::{CommandEnvelope, CommitObservation, OperationRecord, OperationResult},
    error::ContractError,
    ids::{ActorId, Digest, Generation, MailboxId, MeetingId, OperationId},
};
use std::time::{Duration, Instant};

fn authority(generation: u64) -> AuthorityKey {
    AuthorityKey {
        actor: ActorId::new(17).unwrap(),
        scope: ResourceScope::Mailbox(MailboxId::new(91).unwrap()),
        generation: Generation(generation),
    }
}
fn request(generation: u64) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId([4; 16]),
        authority: authority(generation),
        binding: accepted_contract(),
        payload_digest: Digest([9; 32]),
        command: (),
    }
}
fn lifecycle() -> (TransactionLifecycle, Instant) {
    let now = Instant::now();
    (
        TransactionLifecycle::new(&request(3), now + Duration::from_secs(20)).unwrap(),
        now,
    )
}
fn record(result: OperationResult<u64>) -> OperationRecord<u64> {
    OperationRecord {
        operation: OperationId([4; 16]),
        authority: authority(3),
        payload_digest: Digest([9; 32]),
        result,
    }
}

#[test]
fn exact_final_contract_is_adopted() {
    let binding = accepted_contract();
    assert_eq!(binding.major, 1);
    assert_eq!(
        binding.definition,
        Digest::from_hex("332b05bd4ba4047fdde6afc7e7af0b8fe5b0f2b1dbb951214e82ea1f7ddf4468")
            .unwrap()
    );
    assert_eq!(
        binding.fixtures,
        Digest::from_hex("11401bc5edf41025b2f9a85d999894db79afea4beefa2fd1486881d627f8e8bc")
            .unwrap()
    );
}
#[test]
fn rejects_historical_or_drifted_binding() {
    let mut request = request(3);
    request.binding.fixtures = Digest([1; 32]);
    assert_eq!(
        TransactionLifecycle::new(&request, Instant::now()).unwrap_err(),
        LifecycleError::Contract(ContractError::ContractDrift)
    );
}
#[test]
fn rejects_unsupported_major() {
    let mut request = request(3);
    request.binding.major = 2;
    assert_eq!(
        TransactionLifecycle::new(&request, Instant::now()).unwrap_err(),
        LifecycleError::Contract(ContractError::UnsupportedVersion)
    );
}
#[test]
fn rejects_zero_operation() {
    let mut request = request(3);
    request.operation = OperationId([0; 16]);
    assert_eq!(
        TransactionLifecycle::new(&request, Instant::now()).unwrap_err(),
        LifecycleError::Contract(ContractError::InvalidEnvelope)
    );
}
#[test]
fn current_actor_and_physical_mailbox_remain_distinct() {
    let (mut state, now) = lifecycle();
    assert_ne!(authority(3).actor.get(), 91);
    assert_eq!(state.check_current_key(authority(3), now), Ok(()));
    assert_eq!(state.phase(), Phase::Active);
    assert_eq!(
        state.connection_disposition(),
        ConnectionDisposition::Retain
    );
}
#[test]
fn stale_generation_requires_whole_rollback() {
    let (mut state, now) = lifecycle();
    assert_eq!(
        state.check_current_key(authority(4), now),
        Err(LifecycleError::Contract(ContractError::StaleAuthority))
    );
    assert_eq!(state.phase(), Phase::RollbackPending);
    assert_eq!(
        state.request_commit(authority(3), now),
        Err(LifecycleError::InvalidTransition)
    );
    assert_eq!(
        state.connection_disposition(),
        ConnectionDisposition::Retain
    );
}
#[test]
fn actor_mismatch_requires_whole_rollback() {
    let (mut state, now) = lifecycle();
    let mut current = authority(3);
    current.actor = ActorId::new(18).unwrap();
    assert_eq!(
        state.check_current_key(current, now),
        Err(LifecycleError::Contract(ContractError::ActorMismatch))
    );
    assert_eq!(state.phase(), Phase::RollbackPending);
}
#[test]
fn mailbox_mismatch_requires_whole_rollback() {
    let (mut state, now) = lifecycle();
    let mut current = authority(3);
    current.scope = ResourceScope::Mailbox(MailboxId::new(92).unwrap());
    assert_eq!(
        state.check_current_key(current, now),
        Err(LifecycleError::Contract(ContractError::ScopeMismatch))
    );
    assert_eq!(state.phase(), Phase::RollbackPending);
}
#[test]
fn equal_numeric_cross_domain_scope_is_rejected() {
    let (mut state, now) = lifecycle();
    let mut current = authority(3);
    current.scope = ResourceScope::Meeting(MeetingId::new(91).unwrap());
    assert_eq!(
        state.check_current_key(current, now),
        Err(LifecycleError::Contract(ContractError::ScopeMismatch))
    );
}
#[test]
fn exact_deadline_is_expired_not_usable() {
    let now = Instant::now();
    let mut state = TransactionLifecycle::new(&request(3), now).unwrap();
    assert_eq!(
        state.request_commit(authority(3), now),
        Err(LifecycleError::DeadlineElapsed)
    );
    assert_eq!(state.phase(), Phase::RollbackPending);
}
#[test]
fn deadline_is_rechecked_after_prior_success() {
    let (mut state, now) = lifecycle();
    state.check_current_key(authority(3), now).unwrap();
    assert_eq!(
        state.request_commit(authority(3), now + Duration::from_secs(20)),
        Err(LifecycleError::DeadlineElapsed)
    );
}
#[test]
fn authority_is_rechecked_before_commit() {
    let (mut state, now) = lifecycle();
    state.check_current_key(authority(3), now).unwrap();
    assert_eq!(
        state.request_commit(authority(4), now),
        Err(LifecycleError::Contract(ContractError::StaleAuthority))
    );
}
#[test]
fn committed_observation_requires_driver_reset_before_reuse() {
    let (mut state, now) = lifecycle();
    state.request_commit(authority(3), now).unwrap();
    assert_eq!(state.phase(), Phase::CommitPending);
    assert_eq!(
        state.connection_disposition(),
        ConnectionDisposition::Retain
    );
    state.observe_commit(CommitObservation::Committed).unwrap();
    assert_eq!(state.phase(), Phase::Terminal(CommitObservation::Committed));
    assert_eq!(
        state.connection_disposition(),
        ConnectionDisposition::VerifyDriverReset
    );
}
#[test]
fn commit_can_report_known_rollback() {
    let (mut state, now) = lifecycle();
    state.request_commit(authority(3), now).unwrap();
    state.observe_commit(CommitObservation::RolledBack).unwrap();
    assert_eq!(
        state.phase(),
        Phase::Terminal(CommitObservation::RolledBack)
    );
    assert_eq!(
        state.connection_disposition(),
        ConnectionDisposition::VerifyDriverReset
    );
}
#[test]
fn commit_response_loss_quarantines_connection() {
    let (mut state, now) = lifecycle();
    state.request_commit(authority(3), now).unwrap();
    state.observe_commit(CommitObservation::Unknown).unwrap();
    assert_eq!(state.phase(), Phase::Terminal(CommitObservation::Unknown));
    assert_eq!(
        state.connection_disposition(),
        ConnectionDisposition::Quarantine
    );
}
#[test]
fn cancel_before_commit_does_not_infer_rollback() {
    let (mut state, _) = lifecycle();
    state.cancel().unwrap();
    assert_eq!(state.phase(), Phase::RollbackPending);
    assert_eq!(
        state.connection_disposition(),
        ConnectionDisposition::Retain
    );
    state.cancel().unwrap();
    state
        .observe_rollback(RollbackObservation::Acknowledged)
        .unwrap();
    assert_eq!(
        state.phase(),
        Phase::Terminal(CommitObservation::RolledBack)
    );
}
#[test]
fn cancel_during_commit_requires_lookup_and_quarantine() {
    let (mut state, now) = lifecycle();
    state.request_commit(authority(3), now).unwrap();
    state.cancel().unwrap();
    assert_eq!(state.phase(), Phase::Terminal(CommitObservation::Unknown));
    assert_eq!(
        state.connection_disposition(),
        ConnectionDisposition::Quarantine
    );
    assert_eq!(
        state.observe_commit(CommitObservation::Committed),
        Err(LifecycleError::InvalidTransition)
    );
    assert_eq!(
        state.request_rollback(),
        Err(LifecycleError::InvalidTransition)
    );
}
#[test]
fn audit_failure_requests_whole_rollback() {
    let (mut state, now) = lifecycle();
    state.check_current_key(authority(3), now).unwrap();
    state.request_rollback().unwrap();
    state.request_rollback().unwrap();
    assert_eq!(state.phase(), Phase::RollbackPending);
    assert_eq!(
        state.request_commit(authority(3), now),
        Err(LifecycleError::InvalidTransition)
    );
}
#[test]
fn lost_rollback_response_is_unknown() {
    let (mut state, _) = lifecycle();
    state.request_rollback().unwrap();
    state
        .observe_rollback(RollbackObservation::Unknown)
        .unwrap();
    assert_eq!(state.phase(), Phase::Terminal(CommitObservation::Unknown));
    assert_eq!(
        state.connection_disposition(),
        ConnectionDisposition::Quarantine
    );
}
#[test]
fn connection_loss_in_each_nonterminal_phase_quarantines() {
    for phase in 0..3 {
        let (mut state, now) = lifecycle();
        if phase == 1 {
            state.request_commit(authority(3), now).unwrap();
        }
        if phase == 2 {
            state.request_rollback().unwrap();
        }
        state.connection_lost();
        assert_eq!(state.phase(), Phase::Terminal(CommitObservation::Unknown));
        assert_eq!(
            state.connection_disposition(),
            ConnectionDisposition::Quarantine
        );
        assert_eq!(
            state.check_current_key(authority(3), now),
            Err(LifecycleError::InvalidTransition)
        );
    }
}
#[test]
fn connection_loss_preserves_already_known_commit() {
    let (mut state, now) = lifecycle();
    state.request_commit(authority(3), now).unwrap();
    state.observe_commit(CommitObservation::Committed).unwrap();
    state.connection_lost();
    assert_eq!(state.phase(), Phase::Terminal(CommitObservation::Committed));
    assert_eq!(
        state.connection_disposition(),
        ConnectionDisposition::Quarantine
    );
}
#[test]
fn unsolicited_commit_or_rollback_response_is_rejected() {
    let (mut state, _) = lifecycle();
    assert_eq!(
        state.observe_commit(CommitObservation::Committed),
        Err(LifecycleError::InvalidTransition)
    );
    assert_eq!(
        state.observe_rollback(RollbackObservation::Acknowledged),
        Err(LifecycleError::InvalidTransition)
    );
    assert_eq!(state.phase(), Phase::Active);
}
#[test]
fn terminal_state_cannot_start_another_command() {
    let (mut state, now) = lifecycle();
    state.request_commit(authority(3), now).unwrap();
    state.observe_commit(CommitObservation::Committed).unwrap();
    assert_eq!(
        state.request_commit(authority(3), now),
        Err(LifecycleError::InvalidTransition)
    );
    assert_eq!(state.cancel(), Err(LifecycleError::InvalidTransition));
    assert_eq!(
        state.observe_commit(CommitObservation::RolledBack),
        Err(LifecycleError::InvalidTransition)
    );
    assert_eq!(state.phase(), Phase::Terminal(CommitObservation::Committed));
}
#[test]
fn accepted_receipt_returns_exact_value() {
    let row = record(OperationResult::Accepted(73));
    assert_eq!(
        resolve_lookup(&request(3), authority(3), Some(&row)),
        Ok(LookupDecision::Accepted(&73))
    );
}
#[test]
fn reauthorized_caller_can_lookup_historical_generation() {
    let row = record(OperationResult::Accepted(73));
    assert_eq!(
        resolve_lookup(&request(4), authority(4), Some(&row)),
        Ok(LookupDecision::Accepted(&73))
    );
}
#[test]
fn revoked_stale_caller_cannot_lookup_receipt() {
    let row = record(OperationResult::Accepted(73));
    assert_eq!(
        resolve_lookup(&request(3), authority(4), Some(&row)),
        Err(ContractError::StaleAuthority)
    );
}
#[test]
fn rejected_receipt_is_not_an_automatic_retry() {
    let row = record(OperationResult::Rejected);
    assert_eq!(
        resolve_lookup(&request(3), authority(3), Some(&row)),
        Ok(LookupDecision::Rejected)
    );
}
#[test]
fn absent_pending_and_unknown_receipts_require_reconciliation() {
    assert_eq!(
        resolve_lookup::<u64>(&request(3), authority(3), None),
        Ok(LookupDecision::Reconcile)
    );
    for result in [OperationResult::Pending, OperationResult::Unknown] {
        let row = record(result);
        assert_eq!(
            resolve_lookup(&request(3), authority(3), Some(&row)),
            Ok(LookupDecision::Reconcile)
        );
    }
}
#[test]
fn missing_receipt_still_requires_current_authority() {
    assert_eq!(
        resolve_lookup::<u64>(&request(3), authority(4), None),
        Err(ContractError::StaleAuthority)
    );
}
#[test]
fn lookup_rejects_changed_payload() {
    let mut row = record(OperationResult::Accepted(73));
    row.payload_digest = Digest([8; 32]);
    assert_eq!(
        resolve_lookup(&request(3), authority(3), Some(&row)),
        Err(ContractError::ConflictingReplay)
    );
}
#[test]
fn lookup_rejects_changed_operation_id() {
    let mut row = record(OperationResult::Accepted(73));
    row.operation = OperationId([5; 16]);
    assert_eq!(
        resolve_lookup(&request(3), authority(3), Some(&row)),
        Err(ContractError::ConflictingReplay)
    );
}
#[test]
fn lookup_rejects_other_actor_receipt() {
    let mut row = record(OperationResult::Accepted(73));
    row.authority.actor = ActorId::new(18).unwrap();
    assert_eq!(
        resolve_lookup(&request(3), authority(3), Some(&row)),
        Err(ContractError::ActorMismatch)
    );
}
#[test]
fn lookup_rejects_other_mailbox_receipt() {
    let mut row = record(OperationResult::Accepted(73));
    row.authority.scope = ResourceScope::Mailbox(MailboxId::new(92).unwrap());
    assert_eq!(
        resolve_lookup(&request(3), authority(3), Some(&row)),
        Err(ContractError::ScopeMismatch)
    );
}
#[test]
fn lookup_rejects_binding_drift_even_when_receipt_is_missing() {
    let mut request = request(3);
    request.binding.definition = Digest([7; 32]);
    assert_eq!(
        resolve_lookup::<u64>(&request, authority(3), None),
        Err(ContractError::ContractDrift)
    );
}
#[test]
fn operation_lookup_does_not_rehabilitate_ambiguous_connection() {
    let (mut state, now) = lifecycle();
    state.request_commit(authority(3), now).unwrap();
    state.connection_lost();
    let row = record(OperationResult::Accepted(73));
    assert_eq!(
        resolve_lookup(&request(3), authority(3), Some(&row)),
        Ok(LookupDecision::Accepted(&73))
    );
    assert_eq!(
        state.connection_disposition(),
        ConnectionDisposition::Quarantine
    );
    assert_eq!(state.phase(), Phase::Terminal(CommitObservation::Unknown));
}
