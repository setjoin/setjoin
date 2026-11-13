// Package updater owns the privileged, host-local execution half of a
// transactional Setjoin upgrade. Business authorization and the public intent
// history remain authoritative in PostgreSQL reducers.
package updater

import "fmt"

// State is the durable upgrade intent state shared with the V178 reducers.
type State string

const (
	StateAwaitingApproval State = "awaiting_approval"
	StateApproved         State = "approved"
	StateScheduled        State = "scheduled"
	StateClaimed          State = "claimed"
	StatePreflight        State = "preflight"
	StateRecoveryPoint    State = "recovery_point"
	StateStaged           State = "staged"
	StateMaintenance      State = "maintenance"
	StateMigrations       State = "migrations"
	StateSwitched         State = "switched"
	StateReadiness        State = "readiness"
	StateCommitted        State = "committed"
	StateVerified         State = "verified"
	StateCancelRequested  State = "cancel_requested"
	StateRollingBack      State = "rolling_back"
	StateRolledBack       State = "rolled_back"
	StateFailed           State = "failed"
	StateRecoveryRequired State = "recovery_required"
	StateCancelled        State = "cancelled"
	StateExpired          State = "expired"
)

var knownStates = map[State]struct{}{
	StateAwaitingApproval: {}, StateApproved: {}, StateScheduled: {},
	StateClaimed: {}, StatePreflight: {}, StateRecoveryPoint: {}, StateStaged: {},
	StateMaintenance: {}, StateMigrations: {}, StateSwitched: {}, StateReadiness: {},
	StateCommitted: {}, StateVerified: {}, StateCancelRequested: {},
	StateRollingBack: {}, StateRolledBack: {}, StateFailed: {},
	StateRecoveryRequired: {}, StateCancelled: {}, StateExpired: {},
}

var allowedTransitions = map[State]map[State]struct{}{
	StateAwaitingApproval: transitions(StateApproved, StateCancelled, StateExpired),
	StateApproved:         transitions(StateScheduled, StateClaimed, StateCancelled, StateExpired),
	StateScheduled:        transitions(StateClaimed, StateCancelled, StateExpired),
	StateClaimed:          transitions(StatePreflight, StateRollingBack, StateFailed),
	StatePreflight:        transitions(StateRecoveryPoint, StateRollingBack, StateFailed),
	StateRecoveryPoint:    transitions(StateStaged, StateRollingBack, StateFailed),
	StateStaged:           transitions(StateMaintenance, StateRollingBack, StateFailed),
	StateMaintenance:      transitions(StateMigrations, StateRollingBack, StateRecoveryRequired),
	StateMigrations:       transitions(StateSwitched, StateRollingBack, StateRecoveryRequired),
	StateSwitched:         transitions(StateReadiness, StateRollingBack, StateRecoveryRequired),
	StateReadiness:        transitions(StateCommitted, StateRollingBack, StateRecoveryRequired),
	StateCommitted:        transitions(StateVerified, StateRollingBack, StateRecoveryRequired),
	StateCancelRequested:  transitions(StateCancelled, StateRecoveryRequired),
	StateRollingBack:      transitions(StateRolledBack, StateRecoveryRequired),
}

func transitions(states ...State) map[State]struct{} {
	result := make(map[State]struct{}, len(states))
	for _, state := range states {
		result[state] = struct{}{}
	}
	return result
}

// Valid reports whether state is part of the versioned V178 contract.
func (s State) Valid() bool {
	_, ok := knownStates[s]
	return ok
}

// Terminal reports whether no automatic transition may leave this state.
func (s State) Terminal() bool {
	switch s {
	case StateVerified, StateRolledBack, StateFailed, StateRecoveryRequired,
		StateCancelled, StateExpired:
		return true
	default:
		return false
	}
}

// ValidateTransition rejects state drift before a DB reducer is called.
func ValidateTransition(from, to State) error {
	if !from.Valid() || !to.Valid() {
		return fmt.Errorf("unknown upgrade transition %q -> %q", from, to)
	}
	if _, ok := allowedTransitions[from][to]; !ok {
		return fmt.Errorf("illegal upgrade transition %q -> %q", from, to)
	}
	return nil
}
